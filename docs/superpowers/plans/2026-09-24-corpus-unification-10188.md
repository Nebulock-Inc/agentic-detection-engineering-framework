# Corpus Unification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give ADEF one answer to "which detections exist in this workspace," shared by Similarity, Overlap, and `detection search`, and cut the Refine→journal→index feedback loop at provenance.

**Architecture:** A new `adef/core/corpus.py` owns the union of catalog records and journals as `CorpusEntry` objects; `build_corpus(workspace)` is the single membership resolver. `MemoryIndex` stops traversing journals itself and indexes `CorpusEntry.index_text`. Journal blocks written by machines are marked at write time and excluded from indexed text — never from the journal file itself.

**Tech Stack:** Python 3.10+, stdlib only for this change (no new dependencies). pytest, ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-09-24-corpus-unification-design.md`

## Global Constraints

- **No new runtime dependencies.** Everything here is stdlib plus what ADEF already imports.
- **`build_corpus` must never create directories.** It is a read path. Follow the existing precedent in `adef.core.catalog.known_detection_ids`: construct `Catalog` only when `catalog_dir(workspace).is_dir()`. `Catalog.__init__` mkdirs unconditionally and must not be called on a bare workspace.
- **Provenance filtering is index-only.** Refine blocks stay in the journal file, in `adef detection show`, and visible to any agent reading the journal. Only BM25 scoring excludes them.
- **The marker string is `<!-- adef:generated -->`**, defined once in `adef/core/journal.py` as `GENERATED_MARKER` and imported by every other user. No second literal anywhere.
- **Legacy fallback is permanent, not transitional.** Journals written before this change have no marker; matching the `### Refine / ` heading prefix stays in the code indefinitely.
- **Path comparisons in tests must resolve both sides.** `catalog_dir()` calls `.expanduser().resolve()`, so every path from `iter_records` is fully resolved, while a `tmp_path`-derived expectation may not be (on macOS `/tmp` is a symlink to `/private/tmp`). Compare with `.resolve()` on both sides, or the assertion fails for a reason that has nothing to do with the code under test.
- **Never fabricate a path.** A record-only detection reports its record's path. Do not synthesize a `JournalEntry` or a journals/ path for it.
- **ADEF is standalone-first.** No private codebase is a design input, reference corpus, or justification. See "Direction of Integration" in `CLAUDE.md`.
- **Every provenance test must be verified to fail with the filter disabled.** The predecessor of these tests passed against broken code because it exercised a synthetic payload rather than the real pipeline. Corpus properties are asserted end-to-end.

## Review Focus

Five input classes the spec implies but that no task's happy-path tests would otherwise exercise. Each has a test assigned to the task that owns the code.

1. **Bare workspace** — no `catalog/` and/or no `journals/` directory. `build_corpus` must return `[]` and create nothing on disk. (Task 2)
2. **Unparseable artifacts** — a journal with no `id` in frontmatter, a catalog YAML that fails to parse. Must be skipped, not crash the whole corpus build. (Task 2)
3. **Same id in two places** — the same `D-XXXX` present under two platform directories. Must yield exactly one entry, deterministically. (Task 2)
4. **Journal that is only template preamble** — created by `detection new`, never advanced. Narrative is empty; the entry must still index (from its record, if any) and must not produce a zero-length document that skews BM25's `avgdl` or divides by zero. (Task 3)
5. **Marker forgery and heading collision** — a human pastes `<!-- adef:generated -->` into their own note, or writes a `### Refine / Similarity` heading by hand. Defined behavior: the marker is trusted wherever it appears (it is our own format, and a human using it is opting out of indexing), and the legacy heading prefix likewise excludes. Both are documented, not accidental. (Task 1)

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `adef/core/journal.py` | Owns the journal *format*: frontmatter, stage blocks, provenance marker, narrative extraction | Modify |
| `adef/core/corpus.py` | Owns *membership*: the union of records and journals, one `CorpusEntry` per detection | **Create** |
| `adef/core/memory.py` | Owns *scoring*: BM25 over whatever text the corpus hands it. Stops knowing about journals | Modify |
| `adef/agents/rule_similarity.py` | Retrieval consumer | Modify |
| `adef/agents/rule_overlap.py` | Pairwise consumer — same membership, different use | Modify |
| `adef/commands/detection.py` | `detection search` CLI | Modify |
| `adef/mcp/tools/memory_tools.py` | `memory_search` MCP tool | Modify |
| `adef/orchestration/refine_chain.py` | Marks its blocks generated; journal fidelity | Modify |

---

### Task 1: Journal provenance marker and narrative extraction

Move journal block knowledge out of `memory.py` and into `journal.py`, which owns the format. Add the write-time provenance marker.

**Files:**
- Modify: `adef/core/journal.py` (add `GENERATED_MARKER`, `narrative_text`; extend `append_block`)
- Test: `tests/test_journal_narrative.py` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `GENERATED_MARKER: str = "<!-- adef:generated -->"`
  - `Journal.append_block(self, detection_id: str, heading: str, body: str, generated: bool = False) -> None`
  - `narrative_text(body: str) -> str` — module-level function in `journal.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_journal_narrative.py`:

```python
# tests/test_journal_narrative.py
from pathlib import Path

from adef.core.journal import GENERATED_MARKER, Journal, narrative_text


def _journal(tmp_path: Path) -> Journal:
    d = tmp_path / "journals"
    d.mkdir(parents=True)
    return Journal(d)


def test_narrative_drops_the_template_preamble():
    # Everything before the first timestamped stage block is unfilled
    # scaffolding, not reasoning — indexing it makes every detection look
    # alike on the template's own words.
    body = (
        "> A FORGE journal\n\n"
        "- **Hypothesis:**\n"
        "- **Data source:**\n\n"
        "## [2026-09-24T10:00:00-04:00] Stage: observe\n\n"
        "UNIQUEOBSERVATION mshta spawning from Office\n"
    )
    out = narrative_text(body)
    assert "UNIQUEOBSERVATION" in out
    assert "Hypothesis" not in out


def test_narrative_drops_marked_generated_blocks():
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: refine\n\n"
        "HUMANNOTE checked this by hand\n\n"
        f"### Refine / Similarity (2026-09-24T10:01:00-04:00)\n{GENERATED_MARKER}\n\n"
        "- **candidates:** MACHINEOUTPUT D-0002\n"
    )
    out = narrative_text(body)
    assert "HUMANNOTE" in out
    assert "MACHINEOUTPUT" not in out


def test_narrative_drops_unmarked_legacy_refine_blocks():
    # Journals written before the marker existed must still be filtered —
    # this fallback is permanent, not a migration step.
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: refine\n\n"
        "HUMANNOTE checked this by hand\n\n"
        "### Refine / Overlap (2026-09-24T10:01:00-04:00)\n\n"
        "- **overlaps:** LEGACYOUTPUT D-0002\n"
    )
    out = narrative_text(body)
    assert "HUMANNOTE" in out
    assert "LEGACYOUTPUT" not in out


def test_narrative_keeps_a_human_block_that_is_not_refine():
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: govern\n\n"
        "### Deployment decision (2026-09-24T10:01:00-04:00)\n\n"
        "KEEPTHIS approved by the on-call lead\n"
    )
    assert "KEEPTHIS" in narrative_text(body)


def test_narrative_drops_catalogued_from_housekeeping():
    body = (
        "## [2026-09-24T10:00:00-04:00] Stage: find\n\n"
        "Catalogued from /repo/rules/x.yml by adef catalog\n"
        "REALCONTENT here\n"
    )
    out = narrative_text(body)
    assert "REALCONTENT" in out
    assert "Catalogued from" not in out


def test_narrative_of_an_unadvanced_journal_is_empty():
    # `detection new` writes template only. Nothing to index.
    body = "> A FORGE journal\n\n- **Hypothesis:**\n- **Data source:**\n"
    assert narrative_text(body).strip() == ""


def test_append_block_marks_generated_blocks(tmp_path):
    j = _journal(tmp_path)
    j.create(detection_id="D-0001", title="t")
    j.append_block("D-0001", "Refine / Similarity", "- **x:** 1", generated=True)
    text = (tmp_path / "journals" / "D-0001.md").read_text()
    assert GENERATED_MARKER in text
    # The block itself is still in the file — exclusion is index-only.
    assert "**x:**" in text


def test_append_block_is_unmarked_by_default(tmp_path):
    j = _journal(tmp_path)
    j.create(detection_id="D-0001", title="t")
    j.append_block("D-0001", "Deployment decision", "approved")
    text = (tmp_path / "journals" / "D-0001.md").read_text()
    assert GENERATED_MARKER not in text
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_journal_narrative.py -v`
Expected: FAIL with `ImportError: cannot import name 'GENERATED_MARKER'`

- [ ] **Step 3: Implement in `adef/core/journal.py`**

Add near the other module-level regexes:

```python
GENERATED_MARKER = "<!-- adef:generated -->"

# The first timestamped stage block ends the static template preamble —
# everything before it is fill-in scaffolding, not reasoning. Moved here from
# memory.py: the journal module owns its own format, and leaving block
# structure in the search layer is what made "which blocks are machine
# output?" hard to answer.
_STAGE_BLOCK_RE = re.compile(r"^## \[.+?\] Stage:", re.MULTILINE)

# A `### ` sub-block inside a stage block. Refine results land here.
_SUB_BLOCK_RE = re.compile(r"^### ", re.MULTILINE)

# Journals written before GENERATED_MARKER existed carry no marker. This
# prefix identifies them. Permanent fallback, not a migration step.
_LEGACY_GENERATED_HEADING = "### Refine / "


def _is_generated_block(block: str) -> bool:
    """True when this ``### `` sub-block was written by ADEF, not a human."""
    return GENERATED_MARKER in block or block.startswith(_LEGACY_GENERATED_HEADING)


def narrative_text(body: str) -> str:
    """The human-authored prose in a journal body, for indexing.

    Drops three things: the static template preamble, every machine-generated
    sub-block, and `Catalogued from…` housekeeping. What remains is reasoning
    a person or an agent wrote deliberately — the only journal content that can
    be evidence without feeding retrieval its own output.

    Filtering is by *provenance*, never by content: two earlier attempts
    filtered by key name and both failed, because the same text arrived under
    a different key.
    """
    m = _STAGE_BLOCK_RE.search(body)
    if not m:
        return ""
    body = body[m.start():]

    # Split into sub-blocks, keeping any text before the first `### ` heading
    # (that is stage-block prose, which is human by definition).
    pieces: list[str] = []
    last = 0
    for match in _SUB_BLOCK_RE.finditer(body):
        pieces.append(body[last:match.start()])
        last = match.start()
    pieces.append(body[last:])

    kept = [p for p in pieces if not _is_generated_block(p)]

    lines: list[str] = []
    for line in "".join(kept).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith(">"):
            continue
        if stripped.startswith("**Title:**"):
            continue
        if "Catalogued from" in stripped and "adef" in stripped:
            continue
        if stripped == GENERATED_MARKER:
            continue
        lines.append(stripped)
    return "\n".join(lines)
```

Then extend `append_block` (currently at `adef/core/journal.py:296`):

```python
    def append_block(
        self, detection_id: str, heading: str, body: str, generated: bool = False
    ) -> None:
        """Append an arbitrary ``### heading``-level block under the current stage.

        Used by orchestration (Refine chain) to record agent results. Pass
        ``generated=True`` for machine-written blocks: the block stays in the
        file and stays visible to readers, but retrieval excludes it, so a
        Refine result can never feed back into the scoring that produced it.
        """
        entry = self.read(detection_id)
        ts = _now_iso()
        marker = f"{GENERATED_MARKER}\n" if generated else ""
        block = f"\n### {heading} ({ts})\n{marker}\n{body.strip()}\n"
        new_fm = {**entry.frontmatter, "updated": ts}
        _atomic_write(entry.path, _join_frontmatter(new_fm, entry.body.rstrip() + "\n" + block))
```

Add `GENERATED_MARKER` and `narrative_text` to `journal.py`'s `__all__`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_journal_narrative.py -v`
Expected: 8 passed

- [ ] **Step 5: Verify the filter is load-bearing**

Temporarily make `_is_generated_block` return `False`, re-run, and confirm `test_narrative_drops_marked_generated_blocks` and `test_narrative_drops_unmarked_legacy_refine_blocks` both FAIL. Restore. A provenance test that cannot fail is worse than no test.

- [ ] **Step 6: Run the full suite and linters**

Run: `pytest -q && ruff check adef/ tests/ && mypy adef/`
Expected: all pass. (`memory.py` still has its own `_STAGE_BLOCK_RE`; that is removed in Task 3.)

- [ ] **Step 7: Commit**

```bash
git add adef/core/journal.py tests/test_journal_narrative.py
git commit -m "feat(journal): mark generated blocks at write time, extract narrative

Journal blocks written by the Refine chain are marked with an HTML comment
at write time. `narrative_text()` returns only human-authored prose, so
retrieval can never score a machine's own output.

Filtering is by provenance, not content — two earlier attempts filtered by
key name and both failed because the same text arrived under another key.
Block-structure knowledge moves from memory.py to journal.py, which owns
the format."
```

---

### Task 2: `CorpusEntry` and `build_corpus`

The membership resolver. This is the abstraction whose absence let Similarity and Overlap disagree.

**Files:**
- Create: `adef/core/corpus.py`
- Test: `tests/test_corpus.py` (create)

**Interfaces:**
- Consumes: `narrative_text(body) -> str` and `GENERATED_MARKER` from `adef.core.journal` (Task 1).
- Produces:
  - `CorpusEntry` dataclass with fields `detection_id: str`, `record: dict | None`, `record_path: Path | None`, `journal: JournalEntry | None` and properties `title: str`, `current_stage: str`, `path: Path`, `index_text: str`
  - `build_corpus(workspace: Path) -> list[CorpusEntry]`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_corpus.py`:

```python
# tests/test_corpus.py
from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.corpus import CorpusEntry, build_corpus
from adef.core.journal import Journal


def _rec(rid: str, title: str, query: str = "process.name = 'x'") -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=["T1218.005"],
    )


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat, journal = Catalog(w), Journal(w / "journals")

    # D-0001: both artifacts
    r1 = _rec("D-0001", "mshta child process")
    cat.write_raw(w / "catalog" / "D-0001.yml", r1.to_yaml_dict())
    journal.create(detection_id="D-0001", title=r1.title)

    # D-0002: record only (journal deleted) — invisible to Similarity today
    r2 = _rec("D-0002", "mshta spawning child")
    cat.write_raw(w / "catalog" / "D-0002.yml", r2.to_yaml_dict())

    # D-0003: journal only (a `detection new` draft)
    journal.create(detection_id="D-0003", title="draft rundll32 idea")

    cat.rebuild_index()
    return w


def test_membership_is_the_union_of_records_and_journals(ws: Path):
    ids = sorted(e.detection_id for e in build_corpus(ws))
    assert ids == ["D-0001", "D-0002", "D-0003"]


def test_each_detection_appears_exactly_once(ws: Path):
    ids = [e.detection_id for e in build_corpus(ws)]
    assert len(ids) == len(set(ids))


def test_record_only_entry_reports_the_record_path_not_a_fake_journal(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0002")
    assert entry.journal is None
    assert entry.path == ws / "catalog" / "D-0002.yml"
    assert entry.path.exists()


def test_record_only_entry_reports_the_records_stage(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0002")
    assert entry.current_stage == "find"   # CatalogRecord.stage default


def test_journal_only_entry_has_no_record(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0003")
    assert entry.record is None
    assert entry.title == "draft rundll32 idea"
    assert entry.path == ws / "journals" / "D-0003.md"


def test_index_text_includes_the_record_query(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0001")
    assert "process.name" in entry.index_text


def test_index_text_survives_either_half_missing(ws: Path):
    by_id = {e.detection_id: e for e in build_corpus(ws)}
    assert "mshta spawning child" in by_id["D-0002"].index_text   # record only
    assert isinstance(by_id["D-0003"].index_text, str)            # journal only


def test_bare_workspace_returns_nothing_and_creates_nothing(tmp_path: Path):
    # Review Focus 1. `Catalog.__init__` mkdirs, so a naive implementation
    # silently creates `catalog/` on a read path.
    bare = tmp_path / "bare"
    bare.mkdir()
    assert build_corpus(bare) == []
    assert not (bare / "catalog").exists()
    assert not (bare / "journals").exists()


def test_unparseable_artifacts_are_skipped_not_fatal(ws: Path):
    # Review Focus 2.
    (ws / "catalog" / "D-0009.yml").write_text("{{{ not yaml", encoding="utf-8")
    (ws / "journals" / "D-0010.md").write_text("no frontmatter here", encoding="utf-8")
    ids = sorted(e.detection_id for e in build_corpus(ws))
    assert "D-0001" in ids and "D-0002" in ids and "D-0003" in ids


def test_same_id_in_two_platform_dirs_yields_one_entry(ws: Path):
    # Review Focus 3.
    dup_dir = ws / "catalog" / "linux"
    dup_dir.mkdir()
    cat = Catalog(ws)
    cat.write_raw(dup_dir / "D-0001.yml", _rec("D-0001", "duplicate elsewhere").to_yaml_dict())
    entries = [e for e in build_corpus(ws) if e.detection_id == "D-0001"]
    assert len(entries) == 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_corpus.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'adef.core.corpus'`

- [ ] **Step 3: Implement `adef/core/corpus.py`**

```python
"""The corpus — every detection in a workspace, however it is represented.

A detection has up to two artifacts, stored separately and joined only by its
``D-XXXX`` id: a **journal** (``journals/D-XXXX.md``, append-only history) and
a **catalog record** (``catalog/<platform>/D-XXXX-<slug>.yml``, current state).
Either can be absent — ``detection new`` without ``--source`` writes a journal
and no record; a deleted journal leaves a record alone.

Before this module, ``RuleSimilarityAgent`` walked journals and
``RuleOverlapAgent`` walked the catalog, so the same Refine run could report a
rule as a 98% duplicate and as not existing. ``build_corpus`` is the single
membership answer both use.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from adef.core.corpus_text import record_search_text
from adef.core.journal import Journal, JournalEntry, narrative_text


@dataclass(frozen=True)
class CorpusEntry:
    """One detection, with whichever of its two artifacts exist."""

    detection_id: str
    record: Optional[dict] = None
    record_path: Optional[Path] = None
    journal: Optional[JournalEntry] = None

    @property
    def title(self) -> str:
        """Record wins: `sync` refreshes it from source, the journal's is set once."""
        if self.record:
            title = str(self.record.get("title") or "")
            if title:
                return title
        if self.journal is not None:
            return str(self.journal.frontmatter.get("title", "") or "")
        return ""

    @property
    def current_stage(self) -> str:
        """Journal wins: it owns the stage machine — `advance_stage` writes it."""
        if self.journal is not None:
            return self.journal.current_stage
        if self.record:
            return str(self.record.get("stage") or "find")
        return "find"

    @property
    def path(self) -> Path:
        """Whichever artifact exists. Never fabricated."""
        if self.journal is not None:
            return self.journal.path
        assert self.record_path is not None, "a CorpusEntry has at least one artifact"
        return self.record_path

    @property
    def index_text(self) -> str:
        """What retrieval scores: the record projection plus human journal prose.

        Both artifacts, working together. A human's Observe note is legitimate
        evidence for "does a rule like this already exist?" and can never feed
        back, because nothing automated writes it. Machine-generated blocks are
        already gone — `narrative_text` drops them by provenance.
        """
        parts = []
        if self.record:
            parts.append(record_search_text(self.record))
        if self.journal is not None:
            parts.append(narrative_text(self.journal.body))
        return "\n".join(p for p in parts if p)


def build_corpus(workspace: Path) -> list[CorpusEntry]:
    """Every detection in ``workspace`` — it exists if it has a record OR a journal.

    Exactly one entry per detection id, sorted by id. Creates nothing: a
    read path must not mkdir, and ``Catalog.__init__`` does (the same reason
    ``catalog.known_detection_ids`` exists).
    """
    from adef.core.catalog import Catalog, catalog_dir

    records: dict[str, tuple[Path, dict]] = {}
    if catalog_dir(workspace).is_dir():
        for det_id, path, data in Catalog(workspace).iter_records():
            # First one wins, and iter_records sorts by path, so a duplicate id
            # under two platform dirs resolves deterministically.
            records.setdefault(str(det_id), (path, data))

    journals: dict[str, JournalEntry] = {}
    journals_dir = workspace / "journals"
    if journals_dir.is_dir():
        for entry in Journal(journals_dir).iter_entries():
            journals.setdefault(entry.detection_id, entry)

    return [
        CorpusEntry(
            detection_id=det_id,
            record=records.get(det_id, (None, None))[1],
            record_path=records.get(det_id, (None, None))[0],
            journal=journals.get(det_id),
        )
        for det_id in sorted(set(records) | set(journals))
    ]


__all__ = ["CorpusEntry", "build_corpus"]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_corpus.py -v`
Expected: 10 passed

- [ ] **Step 5: Run the full suite and linters**

Run: `pytest -q && ruff check adef/ tests/ && mypy adef/`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add adef/core/corpus.py tests/test_corpus.py
git commit -m "feat(corpus): one membership answer for every consumer

A detection exists if it has a catalog record OR a journal. CorpusEntry
carries whichever artifacts are present; build_corpus resolves the union
once. This is the abstraction whose absence let Similarity (journal-keyed)
and Overlap (catalog-keyed) disagree about the same workspace.

Creates nothing on a read path — Catalog.__init__ mkdirs, so it is only
constructed when catalog/ already exists."
```

---

### Task 3: `MemoryIndex` indexes the corpus

`MemoryIndex` stops traversing journals and stops knowing what a stage block is. All three call sites move atomically so the tree never goes red.

**Files:**
- Modify: `adef/core/memory.py` (constructor, `build`, `_Doc`, `SearchHit`, delete `_STAGE_BLOCK_RE`/`_clean_for_snippet`)
- Modify: `adef/agents/rule_similarity.py:180`
- Modify: `adef/commands/detection.py:631-648`
- Modify: `adef/mcp/tools/memory_tools.py:27-28`
- Test: `tests/test_memory_corpus.py` (create)

**Interfaces:**
- Consumes: `CorpusEntry`, `build_corpus` (Task 2); `narrative_text` (Task 1).
- Produces:
  - `MemoryIndex()` — no constructor arguments
  - `MemoryIndex.build(self, entries: Iterable[CorpusEntry]) -> None` — `extra_text_for` removed
  - `SearchHit` unchanged in shape: `detection_id`, `score`, `title`, `current_stage`, `snippet`, `path`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_memory_corpus.py`:

```python
# tests/test_memory_corpus.py
from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.corpus import build_corpus
from adef.core.journal import Journal
from adef.core.memory import MemoryIndex


def _rec(rid: str, title: str, query: str) -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=["T1218.005"],
    )


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat, journal = Catalog(w), Journal(w / "journals")
    r = _rec("D-0001", "mshta child process", "process.name = 'mshta.exe'")
    cat.write_raw(w / "catalog" / "D-0001.yml", r.to_yaml_dict())
    journal.create(detection_id="D-0001", title=r.title)
    cat.rebuild_index()
    return w


def _search(ws: Path, q: str):
    index = MemoryIndex()
    index.build(build_corpus(ws))
    return index.search(q, limit=10)


def test_a_record_only_detection_is_searchable(ws: Path):
    # The headline bug: catalogued, journal missing, invisible to retrieval.
    cat = Catalog(ws)
    cat.write_raw(
        ws / "catalog" / "D-0002.yml",
        _rec("D-0002", "rundll32 abuse", "process.name = 'RUNDLLMARKER'").to_yaml_dict(),
    )
    cat.rebuild_index()
    assert "D-0002" in [h.detection_id for h in _search(ws, "RUNDLLMARKER")]


def test_a_record_only_hit_reports_the_record_path(ws: Path):
    cat = Catalog(ws)
    cat.write_raw(
        ws / "catalog" / "D-0002.yml",
        _rec("D-0002", "rundll32 abuse", "process.name = 'RUNDLLMARKER'").to_yaml_dict(),
    )
    cat.rebuild_index()
    hit = next(h for h in _search(ws, "RUNDLLMARKER") if h.detection_id == "D-0002")
    assert hit.path == ws / "catalog" / "D-0002.yml"
    assert hit.current_stage == "find"


def test_human_journal_prose_is_indexed(ws: Path):
    Journal(ws / "journals").advance_stage(
        detection_id="D-0001", stage="observe", note="HUMANBASELINE three per day"
    )
    assert "D-0001" in [h.detection_id for h in _search(ws, "HUMANBASELINE")]


def test_a_generated_block_earns_no_score(ws: Path):
    # The feedback loop, asserted end-to-end against the real pipeline.
    Journal(ws / "journals").append_block(
        "D-0001", "Refine / Similarity", "- **candidates:** MACHINEONLYTOKEN", generated=True
    )
    assert _search(ws, "MACHINEONLYTOKEN") == []


def test_a_legacy_unmarked_refine_block_earns_no_score(ws: Path):
    Journal(ws / "journals").append_block(
        "D-0001", "Refine / Overlap", "- **overlaps:** LEGACYONLYTOKEN"
    )
    assert _search(ws, "LEGACYONLYTOKEN") == []


def test_an_unadvanced_journal_does_not_break_scoring(ws: Path):
    # Review Focus 4: template-only journal, no record → zero-length document.
    Journal(ws / "journals").create(detection_id="D-0009", title="bare draft")
    hits = _search(ws, "mshta")            # must not raise ZeroDivisionError
    assert "D-0001" in [h.detection_id for h in hits]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_memory_corpus.py -v`
Expected: FAIL — `MemoryIndex.build()` does not accept `CorpusEntry` (`AttributeError: 'CorpusEntry' object has no attribute 'body'`)

- [ ] **Step 3: Rewrite the indexing core in `adef/core/memory.py`**

Replace the constructor, `_iter_source_entries`, `build`, `_Doc`, and the `search` hit construction:

```python
@dataclass
class _Doc:
    entry: "CorpusEntry"
    tokens: list[str]
    text: str = ""
    tf: Counter = field(default_factory=Counter)
    length: int = 0


class MemoryIndex:
    """BM25 index over the workspace corpus.

    Takes ``CorpusEntry`` objects and scores ``entry.index_text``. It no longer
    reads the filesystem or knows what a journal block is: membership belongs to
    ``adef.core.corpus`` and block structure to ``adef.core.journal``.
    """

    def __init__(self) -> None:
        self._docs: list[_Doc] = []
        self._df: Counter[str] = Counter()
        self._avgdl: float = 0.0
        self._built = False

    def build(self, entries: Iterable["CorpusEntry"]) -> None:
        """Build the index over a corpus."""
        self._docs = []
        self._df = Counter()
        total_len = 0
        for entry in entries:
            text = entry.index_text
            tokens = _tokenize(text)
            tf = Counter(tokens)
            doc = _Doc(entry=entry, tokens=tokens, text=text, tf=tf, length=len(tokens))
            for term in tf:
                self._df[term] += 1
            total_len += doc.length
            self._docs.append(doc)
        # Empty documents (a template-only journal with no record) must not
        # divide by zero or drag `avgdl` toward zero and inflate every score.
        scored = [d for d in self._docs if d.length > 0]
        self._avgdl = (total_len / len(scored)) if scored else 0.0
        self._built = True
```

In `search`, build the hit from the corpus entry:

```python
            out.append(
                SearchHit(
                    detection_id=entry.detection_id,
                    score=round(score, 4),
                    title=entry.title,
                    current_stage=entry.current_stage,
                    snippet=self._snippet(doc.text, query_terms),
                    path=entry.path,
                )
            )
```

Delete `_STAGE_BLOCK_RE`, `_clean_for_snippet`, and `_iter_source_entries` from `memory.py` — journal-block knowledge now lives in `journal.py`, and `index_text` is already clean, so `_snippet` operates on it directly:

```python
    def _snippet(self, text: str, query_terms: list[str], width: int = 240) -> str:
        # `text` is already `CorpusEntry.index_text`: template scaffolding,
        # machine-generated blocks, and housekeeping are gone before it gets
        # here, so no second cleaning pass is needed.
        if not query_terms:
            return text[:width].strip().replace("\n", " ")
        lowered = text.lower()
        for term in query_terms:
            idx = lowered.find(term)
            if idx >= 0:
                start = max(0, idx - width // 2)
                end = min(len(text), start + width)
                snippet = text[start:end].strip().replace("\n", " ")
                return ("…" if start > 0 else "") + snippet + ("…" if end < len(text) else "")
        return text[:width].strip().replace("\n", " ")
```

Add `from adef.core.corpus import CorpusEntry` under `TYPE_CHECKING`, and drop the now-unused `Journal`/`JournalEntry`/`Callable`/`Optional` imports.

- [ ] **Step 4: Update the three call sites**

`adef/agents/rule_similarity.py` — replace the index construction (around line 180):

```python
        index = MemoryIndex()
        index.build(build_corpus(ws))
```

and delete the `record_text` dict and `extra_text_for` lambda. Import `build_corpus` from `adef.core.corpus`. Keep the existing `records` dict — `_logic_fields` and the LLM path still need it.

`adef/commands/detection.py` — replace lines 631-648 of the `search` command:

```python
    from adef.core.corpus import build_corpus
    from adef.core.memory import MemoryIndex

    ws = _workspace_from(workspace)
    index = MemoryIndex()
    index.build(build_corpus(ws))
    hits = index.search(query, limit=limit)
```

`adef/mcp/tools/memory_tools.py` — replace lines 27-28:

```python
        ws = workspace_journals_dir(Path(workspace) if workspace else None).parent
        index = MemoryIndex()
        index.build(build_corpus(ws))
```

Import `build_corpus` from `adef.core.corpus`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_memory_corpus.py -v`
Expected: 6 passed

- [ ] **Step 6: Verify the provenance filter is load-bearing**

Temporarily make `narrative_text` return the raw body, re-run, and confirm `test_a_generated_block_earns_no_score` and `test_a_legacy_unmarked_refine_block_earns_no_score` both FAIL. Restore.

- [ ] **Step 7: Run the full suite and linters**

Run: `pytest -q && ruff check adef/ tests/ && mypy adef/`
Expected: all pass. Existing `MemoryIndex(journals_dir=...)` tests will need updating to the new constructor — that is expected churn, update them to build from `build_corpus` or from a hand-built `[CorpusEntry(...)]` list.

- [ ] **Step 8: Commit**

```bash
git add adef/core/memory.py adef/agents/rule_similarity.py adef/commands/detection.py adef/mcp/tools/memory_tools.py tests/
git commit -m "feat(memory): index the corpus, not the journals directory

MemoryIndex takes CorpusEntry objects and scores entry.index_text. It no
longer walks the filesystem or knows what a stage block is — membership
belongs to corpus.py, block structure to journal.py.

Catalogued rules with no journal become searchable (the headline bug), and
machine-generated Refine blocks earn no score, which closes the feedback
loop at provenance. The extra_text_for callback is gone: it existed only to
keep memory.py from importing Catalog, and corpus.py now owns that join."
```

---

### Task 4: Both agents resolve the same membership

Overlap switches to `build_corpus` so the agreement is a tested property rather than a coincidence of two iteration paths.

**Files:**
- Modify: `adef/agents/rule_overlap.py:126-140`
- Test: `tests/test_agent_agreement.py` (create)

**Interfaces:**
- Consumes: `build_corpus` (Task 2); `MemoryIndex` over corpus entries (Task 3).
- Produces: no new public API. `RuleOverlapAgent.run` keeps its signature.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_agent_agreement.py`:

```python
# tests/test_agent_agreement.py
from pathlib import Path

import pytest

from adef.agents.rule_overlap import RuleOverlapAgent
from adef.agents.rule_similarity import RuleSimilarityAgent
from adef.core.catalog import Catalog, CatalogRecord
from adef.core.journal import Journal


def _rec(rid: str, title: str, query: str) -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=["T1218.005"],
    )


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    """D-0001 has both artifacts; D-0002 is catalogued with its journal deleted."""
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat, journal = Catalog(w), Journal(w / "journals")
    q = "process.name = 'mshta.exe' and parent.name = 'excel.exe'"
    for rid, title in [("D-0001", "mshta child process"), ("D-0002", "mshta spawning child")]:
        cat.write_raw(w / "catalog" / f"{rid}.yml", _rec(rid, title, q).to_yaml_dict())
        journal.create(detection_id=rid, title=title)
    cat.rebuild_index()
    (w / "journals" / "D-0002.md").unlink()      # the divergence case
    return w


def test_similarity_sees_a_catalogued_rule_whose_journal_is_missing(ws: Path):
    # Before this change Similarity returned nothing here while Overlap
    # reported D-0002 as a near-duplicate, in the same Refine run.
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=5, similarity_mode="bm25"
    )
    assert "D-0002" in [c["detection_id"] for c in result["candidates"]]


def test_overlap_still_reports_it(ws: Path):
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert "D-0002" in [o["other_id"] for o in result["overlaps"]]


def test_both_agents_resolve_the_same_membership(ws: Path):
    from adef.core.corpus import build_corpus

    expected = {e.detection_id for e in build_corpus(ws)}
    assert expected == {"D-0001", "D-0002"}


def test_overlap_skips_entries_with_no_query(ws: Path):
    # A journal-only draft is in the corpus but has no logic to compare.
    Journal(ws / "journals").create(detection_id="D-0003", title="draft idea")
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert "D-0003" not in [o["other_id"] for o in result["overlaps"]]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_agent_agreement.py -v`
Expected: `test_similarity_sees_a_catalogued_rule_whose_journal_is_missing` PASSES already (Task 3 fixed it); the others pass or fail depending on Overlap. Confirm by checking out the pre-Task-3 commit that the Similarity test FAILS there — that is the regression this branch exists to prevent.

- [ ] **Step 3: Switch Overlap to the shared resolver**

In `adef/agents/rule_overlap.py`, replace the membership block at lines 128-138:

```python
        journals_dir = workspace_journals_dir(workspace, create=False)
        ws = journals_dir.parent

        # Same membership resolver as Similarity — the two agents disagreeing
        # about what the catalog holds is the bug this replaced. Entries with
        # no query are skipped here rather than absent: `classify_pair` needs
        # logic on both sides, so a journal-only draft is in the corpus and
        # simply not comparable.
        records: dict[str, dict] = {
            e.detection_id: e.record
            for e in build_corpus(ws)
            if e.record is not None and (e.record.get("query") or "")
        }
        target = records.get(detection_id)
        if target is None:
            raise NoCatalogRecordError(f"No catalog record found for {detection_id}")
```

Add `from adef.core.corpus import build_corpus` to the imports and drop the now-unused `Catalog` import if nothing else in the module uses it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_agent_agreement.py -v`
Expected: 4 passed

- [ ] **Step 5: Run the full suite and linters**

Run: `pytest -q && ruff check adef/ tests/ && mypy adef/`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add adef/agents/rule_overlap.py tests/test_agent_agreement.py
git commit -m "feat(overlap): resolve membership through the shared corpus

Overlap used iter_records() and Similarity used the journals directory, so
the same Refine run could call a rule a 98% duplicate and say nothing like
it exists. Both now call build_corpus; Overlap explicitly skips entries
with no query rather than arriving at the right answer by accident.

Observable behaviour is unchanged — a journal-only draft has no MITRE and
was never in a technique cluster. The point is that the agreement is now a
property a test asserts."
```

---

### Task 5: Restore journal fidelity

Undo the censoring added while chasing the feedback loop. It is safe now: Refine blocks are excluded from the index by provenance, so the journal can record what was actually compared.

**Files:**
- Modify: `adef/orchestration/refine_chain.py` (`_JOURNAL_OMIT_KEYS`, `_inline` docstring, `append_block` call)
- Modify: `tests/test_refine_chain.py` (invert `test_rule_logic_never_reaches_the_journal`)
- Modify: `internal-docs/ISA.md`, `CLAUDE.md`
- Test: `tests/test_refine_chain.py`

**Interfaces:**
- Consumes: `Journal.append_block(..., generated=True)` (Task 1); provenance exclusion (Task 3).
- Produces: no new API.

- [ ] **Step 1: Write the failing tests**

In `tests/test_refine_chain.py`, replace `test_rule_logic_never_reaches_the_journal` with:

```python
def test_the_journal_records_what_was_compared(tmp_path):
    # Inverted deliberately. The predecessor of this test asserted the query
    # was ABSENT — correct while the journal fed the index, wrong now that
    # Refine blocks are excluded by provenance. A log that records *that*
    # D-0002 was shortlisted but not what either rule looked for is a worse
    # log, and it stripped the target's own query from its own journal.
    from adef.core.catalog import Catalog, CatalogRecord
    from adef.orchestration.refine_chain import run_refine_chain

    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")

    def _rec(rid, title, query):
        return CatalogRecord(
            id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
            platform="windows", kind="atomic", engine="sigma", format="sigma",
            query=query, mitre=["T1218.005"],
        )

    for rec in (
        _rec("D-0001", "mshta child process", "TARGETLOGIC process.name = 'mshta.exe'"),
        _rec("D-0002", "mshta spawning child", "NEIGHBOURLOGIC parent.name = 'excel.exe'"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    run_refine_chain(journal=journal, detection_id="D-0001", workspace=ws,
                     similarity_mode="agent")
    body = (ws / "journals" / "D-0001.md").read_text()

    assert "TARGETLOGIC" in body          # what was being refined
    assert "NEIGHBOURLOGIC" in body       # what it was compared against
    assert "snippet" not in body          # redundant with the fields beside it
    from adef.core.journal import GENERATED_MARKER
    assert GENERATED_MARKER in body       # and none of it will be indexed
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_refine_chain.py::test_the_journal_records_what_was_compared -v`
Expected: FAIL — `TARGETLOGIC` absent, because `_JOURNAL_OMIT_KEYS` still contains `"query"` and blocks are unmarked.

- [ ] **Step 3: Shrink the omit set and mark the blocks**

In `adef/orchestration/refine_chain.py`, replace the `_JOURNAL_OMIT_KEYS` block and its comment:

```python
# `snippet` is dropped from the journal render for one reason only: it is
# title + MITRE + platform + format + query concatenated, every part of which
# is already on the same line under its own label. It is noise in a log.
#
# It is NOT dropped to protect the retrieval index. That was the old
# justification and it was wrong twice over — a key-name denylist cannot make
# a claim about content, because the same text arrives under other keys. The
# index is protected by provenance now: `Journal.append_block(generated=True)`
# marks these blocks and `narrative_text` excludes them. See the corpus
# unification design doc.
_JOURNAL_OMIT_KEYS = frozenset({"snippet"})
```

Fix `_inline`'s docstring — delete the sentence beginning "The cap matters beyond readability" and replace with:

```python
    The cap is for free text that legitimately belongs here — an LLM judge's
    `reasoning`, a third-party step's prose — which reaches the renderer
    verbatim and can run long. Only the *rendered* form is collapsed and
    capped; callers still receive the value unchanged.
```

Mark the chain's blocks as generated — every `journal.append_block(...)` call in `run_refine_chain` (there are five: the wrapper-missing, success, `NoCatalogRecordError`, `WrapperUnavailable`, and generic-failure paths) gains `generated=True`:

```python
            journal.append_block(
                detection_id, step.heading,
                _format_payload(_prune_for_journal(result)), generated=True,
            )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/test_refine_chain.py -v`
Expected: all pass

- [ ] **Step 5: Update the docs that carry the old claim**

In `internal-docs/ISA.md`, the 2026-09-23 similarity-inversion entry states the feedback loop is closed by the omit set and that closing it fully "belongs with 10188's retrieval rework." Add a dated follow-up bullet recording that 10188 part 1 did close it, by provenance, and that `query` was restored.

In `CLAUDE.md`, add `corpus.py` to the `adef/core/` package-structure listing:

```
│   ├── corpus.py               # CorpusEntry + build_corpus — the one membership answer
```

- [ ] **Step 6: Run the full suite and linters**

Run: `pytest -q && ruff check adef/ tests/ && mypy adef/`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add adef/orchestration/refine_chain.py tests/test_refine_chain.py internal-docs/ISA.md CLAUDE.md
git commit -m "feat(refine): restore journal fidelity, mark blocks generated

The chain marks its blocks generated=True, so retrieval excludes them by
provenance and the journal no longer needs censoring. `query` returns for
the target and every candidate — stripping it left a log that recorded
*that* D-0002 was shortlisted but not what either rule looked for, and
removed the target's own query from its own journal.

_JOURNAL_OMIT_KEYS shrinks to {snippet}, kept for one honest reason: it is
title + MITRE + platform + format + query concatenated, all already on the
same line under their own labels."
```

---

## Self-Review

**Spec coverage.** Corpus model → Task 2. Indexed text and narrative definition → Tasks 1, 2. Provenance marking → Task 1. `MemoryIndex` corpus-agnostic + `_STAGE_BLOCK_RE` relocation → Task 3. Similarity consumer → Task 3. Overlap consumer → Task 4. `detection search` consumer → Task 3. Journal fidelity → Task 5. Migration (legacy fallback) → Task 1 Step 3, tested in Tasks 1 and 3. All eight spec test-table rows appear: union membership (T2), agreement invariant (T4), original bug end-to-end (T4), provenance (T3), legacy provenance (T1, T3), no fabricated paths (T2, T3), journal fidelity (T5), search reach (T3).

**Placeholder scan.** No TBD/TODO. Every code step carries the actual code. The only judgment left to the implementer is updating pre-existing `MemoryIndex(journals_dir=...)` tests in Task 3 Step 7, which is named explicitly as expected churn rather than left implicit.

**Type consistency.** `CorpusEntry` field and property names are identical across Tasks 2, 3, and 4. `build_corpus(workspace: Path) -> list[CorpusEntry]` has one signature throughout. `GENERATED_MARKER` and `narrative_text` are defined in Task 1 and imported unchanged thereafter. `SearchHit`'s shape is unchanged, so `memory_tools.py`'s response dict needs no edit beyond the index construction.

**Review Focus coverage.** Bare workspace → `test_bare_workspace_returns_nothing_and_creates_nothing` (T2). Unparseable artifacts → `test_unparseable_artifacts_are_skipped_not_fatal` (T2). Duplicate id → `test_same_id_in_two_platform_dirs_yields_one_entry` (T2). Template-only journal → `test_an_unadvanced_journal_does_not_break_scoring` (T3), with the `avgdl` guard in the implementation. Marker forgery / heading collision → `test_narrative_keeps_a_human_block_that_is_not_refine` plus the documented trust rule (T1).
