"""Per-detection markdown journal — the core memory primitive of ADEF.

A *journal* is a markdown file at ``<workspace>/journals/D-XXXX.md`` paired
with an upstream detection rule (or pending — Find stage may exist before a
rule is written). It carries YAML frontmatter for machine-readable state and
one ``## [<ISO-8601>] Stage: <stage>`` block per FORGE transition.

Hard invariant: ``Journal`` never opens or writes any path that resolves
under a ``detections/`` directory. A journal lives in the ADEF workspace;
upstream rules live in their own repository. The two are paired by
``rule_uuid`` in frontmatter.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Iterable, Optional

import yaml


FORGE_STAGES: tuple[str, ...] = ("find", "observe", "refine", "govern", "evolve")
"""The five FORGE lifecycle stages, in order."""


_DETECTION_ID_RE = re.compile(r"^D-(\d{4,})$")
_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)

GENERATED_MARKER = "<!-- adef:generated -->"

# The first timestamped stage block ends the static template preamble.
# `narrative_text` filters the preamble and the stage area by different
# rules — see `_preamble_narrative_lines` for why fill-state alone isn't
# enough there. Moved here from memory.py: the journal module owns its own
# format, and leaving block structure in the search layer is what made
# "which blocks are machine output?" hard to answer.
_STAGE_BLOCK_RE = re.compile(r"^## \[.+?\] Stage:", re.MULTILINE)

# A `### ` sub-block inside a stage block. Refine results land here.
_SUB_BLOCK_RE = re.compile(r"^### ", re.MULTILINE)

# Journals written before GENERATED_MARKER existed carry no marker. This
# prefix identifies them. Permanent fallback, not a migration step.
_LEGACY_GENERATED_HEADING = "### Refine / "

# A template fill-in line: `- **Field:** value`. Matched against a single
# already-stripped line so it can be checked in the same per-line pass as
# every other filter in narrative_text.
_FIELD_LINE_RE = re.compile(r"^-\s+\*\*[^*]+:\*\*\s*(.*)$")


def _is_generated_block(block: str) -> bool:
    """True when this ``### `` sub-block was written by ADEF, not a human."""
    return GENERATED_MARKER in block or block.startswith(_LEGACY_GENERATED_HEADING)


def _is_unfilled_field_line(line: str) -> bool:
    """True for a template placeholder (`- **Field:**`) with nothing typed
    after the colon. The same line with a value filled in is reasoning a
    human wrote, not scaffolding."""
    m = _FIELD_LINE_RE.match(line)
    return m is not None and not m.group(1).strip()


def _filled_field_line_or_none(line: str) -> Optional[str]:
    """The line itself if it's a `- **Field:** value` line with a value,
    else ``None``."""
    m = _FIELD_LINE_RE.match(line)
    if m is not None and m.group(1).strip():
        return line
    return None


def _preamble_narrative_lines(preamble: str) -> list[str]:
    """The preamble (everything before the first timestamped stage block) is
    the template's own fill-in section — `Journal.create` writes it once,
    verbatim, before any stage block exists. Unlike the stage area, it is
    *whitelisted*, not blacklisted: keep ONLY a filled `- **Field:** value`
    line. Everything else there — plain-prose section descriptions
    ("Tune, deprecate, replace. Detections never finish — they iterate."),
    headings, blockquotes, unfilled placeholders — is template boilerplate,
    byte-identical in every journal ADEF has ever created (including the
    skeleton journal `adef catalog` pairs with every catalogued rule), so a
    filter that lets any of it through makes every detection in a workspace
    look alike on the template's own words (r2 review, Important). A
    position-only rule would silently drop a filled field just because it
    lives above the first stage block; a fill-state-only rule (r1's mistake)
    lets the unstructured prose through. Only intersecting both catches
    exactly the boilerplate and nothing else.
    """
    lines = []
    for line in preamble.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        kept = _filled_field_line_or_none(stripped)
        if kept is not None:
            lines.append(kept)
    return lines


def narrative_text(body: str) -> str:
    """The human-authored prose in a journal body, for indexing.

    Drops: the static template preamble (position-based — see
    `_preamble_narrative_lines`, which whitelists only its filled
    `- **Field:** value` lines and drops everything else there, plain prose
    included), unfilled placeholders and other scaffolding within the stage
    area (fill-state/content-based), every machine-generated sub-block, and
    `Catalogued from…` housekeeping. What remains is reasoning a person or an
    agent wrote deliberately — the only journal content that can be evidence
    without feeding retrieval its own output.

    The preamble and the stage area are filtered differently on purpose.
    `Journal.create` writes the preamble once, verbatim from the shipped
    template, before the Find block is ever appended — so a user who fills in
    `- **Baseline of normal:** ...` there (the normal way to answer the
    template's own prompts) must not have that answer silently excluded (r1
    review), but the section's plain-prose descriptions must never reach the
    index either, because they are byte-identical in every journal ADEF has
    ever created (r2 review). The stage area has no such guaranteed
    boilerplate — a stage block is appended once, per transition, with
    whatever a human (or an agent, for a non-generated sub-block) actually
    wrote — so it keeps the permissive, content-based rule: drop known
    scaffolding (headings, blockquotes, the echoed title, housekeeping,
    generated sub-blocks by provenance), keep everything else.
    """
    m = _STAGE_BLOCK_RE.search(body)
    preamble = body[: m.start()] if m else body
    stage_area = body[m.start():] if m else ""

    # Split the stage area into sub-blocks, keeping any text before the first
    # `### ` heading (that is stage-block prose, which is human by
    # definition).
    pieces: list[str] = []
    last = 0
    for match in _SUB_BLOCK_RE.finditer(stage_area):
        pieces.append(stage_area[last:match.start()])
        last = match.start()
    pieces.append(stage_area[last:])

    kept = [p for p in pieces if not _is_generated_block(p)]

    lines: list[str] = _preamble_narrative_lines(preamble)
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
        if _is_unfilled_field_line(stripped):
            continue
        lines.append(stripped)
    return "\n".join(lines)


class JournalError(RuntimeError):
    """Base error for journal operations."""


class HardInvariantViolation(JournalError):
    """Raised if a journal path would resolve inside a rule ``detections/`` tree."""


@dataclass(frozen=True)
class StageAdvanceResult:
    """Outcome of ``Journal.advance_stage``."""

    detection_id: str
    stage: str
    was_idempotent: bool
    timestamp: str


def _now_iso() -> str:
    """Return current time as an ISO-8601 string with second precision and TZ."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _atomic_write(target: Path, content: str) -> None:
    """Write ``content`` to ``target`` via a temp file + rename (POSIX atomic)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".adef-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _check_not_under_detections(path: Path) -> None:
    """Raise if ``path`` resolves anywhere under a rule ``detections/`` tree.

    ADEF journals live in the workspace ``journals/`` directory. Any path that
    sits inside an upstream rule repository (whose convention is a top-level
    ``detections/`` directory) is read-only for ADEF — the journal layer must
    never write there.
    """
    parts = path.resolve().parts
    if "detections" in parts:
        raise HardInvariantViolation(
            f"adef.core.journal refused to touch {path} — paths under any "
            "rule 'detections/' directory are read-only for ADEF."
        )


def workspace_journals_dir(workspace: Optional[Path], create: bool = True) -> Path:
    """Resolve the journals directory for ``workspace``.

    Delegates workspace resolution to the canonical ``resolve_workspace`` (one
    resolver for every command — ISA 2026-07-22) so ``adef catalog .`` and
    ``adef detection list`` in the same dir never disagree about *which*
    workspace they mean.

    ``create=True`` (default, for write paths) ensures ``journals/`` exists;
    **read paths must pass ``create=False``** so listing/showing never silently
    scaffolds ``~/work/adef-workspace`` as a side effect.
    """
    from adef.core.workspace import resolve_workspace

    ws = resolve_workspace(workspace)
    journals = ws / "journals"
    if create:
        journals.mkdir(parents=True, exist_ok=True)
    return journals


def next_detection_id(journals_dir: Path) -> str:
    """Return ``D-<next>`` where ``<next>`` is one greater than the max existing index."""
    max_idx = 0
    for child in journals_dir.glob("D-*.md"):
        m = _DETECTION_ID_RE.match(child.stem)
        if m:
            max_idx = max(max_idx, int(m.group(1)))
    return f"D-{max_idx + 1:04d}"


def _load_template_text() -> str:
    """Return the package-data DETECTION_FORGE.md template as a string."""
    return (
        resources.files("adef.data.templates")
        .joinpath("DETECTION_FORGE.md")
        .read_text(encoding="utf-8")
    )


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split markdown ``text`` into (frontmatter dict, body string)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    fm = yaml.safe_load(m.group(1)) or {}
    body = text[m.end() :]
    return fm, body


def _join_frontmatter(fm: dict, body: str) -> str:
    """Re-serialize ``fm`` + ``body`` into a frontmatter+markdown document."""
    head = yaml.safe_dump(fm, sort_keys=False).strip()
    return f"---\n{head}\n---\n{body}" if not body.startswith("\n") else f"---\n{head}\n---{body}"


@dataclass
class JournalEntry:
    """In-memory representation of a single journal."""

    path: Path
    frontmatter: dict
    body: str

    @property
    def detection_id(self) -> str:
        return str(self.frontmatter.get("id", self.path.stem))

    @property
    def current_stage(self) -> str:
        return str(self.frontmatter.get("current_stage", "find"))

    @property
    def rule_uuid(self) -> str:
        return str(self.frontmatter.get("rule_uuid", "") or "")


class Journal:
    """File-system-backed CRUD for ``D-XXXX.md`` journal files.

    Each ``Journal`` instance is bound to a journals directory. Operations on
    individual detections take their id; the class never holds per-detection
    state across calls.
    """

    def __init__(self, journals_dir: Path) -> None:
        _check_not_under_detections(journals_dir)
        self._dir = journals_dir.expanduser().resolve()
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._dir

    def _path_for(self, detection_id: str) -> Path:
        # Every journal read/write routes through here: reject anything that
        # isn't an ADEF-minted id so a hand-edited record id ("../x", an
        # absolute path) can never become a path outside journals/.
        if not _DETECTION_ID_RE.fullmatch(detection_id):
            raise JournalError(f"Invalid detection id {detection_id!r} (expected D-XXXX).")
        candidate = self._dir / f"{detection_id}.md"
        _check_not_under_detections(candidate)
        return candidate

    def create(
        self,
        detection_id: str,
        title: str,
        owner: str = "",
        rule_uuid: str = "",
        note: str = "",
    ) -> JournalEntry:
        """Create a new journal at the Find stage. Returns the populated entry."""
        path = self._path_for(detection_id)
        if path.exists():
            raise JournalError(f"Journal {path} already exists.")

        template = _load_template_text()
        fm_template, body_template = _split_frontmatter(template)
        ts = _now_iso()
        fm = {
            **fm_template,
            "id": detection_id,
            "title": title,
            "status": "draft",
            "current_stage": "find",
            "owner": owner,
            "rule_uuid": rule_uuid,
            "created": ts,
            "updated": ts,
        }
        # Lean Find block, consistent with the other stages — the Find guidance
        # lives in the template's `## Find` fill-in section, not re-printed here.
        find_block = (
            f"\n## [{ts}] Stage: find\n\n"
            f"**Title:** {title}\n\n"
            + (f"{note}\n" if note else "")
        )
        text = _join_frontmatter(fm, body_template.rstrip() + "\n" + find_block)
        _atomic_write(path, text)
        return JournalEntry(path=path, frontmatter=fm, body=body_template + find_block)

    def read(self, detection_id: str) -> JournalEntry:
        """Read an existing journal."""
        path = self._path_for(detection_id)
        if not path.exists():
            raise JournalError(f"Journal {path} not found.")
        text = path.read_text(encoding="utf-8")
        fm, body = _split_frontmatter(text)
        return JournalEntry(path=path, frontmatter=fm, body=body)

    def advance_stage(
        self,
        detection_id: str,
        stage: str,
        note: str = "",
    ) -> StageAdvanceResult:
        """Advance the journal to ``stage``, append a stage block, return outcome.

        Idempotent: re-advancing to the same stage emits a stderr warning and
        does not append a duplicate block (a note, if given, is still added as
        a sub-block within the existing stage).
        """
        if stage not in FORGE_STAGES:
            raise JournalError(f"Unknown stage {stage!r}. Expected one of {FORGE_STAGES}.")

        entry = self.read(detection_id)
        ts = _now_iso()
        was_idempotent = entry.current_stage == stage

        if was_idempotent:
            print(
                f"[adef.journal] {detection_id} already at stage {stage}; "
                f"appending note only.",
                file=sys.stderr,
            )
            new_body = entry.body
            if note:
                new_body = entry.body.rstrip() + f"\n\n_Note ({ts}):_ {note}\n"
        else:
            # A lean transition record: timestamp + note. The FORGE guidance
            # (what to capture at each stage) lives once in the template's
            # fill-in sections — re-printing the prompt prose in every block
            # duplicated it and buried the actual notes (ISA 2026-07-22).
            block = (
                f"\n## [{ts}] Stage: {stage}\n\n"
                + (f"{note}\n" if note else "_(no note)_\n")
            )
            new_body = entry.body.rstrip() + "\n" + block

        new_fm = {
            **entry.frontmatter,
            "current_stage": stage,
            "updated": ts,
        }
        _atomic_write(entry.path, _join_frontmatter(new_fm, new_body))
        return StageAdvanceResult(
            detection_id=detection_id,
            stage=stage,
            was_idempotent=was_idempotent,
            timestamp=ts,
        )

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

    def iter_entries(self) -> Iterable[JournalEntry]:
        """Yield every journal in the directory."""
        for child in sorted(self._dir.glob("D-*.md")):
            text = child.read_text(encoding="utf-8")
            fm, body = _split_frontmatter(text)
            yield JournalEntry(path=child, frontmatter=fm, body=body)

    def find_by_rule_uuid(self, rule_uuid: str) -> Optional[JournalEntry]:
        """Return the journal paired with ``rule_uuid``, or ``None``."""
        if not rule_uuid:
            return None
        for entry in self.iter_entries():
            if entry.rule_uuid == rule_uuid:
                return entry
        return None

    def max_detection_index(self) -> int:
        """Return the highest existing D-XXXX index, or 0."""
        max_idx = 0
        for child in self._dir.glob("D-*.md"):
            m = _DETECTION_ID_RE.match(child.stem)
            if m:
                max_idx = max(max_idx, int(m.group(1)))
        return max_idx


__all__ = [
    "FORGE_STAGES",
    "GENERATED_MARKER",
    "Journal",
    "JournalEntry",
    "JournalError",
    "HardInvariantViolation",
    "StageAdvanceResult",
    "narrative_text",
    "next_detection_id",
    "workspace_journals_dir",
]
