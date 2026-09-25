"""Unit tests — BM25 memory search.

``MemoryIndex`` takes ``CorpusEntry`` objects (see ``adef.core.corpus``), not a
journals directory — these tests build a corpus via ``build_corpus(workspace)``
for the filesystem-backed cases, or a hand-built ``[CorpusEntry(...)]`` list
when a test's point is ``MemoryIndex.build()``'s own behavior (scoring
``entry.index_text``) rather than corpus traversal.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from adef.core.corpus import CorpusEntry, build_corpus
from adef.core.journal import Journal, JournalEntry
from adef.core.memory import MemoryIndex


@pytest.fixture
def populated_journal(tmp_path):
    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="Suspicious mshta", owner="sydney")
    journal.advance_stage("D-0001", "observe", note="powershell parent observed")
    journal.create("D-0002", title="Okta MFA bypass", owner="sydney")
    journal.advance_stage("D-0002", "observe", note="identity logs from Okta tenant")
    return journal


def test_search_returns_relevant_journal(populated_journal):
    index = MemoryIndex()
    index.build(build_corpus(populated_journal.directory.parent))
    hits = index.search("okta")
    assert hits, "expected at least one hit for 'okta'"
    assert hits[0].detection_id == "D-0002"


def test_search_zero_hits_for_nonexistent_term(populated_journal):
    index = MemoryIndex()
    index.build(build_corpus(populated_journal.directory.parent))
    assert index.search("zzzzz-no-such-term") == []


def test_search_empty_workspace(tmp_path):
    Journal(tmp_path / "journals")  # side effect: scaffolds an empty journals/ dir
    index = MemoryIndex()
    index.build(build_corpus(tmp_path))
    assert index.search("anything") == []


def test_snippet_prefers_real_content_over_boilerplate(tmp_path):
    """The snippet should surface the matched note, not the empty template
    scaffolding or the 'Catalogued from…' housekeeping line (ISA 2026-07-22).

    The housekeeping note is marked `generated=True` here, matching the real
    `adef catalog`/`adef sync` call sites (10188 follow-up item 2) — the
    content-based "Catalogued from ... adef ..." filter this test used to
    rely on is gone; provenance is what excludes it now."""
    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="Beacon rule",
                   note="Catalogued from repo/x.conf by `adef catalog`.", generated=True)
    journal.advance_stage("D-0001", "observe",
                          note="beaconing to known C2 over DNS TXT records")
    index = MemoryIndex()
    index.build(build_corpus(journal.directory.parent))
    hit = index.search("beaconing C2")[0]
    assert "beaconing to known C2" in hit.snippet
    assert "Catalogued from" not in hit.snippet          # housekeeping stripped
    assert "Successor rule" not in hit.snippet            # empty template stripped


def test_extra_text_makes_sparse_journal_findable(tmp_path):
    """A detection with a sparse journal but a rich catalog record (mitre,
    platform) is still findable via the record's text — search should answer
    'what do we detect?', not just 'what did someone journal?' (ISA 2026-07-22).

    Formerly exercised via ``MemoryIndex.build(extra_text_for=...)``, which is
    gone — the record/journal join now happens once, in
    ``CorpusEntry.index_text`` (Task 2), so this builds ``CorpusEntry`` objects
    directly rather than going through ``build_corpus``.

    Needs a positive control alongside the negative one (r1 review,
    Important): an entry whose ``index_text`` is empty returns ``[]`` for
    *every* query, so "lsass" absent alone doesn't distinguish "the join is
    missing" from "nothing is indexed at all." Advancing the journal with a
    real, lsass-unrelated note and confirming that note IS findable rules the
    second case out.
    """
    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="Cred dump rule")
    journal.advance_stage("D-0001", "observe", note="PARENTPROCTOKEN spawned by explorer.exe")
    journal_entry = journal.read("D-0001")

    # Positive control: the journal alone has real, indexed content...
    index = MemoryIndex()
    index.build([CorpusEntry(detection_id="D-0001", journal=journal_entry)])
    hits = index.search("PARENTPROCTOKEN")
    assert hits and hits[0].detection_id == "D-0001"
    # ...negative control: that content still says nothing about lsass.
    assert index.search("lsass") == []

    # With the catalog record's searchable text joined in, it's findable.
    record = {
        "title": "Cred dump rule",
        "mitre": ["T1003.001"],
        "platform": "windows",
        "data_source": "",
        "format": "",
        "query": "lsass memory read",
    }
    index.build([
        CorpusEntry(
            detection_id="D-0001",
            record=record,
            record_path=tmp_path / "catalog" / "D-0001.yml",
            journal=journal_entry,
        )
    ])
    hits = index.search("lsass windows")
    assert hits and hits[0].detection_id == "D-0001"


def _plain_entry(detection_id: str, text: str) -> CorpusEntry:
    # A `## [ts] Stage:` body whose stage content is exactly `text` (no
    # title, no record) — narrative_text passes it through untouched, so the
    # resulting index_text token counts are exactly under test's control.
    body = f"## [2026-09-24T10:00:00-04:00] Stage: observe\n\n{text}\n"
    entry = JournalEntry(path=Path(f"/tmp/{detection_id}.md"), frontmatter={"title": ""}, body=body)
    return CorpusEntry(detection_id=detection_id, journal=entry)


def test_zero_length_docs_do_not_reorder_a_multiterm_query():
    # 10188 follow-up item 3: `_idf`'s `n` used to include zero-length docs
    # (`len(self._docs)`) while `avgdl` already excluded them — the
    # inconsistency inflates `n`, compressing idf's relative weighting
    # between a rare and a common query term enough to reorder a multi-term
    # query. Three real docs establish the asymmetric df this needs: only
    # D-000A has "rare" (df=1), D-000B and D-000C both have "common" (df=2).
    docs = [
        _plain_entry("D-000A", "rare filler"),   # rare x1, len 2
        _plain_entry("D-000B", "common"),        # common x1, len 1
        _plain_entry("D-000C", "common"),        # common x1, len 1 (df(common)=2)
    ]
    index = MemoryIndex()
    index.build(docs)
    hits = index.search("rare common")
    order_before = [h.detection_id for h in hits if h.detection_id in ("D-000A", "D-000B")]
    assert order_before == ["D-000A", "D-000B"]  # the rarer term wins

    # 20 zero-length "documents" (drafts with nothing indexable yet) must not
    # change that relative order.
    padded = docs + [
        CorpusEntry(detection_id=f"D-EMPTY{i}") for i in range(20)
    ]
    index2 = MemoryIndex()
    index2.build(padded)
    hits2 = index2.search("rare common")
    order_after = [h.detection_id for h in hits2 if h.detection_id in ("D-000A", "D-000B")]
    assert order_after == order_before
