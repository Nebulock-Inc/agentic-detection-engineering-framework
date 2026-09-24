"""Unit tests — BM25 memory search.

``MemoryIndex`` takes ``CorpusEntry`` objects (see ``adef.core.corpus``), not a
journals directory — these tests build a corpus via ``build_corpus(workspace)``
for the filesystem-backed cases, or a hand-built ``[CorpusEntry(...)]`` list
when a test's point is ``MemoryIndex.build()``'s own behavior (scoring
``entry.index_text``) rather than corpus traversal.
"""

from __future__ import annotations

import pytest

from adef.core.corpus import CorpusEntry, build_corpus
from adef.core.journal import Journal
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
    scaffolding or the 'Catalogued from…' housekeeping line (ISA 2026-07-22)."""
    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="Beacon rule",
                   note="Catalogued from repo/x.conf by `adef catalog`.")
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
    """
    journal_entry = Journal(tmp_path / "journals").create("D-0001", title="Cred dump rule")

    # Journal alone (no catalog record) says nothing about lsass.
    index = MemoryIndex()
    index.build([CorpusEntry(detection_id="D-0001", journal=journal_entry)])
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
