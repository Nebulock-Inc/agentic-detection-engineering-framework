"""Unit tests — BM25 memory search."""

from __future__ import annotations

import pytest

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
    index = MemoryIndex(journals_dir=populated_journal.directory)
    hits = index.search("okta")
    assert hits, "expected at least one hit for 'okta'"
    assert hits[0].detection_id == "D-0002"


def test_search_zero_hits_for_nonexistent_term(populated_journal):
    index = MemoryIndex(journals_dir=populated_journal.directory)
    assert index.search("zzzzz-no-such-term") == []


def test_search_empty_workspace(tmp_path):
    journal = Journal(tmp_path / "journals")
    index = MemoryIndex(journals_dir=journal.directory)
    assert index.search("anything") == []


def test_snippet_prefers_real_content_over_boilerplate(tmp_path):
    """The snippet should surface the matched note, not the empty template
    scaffolding or the 'Catalogued from…' housekeeping line (ISA 2026-07-22)."""
    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="Beacon rule",
                   note="Catalogued from repo/x.conf by `adef catalog`.")
    journal.advance_stage("D-0001", "observe",
                          note="beaconing to known C2 over DNS TXT records")
    index = MemoryIndex(journals_dir=journal.directory)
    hit = index.search("beaconing C2")[0]
    assert "beaconing to known C2" in hit.snippet
    assert "Catalogued from" not in hit.snippet          # housekeeping stripped
    assert "Successor rule" not in hit.snippet            # empty template stripped


def test_extra_text_makes_sparse_journal_findable(tmp_path):
    """A detection with a sparse journal but a rich catalog record (mitre,
    platform) is still findable via the extra_text hook — search should answer
    'what do we detect?', not just 'what did someone journal?' (ISA 2026-07-22)."""
    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="Cred dump rule")  # journal says nothing about lsass
    index = MemoryIndex(journals_dir=journal.directory)

    # Without the record text, "lsass" doesn't match.
    index.build()
    assert index.search("lsass") == []

    # Feed the catalog record's searchable text per entry.
    record_text = {"D-0001": "T1003.001 credential access windows lsass memory"}
    index.build(extra_text_for=lambda e: record_text.get(e.detection_id, ""))
    hits = index.search("lsass windows")
    assert hits and hits[0].detection_id == "D-0001"
