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
