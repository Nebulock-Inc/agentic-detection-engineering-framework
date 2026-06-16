"""Unit tests for ``adef.core.journal``."""

from __future__ import annotations

import pytest

from adef.core.journal import (
    FORGE_STAGES,
    Journal,
    JournalError,
    next_detection_id,
    workspace_journals_dir,
)


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journals")


def test_forge_stages_order():
    assert FORGE_STAGES == ("find", "observe", "refine", "govern", "evolve")


def test_create_journal_writes_at_find_stage(journal):
    entry = journal.create("D-0001", title="Suspicious mshta", owner="sydney")
    assert entry.path.exists()
    assert entry.frontmatter["id"] == "D-0001"
    assert entry.frontmatter["current_stage"] == "find"
    assert entry.frontmatter["owner"] == "sydney"
    body = entry.path.read_text()
    assert "## [" in body and "Stage: find" in body


def test_create_refuses_duplicate(journal):
    journal.create("D-0001", title="X")
    with pytest.raises(JournalError):
        journal.create("D-0001", title="X")


def test_advance_through_all_stages(journal):
    journal.create("D-0001", title="X")
    for stage in ("observe", "refine", "govern", "evolve"):
        result = journal.advance_stage("D-0001", stage)
        assert result.stage == stage
        assert not result.was_idempotent
    entry = journal.read("D-0001")
    assert entry.current_stage == "evolve"


def test_advance_is_idempotent(journal):
    journal.create("D-0001", title="X")
    journal.advance_stage("D-0001", "observe")
    result = journal.advance_stage("D-0001", "observe", note="re-ran")
    assert result.was_idempotent is True


def test_advance_rejects_unknown_stage(journal):
    journal.create("D-0001", title="X")
    with pytest.raises(JournalError):
        journal.advance_stage("D-0001", "ship-it")


def test_next_detection_id_increments(journal):
    assert next_detection_id(journal.directory) == "D-0001"
    journal.create("D-0001", title="X")
    assert next_detection_id(journal.directory) == "D-0002"


def test_find_by_rule_uuid(journal):
    journal.create("D-0001", title="X", rule_uuid="abc-123")
    journal.create("D-0002", title="Y", rule_uuid="xyz-789")
    found = journal.find_by_rule_uuid("xyz-789")
    assert found is not None and found.detection_id == "D-0002"
    assert journal.find_by_rule_uuid("nope") is None


def test_workspace_resolution_prefers_explicit(tmp_path, monkeypatch):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "from-env"))
    explicit = tmp_path / "explicit"
    journals = workspace_journals_dir(explicit)
    assert journals == (explicit / "journals").resolve()


def test_append_block_records_under_current_stage(journal):
    journal.create("D-0001", title="X")
    journal.advance_stage("D-0001", "refine")
    journal.append_block("D-0001", "Refine / Similarity", "- score: 0.8")
    body = journal.read("D-0001").body
    assert "### Refine / Similarity" in body and "score: 0.8" in body
