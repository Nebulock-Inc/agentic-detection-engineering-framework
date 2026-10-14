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


def test_refine_chain_not_rerun_on_idempotent_note(tmp_path, monkeypatch):
    """`refine --note` on a detection already at refine appends the note only —
    re-running the chain spammed duplicate Similarity/Overlap/Verification
    blocks into the journal (two triplets a minute apart).
    `--chain` forces a re-run explicitly."""
    from click.testing import CliRunner

    from adef.commands.detection import detection as detection_cli

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    runner = CliRunner()
    assert runner.invoke(detection_cli, ["new", "T", "--workspace", str(ws)]).exit_code == 0

    r = runner.invoke(detection_cli, ["refine", "D-0001", "--workspace", str(ws)])
    assert r.exit_code == 0, r.output
    journal_text = (ws / "journals" / "D-0001.md").read_text(encoding="utf-8")
    first_count = journal_text.count("### Refine / Similarity")
    assert first_count == 1

    r = runner.invoke(detection_cli, ["refine", "D-0001", "--workspace", str(ws), "--note", "n"])
    assert r.exit_code == 0, r.output
    assert "chain skipped" in r.output
    journal_text = (ws / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert journal_text.count("### Refine / Similarity") == 1  # no duplicate

    r = runner.invoke(detection_cli, ["refine", "D-0001", "--workspace", str(ws), "--chain"])
    assert r.exit_code == 0, r.output
    journal_text = (ws / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert journal_text.count("### Refine / Similarity") == 2  # explicit re-run


def test_backward_stage_move_is_refused_unless_allowed(tmp_path):
    # `detection observe` on a refined rule rewound it silently.
    j = Journal(tmp_path)
    j.create(detection_id="D-0001", title="t")
    j.advance_stage("D-0001", "refine")
    with pytest.raises(JournalError, match="back to observe"):
        j.advance_stage("D-0001", "observe", note="late note")
    entry = j.read("D-0001")
    assert entry.current_stage == "refine"
    assert "late note" not in entry.body
    result = j.advance_stage("D-0001", "observe", allow_backward=True)
    assert result.was_idempotent is False
    assert j.read("D-0001").current_stage == "observe"


def test_forward_and_same_stage_moves_need_no_flag(tmp_path):
    j = Journal(tmp_path)
    j.create(detection_id="D-0001", title="t")
    j.advance_stage("D-0001", "govern")  # skipping ahead is fine
    assert j.advance_stage("D-0001", "govern", note="n").was_idempotent
