"""End-to-end tests for `adef sync` — the guarantee that re-syncing preserves
enrichment while refreshing changed rules."""

from __future__ import annotations

import textwrap

from click.testing import CliRunner

from adef.commands.catalog import catalog
from adef.commands.sync import sync
from adef.core.catalog import Catalog
from adef.core.journal import Journal


def _sigma(uuid: str, title: str = "Rundll32 no args") -> str:
    return textwrap.dedent(
        f"""\
        title: {title}
        id: {uuid}
        logsource:
            product: windows
        detection:
            condition: selection
        tags:
            - attack.t1218.011
        """
    )


def _make_repo(tmp_path):
    repo = tmp_path / "rules"
    repo.mkdir()
    (repo / "r.yml").write_text(_sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca"), encoding="utf-8")
    return repo


def _record(ws, det_id):
    for rid, _p, data in Catalog(ws).iter_records():
        if rid == det_id:
            return data
    raise AssertionError(f"{det_id} not found")


def test_sync_preserves_enrichment_on_modified(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    # Enrich: set MITRE + a manual status/owner on the record.
    path, data = Catalog(ws).find_record("D-0001")
    data["mitre"] = ["T1218.011"]
    data["status"] = "ready"
    data["owner"] = "alice"
    Catalog(ws).write_raw(path, data)

    # Change the source file (new content → new hash).
    (repo / "r.yml").write_text(
        _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca", title="Rundll32 no args v2"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0, result.output

    after = _record(ws, "D-0001")
    # Enrichment preserved:
    assert after["mitre"] == ["T1218.011"]
    assert after["status"] == "ready"
    assert after["owner"] == "alice"
    # Derived refreshed:
    assert after["title"] == "Rundll32 no args v2"


def test_sync_note_preserves_journal_stage(tmp_path, monkeypatch):
    """Journaling an out-of-band source change must NOT yank the detection to
    `evolve` — it stays at whatever FORGE stage it was in (CodeRabbit #97)."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    # Move the detection mid-lifecycle (to `refine`), not evolve.
    journal = Journal(ws / "journals")
    journal.advance_stage(detection_id="D-0001", stage="observe")
    journal.advance_stage(detection_id="D-0001", stage="refine")
    assert journal.read("D-0001").current_stage == "refine"

    # Source changes → sync journals the modification.
    (repo / "r.yml").write_text(
        _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca", title="Rundll32 v2"),
        encoding="utf-8",
    )
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0

    # Stage held at refine, not forced to evolve.
    assert journal.read("D-0001").current_stage == "refine"


def test_sync_orphans_deleted_rule(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (repo / "r.yml").unlink()  # rule gone from the repo

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0, result.output

    after = _record(ws, "D-0001")
    assert after["status"] == "deprecated"
    assert after.get("orphaned") is True
    # The record (and its "why") is kept, never deleted.


def test_sync_check_exits_nonzero_when_behind(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    assert CliRunner().invoke(sync, [str(repo), "--check"]).exit_code == 0  # current

    (repo / "r.yml").unlink()
    result = CliRunner().invoke(sync, [str(repo), "--check"])
    assert result.exit_code == 1  # behind
    # --check writes nothing: record is still its original (non-orphaned) form.
    assert _record(ws, "D-0001").get("orphaned") is not True


def test_sync_recreates_missing_journal(tmp_path, monkeypatch):
    """A matched record whose journal was deleted gets a fresh skeleton on sync,
    even when the source repo has no changes (the backfill-repair pass)."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    jpath = ws / "journals" / "D-0001.md"
    assert jpath.exists()
    jpath.unlink()

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0
    assert jpath.exists()
    text = jpath.read_text(encoding="utf-8")
    # Journal carries the record's real metadata, not bare defaults.
    assert "Rundll32 no args" in text
    assert "rule_uuid: 03cc0c25-389f-4bf8-b48d-11878079f1ca" in text
    assert "re-created by `adef sync`" in text
    entry = Journal(ws / "journals").read("D-0001")
    assert entry.frontmatter["current_stage"] == "find"


def test_sync_dry_run_does_not_recreate_journal(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (ws / "journals" / "D-0001.md").unlink()

    CliRunner().invoke(sync, [str(repo), "--dry-run"])
    assert not (ws / "journals" / "D-0001.md").exists()


def test_sync_check_does_not_recreate_journal(tmp_path, monkeypatch):
    """--check is read-only: a missing journal is not repaired, and with no
    source drift the exit code stays 0."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (ws / "journals" / "D-0001.md").unlink()

    result = CliRunner().invoke(sync, [str(repo), "--check"])
    assert result.exit_code == 0  # no drift
    assert not (ws / "journals" / "D-0001.md").exists()


def test_sync_repair_skips_malformed_record_ids(tmp_path, monkeypatch):
    """A hand-edited record id must never become a filesystem path."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    evil = ws / "catalog" / "windows" / "D-9999-evil.yml"
    evil.parent.mkdir(parents=True, exist_ok=True)
    evil.write_text("id: ../../escape\ntitle: evil\n", encoding="utf-8")

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0
    assert not (ws / "escape.md").exists()
    assert not (tmp_path / "escape.md").exists()
