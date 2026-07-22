"""End-to-end tests for `adef sync` — the guarantee that re-syncing preserves
enrichment while refreshing changed rules."""

from __future__ import annotations

import textwrap

from click.testing import CliRunner

from adef.commands.catalog import catalog
from adef.commands.sync import sync
from adef.core.catalog import Catalog


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
