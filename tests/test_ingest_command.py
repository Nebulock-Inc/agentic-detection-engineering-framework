"""Tests for `adef ingest` (adef/commands/ingest.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.ingest import ingest as ingest_cli
from adef.core.catalog import Catalog, CatalogRecord


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    cat = Catalog(ws)
    rec = CatalogRecord(
        id="D-0042", title="mshta child", rule_ref="r/d42.yml",
        original_path="/tmp/d42.yml", platform="windows", kind="atomic",
        engine="sigma", format="sigma", query="process.name='mshta.exe'",
    )
    cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    return ws


def _write_doc(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _metrics_doc(detection_id: str = "D-0042") -> dict:
    return {
        "schema_version": 1,
        "kind": "metrics",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "detections": [{"detection_id": detection_id, "signal_count": 143}],
    }


def test_ingest_writes_and_reports(workspace: Path, tmp_path: Path):
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc())
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "metrics" in result.output
    assert "D-0042" in result.output or "1 matched" in result.output
    stored = yaml.safe_load(
        (workspace / "health" / "latest" / "D-0042.yml").read_text(encoding="utf-8")
    )
    assert stored["metrics"]["signal_count"] == 143


def test_ingest_routes_on_the_documents_own_kind(workspace: Path, tmp_path: Path):
    # No --kind flag exists; the file says what it is.
    drift = {
        "schema_version": 1,
        "kind": "deployment_drift",
        "captured_at": "2026-09-21T14:00:00Z",
        "environment": "prod-siem",
        "detections": [{"detection_id": "D-0042", "deployed_status": "enabled"}],
    }
    doc = _write_doc(tmp_path / "d.yml", drift)
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    stored = yaml.safe_load(
        (workspace / "health" / "latest" / "D-0042.yml").read_text(encoding="utf-8")
    )
    assert stored["deployment_drift"]["deployed_status"] == "enabled"


def test_dry_run_writes_nothing(workspace: Path, tmp_path: Path):
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc())
    result = CliRunner().invoke(
        ingest_cli, [str(doc), "--workspace", str(workspace), "--dry-run"]
    )

    assert result.exit_code == 0, result.output
    assert not (workspace / "health").exists()


def test_unmatched_ids_are_reported_in_output(workspace: Path, tmp_path: Path):
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc(detection_id="D-9999"))
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "D-9999" in result.output
    assert "unmatched" in result.output.lower()


def test_invalid_document_is_a_clean_error_not_a_traceback(workspace: Path, tmp_path: Path):
    bad = _metrics_doc()
    bad["kind"] = "made_up"
    doc = _write_doc(tmp_path / "bad.yml", bad)
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code != 0
    assert "made_up" in result.output
    assert "Traceback" not in result.output


def test_missing_file_is_a_clean_error(workspace: Path, tmp_path: Path):
    result = CliRunner().invoke(
        ingest_cli, [str(tmp_path / "nope.yml"), "--workspace", str(workspace)]
    )
    assert result.exit_code != 0
    assert "Traceback" not in result.output
