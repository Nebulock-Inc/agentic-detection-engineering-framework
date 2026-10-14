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


def test_dry_run_creates_no_directories_in_a_bare_workspace(tmp_path: Path):
    # A workspace that does not even exist yet, and so has no catalog/ —
    # regression for known_ids-gathering constructing Catalog(ws), whose
    # __init__ mkdirs catalog/ regardless of --dry-run.
    bare_ws = tmp_path / "bare-ws"
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc())
    result = CliRunner().invoke(
        ingest_cli, [str(doc), "--workspace", str(bare_ws), "--dry-run"]
    )

    assert result.exit_code == 0, result.output
    assert "D-0042" in result.output
    assert "unmatched" in result.output.lower()
    assert not bare_ws.exists()


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


def test_bare_workspace_reports_no_catalog_instead_of_the_catalog_does_not_have(
    tmp_path: Path,
):
    # A workspace with no catalog/ at all (e.g. --dry-run from the wrong cwd)
    # should say so plainly rather than the misleading "the catalog does not
    # have" phrasing, which implies a catalog was consulted.
    bare_ws = tmp_path / "bare-ws"
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc())
    result = CliRunner().invoke(
        ingest_cli, [str(doc), "--workspace", str(bare_ws), "--dry-run"]
    )

    assert result.exit_code == 0, result.output
    output_flat = result.output.replace("\n", "")
    assert "no catalog at" in output_flat
    assert str(bare_ws / "catalog") in output_flat
    assert "the catalog does not have" not in output_flat


def test_populated_workspace_keeps_the_catalog_does_not_have_phrasing(
    workspace: Path, tmp_path: Path
):
    doc = _write_doc(tmp_path / "m.yml", _metrics_doc(detection_id="D-9999"))
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "the catalog does not have" in result.output
    assert "no catalog at" not in result.output


def test_ingest_warns_about_a_misspelled_count_key(workspace: Path, tmp_path: Path):
    # The quietest failure in the format: the row matches, the number stores,
    # and nothing derives from it. Reported, never fatal.
    bad = _metrics_doc()
    bad["detections"] = [
        {
            "detection_id": "D-0042",
            "signal_count": 500,
            "false_positives_count": 480,
            "true_positive_count": 2,
        }
    ]
    doc = _write_doc(tmp_path / "typo.yml", bad)
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "1 matched" in result.output
    assert "false_positives_count" in result.output
    assert "false_positive_count" in result.output


def test_a_near_miss_row_key_survives_rich_markup(workspace: Path, tmp_path: Path):
    """The warning interpolates a row key straight out of the capture document.

    The line carries its own `[yellow]` tag, so markup has to stay on and the
    producer's string has to be escaped instead. Unescaped, Rich reads `[bold]`
    as a style tag and *deletes* it — the warning then names a key the producer
    cannot find in their file, which is the one thing it exists to tell them —
    and a malformed tag raises `MarkupError` out of `adef ingest`.

    Row keys are the reachable half of this. The unmatched-id line is escaped
    for the same reason but cannot be reached from a document: lint rejects a
    non-`D-XXXX` `detection_id` before ingest runs, so only a hand-constructed
    `HealthDoc` could put arbitrary text there. Escaped anyway, untested on
    purpose rather than by oversight.

    The key has to be a near-miss of a *read* key or no warning is emitted at
    all, which is why it is a markup-prefixed `false_positives_count` and not
    an arbitrary string.
    """
    doc_data = _metrics_doc()
    doc_data["detections"] = [
        {"detection_id": "D-0042", "[bold]false_positive_count": 480},
    ]
    doc = _write_doc(tmp_path / "markup.yml", doc_data)
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert result.exception is None, result.exception
    assert "ignored key" in result.output, result.output
    assert "[bold]false_positive_count" in result.output, result.output


def test_ingest_is_silent_about_deliberate_extra_keys(workspace: Path, tmp_path: Path):
    doc = _write_doc(tmp_path / "ok.yml", _metrics_doc())
    result = CliRunner().invoke(ingest_cli, [str(doc), "--workspace", str(workspace)])

    assert result.exit_code == 0, result.output
    assert "ignored key" not in result.output


def test_a_bracketed_path_survives_rich_markup(tmp_path: Path):
    """The same escape, on the two interpolations that are *reachable from a path*.

    Both lines carry their own markup tags, so the file name and the catalog
    path have to be escaped rather than the markup turned off. Unescaped, Rich
    reads `[archive]` as a style tag and deletes it: `adef ingest
    "metrics[final].yml"` reported `from metrics.yml`, naming a file that does
    not exist, and `no catalog at .../ws[archive]/catalog` sent the user to look
    in a directory that is not the one ADEF checked.

    Needs no catalog, which is what selects the `no catalog at {cat_dir}` arm
    and makes the row unmatched in the first place. `--dry-run` so nothing is
    written to a workspace that was never initialised.
    """
    ws = tmp_path / "ws[archive]"
    ws.mkdir()
    doc = _write_doc(tmp_path / "metrics[final].yml", _metrics_doc())
    # Rich folds a long path mid-token at the console's width; join the lines
    # back before asserting so the test is about escaping, not wrapping.
    result = CliRunner().invoke(
        ingest_cli, [str(doc), "--workspace", str(ws), "--dry-run"]
    )

    assert result.exit_code == 0, result.output
    assert result.exception is None, result.exception
    flat = result.output.replace("\n", "")
    assert "metrics[final].yml" in flat, result.output
    assert "ws[archive]" in flat, result.output
