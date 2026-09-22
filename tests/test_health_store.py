"""Tests for detection-health storage (adef/core/health_store.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from adef.core.health_docs import HealthDoc, HealthDocError
from adef.core.health_store import health_dir, store_health_doc


def _metrics(captured_at: str = "2026-09-21T14:00:00Z", signal_count: int = 143) -> HealthDoc:
    return HealthDoc(
        kind="metrics",
        schema_version=1,
        captured_at=captured_at,
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        detections=[{"detection_id": "D-0042", "signal_count": signal_count}],
    )


def test_health_dir_is_under_the_workspace(tmp_path: Path):
    assert health_dir(tmp_path) == tmp_path / "health"


def test_writes_latest_snapshot_keyed_by_kind(tmp_path: Path):
    root = tmp_path / "health"
    result = store_health_doc(_metrics(), root, known_ids={"D-0042"})
    stored = yaml.safe_load((root / "latest" / "D-0042.yml").read_text(encoding="utf-8"))
    assert stored["metrics"]["signal_count"] == 143
    assert stored["metrics"]["captured_at"] == "2026-09-21T14:00:00Z"
    assert stored["metrics"]["environment"] == "prod-siem"
    assert result.matched == ["D-0042"]
    assert result.unmatched == []


def test_second_ingest_replaces_latest_but_appends_history(tmp_path: Path):
    root = tmp_path / "health"
    store_health_doc(_metrics(signal_count=143), root, known_ids={"D-0042"})
    store_health_doc(
        _metrics(captured_at="2026-09-28T14:00:00Z", signal_count=7),
        root,
        known_ids={"D-0042"},
    )

    stored = yaml.safe_load((root / "latest" / "D-0042.yml").read_text(encoding="utf-8"))
    assert stored["metrics"]["signal_count"] == 7      # latest wins

    lines = (root / "history" / "D-0042.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2                              # history keeps both
    assert [json.loads(line)["signal_count"] for line in lines] == [143, 7]
    assert json.loads(lines[0])["kind"] == "metrics"


def test_a_second_kind_merges_into_the_same_latest_file(tmp_path: Path):
    root = tmp_path / "health"
    store_health_doc(_metrics(), root, known_ids={"D-0042"})
    perf = HealthDoc(
        kind="performance",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        detections=[{"detection_id": "D-0042", "avg_runtime_seconds": 12.4}],
    )
    store_health_doc(perf, root, known_ids={"D-0042"})

    stored = yaml.safe_load((root / "latest" / "D-0042.yml").read_text(encoding="utf-8"))
    assert stored["metrics"]["signal_count"] == 143     # not clobbered
    assert stored["performance"]["avg_runtime_seconds"] == 12.4


def test_unmatched_detection_ids_are_reported_not_dropped(tmp_path: Path):
    root = tmp_path / "health"
    doc = _metrics()
    doc.detections.append({"detection_id": "D-9999", "signal_count": 1})
    result = store_health_doc(doc, root, known_ids={"D-0042"})

    assert result.matched == ["D-0042"]
    assert result.unmatched == ["D-9999"]
    assert not (root / "latest" / "D-9999.yml").exists()


def test_dry_run_writes_nothing_but_still_reports(tmp_path: Path):
    root = tmp_path / "health"
    result = store_health_doc(_metrics(), root, known_ids={"D-0042"}, dry_run=True)
    assert result.matched == ["D-0042"]
    assert result.paths_written == []
    assert not root.exists()


def test_source_health_is_stored_by_source_name(tmp_path: Path):
    root = tmp_path / "health"
    doc = HealthDoc(
        kind="source_health",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        sources=[{"name": "wineventlog", "event_count": 240000000}],
    )
    result = store_health_doc(doc, root, known_ids=set())

    stored = yaml.safe_load(
        (root / "sources" / "wineventlog.yml").read_text(encoding="utf-8")
    )
    assert stored["source_health"]["event_count"] == 240000000
    assert result.matched == ["wineventlog"]
    assert result.unmatched == []       # source names are not checked against the catalog


def test_field_observations_are_stored_by_source_name(tmp_path: Path):
    root = tmp_path / "health"
    doc = HealthDoc(
        kind="field_observations",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        source="wineventlog",
        fields=[{"name": "process.name", "null_rate": 0.02}],
    )
    store_health_doc(doc, root, known_ids=set())
    stored = yaml.safe_load(
        (root / "sources" / "wineventlog.yml").read_text(encoding="utf-8")
    )
    assert stored["field_observations"]["fields"][0]["name"] == "process.name"


def test_two_source_kinds_do_not_clobber_each_other(tmp_path: Path):
    root = tmp_path / "health"
    source_health_doc = HealthDoc(
        kind="source_health",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        sources=[{"name": "wineventlog", "event_count": 240000000}],
    )
    store_health_doc(source_health_doc, root, known_ids=set())

    field_obs_doc = HealthDoc(
        kind="field_observations",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        source="wineventlog",
        fields=[{"name": "process.name", "null_rate": 0.02}],
    )
    store_health_doc(field_obs_doc, root, known_ids=set())

    stored = yaml.safe_load(
        (root / "sources" / "wineventlog.yml").read_text(encoding="utf-8")
    )
    assert stored["source_health"]["event_count"] == 240000000
    assert stored["field_observations"]["fields"][0]["name"] == "process.name"


def _drift(det_id: str = "D-0042") -> HealthDoc:
    return HealthDoc(
        kind="deployment_drift",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window=None,
        detections=[
            {
                "detection_id": det_id,
                "deployed_status": "enabled",
                "deployed_query": "SELECT 1",
            }
        ],
    )


# --------------------------------------------------------------------------- #
# Finding 1: store-level re-check — lint alone is not a sufficient guard,
# since HealthDoc is a public dataclass any caller can hand-build.
# --------------------------------------------------------------------------- #
def test_store_rejects_hostile_source_health_name(tmp_path: Path):
    root = tmp_path / "health"
    doc = HealthDoc(
        kind="source_health",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        sources=[{"name": "../../../etc/passwd", "event_count": 1}],
    )
    with pytest.raises(HealthDocError):
        store_health_doc(doc, root, known_ids=set())
    assert not root.exists()


def test_store_rejects_absolute_source_health_name(tmp_path: Path):
    root = tmp_path / "health"
    doc = HealthDoc(
        kind="source_health",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        sources=[{"name": "/tmp/x/ESCAPED", "event_count": 1}],
    )
    with pytest.raises(HealthDocError):
        store_health_doc(doc, root, known_ids=set())
    assert not root.exists()
    assert not Path("/tmp/x/ESCAPED.yml").exists()


def test_store_rejects_hostile_field_observations_source(tmp_path: Path):
    root = tmp_path / "health"
    doc = HealthDoc(
        kind="field_observations",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        source="../../../x/TRAVERSED",
        fields=[{"name": "process.name"}],
    )
    with pytest.raises(HealthDocError):
        store_health_doc(doc, root, known_ids=set())
    assert not root.exists()


def test_store_treats_shape_invalid_detection_id_as_unmatched_not_written(tmp_path: Path):
    root = tmp_path / "health"
    doc = _metrics()
    hostile = "../../../detections/evil"
    doc.detections[0]["detection_id"] = hostile
    # Even if a compromised catalog somehow put this in known_ids, the shape
    # check must still keep it from becoming a filename.
    result = store_health_doc(doc, root, known_ids={hostile})
    assert result.matched == []
    assert result.unmatched == [hostile]
    assert not root.exists()


# --------------------------------------------------------------------------- #
# Finding 3: history row shape
# --------------------------------------------------------------------------- #
def test_history_row_includes_window(tmp_path: Path):
    root = tmp_path / "health"
    store_health_doc(_metrics(), root, known_ids={"D-0042"})
    history_row = json.loads(
        (root / "history" / "D-0042.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert history_row["window"] == {
        "start": "2026-09-14T00:00:00Z",
        "end": "2026-09-21T00:00:00Z",
    }


def test_history_row_drops_deployed_query_but_latest_keeps_it(tmp_path: Path):
    root = tmp_path / "health"
    store_health_doc(_drift(), root, known_ids={"D-0042"})

    latest = yaml.safe_load((root / "latest" / "D-0042.yml").read_text(encoding="utf-8"))
    assert latest["deployment_drift"]["deployed_query"] == "SELECT 1"

    history_row = json.loads(
        (root / "history" / "D-0042.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert "deployed_query" not in history_row


def test_history_row_kind_key_cannot_override_document_kind(tmp_path: Path):
    root = tmp_path / "health"
    doc = _metrics()
    doc.detections[0]["kind"] = "whatever"
    doc.detections[0]["captured_at"] = "bogus"
    store_health_doc(doc, root, known_ids={"D-0042"})

    history_row = json.loads(
        (root / "history" / "D-0042.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert history_row["kind"] == "metrics"
    assert history_row["captured_at"] == "2026-09-21T14:00:00Z"


# --------------------------------------------------------------------------- #
# Finding 5: _merge_latest must not crash the CLI on a bad existing file
# --------------------------------------------------------------------------- #
def test_merge_latest_raises_clean_error_on_non_mapping_yaml(tmp_path: Path):
    root = tmp_path / "health"
    latest_path = root / "latest" / "D-0042.yml"
    latest_path.parent.mkdir(parents=True)
    latest_path.write_text("- just\n- a\n- list\n", encoding="utf-8")

    with pytest.raises(HealthDocError):
        store_health_doc(_metrics(), root, known_ids={"D-0042"})


def test_merge_latest_raises_clean_error_on_corrupt_yaml(tmp_path: Path):
    root = tmp_path / "health"
    latest_path = root / "latest" / "D-0042.yml"
    latest_path.parent.mkdir(parents=True)
    latest_path.write_text("kind: [unclosed\n", encoding="utf-8")

    with pytest.raises(HealthDocError):
        store_health_doc(_metrics(), root, known_ids={"D-0042"})
