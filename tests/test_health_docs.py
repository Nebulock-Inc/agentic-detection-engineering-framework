"""Tests for detection-health capture documents (adef/core/health_docs.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from adef.core.health_docs import (
    KINDS,
    SCHEMA_VERSION,
    HealthDocError,
    lint_health_doc,
    load_health_doc,
)


def _metrics_doc() -> dict:
    return {
        "schema_version": 1,
        "kind": "metrics",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "detections": [
            {
                "detection_id": "D-0042",
                "signal_count": 143,
                "true_positive_count": 4,
                "false_positive_count": 131,
                "unlabeled_count": 8,
                "last_true_positive_at": "2026-08-30T11:04:00Z",
            }
        ],
    }


def _drift_doc() -> dict:
    return {
        "schema_version": 1,
        "kind": "deployment_drift",
        "captured_at": "2026-09-21T14:00:00Z",
        "environment": "prod-siem",
        "detections": [{"detection_id": "D-0042", "deployed_status": "enabled"}],
    }


def test_valid_metrics_doc_lints_clean():
    assert lint_health_doc(_metrics_doc()) == []


def test_the_five_kinds_are_the_closed_set():
    assert KINDS == {
        "metrics",
        "performance",
        "deployment_drift",
        "field_observations",
        "source_health",
    }


def test_unknown_kind_is_an_error():
    doc = _metrics_doc()
    doc["kind"] = "made_up"
    errors = lint_health_doc(doc)
    assert any("kind" in e and "made_up" in e for e in errors)


def test_wrong_schema_version_is_an_error():
    doc = _metrics_doc()
    doc["schema_version"] = 2
    errors = lint_health_doc(doc)
    assert any("schema_version" in e for e in errors)


def test_window_required_for_windowed_kinds():
    doc = _metrics_doc()
    del doc["window"]
    errors = lint_health_doc(doc)
    assert any("window" in e and "required" in e for e in errors)


def test_window_forbidden_on_deployment_drift():
    # Point-in-time: captured_at is the whole of its temporal meaning. A window
    # here means the producer misunderstood the format — say so, don't ignore it.
    doc = _drift_doc()
    doc["window"] = {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"}
    errors = lint_health_doc(doc)
    assert any("window" in e and "deployment_drift" in e for e in errors)


def test_deployment_drift_without_window_lints_clean():
    assert lint_health_doc(_drift_doc()) == []


def test_missing_captured_at_is_an_error():
    doc = _metrics_doc()
    del doc["captured_at"]
    errors = lint_health_doc(doc)
    assert any("captured_at" in e for e in errors)


def test_detection_row_without_id_is_an_error():
    doc = _metrics_doc()
    del doc["detections"][0]["detection_id"]
    errors = lint_health_doc(doc)
    assert any("detection_id" in e for e in errors)


def test_empty_detections_is_an_error():
    doc = _metrics_doc()
    doc["detections"] = []
    errors = lint_health_doc(doc)
    assert any("detections" in e for e in errors)


def test_unknown_top_level_key_is_an_error():
    doc = _metrics_doc()
    doc["enviroment"] = "typo-prod"          # realistic misspelling
    errors = lint_health_doc(doc)
    assert any("enviroment" in e for e in errors)


def test_source_health_requires_named_sources():
    doc = {
        "schema_version": 1,
        "kind": "source_health",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "sources": [{"event_count": 240000000}],   # no name
    }
    errors = lint_health_doc(doc)
    assert any("name" in e for e in errors)


def test_field_observations_requires_source_and_fields():
    doc = {
        "schema_version": 1,
        "kind": "field_observations",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "fields": [{"name": "process.name", "null_rate": 0.02}],
    }
    errors = lint_health_doc(doc)
    assert any("source" in e for e in errors)


def test_load_returns_typed_doc(tmp_path: Path):
    path = tmp_path / "metrics.yml"
    path.write_text(yaml.safe_dump(_metrics_doc()), encoding="utf-8")
    doc = load_health_doc(path)
    assert doc.kind == "metrics"
    assert doc.schema_version == SCHEMA_VERSION
    assert doc.environment == "prod-siem"
    assert doc.detections[0]["detection_id"] == "D-0042"
    assert doc.window is not None


def test_load_raises_on_invalid_doc(tmp_path: Path):
    doc = _metrics_doc()
    doc["kind"] = "made_up"
    path = tmp_path / "bad.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(HealthDocError, match="made_up"):
        load_health_doc(path)


def test_load_raises_on_unparseable_yaml(tmp_path: Path):
    path = tmp_path / "broken.yml"
    path.write_text("kind: [unclosed\n", encoding="utf-8")
    with pytest.raises(HealthDocError):
        load_health_doc(path)
