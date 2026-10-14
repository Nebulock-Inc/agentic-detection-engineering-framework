"""Tests for detection-health capture documents (adef/core/health_docs.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from adef.core.health_docs import (
    KINDS,
    SCHEMA_VERSION,
    HealthDoc,
    HealthDocError,
    lint_health_doc,
    load_health_doc,
    near_miss_row_keys,
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


# --------------------------------------------------------------------------- #
# Finding 1: source names / detection ids must not become hostile paths
# --------------------------------------------------------------------------- #
def _source_health_doc(name: str) -> dict:
    return {
        "schema_version": 1,
        "kind": "source_health",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "sources": [{"name": name, "event_count": 1}],
    }


def _field_observations_doc(source: str) -> dict:
    return {
        "schema_version": 1,
        "kind": "field_observations",
        "captured_at": "2026-09-21T14:00:00Z",
        "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        "environment": "prod-siem",
        "source": source,
        "fields": [{"name": "process.name"}],
    }


@pytest.mark.parametrize(
    "hostile",
    [
        "/tmp/x/ESCAPED",           # absolute path
        "../../../x/TRAVERSED",     # traversal
        "aws/cloudtrail",           # nested path — breaks the flat sources/<source>.yml contract
        "..",
        ".",
    ],
)
def test_source_health_name_rejects_hostile_names(hostile):
    errors = lint_health_doc(_source_health_doc(hostile))
    assert any("sources[0].name" in e for e in errors)


@pytest.mark.parametrize(
    "hostile",
    ["/tmp/x/ESCAPED", "../../../x/TRAVERSED", "aws/cloudtrail", "..", "."],
)
def test_field_observations_source_rejects_hostile_names(hostile):
    errors = lint_health_doc(_field_observations_doc(hostile))
    assert any(e.startswith("source:") for e in errors)


def test_source_health_bare_name_still_lints_clean():
    assert lint_health_doc(_source_health_doc("wineventlog")) == []


@pytest.mark.parametrize("hostile", ["../../../etc/detections/foo", "D-42", "not-an-id", "D-abcd"])
def test_detection_id_shape_is_checked(hostile):
    doc = _metrics_doc()
    doc["detections"][0]["detection_id"] = hostile
    errors = lint_health_doc(doc)
    assert any("detection_id" in e for e in errors)


# --------------------------------------------------------------------------- #
# Finding 2: deployment_drift normalization
# --------------------------------------------------------------------------- #
def _drift_doc_with_normalization(apply: list) -> dict:
    doc = _drift_doc()
    doc["normalization"] = {"apply": apply}
    return doc


def test_deployment_drift_with_valid_normalization_lints_clean():
    assert lint_health_doc(
        _drift_doc_with_normalization(["collapse_whitespace", "strip_sql_comments"])
    ) == []


def test_deployment_drift_unknown_transform_is_an_error():
    errors = lint_health_doc(_drift_doc_with_normalization(["collapse_whitespace", "made_up"]))
    assert any("normalization.apply" in e and "made_up" in e for e in errors)


def test_spec_verbatim_deployment_drift_example_lints_clean():
    # The capture contract's `deployment_drift` example, verbatim.
    doc = {
        "schema_version": 1,
        "kind": "deployment_drift",
        "captured_at": "2026-09-21T14:00:00Z",
        "environment": "prod-siem",
        "detections": [
            {
                "detection_id": "D-0042",
                "deployed_status": "enabled",
                "deployed_version": "7",
                "last_deployed_change_at": "2026-09-02T08:11:00Z",
                "deployed_query": "SELECT 1\n",
            }
        ],
        "normalization": {"apply": ["collapse_whitespace", "strip_sql_comments"]},
    }
    assert lint_health_doc(doc) == []


# --------------------------------------------------------------------------- #
# Near-miss row keys: a misspelled count is the quietest failure in the format
# --------------------------------------------------------------------------- #
def _doc_with_row(row: dict) -> HealthDoc:
    doc = _metrics_doc()
    doc["detections"] = [row]
    return HealthDoc(
        kind=doc["kind"],
        schema_version=doc["schema_version"],
        captured_at=doc["captured_at"],
        environment=doc["environment"],
        window=doc["window"],
        detections=doc["detections"],
    )


def test_misspelled_count_key_is_warned_with_the_key_it_resembles():
    warnings = near_miss_row_keys(
        _doc_with_row(
            {
                "detection_id": "D-0042",
                "signal_count": 500,
                "false_positives_count": 480,  # plural — reads as nothing
                "true_positive_count": 2,
            }
        )
    )
    assert len(warnings) == 1, warnings
    assert "false_positives_count" in warnings[0]
    assert "false_positive_count" in warnings[0]
    assert "D-0042" in warnings[0]


def test_near_miss_is_silent_when_the_key_it_resembles_is_also_present():
    # A producer carrying a derived companion alongside the real count has lost
    # nothing. Warning here would train people to ignore the warning.
    assert near_miss_row_keys(
        _doc_with_row(
            {"detection_id": "D-0042", "signal_count": 500, "signal_count_p95": 31}
        )
    ) == []


def test_documented_row_keys_produce_no_warnings():
    # `unlabeled_count` is a documented field nothing derives from — carrying it
    # is correct, so it must not be read as a typo of a derived key.
    assert near_miss_row_keys(_doc_with_row(_metrics_doc()["detections"][0])) == []


def test_only_metrics_rows_are_checked():
    # `performance` is detection-keyed too, so its rows reach the same loop —
    # which is the point: DERIVED_ROW_KEYS are the `metrics` keys, and nothing
    # reads a performance row, so a resemblance there costs nothing.
    # (A `source_health` fixture would not test this: its rows live in
    # `sources`, which this function never iterates, so the kind guard would be
    # unreachable from it.)
    doc = HealthDoc(
        kind="performance",
        schema_version=1,
        captured_at="2026-09-21T14:00:00Z",
        environment="prod-siem",
        window={"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
        detections=[{"detection_id": "D-0042", "false_positives_count": 1}],
    )
    assert near_miss_row_keys(doc) == []


@pytest.mark.parametrize("field", ["captured_at", "start", "end"])
def test_unparseable_timestamps_are_errors(field):
    """A window that can't be parsed used to pass lint and then turn a 30-day
    count into a "weekly" volume downstream."""
    doc = _metrics_doc()
    if field == "captured_at":
        doc["captured_at"] = "last tuesday"
    else:
        doc["window"][field] = "last tuesday"
    assert any("not an ISO-8601 timestamp" in e for e in lint_health_doc(doc))


def test_a_backwards_window_is_an_error():
    doc = _metrics_doc()
    doc["window"] = {"start": "2026-09-21T00:00:00Z", "end": "2026-09-14T00:00:00Z"}
    assert any("'start' must be before 'end'" in e for e in lint_health_doc(doc))


def test_compact_utc_offset_parses_on_every_supported_python():
    """`+0000` is what most SIEM exports emit; 3.10's `fromisoformat` rejects it."""
    from adef.core.health_docs import parse_iso

    doc = _metrics_doc()
    doc["window"] = {"start": "2026-09-01T00:00:00.000+0000", "end": "2026-10-01T00:00:00.000-0500"}
    assert lint_health_doc(doc) == []
    assert parse_iso("2026-09-01T00:00:00.000+0000") == parse_iso("2026-09-01T00:00:00Z")


@pytest.mark.parametrize(
    "key, expected",
    [
        ("signals", "signal_count"),
        ("false_positives", "false_positive_count"),
        ("true_positives", "true_positive_count"),
    ],
)
def test_short_form_row_keys_are_warned(key, expected):
    """Too far from the real key for difflib's 0.85 cutoff, and the names the
    earlier capture format used."""
    warnings = near_miss_row_keys(_doc_with_row({"detection_id": "D-0042", key: 5}))
    assert any(f"did you mean {expected!r}" in w for w in warnings), warnings


@pytest.mark.parametrize(
    "value", ["2026-07-27 10:15:30+0000", "2026-07-27T10:15:30.12Z", "2026-07-27T10:15:30.1234567+0000"]
)
def test_common_siem_timestamp_shapes_parse(value):
    """3.10's `fromisoformat` rejects each of these; 3.11+ accepts them."""
    from adef.core.health_docs import parse_iso

    assert parse_iso(value) is not None


def test_a_one_day_date_only_window_is_valid():
    doc = _metrics_doc()
    doc["window"] = {"start": "2026-10-13", "end": "2026-10-13"}
    assert lint_health_doc(doc) == []


def test_a_one_day_date_only_window_spans_one_day():
    from adef.core.health_store import tuning_metrics

    derived = tuning_metrics({"metrics": {"signal_count": 10, "window": {"start": "2026-10-13", "end": "2026-10-13"}}})
    assert derived["weekly_signal_volume"] == 70
