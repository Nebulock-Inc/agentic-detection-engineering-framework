"""Tests for the five reshape rules (adef/core/reshape.py) and the
`adef schema reshape` CLI (next-steps 2026-07-21 §5, declaration-author)."""

from __future__ import annotations

import csv
import json

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.schema import schema as schema_cli
from adef.core.declaration import lint_declaration_dict
from adef.core.reshape import (
    RawField,
    ReshapeError,
    reshape_export,
    reshape_fields,
)


def _splunk_csv(tmp_path, rows, name="fields.csv"):
    path = tmp_path / name
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["field", "count", "distinct_count", "numeric_count", "values"]
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def _vals(*pairs):
    return json.dumps([{"value": v, "count": c} for v, c in pairs])


SPLUNK_ROWS = [
    {"field": "_time", "count": 100, "distinct_count": 100, "numeric_count": 0, "values": ""},
    {"field": "punct", "count": 100, "distinct_count": 5, "numeric_count": 0, "values": ""},
    {"field": "date_hour", "count": 100, "distinct_count": 24, "numeric_count": 100, "values": ""},
    {"field": "index", "count": 100, "distinct_count": 1, "numeric_count": 0, "values": _vals(("thrunt", 100))},
    {"field": "sourcetype", "count": 100, "distinct_count": 1, "numeric_count": 0, "values": _vals(("XmlWinEventLog", 100))},
    {"field": "EventCode", "count": 90, "distinct_count": 2, "numeric_count": 90, "values": _vals(("4688", 60), ("4624", 30))},
    {"field": "eventcode", "count": 10, "distinct_count": 2, "numeric_count": 10, "values": _vals(("4688", 5), ("4624", 5))},
    {"field": "CommandLine", "count": 80, "distinct_count": 4000, "numeric_count": 0, "values": ""},
    {"field": "action", "count": 100, "distinct_count": 2, "numeric_count": 0, "values": _vals(("allowed", 70), ("blocked", 30))},
    {"field": "blob", "count": 50, "distinct_count": 2, "numeric_count": 0, "values": _vals(("x" * 200, 30), ("y", 20))},
]


# --------------------------------------------------------------------------- #
# Rule 1: internals filter
# --------------------------------------------------------------------------- #
def test_internals_dropped_and_reported():
    fields, report = reshape_fields([RawField("_time"), RawField("punct"), RawField("date_hour"), RawField("User")])
    assert [f["name"] for f in fields] == ["User"]
    assert set(report.dropped_internals) == {"_time", "punct", "date_hour"}


def test_all_internals_is_an_error(tmp_path):
    path = _splunk_csv(tmp_path, [{"field": "_raw", "count": 1, "distinct_count": 1, "numeric_count": 0, "values": ""}])
    with pytest.raises(ReshapeError, match="internal"):
        reshape_export(path, "splunk")


# --------------------------------------------------------------------------- #
# Rule 2: case-dupes → aliases
# --------------------------------------------------------------------------- #
def test_case_dupes_folded_canonical_by_count():
    fields, report = reshape_fields(
        [RawField("eventcode", total_count=10), RawField("EventCode", total_count=90)]
    )
    assert len(fields) == 1
    assert fields[0]["name"] == "EventCode"
    assert fields[0]["aliases"] == ["eventcode"]
    assert report.folded_aliases == {"EventCode": ["eventcode"]}


# --------------------------------------------------------------------------- #
# Rule 3: enum harvesting with caps
# --------------------------------------------------------------------------- #
def test_enum_harvested_for_low_cardinality():
    fields, report = reshape_fields(
        [RawField("action", distinct_count=2, values=["allowed", "blocked"])]
    )
    assert fields[0]["values"] == ["allowed", "blocked"]
    assert report.enum_fields == ["action"]


def test_enum_skipped_when_high_cardinality():
    fields, _ = reshape_fields(
        [RawField("CommandLine", distinct_count=4000, values=["a", "b"])]
    )
    assert "values" not in fields[0]


def test_enum_harvested_at_eventcode_scale():
    """Windows enum-ish fields sit in the 20–50 distinct band (live thrunt
    export: EventCode=24) — the cap must not exclude them."""
    values = [str(4600 + i) for i in range(24)]
    fields, _ = reshape_fields(
        [RawField("EventCode", total_count=100, numeric_count=100, distinct_count=24, values=values)]
    )
    assert fields[0]["values"] == [int(v) for v in values]


def test_enum_skipped_when_value_exceeds_length_cap():
    fields, _ = reshape_fields(
        [RawField("blob", distinct_count=2, values=["x" * 200, "y"])]
    )
    assert "values" not in fields[0]


# --------------------------------------------------------------------------- #
# Rule 2 extensions: suspect folds + --no-fold vetoes
# --------------------------------------------------------------------------- #
def test_disjoint_value_fold_flagged_suspect():
    """eventtype (Splunk meta) vs EventType (Sysmon field): disjoint values."""
    fields, report = reshape_fields(
        [
            RawField("eventtype", total_count=100, distinct_count=3, values=["winsec", "os", "windows"]),
            RawField("EventType", total_count=10, distinct_count=1, values=["SetValue"]),
        ]
    )
    assert report.suspect_folds == ["eventtype"]
    assert len(fields) == 1  # still folded — flagged for a human, never auto-split
    assert report.fold_evidence["eventtype"] == {
        "eventtype": ["winsec", "os", "windows"],
        "EventType": ["SetValue"],
    }


def test_overlapping_value_fold_not_suspect():
    """user/User (CIM pair) share values — a correct fold, no flag."""
    _, report = reshape_fields(
        [
            RawField("user", total_count=100, distinct_count=2, values=["alice", "bob"]),
            RawField("User", total_count=40, distinct_count=2, values=["alice", "carol"]),
        ]
    )
    assert report.folded_aliases == {"user": ["User"]}
    assert report.suspect_folds == []


def test_fold_without_values_not_suspect():
    """No harvested values on one side = no evidence = no flag."""
    _, report = reshape_fields(
        [RawField("Name", total_count=100, values=["x"]), RawField("name", total_count=10)]
    )
    assert report.suspect_folds == []


def test_no_fold_keeps_variant_separate():
    fields, report = reshape_fields(
        [
            RawField("eventtype", total_count=100, distinct_count=1, values=["winsec"]),
            RawField("EventType", total_count=10, distinct_count=1, values=["SetValue"]),
        ],
        no_fold=("EventType",),
    )
    names = {f["name"] for f in fields}
    assert names == {"eventtype", "EventType"}
    assert report.folded_aliases == {}
    assert report.suspect_folds == []


# --------------------------------------------------------------------------- #
# Rule 4: type inference
# --------------------------------------------------------------------------- #
def test_numeric_population_typed_int():
    fields, report = reshape_fields(
        [RawField("EventCode", total_count=90, numeric_count=90, distinct_count=2, values=["4688", "4624"])]
    )
    assert fields[0]["type"] == "int"
    assert fields[0]["values"] == [4688, 4624]  # enum coerced to the inferred type
    assert report.typed_fields == {"EventCode": "int"}


def test_hex_values_typed_int():
    fields, _ = reshape_fields([RawField("flags", distinct_count=2, values=["0x1a", "0xFF"])])
    assert fields[0]["type"] == "int"
    assert fields[0]["values"] == [26, 255]


def test_float_population():
    fields, _ = reshape_fields(
        [RawField("duration", total_count=5, numeric_count=5, distinct_count=3, values=["0.5", "1.25"])]
    )
    assert fields[0]["type"] == "float"


def test_type_hint_from_export_wins():
    fields, _ = reshape_fields([RawField("TimeGenerated", type_hint="datetime")])
    assert fields[0]["type"] == "datetime"


def test_string_field_stays_untyped():
    fields, _ = reshape_fields([RawField("CommandLine", total_count=10, numeric_count=0)])
    assert "type" not in fields[0]


# --------------------------------------------------------------------------- #
# Rule 5: mixed-shape guard
# --------------------------------------------------------------------------- #
def test_mixed_sourcetypes_refused_with_guidance():
    with pytest.raises(ReshapeError, match="re-export"):
        reshape_fields(
            [RawField("sourcetype", distinct_count=2, values=["XmlWinEventLog", "bro:dns:json"])]
        )


def test_single_sourcetype_becomes_scope(tmp_path):
    result = reshape_export(_splunk_csv(tmp_path, SPLUNK_ROWS), "splunk")
    src = result.declaration["sources"][0]
    assert src["scope"] == {"index": "thrunt", "sourcetype": "XmlWinEventLog"}
    assert src["name"] == "xmlwineventlog"  # derived from sourcetype


# --------------------------------------------------------------------------- #
# Parsers + end-to-end contract: output always lints clean
# --------------------------------------------------------------------------- #
def test_splunk_export_end_to_end_lints_clean(tmp_path):
    result = reshape_export(_splunk_csv(tmp_path, SPLUNK_ROWS), "splunk", source_name="winlog")
    errors, _ = lint_declaration_dict(result.declaration)
    assert errors == []
    src = result.declaration["sources"][0]
    assert src["query_language"] == "spl"
    names = [f["name"] for f in src["fields"]]
    assert "EventCode" in names and "eventcode" not in names
    assert "_time" not in names and "punct" not in names


def test_sentinel_getschema_csv(tmp_path):
    path = tmp_path / "SecurityEvent-schema.csv"
    path.write_text(
        "ColumnName,DataType\nEventID,int\nTimeGenerated,datetime\nAccount,string\n",
        encoding="utf-8",
    )
    result = reshape_export(path, "sentinel")
    src = result.declaration["sources"][0]
    assert src["query_language"] == "kql"
    by_name = {f["name"]: f for f in src["fields"]}
    assert by_name["EventID"]["type"] == "int"
    assert by_name["TimeGenerated"]["type"] == "datetime"
    assert "type" not in by_name["Account"]
    assert lint_declaration_dict(result.declaration)[0] == []


def test_elastic_mapping_json(tmp_path):
    mapping = {
        "winlogbeat": {
            "mappings": {
                "properties": {
                    "event": {"properties": {"code": {"type": "keyword"}}},
                    "process": {"properties": {"pid": {"type": "long"}}},
                    "@timestamp": {"type": "date"},
                }
            }
        }
    }
    path = tmp_path / "mapping.json"
    path.write_text(json.dumps(mapping), encoding="utf-8")
    result = reshape_export(path, "elastic", source_name="winlogbeat")
    by_name = {f["name"]: f for f in result.declaration["sources"][0]["fields"]}
    assert by_name["process.pid"]["type"] == "int"
    assert "event.code" in by_name
    assert by_name["@timestamp"]["type"] == "datetime"  # queried in ES, not internal


def test_text_fallback_one_field_per_line(tmp_path):
    path = tmp_path / "fields.txt"
    path.write_text("# comment\nsrc_ip\ndst_ip\n\n", encoding="utf-8")
    result = reshape_export(path, "qradar", source_name="events")
    names = [f["name"] for f in result.declaration["sources"][0]["fields"]]
    assert names == ["dst_ip", "src_ip"]


def test_wrong_csv_shape_errors_with_recipe_pointer(tmp_path):
    path = tmp_path / "fields.csv"
    path.write_text("wrong,columns\n1,2\n", encoding="utf-8")
    with pytest.raises(ReshapeError, match="recipe"):
        reshape_export(path, "splunk")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_reshape_writes_declaration_and_report(tmp_path, monkeypatch):
    export = _splunk_csv(tmp_path, SPLUNK_ROWS)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        schema_cli, ["reshape", str(export), "--platform", "splunk", "--source", "winlog"]
    )
    assert result.exit_code == 0, result.output
    assert "Transformation report" in result.output
    assert "Scope inferred from the export: index=thrunt, sourcetype=XmlWinEventLog" in result.output
    assert "Dropped 5 internals" in result.output
    data = yaml.safe_load((tmp_path / "winlog-sources.yml").read_text(encoding="utf-8"))
    assert lint_declaration_dict(data)[0] == []


def test_cli_reshape_suspect_marker_and_no_fold(tmp_path):
    rows = list(SPLUNK_ROWS) + [
        {"field": "eventtype", "count": 100, "distinct_count": 2, "numeric_count": 0,
         "values": _vals(("winsec", 60), ("os", 40))},
        {"field": "EventType", "count": 10, "distinct_count": 1, "numeric_count": 0,
         "values": _vals(("SetValue", 10))},
    ]
    export = _splunk_csv(tmp_path, rows)
    out = tmp_path / "d.yml"
    result = CliRunner().invoke(schema_cli, ["reshape", str(export), "--platform", "splunk", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "SUSPECT" in result.output
    assert "--no-fold EventType" in result.output
    # evidence shown in place: both spellings with their values
    assert "'winsec'" in result.output
    assert "'SetValue'" in result.output

    out2 = tmp_path / "d2.yml"
    result = CliRunner().invoke(
        schema_cli,
        ["reshape", str(export), "--platform", "splunk", "-o", str(out2), "--no-fold", "EventType"],
    )
    assert result.exit_code == 0, result.output
    assert "SUSPECT" not in result.output
    names = {f["name"] for f in yaml.safe_load(out2.read_text())["sources"][0]["fields"]}
    assert {"eventtype", "EventType"} <= names


def _suspect_rows():
    return list(SPLUNK_ROWS) + [
        {"field": "eventtype", "count": 100, "distinct_count": 2, "numeric_count": 0,
         "values": _vals(("winsec", 60), ("os", 40))},
        {"field": "EventType", "count": 10, "distinct_count": 1, "numeric_count": 0,
         "values": _vals(("SetValue", 10))},
    ]


def test_cli_reshape_interactive_split(tmp_path):
    """Answering 'no' (different fields) splits the fold and echoes the
    reproducible --no-fold command."""
    export = _splunk_csv(tmp_path, _suspect_rows())
    out = tmp_path / "d.yml"
    result = CliRunner().invoke(
        schema_cli,
        ["reshape", str(export), "--platform", "splunk", "-o", str(out), "--interactive"],
        input="n\n",
    )
    assert result.exit_code == 0, result.output
    names = {f["name"] for f in yaml.safe_load(out.read_text())["sources"][0]["fields"]}
    assert {"eventtype", "EventType"} <= names
    assert "Reproducible:" in result.output
    assert "--no-fold EventType" in result.output


def test_cli_reshape_interactive_keep(tmp_path):
    """Answering 'yes' (same field, default) keeps the fold."""
    export = _splunk_csv(tmp_path, _suspect_rows())
    out = tmp_path / "d.yml"
    result = CliRunner().invoke(
        schema_cli,
        ["reshape", str(export), "--platform", "splunk", "-o", str(out), "--interactive"],
        input="y\n",
    )
    assert result.exit_code == 0, result.output
    by = {f["name"]: f for f in yaml.safe_load(out.read_text())["sources"][0]["fields"]}
    assert by["eventtype"]["aliases"] == ["EventType"]
    assert "EventType" not in by


def test_cli_reshape_mixed_shape_exits_nonzero(tmp_path):
    rows = list(SPLUNK_ROWS)
    rows[4] = {
        "field": "sourcetype", "count": 100, "distinct_count": 2, "numeric_count": 0,
        "values": _vals(("XmlWinEventLog", 60), ("bro:dns:json", 40)),
    }
    export = _splunk_csv(tmp_path, rows)
    result = CliRunner().invoke(schema_cli, ["reshape", str(export), "--platform", "splunk"])
    assert result.exit_code != 0
    assert "re-export" in result.output


def test_cli_reshape_no_platform_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))  # no config
    export = _splunk_csv(tmp_path, SPLUNK_ROWS)
    result = CliRunner().invoke(schema_cli, ["reshape", str(export)])
    assert result.exit_code != 0
    assert "--platform" in result.output


def test_cli_reshape_platform_from_cwd_workspace(tmp_path, monkeypatch):
    """Running from inside an init'd workspace picks up its config — the
    `adef init --interactive` platform must work without --platform or env."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".adefconfig.yaml").write_text(
        yaml.safe_dump({"platform": "splunk"}), encoding="utf-8"
    )
    (tmp_path / "journals").mkdir()  # what marks a directory as a workspace
    monkeypatch.delenv("ADEF_WORKSPACE", raising=False)
    monkeypatch.chdir(tmp_path)
    export = _splunk_csv(tmp_path, SPLUNK_ROWS)
    result = CliRunner().invoke(schema_cli, ["reshape", str(export)])
    assert result.exit_code == 0, result.output


def test_cli_reshape_no_platform_error_names_the_config_path(tmp_path, monkeypatch):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))  # no config here
    export = _splunk_csv(tmp_path, SPLUNK_ROWS)
    result = CliRunner().invoke(schema_cli, ["reshape", str(export)])
    assert result.exit_code != 0
    assert ".adefconfig.yaml" in result.output  # says where it looked


def test_cli_reshape_platform_from_config(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".adefconfig.yaml").write_text(yaml.safe_dump({"platform": "splunk"}), encoding="utf-8")
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))
    export = _splunk_csv(tmp_path, SPLUNK_ROWS)
    out = tmp_path / "decl.yml"
    result = CliRunner().invoke(schema_cli, ["reshape", str(export), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
