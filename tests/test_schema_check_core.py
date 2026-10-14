import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.engines import ALLOWED_ENGINES
from adef.commands.schema import run_schema_check, schema as schema_cli


def _schema_v2(source: str, fields: list[dict]) -> dict:
    return {
        "schema_version": 2,
        "source": source,
        "fields": fields,
        "scope": {"index": source},
    }


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "schema").mkdir(parents=True)
    (ws / "schema" / "wineventlog.yml").write_text(
        yaml.safe_dump(_schema_v2("wineventlog", [
            {"name": "process.name", "type": "string"},
            {"name": "user.name", "type": ""},  # declared but no type
        ])),
        encoding="utf-8",
    )
    cat = Catalog(ws)
    good = CatalogRecord(
        id="D-0001", title="ok", rule_ref="r/d1.yml", original_path="/tmp/d1.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query="process.name = 'mshta.exe'", query_language="sql", data_source="wineventlog",
    )
    bad_engine = CatalogRecord(
        id="D-0002", title="bad engine", rule_ref="r/d2.yml", original_path="/tmp/d2.yml",
        platform="windows", kind="atomic", engine="custom_sql", format="sigma",
        query="process.name = 'mshta.exe'", query_language="sql", data_source="wineventlog",
    )
    undeclared_type = CatalogRecord(
        id="D-0003", title="undeclared type", rule_ref="r/d3.yml", original_path="/tmp/d3.yml",
        platform="windows", kind="atomic", engine="sql", format="sql",
        # Backtick-quoted dotted identifier (see extract_sql_fields' docstring);
        # bare `user.name` parses as a
        # table-qualified column and sqlglot drops the `user.` qualifier.
        query="`user.name` = 'admin'", query_language="sql", data_source="wineventlog",
    )
    # Both findings on one rule, so a single `--detection` scope exercises the
    # CLI's rendering of each without any other finding type in the way.
    both = CatalogRecord(
        id="D-0004", title="bad engine and undeclared type", rule_ref="r/d4.yml",
        original_path="/tmp/d4.yml", platform="windows", kind="atomic",
        engine="custom_sql", format="sql",
        query="`user.name` = 'admin'", query_language="sql", data_source="wineventlog",
    )
    for rec in (good, bad_engine, undeclared_type, both):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    return ws


def test_allowed_engines_is_the_closed_four_set():
    assert ALLOWED_ENGINES == frozenset({"sigma", "sql", "sch_sql", "composite"})


def test_flags_engine_outside_closed_set(workspace: Path):
    result = run_schema_check(workspace, detection_ids=("D-0002",))
    assert "D-0002" in result.engine_errors
    assert "custom_sql" in result.engine_errors["D-0002"]


def test_does_not_flag_allowed_engine(workspace: Path):
    result = run_schema_check(workspace, detection_ids=("D-0001",))
    assert "D-0001" not in result.engine_errors


def test_flags_field_with_no_declared_type(workspace: Path):
    result = run_schema_check(workspace, detection_ids=("D-0003",))
    assert "user.name" in result.undeclared_type_fields.get("D-0003", [])


def test_alias_reference_does_not_flag_undeclared_type(tmp_path: Path):
    # CodeRabbit: known_field_names() accepts a field's aliases as
    # legitimate references, but declared_types previously only mapped
    # canonical names — so a rule using an alias was wrongly reported as
    # referencing a field with no declared type.
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "schema").mkdir(parents=True)
    (ws / "schema" / "wineventlog.yml").write_text(
        yaml.safe_dump(_schema_v2("wineventlog", [
            {"name": "process.name", "type": "string", "aliases": ["proc_name"]},
        ])),
        encoding="utf-8",
    )
    cat = Catalog(ws)
    rec = CatalogRecord(
        id="D-0005", title="alias reference", rule_ref="r/d5.yml",
        original_path="/tmp/d5.yml", platform="windows", kind="atomic",
        engine="sql", format="sql",
        query="proc_name = 'mshta.exe'", query_language="sql", data_source="wineventlog",
    )
    cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())

    result = run_schema_check(ws, detection_ids=("D-0005",))
    assert "proc_name" not in result.undeclared_type_fields.get("D-0005", [])


def test_existing_behavior_preserved_whole_catalog(workspace: Path):
    # No `detection_ids` filter — the pre-existing whole-catalog mode must still work.
    result = run_schema_check(workspace)
    assert result.rules_checked >= 1


# --- `adef schema check` CLI: the core already found these; the command has to
# --- actually *report* them, or the documented authoring-loop validator lies.
# --- D-0004 has no missing/unused findings at all, so these also pin the
# --- "No findings." early-return to all four result fields, not just two.

def test_cli_check_reports_engine_and_type_findings_as_text(workspace: Path):
    result = CliRunner().invoke(
        schema_cli, ["check", "--workspace", str(workspace), "--detection", "D-0004"]
    )
    assert result.exit_code == 0, result.output
    assert "No findings." not in result.output
    assert "custom_sql" in result.output
    assert "user.name" in result.output


def test_cli_check_reports_engine_and_type_findings_as_json(workspace: Path):
    result = CliRunner().invoke(
        schema_cli,
        ["check", "--workspace", str(workspace), "--detection", "D-0004", "--report", "json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "custom_sql" in payload["engine_errors"]["D-0004"]
    assert payload["undeclared_type_fields"]["D-0004"] == ["user.name"]


def test_cql_tags_and_query_created_names_are_not_missing_fields(tmp_path: Path):
    # every CrowdStrike rule failed Verification on its
    # `#event_simpleName` tag and on variables the query itself defined.
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "schema").mkdir(parents=True)
    (ws / "schema" / "falcon.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "falcon", "query_language": "cql",
        "fields": [{"name": "CommandLine", "type": "string"}],
        "scope": {"data_source": "Endpoint"},
    }), encoding="utf-8")
    query = (
        '#event_simpleName=ProcessRollup2 | #repo=base_sensor\n'
        '| replace("\\\\s+", with=" ", field=CommandLine, as=cmd)\n'
        '| decoded := base64Decode(cmd) | regex("(?<payload>IEX.*)", field=decoded)\n'
        '| cmd=/-enc/i | payload=* | CommandLine=*powershell*'
    )
    rec = CatalogRecord(
        id="D-0001", title="enc ps", rule_ref="r/d1.yml", original_path="/tmp/d1.yml",
        platform="windows", kind="atomic", engine="sql", format="cql",
        query=query, query_language="cql", data_source="Endpoint",
    )
    Catalog(ws).write_raw(ws / "catalog" / "D-0001.yml", rec.to_yaml_dict())
    result = run_schema_check(ws)
    missing = {f for fields in result.missing_from_schema.values() for f in fields}
    assert missing == set(), missing
