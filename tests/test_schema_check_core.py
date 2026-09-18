from pathlib import Path

import pytest
import yaml

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.engines import ALLOWED_ENGINES
from adef.commands.schema import run_schema_check


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
            {"name": "user.name", "type": ""},  # declared but no type — Task 4's new check
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
        platform="windows", kind="atomic", engine="atomic_sql", format="sigma",
        query="process.name = 'mshta.exe'", query_language="sql", data_source="wineventlog",
    )
    undeclared_type = CatalogRecord(
        id="D-0003", title="undeclared type", rule_ref="r/d3.yml", original_path="/tmp/d3.yml",
        platform="windows", kind="atomic", engine="sql", format="sql",
        # Backtick-dotted identifier — the real Nebulock `sql` engine's convention
        # (see extract_sql_fields' docstring); bare `user.name` parses as a
        # table-qualified column and sqlglot drops the `user.` qualifier.
        query="`user.name` = 'admin'", query_language="sql", data_source="wineventlog",
    )
    for rec in (good, bad_engine, undeclared_type):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    return ws


def test_allowed_engines_is_the_closed_four_set():
    assert ALLOWED_ENGINES == frozenset({"sigma", "sql", "sch_sql", "composite"})


def test_flags_engine_outside_closed_set(workspace: Path):
    result = run_schema_check(workspace, detection_ids=("D-0002",))
    assert "D-0002" in result.engine_errors
    assert "atomic_sql" in result.engine_errors["D-0002"]


def test_does_not_flag_allowed_engine(workspace: Path):
    result = run_schema_check(workspace, detection_ids=("D-0001",))
    assert "D-0001" not in result.engine_errors


def test_flags_field_with_no_declared_type(workspace: Path):
    result = run_schema_check(workspace, detection_ids=("D-0003",))
    assert "user.name" in result.undeclared_type_fields.get("D-0003", [])


def test_existing_behavior_preserved_whole_catalog(workspace: Path):
    # No `detection_ids` filter — the pre-existing whole-catalog mode must still work.
    result = run_schema_check(workspace)
    assert result.rules_checked >= 1
