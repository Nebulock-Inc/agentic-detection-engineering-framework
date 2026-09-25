from pathlib import Path

import pytest
import yaml

from adef.core.catalog import Catalog, CatalogRecord
from adef.agents.verification import VerificationAgent


def _schema_v2(source: str, fields: list[dict]) -> dict:
    return {"schema_version": 2, "source": source, "fields": fields, "scope": {"index": source}}


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "schema").mkdir(parents=True)
    (ws / "schema" / "wineventlog.yml").write_text(
        yaml.safe_dump(_schema_v2("wineventlog", [{"name": "process.name", "type": "string"}])),
        encoding="utf-8",
    )
    cat = Catalog(ws)
    good = CatalogRecord(
        id="D-0001", title="ok", rule_ref="r/d1.yml", original_path="/tmp/d1.yml",
        platform="windows", kind="atomic", engine="sql", format="sql",
        # Backtick-dotted identifier — the real Nebulock `sql` engine's
        # convention (see extract_sql_fields' docstring); bare `process.name`
        # parses as a table-qualified column and sqlglot drops the qualifier.
        query="`process.name` = 'mshta.exe'", query_language="sql", data_source="wineventlog",
    )
    bad = CatalogRecord(
        id="D-0002", title="bad", rule_ref="r/d2.yml", original_path="/tmp/d2.yml",
        platform="windows", kind="atomic", engine="atomic_sql", format="sql",
        query="`user.name` = 'admin'", query_language="sql", data_source="wineventlog",
    )
    for rec in (good, bad):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    return ws


def test_passes_a_conformant_rule(workspace: Path):
    result = VerificationAgent().run(detection_id="D-0001", workspace=workspace)
    assert result["passed"] is True
    assert result["engine_error"] is None
    assert result["schema_matched"] is True


def test_undeclared_source_passes_but_reports_nothing_was_matched(workspace: Path):
    """A rule whose literals match no schema must not read as field-verified.

    This is the normal state of a freshly imported hunt detection: `passed` is
    True because the engine check found no defect, so `schema_matched` is the
    only thing distinguishing that from "every field checked out".
    """
    rec = CatalogRecord(
        id="D-0003", title="no schema", rule_ref="r/d3.yml", original_path="/tmp/d3.yml",
        platform="windows", kind="atomic", engine="sql", format="sql",
        query="SELECT `process.name` FROM undeclared_source", query_language="sql",
        data_source="undeclared_source",
    )
    Catalog(workspace).write_raw(workspace / "catalog" / "D-0003.yml", rec.to_yaml_dict())

    result = VerificationAgent().run(detection_id="D-0003", workspace=workspace)
    assert result["passed"] is True
    assert result["schema_matched"] is False
    assert result["missing_schema_fields"] == []


def test_fails_on_bad_engine_and_unknown_field(workspace: Path):
    result = VerificationAgent().run(detection_id="D-0002", workspace=workspace)
    assert result["passed"] is False
    assert "atomic_sql" in result["engine_error"]
    assert "user.name" in result["missing_schema_fields"]


def test_unknown_detection_id_raises(workspace: Path):
    with pytest.raises(ValueError, match="D-9999"):
        VerificationAgent().run(detection_id="D-9999", workspace=workspace)


# --- Wrapper dispatch (native by default; ADEF_WRAPPER_VERIFICATION overrides) ---

def test_wrapper_runs_native_agent_when_binding_unset(workspace: Path, monkeypatch):
    monkeypatch.delenv("ADEF_WRAPPER_VERIFICATION", raising=False)
    from adef.agents.wrappers.verification import VerificationWrapper

    result = VerificationWrapper().run(detection_id="D-0001", workspace=workspace)
    assert result["detection_id"] == "D-0001"
    assert result["result"]["passed"] is True


def test_wrapper_raises_when_binding_set_but_unimportable(workspace: Path, monkeypatch):
    monkeypatch.setenv("ADEF_WRAPPER_VERIFICATION", "not_a_real_module:NotARealClass")
    from adef.agents.wrappers import WrapperUnavailable
    from adef.agents.wrappers.verification import VerificationWrapper

    with pytest.raises(WrapperUnavailable):
        VerificationWrapper().run(detection_id="D-0001", workspace=workspace)


def test_wrapper_propagates_no_catalog_record(workspace: Path, monkeypatch):
    """A journal-only detection is NOT "wrapper unavailable" — the wrapper must
    let the distinct type through so refine_chain can say what's actually true."""
    monkeypatch.delenv("ADEF_WRAPPER_VERIFICATION", raising=False)
    from adef.agents.wrappers.verification import VerificationWrapper
    from adef.core.catalog import NoCatalogRecordError

    with pytest.raises(NoCatalogRecordError, match="D-9999"):
        VerificationWrapper().run(detection_id="D-9999", workspace=workspace)
