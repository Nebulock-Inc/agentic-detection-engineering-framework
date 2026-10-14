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
        # Backtick-quoted dotted identifier (see extract_sql_fields'
        # docstring); bare `process.name`
        # parses as a table-qualified column and sqlglot drops the qualifier.
        query="`process.name` = 'mshta.exe'", query_language="sql", data_source="wineventlog",
    )
    bad = CatalogRecord(
        id="D-0002", title="bad", rule_ref="r/d2.yml", original_path="/tmp/d2.yml",
        platform="windows", kind="atomic", engine="custom_sql", format="sql",
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
    assert "custom_sql" in result["engine_error"]
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


# --- status / checks / fields_not_run_reason ---

def _put(ws: Path, rid: str, query: str, *, source="wineventlog", lang="sql", fmt="sql", engine="sql"):
    rec = CatalogRecord(id=rid, title=rid, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
                        platform="windows", kind="atomic", engine=engine, format=fmt,
                        query=query, query_language=lang, data_source=source)
    Catalog(ws).write_raw(ws / "catalog" / f"{rid}.yml", rec.to_yaml_dict())


def test_clean_rule_is_status_passed(workspace: Path):
    r = VerificationAgent().run(detection_id="D-0001", workspace=workspace)
    assert (r["status"], r["checks"], r["fields_not_run_reason"]) == (
        "passed", {"engine": "passed", "fields": "passed"}, None)


def test_engine_defect_is_status_failed(workspace: Path):
    r = VerificationAgent().run(detection_id="D-0002", workspace=workspace)
    assert r["status"] == "failed" and r["checks"]["engine"] == "failed"


def test_unmatched_source_is_partial_not_passed(workspace: Path):
    _put(workspace, "D-0010", "`process.name` = 'x'", source="undeclared_source")
    r = VerificationAgent().run(detection_id="D-0010", workspace=workspace)
    assert r["passed"] is True  # compatibility: no defect found
    assert (r["status"], r["checks"]["fields"], r["fields_not_run_reason"]) == (
        "partial", "not_run", "no_schema_matches")


def test_no_schemas_at_all_names_that_reason(workspace: Path):
    for f in (workspace / "schema").glob("*.yml"):
        f.unlink()
    r = VerificationAgent().run(detection_id="D-0001", workspace=workspace)
    assert (r["status"], r["fields_not_run_reason"]) == ("partial", "no_schemas_declared")


def test_unparseable_query_names_that_reason(workspace: Path):
    _put(workspace, "D-0011", "{% if x %} SELECT {{ y }}", lang="", fmt="eql")
    r = VerificationAgent().run(detection_id="D-0011", workspace=workspace)
    assert (r["status"], r["fields_not_run_reason"]) == ("partial", "unparseable_query")


def test_grouping_columns_missing_from_schema_do_not_fail(workspace: Path):
    # BY columns the schema doesn't declare failed every
    # Splunk rule. Filter fields gate; grouping columns are reported only.
    (workspace / "schema" / "splunk.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "sysmon", "query_language": "spl",
        "fields": [{"name": "process_name", "type": "string"}], "scope": {"index": "sysmon"},
    }), encoding="utf-8")
    _put(workspace, "D-0012", "index=sysmon process_name=mshta.exe | stats count by dest user",
         source="sysmon", lang="spl", fmt="splunk-escu")
    r = VerificationAgent().run(detection_id="D-0012", workspace=workspace)
    assert r["missing_grouping_fields"] == ["dest", "user"], r
    assert r["missing_schema_fields"] == []
    assert r["status"] == "passed" and r["passed"] is True


def test_a_missing_filter_field_still_fails(workspace: Path):
    (workspace / "schema" / "splunk.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "sysmon", "query_language": "spl",
        "fields": [{"name": "dest", "type": "string"}], "scope": {"index": "sysmon"},
    }), encoding="utf-8")
    _put(workspace, "D-0013", "index=sysmon process_name=mshta.exe | stats count by dest",
         source="sysmon", lang="spl", fmt="splunk-escu")
    r = VerificationAgent().run(detection_id="D-0013", workspace=workspace)
    assert r["missing_schema_fields"] == ["process_name"]
    assert r["status"] == "failed" and r["checks"]["fields"] == "failed"


def test_projection_only_query_does_not_fail_on_a_projected_column(workspace: Path):
    # CodeRabbit CLI: a query with no filter at all must not fail because a
    # column it only projects is missing from the schema.
    (workspace / "schema" / "kql.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "secevt", "query_language": "kql",
        "fields": [{"name": "Account", "type": "string"}], "scope": {"table": "secevt"},
    }), encoding="utf-8")
    _put(workspace, "D-0014", "secevt | project Computer, Account", source="secevt", lang="kql", fmt="kql")
    r = VerificationAgent().run(detection_id="D-0014", workspace=workspace)
    assert r["missing_grouping_fields"] == ["Computer"] and r["missing_schema_fields"] == [], r
    assert r["status"] == "passed"


def test_failed_predicate_extraction_keeps_every_missing_field_gating(workspace: Path, monkeypatch):
    # If the predicate extractor raises, nothing is demoted to "grouping":
    # a real defect must not be waved through.
    import adef.agents.verification as v

    def boom(_q):
        raise ValueError("parse failure")

    monkeypatch.setitem(v.PREDICATE_FIELD_EXTRACTORS, "spl", boom)
    (workspace / "schema" / "splunk.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "sysmon", "query_language": "spl",
        "fields": [{"name": "process_name", "type": "string"}], "scope": {"index": "sysmon"},
    }), encoding="utf-8")
    _put(workspace, "D-0015", "index=sysmon process_name=mshta.exe | stats count by dest",
         source="sysmon", lang="spl", fmt="splunk-escu")
    r = VerificationAgent().run(detection_id="D-0015", workspace=workspace)
    assert r["missing_grouping_fields"] == [] and r["missing_schema_fields"] == ["dest"], r
    assert r["status"] == "failed"
