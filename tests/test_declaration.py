"""Tests for data-source declarations (adef/core/declaration.py) and the
schema ingest/lint/check CLI (ISA 2026-07-20)."""

from __future__ import annotations

import json
import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.schema import schema as schema_cli
from adef.core.declaration import (
    DeclarationError,
    ingest_source,
    known_field_names,
    lint_declaration_dict,
    load_declaration,
    read_schema_v2,
)

DECLARATION = {
    "version": 1,
    "sources": [
        {
            "name": "wineventlog",
            "platform": "windows",
            "query_language": "spl",
            "description": "Windows Security events",
            "fields": [
                {"name": "EventCode", "type": "int", "values": [4624, 4688]},
                {"name": "CommandLine"},
                {"name": "user", "aliases": ["User", "user_name"]},
            ],
        }
    ],
}


def _decl(tmp_path, data=DECLARATION, name="adef-sources.yml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Lint
# --------------------------------------------------------------------------- #
def test_lint_valid_no_errors():
    errors, warnings = lint_declaration_dict(DECLARATION)
    assert errors == []
    assert warnings == []


def test_lint_low_floor_names_only():
    minimal = {"version": 1, "sources": [{"name": "s", "fields": [{"name": "f"}]}]}
    errors, warnings = lint_declaration_dict(minimal)
    assert errors == []
    assert any("query_language" in w for w in warnings)  # warned, not blocked


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        (lambda d: d.update(version=2), "version"),
        (lambda d: d["sources"][0].pop("name"), "name"),
        (lambda d: d["sources"][0].update(name="a/b"), "path separators"),
        (lambda d: d["sources"][0].update(query_language="lucene"), "query_language"),
        (lambda d: d["sources"][0]["fields"][0].update(type="varchar"), "type"),
        (lambda d: d["sources"][0].update(typo_key=1), "unknown keys"),
        (lambda d: d["sources"][0]["fields"].append({"name": "EventCode"}), "duplicate field"),
        (lambda d: d.update(sources=[]), "non-empty"),
    ],
)
def test_lint_rejects(mutate, fragment):
    data = json.loads(json.dumps(DECLARATION))  # deep copy
    mutate(data)
    errors, _ = lint_declaration_dict(data)
    assert errors and any(fragment in e for e in errors)


def test_load_declaration_raises_with_filename(tmp_path):
    p = _decl(tmp_path, {"version": 9})
    with pytest.raises(DeclarationError) as exc:
        load_declaration(p)
    assert "adef-sources.yml" in str(exc.value)


# --------------------------------------------------------------------------- #
# Ingest + provenance merge + drift
# --------------------------------------------------------------------------- #
def test_ingest_writes_v2_schema(tmp_path):
    sources = load_declaration(_decl(tmp_path))
    path, drift = ingest_source(sources[0], tmp_path / "schema")
    data = read_schema_v2(path)
    assert data is not None
    assert data["source"] == "wineventlog"
    assert data["query_language"] == "spl"
    names = [f["name"] for f in data["fields"]]
    assert names == sorted(["EventCode", "CommandLine", "user"])
    assert all(f["provenance"] == "declared" for f in data["fields"])
    assert not drift.any  # first ingest: no previous declaration


def test_reingest_preserves_corrections_and_reports_drift(tmp_path):
    schema_dir = tmp_path / "schema"
    sources = load_declaration(_decl(tmp_path))
    path, _ = ingest_source(sources[0], schema_dir)

    # Human corrects a type and adds a field.
    data = yaml.safe_load(path.read_text())
    for f in data["fields"]:
        if f["name"] == "EventCode":
            f["type"] = "string"
            f["provenance"] = "corrected"
    data["fields"].append(
        {"name": "LogonType", "type": "int", "description": "", "values": [],
         "aliases": [], "provenance": "corrected"}
    )
    path.write_text(yaml.safe_dump(data, sort_keys=False))

    # New declaration: drops CommandLine, adds ParentImage, re-declares
    # EventCode as int (shadowed by the correction).
    new = json.loads(json.dumps(DECLARATION))
    new["sources"][0]["fields"] = [
        {"name": "EventCode", "type": "int"},
        {"name": "user"},
        {"name": "ParentImage"},
    ]
    sources2 = load_declaration(_decl(tmp_path, new, "v2.yml"))
    path2, drift = ingest_source(sources2[0], schema_dir)

    result = read_schema_v2(path2)
    by_name = {f["name"]: f for f in result["fields"]}
    assert by_name["EventCode"]["type"] == "string"  # correction shadows declaration
    assert by_name["EventCode"]["provenance"] == "corrected"
    assert "LogonType" in by_name  # human-added field survives
    assert "ParentImage" in by_name and by_name["ParentImage"]["provenance"] == "declared"
    assert "CommandLine" not in by_name  # dropped from declared set
    assert drift.added == ["ParentImage"]
    assert drift.removed == ["CommandLine"]
    assert "LogonType" in drift.corrected_kept


def test_known_field_names_include_aliases(tmp_path):
    sources = load_declaration(_decl(tmp_path))
    path, _ = ingest_source(sources[0], tmp_path / "schema")
    names = known_field_names(read_schema_v2(path))
    assert {"user", "User", "user_name", "EventCode"} <= names


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@pytest.fixture
def ws(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    return ws


def test_cli_lint_ok_and_fail(tmp_path):
    good = _decl(tmp_path)
    assert CliRunner().invoke(schema_cli, ["lint", str(good)]).exit_code == 0
    bad = _decl(tmp_path, {"version": 9}, "bad.yml")
    assert CliRunner().invoke(schema_cli, ["lint", str(bad)]).exit_code != 0


def test_cli_ingest_creates_schema(ws, tmp_path):
    result = CliRunner().invoke(schema_cli, ["ingest", str(_decl(tmp_path))])
    assert result.exit_code == 0, result.output
    assert read_schema_v2(ws / "schema" / "wineventlog.yml") is not None
    assert "Ingested" in result.output


def test_cli_show_renders_v2(ws, tmp_path):
    CliRunner().invoke(schema_cli, ["ingest", str(_decl(tmp_path))])
    result = CliRunner().invoke(schema_cli, ["show", "wineventlog"])
    assert result.exit_code == 0, result.output
    assert "schema v2" in result.output and "EventCode" in result.output


def test_cli_check_reports_both_finding_types(ws, tmp_path):
    # Schema for wineventlog…
    CliRunner().invoke(schema_cli, ["ingest", str(_decl(tmp_path))])
    # …and a catalogued SPL rule that uses a declared field, an alias, and an
    # undeclared field.
    from adef.commands.catalog import catalog as catalog_cli

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "saved.conf").write_text(
        textwrap.dedent(
            """\
            [Acme rule]
            search = index=wineventlog EventCode=4688 user_name=admin \
| stats count by NotDeclaredField
            """
        ),
        encoding="utf-8",
    )
    r = CliRunner().invoke(catalog_cli, [str(repo)])
    assert r.exit_code == 0, r.output

    result = CliRunner().invoke(schema_cli, ["check", "--report", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.output)
    assert report["rules_checked"] == 1
    missing = report["missing_from_schema"].get("wineventlog", {})
    assert "NotDeclaredField" in missing
    assert "EventCode" not in missing  # declared
    assert "user_name" not in missing  # alias
    assert "CommandLine" in report["unused_by_rules"]["wineventlog"]


def test_old_model_commands_are_gone():
    """The rules-derived schema model was removed pre-release (ISA 2026-07-20)."""
    commands = set(schema_cli.commands)
    assert commands == {"ingest", "lint", "check", "show"}


# --------------------------------------------------------------------------- #
# Scope (ISA 2026-07-21): name is what a schema IS; scope is every way a
# query might ADDRESS it. Most-specific match wins; ties = union.
# --------------------------------------------------------------------------- #
SCOPED_DECLARATION = {
    "version": 1,
    "sources": [
        {
            "name": "sysmon_operational",
            "platform": "windows",
            "query_language": "spl",
            "scope": {
                "index": "wineventlog",
                "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            },
            "fields": [{"name": "CallTrace"}, {"name": "GrantedAccess"}],
        },
        {
            "name": "windows_dns",
            "platform": "windows",
            "query_language": "spl",
            "scope": {"index": "wineventlog", "sourcetype": "MSDNS"},
            "fields": [{"name": "answer_count", "type": "int"}, {"name": "query_type"}],
        },
    ],
}


def test_lint_scope_valid_and_invalid():
    errors, _ = lint_declaration_dict(json.loads(json.dumps(SCOPED_DECLARATION)))
    assert errors == []
    bad = json.loads(json.dumps(SCOPED_DECLARATION))
    bad["sources"][0]["scope"] = ["not", "a", "mapping"]
    errors, _ = lint_declaration_dict(bad)
    assert any("scope" in e for e in errors)
    bad = json.loads(json.dumps(SCOPED_DECLARATION))
    bad["sources"][0]["scope"] = {"index": {"nested": "no"}}
    errors, _ = lint_declaration_dict(bad)
    assert any("scalar" in e for e in errors)


def test_ingest_carries_scope(tmp_path):
    sources = load_declaration(_decl(tmp_path, SCOPED_DECLARATION, "scoped.yml"))
    path, _ = ingest_source(sources[0], tmp_path / "schema")
    data = read_schema_v2(path)
    assert data["scope"] == {
        "index": "wineventlog",
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    }


def _catalog_conf_rule(tmp_path, name, search):
    from adef.commands.catalog import catalog as catalog_cli

    repo = tmp_path / f"repo-{name}"
    repo.mkdir()
    (repo / f"{name}.conf").write_text(f"[{name}]\nsearch = {search}\n", encoding="utf-8")
    result = CliRunner().invoke(catalog_cli, [str(repo)])
    assert result.exit_code == 0, result.output


def _check_report(ws):
    result = CliRunner().invoke(schema_cli, ["check", "--report", "json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_check_container_only_rule_matches_union(ws, tmp_path):
    """A rule filtered only by index could see any shape in it → checked
    against the union; fields from either scoped source are legitimate."""
    CliRunner().invoke(schema_cli, ["ingest", str(_decl(tmp_path, SCOPED_DECLARATION, "s.yml"))])
    _catalog_conf_rule(
        tmp_path, "union",
        "index=wineventlog CallTrace=x answer_count=3 BogusField=1",
    )
    report = _check_report(ws)
    assert report["rules_checked"] == 1
    all_missing = {f for fields in report["missing_from_schema"].values() for f in fields}
    assert "CallTrace" not in all_missing      # sysmon field, union-legit
    assert "answer_count" not in all_missing   # dns field, union-legit
    assert "BogusField" in all_missing         # in neither
    assert "index" not in all_missing          # meta pseudo-field ignored


def test_check_shape_pinned_rule_narrows(ws, tmp_path):
    """A rule that pins sourcetype= matches only that source — a field from
    the sibling shape is now a finding (most-specific match wins)."""
    CliRunner().invoke(schema_cli, ["ingest", str(_decl(tmp_path, SCOPED_DECLARATION, "s.yml"))])
    _catalog_conf_rule(
        tmp_path, "narrow",
        "index=wineventlog sourcetype=MSDNS CallTrace=oops query_type=A",
    )
    report = _check_report(ws)
    missing = report["missing_from_schema"]
    assert "CallTrace" in missing.get("windows_dns", {})   # flagged: wrong shape
    assert "sysmon_operational" not in missing             # not matched at all


def test_check_covers_profile_claimed_rules_via_query_language(ws, tmp_path):
    """query_language persisted on records (2026-07-21) makes profile-claimed
    rules checkable even though their `format` is the profile name."""
    from adef.commands.catalog import catalog as catalog_cli

    # Profile teaching an in-house SQL wrapper, saved as a workspace profile.
    (ws / "config" / "profiles").mkdir(parents=True)
    (ws / "config" / "profiles" / "acme-sql.yml").write_text(
        yaml.safe_dump({
            "name": "acme-sql", "version": 1,
            "signature": {"container": "yaml", "all_keys": ["alert"]},
            "query_language": "sql",
            "map": {"title": "alert.name", "query": "alert.query"},
        }),
        encoding="utf-8",
    )
    repo = tmp_path / "sql-repo"
    repo.mkdir()
    (repo / "r.yml").write_text(
        "alert:\n  name: R\n  query: SELECT NotAField FROM cloudtrail WHERE eventName='X'\n",
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0

    decl = {"version": 1, "sources": [{
        "name": "cloudtrail", "query_language": "sql",
        "fields": [{"name": "eventName"}, {"name": "userIdentity"}],
    }]}
    CliRunner().invoke(schema_cli, ["ingest", str(_decl(tmp_path, decl, "ct.yml"))])
    report = _check_report(ws)
    assert report["rules_checked"] == 1
    assert "NotAField" in report["missing_from_schema"].get("cloudtrail", {})
