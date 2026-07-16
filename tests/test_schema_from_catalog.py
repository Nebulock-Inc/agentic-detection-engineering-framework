"""Tests for ``adef schema from-catalog`` — generate schemas from the catalog.

Per ISA.md 2026-07-16: group catalogued rules by (data_source, query_language)
into ``schema/<data_source>.yml``; rules with no inferred source fall back to
pool-by-language (``schema/<language>.yml``). Sigma is excluded (structured
YAML, not a query language).
"""

from __future__ import annotations

import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.schema import schema
from adef.commands.catalog import catalog


@pytest.fixture
def catalogued_workspace(tmp_path, monkeypatch):
    """A workspace with a catalog built from a small multi-source repo."""
    repo = tmp_path / "their-detections"
    (repo / "cloud").mkdir(parents=True)
    (repo / "defender").mkdir(parents=True)

    # Two SQL rules on the SAME source (cloudtrail) — should merge into one schema.
    (repo / "cloud" / "iam1.sql").write_text(
        "SELECT user_name, event_name FROM cloudtrail WHERE region = 'us-east-1'",
        encoding="utf-8",
    )
    (repo / "cloud" / "iam2.sql").write_text(
        "SELECT source_ip FROM cloudtrail WHERE event_name = 'ConsoleLogin'",
        encoding="utf-8",
    )
    # A KQL rule on DeviceProcessEvents.
    (repo / "defender" / "lsass.kql").write_text(
        "DeviceProcessEvents | where FileName == \"lsass.exe\" | project FileName",
        encoding="utf-8",
    )
    # A SQL rule with NO from clause → un-inferrable source → pools by language.
    (repo / "cloud" / "weird.sql").write_text("SELECT 1", encoding="utf-8")

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    CliRunner().invoke(catalog, [str(repo)])
    return ws


def test_from_catalog_help():
    result = CliRunner().invoke(schema, ["from-catalog", "--help"])
    assert result.exit_code == 0
    assert "catalog" in result.output.lower()


def test_from_catalog_writes_per_source_schema(catalogued_workspace):
    ws = catalogued_workspace
    result = CliRunner().invoke(schema, ["from-catalog"])
    assert result.exit_code == 0, result.output

    cloudtrail = ws / "schema" / "cloudtrail.yml"
    assert cloudtrail.exists()
    data = yaml.safe_load(cloudtrail.read_text())
    assert data["source"] == "cloudtrail"
    assert data["query_language"] == "sql"
    # Both cloudtrail rules' fields merged into one schema.
    names = {f["name"] for f in data["fields"]}
    assert {"user_name", "event_name", "region", "source_ip"} <= names
    assert all(f["in_rules"] for f in data["fields"])


def test_from_catalog_kql_source(catalogued_workspace):
    ws = catalogued_workspace
    CliRunner().invoke(schema, ["from-catalog"])
    kql = ws / "schema" / "DeviceProcessEvents.yml"
    assert kql.exists()
    data = yaml.safe_load(kql.read_text())
    assert data["query_language"] == "kql"
    assert "FileName" in {f["name"] for f in data["fields"]}


def test_uninferred_source_pools_by_language(catalogued_workspace):
    """A SQL rule with no FROM clause pools into schema/sql.yml."""
    ws = catalogued_workspace
    CliRunner().invoke(schema, ["from-catalog"])
    fallback = ws / "schema" / "sql.yml"
    assert fallback.exists()


def test_from_catalog_excludes_sigma(tmp_path, monkeypatch):
    """Sigma rules are not a query language — no schema generated for them."""
    repo = tmp_path / "rules"
    (repo / "win").mkdir(parents=True)
    (repo / "win" / "r.yml").write_text(
        textwrap.dedent(
            """\
            title: t
            id: 11111111-1111-1111-1111-111111111111
            logsource:
                category: process_creation
                product: windows
            detection:
                condition: selection
            tags: [attack.t1059]
            """
        ),
        encoding="utf-8",
    )
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    CliRunner().invoke(catalog, [str(repo)])

    result = CliRunner().invoke(schema, ["from-catalog"])
    assert result.exit_code == 0
    # No schema file should be written for the sigma-only catalog.
    schema_files = list((ws / "schema").glob("*.yml")) if (ws / "schema").is_dir() else []
    assert schema_files == []


def test_from_catalog_reports_summary(catalogued_workspace):
    result = CliRunner().invoke(schema, ["from-catalog"])
    # Reports how many schemas written + the fallback bucket.
    assert "cloudtrail" in result.output
