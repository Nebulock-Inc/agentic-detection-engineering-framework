"""Tests for the needs_review rework (ISA 2026-07-21): review_reasons,
declaration-based platform inheritance, no_mitre demotion, and the tier-2
MITRE text-sweep for profile-claimed rules."""

from __future__ import annotations

import json
import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog as catalog_cli
from adef.commands.detection import detection as detection_cli
from adef.commands.schema import schema as schema_cli
from adef.core.profiles import profile_from_dict
from adef.core.rule_discovery import discover_rules, structural_reasons


@pytest.fixture
def ws(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    return ws


DECL = {
    "version": 1,
    "sources": [
        {
            "name": "wineventlog_xml",
            "platform": "windows",
            "query_language": "spl",
            "scope": {"index": "thrunt", "sourcetype": "XmlWinEventLog"},
            "fields": [{"name": "EventCode"}, {"name": "CommandLine"}],
        },
        {
            "name": "zeek_dns",
            "platform": "network",
            "query_language": "spl",
            "scope": {"index": "thrunt", "sourcetype": "bro:dns:json"},
            "fields": [{"name": "qtype_name"}],
        },
    ],
}


def _repo(tmp_path):
    repo = tmp_path / "rules"
    repo.mkdir()
    (repo / "pinned.conf").write_text(
        "# T1218.005\n[Pinned rule]\nsearch = index=thrunt sourcetype=XmlWinEventLog EventCode=1\n",
        encoding="utf-8",
    )
    (repo / "broad.conf").write_text(
        "[Broad rule]\nsearch = index=thrunt CommandLine=*\n",  # ambiguous container, no MITRE
        encoding="utf-8",
    )
    return repo


# --------------------------------------------------------------------------- #
# Reasons on records
# --------------------------------------------------------------------------- #
def test_reasons_persisted_on_records(ws, tmp_path):
    assert CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))]).exit_code == 0
    records = {
        d["title"]: d
        for d in (
            yaml.safe_load(p.read_text()) for p in (ws / "catalog").rglob("D-*.yml")
        )
    }
    assert records["Pinned rule"]["review_reasons"] == ["no_platform"]
    assert set(records["Broad rule"]["review_reasons"]) == {"no_platform", "no_mitre"}
    assert all(d["needs_review"] for d in records.values())


def test_structural_reasons_exclude_no_mitre():
    assert structural_reasons(["no_platform", "no_mitre"]) == ("no_platform",)
    assert structural_reasons(["no_mitre"]) == ()


# --------------------------------------------------------------------------- #
# Platform inheritance from declared schemas
# --------------------------------------------------------------------------- #
def test_platform_inherited_from_declarations(ws, tmp_path):
    decl = tmp_path / "decl.yml"
    decl.write_text(yaml.safe_dump(DECL), encoding="utf-8")
    assert CliRunner().invoke(schema_cli, ["ingest", str(decl)]).exit_code == 0

    result = CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "platform(s) inherited" in result.output

    records = {
        d["title"]: d
        for d in (
            yaml.safe_load(p.read_text()) for p in (ws / "catalog").rglob("D-*.yml")
        )
    }
    # sourcetype-pinned rule: unambiguous → inherits windows, no_platform gone.
    pinned = records["Pinned rule"]
    assert pinned["platform"] == "windows"
    assert "no_platform" not in pinned["review_reasons"]
    assert pinned["needs_review"] is False  # MITRE present via comment sweep
    # container-only rule: two sources, two platforms → ambiguous, never guess.
    broad = records["Broad rule"]
    assert broad["platform"] == "multi-platform"
    assert "no_platform" in broad["review_reasons"]


# --------------------------------------------------------------------------- #
# list: structural headline + reason filters
# --------------------------------------------------------------------------- #
def test_list_headline_and_reason_filters(ws, tmp_path):
    decl = tmp_path / "decl.yml"
    decl.write_text(yaml.safe_dump(DECL), encoding="utf-8")
    CliRunner().invoke(schema_cli, ["ingest", str(decl)])
    CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))])

    out = CliRunner().invoke(detection_cli, ["list"]).output
    assert "1" in out and "need review" in out          # only Broad (structural)
    assert "missing ATT&CK" in out                      # enrichment queue surfaced

    out = CliRunner().invoke(detection_cli, ["list", "--needs-review"]).output
    assert "Broad rule" in out and "Pinned rule" not in out

    out = CliRunner().invoke(detection_cli, ["list", "--needs-review", "no_mitre"]).output
    assert "Broad rule" in out and "Pinned rule" not in out

    data = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    assert all("review_reasons" in d for d in data)


# --------------------------------------------------------------------------- #
# Tier-2 MITRE sweep for profile-claimed rules
# --------------------------------------------------------------------------- #
def test_profile_rules_get_mitre_text_sweep(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "r.yml").write_text(
        textwrap.dedent(
            """\
            alert:
              name: Acme lateral movement
              description: Detects psexec-style moves. MITRE T1021.002.
              query: SELECT 1 FROM events
            """
        ),
        encoding="utf-8",
    )
    prof = profile_from_dict(
        {
            "name": "acme", "version": 1,
            "signature": {"container": "yaml", "all_keys": ["alert"]},
            "query_language": "sql",
            "map": {
                "title": "alert.name",
                "query": "alert.query",
                "description": "alert.description",
            },
        }
    )
    rules = list(discover_rules(root, [prof]))
    assert rules[0].mitre == ("T1021.002",)  # swept from description
    assert "no_mitre" not in rules[0].review_reasons
