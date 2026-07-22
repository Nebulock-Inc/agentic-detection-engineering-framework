"""Tests for the shared rule-repo discovery layer.

``rule_discovery`` walks a detection repo (read-only), sniffs each file's
format, and returns a ``DiscoveredRule`` carrying the query text plus
best-effort metadata (platform, MITRE, kind, engine, format, query_language).
Both the catalog engine and the schema rule-scanner consume it.

The distinction that matters here:

- ``format`` / ``query_language`` — the *true* source format (sigma, spl, kql,
  cql, sql). Lossless.
- ``engine`` — ADEF's internal four-value taxonomy (sigma, sql, sch_sql,
  composite) used by the rest of the framework and guarded by
  ``tests/test_no_new_engine_types.py``. Non-Sigma formats fold to sql/composite
  here; the true format lives in ``format``.
"""

from __future__ import annotations

import textwrap

import pytest

from adef.core.rule_discovery import discover_rules, sniff_format


# --------------------------------------------------------------------------- #
# Fixtures — a small multi-format repo on disk
# --------------------------------------------------------------------------- #
@pytest.fixture
def rule_repo(tmp_path):
    """A repo with one file per supported format."""
    root = tmp_path / "their-detections"

    sigma = root / "windows"
    sigma.mkdir(parents=True)
    (sigma / "mshta_child.yml").write_text(
        textwrap.dedent(
            """\
            title: Suspicious mshta.exe child process
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    ParentImage|endswith: '\\mshta.exe'
                    Image|endswith:
                        - '\\powershell.exe'
                        - '\\cmd.exe'
                condition: selection
            tags:
                - attack.t1218.005
                - attack.defense_evasion
            """
        ),
        encoding="utf-8",
    )

    sqldir = root / "cloud"
    sqldir.mkdir(parents=True)
    (sqldir / "iam_backdoor.sql").write_text(
        "SELECT user_name, event_name FROM cloudtrail "
        "WHERE event_name = 'CreateUser'",
        encoding="utf-8",
    )

    kqldir = root / "defender"
    kqldir.mkdir(parents=True)
    (kqldir / "lsass_access.kql").write_text(
        "DeviceProcessEvents | where FileName == \"lsass.exe\" "
        "| project FileName, ProcessCommandLine",
        encoding="utf-8",
    )

    spldir = root / "splunk"
    spldir.mkdir(parents=True)
    (spldir / "savedsearches.conf").write_text(
        textwrap.dedent(
            """\
            [Suspicious PowerShell Encoded Command]
            search = index=edr process_name="powershell.exe" command_line="*-enc*"
            | stats count by host, command_line
            """
        ),
        encoding="utf-8",
    )

    # A non-rule file that must be ignored.
    (root / "README.md").write_text("# our detections", encoding="utf-8")

    return root


# --------------------------------------------------------------------------- #
# sniff_format
# --------------------------------------------------------------------------- #
def test_sniff_sigma_by_content():
    """A YAML file with detection: + logsource: is Sigma, not generic YAML."""
    text = "title: x\nlogsource:\n  product: windows\ndetection:\n  condition: selection\n"
    assert sniff_format("rule.yml", text) == "sigma"


def test_sniff_sql_by_extension():
    assert sniff_format("q.sql", "SELECT a FROM t") == "sql"


def test_sniff_kql_by_extension():
    assert sniff_format("q.kql", "T | where x == 1") == "kql"


def test_sniff_splunk_conf():
    assert sniff_format("savedsearches.conf", "[stanza]\nsearch = index=x") == "spl"


def test_sniff_unknown_returns_none():
    assert sniff_format("README.md", "# hi") is None


# --------------------------------------------------------------------------- #
# discover_rules
# --------------------------------------------------------------------------- #
def test_discover_finds_all_formats(rule_repo):
    rules = list(discover_rules(rule_repo))
    formats = {r.format for r in rules}
    assert formats == {"sigma", "sql", "kql", "spl"}


def test_discover_ignores_non_rule_files(rule_repo):
    paths = [r.path.name for r in discover_rules(rule_repo)]
    assert "README.md" not in paths


def test_sigma_extracts_metadata(rule_repo):
    rules = {r.format: r for r in discover_rules(rule_repo)}
    sigma = rules["sigma"]
    assert sigma.title == "Suspicious mshta.exe child process"
    assert sigma.platform == "windows"
    assert "T1218.005" in sigma.mitre
    assert sigma.engine == "sigma"
    assert sigma.query_language == "sigma"
    assert sigma.kind == "atomic"
    assert sigma.rule_uuid == "03cc0c25-389f-4bf8-b48d-11878079f1ca"


def test_sql_maps_to_sql_engine_and_query_language(rule_repo):
    rules = {r.format: r for r in discover_rules(rule_repo)}
    sql = rules["sql"]
    assert sql.engine == "sql"
    assert sql.query_language == "sql"
    assert sql.format == "sql"
    assert "cloudtrail" in sql.query_text.lower()


def test_kql_preserves_true_format_and_folds_engine(rule_repo):
    """KQL keeps format=kql/query_language=kql; engine folds to the internal set."""
    rules = {r.format: r for r in discover_rules(rule_repo)}
    kql = rules["kql"]
    assert kql.format == "kql"
    assert kql.query_language == "kql"
    # Non-Sigma engines fold into the internal four-value taxonomy.
    assert kql.engine in {"sql", "composite"}
    assert kql.platform == "windows"


def test_ambiguous_rule_flagged_needs_review(rule_repo):
    """A raw SQL file has no platform/MITRE — must be flagged for review."""
    rules = {r.format: r for r in discover_rules(rule_repo)}
    sql = rules["sql"]
    assert sql.needs_review is True
    assert sql.mitre == ()


def test_sigma_not_flagged_needs_review(rule_repo):
    """A fully-tagged Sigma rule needs no review."""
    rules = {r.format: r for r in discover_rules(rule_repo)}
    assert rules["sigma"].needs_review is False


# --------------------------------------------------------------------------- #
# data_source — the raw table/index/logsource literal (verbatim, no normalise)
# --------------------------------------------------------------------------- #
def test_sigma_data_source_from_logsource(rule_repo):
    """Sigma data_source is its logsource category (the table-equivalent)."""
    rules = {r.format: r for r in discover_rules(rule_repo)}
    assert rules["sigma"].data_source == "process_creation"


def test_sql_data_source_from_from_clause(rule_repo):
    rules = {r.format: r for r in discover_rules(rule_repo)}
    assert rules["sql"].data_source == "cloudtrail"


def test_kql_data_source_from_lead_table(rule_repo):
    """KQL data_source is the lead table verbatim — no case normalisation."""
    rules = {r.format: r for r in discover_rules(rule_repo)}
    assert rules["kql"].data_source == "DeviceProcessEvents"


def test_spl_data_source_from_index(rule_repo):
    rules = {r.format: r for r in discover_rules(rule_repo)}
    assert rules["spl"].data_source == "edr"


def test_data_source_empty_when_unresolvable(tmp_path):
    """A SQL query with no FROM clause yields an empty data_source."""
    from adef.core.rule_discovery import discover_rules as _dr

    root = tmp_path / "rules"
    root.mkdir()
    (root / "weird.sql").write_text("SELECT 1", encoding="utf-8")
    rule = next(iter(_dr(root)))
    assert rule.data_source == ""


def test_discover_missing_root_returns_empty(tmp_path):
    assert list(discover_rules(tmp_path / "nope")) == []


def test_discovered_rule_query_text_present(rule_repo):
    """Every discovered rule carries the raw query text for downstream parsing."""
    for r in discover_rules(rule_repo):
        assert r.query_text.strip()
