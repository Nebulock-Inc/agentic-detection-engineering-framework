"""Tests for scan_rule_fields — the shared scanner the schema feature needs.

This closes the documented v1 gap in ``adef schema init`` (the stubbed rule
scanner at ``adef/commands/schema.py``). It walks a repo via ``discover_rules``
and extracts field names for a given query language using the existing
``rule_parser`` extractors.
"""

from __future__ import annotations

import textwrap

import pytest

from adef.core.rule_discovery import scan_rule_fields


@pytest.fixture
def sql_repo(tmp_path):
    root = tmp_path / "rules"
    root.mkdir()
    (root / "a.sql").write_text(
        "SELECT user_name, event_name FROM cloudtrail WHERE region = 'us-east-1'",
        encoding="utf-8",
    )
    (root / "b.sql").write_text(
        "SELECT process_id FROM processes WHERE parent_image LIKE '%mshta%'",
        encoding="utf-8",
    )
    # A KQL file that must be ignored when scanning for SQL fields.
    (root / "c.kql").write_text(
        "DeviceProcessEvents | project FileName", encoding="utf-8"
    )
    return root


def test_scan_sql_fields_across_repo(sql_repo):
    fields = scan_rule_fields(sql_repo, "sql")
    assert {"user_name", "event_name", "region", "process_id", "parent_image"} <= fields


def test_scan_ignores_other_languages(sql_repo):
    """Scanning for SQL must not pull KQL's FileName in."""
    fields = scan_rule_fields(sql_repo, "sql")
    assert "FileName" not in fields


def test_scan_kql_fields(sql_repo):
    fields = scan_rule_fields(sql_repo, "kql")
    assert "FileName" in fields


def test_scan_missing_root_returns_empty(tmp_path):
    assert scan_rule_fields(tmp_path / "nope", "sql") == set()
