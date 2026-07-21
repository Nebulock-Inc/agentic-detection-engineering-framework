"""Tests for schema-grounded new-detection authoring."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from adef.core.catalog import Catalog, draft_record_from_schema


def _write_schema(ws: Path, name: str, platform: str, ql: str, scope: dict) -> None:
    schema_dir = ws / "schema"
    schema_dir.mkdir(parents=True, exist_ok=True)
    (schema_dir / f"{name}.yml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "source": name,
                "platform": platform,
                "query_language": ql,
                "scope": scope,
                "fields": [{"name": "EventCode"}, {"name": "Image"}],
            }
        ),
        encoding="utf-8",
    )


def test_draft_is_grounded_in_schema(tmp_path: Path) -> None:
    _write_schema(
        tmp_path, "wineventlog_xml", "windows", "spl",
        {"index": "thrunt", "sourcetype": "XmlWinEventLog"},
    )
    rec = draft_record_from_schema(tmp_path, "D-0001", "Suspicious mshta", "wineventlog_xml")
    assert rec.platform == "windows"
    assert rec.query_language == "spl"
    assert rec.data_source == "wineventlog_xml"  # canonical identity schema check matches
    assert rec.status == "draft"
    assert rec.stage == "find"
    # scope literals surface in the starter query so the author sees real filters
    assert "index=thrunt" in rec.query
    assert "sourcetype=XmlWinEventLog" in rec.query


def test_missing_schema_raises(tmp_path: Path) -> None:
    (tmp_path / "schema").mkdir()
    with pytest.raises(FileNotFoundError) as exc:
        draft_record_from_schema(tmp_path, "D-0001", "x", "nope")
    assert "nope" in str(exc.value)


def test_draft_persists_and_is_browsable(tmp_path: Path) -> None:
    _write_schema(tmp_path, "zeek_dns", "network", "spl", {"sourcetype": "zeek:dns"})
    rec = draft_record_from_schema(tmp_path, "D-0007", "DNS beacon", "zeek_dns")
    cat = Catalog(tmp_path)
    cat.write(rec)
    cat.rebuild_index()
    found = cat.find_record("D-0007")
    assert found is not None
    _path, data = found
    assert data["platform"] == "network"
    assert data["data_source"] == "zeek_dns"


def test_kql_scope_uses_table_syntax(tmp_path: Path) -> None:
    # A KQL source's scope container should read as a KQL lead table, not index=.
    _write_schema(tmp_path, "SecurityEvent", "windows", "kql", {"table": "SecurityEvent"})
    rec = draft_record_from_schema(tmp_path, "D-0002", "logon anomaly", "SecurityEvent")
    assert rec.query_language == "kql"
    assert "SecurityEvent" in rec.query
    assert "index=" not in rec.query  # not SPL syntax
