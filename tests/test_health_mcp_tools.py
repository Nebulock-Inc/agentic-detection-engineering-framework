"""Tests for the health MCP tools (adef/mcp/tools/health_tools.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from adef.core.catalog import Catalog, CatalogRecord


class _FakeServer:
    """Minimal stand-in for a FastMCP server — captures @server.tool() callables."""

    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    cat = Catalog(ws)
    rec = CatalogRecord(
        id="D-0042", title="mshta child", rule_ref="r/d42.yml",
        original_path="/tmp/d42.yml", platform="windows", kind="atomic",
        engine="sigma", format="sigma", query="process.name='mshta.exe'",
    )
    cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    return ws


def test_health_ingest_tool_stores_and_reports(workspace: Path, tmp_path: Path):
    from adef.mcp.tools import health_tools

    doc_path = tmp_path / "m.yml"
    doc_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "kind": "metrics",
                "captured_at": "2026-09-21T14:00:00Z",
                "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
                "environment": "prod-siem",
                "detections": [{"detection_id": "D-0042", "signal_count": 143}],
            }
        ),
        encoding="utf-8",
    )

    server = _FakeServer()
    health_tools.register(server)
    out = server.tools["health_ingest"](
        document_path=str(doc_path), workspace=str(workspace)
    )

    assert out["kind"] == "metrics"
    assert out["matched"] == ["D-0042"]
    assert out["unmatched"] == []
    stored = yaml.safe_load(
        (workspace / "health" / "latest" / "D-0042.yml").read_text(encoding="utf-8")
    )
    assert stored["metrics"]["signal_count"] == 143


def test_health_ingest_dry_run_creates_no_directories(tmp_path: Path):
    # A workspace that does not exist yet, so no catalog/ either — regression
    # for known_ids-gathering constructing Catalog(ws), whose __init__ mkdirs
    # catalog/ regardless of dry_run.
    from adef.mcp.tools import health_tools

    bare_ws = tmp_path / "bare-ws"
    doc_path = tmp_path / "m.yml"
    doc_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "kind": "metrics",
                "captured_at": "2026-09-21T14:00:00Z",
                "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
                "environment": "prod-siem",
                "detections": [{"detection_id": "D-0042", "signal_count": 143}],
            }
        ),
        encoding="utf-8",
    )

    server = _FakeServer()
    health_tools.register(server)
    out = server.tools["health_ingest"](
        document_path=str(doc_path), dry_run=True, workspace=str(bare_ws)
    )

    assert out["kind"] == "metrics"
    assert out["matched"] == []
    assert out["unmatched"] == ["D-0042"]
    assert out["paths_written"] == []
    assert not bare_ws.exists()


def test_health_ingest_tool_returns_error_instead_of_raising(workspace: Path, tmp_path: Path):
    from adef.mcp.tools import health_tools

    doc_path = tmp_path / "bad.yml"
    doc_path.write_text(yaml.safe_dump({"kind": "made_up"}), encoding="utf-8")

    server = _FakeServer()
    health_tools.register(server)
    out = server.tools["health_ingest"](
        document_path=str(doc_path), workspace=str(workspace)
    )

    assert "error" in out
    assert "made_up" in out["error"]


def test_register_mcp_tools_includes_health_tools():
    from adef.mcp.register import register_mcp_tools

    server = _FakeServer()
    register_mcp_tools(server)
    assert "health_ingest" in server.tools


def test_health_ingest_tool_returns_near_miss_keys(workspace: Path, tmp_path: Path):
    # The MCP caller shaped the document itself, so it is the one caller that
    # can fix a misspelled key and re-ingest in the same turn.
    from adef.mcp.tools import health_tools

    doc_path = tmp_path / "typo.yml"
    doc_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "kind": "metrics",
                "captured_at": "2026-09-21T14:00:00Z",
                "window": {"start": "2026-09-14T00:00:00Z", "end": "2026-09-21T00:00:00Z"},
                "environment": "prod-siem",
                "detections": [
                    {
                        "detection_id": "D-0042",
                        "signal_count": 500,
                        "false_positives_count": 480,
                        "true_positive_count": 2,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    server = _FakeServer()
    health_tools.register(server)
    out = server.tools["health_ingest"](
        document_path=str(doc_path), workspace=str(workspace)
    )

    assert out["matched"] == ["D-0042"]
    assert len(out["ignored_keys"]) == 1, out["ignored_keys"]
    assert "false_positives_count" in out["ignored_keys"][0]
    assert "false_positive_count" in out["ignored_keys"][0]
