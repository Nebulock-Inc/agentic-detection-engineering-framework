"""Tests for the memory MCP tools (adef/mcp/tools/memory_tools.py)."""

from __future__ import annotations

from pathlib import Path


class _FakeServer:
    """Minimal stand-in for a FastMCP server — captures @server.tool() callables."""

    def __init__(self) -> None:
        self.tools: dict = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


def test_memory_search_against_a_bare_workspace_creates_nothing(tmp_path: Path):
    # Minor finding: `workspace_journals_dir(...)` was called without
    # `create=False`, so `memory_search` (a read path) mkdir'd `journals/`
    # (and its parent workspace dir) as a side effect. Same class as the
    # `known_detection_ids` / `rule_similarity.py` precedent.
    from adef.mcp.tools import memory_tools

    bare = tmp_path / "bare-workspace"
    assert not bare.exists()

    server = _FakeServer()
    memory_tools.register(server)
    result = server.tools["memory_search"](query="mshta", workspace=str(bare))

    assert result["hits"] == []
    assert not bare.exists()
