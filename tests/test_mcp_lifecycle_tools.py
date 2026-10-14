"""MCP `forge_advance` honours the backward-move guard the CLI has."""

from __future__ import annotations

from adef.core.journal import Journal
from adef.mcp.tools import lifecycle_tools


class _Server:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


def test_forge_advance_refuses_backward_unless_allowed(tmp_path):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    Journal(ws / "journals").create(detection_id="D-0001", title="t")
    server = _Server()
    lifecycle_tools.register(server)
    advance = server.tools["forge_advance"]

    assert advance("D-0001", "refine", workspace=str(ws))["stage"] == "refine"
    refused = advance("D-0001", "observe", workspace=str(ws))
    assert "error" in refused and "back to observe" in refused["error"]
    assert advance("D-0001", "observe", workspace=str(ws), allow_backward=True)["stage"] == "observe"
