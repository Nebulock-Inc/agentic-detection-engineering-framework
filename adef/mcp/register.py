"""Built-in MCP tool registrar — invoked through the ``adef.mcp_tools`` entry point.

Each tool module exports a ``register(server)`` function. This module simply
calls them in turn so the discovery path through ``PluginRegistry.load_mcp_tools``
is identical for built-in and third-party tools.
"""

from __future__ import annotations

from typing import Any


def register_mcp_tools(server: Any) -> None:
    """Register every built-in tool module against ``server``."""
    from adef.mcp.tools import agent_tools, init_tools, lifecycle_tools, memory_tools

    lifecycle_tools.register(server)
    memory_tools.register(server)
    agent_tools.register(server)
    init_tools.register(server)


__all__ = ["register_mcp_tools"]
