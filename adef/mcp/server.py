"""``adef-mcp`` — FastMCP server exposing ADEF lifecycle, memory, and agents.

Discovers third-party tools through the ``adef.mcp_tools`` entry-point group
(via ``PluginRegistry.load_mcp_tools``). Built-in tools are also registered
through the same group (``adef.mcp.register:register_mcp_tools``) so the
discovery code path is exercised even with no third-party plugins installed.
"""

from __future__ import annotations

import sys

from adef.plugin_system import PluginRegistry


def _new_server():  # pragma: no cover — thin factory, exercised by integration test
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]
    except ImportError as exc:
        import importlib.metadata

        try:
            found = importlib.metadata.version("mcp")
        except importlib.metadata.PackageNotFoundError:
            found = ""
        if found and found.split(".", 1)[0].isdigit() and int(found.split(".", 1)[0]) >= 2:
            # mcp 2.x renamed FastMCP (MCPServer) and changed its API.
            raise SystemExit(
                f"adef-mcp needs mcp<2, but mcp {found} is installed (2.x renamed "
                "FastMCP). Install a compatible SDK with: pip install 'mcp[cli]>=1.0.0,<2'"
            ) from exc
        if found:
            raise  # a compatible SDK that fails to import: the real error is the useful one
        raise SystemExit(
            "adef-mcp requires the optional 'mcp' extra. Install with: pip install 'agentic-detection-engineering-framework[mcp]'"
        ) from exc
    return FastMCP("adef")


def build_server():
    """Return a FastMCP instance with all discovered tool modules registered."""
    server = _new_server()
    for register in PluginRegistry.load_mcp_tools():
        try:
            register(server)
        except Exception as exc:  # noqa: BLE001 — defensive, plugin sandbox
            print(f"[adef-mcp] tool registrar failed: {exc}", file=sys.stderr)
    return server


def cli() -> None:  # pragma: no cover — entry point
    """Console-script entry point for ``adef-mcp``."""
    server = build_server()
    server.run()


if __name__ == "__main__":  # pragma: no cover
    cli()
