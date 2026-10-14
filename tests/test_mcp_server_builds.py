"""The real adef-mcp server builds against the installed `mcp` SDK.

Nothing else constructs it — tool tests call the registrars directly — so an
SDK release that renames `FastMCP` (mcp 2.x did) shipped a broken `adef-mcp`
with a green suite. This is the check that would have caught it.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("mcp")


def test_the_mcp_server_builds_and_registers_tools():
    from adef.mcp.server import build_server

    server = build_server()
    tools = asyncio.run(server.list_tools())
    names = {t.name for t in tools}
    assert len(names) >= 10, names
    assert {"memory_search", "refine_chain"} <= names


def test_an_incompatible_mcp_sdk_is_named_as_such(monkeypatch):
    import builtins

    from adef.mcp import server as srv

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "mcp.server.fastmcp":
            raise ModuleNotFoundError("No module named 'mcp.server.fastmcp'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    import importlib.metadata

    monkeypatch.setattr(importlib.metadata, "version", lambda _pkg: "2.2.0")
    with pytest.raises(SystemExit) as exc:
        srv._new_server()
    message = str(exc.value)
    assert "mcp<2" in message and "optional 'mcp' extra" not in message


def test_a_broken_mcp_1x_install_keeps_its_real_error(monkeypatch):
    # mcp 1.x present but a transitive dependency missing: that is not a
    # version problem, so the original ImportError must surface.
    import builtins
    import importlib.metadata

    from adef.mcp import server as srv

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "mcp.server.fastmcp":
            raise ModuleNotFoundError("No module named 'starlette'", name="starlette")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(importlib.metadata, "version", lambda _pkg: "1.30.0")
    with pytest.raises(ModuleNotFoundError, match="starlette"):
        srv._new_server()
