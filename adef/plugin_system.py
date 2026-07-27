"""Entry-point-based plugin discovery for ADEF.

Mirrors ATHF's plugin_system shape. Three discoverable groups:

- ``adef.commands`` — Click ``Group`` or ``Command`` objects added to the root CLI.
- ``adef.agents`` — agent classes registered for orchestration lookup by name.
- ``adef.mcp_tools`` — callables that register tools into a FastMCP server instance.

Every ``entry_point.load()`` is wrapped per the advisor's guidance — a single
broken plugin never kills CLI startup. Failures are logged via stderr (not the
``logging`` module, to keep startup dependency-free) and the loader continues.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable
from importlib.metadata import EntryPoint, entry_points
from typing import Any

import click

_GROUPS = ("adef.commands", "adef.agents", "adef.mcp_tools")


def _iter_group(group: str) -> Iterable[EntryPoint]:
    """Return entry points for ``group`` across the active Python environment."""
    eps = entry_points()
    # Python 3.10+ EntryPoints supports ``select(group=...)``.
    return eps.select(group=group) if hasattr(eps, "select") else eps.get(group, [])


def _safe_load(ep: EntryPoint) -> Any | None:
    """Load an entry point, swallowing failures with a stderr warning."""
    try:
        return ep.load()
    except Exception as exc:  # noqa: BLE001 — defensive, plugin sandbox
        print(
            f"[adef.plugin_system] failed to load {ep.group}:{ep.name} ({ep.value}): {exc}",
            file=sys.stderr,
        )
        return None


class PluginRegistry:
    """Discovery + registration helper.

    Use ``register_commands(cli)`` from ``adef.cli`` to attach discovered Click
    groups/commands. Use ``load_agents()`` and ``load_mcp_tools()`` from their
    respective subsystems.
    """

    @staticmethod
    def register_commands(cli: click.Group) -> list[str]:
        """Add every discovered ``adef.commands`` entry point to ``cli``.

        Returns the list of names that were attached.
        """
        attached: list[str] = []
        for ep in _iter_group("adef.commands"):
            obj = _safe_load(ep)
            if obj is None:
                continue
            if isinstance(obj, (click.Group, click.Command)):
                cli.add_command(obj, name=ep.name)
                attached.append(ep.name)
            else:
                print(
                    f"[adef.plugin_system] {ep.group}:{ep.name} is not a Click command, skipping",
                    file=sys.stderr,
                )
        return attached

    @staticmethod
    def load_agents() -> dict[str, Any]:
        """Return a mapping of agent name → loaded class/factory."""
        agents: dict[str, Any] = {}
        for ep in _iter_group("adef.agents"):
            obj = _safe_load(ep)
            if obj is not None:
                agents[ep.name] = obj
        return agents

    @staticmethod
    def load_mcp_tools() -> list[Callable[[Any], None]]:
        """Return a list of tool-registration callables for the MCP server."""
        registrants: list[Callable[[Any], None]] = []
        for ep in _iter_group("adef.mcp_tools"):
            obj = _safe_load(ep)
            if callable(obj):
                registrants.append(obj)
        return registrants


__all__ = ["PluginRegistry"]
