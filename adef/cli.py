"""ADEF root command-line interface.

A Click group with version flag, plus plugin discovery through the
``adef.commands`` entry-point group. Built-in commands are registered through
the same plugin path (see ``pyproject.toml``) so external plugins look
identical to first-party commands.
"""

from __future__ import annotations

import click
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

from adef import __version__  # noqa: E402 — must follow load_dotenv()
from adef.plugin_system import PluginRegistry  # noqa: E402

console = Console()


EPILOG = """
\b
Examples:
  # Initialize a new ADEF workspace
  adef init

  # Create a new detection at the Find stage
  adef detection new "Suspicious child process of explorer.exe"

  # Advance through FORGE
  adef detection observe D-0001
  adef detection refine  D-0001
  adef detection govern  D-0001
  adef detection evolve  D-0001

  # Promote a hunt to a draft detection
  adef hunt-promote H-0042

  # Backfill journals for existing rule files
  adef backfill journals

\b
Documentation:
  • Methodology:   docs/methodology.md   (FORGE lifecycle)
  • Maturity model: docs/maturity-model.md (L0 → L4)
  • Why ADEF:      docs/why-adef.md      (adoption guide)
  • Roadmap:       docs/roadmap.md       (v0.2+)
  • North star:    docs/north-star.md    (v1 demo)

\b
Created by Sydney Marrone © 2026
"""


@click.group(epilog=EPILOG)
@click.version_option(
    version=__version__,
    prog_name="adef",
    message="%(prog)s version %(version)s\nAgentic Detection Engineering Framework\nCreated by Sydney Marrone © 2026",
)
def cli() -> None:
    """Agentic Detection Engineering Framework (ADEF) — FORGE lifecycle CLI.

    \b
    ADEF gives detection engineering durable memory and lifecycle structure:
    • FORGE methodology (Find → Observe → Refine → Govern → Evolve)
    • Per-detection markdown journals (D-XXXX.md)
    • Lifecycle-aware orchestration of upstream rule-engineering agents
    • ADEF-native agents (hypothesis-from-intel, tune, deprecation, hunt-promotion)
    • MCP server (adef-mcp) for Claude Code, Copilot, Cursor

    \b
    Quick Start:
      adef init                  Set up the ADEF workspace
      adef detection new TITLE   Create a journalled detection at Find
      adef hunt-promote H-XXXX   Promote an upstream hunt to a draft detection
    """


# Discover and register all entry-point commands (built-in + third-party).
PluginRegistry.register_commands(cli)


def main() -> None:  # pragma: no cover — thin wrapper
    """Console-script entry point."""
    cli()


if __name__ == "__main__":
    main()
