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
from adef.core.journal import JournalError  # noqa: E402
from adef.plugin_system import PluginRegistry  # noqa: E402

console = Console()


class _AdefGroup(click.Group):
    """Renders a ``JournalError`` as a message instead of a traceback.

    ``HardInvariantViolation`` — the refusal to touch anything under a rule
    ``detections/`` tree — is raised from ``_check_not_under_detections``, which
    ``Catalog.__init__`` and ``workspace_journals_dir`` both call. So *any*
    command that resolves a workspace can raise it, not just the ones that
    write journals, and it fires before a command's own ``try`` block has a
    chance to run (``adef catalog`` builds its ``Catalog`` well before it vets
    record paths). One funnel at the root is the only place that covers every
    command, including ones added later by a plugin.

    Commands with a house-style message of their own (``hunt-promote failed:``)
    still catch it locally first; this is the backstop.
    """

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except JournalError as exc:
            raise click.ClickException(str(exc)) from exc


# Click's `\b` marks ONLY the paragraph that immediately follows it as
# no-rewrap, so one marker at the top left every later block to be reflowed —
# each command was pulled up onto its own comment line ("# Advance through
# FORGE   adef detection observe D-0001   adef …"). Every paragraph needs its
# own marker.
EPILOG = """
\b
Examples:
  # Initialize a new ADEF workspace
  adef init

\b
  # Create a new detection at the Find stage
  adef detection new "Suspicious child process of explorer.exe"

\b
  # Advance through FORGE
  adef detection observe D-0001
  adef detection refine  D-0001
  adef detection govern  D-0001
  adef detection evolve  D-0001

\b
  # Promote a hunt to a draft detection
  adef hunt-promote H-0042

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


@click.group(cls=_AdefGroup, epilog=EPILOG)
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
      adef doctor                Check the workspace and what's left to wire up
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
