"""`adef doctor` — one answer to "is my workspace wired up?".

Named after `brew doctor` / `flutter doctor` because that is exactly the
convention it follows, and because a user who has been handed a half-set-up
workspace already knows to try it.

Rendering only; every answer comes from `adef/core/doctor.py`.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from adef.core.doctor import PROBLEM, Check, run_checks

console = Console()

# Glyph per status, matching `adef init`'s capabilities block so the two reads
# of the same facts don't disagree on what a warning looks like.
_MARK = {
    "ok": "[green]✓[/green]",
    "warn": "[yellow]![/yellow]",
    PROBLEM: "[red]✗[/red]",
}


@click.command("doctor")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to ADEF_WORKSPACE, current dir, or ~/work/adef-workspace/).",
)
@click.option(
    "--report",
    type=click.Choice(["json"]),
    default=None,
    help="Machine-readable output instead of the terminal rendering.",
)
def doctor(workspace: Path | None, report: str | None) -> None:
    """Check the workspace and report what's missing, with the next command where there is one.

    Exits 1 when a check is a *problem* — state that makes another command
    answer confidently from bad data, like a stale `catalog/INDEX.yml`. A
    *warning* is an optional capability nobody has set up yet, which is the
    normal state of a new workspace, so warnings exit 0 and stay safe to wire
    into CI.
    """
    checks = run_checks(workspace)

    if report == "json":
        click.echo(
            json.dumps(
                {
                    "checks": [asdict(c) for c in checks],
                    "problems": sum(c.status == PROBLEM for c in checks),
                    "warnings": sum(c.status == "warn" for c in checks),
                },
                indent=2,
                default=str,
            )
        )
    else:
        _render(checks)

    if any(c.status == PROBLEM for c in checks):
        raise SystemExit(1)


def _render(checks: list[Check]) -> None:
    console.print("\n[bold]ADEF workspace check[/bold]\n")
    # A borderless table rather than `_render.py`'s pad/fit helpers: those
    # produce one ellipsized line per row, which is right for `adef detection
    # list` (scan many rows) and wrong here (ten rows, each a sentence that has
    # to be read). Rich wraps inside the cell, so a two-line detail still lines
    # up under its own column instead of returning to column zero.
    table = Table(box=None, show_header=False, pad_edge=True, padding=(0, 1))
    table.add_column(no_wrap=True)  # glyph
    table.add_column(no_wrap=True, style="bold")  # check name
    table.add_column(overflow="fold")  # detail + fix
    for check in checks:
        # `markup=False` is not an option (the glyphs are markup), so the two
        # interpolated fields are escaped instead: `detail` carries workspace
        # paths and record IDs, and `fix` carries a shell command —
        # the `[mcp]` install hint is the one that bites, since Rich reads
        # `[mcp]` as a style tag and silently deletes it.
        detail = escape(check.detail)
        if check.fix:
            detail += f"\n[dim]→[/dim] [bold]{escape(check.fix)}[/bold]"
        table.add_row(_MARK[check.status], check.name, detail)
    console.print(table)

    problems = [c for c in checks if c.status == PROBLEM]
    warnings = [c for c in checks if c.status == "warn"]
    # `highlight=False` throughout: Rich's auto-highlighter colors bare numbers
    # and anything bracket-shaped, which turned "1 problem(s)" into three
    # separately-colored fragments.
    if problems:
        console.print(
            f"\n[red]{len(problems)} problem(s)[/red]"
            + (f", {len(warnings)} warning(s)" if warnings else "")
            + " — a problem means another command is answering from bad state.",
            highlight=False,
        )
    elif warnings:
        console.print(
            f"\n[yellow]{len(warnings)} warning(s)[/yellow], no problems — "
            "warnings are capabilities you haven't set up, not breakage.",
            highlight=False,
        )
    else:
        console.print("\n[green]Everything checks out.[/green]")


__all__ = ["doctor"]
