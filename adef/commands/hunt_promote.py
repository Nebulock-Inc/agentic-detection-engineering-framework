"""``adef hunt-promote`` — convert an upstream hunt artifact into a draft ADEF detection.

Usage::

    adef hunt-promote H-0042

What it does:

1. Resolves ``HUNT_ID`` in the configured hunt source.
2. Calls a configured generator (lazy-imported via a dotted path; see
   ``adef.agents.hunt_promotion``) to produce a draft Sigma rule.
3. Writes the draft to ``<rule-staging-root>/D-draft-XXXX.yml`` (a *staging*
   directory, never any production rule directory).
4. Creates an ADEF journal at the Find stage with intel sources populated.

The generator dotted path and roots are configured by environment variable
or ``--option`` flags. ADEF itself takes no opinion on which upstream system
provides the hunt.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.command(name="hunt-promote")
@click.argument("hunt_id", required=False)
@click.option(
    "--gates",
    "gates_doc",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Import an ATHF GATES document (H-XXXX_GATES.yaml) instead of calling a generator.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="With --gates: show what would be imported, write nothing.",
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
@click.option(
    "--rule-staging-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory where the staging YAML draft is written (overrides ADEF_RULE_STAGING_ROOT).",
)
@click.option(
    "--hunt-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory where hunt artifacts live (overrides ADEF_HUNT_ROOT).",
)
def hunt_promote(
    hunt_id: str | None,
    gates_doc: Path | None,
    dry_run: bool,
    workspace: Path | None,
    rule_staging_root: Path | None,
    hunt_root: Path | None,
) -> None:
    """Promote a hunt to draft ADEF detections.

    Two input modes:

    \b
      adef hunt-promote --gates H-0041_GATES.yaml   # ATHF GATES document (N detections)
      adef hunt-promote H-0042                      # via a configured generator plugin
    """
    if gates_doc is not None:
        _promote_from_gates(gates_doc, workspace, dry_run)
        return
    if not hunt_id:
        console.print("[red]hunt-promote failed:[/red] give a HUNT_ID or --gates <path>.")
        sys.exit(2)

    from adef.agents.hunt_promotion import HuntPromotionAgent, HuntPromotionError

    try:
        agent = HuntPromotionAgent(
            hunt_root=hunt_root,
            rule_staging_root=rule_staging_root,
            workspace_root=workspace,
        )
        result = agent.run(hunt_id=hunt_id)
    except HuntPromotionError as exc:
        console.print(f"[red]hunt-promote failed:[/red] {exc}")
        sys.exit(2)

    console.print(f"[green]Promoted[/green] {hunt_id} → {result.detection_id}")
    console.print(f"  staging YAML: {result.staging_yaml}")
    console.print(f"  ADEF journal: {result.journal_path}")


def _promote_from_gates(gates_doc: Path, workspace: Path | None, dry_run: bool) -> None:
    """Import a GATES document: N detections, one hunt."""
    from adef.core.gates import GatesError, import_gates, parse_gates

    try:
        doc = parse_gates(gates_doc)
        results = import_gates(gates_doc, workspace=workspace, dry_run=dry_run)
    except GatesError as exc:
        console.print(f"[red]hunt-promote failed:[/red] {exc}")
        sys.exit(2)

    prefix = "Would promote" if dry_run else "Promoted"
    console.print(
        f"[green]{prefix}[/green] {doc.hunt_id} ({doc.title}) — "
        f"{len(results)} candidate(s), hunt verdict {doc.verdict or 'unstated'}"
    )
    for res in results:
        if res.detection_id:
            action = "new" if res.minted else "updated"
            console.print(
                f"  {res.detection_id}  {res.verdict:<15} {action:<7} record + journal\n"
                f"          {res.name}"
            )
        else:
            console.print(
                f"  [dim]—       {res.verdict:<15} skipped[/dim] not deployable, no record minted\n"
                f"          [dim]{res.name}[/dim]"
            )
    if not results:
        console.print("  [yellow]no detections in this document[/yellow]")


__all__ = ["hunt_promote"]
