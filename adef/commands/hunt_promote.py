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
@click.argument("hunt_id")
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
    hunt_id: str,
    workspace: Path | None,
    rule_staging_root: Path | None,
    hunt_root: Path | None,
) -> None:
    """Promote ``HUNT_ID`` (e.g. ``H-0042``) to a draft ADEF detection."""
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


__all__ = ["hunt_promote"]
