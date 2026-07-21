"""``adef coverage`` — coverage-quality report + Navigator layer export.

Not another heatmap. This reports coverage *quality*: what you can trust
(solid), what's one change from a gap (fragile), where your log-source risk is
concentrated, and which techniques are single points of failure — all derived
from the catalog with zero human input. ``--navigator`` writes a shareable
Navigator layer scored by the same quality model.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from adef.core.coverage import Tier, build_coverage, navigator_layer

console = Console()

_TIER_STYLE = {Tier.SOLID: "green", Tier.FRAGILE: "yellow", Tier.BLIND: "red"}


def _workspace_from(workspace: Path | None) -> Path:
    from adef.core.journal import workspace_journals_dir

    return workspace_journals_dir(workspace).parent


@click.command()
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
@click.option(
    "--navigator",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Also write a MITRE Navigator layer (scored by coverage quality) to this path.",
)
@click.option("--name", default="ADEF coverage", help="Layer name for the Navigator export.")
def coverage(workspace: Path | None, navigator: Path | None, name: str) -> None:
    """Report coverage quality across the catalog (trust, log-source risk, depth)."""
    from adef.core.catalog import Catalog

    ws = _workspace_from(workspace)
    records = [data for _id, _path, data in Catalog(ws).iter_records()]
    if not records:
        raise click.ClickException(f"No catalog records under {ws}. Run `adef catalog` first.")

    cov = build_coverage(records)
    tiers = cov.by_tier()
    n = len(cov.techniques)

    if n == 0:
        console.print("[yellow]No valid ATT&CK mappings in the catalog yet.[/yellow]")
        console.print("Tag detections with `adef detection tag-mitre` or the mitre-tagger skill.")
    else:
        solid, fragile = len(tiers[Tier.SOLID]), len(tiers[Tier.FRAGILE])
        console.print(f"[bold]Coverage quality[/bold] — {n} techniques mapped across {len(records)} detections")
        console.print(f"  [green]solid[/green]    {solid:>4}  (depth ≥2, at least one reviewed)")
        console.print(f"  [yellow]fragile[/yellow]  {fragile:>4}  (single detection, or all need review)")
        if solid + fragile:
            pct = 100 * solid // (solid + fragile)
            console.print(f"  → only [bold]{pct}%[/bold] of your mapped coverage is trustworthy.")

    # Log-source concentration — the risk a heatmap can't show.
    if cov.dominant_source:
        src, cnt = cov.dominant_source
        total_backed = sum(1 for tc in cov.techniques.values() if tc.sources)
        single = cov.single_source_techniques()
        console.print("\n[bold]Log-source risk[/bold]")
        console.print(f"  Busiest feed: [cyan]{src}[/cyan] backs {cnt} detection mappings.")
        if total_backed:
            console.print(
                f"  {len(single)}/{total_backed} techniques ride a single source — "
                "if that feed breaks, they go dark at once."
            )

    # Single points of failure.
    spof = cov.single_detection_techniques()
    if spof:
        console.print(f"\n[bold]Single points of failure[/bold] — {len(spof)} techniques with one detection")
        for tid in spof[:10]:
            tc = cov.techniques[tid]
            console.print(f"  [yellow]{tid}[/yellow] {tc.name}  ({tc.why()})")
        if len(spof) > 10:
            console.print(f"  … and {len(spof) - 10} more")

    # Fictional coverage.
    if cov.invalid_mappings:
        console.print(f"\n[bold red]Fictional coverage[/bold red] — {len(cov.invalid_mappings)} mapped IDs aren't in ATT&CK")
        for bad, dets in sorted(cov.invalid_mappings.items()):
            console.print(f"  [red]{bad}[/red] used by {', '.join(sorted(set(dets)))}")

    # Tactic rollup.
    roll = cov.tactic_rollup()
    if roll:
        console.print("\n[bold]By tactic[/bold]")
        for tactic in sorted(roll):
            counts = roll[tactic]
            console.print(
                f"  {tactic:<22} "
                f"[green]{counts[Tier.SOLID]} solid[/green], "
                f"[yellow]{counts[Tier.FRAGILE]} fragile[/yellow]"
            )

    if navigator is not None:
        layer = navigator_layer(cov, name=name)
        navigator.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
        console.print(
            f"\n[green]Navigator layer[/green] → {navigator} "
            f"({len(layer['techniques'])} techniques). Import at attack.navigator."
        )


__all__ = ["coverage"]
