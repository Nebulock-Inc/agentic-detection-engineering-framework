"""``adef attack`` — inspect and refresh the ATT&CK reference layer.

The reference is a compact snapshot shipped as package data. ``refresh`` pulls a
newer one from official STIX into the workspace (which then wins over the
shipped copy on read); ``show`` displays a technique; ``info`` prints the active
snapshot's version and counts.
"""

from __future__ import annotations

import os
from pathlib import Path

import click
from rich.console import Console

from adef.core.attack import SNAPSHOT_NAME, attack_reference

console = Console()


@click.group()
def attack() -> None:
    """ATT&CK reference layer (validation + tactic resolution)."""


@attack.command()
def info() -> None:
    """Show the active snapshot's ATT&CK version and counts."""
    ref = attack_reference()
    console.print(
        f"ATT&CK [bold]{ref.attack_version or '?'}[/bold] — "
        f"{len(ref.techniques)} techniques, {len(ref.tactics)} tactics."
    )


@attack.command()
@click.argument("technique_id")
def show(technique_id: str) -> None:
    """Display TECHNIQUE_ID (e.g. T1059.001), including revoked/deprecated status."""
    ref = attack_reference()
    res = ref.resolve(technique_id)
    if not res.valid:
        console.print(f"[red]{res.id} is not a valid ATT&CK technique ID.[/red]")
        raise SystemExit(1)
    entry = ref.technique(res.id)
    assert entry is not None  # valid ⇒ present
    console.print(f"[bold]{res.id}[/bold]  {entry.get('name', '')}")
    tactics = ref.tactics_for(res.id)
    if tactics:
        console.print(f"  tactics: {', '.join(tactics)}")
    if entry.get("parent"):
        console.print(f"  parent:  {entry['parent']}")
    if res.deprecated:
        console.print("  [yellow]deprecated[/yellow]")
    if res.revoked:
        repl = f" → {res.superseded_by}" if res.superseded_by else ""
        console.print(f"  [yellow]revoked[/yellow]{repl}")


@attack.command()
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    help="Workspace to write into (default: $ADEF_WORKSPACE or ~/work/adef-workspace).",
)
def refresh(workspace: Path | None) -> None:
    """Pull a fresh ATT&CK snapshot from official STIX into the workspace.

    The workspace copy wins over the shipped one on read, so a refresh takes
    effect immediately without touching package data.
    """
    # The generator is dev-time code (stdlib-only fetch + distil); reused here
    # so refresh and the build path can never drift.
    from adef.data.attack import _generate

    ws = (
        workspace
        or Path(os.getenv("ADEF_WORKSPACE") or Path.home() / "work" / "adef-workspace")
    ).expanduser().resolve()
    out = ws / "attack" / SNAPSHOT_NAME
    out.parent.mkdir(parents=True, exist_ok=True)

    console.print("Fetching ATT&CK STIX bundle…")
    try:
        bundle = _generate.fetch_bundle()
    except Exception as exc:  # network/parse — report, don't crash the CLI
        console.print(f"[red]Refresh failed:[/red] {exc}")
        console.print("The shipped snapshot is still in use.")
        raise SystemExit(1) from exc

    snapshot = _generate.build_snapshot(bundle)
    import json

    out.write_text(json.dumps(snapshot, indent=1) + "\n", encoding="utf-8")
    console.print(
        f"[green]Wrote[/green] {out} — ATT&CK {snapshot['attack_version']}, "
        f"{len(snapshot['techniques'])} techniques."
    )


__all__ = ["attack"]
