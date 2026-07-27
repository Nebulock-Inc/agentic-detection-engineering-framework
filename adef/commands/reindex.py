"""``adef reindex`` — regenerate ``catalog/INDEX.yml`` from the records.

The INDEX is generated, never hand-edited — but until this command existed,
CLAUDE.md promised it while the CLI didn't ship it, so an agent repairing a
record hand-rolled its own rebuild and produced a *wrong* index (stale
``by_technique`` entries; live case D-1470, 2026-07-24). One command, one
source of truth.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from adef.core.workspace import resolve_workspace

console = Console()


@click.command()
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE, current dir, or ~/work/adef-workspace/).",
)
def reindex(workspace: Path | None) -> None:
    """Rebuild catalog/INDEX.yml from the catalog records (the only safe way)."""
    from adef.core.catalog import Catalog

    ws = resolve_workspace(workspace)
    cat = Catalog(ws)
    records = sum(1 for _ in cat.iter_records())
    index_path = cat.rebuild_index()
    console.print(f"[green]Reindexed[/green] {records} record(s) → {index_path}")


__all__ = ["reindex"]
