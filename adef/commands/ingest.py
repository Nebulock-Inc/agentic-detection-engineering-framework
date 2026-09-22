"""`adef ingest` — take a detection-health capture document into the workspace.

One command for every document kind: the file declares its own ``kind``, so
there is no flag for a producer to mismatch against the file they are passing.
ADEF never contacts the environment the numbers came from.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from adef.core.catalog import known_detection_ids
from adef.core.health_docs import HealthDocError, load_health_doc
from adef.core.health_store import health_dir, store_health_doc
from adef.core.workspace import resolve_workspace

console = Console()


@click.command()
@click.argument(
    "document",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Validate and report what would be written, without writing anything.",
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE, current dir, or ~/work/adef-workspace/).",
)
def ingest(document: Path, dry_run: bool, workspace: Path | None) -> None:
    """Ingest a detection-health capture document (metrics, performance, drift…).

    The document declares its own ``kind`` and ``schema_version``; ingestion
    routes on that. Rows naming a detection the catalog does not know are
    reported and skipped, never silently stored.
    """
    try:
        doc = load_health_doc(document)
    except HealthDocError as exc:
        raise click.ClickException(str(exc)) from exc

    ws = resolve_workspace(workspace)
    known_ids = known_detection_ids(ws)

    result = store_health_doc(
        doc, health_dir(workspace), known_ids=known_ids, dry_run=dry_run
    )

    prefix = "[cyan]Would ingest[/cyan]" if dry_run else "[green]Ingested[/green]"
    console.print(
        f"{prefix} {result.kind} from {document.name} — "
        f"{len(result.matched)} matched"
    )
    if result.unmatched:
        console.print(
            f"  [yellow]unmatched:[/yellow] {len(result.unmatched)} row(s) name a "
            f"detection the catalog does not have: {', '.join(result.unmatched)}"
        )


__all__ = ["ingest"]
