"""`adef ingest` — take a detection-health capture document into the workspace.

One command for every document kind: the file declares its own ``kind``, so
there is no flag for a producer to mismatch against the file they are passing.
ADEF never contacts the environment the numbers came from.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from adef.core.catalog import catalog_dir, known_detection_ids
from adef.core.health_docs import HealthDocError, load_health_doc, near_miss_row_keys
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

    try:
        result = store_health_doc(
            doc, health_dir(workspace), known_ids=known_ids, dry_run=dry_run
        )
    except HealthDocError as exc:
        raise click.ClickException(str(exc)) from exc

    prefix = "[cyan]Would ingest[/cyan]" if dry_run else "[green]Ingested[/green]"
    # Paths are escaped for the same reason the row keys below are: a bracketed
    # path segment Rich reads as a style tag is *deleted*, so `adef ingest
    # "metrics[final].yml"` reported `from metrics.yml` — a file that doesn't
    # exist — and `[/]` raised `MarkupError` out of the command.
    console.print(
        f"{prefix} {escape(str(result.kind))} from {escape(document.name)} — "
        f"{len(result.matched)} matched"
    )
    if result.unmatched:
        cat_dir = catalog_dir(ws)
        if cat_dir.is_dir():
            where = "the catalog does not have"
        else:
            # Escaped here, at the one branch that interpolates a path — so the
            # `{where}` below must NOT be escaped again (that renders `\[`).
            where = f"no catalog at {escape(str(cat_dir))}"
        # `escape`, not `markup=False`: both these lines carry their own
        # `[yellow]` tags, so markup has to stay on and the producer's strings
        # have to be neutralized instead. Unmatched IDs are precisely the ones
        # that *failed* the `D-XXXX` shape check, so they are arbitrary text
        # from the capture document — `[bold]D-0001` was parsed as a style tag
        # and silently deleted, naming a row the producer cannot find in their
        # file, and a malformed tag raised `MarkupError` out of `adef ingest`.
        console.print(
            f"  [yellow]unmatched:[/yellow] {len(result.unmatched)} row(s) name a "
            f"detection {where}: {escape(', '.join(result.unmatched))}"
        )

    if result.superseded:
        console.print(
            f"  [yellow]older than stored:[/yellow] {len(result.superseded)} row(s) "
            "not written to latest/, which already holds a later period "
            "(detection rows still go to history): "
            f"{escape(', '.join(result.superseded))}"
        )

    # A matched row with a misspelled count is the quieter failure: it is
    # reported as ingested and then derives nothing, so `adef detection
    # evolve` answers from the counts that happened to parse.
    for warning in near_miss_row_keys(doc):
        # Embeds the raw row key — same escaping reason as above.
        console.print(f"  [yellow]ignored key:[/yellow] {escape(warning)}")


__all__ = ["ingest"]
