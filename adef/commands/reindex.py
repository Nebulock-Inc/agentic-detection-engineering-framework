"""``adef reindex`` — regenerate ``catalog/INDEX.yml`` from the records.

The INDEX is generated, never hand-edited — but until this command existed,
CLAUDE.md promised it while the CLI didn't ship it, so an agent repairing a
record hand-rolled its own rebuild and produced a *wrong* index (stale
``by_technique`` entries). One command, one
source of truth.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

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
    try:
        # Inside the `try`, not above it. `iter_records` swallows what it can't
        # parse per record, so this rarely raises on its own — but the walk and
        # the build read the same files, and anything that reaches here belongs
        # in the handler below rather than in a traceback.
        records = sum(1 for _ in cat.iter_records())
        index_path = cat.rebuild_index()
    except Exception as exc:  # noqa: BLE001 — report the cause, don't traceback
        # Still a hard failure, deliberately: swallowing it would write an
        # INDEX with every tactic silently dropped, which is why the guard in
        # `adef doctor` lives at *its* caller and not inside `build_index`.
        # Loud, though, not a traceback — the two reachable causes are a
        # truncated `attack/enterprise.json` and a hand-edited record whose
        # `engine`/`status`/`data_source` is a list, and both are things the
        # user can fix once they can read what happened.
        # `escape`: both lines carry their own markup, so `markup=False` is not
        # an option, and an exception message is the least predictable string
        # in the command — an `OSError`'s `[Errno 2]` survives Rich's tag regex
        # only because the first character is uppercase. See `adef ingest`,
        # where an unescaped bracketed path printed a filename that didn't
        # exist. `highlight=False` for the same reason `commands/doctor.py`
        # passes it: the auto-highlighter colors bare numbers and paths inside
        # an exception message, which reads as emphasis nobody chose.
        console.print(f"[red]Reindex failed:[/red] {escape(str(exc))}", highlight=False)
        console.print("catalog/INDEX.yml is unchanged. Run `adef doctor` for the state.")
        raise SystemExit(1) from exc
    console.print(f"[green]Reindexed[/green] {records} record(s) → {escape(str(index_path))}")


__all__ = ["reindex"]
