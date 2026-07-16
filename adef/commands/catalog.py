"""``adef catalog`` — turn an existing detection repo into ADEF's catalog.

Point ADEF at a directory of detection rules (Sigma YAML, Splunk
``savedsearches.conf``, ``.kql``, ``.sql``, ``.cql``). ADEF walks the repo
read-only, catalogs each rule into ``catalog/<platform>/D-XXXX-<slug>.yml``,
creates a paired skeleton journal, and regenerates ``catalog/INDEX.yml``.

Infer-and-flag: cataloging never prompts. Rules whose platform/MITRE can't be
inferred are catalogued with ``needs_review: true`` for later correction. The
user's repo is never modified.
"""

from __future__ import annotations

import os
from pathlib import Path

import click
from rich.console import Console

from adef.core.catalog import Catalog, record_from_discovered
from adef.core.journal import Journal
from adef.core.rule_discovery import discover_rules

console = Console()


def _resolve_workspace(explicit: Path | None) -> Path:
    """Resolve the workspace: explicit arg → ADEF_WORKSPACE → cwd → default."""
    if explicit is not None:
        ws = explicit
    elif env := os.environ.get("ADEF_WORKSPACE"):
        ws = Path(env)
    elif (Path.cwd() / "catalog").is_dir() or (Path.cwd() / "journals").is_dir():
        ws = Path.cwd()
    else:
        ws = Path.home() / "work" / "adef-workspace"
    return ws.expanduser().resolve()


@click.command()
@click.argument(
    "rule_root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
@click.option("--dry-run", is_flag=True, help="Report what would be catalogued without writing.")
def catalog(rule_root: Path, workspace: Path | None, dry_run: bool) -> None:
    """Catalog every detection rule under RULE_ROOT into the ADEF workspace."""
    ws = _resolve_workspace(workspace)
    cat = Catalog(ws)
    journal = Journal(ws / "journals")

    discovered = list(discover_rules(rule_root))
    if not discovered:
        console.print(f"[yellow]No detection rules found under[/yellow] {rule_root}")
        return

    next_idx = int(max(cat.max_index(), cat._journals_max_index())) + 1
    planned: list = []
    for disc in discovered:
        detection_id = f"D-{next_idx:04d}"
        planned.append(record_from_discovered(detection_id, disc, workspace=ws))
        next_idx += 1

    needs_review = sum(1 for r in planned if r.needs_review)

    if dry_run:
        for rec in planned:
            flag = " [yellow](needs review)[/yellow]" if rec.needs_review else ""
            console.print(f"  {rec.id}  {rec.platform:<14} {rec.format:<6} {rec.title}{flag}")
        console.print(
            f"\n[bold]{len(planned)}[/bold] rules would be catalogued "
            f"([yellow]{needs_review}[/yellow] need review). Dry run — nothing written."
        )
        return

    for rec in planned:
        cat.write(rec)
        # Pair each catalogued rule with a skeleton journal (shared D-XXXX ID).
        if not (journal.directory / f"{rec.id}.md").exists():
            journal.create(
                detection_id=rec.id,
                title=rec.title,
                owner=rec.owner,
                rule_uuid="",
                note=f"Catalogued from {rec.rule_ref} by `adef catalog`.",
            )

    index_path = cat.rebuild_index()

    console.print(
        f"[green]Catalogued[/green] {len(planned)} rules into {cat.directory}"
    )
    console.print(f"  INDEX     → {index_path}")
    if needs_review:
        console.print(
            f"  [yellow]{needs_review} need review[/yellow] "
            "(platform or MITRE could not be inferred)."
        )


__all__ = ["catalog"]
