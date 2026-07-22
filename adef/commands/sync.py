"""``adef sync`` — reconcile the catalog against the current source repo.

The catalog is a snapshot; rule repos change. `sync` re-walks the repo, matches
each rule to its existing record via the identity cascade
(`adef/core/reconcile.py`), and applies the plan: unchanged rules are skipped,
modified rules have their *derived* fields refreshed while enrichment (mitre,
status, owner, journal) is **preserved**, new rules are catalogued, and records
whose source rule is gone are marked orphaned (never deleted).

`--dry-run` shows the plan without writing; `--check` reports drift and exits
non-zero if the catalog is behind (CI / PR mode).

Read-only on the source repo, as always — writes only under `catalog/` and
`journals/`.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from adef.core.catalog import Catalog, git_head_sha, record_from_discovered
from adef.core.journal import Journal
from adef.core.profiles import load_user_profiles
from adef.core.reconcile import Action, reconcile
from adef.core.rule_discovery import walk_outcomes
from adef.core.workspace import resolve_workspace as _resolve_workspace

console = Console()


@click.command()
@click.argument("rule_root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
@click.option("--dry-run", is_flag=True, help="Show the reconciliation plan; write nothing.")
@click.option(
    "--check",
    is_flag=True,
    help="Report drift and exit non-zero if the catalog is behind. Writes nothing (CI/PR mode).",
)
def sync(rule_root: Path, workspace: Path | None, dry_run: bool, check: bool) -> None:
    """Reconcile the catalog under RULE_ROOT — refresh changed rules, keep enrichment."""
    ws = _resolve_workspace(workspace)
    cat = Catalog(ws)

    existing = [data for _id, _path, data in cat.iter_records()]
    if not existing:
        raise click.ClickException(
            f"No catalog under {ws} — run `adef catalog {rule_root}` first."
        )

    user_profiles, profile_errors = load_user_profiles(ws)
    for err in profile_errors:
        console.print(f"[yellow]Skipping broken profile:[/yellow] {err}", highlight=False)
    discovered = [r for oc in walk_outcomes(rule_root, user_profiles) for r in oc.rules]

    plan = reconcile(existing, discovered, rule_root=rule_root)
    counts = {a: 0 for a in Action}
    for entry in plan:
        counts[entry.action] += 1

    drift = counts[Action.MODIFIED] + counts[Action.NEW] + counts[Action.ORPHANED]

    # Report (always).
    console.print(
        f"[bold]Sync plan[/bold] for {rule_root}:\n"
        f"  [dim]unchanged[/dim] {counts[Action.UNCHANGED]}   "
        f"[cyan]modified[/cyan] {counts[Action.MODIFIED]}   "
        f"[green]new[/green] {counts[Action.NEW]}   "
        f"[yellow]orphaned[/yellow] {counts[Action.ORPHANED]}"
    )
    for entry in plan:
        if entry.action is Action.UNCHANGED:
            continue
        label = {
            Action.MODIFIED: "[cyan]modified[/cyan]",
            Action.NEW: "[green]new     [/green]",
            Action.ORPHANED: "[yellow]orphaned[/yellow]",
        }[entry.action]
        title = (entry.discovered.title if entry.discovered else "") or (
            (entry.existing or {}).get("title", "")
        )
        console.print(f"  {label}  {entry.detection_id}  {title}")

    if check:
        if drift:
            console.print(f"\n[yellow]Catalog is behind: {drift} change(s).[/yellow] Run `adef sync`.")
            raise SystemExit(1)
        console.print("\n[green]Catalog is current.[/green]")
        return

    if dry_run:
        console.print("\nDry run — nothing written.")
        return

    if not drift:
        console.print("\n[green]Already current — nothing to do.[/green]")
        return

    # Apply.
    journal = Journal(ws / "journals")
    catalog_sha = git_head_sha(rule_root)
    applied = 0
    for entry in plan:
        if entry.action is Action.UNCHANGED:
            continue

        if entry.action is Action.ORPHANED and entry.merged is not None:
            found = cat.find_record(entry.detection_id)
            if found is not None:
                path, _ = found
                cat.write_raw(path, entry.merged)
                _journal_note(journal, entry.detection_id, "Source rule gone — orphaned by `adef sync`.")
                applied += 1
            continue

        # NEW / MODIFIED: re-derive the record with the real root (correct
        # rule_ref/original_path), then graft enrichment for MODIFIED.
        disc = entry.discovered
        assert disc is not None  # NEW/MODIFIED always carry a discovered rule
        rec = record_from_discovered(
            entry.detection_id, disc, workspace=ws, rule_root=rule_root, catalog_sha=catalog_sha
        )
        if entry.action is Action.MODIFIED and entry.merged is not None:
            for f in ("mitre", "status", "stage", "owner", "created"):
                if f in entry.merged:
                    setattr(rec, f, entry.merged[f])
        cat.write(rec)

        if entry.action is Action.NEW:
            if not (journal.directory / f"{rec.id}.md").exists():
                journal.create(
                    detection_id=rec.id, title=rec.title, owner=rec.owner, rule_uuid="",
                    note=f"Catalogued from {rec.rule_ref} by `adef sync`.",
                )
        else:  # MODIFIED — record the out-of-band change in the journal
            _journal_note(
                journal, rec.id,
                f"Source changed (hash {disc.source_hash[:8]}); derived fields refreshed by `adef sync`.",
            )
        applied += 1

    index_path = cat.rebuild_index()
    console.print(f"\n[green]Synced[/green] {applied} change(s); INDEX → {index_path}")


def _journal_note(journal: Journal, detection_id: str, note: str) -> None:
    """Append a note to a detection's journal (create if missing). Best-effort."""
    try:
        if (journal.directory / f"{detection_id}.md").exists():
            journal.advance_stage(detection_id=detection_id, stage="evolve", note=note)
        else:
            journal.create(detection_id=detection_id, title=detection_id, note=note)
    except Exception as exc:  # journaling is enrichment, never fatal to sync
        console.print(f"[yellow]note: could not journal {detection_id}: {exc}[/yellow]")


__all__ = ["sync"]
