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

import re
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from adef.core.catalog import (
    Catalog,
    git_head_sha,
    record_from_discovered,
    refresh_mitre_review,
)
from adef.core.journal import Journal
from adef.core.profiles import load_user_profiles
from adef.core.reconcile import (
    _CARRIED_ENRICHMENT,
    _ENRICHMENT_FIELDS,
    _PRESERVED_IDENTITY,
    Action,
    reconcile,
)
from adef.core.rule_discovery import walk_outcomes
from adef.core.workspace import resolve_workspace as _resolve_workspace

console = Console()


def _from_root(rule_root: Path):
    """Did this record come from ``rule_root``? A workspace can hold several
    repos; syncing one must only ever orphan that repo's rules.

    A record is this repo's if it was catalogued from a path under the root. A
    record catalogued elsewhere is NOT, while that other repo still exists —
    even if both repos share a directory name (`rules/` vs `rules/`). Only when
    its origin is gone does the ``<root-name>/`` ``rule_ref`` claim it: that is
    a moved repo.
    """
    root = Path(rule_root).expanduser().resolve()
    prefix = f"{root.name}/"

    def belongs(rec: dict) -> bool:
        original = str(rec.get("original_path") or "")
        ref = str(rec.get("rule_ref") or "")
        if original:
            path = Path(original).expanduser().resolve()
            try:
                path.relative_to(root)
                return True
            except ValueError:
                pass
            # Catalogued from somewhere else. If that repo still exists, the
            # record is its — even when both repos share a directory name.
            inside = ref[len(prefix):] if ref.startswith(prefix) else ""
            if inside and str(path).endswith(inside):
                origin = Path(str(path)[: -len(inside)])
                if origin.is_dir() and origin.resolve() != root:
                    return False
        # No live origin elsewhere: the <root-name>/ ref ties it here (a moved repo).
        return ref.startswith(prefix)

    return belongs


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
        console.print(f"[yellow]Skipping broken profile:[/yellow] {escape(str(err))}", highlight=False)
    discovered = [r for oc in walk_outcomes(rule_root, user_profiles, ws) for r in oc.rules]

    # Floor NEW ids above any journal-only detection id too (shared ID space) —
    # else a rule whose catalog record was removed but whose journal survives
    # gets its id reused (CodeRabbit; same footgun `detection new` guards).
    plan = reconcile(
        existing, discovered, rule_root=rule_root,
        floor_index=cat.journals_max_index(),
        orphan_scope=_from_root(rule_root),
    )
    counts = {a: 0 for a in Action}
    for entry in plan:
        counts[entry.action] += 1

    drift = counts[Action.MODIFIED] + counts[Action.NEW] + counts[Action.ORPHANED]

    # Report (always).
    console.print(
        f"[bold]Sync plan[/bold] for {escape(str(rule_root))}:\n"
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
        console.print(f"  {label}  {entry.detection_id}  {escape(str(title))}")

    if check:
        if drift:
            console.print(f"\n[yellow]Catalog is behind: {drift} change(s).[/yellow] Run `adef sync`.")
            raise SystemExit(1)
        console.print("\n[green]Catalog is current.[/green]")
        return

    if dry_run:
        console.print("\nDry run — nothing written.")
        return

    # Repair pass (replaces the retired `adef backfill journals`): a matched
    # record whose journal has gone missing gets a fresh skeleton, even when
    # the source repo has no drift.
    journal = Journal(ws / "journals")
    repaired = 0
    for det_id, _rpath, rdata in cat.iter_records():
        # Only ADEF-minted ids reach Journal.create — a hand-edited record id
        # ("../x", absolute path) must not become a filesystem path.
        if not re.fullmatch(r"D-\d{4,}", str(det_id)):
            continue
        if not (journal.directory / f"{det_id}.md").exists():
            journal.create(
                detection_id=det_id,
                title=rdata.get("title") or det_id,
                owner=rdata.get("owner") or "",
                rule_uuid=rdata.get("rule_uuid") or "",
                note="Journal missing for this record — re-created by `adef sync`.",
                # Derived restatement, same class as the other sync housekeeping
                # notes below: the fact that a journal was missing is recoverable
                # from nothing (the file now exists), and repeats on every sync
                # that runs the repair pass. Direct `journal.create()` call, not
                # `_journal_note` — its default doesn't reach here.
                generated=True,
            )
            repaired += 1
    if repaired:
        console.print(f"[green]Re-created[/green] {repaired} missing journal(s).")

    if not drift:
        console.print("\n[green]Already current — nothing to do.[/green]")
        return

    # Apply.
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
            # Every field `_merge` kept, not a hand-picked five. The re-derive
            # above exists only to fix `rule_ref`/`original_path` (reconcile ran
            # without the real root), but it also resets everything discovery
            # can't see — so `description`, `references`, `entities` and the rest
            # of the enrichment block were being destroyed by a sync of an edited
            # rule, which is exactly the guarantee this command advertises.
            for f in _ENRICHMENT_FIELDS + _PRESERVED_IDENTITY + _CARRIED_ENRICHMENT:
                if f in entry.merged:
                    setattr(rec, f, entry.merged[f])
            # `mitre` just came back from the existing record, but the re-derive
            # above computed `review_reasons` from the *source rule*, which has no
            # tags — so a hand-tagged detection was re-queued as `no_mitre` by
            # every sync, undoing `adef detection tag-mitre` on a schedule. The
            # helper subsumes `dev`'s inline drop of `no_mitre`: it also normalizes
            # a scalar `mitre` and re-derives `invalid_mitre`, and `no_platform` is
            # already a review reason, so `bool(review_reasons)` covers the
            # `disc.platform is None` arm the inline version spelled out.
            refresh_mitre_review(rec, ws)
        cat.write(rec)

        if entry.action is Action.NEW:
            if not (journal.directory / f"{rec.id}.md").exists():
                journal.create(
                    detection_id=rec.id, title=rec.title, owner=rec.owner, rule_uuid="",
                    note=f"Catalogued from {rec.rule_ref} by `adef sync`.",
                    generated=True,
                )
        else:  # MODIFIED — record the out-of-band change in the journal
            _journal_note(
                journal, rec.id,
                f"Source changed (hash {disc.source_hash[:8]}); derived fields refreshed by `adef sync`.",
            )
        applied += 1

    index_path = cat.rebuild_index()
    console.print(f"\n[green]Synced[/green] {applied} change(s); INDEX → {escape(str(index_path))}")


def _journal_note(journal: Journal, detection_id: str, note: str, generated: bool = True) -> None:
    """Append a note to a detection's journal (create if missing). Best-effort.

    Re-advance to the journal's *current* stage, not a hardcoded one — sync
    records an out-of-band source change without moving the detection through
    FORGE (advancing to a fixed stage would corrupt the lifecycle state, which
    is the journal's whole point). Re-advancing to the same stage is idempotent:
    it appends the note only, no duplicate stage block (CodeRabbit).

    ``generated=True`` by default: every call site of this helper writes sync
    housekeeping — derived restatement of state already on the record (the
    orphaned flag, the refreshed hashes) — not a fact recorded nowhere else,
    so it is marked generated and excluded from search.
    """
    try:
        if (journal.directory / f"{detection_id}.md").exists():
            stage = journal.read(detection_id).current_stage
            journal.advance_stage(
                detection_id=detection_id, stage=stage, note=note, generated=generated
            )
        else:
            journal.create(
                detection_id=detection_id, title=detection_id, note=note, generated=generated
            )
    except Exception as exc:  # journaling is enrichment, never fatal to sync
        console.print(f"[yellow]note: could not journal {detection_id}: {escape(str(exc))}[/yellow]")


__all__ = ["sync"]
