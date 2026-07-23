"""``adef detection`` — Click subgroup for the FORGE lifecycle commands.

Each subcommand:

- advances the journal's ``current_stage`` frontmatter atomically,
- appends a timestamped ``## [<ISO-8601>] Stage: <stage>`` block,
- renders a stage-specific prompt from ``adef/data/prompts/<stage>.md`` into the block,
- (for ``refine``) invokes the orchestration chain (Similarity → Overlap → Verification).

The hard invariant — no path under any external rule directory is opened — is
enforced by the ``Journal`` class, not here.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from adef.core.journal import (
    FORGE_STAGES,
    Journal,
    workspace_journals_dir,
)

console = Console()


@click.group()
def detection() -> None:
    """FORGE lifecycle commands — new, observe, refine, govern, evolve."""


@detection.command("new")
@click.argument("title")
@click.option("--owner", default="", help="Initial owner of the detection.")
@click.option("--rule-uuid", default="", help="Optional upstream rule UUID to pair.")
@click.option(
    "--source",
    default="",
    help="Declared schema to ground a new rule against (e.g. wineventlog_xml). "
    "Also creates a draft catalog record with the source's platform, "
    "query_language, and scope literals. Omit to create a journal only.",
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
def new(
    title: str, owner: str, rule_uuid: str, source: str, workspace: Path | None
) -> None:
    """Create a new detection journal at the Find stage.

    With ``--source``, also scaffolds a draft catalog record grounded in that
    declared schema — the starting point for authoring a brand-new rule (the
    journal captures *why*; the record holds the *what*). The rule lands in the
    ADEF catalog; getting it into your rules repo is your call.
    """
    journals_dir = workspace_journals_dir(workspace)
    # Allocate from the SHARED id space (catalog + journals), not journals alone —
    # otherwise a workspace whose catalog index exceeds its journal index (e.g. a
    # catalog record whose journal was removed) would mint a duplicate D-XXXX and
    # clobber the existing catalog record on write. (ISA 2026-07-22 guardrail audit.)
    from adef.core.catalog import Catalog

    ws = journals_dir.parent
    detection_id = Catalog(ws).next_id()

    # If grounding a new rule, build the record FIRST so a bad --source fails
    # before we write a dangling journal.
    record = None
    if source:
        from adef.core.catalog import draft_record_from_schema

        try:
            record = draft_record_from_schema(ws, detection_id, title, source)
        except FileNotFoundError as exc:
            raise click.ClickException(str(exc)) from exc

    journal = Journal(journals_dir).create(
        detection_id=detection_id,
        title=title,
        owner=owner,
        rule_uuid=rule_uuid,
    )
    console.print(
        f"[green]Created[/green] {journal.path.relative_to(journals_dir.parent)} at Find stage."
    )

    if record is not None:
        cat = Catalog(journals_dir.parent)
        rec_path = cat.write(record)
        cat.rebuild_index()
        console.print(
            f"[green]Scaffolded[/green] draft rule {rec_path.relative_to(journals_dir.parent)} "
            f"grounded in schema [cyan]{source}[/cyan] "
            f"({record.platform} / {record.query_language})."
        )
        console.print(
            "  Next: fill in the query + author the Find context in the journal "
            "(the AI assistant / mitre-tagger can help)."
        )


def _make_stage_command(stage: str) -> click.Command:
    """Return a Click command implementing ``adef detection <stage> ID``."""

    @click.command(name=stage, help=f"Advance a detection to the {stage.capitalize()} stage.")
    @click.argument("detection_id")
    @click.option(
        "--workspace",
        type=click.Path(file_okay=False, path_type=Path),
        default=None,
        help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
    )
    @click.option(
        "--note",
        default="",
        help="Free-text note appended to the stage block.",
    )
    def cmd(detection_id: str, workspace: Path | None, note: str) -> None:
        journals_dir = workspace_journals_dir(workspace)
        journal = Journal(journals_dir)
        result = journal.advance_stage(detection_id=detection_id, stage=stage, note=note)

        if result.was_idempotent:
            console.print(
                f"[yellow]Already at {stage}[/yellow] — appended note only."
                if note
                else f"[yellow]Already at {stage}[/yellow] — no changes."
            )
        else:
            console.print(f"[green]{detection_id} → {stage}[/green]")

        if stage == "refine":
            from adef.orchestration.refine_chain import run_refine_chain

            run_refine_chain(journal=journal, detection_id=detection_id)
            console.print("[green]Refine chain complete[/green] — Similarity → Overlap → Verification appended.")

    return cmd


# Register each FORGE stage other than ``find`` (Find is the entry-point of ``new``).
for _stage in FORGE_STAGES:
    if _stage == "find":
        continue
    detection.add_command(_make_stage_command(_stage))


# --------------------------------------------------------------------------- #
# Browsing — list / show (story 7393)
# --------------------------------------------------------------------------- #
def _workspace_from(workspace: Path | None) -> Path:
    """Canonical workspace for the read/browse commands. ``create=False`` — a
    list/show/tag never scaffolds a workspace as a side effect."""
    return workspace_journals_dir(workspace, create=False).parent


@detection.command("list")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
@click.option("--platform", default=None, help="Filter by platform (e.g. windows).")
@click.option(
    "--tactic",
    default=None,
    help="Filter by ATT&CK tactic, resolved from each detection's technique IDs. "
    "Accepts the tactic shortname (e.g. defense-evasion) or display name "
    "(e.g. 'Defense Evasion').",
)
@click.option(
    "--engine",
    default=None,
    help="Filter by internal engine (sigma, sql, sch_sql, composite).",
)
@click.option("--rule-format", "rule_format", default=None, help="Filter by source format (sigma, spl, <profile>).")
@click.option("--status", default=None, help="Filter by status (draft, ready, tuning, deprecated).")
@click.option("--stage", default=None, help="Filter by FORGE stage (find … evolve).")
@click.option(
    "--origin",
    type=click.Choice(["authored", "catalogued"]),
    default=None,
    help="Filter by origin: authored (created in ADEF) vs catalogued (from a repo).",
)
@click.option(
    "--needs-review",
    "needs_review",
    is_flag=False,
    flag_value="any",
    default=None,
    help="Only detections needing review. Bare flag = structural reasons "
    "(malformed, external_logic, no_platform); pass a reason to filter it "
    "specifically (e.g. --needs-review no_mitre for the enrichment queue).",
)
@click.option(
    "--report",
    "report_format",
    type=click.Choice(["json"]),
    default=None,
    help="Emit machine-readable output.",
)
def list_cmd(
    workspace: Path | None,
    platform: str | None,
    tactic: str | None,
    engine: str | None,
    rule_format: str | None,
    status: str | None,
    stage: str | None,
    origin: str | None,
    needs_review: str | None,
    report_format: str | None,
) -> None:
    """List catalogued detections (reads the workspace catalog)."""
    import json as _json

    from adef.core.catalog import Catalog
    from adef.core.rule_discovery import structural_reasons

    def _reasons(data: dict) -> list[str]:
        if "review_reasons" in data:
            return list(data.get("review_reasons") or [])
        # Pre-rework records: boolean only — treat as one opaque structural reason.
        return ["legacy"] if data.get("needs_review") else []

    # Tactics aren't stored on records — resolve them from each detection's
    # technique IDs via the ATT&CK reference. Only load the snapshot when a
    # caller actually needs tactics (the --tactic filter or JSON output).
    ref = None
    if tactic or report_format == "json":
        from adef.core.attack import attack_reference

        ref = attack_reference()

    def _norm(value: str) -> str:
        # ATT&CK tactic shortnames are the lowercased, hyphenated display names,
        # so normalizing either input form to the same shape matches both.
        return value.strip().lower().replace(" ", "-").replace("_", "-")

    def _tactics_of(data: dict) -> list[str]:
        """Display names of the tactics this detection's techniques cover."""
        assert ref is not None  # only called once the snapshot is loaded
        display: list[str] = []
        for tid in data.get("mitre") or []:
            names = ref.tactics_for(tid)
            if not names and "." in tid:  # sub-technique w/o its own tactics → parent
                names = ref.tactics_for(tid.split(".")[0])
            for name in names:
                if name not in display:
                    display.append(name)
        return display

    want_tactic = _norm(tactic) if tactic else None

    ws = _workspace_from(workspace)
    records = []
    for det_id, _path, data in Catalog(ws).iter_records():
        if platform and data.get("platform") != platform:
            continue
        if engine and data.get("engine") != engine:
            continue
        if rule_format and data.get("format") != rule_format:
            continue
        if status and data.get("status") != status:
            continue
        if stage and data.get("stage") != stage:
            continue
        # Default origin for legacy records (no field) is "catalogued".
        if origin and (data.get("origin") or "catalogued") != origin:
            continue
        if want_tactic is not None:
            if want_tactic not in {_norm(t) for t in _tactics_of(data)}:
                continue
        reasons = _reasons(data)
        if needs_review == "any":
            if not (structural_reasons(reasons) or "legacy" in reasons):
                continue
        elif needs_review is not None:
            if needs_review not in reasons:
                continue
        records.append(data)
    records.sort(key=lambda d: d.get("id", ""))

    if report_format == "json":
        keys = (
            "id", "title", "platform", "engine", "format", "query_language",
            "data_source", "mitre", "status", "stage", "owner", "origin",
            "needs_review", "review_reasons", "rule_ref",
        )
        payload = []
        for d in records:
            row: dict = {k: d.get(k) for k in keys}
            row["tactics"] = _tactics_of(d)  # derived, not stored
            payload.append(row)
        click.echo(_json.dumps(payload, indent=2))
        return

    if not records:
        console.print("[yellow]No detections match.[/yellow] (Run `adef catalog <rules>` first?)")
        return
    for d in records:
        structural = structural_reasons(_reasons(d)) or (
            ("legacy",) if "legacy" in _reasons(d) else ()
        )
        flag = f" [yellow]⚠ {','.join(structural)}[/yellow]" if structural else ""
        mitre = ",".join(d.get("mitre") or []) or "-"
        console.print(
            f"  {d.get('id', '?')}  {d.get('stage', '?'):<8} {d.get('status', '?'):<10} "
            f"{d.get('platform', '?'):<15} {d.get('format', '?'):<22} {mitre:<12} "
            f"{d.get('title', '')}{flag}"
        )
    n_structural = sum(
        1 for d in records if structural_reasons(_reasons(d)) or "legacy" in _reasons(d)
    )
    n_mitre = sum(1 for d in records if "no_mitre" in _reasons(d))
    summary = f"\n[bold]{len(records)}[/bold] detection(s)"
    if n_structural:
        summary += f" ([yellow]{n_structural}[/yellow] need review)"
    if n_mitre:
        summary += f" ({n_mitre} missing ATT&CK — `--needs-review no_mitre`)"
    console.print(summary)


@detection.command("show")
@click.argument("detection_id")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
def show(detection_id: str, workspace: Path | None) -> None:
    """Show one detection: catalog record + paired journal."""
    from adef.core.catalog import Catalog

    ws = _workspace_from(workspace)
    record = None
    for det_id, _path, data in Catalog(ws).iter_records():
        if det_id == detection_id:
            record = data
            break
    if record is None:
        raise click.ClickException(f"{detection_id} not found in the catalog under {ws}")

    console.print(f"[bold]{record.get('id')}  {record.get('title', '')}[/bold]")
    for key in ("platform", "format", "query_language", "data_source", "kind", "engine"):
        if record.get(key):
            console.print(f"  {key:<15} {record[key]}")
    mitre_ids = record.get("mitre") or []
    console.print(f"  {'mitre':<15} {', '.join(mitre_ids) or '-'}")
    if mitre_ids:  # tactics are derived from the technique IDs, not stored on the record
        from adef.core.attack import attack_reference

        ref = attack_reference()
        tactics: list[str] = []
        for tid in mitre_ids:
            names = ref.tactics_for(tid)
            if not names and "." in tid:  # sub-technique w/o its own tactics → parent
                names = ref.tactics_for(tid.split(".")[0])
            for name in names:
                if name not in tactics:
                    tactics.append(name)
        if tactics:
            console.print(f"  {'tactics':<15} {', '.join(tactics)}")
    console.print(
        f"  {'lifecycle':<15} stage={record.get('stage')} status={record.get('status')}"
        + (f" owner={record['owner']}" if record.get("owner") else "")
    )
    console.print(f"  {'origin':<15} {record.get('origin') or 'catalogued'}")
    if record.get("needs_review"):
        reasons = ", ".join(record.get("review_reasons") or []) or "unspecified (legacy record)"
        console.print(f"  [yellow]needs_review[/yellow]   {reasons}")
    if record.get("rule_ref"):
        console.print(f"  {'source':<15} {record['rule_ref']}")
    support = record.get("support")
    if support and support != "supported":
        console.print(
            f"  [yellow]{'support':<15}[/yellow] {support} "
            "(format recognized; logic not parsed — e.g. external file)"
        )
    if record.get("query"):
        console.print("\n[bold]Query[/bold]")
        for line in record["query"].splitlines():
            console.print(f"  {line}", highlight=False)

    journal_path = ws / "journals" / f"{detection_id}.md"
    if journal_path.is_file():
        console.print(f"\n[bold]Journal[/bold]  {journal_path}")
        stages = [
            line.strip()
            for line in journal_path.read_text(encoding="utf-8").splitlines()
            if line.startswith("## [")
        ]
        for entry in stages[-3:]:
            console.print(f"  {entry}")
    else:
        console.print("\n[yellow]No paired journal.[/yellow]")


@detection.command("tag-mitre")
@click.argument("detection_id")
@click.argument("technique_ids", nargs=-1, required=True)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
def tag_mitre_cmd(
    detection_id: str, technique_ids: tuple[str, ...], workspace: Path | None
) -> None:
    """Add ATT&CK technique IDs to a catalog record (drains the no_mitre queue).

    IDs are validated against the shipped ATT&CK reference; an invalid ID
    aborts without writing. Writes only to ADEF's catalog record — never the
    source rule. Example: ``adef detection tag-mitre D-0007 T1547.001 T1055``.
    """
    from adef.core.tag import InvalidTechniqueError, tag_mitre

    ws = _workspace_from(workspace)
    try:
        result = tag_mitre(ws, detection_id, list(technique_ids))
    except KeyError as exc:
        raise click.ClickException(str(exc).strip('"')) from exc
    except InvalidTechniqueError as exc:
        raise click.ClickException(str(exc)) from exc

    if result.added:
        console.print(f"[green]Tagged[/green] {detection_id} += {', '.join(result.added)}")
    if result.already_present:
        console.print(f"  already present: {', '.join(result.already_present)}")
    for revoked_id, replacement in result.revoked.items():
        console.print(
            f"  [yellow]note[/yellow] {revoked_id} is revoked → consider {replacement}"
        )
    if not result.added and not result.already_present:
        console.print("Nothing to add.")


__all__ = ["detection"]
