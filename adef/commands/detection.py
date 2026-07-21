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
    next_detection_id,
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
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
def new(title: str, owner: str, rule_uuid: str, workspace: Path | None) -> None:
    """Create a new detection journal at the Find stage."""
    journals_dir = workspace_journals_dir(workspace)
    detection_id = next_detection_id(journals_dir)
    journal = Journal(journals_dir).create(
        detection_id=detection_id,
        title=title,
        owner=owner,
        rule_uuid=rule_uuid,
    )
    console.print(
        f"[green]Created[/green] {journal.path.relative_to(journals_dir.parent)} at Find stage."
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
    """Same resolution the stage commands use: journals dir's parent."""
    return workspace_journals_dir(workspace).parent


@detection.command("list")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
@click.option("--platform", default=None, help="Filter by platform (e.g. windows).")
@click.option("--rule-format", "rule_format", default=None, help="Filter by source format (sigma, spl, <profile>).")
@click.option("--status", default=None, help="Filter by status (draft, ready, tuning, deprecated).")
@click.option("--stage", default=None, help="Filter by FORGE stage (find … evolve).")
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
    rule_format: str | None,
    status: str | None,
    stage: str | None,
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

    ws = _workspace_from(workspace)
    records = []
    for det_id, _path, data in Catalog(ws).iter_records():
        if platform and data.get("platform") != platform:
            continue
        if rule_format and data.get("format") != rule_format:
            continue
        if status and data.get("status") != status:
            continue
        if stage and data.get("stage") != stage:
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
            "id", "title", "platform", "format", "query_language", "data_source",
            "mitre", "status", "stage", "owner", "needs_review", "review_reasons",
            "rule_ref",
        )
        click.echo(_json.dumps([{k: d.get(k) for k in keys} for d in records], indent=2))
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
    console.print(f"  {'mitre':<15} {', '.join(record.get('mitre') or []) or '-'}")
    console.print(
        f"  {'lifecycle':<15} stage={record.get('stage')} status={record.get('status')}"
        + (f" owner={record['owner']}" if record.get("owner") else "")
    )
    if record.get("needs_review"):
        reasons = ", ".join(record.get("review_reasons") or []) or "unspecified (legacy record)"
        console.print(f"  [yellow]needs_review[/yellow]   {reasons}")
    if record.get("rule_ref"):
        console.print(f"  {'source':<15} {record['rule_ref']}")
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


__all__ = ["detection"]
