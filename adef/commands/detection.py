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


__all__ = ["detection"]
