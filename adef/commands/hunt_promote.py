"""``adef hunt-promote`` — turn a finished hunt into draft ADEF detections.

Two input modes, and they share nothing but the command name::

    adef hunt-promote --gates H-0041_GATES.yaml   # an ATHF GATES document
    adef hunt-promote H-0042                      # a configured generator plugin

**``--gates`` (the primary path).** ATHF's ``gates`` skill already did the
reasoning and wrote it down: N candidate detections, each with a verdict, the
BASE evidence behind it, and — when the verdict is deployable — the query. So
this mode is a parser, not an agent. Deployable candidates get a catalog record
(``origin: promoted``) and a journal carrying the reasoning; archival ones are
reported and nothing is written. Idempotent on ``hunt_ref``, so re-importing a
regenerated document updates rather than duplicates. The hunt ID comes from the
document, so no ``HUNT_ID`` argument. See ``adef.core.gates``.

**``HUNT_ID`` (the generator path).** For a hunt that has *not* been through
GATES:

1. Resolves ``HUNT_ID`` in the configured hunt source.
2. Calls a configured generator (lazy-imported via a dotted path; see
   ``adef.agents.hunt_promotion``) to produce a draft Sigma rule.
3. Writes the draft to ``<rule-staging-root>/D-draft-XXXX.yml`` (a *staging*
   directory, never any production rule directory).
4. Creates an ADEF journal at the Find stage with intel sources populated.

The generator dotted path and roots are configured by environment variable
or ``--option`` flags. ADEF itself takes no opinion on which upstream system
provides the hunt.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

console = Console()


@click.command(name="hunt-promote")
@click.argument("hunt_id", required=False)
@click.option(
    "--gates",
    "gates_doc",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Import an ATHF GATES document (H-XXXX_GATES.yaml) instead of calling a generator.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="With --gates: show what would be imported, write nothing.",
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
@click.option(
    "--rule-staging-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory where the staging YAML draft is written (overrides ADEF_RULE_STAGING_ROOT).",
)
@click.option(
    "--hunt-root",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory where hunt artifacts live (overrides ADEF_HUNT_ROOT).",
)
def hunt_promote(
    hunt_id: str | None,
    gates_doc: Path | None,
    dry_run: bool,
    workspace: Path | None,
    rule_staging_root: Path | None,
    hunt_root: Path | None,
) -> None:
    """Promote a hunt to draft ADEF detections.

    Two input modes:

    \b
      adef hunt-promote --gates H-0041_GATES.yaml   # ATHF GATES document (N detections)
      adef hunt-promote H-0042                      # via a configured generator plugin
    """
    if gates_doc is not None:
        if hunt_id:
            # The two modes take their hunt from different places: `--gates` reads
            # `hunt_metadata.hunt_id` out of the document. Accepting a positional
            # too meant `hunt-promote H-0099 --gates H-0041_GATES.yaml` silently
            # imported H-0041 and reported success, so a mismatched pair — the one
            # case worth catching — looked like it had worked.
            console.print(
                "[red]hunt-promote failed:[/red] --gates takes the hunt ID from the "
                f"document; drop the HUNT_ID argument ({escape(str(hunt_id))})."
            )
            sys.exit(2)
        # Symmetric with the HUNT_ID rejection above and with `--dry-run` below:
        # both of these only reach the generator path, so under `--gates` they
        # were accepted and silently ignored — the user believes they redirected
        # the output and gets no hint that they didn't.
        ignored = [
            flag
            for flag, value in (
                ("--rule-staging-root", rule_staging_root),
                ("--hunt-root", hunt_root),
            )
            if value is not None
        ]
        if ignored:
            console.print(
                f"[red]hunt-promote failed:[/red] {' and '.join(ignored)} "
                "only applies to the generator path; --gates writes to the "
                "workspace catalog and journals."
            )
            sys.exit(2)
        _promote_from_gates(gates_doc, workspace, dry_run)
        return
    if not hunt_id:
        console.print("[red]hunt-promote failed:[/red] give a HUNT_ID or --gates <path>.")
        sys.exit(2)
    if dry_run:
        # The generator path has no dry run, and accepting the flag here would make
        # `hunt-promote H-0042 --dry-run` write a staging YAML and a journal while
        # the user believes they asked for a preview.
        console.print(
            "[red]hunt-promote failed:[/red] --dry-run is only supported with --gates."
        )
        sys.exit(2)

    from adef.agents.hunt_promotion import HuntPromotionAgent, HuntPromotionError

    try:
        agent = HuntPromotionAgent(
            hunt_root=hunt_root,
            rule_staging_root=rule_staging_root,
            workspace_root=workspace,
        )
        result = agent.run(hunt_id=hunt_id)
    except HuntPromotionError as exc:
        console.print(f"[red]hunt-promote failed:[/red] {escape(str(exc))}")
        sys.exit(2)

    console.print(f"[green]Promoted[/green] {escape(str(hunt_id))} → {result.detection_id}")
    console.print(f"  staging YAML: {escape(str(result.staging_yaml))}")
    console.print(f"  ADEF journal: {escape(str(result.journal_path))}")


def _promote_from_gates(gates_doc: Path, workspace: Path | None, dry_run: bool) -> None:
    """Import a GATES document: N detections, one hunt."""
    from adef.core.catalog import CatalogError
    from adef.core.gates import (
        GatesError,
        import_gates,
        parse_gates,
        superseded_ordinal_refs,
    )
    from adef.core.journal import JournalError

    try:
        doc = parse_gates(gates_doc)
        results = import_gates(gates_doc, workspace=workspace, dry_run=dry_run)
    # A document can also be rejected by the catalog or the journal layer rather
    # than the parser — a `platforms` value that resolves outside the workspace
    # is refused at `Catalog._path_for` (`CatalogError`), and a workspace path
    # with a `detections/` segment is refused by `_check_not_under_detections`
    # (`HardInvariantViolation`, a `JournalError`). Same class of bad input, so
    # all three get the same message instead of a traceback.
    except (GatesError, CatalogError, JournalError) as exc:
        console.print(f"[red]hunt-promote failed:[/red] {escape(str(exc))}")
        sys.exit(2)

    prefix = "Would promote" if dry_run else "Promoted"
    console.print(
        f"[green]{prefix}[/green] {escape(str(doc.hunt_id))} ({escape(str(doc.title))}) — "
        f"{len(results)} candidate(s), hunt verdict {escape(str(doc.verdict or 'unstated'))}"
    )
    for res in results:
        if res.detection_id:
            action = "new" if res.minted else "updated"
            console.print(
                f"  {res.detection_id}  {res.verdict:<15} {action:<7} record + journal\n"
                f"          {escape(str(res.name))}"
            )
        else:
            console.print(
                f"  [dim]—       {res.verdict:<15} skipped[/dim] not deployable, no record minted\n"
                f"          [dim]{escape(str(res.name))}[/dim]"
            )
    if not results:
        console.print("  [yellow]no detections in this document[/yellow]")
    # A document regenerated after GATES renamed `detection_id` → `candidate_id`
    # re-keys every candidate, so the import above could only mint duplicates of
    # records the earlier run already wrote. Say so: the merge is a human call
    # (see `superseded_ordinal_refs`), and a silent duplicate is the worse end.
    for ref in superseded_ordinal_refs(doc, workspace):
        console.print(
            f"  [yellow]warning:[/yellow] an existing record is keyed {escape(str(ref))} — an "
            "ordinal `detection_id` this document no longer uses. If it is one of "
            "the candidates above under its new `candidate_id`, the two records are "
            "the same detection and want merging by hand."
        )


__all__ = ["hunt_promote"]
