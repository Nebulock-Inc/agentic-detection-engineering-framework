"""``adef detection`` — Click subgroup for the FORGE lifecycle commands.

Each subcommand:

- advances the journal's ``current_stage`` frontmatter atomically,
- appends a lean timestamped ``## [<ISO-8601>] Stage: <stage>`` block with the
  note (stage *guidance* lives once in the template's fill-in sections, not
  re-printed per block — ISA 2026-07-22),
- (for ``refine``) invokes the orchestration chain (Similarity → Overlap → Verification).

The hard invariant — no path under any external rule directory is opened — is
enforced by the ``Journal`` class, not here.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from adef.core.corpus_text import record_search_text as _record_search_text
from adef.core.engines import ALLOWED_ENGINES
from adef.core.journal import (
    FORGE_STAGES,
    Journal,
    JournalError,
    workspace_journals_dir,
)

console = Console()

# Closed value-sets for validating `detection list` filters — a typo should
# error, not read as zero coverage. (Open-ended --platform/--rule-format have no
# fixed set to check against.) Engines come from `adef.core.engines`, the single
# canonical copy — never re-type the literal set.
_STATUSES = frozenset({"draft", "ready", "tuning", "deprecated"})


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
    if not title.strip():
        raise click.ClickException("TITLE must not be empty.")
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
        if not record.query:
            # Be honest: the starter query is empty (schema has no scope literals,
            # or an unmodelled query language) — nothing was actually "grounded".
            console.print(
                f"  [yellow]note:[/yellow] schema [cyan]{source}[/cyan] has no scope "
                "literals, so the starter query is empty — you'll write it from scratch."
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
        "notes",
        multiple=True,
        help="Note appended to the stage block. Repeatable — pass --note several "
        'times to capture separate points (e.g. --note "Baseline: 3/day" '
        '--note "FP source: admin scripts"); they render as a bullet list.',
    )
    def cmd(
        detection_id: str,
        workspace: Path | None,
        notes: tuple[str, ...],
        chain: bool = False,
        similarity_mode: str = "bm25",
    ) -> None:
        # One note → plain line; several → a markdown bullet list.
        note = notes[0] if len(notes) == 1 else "\n".join(f"- {n}" for n in notes)
        journals_dir = workspace_journals_dir(workspace)
        journal = Journal(journals_dir)
        try:
            result = journal.advance_stage(detection_id=detection_id, stage=stage, note=note)
        except JournalError as exc:
            # Missing/malformed id → clean error, not a raw traceback (parity with
            # `show`/`tag-mitre`).
            raise click.ClickException(str(exc)) from exc

        if result.was_idempotent:
            console.print(
                f"[yellow]Already at {stage}[/yellow] — appended note only."
                if note
                else f"[yellow]Already at {stage}[/yellow] — no changes."
            )
        else:
            console.print(f"[green]{detection_id} → {stage}[/green]")

        # Mirror the stage onto the paired catalog record — the journal is
        # authoritative for lifecycle, but `detection list --stage` filters on
        # the record; leaving it behind made it lie (found live: D-1470
        # advanced to observe, record stuck at find). Runs on the idempotent
        # path too, so records desynced before this fix self-heal on re-run.
        from adef.core.catalog import Catalog, _now_iso

        cat = Catalog(journals_dir.parent)
        found = cat.find_record(detection_id)
        if found is not None:
            rec_path, rec_data = found
            if rec_data.get("stage") != stage:
                rec_data["stage"] = stage
                rec_data["updated"] = _now_iso()
                cat.write_raw(rec_path, rec_data)
                cat.rebuild_index()
                console.print(f"  catalog record stage → {stage}")

        if stage == "refine":
            # Chain runs on the actual transition (or explicit --chain), never
            # on idempotent note-appends — those were appending a fresh
            # Similarity/Overlap/Verification block set to the journal on
            # every `refine --note` (found live: D-1470 got duplicate
            # WrapperUnavailable triplets one minute apart).
            if chain or not result.was_idempotent:
                from adef.orchestration.refine_chain import run_refine_chain

                # `workspace` must be forwarded: every native Refine agent
                # resolves `workspace_journals_dir(None)` when not given one,
                # which would silently read a *different* catalog than the one
                # `--workspace` named.
                run_refine_chain(journal=journal, detection_id=detection_id,
                                  workspace=workspace, similarity_mode=similarity_mode)
                console.print("[green]Refine chain complete[/green] — Similarity → Overlap → Verification appended.")
            else:
                console.print("  chain skipped (already at refine) — re-run it with [bold]--chain[/bold]")

    if stage == "refine":
        cmd.params.append(
            click.Option(
                ["--chain"],
                is_flag=True,
                help="Re-run the Similarity → Overlap → Verification chain even if "
                "already at refine (e.g. after configuring the wrapper agents).",
            )
        )
        cmd.params.append(
            click.Option(
                ["--similarity-mode"],
                type=click.Choice(["bm25", "agent", "llm", "auto"]),
                default="bm25",
                help="How the Similarity refine-step ranks candidates. 'bm25' (default) is "
                "fully deterministic and makes no network call. 'agent' returns the "
                "shortlist enriched with each candidate's query, MITRE IDs, platform, "
                "and data source for YOU to rank — also no network call, and the mode "
                "to use from an assistant session. 'llm' reranks with an LLM judge "
                "(requires ANTHROPIC_API_KEY + the 'llm' extra) and sends detection "
                "content to the Anthropic API. "
                "'auto' picks llm when available, else bm25.",
            )
        )
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
    "Accepts the tactic shortname (e.g. execution) or display name "
    "(e.g. 'Execution').",
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

    # Validate closed-set filters up front so a typo errors instead of looking
    # like genuine zero coverage. A valid value with no matches still falls
    # through to the normal "No detections match".
    if engine and engine not in ALLOWED_ENGINES:
        raise click.ClickException(
            f"unknown engine {engine!r}. Valid: {', '.join(sorted(ALLOWED_ENGINES))}."
        )
    if status and status not in _STATUSES:
        raise click.ClickException(
            f"unknown status {status!r}. Valid: {', '.join(sorted(_STATUSES))}."
        )
    if stage and stage not in FORGE_STAGES:
        raise click.ClickException(
            f"unknown stage {stage!r}. Valid: {', '.join(FORGE_STAGES)}."
        )
    if want_tactic is not None:
        assert ref is not None  # loaded above whenever --tactic is set
        known = {_norm(sn) for sn in ref.tactics} | {_norm(d) for d in ref.tactics.values()}
        if want_tactic not in known:
            raise click.ClickException(
                f"unknown ATT&CK tactic {tactic!r} (ATT&CK {ref.attack_version}); "
                "see `adef attack info` for the current tactics."
            )

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
            "orphaned", "needs_review", "review_reasons", "rule_ref",
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
        flag_len = len(f" ⚠ {','.join(structural)}") if structural else 0
        if d.get("orphaned"):
            flag += " [red]orphaned[/red]"  # source rule gone from the repo
            flag_len += len(" orphaned")
        mitre = ",".join(d.get("mitre") or []) or "-"
        prefix = (
            f"  {d.get('id', '?')}  {d.get('stage', '?'):<8} {d.get('status', '?'):<10} "
            f"{d.get('platform', '?'):<15} {d.get('format', '?'):<22} {mitre:<12} "
        )
        # Truncate the title so each detection stays on ONE line — long in-house
        # titles otherwise soft-wrap to 3 lines and a 100-rule list is a wall of
        # text (E2E 2026-07-27). Budget = terminal width minus the fixed columns
        # and the (unstyled) flag; ellipsize past that.
        budget = console.width - len(prefix) - flag_len
        title = d.get("title", "")
        if budget > 1 and len(title) > budget:
            title = title[: budget - 1] + "…"
        console.print(f"{prefix}{title}{flag}", highlight=False)
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
    if record.get("orphaned"):
        console.print(
            f"  [red]{'orphaned':<15}[/red] source rule is gone from the repo "
            "(kept for its history; excluded from coverage)"
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
@click.option(
    "--remove",
    is_flag=True,
    help="Remove the listed technique IDs instead of adding them (the retag "
    "seam — Observe findings legitimately invalidate mappings). Emptying the "
    "mapping puts the record back on the no_mitre queue. To replace: "
    "tag-mitre D-X OLD --remove, then tag-mitre D-X NEW.",
)
def tag_mitre_cmd(
    detection_id: str, technique_ids: tuple[str, ...], workspace: Path | None, remove: bool
) -> None:
    """Add ATT&CK technique IDs to a catalog record (drains the no_mitre queue).

    IDs are validated against the shipped ATT&CK reference; an invalid ID
    aborts without writing. Writes only to ADEF's catalog record — never the
    source rule. Example: ``adef detection tag-mitre D-0007 T1547.001 T1055``.
    With ``--remove``, the listed IDs are removed instead.
    """
    from adef.core.tag import InvalidTechniqueError, tag_mitre, untag_mitre

    ws = _workspace_from(workspace)
    if remove:
        try:
            unresult = untag_mitre(ws, detection_id, list(technique_ids))
        except KeyError as exc:
            raise click.ClickException(f"{detection_id} is not in the catalog") from exc
        if unresult.removed:
            console.print(f"[green]Untagged[/green] {detection_id} -= {', '.join(unresult.removed)}")
        if unresult.not_present:
            console.print(f"  not present: {', '.join(unresult.not_present)}")
        if unresult.now_unmapped:
            console.print(
                "  [yellow]![/yellow] no MITRE mappings left — back on the "
                "no_mitre enrichment queue."
            )
        if not unresult.removed:
            console.print("Nothing to remove.")
        return
    try:
        result = tag_mitre(ws, detection_id, list(technique_ids))
    except KeyError as exc:
        # tag_mitre raises KeyError only for a missing detection; emit our own clean
        # message rather than the single-quote-wrapped KeyError repr.
        raise click.ClickException(f"{detection_id} is not in the catalog") from exc
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


@detection.command("search")
@click.argument("query")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Workspace path (defaults to current dir or ~/work/adef-workspace/).",
)
@click.option("--limit", default=10, show_default=True, help="Max results.")
def search(query: str, workspace: Path | None, limit: int) -> None:
    """Search detections by journal reasoning AND catalog metadata (BM25).

    Answers "have we looked at X before / do we cover Y?" across the *why*
    (journals) and the *what* (catalog records: title, MITRE, platform, query).
    """
    from adef.core.catalog import Catalog
    from adef.core.journal import Journal
    from adef.core.memory import MemoryIndex

    ws = _workspace_from(workspace)
    journals_dir = ws / "journals"

    # Map each detection id → its catalog record's searchable text.
    record_text: dict[str, str] = {
        det_id: _record_search_text(data)
        for det_id, _path, data in Catalog(ws).iter_records()
    }

    index = MemoryIndex(journals_dir=journals_dir)
    index.build(
        entries=list(Journal(journals_dir).iter_entries()),
        extra_text_for=lambda e: record_text.get(e.detection_id, ""),
    )
    hits = index.search(query, limit=limit)

    if not hits:
        console.print(f"[yellow]No detections match[/yellow] '{query}'.")
        return
    console.print(f"[bold]{len(hits)}[/bold] match(es) for '{query}':\n")
    for h in hits:
        console.print(
            f"  [bold]{h.detection_id}[/bold]  {h.title}  "
            f"[dim](stage={h.current_stage}, score={h.score})[/dim]"
        )
        if h.snippet:
            console.print(f"    [dim]{h.snippet}[/dim]", highlight=False)


__all__ = ["detection"]
