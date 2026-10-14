"""``adef detection`` — Click subgroup for the FORGE lifecycle commands.

Each subcommand:

- advances the journal's ``current_stage`` frontmatter atomically,
- appends a lean timestamped ``## [<ISO-8601>] Stage: <stage>`` block with the
  note (stage *guidance* lives once in the template's fill-in sections, not
  re-printed per block),
- (for ``refine``) invokes the orchestration chain (Similarity → Overlap → Verification).

The hard invariant — no path under any external rule directory is opened — is
enforced by the ``Journal`` class, not here.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.markup import escape as _escape_markup

from adef.commands._render import cell_width as _cell_width
from adef.commands._render import fit as _fit
from adef.commands._render import pad as _pad
from adef.core.corpus_text import record_mitre
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

# Per-column ceiling for the `detection list` table. Columns size to their own
# widest value, but one pathological value (a 60-char in-house format name, a
# detection mapped to a dozen techniques) must not starve the title column.
_MAX_COL_WIDTH = 20


def _fmt_score(score: Any) -> str:
    try:
        return f"{float(score):.3f}"
    except (TypeError, ValueError):
        return str(score)


def _fmt_fields_line(mitre: Any, platform: Any, data_source: Any) -> str:
    """Render mitre/platform/data_source as `key=value` pairs, escaped for
    markup, omitting any field that's empty rather than printing a blank
    `key=` label. Returns "" when none of the three have a value."""
    parts: list[str] = []
    mitre_ids = [str(m) for m in (mitre or []) if m]
    if mitre_ids:
        parts.append(f"mitre={_escape_markup(','.join(mitre_ids))}")
    if platform:
        parts.append(f"platform={_escape_markup(str(platform))}")
    if data_source:
        parts.append(f"data_source={_escape_markup(str(data_source))}")
    return "  ".join(parts)


def _print_similarity_shortlist(chain_result: dict[str, Any]) -> None:
    """Render the Similarity step's `agent`-mode shortlist to stdout.

    `agent` mode's entire reason to exist is handing the caller the target's
    and each candidate's query, MITRE, platform, and data source to judge —
    printing only "Refine chain complete" computed all of that and threw it
    away, forcing a re-read via `detection show` per candidate. This renders
    it instead.

    Degrades to printing nothing, never raises: the Similarity step may be
    absent from the summary, may have failed (`ok: False`, e.g. a
    journal-only detection with no catalog record yet), or — if an
    `ADEF_WRAPPER_RULE_SIMILARITY` override is configured — may have run a
    configured upstream class that returns some other shape or mode
    entirely. Any of those just means there is nothing to render here.
    """
    similarity = chain_result.get("similarity")
    if not isinstance(similarity, dict) or not similarity.get("ok"):
        return
    wrapper_envelope = similarity.get("result")
    if not isinstance(wrapper_envelope, dict):
        return
    payload = wrapper_envelope.get("result")
    if not isinstance(payload, dict) or payload.get("mode_used") != "agent":
        return
    target = payload.get("target")
    candidates = payload.get("candidates")
    if not isinstance(target, dict) or not isinstance(candidates, list):
        return

    def _print_one(
        label: str, det_id: Any, title: Any, query: Any, mitre: Any, platform: Any,
        data_source: Any, score: Any = None, shared_fields: Any = None, field_score: Any = None,
    ) -> None:
        # `det_id`/`title` come from catalog data, not a trusted literal — escape
        # before interpolating into a markup-enabled string so a query/title
        # containing "[...]" (common: array indices, regex classes) can't be
        # misread as a Rich style tag or break out of the `[bold]`/`[dim]` spans.
        header = f"  [bold]{label}[/bold]  {_escape_markup(str(det_id))}  {_escape_markup(str(title))}"
        if score is not None:
            # The BM25 score, named: the list is in FUSED order (BM25 + field
            # pass), so an unnamed score column read as the list being unsorted.
            header += f"  [dim](bm25={_escape_markup(_fmt_score(score))})[/dim]"
        # `soft_wrap=True` on every line below: this output is read as text (by
        # an agent, or piped/redirected), not just displayed in a terminal —
        # Rich's default wrap inserts a literal newline once a line crosses the
        # console width, silently splitting one logical line into two.
        console.print(header, highlight=False, soft_wrap=True)
        # Technique/platform/data-source alignment is usually the first thing a
        # reader checks before reading the full query — mitre/platform/data_source
        # are already in the payload (and already in the journal render); this is
        # the one place that was still dropping them.
        fields_line = _fmt_fields_line(mitre, platform, data_source)
        if fields_line:
            console.print(f"    [dim]{fields_line}[/dim]", highlight=False, soft_wrap=True)
        # Why a field-set match is on the list at all — a cross-language
        # duplicate shares no words, so without this it reads as a stray.
        if shared_fields:
            label = f"shared fields (field_score={_fmt_score(field_score)})" if field_score is not None else "shared fields"
            console.print(
                f"    [dim]{_escape_markup(label)}: {_escape_markup(', '.join(map(str, shared_fields)))}[/dim]",
                highlight=False, soft_wrap=True,
            )
        # The query has no intended styling at all — disable markup entirely
        # rather than escape line-by-line.
        for line in str(query or "").splitlines() or [""]:
            console.print(f"    {line}", highlight=False, markup=False, soft_wrap=True)

    console.print("\n[bold]Similarity shortlist[/bold] (agent mode — you rank; numbered in fused order):")
    _print_one("target", payload.get("detection_id", ""), target.get("title", ""),
               target.get("query", ""), target.get("mitre"), target.get("platform"),
               target.get("data_source"))
    rank = 0
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        rank += 1
        # `score` is the BM25 value; a field-only match has none (bm25_score is
        # None), and printing its placeholder 0.0 would read as "no match".
        score = candidate.get("score") if candidate.get("bm25_score", 0) is not None else None
        _print_one(f"candidate #{rank}", candidate.get("detection_id", ""), candidate.get("title", ""),
                   candidate.get("query", ""), candidate.get("mitre"), candidate.get("platform"),
                   candidate.get("data_source"), score,
                   candidate.get("shared_fields"), candidate.get("field_score"))


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
    # clobber the existing catalog record on write.
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
        f"[green]Created[/green] {_escape_markup(str(journal.path.relative_to(journals_dir.parent)))} at Find stage."
    )

    if record is not None:
        cat = Catalog(journals_dir.parent)
        rec_path = cat.write(record)
        cat.rebuild_index()
        console.print(
            f"[green]Scaffolded[/green] draft rule {_escape_markup(str(rec_path.relative_to(journals_dir.parent)))} "
            f"grounded in schema [cyan]{_escape_markup(str(source))}[/cyan] "
            f"({_escape_markup(str(record.platform))} / {_escape_markup(str(record.query_language))})."
        )
        if not record.query:
            # Be honest: the starter query is empty (schema has no scope literals,
            # or an unmodelled query language) — nothing was actually "grounded".
            console.print(
                f"  [yellow]note:[/yellow] schema [cyan]{_escape_markup(str(source))}[/cyan] has no scope "
                "literals, so the starter query is empty — you'll write it from scratch."
            )
        console.print(
            "  Next: fill in the query + author the Find context in the journal "
            "(the AI assistant / mitre-tagger can help)."
        )


# Cause -> (what happened, what to do about it). Printed only when the field
# pass ran below full strength; a working feature does not announce itself.
_FIELD_MATCHING_HELP = {
    "unmatched": (
        "no declared source addresses this rule's data source",
        "run `adef schema ingest <declaration>`, then `adef schema check` to see which rules are still unmatched",
    ),
    "declared_no_aliases": (
        "the matched source declares no field aliases, so cross-language matching is inactive",
        "add `aliases` to that source's declared fields — `adef schema check` reports alias coverage",
    ),
    "unparseable": (
        "no fields could be read from this rule: its format has no field extractor, "
        "it has no query, the query is malformed, or it has no field conditions at all",
        "unsupported format: author an extraction profile (`adef profile lint` validates it); "
        "malformed query: fix it at the source, then `adef sync`; no field conditions "
        "(e.g. keyword-only Sigma): nothing to do, keyword search still covers it",
    ),
}


def _print_field_matching(chain_result: dict[str, Any]) -> None:
    """Tell the user when field-set retrieval was skipped, and how to fix it.

    Note the double unwrap. `chain_result["similarity"]["result"]` is the
    WRAPPER's envelope — `RuleSimilarityWrapper.run` returns
    `{"detection_id": ..., "result": <the agent's dict>}` — so the agent's own
    keys are one level deeper. Reading only one level yields None and this
    prints nothing, silently, which is exactly the failure this function
    exists to prevent.
    """
    step = (chain_result or {}).get("similarity") or {}
    envelope = step.get("result")
    inner = envelope.get("result") if isinstance(envelope, dict) else None
    state = inner.get("field_matching") if isinstance(inner, dict) else None
    help_text = _FIELD_MATCHING_HELP.get(str(state))
    if not help_text:
        return
    cause, remedy = help_text
    console.print(f"  [yellow]field matching: {state} (field pass skipped)[/yellow] — {cause}")
    console.print(f"    → {remedy}")


_FIELDS_NOT_RUN_HELP = {
    "no_schemas_declared": "no schemas are declared — `adef schema ingest <declaration>`",
    "no_schema_matches": "no declared schema addresses this rule's data source",
    "unparseable_query": "ADEF couldn't read this query's fields",
}


def _print_verification(chain_result: dict[str, Any]) -> None:
    """One line when Verification didn't fully pass, so "nothing checked"
    never reads as a pass. Same double unwrap as `_print_field_matching`."""
    step = (chain_result or {}).get("verification") or {}
    envelope = step.get("result")
    inner = envelope.get("result") if isinstance(envelope, dict) else None
    if not isinstance(inner, dict):
        return
    status = inner.get("status")
    if status == "partial":
        why = _FIELDS_NOT_RUN_HELP.get(str(inner.get("fields_not_run_reason")), "field check skipped")
        console.print(f"  [yellow]verification: partial — fields not checked[/yellow] ({why})")
    elif status == "failed":
        # Every failed check, so one pass fixes them all.
        details = []
        if inner.get("engine_error"):
            details.append(str(inner["engine_error"]))
        if inner.get("missing_schema_fields"):
            details.append("fields missing from schema: " + ", ".join(inner["missing_schema_fields"]))
        console.print(f"  [red]verification: failed[/red] — {_escape_markup('; '.join(details))}")


_SEVERITY_STYLE = {"high": "red", "medium": "yellow", "low": "cyan"}


def _print_chain_outcome(chain_result: dict[str, Any], label: str, steps: str) -> None:
    """Report a chain's completion, naming any step that failed.

    Both chains are deliberately non-aborting — a partial result is worth
    having — and both used to print an unconditional green "chain complete".
    So a step that blew up was invisible: its block in the journal says
    `error`, but on stdout the run looked clean, and the one place the user
    would notice is an empty summary, which is also exactly what
    `insufficient-data` looks like. Shared by `refine` and `evolve` because
    the failure was identical in both.
    """
    failed = [
        (name, str((outcome or {}).get("error") or "no detail"))
        for name, outcome in (chain_result or {}).items()
        if isinstance(outcome, dict) and not outcome.get("ok")
    ]
    if not failed:
        console.print(f"[green]{label} chain complete[/green] — {steps} appended.")
        return
    # Not "completed with…": that contains "<label> chain complete" as a
    # substring, so anything grepping for the success line — a test, a CI
    # check, a user's `| grep` — reads a partial run as a clean one.
    console.print(
        f"[yellow]{label} chain finished with {len(failed)} failed step(s)[/yellow] "
        f"— {steps}; the rest were appended."
    )
    for name, error in failed:
        console.print(f"  [red]{name} failed:[/red] {_escape_markup(error)}")


def _print_evolve_summary(chain_result: dict[str, Any]) -> None:
    """Put the Evolve chain's verdicts on stdout, not only in the journal.

    The recommendations are the reason to run the stage. Printing only
    "chain complete" makes the user open the journal to find out whether
    anything was recommended at all — and the most common answer,
    ``insufficient-data`` because no health was ever ingested, is precisely
    the one they need to see without going looking.
    """
    # Escaped on the way out even though today every rationale is literal text
    # plus a number format, and `kind`/`severity`/`verdict` are fixed
    # vocabularies — these are `str` fields on a recommendation dataclass, and
    # the obvious next rationale ("overlap 90% with D-0042 <title>") puts an
    # upstream rule title here. One escape at the sink beats a reviewer
    # re-deriving the whole provenance argument the next time one changes.
    tuning = ((chain_result or {}).get("tuning") or {}).get("result")
    for suggestion in getattr(tuning, "suggestions", []) or []:
        style = _SEVERITY_STYLE.get(suggestion.severity, "dim")
        console.print(
            f"  [{style}]{_escape_markup(str(suggestion.severity))}[/{style}] "
            f"[bold]{_escape_markup(str(suggestion.kind))}[/bold] "
            f"— {_escape_markup(str(suggestion.rationale))}"
        )

    deprecation = ((chain_result or {}).get("deprecation") or {}).get("result")
    verdict = getattr(deprecation, "verdict", None)
    if verdict:
        rationale = getattr(deprecation, "rationale", "")
        console.print(
            f"  verdict: [bold]{_escape_markup(str(verdict))}[/bold] "
            f"— {_escape_markup(str(rationale))}"
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
    @click.option(
        "--back",
        is_flag=True,
        help="Allow moving a detection back to an earlier stage (FORGE is a loop). "
        "Without it, a backward move is refused.",
    )
    def cmd(
        detection_id: str,
        workspace: Path | None,
        notes: tuple[str, ...],
        back: bool = False,
        chain: bool = False,
        similarity_mode: str = "bm25",
    ) -> None:
        # One note → plain line; several → a markdown bullet list.
        note = notes[0] if len(notes) == 1 else "\n".join(f"- {n}" for n in notes)
        journals_dir = workspace_journals_dir(workspace)
        journal = Journal(journals_dir)
        try:
            result = journal.advance_stage(
                detection_id=detection_id, stage=stage, note=note, allow_backward=back
            )
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
        # the record; leaving it behind made it lie (a detection
        # advanced to observe while its record stayed at find). Runs on the idempotent
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
            # every `refine --note` (duplicate WrapperUnavailable
            # triplets one minute apart).
            if chain or not result.was_idempotent:
                from adef.orchestration.refine_chain import run_refine_chain

                # `workspace` must be forwarded: every native Refine agent
                # resolves `workspace_journals_dir(None)` when not given one,
                # which would silently read a *different* catalog than the one
                # `--workspace` named.
                chain_result = run_refine_chain(journal=journal, detection_id=detection_id,
                                  workspace=workspace, similarity_mode=similarity_mode)
                _print_chain_outcome(
                    chain_result, "Refine", "Similarity → Overlap → Verification"
                )

                # Degradation must reach the user, not just the payload. It
                # rides in the result, which reaches the journal and agent-mode
                # stdout — but a user on the default bm25 mode would never see
                # it, and silent degradation in the default mode defeats the
                # point of reporting it at all.
                #
                # Printed BEFORE the shortlist on purpose: if field matching ran
                # degraded, that is context for reading the candidates, not a
                # footnote after them.
                _print_field_matching(chain_result)
                _print_verification(chain_result)
                if similarity_mode == "agent":
                    _print_similarity_shortlist(chain_result)
            else:
                # Say so when a mode was asked for and dropped — otherwise
                # `refine D-X --similarity-mode agent` on an already-refined
                # detection is a silent no-op that still looks like it ran.
                dropped = (
                    f" [yellow]--similarity-mode {similarity_mode} not applied[/yellow]"
                    if similarity_mode != "bm25" else ""
                )
                console.print(
                    f"  chain skipped (already at refine){dropped} — "
                    "re-run it with [bold]--chain[/bold]"
                )

        if stage == "evolve":
            # Same gating as Refine's, for the same reason: re-advancing to
            # evolve with `--note` must not append a fresh recommendation
            # triplet every time. `--chain` is the re-run door, and it is the
            # one you want here — tuning is iterative, and the point of
            # re-running is that `adef ingest` has since brought new numbers.
            if chain or not result.was_idempotent:
                from adef.orchestration.evolve_chain import run_evolve_chain

                # `workspace` forwarded for the same reason the Refine chain
                # forwards it: the health read resolves its own workspace when
                # not given one, which would read a *different* workspace than
                # `--workspace` named.
                evolve_result = run_evolve_chain(
                    journal=journal, detection_id=detection_id, workspace=workspace
                )
                _print_chain_outcome(
                    evolve_result, "Evolve", "Health → Tuning → Deprecation"
                )
                _print_evolve_summary(evolve_result)
            else:
                console.print(
                    "  chain skipped (already at evolve) — re-run it with "
                    "[bold]--chain[/bold]"
                )

    if stage == "evolve":
        cmd.params.append(
            click.Option(
                ["--chain"],
                is_flag=True,
                help="Re-run the Health → Tuning → Deprecation chain even if already "
                "at evolve (e.g. after `adef ingest` brought fresh numbers).",
            )
        )

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
# Browsing — list / show
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
    type=click.Choice(["authored", "catalogued", "promoted"]),
    default=None,
    help="Filter by origin: authored (created in ADEF), catalogued (from a repo), "
    "or promoted (imported from an ATHF GATES document).",
)
@click.option(
    "--needs-review",
    "needs_review",
    is_flag=False,
    flag_value="any",
    default=None,
    help="Only detections needing review. Bare flag = the reasons worth surfacing "
    "unprompted (malformed, external_logic, no_platform, invalid_mitre, "
    "gates_conditional, gates_time_box); pass a reason to filter it specifically "
    "(e.g. --needs-review no_mitre for the enrichment queue).",
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

    from adef.core.catalog import Catalog, declared_platforms, record_platforms
    from adef.core.rule_discovery import structural_reasons

    def _reasons(data: dict) -> list[str]:
        if "review_reasons" in data:
            return list(data.get("review_reasons") or [])
        # Pre-rework records: boolean only — treat as one opaque structural reason.
        return ["legacy"] if data.get("needs_review") else []

    # Tactics aren't stored on records — resolve them from each detection's
    # technique IDs via the ATT&CK reference. Only load the snapshot when a
    # caller actually needs tactics (the --tactic filter or JSON output).
    #
    # `ws` is resolved up here, ahead of the records loop that needs it, so the
    # reference comes from the same workspace: `--tactic` *omits* rows whose
    # technique the reference doesn't know, so reading the shipped snapshot
    # under `--workspace X` silently dropped detections mapped to a technique
    # added in the release the user had refreshed into X — and the
    # unknown-tactic error below cited that snapshot's version too.
    ws = _workspace_from(workspace)
    ref = None
    if tactic or report_format == "json":
        from adef.core.attack import attack_reference

        ref = attack_reference(ws)

    def _norm(value: str) -> str:
        # ATT&CK tactic shortnames are the lowercased, hyphenated display names,
        # so normalizing either input form to the same shape matches both.
        return value.strip().lower().replace(" ", "-").replace("_", "-")

    def _tactics_of(data: dict) -> list[str]:
        """Display names of the tactics this detection's techniques cover."""
        assert ref is not None  # only called once the snapshot is loaded
        display: list[str] = []
        for tid in record_mitre(data):
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

    records = []
    for det_id, _path, data in Catalog(ws).iter_records():
        # A cross-platform detection is bucketed `multi-platform` but declares the
        # platforms it actually covers, and `--platform windows` has to find it.
        if platform and platform not in record_platforms(data):
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
            "id", "title", "platform", "platforms", "engine", "format", "query_language",
            "data_source", "mitre", "status", "stage", "owner", "origin",
            "orphaned", "needs_review", "review_reasons", "rule_ref",
        )
        payload = []
        for d in records:
            row: dict = {k: d.get(k) for k in keys}
            # `platforms` is the one key above the record omits when empty (the
            # others are always written), so a straight `.get` reports `null` for
            # every single-platform detection — i.e. nearly all of them — and a
            # consumer iterating the array hits a type error instead of a no-op.
            row["platforms"] = declared_platforms(d)
            row["tactics"] = _tactics_of(d)  # derived, not stored
            payload.append(row)
        click.echo(_json.dumps(payload, indent=2))
        return

    if not records:
        console.print("[yellow]No detections match.[/yellow] (Run `adef catalog <rules>` first?)")
        return
    # Column widths come from the data, not fixed constants. `format` was padded
    # to 22 (for long in-house profile names) and `platform` to 15, so the fixed
    # columns ate 82 chars before the title started — on a 100-col terminal every
    # title ellipsized to "Bro…" even when the real widest value was 5 chars.
    # Each column now takes what its own widest value needs (floored at its
    # header, capped so one outlier can't starve the title), and the title gets
    # whatever is left.
    columns: tuple[tuple[str, Callable[[dict], str]], ...] = (
        ("ID", lambda d: str(d.get("id") or "?")),
        ("STAGE", lambda d: str(d.get("stage") or "?")),
        ("STATUS", lambda d: str(d.get("status") or "?")),
        ("PLATFORM", lambda d: str(d.get("platform") or "?")),
        ("FORMAT", lambda d: str(d.get("format") or "?")),
        ("ATT&CK", lambda d: ",".join(record_mitre(d)) or "-"),
    )
    cells = [[render(d) for _, render in columns] for d in records]
    # Cells, not characters, throughout — see `_render.pad`.
    #
    # ponytail: each column is capped independently, so six columns at
    # `_MAX_COL_WIDTH` can exceed a very narrow terminal and leave the title no
    # room at all — the row stays one line and keeps its flag (both tested), but
    # below roughly 60 columns the title is the part that disappears. Reflowing
    # the columns to reserve a title share means a redistribution pass with a
    # priority order, which is a lot of machinery for a terminal nobody reviews
    # a rule catalog in. Add it if 40-column output is ever a real complaint.
    widths = [
        min(
            max(_cell_width(name), *(_cell_width(cell_row[i]) for cell_row in cells)),
            _MAX_COL_WIDTH,
        )
        for i, (name, _) in enumerate(columns)
    ]

    # Header, so the columns are identifiable without consulting the docs. Fitted
    # like the rows below it — the column widths come from the data, so on a
    # narrow terminal the header overflows exactly when the rows do, and left to
    # Rich it wrapped "TITLE" onto a line of its own above the table.
    console.print(
        _fit(
            "  " + "  ".join(_pad(name, w) for (name, _), w in zip(columns, widths)) + "  TITLE",
            console.width,
        ),
        style="dim",
        highlight=False,
        no_wrap=True,
        overflow="ellipsis",
    )
    for d, cell_row in zip(records, cells):
        structural = structural_reasons(_reasons(d)) or (
            ("legacy",) if "legacy" in _reasons(d) else ()
        )
        flag = f" [yellow]⚠ {','.join(structural)}[/yellow]" if structural else ""
        flag_len = _cell_width(f" ⚠ {','.join(structural)}") if structural else 0
        if d.get("orphaned"):
            flag += " [red]orphaned[/red]"  # source rule gone from the repo
            flag_len += _cell_width(" orphaned")
        prefix = "  " + "  ".join(_pad(v, w) for v, w in zip(cell_row, widths)) + "  "
        # Fit the columns AND the title together, reserving the (unstyled) flag
        # width first, so each detection stays on ONE line — long in-house titles
        # otherwise soft-wrap to 3 lines and a 100-rule list is a wall of text.
        #
        # Reserving the flag is the whole point of the ordering: the flag is
        # what the row is asking you to act on, and a row whose flag got
        # trimmed away reads as a detection with nothing wrong with it. The
        # title is recoverable (`adef detection show`), a silently dropped
        # review flag is not. Cutting it here rather than letting Rich
        # ellipsize matters for the same reason — Rich trims from the right,
        # which is exactly where the flag sits. (`no_wrap` then stops Rich
        # soft-wrapping any residual overflow onto a second line.)
        #
        # Columns and title are fitted as one string, not title-only: six
        # columns at `_MAX_COL_WIDTH` are wider than an 80-column terminal all
        # by themselves, and trimming only the title there leaves the row still
        # over budget — with the flag, again, as the part Rich drops.
        #
        # Escaped AFTER fitting: a `[` costs one display cell either way, so the
        # raw string is the right thing to measure, and escaping only inserts
        # backslashes Rich doesn't render. `highlight=False` stops Rich styling
        # *its* guesses; it does nothing about markup the title itself contains,
        # and a title literally reading "[bold red]LSASS[/]" both styled the row
        # and consumed 14 cells of budget that never reached the screen.
        line = _fit(prefix + str(d.get("title", "")), console.width - flag_len)
        console.print(
            f"{_escape_markup(line)}{flag}",
            highlight=False,
            no_wrap=True,
            overflow="ellipsis",
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
    from adef.core.catalog import Catalog, declared_platforms

    ws = _workspace_from(workspace)
    record = None
    for det_id, _path, data in Catalog(ws).iter_records():
        if det_id == detection_id:
            record = data
            break
    if record is None:
        raise click.ClickException(f"{detection_id} not found in the catalog under {ws}")

    console.print(f"[bold]{_escape_markup(str(record.get('id')))}  {_escape_markup(str(record.get('title', '')))}[/bold]")
    for key in ("platform", "format", "query_language", "data_source", "kind", "engine"):
        if record.get(key):
            console.print(f"  {key:<15} {_escape_markup(str(record[key]))}")
    # Only present on a cross-platform detection, where `platform` is the bucket.
    if declared := declared_platforms(record):
        console.print(f"  {'platforms':<15} {_escape_markup(', '.join(declared))}")
    mitre_ids = record_mitre(record)
    console.print(f"  {'mitre':<15} {_escape_markup(', '.join(mitre_ids) or '-')}")
    if mitre_ids:  # tactics are derived from the technique IDs, not stored on the record
        from adef.core.attack import attack_reference

        ref = attack_reference(ws)  # the workspace we found the record in
        tactics: list[str] = []
        for tid in mitre_ids:
            names = ref.tactics_for(tid)
            if not names and "." in tid:  # sub-technique w/o its own tactics → parent
                names = ref.tactics_for(tid.split(".")[0])
            for name in names:
                if name not in tactics:
                    tactics.append(name)
        if tactics:
            console.print(f"  {'tactics':<15} {_escape_markup(', '.join(tactics))}")
    console.print(
        f"  {'lifecycle':<15} stage={_escape_markup(str(record.get('stage')))} "
        f"status={_escape_markup(str(record.get('status')))}"
        + (f" owner={_escape_markup(str(record['owner']))}" if record.get("owner") else "")
    )
    if record.get("orphaned"):
        console.print(
            f"  [red]{'orphaned':<15}[/red] source rule is gone from the repo "
            "(kept for its history; excluded from coverage)"
        )
    console.print(
        f"  {'origin':<15} {_escape_markup(str(record.get('origin') or 'catalogued'))}"
    )
    if record.get("needs_review"):
        reasons = _escape_markup(
            ", ".join(record.get("review_reasons") or []) or "unspecified (legacy record)"
        )
        # Pad inside the markup, as `orphaned`/`support` above do — a hardcoded
        # gap here left this one label a column short of every other field.
        console.print(f"  [yellow]{'needs_review':<15}[/yellow] {reasons}")
    if record.get("rule_ref"):
        console.print(f"  {'source':<15} {_escape_markup(str(record['rule_ref']))}")
    support = record.get("support")
    if support and support != "supported":
        console.print(
            f"  [yellow]{'support':<15}[/yellow] {_escape_markup(str(support))} "
            "(format recognized; logic not parsed — e.g. external file)"
        )
    if record.get("query"):
        console.print("\n[bold]Query[/bold]")
        # `markup=False`, matching the agent-mode shortlist above: the query has
        # no intended styling, and `escape()` is wrong here specifically. It
        # appends a backslash when its input *ends* with one — so markup can't
        # swallow a tag the caller appends next — and with nothing appended, the
        # extra one is simply printed: an SPL continuation line ending in `\`
        # came out `\\`, which is not valid SPL in a block people copy-paste.
        for line in record["query"].splitlines():
            console.print(f"  {line}", highlight=False, markup=False)

    journal_path = ws / "journals" / f"{detection_id}.md"
    if journal_path.is_file():
        console.print(f"\n[bold]Journal[/bold]  {_escape_markup(str(journal_path))}")
        stages = [
            line.strip()
            for line in journal_path.read_text(encoding="utf-8").splitlines()
            if line.startswith("## [")
        ]
        for entry in stages[-3:]:
            console.print(f"  {_escape_markup(str(entry))}")
    else:
        console.print("\n[yellow]No paired journal.[/yellow]")


#: Both tag and untag end in `rebuild_index()`, and untag pre-flights it, so
#: both can fail on something neither validates: a truncated
#: `attack/enterprise.json`, or a *second*, unrelated record hand-edited to
#: `engine: [sigma]`. Uncaught, that was a raw `TypeError` traceback with
#: nothing saying whether the record had been written. Says "may not" rather
#: than "did not" deliberately: untag's pre-flight does guarantee nothing was
#: written, but this also catches a failure in the write itself, where the
#: honest answer is that `adef doctor` knows and this handler doesn't.
_TAG_FAILED = (
    "{what} failed — {exc}\nThe record and catalog/INDEX.yml may not agree; "
    "run `adef doctor` for the state."
)


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
        except Exception as exc:  # noqa: BLE001 — a message, not a traceback
            raise click.ClickException(_TAG_FAILED.format(what="Untag", exc=exc)) from exc
        if unresult.removed:
            console.print(f"[green]Untagged[/green] {detection_id} -= {_escape_markup(', '.join(unresult.removed))}")
        if unresult.not_present:
            console.print(f"  not present: {_escape_markup(', '.join(unresult.not_present))}")
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
    except Exception as exc:  # noqa: BLE001 — a message, not a traceback
        raise click.ClickException(_TAG_FAILED.format(what="Tag", exc=exc)) from exc

    if result.added:
        console.print(f"[green]Tagged[/green] {detection_id} += {_escape_markup(', '.join(result.added))}")
    if result.already_present:
        console.print(f"  already present: {_escape_markup(', '.join(result.already_present))}")
    for revoked_id, replacement in result.revoked.items():
        console.print(
            f"  [yellow]note[/yellow] {_escape_markup(str(revoked_id))} is revoked → consider {_escape_markup(str(replacement))}"
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
    from adef.core.corpus import build_corpus
    from adef.core.memory import MemoryIndex

    ws = _workspace_from(workspace)
    index = MemoryIndex()
    index.build(build_corpus(ws))
    hits = index.search(query, limit=limit)

    if not hits:
        console.print(f"[yellow]No detections match[/yellow] '{_escape_markup(str(query))}'.")
        return
    console.print(f"[bold]{len(hits)}[/bold] match(es) for '{_escape_markup(str(query))}':\n")
    for h in hits:
        console.print(
            f"  [bold]{h.detection_id}[/bold]  {_escape_markup(str(h.title))}  "
            f"[dim](stage={h.current_stage}, score={h.score})[/dim]"
        )
        if h.snippet:
            console.print(f"    [dim]{_escape_markup(str(h.snippet))}[/dim]", highlight=False)


__all__ = ["detection"]
