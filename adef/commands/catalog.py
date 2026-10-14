"""``adef catalog`` — turn an existing detection repo into ADEF's catalog.

Point ADEF at a directory of detection rules (Sigma YAML, Splunk ESCU /
``savedsearches.conf``, Panther, ``.kql``, ``.sql``,
``.cql``, plus any format taught via an extraction profile). ADEF walks the repo
read-only (it never pulls from any API — export the rules, then point at them),
catalogs each
rule into ``catalog/<platform>/D-XXXX-<slug>.yml``, creates a paired skeleton
journal, and regenerates ``catalog/INDEX.yml``.

Infer-and-flag: cataloging never prompts. Rules whose platform/MITRE can't be
inferred are catalogued with ``needs_review: true`` for later correction. The
user's repo is never modified.

Profile seams:

- User profiles under ``<workspace>/config/profiles/`` are loaded automatically
  and checked before built-in recognizers.
- ``--profile <yml>`` loads one *candidate* profile ahead of everything, and
  the dry-run report includes its per-field extraction rates — the scoreboard
  the catalog-onboarding skill uses to validate agent-drafted profiles.
- ``--report json`` emits a machine-readable outcome report (implies
  ``--dry-run``), including UNCLAIMED files for clustering.
"""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape as _escape_markup

from adef.commands._render import cell_width as _cell_width
from adef.commands._render import fit as _fit
from adef.core.catalog import Catalog, CatalogError, record_from_discovered, record_path
from adef.core.journal import Journal
from adef.core.profiles import Profile, ProfileError, load_profile, load_user_profiles
from adef.core.rule_discovery import (
    NOT_A_RULE,
    UNCLAIMED,
    FileOutcome,
    finalize_review,
    safe_platform,
    shape_literals,
    structural_reasons,
    walk_outcomes,
)
from adef.core.workspace import resolve_workspace as _resolve_workspace

console = Console()

# Fields whose extraction rates the --profile scoreboard reports.
_RATE_FIELDS = ("title", "query", "mitre", "uuid", "data_source", "platform")


def _inherit_platforms(discovered: list, ws: Path) -> int:
    """Inherit platform from scoped declarations.

    A rule with no platform whose literals (data_source + shape literals)
    match declared sources inherits their platform when it's unambiguous —
    most-specific match wins, same semantics as ``schema check``. Declaring
    your data makes your catalog cleaner. Returns how many rules resolved.
    """
    from adef.core.declaration import address_literals, read_schema_v2

    schema_dir = ws / "schema"
    if not schema_dir.is_dir():
        return 0
    addressed_by: dict[str, set[str]] = {}
    platforms: dict[str, str] = {}
    for path in sorted(schema_dir.glob("*.yml")):
        data = read_schema_v2(path)
        if data:
            source = data.get("source")
            if not source:  # v2 but hand-edited/partial (no source) → skip, don't KeyError
                continue
            platforms[source] = str(data.get("platform") or "")
            for literal in address_literals(data):
                addressed_by.setdefault(literal, set()).add(source)
    if not addressed_by:
        return 0

    resolved = 0
    for disc in discovered:
        if disc.platform:
            continue
        literals = {disc.data_source} - {""}
        literals.update(shape_literals(disc.query_text, disc.query_language))
        counts: dict[str, int] = {}
        for literal in literals:
            for source in addressed_by.get(literal, ()):
                counts[source] = counts.get(source, 0) + 1
        if not counts:
            continue
        best = max(counts.values())
        candidates = {platforms[s] for s, n in counts.items() if n == best} - {""}
        if len(candidates) == 1:  # unambiguous only — never guess
            # Through `safe_platform` because this becomes a directory name and
            # the declaration's `platform` is free text the user wrote: `Windows`
            # or `Windows Server` reached `record_path` verbatim and refused the
            # *entire* repo — `--dry-run` included, since the path pre-flight runs
            # before the report. Unusable means the inheritance simply didn't
            # happen: `disc.platform` stays empty, `no_platform` stands, and the
            # record goes to the `multi-platform` bucket for a human to resolve,
            # which is where it was before this pass ran.
            inherited = safe_platform(candidates.pop())
            if inherited is None:
                continue
            disc.platform = inherited
            finalize_review(
                disc, malformed="malformed" in disc.review_reasons, workspace=ws
            )
            resolved += 1
    return resolved


# Top-level keys that mark an unclaimed YAML doc as *rule-shaped* — it carries
# detection logic, so "teach ADEF your format" is the right advice. CI workflows
# (jobs/permissions/env), policies, and schema docs have none of these, so the
# nudge shouldn't count them as detections.
_RULE_SHAPE_KEYS = frozenset({"detection", "query", "search", "rule", "logic"})


def _rule_shaped_unclaimed(outcomes: list[FileOutcome]) -> int:
    """Count UNCLAIMED files that look like detections, not generic config."""
    return sum(
        1
        for oc in outcomes
        if oc.outcome == UNCLAIMED
        and _RULE_SHAPE_KEYS.intersection((*oc.top_level_keys, *oc.record_keys))
    )


def _print_unclaimed_nudge(unclaimed: int, claimed: int = 0) -> None:
    """Nudge toward profile authoring for unrecognized files.

    ``unclaimed`` is the *rule-shaped* unclaimed count (see
    ``_rule_shaped_unclaimed``) — CI/policy/schema YAML is excluded so the
    ratio names in-house detections, not scaffolding. Escalates when those
    files are at least half the rule-relevant repo — ``unclaimed >= claimed``,
    so an all-unclaimed repo qualifies and an empty one is rejected by the
    ``total`` guard, not the ratio. At parity or above is where a bare catalog
    silently captures a fraction of the rules and "N rules would be catalogued"
    still reads like success. A repo in a format ADEF ships no recognizer for
    hits this on the first run. A quiet trailing line loses that; a loud one
    names the proportion.
    """
    total = unclaimed + claimed
    dominant = unclaimed >= claimed
    if dominant and total:
        console.print(
            f"  [bold yellow]⚠ Most of this repo was not recognized[/bold yellow] — "
            f"{unclaimed} of {total} rule-shaped files matched no recognizer or "
            "profile (likely an in-house format).\n"
            "  ADEF catalogs known formats (Sigma, Splunk ESCU, Panther, "
            "KQL/SQL/CQL) out of the box; teach it yours with an extraction profile."
        )
    else:
        console.print(
            f"  [yellow]{unclaimed} rule-shaped files were NOT catalogued[/yellow] — no "
            "recognizer or profile claims their format (likely in-house YAML)."
        )
    console.print(
        "  Cluster them by shape with `adef catalog <root> --dry-run --report json`; "
        "see docs/creating-extraction-profiles.md,\n"
        "  then validate a draft with `adef catalog <root> --dry-run --profile <draft.yml>`."
    )


def _field_rates(rules: list) -> dict[str, float]:
    """Fraction of profile-claimed rules with each field non-empty."""
    if not rules:
        return {f: 0.0 for f in _RATE_FIELDS}
    getters = {
        "title": lambda r: r.title,
        "query": lambda r: r.query_text,
        "mitre": lambda r: r.mitre,
        "uuid": lambda r: r.rule_uuid,
        "data_source": lambda r: r.data_source,
        "platform": lambda r: r.platform,
    }
    return {
        f: round(sum(1 for r in rules if getters[f](r)) / len(rules), 4)
        for f in _RATE_FIELDS
    }


def _build_report(
    rule_root: Path,
    outcomes: list[FileOutcome],
    candidate: Profile | None,
    profile_errors: list[str],
) -> dict:
    """The machine-readable dry-run report (``--report json``)."""
    counts: dict[str, int] = {}
    by_format: dict[str, int] = {}
    files: list[dict] = []
    claimed_by_candidate: list = []

    for oc in outcomes:
        counts[oc.outcome] = counts.get(oc.outcome, 0) + 1
        if oc.format:
            by_format[oc.format] = by_format.get(oc.format, 0) + max(len(oc.rules), 1)
        if oc.outcome == NOT_A_RULE:
            continue  # counted, not listed — keeps the report proportionate
        entry: dict = {
            "path": str(oc.path.relative_to(Path(rule_root).expanduser())),
            "outcome": oc.outcome,
        }
        if oc.format:
            entry["format"] = oc.format
        if oc.outcome == UNCLAIMED:
            entry["top_level_keys"] = list(oc.top_level_keys)
            if oc.records_path:
                entry["records_path"] = oc.records_path
                entry["record_keys"] = list(oc.record_keys)
        if oc.rules:
            entry["needs_review"] = any(r.needs_review for r in oc.rules)
            reasons = sorted({reason for r in oc.rules for reason in r.review_reasons})
            if reasons:
                entry["review_reasons"] = reasons
            missing = [
                f
                for f in _RATE_FIELDS
                if not all(
                    {
                        "title": r.title,
                        "query": r.query_text,
                        "mitre": r.mitre,
                        "uuid": r.rule_uuid,
                        "data_source": r.data_source,
                        "platform": r.platform,
                    }[f]
                    for r in oc.rules
                )
            ]
            if missing:
                entry["missing_fields"] = missing
        files.append(entry)
        if candidate is not None and oc.format == candidate.name:
            claimed_by_candidate.extend(oc.rules)

    report: dict = {
        "rule_root": str(Path(rule_root).expanduser().resolve()),
        "counts": counts,
        "by_format": by_format,
        "files": files,
    }
    if profile_errors:
        report["profile_errors"] = profile_errors
    if candidate is not None:
        report["profile"] = {
            "name": candidate.name,
            "claimed": len(claimed_by_candidate),
            "field_rates": _field_rates(claimed_by_candidate),
        }
    return report


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
@click.option(
    "--report",
    "report_format",
    type=click.Choice(["json"]),
    default=None,
    help="Emit a machine-readable outcome report. Implies --dry-run: NOTHING "
    "is catalogued. Writes to stdout; use -o to write a file.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the --report json to this file instead of stdout.",
)
@click.option(
    "--profile",
    "profile_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Candidate extraction profile to validate (checked before all others; "
    "dry-run report includes its per-field extraction rates).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Catalog even if some rules are already in the workspace (mints duplicate "
    "records). Normally a re-catalog is refused — use `adef sync` to reconcile.",
)
def catalog(
    rule_root: Path,
    workspace: Path | None,
    dry_run: bool,
    report_format: str | None,
    output_path: Path | None,
    profile_path: Path | None,
    force: bool,
) -> None:
    """Catalog every detection rule under RULE_ROOT into the ADEF workspace."""
    ws = _resolve_workspace(workspace)
    if output_path is not None and report_format is None:
        raise click.ClickException("-o/--output requires --report json")
    if report_format:
        dry_run = True

    # Candidate profile (--profile) first, then user profiles — both ahead of
    # built-in recognizers. A broken user profile is reported, never fatal.
    candidate: Profile | None = None
    if profile_path is not None:
        try:
            candidate = load_profile(profile_path)
        except ProfileError as exc:
            raise click.ClickException(f"invalid profile: {exc}") from exc
    user_profiles, profile_errors = load_user_profiles(ws)
    for err in profile_errors:
        console.print(f"[yellow]Skipping broken profile:[/yellow] {_escape_markup(str(err))}", highlight=False)
    active_profiles = ([candidate] if candidate else []) + user_profiles

    outcomes = list(walk_outcomes(rule_root, active_profiles, ws))
    discovered = [rule for oc in outcomes for rule in oc.rules]
    inherited = _inherit_platforms(discovered, ws)

    if report_format == "json":
        report = _build_report(rule_root, outcomes, candidate, profile_errors)
        # The report is a preview — say so IN the data, not just the help text.
        report["dry_run"] = True
        report["written"] = 0
        rendered = json.dumps(report, indent=2)
        if output_path is not None:
            output_path.write_text(rendered + "\n", encoding="utf-8")
            # click.echo: paths must never soft-wrap (they get copy-pasted)
            click.echo(f"Report → {output_path}")
        else:
            click.echo(rendered)
        # stderr: visible on the terminal, never corrupts piped/parsed stdout.
        click.echo(
            "--report implies --dry-run: nothing was catalogued. "
            f"Run `adef catalog {rule_root}` (no flags) to write.",
            err=True,
        )
        return

    unclaimed = _rule_shaped_unclaimed(outcomes)
    if not discovered:
        console.print(f"[yellow]No detection rules found under[/yellow] {_escape_markup(str(rule_root))}")
        if unclaimed:
            _print_unclaimed_nudge(unclaimed, claimed=0)
        return

    cat = Catalog(ws)

    # Re-catalog guard: if some of these rules are ALREADY in
    # the workspace, minting fresh D-XXXX records would silently duplicate them.
    # That's what `adef sync` is for. A genuinely new repo (no overlap) still
    # appends cleanly. --force overrides; --dry-run always previews.
    existing = [data for _id, _path, data in cat.iter_records()]
    if existing and not dry_run:
        from adef.core.reconcile import Action, reconcile

        plan = reconcile(existing, discovered, rule_root=rule_root)
        already = sum(1 for e in plan if e.action in (Action.UNCHANGED, Action.MODIFIED))
        if already and not force:
            raise click.ClickException(
                f"{already} of these rules are already catalogued in {ws}.\n"
                f"  Re-cataloging would mint duplicate records — use "
                f"`adef sync {rule_root}` to reconcile changes instead,\n"
                f"  or `adef catalog {rule_root} --force` to add them anyway."
            )
        if already and force:
            # Proceed, but be honest about the consequence: --force mints fresh IDs,
            # so a later `sync` sees the prior copies as source-less → orphaned.
            console.print(
                f"[yellow]--force:[/yellow] {already} rule(s) already catalogued — "
                f"minting duplicate records with fresh IDs.\n"
                f"  A later `adef sync {_escape_markup(str(rule_root))}` will flag the prior copies as "
                f"orphaned; run `adef sync {_escape_markup(str(rule_root))}` instead to update in place."
            )

    journal = Journal(ws / "journals")

    # One HEAD SHA for the whole run — the sync staleness base (empty if the
    # rule root isn't a git work tree; sync falls back to per-file hashing).
    from adef.core.catalog import git_head_sha

    catalog_sha = git_head_sha(rule_root)

    next_idx = int(max(cat.max_index(), cat.journals_max_index())) + 1
    planned: list = []
    for disc in discovered:
        detection_id = f"D-{next_idx:04d}"
        planned.append(
            record_from_discovered(
                detection_id, disc, workspace=ws, rule_root=rule_root,
                catalog_sha=catalog_sha,
            )
        )
        next_idx += 1

    # Headline count = structural reasons only; MITRE gaps are the enrichment
    # queue, reported separately.
    needs_review = sum(1 for r in planned if structural_reasons(r.review_reasons))
    mitre_gaps = sum(1 for r in planned if "no_mitre" in r.review_reasons)

    # Every planned path checked before the first write — and before the dry-run
    # report, so a dry run can't say "N rules would be catalogued" for a plan the
    # real run then refuses. `record_path` is pure, so vetting the whole plan up
    # front is free: a platform lifted out of a rule by a user profile's
    # `platform_path` is arbitrary text, so a refusal on rule 400 would otherwise
    # leave 399 records on disk with `rebuild_index` never reached. A stale INDEX
    # over a half-written tree is the failure the guard exists to prevent, not a
    # smaller version of it. Same shape as `gates.import_gates`, whose dry run
    # validates paths too.
    try:
        for rec in planned:
            record_path(cat.directory, rec)
    except CatalogError as exc:
        raise click.ClickException(str(exc)) from exc

    if dry_run:
        console.print("[bold]Dry run[/bold] — nothing will be written.\n")
        # Collapse mass-flag noise: a corpus where one reason dominates (ESCU:
        # 1,469 × no_platform) shows a few examples per group, not every row.
        groups: dict[tuple[str, ...], list] = {}
        for rec in planned:
            groups.setdefault(tuple(structural_reasons(rec.review_reasons)), []).append(rec)
        sample = 5
        for reasons, recs in groups.items():
            flag = f" [yellow]({', '.join(reasons)})[/yellow]" if reasons else ""
            collapse = len(recs) > 2 * sample
            for rec in recs[:sample] if collapse else recs:
                # One line per rule, with the flag kept and everything else cut
                # to fit around it. Upstream titles run well past 80 chars, and
                # left to Rich two things went wrong: the row soft-wrapped (so a
                # preview of a 111-rule corpus read as twice as many rules as it
                # planned to write), and the trailing `(no_platform)` was the
                # first thing trimmed — turning the rules that need attention
                # into the ones that look fine. Same fitting rule as
                # `detection list`, which is why it lives in `_render`.
                head = f"  {rec.id}  {rec.platform:<14} {rec.format:<6} "
                plain_flag = f" ({', '.join(reasons)})" if reasons else ""
                row = _fit(head + rec.title, console.width - _cell_width(plain_flag))
                # Escape AFTER fitting, not before: a `[` costs one display cell
                # either way, so the raw string is the right thing to measure,
                # and escaping only inserts backslashes Rich doesn't render. The
                # title is upstream free text — a rule literally titled
                # "[bold red]LSASS[/]" otherwise styled the row and ate 14 cells
                # of budget that never appeared on screen, and one ending in
                # `[/yellow]` would close the review flag's own styling.
                console.print(
                    f"{_escape_markup(row)}{flag}",
                    highlight=False,
                    no_wrap=True,
                    overflow="ellipsis",
                )
            if collapse:
                label = ", ".join(reasons) if reasons else "no flags"
                console.print(
                    f"  … and [bold]{len(recs) - sample}[/bold] more like these "
                    f"({label}; full list: --report json)"
                )
        unclaimed = _rule_shaped_unclaimed(outcomes)
        # Ratio on the headline so the proportion can't be skimmed past — "N
        # would be catalogued" alone reads as success even when most of the
        # repo went unrecognized.
        unrecognized = (
            f"; [yellow]{unclaimed} file(s) unrecognized[/yellow]" if unclaimed else ""
        )
        console.print(
            f"\n[bold]{len(planned)}[/bold] rules would be catalogued "
            f"([yellow]{needs_review}[/yellow] need review){unrecognized}. "
            "Dry run — nothing written."
        )
        if candidate is not None:
            claimed = [r for r in discovered if r.format == candidate.name]
            rates = _field_rates(claimed)
            console.print(
                f"  Profile [bold]{_escape_markup(str(candidate.name))}[/bold] claimed "
                f"{len(claimed)} rules; "
                + ", ".join(f"{f} {rates[f]:.0%}" for f in _RATE_FIELDS)
            )
        if unclaimed:
            _print_unclaimed_nudge(unclaimed, claimed=len(planned))
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
                generated=True,
            )

    index_path = cat.rebuild_index()

    console.print(
        f"[green]Catalogued[/green] {len(planned)} rules into {_escape_markup(str(cat.directory))}"
    )
    console.print(f"  INDEX     → {_escape_markup(str(index_path))}")
    if unclaimed:
        _print_unclaimed_nudge(unclaimed, claimed=len(planned))
    if inherited:
        console.print(f"  [green]{inherited}[/green] platform(s) inherited from declared schemas.")
    if needs_review:
        console.print(
            f"  [yellow]{needs_review} need review[/yellow] "
            "(see `adef detection list --needs-review`)."
        )
    if mitre_gaps:
        console.print(
            f"  {mitre_gaps} without ATT&CK mapping "
            "(enrichment queue: `adef detection list --needs-review no_mitre`)."
        )


__all__ = ["catalog"]
