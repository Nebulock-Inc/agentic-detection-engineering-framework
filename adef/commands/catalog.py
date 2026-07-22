"""``adef catalog`` — turn an existing detection repo into ADEF's catalog.

Point ADEF at a directory of detection rules (Sigma YAML, Splunk ESCU /
``savedsearches.conf``, Panther, ``.kql``, ``.sql``, ``.cql``, plus any format
taught via an extraction profile). ADEF walks the repo read-only, catalogs each
rule into ``catalog/<platform>/D-XXXX-<slug>.yml``, creates a paired skeleton
journal, and regenerates ``catalog/INDEX.yml``.

Infer-and-flag: cataloging never prompts. Rules whose platform/MITRE can't be
inferred are catalogued with ``needs_review: true`` for later correction. The
user's repo is never modified.

Profile seams (ISA 2026-07-20):

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
import os
from pathlib import Path

import click
from rich.console import Console

from adef.core.catalog import Catalog, record_from_discovered
from adef.core.journal import Journal
from adef.core.profiles import Profile, ProfileError, load_profile, load_user_profiles
from adef.core.rule_discovery import (
    NOT_A_RULE,
    UNCLAIMED,
    FileOutcome,
    finalize_review,
    shape_literals,
    structural_reasons,
    walk_outcomes,
)

console = Console()

# Fields whose extraction rates the --profile scoreboard reports.
_RATE_FIELDS = ("title", "query", "mitre", "uuid", "data_source", "platform")


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


def _inherit_platforms(discovered: list, ws: Path) -> int:
    """Inherit platform from scoped declarations (ISA 2026-07-21).

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
            platforms[data["source"]] = str(data.get("platform") or "")
            for literal in address_literals(data):
                addressed_by.setdefault(literal, set()).add(data["source"])
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
            disc.platform = candidates.pop()
            finalize_review(disc, malformed="malformed" in disc.review_reasons)
            resolved += 1
    return resolved


def _print_unclaimed_nudge(unclaimed: int) -> None:
    console.print(
        f"  [yellow]{unclaimed} structured files were NOT catalogued[/yellow] — no "
        "recognizer or profile claims their format (likely in-house YAML).\n"
        "  Teach ADEF the format with an extraction profile: "
        "`adef catalog <root> --dry-run --report json` clusters them by shape;\n"
        "  see docs/creating-extraction-profiles.md, then validate with "
        "`adef catalog <root> --dry-run --profile <draft.yml>`."
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
    help="Emit a machine-readable outcome report (implies --dry-run).",
)
@click.option(
    "--profile",
    "profile_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Candidate extraction profile to validate (checked before all others; "
    "dry-run report includes its per-field extraction rates).",
)
def catalog(
    rule_root: Path,
    workspace: Path | None,
    dry_run: bool,
    report_format: str | None,
    profile_path: Path | None,
) -> None:
    """Catalog every detection rule under RULE_ROOT into the ADEF workspace."""
    ws = _resolve_workspace(workspace)
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
        console.print(f"[yellow]Skipping broken profile:[/yellow] {err}", highlight=False)
    active_profiles = ([candidate] if candidate else []) + user_profiles

    outcomes = list(walk_outcomes(rule_root, active_profiles))
    discovered = [rule for oc in outcomes for rule in oc.rules]
    inherited = _inherit_platforms(discovered, ws)

    if report_format == "json":
        report = _build_report(rule_root, outcomes, candidate, profile_errors)
        click.echo(json.dumps(report, indent=2))
        return

    unclaimed = sum(1 for oc in outcomes if oc.outcome == UNCLAIMED)
    if not discovered:
        console.print(f"[yellow]No detection rules found under[/yellow] {rule_root}")
        if unclaimed:
            _print_unclaimed_nudge(unclaimed)
        return

    cat = Catalog(ws)
    journal = Journal(ws / "journals")

    # One HEAD SHA for the whole run — the sync staleness base (empty if the
    # rule root isn't a git work tree; sync falls back to per-file hashing).
    from adef.core.catalog import git_head_sha

    catalog_sha = git_head_sha(rule_root)

    next_idx = int(max(cat.max_index(), cat._journals_max_index())) + 1
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
    # queue, reported separately (ISA 2026-07-21).
    needs_review = sum(1 for r in planned if structural_reasons(r.review_reasons))
    mitre_gaps = sum(1 for r in planned if "no_mitre" in r.review_reasons)

    if dry_run:
        for rec in planned:
            structural = structural_reasons(rec.review_reasons)
            flag = f" [yellow]({', '.join(structural)})[/yellow]" if structural else ""
            console.print(f"  {rec.id}  {rec.platform:<14} {rec.format:<6} {rec.title}{flag}")
        unclaimed = sum(1 for oc in outcomes if oc.outcome == UNCLAIMED)
        console.print(
            f"\n[bold]{len(planned)}[/bold] rules would be catalogued "
            f"([yellow]{needs_review}[/yellow] need review). Dry run — nothing written."
        )
        if candidate is not None:
            claimed = [r for r in discovered if r.format == candidate.name]
            rates = _field_rates(claimed)
            console.print(
                f"  Profile [bold]{candidate.name}[/bold] claimed {len(claimed)} rules; "
                + ", ".join(f"{f} {rates[f]:.0%}" for f in _RATE_FIELDS)
            )
        if unclaimed:
            console.print(
                f"  [yellow]{unclaimed} structured files unclaimed[/yellow] "
                "(use --report json to cluster them for profile authoring)."
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
    if unclaimed:
        _print_unclaimed_nudge(unclaimed)
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
