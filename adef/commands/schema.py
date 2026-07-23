"""``adef schema`` — declaration-driven data schemas.

Users provide a **data-source declaration** (``adef-sources.yml``: sources +
fields, produced from artifacts they already have — Splunk ``| fieldsummary``,
KQL ``| getschema``, Elastic mappings). ``ingest`` builds one
``schema/<source>.yml`` (``schema_version: 2``) per source with
``declared | corrected`` field provenance; re-ingest preserves human
corrections and reports drift. ``check`` cross-references the fields
catalogued rules actually use against the declared schemas.

The former rules-derived model (interactive ``init`` wizard, ``from-catalog``
field derivation, ``update``/``rescan`` stubs) was removed pre-release — see
``docs/plans/2026-07-20-schema-declaration-design.md`` and ISA 2026-07-20.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console

from adef.core.declaration import (
    DeclarationError,
    address_literals,
    ingest_source,
    known_field_names,
    lint_declaration_dict,
    load_declaration,
    read_schema_v2,
)
from adef.core.recipes import get_recipe, list_platforms, render_recipe_markdown
from adef.core.reshape import ReshapeError, reshape_export
from adef.core.workspace import config_path, platform_from_config, resolve_workspace
from adef.core.rule_discovery import shape_literals
from adef.core.rule_parser import (
    extract_cql_fields,
    extract_kql_fields,
    extract_spl_fields,
    extract_sql_fields,
)

console = Console()

# Query-language field extractors, keyed by the record's ``query_language``.
# Sigma is excluded on purpose — it's structured YAML, not a query language.
_FIELD_EXTRACTORS = {
    "sql": extract_sql_fields,
    "spl": extract_spl_fields,
    "cql": extract_cql_fields,
    "kql": extract_kql_fields,
}

# Routing/meta pseudo-fields — never findings: they address data rather than
# describe events, so no declaration would (or should) list them.
_CHECK_IGNORED_FIELDS = {
    "index", "sourcetype", "source", "host", "earliest", "latest", "_time",
}


def _get_workspace_schema_dir(workspace: Path | None = None) -> Path:
    """Workspace schema dir via the canonical resolver (honors --workspace, env,
    cwd, default — ISA 2026-07-22). Previously env-or-default only, which made
    `schema show`/`ingest` ignore --workspace and the current directory."""
    return resolve_workspace(workspace) / "schema"


@click.group()
def schema():
    """Manage data schemas (declared sources + fields for rule authoring)."""
    pass


@schema.command()
@click.argument(
    "declaration_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
def ingest(declaration_file: Path, workspace: Path | None):
    """Build schemas from a data-source declaration (adef-sources.yml).

    Writes one ``schema/<source>.yml`` (schema_version 2) per declared source.
    Re-ingest replaces declared fields, preserves human ``corrected`` fields,
    and reports drift.
    """
    schema_dir = _get_workspace_schema_dir(workspace)
    try:
        sources = load_declaration(declaration_file)
    except DeclarationError as exc:
        raise click.ClickException(str(exc)) from exc

    _, lint_warnings = lint_declaration_dict(
        yaml.safe_load(declaration_file.read_text(encoding="utf-8"))
    )
    for warning in lint_warnings:
        console.print(f"  [yellow]warning:[/yellow] {warning}")

    for src in sources:
        path, drift = ingest_source(src, schema_dir)
        console.print(
            f"[green]Ingested[/green] {src.name} → schema/{path.name} "
            f"({len(src.fields)} declared fields)"
        )
        if drift.corrected_kept:
            console.print(
                f"  kept {len(drift.corrected_kept)} corrected field(s): "
                + ", ".join(drift.corrected_kept)
            )
        if drift.any:
            if drift.added:
                console.print(f"  [cyan]drift:[/cyan] added: {', '.join(drift.added)}")
            if drift.removed:
                console.print(f"  [cyan]drift:[/cyan] removed: {', '.join(drift.removed)}")
            if drift.type_changed:
                console.print(
                    f"  [cyan]drift:[/cyan] type changed: {', '.join(drift.type_changed)}"
                )


@schema.command(name="lint")
@click.argument(
    "declaration_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def lint_cmd(declaration_file: Path):
    """Validate a data-source declaration (exit 1 on errors)."""
    try:
        data = yaml.safe_load(declaration_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise click.ClickException(f"{declaration_file}: not parseable as YAML: {exc}") from exc

    errors, warnings = lint_declaration_dict(data)
    for warning in warnings:
        console.print(f"  [yellow]warning:[/yellow] {warning}")
    if errors:
        for err in errors:
            console.print(f"  [red]✗[/red] {err}")
        raise click.ClickException(f"{declaration_file}: {len(errors)} problem(s)")
    console.print(f"[green]OK[/green] {declaration_file}")


@schema.command()
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
@click.option(
    "--report",
    "report_format",
    type=click.Choice(["json"]),
    default=None,
    help="Emit a machine-readable findings report.",
)
def check(workspace: Path | None, report_format: str | None):
    """Cross-reference rule field usage against declared schemas.

    For every catalogued rule whose literals match a schema_version-2 schema,
    extract the fields the rule references and compare against the schema
    (field names + aliases). Findings are advisory, never blocking:

    - rule references a field the schema doesn't know (broken rule,
      undeclared alias, or a macro worth documenting);
    - schema fields no rule uses (unexploited detection surface).

    Scope matching (ISA 2026-07-21): a rule matches every source whose name
    OR scope values contain one of the rule's literals (``data_source`` plus
    shape literals like SPL ``sourcetype=``). **Most-specific match wins**:
    sources matching the most literals are kept; ties keep all (the union) —
    correct, because a query filtered only by container could see any of
    those event shapes. A field missing from a union is one finding reported
    against the whole group, not one row per matched source.
    """
    from adef.core.catalog import Catalog

    ws = resolve_workspace(workspace)
    schema_dir = ws / "schema"
    cat = Catalog(ws)

    # source -> known names / declared names; literal -> sources it addresses
    schemas: dict[str, set[str]] = {}
    declared_fields: dict[str, set[str]] = {}
    addressed_by: dict[str, set[str]] = {}
    for path in sorted(schema_dir.glob("*.yml")) if schema_dir.is_dir() else []:
        data = read_schema_v2(path)
        if data:
            name = data["source"]
            schemas[name] = known_field_names(data)
            declared_fields[name] = {str(f.get("name", "")) for f in data.get("fields", [])}
            for literal in address_literals(data):
                addressed_by.setdefault(literal, set()).add(name)

    # matched-source group -> field -> [rule ids]. Group of 1 = a normal match;
    # >1 = a union tie — one finding for the group, not one row per source.
    missing: dict[tuple[str, ...], dict[str, list[str]]] = {}
    used: dict[str, set[str]] = {s: set() for s in schemas}
    rules_checked = 0
    for det_id, _path, data in cat.iter_records():
        query = data.get("query") or ""
        # query_language (persisted 2026-07-21) covers ESCU + profile-claimed
        # rules whose `format` isn't itself a query language.
        language = data.get("query_language") or data.get("format", "")
        extractor = _FIELD_EXTRACTORS.get(language)
        if extractor is None or not query:
            continue

        literals = {(data.get("data_source") or "").strip()} - {""}
        literals.update(shape_literals(query, language))
        match_counts: dict[str, int] = {}
        for literal in literals:
            for source in addressed_by.get(literal, ()):
                match_counts[source] = match_counts.get(source, 0) + 1
        if not match_counts:
            continue
        best = max(match_counts.values())
        matched = sorted(s for s, n in match_counts.items() if n == best)

        rules_checked += 1
        union_known: set[str] = set().union(*(schemas[s] for s in matched))
        for f in extractor(query):
            if f.lower() in _CHECK_IGNORED_FIELDS:
                continue
            if f in union_known:
                for source in matched:
                    if f in schemas[source]:
                        used[source].add(f)
            else:
                missing.setdefault(tuple(matched), {}).setdefault(f, []).append(det_id)

    unused = {
        source: sorted(declared_fields[source] - used[source])
        for source in schemas
        if declared_fields[source] - used[source]
    }

    if report_format == "json":
        click.echo(
            json.dumps(
                {
                    "rules_checked": rules_checked,
                    "sources_with_schemas": sorted(schemas),
                    "missing_from_schema": {
                        ", ".join(group): {f: ids for f, ids in sorted(fields.items())}
                        for group, fields in sorted(missing.items())
                    },
                    "unused_by_rules": unused,
                },
                indent=2,
            )
        )
        return

    if not schemas:
        console.print(
            "[yellow]No schema_version-2 schemas found[/yellow] — run "
            "`adef schema ingest <declaration.yml>` first."
        )
        return
    console.print(
        f"Checked [bold]{rules_checked}[/bold] rules against "
        f"{len(schemas)} schema(s).\n"
    )
    if not missing and not unused:
        console.print("[green]No findings.[/green]")
        return
    for group, fields in sorted(missing.items()):
        label = ", ".join(group)
        suffix = (
            f" — rule fields missing from all {len(group)} union-matched schemas:"
            if len(group) > 1
            else " — rule fields missing from schema:"
        )
        console.print(f"[bold]{label}[/bold]{suffix}")
        for fname, ids in sorted(fields.items()):
            console.print(f"  [yellow]?[/yellow] {fname}  (used by {', '.join(sorted(ids))})")
    for source, unused_fields in sorted(unused.items()):
        console.print(f"[bold]{source}[/bold] — declared fields no rule uses:")
        for fname in unused_fields:
            console.print(f"  [cyan]·[/cyan] {fname}")


@schema.command()
@click.argument("source")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
def show(source: str, workspace: Path | None):
    """Display schema for SOURCE."""
    schema_path = _get_workspace_schema_dir(workspace) / f"{source}.yml"
    if not schema_path.exists():
        console.print(f"[red]Error:[/red] Schema not found: {source}")
        sys.exit(1)

    v2 = read_schema_v2(schema_path)
    if v2 is None:
        console.print(
            f"[red]Error:[/red] {schema_path.name} is not a schema_version-2 file — "
            "re-create it with `adef schema ingest <declaration.yml>`."
        )
        sys.exit(1)

    console.print(f"[bold]{v2['source']}[/bold]  (schema v2)")
    if v2.get("platform"):
        console.print(f"Platform: {v2['platform']}")
    console.print(f"Query language: {v2.get('query_language') or 'unspecified'}")
    console.print(f"Declared: {v2.get('declared', 'unknown')}")
    if v2.get("description"):
        console.print(v2["description"])
    fields = v2.get("fields", [])
    console.print(f"\nFields ({len(fields)} total):")
    for fld in fields:
        marker = "✎" if fld.get("provenance") == "corrected" else " "
        line = f"  {marker} {fld['name']} ({fld.get('type', 'string')})"
        if fld.get("aliases"):
            line += f"  aliases: {', '.join(fld['aliases'])}"
        console.print(line)
        if fld.get("description"):
            console.print(f"      \"{fld['description']}\"")
        if fld.get("values"):
            console.print(f"      values: {fld['values']}")


@schema.command()
@click.argument("platform", required=False)
@click.option(
    "--format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format (markdown or json).",
)
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
def recipe(platform: str | None, format: str, workspace: Path | None):
    """Generate SIEM-specific field extraction recipe.

    If PLATFORM is not specified, reads platform preference from workspace config.
    """
    # If no platform specified, try to read from workspace config
    if not platform:
        platform = platform_from_config(resolve_workspace(workspace))

        if not platform:
            # Interactive fallback
            console.print("\n[bold]No platform configured.[/bold]")
            console.print("Run [cyan]adef init --interactive[/cyan] to set preferences, or choose now:\n")
            platform = click.prompt(
                "Which SIEM/platform?",
                type=click.Choice(list_platforms(), case_sensitive=False),
                default="splunk",
            )

    # Get and render recipe
    try:
        recipe_obj = get_recipe(platform)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if format == "json":
        import dataclasses
        output = dataclasses.asdict(recipe_obj)
        click.echo(json.dumps(output, indent=2))
    else:
        console.print(render_recipe_markdown(recipe_obj))


def _print_fold_evidence(canonical: str, evidence: dict[str, list[str]], indent: str = "  ") -> None:
    """Show each spelling's harvested values so keep-or-split is decidable in place."""
    for spelling, values in evidence.items():
        shown = ", ".join(repr(v) for v in values[:4]) + (", …" if len(values) > 4 else "")
        console.print(f"{indent}{spelling}: {shown or '(no values harvested)'}")


@schema.command()
@click.argument("export_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--platform", default=None, help="Export format: splunk, sentinel, elastic (others: one field per line).")
@click.option("--source", "source_name", default=None, help="Declared source name (default: derived from sourcetype/filename).")
@click.option("--output", "-o", type=click.Path(dir_okay=False, path_type=Path), default=None, help="Output declaration path (default: <source>-sources.yml).")
@click.option("--no-fold", "no_fold", multiple=True, help="Field name to exempt from case-folding — it keeps its own entry. Repeatable. Use when a fold merged two different fields that collide on spelling.")
@click.option("--interactive", "-i", is_flag=True, help="Walk each SUSPECT fold with its value evidence and ask keep or split.")
@click.option("--append", "append_to", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=None, help="Add this source to an existing declaration file instead of writing a new one (multi-table/multi-sourcetype flows).")
@click.option("--workspace", type=click.Path(file_okay=False, path_type=Path), default=None, help="Workspace path (defaults to ADEF_WORKSPACE, current dir, or ~/work/adef-workspace/).")
def reshape(export_file: Path, platform: str | None, source_name: str | None, output: Path | None, no_fold: tuple[str, ...], interactive: bool, append_to: Path | None, workspace: Path | None):
    """Reshape a raw SIEM field export into a draft declaration.

    Applies the five reshape rules (internals filter, case-dupes to aliases,
    capped enum harvesting, type inference, mixed-shape guard) and prints a
    transformation report — approve the transformations, then
    `adef schema ingest` the result. Run `adef schema recipe` first for the
    per-SIEM export command.
    """
    if not platform:
        ws = resolve_workspace(workspace)
        platform = platform_from_config(ws)
        if not platform:
            raise click.ClickException(
                f"No platform given or configured — looked in {config_path(ws)}. "
                "Pass --platform, point --workspace/ADEF_WORKSPACE at your "
                "workspace, or run `adef init --interactive`."
            )

    try:
        result = reshape_export(export_file, platform, source_name, no_fold)
    except ReshapeError as exc:
        raise click.ClickException(str(exc)) from exc

    if interactive and result.report.suspect_folds:
        console.print(
            f"\n[bold]{len(result.report.suspect_folds)} merged pair(s) to review.[/bold]\n\n"
            "Your SIEM has each pair below as two separate fields whose names differ\n"
            "only by capitalization. ADEF merged each pair into one schema entry,\n"
            "assuming both names describe the same thing — but their observed values\n"
            "have nothing in common, so it can't confirm that. You decide, per pair:\n\n"
            "  [bold]MERGE (y)[/bold] if both value lists describe the SAME attribute in\n"
            "  different formats. Example: Direction '%%14592' is the Windows code\n"
            "  for 'inbound' — one attribute, raw vs normalized. Merged = one schema\n"
            "  entry; a detection may reference either name.\n\n"
            "  [bold]SPLIT (n)[/bold] if the value lists describe UNRELATED attributes.\n"
            "  Example: Signature 'Microsoft Corporation' (who signed a binary) vs\n"
            "  signature 'A new process has been created' (what the event is) — two\n"
            "  attributes colliding on a name. Split = two schema entries, each\n"
            "  keeping its own values.\n"
        )
        split: list[str] = []
        for canonical in result.report.suspect_folds:
            variants = result.report.folded_aliases.get(canonical, [])
            _print_fold_evidence(canonical, result.report.fold_evidence.get(canonical, {}))
            if not click.confirm(
                f"  Do {canonical} and {', '.join(variants)} describe the same "
                f"attribute (merge)?",
                default=True,
            ):
                split.extend(variants)
            console.print()
        if split:
            no_fold = tuple(no_fold) + tuple(split)
            result = reshape_export(export_file, platform, source_name, no_fold)

    errors, warnings = lint_declaration_dict(result.declaration)
    if errors:  # reshape output must always lint clean — this is a bug, not user error
        raise click.ClickException("reshape produced an invalid declaration: " + "; ".join(errors))

    src = result.declaration["sources"][0]
    to_write = result.declaration
    if append_to is not None:
        try:
            existing = yaml.safe_load(append_to.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise click.ClickException(f"{append_to}: not parseable as YAML: {exc}") from exc
        if not isinstance(existing, dict) or not isinstance(existing.get("sources"), list):
            raise click.ClickException(f"{append_to}: not a declaration (no `sources:` list)")
        taken = {s.get("name") for s in existing["sources"] if isinstance(s, dict)}
        if src["name"] in taken:
            raise click.ClickException(
                f"{append_to} already declares a source named {src['name']!r} — "
                "pass --source to name this one differently, or re-ingest instead."
            )
        existing["sources"].append(src)
        errors, warnings = lint_declaration_dict(existing)
        if errors:
            raise click.ClickException(f"appending produced an invalid declaration: {'; '.join(errors)}")
        to_write = existing
    out_path = append_to or output or Path(f"{src['name']}-sources.yml")
    out_path.write_text(
        yaml.safe_dump(to_write, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )

    report = result.report
    verb = f"Appended source [bold]{src['name']}[/bold] to" if append_to else "Wrote"
    console.print(
        f"[green]✓[/green] {verb} [bold]{out_path}[/bold] — {len(src['fields'])} fields declared"
        + (f" ({len(to_write['sources'])} sources total)\n" if append_to else "\n")
    )
    console.print("[bold]Transformation report[/bold] (approve these, not the YAML):")
    if src.get("scope"):
        scope_str = ", ".join(f"{k}={v}" for k, v in src["scope"].items())
        console.print(f"  Scope inferred from the export: {scope_str}")
    console.print(f"  Dropped {len(report.dropped_internals)} internals: {', '.join(report.dropped_internals) or '—'}")
    if report.folded_aliases:
        folded = "; ".join(
            f"{k} ← {', '.join(v)}"
            + (" [red][SUSPECT][/red]" if k in report.suspect_folds else "")
            for k, v in report.folded_aliases.items()
        )
        console.print(f"  Folded {len(report.folded_aliases)} case-dupes: {folded}")
    for suspect in report.suspect_folds:
        variant_str = ", ".join(report.folded_aliases.get(suspect, []))
        console.print(
            f"  [red]![/red] SUSPECT merge: {suspect} + {variant_str} — two SIEM fields, "
            f"names differing only by case, merged into one schema entry. Their observed "
            f"values have nothing in common, so verify they describe the same attribute:"
        )
        _print_fold_evidence(suspect, report.fold_evidence.get(suspect, {}), indent="      ")
        console.print(
            "      Same attribute, different formats (raw code vs readable value)? "
            "keep the merge. Unrelated attributes colliding on a name? split:"
        )
        # click.echo: a copy-paste flag must never soft-wrap mid-token
        click.echo(f"        --no-fold {variant_str}    (or walk all pairs with --interactive)")
    if no_fold:
        flags = " ".join(f"--no-fold {n}" for n in no_fold)
        # click.echo, not console.print: a copy-paste command must never soft-wrap
        click.echo(f"\nReproducible: adef schema reshape {export_file} --platform {platform} {flags}")
    console.print(f"  Enums harvested: {len(report.enum_fields)} fields; typed: {len(report.typed_fields)}")
    for note in report.notes:
        console.print(f"  [yellow]![/yellow] {note}")
    for warning in warnings:
        console.print(f"  [yellow]![/yellow] lint: {warning}")
    console.print(f"\nNext: review, then [bold]adef schema ingest {out_path}[/bold]")
