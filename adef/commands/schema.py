"""``adef schema`` — declaration-driven data schemas.

Users provide a **data-source declaration** (``adef-sources.yml``: sources +
fields, produced from artifacts they already have — Splunk ``| fieldsummary``,
KQL ``| getschema``, Elastic mappings). ``ingest`` builds one
``schema/<source>.yml`` (``schema_version: 2``) per source with
``declared | corrected`` field provenance; re-ingest preserves human
corrections and reports drift. ``check`` cross-references the fields
catalogued rules actually use against the declared schemas.

The former rules-derived model (interactive ``init`` wizard, ``from-catalog``
field derivation, ``update``/``rescan`` stubs) was removed pre-release.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Sequence

import click
import yaml
from rich.console import Console
from rich.markup import escape

from adef.core.declaration import (
    DeclarationError,
    address_literals,
    declared_aliases,
    ingest_source,
    known_field_names,
    lint_declaration_dict,
    load_declaration,
    read_schema_v2,
)
from adef.core.engines import ALLOWED_ENGINES
from adef.core.recipes import get_recipe, list_platforms, render_recipe_markdown
from adef.core.reshape import ReshapeError, reshape_export
from adef.core.workspace import config_path, platform_from_config, resolve_workspace
from adef.core.rule_discovery import shape_literals
from adef.core.rule_parser import (
    FIELD_EXTRACTORS,
    field_extractor_key,
    routing_fields,
)

console = Console()


def _get_workspace_schema_dir(workspace: Path | None = None) -> Path:
    """Workspace schema dir via the canonical resolver (honors --workspace, env,
    cwd, default). Previously env-or-default only, which made
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
        console.print(f"  [yellow]warning:[/yellow] {escape(str(warning))}")

    for src in sources:
        path, drift = ingest_source(src, schema_dir)
        console.print(
            f"[green]Ingested[/green] {escape(str(src.name))} → schema/{escape(str(path.name))} "
            f"({len(src.fields)} declared fields)"
        )
        if drift.corrected_kept:
            console.print(
                f"  kept {len(drift.corrected_kept)} corrected field(s): "
                + escape(", ".join(drift.corrected_kept))
            )
        if drift.any:
            if drift.added:
                console.print(f"  [cyan]drift:[/cyan] added: {escape(', '.join(drift.added))}")
            if drift.removed:
                console.print(f"  [cyan]drift:[/cyan] removed: {escape(', '.join(drift.removed))}")
            if drift.type_changed:
                console.print(
                    f"  [cyan]drift:[/cyan] type changed: {escape(', '.join(drift.type_changed))}"
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
        console.print(f"  [yellow]warning:[/yellow] {escape(str(warning))}")
    if errors:
        for err in errors:
            console.print(f"  [red]✗[/red] {escape(str(err))}")
        raise click.ClickException(f"{declaration_file}: {len(errors)} problem(s)")
    console.print(f"[green]OK[/green] {escape(str(declaration_file))}")


@dataclass
class SchemaCheckResult:
    rules_checked: int
    rules_checked_ids: list[str]
    rules_skipped_unmatched: list[str]
    rules_skipped_unparseable: list[str]
    sources_with_schemas: list[str]
    missing_from_schema: dict[tuple[str, ...], dict[str, list[str]]]
    unused_by_rules: dict[str, list[str]]
    engine_errors: dict[str, str] = dataclass_field(default_factory=dict)
    undeclared_type_fields: dict[str, list[str]] = dataclass_field(default_factory=dict)
    # source -> (fields declaring at least one alias, total fields). A source
    # with zero alias coverage passes validation but gives cross-language
    # field retrieval nothing to canonicalize through, so the state has to be
    # legible somewhere a user already looks.
    alias_coverage: dict[str, tuple[int, int]] = dataclass_field(default_factory=dict)


def run_schema_check(ws: Path, detection_ids: Sequence[str] = ()) -> SchemaCheckResult:
    """Cross-reference rule field usage against declared schemas.

    For every catalogued rule whose literals match a schema_version-2 schema,
    extract the fields the rule references and compare against the schema
    (field names + aliases). Findings are advisory, never blocking:

    - rule references a field the schema doesn't know (broken rule,
      undeclared alias, or a macro worth documenting);
    - schema fields no rule uses (unexploited detection surface).

    Scope matching: a rule matches every source whose name
    OR scope values contain one of the rule's literals (``data_source`` plus
    shape literals like SPL ``sourcetype=``). **Most-specific match wins**:
    sources matching the most literals are kept; ties keep all (the union) —
    correct, because a query filtered only by container could see any of
    those event shapes. A field missing from a union is one finding reported
    against the whole group, not one row per matched source.
    """
    from adef.core.catalog import Catalog

    schema_dir = ws / "schema"
    cat = Catalog(ws)

    # source -> known names / declared names; literal -> sources it addresses
    schemas: dict[str, set[str]] = {}
    declared_fields: dict[str, set[str]] = {}
    declared_types: dict[str, dict[str, str]] = {}
    addressed_by: dict[str, set[str]] = {}
    # source -> (fields declaring >=1 alias, total fields). "Has an alias"
    # must agree with field_index._build_alias_maps's predicate — at least
    # one non-empty alias string — or this report claims coverage the
    # retrieval path does not actually honour.
    alias_coverage: dict[str, tuple[int, int]] = {}
    for path in sorted(schema_dir.glob("*.yml")) if schema_dir.is_dir() else []:
        data = read_schema_v2(path)
        if data:
            name = data.get("source")
            if not name:  # v2 but no source (hand-edited/partial) → skip, don't KeyError
                continue
            schemas[name] = known_field_names(data)
            declared_fields[name] = {str(f.get("name", "")) for f in data.get("fields", [])}
            fields_list = data.get("fields", []) or []
            with_alias = sum(
                1 for f in fields_list
                if isinstance(f, dict) and f.get("name") and declared_aliases(f)
            )
            alias_coverage[name] = (with_alias, len(fields_list))
            # Alias names map to their parent field's type too — otherwise a
            # rule referencing a typed field by its alias is accepted as
            # "known" by known_field_names() but then wrongly reported as
            # having no declared type (found via CodeRabbit review).
            declared_types[name] = {}
            for f in data.get("fields", []):
                field_type = str(f.get("type", ""))
                declared_types[name][str(f.get("name", ""))] = field_type
                for alias in declared_aliases(f):
                    declared_types[name][str(alias)] = field_type
            for literal in address_literals(data):
                addressed_by.setdefault(literal, set()).add(name)

    # matched-source group -> field -> [rule ids]. Group of 1 = a normal match;
    # >1 = a union tie — one finding for the group, not one row per source.
    missing: dict[tuple[str, ...], dict[str, list[str]]] = {}
    used: dict[str, set[str]] = {s: set() for s in schemas}
    rules_checked = 0
    # Rules dropped before checking — tracked so the summary can't report a
    # skipped rule as clean (issue #6). Two distinct reasons the user must tell
    # apart: can't parse its fields vs. no schema addresses its data.
    unparseable: list[str] = []  # no field extractor / empty query
    unmatched: list[str] = []    # literals match no declared schema
    engine_errors: dict[str, str] = {}
    undeclared_type_fields: dict[str, list[str]] = {}
    scope = set(detection_ids)
    rules_checked_ids: list[str] = []
    for det_id, _path, data in cat.iter_records():
        if scope:
            if det_id not in scope:
                continue
        rules_checked_ids.append(det_id)
        engine = data.get("engine", "")
        if engine not in ALLOWED_ENGINES:
            engine_errors[det_id] = (
                f"engine '{engine}' is not one of the allowed engines {sorted(ALLOWED_ENGINES)}"
            )
        query = data.get("query") or ""
        # query_language (persisted 2026-07-21) covers ESCU + profile-claimed
        # rules whose `format` isn't itself a query language.
        language = field_extractor_key(data)
        extractor = FIELD_EXTRACTORS.get(language)
        if extractor is None or not query:
            unparseable.append(det_id)
            continue

        literals = {(data.get("data_source") or "").strip()} - {""}
        literals.update(shape_literals(query, language))
        match_counts: dict[str, int] = {}
        for literal in literals:
            for source in addressed_by.get(literal, ()):
                match_counts[source] = match_counts.get(source, 0) + 1
        if not match_counts:
            unmatched.append(det_id)
            continue
        best = max(match_counts.values())
        matched = sorted(s for s, n in match_counts.items() if n == best)

        rules_checked += 1
        union_known: set[str] = set().union(*(schemas[s] for s in matched))
        routing = routing_fields(language)
        for f in extractor(query):
            # A CQL `#tag` (`#event_simpleName`, `#repo`) selects the
            # datasource, like SPL's sourcetype — routing, not a schema field.
            if f.lower() in routing or f.startswith("#"):
                continue
            if f in union_known:
                for source in matched:
                    if f in schemas[source]:
                        used[source].add(f)
                        if not declared_types.get(source, {}).get(f):
                            undeclared_type_fields.setdefault(det_id, []).append(f)
            else:
                missing.setdefault(tuple(matched), {}).setdefault(f, []).append(det_id)

    # Whole-catalog concept: scoped to one detection it would claim nearly
    # every declared field "unused" — suppress it under --detection.
    unused = (
        {}
        if scope
        else {
            source: sorted(declared_fields[source] - used[source])
            for source in schemas
            if declared_fields[source] - used[source]
        }
    )

    return SchemaCheckResult(
        rules_checked=rules_checked,
        rules_checked_ids=rules_checked_ids,
        rules_skipped_unmatched=sorted(unmatched),
        rules_skipped_unparseable=sorted(unparseable),
        sources_with_schemas=sorted(schemas),
        missing_from_schema=dict(missing),
        unused_by_rules=unused,
        engine_errors=engine_errors,
        # A field is appended once per matched schema source, so a union tie
        # yields duplicates — dedupe like the sibling missing-fields report.
        undeclared_type_fields={
            det_id: sorted(set(fields)) for det_id, fields in undeclared_type_fields.items()
        },
        alias_coverage=alias_coverage,
    )


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
@click.option(
    "--detection",
    "detection_ids",
    multiple=True,
    help="Scope the check to specific detection ID(s), e.g. --detection D-0001. "
    "Repeatable. Suppresses the unused-declared-fields section (a whole-catalog "
    "concept). Built for the authoring loop: validate the rule you just wrote.",
)
def check(workspace: Path | None, report_format: str | None, detection_ids: tuple[str, ...]):
    """Cross-reference rule field usage against declared schemas.

    For every catalogued rule whose literals match a schema_version-2 schema,
    extract the fields the rule references and compare against the schema
    (field names + aliases). Findings are advisory, never blocking:

    - rule references a field the schema doesn't know (broken rule,
      undeclared alias, or a macro worth documenting);
    - schema fields no rule uses (unexploited detection surface).

    Scope matching: a rule matches every source whose name
    OR scope values contain one of the rule's literals (``data_source`` plus
    shape literals like SPL ``sourcetype=``). **Most-specific match wins**:
    sources matching the most literals are kept; ties keep all (the union) —
    correct, because a query filtered only by container could see any of
    those event shapes. A field missing from a union is one finding reported
    against the whole group, not one row per matched source.
    """
    ws = resolve_workspace(workspace)
    scope = set(detection_ids)
    result = run_schema_check(ws, detection_ids=detection_ids)
    if scope and (not_found := sorted(scope - set(result.rules_checked_ids))):
        raise click.ClickException(
            f"detection id(s) not in the catalog: {', '.join(not_found)}"
        )

    if report_format == "json":
        click.echo(
            json.dumps(
                {
                    "rules_checked": result.rules_checked,
                    "rules_skipped": {
                        "unmatched": result.rules_skipped_unmatched,
                        "unparseable": result.rules_skipped_unparseable,
                    },
                    "sources_with_schemas": result.sources_with_schemas,
                    "missing_from_schema": {
                        ", ".join(group): {f: ids for f, ids in sorted(fields.items())}
                        for group, fields in sorted(result.missing_from_schema.items())
                    },
                    "unused_by_rules": result.unused_by_rules,
                    "engine_errors": result.engine_errors,
                    "undeclared_type_fields": result.undeclared_type_fields,
                    # Named keys, not the `(with_alias, total)` tuple verbatim:
                    # JSON has no tuple type, so that would silently become a
                    # two-element array — a positional shape a machine
                    # consumer could easily misread as [total, with_alias].
                    # This is the one signal that makes `declared_no_aliases`
                    # (schemas declared, check green, cross-language matching
                    # still inactive) visible to a machine reader the same
                    # way it already is in the terminal report below.
                    "alias_coverage": {
                        source: {"with_aliases": with_alias, "total": total}
                        for source, (with_alias, total) in sorted(result.alias_coverage.items())
                    },
                },
                indent=2,
            )
        )
        return

    if not result.sources_with_schemas:
        console.print(
            "[yellow]No schema_version-2 schemas found[/yellow] — run "
            "`adef schema ingest <declaration.yml>` first."
        )
        return
    total = (
        result.rules_checked
        + len(result.rules_skipped_unmatched)
        + len(result.rules_skipped_unparseable)
    )
    of_total = (
        f" of {total}"
        if (result.rules_skipped_unmatched or result.rules_skipped_unparseable)
        else ""
    )
    console.print(
        f"Checked [bold]{result.rules_checked}[/bold]{of_total} rules against "
        f"{len(result.sources_with_schemas)} schema(s)."
    )
    # A skipped rule is validated against nothing — the most interesting result,
    # and the one that used to produce silence (issue #6). Name them.
    if result.rules_skipped_unmatched:
        console.print(
            f"  [yellow]{len(result.rules_skipped_unmatched)} unmatched[/yellow] (no declared "
            f"schema addresses its data source): {escape(', '.join(result.rules_skipped_unmatched))}"
        )
    if result.rules_skipped_unparseable:
        console.print(
            f"  [yellow]{len(result.rules_skipped_unparseable)} unparseable[/yellow] (no field "
            f"extractor or empty query): {escape(', '.join(result.rules_skipped_unparseable))}"
        )
    console.print()
    for source, (with_alias, total) in sorted(result.alias_coverage.items()):
        if total and with_alias == 0:
            console.print(
                f"  [yellow]{escape(str(source))}[/yellow]: 0/{total} fields declare aliases — "
                "cross-language field matching inactive for this source"
            )
        elif total:
            console.print(f"  {escape(str(source))}: {with_alias}/{total} fields declare aliases")
    if not (
        result.missing_from_schema
        or result.unused_by_rules
        or result.engine_errors
        or result.undeclared_type_fields
    ):
        console.print("[green]No findings.[/green]")
        return
    if result.engine_errors:
        console.print("[bold]Engine taxonomy[/bold] — rules outside the allowed engine set:")
        for det_id, message in sorted(result.engine_errors.items()):
            console.print(f"  [red]✗[/red] {det_id}: {escape(str(message))}")
    for group, fields in sorted(result.missing_from_schema.items()):
        label = ", ".join(group)
        suffix = (
            f" — rule fields missing from all {len(group)} union-matched schemas:"
            if len(group) > 1
            else " — rule fields missing from schema:"
        )
        console.print(f"[bold]{label}[/bold]{suffix}")
        for fname, ids in sorted(fields.items()):
            console.print(f"  [yellow]?[/yellow] {escape(str(fname))}  (used by {escape(', '.join(sorted(ids)))})")
    if result.undeclared_type_fields:
        console.print(
            "[bold]Schema completeness[/bold] — fields a rule uses that the schema "
            "declares without a type:"
        )
        for det_id, type_fields in sorted(result.undeclared_type_fields.items()):
            console.print(f"  [yellow]?[/yellow] {det_id}: {escape(', '.join(type_fields))}")
    for source, unused_fields in sorted(result.unused_by_rules.items()):
        console.print(f"[bold]{escape(str(source))}[/bold] — declared fields no rule uses:")
        for fname in unused_fields:
            console.print(f"  [cyan]·[/cyan] {escape(str(fname))}")


@schema.command(name="list")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
def list_cmd(workspace: Path | None):
    """List the declared schemas in the workspace (one line per source)."""
    schema_dir = _get_workspace_schema_dir(workspace)
    paths = sorted(schema_dir.glob("*.yml")) if schema_dir.is_dir() else []
    if not paths:
        console.print(
            "No schemas declared yet. Run `adef schema ingest <declaration.yml>` first."
        )
        return
    n = 0
    for path in paths:
        v2 = read_schema_v2(path)
        if v2 is None:
            console.print(
                f"  [yellow]{escape(str(path.stem))}[/yellow]  (not a schema_version-2 file — skipped)"
            )
            continue
        n += 1
        platform = v2.get("platform") or "-"
        ql = v2.get("query_language") or "unspecified"
        nfields = len(v2.get("fields", []))
        console.print(
            f"  [bold]{escape(str(v2['source']))}[/bold]  {escape(str(platform))}  {escape(str(ql))}  "
            f"({nfields} field{'s' if nfields != 1 else ''})"
        )
    console.print(
        f"\n[bold]{n}[/bold] schema(s) — `adef schema show <source>` for detail."
    )


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
        console.print(f"[red]Error:[/red] Schema not found: {escape(str(source))}")
        sys.exit(1)

    v2 = read_schema_v2(schema_path)
    if v2 is None:
        console.print(
            f"[red]Error:[/red] {escape(str(schema_path.name))} is not a schema_version-2 file — "
            "re-create it with `adef schema ingest <declaration.yml>`."
        )
        sys.exit(1)

    console.print(f"[bold]{escape(str(v2['source']))}[/bold]  (schema v2)")
    if v2.get("platform"):
        console.print(f"Platform: {escape(str(v2['platform']))}")
    console.print(f"Query language: {escape(str(v2.get('query_language') or 'unspecified'))}")
    console.print(f"Declared: {escape(str(v2.get('declared', 'unknown')))}")
    if v2.get("description"):
        # Bare print of a whole foreign string with no styling of ADEF's own —
        # `markup=False` for the same reason the query block uses it: `escape`
        # doubles a trailing backslash when nothing follows it on the line.
        console.print(str(v2["description"]), markup=False)
    fields = v2.get("fields", [])
    console.print(f"\nFields ({len(fields)} total):")
    for fld in fields:
        marker = "✎" if fld.get("provenance") == "corrected" else " "
        line = f"  {marker} {escape(str(fld['name']))} ({escape(str(fld.get('type', 'string')))})"
        if fld.get("aliases"):
            line += f"  aliases: {escape(', '.join(fld['aliases']))}"
        console.print(line)
        if fld.get("description"):
            console.print(f"      \"{escape(str(fld['description']))}\"")
        if fld.get("values"):
            console.print(f"      values: {escape(str(fld['values']))}")


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
        # `markup=False`, not `escape`: the whole block is copy-paste material
        # with no tags of ADEF's own, and the sumo recipe's `[^\s]` is a regex
        # class Rich would otherwise try to read as a style.
        console.print(render_recipe_markdown(recipe_obj), markup=False)


_MERGE_HELP = """
  Same attribute usually looks like one of these value transformations:
    hex <-> decimal      (0x1538 <-> 5432)            - process/thread/status IDs
    code <-> word        (%%14592 <-> inbound, 0x0 <-> success)
    prefixed <-> bare    (NT AUTHORITY\\SYSTEM <-> SYSTEM)
    quoted <-> unquoted  ("4" <-> 4)
  Unrelated attributes usually differ in KIND, not format:
    names vs sentences, publishers vs descriptions, one constant vs a list.
  Unsure? Split (n) is the safe answer - both spellings stay valid for
  `schema check`, each keeps its own values; you can merge later by hand.
  Better: with the ADEF Claude plugin, ask the schema-declaration skill to
  drive this flow - knowing what a field IS (code-signing publisher vs CIM
  constant) is exactly what an agent session adds over a y/n prompt.
"""


def _ask_merge(question: str) -> bool:
    """y/n/? prompt — '?' prints the same-attribute checklist and re-asks."""
    while True:
        answer = click.prompt(question + " [y/n/?]", default="y", show_default=False)
        answer = answer.strip().lower()
        if answer in ("y", "yes", ""):
            return True
        if answer in ("n", "no"):
            return False
        console.print(_MERGE_HELP)


def _print_fold_evidence(canonical: str, evidence: dict[str, list[str]], indent: str = "  ") -> None:
    """Show each spelling's harvested values so keep-or-split is decidable in place."""
    for spelling, values in evidence.items():
        shown = ", ".join(repr(v) for v in values[:4]) + (", …" if len(values) > 4 else "")
        console.print(f"{indent}{escape(str(spelling))}: {escape(str(shown or '(no values harvested)'))}")


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

    kept_after_review: list[str] = []
    split_after_review: list[str] = []
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
            if not _ask_merge(
                f"  Do {canonical} and {', '.join(variants)} describe the same "
                f"attribute (merge)?"
            ):
                split.extend(variants)
            console.print()
        if split:
            no_fold = tuple(no_fold) + tuple(split)
            result = reshape_export(export_file, platform, source_name, no_fold)
        split_after_review = split
        # The human just adjudicated these — don't re-flag their decisions.
        kept_after_review = list(result.report.suspect_folds)
        result.report.suspect_folds = []

    if interactive:
        # Finish the fields reshape never guesses, while we have the human.
        src_platform = click.prompt(
            "  What kind of system does this source describe? — sets `platform:` "
            "(windows/linux/network/cloud/...; Enter to skip)",
            default="", show_default=False,
        ).strip()
        src_description = click.prompt(
            "  One-line description for this source (Enter to skip)",
            default="", show_default=False,
        ).strip()
        source_entry = result.declaration["sources"][0]
        if src_platform:
            source_entry["platform"] = src_platform
            result.report.notes = [
                n for n in result.report.notes if not n.startswith("source platform")
            ]
        if src_description:
            source_entry["description"] = src_description

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
    verb = (
        f"Appended source [bold]{escape(str(src['name']))}[/bold] to" if append_to else "Wrote"
    )
    console.print(
        f"[green]✓[/green] {verb} [bold]{escape(str(out_path))}[/bold] — {len(src['fields'])} fields declared"
        + (f" ({len(to_write['sources'])} sources total)\n" if append_to else "\n")
    )
    console.print("[bold]Transformation report[/bold] (approve these, not the YAML):")
    if src.get("scope"):
        scope_str = ", ".join(f"{k}={v}" for k, v in src["scope"].items())
        console.print(f"  Scope inferred from the export: {escape(str(scope_str))}")
    console.print(f"  Dropped {len(report.dropped_internals)} internals: {escape(', '.join(report.dropped_internals) or '—')}")
    if report.folded_aliases:
        # Field names are escaped as they go in: the join appends ADEF's own
        # `[red]` tag, so the assembled string can't be escaped as a whole.
        folded = "; ".join(
            f"{escape(k)} ← {escape(', '.join(v))}"
            + (" [red][SUSPECT][/red]" if k in report.suspect_folds else "")
            for k, v in report.folded_aliases.items()
        )
        console.print(f"  Folded {len(report.folded_aliases)} case-dupes: {folded}")
    if kept_after_review:
        console.print(f"  Merges kept after your review: {escape(', '.join(kept_after_review))}")
    if split_after_review:
        console.print(f"  Split after your review: {escape(', '.join(split_after_review))}")
    for suspect in report.suspect_folds:
        variant_str = ", ".join(report.folded_aliases.get(suspect, []))
        console.print(
            f"  [red]![/red] SUSPECT merge: {escape(str(suspect))} + {escape(str(variant_str))} — two SIEM fields, "
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
    console.print(f"  Enums harvested: {len(report.enum_fields)} fields; typed: {len(report.typed_fields)}")
    for note in report.notes:
        console.print(f"  [yellow]![/yellow] {escape(str(note))}")
    for warning in warnings:
        console.print(f"  [yellow]![/yellow] lint: {escape(str(warning))}")
    console.print(f"\nNext: review, then [bold]adef schema ingest {escape(str(out_path))}[/bold]")
    if no_fold:
        flags = " ".join(f"--no-fold {n}" for n in no_fold)
        # click.echo, not console.print: a copy-paste command must never soft-wrap
        click.echo(
            "\nFor later — nothing to run now. To repeat these keep/split "
            "decisions on a future export of this source (no prompts):"
        )
        click.echo(f"  adef schema reshape {export_file} --platform {platform} {flags}")
