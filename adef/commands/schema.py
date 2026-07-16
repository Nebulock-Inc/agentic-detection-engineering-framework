"""``adef schema`` — schema storage commands."""

from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

import click
from rich.console import Console

from adef.core.schema import Schema, merge_fields, write_schema, read_schema
from adef.core.rule_parser import extract_sql_fields, extract_spl_fields, extract_cql_fields, extract_kql_fields
from adef.core.data_sampler import sample_data_from_json, sample_data_from_csv
from adef.core.llm_client import generate_field_descriptions

console = Console()


def _now_iso() -> str:
    """Return current timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _get_workspace_schema_dir() -> Path:
    """Get workspace schema directory from env or default."""
    workspace = Path(os.getenv("ADEF_WORKSPACE", Path.home() / "work" / "adef-workspace"))
    return workspace / "schema"


@click.group()
def schema():
    """Manage data schemas (field inventory + types + populations)."""
    pass


@schema.command()
@click.argument("source")
@click.option("--rule-root", type=Path, help="Path to rules directory")
@click.option("--stdin", is_flag=True, help="Read data sample from stdin")
@click.option("--skip-rules", is_flag=True, help="Only sample data, skip rule parsing")
@click.option("--skip-data", is_flag=True, help="Only parse rules, skip data sampling")
def init(source: str, rule_root: Path | None, stdin: bool, skip_rules: bool, skip_data: bool):
    """Initialize a data schema for SOURCE (interactive wizard)."""
    console.print(f"[bold]Initializing schema for {source}[/bold]\n")

    # 1. Get query language
    query_language = click.prompt(
        "Which query language does this source use?",
        type=click.Choice(["sql", "spl", "cql", "kql"], case_sensitive=False)
    ).lower()

    rule_fields = set()
    last_rule_scan = None

    # 2. Parse rules (if not skipped)
    if not skip_rules:
        scan_rules = click.confirm("Do you have existing rules to scan?", default=True)
        if scan_rules:
            if not rule_root:
                rule_root = click.prompt("Path to rules directory", type=Path)

            console.print(f"Scanning rules in {rule_root}...")
            from adef.core.rule_discovery import scan_rule_fields

            rule_fields = scan_rule_fields(rule_root, query_language)
            last_rule_scan = _now_iso()
            console.print(f"Found {len(rule_fields)} fields in rules")

    data_fields = {}
    last_data_sample = None
    sample_window = None
    sample_size = None

    # 3. Sample data (if not skipped)
    if not skip_data:
        sample_now = click.confirm("Sample data now to discover field types?", default=True)
        if sample_now:
            if stdin:
                console.print("Reading data from stdin...")
                data_input = sys.stdin.read()
            else:
                console.print("Paste JSON or CSV data (Ctrl+D when done):")
                data_input = sys.stdin.read()

            # Detect format and parse
            try:
                data_fields = sample_data_from_json(data_input)
                last_data_sample = _now_iso()
                sample_size = len(json.loads(data_input))
            except json.JSONDecodeError:
                data_fields = sample_data_from_csv(data_input)
                last_data_sample = _now_iso()
                sample_size = len(data_input.strip().split("\n")) - 1  # minus header

            console.print(f"Sampled {sample_size} rows, found {len(data_fields)} fields")

    # 4. Merge fields
    merged_fields = merge_fields(rule_fields, data_fields)

    # 5. Generate descriptions (if fields exist)
    if merged_fields:
        try:
            console.print("Generating field descriptions...")
            descriptions = generate_field_descriptions(merged_fields, query_language, source)
            for field in merged_fields:
                field.description = descriptions.get(field.name, "")
        except RuntimeError as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")
            console.print("Descriptions set to empty (edit schema YAML manually)")

    # 6. Write schema
    schema_obj = Schema(
        source=source,
        query_language=query_language,
        last_rule_scan=last_rule_scan,
        last_data_sample=last_data_sample,
        sample_window=sample_window,
        sample_size=sample_size,
        fields=merged_fields
    )

    schema_dir = _get_workspace_schema_dir()
    schema_path = schema_dir / f"{source}.yml"
    write_schema(schema_obj, schema_path)

    # 7. Output summary
    console.print(f"\n[green]Schema initialized:[/green] schema/{source}.yml")
    console.print(f"  Fields from rules: {sum(1 for f in merged_fields if f.in_rules)}")
    console.print(f"  Fields from data: {sum(1 for f in merged_fields if f.in_data)}")
    console.print(f"  Overlap: {sum(1 for f in merged_fields if f.in_rules and f.in_data)}")

    rules_only = [f.name for f in merged_fields if f.in_rules and not f.in_data]
    if rules_only:
        console.print(f"  [yellow]⚠️  Rules-only (missing in data): {len(rules_only)}[/yellow]")

    console.print(f"\nNext steps:")
    console.print(f"  - Review: adef schema show {source}")
    console.print(f"  - Edit descriptions: schema/{source}.yml")


@schema.command()
@click.argument("source")
def show(source: str):
    """Display schema for SOURCE."""
    schema_path = _get_workspace_schema_dir() / f"{source}.yml"
    if not schema_path.exists():
        console.print(f"[red]Error:[/red] Schema not found: {source}")
        sys.exit(1)

    schema_obj = read_schema(schema_path)

    console.print(f"[bold]{schema_obj.source}[/bold]")
    console.print(f"Query language: {schema_obj.query_language}")
    console.print(f"Last rule scan: {schema_obj.last_rule_scan or 'Never'}")
    console.print(f"Last data sample: {schema_obj.last_data_sample or 'Never'}")
    console.print(f"\nFields ({len(schema_obj.fields)} total):")

    for field in schema_obj.fields:
        icon = "✓" if field.in_rules and field.in_data else "⚠" if field.in_rules else "ℹ"
        console.print(f"  {icon} {field.name} ({field.type}, {int(field.population * 100)}% populated)")
        console.print(f"    In rules: {'yes' if field.in_rules else 'NO'} | In data: {'yes' if field.in_data else 'NO'}")
        if field.description:
            console.print(f"    \"{field.description}\"")


@schema.command()
@click.argument("source")
def update(source: str):
    """Re-sample data to detect drift for SOURCE."""
    console.print(f"[bold]Updating schema: {source}[/bold]")
    # Implementation will go here


@schema.command()
@click.argument("source")
def rescan(source: str):
    """Re-parse rules to refresh in_rules flags for SOURCE."""
    console.print(f"[bold]Rescanning rules: {source}[/bold]")
    # Implementation will go here


# Query-language field extractors, keyed by the catalog record's ``format``.
# Sigma is excluded on purpose — it's structured YAML, not a query language.
_FIELD_EXTRACTORS = {
    "sql": extract_sql_fields,
    "spl": extract_spl_fields,
    "cql": extract_cql_fields,
    "kql": extract_kql_fields,
}


@schema.command(name="from-catalog")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="ADEF workspace path (defaults to ADEF_WORKSPACE or ~/work/adef-workspace/).",
)
def from_catalog(workspace: Path | None):
    """Generate data schemas from the catalog.

    Groups catalogued rules by (data_source, query_language) and writes one
    ``schema/<data_source>.yml`` per group. Rules whose data source could not be
    inferred pool by language into ``schema/<language>.yml`` (the fallback
    bucket). Sigma rules are skipped — they aren't a query language.
    """
    from adef.core.catalog import Catalog

    ws = Path(
        workspace or os.getenv("ADEF_WORKSPACE", Path.home() / "work" / "adef-workspace")
    ).expanduser().resolve()
    cat = Catalog(ws)
    schema_dir = ws / "schema"

    # Group query text by the schema key: the data_source when known, else the
    # language (the pool-by-language fallback). Each group tracks its language.
    groups: dict[tuple[str, str], list[str]] = {}  # (schema_name, language) -> queries
    for _det_id, _path, data in cat.iter_records():
        fmt = data.get("format", "")
        extractor = _FIELD_EXTRACTORS.get(fmt)
        if extractor is None:
            continue  # skips sigma and anything without a query-language extractor
        source = (data.get("data_source") or "").strip()
        schema_name = source or fmt  # fall back to language bucket
        original = data.get("original_path")
        if not original or not Path(original).is_file():
            continue
        try:
            query = Path(original).read_text(encoding="utf-8")
        except OSError:
            continue
        groups.setdefault((schema_name, fmt), []).append(query)

    if not groups:
        console.print("[yellow]No query-language rules in the catalog[/yellow] — nothing to generate.")
        return

    written = []
    fallback = []
    ts = _now_iso()
    for (schema_name, language), queries in sorted(groups.items()):
        extractor = _FIELD_EXTRACTORS[language]
        rule_fields: set[str] = set()
        for q in queries:
            rule_fields |= extractor(q)
        merged = merge_fields(rule_fields, {})  # rules-only; data filled later via `schema update`
        schema_obj = Schema(
            source=schema_name,
            query_language=language,
            last_rule_scan=ts,
            last_data_sample=None,
            sample_window=None,
            sample_size=None,
            fields=merged,
        )
        write_schema(schema_obj, schema_dir / f"{schema_name}.yml")
        written.append((schema_name, language, len(merged)))
        if schema_name == language:  # this group is the pooled-by-language fallback
            fallback.append(schema_name)

    console.print(f"[green]Generated {len(written)} schema(s) from the catalog:[/green]")
    for name, language, n_fields in written:
        tag = " [yellow](language fallback — un-inferred sources)[/yellow]" if name in fallback else ""
        console.print(f"  schema/{name}.yml  ({language}, {n_fields} fields){tag}")
    console.print("\nNext: pipe data to fill types/populations — `adef schema update <source> --results -`")
