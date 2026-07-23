"""MCP tools — declaration-driven schema operations.

Exposes ``schema_show`` (render a schema_version-2 schema), ``schema_ingest``
(build schemas from a data-source declaration file), and ``schema_recipe``
(generate SIEM-specific field extraction recipes). All delegate to
``adef.core.*`` — the same engine the CLI uses — so MCP and CLI never drift.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Optional

import yaml

from adef.core.declaration import (
    DeclarationError,
    ingest_source,
    lint_declaration_dict,
    load_declaration,
    read_schema_v2,
)
from adef.core.recipes import get_recipe, list_platforms, render_recipe_markdown


def _get_workspace_schema_dir(workspace: Optional[str]) -> Path:
    """Workspace schema dir via the canonical resolver (ISA 2026-07-22)."""
    from adef.core.workspace import resolve_workspace

    return resolve_workspace(Path(workspace) if workspace else None) / "schema"


def register(server: Any) -> None:
    """Register schema tools on ``server`` (FastMCP instance)."""

    @server.tool()
    def schema_show(source: str, workspace: Optional[str] = None) -> dict[str, Any]:
        """Display the declared schema for SOURCE (fields, types, aliases, values)."""
        schema_path = _get_workspace_schema_dir(workspace) / f"{source}.yml"
        if not schema_path.exists():
            return {"error": f"Schema not found: {source}"}
        data = read_schema_v2(schema_path)
        if data is None:
            return {
                "error": f"{schema_path.name} is not a schema_version-2 file — "
                "re-create it with `adef schema ingest <declaration.yml>`."
            }
        return data

    @server.tool()
    def schema_ingest(
        declaration_path: str, workspace: Optional[str] = None
    ) -> dict[str, Any]:
        """Build schemas from a data-source declaration file (adef-sources.yml).

        Writes one ``schema/<source>.yml`` (schema_version 2) per declared
        source. Re-ingest replaces declared fields, preserves human
        ``corrected`` fields, and reports drift per source.
        """
        schema_dir = _get_workspace_schema_dir(workspace)
        try:
            sources = load_declaration(Path(declaration_path))
        except DeclarationError as exc:
            return {"error": str(exc)}

        results = []
        for src in sources:
            path, drift = ingest_source(src, schema_dir)
            results.append(
                {
                    "source": src.name,
                    "path": str(path),
                    "declared_fields": len(src.fields),
                    "corrected_kept": drift.corrected_kept,
                    "drift": {
                        "added": drift.added,
                        "removed": drift.removed,
                        "type_changed": drift.type_changed,
                    },
                }
            )
        return {"ingested": results}

    @server.tool()
    def schema_recipe(platform: Optional[str] = None) -> dict[str, Any]:
        """Generate SIEM-specific field extraction recipe.

        Args:
            platform: SIEM platform name (splunk, sentinel, elastic, chronicle,
                      sumo, qradar, other). If None, reads from workspace config.

        Returns:
            Recipe with command, export format, and markdown guide.
        """
        # If no platform provided, try to read from workspace config
        if not platform:
            from adef.core.workspace import platform_from_config, resolve_workspace

            platform = platform_from_config(resolve_workspace(None))
            if not platform:
                # No silent default: guessing splunk would hand a Sentinel user SPL.
                return {
                    "error": "No platform configured. Pass a platform explicitly, "
                    "or run `adef init --interactive` to set one.",
                    "platforms": list_platforms(),
                }

        try:
            recipe_obj = get_recipe(platform)
        except ValueError as exc:
            return {"error": str(exc)}

        result = dataclasses.asdict(recipe_obj)
        result["recipe_markdown"] = render_recipe_markdown(recipe_obj)

        return result

    @server.tool()
    def schema_reshape(
        export_path: str,
        platform: Optional[str] = None,
        source_name: Optional[str] = None,
        no_fold: Optional[list[str]] = None,
        output_path: Optional[str] = None,
    ) -> dict[str, Any]:
        """Convert a raw SIEM field export into a draft declaration file.

        Applies the five reshape rules (internals filter, case-dupes → aliases,
        capped enum harvesting, type inference, mixed-shape guard) and returns
        the transformation report, including SUSPECT merges with per-spelling
        value evidence so the caller can adjudicate keep-vs-split. Split a
        vetoed merge by re-calling with the variant name in ``no_fold``.

        Args:
            export_path: Raw export file (Splunk fieldsummary CSV, Sentinel
                         getschema CSV, Elastic _mapping JSON, or a plain
                         one-field-per-line list).
            platform: splunk | sentinel | elastic | ... If None, read from
                      workspace config.
            source_name: Declared source name (default: derived from the export).
            no_fold: Field spellings to exempt from case-folding.
            output_path: Where to write the declaration (default:
                         <source>-sources.yml next to the export).
        """
        from adef.core.reshape import ReshapeError, reshape_export
        from adef.core.workspace import platform_from_config, resolve_workspace

        if not platform:
            platform = platform_from_config(resolve_workspace(None))
            if not platform:
                return {
                    "error": "No platform given or configured. Pass a platform, "
                    "or run `adef init --interactive`.",
                    "platforms": list_platforms(),
                }

        export = Path(export_path).expanduser()
        if not export.is_file():
            return {"error": f"export not found: {export}"}
        try:
            result = reshape_export(export, platform, source_name, tuple(no_fold or ()))
        except ReshapeError as exc:
            return {"error": str(exc)}

        src = result.declaration["sources"][0]
        out = (
            Path(output_path).expanduser()
            if output_path
            else export.parent / f"{src['name']}-sources.yml"
        )
        out.write_text(
            yaml.safe_dump(result.declaration, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        report = result.report
        return {
            "output_path": str(out),
            "source": src["name"],
            "fields_declared": len(src["fields"]),
            "scope": src.get("scope", {}),
            "report": {
                "dropped_internals": report.dropped_internals,
                "folded_aliases": report.folded_aliases,
                "suspect_merges": report.suspect_folds,
                "suspect_evidence": report.fold_evidence,
                "enum_fields": len(report.enum_fields),
                "typed_fields": report.typed_fields,
                "notes": report.notes,
            },
        }

    @server.tool()
    def schema_lint_declaration(content: str) -> dict[str, Any]:
        """Validate ADEF data source declaration YAML.

        Args:
            content: YAML declaration content as string

        Returns:
            Validation result with errors and warnings.
        """
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            return {
                "valid": False,
                "errors": [f"YAML parse error: {exc}"],
                "warnings": [],
            }

        errors, warnings = lint_declaration_dict(data)

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    @server.tool()
    def schema_list_platforms() -> dict[str, Any]:
        """List supported SIEM platforms for recipe generation."""
        return {"platforms": list_platforms()}


__all__ = ["register"]
