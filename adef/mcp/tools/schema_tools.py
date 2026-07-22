"""MCP tools — declaration-driven schema operations.

Exposes ``schema_show`` (render a schema_version-2 schema), ``schema_ingest``
(build schemas from a data-source declaration file), and ``schema_recipe``
(generate SIEM-specific field extraction recipes). All delegate to
``adef.core.*`` — the same engine the CLI uses — so MCP and CLI never drift.
"""

from __future__ import annotations

import dataclasses
import os
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
    """Get workspace schema directory from env or arg."""
    if workspace:
        return Path(workspace) / "schema"
    workspace_path = Path(os.getenv("ADEF_WORKSPACE", Path.home() / "work" / "adef-workspace"))
    return workspace_path / "schema"


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
