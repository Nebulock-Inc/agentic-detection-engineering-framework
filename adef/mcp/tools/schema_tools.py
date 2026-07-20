"""MCP tools — declaration-driven schema operations.

Exposes ``schema_show`` (render a schema_version-2 schema) and
``schema_ingest`` (build schemas from a data-source declaration file). Both
delegate to ``adef.core.declaration`` — the same engine the CLI uses — so MCP
and CLI can never drift. The former sample/LLM-based ``schema_init`` tool was
removed with the rules-derived schema model (ISA 2026-07-20).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from adef.core.declaration import (
    DeclarationError,
    ingest_source,
    load_declaration,
    read_schema_v2,
)


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


__all__ = ["register"]
