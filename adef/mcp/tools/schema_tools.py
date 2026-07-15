"""MCP tools — schema management operations.

Exposes ``schema_show`` (display schema for a data source) and ``schema_init``
(initialize a new schema with field discovery). Each delegates to
``adef.commands.schema`` module functions to maintain consistency with CLI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from adef.core.schema import read_schema, write_schema, Schema, merge_fields
from adef.core.data_sampler import sample_data_from_json, sample_data_from_csv
from adef.core.llm_client import generate_field_descriptions


def _get_workspace_schema_dir(workspace: Optional[str]) -> Path:
    """Get workspace schema directory from env or arg."""
    if workspace:
        return Path(workspace) / "schema"
    import os
    workspace_path = Path(os.getenv("ADEF_WORKSPACE", Path.home() / "work" / "adef-workspace"))
    return workspace_path / "schema"


def register(server: Any) -> None:
    """Register schema tools on ``server`` (FastMCP instance)."""

    @server.tool()
    def schema_show(source: str, workspace: Optional[str] = None) -> dict[str, Any]:
        """Display schema for SOURCE (field inventory, types, populations)."""
        schema_dir = _get_workspace_schema_dir(workspace)
        schema_path = schema_dir / f"{source}.yml"

        if not schema_path.exists():
            return {"error": f"Schema not found: {source}"}

        try:
            schema_obj = read_schema(schema_path)
        except Exception as exc:
            return {"error": f"Failed to read schema: {str(exc)}"}

        fields_summary = []
        for field in schema_obj.fields:
            fields_summary.append({
                "name": field.name,
                "type": field.type,
                "population": f"{int(field.population * 100)}%",
                "in_rules": field.in_rules,
                "in_data": field.in_data,
                "description": field.description,
            })

        return {
            "source": schema_obj.source,
            "query_language": schema_obj.query_language,
            "last_rule_scan": schema_obj.last_rule_scan,
            "last_data_sample": schema_obj.last_data_sample,
            "total_fields": len(schema_obj.fields),
            "fields": fields_summary,
        }

    @server.tool()
    def schema_init(
        source: str,
        query_language: str,
        data_sample: str = "",
        rule_root: Optional[str] = None,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Initialize a new schema for SOURCE with optional data sample.

        Args:
            source: Data source name (e.g., 'crowdstrike', 'splunk_main')
            query_language: Query language ('sql', 'spl', 'cql', 'kql')
            data_sample: Optional JSON or CSV data sample for field discovery
            rule_root: Optional path to rules directory for field extraction
            workspace: Optional workspace path override

        Returns:
            Dict with schema path and summary.
        """
        if query_language.lower() not in ("sql", "spl", "cql", "kql"):
            return {
                "error": f"Invalid query_language {query_language!r}. Expected one of: sql, spl, cql, kql"
            }

        schema_dir = _get_workspace_schema_dir(workspace)
        schema_dir.mkdir(parents=True, exist_ok=True)
        schema_path = schema_dir / f"{source}.yml"

        if schema_path.exists():
            return {"error": f"Schema already exists: {source}"}

        # Extract fields from data sample if provided
        data_fields = {}
        sample_size = None
        last_data_sample = None

        if data_sample:
            try:
                data_fields = sample_data_from_json(data_sample)
                sample_size = len(json.loads(data_sample))
                from datetime import datetime, timezone
                last_data_sample = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
            except json.JSONDecodeError:
                try:
                    data_fields = sample_data_from_csv(data_sample)
                    sample_size = len(data_sample.strip().split("\n")) - 1  # minus header
                    from datetime import datetime, timezone
                    last_data_sample = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
                except Exception as exc:
                    return {"error": f"Failed to parse data sample: {str(exc)}"}

        # Merge and generate descriptions
        rule_fields = set()  # TODO: implement rule parsing if rule_root provided
        merged_fields = merge_fields(rule_fields, data_fields)

        if merged_fields:
            try:
                descriptions = generate_field_descriptions(
                    merged_fields, query_language.lower(), source
                )
                for field in merged_fields:
                    field.description = descriptions.get(field.name, "")
            except Exception as exc:
                # Log warning but don't fail — descriptions are optional
                pass

        # Create and write schema
        schema_obj = Schema(
            source=source,
            query_language=query_language.lower(),
            last_rule_scan=None,
            last_data_sample=last_data_sample,
            sample_window=None,
            sample_size=sample_size,
            fields=merged_fields,
        )

        try:
            write_schema(schema_obj, schema_path)
        except Exception as exc:
            return {"error": f"Failed to write schema: {str(exc)}"}

        return {
            "source": source,
            "path": str(schema_path),
            "query_language": query_language,
            "total_fields": len(merged_fields),
            "fields_from_data": sum(1 for f in merged_fields if f.in_data),
            "fields_from_rules": sum(1 for f in merged_fields if f.in_rules),
        }


__all__ = ["register"]
