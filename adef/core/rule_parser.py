"""Rule parsing to extract field names from SQL/SPL/CQL/KQL queries."""

from __future__ import annotations

import sqlglot
from sqlglot.expressions import Column


def extract_sql_fields(query: str, dialect: str = "postgres") -> set[str]:
    """Extract all column references from SQL query using AST.

    Args:
        query: SQL query string
        dialect: SQL dialect (postgres, mysql, clickhouse, etc.)

    Returns:
        Set of field names referenced in the query
    """
    try:
        parsed = sqlglot.parse_one(query, dialect=dialect)
        fields = set()

        # Walk AST and collect all Column nodes
        for node in parsed.walk():
            if isinstance(node, Column):
                # Get field name (without table prefix for simplicity)
                field_name = node.name
                if field_name:
                    fields.add(field_name)

        return fields
    except Exception:
        # Parsing failed, return empty set
        # ponytail: log error to stderr in production
        return set()
