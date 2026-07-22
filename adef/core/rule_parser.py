"""Rule parsing to extract field names from SQL/SPL/CQL/KQL queries."""

from __future__ import annotations

import re

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


# SPL field extraction patterns
FIELD_COMPARISON_RE = re.compile(r'\b([a-z_][a-z0-9_.]*)\s*[=<>!]+', re.IGNORECASE)
STATS_BY_RE = re.compile(r'\bby\s+([a-z_][a-z0-9_., ]+)', re.IGNORECASE)
TABLE_RE = re.compile(r'\btable\s+([a-z_][a-z0-9_., ]+)', re.IGNORECASE)
EVAL_RE = re.compile(r'\beval\s+\w+\s*=\s*([a-z_][a-z0-9_.]*)', re.IGNORECASE)
FIELDS_RE = re.compile(r'\bfields\s+[+-]?\s*([a-z_][a-z0-9_., ]+)', re.IGNORECASE)
RENAME_RE = re.compile(r'\brename\s+([a-z_][a-z0-9_.]*)', re.IGNORECASE)


def extract_spl_fields(query: str) -> set[str]:
    """Extract field names from SPL query using enhanced regex.

    Args:
        query: Splunk SPL query string

    Returns:
        Set of field names referenced in the query
    """
    fields = set()

    # Apply all patterns
    for pattern in [FIELD_COMPARISON_RE, STATS_BY_RE, TABLE_RE,
                    EVAL_RE, FIELDS_RE, RENAME_RE]:
        matches = pattern.findall(query)
        for match in matches:
            # SPL lists are comma- or space-separated (e.g. `by src_ip dest_ip`)
            for field in re.split(r'[,\s]+', match):
                field = field.strip()
                if field and not field.isdigit():  # Skip numeric values
                    fields.add(field)

    return fields


# CQL field extraction patterns
CQL_FIELD_EQUALS_RE = re.compile(r'(#?[A-Z][a-zA-Z0-9_]*)\s*[=!]', re.IGNORECASE)
CQL_FIELD_CONTAINS_RE = re.compile(r'(#?[A-Z][a-zA-Z0-9_]*)\s+(?:contains|like)', re.IGNORECASE)


def extract_cql_fields(query: str) -> set[str]:
    """Extract field names from CQL query.

    Args:
        query: CrowdStrike CQL query string

    Returns:
        Set of field names referenced in the query
    """
    fields = set()

    for pattern in [CQL_FIELD_EQUALS_RE, CQL_FIELD_CONTAINS_RE]:
        matches = pattern.findall(query)
        fields.update(matches)

    return fields


# KQL field extraction patterns
KQL_FIELD_COMPARISON_RE = re.compile(r'\b([A-Z][a-zA-Z0-9_]*)\s*[=<>!]+', re.IGNORECASE)
KQL_PROJECT_RE = re.compile(r'\|\s*project\s+([A-Za-z0-9_., ]+)', re.IGNORECASE)
KQL_SUMMARIZE_BY_RE = re.compile(r'\|\s*summarize\s+.*\bby\s+([A-Za-z0-9_., ]+)', re.IGNORECASE)


def extract_kql_fields(query: str) -> set[str]:
    """Extract field names from KQL query.

    Args:
        query: Defender KQL query string

    Returns:
        Set of field names referenced in the query
    """
    fields = set()

    for pattern in [KQL_FIELD_COMPARISON_RE, KQL_PROJECT_RE, KQL_SUMMARIZE_BY_RE]:
        matches = pattern.findall(query)
        for match in matches:
            for field in re.split(r'[,\s]+', match):
                field = field.strip()
                if field and not field.isdigit():
                    fields.add(field)

    return fields
