"""Rule parsing to extract field names from SQL/SPL/CQL/KQL/Sigma queries."""

from __future__ import annotations

import re

import sqlglot
import yaml
from sqlglot.expressions import Column


def extract_sql_fields(query: str, dialect: str = "clickhouse") -> set[str]:
    """Extract all column references from SQL query using AST.

    Args:
        query: SQL query string
        dialect: SQL dialect (clickhouse, postgres, mysql, etc.)

    Returns:
        Set of field names referenced in the query

    The default is ``clickhouse``, not ``postgres``: ADEF's ``sql`` engine is
    Nebulock's dialect (see ``rule_discovery`` — atomic/scheduled_sql), whose
    queries are a bare WHERE predicate over backtick-dotted identifiers
    (``\\`process.command_line\\```). Postgres's grammar rejects both and
    ``parse_one`` throws, silently returning an empty set — so ``schema check``
    would see *zero* fields and pass a rule with a typo'd column. ClickHouse is
    a strict superset here: it recovers the Nebulock case and extracts the same
    columns as Postgres on standard SELECT/JOIN/quoted-identifier queries.
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
# Aggregation segments create OUTPUT fields (`count`, `... as total`) that later
# clauses reference (`| where count > 20`) — they aren't event fields and must
# not surface as schema-check findings.
_AGG_SEGMENT_RE = re.compile(
    r'\|\s*(?:stats|eventstats|streamstats|tstats|chart|timechart)\b([^|]*)', re.IGNORECASE
)
_AGG_AS_RE = re.compile(r'\bas\s+([a-z_][a-z0-9_.]*)', re.IGNORECASE)
_AGG_BARE_COUNT_RE = re.compile(r'\bcount\b(?!\s*\()', re.IGNORECASE)


def _spl_derived_fields(query: str) -> set[str]:
    """Names created by aggregation commands, not read from events."""
    derived: set[str] = set()
    for segment in _AGG_SEGMENT_RE.findall(query):
        # `by` fields inside the segment ARE event fields — only look before `by`
        segment = re.split(r'\bby\b', segment, maxsplit=1, flags=re.IGNORECASE)[0]
        derived.update(_AGG_AS_RE.findall(segment))
        if _AGG_BARE_COUNT_RE.search(segment):
            derived.add("count")
    return derived


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

    # Aggregation outputs (`count`, `as total`) are created by the query,
    # not read from events — never report them as event-field usage.
    return fields - _spl_derived_fields(query)


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


def _sigma_fields_from_identifier(value: object, out: set[str]) -> None:
    """Collect field keys from one Sigma search-identifier value.

    An identifier is a map of ``field|modifier: value`` (fields = the keys), a
    list of such maps, or a bare list of keyword strings (no fields at all).
    Map keys are stripped of ``|modifier`` suffixes (``CommandLine|contains``
    → ``CommandLine``). Value-only modifiers (``|all``) and pure keyword lists
    contribute no field names.
    """
    if isinstance(value, dict):
        for key in value:
            name = str(key).split("|", 1)[0].strip()
            if name:
                out.add(name)
    elif isinstance(value, list):
        for item in value:
            _sigma_fields_from_identifier(item, out)  # list of maps (OR-ed)


def extract_sigma_fields(query: str) -> set[str]:
    """Extract event-field names from a Sigma rule's ``detection:`` block.

    Sigma has no query language — its fields are the map keys of each
    search-identifier under ``detection:`` (``condition`` is boolean logic over
    identifier *names*, not a field source, so it's skipped). Returns an empty
    set on unparseable YAML or a rule with no ``detection`` map.
    """
    try:
        data = yaml.safe_load(query)
    except yaml.YAMLError:
        return set()
    if not isinstance(data, dict):
        return set()
    detection = data.get("detection")
    if not isinstance(detection, dict):
        return set()

    fields: set[str] = set()
    for name, value in detection.items():
        if name == "condition":  # boolean logic over identifier names, not fields
            continue
        _sigma_fields_from_identifier(value, fields)
    return fields
