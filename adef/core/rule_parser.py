"""Rule parsing to extract field names from SQL/SPL/CQL/KQL/Sigma queries."""

from __future__ import annotations

import re
from typing import Any

import sqlglot
import yaml
from sqlglot import exp


# Tried in order after the requested dialect when it can't parse a query.
# Snowflake/Databricks cover warehouse SQL (`col:path` JSON access) that the
# ClickHouse grammar rejects — 70 of the 95 scheduled queries in the public
# panther-analysis corpus came back with no fields at all.
_SQL_FALLBACK_DIALECTS = ("snowflake", "databricks")


def _parse_sql(query: str, dialect: str) -> Any:
    """``sqlglot.parse_one`` in ``dialect``, then each fallback dialect; raises
    the first dialect's error if none parses."""
    first: Exception | None = None
    for d in dict.fromkeys((dialect, *_SQL_FALLBACK_DIALECTS)):
        try:
            return sqlglot.parse_one(query, dialect=d)
        except Exception as exc:  # noqa: BLE001 — sqlglot raises several types
            first = first or exc
    assert first is not None
    raise first


def extract_sql_fields(query: str, dialect: str = "clickhouse") -> set[str]:
    """Extract all column references from SQL query using AST.

    Args:
        query: SQL query string
        dialect: SQL dialect (clickhouse, postgres, mysql, etc.)

    Returns:
        Set of field names referenced in the query

    The default is ``clickhouse``, not ``postgres``: streaming SQL rules are
    often stored as a bare WHERE predicate (no SELECT), and SQL engines that
    index nested or flattened events use backtick-quoted dotted identifiers
    (``\\`process.command_line\\```). Postgres's grammar rejects both and
    ``parse_one`` throws, silently returning an empty set — so ``schema check``
    would see *zero* fields and pass a rule with a typo'd column. ClickHouse's
    grammar accepts both and extracts the same columns as Postgres on standard
    SELECT/JOIN/quoted-identifier queries.
    """
    try:
        parsed = _parse_sql(query, dialect)
        fields = set()

        # Walk AST and collect all Column nodes
        for node in parsed.walk():
            if isinstance(node, exp.Column):
                # Get field name (without table prefix for simplicity)
                field_name = node.name
                if field_name:
                    fields.add(field_name)

        return fields
    except Exception:
        # Parsing failed, return empty set
        # ponytail: log error to stderr in production
        return set()


def mask_literals(query: str, language: str, strings: bool = True) -> str:
    """Blank out string literals and comments, keeping positions and quotes.
    ``strings=False`` blanks comments only and leaves string contents intact.

    Field regexes then never match text *inside* a value or a comment (`has
    "Sign in was blocked"` is not a field `Sign`), and pipeline splitting never
    sees a `|` or an apostrophe that isn't syntax. Quote characters stay, so
    `Field="..."` still reads as a comparison. SPL single quotes delimit field
    NAMES, not strings, so SPL keeps them; KQL `@"..."` verbatim strings have
    no backslash escapes.
    """
    single_is_string = language != "spl"
    out: list[str] = []
    i, n = 0, len(query)
    while i < n:
        ch = query[i]
        two = query[i:i + 2]
        if language == "spl" and query.startswith("```", i):  # SPL comment
            j = query.find("```", i + 3)
            j = n if j < 0 else j + 3
            out.append(" " * (j - i))
            i = j
        elif language in ("kql", "cql") and two == "//":  # line comment
            j = query.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif language == "cql" and two == "/*":
            j = query.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(" " * (j - i))
            i = j
        elif ch == '"' or (ch == "'" and single_is_string):
            verbatim = language == "kql" and i > 0 and query[i - 1] == "@"
            out.append(ch)
            i += 1
            while i < n:
                c = query[i]
                if not verbatim and c == "\\" and i + 1 < n:
                    out.append(query[i:i + 2] if not strings else "  ")
                    i += 2
                    continue
                if c == ch:
                    if verbatim and query[i + 1:i + 2] == ch:  # "" inside @"..."
                        out.append(query[i:i + 2] if not strings else "  ")
                        i += 2
                        continue
                    break
                out.append(c if not strings or c == "\n" else " ")
                i += 1
            if i < n:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# SPL field extraction patterns
FIELD_COMPARISON_RE = re.compile(r'\b([a-z_][a-z0-9_.]*)\s*[=<>!]+', re.IGNORECASE)
SPL_IN_RE = re.compile(r'\b([a-z_][a-z0-9_.]*)\s+IN\s*\(', re.IGNORECASE)  # `field IN (a, b)`
# `in(field, ...)` — the eval/where FUNCTION; the word before it (if any) tells
# it apart from the `field IN (...)` operator.
SPL_IN_FUNC_RE = re.compile(
    r'(?:\b([a-z_][a-z0-9_.]*)\s+)?\bin\s*\(\s*([a-z_][a-z0-9_.]*)\s*,', re.IGNORECASE
)
_SPL_KEYWORDS = frozenset({"where", "not", "and", "or", "search", "if", "case", "eval", "by", "as"})


def _spl_in_fields(text: str) -> list[str]:
    """`field IN (...)` and `in(field, ...)` — never the keyword before a bare `in(`."""
    operator = [f for f in SPL_IN_RE.findall(text) if f.lower() not in _SPL_KEYWORDS]
    function = [arg for before, arg in SPL_IN_FUNC_RE.findall(text)
                if not before or before.lower() in _SPL_KEYWORDS]
    return operator + function
STATS_BY_RE = re.compile(r'\bby\s+([a-z_][a-z0-9_., ]+)', re.IGNORECASE)
TABLE_RE = re.compile(r'\btable\s+([a-z_][a-z0-9_., ]+)', re.IGNORECASE)
EVAL_RE = re.compile(r'\beval\s+\w+\s*=\s*([a-z_][a-z0-9_.]*)(?!\s*\()', re.IGNORECASE)
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
    fields = set(_spl_in_fields(query := mask_literals(query, "spl")))

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


# A filter function names the field it tests with `field=` (`in(field="FileName",
# values=[...])`, `regex("x", field=CommandLine)`).
_CQL_FILTER_FIELD_ARG_RE = re.compile(
    r'\b(?:in|regex|wildcard|cidr|match)\s*\(([^()]*)\)', re.IGNORECASE
)
_CQL_ASSIGN_RE = re.compile(r'([A-Za-z_][\w.]*)\s*:=')
_CQL_AS_RE = re.compile(r'\bas\s*=\s*"?([A-Za-z_][\w.]*)', re.IGNORECASE)
_CQL_NAMED_GROUP_RE = re.compile(r'\(\?<([A-Za-z_]\w*)>')
_CQL_FIELD_PARAM_RE = re.compile(r'\bfield\s*=\s*', re.IGNORECASE)
_CQL_FIELD_VALUE_RE = re.compile(r'"?(#?[A-Za-z_][\w.]*)')


def extract_cql_fields(query: str) -> set[str]:
    """Field names a CQL query compares, plus those its filter functions test.

    Only comparisons OUTSIDE any function call count: inside one,
    `name=value` is a parameter (`groupBy(..., function=count(as=cnt),
    limit=max)`, `bucket(span=1h)`), not a field.
    """
    masked = mask_literals(query, "cql")
    depth = [0] * (len(masked) + 1)
    level = 0
    for i, ch in enumerate(masked):
        if ch in "([":
            level += 1
        elif ch in ")]":
            level = max(level - 1, 0)
        depth[i + 1] = level
    fields: set[str] = set()
    for pattern in (CQL_FIELD_EQUALS_RE, CQL_FIELD_CONTAINS_RE):
        for m in pattern.finditer(masked):
            if depth[m.start()] == 0:
                fields.add(m.group(1))
    # `field="X"` values are string literals, so masking blanks them: find each
    # call in the masked text (never inside a comment or string) and read its
    # arguments from the same span of the raw text.
    for call in _CQL_FILTER_FIELD_ARG_RE.finditer(masked):
        start, end = call.span(1)
        for param in _CQL_FIELD_PARAM_RE.finditer(masked, start, end):  # real `field=` only
            value = _CQL_FIELD_VALUE_RE.match(query, param.end(), end)
            if value:
                fields.add(value.group(1))
    # Names the query creates aren't event fields: `x := ...`, a function's
    # `as=x`, a regex named group `(?<x>...)`. Filtering on one later
    # (`replace(..., as=cmd) | cmd=/enc/`) made `schema check` report it as a
    # missing field.
    # ponytail: order-blind — a field filtered on *before* being overwritten
    # under the same name is dropped too; track stages if that ever matters.
    created = set(_CQL_ASSIGN_RE.findall(masked))
    created |= {m.group(1) for m in _CQL_AS_RE.finditer(query)}
    created |= set(_CQL_NAMED_GROUP_RE.findall(query))
    return fields - created


# KQL field extraction patterns
KQL_FIELD_COMPARISON_RE = re.compile(r'\b([A-Z][a-zA-Z0-9_]*)\s*[=<>!]+', re.IGNORECASE)
KQL_PROJECT_RE = re.compile(r'\|\s*project\s+([A-Za-z0-9_., ]+)', re.IGNORECASE)
KQL_SUMMARIZE_BY_RE = re.compile(r'\|\s*summarize\s+.*\bby\s+([A-Za-z0-9_., ]+)', re.IGNORECASE)
# KQL's word operators — how most KQL detections actually filter
# (`FileName has "x"`, `Col in~ (...)`, `Path startswith "C:"`).
KQL_STRING_OP_RE = re.compile(
    r'\b([A-Z][a-zA-Z0-9_]*)\s+!?(?:has(?:_any|_all|prefix|suffix)?|contains|startswith|'
    r'endswith|in|matches\s+regex|between)(?:_cs)?~?(?=[\s("\'])',
    re.IGNORECASE,
)


def extract_kql_fields(query: str) -> set[str]:
    """Extract field names from KQL query.

    Args:
        query: Defender KQL query string

    Returns:
        Set of field names referenced in the query
    """
    fields = set()
    query = mask_literals(query, "kql")

    for pattern in [KQL_FIELD_COMPARISON_RE, KQL_STRING_OP_RE, KQL_PROJECT_RE, KQL_SUMMARIZE_BY_RE]:
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


# --------------------------------------------------------------------------- #
# Predicate-only extraction — the fields a rule FILTERS on.
#
# ``schema check`` wants every field a query names (a typo in a BY clause is a
# real bug), so it keeps the extractors above. Field-set retrieval compares
# detection *logic*, and logic is the predicate: two rules grouping or
# projecting the same columns say nothing about detecting the same thing. A
# Sigma ``detection:`` block is already predicate-only, so this also puts every
# language on the same footing as Sigma.
#
# Pipelines (SPL, KQL) are read stage by stage: a comparison counts only in a
# FILTER stage, and a name is excluded as an output only if a stage BEFORE the
# filter assigned it — `x=1 | eval x=lower(x)` still filters on the event
# field `x`, while `| eval p=lower(a) | where p="x"` filters on an output.
# --------------------------------------------------------------------------- #
_ASSIGN_RE = re.compile(r'^\s*([a-z_][a-z0-9_.]*)\s*=(?![=~])(.*)$', re.IGNORECASE | re.DOTALL)
_STAGE_CMD_RE = re.compile(r'\s*([A-Za-z][\w-]*)')
# Stages that create or rewrite fields a later filter can test.
_SPL_FIELD_PRODUCERS = frozenset({
    "eval", "rex", "lookup", "rename", "spath", "fillnull", "convert", "makemv",
    "mvexpand", "extract", "kv", "join", "append", "appendpipe", "eventstats",
    "streamstats", "transaction", "inputlookup",
})
_SPL_TSTATS_DATAMODEL_RE = re.compile(r'\bfrom\s+(datamodel\s*=\s*[^\s|]+)', re.IGNORECASE)
_SPL_TSTATS_WHERE_RE = re.compile(r'\bwhere\b(.*?)(?:\bby\b|$)', re.IGNORECASE | re.DOTALL)
_SPL_RENAME_RE = re.compile(r'"?([a-z_][a-z0-9_.]*)"?\s+as\s+"?([a-z_][a-z0-9_.]*)', re.IGNORECASE)
_KQL_RENAME_RE = re.compile(r'([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)')
_REX_GROUP_RE = re.compile(r'\(\?P?<([A-Za-z_]\w*)>')
_IDENT_RE = re.compile(r'\b([A-Za-z_]\w*)\b')
# Columns `summarize` names by default: count() -> count_, dcount(X) -> dcount_X, ...
_KQL_AGG_DEFAULT_RE = re.compile(
    r'^(?:count|countif|dcount|dcountif|sum|sumif|avg|avgif|min|max|stdev|variance|'
    r'percentiles?|make_set|make_list|arg_max|arg_min|take_any|any)_',
    re.IGNORECASE,
)


def _split_pipeline(query: str) -> list[str]:
    """Split on top-level ``|``. Run on ``mask_literals`` output, so quotes and
    comments are already inert; brackets and backtick macros still nest."""
    stages: list[str] = []
    buf: list[str] = []
    depth = 0
    in_macro = False
    for ch in query:
        if ch == "`":
            in_macro = not in_macro
        elif not in_macro and ch in "[(":
            depth += 1
        elif not in_macro and ch in "])":
            depth = max(depth - 1, 0)
        elif ch == "|" and depth == 0 and not in_macro:
            stages.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    stages.append("".join(buf))
    return stages


def _stages(query: str, language: str) -> list[tuple[str, str]]:
    """(masked, raw) text per pipeline stage. Masking keeps every position, so
    stage boundaries found on the masked text slice the raw text exactly."""
    masked = mask_literals(query, language)
    out: list[tuple[str, str]] = []
    pos = 0
    for stage in _split_pipeline(masked):
        out.append((stage, query[pos:pos + len(stage)]))
        pos += len(stage) + 1  # the `|`
    return out


def _split_top_commas(text: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(depth - 1, 0)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def _assigned_names(text: str) -> set[str]:
    """Names an eval/extend-style stage creates. `X = f(X)` is a normalisation
    of the event field X, not a new output, so it isn't counted."""
    out: set[str] = set()
    for part in _split_top_commas(text):
        m = _ASSIGN_RE.match(part)
        if m and not re.search(rf'\b{re.escape(m.group(1))}\b', m.group(2)):
            out.add(m.group(1))
    return out


def _stage(text: str) -> tuple[str, str]:
    """(command, rest) for one pipeline stage; command is lowercased."""
    m = _STAGE_CMD_RE.match(text)
    if not m:
        return "", text
    return m.group(1).lower(), text[m.end():]


class _Outputs:
    """Names created so far in a pipeline, and renames back to event fields."""

    def __init__(self) -> None:
        self.assigned: set[str] = set()
        self.renamed: dict[str, str] = {}

    def rename(self, old: str, new: str) -> None:
        if old in self.assigned:  # renaming an output leaves an output
            self.assigned.add(new)
        else:
            self.renamed[new] = self.renamed.get(old, old)

    def resolve(self, found: list[str]) -> set[str]:
        return {self.renamed.get(f, f) for f in found if f not in self.assigned}


def extract_spl_predicate_fields(query: str) -> set[str]:
    """SPL fields compared in filter stages — the base search, ``search``,
    ``where``, ``regex`` and a ``tstats ... WHERE`` clause. Not BY/table/fields
    lists, command parameters, or names an earlier stage created."""
    fields: set[str] = set()
    outs = _Outputs()
    for n, (text, raw) in enumerate(_stages(query, "spl")):
        cmd, rest = _stage(text)
        if n == 0:
            filt = text  # the base search is an implicit `search`
        elif cmd in ("search", "where", "regex"):
            filt = rest
        elif cmd == "tstats":
            m = _SPL_TSTATS_WHERE_RE.search(rest)
            filt = m.group(1) if m else ""
        else:
            filt = ""
        if filt:
            fields |= outs.resolve(FIELD_COMPARISON_RE.findall(filt) + _spl_in_fields(filt))
        if cmd == "eval":
            outs.assigned |= _assigned_names(rest)
        elif cmd in ("stats", "eventstats", "streamstats", "tstats", "chart", "timechart"):
            outs.assigned |= _spl_derived_fields("| " + text)
        elif cmd == "rename":
            for old, new in _SPL_RENAME_RE.findall(rest):
                outs.rename(old, new)
        elif cmd == "rex":
            outs.assigned.update(_REX_GROUP_RE.findall(raw))  # groups sit in the masked regex string
    return fields


def spl_filter_text(query: str) -> str:
    """The raw text of an SPL query's filter stages — the base search,
    ``search``/``where``/``regex``, and a ``tstats ... WHERE`` clause — joined
    with `` | ``. What the rule *selects on*, without the ESCU scaffolding
    (``tstats`` data-model plumbing, BY lists, ``security_content_*`` and
    ``drop_dm_object_name`` macros, the trailing ``*_filter`` macro) that
    every rule repeats and that dominates a whole-query text comparison."""
    parts: list[str] = []
    produced = False
    for n, (text, raw) in enumerate(_stages(query, "spl")):
        cmd, rest = _stage(text)
        if n == 0:
            span: tuple[int, int] | None = (0, len(text))
        elif cmd in ("search", "where", "regex"):
            if produced:
                # The filter may test a field an earlier stage built
                # (`eval flagged=if(...) | where flagged=1`); without that
                # stage the text says nothing. Caller falls back to the query.
                return ""
            span = (len(text) - len(rest), len(text))
        elif cmd == "tstats":
            # The dataset is part of what the rule selects: the same WHERE over
            # Endpoint.Registry and Endpoint.Processes is two different rules.
            ds = _SPL_TSTATS_DATAMODEL_RE.search(text)
            if ds:
                parts.append(raw[ds.start(1):ds.end(1)].strip())
            m = _SPL_TSTATS_WHERE_RE.search(text)
            span = m.span(1) if m else None
        else:
            produced = produced or cmd in _SPL_FIELD_PRODUCERS
            span = None
        if span and raw[span[0]:span[1]].strip():
            # Keep the command: `regex _raw="^x"` and `search _raw="^x"` differ.
            prefix = f"{cmd} " if n and cmd in ("search", "where", "regex") else ""
            parts.append(prefix + raw[span[0]:span[1]].strip())
    return " | ".join(parts)


_KQL_FILTER_CMDS = ("where", "filter", "search")


def extract_kql_predicate_fields(query: str) -> set[str]:
    """KQL fields compared in ``where``/``filter``/``search`` stages — not
    ``project``/``summarize by`` lists or names an earlier stage created."""
    fields: set[str] = set()
    outs = _Outputs()
    summarized = False
    for text, _raw in _stages(query, "kql"):
        cmd, rest = _stage(text)
        if cmd in _KQL_FILTER_CMDS:
            found = KQL_FIELD_COMPARISON_RE.findall(rest) + KQL_STRING_OP_RE.findall(rest)
            if summarized:
                found = [f for f in found if not _KQL_AGG_DEFAULT_RE.match(f)]
            fields |= outs.resolve(found)
        elif cmd == "project-rename":
            for new, old in _KQL_RENAME_RE.findall(rest):
                outs.rename(old, new)
        elif cmd in ("extend", "project"):
            outs.assigned |= _assigned_names(rest)
        elif cmd == "summarize":
            outs.assigned |= _assigned_names(re.split(r'\bby\b', rest, maxsplit=1)[0])
            summarized = True
        elif cmd == "parse":
            pattern = re.split(r'\bwith\b', rest, maxsplit=1)
            if len(pattern) == 2:  # outputs are the bare names in the pattern
                outs.assigned |= set(_IDENT_RE.findall(pattern[1]))
    return fields


def _is_predicate_column(col: exp.Column) -> bool:
    """Is ``col`` read by a predicate (WHERE / PREWHERE / HAVING / JOIN ON)?

    Walk up to the nearest predicate scope or query. Reaching a SELECT first
    means a projection, GROUP BY or ORDER BY — including a subquery's SELECT
    list inside an outer WHERE. Reaching the root first means a bare predicate
    (no SELECT at all), which is all predicate.
    """
    node: Any = col
    while node.parent is not None:
        parent = node.parent
        if isinstance(parent, (exp.Where, exp.PreWhere, exp.Having)):
            return True
        if isinstance(parent, exp.Join) and node.arg_key == "on":
            return True
        if isinstance(parent, exp.Select):
            return False
        node = parent
    return True


def extract_sql_predicate_fields(query: str, dialect: str = "clickhouse") -> set[str]:
    """SQL columns a predicate reads — not SELECT lists (outer or nested),
    GROUP BY, ORDER BY, or a SELECT alias referenced from HAVING/WHERE."""
    try:
        parsed = _parse_sql(query, dialect)
    except Exception:
        return set()
    aliases = {
        a.alias for a in parsed.find_all(exp.Alias)
        if not (isinstance(a.this, exp.Column) and a.this.name == a.alias)
    }
    return {
        c.name for c in parsed.find_all(exp.Column)
        if c.name and c.name not in aliases and _is_predicate_column(c)
    }


def extract_cql_predicate_fields(query: str) -> set[str]:
    """CQL comparisons, minus ``#``-prefixed tag fields.

    LogScale tag fields (``#event_simpleName``, ``#repo``) select the
    datasource/partition a query reads — routing, the CQL counterpart of SPL's
    ``sourcetype``.
    """
    return {f for f in extract_cql_fields(query) if not f.startswith("#")}


# Field extractors keyed by the record's ``query_language``, falling back to
# ``format`` (see ``field_extractor_key``). Sigma has no query language — it's
# keyed by format, and its fields are the ``detection:`` block's map keys.
# The one copy both ``adef schema check`` and field-set retrieval route through.
FIELD_EXTRACTORS = {
    "sql": extract_sql_fields,
    "spl": extract_spl_fields,
    "cql": extract_cql_fields,
    "kql": extract_kql_fields,
    "sigma": extract_sigma_fields,
}

# Same keys, predicate-only — what field-set retrieval indexes.
PREDICATE_FIELD_EXTRACTORS = {
    "sql": extract_sql_predicate_fields,
    "spl": extract_spl_predicate_fields,
    "cql": extract_cql_predicate_fields,
    "kql": extract_kql_predicate_fields,
    "sigma": extract_sigma_fields,
}

# Routing/meta pseudo-fields, per language — they address data rather than
# describe events, so no declaration would (or should) list them, and two rules
# sharing them say nothing about sharing logic. Per language because the same
# word is an ordinary column elsewhere: `host`, `window` and `field` are
# routing or command parameters in SPL and plain fields in SQL or Sigma.
#
# SPL: default/indexed fields; command parameters the regex extractor captures
# as field=value (`bin _time span=10m`, `head limit=5`, `rex field=_raw`); and
# data-model addressing (`tstats ... FROM datamodel=Endpoint.Processes`), the
# CIM equivalent of `index`/`sourcetype`. Other languages have none today.
ROUTING_FIELDS: dict[str, frozenset[str]] = {
    "spl": frozenset({
        "index", "sourcetype", "source", "host", "earliest", "latest", "_time",
        "span", "limit", "maxspan", "maxpause", "window", "keepevicted", "field",
        "datamodel", "nodename",
    }),
}


def routing_fields(language: str) -> frozenset[str]:
    """Lowercased routing pseudo-fields for a ``FIELD_EXTRACTORS`` key."""
    return ROUTING_FIELDS.get(language, frozenset())


def field_extractor_key(record: dict) -> str:
    """The ``FIELD_EXTRACTORS`` key for a catalog record, or ``""`` if none applies.

    ``format`` is consulted only when ``query_language`` is absent/empty — never
    merely because ``query_language`` names something unsupported, so a record
    tagged ``query_language: eql, format: sigma`` has no extractor.
    """
    from adef.core.rule_discovery import _FORMAT_TO_QUERY_LANGUAGE  # discovery imports this module's peers

    fmt = str(record.get("format") or "")
    # A source format resolves to its language the way discovery derives it
    # (`splunk-escu` carries SPL) — a record that lost `query_language` must
    # not read as a language of its own.
    key = str(record.get("query_language") or _FORMAT_TO_QUERY_LANGUAGE.get(fmt, fmt))
    return key if key in FIELD_EXTRACTORS else ""
