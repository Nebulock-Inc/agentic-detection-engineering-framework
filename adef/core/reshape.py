"""Reshape a raw SIEM field export into a draft data-source declaration.

Implements the five reshape rules specified in docs/2026-07-21-next-steps.md §5
(distilled from hand-converting live Splunk exports):

1. Internals filter — drop platform plumbing (``_*``, ``date_*``, ``punct``,
   routing metadata) so junk never becomes a "declared field".
2. Case-dupes → aliases — one identity per field; other casings recorded as
   ``aliases``.
3. Enum harvesting with caps — low-cardinality observed values become
   ``values:`` (authoring grounding), value length capped so log blobs never
   masquerade as enum members.
4. Type inference — numeric/hex populations get real types instead of
   everything-is-string.
5. Mixed-shape guard — an export that mixes event shapes (multi-sourcetype
   index) is refused with re-export guidance, never guessed at.

Every transformation is recorded in a :class:`ReshapeReport` so the human
approves the *transformations*, not a wall of YAML. This is the "results-in
seam" from the ISA Schema Storage decision (2026-07-15): the user runs the
export; ADEF never connects to a SIEM.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

ENUM_MAX_DISTINCT = 20  # ponytail: fixed caps; make configurable if a real corpus demands it
ENUM_MAX_VALUE_LEN = 64

# Fields that are platform plumbing, never detection-grounding surface.
_INTERNAL_PREFIXES = ("_", "date_")
_INTERNAL_NAMES = {
    "punct",
    "splunk_server",
    "linecount",
    "timeendpos",
    "timestartpos",
    "index",
    "sourcetype",
    "source",
    "host",
}

_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")

_KQL_TYPE_MAP = {
    "string": "string",
    "guid": "string",
    "int": "int",
    "long": "int",
    "real": "float",
    "decimal": "float",
    "datetime": "datetime",
    "bool": "bool",
    "boolean": "bool",
    "dynamic": "object",
}

_ELASTIC_TYPE_MAP = {
    "keyword": "string",
    "text": "string",
    "wildcard": "string",
    "constant_keyword": "string",
    "long": "int",
    "integer": "int",
    "short": "int",
    "byte": "int",
    "double": "float",
    "float": "float",
    "half_float": "float",
    "scaled_float": "float",
    "date": "datetime",
    "boolean": "bool",
    "ip": "ip",
    "object": "object",
    "nested": "object",
    "flattened": "object",
}


class ReshapeError(Exception):
    """Raised when the export cannot be reshaped without guessing."""


@dataclass
class RawField:
    name: str
    type_hint: str | None = None  # declared type from the export, if any
    total_count: int | None = None
    distinct_count: int | None = None
    numeric_count: int | None = None
    values: list[str] = field(default_factory=list)


@dataclass
class ReshapeReport:
    dropped_internals: list[str] = field(default_factory=list)
    folded_aliases: dict[str, list[str]] = field(default_factory=dict)
    enum_fields: list[str] = field(default_factory=list)
    typed_fields: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class ReshapeResult:
    declaration: dict
    report: ReshapeReport


# --------------------------------------------------------------------------- #
# Parsers — one per export format ADEF knows how to read deterministically
# --------------------------------------------------------------------------- #
def _int_or_none(value: str | None) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def _parse_splunk_csv(path: Path) -> list[RawField]:
    """Splunk ``| fieldsummary`` CSV (field, count, distinct_count,
    numeric_count, values). Only ``field`` is required; the distribution
    columns unlock enum harvesting, typing, and the mixed-shape guard."""
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or "field" not in reader.fieldnames:
            raise ReshapeError(
                f"{path.name}: expected a fieldsummary CSV with a 'field' column "
                "(see `adef schema recipe splunk` for the export command)"
            )
        out = []
        for row in reader:
            name = (row.get("field") or "").strip()
            if not name:
                continue
            values: list[str] = []
            raw_values = (row.get("values") or "").strip()
            if raw_values:
                try:
                    parsed = json.loads(raw_values)
                    # fieldsummary emits [{"value": ..., "count": ...}, ...]
                    values = [
                        str(v["value"]) if isinstance(v, dict) else str(v)
                        for v in parsed
                    ]
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass  # unparseable values cell → no enum harvest for this field
            out.append(
                RawField(
                    name=name,
                    total_count=_int_or_none(row.get("count")),
                    distinct_count=_int_or_none(row.get("distinct_count")),
                    numeric_count=_int_or_none(row.get("numeric_count")),
                    values=values,
                )
            )
        return out


def _parse_sentinel_csv(path: Path) -> list[RawField]:
    """Sentinel ``| getschema`` CSV (ColumnName, DataType)."""
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None or "ColumnName" not in reader.fieldnames:
            raise ReshapeError(
                f"{path.name}: expected a getschema CSV with a 'ColumnName' column "
                "(see `adef schema recipe sentinel` for the export command)"
            )
        out = []
        for row in reader:
            name = (row.get("ColumnName") or "").strip()
            if not name:
                continue
            kql_type = (row.get("DataType") or "").strip().lower().removeprefix("system.")
            out.append(RawField(name=name, type_hint=_KQL_TYPE_MAP.get(kql_type)))
        return out


def _walk_elastic_properties(properties: dict, prefix: str = "") -> list[RawField]:
    out: list[RawField] = []
    for name, spec in properties.items():
        dotted = f"{prefix}{name}"
        if not isinstance(spec, dict):
            continue
        if "properties" in spec:
            out.extend(_walk_elastic_properties(spec["properties"], f"{dotted}."))
        else:
            es_type = str(spec.get("type", "")).lower()
            out.append(RawField(name=dotted, type_hint=_ELASTIC_TYPE_MAP.get(es_type)))
    return out


def _parse_elastic_json(path: Path) -> list[RawField]:
    """Elastic ``GET <index>/_mapping`` JSON."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReshapeError(f"{path.name}: not valid JSON ({exc})") from exc
    # _mapping wraps as {"<index>": {"mappings": {"properties": {...}}}};
    # accept the unwrapped forms too.
    if "properties" in data:
        props = data["properties"]
    elif "mappings" in data:
        props = data["mappings"].get("properties", {})
    else:
        first: dict = next(iter(data.values()), {})
        props = first.get("mappings", {}).get("properties", {}) if isinstance(first, dict) else {}
    if not props:
        raise ReshapeError(f"{path.name}: no 'properties' found — is this a _mapping export?")
    return _walk_elastic_properties(props)


def _parse_text(path: Path) -> list[RawField]:
    """Fallback: one field name per line (comments/blanks skipped)."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if name and not name.startswith("#"):
            out.append(RawField(name=name))
    if not out:
        raise ReshapeError(f"{path.name}: no field names found (expected one per line)")
    return out


_PARSERS = {
    "splunk": _parse_splunk_csv,
    "sentinel": _parse_sentinel_csv,
    "elastic": _parse_elastic_json,
}

_QUERY_LANGUAGE_BY_PLATFORM = {"splunk": "spl", "sentinel": "kql"}


# --------------------------------------------------------------------------- #
# The five rules
# --------------------------------------------------------------------------- #
def _is_internal(name: str) -> bool:
    lower = name.lower()
    return lower.startswith(_INTERNAL_PREFIXES) or lower in _INTERNAL_NAMES


def _infer_type(raw: RawField) -> str | None:
    if raw.type_hint:
        return raw.type_hint
    values = [v for v in raw.values if v.strip() != ""]
    if raw.total_count and raw.numeric_count == raw.total_count:
        if values and all(_FLOAT_RE.match(v) for v in values):
            return "float"
        return "int"
    if values:
        if all(_INT_RE.match(v) or _HEX_RE.match(v) for v in values):
            return "int"
        if all(_FLOAT_RE.match(v) or _INT_RE.match(v) for v in values):
            return "float"
    return None


def _coerce_enum(values: list[str], ftype: str | None) -> list:
    if ftype == "int":
        out: list = []
        for v in values:
            try:
                out.append(int(v, 16) if _HEX_RE.match(v) else int(v))
            except ValueError:
                out.append(v)
        return out
    return list(values)


def reshape_fields(raw_fields: list[RawField]) -> tuple[list[dict], ReshapeReport]:
    """Apply the five rules to a parsed field inventory."""
    report = ReshapeReport()

    # Rule 5: mixed-shape guard — refuse, never guess the split.
    for raw in raw_fields:
        if raw.name.lower() == "sourcetype":
            shapes = raw.distinct_count or len(set(raw.values))
            if shapes and shapes > 1:
                observed = ", ".join(sorted(set(raw.values))[:10]) or "unknown"
                raise ReshapeError(
                    f"export mixes {shapes} sourcetypes ({observed}): one declaration "
                    "per event shape — re-export with `sourcetype=<one>` in the "
                    "search and reshape each export separately (this is what "
                    "`scope:` exists for)"
                )

    # Rule 1: internals filter.
    kept: list[RawField] = []
    for raw in raw_fields:
        if _is_internal(raw.name):
            report.dropped_internals.append(raw.name)
        else:
            kept.append(raw)

    # Rule 2: case-dupes → aliases. Canonical = highest event count, then first seen.
    by_lower: dict[str, list[RawField]] = {}
    for raw in kept:
        by_lower.setdefault(raw.name.lower(), []).append(raw)

    fields_out: list[dict] = []
    for group in by_lower.values():
        canonical = max(group, key=lambda r: r.total_count or 0)
        aliases = [r.name for r in group if r is not canonical]
        if aliases:
            report.folded_aliases[canonical.name] = aliases

        entry: dict = {"name": canonical.name}
        if aliases:
            entry["aliases"] = aliases

        # Rule 4: type inference.
        ftype = _infer_type(canonical)
        if ftype and ftype != "string":
            entry["type"] = ftype
            report.typed_fields[canonical.name] = ftype

        # Rule 3: enum harvesting with caps.
        distinct = canonical.distinct_count
        if (
            canonical.values
            and distinct is not None
            and distinct <= ENUM_MAX_DISTINCT
            and all(len(v) <= ENUM_MAX_VALUE_LEN for v in canonical.values)
        ):
            entry["values"] = _coerce_enum(canonical.values, ftype)
            report.enum_fields.append(canonical.name)

        fields_out.append(entry)

    fields_out.sort(key=lambda f: str(f["name"]).lower())
    return fields_out, report


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def reshape_export(
    export_path: Path, platform: str, source_name: str | None = None
) -> ReshapeResult:
    """Parse a raw export for ``platform`` and build a draft declaration."""
    parser = _PARSERS.get(platform.lower(), _parse_text)
    raw_fields = parser(export_path)
    if not raw_fields:
        raise ReshapeError(f"{export_path.name}: no fields found")

    # Splunk routing fields carry the scope literals before rule 1 drops them.
    scope: dict = {}
    for raw in raw_fields:
        if raw.name.lower() in ("index", "sourcetype"):
            uniq = sorted(set(raw.values))
            if len(uniq) == 1:
                scope[raw.name.lower()] = uniq[0]

    fields_out, report = reshape_fields(raw_fields)
    if not fields_out:
        raise ReshapeError(f"{export_path.name}: every field was filtered as internal")

    name = source_name or re.sub(
        r"[^a-z0-9]+", "_", str(scope.get("sourcetype", export_path.stem)).lower()
    ).strip("_")
    source: dict = {"name": name}

    query_language = _QUERY_LANGUAGE_BY_PLATFORM.get(platform.lower())
    if query_language:
        source["query_language"] = query_language
    else:
        report.notes.append("query_language not set — add it if this source is queried")
    report.notes.append("platform not set — never inferred; add it before ingest")

    if scope:
        source["scope"] = scope
    source["fields"] = fields_out

    return ReshapeResult(declaration={"version": 1, "sources": [source]}, report=report)
