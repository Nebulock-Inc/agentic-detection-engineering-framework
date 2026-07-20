"""Data-source declarations — the user-provided document schemas are built from.

The declaration format (v1) is a YAML inventory of data sources and their
fields (see ``docs/plans/2026-07-20-schema-declaration-design.md`` and ISA
2026-07-20). Users produce it from artifacts they already have (Splunk
``| fieldsummary``, KQL ``| getschema``, Elastic mappings, vendor data
dictionaries) — by hand, recipe, or agent. ADEF ingests it into one
``schema/<source>.yml`` (``schema_version: 2``) per source.

Provenance contract (what makes re-ingest safe):

- ingested fields are ``declared``;
- human edits marked ``provenance: corrected`` (fixed types, added fields)
  are preserved across re-ingest and shadow same-named declared fields;
- re-ingest replaces the declared set and reports drift (added / removed /
  type-changed).

No event data is required or stored — this is a field inventory, not samples.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

DECLARATION_VERSION = 1
SCHEMA_VERSION = 2

FIELD_TYPES = (
    "string",
    "int",
    "float",
    "bool",
    "datetime",
    "ip",
    "array",
    "object",
    "unknown",
)

QUERY_LANGUAGES = ("spl", "kql", "cql", "sql")

PROVENANCE_DECLARED = "declared"
PROVENANCE_CORRECTED = "corrected"

_SOURCE_KEYS = {"name", "platform", "query_language", "description", "fields"}
_FIELD_KEYS = {"name", "type", "description", "values", "aliases"}
_BAD_SOURCE_NAME = re.compile(r"[/\\]")


class DeclarationError(ValueError):
    """A declaration failed to load or lint."""


@dataclass
class DeclaredField:
    name: str
    type: str = "string"
    description: str = ""
    values: list[Any] = dataclass_field(default_factory=list)
    aliases: list[str] = dataclass_field(default_factory=list)
    provenance: str = PROVENANCE_DECLARED


@dataclass
class DeclaredSource:
    name: str
    platform: str = ""
    query_language: str = ""
    description: str = ""
    fields: list[DeclaredField] = dataclass_field(default_factory=list)


# --------------------------------------------------------------------------- #
# Lint / load
# --------------------------------------------------------------------------- #
def lint_declaration_dict(data: Any) -> tuple[list[str], list[str]]:
    """Validate a parsed declaration. Returns ``(errors, warnings)``."""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(data, dict):
        return ["declaration must be a YAML mapping"], warnings

    if data.get("version") != DECLARATION_VERSION:
        errors.append(f"version: must be {DECLARATION_VERSION}")

    unknown = set(data) - {"version", "sources"}
    if unknown:
        errors.append(f"unknown top-level keys: {', '.join(sorted(unknown))}")

    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("sources: required non-empty list")
        return errors, warnings

    seen_sources: set[str] = set()
    for i, src in enumerate(sources):
        where = f"sources[{i}]"
        if not isinstance(src, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        name = src.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{where}.name: required non-empty string")
            name = ""
        elif _BAD_SOURCE_NAME.search(name):
            errors.append(f"{where}.name: must not contain path separators ({name!r})")
        if name:
            where = f"sources[{i}] ({name})"
            if name in seen_sources:
                errors.append(f"{where}: duplicate source name")
            seen_sources.add(name)

        unknown = set(src) - _SOURCE_KEYS
        if unknown:
            errors.append(f"{where}: unknown keys: {', '.join(sorted(unknown))}")

        ql = src.get("query_language")
        if ql is None or ql == "":
            warnings.append(
                f"{where}: no query_language — `adef schema check` and query "
                "authoring assistance will skip this source"
            )
        elif ql not in QUERY_LANGUAGES:
            errors.append(
                f"{where}.query_language: must be one of {', '.join(QUERY_LANGUAGES)}"
            )

        fields = src.get("fields")
        if not isinstance(fields, list) or not fields:
            errors.append(f"{where}.fields: required non-empty list")
            continue
        seen_fields: set[str] = set()
        for j, fld in enumerate(fields):
            fwhere = f"{where}.fields[{j}]"
            if not isinstance(fld, dict):
                errors.append(f"{fwhere}: must be a mapping")
                continue
            fname = fld.get("name")
            if not isinstance(fname, str) or not fname.strip():
                errors.append(f"{fwhere}.name: required non-empty string")
            else:
                if fname in seen_fields:
                    errors.append(f"{where}: duplicate field name {fname!r}")
                seen_fields.add(fname)
            unknown = set(fld) - _FIELD_KEYS
            if unknown:
                errors.append(f"{fwhere}: unknown keys: {', '.join(sorted(unknown))}")
            ftype = fld.get("type", "string")
            if ftype not in FIELD_TYPES:
                errors.append(
                    f"{fwhere}.type: {ftype!r} not one of {', '.join(FIELD_TYPES)}"
                )
            values = fld.get("values", [])
            if not isinstance(values, list) or any(
                isinstance(v, (dict, list)) for v in values
            ):
                errors.append(f"{fwhere}.values: must be a list of scalars")
            aliases = fld.get("aliases", [])
            if not isinstance(aliases, list) or not all(
                isinstance(a, str) for a in aliases
            ):
                errors.append(f"{fwhere}.aliases: must be a list of strings")

    return errors, warnings


def parse_declaration(data: dict) -> list[DeclaredSource]:
    """Build ``DeclaredSource`` objects from a linted declaration document."""
    errors, _ = lint_declaration_dict(data)
    if errors:
        raise DeclarationError("; ".join(errors))
    out: list[DeclaredSource] = []
    for src in data["sources"]:
        fields = [
            DeclaredField(
                name=str(f["name"]).strip(),
                type=str(f.get("type", "string")),
                description=str(f.get("description", "")),
                values=list(f.get("values", [])),
                aliases=[str(a) for a in f.get("aliases", [])],
            )
            for f in src["fields"]
        ]
        out.append(
            DeclaredSource(
                name=str(src["name"]).strip(),
                platform=str(src.get("platform", "")),
                query_language=str(src.get("query_language", "") or ""),
                description=str(src.get("description", "")),
                fields=fields,
            )
        )
    return out


def load_declaration(path: Path) -> list[DeclaredSource]:
    """Load, lint, and parse a declaration file."""
    p = Path(path).expanduser()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DeclarationError(f"{p}: {exc}") from exc
    try:
        return parse_declaration(data)
    except DeclarationError as exc:
        raise DeclarationError(f"{p}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Schema v2 read/write
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_schema_v2(path: Path) -> Optional[dict]:
    """Read a ``schema_version: 2`` file; ``None`` if missing or not v2."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None
    if isinstance(data, dict) and data.get("schema_version") == SCHEMA_VERSION:
        return data
    return None


@dataclass
class Drift:
    """What changed for one source between the previous and new declaration."""

    added: list[str] = dataclass_field(default_factory=list)
    removed: list[str] = dataclass_field(default_factory=list)
    type_changed: list[str] = dataclass_field(default_factory=list)
    corrected_kept: list[str] = dataclass_field(default_factory=list)

    @property
    def any(self) -> bool:
        return bool(self.added or self.removed or self.type_changed)


def ingest_source(source: DeclaredSource, schema_dir: Path) -> tuple[Path, Drift]:
    """Write ``schema/<source>.yml`` (v2) for one declared source.

    Merge semantics (ISA 2026-07-20): the ``declared`` field set is replaced by
    the declaration; ``corrected`` fields in the existing file are preserved
    and shadow same-named incoming fields; drift is reported against the
    previous ``declared`` set.
    """
    schema_dir = Path(schema_dir)
    schema_dir.mkdir(parents=True, exist_ok=True)
    path = schema_dir / f"{source.name}.yml"

    previous = read_schema_v2(path)
    prev_declared: dict[str, dict] = {}
    corrected: dict[str, dict] = {}
    if previous:
        for fld in previous.get("fields", []):
            if fld.get("provenance") == PROVENANCE_CORRECTED:
                corrected[fld["name"]] = fld
            else:
                prev_declared[fld["name"]] = fld

    incoming = {f.name: f for f in source.fields}
    drift = Drift(corrected_kept=sorted(corrected))
    if previous:
        drift.added = sorted(set(incoming) - set(prev_declared) - set(corrected))
        drift.removed = sorted(set(prev_declared) - set(incoming))
        drift.type_changed = sorted(
            name
            for name, fld in incoming.items()
            if name in prev_declared and prev_declared[name].get("type") != fld.type
        )

    fields_out: list[dict] = []
    for name in sorted(set(incoming) | set(corrected)):
        if name in corrected:  # human correction shadows the declaration
            fields_out.append(corrected[name])
            continue
        f = incoming[name]
        fields_out.append(
            {
                "name": f.name,
                "type": f.type,
                "description": f.description,
                "values": list(f.values),
                "aliases": list(f.aliases),
                "provenance": PROVENANCE_DECLARED,
            }
        )

    data = {
        "schema_version": SCHEMA_VERSION,
        "source": source.name,
        "platform": source.platform,
        "query_language": source.query_language,
        "description": source.description,
        "declared": _now_iso(),
        "fields": fields_out,
    }
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    return path, drift


def known_field_names(schema_data: dict) -> set[str]:
    """Every name a rule may legitimately reference: field names + aliases."""
    names: set[str] = set()
    for fld in schema_data.get("fields", []):
        names.add(str(fld.get("name", "")))
        names.update(str(a) for a in fld.get("aliases", []))
    names.discard("")
    return names


__all__ = [
    "DECLARATION_VERSION",
    "SCHEMA_VERSION",
    "FIELD_TYPES",
    "PROVENANCE_CORRECTED",
    "PROVENANCE_DECLARED",
    "DeclarationError",
    "DeclaredField",
    "DeclaredSource",
    "Drift",
    "ingest_source",
    "known_field_names",
    "lint_declaration_dict",
    "load_declaration",
    "parse_declaration",
    "read_schema_v2",
]
