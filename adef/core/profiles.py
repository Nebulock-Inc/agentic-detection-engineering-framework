"""Declarative extraction profiles — teach ADEF a rule format with YAML, not code.

A *profile* tells the discovery engine how to recognize a rule format
(``signature``: container + key sets) and where its fields live (``map``:
dot-paths). Profiles are the only mechanism for supporting org-specific
in-house formats: agent-drafted, engine-validated, human-approved (see
``docs/plans/2026-07-20-claude-plugin-design.md``).

Design commitments (ISA 2026-07-20):

- **Dot-paths + ``[]`` array iteration only.** No JSONPath — profiles must be
  reviewable by the human who approves them.
- **Container parse returns a list of documents.** v1 implements
  single-document yaml/json; the multi-doc contract (conf stanzas, ndjson,
  ARM ``resources[]``) is honoured in the signature now so later containers
  are not a breaking change.
- **User profiles are checked before built-in recognizers** (wired in
  ``rule_discovery``), so an org can override how its own format is read.
- This module has no ADEF imports — ``rule_discovery`` imports *it*.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Optional

import yaml

PROFILE_SCHEMA_VERSION = 1

# Containers the schema admits. v1 implements yaml/json; the rest are
# schema-valid but rejected by lint until their parsers exist.
CONTAINERS = ("yaml", "json", "toml", "conf", "raw")
IMPLEMENTED_CONTAINERS = ("yaml", "json")

QUERY_LANGUAGES = ("spl", "kql", "cql", "sql", "none")

# map keys a profile may set; `title` and `query` are required.
MAP_FIELDS = ("title", "query", "mitre", "uuid", "data_source", "severity", "description")

_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_PATH_RE = re.compile(r"^[A-Za-z_][\w-]*(\[\])?(\.[A-Za-z_][\w-]*(\[\])?)*$")


class ProfileError(ValueError):
    """A profile failed to load or lint."""


@dataclass(frozen=True)
class Profile:
    """One parsed extraction profile (see the design doc for the YAML shape)."""

    name: str
    version: int
    container: str
    all_keys: tuple[str, ...] = ()
    any_keys: tuple[str, ...] = ()
    none_keys: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    query_language: str = "none"
    map: dict[str, str] = dataclass_field(default_factory=dict)
    platform_const: str = ""
    platform_path: str = ""
    source_path: Optional[Path] = None


# --------------------------------------------------------------------------- #
# Lint / load
# --------------------------------------------------------------------------- #
def lint_profile_dict(data: Any) -> list[str]:
    """Validate a parsed profile document. Returns a list of errors (empty = ok)."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["profile must be a YAML mapping"]

    name = data.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        errors.append("name: required, kebab-case (e.g. acme-siem-export)")

    if data.get("version") != PROFILE_SCHEMA_VERSION:
        errors.append(f"version: must be {PROFILE_SCHEMA_VERSION}")

    sig = data.get("signature")
    if not isinstance(sig, dict):
        errors.append("signature: required mapping")
        sig = {}
    container = sig.get("container")
    if container not in CONTAINERS:
        errors.append(f"signature.container: must be one of {', '.join(CONTAINERS)}")
    elif container not in IMPLEMENTED_CONTAINERS:
        errors.append(
            f"signature.container: '{container}' is valid in the schema but not "
            f"implemented in v1 (implemented: {', '.join(IMPLEMENTED_CONTAINERS)})"
        )
    for key in ("all_keys", "any_keys", "none_keys", "extension"):
        val = sig.get(key, [])
        if not (isinstance(val, list) and all(isinstance(v, str) for v in val)):
            errors.append(f"signature.{key}: must be a list of strings")
    if not sig.get("all_keys") and not sig.get("any_keys"):
        errors.append("signature: at least one of all_keys / any_keys is required")

    ql = data.get("query_language")
    if ql not in QUERY_LANGUAGES:
        errors.append(f"query_language: must be one of {', '.join(QUERY_LANGUAGES)}")

    mapping = data.get("map")
    if not isinstance(mapping, dict):
        errors.append("map: required mapping of field -> dot-path")
        mapping = {}
    for required in ("title", "query"):
        if required not in mapping:
            errors.append(f"map.{required}: required")
    for key, path in mapping.items():
        if key not in MAP_FIELDS:
            errors.append(f"map.{key}: unknown field (allowed: {', '.join(MAP_FIELDS)})")
        elif not (isinstance(path, str) and _PATH_RE.match(path)):
            errors.append(
                f"map.{key}: invalid dot-path {path!r} (dot-paths + [] iteration only)"
            )

    platform = data.get("platform")
    if platform is not None:
        if not isinstance(platform, dict) or set(platform) - {"const", "path"}:
            errors.append("platform: mapping with 'const' or 'path' only")
        elif "const" in platform and "path" in platform:
            errors.append("platform: 'const' and 'path' are mutually exclusive")
        elif "path" in platform and not (
            isinstance(platform["path"], str) and _PATH_RE.match(platform["path"])
        ):
            errors.append("platform.path: invalid dot-path")

    unknown = set(data) - {"name", "version", "signature", "query_language", "map", "platform"}
    if unknown:
        errors.append(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    return errors


def profile_from_dict(data: dict, source_path: Optional[Path] = None) -> Profile:
    """Build a :class:`Profile` from a linted document. Raises on lint errors."""
    errors = lint_profile_dict(data)
    if errors:
        raise ProfileError("; ".join(errors))
    sig = data["signature"]
    platform = data.get("platform") or {}
    return Profile(
        name=data["name"],
        version=data["version"],
        container=sig["container"],
        all_keys=tuple(sig.get("all_keys", [])),
        any_keys=tuple(sig.get("any_keys", [])),
        none_keys=tuple(sig.get("none_keys", [])),
        extensions=tuple(sig.get("extension", [])),
        query_language=data["query_language"],
        map=dict(data["map"]),
        platform_const=str(platform.get("const", "")),
        platform_path=str(platform.get("path", "")),
        source_path=source_path,
    )


def load_profile(path: Path) -> Profile:
    """Load and lint one profile YAML file."""
    p = Path(path).expanduser()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProfileError(f"{p}: {exc}") from exc
    try:
        return profile_from_dict(data, source_path=p)
    except ProfileError as exc:
        raise ProfileError(f"{p}: {exc}") from exc


def profiles_dir(workspace: Path) -> Path:
    """Where user profiles live: ``<workspace>/config/profiles/``."""
    return Path(workspace).expanduser().resolve() / "config" / "profiles"


def load_user_profiles(workspace: Path) -> tuple[list[Profile], list[str]]:
    """Load every profile under the workspace, defensively.

    Returns ``(profiles, errors)`` — a broken profile never kills discovery
    (same posture as plugin loading); it is reported and skipped.
    """
    directory = profiles_dir(workspace)
    profiles: list[Profile] = []
    errors: list[str] = []
    if not directory.is_dir():
        return profiles, errors
    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        try:
            profiles.append(load_profile(path))
        except ProfileError as exc:
            errors.append(str(exc))
    return profiles, errors


# --------------------------------------------------------------------------- #
# Container parsing — returns a LIST of documents (multi-doc contract)
# --------------------------------------------------------------------------- #
def parse_container(container: str, text: str) -> list[dict]:
    """Parse ``text`` as ``container``; return the list of documents inside.

    v1 implements single-document ``yaml``/``json`` (one mapping → one-element
    list). Anything unparsable or non-mapping returns ``[]`` — the profile
    simply doesn't claim the file.
    """
    if container == "yaml":
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            return []
        return [doc] if isinstance(doc, dict) else []
    if container == "json":
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            return []
        return [doc] if isinstance(doc, dict) else []
    return []  # conf / toml / raw / ndjson: later phases


# --------------------------------------------------------------------------- #
# Matching + extraction
# --------------------------------------------------------------------------- #
def matches(profile: Profile, filename: str, doc: dict) -> bool:
    """Does ``profile``'s signature claim this parsed document?

    Extension is a hint that *narrows* (a listed extension excludes others);
    an empty extension list means any filename. Key sets decide.
    """
    if profile.extensions and not filename.lower().endswith(
        tuple(e.lower() for e in profile.extensions)
    ):
        return False
    if any(k not in doc for k in profile.all_keys):
        return False
    if profile.any_keys and not any(k in doc for k in profile.any_keys):
        return False
    if any(k in doc for k in profile.none_keys):
        return False
    return True


def extract_path(doc: Any, path: str) -> Any:
    """Resolve a dot-path (with ``[]`` iteration) against a document.

    ``a.b`` walks mappings; ``a[]`` requires a list and maps the rest of the
    path over its elements (flattening one level). Returns ``None`` (or ``[]``
    inside an iteration) when the path doesn't resolve.
    """
    return _walk(doc, path.split("."))


def _walk(node: Any, tokens: list[str]) -> Any:
    if not tokens:
        return node
    token, rest = tokens[0], tokens[1:]
    iterate = token.endswith("[]")
    key = token[:-2] if iterate else token
    if not isinstance(node, dict) or key not in node:
        return [] if iterate else None
    value = node[key]
    if not iterate:
        return _walk(value, rest)
    if not isinstance(value, list):
        return []
    out: list[Any] = []
    for element in value:
        resolved = _walk(element, rest)
        if isinstance(resolved, list):
            out.extend(resolved)
        elif resolved is not None:
            out.append(resolved)
    return out


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return ""
    return str(value).strip()


def extract_fields(profile: Profile, doc: dict) -> dict[str, Any]:
    """Extract the mapped fields from one claimed document.

    Returns plain values keyed by ``MAP_FIELDS`` (+ ``platform``): strings for
    scalar fields, a list of raw tokens for ``mitre`` (normalisation is the
    caller's job — same regex path as every other format).
    """
    out: dict[str, Any] = {}
    for field_name, path in profile.map.items():
        value = extract_path(doc, path)
        if field_name == "mitre":
            if isinstance(value, list):
                out["mitre"] = [str(v) for v in value]
            else:
                out["mitre"] = [str(value)] if value is not None else []
        else:
            out[field_name] = _as_str(value)
    if profile.platform_const:
        out["platform"] = profile.platform_const
    elif profile.platform_path:
        out["platform"] = _as_str(extract_path(doc, profile.platform_path)).lower()
    else:
        out["platform"] = ""
    return out


__all__ = [
    "CONTAINERS",
    "IMPLEMENTED_CONTAINERS",
    "MAP_FIELDS",
    "PROFILE_SCHEMA_VERSION",
    "Profile",
    "ProfileError",
    "extract_fields",
    "extract_path",
    "lint_profile_dict",
    "load_profile",
    "load_user_profiles",
    "matches",
    "parse_container",
    "profile_from_dict",
    "profiles_dir",
]
