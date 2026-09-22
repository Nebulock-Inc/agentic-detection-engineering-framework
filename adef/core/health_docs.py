"""Detection-health capture documents — the producer-side contract.

A producer (a person, a scheduled job, or an assistant session with its own
tooling) describes what catalogued detections are doing in a live environment
and hands ADEF the file. ADEF never queries that environment; see the
no-vendor-connector anti-goal.

Documents are self-describing: each declares its own ``kind`` and
``schema_version``, so ingestion routes on content rather than on a CLI flag a
producer could mismatch against the file they are passing.

``field_observations.fields[].sample_values`` is the one field, in any
document kind, that carries event-derived content. It is optional; including
it stores that data at rest in the workspace (``health/sources/<source>.yml``)
— see the anti-goal check in the design doc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any

import yaml

SCHEMA_VERSION = 1

KINDS = frozenset(
    {"metrics", "performance", "deployment_drift", "field_observations", "source_health"}
)

#: Kinds whose numbers are counts over an interval. A count without a
#: denominator is uninterpretable, and trend comparison needs comparable spans.
#: ``deployment_drift`` is excluded: it is a point-in-time observation, so
#: ``captured_at`` carries all of its temporal meaning.
WINDOWED_KINDS = KINDS - {"deployment_drift"}

#: Kinds whose rows are keyed by an ADEF detection ID.
DETECTION_KEYED_KINDS = frozenset({"metrics", "performance", "deployment_drift"})

_COMMON_KEYS = {"schema_version", "kind", "captured_at", "window", "environment"}
_KEYS_BY_KIND = {
    "metrics": _COMMON_KEYS | {"detections"},
    "performance": _COMMON_KEYS | {"detections"},
    "deployment_drift": _COMMON_KEYS | {"detections", "normalization"},
    "field_observations": _COMMON_KEYS | {"source", "fields"},
    "source_health": _COMMON_KEYS | {"sources"},
}

#: Closed set of normalization transforms `deployment_drift.normalization.apply`
#: may name. Closed deliberately (design doc "Normalization"): the document
#: selects from ADEF-shipped transforms, never supplies its own regex, so the
#: comparison contract stays auditable. Adding a transform is a PR to ADEF.
NORMALIZATION_TRANSFORMS = frozenset(
    {"collapse_whitespace", "strip_sql_comments", "strip_trailing_semicolon"}
)

# A user-supplied name that becomes a bare filename component: `sources[].name`,
# `source`, and (defense in depth) `detection_id` are all joined into a path
# under `health/`. Mirrors `declaration.py`'s `_BAD_SOURCE_NAME` and
# `schema_tools.py`'s `_safe_source_name`, applied to the same concept.
_BAD_SOURCE_NAME = re.compile(r"[/\\]")
_DETECTION_ID_RE = re.compile(r"^D-\d{4,}$")


def _unsafe_source_name(name: str) -> bool:
    """True if ``name`` cannot safely become a bare filename component.

    Rejects path separators (POSIX and Windows), ``.``/``..``, and
    empty/blank names. An absolute path always contains a separator, so it is
    already caught by the separator check.
    """
    stripped = (name or "").strip()
    return not stripped or stripped in (".", "..") or bool(_BAD_SOURCE_NAME.search(stripped))


def _path_safe(name: str) -> str | None:
    """Row-validator: error string if ``name`` is unsafe as a filename, else None."""
    if _unsafe_source_name(name):
        return f"must be a bare name, not a path ({name!r})"
    return None


def _detection_id_shape(det_id: str) -> str | None:
    """Row-validator: error string if ``det_id`` isn't a D-XXXX id, else None.

    Defense in depth — a detection_id only becomes a filename after it passes
    the `known_ids` membership check in `health_store`, so this is currently
    safe by construction. It stops being safe the moment a catalog record
    with a hand-edited, non-D-XXXX id exists, so check the shape here too.
    """
    if not _DETECTION_ID_RE.fullmatch(det_id.strip()):
        return f"must look like D-XXXX ({det_id!r})"
    return None


def _lint_normalization(value: Any, errors: list[str]) -> None:
    """Validate `deployment_drift.normalization` (optional)."""
    if value is None:
        return
    if not isinstance(value, dict):
        errors.append("normalization: must be a mapping")
        return
    unknown = set(value) - {"apply"}
    if unknown:
        errors.append(f"normalization: unknown keys: {', '.join(sorted(unknown))}")
    apply = value.get("apply")
    if apply is None:
        return
    if not isinstance(apply, list) or not all(isinstance(t, str) for t in apply):
        errors.append("normalization.apply: must be a list of strings")
        return
    bad = sorted(set(apply) - NORMALIZATION_TRANSFORMS)
    if bad:
        errors.append(
            f"normalization.apply: unknown transform(s) {', '.join(bad)} "
            f"(allowed: {', '.join(sorted(NORMALIZATION_TRANSFORMS))})"
        )


class HealthDocError(ValueError):
    """Raised when a capture document cannot be read or fails validation."""


@dataclass
class HealthDoc:
    """A parsed, validated capture document."""

    kind: str
    schema_version: int
    captured_at: str
    environment: str
    window: dict[str, str] | None = None
    detections: list[dict] = dataclass_field(default_factory=list)
    sources: list[dict] = dataclass_field(default_factory=list)
    source: str = ""
    fields: list[dict] = dataclass_field(default_factory=list)
    normalization: dict | None = None


def _lint_rows(
    rows: Any,
    where: str,
    id_key: str,
    errors: list[str],
    validate: Any = None,
) -> None:
    """Every row must be a mapping carrying a non-empty ``id_key``.

    Row *contents* are deliberately not whitelisted: a producer may carry extra
    context alongside the documented fields, and storage preserves it verbatim.
    Only the key that makes a row addressable is required here. Do not tighten
    this into a per-kind field whitelist — the analysis in story 10097 reads the
    specific keys it needs and ignores the rest.

    ``validate``, if given, receives the (non-empty) ``id_key`` value and
    returns an error string or ``None`` — used for the path-safety and
    D-XXXX-shape checks, which are about what the value becomes, not just
    whether it's present.
    """
    if not isinstance(rows, list) or not rows:
        errors.append(f"{where}: required non-empty list")
        return
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"{where}[{i}]: must be a mapping")
            continue
        value = row.get(id_key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{where}[{i}].{id_key}: required non-empty string")
        elif validate is not None:
            msg = validate(value)
            if msg:
                errors.append(f"{where}[{i}].{id_key}: {msg}")


def lint_health_doc(data: Any) -> list[str]:
    """Return a list of validation errors for ``data``. Never raises."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["document: must be a mapping"]

    kind = data.get("kind")
    if kind not in KINDS:
        errors.append(f"kind: {kind!r} not one of {', '.join(sorted(KINDS))}")
        return errors  # every remaining rule is kind-dependent

    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        errors.append(f"schema_version: expected {SCHEMA_VERSION}, got {version!r}")

    captured_at = data.get("captured_at")
    if not isinstance(captured_at, str) or not captured_at.strip():
        errors.append("captured_at: required non-empty string (ISO-8601)")

    unknown = set(data) - _KEYS_BY_KIND[kind]
    if unknown:
        errors.append(f"unknown keys for kind {kind!r}: {', '.join(sorted(unknown))}")

    window = data.get("window")
    if kind in WINDOWED_KINDS:
        if not isinstance(window, dict) or not window.get("start") or not window.get("end"):
            errors.append(
                f"window: required for kind {kind!r} with 'start' and 'end' "
                "(a count without a denominator cannot be interpreted)"
            )
    elif window is not None:
        errors.append(
            f"window: not allowed on kind {kind!r} — it is a point-in-time "
            "observation, so captured_at carries its temporal meaning"
        )

    if kind in DETECTION_KEYED_KINDS:
        _lint_rows(
            data.get("detections"), "detections", "detection_id", errors,
            validate=_detection_id_shape,
        )
    elif kind == "source_health":
        _lint_rows(data.get("sources"), "sources", "name", errors, validate=_path_safe)
    else:  # field_observations
        source = data.get("source")
        if not isinstance(source, str) or not source.strip():
            errors.append("source: required non-empty string")
        else:
            msg = _path_safe(source)
            if msg:
                errors.append(f"source: {msg}")
        _lint_rows(data.get("fields"), "fields", "name", errors)

    if kind == "deployment_drift":
        _lint_normalization(data.get("normalization"), errors)

    return errors


def load_health_doc(path: Path) -> HealthDoc:
    """Parse and validate the capture document at ``path``."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        raise HealthDocError(f"{path}: could not be read as YAML ({exc})") from exc

    errors = lint_health_doc(data)
    if errors:
        raise HealthDocError(f"{path}: " + "; ".join(errors))

    return HealthDoc(
        kind=str(data["kind"]),
        schema_version=int(data["schema_version"]),
        captured_at=str(data["captured_at"]),
        environment=str(data.get("environment", "")),
        window=data.get("window"),
        detections=list(data.get("detections", [])),
        sources=list(data.get("sources", [])),
        source=str(data.get("source", "")),
        fields=list(data.get("fields", [])),
        normalization=data.get("normalization"),
    )


__all__ = [
    "SCHEMA_VERSION",
    "KINDS",
    "WINDOWED_KINDS",
    "DETECTION_KEYED_KINDS",
    "NORMALIZATION_TRANSFORMS",
    "HealthDoc",
    "HealthDocError",
    "lint_health_doc",
    "load_health_doc",
]
