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
— weigh that against the no-vendor-connector anti-goal.
"""

from __future__ import annotations

import datetime as dt
import difflib
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
#: may name. Closed deliberately: the document
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


# 3.10's `fromisoformat` is strict where 3.11+ is not; SIEM exports routinely
# emit both shapes it rejects. `+0000` → `+00:00`, and any fraction → 6 digits.
_COMPACT_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")
_FRACTION = re.compile(r"\.(\d+)")
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _date_only(value: Any) -> bool:
    """A bare ``YYYY-MM-DD`` — an inclusive day when used as a window end."""
    return isinstance(value, str) and bool(_DATE_ONLY.match(value.strip()))


def parse_iso(value: Any) -> dt.datetime | None:
    """ISO-8601 → aware ``datetime``, or ``None`` if it isn't one.

    ``Z`` and a colon-less ``+HHMM`` offset are rewritten by hand because
    ``fromisoformat`` only accepts them from 3.11 and this package supports
    3.10. A naive timestamp is assumed UTC: every documented example is UTC,
    and the alternative is refusing to compute staleness because a producer
    omitted an offset.

    A ``datetime`` passes through. ``load_health_doc`` normalizes YAML-native
    dates to strings, but ``HealthDoc`` is hand-constructible and a stored
    file can be hand-edited, so the one place that does date arithmetic should
    not care which it got.
    """
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    if len(text) > 10:  # has a time part (any separator)
        text = _COMPACT_OFFSET.sub(r"\1:\2", text)
        text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


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
    this into a per-kind field whitelist — downstream analysis reads the
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
    elif parse_iso(captured_at) is None:
        errors.append(f"captured_at: not an ISO-8601 timestamp ({captured_at!r})")

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
        else:
            # An unreadable window silently turns a 30-day count into a
            # "weekly" volume downstream, so refuse it here instead.
            start, end = parse_iso(window["start"]), parse_iso(window["end"])
            for name, raw, parsed in (("start", window["start"], start), ("end", window["end"], end)):
                if parsed is None:
                    errors.append(f"window.{name}: not an ISO-8601 timestamp ({raw!r})")
            # A date-only end is an inclusive day, so `start == end` is a
            # one-day window there; with a time part it spans nothing.
            if start and end and (start > end or (start == end and not _date_only(window["end"]))):
                errors.append("window: 'start' must be before 'end'")
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


#: The ``metrics`` row keys ``health_store.tuning_metrics`` actually reads.
#: Narrow on purpose: these are the only row keys any consumer reads today, so
#: this is the only key set where a typo has a consequence.
DERIVED_ROW_KEYS = frozenset(
    {
        "signal_count",
        "false_positive_count",
        "true_positive_count",
        "last_true_positive_at",
    }
)


#: Plausible names for a read key that are too far from it for difflib to
#: catch (``signals`` vs ``signal_count`` scores 0.63) — the short forms a
#: producer reaches for first.
_ROW_KEY_ALIASES = {
    "signals": "signal_count",
    "false_positives": "false_positive_count",
    "true_positives": "true_positive_count",
    "fp_count": "false_positive_count",
    "tp_count": "true_positive_count",
    "last_true_positive": "last_true_positive_at",
}


def near_miss_row_keys(doc: HealthDoc) -> list[str]:
    """Warnings for ``metrics`` row keys that look like a typo of a read key.

    Row contents are deliberately not whitelisted (see ``_lint_rows``), which
    is right — a producer may carry extra context and storage keeps it. The
    cost is that a *misspelled* key is completely silent: the document
    validates, ``adef ingest`` reports the row matched, and the number is
    stored where nothing reads it. A capture whose
    ``false_positives_count: 480`` never becomes an ``fp_ratio`` makes
    ``adef detection evolve`` answer ``keep`` on the strength of the counts
    that *did* parse, with no hint that a number was dropped.

    A near-miss is only reported when the key it resembles is **absent from
    the same row**. A producer carrying ``signal_count`` alongside a derived
    ``signal_count_p95`` has lost nothing, and warning there would train
    people to ignore the warning.

    Warnings, never errors: this is a guess about intent, and a document whose
    extra keys are deliberate must still ingest.
    """
    if doc.kind != "metrics":
        return []
    out: list[str] = []
    for row in doc.detections:
        if not isinstance(row, dict):
            continue
        unknown = set(row) - DERIVED_ROW_KEYS
        for key in sorted(unknown):
            close = [_ROW_KEY_ALIASES[key]] if key in _ROW_KEY_ALIASES else (
                difflib.get_close_matches(key, DERIVED_ROW_KEYS, n=1, cutoff=0.85)
            )
            if close and close[0] not in row:
                out.append(
                    f"{row.get('detection_id', '?')}: {key!r} is not read — "
                    f"did you mean {close[0]!r}?"
                )
    return out


def isoify(value: Any) -> Any:
    """Recursively replace YAML-native dates/datetimes with ISO-8601 strings.

    ``yaml.safe_load`` resolves an *unquoted* ``2026-10-06T09:00:00Z`` to a
    ``datetime``, not a string — and every timestamp in this format's own
    documented examples is unquoted. Without this, a correct document was
    refused with ``captured_at: required non-empty string (ISO-8601)``, which
    reads as "you left it out" about a field the producer plainly filled in.

    Normalizing at the document boundary rather than loosening each check
    keeps one type flowing downstream: lint, storage (which YAML-dumps the row
    back out) and the staleness arithmetic all see strings, so none of them
    needs its own date branch. ``isoformat()`` round-trips through
    ``fromisoformat`` exactly.
    """
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dt.date):  # after datetime — a datetime IS a date
        return value.isoformat()
    if isinstance(value, dict):
        return {k: isoify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [isoify(v) for v in value]
    return value


def load_health_doc(path: Path) -> HealthDoc:
    """Parse and validate the capture document at ``path``."""
    try:
        data = isoify(yaml.safe_load(path.read_text(encoding="utf-8")))
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
    "DERIVED_ROW_KEYS",
    "NORMALIZATION_TRANSFORMS",
    "HealthDoc",
    "HealthDocError",
    "isoify",
    "lint_health_doc",
    "load_health_doc",
    "near_miss_row_keys",
    "parse_iso",
]
