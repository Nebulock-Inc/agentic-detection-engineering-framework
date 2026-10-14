"""Storage for detection-health capture documents.

Hybrid by design: ``latest/`` answers "what is true now" in a single read,
``history/`` is the append-only substrate trend analysis consumes. Hybrid for
the three *detection-keyed* kinds only — ``source_health`` and
``field_observations`` are keyed by a free-form telemetry source name and write
``sources/<name>.yml`` with no history file, so nothing here can show a trend
for them. History rows are the document's own per-detection row plus
kind/captured_at/window — small, so growth is bounded by ingest cadence rather
than by document size. ``deployed_query`` (whole-document-sized text) is kept
in ``latest/`` only, never appended to history.

Pure: ``known_ids`` is supplied by the caller rather than read from the catalog
here, so this module is testable without building a catalog fixture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from adef.core.health_docs import (
    DETECTION_KEYED_KINDS,
    HealthDoc,
    HealthDocError,
    _DETECTION_ID_RE,
    _date_only,
    _unsafe_source_name,
    parse_iso,
)
from adef.core.workspace import resolve_workspace


@dataclass
class IngestResult:
    """What one ``store_health_doc`` call did."""

    kind: str
    matched: list[str] = dataclass_field(default_factory=list)
    unmatched: list[str] = dataclass_field(default_factory=list)
    paths_written: list[Path] = dataclass_field(default_factory=list)
    #: Matched rows whose ``latest/`` entry was kept because it is newer than
    #: this document (a backfill). Detection-keyed rows still go to history.
    superseded: list[str] = dataclass_field(default_factory=list)


def health_dir(workspace: Path | None = None) -> Path:
    """Workspace health dir via the canonical resolver (honors --workspace, env,
    cwd, default), matching ``_get_workspace_schema_dir``'s behavior."""
    return resolve_workspace(workspace) / "health"


def _read_mapping(path: Path) -> dict:
    """Load ``path`` as a YAML mapping; ``{}`` when it doesn't exist.

    Guards the file the way ``declaration.py``'s ``read_schema_v2`` does: a
    non-mapping YAML value or unparseable YAML raises a clean
    ``HealthDocError`` instead of a raw ``TypeError``/``yaml.YAMLError`` out of
    the CLI. Matters more than usual here because writes are non-atomic, so a
    crash mid-write must not also leave the *next* run — read or write — with
    an unhandled traceback.
    """
    if not path.exists():
        return {}
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        raise HealthDocError(f"{path}: could not be read as YAML ({exc})") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise HealthDocError(f"{path}: expected a mapping, got {type(loaded).__name__}")
    return loaded


def _is_older(new: dict, stored: dict) -> bool:
    """Does ``new`` describe an earlier period than ``stored``?

    The window's end decides — a re-export of last month's window captured
    today is still last month. Same (or no) window: the later capture is a
    correction and wins. Anything unparseable never blocks.
    """
    def end(entry: dict) -> datetime | None:
        window = entry.get("window")
        return parse_iso(window.get("end")) if isinstance(window, dict) else None

    new_end, stored_end = end(new), end(stored)
    if new_end and stored_end and new_end != stored_end:
        return new_end < stored_end
    new_at, stored_at = parse_iso(new.get("captured_at")), parse_iso(stored.get("captured_at"))
    return bool(new_at and stored_at and new_at < stored_at)


def _merge_latest(path: Path, kind: str, payload: dict) -> bool:
    """Replace this kind's entry in ``path``, leaving other kinds intact.

    Returns ``False`` (and writes nothing) when the stored entry covers a
    *later* period than ``payload`` — backfilling last month must not
    overwrite this week as "what is true now".
    """
    existing = _read_mapping(path)
    current = existing.get(kind)
    if isinstance(current, dict) and _is_older(payload, current):
        return False
    existing[kind] = payload
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(existing, sort_keys=True), encoding="utf-8")
    return True


def _history_key(row: dict) -> tuple:
    """One history row per capture: (kind, window, captured_at). Two captures
    of the same window are distinct observations (labels arrive late) and
    both stay; the *same* capture ingested twice is one row."""
    return row.get("kind"), json.dumps(row.get("window"), sort_keys=True), row.get("captured_at")


def _upsert_history(path: Path, row: dict) -> None:
    """Add ``row``, replacing any earlier row for the same capture.

    Re-ingesting a document — as-is or with corrected counts — replaces its
    row instead of counting the capture twice in a trend.
    """
    key = _history_key(row)
    kept: list[str] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                existing = json.loads(line)
            except ValueError:
                kept.append(line)  # not ours to drop
                continue
            if isinstance(existing, dict) and _history_key(existing) == key:
                continue
            kept.append(line)
    kept.append(json.dumps(row, sort_keys=True))
    path.parent.mkdir(parents=True, exist_ok=True)
    # ponytail: rewrites the file per row; fine at ingest cadence, an index
    # by capture if history files ever grow to many MB.
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")


def store_health_doc(
    doc: HealthDoc,
    health_root: Path,
    known_ids: set[str],
    dry_run: bool = False,
) -> IngestResult:
    """Write ``doc`` under ``health_root``; report matched and unmatched keys.

    Rows whose ``detection_id`` is absent from ``known_ids`` are reported in
    ``unmatched`` and never written — the same infer-and-flag principle the
    catalog follows, so a typo'd or stale ID is visible rather than silently
    creating an orphan record.

    Every name this function joins into a filesystem path — ``detection_id``,
    a source name — is re-validated here even though ``lint_health_doc``
    already checked it: ``HealthDoc`` is a public dataclass any caller
    (including this module's own tests, and the MCP tool) can construct by
    hand, bypassing lint entirely. Lint alone is not a sufficient guard.
    """
    result = IngestResult(kind=doc.kind)
    envelope = {
        "captured_at": doc.captured_at,
        "environment": doc.environment,
        "window": doc.window,
    }
    if doc.kind == "deployment_drift":
        # Carried through so later analysis can see which transforms the
        # producer declared when comparing `deployed_query` against the
        # catalog record's query.
        envelope["normalization"] = doc.normalization

    if doc.kind in DETECTION_KEYED_KINDS:
        for row in doc.detections:
            det_id = str(row["detection_id"])
            # A shape-invalid id can only be in `known_ids` if the catalog
            # itself holds a hand-edited, non-D-XXXX record — but a
            # detection_id becomes a filename, so never trust it on shape
            # alone even then.
            if not _DETECTION_ID_RE.fullmatch(det_id.strip()) or det_id not in known_ids:
                result.unmatched.append(det_id)
                continue
            result.matched.append(det_id)
            if dry_run:
                continue
            payload = {**row, **envelope}
            latest_path = health_root / "latest" / f"{det_id}.yml"
            if _merge_latest(latest_path, doc.kind, payload):
                result.paths_written.append(latest_path)
            else:
                result.superseded.append(det_id)
            # History rows are the thin, append-only trend substrate: drop `deployed_query` (whole-document growth,
            # not a numeric field) and set kind/captured_at/window *after*
            # spreading the row, so a row that happens to carry those key
            # names can never override the document's real values.
            history_row = {k: v for k, v in row.items() if k != "deployed_query"}
            history_row["kind"] = doc.kind
            history_row["captured_at"] = doc.captured_at
            history_row["window"] = doc.window
            history_path = health_root / "history" / f"{det_id}.jsonl"
            _upsert_history(history_path, history_row)
            result.paths_written.append(history_path)
        return result

    # Source-keyed kinds. Source names are free-form labels describing the
    # producer's telemetry, not ADEF identities, so there is nothing to match
    # them against — `unmatched` stays empty by construction.
    if doc.kind == "source_health":
        rows = [(str(row["name"]), dict(row)) for row in doc.sources]
    else:  # field_observations
        rows = [(doc.source, {"fields": list(doc.fields)})]

    for name, payload in rows:
        if _unsafe_source_name(name):
            raise HealthDocError(
                f"source name {name!r} cannot be used as a filename "
                "(path separator, absolute path, '.', or '..')"
            )
        result.matched.append(name)
        if dry_run:
            continue
        path = health_root / "sources" / f"{name}.yml"
        if _merge_latest(path, doc.kind, {**payload, **envelope}):
            result.paths_written.append(path)
        else:
            result.superseded.append(name)

    return result


# --------------------------------------------------------------------------- #
# Reading back. Without this, `adef ingest` writes to a directory nothing
# reads: `TuneRecommenderAgent` tells the user to run it and then cannot see
# the result (`metrics seen: {}`, `insufficient-data`, on numbers that should
# have fired `narrow-filter` high).
# --------------------------------------------------------------------------- #


def read_latest(health_root: Path, detection_id: str) -> dict[str, dict]:
    """Every stored kind for one detection, as ``{kind: payload}``.

    ``{}`` when nothing has been ingested for it — absence of health is the
    normal state for a freshly catalogued detection, not an error.

    ``detection_id`` is re-validated for shape before being joined into a
    path, for the same reason ``store_health_doc`` re-validates it: this is a
    public function and the id reaches it from a CLI argument, so ``../..``
    must not resolve to a read outside ``health/``.
    """
    det_id = detection_id.strip()
    if not _DETECTION_ID_RE.fullmatch(det_id):
        raise HealthDocError(f"{detection_id!r}: must look like D-XXXX")
    stored = _read_mapping(health_root / "latest" / f"{det_id}.yml")
    # Only mapping values: a hand-edited file could put a scalar under a kind,
    # and every consumer here does `.get()` on what comes back.
    return {k: v for k, v in stored.items() if isinstance(v, dict)}


def detections_with_health(health_root: Path) -> list[str]:
    """Detection IDs that have any stored health, sorted. Glob, not catalog —
    a row is only written after passing ``known_ids``, so these are already
    catalogued, and the listing stays useful when the catalog is unreadable.

    No ``is_dir`` guard: ``glob`` already yields nothing for a missing path or
    a plain file. One was here until a mutation couldn't make it fail.
    """
    return sorted(p.stem for p in (health_root / "latest").glob("D-*.yml"))


def read_source(health_root: Path, name: str) -> dict[str, dict]:
    """Every stored kind for one telemetry source, as ``{kind: payload}``.

    The source-keyed twin of ``read_latest`` — ``source_health`` and
    ``field_observations`` are keyed by a free-form source name, not a
    ``D-XXXX``, so they live under ``sources/`` and need their own reader.
    Without one, ``adef health show`` reported "no ingested health" to a user
    who had just ingested two of the five kinds.

    Source names are free-form labels, so the shape check is the path-safety
    one ``store_health_doc`` applies, not the ``D-XXXX`` regex.
    """
    if _unsafe_source_name(name):
        raise HealthDocError(
            f"source name {name!r} cannot be used as a filename "
            "(path separator, absolute path, '.', or '..')"
        )
    stored = _read_mapping(health_root / "sources" / f"{name}.yml")
    return {k: v for k, v in stored.items() if isinstance(v, dict)}


def sources_with_health(health_root: Path) -> list[str]:
    """Telemetry source names that have any stored health, sorted."""
    return sorted(p.stem for p in (health_root / "sources").glob("*.yml"))


def _window_days(window: Any) -> float | None:
    """Span of a capture window in days, or ``None`` if it can't be read."""
    if not isinstance(window, dict):
        return None
    start, end = parse_iso(window.get("start")), parse_iso(window.get("end"))
    if start is None or end is None:
        return None
    if _date_only(window.get("end")):
        end += timedelta(days=1)  # a date-only end is inclusive
    days = (end - start).total_seconds() / 86400
    return days if days > 0 else None


def as_number(value: Any) -> float | None:
    """A stored count as a float, or ``None`` when it isn't a usable number.

    ``None`` and not-a-number are both "absent": the consumers downstream
    treat *presence* of a derived key as "we have this signal", so coercing
    junk to ``0.0`` would assert a measurement nobody made.

    A **negative** count is absent for the same reason. Nothing here can have
    happened a negative number of times, and the derived values are read
    straight into thresholds: ``false_positive_count: -5`` with 10 TPs is a
    plausible-looking ``fp_ratio: -1.0``, and a negative
    ``weekly_signal_volume`` reads as a quieter detection than silence. One
    guard here rather than at ingest, because every count routes through this
    function and a stored file can be hand-edited after lint.

    Public because the *consumers* need the same answer. ``tuning_metrics``
    enforces omit-don't-fabricate on the way out; a consumer that then defaults
    the absent key to ``0.0`` has undone it one function later, which is
    exactly what both recommenders did. Pair it with ``at_least``.

    It is the read-side coercion for any numeric signal a decision table
    reads, not only stored counts — ``deprecation_recommender`` routes
    ``overlap["score"]`` through it, which is a ratio from ``RuleOverlap`` and
    never touched health storage. The negative guard holds there too (a
    negative similarity is as meaningless as a negative count), but the
    argument above is about counts, so say it once here rather than leave the
    non-count callers looking unjustified.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def at_least(value: float | None, threshold: float) -> bool:
    """``value >= threshold``, and ``False`` when the metric is **absent**.

    The read-side half of omit-don't-fabricate. Written as a helper rather than
    `value is not None and value >= threshold` at each site because every arm
    of both recommenders' decision tables needs it, and the one arm that
    forgets is the one that reports a measurement nobody made: a document
    carrying only `last_true_positive_at` derived
    `{days_since_true_positive: 282}`, and a defaulted `weekly_signal_volume`
    of `0.0` turned that into "No signals in 282 days — candidate for
    deprecation review".

    Bare ``== 0`` needs no helper: ``None == 0`` is already ``False``, so
    "silent" can only be read off a volume that was actually supplied.
    """
    return value is not None and value >= threshold


#: Shortest capture window in which zero signals counts as *silence*. A rule
#: quiet for a day may have fired all last week; a week is also the unit
#: ``weekly_signal_volume`` is normalized to. Both recommenders' silence arms
#: require it, so a collector (``ADEF_WRAPPER_METRICS``) must report
#: ``window_days`` for those arms to fire on its numbers.
MIN_SILENCE_WINDOW_DAYS = 7.0


#: Why ``tuning_metrics`` came back empty, in the words of the three rules it
#: enforces below. One copy, deliberately: ``adef health show`` and the Evolve
#: chain's Health block both have to explain this, and the first time the
#: wording was corrected — the FP requirement is a *pair*, so naming the three
#: fields flat reads as "none of these are present" — only one of the two
#: changed. Markup-free (no ``[bold]``, no ``**``) so the same string is
#: correct in a Rich console and in journal markdown.
NOTHING_DERIVABLE = (
    "a stored `metrics` document needs `signal_count`, and/or BOTH "
    "`false_positive_count` and `true_positive_count` (the FP ratio is over "
    "what was adjudicated, so either count alone derives nothing), and/or "
    "`last_true_positive_at`. Negative or non-numeric values count as absent."
)


def tuning_metrics(latest: dict[str, dict], now: datetime | None = None) -> dict[str, float]:
    """Derive ``{fp_ratio, weekly_signal_volume, days_since_true_positive}``,
    plus ``window_days`` — how long the volume was measured over — so the
    silence arms can refuse a too-short window.

    A thin adapter: documents carry **counts**
    (a ratio can't be re-aggregated across windows — averaging two weeks' FP
    ratios is arithmetically wrong), while ``TuneRecommenderAgent`` and
    ``DeprecationRecommenderAgent`` were written against ratios. Deriving here
    leaves both heuristics and their tests untouched.

    A key is emitted **only** when the counts behind it exist. Both consumers
    decide "insufficient data" on key *presence*, so a fabricated ``0.0``
    would read as a measured zero — the difference between "this detection is
    silent" and "nobody told us anything about it".
    """
    metrics = latest.get("metrics") or {}
    out: dict[str, float] = {}

    tp = as_number(metrics.get("true_positive_count"))
    fp = as_number(metrics.get("false_positive_count"))
    if fp is not None and tp is not None:
        # Denominator is what was *adjudicated*, not every signal: unlabeled
        # signals aren't known false positives, so dividing by `signal_count`
        # would report a detection as cleaner than the labelling supports.
        #
        # BOTH counts must be present. Row contents are deliberately not
        # whitelisted at ingest, so `false_positive_count` with no
        # `true_positive_count` is a valid document — and defaulting the
        # missing TP to zero reported `fp_ratio: 1.0`, "100% false positives",
        # about a number nobody supplied. That is the same fabricated zero this
        # function refuses to emit, just moved into the denominator.
        labeled = fp + tp
        if labeled > 0:
            out["fp_ratio"] = fp / labeled

    signals = as_number(metrics.get("signal_count"))
    if signals is not None:
        # Per *week*, whatever the producer's cadence was — the window is
        # required on `metrics` documents precisely so this is computable. An
        # unreadable window falls back to the raw count rather than dropping
        # the signal; the volume thresholds are order-of-magnitude.
        days = _window_days(metrics.get("window"))
        out["weekly_signal_volume"] = signals * 7.0 / days if days else signals
        if days:
            out["window_days"] = days

    last_tp = parse_iso(metrics.get("last_true_positive_at"))
    if last_tp is not None:
        reference = now or datetime.now(timezone.utc)
        out["days_since_true_positive"] = max(
            (reference - last_tp).total_seconds() / 86400, 0.0
        )
    # ponytail: a detection that has NEVER had a true positive carries no
    # `last_true_positive_at`, so staleness stays absent and the deprecation
    # arms (which need >= 90 / >= 180 days) can't fire for it. The honest
    # answer is the earliest window start in `history/<id>.jsonl` across rows
    # with no TP — a lower bound that actually grows as captures accumulate.
    # Add it when the history reader exists; a single `latest` window would
    # report ~7 days forever, which is worse than absent.
    return out


__all__ = [
    "MIN_SILENCE_WINDOW_DAYS",
    "NOTHING_DERIVABLE",
    "IngestResult",
    "as_number",
    "at_least",
    "detections_with_health",
    "health_dir",
    "parse_iso",
    "read_latest",
    "read_source",
    "sources_with_health",
    "store_health_doc",
    "tuning_metrics",
]
