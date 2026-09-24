"""Storage for detection-health capture documents.

Hybrid by design: ``latest/`` answers "what is true now" in a single read,
``history/`` is the append-only substrate the trend analysis in story 10097
consumes. History rows are the document's own per-detection row plus
kind/captured_at/window — small, so growth is bounded by ingest cadence rather
than by document size. ``deployed_query`` (whole-document-sized text) is kept
in ``latest/`` only, never appended to history.

Pure: ``known_ids`` is supplied by the caller rather than read from the catalog
here, so this module is testable without building a catalog fixture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path

import yaml

from adef.core.health_docs import (
    DETECTION_KEYED_KINDS,
    HealthDoc,
    HealthDocError,
    _DETECTION_ID_RE,
    _unsafe_source_name,
)
from adef.core.workspace import resolve_workspace


@dataclass
class IngestResult:
    """What one ``store_health_doc`` call did."""

    kind: str
    matched: list[str] = dataclass_field(default_factory=list)
    unmatched: list[str] = dataclass_field(default_factory=list)
    paths_written: list[Path] = dataclass_field(default_factory=list)


def health_dir(workspace: Path | None = None) -> Path:
    """Workspace health dir via the canonical resolver (honors --workspace, env,
    cwd, default), matching ``_get_workspace_schema_dir``'s behavior."""
    return resolve_workspace(workspace) / "health"


def _merge_latest(path: Path, kind: str, payload: dict) -> None:
    """Replace this kind's entry in ``path``, leaving other kinds intact.

    Guards the existing file the way ``declaration.py``'s ``read_schema_v2``
    does: a non-mapping YAML value or unparseable YAML raises a clean
    ``HealthDocError`` instead of a raw ``TypeError``/``yaml.YAMLError`` out of
    the CLI. Matters more than usual here because writes are non-atomic, so a
    crash mid-write must not also leave the *next* run with an unhandled
    traceback.
    """
    existing: dict = {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise HealthDocError(f"{path}: could not be read as YAML ({exc})") from exc
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise HealthDocError(
                    f"{path}: expected a mapping, got {type(loaded).__name__}"
                )
            existing = loaded
    existing[kind] = payload
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(existing, sort_keys=True), encoding="utf-8")


def _append_history(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


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
        # Carried through so story 10097 can see which transforms the
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
            _merge_latest(latest_path, doc.kind, payload)
            # History rows are the thin, append-only trend substrate (design
            # doc "Storage"): drop `deployed_query` (whole-document growth,
            # not a numeric field) and set kind/captured_at/window *after*
            # spreading the row, so a row that happens to carry those key
            # names can never override the document's real values.
            history_row = {k: v for k, v in row.items() if k != "deployed_query"}
            history_row["kind"] = doc.kind
            history_row["captured_at"] = doc.captured_at
            history_row["window"] = doc.window
            history_path = health_root / "history" / f"{det_id}.jsonl"
            _append_history(history_path, history_row)
            result.paths_written.extend([latest_path, history_path])
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
        _merge_latest(path, doc.kind, {**payload, **envelope})
        result.paths_written.append(path)

    return result


__all__ = ["IngestResult", "health_dir", "store_health_doc"]
