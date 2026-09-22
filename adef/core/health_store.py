"""Storage for detection-health capture documents.

Hybrid by design: ``latest/`` answers "what is true now" in a single read,
``history/`` is the append-only substrate the trend analysis in story 10097
consumes. History rows are the document's own per-detection rows plus a
timestamp and kind — small, so growth is bounded by ingest cadence rather than
by document size.

Pure: ``known_ids`` is supplied by the caller rather than read from the catalog
here, so this module is testable without building a catalog fixture.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path

import yaml

from adef.core.health_docs import DETECTION_KEYED_KINDS, HealthDoc
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
    """Replace this kind's entry in ``path``, leaving other kinds intact."""
    existing: dict = {}
    if path.exists():
        existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
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
    """
    result = IngestResult(kind=doc.kind)
    envelope = {
        "captured_at": doc.captured_at,
        "environment": doc.environment,
        "window": doc.window,
    }

    if doc.kind in DETECTION_KEYED_KINDS:
        for row in doc.detections:
            det_id = str(row["detection_id"])
            if det_id not in known_ids:
                result.unmatched.append(det_id)
                continue
            result.matched.append(det_id)
            if dry_run:
                continue
            payload = {**row, **envelope}
            latest_path = health_root / "latest" / f"{det_id}.yml"
            _merge_latest(latest_path, doc.kind, payload)
            history_path = health_root / "history" / f"{det_id}.jsonl"
            _append_history(history_path, {"kind": doc.kind, **row, "captured_at": doc.captured_at})
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
        result.matched.append(name)
        if dry_run:
            continue
        path = health_root / "sources" / f"{name}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump({**payload, **envelope}, sort_keys=True), encoding="utf-8"
        )
        result.paths_written.append(path)

    return result


__all__ = ["IngestResult", "health_dir", "store_health_doc"]
