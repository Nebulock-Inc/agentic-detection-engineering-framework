"""MCP tools — detection-health capture ingestion and readback.

Same core functions the `adef ingest` / `adef health show` CLI uses. This is
what "MCP-driven tuning" means in practice: an assistant session that already
has its own tooling connected fetches the numbers, writes a capture document,
calls `health_ingest` with it, and reads back what landed. ADEF still makes no
call to the environment itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from adef.core.catalog import known_detection_ids
from adef.core.health_docs import HealthDocError, load_health_doc, near_miss_row_keys
from adef.core.health_store import (
    detections_with_health,
    health_dir,
    read_latest,
    read_source,
    sources_with_health,
    store_health_doc,
    tuning_metrics,
)
from adef.core.workspace import resolve_workspace


def register(server: Any) -> None:
    """Register health tools on ``server``."""

    @server.tool()
    def health_ingest(
        document_path: str,
        dry_run: bool = False,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Ingest a detection-health capture document. Routes on its own `kind`."""
        ws_arg = Path(workspace) if workspace else None
        try:
            doc = load_health_doc(Path(document_path))
        except HealthDocError as exc:
            # A malformed document is expected user input, not an exceptional
            # condition — return it so the assistant can show and fix it.
            return {"error": str(exc)}

        ws = resolve_workspace(ws_arg)
        known_ids = known_detection_ids(ws)
        try:
            result = store_health_doc(
                doc, health_dir(ws_arg), known_ids=known_ids, dry_run=dry_run
            )
        except HealthDocError as exc:
            return {"error": str(exc)}
        return {
            "kind": result.kind,
            "matched": result.matched,
            "unmatched": result.unmatched,
            "superseded": result.superseded,
            # Same warning `adef ingest` prints. An assistant that shaped the
            # document itself is the likeliest author of a near-miss key, and
            # the one caller able to fix it and re-ingest in the same turn.
            "ignored_keys": near_miss_row_keys(doc),
            "dry_run": dry_run,
            "paths_written": [str(p) for p in result.paths_written],
        }

    @server.tool()
    def health_show(
        detection_id: Optional[str] = None,
        source: Optional[str] = None,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Read back ingested health — for one detection or source, or everything stored.

        The readback half of `health_ingest`. Answers both "did my document
        land on the detection I meant?" (ingest skips rows naming an unknown
        detection) and "what would the Evolve chain see?" — `metrics` is the
        derived view the tuning and deprecation heuristics actually consume.

        `source_health` and `field_observations` are keyed by a free-form
        telemetry source name rather than a `D-XXXX`, so they are reached with
        `source=` and appear under `sources` in the full listing.
        """
        root = health_dir(Path(workspace) if workspace else None)
        try:
            if detection_id and source:
                return {"error": "Give either detection_id or source, not both."}
            if source is not None:
                return {"source": source, "latest": read_source(root, source)}
            if detection_id is None:
                stored = {
                    det_id: read_latest(root, det_id)
                    for det_id in detections_with_health(root)
                }
                return {
                    "detections": [
                        {
                            "detection_id": det_id,
                            "latest": latest,
                            "metrics": tuning_metrics(latest),
                        }
                        # One read per detection: the comprehension used to call
                        # `read_latest` twice, so a listing did 2N file reads.
                        for det_id, latest in stored.items()
                    ],
                    "sources": {
                        name: read_source(root, name)
                        for name in sources_with_health(root)
                    },
                }
            latest = read_latest(root, detection_id)
            return {
                "detection_id": detection_id,
                "latest": latest,
                "metrics": tuning_metrics(latest),
            }
        except HealthDocError as exc:
            return {"error": str(exc)}


__all__ = ["register"]
