"""MCP tools — detection-health capture ingestion.

Same core functions the `adef ingest` CLI uses. This is what "MCP-driven
tuning" means in practice: an assistant session that already has its own
tooling connected fetches the numbers, writes a capture document, and calls
this tool with it. ADEF still makes no call to the environment itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from adef.core.catalog import known_detection_ids
from adef.core.health_docs import HealthDocError, load_health_doc
from adef.core.health_store import health_dir, store_health_doc
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
        result = store_health_doc(
            doc, health_dir(ws_arg), known_ids=known_ids, dry_run=dry_run
        )
        return {
            "kind": result.kind,
            "matched": result.matched,
            "unmatched": result.unmatched,
            "dry_run": dry_run,
            "paths_written": [str(p) for p in result.paths_written],
        }


__all__ = ["register"]
