"""MCP tools — read-only memory search across the workspace corpus.

Backed by ``adef.core.memory.MemoryIndex`` (BM25) over
``adef.core.corpus.build_corpus`` — every detection that has a catalog record
and/or a journal, not journals alone. The index is rebuilt per call in
v0.1.0 — corpora are small (≤ a few hundred detections); we measure before
optimizing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from adef.core.corpus import build_corpus
from adef.core.journal import workspace_journals_dir
from adef.core.memory import MemoryIndex


def register(server: Any) -> None:
    """Register memory tools on ``server``."""

    @server.tool()
    def memory_search(
        query: str,
        limit: int = 10,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Search detections by journal reasoning AND catalog metadata for
        ``query`` (BM25). Returns ranked hits, each with a `path` to the
        matched journal or catalog record — a catalogued detection with no
        journal, or a fresh draft with no catalog record yet, is included
        too, not just detections with both."""
        ws = workspace_journals_dir(Path(workspace) if workspace else None).parent
        index = MemoryIndex()
        index.build(build_corpus(ws))
        hits = index.search(query, limit=limit)
        return {
            "query": query,
            "count": len(hits),
            "hits": [
                {
                    "detection_id": h.detection_id,
                    "score": h.score,
                    "title": h.title,
                    "current_stage": h.current_stage,
                    "snippet": h.snippet,
                    "path": str(h.path),
                }
                for h in hits
            ],
        }


__all__ = ["register"]
