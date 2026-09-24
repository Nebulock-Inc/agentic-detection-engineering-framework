"""MCP tools — read-only memory search across journals.

Backed by ``adef.core.memory.MemoryIndex`` (BM25). The index is rebuilt per
call in v0.1.0 — corpora are small (≤ a few hundred journals); we measure
before optimizing.
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
        """Search journal markdown for ``query``. Returns ranked hits."""
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
