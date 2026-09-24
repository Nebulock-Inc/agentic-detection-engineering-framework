"""The catalog-record text projection shared by search, similarity, and overlap.

Extracted from ``adef.commands.detection._record_search_text`` (2026-09-18) so
agents can build the same searchable text without importing a CLI module.
"""

from __future__ import annotations


def record_search_text(data: dict) -> str:
    """The catalog fields worth searching on — so a detection is findable by
    *what it detects* (title, MITRE, platform, source, query), not only by what
    its journal says."""
    parts = [
        str(data.get("title", "")),
        " ".join(data.get("mitre") or []),
        str(data.get("platform", "")),
        str(data.get("data_source", "")),
        str(data.get("format", "")),
        str(data.get("query", "")),
    ]
    return " ".join(p for p in parts if p)


__all__ = ["record_search_text"]
