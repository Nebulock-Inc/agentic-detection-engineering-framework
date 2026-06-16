"""MCP tools — FORGE lifecycle operations.

Exposes ``forge_advance`` (advance a detection to a stage), ``forge_status``
(read frontmatter + current stage), and ``forge_create`` (open a new journal
at the Find stage). Each delegates to ``adef.core.journal.Journal`` so the
hard invariant on writes inside any rule ``detections/`` tree is respected
through a single choke point.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from adef.core.journal import (
    FORGE_STAGES,
    Journal,
    JournalError,
    next_detection_id,
    workspace_journals_dir,
)


def _journal(workspace: Optional[str]) -> Journal:
    return Journal(workspace_journals_dir(Path(workspace) if workspace else None))


def register(server: Any) -> None:
    """Register lifecycle tools on ``server`` (FastMCP instance)."""

    @server.tool()
    def forge_create(
        title: str,
        owner: str = "",
        rule_uuid: str = "",
        note: str = "",
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a new D-XXXX journal at the Find stage."""
        journal = _journal(workspace)
        detection_id = next_detection_id(journal.directory)
        entry = journal.create(
            detection_id=detection_id,
            title=title,
            owner=owner,
            rule_uuid=rule_uuid,
            note=note,
        )
        return {
            "detection_id": detection_id,
            "path": str(entry.path),
            "stage": "find",
        }

    @server.tool()
    def forge_advance(
        detection_id: str,
        stage: str,
        note: str = "",
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Advance ``detection_id`` to ``stage`` (one of FORGE_STAGES). Idempotent."""
        if stage not in FORGE_STAGES:
            return {"error": f"Unknown stage {stage!r}. Expected one of {list(FORGE_STAGES)}."}
        try:
            result = _journal(workspace).advance_stage(detection_id, stage, note=note)
        except JournalError as exc:
            return {"error": str(exc)}
        return {
            "detection_id": result.detection_id,
            "stage": result.stage,
            "was_idempotent": result.was_idempotent,
            "timestamp": result.timestamp,
        }

    @server.tool()
    def forge_status(
        detection_id: str,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Return frontmatter + current stage for ``detection_id``."""
        try:
            entry = _journal(workspace).read(detection_id)
        except JournalError as exc:
            return {"error": str(exc)}
        return {
            "detection_id": entry.detection_id,
            "current_stage": entry.current_stage,
            "frontmatter": entry.frontmatter,
            "path": str(entry.path),
        }


__all__ = ["register"]
