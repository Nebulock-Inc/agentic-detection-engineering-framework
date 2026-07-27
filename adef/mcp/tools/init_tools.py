"""MCP tools — workspace init and inventory.

``workspace_init`` runs the same scaffolding logic as the ``adef init`` CLI;
``workspace_status`` lists the journals + frontmatter summary so an MCP caller
can orient without invoking shell commands.
"""

from __future__ import annotations

import shutil
from importlib import resources
from pathlib import Path
from typing import Any

from adef.commands.init import DEFAULT_CONFIG, DEFAULT_WORKSPACE, WORKSPACE_AGENTS_MD
from adef.core.journal import Journal, workspace_journals_dir


def _scaffold_workspace(workspace: Path, force: bool) -> dict[str, str]:
    workspace.mkdir(parents=True, exist_ok=True)
    journals = workspace / "journals"
    config_dir = workspace / "config"
    templates_dir = workspace / "templates"
    agents_md = workspace / "AGENTS.md"
    config_file = config_dir / ".adefconfig.yaml"

    journals.mkdir(exist_ok=True)
    config_dir.mkdir(exist_ok=True)
    templates_dir.mkdir(exist_ok=True)

    if not config_file.exists() or force:
        config_file.write_text(DEFAULT_CONFIG, encoding="utf-8")
    if not agents_md.exists() or force:
        agents_md.write_text(WORKSPACE_AGENTS_MD, encoding="utf-8")

    template_target = templates_dir / "DETECTION_FORGE.md"
    with resources.as_file(
        resources.files("adef.data.templates").joinpath("DETECTION_FORGE.md")
    ) as src:
        shutil.copyfile(src, template_target)

    return {
        "workspace": str(workspace),
        "journals_dir": str(journals),
        "config_file": str(config_file),
        "agents_md": str(agents_md),
        "template": str(template_target),
    }


def register(server: Any) -> None:
    """Register init/inventory tools on ``server``."""

    @server.tool()
    def workspace_init(
        path: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Initialize an ADEF workspace at ``path`` (default ``~/work/adef-workspace/``)."""
        ws = (Path(path) if path else DEFAULT_WORKSPACE).expanduser().resolve()
        return _scaffold_workspace(ws, force=force)

    @server.tool()
    def workspace_status(workspace: str | None = None) -> dict[str, Any]:
        """Return journal count + brief inventory for ``workspace``."""
        journals_dir = workspace_journals_dir(Path(workspace) if workspace else None)
        journal = Journal(journals_dir)
        inventory: list[dict[str, Any]] = []
        for entry in journal.iter_entries():
            inventory.append(
                {
                    "detection_id": entry.detection_id,
                    "title": entry.frontmatter.get("title", ""),
                    "current_stage": entry.current_stage,
                    "rule_uuid": entry.rule_uuid,
                    "path": str(entry.path),
                }
            )
        return {
            "workspace": str(journals_dir.parent),
            "journals_dir": str(journals_dir),
            "count": len(inventory),
            "journals": inventory,
        }


__all__ = ["register"]
