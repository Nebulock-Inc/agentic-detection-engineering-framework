"""Canonical workspace resolution — one resolver for every command.

Order: explicit ``--workspace`` → ``ADEF_WORKSPACE`` → the current directory
(when it looks like a workspace) → ``~/work/adef-workspace``. Grew from three
diverging per-command copies; a command that skips a rung sends users hunting
for config they already wrote (`adef init --interactive` sets ``platform:``,
then ``schema reshape`` claimed it wasn't configured).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

DEFAULT_WORKSPACE = Path.home() / "work" / "adef-workspace"


def resolve_workspace(explicit: Path | None = None) -> Path:
    """Resolve the workspace: explicit arg → ADEF_WORKSPACE → cwd → default."""
    if explicit is not None:
        ws = Path(explicit)
    elif env := os.environ.get("ADEF_WORKSPACE"):
        ws = Path(env)
    elif any((Path.cwd() / marker).is_dir() for marker in ("catalog", "journals")):
        ws = Path.cwd()
    else:
        ws = DEFAULT_WORKSPACE
    return ws.expanduser().resolve()


def config_path(workspace: Path) -> Path:
    return workspace / "config" / ".adefconfig.yaml"


def read_config(workspace: Path) -> dict:
    """Parsed .adefconfig.yaml, or {} when absent/unreadable."""
    path = config_path(workspace)
    if not path.is_file():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}


def platform_from_config(workspace: Path) -> str | None:
    """The ``platform:`` set by ``adef init --interactive``, if any."""
    value = read_config(workspace).get("platform")
    return str(value) if value else None
