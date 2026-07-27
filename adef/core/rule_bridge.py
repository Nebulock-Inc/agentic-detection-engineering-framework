"""Read-only bridge to an external rule store for memory search and backfill.

ADEF never writes to the upstream rule store. This module reads YAML rule
metadata for two purposes:

- ``MemoryIndex`` ranks rule-YAML metadata alongside markdown journals so a
  single ``adef memory search`` query covers both surfaces.
- ``adef backfill journals`` enumerates rules to create skeleton journals.

The bridge is deliberately conservative: it reads ``id`` (or ``uuid``),
``name``, ``description``, ``mitre`` (if present), and the file path. It does
not parse engine-specific fields. If the configured rule root does not exist
on disk, the bridge degrades to "no rules visible" rather than raising
``ImportError``.

Configuration:

- ``rule_root`` argument (when called from CLI / library code).
- ``ADEF_RULE_ROOT`` environment variable.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class RuleMetadata:
    """Subset of an external rule's YAML used by ADEF."""

    uuid: str
    name: str
    description: str
    mitre: tuple[str, ...]
    path: Path


def _resolve_rule_root(explicit: Path | None) -> Path | None:
    """Resolve rule-store root from explicit arg → env."""
    if explicit is not None:
        candidate = explicit.expanduser()
    elif env := os.environ.get("ADEF_RULE_ROOT"):
        candidate = Path(env).expanduser()
    else:
        return None
    candidate = candidate.resolve()
    return candidate if candidate.is_dir() else None


def _iter_rule_files(detections_root: Path) -> Iterator[Path]:
    """Yield every YAML file under ``detections_root``."""
    for ext in ("*.yml", "*.yaml"):
        yield from detections_root.rglob(ext)


def iter_rules(rule_root: Path | None = None) -> Iterable[RuleMetadata]:
    """Yield every external rule's metadata (read-only).

    Returns empty if the rule root isn't on disk; never raises ``ImportError``.
    """
    root = _resolve_rule_root(rule_root)
    if root is None:
        return
    detections_dir = root / "detections"
    if not detections_dir.is_dir():
        return

    for path in _iter_rule_files(detections_dir):
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(data, dict):
            continue

        uuid = str(data.get("id") or data.get("uuid") or "").strip()
        if not uuid:
            continue
        name = str(data.get("name") or data.get("title") or path.stem)
        description = str(data.get("description") or "")
        mitre_raw = data.get("mitre") or data.get("attack") or ()
        if isinstance(mitre_raw, dict):
            mitre = tuple(str(t) for t in mitre_raw.get("technique", ()))
        elif isinstance(mitre_raw, (list, tuple)):
            mitre = tuple(str(t) for t in mitre_raw)
        else:
            mitre = ()

        yield RuleMetadata(
            uuid=uuid,
            name=name,
            description=description,
            mitre=mitre,
            path=path,
        )


__all__ = ["RuleMetadata", "iter_rules"]
