"""ATT&CK reference layer — runtime read side.

Loads the compact snapshot shipped as package data (``adef/data/attack/
enterprise.json``, distilled from official STIX at build time by
``adef.data.attack._generate``) and answers the questions the catalog and the
mitre-tagger need: is this a real technique ID? which tactics does it belong
to? was it revoked, and what replaced it?

**No STIX, no network, no ``mitreattack-python`` here.** This module only reads
JSON. `adef attack refresh` regenerates the snapshot into the workspace; if a
workspace copy exists it wins over the shipped one (``attack_reference`` checks
``ADEF_WORKSPACE/attack/enterprise.json`` first).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Optional

SNAPSHOT_NAME = "enterprise.json"


@dataclass(frozen=True)
class Resolution:
    """Result of resolving a technique ID against the reference."""

    id: str
    valid: bool
    revoked: bool = False
    deprecated: bool = False
    superseded_by: Optional[str] = None


class AttackReference:
    """Read-only lookup over one ATT&CK snapshot."""

    def __init__(self, snapshot: dict[str, Any]) -> None:
        self.attack_version: str = snapshot.get("attack_version", "")
        self.tactics: dict[str, str] = snapshot.get("tactics", {})
        self.techniques: dict[str, dict[str, Any]] = snapshot.get("techniques", {})

    @classmethod
    def from_path(cls, path: Path) -> "AttackReference":
        if not path.is_file():
            raise FileNotFoundError(f"ATT&CK snapshot not found: {path}")
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def technique(self, tid: str) -> Optional[dict[str, Any]]:
        """The raw entry for ``tid`` (case-insensitive), or None if unknown."""
        return self.techniques.get(tid.strip().upper())

    def is_valid(self, tid: str) -> bool:
        """True if ``tid`` is a real ATT&CK technique ID (revoked/deprecated included)."""
        return self.technique(tid) is not None

    def tactics_for(self, tid: str) -> list[str]:
        """Display names of the tactics ``tid`` belongs to; empty if unknown."""
        entry = self.technique(tid)
        if not entry:
            return []
        return [self.tactics.get(sn, sn) for sn in entry.get("tactics", [])]

    def resolve(self, tid: str) -> Resolution:
        """Classify ``tid``: valid? revoked/deprecated? replacement?"""
        key = tid.strip().upper()
        entry = self.techniques.get(key)
        if entry is None:
            return Resolution(id=key, valid=False)
        return Resolution(
            id=key,
            valid=True,
            revoked=bool(entry.get("revoked")),
            deprecated=bool(entry.get("deprecated")),
            superseded_by=entry.get("superseded_by"),
        )


def _workspace_snapshot() -> Optional[Path]:
    ws = os.getenv("ADEF_WORKSPACE")
    if not ws:
        return None
    candidate = Path(ws).expanduser() / "attack" / SNAPSHOT_NAME
    return candidate if candidate.is_file() else None


@lru_cache(maxsize=1)
def attack_reference() -> AttackReference:
    """The active reference: a ``refresh``-ed workspace snapshot if present,
    else the one shipped as package data. Cached (the snapshot is immutable
    for a process; `refresh` runs in a separate invocation)."""
    ws_snapshot = _workspace_snapshot()
    if ws_snapshot is not None:
        return AttackReference.from_path(ws_snapshot)
    with resources.as_file(
        resources.files("adef.data.attack").joinpath(SNAPSHOT_NAME)
    ) as shipped:
        return AttackReference.from_path(shipped)


__all__ = ["AttackReference", "Resolution", "attack_reference"]
