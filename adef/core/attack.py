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
        # One fold for the lookup, via `technique`. This had its own copy of
        # `.strip().upper()` and its own `self.techniques.get(...)`, which made
        # case-insensitivity two implementations tested once: deleting the
        # `.upper()` here left all 1073 tests green, because every test that
        # touches `resolve` passes an already-upper-case ID. `key` stays, but
        # only for the ID echoed back in the result.
        key = tid.strip().upper()
        entry = self.technique(tid)
        if entry is None:
            return Resolution(id=key, valid=False)
        return Resolution(
            id=key,
            valid=True,
            revoked=bool(entry.get("revoked")),
            deprecated=bool(entry.get("deprecated")),
            superseded_by=entry.get("superseded_by"),
        )


def _workspace_snapshot(workspace: Optional[Path] = None) -> Optional[Path]:
    """The named workspace's snapshot, or ``None`` to mean "use the shipped one".

    An explicit ``workspace`` **replaces** ``$ADEF_WORKSPACE``; it does not take
    priority over it with the env var as a second rung. So
    `adef catalog ./rules --workspace /scratch`, where `/scratch` has no
    `attack/enterprise.json`, judges against the shipped snapshot even when
    ``$ADEF_WORKSPACE`` holds a `refresh`-ed newer one — a rule mapped to a
    technique newer than the shipped copy comes out `invalid_mitre`.

    That is the intended reading of `--workspace X`: X's snapshot or the shipped
    baseline, never a *third* workspace's. Falling back to the env var would mean
    records written into X carry a verdict reached against a snapshot X has never
    seen, which is the cross-workspace bleed the threading exists to stop. The
    fix for the narrow case is `adef attack refresh --workspace X`.
    `adef doctor --workspace X` is where you see you need it: its `att&ck` line
    labels the reference `(shipped)` or `(workspace snapshot)` for X
    specifically. It deliberately offers no `fix` command — the shipped snapshot
    is a supported state, not a deficiency — so the label is the whole signal.
    """
    ws = str(workspace) if workspace is not None else os.getenv("ADEF_WORKSPACE")
    if not ws:
        return None
    candidate = Path(ws).expanduser() / "attack" / SNAPSHOT_NAME
    return candidate if candidate.is_file() else None


@lru_cache(maxsize=4)
def attack_reference(workspace: Optional[Path] = None) -> AttackReference:
    """The active reference: a ``refresh``-ed workspace snapshot if present,
    else the one shipped as package data. Cached (the snapshot is immutable
    for a process; `refresh` runs in a separate invocation).

    ``workspace`` overrides ``$ADEF_WORKSPACE`` for callers that resolved a
    workspace from a ``--workspace`` flag. Without it this resolver could only
    ever see the environment variable, so `adef doctor --workspace /srv/ws`
    reported the *shipped* snapshot's version and counts while labelling them
    the workspace's — and the cache meant the answer also depended on whether
    something earlier in the process had already warmed it. Keyed on the
    argument, so the zero-arg behaviour every other caller relies on is
    unchanged.

    "Immutable for a process" is a CLI assumption and the cache has no
    invalidation, so a snapshot written *after* a read in the same process is
    not seen. Two places that matters, neither of them a rule any code here
    follows today: a long-running ``adef-mcp`` that has already served one
    request keeps the snapshot it first read for its whole lifetime, so an
    out-of-band ``adef attack refresh`` takes effect on restart and not before
    (cross-process, so a ``cache_clear()`` in ``refresh`` would not help it);
    and the suite's own fixtures, which plant a snapshot into a workspace an
    earlier command already read and so have to clear it themselves.
    """
    ws_snapshot = _workspace_snapshot(workspace)
    if ws_snapshot is not None:
        return AttackReference.from_path(ws_snapshot)
    with resources.as_file(
        resources.files("adef.data.attack").joinpath(SNAPSHOT_NAME)
    ) as shipped:
        return AttackReference.from_path(shipped)


__all__ = ["AttackReference", "Resolution", "attack_reference"]
