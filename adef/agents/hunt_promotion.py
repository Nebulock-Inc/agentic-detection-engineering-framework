"""HuntPromotionAgent — convert an upstream hunt artifact into a draft ADEF detection.

The agent is intentionally **decoupled** from any specific hunt-management
package. It looks up a ``DetectionRuleGenerator`` class via a dotted path
(default: ``ADEF_HUNT_RULE_GENERATOR`` env var). The generator is expected to
expose ``run(hunt_id=...)`` and return either a dict with keys ``yaml``,
``title``, ``uuid`` or a string of YAML.

If no generator is configured, the agent raises ``HuntPromotionError`` cleanly
(no traceback) — the caller can surface a user-friendly message.

The agent also writes a journal at the Find stage. The journal lives in the
ADEF workspace (NOT in any external rule directory) and is paired to the
draft via ``rule_uuid`` if the generator returns one.
"""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from adef.core.journal import Journal, next_detection_id, workspace_journals_dir


class HuntPromotionError(RuntimeError):
    """User-facing error during hunt promotion (clean exit, no traceback)."""


@dataclass
class HuntPromotionResult:
    hunt_id: str
    detection_id: str
    staging_yaml: Path
    journal_path: Path


def _resolve_optional_dir(explicit: Optional[Path], env_var: str) -> Optional[Path]:
    if explicit is not None:
        candidate = explicit.expanduser()
    elif env := os.environ.get(env_var):
        candidate = Path(env).expanduser()
    else:
        return None
    candidate = candidate.resolve()
    return candidate if candidate.is_dir() else None


def _resolve_required_dir(explicit: Optional[Path], env_var: str, label: str) -> Path:
    if explicit is not None:
        candidate = explicit.expanduser()
    elif env := os.environ.get(env_var):
        candidate = Path(env).expanduser()
    else:
        raise HuntPromotionError(
            f"{label} is not configured. Pass the matching --option or set {env_var}."
        )
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise HuntPromotionError(f"{label} {candidate} is not a directory.")
    return candidate


class HuntPromotionAgent:
    """Promote an upstream hunt to a draft ADEF detection + populated journal."""

    GENERATOR_ENV = "ADEF_HUNT_RULE_GENERATOR"

    def __init__(
        self,
        hunt_root: Optional[Path] = None,
        rule_staging_root: Optional[Path] = None,
        workspace_root: Optional[Path] = None,
    ) -> None:
        # ``hunt_root`` is informational for the caller (passed to the generator
        # if it accepts it); ADEF doesn't read hunt files itself.
        self.hunt_root = _resolve_optional_dir(hunt_root, "ADEF_HUNT_ROOT")
        self.rule_staging_root = _resolve_required_dir(
            rule_staging_root,
            "ADEF_RULE_STAGING_ROOT",
            "rule-staging root",
        )
        self.workspace_root = workspace_root

    def _load_generator(self) -> Any:
        dotted = os.environ.get(self.GENERATOR_ENV, "").strip()
        if not dotted:
            raise HuntPromotionError(
                f"No hunt-rule generator is configured. Set {self.GENERATOR_ENV} "
                "to a dotted import path (e.g. 'mypkg.agents:DetectionRuleGenerator')."
            )
        module_path, _, class_name = dotted.partition(":")
        if not module_path or not class_name:
            raise HuntPromotionError(
                f"{self.GENERATOR_ENV} must be of the form 'module.path:ClassName'; got {dotted!r}."
            )
        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise HuntPromotionError(
                f"Could not import {module_path}: {exc}. "
                f"Install the package or correct {self.GENERATOR_ENV}."
            ) from exc
        cls = getattr(module, class_name, None)
        if cls is None:
            raise HuntPromotionError(f"{class_name} not found in {module_path}.")
        return cls

    def run(self, hunt_id: str) -> HuntPromotionResult:
        Generator = self._load_generator()
        try:
            generated = Generator().run(hunt_id=hunt_id)
        except Exception as exc:  # noqa: BLE001 — surface clean error to user
            raise HuntPromotionError(
                f"hunt-rule generator failed for {hunt_id}: {exc}"
            ) from exc

        self.rule_staging_root.mkdir(parents=True, exist_ok=True)

        journals_dir = workspace_journals_dir(self.workspace_root)
        detection_id = next_detection_id(journals_dir)

        staging_yaml = self.rule_staging_root / f"{detection_id.replace('D-', 'D-draft-')}.yml"
        body = generated.get("yaml") if isinstance(generated, dict) else str(generated)
        staging_yaml.write_text(body or "", encoding="utf-8")

        journal = Journal(journals_dir).create(
            detection_id=detection_id,
            title=str(
                (generated.get("title") if isinstance(generated, dict) else None)
                or f"Promoted from {hunt_id}"
            ),
            owner="",
            rule_uuid=str((generated.get("uuid") if isinstance(generated, dict) else "") or ""),
            note=f"Promoted from upstream hunt {hunt_id}. Draft YAML: {staging_yaml}",
        )

        return HuntPromotionResult(
            hunt_id=hunt_id,
            detection_id=detection_id,
            staging_yaml=staging_yaml,
            journal_path=journal.path,
        )


__all__ = [
    "HuntPromotionAgent",
    "HuntPromotionError",
    "HuntPromotionResult",
]
