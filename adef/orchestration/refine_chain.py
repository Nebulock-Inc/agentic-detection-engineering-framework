"""Refine orchestration — Similarity → Overlap → Verification.

The Refine stage chains three upstream rule-engineering agents and appends
each result to the detection's journal under the Refine block. The wrappers
in ``adef.agents.wrappers.*`` adapt the upstream agents to a uniform
``run(detection_id, **ctx)`` shape.

Failure of any individual agent is surfaced and logged into the journal but
does NOT abort the chain — partial results are useful, and the user can
re-run after fixing a missing prerequisite (e.g., ClickHouse access).
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from typing import Any

from adef.core.journal import Journal


@dataclass
class ChainStep:
    name: str
    heading: str
    wrapper_attr: str  # name on adef.agents.wrappers


REFINE_STEPS: tuple[ChainStep, ...] = (
    ChainStep(name="similarity", heading="Refine / Similarity",
              wrapper_attr="RuleSimilarityWrapper"),
    ChainStep(name="overlap", heading="Refine / Overlap",
              wrapper_attr="RuleOverlapWrapper"),
    ChainStep(name="verification", heading="Refine / Verification",
              wrapper_attr="VerificationWrapper"),
)


def _format_payload(payload: Any) -> str:
    """Render an agent's return value into a journal-friendly markdown body."""
    if payload is None:
        return "_(no result)_"
    if isinstance(payload, dict):
        lines = [f"- **{k}:** {v}" for k, v in payload.items()]
        return "\n".join(lines)
    if isinstance(payload, (list, tuple)):
        return "\n".join(f"- {item}" for item in payload) or "_(empty)_"
    return str(payload)


def run_refine_chain(journal: Journal, detection_id: str, **context: Any) -> dict[str, Any]:
    """Run Similarity → Overlap → Verification and append results to ``detection_id``.

    Returns a dict mapping step name → ``{"ok": bool, "result": Any, "error": str | None}``.
    """
    from adef.agents import wrappers as wrappers_pkg

    summary: dict[str, Any] = {}
    for step in REFINE_STEPS:
        cls = getattr(wrappers_pkg, step.wrapper_attr, None)
        if cls is None:
            body = f"_Wrapper `{step.wrapper_attr}` not available — skipping._"
            journal.append_block(detection_id, step.heading, body)
            summary[step.name] = {"ok": False, "result": None, "error": "wrapper-missing"}
            continue
        try:
            result = cls().run(detection_id=detection_id, **context)
            journal.append_block(detection_id, step.heading, _format_payload(result))
            summary[step.name] = {"ok": True, "result": result, "error": None}
        except Exception as exc:  # noqa: BLE001 — chain must not abort
            tb = traceback.format_exc(limit=2)
            body = f"**Failed:** {exc}\n\n```\n{tb}\n```"
            journal.append_block(detection_id, step.heading, body)
            summary[step.name] = {"ok": False, "result": None, "error": str(exc)}
    return summary


__all__ = ["run_refine_chain", "ChainStep", "REFINE_STEPS"]
