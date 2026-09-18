"""Overlap step of the Refine chain — native by default.

Runs `RuleOverlapAgent` (deterministic, vendor-free) unless
`ADEF_WRAPPER_RULE_OVERLAP` is explicitly set, in which case behavior is
unchanged from before: delegate to the configured upstream class.
"""

from __future__ import annotations

import os
from typing import Any

from adef.agents.wrappers._base import WrapperBase, WrapperUnavailable


class RuleOverlapWrapper(WrapperBase):
    binding_key = "RULE_OVERLAP"

    def run(self, detection_id: str, **ctx: Any) -> dict[str, Any]:
        if os.environ.get(self._env_var(), "").strip():
            return super().run(detection_id=detection_id, **ctx)
        from adef.agents.rule_overlap import RuleOverlapAgent

        try:
            result = RuleOverlapAgent().run(detection_id=detection_id, **ctx)
        except ValueError as exc:
            # No catalog record for this detection yet (e.g. still journal-only
            # at Find/Observe — nothing to compare for overlap). Same treatment
            # as RuleSimilarityWrapper (Task 2): report it the same clean way as
            # an unconfigured wrapper instead of a raw traceback in the journal.
            raise WrapperUnavailable(str(exc)) from exc
        return {"detection_id": detection_id, "result": result}


__all__ = ["RuleOverlapWrapper"]
