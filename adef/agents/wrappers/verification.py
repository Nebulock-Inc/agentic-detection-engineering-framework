"""Verification step of the Refine chain — native by default.

Runs `VerificationAgent` (schema + four-engine constraint, vendor-free)
unless `ADEF_WRAPPER_VERIFICATION` is explicitly set, in which case behavior
is unchanged from before: delegate to the configured upstream class.
"""

from __future__ import annotations

import os
from typing import Any

from adef.agents.wrappers._base import WrapperBase, WrapperUnavailable


class VerificationWrapper(WrapperBase):
    binding_key = "VERIFICATION"

    def run(self, detection_id: str, **ctx: Any) -> dict[str, Any]:
        if os.environ.get(self._env_var(), "").strip():
            return super().run(detection_id=detection_id, **ctx)
        from adef.agents.verification import VerificationAgent

        try:
            result = VerificationAgent().run(detection_id=detection_id, **ctx)
        except ValueError as exc:
            # No catalog record for this detection yet (e.g. still journal-only
            # at Find/Observe — nothing to verify). Same treatment as
            # RuleSimilarityWrapper (Task 2): report it the same clean way as
            # an unconfigured wrapper instead of a raw traceback in the journal.
            raise WrapperUnavailable(str(exc)) from exc
        return {"detection_id": detection_id, "result": result}


__all__ = ["VerificationWrapper"]
