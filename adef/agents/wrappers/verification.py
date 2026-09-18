"""Verification step of the Refine chain — native by default.

Runs `VerificationAgent` (schema + four-engine constraint, vendor-free)
unless `ADEF_WRAPPER_VERIFICATION` is explicitly set, in which case behavior
is unchanged from before: delegate to the configured upstream class.
"""

from __future__ import annotations

import os
from typing import Any

from adef.agents.wrappers._base import WrapperBase


class VerificationWrapper(WrapperBase):
    binding_key = "VERIFICATION"

    def run(self, detection_id: str, **ctx: Any) -> dict[str, Any]:
        if os.environ.get(self._env_var(), "").strip():
            # `**ctx` is deliberately NOT forwarded to an upstream override: the
            # chain now injects native-only kwargs (workspace, similarity_mode)
            # that a strict-signature upstream class never accepted before.
            return super().run(detection_id=detection_id)
        from adef.agents.verification import VerificationAgent

        # `NoCatalogRecordError` (journal-only detection) propagates on purpose —
        # `refine_chain` renders it as its own accurate message rather than the
        # misleading "isn't configured" a `WrapperUnavailable` would produce.
        result = VerificationAgent().run(detection_id=detection_id, **ctx)
        return {"detection_id": detection_id, "result": result}


__all__ = ["VerificationWrapper"]
