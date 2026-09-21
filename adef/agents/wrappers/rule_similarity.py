"""Similarity step of the Refine chain — native by default.

Runs `RuleSimilarityAgent` (BM25, optionally LLM-reranked) unless
`ADEF_WRAPPER_RULE_SIMILARITY` is explicitly set, in which case behavior is
unchanged from before: delegate to the configured upstream class.
"""

from __future__ import annotations

import os
from typing import Any

from adef.agents.wrappers._base import NATIVE_ONLY_CTX_KEYS, WrapperBase


class RuleSimilarityWrapper(WrapperBase):
    binding_key = "RULE_SIMILARITY"

    def run(self, detection_id: str, **ctx: Any) -> dict[str, Any]:
        if os.environ.get(self._env_var(), "").strip():
            # Forward everything the caller passed EXCEPT the native-only
            # kwargs the chain injects — a configured upstream class may
            # still need other caller context (see NATIVE_ONLY_CTX_KEYS).
            forwarded = {k: v for k, v in ctx.items() if k not in NATIVE_ONLY_CTX_KEYS}
            return super().run(detection_id=detection_id, **forwarded)
        from adef.agents.rule_similarity import RuleSimilarityAgent

        # `NoCatalogRecordError` (journal-only detection) propagates on purpose —
        # `refine_chain` renders it as its own accurate message rather than the
        # misleading "isn't configured" a `WrapperUnavailable` would produce.
        result = RuleSimilarityAgent().run(detection_id=detection_id, **ctx)
        return {"detection_id": detection_id, "result": result}


__all__ = ["RuleSimilarityWrapper"]
