"""Similarity step of the Refine chain — native by default.

Runs `RuleSimilarityAgent` (BM25, optionally LLM-reranked) unless
`ADEF_WRAPPER_RULE_SIMILARITY` is explicitly set, in which case behavior is
unchanged from before: delegate to the configured upstream class.
"""

from __future__ import annotations

import os
from typing import Any

from adef.agents.wrappers._base import WrapperBase, WrapperUnavailable


class RuleSimilarityWrapper(WrapperBase):
    binding_key = "RULE_SIMILARITY"

    def run(self, detection_id: str, **ctx: Any) -> dict[str, Any]:
        if os.environ.get(self._env_var(), "").strip():
            return super().run(detection_id=detection_id, **ctx)
        from adef.agents.rule_similarity import RuleSimilarityAgent

        try:
            result = RuleSimilarityAgent().run(detection_id=detection_id, **ctx)
        except ValueError as exc:
            # No catalog record for this detection yet (e.g. still journal-only
            # at Find/Observe — nothing to compare for similarity). A real, common
            # lifecycle gap, not a code bug — report it the same clean way as an
            # unconfigured wrapper instead of letting refine_chain log a raw
            # traceback for it.
            raise WrapperUnavailable(str(exc)) from exc
        return {"detection_id": detection_id, "result": result}


__all__ = ["RuleSimilarityWrapper"]
