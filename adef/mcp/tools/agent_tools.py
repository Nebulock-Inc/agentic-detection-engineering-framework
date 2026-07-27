"""MCP tools — agent orchestration triggers + individual agent invocations.

Two flavors:

1. ``run_refine_chain`` — orchestration trigger that calls the Similarity →
   Overlap → Verification chain and writes results into the journal.
2. ``hypothesis_from_intel`` / ``tune_recommend`` / ``deprecation_recommend`` —
   ADEF-native agents from ``adef.agents``. Wrappers around upstream rule
   agents are intentionally NOT exposed individually here in v0.1.0; callers
   should use ``run_refine_chain`` (chained) or invoke the upstream agents
   through their own CLI until v0.2 carves a stable schema.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from adef.agents.deprecation_recommender import DeprecationRecommenderAgent
from adef.agents.hypothesis_from_intel import HypothesisFromIntelAgent
from adef.agents.tune_recommender import TuneRecommenderAgent
from adef.core.journal import Journal, workspace_journals_dir
from adef.orchestration.refine_chain import run_refine_chain


def _to_dict(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def register(server: Any) -> None:
    """Register agent + orchestration tools on ``server``."""

    @server.tool()
    def refine_chain(
        detection_id: str,
        workspace: str | None = None,
    ) -> dict[str, Any]:
        """Run the Refine chain (Similarity → Overlap → Verification) for a detection."""
        journals_dir = workspace_journals_dir(Path(workspace) if workspace else None)
        journal = Journal(journals_dir)
        return _to_dict(run_refine_chain(journal, detection_id))

    @server.tool()
    def hypothesis_from_intel(intel_url_or_text: str) -> dict[str, Any]:
        """Turn a CTI URL or pasted text into a draft Find/Observe block."""
        return _to_dict(HypothesisFromIntelAgent().run(intel_url_or_text))

    @server.tool()
    def tune_recommend(
        detection_id: str,
        metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Recommend tuning actions from performance metrics (or live wrapper)."""
        return _to_dict(TuneRecommenderAgent().run(detection_id, metrics=metrics))

    @server.tool()
    def deprecation_recommend(
        detection_id: str,
        performance: dict[str, Any] | None = None,
        overlap: dict[str, Any] | None = None,
        findings: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Decide keep / tune / deprecate from three orthogonal signals."""
        return _to_dict(
            DeprecationRecommenderAgent().run(
                detection_id,
                performance=performance,
                overlap=overlap,
                findings=findings,
            )
        )


__all__ = ["register"]
