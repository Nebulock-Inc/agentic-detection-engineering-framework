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
from typing import Any, Literal, Optional, cast

from adef.agents.deprecation_recommender import DeprecationRecommenderAgent
from adef.agents.hypothesis_from_intel import HypothesisFromIntelAgent
from adef.agents.tune_recommender import TuneRecommenderAgent, stored_metrics
from adef.core.journal import Journal, workspace_journals_dir
from adef.orchestration.evolve_chain import run_evolve_chain
from adef.orchestration.refine_chain import run_refine_chain


def _to_dict(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
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
        workspace: Optional[str] = None,
        # Appended, never inserted: `workspace` was already the second
        # positional of a published tool, so slotting a new parameter ahead of
        # it would bind an existing caller's workspace path to this one.
        similarity_mode: Literal["bm25", "agent", "llm", "auto"] = "agent",
    ) -> dict[str, Any]:
        """Run the Refine chain (Similarity → Overlap → Verification) for a detection.

        Defaults to ``agent`` similarity: you get the BM25 shortlist enriched
        with each candidate's query, MITRE IDs, platform, and data source, and
        you do the ranking. You have context ADEF does not, and your reasoning
        stays visible. Pass ``bm25`` for a deterministic ranking, or ``llm`` to
        have ADEF call the Anthropic API itself (requires ANTHROPIC_API_KEY and
        the ``llm`` extra). ``auto`` picks ``llm`` when available, else ``bm25``.
        The ``agent`` default differs from the CLI's ``bm25`` because an MCP
        caller is an agent by definition.
        """
        ws = Path(workspace) if workspace else None
        journals_dir = workspace_journals_dir(ws)
        journal = Journal(journals_dir)
        return cast(
            "dict[str, Any]",
            _to_dict(
                run_refine_chain(
                    journal, detection_id, workspace=ws, similarity_mode=similarity_mode
                )
            ),
        )

    @server.tool()
    def evolve_chain(detection_id: str, workspace: Optional[str] = None) -> dict[str, Any]:
        """Run the Evolve chain (Health → Tuning → Deprecation) for a detection.

        Reads the detection's ingested health (``health_ingest`` / ``adef
        ingest``) and appends the two recommendations to its journal. No
        network call and no mode switch — the heuristics are deterministic
        over whatever was ingested.
        """
        ws = Path(workspace) if workspace else None
        journal = Journal(workspace_journals_dir(ws))
        return cast(
            "dict[str, Any]",
            _to_dict(run_evolve_chain(journal, detection_id, workspace=ws)),
        )

    @server.tool()
    def hypothesis_from_intel(intel_url_or_text: str) -> dict[str, Any]:
        """Turn a CTI URL or pasted text into a draft Find/Observe block."""
        return cast("dict[str, Any]", _to_dict(HypothesisFromIntelAgent().run(intel_url_or_text)))

    @server.tool()
    def tune_recommend(
        detection_id: str,
        metrics: Optional[dict[str, Any]] = None,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Recommend tuning actions. Omit `metrics` to use ingested health."""
        return cast(
            "dict[str, Any]",
            _to_dict(
                TuneRecommenderAgent().run(
                    detection_id,
                    metrics=metrics,
                    workspace=Path(workspace) if workspace else None,
                )
            ),
        )

    @server.tool()
    def deprecation_recommend(
        detection_id: str,
        performance: Optional[dict[str, Any]] = None,
        overlap: Optional[dict[str, Any]] = None,
        findings: Optional[dict[str, Any]] = None,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Decide keep / tune / deprecate from three orthogonal signals.

        Omit `performance` to use the detection's ingested health — the agent
        itself takes no workspace, so the read happens here rather than
        leaving an MCP caller to hand-assemble the metrics the CLI's Evolve
        chain derives for it.
        """
        if performance is None:
            performance = stored_metrics(
                detection_id, Path(workspace) if workspace else None
            ) or None
        return cast(
            "dict[str, Any]",
            _to_dict(
                DeprecationRecommenderAgent().run(
                    detection_id,
                    performance=performance,
                    overlap=overlap,
                    findings=findings,
                )
            ),
        )


__all__ = ["register"]
