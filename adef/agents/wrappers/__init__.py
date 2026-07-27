"""Lifecycle-aware wrappers around 12 upstream rule-engineering agents.

Each wrapper is a thin adapter — it never modifies the upstream agent's
internals. The wrappers expose a uniform ``run(detection_id, **ctx) -> dict``
shape so orchestration code (e.g., the Refine chain) can compose them without
per-agent special cases.

Each wrapper resolves its underlying class via an environment variable of the
form ``ADEF_WRAPPER_<KEY>=module.path:ClassName``. If the variable is not set
or the import fails, ``run()`` raises ``WrapperUnavailable`` rather than
``ImportError``, and the orchestration layer captures that into the journal.
"""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase, WrapperUnavailable
from adef.agents.wrappers.coverage_analysis import CoverageAnalysisWrapper
from adef.agents.wrappers.detection_decision import DetectionDecisionWrapper
from adef.agents.wrappers.detection_review import DetectionReviewWrapper
from adef.agents.wrappers.dropped_findings import DroppedFindingsWrapper
from adef.agents.wrappers.findings_analysis import FindingsAnalysisWrapper
from adef.agents.wrappers.fp_pattern import FpPatternWrapper
from adef.agents.wrappers.performance_metrics import PerformanceMetricsWrapper
from adef.agents.wrappers.review_queue import ReviewQueueWrapper
from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper
from adef.agents.wrappers.rule_similarity import RuleSimilarityWrapper
from adef.agents.wrappers.threat_review import ThreatReviewWrapper
from adef.agents.wrappers.verification import VerificationWrapper

ALL_WRAPPERS: tuple[type[WrapperBase], ...] = (
    CoverageAnalysisWrapper,
    DetectionDecisionWrapper,
    DetectionReviewWrapper,
    DroppedFindingsWrapper,
    FindingsAnalysisWrapper,
    FpPatternWrapper,
    PerformanceMetricsWrapper,
    ReviewQueueWrapper,
    RuleOverlapWrapper,
    RuleSimilarityWrapper,
    ThreatReviewWrapper,
    VerificationWrapper,
)


__all__ = [
    "ALL_WRAPPERS",
    "CoverageAnalysisWrapper",
    "DetectionDecisionWrapper",
    "DetectionReviewWrapper",
    "DroppedFindingsWrapper",
    "FindingsAnalysisWrapper",
    "FpPatternWrapper",
    "PerformanceMetricsWrapper",
    "ReviewQueueWrapper",
    "RuleOverlapWrapper",
    "RuleSimilarityWrapper",
    "ThreatReviewWrapper",
    "VerificationWrapper",
    "WrapperBase",
    "WrapperUnavailable",
]
