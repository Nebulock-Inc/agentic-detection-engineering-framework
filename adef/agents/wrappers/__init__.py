"""Lifecycle-aware wrappers around the upstream rule-engineering agents ADEF
actually orchestrates.

Each wrapper is a thin adapter — it never modifies the upstream agent's
internals. The wrappers expose a uniform ``run(detection_id, **ctx) -> dict``
shape so orchestration code (e.g., the Refine chain) can compose them without
per-agent special cases.

Each wrapper resolves its underlying class via an environment variable of the
form ``ADEF_WRAPPER_<KEY>=module.path:ClassName``. If the variable is not set
or the import fails, ``run()`` raises ``WrapperUnavailable`` rather than
``ImportError``, and the orchestration layer captures that into the journal.

Scope note (2026-07-22): the original design sketched wrappers for 12 upstream
agents; ADEF wires **four** — the Refine chain's Similarity / Overlap /
Verification, plus PerformanceMetrics for the tune recommender. The other eight
were unreferenced speculative slots and were removed; add a wrapper back when a
concrete orchestration path needs it.
"""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase, WrapperUnavailable
from adef.agents.wrappers.performance_metrics import PerformanceMetricsWrapper
from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper
from adef.agents.wrappers.rule_similarity import RuleSimilarityWrapper
from adef.agents.wrappers.verification import VerificationWrapper


ALL_WRAPPERS: tuple[type[WrapperBase], ...] = (
    PerformanceMetricsWrapper,
    RuleOverlapWrapper,
    RuleSimilarityWrapper,
    VerificationWrapper,
)


__all__ = [
    "WrapperBase",
    "WrapperUnavailable",
    "ALL_WRAPPERS",
    "PerformanceMetricsWrapper",
    "RuleOverlapWrapper",
    "RuleSimilarityWrapper",
    "VerificationWrapper",
]
