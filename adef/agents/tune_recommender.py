"""TuneRecommenderAgent — propose tuning steps given performance metrics.

Calls the ``PerformanceMetricsCollector`` wrapper (lazily — wrappers themselves
are lazy on the upstream agent import) to get current signal volume and FP
ratio, then applies a small heuristic decision table to produce a recommendation.

The output is structured (a list of typed actions), not free-text, so the
Evolve stage can render them deterministically and downstream automation can
act on them later (v0.2+ daemon territory).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TuneSuggestion:
    """A single tuning action."""

    kind: str          # e.g. "narrow-filter", "raise-threshold", "deprecate", "investigate"
    rationale: str
    severity: str = "info"  # info | low | medium | high


@dataclass
class TuneRecommendation:
    """The full set of suggestions for a detection."""

    detection_id: str
    metrics: dict[str, Any] = field(default_factory=dict)
    suggestions: list[TuneSuggestion] = field(default_factory=list)


def _heuristic_suggest(metrics: dict[str, Any]) -> list[TuneSuggestion]:
    """Apply v0.1.0's small decision table to ``metrics``."""
    out: list[TuneSuggestion] = []
    fp_ratio = float(metrics.get("fp_ratio", 0.0) or 0.0)
    weekly_volume = float(metrics.get("weekly_signal_volume", 0.0) or 0.0)
    days_since_true_positive = float(metrics.get("days_since_true_positive", 0.0) or 0.0)

    if fp_ratio >= 0.95 and weekly_volume >= 10:
        out.append(TuneSuggestion(
            kind="narrow-filter",
            rationale=f"FP ratio {fp_ratio:.0%} on {weekly_volume:.0f} weekly signals — narrow filters or raise threshold.",
            severity="high",
        ))
    elif fp_ratio >= 0.75:
        out.append(TuneSuggestion(
            kind="investigate",
            rationale=f"FP ratio {fp_ratio:.0%} — investigate dominant FP cluster before tuning.",
            severity="medium",
        ))

    if weekly_volume == 0 and days_since_true_positive >= 90:
        out.append(TuneSuggestion(
            kind="deprecate",
            rationale=f"No signals in {days_since_true_positive:.0f} days — candidate for deprecation review.",
            severity="medium",
        ))

    if not out:
        out.append(TuneSuggestion(
            kind="hold",
            rationale="Metrics within normal band — no tuning recommended.",
            severity="info",
        ))
    return out


class TuneRecommenderAgent:
    """Recommend tuning actions for a detection given its performance metrics."""

    def run(self, detection_id: str, metrics: dict[str, Any] | None = None) -> TuneRecommendation:
        if metrics is None:
            try:
                from adef.agents.wrappers.performance_metrics import PerformanceMetricsWrapper
                metrics_payload = PerformanceMetricsWrapper().run(detection_id=detection_id)
                metrics = (
                    metrics_payload.get("result")
                    if isinstance(metrics_payload, dict)
                    else {}
                ) or {}
            except Exception:  # noqa: BLE001 — we still produce a recommendation
                metrics = {}

        return TuneRecommendation(
            detection_id=detection_id,
            metrics=metrics,
            suggestions=_heuristic_suggest(metrics),
        )


__all__ = ["TuneRecommendation", "TuneRecommenderAgent", "TuneSuggestion"]
