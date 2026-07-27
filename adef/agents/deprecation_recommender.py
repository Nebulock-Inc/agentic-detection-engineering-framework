"""DeprecationRecommenderAgent — combine performance + overlap + finding ratios.

Returns one of three verdicts: ``keep``, ``tune``, ``deprecate``. The agent is
deterministic given the same inputs — the value is in the *combination* across
three signals that today live in three separate upstream agents.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Verdict = Literal["keep", "tune", "deprecate"]


@dataclass
class DeprecationRecommendation:
    detection_id: str
    verdict: Verdict
    rationale: str
    inputs: dict[str, Any]


def _decide(performance: dict[str, Any], overlap: dict[str, Any], findings: dict[str, Any]) -> tuple[Verdict, str]:
    fp_ratio = float(performance.get("fp_ratio", 0.0) or 0.0)
    weekly_volume = float(performance.get("weekly_signal_volume", 0.0) or 0.0)
    days_since_tp = float(performance.get("days_since_true_positive", 0.0) or 0.0)
    overlap_score = float(overlap.get("score", 0.0) or 0.0)
    high_quality_findings = float(findings.get("high_quality_findings", 0.0) or 0.0)

    if weekly_volume == 0 and days_since_tp >= 180 and high_quality_findings == 0:
        return "deprecate", "Silent for 180+ days, no high-quality findings ever — retire."

    if overlap_score >= 0.85 and high_quality_findings == 0:
        return "deprecate", f"Overlap {overlap_score:.0%} with stronger neighbor and zero high-quality findings."

    if fp_ratio >= 0.9 and weekly_volume >= 10:
        return "tune", f"FP ratio {fp_ratio:.0%} on {weekly_volume:.0f} weekly signals."

    if overlap_score >= 0.7 and fp_ratio >= 0.5:
        return "tune", f"Overlap {overlap_score:.0%} and FP {fp_ratio:.0%} — tune or merge."

    return "keep", "Signals are healthy, overlap manageable — keep."


class DeprecationRecommenderAgent:
    """Decide keep / tune / deprecate from three orthogonal signals."""

    def run(
        self,
        detection_id: str,
        performance: dict[str, Any] | None = None,
        overlap: dict[str, Any] | None = None,
        findings: dict[str, Any] | None = None,
    ) -> DeprecationRecommendation:
        performance = performance or {}
        overlap = overlap or {}
        findings = findings or {}

        verdict, rationale = _decide(performance, overlap, findings)
        return DeprecationRecommendation(
            detection_id=detection_id,
            verdict=verdict,
            rationale=rationale,
            inputs={"performance": performance, "overlap": overlap, "findings": findings},
        )


__all__ = ["DeprecationRecommendation", "DeprecationRecommenderAgent", "Verdict"]
