"""DeprecationRecommenderAgent — combine performance + overlap + finding ratios.

Returns ``keep``, ``tune`` or ``deprecate`` — or ``insufficient_data`` when no
input carries any signal, rather than a reassuring guess. The agent is
deterministic given the same inputs — the value is in the *combination* across
three signals that today live in three separate upstream agents.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from adef.core.health_store import MIN_SILENCE_WINDOW_DAYS, as_number, at_least


Verdict = Literal["keep", "tune", "deprecate", "insufficient_data"]

# Which keys make each input count as provided. Presence, not truthiness: a
# weekly volume of 0 is a finding (silence), not missing data.
_SIGNAL_KEYS = {
    "performance": ("fp_ratio", "weekly_signal_volume", "days_since_true_positive"),
    "overlap": ("score",),
    "findings": ("high_quality_findings",),
}


@dataclass
class DeprecationRecommendation:
    detection_id: str
    verdict: Verdict
    rationale: str
    inputs: dict[str, Any]


def _decide(performance: dict[str, Any], overlap: dict[str, Any], findings: dict[str, Any]) -> tuple[Verdict, str]:
    given = {"performance": performance, "overlap": overlap, "findings": findings}
    provided = [n for n, keys in _SIGNAL_KEYS.items() if any(k in given[n] for k in keys)]
    missing = [n for n in _SIGNAL_KEYS if n not in provided]
    if not provided:
        return "insufficient_data", (
            "No performance, overlap or findings data was provided, so there is "
            "nothing to judge. Ingest detection health (`adef ingest`) and re-run."
        )
    # `None`, not `0.0`, for an absent signal — the `provided` gate above needs
    # only ONE of the three groups, so every other value could be fabricated.
    # The silence arm needs a *measured* zero volume and a measured 180+ days
    # since the last true positive; that alone is the retire case. Findings
    # can only veto it (a supplied count above zero), because
    # `run_evolve_chain` never supplies them — ADEF has no producer — and
    # requiring them made `deprecate` unreachable from `adef detection evolve`.
    fp_ratio = as_number(performance.get("fp_ratio"))
    weekly_volume = as_number(performance.get("weekly_signal_volume"))
    days_since_tp = as_number(performance.get("days_since_true_positive"))
    overlap_score = as_number(overlap.get("score"))
    high_quality_findings = as_number(findings.get("high_quality_findings"))

    # A findings value that was supplied but isn't a usable count (negative,
    # junk) is unknown, not absent — it must not unlock the silence arm.
    findings_unknown = "high_quality_findings" in findings and high_quality_findings is None
    long_enough = at_least(as_number(performance.get("window_days")), MIN_SILENCE_WINDOW_DAYS)
    if (weekly_volume == 0 and long_enough and at_least(days_since_tp, 180)
            and not high_quality_findings and not findings_unknown):
        caveat = (
            "no high-quality findings ever" if high_quality_findings == 0
            else "high-quality findings not provided"
        )
        return "deprecate", (
            f"No signals in a {performance['window_days']:.0f}-day window and no true "
            f"positive in {days_since_tp:.0f} days "
            f"({caveat}) — retire."
        )

    if at_least(overlap_score, 0.85) and high_quality_findings == 0:
        return "deprecate", f"Overlap {overlap_score:.0%} with stronger neighbor and zero high-quality findings."

    if at_least(fp_ratio, 0.9) and at_least(weekly_volume, 10):
        return "tune", f"FP ratio {fp_ratio:.0%} on {weekly_volume:.0f} weekly signals."

    if at_least(overlap_score, 0.7) and at_least(fp_ratio, 0.5):
        return "tune", f"Overlap {overlap_score:.0%} and FP {fp_ratio:.0%} — tune or merge."

    checked = ", ".join(provided)
    note = f"; not provided: {', '.join(missing)}" if missing else ""
    return "keep", f"No deprecate or tune condition met (checked: {checked}{note}) — keep."


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


__all__ = ["DeprecationRecommenderAgent", "DeprecationRecommendation", "Verdict"]
