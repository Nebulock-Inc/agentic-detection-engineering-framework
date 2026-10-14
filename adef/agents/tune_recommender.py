"""TuneRecommenderAgent — propose tuning steps given performance metrics.

Metrics come from the workspace's ingested detection health (``adef ingest``),
derived from the stored counts by ``health_store.tuning_metrics``. An
explicitly configured ``ADEF_WRAPPER_METRICS`` takes precedence,
matching how every other wrapper binding behaves: unset is the default path,
set is a deliberate override. A small heuristic decision table turns whichever
arrived into a recommendation.

The output is structured (a list of typed actions), not free-text, so the
Evolve stage can render them deterministically and downstream automation can
act on them later (v0.2+ daemon territory).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adef.core.health_store import MIN_SILENCE_WINDOW_DAYS, as_number, at_least


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
    if not any(k in metrics for k in ("fp_ratio", "weekly_signal_volume", "days_since_true_positive")):
        return [TuneSuggestion(
            kind="insufficient-data",
            rationale="No performance metrics available, so no tuning call can be made. "
                      "Ingest detection health (`adef ingest`) and re-run.",
            severity="info",
        )]
    # `None`, not `0.0`, for an absent metric. The gate above passes on *one*
    # present key, so a `metrics` document carrying only `last_true_positive_at`
    # — valid, since row keys are deliberately not whitelisted at ingest —
    # derived `{days_since_true_positive: 282}`, defaulted the volume to zero,
    # and fired the silence arm: "No signals in 282 days — candidate for
    # deprecation review", about a signal volume nobody ever supplied. That is
    # the fabricated zero `tuning_metrics` omits keys precisely to avoid,
    # re-introduced one function later. Every arm now requires every value it
    # reads to be present (`at_least`); `== 0` needs no guard because
    # `None == 0` is already False.
    fp_ratio = as_number(metrics.get("fp_ratio"))
    weekly_volume = as_number(metrics.get("weekly_signal_volume"))
    days_since_true_positive = as_number(metrics.get("days_since_true_positive"))

    if at_least(fp_ratio, 0.95) and at_least(weekly_volume, 10):
        out.append(TuneSuggestion(
            kind="narrow-filter",
            rationale=f"FP ratio {fp_ratio:.0%} on {weekly_volume:.0f} weekly signals — narrow filters or raise threshold.",
            severity="high",
        ))
    elif at_least(fp_ratio, 0.75):
        out.append(TuneSuggestion(
            kind="investigate",
            rationale=f"FP ratio {fp_ratio:.0%} — investigate dominant FP cluster before tuning.",
            severity="medium",
        ))

    long_enough = at_least(as_number(metrics.get("window_days")), MIN_SILENCE_WINDOW_DAYS)
    if weekly_volume == 0 and long_enough and at_least(days_since_true_positive, 90):
        out.append(TuneSuggestion(
            kind="deprecate",
            rationale=f"No signals in {days_since_true_positive:.0f} days — candidate for deprecation review.",
            severity="medium",
        ))

    if not out:
        out.append(TuneSuggestion(
            kind="hold",
            rationale="No tuning condition met on the metrics provided — no tuning recommended.",
            severity="info",
        ))
    return out


def stored_metrics(detection_id: str, workspace: Path | None = None) -> dict[str, Any]:
    """Tuning metrics derived from the workspace's ingested health, or ``{}``.

    Swallows every failure: a missing workspace, an unreadable or hand-mangled
    ``health/latest/`` file, a malformed id. The caller's job is to produce a
    recommendation, and "no metrics" is a recommendation
    (``insufficient-data``) rather than a reason to abort the Evolve stage.
    """
    try:
        from adef.core.health_store import health_dir, read_latest, tuning_metrics

        return dict(tuning_metrics(read_latest(health_dir(workspace), detection_id)))
    except Exception:  # noqa: BLE001 — absent health is the normal state
        return {}


def wrapper_metrics(detection_id: str) -> dict[str, Any] | None:
    """Metrics from a configured ``ADEF_WRAPPER_METRICS`` collector.

    ``None`` when no collector is configured, so callers fall through to stored
    health; ``{}`` when it returned nothing usable. A collector that *fails*
    raises — a misconfigured binding must be reportable, not look empty.
    """
    from adef.agents.wrappers.performance_metrics import PerformanceMetricsWrapper

    wrapper = PerformanceMetricsWrapper()
    if not wrapper.is_configured():
        return None
    payload = wrapper.run(detection_id=detection_id)
    result = payload.get("result") if isinstance(payload, dict) else None
    return dict(result) if isinstance(result, dict) else {}


class TuneRecommenderAgent:
    """Recommend tuning actions for a detection given its performance metrics."""

    def run(
        self,
        detection_id: str,
        metrics: dict[str, Any] | None = None,
        workspace: Path | None = None,
    ) -> TuneRecommendation:
        if metrics is None:
            # Unset binding (the default) → read what `adef ingest` stored.
            # Also covers a binding that failed or returned nothing.
            try:
                collected = wrapper_metrics(detection_id)
            except Exception:  # noqa: BLE001 — we still produce a recommendation
                collected = None
            metrics = collected or stored_metrics(detection_id, workspace)

        return TuneRecommendation(
            detection_id=detection_id,
            metrics=metrics,
            suggestions=_heuristic_suggest(metrics),
        )


__all__ = [
    "TuneRecommenderAgent",
    "TuneRecommendation",
    "TuneSuggestion",
    "stored_metrics",
    "wrapper_metrics",
]
