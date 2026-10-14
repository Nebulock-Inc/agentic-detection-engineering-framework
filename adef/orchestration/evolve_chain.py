"""Evolve orchestration — Health → Tuning → Deprecation.

The symmetric counterpart to ``refine_chain``. Refine chained three agents;
Evolve, the stage whose entire purpose is tuning and deprecation, only
advanced the stage and stopped — ``TuneRecommenderAgent`` and
``DeprecationRecommenderAgent`` sat implemented and reachable from MCP alone,
and the detection-health a user ingested was written to a directory nothing
read.

Both agents run off the **same** stored-health read, so the Health block in
the journal is the exact input the two recommendations were made from rather
than a second, separately-timed lookup of it.

Same never-abort semantics as the Refine chain: a failed step is recorded in
the journal and the rest still runs.
"""

from __future__ import annotations

import traceback
from dataclasses import asdict
from pathlib import Path
from typing import Any

from adef.core.health_store import NOTHING_DERIVABLE
from adef.core.journal import Journal

# Private by name, shared on purpose: both chains write into the same journal
# and a second renderer would drift from this one (the lesson `_render.py`
# already records for the two table renderers).
from adef.orchestration.refine_chain import _format_payload


def _health_body(latest: dict[str, dict], metrics: dict[str, Any]) -> str:
    """The Health block: what was ingested, and what was derived from it."""
    if not latest:
        return (
            "_No detection health ingested for this detection. The tuning and "
            "deprecation calls below have nothing to work from — capture the "
            "numbers from your platform into a health document and run "
            "`adef ingest <document>`, then re-run `adef detection evolve "
            "--chain`._"
        )
    lines = [
        f"- **stored kinds:** {', '.join(sorted(latest))}",
    ]
    for kind in sorted(latest):
        captured = latest[kind].get("captured_at")
        window = latest[kind].get("window") or {}
        span = f"{window.get('start')} → {window.get('end')}" if window else "point-in-time"
        lines.append(f"  - {kind}: captured {captured}, window {span}")
    if metrics:
        lines.append("- **derived for tuning:**")
        lines.extend(f"  - {k}: {v:.4g}" for k, v in sorted(metrics.items()))
    else:
        # Health is present but carries none of the counts the heuristics read.
        # Saying "no metrics" without saying which ones were looked for sends
        # the user to re-read the whole document format. Shared wording: this
        # listed the three fields flat — which reads as "none of these are
        # present" — long after `adef health show` was corrected to say the FP
        # requirement is a pair.
        lines.append(f"- **derived for tuning:** none — {NOTHING_DERIVABLE}")
    return "\n".join(lines)


def run_evolve_chain(
    journal: Journal, detection_id: str, workspace: Path | None = None
) -> dict[str, Any]:
    """Append Health, Tuning and Deprecation blocks for ``detection_id``.

    Returns ``{step: {"ok": bool, "result": Any, "error": str | None}}``, the
    same summary shape ``run_refine_chain`` returns.
    """
    from adef.agents.deprecation_recommender import DeprecationRecommenderAgent
    from adef.agents.tune_recommender import TuneRecommenderAgent, wrapper_metrics
    from adef.core.health_store import health_dir, read_latest, tuning_metrics

    summary: dict[str, Any] = {}

    latest: dict[str, dict] = {}
    metrics: dict[str, Any] = {}
    try:
        latest = read_latest(health_dir(workspace), detection_id)
        metrics = dict(tuning_metrics(latest))
        # A configured `ADEF_WRAPPER_METRICS` collector is a deliberate
        # override of stored health — the same precedence every wrapper
        # binding has. Both recommenders then read *its* numbers.
        collector_error = ""
        try:
            collected = wrapper_metrics(detection_id)
        except Exception as exc:  # noqa: BLE001 — chain must not abort
            collected, collector_error = {}, f"{type(exc).__name__}: {exc}"
        if collected:
            body = (
                "- **source:** ADEF_WRAPPER_METRICS (overrides stored health)\n"
                + "\n".join(f"  - {k}: {v}" for k, v in sorted(collected.items()))
            )
            if latest:
                body += "\n- **stored health (not used):**\n" + _health_body(latest, metrics)
            metrics = collected
        else:
            body = _health_body(latest, metrics)
        if collector_error:
            body += f"\n- **ADEF_WRAPPER_METRICS failed** ({collector_error}); using stored health."
        elif collected is not None and not collected:
            body += "\n- _ADEF_WRAPPER_METRICS is set but returned nothing; using stored health._"
        summary["health"] = {
            "ok": True,
            "result": {"kinds": sorted(latest), "metrics": metrics},
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 — chain must not abort
        body = f"**Failed to read stored health:** {exc}"
        summary["health"] = {"ok": False, "result": None, "error": str(exc)}
    journal.append_block(detection_id, "Evolve / Health", body, generated=True)

    # `metrics=metrics` is passed explicitly, including when it is empty: the
    # agent's `metrics is None` branch would otherwise go looking for the
    # numbers a second time, and an empty dict here is a *fact we just
    # established*, not a missing argument.
    steps = (
        ("tuning", "Evolve / Tuning",
         lambda: TuneRecommenderAgent().run(detection_id, metrics=metrics)),
        ("deprecation", "Evolve / Deprecation",
         # Overlap and findings are deliberately not supplied. Overlap is the
         # Refine chain's job and already in the journal; `findings` has no
         # ADEF producer at all. The agent reports which signals it had, so a
         # `keep` from one signal reads as exactly that.
         lambda: DeprecationRecommenderAgent().run(detection_id, performance=metrics)),
    )

    for name, heading, call in steps:
        try:
            result = call()
            # `asdict` recurses, so `TuneRecommendation.suggestions` arrives as
            # a list of dicts — which is the shape `_format_payload` renders as
            # sub-bullets rather than one repr on a single line.
            journal.append_block(
                detection_id, heading, _format_payload(asdict(result)), generated=True
            )
            summary[name] = {"ok": True, "result": result, "error": None}
        except Exception as exc:  # noqa: BLE001 — chain must not abort
            tb = traceback.format_exc(limit=2)
            journal.append_block(
                detection_id, heading, f"**Failed:** {exc}\n\n```\n{tb}\n```",
                generated=True,
            )
            summary[name] = {"ok": False, "result": None, "error": str(exc)}

    return summary


__all__ = ["run_evolve_chain"]
