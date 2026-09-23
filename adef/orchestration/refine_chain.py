"""Refine orchestration — Similarity → Overlap → Verification.

The Refine stage chains three upstream rule-engineering agents and appends
each result to the detection's journal under the Refine block. The wrappers
in ``adef.agents.wrappers.*`` adapt the upstream agents to a uniform
``run(detection_id, **ctx)`` shape.

Failure of any individual agent is surfaced and logged into the journal but
does NOT abort the chain — partial results are useful, and the user can
re-run after fixing a missing prerequisite (e.g., ClickHouse access).
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass
from typing import Any

from adef.agents.wrappers import WrapperUnavailable
from adef.core.catalog import NoCatalogRecordError
from adef.core.journal import Journal


@dataclass
class ChainStep:
    name: str
    heading: str
    wrapper_attr: str  # name on adef.agents.wrappers


REFINE_STEPS: tuple[ChainStep, ...] = (
    ChainStep(name="similarity", heading="Refine / Similarity",
              wrapper_attr="RuleSimilarityWrapper"),
    ChainStep(name="overlap", heading="Refine / Overlap",
              wrapper_attr="RuleOverlapWrapper"),
    ChainStep(name="verification", heading="Refine / Verification",
              wrapper_attr="VerificationWrapper"),
)


# Comfortably above MemoryIndex's 240-char snippet, so the values that were
# always rendered here pass through intact and only genuinely long ones (a
# candidate's verbatim query) get cut.
_MAX_RENDERED = 300


def _inline(value: Any) -> str:
    """Collapse whitespace and cap length for one journal line.

    The journal is markdown: a value containing newlines severs its bullet and
    can turn indented text into a code block. Candidate queries are stored
    verbatim and are routinely multi-line, so this is the common case, not an
    edge one.

    The cap is for the free-text that legitimately belongs here — an LLM
    judge's `reasoning`, a third-party step's prose — which reaches the renderer
    verbatim and can run long. (Rule logic does not reach it at all; see
    `_JOURNAL_OMIT_KEYS`.) Only the *rendered* form is collapsed and capped —
    callers still receive the value unchanged.
    """
    text = " ".join(str(value).split())
    return text if len(text) <= _MAX_RENDERED else text[:_MAX_RENDERED] + "\u2026"


# Rule logic never goes in the journal. It is the neighbour's, not this
# detection's; it already lives in that neighbour's catalog record, keyed by an
# ID the journal does record; and journals are the BM25 corpus, so echoing it
# here scores the same pair higher on the next similarity run for no new
# evidence. The journal keeps the shortlist and the verdict; `adef detection
# show <id>` keeps the logic. Callers still receive both fields in the payload.
#
# `snippet` belongs here as much as `query` does: `MemoryIndex._snippet` builds
# it from the journal body PLUS `record_search_text(record)`, which ends in the
# record's query — so omitting `query` alone left the neighbour's verbatim logic
# in the journal under a different key. Verified end-to-end, not by inspection.
# This shrinks the feedback surface to low-entropy metadata (title, technique
# ID, platform); closing it entirely means not indexing the machine-generated
# `### Refine /` blocks at all, which is a MemoryIndex change — see 10188.
_JOURNAL_OMIT_KEYS = frozenset({"query", "snippet"})


def _format_payload(payload: Any, indent: str = "") -> str:
    """Render an agent's return value into a journal-friendly markdown body.

    Nested dicts and lists-of-dicts become indented sub-bullets. Interpolating
    them as a raw Python repr instead put an entire result set on ONE journal
    line — thousands of characters wide on any realistically-sized catalog.
    Note the payload each step hands us is the *wrapper's* envelope
    (``{"detection_id": ..., "result": {..., "overlaps": [...]}}``), so the
    long value is a nested dict, not a top-level list — both need unpacking.
    """
    if payload is None:
        return "_(no result)_"
    if isinstance(payload, dict):
        lines: list[str] = []
        for key, value in payload.items():
            if isinstance(value, dict) and value:
                rendered = _format_payload(value, indent + "  ")
                if rendered:
                    lines.append(f"{indent}- **{key}:**")
                    lines.append(rendered)
            elif isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
                lines.append(f"{indent}- **{key}:**")
                lines.extend(
                    f"{indent}  - " + ", ".join(f"{k}: {_inline(v)}" for k, v in entry.items())
                    for entry in value
                )
            else:
                lines.append(f"{indent}- **{key}:** {_inline(value)}")
        return "\n".join(lines)
    if isinstance(payload, (list, tuple)):
        return "\n".join(f"{indent}- {_inline(item)}" for item in payload) or "_(empty)_"
    return _inline(payload)


def _prune_for_journal(value: Any) -> Any:
    """Strip `_JOURNAL_OMIT_KEYS` at every depth, before anything is rendered.

    Filtering at each render site instead left holes: a dict nested inside a
    list entry, or a bare list payload, reached `_inline` whole and stringified
    its omitted keys straight back in. Pruning the structure once is both
    smaller and total — the renderer needs no knowledge of what is omitted.
    """
    if isinstance(value, dict):
        return {k: _prune_for_journal(v) for k, v in value.items()
                if k not in _JOURNAL_OMIT_KEYS}
    if isinstance(value, (list, tuple)):
        return [_prune_for_journal(v) for v in value]
    return value


def run_refine_chain(journal: Journal, detection_id: str, **context: Any) -> dict[str, Any]:
    """Run Similarity → Overlap → Verification and append results to ``detection_id``.

    Returns a dict mapping step name → ``{"ok": bool, "result": Any, "error": str | None}``.
    """
    from adef.agents import wrappers as wrappers_pkg

    summary: dict[str, Any] = {}
    for step in REFINE_STEPS:
        cls = getattr(wrappers_pkg, step.wrapper_attr, None)
        if cls is None:
            body = f"_Wrapper `{step.wrapper_attr}` not available — skipping._"
            journal.append_block(detection_id, step.heading, body)
            summary[step.name] = {"ok": False, "result": None, "error": "wrapper-missing"}
            continue
        try:
            result = cls().run(detection_id=detection_id, **context)
            journal.append_block(
                detection_id, step.heading, _format_payload(_prune_for_journal(result))
            )
            summary[step.name] = {"ok": True, "result": result, "error": None}
        except NoCatalogRecordError as exc:
            # The common, expected lifecycle gap: the detection is still
            # journal-only (Find/Observe), so there is no rule to compare or
            # verify yet. Distinct from `WrapperUnavailable` below — calling
            # this "not configured" was simply false for a default install.
            body = (
                f"_Not run — no catalog record for {detection_id} yet "
                f"(still journal-only). {exc}_"
            )
            journal.append_block(detection_id, step.heading, body)
            summary[step.name] = {"ok": False, "result": None, "error": "no-catalog-record"}
        except WrapperUnavailable as exc:
            # Expected, not exceptional: an explicitly-set `ADEF_WRAPPER_*`
            # override that can't be imported (Similarity/Overlap/Verification
            # are native when it's unset; PerformanceMetrics has no native
            # path). A clean one-liner belongs in the journal — a Python
            # traceback in a "readable memory" artifact undermines it. The
            # exception message already names the exact env var to set.
            body = f"_Not run — {step.name} agent isn't configured. {exc}_"
            journal.append_block(detection_id, step.heading, body)
            summary[step.name] = {"ok": False, "result": None, "error": "not-configured"}
        except Exception as exc:  # noqa: BLE001 — chain must not abort
            # A genuine failure of a configured agent — keep the traceback.
            tb = traceback.format_exc(limit=2)
            body = f"**Failed:** {exc}\n\n```\n{tb}\n```"
            journal.append_block(detection_id, step.heading, body)
            summary[step.name] = {"ok": False, "result": None, "error": str(exc)}
    return summary


__all__ = ["run_refine_chain", "ChainStep", "REFINE_STEPS"]
