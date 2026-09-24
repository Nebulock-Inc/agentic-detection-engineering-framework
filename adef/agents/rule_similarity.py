"""Rule-similarity search over the ADEF catalog — does a rule like this
already exist?

Ranks with the same BM25 index `adef detection search` ships
(`adef.core.memory.MemoryIndex`), built over `adef.core.corpus.build_corpus` —
a detection is a member of the corpus if it has a catalog record OR a
journal, so a catalogued rule with no journal is still shortlisted (by its
record's title/mitre/platform/query), and a journal-only draft (a fresh
`detection new`, before it has a catalog record) is still shortlisted too —
at minimum by its title, which `CorpusEntry.index_text` always includes,
even when the journal itself is still template-only. (`RuleOverlapAgent`
still iterates the catalog directly as of this change; unifying it onto
`build_corpus` is tracked separately in 10188.)
What happens to the shortlist depends on `similarity_mode`:
- `bm25`: return the BM25 ranking as-is. No network call.
- `agent`: return the shortlist enriched with the target's *and* each
  candidate's query, MITRE IDs, platform, and data source for the *caller*
  to rank. No network call.
- `llm`: send the shortlist to an LLM judge for a true semantic re-score
  (paraphrase/synonym matches BM25's lexical scoring misses).
- `auto`: `llm` when available (`ANTHROPIC_API_KEY` + the `llm` extra),
  else `bm25`.

The LLM step never scans the whole corpus — cost and latency stay bounded by
`top_k`, not catalog size. See the plan's Task 2 design rationale.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any

from adef.core.catalog import Catalog, NoCatalogRecordError
from adef.core.corpus import build_corpus
from adef.core.corpus_text import record_search_text
from adef.core.journal import workspace_journals_dir
from adef.core.memory import MemoryIndex

DEFAULT_LLM_MODEL = "claude-haiku-4-5-20251001"

#: `agent` returns the shortlist enriched for the caller to judge and ranks
#: nothing — the caller (an assistant session) has context ADEF does not, and
#: its reasoning lands in the transcript where it can be reviewed. Like `bm25`
#: it never makes a network call.
_VALID_SIMILARITY_MODES = frozenset({"auto", "bm25", "llm", "agent"})

_JUDGE_PROMPT = """You are a detection engineering expert. Given a target detection rule and a \
shortlist of candidates retrieved by keyword search, judge which candidates are a true semantic \
match to the target — the same underlying behavior, even if worded or implemented differently.

Target:
Title: {target_title}
MITRE: {target_mitre}
Query: {target_query}

Candidates:
{candidates_block}

Return ONLY a JSON array, one entry per candidate, in the same order given:
[{{"detection_id": "...", "confidence": 0.0-1.0, "reasoning": "one sentence"}}]"""


def _anthropic_importable() -> bool:
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def _llm_available() -> bool:
    if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return False
    return _anthropic_importable()


def _safe_confidence(raw: Any, fallback: float) -> float:
    """Coerce an LLM-reported confidence to a finite float in [0, 1].

    `json.loads` accepts literal `NaN`/`Infinity` tokens (found via
    CodeRabbit review, PR #1) — a non-finite or out-of-range value would
    otherwise reach `list.sort()` and corrupt the ranking without ever
    entering the `bm25_fallback` path, since it parses and converts cleanly.
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return fallback
    if not math.isfinite(value):
        return fallback
    return max(0.0, min(1.0, value))


def _safe_reasoning(raw: Any) -> str:
    """Coerce an LLM-reported reasoning value to a string (found via
    CodeRabbit review, PR #1 — a non-string value passed through unchanged)."""
    if raw is None:
        return ""
    return raw if isinstance(raw, str) else str(raw)


def _validate_judge_coverage(scored: Any, expected_ids: set[str]) -> dict[str, dict]:
    """Require exactly one judge result per shortlisted candidate.

    A missing candidate would otherwise silently keep its raw BM25 score
    while its siblings carry an LLM confidence — the two are not the same
    scale (BM25 scores aren't bounded to [0, 1]), so sorting the mix
    produces a meaningless ranking. A duplicate or unknown ``detection_id``
    is equally a sign the response doesn't match the shortlist it was
    asked to judge. Any violation raises so the caller's existing
    ``bm25_fallback`` path handles it — the same path malformed JSON
    already takes (found via CodeRabbit review, PR #1).
    """
    if not isinstance(scored, list):
        raise ValueError(f"expected a JSON array of judge results, got {type(scored).__name__}")
    by_id: dict[str, dict] = {}
    for entry in scored:
        det_id = entry.get("detection_id") if isinstance(entry, dict) else None
        if not isinstance(det_id, str) or det_id in by_id or det_id not in expected_ids:
            raise ValueError(f"judge response entry has an invalid or duplicate detection_id: {entry!r}")
        by_id[det_id] = entry
    if set(by_id) != expected_ids:
        raise ValueError(
            f"judge response covers {sorted(by_id)}, expected exactly {sorted(expected_ids)}"
        )
    return by_id


def _logic_fields(record: dict) -> dict[str, Any]:
    """The record fields a caller needs to judge *logic* similarity, not topical.

    Missing record (a journal-only detection, which the BM25 index legitimately
    surfaces) collapses to empty values rather than being dropped — a draft
    near-duplicate is exactly what Refine should show you, and the caller reads
    the empty query the same way it reads a blank one: nothing to compare.
    """
    mitre = record.get("mitre") or []
    return {
        "query": record.get("query") or "",
        # A hand-edited record can carry `mitre: T1218.005` as a scalar, and
        # `list("T1218.005")` would hand the caller nine one-character
        # "techniques" to judge alignment against.
        "mitre": [mitre] if isinstance(mitre, str) else list(mitre),
        "platform": record.get("platform") or "",
        "data_source": record.get("data_source") or "",
    }


class RuleSimilarityAgent:
    """Native replacement for the upstream RuleSimilarity wrapper agent."""

    def run(
        self,
        detection_id: str,
        workspace: Path | None = None,
        top_k: int = 5,
        similarity_mode: str = "bm25",
        llm_client: Any | None = None,
        **ctx: Any,
    ) -> dict[str, Any]:
        if similarity_mode not in _VALID_SIMILARITY_MODES:
            raise ValueError(
                f"similarity_mode must be one of {sorted(_VALID_SIMILARITY_MODES)}, "
                f"got {similarity_mode!r}"
            )

        journals_dir = workspace_journals_dir(workspace, create=False)
        ws = journals_dir.parent
        catalog = Catalog(ws)

        records: dict[str, dict] = {}
        for det_id, _path, data in catalog.iter_records():
            records[det_id] = data
        target_record = records.get(detection_id)
        if target_record is None:
            raise NoCatalogRecordError(f"No catalog record found for {detection_id}")
        target_text = record_search_text(target_record)

        index = MemoryIndex()
        index.build(build_corpus(ws))
        hits = [
            h for h in index.search(target_text, limit=top_k + 1)
            if h.detection_id != detection_id
        ][:top_k]
        candidates = [
            {"detection_id": h.detection_id, "title": h.title, "score": h.score,
             "snippet": h.snippet, "reasoning": ""}
            for h in hits
        ]

        resolved_mode = similarity_mode
        if resolved_mode == "auto":
            resolved_mode = "llm" if (llm_client is not None or _llm_available()) else "bm25"

        if resolved_mode == "agent":
            # Hand back everything the caller needs to judge logic similarity
            # itself — a snippet is not enough, the query text is, and it needs
            # BOTH sides: the target's query as well as each candidate's, or
            # the caller has nothing to compare against without another round
            # trip. Deliberately returns before any LLM path: `agent`
            # guarantees no network call.
            target = records[detection_id]
            return {
                "detection_id": detection_id,
                "mode_used": "agent",
                "target": {"title": target.get("title") or "", **_logic_fields(target)},
                "candidates": [
                    {**c, **_logic_fields(records.get(str(c["detection_id"]), {}))}
                    for c in candidates
                ],
            }

        if resolved_mode == "llm":
            if llm_client is None and not _llm_available():
                raise RuntimeError(
                    "similarity_mode='llm' requires ANTHROPIC_API_KEY and the 'llm' extra: "
                    "pip install 'agentic-detection-engineering-framework[llm]'"
                )
            if hits:
                try:
                    candidates = self._rerank_with_llm(records[detection_id], hits, llm_client)
                except Exception as exc:  # noqa: BLE001 — an LLM outage must not break refine
                    return {
                        "detection_id": detection_id,
                        "mode_used": "bm25_fallback",
                        "candidates": [
                            {"detection_id": h.detection_id, "title": h.title, "score": h.score,
                             "snippet": h.snippet, "reasoning": ""}
                            for h in hits
                        ],
                        "llm_error": str(exc),
                    }

        return {"detection_id": detection_id, "mode_used": resolved_mode, "candidates": candidates}

    def _rerank_with_llm(self, target_record: dict, hits: list, llm_client: Any | None) -> list[dict]:
        client = llm_client
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        model = os.environ.get("ADEF_LLM_MODEL", DEFAULT_LLM_MODEL)
        candidates_block = "\n".join(
            f"- id={h.detection_id} title={h.title!r} snippet={h.snippet!r}" for h in hits
        )
        prompt = _JUDGE_PROMPT.format(
            target_title=target_record.get("title", ""),
            target_mitre=", ".join(target_record.get("mitre") or []),
            target_query=str(target_record.get("query", ""))[:500],
            candidates_block=candidates_block,
        )
        response = client.messages.create(
            model=model, max_tokens=1024, messages=[{"role": "user", "content": prompt}],
        )
        # Take the first *text* block, not blindly `content[0]`: only some
        # content-block types carry `.text` (a thinking block doesn't), so
        # indexing raised AttributeError — silently downgrading a working LLM
        # call into the bm25_fallback path — and tripped 11 mypy union-attr
        # errors whenever the `llm` extra is installed.
        # `getattr` for the read too, not just the guard: `b.text` on the SDK's
        # content-block union is what mypy rejected in the first place.
        text = next(
            (getattr(b, "text", "") for b in response.content
             if getattr(b, "type", None) == "text"),
            "",
        )
        scored = json.loads(text)
        by_id = _validate_judge_coverage(scored, {h.detection_id for h in hits})
        reranked = [
            {
                "detection_id": h.detection_id,
                "title": h.title,
                "score": _safe_confidence(by_id.get(h.detection_id, {}).get("confidence"), h.score),
                "snippet": h.snippet,
                "reasoning": _safe_reasoning(by_id.get(h.detection_id, {}).get("reasoning")),
            }
            for h in hits
        ]
        reranked.sort(key=lambda c: c["score"], reverse=True)
        return reranked


__all__ = ["RuleSimilarityAgent"]
