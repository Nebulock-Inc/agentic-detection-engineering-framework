"""Rule-similarity search over the ADEF catalog — BM25 retrieval, optional
LLM rerank.

Answers "does a rule like this already exist?" in two stages:
1. Always: rank the whole catalog with the same BM25 index `adef detection
   search` ships (`adef.core.memory.MemoryIndex`) and take the top-K.
2. Optionally (`similarity_mode` "llm" or "auto" with an LLM available):
   ask an LLM judge to re-score just that shortlist for true semantic
   similarity (paraphrase/synonym matches BM25's lexical scoring misses).

The LLM step never scans the whole corpus — cost and latency stay bounded by
`top_k`, not catalog size. See the plan's Task 2 design rationale.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from adef.core.catalog import Catalog
from adef.core.corpus_text import record_search_text
from adef.core.journal import Journal, workspace_journals_dir
from adef.core.memory import MemoryIndex

DEFAULT_LLM_MODEL = "claude-haiku-4-5-20251001"

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


class RuleSimilarityAgent:
    """Native replacement for the upstream RuleSimilarity wrapper agent."""

    def run(
        self,
        detection_id: str,
        workspace: Path | None = None,
        top_k: int = 5,
        similarity_mode: str = "auto",
        llm_client: Any | None = None,
        **ctx: Any,
    ) -> dict[str, Any]:
        journals_dir = workspace_journals_dir(workspace, create=False)
        ws = journals_dir.parent
        catalog = Catalog(ws)

        records: dict[str, dict] = {}
        record_text: dict[str, str] = {}
        for det_id, _path, data in catalog.iter_records():
            records[det_id] = data
            record_text[det_id] = record_search_text(data)
        target_text = record_text.get(detection_id)
        if target_text is None:
            raise ValueError(f"No catalog record found for {detection_id}")

        index = MemoryIndex(journals_dir=journals_dir)
        index.build(
            entries=list(Journal(journals_dir).iter_entries()),
            extra_text_for=lambda e: record_text.get(e.detection_id, ""),
        )
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
        scored = json.loads(response.content[0].text)
        by_id = {s["detection_id"]: s for s in scored}
        reranked = [
            {
                "detection_id": h.detection_id,
                "title": h.title,
                "score": float(by_id.get(h.detection_id, {}).get("confidence", h.score)),
                "snippet": h.snippet,
                "reasoning": by_id.get(h.detection_id, {}).get("reasoning", ""),
            }
            for h in hits
        ]
        reranked.sort(key=lambda c: c["score"], reverse=True)
        return reranked


__all__ = ["RuleSimilarityAgent"]
