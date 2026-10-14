"""Rule-similarity search over the ADEF catalog — does a rule like this
already exist?

Ranks with the same BM25 index `adef detection search` ships
(`adef.core.memory.MemoryIndex`), built over `adef.core.corpus.build_corpus` —
a detection is a member of the corpus if it has a catalog record OR a
journal, so a catalogued rule with no journal is still shortlisted (by its
record's title/mitre/platform/query), and a journal-only draft (a fresh
`detection new`, before it has a catalog record) is still shortlisted too —
at minimum by its title, which `CorpusEntry.index_text` always includes,
even when the journal itself is still template-only. `RuleOverlapAgent`
resolves membership through the same `build_corpus` call, so the two agents
agree on what the catalog holds.
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
`top_k`, not catalog size.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any

from adef.core.catalog import Catalog, catalog_dir, NoCatalogRecordError
from adef.core.corpus import build_corpus
from adef.core.corpus_text import record_mitre, record_query_logic, record_search_text
from adef.core.value_index import build_value_index
from adef.core.field_index import build_field_index
from adef.core.journal import workspace_journals_dir
from adef.core.memory import MemoryIndex

DEFAULT_LLM_MODEL = "claude-haiku-4-5-20251001"

#: `agent` returns the shortlist enriched for the caller to judge and ranks
#: nothing — the caller (an assistant session) has context ADEF does not, and
#: its reasoning lands in the transcript where it can be reviewed. Like `bm25`
#: it never makes a network call.
_VALID_SIMILARITY_MODES = frozenset({"auto", "bm25", "llm", "agent"})

_JUDGE_PROMPT = """You are a detection engineering expert. Given a target detection rule and a \
shortlist of candidates retrieved by keyword search and by shared telemetry fields (a \
candidate may share fields but no words with the target), judge which candidates are a true semantic \
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
    CodeRabbit review) — a non-finite or out-of-range value would
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
    CodeRabbit review — a non-string value passed through unchanged)."""
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
    already takes (found via CodeRabbit review).
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
    mitre = record_mitre(record)
    return {
        # For Sigma, the logsource+detection blocks — the raw file is mostly
        # title/description/references, and the journal's 300-char render
        # would never reach the detection. `adef detection show` has the rest.
        "query": record_query_logic(record),
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

        # Mirror `adef.core.catalog.known_detection_ids`: constructing
        # `Catalog(ws)` unconditionally mkdirs `catalog/`, which this read
        # path must not do on a bare workspace.
        records: dict[str, dict] = {}
        if catalog_dir(ws).is_dir():
            for det_id, _path, data in Catalog(ws).iter_records():
                # First one wins, matching `build_corpus` (corpus.py) — a
                # duplicate id under two platform dirs must resolve to the
                # same record the shared BM25 index scored.
                records.setdefault(det_id, data)
        target_record = records.get(detection_id)
        if target_record is None:
            raise NoCatalogRecordError(f"No catalog record found for {detection_id}")
        target_text = record_search_text(target_record)

        corpus = build_corpus(ws)
        # Full corpus size, not `top_k`: each pass already scores every
        # candidate internally and only slices its *return* list (see
        # `MemoryIndex.search`/`FieldIndex.candidates`), so retrieving the
        # whole scored pool adds only per-hit result construction (BM25 builds
        # a snippet for each). Truncating each pass to
        # `top_k` *before* fusion (as an early version of this code did) can
        # silently exclude a genuine field-only winner at small `top_k`, or
        # leave it to win only on an accidental detection_id tie rather than
        # fused merit — RRF needs the full candidate pool from both passes to
        # decide correctly; only the merged result gets truncated to `top_k`
        # (CodeRabbit finding).
        pool_size = len(corpus)
        index = MemoryIndex()
        index.build(corpus)
        bm25_hits = [
            h for h in index.search(target_text, limit=pool_size)
            if h.detection_id != detection_id
        ]

        # Second retrieval pass. Cross-language duplicates share no tokens, so
        # BM25 cannot reach them at all — this is recall, not reranking, which
        # is why it expands the shortlist rather than reordering it.
        field_index = build_field_index(corpus, ws)
        field_matching = field_index.matching_for(detection_id)
        # Fused only when the target's fields were canonicalized through a
        # declared schema. Otherwise the pass can only compare literal field
        # names — same language only, which BM25 already covers through shared
        # tokens — and in a mixed-language corpus a field every rule of one
        # language reads (`ParentImage`) is not rare enough to be gated, so its
        # same-language matches score 1.0 and crowd a cross-language twin that
        # BM25 DID find out of the shortlist (observed in a trial run).
        field_hits = (
            field_index.candidates(detection_id, top_k=pool_size)
            if field_matching == "schema" else []
        )

        # Third pass: distinctive values shared with rules in OTHER languages
        # (`bitsadmin.exe`, `EnableLUA`). Needs no schema — a Sigma rule and a
        # CQL rule name the same binary however their fields are spelled — and
        # it never proposes a same-language candidate, which is BM25's job.
        value_hits = build_value_index(corpus).candidates(detection_id, top_k=pool_size)

        # Reciprocal rank fusion. The scores are on incomparable scales;
        # normalizing BM25 by the run's top score would promote a weak lexical
        # match to 1.0 and stand it beside a strong structural one. RRF needs
        # no common scale and no weighting tuned against an eval corpus.
        _RRF_K = 60
        fused: dict[str, float] = {}
        for rank, h in enumerate(bm25_hits, start=1):
            fused[h.detection_id] = fused.get(h.detection_id, 0.0) + 1.0 / (_RRF_K + rank)
        for rank, field_hit in enumerate(field_hits, start=1):
            fused[field_hit.detection_id] = (
                fused.get(field_hit.detection_id, 0.0) + 1.0 / (_RRF_K + rank)
            )
        for rank, value_hit in enumerate(value_hits, start=1):
            fused[value_hit.detection_id] = (
                fused.get(value_hit.detection_id, 0.0) + 1.0 / (_RRF_K + rank)
            )

        entries = {e.detection_id: e for e in corpus}
        bm25_by_id = {h.detection_id: h for h in bm25_hits}
        field_by_id = {fh.detection_id: fh for fh in field_hits}
        value_by_id = {vh.detection_id: vh for vh in value_hits}
        ordered = sorted(fused, key=lambda d: (-fused[d], d))[:top_k]

        candidates = []
        for det in ordered:
            bh = bm25_by_id.get(det)
            fh = field_by_id.get(det)
            vh = value_by_id.get(det)
            candidates.append({
                "detection_id": det,
                "title": entries[det].title,
                # `score` stays the BM25 value so existing consumers are
                # unaffected; the two signals are reported separately beside it.
                "score": bh.score if bh else 0.0,
                "snippet": bh.snippet if bh else "",
                "reasoning": "",
                "bm25_score": bh.score if bh else None,
                "field_score": fh.score if fh else None,
                "shared_fields": fh.shared_fields if fh else [],
                "value_score": vh.score if vh else None,
                "shared_values": vh.shared_values if vh else [],
                "found_by": (["bm25"] if bh else []) + (["fields"] if fh else [])
                + (["values"] if vh else []),
            })

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
                "field_matching": field_matching,
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
            if candidates:
                # Judge the FUSED shortlist, not `bm25_hits` alone — a
                # field-only candidate (the cross-language duplicate this
                # whole task exists to surface) would otherwise never reach
                # the LLM judge in `llm`/`auto` mode, even though `bm25` and
                # `agent` mode already carry it (CodeRabbit finding).
                try:
                    candidates = self._rerank_with_llm(
                        records[detection_id], candidates, llm_client, records
                    )
                except Exception as exc:  # noqa: BLE001 — an LLM outage must not break refine
                    return {
                        "detection_id": detection_id,
                        "mode_used": "bm25_fallback",
                        "field_matching": field_matching,
                        # `candidates` here is still the pre-rerank fused list
                        # (the failed call never completed its reassignment),
                        # so structural-only matches remain in the fallback too.
                        "candidates": candidates,
                        "llm_error": str(exc),
                    }

        return {
            "detection_id": detection_id,
            "mode_used": resolved_mode,
            "field_matching": field_matching,
            "candidates": candidates,
        }

    def _rerank_with_llm(
        self,
        target_record: dict,
        candidates: list[dict],
        llm_client: Any | None,
        records: dict[str, dict],
    ) -> list[dict]:
        """Judge the fused shortlist (`candidates`, already BM25+field-merged).

        Confidence/reasoning replace `score`/`reasoning`; every other key —
        `bm25_score`, `field_score`, `shared_fields`, `found_by` — passes
        through unchanged, so an LLM-judged candidate still carries the same
        provenance a `bm25`/`agent`-mode one does. `records` is looked up only
        to fill the empty-snippet prompt fallback below; it is never merged
        into the returned candidate dicts (that enrichment is `agent` mode's
        job via `_logic_fields`, not `llm` mode's).
        """
        client = llm_client
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        model = os.environ.get("ADEF_LLM_MODEL", DEFAULT_LLM_MODEL)

        def _candidate_line(c: dict) -> str:
            line = f"- id={c['detection_id']} title={c['title']!r} snippet={c['snippet']!r}"
            # A value-only candidate (another language, matched on shared
            # literals) has no field evidence and often no useful snippet, so
            # it needs its query slice too, or the judge can't assess it.
            # `shared_values` itself stays out of the prompt.
            value_only = "values" in c.get("found_by", []) and not c.get("shared_fields")
            if value_only:
                query = record_query_logic(records.get(c["detection_id"], {}))[:200]
                return line + (f" query={query!r}" if query else "")
            if not c.get("shared_fields"):
                return line
            # A field-matched candidate needs its own logic in the prompt
            # regardless of whether it also has a BM25 snippet: the snippet is
            # excerpted from the record's FULL index text (title, mitre,
            # platform, data_source, format, query — see
            # `CorpusEntry.index_text`), so a candidate can score via BM25 on
            # shared title/mitre tokens alone and still get a snippet that
            # never touches its actual query — gating on "snippet is empty"
            # alone missed that case. Fall back to the shared field names AND
            # a bounded slice of the candidate's own query, the same signal
            # `agent` mode already hands the caller via `_logic_fields`, just
            # capped short here since an LLM prompt is the consumer
            # (CodeRabbit finding, three rounds: shared_fields when no
            # snippet, then query when no snippet, then query even with one).
            line += f" shared_fields={c['shared_fields']!r}"
            # For Sigma, only the logsource+detection blocks carry logic; the
            # raw query is mostly title/description/references boilerplate
            # (record_query_logic returns other formats' query unchanged).
            query = record_query_logic(records.get(c["detection_id"], {}))[:200]
            if query:
                line += f" query={query!r}"
            return line

        candidates_block = "\n".join(_candidate_line(c) for c in candidates)
        prompt = _JUDGE_PROMPT.format(
            target_title=target_record.get("title", ""),
            target_mitre=", ".join(record_mitre(target_record)),
            # Same Sigma projection as the candidate side above — the raw
            # query slice is mostly boilerplate for a Sigma target.
            target_query=record_query_logic(target_record)[:500],
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
        by_id = _validate_judge_coverage(scored, {c["detection_id"] for c in candidates})

        def _fallback_score(c: dict) -> float:
            # `c["score"]` is the BM25 value, which is exactly `0.0` for a
            # field-only candidate (no BM25 hit at all) — falling back to it
            # sinks the cross-language duplicate this task exists to surface
            # to the bottom of the shortlist on any invalid judge confidence.
            # `field_score` is a real 0..1 signal for that candidate; use it
            # instead. A candidate WITH a BM25 score keeps the existing
            # fallback unchanged (`c["score"] == c["bm25_score"]` there), so
            # `test_rule_similarity_agent.py`'s pinned NaN-fallback contract
            # is untouched.
            if c.get("bm25_score") is not None:
                return float(c["score"])
            # A value-only candidate (another language) has neither BM25 nor
            # field score; its value_score is its real signal.
            return float(c.get("field_score") or c.get("value_score") or 0.0)

        reranked = [
            {
                **c,
                "score": _safe_confidence(
                    by_id.get(c["detection_id"], {}).get("confidence"), _fallback_score(c)
                ),
                "reasoning": _safe_reasoning(by_id.get(c["detection_id"], {}).get("reasoning")),
            }
            for c in candidates
        ]
        reranked.sort(key=lambda c: c["score"], reverse=True)
        return reranked


__all__ = ["RuleSimilarityAgent"]
