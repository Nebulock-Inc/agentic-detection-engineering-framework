"""Native, vendor-free duplicate/complementary/redundant classification.

Deterministic port of detect-vault's `RuleOverlapAgent._analyze_cluster_deterministic`
(hashlib/difflib, stdlib only) — no LLM call. Operates within one MITRE
technique cluster at a time, using `catalog/INDEX.yml`'s `by_technique` map
(built by `Catalog.rebuild_index()`) rather than re-deriving grouping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

import yaml

from adef.core.catalog import NoCatalogRecordError
from adef.core.corpus import build_corpus
from adef.core.journal import workspace_journals_dir

_DUPLICATE_NEAR_THRESHOLD = 0.85  # matches detect-vault's RuleOverlapAgent reference


@dataclass
class Overlap:
    other_id: str
    overlap_type: str  # duplicate | complementary | redundant
    confidence: float
    reasoning: str


def _normalize_query(query_text: str) -> str:
    if not query_text:
        return ""
    normalized = query_text.lower()
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"\s*([=<>!(),])\s*", r"\1", normalized)
    return normalized.strip()


def _similarity(query_a: str, query_b: str) -> float:
    if not query_a or not query_b:
        return 0.0
    return SequenceMatcher(None, _normalize_query(query_a), _normalize_query(query_b)).ratio()


_BOUNDARY_CONTINUATION_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789._"
)


def _is_clean_substring(needle: str, haystack: str) -> bool:
    """True if ``needle`` occurs in ``haystack`` at a clause boundary, not as
    a partial token — e.g. "event.code=1" is a raw Python substring of
    "event.code=10", but the two are unrelated comparisons, not a superset
    relation. Reject a match whose neighboring character continues an
    identifier or number (found live via CodeRabbit review, PR #1)."""
    idx = haystack.find(needle)
    if idx == -1:
        return False
    before = haystack[idx - 1] if idx > 0 else ""
    after = haystack[idx + len(needle)] if idx + len(needle) < len(haystack) else ""
    return (
        before not in _BOUNDARY_CONTINUATION_CHARS
        and after not in _BOUNDARY_CONTINUATION_CHARS
    )


def classify_pair(record_a: dict, record_b: dict, id_a: str, id_b: str) -> Overlap:
    """Classify the relationship of ``record_b`` relative to ``record_a``.

    ``other_id`` on the returned ``Overlap`` is always ``id_b`` — callers
    build one ``Overlap`` per (target, cluster-mate) pair.
    """
    query_a, query_b = record_a.get("query", ""), record_b.get("query", "")
    norm_a, norm_b = _normalize_query(query_a), _normalize_query(query_b)

    if norm_a and norm_a == norm_b:
        return Overlap(id_b, "duplicate", 1.0, "Identical query logic after normalization")

    # Substring/redundant check runs before the near-duplicate ratio threshold:
    # a substring relation (e.g. one rule adds a single extra clause) can score
    # >= _DUPLICATE_NEAR_THRESHOLD on SequenceMatcher, but the narrower rule is
    # "redundant" (rule 2), not a "duplicate" (rule 1) — the substring test is
    # the more specific signal and must win.
    same_source = bool(record_a.get("data_source")) and record_a.get("data_source") == record_b.get("data_source")
    if same_source and norm_a and norm_b and norm_a != norm_b:
        # Strip one layer of outer wrapping parens before the substring check —
        # detect-vault's WHERE-only predicate convention wraps the whole
        # condition in `(...)`, which otherwise defeats substring matching
        # (found live during Task 6, against detect-vault-shaped fixtures).
        # ponytail: lstrip/rstrip strip a *character set*, not one matched
        # pair — correct for the single-outer-paren case real detect-vault
        # queries use, but would corrupt a query with nested parens
        # immediately at its outer edge (e.g. `((a) and (b))`). Upgrade to a
        # real matched-pair strip if a fixture ever needs that shape.
        norm_a_stripped = norm_a.lstrip("(").rstrip(")")
        norm_b_stripped = norm_b.lstrip("(").rstrip(")")
        if _is_clean_substring(norm_a_stripped, norm_b_stripped):
            return Overlap(
                id_b, "redundant", len(norm_a_stripped) / len(norm_b_stripped),
                f"{id_b}'s query is a strict superset of {id_a}'s predicate — "
                f"{id_b} fires on a subset of what {id_a} already covers",
            )
        if _is_clean_substring(norm_b_stripped, norm_a_stripped):
            return Overlap(
                id_b, "redundant", len(norm_b_stripped) / len(norm_a_stripped),
                f"{id_a}'s query is a strict superset of {id_b}'s predicate — "
                f"{id_a} fires on a subset of what {id_b} already covers",
            )

    ratio = _similarity(query_a, query_b)
    if ratio >= _DUPLICATE_NEAR_THRESHOLD:
        return Overlap(id_b, "duplicate", ratio, f"Near-identical query logic ({ratio:.0%} similar)")

    return Overlap(
        id_b, "complementary", ratio,
        "Same technique, distinct detection logic — different coverage angle",
    )


class RuleOverlapAgent:
    """Native replacement for the upstream RuleOverlap wrapper agent."""

    def run(self, detection_id: str, workspace: Path | None = None, **ctx: Any) -> dict[str, Any]:
        journals_dir = workspace_journals_dir(workspace, create=False)
        ws = journals_dir.parent

        # Same membership resolver as Similarity — the two agents disagreeing
        # about what the catalog holds is the bug this replaced. Entries with
        # no query are skipped here rather than absent: `classify_pair` needs
        # logic on both sides, so a journal-only draft is in the corpus and
        # simply not comparable.
        records: dict[str, dict] = {
            e.detection_id: e.record
            for e in build_corpus(ws)
            if e.record is not None and (e.record.get("query") or "")
        }
        target = records.get(detection_id)
        if target is None:
            raise NoCatalogRecordError(f"No catalog record found for {detection_id}")

        index_path = ws / "catalog" / "INDEX.yml"
        by_technique: dict[str, list[str]] = {}
        if index_path.exists():
            index = yaml.safe_load(index_path.read_text(encoding="utf-8")) or {}
            by_technique = index.get("by_technique", {})

        cluster_ids: set[str] = set()
        techniques = list(target.get("mitre") or [])
        for technique in techniques:
            cluster_ids.update(by_technique.get(technique, []))
        cluster_ids.discard(detection_id)

        overlaps = [
            classify_pair(target, records[other_id], detection_id, other_id)
            for other_id in sorted(cluster_ids)
            if other_id in records
        ]
        # Most-relevant-first for the journal reader. Display ordering only —
        # nothing is filtered or capped (that's a product call, not this
        # agent's); `other_id` breaks ties so the output stays deterministic.
        overlaps.sort(key=lambda o: (-o.confidence, o.other_id))

        return {
            "detection_id": detection_id,
            "techniques": techniques,
            "overlaps": [
                {
                    "other_id": o.other_id,
                    "overlap_type": o.overlap_type,
                    "confidence": round(o.confidence, 4),
                    "reasoning": o.reasoning,
                }
                for o in overlaps
            ],
        }


__all__ = ["RuleOverlapAgent", "Overlap", "classify_pair"]
