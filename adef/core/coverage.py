"""Coverage-quality model — what ADEF knows that a vendor heatmap discards.

A plain ATT&CK heatmap answers "is this technique green?". ADEF knows, per
detection, the log source it fires against, whether it's been reviewed, and how
many detections back each technique — so it answers the questions a skeptical
detection-engineering lead actually asks:

- **How much coverage can I trust?** A technique backed only by one rule, or
  only by rules still flagged ``needs_review``, is *fragile* — one tuning change
  or one bad feed from a blind spot. That is not the same as ``solid`` coverage
  and this model refuses to colour it the same green.
- **What's my single point of failure?** Techniques with exactly one detection.
- **How concentrated is my log-source risk?** If most coverage rides one feed,
  that feed breaking takes a swath of the matrix dark at once.

Mappings to IDs absent from the shipped ATT&CK reference (revoked, typo'd,
fictional) are never counted as coverage — they're surfaced as invalid instead.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from adef.core.attack import attack_reference


class Tier(Enum):
    """Coverage quality for one technique. Ordered worst→best by value."""

    BLIND = "blind"      # no valid detection maps here (not represented in a build)
    FRAGILE = "fragile"  # covered, but single-detection OR all detections need review
    SOLID = "solid"      # depth ≥2 and at least one reviewed (not needs_review) detection

    @property
    def score(self) -> int:
        return {Tier.BLIND: 0, Tier.FRAGILE: 50, Tier.SOLID: 100}[self]


@dataclass
class TechniqueCoverage:
    technique_id: str
    name: str
    tactics: list[str]
    detection_ids: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    reviewed_count: int = 0  # detections NOT flagged needs_review

    @property
    def depth(self) -> int:
        return len(self.detection_ids)

    @property
    def tier(self) -> Tier:
        if self.depth == 0:
            return Tier.BLIND
        if self.depth >= 2 and self.reviewed_count >= 1:
            return Tier.SOLID
        return Tier.FRAGILE

    def why(self) -> str:
        bits = [f"{self.depth} detection{'s' if self.depth != 1 else ''}"]
        if self.reviewed_count == 0 and self.depth:
            bits.append("all need review")
        if len(self.sources) == 1:
            bits.append(f"single source ({next(iter(self.sources))})")
        elif self.sources:
            bits.append(f"{len(self.sources)} sources")
        return "; ".join(bits)


@dataclass
class Coverage:
    techniques: dict[str, TechniqueCoverage] = field(default_factory=dict)
    invalid_mappings: dict[str, list[str]] = field(default_factory=dict)  # bad id -> detection ids
    dominant_source: tuple[str, int] | None = None

    def by_tier(self) -> dict[Tier, list[str]]:
        out: dict[Tier, list[str]] = {t: [] for t in Tier}
        for tid, tc in self.techniques.items():
            out[tc.tier].append(tid)
        return out

    def single_detection_techniques(self) -> list[str]:
        return sorted(tid for tid, tc in self.techniques.items() if tc.depth == 1)

    def single_source_techniques(self) -> list[str]:
        """Techniques whose every backing detection is one and the same source."""
        return sorted(tid for tid, tc in self.techniques.items() if len(tc.sources) == 1)

    def tactic_rollup(self) -> dict[str, dict[Tier, int]]:
        """Per-tactic tier counts (a technique counts under each of its tactics)."""
        roll: dict[str, dict[Tier, int]] = collections.defaultdict(
            lambda: {t: 0 for t in Tier}
        )
        for tc in self.techniques.values():
            for tactic in tc.tactics:
                roll[tactic][tc.tier] += 1
        return dict(roll)


def build_coverage(records: Iterable[dict]) -> Coverage:
    """Compute the coverage model from catalog record dicts."""
    ref = attack_reference()
    cov = Coverage()
    source_counter: collections.Counter[str] = collections.Counter()

    for rec in records:
        det_id = rec.get("id", "?")
        source = rec.get("data_source") or ""
        needs_review = bool(rec.get("needs_review"))
        for raw in rec.get("mitre") or []:
            tid = str(raw).strip().upper()
            entry = ref.technique(tid)
            if entry is None:
                cov.invalid_mappings.setdefault(tid, []).append(det_id)
                continue
            tc = cov.techniques.get(tid)
            if tc is None:
                tc = TechniqueCoverage(
                    technique_id=tid,
                    name=entry.get("name", ""),
                    tactics=ref.tactics_for(tid),
                )
                cov.techniques[tid] = tc
            tc.detection_ids.append(det_id)
            if source:
                tc.sources.add(source)
            if not needs_review:
                tc.reviewed_count += 1
            if source:
                source_counter[source] += 1

    if source_counter:
        cov.dominant_source = source_counter.most_common(1)[0]
    return cov


def navigator_layer(cov: Coverage, name: str = "ADEF coverage") -> dict:
    """A MITRE ATT&CK Navigator layer (v4.5), scored by coverage *quality*.

    score = tier score (solid 100 / fragile 50); the comment carries the why
    (depth, sources, review state) so even the shareable heatmap says more than
    binary presence.
    """
    techniques = []
    for tid, tc in sorted(cov.techniques.items()):
        techniques.append(
            {
                "techniqueID": tid,
                "score": tc.tier.score,
                "comment": f"{tc.tier.value}: {tc.why()}",
                "enabled": True,
            }
        )
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "domain": "enterprise-attack",
        "description": (
            "Scored by ADEF coverage quality: 100=solid (depth≥2, reviewed), "
            "50=fragile (single detection or unreviewed). Absent techniques are "
            "blind spots."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
    }


__all__ = ["Coverage", "TechniqueCoverage", "Tier", "build_coverage", "navigator_layer"]
