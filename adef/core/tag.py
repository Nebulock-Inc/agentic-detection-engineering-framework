"""MITRE enrichment write path — the seam the mitre-tagger skill orchestrates.

``tag_mitre`` validates technique IDs against the shipped ATT&CK reference,
merges them into a catalog record's ``mitre`` list, recomputes the MITRE review
reasons (``no_mitre`` cleared, ``invalid_mitre`` never introduced — invalid IDs
are rejected up front), and rebuilds the INDEX. Deterministic and atomic: if any
ID is invalid, nothing is written.

This is ADEF's enrichment layer — it writes only to the catalog record, never to
the user's source rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from adef.core.attack import attack_reference
from adef.core.corpus_text import record_mitre
from adef.core.catalog import Catalog, _now_iso
from adef.core.rule_discovery import (
    REVIEW_INVALID_MITRE,
    REVIEW_NO_MITRE,
)


class InvalidTechniqueError(ValueError):
    """One or more supplied IDs are not valid ATT&CK techniques."""


@dataclass
class TagResult:
    detection_id: str
    added: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    revoked: dict[str, str] = field(default_factory=dict)  # id -> replacement


def tag_mitre(workspace: Path, detection_id: str, technique_ids: list[str]) -> TagResult:
    """Add validated MITRE technique IDs to a catalog record.

    Raises ``KeyError`` if the detection isn't in the catalog, and
    ``InvalidTechniqueError`` (writing nothing) if any ID isn't real.
    Revoked-but-real IDs are accepted and reported (the caller decides whether
    to swap in the replacement).
    """
    # `workspace`, not the bare resolver, which sees `$ADEF_WORKSPACE` only.
    # This is the harshest place to get it wrong: an ID the reference doesn't
    # know is a *refusal* that writes nothing, so `adef detection tag-mitre
    # D-0007 T<new> --workspace /srv/ws` raised `InvalidTechniqueError` for a
    # technique the user's own refreshed snapshot contains.
    ref = attack_reference(workspace)
    cat = Catalog(workspace)

    found = cat.find_record(detection_id)
    if found is None:
        raise KeyError(f"{detection_id} is not in the catalog")
    path, data = found

    # Normalise + validate all IDs before touching disk (atomic).
    normalised = [t.strip().upper() for t in technique_ids if t.strip()]
    invalid = [t for t in normalised if not ref.is_valid(t)]
    if invalid:
        raise InvalidTechniqueError(
            f"not valid ATT&CK technique IDs: {', '.join(invalid)}"
        )

    result = TagResult(detection_id=detection_id)
    existing = record_mitre(data)
    existing_set = {t.upper() for t in existing}

    for t in normalised:
        if t in existing_set:
            result.already_present.append(t)
            continue
        existing.append(t)
        existing_set.add(t)
        result.added.append(t)
        res = ref.resolve(t)
        if res.revoked and res.superseded_by:
            result.revoked[t] = res.superseded_by

    data["mitre"] = existing

    # Recompute the MITRE review reasons. With ≥1 valid mapping now present,
    # neither no_mitre nor invalid_mitre applies; other reasons are untouched.
    reasons = [
        r for r in (data.get("review_reasons") or [])
        if r not in (REVIEW_NO_MITRE, REVIEW_INVALID_MITRE)
    ]
    data["review_reasons"] = reasons
    data["needs_review"] = bool(reasons)
    data["updated"] = _now_iso()

    cat.write_raw(path, data)
    cat.rebuild_index()
    return result


@dataclass
class UntagResult:
    detection_id: str
    removed: list[str] = field(default_factory=list)
    not_present: list[str] = field(default_factory=list)
    now_unmapped: bool = False  # mitre list emptied → back on the no_mitre queue


def untag_mitre(workspace: Path, detection_id: str, technique_ids: list[str]) -> UntagResult:
    """Remove MITRE technique IDs from a catalog record.

    The retag seam: Observe-stage findings legitimately invalidate mappings
    (e.g. a hypothesis pivot, T1071/T1571 → T1046) and hand-edits
    skip INDEX rebuilds and review-reason bookkeeping. If the removal empties
    the mapping, the record rejoins the ``no_mitre`` enrichment queue.
    """
    cat = Catalog(workspace)
    found = cat.find_record(detection_id)
    if found is None:
        raise KeyError(f"{detection_id} is not in the catalog")
    path, data = found

    targets = {t.strip().upper() for t in technique_ids if t.strip()}
    result = UntagResult(detection_id=detection_id)
    remaining = []
    for t in record_mitre(data):
        if str(t).upper() in targets:
            result.removed.append(str(t).upper())
            targets.discard(str(t).upper())
        else:
            remaining.append(t)
    result.not_present = sorted(targets)

    if not result.removed:
        return result  # nothing changed — don't touch disk

    # Pre-flight the index build *before* the write. Untagging validates
    # nothing — you can always remove an ID — but `rebuild_index()` on the last
    # line can fail, and then the record has been written while `INDEX.yml`
    # still maps the removed technique to this detection. `adef coverage` and
    # `adef detection list --tactic` read the stored INDEX, so they keep
    # claiming coverage the record has disclaimed; nothing surfaces it until
    # someone happens to run `adef reindex`.
    #
    # `build_index()`, not `attack_reference(workspace)`, which was the first
    # version of this guard: it covered only one of the two reachable causes. A
    # corrupt `attack/enterprise.json` is the obvious one (`by_tactic` resolves
    # through it), but `build_index` also groups by `engine`, `status` and
    # `data_source` — so a *second, unrelated* record hand-edited to
    # `engine: [sigma]` raises an unhashable-key `TypeError` and half-applies
    # exactly the same way. Pre-flighting the operation that will actually run
    # covers both, and any third cause, for the same one line. It re-reads the
    # ATT&CK snapshot through the same `lru_cache` entry the rebuild will use,
    # so the only cost is a second walk of the records.
    #
    # Deliberately *not* done in `tag_mitre`, which has the same hole: its
    # failure direction is an omission (the record gains a technique the INDEX
    # lacks — a coverage gap, which `adef doctor`'s index check reports), not a
    # false claim. And the `mitre-tagger` skill drains the whole `no_mitre`
    # queue a record at a time, so a second walk per call is O(n²) over the
    # catalog to defend against the milder direction. Untagging is the one-off
    # retag seam; one extra walk there is free.
    #
    # ponytail: this closes the pre-write causes, which are the reachable ones.
    # A failure *inside* `rebuild_index` after it has built successfully (the
    # atomic write itself) still strands a stale INDEX needing `adef reindex`.
    # Make write+rebuild genuinely atomic only if that stops being enough.
    cat.build_index()

    data["mitre"] = remaining
    reasons = list(data.get("review_reasons") or [])
    if not remaining and REVIEW_NO_MITRE not in reasons:
        reasons.append(REVIEW_NO_MITRE)
        result.now_unmapped = True
    data["review_reasons"] = reasons
    data["needs_review"] = bool(reasons)
    data["updated"] = _now_iso()

    cat.write_raw(path, data)
    cat.rebuild_index()
    return result


__all__ = ["InvalidTechniqueError", "TagResult", "UntagResult", "tag_mitre", "untag_mitre"]
