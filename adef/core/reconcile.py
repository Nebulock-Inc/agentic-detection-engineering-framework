"""Sync reconciliation — the identity cascade.

Given the records already in the catalog and the rules just discovered in the
source repo, decide **which discovered rule is which existing detection** and
what to do about it. Pure logic: no I/O, no filesystem — takes dicts + a plan
out, so the cascade is testable in isolation and `adef sync` just applies the
plan.

The cascade (first match wins), from ``docs/plans/2026-07-22-adef-sync-design.md``:

1. embedded UUID match          → same detection
2. content-hash match (no uuid) → unchanged
3. same path, new hash          → modified
4. *(fuzzy title/query match — deferred; see note below)*
5. no match                     → new
6. existing record, source gone → orphaned (never deleted)

**Enrichment is preserved across re-derivation.** On a match, derived fields
(title, query, platform, hashes, …) are refreshed from the source; enrichment
fields (mitre, status, stage, owner) and identity (id, created) are kept. This
is the whole point — re-syncing never loses the human's work.

Fuzzy matching (cascade step 4, for renamed+edited rules with no UUID) is
**not implemented here**. For git repos, `git diff`'s rename detection covers it
upstream; for the rest, a fuzzy merge risks a *wrong* identity match, which is
worse than a duplicate. Until it lands, such a rule falls through to NEW — a
duplicate a human can merge, not a silent mis-attribution. Called out in the
design doc's open questions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

from adef.core.rule_discovery import DiscoveredRule

_ID_RE = re.compile(r"^D-(\d+)$")

# Fields ADEF owns as enrichment — preserved from the existing record on a match.
# Everything else on a matched record is *derived* and refreshed from the source.
_ENRICHMENT_FIELDS = ("mitre", "status", "stage", "owner")
# Identity/provenance — never change on a match.
_PRESERVED_IDENTITY = ("id", "created")


class Action(Enum):
    UNCHANGED = "unchanged"  # matched, source identical → no write needed
    MODIFIED = "modified"    # matched, source changed → refresh derived fields
    NEW = "new"              # no match → new detection, fresh D-XXXX
    ORPHANED = "orphaned"    # existing record whose source rule is gone


@dataclass
class PlanEntry:
    action: Action
    detection_id: str
    discovered: Optional[DiscoveredRule] = None   # None for ORPHANED
    existing: Optional[dict] = None               # None for NEW
    # For NEW/MODIFIED/ORPHANED: the record dict the caller should persist
    # (enrichment merged in). None for UNCHANGED (nothing to write).
    merged: Optional[dict] = None


def _next_id_after(max_index: int) -> str:
    return f"D-{max_index + 1:04d}"


def _max_index(existing: Iterable[dict]) -> int:
    hi = 0
    for rec in existing:
        m = _ID_RE.match(str(rec.get("id", "")))
        if m:
            hi = max(hi, int(m.group(1)))
    return hi


def reconcile(
    existing: list[dict],
    discovered: list[DiscoveredRule],
    rule_root: Optional[Path] = None,
    floor_index: int = 0,
) -> list[PlanEntry]:
    """Match discovered rules to existing records; return a per-rule plan.

    ``existing`` are catalog record dicts (as from ``Catalog.iter_records``);
    ``discovered`` are freshly walked ``DiscoveredRule`` objects. ``rule_root``
    lets the path-match step (cascade 3) and the unchanged/moved check compare
    against the stored ``rule_ref`` in the same ``<root.name>/<rel>`` form the
    catalog writes; omit it and path-matching is skipped (UUID/hash still work).

    ``floor_index`` is the highest ``D-XXXX`` index seen *outside* the catalog
    (i.e. in ``journals/``); NEW ids allocate above ``max(catalog, floor)`` so a
    journal-only detection whose catalog record is gone never gets its id reused
    — the shared-ID-space guarantee, same as ``Catalog.next_id`` (ISA 2026-07-22).
    This stays a pure function: the caller reads the journal max and passes it in.
    """
    by_uuid = {r["rule_uuid"]: r for r in existing if r.get("rule_uuid")}
    by_hash = {r["source_hash"]: r for r in existing if r.get("source_hash")}
    by_ref = {r["rule_ref"]: r for r in existing if r.get("rule_ref")}

    matched_ids: set[str] = set()
    plan: list[PlanEntry] = []
    next_index = max(_max_index(existing), floor_index)

    for disc in discovered:
        ref = _rule_ref_of(disc, rule_root)
        match = None
        if disc.rule_uuid and disc.rule_uuid in by_uuid:      # 1. UUID
            match = by_uuid[disc.rule_uuid]
        elif disc.source_hash and disc.source_hash in by_hash:  # 2. content hash
            match = by_hash[disc.source_hash]
        elif ref and ref in by_ref:                            # 3. same path
            match = by_ref[ref]

        if match is None:  # 5. new
            next_index += 1
            plan.append(
                PlanEntry(
                    action=Action.NEW,
                    detection_id=_next_id_after(next_index - 1),
                    discovered=disc,
                )
            )
            continue

        matched_ids.add(match["id"])
        merged = _merge(match, disc)
        # Unchanged = content identical AND not moved. "Not moved" only counts
        # when we could resolve a ref (a root was given); without one we can't
        # tell, so we don't spuriously flag a move.
        not_moved = (not ref) or ref == match.get("rule_ref")
        unchanged = (
            bool(disc.source_hash)
            and disc.source_hash == match.get("source_hash")
            and not_moved
        )
        plan.append(
            PlanEntry(
                action=Action.UNCHANGED if unchanged else Action.MODIFIED,
                detection_id=match["id"],
                discovered=disc,
                existing=match,
                merged=None if unchanged else merged,
            )
        )

    # 6. existing records with no discovered match → orphaned — EXCEPT records
    # authored in ADEF, which have no upstream source to reconcile against.
    # Orphaning them would mark a repo-less team's own detections deprecated;
    # they pass through untouched (ISA 2026-07-22, "ADEF as a detection home").
    for rec in existing:
        if rec.get("origin") == "authored":
            continue
        if rec["id"] not in matched_ids:
            orphaned = dict(rec)
            orphaned["status"] = "deprecated"
            orphaned["orphaned"] = True
            plan.append(
                PlanEntry(
                    action=Action.ORPHANED,
                    detection_id=rec["id"],
                    existing=rec,
                    merged=orphaned,
                )
            )
    return plan


def _rule_ref_of(disc: DiscoveredRule, rule_root: Optional[Path]) -> str:
    """The ``rule_ref`` a discovered rule would get — matches how the catalog
    writes it (``<root.name>/<path-inside-root>``) so path-matching and the
    unchanged/moved check compare like-for-like. Empty when it can't be resolved
    (no root, or the file isn't under it) — path-matching then just doesn't fire.
    """
    if rule_root is None or not disc.path:
        return ""
    root = Path(rule_root).expanduser().resolve()
    try:
        return str(Path(root.name) / disc.path.expanduser().resolve().relative_to(root))
    except ValueError:
        return ""


def _merge(existing: dict, disc: DiscoveredRule) -> dict:
    """Refresh derived fields from ``disc``; keep enrichment + identity.

    Pure — starts from the existing record dict and overwrites only the derived
    fields with the freshly-discovered values. ``rule_ref``/``original_path``
    are workspace-relative, so the command re-derives them on apply (it has the
    real root); everything else is captured here.
    """
    merged = dict(existing)
    merged.update(
        {
            "title": disc.title or existing.get("title", ""),
            "rule_uuid": disc.rule_uuid,
            "source_hash": disc.source_hash,
            "query": disc.query_text,
            "platform": disc.platform or existing.get("platform", ""),
            "kind": disc.kind,
            "format": disc.format,
            "query_language": disc.query_language,
            "data_source": disc.data_source,
            "support": disc.support,
        }
    )
    # Enrichment (mitre/status/stage/owner) + identity (id/created) always win.
    for f in _ENRICHMENT_FIELDS + _PRESERVED_IDENTITY:
        if f in existing:
            merged[f] = existing[f]
    return merged


__all__ = ["Action", "PlanEntry", "reconcile"]
