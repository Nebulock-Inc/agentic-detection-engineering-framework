"""Sync reconciliation — the identity cascade.

Given the records already in the catalog and the rules just discovered in the
source repo, decide **which discovered rule is which existing detection** and
what to do about it. Pure logic: no I/O, no filesystem — takes dicts + a plan
out, so the cascade is testable in isolation and `adef sync` just applies the
plan.

The cascade (first match wins):

1. embedded UUID match          → same detection
2. content-hash match (no uuid) → unchanged
3. same path, new hash          → modified
4. *(fuzzy title/query match — deferred; see note below)*
5. no match                     → new
6. existing record, source gone → orphaned (never deleted)

**Enrichment is preserved across re-derivation.** On a match, derived fields
(title, query, platform, hashes, …) are refreshed from the source; enrichment
fields (mitre, status, stage, owner) and identity (id, created) are kept. This
is the whole point — re-syncing never loses the human's work. An *empty*
``mitre`` is not work to keep: when the source now yields a mapping, it fills
the record, even if the source file is unchanged.

Fuzzy matching (cascade step 4, for renamed+edited rules with no UUID) is
**not implemented here**. For git repos, `git diff`'s rename detection covers it
upstream; for the rest, a fuzzy merge risks a *wrong* identity match, which is
worse than a duplicate. Until it lands, such a rule falls through to NEW — a
duplicate a human can merge, not a silent mis-attribution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional

from adef.core.corpus_text import record_mitre
from adef.core.rule_discovery import DiscoveredRule

_ID_RE = re.compile(r"^D-(\d+)$")

# Fields ADEF owns as enrichment — preserved from the existing record on a match.
# Everything else on a matched record is *derived* and refreshed from the source.
_ENRICHMENT_FIELDS = ("mitre", "status", "stage", "owner")
# `catalog._UNKNOWN_PLATFORM`; not imported, because catalog imports discovery
# and reconcile stays a leaf.
_UNKNOWN_PLATFORM = "multi-platform"
# Derived fields compared on an unchanged file to catch re-extraction drift.
_REDERIVED_FIELDS = (
    "title", "query", "platform", "kind", "format", "query_language", "data_source", "support",
    "rule_uuid",
)
# Identity/provenance — never change on a match.
_PRESERVED_IDENTITY = ("id", "created")
# The rest of the enrichment block (`CatalogRecord`'s "never derived from the
# source rule" fields). `_merge` keeps them for free — it starts from the existing
# record — but a caller that *re-derives* the record instead has to carry them
# over by name or they are destroyed: discovery has no value to refresh them
# from, so "refreshed from the source" means "emptied". `sync` is that caller.
# Listed here rather than in `sync` so the write paths can't drift on what
# survives a re-run (cf. `gates._DOC_DERIVED_ENRICHMENT`, which refreshes these
# from a GATES document because there one exists).
_CARRIED_ENRICHMENT = (
    "description",
    "alert",
    "entities",
    "observables",
    "references",
    "hunt_ref",
    "platforms",
)


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
    orphan_scope: Optional[Callable[[dict], bool]] = None,
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
    — the shared-ID-space guarantee, same as ``Catalog.next_id``.
    This stays a pure function: the caller reads the journal max and passes it in.

    ``orphan_scope`` limits which unmatched records are orphaned. Matching still
    considers every record (UUID/hash identity survives a moved repo), but only
    records the predicate accepts can be declared gone — so syncing one repo in
    a workspace holding several never orphans the others. ``None`` = all.
    """
    # The match maps are built from the records this sync *owns*. `authored` and
    # `promoted` are skipped in the orphan pass below for the same reason — no
    # upstream rule repo — but skipping them only there left them matchable: a
    # promoted record's `rule_ref` is `<gates-dir>/<file>.yaml`, which can collide
    # with a discovered `<root.name>/<rel>` and send it down MODIFIED, overwriting
    # `origin` and the GATES-derived enrichment with a rule-repo derivation. A
    # rule that collides this way is NEW — a separate catalogued record — which is
    # the same call the deferred fuzzy rename-match makes: never a silent
    # mis-attribution.
    reconcilable = [r for r in existing if r.get("origin") not in ("authored", "promoted")]
    # Every index is a LIST. A repo can (wrongly) reuse one UUID across two
    # files; one export file holds many records that all share its `rule_ref`;
    # byte-identical files share a hash. Collapsing any of these to a dict
    # silently drops a record and later orphans it — a wrong identity merge is
    # worse than a duplicate.
    by_uuid: dict[str, list[dict]] = {}
    by_hash: dict[str, list[dict]] = {}
    by_ref: dict[str, list[dict]] = {}
    for r in reconcilable:
        if r.get("rule_uuid"):
            by_uuid.setdefault(r["rule_uuid"], []).append(r)
        if r.get("source_hash"):
            by_hash.setdefault(r["source_hash"], []).append(r)
        if r.get("rule_ref"):
            by_ref.setdefault(r["rule_ref"], []).append(r)

    refs = [_rule_ref_of(d, rule_root) for d in discovered]
    bound: dict[int, dict] = {}
    matched_ids: set[str] = set()

    def free(candidates: list[dict], i: int) -> list[dict]:
        """Unbound candidates for discovered[i], never across differing UUIDs;
        the one at discovered[i]'s own path first."""
        uuid = discovered[i].rule_uuid
        ok = [
            c for c in candidates
            if c["id"] not in matched_ids
            and not (uuid and c.get("rule_uuid") and c["rule_uuid"] != uuid)
        ]
        return sorted(ok, key=lambda c: c.get("rule_ref") != refs[i])

    def bind(i: int, rec: dict) -> None:
        bound[i] = rec
        matched_ids.add(rec["id"])

    # Exact identities bind first, for every discovered rule, so a weaker
    # match can never claim a record that a later rule owns outright.
    known_uuid = [bool(d.rule_uuid) and d.rule_uuid in by_uuid for d in discovered]
    for i, disc in enumerate(discovered):                      # 1. UUID
        if known_uuid[i]:
            pick = free(by_uuid[disc.rule_uuid], i)
            if pick:
                bind(i, pick[0])
    for i, disc in enumerate(discovered):                      # 2. content hash
        if i not in bound and not known_uuid[i] and disc.source_hash:
            pick = free(by_hash.get(disc.source_hash, []), i)
            if pick:
                bind(i, pick[0])
    for i, _disc in enumerate(discovered):                     # 3. same path
        # A path is an identity only when exactly one record claims it.
        if i not in bound and not known_uuid[i] and refs[i]:
            same_path = by_ref.get(refs[i], [])
            if len(same_path) == 1 and free(same_path, i):
                bind(i, same_path[0])

    plan: list[PlanEntry] = []
    next_index = max(_max_index(existing), floor_index)
    for i, disc in enumerate(discovered):
        match = bound.get(i)
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

        ref = refs[i]
        merged = _merge(match, disc)
        # Unchanged = content identical AND not moved. "Not moved" only counts
        # when we could resolve a ref (a root was given); without one we can't
        # tell, so we don't spuriously flag a move.
        not_moved = (not ref) or ref == match.get("rule_ref")
        # A record catalogued with no MITRE the source now yields (e.g. before
        # ESCU `tags.mitre_attack_id` was read) is backfilled even when the
        # source file is untouched — otherwise it stays unmapped forever.
        backfill_mitre = not record_mitre(match) and bool(disc.mitre)
        # Same file, different extraction: an edited profile or a newer ADEF
        # derives other values from unchanged bytes. Keying "unchanged" on the
        # file hash alone kept the stale record until the file itself changed
        # (a trial run had to wipe and re-catalog after a profile fix).
        # A key the record lacks counts when discovery now has a value for it
        # (a field a newer ADEF derives): fill it once rather than never.
        rederived = any(
            (merged.get(k) or "") != (match[k] or "") if k in match
            else merged.get(k) not in (None, "")
            for k in _REDERIVED_FIELDS
        )
        unchanged = (
            bool(disc.source_hash)
            and disc.source_hash == match.get("source_hash")
            and not_moved
            and not backfill_mitre
            and not rederived
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
    # authored in ADEF or promoted from a hunt, which have no upstream source to
    # reconcile against. Orphaning them would mark a repo-less team's own
    # detections deprecated; they pass through untouched — see
    # docs/detection-home.md. `promoted` records point at an ATHF GATES document,
    # not a rule repo, so a sync of the rule repo must not touch them either.
    for rec in existing:
        if rec.get("origin") in ("authored", "promoted"):
            continue
        if orphan_scope is not None and not orphan_scope(rec):
            continue  # belongs to another repo in this workspace
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
            # Fresh-catalog defaults, not the stored value: that is what sync
            # writes for a MODIFIED record, and falling back to the stored
            # title/platform hid a profile edit that dropped them.
            "title": disc.title or Path(disc.path).stem,
            "rule_uuid": disc.rule_uuid,
            "source_hash": disc.source_hash,
            "query": disc.query_text,
            "platform": disc.platform or _UNKNOWN_PLATFORM,
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
    # An empty mapping is no enrichment to preserve: take the source's.
    if not record_mitre(existing):
        merged["mitre"] = list(disc.mitre)
    return merged


__all__ = ["Action", "PlanEntry", "reconcile"]
