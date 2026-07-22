"""Tests for the sync reconciliation cascade (adef/core/reconcile.py)."""

from __future__ import annotations

from pathlib import Path

from adef.core.rule_discovery import DiscoveredRule
from adef.core.reconcile import Action, reconcile


def _existing(id, *, uuid="", source_hash="", rule_ref="", title="", query="",
              mitre=None, status="draft", owner="", origin="catalogued"):
    """A minimal existing-record dict as read from the catalog."""
    return {
        "id": id, "rule_uuid": uuid, "source_hash": source_hash,
        "rule_ref": rule_ref, "title": title, "query": query,
        "mitre": mitre or [], "status": status, "owner": owner, "origin": origin,
    }


def _disc(*, uuid="", source_hash="deadbeef", path="repo/r.yml", title="T", query="q"):
    return DiscoveredRule(
        path=Path(path), format="sigma", query_text=query, title=title,
        rule_uuid=uuid, source_hash=source_hash,
    )


def test_uuid_match_is_unchanged_or_modified():
    existing = [_existing("D-0001", uuid="abc", source_hash="h1", rule_ref="repo/r.yml")]
    # same uuid, same hash → unchanged
    plan = reconcile(existing, [_disc(uuid="abc", source_hash="h1")])
    assert plan[0].action is Action.UNCHANGED
    assert plan[0].detection_id == "D-0001"
    # same uuid, new hash → modified
    plan = reconcile(existing, [_disc(uuid="abc", source_hash="h2")])
    assert plan[0].action is Action.MODIFIED
    assert plan[0].detection_id == "D-0001"


def test_uuid_match_survives_rename(tmp_path):
    # Stored ref is <root.name>/old.yml; the file is now at <root>/new.yml.
    (tmp_path / "new.yml").write_text("x")
    existing = [_existing(
        "D-0001", uuid="abc", source_hash="h1",
        rule_ref=f"{tmp_path.name}/old.yml",
    )]
    disc = _disc(uuid="abc", source_hash="h1", path=str(tmp_path / "new.yml"))
    plan = reconcile(existing, [disc], rule_root=tmp_path)
    # Same uuid → still D-0001; moved (ref changed) → modified even if content same.
    assert plan[0].action is Action.MODIFIED
    assert plan[0].detection_id == "D-0001"


def test_hash_match_without_uuid_is_unchanged():
    existing = [_existing("D-0002", source_hash="h9", rule_ref="repo/a.yml")]
    plan = reconcile(existing, [_disc(source_hash="h9", path="repo/a.yml")])
    assert plan[0].action is Action.UNCHANGED
    assert plan[0].detection_id == "D-0002"


def test_same_path_new_hash_is_modified(tmp_path):
    # Same file (path matches stored ref), content changed, no UUID → modified.
    (tmp_path / "b.yml").write_text("x")
    existing = [_existing("D-0003", source_hash="old", rule_ref=f"{tmp_path.name}/b.yml")]
    disc = _disc(source_hash="new", path=str(tmp_path / "b.yml"))
    plan = reconcile(existing, [disc], rule_root=tmp_path)
    assert plan[0].action is Action.MODIFIED
    assert plan[0].detection_id == "D-0003"


def test_no_match_is_new_with_fresh_id():
    existing = [_existing("D-0005", uuid="x", source_hash="h", rule_ref="repo/x.yml")]
    plan = reconcile(existing, [_disc(uuid="brand-new", path="repo/z.yml")])
    assert plan[0].action is Action.NEW
    assert plan[0].detection_id == "D-0006"  # next after max existing


def test_missing_source_is_orphaned():
    existing = [_existing("D-0007", uuid="gone", source_hash="h", rule_ref="repo/gone.yml")]
    plan = reconcile(existing, [])  # rule no longer in the repo
    assert plan[0].action is Action.ORPHANED
    assert plan[0].detection_id == "D-0007"


def test_authored_record_never_orphaned():
    """A rule authored in ADEF has no upstream — sync must leave it untouched,
    not orphan it (ISA 2026-07-22, "ADEF as a detection home")."""
    existing = [_existing("D-0008", origin="authored", title="Authored in ADEF")]
    plan = reconcile(existing, [])  # no source repo match — would orphan a catalogued rule
    # No plan entry at all for the authored record → nothing written, still alive.
    assert plan == []


def test_enrichment_preserved_on_modified():
    existing = [_existing(
        "D-0008", uuid="e", source_hash="old", rule_ref="repo/e.yml",
        mitre=["T1059"], status="ready", owner="alice",
    )]
    plan = reconcile(existing, [_disc(uuid="e", source_hash="new", title="New Title")])
    entry = plan[0]
    assert entry.action is Action.MODIFIED
    # enrichment carried over
    assert entry.merged["mitre"] == ["T1059"]
    assert entry.merged["status"] == "ready"
    assert entry.merged["owner"] == "alice"
    # derived refreshed
    assert entry.merged["title"] == "New Title"
    assert entry.merged["source_hash"] == "new"


def test_counts_summary():
    existing = [
        _existing("D-0001", uuid="a", source_hash="h1", rule_ref="repo/a.yml"),
        _existing("D-0002", uuid="b", source_hash="h2", rule_ref="repo/b.yml"),
    ]
    discovered = [
        _disc(uuid="a", source_hash="h1", path="repo/a.yml"),   # unchanged
        _disc(uuid="b", source_hash="CHANGED", path="repo/b.yml"),  # modified
        _disc(uuid="c", source_hash="h3", path="repo/c.yml"),   # new
    ]
    plan = reconcile(existing, discovered)
    from collections import Counter
    counts = Counter(p.action for p in plan)
    assert counts[Action.UNCHANGED] == 1
    assert counts[Action.MODIFIED] == 1
    assert counts[Action.NEW] == 1
    assert counts[Action.ORPHANED] == 0
