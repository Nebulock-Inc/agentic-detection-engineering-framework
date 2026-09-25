# tests/test_agent_agreement.py
from pathlib import Path

import pytest
import yaml

from adef.agents.rule_overlap import RuleOverlapAgent
from adef.agents.rule_similarity import RuleSimilarityAgent
from adef.core.catalog import Catalog, CatalogRecord
from adef.core.journal import Journal


def _rec(rid: str, title: str, query: str) -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=["T1218.005"],
    )


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    """D-0001 has both artifacts; D-0002 is catalogued with its journal deleted."""
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat, journal = Catalog(w), Journal(w / "journals")
    q = "process.name = 'mshta.exe' and parent.name = 'excel.exe'"
    for rid, title in [("D-0001", "mshta child process"), ("D-0002", "mshta spawning child")]:
        cat.write_raw(w / "catalog" / f"{rid}.yml", _rec(rid, title, q).to_yaml_dict())
        journal.create(detection_id=rid, title=title)
    cat.rebuild_index()
    (w / "journals" / "D-0002.md").unlink()      # the divergence case
    return w


def test_similarity_sees_a_catalogued_rule_whose_journal_is_missing(ws: Path):
    # Before this change Similarity returned nothing here while Overlap
    # reported D-0002 as a near-duplicate, in the same Refine run.
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=5, similarity_mode="bm25"
    )
    assert "D-0002" in [c["detection_id"] for c in result["candidates"]]


def test_overlap_still_reports_it(ws: Path):
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert "D-0002" in [o["other_id"] for o in result["overlaps"]]


def test_both_agents_resolve_the_same_membership(ws: Path):
    from adef.core.corpus import build_corpus

    expected = {e.detection_id for e in build_corpus(ws)}
    assert expected == {"D-0001", "D-0002"}


def test_overlap_skips_entries_with_no_query(ws: Path):
    # A journal-only draft is in the corpus but has no logic to compare.
    # NB: this does not reach the query filter — see the two tests below,
    # which do. D-0003 is journal-only, so it has no `mitre` and is excluded
    # by technique-cluster membership several steps before the filter ever
    # runs; kept anyway because "a journal-only draft never shows up as an
    # overlap" is still a real property worth asserting.
    Journal(ws / "journals").create(detection_id="D-0003", title="draft idea")
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert "D-0003" not in [o["other_id"] for o in result["overlaps"]]


def test_overlap_skips_a_clustered_record_with_no_query(tmp_path: Path):
    """A catalog record that DOES share the target's MITRE technique reaches
    the technique cluster (`by_technique` is built from `mitre` alone, in
    `Catalog.rebuild_index`, regardless of `query`) but carries no query, so
    `classify_pair` has nothing to compare. This is the case the filter
    exists for. Confirmed to fail if the filter (`... and (e.record.get
    ("query") or "")`) is deleted from `rule_overlap.py`, leaving only
    `e.record is not None`: D-0002 then reaches `classify_pair` as a
    zero-confidence "complementary" overlap and the assertion below fails.
    """
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat = Catalog(w)
    cat.write_raw(
        w / "catalog" / "D-0001.yml",
        _rec("D-0001", "mshta child process", "process.name = 'mshta.exe' and parent.name = 'excel.exe'")
        .to_yaml_dict(),
    )
    no_query = CatalogRecord(
        id="D-0002", title="mshta spawning child, logic TBD", rule_ref="r/D-0002.yml",
        original_path="/tmp/D-0002.yml", platform="windows", kind="atomic", engine="sigma",
        format="sigma", query="", mitre=["T1218.005"],
    )
    cat.write_raw(w / "catalog" / "D-0002.yml", no_query.to_yaml_dict())
    cat.rebuild_index()

    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=w)
    assert "D-0002" not in [o["other_id"] for o in result["overlaps"]]


def test_overlap_skips_a_clustered_record_that_parses_to_an_empty_dict(tmp_path: Path):
    """A catalog YAML with no content (e.g. an all-comment file) parses to
    `record == {}` via `yaml.safe_load(...) or {}` in `Catalog.iter_records`
    — `record is not None` alone would admit it (`{}` is not `None`). An
    empty dict carries no `mitre`, so `Catalog.rebuild_index` can never
    legitimately place it in a technique cluster on its own; the INDEX is
    hand-edited below to put it there anyway, isolating the query filter's
    behaviour for this exact shape (pins the manual probe run during the
    prior review round, this time inside the suite).

    `Catalog.iter_records` only globs `D-*.yml` (the hyphen is required to
    even be discovered), and its id-less fallback is `path.stem.split("-")
    [0]` — for any `D-<anything>.yml` stem that always collapses to the
    single character `"D"` (`"D-9999".split("-")` is `["D", "9999"]`). That
    collapse is a pre-existing quirk of that fallback, unrelated to this
    task's filter, so the empty-dict record here is addressed as `"D"`
    rather than as something `D-XXXX`-shaped.
    """
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat = Catalog(w)
    cat.write_raw(
        w / "catalog" / "D-0001.yml",
        _rec("D-0001", "mshta child process", "process.name = 'mshta.exe' and parent.name = 'excel.exe'")
        .to_yaml_dict(),
    )
    (w / "catalog" / "D-9999.yml").write_text("# no content\n")
    cat.rebuild_index()

    index_path = w / "catalog" / "INDEX.yml"
    index = yaml.safe_load(index_path.read_text()) or {}
    index.setdefault("by_technique", {}).setdefault("T1218.005", []).append("D")
    index_path.write_text(yaml.safe_dump(index, sort_keys=False))

    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=w)
    assert "D" not in [o["other_id"] for o in result["overlaps"]]
