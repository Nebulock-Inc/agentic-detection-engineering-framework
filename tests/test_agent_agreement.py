# tests/test_agent_agreement.py
from pathlib import Path

import pytest

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
    Journal(ws / "journals").create(detection_id="D-0003", title="draft idea")
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert "D-0003" not in [o["other_id"] for o in result["overlaps"]]
