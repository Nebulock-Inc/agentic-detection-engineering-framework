import shutil
from pathlib import Path

import pytest

from adef.core.catalog import Catalog
from adef.agents.rule_similarity import RuleSimilarityAgent
from adef.agents.rule_overlap import RuleOverlapAgent
from adef.agents.verification import VerificationAgent

FIXTURES = Path(__file__).parent / "fixtures" / "overlap_corpus"


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    (ws / "schema").mkdir(parents=True)
    for f in FIXTURES.glob("D-*.yml"):
        shutil.copy(f, ws / "catalog" / f.name)

    # Create minimal journal files for each detection
    catalog = Catalog(ws)
    for det_id, _path, data in catalog.iter_records():
        journal_path = ws / "journals" / f"{det_id}.md"
        title = data.get("title", "")
        frontmatter = f"""---
id: {det_id}
title: {title!r}
status: draft
current_stage: refine
owner: test
created: 2026-09-18T00:00:00+00:00
updated: 2026-09-18T00:00:00+00:00
rule_uuid: ''
---

(Test journal)
"""
        journal_path.write_text(frontmatter, encoding="utf-8")

    Catalog(ws).rebuild_index()
    return ws


def test_similarity_ranks_near_duplicate_above_unrelated_technique(workspace: Path):
    result = RuleSimilarityAgent().run(detection_id="D-1001", workspace=workspace, top_k=10,
                                        similarity_mode="bm25")  # pinned: no network call in this test
    ids = [c["detection_id"] for c in result["candidates"]]
    assert ids.index("D-1002") < ids.index("D-1005")


def test_overlap_classifies_the_known_pairs(workspace: Path):
    result = RuleOverlapAgent().run(detection_id="D-1001", workspace=workspace)
    by_id = {o["other_id"]: o["overlap_type"] for o in result["overlaps"]}
    assert by_id["D-1002"] == "duplicate"
    assert by_id["D-1003"] == "redundant"
    assert by_id["D-1004"] == "complementary"
    assert "D-1005" not in by_id  # different technique — never compared


def test_verification_rejects_an_engine_outside_the_closed_set(workspace: Path):
    result = VerificationAgent().run(detection_id="D-1006", workspace=workspace)
    assert result["passed"] is False
    assert "custom_sql" in result["engine_error"]


def test_verification_accepts_a_four_engine_rule_with_no_schema_declared(workspace: Path):
    # No schema/*.yml exists for `edr` in this fixture set, so the field-usage
    # check has nothing to cross-reference — engine membership is still checked
    # and must pass on its own.
    result = VerificationAgent().run(detection_id="D-1001", workspace=workspace)
    assert result["engine_error"] is None
