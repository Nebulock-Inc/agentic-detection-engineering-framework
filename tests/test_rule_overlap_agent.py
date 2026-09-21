# tests/test_rule_overlap_agent.py
from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord
from adef.agents.rule_overlap import RuleOverlapAgent, classify_pair


def _rec(rid: str, title: str, query: str, mitre: list[str], data_source: str = "wineventlog") -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"rules/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=mitre, data_source=data_source,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat = Catalog(ws)
    records = [
        _rec("D-0001", "mshta child - v1", "process.name = 'mshta.exe' and parent = 'winword.exe'",
             ["T1218.005"]),
        _rec("D-0002", "mshta child - near dup", "process.name='mshta.exe' AND parent='winword.exe'",
             ["T1218.005"]),
        _rec("D-0003", "mshta child - narrower", "process.name = 'mshta.exe' and parent = 'winword.exe' and user = 'admin'",
             ["T1218.005"]),
        _rec("D-0004", "mshta via network beacon", "network.dest_port = 4444 and process.name = 'mshta.exe'",
             ["T1218.005"]),
        _rec("D-0005", "AWS console login", "event.name = 'ConsoleLogin'", ["T1078.004"],
             data_source="cloudtrail"),
    ]
    for rec in records:
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    cat.rebuild_index()
    return ws


def test_classify_pair_exact_duplicate():
    a = _rec("A", "t", "process.name='mshta.exe'", []).to_yaml_dict()
    b = _rec("B", "t", "PROCESS.NAME = 'mshta.exe'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "duplicate"
    assert overlap.confidence == 1.0


def test_classify_pair_redundant_substring():
    a = _rec("A", "t", "process.name='mshta.exe' and parent='winword.exe'", []).to_yaml_dict()
    b = _rec("B", "t", "process.name='mshta.exe' and parent='winword.exe' and user='admin'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"


def test_classify_pair_redundant_substring_reversed():
    # record_a's query is the longer/superset text, record_b's is the substring —
    # exercises the `norm_b in norm_a` branch (mirror of the substring test above,
    # which exercises `norm_a in norm_b`). Per classify_pair's own semantics, the
    # superset-query rule (A here) is the narrower one, since it fires on a subset
    # of what the shorter query (B) already covers.
    a = _rec("A", "t", "process.name='mshta.exe' and parent='winword.exe' and user='admin'", []).to_yaml_dict()
    b = _rec("B", "t", "process.name='mshta.exe' and parent='winword.exe'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"
    assert overlap.reasoning == (
        "A's query is a strict superset of B's predicate — "
        "A fires on a subset of what B already covers"
    )


def test_classify_pair_redundant_substring_parenthesized():
    # detect-vault's WHERE-only predicate convention wraps the whole condition
    # in outer parens — the paren-stripping fix in classify_pair must still
    # recognize the substring relation once both sides are unwrapped.
    a = _rec("A", "t", "(process.name='mshta.exe' and parent='winword.exe')", []).to_yaml_dict()
    b = _rec("B", "t", "(process.name='mshta.exe' and parent='winword.exe' and user='admin')", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"
    assert overlap.reasoning == (
        "B's query is a strict superset of A's predicate — "
        "B fires on a subset of what A already covers"
    )


def test_classify_pair_redundant_substring_parenthesized_reversed():
    # Mirror of the above: record_a's wrapped query is the superset, record_b's
    # wrapped query is the substring — exercises the `norm_b_stripped in
    # norm_a_stripped` branch with parenthesized detect-vault-shaped queries.
    a = _rec("A", "t", "(process.name='mshta.exe' and parent='winword.exe' and user='admin')", []).to_yaml_dict()
    b = _rec("B", "t", "(process.name='mshta.exe' and parent='winword.exe')", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"
    assert overlap.reasoning == (
        "A's query is a strict superset of B's predicate — "
        "A fires on a subset of what B already covers"
    )


def test_classify_pair_rejects_adjacent_numeric_literal_false_positive():
    # CodeRabbit PR #1: "event.code=1" is a raw Python substring of
    # "event.code=10", but the two are unrelated comparisons, not a superset
    # relation. Must classify as complementary (or duplicate/near-duplicate on
    # ratio), never "redundant" via the substring path.
    a = _rec("A", "t", "event.code=1", []).to_yaml_dict()
    b = _rec("B", "t", "event.code=10", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type != "redundant"


def test_classify_pair_complementary_different_logic():
    a = _rec("A", "t", "process.name='mshta.exe' and parent='winword.exe'", []).to_yaml_dict()
    b = _rec("B", "t", "network.dest_port=4444 and process.name='mshta.exe'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "complementary"


def test_agent_scopes_to_same_technique_cluster(workspace: Path):
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=workspace)
    other_ids = {o["other_id"] for o in result["overlaps"]}
    assert "D-0005" not in other_ids  # different technique — never compared
    assert {"D-0002", "D-0003", "D-0004"} <= other_ids


def test_agent_reports_near_duplicate_and_redundant(workspace: Path):
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=workspace)
    by_id = {o["other_id"]: o for o in result["overlaps"]}
    assert by_id["D-0002"]["overlap_type"] == "duplicate"
    assert by_id["D-0003"]["overlap_type"] == "redundant"
    assert by_id["D-0004"]["overlap_type"] == "complementary"


# --- Wrapper dispatch (native by default; ADEF_WRAPPER_RULE_OVERLAP overrides) ---

def test_wrapper_runs_native_agent_when_binding_unset(workspace: Path, monkeypatch):
    monkeypatch.delenv("ADEF_WRAPPER_RULE_OVERLAP", raising=False)
    from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper

    result = RuleOverlapWrapper().run(detection_id="D-0001", workspace=workspace)
    assert result["detection_id"] == "D-0001"
    assert "overlaps" in result["result"]


def test_wrapper_raises_when_binding_set_but_unimportable(workspace: Path, monkeypatch):
    monkeypatch.setenv("ADEF_WRAPPER_RULE_OVERLAP", "not_a_real_module:NotARealClass")
    from adef.agents.wrappers import WrapperUnavailable
    from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper

    with pytest.raises(WrapperUnavailable):
        RuleOverlapWrapper().run(detection_id="D-0001", workspace=workspace)


def test_wrapper_propagates_no_catalog_record(workspace: Path, monkeypatch):
    """A journal-only detection is NOT "wrapper unavailable" — the wrapper must
    let the distinct type through so refine_chain can say what's actually true."""
    monkeypatch.delenv("ADEF_WRAPPER_RULE_OVERLAP", raising=False)
    from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper
    from adef.core.catalog import NoCatalogRecordError

    with pytest.raises(NoCatalogRecordError, match="D-9999"):
        RuleOverlapWrapper().run(detection_id="D-9999", workspace=workspace)
