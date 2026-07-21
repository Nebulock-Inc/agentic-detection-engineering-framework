"""Tests for the coverage-quality model (adef.core.coverage)."""

from __future__ import annotations

from adef.core.coverage import Tier, build_coverage, navigator_layer


def _rec(tid_list, needs_review=False, data_source="src_a", status="draft"):
    return {
        "id": "D-x",
        "mitre": tid_list,
        "needs_review": needs_review,
        "data_source": data_source,
        "status": status,
    }


def test_solid_technique_needs_depth_and_a_clean_detection():
    recs = [
        _rec(["T1059.001"], needs_review=False, data_source="edr"),
        _rec(["T1059.001"], needs_review=True, data_source="edr"),
    ]
    cov = build_coverage(recs)
    t = cov.techniques["T1059.001"]
    assert t.tier is Tier.SOLID
    assert t.depth == 2


def test_single_detection_is_fragile_even_if_clean():
    recs = [_rec(["T1003.001"], needs_review=False)]
    cov = build_coverage(recs)
    assert cov.techniques["T1003.001"].tier is Tier.FRAGILE


def test_all_needs_review_is_fragile_even_with_depth():
    recs = [
        _rec(["T1071"], needs_review=True, data_source="proxy"),
        _rec(["T1071"], needs_review=True, data_source="proxy"),
    ]
    cov = build_coverage(recs)
    assert cov.techniques["T1071"].tier is Tier.FRAGILE


def test_invalid_technique_is_not_counted_as_coverage():
    recs = [_rec(["T9999"], needs_review=False)]  # not in the reference
    cov = build_coverage(recs)
    # A fictional ID doesn't create a covered technique.
    assert "T9999" not in cov.techniques
    assert cov.invalid_mappings  # but it's surfaced


def test_single_point_of_failure_list():
    recs = [
        _rec(["T1003.001"], data_source="edr"),
        _rec(["T1059.001"], data_source="edr"),
        _rec(["T1059.001"], data_source="edr"),
    ]
    cov = build_coverage(recs)
    spof = set(cov.single_detection_techniques())
    assert "T1003.001" in spof
    assert "T1059.001" not in spof  # depth 2


def test_source_concentration():
    # 3 techniques, all riding one source → 100% single-source dependent.
    recs = [
        _rec(["T1003.001"], data_source="thrunt"),
        _rec(["T1059.001"], data_source="thrunt"),
        _rec(["T1071"], data_source="thrunt"),
    ]
    cov = build_coverage(recs)
    assert cov.dominant_source == ("thrunt", 3)
    # techniques whose every detection is one source
    assert set(cov.single_source_techniques()) == {"T1003.001", "T1059.001", "T1071"}


def test_navigator_layer_scores_by_tier():
    recs = [
        _rec(["T1059.001"], needs_review=False, data_source="edr"),
        _rec(["T1059.001"], needs_review=True, data_source="edr"),
        _rec(["T1003.001"], needs_review=False),  # fragile (depth 1)
    ]
    cov = build_coverage(recs)
    layer = navigator_layer(cov, name="test")
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1059.001"] == 100  # solid
    assert scores["T1003.001"] == 50   # fragile
    assert layer["domain"] == "enterprise-attack"
    # every technique carries a why-comment
    assert all(t.get("comment") for t in layer["techniques"])
