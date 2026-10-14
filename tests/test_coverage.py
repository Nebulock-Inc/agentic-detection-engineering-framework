"""Tests for the coverage-quality model (adef.core.coverage)."""

from __future__ import annotations

from adef.core.coverage import (
    Tier,
    build_coverage,
    navigator_layer,
    uncovered_by_tactic,
)


def _rec(tid_list, needs_review=False, data_source="src_a", status="draft"):
    return {
        "id": "D-x",
        "mitre": tid_list,
        "needs_review": needs_review,
        "data_source": data_source,
        "status": status,
    }


def test_orphaned_records_excluded_from_coverage():
    """A record whose source rule is gone (sync marks orphaned) must not count
    as coverage — else a deleted detection inflates the report."""
    live = _rec(["T1059.001"])
    orphan = {**_rec(["T1003.001"]), "orphaned": True, "status": "deprecated"}
    cov = build_coverage([live, orphan])
    assert "T1059.001" in cov.techniques        # the live rule counts
    assert "T1003.001" not in cov.techniques     # the orphaned rule does not


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


def test_totals_exclude_revoked_deprecated():
    from adef.core.attack import attack_reference

    ref = attack_reference()
    cov = build_coverage([_rec(["T1059.001"])])
    assert cov.total_techniques > 500
    # Strictly fewer than every entry → revoked/deprecated IDs were dropped.
    assert cov.total_techniques < len(ref.techniques)
    assert cov.tactic_totals  # per-tactic denominator populated


def test_tactic_gaps_reports_covered_vs_total():
    cov = build_coverage([_rec(["T1059.001"])])  # PowerShell → Execution
    gaps = {tactic: (covd, total) for tactic, covd, total in cov.tactic_gaps()}
    assert "Execution" in gaps
    covd, total = gaps["Execution"]
    assert covd == 1
    assert total > covd  # Execution has techniques we don't cover
    # Ordering: largest gap (total - covered) first.
    ordered = cov.tactic_gaps()
    diffs = [total - covd for _t, covd, total in ordered]
    assert diffs == sorted(diffs, reverse=True)


def test_uncovered_by_tactic_lists_missing():
    cov = build_coverage([_rec(["T1059.001"])])
    uncovered = uncovered_by_tactic(cov)
    exec_ids = {tid for tid, _name in uncovered.get("Execution", [])}
    assert exec_ids                      # Execution has uncovered techniques
    assert "T1059.001" not in exec_ids   # the one we cover isn't listed
    all_ids = {tid for techs in uncovered.values() for tid, _ in techs}
    assert "T1143" not in all_ids        # revoked IDs never listed as a gap


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


def test_metadata_gaps_do_not_disqualify_solid():
    """no_platform is a placement gap, not a correctness doubt — a technique
    with depth >=2 backed only by no_platform-flagged rules is SOLID (live
    finding: Splunk's public ESCU corpus read as 0/308 solid)."""
    from adef.core.coverage import Tier, build_coverage

    records = [
        {"id": "D-0001", "mitre": ["T1059.001"], "data_source": "Sysmon EventID 1",
         "needs_review": True, "review_reasons": ["no_platform"]},
        {"id": "D-0002", "mitre": ["T1059.001"], "data_source": "Sysmon EventID 1",
         "needs_review": True, "review_reasons": ["no_platform", "no_mitre"]},
    ]
    cov = build_coverage(records)
    assert cov.techniques["T1059.001"].tier is Tier.SOLID


def test_integrity_doubts_still_disqualify_solid():
    from adef.core.coverage import Tier, build_coverage

    records = [
        {"id": "D-0001", "mitre": ["T1059.001"], "data_source": "s",
         "needs_review": True, "review_reasons": ["malformed"]},
        {"id": "D-0002", "mitre": ["T1059.001"], "data_source": "s",
         "needs_review": True, "review_reasons": ["external_logic"]},
    ]
    cov = build_coverage(records)
    assert cov.techniques["T1059.001"].tier is Tier.FRAGILE


def test_legacy_boolean_flag_stays_conservative():
    """A record with needs_review=true and NO review_reasons has an unknown
    reason — keep treating it as doubted."""
    from adef.core.coverage import Tier, build_coverage

    records = [
        {"id": "D-0001", "mitre": ["T1059.001"], "data_source": "s", "needs_review": True},
        {"id": "D-0002", "mitre": ["T1059.001"], "data_source": "s", "needs_review": True},
    ]
    cov = build_coverage(records)
    assert cov.techniques["T1059.001"].tier is Tier.FRAGILE


def test_the_workspace_snapshot_is_what_gets_scored(tmp_path, monkeypatch):
    """`--workspace X` must score against X's ATT&CK snapshot, not the shipped one.

    Both functions took no workspace and called `attack_reference()` zero-arg,
    which resolves from `$ADEF_WORKSPACE` or the package copy. So
    `adef coverage --workspace X`, after `adef attack refresh` wrote a newer
    snapshot into X, reported the *shipped* technique universe: a wrong
    "N of M" denominator, a gap list naming techniques X doesn't have, and any
    technique X knows about but the shipped copy doesn't counted as fictional
    coverage.

    `T9999` is the lever: fiction to the shipped snapshot, real to this one. The
    env var is pointed somewhere else entirely so a passing result can only come
    from the argument — with `$ADEF_WORKSPACE` set to the same path, the zero-arg
    call would succeed too and the test would prove nothing.
    """
    import json

    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "attack").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(elsewhere))

    ws = tmp_path / "ws"
    (ws / "attack").mkdir(parents=True)
    (ws / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-local",
                "tactics": {"execution": "Execution"},
                "techniques": {
                    "T9999": {"name": "Local Only", "tactics": ["execution"]},
                    "T8888": {"name": "Uncovered Local", "tactics": ["execution"]},
                },
            }
        ),
        encoding="utf-8",
    )

    cov = build_coverage([_rec(["T9999"])], ws)

    # Covered, not fictional — the shipped snapshot would say the opposite.
    assert "T9999" in cov.techniques, cov.invalid_mappings
    assert cov.invalid_mappings == {}
    # And the denominator is this snapshot's universe (2), not the shipped ~800.
    assert cov.total_techniques == 2, cov.total_techniques
    assert cov.tactic_totals == {"Execution": 2}

    # The gap list enumerates the universe, so it needs the same snapshot.
    gaps = uncovered_by_tactic(cov, ws)
    assert gaps == {"Execution": [("T8888", "Uncovered Local")]}, gaps
