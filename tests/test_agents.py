"""Unit tests for the four ADEF-native agents + wrappers exposure."""

from __future__ import annotations


from adef.agents.deprecation_recommender import DeprecationRecommenderAgent
from adef.agents.hypothesis_from_intel import HypothesisFromIntelAgent
from adef.agents.tune_recommender import TuneRecommenderAgent
from adef.agents import wrappers as wrappers_pkg


def test_hypothesis_extracts_mitre_ids():
    draft = HypothesisFromIntelAgent().run("Adversary uses T1059.001 and T1218.005")
    assert "T1059.001" in draft.candidate_mitre
    assert "T1218.005" in draft.candidate_mitre


def test_hypothesis_classifies_data_sources():
    draft = HypothesisFromIntelAgent().run("powershell + okta + cloudtrail + DNS beacon")
    sources = draft.candidate_data_sources
    assert "EDR / process_create" in sources
    assert "Identity / authentication logs" in sources
    assert "Cloud control plane / CloudTrail-like" in sources
    assert "Network / DNS / proxy" in sources


def test_hypothesis_url_recorded_as_intel_source():
    draft = HypothesisFromIntelAgent().run("https://example.com/cti/report")
    assert "https://example.com/cti/report" in draft.intel_sources


def test_tune_recommender_high_fp_high_volume():
    rec = TuneRecommenderAgent().run(
        "D-0001",
        metrics={"fp_ratio": 0.96, "weekly_signal_volume": 50, "days_since_true_positive": 7},
    )
    kinds = {s.kind for s in rec.suggestions}
    assert "narrow-filter" in kinds


def test_tune_recommender_silent_detection():
    rec = TuneRecommenderAgent().run(
        "D-0001",
        metrics={"fp_ratio": 0.0, "weekly_signal_volume": 0, "days_since_true_positive": 120},
    )
    kinds = {s.kind for s in rec.suggestions}
    assert "deprecate" in kinds


def test_tune_recommender_healthy_returns_hold():
    rec = TuneRecommenderAgent().run(
        "D-0001",
        metrics={"fp_ratio": 0.05, "weekly_signal_volume": 8, "days_since_true_positive": 3},
    )
    kinds = {s.kind for s in rec.suggestions}
    assert "hold" in kinds


def test_deprecation_silent_with_no_findings():
    rec = DeprecationRecommenderAgent().run(
        "D-0001",
        performance={"weekly_signal_volume": 0, "days_since_true_positive": 200},
        findings={"high_quality_findings": 0},
    )
    assert rec.verdict == "deprecate"


def test_deprecation_high_overlap_with_no_findings():
    rec = DeprecationRecommenderAgent().run(
        "D-0001",
        performance={"weekly_signal_volume": 5, "days_since_true_positive": 10},
        overlap={"score": 0.9},
        findings={"high_quality_findings": 0},
    )
    assert rec.verdict == "deprecate"


def test_deprecation_high_fp_recommends_tune():
    rec = DeprecationRecommenderAgent().run(
        "D-0001",
        performance={"fp_ratio": 0.95, "weekly_signal_volume": 30, "days_since_true_positive": 3},
        overlap={"score": 0.2},
        findings={"high_quality_findings": 1},
    )
    assert rec.verdict == "tune"


def test_deprecation_healthy_keeps():
    rec = DeprecationRecommenderAgent().run(
        "D-0001",
        performance={"fp_ratio": 0.1, "weekly_signal_volume": 5, "days_since_true_positive": 2},
        overlap={"score": 0.1},
        findings={"high_quality_findings": 4},
    )
    assert rec.verdict == "keep"


def test_twelve_wrappers_exported():
    assert len(wrappers_pkg.ALL_WRAPPERS) == 12
