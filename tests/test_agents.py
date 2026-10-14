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
        metrics={"fp_ratio": 0.0, "weekly_signal_volume": 0, "window_days": 7, "days_since_true_positive": 120},
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
        performance={"weekly_signal_volume": 0, "window_days": 7, "days_since_true_positive": 200},
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


def test_wired_wrappers_exported():
    # The four wrappers ADEF actually orchestrates (3 refine + performance
    # metrics). The other eight speculative slots were removed 2026-07-22.
    assert len(wrappers_pkg.ALL_WRAPPERS) == 4


# --- A verdict needs data behind it (seen in a trial run): with no
# inputs both agents returned "healthy"/"within normal band".

def test_deprecation_with_no_inputs_has_no_verdict():
    from adef.agents.deprecation_recommender import DeprecationRecommenderAgent

    rec = DeprecationRecommenderAgent().run("D-0001")
    assert rec.verdict == "insufficient_data"
    assert "healthy" not in rec.rationale.lower()


def test_deprecation_keep_names_what_it_did_not_check():
    from adef.agents.deprecation_recommender import DeprecationRecommenderAgent

    rec = DeprecationRecommenderAgent().run(
        "D-0001", performance={"fp_ratio": 0.1, "weekly_signal_volume": 4})
    assert rec.verdict == "keep"
    assert "overlap" in rec.rationale and "findings" in rec.rationale  # named as not provided
    assert "manageable" not in rec.rationale  # overlap was never supplied


def test_a_zero_metric_is_data_not_absence():
    from adef.agents.deprecation_recommender import DeprecationRecommenderAgent

    rec = DeprecationRecommenderAgent().run("D-0001", performance={"weekly_signal_volume": 0})
    assert rec.verdict != "insufficient_data"


def test_tune_with_no_metrics_suggests_getting_data():
    from adef.agents.tune_recommender import TuneRecommenderAgent

    kinds = [s.kind for s in TuneRecommenderAgent().run("D-0001", metrics={}).suggestions]
    assert kinds == ["insufficient-data"]


# --------------------------------------------------------------------------- #
# Absent is not zero
#
# `tuning_metrics` omits a key when the counts behind it weren't supplied,
# precisely so a consumer can tell "this detection is silent" from "nobody told
# us the volume". Both decision tables then defaulted every absent key to
# `0.0`, which undid that one function later — and both gates pass on a SINGLE
# present key, so one real number was enough to put fabricated ones into the
# verdict. The partial document below is what `tuning_metrics` actually returns
# for a `metrics` row carrying only `last_true_positive_at` (valid: row keys
# are deliberately not whitelisted at ingest).
# --------------------------------------------------------------------------- #
_ONLY_STALENESS = {"days_since_true_positive": 282.0}


def test_tune_does_not_claim_silence_from_an_unsupplied_volume():
    from adef.agents.tune_recommender import TuneRecommenderAgent

    suggestions = TuneRecommenderAgent().run("D-0001", metrics=_ONLY_STALENESS).suggestions
    kinds = [s.kind for s in suggestions]
    assert "deprecate" not in kinds, [s.rationale for s in suggestions]
    # `hold`, not `insufficient-data`: one metric *was* supplied, so the gate
    # is right to let it through — the bug was what happened afterwards.
    assert kinds == ["hold"], kinds
    assert "No signals in" not in " ".join(s.rationale for s in suggestions)


def test_tune_still_fires_on_a_volume_that_was_measured_as_zero():
    """The other side of the same line: an explicit 0 is a finding.

    Asserted together with the case above because a guard that rejects absence
    is trivially satisfiable by a guard that rejects zero as well — and that
    would delete the silence arm entirely rather than fix it.
    """
    from adef.agents.tune_recommender import TuneRecommenderAgent

    metrics = {**_ONLY_STALENESS, "weekly_signal_volume": 0.0, "window_days": 7.0}
    suggestions = TuneRecommenderAgent().run("D-0001", metrics=metrics).suggestions
    assert [s.kind for s in suggestions] == ["deprecate"], suggestions
    assert "282 days" in suggestions[0].rationale


def test_deprecation_does_not_retire_on_two_invented_conjuncts():
    """`run_evolve_chain` never supplies `findings`, so `high_quality_findings
    == 0` was *always* true on the CLI path. With a defaulted volume as well,
    two of the silence arm's three conjuncts were fabricated and the verdict
    was "Silent for 180+ days, no high-quality findings ever — retire." on a
    detection whose only ingested number was a timestamp."""
    from adef.agents.deprecation_recommender import DeprecationRecommenderAgent

    rec = DeprecationRecommenderAgent().run("D-0001", performance=_ONLY_STALENESS)
    assert rec.verdict == "keep", rec.rationale
    assert "retire" not in rec.rationale
    # The `keep` branch already says which signals were missing — that is the
    # honest answer the fabricated zeros were talking over.
    assert "findings" in rec.rationale and "overlap" in rec.rationale


def test_deprecation_still_retires_when_all_three_signals_are_supplied():
    from adef.agents.deprecation_recommender import DeprecationRecommenderAgent

    rec = DeprecationRecommenderAgent().run(
        "D-0001",
        performance={"weekly_signal_volume": 0, "window_days": 7, "days_since_true_positive": 400},
        findings={"high_quality_findings": 0},
    )
    assert rec.verdict == "deprecate", rec.rationale


def test_deprecation_does_not_retire_on_overlap_with_findings_unsupplied():
    """The second `deprecate` arm, same defect: `overlap_score >= 0.85 and
    high_quality_findings == 0` fired on a real overlap score plus a findings
    count nobody provided — "zero high-quality findings" about an input ADEF
    has no producer for at all."""
    from adef.agents.deprecation_recommender import DeprecationRecommenderAgent

    rec = DeprecationRecommenderAgent().run("D-0001", overlap={"score": 0.9})
    assert rec.verdict != "deprecate", rec.rationale
    assert "zero high-quality findings" not in rec.rationale


def test_deprecation_retires_a_measured_silence_without_findings():
    """The Evolve chain never supplies findings. Requiring them made
    `deprecate` unreachable from `adef detection evolve`."""
    rec = DeprecationRecommenderAgent().run(
        "D-0001", performance={"weekly_signal_volume": 0, "window_days": 7, "days_since_true_positive": 200}
    )
    assert rec.verdict == "deprecate", rec.rationale
    assert "not provided" in rec.rationale


def test_supplied_findings_still_veto_the_silence_arm():
    rec = DeprecationRecommenderAgent().run(
        "D-0001",
        performance={"weekly_signal_volume": 0, "window_days": 7, "days_since_true_positive": 200},
        findings={"high_quality_findings": 2},
    )
    assert rec.verdict != "deprecate", rec.rationale


def test_a_configured_metrics_collector_wins_over_stored_health(monkeypatch, tmp_path):
    """The Evolve chain always passes `metrics=`, so a configured collector
    was never called on the CLI path."""
    import sys
    import types

    from adef.core.journal import Journal
    from adef.orchestration.evolve_chain import run_evolve_chain

    mod = types.ModuleType("fake_collector")

    class Collector:
        def run(self, detection_id):
            return {"weekly_signal_volume": 0, "window_days": 7, "days_since_true_positive": 365}

    mod.Collector = Collector
    monkeypatch.setitem(sys.modules, "fake_collector", mod)
    monkeypatch.setenv("ADEF_WRAPPER_METRICS", "fake_collector:Collector")

    journals = tmp_path / "journals"
    journal = Journal(journals)
    journal.create("D-0001", title="t")
    summary = run_evolve_chain(journal, "D-0001", workspace=tmp_path)

    assert summary["deprecation"]["result"].verdict == "deprecate"
    assert "ADEF_WRAPPER_METRICS" in (journals / "D-0001.md").read_text(encoding="utf-8")


def test_an_unusable_findings_value_does_not_unlock_the_silence_arm():
    rec = DeprecationRecommenderAgent().run(
        "D-0001",
        performance={"weekly_signal_volume": 0, "window_days": 7, "days_since_true_positive": 200},
        findings={"high_quality_findings": -3},
    )
    assert rec.verdict != "deprecate", rec.rationale


def test_collector_only_health_block_does_not_claim_nothing_was_ingested(monkeypatch, tmp_path):
    import sys
    import types

    from adef.core.journal import Journal
    from adef.orchestration.evolve_chain import run_evolve_chain

    mod = types.ModuleType("fake_collector2")
    mod.Collector = type("Collector", (), {"run": lambda self, detection_id: {"fp_ratio": 0.1}})
    monkeypatch.setitem(sys.modules, "fake_collector2", mod)
    monkeypatch.setenv("ADEF_WRAPPER_METRICS", "fake_collector2:Collector")

    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="t")
    run_evolve_chain(journal, "D-0001", workspace=tmp_path)
    text = (tmp_path / "journals" / "D-0001.md").read_text(encoding="utf-8")
    health = text.split("### Evolve / Health", 1)[1].split("\n### ", 1)[0]
    assert "ADEF_WRAPPER_METRICS" in health
    assert "nothing to work from" not in health


def test_a_failing_collector_is_reported_not_shown_as_empty(monkeypatch, tmp_path):
    from adef.core.journal import Journal
    from adef.orchestration.evolve_chain import run_evolve_chain

    monkeypatch.setenv("ADEF_WRAPPER_METRICS", "no_such_module_xyz:Collector")
    journal = Journal(tmp_path / "journals")
    journal.create("D-0001", title="t")
    run_evolve_chain(journal, "D-0001", workspace=tmp_path)
    text = (tmp_path / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert "ADEF_WRAPPER_METRICS failed" in text
    assert "returned nothing" not in text


def test_the_deprecated_metrics_name_warns_once(monkeypatch, capsys, tmp_path):
    import sys
    import types

    from adef.agents.tune_recommender import TuneRecommenderAgent

    mod = types.ModuleType("fake_collector3")
    mod.Collector = type("Collector", (), {"run": lambda self, detection_id: {"fp_ratio": 0.1}})
    monkeypatch.setitem(sys.modules, "fake_collector3", mod)
    monkeypatch.delenv("ADEF_WRAPPER_METRICS", raising=False)
    monkeypatch.setenv("ADEF_WRAPPER_PERFORMANCE_METRICS", "fake_collector3:Collector")
    TuneRecommenderAgent().run("D-0001", workspace=tmp_path)
    assert capsys.readouterr().err.count("is deprecated") == 1


def test_a_short_window_of_silence_does_not_retire():
    """Zero signals in one day says nothing about last week."""
    perf = {"weekly_signal_volume": 0, "window_days": 1, "days_since_true_positive": 200}
    assert DeprecationRecommenderAgent().run("D-0001", performance=perf).verdict != "deprecate"
    kinds = {s.kind for s in TuneRecommenderAgent().run("D-0001", metrics=perf).suggestions}
    assert "deprecate" not in kinds


def test_silence_with_no_window_length_does_not_retire():
    """A collector that omits `window_days` can't prove the silence was long."""
    perf = {"weekly_signal_volume": 0, "days_since_true_positive": 200}
    assert DeprecationRecommenderAgent().run("D-0001", performance=perf).verdict != "deprecate"
