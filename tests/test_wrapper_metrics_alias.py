"""ADEF_WRAPPER_PERFORMANCE_METRICS -> ADEF_WRAPPER_METRICS, old name kept as a
deprecated alias (decided 2026-10-08: v1.0.0 shipped with the
old name, so it can't be dropped outright)."""

import sys
import types

import pytest

from adef.agents.wrappers import PerformanceMetricsWrapper, WrapperUnavailable


class _Upstream:
    def run(self, detection_id, **ctx):
        return {"fp_ratio": 0.5, "seen": detection_id}


@pytest.fixture
def upstream(monkeypatch):
    mod = types.ModuleType("fake_metrics_upstream")
    mod.Collector = _Upstream
    monkeypatch.setitem(sys.modules, "fake_metrics_upstream", mod)
    monkeypatch.delenv("ADEF_WRAPPER_METRICS", raising=False)
    monkeypatch.delenv("ADEF_WRAPPER_PERFORMANCE_METRICS", raising=False)
    return "fake_metrics_upstream:Collector"


def test_new_name_binds_without_a_notice(upstream, monkeypatch, capsys):
    monkeypatch.setenv("ADEF_WRAPPER_METRICS", upstream)
    out = PerformanceMetricsWrapper().run(detection_id="D-0001")
    assert out["result"]["seen"] == "D-0001"
    assert "deprecated" not in capsys.readouterr().err


def test_old_name_still_binds_with_a_deprecation_notice(upstream, monkeypatch, capsys):
    monkeypatch.setenv("ADEF_WRAPPER_PERFORMANCE_METRICS", upstream)
    out = PerformanceMetricsWrapper().run(detection_id="D-0001")
    assert out["result"]["fp_ratio"] == 0.5
    err = capsys.readouterr().err
    assert "ADEF_WRAPPER_PERFORMANCE_METRICS is deprecated" in err and "ADEF_WRAPPER_METRICS" in err


def test_new_name_wins_when_both_are_set(upstream, monkeypatch, capsys):
    monkeypatch.setenv("ADEF_WRAPPER_METRICS", upstream)
    monkeypatch.setenv("ADEF_WRAPPER_PERFORMANCE_METRICS", "no.such.module:Nope")
    assert PerformanceMetricsWrapper().run(detection_id="D-0001")["result"]["seen"] == "D-0001"
    assert "deprecated" not in capsys.readouterr().err


def test_neither_set_names_the_new_variable(upstream):
    with pytest.raises(WrapperUnavailable, match="ADEF_WRAPPER_METRICS is not set"):
        PerformanceMetricsWrapper().run(detection_id="D-0001")
