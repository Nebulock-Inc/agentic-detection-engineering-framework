"""Wrapper for an upstream metrics collector (`fp_ratio`,
`weekly_signal_volume`, `days_since_true_positive`).

Bound by `ADEF_WRAPPER_METRICS`. The old name, `ADEF_WRAPPER_PERFORMANCE_METRICS`,
still works with a deprecation notice: it named the *metrics* measurable under
a performance label, and v1.0.0 shipped with it, so a rename can't drop it
outright."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class PerformanceMetricsWrapper(WrapperBase):
    binding_key = "METRICS"
    deprecated_binding_keys = ("PERFORMANCE_METRICS",)


__all__ = ["PerformanceMetricsWrapper"]
