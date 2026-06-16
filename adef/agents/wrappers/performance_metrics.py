"""Wrapper for an upstream PerformanceMetricsCollector."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class PerformanceMetricsWrapper(WrapperBase):
    binding_key = "PERFORMANCE_METRICS"


__all__ = ["PerformanceMetricsWrapper"]
