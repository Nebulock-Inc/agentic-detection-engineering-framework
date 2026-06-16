"""Wrapper for an upstream CoverageAnalysisAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class CoverageAnalysisWrapper(WrapperBase):
    binding_key = "COVERAGE_ANALYSIS"


__all__ = ["CoverageAnalysisWrapper"]
