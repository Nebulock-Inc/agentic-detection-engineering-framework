"""Wrapper for an upstream FindingsAnalysisAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class FindingsAnalysisWrapper(WrapperBase):
    binding_key = "FINDINGS_ANALYSIS"


__all__ = ["FindingsAnalysisWrapper"]
