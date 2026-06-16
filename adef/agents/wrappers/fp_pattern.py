"""Wrapper for an upstream FpPatternAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class FpPatternWrapper(WrapperBase):
    binding_key = "FP_PATTERN"


__all__ = ["FpPatternWrapper"]
