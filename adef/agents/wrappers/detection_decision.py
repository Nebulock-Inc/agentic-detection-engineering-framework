"""Wrapper for an upstream DetectionDecisionAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class DetectionDecisionWrapper(WrapperBase):
    binding_key = "DETECTION_DECISION"


__all__ = ["DetectionDecisionWrapper"]
