"""Wrapper for an upstream DetectionReviewAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class DetectionReviewWrapper(WrapperBase):
    binding_key = "DETECTION_REVIEW"


__all__ = ["DetectionReviewWrapper"]
