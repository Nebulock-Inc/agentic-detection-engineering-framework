"""Wrapper for an upstream ThreatReviewAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class ThreatReviewWrapper(WrapperBase):
    binding_key = "THREAT_REVIEW"


__all__ = ["ThreatReviewWrapper"]
