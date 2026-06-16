"""Wrapper for an upstream ReviewQueue."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class ReviewQueueWrapper(WrapperBase):
    binding_key = "REVIEW_QUEUE"


__all__ = ["ReviewQueueWrapper"]
