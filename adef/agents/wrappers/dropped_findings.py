"""Wrapper for an upstream DroppedFindingsAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class DroppedFindingsWrapper(WrapperBase):
    binding_key = "DROPPED_FINDINGS"


__all__ = ["DroppedFindingsWrapper"]
