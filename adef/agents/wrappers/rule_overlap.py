"""Wrapper for an upstream RuleOverlapAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class RuleOverlapWrapper(WrapperBase):
    binding_key = "RULE_OVERLAP"


__all__ = ["RuleOverlapWrapper"]
