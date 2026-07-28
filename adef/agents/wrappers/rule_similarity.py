"""Wrapper for an upstream RuleSimilarityAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class RuleSimilarityWrapper(WrapperBase):
    binding_key = "RULE_SIMILARITY"


__all__ = ["RuleSimilarityWrapper"]
