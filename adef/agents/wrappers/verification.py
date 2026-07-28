"""Wrapper for an upstream VerificationAgent."""

from __future__ import annotations

from adef.agents.wrappers._base import WrapperBase


class VerificationWrapper(WrapperBase):
    binding_key = "VERIFICATION"


__all__ = ["VerificationWrapper"]
