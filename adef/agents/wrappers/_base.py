"""Base helper for upstream rule-agent wrappers.

Each wrapper inherits from ``WrapperBase`` and declares a ``binding_key`` —
the suffix of an environment variable of the form ``ADEF_WRAPPER_<KEY>``
whose value is a dotted ``module.path:ClassName`` reference to the upstream
agent class.

The wrappers are deliberately thin. They never modify upstream internals.
If the env var is unset or the import fails, ``run()`` raises
``WrapperUnavailable`` rather than ``ImportError`` so orchestration can
continue and surface the issue in the journal.
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import Any


class WrapperUnavailable(RuntimeError):
    """Raised when the underlying upstream agent cannot be imported."""


#: Kwargs the Refine chain injects for the *native* agents that a
#: pre-existing, strict-signature configured (``ADEF_WRAPPER_*``) upstream
#: class was never written to accept. Each wrapper's configured-upstream
#: branch strips these out of ``**ctx`` before forwarding — everything else
#: the caller passed still reaches the configured class (found live via
#: CodeRabbit review: an earlier fix dropped ALL of ``ctx``, not just
#: these two keys).
NATIVE_ONLY_CTX_KEYS = frozenset({"workspace", "similarity_mode"})


class WrapperBase:
    """Common shape for all upstream rule-agent wrappers."""

    #: Suffix of the environment variable that holds the dotted target.
    binding_key: str = ""
    #: Older suffixes still honoured, with a deprecation notice, when the
    #: current one is unset — a renamed variable must not break a released
    #: install that sets the old name.
    deprecated_binding_keys: tuple[str, ...] = ()

    def _env_var(self) -> str:
        return f"ADEF_WRAPPER_{self.binding_key}"

    def is_configured(self) -> bool:
        """Is any binding set? Silent — ``_binding`` prints the deprecation
        notice, and a probe followed by ``run()`` would print it twice."""
        keys = (self.binding_key, *self.deprecated_binding_keys)
        return any(os.environ.get(f"ADEF_WRAPPER_{k}", "").strip() for k in keys)

    def _binding(self) -> tuple[str, str]:
        """(variable name, value) — the current name, else the first set
        deprecated name, which prints a one-line notice to stderr."""
        current = self._env_var()
        value = os.environ.get(current, "").strip()
        if value:
            return current, value
        for old_key in self.deprecated_binding_keys:
            old = f"ADEF_WRAPPER_{old_key}"
            old_value = os.environ.get(old, "").strip()
            if old_value:
                print(
                    f"[adef.wrappers] {old} is deprecated and will be removed in a "
                    f"future major release; set {current} instead.",
                    file=sys.stderr,
                )
                return old, old_value
        return current, ""

    def _load_class(self) -> type:
        if not self.binding_key:
            raise NotImplementedError(
                f"{type(self).__name__} must set ``binding_key``."
            )
        env_var, dotted = self._binding()
        if not dotted:
            raise WrapperUnavailable(
                f"{env_var} is not set. Configure it as 'module.path:ClassName' to "
                f"enable {type(self).__name__}."
            )
        module_path, _, class_name = dotted.partition(":")
        if not module_path or not class_name:
            raise WrapperUnavailable(
                f"{env_var} must be 'module.path:ClassName'; got {dotted!r}."
            )
        try:
            mod = importlib.import_module(module_path)
        except ImportError as exc:
            raise WrapperUnavailable(
                f"Could not import {module_path} ({exc}). "
                f"Install the package providing {type(self).__name__}'s upstream class."
            ) from exc
        cls = getattr(mod, class_name, None)
        if not isinstance(cls, type):
            raise WrapperUnavailable(f"{class_name} not found in {module_path}.")
        return cls

    def run(self, detection_id: str, **ctx: Any) -> dict[str, Any]:
        """Default implementation — subclasses override when behavior differs."""
        cls = self._load_class()
        agent = cls()
        if hasattr(agent, "run"):
            result = agent.run(detection_id=detection_id, **ctx)
        else:
            result = agent(detection_id=detection_id, **ctx)
        return {"detection_id": detection_id, "result": result}


__all__ = ["WrapperBase", "WrapperUnavailable", "NATIVE_ONLY_CTX_KEYS"]
