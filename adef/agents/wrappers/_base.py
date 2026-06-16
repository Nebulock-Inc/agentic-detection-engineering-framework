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
from typing import Any


class WrapperUnavailable(RuntimeError):
    """Raised when the underlying upstream agent cannot be imported."""


class WrapperBase:
    """Common shape for all upstream rule-agent wrappers."""

    #: Suffix of the environment variable that holds the dotted target.
    binding_key: str = ""

    def _env_var(self) -> str:
        return f"ADEF_WRAPPER_{self.binding_key}"

    def _load_class(self) -> type:
        if not self.binding_key:
            raise NotImplementedError(
                f"{type(self).__name__} must set ``binding_key``."
            )
        env_var = self._env_var()
        dotted = os.environ.get(env_var, "").strip()
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
        if cls is None:
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


__all__ = ["WrapperBase", "WrapperUnavailable"]
