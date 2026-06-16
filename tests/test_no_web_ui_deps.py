"""Anti-goal CI guard — ADEF v0.1.0 ships no web UI dependencies.

Forbidden:
    - flask, fastapi, starlette, django (Python web frameworks)
    - next, react (JS frontend frameworks; would never legitimately appear in
      a Python pyproject.toml, but we check anyway)

The check scans ``pyproject.toml`` (declarations) and source-tree imports
(actual usage). Either is a violation — the framework's CLI + MCP surface is
the only user-facing surface, by design.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
ADEF_PKG = REPO_ROOT / "adef"
PYPROJECT = REPO_ROOT / "pyproject.toml"

FORBIDDEN_PACKAGES = {
    "flask",
    "fastapi",
    "starlette",
    "django",
    # "next" and "react" are not Python packages but we still grep pyproject.toml for
    # them in case someone declares them via a JS bridge.
    "next",
    "react",
}


_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+([a-zA-Z0-9_]+)")


@pytest.mark.unit
def test_pyproject_has_no_web_ui_deps():
    text = PYPROJECT.read_text(encoding="utf-8").lower()
    offenders = sorted(p for p in FORBIDDEN_PACKAGES if p in text)
    assert not offenders, (
        f"pyproject.toml contains a forbidden web-UI dependency: {offenders}. "
        "ADEF v0.1.0 is CLI + MCP only; web UIs are an explicit anti-goal."
    )


@pytest.mark.unit
def test_source_has_no_web_ui_imports():
    offenders: list[tuple[Path, int, str]] = []
    for py in ADEF_PKG.rglob("*.py"):
        for line_no, line in enumerate(py.read_text(encoding="utf-8").splitlines(), start=1):
            m = _IMPORT_RE.match(line)
            if not m:
                continue
            top = m.group(1).lower()
            if top in FORBIDDEN_PACKAGES:
                offenders.append((py.relative_to(REPO_ROOT), line_no, line.strip()))
    assert not offenders, (
        f"Forbidden web-UI framework import detected: {offenders}"
    )
