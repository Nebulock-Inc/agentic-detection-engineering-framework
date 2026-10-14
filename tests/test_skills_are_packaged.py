"""The bundled skills must reach a wheel, not just a checkout.

`adef install-skills` copies `adef/data/claude-plugin/`. Those are data files,
so they ship only if a `[tool.setuptools.package-data]` glob names them — and a
glob that stops matching fails *silently*: the build succeeds and the wheel is
just short. The published 1.0.0 wheel carries zero skill files for exactly this
reason. Checking the declaration rather than building keeps this runnable per
commit; a real build is the end-to-end check.
"""

from __future__ import annotations

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # 3.10 — `tomli` is in the `dev` extra so this guard runs on every CI leg
    import tomli as tomllib

from adef.commands.install_skills import _bundled_plugin_dir

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _declared_globs() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return data["tool"]["setuptools"]["package-data"]["adef.data"]


def test_the_bundled_dir_lives_inside_the_adef_package() -> None:
    """Moved back outside the package, no glob can reach it and the wheel is short.

    Not covered by `tests/test_skills.py`'s existence check: moving the
    directory *and* `_bundled_plugin_dir()` back to the repo root together
    leaves that one green, because the directory does exist in a checkout. Only
    the containment assertion distinguishes "present" from "shippable".
    """
    import adef

    pkg = Path(adef.__file__).resolve().parent
    bundled = _bundled_plugin_dir()

    assert bundled.is_dir(), f"missing {bundled}"
    assert pkg in bundled.parents, f"{bundled} is outside the adef package at {pkg}"


def test_every_bundled_file_is_matched_by_a_declared_glob() -> None:
    """The wheel ships what the globs name — nothing else, with no error.

    Dotfiles are excluded because this walks the working tree, not git: one
    Finder visit leaves a `.DS_Store` that is not a packaging problem.
    `.claude-plugin/plugin.json` is a dot-*directory* and still checked, by its
    own literal glob.
    """
    data_dir = _bundled_plugin_dir().parent  # adef/data/, what the globs are relative to
    globs = [g for g in _declared_globs() if g.startswith("claude-plugin/")]
    assert globs, f"no claude-plugin globs declared in {_PYPROJECT}"

    matched = {p for g in globs for p in data_dir.glob(g)}
    present = {
        p
        for p in _bundled_plugin_dir().rglob("*")
        if p.is_file() and not p.name.startswith(".")
    }
    # Both sets come from the same listing, so an empty directory would satisfy
    # the comparison below by having nothing to compare.
    assert present, f"no bundled files found under {_bundled_plugin_dir()}"
    assert (data_dir / "claude-plugin" / ".claude-plugin" / "plugin.json").is_file()

    unmatched = sorted(str(p.relative_to(data_dir)) for p in present - matched)
    assert not unmatched, (
        f"these files would be missing from the wheel: {unmatched}. "
        f'Add a glob to [tool.setuptools.package-data]."adef.data" in {_PYPROJECT.name}'
    )
