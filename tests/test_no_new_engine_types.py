"""Anti-goal CI guard — ADEF v0.1.0 introduces no new engine types.

The closed set is ``sigma``, ``sql``, ``sch_sql``, ``composite``. This test
scans the ADEF source tree for any string that looks like a new engine literal
appearing alongside known engine literals. It's a tripwire, not a proof — the
intent is to fail loudly when a developer adds, say, ``"yara"`` or
``"detection-as-code"`` next to the existing engine list.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
ADEF_PKG = REPO_ROOT / "adef"
ALLOWED_ENGINES = {"sigma", "sql", "sch_sql", "composite"}

_ENGINE_LIST_RE = re.compile(
    r"['\"]sigma['\"][^\n]*['\"]sql['\"][^\n]*['\"]sch_sql['\"][^\n]*['\"]composite['\"]"
)


def _line_engines(line: str) -> set[str]:
    return set(re.findall(r"['\"]([a-z_]+)['\"]", line))


@pytest.mark.unit
def test_engine_lists_are_closed_set():
    offenders: list[tuple[Path, int, str]] = []
    for py in ADEF_PKG.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if _ENGINE_LIST_RE.search(line):
                tokens = _line_engines(line)
                extras = {t for t in tokens if t not in ALLOWED_ENGINES and len(t) > 2}
                # Allow common Python identifiers found alongside (e.g. "sigma" filename
                # extensions etc.) — only flag if the line obviously *adds* an engine.
                if extras - {"yml", "yaml", "py", "md", "txt", "json"}:
                    offenders.append(
                        (py.relative_to(REPO_ROOT), line_no, line.strip())
                    )

    assert not offenders, (
        "ADEF v0.1.0 introduces no new engine types beyond "
        f"{sorted(ALLOWED_ENGINES)}. Offending lines: {offenders}"
    )


_CANONICAL_COPY = ADEF_PKG / "core" / "engines.py"


@pytest.mark.unit
def test_only_engines_py_spells_the_set_out():
    """One canonical copy — a re-typed *identical* set passed the check above.

    `engines.py`'s own docstring claims this test catches "any other place a
    4-element literal list like this appears", and it didn't: the guard only flags a
    line that *adds* an engine, so `gates.py` carried a byte-identical duplicate for
    the whole of this branch. Identical today is the problem — the two copies drift
    on the next rename, and the boundary that rejects a GATES document's `engine`
    keeps accepting the old spelling with nothing failing.
    """
    duplicates = [
        f"{py.relative_to(REPO_ROOT)}:{line_no}"
        for py in ADEF_PKG.rglob("*.py")
        if py != _CANONICAL_COPY
        for line_no, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1)
        if _ENGINE_LIST_RE.search(line)
    ]
    assert not duplicates, (
        "The engine set is spelled out only in adef/core/engines.py — import "
        f"ALLOWED_ENGINES instead of re-typing it. Found: {duplicates}"
    )
