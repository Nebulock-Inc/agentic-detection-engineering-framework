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
