"""Anti-goal CI guard — ADEF code never writes under any rule ``detections/`` tree.

The hard invariant is enforced at runtime by ``_check_not_under_detections`` in
``adef.core.journal`` and at code-review time by this static check, which
scans the source tree for any path literal that would write under a rule
``detections/`` directory. The combination catches both the runtime path and
any developer who introduces a string-only reference that bypasses the
journal abstraction (e.g. a future loader that opens YAML for writing).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
ADEF_PKG = REPO_ROOT / "adef"

# Forbidden: any source line that would write into an upstream rule
# ``detections/`` directory. Reading YAML from such directories is allowed;
# mutating them never is.
_FORBIDDEN_WRITE_PATTERNS = (
    re.compile(r"/detections/.*\.write_text"),
    re.compile(r"/detections/.*open\(.*['\"][wax]"),
)


@pytest.mark.unit
def test_no_write_path_under_detections_tree():
    offenders: list[tuple[Path, int, str]] = []
    for py in ADEF_PKG.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pat in _FORBIDDEN_WRITE_PATTERNS:
                if pat.search(line):
                    offenders.append((py.relative_to(REPO_ROOT), line_no, line.strip()))
    assert not offenders, (
        "ADEF code must never write inside a rule 'detections/' directory. "
        f"Offending lines: {offenders}"
    )


@pytest.mark.unit
def test_journal_module_blocks_detections_path(tmp_path):
    """``HardInvariantViolation`` is raised if a journals dir resolves under any ``detections/`` tree."""
    from adef.core.journal import Journal, HardInvariantViolation

    fake = tmp_path / "rules" / "detections" / "sigma" / "edr"
    fake.mkdir(parents=True)

    with pytest.raises(HardInvariantViolation):
        Journal(fake)
