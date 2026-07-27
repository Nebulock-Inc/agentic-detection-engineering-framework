"""Anti-goal CI guard — ADEF v0.1.0 ships no vendor connectors.

Forbidden imports / dependencies:
    - CrowdStrike (``crowdstrike``, ``falconpy``)
    - Splunk (``splunk_sdk``, ``splunklib``, ``splunk_appinspect``)
    - SentinelOne (``sentinelone``, ``s1``)
    - Microsoft Sentinel / Defender SDKs (``azure_sentinel``, ``msdefender``)
    - Generic vendor SIEM SDKs (``elasticsearch_dsl`` is borderline; we permit
      it for now since it's a query-language SDK, not a vendor connector — but
      this list is conservative on purpose).

The check scans both ``pyproject.toml`` dependencies *and* the source tree for
import statements; a vendor connector slipping in via a transitive dep that
nobody imports is acceptable, but the moment it shows up in an `import` line
the framework has crossed the anti-goal line.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ADEF_PKG = REPO_ROOT / "adef"
PYPROJECT = REPO_ROOT / "pyproject.toml"

FORBIDDEN_PACKAGES = {
    "crowdstrike",
    "falconpy",
    "splunk_sdk",
    "splunklib",
    "splunk_appinspect",
    "sentinelone",
    "azure_sentinel",
    "msdefender",
}


_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+([a-zA-Z0-9_]+)")


@pytest.mark.unit
def test_pyproject_has_no_vendor_connectors():
    text = PYPROJECT.read_text(encoding="utf-8").lower()
    offenders = sorted(p for p in FORBIDDEN_PACKAGES if p in text)
    assert not offenders, (
        f"pyproject.toml contains a forbidden vendor-connector dependency: {offenders}. "
        "Vendor connectors are an explicit anti-goal — ship them as separate plugins."
    )


@pytest.mark.unit
def test_source_has_no_vendor_connector_imports():
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
        "Forbidden vendor-connector import detected. "
        f"Offending lines: {offenders}"
    )
