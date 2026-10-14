"""The MCP schema tools are a trust boundary — client-supplied `source` names
are joined into a filesystem path, so they must not escape the schema dir
(CodeRabbit)."""

from __future__ import annotations

import pytest

from adef.mcp.tools.schema_tools import _UnsafeName, _safe_source_name


def test_safe_source_name_allows_bare_names():
    assert _safe_source_name("wineventlog") == "wineventlog"
    assert _safe_source_name("sysmon_operational") == "sysmon_operational"
    assert _safe_source_name("  windows-dns  ") == "windows-dns"  # trimmed


@pytest.mark.parametrize(
    "bad",
    [
        "../../../../etc/passwd",   # traversal
        "../secrets",
        "a/b",                       # posix separator
        "a\\b",                      # windows separator (guard is OS-agnostic)
        "..",
        ".",
        "",
        "   ",
    ],
)
def test_safe_source_name_rejects_traversal_and_separators(bad):
    with pytest.raises(_UnsafeName):
        _safe_source_name(bad)
