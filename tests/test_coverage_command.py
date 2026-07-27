"""CLI-level tests for ``adef coverage`` (the gap report + --gaps drill-down)."""

from __future__ import annotations

import textwrap

import pytest
from click.testing import CliRunner

from adef.commands.catalog import catalog as catalog_cli
from adef.commands.coverage import coverage as coverage_cli


@pytest.fixture
def catalogued(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    (repo / "windows" / "sigma.yml").write_text(
        textwrap.dedent(
            """\
            title: Sigma windows rule
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [attack.t1218.005]
            """
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0
    return ws


def test_coverage_reports_gaps(catalogued):
    result = CliRunner().invoke(coverage_cli, [])
    assert result.exit_code == 0, result.output
    assert "Coverage gaps" in result.output
    assert "ATT&CK techniques" in result.output


def test_coverage_gaps_flag_lists_uncovered(catalogued):
    plain = CliRunner().invoke(coverage_cli, [])
    assert "Uncovered techniques by tactic" not in plain.output  # off by default

    result = CliRunner().invoke(coverage_cli, ["--gaps"])
    assert result.exit_code == 0, result.output
    assert "Uncovered techniques by tactic" in result.output


def test_coverage_empty_workspace_errors(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    result = CliRunner().invoke(coverage_cli, [])
    assert result.exit_code != 0
    assert "No catalog records" in result.output
