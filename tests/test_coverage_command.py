"""CLI-level tests for ``adef coverage`` (the gap report + --gaps drill-down)."""

from __future__ import annotations

import json
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


def test_workspace_flag_reaches_the_attack_snapshot(tmp_path, monkeypatch):
    """`--workspace X` must score against X's snapshot, through the command.

    The core-level twin of this lives in `test_coverage.py` and calls
    `build_coverage(records, ws)` directly — which is why it could not catch the
    actual defect. Passing the argument itself is what that test asserts, so all
    it can prove is that the parameter is wired up *inside* the function; the bug
    was the command resolving `--workspace` for `Catalog` and then dropping it on
    the floor for the ATT&CK resolver. Deleting the `ws` argument at either call
    site in `commands/coverage.py` leaves the core test green, measured.

    Every other test in this file drives the workspace through `$ADEF_WORKSPACE`
    and passes no flag, so none of them can see it either: zero-arg
    `attack_reference()` reads that same env var and gets the right answer by
    accident. The env var points somewhere else here on purpose — that is the
    whole fixture.
    """
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "attack").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(elsewhere))

    ws = tmp_path / "ws"
    (ws / "attack").mkdir(parents=True)
    (ws / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-local",
                "tactics": {"execution": "Execution"},
                "techniques": {
                    "T9999": {"name": "Local Only", "tactics": ["execution"]},
                    "T8888": {"name": "Uncovered Local", "tactics": ["execution"]},
                },
            }
        ),
        encoding="utf-8",
    )
    (ws / "catalog" / "windows").mkdir(parents=True)
    (ws / "catalog" / "windows" / "D-0001-local.yml").write_text(
        textwrap.dedent(
            """\
            id: D-0001
            title: Local only rule
            platform: windows
            data_source: wineventlog
            mitre: [T9999]
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(coverage_cli, ["--workspace", str(ws), "--gaps"])
    assert result.exit_code == 0, result.output
    # T9999 is real in this snapshot and absent from the shipped one, so the
    # shipped universe reports it as the report's loudest finding — fabricated.
    assert "Fictional coverage" not in result.output, result.output
    # 1 covered of this snapshot's 2 live techniques, not of the shipped ~700.
    # Whole rendered line, percentage included: `"1" in output` is true of nearly
    # any output, and `1/697` rounds to the 0% a blind workspace would also print.
    assert "detections cover 1 of 2 ATT&CK techniques (50%)" in result.output, result.output
    # --gaps enumerates the universe through a second call site of its own.
    assert "T8888" in result.output, result.output
    assert "Uncovered Local" in result.output, result.output
