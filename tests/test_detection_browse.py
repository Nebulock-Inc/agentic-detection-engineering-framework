"""Tests for ``adef detection list`` / ``show`` (story 7393)."""

from __future__ import annotations

import json
import textwrap

import pytest
from click.testing import CliRunner

from adef.commands.catalog import catalog as catalog_cli
from adef.commands.detection import detection as detection_cli


@pytest.fixture
def ws(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    return ws


@pytest.fixture
def catalogued(ws, tmp_path):
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
    (repo / "hunt.conf").write_text(
        "[Broad hunt]\nsearch = index=thrunt CommandLine=* | stats count\n",
        encoding="utf-8",
    )
    assert CliRunner().invoke(catalog_cli, [str(repo)]).exit_code == 0
    return repo


def test_list_shows_all(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" in result.output
    assert "2 detection(s)" in result.output


def test_list_filters(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["list", "--platform", "windows"])
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" not in result.output

    result = CliRunner().invoke(detection_cli, ["list", "--rule-format", "spl"])
    assert "Broad hunt" in result.output
    assert "Sigma windows rule" not in result.output

    result = CliRunner().invoke(detection_cli, ["list", "--needs-review"])
    assert "Broad hunt" in result.output          # raw SPL: platform unknown
    assert "Sigma windows rule" not in result.output


def test_list_report_json(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["list", "--report", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(data) == 2
    ids = {d["id"] for d in data}
    assert ids == {"D-0001", "D-0002"}
    sigma = next(d for d in data if d["format"] == "sigma")
    assert sigma["mitre"] == ["T1218.005"]
    assert sigma["platform"] == "windows"


def test_list_empty_workspace(ws):
    result = CliRunner().invoke(detection_cli, ["list"])
    assert result.exit_code == 0
    assert "No detections match" in result.output


def test_show_renders_record_and_journal(ws, catalogued):
    listing = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    sigma_id = next(d["id"] for d in listing if d["format"] == "sigma")
    result = CliRunner().invoke(detection_cli, ["show", sigma_id])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "T1218.005" in result.output
    assert "Query" in result.output
    assert "Journal" in result.output  # paired skeleton journal exists


def test_show_unknown_id_fails(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["show", "D-9999"])
    assert result.exit_code != 0
    assert "not found" in result.output
