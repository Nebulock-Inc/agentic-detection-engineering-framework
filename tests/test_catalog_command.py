"""Tests for the ``adef catalog`` CLI command."""

from __future__ import annotations

import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog


@pytest.fixture
def rule_repo(tmp_path):
    root = tmp_path / "their-detections"
    win = root / "windows"
    win.mkdir(parents=True)
    (win / "mshta.yml").write_text(
        textwrap.dedent(
            """\
            title: Suspicious mshta child
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
    raw = root / "cloud"
    raw.mkdir(parents=True)
    (raw / "iam.sql").write_text("SELECT user_name FROM cloudtrail", encoding="utf-8")
    return root


def test_catalog_help():
    result = CliRunner().invoke(catalog, ["--help"])
    assert result.exit_code == 0
    assert "atalog" in result.output


def test_catalog_creates_records_and_index(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo)])
    assert result.exit_code == 0, result.output

    cat_dir = ws / "catalog"
    yamls = sorted(p for p in cat_dir.rglob("D-*.yml"))
    assert len(yamls) == 2  # one sigma, one sql

    index = yaml.safe_load((cat_dir / "INDEX.yml").read_text())
    assert len(index["detections"]) == 2
    assert "windows" in index["by_platform"]


def test_catalog_also_creates_skeleton_journals(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    CliRunner().invoke(catalog, [str(rule_repo)])
    journals = sorted((ws / "journals").rglob("D-*.md"))
    assert len(journals) == 2


def test_catalog_dry_run_writes_nothing(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo), "--dry-run"])
    assert result.exit_code == 0
    assert not list((ws / "catalog").rglob("D-*.yml"))
    assert "2" in result.output  # reports the count it would write


def test_catalog_reports_needs_review_count(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo)])
    # The raw SQL rule has no platform/MITRE → flagged for review.
    assert "review" in result.output.lower()


def test_catalog_ids_do_not_collide_with_existing_journals(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "journals" / "D-0001.md").write_text("---\nid: D-0001\n---\n")
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    CliRunner().invoke(catalog, [str(rule_repo)])
    ids = sorted(
        yaml.safe_load(p.read_text())["id"]
        for p in (ws / "catalog").rglob("D-*.yml")
    )
    # Existing D-0001 journal must not be overwritten; catalog starts at D-0002.
    assert "D-0001" not in ids
    assert ids == ["D-0002", "D-0003"]
