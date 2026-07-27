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


def test_majority_unclaimed_nudge_escalates(tmp_path, monkeypatch):
    """When unclaimed files outnumber catalogued ones, the nudge is loud —
    one recognized Sigma rule beside an in-house repo shouldn't read as success
    (E2E 2026-07-27: real repo catalogued 9 of 127)."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    root = tmp_path / "repo"
    root.mkdir()
    (root / "sigma.yml").write_text(
        textwrap.dedent(
            """\
            title: A sigma rule
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            """
        ),
        encoding="utf-8",
    )
    for i in range(3):  # in-house envelope no recognizer claims → unclaimed
        (root / f"inhouse{i}.yml").write_text(
            f"name: In-house {i}\nmetadata:\n  id: x{i}\ndetection:\n  query: SELECT 1\n",
            encoding="utf-8",
        )

    result = CliRunner().invoke(catalog, [str(root)])
    assert result.exit_code == 0, result.output
    assert "Most of this repo was not recognized" in result.output
    assert "3 of 4 files" in result.output


def test_recatalog_same_repo_is_refused(tmp_path, rule_repo, monkeypatch):
    """A second catalog of the same repo would mint duplicates → refused,
    pointing at `sync` (ISA 2026-07-22)."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    assert CliRunner().invoke(catalog, [str(rule_repo)]).exit_code == 0
    before = len(list((ws / "catalog").rglob("D-*.yml")))

    result = CliRunner().invoke(catalog, [str(rule_repo)])
    assert result.exit_code != 0
    assert "already catalogued" in result.output and "sync" in result.output
    # Nothing written on the refused run.
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before


def test_recatalog_with_force_appends(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    CliRunner().invoke(catalog, [str(rule_repo)])
    before = len(list((ws / "catalog").rglob("D-*.yml")))
    result = CliRunner().invoke(catalog, [str(rule_repo), "--force"])
    assert result.exit_code == 0, result.output
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before * 2  # duplicated on purpose
    # --force proceeds but warns about the duplicate→orphan consequence.
    assert "orphaned" in result.output.lower()
    assert "sync" in result.output.lower()


def test_catalog_new_repo_into_populated_workspace_appends(tmp_path, rule_repo, monkeypatch):
    """No identity overlap → not a re-catalog → appends cleanly, no false block."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    CliRunner().invoke(catalog, [str(rule_repo)])
    before = len(list((ws / "catalog").rglob("D-*.yml")))

    # A second, distinct repo (different rules) — should append, not be refused.
    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / "other.yml").write_text(
        "title: Distinct rule\n"
        "id: 99999999-0000-0000-0000-000000000abc\n"
        "logsource:\n  product: linux\n"
        "detection:\n  condition: selection\n"
        "tags:\n  - attack.t1059\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(catalog, [str(repo2)])
    assert result.exit_code == 0, result.output
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before + 1


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


# --------------------------------------------------------------------------- #
# Report honesty + file output + dry-run collapse (field report 2026-07-23:
# a user ran only --dry-run/--report variants and concluded catalog was broken)
# --------------------------------------------------------------------------- #
def test_report_json_says_nothing_was_written(tmp_path, rule_repo, monkeypatch):
    import json

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo), "--report", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["dry_run"] is True
    assert report["written"] == 0
    assert "nothing was catalogued" in result.stderr  # terminal warning, off stdout
    assert not list((ws / "catalog").rglob("D-*.yml"))


def test_report_json_output_file(tmp_path, rule_repo, monkeypatch):
    import json

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    out = tmp_path / "report.json"

    result = CliRunner().invoke(
        catalog, [str(rule_repo), "--report", "json", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["dry_run"] is True
    assert str(out) in result.output  # confirmation line names the file


def test_output_without_report_errors(tmp_path, rule_repo, monkeypatch):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    result = CliRunner().invoke(catalog, [str(rule_repo), "-o", "x.json"])
    assert result.exit_code != 0
    assert "--report" in result.output


def test_dry_run_leads_with_nothing_written_and_collapses_mass_flags(
    tmp_path, monkeypatch
):
    """1,469 identical no_platform rows drowned the one line that mattered —
    dominant flag groups collapse to samples + a count."""
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(30):
        (root / f"r{i}.sql").write_text(
            f"SELECT user_name FROM cloudtrail WHERE q = {i}", encoding="utf-8"
        )
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(root), "--dry-run"])
    assert result.exit_code == 0, result.output
    first_line = next(line for line in result.output.splitlines() if line.strip())
    assert "nothing will be written" in first_line
    assert "more like these" in result.output
    # collapsed: far fewer record rows than rules
    record_rows = [line for line in result.output.splitlines() if "D-00" in line]
    assert len(record_rows) <= 6
