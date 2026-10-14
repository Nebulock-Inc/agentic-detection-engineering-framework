"""Tests for the profile CLI seams: ``adef profile lint`` and
``adef catalog --report json`` / ``--profile``."""

from __future__ import annotations

import json
import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog
from adef.commands.profile import profile as profile_cmd

ACME_PROFILE = {
    "name": "acme-siem-export",
    "version": 1,
    "signature": {"container": "yaml", "all_keys": ["alert"], "none_keys": ["pack_id"]},
    "query_language": "spl",
    "map": {
        "title": "alert.name",
        "query": "alert.query",
        "mitre": "alert.tags[]",
        "uuid": "alert.id",
        "data_source": "alert.index",
    },
    "platform": {"const": "windows"},
}


@pytest.fixture
def acme_repo(tmp_path):
    root = tmp_path / "acme-rules"
    root.mkdir()
    (root / "proc.yml").write_text(
        textwrap.dedent(
            """\
            alert:
              id: 9b2c1a7e-0001-4a4a-8888-123456789abc
              name: Acme suspicious child process
              query: index=wineventlog EventCode=4688
              index: wineventlog
              tags: [T1059.001]
            """
        ),
        encoding="utf-8",
    )
    (root / "sigma.yml").write_text(
        "title: Sigma one\nlogsource:\n  product: windows\n"
        "detection:\n  condition: selection\ntags: [attack.t1218]\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("# docs\n", encoding="utf-8")
    return root


@pytest.fixture
def ws(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    return ws


def _write_profile(path, data=ACME_PROFILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# adef profile lint
# --------------------------------------------------------------------------- #
def test_profile_lint_ok(tmp_path):
    p = _write_profile(tmp_path / "acme.yml")
    result = CliRunner().invoke(profile_cmd, ["lint", str(p)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_profile_lint_fails_with_errors(tmp_path):
    bad = dict(ACME_PROFILE, version=99)
    p = _write_profile(tmp_path / "bad.yml", bad)
    result = CliRunner().invoke(profile_cmd, ["lint", str(p)])
    assert result.exit_code != 0
    assert "version" in result.output


# --------------------------------------------------------------------------- #
# adef catalog --report json
# --------------------------------------------------------------------------- #
def test_report_json_counts_and_unclaimed(ws, acme_repo):
    result = CliRunner().invoke(catalog, [str(acme_repo), "--report", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["counts"]["supported"] == 1  # sigma
    assert report["counts"]["unclaimed"] == 1  # acme file, no profile loaded
    assert report["counts"]["not_a_rule"] == 1  # README
    unclaimed = [f for f in report["files"] if f["outcome"] == "unclaimed"]
    assert unclaimed[0]["top_level_keys"] == ["alert"]
    # --report implies dry-run: nothing written.
    assert not list((ws / "catalog").rglob("D-*.yml")) if (ws / "catalog").exists() else True


def test_report_json_with_candidate_profile_scores_fields(ws, acme_repo, tmp_path):
    p = _write_profile(tmp_path / "acme.yml")
    result = CliRunner().invoke(
        catalog, [str(acme_repo), "--report", "json", "--profile", str(p)]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["profile"]["name"] == "acme-siem-export"
    assert report["profile"]["claimed"] == 1
    rates = report["profile"]["field_rates"]
    for field in ("title", "query", "mitre", "uuid", "data_source", "platform"):
        assert rates[field] == 1.0
    assert report["counts"].get("unclaimed") is None  # profile claimed the acme file


def test_invalid_candidate_profile_is_fatal(ws, acme_repo, tmp_path):
    p = _write_profile(tmp_path / "bad.yml", dict(ACME_PROFILE, version=99))
    result = CliRunner().invoke(catalog, [str(acme_repo), "--profile", str(p)])
    assert result.exit_code != 0
    assert "invalid profile" in result.output


# --------------------------------------------------------------------------- #
# Workspace profiles feed the real catalog run
# --------------------------------------------------------------------------- #
def test_user_profiles_loaded_from_workspace(ws, acme_repo):
    _write_profile(ws / "config" / "profiles" / "acme.yml")
    result = CliRunner().invoke(catalog, [str(acme_repo)])
    assert result.exit_code == 0, result.output

    records = [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in (ws / "catalog").rglob("D-*.yml")
    ]
    formats = sorted(r["format"] for r in records)
    assert formats == ["acme-siem-export", "sigma"]
    acme = next(r for r in records if r["format"] == "acme-siem-export")
    assert acme["platform"] == "windows"
    assert acme["query"].startswith("index=wineventlog")
    assert acme["mitre"] == ["T1059.001"]


def test_broken_user_profile_never_kills_catalog(ws, acme_repo):
    (ws / "config" / "profiles").mkdir(parents=True)
    (ws / "config" / "profiles" / "broken.yml").write_text("version: 99\n", encoding="utf-8")
    result = CliRunner().invoke(catalog, [str(acme_repo)])
    assert result.exit_code == 0, result.output
    assert "broken" in result.output.lower()
