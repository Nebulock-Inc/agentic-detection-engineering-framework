"""Tests for the needs_review rework: review_reasons,
declaration-based platform inheritance, no_mitre demotion, and the tier-2
MITRE text-sweep for profile-claimed rules."""

from __future__ import annotations

import json
import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog as catalog_cli
from adef.commands.detection import detection as detection_cli
from adef.commands.schema import schema as schema_cli
from adef.core.profiles import profile_from_dict
from adef.core.rule_discovery import discover_rules, structural_reasons


@pytest.fixture
def ws(tmp_path, monkeypatch):
    import adef.commands.detection as det

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    # `detection list` fits the title into whatever the columns and the review
    # flag leave over, and Rich's off-terminal default of 80 leaves almost
    # nothing — these are reason-filter tests, not layout tests, so give them
    # room (layout is covered in tests/test_detection_browse.py).
    monkeypatch.setattr(det.console, "width", 120)
    return ws


DECL = {
    "version": 1,
    "sources": [
        {
            "name": "wineventlog_xml",
            "platform": "windows",
            "query_language": "spl",
            "scope": {"index": "thrunt", "sourcetype": "XmlWinEventLog"},
            "fields": [{"name": "EventCode"}, {"name": "CommandLine"}],
        },
        {
            "name": "zeek_dns",
            "platform": "network",
            "query_language": "spl",
            "scope": {"index": "thrunt", "sourcetype": "bro:dns:json"},
            "fields": [{"name": "qtype_name"}],
        },
    ],
}


def _repo(tmp_path):
    repo = tmp_path / "rules"
    repo.mkdir()
    (repo / "pinned.conf").write_text(
        "# T1218.005\n[Pinned rule]\nsearch = index=thrunt sourcetype=XmlWinEventLog EventCode=1\n",
        encoding="utf-8",
    )
    (repo / "broad.conf").write_text(
        "[Broad rule]\nsearch = index=thrunt CommandLine=*\n",  # ambiguous container, no MITRE
        encoding="utf-8",
    )
    return repo


# --------------------------------------------------------------------------- #
# Reasons on records
# --------------------------------------------------------------------------- #
def test_reasons_persisted_on_records(ws, tmp_path):
    assert CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))]).exit_code == 0
    records = {
        d["title"]: d
        for d in (
            yaml.safe_load(p.read_text()) for p in (ws / "catalog").rglob("D-*.yml")
        )
    }
    assert records["Pinned rule"]["review_reasons"] == ["no_platform"]
    assert set(records["Broad rule"]["review_reasons"]) == {"no_platform", "no_mitre"}
    assert all(d["needs_review"] for d in records.values())


def test_structural_reasons_exclude_no_mitre():
    assert structural_reasons(["no_platform", "no_mitre"]) == ("no_platform",)
    assert structural_reasons(["no_mitre"]) == ()


def test_a_gates_verdict_with_work_outstanding_surfaces_unprompted():
    """`gates_conditional`/`gates_time_box` were only reachable by naming them, so a
    bare `--needs-review` — the "what needs me?" question — missed a rule deployed
    on an unmet prerequisite or past its expiry. They are warnings, not a queue."""
    assert structural_reasons(["gates_conditional"]) == ("gates_conditional",)
    assert structural_reasons(["gates_time_box"]) == ("gates_time_box",)


# --------------------------------------------------------------------------- #
# Platform inheritance from declared schemas
# --------------------------------------------------------------------------- #
def test_platform_inherited_from_declarations(ws, tmp_path):
    decl = tmp_path / "decl.yml"
    decl.write_text(yaml.safe_dump(DECL), encoding="utf-8")
    assert CliRunner().invoke(schema_cli, ["ingest", str(decl)]).exit_code == 0

    result = CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "platform(s) inherited" in result.output

    records = {
        d["title"]: d
        for d in (
            yaml.safe_load(p.read_text()) for p in (ws / "catalog").rglob("D-*.yml")
        )
    }
    # sourcetype-pinned rule: unambiguous → inherits windows, no_platform gone.
    pinned = records["Pinned rule"]
    assert pinned["platform"] == "windows"
    assert "no_platform" not in pinned["review_reasons"]
    assert pinned["needs_review"] is False  # MITRE present via comment sweep
    # container-only rule: two sources, two platforms → ambiguous, never guess.
    broad = records["Broad rule"]
    assert broad["platform"] == "multi-platform"
    assert "no_platform" in broad["review_reasons"]


def test_a_declaration_platform_that_isnt_a_path_segment_doesnt_kill_the_run(ws, tmp_path):
    """`platform: Windows` is free text the user wrote; the bucket is a directory.

    Capitalized or spaced, it reached `record_path` verbatim and refused the
    *entire* repo — `--dry-run` included, since the path pre-flight runs before
    the report. One unusable declaration value took out every unrelated rule in
    the catalog with it. Unusable now means the inheritance simply doesn't happen.
    """
    decl = tmp_path / "decl.yml"
    raw = yaml.safe_load(yaml.safe_dump(DECL))
    raw["sources"][0]["platform"] = "Windows Server"
    decl.write_text(yaml.safe_dump(raw), encoding="utf-8")
    assert CliRunner().invoke(schema_cli, ["ingest", str(decl)]).exit_code == 0

    result = CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))])
    assert result.exit_code == 0, result.output

    pinned = next(
        d
        for d in (yaml.safe_load(p.read_text()) for p in (ws / "catalog").rglob("D-*.yml"))
        if d["title"] == "Pinned rule"
    )
    # Back where it was before the inheritance pass ran: unresolved, not mis-filed.
    assert pinned["platform"] == "multi-platform"
    assert "no_platform" in pinned["review_reasons"]


# --------------------------------------------------------------------------- #
# list: structural headline + reason filters
# --------------------------------------------------------------------------- #
def test_list_headline_and_reason_filters(ws, tmp_path):
    decl = tmp_path / "decl.yml"
    decl.write_text(yaml.safe_dump(DECL), encoding="utf-8")
    CliRunner().invoke(schema_cli, ["ingest", str(decl)])
    CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))])

    out = CliRunner().invoke(detection_cli, ["list"]).output
    assert "1" in out and "need review" in out          # only Broad (structural)
    assert "missing ATT&CK" in out                      # enrichment queue surfaced

    out = CliRunner().invoke(detection_cli, ["list", "--needs-review"]).output
    assert "Broad rule" in out and "Pinned rule" not in out

    out = CliRunner().invoke(detection_cli, ["list", "--needs-review", "no_mitre"]).output
    assert "Broad rule" in out and "Pinned rule" not in out

    data = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    assert all("review_reasons" in d for d in data)


def test_a_hand_edited_scalar_reason_still_surfaces_in_the_queue(ws, tmp_path):
    """The queue is read off a field humans edit, so the dash-less typo hid rules.

    `review_reasons: invalid_mitre` read as 13 one-character reasons: bare
    `--needs-review` matched no structural reason and `--needs-review
    invalid_mitre` — the query that would have found it — matched nothing either.
    A rule mapped to a technique that doesn't exist, silently out of every triage
    view. Coerced in `Catalog.iter_records`, which every reader goes through.
    """
    from adef.core.catalog import Catalog

    assert CliRunner().invoke(catalog_cli, [str(_repo(tmp_path))]).exit_code == 0
    path, data = Catalog(ws).find_record("D-0001")
    Catalog(ws).write_raw(path, {**data, "review_reasons": "invalid_mitre",
                                 "needs_review": True})

    out = CliRunner().invoke(
        detection_cli, ["list", "--needs-review", "invalid_mitre"]
    ).output
    assert "D-0001" in out
    assert "D-0001" in CliRunner().invoke(detection_cli, ["list", "--needs-review"]).output


# --------------------------------------------------------------------------- #
# Tier-2 MITRE sweep for profile-claimed rules
# --------------------------------------------------------------------------- #
def test_profile_rules_get_mitre_text_sweep(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "r.yml").write_text(
        textwrap.dedent(
            """\
            alert:
              name: Acme lateral movement
              description: Detects psexec-style moves. MITRE T1021.002.
              query: SELECT 1 FROM events
            """
        ),
        encoding="utf-8",
    )
    prof = profile_from_dict(
        {
            "name": "acme", "version": 1,
            "signature": {"container": "yaml", "all_keys": ["alert"]},
            "query_language": "sql",
            "map": {
                "title": "alert.name",
                "query": "alert.query",
                "description": "alert.description",
            },
        }
    )
    rules = list(discover_rules(root, [prof]))
    assert rules[0].mitre == ("T1021.002",)  # swept from description
    assert "no_mitre" not in rules[0].review_reasons
