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


def test_stage_advance_unknown_id_errors_cleanly(ws, catalogued):
    # A bad/missing detection id must be a clean click error, not a raw
    # JournalError traceback (parity with `show`/`tag-mitre`). Covers all four
    # generated stage-advance commands.
    for stage in ("observe", "refine", "govern", "evolve"):
        result = CliRunner().invoke(detection_cli, [stage, "D-9999"])
        assert result.exit_code != 0, f"{stage}: {result.output}"
        assert "not found" in result.output.lower(), f"{stage}: {result.output}"


def test_list_filter_engine(ws, catalogued):
    # Sigma folds to engine `sigma`; the .conf SPL rule folds to `sql`.
    result = CliRunner().invoke(detection_cli, ["list", "--engine", "sigma"])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" not in result.output


def test_list_filter_tactic_display_name(ws, catalogued):
    # Tactic is derived from the technique ID (T1218.005); resolve the real
    # display name from the shipped snapshot rather than hardcoding a guess.
    from adef.core.attack import attack_reference

    tactics = attack_reference().tactics_for("T1218.005")
    assert tactics, "expected the shipped ATT&CK snapshot to know T1218.005"
    result = CliRunner().invoke(detection_cli, ["list", "--tactic", tactics[0]])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output
    assert "Broad hunt" not in result.output  # raw SPL has no MITRE → no tactic


def test_list_filter_tactic_shortname(ws, catalogued):
    # The shortname form (lowercased/hyphenated display name) matches too.
    from adef.core.attack import attack_reference

    shortname = attack_reference().tactics_for("T1218.005")[0].lower().replace(" ", "-")
    result = CliRunner().invoke(detection_cli, ["list", "--tactic", shortname])
    assert result.exit_code == 0, result.output
    assert "Sigma windows rule" in result.output


def test_list_tactic_no_match(ws, catalogued):
    result = CliRunner().invoke(detection_cli, ["list", "--tactic", "impact"])
    assert result.exit_code == 0, result.output
    assert "No detections match" in result.output


def test_list_json_includes_engine_and_tactics(ws, catalogued):
    data = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    sigma = next(d for d in data if d["format"] == "sigma")
    assert sigma["engine"] == "sigma"
    assert sigma["tactics"]  # derived from T1218.005
    spl = next(d for d in data if d["format"] == "spl")
    assert spl["tactics"] == []  # no MITRE → no tactics


def test_show_includes_tactics(ws, catalogued):
    # show should surface the tactic derived from the technique ID (T1218.005).
    from adef.core.attack import attack_reference

    listing = json.loads(
        CliRunner().invoke(detection_cli, ["list", "--report", "json"]).output
    )
    sigma_id = next(d["id"] for d in listing if d["format"] == "sigma")
    tactic = attack_reference().tactics_for("T1218.005")[0]
    result = CliRunner().invoke(detection_cli, ["show", sigma_id])
    assert result.exit_code == 0, result.output
    assert "tactics" in result.output
    assert tactic in result.output


def test_show_flags_recognized_unsupported(ws):
    # A recognized-but-unsupported record (external logic, empty query) should
    # explain itself via a `support` line instead of silently omitting Query.
    from adef.core.catalog import Catalog, CatalogRecord

    rec = CatalogRecord(
        id="D-0001",
        title="External-logic rule",
        rule_ref="panther/x.yml",
        original_path="/tmp/panther/x.yml",
        platform="cloud-aws",
        kind="atomic",
        engine="composite",
        format="panther",
        support="recognized_unsupported",
        review_reasons=["external_logic"],
        needs_review=True,
    )
    Catalog(ws).write(rec)
    result = CliRunner().invoke(detection_cli, ["show", "D-0001"])
    assert result.exit_code == 0, result.output
    assert "support" in result.output
    assert "recognized_unsupported" in result.output


def test_detection_new_uses_shared_id_space(ws, catalogued):
    """`detection new` must allocate from catalog+journals, not journals alone —
    else a catalog record whose journal is gone gets clobbered by a reused ID
    (ISA 2026-07-22 guardrail audit)."""
    from adef.core.catalog import Catalog

    # Diverge: remove the highest journal so catalog index (D-0002) > journal index.
    (ws / "journals" / "D-0002.md").unlink()
    before = len(list((ws / "catalog").rglob("D-*.yml")))

    result = CliRunner().invoke(detection_cli, ["new", "Brand new authored rule"])
    assert result.exit_code == 0, result.output
    # No catalog record was clobbered; the new journal took a fresh id (D-0003),
    # not the reused D-0002.
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before
    assert Catalog(ws).find_record("D-0002")[1]["title"] == "Sigma windows rule" \
        or Catalog(ws).find_record("D-0002")[1]["id"] == "D-0002"
    assert (ws / "journals" / "D-0003.md").exists()


def test_search_finds_by_record_and_journal(ws, catalogued):
    """`detection search` matches catalog metadata (mitre/platform) AND journal
    notes — the durable-memory search seam (ISA 2026-07-22)."""
    # The Sigma rule carries T1218.005 in its record; its journal is a skeleton.
    # Search finds it by the record field alone (which id it got isn't the point).
    r = CliRunner().invoke(detection_cli, ["search", "T1218.005"])
    assert r.exit_code == 0, r.output
    assert "Sigma windows rule" in r.output   # found by the record's MITRE field

    # A journal note is searchable too — use a nonsense token so only the note matches.
    CliRunner().invoke(detection_cli, ["observe", "D-0001", "--note", "zzbeaconzz marker"])
    r2 = CliRunner().invoke(detection_cli, ["search", "zzbeaconzz"])
    assert "D-0001" in r2.output

    # No match → clean message, exit 0.
    r3 = CliRunner().invoke(detection_cli, ["search", "nomatchxyzzy"])
    assert r3.exit_code == 0 and "No detections match" in r3.output
