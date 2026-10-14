"""Tests for hunt promotion — the ADEF half of the ATHF bridge.

The generator is stubbed: ADEF's contract is "call a configured class exposing
``run(hunt_id=...)``"; these tests prove the plumbing around that seam.
"""

from __future__ import annotations

import sys
import types

import pytest

from adef.agents.hunt_promotion import HuntPromotionAgent, HuntPromotionError


def _stub_generator(monkeypatch):
    mod = types.ModuleType("huntstub")

    class Gen:
        def run(self, hunt_id=None, **kw):
            return {
                "yaml": f"title: from {hunt_id}\n",
                "title": f"Promoted {hunt_id}",
                "uuid": "u-1",
            }

    mod.Gen = Gen
    monkeypatch.setitem(sys.modules, "huntstub", mod)
    monkeypatch.setenv("ADEF_HUNT_RULE_GENERATOR", "huntstub:Gen")


def _agent(tmp_path):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True, exist_ok=True)
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return HuntPromotionAgent(rule_staging_root=staging, workspace_root=ws), ws


def test_promote_creates_staging_yaml_and_find_journal(tmp_path, monkeypatch):
    _stub_generator(monkeypatch)
    agent, ws = _agent(tmp_path)

    result = agent.run("H-0042")

    assert result.detection_id == "D-0001"
    assert result.staging_yaml.exists()
    assert "from H-0042" in result.staging_yaml.read_text(encoding="utf-8")
    assert result.journal_path.exists()
    assert "H-0042" in result.journal_path.read_text(encoding="utf-8")


def test_promote_id_clears_catalog_records(tmp_path, monkeypatch):
    """Shared ID space: a catalog record without a journal must not be clobbered
    (same footgun fixed in `detection new` on 2026-07-22)."""
    _stub_generator(monkeypatch)
    agent, ws = _agent(tmp_path)
    cat = ws / "catalog" / "windows"
    cat.mkdir(parents=True)
    (cat / "D-0007-existing.yml").write_text("id: D-0007\ntitle: existing\n", encoding="utf-8")

    result = agent.run("H-0001")

    assert result.detection_id == "D-0008"


def test_promoted_note_is_findable_by_hunt_id(tmp_path, monkeypatch):
    # the hunt
    # link is deliberately left unmarked/indexed — it is a fact recorded
    # nowhere else, and "which detections came from H-0042?" is a real search
    # question. Confirms the opposite of sync's housekeeping notes.
    #
    # Searching the bare hunt id would false-pass here even with a broken
    # `generated=True` marking: the stub's title ("Promoted H-0042") and the
    # unmarked fallback title both already carry the hunt id independently of
    # the note. "upstream" appears ONLY in the note text, not in either title
    # form, so it can only be found if the *note* itself is indexed.
    _stub_generator(monkeypatch)
    agent, ws = _agent(tmp_path)

    result = agent.run("H-0042")
    from adef.core.journal import Journal
    text = Journal(ws / "journals").read(result.detection_id).body
    assert "upstream hunt H-0042" in text  # sanity: the note we're about to search for

    from adef.core.corpus import build_corpus
    from adef.core.memory import MemoryIndex

    index = MemoryIndex()
    index.build(build_corpus(ws))
    hits = index.search("upstream")
    assert any(h.detection_id == result.detection_id for h in hits)


def test_dry_run_without_gates_is_refused_not_ignored(tmp_path, monkeypatch):
    """The generator path has no dry run. Accepting the flag there meant
    `hunt-promote H-0042 --dry-run` wrote a staging YAML and a journal while the
    user believed they had asked for a preview."""
    from click.testing import CliRunner

    from adef.commands.hunt_promote import hunt_promote

    _stub_generator(monkeypatch)
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    result = CliRunner().invoke(hunt_promote, ["H-0042", "--dry-run"])

    assert result.exit_code == 2
    assert "--dry-run is only supported with --gates" in result.output
    assert not list((tmp_path / "ws" / "journals").glob("D-*.md"))


def test_a_hunt_id_alongside_gates_is_refused_not_ignored(tmp_path, monkeypatch):
    """The two modes take their hunt from different places — `--gates` reads it out
    of the document. Accepting a positional too meant a mismatched pair imported the
    document's hunt and reported success, which is the one case worth catching."""
    from click.testing import CliRunner

    from adef.commands.hunt_promote import hunt_promote

    ws = tmp_path / "ws"
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    doc = tmp_path / "H-0041_GATES.yaml"
    doc.write_text(
        "hunt_metadata: {hunt_id: H-0041, platforms: [windows]}\n"
        "gates_validation: {verdict: PROMOTE}\n"
        "detections:\n"
        "- candidate_id: a\n"
        "  gates_assessment: {verdict: PROMOTE, base_score: 4.5}\n"
        "  deployment: {engine: sql, detection_logic: {query: 'SELECT 1'}}\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(hunt_promote, ["H-0099", "--gates", str(doc)])

    assert result.exit_code == 2
    # Rich soft-wraps the line, so match fragments rather than the whole sentence.
    assert "--gates takes the hunt ID from the document" in result.output
    assert "(H-0099)" in result.output
    assert not list(ws.glob("journals/D-*.md"))  # nothing imported under either ID


def test_missing_generator_is_a_clean_error(tmp_path, monkeypatch):
    monkeypatch.delenv("ADEF_HUNT_RULE_GENERATOR", raising=False)
    agent, _ws = _agent(tmp_path)

    with pytest.raises(HuntPromotionError, match="generator"):
        agent.run("H-0001")


def test_mcp_forge_create_clears_catalog_records(tmp_path, monkeypatch):
    """The MCP forge_create tool allocates from the same shared ID space."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    cat = ws / "catalog" / "windows"
    cat.mkdir(parents=True)
    (cat / "D-0003-existing.yml").write_text("id: D-0003\ntitle: existing\n", encoding="utf-8")

    captured = {}

    class FakeServer:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    from adef.mcp.tools.lifecycle_tools import register

    register(FakeServer())
    out = captured["forge_create"](title="New rule", workspace=str(ws))

    assert out["detection_id"] == "D-0004"
