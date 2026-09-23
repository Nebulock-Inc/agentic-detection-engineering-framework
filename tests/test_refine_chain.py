"""Refine-chain regressions: workspace plumbing and journal readability.

Both cover failures that every other test in the suite is structurally blind to:
the existing tests set `ADEF_WORKSPACE` and `--workspace` to the *same* path (so
dropping one is invisible), and none of them render a multi-item result set.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from adef.commands.detection import detection as detection_cli
from adef.core.catalog import Catalog, CatalogRecord
from adef.core.journal import Journal
from adef.orchestration.refine_chain import _format_payload


def _rec(rid: str, title: str, query: str) -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"rules/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=["T1218.005"], data_source="wineventlog",
    )


def test_workspace_option_wins_over_adef_workspace_env(tmp_path: Path, monkeypatch):
    """`--workspace` must reach the native agents, not just the journal writer.

    The env workspace deliberately holds NO catalog record and the `--workspace`
    one does, so a dropped `workspace` kwarg is unmistakable: the chain would
    report "no catalog record" against a detection that plainly has one.
    """
    env_ws = tmp_path / "env-ws"
    (env_ws / "journals").mkdir(parents=True)
    (env_ws / "catalog").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(env_ws))

    flag_ws = tmp_path / "flag-ws"
    (flag_ws / "journals").mkdir(parents=True)
    (flag_ws / "catalog").mkdir(parents=True)
    cat = Catalog(flag_ws)
    journal = Journal(flag_ws / "journals")
    for rec in (
        _rec("D-0001", "mshta child process", "process.name='mshta.exe'"),
        _rec("D-0002", "mshta child process near dup", "process.name = 'mshta.exe'"),
    ):
        cat.write_raw(flag_ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(flag_ws), "--similarity-mode", "bm25"],
    )
    assert result.exit_code == 0, result.output

    text = (flag_ws / "journals" / "D-0001.md").read_text()
    refine_block = text[text.index("### Refine / Similarity"):]
    # Read the --workspace catalog: real findings, not the env workspace's void.
    assert "no catalog record" not in refine_block
    assert "D-0002" in refine_block          # Similarity found its neighbour
    assert "overlap_type" in refine_block    # Overlap classified the pair
    assert "passed" in refine_block          # Verification ran
    # The env workspace was never touched as a journal target.
    assert not list((env_ws / "journals").glob("D-*.md"))


def test_mcp_refine_chain_tool_honors_workspace_arg_over_env(tmp_path: Path, monkeypatch):
    """The MCP `refine_chain` tool must forward `workspace` too — it has the

    same env-vs-arg divergence as the CLI (fixed above), but in a second,
    independent caller of `run_refine_chain` that the CLI fix doesn't cover.
    """
    from adef.mcp.tools.agent_tools import register

    env_ws = tmp_path / "mcp-env-ws"
    (env_ws / "journals").mkdir(parents=True)
    (env_ws / "catalog").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(env_ws))

    arg_ws = tmp_path / "mcp-arg-ws"
    (arg_ws / "journals").mkdir(parents=True)
    (arg_ws / "catalog").mkdir(parents=True)
    cat = Catalog(arg_ws)
    journal = Journal(arg_ws / "journals")
    rec = _rec("D-0001", "mshta child process", "process.name='mshta.exe'")
    cat.write_raw(arg_ws / "catalog" / "D-0001.yml", rec.to_yaml_dict())
    journal.create(detection_id="D-0001", title=rec.title)
    # A second, near-duplicate record so Similarity has a neighbor to shortlist
    # — the tool's default `agent` mode needs a candidate to enrich in order to
    # assert the enriched fields actually reach an MCP caller (below).
    rec2 = _rec("D-0002", "mshta child process near dup", "process.name = 'mshta.exe'")
    cat.write_raw(arg_ws / "catalog" / "D-0002.yml", rec2.to_yaml_dict())
    journal.create(detection_id="D-0002", title=rec2.title)
    cat.rebuild_index()

    class _FakeServer:
        def __init__(self) -> None:
            self.tools: dict[str, object] = {}

        def tool(self):
            def deco(fn):
                self.tools[fn.__name__] = fn
                return fn

            return deco

    server = _FakeServer()
    register(server)
    result = server.tools["refine_chain"](detection_id="D-0001", workspace=str(arg_ws))

    for step in ("similarity", "overlap", "verification"):
        assert result[step]["error"] is None, f"{step}: {result[step]['error']}"
    text = (arg_ws / "journals" / "D-0001.md").read_text()
    assert "no catalog record" not in text.lower()
    assert not list((env_ws / "journals").glob("D-*.md"))
    # This tool defaults to `agent` mode — pin that the enriched `query` field
    # actually survives the wrapper envelope, chain summary, and `_to_dict`
    # round-trip to reach an MCP caller, not just the agent's own return value.
    candidates = result["similarity"]["result"]["result"]["candidates"]
    assert candidates and candidates[0]["query"]


def test_mcp_refine_chain_defaults_to_agent_mode(tmp_path: Path, monkeypatch):
    # An MCP caller IS an agent by definition. Ranking internally there is
    # strictly wasteful — it pays a second model to do work the caller is
    # better positioned to do with more context. This default differs from the
    # CLI's `bm25` ON PURPOSE: the split is by entry point, which is knowable,
    # never by sniffing the environment.
    from adef.mcp.tools.agent_tools import register

    ws = _one_rule_workspace(tmp_path, "mcp-default-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.mcp.tools.agent_tools.run_refine_chain", _spy)

    class _FakeServer:
        def __init__(self) -> None:
            self.tools: dict[str, object] = {}

        def tool(self):
            def deco(fn):
                self.tools[fn.__name__] = fn
                return fn

            return deco

    server = _FakeServer()
    register(server)
    server.tools["refine_chain"](detection_id="D-0001", workspace=str(ws))

    assert captured, "spy never called; check the patch target"
    assert captured["similarity_mode"] == "agent"


def test_mcp_refine_chain_honors_an_explicit_mode(tmp_path: Path, monkeypatch):
    from adef.mcp.tools.agent_tools import register

    ws = _one_rule_workspace(tmp_path, "mcp-explicit-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.mcp.tools.agent_tools.run_refine_chain", _spy)

    class _FakeServer:
        def __init__(self) -> None:
            self.tools: dict[str, object] = {}

        def tool(self):
            def deco(fn):
                self.tools[fn.__name__] = fn
                return fn

            return deco

    server = _FakeServer()
    register(server)
    server.tools["refine_chain"](
        detection_id="D-0001", similarity_mode="bm25", workspace=str(ws)
    )

    assert captured, "spy never called; check the patch target"
    assert captured["similarity_mode"] == "bm25"


def test_format_payload_keeps_lines_readable_for_many_overlaps():
    """A list-of-dicts must not collapse into one multi-thousand-char line.

    Guards the *wrapper envelope* shape the chain actually renders — the long
    value is nested under `result`, so a fix that only unpacks top-level lists
    would still emit the giant line this asserts against.
    """
    overlaps = [
        {
            "other_id": f"D-{i:04d}",
            "overlap_type": "duplicate",
            "confidence": 0.9,
            "reasoning": "Identical query logic after normalization",
        }
        for i in range(2, 9)
    ]
    # `agent` mode's candidate `query` field is stored verbatim
    # (`CatalogRecord.query`) and is multi-line Sigma/SQL in practically
    # every real record — unlike `snippet`, which `MemoryIndex._snippet`
    # already sanitizes with `.replace("\n", " ")`. An embedded newline here
    # must not survive into the rendered journal: it would sever the bullet
    # and turn indented query text into a markdown code block.
    overlaps[0]["query"] = "selection:\n  Image|endswith: '\\mshta.exe'\ncondition: selection"
    payload = {
        "detection_id": "D-0001",
        "result": {"detection_id": "D-0001", "techniques": ["T1218.005"], "overlaps": overlaps},
    }

    body = _format_payload(payload)
    lines = body.splitlines()
    assert max(len(line) for line in lines) <= 500
    # Every entry is legible on its own line, and none were dropped.
    for entry in overlaps:
        assert sum(1 for line in lines if entry["other_id"] in line) == 1
    # The embedded newlines in overlaps[0]'s query must not survive into the
    # rendered output: before the fix, "selection:", "Image|endswith...", and
    # "condition: selection" landed on three separate lines, severing the
    # D-0002 bullet and turning the 4-space-indented middle line into a
    # markdown code block. After the fix, all three collapse onto one line.
    query_line = next(line for line in lines if "D-0002" in line)
    assert "selection:" in query_line
    assert "condition: selection" in query_line


@pytest.mark.parametrize("value", [[], [1, 2, 3], {}])
def test_format_payload_leaves_non_dict_collections_alone(value):
    """Only lists *of dicts* get the sub-bullet treatment — the plain-value
    rendering other steps rely on is unchanged."""
    assert _format_payload({"k": value}) == f"- **k:** {value}"


def _one_rule_workspace(tmp_path: Path, name: str) -> Path:
    """A workspace with one catalogued, journalled detection — the minimum the
    refine chain needs to run without reporting 'no catalog record'."""
    ws = tmp_path / name
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat = Catalog(ws)
    journal = Journal(ws / "journals")
    rec = _rec("D-0001", "mshta child process", "process.name='mshta.exe'")
    cat.write_raw(ws / "catalog" / "D-0001.yml", rec.to_yaml_dict())
    journal.create(detection_id="D-0001", title=rec.title)
    cat.rebuild_index()
    return ws


def test_refine_cli_defaults_to_bm25(tmp_path: Path, monkeypatch):
    # The agentic promise is fulfilled by an agent CALLING adef, not by adef
    # quietly calling a model on the user's behalf. Opt in to spend money and
    # egress; do not opt out. An API key in the environment must not change
    # what the CLI does by default.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    ws = _one_rule_workspace(tmp_path, "cli-default-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli, ["refine", "D-0001", "--workspace", str(ws)]
    )
    assert result.exit_code == 0, result.output
    assert captured["similarity_mode"] == "bm25"


def test_refine_cli_accepts_agent_mode(tmp_path: Path, monkeypatch):
    ws = _one_rule_workspace(tmp_path, "cli-agent-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert captured["similarity_mode"] == "agent"


def test_refine_cli_rejects_an_unknown_mode(tmp_path: Path):
    ws = _one_rule_workspace(tmp_path, "cli-bad-mode-ws")
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "nope"],
    )
    assert result.exit_code != 0
    assert "nope" in result.output


def test_run_refine_chain_defaults_to_bm25_when_similarity_mode_omitted(
    tmp_path: Path, monkeypatch
):
    """The hole lives at the orchestration layer, not the agent layer.

    `run_refine_chain` never names `similarity_mode` — it forwards `**context`
    opaquely — so "deterministic by default" held only because the CLI and MCP
    entry points both happen to pass the mode explicitly. A third, hypothetical
    caller of `run_refine_chain` with no `similarity_mode` in context must still
    land on `bm25`, even with an API key present, because the *agent's own*
    default (`adef/agents/rule_similarity.py`) is the actual backstop. A unit
    test on the agent alone would not catch a regression here.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    ws = _one_rule_workspace(tmp_path, "orchestration-default-ws")
    journal = Journal(ws / "journals")

    from adef.orchestration.refine_chain import run_refine_chain

    summary = run_refine_chain(journal=journal, detection_id="D-0001", workspace=ws)

    assert summary["similarity"]["result"]["result"]["mode_used"] == "bm25"
    text = (ws / "journals" / "D-0001.md").read_text()
    similarity_block = text[text.index("### Refine / Similarity"):text.index("### Refine / Overlap")]
    assert "bm25" in similarity_block


def test_similarity_mode_choice_matches_valid_modes():
    """Single source of truth tripwire: the Choice list stays hardcoded (so
    `--help` keeps a deliberate order instead of a frozenset's random one),
    but it must never silently drift from the agent's canonical mode set."""
    from adef.agents.rule_similarity import _VALID_SIMILARITY_MODES

    refine_cmd = detection_cli.commands["refine"]
    choice_param = next(p for p in refine_cmd.params if p.name == "similarity_mode")
    assert set(choice_param.type.choices) == _VALID_SIMILARITY_MODES
