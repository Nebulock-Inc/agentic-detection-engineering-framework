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
from adef.orchestration.refine_chain import _format_payload, _prune_for_journal


def _rec(
    rid: str, title: str, query: str, *,
    platform: str = "windows", mitre: list[str] | None = None,
    data_source: str = "wineventlog",
) -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"rules/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform=platform, kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=mitre if mitre is not None else ["T1218.005"],
        data_source=data_source,
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
    # Free-text fields reach the renderer verbatim and are routinely
    # multi-line — unlike `snippet`, which `MemoryIndex._snippet` already
    # sanitizes with `.replace("\n", " ")`. An embedded newline must not
    # survive into the rendered journal: it would sever the bullet and turn
    # the indented continuation into a markdown code block.
    overlaps[0]["reasoning"] = "selection:\n  Image|endswith: '\\mshta.exe'\ncondition: selection"
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
    # The embedded newlines must not survive into the rendered output: before
    # the fix, "selection:", "Image|endswith...", and "condition: selection"
    # landed on three separate lines, severing the D-0002 bullet and turning
    # the 4-space-indented middle line into a markdown code block. After the
    # fix, all three collapse onto one line.
    query_line = next(line for line in lines if "D-0002" in line)
    assert "selection:" in query_line
    assert "condition: selection" in query_line


def test_the_journal_records_what_was_compared(tmp_path):
    # Inverted deliberately. The predecessor of this test asserted the query
    # was ABSENT — correct while the journal fed the index, wrong now that
    # Refine blocks are excluded by provenance. A log that records *that*
    # D-0002 was shortlisted but not what either rule looked for is a worse
    # log, and it stripped the target's own query from its own journal.
    from adef.core.catalog import Catalog, CatalogRecord
    from adef.orchestration.refine_chain import run_refine_chain

    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")

    def _rec(rid, title, query):
        return CatalogRecord(
            id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
            platform="windows", kind="atomic", engine="sigma", format="sigma",
            query=query, mitre=["T1218.005"],
        )

    for rec in (
        _rec("D-0001", "mshta child process", "TARGETLOGIC process.name = 'mshta.exe'"),
        _rec("D-0002", "mshta spawning child", "NEIGHBOURLOGIC parent.name = 'excel.exe'"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    run_refine_chain(journal=journal, detection_id="D-0001", workspace=ws,
                     similarity_mode="agent")
    body = (ws / "journals" / "D-0001.md").read_text()

    assert "TARGETLOGIC" in body          # what was being refined
    assert "NEIGHBOURLOGIC" in body       # what it was compared against
    assert "snippet" not in body          # redundant with the fields beside it
    from adef.core.journal import GENERATED_MARKER
    assert GENERATED_MARKER in body       # and none of it will be indexed


def test_omitted_keys_are_pruned_at_every_depth():
    # Filtering at each render site left holes — a dict nested inside a list
    # entry reached `_inline` whole and stringified the omitted key back in.
    # `snippet` is the one remaining omitted key (see `_JOURNAL_OMIT_KEYS`) —
    # `query` now reaches the journal deliberately.
    payload = {
        "candidates": [
            {"detection_id": "D-0002", "nested": {"snippet": "SNIPPET_MARKER"}},
        ],
        "target": {"inner": {"snippet": "SNIPPET_MARKER"}},
        "bare_list": [{"snippet": "SNIPPET_MARKER"}],
    }
    body = _format_payload(_prune_for_journal(payload))
    assert "SNIPPET_MARKER" not in body
    assert "D-0002" in body


def test_long_values_are_capped_in_the_rendered_journal():
    # Journals are the BM25 corpus and a human artifact. Rule logic is dropped
    # outright (see the test above), but free-text fields like an LLM judge's
    # `reasoning` still land here and can run long. Cap the rendered form; the
    # caller still gets the value verbatim from the return payload.
    long_text = "the same technique from a different angle, " * 200
    body = _format_payload({"detection_id": "D-0001", "reasoning": long_text})

    rendered = next(line for line in body.splitlines() if "reasoning" in line)
    assert len(rendered) < len(long_text)
    assert rendered.endswith("\u2026")
    # Short values are untouched — the cap must not mangle ordinary output.
    assert "**detection_id:** D-0001" in body


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


def test_mcp_literal_matches_valid_modes():
    """The CLI Choice has a tripwire; the MCP Literal had none, so a fifth mode
    would reach the CLI and silently stay unreachable over MCP."""
    from typing import get_args, get_type_hints

    from adef.agents.rule_similarity import _VALID_SIMILARITY_MODES
    from adef.mcp.tools import agent_tools

    captured = {}

    class _Server:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    agent_tools.register(_Server())
    hints = get_type_hints(captured["refine_chain"])
    assert set(get_args(hints["similarity_mode"])) == _VALID_SIMILARITY_MODES


def test_mcp_refine_chain_keeps_workspace_as_second_positional():
    """`workspace` was the published second positional. Inserting a parameter
    ahead of it binds an existing caller's path to the new one."""
    import inspect

    from adef.mcp.tools import agent_tools

    captured = {}

    class _Server:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn
            return deco

    agent_tools.register(_Server())
    params = list(inspect.signature(captured["refine_chain"]).parameters)
    assert params[:2] == ["detection_id", "workspace"]


def test_scalar_mitre_is_not_exploded_into_characters():
    from adef.agents.rule_similarity import _logic_fields

    assert _logic_fields({"mitre": "T1218.005"})["mitre"] == ["T1218.005"]
    assert _logic_fields({"mitre": ["T1055"]})["mitre"] == ["T1055"]
    assert _logic_fields({})["mitre"] == []


def test_similarity_mode_choice_matches_valid_modes():
    """Single source of truth tripwire: the Choice list stays hardcoded (so
    `--help` keeps a deliberate order instead of a frozenset's random one),
    but it must never silently drift from the agent's canonical mode set."""
    from adef.agents.rule_similarity import _VALID_SIMILARITY_MODES

    refine_cmd = detection_cli.commands["refine"]
    choice_param = next(p for p in refine_cmd.params if p.name == "similarity_mode")
    assert set(choice_param.type.choices) == _VALID_SIMILARITY_MODES


# --------------------------------------------------------------------------- #
# `--similarity-mode agent` prints the shortlist to
# stdout instead of computing it and throwing it away.
# --------------------------------------------------------------------------- #

def _two_rule_workspace(tmp_path: Path, name: str) -> Path:
    """Two catalogued, journalled, near-duplicate detections — enough for
    Similarity's BM25 shortlist to surface D-0002 as D-0001's candidate."""
    ws = tmp_path / name
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in (
        _rec("D-0001", "mshta child process", "TARGETQUERYMARKER process.name = 'mshta.exe'"),
        _rec("D-0002", "mshta child process near dup", "CANDIDATEQUERYMARKER process.name = 'mshta.exe'"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()
    return ws


def test_refine_cli_agent_mode_prints_target_and_candidate_queries(tmp_path: Path):
    ws = _two_rule_workspace(tmp_path, "agent-print-ws")
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    # The target's own query and the candidate's query both land on stdout —
    # the entire point of `agent` mode is comparing the two without a second
    # round trip through `detection show`.
    assert "TARGETQUERYMARKER" in result.output
    assert "CANDIDATEQUERYMARKER" in result.output
    assert "D-0002" in result.output


def test_refine_cli_agent_mode_query_with_brackets_is_not_swallowed_by_rich_markup(
    tmp_path: Path,
):
    """Rich's `console.print` treats `[...]` as markup by default and silently
    drops unrecognized tag-shaped text (found via CodeRabbit review) — a query
    containing a bracketed selector (array index, regex class, KQL/Sigma field
    syntax) must survive verbatim, not vanish from the printed comparison.
    `data_source` gets the same treatment since it's rendered right alongside."""
    ws = tmp_path / "agent-bracket-query-ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in (
        _rec("D-0001", "mshta child process", "process[0].name = 'mshta.exe' [not_a_style_tag]",
             data_source="wineventlog [target_ds_tag]"),
        _rec("D-0002", "mshta child process near dup",
             "process[0].name = 'mshta.exe' [not_a_style_tag_either]",
             data_source="wineventlog [candidate_ds_tag]"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "process[0].name = 'mshta.exe' [not_a_style_tag]" in result.output
    assert "process[0].name = 'mshta.exe' [not_a_style_tag_either]" in result.output
    assert "wineventlog [target_ds_tag]" in result.output
    assert "wineventlog [candidate_ds_tag]" in result.output


def test_refine_cli_agent_mode_bracketed_id_or_title_does_not_crash(tmp_path: Path):
    """A detection id/title containing text shaped like a Rich closing tag
    (e.g. `[/x]`) must not raise `MarkupError` when interpolated into the
    styled shortlist header. `platform` gets the same bracket-shaped value
    since it's rendered on the same styled line."""
    ws = tmp_path / "agent-bracket-header-ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in (
        _rec("D-0001", "mshta child [/oops] process", "TARGETQUERYMARKER",
             platform="windows [/oops]"),
        _rec("D-0002", "mshta child [/oops] process near dup", "CANDIDATEQUERYMARKER",
             platform="windows [/oops]"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "[/oops]" in result.output
    assert "windows [/oops]" in result.output


def test_refine_cli_agent_mode_prints_mitre_platform_and_data_source(tmp_path: Path):
    """Agent mode exists to hand the caller everything it needs to judge
    similarity itself. MITRE/platform/data_source were already in the
    payload and already rendered in the journal — stdout was the only
    surface still dropping them. Technique/platform/data-source alignment is
    usually the first thing a reader checks before reading the full query."""
    ws = tmp_path / "agent-fields-ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in (
        _rec("D-0001", "mshta child process", "TARGETQUERYMARKER",
             platform="windows", mitre=["T1218.005"], data_source="wineventlog_xml"),
        _rec("D-0002", "mshta child process near dup", "CANDIDATEQUERYMARKER",
             platform="linux", mitre=["T1055.001"], data_source="auditd"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    # Target's own fields
    assert "T1218.005" in result.output
    assert "windows" in result.output
    assert "wineventlog_xml" in result.output
    # Candidate's fields — distinct values, so this also proves they're not
    # just the target's fields printed twice.
    assert "T1055.001" in result.output
    assert "linux" in result.output
    assert "auditd" in result.output


def test_refine_cli_agent_mode_omits_absent_fields_rather_than_printing_blank_labels(
    tmp_path: Path,
):
    """An empty mitre/platform/data_source must not render as a dangling
    label (`platform=` with nothing after it) — omit the whole field."""
    ws = tmp_path / "agent-empty-fields-ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in (
        _rec("D-0001", "mshta child process", "TARGETQUERYMARKER",
             platform="", mitre=[], data_source=""),
        _rec("D-0002", "mshta child process near dup", "CANDIDATEQUERYMARKER",
             platform="linux", mitre=["T1055.001"], data_source="auditd"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    # Only the candidate's non-empty fields produced a label — if the
    # target's empty fields also printed a label, these would each appear
    # twice (once blank).
    assert result.output.count("platform=") == 1
    assert result.output.count("data_source=") == 1
    assert result.output.count("mitre=") == 1


def test_refine_cli_agent_mode_long_line_is_not_hard_wrapped(tmp_path: Path):
    """Rich's `console.print` hard-wraps a line exceeding the console width by
    inserting a literal newline (not just a terminal-side visual wrap) unless
    `soft_wrap=True` — found while adding the mitre/platform/data_source line,
    which is long enough to cross the default 80-column width with realistic
    values. A single logical line (query, or the field line) must reach stdout
    as one line verbatim, since an agent reads this output as text, not a
    rendered terminal."""
    ws = tmp_path / "agent-long-line-ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    long_query = "TARGETQUERYMARKER " + "x" * 40 + " = 'mshta.exe' AND y = 'z' " + "w" * 40
    for rec in (
        _rec("D-0001", "mshta child process", long_query,
             platform="a-very-long-platform-name-for-wrap-testing",
             data_source="a-very-long-data-source-name-for-wrap-testing-purposes"),
        _rec("D-0002", "mshta child process near dup", "CANDIDATEQUERYMARKER"),
    ):
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert long_query in result.output
    assert "platform=a-very-long-platform-name-for-wrap-testing  " \
           "data_source=a-very-long-data-source-name-for-wrap-testing-purposes" in result.output


def test_refine_cli_agent_mode_non_numeric_score_does_not_crash(tmp_path: Path, monkeypatch):
    """`score` is always a float from the native agent, but a candidate value
    is caller-shaped data as far as this renderer is concerned (e.g. a
    misbehaving `ADEF_WRAPPER_RULE_SIMILARITY` override). `_fmt_score` falls
    back to `str(score)` for a non-numeric value, and that fallback must be
    escaped too, not just the id/title, before it reaches the styled header."""
    ws = _one_rule_workspace(tmp_path, "agent-bad-score-ws")

    def _spy(journal, detection_id, **context):
        return {
            "similarity": {
                "ok": True,
                "error": None,
                "result": {
                    "detection_id": "D-0001",
                    "result": {
                        "detection_id": "D-0001",
                        "mode_used": "agent",
                        "target": {"title": "t", "query": "TARGETQUERYMARKER"},
                        "candidates": [
                            {"detection_id": "D-0002", "title": "c",
                             "query": "CANDIDATEQUERYMARKER", "score": "[/oops]"},
                        ],
                    },
                },
            }
        }

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "[/oops]" in result.output


def test_refine_cli_bm25_mode_output_is_unchanged(tmp_path: Path):
    ws = _two_rule_workspace(tmp_path, "bm25-unchanged-ws")
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "bm25"],
    )
    assert result.exit_code == 0, result.output
    assert "Refine chain complete" in result.output
    # No shortlist rendering for bm25 — only `agent` mode gets one.
    assert "Similarity shortlist" not in result.output
    assert "TARGETQUERYMARKER" not in result.output
    assert "CANDIDATEQUERYMARKER" not in result.output


def test_refine_cli_agent_mode_prints_nothing_extra_when_similarity_step_is_absent(
    tmp_path: Path, monkeypatch
):
    """Defensive guard: a summary dict with no `similarity` key at all (e.g. a
    future chain change, or a caller-supplied stub) must not raise."""
    ws = _one_rule_workspace(tmp_path, "agent-no-similarity-key-ws")

    def _spy(journal, detection_id, **context):
        return {}

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "Similarity shortlist" not in result.output


def test_refine_cli_agent_mode_prints_nothing_extra_when_similarity_failed(tmp_path: Path):
    """A journal-only detection (no catalog record yet) makes Similarity fail
    with `ok: False` via the real chain — no mocking of our own code."""
    ws = tmp_path / "agent-no-catalog-ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    Journal(ws / "journals").create(detection_id="D-0001", title="journal-only")

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "Similarity shortlist" not in result.output


def test_refine_cli_agent_mode_does_not_render_a_failed_steps_stale_result(
    tmp_path: Path, monkeypatch
):
    """`ok: False` must gate rendering even if `result` is (or looks like) a
    well-formed agent-mode payload — e.g. a stale value left over from a
    partial retry. The other structural guards (dict/mode_used checks) do
    not catch this on their own, so this pins the `ok` check specifically."""
    ws = _one_rule_workspace(tmp_path, "agent-ok-false-ws")

    def _spy(journal, detection_id, **context):
        return {
            "similarity": {
                "ok": False,
                "error": "stale",
                "result": {
                    "detection_id": "D-0001",
                    "result": {
                        "detection_id": "D-0001",
                        "mode_used": "agent",
                        "target": {"title": "t", "query": "SHOULD_NOT_RENDER"},
                        "candidates": [],
                    },
                },
            }
        }

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "Similarity shortlist" not in result.output
    assert "SHOULD_NOT_RENDER" not in result.output


def test_refine_cli_agent_mode_prints_nothing_extra_when_wrapper_override_changes_mode(
    tmp_path: Path, monkeypatch
):
    """An explicitly configured `ADEF_WRAPPER_RULE_SIMILARITY` can return
    whatever shape its upstream class wants — here, one that ran a different
    mode but (coincidentally) still carries a well-formed `target`, to pin
    the `mode_used` check specifically rather than relying on the
    target/candidates type guards to reject it for an unrelated reason.
    Must not raise or misrender."""
    import sys
    import types

    ws = _one_rule_workspace(tmp_path, "agent-wrapper-override-ws")

    class _FakeUpstream:
        def run(self, **kwargs):
            return {
                "mode_used": "bm25_fallback",
                "target": {"title": "t", "query": "SHOULD_NOT_RENDER_EITHER"},
                "candidates": [],
            }

    fake_module = types.ModuleType("fake_upstream_similarity_for_part_a")
    fake_module.FakeUpstream = _FakeUpstream
    monkeypatch.setitem(sys.modules, "fake_upstream_similarity_for_part_a", fake_module)
    monkeypatch.setenv(
        "ADEF_WRAPPER_RULE_SIMILARITY", "fake_upstream_similarity_for_part_a:FakeUpstream"
    )

    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "Similarity shortlist" not in result.output
    assert "SHOULD_NOT_RENDER_EITHER" not in result.output


def test_refine_cli_agent_mode_prints_nothing_extra_when_agent_payload_is_malformed(
    tmp_path: Path, monkeypatch
):
    """`mode_used == "agent"` with a missing/malformed `target` or
    `candidates` (e.g. a future agent-code regression) must not crash the
    CLI — pins the final structural guard specifically."""
    ws = _one_rule_workspace(tmp_path, "agent-malformed-payload-ws")

    def _spy(journal, detection_id, **context):
        return {
            "similarity": {
                "ok": True,
                "error": None,
                "result": {
                    "detection_id": "D-0001",
                    "result": {
                        "detection_id": "D-0001",
                        "mode_used": "agent",
                        "target": None,
                        "candidates": "not-a-list",
                    },
                },
            }
        }

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert "Similarity shortlist" not in result.output


def test_refine_cli_names_a_failed_step_instead_of_reporting_success(
    tmp_path: Path, monkeypatch
):
    """A non-aborting chain must not report an unconditional green success.

    Both chains deliberately keep going past a failed step, because a partial
    result is worth having — but the CLI printed "chain complete" either way.
    The failure was then visible only in the journal block, and on stdout the
    one symptom was an empty summary, which is exactly what the far more
    common `insufficient-data` looks like.
    """
    ws = _two_rule_workspace(tmp_path, "failed-step-ws")

    def _spy(**kwargs):
        return {
            "similarity": {"ok": True, "result": {}, "error": None},
            "overlap": {"ok": False, "result": None, "error": "INDEX.yml is unreadable"},
            "verification": {"ok": True, "result": {}, "error": None},
        }

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli, ["refine", "D-0001", "--workspace", str(ws)]
    )
    assert result.exit_code == 0, result.output
    assert "overlap failed" in result.output, result.output
    assert "INDEX.yml is unreadable" in result.output, result.output
    assert "1 failed step" in result.output, result.output
    # Deliberately substring-safe: "finished with…" does not contain the
    # success phrase, so this assertion means what it says.
    # The success line is the thing that must NOT appear.
    assert "Refine chain complete" not in result.output, result.output
