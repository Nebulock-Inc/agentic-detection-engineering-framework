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


@pytest.mark.parametrize("value", [[], [1, 2, 3], {}])
def test_format_payload_leaves_non_dict_collections_alone(value):
    """Only lists *of dicts* get the sub-bullet treatment — the plain-value
    rendering other steps rely on is unchanged."""
    assert _format_payload({"k": value}) == f"- **k:** {value}"
