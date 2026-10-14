"""End-to-end: drive a detection through the whole FORGE lifecycle via the CLI
and assert the journal reads coherently — the durable-memory selling point.

Covers the usability fixes from the 2026-07-22 journaling pass:
- refine writes clean "couldn't run, and why" notes, NOT Python tracebacks;
- stage blocks are lean (no re-printed prompt prose duplicating the template);
- repeatable --note renders as a bullet list;
- `updated` advances; stages appear in order.
"""

from __future__ import annotations

import time

import pytest
from click.testing import CliRunner

from adef.commands.detection import detection as detection_cli
from adef.core.journal import Journal, workspace_journals_dir


@pytest.fixture
def ws(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    return ws


def _run(*args):
    r = CliRunner().invoke(detection_cli, list(args))
    assert r.exit_code == 0, r.output
    return r


def test_full_forge_lifecycle_reads_coherently(ws):
    _run("new", "Suspicious mshta child process", "--owner", "alice")
    _run("observe", "D-0001",
         "--note", "Baseline: mshta-from-office ~3/day",
         "--note", "FP source: legit admin GPO scripts")
    _run("refine", "D-0001", "--note", "no existing rule; overlap low")
    _run("govern", "D-0001", "--note", "prod ring 1")
    _run("evolve", "D-0001", "--note", "30d: 0 FPs, keep")

    text = (ws / "journals" / "D-0001.md").read_text()

    # Stages appear, in order.
    order = [text.index(f"Stage: {s}") for s in ("find", "observe", "refine", "govern", "evolve")]
    assert order == sorted(order)

    # Notes landed; repeatable --note became a bullet list.
    assert "- Baseline: mshta-from-office ~3/day" in text
    assert "- FP source: legit admin GPO scripts" in text
    assert "prod ring 1" in text

    # THE regression that started the pass: no Python traceback in the journal
    # when a refine step can't run. Since the chain went native, the default
    # reason is no longer "unconfigured wrapper" but "this detection is still
    # journal-only" (`detection new` without `--source` mints no catalog
    # record) — the clean one-liner must still say so in prose.
    assert "Traceback" not in text
    assert "no catalog record for D-0001 yet (still journal-only)" in text

    # Lean blocks: the stage-guidance prose is NOT re-printed per block (it lives
    # in the template's fill-in sections). "Capture, in order:" was the old
    # find-prompt prose that used to be duplicated into the block.
    assert "Capture, in order:" not in text


def test_updated_timestamp_advances(ws, monkeypatch):
    _run("new", "X")
    j = Journal(workspace_journals_dir(None))
    created = j.read("D-0001").frontmatter["updated"]
    time.sleep(1.05)  # _now_iso is second-resolution
    _run("observe", "D-0001", "--note", "later")
    assert j.read("D-0001").frontmatter["updated"] > created


def test_stage_command_refuses_a_backward_move_without_back(ws):
    _run("new", "t")
    _run("govern", "D-0001")
    r = CliRunner().invoke(detection_cli, ["observe", "D-0001", "--note", "late"])
    assert r.exit_code != 0
    assert "--back" in r.output
    assert Journal(workspace_journals_dir(ws)).read("D-0001").current_stage == "govern"
    _run("observe", "D-0001", "--back", "--note", "re-baselining after a log change")
    assert Journal(workspace_journals_dir(ws)).read("D-0001").current_stage == "observe"
