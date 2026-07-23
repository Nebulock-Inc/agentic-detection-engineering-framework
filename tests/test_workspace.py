"""Tests for the canonical workspace resolver (ISA 2026-07-22 guardrail audit).

The bug: three divergent resolvers meant `adef catalog .` then `adef coverage`
in the same dir could read *different* workspaces, and read commands silently
mkdir'd the default workspace. All resolution now routes through
`resolve_workspace`; read paths pass `create=False`.
"""

from __future__ import annotations

from pathlib import Path

from adef.core.journal import workspace_journals_dir
from adef.core.workspace import resolve_workspace


def test_explicit_and_env_and_default(tmp_path, monkeypatch):
    monkeypatch.delenv("ADEF_WORKSPACE", raising=False)
    # explicit wins
    assert resolve_workspace(tmp_path / "x") == (tmp_path / "x").resolve()
    # env next
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "envws"))
    assert resolve_workspace(None) == (tmp_path / "envws").resolve()


def test_cwd_marker_is_catalog_or_journals(tmp_path, monkeypatch):
    """cwd is picked when it has EITHER catalog/ or journals/ — the divergence
    that bit us was journals-only vs catalog-or-journals."""
    monkeypatch.delenv("ADEF_WORKSPACE", raising=False)
    proj = tmp_path / "proj"
    (proj / "catalog").mkdir(parents=True)  # catalog only, no journals
    monkeypatch.chdir(proj)
    assert resolve_workspace(None) == proj.resolve()


def test_journals_dir_agrees_with_resolver(tmp_path, monkeypatch):
    """workspace_journals_dir must resolve to the SAME workspace as
    resolve_workspace — a catalog-only cwd used to send them to different dirs."""
    monkeypatch.delenv("ADEF_WORKSPACE", raising=False)
    proj = tmp_path / "proj"
    (proj / "catalog").mkdir(parents=True)
    monkeypatch.chdir(proj)
    assert workspace_journals_dir(None, create=False).parent == resolve_workspace(None)


def test_read_path_does_not_scaffold(tmp_path, monkeypatch):
    """create=False must not mkdir — a list/coverage from the wrong dir shouldn't
    materialize the default workspace as a side effect."""
    ws = tmp_path / "nope"
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    journals = workspace_journals_dir(None, create=False)
    assert not journals.exists()  # nothing created
    # create=True (write path) does make it
    journals2 = workspace_journals_dir(None, create=True)
    assert journals2.exists()
