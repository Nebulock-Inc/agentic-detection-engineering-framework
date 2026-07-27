"""Tests for `adef install-skills` — copy bundled skills into a .claude/ tree."""

from __future__ import annotations

from pathlib import Path

import pytest

from adef.commands.install_skills import InstallSkillsError, copy_skills


def _fake_source(tmp_path: Path) -> Path:
    """A stand-in claude-plugin/ dir with two skills + one agent."""
    src = tmp_path / "claude-plugin"
    for name in ("alpha", "beta"):
        d = src / "skills" / name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(f"---\nname: {name}\n---\nbody\n", encoding="utf-8")
    (src / "agents").mkdir()
    (src / "agents" / "helper.md").write_text("agent\n", encoding="utf-8")
    return src


def test_copies_skills_and_agents(tmp_path):
    src = _fake_source(tmp_path)
    dest = tmp_path / ".claude"
    result = copy_skills(src, dest)
    assert (dest / "skills" / "alpha" / "SKILL.md").is_file()
    assert (dest / "skills" / "beta" / "SKILL.md").is_file()
    assert (dest / "agents" / "helper.md").is_file()
    assert set(result.skills) == {"alpha", "beta"}
    assert result.agents == ["helper"]


def test_refuses_to_clobber_without_force(tmp_path):
    src = _fake_source(tmp_path)
    dest = tmp_path / ".claude"
    copy_skills(src, dest)                       # first install
    # a user-edited skill already present
    (dest / "skills" / "alpha" / "SKILL.md").write_text("MINE\n", encoding="utf-8")
    with pytest.raises(InstallSkillsError, match="already"):
        copy_skills(src, dest)                   # second install → refuse
    assert (dest / "skills" / "alpha" / "SKILL.md").read_text() == "MINE\n"  # untouched


def test_force_overwrites(tmp_path):
    src = _fake_source(tmp_path)
    dest = tmp_path / ".claude"
    copy_skills(src, dest)
    (dest / "skills" / "alpha" / "SKILL.md").write_text("MINE\n", encoding="utf-8")
    copy_skills(src, dest, force=True)
    assert "body" in (dest / "skills" / "alpha" / "SKILL.md").read_text()  # refreshed


def test_missing_source_raises(tmp_path):
    with pytest.raises(InstallSkillsError, match="no bundled skills"):
        copy_skills(tmp_path / "nope", tmp_path / ".claude")


# --------------------------------------------------------------------------- #
# CLI: flags skip the prompt; bare prompts; agent → dot-dir mapping
# --------------------------------------------------------------------------- #
def test_cli_flags_skip_prompt_and_map_agent(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from adef.commands.install_skills import install_skills

    monkeypatch.chdir(tmp_path)
    # --agent given → no prompt; chatgpt maps to .agents/
    result = CliRunner().invoke(install_skills, ["--agent", "chatgpt"], input="")
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".agents" / "skills").is_dir()      # chatgpt convention
    assert not (tmp_path / ".claude").exists()             # not claude's dir
    assert "chatgpt" in result.output


def test_cli_bare_prompts(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from adef.commands.install_skills import install_skills

    monkeypatch.chdir(tmp_path)
    # bare → two numbered menus: "1" (claude), "1" (this project) → ./.claude/
    result = CliRunner().invoke(install_skills, [], input="1\n1\n")
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".claude" / "skills").is_dir()


def test_cli_prompt_menu_by_number_picks_codex(tmp_path, monkeypatch):
    """Numbered menu: '2' for the agent → codex → .agents/; '2' → user-wide off
    the table, so pick '1' (project)."""
    from click.testing import CliRunner

    from adef.commands.install_skills import install_skills

    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(install_skills, [], input="2\n1\n")  # codex, project
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".agents" / "skills").is_dir()
    assert not (tmp_path / ".claude").exists()


def test_chatgpt_flag_alias_maps_to_agents(tmp_path, monkeypatch):
    """chatgpt stays valid on the flag path (alias for codex → .agents/)."""
    from click.testing import CliRunner

    from adef.commands.install_skills import install_skills

    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(install_skills, ["--agent", "chatgpt"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".agents" / "skills").is_dir()
