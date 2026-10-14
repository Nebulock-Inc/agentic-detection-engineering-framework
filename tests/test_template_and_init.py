"""Unit tests — DETECTION_FORGE template + ``adef init`` scaffolding."""

from __future__ import annotations

from importlib import resources

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.init import init


def test_template_has_all_forge_headings():
    text = (
        resources.files("adef.data.templates")
        .joinpath("DETECTION_FORGE.md")
        .read_text(encoding="utf-8")
    )
    for stage in ("Find", "Observe", "Refine", "Govern", "Evolve"):
        assert f"## {stage}" in text, f"template missing ## {stage} heading"


def test_template_frontmatter_keys_present():
    text = (
        resources.files("adef.data.templates")
        .joinpath("DETECTION_FORGE.md")
        .read_text(encoding="utf-8")
    )
    assert text.startswith("---")
    fm_text = text.split("---", 2)[1]
    fm = yaml.safe_load(fm_text)
    expected = {"id", "title", "status", "current_stage", "owner", "rule_uuid", "created", "updated"}
    assert expected <= set(fm.keys())


def test_init_honors_adef_workspace_env(tmp_path, monkeypatch):
    # `adef init` with no PATH must scaffold at $ADEF_WORKSPACE — parity with every
    # other command — not the hardcoded ~/work/adef-workspace.
    target = tmp_path / "env-ws"
    monkeypatch.setenv("ADEF_WORKSPACE", str(target))
    result = CliRunner().invoke(init, [])
    assert result.exit_code == 0, result.output
    assert (target / "journals").is_dir(), f"init did not scaffold at ADEF_WORKSPACE: {result.output}"


# --------------------------------------------------------------------------- #
# Guided interactive setup (journey routing, capabilities, skills chaining)
# --------------------------------------------------------------------------- #
def _run_interactive(tmp_path, answers, workspace_name="ws", chdir=None):
    runner = CliRunner()
    workspace = tmp_path / workspace_name
    result = runner.invoke(init, [str(workspace), "--interactive"], input=answers)
    return result, workspace


def test_interactive_journey_repo_routes_to_catalog_and_sync(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # journey 1, default platform, default QL, no skills install
    result, ws = _run_interactive(tmp_path, "1\n\n\nn\n")
    assert result.exit_code == 0, result.output
    assert "adef catalog /path/to/your/rules" in result.output
    assert "adef sync" in result.output
    assert "git init" not in result.output  # repo teams already have durability


def test_interactive_journey_siem_only_gets_durability_guidance(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result, ws = _run_interactive(tmp_path, "2\n\n\nn\n")
    assert result.exit_code == 0, result.output
    assert "adef catalog /path/to/export" in result.output
    assert "git init" in result.output  # printed instructions, never executed
    assert "detection-home.md" in result.output
    assert not (ws / ".git").exists()


def test_interactive_journey_fresh_routes_to_schema_flow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result, ws = _run_interactive(tmp_path, "3\nsentinel\nkql\nn\n")
    assert result.exit_code == 0, result.output
    assert "adef schema recipe sentinel" in result.output
    assert "adef schema reshape" in result.output
    assert '--source' in result.output
    assert "git init" in result.output
    config = yaml.safe_load((ws / "config" / ".adefconfig.yaml").read_text())
    assert config["platform"] == "sentinel"
    assert config["query_languages"] == ["kql"]


def test_interactive_reports_capabilities_and_env_hint(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Force the not-installed branch: whether the dev env has `[mcp]` must not
    # decide which half of this test runs.
    monkeypatch.setattr("adef.commands.init._mcp_installed", lambda: False)
    monkeypatch.setattr("adef.core.doctor.editable_install", lambda: False)
    result, ws = _run_interactive(tmp_path, "1\n\n\nn\n")
    assert result.exit_code == 0, result.output
    assert "MCP server" in result.output  # detected either way, never silent
    # the extra must render, not be eaten as markup
    assert "agentic-detection-engineering-framework[mcp]" in result.output
    assert "adef install-skills" in result.output
    assert "inactive until installed" in result.output
    # non-default workspace path → resolver hint
    assert f"export ADEF_WORKSPACE={ws}" in result.output


def test_interactive_skills_chaining_installs_on_yes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # journey 1, defaults, YES to skills, then install-skills menu defaults
    # (1 = Claude Code, 1 = project-local → ./.claude/skills under cwd)
    result, ws = _run_interactive(tmp_path, "1\n\n\ny\n1\n1\n")
    assert result.exit_code == 0, result.output
    assert "Installed" in result.output
    assert (tmp_path / ".claude" / "skills").is_dir()


@pytest.mark.integration
def test_adef_init_scaffolds_workspace(tmp_path):
    runner = CliRunner()
    workspace = tmp_path / "ws"
    result = runner.invoke(init, [str(workspace)])
    assert result.exit_code == 0, result.output

    assert (workspace / "journals").is_dir()
    assert (workspace / "config" / ".adefconfig.yaml").exists()
    assert (workspace / "templates" / "DETECTION_FORGE.md").exists()
    agents_md = (workspace / "AGENTS.md").read_text()
    assert "methodology.md" in agents_md
    assert "maturity-model.md" in agents_md


def test_force_never_clobbers_config(tmp_path, monkeypatch):
    """--force refreshes scaffolding (AGENTS.md, templates), never user
    settings — it previously overwrote config with the commented default,
    silently wiping the interactive platform (bit live, 2026-07-24)."""
    monkeypatch.chdir(tmp_path)
    ws = tmp_path / "ws"
    runner = CliRunner()
    r = runner.invoke(init, [str(ws), "--interactive"], input="1\nsentinel\nkql\nn\n")
    assert r.exit_code == 0, r.output
    assert yaml.safe_load((ws / "config" / ".adefconfig.yaml").read_text())["platform"] == "sentinel"

    r = runner.invoke(init, [str(ws), "--force"])
    assert r.exit_code == 0, r.output
    config = yaml.safe_load((ws / "config" / ".adefconfig.yaml").read_text())
    assert config["platform"] == "sentinel"  # survived --force
    assert config["query_languages"] == ["kql"]


def test_interactive_answers_persist_without_force(tmp_path, monkeypatch):
    """Re-running --interactive on an existing workspace must persist the new
    answers (previously discarded unless --force was also passed) and keep
    keys it didn't prompt for."""
    monkeypatch.chdir(tmp_path)
    ws = tmp_path / "ws"
    runner = CliRunner()
    assert runner.invoke(init, [str(ws)]).exit_code == 0
    # hand-added key a user might have set
    cfg_path = ws / "config" / ".adefconfig.yaml"
    data = yaml.safe_load(cfg_path.read_text())
    data["rule_root"] = "~/rules"
    cfg_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    r = runner.invoke(init, [str(ws), "--interactive"], input="1\nsplunk\nspl\nn\n")
    assert r.exit_code == 0, r.output
    config = yaml.safe_load(cfg_path.read_text())
    assert config["platform"] == "splunk"      # new answer persisted
    assert config["rule_root"] == "~/rules"    # unprompted key survived the merge
