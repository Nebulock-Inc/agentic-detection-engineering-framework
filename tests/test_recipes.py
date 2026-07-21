"""Tests for SIEM recipes (adef/core/recipes.py), the `adef schema recipe`
CLI, and the schema MCP tools (adef/mcp/tools/schema_tools.py)."""

from __future__ import annotations

import json

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.schema import schema as schema_cli
from adef.core.recipes import RECIPES, get_recipe, list_platforms, render_recipe_markdown
from adef.mcp.tools import schema_tools


# --------------------------------------------------------------------------- #
# Core: get_recipe / render_recipe_markdown
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("platform", sorted(RECIPES))
def test_get_recipe_known_platforms(platform):
    recipe = get_recipe(platform)
    assert recipe.platform
    assert recipe.query_language
    assert recipe.command
    assert recipe.reshaping_guide


def test_get_recipe_is_case_insensitive():
    assert get_recipe("SPLUNK").platform == get_recipe("splunk").platform


def test_get_recipe_unknown_platform_lists_supported():
    with pytest.raises(ValueError, match="crowdstrike"):
        get_recipe("crowdstrike")
    with pytest.raises(ValueError, match="splunk"):
        get_recipe("crowdstrike")


def test_list_platforms_sorted():
    assert list_platforms() == sorted(RECIPES)


@pytest.mark.parametrize("platform", sorted(RECIPES))
def test_render_recipe_markdown(platform):
    recipe = get_recipe(platform)
    md = render_recipe_markdown(recipe)
    assert md.startswith(f"# {recipe.platform} Field Extraction Recipe")
    assert recipe.command in md
    assert "adef schema ingest" in md  # next-steps link


# --------------------------------------------------------------------------- #
# CLI: adef schema recipe
# --------------------------------------------------------------------------- #
def _workspace_with_platform(tmp_path, platform):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".adefconfig.yaml").write_text(
        yaml.safe_dump({"platform": platform}), encoding="utf-8"
    )
    return tmp_path


def test_cli_recipe_explicit_platform():
    result = CliRunner().invoke(schema_cli, ["recipe", "sentinel"])
    assert result.exit_code == 0
    assert "Sentinel" in result.output
    assert "getschema" in result.output


def test_cli_recipe_json_format():
    result = CliRunner().invoke(schema_cli, ["recipe", "qradar", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["query_language"] == "aql"


def test_cli_recipe_unknown_platform_errors():
    result = CliRunner().invoke(schema_cli, ["recipe", "crowdstrike"])
    assert result.exit_code != 0
    assert "Unknown platform" in result.output


def test_cli_recipe_reads_platform_from_workspace_config(tmp_path):
    ws = _workspace_with_platform(tmp_path, "elastic")
    result = CliRunner().invoke(schema_cli, ["recipe", "--workspace", str(ws)])
    assert result.exit_code == 0
    assert "Elastic" in result.output


# --------------------------------------------------------------------------- #
# MCP tools
# --------------------------------------------------------------------------- #
class _FakeServer:
    """Captures functions registered via @server.tool()."""

    def __init__(self):
        self.tools = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


@pytest.fixture()
def mcp_tools():
    server = _FakeServer()
    schema_tools.register(server)
    return server.tools


def test_mcp_schema_recipe_explicit_platform(mcp_tools):
    result = mcp_tools["schema_recipe"]("splunk")
    assert result["query_language"] == "spl"
    assert "fieldsummary" in result["recipe_markdown"]


def test_mcp_schema_recipe_unknown_platform(mcp_tools):
    result = mcp_tools["schema_recipe"]("crowdstrike")
    assert "error" in result


def test_mcp_schema_recipe_unconfigured_returns_platforms_not_a_guess(
    mcp_tools, tmp_path, monkeypatch
):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))  # no config file
    result = mcp_tools["schema_recipe"](None)
    assert "error" in result
    assert result["platforms"] == list_platforms()


def test_mcp_schema_recipe_reads_config(mcp_tools, tmp_path, monkeypatch):
    _workspace_with_platform(tmp_path, "chronicle")
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))
    result = mcp_tools["schema_recipe"](None)
    assert result["query_language"] == "udm"


def test_mcp_schema_lint_declaration_valid(mcp_tools):
    content = yaml.safe_dump(
        {
            "version": 1,
            "sources": [
                {
                    "name": "wineventlog",
                    "platform": "windows",
                    "query_language": "spl",
                    "fields": [{"name": "EventCode"}],
                }
            ],
        }
    )
    result = mcp_tools["schema_lint_declaration"](content)
    assert result["valid"] is True
    assert result["errors"] == []


def test_mcp_schema_lint_declaration_invalid_yaml(mcp_tools):
    result = mcp_tools["schema_lint_declaration"]("sources: [unclosed")
    assert result["valid"] is False
    assert result["errors"]


def test_mcp_schema_lint_declaration_bad_structure(mcp_tools):
    result = mcp_tools["schema_lint_declaration"](yaml.safe_dump({"version": 1}))
    assert result["valid"] is False
