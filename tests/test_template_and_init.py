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
