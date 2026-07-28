"""Lint the bundled Claude skills (`claude-plugin/skills/*/SKILL.md`).

Not a behavioral test — skills are model instructions, not code — but it pins the
structural invariants a skill must hold to load and perform well:

- valid YAML frontmatter with a non-empty ``name`` + ``description``
- ``name`` matches its directory (how the skill is identified/discovered)
- ``description`` within Anthropic's 1024-char frontmatter ceiling
- body under Anthropic's 500-line ceiling for optimal performance

Behavioral checks (does it activate on the right prompts, drive the right
commands, stay read-only) live in each skill dir's ``EVALS.md`` and are run by a
human in a live Claude Code session with the plugin installed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

SKILLS_DIR = Path(__file__).resolve().parents[1] / "claude-plugin" / "skills"

DESCRIPTION_MAX_CHARS = 1024  # Anthropic frontmatter ceiling
BODY_MAX_LINES = 500          # Anthropic body ceiling for optimal performance

_FRONTMATTER = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.DOTALL)


def _skill_files() -> list[Path]:
    return sorted(SKILLS_DIR.glob("*/SKILL.md"))


def test_skills_dir_exists_and_is_populated() -> None:
    assert SKILLS_DIR.is_dir(), f"missing {SKILLS_DIR}"
    assert _skill_files(), "no SKILL.md files found under claude-plugin/skills/"


@pytest.mark.parametrize("skill", _skill_files(), ids=lambda p: p.parent.name)
def test_skill_is_well_formed(skill: Path) -> None:
    text = skill.read_text(encoding="utf-8")
    m = _FRONTMATTER.match(text)
    assert m, f"{skill}: missing/malformed YAML frontmatter (--- ... ---)"

    front = yaml.safe_load(m.group(1)) or {}
    assert isinstance(front, dict), f"{skill}: frontmatter is not a mapping"

    name = (front.get("name") or "").strip()
    desc = (front.get("description") or "").strip()
    assert name, f"{skill}: empty/missing `name`"
    assert desc, f"{skill}: empty/missing `description`"

    # name is how the skill is identified — keep it in sync with its directory.
    assert name == skill.parent.name, (
        f"{skill}: frontmatter name {name!r} != directory {skill.parent.name!r}"
    )

    assert len(desc) <= DESCRIPTION_MAX_CHARS, (
        f"{skill}: description is {len(desc)} chars (max {DESCRIPTION_MAX_CHARS})"
    )

    body_lines = m.group(2).count("\n") + 1
    assert body_lines <= BODY_MAX_LINES, (
        f"{skill}: body is {body_lines} lines (max {BODY_MAX_LINES})"
    )
