"""Lint the bundled Claude skills (`adef/data/claude-plugin/skills/*/SKILL.md`).

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

from adef.commands.install_skills import _bundled_plugin_dir

import pytest
import yaml

# Resolved through the same helper the command uses, not a path literal: that
# way this lint runs against whatever `adef install-skills` would actually copy,
# and it breaks if the bundled dir moves again.
SKILLS_DIR = _bundled_plugin_dir() / "skills"

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


@pytest.mark.parametrize("stage", ["observe", "refine", "govern", "evolve"])
def test_forge_stage_names_the_command_for_every_stage_it_claims(stage: str) -> None:
    """A skill that claims a stage and never names its command is a doc, not a
    driver.

    `forge-stage`'s description promises all four stages after Find. Its body
    named `adef detection observe` and `refine` and — for over two months —
    neither `govern` nor `evolve`: the Govern section described what to think
    about with no transition to record it on, and Evolve said "with evidence"
    without naming the command that reads the evidence. Generic on purpose, so
    a fifth stage or a renamed one re-flags this instead of needing a new
    assertion.
    """
    text = (SKILLS_DIR / "forge-stage" / "SKILL.md").read_text(encoding="utf-8")
    assert f"adef detection {stage}" in text


def test_forge_stage_points_evolve_at_the_health_it_reads() -> None:
    """Evolve's recommendations are derived from ingested counts, and the chain
    reports `insufficient-data` when there are none. A skill that drives Evolve
    without naming `adef ingest` leaves the agent re-running the stage, or
    worse, proposing a threshold from an impression of the volume."""
    text = (SKILLS_DIR / "forge-stage" / "SKILL.md").read_text(encoding="utf-8")
    assert "adef ingest" in text
    assert "adef health show" in text
    assert "insufficient-data" in text


def test_forge_stage_documents_current_refine_flags() -> None:
    """`forge-stage` is the skill that drives `adef detection refine` — it
    went stale on the actual CLI flags/behavior once. Pin the specific
    things that were wrong so a future refine change re-flags this skill
    instead of drifting silently again."""
    text = (SKILLS_DIR / "forge-stage" / "SKILL.md").read_text(encoding="utf-8")

    # The mode to recommend for agent-driven use, and the flag that forces a
    # re-run once already at refine.
    assert "--similarity-mode agent" in text
    assert "--chain" in text

    # Native-by-default is the current behavior; `WrapperUnavailable` is now
    # the *exceptional* path (an explicit broken override), not the norm.
    assert "native by default" in text

    # `adef detection refine` prints the agent-mode
    # shortlist itself — the skill must no longer send the reader back
    # through `detection show` once per candidate to read its query.
    assert "for each candidate you are about to judge" not in text
