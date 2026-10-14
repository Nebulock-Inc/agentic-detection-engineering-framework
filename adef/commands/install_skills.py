"""``adef install-skills`` — copy ADEF's bundled skills into an agent's dir.

An alternative to the plugin marketplace for teams that want the skills
**committed into their own detection repo** so everyone gets them without each
installing the plugin — and for AI assistants other than Claude Code.

Run bare (``adef install-skills``) it **prompts** for the agent and for
project-local vs. global — setup is a rare, one-time thing, so it walks you
through it rather than making you remember flags. Passing any of
``--agent``/``--global`` skips the prompt (scriptable / CI-safe).

Targets (same set as Cisco-Talos/EvidenceForge): ``claude`` →
``<base>/.claude/skills/`` (the tested path — also what the plugin installs);
``chatgpt`` / ``codex`` → ``<base>/.agents/skills/``. The skill files are the
same markdown for every agent; only the destination convention differs. Source
of truth is ``adef/data/claude-plugin/``, which ships in the wheel. Nothing
writes outside the chosen dir.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

import click
from rich.console import Console

console = Console()


class InstallSkillsError(Exception):
    """The bundled skills couldn't be found, or would clobber edited files."""


# Agent → the dot-directory its skills live under. `codex` is the coding-agent
# (the Claude Code equivalent) and the label we offer; `chatgpt` is accepted as
# an alias on the flag path — same `.agents/` destination. Only the location
# differs; the SKILL.md files are identical for every agent.
AGENT_DIRS: dict[str, str] = {
    "claude": ".claude",     # also what the plugin installs — the tested path
    "codex": ".agents",
    "chatgpt": ".agents",    # alias for codex (flag path only; not in the prompt)
}

# The choices the interactive prompt offers (one per real destination).
_PROMPT_AGENTS: tuple[str, ...] = ("claude", "codex")


@dataclass
class InstallResult:
    skills: list[str] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)


def _bundled_plugin_dir() -> Path:
    """Locate the bundled ``claude-plugin/`` inside the installed package.

    Under ``adef/data/`` so it ships as ``adef.data`` package-data — at the repo
    root, ``parent.parent`` landed in ``site-packages`` and a wheel user had no
    skills at all.

    A plain join, not ``importlib.resources``: `copy_skills` hands this to
    ``shutil.copytree``, and ``as_file()`` accepts a *directory* only on 3.12+
    while this package supports 3.10.
    """
    import adef

    return Path(adef.__file__).resolve().parent / "data" / "claude-plugin"


def copy_skills(source_plugin_dir: Path, dest_claude_dir: Path, force: bool = False) -> InstallResult:
    """Copy ``<source>/skills/*`` and ``<source>/agents/*`` into ``<dest>/``.

    Refuses to overwrite an existing skill/agent unless ``force`` (so a
    user-edited local skill isn't silently clobbered). Pure filesystem work —
    the Click command supplies the resolved paths.
    """
    skills_src = source_plugin_dir / "skills"
    if not skills_src.is_dir():
        raise InstallSkillsError(
            f"no bundled skills found at {skills_src} — this looks like an "
            "incomplete ADEF install; reinstall it, or run from a checkout."
        )

    result = InstallResult()

    skill_dirs = sorted(d for d in skills_src.iterdir() if (d / "SKILL.md").is_file())
    agents_src = source_plugin_dir / "agents"
    agent_files = sorted(agents_src.glob("*.md")) if agents_src.is_dir() else []

    # Pre-flight the clobber check across everything before writing anything.
    if not force:
        clashes = [
            d.name for d in skill_dirs if (dest_claude_dir / "skills" / d.name).exists()
        ] + [
            f.stem for f in agent_files if (dest_claude_dir / "agents" / f.name).exists()
        ]
        if clashes:
            raise InstallSkillsError(
                f"{len(clashes)} already installed in {dest_claude_dir} "
                f"({', '.join(sorted(clashes))}). Re-run with --force to overwrite."
            )

    for d in skill_dirs:
        target = dest_claude_dir / "skills" / d.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(d, target)
        result.skills.append(d.name)

    for f in agent_files:
        (dest_claude_dir / "agents").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, dest_claude_dir / "agents" / f.name)
        result.agents.append(f.stem)

    return result


def _pick(question: str, options: list[tuple[str, str]], default_index: int = 0) -> str:
    """Print a numbered menu and return the chosen value.

    ``options`` is ``(value, label)`` pairs. Reads a number via Click (no arrow-
    key dependency); works with piped input for tests/CI. Accepts the value name
    too, so `claude` typed in full still works.
    """
    for i, (_val, label) in enumerate(options, 1):
        console.print(f"  {i}) {label}")
    values = [v for v, _ in options]
    raw: str = click.prompt(question, default=str(default_index + 1), show_default=True)
    choice = raw.strip().lower()
    if choice in values:            # they typed the name
        return choice
    if choice.isdigit() and 1 <= int(choice) <= len(values):
        return values[int(choice) - 1]
    raise click.ClickException(f"'{choice}' is not one of: {', '.join(values)} (or 1–{len(values)}).")


@click.command(name="install-skills")
@click.option(
    "--agent",
    type=click.Choice(list(AGENT_DIRS)),
    default=None,
    help="AI assistant to install for (claude | codex; chatgpt = codex alias). "
    "Omit to be prompted.",
)
@click.option(
    "--global",
    "global_",
    is_flag=True,
    default=None,
    help="Install user-wide (~/) instead of project-local (./). Omit to be prompted.",
)
@click.option("--force", is_flag=True, help="Overwrite skills/agents already installed.")
def install_skills(agent: str | None, global_: bool | None, force: bool) -> None:
    """Copy ADEF's skills into an AI assistant's skills directory.

    Bare (`adef install-skills`) prompts for the agent and project-vs-global —
    it's a rare one-time setup, so it walks you through it. Passing --agent or
    --global skips the prompt. For teams: commit the resulting `.claude/`
    (or `.agents/`) into your repo. Solo Claude use? The native
    `/plugin install adef@adef-marketplace` is simpler and also wires adef-mcp.
    """
    # Prompt only when the user gave no explicit targeting flags (scriptable when
    # they do). AskUserQuestion isn't available in a plain CLI — use click.prompt.
    interactive = agent is None and global_ is None
    if agent is None:
        if interactive:
            agent = _pick(
                "Which AI assistant?",
                [
                    ("claude", "Claude Code"),
                    ("codex", "Codex (also ChatGPT) — .agents/"),
                ],
                default_index=0,
            )
        else:
            agent = "claude"  # a --global-only invocation defaults the agent
    if global_ is None:
        global_ = (
            _pick(
                "Install where?",
                [
                    ("project", "This project only (./)"),
                    ("global", "User-wide (~/)"),
                ],
                default_index=0,
            )
            == "global"
            if interactive
            else False
        )

    base = Path.home() if global_ else Path.cwd()
    dest = base / AGENT_DIRS[agent]
    try:
        result = copy_skills(_bundled_plugin_dir(), dest, force=force)
    except InstallSkillsError as exc:
        raise click.ClickException(str(exc)) from exc

    where = f"{'~' if global_ else '.'}/{AGENT_DIRS[agent]}"
    console.print(
        f"[green]Installed[/green] {len(result.skills)} skill(s)"
        + (f" + {len(result.agents)} agent(s)" if result.agents else "")
        + f" for [cyan]{agent}[/cyan] into {where}/"
    )
    console.print(f"  skills: {', '.join(result.skills)}")
    if agent != "claude":
        console.print(
            f"  [yellow]note:[/yellow] the skill content is identical to Claude's; "
            f"the {AGENT_DIRS[agent]}/ location follows {agent}'s convention "
            "(tested primarily on Claude Code)."
        )
    console.print(
        "  This doesn't wire the [bold]adef-mcp[/bold] server (the deeper, "
        "agent-agnostic integration) — run `adef-mcp`, or for Claude use the "
        "plugin (`/plugin install adef@adef-marketplace`)."
    )


__all__ = ["install_skills", "copy_skills", "InstallSkillsError", "InstallResult"]
