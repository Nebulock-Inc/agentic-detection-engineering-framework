"""``adef init`` — scaffold an ADEF workspace.

Creates the directory structure ADEF expects:

::

    <workspace>/
        journals/
        config/.adefconfig.yaml
        AGENTS.md
        templates/DETECTION_FORGE.md

The default workspace location (when no path is given) is ``~/work/adef-workspace/``,
per the project decision logged in ``ISA.md``.
"""

from __future__ import annotations

import os
import shutil
from importlib import resources
from pathlib import Path

import click
import yaml
from rich.console import Console

console = Console()


DEFAULT_WORKSPACE = Path.home() / "work" / "adef-workspace"

DEFAULT_CONFIG = """\
# .adefconfig.yaml — ADEF workspace configuration
workspace_version: 1
workspace_kind: detection-engineering
journals_dir: journals
templates_dir: templates

# SIEM/platform preferences (set via adef init --interactive)
# platform: splunk
# query_languages: [spl]

# Path to an external rule directory (e.g. a Sigma repo). ADEF reads YAML
# metadata from here for memory search; it never writes here. Override with
# the ADEF_RULE_ROOT env var or the --rule-root flag.
# rule_root: ~/path/to/rules

# Path to an external hunt directory. Used by ``adef hunt-promote``. Override
# with the ADEF_HUNT_ROOT env var or the --hunt-root flag.
# hunt_root: ~/path/to/hunts
"""

def _mcp_installed() -> bool:
    """Is the optional FastMCP dependency importable (the `.[mcp]` extra)?"""
    try:
        import fastmcp  # noqa: F401

        return True
    except ImportError:
        return False


def _print_capabilities(workspace: Path) -> None:
    """Honest detection of the optional layers CLI-first users miss."""
    console.print("\n[bold]Optional capabilities[/bold]")
    if _mcp_installed():
        console.print("  [green]✓[/green] MCP server available — run [bold]adef-mcp[/bold] for Claude Code / Cursor / Copilot integration")
    else:
        console.print('  [yellow]✗[/yellow] MCP server not installed — [bold]pip install -e ".\\[mcp]"[/bold] enables agent integration (adef-mcp)')
    console.print(
        "  [yellow]![/yellow] AI-assistant skills are [bold]inactive until installed[/bold]:\n"
        "      teams / any assistant:  [bold]adef install-skills[/bold]\n"
        "      Claude Code (also wires MCP):  [bold]/plugin install adef@adef-marketplace[/bold]"
    )


_JOURNEY_STEPS = {
    "1": [
        "See what ADEF recognizes: [bold]adef catalog /path/to/your/rules --dry-run --report json[/bold]",
        "Catalog it (read-only on your repo): [bold]adef catalog /path/to/your/rules[/bold]",
        "Keep it fresh after repo changes: [bold]adef sync /path/to/your/rules[/bold] ([bold]--check[/bold] in CI)",
        "See your coverage: [bold]adef coverage[/bold]",
    ],
    "2": [
        "Export your rules from the SIEM to a folder (e.g. savedsearches.conf, analytics export)",
        "Catalog the export: [bold]adef catalog /path/to/export[/bold]",
        "See your coverage: [bold]adef coverage[/bold]",
    ],
    "3": [
        "Get your SIEM's field-export command: [bold]adef schema recipe {platform}[/bold]",
        "Run it in your SIEM, save the export, then: [bold]adef schema reshape <export> --interactive[/bold]",
        "Ingest the reviewed declaration: [bold]adef schema ingest <name>-sources.yml[/bold]",
        'Author your first schema-grounded rule: [bold]adef detection new "Title" --source <name>[/bold]',
    ],
}


def _print_next_steps(journey: str, platform: str, workspace: Path) -> None:
    console.print("\n[bold]Next steps:[/bold]")
    for i, step in enumerate(_JOURNEY_STEPS[journey], 1):
        console.print(f"  {i}. {step.format(platform=platform)}")
    if journey in ("2", "3"):
        # ADEF is the system of record here — durability is not optional.
        # Printed, never executed: the `init --git` flag was deliberately
        # retired in favor of docs (ISA 2026-07-22, detection-home step 2).
        console.print(
            "\n[bold]Make the workspace durable[/bold] — your records here are the only copy:"
        )
        click.echo(f'  cd {workspace} && git init && git add -A && git commit -m "detection workspace, day 0"')
        console.print("  Full guide: docs/detection-home.md")
    if (Path.cwd() / "examples" / "demo-rules").is_dir():
        console.print(
            "\nBundled 5-minute demo (sample rules + data): docs/quickstart.md §3"
        )


def _workspace_agents_md() -> str:
    """The operator briefing scaffolded into every workspace as AGENTS.md.

    Lives in package data (``adef/data/templates/WORKSPACE_AGENTS.md``) so it
    ships with the wheel and stays maintainable as one document — this is the
    briefing an AI assistant *operating* ADEF reads, distinct from the repo's
    contributor-facing AGENTS.md.
    """
    return (
        resources.files("adef.data")
        .joinpath("templates/WORKSPACE_AGENTS.md")
        .read_text(encoding="utf-8")
    )


def _copy_template(target_templates_dir: Path) -> Path:
    """Copy the packaged ``DETECTION_FORGE.md`` into the workspace's templates dir."""
    target_templates_dir.mkdir(parents=True, exist_ok=True)
    target = target_templates_dir / "DETECTION_FORGE.md"
    with resources.as_file(
        resources.files("adef.data.templates").joinpath("DETECTION_FORGE.md")
    ) as src:
        shutil.copyfile(src, target)
    return target


@click.command()
@click.argument(
    "path",
    required=False,
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing scaffolding files.",
)
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    help="Prompt for SIEM/platform preferences.",
)
def init(path: Path | None, force: bool, interactive: bool) -> None:
    """Initialize an ADEF workspace at PATH (default ``~/work/adef-workspace/``)."""
    # Explicit PATH → ADEF_WORKSPACE → default. (Deliberately NOT the shared
    # resolver's cwd-fallback: init *creates* a workspace, so it must not infer its
    # target from cwd contents the way the read commands do.)
    workspace = Path(path or os.environ.get("ADEF_WORKSPACE") or DEFAULT_WORKSPACE).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    journals = workspace / "journals"
    catalog = workspace / "catalog"
    config_dir = workspace / "config"
    templates_dir = workspace / "templates"
    schema_dir = workspace / "schema"
    agents_md = workspace / "AGENTS.md"
    config_file = config_dir / ".adefconfig.yaml"

    journals.mkdir(exist_ok=True)
    catalog.mkdir(exist_ok=True)
    config_dir.mkdir(exist_ok=True)
    templates_dir.mkdir(exist_ok=True)
    schema_dir.mkdir(exist_ok=True)

    # Start with default config structure
    config_data = {
        "workspace_version": 1,
        "workspace_kind": "detection-engineering",
        "journals_dir": "journals",
        "templates_dir": "templates",
    }

    # Interactive mode: guided setup
    journey = "1"
    if interactive:
        console.print("\n[bold]Where do your detections live today?[/bold]")
        console.print("  1) In a git repo (detection-as-code)")
        console.print("  2) Only in my SIEM (no repo)")
        console.print("  3) Starting fresh — I'll author them in ADEF")
        journey = click.prompt(
            "Choose", type=click.Choice(["1", "2", "3"]), default="1"
        )

        console.print("\n[bold]SIEM/Platform Configuration[/bold]")
        console.print("These preferences help ADEF provide relevant schema recipes.\n")

        platform = click.prompt(
            "Which SIEM/platform do you use?",
            type=click.Choice(
                ["splunk", "sentinel", "elastic", "chronicle", "sumo", "qradar", "other"],
                case_sensitive=False,
            ),
            default="splunk",
        )

        query_langs_input = click.prompt(
            "Which query language(s) do you write detections in? (comma-separated)",
            default="spl",
        )
        query_langs = [lang.strip() for lang in query_langs_input.split(",")]

        config_data["platform"] = platform
        config_data["query_languages"] = query_langs

        console.print(f"\n[green]✓[/green] Configured for {platform} with {', '.join(query_langs)}")

    if not config_file.exists() or force:
        # Write config with platform preferences if interactive was used
        if interactive or not config_file.exists():
            with config_file.open("w", encoding="utf-8") as f:
                f.write("# .adefconfig.yaml — ADEF workspace configuration\n")
                yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)
                f.write("""
# Path to an external rule directory (e.g. a Sigma repo). ADEF reads YAML
# metadata from here for memory search; it never writes here. Override with
# the ADEF_RULE_ROOT env var or the --rule-root flag.
# rule_root: ~/path/to/rules

# Path to an external hunt directory. Used by ``adef hunt-promote``. Override
# with the ADEF_HUNT_ROOT env var or the --hunt-root flag.
# hunt_root: ~/path/to/hunts
""")
        else:
            config_file.write_text(DEFAULT_CONFIG, encoding="utf-8")

    if not agents_md.exists() or force:
        agents_md.write_text(_workspace_agents_md(), encoding="utf-8")

    template_path = _copy_template(templates_dir)

    console.print(f"\n[green]ADEF workspace initialized at[/green] {workspace}")
    console.print(f"  journals/    → {journals}")
    console.print(f"  catalog/     → {catalog}")
    console.print(f"  config/      → {config_file}")
    console.print(f"  templates/   → {template_path}")
    console.print(f"  schema/      → {schema_dir}")
    console.print(f"  AGENTS.md    → {agents_md}")
    console.print()

    if interactive:
        _print_capabilities(workspace)
        if click.confirm(
            "\nInstall AI-assistant skills now (Claude Code / Codex)?", default=False
        ):
            from adef.commands.install_skills import install_skills

            try:
                click.get_current_context().invoke(
                    install_skills, agent=None, global_=None, force=False
                )
            except click.ClickException as exc:
                # Never let a skills hiccup fail an already-scaffolded init.
                console.print(f"  [yellow]![/yellow] skills install skipped: {exc.message}")
                console.print("  Re-run later with: [bold]adef install-skills[/bold]")

        _print_next_steps(journey, str(config_data.get("platform", "")), workspace)

        if workspace != DEFAULT_WORKSPACE.expanduser().resolve():
            console.print(
                "\n[yellow]![/yellow] Non-default workspace path — so every adef "
                "command can find it, add this to your shell profile:"
            )
            click.echo(f"  export ADEF_WORKSPACE={workspace}")
    else:
        console.print("Next: [bold]adef detection new TITLE[/bold] to create your first journal.")


__all__ = ["init"]
