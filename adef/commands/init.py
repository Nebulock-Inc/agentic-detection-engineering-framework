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

import shutil
from importlib import resources
from pathlib import Path

import click
from rich.console import Console

console = Console()


DEFAULT_WORKSPACE = Path.home() / "work" / "adef-workspace"

DEFAULT_CONFIG = """\
# .adefconfig.yaml — ADEF workspace configuration
workspace_version: 1
workspace_kind: detection-engineering
journals_dir: journals
templates_dir: templates

# Path to an external rule directory (e.g. a Sigma repo). ADEF reads YAML
# metadata from here for memory search; it never writes here. Override with
# the ADEF_RULE_ROOT env var or the --rule-root flag.
# rule_root: ~/path/to/rules

# Path to an external hunt directory. Used by ``adef hunt-promote``. Override
# with the ADEF_HUNT_ROOT env var or the --hunt-root flag.
# hunt_root: ~/path/to/hunts
"""

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
def init(path: Path | None, force: bool) -> None:
    """Initialize an ADEF workspace at PATH (default ``~/work/adef-workspace/``)."""
    workspace = (path or DEFAULT_WORKSPACE).expanduser().resolve()
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

    if not config_file.exists() or force:
        config_file.write_text(DEFAULT_CONFIG, encoding="utf-8")
    if not agents_md.exists() or force:
        agents_md.write_text(_workspace_agents_md(), encoding="utf-8")

    template_path = _copy_template(templates_dir)

    console.print(f"[green]ADEF workspace initialized at[/green] {workspace}")
    console.print(f"  journals/    → {journals}")
    console.print(f"  catalog/     → {catalog}")
    console.print(f"  config/      → {config_file}")
    console.print(f"  templates/   → {template_path}")
    console.print(f"  schema/      → {schema_dir}")
    console.print(f"  AGENTS.md    → {agents_md}")
    console.print()
    console.print("Next: [bold]adef detection new TITLE[/bold] to create your first journal.")


__all__ = ["init"]
