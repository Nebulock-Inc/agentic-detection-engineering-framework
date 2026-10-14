"""``adef profile`` — manage declarative extraction profiles.

Profiles teach ADEF's discovery engine a rule format without code. They live
at ``<workspace>/config/profiles/*.yml`` and are checked before built-in
recognizers. ``lint`` validates a profile against the
v1 schema — used by the catalog-onboarding skill before proposing a profile
for human approval, and by CI on contributed profiles.
"""

from __future__ import annotations

from pathlib import Path

import click
import yaml
from rich.console import Console
from rich.markup import escape

from adef.core.profiles import lint_profile_dict

console = Console()


@click.group()
def profile() -> None:
    """Manage extraction profiles (declarative rule-format support)."""


@profile.command()
@click.argument(
    "profile_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def lint(profile_file: Path) -> None:
    """Validate PROFILE_FILE against the profile schema (exit 1 on errors)."""
    try:
        data = yaml.safe_load(profile_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise click.ClickException(f"{profile_file}: not parseable as YAML: {exc}") from exc

    errors = lint_profile_dict(data)
    if errors:
        for err in errors:
            console.print(f"  [red]✗[/red] {escape(str(err))}")
        raise click.ClickException(f"{profile_file}: {len(errors)} problem(s)")
    console.print(f"[green]OK[/green] {escape(str(profile_file))}")


__all__ = ["profile"]
