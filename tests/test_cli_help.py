"""Tests for the root ``adef --help`` output."""

from __future__ import annotations

from click.testing import CliRunner

from adef.cli import cli


def test_epilog_examples_each_stay_on_their_own_line():
    """Every example paragraph is `\\b`-protected, not just the first.

    Click treats a `\\b` line as "do not rewrap the paragraph that follows".
    With a single marker at the top of the epilog, only the first paragraph was
    protected and every later one got reflowed — each command was pulled up onto
    its preceding comment line, e.g.

        # Advance through FORGE   adef detection observe D-0001   adef detec…

    which is the first output a new user sees. Assert the collapse signature is
    absent: no line holds a `#` comment AND a command.
    """
    result = CliRunner(env={"COLUMNS": "100"}).invoke(cli, ["--help"])
    assert result.exit_code == 0, result.output

    collapsed = [
        line
        for line in result.output.splitlines()
        if "#" in line and "adef " in line.split("#", 1)[1]
    ]
    assert not collapsed, f"epilog example lines were rewrapped: {collapsed}"

    # The examples are actually present (guards against the assertion above
    # passing because the epilog went missing entirely).
    assert "# Advance through FORGE" in result.output
    for stage in ("observe", "refine", "govern", "evolve"):
        assert f"adef detection {stage}" in result.output
