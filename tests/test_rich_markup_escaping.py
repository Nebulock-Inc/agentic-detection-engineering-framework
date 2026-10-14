"""Foreign strings reaching the terminal must survive Rich's markup parser.

`console.print` parses `[...]` as a style tag *before* printing, and almost
everything ADEF prints is a value out of someone else's file: a path, a rule
title, a field name, an ATT&CK ID, an exception message. Measured on rich
15.0.0, three things happen:

* `[archive]` in a path is read as a style and **silently deleted** — the line
  then names a directory ADEF never looked at;
* `[Errno 2]` is an unparseable style, so Rich keeps it — which is why this
  went unnoticed for so long;
* `[/]` is a *closing* tag with nothing to close and raises
  `rich.errors.MarkupError` straight out of the command.

Per-command instances of this live next to the commands they belong to
(`test_ingest_command.py`, `test_doctor.py`, `test_refine_chain.py`,
`test_health_readback.py`). This file is the sweep's own net: one test per
*command surface* that interpolates foreign text, each asserting both halves —
no exception, and the brackets still there. `[/]` is the value throughout
because it is the one shape that cannot pass by accident: unescaped it raises,
so a green here is never Rich being lenient.

Counts, minted `D-XXXX` ids and stage/status enums are deliberately *not*
escaped (they cannot carry a bracket), so nothing here asserts about them.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog as catalog_cli
from adef.commands.coverage import coverage as coverage_cli
from adef.commands.detection import detection as detection_cli
from adef.commands.schema import schema as schema_cli

# Rich folds a long line at the console width; rejoining is about escaping, not
# wrapping. Paths and identifiers fold mid-token without an inserted space.
def _flat(output: str) -> str:
    return output.replace("\n", "")


@pytest.fixture
def ws(tmp_path: Path, monkeypatch) -> Path:
    import adef.commands.detection as det

    workspace = tmp_path / "ws"
    (workspace / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(workspace))
    monkeypatch.setattr(det.console, "width", 200)
    return workspace


def test_catalog_survives_a_bracketed_workspace_path(ws: Path, tmp_path: Path):
    """`adef catalog` echoes where it wrote — the one line that tells you where
    to look. Unescaped, `[/]` raised `MarkupError` and `[archive]` was deleted,
    pointing at a directory ADEF never wrote to.

    The workspace carries the brackets, not the source repo: the success path
    prints the catalog and INDEX paths, and names the repo root only on the
    error paths.
    """
    out_ws = tmp_path / "ws[/]"
    (out_ws / "journals").mkdir(parents=True)
    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    (repo / "windows" / "r.yml").write_text(
        textwrap.dedent(
            """\
            title: Plain rule
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(catalog_cli, [str(repo), "--workspace", str(out_ws)])

    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    assert "ws[/]/catalog" in _flat(result.output), result.output
    assert "ws[/]/catalog/INDEX.yml" in _flat(result.output), result.output


def test_detection_show_survives_a_bracketed_title_and_query(ws: Path):
    """A foreign rule's title and query are the most bracket-dense text ADEF prints.

    Every renderable key the record carries is set, deliberately. The first
    version of this test set `title`/`platform`/`owner`/`query` only, and
    stayed green while `stage`, `status`, `origin`, `review_reasons` and
    `support` each still raised `MarkupError` on their own — the review pass
    found it, which is `verify-tests-fail.md`'s first listed shape ("synthetic
    input missing the field that carries the bug"). The enums are *values in a
    YAML file a human edits*, not Python enums, so "an enum cannot carry a
    bracket" was true of the wrong thing.
    """
    (ws / "catalog" / "windows").mkdir(parents=True)
    (ws / "catalog" / "windows" / "D-0001-x.yml").write_text(
        yaml.safe_dump(
            {
                "id": "D-0001",
                "title": "Detect [/] in cmdline",
                "platform": "windows",
                "data_source": "ds[/]1",
                "query_language": "ql[/]1",
                "owner": "a[/]b",
                "stage": "stg[/]1",
                "status": "sts[/]1",
                "origin": "org[/]1",
                "needs_review": True,
                "review_reasons": ["rr[/]1"],
                "support": "sup[/]1",
                "rule_ref": "repo/r[/]1.yml",
                "query": "index=x | regex cmd=\"[/]\"",
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(detection_cli, ["show", "D-0001"])

    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    for expected in (
        "Detect [/] in cmdline",
        "ds[/]1",
        "ql[/]1",
        "owner=a[/]b",
        "stage=stg[/]1",
        "status=sts[/]1",
        "org[/]1",
        "rr[/]1",
        "sup[/]1",
        "repo/r[/]1.yml",
        'regex cmd="[/]"',
    ):
        assert expected in result.output, (expected, result.output)


def test_coverage_survives_a_bracketed_mitre_mapping(ws: Path):
    """An ID that isn't in ATT&CK is echoed back verbatim — that is the finding."""
    (ws / "catalog" / "windows").mkdir(parents=True)
    (ws / "catalog" / "windows" / "D-0001-x.yml").write_text(
        yaml.safe_dump(
            {
                "id": "D-0001",
                "title": "Bogus mapping",
                "platform": "windows",
                "data_source": "wineventlog",
                "mitre": ["T1059.001", "T[/]"],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(coverage_cli, [])

    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    assert "Fictional coverage" in result.output, result.output
    assert "T[/]" in _flat(result.output), result.output


def test_schema_show_survives_bracketed_field_metadata(ws: Path, tmp_path: Path):
    """Field names, aliases, descriptions and sample values all come from the
    user's own declaration — and a SIEM field name legitimately carries
    brackets (`event[0].name`, `[dbo].[events]`)."""
    decl = tmp_path / "adef-sources.yml"
    decl.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "sources": [
                    {
                        "name": "wineventlog",
                        "platform": "windows",
                        "query_language": "spl",
                        "description": "Events from [/] hosts",
                        "fields": [
                            {
                                "name": "evt[/]code",
                                "type": "int",
                                "aliases": ["alias[/]"],
                                "description": "the [/] code",
                                "values": ["4624[/]"],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert CliRunner().invoke(schema_cli, ["ingest", str(decl)]).exit_code == 0

    result = CliRunner().invoke(schema_cli, ["show", "wineventlog"])

    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    flat = _flat(result.output)
    assert "Events from [/] hosts" in flat, result.output
    assert "evt[/]code" in flat, result.output
    assert "alias[/]" in flat, result.output
    assert "the [/] code" in flat, result.output
    assert "4624[/]" in flat, result.output


def test_a_query_line_ending_in_a_backslash_is_not_doubled(ws: Path):
    """`escape()` is the wrong tool at the end of a line, and this is why.

    `rich.markup.escape` appends a backslash when its input *ends* with one, so
    that a trailing backslash cannot swallow a tag the caller appends next.
    Measured on rich 15.0.0: followed by a tag it renders back to one
    backslash; at end of line, or followed by plain text, the extra one is
    **printed**. An SPL continuation line (`... \\`) came out `... \\\\`, which
    is not valid SPL in a block that exists to be copy-pasted.

    So the Query block prints with `markup=False`, not `escape` — and the
    bracket assertion is here too, because turning markup off has to fix the
    backslash *without* reintroducing the markup bug it replaced.
    """
    (ws / "catalog" / "windows").mkdir(parents=True)
    (ws / "catalog" / "windows" / "D-0001-x.yml").write_text(
        yaml.safe_dump(
            {
                "id": "D-0001",
                "title": "Continuation",
                "platform": "windows",
                "query": 'index=main path="C:\\Windows\\" \\\n| regex cmd="[/]"',
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(detection_cli, ["show", "D-0001"])

    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    assert 'path="C:\\Windows\\" \\\n' in result.output, repr(result.output)
    assert "\\\\" not in result.output, repr(result.output)
    assert 'regex cmd="[/]"' in result.output, repr(result.output)


def test_schema_reshape_names_the_source_it_actually_wrote(ws: Path, tmp_path: Path):
    """The appended-source line is how you learn the name to pass to `ingest`.

    `[bold]{src['name']}[/bold]` sat inside a live span unescaped, so
    `--source 'win[prod]'` printed `Appended source win` — a name that is not
    in the file and that `adef schema ingest` / `detection new --source` will
    not accept. Same fix as `init.py`'s journey steps: escape the value on its
    way into ADEF's own markup, not the assembled string.
    """
    export = tmp_path / "export.csv"
    export.write_text("field,count\nEventCode,10\nCommandLine,8\n", encoding="utf-8")
    base = tmp_path / "base.yml"
    base.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "sources": [{"name": "existing", "fields": [{"name": "f"}]}],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        schema_cli,
        [
            "reshape",
            str(export),
            "--platform",
            "windows",
            "--source",
            "win[prod]",
            "--append",
            str(base),
        ],
    )

    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    # The *header* line, not just the name somewhere in the output. A bare
    # `"win[prod]" in output` passed with the escape reverted, because the lint
    # warning further down names the source too and that line was already
    # escaped — "asserting the weaker property", measured, not hypothetical.
    assert "Appended source win[prod] to" in _flat(result.output), result.output
    written = yaml.safe_load(base.read_text(encoding="utf-8"))
    assert [s["name"] for s in written["sources"]] == ["existing", "win[prod]"], written
