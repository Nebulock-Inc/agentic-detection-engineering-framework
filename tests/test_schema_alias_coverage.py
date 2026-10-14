# tests/test_schema_alias_coverage.py
import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from adef.cli import cli
from adef.core.catalog import Catalog, CatalogRecord
from adef.commands.schema import run_schema_check


def _ws_with_schema(tmp_path, fields) -> Path:
    ws = tmp_path / "ws"
    (ws / "schema").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    (ws / "schema" / "wineventlog.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "wineventlog", "fields": fields,
    }), encoding="utf-8")
    return ws


def test_alias_coverage_counts_fields_with_aliases(tmp_path):
    ws = _ws_with_schema(tmp_path, [
        {"name": "process.name", "type": "string", "aliases": ["Image"]},
        {"name": "parent.name", "type": "string", "aliases": []},
        {"name": "user.name", "type": "string"},
        # m-2 (final whole-branch review): `aliases: [""]` -- a blank string,
        # not an absent key or an empty list -- must NOT count as "has an
        # alias". The naive `bool(f.get("aliases") or [])` disagrees here
        # (`[""]` is a non-empty list, so it's truthy) even though it agrees
        # with the correct predicate on every OTHER fixture field above,
        # which is exactly why that mutation went undetected before.
        {"name": "host.name", "type": "string", "aliases": [""]},
    ])
    result = run_schema_check(ws)
    assert result.alias_coverage["wineventlog"] == (1, 4)


def test_a_source_with_no_aliases_is_visible_in_the_report(tmp_path):
    # The invisible-failure case: schemas declared, check passes, and
    # cross-language retrieval gains nothing. It must be legible here.
    ws = _ws_with_schema(tmp_path, [
        {"name": "process.name", "type": "string", "aliases": []},
    ])
    out = CliRunner().invoke(cli, ["schema", "check", "--workspace", str(ws)]).output
    assert "alias" in out.lower()
    assert "wineventlog" in out
    # m-3: the zero-coverage branch (`if total and with_alias == 0`) prints
    # this specific callout. The sibling `elif total` branch (declared field
    # count > 0 with SOME aliases) also mentions "alias" and the source name,
    # so those two assertions alone don't distinguish "the callout fired"
    # from "some alias-coverage line printed" -- disabling the callout
    # (`if False`) would still pass them.
    # Rich soft-wraps at the console width, so "matching" and "inactive" can
    # land on different lines -- normalize whitespace before checking for the
    # phrase.
    assert "cross-language field matching inactive" in " ".join(out.split())


def test_alias_coverage_survives_a_clean_pass(tmp_path):
    # m-4: the alias-coverage block is printed BEFORE `run_schema_check`'s
    # "No findings." early return -- deliberately, so a workspace that
    # otherwise passes cleanly still surfaces zero alias coverage. Every
    # other fixture in this file produces an `unused_by_rules` finding (the
    # schema's field is declared but no rule uses it), which never takes the
    # early-return path at all -- so none of them can tell "printed before
    # the return" apart from "printed after it", since both orderings print
    # it in that scenario. This fixture uses the declared field in a rule so
    # the check is genuinely clean.
    ws = _ws_with_schema(tmp_path, [
        {"name": "process.name", "type": "string", "aliases": []},
    ])
    cat = Catalog(ws)
    cat.write(CatalogRecord(
        id="D-0001", title="uses process.name", rule_ref="r/d1.yml",
        original_path="/tmp/d1.yml", platform="windows", kind="atomic",
        engine="sql", format="sql", query_language="sql",
        query="SELECT * FROM t WHERE `process.name` = 'mshta.exe'",
        data_source="wineventlog",
    ))
    cat.rebuild_index()
    result = run_schema_check(ws)
    assert not result.missing_from_schema
    assert not result.unused_by_rules
    assert not result.engine_errors
    assert not result.undeclared_type_fields
    out = CliRunner().invoke(cli, ["schema", "check", "--workspace", str(ws)]).output
    assert "cross-language field matching inactive" in " ".join(out.split())
    assert "No findings." in out


def test_alias_coverage_is_report_only(tmp_path):
    # No validation behaviour changes: a workspace that passes today still
    # passes, whatever its alias coverage.
    ws = _ws_with_schema(tmp_path, [
        {"name": "process.name", "type": "string", "aliases": []},
    ])
    r = CliRunner().invoke(cli, ["schema", "check", "--workspace", str(ws)])
    assert r.exit_code == 0


def test_alias_coverage_appears_in_the_json_report(tmp_path):
    # the
    # terminal report already prints alias coverage, but --report json's
    # payload builder (adef/commands/schema.py) omitted the key entirely --
    # a machine consumer had no way to see the one signal that makes
    # `declared_no_aliases` (the invisible failure) visible. Named keys
    # (`with_aliases`/`total`), not a two-element array: JSON has no tuples,
    # and a positional pair is exactly the kind of shape a machine consumer
    # could silently misread.
    ws = _ws_with_schema(tmp_path, [
        {"name": "process.name", "type": "string", "aliases": ["Image"]},
        {"name": "parent.name", "type": "string", "aliases": []},
        {"name": "user.name", "type": "string"},
    ])
    r = CliRunner().invoke(
        cli, ["schema", "check", "--workspace", str(ws), "--report", "json"])
    assert r.exit_code == 0
    payload = json.loads(r.output)
    assert payload["alias_coverage"] == {
        "wineventlog": {"with_aliases": 1, "total": 3},
    }
