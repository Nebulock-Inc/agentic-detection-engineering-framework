# tests/test_refine_degradation_output.py
import yaml
from click.testing import CliRunner

from adef.cli import cli
from adef.core.catalog import Catalog, CatalogRecord
from adef.core.journal import Journal


def _rec(rid, title, query, lang, fmt, source):
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format=fmt,
        query=query, mitre=["T1218.005"],
        query_language=lang, data_source=source,
    )


def _ws(tmp_path, records, schema=None):
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in records:
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()
    if schema:
        (ws / "schema").mkdir()
        (ws / "schema" / f"{schema['source']}.yml").write_text(
            yaml.safe_dump(schema), encoding="utf-8")
    return ws


SQL = "SELECT * FROM wineventlog WHERE process.name = 'mshta.exe'"
SCHEMA_WITH = {
    "schema_version": 2, "source": "wineventlog",
    "fields": [{"name": "process.name", "type": "string", "aliases": ["Image"]}],
}
SCHEMA_WITHOUT = {
    "schema_version": 2, "source": "wineventlog",
    "fields": [{"name": "process.name", "type": "string", "aliases": []}],
}


def _refine(ws):
    # Must-fix (final whole-branch review): a command that raised or exited
    # non-zero must not masquerade as a content-assertion failure below --
    # `test_working_field_matching_prints_nothing` in particular is vacuous
    # if the command actually crashed rather than genuinely printing nothing.
    result = CliRunner().invoke(
        cli, ["detection", "refine", "D-0001", "--workspace", str(ws)])
    assert result.exit_code == 0, (
        f"adef detection refine exited {result.exit_code}: {result.output!r}"
    )
    return result.output


def test_unmatched_prints_the_cause_and_the_remedy(tmp_path):
    out = _refine(_ws(tmp_path, [_rec("D-0001", "a", SQL, "sql", "sql", "wineventlog")]))
    assert "field matching" in out
    assert "unmatched" in out
    assert "adef schema" in out       # the command that fixes it


def test_declared_no_aliases_prints_its_own_cause(tmp_path):
    out = _refine(_ws(tmp_path, [_rec("D-0001", "a", SQL, "sql", "sql", "wineventlog")],
                      schema=SCHEMA_WITHOUT))
    assert "declared_no_aliases" in out
    assert "alias" in out.lower()


def test_working_field_matching_prints_nothing(tmp_path):
    # A feature that works does not announce itself.
    out = _refine(_ws(tmp_path, [_rec("D-0001", "a", SQL, "sql", "sql", "wineventlog")],
                      schema=SCHEMA_WITH))
    assert "field matching" not in out


def test_partial_verification_is_printed_not_silent(tmp_path):
    # Found in testing: "nothing checked" read as passed. Refine now says so.
    ws = _ws(tmp_path, [_rec("D-0001", "mshta child", SQL, "sql", "sql", "unknown_src")])
    out = _refine(ws)
    assert "verification: partial — fields not checked" in out
    assert "no schemas are declared" in out


def test_passing_verification_prints_no_verification_line(tmp_path):
    ws = _ws(tmp_path, [_rec("D-0001", "mshta child", "`process.name` = 'mshta.exe'", "sql", "sql",
                             "wineventlog")],
             schema={**SCHEMA_WITH, "scope": {"index": "wineventlog"}})
    assert "verification:" not in _refine(ws)


def test_failed_verification_shows_every_failed_check(tmp_path):
    # CodeRabbit: an engine error hid the missing filter field.
    rec = _rec("D-0001", "bad", "`user.name` = 'admin'", "sql", "sql", "wineventlog")
    rec.engine = "custom_sql"
    ws = _ws(tmp_path, [rec], schema={**SCHEMA_WITH, "scope": {"index": "wineventlog"}})
    out = _refine(ws)
    assert "verification: failed" in out
    assert "custom_sql" in out and "user.name" in out, out
