"""Unit tests — `adef doctor` and the `core/doctor.py` model it renders.

The checks worth testing are the ones that can be *wrong while looking right*:
a stale INDEX whose detection list is unchanged, a record that every other
command silently skips, a skills count that includes skills ADEF did not ship,
and a `fix` string Rich would eat as markup. Fixtures are built by running the
real commands (`adef init`, `adef catalog`) rather than hand-writing the
workspace, so a check can't pass against a shape the product never produces.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog as catalog_cmd
from adef.commands.doctor import doctor
from adef.commands.init import init
from adef.core.doctor import run_checks

RULE = """\
title: Suspicious mshta child process
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: mshta spawning a shell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\mshta.exe'
    Image|endswith: '\\cmd.exe'
  condition: selection
tags:
  - attack.t1218.005
level: high
"""


def _statuses(checks) -> dict[str, str]:
    return {c.name: c.status for c in checks}


def _check(checks, name):
    return next(c for c in checks if c.name == name)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A real `adef init` workspace — no records yet."""
    ws = tmp_path / "ws"
    result = CliRunner().invoke(init, [str(ws)])
    assert result.exit_code == 0, result.output
    return ws


@pytest.fixture
def catalogued(workspace: Path, tmp_path: Path) -> Path:
    """`workspace` with one real catalogued rule (record + journal + INDEX)."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "mshta.yml").write_text(RULE, encoding="utf-8")
    result = CliRunner().invoke(catalog_cmd, [str(rules), "--workspace", str(workspace)])
    assert result.exit_code == 0, result.output
    return workspace


def _record(ws: Path) -> Path:
    (path,) = (ws / "catalog").rglob("D-*.yml")
    return path


# --------------------------------------------------------------------------- #
# Workspace gate
# --------------------------------------------------------------------------- #
def test_a_missing_workspace_is_the_only_check_reported(tmp_path: Path):
    """One cause, one line. Nine derivative failures bury the fix."""
    checks = run_checks(tmp_path / "nope")
    assert [c.name for c in checks] == ["workspace"]
    assert checks[0].status == "problem"
    assert checks[0].fix == f"adef init {tmp_path / 'nope'}"


def test_an_existing_directory_that_is_not_a_workspace_is_a_problem(tmp_path: Path):
    """`resolve_workspace` falls back to the cwd, so "the directory exists" is
    not the same question as "this is a workspace". Without the scaffold check
    `adef doctor` in any unrelated repo reports a healthy workspace and every
    check below it becomes meaningless."""
    plain = tmp_path / "some-repo"
    plain.mkdir()
    checks = run_checks(plain)
    assert [c.name for c in checks] == ["workspace"]
    assert checks[0].status == "problem"
    assert "not an ADEF workspace" in checks[0].detail
    assert "journals/" in checks[0].detail and "catalog/" in checks[0].detail


def test_doctor_creates_nothing_in_the_directory_it_checks(tmp_path: Path):
    """Read-only. `Catalog.__init__` mkdirs its directory, so a doctor that
    constructs one unconditionally scaffolds a workspace into whatever
    directory it was pointed at."""
    plain = tmp_path / "some-repo"
    plain.mkdir()
    result = CliRunner().invoke(doctor, ["--workspace", str(plain)])
    assert result.exit_code == 1, result.output
    assert list(plain.iterdir()) == []


# --------------------------------------------------------------------------- #
# INDEX freshness — the check the `build_index` split exists for
# --------------------------------------------------------------------------- #
def test_a_mitre_edit_that_changes_no_filename_is_reported_stale(catalogued: Path):
    """The failure that motivated an exact comparison.

    Editing a record's `mitre` leaves the ID set, every filename and every
    mtime-relevant record untouched, while `by_technique`/`by_tactic` — what
    `adef coverage` and `--tactic` read — go wrong. An ID-set or mtime
    comparison reports this workspace as fresh.
    """
    assert _statuses(run_checks(catalogued))["index"] == "ok"

    path = _record(catalogued)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["mitre"] == ["T1218.005"], data["mitre"]
    data["mitre"] = ["T1059.001"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    check = _check(run_checks(catalogued), "index")
    assert check.status == "problem"
    # Names *which* keys drifted, so the report distinguishes a mapping edit
    # from a new record nobody indexed.
    assert "by_technique" in check.detail and "by_tactic" in check.detail
    assert check.fix == "adef reindex"


def test_a_missing_index_on_an_empty_catalog_is_not_a_problem(workspace: Path):
    """`adef init` writes no INDEX, and `adef init` must never hand you a
    problem to fix. An empty catalog owes no INDEX.

    Deliberately takes only the `workspace` fixture. Written originally as one
    test over `workspace` *and* `catalogued`, it could not fail: `catalogued`
    builds on `workspace`, so cataloguing wrote `INDEX.yml` into the very
    workspace this half calls "empty", and the branch under test was never
    reached. It survived `if not catalog.build_index()...` being replaced with
    `if False`.
    """
    assert not (workspace / "catalog" / "INDEX.yml").exists()
    assert _statuses(run_checks(workspace))["index"] == "ok"


def test_a_missing_index_with_records_present_is_a_problem(catalogued: Path):
    (catalogued / "catalog" / "INDEX.yml").unlink()
    check = _check(run_checks(catalogued), "index")
    assert check.status == "problem"
    assert "missing" in check.detail


@pytest.mark.parametrize(
    "payload, kind",
    [("- not\n- a\n- mapping\n", "list"), ("just-a-scalar\n", "str")],
)
def test_a_non_mapping_index_is_reported_not_raised(catalogued: Path, payload: str, kind: str):
    """Valid YAML that isn't a mapping — the state `doctor` died on.

    A hand-edited `INDEX.yml` left as a list, or truncated to a scalar, parses
    cleanly, so the `yaml.YAMLError` guard never sees it. `.get` on a list
    then raised `AttributeError` *through* the command: `adef doctor` exited
    with a traceback on precisely the broken workspace it exists to report.

    Both members of the class, named: "non-mapping" covers a sequence and a
    scalar, and only the sequence reaches `.get` the same way.
    """
    (catalogued / "catalog" / "INDEX.yml").write_text(payload, encoding="utf-8")
    check = _check(run_checks(catalogued), "index")
    assert check.status == "problem"
    assert "not a mapping" in check.detail
    assert kind in check.detail  # names what it found, not just that it's wrong
    assert check.fix == "adef reindex"


def test_an_empty_index_file_is_stale_not_malformed(catalogued: Path):
    """`stored is None` is a different thing and keeps the staleness path.

    An empty file is a mapping of nothing, so it is genuinely stale rather
    than malformed, and the staleness branch is the one that names which keys
    drifted. Guards the `stored is not None` half of the new condition — drop
    it and this case misreports as `NoneType` is not a mapping.
    """
    (catalogued / "catalog" / "INDEX.yml").write_text("", encoding="utf-8")
    check = _check(run_checks(catalogued), "index")
    assert check.status == "problem"
    assert "stale" in check.detail, check.detail
    assert "not a mapping" not in check.detail


# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
def test_a_record_every_command_silently_skips_is_named(catalogued: Path):
    """`Catalog.iter_records` swallows a YAMLError and moves on, so a
    hand-broken record is absent from every listing, coverage number and search
    result with nothing anywhere saying so."""
    broken = catalogued / "catalog" / "windows" / "D-0002-broken.yml"
    broken.write_text("id: D-0002\n  bad: [unclosed\n", encoding="utf-8")

    check = _check(run_checks(catalogued), "catalog")
    assert check.status == "problem"
    assert "unreadable" in check.detail
    # The filename, not a count: a count tells you a file is broken, not which.
    assert "D-0002-broken.yml" in check.detail


def test_a_record_that_is_not_utf8_is_reported_not_raised(catalogued: Path):
    """The failure class `iter_records` caught was narrower than its callers knew.

    `read_text(encoding="utf-8")` raises `UnicodeDecodeError` *before* the YAML
    parser is reached, and that is a `ValueError`, not a `yaml.YAMLError` — so a
    record saved as UTF-16 crashed every command that walks the catalog,
    including this one. Named as a distinct member of the "unparseable" class
    rather than reusing the broken-YAML fixture above: that one parses as far as
    the parser, which is exactly the variant the old guard already handled.
    """
    bad = catalogued / "catalog" / "windows" / "D-0003-utf16.yml"
    bad.write_bytes("id: D-0003\ntitle: Résumé\n".encode("utf-16"))

    check = _check(run_checks(catalogued), "catalog")
    assert check.status == "problem", check.detail
    assert "D-0003-utf16.yml" in check.detail, check.detail


def test_an_empty_catalog_warns_rather_than_failing(workspace: Path):
    check = _check(run_checks(workspace), "catalog")
    assert check.status == "warn"
    assert check.fix.startswith("adef catalog")


# --------------------------------------------------------------------------- #
# Journals, enrichment, health
# --------------------------------------------------------------------------- #
def test_a_record_with_no_journal_is_reported(catalogued: Path):
    (journal,) = (catalogued / "journals").glob("D-*.md")
    journal.unlink()
    check = _check(run_checks(catalogued), "journals")
    assert check.status == "warn"
    assert "D-0001" in check.detail


def test_the_review_queue_is_summarized_by_reason(catalogued: Path):
    path = _record(catalogued)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["review_reasons"] = ["no_mitre"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    check = _check(run_checks(catalogued), "enrichment")
    assert check.status == "warn"
    assert "1× no_mitre" in check.detail
    assert check.fix == "adef detection list --needs-review no_mitre"


def test_ingested_health_flips_the_health_check(catalogued: Path):
    assert _statuses(run_checks(catalogued))["health"] == "warn"
    latest = catalogued / "health" / "latest" / "D-0001.yml"
    latest.parent.mkdir(parents=True)
    latest.write_text(yaml.safe_dump({"metrics": {"signal_count": 10}}), encoding="utf-8")
    check = _check(run_checks(catalogued), "health")
    assert check.status == "ok"
    assert "1 detection(s)" in check.detail


# --------------------------------------------------------------------------- #
# Skills — the check that was green for the wrong reason
# --------------------------------------------------------------------------- #
def test_unrelated_skills_in_the_same_directory_are_not_counted(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """`.claude/skills/` is shared with a developer's own skills, so counting
    directory entries reported "installed" for a workspace with zero ADEF
    skills — a green tick on the exact thing being checked."""
    home = tmp_path / "home"
    (home / ".claude" / "skills" / "my-own-thing").mkdir(parents=True)
    (home / ".claude" / "skills" / "my-own-thing" / "SKILL.md").write_text("x")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(tmp_path)

    check = _check(run_checks(workspace), "skills")
    assert check.status == "warn"
    assert check.detail.startswith("0 of ")
    assert "my-own-thing" not in check.detail


def test_an_installed_adef_skill_is_counted(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The positive half — otherwise the test above passes against a check that
    can only ever say zero."""
    from adef.commands.install_skills import _bundled_plugin_dir

    bundled = sorted(
        d.name for d in (_bundled_plugin_dir() / "skills").iterdir() if (d / "SKILL.md").is_file()
    )
    home = tmp_path / "home"
    dest = home / ".claude" / "skills" / bundled[0]
    dest.mkdir(parents=True)
    (dest / "SKILL.md").write_text("x")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(tmp_path)

    check = _check(run_checks(workspace), "skills")
    assert check.detail.startswith(f"1 of {len(bundled)}")
    # Partial install is still a warning: the missing skills are named so the
    # user knows a re-run is needed, not just that "skills exist".
    assert check.status == "warn"
    assert bundled[1] in check.detail


# --------------------------------------------------------------------------- #
# ATT&CK snapshot
#
# The `lru_cache` on `attack_reference` is cleared around every test by the
# autouse fixture in `conftest.py` — load-bearing here, not hygiene: a warm
# entry leaks the shipped v19.1/858 into these assertions.
# --------------------------------------------------------------------------- #
def test_the_attack_check_reads_the_workspace_it_was_pointed_at(workspace: Path):
    """`--workspace` and `$ADEF_WORKSPACE` disagreeing is the reachable case.

    `attack_reference()` resolved its snapshot from `$ADEF_WORKSPACE` alone, so
    `adef doctor --workspace /srv/ws` reported the *shipped* snapshot's version
    and technique counts under a "(workspace snapshot)" label — the one check
    of the ten that answered about a different workspace than it was asked
    about.

    The planted snapshot carries a version string no real ATT&CK release uses,
    so "it read mine" cannot be confused with "it read the shipped one". The
    env var is deliberately left unset: that is the state in which the old code
    silently fell back, and the test has to distinguish *which* file was read,
    not merely that a label was printed.
    """
    snapshot = workspace / "attack" / "enterprise.json"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(
        json.dumps({"attack_version": "99.9-test", "tactics": {}, "techniques": {"T9999": {}}}),
        encoding="utf-8",
    )

    check = _check(run_checks(workspace), "att&ck")
    assert check.status == "ok", check.detail
    assert "99.9-test" in check.detail, check.detail
    assert "workspace snapshot" in check.detail, check.detail
    # The counts have to come from the same file as the label, not just the
    # version — reading one and labelling the other is the actual defect.
    assert "1 technique(s)" in check.detail, check.detail


def test_a_corrupt_workspace_snapshot_is_reported_not_raised(workspace: Path):
    """What an interrupted `adef attack refresh` leaves behind.

    `AttackReference.from_path` is a bare `json.loads`, and `_check_attack`
    called it unguarded — so a truncated `attack/enterprise.json` exited
    `adef doctor` with a `JSONDecodeError` traceback instead of reporting a
    problem. Same failure class as the non-mapping `INDEX.yml` above: the
    diagnostic command has to survive the broken workspace it exists to
    diagnose.

    Truncated rather than empty, because the two take different paths through
    the decoder and truncation is the one a killed download produces.
    """
    snapshot = workspace / "attack" / "enterprise.json"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text('{"attack_version": "17.1", "techni', encoding="utf-8")

    checks = run_checks(workspace)
    check = _check(checks, "att&ck")
    assert check.status == "problem", check.detail
    assert str(snapshot) in check.detail, check.detail
    assert check.fix == "adef attack refresh"
    # The index check must stay clear of the snapshot entirely on an *empty*
    # catalog. `build_index` reads the reference to resolve `by_tactic`, so
    # asking it "are there records" made a freshly `adef init`ed workspace a
    # `problem` the moment this file was corrupt — for a missing INDEX it does
    # not owe. `next(iter_records(), None)` answers the same question without
    # the reference.
    index = _check(checks, "index")
    assert index.status == "ok", index.detail
    assert "no records yet" in index.detail, index.detail
    # And through the command, which is where the traceback surfaced.
    result = CliRunner().invoke(doctor, ["--workspace", str(workspace)])
    assert result.exit_code == 1, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        result.exception
    )


def test_a_corrupt_snapshot_with_records_reports_the_index_not_raises(catalogued: Path):
    """The populated half: `build_index` really does read the snapshot.

    With records present the staleness comparison has to build the expected
    INDEX, which resolves `by_tactic` through `attack/enterprise.json` — so the
    `JSONDecodeError` reaches `_check_index` one check *before* `_check_attack`,
    the check that reports that file properly. Reported, not raised.
    """
    from adef.core.attack import attack_reference

    snapshot = catalogued / "attack" / "enterprise.json"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text('{"attack_version": "17.1", "techni', encoding="utf-8")
    # `adef catalog` in the fixture already warmed the per-path cache entry for
    # this workspace, so without this the planted file is never read and both
    # checks report happily. A real `adef doctor` is a fresh process.
    attack_reference.cache_clear()

    checks = run_checks(catalogued)
    index = _check(checks, "index")
    assert index.status == "problem", index.detail
    assert "cannot be verified" in index.detail, index.detail
    # No `fix`, the call `_check_catalog` already makes for an unparseable
    # record: whatever stopped `build_index` stops it inside `adef reindex`
    # too, so prescribing that hands the user a command that dies on the same
    # exception. `_check_attack` owns the snapshot fix and is in this same
    # report, four lines down.
    assert index.fix == "", index.fix
    assert _check(checks, "att&ck").fix == "adef attack refresh"
    result = CliRunner().invoke(doctor, ["--workspace", str(catalogued)])
    assert result.exit_code == 1, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), (
        result.exception
    )


def test_an_unindexable_record_is_not_blamed_on_the_attack_snapshot(catalogued: Path):
    """The second member of the input class — and why the message names no cause.

    `build_index` reads the ATT&CK reference, but it also groups by `engine`,
    `status` and `data_source`. A hand-edited `engine:` left as a *list* is
    unhashable, so the same `except` fires with no ATT&CK involvement at all.
    Worded as "the ATT&CK reference is unreadable", `adef doctor` printed
    `→ adef attack refresh` four lines above `att&ck ✓ v19.1` — a
    self-contradicting report prescribing a command that cannot help.
    """
    path = _record(catalogued)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["engine"] = ["sigma"]  # a mapping key build_index cannot hash
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    checks = run_checks(catalogued)
    index = _check(checks, "index")
    assert index.status == "problem", index.detail
    assert "cannot be verified" in index.detail, index.detail
    assert "unhashable" in index.detail, index.detail  # names what it saw
    assert "ATT&CK" not in index.detail, index.detail
    assert index.fix == "", index.fix
    # The snapshot is fine, and the report has to keep saying so.
    assert _check(checks, "att&ck").status == "ok"


# --------------------------------------------------------------------------- #
# Command surface
# --------------------------------------------------------------------------- #
def test_a_journal_in_a_subdirectory_is_flagged_not_paired(catalogued: Path):
    """`Journal` only reads `journals/D-XXXX.md`. A nested journal counted as
    paired here while `adef detection show` raised "Journal not found" for the
    same id, so doctor flags it instead of passing it.

    The journal is *moved*, not copied, so the flat path no longer exists.
    """
    (journal,) = (catalogued / "journals").glob("D-*.md")
    nested = catalogued / "journals" / "windows" / journal.name
    nested.parent.mkdir(parents=True)
    journal.rename(nested)

    check = _check(run_checks(catalogued), "journals")
    assert check.status == "warn", check.detail
    assert f"windows/{journal.name}" in check.detail, check.detail
    journals = catalogued / "journals"
    assert check.fix == f"mv -n {nested} {journals}/"  # absolute: doctor runs from anywhere


def test_nested_journals_do_not_hide_unpaired_records(catalogued: Path):
    """Reporting a nested journal must not stop the unpaired-record check."""
    journals = catalogued / "journals"
    (journal,) = journals.glob("D-*.md")
    (journals / "windows").mkdir()
    (journals / "windows" / "D-9999.md").write_text("stray", encoding="utf-8")
    journal.unlink()  # its record is now genuinely unpaired

    check = _check(run_checks(catalogued), "journals")
    assert "windows/D-9999.md" in check.detail, check.detail
    assert f"{journal.stem}" in check.detail and "no journal" in check.detail, check.detail


def test_a_nested_duplicate_is_flagged_for_a_hand_merge_not_moved(catalogued: Path):
    journals = catalogued / "journals"
    (journal,) = journals.glob("D-*.md")
    (journals / "windows").mkdir()
    (journals / "windows" / journal.name).write_text("older copy", encoding="utf-8")

    check = _check(run_checks(catalogued), "journals")
    assert "merging by hand" in check.detail, check.detail
    assert "mv" not in check.fix


def test_the_config_hint_names_the_file_that_actually_exists(workspace: Path):
    """The file is `.adefconfig.yaml` — hidden. The message said
    `adefconfig.yaml`, so a user who followed it would `ls config/`, see
    nothing, and conclude the file was missing rather than hidden."""
    from adef.core.workspace import config_path

    config_path(workspace).unlink(missing_ok=True)
    check = _check(run_checks(workspace), "workspace")
    assert ".adefconfig.yaml" in check.detail, check.detail
    # And it is the real name, not a second hand-typed copy of it.
    assert config_path(workspace).name in check.detail, check.detail


def test_warnings_alone_exit_zero(workspace: Path):
    """A fresh workspace is all warnings. Exiting 1 on those makes the command
    useless as a CI gate and tells a new user their setup is broken."""
    result = CliRunner().invoke(doctor, ["--workspace", str(workspace)])
    assert result.exit_code == 0, result.output
    assert "no problems" in result.output


def test_a_problem_exits_one(catalogued: Path):
    (catalogued / "catalog" / "INDEX.yml").unlink()
    result = CliRunner().invoke(doctor, ["--workspace", str(catalogued)])
    assert result.exit_code == 1, result.output
    assert "problem(s)" in result.output


def test_the_mcp_extra_hint_survives_rich_markup(workspace: Path, monkeypatch):
    """The install hint is a `fix` string containing a Rich style tag.
    Unescaped, Rich deletes `[mcp]` and prints an instruction that silently
    installs the package with no extras."""
    monkeypatch.setattr("adef.core.doctor.mcp_installed", lambda: False)
    monkeypatch.setattr("adef.core.doctor.editable_install", lambda: False)
    result = CliRunner().invoke(doctor, ["--workspace", str(workspace)])
    assert result.exit_code == 0, result.output
    assert "agentic-detection-engineering-framework[mcp]" in result.output


def test_an_editable_install_is_told_to_stay_editable(workspace: Path, monkeypatch):
    """The PyPI form would replace a clone's editable install with the wheel."""
    monkeypatch.setattr("adef.core.doctor.mcp_installed", lambda: False)
    monkeypatch.setattr("adef.core.doctor.editable_install", lambda: True)
    result = CliRunner().invoke(doctor, ["--workspace", str(workspace)])
    assert 'pip install -e ".[mcp]"' in result.output


def test_editable_install_reads_pep_610_metadata(monkeypatch):
    import importlib.metadata as md

    from adef.core.doctor import editable_install

    class Dist:
        def __init__(self, text):
            self.text = text

        def read_text(self, name):
            return self.text if name == "direct_url.json" else None

    monkeypatch.setattr(md, "distribution", lambda name: Dist('{"url": "file:///x", "dir_info": {"editable": true}}'))
    assert editable_install()
    monkeypatch.setattr(md, "distribution", lambda name: Dist('{"url": "https://files", "archive_info": {}}'))
    assert not editable_install()
    monkeypatch.setattr(md, "distribution", lambda name: Dist(None))  # plain wheel: no direct_url.json
    assert not editable_install()


def test_mcp_installed_checks_the_import_the_server_makes(monkeypatch):
    """The `[mcp]` extra ships `mcp.server.fastmcp`; the separate `fastmcp`
    package is not a dependency and must not be what the check looks for."""
    import builtins

    from adef.core.doctor import mcp_installed

    real_import = builtins.__import__

    def no_standalone_fastmcp(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "fastmcp" and level == 0:  # relative `.fastmcp` inside mcp is fine
            raise ModuleNotFoundError("No module named 'fastmcp'")
        return real_import(name, globals, locals, fromlist, level)

    pytest.importorskip("mcp.server.fastmcp")
    monkeypatch.setattr(builtins, "__import__", no_standalone_fastmcp)
    assert mcp_installed()


def test_report_json_carries_every_check_and_the_counts(catalogued: Path):
    (catalogued / "catalog" / "INDEX.yml").unlink()
    result = CliRunner().invoke(
        doctor, ["--workspace", str(catalogued), "--report", "json"]
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["problems"] == 1
    assert {c["name"] for c in payload["checks"]} == {c.name for c in run_checks(catalogued)}
    index = next(c for c in payload["checks"] if c["name"] == "index")
    assert index == {"name": "index", "status": "problem", "detail": index["detail"], "fix": "adef reindex"}
