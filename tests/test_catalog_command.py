"""Tests for the ``adef catalog`` CLI command."""

from __future__ import annotations

import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands import catalog as catalog_mod
from adef.commands.catalog import catalog
from adef.core.catalog import CatalogError


@pytest.fixture
def rule_repo(tmp_path):
    root = tmp_path / "their-detections"
    win = root / "windows"
    win.mkdir(parents=True)
    (win / "mshta.yml").write_text(
        textwrap.dedent(
            """\
            title: Suspicious mshta child
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [attack.t1218.005]
            """
        ),
        encoding="utf-8",
    )
    raw = root / "cloud"
    raw.mkdir(parents=True)
    (raw / "iam.sql").write_text("SELECT user_name FROM cloudtrail", encoding="utf-8")
    return root


def test_catalog_help():
    result = CliRunner().invoke(catalog, ["--help"])
    assert result.exit_code == 0
    assert "atalog" in result.output


def test_catalog_creates_records_and_index(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo)])
    assert result.exit_code == 0, result.output

    cat_dir = ws / "catalog"
    yamls = sorted(p for p in cat_dir.rglob("D-*.yml"))
    assert len(yamls) == 2  # one sigma, one sql

    index = yaml.safe_load((cat_dir / "INDEX.yml").read_text())
    assert len(index["detections"]) == 2
    assert "windows" in index["by_platform"]


def test_majority_unclaimed_nudge_escalates(tmp_path, monkeypatch):
    """When unclaimed files outnumber catalogued ones, the nudge is loud —
    one recognized Sigma rule beside a repo of an unrecognized format shouldn't
    read as success."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    root = tmp_path / "repo"
    root.mkdir()
    (root / "sigma.yml").write_text(
        textwrap.dedent(
            """\
            title: A sigma rule
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            """
        ),
        encoding="utf-8",
    )
    for i in range(3):  # in-house envelope no recognizer claims → unclaimed
        (root / f"inhouse{i}.yml").write_text(
            f"name: In-house {i}\nmetadata:\n  id: x{i}\ndetection:\n  query: SELECT 1\n",
            encoding="utf-8",
        )
    # A CI workflow is structured YAML but NOT rule-shaped — must not inflate
    # the "rule-shaped files" count.
    (root / ".github").mkdir()
    (root / ".github" / "ci.yml").write_text(
        "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(catalog, [str(root)])
    assert result.exit_code == 0, result.output
    assert "Most of this repo was not recognized" in result.output
    # 3 rule-shaped unclaimed of (3 + 1 catalogued) = 4; the CI file is excluded.
    assert "3 of 4 rule-shaped files" in result.output


def test_nudge_escalation_boundary_is_parity(capsys):
    """Parity escalates; one more catalogued than unclaimed does not.

    The CLI test above only reaches 3:1, so it stays green against any
    threshold up to 3x — a 2x rule passed the whole suite. Called directly
    because the boundary is two integers, not a repo shape.
    """
    from adef.commands.catalog import _print_unclaimed_nudge

    _print_unclaimed_nudge(2, 2)  # parity — the lowest escalating case
    assert "Most of this repo was not recognized" in capsys.readouterr().out

    _print_unclaimed_nudge(2, 3)  # one below parity — quiet
    out = capsys.readouterr().out
    assert "Most of this repo was not recognized" not in out
    assert "no recognizer or profile claims" in out  # still nudges, just not loudly


def test_recatalog_same_repo_is_refused(tmp_path, rule_repo, monkeypatch):
    """A second catalog of the same repo would mint duplicates → refused,
    pointing at `sync`."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    assert CliRunner().invoke(catalog, [str(rule_repo)]).exit_code == 0
    before = len(list((ws / "catalog").rglob("D-*.yml")))

    result = CliRunner().invoke(catalog, [str(rule_repo)])
    assert result.exit_code != 0
    assert "already catalogued" in result.output and "sync" in result.output
    # Nothing written on the refused run.
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before


def test_recatalog_with_force_appends(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    CliRunner().invoke(catalog, [str(rule_repo)])
    before = len(list((ws / "catalog").rglob("D-*.yml")))
    result = CliRunner().invoke(catalog, [str(rule_repo), "--force"])
    assert result.exit_code == 0, result.output
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before * 2  # duplicated on purpose
    # --force proceeds but warns about the duplicate→orphan consequence.
    assert "orphaned" in result.output.lower()
    assert "sync" in result.output.lower()


def test_catalog_new_repo_into_populated_workspace_appends(tmp_path, rule_repo, monkeypatch):
    """No identity overlap → not a re-catalog → appends cleanly, no false block."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    CliRunner().invoke(catalog, [str(rule_repo)])
    before = len(list((ws / "catalog").rglob("D-*.yml")))

    # A second, distinct repo (different rules) — should append, not be refused.
    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / "other.yml").write_text(
        "title: Distinct rule\n"
        "id: 99999999-0000-0000-0000-000000000abc\n"
        "logsource:\n  product: linux\n"
        "detection:\n  condition: selection\n"
        "tags:\n  - attack.t1059\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(catalog, [str(repo2)])
    assert result.exit_code == 0, result.output
    assert len(list((ws / "catalog").rglob("D-*.yml"))) == before + 1


def test_catalog_also_creates_skeleton_journals(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    CliRunner().invoke(catalog, [str(rule_repo)])
    journals = sorted((ws / "journals").rglob("D-*.md"))
    assert len(journals) == 2


def test_catalog_dry_run_writes_nothing(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo), "--dry-run"])
    assert result.exit_code == 0
    assert not list((ws / "catalog").rglob("D-*.yml"))
    assert "2" in result.output  # reports the count it would write


def test_catalog_reports_needs_review_count(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo)])
    # The raw SQL rule has no platform/MITRE → flagged for review.
    assert "review" in result.output.lower()


def test_catalog_ids_do_not_collide_with_existing_journals(tmp_path, rule_repo, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "journals" / "D-0001.md").write_text("---\nid: D-0001\n---\n")
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    CliRunner().invoke(catalog, [str(rule_repo)])
    ids = sorted(
        yaml.safe_load(p.read_text())["id"]
        for p in (ws / "catalog").rglob("D-*.yml")
    )
    # Existing D-0001 journal must not be overwritten; catalog starts at D-0002.
    assert "D-0001" not in ids
    assert ids == ["D-0002", "D-0003"]


# --------------------------------------------------------------------------- #
# Report honesty + file output + dry-run collapse (field report 2026-07-23:
# a user ran only --dry-run/--report variants and concluded catalog was broken)
# --------------------------------------------------------------------------- #
def test_report_json_says_nothing_was_written(tmp_path, rule_repo, monkeypatch):
    import json

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(rule_repo), "--report", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["dry_run"] is True
    assert report["written"] == 0
    assert "nothing was catalogued" in result.stderr  # terminal warning, off stdout
    assert not list((ws / "catalog").rglob("D-*.yml"))


def test_report_json_output_file(tmp_path, rule_repo, monkeypatch):
    import json

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    out = tmp_path / "report.json"

    result = CliRunner().invoke(
        catalog, [str(rule_repo), "--report", "json", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["dry_run"] is True
    assert str(out) in result.output  # confirmation line names the file


def test_output_without_report_errors(tmp_path, rule_repo, monkeypatch):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    result = CliRunner().invoke(catalog, [str(rule_repo), "-o", "x.json"])
    assert result.exit_code != 0
    assert "--report" in result.output


def test_dry_run_leads_with_nothing_written_and_collapses_mass_flags(
    tmp_path, monkeypatch
):
    """1,469 identical no_platform rows drowned the one line that mattered —
    dominant flag groups collapse to samples + a count."""
    root = tmp_path / "repo"
    root.mkdir()
    for i in range(30):
        (root / f"r{i}.sql").write_text(
            f"SELECT user_name FROM cloudtrail WHERE q = {i}", encoding="utf-8"
        )
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(catalog, [str(root), "--dry-run"])
    assert result.exit_code == 0, result.output
    first_line = next(line for line in result.output.splitlines() if line.strip())
    assert "nothing will be written" in first_line
    assert "more like these" in result.output
    # collapsed: far fewer record rows than rules
    record_rows = [line for line in result.output.splitlines() if "D-00" in line]
    assert len(record_rows) <= 6


def test_dry_run_prints_one_line_per_rule_with_long_titles(tmp_path, monkeypatch):
    """A long upstream title must not soft-wrap the preview, or eat the flag.

    Real corpora carry titles well past 80 chars ("AppX Package Installation
    Attempts Via AppInstaller.EXE" and longer). Wrapped, each rule occupies two
    lines and the review flag lands on its own — so a preview of a 111-rule
    corpus reads as if there were twice as many rules as it plans to write.
    Caught previewing Splunk's public ESCU corpus.

    The flag is also the part of the row the reader is meant to act on, so it
    gets the width first: Rich trims from the right, which is exactly where the
    flag sits, and a row whose `(no_platform)` was trimmed away reads as a rule
    that needs nothing.
    """
    root = tmp_path / "repo"
    root.mkdir()
    long_title = "Suspicious Remote Thread Creation By Uncommon Source Image Via AppInstaller"
    # Raw SPL in a `.conf` stanza: the platform can't be inferred, so the row
    # carries `(no_platform)` — the flag competing with the title for the last
    # few columns. (`no_mitre` is an enrichment reason, reported in the
    # headline rather than per row, so it wouldn't exercise this.)
    (root / "r.conf").write_text(
        f"[{long_title}]\nsearch = index=thrunt CommandLine=* | stats count\n",
        encoding="utf-8",
    )
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    # 80 cols: the title alone is over budget. 40: the `D-XXXX platform format`
    # head is over budget *by itself*, so trimming only the title leaves the row
    # still too wide and Rich clips the flag off the right — the head has to be
    # fitted alongside the title, as one string.
    for width in (80, 40):
        monkeypatch.setattr(catalog_mod.console, "width", width)
        result = CliRunner().invoke(catalog, [str(root), "--dry-run"])
        assert result.exit_code == 0, result.output

        lines = result.output.splitlines()
        rows = [ln for ln in lines if "D-0001" in ln]
        assert len(rows) == 1, f"record row was split at {width} cols: {result.output!r}"
        assert "no_platform" in rows[0], (
            f"at {width} cols the review flag was trimmed for the title: {rows[0]!r}"
        )
        assert "…" in rows[0], f"the title should be what gave way: {rows[0]!r}"
        # The continuation would be the line straight after the row, carrying
        # the tail of the title rather than being blank or the next section.
        nxt = lines[lines.index(rows[0]) + 1]
        assert "AppInstaller" not in nxt, f"title wrapped onto the next line: {nxt!r}"


def _profile_repo(tmp_path, monkeypatch, bad_platform):
    """A two-rule repo read by a user profile that lifts `platform` from content."""
    root = tmp_path / "repo"
    root.mkdir()
    for name, platform in (("a.yml", "windows"), ("b.yml", bad_platform)):
        (root / name).write_text(
            yaml.safe_dump({"alert": {"name": name, "query": "SELECT 1",
                                      "platform": platform}}),
            encoding="utf-8",
        )
    prof = tmp_path / "acme.yml"
    prof.write_text(
        yaml.safe_dump({
            "name": "acme", "version": 1,
            "signature": {"container": "yaml", "all_keys": ["alert"]},
            "query_language": "sql",
            "platform": {"path": "alert.platform"},
            "map": {"title": "alert.name", "query": "alert.query"},
        }),
        encoding="utf-8",
    )
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    return root, prof, ws


def test_an_unusable_profile_platform_is_queued_not_fatal(tmp_path, monkeypatch):
    """A profile's `platform.path` lifts arbitrary text out of the user's document.

    This used to kill the run: a 300-character platform passed every charset
    check `safe_platform` made, became the bucket, and then hit `record_path`'s
    length refusal — so one unusable value in one rule refused the *entire*
    repo, `--dry-run` included. The other rule was fine and the author could not
    tell from the message which document to fix. Unusable now means what an
    unreadable platform has always meant: `multi-platform` plus `no_platform`,
    for a human to resolve, and the rest of the repo catalogues normally.
    """
    root, prof, ws = _profile_repo(tmp_path, monkeypatch, "w" * 300)

    dry = CliRunner().invoke(catalog, [str(root), "--dry-run", "--profile", str(prof)])
    assert dry.exit_code == 0, dry.output

    result = CliRunner().invoke(catalog, [str(root), "--profile", str(prof)])
    assert result.exit_code == 0, result.output
    written = {rec["title"]: rec for rec in
               (yaml.safe_load(p.read_text()) for p in (ws / "catalog").rglob("D-*.yml"))}
    assert sorted(written) == ["a.yml", "b.yml"]  # the good rule was not collateral
    assert written["a.yml"]["platform"] == "windows"
    assert written["b.yml"]["platform"] == "multi-platform"
    # Flagged, not silently bucketed: an unusable platform that reads as settled
    # coverage is worse than one that kills the run, because nobody finds out.
    assert "no_platform" in written["b.yml"]["review_reasons"]


def test_a_refused_planned_path_stops_the_whole_run_not_part_of_it(tmp_path, monkeypatch):
    """A refusal mid-loop is worse than a refusal: a half-catalogued tree.

    The write guard used to raise on the offending rule, by which point every
    earlier record was on disk and `rebuild_index` was never reached — a stale
    INDEX over a partial catalog, the exact state the guard exists to prevent.
    `record_path` is pure, so the whole plan is vetted before the first write.

    Injected at the seam rather than driven by a bad platform, because **no CLI
    input can reach this guard any more**: every producer of a record platform
    now routes through `safe_platform` (profile extraction, Sigma `logsource`
    allow-list, declaration inheritance, GATES `platforms`, schema drafts), so a
    value `record_path` would refuse cannot be built from a repo on disk. The
    guard is now a backstop for the next producer that forgets the helper —
    which is worth keeping *and* worth keeping tested, since a backstop nobody
    exercises is indistinguishable from one that was deleted.
    """
    root, prof, ws = _profile_repo(tmp_path, monkeypatch, "linux")
    real = catalog_mod.record_path

    def refuse_the_second(directory, rec):
        if rec.id.endswith("0002"):
            raise CatalogError(f"Refused to write {rec.id}: synthetic refusal.")
        return real(directory, rec)

    monkeypatch.setattr(catalog_mod, "record_path", refuse_the_second)

    # The dry run sees it too — otherwise it reports "2 rules would be catalogued"
    # for a plan the real run refuses, which is the surprise a dry run exists to
    # prevent. `hunt-promote --gates --dry-run` already validated paths; this is the
    # same guarantee on the other entry point.
    dry = CliRunner().invoke(catalog, [str(root), "--dry-run", "--profile", str(prof)])
    assert dry.exit_code != 0
    assert "synthetic refusal" in dry.output

    result = CliRunner().invoke(catalog, [str(root), "--profile", str(prof)])
    assert result.exit_code != 0
    assert "synthetic refusal" in result.output
    # Nothing written at all — not the good rule, not an INDEX, not a journal.
    assert list((ws / "catalog").rglob("D-*.yml")) == []
    assert not (ws / "catalog" / "INDEX.yml").exists()
    assert list((ws / "journals").glob("D-*.md")) == []


def test_dry_run_renders_an_upstream_title_literally(tmp_path, monkeypatch):
    """A rule title containing Rich markup must not be interpreted.

    Titles are upstream free text. A rule literally titled
    ``Dump [bold red]LSASS[/]`` was being handed to Rich as markup, with two
    consequences: it styled the row, and ``[bold red]`` plus ``[/]`` cost 14
    cells of the title budget that never reached the screen, so the ellipsis
    cut content that would have fitted. A title ending in ``[/yellow]`` would
    also close the review flag's own styling — the flag being the one part of
    the row the reader is meant to act on.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / "r.conf").write_text(
        "[Dump [bold red]LSASS[/] memory]\nsearch = index=thrunt | stats count\n",
        encoding="utf-8",
    )
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    monkeypatch.setattr(catalog_mod.console, "width", 120)

    result = CliRunner().invoke(catalog, [str(root), "--dry-run"])
    assert result.exit_code == 0, result.output
    row = next(ln for ln in result.output.splitlines() if "D-0001" in ln)
    assert "[bold red]LSASS[/]" in row, f"markup was consumed, not printed: {row!r}"
    # And the flag still renders, after the escaped title.
    assert "no_platform" in row, row


def test_workspace_flag_reaches_the_mitre_validator(tmp_path, monkeypatch):
    """`--workspace X` must judge `invalid_mitre` against X's ATT&CK snapshot.

    `invalid_mitre` is only answerable against *some* ATT&CK version, and the
    chain that decides it — `walk_outcomes` → `finalize_review` →
    `mitre_review_reasons` → `_has_invalid_mitre` — resolved one from
    `$ADEF_WORKSPACE` or the shipped package copy, never from the `--workspace`
    the command had already resolved for `Catalog`. So a rule mapped to a
    technique newer than the shipped snapshot came out flagged, and unlike a
    wrong report this one *persists*: `needs_review: true` and `invalid_mitre`
    are written into the record, and a human then triages a queue of rules that
    were correct all along.

    The env var points at a different directory on purpose — with it set to the
    same path, zero-arg resolution would find the snapshot too and a pass would
    prove nothing. `T9999` is the lever: fiction to the shipped snapshot, real
    to this one.
    """
    import json

    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "attack").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(elsewhere))

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "attack").mkdir(parents=True)
    (ws / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-local",
                "tactics": {"execution": "Execution"},
                "techniques": {"T9999": {"name": "Local Only", "tactics": ["execution"]}},
            }
        ),
        encoding="utf-8",
    )

    repo = tmp_path / "rules"
    (repo / "windows").mkdir(parents=True)
    (repo / "windows" / "local.yml").write_text(
        textwrap.dedent(
            """\
            title: Mapped to a locally-known technique
            id: 7d1c9b6e-0000-4000-8000-00000000f00d
            logsource:
                product: windows
            detection:
                condition: selection
            tags: [attack.t9999]
            """
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(catalog, [str(repo), "--workspace", str(ws)])
    assert result.exit_code == 0, result.output

    records = sorted((ws / "catalog").rglob("D-*.yml"))
    assert len(records) == 1, records
    rec = yaml.safe_load(records[0].read_text(encoding="utf-8"))
    assert rec["mitre"] == ["T9999"], rec
    # The assertion that matters is *absence* — `invalid_mitre` not written.
    # Checking `needs_review is False` alone would pass on a record flagged for
    # some other reason losing that reason, which is a different bug.
    assert "invalid_mitre" not in (rec.get("review_reasons") or []), rec
    assert rec.get("needs_review") is False, rec


def test_workspace_flag_reaches_the_mitre_validator_after_platform_inheritance(
    tmp_path, monkeypatch
):
    """`adef catalog` recomputes the reasons a *second* time, and that one counts too.

    `_inherit_platforms` re-runs `finalize_review` after a rule inherits its
    platform from a declared schema, and `finalize_review` rebuilds
    `review_reasons` **wholesale** — so a workspace dropped there overwrites the
    correct verdict the walk just computed. The sibling test above cannot reach
    it: its rule declares `logsource: product: windows`, so `disc.platform` is
    already set and the inheritance pass skips it at `if disc.platform: continue`.
    Reverting `workspace=ws` at `commands/catalog.py` left the whole suite green,
    measured — this test is the only thing that reddens it.

    The lever is a `.conf` rule with no platform of its own plus a declaration
    that addresses its `sourcetype`, which is the production shape: a user who
    ran `adef schema ingest` and catalogs rules whose format carries no platform.

    `$ADEF_WORKSPACE` holds a *third* snapshot here, not an empty directory, so a
    pass proves the argument beat the **env var** — the actual production
    confusion. With no snapshot there, zero-arg falls through to the shipped copy
    instead and the test would only prove the argument beat *that*.
    """
    import json

    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "attack").mkdir(parents=True)
    (elsewhere / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "88.8-env",
                "tactics": {"execution": "Execution"},
                "techniques": {"T1111": {"name": "Env Only", "tactics": ["execution"]}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ADEF_WORKSPACE", str(elsewhere))

    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "attack").mkdir(parents=True)
    (ws / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-local",
                "tactics": {"execution": "Execution"},
                "techniques": {"T9999": {"name": "Local Only", "tactics": ["execution"]}},
            }
        ),
        encoding="utf-8",
    )
    (ws / "schema").mkdir()
    (ws / "schema" / "wineventlog_xml.yml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "source": "wineventlog_xml",
                "platform": "windows",
                "scope": {"index": "thrunt", "sourcetype": "XmlWinEventLog"},
                "fields": [{"name": "EventCode", "provenance": "declared"}],
            }
        ),
        encoding="utf-8",
    )

    repo = tmp_path / "rules"
    repo.mkdir()
    # `.conf` carries no platform, so the walk leaves `no_platform` on it and the
    # inheritance pass is what resolves it. `# T9999` is picked up by the comment
    # sweep, which is what gives the recomputation a mapping to misjudge.
    (repo / "pinned.conf").write_text(
        "# T9999\n[Inherits its platform]\n"
        "search = index=thrunt sourcetype=XmlWinEventLog EventCode=1\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(catalog, [str(repo), "--workspace", str(ws)])
    assert result.exit_code == 0, result.output
    # Without this, the rule never enters the branch under test.
    assert "platform(s) inherited" in result.output, result.output

    records = sorted((ws / "catalog").rglob("D-*.yml"))
    assert len(records) == 1, records
    rec = yaml.safe_load(records[0].read_text(encoding="utf-8"))
    assert rec["platform"] == "windows", rec
    assert rec["mitre"] == ["T9999"], rec
    assert rec.get("review_reasons") == [], rec
    assert rec.get("needs_review") is False, rec
