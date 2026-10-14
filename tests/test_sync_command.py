"""End-to-end tests for `adef sync` — the guarantee that re-syncing preserves
enrichment while refreshing changed rules."""

from __future__ import annotations

import json
import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.catalog import catalog
from adef.commands.sync import sync
from adef.core.catalog import Catalog
from adef.core.journal import Journal


def _sigma(uuid: str, title: str = "Rundll32 no args") -> str:
    return textwrap.dedent(
        f"""\
        title: {title}
        id: {uuid}
        logsource:
            product: windows
        detection:
            condition: selection
        tags:
            - attack.t1218.011
        """
    )


def _make_repo(tmp_path):
    repo = tmp_path / "rules"
    repo.mkdir()
    (repo / "r.yml").write_text(_sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca"), encoding="utf-8")
    return repo


def _record(ws, det_id):
    for rid, _p, data in Catalog(ws).iter_records():
        if rid == det_id:
            return data
    raise AssertionError(f"{det_id} not found")


def test_sync_preserves_enrichment_on_modified(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    # Enrich: set MITRE + a manual status/owner on the record.
    path, data = Catalog(ws).find_record("D-0001")
    data["mitre"] = ["T1218.011"]
    data["status"] = "ready"
    data["owner"] = "alice"
    Catalog(ws).write_raw(path, data)

    # Change the source file (new content → new hash).
    (repo / "r.yml").write_text(
        _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca", title="Rundll32 no args v2"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0, result.output

    after = _record(ws, "D-0001")
    # Enrichment preserved:
    assert after["mitre"] == ["T1218.011"]
    assert after["status"] == "ready"
    assert after["owner"] == "alice"
    # Derived refreshed:
    assert after["title"] == "Rundll32 no args v2"


def test_sync_note_preserves_journal_stage(tmp_path, monkeypatch):
    """Journaling an out-of-band source change must NOT yank the detection to
    `evolve` — it stays at whatever FORGE stage it was in (CodeRabbit)."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    # Move the detection mid-lifecycle (to `refine`), not evolve.
    journal = Journal(ws / "journals")
    journal.advance_stage(detection_id="D-0001", stage="observe")
    journal.advance_stage(detection_id="D-0001", stage="refine")
    assert journal.read("D-0001").current_stage == "refine"

    # Source changes → sync journals the modification.
    (repo / "r.yml").write_text(
        _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca", title="Rundll32 v2"),
        encoding="utf-8",
    )
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0

    # Stage held at refine, not forced to evolve.
    assert journal.read("D-0001").current_stage == "refine"


def test_sync_orphans_deleted_rule(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (repo / "r.yml").unlink()  # rule gone from the repo

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0, result.output

    after = _record(ws, "D-0001")
    assert after["status"] == "deprecated"
    assert after.get("orphaned") is True
    # The record (and its "why") is kept, never deleted.


def test_sync_orphaned_note_is_not_findable(tmp_path, monkeypatch):
    # the orphaned-housekeeping note `adef sync`
    # writes is derived restatement — `orphaned: true` is already on the
    # record — so it is marked generated and must not feed back into search.
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (repo / "r.yml").unlink()
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0

    from adef.core.journal import narrative_text

    entry = Journal(ws / "journals").read("D-0001")
    assert "orphaned by" not in narrative_text(entry.body)
    # Sanity: the note really is in the raw file — this is index exclusion
    # only, never a change to what's written (r1 caution).
    assert "orphaned by" in entry.body


def test_sync_modified_note_is_not_findable(tmp_path, monkeypatch):
    # Same principle for the other sync-generated note: the source hash is
    # already stored on the record, and this note repeats on every sync.
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (repo / "r.yml").write_text(
        _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca", title="Rundll32 v2"),
        encoding="utf-8",
    )
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0

    from adef.core.journal import narrative_text

    entry = Journal(ws / "journals").read("D-0001")
    out = narrative_text(entry.body)
    assert "derived fields refreshed" not in out
    assert "derived fields refreshed" in entry.body


def test_sync_check_exits_nonzero_when_behind(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    assert CliRunner().invoke(sync, [str(repo), "--check"]).exit_code == 0  # current

    (repo / "r.yml").unlink()
    result = CliRunner().invoke(sync, [str(repo), "--check"])
    assert result.exit_code == 1  # behind
    # --check writes nothing: record is still its original (non-orphaned) form.
    assert _record(ws, "D-0001").get("orphaned") is not True


def test_sync_recreates_missing_journal(tmp_path, monkeypatch):
    """A matched record whose journal was deleted gets a fresh skeleton on sync,
    even when the source repo has no changes (the backfill-repair pass)."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    # Enrich the record so the repair has real metadata to propagate.
    path, data = Catalog(ws).find_record("D-0001")
    data["owner"] = "alice"
    Catalog(ws).write_raw(path, data)
    jpath = ws / "journals" / "D-0001.md"
    assert jpath.exists()
    jpath.unlink()

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0
    assert jpath.exists()
    # Metadata lands in parsed frontmatter, not merely somewhere in the file.
    entry = Journal(ws / "journals").read("D-0001")
    assert entry.frontmatter["title"] == "Rundll32 no args"
    assert entry.frontmatter["owner"] == "alice"
    assert entry.frontmatter["rule_uuid"] == "03cc0c25-389f-4bf8-b48d-11878079f1ca"
    assert entry.frontmatter["current_stage"] == "find"
    assert "re-created by `adef sync`" in entry.body


def test_sync_repaired_journal_note_is_not_findable(tmp_path, monkeypatch):
    # `sync.py`'s repair-pass `journal.create()` call is a
    # third, separate note-writing site — not routed through `_journal_note`,
    # so that helper's `generated=True` default never reached it. Same
    # derived-restatement class as the other two sync notes: the fact a
    # journal was missing has no search value.
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    jpath = ws / "journals" / "D-0001.md"
    jpath.unlink()

    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0

    from adef.core.journal import narrative_text

    entry = Journal(ws / "journals").read("D-0001")
    assert "re-created by" not in narrative_text(entry.body)
    # Sanity: the note really is in the raw file — index exclusion only.
    assert "re-created by" in entry.body


def test_sync_dry_run_does_not_recreate_journal(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (ws / "journals" / "D-0001.md").unlink()

    CliRunner().invoke(sync, [str(repo), "--dry-run"])
    assert not (ws / "journals" / "D-0001.md").exists()


def test_sync_check_does_not_recreate_journal(tmp_path, monkeypatch):
    """--check is read-only: a missing journal is not repaired, and with no
    source drift the exit code stays 0."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    (ws / "journals" / "D-0001.md").unlink()

    result = CliRunner().invoke(sync, [str(repo), "--check"])
    assert result.exit_code == 0  # no drift
    assert not (ws / "journals" / "D-0001.md").exists()


def test_sync_repair_skips_malformed_record_ids(tmp_path, monkeypatch):
    """A hand-edited record id must never become a filesystem path."""
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)

    CliRunner().invoke(catalog, [str(repo)])
    evil = ws / "catalog" / "windows" / "D-9999-evil.yml"
    evil.parent.mkdir(parents=True, exist_ok=True)
    evil.write_text("id: ../../escape\ntitle: evil\n", encoding="utf-8")

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0
    assert not (ws / "escape.md").exists()
    assert not (tmp_path / "escape.md").exists()


# --- Multi-record files (profile `signature.records`): every record in one
# export shares the file's path and byte hash, so neither can be a per-record
# identity. (CodeRabbit.)
_BULK = {
    "name": "acme-bulk-export", "version": 1,
    "signature": {"container": "json", "records": "data[]", "all_keys": ["name", "body"]},
    "query_language": "sql",
    "map": {"title": "name", "query": "body.predicate", "uuid": "rule_key"},
    "platform": {"const": "windows"},
}


def _rec(name, pred, key=None):
    r = {"name": name, "body": {"predicate": pred}}
    if key:
        r["rule_key"] = key
    return r


def _bulk_setup(tmp_path, monkeypatch, records, with_uuid):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    (ws / "config" / "profiles").mkdir(parents=True)
    prof = json.loads(json.dumps(_BULK))
    if not with_uuid:
        del prof["map"]["uuid"]
    (ws / "config" / "profiles" / "bulk.yml").write_text(yaml.safe_dump(prof), encoding="utf-8")
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = tmp_path / "rules"
    repo.mkdir()
    (repo / "export.json").write_text(json.dumps({"data": records}), encoding="utf-8")
    assert CliRunner().invoke(catalog, [str(repo)]).exit_code == 0
    return ws, repo


def _by_title(ws):
    return {d["title"]: d for _i, _p, d in Catalog(ws).iter_records()}


def test_reordering_a_uuidless_export_keeps_every_record(tmp_path, monkeypatch):
    a, b = _rec("A rule", "`a` = 1"), _rec("B rule", "`b` = 2")
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [a, b], with_uuid=False)
    before = {t: d["id"] for t, d in _by_title(ws).items()}
    (repo / "export.json").write_text(json.dumps({"data": [b, a]}), encoding="utf-8")
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = _by_title(ws)
    assert {t: d["id"] for t, d in after.items()} == before
    assert not any(d.get("orphaned") for d in after.values())


def test_editing_one_record_does_not_touch_its_siblings(tmp_path, monkeypatch):
    a, b = _rec("A rule", "`a` = 1", "k-a"), _rec("B rule", "`b` = 2", "k-b")
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [a, b], with_uuid=True)
    a_hash = _by_title(ws)["A rule"]["source_hash"]
    b2 = _rec("B rule", "`b` = 3", "k-b")
    (repo / "export.json").write_text(json.dumps({"data": [a, b2]}), encoding="utf-8")
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = _by_title(ws)
    assert after["A rule"]["source_hash"] == a_hash  # A unchanged — no spurious modify
    assert after["B rule"]["query"] == "`b` = 3"


def test_an_edited_uuidless_record_never_binds_to_a_sibling(tmp_path, monkeypatch):
    a, b = _rec("A rule", "`a` = 1"), _rec("B rule", "`b` = 2")
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [a, b], with_uuid=False)
    b_id = _by_title(ws)["B rule"]["id"]
    a2 = _rec("A rule v2", "`a` = 9")  # no identity survives this edit
    (repo / "export.json").write_text(json.dumps({"data": [a2, b]}), encoding="utf-8")
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = _by_title(ws)
    assert after["B rule"]["id"] == b_id and not after["B rule"].get("orphaned")
    assert after["B rule"]["query"] == "`b` = 2"  # untouched by A's edit
    assert after["A rule"].get("orphaned") is True  # old A: honest orphan
    assert "A rule v2" in after and not after["A rule v2"].get("orphaned")  # new A: new record


def test_duplicate_records_in_one_export_each_keep_their_record(tmp_path, monkeypatch):
    # Byte-identical records hash identically; each must still bind to its
    # own catalog record rather than both landing on the first.
    a, b = _rec("A rule", "`a` = 1"), _rec("B rule", "`b` = 2")
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [a, a, b], with_uuid=False)
    ids = sorted(d["id"] for _i, _p, d in Catalog(ws).iter_records())
    assert len(ids) == 3
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = [d for _i, _p, d in Catalog(ws).iter_records()]
    assert sorted(d["id"] for d in after) == ids
    assert not any(d.get("orphaned") for d in after)


# --- identity must not depend on order or record count.

def _set_mitre(ws, title, mitre):
    for _rid, path, data in Catalog(ws).iter_records():
        if data["title"] == title:
            data["mitre"] = mitre
            Catalog(ws).write_raw(path, data)
            return data["id"]
    raise AssertionError(title)


def test_duplicate_uuids_in_one_export_each_keep_their_record(tmp_path, monkeypatch):
    a, a_dup, b = _rec("A", "`a` = 1", "k-a"), _rec("A dup", "`a` = 2", "k-a"), _rec("B", "`b` = 2", "k-b")
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [a, a_dup, b], with_uuid=True)
    before = {t: d["id"] for t, d in _by_title(ws).items()}
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = _by_title(ws)
    assert {t: d["id"] for t, d in after.items()} == before
    assert not any(d.get("orphaned") for d in after.values())


def test_a_new_rule_inserted_first_never_takes_an_existing_rules_record(tmp_path, monkeypatch):
    a = _rec("A", "`a` = 1", "k-a")
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [a], with_uuid=True)
    a_id = _set_mitre(ws, "A", ["T1003"])
    (repo / "export.json").write_text(json.dumps({"data": [_rec("N", "`n` = 1", "k-n"), a]}))
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = _by_title(ws)
    assert after["A"]["id"] == a_id and after["A"]["mitre"] == ["T1003"]
    assert "N" in after and after["N"]["id"] != a_id


@pytest.mark.parametrize("before_records, after_records", [
    (["A", "B"], ["A"]),      # a file shrinking to one record
    (["A"], ["N", "A"]),      # one record growing to two, the new one first
])
def test_uuidless_identity_survives_the_record_count_changing(tmp_path, monkeypatch, before_records, after_records):
    rec = {t: _rec(t, f"`{t.lower()}` = 1") for t in {"A", "B", "N"}}
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [rec[t] for t in before_records], with_uuid=False)
    a_id = _set_mitre(ws, "A", ["T1003"])
    (repo / "export.json").write_text(json.dumps({"data": [rec[t] for t in after_records]}))
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = _by_title(ws)
    assert after["A"]["id"] == a_id and after["A"]["mitre"] == ["T1003"]
    assert not after["A"].get("orphaned")


def test_byte_identical_files_each_keep_their_own_record(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = tmp_path / "rules"
    repo.mkdir()
    for name in ("a.sql", "b.sql"):
        (repo / name).write_text("SELECT * FROM t WHERE `x` = 1\n", encoding="utf-8")
    assert CliRunner().invoke(catalog, [str(repo)]).exit_code == 0
    by_ref = {d["rule_ref"]: d["id"] for _i, _p, d in Catalog(ws).iter_records()}
    b_id = by_ref["rules/b.sql"]
    (repo / "a.sql").unlink()
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = {d["id"]: d for _i, _p, d in Catalog(ws).iter_records()}
    assert not after[b_id].get("orphaned")            # b keeps its own record
    assert after[by_ref["rules/a.sql"]].get("orphaned")  # a's record is the orphan


def test_a_replacement_rule_with_its_own_uuid_never_inherits_the_old_rules_record(tmp_path, monkeypatch):
    # Same file, A removed and an unrelated N added: the path is shared, the
    # UUIDs differ — N is new and A is an honest orphan, not a silent rename.
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [_rec("A", "`a` = 1", "k-a")], with_uuid=True)
    a_id = _set_mitre(ws, "A", ["T1003"])
    (repo / "export.json").write_text(json.dumps({"data": [_rec("N", "`n` = 1", "k-n")]}))
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    after = _by_title(ws)
    assert after["A"]["id"] == a_id and after["A"].get("orphaned") is True
    assert after["N"]["id"] != a_id and not after["N"].get("mitre")


# --- A workspace holding two repos: syncing one must never
# orphan the other's records.

def _two_repo_ws(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repos = {}
    for name, uuid in (("sigma-a", "11111111-1111-4111-8111-111111111111"),
                       ("sigma-b", "22222222-2222-4222-8222-222222222222")):
        repo = tmp_path / name
        repo.mkdir()
        (repo / "r.yml").write_text(_sigma(uuid, title=f"{name} rule"), encoding="utf-8")
        assert CliRunner().invoke(catalog, [str(repo)]).exit_code == 0
        repos[name] = repo
    return ws, repos


def test_syncing_one_repo_never_orphans_another_repos_records(tmp_path, monkeypatch):
    ws, repos = _two_repo_ws(tmp_path, monkeypatch)
    assert CliRunner().invoke(sync, [str(repos["sigma-a"])]).exit_code == 0
    after = {d["title"]: d for _i, _p, d in Catalog(ws).iter_records()}
    assert not after["sigma-b rule"].get("orphaned")
    assert after["sigma-b rule"].get("status") != "deprecated"


def test_check_passes_for_an_unchanged_repo_in_a_two_repo_workspace(tmp_path, monkeypatch):
    _ws, repos = _two_repo_ws(tmp_path, monkeypatch)
    result = CliRunner().invoke(sync, ["--check", str(repos["sigma-a"])])
    assert result.exit_code == 0, result.output


def test_a_rule_deleted_from_the_synced_repo_is_still_orphaned(tmp_path, monkeypatch):
    ws, repos = _two_repo_ws(tmp_path, monkeypatch)
    (repos["sigma-a"] / "r.yml").unlink()
    assert CliRunner().invoke(sync, [str(repos["sigma-a"])]).exit_code == 0
    after = {d["title"]: d for _i, _p, d in Catalog(ws).iter_records()}
    assert after["sigma-a rule"].get("orphaned") is True
    assert not after["sigma-b rule"].get("orphaned")


def test_a_moved_repo_still_owns_its_records(tmp_path, monkeypatch):
    # original_path is stale after a move; the <root-name>/ rule_ref still ties
    # the records to the repo, so a rule deleted after the move is orphaned.
    ws, repos = _two_repo_ws(tmp_path, monkeypatch)
    moved = tmp_path / "elsewhere" / "sigma-a"
    moved.parent.mkdir()
    repos["sigma-a"].rename(moved)
    (moved / "r.yml").unlink()
    assert CliRunner().invoke(sync, [str(moved)]).exit_code == 0
    after = {d["title"]: d for _i, _p, d in Catalog(ws).iter_records()}
    assert after["sigma-a rule"].get("orphaned") is True
    assert not after["sigma-b rule"].get("orphaned")


def test_a_legacy_workspace_relative_rule_ref_is_scoped_by_original_path(tmp_path, monkeypatch):
    # Records catalogued before rule_ref became `<root-name>/...` carry a
    # workspace-relative ref; their original_path is what ties them to a repo.
    ws, repos = _two_repo_ws(tmp_path, monkeypatch)
    for _rid, path, data in Catalog(ws).iter_records():
        if data["title"] == "sigma-a rule":
            data["rule_ref"] = "../sigma-a/r.yml"
            Catalog(ws).write_raw(path, data)
    (repos["sigma-a"] / "r.yml").unlink()
    assert CliRunner().invoke(sync, [str(repos["sigma-a"])]).exit_code == 0
    after = {d["title"]: d for _i, _p, d in Catalog(ws).iter_records()}
    assert after["sigma-a rule"].get("orphaned") is True
    assert not after["sigma-b rule"].get("orphaned")


def test_same_named_repos_never_orphan_each_other(tmp_path, monkeypatch):
    # Two repos both called `rules` share the `rules/` rule_ref prefix; a rule
    # deleted from one must not be orphaned by syncing the other.
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    a, b = tmp_path / "org-a" / "rules", tmp_path / "org-b" / "rules"
    for repo, uuid, title in ((a, "33333333-3333-4333-8333-333333333333", "A rule"),
                              (b, "44444444-4444-4444-8444-444444444444", "B rule")):
        repo.mkdir(parents=True)
        (repo / "r.yml").write_text(_sigma(uuid, title=title), encoding="utf-8")
        assert CliRunner().invoke(catalog, [str(repo)]).exit_code == 0
    (b / "r.yml").unlink()  # B's rule is gone — but only B's sync may say so
    assert CliRunner().invoke(sync, [str(a)]).exit_code == 0
    after = {d["title"]: d for _i, _p, d in Catalog(ws).iter_records()}
    assert not after["B rule"].get("orphaned")
    assert not after["A rule"].get("orphaned")


def test_sync_backfills_an_unmapped_record_and_clears_no_mitre(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)
    CliRunner().invoke(catalog, [str(repo)])
    # The shape a record catalogued before its mapping was readable has.
    path, data = Catalog(ws).find_record("D-0001")
    data.update(mitre=[], review_reasons=["no_mitre"], needs_review=True)
    Catalog(ws).write_raw(path, data)

    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0  # file untouched
    rec = _record(ws, "D-0001")
    assert rec["mitre"] == ["T1218.011"]
    assert "no_mitre" not in rec["review_reasons"]


def test_sync_keeps_a_hand_mapping_off_the_no_mitre_queue(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = tmp_path / "rules"
    repo.mkdir()
    untagged = _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca").replace("tags:\n    - attack.t1218.011\n", "")
    (repo / "r.yml").write_text(untagged, encoding="utf-8")
    CliRunner().invoke(catalog, [str(repo)])
    path, data = Catalog(ws).find_record("D-0001")
    assert "no_mitre" in data["review_reasons"]  # the source has no mapping
    data.update(mitre=["T1003"], review_reasons=[], needs_review=False)
    Catalog(ws).write_raw(path, data)

    (repo / "r.yml").write_text(untagged.replace("Rundll32", "Rundll32 v2"), encoding="utf-8")
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0  # MODIFIED
    rec = _record(ws, "D-0001")
    assert rec["title"] == "Rundll32 v2 no args"
    assert rec["mitre"] == ["T1003"]
    assert "no_mitre" not in rec["review_reasons"]



def test_sync_preserves_the_whole_enrichment_block_not_five_fields(tmp_path, monkeypatch):
    """`mitre`/`status`/`stage`/`owner` were not the only things a human writes.

    The MODIFIED path re-derives the record (it needs the real rule root for
    `rule_ref`) and then grafts enrichment back by name — so every enrichment
    field missing from that list was silently destroyed by a sync of an edited
    rule. Discovery has no value to refresh `description` or `references` *from*,
    which is exactly why they can't be left to a re-derive.
    """
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)
    CliRunner().invoke(catalog, [str(repo)])

    path, data = Catalog(ws).find_record("D-0001")
    enrichment = {
        "description": "Written by a human, not by any extractor.",
        "references": ["https://example.invalid/writeup"],
        "entities": [{"name": "endpoint.uid", "type": "endpoint"}],
        "observables": [{"name": "process.command_line", "type": "command_line"}],
        "alert": {"severity": "high"},
        "platforms": ["windows", "macos"],
    }
    Catalog(ws).write_raw(path, {**data, **enrichment})

    (repo / "r.yml").write_text(_sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca") + "\n# edited\n",
                                encoding="utf-8")
    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0

    after = _record(ws, "D-0001")
    for key, value in enrichment.items():
        assert after[key] == value, f"sync destroyed {key}"
    # The point of the re-derive still holds: the changed source refreshed.
    assert after["source_hash"] != data["source_hash"]


def test_sync_does_not_match_a_promoted_record_by_rule_ref(tmp_path, monkeypatch):
    """`promoted` was skipped in the orphan pass but not in the match cascade.

    A promoted record's `rule_ref` is `<gates-dir>/<file>.yaml`. Walk a rule repo
    whose name and layout produce the same string and the cascade matched it,
    sending a GATES-derived record down MODIFIED — overwriting `origin` and the
    enrichment the document supplied with a rule-repo derivation.
    """
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = tmp_path / "rules"
    (repo / "sub").mkdir(parents=True)
    (repo / "sub" / "r.yml").write_text(_sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca"),
                                        encoding="utf-8")

    cat = Catalog(ws)
    CliRunner().invoke(catalog, [str(repo)])
    path, data = cat.find_record("D-0001")
    # Re-stamp it as if it had come from a GATES document at the colliding path.
    promoted = {**data, "origin": "promoted", "hunt_ref": "H-0041#keychain",
                "description": "From the hunt's document."}
    cat.write_raw(path, promoted)

    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0

    after = _record(ws, "D-0001")
    assert after["origin"] == "promoted"          # not re-derived as `catalogued`
    assert after["hunt_ref"] == "H-0041#keychain"
    assert after["description"] == "From the hunt's document."
    assert not after.get("orphaned")              # and not orphaned either
    # The rule itself is unaccounted for now, so it is NEW — a separate record,
    # which is the same call the deferred fuzzy rename-match makes.
    assert any(rid == "D-0002" for rid, _p, _d in Catalog(ws).iter_records())


def test_sync_does_not_requeue_a_hand_tagged_rule(tmp_path, monkeypatch):
    """A nightly `adef sync` was undoing `adef detection tag-mitre`.

    `mitre` is enrichment and comes back on the graft, but `review_reasons` is
    computed by the re-derive — from a source rule that has no tags, so it came
    back `no_mitre`. Correct mapping, wrong queue, re-filled on every run. The
    same bug the GATES re-import had, from the other door.
    """
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = tmp_path / "rules"
    repo.mkdir()
    untagged = _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca").split("tags:")[0]
    (repo / "r.yml").write_text(untagged, encoding="utf-8")

    CliRunner().invoke(catalog, [str(repo)])
    assert _record(ws, "D-0001")["review_reasons"] == ["no_mitre"]  # the premise

    path, data = Catalog(ws).find_record("D-0001")
    Catalog(ws).write_raw(path, {**data, "mitre": ["T1218.011"],
                                 "needs_review": False, "review_reasons": []})

    (repo / "r.yml").write_text(untagged + "# edited\n", encoding="utf-8")
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0

    after = _record(ws, "D-0001")
    assert after["mitre"] == ["T1218.011"]
    assert after["review_reasons"] == []
    assert after["needs_review"] is False


def test_sync_does_not_corrupt_or_crash_on_a_hand_edited_scalar(tmp_path, monkeypatch):
    """The graft writes the raw on-disk value onto a typed field.

    So a hand-edit that drops the list dash — the common typo, in the one part of
    the record humans are meant to edit — reached `to_yaml_dict`, where `list()`
    split `platforms: windows` into seven platforms the INDEX then filed, and
    `dict()` on `alert: high` raised mid-apply, leaving the tree half-synced
    behind a stale INDEX.
    """
    ws = tmp_path / "ws"
    (ws / "journals").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    repo = _make_repo(tmp_path)
    CliRunner().invoke(catalog, [str(repo)])

    path, data = Catalog(ws).find_record("D-0001")
    Catalog(ws).write_raw(path, {**data, "platforms": "windows", "alert": "high",
                                 "references": "https://example.invalid/x",
                                 "mitre": "T1218.011"})

    (repo / "r.yml").write_text(_sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca") + "# edited\n",
                                encoding="utf-8")
    result = CliRunner().invoke(sync, [str(repo)])
    assert result.exit_code == 0, result.output

    after = _record(ws, "D-0001")
    assert after["platforms"] == ["windows"]
    assert after["references"] == ["https://example.invalid/x"]
    assert after["alert"] == "high"  # kept verbatim rather than guessed at or dropped
    # `mitre` is the field the graft always overwrites, and nine one-character
    # "techniques" would reach `by_technique`, coverage and the search text.
    assert after["mitre"] == ["T1218.011"]
    assert after["review_reasons"] == []


def test_sync_applies_an_edited_profile_to_unchanged_files(tmp_path, monkeypatch):
    ws, repo = _bulk_setup(tmp_path, monkeypatch, [_rec("A", "`a` = 1", "k-a")], with_uuid=True)
    prof_path = ws / "config" / "profiles" / "bulk.yml"
    prof = yaml.safe_load(prof_path.read_text())
    prof["platform"] = {"const": "linux"}  # the profile changed; export.json didn't
    prof_path.write_text(yaml.safe_dump(prof), encoding="utf-8")
    assert CliRunner().invoke(sync, [str(repo)]).exit_code == 0
    [rec] = _by_title(ws).values()
    assert rec["platform"] == "linux"


def test_workspace_flag_reaches_the_mitre_validator(tmp_path, monkeypatch):
    """`adef sync --workspace X` judges `invalid_mitre` against X's snapshot.

    `sync` has two call sites on the chain, and both were measured uncovered:
    the whole 1077-test suite stayed green with `ws` deleted from either
    `walk_outcomes(rule_root, user_profiles, ws)` or
    `refresh_mitre_review(rec, ws)`. The core functions and the `catalog`/gates
    entry points were already covered by then — which is exactly how a
    pass-through parameter rots: the ends stay connected and one link in the
    middle quietly stops carrying it.

    Either hole re-flags a correctly-mapped rule as `invalid_mitre` on every
    sync, which is worse than getting it wrong once: it undoes the triage a
    human did last time, on a schedule.

    It takes **both** of sync's actions to reach both sites, and the first
    attempt at this test only had one. On MODIFIED, `refresh_mitre_review`
    recomputes the two MITRE reasons from scratch and overwrites whatever the
    walk decided — so dropping `ws` from `walk_outcomes` stayed green there,
    masked by the very call that corrects it. On NEW there is no
    `refresh_mitre_review`: `record_from_discovered` copies
    `review_reasons=list(disc.review_reasons)` straight from the walk, which is
    the only path where the walk's snapshot reaches disk.
    """
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
    repo.mkdir()
    local = _sigma("03cc0c25-389f-4bf8-b48d-11878079f1ca").replace(
        "attack.t1218.011", "attack.t9999"
    )
    (repo / "r.yml").write_text(local, encoding="utf-8")

    assert (
        CliRunner().invoke(catalog, [str(repo), "--workspace", str(ws)]).exit_code == 0
    )
    assert _record(ws, "D-0001")["mitre"] == ["T9999"]

    # MODIFIED (the `refresh_mitre_review` arm) and NEW (the walk arm) in one
    # sync: edit the existing rule, and drop in a second one it has never seen.
    (repo / "r.yml").write_text(
        local.replace("Rundll32 no args", "Rundll32 no args v2"), encoding="utf-8"
    )
    (repo / "new.yml").write_text(
        local.replace("Rundll32 no args", "Arrived after the catalog").replace(
            "03cc0c25-389f-4bf8-b48d-11878079f1ca",
            "9f2b7a14-0000-4000-8000-00000000beef",
        ),
        encoding="utf-8",
    )
    result = CliRunner().invoke(sync, [str(repo), "--workspace", str(ws)])
    assert result.exit_code == 0, result.output

    modified = _record(ws, "D-0001")
    assert modified["title"] == "Rundll32 no args v2", modified  # the sync really ran
    assert modified["mitre"] == ["T9999"], modified
    assert "invalid_mitre" not in (modified.get("review_reasons") or []), modified

    created = _record(ws, "D-0002")
    assert created["title"] == "Arrived after the catalog", created
    assert created["mitre"] == ["T9999"], created
    assert "invalid_mitre" not in (created.get("review_reasons") or []), created
