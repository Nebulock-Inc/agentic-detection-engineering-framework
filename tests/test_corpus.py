from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.corpus import build_corpus
from adef.core.journal import Journal


def _rec(rid: str, title: str, query: str = "process.name = 'x'") -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=["T1218.005"],
    )


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    w = tmp_path / "ws"
    (w / "catalog").mkdir(parents=True)
    (w / "journals").mkdir(parents=True)
    cat, journal = Catalog(w), Journal(w / "journals")

    # D-0001: both artifacts
    r1 = _rec("D-0001", "mshta child process")
    cat.write_raw(w / "catalog" / "D-0001.yml", r1.to_yaml_dict())
    journal.create(detection_id="D-0001", title=r1.title)

    # D-0002: record only (journal deleted) — invisible to Similarity today
    r2 = _rec("D-0002", "mshta spawning child")
    cat.write_raw(w / "catalog" / "D-0002.yml", r2.to_yaml_dict())

    # D-0003: journal only (a `detection new` draft)
    journal.create(detection_id="D-0003", title="draft rundll32 idea")

    cat.rebuild_index()
    return w


def test_membership_is_the_union_of_records_and_journals(ws: Path):
    ids = sorted(e.detection_id for e in build_corpus(ws))
    assert ids == ["D-0001", "D-0002", "D-0003"]


def test_each_detection_appears_exactly_once(ws: Path):
    ids = [e.detection_id for e in build_corpus(ws)]
    assert len(ids) == len(set(ids))


def test_record_only_entry_reports_the_record_path_not_a_fake_journal(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0002")
    assert entry.journal is None
    # Deviation from the brief (controller ruling): catalog_dir() resolves the
    # workspace (.expanduser().resolve()); on macOS tmp_path lives under a
    # symlink (/tmp -> /private/tmp), so the unresolved `ws / ...` expectation
    # the brief wrote would not compare equal to entry.path. Resolve both
    # sides.
    assert entry.path.resolve() == (ws / "catalog" / "D-0002.yml").resolve()
    assert entry.path.exists()


def test_record_only_entry_reports_the_records_stage(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0002")
    assert entry.current_stage == "find"   # CatalogRecord.stage default


def test_journal_only_entry_has_no_record(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0003")
    assert entry.record is None
    assert entry.title == "draft rundll32 idea"
    # Deviation from the brief (controller ruling): same resolve-both-sides
    # fix as above — Journal() resolves its directory too.
    assert entry.path.resolve() == (ws / "journals" / "D-0003.md").resolve()


def test_index_text_includes_the_record_query(ws: Path):
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0001")
    assert "process.name" in entry.index_text


def test_index_text_survives_either_half_missing(ws: Path):
    by_id = {e.detection_id: e for e in build_corpus(ws)}
    assert "mshta spawning child" in by_id["D-0002"].index_text   # record only
    assert isinstance(by_id["D-0003"].index_text, str)            # journal only


def test_record_backed_title_is_not_double_counted(ws: Path):
    # Minor finding: `index_text` used to prepend `self.title` unconditionally,
    # and `record_search_text` already starts with the record's title, so a
    # record-backed entry indexed its title twice — double-weighting it in
    # BM25 relative to every other field.
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0001")
    assert entry.index_text.count("mshta child process") == 1


def test_journal_only_entry_still_carries_its_title(ws: Path):
    # The unconditional prepend was there for exactly this case (r1 review,
    # Critical) — a journal-only entry has no `record_search_text` to fall
    # back on, so it must still get its title from somewhere.
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0003")
    assert "draft rundll32 idea" in entry.index_text


def test_bare_workspace_returns_nothing_and_creates_nothing(tmp_path: Path):
    # Review Focus 1. `Catalog.__init__` mkdirs, so a naive implementation
    # silently creates `catalog/` on a read path.
    bare = tmp_path / "bare"
    bare.mkdir()
    assert build_corpus(bare) == []
    assert not (bare / "catalog").exists()
    assert not (bare / "journals").exists()


def test_unparseable_artifacts_are_skipped_not_fatal(ws: Path):
    # Review Focus 2. `D-0010` has NO frontmatter at all, which parses fine
    # (`_split_frontmatter` just returns `{}, text`) — it never exercises a
    # parse failure. `D-0011` is the real case: frontmatter that IS present
    # but is malformed YAML, which used to propagate a `yaml.YAMLError` out
    # of `Journal.iter_entries()` and abort `build_corpus` entirely.
    (ws / "catalog" / "D-0009.yml").write_text("{{{ not yaml", encoding="utf-8")
    (ws / "journals" / "D-0010.md").write_text("no frontmatter here", encoding="utf-8")
    (ws / "journals" / "D-0011.md").write_text(
        "---\n{{{ not: [valid\n---\n\nbroken frontmatter body\n", encoding="utf-8"
    )
    ids = sorted(e.detection_id for e in build_corpus(ws))
    assert "D-0001" in ids and "D-0002" in ids and "D-0003" in ids
    assert "D-0011" not in ids
    # D-0010 has no frontmatter at all, so
    # `JournalEntry.detection_id` used to fall back to `path.stem` and the
    # file entered the corpus as "D-0010" — a malformed file, not a
    # detection. This assertion is the whole point of the test; without it,
    # the fixture above never actually exercised the code this test claims to
    # cover (it only checked the good ids were present).
    assert "D-0010" not in ids


def test_malformed_journal_warns_once_per_process(tmp_path: Path, capsys):
    # `build_corpus` runs on every search and every
    # refine, so a process that lives a long time (the MCP server) used to
    # re-emit the same "skipping ... malformed frontmatter" warning forever.
    # Two consecutive `build_corpus` calls over the same bad file must
    # produce exactly one warning.
    w = tmp_path / "ws"
    (w / "journals").mkdir(parents=True)
    (w / "journals" / "D-0099.md").write_text(
        "---\n{{{ not: [valid\n---\n\nbroken frontmatter body\n", encoding="utf-8"
    )

    build_corpus(w)
    build_corpus(w)

    err = capsys.readouterr().err
    assert err.count("malformed frontmatter") == 1


def test_non_mapping_frontmatter_is_skipped_not_fatal(ws: Path, capsys):
    # Final pre-PR follow-up item 1, variant 1: frontmatter that parses as a
    # YAML list, not a mapping (`yaml.safe_load` happily returns a list — no
    # `yaml.YAMLError`). `iter_entries`'s old guard caught only `YAMLError`,
    # so `entry.detection_id` (`self.frontmatter.get(...)`), evaluated inside
    # `iter_entries` itself via `journals.setdefault(entry.detection_id, ...)`,
    # raised `AttributeError: 'list' object has no attribute 'get'` straight
    # out of `build_corpus` and aborted the whole scan.
    (ws / "journals" / "D-0012.md").write_text(
        "---\n- a\n- b\n---\n\nnot a mapping\n", encoding="utf-8"
    )
    ids = sorted(e.detection_id for e in build_corpus(ws))
    assert "D-0001" in ids and "D-0002" in ids and "D-0003" in ids
    assert "D-0012" not in ids
    assert capsys.readouterr().err.count("malformed frontmatter") == 1


def test_non_utf8_journal_is_skipped_not_fatal(ws: Path, capsys):
    # Final pre-PR follow-up item 1, variant 2: a journal file that is not
    # valid UTF-8. The old guard wrapped only `_split_frontmatter`, but
    # `child.read_text(encoding="utf-8")` sat *outside* the `try`, so a
    # bad-encoding file raised `UnicodeDecodeError` straight out of
    # `iter_entries` and aborted the whole corpus build.
    (ws / "journals" / "D-0013.md").write_bytes(
        b"---\ntitle: bad\n---\n\n\xff\xfe not utf-8\n"
    )
    ids = sorted(e.detection_id for e in build_corpus(ws))
    assert "D-0001" in ids and "D-0002" in ids and "D-0003" in ids
    assert "D-0013" not in ids
    assert capsys.readouterr().err.count("malformed frontmatter") == 1


def test_same_id_in_two_platform_dirs_yields_one_entry(ws: Path):
    # Review Focus 3.
    dup_dir = ws / "catalog" / "linux"
    dup_dir.mkdir()
    cat = Catalog(ws)
    cat.write_raw(dup_dir / "D-0001.yml", _rec("D-0001", "duplicate elsewhere").to_yaml_dict())
    entries = [e for e in build_corpus(ws) if e.detection_id == "D-0001"]
    assert len(entries) == 1


def test_duplicate_id_resolves_first_wins_by_sorted_path(ws: Path):
    # Pins the determinism this module's own comment claims ("First one
    # wins, and iter_records sorts by path...") and that nothing before this
    # test actually checked: the review's mutation of `setdefault` to plain
    # assignment survived the whole suite because `len(entries) == 1` above
    # doesn't say WHICH record survives. `ws/catalog/D-0001.yml` sorts before
    # `ws/catalog/linux/D-0001.yml`, so the original ("mshta child process")
    # must win, not the later-encountered duplicate.
    dup_dir = ws / "catalog" / "linux"
    dup_dir.mkdir()
    cat = Catalog(ws)
    cat.write_raw(dup_dir / "D-0001.yml", _rec("D-0001", "duplicate elsewhere").to_yaml_dict())
    entry = next(e for e in build_corpus(ws) if e.detection_id == "D-0001")
    assert entry.record["title"] == "mshta child process"
