"""Tests for the catalog artifact — ADEF's enrichment record + INDEX.

The catalog is ``<workspace>/catalog/<platform>/D-XXXX-<slug>.yml`` plus a
generated ``<workspace>/catalog/INDEX.yml``. A catalog record *references* a
rule in the user's repo (``rule_ref``); it never copies the repo or writes to it.
"""

from __future__ import annotations

import textwrap

import pytest
import yaml

from adef.core.catalog import (
    Catalog,
    CatalogError,
    CatalogRecord,
    catalog_dir,
    declared_platforms,
    record_from_discovered,
    record_path,
    refresh_mitre_review,
)
from adef.core.rule_discovery import DiscoveredRule
from pathlib import Path


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "adef-workspace"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    return ws


@pytest.fixture
def rule_repo(tmp_path):
    root = tmp_path / "their-detections" / "windows"
    root.mkdir(parents=True)
    (root / "mshta.yml").write_text(
        textwrap.dedent(
            """\
            title: Suspicious mshta.exe child process
            id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
            logsource:
                product: windows
            detection:
                condition: selection
            tags:
                - attack.t1218.005
            """
        ),
        encoding="utf-8",
    )
    return tmp_path / "their-detections"


# --------------------------------------------------------------------------- #
# record_from_discovered — mapping discovery → catalog record
# --------------------------------------------------------------------------- #
def test_record_from_discovered_maps_fields(rule_repo, workspace):
    from adef.core.rule_discovery import discover_rules

    disc = next(iter(discover_rules(rule_repo)))
    rec = record_from_discovered("D-0001", disc, workspace=workspace)

    assert rec.id == "D-0001"
    assert rec.title == "Suspicious mshta.exe child process"
    assert rec.platform == "windows"
    assert rec.engine == "sigma"
    assert rec.format == "sigma"
    assert rec.kind == "atomic"
    assert rec.mitre == ["T1218.005"]
    assert rec.status == "draft"
    assert rec.stage == "find"
    assert rec.needs_review is False
    # Sigma `id:` is persisted as the identity key for `adef sync` reconciliation.
    assert rec.rule_uuid == "03cc0c25-389f-4bf8-b48d-11878079f1ca"


def test_rule_uuid_round_trips_through_yaml(rule_repo, workspace):
    """The embedded UUID survives serialization (sync's primary identity key)."""
    from adef.core.rule_discovery import discover_rules

    disc = next(iter(discover_rules(rule_repo)))
    rec = record_from_discovered("D-0001", disc, workspace=workspace)
    assert rec.to_yaml_dict()["rule_uuid"] == "03cc0c25-389f-4bf8-b48d-11878079f1ca"
    # A format with no embedded UUID stays empty, not None.
    from adef.core.catalog import CatalogRecord

    bare = CatalogRecord(
        id="D-2", title="t", rule_ref="r", original_path="/p",
        platform="x", kind="atomic", engine="sql", format="spl",
    )
    assert bare.to_yaml_dict()["rule_uuid"] == ""


def test_source_hash_is_sha256_of_raw_bytes(rule_repo, workspace):
    """Discovery stamps a SHA-256 of the file bytes; it lands on the record."""
    import hashlib

    from adef.core.rule_discovery import discover_rules

    disc = next(iter(discover_rules(rule_repo)))
    expected = hashlib.sha256((rule_repo / "windows" / "mshta.yml").read_bytes()).hexdigest()
    assert disc.source_hash == expected
    rec = record_from_discovered("D-0001", disc, workspace=workspace, catalog_sha="cafe123")
    y = rec.to_yaml_dict()
    assert y["source_hash"] == expected
    assert y["catalog_sha"] == "cafe123"


def test_git_head_sha_empty_for_non_git_dir(tmp_path):
    from adef.core.catalog import git_head_sha

    assert git_head_sha(tmp_path) == ""  # not a git work tree → empty, never raises


def test_record_carries_data_source(rule_repo, workspace):
    from adef.core.rule_discovery import discover_rules

    disc = next(iter(discover_rules(rule_repo)))
    rec = record_from_discovered("D-0001", disc, workspace=workspace)
    # This fixture's Sigma logsource has product but no category → product used.
    assert rec.data_source == "windows"


def test_record_captures_query_from_discovered(rule_repo, workspace):
    """The extracted query text lands in the catalog record (self-contained)."""
    from adef.core.rule_discovery import discover_rules

    disc = next(iter(discover_rules(rule_repo)))
    rec = record_from_discovered("D-0001", disc, workspace=workspace)
    assert "detection:" in rec.query  # sigma fixture's query text
    assert rec.query == disc.query_text


def test_written_yaml_includes_query(workspace):
    cat = Catalog(workspace)
    rec = CatalogRecord(
        id="D-0001", title="x", rule_ref="r", original_path="/a",
        platform="windows", kind="atomic", engine="sql", format="splunk-escu",
        query="| tstats count from datamodel=Web by Web.url",
    )
    path = cat.write(rec)
    data = yaml.safe_load(path.read_text())
    assert data["query"] == "| tstats count from datamodel=Web by Web.url"


def test_record_carries_support_from_discovered(workspace):
    from adef.core.rule_discovery import DiscoveredRule, RECOGNIZED_UNSUPPORTED

    disc = DiscoveredRule(
        path=Path("/tmp/x/panther_rule.yml"),
        format="panther",
        query_text="",
        title="AWS Test",
        support=RECOGNIZED_UNSUPPORTED,
        needs_review=True,
    )
    rec = record_from_discovered("D-0009", disc, workspace=workspace)
    assert rec.support == RECOGNIZED_UNSUPPORTED


def test_written_yaml_includes_support(workspace):
    cat = Catalog(workspace)
    rec = CatalogRecord(
        id="D-0001", title="x", rule_ref="r", original_path="/a",
        platform="windows", kind="atomic", engine="sql", format="panther",
        support="recognized_unsupported",
    )
    path = cat.write(rec)
    data = yaml.safe_load(path.read_text())
    assert data["support"] == "recognized_unsupported"


def test_written_yaml_includes_data_source(workspace):
    cat = Catalog(workspace)
    rec = CatalogRecord(
        id="D-0001", title="x", rule_ref="r", original_path="/a",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        data_source="process_creation",
    )
    path = cat.write(rec)
    data = yaml.safe_load(path.read_text())
    assert data["data_source"] == "process_creation"


def test_record_rule_ref_is_relative_to_workspace(rule_repo, workspace):
    from adef.core.rule_discovery import discover_rules

    disc = next(iter(discover_rules(rule_repo)))
    rec = record_from_discovered("D-0001", disc, workspace=workspace)

    # rule_ref points at the source file; original_path is absolute provenance.
    assert rec.rule_ref.endswith("their-detections/windows/mshta.yml")
    assert Path(rec.original_path).is_absolute()


def test_record_rule_ref_is_rule_root_relative_even_for_distant_workspace(
    rule_repo, tmp_path
):
    """2026-07-21 E2E finding: with the workspace far from the rule repo,
    rule_ref degraded to ../../..-style walks. With rule_root given, the ref
    is <root-name>/<path-inside-root> regardless of workspace location."""
    from adef.core.rule_discovery import discover_rules

    far_ws = tmp_path / "deep" / "nested" / "elsewhere" / "ws"
    far_ws.mkdir(parents=True)
    disc = next(iter(discover_rules(rule_repo)))
    rec = record_from_discovered(
        "D-0001", disc, workspace=far_ws, rule_root=rule_repo
    )
    assert rec.rule_ref == "their-detections/windows/mshta.yml"
    assert ".." not in rec.rule_ref


def test_record_missing_platform_defaults_and_flags(workspace):
    disc = DiscoveredRule(
        path=Path("/tmp/x/raw.sql"),
        format="sql",
        query_text="SELECT a FROM t",
        needs_review=True,
    )
    rec = record_from_discovered("D-0007", disc, workspace=workspace)
    assert rec.platform == "multi-platform"  # escape hatch when unknown
    assert rec.needs_review is True


# --------------------------------------------------------------------------- #
# Catalog.write — the YAML on disk
# --------------------------------------------------------------------------- #
def test_write_creates_platform_scoped_yaml(workspace):
    cat = Catalog(workspace)
    rec = CatalogRecord(
        id="D-0001",
        title="Suspicious mshta.exe child process",
        rule_ref="../their/windows/mshta.yml",
        original_path="/abs/their/windows/mshta.yml",
        platform="windows",
        kind="atomic",
        engine="sigma",
        format="sigma",
        mitre=["T1218.005"],
    )
    path = cat.write(rec)

    assert path == workspace / "catalog" / "windows" / "D-0001-suspicious-mshta-exe-child-process.yml"
    assert path.exists()
    data = yaml.safe_load(path.read_text())
    assert data["id"] == "D-0001"
    assert data["rule_ref"] == "../their/windows/mshta.yml"
    assert data["engine"] == "sigma"
    assert data["format"] == "sigma"
    assert data["mitre"] == ["T1218.005"]


def test_write_never_touches_a_detections_path(workspace):
    """Catalog writes land under catalog/, never a repo detections/ tree."""
    cat = Catalog(workspace)
    rec = CatalogRecord(
        id="D-0001", title="x", rule_ref="r", original_path="/a",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
    )
    path = cat.write(rec)
    assert "detections" not in path.parts


# --------------------------------------------------------------------------- #
# INDEX.yml — generated reverse maps
# --------------------------------------------------------------------------- #
def test_index_has_reverse_maps(workspace):
    cat = Catalog(workspace)
    cat.write(CatalogRecord(
        id="D-0001", title="mshta", rule_ref="a", original_path="/a",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        mitre=["T1218.005"], status="ready",
    ))
    cat.write(CatalogRecord(
        id="D-0002", title="iam backdoor", rule_ref="b", original_path="/b",
        platform="cloud-aws", kind="atomic", engine="sql", format="sql",
        mitre=[], status="draft",
    ))
    index_path = cat.rebuild_index()

    idx = yaml.safe_load(index_path.read_text())
    assert idx["detections"]["D-0001"].endswith("D-0001-mshta.yml")
    assert set(idx["by_platform"]["windows"]) == {"D-0001"}
    assert set(idx["by_platform"]["cloud-aws"]) == {"D-0002"}
    assert set(idx["by_engine"]["sigma"]) == {"D-0001"}
    assert set(idx["by_status"]["ready"]) == {"D-0001"}
    assert set(idx["by_status"]["draft"]) == {"D-0002"}
    # Honestly named: keyed by technique; a true by_tactic map arrives with
    # the ATT&CK reference layer.
    assert "D-0001" in idx["by_technique"]["T1218.005"]


def test_index_is_generated_marker(workspace):
    cat = Catalog(workspace)
    cat.write(CatalogRecord(
        id="D-0001", title="x", rule_ref="a", original_path="/a",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
    ))
    idx = yaml.safe_load(cat.rebuild_index().read_text())
    assert idx.get("generated") is True


# --------------------------------------------------------------------------- #
# Shared ID space with journals
# --------------------------------------------------------------------------- #
def test_next_id_accounts_for_both_catalog_and_journals(workspace):
    # A journal already claims D-0001.
    (workspace / "journals" / "D-0001.md").write_text("---\nid: D-0001\n---\n")
    cat = Catalog(workspace)
    cat.write(CatalogRecord(
        id="D-0002", title="x", rule_ref="a", original_path="/a",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
    ))
    # Next ID must clear both the journal (D-0001) and the catalog (D-0002).
    assert cat.next_id() == "D-0003"


def test_catalog_dir_resolves_under_workspace(workspace):
    assert catalog_dir(workspace) == workspace / "catalog"


def _rec(id, title, rule_ref, platform="windows"):
    return CatalogRecord(
        id=id, title=title, rule_ref=rule_ref, original_path="/x",
        platform=platform, kind="atomic", engine="sigma", format="sigma",
    )


def test_write_refuses_duplicate_id_clobber(workspace):
    """Two DIFFERENT detections (different rule_ref) at the same ID → refuse."""
    cat = Catalog(workspace)
    cat.write(_rec("D-0001", "First rule", "repo/a.yml"))
    with pytest.raises(CatalogError, match="clobber"):
        cat.write(_rec("D-0001", "Different rule", "repo/b.yml"))
    # the original survives untouched
    _p, data = cat.find_record("D-0001")
    assert data["title"] == "First rule"


def test_write_allows_same_detection_reslug(workspace):
    """Same detection (same rule_ref), new title → migrate, no stale sibling."""
    cat = Catalog(workspace)
    cat.write(_rec("D-0001", "Old title", "repo/a.yml"))
    cat.write(_rec("D-0001", "New title", "repo/a.yml"))  # title/slug changed
    # exactly one file for D-0001, with the new title
    files = list((workspace / "catalog").rglob("D-0001-*.yml"))
    assert len(files) == 1
    _p, data = cat.find_record("D-0001")
    assert data["title"] == "New title"


def test_index_tolerates_scalar_and_none_mitre(workspace):
    cat = Catalog(workspace)
    for rid, mitre in (("D-0001", "T1219.002"), ("D-0002", ["T1219", None])):
        rec = _rec(rid, f"r{rid}", f"repo/{rid}.yml")
        cat.write(rec)
        path, data = cat.find_record(rid)
        data["mitre"] = mitre  # hand-edited shapes
        cat.write_raw(path, data)
    idx = yaml.safe_load(cat.rebuild_index().read_text())
    assert idx["by_technique"] == {"T1219": ["D-0002"], "T1219.002": ["D-0001"]}


def test_index_buckets_a_lowercase_technique_with_its_uppercase_siblings(workspace):
    """Only *some* producers normalize case. `rule_discovery._normalise_mitre`
    uppercases, the GATES import did not, and a hand-edited record never does —
    so `t1219.002` keyed its own `by_technique` bucket. The overlap agent reads
    its technique cluster out of that map, so the lowercase record never
    clustered with its siblings and the duplicate it was a copy of went
    unreported. `record_mitre` — the one projection every reader goes through —
    uppercases now.
    """
    cat = Catalog(workspace)
    for rid, mitre in (("D-0001", ["T1219.002"]), ("D-0002", ["t1219.002", " T1219 "])):
        rec = _rec(rid, f"r{rid}", f"repo/{rid}.yml")
        cat.write(rec)
        path, data = cat.find_record(rid)
        data["mitre"] = mitre  # hand-edited shapes
        cat.write_raw(path, data)
    idx = yaml.safe_load(cat.rebuild_index().read_text())
    assert idx["by_technique"] == {
        "T1219": ["D-0002"],
        "T1219.002": ["D-0001", "D-0002"],
    }


def test_a_scalar_platforms_does_not_become_one_platform_per_character(workspace):
    """`platforms` is hand-editable on disk, and a comprehension over the string
    `windows` iterates characters — which reached `by_platform` as seven bogus
    keys, each matching `--platform w`. Every reader goes through
    `declared_platforms`, the record-side twin of `gates._str_list`."""
    from adef.core.catalog import declared_platforms, record_platforms

    typo = {"id": "D-0001", "platform": "multi-platform", "platforms": "windows"}
    assert declared_platforms(typo) == ["windows"]
    assert record_platforms(typo) == ["multi-platform", "windows"]
    # The correct form is unchanged, and the bucket still leads.
    assert record_platforms({"platform": "multi-platform", "platforms": ["windows", "macos"]}) == [
        "multi-platform",
        "windows",
        "macos",
    ]
    assert declared_platforms({"platforms": None}) == []


def test_a_hand_edited_scalar_survives_a_write_intact(workspace):
    """`to_yaml_dict` normalized with `list()`/`dict()`, which a scalar breaks.

    The enrichment block is the part of a record humans edit, and the graft in
    `adef sync` / a GATES re-import puts the raw on-disk value back on the typed
    field — so `references: https://x` (no dash) was written back as 17
    references, and `alert: high` raised `ValueError` mid-write.
    """
    rec = CatalogRecord(
        id="D-0001", title="x", rule_ref="r", original_path="/a",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
    )
    rec.mitre = "T1218.011"              # type: ignore[assignment]
    rec.platforms = "windows"            # type: ignore[assignment]
    rec.references = "https://example.invalid/x"  # type: ignore[assignment]
    rec.alert = "high"                   # type: ignore[assignment]
    rec.entities = {"name": "endpoint.uid", "type": "endpoint"}  # type: ignore[assignment]

    data = rec.to_yaml_dict()
    # `mitre` is the one in `_ENRICHMENT_FIELDS`, so it is the field the graft
    # *always* overwrites — and the one with the most consumers downstream
    # (`by_technique`, coverage, the search text).
    assert data["mitre"] == ["T1218.011"]
    assert data["platforms"] == ["windows"]
    assert data["references"] == ["https://example.invalid/x"]
    assert data["entities"] == [{"name": "endpoint.uid", "type": "endpoint"}]
    assert data["alert"] == "high"  # not guessed at, not dropped — and not a crash
    assert yaml.safe_load(yaml.safe_dump(data))["platforms"] == ["windows"]

    # The other half of the same typo: a *mapping* where a list of strings belongs.
    # `list()` read its keys, which is right here and wrong for `entities` — hence
    # two coercions, not one.
    assert declared_platforms({"platforms": {"windows": None, "macos": None}}) == [
        "windows",
        "macos",
    ]

    # And a scalar `mitre` reaching `refresh_mitre_review` (the graft's own path) is
    # read as one technique, not nine one-character ones flagged `invalid_mitre`.
    rec.mitre = "T1218.011"  # type: ignore[assignment]
    refresh_mitre_review(rec)
    assert rec.mitre == ["T1218.011"]
    assert rec.review_reasons == []


def test_an_overlong_platform_is_refused_by_name(workspace):
    """The slug is capped, but `platform` is the other half of the same path.

    It arrives from outside ADEF too (a GATES document's `platforms`, a source
    rule's `logsource.product`), and resolving an overlong component succeeds, so
    the write raised a bare `OSError` mid-loop with part of the import already on
    disk. A named `CatalogError` instead, and both dry runs (`hunt-promote --gates`
    and, since round 6, `adef catalog`) vet their whole plan through this function
    before writing. Refused, not truncated: the directory and the record's
    `platform` have to stay the same string.
    """
    rec = CatalogRecord(
        id="D-0001", title="x", rule_ref="r", original_path="/a",
        platform="w" * 300, kind="atomic", engine="sigma", format="sigma",
    )
    with pytest.raises(CatalogError, match="too long"):
        record_path(catalog_dir(workspace), rec)

    rec.platform = "windows"
    assert record_path(catalog_dir(workspace), rec).name == "D-0001-x.yml"


def test_a_hand_edited_scalar_reads_clean_without_any_write(workspace):
    """The write-side coercion can't help a record nobody rewrites.

    `adef reindex`, `coverage`, `detection list/show` and the search corpus all read
    records straight off disk, so a hand-edited `mitre: T1218.011` (no dash) was
    iterated per character by every one of them — nine `by_technique` buckets from a
    typo, with no write anywhere in the path. Coerced in `iter_records`, the one
    boundary they share.
    """
    rec = CatalogRecord(
        id="D-0001", title="x", rule_ref="r", original_path="/a",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
    )
    cat = Catalog(workspace)
    path = cat.write(rec)
    # Hand-edit the file the way a human does: no dashes.
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    path.write_text(
        yaml.safe_dump({**data, "mitre": "T1218.011",
                        "platforms": {"windows": None, "macos": None}}),
        encoding="utf-8",
    )

    _p, read_back = Catalog(workspace).find_record("D-0001")
    assert read_back["mitre"] == ["T1218.011"]
    assert sorted(read_back["platforms"]) == ["macos", "windows"]

    index = yaml.safe_load(Catalog(workspace).rebuild_index().read_text(encoding="utf-8"))
    assert list(index["by_technique"]) == ["T1218.011"]
    assert sorted(index["by_platform"]) == ["macos", "windows"]


def test_a_hand_edited_numeric_id_is_still_a_string_id(workspace):
    """The ID is hand-editable too, and it is a *dict key* and a sort key.

    `id: 1470` with the `D-` prefix dropped reads back as an int: `INDEX.yml`
    gained an int key under `detections`, and any code that sorts or joins
    record IDs next to IDs taken from journal *filenames* — always strings —
    raised `TypeError: '<' not supported between 'str' and 'int'`. That killed
    `adef doctor` outright, on the exact kind of broken workspace it exists to
    report. Coerced at the same read boundary as the four list fields.
    """
    from adef.core.doctor import run_checks

    cat = Catalog(workspace)
    for n, journal in ((1, True), (2, False)):
        path = cat.write(CatalogRecord(
            id=f"D-000{n}", title=f"r{n}", rule_ref=f"r{n}", original_path="/a",
            platform="windows", kind="atomic", engine="sigma", format="sigma",
        ))
        if journal:
            # One record keeps its journal, so `D-0002` is left unpaired and the
            # mixed-type set actually reaches the sort and the join.
            (workspace / "journals" / f"D-000{n}.md").write_text("x", encoding="utf-8")
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            cat.write_raw(path, {**data, "id": 1470})

    ids = [det_id for det_id, _p, _d in Catalog(workspace).iter_records()]
    assert ids == ["1470", "D-0002"]

    index = yaml.safe_load(Catalog(workspace).rebuild_index().read_text(encoding="utf-8"))
    assert all(isinstance(key, str) for key in index["detections"])

    journals = next(c for c in run_checks(workspace) if c.name == "journals")
    # Both records are unpaired now — `1470` no longer matches its own journal.
    assert "1470" in journals.detail and "D-0002" in journals.detail


def test_a_scalar_review_reason_is_not_read_as_clean_coverage(workspace):
    """`review_reasons` is a list of strings too — and it decides what's trusted.

    `coverage` tests each reason for membership in its integrity set, so a
    hand-edited `review_reasons: invalid_mitre` (no dash) matched on no character
    and the record came back *undoubted*: two such records reported the technique
    as **solid** coverage, the one word on the record saying otherwise. Hence all
    four list-of-string fields are coerced at the read boundary, not just `mitre`.
    """
    from adef.core.coverage import Tier, build_coverage

    cat = Catalog(workspace)
    for n in (1, 2):
        path = cat.write(CatalogRecord(
            id=f"D-000{n}", title=f"r{n}", rule_ref=f"r{n}", original_path="/a",
            platform="windows", kind="atomic", engine="sigma", format="sigma",
            mitre=["T1059.001"], data_source="edr",
        ))
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        cat.write_raw(path, {**data, "review_reasons": "invalid_mitre"})

    records = [data for _id, _p, data in Catalog(workspace).iter_records()]
    assert [r["review_reasons"] for r in records] == [["invalid_mitre"]] * 2
    cov = build_coverage(records)
    assert cov.techniques["T1059.001"].tier is Tier.FRAGILE
