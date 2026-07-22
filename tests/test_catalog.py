"""Tests for the catalog artifact — ADEF's enrichment record + INDEX.

The catalog is ``<workspace>/catalog/<platform>/D-XXXX-<slug>.yml`` plus a
generated ``<workspace>/catalog/INDEX.yml``. A catalog record *references* a
rule in the user's repo (``rule_ref``); it never copies the repo or writes to
it. See ISA.md 2026-07-15 catalog decision.
"""

from __future__ import annotations

import textwrap

import pytest
import yaml

from adef.core.catalog import (
    Catalog,
    CatalogRecord,
    catalog_dir,
    record_from_discovered,
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
