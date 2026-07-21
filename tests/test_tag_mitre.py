"""Tests for `adef detection tag-mitre` — writing MITRE enrichment to records."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.tag import InvalidTechniqueError, tag_mitre


def _seed(ws: Path, mitre: list[str], reasons: list[str]) -> str:
    cat = Catalog(ws)
    rec = CatalogRecord(
        id="D-0001",
        title="Test rule",
        rule_ref="repo/r.yml",
        original_path="/x/repo/r.yml",
        platform="windows",
        kind="atomic",
        engine="sigma",
        format="sigma",
        mitre=list(mitre),
        needs_review=bool(reasons),
        review_reasons=list(reasons),
    )
    cat.write(rec)
    cat.rebuild_index()
    return "D-0001"


def _load(ws: Path, det_id: str) -> dict:
    cat = Catalog(ws)
    for rid, _path, data in cat.iter_records():
        if rid == det_id:
            return data
    raise AssertionError(f"{det_id} not found")


def test_tag_adds_and_dedupes(tmp_path: Path) -> None:
    _seed(tmp_path, mitre=["T1059.001"], reasons=["no_mitre"])  # reasons stale on purpose
    result = tag_mitre(tmp_path, "D-0001", ["T1055", "T1059.001"])  # one new, one dup
    assert set(result.added) == {"T1055"}
    data = _load(tmp_path, "D-0001")
    assert set(data["mitre"]) == {"T1059.001", "T1055"}


def test_tag_drops_no_mitre_reason(tmp_path: Path) -> None:
    _seed(tmp_path, mitre=[], reasons=["no_mitre", "no_platform"])
    tag_mitre(tmp_path, "D-0001", ["T1055"])
    data = _load(tmp_path, "D-0001")
    assert "no_mitre" not in data["review_reasons"]
    assert "no_platform" in data["review_reasons"]  # untouched
    assert data["needs_review"] is True  # still flagged for platform


def test_tag_clears_needs_review_when_last_reason(tmp_path: Path) -> None:
    _seed(tmp_path, mitre=[], reasons=["no_mitre"])
    tag_mitre(tmp_path, "D-0001", ["T1055"])
    data = _load(tmp_path, "D-0001")
    assert data["review_reasons"] == []
    assert data["needs_review"] is False


def test_invalid_id_rejected_atomically(tmp_path: Path) -> None:
    _seed(tmp_path, mitre=[], reasons=["no_mitre"])
    with pytest.raises(InvalidTechniqueError) as exc:
        tag_mitre(tmp_path, "D-0001", ["T1055", "T9999"])
    assert "T9999" in str(exc.value)
    # nothing written — record unchanged
    data = _load(tmp_path, "D-0001")
    assert data["mitre"] == []


def test_index_rebuilt_with_tactic(tmp_path: Path) -> None:
    _seed(tmp_path, mitre=[], reasons=["no_mitre"])
    tag_mitre(tmp_path, "D-0001", ["T1547.001"])  # Persistence + Priv Esc
    idx = yaml.safe_load((tmp_path / "catalog" / "INDEX.yml").read_text())
    assert "D-0001" in idx["by_tactic"].get("Persistence", [])
    assert "D-0001" in idx["by_tactic"].get("Privilege Escalation", [])


def test_unknown_detection_raises(tmp_path: Path) -> None:
    Catalog(tmp_path)
    with pytest.raises(KeyError):
        tag_mitre(tmp_path, "D-9999", ["T1055"])
