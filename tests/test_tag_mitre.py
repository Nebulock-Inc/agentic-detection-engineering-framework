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


# --------------------------------------------------------------------------- #
# untag (--remove): the retag seam — live case D-1470's hypothesis pivot
# --------------------------------------------------------------------------- #
def test_untag_removes_and_rebuilds_index(tmp_path: Path) -> None:
    from adef.core.tag import untag_mitre
    import yaml

    _seed(tmp_path, ["T1071", "T1571"], [])
    result = untag_mitre(tmp_path, "D-0001", ["T1571"])
    assert result.removed == ["T1571"]
    data = _load(tmp_path, "D-0001")
    assert data["mitre"] == ["T1071"]
    assert not data["needs_review"]  # one mapping remains — not unmapped
    index = yaml.safe_load((tmp_path / "catalog" / "INDEX.yml").read_text())
    assert "D-0001" not in index["by_technique"].get("T1571", [])
    assert "D-0001" in index["by_technique"].get("T1071", [])


def test_untag_to_empty_rejoins_no_mitre_queue(tmp_path: Path) -> None:
    from adef.core.tag import untag_mitre

    _seed(tmp_path, ["T1071"], [])
    result = untag_mitre(tmp_path, "D-0001", ["T1071"])
    assert result.now_unmapped
    data = _load(tmp_path, "D-0001")
    assert data["mitre"] == []
    assert "no_mitre" in data["review_reasons"]
    assert data["needs_review"]


def test_untag_not_present_writes_nothing(tmp_path: Path) -> None:
    from adef.core.tag import untag_mitre

    _seed(tmp_path, ["T1071"], [])
    before = _load(tmp_path, "D-0001")["updated"]
    result = untag_mitre(tmp_path, "D-0001", ["T1046"])
    assert result.removed == []
    assert result.not_present == ["T1046"]
    assert _load(tmp_path, "D-0001")["updated"] == before  # untouched


def test_cli_tag_mitre_remove_flag(tmp_path: Path, monkeypatch) -> None:
    from click.testing import CliRunner

    from adef.commands.detection import detection as detection_cli

    _seed(tmp_path, ["T1071", "T1571"], [])
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))
    result = CliRunner().invoke(
        detection_cli,
        ["tag-mitre", "D-0001", "T1071", "T1571", "--remove", "--workspace", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert "Untagged" in result.output
    assert "no_mitre enrichment queue" in result.output


def test_cli_reindex(tmp_path: Path, monkeypatch) -> None:
    from click.testing import CliRunner

    from adef.commands.reindex import reindex as reindex_cli

    _seed(tmp_path, ["T1071"], [])
    (tmp_path / "catalog" / "INDEX.yml").unlink()  # simulate a broken/missing index
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))
    result = CliRunner().invoke(reindex_cli, ["--workspace", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "Reindexed 1 record(s)" in result.output
    assert (tmp_path / "catalog" / "INDEX.yml").exists()
