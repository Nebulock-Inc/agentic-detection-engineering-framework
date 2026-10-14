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
# untag (--remove): the retag seam — a hypothesis pivot
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


def _plant_snapshot(ws: Path) -> None:
    """A snapshot carrying one technique the shipped reference does not have."""
    import json

    (ws / "attack").mkdir(parents=True, exist_ok=True)
    (ws / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-test",
                "tactics": {"zzz-tactic": "Zzz Tactic"},
                "techniques": {"T9999": {"name": "Planted", "tactics": ["zzz-tactic"]}},
            }
        ),
        encoding="utf-8",
    )


def test_tag_validates_against_the_workspace_snapshot(tmp_path: Path) -> None:
    """`adef attack refresh --workspace X` then `tag-mitre --workspace X` must agree.

    `tag_mitre` *refuses and writes nothing* on an unknown ID, so reading the
    wrong reference is not a mislabel — it is a hard rejection of correct
    input. `test_tag_rejects_invalid` is the other half of the pair: the same
    `T9999` with no workspace snapshot raises, so this is not degenerate.
    """
    _plant_snapshot(tmp_path)
    _seed(tmp_path, mitre=[], reasons=["no_mitre"])

    result = tag_mitre(tmp_path, "D-0001", ["T9999"])

    assert result.added == ["T9999"]
    assert _load(tmp_path, "D-0001")["mitre"] == ["T9999"]


def test_untag_writes_nothing_when_the_index_rebuild_cannot_run(tmp_path: Path) -> None:
    """A corrupt snapshot must not leave the record and the INDEX disagreeing.

    `untag_mitre` validates nothing (you can always remove an ID), so its only
    reference read was `rebuild_index()` on the last line — *after* `write_raw`.
    With a truncated `attack/enterprise.json` the record was written with the
    technique removed and then `JSONDecodeError` escaped, leaving `INDEX.yml`
    still mapping that technique to this detection. `adef coverage` and
    `adef detection list --tactic` read the stored INDEX, so they went on
    claiming coverage the record no longer has — silently, and until someone
    happened to run `adef reindex`.
    """
    import json

    from adef.core.attack import attack_reference
    from adef.core.tag import untag_mitre

    _seed(tmp_path, ["T1071", "T1571"], [])
    before = _load(tmp_path, "D-0001")

    (tmp_path / "attack").mkdir(parents=True, exist_ok=True)
    (tmp_path / "attack" / "enterprise.json").write_text(
        '{"attack_version": "17.1", "techni', encoding="utf-8"
    )
    # `_seed`'s own `rebuild_index()` already warmed the per-path cache entry
    # for this workspace, so without this the planted file is never read and
    # the test passes against the unfixed code. A real `adef` invocation is a
    # fresh process and has no warm entry.
    attack_reference.cache_clear()

    with pytest.raises(json.JSONDecodeError):
        untag_mitre(tmp_path, "D-0001", ["T1571"])

    assert _load(tmp_path, "D-0001") == before  # not half-applied
    index = yaml.safe_load((tmp_path / "catalog" / "INDEX.yml").read_text())
    assert index["by_technique"]["T1571"] == ["D-0001"]  # still agrees with it


def _break_a_second_record(ws: Path) -> None:
    """A record `build_index` cannot index, with no ATT&CK involvement at all.

    `build_index` groups by `engine` as well as resolving `by_tactic`, so a
    hand-edited list value is an unhashable mapping key. This is the second
    reachable cause of the same half-applied write, and the one the first
    version of untag's pre-flight — `attack_reference(workspace)` — did not
    cover: the snapshot here is perfectly fine.
    """
    cat = Catalog(ws)
    cat.write(
        CatalogRecord(
            id="D-0002",
            title="Other rule",
            rule_ref="repo/r2.yml",
            original_path="/x/repo/r2.yml",
            platform="windows",
            kind="atomic",
            engine="sigma",
            format="sigma",
            mitre=["T1059.001"],
        )
    )
    path = next(p for p in (ws / "catalog").rglob("D-0002*.yml"))
    data = yaml.safe_load(path.read_text())
    data["engine"] = ["sigma"]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_untag_writes_nothing_when_an_unrelated_record_breaks_the_rebuild(tmp_path: Path) -> None:
    """The non-ATT&CK half of the same defect — and of a different record.

    `untag_mitre` pre-flights the index build, not just the ATT&CK reference,
    because the reference is only one of the things `rebuild_index` needs. Here
    the snapshot is untouched and D-0002's `engine` is a list, so the rebuild
    raises `TypeError` — and the removal still has to not land, because the
    consequence is identical: `INDEX.yml` keeps a mapping D-0001 has
    disclaimed, and `adef coverage` reads the stored INDEX.
    """
    _seed(tmp_path, ["T1071", "T1571"], [])
    _break_a_second_record(tmp_path)
    before = _load(tmp_path, "D-0001")
    index_before = (tmp_path / "catalog" / "INDEX.yml").read_text()

    from adef.core.tag import untag_mitre

    with pytest.raises(TypeError):
        untag_mitre(tmp_path, "D-0001", ["T1571"])

    assert _load(tmp_path, "D-0001") == before
    assert (tmp_path / "catalog" / "INDEX.yml").read_text() == index_before


def test_cli_reindex_reports_an_unbuildable_index_without_a_traceback(
    tmp_path: Path, monkeypatch
) -> None:
    """`adef doctor` stopped prescribing `adef reindex` for this state; the
    command still has to fail readably when a user reaches it anyway.

    Loud, not swallowed — swallowing would write an INDEX with every tactic
    silently dropped, which is why the guard in `adef doctor` lives at its own
    caller rather than inside `build_index`. But a `TypeError` traceback tells
    the user nothing actionable, and the exception text names the cause.
    """
    from click.testing import CliRunner

    from adef.commands.reindex import reindex as reindex_cli

    _seed(tmp_path, ["T1071"], [])
    index_before = (tmp_path / "catalog" / "INDEX.yml").read_text()
    _break_a_second_record(tmp_path)
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))

    result = CliRunner().invoke(reindex_cli, ["--workspace", str(tmp_path)])

    assert result.exit_code == 1, result.output
    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert "Reindex failed" in result.output, result.output
    assert "unhashable" in result.output, result.output  # the cause, not just "failed"
    # And *which* record. "unhashable type: 'list'" is accurate and unusable in
    # a 400-record catalog; `build_index` names the file it tripped over.
    assert "D-0002" in result.output, result.output
    assert (tmp_path / "catalog" / "INDEX.yml").read_text() == index_before


@pytest.mark.parametrize("extra", [["--remove"], []])
def test_cli_tag_mitre_reports_an_unbuildable_index_without_a_traceback(
    tmp_path: Path, monkeypatch, extra: list[str]
) -> None:
    """Both branches of `tag-mitre` end in an index build, so both can fail.

    `untag_mitre` gained a `build_index()` pre-flight, and `tag_mitre` has
    always ended in `rebuild_index()` — but the command caught only `KeyError`
    and `InvalidTechniqueError`, so an unindexable *second* record surfaced as a
    raw `TypeError` traceback with nothing saying whether the write had landed.
    Parametrized because the two branches have separate handlers: fixing one and
    not the other is exactly the shape this is here to catch.

    `T1571` for both: it is already mapped, so `--remove` has something to
    remove (untag returns early when nothing matches, before its pre-flight),
    and the add branch rebuilds the index even when the ID was already present.
    """
    from click.testing import CliRunner

    from adef.commands.detection import detection as detection_cli

    _seed(tmp_path, ["T1071", "T1571"], [])
    _break_a_second_record(tmp_path)
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))

    result = CliRunner().invoke(
        detection_cli,
        ["tag-mitre", "D-0001", "T1571", "--workspace", str(tmp_path), *extra],
    )

    assert result.exit_code != 0, result.output
    assert not isinstance(result.exception, TypeError), result.exception
    assert "unhashable" in result.output, result.output
    assert "D-0002" in result.output, result.output
    assert "adef doctor" in result.output, result.output


def test_the_index_resolves_tactics_from_the_workspace_snapshot(tmp_path: Path) -> None:
    """`by_tactic` is persisted, so a wrong reference here outlives the command.

    `adef coverage` and `adef detection list --tactic` read the stored
    `INDEX.yml`, never the reference directly — so `adef reindex --workspace X`
    resolving against the *shipped* snapshot writes tactic assignments from a
    different ATT&CK release than the records it indexed, and every later read
    inherits them.
    """
    _plant_snapshot(tmp_path)
    _seed(tmp_path, mitre=["T9999"], reasons=[])

    index = Catalog(tmp_path).build_index()

    assert index["by_technique"]["T9999"] == ["D-0001"]
    assert index["by_tactic"]["Zzz Tactic"] == ["D-0001"]
