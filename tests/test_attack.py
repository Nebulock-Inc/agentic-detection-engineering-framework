"""Tests for the ATT&CK reference layer (runtime side)."""

from __future__ import annotations

import pytest

from adef.core.attack import AttackReference, attack_reference


@pytest.fixture(scope="module")
def ref() -> AttackReference:
    return attack_reference()


def test_snapshot_loads_and_has_content(ref: AttackReference) -> None:
    assert ref.attack_version  # e.g. "19.1"
    assert len(ref.techniques) > 500
    assert ref.tactics  # shortname -> display name


def test_known_technique_lookup(ref: AttackReference) -> None:
    t = ref.technique("T1059.001")
    assert t is not None
    assert t["name"] == "PowerShell"
    assert "execution" in t["tactics"]


def test_case_insensitive(ref: AttackReference) -> None:
    assert ref.technique("t1059.001") == ref.technique("T1059.001")


def test_is_valid(ref: AttackReference) -> None:
    assert ref.is_valid("T1059")
    assert ref.is_valid("T1059.001")
    assert not ref.is_valid("T9999")
    assert not ref.is_valid("not-an-id")


def test_tactics_for_technique(ref: AttackReference) -> None:
    # Subtechnique inherits nothing extra; returns display names.
    assert ref.tactics_for("T1059.001") == ["Execution"]
    # Unknown id -> empty.
    assert ref.tactics_for("T9999") == []


def test_revoked_resolution(ref: AttackReference) -> None:
    r = ref.resolve("T1143")  # revoked -> Hidden Window -> T1564.003
    assert r.valid  # it IS a real (if revoked) id
    assert r.revoked
    assert r.superseded_by == "T1564.003"
    # A live id resolves to itself, not revoked.
    live = ref.resolve("T1059.001")
    assert live.valid and not live.revoked and live.superseded_by is None


def test_unknown_id_resolve(ref: AttackReference) -> None:
    r = ref.resolve("T9999")
    assert not r.valid and not r.revoked and r.superseded_by is None


def test_missing_snapshot_raises_clear_error(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        AttackReference.from_path(tmp_path / "nope.json")


def test_invalid_mitre_review_reason() -> None:
    """finalize_review flags a bogus ID as invalid_mitre, leaves real IDs clean."""
    from pathlib import Path

    from adef.core.rule_discovery import (
        REVIEW_INVALID_MITRE,
        REVIEW_NO_MITRE,
        DiscoveredRule,
        finalize_review,
    )

    def mk(mitre: tuple[str, ...]) -> DiscoveredRule:
        return DiscoveredRule(
            path=Path("x"), format="sigma", query_text="x", platform="windows", mitre=mitre
        )

    bad = finalize_review(mk(("T1059.001", "T9999")))
    assert REVIEW_INVALID_MITRE in bad.review_reasons

    good = finalize_review(mk(("T1059.001",)))
    assert REVIEW_INVALID_MITRE not in good.review_reasons

    # No mapping is the quiet enrichment queue, not an invalid-ID defect.
    none = finalize_review(mk(()))
    assert REVIEW_NO_MITRE in none.review_reasons
    assert REVIEW_INVALID_MITRE not in none.review_reasons
