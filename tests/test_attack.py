"""Tests for the ATT&CK reference layer (runtime side)."""

from __future__ import annotations

import pytest

from adef.core.attack import AttackReference, attack_reference


@pytest.fixture(scope="module")
def ref() -> AttackReference:
    return attack_reference()


# --------------------------------------------------------------------------- #
# The autouse cache clear in `conftest.py` — verified, not asserted
#
# `attack_reference`'s *zero-arg* key is shared by every caller that passes no
# workspace — `adef attack info` and `adef attack show`, the two subcommands
# with no `--workspace` flag to pass (`coverage.py` and `rule_discovery.py`
# were on this list until they were threaded; `lru_cache` keys `f(None)` as
# `(None,)`, a different entry from `f()`'s `()`, so a defaulted forward does
# not touch it either). A test that sets `$ADEF_WORKSPACE` and resolves zero-arg
# writes into it — and with the caller list down to two, the test below is now
# the main such writer, which is the whole reason this block exists.
# The fixture clears that key
# when each test ends, and these two tests — in this order, which is
# load-bearing — are what make the clear falsifiable: the first poisons the
# shared key, and `test_snapshot_loads_and_has_content` below is the first
# consumer of the module-scoped `ref` fixture, which pytest sets up *before*
# any function-scoped fixture of its own. So it reads the poison and fails with
# `assert 0 > 500` (five more `ref` consumers follow it down) unless the clear
# ran at the end of the test above.
#
# Written because the fixture was otherwise unfalsifiable: the whole suite
# stayed green with it deleted, since every other test that plants a snapshot
# keys on its own `tmp_path` and so never contends the shared key. A
# hermeticity guard nothing can fail is indistinguishable from one that does
# nothing.
# --------------------------------------------------------------------------- #
def test_a_poisoned_zero_arg_cache_does_not_outlive_this_test(tmp_path, monkeypatch) -> None:
    import json

    (tmp_path / "attack").mkdir()
    (tmp_path / "attack" / "enterprise.json").write_text(
        json.dumps({"attack_version": "99.9-poison", "tactics": {}, "techniques": {}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path))
    assert attack_reference().attack_version == "99.9-poison"


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
    # `is not None` first: the equality alone passes when *both* lookups miss.
    # That is *an* outcome of broken folding, not the only one — deleting
    # `.upper()` outright leaves the upper-case lookup hitting, which the bare
    # equality already caught. Folding the wrong *direction* (`.lower()`) is
    # what makes both miss, and so is an empty snapshot, which is how this was
    # found.
    lower = ref.technique("t1059.001")
    assert lower is not None
    assert lower == ref.technique("T1059.001")


def test_is_valid(ref: AttackReference) -> None:
    assert ref.is_valid("T1059")
    assert ref.is_valid("T1059.001")
    assert not ref.is_valid("T9999")
    assert not ref.is_valid("not-an-id")


def test_tactics_for_technique(ref: AttackReference) -> None:
    # What this actually tests is the shortname→display-name mapping
    # (`execution` → `Execution`). It said "subtechnique inherits nothing
    # extra" as well, which no fixture over this snapshot can falsify: zero
    # sub-techniques in it differ from their parent's tactic set, so the
    # assertion reads the same whether inheritance exists or not.
    assert ref.tactics_for("T1059.001") == ["Execution"]
    # Unknown id -> empty.
    assert ref.tactics_for("T9999") == []


def test_revoked_resolution(ref: AttackReference) -> None:
    r = ref.resolve("T1143")  # revoked -> Hidden Window -> T1564.003
    assert r.valid  # it IS a real (if revoked) id
    assert r.revoked
    assert r.superseded_by == "T1564.003"
    # Lower-case too. `resolve` carried its own copy of the case fold and its
    # own dict lookup, and every test that touched it passed an already-upper
    # ID — so deleting that `.upper()` left all 1073 tests green. It routes
    # through `technique` now, and this is the line that goes red if it stops.
    assert ref.resolve("t1143").superseded_by == "T1564.003"
    # A live id resolves to itself, not revoked.
    live = ref.resolve("T1059.001")
    assert live.valid and not live.revoked and live.superseded_by is None


def test_unknown_id_resolve(ref: AttackReference) -> None:
    r = ref.resolve("T9999")
    assert not r.valid and not r.revoked and r.superseded_by is None


def test_missing_snapshot_raises_clear_error(tmp_path) -> None:
    # `match` is the whole test. `Path.read_text` raises `FileNotFoundError` by
    # itself, so `pytest.raises(FileNotFoundError)` alone passed identically
    # with `from_path`'s guard deleted — it asserted CPython's behaviour, not
    # ADEF's. The message is the thing the name promises and the only part a
    # bare OSError can't supply.
    with pytest.raises(FileNotFoundError, match="ATT&CK snapshot not found"):
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
