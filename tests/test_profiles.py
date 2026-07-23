"""Tests for declarative extraction profiles (adef/core/profiles.py) and their
integration into rule discovery (ISA 2026-07-20)."""

from __future__ import annotations

import textwrap

import pytest

from adef.core.profiles import (
    ProfileError,
    extract_path,
    lint_profile_dict,
    load_profile,
    load_user_profiles,
    parse_container,
    profile_from_dict,
)
from adef.core.rule_discovery import (
    NOT_A_RULE,
    SUPPORTED,
    UNCLAIMED,
    discover_rules,
    walk_outcomes,
)

# --------------------------------------------------------------------------- #
# Fixtures — an in-house wrapper format no built-in recognizer knows
# --------------------------------------------------------------------------- #
ACME_PROFILE = {
    "name": "acme-siem-export",
    "version": 1,
    "signature": {
        "container": "yaml",
        "all_keys": ["alert"],
        "none_keys": ["pack_id"],
        "extension": [".yml", ".yaml"],
    },
    "query_language": "spl",
    "map": {
        "title": "alert.name",
        "query": "alert.query",
        "mitre": "alert.tags[]",
        "uuid": "alert.id",
        "data_source": "alert.index",
    },
    "platform": {"const": "windows"},
}

ACME_RULE = textwrap.dedent(
    """\
    alert:
      id: 9b2c1a7e-0001-4a4a-8888-123456789abc
      name: Acme suspicious child process
      query: index=wineventlog EventCode=4688 | stats count by parent
      index: wineventlog
      tags: [T1059.001, persistence]
    """
)

ACME_PACK = "pack_id: acme-pack\nalert:\n  name: not a rule\n  query: x\n"


@pytest.fixture
def acme_repo(tmp_path):
    root = tmp_path / "acme-rules"
    root.mkdir()
    (root / "proc.yml").write_text(ACME_RULE, encoding="utf-8")
    (root / "pack.yml").write_text(ACME_PACK, encoding="utf-8")
    # A Sigma rule to prove built-ins still work alongside profiles.
    (root / "sigma.yml").write_text(
        "title: Sigma one\nlogsource:\n  product: windows\n"
        "detection:\n  condition: selection\ntags: [attack.t1218]\n",
        encoding="utf-8",
    )
    return root


def _profile():
    return profile_from_dict(dict(ACME_PROFILE))


# --------------------------------------------------------------------------- #
# Lint
# --------------------------------------------------------------------------- #
def test_lint_accepts_valid_profile():
    assert lint_profile_dict(dict(ACME_PROFILE)) == []


def test_lint_toml_profile_errors_without_tomllib(monkeypatch):
    """A TOML-container profile lints as an ERROR when the interpreter can't
    parse TOML (Python 3.10) — else it lints OK then silently claims nothing
    (ISA 2026-07-22 guardrail audit)."""
    import adef.core.profiles as profiles_mod

    monkeypatch.setattr(profiles_mod, "_toml_available", lambda: False)
    prof = dict(ACME_PROFILE)
    prof["signature"] = {**prof["signature"], "container": "toml"}
    errors = lint_profile_dict(prof)
    assert any("Python 3.11+" in e for e in errors)

    # With TOML available, the same profile lints clean.
    monkeypatch.setattr(profiles_mod, "_toml_available", lambda: True)
    assert not any("Python 3.11+" in e for e in lint_profile_dict(prof))


@pytest.mark.parametrize(
    ("mutate", "expected_fragment"),
    [
        (lambda d: d.pop("name"), "name"),
        (lambda d: d.update(version=2), "version"),
        (lambda d: d["map"].pop("query"), "map.query"),
        (lambda d: d["signature"].update(container="conf"), "not implemented"),
        (lambda d: d["signature"].update(container="pdf"), "container"),
        (lambda d: d.update(query_language="powershell"), "query_language"),
        (lambda d: d["map"].update(title="$..name"), "dot-path"),
        (lambda d: d["signature"].update(all_keys=[], any_keys=[]), "at least one"),
        (lambda d: d.update(extra_key=1), "unknown top-level"),
    ],
)
def test_lint_rejects_bad_profiles(mutate, expected_fragment):
    data = {
        **ACME_PROFILE,
        "signature": dict(ACME_PROFILE["signature"]),
        "map": dict(ACME_PROFILE["map"]),
    }
    mutate(data)
    errors = lint_profile_dict(data)
    assert errors, "expected lint errors"
    assert any(expected_fragment in e for e in errors)


def test_load_profile_raises_with_filename(tmp_path):
    p = tmp_path / "bad.yml"
    p.write_text("name: BAD NAME\nversion: 1\n", encoding="utf-8")
    with pytest.raises(ProfileError) as exc:
        load_profile(p)
    assert "bad.yml" in str(exc.value)


def test_load_user_profiles_is_defensive(tmp_path):
    ws = tmp_path / "ws"
    pdir = ws / "config" / "profiles"
    pdir.mkdir(parents=True)
    import yaml as _yaml

    (pdir / "good.yml").write_text(_yaml.safe_dump(ACME_PROFILE), encoding="utf-8")
    (pdir / "broken.yml").write_text("version: 99\n", encoding="utf-8")
    profiles, errors = load_user_profiles(ws)
    assert [p.name for p in profiles] == ["acme-siem-export"]
    assert len(errors) == 1 and "broken.yml" in errors[0]


# --------------------------------------------------------------------------- #
# Dot-path extraction
# --------------------------------------------------------------------------- #
def test_extract_path_walks_mappings():
    assert extract_path({"a": {"b": {"c": 7}}}, "a.b.c") == 7


def test_extract_path_iterates_arrays():
    doc = {"rules": [{"q": "one"}, {"q": "two"}, {"other": 3}]}
    assert extract_path(doc, "rules[].q") == ["one", "two"]


def test_extract_path_missing_returns_none_or_empty():
    assert extract_path({"a": 1}, "b.c") is None
    assert extract_path({"a": 1}, "b[]") == []


def test_parse_container_returns_document_list():
    assert parse_container("yaml", "a: 1\n") == [{"a": 1}]
    assert parse_container("json", '{"a": 1}') == [{"a": 1}]
    assert parse_container("yaml", "- just\n- a list\n") == []
    assert parse_container("conf", "[stanza]\nsearch = x") == []  # later phase


def test_parse_container_toml():
    import sys

    import pytest

    if sys.version_info < (3, 11):
        pytest.skip("tomllib requires Python 3.11+")
    # Elastic-shaped TOML: nested tables become nested dicts.
    doc = parse_container("toml", '[rule]\nname = "X"\nquery = "process where true"\n')
    assert doc == [{"rule": {"name": "X", "query": "process where true"}}]
    # Invalid TOML → [] (profile simply doesn't claim the file).
    assert parse_container("toml", "this is = not [valid toml") == []


# --------------------------------------------------------------------------- #
# Discovery integration
# --------------------------------------------------------------------------- #
def test_profile_claims_and_extracts(acme_repo):
    rules = list(discover_rules(acme_repo, [_profile()]))
    acme = [r for r in rules if r.format == "acme-siem-export"]
    assert len(acme) == 1
    rule = acme[0]
    assert rule.title == "Acme suspicious child process"
    assert rule.query_text.startswith("index=wineventlog")
    assert rule.mitre == ("T1059.001",)
    assert rule.rule_uuid == "9b2c1a7e-0001-4a4a-8888-123456789abc"
    assert rule.data_source == "wineventlog"
    assert rule.platform == "windows"
    assert rule.support == SUPPORTED
    assert rule.needs_review is False
    assert rule.query_language == "spl"  # from profile hint
    assert rule.engine == "sql"  # folds into the internal taxonomy


def test_none_keys_excludes_near_misses(acme_repo):
    rules = list(discover_rules(acme_repo, [_profile()]))
    titles = [r.title for r in rules]
    assert "not a rule" not in titles  # the pack was excluded


def test_builtins_still_work_alongside_profiles(acme_repo):
    rules = list(discover_rules(acme_repo, [_profile()]))
    assert any(r.format == "sigma" for r in rules)


def test_profiles_checked_before_builtins(tmp_path):
    # A file that satisfies BOTH sigma and a user profile → the profile wins.
    root = tmp_path / "repo"
    root.mkdir()
    (root / "both.yml").write_text(
        "title: overridden\nlogsource:\n  product: windows\n"
        "detection:\n  condition: sel\nalert:\n  name: profile title\n  query: q\n",
        encoding="utf-8",
    )
    rules = list(discover_rules(root, [_profile()]))
    assert len(rules) == 1
    assert rules[0].format == "acme-siem-export"
    assert rules[0].title == "profile title"


def test_discover_rules_backcompat_without_profiles(acme_repo):
    # No profiles: acme files are invisible, sigma still found.
    rules = list(discover_rules(acme_repo))
    assert [r.format for r in rules] == ["sigma"]


def test_walk_outcomes_reports_unclaimed_with_keys(acme_repo):
    outcomes = {o.path.name: o for o in walk_outcomes(acme_repo)}
    assert outcomes["proc.yml"].outcome == UNCLAIMED
    assert outcomes["proc.yml"].top_level_keys == ("alert",)
    assert outcomes["sigma.yml"].outcome == SUPPORTED


def test_walk_outcomes_not_a_rule_for_unstructured(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("# hello\n", encoding="utf-8")
    outcomes = list(walk_outcomes(root))
    assert len(outcomes) == 1
    assert outcomes[0].outcome == NOT_A_RULE


def test_profile_data_source_falls_back_to_query_literal(tmp_path):
    """A profile with no data_source mapping still yields the raw source
    literal from the query (2026-07-21 E2E finding: Panther scheduled
    queries carried their table in SQL FROM but records were empty)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "sched.yml").write_text(
        "alert:\n  name: Sched\n  query: SELECT 1 FROM panther_logs.public.auth0_events\n",
        encoding="utf-8",
    )
    prof_dict = {
        **ACME_PROFILE,
        "query_language": "sql",
        "map": {"title": "alert.name", "query": "alert.query"},  # no data_source
    }
    rules = list(discover_rules(root, [profile_from_dict(prof_dict)]))
    assert rules[0].data_source == "panther_logs.public.auth0_events"


def test_profile_mapped_data_source_wins_over_fallback(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "r.yml").write_text(
        "alert:\n  name: R\n  query: SELECT 1 FROM other_table\n  index: declared_source\n",
        encoding="utf-8",
    )
    prof_dict = {**ACME_PROFILE, "query_language": "sql"}  # maps data_source: alert.index
    rules = list(discover_rules(root, [profile_from_dict(prof_dict)]))
    assert rules[0].data_source == "declared_source"


def test_sql_data_source_ignores_comments(tmp_path):
    """Prose in SQL comments ("adapted from a SnowAlert query") must not
    masquerade as the FROM table (2026-07-21 E2E finding)."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "r.yml").write_text(
        "alert:\n  name: R\n  query: |\n"
        "    -- this was adapted from a SnowAlert query\n"
        "    /* also copied from elsewhere */\n"
        "    SELECT 1 FROM snowflake.account_usage.login_history\n",
        encoding="utf-8",
    )
    prof_dict = {
        **ACME_PROFILE,
        "query_language": "sql",
        "map": {"title": "alert.name", "query": "alert.query"},
    }
    rules = list(discover_rules(root, [profile_from_dict(prof_dict)]))
    assert rules[0].data_source == "snowflake.account_usage.login_history"
