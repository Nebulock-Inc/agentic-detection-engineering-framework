"""Phase 1: discover_rules carries `support` and never silently drops rules.

Recognized-but-unsupported formats (e.g. Panther) are yielded with
support=recognized_unsupported rather than skipped. Only NOT_A_RULE files are
skipped. Includes corpus smoke tests against the cloned test-rules/ repos when
present.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from adef.core.rule_discovery import (
    RECOGNIZED_UNSUPPORTED,
    SUPPORTED,
    discover_rules,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_RULES = REPO_ROOT / "test-rules"


@pytest.fixture
def mixed_repo(tmp_path):
    root = tmp_path / "repo"
    (root / "win").mkdir(parents=True)
    (root / "splunk").mkdir(parents=True)
    (root / "panther").mkdir(parents=True)

    (root / "win" / "sigma.yml").write_text(
        "title: t\nlogsource:\n  product: windows\ndetection:\n  condition: selection\ntags: [attack.t1059]\n",
        encoding="utf-8",
    )
    (root / "splunk" / "detect.yml").write_text(
        textwrap.dedent(
            """\
            name: Suspicious tstats
            id: aaaa
            type: TTP
            search: '| tstats count from datamodel=Endpoint'
            mitre_attack_id: [T1059]
            data_source: [Endpoint]
            """
        ),
        encoding="utf-8",
    )
    (root / "panther" / "rule.yml").write_text(
        textwrap.dedent(
            """\
            AnalysisType: rule
            RuleID: AWS.Test
            DisplayName: AWS Test
            Filename: aws_test.py
            LogTypes: [AWS.CloudTrail]
            Reports:
                MITRE ATT&CK: [TA0001:T1078]
            """
        ),
        encoding="utf-8",
    )
    # Non-rules that must be skipped.
    (root / "README.md").write_text("# docs", encoding="utf-8")
    (root / "panther" / "pack.yml").write_text(
        "AnalysisType: pack\nPackID: X\nDisplayName: X\n", encoding="utf-8"
    )
    return root


def test_all_rule_shaped_files_discovered(mixed_repo):
    rules = {r.format: r for r in discover_rules(mixed_repo)}
    assert set(rules) == {"sigma", "splunk-escu", "panther"}


def test_support_outcomes_carried(mixed_repo):
    rules = {r.format: r for r in discover_rules(mixed_repo)}
    assert rules["sigma"].support == SUPPORTED
    assert rules["splunk-escu"].support == SUPPORTED
    assert rules["panther"].support == RECOGNIZED_UNSUPPORTED


def test_non_rules_skipped(mixed_repo):
    names = [r.path.name for r in discover_rules(mixed_repo)]
    assert "README.md" not in names
    assert "pack.yml" not in names


def test_splunk_metadata_extracted(mixed_repo):
    rules = {r.format: r for r in discover_rules(mixed_repo)}
    splunk = rules["splunk-escu"]
    assert splunk.title == "Suspicious tstats"
    assert "T1059" in splunk.mitre
    assert splunk.data_source == "Endpoint"
    assert "tstats" in splunk.query_text


def test_panther_metadata_extracted_query_deferred(mixed_repo):
    rules = {r.format: r for r in discover_rules(mixed_repo)}
    p = rules["panther"]
    assert p.title == "AWS Test"
    assert "T1078" in p.mitre
    # Logic is in a sibling .py — not captured in v1.
    assert p.query_text == ""


# --------------------------------------------------------------------------- #
# Corpus smoke — only when the cloned repos are present locally
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(
    not (TEST_RULES / "security_content" / "detections").is_dir(),
    reason="splunk security_content not cloned",
)
def test_corpus_splunk_detections_found():
    det = TEST_RULES / "security_content" / "detections" / "endpoint"
    rules = list(discover_rules(det))
    # Endpoint alone has hundreds of detections; assert we find a lot, all splunk.
    assert len(rules) > 100
    assert all(r.format == "splunk-escu" for r in rules)


@pytest.mark.skipif(
    not (TEST_RULES / "panther-analysis" / "rules").is_dir(),
    reason="panther-analysis not cloned",
)
def test_corpus_panther_rules_found():
    rules = list(discover_rules(TEST_RULES / "panther-analysis" / "rules"))
    assert len(rules) > 100
    assert all(r.format == "panther" for r in rules)
    assert all(r.support == RECOGNIZED_UNSUPPORTED for r in rules)
