"""Splunk ESCU platform inference from `data_source`.

ESCU's `data_source` list names each rule's telemetry in Splunk's public
data-source vocabulary, which is platform-specific for most sources. Map it
so ESCU rules stop uniformly landing in `multi-platform` with `no_platform`.
"""

from __future__ import annotations

import textwrap

import pytest

from adef.core.rule_discovery import _escu_platform, discover_rules


@pytest.mark.parametrize(
    "sources, expected",
    [
        (
            ["Sysmon EventID 1", "Windows Event Log Security 4688", "CrowdStrike ProcessRollup2"],
            "windows",
        ),
        (["Sysmon for Linux EventID 1"], "linux"),
        (["Linux Auditd Syscall"], "linux"),
        (["Powershell Script Block Logging 4104"], "windows"),
        (["AWS CloudTrail DeleteKnowledgeBase"], "cloud-aws"),
        (["ASL AWS CloudTrail"], "cloud-aws"),
        (["Azure Active Directory Add member to role"], "cloud-azure"),
        (["O365 Update application."], "cloud-azure"),
        (["CrowdStrike ProcessRollup2"], None),  # no opinion
        (["GitHub Enterprise Audit Logs"], None),
        (["Sysmon EventID 1", "Sysmon for Linux EventID 1"], None),  # disagreement
        ([], None),
    ],
)
def test_escu_platform_from_data_sources(sources, expected):
    assert _escu_platform(sources) == expected


def test_escu_discovery_infers_windows_platform_and_drops_no_platform(tmp_path):
    (tmp_path / "detect.yml").write_text(
        textwrap.dedent(
            """\
            name: Suspicious tstats
            id: aaaa
            type: TTP
            search: '| tstats count from datamodel=Endpoint'
            mitre_attack_id: [T1059]
            data_source: [Sysmon EventID 1, CrowdStrike ProcessRollup2]
            """
        ),
        encoding="utf-8",
    )
    [rule] = list(discover_rules(tmp_path))
    assert rule.platform == "windows"
    assert "no_platform" not in rule.review_reasons


def test_escu_discovery_keeps_no_platform_when_data_source_has_no_opinion(tmp_path):
    (tmp_path / "detect.yml").write_text(
        textwrap.dedent(
            """\
            name: Suspicious tstats
            id: bbbb
            type: TTP
            search: '| tstats count from datamodel=Endpoint'
            mitre_attack_id: [T1059]
            data_source: [GitHub Enterprise Audit Logs]
            """
        ),
        encoding="utf-8",
    )
    [rule] = list(discover_rules(tmp_path))
    assert rule.platform is None
    assert "no_platform" in rule.review_reasons


def test_escu_discovery_reads_mitre_nested_under_tags(tmp_path):
    (tmp_path / "detect.yml").write_text(
        textwrap.dedent(
            """\
            name: Remote access tool
            id: bbbb
            type: TTP
            search: '| tstats count from datamodel=Endpoint'
            data_source: [Sysmon EventID 1]
            tags:
              analytic_story: [Remote Access]
              mitre_attack_id: [T1219]
            """
        ),
        encoding="utf-8",
    )
    [rule] = list(discover_rules(tmp_path))
    assert rule.format == "splunk-escu"
    assert rule.mitre == ("T1219",)
    assert "no_mitre" not in rule.review_reasons
