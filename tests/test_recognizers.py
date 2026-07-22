"""Phase 1: content-signature recognizers + three-outcome support model.

`recognize(filename, text)` returns a `Recognition(format, support)` where
support is one of SUPPORTED / RECOGNIZED_UNSUPPORTED / NOT_A_RULE. Detection is
general-shape-first (has a query/logic field + detection metadata); vendor
signatures are hints for where to read, not a closed list. Extension is a hint,
never the decision.
"""

from __future__ import annotations

import textwrap

from adef.core.rule_discovery import (
    NOT_A_RULE,
    RECOGNIZED_UNSUPPORTED,
    SUPPORTED,
    recognize,
    sniff_format,
)


# --------------------------------------------------------------------------- #
# Sigma — supported
# --------------------------------------------------------------------------- #
def test_sigma_recognized_supported():
    text = "title: x\nlogsource:\n  product: windows\ndetection:\n  condition: selection\n"
    r = recognize("rule.yml", text)
    assert r.format == "sigma"
    assert r.support == SUPPORTED


# --------------------------------------------------------------------------- #
# Splunk ESCU — detection is supported, story/pack are NOT a rule
# --------------------------------------------------------------------------- #
SPLUNK_DETECTION = textwrap.dedent(
    """\
    name: Cisco IOS XE Implant Access
    id: 07c36cda-6567-43c3-bc1a-89dff61e2cd9
    type: TTP
    search: '| tstats count from datamodel=Web where Web.url="*/logoutconfirm*"'
    mitre_attack_id:
        - T1190
    data_source:
        - Web
    """
)

SPLUNK_STORY = textwrap.dedent(
    """\
    name: Linux Post Exploitation
    id: 11111111-2222-3333-4444-555555555555
    description: A collection of analytics.
    narrative: Long prose about the story.
    references:
        - https://example.com
    """
)


def test_splunk_detection_recognized_supported():
    r = recognize("cisco.yml", SPLUNK_DETECTION)
    assert r.format == "splunk-escu"
    assert r.support == SUPPORTED


def test_splunk_story_is_not_a_rule():
    """A story has no query/logic → not a rule, regardless of vendor keys."""
    r = recognize("linux_post_exploitation.yml", SPLUNK_STORY)
    assert r.support == NOT_A_RULE


def test_escu_captures_rule_uuid():
    """ESCU rules carry a stable `id:` — the sync identity key must persist it."""
    from adef.core.rule_discovery import _extract_splunk_escu

    rule = _extract_splunk_escu(SPLUNK_DETECTION)
    assert rule.rule_uuid == "07c36cda-6567-43c3-bc1a-89dff61e2cd9"


# --------------------------------------------------------------------------- #
# Panther — recognized, but query lives in sibling .py → recognized_unsupported
# --------------------------------------------------------------------------- #
PANTHER_RULE = textwrap.dedent(
    """\
    AnalysisType: rule
    RuleID: "AWS.Console.Sign-In"
    DisplayName: AWS Console Sign-In
    Filename: aws_console_signin.py
    LogTypes:
        - AWS.CloudTrail
    Severity: High
    Reports:
        MITRE ATT&CK:
            - TA0001:T1078
    """
)

PANTHER_PACK = textwrap.dedent(
    """\
    AnalysisType: pack
    PackID: PantherManaged.AWS
    DisplayName: AWS Pack
    PackDefinition:
        IDs:
            - AWS.Console.Sign-In
    """
)


def test_panther_rule_recognized_unsupported():
    r = recognize("aws_console_signin.yml", PANTHER_RULE)
    assert r.format == "panther"
    assert r.support == RECOGNIZED_UNSUPPORTED


def test_panther_captures_rule_uuid():
    """Panther's `RuleID` is its stable identity key — persist it for sync."""
    from adef.core.rule_discovery import _extract_panther

    rule = _extract_panther(PANTHER_RULE)
    assert rule.rule_uuid == "AWS.Console.Sign-In"


def test_panther_pack_is_not_a_rule():
    r = recognize("aws_pack.yml", PANTHER_PACK)
    assert r.support == NOT_A_RULE


# --------------------------------------------------------------------------- #
# Non-rules
# --------------------------------------------------------------------------- #
def test_readme_is_not_a_rule():
    r = recognize("README.md", "# our detections")
    assert r.support == NOT_A_RULE


def test_plain_yaml_config_is_not_a_rule():
    r = recognize("ci.yml", "on: push\njobs:\n  build:\n    runs-on: ubuntu\n")
    assert r.support == NOT_A_RULE


def test_raw_sql_supported():
    r = recognize("q.sql", "SELECT a FROM t WHERE b = 1")
    assert r.format == "sql"
    assert r.support == SUPPORTED


# --------------------------------------------------------------------------- #
# Backwards-compat: sniff_format still returns the format string (or None)
# --------------------------------------------------------------------------- #
def test_sniff_format_compat_sigma():
    text = "title: x\nlogsource:\n  product: windows\ndetection:\n  condition: selection\n"
    assert sniff_format("rule.yml", text) == "sigma"


def test_sniff_format_compat_not_a_rule_is_none():
    assert sniff_format("README.md", "# hi") is None


def test_sniff_format_compat_splunk():
    assert sniff_format("d.yml", SPLUNK_DETECTION) == "splunk-escu"
