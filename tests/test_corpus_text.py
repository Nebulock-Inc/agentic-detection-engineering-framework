from adef.core.corpus_text import record_query_logic, record_search_text


def test_joins_title_mitre_platform_source_format_query():
    text = record_search_text({
        "title": "Suspicious mshta child",
        "mitre": ["T1218.005", "T1059.005"],
        "platform": "windows",
        "data_source": "wineventlog",
        "format": "sigma",
        "query": "process.name:mshta.exe",
    })
    assert "Suspicious mshta child" in text
    assert "T1218.005" in text
    assert "windows" in text
    assert "wineventlog" in text
    assert "process.name:mshta.exe" in text


def test_skips_empty_fields():
    text = record_search_text({"title": "Only a title"})
    assert text == "Only a title"


def test_empty_record_returns_empty_string():
    assert record_search_text({}) == ""


SIGMA = """title: Bypass UAC via Fodhelper.exe
id: 7f741dcf-fc22-4759-87b4-9ae8376676a2
status: test
description: Identifies use of Fodhelper.exe to bypass User Account Control.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md
author: E.M. Anhaus
date: 2019-10-24
tags:
    - attack.t1548.002
    - attack.g0016
    - cve.2021-44228
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\fodhelper.exe'
    condition: selection
falsepositives:
    - Legitimate use of fodhelper.exe utility by legitimate user
level: high
"""


def _sigma_record(query=SIGMA):
    return {"title": "Bypass UAC via Fodhelper.exe", "format": "sigma", "query": query,
            "mitre": ["T1548.002"], "platform": "windows", "data_source": "process_creation"}


def test_sigma_logic_is_logsource_and_detection_only():
    logic = record_query_logic(_sigma_record())
    assert "fodhelper.exe" in logic and "process_creation" in logic and "condition" in logic
    for boilerplate in ("atomic-red-team", "Anhaus", "falsepositives", "Legitimate use",
                        "level", "status", "2019-10-24"):
        assert boilerplate not in logic, boilerplate


def test_search_text_carries_sigma_logic_not_boilerplate():
    text = record_search_text(_sigma_record())
    assert "Bypass UAC via Fodhelper.exe" in text  # title still searchable
    assert "fodhelper.exe" in text
    assert "atomic-red-team" not in text and "Anhaus" not in text


def test_non_sigma_and_unparseable_queries_pass_through_unchanged():
    spl = {"format": "splunk-escu", "query": "| tstats count where Processes.parent_process_name=fodhelper.exe"}
    assert record_query_logic(spl) == spl["query"]
    broken = _sigma_record(query="title: x\ndetection: [unclosed")
    assert record_query_logic(broken) == broken["query"]
    no_detection = _sigma_record(query="title: x\nlevel: high\n")
    assert record_query_logic(no_detection) == no_detection["query"]


def test_the_stored_query_is_not_modified():
    rec = _sigma_record()
    record_query_logic(rec)
    record_search_text(rec)
    assert rec["query"] == SIGMA


# I-2 (final whole-branch review): Cyrillic С (U+0441, a Latin-c homoglyph)
# plus an RTLO override (U+202E) -- the kind of non-ASCII a real detection
# value carries when the thing being detected is itself an evasion trick.
_NON_ASCII_VALUE = "сmd.exe‮"
_SIGMA_NON_ASCII = (
    "title: x\n"
    "logsource:\n"
    "  product: windows\n"
    "detection:\n"
    f"  selection:\n    Image|endswith: '{_NON_ASCII_VALUE}'\n"
    "  condition: selection\n"
)


def test_non_ascii_detection_values_survive_as_literal_characters():
    # `yaml.safe_dump` without `allow_unicode=True` escapes any non-ASCII
    # codepoint to a `\uXXXX` sequence -- unreadable, and it silently defeats
    # substring/BM25 matching on the real value.
    rec = _sigma_record(query=_SIGMA_NON_ASCII)
    logic = record_query_logic(rec)
    assert _NON_ASCII_VALUE in logic
    assert "\\u" not in logic
    text = record_search_text(rec)
    assert _NON_ASCII_VALUE in text
    assert "\\u" not in text


def test_search_text_carries_sigma_description_and_tags():
    # Search regression: a description word or a CVE / threat-group tag must
    # still find a Sigma rule; references and author must not.
    text = record_search_text(_sigma_record())
    assert "Account" in text  # description only: "...bypass User Account Control."
    assert "cve.2021-44228" in text and "attack.g0016" in text
    assert "atomic-red-team" not in text and "Anhaus" not in text


def test_query_logic_still_excludes_description_and_tags():
    logic = record_query_logic(_sigma_record())
    assert "Account" not in logic and "attack.g0016" not in logic


def test_query_logic_emits_no_generated_yaml_anchors():
    query = (
        "title: x\nlogsource:\n    category: process_creation\n"
        "detection:\n    sel1: &s\n        Image|endswith: '\\\\mshta.exe'\n"
        "    sel2: *s\n    condition: sel1 or sel2\n"
    )
    logic = record_query_logic(_sigma_record(query=query))
    assert "&id" not in logic and "*id" not in logic, logic
    assert logic.count("mshta.exe") == 2, logic


def test_query_logic_does_not_fold_long_values():
    value = "powershell.exe" + "\\t" + "-EncodedCommand " * 8  # >80 chars, has a tab
    query = (
        "title: x\nlogsource:\n    category: process_creation\n"
        f'detection:\n    selection:\n        CommandLine|contains: "{value}"\n'
        "    condition: selection\n"
    )
    logic = record_query_logic(_sigma_record(query=query))
    assert "\\\n" not in logic, logic


def test_search_text_joins_a_scalar_mitre_whole():
    text = record_search_text({"title": "t", "mitre": "T1219.002", "format": "sql", "query": "x"})
    assert "T1219.002" in text
    assert "T 1 2" not in text
    record_search_text({"title": "t", "mitre": ["T1219", None], "format": "sql", "query": "x"})
