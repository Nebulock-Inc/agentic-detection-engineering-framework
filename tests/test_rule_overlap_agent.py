# tests/test_rule_overlap_agent.py
from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord
from adef.core.rule_parser import spl_filter_text
from adef.agents.rule_overlap import RuleOverlapAgent, classify_pair


def _rec(rid: str, title: str, query: str, mitre: list[str], data_source: str = "wineventlog") -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"rules/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=mitre, data_source=data_source,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat = Catalog(ws)
    records = [
        _rec("D-0001", "mshta child - v1", "process.name = 'mshta.exe' and parent = 'winword.exe'",
             ["T1218.005"]),
        _rec("D-0002", "mshta child - near dup", "process.name='mshta.exe' AND parent='winword.exe'",
             ["T1218.005"]),
        _rec("D-0003", "mshta child - narrower", "process.name = 'mshta.exe' and parent = 'winword.exe' and user = 'admin'",
             ["T1218.005"]),
        _rec("D-0004", "mshta via network beacon", "network.dest_port = 4444 and process.name = 'mshta.exe'",
             ["T1218.005"]),
        _rec("D-0005", "AWS console login", "event.name = 'ConsoleLogin'", ["T1078.004"],
             data_source="cloudtrail"),
    ]
    for rec in records:
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    cat.rebuild_index()
    return ws


def test_classify_pair_exact_duplicate():
    a = _rec("A", "t", "process.name='mshta.exe'", []).to_yaml_dict()
    b = _rec("B", "t", "PROCESS.NAME = 'mshta.exe'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "duplicate"
    assert overlap.confidence == 1.0


def test_classify_pair_redundant_substring():
    a = _rec("A", "t", "process.name='mshta.exe' and parent='winword.exe'", []).to_yaml_dict()
    b = _rec("B", "t", "process.name='mshta.exe' and parent='winword.exe' and user='admin'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"


def test_classify_pair_redundant_substring_reversed():
    # record_a's query is the longer/superset text, record_b's is the substring —
    # exercises the `norm_b in norm_a` branch (mirror of the substring test above,
    # which exercises `norm_a in norm_b`). Per classify_pair's own semantics, the
    # superset-query rule (A here) is the narrower one, since it fires on a subset
    # of what the shorter query (B) already covers.
    a = _rec("A", "t", "process.name='mshta.exe' and parent='winword.exe' and user='admin'", []).to_yaml_dict()
    b = _rec("B", "t", "process.name='mshta.exe' and parent='winword.exe'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"
    assert overlap.reasoning == (
        "A's query is a strict superset of B's predicate — "
        "A fires on a subset of what B already covers"
    )


def test_classify_pair_redundant_substring_parenthesized():
    # A bare WHERE-only predicate is commonly stored wrapped in outer parens — the paren-stripping fix in classify_pair must still
    # recognize the substring relation once both sides are unwrapped.
    a = _rec("A", "t", "(process.name='mshta.exe' and parent='winword.exe')", []).to_yaml_dict()
    b = _rec("B", "t", "(process.name='mshta.exe' and parent='winword.exe' and user='admin')", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"
    assert overlap.reasoning == (
        "B's query is a strict superset of A's predicate — "
        "B fires on a subset of what A already covers"
    )


def test_classify_pair_redundant_substring_parenthesized_reversed():
    # Mirror of the above: record_a's wrapped query is the superset, record_b's
    # wrapped query is the substring — exercises the `norm_b_stripped in
    # norm_a_stripped` branch with parenthesized bare-predicate queries.
    a = _rec("A", "t", "(process.name='mshta.exe' and parent='winword.exe' and user='admin')", []).to_yaml_dict()
    b = _rec("B", "t", "(process.name='mshta.exe' and parent='winword.exe')", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "redundant"
    assert overlap.reasoning == (
        "A's query is a strict superset of B's predicate — "
        "A fires on a subset of what B already covers"
    )


def test_classify_pair_rejects_adjacent_numeric_literal_false_positive():
    # CodeRabbit: "event.code=1" is a raw Python substring of
    # "event.code=10", but the two are unrelated comparisons, not a superset
    # relation. Must classify as complementary (or duplicate/near-duplicate on
    # ratio), never "redundant" via the substring path.
    a = _rec("A", "t", "event.code=1", []).to_yaml_dict()
    b = _rec("B", "t", "event.code=10", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type != "redundant"


def test_classify_pair_complementary_different_logic():
    a = _rec("A", "t", "process.name='mshta.exe' and parent='winword.exe'", []).to_yaml_dict()
    b = _rec("B", "t", "network.dest_port=4444 and process.name='mshta.exe'", []).to_yaml_dict()
    overlap = classify_pair(a, b, "A", "B")
    assert overlap.overlap_type == "complementary"


def test_agent_scopes_to_same_technique_cluster(workspace: Path):
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=workspace)
    other_ids = {o["other_id"] for o in result["overlaps"]}
    assert "D-0005" not in other_ids  # different technique — never compared
    assert {"D-0002", "D-0003", "D-0004"} <= other_ids


def test_agent_reports_near_duplicate_and_redundant(workspace: Path):
    result = RuleOverlapAgent().run(detection_id="D-0001", workspace=workspace)
    by_id = {o["other_id"]: o for o in result["overlaps"]}
    assert by_id["D-0002"]["overlap_type"] == "duplicate"
    assert by_id["D-0003"]["overlap_type"] == "redundant"
    assert by_id["D-0004"]["overlap_type"] == "complementary"


# --- Wrapper dispatch (native by default; ADEF_WRAPPER_RULE_OVERLAP overrides) ---

def test_wrapper_runs_native_agent_when_binding_unset(workspace: Path, monkeypatch):
    monkeypatch.delenv("ADEF_WRAPPER_RULE_OVERLAP", raising=False)
    from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper

    result = RuleOverlapWrapper().run(detection_id="D-0001", workspace=workspace)
    assert result["detection_id"] == "D-0001"
    assert "overlaps" in result["result"]


def test_wrapper_raises_when_binding_set_but_unimportable(workspace: Path, monkeypatch):
    monkeypatch.setenv("ADEF_WRAPPER_RULE_OVERLAP", "not_a_real_module:NotARealClass")
    from adef.agents.wrappers import WrapperUnavailable
    from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper

    with pytest.raises(WrapperUnavailable):
        RuleOverlapWrapper().run(detection_id="D-0001", workspace=workspace)


def test_wrapper_propagates_no_catalog_record(workspace: Path, monkeypatch):
    """A journal-only detection is NOT "wrapper unavailable" — the wrapper must
    let the distinct type through so refine_chain can say what's actually true."""
    monkeypatch.delenv("ADEF_WRAPPER_RULE_OVERLAP", raising=False)
    from adef.agents.wrappers.rule_overlap import RuleOverlapWrapper
    from adef.core.catalog import NoCatalogRecordError

    with pytest.raises(NoCatalogRecordError, match="D-9999"):
        RuleOverlapWrapper().run(detection_id="D-9999", workspace=workspace)


_SIGMA_TEMPLATE = """title: {title}
status: test
description: {desc}
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{t}/{t}.md
author: {author}
date: 2022-01-01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\\\fodhelper.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
"""


def test_identical_sigma_logic_with_different_metadata_is_a_duplicate():
    # Two write-ups of the same rule: whole-file comparison scored 0.66
    # (complementary) because titles, descriptions, authors and references
    # differ; the detection logic is byte-identical.
    a = _rec("A", "a", _SIGMA_TEMPLATE.format(
        title="Fodhelper UAC bypass", t="T1548.002", author="Alice Example",
        desc="Identifies use of Fodhelper.exe to bypass UAC via registry."), ["T1548.002"]).to_yaml_dict()
    b = _rec("B", "b", _SIGMA_TEMPLATE.format(
        title="Suspicious fodhelper child", t="T1548", author="Bob Other, oscd.community",
        desc="A different write-up of the same thing, longer and worded otherwise."), ["T1548.002"]).to_yaml_dict()
    result = classify_pair(a, b, "A", "B")
    assert result.overlap_type == "duplicate", result


def _cluster_ws(tmp_path, recs):
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat = Catalog(ws)
    for rec in recs:
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
    cat.rebuild_index()
    return ws


def test_a_sub_technique_and_its_parent_share_a_cluster(tmp_path):
    ws = _cluster_ws(tmp_path, [
        _rec("D-0001", "anydesk artefact", "file.name = 'anydesk.exe'", ["T1219.002"]),
        _rec("D-0002", "remote access software", "process.name = 'anydesk.exe'", ["T1219"]),
        _rec("D-0003", "unrelated", "event.name = 'ConsoleLogin'", ["T1078.004"]),
    ])
    out = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert [o["other_id"] for o in out["overlaps"]] == ["D-0002"]
    back = RuleOverlapAgent().run(detection_id="D-0002", workspace=ws)
    assert [o["other_id"] for o in back["overlaps"]] == ["D-0001"]


def test_sibling_sub_techniques_do_not_cluster(tmp_path):
    # A T1219.001 target is compared with its parent (D-0003) and with a
    # sibling that also carries the parent tag (D-0004) — never with a
    # sibling on the sub-technique alone (D-0002).
    ws = _cluster_ws(tmp_path, [
        _rec("D-0001", "a", "x = 1", ["T1219.001"]),
        _rec("D-0002", "b", "y = 2", ["T1219.002"]),
        _rec("D-0003", "c", "z = 3", ["T1219"]),
        _rec("D-0004", "d", "w = 4", ["T1219.003", "T1219"]),
    ])
    out = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert sorted(o["other_id"] for o in out["overlaps"]) == ["D-0003", "D-0004"]


def _sigma(selection: str, category: str = "process_creation", condition: str = "selection") -> str:
    return (
        "title: t\nlogsource:\n    category: " + category + "\n    product: windows\n"
        "detection:\n" + selection + "    condition: " + condition + "\n"
    )


def _sigma_pair(query_a: str, query_b: str):
    a = _rec("A", "a", query_a, ["T1218"]).to_yaml_dict()
    b = _rec("B", "b", query_b, ["T1218"]).to_yaml_dict()
    return classify_pair(a, b, "A", "B")


_MSHTA = "    selection:\n        Image|endswith: '\\\\mshta.exe'\n"
_REGSVR = "    selection:\n        Image|endswith: '\\\\regsvr32.exe'\n"


def test_distinct_single_selection_sigma_rules_are_not_duplicates():
    # Dumped-YAML SequenceMatcher scored this pair 0.956 "duplicate" — the
    # shared structure, not the logic. Token Jaccard is {condition} / 3.
    result = _sigma_pair(_sigma(_MSHTA), _sigma(_REGSVR))
    assert result.overlap_type != "duplicate", result
    assert result.confidence < 0.85, result


def test_sigma_token_superset_is_never_redundant():
    # An extra list value ORs (broader); an extra field ANDs (narrower). The
    # token sets can't tell which, so neither may claim containment.
    extra_value = "    selection:\n        Image|endswith:\n            - '\\\\mshta.exe'\n            - '\\\\wscript.exe'\n"
    extra_field = _MSHTA + "        CommandLine|contains: 'http'\n"
    for wider in (extra_value, extra_field):
        result = _sigma_pair(_sigma(_MSHTA), _sigma(wider))
        assert result.overlap_type != "redundant", result


def test_sigma_selection_filter_binding_is_kept():
    # Same values, swapped between the selection and the negated filter:
    # opposite rules, identical tokens once selection names are dropped.
    x = ("    selection:\n        Image|endswith: a.exe\n"
         "    filter:\n        Image|endswith: b.exe\n")
    y = ("    selection:\n        Image|endswith: b.exe\n"
         "    filter:\n        Image|endswith: a.exe\n")
    cond = "selection and not filter"
    result = _sigma_pair(_sigma(x, condition=cond), _sigma(y, condition=cond))
    assert result.overlap_type != "duplicate", result
    assert result.confidence < 0.85, result


def test_sigma_regex_case_is_significant():
    a = "    selection:\n        CommandLine|re: '\\W+enc'\n"
    b = "    selection:\n        CommandLine|re: '\\w+enc'\n"
    result = _sigma_pair(_sigma(a), _sigma(b))
    assert result.overlap_type != "duplicate", result
    assert result.confidence < 0.85, result


def test_same_sigma_detection_on_a_different_logsource_is_not_a_duplicate():
    result = _sigma_pair(_sigma(_MSHTA), _sigma(_MSHTA, category="image_load"))
    assert result.overlap_type != "duplicate", result


def test_sigma_selection_names_are_arbitrary():
    renamed = _MSHTA.replace("selection:", "sel_mshta:")
    result = _sigma_pair(_sigma(_MSHTA), _sigma(renamed, condition="sel_mshta"))
    assert result.overlap_type == "duplicate", result
    assert result.confidence == 1.0, result


def test_scalar_mitre_target_clusters_with_its_parent(tmp_path):
    # A hand-edited `mitre: T1219.002` was iterated character by character.
    ws = _cluster_ws(tmp_path, [
        _rec("D-0001", "anydesk artefact", "file.name = 'anydesk.exe'", ["T1219.002"]),
        _rec("D-0002", "remote access software", "process.name = 'anydesk.exe'", ["T1219"]),
    ])
    path = ws / "catalog" / "D-0001.yml"
    path.write_text(path.read_text(encoding="utf-8").replace(
        "mitre:\n- T1219.002\n", "mitre: T1219.002\n"), encoding="utf-8")
    assert "mitre: T1219.002\n" in path.read_text(encoding="utf-8")
    Catalog(ws).rebuild_index()
    out = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert [o["other_id"] for o in out["overlaps"]] == ["D-0002"]


def test_non_string_mitre_entries_do_not_raise(tmp_path):
    ws = _cluster_ws(tmp_path, [
        _rec("D-0001", "a", "x = 1", ["T1219"]),
        _rec("D-0002", "b", "y = 2", ["T1219"]),
    ])
    path = ws / "catalog" / "D-0001.yml"
    path.write_text(path.read_text(encoding="utf-8").replace(
        "mitre:\n- T1219\n", "mitre:\n- T1219\n- null\n- 1059\n"), encoding="utf-8")
    assert "- null\n" in path.read_text(encoding="utf-8")
    # rebuild_index does not accept these shapes; hand-write the INDEX with
    # the non-string keys a hand-edited index would carry.
    (ws / "catalog" / "INDEX.yml").write_text(
        "by_technique:\n  T1219: [D-0001, D-0002]\n  null: [D-0001]\n  1059: [D-0001]\n",
        encoding="utf-8")
    out = RuleOverlapAgent().run(detection_id="D-0001", workspace=ws)
    assert [o["other_id"] for o in out["overlaps"]] == ["D-0002"]


def test_sigma_placeholders_ignore_selection_names():
    # Sorted by name, `filter` < `selection` but `amain` < `zfilter`: only a
    # placeholder that ignores names lines the two renamed rules up.
    a = ("    selection:\n        Image|endswith: a.exe\n"
         "    filter:\n        User: system\n")
    b = ("    zfilter:\n        User: system\n"
         "    amain:\n        Image|endswith: a.exe\n")
    result = _sigma_pair(_sigma(a, condition="selection and not filter"),
                         _sigma(b, condition="amain and not zfilter"))
    print(result)
    assert result.overlap_type == "duplicate", result
    assert result.confidence == 1.0, result


def test_sigma_file_order_never_matters():
    # Same selections, opposite file order: numbering must not follow the
    # YAML mapping order.
    a = ("    selection_a:\n        Image|endswith: a.exe\n"
         "    selection_b:\n        Image|endswith: b.exe\n")
    b = ("    selection_b:\n        Image|endswith: b.exe\n"
         "    selection_a:\n        Image|endswith: a.exe\n")
    cond = "1 of selection_*"
    result = _sigma_pair(_sigma(a, condition=cond), _sigma(b, condition=cond))
    print(result)
    assert result.overlap_type == "duplicate", result
    assert result.confidence == 1.0, result


def test_sigma_wildcard_selection_filter_swap_is_not_a_duplicate():
    # Sorted by name both rules number a_* S1 and b_* S2 with the same values,
    # and the condition text is identical: opposite rules, identical tokens,
    # unless the wildcards are resolved to what they match.
    x = ("    a_sel:\n        Image|endswith: a.exe\n"
         "    b_filter:\n        Image|endswith: b.exe\n")
    y = ("    b_sel:\n        Image|endswith: b.exe\n"
         "    a_filter:\n        Image|endswith: a.exe\n")
    cond = "1 of *_sel and not 1 of *_filter"
    result = _sigma_pair(_sigma(x, condition=cond), _sigma(y, condition=cond))
    print(result)
    assert result.overlap_type != "duplicate", result
    assert result.confidence < 0.85, result


def test_sigma_wildcard_logic_under_other_name_prefixes_is_a_duplicate():
    x = ("    sel_a:\n        Image|endswith: a.exe\n"
         "    sel_b:\n        Image|endswith: b.exe\n"
         "    filter_x:\n        User: system\n")
    y = ("    main_1:\n        Image|endswith: a.exe\n"
         "    main_2:\n        Image|endswith: b.exe\n"
         "    excl_1:\n        User: system\n")
    result = _sigma_pair(_sigma(x, condition="1 of sel_* and not 1 of filter_*"),
                         _sigma(y, condition="1 of main_* and not 1 of excl_*"))
    print(result)
    assert result.overlap_type == "duplicate", result
    assert result.confidence == 1.0, result
    # `them` is every selection.
    both = ("    sel_a:\n        Image|endswith: a.exe\n"
            "    sel_b:\n        Image|endswith: b.exe\n")
    result = _sigma_pair(_sigma(both, condition="all of them"), _sigma(both, condition="all of sel_*"))
    print(result)
    assert result.overlap_type == "duplicate", result
    assert result.confidence == 1.0, result


def test_sigma_commutative_operand_order_is_a_duplicate():
    sels = ("    sel1:\n        Image|endswith: a.exe\n"
            "    sel2:\n        CommandLine|contains: http\n")
    result = _sigma_pair(_sigma(sels, condition="sel1 and sel2"), _sigma(sels, condition="sel2 and sel1"))
    print(result)
    assert result.overlap_type == "duplicate", result
    assert result.confidence == 1.0, result


def test_sigma_leaves_stay_grouped_by_selection():
    # (a AND b) OR c vs a OR (b AND c): same leaves, same condition text —
    # only the selection prefix on each leaf tells the groupings apart.
    x = ("    sel1:\n        Image|endswith: a.exe\n        User: bob\n"
         "    sel2:\n        CommandLine|contains: http\n")
    y = ("    sel1:\n        Image|endswith: a.exe\n"
         "    sel2:\n        User: bob\n        CommandLine|contains: http\n")
    cond = "sel1 or sel2"
    result = _sigma_pair(_sigma(x, condition=cond), _sigma(y, condition=cond))
    print(result)
    assert result.overlap_type != "duplicate", result
    assert result.confidence < 0.85, result


_TWELVE = "    selection:\n        Image|endswith:\n" + "".join(
    f"            - '\\\\bin{i}.exe'\n" for i in range(12)
) + "    filter:\n        User: SYSTEM\n"


@pytest.mark.parametrize("flipped", ["selection and filter", "selection or filter"])
def test_same_leaves_under_a_different_condition_are_not_duplicates(flipped):
    # One condition token among 14 leaf tokens: Jaccard 0.867 >= 0.85, yet
    # `and not filter` vs `and filter` fire on disjoint events.
    result = _sigma_pair(
        _sigma(_TWELVE, condition="selection and not filter"),
        _sigma(_TWELVE, condition=flipped),
    )
    assert result.confidence >= 0.85, result  # the case the Jaccard alone misses
    assert result.overlap_type == "complementary", result



def test_a_later_clean_occurrence_still_counts_as_a_superset():
    """The boundary check judged only the *first* occurrence of the predicate.

    A broad rule can mention the narrow rule's predicate twice — once inside a
    longer token (`event.code=10`) and once on its own. The first match failed the
    token-boundary test, the function returned there, and a genuinely redundant
    pair came back `complementary`: the Refine journal says "different coverage
    angle" and the duplicate ships. Every occurrence is tested now.
    """
    a = _rec("A", "t", "event.code=1", []).to_yaml_dict()
    b = _rec("B", "t", "event.code=10 and event.code=1", []).to_yaml_dict()
    assert classify_pair(a, b, "A", "B").overlap_type == "redundant"
    # The boundary rejection itself still holds when there is no clean occurrence.
    c = _rec("C", "t", "event.code=10 and event.code=100", []).to_yaml_dict()
    assert classify_pair(a, c, "A", "C").overlap_type != "redundant"


def test_paren_wrapped_identical_logic_is_a_duplicate_not_redundant():
    """`(x)` and `((x))` are the same predicate.

    The identity check compared the *unstripped* normalized forms while the
    substring arm below it compared the stripped halves, so an identical pair
    fell through to `redundant` at confidence 1.0 — with reasoning asserting
    each side was both a strict superset and a subset of the other. A dedupe
    review reading "redundant, 100%" deletes the wrong rule.
    """
    a = _rec("A", "t", "(process.name = 'mshta.exe')", []).to_yaml_dict()
    b = _rec("B", "t", "((process.name = 'mshta.exe'))", []).to_yaml_dict()
    result = classify_pair(a, b, "A", "B")
    assert result.overlap_type == "duplicate", result
    assert result.confidence == 1.0, result


def test_a_placeholder_query_does_not_divide_by_zero():
    """`()` normalizes non-empty and strips to nothing, and the confidence is a
    ratio of the stripped lengths — so a stub candidate (or a GATES document with
    the logic left out) raised `ZeroDivisionError` inside `classify_pair`, which
    `run_refine_chain` then wrote into the user's journal as a traceback."""
    a = _rec("A", "t", "()", []).to_yaml_dict()
    b = _rec("B", "t", "(())", []).to_yaml_dict()
    assert classify_pair(a, b, "A", "B").overlap_type == "complementary"


# --- SPL: compare filter stages, not ESCU scaffolding (0.74 on boilerplate alone).

_ESCU = (
    "| tstats `security_content_summariesonly` count min(_time) as firstTime "
    "FROM datamodel=Endpoint.Registry WHERE {where} by Registry.action Registry.dest "
    "Registry.registry_path Registry.registry_value_data Registry.user "
    "| `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `{name}_filter`"
)


def _spl(rid: str, query: str) -> dict:
    return {"id": rid, "query": query, "query_language": "spl", "format": "splunk-escu",
            "data_source": "Sysmon EventID 13", "mitre": ["T1548.002"]}


def test_spl_filter_text_keeps_only_filter_stages():
    q = _ESCU.format(where='Registry.registry_path="*mscfile*"', name="x") + ' | where count > 5'
    assert spl_filter_text(q) == (
        'datamodel=Endpoint.Registry | Registry.registry_path="*mscfile*" | where count > 5'
    )


def test_escu_rules_sharing_only_boilerplate_are_not_duplicates():
    a = _spl("A", _ESCU.format(where='Registry.registry_path="*EnableLUA*" Registry.registry_value_data="0x0"', name="a"))
    b = _spl("B", _ESCU.format(where='Registry.registry_path="*mscfile\\\\shell\\\\open\\\\command*"', name="b"))
    result = classify_pair(a, b, "A", "B")
    assert result.overlap_type == "complementary", result
    assert result.confidence < 0.5, result


def test_spl_predicates_differing_in_one_value_are_not_duplicates():
    # A character ratio scored this 0.97 "duplicate".
    a = _spl("A", "`wineventlog_security` EventCode=4946 | stats count by dest")
    b = _spl("B", "`wineventlog_security` EventCode=4948 | stats count by dest")
    result = classify_pair(a, b, "A", "B")
    assert result.overlap_type == "complementary", result


def test_same_spl_filter_under_different_scaffolding_is_a_duplicate():
    where = 'Registry.registry_path="*mscfile*"'
    a = _spl("A", _ESCU.format(where=where, name="a"))
    b = _spl("B", f"| tstats count FROM datamodel=Endpoint.Registry WHERE {where} by Registry.dest")
    assert classify_pair(a, b, "A", "B").overlap_type == "duplicate"


def test_spl_same_tokens_different_boolean_shape_are_not_duplicates():
    # CodeRabbit: token Jaccard is 1.0 here, but the logic differs.
    a = _spl("A", "index=x | where a=1 AND b=2 OR c=3")
    b = _spl("B", "index=x | where a=1 OR b=2 AND c=3")
    result = classify_pair(a, b, "A", "B")
    assert result.confidence == 1.0, result
    assert result.overlap_type == "complementary", result


def test_spl_reordered_and_implicit_and_still_duplicates():
    a = _spl("A", "index=x a=1 b=2 c=3")
    b = _spl("B", "index=x c=3 AND a=1 AND b=2")
    assert classify_pair(a, b, "A", "B").overlap_type == "duplicate"


def test_tstats_same_where_different_datamodel_are_not_duplicates():
    # CodeRabbit: the dataset is not interchangeable scaffolding.
    where = 'Processes.process_name="wmic.exe"'
    a = _spl("A", f"| tstats count FROM datamodel=Endpoint.Processes WHERE {where} by dest")
    b = _spl("B", f"| tstats count FROM datamodel=Endpoint.Filesystem WHERE {where} by dest")
    assert "datamodel=Endpoint.Processes" in spl_filter_text(a["query"])
    assert classify_pair(a, b, "A", "B").overlap_type != "duplicate"


# Four more false-duplicate shapes.

def test_spl_not_bound_to_different_predicates_are_not_duplicates():
    a = _spl("A", "index=x | where NOT (a=1) AND b=2")
    b = _spl("B", "index=x | where NOT (b=2) AND a=1")
    assert classify_pair(a, b, "A", "B").overlap_type != "duplicate"


def test_spl_filter_on_an_eval_built_field_falls_back_to_the_query():
    q = 'index=x | eval flagged=if(process="{p}",1,0) | where flagged=1'
    assert spl_filter_text(q.format(p="powershell.exe")) == ""
    a = _spl("A", q.format(p="powershell.exe"))
    b = _spl("B", q.format(p="cmd.exe"))
    assert classify_pair(a, b, "A", "B").overlap_type != "duplicate"


def test_spl_regex_and_search_on_the_same_value_are_not_duplicates():
    a = _spl("A", 'index=x | regex _raw="^foo"')
    b = _spl("B", 'index=x | search _raw="^foo"')
    assert classify_pair(a, b, "A", "B").overlap_type != "duplicate"


def test_spl_and_inside_a_quoted_value_is_not_an_operator():
    a = _spl("A", 'index=x CommandLine="foo AND bar"')
    b = _spl("B", 'index=x CommandLine="foo bar"')
    assert classify_pair(a, b, "A", "B").overlap_type != "duplicate"


def test_spl_extra_predicate_in_a_conjunction_is_redundant():
    a = _spl("A", "index=x a=1 b=2")
    b = _spl("B", "index=x a=1 b=2 c=3")
    assert classify_pair(a, b, "A", "B").overlap_type == "redundant"


def test_spl_extra_or_branch_is_not_redundant():
    # A token superset under OR is a *broader* rule, not a narrower one.
    a = _spl("A", "index=x a=1")
    b = _spl("B", "index=x a=1 OR c=3")
    assert classify_pair(a, b, "A", "B").overlap_type == "complementary"


def test_spl_not_without_parens_binds_to_its_own_predicate():
    a = _spl("A", "index=x NOT a=1 b=2")
    b = _spl("B", "index=x NOT b=2 a=1")
    assert classify_pair(a, b, "A", "B").overlap_type != "duplicate"
    same = _spl("C", "index=x b=2 NOT a=1")  # reordered, same negation
    assert classify_pair(a, same, "A", "C").overlap_type == "duplicate"


def test_spl_conjunctions_with_conflicting_predicates_are_not_duplicates():
    shared = " ".join(f"f{i}=v{i}" for i in range(13))
    a = _spl("A", f'index=x {shared} process_name="cmd.exe"')
    b = _spl("B", f'index=x {shared} process_name="powershell.exe"')
    result = classify_pair(a, b, "A", "B")
    assert result.confidence >= 0.85, result  # what the old threshold accepted
    assert result.overlap_type == "complementary", result


def test_spl_regex_patterns_differing_only_in_case_are_not_duplicates():
    # CodeRabbit: unflagged PCRE in `regex` is case-sensitive.
    a = _spl("A", 'index=x | regex _raw="^Foo"')
    b = _spl("B", 'index=x | regex _raw="^foo"')
    assert classify_pair(a, b, "A", "B").overlap_type != "duplicate"
    # ...while search/where values stay case-insensitive.
    c = _spl("C", 'index=x Image="CMD.EXE" | regex _RAW="^Foo"')
    assert classify_pair(a, c, "A", "C").overlap_type != "duplicate"  # extra Image predicate
    d = _spl("D", 'index=x | REGEX _raw="^Foo"')  # command case folds
    assert classify_pair(a, d, "A", "D").overlap_type == "duplicate"


def test_spl_normalization_never_touches_meaning():
    # CodeRabbit: whitespace inside a quoted regex, case-sensitive
    # field names, and CASE() terms all change which events match.
    pairs = [
        ('index=x | regex _raw="^foo (bar)$"', 'index=x | regex _raw="^foo(bar)$"'),
        ("index=x User=alice", "index=x user=alice"),
        ("index=x CASE(Foo)", "index=x CASE(foo)"),
    ]
    for qa, qb in pairs:
        assert classify_pair(_spl("A", qa), _spl("B", qb), "A", "B").overlap_type != "duplicate", (qa, qb)
    # ...while keyword case and operator spacing still normalize.
    same = (_spl("A", "index=x a = 1 OR b=2"), _spl("B", "index=x a=1 or b=2"))
    assert classify_pair(*same, "A", "B").overlap_type == "duplicate"


# --- Cross-language pairs are unassessed, not "complementary" at ~0.01.

def test_cross_language_pair_is_unassessed_not_complementary():
    sigma = _rec("A", "a", _sigma(_MSHTA), ["T1218"]).to_yaml_dict()
    spl = _spl("B", 'index=x Image="*\\\\mshta.exe"')
    result = classify_pair(sigma, spl, "A", "B")
    assert result.overlap_type == "unassessed", result
    assert "sigma vs spl" in result.reasoning


def test_same_language_pairs_are_still_classified():
    a = _spl("A", "index=x a=1")
    b = _spl("B", "index=x a=1")
    assert classify_pair(a, b, "A", "B").overlap_type == "duplicate"


def test_sigma_labelled_record_without_detection_block_is_not_a_language():
    # A bare predicate stored under format: sigma isn't Sigma logic; keep the
    # text comparison rather than declaring the pair cross-language.
    bare = _rec("A", "a", "process.name = 'mshta.exe'", ["T1218"]).to_yaml_dict()
    sql = {"id": "B", "query": "process.name = 'mshta.exe' and user = 'x'", "format": "sql",
           "query_language": "sql", "data_source": "wineventlog", "mitre": ["T1218"]}
    assert classify_pair(bare, sql, "A", "B").overlap_type != "unassessed"
