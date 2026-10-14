"""Value retrieval: other-language rules testing the same distinctive literals."""

from adef.agents.rule_similarity import RuleSimilarityAgent
from adef.core.catalog import Catalog, CatalogRecord
from adef.core.corpus import CorpusEntry
from adef.core.journal import Journal
from adef.core.value_index import build_value_index, value_tokens

SIGMA_MSHTA = """title: t
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\\\mshta.exe'
    CommandLine|contains: 'vbscript:Execute'
  condition: selection
"""
CQL_MSHTA = '#event_simpleName=ProcessRollup2 | ImageFileName=/\\\\mshta\\.exe/i | CommandLine=*vbscript:Execute*'


def _sigma(rid, query):
    return {"id": rid, "format": "sigma", "query": query}


def _cql(rid, query):
    return {"id": rid, "format": "crowdstrike-query-hub", "query_language": "cql", "query": query}


def test_value_tokens_take_values_not_field_names():
    toks = value_tokens(_sigma("A", SIGMA_MSHTA))
    assert {"mshta.exe", "mshta", "vbscript"} <= toks
    assert not {"image", "commandline", "selection", "endswith"} & toks
    cql = value_tokens(_cql("B", CQL_MSHTA))
    assert {"mshta", "vbscript"} <= cql
    assert not {"imagefilename", "commandline", "event_simplename"} & cql


def test_unquoted_operands_count_but_assignments_do_not():
    toks = value_tokens({"format": "splunk-escu", "query_language": "spl",
                         "query": 'index=x Image=*\\\\certutil.exe | eval decoded := base64(x)'})
    assert "certutil.exe" in toks
    assert "base64" not in toks


def _corpus(records):
    return [CorpusEntry(detection_id=r["id"], record=r) for r in records]


def _decoys(n):
    # Same-language noise so a token in only the pair is rare (df gate needs N).
    return [_sigma(f"N{i}", SIGMA_MSHTA.replace("mshta.exe", f"tool{i}.exe")
                   .replace("vbscript:Execute", f"flag{i}")) for i in range(n)]


def test_candidates_are_other_language_only():
    # 60 decoys: the df cap is 5% of the corpus, and the pair's values sit in
    # three rules (A, A2, B) — a corpus of 11 would gate them out entirely.
    records = [_sigma("A", SIGMA_MSHTA), _sigma("A2", SIGMA_MSHTA), _cql("B", CQL_MSHTA), *_decoys(60)]
    hits = build_value_index(_corpus(records)).candidates("A", top_k=10)
    assert [h.detection_id for h in hits] == ["B"]  # A2 is identical but same-language
    assert "vbscript" in hits[0].shared_values


def test_ubiquitous_values_carry_no_weight():
    # `cmd.exe` in every rule must not make two unrelated rules candidates.
    common = [_sigma(f"S{i}", SIGMA_MSHTA.replace("mshta.exe", "cmd.exe")
                     .replace("vbscript:Execute", f"only{i}")) for i in range(10)]
    other = _cql("C", "ImageFileName=/cmd\\.exe/i | CommandLine=*unrelated*")
    hits = build_value_index(_corpus([*common, other])).candidates("C", top_k=10)
    assert hits == []


def _twin_workspace(tmp_path):
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")

    def put(rid, fmt, lang, query, title):
        rec = CatalogRecord(id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
                            platform="windows", kind="atomic", engine="sigma", format=fmt,
                            query=query, mitre=["T1218.005"], query_language=lang)
        cat.write_raw(ws / "catalog" / f"{rid}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rid, title=title)

    put("D-0001", "sigma", "", SIGMA_MSHTA, "Mshta VBScript execution")
    # Same-language decoys: lexically closer to the target than the twin is.
    for i in range(8):
        put(f"D-01{i:02d}", "sigma", "", SIGMA_MSHTA.replace("mshta.exe", f"tool{i}.exe")
            .replace("vbscript:Execute", f"flag{i}"), f"Tool{i} execution")
    put("D-0200", "crowdstrike-query-hub", "cql", CQL_MSHTA, "LOLBin abuse")
    cat.rebuild_index()
    return ws


def test_similarity_shortlists_a_cross_language_twin_through_values(tmp_path):
    ws = _twin_workspace(tmp_path)
    result = RuleSimilarityAgent().run("D-0001", workspace=ws, top_k=3, similarity_mode="bm25")
    by_id = {c["detection_id"]: c for c in result["candidates"]}
    assert "D-0200" in by_id, [c["detection_id"] for c in result["candidates"]]
    assert "values" in by_id["D-0200"]["found_by"]
    assert "vbscript" in by_id["D-0200"]["shared_values"]
    assert all("values" not in c["found_by"] for d, c in by_id.items() if d != "D-0200")


class _FakeClient:
    def __init__(self):
        self.calls: list[dict] = []
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.calls.append(kwargs)
                block = type("B", (), {"type": "text", "text": "[]"})()
                return type("R", (), {"content": [block]})()

        self.messages = _Messages()


def test_llm_judge_gets_the_query_of_a_value_only_candidate(tmp_path):
    # CodeRabbit: a value-matched candidate had no field evidence and
    # no useful snippet, so the judge couldn't assess it.
    ws = _twin_workspace(tmp_path)
    fake = _FakeClient()
    RuleSimilarityAgent().run("D-0001", workspace=ws, top_k=3, similarity_mode="llm", llm_client=fake)
    prompt = fake.calls[0]["messages"][0]["content"]
    line = next(ln for ln in prompt.splitlines() if "id=D-0200" in ln)
    assert "query=" in line and "ImageFileName" in line, line
    assert "shared_values" not in prompt  # egress: values themselves stay out


def test_a_distinctive_event_id_is_a_value():
    # CodeRabbit CLI: rules testing only an event ID had no tokens.
    sigma = _sigma("A", "title: t\nlogsource: {product: windows, service: security}\n"
                        "detection:\n  selection:\n    EventID: 4946\n  condition: selection\n")
    spl = {"id": "B", "format": "splunk-escu", "query_language": "spl",
           "query": "`wineventlog_security` EventCode=4946"}
    hits = build_value_index(_corpus([sigma, spl, *_decoys(60)])).candidates("A", top_k=5)
    assert [h.detection_id for h in hits] == ["B"] and hits[0].shared_values == ["4946"]


def test_assignment_values_are_not_tested_values():
    toks = value_tokens({"format": "crowdstrike-query-hub", "query_language": "cql",
                         "query": '#event_simpleName=ProcessRollup2 | label := "EnableLUA" | ImageFileName=/reg\\.exe/i'})
    assert "enablelua" not in toks and "reg.exe" in toks


def test_kql_double_equals_operand_is_a_value():
    toks = value_tokens({"format": "kql", "query_language": "kql",
                         "query": "SecurityEvent | where EventID == 4946"})
    assert "4946" in toks


def test_in_list_members_are_values():
    toks = value_tokens({"format": "sql", "query_language": "sql",
                         "query": "SELECT * FROM security WHERE EventID IN (4946, 4948)"})
    assert {"4946", "4948"} <= toks


def test_a_quoted_value_containing_assignment_syntax_is_still_a_value():
    # CodeRabbit: the assignment filter wiped `"x := mshta.exe"`.
    toks = value_tokens({"format": "splunk-escu", "query_language": "spl",
                         "query": 'index=x CommandLine="x := mshta.exe"'})
    assert "mshta.exe" in toks


def test_range_comparison_operands_are_values():
    # Symmetric with Sigma, whose `EventID|gte: 4946` leaf is indexed.
    toks = value_tokens({"format": "kql", "query_language": "kql",
                         "query": "SecurityEvent | where EventID >= 4946 and EventID < 4950"})
    assert {"4946", "4950"} <= toks


def test_values_in_comments_are_not_tested_values():
    # CodeRabbit: a commented-out predicate isn't what the rule tests.
    cql = value_tokens(_cql("A", '// ImageFileName="mshta.exe"\n#event_simpleName=ProcessRollup2 | ImageFileName=/regsvr32\\.exe/i'))
    assert "mshta.exe" not in cql and "regsvr32.exe" in cql
    sql = value_tokens({"format": "sql", "query_language": "sql",
                        "query": "SELECT * FROM t WHERE x = 'certutil.exe' -- was 'mshta.exe'\n/* 'rundll32.exe' */"})
    assert "certutil.exe" in sql and not {"mshta.exe", "rundll32.exe"} & sql


def test_llm_fallback_score_uses_value_score_for_a_value_only_candidate():
    # CodeRabbit: an invalid judge confidence sank a value-only twin
    # (no BM25 hit, no field hit) to 0.0. Driven through the reranker
    # directly: in a real corpus shared MITRE/platform tokens nearly always
    # give the twin a BM25 score too, which would bypass the fallback.
    class _NaNClient(_FakeClient):
        def __init__(self):
            super().__init__()
            outer = self

            class _Messages:
                def create(self, **kwargs):
                    outer.calls.append(kwargs)
                    text = '[{"detection_id": "D-0200", "confidence": "NaN", "reasoning": "r"}]'
                    return type("R", (), {"content": [type("B", (), {"type": "text", "text": text})()]})()

            self.messages = _Messages()

    value_only = {"detection_id": "D-0200", "title": "LOLBin abuse", "score": 0.0, "snippet": "",
                  "reasoning": "", "bm25_score": None, "field_score": None, "shared_fields": [],
                  "value_score": 0.6, "shared_values": ["vbscript"], "found_by": ["values"]}
    target = {"id": "D-0001", "title": "t", "format": "sigma", "query": SIGMA_MSHTA, "mitre": []}
    records = {"D-0001": target, "D-0200": _cql("D-0200", CQL_MSHTA)}
    [twin] = RuleSimilarityAgent()._rerank_with_llm(target, [value_only], _NaNClient(), records)
    assert twin["score"] == 0.6, twin
