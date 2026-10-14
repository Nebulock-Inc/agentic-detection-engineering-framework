# tests/test_similarity_fusion.py
import yaml

from adef.agents.rule_similarity import RuleSimilarityAgent
from adef.core.catalog import Catalog, CatalogRecord
from adef.core.journal import Journal


def _rec(rid, title, query, lang, fmt, source, platform="windows", mitre=None):
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"r/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform=platform, kind="atomic", engine="sigma", format=fmt,
        query=query, mitre=["T1218.005"] if mitre is None else list(mitre),
        query_language=lang, data_source=source,
    )


def _ws(tmp_path, records, schema=None):
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat, journal = Catalog(ws), Journal(ws / "journals")
    for rec in records:
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()
    # `schema` is a single dict (existing call sites) or a list of dicts
    # (two independent schema sources
    # both aliasing to the same canonical field, so a candidate can share
    # zero literal tokens with the target and still be a genuine field match).
    schemas = schema if isinstance(schema, list) else ([schema] if schema else [])
    if schemas:
        (ws / "schema").mkdir()
        for s in schemas:
            (ws / "schema" / f"{s['source']}.yml").write_text(
                yaml.safe_dump(s), encoding="utf-8")
    return ws


SIGMA = """
detection:
  selection:
    Image|endswith: '\\mshta.exe'
    ParentImage|endswith: '\\excel.exe'
  condition: selection
"""
# Dotted field names need backtick quoting: sqlglot otherwise parses
# `process.name` as table `process`, column `name`, and `Column.name` returns
# only the bare `name` -- collapsing two distinct fields into one token and
# silently defeating alias canonicalization against the schema below.
SQL = "SELECT * FROM wineventlog WHERE `process.name` = 'mshta.exe' AND `parent.name` = 'excel.exe'"
# A field shared by every detection in the corpus is "universal" (df == N)
# and FieldIndex.candidates() refuses to match on it alone (see
# adef/core/field_index.py's _UBIQUITOUS_FLOOR) -- a fixture with only the
# two rules under test would make `process.name`/`parent.name` universal and
# produce no field match for the wrong reason. This noise record's disjoint
# field keeps df(process.name) < N so the shared fields carry real idf signal.
NOISE = "SELECT * FROM other WHERE `other.field` = 'z'"
# A pure-BM25 competitor with NO matching fields, engineered to score higher
# on raw lexical overlap than D-0002 does (reuses the same literal values,
# repeated, against unrelated field names/source) -- CodeRabbit review: the
# original two-record fixture let D-0002 win on BM25 alone too, so a test
# built on it couldn't actually distinguish "the field pass expanded the
# shortlist" from "BM25 would have found it anyway."
BM25_STRONG = (
    "SELECT * FROM otherhost WHERE `user.exe` = 'mshta.exe' AND `parent.exe` = 'excel.exe' "
    "AND `cmdline.raw` = 'mshta.exe excel.exe mshta.exe excel.exe'"
)
SCHEMA = {
    "schema_version": 2, "source": "wineventlog",
    "fields": [
        {"name": "process.name", "type": "string", "aliases": ["Image"]},
        {"name": "parent.name", "type": "string", "aliases": ["ParentImage"]},
    ],
}


def test_the_field_pass_expands_the_shortlist(tmp_path):
    # THE point of the story: at top_k=1 (only the single best candidate
    # survives), D-0000 outranks D-0002 on raw BM25 alone -- but D-0002's
    # field match promotes it to first place once fused. Proving this needs a
    # competitor that genuinely beats D-0002 on BM25 (see BM25_STRONG above);
    # without one, D-0002's own nonzero lexical overlap with D-0001 (shared
    # data_source/mitre/platform tokens, plus the literal "mshta.exe"/
    # "excel.exe" values Sigma and SQL both name) can win a small top_k on
    # BM25 alone, which would prove nothing about the field pass.
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta via sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "zzz unrelated wording", SQL, "sql", "sql", "wineventlog"),
        _rec("D-9000", "unrelated noise rule", NOISE, "sql", "sql", "other"),
        _rec("D-0000", "mshta exe excel exe strong lexical overlap mshta excel",
             BM25_STRONG, "sql", "sql", "otherhost"),
    ], schema=SCHEMA)
    result5 = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=5, similarity_mode="bm25")
    by_id = {c["detection_id"]: c for c in result5["candidates"]}
    assert "D-0002" in by_id
    assert "fields" in by_id["D-0002"]["found_by"]
    assert by_id["D-0002"]["field_score"] > 0
    assert by_id["D-0002"]["shared_fields"]
    # D-0000 has no field match at all, and out-scores D-0002 on raw BM25 --
    # so a BM25-only ranking (no field pass) would put D-0000 first.
    assert by_id["D-0000"]["field_score"] is None
    assert by_id["D-0000"]["bm25_score"] > by_id["D-0002"]["bm25_score"]

    # At top_k=1, fusion still puts D-0002 first: its combined bm25 rank 2 +
    # field rank 1 outweighs D-0000's bm25 rank 1 alone. This only holds
    # because both passes are fused at full depth before any truncation to
    # top_k (see rule_similarity.py's `pool_size` comment) -- truncating each
    # pass to top_k=1 *before* fusion would drop D-0002 from bm25_hits
    # entirely and hand D-0000 the win.
    result1 = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=1, similarity_mode="bm25")
    assert [c["detection_id"] for c in result1["candidates"]] == ["D-0002"]


def test_the_result_reports_the_matching_mode(tmp_path):
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "b", SQL, "sql", "sql", "wineventlog"),
    ], schema=SCHEMA)
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, similarity_mode="bm25")
    assert result["field_matching"] == "schema"


def test_a_bm25_only_candidate_keeps_its_score_and_provenance(tmp_path):
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta child process", "SELECT * FROM t WHERE a.b='x'", "sql", "sql", "t"),
        _rec("D-0002", "mshta child process again", "SELECT * FROM t WHERE q.r='y'", "sql", "sql", "t"),
    ], schema=None)
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, similarity_mode="bm25")
    by_id = {c["detection_id"]: c for c in result["candidates"]}
    assert by_id["D-0002"]["found_by"] == ["bm25"]
    assert by_id["D-0002"]["bm25_score"] > 0
    assert by_id["D-0002"]["field_score"] is None


def test_fusion_is_deterministic(tmp_path):
    # comparing two runs of the SAME
    # fixture against each other is trivially true regardless of whether the
    # `d` (detection_id) tie-break exists in `sorted(fused, key=lambda d:
    # (-fused[d], d))` at all -- removing it reddened nothing, since a
    # deterministic computation run twice agrees with itself either way. This
    # fixture constructs an EXACT fused-score tie: D-0002 (bm25 rank 2, field
    # rank 1) and D-0003 (bm25 rank 1, field rank 2) sum to the identical
    # value (1/62+1/61 == 1/61+1/62) by symmetry. D-0002 wins only because its
    # id sorts first -- without the `d` key, Python's stable sort would
    # instead preserve insertion order into `fused` (D-0003 is added first,
    # since it's bm25-rank1 and the bm25 loop runs before the field loop),
    # putting D-0003 first instead.
    schema = {
        "schema_version": 2, "source": "wineventlog", "scope": {"ref": "zzzcode1"},
        "fields": [
            {"name": "process.name", "type": "string", "aliases": ["Image"]},
            {"name": "parent.name", "type": "string", "aliases": ["ParentImage"]},
        ],
    }
    target_query = "SELECT * FROM t WHERE `process.name` = 'x' AND `parent.name` = 'y'"
    ws = _ws(tmp_path, [
        _rec("D-0001", "kappa lambda mu", target_query, "sql", "sql", "wineventlog"),
        # bm25 rank 2 (short title), field rank 1 (pure single-field match, ratio 1.0)
        _rec("D-0002", "kappa", "SELECT * FROM zzzcode1 WHERE `Image` = 'w1'",
             "sql", "sql", "zzzcode1"),
        # bm25 rank 1 (long, repeated title), field rank 2 (diluted by an extra field)
        _rec("D-0003", "kappa lambda mu kappa lambda mu kappa lambda mu",
             "SELECT * FROM zzzcode1 WHERE `Image` = 'w3' AND `extra.f2` = 'v'",
             "sql", "sql", "zzzcode1"),
        _rec("D-9000", "noise", "SELECT * FROM other9 WHERE `noisefield` = 'z'",
             "sql", "sql", "other9"),
    ], schema=schema)

    a = RuleSimilarityAgent().run(detection_id="D-0001", workspace=ws, top_k=1, similarity_mode="bm25")
    b = RuleSimilarityAgent().run(detection_id="D-0001", workspace=ws, top_k=1, similarity_mode="bm25")
    assert [c["detection_id"] for c in a["candidates"]] == \
           [c["detection_id"] for c in b["candidates"]] == ["D-0002"]


def test_top_k_larger_than_the_corpus_does_not_pad_or_duplicate(tmp_path):
    # Review Focus 5.
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", SQL, "sql", "sql", "wineventlog"),
        _rec("D-0002", "b", SQL, "sql", "sql", "wineventlog"),
    ], schema=SCHEMA)
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=50, similarity_mode="bm25")
    ids = [c["detection_id"] for c in result["candidates"]]
    assert ids == ["D-0002"]
    assert len(ids) == len(set(ids))


def test_bm25_mode_still_makes_no_network_call(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-never-be-used")
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "b", SQL, "sql", "sql", "wineventlog"),
    ], schema=SCHEMA)

    def _boom(*a, **k):
        raise AssertionError("bm25 mode must not construct an LLM client")

    monkeypatch.setattr("adef.agents.rule_similarity._llm_available", _boom)
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, similarity_mode="bm25")
    assert result["mode_used"] == "bm25"


def test_agent_mode_carries_the_fusion_fields(tmp_path):
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "b", SQL, "sql", "sql", "wineventlog"),
        _rec("D-9000", "c", NOISE, "sql", "sql", "other"),
    ], schema=SCHEMA)
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, similarity_mode="agent")
    top = result["candidates"][0]
    assert top["field_score"] is not None
    assert top["found_by"]
    assert result["field_matching"] == "schema"


class _FakeAnthropicClient:
    """Injected in place of `anthropic.Anthropic()` — no network calls in tests."""

    def __init__(self, response_text: str):
        self._response_text = response_text
        self.calls: list[dict] = []

    class _Messages:
        def __init__(self, outer: "_FakeAnthropicClient"):
            self._outer = outer

        def create(self, **kwargs):
            self._outer.calls.append(kwargs)
            block = type(
                "Block", (), {"type": "text", "text": self._outer._response_text}
            )()
            return type("Response", (), {"content": [block]})()

    @property
    def messages(self):
        return self._Messages(self)


def test_llm_prompt_falls_back_to_shared_fields_and_query_when_snippet_is_empty():
    # CodeRabbit (three rounds): a field-only candidate has no BM25 snippet
    # (nothing to excerpt), leaving the judge nothing to compare logic
    # against. Round 1 added shared_fields; round 2 pointed out that field
    # names alone still don't let the judge compare *logic* -- a bounded
    # slice of the candidate's own query does. Unit-level on
    # `_rerank_with_llm` directly -- reaching a genuinely bm25-absent
    # candidate through the full `run()` pipeline would require defeating
    # even the shared platform/mitre/data_source tokens every fixture record
    # in this file carries, which this finding doesn't need to prove.
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 0.0, "snippet": "",
        "reasoning": "", "bm25_score": None, "field_score": 1.0,
        "shared_fields": ["parent.name", "process.name"], "found_by": ["fields"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.6}]')
    RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": SIGMA}, [candidate], fake,
        {"D-0002": {"query": "SELECT * FROM t WHERE marker = 'uniquemarkerxyz'"}})
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "shared_fields" in prompt
    assert "process.name" in prompt
    assert "uniquemarkerxyz" in prompt  # the candidate's own query reached the judge


def test_llm_prompt_adds_shared_fields_and_query_even_when_a_snippet_exists():
    # CodeRabbit round 3 (a third round on this same fallback): a BM25
    # snippet is excerpted from the record's FULL index text (title, mitre,
    # platform, data_source, format, query -- see `CorpusEntry.index_text`),
    # not just the query. A candidate can score via BM25 purely on shared
    # title/mitre tokens and still get a snippet that never touches its
    # actual query -- so gating the fallback on "snippet is empty" missed a
    # field-matched candidate that happens to also have an unrelated snippet.
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 1.0, "snippet": "some snippet",
        "reasoning": "", "bm25_score": 1.0, "field_score": 1.0,
        "shared_fields": ["parent.name", "process.name"], "found_by": ["bm25", "fields"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.6}]')
    RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": SIGMA}, [candidate], fake,
        {"D-0002": {"query": "SELECT * FROM t WHERE marker = 'uniquemarkerxyz'"}})
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "shared_fields" in prompt
    assert "uniquemarkerxyz" in prompt


def test_llm_prompt_does_not_add_shared_fields_or_query_for_a_pure_bm25_candidate():
    # The fallback must not clutter a candidate with no field match at all.
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 1.0, "snippet": "some snippet",
        "reasoning": "", "bm25_score": 1.0, "field_score": None,
        "shared_fields": [], "found_by": ["bm25"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.6}]')
    RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": SIGMA}, [candidate], fake,
        {"D-0002": {"query": "SELECT * FROM t WHERE marker = 'uniquemarkerxyz'"}})
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "shared_fields" not in prompt
    assert "uniquemarkerxyz" not in prompt


def test_llm_mode_judges_the_fused_shortlist_not_bm25_hits_alone(tmp_path):
    # CodeRabbit (uncommitted-diff review, two rounds):
    # (1) `_rerank_with_llm` originally reranked `bm25_hits` only, so a
    #     field-only candidate never even reached the LLM judge in
    #     `llm`/`auto` mode, though `bm25`/`agent` mode already carried it.
    # (2) The first fix of this test reused a fixture where D-0002 was ALSO
    #     the strongest BM25 hit on its own (no competitor beat it), so the
    #     test couldn't tell "the fused shortlist reached the judge" apart
    #     from "bm25_hits would have been identical anyway." D-0000 is a
    #     competitor with no field match that out-scores D-0002 on raw BM25,
    #     so at top_k=1 the pre-fix code would hand the judge D-0000, not
    #     D-0002.
    ws = _ws(tmp_path, [
        _rec("D-0001", "mshta via sigma", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "zzz unrelated wording", SQL, "sql", "sql", "wineventlog"),
        _rec("D-9000", "unrelated noise rule", NOISE, "sql", "sql", "other"),
        _rec("D-0000", "mshta exe excel exe strong lexical overlap mshta excel",
             BM25_STRONG, "sql", "sql", "otherhost"),
    ], schema=SCHEMA)
    fake = _FakeAnthropicClient(
        '[{"detection_id": "D-0002", "confidence": 0.8, "reasoning": "same behavior"}]'
    )
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=1, similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "llm"
    assert len(fake.calls) == 1
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "D-0002" in prompt  # the judge was actually asked about it
    assert "D-0000" not in prompt  # the bm25-stronger, field-blind competitor lost the fused top-1
    top = result["candidates"][0]
    assert top["detection_id"] == "D-0002"
    assert top["score"] == 0.8
    assert top["field_score"] is not None  # fusion provenance survives rerank
    assert "fields" in top["found_by"]


def test_llm_mode_falls_back_to_field_score_for_a_bm25_absent_candidate():
    # `_safe_confidence`'s fallback
    # used to be `c["score"]`, the BM25 value -- exactly `0.0` for a
    # field-only candidate, since there is no BM25 hit to take a score from.
    # An invalid judge confidence therefore sank the cross-language duplicate
    # this whole task exists to surface to the bottom of a shortlist with
    # siblings present. Falls back to `field_score` (a real 0..1 signal)
    # instead, for a BM25-absent candidate only -- a candidate that DOES have
    # a BM25 score keeps the pre-existing fallback, so
    # test_rule_similarity_agent.py::test_llm_mode_clamps_non_finite_confidence_and_stringifies_reasoning's
    # pinned contract (fallback == the BM25 score) stays intact.
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 0.0, "snippet": "",
        "reasoning": "", "bm25_score": None, "field_score": 0.8,
        "shared_fields": ["parent.name", "process.name"], "found_by": ["fields"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": NaN}]')
    reranked = RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": SIGMA}, [candidate], fake, {})
    assert reranked[0]["score"] == 0.8  # fell back to field_score, not to score (0.0)


def test_llm_mode_reaches_a_genuinely_bm25_absent_candidate(tmp_path):
    # every other bm25-vs-field test in
    # this file uses a candidate with SOME nonzero BM25 score against the
    # target (this file's shared `_rec()` defaults put every record in the
    # same platform/mitre, which alone yields a nonzero score) -- so none of
    # them can distinguish "the fused selection reached the judge" from "a
    # BM25-absent candidate specifically reached the judge." A filter of
    # `candidates` to `bm25_score is not None` immediately before
    # `_rerank_with_llm` would leave every other test in this file green.
    # This fixture is genuinely BM25-unreachable: disjoint title, platform,
    # mitre, data_source, format, and query literal between target and
    # candidate, canonicalizing through TWO INDEPENDENT schema sources to the
    # same field name -- the actual cross-language-duplicate shape this task
    # exists for, not merely "no BM25 score by construction."
    schema_a = {
        "schema_version": 2, "source": "srcalpha",
        "fields": [{"name": "process.name", "type": "string", "aliases": ["Image"]}],
    }
    schema_b = {
        "schema_version": 2, "source": "srcbeta",
        "fields": [{"name": "process.name", "type": "string", "aliases": ["procpath"]}],
    }
    target_sigma = """
detection:
  selection:
    Image: 'alphavalue.exe'
  condition: selection
"""
    ws = _ws(tmp_path, [
        _rec("D-0001", "alpha widget zzzzz", target_sigma, "", "sigma", "srcalpha",
             platform="windows", mitre=[]),
        _rec("D-0002", "beta gadget yyyyy", "SELECT * FROM t WHERE procpath = 'betavalue'",
             "sql", "sql", "srcbeta", platform="linux", mitre=[]),
        _rec("D-9001", "noise record one", "SELECT * FROM t WHERE noisefield1 = 'x'",
             "sql", "sql", "other1", platform="macos", mitre=[]),
        _rec("D-9002", "noise record two", "SELECT * FROM t WHERE noisefield2 = 'y'",
             "sql", "sql", "other2", platform="macos", mitre=[]),
    ], schema=[schema_a, schema_b])

    # Prove the exclusion first: D-0002 carries no BM25 score at all.
    bm25_result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=5, similarity_mode="bm25")
    by_id = {c["detection_id"]: c for c in bm25_result["candidates"]}
    assert by_id["D-0002"]["bm25_score"] is None
    assert by_id["D-0002"]["found_by"] == ["fields"]
    assert by_id["D-0002"]["field_score"] is not None

    fake = _FakeAnthropicClient(
        '[{"detection_id": "D-0002", "confidence": 0.9, "reasoning": "same behavior"}]'
    )
    llm_result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=1, similarity_mode="llm", llm_client=fake)
    assert llm_result["mode_used"] == "llm"
    assert len(fake.calls) == 1
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "D-0002" in prompt  # the BM25-absent candidate reached the judge at all
    assert "process.name" in prompt  # procpath's canonical name reached the prompt
    assert llm_result["candidates"][0]["detection_id"] == "D-0002"


def test_fusion_uses_rrf_not_a_normalized_bm25_plus_field_score_sum(tmp_path):
    # Pins RRF (k=60) against its rejected alternative, "top-normalized BM25
    # summed against field_score", which would otherwise leave the whole suite
    # green. This fixture makes the two
    # formulas disagree on the winner: D-0004 has the WEAKEST raw BM25 score
    # in the run but a real (partial) field match; D-0002 has the STRONGEST
    # raw BM25 score and no field match at all. RRF's rank-based scoring lets
    # D-0004's presence in a second list outweigh a worse BM25 rank; a
    # normalized-sum scored on raw magnitude cannot, because D-0004's BM25
    # share of the run's top score plus its partial field_score stays below
    # D-0002's normalized 1.0.
    schema = {
        "schema_version": 2, "source": "wineventlog", "scope": {"ref": "zzzcode1"},
        "fields": [
            {"name": "process.name", "type": "string", "aliases": ["Image"]},
            {"name": "parent.name", "type": "string", "aliases": ["ParentImage"]},
        ],
    }
    target_query = "SELECT * FROM t WHERE `process.name` = 'x' AND `parent.name` = 'y'"
    ws = _ws(tmp_path, [
        _rec("D-0001", "kappa lambda mu nu xi", target_query, "sql", "sql", "wineventlog"),
        _rec("D-0002", "kappa lambda mu nu xi omicron pi rho sigma tau upsilon phi chi psi omega alpha beta gamma delta",
             "SELECT * FROM other1 WHERE unrelatedfield = 'z'", "sql", "sql", "other1"),
        _rec("D-0003", "kappa lambda mu", "SELECT * FROM other2 WHERE unrelatedfield2 = 'z'",
             "sql", "sql", "other2"),
        _rec("D-0004", "zzzzznothingshared",
             "SELECT * FROM other4 WHERE `Image` = 'w' AND `extra.field` = 'v'", "sql", "sql", "zzzcode1"),
        _rec("D-9000", "noise", "SELECT * FROM t WHERE somefield = 'n'", "sql", "sql", "other3"),
    ], schema=schema)

    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=10, similarity_mode="bm25")
    by_id = {c["detection_id"]: c for c in result["candidates"]}

    # Confirm the fixture actually produces the intended divergence before
    # trusting the order assertion below -- computed from the same
    # bm25_score/field_score the real run already exposes, not hardcoded.
    top_bm25 = max(c["bm25_score"] for c in by_id.values() if c["bm25_score"] is not None)

    def normalized_sum(c):
        return (c["bm25_score"] or 0.0) / top_bm25 + (c["field_score"] or 0.0)

    assert normalized_sum(by_id["D-0002"]) > normalized_sum(by_id["D-0004"])  # normalized-sum would pick D-0002
    assert by_id["D-0004"]["bm25_score"] < by_id["D-0002"]["bm25_score"]  # D-0004 is NOT the strongest bm25 hit

    # The actual (RRF, k=60) implementation picks D-0004 instead.
    assert result["candidates"][0]["detection_id"] == "D-0004"


def test_fusion_uses_k_60_specifically(tmp_path):
    # `k=1` and `k=100000` both currently
    # leave the suite green, because no test asserts an outcome that depends
    # on the SPECIFIC value 60. D-0003 (bm25 rank 2, field rank 6 -- five
    # filler records with a stronger field match sit above it) beats D-0002
    # (bm25 rank 1, no field match at all) only because k=60 is small enough
    # for D-0003's two-list presence to outweigh D-0002's better single rank.
    # At k=1, rank position dominates far more sharply and D-0002 would win
    # instead (verified by hand: fused(D-0002)=1/(1+1)=0.5 vs
    # fused(D-0003)=1/(1+2)+1/(1+6)~=0.476 at k=1, but
    # fused(D-0002)=1/61~=0.0164 vs fused(D-0003)=1/62+1/66~=0.0313 at k=60).
    schema = {
        "schema_version": 2, "source": "wineventlog", "scope": {"ref": "zzzcode1"},
        "fields": [
            {"name": "process.name", "type": "string", "aliases": ["Image"]},
            {"name": "parent.name", "type": "string", "aliases": ["ParentImage"]},
        ],
    }
    target_query = "SELECT * FROM t WHERE `process.name` = 'x' AND `parent.name` = 'y'"
    filler_sigma = """
detection:
  selection:
    Image: 'x{i}'
    ParentImage: 'y{i}'
  condition: selection
"""
    records = [
        _rec("D-0001", "kappa lambda mu nu xi", target_query, "sql", "sql", "wineventlog"),
        _rec("D-0002",
             "kappa lambda mu nu xi kappa lambda mu nu xi kappa lambda mu nu xi",
             "SELECT * FROM other1 WHERE unrelatedfield = 'z'", "sql", "sql", "other1"),
        _rec("D-0003", "kappa lambda",
             "SELECT * FROM other4 WHERE `Image` = 'w' AND `extra.field` = 'v'", "sql", "sql", "zzzcode1"),
    ]
    for i in range(1, 6):
        records.append(_rec(
            f"D-500{i}", f"filler{i}", filler_sigma.format(i=i), "", "sigma", "zzzcode1",
            platform="linux", mitre=[],
        ))
    ws = _ws(tmp_path, records, schema=schema)

    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=1, similarity_mode="bm25")
    assert result["candidates"][0]["detection_id"] == "D-0003"


def test_the_field_pass_full_depth_is_one_sided_with_bm25(tmp_path):
    # the field pass's full-depth retrieval
    # carries the same `1/(60+1)` tie flaw the BM25
    # side's correction was accepted for, but reverting ONLY the field side
    # back to `top_k=top_k` (leaving the BM25 side at `pool_size`) reddens
    # nothing today -- a one-sided guard. Same shape as
    # `test_fusion_uses_k_60_specifically` (D-0003 needs its field-rank-6
    # match to beat D-0002's bm25-rank-1), but this test exists specifically
    # to catch the field-only truncation regression, independent of any `k`
    # value change.
    schema = {
        "schema_version": 2, "source": "wineventlog", "scope": {"ref": "zzzcode1"},
        "fields": [
            {"name": "process.name", "type": "string", "aliases": ["Image"]},
            {"name": "parent.name", "type": "string", "aliases": ["ParentImage"]},
        ],
    }
    target_query = "SELECT * FROM t WHERE `process.name` = 'x' AND `parent.name` = 'y'"
    filler_sigma = """
detection:
  selection:
    Image: 'x{i}'
    ParentImage: 'y{i}'
  condition: selection
"""
    records = [
        _rec("D-0001", "kappa lambda mu nu xi", target_query, "sql", "sql", "wineventlog"),
        _rec("D-0002",
             "kappa lambda mu nu xi kappa lambda mu nu xi kappa lambda mu nu xi",
             "SELECT * FROM other1 WHERE unrelatedfield = 'z'", "sql", "sql", "other1"),
        _rec("D-0003", "kappa lambda",
             "SELECT * FROM other4 WHERE `Image` = 'w' AND `extra.field` = 'v'", "sql", "sql", "zzzcode1"),
    ]
    for i in range(1, 6):
        records.append(_rec(
            f"D-500{i}", f"filler{i}", filler_sigma.format(i=i), "", "sigma", "zzzcode1",
            platform="linux", mitre=[],
        ))
    ws = _ws(tmp_path, records, schema=schema)

    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, top_k=1, similarity_mode="bm25")
    assert result["candidates"][0]["detection_id"] == "D-0003"


def test_bm25_fallback_reports_field_matching_too(tmp_path):
    # `field_matching` is unguarded on the
    # `bm25_fallback` return -- the agent branch and the final shared return
    # (serving both `bm25` and a successful `llm` rerank) already had a
    # covering assertion; this branch (an LLM outage/malformed response) did
    # not.
    ws = _ws(tmp_path, [
        _rec("D-0001", "a", SIGMA, "", "sigma", "wineventlog"),
        _rec("D-0002", "b", SQL, "sql", "sql", "wineventlog"),
    ], schema=SCHEMA)
    fake = _FakeAnthropicClient("not valid json")
    result = RuleSimilarityAgent().run(
        detection_id="D-0001", workspace=ws, similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "bm25_fallback"
    assert result["field_matching"] == "schema"


def test_llm_prompt_bounds_the_candidate_query_egress_to_200_chars():
    # removing the `[:200]` bound on the
    # candidate-query prompt fallback left the whole suite green, and the
    # docs assert this bound is real -- it has to be.
    long_query = "x" * 250
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 0.0, "snippet": "",
        "reasoning": "", "bm25_score": None, "field_score": 1.0,
        "shared_fields": ["process.name"], "found_by": ["fields"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.6}]')
    RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": SIGMA}, [candidate], fake,
        {"D-0002": {"query": long_query}})
    prompt = fake.calls[0]["messages"][0]["content"]
    assert ("x" * 200) in prompt
    assert ("x" * 201) not in prompt


def test_llm_prompt_bounds_the_target_query_egress_to_500_chars():
    # the
    # target-query 500-char bound in _JUDGE_PROMPT (rule_similarity.py:359)
    # had no test pinning the literal number,
    # while CLAUDE.md and docs/cli-reference.md now assert it as a real
    # guarantee. A declared constraint with no test is indistinguishable from
    # an undeclared one. Mirrors the candidate-query 200-char test above:
    # this one is on the TARGET side of the prompt, not a candidate's.
    long_query = "y" * 600
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 0.5, "snippet": "some snippet",
        "reasoning": "", "bm25_score": 0.5, "field_score": None,
        "shared_fields": [], "found_by": ["bm25"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.6}]')
    RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": long_query}, [candidate], fake, {})
    prompt = fake.calls[0]["messages"][0]["content"]
    assert ("y" * 500) in prompt
    assert ("y" * 501) not in prompt


def test_llm_prompt_sigma_target_projects_logic_not_raw_boilerplate_at_500_chars():
    # I-1 (final whole-branch review): the target's raw query slice was
    # `str(target_record.get("query", ""))[:500]` -- for a real Sigma rule,
    # description/references/author routinely push `detection:` past byte
    # 500 (measured: 72% of real rules have no logic at all in the first 500
    # chars), so the judge saw pure boilerplate and never the actual
    # selectors. Wrapping with `record_query_logic` (logsource+detection
    # only, see adef/core/corpus_text.py) fixes this at the source. This
    # target's `detection:` block starts at byte 576 of the raw file -- well
    # past the 500-char raw slice -- so a fix that merely widened the bound,
    # rather than projecting first, would still fail this.
    target_sigma = (
        "title: Test Rule\n"
        "description: >\n"
        "    Filler filler filler filler filler filler filler filler filler filler.\n"
        "    Filler filler filler filler filler filler filler filler filler filler.\n"
        "    Filler filler filler filler filler filler filler filler filler filler.\n"
        "    Filler filler filler filler filler filler filler filler filler filler.\n"
        "    Filler filler filler filler filler filler filler filler filler filler.\n"
        "references:\n"
        "    - https://example.com/ref1\n"
        "    - https://example.com/ref2\n"
        "author: AuthorMarkerBoilerplate\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        "        Image|endswith: '\\fodhelper.exe'\n"
        "    condition: selection\n"
        "level: high\n"
    )
    assert target_sigma.index("detection:") > 500  # confirm the fixture actually forces the case
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 0.5, "snippet": "some snippet",
        "reasoning": "", "bm25_score": 0.5, "field_score": None,
        "shared_fields": [], "found_by": ["bm25"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.6}]')
    RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": target_sigma, "format": "sigma"},
        [candidate], fake, {})
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "fodhelper.exe" in prompt
    assert "AuthorMarkerBoilerplate" not in prompt


def test_llm_prompt_sigma_candidate_fallback_projects_logic_not_raw_boilerplate_at_200_chars():
    # I-1, candidate side: the field-matched-candidate fallback took
    # `str(records[...].get("query") or "")[:200]` -- the same
    # raw-boilerplate problem as the target side, just at the 200-char bound.
    # This candidate's `detection:` block starts at byte 242 of the raw
    # file -- past the 200-char raw slice.
    candidate_sigma = (
        "title: Candidate Rule\n"
        "description: >\n"
        "    Padding padding padding padding padding padding padding padding padding.\n"
        "    Padding padding padding padding padding padding padding.\n"
        "author: CandidateAuthorBoilerplate\n"
        "logsource:\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        "        Image|endswith: '\\globalmarkerabc.exe'\n"
        "    condition: selection\n"
        "level: high\n"
    )
    assert candidate_sigma.index("detection:") > 200  # confirm the fixture forces the case
    candidate = {
        "detection_id": "D-0002", "title": "b", "score": 0.0, "snippet": "",
        "reasoning": "", "bm25_score": None, "field_score": 1.0,
        "shared_fields": ["process.name"], "found_by": ["fields"],
    }
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.6}]')
    RuleSimilarityAgent()._rerank_with_llm(
        {"title": "a", "mitre": ["T1218.005"], "query": "irrelevant"}, [candidate], fake,
        {"D-0002": {"query": candidate_sigma, "format": "sigma"}})
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "globalmarkerabc.exe" in prompt
    assert "CandidateAuthorBoilerplate" not in prompt


def test_agent_mode_cli_shows_why_a_field_only_candidate_is_listed(tmp_path):
    # A field-only match has no BM25 score; the CLI must show its shared
    # fields rather than a placeholder `score=0.000` that reads as "no match".
    from click.testing import CliRunner

    from adef.cli import cli

    ws = _ws(tmp_path, [
        _rec("D-0001", "alpha widget zzzzz", "detection:\n  s:\n    Image: 'a.exe'\n  condition: s\n",
             "", "sigma", "srcalpha", platform="windows", mitre=[]),
        _rec("D-0002", "beta gadget yyyyy", "SELECT * FROM t WHERE procpath = 'b'",
             "sql", "sql", "srcbeta", platform="linux", mitre=[]),
        _rec("D-9001", "noise record one", "SELECT * FROM t WHERE noisefield1 = 'x'",
             "sql", "sql", "other1", platform="macos", mitre=[]),
    ], schema=[
        {"schema_version": 2, "source": "srcalpha",
         "fields": [{"name": "process.name", "type": "string", "aliases": ["Image"]}]},
        {"schema_version": 2, "source": "srcbeta",
         "fields": [{"name": "process.name", "type": "string", "aliases": ["procpath"]}]},
    ])
    result = CliRunner().invoke(
        cli, ["detection", "refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"])
    assert result.exit_code == 0, result.output
    header = next(line for line in result.output.splitlines() if "D-0002" in line)
    assert "score=" not in header
    assert "shared fields" in result.output and "process.name" in result.output
    assert "shared fields (field_score=0.398): process.name" in result.output


# --- The field pass only fuses when canonicalization happened (observed in a
# trial run). Without a schema it can only compare literal field
# names, i.e. only within one language — BM25 already covers that through
# shared tokens — and in a mixed corpus a common Sigma field isn't rare
# enough to be gated, so same-language rules scored 1.0 and pushed a real
# cross-language twin that BM25 HAD found out of the shortlist.

_PARENT = "detection:\n  s:\n    ParentImage|endswith: '\\\\{}.exe'\n  condition: s\n"


def _trial_ws(tmp_path):
    recs = [_rec("D-0001", "Bypass UAC via Fodhelper", _PARENT.format("fodhelper"), "", "sigma", "process_creation")]
    # six more Sigma rules reading the same single field, about other processes
    recs += [_rec(f"D-00{i:02d}", f"Suspicious {p} parent", _PARENT.format(p), "", "sigma", "process_creation")
             for i, p in enumerate(["mshta", "wscript", "cscript", "rundll32", "regsvr32", "winword"], start=2)]
    # the cross-language twin: shares the process name, no field names
    recs.append(_rec("D-0008", "FodHelper UAC Bypass",
                     "| tstats count from datamodel=Endpoint.Processes "
                     "where Processes.parent_process_name=fodhelper.exe by Processes.dest",
                     "spl", "splunk-escu", "Sysmon EventID 1"))
    # filler so ParentImage is in 7 of 15 rules — above the ubiquitous floor
    recs += [_rec(f"D-00{i:02d}", f"filler {i}", f"index=x EventCode={i}", "spl", "spl", "x")
             for i in range(9, 16)]
    return _ws(tmp_path, recs)


def test_without_a_schema_the_field_pass_does_not_crowd_out_a_bm25_twin(tmp_path):
    ws = _trial_ws(tmp_path)
    res = RuleSimilarityAgent().run(detection_id="D-0001", workspace=ws, top_k=5,
                                    similarity_mode="bm25")
    assert res["field_matching"] == "unmatched"
    ids = [c["detection_id"] for c in res["candidates"]]
    assert "D-0008" in ids, ids
    assert all("fields" not in c["found_by"] for c in res["candidates"])


def test_a_schema_without_aliases_is_still_literal_and_is_not_fused(tmp_path):
    ws = _trial_ws(tmp_path)
    (ws / "schema").mkdir()
    (ws / "schema" / "process_creation.yml").write_text(yaml.safe_dump({
        "schema_version": 2, "source": "process_creation",
        "fields": [{"name": "ParentImage", "type": "string"}],
    }), encoding="utf-8")
    res = RuleSimilarityAgent().run(detection_id="D-0001", workspace=ws, top_k=5,
                                    similarity_mode="bm25")
    assert res["field_matching"] == "declared_no_aliases"
    assert "D-0008" in [c["detection_id"] for c in res["candidates"]]
    assert all("fields" not in c["found_by"] for c in res["candidates"])


def test_the_cli_shortlist_is_numbered_and_labels_the_bm25_score(tmp_path, monkeypatch):
    # The list is in fused order; a bare `score=` (the BM25 value) read as if
    # the list were out of order. Number it and name the score.
    from click.testing import CliRunner

    from adef.commands.detection import detection

    ws = _trial_ws(tmp_path)
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    result = CliRunner().invoke(detection, ["refine", "D-0001", "--similarity-mode", "agent"])
    assert result.exit_code == 0, result.output
    assert "candidate #1" in result.output and "candidate #2" in result.output
    assert "(bm25=" in result.output and "(score=" not in result.output
