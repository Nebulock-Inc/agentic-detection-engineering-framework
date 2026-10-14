# tests/test_rule_similarity_agent.py
import math
from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord, NoCatalogRecordError
from adef.core.journal import Journal
from adef.agents.rule_similarity import RuleSimilarityAgent, _llm_available


def _make_record(rid: str, title: str, query: str, mitre: list[str]) -> CatalogRecord:
    return CatalogRecord(
        id=rid, title=title, rule_ref=f"rules/{rid}.yml", original_path=f"/tmp/{rid}.yml",
        platform="windows", kind="atomic", engine="sigma", format="sigma",
        query=query, mitre=mitre,
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat = Catalog(ws)
    journal = Journal(ws / "journals")
    records = [
        _make_record("D-0001", "Suspicious mshta child process", "process.name:mshta.exe",
                     ["T1218.005"]),
        _make_record("D-0002", "mshta.exe spawning a child process", "process.name:mshta.exe",
                     ["T1218.005"]),
        _make_record("D-0003", "AWS root console login", "event.name:ConsoleLogin",
                     ["T1078.004"]),
    ]
    for rec in records:
        cat.write_raw(ws / "catalog" / f"{rec.id}.yml", rec.to_yaml_dict())
        journal.create(detection_id=rec.id, title=rec.title)
    cat.rebuild_index()
    return ws


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
            # `type="text"` mirrors the real SDK's TextBlock — the agent selects
            # the first text block rather than trusting content[0] to be one.
            block = type(
                "Block", (), {"type": "text", "text": self._outer._response_text}
            )()
            return type("Response", (), {"content": [block]})()

    @property
    def messages(self):
        return self._Messages(self)


# --- BM25-only behavior (mode="bm25"), unaffected by LLM availability ---

def test_bm25_mode_finds_the_near_duplicate_and_excludes_self(workspace: Path):
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=5,
                                        similarity_mode="bm25")
    assert result["mode_used"] == "bm25"
    ids = [c["detection_id"] for c in result["candidates"]]
    assert "D-0001" not in ids
    assert ids[0] == "D-0002"
    assert result["candidates"][0]["score"] > 0


def test_bm25_mode_never_imports_anthropic(workspace: Path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")  # even if "available", bm25 mode ignores it
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        similarity_mode="bm25")
    assert result["mode_used"] == "bm25"


def test_unknown_detection_id_raises(workspace: Path):
    with pytest.raises(ValueError, match="D-9999"):
        RuleSimilarityAgent().run(detection_id="D-9999", workspace=workspace, similarity_mode="bm25")


def test_unsupported_similarity_mode_raises(workspace: Path):
    # CodeRabbit: a direct caller (MCP tool, wrapper, programmatic use)
    # bypasses the CLI's click.Choice(["auto", "bm25", "llm"]) validation —
    # the agent itself must reject an unsupported mode rather than silently
    # falling through to BM25 candidates while reporting the bad value as
    # mode_used.
    with pytest.raises(ValueError, match="not_a_real_mode"):
        RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                   similarity_mode="not_a_real_mode")


# --- Mode selection ---

def test_llm_available_false_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert _llm_available() is False


def test_llm_available_false_without_package(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    monkeypatch.setattr("adef.agents.rule_similarity._anthropic_importable", lambda: False)
    assert _llm_available() is False


def test_explicit_llm_mode_without_availability_raises(workspace: Path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, similarity_mode="llm")


def test_auto_mode_falls_back_to_bm25_without_llm(workspace: Path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        similarity_mode="auto")
    assert result["mode_used"] == "bm25"


def test_bm25_mode_ignores_an_injected_llm_client(workspace: Path):
    """`bm25` is a promise, not a preference: an available client must not be
    consulted, or "fully deterministic, never bills" stops being true."""
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.99}]')
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        similarity_mode="bm25", llm_client=fake)
    assert result["mode_used"] == "bm25"
    assert fake.calls == []  # no LLM call attempted


def test_auto_mode_resolves_to_llm_when_a_client_is_injected(workspace: Path, monkeypatch):
    """The branch that decides whether a billed network call happens: an
    injected client counts as "LLM available" even with no API key in the env."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    fake = _FakeAnthropicClient(
        '[{"detection_id": "D-0002", "confidence": 0.91, "reasoning": "same predicate"}]'
    )
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="auto", llm_client=fake)
    assert result["mode_used"] == "llm"
    assert len(fake.calls) == 1


# --- LLM rerank path (client injected, no network) ---

def test_llm_mode_reranks_using_injected_client(workspace: Path):
    fake = _FakeAnthropicClient(
        '[{"detection_id": "D-0002", "confidence": 0.97, "reasoning": "same predicate"}]'
    )
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "llm"
    assert result["candidates"][0]["detection_id"] == "D-0002"
    assert result["candidates"][0]["score"] == 0.97
    assert result["candidates"][0]["reasoning"] == "same predicate"
    assert len(fake.calls) == 1


def test_llm_prompt_joins_a_scalar_mitre_as_one_technique(workspace: Path):
    path = workspace / "catalog" / "D-0001.yml"
    path.write_text(path.read_text(encoding="utf-8").replace(
        "mitre:\n- T1218.005\n", "mitre: T1218.005\n"), encoding="utf-8")
    assert "mitre: T1218.005\n" in path.read_text(encoding="utf-8")
    fake = _FakeAnthropicClient(
        '[{"detection_id": "D-0002", "confidence": 0.9, "reasoning": "r"}]'
    )
    RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                              similarity_mode="llm", llm_client=fake)
    prompt = fake.calls[0]["messages"][0]["content"]
    assert "T1218.005" in prompt and "T, 1, 2" not in prompt


def test_llm_mode_falls_back_on_malformed_response(workspace: Path):
    fake = _FakeAnthropicClient("not valid json")
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "bm25_fallback"
    assert "llm_error" in result
    assert result["candidates"]  # BM25 shortlist still returned, not empty


def test_llm_mode_falls_back_when_response_omits_a_candidate(workspace: Path):
    # CodeRabbit: an omitted candidate would otherwise silently keep its
    # raw BM25 score while judged siblings carry an LLM confidence — the two
    # scales aren't comparable (BM25 scores aren't bounded to [0,1]), so the
    # response must cover every shortlisted candidate exactly once or fall
    # back entirely, same as malformed JSON.
    fake = _FakeAnthropicClient("[]")
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "bm25_fallback"
    assert "llm_error" in result


def test_llm_mode_falls_back_on_duplicate_detection_id(workspace: Path):
    fake = _FakeAnthropicClient(
        '[{"detection_id": "D-0002", "confidence": 0.9},'
        ' {"detection_id": "D-0002", "confidence": 0.5}]'
    )
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "bm25_fallback"
    assert "llm_error" in result


def test_llm_mode_falls_back_on_unknown_detection_id(workspace: Path):
    fake = _FakeAnthropicClient('[{"detection_id": "D-9999", "confidence": 0.9}]')
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "bm25_fallback"
    assert "llm_error" in result


def test_llm_mode_clamps_non_finite_confidence_and_stringifies_reasoning(workspace: Path):
    # CodeRabbit: json.loads accepts literal NaN/Infinity, so a
    # malformed-but-parseable LLM response could reach list.sort() with a
    # non-finite score (corrupting ranking) or a non-string reasoning value.
    # A NaN confidence falls back to the BM25 score (not itself clamped to
    # [0,1] — that's how the underlying retrieval score is scaled).
    bm25_result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                             similarity_mode="bm25")
    bm25_score = bm25_result["candidates"][0]["score"]

    fake = _FakeAnthropicClient(
        '[{"detection_id": "D-0002", "confidence": NaN, "reasoning": 42}]'
    )
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "llm"
    score = result["candidates"][0]["score"]
    assert math.isfinite(score)
    assert score == bm25_score  # NaN rejected -> fell back to the BM25 score
    assert result["candidates"][0]["reasoning"] == "42"


# --- Wrapper dispatch (native by default; ADEF_WRAPPER_RULE_SIMILARITY overrides) ---

def test_wrapper_runs_native_agent_when_binding_unset(workspace: Path, monkeypatch):
    monkeypatch.delenv("ADEF_WRAPPER_RULE_SIMILARITY", raising=False)
    from adef.agents.wrappers.rule_similarity import RuleSimilarityWrapper

    result = RuleSimilarityWrapper().run(detection_id="D-0001", workspace=workspace,
                                          similarity_mode="bm25")
    assert result["detection_id"] == "D-0001"
    assert result["result"]["mode_used"] == "bm25"


def test_wrapper_raises_when_binding_set_but_unimportable(workspace: Path, monkeypatch):
    monkeypatch.setenv("ADEF_WRAPPER_RULE_SIMILARITY", "not_a_real_module:NotARealClass")
    from adef.agents.wrappers import WrapperUnavailable
    from adef.agents.wrappers.rule_similarity import RuleSimilarityWrapper

    with pytest.raises(WrapperUnavailable):
        RuleSimilarityWrapper().run(detection_id="D-0001", workspace=workspace,
                                     similarity_mode="bm25")


def test_wrapper_propagates_no_catalog_record(workspace: Path, monkeypatch):
    """A journal-only detection is NOT "wrapper unavailable" — the wrapper must
    let the distinct type through so refine_chain can say what's actually true."""
    monkeypatch.delenv("ADEF_WRAPPER_RULE_SIMILARITY", raising=False)
    from adef.agents.wrappers import WrapperUnavailable
    from adef.agents.wrappers.rule_similarity import RuleSimilarityWrapper

    with pytest.raises(NoCatalogRecordError, match="D-9999"):
        RuleSimilarityWrapper().run(detection_id="D-9999", workspace=workspace,
                                     similarity_mode="bm25")
    assert not issubclass(NoCatalogRecordError, WrapperUnavailable)


def test_wrapper_forwards_non_native_ctx_to_configured_upstream(workspace: Path, monkeypatch):
    # CodeRabbit: the configured-upstream branch must strip only the
    # native-only kwargs (workspace, similarity_mode) the chain injects, not
    # ALL caller context — a configured class may rely on other kwargs.
    import sys
    import types

    captured: dict = {}

    class _FakeUpstream:
        def run(self, **kwargs):
            captured.update(kwargs)
            return {"ok": True}

    fake_module = types.ModuleType("fake_upstream_rule_similarity")
    fake_module.FakeUpstream = _FakeUpstream
    monkeypatch.setitem(sys.modules, "fake_upstream_rule_similarity", fake_module)
    monkeypatch.setenv("ADEF_WRAPPER_RULE_SIMILARITY", "fake_upstream_rule_similarity:FakeUpstream")

    from adef.agents.wrappers.rule_similarity import RuleSimilarityWrapper

    RuleSimilarityWrapper().run(detection_id="D-0001", workspace=workspace,
                                 similarity_mode="bm25", extra_context="keep-me")

    assert captured == {"detection_id": "D-0001", "extra_context": "keep-me"}


# --- Agent mode (hand back everything the caller needs to judge) ---

def test_agent_mode_returns_candidates_with_judgment_fields(workspace: Path):
    # `agent` mode exists so the CALLER can judge logic similarity. A snippet is
    # not enough for that — the candidate's actual query text is. This is the
    # whole reason the mode is distinct from `bm25`.
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        top_k=5, similarity_mode="agent")
    assert result["mode_used"] == "agent"
    top = result["candidates"][0]
    assert top["detection_id"] == "D-0002"
    assert top["query"] == "process.name:mshta.exe"     # full text, not a snippet
    assert top["mitre"] == ["T1218.005"]
    assert top["platform"] == "windows"
    assert "data_source" in top


def test_agent_mode_returns_the_target_side_too(workspace: Path):
    # Judging similarity takes two sides. Returning only the candidates' queries
    # forces the caller into another round trip to read its own target — which
    # defeats the point of handing back the shortlist in the first place.
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        top_k=5, similarity_mode="agent")
    assert result["target"]["query"] == "process.name:mshta.exe"
    assert result["target"]["title"] == "Suspicious mshta child process"
    assert result["target"]["mitre"] == ["T1218.005"]
    assert result["target"]["platform"] == "windows"


_LONG_SIGMA = """title: Suspicious mshta child {n}
description: {pad}
references:
    - https://example.invalid/mshta-writeup
author: Carol Authorname
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\mshta.exe'
    condition: selection
"""


def test_agent_mode_hands_back_sigma_logic_not_the_raw_file(tmp_path: Path):
    # The detection block starts past char 300 of the stored file, so a
    # 300-char journal render of the raw query never reaches it.
    ws = tmp_path / "ws"
    (ws / "catalog").mkdir(parents=True)
    (ws / "journals").mkdir(parents=True)
    cat = Catalog(ws)
    pad = "Detects mshta spawning from an office parent process. " * 5
    for rid in ("D-0001", "D-0002"):
        query = _LONG_SIGMA.format(n=rid, pad=pad)
        assert query.index("detection:") > 300
        rec = _make_record(rid, f"Suspicious mshta child {rid}", query, ["T1218.005"])
        cat.write_raw(ws / "catalog" / f"{rid}.yml", rec.to_yaml_dict())
    cat.rebuild_index()
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=ws,
                                        top_k=5, similarity_mode="agent")
    candidate = next(c for c in result["candidates"] if c["detection_id"] == "D-0002")
    for side in (result["target"], candidate):
        assert "mshta.exe" in side["query"] and "Image|endswith" in side["query"], side
        assert "Carol Authorname" not in side["query"], side


def test_agent_mode_never_calls_an_injected_llm_client(workspace: Path):
    # `agent` is a promise, not a preference: the caller does the ranking, so an
    # available client must not be consulted or "no network call" stops being true.
    fake = _FakeAnthropicClient('[{"detection_id": "D-0002", "confidence": 0.99}]')
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        similarity_mode="agent", llm_client=fake)
    assert result["mode_used"] == "agent"
    assert fake.calls == []


def test_agent_mode_ignores_an_available_api_key(workspace: Path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        similarity_mode="agent")
    assert result["mode_used"] == "agent"


def test_agent_mode_excludes_self_like_every_other_mode(workspace: Path):
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        top_k=5, similarity_mode="agent")
    assert "D-0001" not in [c["detection_id"] for c in result["candidates"]]


def test_bm25_mode_stays_lean(workspace: Path):
    # The enriched payload belongs to `agent` only — `bm25` keeps its existing
    # shape so nothing downstream of it has to change.
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        top_k=1, similarity_mode="bm25")
    assert "query" not in result["candidates"][0]


# --- Read-path discipline + duplicate-id determinism (final review items 2, 3) ---

def test_bare_workspace_creates_no_catalog_dir(tmp_path: Path):
    # Global constraint: `build_corpus` never creates directories — it's a
    # read path. `RuleSimilarityAgent.run` constructed `Catalog(ws)`
    # unconditionally, and `Catalog.__init__` mkdirs `catalog/`, creating the
    # directory on a bare workspace even though the call is read-only.
    ws = tmp_path / "bare-ws"
    (ws / "journals").mkdir(parents=True)
    Journal(ws / "journals").create(detection_id="D-0001", title="draft only")
    with pytest.raises(NoCatalogRecordError):
        RuleSimilarityAgent().run(detection_id="D-0001", workspace=ws, similarity_mode="bm25")
    assert not (ws / "catalog").exists()


def test_duplicate_detection_id_target_resolves_first_wins(workspace: Path):
    # `corpus.py:102` resolves a duplicate id first-wins (`setdefault` over
    # path-sorted records) so `build_corpus`'s index and Similarity's target
    # lookup agree on which record is "the" D-0001. `rule_similarity.py` built
    # its own last-wins `records` map, so for a duplicated id the target
    # record Similarity judged could differ from the one the index actually
    # scored — this branch's own bug class (two code paths disagreeing about
    # one catalog) surviving in miniature.
    dup_dir = workspace / "catalog" / "linux"
    dup_dir.mkdir()
    Catalog(workspace).write_raw(
        dup_dir / "D-0001.yml",
        _make_record("D-0001", "DUPLICATE-SHOULD-NOT-WIN", "process.name:evil.exe",
                     ["T1218.005"]).to_yaml_dict(),
    )
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace,
                                        similarity_mode="agent")
    assert result["target"]["title"] == "Suspicious mshta child process"
