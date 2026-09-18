# tests/test_rule_similarity_agent.py
from pathlib import Path

import pytest

from adef.core.catalog import Catalog, CatalogRecord
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
            block = type("Block", (), {"text": self._outer._response_text})()
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


def test_llm_mode_falls_back_on_malformed_response(workspace: Path):
    fake = _FakeAnthropicClient("not valid json")
    result = RuleSimilarityAgent().run(detection_id="D-0001", workspace=workspace, top_k=1,
                                        similarity_mode="llm", llm_client=fake)
    assert result["mode_used"] == "bm25_fallback"
    assert "llm_error" in result
    assert result["candidates"]  # BM25 shortlist still returned, not empty


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
