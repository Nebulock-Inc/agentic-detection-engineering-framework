# Similarity Mode: Agent Inversion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the calling agent — not ADEF's private LLM call — the default place semantic similarity judgment happens, without removing ADEF's ability to rank unattended.

**Architecture:** Add a fourth `similarity_mode` value, `agent`, that returns the BM25 shortlist enriched with the fields needed to judge logic (the full query text, MITRE, platform, data source) and ranks nothing. Then set defaults by *entry point* rather than by sniffing the environment: the CLI defaults to `bm25` (deterministic, no surprise billing, correct for a human at a terminal), and the MCP tool defaults to `agent` (its caller is an agent by definition). `auto` and `llm` remain available for anyone who explicitly asks.

**Tech Stack:** Python 3.10+, Click, FastMCP. No new runtime dependencies.

**Spec:** Shortcut stories [10185](https://app.shortcut.com/nebulock/story/10185) (this work) and [10188](https://app.shortcut.com/nebulock/story/10188) (the retrieval-recall gap, explicitly NOT in scope here). Design context: `internal-docs/plans/2026-09-21-vendor-capture-design.md` is unrelated; the governing decision is ISA's 2026-09-18 entry on the native Refine chain.

## Global Constraints

- **`from __future__ import annotations`** at the top of every module touched; Python 3.10+ syntax.
- **No new runtime dependencies.**
- **No vendor API connectors** anywhere in `adef/` — CI-enforced by `tests/test_no_vendor_connectors.py`. `agent` mode must make no network call of any kind.
- **No write path may contain `detections/`** — CI-enforced by `tests/test_schema_parity.py`.
- **`bm25` remains the only mode guaranteed to make no network call** — and after this plan, `agent` joins it. Both must be provably offline.
- **Do not remove the `llm` path.** Headless and CI use has no agent present; deleting it removes ADEF's only unattended semantic capability. This plan changes which mode is *default*, never which modes *exist*.
- **Defaults are set by entry point, never by environment detection.** Do not add harness sniffing (`CLAUDECODE` or similar) — that fragility is tracked separately in story 10182.
- **`_VALID_SIMILARITY_MODES` is the single source of truth** for the mode set; the Click `Choice` and any MCP validation must derive from it or stay exactly in sync with it.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `adef/agents/rule_similarity.py` | modify | Add `agent` to the valid mode set; short-circuit before the LLM rerank and return enriched candidates. |
| `adef/commands/detection.py` | modify | Add `agent` to the Click `Choice`; flip the default to `bm25`; rewrite the help text. |
| `adef/mcp/tools/agent_tools.py` | modify | Thread `similarity_mode` through the `refine_chain` tool, defaulting to `agent`. |
| `docs/cli-reference.md` | modify | Document the four modes and the new CLI default. |
| `CLAUDE.md` | modify | Correct "The Refine Chain" section: new default, new mode, unchanged egress description for `llm`/`auto`. |
| `docs/methodology.md` | modify | Same correction, one paragraph. |
| `tests/test_rule_similarity_agent.py` | modify | Agent-mode behavior and offline guarantee. |
| `tests/test_refine_chain.py` | modify | MCP tool default and pass-through. |

`agent` mode is a short-circuit inside the existing agent rather than a new module: it reuses the same retrieval, and the only difference is what it returns and what it declines to do. A separate module would duplicate the BM25 path for no gain.

---

## Task 1: `agent` mode in the similarity agent

**Files:**
- Modify: `adef/agents/rule_similarity.py`
- Test: `tests/test_rule_similarity_agent.py`

**Interfaces:**
- Consumes: the existing `RuleSimilarityAgent.run(detection_id, workspace, top_k, similarity_mode, llm_client, **ctx)` signature — unchanged.
- Produces: `similarity_mode="agent"` returns `{"detection_id": str, "mode_used": "agent", "candidates": [...]}` where each candidate carries `detection_id`, `title`, `score`, `snippet`, `reasoning`, **plus** `query`, `mitre`, `platform`, `data_source` drawn from the candidate's catalog record. No LLM call is made under any circumstance.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_rule_similarity_agent.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_rule_similarity_agent.py -k agent -v`
Expected: FAIL — `ValueError: similarity_mode must be one of ['auto', 'bm25', 'llm'], got 'agent'`

- [ ] **Step 3: Add `agent` to the valid mode set**

In `adef/agents/rule_similarity.py`, change:

```python
_VALID_SIMILARITY_MODES = frozenset({"auto", "bm25", "llm"})
```

to:

```python
#: `agent` returns the shortlist enriched for the caller to judge and ranks
#: nothing — the caller (an assistant session) has context ADEF does not, and
#: its reasoning lands in the transcript where it can be reviewed. Like `bm25`
#: it never makes a network call.
_VALID_SIMILARITY_MODES = frozenset({"auto", "bm25", "llm", "agent"})
```

- [ ] **Step 4: Short-circuit before the rerank**

In `RuleSimilarityAgent.run`, the mode-resolution block currently reads:

```python
        resolved_mode = similarity_mode
        if resolved_mode == "auto":
            resolved_mode = "llm" if (llm_client is not None or _llm_available()) else "bm25"

        if resolved_mode == "llm":
```

Insert the `agent` branch between those two blocks, so it is reached before any LLM consideration:

```python
        resolved_mode = similarity_mode
        if resolved_mode == "auto":
            resolved_mode = "llm" if (llm_client is not None or _llm_available()) else "bm25"

        if resolved_mode == "agent":
            # Hand back everything the caller needs to judge logic similarity
            # itself — a snippet is not enough, the query text is. Deliberately
            # returns before any LLM path: `agent` guarantees no network call.
            enriched = [
                {
                    **candidate,
                    "query": str(records.get(candidate["detection_id"], {}).get("query", "")),
                    "mitre": list(records.get(candidate["detection_id"], {}).get("mitre") or []),
                    "platform": str(records.get(candidate["detection_id"], {}).get("platform", "")),
                    "data_source": str(
                        records.get(candidate["detection_id"], {}).get("data_source", "")
                    ),
                }
                for candidate in candidates
            ]
            return {
                "detection_id": detection_id,
                "mode_used": "agent",
                "candidates": enriched,
            }

        if resolved_mode == "llm":
```

`records` is already built at the top of `run()` (the `for det_id, _path, data in catalog.iter_records()` loop), so no extra catalog read is needed.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_rule_similarity_agent.py -v`
Expected: PASS — all existing tests plus the 5 new ones

- [ ] **Step 6: Run the full suite and linters**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m ruff check adef/ tests/ && .venv/bin/python -m mypy adef/`
Expected: all pass, no regressions

- [ ] **Step 7: Commit**

```bash
git add adef/agents/rule_similarity.py tests/test_rule_similarity_agent.py
git commit -m "feat(similarity): add agent mode — return the shortlist, rank nothing"
```

---

## Task 2: CLI — flip the default to `bm25`, expose `agent`

**Files:**
- Modify: `adef/commands/detection.py`
- Modify: `docs/cli-reference.md`
- Modify: `CLAUDE.md`
- Modify: `docs/methodology.md`
- Test: `tests/test_refine_chain.py`

**Interfaces:**
- Consumes: `similarity_mode="agent"` from Task 1.
- Produces: `adef detection refine` defaults to `bm25`; `--similarity-mode` accepts `{auto,bm25,llm,agent}`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_refine_chain.py`. **Note the existing conventions in that file — match them, do not invent new ones:** there is no `workspace` fixture (workspaces are built inline from `tmp_path`), the CLI group is imported as `detection_cli`, `CliRunner` is already imported, and `_rec(rid, title, query)` is an existing module-level helper.

```python
def _one_rule_workspace(tmp_path: Path, name: str) -> Path:
    """A workspace with one catalogued, journalled detection — the minimum the
    refine chain needs to run without reporting 'no catalog record'."""
    ws = tmp_path / name
    (ws / "journals").mkdir(parents=True)
    (ws / "catalog").mkdir(parents=True)
    cat = Catalog(ws)
    journal = Journal(ws / "journals")
    rec = _rec("D-0001", "mshta child process", "process.name='mshta.exe'")
    cat.write_raw(ws / "catalog" / "D-0001.yml", rec.to_yaml_dict())
    journal.create(detection_id="D-0001", title=rec.title)
    cat.rebuild_index()
    return ws


def test_refine_cli_defaults_to_bm25(tmp_path: Path, monkeypatch):
    # The agentic promise is fulfilled by an agent CALLING adef, not by adef
    # quietly calling a model on the user's behalf. Opt in to spend money and
    # egress; do not opt out. An API key in the environment must not change
    # what the CLI does by default.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
    ws = _one_rule_workspace(tmp_path, "cli-default-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli, ["refine", "D-0001", "--workspace", str(ws)]
    )
    assert result.exit_code == 0, result.output
    assert captured["similarity_mode"] == "bm25"


def test_refine_cli_accepts_agent_mode(tmp_path: Path, monkeypatch):
    ws = _one_rule_workspace(tmp_path, "cli-agent-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "agent"],
    )
    assert result.exit_code == 0, result.output
    assert captured["similarity_mode"] == "agent"


def test_refine_cli_rejects_an_unknown_mode(tmp_path: Path):
    ws = _one_rule_workspace(tmp_path, "cli-bad-mode-ws")
    result = CliRunner().invoke(
        detection_cli,
        ["refine", "D-0001", "--workspace", str(ws), "--similarity-mode", "nope"],
    )
    assert result.exit_code != 0
    assert "nope" in result.output
```

`detection.py` imports `run_refine_chain` *inside* the command body, so patching the module attribute (`adef.orchestration.refine_chain.run_refine_chain`) takes effect at call time — that is why the spy works.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_refine_chain.py -k "cli" -v`
Expected: FAIL — the default assertion fails with `'auto' != 'bm25'`, and `agent` is rejected by the `Choice`

- [ ] **Step 3: Update the Click option**

In `adef/commands/detection.py`, replace the `--similarity-mode` option block:

```python
                ["--similarity-mode"],
                type=click.Choice(["auto", "bm25", "llm"]),
                default="auto",
                help="How the Similarity refine-step ranks candidates: 'llm' reranks the "
                "BM25 shortlist with an LLM judge (requires ANTHROPIC_API_KEY + the 'llm' "
                "extra), 'bm25' stays fully deterministic, 'auto' (default) uses llm when "
                "available.",
```

with:

```python
                ["--similarity-mode"],
                type=click.Choice(["bm25", "agent", "llm", "auto"]),
                default="bm25",
                help="How the Similarity refine-step ranks candidates. 'bm25' (default) is "
                "fully deterministic and makes no network call. 'agent' returns the "
                "shortlist enriched with each candidate's query and MITRE IDs for YOU to "
                "rank — also no network call, and the mode to use from an assistant "
                "session. 'llm' reranks with an LLM judge (requires ANTHROPIC_API_KEY + "
                "the 'llm' extra) and sends detection content to the Anthropic API. "
                "'auto' picks llm when available, else bm25.",
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_refine_chain.py -v`
Expected: PASS

- [ ] **Step 5: Update `docs/cli-reference.md`**

In the `adef detection refine` entry's option table, replace the `--similarity-mode` row with:

```markdown
| `--similarity-mode` | `bm25` \| `agent` \| `llm` \| `auto` | How the Similarity step ranks. Default `bm25` — deterministic, no network call. `agent` returns the shortlist enriched with each candidate's query/MITRE/platform for the caller to rank, also with no network call. `llm` reranks with an LLM judge and **sends detection content to the Anthropic API** (requires `ANTHROPIC_API_KEY` + the `llm` extra). `auto` picks `llm` when available, else `bm25`. |
```

- [ ] **Step 6: Correct `CLAUDE.md`**

In the "The Refine Chain" section, replace the RuleSimilarity bullet's mode sentence. The current text says `auto`, the default, uses the LLM when available. Replace with:

```markdown
     optionally reranked by an LLM judge (`adef detection refine D-XXXX
     --similarity-mode {bm25,agent,llm,auto}`). **`bm25` is the default** and
     makes no network call. **`agent`** returns the shortlist enriched with each
     candidate's query, MITRE IDs, platform, and data source for the *caller* to
     rank — also no network call, and the mode to use from an assistant session,
     where the agent has context ADEF does not and its reasoning lands in the
     transcript. `llm` reranks with an LLM judge; `auto` picks `llm` when
     `ANTHROPIC_API_KEY` and the `llm` extra are both present, else `bm25`.
     **Data egress in `llm`/`auto` mode:** the target's title, MITRE IDs, and
     query (truncated to 500 chars), plus each shortlisted candidate's ID, title,
     and snippet, are sent to the Anthropic API — the snippet is built from both
     the journal body AND the catalog search text (title, MITRE IDs, platform,
     data source, format, query — see `record_search_text`), so catalog and query
     content can be disclosed too, not just journal prose. `bm25` and `agent`
     make no network call.
```

- [ ] **Step 7: Correct `docs/methodology.md`**

In the Refine section, the paragraph currently says RuleSimilarity's default `auto` mode can call the Anthropic API. Replace that clause with:

```markdown
Refine is where the rule is drafted, redrafted, and trimmed. ADEF's Refine stage automatically chains three steps, native by default (v2, 2026-09) — and deterministic by default: RuleSimilarity's default `bm25` mode makes no network call, as does its `agent` mode, which hands the shortlist to the calling assistant to rank. Only the opt-in `llm` and `auto` modes call the Anthropic API (see CLAUDE.md's "The Refine Chain" for the exact data egress).
```

- [ ] **Step 8: Run the full suite and linters**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m ruff check adef/ tests/ && .venv/bin/python -m mypy adef/`
Expected: all pass

- [ ] **Step 9: Commit**

```bash
git add adef/commands/detection.py docs/cli-reference.md CLAUDE.md docs/methodology.md tests/test_refine_chain.py
git commit -m "feat(cli): default similarity to bm25, expose agent mode"
```

---

## Task 3: MCP — thread `similarity_mode` through, defaulting to `agent`

**Files:**
- Modify: `adef/mcp/tools/agent_tools.py`
- Modify: `CLAUDE.md`
- Test: `tests/test_refine_chain.py`

**Interfaces:**
- Consumes: `similarity_mode="agent"` from Task 1.
- Produces: `refine_chain(detection_id, similarity_mode="agent", workspace=None)` MCP tool — the parameter does not exist today, so the tool currently inherits the agent's own default silently.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_refine_chain.py`:

Reuse `_one_rule_workspace` from Task 2. The existing `test_mcp_refine_chain_tool_honors_workspace_arg_over_env` in this same file already defines a `_FakeServer` **inside** the test function — follow that local-class convention rather than hoisting a module-level one, so this change stays additive.

```python
def test_mcp_refine_chain_defaults_to_agent_mode(tmp_path: Path, monkeypatch):
    # An MCP caller IS an agent by definition. Ranking internally there is
    # strictly wasteful — it pays a second model to do work the caller is
    # better positioned to do with more context. This default differs from the
    # CLI's `bm25` ON PURPOSE: the split is by entry point, which is knowable,
    # never by sniffing the environment.
    from adef.mcp.tools.agent_tools import register

    ws = _one_rule_workspace(tmp_path, "mcp-default-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)

    class _FakeServer:
        def __init__(self) -> None:
            self.tools: dict[str, object] = {}

        def tool(self):
            def deco(fn):
                self.tools[fn.__name__] = fn
                return fn

            return deco

    server = _FakeServer()
    register(server)
    server.tools["refine_chain"](detection_id="D-0001", workspace=str(ws))

    assert captured["similarity_mode"] == "agent"


def test_mcp_refine_chain_honors_an_explicit_mode(tmp_path: Path, monkeypatch):
    from adef.mcp.tools.agent_tools import register

    ws = _one_rule_workspace(tmp_path, "mcp-explicit-ws")
    captured: dict = {}

    def _spy(journal, detection_id, **context):
        captured.update(context)
        return {}

    monkeypatch.setattr("adef.orchestration.refine_chain.run_refine_chain", _spy)

    class _FakeServer:
        def __init__(self) -> None:
            self.tools: dict[str, object] = {}

        def tool(self):
            def deco(fn):
                self.tools[fn.__name__] = fn
                return fn

            return deco

    server = _FakeServer()
    register(server)
    server.tools["refine_chain"](
        detection_id="D-0001", similarity_mode="bm25", workspace=str(ws)
    )

    assert captured["similarity_mode"] == "bm25"
```

**Patch target differs from Task 2 — this is not a copy-paste of the CLI tests.** `detection.py` imports `run_refine_chain` *inside* the command body (line ~198), so patching `adef.orchestration.refine_chain.run_refine_chain` works there. `adef/mcp/tools/agent_tools.py` imports it at **module level** (line ~24), so that same patch would leave the tool holding its own already-bound reference and the spy would never fire — the test would pass vacuously while exercising the real chain.

Both MCP tests above must therefore patch the *binding in the consuming module*:

```python
    monkeypatch.setattr("adef.mcp.tools.agent_tools.run_refine_chain", _spy)
```

Use that line in place of the `adef.orchestration.refine_chain.run_refine_chain` target shown in the two MCP tests. If you find yourself unsure whether a spy is firing, assert on it directly — e.g. `assert captured, "spy never called; check the patch target"` — rather than trusting a passing assertion on an empty dict.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_refine_chain.py -k mcp -v`
Expected: FAIL — `TypeError: refine_chain() got an unexpected keyword argument 'similarity_mode'`

- [ ] **Step 3: Add the parameter**

In `adef/mcp/tools/agent_tools.py`, the tool currently reads:

```python
    def refine_chain(
        detection_id: str,
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Run the Refine chain (Similarity → Overlap → Verification) for a detection."""
        ws = Path(workspace) if workspace else None
        journals_dir = workspace_journals_dir(ws)
        journal = Journal(journals_dir)
        return cast(
            "dict[str, Any]",
            _to_dict(run_refine_chain(journal, detection_id, workspace=ws)),
        )
```

Replace with:

```python
    def refine_chain(
        detection_id: str,
        similarity_mode: str = "agent",
        workspace: Optional[str] = None,
    ) -> dict[str, Any]:
        """Run the Refine chain (Similarity → Overlap → Verification) for a detection.

        Defaults to ``agent`` similarity: you get the BM25 shortlist enriched
        with each candidate's query, MITRE IDs, platform, and data source, and
        you do the ranking. You have context ADEF does not, and your reasoning
        stays visible. Pass ``bm25`` for a deterministic ranking, or ``llm`` to
        have ADEF call the Anthropic API itself (requires ANTHROPIC_API_KEY and
        the ``llm`` extra). This default differs from the CLI's ``bm25`` because
        an MCP caller is an agent by definition.
        """
        ws = Path(workspace) if workspace else None
        journals_dir = workspace_journals_dir(ws)
        journal = Journal(journals_dir)
        return cast(
            "dict[str, Any]",
            _to_dict(
                run_refine_chain(
                    journal, detection_id, workspace=ws, similarity_mode=similarity_mode
                )
            ),
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_refine_chain.py -v`
Expected: PASS

- [ ] **Step 5: Document the MCP default in `CLAUDE.md`**

In the MCP Server section, below the `adef-mcp` code block, add:

```markdown
`refine_chain` defaults to `similarity_mode="agent"` — it returns the shortlist
enriched for *you* to rank rather than ranking internally, since an MCP caller is
an agent by definition. This deliberately differs from the CLI default (`bm25`):
the split is by entry point, not by detecting which environment you are in.
```

- [ ] **Step 6: Run the full suite and linters**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m ruff check adef/ tests/ && .venv/bin/python -m mypy adef/`
Expected: all pass

- [ ] **Step 7: Commit**

```bash
git add adef/mcp/tools/agent_tools.py CLAUDE.md tests/test_refine_chain.py
git commit -m "feat(mcp): refine_chain takes similarity_mode, defaults to agent"
```

---

## Done when

- `--similarity-mode` accepts `{bm25,agent,llm,auto}` and the CLI defaults to `bm25`.
- The MCP `refine_chain` tool accepts `similarity_mode` and defaults to `agent`.
- `agent` mode returns candidates carrying `query`, `mitre`, `platform`, and `data_source`, and provably makes no network call even with a key set and a client injected.
- `bm25` keeps its existing lean shape.
- `llm` and `auto` are unchanged and still available.
- CLAUDE.md, `docs/methodology.md`, and `docs/cli-reference.md` state the new defaults and the unchanged egress description for `llm`/`auto`.
- Full suite green, ruff clean, mypy clean, all four anti-goal guards passing.

**Explicitly not in scope:** the retrieval-recall gap (BM25 cannot surface cross-language or structurally-similar rules) is story 10188 and needs its own design pass. Nothing in this plan improves *which* candidates reach the shortlist — only what happens to them afterward. Do not attempt to fix recall here.
