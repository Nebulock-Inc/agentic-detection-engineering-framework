# ADEF v0.1.0 — 31-Fact Verification Trail

> Each row points to the file, test, or command that proves the fact. Every
> cell must resolve to actual code, doc, or test on this branch.

| # | Fact | Evidence |
|---|------|----------|
| 1 | ADEF ships as the `adef` Python package, structurally distinct from athf and any upstream rule package. | `pyproject.toml` `name = "agentic-detection-engineering-framework"`, package `adef/`. |
| 2 | The lifecycle pattern is FORGE: Find → Observe → Refine → Govern → Evolve. | `adef/core/journal.py` constant `FORGE_STAGES = ("find", "observe", "refine", "govern", "evolve")`; `tests/test_journal_core.py::test_forge_stages_order`. |
| 3 | The methodology doc names FORGE and explains each of the five stages with examples. | `docs/methodology.md` — five `### Stage` sections, each with an "Example." paragraph. |
| 4 | The detection markdown template has explicit FORGE-shaped sections. | `adef/data/templates/DETECTION_FORGE.md`; `tests/test_template_and_init.py::test_template_has_all_forge_headings`. |
| 5 | ADEF defines 5 maturity levels: L0 Ad-hoc, L1 Documented, L2 Searchable, L3 Generative, L4 Agentic. | `docs/maturity-model.md` — `## L0 — Ad-hoc` through `## L4 — Agentic`. |
| 6 | Each maturity level has a documented "what you get" description and rough time-to-value estimate. | `docs/maturity-model.md` — every level has **What you get** and **Time to next level** subsections. |
| 7 | `adef init` scaffolds an ADEF workspace including a journals/, AGENTS.md, methodology link, and config file. | `adef/commands/init.py`; `tests/test_template_and_init.py::test_adef_init_scaffolds_workspace`. |
| 8 | `adef detection new` creates a new detection with a FORGE journal at journals/D-XXXX.md. | `adef/commands/detection.py` `new` subcommand; `tests/test_journal_core.py::test_create_journal_writes_at_find_stage`. |
| 9 | `adef detection observe <id>` advances to Observe with stage-appropriate prompts. | `adef/commands/detection.py` `_make_stage_command`; `adef/data/prompts/observe.md`; `tests/test_journal_core.py::test_advance_through_all_stages`. |
| 10 | `adef detection refine <id>` triggers Similarity / Overlap / Verification chain. | `adef/orchestration/refine_chain.py` `REFINE_STEPS`; `adef/commands/detection.py` Refine command calls `run_refine_chain`. |
| 11 | `adef detection govern <id>` advances to Govern, capturing deployment gates, ownership, review cadence. | `adef/data/prompts/govern.md`; `adef/data/templates/DETECTION_FORGE.md` `## Govern` section. |
| 12 | `adef detection evolve <id>` advances to Evolve and surfaces tuning/deprecation/replacement decisions. | `adef/data/prompts/evolve.md`; `adef/data/templates/DETECTION_FORGE.md` `## Evolve` section. |
| 13 | Every lifecycle stage transition writes a durable, timestamped entry to the detection's journal. | `adef/core/journal.py::Journal.advance_stage` appends `## [<ISO-8601>] Stage: <stage>` block; `tests/test_journal_core.py::test_advance_through_all_stages` confirms persistence. |
| 14 | ADEF ships an MCP server entry point (`adef-mcp`) compatible with Claude Code, GitHub Copilot, and Cursor. | `pyproject.toml` `[project.scripts] adef-mcp = "adef.mcp.server:cli"`; FastMCP-based server in `adef/mcp/server.py`. |
| 15 | The MCP server exposes lifecycle commands, journal/memory search, and agent orchestration as tools. | `adef/mcp/tools/{lifecycle_tools,memory_tools,agent_tools,init_tools}.py`. |
| 16 | `adef hunt-promote <H-XXXX>` converts an upstream hunt into a draft ADEF detection with a populated journal. | `adef/commands/hunt_promote.py`; `adef/agents/hunt_promotion.py::HuntPromotionAgent.run` (resolves the generator via `ADEF_HUNT_RULE_GENERATOR`). |
| 17 | ADEF wraps 12 upstream rule-engineering agents as lifecycle-aware tools without modifying their internals. | `adef/agents/wrappers/__init__.py::ALL_WRAPPERS` (12 entries); each wrapper carries a `binding_key` and resolves its class via `ADEF_WRAPPER_<KEY>`; `tests/test_agents.py::test_twelve_wrappers_exported`. |
| 18 | ADEF adds 4 new agents: HypothesisFromIntel, TuneRecommender, DeprecationRecommender, HuntPromotion. | `adef/agents/{hypothesis_from_intel,tune_recommender,deprecation_recommender,hunt_promotion}.py`; covered by `tests/test_agents.py`. |
| 19 | Upstream YAML detection files are never modified by any ADEF code path (schema parity test). | `adef/core/journal.py::_check_not_under_detections`; `tests/test_schema_parity.py` (both static and runtime checks). |
| 20 | Each detection has a sibling markdown journal at journals/D-XXXX.md, paired with the YAML rule. | `adef/core/journal.py::Journal.create` writes `D-XXXX.md`; `rule_uuid` lives in frontmatter. |
| 21 | The detection journal captures FORGE-stage notes, hypothesis, intel sources, query iterations, tuning decisions, deprecation rationale. | `adef/data/templates/DETECTION_FORGE.md` template body covers every named field. |
| 22 | Memory search queries traverse both YAML rule metadata and markdown journals in a single call. | `adef/core/memory.py::MemoryIndex.search` walks journals; `adef/core/rule_bridge.py::iter_rules` yields YAML metadata via `ADEF_RULE_ROOT`; the MCP `memory_search` tool ties them together. |
| 23 | v0.1.0 ships with no extracted shared library — code duplication accepted. | No `adef-core` or shared-lib package in `pyproject.toml`. ADEF carries its own thin wrappers and depends on no first-party sibling library. |
| 24 | v0.1.0 introduces no new engine types beyond sigma, sql, sch_sql, composite. | `tests/test_no_new_engine_types.py::test_engine_lists_are_closed_set` (CI guard). |
| 25 | v0.1.0 ships no vendor-specific API connectors. | `tests/test_no_vendor_connectors.py` (CI guard, both pyproject and source-tree scan). |
| 26 | v0.1.0 ships no web UI; CLI and MCP are the only user-facing surfaces. | `tests/test_no_web_ui_deps.py` (CI guard). |
| 27 | v0.2+ roadmap explicitly lists long-running orchestration daemons, agent-to-agent handoff, autonomous deprecation. | `docs/roadmap.md` — `## v0.2.0 — Autonomy` section names all three. |
| 28 | The north-star v1 demo flow `adef detection new --from-intel <url>` is documented. | `docs/north-star.md` — opening command literal, plus stage-by-stage expansion. |
| 29 | Public-facing docs frame ADEF and ATHF as paired siblings, not as a successor relationship. | `docs/why-adef.md` — `## What ADEF and ATHF are to each other` section explicitly says "paired siblings, not a successor relationship". |
| 30 | Maturity model docs ship at v0.1.0. | `docs/maturity-model.md` exists in this commit. |
| 31 | Methodology doc ships at v0.1.0 and serves as the "why ADEF / how to adopt ADEF" framework adoption guide. | `docs/methodology.md` + `docs/why-adef.md` (the methodology paper plus its adoption companion). |

## Test summary

```
$ pytest
all tests passing
```

In-repo guard tests + functional tests cover:

- Schema parity + hard invariant (2)
- Engine type closed set (1)
- Vendor connector absence (2)
- Web-UI dep absence (2)
- Journal CRUD + FORGE stage transitions (10)
- Memory BM25 search (3)
- Template + init scaffolding (3)
- Agents (11)

## How to re-run verification

```bash
source .venv/bin/activate
pytest -v
adef --help        # CLI smoke test
adef detection --help
adef-mcp --help    # MCP server (requires `pip install -e .[mcp]`)
```
