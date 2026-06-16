---
project: adef
task: Build ADEF v0.1.0 — Agentic Detection Engineering Framework
slug: adef-v0.1.0
effort: E5
phase: execute
progress: 0/80
mode: build
started: 2026-06-16T16:30:00-07:00
updated: 2026-06-16T16:30:00-07:00
algorithm_config:
  effort_source: context-override
  invoked_from: /goal goals/adef/goal.md
---

## Problem

Detection engineering has no memory and no lifecycle. Rules accumulate as YAML in upstream repositories, but every fact about *why* a rule exists, *what* telemetry shaped it, *how* it was iterated on, *who* gates its deployment, and *when* it should be tuned or retired lives in chat threads, ticket comments, and individual recall. Across teams the loss is structural: prior reasoning is unavailable to the agent or analyst encountering the rule next, AI augmentation has nothing durable to ground in, and tuning/deprecation decisions repeat.

Adjacently, the threat-hunting side of the same problem already has a solution — ATHF — but the threat-hunting and detection-engineering lifecycles need separate frameworks, not a single conflated one.

## Vision

ADEF is the detection-engineering sibling of ATHF: a small, opinionated, self-contained Python framework (`adef`) that turns every detection into a first-class, journalled artifact moving through a five-stage lifecycle (FORGE — Find → Observe → Refine → Govern → Evolve). A new analyst, an AI agent, or a future-you can open the journal and reconstruct the entire reasoning trail in seconds. Memory queries traverse YAML and journals together. New detections originate from a CTI URL or a hunt promotion in minutes, not days. ATHF and ADEF are paired siblings, both legible to humans and agents, neither subordinate to the other.

The euphoric surprise on encounter is: "this *is* the framework I would have wished into existence — minimal moving parts, total memory, and the agentic surface is just there."

## Out of Scope

- Replacing the upstream YAML rule schema. Rules stay where they are; ADEF wraps and journals.
- Introducing new engine types beyond `sigma`, `sql`, `sch_sql`, `composite`. The four engines are settled.
- Vendor-specific API connectors inside the framework (CrowdStrike, Splunk, SentinelOne, etc.). Connectors live elsewhere.
- Replacing ATHF. ADEF and ATHF are paired siblings.
- Web UI. CLI and MCP are the only user-facing surfaces in v0.1.0.
- Auto-deploying rules without human approval. ADEF can recommend; humans gate.
- Extracting a shared core library. Duplication between `adef` and `athf` is accepted in v0.1.0.
- Long-running orchestration daemons, agent-to-agent handoff, autonomous deprecation. v0.2+ surface.

## Principles

- **Wrap, don't rewrite.** Upstream rule-engineering agents stay intact; ADEF adds a thin lifecycle-aware orchestration layer. Upstream YAML is never modified by an ADEF code path.
- **Memory is markdown.** Journals are human-readable, AI-readable, version-controlled. The shape of the markdown IS the schema.
- **Lifecycle is a five-stage loop.** FORGE — Find, Observe, Refine, Govern, Evolve. Each stage is idempotent, each transition is timestamped, each step writes durably.
- **Plugin parity with ATHF.** Same Click + entry-point + FastMCP shape; same conventions for commands/agents/mcp_tools entry-point groups. A reader of ATHF's source recognizes ADEF's source immediately.
- **Anti-goals are anti-criteria.** Out-of-scope items are CI-enforced, not hopes.

## Constraints

- Python 3.10+ only.
- Distribution name `agentic-detection-engineering-framework` (PyPI). Importable package `adef`. CLI `adef`. Repo at `~/work/agentic-detection-engineering-framework/` mirroring ATHF's full-name convention.
- Entry-point groups: `adef.commands`, `adef.agents`, `adef.mcp_tools`.
- Workspace lives at `~/work/adef-workspace/` (decided per goal Q1) — fresh top-level workspace.
- D-XXXX is a journal ID. Upstream rules continue to use UUIDs. Mapping is stored in journal frontmatter as `rule_uuid:`.
- No new engine types. No vendor API connectors. No web-UI dependencies (`flask|fastapi|starlette|django|next|react`).
- Hard invariant: no path under any rule `detections/` directory is opened or written by any `adef.*` import.

## Goal

Build ADEF v0.1.0 such that: (a) `pip install -e .` succeeds and `adef --help` shows the full lifecycle CLI; (b) `adef init` scaffolds a workspace; (c) all five FORGE lifecycle commands advance state and write timestamped journal entries, with `refine` invoking the Similarity → Overlap → Verification orchestration chain; (d) `adef-mcp` exposes lifecycle/memory/agent tools via FastMCP; (e) `adef hunt-promote H-XXXX` produces a draft staging YAML + populated journal; (f) all 31 facts in `docs/verification.md` pass verification; (g) all four anti-goal CI guards pass.

## Criteria

### Phase A — package skeleton

- [ ] ISC-1: `~/work/agentic-detection-engineering-framework/pyproject.toml` exists with `name = "agentic-detection-engineering-framework"`.
- [ ] ISC-2: `pyproject.toml` declares `[project.scripts]` entries `adef = "adef.cli:main"` and `adef-mcp = "adef.mcp.server:cli"`.
- [ ] ISC-3: `pyproject.toml` declares entry-point groups `adef.commands`, `adef.agents`, `adef.mcp_tools` (consumed by plugin_system).
- [ ] ISC-4: `adef/__init__.py` defines `__version__ = "0.1.0"`.
- [ ] ISC-5: `adef/cli.py` exposes `main()` Click group; `pip install -e . && adef --help` exits 0 and lists the root group.
- [ ] ISC-6: `adef/plugin_system.py` enumerates entry points for `adef.commands`, `adef.agents`, `adef.mcp_tools` and registers them with the root Click group.
- [ ] ISC-7: Repo has `README.md`, `LICENSE` (MIT), `AGENTS.md`, `pytest.ini`, `.gitignore` at root.
- [ ] ISC-8: `git init` + initial commit on `main` succeeds; `git log --oneline` shows the initial commit.

### Phase B — methodology + maturity + why-adef docs

- [ ] ISC-9: `docs/methodology.md` contains heading `# FORGE Methodology` and one `##` heading per stage (`Find`, `Observe`, `Refine`, `Govern`, `Evolve`) with a worked example each.
- [ ] ISC-10: `docs/maturity-model.md` contains five level headings (`L0 Ad-hoc`, `L1 Documented`, `L2 Searchable`, `L3 Generative`, `L4 Agentic`), each with a "what you get" bullet and a "time-to-value" line.
- [ ] ISC-11: `docs/why-adef.md` (adoption guide) exists, frames ADEF and ATHF as paired siblings (literal phrase "paired siblings"), is linked from `README.md` and from `AGENTS.md`.

### Phase C — template + workspace init

- [ ] ISC-12: `adef/data/templates/DETECTION_FORGE.md` has YAML frontmatter (id, status, current_stage, owner, created, updated, rule_uuid) plus five `##` headings (Find, Observe, Refine, Govern, Evolve).
- [ ] ISC-13: `adef init` creates `journals/`, `config/.adefconfig.yaml`, `AGENTS.md`, `templates/DETECTION_FORGE.md` in the target dir; AGENTS.md links to methodology.md and maturity-model.md.
- [ ] ISC-14: `adef init` defaults to `~/work/adef-workspace/` when invoked with no path argument and creates it if missing.

### Phase D — journal core + lifecycle CLI

- [ ] ISC-15: `adef/core/journal.py` defines `Journal.create(detection_id)`.
- [ ] ISC-15.1: `adef/core/journal.py` defines `Journal.advance_stage(detection_id, stage, payload)`.
- [ ] ISC-15.2: `adef/core/journal.py` defines `Journal.read(detection_id)`.
- [ ] ISC-15.3: `Journal.create` writes file at `journals/D-XXXX.md` from package template.
- [ ] ISC-15.4: `Journal.create` populates frontmatter (`id`, `status`, `current_stage`, `owner`, `created`, `updated`, `rule_uuid`).
- [ ] ISC-16: Stage transition appends `## [<ISO-8601>] Stage: <stage>` block.
- [ ] ISC-16.1: Stage transition updates frontmatter `current_stage` atomically (write-temp + rename).
- [ ] ISC-16.2: Stage transition updates frontmatter `updated` timestamp.
- [ ] ISC-17: Re-advancing the same stage is idempotent (no duplicate block).
- [ ] ISC-17.1: Re-advancing the same stage emits a warning to stderr.
- [ ] ISC-18: Anti: no `adef.*` import opens or writes any path under a rule `detections/` directory (parity test using Path-monkey-patch fixture).
- [ ] ISC-18.1: Anti: `Journal` class never receives a path under any rule `detections/` directory (unit test asserts).
- [ ] ISC-19: `adef detection new` creates `D-XXXX.md` journal at Find stage.
- [ ] ISC-19.1: D-XXXX numbering scans `journals/`, finds max, increments by 1.
- [ ] ISC-19.2: D-XXXX numbering handles empty `journals/` directory (returns D-0001).
- [ ] ISC-20: `adef detection observe <id>` advances state to Observe.
- [ ] ISC-20.1: `adef detection observe <id>` appends Observe block to journal.
- [ ] ISC-20.2: `adef detection observe <id>` renders `data/prompts/observe.md` into block.
- [ ] ISC-21: `adef detection refine <id>` advances state to Refine.
- [ ] ISC-21.1: `adef detection refine <id>` appends Refine block to journal.
- [ ] ISC-21.2: `adef detection refine <id>` renders `data/prompts/refine.md` into block.
- [ ] ISC-21.3: `adef detection refine <id>` invokes orchestration chain (cross-ref ISC-31..33).
- [ ] ISC-22: `adef detection govern <id>` advances state to Govern.
- [ ] ISC-22.1: `adef detection govern <id>` appends Govern block with deployment-gate / ownership / cadence prompts.
- [ ] ISC-23: `adef detection evolve <id>` advances state to Evolve.
- [ ] ISC-23.1: `adef detection evolve <id>` appends Evolve block with tuning / deprecation / replacement prompts.

### Phase E — upstream rule-agent wrappers

- [ ] ISC-24: `adef/agents/wrappers/` contains 12 wrapper files, one per upstream rule-engineering agent (RuleSimilarity, RuleOverlap, Coverage, Performance, DetectionDecision, DetectionReview, DroppedFindings, FindingsAnalysis, FpPattern, ReviewQueue, ThreatReview, Verification).
- [ ] ISC-25: Each wrapper resolves its underlying upstream class via the `ADEF_WRAPPER_<KEY>=module.path:ClassName` env var (where `<KEY>` matches the wrapper's `binding_key`).
- [ ] ISC-26: Anti: ADEF wrappers never modify upstream rule-agent source — wrappers are pure adapters; the upstream package owns its own state.

### Phase F — new ADEF agents

- [ ] ISC-27: `adef/agents/hypothesis_from_intel.py` defines `HypothesisFromIntelAgent` with a `run(intel_url_or_text)` method returning a draft Find/Observe block.
- [ ] ISC-28: `adef/agents/tune_recommender.py` defines `TuneRecommenderAgent` returning tuning suggestions given a `detection_id`.
- [ ] ISC-29: `adef/agents/deprecation_recommender.py` defines `DeprecationRecommenderAgent` returning keep/tune/deprecate.
- [ ] ISC-30: `adef/agents/hunt_promotion.py` defines `HuntPromotionAgent` invoking the configured hunt-rule generator (resolved via `ADEF_HUNT_RULE_GENERATOR=module.path:ClassName`) and writing a populated journal.

### Phase G — Refine orchestration chain

- [ ] ISC-31: `adef/orchestration/refine_chain.py` defines a function/class that runs Similarity → Overlap → Verification in sequence.
- [ ] ISC-32: Each agent's result is appended to the detection's journal under the Refine block.
- [ ] ISC-33: Integration test using fixtures (no live ClickHouse) asserts all three wrappers fire and outputs land in the journal.

### Phase H — Memory search

- [ ] ISC-34: `adef/core/memory.py` defines `MemoryIndex.search(query)` returning ranked merged results (journal markdown + YAML metadata).
- [ ] ISC-35: BM25 over markdown is implemented (no embeddings — deferred to v0.2).
- [ ] ISC-36: Lazy-loads upstream YAML rule metadata via `adef.core.rule_bridge` (configured by `ADEF_RULE_ROOT`); no eager import, gracefully degrades if not configured.

### Phase I — MCP server

- [ ] ISC-37: `adef/mcp/server.py` instantiates a FastMCP named `"adef"` and exposes `cli` callable.
- [ ] ISC-38: `adef/mcp/tools/lifecycle_tools.py` exposes FORGE stage-advance tools.
- [ ] ISC-39: `adef/mcp/tools/memory_tools.py` exposes `memory_search` tool.
- [ ] ISC-40: `adef/mcp/tools/agent_tools.py` exposes orchestration triggers + individual agent invocation tools.
- [ ] ISC-41: `adef/mcp/tools/init_tools.py` exposes workspace ops (init, status).
- [ ] ISC-42: Server discovers plugin tools via `entry_points(group="adef.mcp_tools")`.
- [ ] ISC-43: In-process integration test boots server, lists tools, asserts each expected tool is registered.

### Phase J — hunt-to-detection promotion

- [ ] ISC-44: `adef/commands/hunt_promote.py` defines `adef hunt-promote H-XXXX`.
- [ ] ISC-45: Resolves H-XXXX through the configured hunt source, invokes `HuntPromotionAgent` (ISC-30).
- [ ] ISC-46: Writes draft staging YAML to the configured rule-staging directory (`--rule-staging-root` / `ADEF_RULE_STAGING_ROOT`) — never inside any rule `detections/` directory.
- [ ] ISC-47: Creates ADEF journal at Find stage with intel sources populated.
- [ ] ISC-48: Anti: hunt-promote with no generator configured exits with a clear error (no ImportError surface).

### Phase K — [DROPPED — see Decisions 2026-06-16 vendor neutralization scope cut]

- [ ] ISC-49: [DROPPED — internal-package coupling, removed from public framework scope]
- [ ] ISC-50: [DROPPED — internal-package coupling, removed from public framework scope]
- [ ] ISC-51: [DROPPED — internal-package coupling, removed from public framework scope]
- [ ] ISC-52: [DROPPED — internal-package coupling, removed from public framework scope]
- [ ] ISC-53: [DROPPED — internal-package coupling, removed from public framework scope]
- [ ] ISC-54: [DROPPED — internal-package coupling, removed from public framework scope]
- [ ] ISC-55: [DROPPED — internal-package coupling, removed from public framework scope]

### Phase L — roadmap + north-star + backfill

- [ ] ISC-56: `docs/roadmap.md` lists daemons, agent-to-agent handoff, autonomous deprecation as v0.2+ items.
- [ ] ISC-57: `docs/north-star.md` contains the literal phrase `--from-intel` and describes the v1 demo flow.
- [ ] ISC-58: `adef backfill journals` command creates skeleton journals for existing upstream rule YAML (decided per goal Q2 — ships in v0.1.0).

### Phase M — anti-goal CI guards

- [ ] ISC-59: Anti: `tests/test_schema_parity.py` greps every `adef.*` source file for write-paths inside any `detections/` directory — passes (no offenders).
- [ ] ISC-60: Anti: `tests/test_engine_guard.py` greps adef source — no engine name beyond `sigma|sql|sch_sql|composite` appears.
- [ ] ISC-61: Anti: `tests/test_connector_guard.py` greps adef source — no `crowdstrike|splunk|sentinelone` import appears.
- [ ] ISC-62: Anti: `tests/test_no_web_ui.py` parses `pyproject.toml` dependencies — none of `flask|fastapi|starlette|django|next|react` present.

### Cross-cutting

- [ ] ISC-63: All 31 facts in `docs/verification.md` are evidence-mapped (probe-by-probe).
- [ ] ISC-64: Antecedent: when hunt-promotion or wrapper functionality is exercised, an upstream rule + hunt package is installed and resolvable via `ADEF_HUNT_RULE_GENERATOR` and `ADEF_WRAPPER_*` env vars. Verified by configuring those env vars and running an end-to-end smoke test in the operating environment.

## Test Strategy

| isc | type | check | threshold | tool |
|---|---|---|---|---|
| ISC-1 | file | `Read` pyproject.toml; assert name | exact match | Read |
| ISC-2 | file | grep `adef = "adef.cli:main"` | match | Grep |
| ISC-3 | file | grep `adef.commands` | match | Grep |
| ISC-4 | file | Read __init__.py for `__version__` | match | Read |
| ISC-5 | exec | `pip install -e . && adef --help` | exit 0 | Bash |
| ISC-6 | unit | pytest test for plugin discovery | pass | Bash |
| ISC-7 | file | `ls` shows all root files | exact set | Bash |
| ISC-8 | exec | `git log --oneline | head -1` | one commit | Bash |
| ISC-9 | file | grep five FORGE headings | all present | Grep |
| ISC-10 | file | grep five level headings | all present | Grep |
| ISC-11 | file | grep "paired siblings" | match | Grep |
| ISC-12 | file | parse template, assert frontmatter+headings | all keys/headings | Bash |
| ISC-13 | exec | `adef init <tmp>` then `ls <tmp>` | expected files | Bash |
| ISC-14 | exec | `adef init` with no arg, check `~/work/adef-workspace/` | exists | Bash |
| ISC-15 | unit | pytest Journal API | pass | Bash |
| ISC-16 | unit | create+advance, regex assert ISO-8601 + frontmatter | pass | Bash |
| ISC-17 | unit | re-advance same stage, assert no duplicate | pass | Bash |
| ISC-18 | unit | Path-monkey-patch parity test | pass | Bash |
| ISC-19 | exec | `adef detection new`, list journals/ | D-0001.md exists | Bash |
| ISC-20-23 | exec | each subcommand → assert state | pass | Bash |
| ISC-24 | file | ls wrappers/, expect 12 .py files | 12 | Bash |
| ISC-25 | unit | pytest each wrapper resolves binding_key and class via env var | pass | Bash |
| ISC-26 | unit | wrappers contain no upstream-source mutation paths | pass | Bash |
| ISC-27-30 | unit | pytest each agent class signature | pass | Bash |
| ISC-31 | file | grep refine_chain | match | Grep |
| ISC-32-33 | unit | integration test refine chain | pass | Bash |
| ISC-34-36 | unit | pytest MemoryIndex | pass | Bash |
| ISC-37-43 | unit | MCP in-process boot test | tools registered | Bash |
| ISC-44-48 | unit | hunt_promote integration | pass | Bash |
| ISC-49-55 | — | DROPPED (Phase K scope cut, see Decisions) | n/a | n/a |
| ISC-56-57 | file | grep literal strings | match | Grep |
| ISC-58 | exec | `adef backfill journals` against fixture | journals created | Bash |
| ISC-59-62 | unit | parity tests | pass | Bash |
| ISC-63 | doc | each fact has Verification entry | 31/31 | Read |
| ISC-64 | exec | python imports check | exit 0 | Bash |

## Features

| name | description | satisfies | depends_on | parallelizable |
|---|---|---|---|---|
| skeleton | repo + pyproject + cli root + plugin_system | ISC-1..8 | — | no |
| docs | methodology + maturity + why-adef | ISC-9..11 | skeleton | yes (with templates) |
| templates | DETECTION_FORGE.md + init scaffolding | ISC-12..14 | skeleton | yes (with docs) |
| journal-core | core/journal.py + lifecycle commands | ISC-15..23 | skeleton, templates | no |
| wrappers | wrap 12 upstream rule-engineering agents | ISC-24..26 | skeleton | yes (after journal-core) |
| new-agents | 4 new ADEF agents | ISC-27..30 | wrappers | yes (with refine-chain) |
| refine-chain | orchestration sequence | ISC-31..33 | wrappers | no |
| memory | core/memory.py BM25 + YAML lazy | ISC-34..36 | journal-core | yes (with refine-chain) |
| mcp | FastMCP server + tool modules | ISC-37..43 | journal-core, memory, refine-chain | no |
| hunt-promote | adef hunt-promote command | ISC-44..48 | new-agents | no |
| roadmap | roadmap, north-star, backfill | ISC-56..58 | journal-core | yes |
| guards | 4 anti-goal CI tests | ISC-59..62 | all above | no |
| verification | 31-fact evidence trail | ISC-63..64 | all above | no |

## Decisions

- 2026-06-16T16:30:00-07:00 — Workspace location decided: `~/work/adef-workspace/` (goal Q1, fresh top-level workspace). Rationale: clean separation between framework and any consumer rule/hunt repository.
- 2026-06-16T16:30:00-07:00 — Backfill timing decided: ship `adef backfill journals` in v0.1.0 (goal Q2). Rationale: makes memory search immediately useful for the existing rule corpus.
- 2026-06-16T16:30:00-07:00 — Repo init decided: `git init` + initial commit on the new repo. Rationale: clean history from day one.
- 2026-06-16T16:30:00-07:00 — Effort source: context-override. Classifier returned NATIVE on the original `/goal` command (just file loading, correctly), but the actual goal is build ADEF v0.1.0 — unambiguous E5. Logging the override per Algorithm v6.3.0.
- 2026-06-16T16:30:00-07:00 — Delegation soft floor (E5 ≥4) met: Forge (skeleton + wrappers), Cato (E5 mandatory VERIFY audit), Engineer (Claude-family producer for ISC-heavy code), Advisor (commitment-boundary call before BUILD on plugin architecture). Anvil held in reserve.
- 2026-06-16T16:30:00-07:00 — Thinking hard floor (E5 ≥8) met with: ISA, FirstPrinciples, SystemsThinking, RootCauseAnalysis, IterativeDepth, ApertureOscillation, BitterPillEngineering, ReReadCheck, Advisor (9 capabilities, all from v6.3.0 closed enumeration verbatim).
- 2026-06-16T16:35:00-07:00 — Risks captured at THINK: (1) stale egg-info masking plugin entries — clean install required when ADEF is installed alongside any upstream rule package; (2) schema parity test implemented as static-source scan + Path-monkey-patch fixture, not git-diff against live tree, to avoid false positives; (3) hunt-rule generator resolved lazily through `ADEF_HUNT_RULE_GENERATOR`, surfacing a clean `HuntPromotionError` if unconfigured; (4) MCP boot test uses asyncio.run, mirroring conventional FastMCP test rigs.
- 2026-06-16T16:30:00-07:00 — ISC floor show-your-math: E5 soft floor is ≥256. Current count is ~80 atomic ISCs (each one binary-tool-probe verifiable). Splitting further would add ceremony, not verifiability — most remaining splits would be "and the file ends with a newline" / "and the import path is exactly X" trivia. The granularity rule (one binary tool probe per ISC) is satisfied; the count axis is relaxed because the work is well-bounded by `goals/adef/plan.md`'s 20 ordered steps. Per Algorithm v6.3.0, ISC floor is soft; thinking and completeness gates remain HARD-met.
- 2026-06-16 — Vendor neutralization: scrubbed all literal references to specific internal package names (any string that hardcodes a vendor's rule or hunt repository) from the ADEF source, docs, tests, and ISA. Wrappers now resolve their upstream class through `ADEF_WRAPPER_<KEY>=module.path:ClassName` env vars; hunt promotion through `ADEF_HUNT_RULE_GENERATOR`. Rationale: ADEF is a public framework; the internal rule/hunt repos are out-of-tree concerns and must not appear in the public surface.

## Changelog

(populated at LEARN — conjecture / refuted_by / learned / criterion_now)

## Verification

(populated at VERIFY — evidence per ISC)
