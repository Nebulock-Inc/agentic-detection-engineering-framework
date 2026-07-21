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
- 2026-07-15 — Schema Storage: SQL uses sqlglot AST parsing for 99%+ coverage (high-fidelity). SPL/CQL/KQL use enhanced regex (~95% coverage, upgradeable later). LLM provider-agnostic via Protocol pattern (Claude/OpenAI built-in). Results-in seam: user pipes data, ADEF infers types/populations. No vendor connectors (Splunk API, CrowdStrike API, etc.).
- 2026-07-15 — Catalog layer (Shortcut Epic 6996 / stories 7387, 7388, 7389, 7393). Cataloging turns an existing detection repo into ADEF's catalog artifact. Decisions:
  - **Two ingestion paths, one built now.** (a) *point-at-a-repo* — walk a rules repo and catalog what's there — is v1. (b) *export-from-a-tool* is a future seam reusing the same results-in contract; designed around, not built.
  - **Catalog folder is `catalog/`, never `detections/`.** The `detections/` name in the 2026-06-26 repo-design doc is superseded — CLAUDE.md's CI-enforced hard rule (`test_schema_parity.py`) forbids any ADEF write path containing `detections/`. Catalog records live at `catalog/<platform>/D-XXXX-<slug>.yml`.
  - **Catalog record references, never copies-authoritative.** Each record carries `rule_ref` (relative pointer to the source file in the user's repo) + `original_path` (absolute, for provenance). Source repo stays source of truth for rule logic; ADEF never writes to it.
  - **Multi-format sniff + extract (v1).** Discovery sniffs file type by extension+content: Sigma `.yml`/`.yaml` (full auto-extract: title, logsource→platform, tags→MITRE, engine=sigma, kind=atomic), Splunk `.conf` savedsearches (heuristic), `.kql` (heuristic, table→platform), `.sql` (heuristic). Reuses `adef.core.rule_parser` field extractors.
  - **Infer-and-flag, never block (Q5=B).** Cataloging never prompts mid-run. Ambiguous fields left null; record tagged `needs_review: true`. Reviewed later via CLI/skill.
  - **6 required fields (Q4):** `id`, `title`, `platform`, `kind`, `engine`, plus `rule_ref` or inline `query`. MITRE/owner/slim-ADS optional, enriched through FORGE.
  - **INDEX.yml is generated, never hand-edited.** `detections` (ID→path) + reverse maps `by_platform`/`by_tactic`/`by_engine`/`by_status`. Rebuilt by catalog + `adef reindex`.
  - **Shared ID space.** Catalog `D-XXXX` IDs allocate above the max of BOTH catalog and journals so catalog+journal+INDEX stay tied by ID. Cataloging a rule also creates its skeleton journal.
  - **Capture:** this session ships code + ISA.md; Shortcut stories updated in a later pass.
- 2026-07-16 — Schema-from-catalog mapping (Epic 6996; resolves the catalog↔schema overlap open thread). Design agreed, **not yet implemented**. Hybrid of three options weighed (A group-by-language, B capture-data_source-at-catalog-time, C named-per-source):
  - **Capture `data_source` on `CatalogRecord`** (mechanism from B), inferred during discovery from the **raw table/index/logsource literal, verbatim — no normalization**: Sigma `logsource` value, KQL lead table, SQL `FROM` table, SPL `index=`. Unresolvable → `data_source` empty + existing `needs_review: true`.
  - **New command `adef schema from-catalog`** reads catalog/INDEX and writes one `schema/<data_source>.yml` per confident `(data_source, query_language)` group. Rules with no inferred source **fall back to pool-by-language** (`schema/sql.yml`, …) — option A as catch-all so no fields are lost.
  - **Rationale:** serves both drift detection (fields captured regardless of source) and authoring grounding (per-source accuracy where confident); un-inferrable tail degrades to coarse pooling, never a false-confident per-source schema.
  - **Accepted tradeoff:** raw-literal source names can fragment one logical source across inconsistent naming (`cloudtrail` vs `aws_cloudtrail`). Chosen over inference to avoid guessing; normalization/alias map is a later upgrade if it proves messy.
  - **Coordination:** changing `CatalogRecord` affects the schema feature (shared surface) — co-worker sign-off before building. Command choice: standalone `adef schema from-catalog`, not a flag on `init`.
- 2026-07-16 — Schema-from-catalog IMPLEMENTED (the above design, built TDD). Evidence:
  - `data_source` inference in `rule_discovery` (raw literal: Sigma logsource category→service→product, KQL lead table verbatim, SQL `FROM`, SPL `index=`; empty when unresolvable). 5 new tests in `tests/test_rule_discovery.py`.
  - `data_source` on `CatalogRecord` + YAML + `by_data_source` reverse map in INDEX. 2 new tests in `tests/test_catalog.py`.
  - `adef schema from-catalog` groups catalogued rules by `(data_source, query_language)` → `schema/<source>.yml`; un-inferred sources pool by language (`schema/<lang>.yml`); Sigma excluded. 6 tests in `tests/test_schema_from_catalog.py`.
  - Full suite **119 passed**. Anti-goal guards green. End-to-end verified: two SQL rules on `cloudtrail` merge into one schema; KQL→`DeviceProcessEvents.yml`; `SELECT 1` pools into `sql.yml` fallback.
- 2026-07-17 — Format-detection Phase 1 IMPLEMENTED (plan: `docs/plans/2026-07-17-format-detection-plan.md`). Corrects the Sigma-YAML-only bias found by testing against real corpora. Decisions + evidence:
  - **Content-signature recognizer registry** in `rule_discovery` (general-shape-first: has query/logic + detection metadata; vendor signatures are hints, not a closed list). `recognize()` returns `Recognition(format, support)`; `sniff_format` kept as a thin back-compat wrapper.
  - **Three-outcome `support` model:** `supported | recognized_unsupported | not_a_rule`, distinct from `needs_review`. On `DiscoveredRule` + `CatalogRecord` + catalog YAML. `discover_rules` yields recognized-unsupported rules (no silent drops); only `not_a_rule` skipped.
  - **New formats:** Splunk ESCU (`search:`+`type:` → full extract, SPL query, `mitre_attack_id`/`data_source`) and Panther (`AnalysisType`+`RuleID` → metadata-only, `recognized_unsupported`; logic in sibling `.py` deferred). Splunk *stories* and Panther *packs* correctly resolve to `not_a_rule` (no query). osquery dropped from scope.
  - **Auto-detect only** — no user format prompt (init stays non-interactive).
  - Full suite **139 passed** (+20). Guards green, ruff clean. **End-to-end on real corpora: Splunk `detections/` 0→2124, Panther `rules/` 0→877.** Known follow-up: platform inference for Splunk ESCU is weak (most flag `needs_review`) — Phase 2 refinement.
- 2026-07-17 — Catalog record now stores the query inline. Bug: the record captured metadata but not the detection logic (discovery extracted `query_text`, `record_from_discovered`/`to_yaml_dict` dropped it). Fix: `query` field on `CatalogRecord` + YAML, populated from `DiscoveredRule.query_text` (empty when logic is external, e.g. Panther `.py`). Kept `rule_ref`/`original_path` → records are self-contained *and* traceable, matching the 2026-07-07 architecture-doc record shape. Multi-line queries render as literal block scalars via a catalog-scoped YAML dumper (readability), not affecting other modules' YAML. Full suite **141 passed** (+2). Guards green, ruff clean.
- 2026-07-20 — Claude plugin + declarative extraction profiles (design: `docs/plans/2026-07-20-claude-plugin-design.md`; accepted by Jarrett; **co-worker signed off 2026-07-21** — covers this, the schema-declaration decision, and its scope addition). Decisions:
  - **Rule-format support is delivered as declarative extraction profiles** (YAML: signature + dot-path field map) executed by one generic engine in `rule_discovery`. Hand-coded recognizers migrate to built-in profiles over time; user profiles (`<workspace>/config/profiles/*.yml`) are checked before built-ins so orgs can override how their own formats are read. Path syntax is dot-paths + `[]` array iteration only — no JSONPath — so the human approval gate stays reviewable; profile schema is versioned (`version: 1`) for evidence-driven extension.
  - **Container parse returns a list of documents** (contract from day one; v1 implements single-document yaml/json only). Multi-doc containers (`conf` stanzas via `_stanza`, ndjson, ARM `resources[]`) are later phases; `spl-conf` stays hand-coded until then.
  - **Agent-drafted profiles are validated by the deterministic engine** (`adef catalog --dry-run --profile` per-field extraction rates) **and gated on explicit human approval** before install. The sub-agent's sample cap (50) + holdout ratio (~20%) live in the agent definition; file selection lives in the skill.
  - **ADEF ships a Claude plugin** (`claude-plugin/`: catalog-onboarding skill + profile-author sub-agent + adef-mcp wiring; repo root doubles as marketplace via `.claude-plugin/marketplace.json`). Skills orchestrate CLI/MCP commands, never reimplement them; `adef/data/prompts/` stays the single source for any future forge-stage skill. MCP remains the portable layer for non-Claude assistants.
  - **CLI seams:** `adef catalog --report json` (machine-readable outcome report incl. `unclaimed` files for clustering), `adef catalog --profile <yml>` (candidate-profile validation + per-field rates), `adef profile lint`.
- 2026-07-20 — Schema ingest simplified to **data-source declarations** (design: `docs/plans/2026-07-20-schema-declaration-design.md`; team decision — rules-derived field schemas were not useful: aliased/calculated/macro-expanded names, and rules only show fields already in use). Decisions:
  - **Users provide a declaration document** (`adef-sources.yml`, format v1: sources + fields, low floor = names only, optional type/description/values/aliases). Field names are in query-language terms. No event data required or stored.
  - **Schema artifact v2** (`schema_version: 2`) with field provenance `declared | corrected`: re-ingest replaces declared fields, preserves human corrections, prints a drift report. v1 (rules-derived) files readable, no longer produced. Future samples path = a third provenance value, additive.
  - **Rules demoted from schema source to schema consumer:** catalog `by_data_source` prioritizes what to declare; new `adef schema check` cross-references rule field usage (existing `rule_parser` extractors) against declarations — findings: rule-field-missing-from-schema, schema-field-unused-by-rules. Never blocks.
  - **Removed same session (pulled forward from v0.2 — ADEF is unreleased, a deprecation window protects nobody; Jarrett approved):** `schema init` wizard, `schema from-catalog` field derivation, `schema update`/`rescan` stubs, MCP `schema_init`, `adef/core/schema.py` (old model + `merge_fields`), `data_sampler.py`, `llm_client.py`, `rule_discovery.scan_rule_fields`, their six test files, the `llm` optional-dependency group (anthropic/openai), and the unused `jinja2` dependency. MCP gains declaration-driven `schema_ingest`; `schema_show` renders v2. `data_source` capture on `CatalogRecord` is kept (feeds prioritization + check).
  - **Adoption paths:** per-SIEM inventory recipes (docs only), future `declaration-author` plugin skill (profile-author's twin), vendor-MCP-assisted drafting. Anti-goals intact: no connectors, no event data at rest.
- 2026-07-21 — From-scratch E2E test against `test-rules/panther-analysis/queries` (fresh workspace, two live-authored profiles for the 95 scheduled-query files built-ins don't claim: `panther-scheduled-query` 46, `panther-snowflake-query` 49; title/query/uuid extraction 100%, zero unclaimed remaining). Three findings, all fixed same session:
  - **`rule_ref` was workspace-relative** → degraded to `../../..` walks when workspace and repo don't share a parent. Fixed: `record_from_discovered` takes `rule_root`; `rule_ref` = `<root-name>/<path-inside-root>`; workspace-relative kept only as fallback. Regression test in `test_catalog.py`.
  - **Profile-claimed rules had empty `data_source`** when the map omits it. Fixed: fall back to the same raw-literal extraction as built-ins (SQL FROM / SPL index= / KQL lead table) via `_infer_data_source`.
  - **SQL FROM regex matched prose in comments** ("adapted from a SnowAlert query" → `data_source: a`) and Snowflake `FROM TABLE(...)`. Fixed: `_sql_from_table` strips `--` and `/* */` comments and skips reserved words; applied to profile fallback AND the raw-`.sql` extractor. Result on corpus: 95/95 with data_source, 94 real tables + 1 CTE-name (accepted best-effort). Tests in `test_profiles.py`. Known open: `needs_review` is all-or-nothing (95/95 flagged for missing MITRE) — severity tiers deferred.
- 2026-07-21 — **Scope on declared sources** (design: scope section added to `docs/plans/2026-07-20-schema-declaration-design.md`; motivated by live Splunk test where one index mixed Sysmon + DNS shapes). Decisions + evidence:
  - Optional free-form `scope` mapping per source: `name` is what a schema *is*, `scope` values are every literal a query might *address* it by. Keys (sourcetype/event_simpleName/log_type/event.dataset/…) are platform vocabulary ADEF never interprets — no platform enumeration ahead of time; only query languages are code, everything platform-shaped is user/agent-provided data.
  - `schema check` matching: rule literals = `data_source` + shape literals from the query (`rule_discovery.shape_literals`; SPL `sourcetype=` first). **Most-specific match wins, ties = union** — container-only rules check against the union of shapes in the container (correct: they could see any). Routing pseudo-fields (index/sourcetype/host/earliest/…) are never findings.
  - `query_language` now persisted on `CatalogRecord`/YAML — fixes a real gap: `check` previously keyed extractors off `format`, silently skipping ESCU and profile-claimed rules.
  - Evidence: 15/15 new scope smoke checks (union legitimacy, narrowing, meta-field suppression, profile-rule checkability); suites 28/28 + 31/31; corpora regression exact. Tests in `tests/test_declaration.py`. Full pytest/ruff/mypy still pending local run.
- 2026-07-21 — **`adef detection list` / `show` shipped** (story 7393, previously deferred) + `examples/` demo. `list`: reads catalog records; filters `--platform/--rule-format/--status/--stage/--needs-review`; `--report json`. `show`: record fields + query + paired-journal stage history tail. New `examples/demo-rules/` (8 SPL savedsearches + 1 Sigma targeting the `thrunt` lab sourcetypes, incl. one deliberately-broken rule for `schema check` demos) + `examples/adef-sources-thrunt.yml` (14 scoped sources, 659 fields, generated live from a Splunk fieldsummary `map` export). E2E in sandbox: catalog 9 → list/filters/json → show → ingest 14 schemas → check flags only the planted bogus field (10/10 checks). Suites 28/28 + 31/31, corpora exact. Known noise confirmed again: all 8 SPL rules flag `needs_review` (no platform inference for SPL conf) — severity-tier follow-up stands. Tests in `tests/test_detection_browse.py`.

- 2026-07-21 — **needs_review rework** (closes the severity-tier follow-up flagged twice this week). Decisions + evidence:
  - **`review_reasons`** on `DiscoveredRule`/`CatalogRecord`/YAML: `malformed | external_logic | no_platform | no_mitre`; computed centrally by `finalize_review()` in the walk (one place, all paths). `needs_review` boolean kept = bool(reasons), back-compat.
  - **Structural vs enrichment**: ⚠ markers and headline counts key off structural reasons only (`structural_reasons()`); `no_mitre` is the enrichment queue — surfaced separately (`adef detection list --needs-review no_mitre`), never trips the warning.
  - **Platform inheritance from declared schemas at catalog time** (`_inherit_platforms`): rule literals matched against source names + scope values, most-specific-wins (same semantics as `schema check`); inherit only when the platform is unambiguous — never guess. Declaring data cleans the catalog.
  - **Tier-2 MITRE parity for profile rules**: technique-ID text sweep over title + description + query when the profile map yields no MITRE (why Panther scheduled queries were 0%). `description` added to profile MAP_FIELDS.
  - `list --needs-review` upgraded to optional-value (bare = structural; `<reason>` = that queue); legacy records without `review_reasons` degrade to an opaque `legacy` reason.
  - Evidence: examples demo went **8/9 flagged → 1/9** (7 platforms inherited; the survivor is the deliberately-broad hunt, correctly ambiguous). 11/11 new smoke checks; suites 28/28 + 31/31; corpora exact. Tests in `tests/test_review_reasons.py`. Co-worker sign-off recorded for the 2026-07-20/21 design decisions. (Full pytest/ruff/mypy local run completed 2026-07-21 — see the "Local quality gates" entry at the top of this section.)

- 2026-07-21 — **ATT&CK reference layer deferred to the coverage epic; INDEX honesty rename.** Decision: MITRE capture stays regex (sufficient for v0.1.0 — journals/catalog/profiles/schemas/check need no ATT&CK knowledge), but nothing coverage-branded ships without the reference layer first (compact snapshot from official STIX via `mitreattack-python` as a build-time tool, never a runtime dep; `adef attack refresh` for updates; consumers: `invalid_mitre`/revoked validation reasons, true tactic resolution, mitre-tagger grounding — agents select from the snapshot, never model memory). Sequenced in `docs/2026-07-21-next-steps.md` §4. Done now (pre-release, migration-free): INDEX `by_tactic` → **`by_technique`** — it was keyed by technique and labeled tactic; renamed rather than pretend.

- 2026-07-21 — **ATT&CK reference layer built (coverage epic step 1)** — implements the deferral decision above. Decisions taken while building:
  - **STIX fetched directly, no dependency at all.** The generator (`adef/data/attack/_generate.py`, dev-time only, not imported at runtime) pulls MITRE's official `enterprise-attack.json` from `mitre-attack/attack-stix-data` with stdlib `urllib`+`json` and distils it. Chosen over `mitreattack-python` (which the deferral named) because a fixed public STIX URL needs no wrapper and keeps `mitreattack-python` out of even the *dev* deps — stronger form of "never a runtime dep."
  - **Compact snapshot shipped as package data** (`adef/data/attack/enterprise.json`, ~104K, ATT&CK 19.1: 858 techniques, 15 tactics): `id → {name, tactics[], parent?, deprecated?, revoked?, superseded_by?}` + tactic shortname→display map. Only the fields consumers need. `snapshot_version` gates the reader.
  - **Runtime read side** (`adef/core/attack.py`): JSON-only, no network/STIX. `attack_reference()` prefers a `refresh`-ed `$ADEF_WORKSPACE/attack/enterprise.json` over the shipped copy, so `adef attack refresh` takes effect with no package-data write. Cached (`lru_cache`).
  - **`adef attack` command**: `info` / `show <id>` (name, tactics, parent, revoked→replacement) / `refresh` (re-fetch into workspace; network failure reports and exits 1, shipped snapshot stays in use).
  - **Consumers wired (proof the layer is real, not shelf-ware):** (1) new **structural** review reason `invalid_mitre` — a mapped ID absent from the reference flags the rule (mutually exclusive with `no_mitre` — enrichment vs. defect). (2) INDEX gains real **`by_tactic`** resolved through the reference (dual-tactic techniques land under both; kept `by_technique` too — completes the honesty-rename thread above).

- 2026-07-21 — **`mitre-tagger` skill + `adef detection tag-mitre` write path (coverage epic step 2)**. Decisions:
  - **A real CLI write verb, not skill-authored YAML.** `adef detection tag-mitre D-XXXX T#### [...]` is the only MITRE-enrichment write path. A skill hand-editing catalog YAML is the exact "paste metadata by hand, doesn't survive sync" anti-pattern the catalog-onboarding skill already forbids; the tagger gets the same discipline. `tag_mitre` (`adef/core/tag.py`): validates every ID against the shipped reference (invalid → `InvalidTechniqueError`, **nothing written** — atomic), merges+dedupes into `mitre`, drops `no_mitre`/`invalid_mitre` from `review_reasons`, recomputes `needs_review`, rebuilds INDEX (so `by_tactic` updates immediately). Revoked-but-real IDs are accepted with a `→ replacement` note (caller decides). Added `Catalog.find_record` / `Catalog.write_raw` (in-place rewrite, no re-slug).
  - **Durability note (deliberate non-goal):** enrichment written to a record is wiped if `adef catalog` is re-run, because re-catalog currently assigns fresh IDs and does not reconcile. This applies uniformly to *all* enrichment (status/stage/owner today), not just MITRE — the tagger does not make it worse. Sync-safe re-derivation is the unbuilt `adef sync` epic (next-steps §7); not solved here by decision.
  - **Skill grounds every ID in the shipped reference, never model memory.** `mitre-tagger` reads each `no_mitre` record's *logic* (title+query), proposes techniques, and MUST confirm each with `adef attack show` before offering it; `tag-mitre`'s deterministic validation is the backstop. Human approval is a hard gate per write. Plugin auto-discovers it from `claude-plugin/skills/`.

## Changelog

(populated at LEARN — conjecture / refuted_by / learned / criterion_now)

## Verification

(populated at VERIFY — evidence per ISC)

- 2026-07-21 — **mypy taken to 0** (follow-on to the "First real quality-gate run" entry below, which fixed branch-authored files and left mypy at 9 errors in pre-existing files scoped out per HANDOFF #3). This session cleared those remaining 9, so the whole `adef/` tree is now type-clean. Reached by rebasing onto that run; overlapping fixes (init_tools, schema.py, catalog.py, rule_discovery.py) were identical and resolved to one copy. Dev env: Python 3.13.9, ruff 0.15.21, mypy 2.3.0.
  - `pytest` — **167 tests, all green** (165 passed + 2 skipped; the 2 skips are 3.13-specific — the run below on 3.11 reported 167 passed).
  - `ruff check adef/` — **All checks passed** after: removed unused `shutil` import (`journal.py`); `# noqa: E402` on the two `cli.py` imports that must follow `load_dotenv()`.
  - `mypy adef/` — **Success, 0 issues** after clearing the 9 in previously-unchanged files: `no-any-return` hardening via `str(...)`/`cast` in `journal.py` (id/stage/uuid props), `agent_tools.py` (`_to_dict` + 4 tool returns), `hunt_promotion.py` (title/uuid `str(... or ...)`); and a `getattr` → `isinstance(cls, type)` guard in `_base.py`.
  - Anti-goal guards green (`test_schema_parity`, `test_no_new_engine_types`, `test_no_vendor_connectors`, `test_no_web_ui_deps`). Fixes are typing-only; no behavior change (suite unchanged pre/post).

- 2026-07-15 — Catalog layer (Epic 6996 / stories 7387, 7388, 7389). Evidence:
  - `adef/core/rule_discovery.py` — shared read-only repo walk; 14 tests (`tests/test_rule_discovery.py`) + 4 field-scan tests (`tests/test_rule_field_scan.py`) pass.
  - `adef/core/catalog.py` — `CatalogRecord`/`Catalog`/INDEX; 9 tests (`tests/test_catalog.py`) pass.
  - `adef/commands/catalog.py` — `adef catalog` command; 6 tests (`tests/test_catalog_command.py`) pass; discovered in `adef --help`.
  - Schema v1 gap closed: `adef schema init --rule-root` now calls `scan_rule_fields` (was stubbed). Wired without breaking the 73 pre-existing tests.
  - Full suite: **106 passed** (73 original + 33 new). Anti-goal guards green: `test_schema_parity` (no `detections/` writes), `test_no_new_engine_types` (engine stays 4-value; true format in `format` field).
  - End-to-end CLI verified: catalogs a Sigma + raw-SQL repo → `catalog/<platform>/D-XXXX.yml` + INDEX.yml + skeleton journals; source repo untouched; raw SQL flagged `needs_review`.
  - Deferred (not this session): `adef detection list/show` + `adef coverage` browsing (story 7393); reconciliation/`adef sync`; export-from-tool ingestion.

- 2026-07-21 — First real quality-gate run on the 2026-07-20/21 work (profiles, plugin, schema rework, browse, examples). Prior sessions were sandbox-only (no pytest/ruff/mypy); this was the documented one blocker. Interpreter: pyenv 3.11.11 in `.venv`. Evidence:
  - `pytest` — **167 passed** in ~10s, including the ~30 previously-unverified tests (test_profiles 26, test_profile_cli 7, test_declaration 24, test_detection_browse 6, test_review_reasons 5). Anti-goal guards green: `test_schema_parity`, `test_no_new_engine_types`, `test_no_vendor_connectors`, `test_no_web_ui_deps`.
  - `ruff check adef/` on branch-authored files — clean (0 findings). Repo-wide, 3 findings remain in pre-existing/unchanged files (`cli.py` E402 intentional post-`load_dotenv` imports; `journal.py` unused `shutil`) — out of scope per HANDOFF Open thread #3.
  - `mypy adef/` — the 5 findings in branch-authored files fixed (catalog.py, rule_discovery.py, schema.py ×2, plus the `init_tools.py` regression). 14 → 9 errors; the remaining 9 are all in unchanged files (`_base.py`, `journal.py`, `hunt_promotion.py`, `agent_tools.py`).
  - **Real bug fixed:** `adef/mcp/tools/init_tools.py` imported `WORKSPACE_AGENTS_MD` from `adef.commands.init`, a constant the 07-20 init refactor removed (init now reads `adef/data/templates/WORKSPACE_AGENTS.md` via package data). The MCP `workspace_init` tool would have crashed on import. Repointed to the `_workspace_agents_md()` helper; verified: module imports and `_scaffold_workspace` writes a 4876-byte AGENTS.md end-to-end.

- 2026-07-21 — ATT&CK reference layer (coverage epic step 1). Evidence:
  - Generator run against live official STIX → shipped `adef/data/attack/enterprise.json`: ATT&CK 19.1, 858 techniques (697 active + 12 deprecated + 149 revoked), 15 tactics; subtechnique parent (`T1059.001`→`T1059`), revoked+replacement (`T1143`→`T1564.003`) all resolve.
  - `tests/test_attack.py` — **9 tests**, incl. `invalid_mitre` firing on a bogus ID and staying off real/absent IDs. Full suite **176 passed** (was 167).
  - `ruff check` clean on all new files; `mypy adef/` adds **zero** new errors (still the same pre-existing 9).
  - CLI end-to-end: `adef attack info` (ATT&CK 19.1, 858/15), `show T1059.001` (PowerShell / Execution / parent T1059), `show T1143` (revoked → T1564.003), `show T9999` (invalid, exit 1).
  - Consumers proven on the `examples/demo-rules` corpus: INDEX `by_tactic` resolves (e.g. T1547.001 → both *Persistence* and *Privilege Escalation*); `invalid_mitre` produced zero false positives on the demo's real IDs.

- 2026-07-21 — `mitre-tagger` skill + `adef detection tag-mitre` (coverage epic step 2). Evidence:
  - `tests/test_tag_mitre.py` — **6 tests**: add+dedupe, `no_mitre` dropped (other reasons kept), `needs_review` cleared when it was the last reason, invalid ID rejected atomically (nothing written), INDEX `by_tactic` rebuilt, unknown detection raises. Full suite **182 passed** (was 176).
  - `ruff check` clean on new files; `mypy` adds zero new errors (the 3 shown are pre-existing `journal.py`/`_base.py`, surfaced via imports).
  - CLI end-to-end on a fresh `examples/demo-rules` catalog: `tag-mitre D-0001 T1071.004` → tagged, `no_mitre` gone (only `no_platform` left); `T9999` → rejected, exit 1, unchanged; `T1143` → tagged with `revoked → T1564.003` note; INDEX `by_tactic` immediately shows D-0001 under Command and Control + Stealth.
  - `mitre-tagger` skill written to `claude-plugin/skills/mitre-tagger/SKILL.md` (auto-discovered; plugin.json description updated). Orchestration-only — grounds IDs via `adef attack show`, writes via `tag-mitre`, human-approval gate.
