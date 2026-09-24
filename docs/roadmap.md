# ADEF Roadmap

> What's in v0.1.0, what's coming, and — just as important — what ADEF is deliberately *not* going to ship.

## v0.1.0 — Foundations (this release)

The minimum viable framework: FORGE methodology, journal memory, twelve wrapped agents, four new agents, MCP surface.

- FORGE lifecycle CLI: `adef detection {new, observe, refine, govern, evolve}`.
- Journal memory: per-detection markdown at `journals/D-XXXX.md`, idempotent stage advance, atomic writes.
- Refine-stage orchestration chain: RuleSimilarity → RuleOverlap → Verification.
- Four new agents: `HypothesisFromIntel`, `TuneRecommender`, `DeprecationRecommender`, `HuntPromotion`.
- `adef hunt-promote` — convert an ATHF hunt to a draft ADEF detection.
- MCP server (`adef-mcp`) exposing lifecycle, memory, and agent tools.
- Public docs frame ADEF and ATHF as paired siblings.

## v2 (Shortcut epic 9324, "ADEFv2", target end of September 2026) — in progress

Clears deferred v0.1.0 debt and moves the framework from "journal + catalog"
toward vendor-connected.

- **Refine chain goes native by default** — RuleSimilarity (BM25 by default,
  optional LLM rerank via `--similarity-mode {auto,bm25,llm}`), RuleOverlap,
  and Verification no longer require an `ADEF_WRAPPER_<KEY>` binding to an
  upstream package; the `ADEF_WRAPPER_*` env var remains a supported opt-in
  override. **Shipped, in PR, not yet merged** — see `STATUS.md`.
- **Composite rule builder** — not started.
- **Vendor testing-platform support** (CrowdStrike, Splunk, maybe Defender) —
  not started.
- **MCP-driven tuning** against a user's own live environment — not started.
- **Vendor-connected metrics, performance, and drift capture** — blocked on a
  capture-mechanism spike (no vendor API connectors in ADEF core); not started.
- **Organization/tenant scoping** for native Similarity/Overlap catalog reads
  in a multi-org workspace — deliberately out of scope for ADEF standalone;
  revisit only if this work is explicitly scoped into detect-vault
  integration.

## v0.2.0 — Autonomy

The first autonomous agent loops.

- **Per-alias values + namespace preference.** A folded field stores only the
  canonical spelling's value vocabulary today; the alias's is discarded, so an
  agent pairing the alias spelling with harvested values (`Status=failure`)
  writes a legal-per-schema query that never matches. v2: each spelling keeps
  its own `values` inside one folded entry, plus a `prefer: cim|raw` key so
  schema-grounded authoring follows team convention instead of the
  canonical-by-count accident — together they enable a value-aware
  `schema check` that catches the never-fires class.
- **Data-model schemas (the third field namespace).** Declarations currently
  model the *index* namespace (raw + CIM alias fields from a `fieldsummary`
  export). Splunk `tstats` rules reference accelerated data-model fields
  (`Processes.process_name`) that never appear in an index export — measured
  against ESCU: ~39% of its 2,113 active detections (49% of endpoint) query
  data models and would union-miss in `schema check` against index-derived
  schemas. v2 seam: declare a data model as a source (fields from
  `| datamodel <name> ... | fieldsummary` or the DM JSON), same declaration
  format, `scope: {datamodel: Endpoint.Processes}`.

- Long-running orchestration daemon: `adef-daemon` watches detection health (FP ratio, signal volume, days-since-true-positive) and emits proposals.
- Agent-to-agent handoff workflows: `HypothesisFromIntel → DraftRule → RuleSimilarity → RuleOverlap → Verification → DeploymentGate` as a single orchestrated DAG.
- Autonomous deprecation recommendations: the `DeprecationRecommender` can open PRs against the configured upstream rule repository when its verdict is `deprecate` and confidence exceeds a configured floor. Humans review and approve.

## v0.3.0+ — Generative authoring

The shape of L3-Generative as a first-class workflow.

- `adef detection new --from-intel <url>` is the documented happy path.
- Backtest-aware drafting: the agent does not propose a rule it can't backtest.
- Cross-project memory: search journals + upstream hunt artifacts + upstream rule YAML in one query.

## v1.0 — North star

See [north-star.md](./north-star.md). The v1 demo is `adef detection new --from-intel <url>` producing a backtested, MITRE-tagged, deduplicated, journaled detection in minutes — without short-circuiting any of FORGE.

---

## Anti-goals

The framework's gravity well bends toward feature creep; the anti-goals push back. **None of the following will land in v0.1.0** — and several won't land *ever*:

- **No new engine types.** `sigma`, `sql`, `sch_sql`, `composite` is the closed set. The CI guard `tests/test_no_new_engine_types.py` enforces it.
- **No vendor connectors.** ADEF will not ship CrowdStrike, Splunk, SentinelOne, Microsoft Sentinel, etc. integrations inside the framework. They are policy-coupled, vendor-coupled, and a maintenance trap. Build them as separate plugins.
- **No web UI.** v0.1.0 is CLI + MCP. Web frameworks (`flask`, `fastapi`, `starlette`, `django`, `next`, `react`) will not appear in `pyproject.toml`. The CI guard `tests/test_no_web_ui_deps.py` enforces it.
- **No upstream YAML mutation.** ADEF code paths never open or write any path under any rule `detections/` directory. Enforced at runtime by `_check_not_under_detections()` in `adef/core/journal.py` and at CI time by `tests/test_schema_parity.py`.
- **No silent plugin failures.** Plugin entry-point loading is wrapped in defensive try/except so one broken plugin can't hide all the others — the failure is logged, not swallowed.

If you find yourself reaching for one of these, that is the framework telling you to ship it as a separate package.
