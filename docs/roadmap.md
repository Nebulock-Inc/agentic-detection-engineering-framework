# ADEF Roadmap

> What has shipped, what's coming, and — just as important — what ADEF is deliberately *not* going to ship.

## v1.0 — Foundations (released 2026-07-28)

The minimum viable framework: FORGE methodology, journal memory, wrappers for upstream rule agents, four new agents, MCP surface.

- FORGE lifecycle CLI: `adef detection {new, observe, refine, govern, evolve}`.
- Journal memory: per-detection markdown at `journals/D-XXXX.md`, idempotent stage advance, atomic writes.
- Refine-stage orchestration chain: RuleSimilarity → RuleOverlap → Verification.
- Four new agents: `HypothesisFromIntel`, `TuneRecommender`, `DeprecationRecommender`, `HuntPromotion`.
- `adef hunt-promote` — convert an ATHF hunt to a draft ADEF detection.
- MCP server (`adef-mcp`) exposing lifecycle, memory, and agent tools.
- Public docs frame ADEF and ATHF as paired siblings.

## v2 — native Refine, cross-language retrieval, health capture (in progress)

**Shipped (merged, not yet released):**

- **Refine chain runs natively by default.** RuleSimilarity, RuleOverlap and
  Verification need no upstream binding; an `ADEF_WRAPPER_<KEY>` override
  still works.
  - **Similarity** fuses BM25, a field pass (through declared schema aliases)
    and a value pass that finds rules in *other* query languages testing the
    same rare values. `--similarity-mode`: `bm25` (CLI default, no network),
    `agent` (MCP default; the calling assistant ranks), `llm`/`auto`.
  - **Overlap** compares rules on the same ATT&CK technique, its parent and
    its sub-techniques (not siblings):
    `duplicate`, `redundant`, `complementary`, or `unassessed` for a pair in
    two query languages, which ADEF doesn't compare yet.
  - **Verification** reports `passed`, `failed`, or `partial` when the field
    check couldn't run, and says why.
- **Detection health ingestion.** `adef ingest` takes five self-describing
  document kinds (`metrics`, `performance`, `deployment_drift`,
  `field_observations`, `source_health`) from any producer. The three
  detection-keyed kinds store a latest snapshot plus append-only history; the
  two source-keyed ones store latest only. ADEF still never queries your
  environment.
- **Health readback into Evolve.** `adef health show` prints what was stored
  plus the values the heuristics read (`fp_ratio`, `weekly_signal_volume`,
  `days_since_true_positive`), and `adef detection evolve --chain` reasons from
  them — so a keep/tune/deprecate verdict is dated, sourced, and written to the
  journal. This is what closed the loop: Evolve used to report
  `insufficient-data` on numbers that had just been ingested. The *fleet*
  report (`adef health report`) is still to come.
- **Workspace self-check.** `adef doctor` — ten checks over one workspace, each
  carrying the next command to run. Warnings exit 0; state that would make
  another command lie exits 1.
- **ATHF GATES import.** `adef hunt-promote --gates` turns a hunt's validated
  candidates into catalogued detections.
- **Catalog and sync.** Extraction profiles cover YAML-wrapped queries (CQL
  query hubs, Panther scheduled queries); `sync` picks up profile edits; a
  backward FORGE stage move needs `--back` on the CLI (`allow_backward` in the
  API and MCP).

**Not started:**

- **Fleet health report.** A `health report` view across every detection, the
  coverage report's peer. Per-detection readback shipped; the aggregate didn't.
- **Trend analysis over the health history.** `health/history/*.jsonl` is
  append-only so this can be built; nothing reads more than the latest
  snapshot yet.
- **Composite rule builder.**
- **Testing-platform support** (CrowdStrike, Splunk, maybe Defender), as
  separate packages per the no-connectors anti-goal.
- **MCP-driven tuning** against a user's own environment.
- **Logic comparison across query languages**, beyond today's shortlist.

## Next — Autonomy

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

## Later — Generative authoring

The shape of L3-Generative as a first-class workflow.

- `adef detection new --from-intel <url>` is the documented happy path.
- Backtest-aware drafting: the agent does not propose a rule it can't backtest.
- Cross-project memory: search journals + upstream hunt artifacts + upstream rule YAML in one query.

## North star

See [north-star.md](./north-star.md). The demo is `adef detection new --from-intel <url>` producing a backtested, MITRE-tagged, deduplicated, journaled detection in minutes — without short-circuiting any of FORGE.

---

## Anti-goals

The framework's gravity well bends toward feature creep; the anti-goals push back. **None of the following will land in v2** — and several won't land *ever*:

- **No new engine types.** `sigma`, `sql`, `sch_sql`, `composite` is the closed set. The CI guard `tests/test_no_new_engine_types.py` enforces it.
- **No vendor connectors.** ADEF will not ship CrowdStrike, Splunk, SentinelOne, Microsoft Sentinel, etc. integrations inside the framework. They are policy-coupled, vendor-coupled, and a maintenance trap. Build them as separate plugins.
- **No web UI.** ADEF is CLI + MCP. Web frameworks (`flask`, `fastapi`, `starlette`, `django`, `next`, `react`) will not appear in `pyproject.toml`. The CI guard `tests/test_no_web_ui_deps.py` enforces it.
- **No upstream YAML mutation.** ADEF code paths never open or write any path under any rule `detections/` directory. Enforced at runtime by `_check_not_under_detections()` in `adef/core/journal.py` and at CI time by `tests/test_schema_parity.py`.
- **No silent plugin failures.** Plugin entry-point loading is wrapped in defensive try/except so one broken plugin can't hide all the others — the failure is logged, not swallowed.

If you find yourself reaching for one of these, that is the framework telling you to ship it as a separate package.
