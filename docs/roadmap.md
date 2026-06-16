# ADEF Roadmap

> What's in v0.1.0, what's coming, and — just as important — what ADEF is deliberately *not* going to ship.

## v0.1.0 — Foundations (this release)

The minimum viable framework: FORGE methodology, journal memory, twelve wrapped agents, four new agents, MCP surface, dual registration with `athf detect`.

- FORGE lifecycle CLI: `adef detection {new, observe, refine, govern, evolve}`.
- Journal memory: per-detection markdown at `journals/D-XXXX.md`, idempotent stage advance, atomic writes.
- Refine-stage orchestration chain: RuleSimilarity → RuleOverlap → Verification.
- Four new agents: `HypothesisFromIntel`, `TuneRecommender`, `DeprecationRecommender`, `HuntPromotion`.
- `adef hunt-promote` — convert ATHF hunt to draft ADEF detection.
- `adef backfill journals` — scaffold journals for an existing upstream rule corpus.
- MCP server (`adef-mcp`) exposing lifecycle, memory, and agent tools.
- Dual registration: the upstream rule package loads under both `athf.commands` and `adef.commands`. `athf detect` continues to work and prints a deprecation banner pointing at `adef detect`.
- Public docs frame ADEF and ATHF as paired siblings.

## v0.2.0 — Removal + autonomy

The first deliberate break in the dual-registration bridge, and the first autonomous agent loops.

- **`athf detect` registration is removed.** Users must migrate to `adef detect`. The deprecation banner has been live the entire v0.1.x cycle to give a runway.
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
