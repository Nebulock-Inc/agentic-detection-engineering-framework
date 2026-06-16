# AGENTS.md — Working Inside the ADEF Repo

This file briefs an AI agent operating inside the `agentic-detection-engineering-framework` source tree. ADEF is the **detection-engineering sibling** of [ATHF](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework). Both frameworks share the same Click + entry-point + FastMCP shape; reading either makes the other instantly familiar.

## Repo Shape

```
adef/                    # importable Python package
  cli.py                 # Click root group, registers entry-point commands
  plugin_system.py       # entry-point discovery (defensive load, never kills CLI)
  __version__ via __init__.py
  agents/                # ADEF-native agents (Hypothesis, Tune, Deprecation, HuntPromotion)
    wrappers/            # Thin wrappers around 12 upstream rule-engineering agents
  commands/              # Click subgroups: detection, init, hunt-promote, backfill
  core/                  # Journal, MemoryIndex, rule_bridge
  data/                  # Package data — templates/, prompts/
  mcp/                   # FastMCP server + tool modules
  orchestration/         # Refine chain (Similarity → Overlap → Verification)
docs/                    # methodology.md, maturity-model.md, why-adef.md, roadmap.md, north-star.md
tests/                   # unit + integration + parity tests
ISA.md                   # Algorithm v6.3.0 ISA — system of record for the project
```

## Hard Rules — Anti-Goals

These are CI-enforced. Do not work around them:

1. **Never write inside an upstream rule `detections/` tree.** ADEF is read-only for upstream rule YAML. Journals live alongside in the ADEF workspace at `journals/D-XXXX.md`. Parity test: `tests/test_schema_parity.py`.
2. **Never introduce new engine types.** The four engines are `sigma`, `sql`, `sch_sql`, `composite`. Anything else is out of scope. Parity test: `tests/test_no_new_engine_types.py`.
3. **Never add vendor-specific API connectors** (CrowdStrike, Splunk, SentinelOne, etc.). ADEF is a framework; connectors live in adapter packages. Parity test: `tests/test_no_vendor_connectors.py`.
4. **Never add web-UI dependencies** (`flask`, `fastapi`, `starlette`, `django`, `next`, `react`). v0.1.0 is CLI + MCP only. Parity test: `tests/test_no_web_ui_deps.py`.

## Methodology and Maturity

- [FORGE methodology](docs/methodology.md) — the lifecycle the framework gates around
- [Maturity model](docs/maturity-model.md) — five levels users move through
- [Why ADEF](docs/why-adef.md) — the framework adoption guide; ADEF and ATHF are paired siblings

## Upstream Decoupling

ADEF never hardcodes upstream package names. Integration is configured via environment variables:

- `ADEF_WRAPPER_<KEY>=module.path:ClassName` — bind a wrapper in `adef.agents.wrappers.*` to its upstream class. `<KEY>` matches the wrapper's `binding_key` (e.g. `COVERAGE_ANALYSIS`, `RULE_OVERLAP`, `VERIFICATION`).
- `ADEF_HUNT_RULE_GENERATOR=module.path:ClassName` — bind `adef hunt-promote` to a hunt-rule generator that exposes `run(hunt_id=...)`.
- `ADEF_RULE_ROOT=/path/to/rules` (or `--rule-root`) — directory of upstream rule YAML for `adef backfill journals` and memory search.
- `ADEF_HUNT_ROOT=/path/to/hunts` (or `--hunt-root`) — directory of upstream hunt artifacts.

If a binding is missing or the import fails, the wrapper raises `WrapperUnavailable` (or `HuntPromotionError`) — orchestration captures the error in the journal and continues with the rest of the chain.

## ISA Discipline

`ISA.md` at the repo root is the system of record for the project (Algorithm v6.3.0). Every meaningful decision lands in `## Decisions`; every conjecture/refutation goes in `## Changelog`; every ISC verification goes in `## Verification`.
