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

## Cataloging

`adef catalog <rule-root>` walks an existing detection repo (read-only), sniffs
each rule's format, and writes an enrichment record to
`<workspace>/catalog/<platform>/D-XXXX-<slug>.yml` that references the source via
`rule_ref`. It also generates `catalog/INDEX.yml` and a paired skeleton journal
per rule. Ambiguous rules are flagged `needs_review: true` (infer-and-flag,
never block). See `docs/plans/2026-07-15-catalog-design.md`.

**When `adef catalog` reports unclaimed files — drive the profile loop.**
Unclaimed = structured files no recognizer or profile claims (in-house
formats). Do NOT stop at diagnosis; walk the user through authoring:
1. `adef catalog <root> --dry-run --report json` → cluster unclaimed files by
   `top_level_keys` (one cluster = one format = one profile).
2. Read 2–3 samples per cluster; draft a profile
   (see `docs/creating-extraction-profiles.md` for the schema).
3. `adef profile lint <draft>` then
   `adef catalog <root> --dry-run --profile <draft>` — the per-field
   extraction rates are the scoreboard (query ≥95%, title ≥90%).
4. On user approval, save to `<workspace>/config/profiles/` and re-run the
   real catalog.

**Key modules:**
- `adef/core/rule_discovery.py` — shared repo walk (`discover_rules`,
  `walk_outcomes`, `sniff_format`). User extraction profiles are checked
  before built-in recognizers.
- `adef/core/profiles.py` — declarative extraction profiles (teach ADEF a rule
  format with YAML, not code; see 2026-07-20 plugin design doc).
- `adef/core/catalog.py` — `CatalogRecord`, `Catalog`, INDEX generation.
- `adef/commands/catalog.py` — the `adef catalog` command
  (`--report json`, `--profile` validation scoreboard).

**`engine` vs `format`:** catalog `engine` stays in the internal four-value
taxonomy (guarded by `test_no_new_engine_types.py`); `format`/`query_language`
carry the true source language (sigma/spl/kql/cql/sql) losslessly.

## Schema Storage (declaration-driven)

Users provide a **data-source declaration** (`adef-sources.yml`: sources +
fields, produced from `| fieldsummary` / `| getschema` / index mappings).
Schemas live at `<workspace>/schema/<source>.yml` (`schema_version: 2`) with
`declared | corrected` field provenance. Rules are a schema *consumer*, never
a *source* — the rules-derived model was removed pre-release (ISA 2026-07-20).

**Commands:**
- `adef schema ingest <declaration.yml>` — build schemas; re-ingest preserves
  human `corrected` fields and reports drift
- `adef schema lint <declaration.yml>` — validate a declaration
- `adef schema check` — cross-reference rule field usage vs declared schemas
- `adef schema show <source>` — display schema

**Key modules:**
- `adef/core/declaration.py` — declaration lint/parse, ingest, provenance
  merge, drift
- `adef/core/rule_parser.py` — SQL (sqlglot AST), SPL/CQL/KQL (regex) field
  extractors (consumed by `schema check`)

## ISA Discipline

`ISA.md` at the repo root is the system of record for the project (Algorithm v6.3.0). Every meaningful decision lands in `## Decisions`; every conjecture/refutation goes in `## Changelog`; every ISC verification goes in `## Verification`.
