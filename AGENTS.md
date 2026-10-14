# AGENTS.md — Working Inside the ADEF Repo

This file briefs an AI agent operating inside the `agentic-detection-engineering-framework` source tree. ADEF is the **detection-engineering sibling** of [ATHF](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework). Both frameworks share the same Click + entry-point + FastMCP shape; reading either makes the other instantly familiar.

## Repo Shape

```
adef/                    # importable Python package
  cli.py                 # Click root group, registers entry-point commands
  plugin_system.py       # entry-point discovery (defensive load, never kills CLI)
  __version__ via __init__.py
  agents/                # ADEF-native agents (7): Hypothesis, Tune, Deprecation,
                         #   HuntPromotion, RuleSimilarity, RuleOverlap, Verification
    wrappers/            # Dispatchers for the 4 orchestrated rule agents. Similarity/
                         #   Overlap/Verification are native by default and only delegate
                         #   upstream when ADEF_WRAPPER_<KEY> is explicitly set;
                         #   PerformanceMetrics is the one true upstream-only wrapper.
  commands/              # Click subgroups: detection, init, hunt-promote, catalog, sync, schema
  core/                  # Journal, MemoryIndex, Catalog, corpus_text, engines (ALLOWED_ENGINES)
  data/                  # Package data — templates/, prompts/
  mcp/                   # FastMCP server + tool modules
  orchestration/         # Refine chain (Similarity → Overlap → Verification)
docs/                    # methodology.md, maturity-model.md, why-adef.md, roadmap.md, north-star.md
tests/                   # unit + integration + parity tests
```

## Hard Rules — Anti-Goals

These are CI-enforced. Do not work around them:

1. **Never write inside an upstream rule `detections/` tree.** ADEF is read-only for upstream rule YAML. Journals live alongside in the ADEF workspace at `journals/D-XXXX.md`. Parity test: `tests/test_schema_parity.py`.
2. **Never introduce new engine types.** The four engines are `sigma`, `sql`, `sch_sql`, `composite`. Anything else is out of scope. Parity test: `tests/test_no_new_engine_types.py`.
3. **Never add vendor-specific API connectors** (CrowdStrike, Splunk, SentinelOne, etc.). ADEF is a framework; connectors live in adapter packages. Parity test: `tests/test_no_vendor_connectors.py`.
4. **Never add web-UI dependencies** (`flask`, `fastapi`, `starlette`, `django`, `next`, `react`). v0.1.0 is CLI + MCP only. Parity test: `tests/test_no_web_ui_deps.py`.

## Hard Rule — Not CI-Enforceable

5. **ADEF is built standalone first; adopters integrate it later, never the reverse.**
   Any private or in-house codebase — including the maintainers' own — is a *future
   adopter*, not a design input. Concretely: a private codebase is never a reference
   corpus (don't measure against it or query its production data to settle an ADEF
   design question), never a justification ("our pipeline does X" is not a reason for
   ADEF to support X), and never an interface shape (don't fit a public format to one
   in-house implementation's quirks). Justify from language semantics, published
   practitioner standards, or a demonstrated user need instead. If a capability is only
   explicable by pointing at in-house tooling, it doesn't belong in ADEF yet.

   No test catches this one. Rule 3 blocks vendor SDK *imports*; this governs **design
   inputs**, which is upstream of any import and invisible to CI. It is on you.

## Methodology and Maturity

- [FORGE methodology](docs/methodology.md) — the lifecycle the framework gates around
- [Maturity model](docs/maturity-model.md) — five levels users move through
- [Why ADEF](docs/why-adef.md) — the framework adoption guide; ADEF and ATHF are paired siblings

## Upstream Decoupling

ADEF never hardcodes upstream package names. Integration is configured via environment variables:

- `ADEF_WRAPPER_<KEY>=module.path:ClassName` — bind a wrapper in `adef.agents.wrappers.*` to its upstream class. `<KEY>` matches the wrapper's `binding_key` (e.g. `RULE_SIMILARITY`, `RULE_OVERLAP`, `VERIFICATION`).
- `ADEF_HUNT_RULE_GENERATOR=module.path:ClassName` — bind `adef hunt-promote` to a hunt-rule generator that exposes `run(hunt_id=...)`.
- `ADEF_HUNT_ROOT=/path/to/hunts` (or `--hunt-root`) — directory of upstream hunt artifacts.

For Similarity/Overlap/Verification, a missing binding runs the native agent instead of raising `WrapperUnavailable`. PerformanceMetrics (which has no native implementation) and any explicitly set binding whose import fails still raise `WrapperUnavailable` (or `HuntPromotionError`) — orchestration captures the error in the journal and continues with the rest of the chain.

## Cataloging

`adef catalog <rule-root>` walks an existing detection repo (read-only), sniffs
each rule's format, and writes an enrichment record to
`<workspace>/catalog/<platform>/D-XXXX-<slug>.yml` that references the source via
`rule_ref`. It also generates `catalog/INDEX.yml` and a paired skeleton journal
per rule. Ambiguous rules are flagged `needs_review: true` (infer-and-flag,
never block).

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
  format with YAML, not code).
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
a *source* — the rules-derived model was removed pre-release.

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

## Recording decisions

A design decision that outlives its PR belongs in the artifact it governs — a
detection's journal for a detection, `CHANGELOG.md` for a user-visible change,
and a comment at the line for a constraint a future reader could plausibly
undo. `.claude/rules/verify-tests-fail.md` covers the one case where a comment
is not enough: a declared numeric constraint needs a test, or it is
indistinguishable from an undeclared one.
