# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ADEF (Agentic Detection Engineering Framework)** is the detection-engineering sibling of ATHF (Agentic Threat Hunting Framework). It gives detection engineering durable memory and lifecycle structure through the **FORGE** methodology:

- **F**ind → **O**bserve → **R**efine → **G**overn → **E**volve

ADEF wraps existing detection rules (YAML) with sibling markdown journals (`journals/D-XXXX.md`) that capture *why*, *how*, and *when next* for every detection. Rules stay in their upstream repositories; ADEF never modifies upstream YAML.

## Direction of Integration (read before designing anything)

**ADEF is built standalone and open-source first. Adopters integrate ADEF into their
own stacks later — never the reverse.**

Any private or in-house codebase — including the maintainers' own — is a *future
adopter* of ADEF, not an input to it. When designing or implementing any feature:

- A private codebase is **not a reference corpus**. Do not measure against it, sample
  from it, or query its production data to settle an ADEF design question.
- A private codebase is **not a justification**. "Our pipeline does X" is not a reason
  for ADEF to support X. Justify from language semantics, published practitioner
  standards, or a demonstrated ADEF user need.
- A private dialect is **not an interface shape**. Never fit a public format to one
  in-house implementation's quirks.

If a proposed capability is only explicable by pointing at in-house tooling, it does
not belong in ADEF yet.

This is broader than the "no vendor connectors" CI guard, which only catches SDK
imports. This one governs **design inputs**, which no test can enforce — it is on you.

**Key concepts:**
- **Journals**: Per-detection markdown files (`D-XXXX.md`) with YAML frontmatter + timestamped stage-transition blocks
- **Workspace**: `~/work/adef-workspace/` with `journals/`, `templates/`, `config/`
- **Paired sibling of ATHF**: Hunts graduate to detections via `adef hunt-promote H-XXXX`
- **Plugin architecture**: Click + entry-point groups + FastMCP (same shape as ATHF)

## Essential Commands

> Full per-command reference (synopsis, options, examples): **`docs/cli-reference.md`**.

### Installation & Setup
```bash
pip install -e .                    # Editable install for development
pip install -e ".[dev]"             # Include dev dependencies (pytest, mypy, ruff)
pip install -e ".[mcp]"             # Include MCP server support

adef --version                      # Verify installation
adef --help                         # List all commands
```

### Workspace Initialization
```bash
adef init                           # Create workspace at ~/work/adef-workspace/
adef init /custom/path              # Create workspace at custom location
adef init --interactive             # + prompt for SIEM/platform (drives schema recipes)
```
Using ADEF as your detection home (no repo)? Version the workspace with native
git — it's plain markdown + YAML. See `docs/detection-home.md`.

### Workspace Self-Check
```bash
adef doctor                         # every piece of workspace state + the next command for each
adef doctor --report json           # machine-readable (checks + problem/warning counts)
```
Ten checks over one workspace — workspace scaffold, catalog records, INDEX
freshness, journal pairing, declared schemas, ATT&CK snapshot, enrichment
queue, ingested health, the `[mcp]` extra, installed skills — each carrying the
literal next command to run — the fix where one command fixes it, the triage
entry point (`enrichment`) where the work is a human's, and none where no
command would help (`catalog`'s unreadable YAML, `index` when the expected
INDEX can't even be built — `adef reindex` dies on the same cause). It exists because every other command is silent
about the state it doesn't use: `adef detection list` says nothing about a
stale INDEX, `adef coverage` nothing about an un-ingested schema, and
`adef detection evolve` says `insufficient-data` whether you never ingested
health or ingested it under an ID the catalog doesn't have. Each gives a
plausible empty answer separately, with no way to see the common cause.

**Two severities, and only one gates the exit code.** `warn` is an optional
capability nobody has set up (no schemas, no health, no skills) — the normal
state of a day-one workspace, so warnings **exit 0** and `adef doctor` stays
safe in a CI job. `problem` is state that makes another command *lie*: a
missing workspace, a record whose YAML no command can parse, a stale INDEX.
Those **exit 1**.

The INDEX check is an exact comparison of the stored `INDEX.yml` against the
one the records imply (`Catalog.build_index()`, split out of `rebuild_index`
for exactly this). An ID-set or mtime comparison would miss the case that
matters most: edit a record's `mitre` — which `adef detection tag-mitre` and a
human both do — and every filename stays identical while `by_technique` and
`by_tactic` go wrong, which is what `adef coverage` and `--tactic` read.

Read-only, including on the directory it's pointed at. `Catalog.__init__`
mkdirs, so it is constructed only *after* the workspace-scaffold check has
passed; otherwise `adef doctor` in an unrelated repo would leave a workspace
skeleton behind. Core: `adef/core/doctor.py` (pure `Check` model) +
`adef/commands/doctor.py` (rendering + exit code).

### Detection Lifecycle (FORGE)
```bash
# Create a new detection at Find stage
adef detection new "Suspicious mshta.exe child process"
adef detection new "Title" --owner alice --rule-uuid <UUID>

# Author a NEW rule grounded in a declared schema (journal + draft catalog record)
adef detection new "Suspicious mshta child" --source wineventlog_xml
#   --source pulls platform/query_language/scope from schema/<source>.yml and
#   scaffolds a starter query with the real index/sourcetype literals. Errors if
#   the schema isn't declared. Omit --source for a journal only (as before).
#   The rule lands in the ADEF catalog; moving it to the user's repo is deferred.

# Advance through FORGE stages
adef detection observe D-0001       # Stage 2: characterize telemetry
adef detection refine  D-0001       # Stage 3: runs Similarity → Overlap → Verification chain
adef detection govern  D-0001       # Stage 4: deployment gates, ownership
adef detection evolve  D-0001       # Stage 5: runs Health → Tuning → Deprecation chain
adef detection evolve  D-0001 --chain   # re-run it after a fresh `adef ingest`

# Add notes to any stage transition (--note is repeatable → renders as a bullet list)
adef detection observe D-0001 --note "Baseline: mshta-from-office ~3/day" \
                              --note "FP source: legit admin GPO scripts"

# Enrich a catalog record with ATT&CK technique IDs (drains the no_mitre queue)
adef detection tag-mitre D-0007 T1547.001 T1055   # validated vs the workspace's reference
adef detection tag-mitre D-0007 T1055 --remove    # untag (retag seam); emptying re-queues no_mitre
```
`tag-mitre` validates each ID against the ATT&CK reference (invalid ID aborts,
nothing written), merges into the record's `mitre`, drops the `no_mitre` review
reason, and rebuilds the INDEX. Writes only to ADEF's catalog record — never the
source rule. The `mitre-tagger` skill orchestrates this over the whole queue.

### Hunt Promotion (ATHF Integration)
```bash
adef hunt-promote H-0042            # Promote ATHF hunt to draft detection
```

### Sync (reconcile the catalog with the source repo)
```bash
adef sync /path/to/rules            # reconcile: refresh changed rules, keep enrichment
adef sync /path/to/rules --dry-run  # show the plan (unchanged/modified/new/orphaned), write nothing
adef sync /path/to/rules --check    # CI/PR mode: exit 1 if behind, write nothing
```
Re-walks the repo and matches each rule to its record via the identity cascade
(`rule_uuid` → `source_hash` → `rule_ref` path → new; missing source →
**orphaned, never deleted**). On a match, **derived** fields (query, platform,
hashes…) are refreshed while **enrichment** (`mitre`, `status`, `stage`, `owner`,
journal) is preserved — re-syncing never loses your work. Modified rules get a
journal note recording the out-of-band change. Read-only on the source repo.
Core: `adef/core/reconcile.py` (pure cascade) + `adef/commands/sync.py`. Fuzzy
rename-match (UUID-less renamed+edited rules) is deferred → such a rule shows as
`new` for a human to merge, never a silent mis-attribution.

Records carry `origin: authored | catalogued | promoted` (`detection new --source` →
authored; `catalog`/`sync` → catalogued). **`sync` never touches `authored`
records** — they were created in ADEF and have no upstream to reconcile, so a
repo-less team using ADEF as its detection home keeps its own rules through a
sync. `hunt-promote --gates` → `promoted`, which sync also skips: its `rule_ref`
points at a GATES document in the *ATHF* workspace, not a rule repo ADEF walks.
Filter with `adef detection list --origin authored`, or with `catalogued` or
`promoted` — all three are values the records carry, not just `authored`. (One
value per invocation: written `{a,b,c}` this line looked like a usage synopsis
but is shell brace expansion, so pasting it passes all three and Click refuses.)

### Cataloging Existing Rules
```bash
adef catalog /path/to/rules             # Walk a rule repo → catalog/ + INDEX.yml + skeleton journals
adef catalog /path/to/rules --dry-run   # Preview what would be catalogued (nothing written)
adef catalog /path/to/rules --force     # Catalog even if rules are already present (mints duplicates)
adef profile lint <profile.yml>         # Validate an in-house-format extraction profile
adef reindex                            # Rebuild catalog/INDEX.yml from the records
```
Cataloging is read-only on the source repo. It sniffs each file's format
(Sigma YAML, Splunk `.conf`, `.kql`, `.sql`, `.cql`), writes an enrichment
record to `catalog/<platform>/D-XXXX-<slug>.yml` that references the source via
`rule_ref`, and flags rules whose platform/MITRE couldn't be inferred with
`needs_review: true`.

**Re-catalog guard:** if some incoming rules are *already* in the workspace
(matched by the identity cascade), `catalog` **refuses** rather than silently
minting duplicates — it points you to `adef sync` (the reconciling re-run) or
`--force`. Cataloging a genuinely new repo into a populated workspace still
appends cleanly (no identity overlap → no block). `--dry-run` is never blocked.

### Schema Management (declaration-driven)
```bash
adef schema ingest adef-sources.yml     # Build schemas from a data-source declaration
adef schema lint adef-sources.yml       # Validate a declaration (exit 1 on errors)
adef schema check                       # Cross-reference rule field usage vs schemas
adef schema show wineventlog            # Display a schema (schema_version 2)
```
Users provide a declaration document (sources + fields, produced from
`| fieldsummary` / `| getschema` / index mappings). Ingest writes
`schema/<source>.yml` with `declared | corrected` field provenance; re-ingest
preserves human corrections and reports drift. Rules are a schema *consumer*
(via `check`), never a schema *source*.

### Detection Health Capture
```bash
adef ingest health-metrics.yml           # ingest a capture document (routes on its own `kind`)
adef ingest health-metrics.yml --dry-run # validate and report, write nothing
adef health show                         # everything stored: detections, then sources
adef health show D-0001                  # one detection in full + the derived metrics
adef health show --source wineventlog    # one telemetry source (the source-keyed kinds)
```
Five self-describing document kinds — `metrics`, `performance`,
`deployment_drift`, `field_observations`, `source_health` — bulk. The first
three are keyed by `D-XXXX`; `source_health` and `field_observations` are keyed
by a **free-form telemetry source name** and land in `health/sources/`, which
is why `show` reaches them with `--source NAME` rather than positionally (a
free-form name has no shape to dispatch on). Stored under `<workspace>/health/`:
the three detection-keyed kinds as a latest snapshot (newest `captured_at`
wins, so a backfill never replaces newer data) **plus** an append-only `.jsonl`
history (identical rows are not re-appended), the two source-keyed ones
latest-only. ADEF never
queries the environment the numbers came from; the producer hands over a file.

`health show` is the readback half: ingest wrote to `health/` and nothing read
it, so `adef detection evolve` reported `insufficient-data` on numbers the user
had just ingested. `adef/core/health_store.py`'s `tuning_metrics()` is the
counts→ratios adapter (documents carry **counts**
because a ratio can't be re-aggregated across windows). Three rules it
enforces, each with its own test:
- `fp_ratio`'s denominator is what was **adjudicated** (FP + TP), never
  `signal_count` — unlabeled signals aren't known false positives. It needs
  **both** counts present: FPs with no TP count is a valid document (rows
  aren't whitelisted at ingest), and defaulting the absent TP to zero reported
  `fp_ratio: 1.0` about a number nobody supplied.
- `weekly_signal_volume` is normalized by the document's declared window, and
  emitted with `window_days` (the measured span): both recommenders' silence
  arms require ≥ 7 days (`MIN_SILENCE_WINDOW_DAYS`), since zero signals in a
  day says nothing about the week.
- A key is **omitted** when its counts are absent, never emitted as `0.0`:
  both recommenders decide "insufficient data" on key *presence*, so a
  fabricated zero would read as a measured zero. Junk and **negative** values
  count as absent — nothing happens a negative number of times, and the
  derived values are read straight into thresholds.

A `health report` subcommand (a coverage-peer view) is why
`health` is a group, not a bare command with flags.

### ATT&CK Reference Layer
```bash
adef attack info                    # Active snapshot's ATT&CK version + counts
adef attack show T1059.001          # Technique name, tactics, parent, revoked→replacement
adef attack refresh                 # Pull a fresh snapshot from official STIX into the workspace
```
Compact ATT&CK snapshot (`adef/data/attack/enterprise.json`, distilled from
official STIX at build time by `adef/data/attack/_generate.py` — a dev-time
stdlib script, **never a runtime dep**). Consumers: catalog-time `invalid_mitre`
validation and true `by_tactic` INDEX resolution. `refresh` writes to
`$ADEF_WORKSPACE/attack/enterprise.json`, which wins over the shipped copy on read.

### Detection Browsing
```bash
adef detection list                            # all catalogued detections
adef detection list --platform windows --status draft
adef detection list --tactic execution         # by ATT&CK tactic (shortname or display name)
adef detection list --engine sigma             # by internal engine (sigma|sql|sch_sql|composite)
adef detection list --origin authored          # created in ADEF vs catalogued from a repo
adef detection list --needs-review no_mitre    # triage the enrichment queue
adef detection list --report json              # machine-readable (adds a derived `tactics` array)
adef detection show D-0001                     # record + query + derived tactics + journal tail
adef detection search "credential dumping windows"  # BM25 over journals + catalog metadata
```
`list` filters on catalog record fields (`--platform`/`--status`/`--stage`/
`--rule-format`/`--origin`/`--needs-review`) plus `--tactic` and `--engine`, which
are resolved from each detection's ATT&CK technique IDs (`--tactic` accepts the
tactic shortname or display name). `show` renders the record, its query, derived
ATT&CK tactics, a `support` line for recognized-but-unsupported formats, and the
tail of the paired journal. `search` ranks detections by a BM25 index over the
**journal reasoning (the *why*) AND the catalog record** (title, MITRE, platform,
data_source, query — the *what*), so a detection is findable by what it detects
even when its journal is sparse. For a Sigma rule the query part is its
`description`, `tags`, and `logsource`/`detection` blocks, not the whole file
(no references, author, dates, false positives, level or status); snippets
strip template scaffolding to show the matched content. All read-only over the
workspace. (Also exposed as the `memory_search` MCP tool.)

### Coverage Report
```bash
adef coverage                                  # coverage-quality report (terminal)
adef coverage --navigator layer.json           # + a scored MITRE Navigator layer
adef coverage --gaps                            # + list uncovered technique IDs by tactic
```
Not a heatmap — reports coverage *quality* from the catalog with zero human
input: **solid** (depth ≥2, ≥1 reviewed) vs **fragile** (single detection or all
`needs_review`); **log-source concentration** (techniques riding one feed);
**single points of failure** (depth-1 techniques); and **fictional coverage**
(mapped IDs absent from the ATT&CK reference). It also reports **coverage gaps** —
how many ATT&CK techniques you cover of the total (revoked/deprecated excluded),
per tactic, with fully-blind tactics flagged; `--gaps` lists the uncovered
technique IDs by tactic. `--navigator` writes a Navigator v4.5 layer scored by the
same tiers (solid=100, fragile=50) with the why in each comment. Core model:
`adef/core/coverage.py`.

### MCP Server
```bash
adef-mcp                            # Start FastMCP server for Claude Code/Cursor/Copilot
```
`refine_chain` defaults to `similarity_mode="agent"` — it returns the shortlist
enriched for *you* to rank rather than ranking internally, since an MCP caller is
an agent by definition. This deliberately differs from the CLI default (`bm25`):
the split is by entry point, not by detecting which environment you are in.

Tools include `health_ingest` — the MCP twin of `adef ingest`, over the same
core. An assistant session with its own environment tooling connected can fetch
the numbers, write a capture document, and ingest it without shelling out — the
tool takes the document's *path*, like the CLI, and returns the ingest result as
structured data. Its readback twin is `health_show`, and `evolve_chain` mirrors
`adef detection evolve` (Health → Tuning → Deprecation; no mode switch — the
heuristics are deterministic over whatever was ingested). `tune_recommend` and
`deprecation_recommend` both take an optional `workspace` and read the stored
health when their metrics argument is omitted, so an MCP caller doesn't have to
hand-assemble what the CLI's chain derives for it.

### Skills
```bash
adef install-skills                          # numbered-menu prompt: agent, then project/global
adef install-skills --agent claude           # skip the prompt (scriptable/CI)
adef install-skills --agent codex --global   # Codex/ChatGPT, user-wide
adef install-skills --force                  # overwrite skills already installed
```
Run bare, it shows a **numbered menu** for the AI assistant (Claude Code /
Codex) and then project-local vs. global — setup is a rare one-time thing, so it
walks you through it. Any `--agent`/`--global` flag skips the prompt. `codex`
and `chatgpt` are the same target (`.agents/skills/`); `codex` is the menu label
(the Claude Code equivalent), `chatgpt` a flag alias. Destinations: claude →
`.claude/skills/`, codex → `.agents/skills/` (same skill files; only the
location differs). Refuses to
clobber edited local skills without `--force`.

The skills live at `adef/data/claude-plugin/` and ship as `adef.data`
package-data, so this is **not** a clone-only command — a pip install carries
them. They sat at the repo root until 2026-10-09, outside any package, which is
why the published 1.0.0 wheel has none and `install-skills` failed on it.
`tests/test_skills_are_packaged.py` is what keeps the `package-data` globs and
the directory from drifting apart: a glob that stops matching drops files from
the wheel with no build error.

Two ways to get the skills in:
- **`adef install-skills` (primary — all agents, all teams):** copies the skills
  into a `.claude/`/`.agents/` tree so a team can **commit them into their own
  repo**, and so ChatGPT/Codex users get them too, not just Claude. Does *not*
  wire `adef-mcp` — run `adef-mcp` separately (it works in any MCP client:
  Claude, Cursor, Copilot, ChatGPT desktop). This is the path the README and
  quickstart lead with.
- **Plugin marketplace (solo-Claude shortcut):** the repo doubles as a
  marketplace (`.claude-plugin/marketplace.json` → `./adef/data/claude-plugin`,
  the same single copy the wheel ships and `install-skills` reads), so
  `/plugin marketplace add Nebulock-Inc/…` then `/plugin install
  adef@adef-marketplace` bundles the skills **and** the `adef-mcp` wiring in one
  step. Still needs the `[mcp]` extra installed.

### Testing
```bash
pytest                              # Run all tests
pytest -v                           # Verbose output
pytest -k test_journal              # Run specific test pattern
pytest -m unit                      # Run only unit tests (fast)
pytest -m integration               # Run integration tests (requires siblings)
pytest --cov=adef                   # Run with coverage report
```

### Code Quality
```bash
ruff check adef/                    # Lint with ruff
ruff format adef/                   # Format with ruff
mypy adef/                          # Type checking
```

## Architecture

### Package Structure
```
adef/
├── cli.py                      # Click root group + plugin discovery
├── plugin_system.py            # Entry-point discovery (adef.commands, adef.agents, adef.mcp_tools)
├── agents/
│   ├── hypothesis_from_intel.py      # ADEF-native: draft Find/Observe from CTI
│   ├── tune_recommender.py           # ADEF-native: tuning suggestions; reads ingested
│   │                                 #   health via stored_metrics() when no metrics passed
│   ├── deprecation_recommender.py    # ADEF-native: keep/tune/deprecate
│   ├── hunt_promotion.py             # ADEF-native: ATHF hunt → ADEF detection
│   ├── rule_similarity.py            # ADEF-native: BM25 + field-set + value shortlist (fused via RRF);
│   │                                 #   agent returns it for the caller to rank, llm reranks itself
│   ├── rule_overlap.py               # ADEF-native: duplicate/complementary/redundant/unassessed
│   ├── verification.py               # ADEF-native: schema + four-engine constraint
│   └── wrappers/                     # Dispatchers for the 4 rule agents the Refine chain and
│                                     #   tune recommender orchestrate. Similarity/Overlap/
│                                     #   Verification run the native agents above unless
│                                     #   ADEF_WRAPPER_<KEY> is explicitly set; performance-
│                                     #   metrics is the one remaining upstream-only wrapper.
├── commands/
│   ├── detection.py            # FORGE lifecycle commands (new, observe, refine, govern, evolve)
│   ├── init.py                 # Workspace scaffolding
│   ├── hunt_promote.py         # Hunt-to-detection promotion
│   ├── catalog.py              # Walk a rule repo into the catalog (read-only on source)
│   ├── sync.py                 # Reconcile catalog vs. repo; journal repair pass
│   ├── schema.py               # Declaration-driven schemas (ingest/lint/check/recipe/reshape)
│   ├── attack.py               # ATT&CK reference layer (info/show/refresh)
│   ├── coverage.py             # Coverage-quality report + Navigator export
│   ├── ingest.py               # `adef ingest` — detection-health capture documents
│   ├── health.py               # `adef health show` — read back what ingest stored
│   ├── doctor.py               # `adef doctor` — workspace self-check rendering + exit code
│   ├── _render.py              # cell_width/fit/pad — the one table-cell renderer
│   └── profile.py, reindex.py, install_skills.py
├── core/
│   ├── journal.py              # Journal CRUD + stage advancement (NEVER writes to detections/)
│   ├── catalog.py              # CatalogRecord, Catalog, INDEX generation, NoCatalogRecordError
│   ├── memory.py               # BM25 search over journals + catalog records
│   ├── corpus.py               # CorpusEntry + build_corpus — the one membership answer
│   ├── corpus_text.py          # record_search_text() — the record projection search/similarity share; record_query_logic() — for Sigma, only logsource+detection
│   ├── field_index.py          # field-set retrieval — the second, language-agnostic pass
│   ├── value_index.py          # value retrieval — other-language rules testing the same rare literals
│   ├── engines.py              # ALLOWED_ENGINES — the single canonical copy of the 4-engine set
│   ├── health_docs.py          # capture document model, lint, load, isoify
│   ├── health_store.py         # write: latest snapshot + append-only history;
│   │                           #   read: read_latest / tuning_metrics (counts→ratios)
│   └── doctor.py               # pure Check model — the ten workspace answers
├── data/
│   ├── templates/DETECTION_FORGE.md    # Journal template
│   └── prompts/                        # Stage-specific prompts (find.md, observe.md, etc.)
├── mcp/
│   ├── server.py               # FastMCP server + plugin tool discovery
│   └── tools/                  # lifecycle_tools, memory_tools, agent_tools, init_tools
└── orchestration/
    ├── refine_chain.py         # Similarity → Overlap → Verification orchestration
    └── evolve_chain.py         # Health → Tuning → Deprecation; reuses refine_chain's
                                #   `_format_payload` — both chains write one journal
```

### Plugin System (Entry Points)

ADEF uses Python entry points for extensibility (same as ATHF):

**Entry-point groups in `pyproject.toml`:**
- `adef.commands` → Click commands/groups attached to root CLI
- `adef.agents` → Agent classes for orchestration lookup
- `adef.mcp_tools` → Tool registration callables for FastMCP server

**Plugin discovery is defensive**: A broken plugin never kills CLI startup. Failures log to stderr and discovery continues.

### Journal Architecture

**Core invariant**: No `adef.*` code path ever writes to any path under a `detections/` directory. This is CI-enforced by `tests/test_schema_parity.py`.

**Journal lifecycle**:
1. `Journal.create(detection_id)` → writes `journals/D-XXXX.md` from template
2. `Journal.advance_stage(detection_id, stage, note)` → appends timestamped `## [ISO-8601] Stage: <stage>` block, updates frontmatter atomically (temp file + rename)
3. `Journal.read(detection_id)` → returns journal content + parsed frontmatter

**Frontmatter fields**: `id`, `status`, `current_stage`, `owner`, `created`, `updated`, `rule_uuid`

**Stage transitions are idempotent**: Re-advancing to the same stage appends only the note (if provided), no duplicate block.

### Upstream Decoupling via Environment Variables

ADEF never hardcodes upstream package names. Integration uses env vars:

```bash
# Wrapper bindings (optional upstream overrides — native by default since v2)
ADEF_WRAPPER_RULE_SIMILARITY=package.module:RuleSimilarityClass
ADEF_WRAPPER_RULE_OVERLAP=package.module:RuleOverlapClass
ADEF_WRAPPER_VERIFICATION=package.module:VerificationClass
ADEF_WRAPPER_METRICS=package.module:MetricsCollectorClass   # was ADEF_WRAPPER_PERFORMANCE_METRICS (still honoured, deprecated)

# Hunt promotion
ADEF_HUNT_RULE_GENERATOR=athf_package.module:HuntRuleGeneratorClass

# Paths
ADEF_RULE_ROOT=/path/to/upstream/rules      # Read-only rule YAML directory
ADEF_HUNT_ROOT=/path/to/upstream/hunts      # Read-only hunt artifacts directory
ADEF_WORKSPACE=/path/to/adef-workspace      # Override default workspace location
```

For Similarity/Overlap/Verification, a missing binding now runs the native
agent instead of raising `WrapperUnavailable` (PerformanceMetrics has no
native implementation yet and is unaffected by this change). An explicitly
set binding whose import fails still raises `WrapperUnavailable` as before.

### The Refine Chain

When `adef detection refine D-XXXX` runs:
1. Advances stage to `refine`
2. Invokes `orchestration/refine_chain.py`
3. Runs **three steps in sequence, native by default** (v2, 2026-09) — native
   execution and vendor-free execution are not the same guarantee: only
   RuleSimilarity's `bm25` and `agent` modes are vendor-free, and `bm25` is
   the default:
   - **RuleSimilarity** (`adef/agents/rule_similarity.py`): does a rule like
     this already exist? Three retrieval passes, fused by reciprocal rank
     fusion: BM25 nearest-neighbor search over the catalog, plus a
     language-agnostic field-set pass (`adef/core/field_index.py`) that
     matches rules on the telemetry fields their queries filter on (predicate
     fields only — not BY/SELECT/project lists or routing) — canonicalized
     through declared schema aliases so a Sigma rule and a SQL rule reading
     the same field can find each other with zero shared tokens. A third
     pass (`adef/core/value_index.py`) proposes rules in a *different* query
     language that test the same rare values (`bitsadmin.exe`, `EnableLUA`),
     with no schema needed; it never proposes a same-language candidate.
     Only `RuleSimilarity` runs the field and value passes; `adef detection search` stays pure
     BM25 (see `docs/cli-reference.md`). Each run reports a `field_matching`
     state (`schema` / `declared_no_aliases` / `unmatched` / `unparseable`)
     naming how well canonicalization worked; `adef detection refine` prints
     it when the field pass was skipped. The fused shortlist is optionally
     reranked by an LLM judge (`adef detection refine D-XXXX
     --similarity-mode {bm25,agent,llm,auto}`). **`bm25` is the default** and
     makes no network call. **`agent`** returns the shortlist with the
     target's *and* each candidate's query, MITRE IDs, platform, and data source
     for the *caller* to rank — also no network call, and the mode to use from an assistant session,
     where the agent has context ADEF does not and its reasoning lands in the
     transcript. `llm` reranks with an LLM judge; `auto` picks `llm` when
     `ANTHROPIC_API_KEY` and the `llm` extra are both present, else `bm25`.
     **Data egress in `llm`/`auto` mode:** the target's title (unbounded),
     MITRE technique IDs (unbounded count), and query (truncated to 500
     chars; for Sigma, its logsource and detection blocks) are sent to the
     Anthropic API, plus — for each of at most `top_k` shortlisted
     candidates — its detection ID, title (unbounded), and a snippet (up to
     242 chars, built from both the journal body AND the catalog search
     text: title, MITRE IDs, platform, data source, format, query —
     see `record_search_text`; for Sigma rules the query part is the rule's
     `description`, `tags`, and `logsource`/`detection` blocks, not the whole
     file — so catalog and query content can be disclosed too, not just
     journal prose). When a candidate matched via the field-set pass
     (`shared_fields` non-empty), the prompt additionally
     carries that candidate's full `shared_fields` list plus a bounded slice
     (≤200 chars; for Sigma, its logsource and detection blocks) of its own
     query — a field-only candidate has no BM25 snippet, so without this the
     judge would see an entry with no evidence attached at all. A candidate
     found only by the value pass (another query language, no
     `shared_fields`) likewise carries a ≤200-char slice of its query, but
     not its `shared_values` — also **newly disclosed** in `llm` mode. Two things
     worth stating plainly rather than leaving to be discovered:
     `shared_fields` names are drawn from the rule's OWN literal field names
     AND, wherever canonicalization through a declared
     schema applied, their canonical form too (I-1 fix, final whole-branch
     review: canonicalization adds to a rule's literal fields, it never
     replaces them) — so the list can mix a raw name straight from the query
     (`Image`) with a canonical one drawn from the user's own declared schema
     (`process.name`), and either or both may appear depending on what each
     side of the match declared. This still discloses schema vocabulary about
     the environment whenever a canonical name is present, not merely rule
     content; and a field-only candidate could not reach the shortlist at all
     before `field_index.py` existed, so its query slice is **newly disclosed
     data**, not a reshaping of egress that already happened. This same
     mixed-vocabulary `shared_fields` list is also what `agent` mode hands
     back to the caller (unbounded, no truncation — `agent` makes no network
     call, so the ≤200-char query bound above is specific to the `llm` prompt
     and does not apply there). `bm25` and `agent` make no network call,
     unless an `ADEF_WRAPPER_*` override is configured, in which case the
     configured upstream class runs instead and this guarantee no longer
     applies.
   - **RuleOverlap** (`adef/agents/rule_overlap.py`): deterministic
     duplicate/complementary/redundant classification within the target's MITRE
     technique cluster (`catalog/INDEX.yml`'s `by_technique` map): a
     sub-technique and its parent technique are compared; sibling
     sub-techniques are not. A pair in two different query languages is
     `unassessed` — no path compares logic across languages yet
   - **Verification** (`adef/agents/verification.py`): schema field-usage +
     four-engine-constraint check, via `adef.commands.schema.run_schema_check`
     scoped to one detection. Reports `status` (`passed` / `failed` /
     `partial` when the field check couldn't run), per-check `checks`, and
     `fields_not_run_reason`. Grouping/projection columns missing from the
     schema are `missing_grouping_fields` and don't fail it
4. Each result is appended to the detection's journal under `### Refine / <step>` heading
5. Chain does NOT abort on failure; partial results are valuable
6. Each step still honors its `ADEF_WRAPPER_<KEY>` env var as an opt-in override
   — if set, the step delegates to the configured upstream class exactly as
   before v2. Unset (the default) now runs the native implementation instead of
   raising `WrapperUnavailable`. `detection_id` plus any other caller context is
   forwarded to an override — except the chain's native-only kwargs
   (`workspace`, `similarity_mode`), which are filtered out so a
   strict-signature upstream class keeps working.
7. A detection with no catalog record yet (still journal-only) raises
   `NoCatalogRecordError` from the native agent; the chain renders that as
   *"Not run — no catalog record for D-XXXX yet (still journal-only)"*. That's
   a distinct case from `WrapperUnavailable`'s *"isn't configured"*, which now
   only fires for a genuinely broken explicit `ADEF_WRAPPER_*` override.

## Hard Rules (CI-Enforced Anti-Goals)

These are tested and will fail CI if violated:

1. **`tests/test_schema_parity.py`**: Never write inside any `detections/` tree. ADEF is read-only for upstream YAML.
2. **`tests/test_no_new_engine_types.py`**: Only four engines allowed: `sigma`, `sql`, `sch_sql`, `composite`. No new engine types.
3. **`tests/test_no_vendor_connectors.py`**: Never add vendor API connectors (CrowdStrike, Splunk, SentinelOne, etc.). Connectors live in adapter packages.
4. **`tests/test_no_web_ui_deps.py`**: No web UI dependencies (`flask`, `fastapi`, `starlette`, `django`, `next`, `react`). ADEF is CLI + MCP only.

## Process Rules (`.claude/rules/`)

Distinct from the CI-enforced anti-goals above: these bind how work is done, and
no test can catch a violation.

- **`pre-pr-review.md`** — the two review passes and their ordering. Only the
  CodeRabbit CLI can run before a PR exists; `/code-review` reviews an *open*
  PR, so it applies from the second push onward. **Maintainer-local, not in the
  public tree**: it requires a paid authenticated CLI, so publishing it would
  tell a contributor's agent to block on a tool it cannot install. The public
  contract is `CONTRIBUTING.md`'s gate — `pytest`, `ruff check`, `mypy`.
- **`verify-tests-fail.md`** — break the behaviour a test names and confirm it
  goes red before trusting it. Twenty tests in ADEFv2 passed for the wrong
  reason because their fixtures could not reach the code they covered; one let
  a false claim ship into a design doc, a skill file and a PR description. The
  file catalogues the shapes that recur here.

## Key Documentation

Read these to understand the framework:
- **`docs/methodology.md`**: The FORGE lifecycle explained with examples
- **`docs/maturity-model.md`**: L0 (Ad-hoc) → L4 (Agentic) progression
- **`docs/why-adef.md`**: Adoption guide, ADEF vs ATHF relationship
- **`AGENTS.md`**: AI agent briefing for working in this repo

## ADEF and ATHF Relationship

ADEF and ATHF are **paired siblings, not successors**:

| Framework | Lifecycle | Unit of Work | Purpose |
|-----------|-----------|--------------|---------|
| **ATHF** | LOCK (Learn → Observe → Check → Keep) | Hunt (`H-XXXX`) | "Is this happening?" — exploratory |
| **ADEF** | FORGE (Find → Observe → Refine → Govern → Evolve) | Detection (`D-XXXX`) | "Codify this so it pages someone" — production rules |

Hunts graduate to detections via `adef hunt-promote H-XXXX`. Both frameworks share Click + entry-point + FastMCP architecture.

## Development Patterns

### Adding a New CLI Command

1. Create command in `adef/commands/<name>.py` as a Click group or command
2. Register in `pyproject.toml`:
   ```toml
   [project.entry-points."adef.commands"]
   my-command = "adef.commands.my_command:my_command"
   ```
3. Test with `adef --help` (should appear in list)
4. Plugin discovery is automatic via `PluginRegistry.register_commands(cli)` in `adef/cli.py`

### Adding a New Agent

1. Create agent in `adef/agents/<name>.py`
2. Register in `pyproject.toml`:
   ```toml
   [project.entry-points."adef.agents"]
   my-agent = "adef.agents.my_agent:MyAgentClass"
   ```
3. Ensure agent has a `.run()` method compatible with orchestration

### Adding MCP Tools

1. Create tools module in `adef/mcp/tools/<name>.py`
2. Define a `register_mcp_tools(server)` function
3. Register in `pyproject.toml`:
   ```toml
   [project.entry-points."adef.mcp_tools"]
   my-tools = "adef.mcp.tools.my_tools:register_mcp_tools"
   ```
4. Tools are auto-discovered when `adef-mcp` starts

### Working with Journals

```python
from adef.core.journal import Journal, workspace_journals_dir

journals_dir = workspace_journals_dir(None)  # Uses ADEF_WORKSPACE or default
journal = Journal(journals_dir)

# Create
journal.create(detection_id="D-0042", title="My Detection", owner="alice")

# Advance stage
result = journal.advance_stage(detection_id="D-0042", stage="observe", note="Analyzed 30d")

# Read
content = journal.read(detection_id="D-0042")
```

### Memory Search

```python
from pathlib import Path

from adef.core.corpus import build_corpus
from adef.core.memory import MemoryIndex

index = MemoryIndex()
index.build(build_corpus(Path("/path/to/workspace")))
results = index.search("mshta.exe public directory")  # BM25 over CorpusEntry.index_text
```

## Common Patterns

### Atomic File Writes
All journal writes use temp file + `os.replace()` for POSIX atomicity:
```python
from adef.core.journal import _atomic_write
_atomic_write(target_path, content)
```

### Defensive Plugin Loading
All entry-point loads are wrapped to never crash:
```python
from adef.plugin_system import PluginRegistry
commands = PluginRegistry.register_commands(cli)  # Broken plugins log to stderr, don't crash
```

### Stage Prompt Rendering
Stage prompts are markdown files in `adef/data/prompts/`:
```python
from importlib import resources
prompt = resources.files("adef.data").joinpath("prompts/observe.md").read_text()
```

## Version

Current version: **v2.0.0** — `adef/__init__.py` and `pyproject.toml` must
agree; nothing derives one from the other, so
`tests/test_version_agreement.py` is what catches drift. `publish.yml` also
refuses a tag that doesn't match `pyproject.toml`, but that fires only at
release time.

```python
__version__ = "2.0.0"
```
