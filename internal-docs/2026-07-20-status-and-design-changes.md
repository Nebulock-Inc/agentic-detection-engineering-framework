# ADEF Status & Design Changes — 2026-07-20

**For:** the team, to stay in sync
**Branch:** `feature/adef-v1-design` (v0.1.0, unreleased) — latest commit `b489c02`

---

## Where we are

**Working today:**

- **FORGE lifecycle + journals** — `adef detection new/observe/refine/govern/evolve`; per-detection journals with timestamped stage blocks; hunt promotion from ATHF.
- **Catalog** — `adef catalog <repo>` walks any rules repo read-only and produces enrichment records + skeleton journals + INDEX. Recognizes Sigma, Splunk ESCU, Splunk `savedsearches.conf`, Panther, raw KQL/SQL/CQL out of the box. Verified against real corpora: Splunk security_content 2,124 rules, panther-analysis 877, osquery config correctly rejected (0).
- **Extraction profiles (new)** — in-house/unknown rule formats are taught with a small YAML profile, no code. `adef catalog --report json` surfaces unclaimed files with clustering info; `--profile` scores a candidate profile with per-field extraction rates; `adef profile lint` validates.
- **Claude plugin (new)** — `claude-plugin/` bundles the catalog-onboarding skill, the profile-author sub-agent, and `adef-mcp` wiring. The repo root doubles as a plugin marketplace (`/plugin marketplace add Nebulock-Inc/agentic-detection-engineering-framework`).
- **Declaration-driven schema (new)** — `adef schema ingest adef-sources.yml` builds `schema/<source>.yml` per declared source; `schema lint` validates declarations; `schema check` cross-references what fields catalogued rules actually use against declared schemas; `schema show` renders.

**Still roadmap:** `detection list/show/search/coverage/gaps`, `adef sync` (catalog reconciliation), export-from-tool ingestion, `schema list` / per-detection `schema validate`, research commands.

## Design changes made (and why)

### 1. Rule-format support is now declarative profiles, not hand-coded recognizers

The catalog was fighting a long tail: every vendor packaging (and every in-house wrapper) needed a new Python recognizer/extractor pair. We separated the three conflated axes — container (yaml/json/conf/raw), metadata dialect (where title/query/MITRE live), query language (spl/kql/sql/cql) — and made the dialect a data file:

- A profile = signature (container + key sets) + dot-path field map. One generic engine executes all profiles.
- **User profiles are checked before built-ins**, so an org can override how its own format is read.
- The agentic loop makes this scale: the profile-author sub-agent drafts a profile from ~50 samples, the deterministic engine scores it (`--profile` extraction rates), a human approves. The agent never grades its own work.
- Locked decisions: dot-paths + `[]` only (no JSONPath — profiles must stay human-reviewable at the approval gate); container parse returns a *list* of documents (multi-doc contract now, conf/ndjson/ARM containers later); sample cap lives in the agent, file selection in the skill.

### 2. Skills and sub-agents ship as a Claude plugin

Three-layer division of labor: CLI/MCP owns everything deterministic; skills own methodology; sub-agents own context-heavy grunt work returning small artifacts. Skills orchestrate `adef` commands, never reimplement them. MCP stays the portable layer for Cursor/Copilot; the plugin is the Claude-native enhancement.

### 3. Schema ingest simplified: users declare their data, rules are demoted to consumer

Team decision — deriving schemas from rules failed structurally (aliased/calculated/macro-expanded field names; rules only show fields already in use, which is exactly wrong for suggesting new detections). New model:

- Users hand ADEF a **data-source declaration** (`adef-sources.yml`): sources + fields, reshaped in minutes from `| fieldsummary` / `| getschema` / index mappings. Low floor (names only), high ceiling (types, enum values, aliases, descriptions). No event data required or stored.
- Schemas carry **provenance** (`declared | corrected`): re-ingest replaces declared fields, preserves human corrections, reports drift. A future samples path is just a third provenance value.
- **Rules' role inverted**: catalog `data_source` counts tell you what to declare first; `schema check` finds rule fields missing from schemas (broken rule / undocumented alias) and declared fields no rule uses (unexploited detection surface).
- The old machinery was **removed, not deprecated** (unreleased — a grace window protects nobody): `schema init` wizard, `from-catalog`, `update`/`rescan` stubs, MCP `schema_init`, `core/schema.py`, `data_sampler.py`, `llm_client.py`, `scan_rule_fields`, the `llm` extra and `jinja2` dep.

### 4. Strategy positions (from discussion, guiding future work)

- **ADEF must never require being in the write path.** Sync/drift design (not yet built): git-first reconciliation with an identity cascade (rule UUID → hash → path → fuzzy), staleness-aware reads, and auto-journaling of out-of-band edits with harvested commit messages — edits that bypass ADEF become history, not lost value.
- **SIEM-only teams:** the export-into-ADEF loop *is* their first rules repo. Pitch: "you now have version control for your detections." Deploy story is prepare-don't-push, with intended-vs-deployed drift caught on the next export.
- **First-15-minutes value** for a skeptical DE lead should come with zero manual journaling: catalog report, coverage/Navigator layer, duplicate detection (mostly still to build on the reporting side).

## Verification state

- Sandbox smoke suites: 28/28 (profiles/plugin), 31/31 (declaration/cleanup); real-corpora regression exact after every change.
- Anti-goal guards intact by design (no connectors, four engines, no web UI, no `detections/` writes).
- **Pending:** full `pytest` + `ruff check adef/` + `mypy adef/` in a real dev environment (sandbox package index lacks the tooling). Run before pushing; record evidence in ISA `## Verification`.

## Open items

1. Local quality gates (above) — the one blocker before this branch is push-ready.
2. Co-worker sign-off on the two new design docs (`2026-07-20-claude-plugin-design.md`, `2026-07-20-schema-declaration-design.md`) per ISA discipline.
3. Per-SIEM recipe docs: export-for-catalog and field-inventory-for-declaration one-liners (docs only, no code).
4. Plugin skills wave 2: `declaration-author` (profile-author's twin), `journal-backfill`, `forge-stage` (rendered from `adef/data/prompts/`), `coverage-gaps`.
5. `adef sync` design doc (identity cascade + git diffing + auto-journal of upstream changes).
6. Benchmark corpus rates in CI (recognition/extraction % per public repo) so format-support quality is a number, not a feeling.
7. Catalog-time report polish: coverage summary + Navigator layer export (the first-15-minutes wow).

## Key documents

- `docs/plans/2026-07-20-claude-plugin-design.md` — profiles + plugin architecture, resolutions
- `docs/plans/2026-07-20-schema-declaration-design.md` — declaration format, provenance, check
- `docs/plans/2026-07-17-format-detection-plan.md` — recognizer registry (Phase 1 shipped)
- `ISA.md ## Decisions` — 2026-07-20 entries record all of the above
