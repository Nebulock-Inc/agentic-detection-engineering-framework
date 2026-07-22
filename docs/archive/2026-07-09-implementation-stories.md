# ADEF v1 Implementation Stories — 3 Week Sprint

**Epic:** ADEF v1 — Detection Engineering Framework (Layer on Top of Existing Repos)

**Goal:** Build the core ADEF CLI and skills layer that reads/catalogs/journals existing detection repos, assists with authoring new detections, and provides schema-grounded drift detection — all without modifying the source repo or handling deployment.

**Timeline:** 3 weeks (July 9 - July 30, 2026)  
**Team Capacity:** TBD (adjust story assignments accordingly)

---

## Sprint Structure

**Week 1:** Foundation (workspace, backfill, browsing)  
**Week 2:** Lifecycle + Schema (FORGE commands, schema discovery/drift)  
**Week 3:** Authoring + Skills (test recording, skills layer, guidance docs)

---

## Week 1 — Foundation

### Story 1.1: Workspace Initialization & Data Model

**As a** detection engineer  
**I want** to initialize an ADEF workspace  
**So that** I have a structured place to catalog and journal my detections

**Description:**
Implement `adef init` to scaffold the workspace with the three-artifact structure (catalog, journals, schema) and define the YAML schemas for each artifact type.

**Acceptance Criteria:**
- [ ] `adef init` creates `~/work/adef-workspace/` with folders: `catalog/`, `journals/`, `schema/`, `config/`, `templates/`
- [ ] Platform subfolders created: `catalog/windows/`, `catalog/linux/`, `catalog/cloud-aws/`, `catalog/cloud-azure/`, `catalog/identity/`, `catalog/network/`, `catalog/multi-platform/`
- [ ] Same structure mirrored in `journals/`
- [ ] Template files exist: `templates/CATALOG.yml`, `templates/FORGE.md`, `templates/SCHEMA.yml`
- [ ] Catalog YAML schema defined and documented (id, title, rule_ref, platform, kind, engine, mitre, status, stage, owner, created, updated, + slim-ADS fields)
- [ ] Journal markdown schema defined (YAML frontmatter + timestamped stage blocks)
- [ ] Schema artifact YAML defined (source, last_learned, fields with name/type/population)
- [ ] Config file `config/adef.yml` created with sensible defaults
- [ ] Tests: workspace structure exists after `adef init`, templates are valid YAML/markdown

**Effort:** 1 day  
**Dependencies:** None (foundational)  
**Owner:** TBD

---

### Story 1.2: Backfill — Sigma Parser & Catalog Generation

**As a** detection engineer  
**I want** to point ADEF at my existing Sigma detection repo  
**So that** ADEF catalogs and journals every rule without modifying my source repo

**Description:**
Implement `adef backfill --rule-root <path>` to read a Sigma repo, parse each rule, and create catalog + journal entries that reference the original files.

**Acceptance Criteria:**
- [ ] `adef backfill --rule-root /path/to/rules` command works
- [ ] Sigma parser implemented (using `pySigma` or custom YAML parser):
  - Extracts: title, logsource → platform mapping, detection logic, tags → MITRE (if present)
  - Maps logsource to platform (e.g., `category: process_creation` → `windows`, `product: linux` → `linux`)
  - Infers `kind: atomic` (Sigma is almost always atomic), `engine: sigma`
- [ ] For each rule, writes:
  - `catalog/<platform>/D-XXXX-<slug>.yml` with `rule_ref` (relative or absolute path to original file)
  - `journals/<platform>/D-XXXX.md` with empty Find stage block (backfill doesn't invent history)
- [ ] `D-XXXX` ID allocated sequentially (starting from D-0001)
- [ ] `INDEX.yml` generated at workspace root with:
  - `detections`: map of `D-XXXX` → catalog path
  - `by_platform`, `by_tactic`, `by_engine`, `by_status` reverse indexes
- [ ] Handles parsing errors gracefully (logs warning, skips rule, continues)
- [ ] Tests: backfill a fixture repo (5-10 Sigma rules) → verify catalog, journals, INDEX

**Effort:** 1.5 days  
**Dependencies:** Story 1.1 (workspace structure)  
**Owner:** TBD

---

### Story 1.3: Detection Browsing & Coverage Queries

**As a** detection engineer  
**I want** to query and view my cataloged detections  
**So that** I can find what I already have and identify coverage gaps

**Description:**
Implement read-only CLI commands to list, show, and analyze detections using the INDEX and catalog.

**Acceptance Criteria:**
- [ ] `adef detection list` works with filters:
  - `--platform windows` (reads `INDEX.yml` → `by_platform`)
  - `--tactic execution` (reads → `by_tactic`)
  - `--engine sigma` (reads → `by_engine`)
  - `--status ready` (reads → `by_status`)
  - Multiple filters combine with AND logic
  - Outputs table: ID, Title, Platform, Status, Stage
- [ ] `adef detection show D-0047` works:
  - Reads catalog YAML (pretty-prints all fields)
  - Reads journal markdown (prints full history)
  - Handles missing detection gracefully (error message)
- [ ] `adef coverage` works with optional filters:
  - `--tactic execution` (counts detections per tactic)
  - `--actor APT28` (if actors field populated)
  - Outputs coverage summary: tactic → count, highlights gaps (tactics with 0 detections)
- [ ] Tests: backfill fixture, run list/show/coverage commands, verify output

**Effort:** 0.5 day  
**Dependencies:** Story 1.2 (catalog + INDEX exist)  
**Owner:** TBD

---

## Week 2 — Lifecycle + Schema

### Story 2.1: FORGE Lifecycle State Transitions

**As a** detection engineer  
**I want** to advance detections through FORGE stages  
**So that** every lifecycle transition is journaled with rationale

**Description:**
Implement the four lifecycle commands (observe, refine, govern, evolve) that append timestamped journal blocks and update catalog state atomically.

**Acceptance Criteria:**
- [ ] `adef detection observe D-XXXX --note "..."` works:
  - Appends `## [ISO-8601] Stage: observe` block to journal
  - Updates catalog: `stage: observe`, `updated: <now>`
  - Atomic writes (temp file + rename) for both catalog and journal
- [ ] `adef detection refine D-XXXX` works (same pattern)
- [ ] `adef detection govern D-XXXX` works:
  - Checks readiness gates: owner set, severity set, response guidance written, peer-review note present
  - If gates pass → `status: ready`, appends Govern block with gate evidence
  - If gates fail → error message listing missing gates
- [ ] `adef detection evolve D-XXXX --note "..."` works
- [ ] Idempotency: re-advancing to the same stage appends only the note (if provided), no duplicate heading
- [ ] Tests: advance through FORGE stages, verify journal blocks + catalog updates

**Effort:** 1 day  
**Dependencies:** Story 1.1 (catalog/journal schemas)  
**Owner:** TBD

---

### Story 2.2: Schema Discovery — Learn Command

**As a** detection engineer  
**I want** to teach ADEF what my data looks like  
**So that** detections can be grounded in real field availability

**Description:**
Implement `adef schema learn <source> --results -` to infer schema from sampled data rows and persist the schema artifact.

**Acceptance Criteria:**
- [ ] `adef schema learn <source> --results -` (or `--results <file>`) works:
  - Reads rows from stdin or file (JSON array of objects, or CSV)
  - Infers schema:
    - Field names from keys
    - Types (heuristic: if parseable as int/float/bool, type it; else string)
    - Population rate (% non-null across sample)
  - Writes `schema/<source>.yml`:
    ```yaml
    source: edr_process
    last_learned: 2026-07-09T...
    sample_window: "30d"  # user can pass via --window flag
    sample_size: 10000
    fields:
      - name: parent_image
        type: string
        population: 0.98
        sample_values: ["C:\\Windows\\System32\\cmd.exe", "mshta.exe", ...]
      - name: command_line
        type: string
        population: 0.85
    ```
  - Writes `schema/schema.lock` (SHA256 hash of schema YAML for drift detection)
- [ ] Handles malformed input gracefully (error message)
- [ ] Tests: pipe sample JSON/CSV, verify schema artifact, verify hash in lock file

**Effort:** 1 day  
**Dependencies:** Story 1.1 (workspace structure)  
**Owner:** TBD

---

### Story 2.3: Schema Drift Detection

**As a** detection engineer  
**I want** to re-run schema discovery and see what changed  
**So that** I can identify detections that may be broken by data drift

**Description:**
Implement `adef schema diff <source> --results -` to compare a new sample against the stored schema and report which detections are affected by drift.

**Acceptance Criteria:**
- [ ] `adef schema diff <source> --results -` works:
  - Learns schema from new sample (same logic as `learn`)
  - Loads stored `schema/<source>.yml`
  - Compares:
    - Fields added (in new, not in stored)
    - Fields removed (in stored, not in new)
    - Population changes (threshold: >10% change is flagged)
  - Outputs drift report:
    ```
    Drift detected in source 'edr_process':
      • Field 'command_line': population 0.85 → 0.40 (degraded)
      • Field 'new_field': added
      • Field 'old_field': removed
    
    Affected detections (reference drifted fields):
      • D-0001 (mshta-suspicious-child-process) — uses command_line
      • D-0009 (powershell-encoded-command) — uses command_line
    ```
  - Affected detection lookup: greps catalog YAML files for field names in the drift set
  - Updates `schema/<source>.yml` and `schema.lock` with new schema
- [ ] `adef schema show <source>` works (pretty-prints stored schema)
- [ ] Tests: learn schema, modify sample data, diff, verify drift report + affected detections

**Effort:** 1 day  
**Dependencies:** Story 2.2 (schema learn)  
**Owner:** TBD

---

## Week 3 — Authoring + Skills

### Story 3.1: Detection Test — Query Run Recording

**As a** detection engineer  
**I want** to record query test results in the journal  
**So that** every iteration is remembered and I can see what was tried

**Description:**
Implement `adef detection test D-XXXX --results -` to ingest query results and append a Test block to the journal with row count, samples, and verdict.

**Acceptance Criteria:**
- [ ] `adef detection test D-XXXX --results -` (or `--results <file>`) works:
  - Reads rows from stdin or file (JSON/CSV)
  - Computes: row count, sample (first 3 rows, redacted if --redact flag passed)
  - Reads detection catalog to get query (from `rule_ref` or inline `query`)
  - Appends to journal:
    ```markdown
    ### [ISO-8601] Refine / Test
    Query: <extracted from rule_ref or inline>
    Source: <inferred from schema or user-provided via --source flag>
    Result: 1,240 rows
    Sample (first 3):
      - parent: mshta.exe, child: powershell.exe, cmdline: -enc ...
      - parent: mshta.exe, child: InstallHelper.exe
      - parent: mshta.exe, child: wscript.exe
    Verdict: <user can add via --verdict flag, or left blank for skill to fill>
    ```
  - Handles missing detection gracefully (error)
- [ ] Optional `--verdict "too noisy, exclude InstallHelper.exe"` flag adds verdict to journal block
- [ ] Tests: pipe sample results, verify journal Test block

**Effort:** 0.75 day  
**Dependencies:** Story 1.1 (journal schema), Story 2.2 (schema for source inference, optional)  
**Owner:** TBD

---

### Story 3.2: Skills Installation & Discovery Guidance

**As a** detection engineer  
**I want** to install ADEF skills into my agent environment  
**So that** I can use agentic workflows to research, author, and tune detections

**Description:**
Implement `adef skills install` and write guidance docs for schema discovery and rule authoring.

**Acceptance Criteria:**
- [ ] `adef skills install [--target .claude]` works:
  - Copies 5 skill markdown files from `adef/data/skills/` to target directory
  - Skills: `adef-research.md`, `adef-author.md`, `adef-schema.md`, `adef-coverage.md`, `adef-evolve.md`
  - Default target is `.claude/` (detects via env or common paths)
  - Supports `--target` override for Cursor/Copilot
  - Version-pins skills to CLI (adds version check or warning if mismatch)
- [ ] Skill files exist in `adef/data/skills/` (stub implementations OK for this story; detail in 3.3):
  - Each skill is a markdown file with skill frontmatter (name, description, when-to-use)
  - Each has a "how to invoke" section and "what it does" outline
- [ ] Guidance docs written:
  - `docs/schema-discovery-guide.md`: how to sample your data (example queries for Splunk/Elastic/SQL), what ADEF needs (JSON/CSV format), how to pipe to `adef schema learn`
  - `docs/writing-good-rules-with-agents.md`: primer for users on helping agents write quality detections (be specific about intent, provide examples from your corpus, iterate with test runs)
- [ ] Tests: run `adef skills install`, verify files copied, verify guidance docs readable

**Effort:** 1 day  
**Dependencies:** None (can run parallel with other stories)  
**Owner:** TBD

---

### Story 3.3: Skills Implementation — The Brain Layer

**As a** detection engineer  
**I want** skills that think and call the CLI  
**So that** I can use agentic workflows for complex detection tasks

**Description:**
Implement the 5 skill workflows (research, author, schema, coverage, evolve) as markdown skill files that orchestrate CLI commands.

**Acceptance Criteria:**
- [ ] **adef-research** skill works:
  - Prompt includes: "Given CTI input (URL or text), extract behaviors, map MITRE, check corpus for coverage, ground in schema"
  - Calls: `adef coverage --tactic <T>`, `adef detection list --tactic <T>`, `adef schema show <source>`
  - Outputs: prioritized candidates with gap/coverage verdict ("Build new for T1218.005 — clean gap, we have data" OR "Extend D-0005 — 70% covered, just add Startup folder variant")
  - Proposes (doesn't execute) `adef detection new` commands
- [ ] **adef-author** skill works:
  - Prompt includes: "Draft detection grounded in schema, iterate with test runs, run refine chain"
  - Calls: `adef schema show <source>` (reads before drafting), `adef detection observe/refine/test`, guides user to run query via their transport, interprets test results
  - Iterates on logic based on test verdicts (noisy → tighten, missing cases → broaden)
- [ ] **adef-schema** skill works:
  - Prompt includes: "Guide user through sampling, call schema learn, interpret drift reports"
  - Guides user: "Run this query in your SIEM: `SELECT * FROM edr_process LIMIT 10000` and pipe to `adef schema learn edr_process --results -`"
  - On diff: interprets drift report, explains impact ("command_line went null → D-0001, D-0009 may be broken")
- [ ] **adef-coverage** skill works:
  - Prompt includes: "Analyze MITRE coverage, surface gaps, recommend prioritization"
  - Calls: `adef coverage`, interprets output, highlights top gaps
  - Reads INDEX directly if deeper analysis needed (optional)
- [ ] **adef-evolve** skill works:
  - Prompt includes: "Given journal history + drift report + signal volume, recommend tune/keep/deprecate"
  - Calls: reads journal (via file read), interprets drift from user paste, recommends with rationale
  - Proposes `adef detection evolve D-XXXX --note "..."` with filled reasoning
- [ ] All skills use the CLI as the commit layer (no direct file writes)
- [ ] Tests: invoke each skill in a test harness (mock CLI calls), verify correct commands issued

**Effort:** 2 days  
**Dependencies:** Story 3.2 (skills installer), all prior CLI commands (1.1-3.1)  
**Owner:** TBD

---

## Summary — Story Map

| Week | Story | Title | Effort | Dependencies |
|------|-------|-------|--------|--------------|
| 1 | 1.1 | Workspace Initialization & Data Model | 1d | None |
| 1 | 1.2 | Backfill — Sigma Parser & Catalog Generation | 1.5d | 1.1 |
| 1 | 1.3 | Detection Browsing & Coverage Queries | 0.5d | 1.2 |
| 2 | 2.1 | FORGE Lifecycle State Transitions | 1d | 1.1 |
| 2 | 2.2 | Schema Discovery — Learn Command | 1d | 1.1 |
| 2 | 2.3 | Schema Drift Detection | 1d | 2.2 |
| 3 | 3.1 | Detection Test — Query Run Recording | 0.75d | 1.1, (2.2 optional) |
| 3 | 3.2 | Skills Installation & Discovery Guidance | 1d | None (parallel) |
| 3 | 3.3 | Skills Implementation — The Brain Layer | 2d | 3.2, all CLI commands |

**Total Effort:** ~9.75 days (ideal, single engineer)  
**Parallelization:** Stories 2.1, 2.2 can run in parallel (both depend on 1.1 only). Story 3.2 can run parallel with 3.1. With 2 engineers: ~6-7 calendar days. With 3 weeks and interrupts/reviews: achievable.

---

## Out of Scope (Deferred Post-v1)

These are intentionally NOT in the 3-week sprint:

- **MCP Server** (`adef-mcp`) — CLI-first; add MCP once CLI is stable (v1.1 or v2)
- **Generated views/** (`by-tactic/execution.md`) — INDEX is enough; views are sugar (v2)
- **Non-Sigma parsers** (Splunk, Elastic, KQL) — Sigma-first, others community-driven (v2)
- **ATHF integration** (`adef hunt-promote`) — standalone first (v2)
- **Acceptance criteria pass/fail** in Story 3.1 — deferred (requires FP-rate calculation, which needs labeled data or heuristics; v2)
- **Auto-write ADEF-authored rules to their repo** — manual copy for v1, opt-in auto-write later (v1.1)

---

## Testing Strategy

Each story has inline acceptance criteria tests. Additionally:

- **Integration tests** (end-to-end):
  - Backfill fixture repo → browse → advance through FORGE → schema learn/diff → test recording
  - Run all CLI commands in sequence, verify workspace state
- **Fixture repo**: Create a `tests/fixtures/sigma-rules/` with 5-10 sample Sigma rules (mix of Windows/Linux, different tactics) for backfill/browsing tests

---

## Definition of Done (Per Story)

- [ ] Acceptance criteria met (all checkboxes ticked)
- [ ] Unit tests written and passing
- [ ] Integration test coverage (if applicable)
- [ ] CLI help text written (`adef <command> --help`)
- [ ] Error handling for common failure modes (missing files, malformed input)
- [ ] Code reviewed by peer
- [ ] Documentation updated (if user-facing change)

---

## Epic Acceptance Criteria (v1 Complete)

- [ ] All 9 stories complete
- [ ] End-to-end demo works: backfill → browse → advance → schema → test → skills
- [ ] Guidance docs published (`schema-discovery-guide.md`, `writing-good-rules-with-agents.md`)
- [ ] README updated with quickstart
- [ ] Tagged release: `v1.0.0`
