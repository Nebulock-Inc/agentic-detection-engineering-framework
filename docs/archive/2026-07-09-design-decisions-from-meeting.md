# ADEF Design Decisions — Team Meeting Notes

**Date:** 2026-07-09  
**Epic:** https://app.shortcut.com/nebulock/epic/6996 (Black Hat 2026 objective)  
**Purpose:** Capture team design decisions and open questions for Claude Code context

---

## Design Decisions (Locked)

### 1. Rule Storage Format

**Decision:** Rules will be stored in their **native detection language** (SPL for Splunk, SQL, KQL, Sigma YAML, etc.) within the ADEF YAML files.

**Details:**
- The ADEF detection file includes:
  - The **native query** (copied verbatim from the original rule)
  - A **reference** to the original rule file (`original_path`)
  - **Enrichment metadata** (MITRE, platform, kind, slim-ADS strategy fields)
  - A **journal reference** (`journals/<platform>/D-XXXX.md`)
  
- The ADEF file acts as a **catalog/workbench**, NOT the sole source of truth.
  - The user's original repo remains authoritative for the rule logic
  - ADEF wraps it with metadata, documentation, and journal history

**Example structure:**
```yaml
# detections/windows/D-0001-mshta-suspicious-child.yml
id: D-0001
title: Suspicious mshta.exe child process
platform: windows
kind: atomic
engine: sigma
mitre: [T1218.005]
status: draft
stage: find

# Slim-ADS enrichment
goal: Catch mshta.exe spawning suspicious child processes
strategy: Monitors process_create for parent_image=mshta.exe + unusual children
# ... (more enrichment fields)

# Native rule logic (copied verbatim from their repo)
query: |
  title: Suspicious mshta.exe child process
  id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
  logsource:
      category: process_creation
      product: windows
  detection:
      selection:
          ParentImage|endswith: '\mshta.exe'
          Image|endswith:
              - '\powershell.exe'
              - '\cmd.exe'
      condition: selection
  # ... (full Sigma rule)

# Reference to original
original_path: /Users/jarrett/their-repo/windows/mshta.yml
```

**Rationale:** Preserves the user's existing rule exactly as-is, no lossy conversion. ADEF provides the organization, memory, and enrichment layer on top.

---

### 2. Cataloging Existing Rules (Backfill)

**Decision:** A CLI tool (`adef backfill --rule-root <path>`) will recursively traverse a user's detection repo, classify files by extension/content, and generate ADEF detection files.

**Details:**
- **Multi-format discovery:** Walks the repo, sniffs file types (Sigma YAML, Splunk `.conf`, KQL `.kql`, SQL `.sql`, Elastic TOML/JSON, etc.)
- **Auto-tagging:** Attempts to extract/infer:
  - Platform (from logsource, table names, comments)
  - MITRE techniques (from tags, comments, descriptions)
  - Detection kind (atomic vs correlation, heuristic-based)
  - Engine type (sigma, spl, kql, sql, etc.)
- **User prompts for ambiguity:** When uncertain (e.g., raw SQL file with no comments), prompts user for clarifying info or leaves fields `null` for manual correction
- **Graceful failures:** Parse errors → log warning, skip file, continue. Unknown formats → listed in summary for manual review.

**Supported formats (v1):**
- **Sigma** (`.yml` with `detection:` + `logsource:`) — full auto-extraction
- **Splunk** (`.conf` savedsearches) — parse stanzas, heuristic platform/MITRE
- **KQL** (`.kql`) — infer platform from table names (DeviceProcessEvents → windows)
- **SQL** (`.sql`) — similar to KQL
- **(Optional) Elastic** (`.toml`, `.json`) — if time allows

**Output:** ADEF detection files in `catalog/<platform>/D-XXXX.yml` + journals in `journals/<platform>/D-XXXX.md` + `INDEX.yml` for fast lookup.

**Rationale:** Meets users where they are — no migration required. Auto-extraction gets them 80% there; they review/fix the remaining 20%.

---

### 3. Data Schema Catalog

**Decision:** The preferred method for schema ingestion is for users to **run a provided query in their platform** (Splunk, Elastic, SQL, etc.), export the schema, and import it via CLI.

**Details:**
- **User-driven sampling:**
  - ADEF provides example queries for common platforms (Splunk: `| head 10000 | table *`, SQL: `SELECT * FROM table LIMIT 10000`)
  - User runs query, exports results (JSON/CSV)
  - Pipes to `adef schema learn <source> --results -`
  - ADEF infers: field names, types, population rates
  
- **Fallback — inference from detections:**
  - If no schema is provided, ADEF scans cataloged detections and extracts referenced fields
  - Less accurate (doesn't know population rates), but functional
  
- **Default mappings for common sources:**
  - ADEF ships with stub schemas for well-known sources (Sysmon, CrowdStrike, Windows Security Event Logs, CloudTrail)
  - Users without schema or detections can start with these defaults and refine
  
- **Schema catalog is NOT required for initial use:**
  - Backfill works without schema (just catalogs rules)
  - Schema enhances authoring (field availability checks) and coverage analysis (data source gaps)

**Schema artifact structure:**
```yaml
# schema/edr_process.yml
source: edr_process
last_learned: 2026-07-09T10:00:00Z
sample_size: 10000
fields:
  - name: parent_image
    type: string
    population: 0.98
  - name: command_line
    type: string
    population: 0.85
  # ...
```

**Rationale:** No vendor connectors in the framework (ADEF doesn't reach into SIEMs). User provides data, ADEF learns from it. Aligns with "allow integrations, don't provide them" principle.

---

### 4. Syncing with Source Repo (Read-Only Model)

**Decision:** The ADEF catalog is **not the source of truth**; it wraps the user's existing repo. There needs to be a **reconciliation mechanism** to detect and handle changes made outside of ADEF.

**Details:**
- **ADEF never writes to the user's detection repo** (read-only on their files)
- **Changes made outside ADEF:**
  - If a user edits `their-repo/windows/mshta.yml` directly (bypassing ADEF), the ADEF catalog (`catalog/windows/D-0001.yml`) becomes stale
  - Reconciliation detects this by comparing file hashes or timestamps
  
- **Reconciliation workflow (to be implemented):**
  - `adef sync` command:
    - Reads each catalog entry's `original_path`
    - Checks if the original file changed (hash mismatch or mtime newer than ADEF catalog `updated`)
    - If changed: re-extracts metadata, updates catalog, appends journal note ("Detected external change")
    - If deleted: flags catalog entry as orphaned, prompts user
    - If new files added to their repo: prompts to backfill the new rules
  
- **User workflow:**
  - Edit rules directly in their repo (ADEF doesn't block this)
  - Periodically run `adef sync` to reconcile
  - ADEF updates its catalog to reflect external changes

**Open design question (see below):** How aggressive should sync be? Auto-detect on every command, or manual user-triggered only?

**Rationale:** ADEF rides alongside the user's repo, doesn't replace it. This is a feature, not a bug — preserves their existing workflows and tooling.

---

### 5. CLI/Skill Functionality

**Decision:** CLI tools will support listing, searching, and displaying detections with filters. Skills will be **optional but recommended**, providing advanced features.

**Details:**
- **CLI (always available):**
  - `adef detection list --platform windows --tactic execution`
  - `adef detection show D-0047`
  - `adef coverage --tactic defense-evasion`
  - Deterministic, scriptable, CI-friendly
  
- **Skills (optional install via `adef skills install`):**
  - `adef-research` — CTI → detection candidates, gap-checked + schema-grounded
  - `adef-author` — drafts detections, iterates with test runs
  - `adef-schema` — guides schema discovery, interprets drift
  - `adef-coverage` — analyzes MITRE coverage, highlights gaps
  - `adef-evolve` — tune/keep/deprecate recommendations
  - Skills think (research, draft, recommend), then call CLI to commit state
  
**Rationale:** CLI is the engine (integrity guarantees, state writes). Skills are the brain (agentic workflows, complex orchestration). Both are valuable, neither is mandatory for the other.

---

### 6. Story/Work Breakdown Priority

**Decision:** Cataloging detections (backfill) and building the data schema catalog are the **two foundational (and most complex) stories** for the next sprint. Detection browsing and coverage queries are simpler and can be developed in parallel or after.

**Sprint priorities (3 weeks):**
1. **Week 1:** Workspace + backfill (multi-format discovery) + browsing
2. **Week 2:** FORGE lifecycle + schema (learn/diff)
3. **Week 3:** Detection test recording + skills layer

**Critical path:**
- Backfill (Story 1.2) depends on workspace (Story 1.1)
- Everything else depends on backfill (need a catalog to browse/lifecycle/schema-link)
- Skills (Story 3.3) depend on all CLI commands being complete

**Rationale:** Get detections cataloged first (the foundational artifact). Everything else builds on that.

---

## Open Questions for Claude (Needs Team Input)

### Q1: Reconciliation Between ADEF Catalog and Source Repo

**Question:** How should we handle reconciliation between the ADEF catalog and the original detection repo if changes are made outside of ADEF?

**Context:**
- ADEF's catalog wraps the user's repo (read-only)
- User can edit rules directly in their repo, bypassing ADEF
- ADEF's catalog becomes stale when this happens

**Options:**

**A. Manual sync only (`adef sync` command):**
- User explicitly runs `adef sync` to reconcile
- Compares file hashes/mtimes, re-extracts metadata, updates catalog
- Pro: Explicit control, no surprises
- Con: Easy to forget; catalog can be stale for weeks

**B. Auto-sync on read (check on every `adef detection show/list`):**
- Every time ADEF reads a catalog entry, checks if original file changed
- If stale, auto-updates catalog inline
- Pro: Catalog always fresh
- Con: Performance overhead (stat() call per detection); could be slow for large repos

**C. Periodic background sync (cron/scheduled):**
- ADEF runs a background sync task daily/weekly
- Pro: Keeps catalog fresh without manual intervention
- Con: Requires a daemon or cron setup; out of scope for v1?

**D. Sync on write only (detect staleness, warn, require manual sync):**
- When user tries to `adef detection refine D-XXXX`, ADEF checks if original file changed
- If stale, error: "Original rule changed externally. Run `adef sync D-XXXX` first."
- Pro: Prevents operating on stale data
- Con: Blocks user workflows; requires sync before every operation

**Recommendation for discussion:** Start with **A (manual `adef sync`)** for v1. Add **D (staleness check on write)** as a safety gate. Defer auto-sync (B/C) to v2 after we see real-world usage patterns.

---

### Q2: Auto-Tagging and Organizing by Platform/Type

**Question:** What is the best way to auto-tag and organize detections by platform/type when the source format is ambiguous?

**Context:**
- Raw KQL/SQL files often have no metadata (no comments, no MITRE tags)
- Platform must be inferred from table names (DeviceProcessEvents → windows) or keywords
- MITRE tags often missing or in freetext comments

**Current approach (heuristic-based):**
1. **Platform inference:**
   - KQL: table name → platform (DeviceProcessEvents → windows, AzureActivity → cloud-azure)
   - SQL: table name heuristics (syslog → linux, security_event → windows)
   - Fallback: prompt user or set to `multi-platform`
   
2. **MITRE extraction:**
   - Sigma: extract from `tags:` field
   - Others: regex search for `T\d{4}` in comments/descriptions
   - Fallback: leave `mitre: []` empty, user fills later
   
3. **Kind inference:**
   - Sigma: always `atomic` (single-event)
   - SQL/KQL with JOIN/stats: `correlation` (heuristic)
   - Fallback: `atomic`

**Options for improvement:**

**A. Keep heuristics, provide easy correction path:**
- Accept that auto-tagging is 80% accurate
- After backfill, show summary: "12 detections need review (platform inferred, MITRE missing)"
- Provide `adef detection update D-XXXX --platform linux --mitre T1059.001` for quick fixes
- **(Recommended for v1)**

**B. Interactive prompts during backfill:**
- When ambiguous, pause and ask: "File mshta.kql — Platform? [windows/linux/multi]: "
- For large repos (hundreds of rules), this is painful
- Only prompt for high-confidence ambiguities (e.g., SQL files with no table name hints)?

**C. Post-backfill enrichment skill:**
- Backfill does best-effort auto-tagging
- After backfill, user runs `adef-enrich` skill
- Skill reads each detection with missing/uncertain metadata, prompts LLM to infer from query logic
- User reviews LLM suggestions, accepts/rejects
- **(Good for v2, too heavy for v1)**

**Recommendation for discussion:** **A (heuristics + easy correction)** for v1. Accept imperfection; provide fast tooling to fix mistakes. Add **C (LLM-assisted enrichment skill)** in v2.

---

### Q3: Schema Catalog Structure

**Question:** How should we structure the schema catalog for maximum flexibility and ease of use, given the variety of possible data sources and formats?

**Current proposal:**
- One YAML file per data source: `schema/<source>.yml`
- Master inventory: `data-sources/inventory.yml` (lists all sources with metadata)
- Schema files are flat (array of fields with name/type/population)

**Alternatives considered:**

**A. Hierarchical schemas (nested fields):**
```yaml
# schema/windows_security.yml
fields:
  - name: EventData
    type: object
    fields:
      - name: CommandLine
        type: string
      - name: User
        type: string
```
Pro: Matches real data structure (JSON events with nested objects)  
Con: More complex to query/diff; most detections flatten fields anyway

**B. Separate schema per platform per vendor:**
```
schema/
├── windows/
│   ├── crowdstrike_process.yml
│   ├── sysmon_process.yml
│   ├── windows_security.yml
├── cloud-aws/
│   ├── cloudtrail.yml
```
Pro: Organizes by platform (mirrors catalog structure)  
Con: Source names need namespacing (edr_process vs crowdstrike_edr_process?)

**C. Single unified schema file (all sources in one YAML):**
```yaml
# schema/all.yml
sources:
  - id: edr_process
    fields: [...]
  - id: cloudtrail
    fields: [...]
```
Pro: Simple, one file to manage  
Con: Gets huge (thousands of lines); hard to diff

**Recommendation for discussion:** **Keep current proposal (one file per source + inventory)** for v1. Flat field structure is simplest and covers 95% of use cases. Add nested/hierarchical in v2 if users need it.

---

### Q4: Minimal Required Metadata

**Question:** What is the minimal set of metadata we should require or infer for each detection to ensure catalog usefulness without overburdening the user?

**Current proposal (fields in catalog YAML):**

**Required (enforced by backfill or CLI):**
- `id` (auto-allocated)
- `title` (extracted or user-provided)
- `platform` (inferred or user-prompted)
- `kind` (atomic/correlation/composite, inferred or defaulted)
- `engine` (sigma/spl/kql/sql, inferred from file type)
- `query` (native rule logic, copied verbatim)

**Optional but recommended (can be null/empty on backfill):**
- `mitre` (extracted if present, else empty array)
- `data_sources` (linked to data source inventory, filled during authoring/review)
- `owner` (null on backfill, set via `adef detection govern`)
- `status` (defaults to `draft`)
- `stage` (defaults to `find`)

**Slim-ADS fields (always optional, filled during FORGE lifecycle):**
- `goal`, `strategy`, `assumptions`, `blind_spots`, `false_positives`, `priority`, `response`

**Trade-offs:**
- **More required fields** → better catalog out-of-the-box, but painful for large repos or ambiguous formats
- **Fewer required fields** → easier backfill, but catalog less useful (lots of nulls)

**Recommendation for discussion:** Current split is good. Only enforce the 6 "required" fields. Everything else can be enriched over time as detections move through FORGE stages. The catalog is useful even with minimal metadata (you can still list/search/browse).

---

### Q5: Large Repo Prompt Optimization

**Question:** How can we optimize the user prompt flow for large repos (hundreds of rules) to minimize manual input while ensuring accuracy?

**Context:**
- A team with 500 Sigma rules can backfill fully automated (Sigma has all metadata)
- A team with 500 raw KQL files needs human input for ambiguous cases (platform, MITRE)
- Prompting for every ambiguous file = 200+ interactive prompts (painful)

**Options:**

**A. Batch prompting with preview:**
- After discovery, show summary: "Found 237 KQL files. 180 inferred as Windows, 42 ambiguous. Review ambiguous batch?"
- User reviews list of ambiguous files, sets platform in bulk: "Files 1-30 are Linux, 31-42 are Windows"
- Faster than one-by-one, still accurate

**B. Infer-and-flag (no prompts during backfill):**
- Backfill makes best guess for everything (never prompts)
- Tags ambiguous detections with `needs_review: true`
- After backfill: `adef detection list --needs-review` → 42 detections
- User corrects via CLI or skill

**C. Sample-based prompting:**
- For 200 ambiguous KQL files, prompt for 5-10 samples
- User answers: "These 5 are Windows, these 3 are Linux"
- Apply learned pattern to remaining files heuristically
- Risk: incorrect generalization

**D. Skip ambiguous, manual-add later:**
- Backfill only auto-catalogs high-confidence files
- Ambiguous files listed in `backfill_skipped.txt`
- User manually adds via `adef detection new --query-file <file>`

**Recommendation for discussion:** **B (infer-and-flag)** for v1. Backfill never blocks on prompts (runs unattended). User reviews flagged detections afterward at their own pace. Add **A (batch prompting)** as an interactive mode (`adef backfill --interactive`) in v2 if users want it.

---

### Q6: Schema/Data Extraction Integrations

**Question:** Should we support integrations for schema/data extraction out of the box, or only provide guidelines for manual export/import?

**Context:**
- Schema discovery requires sampling data from the SIEM/data lake
- Current approach: user runs a query, exports results, pipes to ADEF (manual, but no connectors)
- Alternative: ADEF ships Splunk/Elastic/SQL connectors that fetch data directly

**Trade-offs:**
- **Manual export/import (current):**
  - Pro: No vendor connectors, zero maintenance, aligns with "allow not provide" principle
  - Con: Extra step for users; have to figure out the export themselves
  
- **Ship integrations:**
  - Pro: Smoother UX; one command (`adef schema learn splunk://index=main`)
  - Con: Maintenance burden (Splunk API changes, auth tokens, network issues), vendor coupling

**Recommendation for discussion:** **Stick with manual export/import for v1.** Provide **excellent documentation** (`docs/schema-discovery-guide.md`) with example queries for every major platform (Splunk, Elastic, Sentinel, SQL, BigQuery, etc.). Users copy-paste, run, export, pipe to ADEF. If demand is high, add **optional connector plugins** in v2 (community-maintained, not bundled with ADEF core).

---

### Q7: Versioning and Updates (Schema + Catalog Evolution)

**Question:** How should we handle versioning and updates to the schema and detection catalogs as users' environments evolve?

**Context:**
- Schemas drift over time (new fields added, old fields deprecated)
- Detections change (queries tuned, MITRE mappings updated)
- ADEF's catalog needs to track this evolution

**Current approach:**
- **Schema:** `adef schema diff` detects drift, produces report
- **Detections:** Journal tracks all changes (timestamped FORGE stage transitions, notes)
- **Catalog YAML:** Has `updated` timestamp, but no version number

**Open questions:**

**7a. Should catalog entries have version numbers?**
- Example: `version: 3` in catalog YAML, incremented on every update
- Pro: Clear audit trail ("this detection is on version 5")
- Con: What does "version" mean? Is it rule version or metadata version?

**7b. Should journals track diffs, or just notes?**
- Current: journals are freeform markdown (timestamped notes)
- Alternative: structured diff blocks (YAML showing old → new values)
- Pro: Machine-readable history (could generate changelog)
- Con: Verbose, harder to read for humans

**7c. Should schema files store history (previous samples)?**
- Example: `schema/edr_process.yml` keeps last 3 learned schemas
- Pro: Can compare "schema as of 30 days ago" vs now
- Con: Files get large; diffs are noisy

**Recommendation for discussion:** Keep it simple for v1:
- **No version numbers** in catalog (use `updated` timestamp + journal for history)
- **Journals stay freeform markdown** (human-readable, timestamped notes)
- **Schema stores only current state** (no history in the file itself; diff reports are ephemeral)

If versioning becomes important (e.g., for compliance/audit), add it in v2 with a clear versioning policy.

---

## Summary — Next Steps

**Design decisions locked (ready to implement):**
1. ✅ Rule storage format (native logic inline, ADEF wraps with metadata)
2. ✅ Cataloging approach (multi-format backfill, heuristic auto-tagging)
3. ✅ Data schema catalog (user-driven sampling, optional, enhances authoring)
4. ✅ Syncing model (ADEF is read-only on their repo, reconciliation via `adef sync`)
5. ✅ CLI/skills split (CLI = engine, skills = brain, both valuable)
6. ✅ Sprint priorities (backfill + schema are foundational, week 1-2 focus)

**Open questions need team input (discussion agenda):**
1. ❓ **Q1 — Reconciliation:** Manual sync only, or auto-sync on read/write?
2. ❓ **Q2 — Auto-tagging:** Heuristics + correction, or interactive prompts?
3. ❓ **Q3 — Schema structure:** Flat files per source, or hierarchical/unified?
4. ❓ **Q4 — Minimal metadata:** Current split (6 required, rest optional) OK?
5. ❓ **Q5 — Large repo prompts:** Infer-and-flag, or batch prompting?
6. ❓ **Q6 — Integrations:** Manual export/import, or ship connectors?
7. ❓ **Q7 — Versioning:** Timestamps + journals, or explicit version numbers?

**Recommended for next meeting:**
- Quick vote on Q1, Q2, Q5, Q6 (those impact Story 1.2 implementation urgency)
- Q3, Q4, Q7 are refinements; current proposals are fine for v1, revisit in v2 if needed

**Epic tracking:** https://app.shortcut.com/nebulock/epic/6996 (6 stories, 28 points)
