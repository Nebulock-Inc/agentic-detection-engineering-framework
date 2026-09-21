# ADEF Architecture — High-Level System Design

**Date:** 2026-07-07  
**Purpose:** Visual/conceptual architecture for team review before implementation  
**Status:** Pre-build design (locked scope from 2026-07-01 decisions)

---

## The Big Picture

ADEF is **the layer on top of your existing detection repository.** It reads what you
have, organizes it, journals it, helps you author new detections, and keeps everything
schema-grounded — without modifying your source repo or touching deployment.

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER (Detection Engineer)                     │
│  "Research this APT" · "Author a detection" · "Did our data     │
│   change?" · "Should we keep D-0042?"                           │
└────────────┬─────────────────────────────────────┬──────────────┘
             │                                     │
             │ invokes skills                     │ or calls CLI directly
             ▼                                     ▼
┌─────────────────────────────┐      ┌────────────────────────────┐
│   SKILLS (optional brain)    │      │   CLI (always-on engine)    │
│                             │──────▶│   adef detection *          │
│  adef-research              │ calls │   adef schema *             │
│  adef-author                │  CLI  │   adef backfill             │
│  adef-schema                │       │   adef coverage             │
│  adef-coverage              │       │   All state writes here     │
│  adef-evolve                │       └────────────┬───────────────┘
└─────────────────────────────┘                    │ reads/writes
                                                   ▼
                        ┌───────────────────────────────────────────┐
                        │   WORKSPACE  ~/work/adef-workspace/       │
                        │  ┌─────────────────────────────────────┐  │
                        │  │ catalog/     D-XXXX.yml              │  │
                        │  │   (enrichment records)               │  │
                        │  │   - references their-repo rule       │  │
                        │  │   - adds: MITRE, platform, kind,     │  │
                        │  │     tags, strategy, status, stage    │  │
                        │  └─────────────────────────────────────┘  │
                        │  ┌─────────────────────────────────────┐  │
                        │  │ journals/    D-XXXX.md               │  │
                        │  │   (history: why/when/decisions)      │  │
                        │  │   - timestamped FORGE stage blocks   │  │
                        │  │   - test results, tuning notes       │  │
                        │  └─────────────────────────────────────┘  │
                        │  ┌─────────────────────────────────────┐  │
                        │  │ schema/      <source>.yml            │  │
                        │  │   (learned data shape)               │  │
                        │  │   - fields, types, population        │  │
                        │  │   - drift detection on re-run        │  │
                        │  └─────────────────────────────────────┘  │
                        │  ┌─────────────────────────────────────┐  │
                        │  │ INDEX.yml  (generated lookup)        │  │
                        │  │   D-0001 → catalog path              │  │
                        │  │   by-tactic, by-platform, by-engine  │  │
                        │  └─────────────────────────────────────┘  │
                        └───────────────────────────────────────────┘
                                         │
                          reads (never writes)
                                         ▼
                        ┌───────────────────────────────────────────┐
                        │   THEIR DETECTION REPO                     │
                        │   ~/work/their-detections/                 │
                        │     windows/mshta.yml                      │
                        │     linux/cron_persistence.yml             │
                        │     ... (Sigma, Splunk, whatever)          │
                        │                                            │
                        │   (Source of truth for rule logic)         │
                        │   (ADEF never modifies this)               │
                        └────────────────────────────────────────────┘
```

**Key invariants:**
- **ADEF never writes to the detection repo.** It's read-only. Catalog records
  *reference* rules via `rule_ref:` (a path pointer).
- **All state writes go through the CLI.** Skills think and recommend; the CLI commits.
- **Three artifacts, three jobs:** catalog (what + enrichment), journal (why + when),
  schema (can we build it?).

---

## The Three Artifacts (What ADEF Owns)

### 1. Catalog Record — `catalog/<platform>/D-XXXX-<slug>.yml`

The **enrichment layer** on top of their rule. References the rule, adds value.

```yaml
id: D-0001
title: Suspicious mshta.exe child process
rule_ref: ../../their-repo/windows/mshta.yml    # pointer to THEIR file
platform: windows
kind: atomic                # ADEF's categorization
engine: sigma               # extracted from rule
mitre: [T1218.005]          # extracted or added
status: ready               # draft | ready | tuning | deprecated
stage: govern               # find | observe | refine | govern | evolve
owner: alice
created: 2026-07-01
updated: 2026-07-05

# Slim-ADS strategy fields (ADEF-added documentation)
goal: Catch mshta.exe spawning suspicious child processes
strategy: Monitors process_create for parent_image=mshta.exe + unusual children
assumptions: [EDR process logging enabled, parent_image populated]
blind_spots: [Renamed mshta.exe, legitimate admin tools using mshta]
false_positives: [Patching tools, software installers]
priority: medium
response: Isolate endpoint, review parent process context, check network connections
```

**What it adds beyond the rule:**
- **Organization**: platform folder, INDEX lookup, tags.
- **MITRE mapping** (auto-extracted on backfill if in Sigma tags, else manual).
- **Lifecycle state**: status (draft → ready → tuning → deprecated), stage (FORGE).
- **Documentation**: slim-ADS strategy fields (goal, blind spots, FPs, response).

**The rule logic stays in their repo.** ADEF reads it via `rule_ref`, never rewrites it.

---

### 2. Journal — `journals/<platform>/D-XXXX.md`

The **memory artifact**. Answers "why does this exist? what's been tried? what's next?"

```markdown
---
id: D-0001
detection_title: Suspicious mshta.exe child process
current_stage: govern
last_updated: 2026-07-05
---

# Detection Journal: D-0001

## [2026-07-01T10:23:00Z] Stage: find
**Source:** CTI report https://example.com/apt42
**Motivation:** APT42 uses mshta.exe for defense evasion.
**MITRE:** T1218.005
**Hypothesis:** Catch mshta spawning unusual children (powershell, cmd, wscript).

## [2026-07-01T14:15:00Z] Stage: observe
**Telemetry check:** Queried 30d of process_create events.
- parent_image field: 98% populated
- command_line field: 85% populated (was 95% last quarter — drift?)
- Volume: ~1.2M process_create/day

**Baseline normal:** mshta.exe spawns 12 distinct children in 30d, mostly legit
(svchost, dllhost, patching tool "InstallHelper.exe").

## [2026-07-02T09:00:00Z] Stage: refine
### Similarity Check
No duplicate. Closest match: D-0005 (generic script interpreter monitoring), 40% overlap.

### Overlap Analysis
Minor overlap with D-0005 on powershell children; acceptable.

### Verification
Schema: PASS (all referenced fields exist in schema/edr_process.yml)
Engine: PASS (valid Sigma, four-engine constraint satisfied)

### Test Run 1
Query: (Sigma rule from their-repo/windows/mshta.yml)
Source: edr_process
Result: 1,240 rows over 30d
Sample:
  - parent: mshta.exe, child: powershell.exe, cmdline: -enc ...
  - parent: mshta.exe, child: InstallHelper.exe (patching tool)
  - parent: mshta.exe, child: wscript.exe
Verdict: Too noisy — InstallHelper.exe is a known FP (patching tool).

### Test Run 2
Query: (Sigma rule, added exclusion for InstallHelper.exe)
Result: 14 rows over 30d
Sample: All look suspicious (powershell -enc, wscript with encoded payloads).
Verdict: PASS — FP rate ~0%, target 2%.

## [2026-07-05T11:30:00Z] Stage: govern
**Owner:** alice
**Severity:** medium
**Response guidance:** Isolate endpoint, review parent context, check network.
**Peer review:** Reviewed by @sam, approved.
**Deployment gate:** PASS (owner set, response written, peer-reviewed).
Status → ready.

(Detection deployed via team pipeline 2026-07-05.)
```

**What it captures:**
- **Why it exists** (Find: source CTI, motivation).
- **What telemetry was checked** (Observe: field populations, volumes, baseline).
- **How it was iterated** (Refine: test runs, exclusions added, verdicts).
- **Who owns it and why** (Govern: gates passed, peer review).

**Volatile facts (test results, tuning notes) live here as timestamped entries, NOT in
the catalog YAML.** The catalog is the *current* state; the journal is the *history*.

---

### 3. Schema — `schema/<source>.yml`

The **ground truth** about your data shape. Answers "can we even write this?"

```yaml
source: edr_process
last_learned: 2026-07-01T10:00:00Z
sample_window: 30d
sample_size: 10000 rows

fields:
  - name: parent_image
    type: string
    population: 0.98        # 98% of events have this field
    sample_values: ["C:\\Windows\\System32\\cmd.exe", "mshta.exe", ...]

  - name: command_line
    type: string
    population: 0.85        # dropped from 0.95 last quarter (drift!)
    sample_values: ["powershell.exe -enc ...", null, ...]

  - name: process_id
    type: integer
    population: 1.0

  - name: timestamp
    type: datetime
    population: 1.0
```

**How it's used:**
- **Authoring:** The `adef-author` skill reads this before drafting logic. If a
  detection wants `command_line` but population is 15% (mostly null), the skill warns
  or suggests an alternative.
- **Drift detection:** Re-run `adef schema diff edr_process --results -` weeks later.
  If `command_line` population drops to 40%, the diff report flags:
  - "Field `command_line` degraded: was 85%, now 40%"
  - "Affected detections: D-0001, D-0009" (catalog YAMLs that reference `command_line`)
  - Engineer runs `adef-evolve` on those detections → recommends tuning.

**How it's learned:**
- User samples their data however they already do (a query via their SIEM/tool).
- Pipes rows to `adef schema learn edr_process --results -` (results-in seam).
- ADEF infers schema from the sample (field names, types, population rates).
- No vendor connector; ADEF just reads the rows you hand it.

---

## The INDEX (Fast Lookup)

**`INDEX.yml`** is generated (never hand-edited) by `adef backfill` and `adef reindex`.

```yaml
detections:
  D-0001: catalog/windows/D-0001-mshta-suspicious-child-process.yml
  D-0002: catalog/cloud-aws/D-0002-iam-backdoor-user.yml
  D-0005: catalog/windows/D-0005-lsass-memory-access.yml
  # ...

by_platform:
  windows: [D-0001, D-0005, ...]
  linux: [D-0012, ...]
  cloud-aws: [D-0002, ...]

by_tactic:
  execution: [D-0001, D-0005, ...]
  defense-evasion: [D-0001, ...]
  persistence: [D-0012, ...]

by_engine:
  sigma: [D-0001, D-0005, D-0012, ...]
  sql: [D-0002, ...]

by_status:
  ready: [D-0001, D-0005, ...]
  draft: [D-0012, ...]
  tuning: []
  deprecated: []
```

**Why it exists:**
- **O(1) lookup.** `adef detection show D-0001` reads INDEX → path, no tree walk.
- **Fast filtering.** `adef detection list --tactic execution --platform windows`
  intersects two INDEX lists, no grep.
- **Coverage queries.** `adef coverage --tactic execution` reads `by_tactic`, counts.
- **Drift reports.** `adef schema diff` greps catalog YAMLs for field references,
  uses INDEX to map file → detection ID.

**When it's regenerated:**
- After `adef backfill` (initial catalog creation).
- After any detection add/edit (automatic).
- Manually via `adef reindex` (e.g., if you moved files by hand).

---

## The Two Interfaces (CLI + Skills)

### CLI — The Engine (Always Required)

**All state writes go here.** CI-enforced invariants (no upstream writes, four engines
only, no vendor connectors) live in CLI code, not model memory.

```bash
# Workspace
adef init
adef reindex

# Backfill (Day 0)
adef backfill --rule-root ~/their-detections

# Browsing (read-only)
adef detection list [--platform] [--tactic] [--engine] [--status]
adef detection show D-0047
adef coverage [--tactic] [--actor]

# FORGE lifecycle (state transitions)
adef detection observe  D-0047 --note "checked telemetry"
adef detection refine   D-0047
adef detection test     D-0047 --results -    # ingest query results
adef detection govern   D-0047 --note "peer-reviewed by @sam"
adef detection evolve   D-0047 --note "tuned threshold"

# Schema (living data artifact)
adef schema learn <source> --results -
adef schema diff  <source> --results -
adef schema show  <source>

# Skills installer
adef skills install [--target .claude]
```

**The CLI is pip-installable, works headless, and is CI-friendly.** No agent required.

---

### Skills — The Brain (Optional)

**Five coarse workflows** a detection engineer invokes. Each skill *thinks* (research,
draft, recommend), then *calls the CLI* to commit state.

| Skill | Job | Calls |
|-------|-----|-------|
| **adef-research** | CTI → detection candidates, *gap-checked* (do we already cover this?) + *schema-grounded* (can we build it on our data?). Outputs prioritized, deduped, buildable candidates. | `adef coverage`, `adef detection list`, `adef schema show` (reads), then proposes (no write) |
| **adef-author** | Drafts a detection: reads schema, writes logic grounded in real fields, picks kind/engine, fills slim-ADS fields. Runs the refine chain (similarity/overlap/verification), iterates with test runs. | `adef detection observe/refine/test` |
| **adef-schema** | Guides user through sampling their data, then calls schema learn/diff. Interprets drift reports ("command_line went null → these detections may be broken"). | `adef schema learn/diff` |
| **adef-coverage** | "Do we already cover X? Where are the gaps?" Reads INDEX + MITRE, produces coverage/partial-coverage verdicts. | `adef coverage`, `adef detection list` (reads only) |
| **adef-evolve** | Reads journal history + drift report + (pasted) signal volume → recommends tune/keep/deprecate with rationale. | `adef detection evolve` |

**Install:** `adef skills install` drops 5 markdown skill files into `.claude/`.

**Guidance docs** (for users helping the agent):
- `docs/schema-discovery-guide.md` — how to sample your data for schema learning.
- `docs/writing-good-rules-with-agents.md` — primer on helping the agent write quality rules.

---

## Data Flow — The Critical Paths

### Path 1: Day 0 (Backfill Existing Repo)

```
User's detection repo (Sigma files)
         │
         │ adef backfill --rule-root ~/their-detections
         ▼
    [Sigma parser]
         │ reads each .yml
         │ extracts: title, logsource→platform, MITRE, logic
         ▼
    For each rule:
      - Write catalog/<platform>/D-XXXX.yml (rule_ref points to their file)
      - Write journals/<platform>/D-XXXX.md (empty Find block)
         │
         ▼
    Generate INDEX.yml (D-XXXX → path, reverse maps)
         │
         ▼
    RESULT: Cataloged, organized, journaled — their repo untouched
```

**The catalog is now queryable.** `adef detection list --tactic execution` works.

---

### Path 2: Authoring a New Detection (Research → Author → Ship)

```
USER: Drops CTI report into agent, invokes /adef-research

adef-research skill:
  1. Extracts behaviors, maps MITRE
  2. Calls `adef coverage --tactic T1218` → "no coverage for T1218.005"
  3. Calls `adef schema show edr_process` → confirms fields exist
  4. Recommends: "Build new detection for mshta (clean gap, we have data)"

USER: "Build it"

adef-author skill:
  5. Reads schema/edr_process.yml (grounds in real fields)
  6. Drafts Sigma logic (not written to their repo yet — just in memory)
  7. Calls `adef detection observe D-0047 --note "schema checked"` → journal block
  8. USER runs query via their own tool (SIEM/script) → returns 1,240 rows
  9. Pipes results to `adef detection test D-0047 --results -` → journal Test block
     "Too noisy (1,240 hits), tighten exclusions"
  10. Re-drafts logic, re-runs (14 hits), re-tests → "PASS"
  11. Calls `adef detection refine D-0047` → similarity/overlap/verification chain
      (results appended to journal)
  12. Writes the finalized Sigma rule to... WHERE?

USER: Manually copies the drafted rule into ~/their-detections/windows/mshta.yml
      (or ADEF writes it there if configured — see Open Q1 resolution)
      Updates catalog D-0047 `rule_ref: ../../their-detections/windows/mshta.yml`

USER: `adef detection govern D-0047 --note "peer-reviewed by @sam"`
      → status: ready, journal records gate evidence

USER: Deploys via their own pipeline (ADEF doesn't deploy)
```

**Key handoff point (step 12):** The drafted rule needs to land in their repo. Two
options:
- **Manual:** User copies it (low friction but manual).
- **Auto (if configured):** ADEF writes to their repo if `config/adef.yml` sets
  `rules_root:` and user opts in. (Per meeting decision: "point at existing repo" —
  so likely manual for v1, auto as opt-in later.)

---

### Path 3: Schema Drift → Tuning Recommendation

```
Weeks after D-0047 shipped...

USER: Re-samples data, pipes to `adef schema diff edr_process --results -`

adef schema diff:
  1. Learns schema from new sample
  2. Compares to stored schema/edr_process.yml
  3. Detects: "command_line field: was 85% populated, now 40%"
  4. Greps catalog YAMLs for "command_line" references
  5. Finds: D-0001, D-0047 use command_line
  6. Outputs drift report:
     "Field command_line degraded. Affected: D-0001, D-0047."

USER: Invokes /adef-evolve D-0047 (pastes signal volume: 0 hits last 30d)

adef-evolve skill:
  7. Reads journals/windows/D-0047.md → sees it was tuned to 14 hits/30d
  8. Reads drift report → command_line went null
  9. Reason: "0 hits + field null = likely broken by logging change, not real drop"
  10. Recommends: TUNE — switch to image-path match (survives null)

USER: Updates their rule (edits ~/their-detections/windows/mshta.yml)
USER: `adef detection evolve D-0047 --note "switched to image-path, command_line unreliable"`
      → journal records the tuning decision
```

**The schema artifact feeds back into the lifecycle at Evolve.**

---

## The Results-In Seam (No Vendor Connectors)

ADEF never reaches into a SIEM/EDR/data lake. Instead, it defines a **results-in
contract**: you run queries/sampling however you already do (your MCP, script, API),
and pipe rows to ADEF.

**Three places this seam is used:**

1. **Query testing** — `adef detection test D-XXXX --results -`
   - User runs the detection logic via their own tool → gets rows (JSON/CSV).
   - Pipes to `adef detection test` → ADEF records row count, sample, verdict.
   
2. **Schema learning** — `adef schema learn <source> --results -`
   - User samples their data (e.g., `SELECT * FROM process_create LIMIT 10000` via
     their SIEM).
   - Pipes rows → ADEF infers schema (field names, types, population).

3. **Schema diffing** — `adef schema diff <source> --results -`
   - User re-samples weeks later, pipes rows → ADEF compares to stored schema,
     outputs drift report.

**Format:** JSON (array of objects) or CSV. Example:
```json
[
  {"parent_image": "mshta.exe", "child_image": "powershell.exe", "command_line": "-enc ..."},
  {"parent_image": "cmd.exe", "child_image": "whoami.exe", "command_line": null}
]
```

**Why this works:**
- **Zero vendor coupling.** ADEF ships no Splunk/Elastic/Sentinel/CrowdStrike connectors.
- **Composable.** Works with MCP servers, scripts, adapters, even manual exports.
- **CI-enforceable.** `tests/test_no_vendor_connectors.py` guards this.

**The agent (skills) can drive the user's transport via their existing MCP.** The skill
says "run this query via your Splunk MCP," gets results, pipes to `adef detection test`.
ADEF just consumes the results.

---

## What ADEF Does NOT Do (v1 Scope Boundaries)

### ❌ Does Not Extract Rules from a SIEM
- **Assumes:** Detections live as files in a repo.
- **Future:** Could add SIEM export support via the same results-in seam (export → pipe
  to `adef backfill --results -`), but v1 is file-based only.

### ❌ Does Not Deploy Rules
- **ADEF tracks readiness** (`status: ready`), not live state.
- **The team deploys** via their own pipeline (CI/CD, manual SIEM upload, whatever).
- **Govern stage** is a *documentation gate*, not a deployment action.

### ❌ Does Not Modify the Team's Detection Repo
- **ADEF is read-only** on their repo. Catalog records *reference* rules (`rule_ref:`).
- **Exception (open for discussion):** ADEF-authored *new* rules — where do they land?
  (Manual copy vs auto-write if configured — team to decide.)

### ❌ Does Not Ship Vendor Connectors
- **Results-in seam** means ADEF ingests rows you hand it, never reaches out.
- **"Allow integrations, don't provide them"** — same DNA as ATHF.

### ❌ Does Not Parse Non-Sigma Formats (v1)
- **Sigma parser only** for backfill auto-enrichment (extract MITRE, platform, kind).
- **Future:** Splunk, Elastic, KQL parsers as community-driven or v2 work.

---

## Implementation Chunks (For Reference)

See `2026-07-01-meeting-summary-open-questions.md` for the 7-chunk build plan. In order:

1. **Workspace + data model** (init, schemas, templates)
2. **Backfill** (Sigma parser, catalog/journal creation, INDEX generation)
3. **Browsing** (list, show, coverage — read-only CLI)
4. **FORGE lifecycle** (observe/refine/govern/evolve — state transitions)
5. **Schema** (learn, diff, show — living data artifact)
6. **Detection test** (query run recording)
7. **Skills layer** (5 skills + guidance docs)

**Week 1 target:** Chunks 1-4 (workspace, backfill, browsing, lifecycle) = usable CLI.  
**Week 2 target:** Chunks 5-7 (schema, test, skills) = full agentic surface.

---

## Open Design Questions (Already Decided, For Context)

From the 2026-07-01 meeting:
- **Q1 (ADEF-authored rules → pipeline):** Point at existing repo. Mechanism TBD (manual
  copy vs auto-write if configured).
- **Q2 (Rule-writing assistance):** Schema-grounded + few-shot from corpus. Guidance
  docs for users.
- **Q3 (ATHF integration):** Standalone for v1. No unified workspace yet.
- **Q4 (athf detect overlap):** Build ADEF first; remove overlap eventually.
- **Q5 (Format parsers):** Sigma-first; others later.

---

## Summary — What to React To

**For the team:**
1. Does the three-artifact split (catalog, journal, schema) make sense? Any artifacts
   missing or redundant?
2. Is the INDEX lookup model clear, or does it feel like over-engineering?
3. The results-in seam (no vendor connectors, just pipe rows) — does this match how
   teams would actually use it, or is it too manual?
4. The "ADEF never modifies their repo" rule — is this the right default, or should
   ADEF be allowed to write *new* rules into their repo (with a config gate)?
5. Skills calling CLI (brain/engine split) — does this feel like the right interface
   experience, or should skills be more autonomous?

**Next step:** If this architecture lands well, start Chunk 1 (workspace + data model)
this week.
