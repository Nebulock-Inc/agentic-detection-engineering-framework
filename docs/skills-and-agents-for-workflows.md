# Skills & Sub-Agents for ADEF Workflows

**Updated:** 2026-06-25  
**Purpose:** Map CLI commands to conversational skills and autonomous agents

---

## Overview

The CLI commands provide **programmatic access**. Skills and agents provide **conversational and autonomous access** to the same capabilities.

**Three layers:**
1. **CLI commands** — Scripting, automation, direct invocation
2. **Claude Code skills** — Conversational wrappers for interactive work
3. **Autonomous agents** — Background processes, scheduled analysis

---

## Skills (Claude Code / Cursor / Copilot)

Skills are conversational wrappers that make CLI commands easier to discover and use in natural language.

### 1. Detection Explorer Skill

**Purpose:** Help users discover, search, and navigate detections

**Triggers:**
- "Show me all detections at Refine stage"
- "What detections does Alice own?"
- "Find detections about LSASS dumping"
- "Which detections haven't been updated in 2 weeks?"

**What it does:**
1. Translates natural language to CLI commands
2. Runs `adef detection list/search/show`
3. Formats results conversationally
4. Suggests next actions

**Example conversation:**
```
User: Show me all detections at Refine stage

Skill: Let me check your detections in Refine stage.

[Runs: adef detection list --stage refine --format json]

I found 4 detections currently at Refine stage:

1. **D-0002** - LSASS memory dumping (Owner: Bob, Updated: 2 days ago)
2. **D-0003** - Kerberoasting via Rubeus (Owner: Bob, Updated: 1 day ago)
3. **D-0007** - WMI lateral movement (Owner: Alice, Updated: 3 days ago)
4. **D-0012** - Mimikatz via memory (Owner: Carol, Updated: 4 days ago)

Would you like me to:
- Show details for any of these?
- Check why they're stuck at Refine?
- Advance one to Govern stage?
```

**CLI commands used:**
- `adef detection list`
- `adef detection show`
- `adef detection search`

---

### 2. Coverage Analyst Skill

**Purpose:** Analyze ATT&CK coverage, identify gaps, recommend priorities

**Triggers:**
- "What's our coverage for Credential Access?"
- "Show me gaps in our detection program"
- "What should I build next?"
- "Do we detect T1003.001?"

**What it does:**
1. Runs `adef detection coverage`
2. Analyzes gaps with `adef detection gaps`
3. Cross-references with recent CTI
4. Recommends priority detections to build

**Example conversation:**
```
User: What's our coverage for Credential Access?

Skill: Let me analyze your Credential Access coverage.

[Runs: adef detection coverage --tactic credential-access --format json]
[Runs: adef detection gaps --tactic credential-access --format json]

**Credential Access Coverage: 62% (8 of 13 techniques)**

✅ Covered:
- T1003.001 - LSASS Memory (3 detections: D-0002, D-0012, D-0034)
- T1558.003 - Kerberoasting (1 detection: D-0003)
- T1110.003 - Password Spraying (2 detections: D-0018, D-0025)

❌ Gaps:
- T1003.003 - NTDS.dit (HIGH priority - seen in recent FIN7 activity)
- T1003.007 - /etc/shadow (MEDIUM priority)
- T1555.003 - Browser credentials (LOW priority)

Recommendation: Build T1003.003 detection next - highest risk, recent threat intel.

Would you like me to:
- Research T1003.003 to draft a detection?
- Show details of existing T1003.001 detections?
- Export coverage report?
```

**CLI commands used:**
- `adef detection coverage`
- `adef detection gaps`
- `adef detection list --technique`

---

### 3. Detection Researcher Skill

**Purpose:** Research threats and generate detection drafts

**Triggers:**
- "Research this CTI report for detections: [URL]"
- "Generate detection drafts for CVE-2024-1234"
- "What detections should we build for FIN7?"
- "Research LSASS dumping techniques"

**What it does:**
1. Fetches CTI source (URL, CVE, actor profile)
2. Extracts TTPs and maps to MITRE ATT&CK
3. Runs `adef detection coverage` to check existing coverage
4. Generates detection drafts with Find/Observe starters
5. Creates research document via `adef research new`
6. Suggests which drafts to build first

**Example conversation:**
```
User: Research this Mandiant report for detections: https://example.com/fin7-report

Skill: I'll research that FIN7 report and identify detection opportunities.

[Fetches report, extracts TTPs]
[Runs: adef detection coverage --format json]
[Runs: adef research new --cti-url https://example.com/fin7-report]

**Research Summary (R-0005):**

Found 5 TTPs, 3 have coverage gaps:

1. **T1218.005 - Mshta.exe** [HIGH PRIORITY - No coverage]
   - Behavior: Mshta.exe from writable public directories
   - Data source: Process creation (Sysmon ID 1, Event ID 4688)
   - Baseline: <5 events/day in benign environments
   - Draft query ready

2. **T1059.001 - PowerShell** [MEDIUM - Partial coverage]
   - Existing: D-0023 covers basic PowerShell execution
   - Gap: PowerShell with mshta.exe parent not covered
   - Enhancement opportunity

3. **T1547.001 - Registry Run Keys** [MEDIUM - No coverage]
   - Behavior: Persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   - Data source: Registry monitoring
   - Draft query ready

Would you like me to:
- Create detection from draft #1 (mshta.exe)?
- Show the full research document?
- Compare draft #2 with existing D-0023?
```

**CLI commands used:**
- `adef research new`
- `adef research show`
- `adef detection coverage`
- `adef detection new --from-research` (proposed)

---

### 4. Schema Discovery Assistant Skill

**Purpose:** Help discover and validate data source schemas

> **Updated 2026-07-20:** connector-based discovery was dropped (anti-goal).
> This skill is now the **declaration-author** — profile-author's twin: the
> user pastes whatever field inventory they have, the skill reshapes it into
> a declaration, lints it, and ingests on approval.

**Triggers:**
- "Here's my fieldsummary output for Splunk security logs"
- "What fields are available in my EDR?"
- "Check if process_name exists in wineventlog"
- "Set up the schema for my Sentinel tables"

**What it does:**
1. Asks the user for a field inventory (Splunk `| fieldsummary`, KQL
   `| getschema`, Elastic `_mapping`, a vendor data dictionary — any shape)
2. Reshapes it into a data-source declaration (`adef-sources.yml`)
3. Validates with `adef schema lint`; user approves
4. Runs `adef schema ingest`; summarizes fields per source
5. Runs `adef schema check` to cross-reference existing rules

**Example conversation:**
```
User: [pastes | fieldsummary output for WinEventLog:Security]

Skill: That's 47 fields. Drafting a declaration...

  - EventCode (int) — values look enum-ish, keeping top 10
  - CommandLine, user (+ aliases User/user_name spotted in your rules)
  ...

[Writes adef-sources.yml; runs: adef schema lint adef-sources.yml → OK]

Approve ingest? [User: yes]

[Runs: adef schema ingest adef-sources.yml]
[Runs: adef schema check]

**wineventlog ingested (47 fields).** schema check: your rules reference
2 fields not in the declaration (`proc_name`, `cmdline`) — likely aliases.
Add them to the declaration, or fix the rules?
```

**CLI commands used:**
- `adef schema ingest`
- `adef schema lint`
- `adef schema check`
- `adef schema show`

---

### 5. Detection Stage Advisor Skill

**Purpose:** Guide detections through FORGE lifecycle with AI assistance

**Triggers:**
- "Help me advance D-0042"
- "What should I do at Observe stage?"
- "Review D-0042 at Refine stage"
- "Is D-0042 ready to deploy?"

**What it does:**
1. Reads current detection stage
2. Provides stage-specific guidance
3. Checks prerequisites for advancement
4. Runs relevant validation/analysis
5. Suggests next actions

**Example conversation:**
```
User: Help me advance D-0042

Skill: Let me check D-0042's current state.

[Runs: adef detection show D-0042 --format json]

**D-0042 - LSASS memory dumping via comsvcs.dll**
- Current stage: Observe
- Owner: You
- Last updated: 2 days ago

**Observe Stage Checklist:**

Based on the journal, you've documented:
✅ Data source: Sysmon Event ID 1 (Process Creation)
✅ Field availability: process_name, parent_process, command_line
⚠️ Missing: Volume/cardinality estimates
⚠️ Missing: Baseline of normal behavior
❌ Missing: Sample query

To advance to Refine, I recommend:
1. Run this sample query in Splunk:
   ```
   index=windows EventCode=1 
   | where process_name="rundll32.exe" 
   | where like(command_line, "%comsvcs.dll%MiniDump%")
   | stats count by host, user
   ```
2. Document volume (expect <10 events/day)
3. Document baseline (legitimate uses of comsvcs.dll)

Would you like me to:
- Generate sample queries for you?
- Check schema for field availability?
- Advance to Refine stage once complete?
```

**CLI commands used:**
- `adef detection show`
- `adef detection observe/refine/govern/evolve`
- `adef schema validate`

---

### 6. Hunt Promotion Assistant Skill

**Purpose:** Help promote ATHF hunts to ADEF detections

**Triggers:**
- "Promote hunt H-0042"
- "Which hunts are ready to promote?"
- "Show me completed hunts"
- "Check if H-0042 has similar detections"

**What it does:**
1. Lists promotable hunts from ATHF
2. Checks hunt status/quality
3. Searches for similar existing detections
4. Guides through promotion workflow
5. Creates detection journal with hunt context

**Example conversation:**
```
User: Which hunts are ready to promote?

Skill: Let me check your completed ATHF hunts.

[Runs: adef hunt-promote list --status completed]

**Promotable Hunts (3):**

1. **H-0042 - LSASS memory dumping**
   - Status: Completed
   - Findings: 3 true positives, 0 false positives
   - Query validated: ✅
   - Similar detection exists: ⚠️ D-0023 (70% similar)

2. **H-0051 - Kerberoasting via Rubeus**
   - Status: Completed
   - Findings: 1 true positive, 0 false positives
   - Query validated: ✅
   - Similar detection exists: ❌ None

3. **H-0067 - WMI lateral movement**
   - Status: Completed
   - Findings: 2 true positives, 1 false positive
   - Query validated: ✅
   - Similar detection exists: ❌ None

Recommendation: Promote H-0051 first (clean findings, no overlap).

Would you like me to:
- Promote H-0051 to detection?
- Compare H-0042 with existing D-0023?
- Show hunt details?
```

**CLI commands used:**
- `adef hunt-promote list` (proposed)
- `adef hunt-promote status` (proposed)
- `adef hunt-promote`
- `adef detection similar` (proposed)

---

### 7. Detection Quality Checker Skill

**Purpose:** Review detection quality, find issues, suggest improvements

**Triggers:**
- "Review D-0042 for issues"
- "Check detection quality for all Refine-stage detections"
- "Find stale detections"
- "Validate D-0042 against schema"

**What it does:**
1. Runs validation checks (schema, syntax, completeness)
2. Checks for staleness (no updates in X days)
3. Finds overlaps/duplicates
4. Suggests improvements

**Example conversation:**
```
User: Review D-0042 for issues

Skill: Running quality checks on D-0042...

[Runs: adef detection show D-0042]
[Runs: adef schema validate D-0042]
[Runs: adef detection overlap D-0042]
[Runs: adef detection similar D-0042]

**Quality Report - D-0042 (LSASS memory dumping)**

✅ **Schema Validation:** Passed
   - All fields exist in splunk-security schema
   - All fields >80% populated

⚠️ **Overlap Check:** Potential issue
   - 70% overlap with D-0023 (Mimikatz via memory)
   - Both trigger on same process_name patterns
   - Recommendation: Consider merging or differentiating logic

✅ **Completeness:** Good
   - MITRE technique mapped (T1003.001)
   - Owner assigned (alice)
   - All FORGE stages documented

⚠️ **Freshness:** Stale
   - Last updated 12 days ago
   - Currently at Refine stage
   - Recommendation: Advance to Govern or document blocker

**Suggested Actions:**
1. Review overlap with D-0023 - merge or differentiate?
2. If distinct, advance to Govern stage
3. If duplicate, archive D-0042

Would you like me to:
- Show D-0023 for comparison?
- Advance D-0042 to Govern?
- Mark D-0042 for review?
```

**CLI commands used:**
- `adef detection show`
- `adef detection validate` (proposed)
- `adef detection overlap` (proposed)
- `adef detection similar` (proposed)
- `adef schema validate`

---

## Autonomous Agents (Background Processing)

Agents run autonomously on schedules or triggers, no human in the loop.

### 1. Coverage Monitor Agent

**Purpose:** Continuously monitor and report on coverage

**Trigger:** Daily/weekly schedule

**What it does:**
1. Runs `adef detection coverage`
2. Compares to previous period
3. Identifies new gaps (from updated ATT&CK matrix)
4. Generates coverage report
5. Posts to Slack/email if coverage drops

**Output:**
```
Daily Coverage Report - 2026-06-25

Overall: 78% (unchanged from yesterday)

New gaps identified:
- T1087.003 (Email Account Discovery) - added to ATT&CK v14

Coverage by tactic:
- Credential Access: 62% (↓ 3% - 1 detection archived)
- Lateral Movement: 85% (unchanged)
- Defense Evasion: 71% (↑ 5% - 2 new detections)

Recommendation: Review archived credential-access detection D-0067
```

**CLI commands used:**
- `adef detection coverage --format json`
- `adef detection gaps --format json`

---

### 2. Stale Detection Reminder Agent

**Purpose:** Identify and alert on stale detections

**Trigger:** Daily schedule

**What it does:**
1. Runs `adef detection list --format json`
2. Filters detections not updated in 14 days
3. Groups by stage and owner
4. Sends reminders to owners

**Output:**
```
Stale Detection Alert - 2026-06-25

The following detections haven't been updated in 14+ days:

Alice (2 detections):
- D-0007 (WMI lateral movement) - Refine stage, 18 days stale
- D-0023 (Mimikatz via memory) - Observe stage, 21 days stale

Bob (1 detection):
- D-0034 (Procdump LSASS) - Refine stage, 15 days stale

Recommendation: Review these detections and either advance or document blockers.
```

**CLI commands used:**
- `adef detection list --format json`

---

### 3. Hunt Promotion Scout Agent

**Purpose:** Automatically identify hunts ready for promotion

**Trigger:** Daily schedule

**What it does:**
1. Queries ATHF for completed hunts
2. Runs `adef hunt-promote status` for each
3. Checks for overlaps with existing detections
4. Creates promotion candidates list
5. Posts to Slack for review

**Output:**
```
Hunt Promotion Candidates - 2026-06-25

3 hunts ready for promotion:

HIGH CONFIDENCE:
- H-0051 (Kerberoasting) - 1 TP, 0 FP, no similar detections

MEDIUM CONFIDENCE:
- H-0067 (WMI lateral movement) - 2 TP, 1 FP, no similar detections

REVIEW NEEDED:
- H-0042 (LSASS dumping) - 3 TP, 0 FP, 70% overlap with D-0023

Next steps: Review and promote via `adef hunt-promote H-XXXX`
```

**CLI commands used:**
- `adef hunt-promote list`
- `adef hunt-promote status`
- `adef detection similar`

---

### 4. Research Digest Agent

**Purpose:** Automatically research new CTI and generate detection drafts

**Trigger:** Daily/weekly schedule + RSS/API feeds

**What it does:**
1. Monitors CTI feeds (RSS, Twitter, vendor blogs)
2. Identifies new reports/advisories
3. Runs `adef research new --cti-url` for each
4. Generates detection draft summaries
5. Posts digest to Slack/email

**Output:**
```
Weekly Detection Research Digest - 2026-06-25

5 new CTI sources researched:

1. Mandiant FIN7 Report (R-0008)
   - 3 detection drafts generated
   - Priority: 2 HIGH, 1 MEDIUM
   - Coverage gaps: T1218.005, T1547.001

2. Microsoft Patch Tuesday (R-0009)
   - 1 detection draft for CVE-2024-1234
   - Priority: HIGH (actively exploited)
   - Coverage gap: T1068

[3 more...]

Next steps: Review research docs via `adef research show R-XXXX`
```

**CLI commands used:**
- `adef research new --cti-url`
- `adef research list`
- `adef detection coverage`

---

### 5. Schema Drift Detector Agent

**Purpose:** Monitor schema changes over time

**Trigger:** Weekly schedule

**What it does:** *(updated 2026-07-20 — declaration-driven)*
1. Prompts for (or is handed) a fresh field inventory per source; reshapes it
   into a declaration
2. Runs `adef schema ingest` — drift (added/removed/type-changed fields) is
   reported by ingest itself, with human `corrected` fields preserved
3. Runs `adef schema check` to flag detections referencing changed fields
4. Generates schema drift report

**Output:**
```
Schema Drift Report - 2026-06-25

Source: splunk-security

Field changes detected:
- parent_command_line: 45% → 38% population (↓ 7%) ⚠️
- hash_sha256: Added (12% population) ✅
- parent_process: Removed ❌

Impacted detections (3):
- D-0007 (WMI lateral movement) - references parent_command_line
- D-0023 (Mimikatz via memory) - references parent_process
- D-0042 (LSASS dumping) - references parent_command_line

Recommendation: Review and update impacted detections
```

**CLI commands used:**
- `adef schema ingest` (drift reported on re-ingest)
- `adef schema check`
- `adef schema show`
- `adef detection list --format json` (to find impacted)

---

### 6. Detection Health Monitor Agent

**Purpose:** Monitor detection performance metrics (requires signal data)

**Trigger:** Daily schedule

**What it does:**
1. Queries signal/finding data from SIEM/SOAR
2. Calculates metrics (FP rate, signal volume, MTTD)
3. Compares to historical baselines
4. Flags degraded detections
5. Suggests tuning actions

**Output:**
```
Detection Health Report - 2026-06-25

Degraded detections (2):

D-0023 (Mimikatz via memory):
- FP rate: 15% (baseline: 5%) ↑ 10% ⚠️
- Signal volume: 150/day (baseline: 50/day) ↑ 200%
- Recommendation: Tune threshold or add exclusions

D-0034 (Procdump LSASS):
- Signal volume: 0/day (baseline: 10/day) ↓ 100% ❌
- Recommendation: Check if detection is still active

Next steps: Run `adef detection evolve D-XXXX` to document tuning
```

**Note:** This agent is in the gray zone (requires product-level signal stream access)

**CLI commands used:**
- `adef detection list`
- `adef detection evolve` (to document tuning)

---

## Skill & Agent Roadmap

### Phase 1: Essential Skills (P0)
1. ✅ Detection Explorer Skill
2. ✅ Coverage Analyst Skill
3. ✅ Declaration Author Skill (formerly Schema Discovery Assistant — declaration-driven since 2026-07-20)

**Timeline:** 2 weeks (parallel with P0 CLI commands)

---

### Phase 2: Research & Quality (P1)
4. ✅ Detection Researcher Skill
5. ✅ Detection Stage Advisor Skill
6. ✅ Detection Quality Checker Skill
7. ✅ Hunt Promotion Assistant Skill

**Timeline:** 4 weeks total

---

### Phase 3: Autonomous Agents (P2)
8. ✅ Coverage Monitor Agent
9. ✅ Stale Detection Reminder Agent
10. ✅ Hunt Promotion Scout Agent
11. ✅ Research Digest Agent
12. ✅ Schema Drift Detector Agent

**Timeline:** 6-8 weeks total

---

### Phase 4: Advanced Agents (P3)
13. ⏳ Detection Health Monitor Agent (gray zone - product)
14. ⏳ Auto-Tuning Recommender Agent (gray zone - product)
15. ⏳ Deprecation Candidate Scout Agent (gray zone)

---

## Skill vs Agent Decision Matrix

| Feature | Skill | Agent | Rationale |
|---------|-------|-------|-----------|
| Search/list detections | ✅ | ❌ | Interactive, user-driven |
| Coverage analysis | ✅ | ✅ | Both (on-demand + monitoring) |
| Gap identification | ✅ | ✅ | Both (on-demand + monitoring) |
| CTI research | ✅ | ✅ | Both (manual + automated) |
| Schema discovery | ✅ | ⚠️ | Skill primary, agent for drift |
| Stage guidance | ✅ | ❌ | Interactive, contextual |
| Quality checks | ✅ | ⚠️ | Skill primary, agent for monitoring |
| Hunt promotion | ✅ | ✅ | Both (manual + scouting) |
| Stale detection alerts | ❌ | ✅ | Pure monitoring |
| Signal health (gray zone) | ⚠️ | ✅ | Monitoring, product feature |

**Key:**
- ✅ = Good fit
- ⚠️ = Possible, depends on use case
- ❌ = Not recommended

---

## Implementation Notes

### Skills
- Built as markdown files in `.claude/skills/` or marketplace
- Use Claude Code's conversational interface
- Call CLI commands via subprocess
- Parse JSON output for structured data
- Format results conversationally

### Agents
- Built as Python scripts/cron jobs
- Run on schedule (cron, GitHub Actions, etc.)
- Call CLI commands programmatically
- Post results to Slack/email/dashboards
- Store state in workspace for trend analysis

---

## Summary

### Skills (7 conversational interfaces)
1. Detection Explorer — Search & navigate
2. Coverage Analyst — Gaps & priorities
3. Detection Researcher — CTI → drafts
4. Schema Discovery Assistant — Field discovery
5. Detection Stage Advisor — FORGE guidance
6. Hunt Promotion Assistant — ATHF → ADEF
7. Detection Quality Checker — Validation & review

### Agents (6 autonomous monitors)
1. Coverage Monitor — Daily coverage reports
2. Stale Detection Reminder — Nudge owners
3. Hunt Promotion Scout — Find candidates
4. Research Digest — Auto-research CTI
5. Schema Drift Detector — Monitor field changes
6. Detection Health Monitor — Signal metrics (gray zone)

**Total:** 13 skills/agents enhancing CLI workflows
