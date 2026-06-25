# Existing Commands vs. Roadmap Integration

**Updated:** 2026-06-25  
**Purpose:** Show how existing FORGE commands fit with proposed roadmap features

---

## TL;DR

The **existing FORGE commands are the core lifecycle engine**. The **roadmap commands enhance them** with discovery, analytics, search, and governance. Think of it as:

- **Existing (v0.1.0):** The engine that moves detections through stages
- **Roadmap (v0.1.1+):** The dashboard, search, analytics, and tooling around that engine

---

## The Foundation (Already Built)

### Existing FORGE Lifecycle Commands ✅

```bash
adef detection new "Title"          # Create detection at Find
adef detection observe D-XXXX       # Advance to Observe
adef detection refine D-XXXX        # Advance to Refine + run agents
adef detection govern D-XXXX        # Advance to Govern
adef detection evolve D-XXXX        # Advance to Evolve
```

**What they provide:**
- ✅ Structured detection lifecycle (Find → Observe → Refine → Govern → Evolve)
- ✅ Durable journal memory (`journals/D-XXXX.md`)
- ✅ Stage-specific prompts (what to document at each stage)
- ✅ Atomic state transitions (frontmatter updates)
- ✅ Orchestration (Refine chain: Similarity → Overlap → Verification)

**What they DON'T provide:**
- ❌ Visibility into all detections (can't list/search/filter)
- ❌ Program-level analytics (coverage, gaps, stats)
- ❌ Schema discovery (no data source integration)
- ❌ Research workflow (no CTI → detection drafts)
- ❌ Governance enhancements (no assign/approve/deploy)

---

## How Roadmap Commands Enhance the Foundation

### Category 1: Visibility & Discovery 🔍

**Problem:** You have 50 detections in `journals/`. How do you:
- See what exists?
- Find detections by stage/owner/technique?
- Understand program health?

**Roadmap Solution:**

```bash
# 🔴 P0 — Critical additions
adef detection list                          # Show all detections
adef detection list --stage refine           # Filter by stage
adef detection list --owner alice            # Filter by owner
adef detection list --technique T1003.001    # Filter by MITRE

adef detection search "mshta.exe"            # Full-text search journals

adef detection show D-XXXX                   # Rich detail view
```

**How they integrate with existing commands:**
- `list` queries journal frontmatter (`current_stage`, `owner`, etc.)
- `search` uses existing `adef/core/memory.py` (BM25 already implemented!)
- `show` reads journal and renders rich display with current stage highlighted

**Example workflow:**
```bash
# Find all detections stuck in Observe stage
adef detection list --stage observe

# Review one
adef detection show D-0023

# Advance it
adef detection observe D-0023 --note "Completed telemetry analysis"
adef detection refine D-0023
```

---

### Category 2: Coverage & Gap Analysis 📊

**Problem:** You've created 100 detections. Do you know:
- Which MITRE techniques are covered?
- Which tactics have gaps?
- What to build next?

**Roadmap Solution:**

```bash
# 🔴 P0 — Critical additions
adef detection coverage                      # ATT&CK heatmap
adef detection coverage --tactic execution   # Filter by tactic

adef detection gaps                          # Prioritized coverage gaps
adef detection gaps --top 10                 # Top 10 gaps

adef detection stats                         # Program metrics
# Output: 100 total, 20 at Find, 35 at Refine, 45 deployed
```

**How they integrate with existing commands:**
- Scan all journals, extract MITRE techniques from frontmatter/content
- Compare to full ATT&CK matrix
- Identify gaps

**Example workflow:**
```bash
# Check coverage
adef detection coverage --tactic credential-access

# Find gaps
adef detection gaps --tactic credential-access
# Output: T1003.001 (LSASS), T1003.003 (NTDS), T1558 (Kerberoasting) not covered

# Create detection for gap
adef detection new "LSASS memory dumping via comsvcs.dll" --technique T1003.001

# Advance through FORGE
adef detection observe D-0101
adef detection refine D-0101
# ... etc
```

---

### Category 3: Research → Detection Pipeline 🔬

**Problem:** You read a threat intel report. How do you:
- Extract relevant TTPs?
- Map to your environment's data sources?
- Draft multiple detection variants?
- Avoid duplicating existing coverage?

**Roadmap Solution:**

```bash
# 🔴 P0 — Research workflow
adef research new --cti-url https://example.com/fin7-report
# Creates R-0001.md with:
#   - MITRE technique mapping
#   - Coverage gap analysis (checks existing detections!)
#   - 3-5 prioritized detection drafts (Find + Observe starters)

adef research show R-0001
# Output (markdown report):
#   ## MITRE Mapping
#   - T1218.005 (mshta.exe) — ❌ No coverage
#   - T1059.001 (PowerShell) — ⚠️ Partial coverage (D-0023)
#
#   ## Detection Drafts
#   ### 1. [HIGH] Mshta.exe from Public Directory
#   **Hypothesis:** Rare in benign telemetry
#   **Data sources:** Process creation (Sysmon ID 1, Event ID 4688)
#   **Baseline:** <5 events/day in normal environments
#
#   ### 2. [MEDIUM] PowerShell with mshta parent
#   [...]

# Create detection from research
adef detection new "Mshta.exe from Public Directory" --technique T1218.005
# Opens D-0102.md at Find stage

# Copy research findings into journal
# Then advance through FORGE
adef detection observe D-0102
# (Document data sources from research)

adef detection refine D-0102
# (Refine chain runs, checks similarity)
```

**How they integrate with existing commands:**
- Research **produces** detection hypotheses
- Existing `adef detection new` **creates** the journal
- Existing FORGE commands **advance** it through lifecycle
- Research **pre-fills** Find and Observe stage guidance

**Key integration point:** Coverage gap analysis
- `adef research` calls `adef detection coverage` internally
- Only suggests detections for uncovered techniques
- Avoids duplicate work

---

### Category 4: Schema Discovery Integration 🗺️

**Problem:** You're at **Observe stage**, need to document:
- Which data sources have the fields?
- Field population rates?
- Sample data?

**Currently:** Manual — query Splunk/EDR, copy results into journal

**Roadmap Solution:**

```bash
# 🔴 P0 — Schema discovery
adef schema discover --connector splunk --source security-logs
# Creates config/schemas/splunk-security.yaml with:
#   - All available fields
#   - Field types, population rates
#   - Sample values

adef schema show splunk-security
# Display schema in terminal

# Observe stage enhancement (future)
adef detection observe D-XXXX --discover-schema
# Automatically:
#   1. Reads detection hypothesis from Find stage
#   2. Identifies required fields (e.g., "process_name", "parent_path")
#   3. Checks available schemas
#   4. Appends field availability report to Observe block

# Refine stage enhancement (future)
adef detection refine D-XXXX
# Before running Similarity → Overlap → Verification:
#   4. Schema Validation — Check if rule fields exist in discovered schema
```

**How they integrate with existing commands:**

**Observe stage:**
```bash
# Today (manual)
adef detection observe D-XXXX
# Edit journal manually:
#   - Data source: Splunk sourcetype=WinEventLog:Security
#   - Fields: process_name (100% populated), command_line (68% populated)
#   - Volume: ~50k events/day

# Future (semi-automated)
adef detection observe D-XXXX --schema splunk-security
# Appends to journal automatically:
#   **Schema Validation:**
#   - ✓ process_name exists (100% populated)
#   - ⚠️ command_line exists (68% populated - may miss events)
#   - ❌ parent_process_path not found (use parent_image instead)
```

**Refine stage:**
```bash
# Today
adef detection refine D-XXXX
# Chain: Similarity → Overlap → Verification

# Future (with schema)
adef detection refine D-XXXX
# Chain: Similarity → Overlap → Schema Check → Verification
#   ### Refine / Schema Check
#   ✓ All fields exist in splunk-security schema
#   ⚠️ command_line has 68% population (consider fallback logic)
```

---

### Category 5: Governance Enhancements 👥

**Problem:** You're at **Govern stage**, need to:
- Assign owner
- Get approval
- Track deployment status

**Currently:** Manual — edit frontmatter, document in Govern block

**Roadmap Solution:**

```bash
# 🟢 P2 — Governance commands
adef detection assign D-XXXX --owner bob@example.com
# Updates frontmatter: owner: bob@example.com
# Appends note to current stage block

adef detection approve D-XXXX
# Updates frontmatter: approved_at: <timestamp>, approved_by: alice
# Prerequisite for deploy command

adef detection deploy D-XXXX --environment production
# Updates frontmatter: deployed_at: <timestamp>, deployed_env: production
# Optionally triggers deployment pipeline (future)

adef detection archive D-XXXX --reason "Deprecated per D-0125"
# Updates frontmatter: status: archived, archived_at: <timestamp>
# Moves journal to archives/ directory
```

**How they integrate with existing commands:**

```bash
# Today (manual)
adef detection govern D-XXXX
# Edit journal: "Owner: bob@example.com, Approved by Alice on 2026-06-25"

# Future (structured)
adef detection govern D-XXXX
adef detection assign D-XXXX --owner bob
adef detection approve D-XXXX  # Alice runs this
# Frontmatter now has:
#   owner: bob@example.com
#   approved_at: 2026-06-25T10:00:00Z
#   approved_by: alice@example.com

adef detection deploy D-XXXX
# Frontmatter:
#   deployed_at: 2026-06-25T11:00:00Z
#   deployed_env: production

adef detection evolve D-XXXX
# Can now track deployment → tuning → deprecation lifecycle
```

---

### Category 6: Hunt Promotion Integration 🎯

**Already exists but enhanced by roadmap:**

```bash
# ✅ Today
adef hunt-promote H-0042
# Creates:
#   - staging/D-draft-0001.yml (Sigma rule)
#   - journals/D-0001.md at Find stage with hunt context

# Then use existing FORGE commands
adef detection observe D-0001
adef detection refine D-0001
# ... etc

# 🟡 P1 — Hunt promotion enhancements
adef hunt-promote list
# Shows promotable hunts from ATHF:
#   H-0042 — LSASS dumping (status: completed, findings: 3 TP)
#   H-0051 — Kerberoasting (status: completed, findings: 1 TP)

adef hunt-promote status H-0042
# Output:
#   ✓ Hunt completed
#   ✓ Findings documented (3 TP, 0 FP)
#   ✓ Query validated
#   ⚠️ Similar detection exists: D-0023 (check for overlap)
#   → Ready to promote

adef hunt-promote H-0042 --preview
# Shows what would be created (detection draft + journal)
```

**Enhanced workflow:**
```bash
# Check what's ready to promote
adef hunt-promote list --status completed

# Check if hunt overlaps with existing detections
adef hunt-promote status H-0042
# Output: ⚠️ Similar detection D-0023 exists

# Compare before promoting
adef detection show D-0023
adef hunt-promote H-0042 --preview

# Decide: promote as new or enhance existing
adef hunt-promote H-0042
# OR
adef detection evolve D-0023 --note "Enhanced based on H-0042 findings"
```

---

## The Complete Workflow (Foundation + Roadmap)

### Scenario: Research → Detection → Deployment

```bash
# ════════════════════════════════════════════════════════════════
# PHASE 1: Research (Roadmap — 🔴 P0)
# ════════════════════════════════════════════════════════════════

# Start with CTI report
adef research new --cti-url https://mandiant.com/fin7-report

# Review research output
adef research show R-0001
# Output:
#   Coverage gaps: T1218.005 (mshta), T1059.001 (PowerShell)
#   3 detection drafts generated

# Check current coverage
adef detection coverage --tactic defense-evasion
# Confirms: T1218.005 not covered

# ════════════════════════════════════════════════════════════════
# PHASE 2: Detection Creation (Foundation — ✅ Existing)
# ════════════════════════════════════════════════════════════════

# Create detection from research
adef detection new "Mshta.exe from Public Directory" --technique T1218.005
# Creates journals/D-0101.md at Find stage

# Edit journal, document hypothesis from research

# ════════════════════════════════════════════════════════════════
# PHASE 3: Observe (Foundation + Roadmap)
# ════════════════════════════════════════════════════════════════

# Discover schema (Roadmap — 🔴 P0)
adef schema discover --connector splunk --source security-logs

# Advance to Observe (Foundation — ✅ Existing)
adef detection observe D-0101

# Validate fields against schema (Roadmap — 🟡 P1)
adef schema validate D-0101 --schema splunk-security
# Appends to journal:
#   ✓ process_name exists (100% populated)
#   ✓ current_directory exists (95% populated)

# Document baseline in journal (manual)

# ════════════════════════════════════════════════════════════════
# PHASE 4: Refine (Foundation — ✅ Existing)
# ════════════════════════════════════════════════════════════════

adef detection refine D-0101
# Runs chain:
#   Similarity: No similar rules found
#   Overlap: No overlaps
#   Verification: Schema valid, sigma engine

# Review feedback, iterate rule in journal

# ════════════════════════════════════════════════════════════════
# PHASE 5: Govern (Foundation + Roadmap)
# ════════════════════════════════════════════════════════════════

# Advance to Govern (Foundation — ✅ Existing)
adef detection govern D-0101

# Assign owner (Roadmap — 🟢 P2)
adef detection assign D-0101 --owner alice

# Get approval (Roadmap — 🟢 P2)
adef detection approve D-0101

# Deploy (Roadmap — 🟢 P2)
adef detection deploy D-0101 --environment production

# ════════════════════════════════════════════════════════════════
# PHASE 6: Evolve (Foundation — ✅ Existing)
# ════════════════════════════════════════════════════════════════

# Monitor for 30 days (manual)

# Tune based on signal volume (Foundation — ✅ Existing)
adef detection evolve D-0101 --note "FP rate 5%, within threshold"

# Check coverage after deployment (Roadmap — 🟡 P1)
adef detection coverage --tactic defense-evasion
# Now shows: T1218.005 ✓ Covered (D-0101)

# Update program stats (Roadmap — 🟡 P1)
adef detection stats
# Output:
#   Total: 101 detections
#   Deployed: 46 (+1 from last month)
#   Coverage: 78% of ATT&CK matrix
```

---

## Integration Matrix

| Roadmap Feature | Integrates With | How |
|-----------------|-----------------|-----|
| **list** | All FORGE commands | Queries journals created by `new`, filters by `current_stage` |
| **search** | All FORGE commands | Searches journal content created/updated by FORGE stages |
| **show** | All FORGE commands | Displays journal with stage history and current position |
| **coverage** | `new`, research | Creates detections for gaps, measures what's deployed |
| **gaps** | research, `new` | Identifies what to research/build next |
| **stats** | All FORGE commands | Aggregates journal metadata (stage, owner, dates) |
| **research new** | `new`, coverage | Generates detection drafts, checks existing coverage |
| **schema discover** | `observe`, `refine` | Validates fields during Observe, checks in Refine chain |
| **schema validate** | `refine` | Adds schema check to Refine orchestration chain |
| **hunt-promote** | `new` | Creates journal at Find with hunt context |
| **assign/approve** | `govern` | Structured governance during Govern stage |
| **deploy** | `govern`, `evolve` | Marks deployment, enables evolution tracking |

---

## Priority Alignment

### 🔴 P0 (v0.1.1 — 2 weeks)
**Goal:** Visibility and discovery around existing FORGE engine

- `list` — See what detections exist
- `search` — Find detections by content
- `coverage` — Understand ATT&CK coverage
- `gaps` — Know what to build next
- `research new` — Structured CTI → detection pipeline
- `schema discover` — Understand data source capabilities

**Why P0?** Without these, you can only work on one detection at a time. No program-level view.

---

### 🟡 P1 (v0.2 — 4 weeks)
**Goal:** Analytics and enhanced workflows

- `stats` — Program health metrics
- `show` — Rich detail view
- `overlap/similar` — Detection comparison
- `validate` — Standalone schema validation
- `schema validate D-XXXX` — Integrate schema into Refine
- `research list/show` — Research management

**Why P1?** Enhances FORGE with analytics and quality checks.

---

### 🟢 P2 (v0.3+ — 8+ weeks)
**Goal:** Governance and automation

- `assign/approve/deploy` — Structured governance
- `connector` — Data source management
- `metrics` — Velocity, drift, forecasting
- Integrations (splunk/clickhouse)

**Why P2?** Nice to have, but FORGE works without them.

---

## Summary: Foundation vs. Enhancement

| | Foundation (Existing) | Enhancement (Roadmap) |
|---|---|---|
| **Focus** | Individual detection lifecycle | Program-level analytics |
| **Scope** | One detection at a time | All detections together |
| **Commands** | 5 lifecycle stages | 100+ supporting commands |
| **State** | Stage transitions | Detection discovery & management |
| **Orchestration** | Refine chain (3 agents) | Research, schema, coverage, governance |
| **Output** | Journal updates | Analytics, reports, comparisons |
| **Without it** | Can't track lifecycle | Can't see program health |

**Analogy:**
- **Foundation** = Git (track changes to one file/repo)
- **Roadmap** = GitHub (search, PR workflows, insights, CI/CD)

You need Git to track history, but GitHub makes it usable at scale.

---

## Key Takeaway

The **existing FORGE commands are not replaced by roadmap commands**—they're **enhanced by them**.

Every roadmap feature either:
1. **Feeds into** FORGE (research → new, schema → observe/refine)
2. **Queries across** FORGE journals (list, search, coverage, stats)
3. **Augments** FORGE stages (assign, approve, deploy)

The FORGE lifecycle remains the **beating heart** of ADEF. Everything else orbits around it.
