# FORGE Commands Explained — What They Actually Do

**Current State:** v0.1.0  
**Updated:** 2026-06-25

---

## Quick Summary

The **FORGE lifecycle commands** are the heart of ADEF. Each command advances a detection through stages (Find → Observe → Refine → Govern → Evolve) by:

1. **Updating journal frontmatter** (current_stage, updated timestamp)
2. **Appending a timestamped markdown block** with stage-specific prompts
3. **(For Refine only)** Running orchestration chain (Similarity → Overlap → Verification)

**All changes are atomic** (temp file + rename) and **idempotent** (re-advancing to same stage just adds a note).

---

## Command Reference

### `adef detection new`

**Purpose:** Create a new detection journal at the **Find** stage

**What it does:**
1. Generates next detection ID (`D-0001`, `D-0002`, etc.)
2. Creates `journals/D-XXXX.md` from template
3. Populates YAML frontmatter:
   ```yaml
   id: D-0001
   title: "Detection Title"
   status: draft
   current_stage: find
   owner: alice@example.com
   rule_uuid: ""  # Optional upstream rule UUID
   created: 2026-06-25T10:30:00-07:00
   updated: 2026-06-25T10:30:00-07:00
   ```
4. Appends **Find stage block** with prompt:
   ```markdown
   ## [2026-06-25T10:30:00-07:00] Stage: find
   
   **Title:** Detection Title
   
   **FORGE / Find — what triggered this detection?**
   
   Capture, in order:
   
   - The gap, signal source, intel report, or hunt that motivated the detection.
   - The one-sentence hypothesis the detection will test.
   - Initial MITRE ATT&CK mapping (technique IDs are best — sub-techniques even better).
   - Whether this is paired with an existing upstream rule (paste UUID into frontmatter).
   ```

**Usage:**
```bash
adef detection new "Suspicious mshta.exe child process"
adef detection new "Suspicious mshta.exe" --owner alice@example.com
adef detection new "Suspicious mshta.exe" --rule-uuid a1b2c3d4-5678-90ab-cdef-1234567890ab
adef detection new "Title" --workspace /path/to/workspace
```

**Output:**
```
Created journals/D-0001.md at Find stage.
```

**What it doesn't do:**
- ❌ Doesn't generate detection logic/query
- ❌ Doesn't validate against data sources
- ❌ Doesn't check for duplicates
- ❌ Doesn't create upstream YAML file

**Next step:** Edit `journals/D-0001.md` to flesh out hypothesis, then advance to Observe

---

### `adef detection observe`

**Purpose:** Advance detection to **Observe** stage (characterize telemetry)

**What it does:**
1. Reads current journal from disk
2. Updates frontmatter:
   - `current_stage: observe`
   - `updated: <timestamp>`
3. Appends **Observe stage block**:
   ```markdown
   ## [2026-06-25T11:00:00-07:00] Stage: observe
   
   **FORGE / Observe — characterize real telemetry before defining weird.**
   
   You can't find weird if you don't know normal.
   
   - Which data source(s) carry the relevant fields? (note OCSF or vendor-native)
   - Field population rates: which fields are reliably populated vs. sparse?
   - Volume / cardinality estimates over a representative window.
   - Sample query that surfaces the *behavior* (top of Pyramid of Pain), not just an indicator.
   - Note the baseline of normal — what does the legitimate version of this look like?
   ```
4. Writes changes atomically

**Usage:**
```bash
adef detection observe D-0001
adef detection observe D-0001 --note "Checked 30 days of process_create events"
adef detection observe D-0001 --workspace /path/to/workspace
```

**Output:**
```
D-0001 → observe
```

**If already at Observe stage:**
```
Already at observe — no changes.
# OR (with --note)
Already at observe — appended note only.
```

**What it doesn't do:**
- ❌ Doesn't query data sources automatically
- ❌ Doesn't discover schema
- ❌ Doesn't validate field availability
- ❌ Doesn't run sample queries

**This is where declared schemas integrate** — `adef schema ingest` (shipped) captures the fields per data source; a future `adef detection observe D-0001 --check-schema` can validate the hypothesis's required fields against them.

**Next step:** Manually query data sources, document findings in journal, then advance to Refine

---

### `adef detection refine`

**Purpose:** Advance detection to **Refine** stage AND run orchestration chain

**What it does:**
1. Reads current journal
2. Updates frontmatter:
   - `current_stage: refine`
   - `updated: <timestamp>`
3. Appends **Refine stage block**:
   ```markdown
   ## [2026-06-25T12:00:00-07:00] Stage: refine
   
   **FORGE / Refine — iterate the rule with feedback.**
   
   `adef detection refine <id>` invokes the orchestration chain
   (Similarity → Overlap → Verification) and appends each agent's output below
   this block. Capture, alongside it:
   
   - Each iteration of the draft query and *why* it changed.
   - Backtest outcomes: true positives, false positives, ratio over a representative window.
   - Similar or overlapping rules surfaced by Similarity / Overlap — link to their UUIDs.
   - Verification agent's verdict on whether the rule fires for the intended behavior.
   ```
4. **Runs orchestration chain** (unique to Refine stage):
   - **Step 1: RuleSimilarity** — Does a similar rule already exist?
   - **Step 2: RuleOverlap** — Do triggers overlap with another rule?
   - **Step 3: Verification** — Schema validation + four-engine constraint check
5. Appends each agent's output to journal:
   ```markdown
   ### Refine / Similarity
   
   [Agent output: found 2 similar rules, D-0023 and D-0045]
   
   ### Refine / Overlap
   
   [Agent output: 30% overlap with D-0023 on process_name field]
   
   ### Refine / Verification
   
   [Agent output: Schema valid, passes four-engine constraint (sigma)]
   ```

**Usage:**
```bash
adef detection refine D-0001
adef detection refine D-0001 --note "Fixed command_line false positive"
```

**Output:**
```
D-0001 → refine
Refine chain complete — Similarity → Overlap → Verification appended.
```

**What it doesn't do:**
- ❌ Doesn't execute queries against live data
- ❌ Doesn't automatically fix issues (just reports them)
- ❌ Doesn't create upstream YAML file yet

**Orchestration details:**
- Chain runs even if one step fails (graceful degradation)
- Agents are lazy-loaded via `ADEF_WRAPPER_*` env vars
- If agent unavailable, logs warning and continues

**Next step:** Review agent feedback, iterate on rule, then advance to Govern

---

### `adef detection govern`

**Purpose:** Advance detection to **Govern** stage (deployment gates)

**What it does:**
1. Reads current journal
2. Updates frontmatter:
   - `current_stage: govern`
   - `updated: <timestamp>`
3. Appends **Govern stage block**:
   ```markdown
   ## [2026-06-25T13:00:00-07:00] Stage: govern
   
   **FORGE / Govern — deploy with quality gates, ownership, review cadence.**
   
   A detection without ownership is a detection without a future.
   
   - **Engine type** — exactly one of `sigma | sql | sch_sql | composite`.
   - **Severity / risk score / RBA contribution** — calibrate against neighbors.
   - **Owner** — the human who carries the pager for this rule.
   - **On-call rotation** — which rotation responds when this fires.
   - **Review cadence** — every N days/weeks. Calendar it.
   - **Deployment gate evidence** — peer review, backtest summary, false-positive review.
   ```

**Usage:**
```bash
adef detection govern D-0001
adef detection govern D-0001 --note "Security team approved, deploying to prod"
```

**Output:**
```
D-0001 → govern
```

**What it doesn't do:**
- ❌ Doesn't enforce deployment gates automatically
- ❌ Doesn't require approval workflow (yet - see gray-zone docs)
- ❌ Doesn't deploy to production automatically
- ❌ Doesn't create upstream YAML file

**Future enhancements (v0.2):**
- `adef detection approve D-0001` — Mark as approved
- `adef detection deploy D-0001` — Trigger deployment workflow
- Enhanced frontmatter: `approved_at`, `deployed_at`, `reviewers[]`

**Next step:** Manually deploy detection to production, document deployment in journal, then advance to Evolve

---

### `adef detection evolve`

**Purpose:** Advance detection to **Evolve** stage (tuning/deprecation)

**What it does:**
1. Reads current journal
2. Updates frontmatter:
   - `current_stage: evolve`
   - `updated: <timestamp>`
3. Appends **Evolve stage block**:
   ```markdown
   ## [2026-06-25T14:00:00-07:00] Stage: evolve
   
   **FORGE / Evolve — detections never finish.**
   
   Capture the rolling state of the rule:
   
   - **Recent tuning decisions** — what changed, why, and what the noise floor is now.
   - **Performance trend** — signal volume, false-positive ratio, query latency.
   - **Replacement / deprecation rationale** — if you're retiring this rule, what's the better signal?
   - **Successor rule(s)** — link the UUID(s) of the replacements so the chain of reasoning survives.
   ```

**Usage:**
```bash
adef detection evolve D-0001
adef detection evolve D-0001 --note "Tuned threshold from 5 to 10, FP rate dropped 50%"
adef detection evolve D-0001 --note "Deprecated in favor of D-0125"
```

**Output:**
```
D-0001 → evolve
```

**What it doesn't do:**
- ❌ Doesn't automatically monitor signal volume
- ❌ Doesn't automatically detect drift
- ❌ Doesn't recommend tuning actions
- ❌ Doesn't archive/deprecate the rule

**Future enhancements (v0.2+):**
- Drift monitoring (requires signal stream access - product feature)
- Auto-tuning recommendations based on signal history
- Deprecation workflow with successor linking

**Next step:** Detections cycle through Evolve repeatedly (tune, test, repeat)

---

## Stage Transition Diagram

```
           ┌─────────────────────────────────────┐
           │    adef detection new "Title"       │
           │    Creates D-XXXX.md at Find stage  │
           └──────────────┬──────────────────────┘
                          │
                          ▼
                   ┌─────────────┐
                   │  🔵 FIND    │  ← What triggered this?
                   │  (Draft)    │     Hypothesis, MITRE mapping
                   └──────┬──────┘
                          │ adef detection observe D-XXXX
                          ▼
                   ┌─────────────┐
                   │ 🟢 OBSERVE  │  ← Characterize telemetry
                   │             │     Fields, volume, baseline
                   └──────┬──────┘
                          │ adef detection refine D-XXXX
                          ▼
                   ┌─────────────┐
                   │ 🟡 REFINE   │  ← Iterate rule + feedback
                   │ ⚙️ Chain!   │     Similarity → Overlap → Verification
                   └──────┬──────┘
                          │ adef detection govern D-XXXX
                          ▼
                   ┌─────────────┐
                   │ 🟠 GOVERN   │  ← Deployment gates
                   │             │     Owner, severity, approval
                   └──────┬──────┘
                          │ adef detection evolve D-XXXX
                          ▼
                   ┌─────────────┐
                   │ 🔴 EVOLVE   │  ← Tuning, deprecation
                   │  ↻ Loop     │     Performance trends, successors
                   └──────┬──────┘
                          │
                          └──────┐
                                 │ Can cycle back to Evolve repeatedly
                                 │ (tune, test, document, repeat)
                                 └────────────────────────────────►
```

---

## Common Workflows

### New Detection from CTI
```bash
# 1. Create detection
adef detection new "Suspicious mshta.exe from Public directory"

# 2. Edit journals/D-0001.md, add hypothesis and MITRE mapping

# 3. Advance to Observe
adef detection observe D-0001

# 4. Query data sources, document findings in journal

# 5. Advance to Refine (runs orchestration)
adef detection refine D-0001

# 6. Review similarity/overlap feedback, iterate rule

# 7. Advance to Govern
adef detection govern D-0001 --note "SOC team approved"

# 8. Deploy to production

# 9. Advance to Evolve
adef detection evolve D-0001 --note "Monitoring for 30d before tuning"
```

---

### Promote Hunt to Detection
```bash
# 1. Promote ATHF hunt to ADEF detection
adef hunt-promote H-0042
# Creates: staging/D-draft-0001.yml + journals/D-0001.md at Find stage

# 2. Detection is already at Find with intel sources populated

# 3. Continue with Observe → Refine → Govern → Evolve
adef detection observe D-0001
adef detection refine D-0001
# ... etc
```

---

### Tune Existing Detection
```bash
# Detection already at Evolve stage
adef detection evolve D-0042 --note "Increased threshold from 5 to 10, testing for 7d"

# Wait, monitor, then document results
adef detection evolve D-0042 --note "FP rate dropped 60%, keeping new threshold"
```

---

### Deprecate Detection
```bash
adef detection evolve D-0042 --note "Deprecated: D-0125 is superior (better coverage, lower FPs)"
# Then manually disable rule in production
```

---

## Idempotency Behavior

### Re-advancing to Same Stage

```bash
adef detection refine D-0001    # First time
# Output: D-0001 → refine
# Result: Stage block appended, Refine chain runs

adef detection refine D-0001    # Second time
# Output: Already at refine — no changes.
# Result: No new block appended

adef detection refine D-0001 --note "Fixed issue"    # With note
# Output: Already at refine — appended note only.
# Result: Note added as sub-block within existing Refine stage:
#   _Note (2026-06-25T15:00:00-07:00):_ Fixed issue
```

**Why idempotent?**
- Prevents duplicate stage blocks
- Allows incremental notes within a stage
- Refine chain doesn't re-run on idempotent advance (saves time)

---

## File System Changes

### Before Any Commands
```
~/work/adef-workspace/
└── journals/           (empty directory)
```

### After `adef detection new "Title"`
```
~/work/adef-workspace/
└── journals/
    └── D-0001.md       (new file, 2KB)
```

### After All Stage Advances
```
~/work/adef-workspace/
└── journals/
    └── D-0001.md       (updated file, ~8KB)
        ├── Frontmatter with current_stage: evolve
        ├── ## [timestamp] Stage: find
        ├── ## [timestamp] Stage: observe
        ├── ## [timestamp] Stage: refine
        │   ├── ### Refine / Similarity
        │   ├── ### Refine / Overlap
        │   └── ### Refine / Verification
        ├── ## [timestamp] Stage: govern
        └── ## [timestamp] Stage: evolve
```

---

## What's Missing (Future Commands)

These commands **don't exist yet** but would enhance the workflow:

```bash
# Show detection details
adef detection show D-0001

# List all detections
adef detection list --stage refine

# Search detections
adef detection search "mshta.exe"

# Validate detection
adef detection validate D-0001

# Governance enhancements
adef detection assign D-0001 --owner bob
adef detection approve D-0001
adef detection deploy D-0001

# Analytics
adef detection stats
adef detection coverage
adef detection gaps
```

See `docs/cli-commands-roadmap.md` for full list.

---

## Key Takeaways

1. **Commands = Stage Transitions + Journal Updates**
   - Each command advances `current_stage` and appends timestamped markdown

2. **Refine is Special**
   - Only stage that runs automated agents (Similarity → Overlap → Verification)

3. **Everything is Durable**
   - All reasoning, feedback, and decisions captured in markdown
   - Atomic writes ensure consistency

4. **Idempotent by Design**
   - Re-running same command is safe (just adds notes)

5. **Human-in-the-Loop**
   - Commands don't execute queries, deploy rules, or make decisions
   - They structure and capture **your** workflow

6. **Linear Progression (for now)**
   - Stages go forward only: Find → Observe → Refine → Govern → Evolve
   - Can cycle Evolve → Evolve for ongoing tuning
   - Future: might allow backward transitions or stage skipping
