# What's Real vs. What's Proposed

**Updated:** 2026-07-20 (originally 2026-06-25)
**Purpose:** Clear distinction between implemented commands and future ideas

> **2026-07-20 update — schema and catalog are now REAL.** Since the 06-25
> snapshot: `adef catalog` (walk an existing rules repo read-only, incl.
> `--report json` and extraction-profile support via `adef profile lint` /
> `--profile`), and the declaration-driven schema commands
> (`adef schema ingest / lint / check / show`) are **shipped**. The
> connector-based `adef schema discover` idea below is **dead** — replaced by
> user-provided declarations (see
> `docs/plans/2026-07-20-schema-declaration-design.md`). References to
> `schema discover` in the body below are retained as history but are ❌
> permanently, not ❌ not-yet.

---

## TL;DR

**`adef detection observe` IS REAL AND WORKING RIGHT NOW.**

It's just **simpler than you might expect**—it only updates the journal, it doesn't query data sources automatically. All the FORGE commands (new/observe/refine/govern/evolve) are **fully implemented** and working today.

The **roadmap commands** (list/search/coverage/gaps) are the ones that **don't exist yet**. Schema commands shipped 2026-07-20 in declaration-driven form (`ingest`/`lint`/`check`/`show`).

---

## ✅ What's Real (v0.1.0 — Implemented and Working)

### Core FORGE Commands

#### `adef init`
**Status:** ✅ Fully implemented

**What it does:**
- Creates workspace directory structure
- Copies templates
- Creates config file

**Try it:**
```bash
adef init
ls ~/work/adef-workspace/
# Output: journals/ config/ templates/ AGENTS.md
```

---

#### `adef detection new "Title"`
**Status:** ✅ Fully implemented

**What it does:**
1. Generates next detection ID (D-0001, D-0002, etc.)
2. Creates `journals/D-XXXX.md` file
3. Populates YAML frontmatter
4. Appends Find stage block with prompt

**What it does NOT do:**
- ❌ Query data sources
- ❌ Generate detection logic
- ❌ Validate anything
- ❌ Check for duplicates

**Try it:**
```bash
adef detection new "Test Detection"
cat ~/work/adef-workspace/journals/D-0001.md
# You'll see: frontmatter + Find stage block
```

**Proof from my test:**
```bash
$ adef detection new "Test Detection for Demo"
Created journals/D-0001.md at Find stage.

$ cat ~/work/adef-workspace/journals/D-0001.md
---
id: D-0001
title: Test Detection for Demo
status: draft
current_stage: find
owner: ''
created: '2026-06-25T14:20:42-04:00'
updated: '2026-06-25T14:20:42-04:00'
rule_uuid: ''
---
[... template content ...]

## [2026-06-25T14:20:42-04:00] Stage: find

**Title:** Test Detection for Demo

**FORGE / Find — what triggered this detection?**

Capture, in order:
- The gap, signal source, intel report, or hunt that motivated the detection.
- The one-sentence hypothesis the detection will test.
[...]
```

---

#### `adef detection observe D-XXXX`
**Status:** ✅ Fully implemented

**What it does:**
1. Reads journal file
2. Updates frontmatter:
   - `current_stage: observe`
   - `updated: <timestamp>`
3. Appends new timestamped Observe stage block
4. Includes prompt asking about:
   - Data sources
   - Field population rates
   - Volume estimates
   - Baseline normal
5. Writes file atomically

**What it does NOT do:**
- ❌ Query Splunk/EDR/data sources automatically
- ❌ Discover schema automatically
- ❌ Validate field availability
- ❌ Run sample queries
- ❌ Fetch baseline data

**You still have to:**
- Manually query your data sources
- Manually document findings in the journal
- Manually copy/paste results

**Try it:**
```bash
adef detection observe D-0001 --note "Checked 30d of logs"
cat ~/work/adef-workspace/journals/D-0001.md
# You'll see: current_stage changed to "observe", new block appended
```

**Proof from my test:**
```bash
$ adef detection observe D-0001 --note "Testing what observe actually does"
D-0001 → observe

$ cat ~/work/adef-workspace/journals/D-0001.md
---
id: D-0001
current_stage: observe  ← Changed from "find"
updated: '2026-06-25T14:20:49-04:00'  ← Updated
---
[... previous content ...]

## [2026-06-25T14:20:49-04:00] Stage: observe  ← NEW BLOCK

**FORGE / Observe — characterize real telemetry before defining weird.**

You can't find weird if you don't know normal.

- Which data source(s) carry the relevant fields? (note OCSF or vendor-native)
- Field population rates: which fields are reliably populated vs. sparse?
- Volume / cardinality estimates over a representative window.
- Sample query that surfaces the *behavior* (top of Pyramid of Pain), not just an indicator.
- Note the baseline of normal — what does the legitimate version of this look like?

_Note:_ Testing what observe actually does  ← Note added
```

**The confusion:** People might think "observe" means it observes/queries data automatically. **It doesn't.** It just:
- Advances the stage in the journal
- Gives you a prompt reminding you what to document
- You do the actual observing manually

---

#### `adef detection refine D-XXXX`
**Status:** ✅ Fully implemented (most complex of the 5)

**What it does:**
1. Updates frontmatter (`current_stage: refine`)
2. Appends Refine stage block
3. **Runs orchestration chain** (this is unique to Refine):
   - RuleSimilarity agent
   - RuleOverlap agent
   - Verification agent
4. Appends each agent's output as subsections

**What it does NOT do:**
- ❌ Execute queries against live data
- ❌ Automatically fix issues found
- ❌ Create upstream YAML file

**Try it:**
```bash
adef detection refine D-0001
# Output: D-0001 → refine
#         Refine chain complete — Similarity → Overlap → Verification appended.
```

**Note:** The agent chain only runs if agents are configured via env vars. If not configured, it still advances the stage but agents return "unavailable" messages.

---

#### `adef detection govern D-XXXX`
**Status:** ✅ Fully implemented

**What it does:**
1. Updates frontmatter (`current_stage: govern`)
2. Appends Govern stage block with prompt about:
   - Engine type
   - Severity
   - Owner
   - On-call rotation
   - Deployment gates

**What it does NOT do:**
- ❌ Enforce deployment gates
- ❌ Require approval
- ❌ Deploy to production
- ❌ Validate owner exists

**Try it:**
```bash
adef detection govern D-0001
```

---

#### `adef detection evolve D-XXXX`
**Status:** ✅ Fully implemented

**What it does:**
1. Updates frontmatter (`current_stage: evolve`)
2. Appends Evolve stage block with prompt about:
   - Tuning decisions
   - Performance trends
   - Deprecation rationale
   - Successor rules

**What it does NOT do:**
- ❌ Monitor signal volume automatically
- ❌ Detect drift automatically
- ❌ Recommend tuning actions
- ❌ Archive/deprecate rules

**Try it:**
```bash
adef detection evolve D-0001 --note "Tuned threshold"
```

**Note:** You can run this multiple times (idempotent)

---

### Other Implemented Commands

#### `adef hunt-promote H-XXXX`
**Status:** ✅ Fully implemented

**What it does:**
- Loads hunt from ATHF workspace
- Generates draft detection YAML
- Creates detection journal at Find stage
- Populates with hunt context

**Requires:** ATHF installed, hunt exists

---

#### `adef backfill journals`
**Status:** ✅ Fully implemented

**What it does:**
- Scans upstream rule directory
- Creates journals for rules without journals
- Populates basic frontmatter from rule metadata

**Try it:**
```bash
adef backfill journals --rule-root /path/to/rules --dry-run
```

---

## ❌ What's NOT Real (Roadmap — Not Implemented Yet)

### 🔴 P0 Commands (Proposed for v0.1.1)

All of these **do not exist** and will return "command not found":

```bash
# Detection management
adef detection list                    # ❌ Does not exist
adef detection list --stage refine     # ❌ Does not exist
adef detection search "mshta"          # ❌ Does not exist
adef detection show D-XXXX             # ❌ Does not exist

# Coverage & analytics
adef detection coverage                # ❌ Does not exist
adef detection gaps                    # ❌ Does not exist
adef detection stats                   # ❌ Does not exist

# Research
adef research new --topic "LSASS"      # ❌ Does not exist
adef research list                     # ❌ Does not exist
adef research show R-0001              # ❌ Does not exist

# Schema (declaration-driven — shipped 2026-07-20)
adef schema ingest adef-sources.yml    # ✅ SHIPPED
adef schema lint adef-sources.yml      # ✅ SHIPPED
adef schema check                      # ✅ SHIPPED (repo-wide field validation)
adef schema show wineventlog           # ✅ SHIPPED
adef schema discover --connector splunk  # ❌ DEAD — connector approach dropped
adef schema list                       # ❌ Does not exist yet
adef schema validate D-XXXX            # ❌ Does not exist yet (per-detection)
```

---

### 🟡 P1 Commands (Proposed for v0.2)

```bash
# Detection comparison
adef detection overlap D-XXXX          # ❌ Does not exist
adef detection similar D-XXXX          # ❌ Does not exist
adef detection validate D-XXXX         # ❌ Does not exist

# Hunt promotion enhancements
adef hunt-promote list                 # ❌ Does not exist
adef hunt-promote status H-XXXX        # ❌ Does not exist
```

---

### 🟢 P2 Commands (Proposed for v0.3+)

```bash
# Governance
adef detection assign D-XXXX --owner bob    # ❌ Does not exist
adef detection approve D-XXXX               # ❌ Does not exist
adef detection deploy D-XXXX                # ❌ Does not exist

# Connectors
adef connector list                    # ❌ Does not exist
adef connector test splunk             # ❌ Does not exist

# Metrics
adef metrics program                   # ❌ Does not exist
adef metrics velocity                  # ❌ Does not exist
```

---

## The Confusion: What "Observe" Actually Does

### What People Might Expect (NOT Real):

```bash
adef detection observe D-0001
```

**Expected (but wrong) behavior:**
1. ✅ Reads detection hypothesis from Find stage
2. ✅ Identifies required fields (process_name, parent_path, etc.)
3. ✅ Connects to Splunk/EDR automatically
4. ✅ Queries data sources for field availability
5. ✅ Calculates population rates
6. ✅ Estimates volume
7. ✅ Appends report to journal

**This does NOT happen!**

---

### What Actually Happens (Real):

```bash
adef detection observe D-0001
```

**Actual behavior:**
1. ✅ Reads `journals/D-0001.md`
2. ✅ Updates `current_stage: observe` in frontmatter
3. ✅ Appends timestamped Observe block with prompt text
4. ✅ Writes file atomically
5. ❌ **Does not query anything**
6. ❌ **Does not discover anything**
7. ❌ **Does not validate anything**

**You then manually:**
1. Open your Splunk/EDR/SIEM
2. Run queries yourself
3. Copy results into the journal
4. Edit `journals/D-0001.md` to document findings

---

## Why This Design?

### Current Design (v0.1.0): Human-in-the-Loop
**Philosophy:** ADEF structures your workflow, you execute it

**Pros:**
- ✅ Simple, no external dependencies
- ✅ Works with any data source
- ✅ No credentials/auth needed
- ✅ You control what's queried
- ✅ Fast implementation

**Cons:**
- ❌ Manual work required
- ❌ No automation
- ❌ Easy to skip steps
- ❌ No validation

---

### Roadmap Design (v0.2+): Semi-Automated
**Philosophy:** ADEF assists your workflow, provides data

**Planned for Observe** *(schema part shipped 2026-07-20 in declaration form)*:
```bash
adef schema ingest adef-sources.yml     # ✅ shipped (replaces the dead `discover --connector`)
adef detection observe D-0001 --schema wineventlog   # roadmap

# Would append to journal:
# **Schema Validation:**
# - ✓ process_name exists (100% populated)
# - ⚠️ command_line exists (68% populated)
# - ❌ parent_process_path not found (use parent_image instead)
```

**Planned for Refine:**
```bash
adef detection refine D-0001

# Chain would include:
# Similarity → Overlap → Schema Check → Verification
#   ### Refine / Schema Check
#   ✓ All referenced fields exist in schema
#   ⚠️ command_line low population (68%)
```

---

## Summary Table

| Command | Implemented? | What It Does | What It Doesn't Do |
|---------|--------------|--------------|-------------------|
| `adef init` | ✅ Yes | Creates workspace structure | - |
| `adef detection new` | ✅ Yes | Creates journal at Find | Doesn't generate queries |
| `adef detection observe` | ✅ Yes | Advances to Observe, adds prompt | **Doesn't query data sources** |
| `adef detection refine` | ✅ Yes | Advances to Refine, runs agent chain | Doesn't execute queries on live data |
| `adef detection govern` | ✅ Yes | Advances to Govern, adds prompt | Doesn't enforce gates |
| `adef detection evolve` | ✅ Yes | Advances to Evolve, adds prompt | Doesn't monitor automatically |
| `adef hunt-promote` | ✅ Yes | Creates journal from hunt | Requires ATHF |
| `adef backfill` | ✅ Yes | Bulk journal creation | Requires rule files |
| | | | |
| `adef detection list` | ❌ No | Would list all detections | N/A - not built |
| `adef detection search` | ❌ No | Would search journals | N/A - not built |
| `adef detection coverage` | ❌ No | Would show ATT&CK coverage | N/A - not built |
| `adef schema ingest/lint/check/show` | ✅ Yes (2026-07-20) | Declaration-driven schemas + rule-vs-schema check | Shipped; `discover` (connector-based) permanently dropped |
| `adef research new` | ❌ No | Would generate detection drafts from CTI | N/A - not built |

---

## How to Verify What's Real

### Test it yourself:

```bash
# Install ADEF
pip install -e .

# See what commands exist
adef --help
adef detection --help

# Try a real command
adef init
adef detection new "Test"
adef detection observe D-0001
cat ~/work/adef-workspace/journals/D-0001.md

# Try a fake command (will fail)
adef detection list
# Output: Error: No such command 'list'.

adef detection search "test"
# Output: Error: No such command 'search'.

adef schema discover
# Output: Error: No such command 'discover'.
# (The `schema` group itself is real since 2026-07-20: ingest/lint/check/show)
```

---

## The Bottom Line

**All 5 FORGE commands are real and working:**
- `adef detection new` ✅
- `adef detection observe` ✅
- `adef detection refine` ✅
- `adef detection govern` ✅
- `adef detection evolve` ✅

**They just do simpler things than the names might suggest:**
- They advance stages in the journal
- They append prompts to guide you
- They (mostly) don't automate anything
- You do the actual work (querying, analyzing, documenting)

**Everything else in the roadmap (list, search, coverage, gaps, research) does not exist yet.** Schema and catalog shipped 2026-07-20: `adef catalog` (+ extraction profiles) and `adef schema ingest/lint/check/show` (declaration-driven).

**The confusion comes from:** Documentation describing "how Observe **should work with schema validation**" vs. "how Observe **actually works today**" (just adds a prompt).

---

## Analogy

Think of FORGE commands like **git commit**:

**`git commit` doesn't:**
- ❌ Write your code
- ❌ Fix bugs
- ❌ Run tests
- ❌ Deploy to production

**`git commit` just:**
- ✅ Records a snapshot
- ✅ Adds metadata (author, date, message)
- ✅ Advances HEAD pointer

**Similarly, `adef detection observe` doesn't:**
- ❌ Query data sources
- ❌ Discover schemas
- ❌ Validate fields

**`adef detection observe` just:**
- ✅ Records stage transition
- ✅ Adds prompt (what to document)
- ✅ Advances `current_stage` pointer

**You** do the observing. ADEF structures it.
