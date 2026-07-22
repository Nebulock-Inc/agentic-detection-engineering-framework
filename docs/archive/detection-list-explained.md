# `adef detection list` Command Explained

**Status:** 🔴 Proposed (not implemented yet)  
**Priority:** P0 — Critical for v0.1.1  
**Purpose:** See all detections at once with filtering

---

## The Problem It Solves

**Today (v0.1.0):**
```bash
# You've created 50 detections using:
adef detection new "Title 1"
adef detection new "Title 2"
# ... (48 more times)

# Now you want to know:
# - Which detections exist?
# - Which are stuck at Refine stage?
# - Which does Alice own?
# - What's the status of the program?

# Your only option:
ls ~/work/adef-workspace/journals/
# Output: D-0001.md D-0002.md D-0003.md ... D-0050.md
# (Not helpful - no stage, owner, or technique info)

# Or manually open each file:
cat ~/work/adef-workspace/journals/D-0001.md
cat ~/work/adef-workspace/journals/D-0002.md
# (Very slow, can't see patterns)
```

**With `adef detection list`:**
```bash
adef detection list

# Output:
# ID      Title                                   Stage    Owner    Technique    Updated
# D-0001  Suspicious mshta.exe                   evolve   alice    T1218.005    2026-06-20
# D-0002  LSASS memory dumping                   refine   bob      T1003.001    2026-06-23
# D-0003  Kerberoasting via Rubeus               refine   bob      T1558.003    2026-06-24
# D-0004  PowerShell download cradle             observe  alice    T1059.001    2026-06-19
# D-0005  Scheduled task for persistence         govern   carol    T1053.005    2026-06-25
# ... (45 more)
```

---

## How It Works

### Basic Usage

```bash
adef detection list
```

**What it does:**
1. Scans `~/work/adef-workspace/journals/` directory
2. Reads each `D-XXXX.md` file
3. Parses YAML frontmatter from each file
4. Extracts key fields:
   - `id` — Detection ID (D-0001, D-0002, etc.)
   - `title` — Detection title
   - `current_stage` — Which FORGE stage (find, observe, refine, govern, evolve)
   - `owner` — Who owns this detection
   - `updated` — Last modified timestamp
5. Displays as a Rich table (colored, formatted)

**Example output:**
```
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ ID     ┃ Title                               ┃ Stage   ┃ Owner   ┃ Technique   ┃ Updated    ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ D-0001 │ Suspicious mshta.exe                │ evolve  │ alice   │ T1218.005   │ 2026-06-20 │
│ D-0002 │ LSASS memory dumping                │ refine  │ bob     │ T1003.001   │ 2026-06-23 │
│ D-0003 │ Kerberoasting via Rubeus            │ refine  │ bob     │ T1558.003   │ 2026-06-24 │
│ D-0004 │ PowerShell download cradle          │ observe │ alice   │ T1059.001   │ 2026-06-19 │
│ D-0005 │ Scheduled task for persistence      │ govern  │ carol   │ T1053.005   │ 2026-06-25 │
└────────┴─────────────────────────────────────┴─────────┴─────────┴─────────────┴────────────┘

Total: 50 detections
```

---

## Filtering: `--stage refine`

### The Use Case

**Scenario:** You're a detection manager. You want to see which detections are currently stuck in the Refine stage so you can:
- Prioritize which ones to review
- See who needs help
- Understand bottlenecks

```bash
adef detection list --stage refine
```

**What it does:**
1. Scans all journals (same as before)
2. **Filters** to only show detections where `current_stage: refine`
3. Displays filtered table

**Example output:**
```
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ ID     ┃ Title                               ┃ Stage   ┃ Owner   ┃ Technique   ┃ Updated    ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ D-0002 │ LSASS memory dumping                │ refine  │ bob     │ T1003.001   │ 2026-06-23 │
│ D-0003 │ Kerberoasting via Rubeus            │ refine  │ bob     │ T1558.003   │ 2026-06-24 │
│ D-0007 │ WMI lateral movement                │ refine  │ alice   │ T1047       │ 2026-06-22 │
│ D-0012 │ Mimikatz via memory                 │ refine  │ carol   │ T1003.001   │ 2026-06-21 │
└────────┴─────────────────────────────────────┴─────────┴─────────┴─────────────┴────────────┘

Showing 4 of 50 detections (filtered by stage: refine)
```

**Why this is useful:**
- See ALL detections at Refine in one view
- Notice Bob owns 2 of them (maybe offer help?)
- See D-0012 hasn't been updated in 4 days (stale?)
- Prioritize based on technique (T1003.001 appears twice)

---

## Multiple Filters

### Filter by Stage and Owner

```bash
adef detection list --stage refine --owner bob
```

**Output:**
```
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ ID     ┃ Title                               ┃ Stage   ┃ Owner   ┃ Technique   ┃ Updated    ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ D-0002 │ LSASS memory dumping                │ refine  │ bob     │ T1003.001   │ 2026-06-23 │
│ D-0003 │ Kerberoasting via Rubeus            │ refine  │ bob     │ T1558.003   │ 2026-06-24 │
└────────┴─────────────────────────────────────┴─────────┴─────────┴─────────────┴────────────┘

Showing 2 of 50 detections (filtered by stage: refine, owner: bob)
```

**Use case:** "Show me Bob's in-progress detections"

---

### Filter by Multiple Stages

```bash
adef detection list --stage refine,govern
```

**Output:**
```
Shows all detections at EITHER refine OR govern stage
(Useful for "show me everything in active development/deployment")
```

---

### Filter by Technique

```bash
adef detection list --technique T1003.001
```

**Output:**
```
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ ID     ┃ Title                               ┃ Stage   ┃ Owner   ┃ Technique   ┃ Updated    ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ D-0002 │ LSASS memory dumping                │ refine  │ bob     │ T1003.001   │ 2026-06-23 │
│ D-0012 │ Mimikatz via memory                 │ refine  │ carol   │ T1003.001   │ 2026-06-21 │
│ D-0034 │ Procdump LSASS                      │ evolve  │ alice   │ T1003.001   │ 2026-06-15 │
└────────┴─────────────────────────────────────┴─────────┴─────────┴─────────────┴────────────┘

Showing 3 of 50 detections (filtered by technique: T1003.001)
```

**Use case:** "Show me all LSASS dumping detections"

---

## JSON Output for Scripting

```bash
adef detection list --stage refine --format json
```

**Output:**
```json
[
  {
    "id": "D-0002",
    "title": "LSASS memory dumping",
    "current_stage": "refine",
    "owner": "bob",
    "technique": "T1003.001",
    "created": "2026-06-20T10:00:00-07:00",
    "updated": "2026-06-23T14:30:00-07:00",
    "rule_uuid": ""
  },
  {
    "id": "D-0003",
    "title": "Kerberoasting via Rubeus",
    "current_stage": "refine",
    "owner": "bob",
    "technique": "T1558.003",
    "created": "2026-06-21T09:00:00-07:00",
    "updated": "2026-06-24T11:15:00-07:00",
    "rule_uuid": ""
  }
]
```

**Use case:** Integrate with other tools, scripts, dashboards

---

## Real-World Workflows

### 1. Daily Standup
```bash
# See what's in progress
adef detection list --stage observe,refine,govern

# Count by owner
adef detection list --format json | jq 'group_by(.owner) | map({owner: .[0].owner, count: length})'
```

### 2. Sprint Planning
```bash
# What's ready to advance?
adef detection list --stage refine

# Who's overloaded?
adef detection list --owner alice
adef detection list --owner bob
```

### 3. Coverage Review
```bash
# All credential access detections
adef detection list --technique T1003

# See which stages they're in
adef detection list --technique T1003 --format json | jq 'group_by(.current_stage)'
```

### 4. Stale Detection Cleanup
```bash
# Show oldest detections at Observe
adef detection list --stage observe --format json | jq 'sort_by(.updated) | .[0:5]'
```

---

## How Stages Work in Frontmatter

### Every journal has this in the YAML frontmatter:

```yaml
---
id: D-0002
title: LSASS memory dumping
current_stage: refine  ← This is what --stage filters on
owner: bob
created: '2026-06-20T10:00:00-07:00'
updated: '2026-06-23T14:30:00-07:00'
---
```

### Stage progression:

```
find → observe → refine → govern → evolve
```

When you run:
```bash
adef detection observe D-0002
```

The `current_stage` changes from `find` to `observe`.

When you run:
```bash
adef detection list --stage observe
```

It finds all journals where `current_stage: observe`.

---

## Implementation Details (For Reference)

### Pseudocode

```python
def list_detections(stage=None, owner=None, technique=None):
    journals_dir = Path("~/work/adef-workspace/journals")
    
    # Step 1: Find all journal files
    journal_files = journals_dir.glob("D-*.md")
    
    # Step 2: Parse each file
    detections = []
    for file in journal_files:
        content = file.read_text()
        frontmatter = parse_yaml_frontmatter(content)
        detections.append(frontmatter)
    
    # Step 3: Apply filters
    if stage:
        detections = [d for d in detections if d['current_stage'] == stage]
    if owner:
        detections = [d for d in detections if d['owner'] == owner]
    if technique:
        detections = [d for d in detections if technique in d.get('technique', '')]
    
    # Step 4: Display
    display_table(detections)
```

### What gets read from journals:

From `journals/D-0002.md`:
```yaml
---
id: D-0002                          ← Column: ID
title: LSASS memory dumping         ← Column: Title
current_stage: refine               ← Filter: --stage
owner: bob                          ← Filter: --owner, Column: Owner
created: '2026-06-20T10:00:00-07:00'
updated: '2026-06-23T14:30:00-07:00' ← Column: Updated
rule_uuid: ''
---
```

The command **does NOT** read the full markdown body, just the frontmatter (faster).

---

## Comparison with Existing Commands

### Today (Manual)
```bash
# To see what's at Refine stage:
grep -l "current_stage: refine" ~/work/adef-workspace/journals/*.md
# Output: /path/journals/D-0002.md
#         /path/journals/D-0003.md
# (Not formatted, no other info)
```

### With `adef detection list`
```bash
adef detection list --stage refine
# Output: Formatted table with all fields, counts, colors
```

**10x better UX.**

---

## Why `--stage refine` is Useful

### Common questions it answers:

1. **"Which detections are in Refine?"**
   ```bash
   adef detection list --stage refine
   ```

2. **"How many detections are stuck in Refine?"**
   ```bash
   adef detection list --stage refine
   # Output: "Showing 4 of 50 detections"
   ```

3. **"Who owns the Refine-stage detections?"**
   ```bash
   adef detection list --stage refine
   # Look at Owner column
   ```

4. **"Which Refine detections haven't been touched in a week?"**
   ```bash
   adef detection list --stage refine --format json | jq '.[] | select(.updated < "2026-06-18")'
   ```

5. **"I want to help with Refine-stage work, what's available?"**
   ```bash
   adef detection list --stage refine
   # Pick one and advance it
   ```

---

## Related Commands

```bash
# List all at Refine
adef detection list --stage refine

# Show detail of one
adef detection show D-0002

# Advance it to next stage
adef detection govern D-0002

# See updated list
adef detection list --stage govern
# (D-0002 now appears here)
```

---

## Summary

**`adef detection list --stage refine`** answers:
- "Which detections are currently in Refine stage?"

**How it works:**
1. Scans all `journals/D-*.md` files
2. Parses YAML frontmatter
3. Filters to `current_stage: refine`
4. Displays as formatted table

**Why it's useful:**
- See all Refine detections at once
- Identify bottlenecks
- Prioritize work
- Track progress

**Current status:**
- ❌ Not implemented yet (proposed for v0.1.1)
- 🔴 P0 priority (critical for visibility)

---

## Try It (Once Implemented)

```bash
# Basic usage
adef detection list

# Filter by stage
adef detection list --stage refine

# Multiple filters
adef detection list --stage refine --owner bob

# JSON output
adef detection list --stage refine --format json

# All in-progress detections
adef detection list --stage observe,refine,govern
```
