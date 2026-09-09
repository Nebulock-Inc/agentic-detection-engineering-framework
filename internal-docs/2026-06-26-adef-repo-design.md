# ADEF Repo Design — Agentic Detection Engineering Framework

**Date:** 2026-06-26
**Status:** Design (brainstormed, validated section-by-section)
**Purpose:** Define what the ADEF community repo is — CLI surface, skills/sub-agents,
and the artifacts that tie them together — optimized for agentic workflows.

---

## 1. What ADEF is

ADEF is the detection-engineering sibling of ATHF. Same worldview, same agentic
posture, different surface area: ATHF answers *"is this happening?"* (hunting);
ADEF answers *"codify this so it pages someone"* (production detections).

The lifecycle is **FORGE**: Find → Observe → Refine → Govern → Evolve.

**The doctrine — be opinionated.** The moat is not "another detection framework";
it is *how* we think detections should be stored, organized, tagged, and grounded,
and *why*. Users get defended defaults and add their own flavor on top.

### v1 scope — the layer on top of a rules repo

ADEF v1 is deliberately scoped as **the enrichment, memory, and guidance layer that
sits on top of a team's existing rules repository.** You point ADEF at a repo of
detections you already have; it **reads, catalogs, journals, organizes, tags, and
documents** them, and **assists in creating new detections** — research, authoring,
refinement, all schema-grounded and coverage-aware.

What v1 deliberately does **not** do:
- **Does not extract rules from a SIEM.** Assume a file-based rules repo. (SIEM
  export is a later iteration; the results-in seam leaves the door open.)
- **Does not deploy rules.** Teams deploy through their own pipeline. ADEF's Govern
  stage is a *readiness & documentation* gate, not a deployment action.
- **Does not own rule logic by default.** The team's repo stays the source of truth
  for the query; ADEF references and *enriches* it (see §4.1).

The value proposition in one line: **ADEF brings mature, opinionated tagging,
categorization, organization, and documentation to detections you already have —
and helps you author new ones — without asking you to migrate or change how you
deploy.**

---

## 2. Shared-DNA principle: allow integrations, don't provide them

ADEF mirrors ATHF's integration posture exactly, stated once as a principle so it
propagates everywhere instead of being re-decided per feature:

> **ADEF defines the seams (the formats it ingests and emits) and ships zero
> transport. Anything that talks to a vendor tool — running a query, sampling for
> schema discovery, pulling signal volume — happens through whatever the user
> already has. ADEF consumes results and remembers them; it never reaches out.**

Consequences:
- **One seam, not many.** Query-test, schema-learn, and schema-diff all ingest
  rows (JSON/CSV) via `--results -` (stdin/file). How you got the rows is yours.
- **No bundled connectors, no adapter interface, no baked-in MCP-tool assumption.**
  The loosest possible contract: results in.
- **CI-enforced, not hoped.** `tests/test_no_vendor_connectors.py` already guards
  this. The principle is the *why* behind the guard.
- **Sharpens the Nebulock line:** integrations / transport / always-on runtime =
  product territory. Formats + memory + lifecycle + on-demand intelligence =
  framework territory.

---

## 3. Architecture — three layers

```
┌─────────────────────────────────────────────────────────────┐
│  SKILLS / SUB-AGENTS  (the brain — optional install)          │
│  They THINK. They never write state directly. They call CLI.  │
└───────────────────────────┬───────────────────────────────────┘
                            │ shells out / MCP calls
┌───────────────────────────▼───────────────────────────────────┐
│  CLI  (the engine — pip install, always required)             │
│  ALL durable state mutations. CI-enforced invariants live here.│
└───────────────────────────┬───────────────────────────────────┘
                            │ reads/writes
┌───────────────────────────▼───────────────────────────────────┐
│  WORKSPACE  (the memory — ~/work/adef-workspace/)             │
└───────────────────────────────────────────────────────────────┘
```

**State ownership — the load-bearing rule:** every state write (new detection,
stage transition, schema persist, run record) goes through the CLI. Skills produce
*proposals*; the CLI *commits* them. This keeps the hard rules (no upstream
`detections/` writes, four engines only, no vendor connectors) as **enforced code**,
not things a model must remember. Skills are primary *experientially*; the CLI is
primary *architecturally*.

**Two install tiers:**
- `pip install adef` → CLI + workspace + MCP. Works fully headless / in CI. Source of truth.
- `adef skills install` → drops skill/sub-agent files into the user's `.claude/`
  (+ parallel path for Cursor/Copilot). Optional, version-pinned to the CLI.

**Relationship to v0.1.0:** the original "wrap, don't rewrite" posture is the v1
default and is *vindicated* by the scope decision — ADEF sits on top of the team's
repo, which stays the source of truth for rule logic. ADEF's owned artifacts are the
**journal** + a **catalog/enrichment record** that *references* the rule (`rule_ref:`)
and carries the value-add (strategy, taxonomy, tags, MITRE, organization). Detections
*authored from scratch in ADEF* may still carry inline logic, but reference-and-enrich
is the primary model for an existing corpus.

---

## 4. The three workspace artifacts

Three artifact types, separated because they change at different rates and are read
for different reasons.

```
~/work/adef-workspace/
├── detections/                       ← the WHAT (structured, diffable)
│   ├── windows/
│   │   ├── D-0001-mshta-suspicious-child-process.yml
│   │   └── D-0005-lsass-memory-access.yml
│   ├── linux/
│   ├── cloud-aws/
│   ├── cloud-azure/
│   ├── identity/                     ← Okta/Entra/auth, cross-host
│   ├── network/
│   ├── multi-platform/               ← escape hatch: OS-agnostic, multi-cloud
│   ├── INDEX.yml                     ← generated: ID→path + reverse maps
│   └── views/                        ← generated, read-only, human browsing
│       ├── by-tactic/execution.md
│       ├── by-engine/
│       └── by-data-source/
├── journals/                         ← the WHY/WHEN (append-only history)
│   └── windows/D-0001.md             ← mirrors detection platform tree
├── schema/                           ← the GROUND TRUTH (learned, re-runnable)
│   ├── edr_process.yml
│   └── schema.lock                   ← last-known hash, for drift diff
├── config/adef.yml
└── templates/  DETECTION.yml, FORGE.md
```

### 4.1 Detection — `detections/<platform>/D-XXXX-<slug>.yml`

The enrichment/catalog record. It **references** a rule in the team's repo
(`rule_ref:`) and owns the value-add layer: slim-ADS strategy fields + two-axis
taxonomy + tags + MITRE + organization. The team's repo stays the source of truth
for the query logic; ADEF does not modify it. Detections *authored from scratch in
ADEF* may carry inline `query`, but `rule_ref` is the primary model for an existing
corpus.

```yaml
id: D-0001
title: Suspicious mshta.exe child process
status: draft              # draft | ready | tuning | deprecated  (ADEF tracks readiness, not live state)
stage: refine              # find | observe | refine | govern | evolve
owner: alice
created: 2026-06-26
updated: 2026-06-26

# --- Taxonomy (two orthogonal axes) ---
kind: atomic               # axis 1: atomic | correlation | composite
engine: sigma              # axis 2: sigma | sql | sch_sql | composite
mitre: [T1218.005, T1059.003]   # full, honest multi-mapping
data_sources: [process_create]
actors: []                 # optional

# --- Strategy (slimmed Palantir ADS) ---
goal: >                    # one sentence: the malicious thing this catches
strategy: >                # how it works, in prose
assumptions: []            # what must be true (logging on, fields present)
blind_spots: []            # known evasions / gaps
false_positives: []        # known benign triggers
priority: medium           # severity / risk
response: >                # what an analyst does when it fires

# --- Logic ---
rule_ref: rules/windows/mshta.yml   # primary: pointer into the team's rules repo
query:                              # optional inline logic (ADEF-authored from scratch)
```

**Dropped/merged from ADS, and why:** *Categorization* → replaced by richer
`kind`+`engine`+`mitre`. *Validation* → lives in the journal as timestamped test
results (it goes stale as a static field). *References* → journal, or a single
queryable `references: []` if wanted.

### 4.2 Journal — `journals/<platform>/D-XXXX.md`

Unchanged in spirit from v0.1.0. YAML frontmatter + timestamped FORGE stage blocks.
Answers "why does this exist, what's been tried, what's next?" **Volatile facts that
go stale (backtest counts, tuning decisions, test runs) live here as timestamped
entries, not in the detection YAML.**

### 4.3 Schema — `schema/<source>.yml`

The living data-shape artifact. Per source: fields, types, population rates,
last-seen, cardinality. Answers "can I even write this on our data?" Re-running
discovery diffs against this (§7).

**Why three, not one:** "do we cover mshta?" reads *detections* (cheap, structured).
"should we deprecate?" reads the *journal* (history). "can we build this?" reads
*schema* (grounding). Collapsing them forces every read to parse everything. The
`D-XXXX` ID ties all three; journal frontmatter and detection YAML cross-reference by ID.

---

## 5. Organization — platform folders, everything else is metadata

**Decision:** folder = **platform** (the one reliably single-valued dimension).
Tactic, engine, data source, actor are all multi-valued and live in YAML +
generated indexes/views — **never** in the path.

Why: a detection legitimately maps to N tactics; a file lives at exactly one path.
Forcing tactic into the path means picking a fake "primary tactic" or duplicating
files. Platform sidesteps this — "which folder?" almost never has a bad answer.
Cross-platform detections get the `multi-platform/` escape hatch.

Rules:
- **`INDEX.yml` is generated, never hand-edited.** `ID → path` + reverse maps
  (`by-tactic`, `by-engine`, `by-data-source`, `by-actor`) → O(1) lookup, no tree walk.
- **`views/` are generated read-only** — the human-browsable "all Execution
  detections" lists. Regenerated on every write; never drift.
- **Journals mirror the platform tree** so detection + journal sit side by side.
- Moving a file between platform folders is safe — `adef reindex` rebuilds
  INDEX + views. The `D-XXXX` ID is the only stable reference anything depends on.

---

## 6. Skills & sub-agents catalog (the optional brain)

Each skill *thinks*, then calls the CLI to *commit*. ~5 coarse user-facing skills
keep the mental model small; narrow sub-agents (several already in v0.1.0
`agents/`) do composable work underneath.

| Skill (user-invoked) | FORGE | What it does | Commits via |
|---|---|---|---|
| **adef-research** | Find | CTI → candidates, *gap-checked* vs corpus **and** *schema-grounded* vs learned data. Outputs prioritized, deduped, buildable candidates (incl. "70% covered by D-0005, extend it"). | `adef detection new` |
| **adef-author** | Observe→Refine | Drafts logic grounded in schema; picks kind/engine; fills slim-ADS; runs similarity/overlap/verification; runs & records test queries. | `adef detection observe/refine/test`, writes `D-XXXX.yml` |
| **adef-schema** | cross-cutting | Drives discovery via the user's transport, then `adef schema learn`; on re-run interprets the drift diff. | `adef schema learn/diff` |
| **adef-coverage** | cross-cutting | "Do we already cover X? Where are the gaps?" Reads INDEX + MITRE → coverage / partial-coverage verdicts. | read-only |
| **adef-evolve** | Govern→Evolve | Reads journal history + drift report + pasted signal data → recommends tune / keep / deprecate, with rationale. | `adef detection govern/evolve` |

**Sub-agents** (orchestrated, not user-facing): `rule-similarity`, `rule-overlap`,
`verification`, `schema-diff-interpreter`, `tune-recommender`, `deprecation-recommender`.

**ADEF research vs ATHF research:** ADEF research wears a *detection lens* — every
CTI input is (a) checked against the existing corpus for full/partial coverage and
(b) grounded against the learned schema (can we build it on our data?). Output is
deduplicated, buildable, prioritized candidates — not raw hunt hypotheses.

---

## 7. The query/results seam (authoring loop + schema)

Running a query means talking to the SIEM — which the framework never does. Per §2,
ADEF defines the **results-in contract** and consumes rows; transport is the user's.
Query execution and schema discovery are the *same door*.

**ADEF owns:** a durable **run record** (query, source, timestamp, row count, capped
sample, verdict), the CLI verb to persist it, and the **acceptance-criteria check**
(FP-rate / volume vs the detection's targets — pure logic, no transport).

**Authoring loop:**
```
adef-author drafts query in D-0047.yml
   ├─→ runs query via USER'S tool (their MCP/adapter/script)   ← transport, external
   │     returns rows
   ├─→ skill reads results, decides "too noisy / good / misses X"
   └─→ adef detection test D-0047 --results -                  ← CLI commits
         → journal ### Refine/Test block:
           query, source, 1,240 rows, 3 sample, FP-rate 8% > target 2% → FAIL
   (iterate: tighten, run, test again — every run journaled)
```

This is where the comparison doc's missing **backtesting / acceptance criteria**
finally lands. ADEF's value is not running the query — it is making every run
*remembered and gated*.

---

## 8. Schema discovery + drift loop

The schema artifact is **living**, with an on-demand drift loop:

1. **Learn** — point ADEF at the data you build on; sampling runs via the user's
   transport; `adef schema learn <source> --results -` persists the field/schema
   inventory.
2. **Diff** — re-run later; `adef schema diff <source> --results -` diffs vs stored,
   produces a **drift report** naming detections whose referenced fields
   changed/vanished ("fields X,Y changed; D-0003, D-0007 may be broken").
3. **Feed back** — drift re-enters the lifecycle at **Evolve** as tuning/repair
   candidates.

**Framework/product line:** ADEF owns *on-demand* learn + diff + broken-detection
report (run it manually or wire into your own CI/cron). *Continuous always-on*
monitoring, live signal-health dashboards, and auto-alerting are Nebulock product.

---

## 9. CLI command surface

```bash
# Workspace
adef init                          # scaffold ~/work/adef-workspace/
adef reindex                       # rebuild INDEX.yml + views/ after manual moves

# Detection lifecycle (FORGE)
adef detection new "<title>" --platform windows [--kind atomic --engine sigma]
adef detection observe  D-0047 --note "..."
adef detection refine   D-0047               # similarity→overlap→verification chain
adef detection test     D-0047 --results -   # ingest results → journal Test block + acceptance check
adef detection govern   D-0047               # readiness/documentation gate → status: ready
adef detection evolve   D-0047 --note "..."

# Browsing / lookup (read-only; what skills lean on)
adef detection list [--platform ...] [--tactic ...] [--engine ...] [--status ...]
adef detection show D-0047
adef coverage [--tactic ...] [--actor ...]   # gap / partial-coverage report

# Schema (living data artifact)
adef schema learn <source> --results -
adef schema diff  <source> --results -       # drift report, names affected detections
adef schema show  <source>

# Integration
adef hunt-promote H-0042                     # ATHF hunt → draft detection (Find)
adef backfill                                # detections+journals for an existing rule repo

# Skills installer (optional brain layer)
adef skills install [--target .claude]

# MCP
adef-mcp                                     # FastMCP server exposing all of the above
```

Every verb maps to an MCP tool of the same name — a skill can shell out or call MCP,
same surface either way. New vs v0.1.0: `detection test`, `coverage`, `schema *`,
`reindex`, `skills install`.

---

## 10. End-to-end flow

- **Find** — adef-research on a CTI report → gap-check (INDEX) + schema-ground → picks
  candidate → `adef detection new` writes `detections/windows/D-0047-*.yml` + journal
  Find block + updates INDEX.
- **Observe** — adef-author reads `schema/edr_process.yml`, confirms fields/populations
  → `adef detection observe` appends telemetry facts.
- **Refine** — adef-author drafts logic, `adef detection refine` runs the chain (journal
  blocks); iterates with `adef detection test --results -` (journal Test blocks).
- **Govern** — `adef detection govern` is a *readiness/documentation* gate (owner,
  severity, response guidance, peer-review note) → `status: ready`, journal records
  gate evidence. ADEF makes no deployment claim; the team deploys via their own pipeline.
- **Evolve** — `adef schema diff` flags D-0047's changed field → adef-evolve reads journal
  + drift + pasted signal volume → recommends tune → `adef detection evolve --note "..."`.

The spine: **CLI writes all three artifacts atomically and keeps INDEX/views in sync;
skills only read artifacts and call CLI verbs.**

---

## 11. Open threads (deliberately deferred)

- Schema refresh cadence over time (beyond on-demand diff).
- Composite detections that combine signals → findings — definitional layer exists
  (signals = detection output; findings = correlated/triaged signals); orchestration deferred.
- Cursor/Copilot skill-install parity details.
- Which gray-zone items (baselines/lookups, governance/approval flows) stay framework
  vs product — decided per-feature, not by blanket rule.
