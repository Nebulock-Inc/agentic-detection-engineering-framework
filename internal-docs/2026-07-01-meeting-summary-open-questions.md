# ADEF Meeting Summary — Open Questions & Decisions

**Date:** 2026-07-01  
**Context:** Brainstorming session on 2026-06-26 → scope tightening on 2026-07-01  
**Artifacts:** `2026-06-26-adef-repo-design.md`, `2026-06-26-adef-day-in-the-life.md`

**For the meeting:** This doc surfaces what we've locked and what still needs team
input. The goal is to get feedback on the v1 scope and resolve the open integration
questions before implementation.

---

## What We've Locked (Decisions Made)

### 1. v1 Scope — The Layer on Top

**Decision:** ADEF v1 is deliberately scoped as **the enrichment, memory, and guidance
layer that sits on top of a team's existing rules repository.** It is not a
deployment tool, and it does not extract rules from a SIEM.

- You **point ADEF at a file-based rules repo** (Sigma, Splunk, custom, whatever).
- ADEF **reads, catalogs, journals, organizes (by platform), tags, and documents**
  them — leaving the original repo untouched.
- It **assists in authoring new detections** (research, drafting, refinement), all
  schema-grounded and coverage-aware.
- The team **deploys through their own pipeline**. ADEF doesn't touch deployment.

**Out of v1 scope:**
- Extracting rules from a SIEM (no file repo).
- Deploying rules to a SIEM.
- The "allow integrations, don't provide them" principle leaves the door open for
  both later, but v1 assumes a rules repo exists as files.

**Why this matters:** This sidesteps the hardest, most vendor-coupled problems and
focuses ADEF on the organizing/documenting/guidance layer where it's differentiated.

---

### 2. Reference-and-Enrich (Wrap Primary)

**Decision:** For an existing corpus, ADEF's detection records are
**catalog/enrichment entries** that *reference* rules in the team's repo
(`rule_ref:`), not containers that own the logic. The team's repo stays the source
of truth for query logic.

ADEF owns:
- The **journal** (why/when/history).
- The **enrichment layer**: slim-ADS strategy fields, two-axis taxonomy (kind +
  engine), tags, MITRE mapping, organization.

Detections *authored from scratch in ADEF* may carry inline `query`, but `rule_ref`
is the primary model for existing rules.

**Why this matters:** ADEF "meets you where you are" — no migration, no rewriting
your rules. This is the original v0.1.0 "wrap, don't rewrite" posture, vindicated.

---

### 3. Three Layers — CLI Commits, Skills Think

**Decision:**
- **CLI** = the engine. ALL durable state writes go through it. CI-enforced
  invariants live here (no upstream `detections/` writes, four engines only, no
  vendor connectors). Always required (`pip install adef`).
- **Skills/sub-agents** = the brain. They think, research, draft, recommend — but
  never write state directly. They call the CLI to commit. Optional install
  (`adef skills install`).
- **Workspace** = the memory. Three artifacts: detection (catalog/enrichment),
  journal (history), schema (ground truth).

**Why this matters:** Skills are primary *experientially* (the agentic surface); the
CLI is primary *architecturally* (integrity guarantees). Hard rules stay code, not
model memory.

---

### 4. Platform-as-Folder, Everything Else Metadata

**Decision:** Detections are organized by **platform** (the one reliably
single-valued dimension): `windows/`, `linux/`, `cloud-aws/`, `identity/`,
`multi-platform/`. Tactic, engine, data source, actor are multi-valued and live in
YAML + generated `INDEX.yml` + `views/` — never in the path.

**Why this matters:** Solves the multi-tactic problem (an mshta rule is both
Defense Evasion *and* Execution) without fake "primary tactic" or file duplication.
Platform is intuitive and rarely ambiguous.

---

### 5. Allow Integrations, Don't Provide Them (ATHF DNA)

**Decision:** ADEF defines the *seams* (formats it ingests/emits) and ships zero
transport. Query execution, schema discovery, signal volume — all happen through
whatever the user already has (their MCP, adapter, script). ADEF consumes results
and remembers them; it never reaches out.

Consequence: one seam, not many. `--results -` everywhere (query-test, schema-learn,
schema-diff). CI-enforced via `tests/test_no_vendor_connectors.py`.

**Why this matters:** Same posture as ATHF; sharpens the Nebulock line
(integrations/transport = product; formats + memory + lifecycle = framework).

---

### 6. Govern = Readiness Gate, Not Deployment

**Decision:** `adef detection govern` is a *readiness & documentation* gate (owner,
severity, response guidance, peer-review note) → `status: ready`. ADEF makes no
deployment claim; the team deploys via their own pipeline.

**Why this matters:** Matches the v1 "layer on top" scope. ADEF tracks readiness,
not live state.

---

## What's Still Open (Needs Team Input)

### Open Q1 — How do ADEF-authored rules get into the team's pipeline?

**The tension (from Jarrett's notes):**
> "If we are helping to author new rules, are we making changes to their repo? If
> not, how should someone get an authored rule from ADEF into their pipeline?"

**The situation:**
- ADEF authors a new detection (`D-0047`, status: ready, fully journaled).
- The team's *existing* rules live in their repo (`~/work/our-detections/`).
- The team deploys from that repo.
- ADEF's authored rule is in the *workspace* (`~/work/adef-workspace/detections/`).

**Three options to resolve:**

**A. ADEF writes directly into the team's repo (guided by config).**
- `adef detection new` writes the rule YAML into `~/work/our-detections/windows/`
  (path from workspace config) *and* creates the ADEF catalog/journal in the workspace.
- The rule is immediately in their deployment pipeline. ADEF's catalog references it
  (`rule_ref:`).
- **Pro:** No manual copy step; authored rules land where they need to be.
- **Con:** ADEF now mutates the team's repo (contradicts "wrap, don't rewrite"). Needs
  careful scoping: only *new* rules, never existing ones.

**B. Manual export / copy step (ADEF is a staging area).**
- ADEF-authored rules stay in the workspace. When ready, the engineer runs
  `adef detection export D-0047 --to ~/work/our-detections/` (or copies manually).
- ADEF updates the catalog to point at the exported location (`rule_ref:`).
- **Pro:** ADEF never touches the team's repo unbidden; clean separation.
- **Con:** Friction — an extra step every time you author. Easy to forget.

**C. ADEF's workspace *is* the repo (for teams adopting ADEF fully).**
- The workspace becomes the team's detection repo. They deploy from
  `~/work/adef-workspace/detections/`. No separate "their repo."
- **Pro:** Zero impedance; ADEF is the source of truth.
- **Con:** Only works for greenfield or full-migration teams. Doesn't solve the
  "ADEF on top of an existing repo" use case.

**Recommendation to discuss:** **A for ADEF-authored rules only**, with a config gate
— `adef detection new` can write into the team's repo *if* `config/adef.yml` sets
`rules_root:` and the user opts in. Existing rules stay read-only. Authored rules
are born in the right place. If not configured, fallback to B (manual export).

---

### Open Q2 — How do we assist with writing rules? Schema + MCP guidance?

**The tension (from Jarrett's notes):**
> "ATHF (hunt-vault) works well because it understands our data and we've provided
> that guidance. Beyond data schema, how do we assist with writing the rules? Do we
> suggest users just setup MCP (Splunk, etc)? Do we simply provide guidance on how
> to tell an agent how to write good rules?"

**What we decided:**
- **Schema discovery is first-class.** `adef schema learn <source> --results -`
  persists the field/schema inventory; the author skill grounds all logic in it
  ("can we even write this on our data?").
- **Query execution goes through the user's transport** (MCP, script, adapter) via
  the results-in seam. `adef detection test D-0047 --results -` records every run.

**What's still unclear:**
- Is schema + the results-in seam *enough* for the author skill to write good rules,
  or does it also need:
  - **Example rules from the corpus** (few-shot prompting from D-0001, D-0005)?
  - **SIEM-specific query patterns** (e.g., "here's how Splunk's `tstats` works")?
  - **A 'how to write good rules' primer** in the skill's prompt?
  
**Options:**

**A. Schema-grounded + few-shot from corpus (recommended).**
- The author skill reads the learned schema *and* 2-3 example detections from the
  corpus (same platform, similar kind/engine) to learn the team's query style.
- No SIEM-specific guidance baked in; the skill infers patterns from examples.
- **Pro:** Adapts to the team's existing style. No SIEM coupling.
- **Con:** Quality depends on the corpus having good examples.

**B. Schema + SIEM/engine-specific primers.**
- ADEF ships a library of "how to write good Sigma / SPL / KQL" primers that the
  author skill references based on the detection's `engine:` field.
- **Pro:** Stronger guidance for common engines.
- **Con:** Maintaining primers is work; risks vendor coupling (edging toward "providing
  integrations").

**C. Schema only, rely on the agent's training.**
- The author skill gets the schema and is expected to know how to write queries from
  its training. No few-shot, no primers.
- **Pro:** Simplest; no corpus dependency.
- **Con:** Quality unknown; may produce brittle or non-idiomatic queries.

**Recommendation:** **A (schema + few-shot from corpus)** to start. Test with a real
corpus. Add B (primers) only if teams report the skill writes bad queries.

---

### Open Q3 — ATHF + ADEF Integration: Shared Directory? Shared Commands?

**The tension (from Jarrett's notes):**
> "If someone is using both frameworks, do they live within the same directory (like
> hunt-vault)? If they are that closely connected, do we need to have 2 different
> means for doing something like `athf query`?"

**Current state:**
- ATHF workspace: `~/work/hunt-vault/` (hunts, queries, artifacts).
- ADEF workspace: `~/work/adef-workspace/` (detections, journals, schema).
- `adef hunt-promote H-0042` exists — bridges the two by reading an ATHF hunt and
  creating an ADEF detection (Find stage).

**Three integration models:**

**A. Separate workspaces, explicit bridge commands (current v0.1.0).**
- `~/work/hunt-vault/` and `~/work/adef-workspace/` are siblings.
- `adef hunt-promote H-XXXX` is the *only* connection — it reads ATHF's workspace
  and writes to ADEF's.
- No shared commands; `athf query` stays ATHF, `adef detection test` stays ADEF.
- **Pro:** Clean separation; each framework is standalone. Easier to maintain.
- **Con:** Duplication (schema, query testing, data understanding live in both).
  Jarrett's question: "do we need two ways to do `athf query`?"

**B. Unified workspace, both frameworks side-by-side.**
- `~/work/detection-engineering-workspace/` (or name TBD) holds *both* hunts and
  detections. Directory structure:
  ```
  ~/work/de-workspace/
  ├── hunts/       H-XXXX.md       (ATHF)
  ├── detections/  D-XXXX.yml      (ADEF)
  ├── journals/    D-XXXX.md       (ADEF)
  ├── schema/                      (shared by both)
  └── config/
  ```
- `adef hunt-promote` becomes a workspace-internal operation (same directory).
- `athf query` and `adef detection test` *could* share underlying machinery (both
  use the results-in seam, both record runs).
- **Pro:** No duplication; schema is learned once. Hunt → detection flow is seamless.
- **Con:** Tighter coupling; harder to use one framework without the other. More to
  coordinate on release.

**C. Separate workspaces, shared schema + query layer.**
- Workspaces stay separate, but `schema/` lives in a *shared* location both
  frameworks reference (e.g., `~/.detection-data/schema/`).
- `athf query` and `adef detection test` both invoke a shared query-recording layer
  (maybe a third micro-package `de-query`?).
- **Pro:** DRY on schema/query; frameworks still standalone.
- **Con:** Introduces a third dependency; versioning gets trickier.

**Recommendation for discussion:** Lean toward **B (unified workspace)** if the team
expects most users to run *both* frameworks. The "hunts graduate to detections"
story is smoother, and schema isn't duplicated. The name could be `~/work/detection-eng/`
or `~/work/security-content/` (neutral). If frameworks need to stay fully decoupled,
fallback to **A** and accept the duplication.

---

### Open Q4 — The `detect` Command Overlap (ATHF → ADEF Migration)

**The tension (from Jarrett's notes):**
> "Move detect commands from ATHF → ADEF and some of the ones from detect-vault?"

**Current state:**
- ATHF has `athf detect *` commands (a detection sub-suite within the hunting framework).
- ADEF now has `adef detection *` commands (the full FORGE lifecycle).
- Overlap: both frameworks touch detections.

**The question:** Should the `athf detect *` commands migrate to ADEF, or stay?

**Two options:**

**A. Migrate `athf detect` → `adef detection` (consolidate).**
- ATHF drops its `detect` sub-commands. Teams using ATHF *and* wanting detection
  features install ADEF.
- `athf` is hunting-only; `adef` is detection-only. Clean split by domain.
- **Pro:** No duplication; clear ownership.
- **Con:** ATHF loses detection features unless you also install ADEF (acceptable if
  the product story is "use both").

**B. Keep both, specialize them.**
- `athf detect` stays as a lightweight "convert this hunt finding to a draft detection"
  helper (hunt-centric, minimal).
- `adef detection` is the full lifecycle (FORGE, journals, schema, governance).
- **Pro:** ATHF stays self-contained; ADEF is the power-user layer.
- **Con:** Duplication; users confused about which to use.

**Recommendation:** **A (migrate to ADEF)**, especially if you lean toward the unified
workspace (Q3B). The `athf detect` surface becomes `adef hunt-promote` + `adef detection *`.
ATHF stays pure-hunting; ADEF owns the detection lifecycle. If ATHF needs to stay
standalone, keep a minimal `athf detect draft` that shells out to ADEF if it's installed.

---

### Open Q5 — Format Parsers (How Much to Read from Existing Rules)

**The situation:**
- On Day 0, `adef backfill --rule-root ~/work/our-detections` reads the team's
  existing rules (Sigma, Splunk, Elastic, custom).
- To *catalog and enrich* them (auto-tag with MITRE, categorize by platform/kind,
  extract severity), ADEF needs to *parse* the rules, not just wrap them opaquely.

**The question:** How much parsing do we ship?

**Three options:**

**A. Sigma-first, others as needed (recommended).**
- Ship a solid Sigma parser (most common, already YAML, closest to ADEF's shape).
- Other formats (Splunk `savedsearches.conf`, Elastic detection-rules JSON, KQL)
  get parsers driven by community demand or as v2 work.
- **Pro:** Tight scope; highest-value first. Sigma covers a lot of teams.
- **Con:** Teams using other formats get minimal auto-enrichment (manual tagging).

**B. Generic + pluggable parsers.**
- Define a parser *interface* (`parse_rule(file) -> {title, logic, mitre, severity, ...}`).
- Ship Sigma + one SIEM parser (e.g., Splunk). Community contributes the rest.
- **Pro:** Extensible, future-proof.
- **Con:** More upfront design; edges toward "ADEF maintains format adapters," which
  feels like the vendor-connector problem in disguise.

**C. Raw passthrough only (defer parsing).**
- `adef backfill` creates journals + catalog entries with `rule_ref:`, but doesn't
  parse the rule contents. The MITRE/platform/kind fields start empty; engineer fills
  them in manually or via a separate `adef detection enrich D-XXXX` command later.
- **Pro:** Zero parser maintenance; simplest v1.
- **Con:** Weak Day 0 experience — the catalog is a list of untagged references.
  Auto-enrichment was supposed to be the value-add.

**Recommendation:** **A (Sigma-first)**. Parsing Sigma is tractable and valuable.
Teams using other formats can still *wrap* (journals + references), they just don't
get auto-tagging yet. Add more parsers in v2 based on demand.

---

## Summary — What the Team Should Weigh In On

1. **Q1 — ADEF-authored rules into the pipeline:** Option A (write into their repo
   if configured), B (manual export), or C (workspace *is* the repo)?
2. **Q2 — Rule-writing assistance:** Schema + few-shot from corpus (A), schema +
   SIEM primers (B), or schema-only (C)?
3. **Q3 — ATHF+ADEF integration:** Unified workspace (B), separate workspaces with
   a bridge (A), or shared schema layer (C)?
4. **Q4 — `athf detect` overlap:** Migrate to ADEF (A) or keep both (B)?
5. **Q5 — Format parsers:** Sigma-first (A), pluggable (B), or raw passthrough (C)?

**Artifacts to review:**
- `docs/plans/2026-06-26-adef-repo-design.md` — full design, 11 sections.
- `docs/plans/2026-06-26-adef-day-in-the-life.md` — end-to-end user flow.

Both are untracked; nothing committed yet pending this discussion.
