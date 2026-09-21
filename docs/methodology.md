# FORGE — The ADEF Methodology

> ADEF gives detection engineering a memory and a lifecycle. **FORGE** is the lifecycle.

## What FORGE is

FORGE is a five-stage cycle for the life of a detection. It is to detection engineering what PEAK is to threat hunting and what LOCK is to ATHF: a deliberate, named loop that replaces ad-hoc shipping with a durable record of *why* a detection exists, *how* it was characterized, and *what comes next*.

> **F**ind → **O**bserve → **R**efine → **G**overn → **E**volve

FORGE is iterative, not linear. A rule rarely passes through it once. The point is not the order — the point is that **every detection has a stage**, and every transition leaves a timestamped trace in a journal.

ADEF is the **paired sibling** of [ATHF](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework) (Agentic Threat Hunting Framework). ATHF is for hunting. ADEF is for what comes after a hunt — codifying repeatable detection logic. Detections graduate from hunts via `adef hunt-promote`. They are not in a successor relationship; they are designed to coexist.

---

## The five stages

### Find — what triggered this detection?

The Find stage captures the *why*. Every detection begins because a human (or agent) noticed a gap, read a threat-intel report, finished a hunt, or got asked by an IR team. This is where that motive lives.

What goes here:
- The gap, signal source, intel report, or hunt that motivated the detection.
- The one-sentence hypothesis the detection will test.
- Initial MITRE ATT&CK mapping (technique IDs are best — sub-techniques even better).
- Whether this is paired with an existing upstream rule (paste UUID into frontmatter).

**Example.** A FIN7 retrospective from Mandiant describes the actor running `mshta.exe` from `C:\Users\Public\` to stage payloads. Find writes: *"Hypothesis: mshta.exe with parent shell from a Public\ writable path is rare in benign telemetry. Source: Mandiant 2024 FIN7 retrospective. ATT&CK: T1218.005."*

### Observe — characterize real telemetry before defining "weird"

You can't find weird if you don't know normal. Observe forces you to look at production data before crafting query syntax.

What goes here:
- Which data source(s) carry the relevant fields (note OCSF or vendor-native).
- Field population rates: which fields are reliably populated vs. sparse.
- Volume / cardinality estimates over a representative window.
- A sample query that surfaces the *behavior* (top of Pyramid of Pain), not just an indicator.
- Note the baseline of normal — what does the legitimate version of this look like?

**Example.** Pull 30 days of `process_create` events where `parent_process_name` is a shell and `process_name` is `mshta.exe`. Find ~140 events from 6 hosts; isolate that 4 hosts are dev workstations running an internal MSI installer. *That* is the baseline normal. The detection has to survive it.

### Refine — iterate the rule with structured feedback

Refine is where the rule is drafted, redrafted, and trimmed. ADEF's Refine stage automatically chains three steps, native by default (v2, 2026-09) — native and vendor-free are not the same guarantee here: RuleSimilarity's default `auto` mode can call the Anthropic API (see CLAUDE.md's "The Refine Chain" for the exact data egress); only its `bm25` mode is vendor-free.

1. **RuleSimilarity** — BM25 nearest-neighbor search over the catalog — does a rule like this already exist?
2. **RuleOverlap** — deterministic duplicate/complementary/redundant classification within the target's MITRE technique cluster — do its triggers heavily overlap with another rule's findings?
3. **Verification** — schema field-usage + four-engine-constraint check — would the rule survive those constraints and pass validation?

Each result is appended to the detection's journal under a `### Refine / <step>` heading. The chain does not abort on failure; partial results are valuable. Each step honors an optional `ADEF_WRAPPER_<KEY>` env var override to delegate to a configured upstream agent (exactly as before v2, if explicitly set).

**Example.** The Overlap step appends this to the journal — one sub-bullet per
cluster-mate, most confident first:

```markdown
### Refine / Overlap (2026-09-18T14:32:06-04:00)

- **detection_id:** D-0001
- **result:**
  - **detection_id:** D-0001
  - **techniques:** ['T1218.005']
  - **overlaps:**
    - other_id: D-0042, overlap_type: duplicate, confidence: 0.91, reasoning: Near-identical query logic (91% similar)
    - other_id: D-0117, overlap_type: redundant, confidence: 0.78, reasoning: D-0117's query is a strict superset of D-0001's predicate — D-0117 fires on a subset of what D-0001 already covers
    - other_id: D-0203, overlap_type: complementary, confidence: 0.34, reasoning: Same technique, distinct detection logic — different coverage angle
```

Note what the classifier does and doesn't give you: `other_id` is always a
`D-XXXX` (the catalog ID, never a filename), the `overlap_type` is one of
exactly three values, and there is no "recommendation" — deciding to merge,
narrow, or keep both is the engineer's call, which is why the `reasoning`
explains the relationship rather than prescribing an action. `duplicate`
requires ≥0.85 similarity; the 0.78 pair above is classified on the substring
relation, not the ratio.

### Govern — deploy with quality gates, ownership, review cadence

A detection without ownership is a detection without a future. Govern names the engine, the human, and the calendar.

What goes here:
- **Engine type** — exactly one of `sigma | sql | sch_sql | composite` (no new engines in v0.1.0).
- **Severity / risk score / RBA contribution** — calibrate against neighbors.
- **Owner** — the human who carries the pager for this rule.
- **On-call rotation** — which rotation responds when this fires.
- **Review cadence** — every N days/weeks. Calendar it.
- **Deployment gate evidence** — peer review, backtest summary, false-positive review.

**Example.** Govern entry: *"Engine: sigma. Severity: medium. RBA: +35. Owner: @sydney. Rotation: weekday-detection-rota. Review cadence: 90d. Backtested 14d / 480 events / 2 TP / 1 FP."*

### Evolve — tune, deprecate, replace

Detections never finish — they iterate. Evolve is the structured place to record *why* a detection's behavior was tuned, retired, or replaced.

What goes here:
- Recent tuning decisions and the metrics that prompted them.
- Performance trend (signal volume, FP ratio, latency).
- Replacement / deprecation rationale (if any).
- Successor rule(s) (if deprecated).

**Example.** Evolve entry six months later: *"FP ratio rose to 0.92 over 30d after a Citrix LOLBin deployment whitelisted `mshta.exe` org-wide. Tuning: narrow filter to non-Citrix-managed hosts. Replacement: pair with `windows_citrix_lolbin_baseline.yml`."*

---

## Two related pieces

### Journals are the memory layer

Each detection gets a per-rule markdown file at `<workspace>/journals/D-XXXX.md`. The YAML rule (in its upstream repository) is the *source of truth for what the detection looks for*; the journal is the *source of truth for why, how, and what next*. They are paired by `rule_uuid` in the journal frontmatter.

ADEF never modifies upstream rule YAML. The journal lives in the workspace, not inside the rule repository.

### Why FORGE, not "the SDLC for detections"

Detection engineering is not exactly software development and not exactly hunting. The signal you need to capture across the lifecycle isn't "did this code run" — it's "did this rule survive contact with reality." FORGE is shaped around that question. Each stage forces a small, named act of evidence. The lifecycle is the artifact.

---

## See also

- [maturity-model.md](./maturity-model.md) — L0 Ad-hoc → L4 Agentic. Where on the curve does your team sit?
- [why-adef.md](./why-adef.md) — adoption guide; the practical "why this, why now."
- [Roadmap](./roadmap.md) — what comes after v0.1.0.
