---
name: forge-stage
description: Drive a detection through the FORGE stages after Find — Observe (baseline real telemetry, validate or kill the hypothesis), Refine (similarity/overlap/verification gates), Govern (deployment gate decision), Evolve (tune or deprecate). Use when the user advances a detection stage, runs or interprets baseline queries, says a query returned zero results, tunes a threshold, preps a detection for deployment, or asks whether to tune/deprecate. Encodes the workspace conventions — artifacts in analysis/<D-XXXX>/ never /tmp, findings as journal notes, one summary per stage, honest status claims. For creating detections use detection-author; for MITRE changes use mitre-tagger.
---

# FORGE Stage Work — Observe, Refine, Govern, Evolve

Guide a detection through the lifecycle stages after Find. Every convention
here comes from real sessions where excellent analysis was undermined by
placement, duplication, or claims the record didn't back.

## Ground rules (all stages)

1. **Artifacts live in the workspace: `analysis/<D-XXXX>/`. Never `/tmp`,
   never outside the workspace.** Write them there directly — don't draft in
   `/tmp` and copy. The workspace IS the durable memory; `/tmp` is gone at
   reboot (a live Observe session parked its whole methodology there).
2. **Findings land as journal notes on the stage transition**, via the CLI:
   `adef detection <stage> D-XXXX --note "..."` (repeatable; re-running a
   stage is idempotent and appends the note only). Every artifact you write
   gets a note pointing at it — an unreferenced artifact is invisible.
3. **One summary document per stage, maximum.** The journal is the narrative;
   a summary is an index, not a celebration. A live Govern session produced
   three overlapping "complete!" documents (~800 lines saying one thing) —
   that's noise the next engineer has to wade through. No banner art.
4. **Claims must match the record.** Say what `adef detection show D-XXXX`
   says. If gates passed but the record reads `status: draft`, write "gate
   decision: ready — recorded in journal; record status remains draft (no
   status CLI yet)". Never declare "production ready" in prose the record
   contradicts.
5. **Use the write seams; never hand-roll their jobs.** MITRE changes:
   `adef detection tag-mitre D-X T… [--remove]` (validated, INDEX rebuilt).
   INDEX: `adef reindex` — a hand-rolled rebuild produced a *wrong* index in
   a live session. Hand-editing record YAML is allowed only for
   `origin: authored` records where no seam exists (query text, title,
   owner) — and then bump `updated:`, run `adef reindex`, and keep the
   journal frontmatter title in sync if the title changed.

## Observe — characterize reality before trusting the hypothesis

Goal: measure what the data actually does. **Zero results is a finding, not a
failure** — it means the detection would never fire, and discovering that now
is the stage doing its job.

- Draft ONE baseline query file + ONE interpretation guide into
  `analysis/<D-XXXX>/`. Cover: volume/time distribution, source cardinality,
  field population rates, threshold sensitivity (test several values),
  top-pattern extraction (allowlist candidates), temporal patterns.
- ADEF never connects to the SIEM — the engineer runs the queries and brings
  results back. Interpret against decision points you stated up front.
- Zero results → diagnose in order: does the data exist at all → are the
  fields populated on the events the filter selects (a field can exist on the
  source but never co-occur with your filter) → is the hypothesis wrong.
  Use `adef schema show <source>` as evidence, not memory.
- Outcomes to record via `--note`:
  - **Confirmed** — threshold tuned with evidence; proceed.
  - **Invalidated** — the honest win. Pivot the detection: update the query,
    title, and MITRE through the seams (`tag-mitre --remove` old + add new,
    `adef reindex`, sync the journal title). Journal the invalidation
    evidence — the dead hypothesis is knowledge.
  - **Inconclusive** — say what data would decide it.

## Refine — the similarity / overlap / verification gates

- `adef detection refine D-XXXX` runs the chain **once, on the transition**.
  `WrapperUnavailable` blocks in the journal are designed degradation when
  wrapper agents aren't configured — say so; don't call it a failure.
  `--note` appends never re-run the chain; `--chain` re-runs it explicitly
  (e.g. after configuring wrappers).
- When wrappers are unavailable, run the gates manually:
  - **Similarity**: `adef detection search "<concept>"` +
    `adef detection list --tactic/--engine`. Name the verdict per neighbor:
    *duplicate* (stop — tune the existing rule instead) vs *complementary*
    (different layer/telemetry — keep both, cross-reference in the journal).
  - **Overlap**: would this rule's triggers heavily co-fire with another's?
    Compare data sources and trigger logic, not just titles.
  - **Verification**: `adef schema check --detection D-XXXX` must be clean;
    run the query live in the SIEM if possible and record hit counts.
- One combined findings note (or one per gate); at most one analysis doc.

## Govern — the deployment gate decision

- Cover: false-positive investigation actions (name the owner and system,
  e.g. "CMDB lookup on 10.60.10.11 before enabling"), alert routing and
  severity, threshold rationale, ownership, review cadence.
- **State the gate decision explicitly and honestly** (ground rule 4): the
  decision lives in the journal note; the record's `status` field has no CLI
  setter yet, so name both facts rather than papering over the gap.
- ADEF does not deploy. Getting the rule into the SIEM or repo is the team's
  push — read-only invariant. Offer the query text; don't pretend to ship it.

## Evolve — tune or deprecate, with evidence

- Triggers: FP rate drift, volume change, telemetry loss, superseding rule.
- Tune: journal the before/after threshold and the evidence that forced it.
- Deprecate: journal the reason and the replacement (`D-XXXX`) if any — a
  deprecation without a pointer strands the coverage it provided (check
  `adef coverage` for what goes dark).

## Anti-patterns (each observed live)

- Writing artifacts to `/tmp`, or drafting there and copying after
- Multiple overlapping stage summaries; celebration formatting
- Expecting `refine --note` to re-run the chain (it doesn't; use `--chain`)
- Hand-editing `mitre:` or hand-rolling an INDEX rebuild
- Declaring "production ready" while the record says `status: draft`
- Advancing a stage with no note — an empty transition tells the next
  engineer nothing
