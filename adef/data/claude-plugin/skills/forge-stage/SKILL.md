---
name: forge-stage
description: Drive a detection through the FORGE stages after Find — Observe (baseline real telemetry, validate or kill the hypothesis), Refine (similarity/overlap/verification gates), Govern (deployment gate decision), Evolve (tune or deprecate). Use when the user advances a detection stage, runs or interprets baseline queries, says a query returned zero results, tunes a threshold, preps a detection for deployment, asks whether to tune/deprecate, or reports that Evolve came back `insufficient-data`. Encodes the workspace conventions — artifacts in analysis/<D-XXXX>/ never /tmp, findings as journal notes, one summary per stage, honest status claims. For creating detections use detection-author; for MITRE changes use mitre-tagger; to get the health numbers Evolve reads into the workspace use health-capture.
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

- `adef detection observe D-XXXX --note "..."` records the transition and the
  findings. There is no chain here — Observe is the engineer running queries
  against their own data and you interpreting what came back.
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

- `adef detection refine D-XXXX` runs the chain **once, on the transition**,
  and all three steps are **native by default** — Similarity, Overlap, and
  Verification execute real ADEF code, not a stub, with no configuration
  needed. Overlap and Verification are always deterministic; they take no
  mode. Only Similarity has a `--similarity-mode`.
  - `WrapperUnavailable` is no longer the default-path message. It now only
    fires when someone has *explicitly* set an `ADEF_WRAPPER_<KEY>` override
    that fails to import — that IS a real misconfiguration worth flagging,
    not designed degradation.
  - A block reading "no catalog record for D-XXXX yet (still journal-only)"
    is a **different, expected** lifecycle state — the detection hasn't been
    catalogued/authored into a rule yet (still Find/Observe). Don't treat it
    as something to fix; catalog or author the rule first if you actually
    need Refine to compare it against anything.
  - `--note` appends never re-run the chain; `--chain` re-runs it explicitly
    (e.g. to pick up a newly-added candidate, or after wiring an
    `ADEF_WRAPPER_*` override) — on a detection **already** at refine, the
    chain does not re-run and any `--similarity-mode` is silently dropped
    without it. The CLI says so, but check for it.
- Run it as `adef detection refine D-XXXX --similarity-mode agent` — the mode
  to use from an assistant session, since you have context ADEF does not and
  your reasoning belongs in the transcript, not a second model call:
  - The command itself now prints a **Similarity shortlist** to stdout: the
    target's own id, title, MITRE IDs, platform, data source, and query,
    plus the same for every candidate (with its score), side by side. No
    separate `adef detection show` round trip per candidate needed — that's
    the one thing this mode used to force you to do.
  - `adef detection show D-XXXX` is still the right call for the *target's*
    own full record (stage, MITRE, platform, needs_review) before or after
    refining — just not for reading candidate queries anymore.
  - Name each neighbor *duplicate* (stop — tune the existing rule instead) vs.
    *complementary* (different layer/telemetry — keep both, cross-reference),
    and say why, from the **full** query text the shortlist just gave you.
    Never classify from a title or score alone.
  - `bm25` (the CLI default) and `agent` both make no network call. `llm` and
    `auto` (when it resolves to `llm`) send the target's title, MITRE IDs, and
    query (truncated to 500 chars), plus each candidate's id, title, and
    snippet, to the Anthropic API — see `docs/cli-reference.md` / `CLAUDE.md`
    for exactly what that snippet contains before using either from a
    sensitive workspace.
- If Similarity, Overlap, or Verification genuinely can't run (an explicit
  wrapper override misconfigured), fall back to running the gates manually:
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

- `adef detection govern D-XXXX --note "..."` records the decision. There is
  no gate chain here — Govern is judgment, and the note *is* the artifact.
- Cover: false-positive investigation actions (name the owner and system,
  e.g. "CMDB lookup on 10.60.10.11 before enabling"), alert routing and
  severity, threshold rationale, ownership, review cadence.
- **State the gate decision explicitly and honestly** (ground rule 4): the
  decision lives in the journal note; the record's `status` field has no CLI
  setter yet, so name both facts rather than papering over the gap.
- ADEF does not deploy. Getting the rule into the SIEM or repo is the team's
  push — read-only invariant. Offer the query text; don't pretend to ship it.

## Evolve — tune or deprecate, with evidence

- `adef detection evolve D-XXXX` runs a chain on the transition, like Refine:
  **Health → Tuning → Deprecation**. All three are deterministic — there is no
  mode flag, because the heuristics just read whatever health was ingested.
  Health reports what is stored and what was derived from it; Tuning proposes
  threshold/allowlist changes; Deprecation returns `keep` / `tune` /
  `deprecate` / `insufficient_data`.
- **The evidence is ingested, not estimated.** ADEF never queries the SIEM, so
  the counts come from a capture document the engineer (or you, with your own
  environment tooling) hands over: `adef ingest weekly-metrics.yml`. See the
  **health-capture** skill for the document kinds and shapes.
- `insufficient-data` / `insufficient_data` is **not a failure** — it means no
  numbers were ingested for this detection, or the ones ingested lack the
  counts a heuristic needs. Triage in this order, don't re-run hoping:
  1. `adef health show D-XXXX` — is anything stored for *this* ID? `adef
     doctor` answers it for the whole workspace in one line.
  2. If nothing: the fix is an ingest, not a flag. Produce the document.
  3. If something: name which derived key is missing and which count it
     needs — then ask for *that* count, don't re-ingest the same document.
     `fp_ratio` needs **both** `false_positive_count` and
     `true_positive_count` (the denominator is what was *adjudicated* —
     unlabeled signals are not known false positives); a key is **omitted**
     rather than zeroed when its counts are absent; and only the `metrics`
     kind feeds these heuristics, so a stored `performance` document is not
     the data they were waiting for.
- After a fresh ingest on a detection **already** at evolve, re-run the chain
  explicitly: `adef detection evolve D-XXXX --chain`. Without it the stage is
  idempotent and only the note is appended — the new numbers are never read.
- Triggers: FP rate drift, volume change, telemetry loss, superseding rule.
- Tune: journal the before/after threshold and the evidence that forced it.
  Cite the ingested number, not an impression.
- Deprecate: journal the reason and the replacement (`D-XXXX`) if any — a
  deprecation without a pointer strands the coverage it provided (check
  `adef coverage` for what goes dark).

## Anti-patterns (each observed live)

- Writing artifacts to `/tmp`, or drafting there and copying after
- Multiple overlapping stage summaries; celebration formatting
- Expecting `refine --note` to re-run the chain (it doesn't; use `--chain`)
- Treating "no catalog record … yet" as a bug to fix — it's the expected
  state for a detection still at Find/Observe, not a misconfiguration
- Re-reading each candidate via `adef detection show` after `--similarity-mode
  agent` — the refine command already prints every candidate's query
- Treating Evolve's `insufficient-data` as a bug or a wrapper problem — it
  says the numbers behind a heuristic aren't in the workspace. Diagnose which
  (nothing ingested, or ingested without the counts) before prescribing
- Proposing a threshold from an impression of the volume instead of from the
  counts in the workspace — if no one ingested numbers, say so and stop
- Expecting `evolve --note` to re-run the chain after an ingest (use `--chain`)
- Hand-editing `mitre:` or hand-rolling an INDEX rebuild
- Declaring "production ready" while the record says `status: draft`
- Advancing a stage with no note — an empty transition tells the next
  engineer nothing
