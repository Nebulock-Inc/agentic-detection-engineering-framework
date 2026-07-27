---
name: mitre-tagger
description: Map ATT&CK techniques onto catalogued detections that have none. Use when the user wants to drain the `no_mitre` enrichment queue, add MITRE ATT&CK coverage to catalog records, or asks "which techniques does this detection cover?". Selects technique IDs grounded in the shipped ATT&CK reference (never from memory), validates every ID deterministically, gets human approval, and writes to ADEF's catalog records — the source rules stay untouched.
---

# MITRE Tagger

You are enriching catalogued detections with ATT&CK technique IDs. Your job is
to drain the `no_mitre` queue — detections ADEF catalogued but couldn't map to
ATT&CK — by proposing accurate technique mappings, **grounding every ID in the
shipped ATT&CK reference**, and writing them through `adef detection tag-mitre`.

## Ground rules

- **Never invent technique IDs from memory.** ATT&CK has 800+ techniques and IDs
  drift (renames, revocations). A plausible-looking `T####` is worthless if it's
  wrong. Every ID you propose must be confirmed against the shipped reference
  with `adef attack show <id>` before you offer it to the user.
- **The write path is `adef detection tag-mitre` only.** Never hand-edit catalog
  YAML — that doesn't survive the next catalog run, and it skips validation.
- **`tag-mitre` is the deterministic gate.** It rejects any ID absent from the
  reference and aborts atomically. Lean on it; it's the scoreboard, not your
  judgment of an ID's validity.
- **Enrichment writes to ADEF's catalog record, never the source rule.** The
  user's rule repo is read-only.
- **Human approval before every write.** You propose; the user decides.

## Flow

### 1. Pull the queue

```
adef detection list --needs-review no_mitre --report json
```

Each record has `id`, `title`, `query`, `data_source`, `platform`. That's your
evidence — the detection *logic*, not a guess from the title. If the queue is
empty, say so and stop.

Report the count and offer to work through them (all, or a subset the user
names — e.g. "just the windows ones").

### 2. Read the detection, propose techniques

For each detection, read its `title` + `query` (+ `data_source` for context).
Reason about what adversary behavior the logic actually detects, and propose
the ATT&CK technique(s) it covers. Prefer sub-techniques (`T1059.001`) when the
logic is specific (e.g. a PowerShell command line), the parent (`T1059`) when
it's broad.

Be honest about coverage: one detection often maps to 1–3 techniques. Don't
pad. If the logic is too generic to map confidently, flag it for the user
rather than forcing a tag.

### 3. Confirm each ID against the reference — mandatory

Before proposing an ID to the user, run:

```
adef attack show <id>
```

Check the returned name and tactics actually match your intent. If `show`
reports the ID is invalid, or names a technique unrelated to what you meant,
you misremembered — find the right ID (search the shipped snapshot at
`adef/data/attack/enterprise.json`, or `adef attack show` candidates) and
re-confirm. **Do not propose an ID you haven't confirmed this run.**

If `show` reports the ID is revoked, use the replacement it names instead.

### 4. Human approval — hard gate

Present, per detection: the title, a one-line reading of what it detects, and
the proposed `ID — name (tactics)` lines (from `attack show`, so the user sees
the same grounding you did). Use AskUserQuestion: apply as-is / edit the ID set
/ skip this one.

Batch sensibly — for a long queue, propose a handful, get approval, write, then
continue; don't dump 50 at once.

### 5. Write

On approval:

```
adef detection tag-mitre <D-XXXX> <id> [<id> ...]
```

This validates, merges (dedupes), clears the `no_mitre` flag, and rebuilds the
INDEX (so `by_tactic` coverage updates immediately). If it rejects an ID you
thought was valid, you skipped step 3 — go back and confirm.

### 6. Summary

When done (or the user stops): how many detections tagged, how many techniques
added, how many skipped and why, and how many remain in the `no_mitre` queue.
Offer the coverage view next (`adef` coverage report / Navigator export, once
available) — the freshly-tagged records now count toward tactic coverage.

## Why grounding matters

The reference layer exists precisely so mappings are validated before anything
depends on them. A hallucinated ID that passes visual review still fails
`tag-mitre`, and a *wrong-but-real* ID (right format, wrong technique) is worse —
it silently mis-attributes coverage. Reading the logic (step 2) plus confirming
against the reference (step 3) is how you avoid both.
