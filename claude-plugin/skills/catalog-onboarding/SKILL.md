---
name: catalog-onboarding
description: Onboard a detection-rule repository into the ADEF catalog. Use when the user wants to catalog a rules repo, when `adef catalog` leaves files unrecognized or needs_review, or when a repo contains a custom/in-house rule format ADEF doesn't parse yet. Drafts extraction profiles for unknown formats via the profile-author sub-agent, validates them deterministically, and gets human approval before installing.
---

# Catalog Onboarding

You are onboarding a detection-rule repository into ADEF. Your job is to get
every rule-shaped file in the repo recognized and correctly extracted — by
drafting **extraction profiles** for formats ADEF doesn't know, never by
hand-editing catalog output.

## Ground rules

- The source repo is **read-only**. Never modify, move, or reformat the
  user's rule files. ADEF's CI enforces this; so do you.
- Profiles are the only mechanism for teaching ADEF a new format. Do not
  paste per-file metadata into the catalog by hand — that doesn't survive
  the next sync.
- A profile is never installed without explicit human approval.
- Orchestrate `adef` commands; do not reimplement the walk, recognition, or
  index rebuild yourself.

## Flow

### 1. Dry-run and triage

Run `adef catalog <rule_root> --dry-run --report json` (fall back to plain
`--dry-run` if `--report json` is unavailable — see "Before the profile
engine lands"). Summarize for the user:

- counts by outcome: supported / recognized_unsupported / unclaimed
- counts by format for the supported set
- how many supported rules are `needs_review` (metadata gaps, not format gaps)

If everything rule-shaped is supported, skip to step 6.

### 2. Cluster the unrecognized files

Group unclaimed (and recognized_unsupported, if the user wants them improved)
files by structure: extension, container type (YAML/JSON/TOML/conf/raw), and
top-level key set. Files sharing a key set are almost certainly one in-house
format. Ignore obvious non-rules (READMEs, CI config, lookup data) — a rule
has a query/logic field plus detection metadata; when in doubt, show the user
one example and ask.

Present the clusters: one line each — count, example path, top-level keys.
Ask the user which clusters to onboard if there are more than two.

### 3. Dispatch profile-author per cluster

For each cluster, launch the `profile-author` sub-agent. Give it:

- the cluster's file paths (it samples up to 50 itself)
- the profile schema (see [`docs/creating-extraction-profiles.md`](../../../docs/creating-extraction-profiles.md))
- any hints the user volunteered ("those are our Sentinel exports")

It returns a draft profile YAML, self-reported extraction stats, and a list
of uncertainties. Do not read the sample files yourself in bulk — that is
exactly the context the sub-agent exists to absorb.

### 4. Validate deterministically

Write the draft to a temp file and **lint its structure first** — this catches
a malformed profile (bad container, missing required map field) in a second,
before you spend a full repo walk on it:

```
adef profile lint <draft.yml>
```

If lint fails, send the errors straight back to the sub-agent; don't walk the
repo with a profile that won't load. Once it lints clean, measure extraction:

```
adef catalog <rule_root> --dry-run --profile <draft.yml>
```

Read the per-field extraction rates. Targets: query ≥ 95%, title ≥ 90%,
uuid/mitre/data_source — best effort but investigate anything under 50%.
If rates miss, send the failures (which files, which fields) back to the
sub-agent for revision. At most 3 iterations; after that, show the user
what's failing and ask how to proceed rather than looping.

Never grade the profile yourself by eyeballing samples — the engine's
numbers are the scoreboard.

### 5. Human approval — hard gate

Show the user the final profile YAML and its extraction rates, and note that
the profile changes how every future catalog/sync run reads these files. Use
AskUserQuestion: install / edit first / discard. On approval, save to
`<workspace>/config/profiles/<name>.yml`.

### 6. Real run and summary

Run `adef catalog <rule_root>`. Report: total catalogued, counts by
platform and format, needs_review count, and what (if anything) is still
unclaimed. Offer next steps: reviewing `needs_review` records, or a coverage
look at the freshly catalogued set.

## Before the profile engine lands

If `--report json` / `--profile` are not yet available in the installed
`adef` version:

- Triage from plain `--dry-run` output plus your own clustering (step 2
  still works — it only needs file listings and top-level keys).
- Still dispatch profile-author and produce the profile YAML; validate by
  having the sub-agent hold out ~20% of its samples for a self-check, and
  say clearly in the approval step that validation was sample-based, not
  engine-based.
- Save the approved profile to `<workspace>/config/profiles/` anyway — it is
  the contract; the engine will consume it when it ships.
