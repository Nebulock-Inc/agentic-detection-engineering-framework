---
name: detection-explorer
description: Browse and inspect the ADEF detection catalog (read-only). Use when the user asks which detections exist or wants to find/filter them (by platform, ATT&CK tactic, engine, status, stage, origin, or review state), asks what needs MITRE tagging or review, or wants one detection's record, query, tactics, and journal history. For coverage or gap analysis, use the coverage skill.
---

# Detection Explorer

Translate a "what do we have?" question into the right `adef detection list` /
`show` call, run it, and summarize.

## Rules

- **Read-only.** `list`/`show` only read; never edit records, journals, or rule files.
- **Orchestrate**, don't reimplement — never hand-parse `catalog/*.yml` or the INDEX.
- Report only what the commands return. Empty result → check the catalog exists
  (`adef catalog <rule-root>`) before assuming zero coverage.
- Hand off writes: onboarding → `catalog-onboarding`, authoring → `detection-author`,
  MITRE tagging → `mitre-tagger`, coverage/gaps → the coverage skill.

## Query — map the question to `adef detection list` (filters combine)

| Question | Filter |
|----------|--------|
| Windows detections | `--platform windows` |
| covers a tactic / lateral movement | `--tactic lateral-movement` (shortname or display name) |
| Sigma / SQL rules | `--engine sigma` (of `sigma\|sql\|sch_sql\|composite`) |
| a specific source format | `--rule-format sigma\|spl\|panther\|<profile>` |
| draft / deprecated | `--status draft` |
| at a FORGE stage | `--stage refine` |
| authored in ADEF vs from a repo | `--origin authored\|catalogued` |
| needs review / still needs MITRE | `--needs-review` (bare = structural) / `--needs-review no_mitre` |

Add `--report json` to count, group, or pick precisely — it includes a derived
`tactics` array. Parse the JSON; don't eyeball the table.

## Inspect

`adef detection show D-XXXX` → record, query, derived tactics, a `support` line
for recognized-but-unsupported formats, and the paired-journal tail (the "why" a
list can't show). Summarize — especially the journal.

## Notes

- Both accept `--workspace PATH` (default: `ADEF_WORKSPACE` env or cwd).
- Tactic names track the shipped ATT&CK snapshot (e.g. 19.1 renamed "Defense
  Evasion" → "Stealth"); confirm a surprising name with `adef attack show <ID>`.
