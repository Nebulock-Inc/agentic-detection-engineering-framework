# detection-author — behavioral evals

Run in a live Claude Code session with the plugin installed; re-run after any
`SKILL.md` edit. Setup: a workspace with ≥1 ingested schema (cisco_asa from the
fixture flow works) and ideally a populated catalog so the overlap check has
real work.

## Should activate + drive the authoring flow

| Prompt | Expected behavior |
|--------|-------------------|
| "Help me author a detection for X against <source>." | Interview FIRST (gap, trigger, hypothesis, FPs) — no query before the hypothesis is confirmed back |
| Interview about thresholds | Surfaces schema evidence while asking (enum values, types) — reads the schema ONCE, works from context |
| Query drafting | Values come from the schema's harvested vocabulary — live exam: chose `action=blocked` because the schema said so, overriding both the human's and the reference rule's `denied` |
| Namespace choice (raw vs CIM spellings) | Uses the canonical spelling (the one carrying values); never pairs an alias name with harvested values |
| Before finishing | Overlap check against the catalog (`detection search` + `list`) with a named verdict; `adef schema check --detection D-XXXX` clean |
| Journal capture | Find section filled with the interview content — the durable why, not a query dump |
| Record edits (query text) | Direct edit is sanctioned for `origin: authored` — MUST bump `updated:` (live miss: an edited record claimed it was never touched) |

## Should NOT handle here — hand off

| Prompt | Expected behavior |
|--------|-------------------|
| "Baseline it / tune the threshold / is it deployable?" | forge-stage (Observe onward) |
| "Tag the MITRE queue." | mitre-tagger |
| Source isn't declared | schema-declaration first — flags it as a prerequisite |

## Convention checks (inspect after a run)

- Journal Find section populated; hypothesis readable as one sentence
- Record: real scope literals in the query, `updated:` ≥ `created:`
- `schema check --detection` clean; no invented field spellings
