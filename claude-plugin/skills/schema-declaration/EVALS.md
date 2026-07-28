# schema-declaration — behavioral evals

Run in a live Claude Code session with the plugin installed; re-run after any
`SKILL.md` edit. Setup: a workspace with a configured platform and the repo's
Splunk fixture (`tests/fixtures/splunk-fieldsummary-wineventlog.csv`) — it
carries real suspect merges. All rows below are grounded in two live sessions
(wineventlog: 337 fields / 9 suspects; cisco_asa: clean single-shape run).

## Should activate + drive recipe → reshape → ingest

| Prompt | Expected behavior |
|--------|-------------------|
| "Help me set up schemas for my Splunk environment." | `schema_recipe`/`adef schema recipe`; presents the export command; tells the user to save a FILE (never hand-reshapes pasted output) |
| "Here's my field export." | `adef schema reshape <file>` — never drafts the YAML by hand |
| User's export produces `[SUSPECT]` merges | Adjudicates each with the value evidence; encodes verdicts as a `--no-fold` re-run, not a YAML edit |
| `eventtype ← EventType`-class fold (meta vs raw field) | Split — and explains why from the values |
| `user ← User` / `ProcessID ← ProcessId` (encoding variants) | Keep — flags are "verify", not "wrong" |
| The user wants to merge a pair the evidence says are strangers | States the evidence plainly, then respects their call (live case: `product ← Product` was mis-merged at the CLI; the skill exists to catch this) |
| "Fields changed in the SIEM." | Re-export → reshape → re-ingest; explains corrections survive + drift is reported; no "schema sync" invented |
| Reshape output lacks `platform:` | Asks the user; never infers (the note means the *source* platform, not the SIEM) |

## Should NOT handle here — hand off

| Prompt | Expected behavior |
|--------|-------------------|
| "Catalog my rules repo." | catalog-onboarding |
| "Which fields do my rules use that don't exist?" | `adef schema check` (detection-author covers `--detection`) |

## Convention checks (inspect after a run)

- Declaration produced by `reshape`, not hand-written; lints clean
- Suspect verdicts reproducible from the closing `--no-fold` command
- `platform:`/`description:` set before ingest; ingest ran; `schema show` agrees
