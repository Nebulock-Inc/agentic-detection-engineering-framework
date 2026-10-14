# catalog-onboarding — behavioral evals

Run in a live Claude Code session with the plugin installed; re-run after any
`SKILL.md` edit. Setup: `examples/demo-rules` + `examples/inhouse-rules` (the
unclaimed-format fixture). Rows marked *(evidence)* come from the live ESCU
endpoint onboarding (1,469 rules, 2026-07-23); the profile-authoring rows are
design-derived — that loop ran in earlier sessions not transcribed here.

## Should activate + drive cataloging

| Prompt | Expected behavior |
|--------|-------------------|
| "Catalog my rules repo." | `--dry-run --report json` triage FIRST, then the flagless writing run — and says explicitly which commands write and which don't |
| User ran only `--dry-run`/`--report` variants *(evidence)* | Recognizes nothing was written (the report says `"written": 0`); points at the flagless run — a live user concluded cataloging was broken after four non-writing commands |
| Mass `no_platform` flags on a datamodel-heavy corpus *(evidence)* | Explains honestly: rules address data models/macros an index schema can't match; ADEF refuses to guess; triage via `list --needs-review no_platform` |
| Re-catalog of the same repo *(evidence)* | Respects the guard: `adef sync` for reconciliation, `--force` only with the duplicate warning acknowledged |
| Unclaimed in-house files *(design)* | Clusters by `top_level_keys`, reads samples, drafts a profile (or dispatches `profile-author`), validates via `adef profile lint` + `--dry-run --profile` scoreboard (query ≥95%, title ≥90%), human approves, installs to `config/profiles/` |
| Declared schemas exist *(evidence)* | Notes platform inheritance in the summary (declaring data makes the catalog cleaner) |

## Should NOT handle here — hand off

| Prompt | Expected behavior |
|--------|-------------------|
| "The repo changed since we catalogued." | catalog-sync |
| "Set up schemas first." | schema-declaration |
| "What did we just catalog?" | detection-explorer |

## Convention checks (inspect after a run)

- Writing run actually wrote (records + journals + INDEX exist; count matches)
- Any `--report json` output saved with `-o` or explicitly summarized — not
  scrolled into oblivion
- Profile drafts validated on the scoreboard before install; never installed
  on vibes
