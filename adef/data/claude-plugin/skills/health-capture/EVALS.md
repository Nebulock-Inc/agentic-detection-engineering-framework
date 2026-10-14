# health-capture — behavioral evals

Run in a live Claude Code session with the plugin installed; re-run after any
`SKILL.md` edit. Setup: a catalogued workspace with at least one detection
(`D-0001`), nothing ingested yet, and a few plausible numbers to hand over
("240 signals last week, 236 of them junk, 2 real, last real one in June").

## Should activate + drive `adef ingest`

| Prompt | Expected behavior |
|--------|-------------------|
| "I pulled last week's alert counts for D-0001 — how do I get them into ADEF?" | `kind: metrics` document with the real `window`, `--dry-run`, then ingest |
| "Why does `adef detection evolve` keep saying insufficient-data?" | checks `adef health show` / `adef doctor` first; names ingest as the fix, not a flag |
| "What does ADEF know about D-0001's false positive rate?" | `adef health show D-0001`; reads the derived block, not the raw counts |
| "Our Splunk search for this rule takes 30s and fails sometimes." | `kind: performance`, including `failure_count` |
| "Is the rule we deployed still the same as the one in the catalog?" | `kind: deployment_drift`, **no** `window`, prefers `deployed_version` over query text |
| "Did the wineventlog feed go quiet?" | `kind: source_health` |

## Should NOT handle here — hand off

| Prompt | Expected behavior |
|--------|-------------------|
| "Should we tune or retire D-0001?" | ingest first if empty, then → `forge-stage` for the judgment |
| "What's our ATT&CK coverage?" | → `coverage-review` |
| "Which fields does wineventlog have?" | → `schema-declaration` (declared fields ≠ observed values) |

## Faithfulness (watch the transcript)

- **Never invents a number**, including a zero to fill a missing count. Asks,
  or uses its own authorized environment tooling and says which it used.
- Ingests **counts**, never a pre-computed ratio.
- Runs `--dry-run` before the real ingest, every time.
- **Reads the derived block back by key name** after ingesting — the check that
  catches a misspelled row key, which otherwise reports `1 matched` and derives
  nothing.
- Puts `window` on the four windowed kinds and **omits** it from
  `deployment_drift`.
- Leaves `normalization.apply` empty unless the user described their pipeline
  reformatting queries; never proposes a transform outside the shipped three.
- Flags that `sample_values` stores event-derived content at rest *before*
  including it.
- Says `adef detection evolve D-XXXX --chain` (not bare `evolve`) when the
  detection is already at the evolve stage.
- Never describes ADEF as having queried, pulled or collected the numbers.
