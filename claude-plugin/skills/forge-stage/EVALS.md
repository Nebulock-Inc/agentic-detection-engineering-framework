# forge-stage — behavioral evals

Run in a live Claude Code session with the plugin installed; re-run after any
`SKILL.md` edit. Setup: a workspace with at least one authored detection past
Find (e.g. the D-1470 fixture flow: schema-grounded record + journal).

## Should activate + drive the stage conventions

| Prompt | Expected behavior |
|--------|-------------------|
| "Advance D-XXXX to observe and help me baseline it." | `adef detection observe` with a note; baseline queries written to `analysis/D-XXXX/` (NOT /tmp); one queries file + one guide |
| "None of the baseline queries returned results." | Treats it as a finding; diagnoses data → field co-occurrence → hypothesis, using `adef schema show` evidence |
| "The hypothesis is wrong — it's scanner behavior, not C2." | Pivots via seams: `tag-mitre --remove` + add, `adef reindex`, journal title sync, invalidation evidence journaled |
| "Run refine on D-XXXX." | `adef detection refine`; explains WrapperUnavailable as designed degradation; manual gates with named verdicts |
| "Add my refine findings." | `refine --note ...`; does NOT expect the chain to re-run; mentions `--chain` if a re-run is wanted |
| "Is D-XXXX ready to deploy?" | Govern gates with named FP actions; states gate decision AND that record status stays `draft` (no status CLI) |
| "This rule is too noisy now." | Evolve: tune with before/after evidence, or deprecate with replacement pointer + coverage check |

## Should NOT handle here — hand off

| Prompt | Expected behavior |
|--------|-------------------|
| "Create a new detection for X." | detection-author (Find + creation) |
| "Fix the MITRE tags across the queue." | mitre-tagger |
| "How's our coverage?" | coverage-review |

## Convention checks (inspect after a run)

- No files under `/tmp`; artifacts under `analysis/<D-XXXX>/` with journal
  notes pointing at each
- At most one summary doc per stage; no banner/celebration formatting
- Any hand-edited record: `updated:` bumped, `adef reindex` run
- No prose claims the record contradicts (`adef detection show` agrees)
