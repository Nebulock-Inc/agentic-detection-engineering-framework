# coverage-review — behavioral evals

Run these in a **live Claude Code session with the plugin installed**; re-run
after any `SKILL.md` edit.

**Setup:** `/plugin install`, then catalog something with ATT&CK mappings
(e.g. `adef catalog examples/demo-rules`). Tagging a couple of records first
(`adef detection tag-mitre …`) makes the trust/gap output more interesting.

## Should activate + drive `adef coverage`

| Prompt | Expected behavior |
|--------|-------------------|
| "How good is our coverage?" | fires; runs `adef coverage`; explains solid vs fragile |
| "Where are our blind spots / gaps?" | `adef coverage --gaps`; names blind tactics + uncovered IDs |
| "What should we build next?" | prioritizes from gaps + SPOFs into a plan |
| "Which techniques are single points of failure?" | reads the SPOF / depth-1 section |
| "Give me a Navigator layer to share." | `adef coverage --navigator <path>` |

## Should NOT handle here — hand off (routing boundary)

| Prompt | Expected behavior |
|--------|-------------------|
| "Show me D-0001" / "what Windows detections do we have?" | → `detection-explorer` |
| "Tag D-0003 with T1005." | → `mitre-tagger` |
| "Catalog this repo." | → `catalog-onboarding` |

## Faithfulness (watch the transcript)

- Runs `adef coverage`; does **not** recompute coverage or hand-parse the INDEX.
- **Read-only** — never edits records, journals, or rule files.
- **Honesty guard:** when many records are `no_mitre`, says coverage undercounts
  and offers the mitre-tagger handoff *before* trusting the gap numbers.
- Doesn't treat a cold, all-`draft` catalog reading as fragile as a bug.
- Uses `--gaps` for the uncovered-ID list and `--navigator` for sharing, not prose approximations.
