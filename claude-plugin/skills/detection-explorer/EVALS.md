# detection-explorer — behavioral evals

Skills are model instructions, not code — the real test is running representative
prompts in a **live Claude Code session with the plugin installed** and checking
what the model does. Re-run this list after any edit to `SKILL.md`.

**Setup:** install the plugin (`/plugin install`), then catalog something so the
workspace has records — e.g. `adef catalog examples/demo-rules` (or point at any
rules repo). Ask each prompt in a fresh session.

## Should activate + drive the right command

| Prompt | Expected behavior |
|--------|-------------------|
| "What detections do we have?" | fires; runs `adef detection list`; summarizes counts |
| "Show me our Windows detections." | `list --platform windows` |
| "Anything covering lateral movement?" | `list --tactic lateral-movement` (or via `--report json`) |
| "Which of our rules are Sigma?" | `list --engine sigma` |
| "What still needs MITRE tagging?" | `list --needs-review no_mitre`; offers the mitre-tagger handoff |
| "Walk me through D-0003." | `show D-0003`; summarizes record + query + tactics + **journal** |

## Should NOT handle here — hand off (routing boundary)

| Prompt | Expected behavior |
|--------|-------------------|
| "How good is our coverage?" | routes to the coverage skill; does **not** run `adef coverage` here |
| "What should we build next?" | coverage/gap analysis → coverage skill |
| "Catalog this new repo for me." | → `catalog-onboarding` |
| "Write a new detection for X." | → `detection-author` |

## Faithfulness (watch the transcript)

- Uses real flags only (`--platform/--tactic/--engine/--rule-format/--status/--stage/--origin/--needs-review/--report json`).
- **Read-only** — never edits records, journals, or rule files.
- Prefers `--report json` when counting/grouping/picking, rather than eyeballing.
- On an empty result, checks whether the catalog exists rather than asserting zero coverage.
- On `show`, surfaces the journal ("why"), not just the record fields.
