# mitre-tagger — behavioral evals

Run in a live Claude Code session with the plugin installed; re-run after any
`SKILL.md` edit. Setup: a catalog with a populated `no_mitre` queue (an ESCU
catalog gives ~8 for free). Rows marked *(evidence)* were observed live
(a tag + retag session); the queue-drain rows are
design-derived — **the batch flow has not yet been exercised live**.

## Should activate + drive validated tagging

| Prompt | Expected behavior |
|--------|-------------------|
| "Tag D-XXXX with MITRE." *(evidence)* | Proposes candidates FROM the snapshot (`adef attack show`), never from model memory; human approves before `tag-mitre` writes |
| "The mapping is wrong — this is T1046, not T1071." *(evidence)* | `tag-mitre D-X T1071 T1571 --remove` then add — never a hand-edit of `mitre:` (live failure: hand-edit skipped validation and produced a wrong INDEX) |
| "Work through the no_mitre queue." *(design)* | `detection list --needs-review no_mitre`; per detection: read title/query/journal, propose, validate, human approves, write; progress reported |
| Proposed ID is revoked *(design)* | Surfaces the replacement from the snapshot; asks which to use |
| Candidate justification *(evidence)* | Reasoned against the hypothesis/behavior, not the title (live: T1046 chosen because the *behavior* is service discovery) |

## Should NOT handle here — hand off

| Prompt | Expected behavior |
|--------|-------------------|
| "How's our coverage now?" | coverage-review (though noting a tier flip after tagging is welcome) |
| "Author a detection for this technique." | detection-author |

## Convention checks (inspect after a run)

- Every written ID validates via `adef attack show`
- `no_mitre` flag dropped on tagged records; re-added if a removal empties the mapping
- INDEX consistent (`by_technique` matches records) — no hand-rolled rebuilds
