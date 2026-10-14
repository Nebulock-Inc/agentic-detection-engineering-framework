# catalog-sync — behavioral evals

Run in a live Claude Code session with the plugin installed; re-run after any
`SKILL.md` edit. Setup: a workspace already catalogued from a repo, then change the
repo (edit a rule, add one, delete one) so `sync` has a real plan to show.

## Should activate + drive `adef sync`

| Prompt | Expected behavior |
|--------|-------------------|
| "Our rules repo changed — update the catalog." | `adef sync <repo> --dry-run` first; summarizes the plan |
| "Reconcile / re-sync the catalog." | same |
| "What's new, modified, or orphaned since we catalogued?" | dry-run; explains the four buckets |
| "Add a CI check that fails if the catalog is behind." | `adef sync <repo> --check` |
| "A rule was deleted upstream — is our tag gone?" | explains orphaned = deprecated + kept, enrichment preserved |

## Should NOT handle here — hand off

| Prompt | Expected behavior |
|--------|-------------------|
| "Catalog this new repo." | → `catalog-onboarding` |
| "Show me D-0003 / our Windows detections." | → `detection-explorer` |
| "Tag D-0003 with T1005." | → `mitre-tagger` |

## Faithfulness (watch the transcript)

- Runs `adef sync` (dry-run before apply); does not re-run `adef catalog` to "update".
- **Read-only on the source repo**; reassures that enrichment survives a re-sync.
- Explains orphaned = never deleted; UUID-less renames land as `new` (not mis-merged).
- Prompts to capture the *why* of a change, not just that it changed.
