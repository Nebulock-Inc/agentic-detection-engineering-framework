# ADEF Sync — Design (staleness & reconciliation)

**Date:** 2026-07-22
**Status:** Steps 1–3 implemented (`adef sync` ships; core in
`adef/core/reconcile.py`). Remaining: fuzzy rename-match (step 4 of the cascade)
and staleness-aware reads. Sequencing tracked at the bottom.
**Supersedes the verbal sketch** captured in `docs/archive/2026-07-21-handoff-full.md`
§B and the deferred `adef sync` open thread.

---

## The problem

The catalog is a **snapshot** of a rules repo; rule repos change weekly. A stale
catalog is *worse* than no catalog when an AI assistant answers from it
confidently — "you already have a detection for that" when it was deprecated
last month is the single fastest way to lose a skeptical team's trust.

Two forces make this urgent now:

1. **Re-catalog wipes enrichment.** `adef catalog` today assigns IDs by
   `max_index + 1` and never reconciles (`adef/commands/catalog.py`). Re-running
   it produces *all-new* `D-XXXX` records — every MITRE tag (`tag-mitre`),
   authored draft (`detection new --source`), journal, `status`/`owner`, and
   review decision is orphaned. The enrichment we've built sits directly over
   this hole.
2. **Nothing tracks currency.** `CatalogRecord` carries `rule_ref` +
   `original_path` but **no content hash and no catalog-time commit SHA**
   (`adef/core/catalog.py`). There is no way, today, to answer "is this record
   still true?"

## The governing principle

**ADEF must never require being in the write path.** The moment currency depends
on an engineer remembering to run `adef` when they edit a rule, we've lost.
Design `sync` to *observe* changes, not mediate them.

Corollary — **catalog = disposable index; journals = the only durable data.**
Catalog records are pure derivations of the source repo, so "staying current" is
"re-derive and reconcile," not state management. The only genuinely hard problem
is **identity**: when a rule changes, which `D-XXXX` is it?

## Identity: the fields to persist

The identity cascade needs keys the record doesn't store yet. Add to
`CatalogRecord` (and `to_yaml_dict`):

| Field | Source | Purpose | Status |
|-------|--------|---------|--------|
| `rule_uuid` | Sigma `id:` / profile uuid (already on `DiscoveredRule`) | primary identity key when present | **persisted 2026-07-22** |
| `source_hash` | SHA-256 of the source file's bytes at catalog time | unchanged/modified detection; identity fallback for non-UUID rules | **persisted 2026-07-22** |
| `catalog_sha` | repo HEAD SHA at catalog time (git repos only; empty otherwise) | one-shot staleness check + `git diff` base | **persisted 2026-07-22** |

All three identity fields are now written at catalog time — the data the
reconciler needs is in place; only the reconciler itself remains.

- `rule_uuid` hardens `rule_ref` against renames today.
- `source_hash` is stamped once per file in `walk_outcomes` (all extraction
  paths) as SHA-256 of the **raw bytes** (not decoded text — a faithful digest
  of the file on disk).
- `catalog_sha` is one HEAD SHA per catalog run (`git_head_sha` in
  `core/catalog.py` — detects the git work tree, empty otherwise, never raises).

Authored rules (`draft_record_from_schema`) leave `source_hash`/`catalog_sha`
empty — they have no source file or repo, by construction.

## The reconciliation cascade

When `adef sync` re-derives the repo, each discovered rule is matched against
existing records **in this order** (first match wins). Same shape as
detection-as-code / Terraform drift handling:

1. **Embedded UUID match** → same detection. (Sigma rules carry `id:` — a gift.)
2. **Content-hash match** (`source_hash` unchanged) → unchanged; skip.
3. **Same path, new hash** → **modified** (see out-of-band journaling below).
4. **Fuzzy match** on title/query for renamed+edited rules → attach with
   `needs_review` so a human confirms the identity.
5. **No match** → **new** rule; assign the next `D-XXXX`.

And for existing records with no corresponding source rule:

6. **Rule gone** → mark the record/journal **orphaned; never delete.** The
   enrichment (the "why") outlives the rule and may be the most valuable thing
   left. `status: deprecated` + an orphaned marker; surfaced in `list`/`show`.

**Enrichment is always preserved across re-derivation.** Reconciliation updates
the *derived* fields (query, platform, data_source, …) on a matched record and
leaves the *enrichment* fields (`mitre`, `status`, `stage`, `owner`, journal)
untouched. This is the fix for problem #1 above.

## Lean on git

For repo-based teams git solves most of this for free:

- Store `catalog_sha` at catalog time. **Staleness is one comparison** against
  `git rev-parse HEAD`.
- `git diff --name-status <catalog_sha>..HEAD` yields adds / modifies / deletes
  **and renames** — git's rename detection resolves cascade step 4 without our
  own fuzzy match for the git case.
- **Hash-diffing is the fallback** for non-git sources (SIEM exports): no SHA, so
  reconcile purely on UUID + `source_hash` + path.

`sync` should detect whether the rule root is a git work tree and pick the git
path or the hash path accordingly — no configuration.

## Staleness-aware reads

Every read path checks currency and is honest about it:

- **CLI** (`list`, `show`, `coverage`): if `catalog_sha` != HEAD, print a banner
  — "catalog is N commits behind; run `adef sync`" — and optionally auto-resync
  (cheap for git).
- **MCP server**: same check per query; annotate results (`"stale": true,
  "commits_behind": N`) so an AI assistant *knows what it can't trust* and can
  say so instead of answering confidently from a stale record.

A confident answer from a stale catalog is the trust-killer this whole feature
exists to prevent — so the read paths, not just `sync` itself, must be
staleness-aware.

## Out-of-band edits become a feature

When `sync` detects an externally-modified rule (cascade step 3), it
**auto-appends a journal entry**: timestamp, diff summary, old→new hash, and —
for git repos — the **commit message(s) + PR reference** for that change
(`git log <old>..<new> -- <path>`). Commit messages are the "why" corpus teams
already have; harvesting them means journals accumulate rationale *even for teams
who never manually journal*. Later, an agent can draft an Evolve-stage note from
the diff + commit message for human approval.

Net: edits that bypass ADEF **don't lose value — ADEF becomes the change
historian regardless of where the change happened.**

## Closing the loop with CI, not discipline

- A one-step GitHub Action: `adef sync` on merge to main (commit the updated
  catalog), or `adef sync --check` that comments on PRs ("this rule change has no
  journal rationale" / "catalog will reconcile D-0042").
- The same seam runs off a scheduled export for SIEM-stored teams.

Currency becomes automatic for the git crowd; **humans are never the sync
mechanism.**

## Proposed command surface

```
adef sync                 # reconcile catalog against the current source repo
adef sync --check         # report drift, exit non-zero if behind; write nothing (CI/PR mode)
adef sync --dry-run       # show the reconciliation plan (adds/modified/orphaned) without writing
```

`sync` reuses the existing `discover_rules` walk and `Catalog` writer — it is
`catalog` plus reconciliation, not a parallel walker. Likely factoring: a
`reconcile(existing_records, discovered_rules)` core in `adef/core/` that returns
a plan (per-rule: unchanged / modified / renamed / new / orphaned), consumed by
both `sync` and a future `catalog` that reconciles by default.

## Open questions (decide before building)

1. **Should `catalog` become `sync` under the hood?** Arguably a first
   `catalog` is just `sync` against an empty catalog. Unifying avoids two
   code paths; risk is surprising the "fresh catalog" mental model.
2. **Fuzzy-match threshold (step 4).** What similarity on title/query attaches
   vs. treats-as-new? Start conservative (high threshold → prefer "new +
   needs_review" over a wrong merge); a wrong identity merge is worse than a
   duplicate.
3. ✅ **`catalog_sha` granularity** — resolved: per-record (one HEAD per run,
   stamped on every record), matching how `rule_ref` is per-record.
4. ✅ **Orphan surfacing** — resolved: `status: deprecated` + `orphaned: true`
   on the record (drops out of coverage math, stays browsable, never deleted).
5. **Fuzzy-match threshold (cascade step 4).** Still open — not yet built. When
   added, start conservative (high title/query-similarity threshold; prefer
   "new + needs_review" over a wrong merge — a wrong identity merge is worse
   than a duplicate). Until then, UUID-less renamed+edited rules fall to `new`.
6. **Should `catalog` become `sync` under the hood?** A first `catalog` is
   `sync` against an empty catalog. Unifying avoids two code paths; risk is
   surprising the "fresh catalog" mental model. Deferred — they coexist for now.

## Sequencing

1. ✅ **Persist `rule_uuid` on the record** (done 2026-07-22) — tiny; valuable
   on its own; hardens identity immediately.
2. ✅ **Add `source_hash` + `catalog_sha`** at catalog time (done 2026-07-22) —
   all identity data now captured; the reconciler has what it needs.
3. ✅ **`reconcile()` core + `adef sync` / `--dry-run` / `--check`** (done
   2026-07-22) — `adef/core/reconcile.py` (pure cascade, UUID→hash→path→new→
   orphaned; enrichment preserved) + `adef/commands/sync.py`. Modified rules get
   a journal note; orphaned records marked `deprecated`+`orphaned`, never
   deleted. Fuzzy step 4 not yet built (falls to `new`).
4. **Fuzzy rename-match** (cascade step 4) — the one remaining cascade step.
5. **Staleness-aware reads** (CLI banner, MCP annotation) — `catalog_sha` is
   already stored; this reads it on every query.
6. **Out-of-band journal harvesting upgrade** — `sync` journals *that* a rule
   changed; harvesting the git commit message/PR for the "why" is a follow-up.
7. **CI action** (docs + a sample workflow).

Steps 1–3 ship the core value: re-sync safely without losing enrichment.
Nothing here changes the read-only invariant — `sync` only ever writes under
`catalog/` and `journals/`, never to the user's rules.
