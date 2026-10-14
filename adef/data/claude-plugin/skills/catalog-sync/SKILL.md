---
name: catalog-sync
description: Keep the ADEF catalog current after the source rules repo changes, using `adef sync`. Use when the user says their rules repo changed and the catalog needs refreshing, asks to reconcile / re-sync / "what's new, modified, or orphaned since we catalogued", wants a CI staleness check, or asks why the catalog disagrees with the repo. Read-only on the source repo; preserves enrichment. For first-time cataloging use catalog-onboarding; for browsing use detection-explorer.
---

# Catalog Sync

Keep the catalog in step with the source rules repo by running `adef sync` and
interpreting its reconcile plan — the companion to `catalog-onboarding` (onboard
once, sync thereafter).

## Rules

- **Read-only on the source repo.** `sync` writes only under `catalog/` and
  `journals/`, never the user's rules. Say so if they worry.
- **Orchestrate `adef sync`; don't reimplement** the identity cascade or reconcile.
- **Enrichment is safe.** On a match, derived fields (query/platform/hashes) refresh
  while `mitre`/`status`/`stage`/`owner`/journal are **preserved**. Reassure the user
  re-syncing never loses their work.
- **Never re-catalog to "update."** A second `adef catalog` mints duplicates — `sync`
  is the reconciling re-run.
- Hand off: first-time onboarding → `catalog-onboarding`; finding/inspecting →
  `detection-explorer`; ATT&CK tagging → `mitre-tagger`.

## Flow

1. **Preview:** `adef sync <rule-root> --dry-run` → summarize the plan by outcome:
   **unchanged / modified / new / orphaned**.
2. **Interpret each bucket:**
   - **modified** — source changed; derived fields refresh, enrichment kept, a journal
     note records the out-of-band change.
   - **new** — a rule not in the catalog (incl. UUID-less renames, which land as `new`
     rather than risk a wrong merge) → flag for review/enrichment.
   - **orphaned** — source gone; marked `deprecated` + `orphaned`, **never deleted** —
     ask whether to retire or investigate.
   - **authored** records are skipped (no upstream).
3. **Apply:** `adef sync <rule-root>` to write; point out what got journaled.
4. **CI:** `adef sync <rule-root> --check` exits non-zero when the catalog is behind.
5. **Capture the why:** the journal note records *that* a rule changed; add the *why*
   (a `--note` on a FORGE stage, or the journal) so the rationale isn't lost.

## Notes

- Fuzzy rename-match isn't built — UUID-less renamed+edited rules show as `new` (a
  duplicate a human merges), never a silent mis-attribution.
- Staleness-aware reads aren't wired yet; run `--dry-run` to check drift on demand.
- `--workspace PATH` (default `ADEF_WORKSPACE`/cwd). Full flags: `docs/cli-reference.md`.
