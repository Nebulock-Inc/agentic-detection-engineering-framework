# ADEF as a Detection Home — Design (repo-less teams)

**Date:** 2026-07-22
**Status:** Proposed (design-before-build; no code yet)
**Update 2026-07-27:** steps 1–2 (origin marker + sync-exclusion + `docs/detection-home.md`) shipped 2026-07-22; `adef export` still deferred. (The Status line above is the original 2026-07-22 framing, kept for the record.)
**Motivated by:** the "no repo" usage scenario (Option 2 in
`docs/archive/2026-07-21-handoff-full.md` §C) — a team with no detection-as-code
repo that wants to author and keep detections in ADEF itself.

---

## The assumption this challenges

Everything ADEF has built assumes **rules live somewhere else** and ADEF is a
read-only layer over them: `catalog` walks a repo, `sync` reconciles against a
repo, schema is declared from a SIEM export, authoring lands a rule in the
catalog but punts on getting it into "their repo." The catalog is explicitly a
**disposable, re-derivable index** — "re-run catalog, it's cheap and safe."

For a team with no repo, that assumption is false. Their authored records are
**the only copy**. The catalog is not disposable — it is the system of record.

## Two journeys (don't conflate them)

- **Journey A — ADEF as on-ramp to detection-as-code.** Team has SIEM rules, no
  git; uses ADEF to catalog + journal, likes it, decides to go
  detection-as-code. ADEF is a *midwife*: help them stand up a repo, then step
  back to the normal read-only role. Mostly supported already (export → they
  `git init` → `catalog`/`sync` take over).
- **Journey B — ADEF as the detection home.** Team has no repo and no intent to
  build one. They author and keep detections *in ADEF*. This is the one that
  contradicts the disposable-index model, and the one this design addresses.

**Decision (2026-07-22): ADEF becomes a system of record for detections
authored in it.** This is a deliberate expansion of the mission, taken with the
durability obligations that implies. The read-only invariant over the *user's
own rule repo* is unchanged — ADEF still never writes there. What changes is
that ADEF now owns the durable copy of records it *authored*.

## The immediate danger (a data-integrity bug today)

There is no field distinguishing "authored in ADEF" from "catalogued from a
repo." An authored record has empty `rule_ref`/`source_hash`/`rule_uuid`
(`draft_record_from_schema`). So if a Journey-B team ever runs `adef sync`, the
reconciler finds no match for their authored records and **orphans every one of
them** — marks the team's own detections `deprecated`. This must be fixed before
we invite repo-less teams in.

## Design

### 1. Origin marker (the linchpin)

Add `origin: authored | catalogued` to `CatalogRecord`.

- `authored` — created in ADEF (`detection new`, hunt-promote, future direct
  authoring). ADEF owns the durable copy.
- `catalogued` — derived from a source file by `catalog`/`sync`. The source repo
  owns it; ADEF's record is a derivation.

Set at creation: `draft_record_from_schema` → `authored`;
`record_from_discovered` → `catalogued`. Default for legacy records without the
field: treat as `catalogued` (they came from a repo walk — the only path that
existed before authoring). Surfaced in `list`/`show`; filterable
(`--origin authored`).

### 2. Sync excludes authored records (the safety fix)

`reconcile()` must **not** consider `origin: authored` records for
orphaning — they have no upstream to reconcile against. They pass through
untouched. Only `catalogued` records participate in the cascade.

This is the urgent guardrail: without it, `adef sync` corrupts a repo-less
team's catalog. It's small and should land first regardless of the rest.

### 3. Catalog won't clobber authored records

Re-running `catalog` over a repo assigns fresh IDs today (pre-sync behavior) and
must never reuse or overwrite an `authored` record's ID or file. Authored IDs
are counted in `next_id` (they already are — shared ID space) and their files
are never targets of a catalog write. (Once catalog reconciles by default —
sync design open Q6 — authored records are simply excluded, same as §2.)

### 4. Durability: lean on git

The workspace is already markdown + YAML — a text tree git handles perfectly.

- **Git-friendly workspace.** Document `git init` on the *workspace* —
  `journals/` + `catalog/` + `schema/` get version history, blame, and backup
  for free. This is the Journey-B team's system-of-record durability, using the
  tool they'd use anyway. **Docs only, no code:** native git covers it
  end-to-end; an ADEF flag would just wrap three git commands (built and removed,
  2026-07-22). No bespoke backup machinery either (a snapshot command would
  reinvent git for a text tree).

### 5. Export / deployment — deliberately deferred

`adef export` (emit `authored` records back as real rule files — the graduation
path to detection-as-code, and the "paste into the SIEM" deployment bridge) is
**not built and not planned for now** (decision 2026-07-22). Reasons:

- **It's speculative.** A repo-less team is here *because* they don't want a
  repo; the off-ramp is a problem they don't have yet. It only matters once
  people are authoring meaningfully in ADEF — the *last* thing needed, not a
  thing to design around now.
- **Fidelity is genuinely hard.** Round-tripping a record into valid, complete
  Sigma/SPL (every metadata field a real rule needs) is not small; a lossy emit
  produces files that *look* deployable but aren't. Better absent than
  half-right.

When there's demand (teams actually authoring in ADEF and asking to leave with
their rules), revisit — the `origin: authored` marker already tells export
exactly what it owns. Deployment connectors remain an anti-goal regardless.

## Anti-goal impact

- **No change to the "no writes under `detections/`" invariant** — ADEF still
  never writes to the user's rule repo.
- **No vendor connectors** — unaffected (export/deployment deferred anyway).
- **No new engine types, no web UI** — unaffected.

The one philosophical shift: ADEF is now a *system of record* for `authored`
records, not purely a layer. That's the decision above, logged in `ISA.md`.

## Sequencing

1. ✅ **Origin marker + sync-exclusion** (the safety fix — done 2026-07-22) —
   `origin: authored|catalogued` on the record (`draft_record_from_schema` →
   authored, `record_from_discovered` → catalogued, legacy defaults catalogued);
   `reconcile()` skips `authored` records so `adef sync` never orphans them;
   surfaced in `list --origin` / `show`. Proved E2E: an authored rule survives a
   `sync` against a repo that doesn't contain it.
2. ✅ **Git-friendly workspace docs** (done 2026-07-22) — user guide
   `docs/detection-home.md` covers the repo-less workflow: version the workspace
   with **native git** (it's plain markdown + YAML), author here, sync-is-safe,
   deploy by hand. An `adef init --git` convenience flag was built then removed
   — it only wrapped `git init && git add && git commit`, which native git does
   directly; the doc carries the value (ISA 2026-07-22).
3. *(deferred — §5)* `adef export` + per-SIEM deployment docs. Not now.

## Open questions

1. **Mixed workspace** (some authored, some catalogued — a team going
   detection-as-code incrementally). The `origin` marker handles it per-record;
   confirm `list`/`coverage`/`sync` all read cleanly in a mixed workspace.
2. **`init --git`** default on or off? Lean off (explicit opt-in) — don't create
   git repos in someone's workspace without asking.
