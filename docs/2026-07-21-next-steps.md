# ADEF Next Steps — 2026-07-21

**Context:** follows `docs/2026-07-20-status-and-design-changes.md`. Since that
summary shipped: scope on declared sources + scope-aware `schema check`,
`query_language` persisted on records, `adef detection list`/`show` (story
7393), the `examples/` demo pack (rules + 14-source scoped declaration built
from a live Splunk export), the declaring-data-sources guide, and E2E fixes
(rule-root-relative `rule_ref`, data_source fallback + SQL comment stripping).

Ordered by what unblocks what.

## Immediate — makes the branch mergeable

1. **Local quality gates.** `pytest`, `ruff check adef/`, `mypy adef/` in a
   real dev environment; record evidence in ISA `## Verification`. Everything
   since 2026-07-20 is sandbox-smoke-verified (28/28, 31/31, 15/15, 10/10 +
   exact corpora regression) but not suite-verified. The only blocker.
2. **Co-worker sign-off** on the three implemented design decisions, per ISA
   discipline: extraction profiles + plugin (`2026-07-20-claude-plugin-design.md`),
   declarations (`2026-07-20-schema-declaration-design.md`), and its scope
   section (2026-07-21). All changed schema-shared surfaces.
3. **`needs_review` rework** (agreed, unbuilt). The demo showed 8/9 rules
   flagged → zero signal. Scope:
   - `review_reasons: [no_platform, no_mitre, malformed, external_logic]` on
     records; boolean kept for compat; `list --needs-review <reason>` triage.
   - **Platform inheritance from declarations**: a rule whose literals match a
     scoped source inherits that source's `platform` at catalog time —
     declaring data makes the catalog cleaner (kills 7/8 demo flags, moves
     records out of `multi-platform/`).
   - `no_mitre` demoted: visible in `show`/JSON, excluded from the ⚠ marker
     and headline count (it's enrichment work, not a defect).
   - **Tier-2 MITRE parity for profile rules**: fall back to the technique-ID
     text sweep (title + description + query) when the profile map yields no
     MITRE — same behavior conf rules already get. (Why the Panther scheduled
     queries came back 0% MITRE.)

## Near-term — makes the launch demo compelling

4. **`mitre-tagger` skill.** Drains the `no_mitre` queue: propose techniques
   from query + title, human approves, enrichment written to *catalog records*
   (ADEF's layer — upstream rules stay untouched). Gate to everything
   coverage-shaped.
5. **Catalog-time coverage report + MITRE Navigator layer export.** The
   "first 15 minutes" artifact identified at the very start and still
   unshipped. Cheap once MITRE density is decent; it's the
   screenshot-into-Slack moment for a skeptical DE lead.
6. **`declaration-author` skill.** Performed manually twice this session
   against live Splunk exports; logic now fully specified: internals filter,
   case-dupe → aliases, enum harvesting with value-length caps, numeric/hex
   typing, and mixed-shape detection → "re-export per sourcetype" guard.
7. **`schema check` report polish.** Union-matched rules attribute a missing
   field to every matched source (`NotARealField` × 14 rows in the demo).
   Correct but noisy — collapse union findings into one row.

## Strategic — design before build

8. **`adef sync` design doc.** The biggest unaddressed trust risk: stale
   catalogs. Already designed verbally: identity cascade (rule UUID → content
   hash → path → fuzzy), git-based diffing (SHA at catalog time,
   rename detection), staleness-aware reads (CLI + MCP annotate or auto-resync),
   and auto-journaling of out-of-band edits with harvested commit messages —
   edits that bypass ADEF become history, not lost value. Write the doc before
   v0.1.0 even if implementation follows later.
9. **Benchmark corpus in CI.** Recognition/extraction rates per public repo
   (SigmaHQ, security_content, panther-analysis, Sentinel, elastic) as
   tracked numbers — the objective merge gate for community-contributed
   profiles.
10. **v0.1.0 release framing.** Gap to releasable is small: items 1–3, a
    README pass, and confirming `examples/` + the Claude plugin are part of
    the launch story (recommended — they *are* the demo). "Release and
    iterate" was the plan from day one.

## Standing follow-ups (tracked, not scheduled)

- Per-SIEM recipe docs beyond the two worked examples (Sentinel `getschema`,
  Elastic `_mapping`).
- Plugin skills wave 2: `journal-backfill`, `forge-stage` (rendered from
  `adef/data/prompts/`), `coverage-gaps`.
- `schema list` + per-detection `schema validate`; `detection search`.
- Deploy-prep flow for SIEM-stored teams (prepare-don't-push + intended-vs-
  deployed drift on next export).
- Shape-literal extractors beyond SPL `sourcetype=` (CQL `#event_simpleName`,
  Elastic `event.dataset`) — each upgrades a platform from union- to
  exact-matching in `check`.
