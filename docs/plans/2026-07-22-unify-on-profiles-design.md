# Unify Extraction on Profiles? — Design analysis

**Date:** 2026-07-22
**Status:** Analysis / open decision (no code — informs a future fork)
**Update 2026-07-27:** P1 (TOML container) + P2 (Azure-Sentinel profile) shipped 2026-07-22; keep-the-split still holds. (The Status line above is the original 2026-07-22 framing, kept for the record.)
**Motivated by:** "is having both built-in parsers *and* profiles confusing?"
→ sharpened to "does cataloging *scale* across real repos?" → answered with a
**wide-corpus measurement** (below), which reframed the whole question.

---

## Measured evidence — recognition across 6 real repos (2026-07-22)

The decisive input. Cataloged (dry-run) six major public detection repos:

| Repo | Container | Rules | Outcome |
|------|-----------|-------|---------|
| **SigmaHQ/sigma** | YAML | 3,142 | ✅ **100% recognized** — 88% MITRE, 91% platform, only 18% needs_review |
| **splunk/security_content** | YAML | 2,124 | ✅ recognized — 98% MITRE (100% needs_review = ESCU has no OS platform) |
| **panther-analysis** | YAML | 877 | ✅ recognized (unsupported — logic in sibling `.py`) |
| **Azure/Azure-Sentinel** (Detections) | YAML | 483 | ❌ **unclaimed** — rule-shaped (`id`/`name`/`query`/`queryFrequency`) but no matching signature |
| **elastic/detection-rules** | **TOML** | 2,015 | ❌ **not_a_rule** — not parseable as YAML at all |
| **chronicle/detection-rules** | **YARA-L** (`.yaral`) | ~917 | ❌ **not_a_rule** — a custom DSL, not YAML |

**Three distinct gap categories** — this replaces the earlier speculation:

1. **YAML + known signature** (Sigma/ESCU/Panther) — **works, at scale.** Sigma
   in particular (never tested before) is the healthiest corpus seen. Same-format
   different-repo generalization is *not* a real problem.
2. **YAML + unknown signature** (Azure-Sentinel, 483) — rule-shaped YAML ADEF has
   no recognizer for → **unclaimed → needs a profile.** The fields sit at clean
   top-level paths (`query`, `name`, `id`), so the *current* profile format likely
   suffices — maybe + coalesce. This is the genuine "Case B."
3. **Non-YAML container** (Elastic TOML 2,015; Chronicle YARA-L ~917) — ADEF can't
   even parse the file → **not_a_rule.** ~4,000 real rules across two major repos
   are completely dark. Neither a signature nor a dot-path profile helps until the
   **container** is parseable.

**Takeaway that reframes everything below:** the scaling gap is *not* "renamed
fields in almost-Sigma rules." It's **containers we don't parse** (category 3,
the big one) and **unknown-but-YAML signatures** (category 2, cheap). The profile
format already *declares* `toml`/`conf`/`raw` containers but only *implements*
`yaml`/`json` (`IMPLEMENTED_CONTAINERS`) — the design anticipated this.

## Today: two extraction paths

ADEF turns a rule file into a `DiscoveredRule` via one of two mechanisms:

1. **Built-in extractors** (`adef/core/rule_discovery.py`: `_extract_sigma`,
   `_extract_splunk_escu`, `_extract_panther`, `_extract_spl_conf`,
   `_extract_generic`) — imperative Python, shipped in ADEF, for the formats
   ADEF *owns*: Sigma, Splunk ESCU, Panther, SPL `.conf`, raw sql/kql/cql.
2. **Profiles** (`adef/core/profiles.py`) — declarative YAML (a dot-path `map:`
   + signature) authored by **users** to teach ADEF an **in-house format** it
   doesn't recognize. Deliberately restricted: no code, lints cleanly, safe.

Same output shape, two authoring models with **deliberately different power**:
maintainers write Python for known formats; users write safe dot-paths for
their own. The confusion is real but it's largely a *documentation* gap — the
tool never says "built-ins = formats we own; profiles = yours."

## The question: could profiles absorb the built-ins?

Yes — but only by growing the profile format into a mini-DSL. Here is the exact
delta, from comparing each built-in to what a profile can express today:

| Built-in behavior | Profile today? | Would need |
|---|---|---|
| Dot-path pull (title/query/uuid) | ✅ `map:` | — |
| `platform` constant or single path | ✅ `platform_const`/`platform_path` | — |
| MITRE prose-sweep fallback | ✅ (in `_extract_via_profile`) | — |
| Sigma `logsource.{category→service→product}` for data_source | ❌ | **coalesce** (first non-empty of N paths) |
| ESCU `data_source` may be a list → `[0]`; else `datamodel` | ❌ | **list-index + coalesce** |
| Sigma `logsource{product/category/service}` → one platform via a mapping (`aws`→cloud-aws, …) | ❌ | **value-mapping table** |
| SPL `.conf`: regex-parse `[stanza]` + multi-line `search =` | ❌ (not even a structured container) | **regex/`.conf` container type** + capture groups |
| Panther: logic in a **sibling `.py`** (`Filename:`) | ❌ (profile sees one doc) | **sibling-file awareness** |

The pure field-plucks (most of ESCU/Sigma metadata) are already profile-able.
It's the **transformations** — coalesce, list-indexing, platform mapping, regex
containers, sibling files — that resist.

## The tradeoff (the real decision)

Every capability added to close that gap is one the profile format must lint,
document, and let a user get wrong. The current split **keeps the user-facing
format dumb on purpose** — that dumbness is what makes profiles safe and
authorable. Turning profiles into a DSL powerful enough to express the built-ins
trades that away.

- **Collapse built-ins → profiles as-is:** would *cripple* the built-ins down to
  dot-paths (lose ESCU list handling, Sigma tag/platform normalization, `.conf`
  regex, Panther sibling `.py`). Not viable.
- **Grow profiles into a DSL:** doable, but the format stops being "a dumb map"
  and becomes a small language — more power, less safety, more to get wrong.
- **Keep both (status quo):** two mechanisms, but each is simple for its
  audience. Confusion is a docs problem, cheaply fixed.

## The real question: does this SCALE? (reframed 2026-07-22)

The framing above ("is it confusing?") is secondary. The sharper worry: **we had
to write a special extractor for ESCU and for Panther. That's a closed set only
maintainers can grow — it does not scale to the long tail of real repos.** Every
org's slightly-bent format would need either a new built-in (we can't write one
per org) or a profile (the open, user-authorable set). So profiles are the only
mechanism that scales — and if they're too weak, users fall back to "please add a
built-in," which is the thing that doesn't scale.

The measurement (top of doc) settles it: special extractors are a closed set only
maintainers can grow. Sigma/ESCU/Panther work; **Azure-Sentinel, Elastic, and
Chronicle don't** — and profiles are the only mechanism that scales to those
without us shipping a built-in per format. But the *reason* each fails differs,
so the fix differs.

## Priority-ordered plan (grounded in the three categories)

**P1 — Container support (unlocks the biggest dark corpora). ✅ DONE 2026-07-22
(TOML).** Implemented the `toml` container in profiles via stdlib `tomllib`
(3.11+; graceful skip on 3.10 — the file simply isn't claimed). Proven: with
`examples/profiles/elastic-detection-rules.yml`, **Elastic went from 2,017
not_a_rule (100% dark) → 2,015 claimed** — title 100%, uuid 100%, mitre 94%,
query 94% — via a *user profile*, no built-in. Their fields (`rule.name`,
`rule.query`, `rule.threat[].technique[].id`) are clean paths once TOML parses.
`conf` (SPL savedsearches) is the next container, still unimplemented. YARA-L
(Chronicle) is a *DSL*, not a data format — genuinely harder; defer or treat as
a specialized built-in. **This validated the whole thesis: profiles are the
scaling mechanism; they just needed the container.**

**P2 — Profiles catch unknown-but-YAML formats. ✅ DONE 2026-07-22 (no code
needed).** Azure-Sentinel was YAML with clean top-level fields, as predicted —
`examples/profiles/azure-sentinel.yml` claims it with **today's profile format,
zero new features**: Detections/ 170 (title/query/uuid 100%, mitre 91% via
`relevantTechniques[]`), Hunting Queries/ 1158 — one profile, both dirs. The
`all_keys: [id, name, query]` signature correctly excludes ~300 migration stubs
(no `query`) → unclaimed; **0 real rules missed** (every query-bearing file
claimed). Confirms the "users profile their own variant" story on a real repo —
and that coalesce was *not* needed here.

**P3 — Small transform helpers: NOT NEEDED (confirmed 2026-07-22).** list-index
(`[0]`), value-mapping. Both real unclaimed corpora (Elastic P1, Azure-Sentinel
P2) were fully handled without them — Sigma's built-in already does its own
mapping, and the unknown-YAML/TOML formats had flat or `[]`-iterable fields. **No
evidence P3 is a blocker.** Left unbuilt; add only if a future real profile
actually hits the wall (YAGNI).

**Explicitly out:** regex/exec in profiles, sibling-file logic (Panther `.py`) —
structural and rare; keep as built-ins. The line to hold: **named, bounded
features, never a Turing-complete DSL.**

## Options

1. **Keep the split; docs only.** Under-serves the ~4,000 dark Elastic+Chronicle
   rules and the 483 Azure-Sentinel ones the measurement exposed. Not enough.
2. **P1 + P2 (recommended): container support + profiles-catch-unknown-YAML.**
   Implement the TOML container (unlocks Elastic), confirm a profile catches
   Azure-Sentinel (+ coalesce if needed). Ship those as example profiles —
   worked references. Defer P3 until measured. Keep `.conf`/Panther built-in.
3. **Full unification.** Grow profiles to cover every built-in incl. regex/DSL.
   Trades away the safety that is the profile format's whole point. Not
   recommended.

## Recommendation

**Option 2, P1-first.** The wide-corpus test moved the answer from a speculative
"add three DSL features" to a measured "**implement the TOML container** — it
unlocks a major repo (Elastic, 2,015 rules) that's 100% dark today, and the
profile format already declares the container slot." P2 (profile Azure-Sentinel,
maybe + coalesce) is the cheap follow-on that proves the user-profiles-their-own-
format story on real data. P3 stays deferred — no evidence it's the blocker. The
line to hold: **named, bounded features, not a Turing-complete DSL** — the moment
profiles need loops/conditionals/exec, we've lost the safety that makes them
user-authorable.

Sequencing when built: **(P1)** TOML container in profiles → validate against
Elastic's 2,015 rules; then `conf`. **(P2)** confirm a profile catches
Azure-Sentinel; add `coalesce` if a real profile needs it. **(P3)** list-index /
value-mapping only if measured need. Ship the resulting Elastic/Azure profiles as
living example documentation. YARA-L (Chronicle) deferred — it's a DSL, not a
data container. **Still design-before-build — not implemented; this doc + the
6-repo measurement are the plan.**
