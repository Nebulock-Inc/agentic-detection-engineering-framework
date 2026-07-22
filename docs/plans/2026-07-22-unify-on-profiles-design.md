# Unify Extraction on Profiles? — Design analysis

**Date:** 2026-07-22
**Status:** Analysis / open decision (no code — informs a future fork)
**Motivated by:** the question "is having both built-in parsers *and* profiles
confusing? Should the known formats just be shipped profiles?" (raised during
the heavy real-corpus E2E pass).

---

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

## Options

1. **Keep the split; fix the docs.** Conclude the split is sound (different power
   for different authors) and add a short "built-ins vs profiles" explainer so
   it stops being confusing. Cheapest; the `rule_uuid` gap the heavy pass found
   is a separate built-in bug, already fixed (2026-07-22).
2. **The 80% version.** Add just **coalesce + value-mapping** to the profile
   format and migrate Sigma + ESCU to *shipped* profiles (which double as
   worked examples for users). Keep built-ins only for the genuinely weird ones
   (`.conf` regex, Panther sibling `.py`). Partial unification; commits to the
   DSL direction.
3. **Full unification.** Grow the profile format to cover every built-in
   (regex container, sibling-file lookup, …). Maximal consistency, maximal
   format complexity. Highest cost; hardest to keep safe.

## Recommendation

**Option 1 for now, with Option 2 as the considered upgrade path.** The split is
architecturally sound — it's not accidental complexity, it's two audiences. The
*confusion* is real and worth a docs fix. The *unification* only becomes worth
its cost if users are hitting the wall of "I want a profile to do what a built-in
does" — which we have no evidence of yet (profiles today serve unknown in-house
formats, and the built-ins cover the public ones). Revisit Option 2 if that
demand shows up: shipping Sigma/ESCU as example profiles is genuinely nice
documentation, and coalesce+mapping is the smallest step that unlocks it.

**Not built. This doc is the decision record for when the question recurs.**
