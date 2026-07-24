# README reshape — proposal (shape only, not a replacement)

**Status:** ✅ **implemented 2026-07-24** — `README.md` was reshaped on these
recommendations (all four open questions resolved on the recommended defaults; see
ISA Decisions 2026-07-24). Kept for the rationale + open-question record.

**What this is:** a proposed *reorganization* of the existing README — same
content, mostly the same words, in an order that reads as one linear journey
instead of a pile of capability sections. Feature-freeze safe: no new features,
no new claims, just structure + tightening.

---

## 1. What's already working (keep verbatim)

- The title, tagline, and "What you get" 4-bullet block (lines 1–12). Strong,
  concrete, honest. **Keep.**
- The three on-ramps (repo / SIEM-only / fresh). The *content* is right — the
  branching is ADEF's best idea. Only their **placement** changes.
- The honesty framing everywhere ("not a vanity heatmap", "fictional coverage",
  read-only, orphaned-never-deleted). **Keep the voice.**
- ATHF sibling, maturity model, north-star, license. **Keep, relocated** to a
  "context / learn more" tier at the end (they already live near the end).

## 2. What's clunky (the case for reshaping)

| Problem | Where | Effect on a first-time reader |
|---------|-------|-------------------------------|
| Commands grouped by **capability**, never a single start-to-finish path | whole body | "I installed it — now what, in order?" is unanswered |
| **FORGE philosophy up front** (lines 14–24) before any concrete action | §2 | Philosophy before payoff; reader wants "what does a run look like" |
| The **schema merge deep-dive** (lines 135–158, 24 lines) | §5 | Reads like reference docs mid-README; buries the 4 commands above it |
| On-ramps come **before** "teach ADEF your data", but schema is often step 0 | §4 vs §5 | Ordering implies catalog-then-schema; for authoring it's the reverse |
| Examples lean almost entirely on **Splunk / `wineventlog_xml`** | §4, §5 | Non-Splunk readers don't see themselves |
| New **`docs/skills-reference.md`** and `catalog-sync` not surfaced | §8 | Latest work invisible from the front door |

## 3. Proposed shape at a glance — three tiers

```
TIER 1 — START (linear, numbered, one narrative)
  ├─ What ADEF is + What you get          (unchanged)
  ├─ Install                              (unchanged)
  └─ Quick start: 0 → first coverage      (NEW spine — numbered 1..5)
        step 3 branches to your on-ramp (repo / SIEM / fresh)

TIER 2 — THE BUILDING BLOCKS (reference-style, dip in as needed)
  ├─ Catalog & keep it current  (catalog + sync + profiles)
  ├─ Teach ADEF your data       (schema recipe→reshape→ingest→check)
  │     merge mental-model compressed to ~4 lines + link out
  ├─ See your coverage — honestly
  ├─ Work the FORGE lifecycle   (the 5 stages, now *here* with commands)
  └─ Author new rules           (detection new --source)

TIER 3 — AGENTS & CONTEXT
  ├─ Claude plugin & MCP        (+ link to docs/skills-reference.md)
  ├─ ADEF & ATHF — paired siblings
  ├─ Maturity model
  ├─ Why ADEF / North-star / License
```

**The one big move:** introduce a single numbered **Quick start** as the spine
(Tier 1), demote FORGE-the-philosophy into a two-line mention up top with the
full stage walkthrough moving down to Tier 2 ("Work the FORGE lifecycle"), and
fold the on-ramps into **step 3** of the quick start instead of a standalone
section. Everything else keeps its words and just gets a tier.

---

## 4. Section-by-section mapping (current → proposed)

| Current section | Proposed home | Change |
|-----------------|---------------|--------|
| Title / tagline / What you get | Tier 1 (top) | none |
| The FORGE Lifecycle | 2-line teaser at top; full list → Tier 2 | split |
| Install | Tier 1 | none |
| Pick your on-ramp (A/B/C) | Tier 1, **as quick-start step 3** | reframed as a branch |
| Teach ADEF your data | Tier 2 | compress merge deep-dive, +multi-platform |
| See your coverage | Tier 2 | none |
| Work the lifecycle | Tier 2, retitled "Work the FORGE lifecycle" | absorbs the 5 stages |
| Claude plugin & MCP | Tier 3 | + link to skills-reference.md |
| ADEF & ATHF | Tier 3 | none |
| Maturity model / Why / North-star / License | Tier 3 | none |

---

## 5. Skeleton render (the mockup)

> Headers + intent lines + example command sketches only — real prose is lifted
> from today's README where noted. Examples deliberately show **two platforms**
> (Splunk + Microsoft Sentinel) so non-Splunk readers see themselves.

```markdown
# Agentic Detection Engineering Framework (ADEF)

> Detection engineering with durable memory, a five-stage lifecycle (FORGE),
> and an agentic surface — the sibling of ATHF.

<one paragraph: what it is — REUSE lines 5>
<**What you get** — REUSE the 4 bullets verbatim>

FORGE in one line: Find → Observe → Refine → Govern → Evolve. Full walkthrough
below and in docs/methodology.md.

## Install
<REUSE current Install block verbatim — clone / venv / pip install -e . /
 adef init --interactive>

## Quick start — from zero to your first coverage report

1. **Scaffold a workspace.**   `adef init --interactive`
2. **Teach ADEF your data** (one SIEM export; ADEF never connects):
   - Splunk:   `adef schema recipe splunk`  → run it → `adef schema reshape fields.csv --platform splunk`
   - Sentinel: `adef schema recipe sentinel` → run it → `adef schema reshape schema.csv --platform sentinel`
   then `adef schema ingest <sources>.yml`
3. **Bring in your detections — pick the line that's you:**
   - **Have a repo?**        `adef catalog /path/to/rules`  (read-only; `--dry-run` to preview)
   - **Only in your SIEM?**  export rules to a folder, then `adef catalog /path/to/export`
   - **Starting fresh?**     `adef detection new "…" --source <schema>`
   <one line each — REUSE the A/B/C prose, trimmed to 2 sentences apiece>
4. **See where you stand.**   `adef coverage`  (+ `--gaps`, `--navigator layer.json`)
5. **Work a detection.**      `adef detection show D-0001` → `observe` → `refine` …

> Each on-ramp is expanded under "Building blocks" below; the full repo-less
> path is docs/detection-home.md.

## Building blocks

### Catalog & keep it current
<REUSE on-ramp A prose: read-only, formats supported, profiles, sync preserves
 enrichment, orphaned-never-deleted. Show catalog + sync + --check.>

### Teach ADEF your data
<REUSE the 4 schema commands + recipe/reshape/re-ingest paragraph.
 COMPRESS the merge mental-model to ~4 lines:>
  SIEMs often expose one fact as two fields with two value formats (Splunk
  `Status=0xc00…` raw vs `status=failure` CIM). `reshape` merges them with
  `aliases:`; when it marks a merge `[SUSPECT]`, read the values it shows —
  same info two formats → keep; different fields colliding on spelling →
  split with `--no-fold` (or `--interactive`). Full reasoning + the
  per-alias-values caveat: <docs/schema link>. With the plugin, the
  `schema-declaration` skill drives the whole flow.

### See your coverage — honestly
<REUSE verbatim: solid vs fragile, SPOFs, fictional coverage, Navigator,
 attack show/refresh.>

### Work the FORGE lifecycle
<MOVE the 5-stage list here (Find/Observe/Refine/Govern/Evolve, one line each),
 immediately followed by the current "Work the lifecycle" command block and the
 "six months from now the next engineer reads why" close.>

### Author new rules
<REUSE on-ramp C prose: detection new --source, origin marker, sync skips
 authored, detection-home link.>

## Claude plugin & MCP
<REUSE verbatim + one new line:>
  Which skill fronts which command: docs/skills-reference.md.

## ADEF & ATHF — paired siblings, not successor
<REUSE verbatim>

## Maturity model / Why ADEF / North-star v1 demo / License
<REUSE verbatim>
```

---

## 6. What gets rewritten vs. reused

- **Rewritten (small):** a new numbered *Quick start* block (~15 lines);
  the merge deep-dive compressed 24 → ~5 lines with a link out; FORGE split into
  a top teaser + a Tier-2 heading.
- **Reused verbatim:** ~85% of the body — What-you-get, Install, on-ramp prose,
  schema commands, coverage, lifecycle commands, plugin, ATHF, maturity,
  north-star, license.
- **Net length:** roughly flat or slightly shorter (the merge section shrinks
  more than the quick-start adds).

## 7. Open questions for colleagues

1. **Second example platform** — I used **Sentinel** as the Splunk contrast.
   Prefer Elastic, or show three?
2. **Where does the compressed merge deep-dive link to?** We don't have a
   standalone `docs/schema-*.md` yet — link the `schema-declaration` skill, add
   a short schema doc, or keep it inline at ~5 lines?
3. **FORGE placement** — is a 2-line teaser up top + full walkthrough in Tier 2
   the right split, or should the 5 stages stay near the top as identity?
4. **Quick-start step 2 (schema) before step 3 (catalog)** — correct for
   authoring and for `schema check`, but a repo-only reader could catalog first.
   Do we order schema-first (shown) or catalog-first with schema as step 4?
```
