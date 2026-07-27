# ADEF — A Day in the Life

**Date:** 2026-06-26
**Purpose:** Show how a detection engineer actually uses ADEF day-to-day, so the
team can react to the *experience* before we lock the design. Companion to
`2026-06-26-adef-repo-design.md`.

> The mental model: **ADEF meets you where your detections already are.** You don't
> migrate to use it. The CLI is the engine that remembers everything; the skills are
> the agent "brain" that does the thinking. The agent thinks, the CLI commits.

---

## Day 0 — Getting set up (one time)

```bash
pip install adef            # the engine: CLI + workspace + MCP
adef init                   # scaffolds ~/work/adef-workspace/
adef skills install         # optional: drops the agent skills into .claude/
```

**Point ADEF at your existing rules repo.** v1 assumes your detections live as files
in a repo (Sigma, Splunk, Elastic, custom — whatever you already use):

```bash
adef backfill --rule-root ~/work/our-detections
# → for every existing rule: creates a D-XXXX journal + a catalog/enrichment record
#   that REFERENCES your file (rule_ref). Your repo is NOT modified. ADEF rides on top.
```

After Day 0 you have a **map of everything you already own** — cataloged, tagged,
organized by platform, journaled, and queryable — without touching the source of
truth or changing how you deploy. ADEF is the layer on top.

> Out of scope for v1: pulling rules out of a SIEM that has no file repo, and
> deploying rules. ADEF organizes, documents, and helps you *author*; your pipeline
> still deploys.

---

## A typical morning — "Here's a new threat report, do we care?"

You drop a CTI report into the agent and invoke the **research** skill.

```
You:  /adef-research  https://intel.example/apt-report

ADEF (research skill, thinking out loud):
  • Extracted 4 behaviors, mapped to T1218.005, T1059.003, T1547.001
  • Checked our corpus (INDEX):
      - T1059.003 → already covered by D-0005 (active)
      - T1547.001 → PARTIALLY covered by D-0012 (covers Run key, not Startup folder)
      - T1218.005 → NO coverage
  • Checked our data (schema/edr_process.yml):
      - mshta behavior → fields present, good population. Buildable. ✅
      - Startup-folder behavior → we don't collect file_create on that path. ✗
  • Recommendation:
      1. Build new detection for T1218.005 (mshta) — clean gap, we have the data
      2. EXTEND D-0012 to cover Startup folder (don't build new)
      3. Skip the file-create idea — no telemetry; flag as a data-collection gap
```

The valuable part is what it tells you *not* to build: you're already covered for
one, partially covered for another (extend, don't duplicate), and a third isn't
buildable on your current data. You pick #1.

```
You:  build candidate 1

ADEF:  adef detection new "Suspicious mshta.exe child process" --platform windows
       → created D-0047  (status: draft, stage: find)
       → journal records: source CTI URL, MITRE mapping, why it exists
```

---

## Authoring — the part that usually hurts, now in a loop

You invoke the **author** skill on D-0047. It grounds itself in your real data
before writing a line of logic.

```
ADEF (author skill):
  • Read schema/edr_process.yml — confirmed parent_image, child_image, command_line
    all present, populated. (Observe stage recorded.)
  • Drafted Sigma logic into D-0047.yml
  • Let's see what it actually returns on your data...
```

Now the piece that makes it real — **running the query and seeing results.** ADEF
doesn't touch your SIEM; it runs through whatever you already use (your MCP, a
script, even paste), and then *records the run so it's remembered*:

```
   [query runs via YOUR tool — returns 1,240 hits over 30 days]

ADEF:  That's noisy — 1,240 hits, FP rate looks ~8%, target is 2%.
       Most are a legit patching tool spawning mshta. Tightening to exclude it...
       [re-runs → 14 hits, all look suspicious]

       adef detection test D-0047 --results -
       → journal Test block:  14 rows, 3 sampled, FP-rate ~0% < target 2% → PASS
```

Every iteration is journaled. Six months from now, "why is there an exclusion for
that patching tool?" is answered by the journal — not lost to memory.

```
ADEF:  adef detection refine D-0047
       → similarity check: no duplicate. overlap: minor with D-0005, acceptable.
         verification: passes schema + engine constraints. (all journaled)
```

---

## Marking it ready — the documentation gate

ADEF doesn't deploy (you do that through your own pipeline). Govern is a
*readiness & documentation* gate — it makes sure the detection is properly owned,
reviewed, and documented before you take it live yourself.

```
You:  adef detection govern D-0047

ADEF:  Readiness gates:
         ✅ owner set (you)        ✅ severity set (medium)
         ✅ response guidance        ⚠️  peer review note missing
       → Add a peer-review note to pass the gate.

You:  adef detection govern D-0047 --note "reviewed by @sam, approved"

ADEF:  → status: ready. Gate evidence recorded in journal.
       (Deploy via your own pipeline; ADEF keeps the record + history.)
```

The detection is now `detections/windows/D-0047-mshta-suspicious-child-process.yml`,
fully journaled and documented from intel → review-ready, in one sitting.

---

## Weeks later — keeping it healthy

**Did our data change underneath us?** Re-run schema discovery. You sample your data
however you already do (a query through your own tooling) and pipe the rows in — ADEF
never reaches into your environment, it just reads the sample you hand it:

```bash
your-data-sample-query | adef schema diff edr_process --results -

ADEF:  Drift detected:
         • field 'command_line' now null in 40% of events (was 2%)
         • affected detections: D-0047, D-0009
       → D-0047 may be degraded. Recommend review.
```

That drift report re-enters the lifecycle. You invoke **evolve**:

```
You:  /adef-evolve D-0047    (paste in last 30d signal volume)

ADEF:  • Journal shows it was tuned to 14 hits/30d at govern time.
       • Now firing 0 hits/30d + command_line went null 40% → likely broken by a
         logging change, not a real drop in activity.
       • Recommendation: TUNE — switch to image-path match that survives the null.

You:  adef detection evolve D-0047 --note "logging change nulled command_line; switched to image-path match"
```

Keep / tune / deprecate — all recommended by the agent from journal history + drift
+ signal data, all committed through the CLI, all remembered.

---

## What the team should react to

1. **The research lens** — does "tells you what NOT to build (already/partially
   covered, or not buildable on our data)" match how you'd want to start a workday?
2. **The author loop** — running queries through *your own* transport and having
   ADEF *record every run* — is the journaled-iteration the thing you wish you had?
3. **Meeting you where you are** — wrap your existing repo/SIEM export on Day 0, no
   migration. Is the wrap-first adoption story low-friction enough?
4. **The Govern gate** — are these the right hard gates (owner, severity, response,
   peer review), or do you want more/fewer?
5. **On-demand drift** — point-in-time `schema diff` in the framework; continuous
   monitoring stays Nebulock product. Is that line in the right place?

---

## The one-liner north star (for context)

Eventually, the whole morning flow compresses to:

```bash
adef detection new --from-intel https://intel.example/apt-report
```

…which runs Find → Observe → Refine *without skipping any stage* — every step
journaled, deduplicated, schema-grounded, and gated. The day-in-the-life above is
that same flow, unrolled so you can see each decision point.
