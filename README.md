<p align="center">
  <img src="https://raw.githubusercontent.com/Nebulock-Inc/agentic-detection-engineering-framework/main/docs/assets/adef-logo.png" width="260" alt="ADEF logo: an anvil built from angular orange segments">
</p>

# Agentic Detection Engineering Framework (ADEF)

<p align="center">
  <a href="https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/actions/workflows/tests.yml"><img src="https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/interface-CLI%20%2B%20MCP-informational.svg" alt="CLI + MCP">
</p>

> Detection engineering with durable memory, a five-stage lifecycle, and an agentic surface — the sibling of [ATHF](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework).

**ADEF wraps the detection rules you already have in a per-detection journal and
a five-stage lifecycle — Find → Observe → Refine → Govern → Evolve (FORGE) — so
that every threshold, every tuning decision, and every keep-or-retire call has a
dated written reason the next engineer can read.** It's a CLI and an MCP server.
It reads your rule repo and never writes to it, and it never connects to your
SIEM.

Throughout: a **rule** is the query you already have, in whatever file your repo
keeps it in. A **detection** (`D-XXXX`) is ADEF's view of it — the rule plus its
journal, its ATT&CK mapping, its stage, and its history. ADEF adds detections;
it never edits rules.

Requires Python 3.10+: `pip install agentic-detection-engineering-framework`.
See [Install](#install).

**Contents** · [The problem](#the-problem) · [See it](#see-it--the-bundled-demo-real-output) · [Install](#install) · [How you'd actually use it](#how-youd-actually-use-it) · [Building blocks](#building-blocks) · [Skills & MCP](#skills--mcp) · [Is ADEF for you?](#is-adef-for-you) · [ADEF and ATHF](#adef-and-athf--paired-siblings-not-successor) · [Contributing](#contributing)

## The problem

Your detection repo says *what* each rule looks for. Almost nothing says *why*.

So the questions that actually come up have no owner:

- *This rule fires 200 times a week and nobody has closed one as a true positive in four months. Does it still earn its keep?*
- *We have 40 rules tagged T1059. Is that depth, or is it one `process_create` feed wearing 40 hats?*
- *The person who wrote this threshold left. Why 15 and not 5?*
- *An intel report just landed. Do we already cover this, or does it feel familiar because we looked at it in March?*

Teams answer these in Slack threads, in a spreadsheet someone maintains by hand,
and from memory — and the answers leave when people do. The rules are
version-controlled. The reasoning isn't.

**ADEF is the memory-and-lifecycle layer over the detections you already have.**
It never touches your rule repo, never connects to your SIEM, and doesn't ask
you to migrate anything.

**What you get:**

- **A catalog of every detection you have** — walked read-only from a repo or a one-time SIEM export, in any mix of Sigma, Splunk, Panther (metadata only), KQL/SQL/CQL, or your in-house format
- **An honest coverage report** — solid vs. fragile ATT&CK coverage, single points of failure, and fictional technique IDs, exportable as a scored MITRE Navigator layer
- **Schema-grounded authoring** — new rules scaffolded against the fields and values that actually exist in your data, not guesses
- **A journal per detection** — the reasoning, tuning history, and review cadence that normally lives in chat threads and leaves with the person who wrote it
- **Keep/tune/deprecate verdicts from measured numbers** — you hand over the counts, ADEF does the arithmetic and writes the verdict down with a date on it

**Where each of those four questions gets answered:**

| The question | What answers it |
|---|---|
| Does this noisy rule still earn its keep? | [`adef ingest` → `adef detection evolve`](#decide-tune-or-retire-from-numbers-not-impressions) — a keep/tune/deprecate verdict computed from counts you supply |
| Is 40 rules on T1059 depth, or one feed wearing 40 hats? | [`adef coverage`](#see-your-coverage--honestly) — solid vs. fragile, and which techniques ride a single log source |
| Why 15 and not 5? | [the journal](#day-thirty--the-lifecycle-does-the-remembering) — every stage transition timestamped, with the evidence that forced it |
| Do we already cover this, or did we just look at it in March? | [`adef detection search` / `adef detection refine`](#find-what-you-already-have--across-query-languages) — retrieval over reasoning *and* rule logic, across query languages |

## See it — the bundled demo, real output

The repo ships a small mixed-format rules "repo" and a matching schema
declaration and health capture, so you can run the whole arc — catalog through
Evolve verdict — with no SIEM, no data, and no setup. The demo files live in a
[clone](#from-a-clone), not the pip package. Everything below is real output,
abridged only where a `…` line marks rows removed:

```bash
adef init                            # scaffold ~/work/adef-workspace/
adef catalog examples/demo-rules     # read-only walk → catalog + journals
```

```
Catalogued 9 rules into ~/work/adef-workspace/catalog
  INDEX     → ~/work/adef-workspace/catalog/INDEX.yml
  8 need review (see `adef detection list --needs-review`).
  1 without ATT&CK mapping (enrichment queue: `adef detection list --needs-review no_mitre`).
```

Then ask the question nobody can answer from a repo:

```bash
adef coverage
```

```
Coverage quality — 8 techniques mapped across 9 detections
  solid       0  (depth ≥2, at least one reviewed)
  fragile     8  (single detection, or all need review)
  → only 0% of your mapped coverage is trustworthy.

Log-source risk
  Busiest feed: thrunt backs 7 detection mappings.
  8/8 techniques ride a single source — if that feed breaks, they go dark at once.

Single points of failure — 8 techniques with one detection
  T1003.001 LSASS Memory  (1 detection; single source (thrunt))
  T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol  (1 detection; single source (thrunt))
  …

By tactic
  Command and Control    0 solid, 2 fragile
  Credential Access      0 solid, 1 fragile
  …

Coverage gaps — detections cover 8 of 697 ATT&CK techniques (1%)
  Stealth                2/148 covered  (146 gaps)
  Persistence            1/113 covered  (112 gaps)
  …
  Execution              0/64 covered  ← blind
  Defense Impairment     0/56 covered  ← blind
  …
```

That is the point of ADEF in one screen. A heatmap would have shown eight green
squares. What you actually have is eight techniques with one rule each, seven of
them riding one feed, and **8 of 15 tactics with nothing at all** — and now it's
written down, re-runnable, and diffable next quarter.

**On order:** this run deliberately catalogs *before* declaring any schema,
because that's how most teams arrive — with a repo and nothing else. The cost
shows up in the output above: 8 of 9 records come back `no_platform`, because a
platform is inherited from a declared source. Run
`adef schema ingest examples/adef-sources-thrunt.yml` first instead and the same
catalog reports *"7 platform(s) inherited, 1 need review"*. Either order works;
schema-first suits authoring and `adef schema check`.

Full walkthrough, including the deliberately broken rule planted in the demo:
[`docs/quickstart.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/quickstart.md).

## Install

```bash
pip install agentic-detection-engineering-framework           # the CLI
pip install "agentic-detection-engineering-framework[mcp]"    # + the adef-mcp server

adef --version                         # verify
adef init --interactive                # scaffold a workspace + set your SIEM
adef doctor                            # what's set up, what isn't, and what to run next
```

`adef doctor` is the command to run whenever you're not sure what to do next.
It reports every piece of workspace state — catalog, INDEX freshness, journal
pairing, declared schemas, ATT&CK snapshot, enrichment queue, ingested health,
MCP, skills — and prints the next command to run where there is one: the fix
for a stale INDEX, the triage entry point for an enrichment queue (that work is
a human's), nothing at all where no command would help. Unconfigured optional
capabilities are warnings and exit 0; state that would make another command
*lie* to you is a problem and exits 1, so it works as a CI check too.

`--interactive` is a guided setup: it asks where your detections live today
(repo / SIEM-only / starting fresh) and tailors your next steps, remembers
your SIEM and query language so later commands stop asking, surfaces the
optional layers (MCP server, AI-assistant skills — inactive until installed)
and offers to install the skills on the spot. Plain `adef init` works too.

The `[mcp]` extra is optional because FastMCP is a dependency nobody using only
the CLI should have to carry. The AI-assistant skills ship *inside* the
package, so `adef install-skills` works from a pip install.

### From a clone

The bundled demo under `examples/` does not ship in the package, so the demo
above and the [quickstart](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/quickstart.md)
run from a checkout — as does contributing:

```bash
git clone https://github.com/Nebulock-Inc/agentic-detection-engineering-framework.git
cd agentic-detection-engineering-framework
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip              # pip >= 21.3 required for editable installs
pip install -e ".[mcp]"                # editable; drop [mcp] for the CLI alone
```

## How you'd actually use it

### Day one — get the truth on paper

Point ADEF at whatever you have. The three on-ramps:

| Where your detections live | What you run |
|---|---|
| **A git repo** | `adef catalog /path/to/rules` — read-only; `--dry-run` previews first |
| **Only in the SIEM** | Export the rules to a folder, then `adef catalog /path/to/export` |
| **Nowhere yet** | `adef detection new "…" --source <schema>` to author against your real data |

Then ask ADEF what to do next rather than guessing:

```bash
adef doctor
```

```
ADEF workspace check

 ✓  workspace   ~/work/adef-workspace (configured)
 ✓  catalog     9 record(s)
 ✓  index       9 detection(s) indexed
 ✓  journals    9 journal(s), all records paired
 !  schemas     no declared data sources — `adef schema check` and cross-language field matching in
                Refine have nothing to canonicalize against
                → adef schema ingest adef-sources.yml
 ✓  att&ck      v19.1 (shipped), 858 technique(s)
 !  enrichment  1× no_mitre, 8× no_platform
                → adef detection list --needs-review no_mitre
 !  health      nothing ingested — Evolve reports `insufficient-data` until it has numbers to read
                → adef ingest weekly-metrics.yml
 !  mcp         not installed
                → pip install 'agentic-detection-engineering-framework[mcp]'
 !  skills      0 of 9 ADEF skills installed — they stay inactive until they're in an assistant's
                skills directory
                → adef install-skills

5 warning(s), no problems — warnings are capabilities you haven't set up, not breakage.
```

That *is* the day-one plan, generated from your own workspace: enrich the
`no_mitre` queue, declare a data source, get health numbers in. Day one ends
with a written, re-runnable account of what you cover, what's fragile, and what
needs enrichment — the thing that previously lived in one person's head.

### Day two — make the catalog mean something

A catalogued rule starts as metadata. Two commands turn it into knowledge:

```bash
adef detection tag-mitre D-0001 T1071.004     # validated against your workspace's ATT&CK snapshot
adef detection show D-0001                    # record + query + derived tactics + journal
```

```
D-0001  Broad thrunt hunt - deliberate schema-check demo
  platform        multi-platform
  format          spl
  query_language  spl
  data_source     thrunt
  kind            atomic
  engine          sql
  mitre           T1071.004
  tactics         Command and Control
  lifecycle       stage=find status=draft
  origin          catalogued
  needs_review    no_platform
  source          demo-rules/broad_hunt_bogus_field.conf

Query
  index=thrunt CommandLine=* qtype_name=TXT NotARealField=1 | stats count

Journal  ~/work/adef-workspace/journals/D-0001.md
  ## [2026-10-07T11:18:44-04:00] Stage: find
```

Nothing in that record was typed by a human — format, query language, engine,
and data source were all inferred from the file. The one line a human added is
`mitre`, and look at what it bought: `tactics` resolved itself from the shipped
ATT&CK snapshot, and `needs_review` dropped `no_mitre` and shrank to the one
real problem left. From here on, what a human adds is the reasoning.

### Day thirty — the lifecycle does the remembering

Every detection moves through five stages, and **every transition is a
timestamped journal entry**:

| Stage | The question it answers |
|---|---|
| **F**ind | What behaviour are we trying to catch, and why now? |
| **O**bserve | What does this look like in *our* telemetry? Understand normal before defining weird. |
| **R**efine | Do we already have this rule? Does its logic hold against the real schema? |
| **G**overn | Who owns it, what gates it, how often does it get reviewed? |
| **E**volve | Given measured numbers: keep it, tune it, or retire it? |

```bash
adef detection observe D-0009 --note "30d of process_create: mshta-from-office ~3/day, all GPO scripts"
adef detection refine  D-0009          # similarity → overlap → verification chain
adef detection govern  D-0009 --note "owner: windows-detection; review quarterly"
adef ingest  examples/weekly-metrics.yml   # the counts from your SIEM — ADEF never fetches them
adef detection evolve D-0009           # health → tuning → deprecation, from those counts
```

`refine` and `evolve` don't need a `--note` — each runs a chain and writes its
own findings. Here's the real journal after `evolve` read the ingested counts.
The chain writes *three* blocks; the `### Evolve / Health` one that comes first
is shown [further down](#decide-tune-or-retire-from-numbers-not-impressions),
and the repeated `detection_id`/`inputs` keys plus ADEF's
`<!-- adef:generated -->` markers are trimmed. Everything else is verbatim:

```markdown
### Evolve / Tuning (2026-10-08T09:59:47-04:00)
- **metrics:**
  - **fp_ratio:** 1.0
  - **weekly_signal_volume:** 238.0
  - **window_days:** 7.0
  - **days_since_true_positive:** 122.08318704664352
- **suggestions:**
  - kind: narrow-filter, rationale: FP ratio 100% on 238 weekly signals — narrow filters or raise threshold., severity: high

### Evolve / Deprecation (2026-10-08T09:59:47-04:00)
- **verdict:** tune
- **rationale:** FP ratio 100% on 238 weekly signals.
```

(`days_since_true_positive` is computed at read time, so it climbs by one a day
— yours will differ from the capture's.)

Six months later, "why 15 and not 5" has an answer with a date on it — and so
does "why did we stop trusting this rule". That's the whole bet: a detection is
never one-and-done, so the reasoning has to live somewhere that survives the
person. See [`docs/methodology.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/methodology.md) for the full FORGE
walkthrough.

## Building blocks

Each capability in depth — dip in as needed. Every command's full synopsis,
options, and examples live in [`docs/cli-reference.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/cli-reference.md).

### Teach ADEF your data

Detections are only as good as knowledge of the data they query. ADEF never
connects to your SIEM — you run one export, ADEF does the rest:

```bash
adef schema recipe splunk              # the exact field-export command for YOUR SIEM
adef schema reshape fields.csv --platform splunk   # export → draft declaration + report
adef schema ingest splunk-sources.yml  # → schema/<source>.yml per source
adef schema check                      # do your rules use fields that exist?
```

`recipe` knows Splunk, Sentinel, Elastic, Chronicle, Sumo Logic, and QRadar.
`reshape` converts the raw export deterministically — filters platform
internals, folds case-duplicate fields into aliases, harvests enum values,
infers types — and prints a transformation report so you approve the
transformations instead of hand-auditing YAML. Re-ingest anytime: your hand
corrections survive, drift is reported.

**Why the merge step matters.** SIEMs often expose one fact as two fields in two
value formats:

```
# Splunk — one logon failure, two fields
Status = 0xc000006d    raw field, NTSTATUS codes
status = failure       normalized field (CIM)
```

`reshape` merges such pairs into one declared field with `aliases:`, so a rule
written against either spelling passes `adef schema check`. It marks a pair
`[SUSPECT]` when it can't tell they're the same field — read the values it shows:

- **Same fact, two formats** (`SYSTEM` vs `NT AUTHORITY\SYSTEM`) → keep the merge.
- **Different fields colliding on spelling** → split with `--no-fold` (or `--interactive`).

With the Claude plugin, the `schema-declaration` skill drives this — the
keep-or-split call turns on knowing what a field *is*, exactly the domain
knowledge an agent session adds.

In depth: [`docs/declaring-data-sources.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/declaring-data-sources.md)
for the declaration format, and
[`docs/siem-recipes.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/siem-recipes.md)
for the per-SIEM export commands `adef schema recipe` prints.

### Catalog & keep it current

Point ADEF at a detection repo — the repo is never modified:

```bash
adef catalog /path/to/rules --report json   # see what ADEF recognizes first (implies --dry-run)
adef catalog /path/to/rules      # walk read-only → catalog + skeleton journals
adef sync /path/to/rules         # later: refresh changed rules, keep your enrichment
adef sync /path/to/rules --check # CI mode: exit 1 if the catalog is behind
```

Run `adef catalog` twice on the same repo and ADEF **refuses** rather than
minting duplicate `D-XXXX` records — it points you at `adef sync`, the
reconciling re-run. Cataloging a *different* repo into a populated workspace
appends cleanly.

Sigma, Splunk ESCU / `savedsearches.conf`, Panther rule metadata, and raw
`.kql`/`.sql`/`.cql` files work out of the box. Queries wrapped in YAML or JSON
(a CQL query hub, Panther scheduled queries, in-house formats) are taught with a small
**extraction profile**
(YAML, no code) — draft one by hand or let the bundled agent draft it from
samples: `adef profile lint` validates, you approve, every future run uses it.
Writing one is documented end to end in
[`docs/creating-extraction-profiles.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/creating-extraction-profiles.md).

`sync` preserves everything you've added — MITRE tags, status, stage, owner and
journal entries survive a re-sync; rules edited outside ADEF get a journal note
instead of silent loss. Rules that vanish from the repo are marked orphaned,
never deleted — orphaning is the one case that overwrites a field you set, and
it sets `status: deprecated`.

### Author new rules

Rules authored in ADEF live in ADEF. Declare a data source first (above), then
scaffold new detections against it:

```bash
adef detection new "Suspicious mshta.exe child process" --source wineventlog_xml
adef detection list --origin authored     # your ADEF-native rules
```

`--source` grounds the draft in a declared schema: the record gets the real
platform, query language, and a starter query carrying your actual index and
sourcetype literals. Records carry an `origin` marker — `adef sync` never
touches rules authored in ADEF, so mixing authored rules with a catalogued
repo is safe. Using ADEF as your system of record with no repo at all is a
supported path: [`docs/detection-home.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/detection-home.md) covers
making the workspace durable under git.

### Find what you already have — across query languages

Before you write a rule, find out whether you wrote it in March:

```bash
adef detection search "credential dumping windows"   # BM25 over journals AND records
adef detection list --tactic execution --status draft
adef detection list --needs-review no_mitre          # the enrichment queue
```

`search` ranks over the journal reasoning (*why*) **and** the catalog record
(title, MITRE, platform, data source, query — the *what*), so a detection is
findable by what it detects even when its journal is still sparse.

**Merging two repos, or suspect you have duplicates?** That's the Refine stage:

```bash
adef detection refine D-0009     # similarity → overlap → verification, all three logged
```

- **Similarity** answers *does a rule like this already exist?* — three
  retrieval passes fused by reciprocal rank fusion:
  - **BM25** over text (title, MITRE, platform, query, journal).
  - **Field-set** — matches rules on the telemetry fields their queries actually
    filter on, canonicalized through your declared schema's aliases, so `Image`
    and `process.name` line up. Needs a declared schema.
  - **Value** — matches rules that test the same *rare literals*
    (`bitsadmin.exe`, `EnableLUA`). Needs **no schema at all**, and only ever
    proposes candidates in a *different* query language.
- **Overlap** classifies rules in the same ATT&CK technique cluster as
  duplicate / complementary / redundant / **unassessed**.
- **Verification** checks the query's fields against your declared schema.

Every result is appended to the detection's journal under a `### Refine /` heading
with a timestamp — so the overlap call is written down where the next person finds
it, which is the part a one-off script can't give you.

**Finding a cross-language twin is the hard case**, and ADEF is explicit about
how far it goes. A Sigma rule and a CQL rule for the same behaviour share no
syntax tokens, and without a schema their field names (`Image` vs
`ImageFileName`) don't line up either — so the value pass meets them on the one
thing they *do* share: the literals they test. That pass needs no setup. The
field pass is stronger but needs a declared schema; without one `refine` says so
plainly rather than silently degrading:

```
field matching: unmatched (field pass skipped) — no declared source addresses this rule's data source
  → run `adef schema ingest <declaration>`, then `adef schema check` to see which rules are still unmatched
```

**And where ADEF can't yet answer, it refuses to guess.** Two rules in different
query languages come back `unassessed`, not scored:

> Different query languages (sigma vs spl) — logic not compared. Judge the pair
> from Similarity's shortlist; a text score across languages says nothing about
> overlap

That's deliberate. Retrieval across languages works; *comparing logic* across
them doesn't yet, and a 0.01 "complementary" would read as a verdict. ADEF
surfaces the pair and leaves the call to you.

Which is the natural fit for an assistant session: `--similarity-mode agent`
hands you the shortlist with each candidate's query, fields, and shared values
to rank yourself, using context ADEF doesn't have — and makes no network call.

### See your coverage — honestly

Coverage reads straight from your ATT&CK tags, so enrich first, then measure:

```bash
adef detection tag-mitre D-0007 T1547.001    # enrich, validated against ATT&CK
adef coverage                                # coverage QUALITY report (shown above)
adef coverage --gaps                         # + uncovered technique IDs by tactic
adef coverage --navigator layer.json         # scored MITRE Navigator layer
```

Not a vanity heatmap: `coverage` separates **solid** techniques (multiple
reviewed detections) from **fragile** ones (a single rule, or nothing but
unreviewed inferences), flags techniques riding a single log source, and
calls out *fictional coverage* — mapped technique IDs that don't exist in
ATT&CK. Every mapping is validated against an ATT&CK snapshot — the one in
your workspace once you've run `adef attack refresh`, otherwise the copy
shipped with ADEF (`adef attack show T1059.001`).

### Decide tune-or-retire from numbers, not impressions

"Does this rule still earn its keep?" is the question teams answer worst,
because the honest answer needs numbers nobody writes down. ADEF has no vendor
connectors and will never have any — so **you hand it the counts**, in a small
self-describing document, and it does the arithmetic and the remembering:

```bash
adef ingest examples/weekly-metrics.yml --dry-run   # validate, write nothing
adef ingest examples/weekly-metrics.yml             # → health/latest/ + append-only health/history/
adef health show D-0009                    # read it back, with what ADEF derived
adef detection evolve D-0009 --chain       # → keep / tune / deprecate, journalled
```

(`--chain` re-runs the chain on a detection *already* at Evolve — stage
transitions are idempotent, so without it a fresh ingest is never read.)

```yaml
# examples/weekly-metrics.yml — counts, not ratios (shipped, runnable)
schema_version: 1
kind: metrics
captured_at: 2026-10-08T14:00:00Z
window: {start: 2026-10-01T00:00:00Z, end: 2026-10-08T00:00:00Z}
detections:
  - detection_id: D-0009
    signal_count: 238
    false_positive_count: 236
    true_positive_count: 0
    last_true_positive_at: 2026-06-08T12:00:00Z
```

`health show` prints the stored document back first, then the second half —
what ADEF computed from it, which is what the Evolve heuristics actually read:

```
derived for tuning
  days_since_true_positive: 122.1
  fp_ratio: 1
  weekly_signal_volume: 238
  window_days: 7

Run adef detection evolve D-0009 --chain to turn these into tuning and deprecation recommendations.
```

That derived block is also the `### Evolve / Health` journal entry the chain
writes before it decides anything — the numbers it reasoned from, dated, next
to the verdict they produced.

…and `evolve` turns that into a verdict, in the journal and on stdout:

```
Evolve chain complete — Health → Tuning → Deprecation appended.
  high narrow-filter — FP ratio 100% on 238 weekly signals — narrow filters or raise threshold.
  verdict: tune — FP ratio 100% on 238 weekly signals.
```

Note what it *didn't* say. A rule still throwing 238 signals a week isn't a
retirement candidate — it's mis-filtered. `deprecate` is reserved for the
detection that went silent — zero signals across a capture window of at least
seven days, and no true positive in 180+ days, unless a supplied
high-quality-finding count says otherwise — or one a stronger neighbor already
covers. Same numbers, two different calls, and the journal records which
one and why.

Five document kinds cover it: `metrics` (is it firing, and is it right),
`performance` (what it costs, and whether it errors), `deployment_drift` (does
the *deployed* rule still match the catalogued one), `source_health` (is the
telemetry even arriving), `field_observations` (did a field's values change
shape). Each file declares its own `kind` — `adef ingest` routes on content, so
there's no flag to get wrong.

**Three deliberate refusals, because a tuning decision is only as good as the
number under it:**

- **Counts, never ratios.** A ratio can't be re-aggregated — two weeks at "50%
  FP" average to nothing without each week's volume. You supply
  `false_positive_count: 236`; ADEF derives `fp_ratio` itself.
- **`fp_ratio`'s denominator is what was *adjudicated*** (FP + TP), never
  `signal_count` — an unlabeled signal is not a known false positive.
- **A derived value is omitted, never zeroed,** when its counts are absent. Both
  recommenders decide "insufficient data" on key *presence*, so a fabricated
  zero would read as a measured zero and get acted on.

`source_health` is small and load-bearing: a detection that went quiet because
its feed died is a telemetry incident, not a rule to retire. Check it before
deprecating anything. And if `evolve` says `insufficient-data`, that's not a
bug — it's ADEF declining to guess. `adef health show D-XXXX` names what's
missing; `adef doctor` answers it for the whole workspace in one line.

## Skills & MCP

ADEF ships the `adef-mcp` server, **nine task-specific skills**
(cataloging, coverage, authoring, schema setup, FORGE-stage work, health
capture, and more), and
the `profile-author` sub-agent. Which skill fronts which command:
[`docs/skills-reference.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/skills-reference.md).

Install the skills, then wire the MCP server:

```bash
adef install-skills       # copies skills into .claude/ (or .agents/ for Codex/ChatGPT)
pip install "agentic-detection-engineering-framework[mcp]"   # adef-mcp needs the extra (clone: pip install -e ".[mcp]")
adef-mcp                  # start the server; point your assistant's MCP config at it
```

`install-skills` prompts for the agent and project-vs-global on the first run;
commit the resulting `.claude/` (or `.agents/`) tree into your repo so your team
gets the skills too. With them in place, "help me set up schemas for my Splunk
environment" drives the whole recipe → reshape → ingest flow conversationally.
The MCP server is the portable layer — it works in any MCP client (Claude,
Cursor, Copilot, ChatGPT desktop).

**The division of labour is deliberate.** ADEF does the parts that must be
deterministic — walking a repo, validating a technique ID, computing coverage
tiers, checking fields against a declared schema. The agent does the parts that
need judgment and context ADEF doesn't have: *is this field the same fact as
that one?*, *does this intel report describe something we already cover?*, *is
this rule worth keeping?* Neither half is useful alone.

## Is ADEF for you?

**It's a fit if** you have more detections than you can hold in your head, rules
whose authors have moved on, a coverage story you can't defend with evidence, or
an AI assistant you'd like pointed at your detection estate with real structure
behind it.

**It's not** a SIEM, a rule repo, a detection-as-code pipeline, or a replacement
for any of them. It doesn't deploy rules, query your data, or modify your YAML.
It reads what you have and remembers what you learned.

**What you give up:** the catalog is a second place that knows about your rules,
so it has to be kept current (`adef sync`, or `--check` in CI). Schemas come
from an export you run, and health numbers from a document you hand over, so
both are as fresh as the last one — nothing here phones your SIEM on a
schedule. ADEF trades a little upkeep for institutional memory — [`docs/why-adef.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/why-adef.md)
is the full adoption guide, including where it fits in an existing program.

## ADEF and ATHF — paired siblings, not successor

The structural parallel is deliberate:

| | ATHF | ADEF |
|---|---|---|
| **Lifecycle** | LOCK (Learn → Observe → Check → Keep) | FORGE (Find → Observe → Refine → Govern → Evolve) |
| **Unit of work** | a hunt (`H-XXXX`) | a detection (`D-XXXX`) |
| **Answers** | "Is this active in our environment?" | "How do we codify this so it pages someone?" |

Both are built on the same Click + entry-point + FastMCP foundation, so analysts
and agents move between hunting and detection engineering without a learning
curve.

A hunt that found something graduates directly. ATHF's `gates` skill already did
the reasoning — N candidate detections, each with a verdict, the evidence behind
it, and the query where the verdict is deployable — and wrote it into a GATES
document. ADEF imports that document, so this is a parser, not a second opinion:

```bash
adef hunt-promote --gates ~/athf-workspace/hunt-promotion-analysis/H-0041_GATES.yaml
adef hunt-promote --gates H-0041_GATES.yaml --dry-run   # what would be imported
```

Deployable candidates (`PROMOTE` / `CONDITIONAL` / `TIME_BOX`) each land as a
catalog record with `origin: promoted` plus a journal carrying the hunt's
reasoning — and a `CONDITIONAL` or `TIME_BOX` arrives flagged
(`needs_review: gates_conditional` / `gates_time_box`) rather than as a clean
promote, because "deploy with a condition" and "deploy with an expiry" are only
meaningful if someone can find them again. Archival ones (`HOLD` / `DROP` / `RECURRING_HUNT`) are reported and
nothing is written — the decision not to promote is worth seeing, and ADEF
doesn't second-guess it. Re-import is idempotent on `hunt_ref` and preserves
your enrichment, so regenerating a GATES document updates rather than
duplicates. `adef sync` skips `origin: promoted` records: their provenance
points into the ATHF workspace, not a rule repo ADEF walks.

For a hunt that never went through GATES, `adef hunt-promote H-0042` drafts a
rule into a *staging* directory via a configured generator
(`ADEF_HUNT_RULE_GENERATOR` — ADEF takes no opinion on the upstream hunt
system). Full synopsis: [`docs/cli-reference.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/cli-reference.md#adef-hunt-promote).

## Where this takes you

| Level | Name | What you get |
|---|---|---|
| L0 | Ad-hoc | Rules in chat threads and tickets |
| L1 | Documented | Rules in a repo with metadata |
| L2 | Searchable | AI reads coverage, performance, overlap |
| L3 | Generative | AI proposes/drafts/backtests rules from intel or hunts |
| L4 | Agentic | Autonomous tuning, deprecation recommendations, scheduled gap sweeps |

Most teams land at L1 and stall there — the rules are in git, and nothing else
is. `adef catalog` plus `adef coverage` is L2 in an afternoon. See
[`docs/maturity-model.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/docs/maturity-model.md) for full descriptions and
time-to-value estimates.

## Contributing

Bug reports, feature requests, and detection contributions each have an issue
template — [open an issue](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/issues/new/choose).
Before opening a pull request, read
[`CONTRIBUTING.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/CONTRIBUTING.md):
it covers the dev setup, the test/lint gate, and the four anti-goals that are
CI-enforced (no writes to your rule repo, no new engine types, no vendor API
connectors, no web UI). To report a security issue privately, see
[`SECURITY.md`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/SECURITY.md).

## Credits

Built by the Detection Engineering & Threat Hunting (DE&TH) Team at [Nebulock, Inc.](https://nebulock.io):

- Eric Brown ([eric@nebulock.io](mailto:eric@nebulock.io))
- Joshua Hines ([josh@nebulock.io](mailto:josh@nebulock.io))
- Sydney Marrone ([sydney@nebulock.io](mailto:sydney@nebulock.io))
- Jarrett Polcari ([jarrett@nebulock.io](mailto:jarrett@nebulock.io))

## License

MIT — see [`LICENSE`](https://github.com/Nebulock-Inc/agentic-detection-engineering-framework/blob/main/LICENSE).
