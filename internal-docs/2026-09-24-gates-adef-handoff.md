# GATES → ADEF handoff

**Date:** 2026-09-24
**Branch:** `feat/adef-gates-handoff` (off `origin/dev`)
**Shortcut:** Epic 9324 (ADEFv2); relates to SC-9326. Composites (SC-9334, SC-9341) stay deferred.
**ATHF side:** PR #62, branch `feat/gates-validation-skill` @ `467d819`

## What this is

ATHF's GATES skill validates hunt findings and emits a per-hunt YAML describing N
candidate detections. ADEF's job is to consume that file: mint records for the
deployable ones, preserve the reasoning for the rest, and tell the user whether
each candidate is already covered.

The GATES skill is pure markdown — no code, nothing to install. "Running GATES"
means invoking the skill against a hunt file.

## Why `adef forge` doesn't exist and `hunt-promote` isn't a drop-in

PR #62 documents `adef forge --input <H-XXXX_GATES.yaml>` in five files. There is no
`forge` command. The PR review proposes pointing at `adef hunt-promote H-XXXX`
instead, but that command cannot complete the workflow either:

1. It lazy-imports a rule generator from `ADEF_HUNT_RULE_GENERATOR` and raises
   `HuntPromotionError` when unset (`adef/agents/hunt_promotion.py:88-112`). No
   package provides that binding, so the command errors out of the box.
2. It takes a *hunt ID* resolved against `ADEF_HUNT_ROOT`. It has no path to read a
   GATES YAML, which is the entire artifact.
3. It mints exactly one `D-XXXX` and writes **no catalog record** —
   journal + staging YAML only (`hunt_promotion.py:126`). GATES emits N detections
   per hunt (4 in their H-0062 example, 5 in our H-0041 run).

**The GATES document is the missing generator's output.** ATHF already did the
reasoning; ADEF parses a file. So no generator binding is needed for this path, and
`hunt-promote` gaining a file input mode is the smallest correct change — it keeps
the verb the ATHF docs already reference and replaces an inert code path rather
than adding a sixth command.

## Test fixture

`/tmp/athf-workspace/hunt-promotion-analysis/H-0041_GATES.yaml` — produced by running
the GATES rubric against hunt-vault `H-0041` (MCP server spawn chain; 2 TPs, 15
findings, 30-day window). Sanitized: employee names, customer orgs, hostnames and
live secrets replaced with `<REDACTED>`; adversary domains retained as the IOC
layer's payload.

Deliberately covers the whole verdict spread so the importer gets exercised:

| # | Verdict | Score | Engine | Why it's here |
|---|---------|-------|--------|---------------|
| 1 | PROMOTE | 5.0 | sigma | Clean 5/5. Keychain abuse discriminated by parent process. |
| 2 | PROMOTE | 4.0 | sql | PARTIALs on T and S — allowlist-bound. |
| 3 | CONDITIONAL | 3.5 | sql | Carries `baseline_required` + `baseline_query`. |
| 4 | TIME_BOX | 3.5 | sigma | IOC layer split from #2 per hybrid decomposition. |
| 5 | HOLD | 2.0 | — | No `deployment` block at all. RECURRING_HUNT in spirit. |

Note hunt-vault is a **test fixture only**. Per CLAUDE.md "Direction of Integration",
it must not shape the interface — the public GATES schema does that.

## Changes ADEF needs in the ATHF PR

**Status: implemented, uncommitted.** All of these are done directly on PR #62's own
branch — `feat/gates-validation-skill` in `../agentic-threat-hunting-framework` —
so they land as commits on the existing PR rather than a second one. Nine files
touched, all markdown/YAML; the skill has no code. See "What was changed in ATHF"
below.

The PR review already covers internal consistency (acronym drift, enum spelling,
example math, `detections_promoted` counting CONDITIONALs, undefined "BASE score").
Those are real but they're theirs. The list below is what blocks *ADEF's parser*
specifically, and is mostly not in that review.

Four more surfaced while implementing the fixes; they're numbered 9-12 below.

### Blocking

1. **Stable candidate identity.** `detection_id` is a hunt-local integer and the
   hybrid-decomposition rule introduces suffixed variants (`1a`, `1b`). Nothing
   guarantees it's stable when GATES is re-run on an edited hunt, and it demonstrably
   isn't positional either: `H-0062_EXAMPLE.yaml` emitted `2, 1, 4, 3` and
   `H-0061_EXAMPLE.yaml` had `detection_id: 3` **in a list of one**. ADEF mints a
   permanent `D-XXXX` per detection, so without a stable key, re-importing the same
   hunt silently mints duplicates. *(Worth stating plainly: GATES does **not** mint
   `D-XXXX` IDs — that was never the problem. The ordinal's instability is.)*
   **Fixed as:** `detection_id` → **`candidate_id`**, a hunt-scoped kebab-case slug
   derived from the behavior (`remote-package-installer-execution`). Four rules in the
   schema: derive from behavior not position; byte-identical across re-runs; change
   only when meaning changes; hybrid decomposition uses `-behavioral`/`-ioc` suffixes.
   ADEF's key is `hunt_ref = "<hunt_id>#<candidate_id>"`.
   The trade is explicit in the schema: a rename is a visible, deliberate edit a human
   can reconcile; an ordinal reshuffle is invisible and corrupts silently. Same
   philosophy as `reconcile.py` — a wrong identity merge is worse than a duplicate.

2. **Closed verdict enum, including RECURRING_HUNT.** Schema said
   `PROMOTE | CONDITIONAL | HOLD | TIME_BOX | DROP`. SKILL.md and the PR body add
   `RECURRING HUNT` and spell it `TIME-BOX`. Writing the H-0041 fixture, detection 5
   had no legal slot — it had to be encoded as `HOLD` plus a non-schema
   `classification: RECURRING_HUNT` field.
   **Fixed as:** a "Canonical enums" section listing four closed sets (verdict, gate
   result, deployment status, engine), with `RECURRING_HUNT` promoted to a first-class
   verdict — *"not a `HOLD` with an annotation."* `TIME-BOX`/`RECURRING HUNT` tokens
   normalized across every file.

3. **Scoring precedence.** Not a doc nit — it changes what ADEF writes. A 3.5 score
   lands in the CONDITIONAL band (mint with prerequisites) while a G-FAIL says TIME_BOX
   (mint with a 90-day expiry). Both conflicts occurred in a single real hunt.
   **Fixed as:** SKILL.md Step 4 is now the single authoritative verdict statement
   (the duplicate mapping under "BASE Scoring" points at it). Precedence: a gate FAIL
   names a specific defect and overrides the band — **A→DROP, E→HOLD+expand,
   S→RECURRING_HUNT, G→TIME_BOX, T→CONDITIONAL, no FAIL→score band**. Bands made
   contiguous (4.0–5.0 / 3.0–3.9 / 0.0–2.9) with a note that the no-FAIL floor is 2.5.
   Six worked examples; three of them are cases that were undecidable before the rule.

4. **Engine enum constrained to ADEF's four.** The field was unconstrained, and ADEF
   CI-enforces exactly `sigma | sql | sch_sql | composite`
   (`tests/test_no_new_engine_types.py`), so a fifth value is an import failure.
   **Fixed as:** closed enum in "Canonical enums", referencing ADEF's four.

5. **Guaranteed fields when the verdict is deployable.** In their own H-0062 example,
   candidate 4 had no `engine` and candidate 3 no `detection_logic` — both verdicts
   ADEF mints records for. Proven rather than argued: the pre-fix H-0062 fails ADEF's
   importer with exit 2 (*"no `deployment.engine`"*).
   **Fixed as:** a "Required fields" section — a deployable candidate
   (PROMOTE/CONDITIONAL/TIME_BOX) MUST carry `candidate_id`, `name`,
   `gates_assessment.verdict`, `deployment.engine`,
   `deployment.detection_logic.query`. Both examples rewritten to conform.

### Should fix

6. **`base_score` type.** `5/5` (string) in the schema, `4.25` (float) in examples.
   **Fixed as:** float everywhere (`5/5`→`5.0`, `3/5`→`3.5` — the latter was also an
   arithmetic error), with `# float, never "4.5/5"` in the output template.

7. **`detection_logic` was polymorphic.** Sigma used a bare `selection:`/`condition:`
   mapping; sql used `{query, description}`, so ADEF had to branch on engine.
   **Fixed as:** `{query, description}` for **every** engine; sigma bodies go inside
   `query` as a block scalar. ADEF still re-serializes the inline form for documents
   already on disk.

8. **Hunt-level vs candidate-level verdict.** The Smart Single-File Strategy routes
   `.yaml` vs `.md` on the *hunt* verdict, so a PROMOTE hunt's YAML legitimately
   carries TIME_BOX and HOLD candidates. The schema never said so.
   **Fixed as:** a table separating the two, closing with *"Consumers must handle
   every verdict inside a `.yaml`, not only the deployable ones."*

### Found while implementing (not in anyone's review)

9. **The schema and SKILL.md were two different schemas.** `gates_validation` is
   structurally different between them, and the hunt-level verdict is
   `aggregate_verdict` in the schema but `verdict` in SKILL.md and both examples —
   ADEF's parser reads a field the schema doesn't define.
   **Fixed as:** a top-matter section declaring *"this document is the contract"*;
   SKILL.md is *"an **instance** of this schema, not a second schema."* Field renamed
   to `verdict`, under an explicit `# --- REQUIRED ---` / `# --- OPTIONAL ---` split.

10. **`hunt_metadata.platforms` didn't exist in the schema**, though a catalog record
    requires a platform. Imports landed as `multi-platform` until it was added.
    **Fixed as:** added to the schema and to both examples (`platforms: [windows]`).

11. **Invented enum values in `examples/README.md`.** `PROMOTE_PENDING_VALIDATION`
    and `LIKELY_PASS` — the latter makes a stated score unverifiable, since a gate
    you *believe* will pass but haven't evidenced is `PARTIAL`.
    **Fixed as:** replaced with canonical tokens plus a note explaining each mapping.

12. **Two conflicting, non-contiguous score bands in SKILL.md** — covered by the
    Step 4 rewrite in #3.

Not fixed, lower priority: **prerequisites are expressible in four places** —
`gates_validation.prerequisites`, `gates_assessment.conditional_requirements`,
candidate-level `prerequisites`, and `operational_parameters.deployment_prerequisites`.
ADEF reads none of them yet, so it's a consolidation ask, not a blocker.

### Also done in ATHF while in there

**Sanitized apparent customer data out of a public open-source example.**
`H-0061_EXAMPLE.yaml` carried what read as a real tenant's SPN allowlist — a storage
hostname, an `ANFGEO*` SPN prefix, and a codename. Replaced with
`<managed-file-service-spn-prefix>*`, `<storage-account>.file.core.windows.net`,
`<legacy-app-spn>`. Flag this in the PR regardless of whether the contract asks land.

### What was changed in ATHF

On PR #62's branch `feat/gates-validation-skill` (base commit `467d819`), all under
`.claude/skills/gates/`:

| File | Change |
|------|--------|
| `AGENT_MEMORY_SCHEMA.md` | five new top-matter sections (contract precedence, hunt-vs-candidate verdicts, canonical enums, candidate identity, required fields); `aggregate_verdict`→`verdict`; `hunt_metadata.platforms`; float scores; uniform `detection_logic` |
| `SKILL.md` | Step 4 rewritten as the single verdict authority (precedence + contiguous bands + 6 examples); duplicate mapping removed; hybrid decomposition uses slugs; output template conforms |
| `examples/outputs/H-0062_EXAMPLE.yaml` | full rewrite — 4 slugged candidates, criteria summing exactly to their scores, public-knowledge ClickFix logic, `deployment_order` by slug |
| `examples/outputs/H-0061_EXAMPLE.yaml` | slug id, uniform `detection_logic`, `platforms`, **sanitized** |
| `examples/README.md` | canonical enums, slugs, complete criteria, composite `detection_logic.query` |
| `README.md` + 4 `.md` example outputs | verdict-token normalization only |

Verification: both rewritten examples import end-to-end through
`adef hunt-promote --gates` (dry-run and real); `adef detection show D-0004` confirms
`platform windows`, intact sigma query, `needs_review gates_conditional`,
`origin promoted`. The pre-fix H-0062 still fails with exit 2 — that's ask #5 as an
experiment rather than an argument.

## ADEF-side design

`adef hunt-promote --gates <path>` — new file input mode on the existing command.
The bare `H-XXXX` argument keeps working via the (still optional) generator plugin.

Per detection, routed on verdict:

| Verdict | ADEF action |
|---------|-------------|
| PROMOTE, CONDITIONAL, TIME_BOX | Mint `D-XXXX`, write catalog record + journal at Find stage |
| HOLD, DROP, RECURRING_HUNT | Reported as skipped. Nothing written — no ID, no record, no journal |

The archival row started out as "journal note only, mint nothing," and the test
suite killed that: a journal needs a `D-XXXX` to be named after, so "mint nothing"
and "write a journal" contradict each other. Worse, with no record there is no
`hunt_ref` to match on, so every re-import minted the rejected candidate again
(`test_reimport_updates_instead_of_duplicating` caught it: `D-0003` then `D-0004`).
Archival candidates now consume nothing. The reasoning isn't lost — it lives in the
GATES document, which every promoted sibling record points at via `rule_ref`.
If rejected candidates ever need to be searchable, that's a coverage-gaps store,
not a per-candidate journal.

Everything imported lands on the **enrichment** side of sync, so a later
`adef sync` never clobbers it.

`origin` gets a third value: `authored | catalogued | promoted`. Promoted records
have no upstream repo, so — like `authored` — `sync` must skip them.

### Field mapping

| GATES | ADEF `CatalogRecord` |
|-------|----------------------|
| `deployment.engine` | `engine` |
| `deployment.detection_logic.query` | `query` |
| `deployment.mitre_attack` | `mitre` |
| `deployment.status` (`EXPERIMENTAL`/`ACTIVE`/`INACTIVE`) | `status` (needs a mapping; ADEF owns it) |
| `name` | `title` |
| `detection_logic.description` | `description` *(SC-9326)* |
| `deployment.entities` | `entities` *(SC-9326)* |
| `deployment.alert_configuration.throttle` | `alert.throttle` *(SC-9326)* |
| `deployment.severity` | `alert.severity` *(SC-9326)* |
| `deployment.references` | `references` *(SC-9326)* |
| `operational_parameters.{expected_volume,fp_rate}` | health store via `adef ingest` (PR #4) |

**This independently validates the SC-9326 field cut.** Every field in that story is
required to represent a GATES detection without data loss. The justification is now
"the public ATHF handoff contract needs them," not any private schema — which is
what CLAUDE.md's Direction of Integration rule asks for.

### The A-gate is where ADEF's similarity work plugs in

SKILL.md Step 2 says: *"If detection repository IS accessible (ATHF/ADEF integrated),
automatically check for overlaps"* — otherwise it prompts the human. That is exactly
`rule_similarity.py` + `rule_overlap.py` (PR #1/#5). The `agent` similarity mode added
in PR #5 returns an unranked shortlist with full queries, which is the right shape for
scoring "does this fill a coverage gap?"

So the coverage-check half of the handoff is *already built* — it needs wiring, not
inventing.

## What shipped (branch `feat/adef-gates-handoff`, uncommitted)

| File | Change |
|------|--------|
| `adef/core/gates.py` | new — parser (`parse_gates`) + importer (`import_gates`). Engine allowlist, verdict normalization (`TIME-BOX`→`TIME_BOX`), `"5/5"`→float, sigma-inline-vs-sql `detection_logic`, `hunt_ref` idempotency. Reads `candidate_id` with `detection_id` as fallback; `_candidate_verdict` recovers `RECURRING_HUNT` from the legacy `HOLD` + `classification` pair |
| `adef/core/catalog.py` | `CatalogRecord` + 6 enrichment fields (`description`, `alert`, `entities`, `observables`, `references`, `hunt_ref`), omitted from YAML when empty |
| `adef/commands/hunt_promote.py` | `--gates` / `--dry-run`; `hunt_id` now optional |
| `adef/core/reconcile.py` | orphan exemption extended to `origin: promoted` |
| `adef/commands/detection.py` | `--origin` accepts `promoted` |
| `tests/test_gates_import.py` | new — 11 tests, two fixtures: `CANONICAL_DOC` (the fixed contract) and `DOC` (every pre-contract hazard, so the back-compat paths can't rot silently) |

**Bug found and fixed in ADEF's own code: `--dry-run` didn't validate.** The dry-run
branch returned before `record_from_gates` ran, so engine validation never executed —
`--dry-run` exited 0 on the pre-fix H-0062 while the real run exited 2. A dry run that
can't predict failure is worse than none. Now it builds each record and discards it;
`test_dry_run_catches_what_the_real_run_would_reject` pins it.

Verified: **558 passed / 2 skipped**, `mypy` clean (65 files), `ruff` clean.
End-to-end against the H-0041 fixture (`--dry-run` and real): `D-0001`..`D-0004`
minted + 1 skipped; `D-0001` round-trips all six enrichment fields including
`hunt_ref: H-0041#1` and `origin: promoted`.

## PR #62 feedback pass (2026-09-24 → 09-25)

Sydney's review plus 15 CodeRabbit inline items, all addressed on
`feat/gates-validation-skill` (still uncommitted). 14 files, ~780 insertions.
Most of it was reconciling three layers that had drifted: `SKILL.md`'s prose rules,
`AGENT_MEMORY_SCHEMA.md`'s contract, and the seven worked examples.

**Two of the findings turned out to be rule defects, not typos.** Recomputing the
examples' arithmetic is what surfaced them:

1. **Verdict precedence was in the wrong order.** It read `A → E → S → G → T`, which
   sent H-0065 (G, E and S all FAIL, stated TIME_BOX) to HOLD — and would have sent
   *every* IOC watchlist there, making TIME_BOX unreachable. Reordered to
   `A(1) → G(2) → E(3) → S(4) → T(5) → no-FAIL band(6)`. A `G` FAIL describes the
   candidate's *kind* (IOC/campaign rule), which is single-dimensional and
   short-lived by construction, so it almost always trips `E` and `S` too — one fact
   reported three times, with TIME_BOX already the mitigation for all three. `A` still
   outranks `G`.
2. **HOLD was unreachable at zero prevalence.** H-0060 (0 TPs) couldn't derive its
   stated HOLD: `E` was PASS and the no-FAIL floor is 2.5. Added **row 4b** — `S = FAIL`
   *and* the hunt found zero instances → HOLD, not RECURRING_HUNT. Row 4 trades coverage
   for cadence, which only helps if there is something to find. Rather than mislabel the
   example or silently re-verdict Sydney's work, the rule got the new row and the
   rationale in writing.

Contract fixes worth remembering:

- **`verdict_breakdown` is the sole home for per-verdict counts.** `detections_promoted`
  / `detections_conditional` were a duplicate tally with no tie-break rule, and were
  already wrong in an example: H-0061 counted its single *CONDITIONAL* candidate as
  `detections_promoted: 1`, telling a consumer a detection was deploy-ready when none
  was. Removed.
- **`base_score_average` is derived and informational only; nothing may be verdicted
  from it.** A hunt with one 5.0 and one 0.0 candidate averages 2.5, which describes
  neither candidate.
- **No `UNKNOWN` gate result.** It has no point value, so scoring it silently drops the
  total. Unevidenced → `PARTIAL`. Three examples' scores didn't derive from their gates
  (H-0060, H-0064 stated `2/5`; H-0066's hypothetical had no score at all) — all
  recomputed and annotated with the per-gate arithmetic.
- Scores are floats `0.0–5.0`, never `"X.X/5"`.

**Public-clearance sweep** (the repo is public): removed an internal ClickHouse table
name (the internal prefix stripped, leaving `unified_events`), campaign/actor
designators, a
service-account naming convention, and rounded verbatim production volumetrics to
order-of-magnitude. The most serious was H-0066 — a risk assessment's output is a
named organization's *unremediated* weaknesses, which is more sensitive than a
detection rule; de-identified to publish the shape of the finding, never the
environment that has it. Defanged IOC placeholders now carry a warning that a
watchlist deployed with `[.]` intact silently never fires.

**Verified after the ATHF rewrite** (the YAML shape changed, so the importer had to be
re-checked against it): 558 passed / 2 skipped, `ruff` clean, `mypy` clean (65 files).
End-to-end `adef hunt-promote --gates` against both rewritten examples — H-0062 →
`D-0001`..`D-0004` (3 PROMOTE + 1 CONDITIONAL), H-0061 → `D-0005`. Re-importing H-0062
reports all four as `updated`, confirming `(hunt_id, candidate_id)` idempotency survives
the slug change from ordinals.

**Needs the PR author, not a repo edit:** PR #62's *body* expands the acronym as
"Accuracy / Telemetry / Executability". Those are not GATES gates — BASE is
Generalizable / Additive / Tunable / Exposure-tested / Sustainable. Only they can edit it.

Not fixed, lower priority: prerequisites are expressible in four places
(`gates_validation.prerequisites`, `gates_assessment.conditional_requirements`,
candidate-level `prerequisites`, `operational_parameters.deployment_prerequisites`).

## Full-PR review + flow testing (2026-09-25)

Reviewed the ~60% of PR #62 not covered by the size cut, then exercised
ATHF → ADEF against synthetic hunts. Two classes of finding.

### One rule defect, and it unified two rules I had wrongly split

`SKILL.md` Step 2 carried a "G-gate Fast-Path (IOC + Zero TPs) → HOLD, skip
remaining gates" block that contradicted Step 4 row 2 (`G` FAIL → `TIME_BOX`)
and contradicted the `fast_path_hold` comment I had written in
`AGENT_MEMORY_SCHEMA.md`. My first instinct was to delete the fast-path as an
"optimization that returns a different answer than the authoritative rule."

That was wrong. Both rules were correct and I had missed the principle joining
them. Rows 2 (`TIME_BOX`) and 4 (`RECURRING_HUNT`) both mean *carry this rule
anyway, on a cycle*, and neither is worth the maintenance at **zero
prevalence** — a watchlist for a campaign that has never been here, and a
quarterly re-run of a query that matches nothing, are the same mistake. So:

> **Zero prevalence downgrades a deploy-anyway verdict to `HOLD`.** Applies to
> rows 2 and 4 only. It does **not** apply when no gate FAILed — 0 TPs over a
> clean baseline is a proactive `PROMOTE`.

That last clause is what makes it non-trivial: `H-0062_EXAMPLE.yaml` has 0 TPs
and PROMOTEs four candidates, so a blanket "zero prevalence → HOLD" would have
broken the reference example. Verified against all five worked examples.

Row 4b is now gone, replaced by this rule. Propagated to `SKILL.md`,
`examples/README.md`, `AGENT_MEMORY_SCHEMA.md`'s `fast_path_hold`, and
`templates/HUNT_LOCK.md`. `H-0065` (IOC, campaign present → `TIME_BOX`) and
`H-0060` (zero prevalence → `HOLD`) are now cross-referenced as the two sides.

### Defects the review found in the regions not yet read

Almost all are one pattern: **a verdict asserted somewhere other than Step 4**,
which is what the earlier de-duplication pass was supposed to have ended.

- `Missing data → PARTIAL scores or CONDITIONAL verdict` directly contradicted
  the band: five PARTIALs is 2.5, which is `HOLD`. Now states that PARTIALs do
  not accumulate into `CONDITIONAL`.
- `🎯 PROACTIVE BOOST: → +0.5 confidence` invented a sixth scoring token. A
  clean baseline lifts **T from PARTIAL to PASS**; there is no bonus to add.
- `score 5 BASE criteria (✅ PASS / ❌ FAIL)` omitted PARTIAL — a third of the
  model, defined 35 lines below it.
- BASE `A`'s row included "Actionable: single alert = clear action", which is
  the **ADVANCED** tier's `A`. Exactly the acronym confusion Sydney flagged,
  surviving inside the BASE table.
- `Baseline-required → RECURRING_HUNT` in the quick-reference table: a missing
  baseline is a `T` FAIL (row 5, `CONDITIONAL`), not an `S` one.
- Four places assigned `RECURRING_HUNT` during candidate *extraction*, before
  scoring. **I initially over-corrected these** to "route it, don't score it" —
  which bypasses the `S` gate's automation check, the gate purpose-built for
  multi-step investigations, and would emit a candidate with no `base_score`.
  Reverted to: it *is* scored, `S` FAILs the automation check, Step 4 returns
  `RECURRING_HUNT`.
- Verdict-position `NON-GATES` → a classification. Step 0.6's Question 3 had no
  stated consequence while 1 and 2 did (it's a `T` FAIL → `CONDITIONAL`).
- `ATHF/ADEF Integration` was 8 lines that never named `adef hunt-promote
  --gates` — the skill produced the handoff file without saying what reads it.

`SKILL.md` is 803 lines (from 1480; base was 1365).

### The `n/43` corpus statistics are pre-existing, not this PR's

Nine private-corpus figures — `frequency: "~5% of hunts (2/43)"`, `H-0041:
1,487/day, 2 TPs = 0.004% TP rate`, `H-0051: Build systems (31,872 FPs, 70x
baseline)`, `0 TPs across 16 orgs` — are **already merged on `main`**, confirmed
with `git show 467d819:`. Not introduced here.

So this is **not this PR's defect to fix**, and scrubbing `AGENT_MEMORY_SCHEMA.md`'s
pre-existing pattern library would be unrequested scope creep on someone else's
corpus-clearance call. The ones inside sections this PR rewrote are gone as a side
effect. **Raise the rest with Sydney separately** — they are verbatim production
measurements in a public repo, and only she can say what's cleared.

### ATHF → ADEF flow tested against synthetic hunts

`/tmp/gb/` (throwaway). Shapes exercised beyond the H-0041 fixture:

| Shape | Result |
|---|---|
| All-archival hunt (HOLD + DROP + `recurring hunt`) | all 3 skipped, nothing written, verdict spellings normalized |
| Four engines in one hunt (`sql`, `sch_sql`, `composite`, `sigma`) | D-0001..D-0004 minted, all four engines round-trip |
| Mixed verdicts in a `PROMOTE` hunt's `.yaml` | `TIME_BOX` + `CONDITIONAL` minted alongside `PROMOTE`, flagged for review |
| Legacy inline sigma body (no `query` key) | re-serialized into `query` as designed |
| `"5/5"` string score | coerced to `5.0` |
| Re-import the same document | all 4 `updated`, no duplicate IDs — `hunt_ref` idempotency holds |
| `adef sync` over an unrelated repo | `orphaned 0` — `origin: promoted` skipped correctly |
| Engine outside the four / no engine / no `candidate_id` / no `hunt_id` / broken YAML | clean `GatesError` each, no traceback |
| No MITRE anywhere | minted + `needs_review: no_mitre` |
| `--needs-review gates_time_box`, `--engine composite`, `--origin promoted` | all filter correctly |

**Two real ADEF defects found and fixed:**

1. **Stale contract in my own docstrings.** The module docstring and
   `import_gates`'s both claimed archival candidates "get a journal only". They
   get *nothing* — and the implementation is right: with no record there is no
   `hunt_ref`, so a journal would be re-appended on every re-import. Docstrings
   corrected to match, keeping the reasoning.
2. **A `.md` GATES narrative — the likeliest wrong input — failed inside the YAML
   scanner** (`while scanning an alias ... line 2, column 1`) instead of saying
   why. Added a suffix guard that names the reason. The `hunt_id` error already
   anticipated this case but was never reached.

Both have regression tests in `tests/test_gates_import.py`. 560 pass, ruff and
mypy clean.

### Also: `origin: promoted` was undocumented

The code wires it fully (`catalog.py`, `reconcile.py` skip list, `--origin`
choices) but four docs described `origin` as `authored | catalogued` only —
including `CLAUDE.md`, which is what future sessions read. Updated `CLAUDE.md`,
`docs/cli-reference.md`, `docs/detection-home.md`.

## Real-hunt end-to-end run (2026-09-25)

The earlier flow testing was **synthetic** — I wrote both the fixtures and the
parser, so it tested my model of the contract against itself. This pass scored two
**real completed hunts** with the skill by hand and imported the results, which is
what found the two defects below. Nothing from this run is committed: the GATES
documents and the minted workspace live in `/tmp/gates-real/` and contain customer
telemetry detail, so they stay there permanently.

### Hunts used and why

| Hunt | Real outcome | Shape it exercises |
|------|--------------|--------------------|
| H-0062 ClickFix paste-delivered execution | 0 TP / 5 FP, 9,330 hosts | Hunt-level `PROMOTE` → `.yaml`; 4 candidates, 3 PROMOTE + 1 CONDITIONAL; the **no-FAIL carve-out** (0 TPs over a clean baseline is a proactive PROMOTE, not a HOLD) |
| H-0032 Huntress fake tech support | 0 TP / 0 FP, 11M events | One hunt covering **three branches at once**: `G` FAIL + zero prevalence → HOLD (the downgrade), no-FAIL at 0 TPs → PROMOTE (the carve-out), `S` FAIL at 9,094 benign events → RECURRING_HUNT (no downgrade, behavior present) |
| H-0051 build-system manipulation | 0 TP / 32,616 FP | Hunt-level non-PROMOTE → `.md`, which ADEF must refuse legibly |

H-0032 is the important one: it is a real hunt where the zero-prevalence rule and
its carve-out both fire, which is the strongest evidence available that the
unification in SKILL.md Step 4 is right rather than merely tidy. It is also the
hunt the deleted fast-path statistic used to cite.

### Defect 1 — `deployment_prerequisites` were dropped on the floor

A CONDITIONAL candidate landed flagged `needs_review: gates_conditional` with **no
statement anywhere in ADEF of what the prerequisite was**. The engineer had to
reopen the ATHF document to find out, which defeats the point of a review queue.
`grep prerequisite adef/core/gates.py` returned nothing.

Fixed in `journal_note` — prerequisites now render as `Prerequisite: <text>` lines.
Pinned by `test_deployment_prerequisites_reach_the_journal`.

Two contract facts worth recording, because I got both wrong first:

* The per-candidate channel is **`deployment.operational_parameters.deployment_prerequisites`**
  (a plain string list), not `deployment.deployment_prerequisites`.
* Hunt-level `prerequisites` uses `type` / `requirement` / `blocker` / `effort` and
  has **no `candidate_id`** — it is hunt-wide. My first GATES document invented a
  `candidate_id` key there. Deliberately *not* wired into ADEF: with no candidate
  key, attaching it would duplicate the same text across every journal in the hunt.

### Defect 2 — `Verification: passed: True` when nothing was checked

The refine chain's Verification step reported a clean pass on every promoted
detection. `run_schema_check` exposes `rules_skipped_unmatched` and the agent was
ignoring it, so a rule whose literals match no declared schema — **the normal state
of a freshly imported hunt detection** — reported `passed: True, missing_schema_fields: []`,
which reads as "every field verified" when no field was examined.

Added `schema_matched` to `VerificationAgent.run()`'s result. `passed` semantics are
unchanged (it correctly reflects only authoring defects, and the engine check *did*
run); the new flag is what separates "verified" from "not checked". Pinned by
`test_undeclared_source_passes_but_reports_nothing_was_matched`.

### What the run confirmed works

Full FORGE lifecycle on a promoted detection (`observe` → `refine` → `govern` →
`evolve`); archival candidates skipped inside a `PROMOTE` `.yaml` with real data;
re-import idempotent on `hunt_ref` (4 journals stayed 4, notes appended, no
duplicate records); `sync` against an empty repo reported **0 orphaned** rather than
orphaning the promoted records; `coverage` resolved real tactics and flagged the
single-log-source risk; `detection list --needs-review gates_conditional` surfaced
exactly the one CONDITIONAL; `--origin promoted` and `--tactic execution` both
resolved; BM25 `search` and the refine chain produced substantively *correct*
output, not just non-crashing output — RuleSimilarity ranked the WebDAV candidate
top for the RunMRU candidate, which is right, because the RunMRU lens includes the
WebDAV tokens by construction. All four failure modes (`.md`, broken YAML, missing
file, valid) exit consistently (2 / 2 / 2 / 0).

### Caveat on the scoring itself

I scored these hunts, so the *verdicts* are one reader's application of the skill,
not ground truth. What this run validates is the **plumbing and the rules as
written** — that a document conforming to `AGENT_MEMORY_SCHEMA.md` built from real
hunt evidence survives the whole flow, and that the rules produce a defensible call
on real inputs. Two judgment calls a second reader could reasonably flip: H-0032's
`epoch-named-scheduled-task` `E` gate (PARTIAL vs FAIL — the bypass is one
character) and H-0062's `paste-delivered-payload` `S` gate.

## How much of the hunt corpus is GATES-ready (2026-09-25)

An operational measurement of the private hunt program, kept here only as the
**denominator for the handoff** — how much existing material GATES would have to
chew on. Per CLAUDE.md's design-inputs rule this must *not* reshape the ADEF or
GATES interface: it is an input to planning, not to design. Aggregates only; the
classifier and per-hunt results stay in `/tmp`.

Grep is not a usable method here: the template heading `Detection Logic` matches
16 hunts with nothing under it, and `GATES Verdict` matches **zero** — no real
GATES document has ever been produced. There is also no structured field to count:
`detection_rules_generated` exists in **3 of 49** hunts. So this is a content
classifier over four tiers, validated against four hand-verified hunts.

| tier | meaning | all | completed |
|---|---|---|---|
| RULE | concrete rule text present | 10% | 12% |
| NAMED | candidates named in prose/table, no rule text | 26% | 31% |
| INTENT | only a follow-up action | 40% | 43% |
| NONE | nothing | 22% | 12% |

**GATES-ready (RULE+NAMED): 36% of all hunts, 43% of completed.** Some detection
intent: 76% / 88%.

Two things this says about the handoff:

* The common case is **NAMED, not RULE** — a candidate named but not written. That
  matches the run above, where the last-mile authoring was mine. GATES validates;
  something still has to author. Worth knowing before promising an unattended path.
* Most `NONE` hunts are `NONE` *correctly* — they map a detection **boundary**
  ("EDR cannot see this") rather than proposing a candidate. A negative hunt with
  no candidates is a complete hunt, not an incomplete one. Do not treat this
  percentage as a backlog.

Known classifier limit: a prose recommendation with no imperative verb
("this pattern *should be* a detection rule candidate") sits on the INTENT
boundary and moved the count by one when the verb list changed. Treat every
figure as ±1 tier at the margin.

## Pushed to PR #62 for coworker testing (2026-09-25)

Two commits on `feat/gates-validation-skill`, `467d819..28a6fef`:

* `8182901` — SKILL.md tightening (net **-513 lines** across the 14 files) plus four
  defects found by running the skill against real hunts: the phantom `Query Plan`
  heading, the unfollowable H-0064 quickstart, the `T` clean-baseline lift capped to a
  ≥30-day window, and that cap propagated to the two places it is restated.
* `28a6fef` — CodeRabbit pass: 5 of 10 findings fixed, 5 rejected with reasons recorded
  in the commit message. The rejections matter as precedent: the WebDAV backslash
  "fix" was wrong because it accounted for YAML quoting but not Sigma's own escaping
  layer on top, and the `organization_id` scoping suggestion was declined under the
  CLAUDE.md design-inputs rule (a public skill must not be fitted to one deployment's
  tenancy model; cross-org baselining is the evidence GATES scores).

Verification that is now a reusable check, not a one-off: a ~20-line script over
`examples/outputs/*.yaml` asserting every `base_score` equals the exact sum of its
criteria and every verdict matches Step 4 precedence. It caught nothing after the
reduction but found the `detection_patterns` 5/5/3-vs-5.0/5.0/3.5 drift that CodeRabbit
missed. **Worth committing into the ATHF repo as a real test** — it is the only
mechanical guard on a contract the docs assert in prose.

### Two things block the coworker test end to end

1. **`adef hunt-promote --gates` exists in no pushed ADEF.** `adef/core/gates.py` is
   untracked on `feat/adef-gates-handoff` and absent from ADEF `main`. Coworkers can run
   `/gates` and get a document; they cannot import it. The ADEF PR is the critical path
   for the handoff half of the test — until it lands, testing covers GATES only.
2. **Three example outputs still name hunts that don't reconcile** (H-0064 doesn't
   exist; H-0065 is `planning` with 0 findings; H-0066 is Okta, not cameras). A coworker
   who opens an example and greps for the hunt finds nothing. Still awaiting the
   relabel-all-six vs fix-the-three call.

### Open design gap found during triage

A hunt whose **hunt-level** verdict is `TIME_BOX` emits `.md`, which
`hunt-promote --gates` rejects by design — but ADEF treats `TIME_BOX` as *deployable*
(`test_import_mints_only_deployable_verdicts` mints a record and flags `gates_time_box`).
So a hunt whose candidates are all `TIME_BOX` produces deployable IOC rules that can
never reach ADEF. Same bug class as the H-0064 quickstart: a documented path nobody
executed. Needs a decision — either `TIME_BOX` hunts emit `.yaml`, or ADEF stops
treating it as deployable. Not patched; CodeRabbit surfaced it from a wrong premise
(it read the hunt-level table as candidate-level).

`/code-review` (step 1 of `.claude/rules/pre-pr-review.md`) was **not** run before this
push — it spawns parallel agents and this session carries a standing instruction not to
use the Agent tool unless asked. CodeRabbit (step 2) ran clean. Flagged to the user.

## Blind test: Step 1.5 on H-0055, scored against shipped rules (2026-09-25)

The open test from the section below, run. **Design:** H-0055 chosen because 7 rules
were shipped from it, giving ground truth that isn't my judgment. Candidates were
extracted from the hunt document following SKILL.md Step 1/1.5, **frozen to
`/tmp/gates-real/H-0055_extraction_prediction.md` before looking at detect-vault**, then
compared. (The `gates` skill isn't installed in this session, so the procedure was
followed by hand from SKILL.md — a real weakness of the test, noted below.)

H-0055: 1,379 lines, `completed`, 14 queries, 0 TP / 7 FP / 2 patterns. KEEP *names* 9
intended detections with filenames and source query numbers but leaves `### Detection
Logic` empty — so the route is "named candidates, logic extracted from CHECK queries".

**Predicted 13 candidates.** 9 the hunt names, plus 4 macOS ones the hunt's own
deployment list omits, picked up by Step 1.5's "query patterns that returned results".

**Shipped: 7 files = 5 distinct rules** (two are dual-published as both `sigma` and
`atomic-sql`).

| shipped rule | predicted? |
|---|---|
| `edr-macos-impacket-kerberos-tool-execution` | ✅ #10 |
| `edr-macos-kerberos-ticket-file-access` | ✅ #11 |
| `edr-macos-kerberos-pass-the-ticket` | ✅ #13 |
| `edr-win-kerberos-credential-theft-attack-chain` (composite) | ✅ #6 (Query 7) |
| `edr-win-generic-hacktool-process` | ⚠️ #1+#2+#3+#4 **merged** |

**Recall 5/5 — nothing that shipped was missed.** And the five candidates predicted as
`RECURRING_HUNT`/`CONDITIONAL` (the behavioral SQL set + keychain dumping) shipped
nothing, which is the correct outcome.

**Step 1.5 earned its place.** All three macOS rules that shipped were ones the hunt's
own `Follow-up Actions` list left out. Reading KEEP's checkboxes alone would have missed
3 of 5 real detections. That is the strongest evidence yet that the extraction step adds
value over scoring what KEEP happens to name.

### Three real defects the test exposed

1. **Granularity — the worst one.** The hunt planned four separate Sigma files
   (`kerberos-golden-ticket-forgery`, `-silver-`, `-asrep-roasting`,
   `-pass-the-ticket`). Reality merged all four into **one** rule matching on
   command-line argument patterns. I reproduced the hunt's plan faithfully and was
   wrong 4→1. **Fidelity to the hunt is not correctness.** The only gate that catches
   this is `A` (Additive) — precedence row 1 is explicitly "DROP *or merge into the
   existing detection*" — and `A` is the one gate that cannot be scored from the hunt.
   This makes wiring `A` to `rule_similarity` a correctness requirement, not a nicety.

2. **The clean-baseline→T PASS rule produced an over-confident verdict.** I scored the
   tool candidates 5.0/PROMOTE, leaning on SKILL.md's *"0 suspicious over a large sample
   … lifts T from PARTIAL to PASS"*. The shipped rule's own notes say: *"The H-0055
   zero-baseline finding (2M process events / 28 EDR orgs / 7 days) did NOT hold in
   production: a 2026-08-04 review found 187 signals in 30 days, all false [positives]."*
   ~6 FP/day against a predicted zero. A 7-day hunt baseline is not evidence that `T` is
   satisfied, and the skill currently treats it as if it were. Worth a caveat in the
   `T` row: the lift should be capped at PARTIAL→PASS only with a 30-day window, or
   flagged as soak-contingent.

3. **Dual publishing isn't modelled.** Two of the five rules ship as *both* `sigma` and
   `atomic-sql` for the same logic. GATES emits one candidate per detection and ADEF
   mints one `D-XXXX` per `hunt_ref`, so one candidate → two artifacts has no
   representation. Not urgent (it's a detect-vault convention, and per the design-inputs
   rule a private dialect must not shape the interface) — but note it before anyone
   assumes candidate:rule is 1:1.

Minor: Query 7 was predicted as behavioral SQL → `RECURRING_HUNT`; it shipped as a
`composite`. Right candidate, wrong engine and verdict.

### What the test does and does not establish

Establishes: the skill's Step 1 addressing works on a real unmodified hunt; Step 1.5
extracts a superset of what actually shipped with no misses; its verdict logic correctly
separates deploy-now from defer.

Does **not** establish: that the skill does this unaided. I followed the procedure by
hand, and I already knew this hunt's domain. Re-run once the skill is installed, ideally
on a hunt whose shipped rules haven't been read. **The granularity defect would not have
been caught by any test I designed** — it took external ground truth. That is the
lesson to carry: score GATES against shipped rules, not against a reading of the hunt.

## Does GATES actually fit what ATHF generates? (2026-09-25)

The question the examples problem raises but doesn't answer. Tested by checking whether
the sections GATES Step 1 addresses exist in (a) `templates/HUNT_LOCK.md` — the contract
— and (b) the real corpus.

**Structural fit: good.** All four LOCK headings GATES names are byte-exact matches for
the template, and present in **46–49 of 49** real hunts:

| GATES expects | in template | in real hunts |
|---|---|---|
| `## LEARN: Prepare the Hunt` | ✅ L30 | 49/49 |
| `## OBSERVE: Expected Behaviors` | ✅ L62 | 46/49 |
| `## CHECK: Execute & Analyze` | ✅ L82 | 46/49 |
| `## KEEP: Findings & Response` | ✅ L130 | 46/49 |

Sub-sections likewise: `What Suspicious Looks Like` (L68), `Expected Observables` (L72),
`Findings` (L136), `Detection Logic` (L146), `Lessons Learned` (L169), `Follow-up
Actions` (L180) all exist. **One stale reference:** Step 1 names *"Query Plan (approved
queries)"* under CHECK — that section is in neither the template nor any hunt (0/49).
The template calls it `### Hunting Queries` / `#### Initial Query` / `#### Refined
Query`. Cheap fix, but it shows Step 1's input list wasn't written against the template.

**Substantive fit: about two-thirds.** What Step 1.5 and the T/S gates actually need:

| input | present | feeds |
|---|---|---|
| `What Suspicious Looks Like` — Step 1.5's primary candidate seed | **43/49** | G, candidate derivation |
| result counts **and** a lookback window | **34/49** | T, S (volume thresholds) |
| TP/FP counts in frontmatter | ~41/49 | T |
| `Detection Logic` filled in | **8/49** | direct scoring (Step 2, skip 1.5) |

So the common path is the Step 1.5 path, and its seed material is there in 43/49 hunts.
The binding constraint is the **34/49 with counts + window** — without those, `T` and `S`
both fall to PARTIAL, capping a candidate at 4.0 and pushing borderline ones into
CONDITIONAL for want of evidence rather than for a real prerequisite.

**Conclusion:** the skill is not mismatched to ATHF's output. It reads the right
sections and they're there. What is unproven is that the skill *as written* can do
Step 1.5 unaided — the one real-hunt run we have is the H-0062/H-0032/H-0051 pass, and
I was the extractor in it. That remains the open test: run `/gates` on a completed hunt
nobody has hand-prepared and compare against a hand-derived candidate list.

## PR #62 blocker: 3 of 6 shipped examples don't reconcile with the real hunts (2026-09-25)

The skill ships six worked examples named after real hunt IDs. Checked each against
hunt-vault:

| example | verdict shown | real hunt | reconciles? |
|---|---|---|---|
| `H-0060_EXAMPLE.md` | HOLD | EDGECUTION Chromium, T1176.001, completed | ✅ topic + technique match |
| `H-0061_EXAMPLE.yaml` | CONDITIONAL | Zeek cleartext creds; T1558.003 is angles 3–4 | ✅ real candidate from it |
| `H-0062_EXAMPLE.yaml` | PROMOTE | Windows ClickFix paste-delivered, completed | ✅ |
| `H-0064_EXAMPLE.md` | RECURRING_HUNT — "EC2 Encryption Disable" | **no H-0064 exists**; gap in the sequence | ❌ |
| `H-0065_EXAMPLE.md` | TIME_BOX — "ClickFix C2 domains" | real H-0065 is **`status: planning`**, 0 findings, 31 unfilled placeholders, no domain list | ❌ **contradicts Step 0.5** |
| `H-0066_EXAMPLE.md` | non-GATES — "IP Camera/NVR/VMS assessment" | real H-0066 is **Okta session/token compromise, T1539** — a detection hunt. No camera hunt exists anywhere in hunt-vault | ❌ |

**H-0065 is the sharp one.** `SKILL.md` Step 0.5 says a `planning` hunt must be refused
with *"Hunt not ready for GATES validation"* and routed to a planning assessment. The
real H-0065 is `planning`. So the shipped example shows a full TIME_BOX verdict for a
hunt the skill's own gate would reject. Two parts of the same PR give opposite guidance
on whether a planning hunt is scoreable.

**H-0064 is the most visible.** It's the README's primary quickstart example — `/gates
--hunt H-0064` appears twice, plus `H-0064_GATES.yaml` in the output walkthrough and in
`SKILL.md:793`'s ADEF handoff command. Five citations of a nonexistent hunt. (It was
real once: detect-vault has 5 rules citing it. The document is gone from hunt-vault.)

**What this implies about the examples' status:** they are
*specification-by-example*, not captured output. If they had been produced by running
the skill, they would match the hunts. So the skill has never been validated end to end
against its own examples — which is the same gap the real-hunt run on H-0062/H-0032/
H-0051 was closing, and is why that run found defects.

**Clearance is fine.** No customer, org, or person names in any example; `H-0066`'s even
carries an explicit de-identification preamble. Not a disclosure problem.

**Recommended fix (cheapest first):** stop citing real hunt IDs in examples. An adopter
can't resolve our IDs anyway, so the IDs carry no information for them and guarantee
drift for us. Relabel all six to obviously-fictional IDs, or keep the three that
reconcile and relabel the three that don't. Either way `README.md`'s quickstart must
stop referring to H-0064.

## CORRECTION (2026-09-25, same day): the section below is wrong on its main point

I wrote the section below after grepping `templates/`, `docs/`, `prompts/` and
`knowledge/` and concluding that nothing in the ATHF/GATES chain owns candidate
generation. I had not read `SKILL.md` Step 1.5. **It does own it.**

`.claude/skills/gates/SKILL.md:238` — **"Step 1.5: Detection Opportunity
Identification"** — is exactly the link I claimed was missing:

> **If hunt does NOT explicitly propose detections → identify opportunities:**
> Extract detection candidates from hunt content by analyzing: behavioral patterns
> observed … query patterns that returned results … "What Suspicious Looks Like" …
> findings without TP/FP counts … multi-step investigations

Plus `SKILL.md:642` **"Detection Extraction Examples (Generic Hunts)"**, four worked
cases covering precisely the hard inputs: prose-only findings (Ex 1), queries with no
proposed rule (Ex 2), a hunt with genuinely no detectable artifact (Ex 3), and a
multi-step investigation that resolves to `RECURRING_HUNT` (Ex 4).

So the accurate statement of the division of labour is:

* **ATHF template** — collects hunt evidence across LEARN → OBSERVE → CHECK → KEEP.
* **GATES skill (this PR)** — *derives* candidates from that evidence (Step 1.5),
  then scores them (Steps 2–4). It is an **extractor + validator**, not a validator.
* **ADEF** — stores and engineers what survives.

Two things in the section below survive the correction:

1. ATHF `main` really does have only four placeholder lines. The gap was real; **this
   PR is the thing that closes it.** That reframes the PR's value: it isn't bolting a
   scorer onto a working pipeline, it's supplying the missing stage.
2. The earlier session framing *"GATES is a validator, not a generator"* was too
   narrow and should not be reused. GATES doesn't invent detections from nothing, but
   deriving a candidate from hunt evidence is generation in the sense that matters.

**It also invalidates how I characterised the measurement.** GATES Step 1 reads *all
four LOCK phases* — CHECK-phase queries and OBSERVE's "What Suspicious Looks Like"
included. My classifier only scored detection-headed sections, so **36% GATES-ready is
a floor on GATES' input, not a ceiling.** 54 of 61 hunt files carry SQL fences, which
is Example 2's exact input shape. The INTENT and many NONE hunts are workable for
GATES. Do not quote 36% as "how much GATES can use".

## The missing step 1.5: ATHF does not generate detection candidates (2026-09-25) — SUPERSEDED, see correction above

**This is a framework gap, not a data gap, and it is argued entirely from ATHF's own
text — no private corpus required** (that matters: CLAUDE.md forbids justifying design
from in-house tooling, so the argument below stands on the framework alone and the
hunt-vault numbers are corroboration only).

`docs/lock-pattern.md` documents a three-step handoff:

1. Complete LOCK phases
2. Validate with GATES → `/gates --hunt H-XXXX`
3. Engineer with ADEF → `adef hunt-promote --gates …`

Step 2 consumes a **detection candidate**. Nothing in step 1 produces one. On `main`,
ATHF's entire detection-recommendation apparatus is four placeholder lines in
`templates/HUNT_LOCK.md`:

```md
### Detection Logic
**Automation Opportunity:**
[Can this hunt become an automated detection rule?]
**Proposed Detection:**
[Detection rule if applicable]
```

No derivation process, no candidate criteria, no worked example. `docs/lock-pattern.md`
defines the stage as *"Keep: Record Findings — Record findings and lessons learned."*
Nothing in `prompts/`, `knowledge/`, or `docs/` derives a candidate from findings.
`docs/why-athf.md` never mentions ADEF or detection engineering at all. PR #62 adds 42
lines to the template and 63 to `lock-pattern.md`, and every one is GATES *validation*
wiring — verdict recording, the precedence rule, the ADEF handoff. None is generation.

So the chain is **generate → validate → engineer** with the first link unowned.

This explains the real-hunt run above: the last-mile authoring was mine (H-0062's SQL
reconstructed from prose, H-0032's follow-up checkboxes turned into three candidates).
I logged that as a caveat on my run. It is not a caveat on my run — it is step 1.5,
and someone has to own it.

Corroboration from the corpus (planning input, not design input): 40% of hunts land at
INTENT — a follow-up action, no candidate — and **8 of the 15 hunts that eventually
shipped rules to detect-vault read as INTENT-or-NONE in their own hunt document**. The
candidate got authored off-framework, with a free-text back-reference that has already
drifted twice (H-0049→H-0050 mis-citation; 5 rules citing a nonexistent H-0064).

### Why this bites adopters harder than it bites us

hunt-vault is heavily modified from stock ATHF. Its richest hunts — H-0061's
`### Detection Guidance` with eight proposed detections, the inline sigma in
H-0001/H-0003/H-0014 — are **local practice, not framework output**. A fresh ATHF
adopter gets the four placeholder lines. If GATES ships assuming candidates exist,
the common adopter experience is running `/gates --hunt H-XXXX` against a hunt with
nothing to score.

### Options (undecided — needs a call)

1. **GATES states its precondition and fails loudly.** Cheapest. `/gates` with no
   candidate returns "no candidates found — here is what one looks like" rather than
   scoring vapour. Doesn't fill the gap, but stops it being silent.
2. **ATHF's template prompts derivation.** Replace the placeholder with the questions
   that turn a finding into a candidate (what's the discriminator? what's the
   invariant vs the IOC? what did the baseline look like?). Doc change, no machinery.
3. **A generation step becomes a real thing** — ATHF skill, or ADEF's authoring seam
   (`detection new --source`) extended to take hunt evidence. Biggest, most speculative.

Ordering note: (1) and (2) are honest about the gap and cost almost nothing; (3) is a
design question that should not be answered from our own pipeline's habits.

## ADEF branch review: 13 findings, 9 fixed, 4 held (2026-09-25)

`coderabbit review --agent --committed --base dev` on `feat/adef-gates-handoff`, run
twice (7 findings, then 6 on the fix commit's diff). Base is **`dev`**, not `main` —
per `.coderabbit.yaml`, ADEFv2 lands as stacked PRs into `dev`.

**Fixed (9).** All the same failure family — a re-import or a malformed document
changing state without saying so:

| # | Defect | Why it mattered |
|---|--------|-----------------|
| 1 | Re-import rebuilt the record from the document | Reset `status`/`stage`/`owner`/`mitre` and re-stamped `created` — an engineer's FORGE progress erased by a regenerated hunt |
| 2 | Re-import called `advance_stage(stage="find")` | Dragged a detection someone had taken to Govern back to the start of the lifecycle |
| 3 | Unrecognized verdict read as archival | `PROMOTED` (typo) or a missing `verdict` silently dropped a deployable candidate; "nothing imported" is indistinguishable from "the hunt built nothing" |
| 4 | Duplicate `candidate_id` accepted | Two candidates collapse onto one `hunt_ref`; the second write overwrote the first's record |
| 5 | Empty `detection_logic` minted a record | A query-less detection can't be verified, refined or deployed — and `adef coverage` counts it as coverage. That is the "fictional coverage" the report exists to flag |
| 6 | Non-list `detections` defaulted to `[]` | Reported 0 candidates for a malformed document |
| 7 | A mid-document rejection left a half-import | Candidate 1 written, candidate 2's bad engine aborts the run |
| 8 | `--dry-run` scaffolded a workspace | `workspace_journals_dir` defaults `create=True`, and `Catalog`/`Journal` both mkdir — a dry run against a mistyped path created the tree it was only inspecting |
| 9 | **Path traversal via `platforms`** | `platform` becomes a directory name in `catalog/<platform>/`. A document declaring `platforms: ["../../escaped"]` wrote the record outside the workspace entirely. Confirmed by execution, not inference. Guarded in `Catalog._path_for`, where every writer routes, so no caller has to remember to sanitize — this protects `catalog`/`sync` too, whose platform comes from a source rule's `logsource` |

Plus two smaller ones: `VerificationAgent.run` reported `schema_matched: true` for a
rule in `rules_skipped_unparseable` (claiming a field check that never ran), and
`record_from_gates` hardcoded `kind="atomic"` even for a `composite` engine.

**Held (4), each with the reasoning:**

1. **No reverse reconciliation.** A candidate that was PROMOTE last import and is now
   HOLD — or dropped from the document entirely — leaves its record behind untouched.
   Real gap, but the answer is an orphan pass, not deletion inside the import loop:
   `adef sync` already answers this shape of question by reporting a vanished source
   rule as **orphaned, never deleted**, and this path should match it. Marked with a
   `ponytail:` comment in `import_gates`.
2. **The re-import journal note is marked `generated`**, so the newest GATES reasoning
   is in the journal but not in the BM25 corpus. Kept deliberately: a re-import is
   usually a no-op re-run, and leaving these searchable stacks a near-duplicate block
   per run. `sync`'s housekeeping notes are `generated` for the same reason. The cost
   — a *changed* verdict isn't searchable until someone writes it up — is named in the
   comment rather than hidden.
3. **`TIME_BOX` routing** (again): the reviewer's fix is "let ADEF import the `.md`",
   which is backwards — a narrative has no query. Still the same open design call
   below: either `TIME_BOX` hunts emit `.yaml`, or ADEF stops treating `TIME_BOX` as
   deployable. Not a review fix.
4. `Catalog._path_for` containment was suggested *alongside* sanitizing `_platform_of`.
   Only the `_path_for` guard was taken — one guard at the chokepoint beats two.

Verified after: 637 passed / 2 skipped, ruff and mypy clean, and the H-0062 example
re-imported end to end with `govern`/`ready`/`alice` on D-0003 surviving intact and the
journal still at `govern`.

## State / next

- [x] ATHF cloned to `../agentic-threat-hunting-framework`, on `feat/gates-validation-skill`
- [x] GATES contract read; H-0041 run; fixture written and parses
- [x] Contract-change list for the ATHF PR (above)
- [x] Build `adef hunt-promote --gates`
- [x] SC-9326 record fields (the mapping above is the spec) — the six GATES-fed ones
- [x] Implement the contract fixes on PR #62's branch `feat/gates-validation-skill` (uncommitted)
- [x] Update ADEF's parser for `candidate_id` + canonical verdicts, keeping back-compat
- [x] Address PR #62's review feedback (Sydney + 15 CodeRabbit items) — see the section
      above; includes the two rule defects and the public-clearance sweep
- [x] Review the remaining ~60% of PR #62 (see the section above)
- [x] Test ATHF → ADEF across verdict families, all four engines, and malformed input
- [x] Run **real** hunts (H-0062, H-0032, H-0051) end to end — found 2 defects, both
      fixed (see the section above). Supersedes the synthetic pass.
- [ ] Ask the PR author to fix the acronym in PR #62's *body* (not editable from the repo)
- [ ] Raise the pre-existing `n/43` production statistics with Sydney — a separate
      clearance call on her corpus, not this PR's scope
- [x] Commit the branch, rebase onto `origin/dev`, run the CodeRabbit pass (twice) and
      push `feat/adef-gates-handoff` — see the review section above. **A PR targets
      `dev`, not `main`** (stacked-PR topology, `.coderabbit.yaml`); not opened yet.
- [ ] Close the two held design calls: reverse reconciliation (orphan pass for a
      candidate that flipped to HOLD) and `TIME_BOX` routing
- [ ] Commit + push to `feat/gates-validation-skill` — this updates the live PR #62,
      so it's outward-facing and needs Jarrett's go-ahead. Commit message should
      summarize the contract fixes for the reviewers already on the PR.
- [ ] Wire the A-gate coverage check to `rule_similarity`
- [ ] SC-9326 leftovers GATES doesn't feed: `schedule.{cron,earliest_offset}`,
      `tags.detection_category`, `tags.security_domain`, `type`. Permanently out:
      `test.simulation`, `author_notes`, `validation`, tactic/technique slugs,
      any `role`/`composable` field.
- [ ] Deferred in Shortcut: SC-9334 composite builder, SC-9341 composite taxonomy spike
