# Detection Health Capture — Metrics, Performance, and Drift

**Status:** Design agreed, not yet implemented
**Created:** 2026-09-21
**Story:** Shortcut 9342 (spike). Unblocks 9335 (implementation).

How ADEF learns what its catalogued detections are actually doing once they run
somewhere real — without ADEF ever talking to that somewhere.

---

## Why

ADEF's catalog knows what a detection *is*. It has no idea whether that detection
fires, whether it costs a fortune to run, whether anyone edited it after deployment,
or whether it quietly stopped matching three months ago. The Evolve stage exists to
answer exactly those questions and currently cannot: `adef detection evolve` advances
the stage and writes a note. `TuneRecommenderAgent` and `DeprecationRecommenderAgent`
are implemented but unwired — reachable only through MCP tools, never from the CLI
lifecycle.

The hard constraint is that ADEF must not grow vendor API connectors
(`tests/test_no_vendor_connectors.py`). So the question is not "how does ADEF query
Splunk" — it never will. The question is what contract lets someone else do the
querying and hand ADEF the answers.

## What "drift" means

Practitioner literature uses "drift" for several unrelated failure modes. Conflating
them produces a feature that reports the wrong cause confidently. This design names
four and covers two:

| Failure mode | What breaks | In scope? |
|---|---|---|
| **Deployment drift** | Deployed rule no longer matches the catalogued source — someone edited it in the console | Yes, ingested |
| **Efficacy drift** | Logic unchanged, but the ground moved: field renamed/retyped, log source changed shape, volume silently died | Yes, derived (+ optional ingest) |
| **Adversary / TTP drift** | The technique evolved past the rule | **No** — not derivable from telemetry; belongs to ATT&CK coverage tooling and adversary emulation |
| **Environment drift** | New assets/software push false positives up | Partially — surfaces as an FP-ratio trend, not modelled separately |

Adversary drift is called out explicitly so the feature doesn't imply coverage it
doesn't have.

## The capture documents (v1)

One document, one kind, many detections. Self-describing — the file declares what it
is, so ingestion routes on content rather than a CLI flag the producer could
mismatch. `schema_version` is present from day one, per the schema-artifact
precedent.

Common envelope:

```yaml
schema_version: 1
kind: metrics        # metrics | performance | deployment_drift | field_observations | source_health
captured_at: 2026-09-21T14:00:00Z
window: {start: 2026-09-14T00:00:00Z, end: 2026-09-21T00:00:00Z}
environment: prod-siem      # free-form label; which deployment these numbers describe
```

`window` is **required** for the kinds whose numbers are counts over an interval —
`metrics`, `performance`, `field_observations`, `source_health` — because a count
without a denominator is uninterpretable, and trend comparison needs comparable spans.
It is **omitted** for `deployment_drift`, which is a point-in-time observation:
`captured_at` is the whole of its temporal meaning. Validation enforces both
directions, so a window on a drift document is an error rather than something silently
ignored.

### `metrics` — signal-generation efficacy

```yaml
detections:
  - detection_id: D-0042
    signal_count: 143
    true_positive_count: 4
    false_positive_count: 131
    unlabeled_count: 8
    last_true_positive_at: 2026-08-30T11:04:00Z
```

**Counts, not ratios.** A ratio cannot be re-aggregated across windows — averaging
two weeks' FP ratios is arithmetically wrong. Counts derive ratios; the reverse
fails. This matches the field set in FIRST.org's Detection Engineering Metrics
Catalog, which is the closest thing to a published standard here.

**`last_true_positive_at`, not `days_since_true_positive`.** An absolute timestamp
stays true; a stored "days since" is wrong the moment it is written. Staleness is
computed at read time.

`TuneRecommenderAgent` currently expects `{fp_ratio, weekly_signal_volume,
days_since_true_positive}`. A thin adapter derives that shape from the stored counts,
so the agent's heuristic and its tests are untouched.

### `performance` — query cost and execution health

```yaml
detections:
  - detection_id: D-0042
    avg_runtime_seconds: 12.4
    p95_runtime_seconds: 31.0      # optional
    data_scanned_bytes: 8400000000 # optional
    run_count: 168
    failure_count: 3
    timeout_count: 1
    events_evaluated: 240000000    # optional
```

`failure_count` is not cost — it is health. A rule erroring on every run is not slow,
it is dead, and no runtime average reveals that.

### `deployment_drift` — catalogued vs. deployed

```yaml
detections:
  - detection_id: D-0042
    deployed_status: enabled       # enabled | disabled | absent
    deployed_version: "7"          # optional; exact-comparison path
    last_deployed_change_at: 2026-09-02T08:11:00Z   # optional
    deployed_query: |              # optional; text-comparison fallback
      ...
normalization:
  apply: [collapse_whitespace, strip_sql_comments]  # optional; text path only
```

Two comparison paths, preferred order:

1. **Version reference.** When the deployment target exposes a stable identifier for
   the deployed rule — a version integer, an etag, the commit that deployed it —
   compare that. Exact, cheap, no normalization needed.
2. **Query text.** When it doesn't, compare `deployed_query` against the catalog
   record's `query`, after normalization, and report a unified diff.

`deployed_status: absent` means the rule is catalogued but not deployed at all, which
is drift worth knowing about and costs no comparison.

## Normalization

Raw text comparison is unusable. Deployment pipelines reformat queries in ways that
change nothing semantically — whitespace, comment injection, statement terminators —
and every such difference reads as drift. Normalization is a deterministic transform
applied to **both** sides before comparison so those artifacts cancel out.

Two properties govern the design:

**Every normalization is lossy.** Each transform applied is a class of drift that can
no longer be seen. That is acceptable only for transforms that cannot change
behavior. It is why `_normalize_query()` in `adef/agents/rule_overlap.py` cannot be
reused here: it lowercases everything, so `user='Admin'` → `user='admin'` — a real
behavior change on a case-sensitive backend, silently erased. That function was built
for fuzzy similarity scoring, where lossy is correct. Equality comparison is the
opposite problem.

**The document selects; it does not define.** `apply` names transforms from a closed
set ADEF ships. Arbitrary producer-supplied regex would be a ReDoS surface and
unreviewable, and it would make the comparison contract unauditable. This follows the
extraction-profile precedent, which deliberately allows dot-paths but not JSONPath
"so the human approval gate stays reviewable." A transform outside the set is a PR to
ADEF — deliberately higher friction than editing a data file.

Shipped set, each justified by language semantics alone:

| Transform | Why it cannot change behavior |
|---|---|
| `collapse_whitespace` | Whitespace is non-semantic in all four engines |
| `strip_sql_comments` | Comments do not execute |
| `strip_trailing_semicolon` | Statement terminator, not logic |

Deliberately absent: anything touching case, quoting style, numeric literal form, or
parenthesis structure. Each of those can change behavior, so a difference there must
surface as drift. The default `apply` is empty — teams opt in per environment after
observing what their own pipeline does.

### Evidence

Public practitioner sources treat deployment/config drift as a recognized category
and document normalization and parsing differences as the reason naive comparison
fails; detection-as-code tooling surfaces field-level diffs at PR time for the same
reason.

*Non-normative internal data point, not an ADEF dependency:* an internal measurement
over 53 rules found 11% byte-identical to their deployed form, with the remainder
differing by whitespace, case, or parameter style. Hash-only comparison would have
reported ~89% false drift. Recorded because the conclusion was empirically checked,
not assumed. ADEF's design does not depend on that environment, and no transform in
the shipped set exists because of it.

### `field_observations` — optional, for value-shape drift

```yaml
kind: field_observations
source: wineventlog
fields:
  - name: process.name
    null_rate: 0.02
    distinct_count: 1450
    sample_values: ["mshta.exe", "powershell.exe"]   # optional
```

Covers the efficacy-drift case ADEF cannot derive: the field is still present and
populated, but its values changed shape. `sample_values` is the only field in any
document that carries event-derived content — it is optional, and its privacy
implication is documented at the point of use.

### `source_health` — the disambiguator

```yaml
kind: source_health
sources:
  - name: wineventlog
    event_count: 240000000
    last_event_at: 2026-09-21T13:58:00Z
```

Small, and load-bearing. See below.

## Storage

`<workspace>/health/` — named for what it holds. Not `telemetry/`: ADEF stores no
event data, and the directory name should not imply otherwise.

```
health/latest/D-0042.yml      # newest snapshot of each kind, merged per detection
health/history/D-0042.jsonl   # append-only, one compact row per ingest
health/sources/<source>.yml   # newest snapshot of each source-keyed kind, merged
```

Both source-keyed kinds — `source_health` and `field_observations` — land in the
same `sources/<source>.yml`, keyed by kind, and merge the same way `latest/` does.
A source receiving a throughput report and a field-null-rate report is the expected
path, not an edge case, so the merge is load-bearing: without it the second ingest
silently destroys the first. (Found during implementation — the first draft of this
design named `sources/` for `source_health` alone and carried no merge.)

Hybrid by design. `latest/` answers "what is true now" in one read. `history/` is the
trend substrate — JSON Lines because append is the only write it ever takes. Rows are
numeric fields plus a timestamp, not whole documents, so growth is bounded by ingest
cadence rather than document size.

## Derived analysis — efficacy drift

`adef/core/health.py`, pure functions over stored artifacts. Same shape as
`adef/core/coverage.py`: an analysis core over workspace state, consumed by a command,
testable against fixtures with no I/O.

Trend uses **EWMA** (λ = 0.3), not a static threshold. Practitioner and NIST guidance
both favour control-chart methods for gradual drift; threshold alerting on a noisy
series produces alarms nobody keeps. It is a handful of lines of stdlib — no numeric
dependency.

The governing rule: **every finding names its alternative explanation.**

```
signal volume below EWMA trend?
  └─ look up source_health for the record's data_source
       ├─ source event_count collapsed too → "telemetry gap"
       │                                     (the feed died — the rule is not the story)
       └─ source healthy                   → "possible efficacy drift"
                                             (rule went quiet while data kept flowing)

referenced field missing or retyped in schema/   → "schema drift"  (via run_schema_check)
field_observations null_rate spike on a field    → "field population drift"
fewer than 4 ingests of history                  → "insufficient history" — say so
```

That first branch is the whole reason `source_health` exists. Practitioner reporting
attributes roughly half of detection failures to log-collection gaps, and guidance is
consistent: correlate against ingestion health *before* concluding a rule decayed.
Without it, this analysis would confidently blame the rule for a dead feed about half
the time it fires — worse than not shipping it.

"Insufficient history" is a first-class outcome. Two data points cannot support a
trend claim, and saying so is more useful than a confident number.

## CLI surface

```bash
adef ingest <file>              # route on kind, validate, write latest + append history
adef ingest <file> --dry-run    # validate and report, write nothing

adef health                     # fleet report
adef health --detection D-0042  # scope to one
adef health --report json       # machine-readable
```

`adef health` is a peer of `adef coverage`: coverage answers *what do we cover*,
health answers *how are those detections doing*. Report sections: decaying, drifted,
telemetry gaps, never-fired, failing runs.

Ingestion reports matched and unmatched `detection_id`s. Unmatched rows are never
silently dropped — same infer-and-flag principle the catalog already follows.

MCP gets `health_ingest` and `health_report` through the normal `adef.mcp_tools`
entry point, over the same core functions. This is what "MCP-driven tuning" means in
practice: an assistant session that already has its own vendor tooling connected
fetches the numbers and calls ADEF's ingest tool with them. It is not a separate
capture mechanism, and ADEF still makes no vendor call.

## The Evolve chain

Refine runs a three-step chain. Evolve — the stage whose entire purpose is tuning and
deprecation — advances the stage and stops. This design closes that asymmetry:

`adef detection evolve D-XXXX` reads stored health, then runs `TuneRecommenderAgent`
and `DeprecationRecommenderAgent` (both already written), appending
`### Evolve / Health`, `### Evolve / Tuning`, and `### Evolve / Deprecation` blocks to
the journal. Same orchestration shape as `refine_chain.py`: never aborts on a failed
step, renders `NoCatalogRecordError` as its own outcome, partial results are kept.

## Wrapper bindings

`ADEF_WRAPPER_PERFORMANCE_METRICS` returns `{fp_ratio, weekly_signal_volume,
days_since_true_positive}` — the *metrics* measurable under a performance label.
Rename to **`ADEF_WRAPPER_METRICS`**, outright, no compatibility shim, on the repo's
own precedent: ADEF is unreleased and a deprecation window protects nobody.

**No new bindings.** Earlier drafting proposed `ADEF_WRAPPER_PERFORMANCE` and
`ADEF_WRAPPER_DRIFT` by analogy. No ADEF user has asked for either, and an unused
public env-var contract is far easier to add later than to remove. Ingestion is the
path; `ADEF_WRAPPER_METRICS` survives only because `TuneRecommenderAgent` genuinely
consumes it today.

## Getting documents made (adoption paths)

1. **Recipes (docs, no code).** Per-platform one-liners that emit per-rule counts and
   runtimes, plus the reshape into the document format. Mirrors the SIEM recipes the
   schema declaration path already ships.
2. **An assistant session.** The user pastes whatever their platform gave them — CSV,
   API JSON, a console export — and the assistant reshapes it into a valid document;
   `adef ingest --dry-run` validates; a human approves. Same division of labour as the
   profile-author and declaration-author skills: the format stays dumb and stable, the
   assistant absorbs the hundred input shapes.
3. **A team's own scheduled job.** A cron that runs the saved query and writes the
   document into the workspace. ADEF neither knows nor cares that it exists.

## Known tradeoffs

- **Cadence is the producer's choice.** ADEF cannot know whether a window is a day or
  a quarter except from `window`, and trend quality follows directly from how
  regularly documents arrive. Irregular ingestion produces a defensible-looking EWMA
  over an undefensible series. Mitigated only by reporting the window span alongside
  findings.
- **TP/FP counts require analyst labelling** that many teams do not do. Where labels
  are absent, `unlabeled_count` carries the whole volume and precision-derived
  findings stay silent rather than guessing.
- **`environment` is a free-form label.** Two teams ingesting from two deployments
  into one workspace will interleave rows. v1 stores the label and reports it; it does
  not partition by it.
- **Value-shape drift depends on optional input.** Without `field_observations`, a
  field that still populates but changed meaning is invisible. That is a real gap,
  stated rather than papered over.

## Anti-goal check

No vendor connectors — every path is a file or an already-written wrapper binding; no
ADEF code path opens a network connection to a security product. No new engine types.
No web UI. No writes under any `detections/` tree. No event data at rest, with the
single documented exception of optional `sample_values`, which is opt-in and flagged
at the point of use.

## ISA entries to record

- Detection health capture is document-driven: five versioned `kind`s ingested through
  one self-describing `adef ingest`, stored as latest-plus-thin-history under
  `health/`, with `adef health` as the fleet report.
- Drift is two things, not one: deployment drift is ingested and compared
  version-first with a normalized-text fallback; efficacy drift is derived from
  history, schema state, and source health. Adversary/TTP drift is explicitly out of
  scope.
- Efficacy-drift findings must name their alternative explanation; a volume cliff is
  correlated against `source_health` before it is ever attributed to the rule.
- Normalization is a closed, ADEF-shipped set the document selects from, never
  producer-supplied regex. `_normalize_query()` is unsuitable (lowercasing masks real
  drift) and is not reused.
- `ADEF_WRAPPER_PERFORMANCE_METRICS` → `ADEF_WRAPPER_METRICS` (it always returned
  metrics). No new wrapper bindings until a user demonstrates need.
- The Evolve stage gains a chain symmetric with Refine's, wiring the two already-built
  recommender agents into the CLI lifecycle for the first time.
