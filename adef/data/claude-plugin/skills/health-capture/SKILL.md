---
name: health-capture
description: Get real detection-health numbers into the ADEF workspace so the Evolve stage has evidence — signal volume, false/true positive counts, runtime cost, deployed-vs-catalogued drift, and telemetry-source liveness. Use when the user has metrics from their SIEM and asks how to record them, wants to know why `adef detection evolve` says `insufficient-data`, asks what ADEF knows about a detection's FP rate or volume, wants to track whether a deployed rule still matches the catalogued one, or asks whether a log source went quiet. Drives `adef ingest` / `adef health show`; never queries the SIEM itself. For the stage work those numbers feed, use forge-stage.
---

# Detection Health Capture

ADEF's Evolve stage recommends tune / keep / deprecate from **measured**
numbers, and it has none until someone hands them over. Your job is to turn
what the engineer has — a search result, a CSV, a dashboard export, numbers
from your own environment tooling — into a valid capture document, ingest it,
and confirm it reads back.

**ADEF never connects to the SIEM.** There are no vendor connectors and there
will not be; the producer hands over a file. If you have your own tooling
connected (an MCP server for their platform, a CLI they've authorized), you are
a legitimate producer — fetch the numbers, shape the document, ingest it. If you
don't, ask for the numbers. Never invent them, and never round an engineer's
figure into something tidier.

## The one rule that decides document shape

**Anything counted over the window is reported as a count, never as a ratio.**
A ratio cannot be re-aggregated across windows — two weeks at "50% FP" don't
average to anything meaningful without knowing how many signals each week had.
ADEF derives those ratios itself (`adef/core/health_store.py`), so give it
`false_positive_count: 236` and `true_positive_count: 2`, not `fp_rate: 0.99`.

This is about the *interval* counts in `metrics` and `performance`. It is not a
ban on every fractional value: `field_observations.fields[].null_rate` is a
point-in-time property of how a field is populated, not a count ADEF
re-aggregates, and it belongs in the document as a rate.

Consequences worth stating to the user, because they decide what to collect:

- `fp_ratio` needs **both** FP and TP counts. Its denominator is what was
  *adjudicated* (FP + TP) — never `signal_count`, because an unlabeled signal
  is not a known false positive. FPs with no TP count is a *valid* document;
  ADEF just omits `fp_ratio` rather than reporting `1.0` about a number nobody
  supplied.
- A derived key is **omitted** when its counts are absent, never emitted as
  `0.0` — both recommenders decide "insufficient data" on key *presence*. So a
  missing count is honest; a zero you supplied to fill a gap is a lie the
  heuristics will act on.
- `weekly_signal_volume` is normalized by the document's declared `window`, so
  the window must be the real one the numbers cover.

## The five kinds

Each document declares its own `kind` — `adef ingest` routes on the file's
content, not on a flag, so there is nothing to mismatch. Pick by what the
engineer actually has; one kind per file.

| Kind | Keyed by | Answers |
|------|----------|---------|
| `metrics` | `detection_id` | Is this rule firing, and is it right? |
| `performance` | `detection_id` | What does it cost, and does it error? |
| `deployment_drift` | `detection_id` | Does the deployed rule still match the catalogued one? |
| `field_observations` | source name | Did a field's *values* change shape? |
| `source_health` | source name | Is the telemetry still arriving? |

Common header on every document:

```yaml
schema_version: 1
kind: metrics
captured_at: 2026-10-08T14:00:00Z
window: {start: 2026-10-01T00:00:00Z, end: 2026-10-08T00:00:00Z}
environment: prod-siem      # free-form label: which deployment these describe
```

`window` is **required** for every kind except `deployment_drift`, which is
point-in-time (`captured_at` is all of its temporal meaning) and where a window
is an *error*, not something ignored.

### `metrics` — the one Evolve's tuning heuristics read

```yaml
detections:
  - detection_id: D-0042
    signal_count: 240
    false_positive_count: 236
    true_positive_count: 2
    last_true_positive_at: 2026-06-08T12:00:00Z   # drives staleness
```

### `performance`

```yaml
detections:
  - detection_id: D-0042
    run_count: 168
    failure_count: 3        # health, not cost — a rule erroring every run is dead
    timeout_count: 1
    avg_runtime_seconds: 12.4       # optional
    data_scanned_bytes: 8400000000  # optional
    events_evaluated: 240000000     # optional
```

### `deployment_drift`

```yaml
detections:
  - detection_id: D-0042
    deployed_status: enabled        # enabled | disabled | absent
    deployed_version: "7"           # preferred: exact comparison, no normalization
    last_deployed_change_at: 2026-09-02T08:11:00Z   # optional
    deployed_query: |                # fallback when there's no version identifier
      ...
normalization:
  apply: [collapse_whitespace, strip_sql_comments]   # text path only; optional
```

Prefer a **version reference** over query text whenever the platform exposes
one (a version integer, an etag, the deploying commit) — exact and cheap.
`deployed_status: absent` means catalogued but not deployed, which is drift
worth knowing and costs no comparison.

`normalization.apply` selects from a **closed** set ADEF ships:
`collapse_whitespace`, `strip_sql_comments`, `strip_trailing_semicolon`. Each
is behavior-preserving in all four engines. A producer-supplied regex is not
accepted, by design — the comparison contract stays auditable. Nothing touching
case, quoting, numeric form or parentheses is in the set, because each of those
can change behavior and so must surface as real drift. **Default to no
transforms**; add one only after the user has seen their pipeline do it.

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

`sample_values` is the **only** field in any document kind that carries
event-derived content, and ingesting it stores that data at rest in
`health/sources/<source>.yml`. Say so before including it, and leave it out
unless the value shape is the actual question.

### `source_health`

```yaml
kind: source_health
sources:
  - name: wineventlog
    event_count: 240000000
    last_event_at: 2026-10-08T13:58:00Z
```

Small and load-bearing: a detection that stopped firing because its feed died
is a telemetry incident, not a rule to deprecate. Check this before letting
anyone retire a quiet rule.

## Workflow

1. **Find out what they have.** Ask for the numbers and the window they cover.
   Don't propose a kind before you know which figures exist — collecting for
   `deployment_drift` when they only have volume wastes their time.
2. **Write the document into the workspace**, not `/tmp`:
   `<workspace>/health/captures/<date>-<kind>.yml`. The workspace is the
   durable memory; the input document is evidence of where the numbers came
   from.
3. **Validate before writing anything:** `adef ingest <file> --dry-run`
   reports what it would store and writes nothing. Do this every time.
4. **Ingest:** `adef ingest <file>`. Detection-keyed kinds land as a latest
   snapshot (`health/latest/D-XXXX.yml`) **plus** an append-only
   `health/history/D-XXXX.jsonl`, so a re-ingest is a new data point, never a
   silent overwrite of the trend. The two source-keyed kinds write
   `health/sources/<name>.yml` — **latest only, no history** — so don't promise
   a trend you can't show for those.
5. **Read it back and check the derived keys, not just the exit code.**
   `adef health show D-XXXX` for one detection, `adef health show --source
   NAME` for the source-keyed kinds (positional is for detection IDs; a
   free-form source name has no shape to dispatch on, hence the flag), bare
   `adef health show` for everything stored.

   This step is not a formality. **Row keys are not a closed set** — only the
   top-level document keys are validated. A misspelled
   `false_positives_count` (note the plural) ingests cleanly, reports
   `1 matched`, and is then invisible to every heuristic: the stored document
   shows the key, and the `derived for tuning` block silently has no
   `fp_ratio`. So read that block and confirm the key you expected to produce
   is actually in it, by name, before telling the user the numbers landed.
6. **Close the loop into Evolve — only for the detection-keyed kinds.** There
   is nothing to advance after a `source_health` or `field_observations`
   ingest: those documents are keyed by a telemetry source name and carry no
   detection ID. Finish at readback, say what the source looks like, and hand
   off.

   For the three detection-keyed kinds, closing the loop means
   `adef detection evolve D-XXXX --chain`. **That command advances the
   detection's FORGE stage**, so it is a stage decision, not a step of
   ingesting — never run it just because an ingest succeeded:

   - **Already at evolve?** Run it. `--chain` is *required* here: without it
     the stage is idempotent and the fresh numbers are never read.
   - **Not at evolve yet?** Say what was ingested, say that acting on it means
     moving the detection to Evolve, and let the user decide. Ingesting a
     week of drift data is not a reason to graduate a detection that is still
     being refined.

   What each kind buys, because it decides whether Evolve is worth running at
   all: the tuning and deprecation heuristics read the **`metrics`** kind
   only. A `performance` or `deployment_drift` ingest enriches the journal's
   Health block (it lists every kind stored) but cannot move a recommendation
   off `insufficient-data` on its own — so for those two, readback plus a
   summary is usually the whole job. Then hand off to **forge-stage** for the
   tune/deprecate judgment.

`adef doctor` reports whether anything is ingested at all, which is the fastest
answer to "why is Evolve empty?".

**In an MCP session** (`adef-mcp`), prefer the tools over shelling out:
`health_ingest` takes the document's **path** — write the file first, same as
the CLI — and hands back the ingest result as structured data instead of stdout
you have to parse. `health_show` is its readback twin, with `evolve_chain` mirroring `adef
detection evolve`. `tune_recommend` and `deprecation_recommend` read the stored
health themselves when you omit their metrics argument, so don't hand-assemble
what the chain already derives. Still write the document into the workspace
even when ingesting through MCP: the file is the provenance for where the
numbers came from.

## Anti-patterns

**❌ Don't:**
- Supply a number the user didn't give you, including a zero to fill a gap —
  an omitted count reads as "unknown", a zero reads as "measured zero"
- Convert an interval count to a ratio before ingesting — ADEF derives those
  ratios, and a ratio can't be re-aggregated across windows (`null_rate` on a
  `field_observations` field is not this; it's a point-in-time rate)
- Ingest without `--dry-run` first
- Report "ingested, N matched" as success without reading the derived block
  back — a typo in a row key matches, stores, and derives nothing
- Put a `window` on a `deployment_drift` document (it's an error) or omit one
  from the other four kinds
- Add a `normalization.apply` transform the user never asked for, or invent one
  outside the shipped three — a new transform is a PR to ADEF, not a data edit
- Include `sample_values` without naming that it stores event-derived content
  in the workspace
- Draft the capture document in `/tmp`, or ingest a file you then delete — the
  document is the provenance
- Recommend deprecating a quiet detection before checking `source_health`
- Claim ADEF "pulled" or "collected" the numbers. It was handed them.
