# Declaring Your Data Sources

ADEF builds data schemas from a **declaration document you provide** — a YAML
inventory of your data sources and their fields. The declaration is the entire
contract: ADEF never connects to your SIEM, never sees event data, and doesn't
care how you produced the file. Get your data into this one format, by any
means, and everything downstream (query-authoring assistance, `adef schema
check`, drift reporting) lights up.

```bash
adef schema recipe <platform>                   # SIEM-specific extraction recipe
adef schema reshape <export> --platform <p>     # export -> draft declaration + report
adef schema lint adef-sources.yml               # validate
adef schema ingest adef-sources.yml             # build schema/<source>.yml per source
adef schema check                               # cross-reference your rules against it
```

**Platform-specific recipes + deterministic reshaping.** `adef schema recipe
<platform>` prints exactly what command to run in your SIEM to extract a field
inventory; `adef schema reshape` then converts that export into a draft
declaration in tested code — filtering platform internals, folding
case-duplicates into `aliases`, harvesting capped enum values, inferring
types, and refusing mixed-shape exports with re-export guidance. It prints a
transformation report so you approve the transformations rather than
hand-auditing YAML. See [`siem-recipes.md`](./siem-recipes.md) for guides
covering Splunk, Sentinel, Elastic, Chronicle, Sumo Logic, QRadar, and
generic SQL platforms.

## The format

```yaml
version: 1
sources:
  - name: sysmon_operational          # unique; what this schema IS
    platform: windows                  # optional
    query_language: spl                # optional but recommended: spl | kql | cql | sql
    description: Sysmon via Splunk UF  # optional
    scope:                             # optional: every way a query might ADDRESS this source
      index: main
      sourcetype: XmlWinEventLog
    fields:
      - name: EventCode                # in query-language terms (what a rule would write)
        type: int                      # optional, default string
        description: Windows event ID  # optional
        values: [1, 3, 7, 10, 11]      # optional — enum-ish fields; gold for rule authoring
      - name: CommandLine
      - name: user
        aliases: [User, user_name]     # optional — same concept under other extracted names
```

**The floor is low on purpose.** `version`, source `name`, and field `name`s
are the only requirements — a valid declaration for a small source is ten
lines. Everything else is enrichment you can add incrementally, and each
addition directly improves what an assistant can do: `type` prevents wrong
comparisons, `values` lets it write correct predicates without guessing enum
members, `aliases` documents the extraction mess so `check` doesn't
false-positive on it.

**`name` vs `scope`.** `name` is what the schema *is* — one event shape, one
schema file. `scope` lists every literal a query might use to *address* it.
You need scope when one container holds many shapes: a Splunk index with a
dozen sourcetypes, a Falcon repo with hundreds of event types. Declare one
source per shape, scope each to the shared container, and `adef schema check`
does the right thing automatically — a rule filtered only by the container is
checked against the union of its shapes; a rule that also pins the shape
(`sourcetype=...`) is checked against exactly that schema. Platforms where
one table = one schema (Sentinel, warehouse tables) don't need scope at all.

## Four ways to produce one

1. **Use `adef schema recipe` + `adef schema reshape`** (easiest for supported
   platforms). The recipe gives you the exact command to run in your SIEM;
   reshape converts the export deterministically:
   ```bash
   adef schema recipe splunk     # or sentinel, elastic, chronicle, sumo, qradar, other
   # run the printed command in your SIEM, save the export, then:
   adef schema reshape fields.csv --platform splunk
   ```
   Reshape applies the five reshape rules (internals filter, case-dupes →
   aliases, capped enums, type inference, mixed-shape guard), prints a
   transformation report, and writes a declaration that lints clean. Set
   `platform:` and `description:` in the output, then ingest.
   **Deterministic parsers:** Splunk `fieldsummary` CSV, Sentinel `getschema`
   CSV, Elastic `_mapping` JSON; any other platform via a plain field list
   (one per line).
   **Detailed guides:** [`siem-recipes.md`](./siem-recipes.md)

2. **Reshape an inventory export manually.** Every platform can emit a field
   list — Splunk `| fieldsummary`, KQL `| getschema`, Elastic
   `GET <index>/_mapping`, a vendor's event data dictionary. The reshape into
   the format is mechanical; the worked examples below show it end to end.

3. **Ask your AI assistant.** Paste whatever you have — fieldsummary output, a
   CSV, a docs page — and have it draft the declaration, then run
   `adef schema lint` before ingesting. The format is small enough that this
   works reliably. (The `schema-declaration` skill orchestrates this workflow
   when using Claude Code with ADEF's MCP server.)

4. **Write it by hand.** Reasonable for small or high-value sources where you
   want to be deliberate about descriptions and enum values.

Nobody hand-types 200 fields — pick 1, 2, or 3 for anything big.

## Worked example: Splunk

**Step 1 — see what shapes live in the index** (one schema per sourcetype,
not per index):

```
| tstats count where index=main by sourcetype
```

**Step 2 — field inventory per sourcetype you care about:**

```
index=main sourcetype="bro:dns:json" earliest=-7d
| head 5000
| fieldsummary maxvals=10
| fields field count distinct_count numeric_count values
```

Export as JSON/CSV. A few rows of what comes back:

```
field           count  distinct_count  numeric_count  values
answer_count    4980   7               4980           [{"value":"1","count":4211}, ...]
qtype_name      4993   9               0              [{"value":"A","count":3120}, ...]
punct           5000   43              0              ...
```

**Step 3 — reshape.** The mapping is mechanical: `field` → `name`;
`numeric_count == count` → numeric type; small `distinct_count` → keep the
top `values`; drop Splunk internals (`_*`, `punct`, `linecount`,
`splunk_server`, `date_*`); same concept under multiple extracted names →
one field + `aliases`.

```yaml
version: 1
sources:
  - name: zeek_dns
    platform: network
    query_language: spl
    description: Zeek DNS via Splunk (declared from fieldsummary, 5k-event sample)
    scope:
      index: main
      sourcetype: bro:dns:json
    fields:
      - name: answer_count
        type: int
        values: [1, 2, 3]
      - name: qtype_name
        values: [A, AAAA, PTR, TXT, SRV, SOA, NS, MX, CNAME]
      - name: query
      - name: rcode_name
        values: [NOERROR, NXDOMAIN, SERVFAIL]
```

Repeat per sourcetype; all sources go in the same file. Keep the `sourcetype`
literal exactly as Splunk reports it — it's what `check` matches against your
rules' `sourcetype=` predicates.

## Worked example: CrowdStrike Falcon

No export needed — CrowdStrike publishes its event shapes in the **Events
Data Dictionary** (Falcon console → Documentation). Each event type
(`event_simpleName`) is one source; the repo is the shared container:

```yaml
version: 1
sources:
  - name: ProcessRollup2
    platform: windows
    query_language: cql
    description: Process execution events (Falcon Events Data Dictionary)
    scope:
      repo: base_sensor
      event_simpleName: ProcessRollup2
    fields:
      - name: ImageFileName
      - name: CommandLine
      - name: ParentBaseFileName
      - name: SHA256HashData
        description: SHA-256 of the executed image
      - name: UserSid
      - name: TargetProcessId
        type: int
  - name: DnsRequest
    platform: windows
    query_language: cql
    scope:
      repo: base_sensor
      event_simpleName: DnsRequest
    fields:
      - name: DomainName
      - name: RequestType
        type: int
        values: [1, 5, 16, 28]
```

The dictionary page → declaration reshape is copy-adjacent work, and an AI
assistant will do it from a pasted page in one shot.

## After ingest: corrections and drift

`adef schema ingest` writes one `schema/<source>.yml` per source with every
field marked `provenance: declared`. Two things to know:

- **Your edits are protected.** Fix a type or add a field the sample missed
  directly in the generated file and mark it `provenance: corrected`.
  Re-ingesting a newer declaration replaces `declared` fields but never
  touches `corrected` ones.
- **Drift is reported on re-ingest.** Export a fresh inventory next month,
  regenerate the declaration, re-ingest: ADEF prints fields added / removed /
  type-changed since last time, and `adef schema check` will flag any rules
  referencing fields that disappeared.

## What makes a declaration good

Declare the sources rules actually target — not everything that exists.
Spend enrichment effort where it pays: `values` on enum-ish fields
(event codes, action types, protocol names) and `aliases` wherever your
platform extracts the same concept under multiple names. Those two are the
difference between an assistant that writes correct queries and one that
guesses.
