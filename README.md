# Agentic Detection Engineering Framework (ADEF)

> Detection engineering with durable memory, a five-stage lifecycle, and an agentic surface — the sibling of [ATHF](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework).

ADEF gives every detection a journal, every transition a timestamp, and every lifecycle stage an agent surface that current and future engineers can read. Whether your rules live in a git repo, only in your SIEM, or don't exist yet, ADEF wraps them with durable memory: *why* the rule exists, *how* it evolved, and *when next* it needs attention.

**What you get:**

- **A catalog of every detection you have** — walked read-only from a repo or a one-time SIEM export, in any mix of Sigma, Splunk, Panther, KQL/SQL/CQL, or your in-house format
- **An honest coverage report** — solid vs. fragile ATT&CK coverage, single points of failure, and fictional technique IDs, exportable as a scored MITRE Navigator layer
- **Schema-grounded authoring** — new rules scaffolded against the fields and values that actually exist in your data, not guesses
- **A journal per detection** — the reasoning, tuning history, and review cadence that normally lives in chat threads and leaves with the person who wrote it

## The FORGE Lifecycle

ADEF detections move through five stages:

1. **Find** — a gap, a signal source, an intel report, a hunt outcome
2. **Observe** — characterize real telemetry behavior; understand normal before defining weird
3. **Refine** — iterate the rule with backtest, similarity, overlap, and verification feedback
4. **Govern** — deploy with quality gates, ownership, review cadence
5. **Evolve** — tune, deprecate, replace; detections never finish, they iterate

See [`docs/methodology.md`](docs/methodology.md) for the full FORGE walkthrough.

## Install

> **ADEF is not yet published to PyPI.** Until v0.1.0 ships, install from
> source — see [`docs/quickstart.md`](docs/quickstart.md) for the full local
> walkthrough (including a self-contained demo with sample rules and data).

```bash
git clone https://github.com/Nebulock-Inc/agentic-detection-engineering-framework.git
cd agentic-detection-engineering-framework
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip              # pip >= 21.3 required for editable installs
pip install -e .

adef --version                         # verify
adef init --interactive                # scaffold ~/work/adef-workspace/ + set your SIEM
```

`--interactive` is a guided setup: it asks where your detections live today
(repo / SIEM-only / starting fresh) and tailors your next steps, remembers
your SIEM and query language so later commands stop asking, surfaces the
optional layers (MCP server, AI-assistant skills — inactive until installed)
and offers to install the skills on the spot. Plain `adef init` works too.
After release: `pip install agentic-detection-engineering-framework`.

## Pick your on-ramp

ADEF meets you where your detections are. Three starting points — they all
end at the same place: a catalog, journals, and a coverage report.

### A. You have a detection repo

Point ADEF at it — the repo is never modified:

```bash
adef catalog /path/to/rules --dry-run --report json   # see what ADEF recognizes first
adef catalog /path/to/rules      # walk read-only → catalog + skeleton journals
adef sync /path/to/rules         # later: refresh changed rules, keep your enrichment
adef sync /path/to/rules --check # CI mode: exit 1 if the catalog is behind
```

Sigma, Splunk ESCU / `savedsearches.conf`, Panther, raw KQL/SQL/CQL work out
of the box. In-house formats are taught with a small **extraction profile**
(YAML, no code) — draft one by hand or let the bundled agent draft it from
samples: `adef profile lint` validates, you approve, every future run uses it.

`sync` preserves everything you've added — MITRE tags, stage, owner, journal
entries survive a re-sync; rules edited outside ADEF get a journal note
instead of silent loss. Rules that vanish from the repo are marked orphaned,
never deleted.

### B. Your rules live only in your SIEM

No repo required. Export your rules once (Splunk `savedsearches.conf`,
Sentinel analytics export, Panther bulk download — any folder of rule files),
then catalog the export:

```bash
adef catalog /path/to/exported-rules
```

The ADEF workspace — catalog records plus journals — is now your first
version-controlled detection inventory:

```bash
cd ~/work/adef-workspace
git init && git add -A && git commit -m "detection inventory, day 0"
```

If you later adopt detection-as-code, your export becomes the repo and
`adef sync` takes over from there. If you never do, that's fine too — see C
and the full guide: [`docs/detection-home.md`](docs/detection-home.md).

### C. You're starting fresh (or authoring new rules)

Rules authored in ADEF live in ADEF. Declare a data source first (section
below), then scaffold new detections against it:

```bash
adef detection new "Suspicious mshta.exe child process" --source wineventlog_xml
adef detection list --origin authored     # your ADEF-native rules
```

`--source` grounds the draft in a declared schema: the record gets the real
platform, query language, and a starter query carrying your actual index and
sourcetype literals. Records carry an `origin` marker — `adef sync` never
touches rules authored in ADEF, so mixing authored rules with a catalogued
repo is safe. Using ADEF as your system of record with no repo at all is a
supported path: [`docs/detection-home.md`](docs/detection-home.md) covers
making the workspace durable under git.

## Teach ADEF your data

Detections are only as good as knowledge of the data they query. ADEF never
connects to your SIEM — you run one export, ADEF does the rest:

```bash
adef schema recipe                     # the exact field-export command for YOUR SIEM
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

**The mental model behind the merge step.** SIEMs often expose one underlying
fact as *two* fields with *two* value formats. In Splunk, a single logon
failure carries both the raw event field and its CIM-normalized sibling:

```
Status = 0xc000006d        # raw field: NTSTATUS codes
status = failure           # normalized field, derived from Status
```

`reshape` merges such pairs into one declared field with `aliases:`, so a rule
written against *either* spelling passes `adef schema check`. But in your SIEM
each spelling only matches **its own** values — `status=failure` and
`Status=0xc000006d` both fire; `Status=failure` is a syntactically fine query
that matches nothing, forever. Two rules follow: pair values with the spelling
they were harvested from, and when reshape marks a merge `[SUSPECT]` (the two
spellings' observed values have nothing in common), read the values it shows —
same information in two formats (`SYSTEM` vs `NT AUTHORITY\SYSTEM`) means one
field, keep the merge; different information (code-signing publishers vs event
descriptions) means two unrelated fields that collide on spelling — split them
with `--no-fold`, or let `--interactive` walk you through each pair. Better
still, with the Claude plugin installed, ask the `schema-declaration` skill to
drive the whole flow: the keep-or-split call requires knowing what a field *is*
(a code-signing publisher? a CIM constant?), and that domain knowledge is
exactly what an agent session adds over a y/n prompt.

## See your coverage — honestly

```bash
adef detection tag-mitre D-0007 T1547.001    # enrich, validated against ATT&CK
adef coverage                                # coverage QUALITY report
adef coverage --navigator layer.json         # scored MITRE Navigator layer
```

Not a vanity heatmap: `coverage` separates **solid** techniques (multiple
reviewed detections) from **fragile** ones (a single rule, or nothing but
unreviewed inferences), flags techniques riding a single log source, and
calls out *fictional coverage* — mapped technique IDs that don't exist in
ATT&CK. Every mapping is validated against a shipped ATT&CK snapshot
(`adef attack show T1059.001`; refresh it anytime with `adef attack refresh`).

## Work the lifecycle

```bash
adef detection list --platform windows --needs-review no_mitre
adef detection show D-0042             # record + query + journal history
adef detection observe D-0042 --note "checked 30d of process_create events"
adef detection refine  D-0042          # similarity → overlap → verification chain
adef detection govern  D-0042
adef detection evolve  D-0042 --note "raised threshold, FP rate halved"
```

Every transition is a timestamped journal entry. Six months from now, the
next engineer reads *why* the threshold is what it is.

## Claude plugin & MCP

The repo doubles as a plugin marketplace: one install wires up the `adef-mcp`
server, the catalog-onboarding, catalog-sync, detection-explorer,
coverage-review, mitre-tagger, detection-author, and schema-declaration skills,
and the profile-author sub-agent.

```
pip install -e ".[mcp]"   # adef-mcp needs the mcp extra — the base install lacks it
/plugin marketplace add Nebulock-Inc/agentic-detection-engineering-framework
/plugin install adef
/reload-plugins           # skills + MCP load on reload, not on install
```

MCP alone works with Cursor/Copilot; the plugin is the Claude-native layer.
With it installed, "help me set up schemas for my Splunk environment" drives
the whole recipe → reshape → ingest flow conversationally.

## ADEF and ATHF — paired siblings, not successor

ADEF and ATHF are *paired siblings*. ATHF owns the threat-hunting lifecycle (LOCK pattern, hunts repo). ADEF owns the detection-engineering lifecycle (FORGE pattern, journals repo). Hunts that earn detections cross the bridge via `adef hunt-promote H-XXXX`. Both frameworks share the same Click + entry-point + FastMCP shape, so analysts and agents that learn one recognize the other immediately.

## Maturity Model

| Level | Name | What you get |
|---|---|---|
| L0 | Ad-hoc | Rules in chat threads and tickets |
| L1 | Documented | Rules in a repo with metadata |
| L2 | Searchable | AI reads coverage, performance, overlap |
| L3 | Generative | AI proposes/drafts/backtests rules from intel or hunts |
| L4 | Agentic | Autonomous tuning, deprecation recommendations, scheduled gap sweeps |

See [`docs/maturity-model.md`](docs/maturity-model.md) for full descriptions and time-to-value estimates.

## Why ADEF

[`docs/why-adef.md`](docs/why-adef.md) is the adoption guide — what problem ADEF solves, where it fits in your stack, what you give up to use it, and how to bring it into an existing detection program.

## North-Star v1 Demo

The target experience — not yet built:

```bash
adef detection new --from-intel https://example.com/cti-report
```

In minutes: a backtested, MITRE-tagged, deduplicated, journalled detection. Six months later, ADEF flags it for tuning when noise crosses threshold. See [`docs/north-star.md`](docs/north-star.md).

## License

MIT — see [`LICENSE`](LICENSE).
