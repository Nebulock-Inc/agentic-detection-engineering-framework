# ADEF examples

A self-contained demo you can run end to end against a scratch workspace.

- `demo-rules/` — a small mixed-format rules repo (Splunk `savedsearches.conf`
  + Sigma) targeting a lab index (`thrunt`) with Sysmon, Zeek, Cisco ASA,
  Apache, and eCAR data. One rule (`broad_hunt_bogus_field.conf`) deliberately
  references a nonexistent field so `schema check` has something to find.
- `adef-sources-thrunt.yml` — the matching data-source declaration: 14 sources
  scoped to `{index: thrunt, sourcetype: ...}`, generated from a Splunk
  `fieldsummary` export.
- `inhouse-rules/` + `profiles/acme-hunt.yml` — a made-up rule format no
  built-in recognizer claims, with its ready-made extraction profile: the
  quickstart's hands-on demo of the profile loop (unclaimed → validate →
  install → catalogued).
- `weekly-metrics.yml` — a detection-health capture keyed to `D-0009`
  ("Suspicious mshta.exe child process"), so the Evolve half of the arc runs
  too: 236 of 238 signals adjudicated false positive, none true in four months,
  which the recommenders turn into a `tune` verdict. Invented numbers; the
  arithmetic is real.

```bash
export ADEF_WORKSPACE=$(mktemp -d)
adef schema ingest examples/adef-sources-thrunt.yml   # first: catalog inherits platforms from these
adef catalog examples/demo-rules
adef detection list
adef detection list --platform windows --report json
adef detection show D-0001
adef schema check

adef ingest examples/weekly-metrics.yml                # hand over the numbers
adef health show D-0009                                # what was stored + what's derived
adef detection evolve D-0009 --chain                   # → keep / tune / deprecate, in the journal
```

See [`docs/quickstart.md`](../docs/quickstart.md) for the full walkthrough.
