# ADEF examples

A self-contained demo you can run end to end against a scratch workspace.

- `demo-rules/` — a small mixed-format rules repo (Splunk `savedsearches.conf`
  + Sigma) targeting a lab index (`thrunt`) with Sysmon, Zeek, Cisco ASA,
  Apache, and eCAR data. One rule (`broad_hunt_bogus_field.conf`) deliberately
  references a nonexistent field so `schema check` has something to find.
- `adef-sources-thrunt.yml` — the matching data-source declaration: 14 sources
  scoped to `{index: thrunt, sourcetype: ...}`, generated from a Splunk
  `fieldsummary` export.

```bash
export ADEF_WORKSPACE=$(mktemp -d)
adef catalog examples/demo-rules
adef detection list
adef detection list --platform windows --report json
adef detection show D-0001
adef schema ingest examples/adef-sources-thrunt.yml
adef schema check
```
