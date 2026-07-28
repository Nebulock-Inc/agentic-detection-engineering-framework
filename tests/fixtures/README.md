# Shared test exports

SIEM field exports (from `adef schema recipe` queries) committed for team-wide
testing of `adef schema reshape` / `ingest`.

**Lab or sanitized data only.** Exports carry harvested field values —
hostnames, usernames, IPs. Never commit an export from a real/customer
environment; keep those local (e.g. an untracked scratch dir).

Name files `<platform>-<recipe or sourcetype>.csv`, e.g.
`splunk-fieldsummary-wineventlog.csv`.
