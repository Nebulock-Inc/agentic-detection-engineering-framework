# Overlap Corpus Fixtures

Static, hand-authored catalog records modeled on real detect-vault patterns
(WHERE-only predicate shape, `nebulock_organization_id` placeholder, MITRE
tag conventions from detect-vault's `AGENTS.md`) — not a live copy of any
detect-vault rule and not kept in sync with that repo. Used by
`tests/test_cross_validation_detect_vault_patterns.py` to assert the native
Refine-chain agents (Tasks 2, 3, 5) correctly classify:

- D-1001 / D-1002 — near-duplicate (same predicate, different title)
- D-1001 / D-1003 — redundant (D-1003's predicate is a strict superset of D-1001's)
- D-1001 / D-1004 — complementary (same technique, different detection logic)
- D-1005 — different technique entirely; must never be compared against the D-1001 cluster
- D-1006 — `atomic_sql` engine, which is valid in detect-vault's 5-engine model
  but outside ADEF's closed 4-engine set — must fail Verification
