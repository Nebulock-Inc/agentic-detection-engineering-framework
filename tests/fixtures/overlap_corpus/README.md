# Overlap Corpus Fixtures

Static, hand-authored catalog records in the bare-predicate SQL shape a
streaming rule is often stored as (a parenthesized WHERE-only condition with a
`tenant_id` placeholder, backtick-quoted dotted fields, ATT&CK tags). Used by
`tests/test_cross_validation_overlap_corpus.py` to assert the native
Refine-chain agents (Tasks 2, 3, 5) correctly classify:

- D-1001 / D-1002 — near-duplicate (same predicate, different title)
- D-1001 / D-1003 — redundant (D-1003's predicate is a strict superset of D-1001's)
- D-1001 / D-1004 — complementary (same technique, different detection logic)
- D-1005 — different technique entirely; must never be compared against the D-1001 cluster
- D-1006 — `custom_sql` engine, a name another platform's taxonomy might use,
  outside ADEF's closed 4-engine set — must fail Verification
