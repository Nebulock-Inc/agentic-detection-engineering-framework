"""ADEF's closed, CI-enforced engine taxonomy.

The single canonical copy — `tests/test_no_new_engine_types.py` scans for any
*other* place a 4-element literal list like this appears, so every consumer
must import this constant rather than re-typing it.
"""

from __future__ import annotations

ALLOWED_ENGINES: frozenset[str] = frozenset({"sigma", "sql", "sch_sql", "composite"})

__all__ = ["ALLOWED_ENGINES"]
