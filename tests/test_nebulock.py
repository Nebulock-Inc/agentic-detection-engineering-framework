"""Nebulock rule-export support: recognizer + envelope-driven extractor.

Nebulock exports rules as JSON (the ``/public/v1/rules`` shape). ADEF supports
the *format* the same way it supports Sigma / Splunk ESCU / Panther — a
content-signature recognizer plus a metadata extractor, read-only, offline. It
does NOT pull rules from the API; a user exports the JSON and points
``adef catalog`` at it.

The fixtures below are trimmed from a real export (one rule per rule_type). The
real workload is ``atomic_sql`` (dominant) and ``scheduled_sql``; ``sigma`` is
rare but must round-trip. Metadata lives at the envelope level; ``content`` holds
the query. MITRE rides the ``attack.id.Txxxx`` tag form, platform the ``os.<name>``
tag, and data_source the ``nebulock_im_source`` literal in the query.
"""

from __future__ import annotations

import json

from adef.core.rule_discovery import (
    NOT_A_RULE,
    SUPPORTED,
    _extract_nebulock,
    discover_rules,
    recognize,
)

# One rule per rule_type, trimmed from a live export.
ATOMIC_SQL = {
    "rule_id": "6ebf3b7c-a9a9-4f8c-9f89-b590fbdecd1b",
    "rule_type": "atomic_sql",
    "title": "T1053.005 Scheduled Task Creation via Unusual Parent Process",
    "severity": 70,
    "status": "inactive",
    "tags": [
        "attack.tactic.persistence",
        "attack.technique.scheduled-task-job.scheduled-task",
        "attack.id.T1053.005",
        "os.windows",
    ],
    "content": {
        "content_type": "atomic_sql",
        "sql_query": (
            "nebulock_im_source = 'im-process_create'\n"
            "AND `endpoint.os.type` = 'Win'\n"
            "AND `process.name` = 'schtasks.exe'"
        ),
    },
}

SCHEDULED_SQL = {
    "rule_id": "2bfd3d04-8b78-49ee-9f48-d9168740eab5",
    "rule_type": "scheduled_sql",
    "title": "Suspicious Process Execution from VS Code Extension",
    "severity": 0,
    "status": "inactive",
    "tags": [
        "attack.tactic.initial-access",
        "attack.id.T1195.002",
        "os.windows",
    ],
    "content": {
        "content_type": "scheduled_sql",
        "query": (
            "time >= now() - INTERVAL 3 HOUR AND time < now()\n"
            "  AND nebulock_im_source = 'im-process_create'\n"
            "  AND `process.parent.name` = 'code.exe'"
        ),
        "schedule": "0 * * * *",
        "entity_fields": ["actor_identifier", "endpoint.uid"],
    },
}

SIGMA = {
    "rule_id": "e019da93-3c5f-4cd0-926b-9896452a0b80",
    "rule_type": "sigma",
    "title": "Sigma-authored rule",
    "severity": 80,
    "status": "inactive",
    "tags": ["attack.id.T1059.001", "os.linux"],
    "content": {
        "content_type": "sigma",
        "sql_query": "nebulock_im_source = 'im-process_create' AND `process.name` = 'powershell'",
        "original_yaml": "title: Sigma-authored rule\nlogsource:\n  product: linux\n",
    },
}


def _write(tmp_path, name, payload):
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Recognition — JSON export is claimed as `nebulock`, non-rules are not
# --------------------------------------------------------------------------- #
def test_recognizes_single_rule_object():
    r = recognize("rule.json", json.dumps(ATOMIC_SQL))
    assert r.format == "nebulock"
    assert r.support == SUPPORTED


def test_recognizes_api_envelope():
    envelope = {"data": [ATOMIC_SQL, SCHEDULED_SQL], "meta": {}, "error": None}
    r = recognize("export.json", json.dumps(envelope))
    assert r.format == "nebulock"


def test_recognizes_bare_array():
    r = recognize("export.json", json.dumps([ATOMIC_SQL, SIGMA]))
    assert r.format == "nebulock"


def test_plain_json_is_not_a_rule():
    # JSON without the Nebulock signature must not be claimed.
    r = recognize("package.json", json.dumps({"name": "x", "version": "1.0"}))
    assert r.support == NOT_A_RULE


def test_invalid_json_is_not_a_rule():
    r = recognize("notes.txt", "this is not json { rule_id")
    assert r.support == NOT_A_RULE


# --------------------------------------------------------------------------- #
# Extraction — envelope-driven metadata, query by rule_type
# --------------------------------------------------------------------------- #
def test_atomic_sql_extraction():
    rule = _extract_nebulock(json.dumps(ATOMIC_SQL))[0]
    assert rule.format == "nebulock"
    assert rule.engine == "sql"
    assert rule.rule_uuid == "6ebf3b7c-a9a9-4f8c-9f89-b590fbdecd1b"
    assert rule.title.startswith("T1053.005 Scheduled Task")
    assert rule.platform == "windows"  # from os.windows tag
    assert rule.mitre == ("T1053.005",)  # from attack.id tag
    assert rule.data_source == "im-process_create"  # from nebulock_im_source literal
    assert "schtasks.exe" in rule.query_text


def test_scheduled_sql_reads_query_field():
    # scheduled_sql puts the query in `content.query`, not `sql_query`.
    rule = _extract_nebulock(json.dumps(SCHEDULED_SQL))[0]
    assert "code.exe" in rule.query_text
    assert rule.mitre == ("T1195.002",)
    assert rule.data_source == "im-process_create"


def test_sigma_subtype_extraction():
    rule = _extract_nebulock(json.dumps(SIGMA))[0]
    assert rule.engine == "sql"  # Nebulock sigma folds to sql like the rest
    assert rule.platform == "linux"
    assert rule.mitre == ("T1059.001",)


def test_envelope_fans_out_to_multiple_rules():
    envelope = {"data": [ATOMIC_SQL, SCHEDULED_SQL, SIGMA]}
    rules = _extract_nebulock(json.dumps(envelope))
    assert len(rules) == 3
    assert {r.rule_uuid for r in rules} == {
        ATOMIC_SQL["rule_id"],
        SCHEDULED_SQL["rule_id"],
        SIGMA["rule_id"],
    }


def test_malformed_content_does_not_sink_the_envelope():
    """One rule with a non-dict `content` must not discard its siblings.

    `content: null` was already handled (`or {}`), but a truthy non-dict
    (string/list) hit `.get()` and raised, and the single list comprehension
    took the whole envelope down with it — losing every good rule too.
    """
    for bad_content in (None, "oops", [1, 2]):
        bad = {"rule_id": "bad", "rule_type": "atomic_sql", "content": bad_content}
        rules = _extract_nebulock(json.dumps({"data": [ATOMIC_SQL, bad]}))
        assert {r.rule_uuid for r in rules} == {ATOMIC_SQL["rule_id"], "bad"}
        good = next(r for r in rules if r.rule_uuid == ATOMIC_SQL["rule_id"])
        bad_rule = next(r for r in rules if r.rule_uuid == "bad")
        assert not good.needs_review  # the good rule survives fully extracted
        assert bad_rule.needs_review  # the bad one is kept, flagged, not crashed


# --------------------------------------------------------------------------- #
# End-to-end through the walker — a JSON export in a repo yields all rules
# --------------------------------------------------------------------------- #
def test_discover_rules_through_walker(tmp_path):
    _write(tmp_path, "export.json", {"data": [ATOMIC_SQL, SCHEDULED_SQL, SIGMA]})
    rules = list(discover_rules(tmp_path))
    assert len(rules) == 3
    # All fully extracted → none flagged for review (platform + MITRE present).
    assert all(not r.needs_review for r in rules)
    assert all(r.source_hash for r in rules)  # walker stamped the file hash
    assert all(r.path.name == "export.json" for r in rules)


def test_rule_missing_platform_and_mitre_needs_review():
    bare = {
        "rule_id": "no-meta",
        "rule_type": "atomic_sql",
        "title": "bare",
        "tags": [],
        "content": {"sql_query": "SELECT 1"},
    }
    rule = _extract_nebulock(json.dumps(bare))[0]
    assert rule.needs_review
