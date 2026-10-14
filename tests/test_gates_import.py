"""GATES document import — `adef hunt-promote --gates`.

Two fixtures, deliberately:

* ``CANONICAL_DOC`` is the contract as pinned down in ATHF's
  ``AGENT_MEMORY_SCHEMA.md`` — slug ``candidate_id``, canonical verdict enum
  (``RECURRING_HUNT`` included), float ``base_score``, ``detection_logic.query``
  for every engine. This is what new documents look like.
* ``DOC`` is the shape documents were written in *before* that contract was
  pinned: ordinal ``detection_id``, ``TIME-BOX`` with a hyphen, ``base_score``
  as ``"5/5"``, ``RECURRING_HUNT`` smuggled in via ``classification``, and a
  sigma rule body inlined instead of placed in ``query``. Those documents exist,
  so the importer keeps reading them; every hazard is pinned by a test here so
  the back-compat paths can't rot silently.
"""

from __future__ import annotations

import textwrap

import pytest
import yaml
from click.testing import CliRunner

from adef.commands.hunt_promote import hunt_promote
from adef.core.catalog import Catalog, CatalogError, record_path, record_platforms
from adef.core.gates import (
    _STATUS_MAP,
    GatesError,
    import_gates,
    journal_note,
    parse_gates,
    record_from_gates,
    superseded_ordinal_refs,
)
from adef.core.journal import Journal

pytestmark = pytest.mark.unit


DOC = textwrap.dedent(
    """
    schema_version: "2.0"
    hunt_metadata:
      hunt_id: H-0041
      title: "MCP Server Process Spawn Chain Detection"
      techniques: [T1059.007, T1555.001]
      platforms: [macOS]
      hunt_outcomes:
        data_sources: [EDR, Sysmon]   # nested, per AGENT_MEMORY_SCHEMA.md
    gates_validation:
      verdict: PROMOTE
    detections:
      - detection_id: 1
        name: "Keychain Extraction by Non-Application Parent"
        gates_assessment:
          verdict: PROMOTE
          base_score: "5/5"          # schema documents the string form
          criteria: {generalizable: PASS, additive: PASS}
          scoring_rationale: {g_evidence: "Behavioural, not IOC."}
          pattern_learned: "Parent-process provenance is the discriminator."
        deployment:
          engine: sigma
          status: EXPERIMENTAL
          severity: high
          detection_logic:           # sigma form: inline mapping, no `query:`
            selection:
              process.name: security
            condition: selection
          entities:
            - {name: endpoint.name, type: endpoint}
          observables:
            - {name: process.command_line, type: command_line}
          alert_configuration:
            throttle: {entity: endpoint.name, duration: 1h}
          mitre_attack: [T1555.001]
          references: ["https://attack.mitre.org/techniques/T1555/001/"]
      - detection_id: 2
        name: "Malicious Remote MCP Infrastructure"
        gates_assessment:
          verdict: TIME-BOX          # hyphen spelling, per SKILL.md
          base_score: 3.5
        deployment:
          engine: sql
          severity: critical
          detection_logic:
            query: "SELECT 1"
            description: "IOC layer."
      - detection_id: 5
        name: "Ungoverned MCP Fleet Inventory"
        gates_assessment:
          verdict: HOLD
          classification: RECURRING_HUNT
          base_score: 2.0
    """
).strip()


CANONICAL_DOC = textwrap.dedent(
    """
    schema_version: "2.0"
    hunt_metadata:
      hunt_id: H-0041
      title: "MCP Server Process Spawn Chain Detection"
      techniques: [T1059.007, T1555.001]
      platforms: [macOS]
      hunt_outcomes:
        data_sources: [EDR, Sysmon]   # nested, per AGENT_MEMORY_SCHEMA.md
    gates_validation:
      verdict: PROMOTE
    detections:
      - candidate_id: keychain-access-non-app-parent
        name: "Keychain Extraction by Non-Application Parent"
        gates_assessment:
          verdict: PROMOTE
          base_score: 5.0
          criteria:
            generalizable: PASS
            additive: PASS
            tunable: PASS
            exposure_tested: PASS
            sustainable: PASS
        deployment:
          engine: sigma
          status: EXPERIMENTAL
          severity: high
          detection_logic:
            query: |
              selection:
                process.name: security
              condition: selection
            description: "Keychain read by a parent that isn't an application."
          mitre_attack: [T1555.001]
      - candidate_id: ungoverned-mcp-fleet-inventory
        name: "Ungoverned MCP Fleet Inventory"
        gates_assessment:
          verdict: RECURRING_HUNT      # first-class verdict, no `classification`
          base_score: 2.0
    """
).strip()


def _write(tmp_path, text=None, name="H-0041_GATES.yaml"):
    path = tmp_path / "hunt-promotion-analysis" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DOC if text is None else text, encoding="utf-8")
    return path


def test_canonical_contract_parses_and_imports(tmp_path, monkeypatch):
    """The fixed contract: slug ids, canonical verdicts, uniform detection_logic."""
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    path = _write(tmp_path, CANONICAL_DOC)
    doc = parse_gates(path)

    assert [c.local_id for c in doc.candidates] == [
        "keychain-access-non-app-parent",
        "ungoverned-mcp-fleet-inventory",
    ]
    # RECURRING_HUNT read straight from `verdict` — no two-field decode.
    assert [c.verdict for c in doc.candidates] == ["PROMOTE", "RECURRING_HUNT"]
    assert [c.deployable for c in doc.candidates] == [True, False]
    assert doc.candidates[0].hunt_ref == "H-0041#keychain-access-non-app-parent"

    results = import_gates(path)
    minted = [r for r in results if r.detection_id]
    assert len(minted) == 1  # RECURRING_HUNT builds nothing
    rec = Catalog(tmp_path / "ws").find_record(minted[0].detection_id)[1]
    assert "selection" in rec["query"]
    assert rec["description"] == "Keychain read by a parent that isn't an application."
    assert rec["hunt_ref"] == "H-0041#keychain-access-non-app-parent"

    # Re-import is idempotent on the slug, which is the whole point of the rename.
    assert {r.hunt_ref: r.detection_id for r in import_gates(path)} == {
        r.hunt_ref: r.detection_id for r in results
    }


def test_parse_normalizes_verdicts_and_scores(tmp_path):
    doc = parse_gates(_write(tmp_path))

    assert doc.hunt_id == "H-0041"
    assert doc.platform == "macos"
    verdicts = {c.local_id: c.verdict for c in doc.candidates}
    # "TIME-BOX" -> TIME_BOX; HOLD + classification -> the specific one.
    assert verdicts == {"1": "PROMOTE", "2": "TIME_BOX", "5": "RECURRING_HUNT"}
    # "5/5" coerces to a float rather than crashing or silently becoming 0.
    assert [c.base_score for c in doc.candidates] == [5.0, 3.5, 2.0]
    assert [c.deployable for c in doc.candidates] == [True, True, False]
    assert doc.candidates[0].hunt_ref == "H-0041#1"


def test_sigma_inline_logic_becomes_a_query(tmp_path):
    doc = parse_gates(_write(tmp_path))
    rec = record_from_gates("D-0001", doc.candidates[0], doc)

    # The sigma form has no `query:` key — the inline mapping must survive.
    assert "selection" in rec.query and "condition" in rec.query
    assert rec.description == ""  # sigma form carries no description
    assert rec.alert == {
        "severity": "high",
        "throttle": {"entity": "endpoint.name", "duration": "1h"},
    }
    assert rec.entities == [{"name": "endpoint.name", "type": "endpoint"}]
    assert rec.mitre == ["T1555.001"]
    assert rec.origin == "promoted"  # so `adef sync` leaves it alone
    assert rec.hunt_ref == "H-0041#1"
    assert rec.status == "draft"  # EXPERIMENTAL is not `ready`


def test_import_mints_only_deployable_verdicts(tmp_path, monkeypatch):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    results = import_gates(_write(tmp_path))

    assert len(results) == 3
    minted = {r.hunt_ref: r for r in results}
    # Deployable verdicts get a record + journal. The archival one gets neither and
    # no D-XXXX: the hunt decided against building it, so a permanent detection ID
    # would imply a rule that doesn't exist.
    assert minted["H-0041#1"].record_path is not None
    assert minted["H-0041#2"].record_path is not None
    assert minted["H-0041#5"].record_path is None
    assert minted["H-0041#5"].detection_id == ""
    deployed = [minted["H-0041#1"], minted["H-0041#2"]]
    assert all(r.journal_path is not None and r.journal_path.exists() for r in deployed)
    assert len({r.detection_id for r in deployed}) == 2  # distinct IDs

    # TIME_BOX is deployable but unfinished, so it lands in the review queue.
    catalog = Catalog(tmp_path / "ws")
    _path, data = catalog.find_record(minted["H-0041#2"].detection_id)
    assert data["needs_review"] is True
    assert "gates_time_box" in data["review_reasons"]


def test_reimport_updates_instead_of_duplicating(tmp_path, monkeypatch):
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    path = _write(tmp_path)
    first = {r.hunt_ref: r.detection_id for r in import_gates(path)}

    # Regenerating GATES for an edited hunt must not mint a second D-XXXX per
    # candidate — hunt_ref is the identity key.
    second = import_gates(path)
    assert {r.hunt_ref: r.detection_id for r in second} == first
    assert all(r.minted is False for r in second)
    assert first["H-0041#5"] == ""  # archival candidate never consumed an ID

    records = list(Catalog(tmp_path / "ws").iter_records())
    assert len(records) == 2  # two deployable candidates, not four


def test_rejects_engine_outside_adefs_four(tmp_path):
    bad = DOC.replace("engine: sigma", "engine: eql")
    doc = parse_gates(_write(tmp_path, bad))
    with pytest.raises(GatesError, match="eql"):
        record_from_gates("D-0001", doc.candidates[0], doc)


def test_dry_run_catches_what_the_real_run_would_reject(tmp_path, monkeypatch):
    """A dry run that can't predict failure is worse than no dry run."""
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    broken = yaml.safe_load(DOC)
    del broken["detections"][0]["deployment"]["engine"]  # still verdict PROMOTE
    path = _write(tmp_path, yaml.safe_dump(broken))

    with pytest.raises(GatesError, match="no `deployment.engine`"):
        import_gates(path, dry_run=True)


def test_deployable_without_an_engine_is_an_error(tmp_path):
    raw = yaml.safe_load(DOC)
    del raw["detections"][0]["deployment"]["engine"]
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    with pytest.raises(GatesError, match="no `deployment.engine`"):
        record_from_gates("D-0001", doc.candidates[0], doc)


@pytest.mark.parametrize(
    ("gates_status", "expected"),
    [
        # The current enum, renamed 2026-09-27.
        ("TEST", "draft"),
        ("PRODUCTION", "ready"),
        ("DISABLED", "deprecated"),
        # The pre-rename spelling of the same three states. Documents written
        # against it are already on disk, so it stays readable.
        ("EXPERIMENTAL", "draft"),
        ("ACTIVE", "ready"),
        ("INACTIVE", "deprecated"),
    ],
)
def test_both_status_spellings_map_to_adef_status(tmp_path, gates_status, expected):
    raw = yaml.safe_load(DOC)
    raw["detections"][0]["deployment"]["status"] = gates_status
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    assert record_from_gates("D-0001", doc.candidates[0], doc).status == expected


def test_unknown_status_is_rejected_not_defaulted_to_draft(tmp_path):
    """`PRODUCTION` mistyped used to read as `draft`, so a deployed detection
    looked unbuilt — the silent state change the verdict check also guards."""
    raw = yaml.safe_load(DOC)
    raw["detections"][0]["deployment"]["status"] = "PRODUCTON"
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    with pytest.raises(GatesError, match="not a GATES status") as exc:
        record_from_gates("D-0001", doc.candidates[0], doc)
    # Every accepted spelling, not the three current ones: the message hand-listed
    # TEST/PRODUCTION/DISABLED while the map also accepts the legacy enum above, so
    # a typo in a legacy document was answered by calling that document's own
    # vocabulary invalid. Derived from `_STATUS_MAP` here too, so the next spelling
    # added to the map can't drift out of the message.
    assert all(status in str(exc.value) for status in _STATUS_MAP)


def test_absent_status_is_draft(tmp_path):
    doc = parse_gates(_write(tmp_path))
    # Second candidate carries no `status` at all — absent is not an error.
    assert record_from_gates("D-0002", doc.candidates[1], doc).status == "draft"


def test_narrative_markdown_is_not_importable(tmp_path):
    # HOLD/DROP/RECURRING_HUNT hunts emit a .md narrative with no `detections` list.
    path = tmp_path / "H-0060_GATES.md"
    path.write_text("# GATES Validation: H-0060\n\n**Verdict:** HOLD\n", encoding="utf-8")
    with pytest.raises(GatesError):
        parse_gates(path)


def test_dry_run_writes_nothing(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    results = import_gates(_write(tmp_path), dry_run=True)

    # Not even a directory: `--dry-run` against a path that turns out to be the
    # wrong workspace must not leave a scaffolded one behind. Asserted before
    # Catalog(ws) below, which creates `catalog/` itself.
    assert not ws.exists()
    assert len(results) == 3
    assert not list(Catalog(ws).iter_records())
    assert not list((ws / "journals").glob("D-*.md"))


def test_reimport_preserves_enrichment_and_journal_stage(tmp_path, monkeypatch):
    """A regenerated document refreshes the logic, not the engineer's work.

    `adef sync` guarantees enrichment survives a re-run; this path owes the same
    guarantee. Before the fix a re-import rewrote the record from the document
    (status/stage/owner/mitre back to their import-time defaults) and called
    `advance_stage(stage="find")`, dragging an advanced journal back to the start.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    path = _write(tmp_path)
    detection_id = next(r.detection_id for r in import_gates(path) if r.detection_id)

    catalog = Catalog(tmp_path / "ws")
    rec_path, data = catalog.find_record(detection_id)
    catalog.write_raw(
        rec_path,
        {**data, "status": "ready", "stage": "govern", "owner": "alice", "mitre": ["T1003"]},
    )
    journal = Journal(tmp_path / "ws" / "journals")
    journal.advance_stage(detection_id=detection_id, stage="govern", note="Deployed.")

    import_gates(path)

    _p, after = catalog.find_record(detection_id)
    assert (after["status"], after["stage"], after["owner"]) == ("ready", "govern", "alice")
    assert after["mitre"] == ["T1003"]
    assert after["created"] == data["created"]  # identity, not a fresh timestamp
    assert journal.read(detection_id).current_stage == "govern"


def test_duplicate_candidate_id_is_rejected(tmp_path):
    """Two candidates sharing an id collapse onto one `hunt_ref`, so the second
    import would silently overwrite the first's record."""
    dupe = DOC.replace("detection_id: 2", "detection_id: 1")
    with pytest.raises(GatesError, match="appears twice"):
        parse_gates(_write(tmp_path, dupe))


def test_unknown_verdict_is_rejected_not_read_as_archival(tmp_path):
    """A typo'd verdict used to fall through to "archival", so a deployable
    candidate vanished and the output looked like the hunt built nothing."""
    typo = yaml.safe_load(DOC)
    typo["detections"][0]["gates_assessment"]["verdict"] = "PROMOTED"
    with pytest.raises(GatesError, match="not a GATES verdict"):
        parse_gates(_write(tmp_path, yaml.safe_dump(typo)))

    missing = yaml.safe_load(DOC)
    del missing["detections"][0]["gates_assessment"]["verdict"]
    with pytest.raises(GatesError, match="not a GATES verdict"):
        parse_gates(_write(tmp_path, yaml.safe_dump(missing)))


def test_deployable_without_detection_logic_is_an_error(tmp_path):
    """An empty query is coverage that doesn't exist — the "fictional coverage"
    `adef coverage` reports on. Rejected at the boundary like a missing engine."""
    raw = yaml.safe_load(DOC)
    del raw["detections"][0]["deployment"]["detection_logic"]
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    with pytest.raises(GatesError, match="no detection logic"):
        record_from_gates("D-0001", doc.candidates[0], doc)


def test_data_source_is_read_from_hunt_outcomes_as_a_single_literal(tmp_path):
    """The contract nests `data_sources` under `hunt_metadata.hunt_outcomes`.

    Reading it off `hunt_metadata` directly left `data_source` empty on every real
    document — an empty `by_data_source` INDEX bucket and no log-source
    concentration in `adef coverage`. It is also a single literal, not a joined
    list, because that's the key `schema check` matches on.
    """
    doc = parse_gates(_write(tmp_path))
    assert doc.data_sources == ["EDR", "Sysmon"]
    assert record_from_gates("D-0001", doc.candidates[0], doc).data_source == "EDR"

    # A non-mapping `hunt_outcomes` must not crash the parse.
    raw = yaml.safe_load(DOC)
    raw["hunt_metadata"]["hunt_outcomes"] = "30 days"
    assert parse_gates(_write(tmp_path, yaml.safe_dump(raw))).data_sources == []


def test_candidate_data_source_wins_over_the_hunt_level_rollup(tmp_path):
    """A hunt spanning two feeds must not file every candidate under the first.

    The hunt-level list is ordered most-specific-first for a consumer that needs one
    value, which is right only while the candidates all read the same thing. A
    registry candidate in a process-creation hunt would otherwise be reported by
    `adef coverage` as going dark when process creation breaks.
    """
    raw = yaml.safe_load(DOC)
    raw["detections"][0]["deployment"]["data_source"] = "Windows registry modification events"
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    record = record_from_gates("D-0001", doc.candidates[0], doc)
    assert record.data_source == "Windows registry modification events"

    # A list where the contract says one literal is taken, not dropped: dropping it
    # silently substitutes another candidate's feed.
    raw["detections"][0]["deployment"]["data_source"] = ["Sysmon EID 13", "EDR"]
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    assert (
        record_from_gates("D-0001", doc.candidates[0], doc).data_source == "Sysmon EID 13"
    )


def test_a_scalar_where_the_contract_says_list_is_wrapped_not_iterated(tmp_path):
    """`techniques: T1059.001` must not become nine one-character techniques.

    Every list-typed field was read with a comprehension, which over a string
    iterates *characters* — so one hand-written scalar produced a record whose
    `mitre` was `['T','1','0','5','9','.','0','0','1']`, and `adef coverage` counted
    each as a mapped technique. The scalar is unambiguous, so it is wrapped.
    """
    raw = yaml.safe_load(DOC)
    raw["hunt_metadata"]["techniques"] = "T1059.001"
    raw["hunt_metadata"]["platforms"] = "windows"
    raw["hunt_metadata"]["hunt_outcomes"]["data_sources"] = "EDR"
    raw["detections"][0]["deployment"]["mitre_attack"] = "T1218.005"
    raw["detections"][0]["deployment"]["references"] = "https://example.invalid/w"
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    assert doc.techniques == ["T1059.001"]
    assert doc.platform == "windows"
    assert doc.data_sources == ["EDR"]
    record = record_from_gates("D-0001", doc.candidates[0], doc)
    assert record.mitre == ["T1218.005"]
    assert record.references == ["https://example.invalid/w"]


def test_non_mapping_criteria_is_a_document_error_not_a_traceback(tmp_path):
    """`dict()` on a list raises a bare ValueError.

    The CLI catches `(GatesError, CatalogError)`, so that escaped as a traceback with
    no mention of which file or candidate was malformed.
    """
    raw = yaml.safe_load(DOC)
    raw["detections"][0]["gates_assessment"]["criteria"] = ["generalizable: PASS"]
    with pytest.raises(GatesError, match="criteria"):
        parse_gates(_write(tmp_path, yaml.safe_dump(raw)))

    raw = yaml.safe_load(DOC)
    raw["detections"][0]["gates_assessment"]["scoring_rationale"] = "all good"
    with pytest.raises(GatesError, match="scoring_rationale"):
        parse_gates(_write(tmp_path, yaml.safe_dump(raw)))


def test_non_mapping_candidate_entry_is_rejected(tmp_path):
    """Skipping it would drop a candidate from the count, and "3 of 4 imported"
    reads as a verdict rather than a broken document."""
    raw = yaml.safe_load(DOC)
    raw["detections"].insert(1, "Malicious Remote MCP Infrastructure")  # a bare string
    # Inserted at list index 1, so the index-syntax message says `[1]`. This
    # asserted `[2]` while `enumerate` counted from 1 — the off-by-one was in
    # the test as well as the message.
    with pytest.raises(GatesError, match=r"`detections\[1\]` is str"):
        parse_gates(_write(tmp_path, yaml.safe_dump(raw)))


def test_non_list_detections_is_rejected(tmp_path):
    """Defaulting a malformed `detections` to empty reports "0 candidates", which
    reads identically to a hunt that genuinely built nothing."""
    raw = yaml.safe_load(DOC)
    raw["detections"] = {"1": raw["detections"][0]}  # mapping, not a list
    with pytest.raises(GatesError, match="expected a list"):
        parse_gates(_write(tmp_path, yaml.safe_dump(raw)))


def test_composite_engine_is_not_labelled_atomic(tmp_path):
    raw = yaml.safe_load(DOC)
    raw["detections"][0]["deployment"]["engine"] = "composite"
    doc = parse_gates(_write(tmp_path, yaml.safe_dump(raw)))
    assert record_from_gates("D-0001", doc.candidates[0], doc).kind == "composite"
    assert record_from_gates("D-0002", doc.candidates[1], doc).kind == "atomic"


def test_platform_from_the_document_cannot_escape_the_catalog(tmp_path, monkeypatch):
    """`platforms` is attacker-adjacent input that becomes a directory name. A
    traversal value used to write the record outside the workspace entirely.

    It is no longer a hard failure: a value that isn't usable as a path segment
    is simply not usable as a *bucket* either, so the record goes to
    `multi-platform` with `no_platform` queued for a human — the same answer an
    undeclared platform gets, and the same answer `adef catalog` gives for an
    unusable declaration value. The security property is what this test asserts,
    and it is unchanged — the traversal value no longer reaches a path at all.
    `record_path`'s refusal is still the backstop, and is still tested head-on
    over this exact value in `tests/test_catalog_path_guard.py`.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    raw = yaml.safe_load(DOC)
    raw["hunt_metadata"]["platforms"] = ["../../escaped"]
    path = _write(tmp_path, yaml.safe_dump(raw))

    result = CliRunner().invoke(hunt_promote, ["--gates", str(path)])
    assert result.exit_code == 0, result.output
    assert not list(tmp_path.glob("escaped*"))  # nothing beside the workspace
    written = sorted((tmp_path / "ws" / "catalog").rglob("D-*.yml"))
    assert [p.parent.name for p in written] == ["multi-platform"] * 2
    for record in written:
        assert "no_platform" in yaml.safe_load(record.read_text())["review_reasons"]


def test_the_escape_guard_does_not_refuse_an_unresolved_catalog_path(tmp_path):
    """The other half of the guard: it must not block the legitimate case.

    It compared a caller-supplied directory against a *resolved* candidate, and
    `record_path` is a module-level helper any caller can hand a raw path to — a
    workspace reached through a symlink (`/tmp` is one on macOS) resolved to a
    different string and every valid record was refused. A guard with a false
    positive that big gets deleted by the next person who trips over it.
    """
    (tmp_path / "ws" / "catalog").mkdir(parents=True)
    link = tmp_path / "via-symlink"
    link.symlink_to(tmp_path / "ws", target_is_directory=True)
    doc = parse_gates(_write(tmp_path))
    rec = record_from_gates("D-0001", doc.candidates[0], doc)
    assert record_path(link / "catalog", rec).name.startswith("D-0001-")


def test_a_rejected_candidate_does_not_half_import_the_document(tmp_path, monkeypatch):
    """Validation is a whole-document pass, so the first candidate isn't written
    only for the second to abort the run."""
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    raw = yaml.safe_load(DOC)
    raw["detections"][1]["deployment"]["engine"] = "eql"  # second candidate, not first
    path = _write(tmp_path, yaml.safe_dump(raw))

    with pytest.raises(GatesError, match="eql"):
        import_gates(path)
    assert not list(Catalog(tmp_path / "ws").iter_records())


def test_markdown_narrative_is_rejected_with_its_reason(tmp_path):
    """The likeliest wrong input is a HOLD hunt's .md, which has nothing to import.

    Without the suffix guard this failed inside the YAML scanner, reporting a
    column number instead of the reason.
    """
    md = tmp_path / "H-0206_GATES.md"
    md.write_text("# GATES Validation: H-0206\n**Verdict:** HOLD\n", encoding="utf-8")
    with pytest.raises(GatesError, match="markdown narrative"):
        parse_gates(md)


def test_deployment_prerequisites_reach_the_journal(tmp_path):
    """A CONDITIONAL is flagged `gates_conditional`, which is only actionable if
    the engineer can read *what* the prerequisite is without reopening the ATHF
    document. The contract puts them at
    ``deployment.operational_parameters.deployment_prerequisites``."""
    doc = tmp_path / "H-0102_GATES.yaml"
    doc.write_text(
        "hunt_metadata: {hunt_id: H-0102, platforms: [windows]}\n"
        "gates_validation: {verdict: CONDITIONAL}\n"
        "detections:\n"
        "- candidate_id: needs-allowlist\n"
        "  name: Needs an allowlist\n"
        "  gates_assessment: {verdict: CONDITIONAL, base_score: 3.5}\n"
        "  deployment:\n"
        "    engine: sql\n"
        '    detection_logic: {query: "SELECT 1"}\n'
        "    operational_parameters:\n"
        "      deployment_prerequisites:\n"
        "        - BLOCKING build the 7-shape allowlist\n"
        "        - Monthly token refresh cadence\n",
        encoding="utf-8",
    )
    parsed = parse_gates(doc)
    note = journal_note(parsed.candidates[0], parsed)
    assert "Prerequisite: BLOCKING build the 7-shape allowlist" in note
    assert "Prerequisite: Monthly token refresh cadence" in note


def test_time_box_expiry_reaches_the_journal(tmp_path):
    """TIME_BOX means "deploy with an expiry", and the expiry was being dropped.

    The four dates the contract marks REQUIRED for this verdict landed nowhere ADEF
    could see — leaving a record indistinguishable from a PROMOTE, which is how a
    campaign watchlist outlives its own IOCs.
    """
    doc = tmp_path / "H-0103_GATES.yaml"
    doc.write_text(
        "hunt_metadata: {hunt_id: H-0103, platforms: [network]}\n"
        "gates_validation: {verdict: TIME_BOX}\n"
        "detections:\n"
        "- candidate_id: ioc-watchlist\n"
        "  name: Campaign IOC watchlist\n"
        "  gates_assessment: {verdict: TIME_BOX, base_score: 2.0}\n"
        "  deployment:\n"
        "    engine: sql\n"
        '    detection_logic: {query: "SELECT 1"}\n'
        "    operational_parameters:\n"
        "      activation_date: '2026-09-20'\n"
        "      expiration_date: '2026-12-19'\n"
        "      review_date: '2026-12-15'\n"
        "      refresh_cycle_days: 90\n",
        encoding="utf-8",
    )
    parsed = parse_gates(doc)
    note = journal_note(parsed.candidates[0], parsed)
    assert "Expiration date: 2026-12-19" in note
    assert "Activation date: 2026-09-20" in note
    assert "Review date: 2026-12-15" in note
    # An int in YAML, so the value has to survive stringification, not just a date.
    assert "Refresh cycle days: 90" in note


def test_archival_candidates_write_nothing(tmp_path):
    """Archival verdicts are reported and nothing is written — no record (there is
    no rule) and no journal (no record means no hunt_ref, so a re-import would
    append a duplicate note every run)."""
    doc = tmp_path / "H-0101_GATES.yaml"
    doc.write_text(
        "hunt_metadata: {hunt_id: H-0101, platforms: [windows]}\n"
        "gates_validation: {verdict: HOLD}\n"
        "detections:\n"
        "- {candidate_id: a, gates_assessment: {verdict: HOLD, base_score: 2.5}}\n"
        "- {candidate_id: b, gates_assessment: {verdict: DROP, base_score: 4.0}}\n"
        "- {candidate_id: c, gates_assessment: {verdict: 'recurring hunt'}}\n",
        encoding="utf-8",
    )
    ws = tmp_path / "ws"
    results = import_gates(doc, workspace=ws)
    assert [r.verdict for r in results] == ["HOLD", "DROP", "RECURRING_HUNT"]
    assert not any(r.minted or r.record_path or r.journal_path for r in results)
    assert not list(ws.glob("journals/*.md"))


def test_unchanged_reimport_does_not_restack_the_same_note(tmp_path):
    """Found by running a real GATES document through three times.

    The note is derived wholly from the document, so re-running an unedited one
    produces it byte-identically. Appending that grew the journal by a full
    restatement per run — three runs, three identical copies — burying whatever a
    human wrote. A re-import that changes something still records it.
    """
    path = _write(tmp_path)
    ws = tmp_path / "ws"
    for _ in range(3):
        import_gates(path, workspace=ws)
    body = (ws / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert body.count("Promoted from ATHF hunt") == 1
    assert "GATES re-import" not in body

    # A changed verdict is still recorded — the skip is on identical text, not on
    # "this is a re-import".
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["detections"][0]["gates_assessment"]["base_score"] = 4.0
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    import_gates(path, workspace=ws)
    body = (ws / "journals" / "D-0001.md").read_text(encoding="utf-8")
    assert "GATES re-import" in body
    assert "BASE score 4/5" in body


# --- The first real GATES run (H-0068, 2026-09-30) found the next four. ---


def test_cross_platform_document_keeps_the_platforms_it_declared(tmp_path, monkeypatch):
    """`platform` is a directory name, so a two-platform hunt buckets to
    `multi-platform` — and discarding the list made the detection unfindable by
    either platform it actually covers."""
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    doc = tmp_path / "H-0068_GATES.yaml"
    doc.write_text(
        "hunt_metadata: {hunt_id: H-0068, platforms: [Windows, macOS]}\n"
        "gates_validation: {verdict: PROMOTE}\n"
        "detections:\n"
        "- candidate_id: kvm-descriptor\n"
        "  name: KVM descriptor string\n"
        "  gates_assessment: {verdict: PROMOTE, base_score: 4.5}\n"
        "  deployment: {engine: sql, detection_logic: {query: 'SELECT 1'}}\n",
        encoding="utf-8",
    )
    parsed = parse_gates(doc)
    assert parsed.platform == "multi-platform"
    assert parsed.platforms == ["windows", "macos"]

    ws = tmp_path / "ws"
    detection_id = next(r.detection_id for r in import_gates(doc, workspace=ws) if r.detection_id)
    _p, data = Catalog(ws).find_record(detection_id)
    assert data["platforms"] == ["windows", "macos"]

    # Reachable through either constituent *and* through the bucket.
    index = yaml.safe_load((ws / "catalog" / "INDEX.yml").read_text(encoding="utf-8"))
    for key in ("windows", "macos", "multi-platform"):
        assert index["by_platform"][key] == [detection_id]

    from adef.commands.detection import detection

    result = CliRunner().invoke(
        detection, ["list", "--workspace", str(ws), "--platform", "windows"]
    )
    assert result.exit_code == 0, result.output
    assert detection_id in result.output


def test_single_platform_record_does_not_carry_a_redundant_list(tmp_path):
    """`platform` already says it — emitting `platforms` too would add a key to
    every record in the tree for nothing."""
    doc = parse_gates(_write(tmp_path))  # platforms: [macOS]
    assert doc.platform == "macos"
    assert doc.platforms == []
    rec = record_from_gates("D-0001", doc.candidates[0], doc)
    assert "platforms" not in rec.to_yaml_dict()


def test_hunt_techniques_are_not_handed_to_every_unmapped_candidate(tmp_path):
    """The hunt's techniques are its *scope*; inheriting them per candidate gave
    `adef coverage` depth-N on each technique built from one real detection and
    N-1 guesses. Unmapped is honest and has a drain (`no_mitre` → `tag-mitre`),
    and the hunt scope goes to the journal so the tagger isn't guessing.
    """
    doc = parse_gates(_write(tmp_path))  # 2 deployable candidates, techniques on the hunt
    mapped, unmapped = doc.candidates[0], doc.candidates[1]
    assert record_from_gates("D-0001", mapped, doc).mitre == ["T1555.001"]

    rec = record_from_gates("D-0002", unmapped, doc)
    assert rec.mitre == []
    assert "no_mitre" in rec.review_reasons
    note = journal_note(unmapped, doc)
    assert "Hunt scope ATT&CK (unverified for this candidate): T1059.007, T1555.001" in note


def test_a_lone_candidate_still_inherits_the_hunt_techniques(tmp_path):
    """With one candidate there is nothing to confuse it with, so making someone
    retype the technique the document already states is busywork."""
    doc = tmp_path / "H-0069_GATES.yaml"
    doc.write_text(
        "hunt_metadata: {hunt_id: H-0069, platforms: [windows], techniques: [T1200]}\n"
        "gates_validation: {verdict: PROMOTE}\n"
        "detections:\n"
        "- candidate_id: only-one\n"
        "  gates_assessment: {verdict: PROMOTE, base_score: 4.5}\n"
        "  deployment: {engine: sql, detection_logic: {query: 'SELECT 1'}}\n"
        "- candidate_id: archival-sibling\n"
        "  gates_assessment: {verdict: RECURRING_HUNT, base_score: 3.0}\n",
        encoding="utf-8",
    )
    parsed = parse_gates(doc)
    # The archival sibling doesn't count — it gets no record to mis-attribute.
    assert parsed.deployable_count == 1
    assert record_from_gates("D-0001", parsed.candidates[0], parsed).mitre == ["T1200"]


def test_hunt_level_narrative_and_prerequisites_reach_the_journal(tmp_path):
    """`narrative_analysis` is the only place a deployable hunt's BASE reasoning is
    written down, and the hunt-level prerequisites include the blockers. Both were
    dropped on import, leaving ADEF holding verdicts with none of the argument.
    """
    doc = tmp_path / "H-0070_GATES.yaml"
    doc.write_text(
        "hunt_metadata: {hunt_id: H-0070, platforms: [windows]}\n"
        "gates_validation:\n"
        "  verdict: CONDITIONAL\n"
        "  prerequisites:\n"
        "    - {type: tooling, requirement: Run overlap validation, blocker: true, effort: 1 day}\n"
        "    - {type: data, requirement: Ingest auditd}\n"
        "detections:\n"
        "- candidate_id: only-one\n"
        "  gates_assessment: {verdict: CONDITIONAL, base_score: 3.5}\n"
        "  deployment: {engine: sql, detection_logic: {query: 'SELECT 1'}}\n"
        "narrative_analysis: |\n"
        "  ## BASE Criteria Scoring\n"
        "  **G - Generalizable: PASS** Tool signature, not an IOC.\n",
        encoding="utf-8",
    )
    parsed = parse_gates(doc)
    note = journal_note(parsed.candidates[0], parsed)
    assert "Hunt prerequisite (BLOCKER, tooling, 1 day): Run overlap validation" in note
    assert "Hunt prerequisite (data): Ingest auditd" in note
    assert "Tool signature, not an IOC." in note
    # Demoted, so the hunt's own headings can't pose as journal structure.
    assert "#### BASE Criteria Scoring" in note
    assert "\n## BASE" not in note


def test_a_document_without_a_description_does_not_erase_a_handwritten_one(tmp_path, monkeypatch):
    """`description`/`references` are derived from the document here, so an edited
    document must be able to change them — but a document that never said anything
    was overwriting prose a human had added to the record. Fill, don't clobber."""
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    path = _write(tmp_path)  # candidate 1 is the sigma form: no description
    detection_id = next(r.detection_id for r in import_gates(path) if r.detection_id)
    catalog = Catalog(tmp_path / "ws")
    rec_path, data = catalog.find_record(detection_id)
    assert not data.get("description")  # the document is silent on it
    assert data["references"] == ["https://attack.mitre.org/techniques/T1555/001/"]
    catalog.write_raw(
        rec_path, {**data, "description": "Written by a human.", "references": ["mine"]}
    )

    import_gates(path)

    _p, after = catalog.find_record(detection_id)
    assert after["description"] == "Written by a human."
    # The other half: a field the document *does* declare still refreshes from it,
    # or an edited document could never correct one.
    assert after["references"] == ["https://attack.mitre.org/techniques/T1555/001/"]


def test_reimport_does_not_requeue_a_hand_tagged_candidate(tmp_path, monkeypatch):
    """`tag-mitre` drains the `no_mitre` queue; a re-import must not refill it.

    `review_reasons` is computed from the *document*, before the record inherits
    the human's `mitre` — so a candidate the document doesn't map but someone
    tagged by hand got `no_mitre` pushed back onto it by every re-import, undoing
    the enrichment pass on each nightly run. The verdict-derived reason is
    untouched: it is still a TIME_BOX, and that is the document's to say.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    path = _write(tmp_path)
    import_gates(path)
    catalog = Catalog(tmp_path / "ws")
    # Candidate 2 — unmapped by the document, and with two deployable candidates
    # the hunt scope is not inherited, so it lands in the `no_mitre` queue.
    rec_path, data = next(
        (p, d) for _i, p, d in catalog.iter_records() if "no_mitre" in (d.get("review_reasons") or [])
    )
    assert data["review_reasons"] == ["no_mitre", "gates_time_box"]
    catalog.write_raw(
        rec_path,
        {**data, "mitre": ["T1071.001"], "review_reasons": ["gates_time_box"], "needs_review": True},
    )

    import_gates(path)

    _p, after = catalog.find_record(data["id"])
    assert after["mitre"] == ["T1071.001"]
    assert after["review_reasons"] == ["gates_time_box"]  # not back to no_mitre
    assert after["needs_review"] is True  # still unfinished, for the other reason


def test_an_undeclared_platform_is_flagged_not_filed_as_cross_platform(tmp_path, monkeypatch):
    """`multi-platform` is both the cross-platform bucket and the unknown one.

    So the bucket alone can't tell "runs everywhere" from "nobody said", and the
    second was becoming silent coverage in the INDEX. The declared list breaks the
    tie: empty bucket plus empty list means undeclared → `no_platform`, the same
    reason `catalog` raises when it can't infer one.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    silent = DOC.replace("  platforms: [macOS]\n", "")
    import_gates(_write(tmp_path, silent))

    catalog = Catalog(tmp_path / "ws")
    for _id, _p, data in catalog.iter_records():
        assert data["platform"] == "multi-platform"
        assert "no_platform" in data["review_reasons"]
        assert data["needs_review"] is True

    # The genuinely cross-platform case keeps the same bucket and is *not* flagged:
    # it declared its platforms, ADEF just can't file a record under two directories.
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws2"))
    both = DOC.replace("platforms: [macOS]", "platforms: [macOS, windows]")
    import_gates(_write(tmp_path, both, name="H-0041b_GATES.yaml"))
    for _id, _p, data in Catalog(tmp_path / "ws2").iter_records():
        assert (data["platform"], data["platforms"]) == ("multi-platform", ["macos", "windows"])
        assert "no_platform" not in data["review_reasons"]


@pytest.mark.parametrize(
    "declared",
    [
        "Windows 11",  # wrong charset: a space
        "w" * 256,  # right charset, one byte over what `record_path` will write
    ],
    ids=["not-a-segment", "too-long-for-a-directory"],
)
def test_a_single_unusable_platform_is_queued_not_fatal(tmp_path, monkeypatch, declared):
    """`platforms: [Windows 11]` is a reasonable thing to write and not a bucket.

    It used to become the bucket verbatim and then kill the whole import on
    `record_path`'s refusal — a message about path segments, for a field the
    author filled in correctly by their own lights. Unusable now means the same
    thing an undeclared platform means: `multi-platform` plus `no_platform`.

    Both members of "unusable" are here because only the charset one was, and
    `safe_platform`'s pattern had no length bound: a 256-character platform
    passed every check it makes, became the bucket with *nothing* flagged, and
    died at write time on the one refusal this whole helper exists to pre-empt.
    Two gates, one failure mode — name which member you used.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    raw = DOC.replace("platforms: [macOS]", f"platforms: ['{declared}']")
    import_gates(_write(tmp_path, raw))

    for _id, _p, data in Catalog(tmp_path / "ws").iter_records():
        assert data["platform"] == "multi-platform"
        # Flagged: the declared list is non-empty, so the undeclared-platform
        # predicate had to stop reading "they said something" as "they said
        # something usable" or this record would have passed as settled coverage.
        assert "no_platform" in data["review_reasons"]
        assert data["platforms"] == [declared.lower()]  # kept verbatim for the reviewer


def test_an_all_archival_document_creates_no_workspace_directories(tmp_path, monkeypatch):
    """"Archival verdicts write nothing" was false for the whole-document case.

    `Catalog(ws)` and `Journal(journals_dir)` both mkdir on construction, so a
    document of nothing but HOLDs scaffolded `catalog/` and `journals/` in a
    directory that was never a workspace — `adef init`'s job, done by accident.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    raw = yaml.safe_load(DOC)
    for entry in raw["detections"]:
        entry["gates_assessment"]["verdict"] = "HOLD"
        entry["gates_assessment"].pop("classification", None)
    results = import_gates(_write(tmp_path, yaml.safe_dump(raw)))

    assert [r.detection_id for r in results] == ["", "", ""]
    assert not (tmp_path / "ws").exists()


def test_two_candidates_from_one_document_cannot_clobber_each_other(tmp_path, monkeypatch):
    """`Catalog.write`'s collision guard reads `rule_ref` to tell "same detection,
    re-slugged" from "two detections, one ID". Every candidate promoted from one
    GATES document shares that `rule_ref`, so there the guard saw two distinct
    detections as one and *unlinked* the sibling's record. `hunt_ref` is the
    per-candidate identity, and is what decides it when both records carry one.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    ws = tmp_path / "ws"
    doc = parse_gates(_write(tmp_path))
    first, second = (c for c in doc.candidates if c.deployable)
    catalog = Catalog(ws)
    kept = catalog.write(record_from_gates("D-0001", first, doc))

    collision = record_from_gates("D-0001", second, doc)  # same ID, other candidate
    # The premise: identical `rule_ref` (one document), different `hunt_ref`.
    assert collision.rule_ref == yaml.safe_load(kept.read_text())["rule_ref"]
    assert collision.hunt_ref != yaml.safe_load(kept.read_text())["hunt_ref"]
    with pytest.raises(CatalogError, match="clobber"):
        catalog.write(collision)
    assert kept.exists()  # refused, not migrated


def test_a_technique_id_that_isnt_in_attack_is_flagged(tmp_path, monkeypatch):
    """The catalog path validates mapped IDs against the ATT&CK reference; this one
    didn't. The IDs come from a document an agent wrote outside ADEF, and a bogus
    one is counted in `by_technique` and in coverage depth exactly like a real
    one — the "fictional coverage" `adef coverage` reports, arriving unflagged."""
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    bogus = DOC.replace("mitre_attack: [T1555.001]", "mitre_attack: [T9999.123]")
    import_gates(_write(tmp_path, bogus))

    data = next(
        d for _i, _p, d in Catalog(tmp_path / "ws").iter_records() if d["mitre"] == ["T9999.123"]
    )
    assert "invalid_mitre" in data["review_reasons"]
    assert data["needs_review"] is True


def test_a_long_candidate_name_does_not_crash_the_import_midway(tmp_path, monkeypatch):
    """The slug is a filename and the `name` comes from outside ADEF.

    Uncapped, a long name raised `OSError: File name too long` out of
    `catalog.write` — uncaught, mid-loop, with earlier candidates already written
    and no INDEX (`rebuild_index` runs after the loop). `--dry-run` could not
    predict it either: `record_path` only resolves, and resolving an overlong
    component succeeds.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    long_name = "Keychain " + "extraction " * 40
    path = _write(tmp_path, DOC.replace('"Malicious Remote MCP Infrastructure"', f'"{long_name}"'))

    results = import_gates(path, dry_run=True)
    assert [r.detection_id for r in results if r.detection_id] == ["D-????", "D-????"]
    for res in import_gates(path):
        if res.record_path is not None:
            assert len(res.record_path.name.encode()) <= 255
            assert res.record_path.exists()
    assert (tmp_path / "ws" / "catalog" / "INDEX.yml").exists()  # loop ran to completion


def test_a_regenerated_document_warns_about_the_records_it_abandons(tmp_path, monkeypatch):
    """`hunt_ref` is built from `candidate_id`, falling back to the old ordinal
    `detection_id`. Regenerating a hunt's document across that rename re-keys every
    candidate, so the import can only mint duplicates of records the first run
    wrote — and with no reverse reconciliation the originals stay behind looking
    equally current. Can't be merged automatically (that is the fuzzy rename-match
    `sync` refuses to guess at), so it has to be said out loud."""
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    ordinal = _write(tmp_path)                       # `detection_id: 1` / `2`
    import_gates(ordinal)
    slugged = _write(tmp_path, CANONICAL_DOC, name="H-0041_GATES_v2.yaml")

    assert superseded_ordinal_refs(parse_gates(slugged)) == ["H-0041#1", "H-0041#2"]
    # An unchanged, still-ordinal document is *not* a rename — it matches itself.
    assert superseded_ordinal_refs(parse_gates(ordinal)) == []

    result = CliRunner().invoke(hunt_promote, ["--gates", str(slugged)])
    assert result.exit_code == 0
    assert "H-0041#1" in result.output and "merging by hand" in result.output


def test_an_explicitly_declared_multi_platform_is_not_flagged(tmp_path, monkeypatch):
    """`multi-platform` is the value ADEF itself writes, so a document copies it.

    And the undeclared check reads the derived pair, where one explicit
    `multi-platform` is byte-identical to saying nothing — so an author who did
    state a platform was told to go review it.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    declared = DOC.replace("platforms: [macOS]", "platforms: [multi-platform]")
    import_gates(_write(tmp_path, declared))

    for _id, _p, data in Catalog(tmp_path / "ws").iter_records():
        assert data["platform"] == "multi-platform"
        assert "no_platform" not in data["review_reasons"]
        # And the bucket isn't also listed as its own constituent on disk.
        assert record_platforms(data) == ["multi-platform"]


def test_a_broken_first_candidate_is_reported_at_index_zero(tmp_path):
    """The message is index syntax, so it has to count the way a YAML tool does.

    `enumerate(..., start=1)` fed an index-style `detections[N]`, so a broken
    *first* candidate read as `detections[1]` — pointing the user at the second
    entry, which is the one place in the document they would find nothing wrong.
    """
    raw = yaml.safe_load(DOC)
    raw["detections"][0] = "not a mapping"
    path = _write(tmp_path, yaml.safe_dump(raw))

    with pytest.raises(GatesError, match=r"`detections\[0\]` is str"):
        parse_gates(path)


def test_gates_mode_refuses_generator_only_flags_instead_of_ignoring_them(tmp_path, monkeypatch):
    """`--rule-staging-root` and `--hunt-root` only reach the generator path.

    Under `--gates` they were accepted and silently discarded — the user
    believes they redirected the output and gets a success message with the
    files written somewhere else. The positional HUNT_ID and `--dry-run` both
    already reject on mode mismatch; these two were the asymmetry.
    """
    monkeypatch.setenv("ADEF_WORKSPACE", str(tmp_path / "ws"))
    path = _write(tmp_path)

    for flag in ("--rule-staging-root", "--hunt-root"):
        result = CliRunner().invoke(hunt_promote, ["--gates", str(path), flag, str(tmp_path / "x")])
        assert result.exit_code == 2, (flag, result.output)
        assert flag in result.output
        # Refused before anything is written, not after.
        assert not (tmp_path / "ws" / "catalog").exists(), flag


def test_a_workspace_under_a_detections_tree_is_a_sentence_not_a_traceback(tmp_path, monkeypatch):
    """The hard invariant is the one refusal most worth reading as a sentence.

    `_check_not_under_detections` raises `HardInvariantViolation`, a
    `JournalError` — unrelated to `CatalogError`, so the `hunt-promote` funnel
    let it through as a traceback. `adef catalog` can't be fixed the same way:
    it raises from `Catalog(ws)`, long before the record-path pre-flight it
    wraps in a `try`, so the backstop is the root group (`cli._AdefGroup`) and
    the assertion below goes through it rather than the bare subcommand.
    """
    from adef.cli import cli

    ws = tmp_path / "repo" / "detections" / "ws"
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))

    result = CliRunner().invoke(hunt_promote, ["--gates", str(_write(tmp_path))])
    assert result.exit_code == 2, result.output
    assert "hunt-promote failed" in result.output
    assert isinstance(result.exception, SystemExit), result.exception

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text(
        "title: t\nid: 11111111-1111-1111-1111-111111111111\n"
        "logsource: {product: windows}\ndetection: {selection: {EventID: 1}, condition: selection}\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["catalog", str(rules)])
    assert result.exit_code != 0, result.output
    assert "read-only for ADEF" in " ".join(result.output.split()), result.output
    assert isinstance(result.exception, SystemExit), result.exception


def test_workspace_flag_reaches_the_mitre_validator(tmp_path, monkeypatch):
    """`hunt-promote --gates --workspace X` judges `invalid_mitre` against X.

    `record_from_gates` used to document itself as taking no workspace —
    "everything here comes from the document" — while calling
    `mitre_review_reasons`, which cannot decide `invalid_mitre` without an
    ATT&CK snapshot. The snapshot came from `$ADEF_WORKSPACE` behind the
    caller's back, so the verdict written into X was judged against whatever
    the environment named. `_preserve_enrichment` has the same hole on
    re-import, via `refresh_mitre_review`.

    The env var points elsewhere on purpose: with it set to `ws`, zero-arg
    resolution finds the same snapshot and a pass proves nothing.
    """
    import json

    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "attack").mkdir(parents=True)
    monkeypatch.setenv("ADEF_WORKSPACE", str(elsewhere))

    ws = tmp_path / "ws"
    (ws / "attack").mkdir(parents=True)
    (ws / "attack" / "enterprise.json").write_text(
        json.dumps(
            {
                "attack_version": "99.9-local",
                "tactics": {"execution": "Execution"},
                "techniques": {"T9999": {"name": "Local Only", "tactics": ["execution"]}},
            }
        ),
        encoding="utf-8",
    )

    # Both spellings: candidate 1 declares `deployment.mitre_attack`, candidate 2
    # declares nothing and inherits `hunt_metadata.techniques`. Replacing only
    # the hunt-level list left candidate 1 on T1555.001 and the test red on the
    # wrong assertion — the candidate's own mapping wins, which is the point of
    # the fallback. Both candidates must map to the lever and nothing else.
    doc = DOC.replace("techniques: [T1059.007, T1555.001]", "techniques: [T9999]")
    doc = doc.replace("mitre_attack: [T1555.001]", "mitre_attack: [T9999]")
    path = _write(tmp_path, doc)

    result = CliRunner().invoke(
        hunt_promote, ["--gates", str(path), "--workspace", str(ws)]
    )
    assert result.exit_code == 0, result.output

    # Only the candidate that *declares* a mapping is the lever. The hunt-level
    # `techniques` fallback is deliberately limited to a single-candidate
    # document — it won't copy one guess onto N records — so candidate 2 lands
    # unmapped and carries `no_mitre`, which is correct and not what this tests.
    mapped = [d for _id, _p, d in Catalog(ws).iter_records() if d.get("mitre")]
    assert [d["mitre"] for d in mapped] == [["T9999"]], mapped
    # Absence is the assertion: the shipped snapshot flags T9999 as fiction.
    assert "invalid_mitre" not in (mapped[0].get("review_reasons") or []), mapped[0]

    # Re-import drives `_preserve_enrichment` → `refresh_mitre_review`, the
    # second hole, which recomputes the same two reasons from scratch.
    assert (
        CliRunner()
        .invoke(hunt_promote, ["--gates", str(path), "--workspace", str(ws)])
        .exit_code
        == 0
    )
    reimported = [d for _id, _p, d in Catalog(ws).iter_records() if d.get("mitre")]
    assert [d["mitre"] for d in reimported] == [["T9999"]], reimported
    assert "invalid_mitre" not in (reimported[0].get("review_reasons") or []), reimported[0]
