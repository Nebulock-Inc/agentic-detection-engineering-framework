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

from adef.core.catalog import Catalog
from adef.core.gates import (
    GatesError,
    import_gates,
    journal_note,
    parse_gates,
    record_from_gates,
)

pytestmark = pytest.mark.unit


DOC = textwrap.dedent(
    """
    schema_version: "2.0"
    hunt_metadata:
      hunt_id: H-0041
      title: "MCP Server Process Spawn Chain Detection"
      techniques: [T1059.007, T1555.001]
      platforms: [macOS]
      data_sources: [EDR]
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
      data_sources: [EDR]
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
    rec = record_from_gates("D-0001", doc.candidates[0], doc, tmp_path)

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
        record_from_gates("D-0001", doc.candidates[0], doc, tmp_path)


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
        record_from_gates("D-0001", doc.candidates[0], doc, tmp_path)


def test_narrative_markdown_is_not_importable(tmp_path):
    # HOLD/TIME-BOX hunts emit a .md narrative with no `detections` list.
    path = tmp_path / "H-0060_GATES.md"
    path.write_text("# GATES Validation: H-0060\n\n**Verdict:** HOLD\n", encoding="utf-8")
    with pytest.raises(GatesError):
        parse_gates(path)


def test_dry_run_writes_nothing(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("ADEF_WORKSPACE", str(ws))
    results = import_gates(_write(tmp_path), dry_run=True)

    assert len(results) == 3
    assert not list(Catalog(ws).iter_records())
    assert not list((ws / "journals").glob("D-*.md"))


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
        "    detection_logic: {query: \"SELECT 1\"}\n"
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
