"""Import an ATHF GATES validation document into the ADEF catalog.

A GATES document (``hunt-promotion-analysis/H-XXXX_GATES.yaml``, produced by
ATHF's ``gates`` skill) scores one hunt's findings and describes N candidate
detections. Each candidate carries a verdict, the evidence behind it, and — when
the verdict is deployable — a ``deployment`` block holding the query, engine,
entities and alert configuration.

That document *is* the output ADEF used to expect from a plugged-in rule
generator, so this module is a parser rather than an agent: ATHF already did the
reasoning, and ADEF has no LLM call to make here.

Contract: ``.claude/skills/gates/AGENT_MEMORY_SCHEMA.md`` in
``Nebulock-Inc/agentic-threat-hunting-framework`` (``schema_version: "2.0"``).

Two verdict families drive everything:

* **deployable** → mint a ``D-XXXX``, write a catalog record and a journal.
* **archival** → nothing is written. The hunt decided *not* to build these, so a
  record would imply a rule that doesn't exist — and with no record there is no
  ``hunt_ref`` to match on, so a journal would be re-appended on every re-import.
  They are reported as skipped; the reasoning stays in the GATES document, which
  every promoted sibling record points at via ``rule_ref``.

Re-importing the same document is idempotent: a candidate is matched to an
existing record by ``hunt_ref`` (``H-XXXX#<candidate-id>``) before a new ID is
minted, so an edited-and-regenerated hunt updates its records instead of
duplicating them. This rests entirely on GATES keeping ``candidate_id`` stable
across regenerations — the contract says it must, and nothing here can detect a
violation, only suffer it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from adef.core.catalog import _UNKNOWN_PLATFORM, Catalog, CatalogRecord
from adef.core.journal import Journal, workspace_journals_dir
from adef.core.rule_discovery import REVIEW_NO_MITRE

# ADEF's four engines (tests/test_no_new_engine_types.py). GATES leaves its own
# `engine` field unconstrained, so a fifth value is rejected at the boundary
# rather than smuggled into the catalog.
VALID_ENGINES = frozenset({"sigma", "sql", "sch_sql", "composite"})

DEPLOYABLE_VERDICTS = frozenset({"PROMOTE", "CONDITIONAL", "TIME_BOX"})
ARCHIVAL_VERDICTS = frozenset({"HOLD", "DROP", "RECURRING_HUNT"})

# GATES `deployment.status` → ADEF `status`. EXPERIMENTAL means "entering soak",
# which is ADEF's `draft`; nothing arrives pre-promoted.
_STATUS_MAP = {"EXPERIMENTAL": "draft", "ACTIVE": "ready", "INACTIVE": "deprecated"}

# A deployable-but-not-finished verdict is flagged so it surfaces in
# `adef detection list --needs-review`.
REVIEW_GATES_CONDITIONAL = "gates_conditional"
REVIEW_GATES_TIME_BOX = "gates_time_box"

_QUERY_LANGUAGE = {"sql": "sql", "sch_sql": "sql"}


class GatesError(ValueError):
    """The document isn't a GATES validation output we can import."""


def _normalize_verdict(raw: object) -> str:
    """``TIME-BOX``/``recurring hunt`` → ``TIME_BOX``/``RECURRING_HUNT``.

    The canonical form is uppercase-with-underscores. Documents written before the
    contract was pinned down spell these with hyphens and spaces too, so normalize
    rather than reject: the verdict decides whether we mint a detection, and
    failing an import over punctuation would be absurd.
    """
    return str(raw or "").strip().upper().replace("-", "_").replace(" ", "_")


def _candidate_verdict(assessment: dict) -> str:
    """The candidate's verdict, preferring the canonical field.

    ``verdict`` is authoritative. Legacy exception: before ``RECURRING_HUNT`` had a
    slot in the verdict enum, it was encoded as ``verdict: HOLD`` plus a free-form
    ``classification``. Recover the specific label in exactly that case — both
    values are archival, so this sharpens the journal note without changing what
    gets written.
    """
    verdict = _normalize_verdict(assessment.get("verdict"))
    if not verdict:
        return _normalize_verdict(assessment.get("classification"))
    if verdict == "HOLD":
        legacy = _normalize_verdict(assessment.get("classification"))
        if legacy in ARCHIVAL_VERDICTS:
            return legacy
    return verdict


def _coerce_score(raw: object) -> float:
    """Accept both ``4.25`` and the ``"5/5"`` form the schema documents."""
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw or "").strip()
    if not text:
        return 0.0
    head = text.split("/", 1)[0].strip()
    try:
        return float(head)
    except ValueError:
        return 0.0


def _platform_of(platforms: list) -> str:
    """One record needs one platform; a genuinely cross-platform hunt gets the
    existing ``multi-platform`` bucket rather than an arbitrary pick."""
    values = [str(p).strip().lower() for p in platforms if str(p).strip()]
    unique = list(dict.fromkeys(values))
    return unique[0] if len(unique) == 1 else _UNKNOWN_PLATFORM


def _extract_logic(deployment: dict) -> tuple[str, str]:
    """Return ``(query, description)`` from a ``detection_logic`` block.

    The contract is ``{query, description}`` for every engine. Earlier documents
    inlined a sigma rule body as sibling mapping keys (``selection:``/``condition:``)
    instead of putting it in ``query``, so that shape is re-serialized rather than
    dropped — the query round-trips into the catalog verbatim in spirit if not
    byte-for-byte.
    """
    logic = deployment.get("detection_logic")
    if isinstance(logic, str):
        return logic.strip(), ""
    if not isinstance(logic, dict):
        return "", ""
    description = str(logic.get("description") or "").strip()
    query = str(logic.get("query") or "").strip()
    if not query:
        inline = {k: v for k, v in logic.items() if k not in ("query", "description")}
        if inline:
            query = yaml.safe_dump(inline, sort_keys=False, default_flow_style=False).strip()
    return query, description


@dataclass
class GatesCandidate:
    """One entry from the document's ``detections`` list."""

    hunt_id: str
    local_id: str  # GATES `candidate_id` — hunt-scoped slug, not a global ADEF ID
    name: str
    verdict: str
    base_score: float
    criteria: dict = field(default_factory=dict)
    rationale: dict = field(default_factory=dict)
    deployment: dict = field(default_factory=dict)
    pattern_learned: str = ""

    @property
    def hunt_ref(self) -> str:
        """Stable cross-document identity: ``H-0041#keychain-access-non-app-parent``."""
        return f"{self.hunt_id}#{self.local_id}"

    @property
    def deployable(self) -> bool:
        return self.verdict in DEPLOYABLE_VERDICTS


@dataclass
class GatesDocument:
    hunt_id: str
    title: str
    verdict: str
    platform: str
    techniques: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    candidates: list[GatesCandidate] = field(default_factory=list)
    path: Path | None = None


def parse_gates(path: Path) -> GatesDocument:
    """Parse a GATES YAML document. Pure: reads one file, writes nothing."""
    path = Path(path).expanduser().resolve()
    if path.suffix.lower() in (".md", ".markdown"):
        raise GatesError(
            f"{path.name} is a markdown narrative, not a GATES YAML document. "
            "A hunt whose verdict is HOLD/DROP/TIME_BOX/RECURRING_HUNT emits .md "
            "and has nothing to import — only a PROMOTE/CONDITIONAL hunt emits the "
            ".yaml ADEF reads."
        )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise GatesError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise GatesError(f"{path.name} does not contain a YAML mapping.")

    meta = raw.get("hunt_metadata")
    if not isinstance(meta, dict) or not meta.get("hunt_id"):
        raise GatesError(
            f"{path.name} has no `hunt_metadata.hunt_id` — is this a GATES document? "
            "HOLD/TIME-BOX hunts emit a .md narrative, which has nothing to import."
        )
    hunt_id = str(meta["hunt_id"]).strip()
    validation = raw.get("gates_validation")
    if not isinstance(validation, dict):
        validation = {}

    detections = raw.get("detections")
    if not isinstance(detections, list):
        detections = []

    candidates = []
    for entry in detections:
        if not isinstance(entry, dict):
            continue
        assessment = entry.get("gates_assessment")
        assessment = assessment if isinstance(assessment, dict) else {}
        deployment = entry.get("deployment")
        deployment = deployment if isinstance(deployment, dict) else {}
        # `candidate_id` is the canonical key: a hunt-scoped, meaning-derived slug
        # that survives GATES re-ordering its output. `detection_id` was the earlier
        # spelling and was a bare ordinal, which is why matching on it was unsafe —
        # still read as a fallback so documents already on disk import.
        local_id = str(entry.get("candidate_id") or entry.get("detection_id") or "").strip()
        if not local_id:
            raise GatesError(
                f"{path.name}: a detection has no `candidate_id`. ADEF needs a stable "
                "per-candidate key to make re-import idempotent."
            )
        verdict = _candidate_verdict(assessment)
        candidates.append(
            GatesCandidate(
                hunt_id=hunt_id,
                local_id=local_id,
                name=str(entry.get("name") or f"{hunt_id} detection {local_id}").strip(),
                verdict=verdict,
                base_score=_coerce_score(assessment.get("base_score")),
                criteria=dict(assessment.get("criteria") or {}),
                rationale=dict(assessment.get("scoring_rationale") or {}),
                deployment=deployment,
                pattern_learned=str(assessment.get("pattern_learned") or "").strip(),
            )
        )

    return GatesDocument(
        hunt_id=hunt_id,
        title=str(meta.get("title") or hunt_id).strip(),
        verdict=_normalize_verdict(validation.get("verdict")),
        platform=_platform_of(meta.get("platforms") or []),
        techniques=[str(t).strip() for t in (meta.get("techniques") or []) if str(t).strip()],
        data_sources=[str(d).strip() for d in (meta.get("data_sources") or []) if str(d).strip()],
        candidates=candidates,
        path=path,
    )


def record_from_gates(
    detection_id: str,
    cand: GatesCandidate,
    doc: GatesDocument,
    workspace: Path,
) -> CatalogRecord:
    """Build a catalog record for one deployable candidate.

    ``rule_ref`` points at the GATES document: for a promoted detection that file
    *is* the source of record. ``origin`` is ``promoted``, which — like
    ``authored`` — tells ``adef sync`` there is no upstream repo to reconcile.
    """
    deployment = cand.deployment
    engine = str(deployment.get("engine") or "").strip().lower()
    if engine and engine not in VALID_ENGINES:
        raise GatesError(
            f"{cand.hunt_ref} declares engine {engine!r}; ADEF supports only "
            f"{', '.join(sorted(VALID_ENGINES))}."
        )
    if not engine:
        raise GatesError(
            f"{cand.hunt_ref} has verdict {cand.verdict} but no `deployment.engine`. "
            "A deployable candidate needs one."
        )

    query, description = _extract_logic(deployment)
    mitre = [str(m).strip() for m in (deployment.get("mitre_attack") or []) if str(m).strip()]
    if not mitre:
        mitre = list(doc.techniques)

    alert: dict = {}
    severity = str(deployment.get("severity") or "").strip().lower()
    if severity:
        alert["severity"] = severity
    config = deployment.get("alert_configuration")
    if isinstance(config, dict) and isinstance(config.get("throttle"), dict):
        alert["throttle"] = dict(config["throttle"])

    reasons = []
    if not mitre:
        reasons.append(REVIEW_NO_MITRE)
    if cand.verdict == "CONDITIONAL":
        reasons.append(REVIEW_GATES_CONDITIONAL)
    elif cand.verdict == "TIME_BOX":
        reasons.append(REVIEW_GATES_TIME_BOX)

    gates_path = doc.path or Path(".")
    return CatalogRecord(
        id=detection_id,
        title=cand.name,
        rule_ref=f"{gates_path.parent.name}/{gates_path.name}",
        original_path=str(gates_path),
        platform=doc.platform,
        kind="atomic",
        engine=engine,
        format=engine,
        origin="promoted",
        query_language=_QUERY_LANGUAGE.get(engine, ""),
        query=query,
        data_source=", ".join(doc.data_sources),
        mitre=mitre,
        status=_STATUS_MAP.get(str(deployment.get("status") or "").strip().upper(), "draft"),
        stage="find",
        description=description,
        alert=alert,
        entities=[dict(e) for e in (deployment.get("entities") or []) if isinstance(e, dict)],
        observables=[dict(o) for o in (deployment.get("observables") or []) if isinstance(o, dict)],
        references=[str(r).strip() for r in (deployment.get("references") or []) if str(r).strip()],
        hunt_ref=cand.hunt_ref,
        needs_review=bool(reasons),
        review_reasons=reasons,
    )


def journal_note(cand: GatesCandidate, doc: GatesDocument) -> str:
    """Render the GATES reasoning as a journal note.

    The verdict and its evidence are *why* the detection exists (or doesn't), so
    they belong in the journal — ADEF's durable memory and its search corpus —
    not duplicated onto the record.
    """
    lines = [
        f"Promoted from ATHF hunt {doc.hunt_id} via GATES ({cand.hunt_ref}).",
        f"Verdict: {cand.verdict} — BASE score {cand.base_score:g}/5.",
    ]
    if cand.criteria:
        scored = ", ".join(f"{gate}={result}" for gate, result in cand.criteria.items())
        lines.append(f"Criteria: {scored}.")
    for gate, evidence in cand.rationale.items():
        text = str(evidence or "").strip()
        if text:
            lines.append(f"{gate}: {text}")
    if cand.pattern_learned:
        lines.append(f"Pattern learned: {cand.pattern_learned}")
    # A CONDITIONAL lands flagged `gates_conditional`, which is only actionable if the
    # engineer can see *what* the prerequisite is without reopening the ATHF document.
    params = cand.deployment.get("operational_parameters")
    params = params if isinstance(params, dict) else {}
    prereqs = [str(p).strip() for p in (params.get("deployment_prerequisites") or [])]
    for prereq in filter(None, prereqs):
        lines.append(f"Prerequisite: {prereq}")
    if not cand.deployable:
        lines.append(
            f"No catalog record minted — {cand.verdict} means the hunt decided against "
            "building this. Kept for the reasoning."
        )
    return "\n".join(lines)


@dataclass
class ImportResult:
    hunt_ref: str
    name: str
    verdict: str
    detection_id: str
    minted: bool  # False when an existing record for this hunt_ref was updated
    record_path: Path | None
    journal_path: Path | None


def import_gates(
    path: Path,
    workspace: Path | None = None,
    dry_run: bool = False,
) -> list[ImportResult]:
    """Import every candidate in a GATES document into the workspace.

    Deployable candidates get a catalog record and a journal. Archival ones are
    reported as skipped and nothing is written — see the ``not cand.deployable``
    branch for why. Idempotent on ``hunt_ref``.
    """
    doc = parse_gates(path)
    journals_dir = workspace_journals_dir(workspace)
    ws = journals_dir.parent
    catalog = Catalog(ws)
    journal = Journal(journals_dir)

    # Existing promoted records, so a re-import updates rather than duplicates.
    by_hunt_ref = {
        str(data.get("hunt_ref")): det_id
        for det_id, _path, data in catalog.iter_records()
        if data.get("hunt_ref")
    }

    results = []
    for cand in doc.candidates:
        existing = by_hunt_ref.get(cand.hunt_ref)

        # An archival verdict is the hunt deciding *not* to build this. Minting a
        # permanent D-XXXX for a non-detection would pollute the ID space and show
        # up in `detection list`, and there'd be no record to carry the hunt_ref —
        # so a re-import could never recognize it and would mint again every run.
        # The reasoning is preserved in the GATES document itself, which every
        # promoted sibling record already points at via `rule_ref`.
        # ponytail: rejected candidates aren't in ADEF's search corpus. If they
        # need to be, that's a coverage-gaps store, not a per-candidate journal.
        if not cand.deployable:
            results.append(
                ImportResult(
                    hunt_ref=cand.hunt_ref,
                    name=cand.name,
                    verdict=cand.verdict,
                    detection_id="",
                    minted=False,
                    record_path=None,
                    journal_path=None,
                )
            )
            continue

        if dry_run:
            # Build the record and throw it away. A dry run that skipped this would
            # report success on a document the real run rejects (missing engine,
            # engine outside ADEF's four) — which is the one thing a dry run exists
            # to tell you.
            # ponytail: aborts on the first bad candidate, same as the real run, so
            # validating a broken document is fix-one-and-rerun. Accumulate errors
            # if that gets tedious.
            record_from_gates(existing or "D-????", cand, doc, ws)
            results.append(
                ImportResult(
                    hunt_ref=cand.hunt_ref,
                    name=cand.name,
                    verdict=cand.verdict,
                    detection_id=existing or "D-????",
                    minted=existing is None,
                    record_path=None,
                    journal_path=None,
                )
            )
            continue

        detection_id = existing or catalog.next_id()
        record_path = catalog.write(record_from_gates(detection_id, cand, doc, ws))

        journal_path = journals_dir / f"{detection_id}.md"
        if journal_path.exists():
            # Re-import of an edited hunt: advance_stage is idempotent for the
            # stage it's already on and appends the note as a sub-block.
            journal.advance_stage(
                detection_id=detection_id, stage="find", note=journal_note(cand, doc)
            )
        else:
            journal_path = journal.create(
                detection_id=detection_id,
                title=cand.name,
                owner="",
                note=journal_note(cand, doc),
            ).path

        by_hunt_ref[cand.hunt_ref] = detection_id
        results.append(
            ImportResult(
                hunt_ref=cand.hunt_ref,
                name=cand.name,
                verdict=cand.verdict,
                detection_id=detection_id,
                minted=existing is None,
                record_path=record_path,
                journal_path=journal_path,
            )
        )

    if results and not dry_run:
        catalog.rebuild_index()
    return results


__all__ = [
    "ARCHIVAL_VERDICTS",
    "DEPLOYABLE_VERDICTS",
    "VALID_ENGINES",
    "GatesCandidate",
    "GatesDocument",
    "GatesError",
    "ImportResult",
    "import_gates",
    "journal_note",
    "parse_gates",
    "record_from_gates",
]
