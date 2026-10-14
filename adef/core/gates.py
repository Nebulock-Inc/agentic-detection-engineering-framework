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

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from adef.core.catalog import (
    _UNKNOWN_PLATFORM,
    Catalog,
    CatalogRecord,
    catalog_dir,
    refresh_mitre_review,
)
from adef.core.catalog import record_path as catalog_record_path
# ADEF's four engines, imported rather than re-typed (`engines.py` is the single
# canonical copy). GATES leaves its own `engine` field unconstrained, so a fifth
# value is rejected at this boundary rather than smuggled into the catalog.
from adef.core.engines import ALLOWED_ENGINES as VALID_ENGINES
from adef.core.journal import Journal, workspace_journals_dir

# One definition of "what counts as enrichment" for every re-entrant write path
# (`sync` and this one), so the two can't drift apart on what they preserve.
from adef.core.reconcile import _ENRICHMENT_FIELDS

# The two GATES review reasons live with the other `REVIEW_*` constants, so the
# headline-warning set can include them without importing this module.
from adef.core.rule_discovery import (
    REVIEW_GATES_CONDITIONAL,
    REVIEW_GATES_TIME_BOX,
    REVIEW_NO_PLATFORM,
    mitre_review_reasons,
    safe_platform,
)

# Stand-in ID for a candidate a dry run *would* mint. The real one is allocated
# in the write phase, where the catalog can see what's already on disk.
_PENDING_ID = "D-????"


DEPLOYABLE_VERDICTS = frozenset({"PROMOTE", "CONDITIONAL", "TIME_BOX"})
ARCHIVAL_VERDICTS = frozenset({"HOLD", "DROP", "RECURRING_HUNT"})
# Anything outside the enum is rejected rather than read as archival: a typo
# ("PROMOTED", "CONDITONAL") would otherwise silently drop a deployable
# detection, and "nothing was imported" looks identical to "the hunt built
# nothing" in the output.
KNOWN_VERDICTS = DEPLOYABLE_VERDICTS | ARCHIVAL_VERDICTS

# GATES `deployment.status` → ADEF `status`. TEST means "entering soak", which is
# ADEF's `draft`; nothing arrives pre-promoted. The EXPERIMENTAL/ACTIVE/INACTIVE
# row is the pre-2026-09-27 spelling of the same three states, kept because
# documents written against it are already on disk.
_STATUS_MAP = {
    "TEST": "draft",
    "PRODUCTION": "ready",
    "DISABLED": "deprecated",
    "EXPERIMENTAL": "draft",
    "ACTIVE": "ready",
    "INACTIVE": "deprecated",
}

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


def _str_list(raw: object) -> list[str]:
    """Every list-typed GATES field, read the one way that survives a scalar.

    The contract says these are lists, but a hand-written document says
    ``techniques: T1059.001`` sooner or later — and a comprehension over a string
    iterates *characters*, so that one typo becomes nine bogus technique IDs, each
    counted as coverage by `adef coverage`. Wrapping the scalar is better than
    rejecting it: the author's intent is unambiguous, and silent corruption is the
    failure mode worth eliminating, not sloppy YAML.
    """
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)) or not isinstance(raw, (list, tuple, set)):
        raw = [raw]
    return [text for text in (str(v).strip() for v in raw) if text]


def _mapping(raw: object, what: str, where: str) -> dict:
    """``criteria`` and ``scoring_rationale`` are mappings; a list is an error.

    ``dict()`` on a list raises a bare ``ValueError`` that escapes the caller's
    ``except (GatesError, CatalogError)`` and surfaces as a traceback instead of a
    document-level complaint naming the file.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise GatesError(
            f"{where}: `{what}` is a {type(raw).__name__}, not a mapping of name → value."
        )
    return dict(raw)


def _platforms_of(platforms: object) -> tuple[str, list[str]]:
    """Return ``(bucket, declared)`` for a document's ``platforms`` list.

    ``platform`` is ADEF's one single-valued axis — it is a directory name — so a
    genuinely cross-platform hunt gets the existing ``multi-platform`` bucket
    rather than an arbitrary pick. But collapsing to the bucket and *discarding*
    the list made the detection unfindable: a hunt declaring
    ``[windows, macos]`` is real coverage on both, and `--platform windows`
    missed it. The declared list is kept alongside the bucket so the filter and
    the INDEX can see through it (found by the first cross-platform document —
    every shipped example is single-platform).

    The single value goes through ``safe_platform`` because it becomes a
    directory name, and a hunt document is read-only to ADEF: ``platforms:
    ["Windows 11"]`` or ``["macOS 14"]`` is ordinary prose for a human-written
    document, but it used to reach ``record_path`` verbatim and refuse the
    *entire* import — every candidate, in the dry run too — leaving the user
    nothing to fix but an upstream file they don't own. Unusable as a segment now
    means the ``multi-platform`` bucket with the raw value kept in the declared
    list, which is exactly what ``rule_discovery`` already does for a
    profile-extracted platform. ``record_path`` still refuses anything that
    slips through; that guard is the backstop, not the diagnostic.
    """
    declared = list(dict.fromkeys(p.lower() for p in _str_list(platforms)))
    bucket = safe_platform(declared[0]) if len(declared) == 1 else None
    if bucket is None or bucket == _UNKNOWN_PLATFORM:
        # Unusable *or* literally `[multi-platform]`: either way the document said
        # something, and `(bucket, [])` is byte-identical to the undeclared case
        # `no_platform` flags — so it would be told to review a platform it had
        # stated. The raw values are kept in the declared list to break that tie
        # (and to show the reviewer what was written); `record_platforms` dedupes
        # them against the bucket, so nothing downstream sees one twice.
        return _UNKNOWN_PLATFORM, declared
    return bucket, []


def _candidate_data_source(cand: "GatesCandidate", doc: "GatesDocument") -> str:
    """The feed this one candidate reads, falling back to the hunt's roll-up.

    ``deployment.data_source`` is a single literal by contract; a list is accepted
    (and its first entry taken) rather than dropped, since dropping it silently
    substitutes another candidate's feed.
    """
    own = _str_list(cand.deployment.get("data_source"))
    if own:
        return own[0]
    return doc.data_sources[0] if doc.data_sources else ""


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
    platforms: list[str] = field(default_factory=list)  # declared list when cross-platform
    techniques: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    candidates: list[GatesCandidate] = field(default_factory=list)
    # Hunt-level reasoning, shared by every candidate: the BASE narrative and the
    # prerequisites blocking promotion. Both are *why*, so both end up in the
    # journal rather than on the record.
    narrative: str = ""
    prerequisites: list[dict] = field(default_factory=list)
    path: Path | None = None

    @property
    def deployable_count(self) -> int:
        return sum(1 for cand in self.candidates if cand.deployable)


def parse_gates(path: Path) -> GatesDocument:
    """Parse a GATES YAML document. Pure: reads one file, writes nothing."""
    path = Path(path).expanduser().resolve()
    if path.suffix.lower() in (".md", ".markdown"):
        raise GatesError(
            f"{path.name} is a markdown narrative, not a GATES YAML document. "
            "A hunt whose verdict is HOLD/DROP/RECURRING_HUNT emits .md and has "
            "nothing to import — only a PROMOTE/CONDITIONAL/TIME_BOX hunt emits the "
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
            "HOLD/DROP/RECURRING_HUNT hunts emit a .md narrative, which has nothing "
            "to import."
        )
    hunt_id = str(meta["hunt_id"]).strip()
    validation = raw.get("gates_validation")
    if not isinstance(validation, dict):
        validation = {}

    detections = raw.get("detections", [])
    # Absent is fine (a hunt that produced no candidates). Present but not a list
    # is a malformed document, and defaulting it to empty would report "0
    # candidates" — indistinguishable from a hunt that genuinely built nothing.
    if not isinstance(detections, list):
        raise GatesError(
            f"{path.name}: `detections` is {type(detections).__name__}, expected a list "
            "of candidates."
        )

    candidates = []
    seen_ids: set[str] = set()
    # `start=0`: the message below is index syntax (`detections[N]`), which the
    # user resolves with a YAML tool that counts from zero. `start=1` made a
    # broken *first* candidate read as `detections[1]` — pointing at the second.
    for position, entry in enumerate(detections):
        if not isinstance(entry, dict):
            # Skipping it would drop a candidate from the count, and "3 of 4
            # imported" reads as a deliberate verdict rather than a broken document.
            raise GatesError(
                f"{path.name}: `detections[{position}]` is {type(entry).__name__}, "
                "expected a candidate mapping."
            )
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
        # `candidate_id` is the identity key, so a document that reuses one maps
        # two candidates onto the same `hunt_ref` — the second import would
        # overwrite the first's record and the first detection would vanish.
        if local_id in seen_ids:
            raise GatesError(
                f"{path.name}: `candidate_id: {local_id}` appears twice. Each candidate "
                "needs its own id — it is the key ADEF matches on across re-imports."
            )
        seen_ids.add(local_id)

        verdict = _candidate_verdict(assessment)
        if verdict not in KNOWN_VERDICTS:
            raise GatesError(
                f"{path.name}: candidate {local_id!r} has verdict {verdict or '(none)'!r}, "
                f"which is not a GATES verdict. Expected one of {', '.join(sorted(KNOWN_VERDICTS))}."
            )
        candidates.append(
            GatesCandidate(
                hunt_id=hunt_id,
                local_id=local_id,
                name=str(entry.get("name") or f"{hunt_id} detection {local_id}").strip(),
                verdict=verdict,
                base_score=_coerce_score(assessment.get("base_score")),
                criteria=_mapping(
                    assessment.get("criteria"), "criteria", f"{path.name}:{local_id}"
                ),
                rationale=_mapping(
                    assessment.get("scoring_rationale"),
                    "scoring_rationale",
                    f"{path.name}:{local_id}",
                ),
                deployment=deployment,
                pattern_learned=str(assessment.get("pattern_learned") or "").strip(),
            )
        )

    outcomes = meta.get("hunt_outcomes")
    outcomes = outcomes if isinstance(outcomes, dict) else {}
    bucket, declared = _platforms_of(meta.get("platforms"))

    return GatesDocument(
        hunt_id=hunt_id,
        title=str(meta.get("title") or hunt_id).strip(),
        verdict=_normalize_verdict(validation.get("verdict")),
        platform=bucket,
        platforms=declared,
        techniques=_str_list(meta.get("techniques")),
        # `narrative_analysis` is the only place a deployable hunt's BASE
        # reasoning is written down — the `.md` an archival hunt emits carries the
        # same prose. Dropping it left ADEF holding the verdict with none of the
        # argument, which is the opposite of the point.
        narrative=str(raw.get("narrative_analysis") or "").strip(),
        prerequisites=[
            dict(p) for p in (validation.get("prerequisites") or []) if isinstance(p, dict)
        ],
        # `data_sources` is nested under `hunt_outcomes`, not alongside `techniques`
        # — reading it off `hunt_metadata` directly left every imported record with
        # an empty `data_source`, which is also an empty `by_data_source` bucket in
        # the INDEX and no log-source concentration in `adef coverage`.
        data_sources=_str_list(outcomes.get("data_sources")),
        candidates=candidates,
        path=path,
    )


def _status_of(deployment: dict, cand: GatesCandidate) -> str:
    """``deployment.status`` → ADEF ``status``, absent meaning ``draft``.

    An unrecognized value is rejected rather than defaulted: silently reading
    ``PRODUCTON`` as ``draft`` would leave a deployed detection looking unbuilt,
    the same silent-state-change failure the verdict check exists to stop.
    """
    raw = str(deployment.get("status") or "").strip().upper()
    if not raw:
        return "draft"
    if raw not in _STATUS_MAP:
        # Listed from the map, not hand-typed: the message named only the three
        # current spellings while the map also accepts the legacy
        # EXPERIMENTAL/ACTIVE/INACTIVE enum the handoff contract documents — so a
        # typo in a legacy document was answered by telling the engineer that the
        # vocabulary their document legitimately uses is invalid.
        raise GatesError(
            f"{cand.hunt_ref} declares `deployment.status: {raw}`, which is not a GATES "
            f"status. Expected one of {', '.join(sorted(_STATUS_MAP))}."
        )
    return _STATUS_MAP[raw]


def record_from_gates(
    detection_id: str,
    cand: GatesCandidate,
    doc: GatesDocument,
    workspace: Path | None = None,
) -> CatalogRecord:
    """Build a catalog record for one deployable candidate.

    ``rule_ref`` points at the GATES document: for a promoted detection that file
    *is* the source of record. ``origin`` is ``promoted``, which — like
    ``authored`` — tells ``adef sync`` there is no upstream repo to reconcile.

    Almost everything here comes from the document, and the one field that
    *looked* workspace-relative (``rule_ref``) is the GATES path. ``workspace``
    is the exception, and it is read — by ``mitre_review_reasons`` below, which
    cannot decide ``invalid_mitre`` without an ATT&CK snapshot to judge the
    document's techniques against.

    This docstring previously said "takes no workspace: everything here comes
    from the document", on the reasoning that a parameter a function never reads
    is a false claim about its inputs. The reasoning stands; the premise was
    wrong. The ATT&CK dependency was already here, resolved from
    ``$ADEF_WORKSPACE`` behind the caller's back — so `adef hunt-promote
    --gates --workspace X` judged X's candidates against whatever snapshot the
    environment named, and wrote the verdict into X.
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
    if not query:
        # Rejected at the boundary for the same reason a missing engine is: a
        # record with no logic is a detection that cannot be verified, refined or
        # deployed, and `adef coverage` would count it as covering its techniques.
        # That is the "fictional coverage" the coverage report exists to flag.
        raise GatesError(
            f"{cand.hunt_ref} has verdict {cand.verdict} but no detection logic — "
            "`deployment.detection_logic` is empty. A deployable candidate needs a query."
        )
    mitre = _str_list(deployment.get("mitre_attack"))
    if not mitre and doc.deployable_count == 1:
        # The hunt's techniques describe its *scope*, so handing them to a
        # candidate is only sound when there is exactly one candidate to hand them
        # to. With several, every under-mapped one inherited the whole hunt scope
        # and `adef coverage` read depth-N on each technique — "solid" coverage
        # built from one real detection and N-1 copies of a guess. Unmapped is the
        # honest state, and it has a drain: `no_mitre` below puts it in the
        # enrichment queue `adef detection tag-mitre` exists to empty. The hunt's
        # techniques go into the journal note so the tagger isn't guessing either.
        mitre = list(doc.techniques)

    alert: dict = {}
    severity = str(deployment.get("severity") or "").strip().lower()
    if severity:
        alert["severity"] = severity
    config = deployment.get("alert_configuration")
    if isinstance(config, dict) and isinstance(config.get("throttle"), dict):
        alert["throttle"] = dict(config["throttle"])

    reasons = mitre_review_reasons(mitre, workspace)
    # An *empty* `platforms` collapses to the same `multi-platform` bucket a
    # genuinely cross-platform hunt gets, so the bucket alone can't tell "runs
    # everywhere" from "nobody said" — and the second one silently became
    # coverage in the INDEX. The declared list disambiguates: empty bucket plus
    # empty list means undeclared. Same reason `catalog` raises on an
    # un-inferrable platform.
    #
    # The test is "is any declared value *usable* as a platform", not "did they
    # say anything": since `_platforms_of` stopped hard-failing on a value that
    # isn't a path segment, `["Windows 11"]` also lands in the bucket with a
    # non-empty declared list, and `not doc.platforms` would have read that as
    # settled cross-platform coverage and skipped the review queue.
    if doc.platform == _UNKNOWN_PLATFORM and not any(
        safe_platform(p) for p in doc.platforms
    ):
        reasons.append(REVIEW_NO_PLATFORM)
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
        platforms=list(doc.platforms),
        # `kind` and `engine` are separate axes, but a composite engine is a
        # composite detection by definition — leaving it `atomic` mislabels it in
        # `detection list` and in the INDEX. `correlation` has no GATES signal, so
        # it isn't inferred.
        kind="composite" if engine == "composite" else "atomic",
        engine=engine,
        format=engine,
        origin="promoted",
        query_language=_QUERY_LANGUAGE.get(engine, ""),
        query=query,
        # One literal, not a joined list: `data_source` is the key `schema check`
        # matches against a declared source and the key the INDEX buckets on, so
        # "EDR, Sysmon" matches no schema and gets its own concentration bucket.
        # The candidate's own `deployment.data_source` wins over the hunt-level
        # roll-up: a hunt spanning process-creation and registry telemetry would
        # otherwise attribute the first feed to every candidate, and `adef coverage`
        # would report the registry detection going dark when process creation breaks.
        # ponytail: still one literal per record — the full list stays in the GATES
        # document `rule_ref` points at. Recording all of them means making
        # `data_source` a list across every record consumer.
        data_source=_candidate_data_source(cand, doc),
        mitre=mitre,
        status=_status_of(deployment, cand),
        stage="find",
        description=description,
        alert=alert,
        entities=[dict(e) for e in (deployment.get("entities") or []) if isinstance(e, dict)],
        observables=[dict(o) for o in (deployment.get("observables") or []) if isinstance(o, dict)],
        references=_str_list(deployment.get("references")),
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
    for prereq in _str_list(params.get("deployment_prerequisites")):
        lines.append(f"Prerequisite: {prereq}")
    # Same reasoning for TIME_BOX: the verdict means "deploy with an expiry", so dropping
    # the expiry keeps only the half of the decision that ships. A rule whose expiration
    # date lives nowhere ADEF can see is a PROMOTE nobody dares delete.
    # ponytail: journal prose, not record fields — an `adef detection list --expiring`
    # needs dates on the record, which is a schema change for one verdict's benefit.
    for key in ("activation_date", "expiration_date", "review_date", "refresh_cycle_days"):
        value = str(params.get(key) or "").strip()
        if value:
            lines.append(f"{key.replace('_', ' ').capitalize()}: {value}")
    # The hunt's own techniques, when the candidate didn't claim any of its own and
    # there are siblings it can't be told apart from (see `record_from_gates`). The
    # record stays unmapped and queued; this is the context whoever drains the
    # queue with `adef detection tag-mitre` needs.
    # Mirrors `record_from_gates`' condition: said only when the record did *not*
    # inherit, so the note never claims a mapping is unverified when it was used.
    if doc.techniques and doc.deployable_count != 1 and not _str_list(
        cand.deployment.get("mitre_attack")
    ):
        lines.append(
            f"Hunt scope ATT&CK (unverified for this candidate): {', '.join(doc.techniques)}"
        )
    for req in doc.prerequisites:
        requirement = str(req.get("requirement") or "").strip()
        if not requirement:
            continue
        marks = [str(req.get("type") or "").strip()]
        if req.get("blocker"):
            marks.insert(0, "BLOCKER")
        if effort := str(req.get("effort") or "").strip():
            marks.append(effort)
        detail = ", ".join(m for m in marks if m)
        lines.append(f"Hunt prerequisite{f' ({detail})' if detail else ''}: {requirement}")
    if not cand.deployable:
        lines.append(
            f"No catalog record minted — {cand.verdict} means the hunt decided against "
            "building this. Kept for the reasoning."
        )
    if doc.narrative:
        # Hunt-level, so every deployable sibling's journal gets a copy. That is not
        # the near-duplicate problem the generated marker exists for: the prose
        # genuinely applies to all of them, and leaving it searchable is the whole
        # point of carrying it over. Headings are demoted so the hunt's `##` can't
        # masquerade as journal structure.
        # ponytail: demotes `#` runs anywhere, including inside a fenced block, so a
        # `# comment` line in an embedded query shifts. Cosmetic; track fences if it
        # ever matters.
        lines.append(f"\nHunt-level GATES analysis ({doc.hunt_id}):\n")
        lines.append(re.sub(r"^(#{1,4}) ", r"##\1 ", doc.narrative, flags=re.MULTILINE))
    return "\n".join(lines)


def _existing_hunt_refs(ws: Path) -> dict[str, str]:
    """``hunt_ref`` → ``D-XXXX`` for the promoted records already in the catalog.

    Read-only by construction: ``Catalog.__init__`` creates ``catalog/``, so a
    dry run against a workspace that doesn't exist yet must not go through it.
    No catalog means nothing to match, which is the truth for a fresh workspace.
    """
    if not (ws / "catalog").is_dir():
        return {}
    return {
        str(data["hunt_ref"]): det_id
        for det_id, _path, data in Catalog(ws).iter_records()
        if data.get("hunt_ref")
    }


# Record fields the catalog calls enrichment but a GATES document supplies: the
# promoted record's `description`/`alert`/`entities`/`observables`/`references`
# all come out of its `deployment` block. So they are *derived* here, and an
# edited document must be able to change them — unlike `status`/`stage`, which
# only a human moves. They are only filled from the existing record when the
# document says nothing, which is where the data loss was: a hand-written
# `description` on a record whose document has none was overwritten with "".
_DOC_DERIVED_ENRICHMENT = ("description", "alert", "entities", "observables", "references")


def _preserve_enrichment(
    rec: CatalogRecord, existing: dict, workspace: Path | None = None
) -> None:
    """Carry the engineer's work across a re-import, mutating ``rec`` in place.

    ``adef sync`` guarantees that re-running it never loses enrichment: it starts
    from the existing record and overwrites only derived fields (see
    ``reconcile._merge``), so anything it doesn't derive survives by construction.
    A GATES re-import builds the record from the document instead, so the same
    guarantee has to be spelled out — without it, regenerating a hunt's document
    resets a detection someone had taken to Govern back to a ``draft`` at
    ``find``.

    Two tiers: ``mitre``/``status``/``stage``/``owner`` (plus ``created``) are the
    human's, and always win; the fields in ``_DOC_DERIVED_ENRICHMENT`` refresh
    from the document and fall back to the record only when the document is
    silent.
    """
    for name in (*_ENRICHMENT_FIELDS, "created"):
        if value := existing.get(name):
            setattr(rec, name, value)
    for name in _DOC_DERIVED_ENRICHMENT:
        if not getattr(rec, name) and (value := existing.get(name)):
            setattr(rec, name, value)
    # `review_reasons` was computed from the *document*, before `mitre` above
    # inherited the human's mapping — so a candidate the document doesn't map but
    # `adef detection tag-mitre` does got `no_mitre` pushed back onto it by every
    # re-import, re-filling the queue the tagger had drained. Recomputed against
    # the mapping the record actually ends up with, as `core/tag.py` does after a
    # tag. The verdict-derived reasons are the document's to say and stay.
    refresh_mitre_review(rec, workspace)


@dataclass
class ImportResult:
    hunt_ref: str
    name: str
    verdict: str
    detection_id: str
    minted: bool  # False when an existing record for this hunt_ref was updated
    record_path: Path | None
    journal_path: Path | None


def superseded_ordinal_refs(doc: "GatesDocument", workspace: Path | None = None) -> list[str]:
    """Ordinal-keyed records for this hunt that a slug-keyed document abandons.

    GATES' earlier contract keyed a candidate by a bare ordinal ``detection_id``;
    the canonical key is now a ``candidate_id`` slug, and ``hunt_ref`` is built
    from whichever one the document carries. So regenerating a hunt's document
    across that rename changes every key: ``H-0041#1`` → ``H-0041#keychain-…``.
    Nothing matches, the import mints a second record for each detection the first
    run already created, and with no reverse reconciliation the originals stay
    behind looking equally current.

    Reported, not repaired. Re-attributing by candidate name is the fuzzy
    rename-match ``sync`` deliberately refuses — a wrong identity merge is worse
    than a duplicate — so the human merges. ADEF's job is to say so.
    """
    claimed = {cand.hunt_ref for cand in doc.candidates}
    if not any(not cand.local_id.isdigit() for cand in doc.candidates):
        return []  # still an ordinal-keyed document; nothing was renamed
    return sorted(
        ref
        for ref in _existing_hunt_refs(workspace_journals_dir(workspace, create=False).parent)
        if ref.startswith(f"{doc.hunt_id}#")
        and ref.split("#", 1)[1].isdigit()
        and ref not in claimed
    )


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
    # `create=False` even for a real run: whether anything gets written depends on
    # `planned` below, and an all-archival (or empty) document writes nothing by
    # contract. Creating here scaffolded `journals/` — and then `Catalog(ws)`
    # scaffolded `catalog/` — in a directory that was never a workspace, for a
    # document whose every candidate was a HOLD. Re-resolved with `create=True`
    # at the write phase, through the same canonical resolver.
    journals_dir = workspace_journals_dir(workspace, create=False)
    ws = journals_dir.parent
    # Existing promoted records, so a re-import updates rather than duplicates.
    by_hunt_ref = _existing_hunt_refs(ws)

    # Build every record *before* writing any. `record_from_gates` is where all
    # the boundary rejections live (no engine, an engine outside ADEF's four, no
    # query), so validating the whole document up front means a bad candidate
    # halfway down can't leave a half-imported workspace behind. It is also
    # exactly what a dry run has to do, so there is only one validation path.
    #
    # An archival verdict is the hunt deciding *not* to build this, and gets no
    # record: minting a permanent D-XXXX for a non-detection would pollute the ID
    # space and show up in `detection list`, and there'd be no record to carry the
    # hunt_ref — so a re-import could never recognize it and would mint again
    # every run. The reasoning is preserved in the GATES document itself, which
    # every promoted sibling record already points at via `rule_ref`.
    # ponytail: aborts on the first bad candidate, so validating a broken document
    # is fix-one-and-rerun. Accumulate errors if that gets tedious.
    # ponytail: rejected candidates aren't in ADEF's search corpus. If they need
    # to be, that's a coverage-gaps store, not a per-candidate journal.
    # ponytail: no reverse reconciliation. A candidate that was PROMOTE last
    # import and is now HOLD (or dropped from the document entirely) leaves its
    # record behind, untouched. `adef sync` has the same shape of answer for a
    # vanished source rule — report it orphaned, never delete — so the fix is an
    # orphan pass here, not deletion inside this loop.
    planned: list[tuple[GatesCandidate, CatalogRecord | None]] = [
        (
            cand,
            record_from_gates(
                by_hunt_ref.get(cand.hunt_ref) or _PENDING_ID, cand, doc, ws
            )
            if cand.deployable
            else None,
        )
        for cand in doc.candidates
    ]

    def _result(
        cand: GatesCandidate,
        rec: CatalogRecord | None,
        record_path: Path | None = None,
        journal_path: Path | None = None,
    ) -> ImportResult:
        return ImportResult(
            hunt_ref=cand.hunt_ref,
            name=cand.name,
            verdict=cand.verdict,
            detection_id="" if rec is None else rec.id,
            minted=rec is not None and cand.hunt_ref not in by_hunt_ref,
            record_path=record_path,
            journal_path=journal_path,
        )

    if dry_run:
        # Validate the paths the real run would write, so a `platforms` value that
        # escapes the workspace fails in the preview too — a dry run that can't
        # predict failure is worse than no dry run. Side-effect free: `record_path`
        # derives and checks without constructing a `Catalog`, which would create
        # the directory this run is supposed to leave untouched.
        for _cand, rec in planned:
            if rec is not None:
                catalog_record_path(catalog_dir(ws), rec)
        return [_result(cand, rec) for cand, rec in planned]

    if not any(rec is not None for _cand, rec in planned):
        # Nothing to write, so write nothing — including the directories.
        # `Catalog(ws)` and `Journal(journals_dir)` both create their directory on
        # construction, which made "archival verdicts write nothing" false for the
        # one case where the whole document is archival.
        return [_result(cand, rec) for cand, rec in planned]

    journals_dir = workspace_journals_dir(workspace, create=True)
    catalog = Catalog(ws)
    journal = Journal(journals_dir)
    # `next_id` reads the catalog, so it can't tell two unwritten records apart —
    # allocate from one seed instead of re-reading between writes.
    next_index = int(catalog.next_id().removeprefix("D-"))

    results = []
    for cand, rec in planned:
        if rec is None:
            results.append(_result(cand, None))
            continue

        # `rec.id` is already the existing ID when there is one (set in the plan).
        existing = by_hunt_ref.get(cand.hunt_ref)
        if existing is None:
            rec.id = f"D-{next_index:04d}"
            next_index += 1
        elif (found := catalog.find_record(existing)) is not None:
            _preserve_enrichment(rec, found[1], ws)
        record_path = catalog.write(rec)

        journal_path = journals_dir / f"{rec.id}.md"
        if journal_path.exists():
            # Re-import of an edited hunt. The note lands under whatever stage the
            # journal is already on — `advance_stage(stage="find")` would drag a
            # detection someone has taken to Govern back to the start. Marked
            # generated (as `sync`'s housekeeping notes are): it's a machine
            # restatement of a document the first import's note already put in the
            # search corpus, and a re-import is usually a no-op re-run, so leaving
            # these searchable would stack near-duplicates in the BM25 corpus for
            # every run. The cost is that a *changed* verdict is visible in the
            # journal but not searchable until someone writes it up.
            # Only when something actually changed. The note is derived wholly from
            # the document, so a re-run of an unedited document produces it
            # byte-identically — and appending that grows the journal by a full
            # restatement per run while adding nothing, so a nightly re-import
            # buries the human prose under n copies of itself. Skipping on an exact
            # match also covers the first re-import, whose note is already verbatim
            # in the find-stage block the initial import wrote. Matches `sync`,
            # which notes a *modified* rule and stays silent on an unchanged one.
            note = journal_note(cand, doc)
            if note.strip() not in journal.read(rec.id).body:
                journal.append_block(rec.id, "GATES re-import", note, generated=True)
        else:
            journal_path = journal.create(
                detection_id=rec.id,
                title=cand.name,
                owner="",
                note=journal_note(cand, doc),
            ).path

        results.append(_result(cand, rec, record_path=record_path, journal_path=journal_path))

    if results:
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
    "superseded_ordinal_refs",
    "journal_note",
    "parse_gates",
    "record_from_gates",
]
