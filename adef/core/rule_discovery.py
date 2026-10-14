"""Shared, read-only discovery layer for an existing detection-rule repository.

Both the catalog engine (``adef catalog``) and the schema rule-scanner
(``adef schema init --rule-root``) need the same thing: walk a repo the user
points at, figure out what each rule file *is*, and pull out its query text plus
whatever metadata can be inferred without asking. This module is that single
walk — built once so the two callers can never drift.

Design commitments:

- **Read-only.** Discovery never writes anywhere. It only reads the user's repo.
- **Infer-and-flag, never block.** Ambiguous files are catalogued with null
  fields and ``needs_review=True``; discovery never prompts.
- **Format vs engine are distinct.** ``format`` / ``query_language`` carry the
  *true* source language (``sigma``, ``spl``, ``kql``, ``cql``, ``sql``) losslessly.
  ``engine`` folds to ADEF's internal four-value taxonomy (``sigma``, ``sql``,
  ``sch_sql``, ``composite``) guarded by ``tests/test_no_new_engine_types.py``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, Sequence, Union

import yaml

from adef.core import profiles as profiles_mod
from adef.core.profiles import Profile

# Query languages we recognise. This is the *source-format* axis, NOT the
# four-value engine taxonomy — keep the two separate on purpose.
# User extraction profiles add their own format names (the profile ``name``).
Format = str  # one of: "sigma", "spl", "kql", "cql", "sql", "splunk-escu", "panther"

# Support outcome: how well ADEF can handle a recognized file.
SUPPORTED = "supported"                            # recognized AND metadata/query extractable
RECOGNIZED_UNSUPPORTED = "recognized_unsupported"  # format known, extractor pending
NOT_A_RULE = "not_a_rule"                          # config, docs, pack, story, data model…
# Reporting-only outcome (never on DiscoveredRule): a structured file no
# profile or recognizer claimed. This is the clustering input for the
# catalog-onboarding skill.
UNCLAIMED = "unclaimed"

# Review reasons: needs_review with a *why*. Structural
# reasons drive the ⚠ marker and headline counts; NO_MITRE is enrichment
# work (the mitre-tagger queue), visible but quiet.
REVIEW_MALFORMED = "malformed"          # extraction threw; catalogued raw
REVIEW_EXTERNAL_LOGIC = "external_logic"  # logic in a sibling file we don't parse
REVIEW_NO_PLATFORM = "no_platform"      # platform could not be inferred/inherited
REVIEW_NO_MITRE = "no_mitre"            # no ATT&CK mapping found anywhere
REVIEW_INVALID_MITRE = "invalid_mitre"  # a mapped ID isn't in the ATT&CK reference
# Set by the GATES import, not by discovery, but they live here so the
# headline-warning set below can name them without importing `gates` (which
# imports *this* module). A deployable-but-unfinished verdict: CONDITIONAL means
# prerequisites are outstanding, TIME_BOX means the rule has an expiry.
REVIEW_GATES_CONDITIONAL = "gates_conditional"
REVIEW_GATES_TIME_BOX = "gates_time_box"
# The reasons that trip the ⚠ marker and the headline count — i.e. what a bare
# `--needs-review` surfaces. Named "structural" for the discovery cases that
# defined it (ADEF couldn't parse or infer something), but the membership test
# is behavioural: is this worth putting in front of someone unprompted? A
# CONDITIONAL rule whose prerequisite is unmet and a TIME_BOX rule past its
# expiry both are — they are deployed, or about to be, on an unfinished
# decision. `no_mitre` stays out: it's a queue to drain, not a warning.
STRUCTURAL_REVIEW_REASONS = frozenset(
    {
        REVIEW_MALFORMED,
        REVIEW_EXTERNAL_LOGIC,
        REVIEW_NO_PLATFORM,
        REVIEW_INVALID_MITRE,
        REVIEW_GATES_CONDITIONAL,
        REVIEW_GATES_TIME_BOX,
    }
)


def structural_reasons(reasons) -> tuple[str, ...]:
    """The review reasons that should trip the headline warning."""
    return tuple(r for r in reasons if r in STRUCTURAL_REVIEW_REASONS)

# Fold a source format into ADEF's internal engine taxonomy. Sigma is its own
# engine; SQL is sql; everything else is a query engine we treat as sql-shaped
# for the internal taxonomy while preserving the true format in ``format``.
_FORMAT_TO_ENGINE = {
    "sigma": "sigma",
    "sql": "sql",
    "spl": "sql",
    "kql": "sql",
    "cql": "sql",
    "splunk-escu": "sql",  # SPL query engine
    "panther": "sql",      # Python-defined detection; folds to sql internally
}

# Map a source format to the query language its ``query_text`` is written in, for
# schema field extraction. Splunk ESCU rules carry SPL. Formats without a single
# extractable query language (sigma structure, panther python) map to themselves
# and are simply skipped by the field scanner.
_FORMAT_TO_QUERY_LANGUAGE = {
    "splunk-escu": "spl",
}

_MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Raw source-literal extractors: the table/index the rule reads from, verbatim.
_SQL_FROM_RE = re.compile(r"\bfrom\s+([A-Za-z_][\w.]*)", re.IGNORECASE)
_SPL_SOURCETYPE_RE = re.compile(r"\bsourcetype\s*=\s*\"?([^\s\"|]+)\"?", re.IGNORECASE)
_SQL_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_sql_comments(query: str) -> str:
    """Drop ``--`` and ``/* */`` comments so prose like "adapted from a
    SnowAlert query" can't masquerade as a FROM table (2026-07-21 E2E
    finding against Panther scheduled queries)."""
    return _SQL_LINE_COMMENT_RE.sub("", _SQL_BLOCK_COMMENT_RE.sub("", query))


# Not table names: SQL constructs that can follow FROM.
_SQL_FROM_RESERVED = {"table", "select", "values", "unnest", "lateral"}


def _sql_from_table(query: str) -> str:
    """First plausible FROM table literal, skipping comments and constructs
    like Snowflake's ``FROM TABLE(RESULT_SCAN(...))``."""
    for m in _SQL_FROM_RE.finditer(_strip_sql_comments(query)):
        candidate = m.group(1)
        if candidate.lower() not in _SQL_FROM_RESERVED:
            return candidate
    return ""
_SPL_INDEX_RE = re.compile(r"\bindex\s*=\s*\"?([A-Za-z_][\w.-]*)\"?", re.IGNORECASE)
_KQL_LEAD_TABLE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)")

# KQL table name → platform. Best-effort; unknowns leave platform unset.
_KQL_TABLE_PLATFORM = {
    "deviceprocessevents": "windows",
    "devicenetworkevents": "windows",
    "devicefileevents": "windows",
    "deviceevents": "windows",
    "devicelogonevents": "windows",
    "signinlogs": "identity",
    "auditlogs": "identity",
    "azureactivity": "cloud-azure",
    "awscloudtrail": "cloud-aws",
}


@dataclass
class DiscoveredRule:
    """One rule file found in the user's repo, plus inferred metadata.

    ``path`` is the source file (in the user's repo — never modified). The
    ``platform``/``mitre``/``kind`` fields are best-effort: empty/None means
    "could not infer", which the caller records as ``needs_review``.
    """

    path: Path
    format: Format
    query_text: str
    title: str = ""
    platform: Optional[str] = None
    mitre: tuple[str, ...] = ()
    kind: str = "atomic"
    rule_uuid: str = ""
    # The raw table/index/logsource literal the rule queries, verbatim (no
    # normalisation). Empty when unresolvable. Keys schema prioritization and
    # `adef schema check`.
    data_source: str = ""
    # SHA-256 of the source file's raw bytes at discovery time. Stamped by
    # ``walk_outcomes`` (one place, all extraction paths). The `adef sync`
    # reconciler uses it to tell unchanged from modified, and as the identity
    # fallback for formats with no embedded UUID. Empty only if unreadable.
    source_hash: str = ""
    # How well ADEF handles this format: SUPPORTED (parsed) or
    # RECOGNIZED_UNSUPPORTED (format known, extractor pending, e.g. Panther .py).
    support: str = SUPPORTED
    needs_review: bool = False
    # Why review is needed (REVIEW_* constants). Computed centrally by
    # ``walk_outcomes``; ``needs_review`` == bool(review_reasons).
    review_reasons: tuple[str, ...] = ()
    # Set by profile-based extraction, where the query language comes from the
    # profile document rather than the static format map.
    query_language_hint: str = ""

    @property
    def query_language(self) -> Format:
        """The source query language for schema field extraction.

        Usually the same as ``format``; vendor packagings map to their underlying
        query language (Splunk ESCU rules are SPL). Panther has no single query
        language we extract in v1. Profile-discovered rules carry the profile's
        declared ``query_language`` as a hint.
        """
        if self.query_language_hint:
            return self.query_language_hint
        return _FORMAT_TO_QUERY_LANGUAGE.get(self.format, self.format)

    @property
    def engine(self) -> str:
        """ADEF internal four-value engine taxonomy (folds non-Sigma formats)."""
        return _FORMAT_TO_ENGINE.get(self.format, "sql")


# --------------------------------------------------------------------------- #
# Format recognition — content-signature registry (general-shape-first)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Recognition:
    """The outcome of classifying one file: its format + how well we support it."""

    format: Optional[Format]  # None only when support is NOT_A_RULE
    support: str              # one of SUPPORTED / RECOGNIZED_UNSUPPORTED / NOT_A_RULE


def _load_yaml(text: str) -> Optional[dict]:
    """Parse ``text`` as a YAML mapping, or return ``None`` if it isn't one."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


# Each recognizer takes (name, text, parsed-yaml-or-None) and returns a
# ``Recognition`` if it claims the file, else ``None``. Order matters: the first
# claim wins. Recognizers key on *content signature* — the presence of a
# query/logic field plus detection metadata — not on file extension. Extension
# only gates the raw-query recognizers (a ``.sql`` file is SQL by extension).


def _recognize_sigma(name: str, text: str, doc: Optional[dict]) -> Optional[Recognition]:
    if doc is None:
        return None
    # Sigma's signature: a detection block + a logsource block.
    if isinstance(doc.get("detection"), dict) and "logsource" in doc:
        return Recognition("sigma", SUPPORTED)
    return None


def _recognize_splunk_escu(name: str, text: str, doc: Optional[dict]) -> Optional[Recognition]:
    if doc is None:
        return None
    # Splunk ESCU detection: has a `search` (the SPL query) + a `type`. A *story*
    # or *data model* has neither → falls through to not-a-rule. This is the
    # general-shape test (query field present), not a filename check.
    if doc.get("search") and doc.get("type"):
        return Recognition("splunk-escu", SUPPORTED)
    return None


def _recognize_panther(name: str, text: str, doc: Optional[dict]) -> Optional[Recognition]:
    if doc is None:
        return None
    analysis = str(doc.get("AnalysisType", "")).lower()
    # A Panther *pack* has AnalysisType: pack (+ PackID) and no rule logic → not a
    # rule. A rule/scheduled_rule/correlation_rule carries RuleID and points at
    # its logic via Filename (a sibling .py we don't parse in v1) → recognized,
    # not-yet-supported for query extraction.
    if analysis == "pack" or "PackID" in doc:
        return None  # let it fall through to NOT_A_RULE
    if doc.get("RuleID") and analysis:
        return Recognition("panther", RECOGNIZED_UNSUPPORTED)
    return None


def _recognize_raw_query(name: str, text: str, doc: Optional[dict]) -> Optional[Recognition]:
    """Raw single-query files, gated by extension (they carry no metadata block)."""
    lower = name.lower()
    if lower.endswith(".sql"):
        return Recognition("sql", SUPPORTED)
    if lower.endswith(".kql"):
        return Recognition("kql", SUPPORTED)
    if lower.endswith(".cql"):
        return Recognition("cql", SUPPORTED)
    return None


def _recognize_spl_conf(name: str, text: str, doc: Optional[dict]) -> Optional[Recognition]:
    """Splunk ``savedsearches.conf``: a stanza with a real ``search = <SPL>`` line.

    Tighter than the old ``[`` + ``search`` guess so osquery/app ``.conf`` files
    don't false-positive.
    """
    if not name.lower().endswith(".conf"):
        return None
    if re.search(r"^\[.+\]\s*$", text, re.MULTILINE) and re.search(
        r"^\s*search\s*=", text, re.MULTILINE
    ):
        return Recognition("spl", SUPPORTED)
    return None


_RECOGNIZERS = (
    _recognize_sigma,
    _recognize_splunk_escu,
    _recognize_panther,
    _recognize_spl_conf,
    _recognize_raw_query,
)


def recognize(filename: str, text: str) -> Recognition:
    """Classify a file: its detection format and how well ADEF supports it.

    Content-signature driven (general-shape-first): a file is a *rule* when it
    carries a query/logic field plus detection metadata. Vendor signatures locate
    those; they are not a closed list. Anything no recognizer claims — configs,
    docs, packs, stories, data models — is ``NOT_A_RULE``.
    """
    doc = _load_yaml(text) if _looks_like_yaml(filename, text) else None
    for recognizer in _RECOGNIZERS:
        result = recognizer(filename, text, doc)
        if result is not None:
            return result
    return Recognition(None, NOT_A_RULE)


def _looks_like_yaml(filename: str, text: str) -> bool:
    """Cheap gate: only attempt YAML parse for plausibly-YAML files."""
    if filename.lower().endswith((".yml", ".yaml")):
        return True
    # Some rule files are YAML without the extension; a leading mapping key is a
    # good-enough hint without paying the parse cost on every .sql/.conf.
    return bool(re.match(r"^\s*[A-Za-z_][\w-]*\s*:", text))


def sniff_format(filename: str, text: str) -> Optional[Format]:
    """Back-compat: return the recognized format string, or ``None`` if not a rule.

    Thin wrapper over :func:`recognize`; prefer ``recognize`` for new code so you
    get the support outcome too.
    """
    result = recognize(filename, text)
    return result.format if result.support != NOT_A_RULE else None


# --------------------------------------------------------------------------- #
# Per-format metadata extraction
# --------------------------------------------------------------------------- #
def _sigma_platform(logsource: dict) -> Optional[str]:
    """Map a Sigma ``logsource`` block to an ADEF platform folder name."""
    product = str(logsource.get("product", "")).lower()
    if product in {"windows", "linux", "macos"}:
        return "macos" if product == "macos" else product
    service = str(logsource.get("service", "")).lower()
    if "aws" in product or "aws" in service:
        return "cloud-aws"
    if "azure" in product or "azure" in service:
        return "cloud-azure"
    return None


def _has_invalid_mitre(ids: Iterable[str], workspace: Path | None = None) -> bool:
    """True if any mapped ID isn't a real ATT&CK technique.

    Imported lazily so discovery never hard-depends on the snapshot at import
    time; the reference itself is cached after first load.

    ``workspace`` picks the snapshot. "Is this a real technique" is only
    answerable against *some* ATT&CK version, and zero-arg answers against
    ``$ADEF_WORKSPACE`` or the shipped copy — so `adef catalog --workspace X`,
    after `adef attack refresh` wrote a newer snapshot into X, flagged every
    rule mapped to a technique newer than the shipped copy as
    ``invalid_mitre``. Unlike a bad report, that one *persists*: it is written
    into the record and into the `needs_review` queue a human then triages.
    """
    from adef.core.attack import attack_reference

    ref = attack_reference(workspace)
    return any(not ref.is_valid(tid) for tid in ids)


def _normalise_mitre(tokens: Iterable[str]) -> tuple[str, ...]:
    """Uppercase + dedupe MITRE technique IDs, preserving first-seen order.

    Each token may pack *several* IDs (a comma-joined string, ``TAxxxx:Txxxx``
    pairs, prose) — capture **all** of them, not just the first. (Regression:
    `.search()` silently dropped every ID after the first in a shared string.)
    """
    seen: dict[str, None] = {}
    for tok in tokens:
        for m in _MITRE_TECHNIQUE_RE.finditer(str(tok)):  # str(): tolerate ints/etc from parsed lists
            seen.setdefault(m.group(0).upper(), None)
    return tuple(seen)


def _extract_sigma(text: str) -> DiscoveredRule:
    """Full auto-extraction for a Sigma YAML rule."""
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        data = {}
    logsource = data.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}
    tags = data.get("tags") or []
    mitre = _normalise_mitre(str(t) for t in tags) if isinstance(tags, list) else ()
    platform = _sigma_platform(logsource)
    # data_source: Sigma's table-equivalent is its logsource category
    # (else service, else product), verbatim.
    data_source = str(
        logsource.get("category") or logsource.get("service") or logsource.get("product") or ""
    ).strip()
    return DiscoveredRule(
        path=Path("."),  # filled by caller
        format="sigma",
        query_text=text,
        title=str(data.get("title") or "").strip(),
        platform=platform,
        mitre=mitre,
        kind="atomic",
        rule_uuid=str(data.get("id") or "").strip(),
        data_source=data_source,
        needs_review=not (platform and mitre),
    )


def _extract_spl_conf(text: str) -> DiscoveredRule:
    """Extract the search body + title from a Splunk savedsearches.conf stanza."""
    stanza = re.search(r"^\[(.+?)\]\s*$", text, re.MULTILINE)
    title = stanza.group(1).strip() if stanza else ""
    # ``search = ...`` may span continuation lines; grab through end of stanza.
    body = re.search(r"^\s*search\s*=\s*(.+)", text, re.MULTILINE | re.DOTALL)
    query = body.group(1).strip() if body else text.strip()
    mitre = _normalise_mitre([text])
    idx = _SPL_INDEX_RE.search(query)
    return DiscoveredRule(
        path=Path("."),
        format="spl",
        query_text=query,
        title=title,
        platform=None,
        mitre=mitre,
        kind="atomic",
        data_source=idx.group(1) if idx else "",
        needs_review=True,  # raw SPL: platform unknown until reviewed
    )


def _extract_kql(text: str) -> DiscoveredRule:
    """Best-effort platform inference for a KQL query from its lead table."""
    lead_table = _KQL_LEAD_TABLE_RE.match(text)
    platform = None
    data_source = ""
    if lead_table:
        data_source = lead_table.group(1)  # verbatim, no case normalisation
        platform = _KQL_TABLE_PLATFORM.get(data_source.lower())
    mitre = _normalise_mitre([text])
    return DiscoveredRule(
        path=Path("."),
        format="kql",
        query_text=text.strip(),
        platform=platform,
        mitre=mitre,
        kind="atomic",
        data_source=data_source,
        needs_review=not (platform and mitre),
    )


def _extract_generic(text: str, fmt: Format) -> DiscoveredRule:
    """Fallback for raw SQL / CQL: no reliable metadata → flag for review.

    SQL still yields a data_source from its ``FROM`` clause; CQL has no reliable
    table literal, so it stays empty.
    """
    data_source = ""
    if fmt == "sql":
        data_source = _sql_from_table(text)
    return DiscoveredRule(
        path=Path("."),
        format=fmt,
        query_text=text.strip(),
        platform=None,
        mitre=_normalise_mitre([text]),
        kind="atomic",
        data_source=data_source,
        needs_review=True,
    )


# ESCU's public data_source vocabulary, mapped to an ADEF platform. First
# prefix match wins; of this table, only one ordering is load-bearing —
# `Sysmon for Linux` before `Sysmon` — since "Sysmon for Linux..." also
# starts with "sysmon" and would otherwise resolve to windows. No other pair
# here shares a prefix relationship, so their relative order is arbitrary.
_ESCU_DATA_SOURCE_PLATFORMS: tuple[tuple[str, str], ...] = (
    ("sysmon for linux", "linux"),
    ("linux", "linux"),
    ("sysmon", "windows"),
    ("windows", "windows"),
    ("powershell", "windows"),
    ("asl aws", "cloud-aws"),
    ("aws", "cloud-aws"),
    ("azure", "cloud-azure"),
    ("o365", "cloud-azure"),
)


def _escu_platform(sources: Iterable[str]) -> Optional[str]:
    """Infer an ADEF platform from ESCU ``data_source`` entries.

    Each entry is matched (case-insensitive prefix, first match wins) against
    Splunk's public data-source vocabulary; entries with no opinion (e.g.
    ``CrowdStrike``, ``Osquery``) are ignored. Returns the platform only if
    every opinionated entry agrees — ``None`` on no opinions or disagreement.
    """
    platforms: set[str] = set()
    for source in sources:
        text = str(source).strip().lower()
        for prefix, platform in _ESCU_DATA_SOURCE_PLATFORMS:
            if text.startswith(prefix):
                platforms.add(platform)
                break
    if len(platforms) == 1:
        return next(iter(platforms))
    return None


def _extract_splunk_escu(text: str) -> DiscoveredRule:
    """Full extraction for a Splunk ESCU detection YAML.

    The SPL query is the ``search`` field; metadata is inline
    (``name``/``mitre_attack_id``/``data_source``).
    """
    doc = _load_yaml(text) or {}
    query = str(doc.get("search") or "").strip()
    title = str(doc.get("name") or "").strip()

    # Top-level first; upstream ESCU nests it under `tags:`.
    tags = doc.get("tags")
    mitre_raw = doc.get("mitre_attack_id") or (
        tags.get("mitre_attack_id") if isinstance(tags, dict) else None
    ) or []
    mitre = _normalise_mitre(str(t) for t in mitre_raw) if isinstance(mitre_raw, list) else ()

    # data_source may be a list (ESCU) — take the first, verbatim, for the
    # recorded data_source; the platform inference below considers all of them.
    ds_raw = doc.get("data_source") or doc.get("datamodel") or ""
    if isinstance(ds_raw, list):
        data_source = str(ds_raw[0]).strip() if ds_raw else ""
        ds_list = [str(v) for v in ds_raw]
    else:
        data_source = str(ds_raw).strip()
        ds_list = [data_source] if data_source else []

    return DiscoveredRule(
        path=Path("."),
        format="splunk-escu",
        query_text=query,
        title=title,
        platform=_escu_platform(ds_list),  # from data_source, Splunk's public vocabulary
        mitre=mitre,
        kind="atomic",
        rule_uuid=str(doc.get("id") or "").strip(),  # ESCU carries a stable UUID
        data_source=data_source,
        support=SUPPORTED,
        needs_review=not mitre,
    )


def _extract_panther(text: str) -> DiscoveredRule:
    """Metadata-only extraction for a Panther rule.

    The detection logic lives in a sibling ``.py`` (``Filename:``) which we do
    not parse in v1 → ``query_text`` stays empty, ``support`` is
    RECOGNIZED_UNSUPPORTED. Metadata (title, MITRE via ``Reports``, data source
    via ``LogTypes``) still comes from the YAML.
    """
    doc = _load_yaml(text) or {}
    title = str(doc.get("DisplayName") or doc.get("RuleID") or "").strip()

    # MITRE lives under Reports -> "MITRE ATT&CK" -> ["TA0001:T1078", ...].
    reports = doc.get("Reports") or {}
    mitre_tokens: list[str] = []
    if isinstance(reports, dict):
        for vals in reports.values():
            if isinstance(vals, list):
                mitre_tokens.extend(str(v) for v in vals)
    mitre = _normalise_mitre(mitre_tokens)

    logtypes = doc.get("LogTypes") or []
    data_source = str(logtypes[0]).strip() if isinstance(logtypes, list) and logtypes else ""

    return DiscoveredRule(
        path=Path("."),
        format="panther",
        query_text="",  # logic is in the sibling .py — deferred
        title=title,
        platform=None,
        mitre=mitre,
        kind="atomic",
        rule_uuid=str(doc.get("RuleID") or "").strip(),  # Panther's stable key (a name)
        data_source=data_source,
        support=RECOGNIZED_UNSUPPORTED,
        needs_review=True,
    )


# An extractor returns one rule or many (a JSON export can carry several).
_EXTRACTORS: dict[str, Callable[[str], Union[DiscoveredRule, list[DiscoveredRule]]]] = {
    "sigma": lambda text: _extract_sigma(text),
    "spl": lambda text: _extract_spl_conf(text),
    "kql": lambda text: _extract_kql(text),
    "sql": lambda text: _extract_generic(text, "sql"),
    "cql": lambda text: _extract_generic(text, "cql"),
    "splunk-escu": lambda text: _extract_splunk_escu(text),
    "panther": lambda text: _extract_panther(text),
}


# --------------------------------------------------------------------------- #
# Profile-based extraction (user profiles claim files before built-ins)
# --------------------------------------------------------------------------- #
def shape_literals(query: str, query_language: str) -> tuple[str, ...]:
    """Shape-axis literals a query pins beyond its container.

    Today: SPL ``sourcetype=`` values. Each language we teach here upgrades
    ``schema check`` from union-matching to exact-matching on that platform —
    incrementally, with no format change (e.g. CQL ``#event_simpleName=`` and
    Elastic ``event.dataset`` are future additions).
    """
    if not query:
        return ()
    if query_language == "spl":
        seen: dict[str, None] = {}
        for m in _SPL_SOURCETYPE_RE.finditer(query):
            seen.setdefault(m.group(1), None)
        return tuple(seen)
    return ()


def _infer_data_source(query: str, query_language: str) -> str:
    """Best-effort raw source literal from a query, by language.

    The same extraction the built-in formats use (SQL ``FROM``, SPL
    ``index=``, KQL lead table) — applied when a profile's map doesn't
    provide ``data_source`` (found by the 2026-07-21 E2E test: Panther
    scheduled queries carried their table in ``FROM`` but records were empty).
    """
    if not query:
        return ""
    if query_language == "sql":
        return _sql_from_table(query)
    if query_language == "spl":
        m = _SPL_INDEX_RE.search(query)
        return m.group(1) if m else ""
    if query_language == "kql":
        m = _KQL_LEAD_TABLE_RE.match(query)
        return m.group(1) if m else ""
    return ""


# `platform` becomes a directory name (catalog/<platform>/), and a profile can
# take it from rule content — so it must be exactly one plain path segment.
# Charset only: `record_path` reuses this to refuse a bad platform *by reason*,
# and folding the length bound in here made its charset message answer an
# overlong value with "not a single plain path segment (lowercase letters,
# digits, '-' or '_')" — false, and unactionable. Length is a separate gate.
_PLATFORM_SEGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

# The longest platform `record_path` will write as a directory name. Lives here
# rather than in `catalog` because `catalog` imports this module and not the
# reverse, and both ends have to agree: `safe_platform` admitting a value the
# writer then refuses is the whole bug this constant closes.
PLATFORM_MAX_BYTES = 255


def safe_platform(value: object) -> Optional[str]:
    """``value`` lowercased if it is one safe path segment, else ``None``."""
    text = str(value or "").strip().lower()
    if not _PLATFORM_SEGMENT_RE.match(text):
        return None
    # Length too, not just charset: an overlong value passed every check here,
    # became the bucket with nothing flagged for review, and then killed the run
    # at write time on `record_path`'s refusal — the exact failure the callers
    # route through this helper to avoid. The charset above admits only ASCII,
    # so this is a byte count despite measuring characters.
    return text if len(text) <= PLATFORM_MAX_BYTES else None


def _extract_via_profile(profile: Profile, doc: dict) -> DiscoveredRule:
    """Build a ``DiscoveredRule`` from one profile-claimed document."""
    fields = profiles_mod.extract_fields(profile, doc)
    mitre = _normalise_mitre(fields.get("mitre") or [])
    if not mitre:
        # Tier-2 parity with the conf extractor: sweep the
        # rule's prose for technique-ID tokens when the map yields nothing.
        mitre = _normalise_mitre(
            [fields.get("title", ""), fields.get("description", ""), fields.get("query", "")]
        )
    # Profile platform comes from rule content: keep it only if it is one plain
    # path segment (it becomes catalog/<platform>/); anything else is unknown.
    platform = safe_platform(fields.get("platform"))
    data_source = fields.get("data_source", "") or _infer_data_source(
        fields.get("query", ""), profile.query_language
    )
    return DiscoveredRule(
        path=Path("."),  # filled by caller
        format=profile.name,
        query_text=fields.get("query", ""),
        title=fields.get("title", ""),
        platform=platform,
        mitre=mitre,
        kind="atomic",
        rule_uuid=fields.get("uuid", ""),
        data_source=data_source,
        support=SUPPORTED,
        needs_review=not (platform and mitre),
        query_language_hint=(
            profile.query_language if profile.query_language != "none" else ""
        ),
    )


def _record_hash(doc: dict) -> str:
    """Content hash of one record, stable across key order and file position."""
    canonical = json.dumps(_str_keys(doc), sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _str_keys(node: Any) -> Any:
    """YAML allows int/date keys; json.dumps(sort_keys=True) can't order them."""
    if isinstance(node, dict):
        return {str(k): _str_keys(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_str_keys(v) for v in node]
    return node


def _common_keys(records: list[dict]) -> tuple[str, ...]:
    keys = set(map(str, records[0]))
    for r in records[1:]:
        keys &= set(map(str, r))
    return tuple(sorted(keys))


def _unclaimed_shape(
    filename: str, text: str
) -> Optional[tuple[tuple[str, ...], str, tuple[str, ...]]]:
    """(top-level keys, records path, record keys) for a structured file nothing
    claimed, or None if it holds no mapping. JSON counts as structured too: a
    bulk export is usually a JSON envelope or array, and a file the onboarding
    report never lists can never get a profile."""
    stripped = text.lstrip()
    parsed: Any = None
    if filename.lower().endswith(".json") or stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    if parsed is None and (_looks_like_yaml(filename, text) or stripped.startswith("- ")):
        try:  # not _load_yaml: that keeps mappings only, and a bare list is a shape we report
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            parsed = None
    if isinstance(parsed, list):
        records = [r for r in parsed if isinstance(r, dict)]
        return ((), "[]", _common_keys(records)) if records else None
    if not (isinstance(parsed, dict) and parsed):
        return None
    top = tuple(sorted(str(k) for k in parsed))
    for key, value in parsed.items():  # an envelope: the first list of mappings
        records = [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []
        if records:
            return top, f"{key}[]", _common_keys(records)
    return top, "", ()


def _profile_claim(
    profiles: Sequence[Profile], filename: str, text: str
) -> Optional[tuple[Profile, list[dict], bool]]:
    """First profile whose signature claims the file: its records, and whether
    the file is a multi-record container (so each record needs its own hash)."""
    parsed: dict[str, tuple[list[dict], bool]] = {}
    for profile in profiles:
        if profile.container not in parsed:
            parsed[profile.container] = profiles_mod.parse_container_shaped(profile.container, text)
        documents, is_array = parsed[profile.container]
        docs = [
            rec
            for d in documents
            for rec in profiles_mod.records_of(profile, d)
            if profiles_mod.matches(profile, filename, rec)
        ]
        if docs:
            return profile, docs, bool(profile.records) or is_array
    return None


# --------------------------------------------------------------------------- #
# The walk — ONE walker, shared by discovery, catalog, and reporting
# --------------------------------------------------------------------------- #
@dataclass
class FileOutcome:
    """Per-file classification result, for reporting (``adef catalog --report``).

    ``outcome`` is SUPPORTED / RECOGNIZED_UNSUPPORTED / UNCLAIMED / NOT_A_RULE.
    ``rules`` is non-empty only for the first two. UNCLAIMED = the file parses
    as a structured mapping but nothing claimed it — the clustering input for
    profile authoring. NOT_A_RULE = everything else (docs, raw config, data).
    """

    path: Path
    outcome: str
    format: Optional[Format] = None
    rules: tuple[DiscoveredRule, ...] = ()
    top_level_keys: tuple[str, ...] = ()
    # For an unclaimed file holding many records: where they are (`[]` for a
    # top-level array, `data[]` for an envelope) and the keys every record
    # shares — what a profile's `signature.records` and `all_keys` need.
    records_path: str = ""
    record_keys: tuple[str, ...] = ()


def mitre_review_reasons(
    mitre: Sequence[str], workspace: Path | None = None
) -> list[str]:
    """The review reasons for one MITRE mapping: unmapped, or mapped to fiction.

    Split out of ``finalize_review`` because ``mitre`` is *enrichment*: every path
    that restores a human's mapping onto a record whose ``review_reasons`` were
    already computed (``adef sync``, a GATES re-import) has to recompute these
    two reasons, and only these two. See ``catalog.refresh_mitre_review``.

    ``no_mitre`` needs no workspace — it's a test for emptiness. ``invalid_mitre``
    does: see ``_has_invalid_mitre``.
    """
    if not mitre:
        return [REVIEW_NO_MITRE]
    if _has_invalid_mitre(mitre, workspace):
        return [REVIEW_INVALID_MITRE]
    return []


def finalize_review(
    rule: DiscoveredRule, malformed: bool = False, workspace: Path | None = None
) -> DiscoveredRule:
    """Compute ``review_reasons`` + ``needs_review`` centrally.

    One place, all discovery paths — so the semantics can't drift between
    built-in extractors and profile extraction. Also re-run by the catalog
    after declaration-based platform inheritance.

    ``workspace`` is a pass-through for the one reason of the five that depends
    on an ATT&CK snapshot (``invalid_mitre``). The other four — ``malformed``,
    ``external_logic``, ``no_platform`` and ``no_mitre`` — are properties of the
    file in front of it; ``no_mitre`` in particular is just a test for
    emptiness, which is why it needs no snapshot either.
    """
    reasons: list[str] = []
    if malformed:
        reasons.append(REVIEW_MALFORMED)
    if rule.support == RECOGNIZED_UNSUPPORTED:
        reasons.append(REVIEW_EXTERNAL_LOGIC)
    if not rule.platform:
        reasons.append(REVIEW_NO_PLATFORM)
    reasons += mitre_review_reasons(rule.mitre, workspace)
    rule.review_reasons = tuple(reasons)
    rule.needs_review = bool(reasons)
    return rule


def walk_outcomes(
    rule_root: Path,
    profiles: Sequence[Profile] = (),
    workspace: Path | None = None,
) -> Iterator[FileOutcome]:
    """Classify every file under ``rule_root``; yield one ``FileOutcome`` each.

    Read-only. User ``profiles`` are checked **before** built-in recognizers
    (an org can override how its own format is read). A profile
    may claim multiple documents per file (multi-doc contract; v1 containers
    yield one). Unreadable files are skipped entirely.
    """
    root = Path(rule_root).expanduser()
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Never descend into VCS internals: .git holds packed refs, hook
        # samples, and object blobs — never rules, and parsing them is pure
        # noise (.git objects surfaced as "unrecognized").
        if ".git" in path.parts:
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Hash the raw bytes (not the decoded text) so it's a faithful digest of
        # the file on disk — the `adef sync` unchanged/modified signal.
        source_hash = hashlib.sha256(raw).hexdigest()

        # 1. User profiles first.
        claim = _profile_claim(profiles, path.name, text)
        if claim is not None:
            profile, docs, per_record = claim
            rules = []
            for doc in docs:
                rule = _extract_via_profile(profile, doc)
                rule.path = path
                # In a multi-record container (the profile declares `records`,
                # or the file is a top-level array) every record shares the
                # file's bytes, so each is hashed on its own content. Decided by
                # the file's SHAPE, never by how many records it holds today —
                # a count-based choice re-keys every record when one is added.
                # Single-document formats keep the file hash (no churn).
                rule.source_hash = _record_hash(doc) if per_record else source_hash
                rules.append(finalize_review(rule, workspace=workspace))
            yield FileOutcome(
                path=path, outcome=SUPPORTED, format=profile.name, rules=tuple(rules)
            )
            continue

        # 2. Built-in recognizers.
        rec = recognize(path.name, text)
        if rec.support == NOT_A_RULE or rec.format is None:
            shape = _unclaimed_shape(path.name, text)
            if shape is not None:
                top, records_path, record_keys = shape
                yield FileOutcome(
                    path=path,
                    outcome=UNCLAIMED,
                    top_level_keys=top,
                    records_path=records_path,
                    record_keys=record_keys,
                )
            else:
                yield FileOutcome(path=path, outcome=NOT_A_RULE)
            continue

        extractor = _EXTRACTORS.get(rec.format)
        malformed = False
        if extractor is None:
            extracted: list[DiscoveredRule] = [
                DiscoveredRule(
                    path=path,
                    format=rec.format,
                    query_text="",
                    support=rec.support,
                )
            ]
        else:
            try:
                result = extractor(text)
                # An extractor may yield one rule or many (a JSON export can
                # carry several); normalise to a list either way.
                extracted = result if isinstance(result, list) else [result]
            except Exception:
                # A malformed rule of a known format still gets catalogued as
                # needs_review rather than vanishing.
                malformed = True
                extracted = [
                    DiscoveredRule(
                        path=path,
                        format=rec.format,
                        query_text=text.strip(),
                        support=rec.support,
                    )
                ]
        for rule in extracted:
            rule.path = path
            rule.source_hash = source_hash
            finalize_review(rule, malformed=malformed, workspace=workspace)
        # A supported multi-rule file with no rules (empty envelope) still
        # reports as its format, not a silent drop.
        outcome = extracted[0].support if extracted else rec.support
        yield FileOutcome(
            path=path, outcome=outcome, format=rec.format, rules=tuple(extracted)
        )


def discover_rules(
    rule_root: Path,
    profiles: Sequence[Profile] = (),
    workspace: Path | None = None,
) -> Iterator[DiscoveredRule]:
    """Yield a ``DiscoveredRule`` for every *rule* file under ``rule_root``.

    Read-only; built on :func:`walk_outcomes` (one walker, no divergence).
    ``NOT_A_RULE``/``UNCLAIMED`` files are skipped. Recognized files are
    yielded — including ``RECOGNIZED_UNSUPPORTED`` formats (e.g. Panther, whose
    logic is external) so the catalog reports honest coverage instead of
    silently dropping them.
    """
    for outcome in walk_outcomes(rule_root, profiles, workspace):
        yield from outcome.rules


__all__ = [
    "DiscoveredRule",
    "FileOutcome",
    "Recognition",
    "SUPPORTED",
    "RECOGNIZED_UNSUPPORTED",
    "NOT_A_RULE",
    "UNCLAIMED",
    "REVIEW_MALFORMED",
    "REVIEW_EXTERNAL_LOGIC",
    "REVIEW_NO_PLATFORM",
    "REVIEW_NO_MITRE",
    "REVIEW_GATES_CONDITIONAL",
    "REVIEW_GATES_TIME_BOX",
    "STRUCTURAL_REVIEW_REASONS",
    "discover_rules",
    "finalize_review",
    "mitre_review_reasons",
    "recognize",
    "shape_literals",
    "sniff_format",
    "structural_reasons",
    "walk_outcomes",
]
