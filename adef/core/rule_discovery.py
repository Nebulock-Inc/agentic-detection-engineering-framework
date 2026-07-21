"""Shared, read-only discovery layer for an existing detection-rule repository.

Both the catalog engine (``adef catalog``) and the schema rule-scanner
(``adef schema init --rule-root``) need the same thing: walk a repo the user
points at, figure out what each rule file *is*, and pull out its query text plus
whatever metadata can be inferred without asking. This module is that single
walk — built once so the two callers can never drift.

Design commitments (see ISA.md 2026-07-15 catalog decision):

- **Read-only.** Discovery never writes anywhere. It only reads the user's repo.
- **Infer-and-flag, never block.** Ambiguous files are catalogued with null
  fields and ``needs_review=True``; discovery never prompts.
- **Format vs engine are distinct.** ``format`` / ``query_language`` carry the
  *true* source language (``sigma``, ``spl``, ``kql``, ``cql``, ``sql``) losslessly.
  ``engine`` folds to ADEF's internal four-value taxonomy (``sigma``, ``sql``,
  ``sch_sql``, ``composite``) guarded by ``tests/test_no_new_engine_types.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence

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
# catalog-onboarding skill (ISA 2026-07-20).
UNCLAIMED = "unclaimed"

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
    # `adef schema check`; see ISA.md 2026-07-16 + 2026-07-20.
    data_source: str = ""
    # How well ADEF handles this format: SUPPORTED (parsed) or
    # RECOGNIZED_UNSUPPORTED (format known, extractor pending, e.g. Panther .py).
    support: str = SUPPORTED
    needs_review: bool = False
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


def _normalise_mitre(tokens: Iterable[str]) -> tuple[str, ...]:
    """Uppercase + dedupe MITRE technique IDs, preserving first-seen order."""
    seen: dict[str, None] = {}
    for tok in tokens:
        m = _MITRE_TECHNIQUE_RE.search(tok)
        if m:
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


def _extract_splunk_escu(text: str) -> DiscoveredRule:
    """Full extraction for a Splunk ESCU detection YAML.

    The SPL query is the ``search`` field; metadata is inline
    (``name``/``mitre_attack_id``/``data_source``).
    """
    doc = _load_yaml(text) or {}
    query = str(doc.get("search") or "").strip()
    title = str(doc.get("name") or "").strip()

    mitre_raw = doc.get("mitre_attack_id") or []
    mitre = _normalise_mitre(str(t) for t in mitre_raw) if isinstance(mitre_raw, list) else ()

    # data_source may be a list (ESCU) — take the first, verbatim.
    ds_raw = doc.get("data_source") or doc.get("datamodel") or ""
    if isinstance(ds_raw, list):
        data_source = str(ds_raw[0]).strip() if ds_raw else ""
    else:
        data_source = str(ds_raw).strip()

    return DiscoveredRule(
        path=Path("."),
        format="splunk-escu",
        query_text=query,
        title=title,
        platform=None,  # ESCU doesn't carry a clean OS platform; inferred later
        mitre=mitre,
        kind="atomic",
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
        query_text="",  # logic is in the sibling .py — deferred (ISA 2026-07-17)
        title=title,
        platform=None,
        mitre=mitre,
        kind="atomic",
        data_source=data_source,
        support=RECOGNIZED_UNSUPPORTED,
        needs_review=True,
    )


_EXTRACTORS = {
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
    """Shape-axis literals a query pins beyond its container (ISA 2026-07-21).

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


def _extract_via_profile(profile: Profile, doc: dict) -> DiscoveredRule:
    """Build a ``DiscoveredRule`` from one profile-claimed document."""
    fields = profiles_mod.extract_fields(profile, doc)
    mitre = _normalise_mitre(fields.get("mitre") or [])
    platform = fields.get("platform") or None
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


def _profile_claim(
    profiles: Sequence[Profile], filename: str, text: str
) -> Optional[tuple[Profile, list[dict]]]:
    """First profile whose signature claims the file, with its documents."""
    parsed: dict[str, list[dict]] = {}
    for profile in profiles:
        if profile.container not in parsed:
            parsed[profile.container] = profiles_mod.parse_container(profile.container, text)
        docs = [d for d in parsed[profile.container] if profiles_mod.matches(profile, filename, d)]
        if docs:
            return profile, docs
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


def walk_outcomes(
    rule_root: Path, profiles: Sequence[Profile] = ()
) -> Iterator[FileOutcome]:
    """Classify every file under ``rule_root``; yield one ``FileOutcome`` each.

    Read-only. User ``profiles`` are checked **before** built-in recognizers
    (ISA 2026-07-20: an org can override how its own format is read). A profile
    may claim multiple documents per file (multi-doc contract; v1 containers
    yield one). Unreadable files are skipped entirely.
    """
    root = Path(rule_root).expanduser()
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # 1. User profiles first.
        claim = _profile_claim(profiles, path.name, text)
        if claim is not None:
            profile, docs = claim
            rules = []
            for doc in docs:
                rule = _extract_via_profile(profile, doc)
                rule.path = path
                rules.append(rule)
            yield FileOutcome(
                path=path, outcome=SUPPORTED, format=profile.name, rules=tuple(rules)
            )
            continue

        # 2. Built-in recognizers.
        rec = recognize(path.name, text)
        if rec.support == NOT_A_RULE or rec.format is None:
            doc = _load_yaml(text) if _looks_like_yaml(path.name, text) else None
            if isinstance(doc, dict) and doc:
                yield FileOutcome(
                    path=path,
                    outcome=UNCLAIMED,
                    top_level_keys=tuple(sorted(str(k) for k in doc)),
                )
            else:
                yield FileOutcome(path=path, outcome=NOT_A_RULE)
            continue

        extractor = _EXTRACTORS.get(rec.format)
        if extractor is None:
            rule = DiscoveredRule(
                path=path,
                format=rec.format,
                query_text="",
                support=rec.support,
                needs_review=True,
            )
        else:
            try:
                rule = extractor(text)
            except Exception:
                # A malformed rule of a known format still gets catalogued as
                # needs_review rather than vanishing.
                rule = DiscoveredRule(
                    path=path,
                    format=rec.format,
                    query_text=text.strip(),
                    support=rec.support,
                    needs_review=True,
                )
            rule.path = path
        yield FileOutcome(
            path=path, outcome=rule.support, format=rec.format, rules=(rule,)
        )


def discover_rules(
    rule_root: Path, profiles: Sequence[Profile] = ()
) -> Iterator[DiscoveredRule]:
    """Yield a ``DiscoveredRule`` for every *rule* file under ``rule_root``.

    Read-only; built on :func:`walk_outcomes` (one walker, no divergence).
    ``NOT_A_RULE``/``UNCLAIMED`` files are skipped. Recognized files are
    yielded — including ``RECOGNIZED_UNSUPPORTED`` formats (e.g. Panther, whose
    logic is external) so the catalog reports honest coverage instead of
    silently dropping them.
    """
    for outcome in walk_outcomes(rule_root, profiles):
        yield from outcome.rules


__all__ = [
    "DiscoveredRule",
    "FileOutcome",
    "Recognition",
    "SUPPORTED",
    "RECOGNIZED_UNSUPPORTED",
    "NOT_A_RULE",
    "UNCLAIMED",
    "discover_rules",
    "recognize",
    "shape_literals",
    "sniff_format",
    "walk_outcomes",
]
