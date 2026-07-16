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
from typing import Iterable, Iterator, Optional

import yaml

# Query languages we recognise. This is the *source-format* axis, NOT the
# four-value engine taxonomy — keep the two separate on purpose.
Format = str  # one of: "sigma", "spl", "kql", "cql", "sql"

# Fold a source format into ADEF's internal engine taxonomy. Sigma is its own
# engine; SQL is sql; everything else is a query engine we treat as sql-shaped
# for the internal taxonomy while preserving the true format in ``format``.
_FORMAT_TO_ENGINE = {
    "sigma": "sigma",
    "sql": "sql",
    "spl": "sql",
    "kql": "sql",
    "cql": "sql",
}

_MITRE_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

# Raw source-literal extractors: the table/index the rule reads from, verbatim.
_SQL_FROM_RE = re.compile(r"\bfrom\s+([A-Za-z_][\w.]*)", re.IGNORECASE)
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
    # normalisation). Empty when unresolvable. Drives schema-from-catalog
    # grouping; see ISA.md 2026-07-16.
    data_source: str = ""
    needs_review: bool = False

    @property
    def query_language(self) -> Format:
        """The source query language (alias of ``format``, for schema callers)."""
        return self.format

    @property
    def engine(self) -> str:
        """ADEF internal four-value engine taxonomy (folds non-Sigma formats)."""
        return _FORMAT_TO_ENGINE.get(self.format, "sql")


# --------------------------------------------------------------------------- #
# Format sniffing
# --------------------------------------------------------------------------- #
def sniff_format(filename: str, text: str) -> Optional[Format]:
    """Classify a rule file by extension + content. ``None`` if not a rule.

    Extension decides the obvious cases; YAML needs a content sniff because a
    ``.yml`` file is only a Sigma rule if it has ``detection:`` and
    ``logsource:`` (otherwise it's config, a workflow, docs, etc.).
    """
    name = filename.lower()
    if name.endswith(".sql"):
        return "sql"
    if name.endswith(".kql"):
        return "kql"
    if name.endswith(".cql"):
        return "cql"
    if name.endswith(".conf"):
        # Splunk savedsearches.conf-style: a stanza with a ``search =`` line.
        if "search" in text and "[" in text:
            return "spl"
        return None
    if name.endswith((".yml", ".yaml")):
        # Sigma is YAML with both a logsource and a detection block.
        if re.search(r"^\s*detection\s*:", text, re.MULTILINE) and re.search(
            r"^\s*logsource\s*:", text, re.MULTILINE
        ):
            return "sigma"
        return None
    return None


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
        m = _SQL_FROM_RE.search(text)
        data_source = m.group(1) if m else ""
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


_EXTRACTORS = {
    "sigma": lambda text: _extract_sigma(text),
    "spl": lambda text: _extract_spl_conf(text),
    "kql": lambda text: _extract_kql(text),
    "sql": lambda text: _extract_generic(text, "sql"),
    "cql": lambda text: _extract_generic(text, "cql"),
}


# --------------------------------------------------------------------------- #
# The walk
# --------------------------------------------------------------------------- #
def discover_rules(rule_root: Path) -> Iterator[DiscoveredRule]:
    """Yield a ``DiscoveredRule`` for every rule file under ``rule_root``.

    Read-only. Files that don't sniff to a known format are skipped silently
    (a repo has READMEs, configs, CI files). Unreadable/malformed files are
    skipped too — discovery never aborts the whole walk on one bad file.
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
        fmt = sniff_format(path.name, text)
        if fmt is None:
            continue
        try:
            rule = _EXTRACTORS[fmt](text)
        except Exception:
            # A malformed rule of a known format still gets catalogued as
            # needs_review rather than vanishing.
            rule = DiscoveredRule(
                path=path,
                format=fmt,
                query_text=text.strip(),
                needs_review=True,
            )
            yield rule
            continue
        rule.path = path
        yield rule


def scan_rule_fields(rule_root: Path, query_language: Format) -> set[str]:
    """Return the set of field names referenced by all ``query_language`` rules.

    This is the scanner the schema feature (``adef schema init --rule-root``)
    needs: walk the repo, keep only files of the requested language, and run the
    matching ``rule_parser`` extractor over each. Sigma is a structured YAML
    format (not a query language) and is excluded here — pass ``spl``/``kql``/
    ``cql``/``sql``.
    """
    # Imported lazily so the discovery module stays import-light for callers
    # that only need the walk.
    from adef.core.rule_parser import (
        extract_cql_fields,
        extract_kql_fields,
        extract_spl_fields,
        extract_sql_fields,
    )

    extractors = {
        "sql": extract_sql_fields,
        "spl": extract_spl_fields,
        "cql": extract_cql_fields,
        "kql": extract_kql_fields,
    }
    extractor = extractors.get(query_language)
    if extractor is None:
        return set()

    fields: set[str] = set()
    for rule in discover_rules(rule_root):
        if rule.query_language == query_language:
            fields |= extractor(rule.query_text)
    return fields


__all__ = ["DiscoveredRule", "discover_rules", "scan_rule_fields", "sniff_format"]
