"""The catalog-record text projection shared by search, similarity, and overlap.

Extracted from ``adef.commands.detection._record_search_text`` (2026-09-18) so
agents can build the same searchable text without importing a CLI module.
"""

from __future__ import annotations

import yaml


class _NoAliasDumper(yaml.SafeDumper):
    """A source alias (``sel2: *s``) is re-emitted as its value, not as a
    generated ``&id001`` / ``*id001`` pair that means nothing to a reader."""

    def ignore_aliases(self, data: object) -> bool:
        return True


def _sigma_doc(data: dict) -> dict | None:
    """The parsed Sigma rule document, or ``None`` if ``data`` is not a Sigma
    record whose ``query`` parses to a mapping with a ``detection`` key."""
    query = str(data.get("query") or "")
    if str(data.get("format") or "") != "sigma" or not query:
        return None
    try:
        # C-accelerated when libyaml is present (identical safe-loader
        # semantics); falls back to the pure-Python SafeLoader otherwise.
        doc = yaml.load(query, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict) or "detection" not in doc:
        return None
    return doc


def record_language(data: dict) -> str:
    """The language a record's logic is written in: its field-extractor key
    (``sigma``, ``spl``, ``kql``, ``cql``, ``sql``), else its declared
    ``query_language``/``format``. A ``sigma``-format record whose query has
    no parseable ``detection:`` block isn't Sigma logic at all (some stores
    keep a bare predicate under that label), so its language is unknown."""
    from adef.core.rule_parser import field_extractor_key  # rule_parser is heavy (sqlglot)

    key = field_extractor_key(data)
    if key == "sigma" and _sigma_doc(data) is None:
        return ""
    return key or str(data.get("query_language") or data.get("format") or "").lower()


def record_query_logic(data: dict) -> str:
    """The part of a record's query that carries detection LOGIC.

    For Sigma, the stored ``query`` is the whole rule file — title,
    description, references, author, false positives, level. Search and
    comparison over that follow shared boilerplate, not behaviour. This
    returns only the ``logsource`` and ``detection`` blocks. Every other
    format, and any Sigma text that isn't a mapping with ``detection``, is
    returned unchanged. Read-side only: the stored ``query`` is never touched.
    """
    doc = _sigma_doc(data)
    if doc is None:
        return str(data.get("query") or "")
    logic = {k: doc[k] for k in ("logsource", "detection") if k in doc}
    # allow_unicode: a Sigma detection value that is itself non-ASCII (a
    # Cyrillic homoglyph, an RTLO override) must reach search/similarity/
    # overlap as the literal character, not a `\uXXXX` escape — the escape
    # is unreadable and defeats substring/BM25 matching on the real value.
    # width=inf: no folding of long double-quoted scalars into `"...\` +
    # newline continuations.
    return str(
        yaml.dump(
            logic, Dumper=_NoAliasDumper, sort_keys=False, default_flow_style=False,
            allow_unicode=True, width=float("inf"),
        )
    ).strip()


def record_mitre(data: dict) -> list[str]:
    """A record's MITRE technique IDs, uppercased, as a list of strings,
    whatever the hand-edited shape: a scalar ``mitre: T1219.002`` is one ID
    (not nine characters), a list keeps only its ``str`` entries, anything
    else is empty.

    Uppercased here because this is the one projection every MITRE consumer
    reads through — ``rebuild_index``'s ``by_technique`` keys, ``coverage``,
    ``tag``/``untag``, the overlap cluster lookup, ``detection list``/``show``.
    Only some *producers* normalize (``rule_discovery._normalise_mitre`` does,
    the GATES import did not), so a ``t1555.001`` from a GATES document or a
    hand-edited record got its own ``by_technique`` bucket and never clustered
    with its ``T1555.001`` siblings — meaning overlap analysis silently missed
    the duplicate. One guard on the read side covers every producer.
    """
    mitre = data.get("mitre")
    if isinstance(mitre, str):
        raw = [mitre]
    elif isinstance(mitre, list):
        raw = [t for t in mitre if isinstance(t, str)]
    else:
        return []
    # Empties dropped: a blank entry would otherwise key an empty `by_technique`
    # bucket, matching `as_str_list`'s handling of the same shape.
    return [text for text in (t.strip().upper() for t in raw) if text]


def record_search_text(data: dict) -> str:
    """The catalog fields worth searching on — so a detection is findable by
    *what it detects* (title, description, MITRE, platform, source, query), not
    only by what its journal says.

    For Sigma the query part is the rule's ``description`` and ``tags`` plus
    its logsource/detection blocks — a description word, a CVE tag or a
    threat-group tag still finds the rule — but not references, author,
    dates, false positives, level, status or id.
    """
    # Imported here, not at module scope: `catalog` imports `record_mitre` from
    # this module, so a top-level import back into `catalog` is a cycle that
    # fails on whichever of the two is imported first.
    from adef.core.catalog import declared_platforms

    parts = [
        str(data.get("title", "")),
        # Prose about what it detects and how. A promoted record gets this from the
        # GATES document's `detection_logic.description`, which is often the only
        # plain-language statement of the behaviour anywhere on the record.
        str(data.get("description", "")),
        " ".join(record_mitre(data)),
        str(data.get("platform", "")),
        " ".join(declared_platforms(data)),
        str(data.get("data_source", "")),
        str(data.get("format", "")),
    ]
    doc = _sigma_doc(data)
    if doc is not None:
        tags = doc.get("tags")
        parts += [
            str(doc.get("description") or ""),
            " ".join(map(str, tags)) if isinstance(tags, list) else str(tags or ""),
        ]
    parts.append(record_query_logic(data))
    return " ".join(p for p in parts if p)


__all__ = ["record_language", "record_mitre", "record_query_logic", "record_search_text"]
