"""MITRE enrichment write path — the seam the mitre-tagger skill orchestrates.

``tag_mitre`` validates technique IDs against the shipped ATT&CK reference,
merges them into a catalog record's ``mitre`` list, recomputes the MITRE review
reasons (``no_mitre`` cleared, ``invalid_mitre`` never introduced — invalid IDs
are rejected up front), and rebuilds the INDEX. Deterministic and atomic: if any
ID is invalid, nothing is written.

This is ADEF's enrichment layer — it writes only to the catalog record, never to
the user's source rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from adef.core.attack import attack_reference
from adef.core.catalog import Catalog
from adef.core.rule_discovery import (
    REVIEW_INVALID_MITRE,
    REVIEW_NO_MITRE,
)


class InvalidTechniqueError(ValueError):
    """One or more supplied IDs are not valid ATT&CK techniques."""


@dataclass
class TagResult:
    detection_id: str
    added: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    revoked: dict[str, str] = field(default_factory=dict)  # id -> replacement


def tag_mitre(workspace: Path, detection_id: str, technique_ids: list[str]) -> TagResult:
    """Add validated MITRE technique IDs to a catalog record.

    Raises ``KeyError`` if the detection isn't in the catalog, and
    ``InvalidTechniqueError`` (writing nothing) if any ID isn't real.
    Revoked-but-real IDs are accepted and reported (the caller decides whether
    to swap in the replacement).
    """
    ref = attack_reference()
    cat = Catalog(workspace)

    found = cat.find_record(detection_id)
    if found is None:
        raise KeyError(f"{detection_id} is not in the catalog")
    path, data = found

    # Normalise + validate all IDs before touching disk (atomic).
    normalised = [t.strip().upper() for t in technique_ids if t.strip()]
    invalid = [t for t in normalised if not ref.is_valid(t)]
    if invalid:
        raise InvalidTechniqueError(
            f"not valid ATT&CK technique IDs: {', '.join(invalid)}"
        )

    result = TagResult(detection_id=detection_id)
    existing = list(data.get("mitre") or [])
    existing_set = {t.upper() for t in existing}

    for t in normalised:
        if t in existing_set:
            result.already_present.append(t)
            continue
        existing.append(t)
        existing_set.add(t)
        result.added.append(t)
        res = ref.resolve(t)
        if res.revoked and res.superseded_by:
            result.revoked[t] = res.superseded_by

    data["mitre"] = existing

    # Recompute the MITRE review reasons. With ≥1 valid mapping now present,
    # neither no_mitre nor invalid_mitre applies; other reasons are untouched.
    reasons = [
        r for r in (data.get("review_reasons") or [])
        if r not in (REVIEW_NO_MITRE, REVIEW_INVALID_MITRE)
    ]
    data["review_reasons"] = reasons
    data["needs_review"] = bool(reasons)

    cat.write_raw(path, data)
    cat.rebuild_index()
    return result


__all__ = ["InvalidTechniqueError", "TagResult", "tag_mitre"]
