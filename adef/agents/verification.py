"""Native, vendor-free rule verification — would this rule pass schema
validation and the four-engine constraint?

Delegates to `adef.commands.schema.run_schema_check`, scoped to exactly one
detection, so the Refine chain's Verification step and the standalone
`adef schema check --detection` CLI share one implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adef.commands.schema import run_schema_check
from adef.core.catalog import Catalog, NoCatalogRecordError
from adef.core.rule_parser import PREDICATE_FIELD_EXTRACTORS, field_extractor_key
from adef.core.journal import workspace_journals_dir


class VerificationAgent:
    """Native replacement for the upstream Verification wrapper agent."""

    def run(self, detection_id: str, workspace: Path | None = None, **ctx: Any) -> dict[str, Any]:
        """Verify one detection against the declared schemas and engine taxonomy.

        Two checks run: **engine** (is the engine in the closed set?) and
        **fields** (does a matched schema declare every field the rule
        filters on?). ``status`` is the headline: ``failed`` if either check
        failed, ``partial`` if the field check could not run, ``passed`` only
        if both ran clean. ``checks`` reports each, and
        ``fields_not_run_reason`` says why the field check didn't run:
        ``no_schemas_declared``, ``no_schema_matches`` or
        ``unparseable_query``. Before ``status`` existed, "nothing checked"
        read as ``passed: True`` (seen in trial runs).

        Only fields the rule *filters on* gate the result. Grouping and
        projection columns (SPL ``BY``, ``SELECT`` lists, KQL ``project``)
        the schema doesn't declare are reported as ``missing_grouping_fields``
        and don't fail it: a missing grouping column breaks the output, not
        the detection (a trial run turned up a field crosswalk good enough for
        matching failed Verification on every Splunk rule over BY columns).

        `passed` deliberately reflects only rule-authoring defects (an engine
        outside the closed set, a field no matched schema declares) and does
        NOT factor in `undeclared_type_fields`: an undeclared type is the
        *schema's* incompleteness, not the rule's defect. It is still reported
        for visibility — just not gating.

        `schema_matched` is False when no field check ran: either the rule's
        literals match no declared schema (the normal state of a freshly imported
        hunt detection) or its query couldn't be parsed for fields at all.
        `passed` is still True in both cases (the engine check ran and found no
        defect), so the flag is what distinguishes "fields verified" from "no
        fields checked" — reporting it True for an unparseable query would claim
        a verification that never happened.
        """
        journals_dir = workspace_journals_dir(workspace, create=False)
        ws = journals_dir.parent

        result = run_schema_check(ws, detection_ids=(detection_id,))
        # `rules_checked_ids` collects every catalog record the scope filter
        # matched, *before* run_schema_check decides it's unparseable/
        # unmatched/engine-invalid — it's the same "was this ID even in the
        # catalog" signal `adef schema check --detection` already uses
        # (schema.py's `check` command diffs the requested scope against this
        # same list). Absence here means no catalog record exists at all.
        if detection_id not in result.rules_checked_ids:
            raise NoCatalogRecordError(f"No catalog record found for {detection_id}")

        engine_error = result.engine_errors.get(detection_id)
        missing_all = sorted(
            {
                field_name
                for fields in result.missing_from_schema.values()
                for field_name, ids in fields.items()
                if detection_id in ids
            }
        )
        undeclared_type_fields = result.undeclared_type_fields.get(detection_id, [])

        not_run_reason: str | None = None
        if detection_id in result.rules_skipped_unparseable:
            not_run_reason = "unparseable_query"
        elif detection_id in result.rules_skipped_unmatched:
            not_run_reason = (
                "no_schema_matches" if result.sources_with_schemas else "no_schemas_declared"
            )

        # Split missing fields into what the rule filters on (gating) and
        # grouping/projection columns (reported, not gating). A query with no
        # filter at all (`T | project a, b`) demotes everything; if predicate
        # extraction FAILED (None), nothing is demoted, so a real defect is
        # never waved through as "grouping".
        predicate = _predicate_fields(ws, detection_id)
        missing_grouping = (
            [] if predicate is None else [f for f in missing_all if f not in predicate]
        )
        missing_filter = [f for f in missing_all if f not in missing_grouping]

        engine_check = "failed" if engine_error else "passed"
        fields_check = (
            "not_run" if not_run_reason else ("failed" if missing_filter else "passed")
        )
        if "failed" in (engine_check, fields_check):
            status = "failed"
        elif fields_check == "not_run":
            status = "partial"
        else:
            status = "passed"

        return {
            "detection_id": detection_id,
            "status": status,
            "checks": {"engine": engine_check, "fields": fields_check},
            "fields_not_run_reason": not_run_reason,
            # Kept for existing callers: "no defect found". It is True for a
            # `partial` result too — read `status` to tell the two apart.
            "passed": not engine_error and not missing_filter,
            "schema_matched": not_run_reason is None,
            "engine_error": engine_error,
            "missing_schema_fields": missing_filter,
            "missing_grouping_fields": missing_grouping,
            "undeclared_type_fields": undeclared_type_fields,
        }


def _predicate_fields(ws: Path, detection_id: str) -> set[str] | None:
    """The fields a record's query filters on, via the same predicate
    extractors field-set retrieval uses. An empty set means "no filter";
    ``None`` means the extraction couldn't be done."""
    found = Catalog(ws).find_record(detection_id)
    if found is None:
        return None
    _path, data = found
    key = field_extractor_key(data)
    query = str(data.get("query") or "")
    if not key or not query:
        return None
    try:
        return set(PREDICATE_FIELD_EXTRACTORS[key](query))
    except Exception:  # noqa: BLE001 — a malformed query is data, not a crash
        return None


__all__ = ["VerificationAgent"]
