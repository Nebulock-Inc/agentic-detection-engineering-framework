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
from adef.core.catalog import NoCatalogRecordError
from adef.core.journal import workspace_journals_dir


class VerificationAgent:
    """Native replacement for the upstream Verification wrapper agent."""

    def run(self, detection_id: str, workspace: Path | None = None, **ctx: Any) -> dict[str, Any]:
        """Verify one detection against the declared schemas and engine taxonomy.

        `passed` deliberately reflects only rule-authoring defects (an engine
        outside the closed set, a field no matched schema declares) and does
        NOT factor in `undeclared_type_fields`: an undeclared type is the
        *schema's* incompleteness, not the rule's defect. It is still reported
        for visibility — just not gating.
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
        missing_fields = sorted(
            {
                field_name
                for fields in result.missing_from_schema.values()
                for field_name, ids in fields.items()
                if detection_id in ids
            }
        )
        undeclared_type_fields = result.undeclared_type_fields.get(detection_id, [])

        return {
            "detection_id": detection_id,
            "passed": not engine_error and not missing_fields,
            "engine_error": engine_error,
            "missing_schema_fields": missing_fields,
            "undeclared_type_fields": undeclared_type_fields,
        }


__all__ = ["VerificationAgent"]
