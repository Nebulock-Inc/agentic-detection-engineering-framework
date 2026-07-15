"""Schema storage data model and YAML I/O."""

from __future__ import annotations
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any
import yaml


@dataclass
class SchemaField:
    """A single field in a data schema."""
    name: str
    in_rules: bool
    in_data: bool
    type: str
    population: float
    sample_values: list[Any]
    description: str
    description_source: str  # 'generated' or 'manual'


@dataclass
class Schema:
    """Complete data schema for a source."""
    source: str
    query_language: str  # 'sql', 'spl', 'cql', 'kql'
    last_rule_scan: str | None
    last_data_sample: str | None
    sample_window: str | None
    sample_size: int | None
    fields: list[SchemaField] = dataclass_field(default_factory=list)


def write_schema(schema: Schema, path: Path) -> None:
    """Write schema to YAML file."""
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert to dict for YAML serialization
    data = {
        "source": schema.source,
        "query_language": schema.query_language,
        "last_rule_scan": schema.last_rule_scan,
        "last_data_sample": schema.last_data_sample,
        "sample_window": schema.sample_window,
        "sample_size": schema.sample_size,
        "fields": [
            {
                "name": f.name,
                "in_rules": f.in_rules,
                "in_data": f.in_data,
                "type": f.type,
                "population": f.population,
                "sample_values": f.sample_values,
                "description": f.description,
                "description_source": f.description_source,
            }
            for f in schema.fields
        ]
    }

    with open(path, 'w', encoding='utf-8') as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True)


def read_schema(path: Path) -> Schema:
    """Read schema from YAML file."""
    with open(path, 'r', encoding='utf-8') as fh:
        data = yaml.safe_load(fh)

    fields = [
        SchemaField(
            name=f["name"],
            in_rules=f["in_rules"],
            in_data=f["in_data"],
            type=f["type"],
            population=f["population"],
            sample_values=f["sample_values"],
            description=f["description"],
            description_source=f["description_source"],
        )
        for f in data.get("fields", [])
    ]

    return Schema(
        source=data["source"],
        query_language=data["query_language"],
        last_rule_scan=data.get("last_rule_scan"),
        last_data_sample=data.get("last_data_sample"),
        sample_window=data.get("sample_window"),
        sample_size=data.get("sample_size"),
        fields=fields
    )


def merge_fields(rule_fields: set[str], data_fields: dict[str, dict]) -> list[SchemaField]:
    """Merge fields from rules and data into unified field list.

    Args:
        rule_fields: Set of field names extracted from rules
        data_fields: Dict mapping field name to {type, population, sample_values}

    Returns:
        List of SchemaField objects with correct in_rules/in_data flags
    """
    all_field_names = rule_fields | set(data_fields.keys())
    fields = []

    for name in sorted(all_field_names):
        in_rules = name in rule_fields
        in_data = name in data_fields

        if in_data:
            data = data_fields[name]
            field = SchemaField(
                name=name,
                in_rules=in_rules,
                in_data=True,
                type=data["type"],
                population=data["population"],
                sample_values=data["sample_values"],
                description="",  # Will be filled by LLM
                description_source="generated"
            )
        else:
            # Field is only in rules, not in data
            field = SchemaField(
                name=name,
                in_rules=True,
                in_data=False,
                type="null",
                population=0.0,
                sample_values=[],
                description="",
                description_source="generated"
            )

        fields.append(field)

    return fields
