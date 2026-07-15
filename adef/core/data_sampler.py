"""Data sampling to infer field types and populations from piped results."""

from __future__ import annotations
import csv
import json
import re
from io import StringIO
from typing import Any


def infer_type(values: list) -> str:
    """Infer type from first non-null value.

    Args:
        values: List of values for a field

    Returns:
        Type string: 'string', 'integer', 'float', 'boolean', 'datetime', 'null'
    """
    for v in values:
        if v is None or v == "":
            continue
        if isinstance(v, bool):
            return "boolean"
        if isinstance(v, int):
            return "integer"
        if isinstance(v, float):
            return "float"
        if isinstance(v, str):
            # Simple heuristics for datetime
            if re.match(r'^\d{4}-\d{2}-\d{2}', v):
                return "datetime"
            return "string"
    return "null"  # all values were null


def calculate_population(values: list) -> float:
    """Fraction of non-null values.

    Args:
        values: List of values for a field

    Returns:
        Population as float 0.0 to 1.0
    """
    if not values:
        return 0.0
    non_null = sum(1 for v in values if v is not None and v != "")
    return non_null / len(values)


def get_sample_values(values: list, max_samples: int = 3) -> list:
    """Return up to max_samples unique values, including null if present.

    Args:
        values: List of values for a field
        max_samples: Maximum number of sample values to return

    Returns:
        List of up to max_samples unique values
    """
    seen = set()
    samples = []
    has_null = False

    for v in values:
        if v is None or v == "":
            has_null = True
            continue
        # Convert to hashable type for set membership
        hashable = v if not isinstance(v, (list, dict)) else str(v)
        if hashable not in seen:
            seen.add(hashable)
            samples.append(v)
            if len(samples) >= max_samples:
                break

    if has_null and len(samples) < max_samples:
        samples.append(None)

    return samples[:max_samples]


def sample_data_from_json(json_str: str) -> dict[str, dict]:
    """Sample data from JSON input (array of objects).

    Args:
        json_str: JSON string containing array of objects

    Returns:
        Dict mapping field name to {type, population, sample_values}
    """
    rows = json.loads(json_str)

    # Collect all field names
    field_names = set()
    for row in rows:
        field_names.update(row.keys())

    # For each field, collect values
    result = {}
    for field_name in field_names:
        values = [row.get(field_name) for row in rows]
        result[field_name] = {
            "type": infer_type(values),
            "population": calculate_population(values),
            "sample_values": get_sample_values(values),
        }

    return result


def sample_data_from_csv(csv_str: str) -> dict[str, dict]:
    """Sample data from CSV input (header + data rows).

    Args:
        csv_str: CSV string with header row

    Returns:
        Dict mapping field name to {type, population, sample_values}
    """
    reader = csv.DictReader(StringIO(csv_str))
    rows = list(reader)

    # Collect field names from header
    field_names = reader.fieldnames or []

    # For each field, collect values
    result = {}
    for field_name in field_names:
        values = [row.get(field_name) for row in rows]
        # CSV reader returns empty string for missing values, treat as None
        values = [v if v != "" else None for v in values]
        result[field_name] = {
            "type": infer_type(values),
            "population": calculate_population(values),
            "sample_values": get_sample_values(values),
        }

    return result
