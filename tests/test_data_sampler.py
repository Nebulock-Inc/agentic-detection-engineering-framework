"""Tests for data sampler module."""

import pytest
from adef.core.data_sampler import (
    infer_type,
    calculate_population,
    get_sample_values,
    sample_data_from_json,
    sample_data_from_csv,
)


# =============================================================================
# Tests for infer_type
# =============================================================================

def test_infer_type_string():
    """Test type inference for strings."""
    assert infer_type(["cmd.exe", "powershell.exe"]) == "string"


def test_infer_type_integer():
    """Test type inference for integers."""
    assert infer_type([1234, 5678, 9012]) == "integer"


def test_infer_type_float():
    """Test type inference for floats."""
    assert infer_type([1.5, 2.3, 4.7]) == "float"


def test_infer_type_boolean():
    """Test type inference for booleans."""
    assert infer_type([True, False, True]) == "boolean"


def test_infer_type_null():
    """Test type inference for all-null values."""
    assert infer_type([None, None, ""]) == "null"


def test_infer_type_datetime():
    """Test type inference for datetime strings."""
    assert infer_type(["2026-07-15T10:00:00", "2026-07-15T11:00:00"]) == "datetime"


# =============================================================================
# Tests for calculate_population
# =============================================================================

def test_calculate_population_full():
    """Test population calculation with all non-null values."""
    assert calculate_population([1, 2, 3]) == 1.0


def test_calculate_population_partial():
    """Test population calculation with some nulls."""
    assert calculate_population([1, None, 3, None]) == 0.5


def test_calculate_population_empty():
    """Test population calculation with all nulls."""
    assert calculate_population([None, None, ""]) == 0.0


def test_calculate_population_empty_list():
    """Test population calculation with empty list."""
    assert calculate_population([]) == 0.0


# =============================================================================
# Tests for get_sample_values
# =============================================================================

def test_get_sample_values_unique():
    """Test sample values extraction with unique values."""
    samples = get_sample_values(["cmd.exe", "powershell.exe", "notepad.exe", "calc.exe"])
    assert len(samples) == 3  # max_samples default is 3
    assert "cmd.exe" in samples


def test_get_sample_values_with_null():
    """Test sample values includes null if present."""
    samples = get_sample_values(["cmd.exe", None, "powershell.exe"])
    assert None in samples
    assert len(samples) <= 3


def test_get_sample_values_duplicates():
    """Test sample values deduplicates."""
    samples = get_sample_values(["cmd.exe", "cmd.exe", "cmd.exe"])
    assert len(samples) == 1
    assert samples[0] == "cmd.exe"


# =============================================================================
# Tests for sample_data_from_json
# =============================================================================

def test_sample_data_from_json():
    """Test sampling data from JSON input."""
    json_str = """
    [
      {"parent_image": "cmd.exe", "command_line": "whoami", "process_id": 1234},
      {"parent_image": null, "command_line": "ls -la", "process_id": 5678},
      {"parent_image": "powershell.exe", "command_line": null, "process_id": 9012}
    ]
    """

    result = sample_data_from_json(json_str)

    assert "parent_image" in result
    assert result["parent_image"]["type"] == "string"
    assert result["parent_image"]["population"] == pytest.approx(0.666, abs=0.01)
    assert "cmd.exe" in result["parent_image"]["sample_values"]

    assert "process_id" in result
    assert result["process_id"]["type"] == "integer"
    assert result["process_id"]["population"] == 1.0


# =============================================================================
# Tests for sample_data_from_csv
# =============================================================================

def test_sample_data_from_csv():
    """Test sampling data from CSV input."""
    csv_str = """parent_image,command_line,process_id
cmd.exe,whoami,1234
,ls -la,5678
powershell.exe,,9012"""

    result = sample_data_from_csv(csv_str)

    assert "parent_image" in result
    assert result["parent_image"]["type"] == "string"
    assert result["parent_image"]["population"] == pytest.approx(0.666, abs=0.01)

    assert "process_id" in result
    assert result["process_id"]["type"] == "string"  # CSV reads as strings
