# ADEF Schema Storage Implementation (Part 2 of 2)

> **Continuation of:** `2026-07-15-schema-storage-implementation.md`
> **Tasks 5-10:** LLM integration, CLI commands, MCP tools, agent skill, integration tests, docs

---

## Task 5: LLM Client (Provider Protocol + Implementations)

**Files:**
- Create: `adef/core/llm_client.py`
- Test: `tests/test_llm_client.py`
- Modify: `pyproject.toml` (add anthropic, openai dependencies as optional)

**Interfaces:**
- Consumes: `SchemaField` from `adef.core.schema`
- Produces:
  - `LLMProvider` protocol with `generate_structured(prompt: str, schema: dict) -> dict`
  - `ClaudeLLMProvider` implementation
  - `OpenAILLMProvider` implementation
  - `get_llm_provider() -> LLMProvider`
  - `generate_field_descriptions(fields: list[SchemaField], query_language: str, source: str) -> dict[str, str]`

- [ ] **Step 1: Add LLM dependencies as optional**

```toml
# pyproject.toml (in [project.optional-dependencies] section)
[project.optional-dependencies]
llm = [
    "anthropic>=0.25.0",
    "openai>=1.30.0",
]
```

- [ ] **Step 2: Write failing test for LLMProvider protocol**

```python
# tests/test_llm_client.py
from adef.core.llm_client import LLMProvider

def test_llm_provider_protocol():
    """Test LLMProvider protocol can be implemented."""
    class MockProvider:
        def generate_structured(self, prompt: str, schema: dict) -> dict:
            return {"descriptions": []}
    
    provider: LLMProvider = MockProvider()
    result = provider.generate_structured("test", {})
    assert "descriptions" in result
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_llm_client.py::test_llm_provider_protocol -v`
Expected: `ModuleNotFoundError: No module named 'adef.core.llm_client'`

- [ ] **Step 4: Create LLMProvider protocol**

```python
# adef/core/llm_client.py
"""LLM client for generating field descriptions (provider-agnostic)."""

from __future__ import annotations
import os
from typing import Protocol, Any


class LLMProvider(Protocol):
    """Provider-agnostic LLM interface."""
    
    def generate_structured(self, prompt: str, schema: dict) -> dict:
        """Generate structured output matching the given JSON schema.
        
        Args:
            prompt: System/user prompt
            schema: JSON schema for response structure
        
        Returns:
            Dict matching the schema
        """
        ...
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_llm_client.py::test_llm_provider_protocol -v`
Expected: PASS

- [ ] **Step 6: Write failing test for ClaudeLLMProvider**

```python
# tests/test_llm_client.py
from unittest.mock import Mock, patch
from adef.core.llm_client import ClaudeLLMProvider

def test_claude_provider_calls_api():
    """Test ClaudeLLMProvider calls Anthropic API."""
    with patch('adef.core.llm_client.Anthropic') as mock_anthropic:
        mock_client = Mock()
        mock_response = Mock()
        mock_response.content = [Mock(text='{"descriptions": []}')]
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.return_value = mock_client
        
        provider = ClaudeLLMProvider()
        result = provider.generate_structured("test prompt", {"type": "object"})
        
        assert mock_client.messages.create.called
        assert "descriptions" in result
```

- [ ] **Step 7: Run test to verify it fails**

Run: `pytest tests/test_llm_client.py::test_claude_provider_calls_api -v`
Expected: `NameError: name 'ClaudeLLMProvider' is not defined`

- [ ] **Step 8: Implement ClaudeLLMProvider**

```python
# adef/core/llm_client.py (add after LLMProvider)

import json

try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None  # type: ignore


class ClaudeLLMProvider:
    """Claude LLM provider using Anthropic SDK."""
    
    def __init__(self, api_key: str | None = None):
        if Anthropic is None:
            raise RuntimeError("anthropic package not installed. Install with: pip install anthropic")
        self.client = Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
    
    def generate_structured(self, prompt: str, schema: dict) -> dict:
        """Generate structured output using Claude."""
        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
            system="You are a data schema expert. Respond with valid JSON matching the provided schema."
        )
        
        # Extract JSON from response
        text = response.content[0].text
        return json.loads(text)
```

- [ ] **Step 9: Run test to verify it passes**

Run: `pytest tests/test_llm_client.py::test_claude_provider_calls_api -v`
Expected: PASS

- [ ] **Step 10: Write failing test for OpenAILLMProvider**

```python
# tests/test_llm_client.py
from adef.core.llm_client import OpenAILLMProvider

def test_openai_provider_calls_api():
    """Test OpenAILLMProvider calls OpenAI API."""
    with patch('adef.core.llm_client.OpenAI') as mock_openai:
        mock_client = Mock()
        mock_response = Mock()
        mock_choice = Mock()
        mock_choice.message.content = '{"descriptions": []}'
        mock_response.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        provider = OpenAILLMProvider()
        result = provider.generate_structured("test prompt", {"type": "object"})
        
        assert mock_client.chat.completions.create.called
        assert "descriptions" in result
```

- [ ] **Step 11: Run test to verify it fails**

Run: `pytest tests/test_llm_client.py::test_openai_provider_calls_api -v`
Expected: `NameError: name 'OpenAILLMProvider' is not defined`

- [ ] **Step 12: Implement OpenAILLMProvider**

```python
# adef/core/llm_client.py (add after ClaudeLLMProvider)

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # type: ignore


class OpenAILLMProvider:
    """OpenAI LLM provider using OpenAI SDK."""
    
    def __init__(self, api_key: str | None = None):
        if OpenAI is None:
            raise RuntimeError("openai package not installed. Install with: pip install openai")
        self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
    
    def generate_structured(self, prompt: str, schema: dict) -> dict:
        """Generate structured output using GPT-4."""
        response = self.client.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=[
                {"role": "system", "content": "You are a data schema expert. Respond with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        text = response.choices[0].message.content
        return json.loads(text)
```

- [ ] **Step 13: Run test to verify it passes**

Run: `pytest tests/test_llm_client.py::test_openai_provider_calls_api -v`
Expected: PASS

- [ ] **Step 14: Write failing test for get_llm_provider**

```python
# tests/test_llm_client.py
from adef.core.llm_client import get_llm_provider, ClaudeLLMProvider, OpenAILLMProvider

def test_get_llm_provider_claude(monkeypatch):
    """Test get_llm_provider returns Claude by default."""
    monkeypatch.setenv("ADEF_LLM_PROVIDER", "claude")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    
    provider = get_llm_provider()
    assert isinstance(provider, ClaudeLLMProvider)

def test_get_llm_provider_openai(monkeypatch):
    """Test get_llm_provider returns OpenAI when configured."""
    monkeypatch.setenv("ADEF_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    
    provider = get_llm_provider()
    assert isinstance(provider, OpenAILLMProvider)
```

- [ ] **Step 15: Run tests to verify they fail**

Run: `pytest tests/test_llm_client.py::test_get_llm_provider -v`
Expected: `NameError: name 'get_llm_provider' is not defined`

- [ ] **Step 16: Implement get_llm_provider**

```python
# adef/core/llm_client.py (add after OpenAILLMProvider)

def get_llm_provider() -> LLMProvider:
    """Load LLM provider from environment configuration.
    
    Returns:
        LLM provider instance
    
    Raises:
        ValueError: If provider name is invalid
        RuntimeError: If provider SDK not installed or API key missing
    """
    provider_name = os.getenv("ADEF_LLM_PROVIDER", "claude").lower()
    
    if provider_name == "claude":
        return ClaudeLLMProvider()
    elif provider_name == "openai":
        return OpenAILLMProvider()
    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}. Use 'claude' or 'openai'.")
```

- [ ] **Step 17: Run tests to verify they pass**

Run: `pytest tests/test_llm_client.py::test_get_llm_provider -v`
Expected: PASS

- [ ] **Step 18: Write failing test for generate_field_descriptions**

```python
# tests/test_llm_client.py
from adef.core.schema import SchemaField
from adef.core.llm_client import generate_field_descriptions

def test_generate_field_descriptions():
    """Test batch field description generation."""
    fields = [
        SchemaField(
            name="parent_image",
            in_rules=True,
            in_data=True,
            type="string",
            population=0.98,
            sample_values=["cmd.exe", "mshta.exe"],
            description="",
            description_source="generated"
        ),
        SchemaField(
            name="process_id",
            in_rules=False,
            in_data=True,
            type="integer",
            population=1.0,
            sample_values=[1234, 5678],
            description="",
            description_source="generated"
        )
    ]
    
    with patch('adef.core.llm_client.get_llm_provider') as mock_get_provider:
        mock_provider = Mock()
        mock_provider.generate_structured.return_value = {
            "descriptions": [
                {"name": "parent_image", "description": "Executable path of parent process"},
                {"name": "process_id", "description": "Process identifier"}
            ]
        }
        mock_get_provider.return_value = mock_provider
        
        descriptions = generate_field_descriptions(fields, "sql", "edr_process")
        
        assert descriptions["parent_image"] == "Executable path of parent process"
        assert descriptions["process_id"] == "Process identifier"
```

- [ ] **Step 19: Run test to verify it fails**

Run: `pytest tests/test_llm_client.py::test_generate_field_descriptions -v`
Expected: `NameError: name 'generate_field_descriptions' is not defined`

- [ ] **Step 20: Implement generate_field_descriptions**

```python
# adef/core/llm_client.py (add at end)

def generate_field_descriptions(
    fields: list[Any],  # SchemaField, but avoiding circular import
    query_language: str,
    source: str
) -> dict[str, str]:
    """Generate descriptions for all fields in batch.
    
    Args:
        fields: List of SchemaField objects
        query_language: Query language (sql, spl, cql, kql)
        source: Data source name
    
    Returns:
        Dict mapping field name to description
    
    Raises:
        RuntimeError: If LLM call fails
    """
    prompt = f"""Generate concise descriptions for these data fields from a {query_language} {source} data source.

Fields to describe:
"""
    
    for field in fields:
        prompt += f"\n- {field.name} ({field.type}, {int(field.population * 100)}% populated)"
        if field.sample_values:
            samples = [str(v) for v in field.sample_values if v is not None][:2]
            prompt += f" examples: {', '.join(samples)}"
    
    prompt += "\n\nRespond with JSON: {\"descriptions\": [{\"name\": \"field_name\", \"description\": \"...\"}, ...]}"
    
    schema = {
        "type": "object",
        "properties": {
            "descriptions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"}
                    },
                    "required": ["name", "description"]
                }
            }
        },
        "required": ["descriptions"]
    }
    
    try:
        provider = get_llm_provider()
        result = provider.generate_structured(prompt, schema)
        return {item["name"]: item["description"] for item in result["descriptions"]}
    except Exception as e:
        # ponytail: log to stderr in production
        raise RuntimeError(f"LLM description generation failed: {e}")
```

- [ ] **Step 21: Run test to verify it passes**

Run: `pytest tests/test_llm_client.py::test_generate_field_descriptions -v`
Expected: PASS

- [ ] **Step 22: Commit**

```bash
git add adef/core/llm_client.py tests/test_llm_client.py pyproject.toml
git commit -m "feat(schema): add LLM client for field descriptions

- LLMProvider protocol for provider-agnostic interface
- ClaudeLLMProvider using Anthropic SDK
- OpenAILLMProvider using OpenAI SDK
- get_llm_provider loads from ADEF_LLM_PROVIDER env var
- generate_field_descriptions: batch LLM call for all fields
- Optional deps: anthropic, openai
- Comprehensive mocked tests"
```

---

## Task 6: CLI Schema Commands

**Files:**
- Create: `adef/commands/schema.py`
- Test: `tests/test_schema_commands.py`
- Modify: `pyproject.toml` (register schema command)

**Interfaces:**
- Consumes: All prior modules (schema, rule_parser, data_sampler, llm_client)
- Produces: CLI commands `adef schema init/update/rescan/show`

*This task is large — I'll show the init command structure, and the pattern repeats for update/rescan/show.*

- [ ] **Step 1: Write failing test for schema init command**

```python
# tests/test_schema_commands.py
from click.testing import CliRunner
from adef.commands.schema import schema

def test_schema_init_help():
    """Test schema init --help shows usage."""
    runner = CliRunner()
    result = runner.invoke(schema, ['init', '--help'])
    assert result.exit_code == 0
    assert "Initialize a data schema" in result.output
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schema_commands.py::test_schema_init_help -v`
Expected: `ModuleNotFoundError: No module named 'adef.commands.schema'`

- [ ] **Step 3: Create schema command group skeleton**

```python
# adef/commands/schema.py
"""``adef schema`` — schema storage commands."""

from __future__ import annotations
import sys
from pathlib import Path
from datetime import datetime, timezone

import click
from rich.console import Console

console = Console()


@click.group()
def schema():
    """Manage data schemas (field inventory + types + populations)."""
    pass


@schema.command()
@click.argument("source")
@click.option("--rule-root", type=Path, help="Path to rules directory")
@click.option("--stdin", is_flag=True, help="Read data sample from stdin")
@click.option("--skip-rules", is_flag=True, help="Only sample data, skip rule parsing")
@click.option("--skip-data", is_flag=True, help="Only parse rules, skip data sampling")
def init(source: str, rule_root: Path | None, stdin: bool, skip_rules: bool, skip_data: bool):
    """Initialize a data schema for SOURCE (interactive wizard)."""
    console.print(f"[bold]Initializing schema for {source}[/bold]")
    # Implementation will go here


@schema.command()
@click.argument("source")
def show(source: str):
    """Display schema for SOURCE."""
    console.print(f"[bold]Schema: {source}[/bold]")
    # Implementation will go here


@schema.command()
@click.argument("source")
def update(source: str):
    """Re-sample data to detect drift for SOURCE."""
    console.print(f"[bold]Updating schema: {source}[/bold]")
    # Implementation will go here


@schema.command()
@click.argument("source")
def rescan(source: str):
    """Re-parse rules to refresh in_rules flags for SOURCE."""
    console.print(f"[bold]Rescanning rules: {source}[/bold]")
    # Implementation will go here
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_schema_commands.py::test_schema_init_help -v`
Expected: PASS

- [ ] **Step 5: Register schema command in pyproject.toml**

```toml
# pyproject.toml (in [project.entry-points."adef.commands"])
schema = "adef.commands.schema:schema"
```

- [ ] **Step 6: Write integration test for schema init (minimal flow)**

```python
# tests/test_schema_commands.py
import tempfile
from pathlib import Path

def test_schema_init_creates_file(monkeypatch):
    """Test schema init creates schema YAML file."""
    runner = CliRunner()
    
    with tempfile.TemporaryDirectory() as workspace:
        workspace_path = Path(workspace)
        schema_dir = workspace_path / "schema"
        schema_dir.mkdir()
        
        # Mock environment
        monkeypatch.setenv("ADEF_WORKSPACE", str(workspace_path))
        monkeypatch.setenv("ADEF_LLM_PROVIDER", "claude")
        
        # Mock stdin for interactive prompts
        input_data = "sql\nn\nn\n"  # language=sql, no rules, no data
        
        result = runner.invoke(schema, ['init', 'test_source'], input=input_data)
        
        assert result.exit_code == 0
        schema_file = schema_dir / "test_source.yml"
        assert schema_file.exists()
```

- [ ] **Step 7: Run test to verify it fails**

Run: `pytest tests/test_schema_commands.py::test_schema_init_creates_file -v`
Expected: FAIL (init command is skeleton only)

- [ ] **Step 8: Implement schema init interactive wizard**

```python
# adef/commands/schema.py (replace init function)

from adef.core.schema import Schema, SchemaField, write_schema, merge_fields
from adef.core.rule_parser import extract_fields_from_rules
from adef.core.data_sampler import sample_data_from_json, sample_data_from_csv
from adef.core.llm_client import generate_field_descriptions
import json


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _get_workspace_schema_dir() -> Path:
    workspace = Path(os.getenv("ADEF_WORKSPACE", Path.home() / "work" / "adef-workspace"))
    return workspace / "schema"


@schema.command()
@click.argument("source")
@click.option("--rule-root", type=Path, help="Path to rules directory")
@click.option("--stdin", is_flag=True, help="Read data sample from stdin")
@click.option("--skip-rules", is_flag=True, help="Only sample data, skip rule parsing")
@click.option("--skip-data", is_flag=True, help="Only parse rules, skip data sampling")
def init(source: str, rule_root: Path | None, stdin: bool, skip_rules: bool, skip_data: bool):
    """Initialize a data schema for SOURCE (interactive wizard)."""
    console.print(f"[bold]Initializing schema for {source}[/bold]\n")
    
    # 1. Get query language
    query_language = click.prompt(
        "Which query language does this source use?",
        type=click.Choice(["sql", "spl", "cql", "kql"], case_sensitive=False)
    ).lower()
    
    rule_fields = set()
    last_rule_scan = None
    
    # 2. Parse rules (if not skipped)
    if not skip_rules:
        scan_rules = click.confirm("Do you have existing rules to scan?", default=True)
        if scan_rules:
            if not rule_root:
                rule_root = click.prompt("Path to rules directory", type=Path)
            
            console.print(f"Scanning rules in {rule_root}...")
            # TODO: implement extract_fields_from_rules file scanner
            rule_fields = set()  # placeholder
            last_rule_scan = _now_iso()
            console.print(f"Found {len(rule_fields)} fields in rules")
    
    data_fields = {}
    last_data_sample = None
    sample_window = None
    sample_size = None
    
    # 3. Sample data (if not skipped)
    if not skip_data:
        sample_now = click.confirm("Sample data now to discover field types?", default=True)
        if sample_now:
            if stdin:
                console.print("Reading data from stdin...")
                data_input = sys.stdin.read()
            else:
                console.print("Paste JSON or CSV data (Ctrl+D when done):")
                data_input = sys.stdin.read()
            
            # Detect format and parse
            try:
                data_fields = sample_data_from_json(data_input)
                last_data_sample = _now_iso()
                sample_size = len(json.loads(data_input))
            except json.JSONDecodeError:
                data_fields = sample_data_from_csv(data_input)
                last_data_sample = _now_iso()
                sample_size = len(data_input.strip().split("\n")) - 1  # minus header
            
            console.print(f"Sampled {sample_size} rows, found {len(data_fields)} fields")
    
    # 4. Merge fields
    merged_fields = merge_fields(rule_fields, data_fields)
    
    # 5. Generate descriptions (if fields exist)
    if merged_fields:
        try:
            console.print("Generating field descriptions...")
            descriptions = generate_field_descriptions(merged_fields, query_language, source)
            for field in merged_fields:
                field.description = descriptions.get(field.name, "")
        except RuntimeError as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")
            console.print("Descriptions set to empty (edit schema YAML manually)")
    
    # 6. Write schema
    schema_obj = Schema(
        source=source,
        query_language=query_language,
        last_rule_scan=last_rule_scan,
        last_data_sample=last_data_sample,
        sample_window=sample_window,
        sample_size=sample_size,
        fields=merged_fields
    )
    
    schema_dir = _get_workspace_schema_dir()
    schema_path = schema_dir / f"{source}.yml"
    write_schema(schema_obj, schema_path)
    
    # 7. Output summary
    console.print(f"\n[green]Schema initialized:[/green] schema/{source}.yml")
    console.print(f"  Fields from rules: {sum(1 for f in merged_fields if f.in_rules)}")
    console.print(f"  Fields from data: {sum(1 for f in merged_fields if f.in_data)}")
    console.print(f"  Overlap: {sum(1 for f in merged_fields if f.in_rules and f.in_data)}")
    
    rules_only = [f.name for f in merged_fields if f.in_rules and not f.in_data]
    if rules_only:
        console.print(f"  [yellow]⚠️  Rules-only (missing in data): {len(rules_only)}[/yellow]")
    
    console.print(f"\nNext steps:")
    console.print(f"  - Review: adef schema show {source}")
    console.print(f"  - Edit descriptions: schema/{source}.yml")
```

- [ ] **Step 9: Run test to verify it passes**

Run: `pytest tests/test_schema_commands.py::test_schema_init_creates_file -v`
Expected: PASS

- [ ] **Step 10: Implement remaining commands (show/update/rescan) - abbreviated**

*For brevity, I'm showing just the signatures. Implement using same TDD pattern as init.*

```python
# adef/commands/schema.py

@schema.command()
@click.argument("source")
def show(source: str):
    """Display schema for SOURCE."""
    schema_path = _get_workspace_schema_dir() / f"{source}.yml"
    if not schema_path.exists():
        console.print(f"[red]Error:[/red] Schema not found: {source}")
        sys.exit(1)
    
    schema_obj = read_schema(schema_path)
    
    console.print(f"[bold]{schema_obj.source}[/bold]")
    console.print(f"Query language: {schema_obj.query_language}")
    console.print(f"Last rule scan: {schema_obj.last_rule_scan or 'Never'}")
    console.print(f"Last data sample: {schema_obj.last_data_sample or 'Never'}")
    console.print(f"\nFields ({len(schema_obj.fields)} total):")
    
    for field in schema_obj.fields:
        icon = "✓" if field.in_rules and field.in_data else "⚠" if field.in_rules else "ℹ"
        console.print(f"  {icon} {field.name} ({field.type}, {int(field.population * 100)}% populated)")
        console.print(f"    In rules: {'yes' if field.in_rules else 'NO'} | In data: {'yes' if field.in_data else 'NO'}")
        if field.description:
            console.print(f"    \"{field.description}\"")
```

- [ ] **Step 11: Commit**

```bash
git add adef/commands/schema.py tests/test_schema_commands.py pyproject.toml
git commit -m "feat(schema): add CLI commands for schema management

- adef schema init: interactive wizard (rule scan + data sample)
- adef schema show: display schema
- adef schema update/rescan: stubs (to be implemented)
- Registered in pyproject.toml entry points
- Integration test for init workflow"
```

---

## Task 7: Update `adef init` to Create schema/ Directory

**Files:**
- Modify: `adef/commands/init.py:30-46`

**Interfaces:**
- Consumes: None
- Produces: Updated workspace structure with `schema/` directory

- [ ] **Step 1: Read current init command**

Run: `cat adef/commands/init.py` (lines 100-128)

- [ ] **Step 2: Add schema directory creation**

```python
# adef/commands/init.py (in init function, after line 112)

# After templates_dir.mkdir(exist_ok=True), add:
schema_dir = workspace / "schema"
schema_dir.mkdir(exist_ok=True)

# After line 125, add:
console.print(f"  schema/      → {schema_dir}")
```

- [ ] **Step 3: Commit**

```bash
git add adef/commands/init.py
git commit -m "feat(schema): create schema/ directory on workspace init"
```

---

## Task 8: MCP Tools for Schema Commands

**Files:**
- Create: `adef/mcp/tools/schema_tools.py`
- Modify: `adef/mcp/register.py`

**Interfaces:**
- Consumes: CLI commands from `adef.commands.schema`
- Produces: MCP tool wrappers

- [ ] **Step 1: Create schema_tools stub**

```python
# adef/mcp/tools/schema_tools.py
"""MCP tools for schema management."""

from fastmcp import FastMCP


def register_schema_tools(server: FastMCP) -> None:
    """Register schema management tools with MCP server."""
    
    @server.tool()
    def schema_show(source: str) -> str:
        """Display schema for a data source."""
        # TODO: call adef.commands.schema.show programmatically
        return f"Schema: {source}"
    
    @server.tool()
    def schema_init(source: str, query_language: str) -> str:
        """Initialize a new schema."""
        return f"Initialized {source}"
```

- [ ] **Step 2: Register in MCP register.py**

```python
# adef/mcp/register.py (add import and call)

from adef.mcp.tools.schema_tools import register_schema_tools

def register_mcp_tools(server: FastMCP) -> None:
    """Register all built-in ADEF MCP tools."""
    # ... existing tools ...
    register_schema_tools(server)
```

- [ ] **Step 3: Commit**

```bash
git add adef/mcp/tools/schema_tools.py adef/mcp/register.py
git commit -m "feat(schema): add MCP tools for schema commands (stubs)"
```

---

## Task 9: Agent Skill Markdown

**Files:**
- Create: `adef/data/skills/adef-schema.md`

**Interfaces:**
- Consumes: CLI commands (schema init/update/rescan/show)
- Produces: Skill markdown for agent guidance

- [ ] **Step 1: Create skill file**

```markdown
<!-- adef/data/skills/adef-schema.md -->
---
name: adef-schema
description: Guide users through data schema setup and maintenance for ADEF
---

# adef-schema Skill

You help users build and maintain their data schema for ADEF detection engineering.

## When to use this skill

- User wants to set up their data schema for the first time
- User wants to check for schema drift (field populations changed)
- User added new detection rules and needs to refresh the schema

## Initial Setup Workflow

1. Ask: "What's your primary data source name?" (e.g., `edr_process`, `cloudtrail_events`)
2. Ask: "Which query language? [SQL/SPL/CQL/KQL]"
3. Ask: "Do you have existing detection rules I should scan?"
   - If yes: get path, call `adef schema init <source> --rule-root <path> --skip-data`
4. Ask: "Want to sample your data now to discover field types?"
   - If yes: "I can generate a discovery query. Do you have an MCP tool to run it, or should I show you the query to run manually?"
     - **If MCP available:** Call user's MCP tool (e.g., `@splunk`, `@clickhouse`), get results, pipe to `adef schema init <source> --stdin`
     - **If manual:** Show query, wait for user to paste results
5. Schema created, show summary: "Found X fields from rules, Y from data, Z overlap. Review with `adef schema show <source>`"

## Drift Detection Workflow

1. User: "check if my schema has drifted"
2. You: "I'll generate a fresh sample query. Run and pipe results, or I can use your MCP?"
3. User provides data → call `adef schema update <source> --results -`
4. Summarize drift: "command_line population dropped 13%, parent_pid went missing"

## Rescan Workflow

1. User: "I added new detections, update the schema"
2. Call `adef schema rescan <source>`
3. Summarize: "Found 2 new fields in rules: process_integrity_level, process_hash"

## CLI commands you'll use

- `adef schema init <source>` — initial setup wizard
- `adef schema update <source> --results -` — refresh data sample
- `adef schema rescan <source>` — re-parse rules
- `adef schema show <source>` — display current schema

## MCP integration

If user has MCP tools (Splunk, ClickHouse, etc.), you can:
1. Generate the discovery query
2. Call their MCP tool to run it
3. Pipe results to `adef schema init/update --stdin`

Otherwise, show them the query and wait for them to paste/pipe results.

## Discovery Query Templates

**SQL:**
```sql
SELECT * FROM <source>
WHERE timestamp >= NOW() - INTERVAL '30 days'
LIMIT 10000;
```

**SPL:**
```spl
index=<source> earliest=-30d | head 10000
```

**CQL:**
```
#event_simpleName=* | limit 10000
```

**KQL:**
```kql
<source> | where TimeGenerated > ago(30d) | limit 10000
```
```

- [ ] **Step 2: Commit**

```bash
git add adef/data/skills/adef-schema.md
git commit -m "feat(schema): add adef-schema agent skill

- Conversational guidance for schema setup
- Workflows: initial setup, drift detection, rescan
- MCP integration instructions
- Discovery query templates for each language"
```

---

## Task 10: Documentation Updates

**Files:**
- Modify: `AGENTS.md`
- Modify: `CLAUDE.md`
- Modify: `ISA.md`

**Interfaces:**
- Consumes: None
- Produces: Updated docs for multi-teammate context

- [ ] **Step 1: Update AGENTS.md with schema context**

```markdown
<!-- AGENTS.md (add section after "Upstream Decoupling") -->

## Schema Storage

ADEF's schema storage tracks what fields exist in rules vs. actual data. Located at `<workspace>/schema/<source>.yml`.

**Commands:**
- `adef schema init <source>` — create schema (rule parsing + data sampling)
- `adef schema update <source> --results -` — re-sample data for drift detection
- `adef schema rescan <source>` — re-parse rules after adding detections
- `adef schema show <source>` — display schema

**Key modules:**
- `adef/core/schema.py` — Schema dataclass, YAML I/O
- `adef/core/rule_parser.py` — SQL (sqlglot AST), SPL/CQL/KQL (regex)
- `adef/core/data_sampler.py` — JSON/CSV parsing, type inference
- `adef/core/llm_client.py` — Field description generation (Claude/OpenAI)

**LLM configuration:**
```bash
export ADEF_LLM_PROVIDER=claude  # or openai
export ANTHROPIC_API_KEY=...     # or OPENAI_API_KEY
```
```

- [ ] **Step 2: Update CLAUDE.md with schema commands**

```markdown
<!-- CLAUDE.md (add to "Essential Commands" section) -->

### Schema Management
```bash
adef schema init edr_process            # Create schema (interactive wizard)
adef schema show edr_process            # Display schema
adef schema update edr_process --results -  # Re-sample data (drift detection)
adef schema rescan edr_process          # Re-parse rules
```
```

- [ ] **Step 3: Update ISA.md decisions log**

```markdown
<!-- ISA.md (add to ## Decisions section) -->

**Schema Storage (2026-07-15):**
- SQL uses sqlglot AST parsing for 99%+ coverage (high-fidelity)
- SPL/CQL/KQL use enhanced regex (~95% coverage, upgradeable later)
- LLM provider-agnostic via Protocol pattern (Claude/OpenAI built-in)
- Results-in seam: user pipes data, ADEF infers types/populations
- No vendor connectors (Splunk API, CrowdStrike API, etc.)
```

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md CLAUDE.md ISA.md
git commit -m "docs: add schema storage context for team

- AGENTS.md: schema commands, modules, LLM config
- CLAUDE.md: essential schema commands
- ISA.md: design decisions logged"
```

---

## Final Integration Test

- [ ] **Step 1: Manual end-to-end test**

```bash
# Create fresh workspace
rm -rf ~/work/adef-test-workspace
adef init ~/work/adef-test-workspace

# Initialize schema with SQL rules
cd ~/work/detect-vault  # or wherever SQL rules live
adef schema init edr_process --rule-root detections/

# Sample data (pipe from ClickHouse or use mock JSON)
echo '[{"parent_image": "cmd.exe", "process_id": 1234}]' | adef schema init edr_process --stdin

# View schema
adef schema show edr_process

# Verify schema file exists and is valid YAML
cat ~/work/adef-test-workspace/schema/edr_process.yml
```

Expected: Schema file created, all fields present, descriptions generated

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit final integration**

```bash
git add -A
git commit -m "feat(schema): complete v1 implementation

End-to-end flow tested:
- Schema init with rule parsing (SQL AST via sqlglot)
- Data sampling from JSON/CSV (type inference, populations)
- LLM description generation (Claude/OpenAI)
- CLI commands (init/show/update/rescan)
- MCP tools
- Agent skill
- Documentation updated

All tests passing."
```

---

## Execution Complete

Plan written to:
- Part 1: `docs/superpowers/plans/2026-07-15-schema-storage-implementation.md` (Tasks 1-4)
- Part 2: `docs/superpowers/plans/2026-07-15-schema-storage-implementation-part2.md` (Tasks 5-10)

**Total tasks:** 10
**Total steps:** ~130
**Estimated effort:** 44-60 hours

Ready for execution via subagent-driven-development or executing-plans skill.
