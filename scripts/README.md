# ADEF Development Scripts

Development utility scripts for ADEF maintenance and testing.

## fresh-install.sh

Quick ADEF reinstallation from GitHub for testing from a completely clean state.

### What it does

1. Removes ADEF workspace directory (`~/work/adef-workspace` by default)
2. Removes existing ADEF checkout (if present)
3. Clones ADEF from GitHub
4. Creates a fresh Python virtual environment (`.adef`)
5. Upgrades pip
6. Installs ADEF in editable mode
7. Verifies installation

### Usage

**Basic usage** (feature branch, default location):
```bash
./scripts/fresh-install.sh
```

**Custom branch:**
```bash
./scripts/fresh-install.sh --branch main
```

**Custom installation directory:**
```bash
./scripts/fresh-install.sh --path /tmp/adef-test
```

**Custom Python version:**
```bash
./scripts/fresh-install.sh --python 3.11
```

**Keep existing workspace (don't delete ~/work/adef-workspace):**
```bash
./scripts/fresh-install.sh --keep-workspace
```

**Custom workspace location:**
```bash
./scripts/fresh-install.sh --workspace /tmp/my-workspace
```

**Combined options:**
```bash
./scripts/fresh-install.sh --branch main --path /tmp/adef --python 3.13 --keep-workspace
```

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--branch` | `-b` | Git branch to clone | `feature/adef-v1-design` |
| `--path` | `-p` | Installation directory | `~/agentic-detection-engineering-framework` |
| `--python` | | Python version (3.11, 3.12, 3.13) | `3.12` |
| `--workspace` | | ADEF workspace directory | `~/work/adef-workspace` |
| `--keep-workspace` | | Don't remove existing workspace | (workspace is removed by default) |
| `--help` | `-h` | Show help | |

### Safety Features

**Automatic self-relocation**: If you run the script from within the ADEF directory that's about to be deleted, it automatically copies itself to `/tmp` and re-executes from there. This means you can safely run:

```bash
cd ~/agentic-detection-engineering-framework
./scripts/fresh-install.sh  # ✓ Safe - script relocates itself automatically
```

The script detects this situation and displays:
```
⚠️  Warning: Running from directory that will be deleted
   Copying script to /tmp and re-executing...
```

### After Installation

The script prints next steps, but here's a quick reference:

1. **Activate the virtual environment:**
   ```bash
   source ~/agentic-detection-engineering-framework/.adef/bin/activate
   ```

2. **Verify installation:**
   ```bash
   adef --version
   adef --help
   ```

3. **Run the quickstart demo:**
   ```bash
   export ADEF_WORKSPACE=$(mktemp -d)
   adef schema ingest examples/adef-sources-thrunt.yml
   adef catalog examples/demo-rules
   adef detection list
   ```

4. **Optional: Install dev dependencies:**
   ```bash
   pip install -e ".[dev]"   # pytest, ruff, mypy
   pip install -e ".[mcp]"   # FastMCP for adef-mcp server
   ```

### Platform Support

- **macOS / Linux**: Fully supported
- **Windows**: Supported via Git Bash, WSL, or MSYS2

### Troubleshooting

**Python version not found:**
```
✗ Python 3.12 not found
```

Solutions:
- Install Python 3.12 from [python.org](https://www.python.org/downloads/)
- Use a different version: `./scripts/fresh-install.sh --python 3.11`
- Check available versions: `python3 --version`, `python3.11 --version`, etc.

**Permission denied:**
```
Permission denied: ./scripts/fresh-install.sh
```

Fix:
```bash
chmod +x scripts/fresh-install.sh
```

**Git authentication required:**

If the clone step hangs or fails, ensure you have GitHub credentials configured:
- HTTPS: Use a personal access token
- SSH: Ensure your SSH key is added to your GitHub account

## Adding New Scripts

When adding scripts to this directory:

1. **Make them executable:**
   ```bash
   chmod +x scripts/your-script.sh
   ```

2. **Add a header comment block** with:
   - Purpose
   - Usage examples
   - Options

3. **Update this README** with a new section

4. **Follow the existing patterns:**
   - Use `set -euo pipefail` for Bash scripts
   - Color-coded output for clarity
   - Cross-platform compatibility (macOS/Linux/Windows)
   - `--help` flag for usage information
