# ADEF Development Scripts

Development utility scripts for ADEF maintenance and testing.

## fresh-install.sh

Quick ADEF reinstallation from GitHub for testing from a clean state.

### What it does

1. Removes existing ADEF checkout (if present)
2. Clones ADEF from GitHub
3. Creates a fresh Python virtual environment (`.adef`)
4. Upgrades pip
5. Installs ADEF in editable mode
6. Verifies installation

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

**Combined options:**
```bash
./scripts/fresh-install.sh --branch main --path /tmp/adef --python 3.13
```

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--branch` | `-b` | Git branch to clone | `feature/adef-v1-design` |
| `--path` | `-p` | Installation directory | `~/agentic-detection-engineering-framework` |
| `--python` | | Python version (3.11, 3.12, 3.13) | `3.12` |
| `--help` | `-h` | Show help | |

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
