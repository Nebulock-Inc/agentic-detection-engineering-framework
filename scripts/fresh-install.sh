#!/usr/bin/env bash
#
# fresh-install.sh — Quick ADEF reinstall for testing
#
# Removes existing ADEF checkout, re-clones from GitHub, and sets up
# a fresh Python 3.12 venv with all dependencies. Useful for testing
# from a clean state.
#
# Usage:
#   ./scripts/fresh-install.sh                    # Clone feature branch to ~/agentic-detection-engineering-framework
#   ./scripts/fresh-install.sh --branch main      # Clone main branch
#   ./scripts/fresh-install.sh --path /tmp/adef   # Clone to custom location
#   ./scripts/fresh-install.sh --help             # Show this help

set -euo pipefail

# Defaults
REPO_URL="https://github.com/Nebulock-Inc/agentic-detection-engineering-framework.git"
BRANCH="feature/adef-v1-design"
PYTHON_VERSION="3.12"
VENV_NAME=".adef"

# Platform detection
OS_TYPE=$(uname -s)
case "$OS_TYPE" in
    Darwin|Linux)
        DEFAULT_INSTALL_DIR="$HOME/agentic-detection-engineering-framework"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        DEFAULT_INSTALL_DIR="$HOME/agentic-detection-engineering-framework"
        ;;
    *)
        echo "⚠️  Unsupported OS: $OS_TYPE"
        DEFAULT_INSTALL_DIR="$HOME/agentic-detection-engineering-framework"
        ;;
esac

INSTALL_DIR="$DEFAULT_INSTALL_DIR"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --branch|-b)
            BRANCH="$2"
            shift 2
            ;;
        --path|-p)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --python)
            PYTHON_VERSION="$2"
            shift 2
            ;;
        --help|-h)
            grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Run with --help for usage"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  ADEF Fresh Install${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  Install dir:${NC} $INSTALL_DIR"
echo -e "${YELLOW}  Branch:${NC}      $BRANCH"
echo -e "${YELLOW}  Python:${NC}      $PYTHON_VERSION"
echo -e "${YELLOW}  Venv name:${NC}   $VENV_NAME"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

# Step 1: Remove existing installation
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}⚙  Removing existing installation...${NC}"
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}✓  Removed $INSTALL_DIR${NC}"
else
    echo -e "${GREEN}✓  No existing installation found${NC}"
fi

# Step 2: Clone repository
echo -e "${YELLOW}⚙  Cloning from GitHub...${NC}"
git clone --branch "$BRANCH" --single-branch "$REPO_URL" "$INSTALL_DIR"
echo -e "${GREEN}✓  Cloned $BRANCH to $INSTALL_DIR${NC}"

# Step 3: Navigate to repo
cd "$INSTALL_DIR"
echo -e "${GREEN}✓  Changed to $INSTALL_DIR${NC}"

# Step 4: Find Python executable
PYTHON_CMD=""
for cmd in "python$PYTHON_VERSION" "python3.$PYTHON_VERSION" "python3" "python"; do
    if command -v "$cmd" &> /dev/null; then
        DETECTED_VERSION=$("$cmd" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        if [[ "$DETECTED_VERSION" == "$PYTHON_VERSION"* ]]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}✗  Python $PYTHON_VERSION not found${NC}"
    echo -e "${YELLOW}Available Python versions:${NC}"
    for cmd in python3 python python3.11 python3.12 python3.13; do
        if command -v "$cmd" &> /dev/null; then
            echo "  - $cmd ($("$cmd" --version 2>&1))"
        fi
    done
    echo
    echo -e "${YELLOW}Install Python $PYTHON_VERSION or use --python flag:${NC}"
    echo "  ./scripts/fresh-install.sh --python 3.11"
    exit 1
fi

echo -e "${GREEN}✓  Found Python: $PYTHON_CMD ($("$PYTHON_CMD" --version 2>&1))${NC}"

# Step 5: Create virtual environment
echo -e "${YELLOW}⚙  Creating virtual environment...${NC}"
"$PYTHON_CMD" -m venv "$VENV_NAME"
echo -e "${GREEN}✓  Created $VENV_NAME${NC}"

# Step 6: Activate venv (platform-aware)
echo -e "${YELLOW}⚙  Activating virtual environment...${NC}"
if [ -f "$VENV_NAME/bin/activate" ]; then
    # Unix-like
    source "$VENV_NAME/bin/activate"
elif [ -f "$VENV_NAME/Scripts/activate" ]; then
    # Windows
    source "$VENV_NAME/Scripts/activate"
else
    echo -e "${RED}✗  Could not find venv activation script${NC}"
    exit 1
fi
echo -e "${GREEN}✓  Virtual environment activated${NC}"

# Step 7: Upgrade pip
echo -e "${YELLOW}⚙  Upgrading pip...${NC}"
python -m pip install --upgrade pip --quiet
echo -e "${GREEN}✓  Pip upgraded to $(pip --version | awk '{print $2}')${NC}"

# Step 8: Install ADEF
echo -e "${YELLOW}⚙  Installing ADEF...${NC}"
pip install -e . --quiet
echo -e "${GREEN}✓  ADEF installed (editable mode)${NC}"

# Step 9: Verify installation
echo -e "${YELLOW}⚙  Verifying installation...${NC}"
ADEF_VERSION=$(adef --version 2>&1 | head -1)
echo -e "${GREEN}✓  $ADEF_VERSION${NC}"

# Summary
echo
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓  Installation complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo
echo -e "  1. Activate the virtual environment in your shell:"
if [ -f "$VENV_NAME/bin/activate" ]; then
    echo -e "     ${BLUE}source $INSTALL_DIR/$VENV_NAME/bin/activate${NC}"
else
    echo -e "     ${BLUE}source $INSTALL_DIR/$VENV_NAME/Scripts/activate${NC}"
fi
echo
echo -e "  2. Verify ADEF is working:"
echo -e "     ${BLUE}adef --version${NC}"
echo -e "     ${BLUE}adef --help${NC}"
echo
echo -e "  3. Run the quickstart demo:"
echo -e "     ${BLUE}export ADEF_WORKSPACE=\$(mktemp -d)${NC}"
echo -e "     ${BLUE}adef schema ingest examples/adef-sources-thrunt.yml${NC}"
echo -e "     ${BLUE}adef catalog examples/demo-rules${NC}"
echo -e "     ${BLUE}adef detection list${NC}"
echo
echo -e "${YELLOW}Optional: Install dev/MCP dependencies${NC}"
echo -e "  ${BLUE}pip install -e \".[dev]\"${NC}    # pytest, ruff, mypy"
echo -e "  ${BLUE}pip install -e \".[mcp]\"${NC}    # FastMCP for adef-mcp server"
echo
