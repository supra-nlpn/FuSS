#!/bin/bash
# Wrapper script to ensure FuSS commands always run in the virtual environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
FUSS_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$FUSS_ROOT/symbolic_fuzzing/venv"
VENV_ACTIVATE="$VENV_DIR/bin/activate"

# Check if virtual environment exists
if [ ! -f "$VENV_ACTIVATE" ]; then
    echo -e "${RED}❌ Virtual environment not found.${NC}"
    echo "Please run the setup first:"
    echo "  cd $FUSS_ROOT"
    echo "  python3 fuss.py setup"
    exit 1
fi

# Activate virtual environment and run the command
cd "$FUSS_ROOT"
source "$VENV_ACTIVATE"

# Execute the command passed as arguments
exec "$@"
