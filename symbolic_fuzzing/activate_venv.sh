#!/bin/bash
# Activation script for DifuzzRTL Symbolic Fuzzing virtual environment

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VENV_DIR="$SCRIPT_DIR/venv"

if [ -f "$VENV_DIR/bin/activate" ]; then
    echo "Activating DifuzzRTL Symbolic Fuzzing virtual environment..."
    source "$VENV_DIR/bin/activate"
    echo "Virtual environment activated!"
    echo "Python: $(which python)"
    echo "Pip: $(which pip)"
    echo ""
    echo "To deactivate, run: deactivate"
    echo ""
    echo "Available commands:"
    echo "  python scripts/symbolic_fuzzing_main.py --help"
    echo "  python tests/test_symbolic_fuzzing.py --basic-tests"
    echo "  python scripts/demo.py"
else
    echo "Error: Virtual environment not found at $VENV_DIR"
    echo "Please run scripts/setup_venv.sh first"
    exit 1
fi
