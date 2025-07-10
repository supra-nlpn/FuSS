#!/bin/bash
# Virtual Environment Setup Script for DifuzzRTL Symbolic Fuzzing System

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/venv"

echo -e "${BLUE}DifuzzRTL Symbolic Fuzzing System - Virtual Environment Setup${NC}"
echo "============================================================="
echo

# Check if we're in the right directory
if [ ! -f "$PROJECT_ROOT/src/symbolic_executor.py" ]; then
    echo -e "${RED}Error: symbolic_executor.py not found. Are you running this from the symbolic_fuzzing directory?${NC}"
    exit 1
fi

echo "Project root: $PROJECT_ROOT"
echo "Virtual environment will be created at: $VENV_DIR"
echo

# Check Python version
echo -e "${BLUE}Checking Python version...${NC}"
python3 --version
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Detected Python version: $PYTHON_VERSION"

# Check minimum Python version (3.6)
if python3 -c "import sys; exit(0 if sys.version_info >= (3, 6) else 1)"; then
    echo -e "${GREEN}✓ Python version is compatible${NC}"
else
    echo -e "${RED}✗ Python 3.6 or later is required${NC}"
    exit 1
fi

# Check if venv module is available
echo -e "${BLUE}Checking venv module...${NC}"
if python3 -c "import venv" 2>/dev/null; then
    echo -e "${GREEN}✓ venv module is available${NC}"
else
    echo -e "${RED}✗ venv module not found${NC}"
    echo "Please install python3-venv:"
    echo "  Ubuntu/Debian: sudo apt-get install python3-venv"
    echo "  CentOS/RHEL: sudo yum install python3-venv"
    echo "  Fedora: sudo dnf install python3-venv"
    exit 1
fi

# Remove existing virtual environment if it exists
if [ -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Existing virtual environment found. Removing...${NC}"
    rm -rf "$VENV_DIR"
fi

# Create virtual environment
echo -e "${BLUE}Creating virtual environment...${NC}"
python3 -m venv "$VENV_DIR"

if [ ! -f "$VENV_DIR/bin/activate" ]; then
    echo -e "${RED}✗ Failed to create virtual environment${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Virtual environment created successfully${NC}"

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo -e "${BLUE}Upgrading pip...${NC}"
pip install --upgrade pip

# Install wheel for better package installation
echo -e "${BLUE}Installing wheel...${NC}"
pip install wheel

# Install requirements
echo -e "${BLUE}Installing requirements from requirements.txt...${NC}"
if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
    pip install -r "$PROJECT_ROOT/requirements.txt"
else
    echo -e "${RED}✗ requirements.txt not found${NC}"
    exit 1
fi

# Verify key packages are installed
echo -e "${BLUE}Verifying package installations...${NC}"

# Check angr
if python -c "import angr; print(f'angr version: {angr.__version__}')" 2>/dev/null; then
    echo -e "${GREEN}✓ angr installed successfully${NC}"
else
    echo -e "${RED}✗ angr installation failed${NC}"
    echo "Trying to install angr with specific options..."
    pip install --no-cache-dir angr
    if python -c "import angr" 2>/dev/null; then
        echo -e "${GREEN}✓ angr installed successfully (retry)${NC}"
    else
        echo -e "${RED}✗ angr installation failed. You may need to install system dependencies.${NC}"
        echo "See: https://docs.angr.io/introductory-errata/install"
    fi
fi

# Check claripy
if python -c "import claripy; print('claripy: OK')" 2>/dev/null; then
    echo -e "${GREEN}✓ claripy installed successfully${NC}"
else
    echo -e "${YELLOW}⚠ claripy installation issue${NC}"
fi

# Check z3
if python -c "import z3; print(f'z3 version: {z3.get_version_string()}')" 2>/dev/null; then
    echo -e "${GREEN}✓ z3-solver installed successfully${NC}"
else
    echo -e "${YELLOW}⚠ z3-solver installation issue${NC}"
fi

# Check capstone
if python -c "import capstone; print(f'capstone version: {capstone.cs_version()}')" 2>/dev/null; then
    echo -e "${GREEN}✓ capstone installed successfully${NC}"
else
    echo -e "${YELLOW}⚠ capstone installation issue${NC}"
fi

# Install development tools if in development mode
if [ "$1" = "--dev" ]; then
    echo -e "${BLUE}Installing development dependencies...${NC}"
    pip install pytest pytest-cov black flake8 mypy
fi

# Create activation script
echo -e "${BLUE}Creating activation script...${NC}"
cat > "$PROJECT_ROOT/activate_venv.sh" << 'EOF'
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
EOF

chmod +x "$PROJECT_ROOT/activate_venv.sh"

# Test the installation
echo -e "${BLUE}Testing symbolic fuzzing system...${NC}"
cd "$PROJECT_ROOT"

# Test basic imports
if python -c "
import sys
sys.path.append('src')
sys.path.append('config')
from symbolic_config import SymbolicConfig
config = SymbolicConfig()
print('✓ Configuration module works')
" 2>/dev/null; then
    echo -e "${GREEN}✓ Basic modules import successfully${NC}"
else
    echo -e "${YELLOW}⚠ Some import issues detected${NC}"
fi

# Test symbolic executor import
if python -c "
import sys
sys.path.append('src')
sys.path.append('config')
from symbolic_executor import SymbolicExecutor
from symbolic_config import SymbolicConfig
config = SymbolicConfig()
executor = SymbolicExecutor(config)
print('✓ Symbolic executor can be created')
" 2>/dev/null; then
    echo -e "${GREEN}✓ Symbolic executor works${NC}"
else
    echo -e "${YELLOW}⚠ Symbolic executor has import issues (may be due to angr)${NC}"
fi

# Create a simple test script that runs in the venv
cat > "$PROJECT_ROOT/test_installation.py" << 'EOF'
#!/usr/bin/env python3
"""
Test script to verify the symbolic fuzzing installation.
This script should be run within the virtual environment.
"""

import sys
import traceback
from pathlib import Path

# Add our modules to path
sys.path.append('src')
sys.path.append('config')

def test_imports():
    """Test that all required modules can be imported."""
    tests = []
    
    try:
        import angr
        tests.append(("angr", True, f"version {angr.__version__}"))
    except ImportError as e:
        tests.append(("angr", False, str(e)))
    
    try:
        import claripy
        tests.append(("claripy", True, "OK"))
    except ImportError as e:
        tests.append(("claripy", False, str(e)))
    
    try:
        import z3
        tests.append(("z3", True, f"version {z3.get_version_string()}"))
    except ImportError as e:
        tests.append(("z3", False, str(e)))
    
    try:
        from symbolic_config import SymbolicConfig
        config = SymbolicConfig()
        tests.append(("symbolic_config", True, "OK"))
    except Exception as e:
        tests.append(("symbolic_config", False, str(e)))
    
    try:
        from symbolic_executor import SymbolicExecutor
        tests.append(("symbolic_executor", True, "OK"))
    except Exception as e:
        tests.append(("symbolic_executor", False, str(e)))
    
    try:
        from fuzzer_integration import FuzzerIntegration
        tests.append(("fuzzer_integration", True, "OK"))
    except Exception as e:
        tests.append(("fuzzer_integration", False, str(e)))
    
    return tests

def main():
    print("Testing DifuzzRTL Symbolic Fuzzing Installation")
    print("=" * 50)
    
    results = test_imports()
    
    passed = 0
    failed = 0
    
    for name, success, message in results:
        status = "✓ PASS" if success else "✗ FAIL"
        color = "\033[0;32m" if success else "\033[0;31m"
        reset = "\033[0m"
        
        print(f"{color}{status}{reset} {name:20} - {message}")
        
        if success:
            passed += 1
        else:
            failed += 1
    
    print()
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\033[0;32m✓ All tests passed! Installation is working correctly.\033[0m")
        return 0
    else:
        print(f"\033[0;31m✗ {failed} tests failed. Check the error messages above.\033[0m")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x "$PROJECT_ROOT/test_installation.py"

# Deactivate virtual environment
deactivate

echo
echo -e "${GREEN}✓ Virtual environment setup completed!${NC}"
echo
echo "Next steps:"
echo "1. Activate the virtual environment:"
echo "   source ./activate_venv.sh"
echo
echo "2. Test the installation:"
echo "   python test_installation.py"
echo
echo "3. Run the demo:"
echo "   python scripts/demo.py"
echo
echo "4. Try the symbolic fuzzing system:"
echo "   python scripts/symbolic_fuzzing_main.py --help"
echo
echo -e "${BLUE}Virtual environment location:${NC} $VENV_DIR"
echo -e "${BLUE}Activation script:${NC} $PROJECT_ROOT/activate_venv.sh"
echo

# Check for potential issues
echo -e "${YELLOW}Common troubleshooting:${NC}"
echo "- If angr installation fails, you may need system dependencies:"
echo "  Ubuntu: sudo apt-get install build-essential libffi-dev"
echo "- For Z3 issues, try: pip install --upgrade z3-solver"
echo "- For permission issues, ensure the script is executable: chmod +x scripts/*.sh"
echo

echo -e "${GREEN}Setup completed successfully!${NC}"
