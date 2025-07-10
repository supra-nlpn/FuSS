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
