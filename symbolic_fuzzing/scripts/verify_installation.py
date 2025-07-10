#!/usr/bin/env python3
"""
Quick verification script for the DifuzzRTL Symbolic Fuzzing System.
This should be run after setting up the virtual environment.
"""

import sys
import os
import tempfile
import subprocess
from pathlib import Path

def run_test(name, test_func):
    """Run a test and report results."""
    try:
        result = test_func()
        print(f"✓ {name}: {'PASS' if result else 'FAIL'}")
        return result
    except Exception as e:
        print(f"✗ {name}: FAIL ({e})")
        return False

def test_basic_imports():
    """Test that basic modules can be imported."""
    try:
        # Add our modules to path
        script_dir = Path(__file__).parent
        src_dir = script_dir.parent / "src"
        config_dir = script_dir.parent / "config"
        
        sys.path.insert(0, str(src_dir))
        sys.path.insert(0, str(config_dir))
        
        from symbolic_config import SymbolicConfig
        from fuzzer_integration import FuzzerIntegration
        
        return True
    except ImportError:
        return False

def test_angr_import():
    """Test that angr can be imported."""
    try:
        import angr
        import claripy
        return True
    except ImportError:
        return False

def test_config_creation():
    """Test that configuration can be created and validated."""
    try:
        script_dir = Path(__file__).parent
        src_dir = script_dir.parent / "src"
        config_dir = script_dir.parent / "config"
        
        sys.path.insert(0, str(src_dir))
        sys.path.insert(0, str(config_dir))
        
        from symbolic_config import SymbolicConfig
        
        config = SymbolicConfig()
        return config.validate()
    except:
        return False

def test_symbolic_executor_creation():
    """Test that symbolic executor can be created."""
    try:
        script_dir = Path(__file__).parent
        src_dir = script_dir.parent / "src"
        config_dir = script_dir.parent / "config"
        
        sys.path.insert(0, str(src_dir))
        sys.path.insert(0, str(config_dir))
        
        from symbolic_executor import SymbolicExecutor
        from symbolic_config import SymbolicConfig
        
        config = SymbolicConfig()
        executor = SymbolicExecutor(config)
        return True
    except:
        return False

def test_integration_creation():
    """Test that fuzzer integration can be created."""
    try:
        script_dir = Path(__file__).parent
        src_dir = script_dir.parent / "src"
        config_dir = script_dir.parent / "config"
        
        sys.path.insert(0, str(src_dir))
        sys.path.insert(0, str(config_dir))
        
        from fuzzer_integration import FuzzerIntegration
        from symbolic_config import SymbolicConfig
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config = SymbolicConfig()
            integration = FuzzerIntegration(temp_dir, temp_dir, config)
            return True
    except:
        return False

def test_main_script_help():
    """Test that the main script can show help."""
    try:
        script_dir = Path(__file__).parent
        main_script = script_dir / "symbolic_fuzzing_main.py"
        
        result = subprocess.run([
            sys.executable, str(main_script), "--help"
        ], capture_output=True, text=True, timeout=10)
        
        return result.returncode == 0 and "DifuzzRTL Symbolic Fuzzing System" in result.stdout
    except:
        return False

def test_simple_angr_functionality():
    """Test basic angr functionality with a simple binary."""
    try:
        import angr
        import tempfile
        import subprocess
        
        # Create a simple C program
        c_code = '''
#include <stdio.h>
int main() {
    int x = 42;
    if (x == 42) {
        printf("Hello World!\\n");
        return 0;
    }
    return 1;
}
'''
        
        with tempfile.TemporaryDirectory() as temp_dir:
            c_file = Path(temp_dir) / "test.c"
            binary_file = Path(temp_dir) / "test"
            
            # Write C code
            with open(c_file, 'w') as f:
                f.write(c_code)
            
            # Try to compile
            try:
                result = subprocess.run([
                    "gcc", "-o", str(binary_file), str(c_file)
                ], capture_output=True, timeout=10)
                
                if result.returncode != 0:
                    # GCC not available, skip this test
                    return None
                
                # Try to load with angr
                project = angr.Project(str(binary_file), auto_load_libs=False)
                return project is not None
                
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # GCC not available or timeout
                return None
                
    except Exception:
        return False

def main():
    """Run all verification tests."""
    print("DifuzzRTL Symbolic Fuzzing System - Verification")
    print("=" * 55)
    print()
    
    # Check Python version
    print(f"Python version: {sys.version}")
    print(f"Python executable: {sys.executable}")
    print()
    
    # Run tests
    tests = [
        ("Basic module imports", test_basic_imports),
        ("angr import", test_angr_import),
        ("Configuration creation", test_config_creation),
        ("Symbolic executor creation", test_symbolic_executor_creation),
        ("Integration creation", test_integration_creation),
        ("Main script help", test_main_script_help),
        ("Simple angr functionality", test_simple_angr_functionality),
    ]
    
    passed = 0
    failed = 0
    skipped = 0
    
    for name, test_func in tests:
        result = run_test(name, test_func)
        if result is True:
            passed += 1
        elif result is False:
            failed += 1
        else:  # None means skipped
            print(f"⚠ {name}: SKIPPED (dependencies not available)")
            skipped += 1
    
    print()
    print("=" * 55)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    
    if failed == 0:
        print("\n✓ Verification completed successfully!")
        print("\nYou can now:")
        print("  1. Run the demo: python scripts/demo.py")
        print("  2. Test the system: python scripts/symbolic_fuzzing_main.py --help")
        print("  3. Start using: python scripts/symbolic_fuzzing_main.py analyze --help")
        return 0
    else:
        print(f"\n✗ {failed} tests failed. Please check the installation.")
        if skipped > 0:
            print(f"  ({skipped} tests were skipped due to missing dependencies)")
        return 1

if __name__ == "__main__":
    sys.exit(main())
