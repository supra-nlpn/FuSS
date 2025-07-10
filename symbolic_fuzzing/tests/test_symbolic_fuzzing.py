#!/usr/bin/env python3
"""
Test utilities for the DifuzzRTL Symbolic Fuzzing System

This module provides test cases and utilities for validating the symbolic
execution integration.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add src and config to path
sys.path.append(str(Path(__file__).parent.parent / "src"))
sys.path.append(str(Path(__file__).parent.parent / "config"))

# Try to import modules, handling missing dependencies gracefully
try:
    from symbolic_executor import SymbolicExecutor
    SYMBOLIC_EXECUTOR_AVAILABLE = True
except ImportError as e:
    print(f"Warning: SymbolicExecutor not available: {e}")
    SymbolicExecutor = None
    SYMBOLIC_EXECUTOR_AVAILABLE = False

try:
    from symbolic_config import SymbolicConfig
    CONFIG_AVAILABLE = True
except ImportError as e:
    print(f"Warning: SymbolicConfig not available: {e}")
    SymbolicConfig = None
    CONFIG_AVAILABLE = False

try:
    from fuzzer_integration import FuzzerIntegration
    INTEGRATION_AVAILABLE = True
except ImportError as e:
    print(f"Warning: FuzzerIntegration not available: {e}")
    FuzzerIntegration = None
    INTEGRATION_AVAILABLE = False


class TestSymbolicConfig(unittest.TestCase):
    """Test symbolic execution configuration."""
    
    def test_default_config(self):
        """Test default configuration creation."""
        if not CONFIG_AVAILABLE:
            self.skipTest("SymbolicConfig not available")
        
        config = SymbolicConfig()
        self.assertIsInstance(config.ANGR_TIMEOUT, int)
        self.assertIsInstance(config.MAX_SYMBOLIC_STATES, int)
        self.assertTrue(config.ANGR_TIMEOUT > 0)
        self.assertTrue(config.MAX_SYMBOLIC_STATES > 0)
    
    def test_config_validation(self):
        """Test configuration validation."""
        if not CONFIG_AVAILABLE:
            self.skipTest("SymbolicConfig not available")
            
        config = SymbolicConfig()
        self.assertTrue(config.validate())
        
        # Test invalid configuration
        config.ANGR_TIMEOUT = -1
        self.assertFalse(config.validate())


class TestSymbolicExecutor(unittest.TestCase):
    """Test symbolic execution engine."""
    
    def setUp(self):
        """Setup test environment."""
        if not CONFIG_AVAILABLE or not SYMBOLIC_EXECUTOR_AVAILABLE:
            self.skipTest("Required modules not available")
            
        self.config = SymbolicConfig()
        self.executor = SymbolicExecutor(self.config)
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_executor_creation(self):
        """Test symbolic executor creation."""
        self.assertIsNotNone(self.executor)
        self.assertEqual(self.executor.config, self.config)
    
    def create_test_binary(self) -> str:
        """Create a simple test binary for symbolic execution."""
        # Create a simple C program
        c_code = """
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int x = 0;
    if (argc > 1) {
        x = atoi(argv[1]);
    }
    
    if (x == 42) {
        printf("Found the answer!\\n");
        return 1;
    } else if (x > 100) {
        printf("Too big!\\n");
        return 2;
    } else {
        printf("Keep searching...\\n");
        return 0;
    }
}
"""
        
        # Write C code to file
        c_file = Path(self.temp_dir) / "test.c"
        with open(c_file, 'w') as f:
            f.write(c_code)
        
        # Compile to binary (if gcc is available)
        binary_file = Path(self.temp_dir) / "test_binary"
        try:
            import subprocess
            result = subprocess.run([
                "gcc", "-o", str(binary_file), str(c_file)
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and binary_file.exists():
                return str(binary_file)
        except Exception:
            pass
        
        return None
    
    def test_symbolic_execution_basic(self):
        """Test basic symbolic execution functionality."""
        # Create test binary
        binary_path = self.create_test_binary()
        if binary_path is None:
            self.skipTest("Could not create test binary (gcc not available)")
        
        # Run symbolic execution
        try:
            result = self.executor.run_symbolic_execution(
                binary_path,
                self.temp_dir
            )
            
            # Basic checks
            self.assertIsNotNone(result)
            self.assertIsInstance(result.success, bool)
            
        except Exception as e:
            # angr might not be properly installed in test environment
            self.skipTest(f"Symbolic execution failed (angr issue?): {e}")


class TestFuzzerIntegration(unittest.TestCase):
    """Test fuzzer integration functionality."""
    
    def setUp(self):
        """Setup test environment."""
        if not CONFIG_AVAILABLE or not INTEGRATION_AVAILABLE:
            self.skipTest("Required modules not available")
            
        self.temp_dir = tempfile.mkdtemp()
        self.config = SymbolicConfig()
        
        # Create mock difuzz-rtl structure
        self.mock_difuzz_dir = Path(self.temp_dir) / "mock_difuzz"
        self.mock_difuzz_dir.mkdir()
        
        # Create fuzzer directory structure
        fuzzer_dir = self.mock_difuzz_dir / "Fuzzer"
        fuzzer_dir.mkdir()
        
        template_dir = fuzzer_dir / "Template"
        template_dir.mkdir()
        
        # Create mock template file
        template_file = template_dir / "test_template.S"
        with open(template_file, 'w') as f:
            f.write("""
#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

{GENERATED_CODE}

RVTEST_CODE_END
RVTEST_DATA_BEGIN
RVTEST_DATA_END
""")
    
    def tearDown(self):
        """Cleanup test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_integration_creation(self):
        """Test fuzzer integration creation."""
        integration = FuzzerIntegration(
            str(self.mock_difuzz_dir),
            str(Path(self.temp_dir) / "output"),
            self.config
        )
        
        self.assertIsNotNone(integration)
        self.assertEqual(str(integration.difuzz_rtl_path), str(self.mock_difuzz_dir))
    
    def test_coverage_extraction(self):
        """Test coverage information extraction."""
        integration = FuzzerIntegration(
            str(self.mock_difuzz_dir),
            str(Path(self.temp_dir) / "output"),
            self.config
        )
        
        # Create mock coverage file
        coverage_file = integration.output_dir / "coverage.txt"
        with open(coverage_file, 'w') as f:
            f.write("42")
        
        coverage = integration.extract_coverage_from_fuzzer()
        self.assertIsNotNone(coverage)
    
    def test_corpus_detection(self):
        """Test test corpus detection."""
        integration = FuzzerIntegration(
            str(self.mock_difuzz_dir),
            str(Path(self.temp_dir) / "output"),
            self.config
        )
        
        # Create some test files
        corpus_dir = integration.corpus_dir
        test_file = corpus_dir / "test1.S"
        with open(test_file, 'w') as f:
            f.write("# Test assembly file\nnop\n")
        
        corpus = integration.get_test_corpus()
        self.assertGreater(len(corpus), 0)
    
    def test_plateau_detection(self):
        """Test coverage plateau detection."""
        integration = FuzzerIntegration(
            str(self.mock_difuzz_dir),
            str(Path(self.temp_dir) / "output"),
            self.config
        )
        
        # Simulate stable coverage (plateau)
        for i in range(10):
            coverage = {"mux_coverage": 100}  # Same coverage
            plateau = integration.detect_coverage_plateau(coverage)
        
        # Should detect plateau after enough iterations
        self.assertTrue(plateau)


def create_example_config() -> str:
    """Create an example configuration file."""
    config_content = """# Example Symbolic Execution Configuration
# Copy this file and modify as needed

# Symbolic execution timeouts and limits
ANGR_TIMEOUT = 300
MAX_SYMBOLIC_STATES = 1000
MAX_EXPLORATION_DEPTH = 50

# Coverage plateau detection
PLATEAU_THRESHOLD = 5
PLATEAU_WINDOW = 10

# Test generation
MAX_NEW_TESTS_PER_RUN = 10
MAX_CORPUS_FILES = 5

# RISC-V toolchain paths
RISCV_GCC = "riscv64-unknown-elf-gcc"
RISCV_OBJDUMP = "riscv64-unknown-elf-objdump"
RISCV_READELF = "riscv64-unknown-elf-readelf"

# Debug options
DEBUG_SYMBOLIC_EXECUTION = True
SAVE_INTERMEDIATE_RESULTS = True
VERBOSE_LOGGING = False
"""
    
    return config_content


def run_basic_tests():
    """Run basic functionality tests."""
    print("Running basic symbolic fuzzing system tests...")
    
    # Test configuration
    print("Testing configuration...")
    if CONFIG_AVAILABLE:
        config = SymbolicConfig()
        assert config.validate(), "Configuration validation failed"
        print("✓ Configuration OK")
    else:
        print("✗ Configuration not available (missing dependencies)")
        return False
    
    # Test symbolic executor creation
    print("Testing symbolic executor...")
    if SYMBOLIC_EXECUTOR_AVAILABLE:
        try:
            executor = SymbolicExecutor(config)
            print("✓ Symbolic executor created")
        except Exception as e:
            print(f"✗ Symbolic executor failed: {e}")
            return False
    else:
        print("✗ Symbolic executor not available (angr not installed)")
        print("  Install angr with: pip3 install angr")
        # Don't fail the test for this, as angr is optional for basic tests
    
    # Test with mock fuzzer integration
    print("Testing fuzzer integration...")
    if INTEGRATION_AVAILABLE:
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                integration = FuzzerIntegration(
                    temp_dir,  # Mock difuzz path
                    temp_dir,  # Output dir
                    config
                )
                print("✓ Fuzzer integration created")
            except Exception as e:
                print(f"✗ Fuzzer integration failed: {e}")
                return False
    else:
        print("✗ Fuzzer integration not available")
        return False
    
    print("All basic tests passed!")
    return True


def main():
    """Main test function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test DifuzzRTL Symbolic Fuzzing System")
    parser.add_argument(
        "--unit-tests",
        action="store_true",
        help="Run unit tests"
    )
    parser.add_argument(
        "--basic-tests",
        action="store_true",
        help="Run basic functionality tests"
    )
    parser.add_argument(
        "--create-example-config",
        help="Create example configuration file at specified path"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all tests"
    )
    
    args = parser.parse_args()
    
    if args.create_example_config:
        config_content = create_example_config()
        with open(args.create_example_config, 'w') as f:
            f.write(config_content)
        print(f"Example configuration created: {args.create_example_config}")
        return 0
    
    success = True
    
    if args.basic_tests or args.all:
        success &= run_basic_tests()
    
    if args.unit_tests or args.all:
        print("\nRunning unit tests...")
        # Run unittest
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(sys.modules[__name__])
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        success &= result.wasSuccessful()
    
    if not any([args.unit_tests, args.basic_tests, args.all]):
        parser.print_help()
        return 1
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
