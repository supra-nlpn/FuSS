#!/usr/bin/env python3
"""
Fuzzer Integration Module for DifuzzRTL Symbolic Execution

This module provides the interface between the DifuzzRTL fuzzer and the symbolic
execution engine. It monitors fuzzer progress, detects coverage plateaus, and
orchestrates symbolic execution to generate new test vectors.
"""

import os
import sys
import json
import time
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Add symbolic fuzzing src to path for imports
sys.path.append(str(Path(__file__).parent))
sys.path.append(str(Path(__file__).parent.parent / "config"))

from symbolic_executor import SymbolicExecutor, SymbolicExecutionResult
from symbolic_config import SymbolicConfig


class FuzzerIntegration:
    """Main integration class that bridges DifuzzRTL with symbolic execution."""
    
    def __init__(self, difuzz_rtl_path: str, output_dir: str, config: SymbolicConfig):
        """
        Initialize the fuzzer integration.
        
        Args:
            difuzz_rtl_path: Path to the difuzz-rtl directory
            output_dir: Directory for symbolic execution outputs
            config: Symbolic execution configuration
        """
        self.difuzz_rtl_path = Path(difuzz_rtl_path)
        self.output_dir = Path(output_dir)
        self.config = config
        # Note: SymbolicExecutor will be created on demand with specific toplevel
        self.symbolic_executor = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'fuzzer_integration.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Coverage tracking
        self.coverage_history = []
        self.last_coverage = 0
        self.plateau_counter = 0
        self.symbolic_runs = 0
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Paths to important directories
        self.fuzzer_dir = self.difuzz_rtl_path / "Fuzzer"
        self.corpus_dir = self.output_dir / "corpus"
        self.symbolic_output_dir = self.output_dir / "symbolic_results"
        
        self.corpus_dir.mkdir(exist_ok=True)
        self.symbolic_output_dir.mkdir(exist_ok=True)
    
    def extract_coverage_from_fuzzer(self) -> Optional[Dict[str, Any]]:
        """
        Extract current coverage information from the DifuzzRTL fuzzer.
        
        Returns:
            Dictionary containing coverage metrics or None if unavailable
        """
        try:
            # Look for coverage files in typical locations
            coverage_files = [
                self.difuzz_rtl_path / "micro" / "results" / "avg_reached_mux.txt",
                self.fuzzer_dir / "coverage.txt",
                self.output_dir / "coverage.txt"
            ]
            
            coverage_data = {}
            
            for coverage_file in coverage_files:
                if coverage_file.exists():
                    try:
                        with open(coverage_file, 'r') as f:
                            content = f.read().strip()
                            if content.isdigit():
                                coverage_data['mux_coverage'] = int(content)
                            else:
                                # Try to parse as JSON or other format
                                try:
                                    data = json.loads(content)
                                    coverage_data.update(data)
                                except json.JSONDecodeError:
                                    # Parse line by line for simple formats
                                    lines = content.split('\n')
                                    for line in lines:
                                        if ':' in line:
                                            key, value = line.split(':', 1)
                                            try:
                                                coverage_data[key.strip()] = int(value.strip())
                                            except ValueError:
                                                coverage_data[key.strip()] = value.strip()
                    except Exception as e:
                        self.logger.warning(f"Error reading coverage file {coverage_file}: {e}")
            
            # If no coverage files found, try to get coverage from fuzzer logs
            if not coverage_data:
                coverage_data = self._parse_fuzzer_logs()
            
            return coverage_data if coverage_data else None
            
        except Exception as e:
            self.logger.error(f"Error extracting coverage: {e}")
            return None
    
    def _parse_fuzzer_logs(self) -> Dict[str, Any]:
        """Parse fuzzer log files to extract coverage information."""
        coverage_data = {}
        
        # Look for log files
        log_files = list(self.fuzzer_dir.glob("*.log")) + list(self.output_dir.glob("*.log"))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    # Look for coverage-related lines (last 100 lines)
                    for line in lines[-100:]:
                        if 'coverage' in line.lower() or 'mux' in line.lower():
                            # Extract numbers from the line
                            import re
                            numbers = re.findall(r'\d+', line)
                            if numbers:
                                coverage_data['parsed_coverage'] = int(numbers[-1])
                                break
            except Exception as e:
                self.logger.debug(f"Error parsing log file {log_file}: {e}")
        
        return coverage_data
    
    def detect_coverage_plateau(self, current_coverage: Dict[str, Any]) -> bool:
        """
        Detect if the fuzzer has hit a coverage plateau.
        
        Args:
            current_coverage: Current coverage metrics
            
        Returns:
            True if plateau detected, False otherwise
        """
        # Extract main coverage metric
        coverage_value = 0
        if 'mux_coverage' in current_coverage:
            coverage_value = current_coverage['mux_coverage']
        elif 'parsed_coverage' in current_coverage:
            coverage_value = current_coverage['parsed_coverage']
        elif 'total_coverage' in current_coverage:
            coverage_value = current_coverage['total_coverage']
        else:
            # Use first numeric value found
            for value in current_coverage.values():
                if isinstance(value, int):
                    coverage_value = value
                    break
        
        self.coverage_history.append(coverage_value)
        
        # Keep only recent history
        if len(self.coverage_history) > self.config.PLATEAU_WINDOW:
            self.coverage_history = self.coverage_history[-self.config.PLATEAU_WINDOW:]
        
        # Check for plateau
        if len(self.coverage_history) >= self.config.PLATEAU_WINDOW:
            recent_coverage = self.coverage_history[-self.config.PLATEAU_WINDOW:]
            max_coverage = max(recent_coverage)
            min_coverage = min(recent_coverage)
            
            # Plateau if coverage hasn't improved significantly
            plateau_detected = (max_coverage - min_coverage) <= self.config.PLATEAU_THRESHOLD
            
            if plateau_detected:
                self.plateau_counter += 1
                self.logger.info(f"Coverage plateau detected (count: {self.plateau_counter})")
                self.logger.info(f"Coverage range in last {self.config.PLATEAU_WINDOW} iterations: {min_coverage}-{max_coverage}")
            else:
                self.plateau_counter = 0
            
            return plateau_detected and self.plateau_counter >= 3
        
        return False
    
    def get_test_corpus(self) -> List[Path]:
        """
        Get the current test corpus from the fuzzer.
        
        Returns:
            List of paths to test files
        """
        test_files = []
        
        # Look for test files in common locations
        corpus_dirs = [
            self.corpus_dir,
            self.fuzzer_dir / "corpus",
            self.difuzz_rtl_path / "corpus",
            self.output_dir / "tests"
        ]
        
        for corpus_dir in corpus_dirs:
            if corpus_dir.exists():
                # Look for assembly files, binary files, etc.
                for pattern in ["*.S", "*.s", "*.asm", "*.bin", "*.elf", "*.hex"]:
                    test_files.extend(corpus_dir.glob(pattern))
        
        # If no corpus found, look for template files
        if not test_files:
            template_dir = self.fuzzer_dir / "Template"
            if template_dir.exists():
                for pattern in ["*.S", "*.s", "*.asm"]:
                    test_files.extend(template_dir.glob(pattern))
        
        self.logger.info(f"Found {len(test_files)} test files in corpus")
        return test_files
    
    def run_symbolic_execution(self, plateau_info: Dict[str, Any]) -> List[Path]:
        """
        Run symbolic execution to generate new test vectors.
        
        Args:
            plateau_info: Information about the current plateau
            
        Returns:
            List of paths to newly generated test files
        """
        self.logger.info("Starting symbolic execution to overcome coverage plateau")
        
        # Create symbolic executor if not exists (we need a toplevel for this)
        # For now, use a default toplevel - this could be made configurable
        if self.symbolic_executor is None:
            self.symbolic_executor = SymbolicExecutor("RocketTile", str(self.output_dir))
        
        # Get current test corpus
        corpus_files = self.get_test_corpus()
        
        if not corpus_files:
            self.logger.warning("No corpus files found, using template")
            template_file = self.fuzzer_dir / "Template" / "test_template.S"
            if template_file.exists():
                corpus_files = [template_file]
            else:
                self.logger.error("No template file found, cannot run symbolic execution")
                return []
        
        new_test_files = []
        
        for i, test_file in enumerate(corpus_files[:self.config.MAX_CORPUS_FILES]):
            try:
                self.logger.info(f"Running symbolic execution on {test_file} ({i+1}/{min(len(corpus_files), self.config.MAX_CORPUS_FILES)})")
                
                # Create output directory for this run
                run_output_dir = self.symbolic_output_dir / f"run_{self.symbolic_runs}_{i}"
                run_output_dir.mkdir(exist_ok=True)
                
                # Run symbolic execution
                result = self.symbolic_executor.run_symbolic_execution(
                    str(test_file),
                    str(run_output_dir)
                )
                
                if result.success and result.new_test_vectors:
                    self.logger.info(f"Generated {len(result.new_test_vectors)} new test vectors")
                    
                    # Convert and save new test vectors
                    for j, test_vector in enumerate(result.new_test_vectors):
                        test_path = self.corpus_dir / f"symbolic_{self.symbolic_runs}_{i}_{j}.S"
                        self._save_test_vector(test_vector, test_path)
                        new_test_files.append(test_path)
                
            except Exception as e:
                self.logger.error(f"Error in symbolic execution for {test_file}: {e}")
        
        self.symbolic_runs += 1
        self.logger.info(f"Symbolic execution completed. Generated {len(new_test_files)} new test files")
        
        return new_test_files
    
    def _save_test_vector(self, test_vector: bytes, output_path: Path):
        """
        Save a test vector as a RISC-V assembly file.
        
        Args:
            test_vector: Raw test vector bytes
            output_path: Path to save the assembly file
        """
        try:
            # Convert test vector to RISC-V assembly
            assembly_code = self._convert_to_assembly(test_vector)
            
            with open(output_path, 'w') as f:
                f.write(assembly_code)
            
            self.logger.debug(f"Saved test vector to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving test vector to {output_path}: {e}")
    
    def _convert_to_assembly(self, test_vector: bytes) -> str:
        """
        Convert raw test vector bytes to RISC-V assembly code.
        
        Args:
            test_vector: Raw bytes
            
        Returns:
            RISC-V assembly code as string
        """
        # Read template file
        template_file = self.fuzzer_dir / "Template" / "test_template.S"
        if template_file.exists():
            with open(template_file, 'r') as f:
                template = f.read()
        else:
            # Basic template
            template = """
#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64M
RVTEST_CODE_BEGIN

{GENERATED_CODE}

RVTEST_CODE_END
RVTEST_DATA_BEGIN
RVTEST_DATA_END
"""
        
        # Convert bytes to RISC-V instructions
        generated_code = []
        
        # Simple conversion: use bytes as immediate values in various instructions
        for i in range(0, len(test_vector), 4):
            chunk = test_vector[i:i+4]
            if len(chunk) == 4:
                value = int.from_bytes(chunk, byteorder='little')
                # Generate different instruction types
                reg_num = (i // 4) % 32
                generated_code.append(f"    li x{reg_num}, {value & 0xFFFF}")
                if value > 0xFFFF:
                    generated_code.append(f"    lui x{reg_num}, {(value >> 16) & 0xFFFF}")
        
        # Add some control flow instructions
        generated_code.extend([
            "    nop",
            "    nop",
            "RVTEST_PASS"
        ])
        
        return template.replace("{GENERATED_CODE}", "\n".join(generated_code))
    
    def integrate_new_tests(self, new_test_files: List[Path]) -> bool:
        """
        Integrate newly generated test files into the fuzzer corpus.
        
        Args:
            new_test_files: List of new test file paths
            
        Returns:
            True if integration successful, False otherwise
        """
        try:
            self.logger.info(f"Integrating {len(new_test_files)} new test files into fuzzer corpus")
            
            # Copy files to fuzzer corpus directory if different
            fuzzer_corpus = self.fuzzer_dir / "corpus"
            if fuzzer_corpus.exists() and fuzzer_corpus != self.corpus_dir:
                for test_file in new_test_files:
                    dest_file = fuzzer_corpus / test_file.name
                    dest_file.write_text(test_file.read_text())
                    self.logger.debug(f"Copied {test_file} to {dest_file}")
            
            # Create integration status file
            status_file = self.output_dir / "integration_status.json"
            status = {
                "timestamp": time.time(),
                "new_tests_count": len(new_test_files),
                "new_test_files": [str(f) for f in new_test_files],
                "symbolic_runs": self.symbolic_runs,
                "coverage_history": self.coverage_history[-10:]  # Last 10 entries
            }
            
            with open(status_file, 'w') as f:
                json.dump(status, f, indent=2)
            
            self.logger.info("Test integration completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error integrating new tests: {e}")
            return False
    
    def run_integration_cycle(self) -> bool:
        """
        Run one complete integration cycle: check coverage, detect plateau, run symbolic execution.
        
        Returns:
            True if symbolic execution was triggered, False otherwise
        """
        try:
            # Extract current coverage
            coverage = self.extract_coverage_from_fuzzer()
            if coverage is None:
                self.logger.warning("Could not extract coverage information")
                return False
            
            self.logger.info(f"Current coverage: {coverage}")
            
            # Check for plateau
            if self.detect_coverage_plateau(coverage):
                self.logger.info("Coverage plateau detected, triggering symbolic execution")
                
                # Run symbolic execution
                new_test_files = self.run_symbolic_execution(coverage)
                
                if new_test_files:
                    # Integrate new tests
                    success = self.integrate_new_tests(new_test_files)
                    if success:
                        self.logger.info("Symbolic execution cycle completed successfully")
                        # Reset plateau counter after successful symbolic execution
                        self.plateau_counter = 0
                        return True
                else:
                    self.logger.warning("Symbolic execution did not generate new tests")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error in integration cycle: {e}")
            return False


def main():
    """Main function for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description="DifuzzRTL Symbolic Execution Integration")
    parser.add_argument("--difuzz-path", required=True, help="Path to difuzz-rtl directory")
    parser.add_argument("--output-dir", required=True, help="Output directory for symbolic execution")
    parser.add_argument("--config-file", help="Path to symbolic config file")
    parser.add_argument("--continuous", action="store_true", help="Run in continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=300, help="Monitoring interval in seconds")
    
    args = parser.parse_args()
    
    # Load configuration
    if args.config_file:
        config = SymbolicConfig.from_file(args.config_file)
    else:
        config = SymbolicConfig()
    
    # Create integration instance
    integration = FuzzerIntegration(args.difuzz_path, args.output_dir, config)
    
    if args.continuous:
        # Continuous monitoring mode
        print(f"Starting continuous monitoring with {args.interval}s intervals...")
        try:
            while True:
                integration.run_integration_cycle()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Monitoring stopped by user")
    else:
        # Single cycle
        print("Running single integration cycle...")
        success = integration.run_integration_cycle()
        if success:
            print("Symbolic execution triggered and completed")
        else:
            print("No symbolic execution needed or failed")


if __name__ == "__main__":
    main()
