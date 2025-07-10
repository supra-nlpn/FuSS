#!/usr/bin/env python3
"""
Main wrapper script for the DifuzzRTL Symbolic Fuzzing System

This script provides an easy-to-use interface for running the integrated
symbolic fuzzing system with DifuzzRTL.
"""

import os
import sys
import argparse
import json
import logging
import signal
import subprocess
from pathlib import Path
from typing import Optional

# Add symbolic fuzzing modules to path
SCRIPT_DIR = Path(__file__).parent
SRC_DIR = SCRIPT_DIR.parent / "src"
CONFIG_DIR = SCRIPT_DIR.parent / "config"

sys.path.append(str(SRC_DIR))
sys.path.append(str(CONFIG_DIR))

from fuzzer_integration import FuzzerIntegration
from symbolic_config import SymbolicConfig


class SymbolicFuzzingRunner:
    """Main runner for the symbolic fuzzing system."""
    
    def __init__(self):
        self.integration = None
        self.fuzzer_process = None
        self.running = False
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\nReceived signal {signum}, shutting down gracefully...")
        self.running = False
        if self.fuzzer_process:
            self.fuzzer_process.terminate()
    
    def setup_workspace(self, workspace_dir: str) -> Path:
        """
        Setup the workspace directory structure.
        
        Args:
            workspace_dir: Path to workspace directory
            
        Returns:
            Path to the workspace directory
        """
        workspace = Path(workspace_dir)
        workspace.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (workspace / "corpus").mkdir(exist_ok=True)
        (workspace / "symbolic_results").mkdir(exist_ok=True)
        (workspace / "logs").mkdir(exist_ok=True)
        (workspace / "coverage").mkdir(exist_ok=True)
        
        print(f"Workspace setup complete: {workspace}")
        return workspace
    
    def start_fuzzer(self, difuzz_rtl_path: str, target: str, workspace: Path) -> Optional[subprocess.Popen]:
        """
        Start the DifuzzRTL fuzzer in the background.
        
        Args:
            difuzz_rtl_path: Path to difuzz-rtl directory
            target: Target design to fuzz
            workspace: Workspace directory
            
        Returns:
            Popen object for the fuzzer process or None if failed
        """
        try:
            difuzz_path = Path(difuzz_rtl_path)
            fuzzer_script = difuzz_path / "Fuzzer" / "DifuzzRTL.py"
            
            if not fuzzer_script.exists():
                print(f"Error: Fuzzer script not found at {fuzzer_script}")
                return None
            
            # Prepare fuzzer command
            cmd = [
                sys.executable,  # Use same Python interpreter
                str(fuzzer_script),
                "--target", target,
                "--output", str(workspace / "logs"),
                "--corpus", str(workspace / "corpus")
            ]
            
            print(f"Starting DifuzzRTL fuzzer: {' '.join(cmd)}")
            
            # Start fuzzer process
            process = subprocess.Popen(
                cmd,
                cwd=str(difuzz_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            print(f"Fuzzer started with PID: {process.pid}")
            return process
            
        except Exception as e:
            print(f"Error starting fuzzer: {e}")
            return None
    
    def run_standalone_symbolic(self, args) -> int:
        """
        Run symbolic execution in standalone mode (without continuous fuzzing).
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Exit code
        """
        try:
            # Setup workspace
            workspace = self.setup_workspace(args.workspace)
            
            # Load configuration
            if args.config:
                config = SymbolicConfig.from_file(args.config)
            else:
                config = SymbolicConfig()
            
            # Create integration instance
            self.integration = FuzzerIntegration(
                args.difuzz_rtl_path,
                str(workspace),
                config
            )
            
            print("Running standalone symbolic execution...")
            
            # Force a symbolic execution run
            coverage_info = {"forced_run": True}
            new_tests = self.integration.run_symbolic_execution(coverage_info)
            
            if new_tests:
                print(f"Generated {len(new_tests)} new test cases")
                self.integration.integrate_new_tests(new_tests)
                print("New test cases integrated into corpus")
                return 0
            else:
                print("No new test cases generated")
                return 1
                
        except Exception as e:
            print(f"Error in standalone symbolic execution: {e}")
            return 1
    
    def run_integrated_fuzzing(self, args) -> int:
        """
        Run integrated fuzzing with symbolic execution.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Exit code
        """
        try:
            # Setup workspace
            workspace = self.setup_workspace(args.workspace)
            
            # Load configuration
            if args.config:
                config = SymbolicConfig.from_file(args.config)
            else:
                config = SymbolicConfig()
            
            # Create integration instance
            self.integration = FuzzerIntegration(
                args.difuzz_rtl_path,
                str(workspace),
                config
            )
            
            # Start the fuzzer if requested
            if args.start_fuzzer:
                self.fuzzer_process = self.start_fuzzer(
                    args.difuzz_rtl_path,
                    args.target,
                    workspace
                )
                if not self.fuzzer_process:
                    return 1
            
            print(f"Starting integrated fuzzing with {args.interval}s monitoring intervals...")
            print("Press Ctrl+C to stop")
            
            self.running = True
            cycles = 0
            symbolic_runs = 0
            
            try:
                while self.running:
                    cycles += 1
                    print(f"\n--- Monitoring Cycle {cycles} ---")
                    
                    # Check if fuzzer is still running
                    if self.fuzzer_process and self.fuzzer_process.poll() is not None:
                        print("Fuzzer process has terminated")
                        if not args.continue_without_fuzzer:
                            break
                    
                    # Run integration cycle
                    symbolic_triggered = self.integration.run_integration_cycle()
                    if symbolic_triggered:
                        symbolic_runs += 1
                        print(f"Symbolic execution run #{symbolic_runs} completed")
                    
                    # Wait for next cycle
                    import time
                    for i in range(args.interval):
                        if not self.running:
                            break
                        time.sleep(1)
                        if i % 30 == 0 and i > 0:  # Progress update every 30 seconds
                            print(f"Next cycle in {args.interval - i}s...")
                
            except KeyboardInterrupt:
                print("\nShutdown requested by user")
            
            finally:
                # Cleanup
                if self.fuzzer_process:
                    print("Terminating fuzzer process...")
                    self.fuzzer_process.terminate()
                    try:
                        self.fuzzer_process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        print("Force killing fuzzer process...")
                        self.fuzzer_process.kill()
            
            print(f"\nIntegrated fuzzing completed:")
            print(f"  Total monitoring cycles: {cycles}")
            print(f"  Symbolic execution runs: {symbolic_runs}")
            
            return 0
            
        except Exception as e:
            print(f"Error in integrated fuzzing: {e}")
            return 1
    
    def run_coverage_analysis(self, args) -> int:
        """
        Run coverage analysis on existing corpus.
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            Exit code
        """
        try:
            workspace = self.setup_workspace(args.workspace)
            
            # Load configuration
            if args.config:
                config = SymbolicConfig.from_file(args.config)
            else:
                config = SymbolicConfig()
            
            # Create integration instance
            self.integration = FuzzerIntegration(
                args.difuzz_rtl_path,
                str(workspace),
                config
            )
            
            print("Analyzing coverage...")
            
            # Extract current coverage
            coverage = self.integration.extract_coverage_from_fuzzer()
            if coverage:
                print("Current coverage metrics:")
                for key, value in coverage.items():
                    print(f"  {key}: {value}")
            else:
                print("No coverage information available")
            
            # Analyze corpus
            corpus_files = self.integration.get_test_corpus()
            print(f"\nCorpus analysis:")
            print(f"  Total test files: {len(corpus_files)}")
            
            if corpus_files:
                print("  Test file sizes:")
                for test_file in corpus_files[:10]:  # Show first 10
                    size = test_file.stat().st_size
                    print(f"    {test_file.name}: {size} bytes")
                
                if len(corpus_files) > 10:
                    print(f"    ... and {len(corpus_files) - 10} more files")
            
            return 0
            
        except Exception as e:
            print(f"Error in coverage analysis: {e}")
            return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="DifuzzRTL Symbolic Fuzzing System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run integrated fuzzing with automatic fuzzer startup
  python3 symbolic_fuzzing_main.py integrated \\
    --difuzz-rtl-path ./difuzz-rtl \\
    --workspace ./workspace \\
    --target RocketTile \\
    --start-fuzzer
  
  # Run only symbolic execution on existing corpus
  python3 symbolic_fuzzing_main.py symbolic \\
    --difuzz-rtl-path ./difuzz-rtl \\
    --workspace ./workspace
  
  # Analyze coverage of existing corpus
  python3 symbolic_fuzzing_main.py analyze \\
    --difuzz-rtl-path ./difuzz-rtl \\
    --workspace ./workspace
        """
    )
    
    # Global arguments
    parser.add_argument(
        "--difuzz-rtl-path",
        required=True,
        help="Path to the difuzz-rtl directory"
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="Workspace directory for outputs and corpus"
    )
    parser.add_argument(
        "--config",
        help="Path to symbolic execution configuration file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Integrated fuzzing command
    integrated_parser = subparsers.add_parser(
        "integrated",
        help="Run integrated fuzzing with symbolic execution"
    )
    integrated_parser.add_argument(
        "--target",
        default="RocketTile",
        help="Target design to fuzz (default: RocketTile)"
    )
    integrated_parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Monitoring interval in seconds (default: 300)"
    )
    integrated_parser.add_argument(
        "--start-fuzzer",
        action="store_true",
        help="Automatically start the DifuzzRTL fuzzer"
    )
    integrated_parser.add_argument(
        "--continue-without-fuzzer",
        action="store_true",
        help="Continue monitoring even if fuzzer process dies"
    )
    
    # Standalone symbolic execution command
    symbolic_parser = subparsers.add_parser(
        "symbolic",
        help="Run standalone symbolic execution"
    )
    
    # Coverage analysis command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze coverage and corpus"
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Validate difuzz-rtl path
    difuzz_path = Path(args.difuzz_rtl_path)
    if not difuzz_path.exists():
        print(f"Error: DifuzzRTL path does not exist: {difuzz_path}")
        return 1
    
    # Create runner and execute command
    runner = SymbolicFuzzingRunner()
    
    try:
        if args.command == "integrated":
            return runner.run_integrated_fuzzing(args)
        elif args.command == "symbolic":
            return runner.run_standalone_symbolic(args)
        elif args.command == "analyze":
            return runner.run_coverage_analysis(args)
        else:
            print(f"Unknown command: {args.command}")
            return 1
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
