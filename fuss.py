#!/usr/bin/env python3
"""
FuSS (Fuzzing with Selective Symbolic Execution) - Main Entry Point

This is the main interface for the FuSS framework that integrates DifuzzRTL
with symbolic execution capabilities using angr.

FuSS provides enhanced RTL fuzzing by automatically detecting coverage plateaus
and using symbolic execution to generate targeted test vectors.

All commands automatically use the Python virtual environment for consistency.
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path
from typing import List, Optional


def ensure_venv_and_rerun():
    """Ensure we're running in the virtual environment, restart if needed."""
    # Skip venv check for setup command since we might be creating the venv
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        return
    
    script_path = Path(__file__).resolve()
    fuss_root = script_path.parent
    venv_dir = fuss_root / "symbolic_fuzzing" / "venv"
    venv_activate = venv_dir / "bin" / "activate"
    
    # Check if we're already in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        # We're in a virtual environment, check if it's the right one
        current_venv = Path(sys.prefix)
        if current_venv == venv_dir:
            # We're in the correct venv, continue
            return
    
    # We're not in the venv or in the wrong venv, restart with venv
    if not venv_activate.exists():
        print("❌ Virtual environment not found.")
        print("Please run setup first:")
        print(f"  cd {fuss_root}")
        print("  python3 fuss.py setup")
        sys.exit(1)
    
    # Restart with virtual environment
    cmd = [
        "bash", "-c",
        f"cd {fuss_root} && source {venv_activate} && python {script_path} {' '.join(sys.argv[1:])}"
    ]
    
    try:
        result = subprocess.run(cmd)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error restarting with virtual environment: {e}")
        sys.exit(1)


class FuSSFramework:
    """Main FuSS framework controller."""
    
    def __init__(self):
        self.fuss_root = Path(__file__).parent
        self.difuzz_rtl_path = self.fuss_root / "difuzz-rtl"
        self.symbolic_fuzzing_path = self.fuss_root / "symbolic_fuzzing"
        self.symbolic_main_script = self.symbolic_fuzzing_path / "scripts" / "symbolic_fuzzing_main.py"
        
    def validate_environment(self) -> bool:
        """Validate that the FuSS environment is properly set up."""
        issues = []
        
        # Check if difuzz-rtl exists
        if not self.difuzz_rtl_path.exists():
            issues.append(f"DifuzzRTL not found at {self.difuzz_rtl_path}")
            issues.append("  - Clone DifuzzRTL as a submodule or place it in the FuSS directory")
        
        # Check if symbolic_fuzzing exists
        if not self.symbolic_fuzzing_path.exists():
            issues.append(f"Symbolic fuzzing system not found at {self.symbolic_fuzzing_path}")
        
        # Check if main script exists
        if not self.symbolic_main_script.exists():
            issues.append(f"Symbolic fuzzing main script not found at {self.symbolic_main_script}")
        
        # Check Python version
        if sys.version_info < (3, 6):
            issues.append(f"Python 3.6+ required, found {sys.version}")
        
        if issues:
            print("❌ Environment validation failed:")
            for issue in issues:
                print(f"   {issue}")
            return False
        
        print("✅ Environment validation passed")
        return True
    
    def setup_symbolic_fuzzing(self, use_venv: bool = True) -> bool:
        """Set up the symbolic fuzzing system."""
        print("Setting up symbolic fuzzing system...")
        
        setup_script = self.symbolic_fuzzing_path / "scripts" / ("setup_venv.sh" if use_venv else "setup.sh")
        
        if not setup_script.exists():
            print(f"❌ Setup script not found: {setup_script}")
            return False
        
        try:
            result = subprocess.run([str(setup_script)], cwd=str(self.symbolic_fuzzing_path), check=True)
            print("✅ Symbolic fuzzing setup completed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Setup failed: {e}")
            return False
    
    def run_symbolic_fuzzing(self, args: List[str]) -> int:
        """Run the symbolic fuzzing system with given arguments."""
        if not self.validate_environment():
            return 1

        try:
            # Update difuzz-rtl path to be absolute if it's relative
            updated_args = []
            i = 0
            while i < len(args):
                if args[i] == "--difuzz-rtl-path" and i + 1 < len(args):
                    # Convert relative path to absolute
                    difuzz_path = args[i + 1]
                    if not os.path.isabs(difuzz_path):
                        if difuzz_path.startswith("./difuzz-rtl") or difuzz_path == "difuzz-rtl":
                            difuzz_path = str(self.difuzz_rtl_path)
                        else:
                            difuzz_path = str(self.fuss_root / difuzz_path)
                    updated_args.extend([args[i], difuzz_path])
                    i += 2
                else:
                    updated_args.append(args[i])
                    i += 1
            
            # Run with the current Python (which should be in venv)
            cmd = [sys.executable, str(self.symbolic_main_script)] + updated_args
            
            result = subprocess.run(cmd, cwd=str(self.fuss_root))
            return result.returncode
        except KeyboardInterrupt:
            print("\n🔄 Interrupted by user")
            return 130
        except Exception as e:
            print(f"❌ Error running symbolic fuzzing: {e}")
            return 1
    
    def show_status(self) -> None:
        """Show the current status of the FuSS framework."""
        print("FuSS Framework Status")
        print("=" * 40)
        print(f"FuSS Root: {self.fuss_root}")
        print(f"DifuzzRTL: {'✅ Found' if self.difuzz_rtl_path.exists() else '❌ Not found'}")
        print(f"Symbolic Fuzzing: {'✅ Found' if self.symbolic_fuzzing_path.exists() else '❌ Not found'}")
        
        # Check virtual environment
        venv_path = self.symbolic_fuzzing_path / "venv"
        if venv_path.exists():
            print("Virtual Environment: ✅ Available and Active")
        else:
            print("Virtual Environment: ❌ Not set up")
        
        # Check Python version and environment
        print(f"Python Version: {sys.version}")
        print(f"Python Executable: {sys.executable}")
        
        # Check if we're in virtual environment
        if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
            venv_info = "✅ Active"
        else:
            venv_info = "❌ Not active"
        print(f"Virtual Environment Status: {venv_info}")
        
        print("\nDirectory Structure:")
        for item in self.fuss_root.iterdir():
            if item.is_dir():
                print(f"  📁 {item.name}/")
            else:
                print(f"  📄 {item.name}")
    
    def run_tests(self) -> int:
        """Run the symbolic fuzzing test suite."""
        if not self.validate_environment():
            return 1
        
        print("Running FuSS test suite...")
        
        test_script = self.symbolic_fuzzing_path / "scripts" / "verify_installation.py"
        cmd = [sys.executable, str(test_script)]
        
        try:
            # Run from the symbolic_fuzzing directory to ensure correct paths
            result = subprocess.run(cmd, cwd=str(self.symbolic_fuzzing_path))
            return result.returncode
        except Exception as e:
            print(f"❌ Error running tests: {e}")
            return 1
    
    def run_demo(self) -> int:
        """Run the FuSS demonstration."""
        if not self.validate_environment():
            return 1
        
        print("Running FuSS demo...")
        
        demo_script = self.symbolic_fuzzing_path / "scripts" / "demo.py"
        cmd = [sys.executable, str(demo_script)]
        
        try:
            result = subprocess.run(cmd, cwd=str(self.symbolic_fuzzing_path))
            return result.returncode
        except Exception as e:
            print(f"❌ Error running demo: {e}")
            return 1


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        description="FuSS - Fuzzing with Selective Symbolic Execution Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
FuSS integrates DifuzzRTL with symbolic execution to enhance RTL fuzzing coverage.

Framework Commands:
  setup              Setup the symbolic fuzzing system
  status             Show framework status
  test               Run test suite
  demo               Run demonstration with realistic RTL design

Fuzzing Commands:
  integrated         Run integrated fuzzing with symbolic execution
  symbolic           Run standalone symbolic execution
  analyze            Analyze coverage and corpus

Examples:
  # Setup the framework
  ./fuss setup
  
  # Experience the RTL demo (creates toyProcessor.v with 14+ basic blocks)
  ./fuss demo
  
  # Show status
  ./fuss status
  
  # Run integrated fuzzing
  ./fuss integrated --workspace ./workspace --target RocketTile --start-fuzzer
  
  # Run standalone symbolic execution
  ./fuss symbolic --workspace ./workspace
  
  # Analyze coverage
  ./fuss analyze --workspace ./workspace
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Framework management commands
    setup_parser = subparsers.add_parser("setup", help="Setup the symbolic fuzzing system")
    setup_parser.add_argument("--no-venv", action="store_true", help="Skip virtual environment setup")
    
    status_parser = subparsers.add_parser("status", help="Show framework status")
    
    test_parser = subparsers.add_parser("test", help="Run test suite")
    
    demo_parser = subparsers.add_parser("demo", help="Run demonstration")
    
    # Fuzzing commands (these will be passed through to symbolic_fuzzing_main.py)
    integrated_parser = subparsers.add_parser("integrated", help="Run integrated fuzzing")
    integrated_parser.add_argument("--workspace", required=True, help="Workspace directory")
    integrated_parser.add_argument("--target", default="RocketTile", help="Target design")
    integrated_parser.add_argument("--interval", type=int, default=300, help="Monitoring interval")
    integrated_parser.add_argument("--start-fuzzer", action="store_true", help="Start DifuzzRTL automatically")
    integrated_parser.add_argument("--continue-without-fuzzer", action="store_true", help="Continue if fuzzer dies")
    integrated_parser.add_argument("--config", help="Configuration file")
    integrated_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    symbolic_parser = subparsers.add_parser("symbolic", help="Run standalone symbolic execution")
    symbolic_parser.add_argument("--workspace", required=True, help="Workspace directory")
    symbolic_parser.add_argument("--config", help="Configuration file")
    symbolic_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    analyze_parser = subparsers.add_parser("analyze", help="Analyze coverage and corpus")
    analyze_parser.add_argument("--workspace", required=True, help="Workspace directory")
    analyze_parser.add_argument("--config", help="Configuration file")
    analyze_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    return parser


def main():
    """Main entry point for FuSS framework."""
    # Ensure we're running in the virtual environment
    ensure_venv_and_rerun()
    
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    framework = FuSSFramework()
    
    # Handle framework management commands
    if args.command == "setup":
        # For setup command, we need to bypass the venv requirement
        # since we might be setting up the venv for the first time
        print("Setting up FuSS framework...")
        success = framework.setup_symbolic_fuzzing(use_venv=not args.no_venv)
        if success:
            print("\n✅ Setup completed! All future commands will automatically use the virtual environment.")
        return 0 if success else 1
    
    elif args.command == "status":
        framework.show_status()
        return 0
    
    elif args.command == "test":
        return framework.run_tests()
    
    elif args.command == "demo":
        return framework.run_demo()
    
    # Handle fuzzing commands (pass through to symbolic_fuzzing_main.py)
    elif args.command in ["integrated", "symbolic", "analyze"]:
        # Convert args back to command line format
        cmd_args = [args.command]
        
        # Add difuzz-rtl-path (always use the local one)
        cmd_args.extend(["--difuzz-rtl-path", "difuzz-rtl"])
        
        # Add other arguments
        if hasattr(args, 'workspace'):
            cmd_args.extend(["--workspace", args.workspace])
        
        if hasattr(args, 'target') and args.target != "RocketTile":
            cmd_args.extend(["--target", args.target])
        
        if hasattr(args, 'interval') and args.interval != 300:
            cmd_args.extend(["--interval", str(args.interval)])
        
        if hasattr(args, 'start_fuzzer') and args.start_fuzzer:
            cmd_args.append("--start-fuzzer")
        
        if hasattr(args, 'continue_without_fuzzer') and args.continue_without_fuzzer:
            cmd_args.append("--continue-without-fuzzer")
        
        if hasattr(args, 'config') and args.config:
            cmd_args.extend(["--config", args.config])
        
        if hasattr(args, 'verbose') and args.verbose:
            cmd_args.append("--verbose")
        
        return framework.run_symbolic_fuzzing(cmd_args)
    
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
