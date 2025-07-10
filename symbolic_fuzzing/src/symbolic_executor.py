#!/usr/bin/env python3
"""
Symbolic Execution Engine for DifuzzRTL using angr
Addresses coverage plateau problem by generating targeted test vectors

This module provides symbolic execution capabilities to enhance the 
DifuzzRTL fuzzer when coverage plateaus are detected.
"""

import angr
import claripy
import os
import sys
import time
import struct
import logging
import subprocess
import json
from typing import List, Tuple, Optional, Dict, Any, Union
from collections import deque
from pathlib import Path
import tempfile
import shutil

# Add the config directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "config"))
import symbolic_config as config

# Setup logging for angr
logging.getLogger('angr').setLevel(logging.WARNING if not config.SYMEXEC_VERBOSE_LOGGING else logging.INFO)
logging.getLogger('claripy').setLevel(logging.WARNING if not config.SYMEXEC_VERBOSE_LOGGING else logging.INFO)


class SymbolicExecutionResult:
    """Represents the results of a symbolic execution run"""
    
    def __init__(self, success: bool = False, test_vectors: List[Dict[str, Any]] = None, 
                 error_message: str = None, execution_time: float = 0.0,
                 targets_explored: int = 0, solutions_found: int = 0):
        """
        Initialize symbolic execution result.
        
        Args:
            success: Whether the symbolic execution was successful
            test_vectors: List of generated test vectors
            error_message: Error message if execution failed
            execution_time: Time taken for execution in seconds
            targets_explored: Number of targets that were explored
            solutions_found: Number of concrete solutions found
        """
        self.success = success
        self.test_vectors = test_vectors or []
        self.error_message = error_message
        self.execution_time = execution_time
        self.targets_explored = targets_explored
        self.solutions_found = solutions_found
        self.timestamp = time.time()
        
    def __str__(self) -> str:
        """String representation of the result"""
        if self.success:
            return (f"SymbolicExecutionResult(success=True, "
                   f"test_vectors={len(self.test_vectors)}, "
                   f"execution_time={self.execution_time:.2f}s)")
        else:
            return (f"SymbolicExecutionResult(success=False, "
                   f"error='{self.error_message}')")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization"""
        return {
            'success': self.success,
            'test_vectors': self.test_vectors,
            'error_message': self.error_message,
            'execution_time': self.execution_time,
            'targets_explored': self.targets_explored,
            'solutions_found': self.solutions_found,
            'timestamp': self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SymbolicExecutionResult':
        """Create result from dictionary"""
        return cls(
            success=data.get('success', False),
            test_vectors=data.get('test_vectors', []),
            error_message=data.get('error_message'),
            execution_time=data.get('execution_time', 0.0),
            targets_explored=data.get('targets_explored', 0),
            solutions_found=data.get('solutions_found', 0)
        )


class CoveragePlateauDetector:
    """Detects when fuzzer coverage plateaus and needs symbolic execution assistance"""
    
    def __init__(self, window_size: int = None, threshold_ratio: float = None):
        self.window_size = window_size or config.PLATEAU_WINDOW_SIZE
        self.threshold_ratio = threshold_ratio or config.PLATEAU_THRESHOLD_RATIO
        self.coverage_history = deque(maxlen=self.window_size)
        self.iteration_history = deque(maxlen=self.window_size)
        self.last_symexec_iteration = 0
        
    def add_coverage_point(self, iteration: int, coverage: int) -> bool:
        """
        Add a coverage measurement and check if plateau detected
        Returns True if plateau is detected
        """
        self.coverage_history.append(coverage)
        self.iteration_history.append(iteration)
        
        # Check cooldown period
        if iteration - self.last_symexec_iteration < config.SYMEXEC_PLATEAU_COOLDOWN:
            return False
        
        if len(self.coverage_history) < min(self.window_size, config.PLATEAU_MIN_ITERATIONS):
            return False
            
        # Calculate coverage improvement rate
        window_quarter = self.window_size // 4
        recent_coverage = list(self.coverage_history)[-window_quarter:]
        older_coverage = list(self.coverage_history)[:window_quarter]
        
        if len(recent_coverage) < window_quarter or len(older_coverage) < window_quarter:
            return False
            
        recent_avg = sum(recent_coverage) / len(recent_coverage)
        older_avg = sum(older_coverage) / len(older_coverage)
        
        improvement_rate = (recent_avg - older_avg) / max(older_avg, 1)
        
        if config.SYMEXEC_DEBUG:
            print(f"[SymExec] Coverage improvement rate: {improvement_rate:.4f} (threshold: {self.threshold_ratio})")
        
        plateau_detected = improvement_rate < self.threshold_ratio
        if plateau_detected:
            self.last_symexec_iteration = iteration
            
        return plateau_detected
        
    def get_plateau_info(self) -> Dict[str, Any]:
        """Get information about the current plateau"""
        if len(self.coverage_history) == 0:
            return {}
            
        return {
            'current_coverage': self.coverage_history[-1],
            'average_coverage': sum(self.coverage_history) / len(self.coverage_history),
            'window_size': len(self.coverage_history),
            'iterations_tracked': len(self.iteration_history)
        }


class SymbolicTargetIdentifier:
    """Identifies potential start/end points for symbolic execution"""
    
    def __init__(self, toplevel: str, template_dir: str):
        self.toplevel = toplevel
        self.template_dir = template_dir
        self.uncovered_branches = set()
        self.coverage_map = {}
        
    def analyze_coverage_map(self, coverage_files: List[str]) -> List[Tuple[int, int]]:
        """
        Analyze coverage files to identify uncovered or rarely covered areas
        Returns list of (start_addr, end_addr) tuples for symbolic execution targets
        """
        targets = []
        
        for cov_file in coverage_files:
            if not os.path.exists(cov_file):
                continue
                
            try:
                with open(cov_file, 'r') as f:
                    coverage_data = f.read().strip()
                    
                # Find gaps in coverage (consecutive 0s)
                gap_start = None
                gap_length = 0
                
                for i, bit in enumerate(coverage_data):
                    if bit == '0':
                        if gap_start is None:
                            gap_start = i
                        gap_length += 1
                    else:
                        if gap_start is not None and gap_length >= config.SYMEXEC_MIN_GAP_SIZE:
                            # Convert bit positions to approximate addresses
                            start_addr = gap_start * config.RISCV_INSTRUCTION_SIZE + config.RISCV_BASE_ADDR
                            end_addr = (gap_start + gap_length) * config.RISCV_INSTRUCTION_SIZE + config.RISCV_BASE_ADDR
                            targets.append((start_addr, end_addr))
                        gap_start = None
                        gap_length = 0
                        
            except Exception as e:
                if config.SYMEXEC_DEBUG:
                    print(f"[SymExec] Warning: Could not parse coverage file {cov_file}: {e}")
                    
        if config.SYMEXEC_DEBUG:
            print(f"[SymExec] Identified {len(targets)} potential symbolic execution targets")
        return targets[:config.SYMEXEC_MAX_TARGETS]
        
    def identify_branch_points(self, asm_files: List[str]) -> List[Tuple[int, str]]:
        """
        Identify branch instructions that could benefit from symbolic execution
        Returns list of (address, instruction) tuples
        """
        branch_points = []
        
        for asm_file in asm_files:
            if not os.path.exists(asm_file):
                continue
                
            try:
                with open(asm_file, 'r') as f:
                    lines = f.readlines()
                    
                addr = config.RISCV_BASE_ADDR
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('.'):
                        continue
                        
                    # Parse instruction
                    parts = line.split()
                    if len(parts) > 0:
                        instr = parts[0].lower()
                        if any(branch in instr for branch in config.TARGET_BRANCH_INSTRUCTIONS):
                            branch_points.append((addr, line))
                    addr += config.RISCV_INSTRUCTION_SIZE
                    
            except Exception as e:
                if config.SYMEXEC_DEBUG:
                    print(f"[SymExec] Warning: Could not parse {asm_file}: {e}")
                
        return branch_points


class RISCVSymbolicModel:
    """Creates and manages symbolic execution model for RISC-V processor"""
    
    def __init__(self, binary_path: str, base_addr: int = None):
        self.binary_path = binary_path
        self.base_addr = base_addr or config.RISCV_BASE_ADDR
        self.project = None
        self.initial_state = None
        
    def create_project(self) -> bool:
        """Create angr project from binary"""
        try:
            # Load binary with RISC-V architecture
            self.project = angr.Project(
                self.binary_path,
                main_opts={
                    'base_addr': self.base_addr,
                    'arch': 'RISCV64'  # or 'RISCV32' based on your processor
                },
                auto_load_libs=False
            )
            
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Created angr project for {self.binary_path}")
            return True
            
        except Exception as e:
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Error creating project: {e}")
            return False
            
    def setup_initial_state(self, start_addr: int, 
                          register_constraints: Dict[str, Any] = None) -> bool:
        """Setup initial symbolic state"""
        try:
            # Create initial state at specified address
            angr_options = set()
            for option_name, enabled in config.ANGR_OPTIONS.items():
                if enabled and hasattr(angr.options, option_name):
                    angr_options.add(getattr(angr.options, option_name))
            
            self.initial_state = self.project.factory.blank_state(
                addr=start_addr,
                add_options=angr_options
            )
            
            # Apply register constraints if provided
            if register_constraints:
                for reg_name, constraint in register_constraints.items():
                    if hasattr(self.initial_state.regs, reg_name):
                        reg = getattr(self.initial_state.regs, reg_name)
                        self.initial_state.solver.add(constraint(reg))
                        
            # Make certain registers symbolic for input generation
            symbolic_regs = ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7']
            for reg_name in symbolic_regs:
                if hasattr(self.initial_state.regs, reg_name):
                    symbolic_val = self.initial_state.solver.BVS(
                        f"input_{reg_name}", 
                        config.RISCV_REGISTER_SIZE
                    )
                    setattr(self.initial_state.regs, reg_name, symbolic_val)
                    
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Setup initial state at 0x{start_addr:x}")
            return True
            
        except Exception as e:
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Error setting up initial state: {e}")
            return False
            
    def create_memory_constraints(self, memory_layout: Dict[int, bytes]) -> None:
        """Apply memory constraints to the initial state"""
        if not self.initial_state:
            return
            
        for addr, data in memory_layout.items():
            self.initial_state.memory.store(addr, data)


class SymbolicExecutor:
    """Main symbolic execution engine"""
    
    def __init__(self, toplevel: str, output_dir: str, debug: bool = False):
        self.toplevel = toplevel
        self.output_dir = output_dir
        self.debug = debug
        self.plateau_detector = CoveragePlateauDetector()
        self.target_identifier = SymbolicTargetIdentifier(toplevel, output_dir)
        self.last_symbolic_run = 0
        self.temp_dir = None
        
    def __enter__(self):
        """Context manager entry"""
        self.temp_dir = tempfile.mkdtemp(prefix="symexec_")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup temp files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        
    def should_run_symbolic_execution(self, iteration: int, coverage: int) -> bool:
        """Determine if symbolic execution should be triggered"""
        plateau_detected = self.plateau_detector.add_coverage_point(iteration, coverage)
        
        if plateau_detected:
            info = self.plateau_detector.get_plateau_info()
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Coverage plateau detected at iteration {iteration}")
                print(f"[SymExec] Current coverage: {info['current_coverage']}")
                print(f"[SymExec] Average coverage: {info['average_coverage']:.2f}")
            return True
            
        return False
        
    def prepare_symbolic_model(self, sim_input_data: Dict[str, Any]) -> Optional[RISCVSymbolicModel]:
        """Prepare symbolic execution model from current fuzzer state"""
        try:
            if not self.temp_dir:
                self.temp_dir = tempfile.mkdtemp(prefix="symexec_")
            
            # Generate assembly and binary from sim_input
            asm_path = os.path.join(self.temp_dir, 'symexec_test.S')
            bin_path = os.path.join(self.temp_dir, 'symexec_test.elf')
            
            # Write assembly file
            self._write_assembly_file(sim_input_data, asm_path)
            
            # Compile to binary
            if not self._compile_assembly(asm_path, bin_path):
                return None
                
            # Create symbolic model
            model = RISCVSymbolicModel(bin_path)
            if not model.create_project():
                return None
                
            return model
            
        except Exception as e:
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Error preparing symbolic model: {e}")
            return None
            
    def _write_assembly_file(self, sim_input_data: Dict[str, Any], asm_path: str) -> None:
        """Write assembly file from sim_input data"""
        with open(asm_path, 'w') as f:
            # Write header
            f.write("# Symbolic execution test case\n")
            f.write(".section .text\n")
            f.write(".global _start\n")
            f.write("_start:\n")
            
            # Write instructions from sim_input_data
            if 'prefix_instructions' in sim_input_data:
                for inst in sim_input_data['prefix_instructions']:
                    f.write(f"    {inst}\n")
                    
            if 'main_instructions' in sim_input_data:
                for inst in sim_input_data['main_instructions']:
                    f.write(f"    {inst}\n")
                    
            if 'suffix_instructions' in sim_input_data:
                for inst in sim_input_data['suffix_instructions']:
                    f.write(f"    {inst}\n")
                
            # Add end marker
            f.write("    ecall\n")
            f.write("    .section .data\n")
            
    def _compile_assembly(self, asm_path: str, bin_path: str) -> bool:
        """Compile assembly to binary"""
        try:
            # Use RISC-V toolchain to compile
            linker_script = Path(__file__).parent.parent / "config" / "riscv.ld"
            
            cmd = [config.RISCV_COMPILER] + config.RISCV_COMPILE_FLAGS + [
                '-T', str(linker_script),
                '-o', bin_path,
                asm_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                if config.SYMEXEC_DEBUG:
                    print(f"[SymExec] Compilation failed: {result.stderr}")
                return False
                
            return True
            
        except subprocess.TimeoutExpired:
            if config.SYMEXEC_DEBUG:
                print("[SymExec] Compilation timeout")
            return False
        except Exception as e:
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Compilation error: {e}")
            return False
            
    def run_symbolic_execution(self, model: RISCVSymbolicModel, 
                             targets: List[Tuple[int, int]]) -> List[Dict[str, Any]]:
        """Run symbolic execution to generate new test vectors"""
        test_vectors = []
        
        for start_addr, end_addr in targets:
            try:
                if config.SYMEXEC_DEBUG:
                    print(f"[SymExec] Running symbolic execution from 0x{start_addr:x} to 0x{end_addr:x}")
                
                # Setup initial state
                if not model.setup_initial_state(start_addr):
                    continue
                    
                # Create simulation manager
                simgr = model.project.factory.simgr(model.initial_state)
                
                # Set solver timeout
                model.initial_state.solver._solver.timeout = config.SYMEXEC_SOLVER_TIMEOUT * 1000  # Convert to ms
                
                # Run symbolic execution with constraints
                simgr.explore(
                    find=end_addr,
                    avoid=[],  # Add addresses to avoid if known
                    num_find=config.SYMEXEC_MAX_SOLUTIONS,
                    max_steps=config.SYMEXEC_MAX_STEPS
                )
                
                # Extract test vectors from found states
                for found_state in simgr.found:
                    test_vector = self._extract_test_vector(found_state)
                    if test_vector:
                        test_vectors.append(test_vector)
                        
                if config.SYMEXEC_DEBUG:
                    print(f"[SymExec] Found {len(simgr.found)} solutions for target 0x{start_addr:x}")
                
            except Exception as e:
                if config.SYMEXEC_DEBUG:
                    print(f"[SymExec] Error in symbolic execution: {e}")
                continue
                
        return test_vectors
        
    def _extract_test_vector(self, state) -> Optional[Dict[str, Any]]:
        """Extract concrete test vector from symbolic state"""
        try:
            test_vector = {
                'registers': {},
                'memory': {},
                'constraints': []
            }
            
            # Extract register values
            symbolic_regs = ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7']
            for reg_name in symbolic_regs:
                if hasattr(state.regs, reg_name):
                    reg_val = getattr(state.regs, reg_name)
                    if state.solver.symbolic(reg_val):
                        # Get concrete value
                        concrete_val = state.solver.eval(reg_val)
                        test_vector['registers'][reg_name] = concrete_val
                        
            return test_vector
            
        except Exception as e:
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Error extracting test vector: {e}")
            return None
            
    def generate_test_vectors(self, sim_input_data: Dict[str, Any], 
                            coverage_files: List[str]) -> SymbolicExecutionResult:
        """Main entry point for generating new test vectors"""
        start_time = time.time()
        
        if config.SYMEXEC_DEBUG:
            print("[SymExec] Starting symbolic execution for test vector generation")
        
        try:
            # Prepare symbolic model
            model = self.prepare_symbolic_model(sim_input_data)
            if not model:
                if config.SYMEXEC_DEBUG:
                    print("[SymExec] Failed to prepare symbolic model")
                return SymbolicExecutionResult(
                    success=False,
                    error_message="Failed to prepare symbolic model",
                    execution_time=time.time() - start_time
                )
                
            # Identify targets for symbolic execution
            targets = self.target_identifier.analyze_coverage_map(coverage_files)
            if not targets:
                if config.SYMEXEC_DEBUG:
                    print("[SymExec] No suitable targets found for symbolic execution")
                return SymbolicExecutionResult(
                    success=False,
                    error_message="No suitable targets found for symbolic execution",
                    execution_time=time.time() - start_time
                )
                
            # Run symbolic execution
            test_vectors = self.run_symbolic_execution(model, targets)
            
            execution_time = time.time() - start_time
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] Generated {len(test_vectors)} new test vectors in {execution_time:.2f}s")
                
            return SymbolicExecutionResult(
                success=True,
                test_vectors=test_vectors,
                execution_time=execution_time,
                targets_explored=len(targets),
                solutions_found=len(test_vectors)
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Symbolic execution failed: {str(e)}"
            if config.SYMEXEC_DEBUG:
                print(f"[SymExec] {error_msg}")
            return SymbolicExecutionResult(
                success=False,
                error_message=error_msg,
                execution_time=execution_time
            )


def create_symbolic_executor(toplevel: str, output_dir: str, debug: bool = False) -> SymbolicExecutor:
    """Factory function to create and configure symbolic executor"""
    return SymbolicExecutor(toplevel, output_dir, debug)


if __name__ == "__main__":
    # Example usage
    print("Symbolic Execution Engine for DifuzzRTL")
    print("This module should be imported and used with the fuzzer integration.")
