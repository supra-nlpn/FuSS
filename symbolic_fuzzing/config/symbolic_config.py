#!/usr/bin/env python3
"""
Configuration management for Symbolic Execution Integration with DifuzzRTL
"""

import os
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional


class SymbolicConfig:
    """Configuration management for symbolic execution system."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration with default values and optional config file."""
        # Default configuration values
        self.plateau_window_size = 100
        self.plateau_threshold_ratio = 0.05
        self.plateau_min_iterations = 50
        
        self.symexec_max_steps = 1000
        self.symexec_max_solutions = 5
        self.symexec_timeout = 300
        self.symexec_max_targets = 10
        self.symexec_min_gap_size = 5
        
        self.target_branch_instructions = [
            'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu',
            'jal', 'jalr', 'beqz', 'bnez', 'bgtz', 'bltz'
        ]
        
        self.riscv_base_addr = 0x80000000
        self.riscv_instruction_size = 4
        self.riscv_register_size = 64
        
        self.symexec_periodic_interval = 1000
        
        # Load configuration from file if provided
        if config_file:
            self.load_from_file(config_file)
    
    def load_from_file(self, config_file: str) -> None:
        """Load configuration from YAML file."""
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Update configuration values
            if config_data:
                self._update_from_dict(config_data)
        except Exception as e:
            raise ValueError(f"Error loading configuration from {config_file}: {e}")
    
    def _update_from_dict(self, config_dict: Dict[str, Any]) -> None:
        """Update configuration from dictionary."""
        # Plateau detection parameters
        plateau = config_dict.get('plateau', {})
        self.plateau_window_size = plateau.get('window_size', self.plateau_window_size)
        self.plateau_threshold_ratio = plateau.get('threshold_ratio', self.plateau_threshold_ratio)
        self.plateau_min_iterations = plateau.get('min_iterations', self.plateau_min_iterations)
        
        # Symbolic execution parameters
        symexec = config_dict.get('symbolic_execution', {})
        self.symexec_max_steps = symexec.get('max_steps', self.symexec_max_steps)
        self.symexec_max_solutions = symexec.get('max_solutions', self.symexec_max_solutions)
        self.symexec_timeout = symexec.get('timeout', self.symexec_timeout)
        self.symexec_max_targets = symexec.get('max_targets', self.symexec_max_targets)
        self.symexec_min_gap_size = symexec.get('min_gap_size', self.symexec_min_gap_size)
        self.symexec_periodic_interval = symexec.get('periodic_interval', self.symexec_periodic_interval)
        
        # Target identification parameters
        targets = config_dict.get('targets', {})
        self.target_branch_instructions = targets.get('branch_instructions', self.target_branch_instructions)
        
        # RISC-V architecture parameters
        riscv = config_dict.get('riscv', {})
        self.riscv_base_addr = riscv.get('base_addr', self.riscv_base_addr)
        self.riscv_instruction_size = riscv.get('instruction_size', self.riscv_instruction_size)
        self.riscv_register_size = riscv.get('register_size', self.riscv_register_size)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'plateau': {
                'window_size': self.plateau_window_size,
                'threshold_ratio': self.plateau_threshold_ratio,
                'min_iterations': self.plateau_min_iterations,
            },
            'symbolic_execution': {
                'max_steps': self.symexec_max_steps,
                'max_solutions': self.symexec_max_solutions,
                'timeout': self.symexec_timeout,
                'max_targets': self.symexec_max_targets,
                'min_gap_size': self.symexec_min_gap_size,
                'periodic_interval': self.symexec_periodic_interval,
            },
            'targets': {
                'branch_instructions': self.target_branch_instructions,
            },
            'riscv': {
                'base_addr': self.riscv_base_addr,
                'instruction_size': self.riscv_instruction_size,
                'register_size': self.riscv_register_size,
            }
        }
    
    def save_to_file(self, config_file: str) -> None:
        """Save configuration to YAML file."""
        config_path = Path(config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, indent=2)
    
    def __str__(self) -> str:
        """String representation of configuration."""
        return f"SymbolicConfig(plateau_window={self.plateau_window_size}, " \
               f"symexec_timeout={self.symexec_timeout}, " \
               f"max_targets={self.symexec_max_targets})"


# Backward compatibility - maintain the original constants
PLATEAU_WINDOW_SIZE = 100
PLATEAU_THRESHOLD_RATIO = 0.05
PLATEAU_MIN_ITERATIONS = 50

SYMEXEC_MAX_STEPS = 1000
SYMEXEC_MAX_SOLUTIONS = 5
SYMEXEC_TIMEOUT = 300
SYMEXEC_MAX_TARGETS = 10
SYMEXEC_MIN_GAP_SIZE = 5

TARGET_BRANCH_INSTRUCTIONS = [
    'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu',
    'jal', 'jalr', 'beqz', 'bnez', 'bgtz', 'bltz'
]

RISCV_BASE_ADDR = 0x80000000
RISCV_INSTRUCTION_SIZE = 4
RISCV_REGISTER_SIZE = 64

SYMEXEC_PERIODIC_INTERVAL = 1000
SYMEXEC_PLATEAU_COOLDOWN = 500      # Minimum iterations between plateau-triggered runs

# File and directory settings
SYMEXEC_TEMP_DIR = 'symbolic_temp'  # Temporary directory for symbolic execution
SYMEXEC_LOG_FILE = 'symbolic_execution.log'

# Compiler settings for RISC-V
RISCV_COMPILER = 'riscv64-unknown-elf-gcc'
RISCV_LINKER_SCRIPT = 'riscv.ld'
RISCV_COMPILE_FLAGS = [
    '-nostdlib',
    '-static',
    '-mcmodel=medany',
    '-fno-common',
    '-fno-builtin-printf',
    '-fno-tree-loop-distribute-patterns'
]

# angr options
ANGR_OPTIONS = {
    'SYMBOL_FILL_UNCONSTRAINED_MEMORY': True,
    'SYMBOL_FILL_UNCONSTRAINED_REGISTERS': True,
    'LAZY_SOLVES': True,
    'TRACK_JMP_ACTIONS': False,
    'TRACK_MEMORY_ACTIONS': False,
    'TRACK_REGISTER_ACTIONS': False,
    'STRICT_PAGE_ACCESS': False,
    'ENABLE_NX': False,
    'ZERO_FILL_UNCONSTRAINED_MEMORY': False,
    'ZERO_FILL_UNCONSTRAINED_REGISTERS': False
}

# Debug and logging settings
SYMEXEC_DEBUG = True
SYMEXEC_VERBOSE_LOGGING = False
SYMEXEC_SAVE_INTERMEDIATE_RESULTS = True

# Performance tuning
SYMEXEC_MEMORY_LIMIT_MB = 2048      # Memory limit for symbolic execution
SYMEXEC_SOLVER_TIMEOUT = 30         # Solver timeout in seconds
