"""
DifuzzRTL Symbolic Fuzzing System

This package provides symbolic execution integration for the DifuzzRTL RTL-level
RISC-V fuzzer. It includes tools for coverage monitoring, plateau detection,
and symbolic test vector generation.

Main modules:
- symbolic_executor: Core symbolic execution engine using angr
- fuzzer_integration: Integration layer with DifuzzRTL
- symbolic_config: Configuration management

Example usage:
    from symbolic_fuzzing.src.symbolic_executor import SymbolicExecutor
    from symbolic_fuzzing.config.symbolic_config import SymbolicConfig
    
    config = SymbolicConfig()
    executor = SymbolicExecutor(config)
"""

__version__ = "1.0.0"
__author__ = "DifuzzRTL Symbolic Fuzzing Team"

from .symbolic_executor import SymbolicExecutor, SymbolicExecutionResult
from .fuzzer_integration import FuzzerIntegration

__all__ = [
    'SymbolicExecutor',
    'SymbolicExecutionResult', 
    'FuzzerIntegration'
]
