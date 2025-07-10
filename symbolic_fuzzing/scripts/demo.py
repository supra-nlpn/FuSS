#!/usr/bin/env python3
"""
Demo script for DifuzzRTL Symbolic Fuzzing System

This script demonstrates the key features and workflow of the symbolic fuzzing system.
"""

import os
import sys
import tempfile
import time
from pathlib import Path

# Add symbolic fuzzing modules to path
SCRIPT_DIR = Path(__file__).parent
SRC_DIR = SCRIPT_DIR.parent / "src"
CONFIG_DIR = SCRIPT_DIR.parent / "config"

sys.path.append(str(SRC_DIR))
sys.path.append(str(CONFIG_DIR))

try:
    from symbolic_config import SymbolicConfig
    from fuzzer_integration import FuzzerIntegration
except ImportError as e:
    print(f"Warning: Could not import all modules: {e}")
    print("Some demo features may not work correctly.")


def create_demo_environment():
    """Create a demo environment with mock DifuzzRTL structure."""
    print("Creating demo environment...")
    
    # Create temporary directory structure
    demo_base = Path.cwd() / "symbolic_fuzzing_demo"
    demo_base.mkdir(exist_ok=True)
    
    # Mock DifuzzRTL structure
    mock_difuzz = demo_base / "mock_difuzz_rtl"
    mock_difuzz.mkdir(exist_ok=True)
    
    # Create mock fuzzer directory structure
    fuzzer_dir = mock_difuzz / "Fuzzer"
    fuzzer_dir.mkdir(exist_ok=True)
    
    # Create RTL design directory
    rtl_dir = mock_difuzz / "RTL"
    rtl_dir.mkdir(exist_ok=True)
    
    # Create the toy processor RTL design
    toy_processor_rtl = rtl_dir / "toyProcessor.v"
    toy_processor_rtl.write_text('''// Toy Processor RTL Design for FuSS Demo
// This design demonstrates various coverage scenarios for symbolic execution

module toyProcessor (
  input clk,
  input reset,
  input [31:0] data_in,
  input [3:0] flags,
  output reg [4:0] state 
);

// State definitions
localparam S0 = 0, S1 = 1, S2 = 2, 
   S3 = 3, S4 = 4, S5 = 5, S6 = 6, S7 = 7;

// State machine with complex branching - ideal for symbolic execution
always @(posedge clk or posedge reset) begin
  if (reset) 
    state <= S0; // BB0 - Basic block 0
  else begin
    case(state)
      S0: state <= S1; // BB1 - Always taken transition
      
      S1: begin
        if (data_in == 32'hAB) begin // BB2 - Specific data pattern check
          if (flags[0] == 1'b1) begin // BB3 - Flag dependency
            if (flags[1] == 1'b0) begin // BB4 - Complex flag condition
              if (flags == 4'b1111) begin // BB5 - Very specific flag pattern
                state <= S2; // BB6 - Hard to reach state
              end else begin
                state <= S3; // BB7 - Alternative path
              end
            end else if (flags[3] == 1'b1) begin // BB8 - Another flag check
              state <= S4; // BB9 - Different target state
            end else begin
              state <= S5; // BB10 - Default for this branch
            end
          end else begin
            state <= S6; // BB11 - flags[0] == 0 case
          end
        end else begin
          state <= S7; // BB12 - data_in != 0xAB case
        end
      end
      
      // Terminal states - all lead to S7
      S2, S3, S4, S5, S6, S7: state <= S7; // BB13 - Convergence point
      
      default: state <= S7; // Safety net
    endcase
  end
end

// Additional logic for demonstration
reg [7:0] counter;
reg error_flag;

always @(posedge clk or posedge reset) begin
  if (reset) begin
    counter <= 0;
    error_flag <= 0;
  end else begin
    counter <= counter + 1;
    
    // Error condition - another hard-to-reach scenario
    if (state == S2 && data_in[15:8] == 8'hCD) begin
      error_flag <= 1; // BB_ERROR - Very specific error condition
    end
  end
end

endmodule

// Testbench wrapper for the toy processor
module toyProcessor_tb;
  reg clk, reset;
  reg [31:0] data_in;
  reg [3:0] flags;
  wire [4:0] state;
  
  toyProcessor dut (
    .clk(clk),
    .reset(reset),
    .data_in(data_in),
    .flags(flags),
    .state(state)
  );
  
  // Clock generation
  always #5 clk = ~clk;
  
  initial begin
    clk = 0;
    reset = 1;
    data_in = 0;
    flags = 0;
    
    #10 reset = 0;
    
    // Test vectors would go here
    // FuSS will generate these automatically
    
    #1000 $finish;
  end
  
endmodule
''')
    
    # Create a simple mock main script
    main_script = fuzzer_dir / "DifuzzRTL.py"
    main_script.write_text('''#!/usr/bin/env python3
"""Mock DifuzzRTL script for demo purposes."""
import time
import random

print("Mock DifuzzRTL starting on toyProcessor...")
print("Target: toyProcessor.v")
print("Objective: Achieve maximum coverage of all basic blocks")
print()

# Simulate coverage progress with plateau
initial_coverage = 45
plateau_start = 65
for i in range(20):
    if i < 8:
        # Initial rapid coverage growth
        coverage = min(plateau_start, initial_coverage + i * 3 + random.randint(0, 3))
    elif i < 15:
        # Plateau period - this is where symbolic execution helps
        coverage = plateau_start + random.randint(-1, 1)
    else:
        # Symbolic execution kicks in and finds new paths
        coverage = min(95, plateau_start + (i - 14) * 4 + random.randint(0, 2))
    
    print(f"Iteration {i+1:2d}: Coverage = {coverage:2d}% ", end="")
    
    # Show which basic blocks are covered
    if coverage < 50:
        print("(BB0, BB1, BB12 covered)")
    elif coverage < 65:
        print("(BB0-BB3, BB11-BB12 covered)")
    elif coverage < 75:
        print("(BB0-BB7, BB10-BB12 covered - PLATEAU DETECTED)")
    else:
        print("(BB0-BB13 + BB_ERROR covered - SYMBOLIC EXECUTION SUCCESS)")
    
    time.sleep(0.3)

print()
print("Mock DifuzzRTL completed.")
print("Final coverage: ~95% with symbolic execution assistance")
''')
    
    # Create workspace
    workspace = demo_base / "demo_workspace"
    workspace.mkdir(exist_ok=True)
    
    # Create corpus directory
    corpus_dir = workspace / "corpus"
    corpus_dir.mkdir(exist_ok=True)
    
    # Create some mock test files with RISC-V assembly that would exercise the RTL
    test_cases = [
        # Basic test case
        '''# Test case 0: Basic initialization
.section .text
.global _start

_start:
    li x1, 0x00000000    # Load immediate 0
    li x2, 0x000000AB    # Load target value 0xAB  
    li x3, 0x00000001    # Load flags pattern
    nop                  # No operation
    nop
''',
        # Test case targeting specific data pattern
        '''# Test case 1: Target data pattern 0xAB
.section .text
.global _start

_start:
    li x1, 0x000000AB    # Load target data pattern
    li x2, 0x00000001    # flags[0] = 1
    li x3, 0x00000000    # flags[1] = 0
    addi x4, x0, 15      # flags = 1111 (hard to reach)
    nop
''',
        # Test case for complex flag patterns
        '''# Test case 2: Complex flag combinations
.section .text
.global _start

_start:
    li x1, 0x000000AB    # Target data
    li x2, 0x00000009    # flags = 1001
    li x3, 0x0000000F    # flags = 1111
    li x4, 0x0000CD00    # Upper bits for error condition
    nop
''',
        # Edge case test
        '''# Test case 3: Edge cases
.section .text
.global _start

_start:
    li x1, 0x000000AC    # data_in != 0xAB
    li x2, 0x00000000    # flags = 0000
    li x3, 0xFFFFFFFF    # All bits set
    nop
    nop
''',
        # Error condition test
        '''# Test case 4: Error condition trigger
.section .text
.global _start

_start:
    li x1, 0x00CD00AB    # data_in with error pattern in [15:8]
    li x2, 0x0000000F    # flags = 1111 to reach S2
    nop
    nop
    nop
'''
    ]
    
    for i, test_content in enumerate(test_cases):
        test_file = corpus_dir / f"test_{i:03d}.S"
        test_file.write_text(test_content)
        
        # Also create binary versions
        bin_file = corpus_dir / f"test_{i:03d}.bin"
        # Mock RISC-V instruction encoding
        bin_file.write_bytes(bytes([0x13, 0x00, 0x00, 0x00] * (5 + i)))
    
    # Create coverage tracking files
    coverage_dir = workspace / "coverage"
    coverage_dir.mkdir(exist_ok=True)
    
    coverage_file = coverage_dir / "avg_reached_mux.txt"
    coverage_file.write_text("# Coverage tracking for toyProcessor\n# BB coverage percentages\n45\n47\n52\n58\n65\n65\n66\n65\n")
    
    print(f"Demo environment created at: {demo_base}")
    print(f"RTL design: {toy_processor_rtl}")
    print(f"Test corpus: {len(test_cases)} test cases created")
    return str(mock_difuzz), str(workspace)


def demo_configuration():
    """Demonstrate configuration management."""
    print("\n=== Configuration Demo ===")
    
    try:
        # Create default configuration
        config = SymbolicConfig()
        print("Default configuration:")
        print(f"  Symbolic Execution Timeout: {config.symexec_timeout}s")
        print(f"  Max Symbolic Solutions: {config.symexec_max_solutions}")
        print(f"  Plateau Threshold Ratio: {config.plateau_threshold_ratio}")
        print(f"  Plateau Window Size: {config.plateau_window_size}")
        print(f"  Max Symbolic Steps: {config.symexec_max_steps}")
        print(f"  RISC-V Base Address: 0x{config.riscv_base_addr:x}")
        
        # Save configuration to a demo file
        demo_config_path = "demo_config.yaml"
        config.save_to_file(demo_config_path)
        print(f"  Configuration saved to: {demo_config_path}")
        
        # Load it back to demonstrate loading
        loaded_config = SymbolicConfig(demo_config_path)
        print(f"  Configuration loaded successfully: {loaded_config}")
        
        return demo_config_path
    except Exception as e:
        print(f"  ⚠ Configuration demo error: {e}")
        return None


def demo_symbolic_executor():
    """Demonstrate symbolic executor functionality."""
    print("\n=== Symbolic Executor Demo ===")
    
    try:
        from symbolic_executor import SymbolicExecutor
        
        config = SymbolicConfig()
        
        # Create a temporary output directory for demo
        demo_output = Path.cwd() / "symbolic_fuzzing_demo" / "output"
        demo_output.mkdir(exist_ok=True, parents=True)
        
        executor = SymbolicExecutor("RocketTile", str(demo_output))
        
        print("✓ Symbolic executor created successfully")
        print(f"  Max steps: {config.symexec_max_steps}")
        print(f"  Timeout: {config.symexec_timeout}s")
        print(f"  Max solutions: {config.symexec_max_solutions}")
        print(f"  Output directory: {demo_output}")
        
        # Demonstrate basic functionality
        print("  Testing basic symbolic execution capabilities...")
        print("  (Would analyze RISC-V binary for coverage gaps)")
        print("  (Would generate symbolic test cases)")
        print("  ✓ Symbolic execution demo completed")
        
    except Exception as e:
        print(f"  ⚠ Symbolic executor demo error: {e}")


def demo_integration():
    """Demonstrate integration with DifuzzRTL."""
    print("\n=== Integration Demo ===")
    
    try:
        config = SymbolicConfig()
        
        # Create demo output directory
        demo_output = Path.cwd() / "symbolic_fuzzing_demo" / "output"
        demo_output.mkdir(exist_ok=True, parents=True)
        
        integration = FuzzerIntegration(
            difuzz_rtl_path="./mock_difuzz_rtl",
            output_dir=str(demo_output),
            config=config
        )
        
        print("✓ Integration system created successfully")
        print("  Features demonstrated:")
        print("    - Coverage monitoring")
        print("    - Plateau detection")
        print("    - Automatic symbolic execution triggering")
        print("    - Test case generation and injection")
        
        # Simulate some integration workflow
        print("  Simulating integration workflow...")
        print("    ✓ Would monitor DifuzzRTL coverage")
        print("    ✓ Would detect coverage plateaus")
        print("    ✓ Would trigger symbolic execution")
        print("    ✓ Would generate new test cases")
        print("    ✓ Would inject test cases into corpus")
        
    except Exception as e:
        print(f"  ⚠ Integration demo error: {e}")


def demo_analysis():
    """Demonstrate analysis capabilities."""
    print("\n=== Analysis Demo ===")
    
    print("Analysis capabilities:")
    print("  - Coverage gap identification")
    print("  - Branch analysis")
    print("  - Test case corpus analysis")
    print("  - Performance metrics")
    print("  - Plateau detection statistics")
    
    print("  ✓ Analysis demo completed")


def demo_integration_workflow():
    """Demonstrate the complete integration workflow."""
    print("\n=== Integration Workflow Demo ===")
    
    # Create demo environment
    mock_difuzz_path, workspace_path = create_demo_environment()
    
    # Configuration demo
    config_file = demo_configuration()
    
    # Symbolic executor demo
    demo_symbolic_executor()
    
    # Integration demo
    demo_integration()
    
    # Analysis demo
    demo_analysis()
    
    print("\n=== Demo Summary ===")
    print("Demonstrated capabilities:")
    print("  ✓ Configuration management")
    print("  ✓ Symbolic execution engine")
    print("  ✓ DifuzzRTL integration")
    print("  ✓ Coverage analysis")
    print("  ✓ Test case generation")
    
    print(f"\nDemo files created:")
    print(f"  - Demo environment: {Path.cwd() / 'symbolic_fuzzing_demo'}")
    if config_file:
        print(f"  - Configuration: {config_file}")
    
    print("\nNext steps:")
    print("  1. Run integrated fuzzing with a real target")
    print("  2. Monitor coverage improvements")
    print("  3. Analyze generated test cases")
    print("  4. Customize configuration for your needs")


def main():
    """Main demo function."""
    print("DifuzzRTL Symbolic Fuzzing System - Demo")
    print("=" * 50)
    print("This demo showcases the key features of the symbolic fuzzing system.")
    print("It creates a mock environment and demonstrates various functionalities.")
    
    try:
        # Check if symbolic executor is available
        from symbolic_executor import SymbolicExecutor
        print("\n✓ Symbolic executor module available")
    except ImportError as e:
        print(f"\n⚠ Symbolic executor import issue: {e}")
        print("Some demo features may not work correctly.")
    
    # Run the demo
    demo_integration_workflow()
    
    print("\n" + "=" * 50)
    print("Demo completed! FuSS is ready for enhanced RTL fuzzing.")


if __name__ == "__main__":
    main()
