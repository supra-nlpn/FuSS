# FuSS - Fuzzing with Selective Symbolic Execution

FuSS (Fuzzing with Selective Symbolic Execution) integrates [angr](https://angr.io/)-based symbolic execution with the DifuzzRTL RTL-level RISC-V fuzzer to overcome coverage plateaus and improve test generation efficiency.

## Overview

FuSS provides a comprehensive framework that monitors DifuzzRTL's coverage progress and automatically triggers symbolic execution when coverage plateaus are detected. This hybrid approach combines the speed of mutation-based fuzzing with the precision of symbolic execution to achieve better coverage of complex hardware designs.

### Key Features

- **Automatic Plateau Detection**: Monitors fuzzer coverage and detects when progress stalls
- **RISC-V Symbolic Execution**: Uses angr to perform symbolic execution on RISC-V binaries
- **Test Vector Generation**: Generates new test vectors to explore uncovered code paths
- **Seamless Integration**: Works with existing DifuzzRTL corpus and workflow
- **Top-level Interface**: Single entry point for the entire framework
- **Automatic Virtual Environment**: All commands automatically use Python virtual environment
- **Python 3 Compatible**: All code runs with Python 3.6+
- **Realistic RTL Demo**: Includes `toyProcessor.v` - a complex RTL design for demonstration

## Project Structure

```
FuSS/
├── fuss.py                          # Main framework entry point
├── README.md                        # This file
├── difuzz-rtl/                      # DifuzzRTL fuzzer (submodule)
│   ├── Fuzzer/
│   ├── firrtl/
│   └── ...
└── symbolic_fuzzing/                # Symbolic execution integration
    ├── src/
    │   ├── symbolic_executor.py     # Core symbolic execution engine
    │   └── fuzzer_integration.py    # Integration with DifuzzRTL
    ├── config/
    │   └── symbolic_config.py       # Configuration management
    ├── scripts/
    │   ├── symbolic_fuzzing_main.py # Symbolic fuzzing interface
    │   ├── setup_venv.sh           # Virtual environment setup
    │   └── ...
    └── tests/
        └── test_symbolic_fuzzing.py # Test suite
```

## Quick Start

> **🔧 Automatic Virtual Environment**: All FuSS commands automatically use a Python virtual environment. You don't need to manually activate it - the framework handles this transparently!

### 1. Initial Setup (2 minutes)

```bash
# Clone the repository with submodules (or ensure you're in the FuSS directory)
git clone --recursive <repository-url> FuSS
cd FuSS

# Setup the symbolic execution system with virtual environment
./fuss setup

# Verify the installation
./fuss test
```

### 2. Check Framework Status

```bash
# Show current status of all components
./fuss status
```

### 3. Try the Demo

```bash
# Experience FuSS with a realistic RTL demo
./fuss demo
```

This creates a complete demo environment with:
- `toyProcessor.v` - A realistic RTL design with 14+ basic blocks
- RISC-V test cases targeting specific coverage scenarios  
- Coverage plateau simulation and symbolic execution breakthrough

**Note**: The demo creates the RTL design and shows framework capabilities. To run the actual RTL simulation, see the Interactive Demo section below.

### 4. Start Fuzzing

```bash
# Run integrated fuzzing with automatic symbolic execution
./fuss integrated \
  --workspace ./my_workspace \
  --target RocketTile \
  --start-fuzzer
```

## RTL Demo

The FuSS framework includes a comprehensive demo environment featuring a realistic RTL design that demonstrates the power of symbolic execution in RTL fuzzing.

### Demo RTL Design: `toyProcessor.v`

#### Architecture

The demo includes a realistic toy processor RTL design with the following characteristics:

- **Processor Type**: Simple state machine processor
- **Interface**: 32-bit data input, 4-bit flags, 5-bit state output
- **Complexity**: 14 distinct basic blocks (BB0-BB13 + BB_ERROR)
- **Purpose**: Demonstrates coverage plateau scenarios and symbolic execution benefits

#### Key Features

**1. Complex State Machine**
```verilog
module toyProcessor (
  input clk,
  input reset,
  input [31:0] data_in,
  input [3:0] flags,
  output reg [4:0] state 
);
```

**2. Hard-to-Reach States**
The design includes several challenging coverage scenarios:

- **Specific Data Pattern**: `data_in == 32'hAB` (BB2)
- **Complex Flag Dependencies**: Multiple nested flag conditions (BB3-BB5)
- **Very Specific Patterns**: `flags == 4'b1111` (BB5) 
- **Error Condition**: `state == S2 && data_in[15:8] == 8'hCD` (BB_ERROR)

**3. Coverage Challenge Areas**
```verilog
// Hard to reach without symbolic execution:
if (flags == 4'b1111) begin // BB5 - Very specific flag pattern
  state <= S2; // BB6 - Hard to reach state
end

// Error condition requiring precise state + data combination
if (state == S2 && data_in[15:8] == 8'hCD) begin
  error_flag <= 1; // BB_ERROR - Very specific error condition
end
```

### Demo Environment Structure

When you run `./fuss demo`, the following realistic environment is created:

```
symbolic_fuzzing_demo/
├── mock_difuzz_rtl/
│   ├── Fuzzer/
│   │   └── DifuzzRTL.py          # Mock fuzzer with coverage simulation
│   └── RTL/
│       └── toyProcessor.v        # Realistic RTL design
├── demo_workspace/
│   ├── corpus/
│   │   ├── test_000.S            # Basic RISC-V test
│   │   ├── test_001.S            # Target pattern test  
│   │   ├── test_002.S            # Complex flag test
│   │   ├── test_003.S            # Edge case test
│   │   ├── test_004.S            # Error condition test
│   │   └── *.bin                 # Compiled binaries
│   └── coverage/
│       └── avg_reached_mux.txt   # Coverage tracking
└── output/                       # Symbolic execution outputs
```

### RISC-V Test Cases

The demo includes realistic RISC-V assembly test cases designed to exercise the RTL:

**Test Case 1: Target Data Pattern**
```assembly
# Test case 1: Target data pattern 0xAB
.section .text
.global _start

_start:
    li x1, 0x000000AB    # Load target data pattern
    li x2, 0x00000001    # flags[0] = 1
    li x3, 0x00000000    # flags[1] = 0
    addi x4, x0, 15      # flags = 1111 (hard to reach)
    nop
```

**Test Case 2: Complex Flag Combinations**
```assembly
# Test case 2: Complex flag combinations
.section .text
.global _start

_start:
    li x1, 0x000000AB    # Target data
    li x2, 0x00000009    # flags = 1001
    li x3, 0x0000000F    # flags = 1111
    li x4, 0x0000CD00    # Upper bits for error condition
    nop
```

### Coverage Simulation

The mock DifuzzRTL demonstrates a realistic fuzzing scenario:

**Phase 1: Initial Coverage Growth (45% → 65%)**
- Random testing discovers basic paths
- Covers easily reachable states (BB0, BB1, BB12)
- Gradual progress to BB2-BB7

**Phase 2: Coverage Plateau (65% ± 2%)**
- Traditional fuzzing gets stuck
- Cannot find specific flag patterns
- Plateau detection triggers symbolic execution

**Phase 3: Symbolic Execution Breakthrough (65% → 95%)**
- Symbolic execution analyzes uncovered paths
- Generates precise inputs for hard-to-reach states
- Discovers error conditions and complex flag combinations

### Running the Demo

**Basic Demo (Framework Showcase)**
```bash
./fuss demo
```
This creates the demo environment, RTL design files, and demonstrates the framework's capabilities without running RTL simulation.

**Interactive Demo (RTL Simulation)**
```bash
# Run the demo first to create the environment
./fuss demo

# Explore the created environment
cd symbolic_fuzzing/symbolic_fuzzing_demo

# View the RTL design
cat mock_difuzz_rtl/RTL/toyProcessor.v

# Check test cases
ls demo_workspace/corpus/

# Run mock fuzzing simulation with coverage plateau demonstration
python3 -u symbolic_fuzzing/symbolic_fuzzing_demo/mock_difuzz_rtl/Fuzzer/DifuzzRTL.py

# Alternative: navigate to the fuzzer directory first
cd symbolic_fuzzing/symbolic_fuzzing_demo/mock_difuzz_rtl/Fuzzer
python3 -u DifuzzRTL.py

# Note: Use -u flag for unbuffered output to see real-time progress
```

### Demo Output Analysis

The demo shows realistic progression with the mock fuzzer. Note: Use `python3 -u` for unbuffered output to see real-time progress:

```
Iteration  1: Coverage = 48% (BB0, BB1, BB12 covered)
...
Iteration  8: Coverage = 65% (BB0-BB7, BB10-BB12 covered - PLATEAU DETECTED)
...
Iteration 15: Coverage = 66% (BB0-BB7, BB10-BB12 covered - PLATEAU DETECTED)
Iteration 16: Coverage = 70% (BB0-BB7, BB10-BB12 covered - PLATEAU DETECTED)
...
Iteration 20: Coverage = 86% (BB0-BB13 + BB_ERROR covered - SYMBOLIC EXECUTION SUCCESS)
```

### Key Insights Demonstrated

**1. Plateau Detection**
- Coverage stagnates around 65-66%
- Traditional fuzzing cannot find specific patterns
- Automatic detection triggers symbolic analysis

**2. Symbolic Execution Benefits**
- Precise constraint solving for complex conditions
- Discovery of error conditions requiring exact state/data combinations
- Breakthrough from 65% to 95% coverage

**3. Realistic RTL Challenges**
- Multi-level nested conditions
- State-dependent behavior
- Data pattern dependencies
- Flag combination requirements

### Extending the Demo

**Custom RTL Designs**
Replace `toyProcessor.v` with your own RTL design to test FuSS on real hardware:

```bash
# Copy your RTL design
cp your_design.v symbolic_fuzzing_demo/mock_difuzz_rtl/RTL/

# Update test cases for your design
# Modify corpus files in demo_workspace/corpus/
```

**Real Integration**
For production use, integrate with actual DifuzzRTL:

```bash
# Configure for real DifuzzRTL path
./fuss configure

# Set up integration
./fuss integrate --difuzz-path /path/to/difuzz-rtl --target your_design
```

The FuSS RTL demo provides a realistic environment showcasing how symbolic execution can break through coverage plateaus in RTL fuzzing. The `toyProcessor.v` design demonstrates common RTL verification challenges where traditional fuzzing struggles, making it an ideal testbed for symbolic execution research and development.

## Usage

### Framework Management

```bash
# Setup the system
./fuss setup

# Show status
./fuss status

# Run tests
./fuss test

# Run demo
./fuss demo
```

### Fuzzing Operations

```bash
# Integrated fuzzing with symbolic execution
./fuss integrated \
  --workspace ./workspace \
  --target RocketTile \
  --start-fuzzer \
  --interval 300

# Standalone symbolic execution
./fuss symbolic \
  --workspace ./workspace

# Coverage analysis
./fuss analyze \
  --workspace ./workspace
```

### Using Make (Alternative Interface)

```bash
# Setup and management
make setup
make status
make test
make demo

# Fuzzing operations
make integrated WORKSPACE=./workspace START_FUZZER=1
make symbolic WORKSPACE=./workspace
make analyze WORKSPACE=./workspace

# Advanced usage
make integrated WORKSPACE=./ws TARGET=RocketTile CONFIG=config.py VERBOSE=1
```

### Advanced Options

```bash
# Use custom configuration
./fuss integrated \
  --workspace ./workspace \
  --config my_config.py \
  --verbose

# Continue monitoring even if fuzzer dies
./fuss integrated \
  --workspace ./workspace \
  --start-fuzzer \
  --continue-without-fuzzer

# Different targets
./fuss integrated --workspace ./boom --target SmallBoomTile --start-fuzzer
./fuss integrated --workspace ./rocket --target RocketTile --start-fuzzer
```

## Installation Details

### Prerequisites

- **Python 3.6+** with pip
- **4GB+ RAM** recommended
- **Internet connection** for package downloads
- **DifuzzRTL** (included as submodule or placed in FuSS directory)

### Setup Process

The setup process:
1. Creates a Python virtual environment
2. Installs angr and all dependencies
3. Verifies the installation
4. Creates activation scripts

```bash
# Automatic setup with virtual environment
./fuss setup

# Manual setup without virtual environment
./fuss setup --no-venv
```

## Configuration Options

The system can be configured via the `symbolic_config.py` file or a custom configuration file. Key options include:

### Symbolic Execution Parameters

```python
# Timeout for symbolic execution (seconds)
ANGR_TIMEOUT = 300

# Maximum number of symbolic states to explore
MAX_SYMBOLIC_STATES = 1000

# Maximum exploration depth
MAX_EXPLORATION_DEPTH = 50
```

### Plateau Detection

```python
# Coverage improvement threshold to avoid plateau detection
PLATEAU_THRESHOLD = 5

# Number of iterations to consider for plateau detection
PLATEAU_WINDOW = 10
```

### Test Generation

```python
# Maximum new tests to generate per symbolic execution run
MAX_NEW_TESTS_PER_RUN = 10

# Maximum corpus files to use for symbolic execution
MAX_CORPUS_FILES = 5
```

### RISC-V Toolchain

```python
# Paths to RISC-V tools (auto-detected if in PATH)
RISCV_GCC = "riscv64-unknown-elf-gcc"
RISCV_OBJDUMP = "riscv64-unknown-elf-objdump"
RISCV_READELF = "riscv64-unknown-elf-readelf"
```

## How It Works

### 1. Coverage Monitoring

The system continuously monitors DifuzzRTL's coverage progress by:
- Reading coverage files (e.g., `avg_reached_mux.txt`)
- Parsing fuzzer logs for coverage information
- Tracking coverage history over time

### 2. Plateau Detection

A coverage plateau is detected when:
- Coverage improvement is below threshold for multiple iterations
- The plateau persists for a configurable window of time
- The fuzzer appears to be stuck in a local optimum

### 3. Symbolic Execution

When a plateau is detected:
1. Select interesting test cases from the current corpus
2. Compile test cases to RISC-V binaries
3. Run angr symbolic execution to explore new paths
4. Extract satisfying inputs that reach new code paths
5. Convert inputs back to RISC-V assembly test cases

### 4. Test Integration

New test vectors are:
- Converted to proper RISC-V assembly format
- Added to the fuzzer corpus
- Made available for further mutation and fuzzing

## Testing

Run the test suite to verify installation:

```bash
# Run basic functionality tests
python3 tests/test_symbolic_fuzzing.py --basic-tests

# Run unit tests
python3 tests/test_symbolic_fuzzing.py --unit-tests

# Run all tests
python3 tests/test_symbolic_fuzzing.py --all
```

## Example Workflows

### Continuous Fuzzing with Symbolic Assistance

```bash
# Start integrated fuzzing session
python3 scripts/symbolic_fuzzing_main.py integrated \
  --difuzz-rtl-path ./difuzz-rtl \
  --workspace ./workspace_rocket \
  --target RocketTile \
  --start-fuzzer \
  --interval 600 \
  --verbose
```

This will:
1. Start DifuzzRTL fuzzer targeting RocketTile
2. Monitor coverage every 10 minutes
3. Trigger symbolic execution when plateaus are detected
4. Generate new test vectors and integrate them into the corpus
5. Continue until stopped with Ctrl+C

### Batch Test Generation

```bash
# Generate tests for existing corpus
python3 scripts/symbolic_fuzzing_main.py symbolic \
  --difuzz-rtl-path ./difuzz-rtl \
  --workspace ./batch_generation \
  --config high_exploration_config.py
```

### Coverage Analysis

```bash
# Analyze current fuzzing progress
python3 scripts/symbolic_fuzzing_main.py analyze \
  --difuzz-rtl-path ./difuzz-rtl \
  --workspace ./workspace_rocket
```


### Debug Mode

Enable verbose logging for troubleshooting:

```bash
python3 scripts/symbolic_fuzzing_main.py integrated \
  --difuzz-rtl-path ./difuzz-rtl \
  --workspace ./workspace \
  --verbose
```

This provides detailed logs about:
- Coverage monitoring
- Plateau detection
- Symbolic execution progress
- Test generation and integration



## License

This project is licensed under the same terms as DifuzzRTL. See the DifuzzRTL repository for license details.

## References

- [DifuzzRTL](https://github.com/compsec-snu/difuzz-rtl): RTL-level RISC-V Fuzzer
- [angr](https://angr.io/): Binary analysis and symbolic execution framework
- [RISC-V ISA](https://riscv.org/): RISC-V Instruction Set Architecture
- [Symbolic Execution](https://en.wikipedia.org/wiki/Symbolic_execution): Overview of symbolic execution techniques


## Contact

For questions, open an issue or contact [supra.nlpn@gmail.com].