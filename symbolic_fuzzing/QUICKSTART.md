# Quick Start Guide - DifuzzRTL Symbolic Fuzzing

This guide will get you up and running with the DifuzzRTL Symbolic Fuzzing System in under 10 minutes.

## Prerequisites

- Python 3.6 or later
- DifuzzRTL fuzzer (as a submodule or in adjacent directory)
- 4GB+ RAM recommended

# Quick Start Guide - DifuzzRTL Symbolic Fuzzing

This guide will get you up and running with the DifuzzRTL Symbolic Fuzzing System in under 10 minutes.

## Prerequisites

- Python 3.6 or later
- DifuzzRTL fuzzer (as a submodule or in adjacent directory)
- 4GB+ RAM recommended
- Internet connection for package downloads

## Installation (3 minutes)

### Option A: Virtual Environment (Recommended)

1. **Create and setup virtual environment:**
```bash
cd symbolic_fuzzing
./scripts/setup_venv.sh
```

2. **Activate the virtual environment:**
```bash
source ./activate_venv.sh
```

3. **Verify installation:**
```bash
python scripts/verify_installation.py
```

### Option B: System-wide Installation

1. **Run the setup script:**
```bash
cd symbolic_fuzzing
./scripts/setup.sh
```

2. **Verify installation:**
```bash
python3 tests/test_symbolic_fuzzing.py --basic-tests
```

## First Run (3 minutes)

### Option A: Try the Demo (Recommended for first-time users)

```bash
# Make sure virtual environment is activated
source ./activate_venv.sh

# Run the demo
python scripts/demo.py
```

This creates a mock environment and demonstrates all features without needing a real DifuzzRTL setup.

### Option B: Real Integration

If you have DifuzzRTL ready:

```bash
# Activate virtual environment
source ./activate_venv.sh

# Run integrated fuzzing
python scripts/symbolic_fuzzing_main.py integrated \
  --difuzz-rtl-path ../difuzz-rtl \
  --workspace ./my_workspace \
  --target RocketTile \
  --start-fuzzer
```

## Quick Commands

All commands assume the virtual environment is activated (`source ./activate_venv.sh`)

### Generate Test Vectors
```bash
python scripts/symbolic_fuzzing_main.py symbolic \
  --difuzz-rtl-path ../difuzz-rtl \
  --workspace ./workspace
```

### Monitor Existing Fuzzer
```bash
python scripts/symbolic_fuzzing_main.py integrated \
  --difuzz-rtl-path ../difuzz-rtl \
  --workspace ./workspace \
  --interval 300
```

### Analyze Coverage
```bash
python scripts/symbolic_fuzzing_main.py analyze \
  --difuzz-rtl-path ../difuzz-rtl \
  --workspace ./workspace
```

## Customize Configuration

Create your config file:
```bash
python tests/test_symbolic_fuzzing.py --create-example-config my_config.py
```

Edit `my_config.py` as needed, then use:
```bash
python scripts/symbolic_fuzzing_main.py integrated \
  --config my_config.py \
  --difuzz-rtl-path ../difuzz-rtl \
  --workspace ./workspace
```

## Virtual Environment Management

### Activate environment:
```bash
source ./activate_venv.sh
```

### Deactivate environment:
```bash
deactivate
```

### Reinstall/Update packages:
```bash
# Activate environment first
source ./activate_venv.sh

# Update packages
pip install --upgrade -r requirements.txt
```

### Remove environment:
```bash
rm -rf venv activate_venv.sh test_installation.py
```

## Need Help?

- **Read the full README.md** for detailed documentation
- **Run the demo** to see all features in action
- **Check test output** for installation issues
- **Use `--help`** with any command for options

## Common First-Time Issues

1. **"angr not found"**: Run `pip3 install angr`
2. **Permission errors**: Run `chmod +x scripts/*.py`
3. **No coverage data**: Ensure DifuzzRTL is running and writing coverage files
4. **Slow symbolic execution**: Reduce `ANGR_TIMEOUT` in config

That's it! You should now have a working symbolic fuzzing system integrated with DifuzzRTL.
