# Getting Started with FuSS

Welcome to FuSS (Fuzzing with Selective Symbolic Execution)! This guide will get you up and running quickly.

## Common Issues

1. **"angr not found"**: The setup will install this automatically in the virtual environment
2. **Permission errors**: Make sure `fuss` and `fuss.py` are executable (`chmod +x fuss fuss.py`)
3. **DifuzzRTL not found**: Ensure difuzz-rtl is in the FuSS directory
4. **Python version**: Python 3.6+ is required
5. **Virtual environment**: All commands automatically use the venv - no manual activation needed!

Enjoy enhanced RTL fuzzing with FuSS! 🚀p and running in just a few minutes.

> **🔧 Automatic Virtual Environment**: All FuSS commands automatically use a Python virtual environment. You don't need to manually activate it!

## What is FuSS?

FuSS enhances the DifuzzRTL RTL fuzzer by automatically detecting coverage plateaus and using symbolic execution to generate new test vectors. This helps overcome situations where traditional mutation-based fuzzing gets stuck.

## Quick Setup (2 minutes)

1. **Setup the framework:**
   ```bash
   ./fuss setup
   ```

2. **Check everything is working:**
   ```bash
   ./fuss status
   ./fuss test
   ```

3. **Try the demo:**
   ```bash
   ./fuss demo
   ```

That's it! FuSS is now ready to use.

## Your First Fuzzing Session (3 minutes)

Start integrated fuzzing that automatically combines DifuzzRTL with symbolic execution:

```bash
./fuss integrated \
  --workspace ./my_first_run \
  --target RocketTile \
  --start-fuzzer
```

This will:
- Create a workspace directory
- Start the DifuzzRTL fuzzer targeting RocketTile
- Monitor coverage progress
- Automatically trigger symbolic execution when plateaus are detected
- Generate new test vectors to improve coverage

## Available Commands

### Framework Management
```bash
./fuss setup     # Setup the system
./fuss status    # Show status
./fuss test      # Run tests
./fuss demo      # Run demo
```

### Fuzzing Operations
```bash
# Integrated fuzzing (recommended)
./fuss integrated --workspace ./ws --start-fuzzer

# Standalone symbolic execution
./fuss symbolic --workspace ./ws

# Coverage analysis
./fuss analyze --workspace ./ws
```

## Using Make (Alternative)

If you prefer using make:

```bash
make setup                                    # Setup
make status                                   # Status
make integrated WORKSPACE=./ws START_FUZZER=1 # Fuzzing
make help                                     # Show all options
```

## Next Steps

- **Read the full README.md** for detailed documentation
- **Customize configuration** for your specific needs
- **Analyze results** to understand coverage improvements
- **Scale up** to longer fuzzing campaigns

## Need Help?

- Run `./fuss --help` for command options
- Check `make help` for make-based usage
- See README.md for comprehensive documentation
- Run the demo to see all features in action

## Common Issues

1. **"angr not found"**: The setup will install this automatically
2. **Permission errors**: Make sure `fuss.py` is executable (`chmod +x fuss.py`)
3. **DifuzzRTL not found**: Ensure difuzz-rtl is in the FuSS directory
4. **Python version**: Python 3.6+ is required

Enjoy enhanced RTL processor fuzzing with FuSS! 
