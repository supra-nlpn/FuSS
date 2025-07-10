#!/bin/bash
# Setup script for DifuzzRTL Symbolic Fuzzing System

set -e

echo "Setting up DifuzzRTL Symbolic Fuzzing System..."
echo "This script will create a virtual environment and install all dependencies."
echo

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Project root: $PROJECT_ROOT"

# Check if we're in the right directory
if [ ! -f "$PROJECT_ROOT/src/symbolic_executor.py" ]; then
    echo "Error: symbolic_executor.py not found. Are you running this from the symbolic_fuzzing directory?"
    exit 1
fi

echo "Choose installation method:"
echo "1. Virtual environment (recommended) - isolated, clean installation"
echo "2. System-wide installation - installs packages globally"
echo -n "Enter choice [1-2]: "
read -r choice

case $choice in
    1)
        echo "Setting up virtual environment..."
        "$SCRIPT_DIR/setup_venv.sh"
        echo
        echo "Virtual environment setup completed!"
        echo "To activate: source ./activate_venv.sh"
        exit 0
        ;;
    2)
        echo "Proceeding with system-wide installation..."
        ;;
    *)
        echo "Invalid choice. Using virtual environment (default)..."
        "$SCRIPT_DIR/setup_venv.sh"
        exit 0
        ;;
esac

# System-wide installation (original approach)
echo "Checking Python version..."
python3 --version

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 not found. Please install pip for Python 3."
    exit 1
fi

# Install required packages
echo "Installing required Python packages globally..."
pip3 install --user -r "$PROJECT_ROOT/requirements.txt"

# Check if angr is installed correctly
echo "Verifying angr installation..."
python3 -c "import angr; print(f'angr version: {angr.__version__}')" || {
    echo "Error: angr not properly installed"
    exit 1
}

# Setup RISC-V toolchain check
echo "Checking RISC-V toolchain..."
if command -v riscv64-unknown-elf-gcc &> /dev/null; then
    echo "RISC-V GCC found: $(riscv64-unknown-elf-gcc --version | head -n1)"
else
    echo "Warning: RISC-V GCC not found. You may need to install the RISC-V toolchain."
    echo "See: https://github.com/riscv-collab/riscv-gnu-toolchain"
fi

# Make scripts executable
echo "Making scripts executable..."
chmod +x "$PROJECT_ROOT/scripts/symbolic_fuzzing_main.py"
chmod +x "$PROJECT_ROOT/scripts/setup.sh"

# Create symbolic link for easy access
SYMLINK_PATH="$HOME/.local/bin/symbolic-fuzzing"
if [ -d "$HOME/.local/bin" ]; then
    echo "Creating symbolic link: $SYMLINK_PATH"
    ln -sf "$PROJECT_ROOT/scripts/symbolic_fuzzing_main.py" "$SYMLINK_PATH"
    echo "You can now run 'symbolic-fuzzing' from anywhere (ensure ~/.local/bin is in your PATH)"
fi

echo ""
echo "Setup completed successfully!"
echo ""
echo "Usage examples:"
echo "  # Run integrated fuzzing:"
echo "  python3 $PROJECT_ROOT/scripts/symbolic_fuzzing_main.py integrated \\"
echo "    --difuzz-rtl-path ./difuzz-rtl \\"
echo "    --workspace ./workspace \\"
echo "    --start-fuzzer"
echo ""
echo "  # Run standalone symbolic execution:"
echo "  python3 $PROJECT_ROOT/scripts/symbolic_fuzzing_main.py symbolic \\"
echo "    --difuzz-rtl-path ./difuzz-rtl \\"
echo "    --workspace ./workspace"
echo ""
echo "For more options, run:"
echo "  python3 $PROJECT_ROOT/scripts/symbolic_fuzzing_main.py --help"
