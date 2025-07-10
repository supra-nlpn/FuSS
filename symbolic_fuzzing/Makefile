# Makefile for DifuzzRTL Symbolic Fuzzing System

.PHONY: help setup setup-venv clean test demo verify lint format install-dev

# Default target
help:
	@echo "DifuzzRTL Symbolic Fuzzing System - Available Commands"
	@echo "====================================================="
	@echo
	@echo "Setup commands:"
	@echo "  setup-venv     - Create virtual environment and install dependencies"
	@echo "  setup          - Interactive setup (choose venv or system-wide)"
	@echo "  verify         - Verify installation works correctly"
	@echo
	@echo "Development commands:"
	@echo "  test           - Run all tests"
	@echo "  demo           - Run demonstration"
	@echo "  lint           - Run code linting (requires dev dependencies)"
	@echo "  format         - Format code with black (requires dev dependencies)"
	@echo "  install-dev    - Install development dependencies"
	@echo
	@echo "Cleanup commands:"
	@echo "  clean          - Remove virtual environment and generated files"
	@echo "  clean-cache    - Remove Python cache files"
	@echo
	@echo "Usage examples:"
	@echo "  make setup-venv    # Set up virtual environment"
	@echo "  make verify        # Check installation"
	@echo "  make demo          # Run demo"
	@echo

# Setup virtual environment
setup-venv:
	@echo "Setting up virtual environment..."
	./scripts/setup_venv.sh

# Interactive setup
setup:
	@echo "Running interactive setup..."
	./scripts/setup.sh

# Verify installation
verify:
	@echo "Verifying installation..."
	@if [ -f ./activate_venv.sh ]; then \
		echo "Using virtual environment..."; \
		bash -c "source ./activate_venv.sh && python scripts/verify_installation.py"; \
	else \
		echo "Using system Python..."; \
		python3 scripts/verify_installation.py; \
	fi

# Run tests
test:
	@echo "Running tests..."
	@if [ -f ./activate_venv.sh ]; then \
		bash -c "source ./activate_venv.sh && python tests/test_symbolic_fuzzing.py --all"; \
	else \
		python3 tests/test_symbolic_fuzzing.py --all; \
	fi

# Run demo
demo:
	@echo "Running demo..."
	@if [ -f ./activate_venv.sh ]; then \
		bash -c "source ./activate_venv.sh && python scripts/demo.py"; \
	else \
		python3 scripts/demo.py; \
	fi

# Install development dependencies
install-dev:
	@echo "Installing development dependencies..."
	@if [ -f ./activate_venv.sh ]; then \
		bash -c "source ./activate_venv.sh && pip install pytest pytest-cov black flake8 mypy"; \
	else \
		pip3 install --user pytest pytest-cov black flake8 mypy; \
	fi

# Lint code
lint: install-dev
	@echo "Running linting..."
	@if [ -f ./activate_venv.sh ]; then \
		bash -c "source ./activate_venv.sh && flake8 src/ tests/ scripts/ --max-line-length=100"; \
	else \
		python3 -m flake8 src/ tests/ scripts/ --max-line-length=100; \
	fi

# Format code
format: install-dev
	@echo "Formatting code..."
	@if [ -f ./activate_venv.sh ]; then \
		bash -c "source ./activate_venv.sh && black src/ tests/ scripts/ --line-length=100"; \
	else \
		python3 -m black src/ tests/ scripts/ --line-length=100; \
	fi

# Clean virtual environment and generated files
clean:
	@echo "Cleaning up..."
	rm -rf venv/
	rm -f activate_venv.sh
	rm -f test_installation.py
	rm -rf symbolic_fuzzing_demo/
	rm -rf __pycache__/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleanup completed"

# Clean Python cache files
clean-cache:
	@echo "Cleaning Python cache files..."
	rm -rf __pycache__/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Cache cleanup completed"

# Quick start command
quickstart: setup-venv verify demo
	@echo
	@echo "Quick start completed!"
	@echo "Next steps:"
	@echo "  1. Activate environment: source ./activate_venv.sh"
	@echo "  2. Run fuzzing: python scripts/symbolic_fuzzing_main.py --help"

# Show status
status:
	@echo "DifuzzRTL Symbolic Fuzzing System Status"
	@echo "======================================="
	@echo
	@if [ -d ./venv ]; then \
		echo "✓ Virtual environment: Present"; \
	else \
		echo "✗ Virtual environment: Not found"; \
	fi
	@if [ -f ./activate_venv.sh ]; then \
		echo "✓ Activation script: Present"; \
	else \
		echo "✗ Activation script: Not found"; \
	fi
	@echo "Python version: $(shell python3 --version)"
	@echo "Project root: $(shell pwd)"
	@echo
	@echo "Available scripts:"
	@ls -la scripts/
