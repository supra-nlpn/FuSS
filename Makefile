# Makefile for FuSS (Fuzzing with Selective Symbolic Execution) Framework

.PHONY: help setup status test demo clean clean-all integrated symbolic analyze

# Default target
help:
	@echo "FuSS - Fuzzing with Selective Symbolic Execution Framework"
	@echo "=============================================="
	@echo
	@echo "Framework Management:"
	@echo "  setup              - Setup the symbolic execution system"
	@echo "  status             - Show framework status"
	@echo "  test               - Run test suite"
	@echo "  demo               - Run demonstration"
	@echo
	@echo "Fuzzing Operations:"
	@echo "  integrated         - Run integrated fuzzing (requires WORKSPACE=dir)"
	@echo "  symbolic           - Run standalone symbolic execution (requires WORKSPACE=dir)"
	@echo "  analyze            - Analyze coverage (requires WORKSPACE=dir)"
	@echo
	@echo "Cleanup:"
	@echo "  clean              - Clean symbolic fuzzing artifacts"
	@echo "  clean-all          - Clean everything including virtual environment"
	@echo
	@echo "Usage Examples:"
	@echo "  make setup                                    # Initial setup"
	@echo "  make integrated WORKSPACE=./my_workspace     # Start fuzzing"
	@echo "  make symbolic WORKSPACE=./my_workspace       # Generate tests"
	@echo "  make analyze WORKSPACE=./my_workspace        # Analyze coverage"
	@echo
	@echo "Advanced Options:"
	@echo "  TARGET=RocketTile          # Set target design"
	@echo "  CONFIG=config.py           # Use custom config"
	@echo "  START_FUZZER=1             # Auto-start DifuzzRTL"
	@echo "  VERBOSE=1                  # Enable verbose output"
	@echo

# Framework management targets
setup:
	@echo "Setting up FuSS framework..."
	./fuss setup

status:
	@echo "Checking FuSS framework status..."
	./fuss status

test:
	@echo "Running FuSS test suite..."
	./fuss test

demo:
	@echo "Running FuSS demonstration..."
	./fuss demo

# Fuzzing operation targets
integrated:
	@if [ -z "$(WORKSPACE)" ]; then \
		echo "Error: WORKSPACE variable is required"; \
		echo "Usage: make integrated WORKSPACE=./my_workspace"; \
		exit 1; \
	fi
	@echo "Running integrated fuzzing..."
	@cmd="./fuss integrated --workspace $(WORKSPACE)"; \
	if [ -n "$(TARGET)" ]; then cmd="$$cmd --target $(TARGET)"; fi; \
	if [ -n "$(CONFIG)" ]; then cmd="$$cmd --config $(CONFIG)"; fi; \
	if [ "$(START_FUZZER)" = "1" ]; then cmd="$$cmd --start-fuzzer"; fi; \
	if [ "$(VERBOSE)" = "1" ]; then cmd="$$cmd --verbose"; fi; \
	echo "Running: $$cmd"; \
	$$cmd

symbolic:
	@if [ -z "$(WORKSPACE)" ]; then \
		echo "Error: WORKSPACE variable is required"; \
		echo "Usage: make symbolic WORKSPACE=./my_workspace"; \
		exit 1; \
	fi
	@echo "Running standalone symbolic execution..."
	@cmd="./fuss symbolic --workspace $(WORKSPACE)"; \
	if [ -n "$(CONFIG)" ]; then cmd="$$cmd --config $(CONFIG)"; fi; \
	if [ "$(VERBOSE)" = "1" ]; then cmd="$$cmd --verbose"; fi; \
	echo "Running: $$cmd"; \
	$$cmd

analyze:
	@if [ -z "$(WORKSPACE)" ]; then \
		echo "Error: WORKSPACE variable is required"; \
		echo "Usage: make analyze WORKSPACE=./my_workspace"; \
		exit 1; \
	fi
	@echo "Running coverage analysis..."
	@cmd="./fuss analyze --workspace $(WORKSPACE)"; \
	if [ -n "$(CONFIG)" ]; then cmd="$$cmd --config $(CONFIG)"; fi; \
	if [ "$(VERBOSE)" = "1" ]; then cmd="$$cmd --verbose"; fi; \
	echo "Running: $$cmd"; \
	$$cmd

# Cleanup targets
clean:
	@echo "Cleaning symbolic fuzzing artifacts..."
	@cd symbolic_fuzzing && make clean-cache 2>/dev/null || true
	@rm -rf symbolic_fuzzing_demo/
	@echo "Cleanup completed"

clean-all: clean
	@echo "Cleaning everything including virtual environment..."
	@cd symbolic_fuzzing && make clean 2>/dev/null || true
	@echo "Complete cleanup finished"

# Quick start target
quickstart: setup test demo
	@echo
	@echo "FuSS framework is ready!"
	@echo "Next steps:"
	@echo "  make integrated WORKSPACE=./workspace START_FUZZER=1"

# Development targets
format:
	@echo "Formatting code..."
	@cd symbolic_fuzzing && make format 2>/dev/null || echo "Formatting tools not available"

lint:
	@echo "Linting code..."
	@cd symbolic_fuzzing && make lint 2>/dev/null || echo "Linting tools not available"

# Show example commands
examples:
	@echo "FuSS Framework Usage Examples"
	@echo "============================="
	@echo
	@echo "Basic Setup:"
	@echo "  make setup                    # Initial setup"
	@echo "  make status                   # Check status"
	@echo "  make test                     # Verify installation"
	@echo
	@echo "Running Fuzzing:"
	@echo "  make integrated WORKSPACE=./rocket_ws TARGET=RocketTile START_FUZZER=1"
	@echo "  make symbolic WORKSPACE=./boom_ws"
	@echo "  make analyze WORKSPACE=./rocket_ws VERBOSE=1"
	@echo
	@echo "With Custom Configuration:"
	@echo "  make integrated WORKSPACE=./ws CONFIG=my_config.py START_FUZZER=1"
	@echo
	@echo "Multiple Targets:"
	@echo "  make integrated WORKSPACE=./rocket TARGET=RocketTile START_FUZZER=1"
	@echo "  make integrated WORKSPACE=./boom TARGET=SmallBoomTile START_FUZZER=1"
	@echo
	@echo "Development:"
	@echo "  make clean                    # Clean artifacts"
	@echo "  make clean-all                # Clean everything"
	@echo "  make format                   # Format code"
