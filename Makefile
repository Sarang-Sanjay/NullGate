# ==============================================================================
# NullGate — Developer Convenience & Automation Makefile
# Wraps CMake, CTest, Micro-Benchmarks, and Verification Suites
# ==============================================================================

BUILD_DIR ?= build
NPROC     ?= $(shell nproc 2>/dev/null || echo 4)

.PHONY: all build test bench verify install clean help

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f $(BUILD_DIR)/CMakeCache.txt ]; then \
		cmake -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release; \
	fi
	@cmake --build $(BUILD_DIR) -j$(NPROC)

test: build
	@ctest --test-dir $(BUILD_DIR) --output-on-failure

bench: build
	@echo "===================================================================="
	@echo " Running NullGate Performance & Micro-Benchmark Suite"
	@echo "===================================================================="
	@./$(BUILD_DIR)/benchmarks/micro/bench_callgate_rdtscp
	@./$(BUILD_DIR)/benchmarks/micro/bench_ipc_latency
	@./$(BUILD_DIR)/benchmarks/micro/bench_syscall_lsm
	@python3 benchmarks/sqlite/bench_sqlite_nullgate.py

verify: build
	@bash scripts/verify_nullgate.sh

install: build
	@cmake --install $(BUILD_DIR)

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

help:
	@echo "NullGate Development Targets:"
	@echo "  make          - Build all libraries, daemons, shims, and tests"
	@echo "  make test     - Run automated CTest regression matrix (24 tests)"
	@echo "  make bench    - Execute micro-benchmarks and SQLite UDF benchmark"
	@echo "  make verify   - Run master end-to-end certification gate"
	@echo "  make install  - Install libraries, headers, and binaries to system"
	@echo "  make clean    - Remove build directory"
