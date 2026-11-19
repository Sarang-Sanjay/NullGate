#!/usr/bin/env bash
# NullGate - Kernel BTF Type Generation Script (Step 2)
# Dumps kernel BTF types from /sys/kernel/btf/vmlinux into src/bpf/vmlinux.h

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_FILE="$ROOT_DIR/src/bpf/vmlinux.h"
BTF_SOURCE="/sys/kernel/btf/vmlinux"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BLUE}[INFO]${NC} Generating local CO-RE kernel definitions header..."

# 1. Verify bpftool exists
if ! command -v bpftool >/dev/null 2>&1; then
    echo -e "${RED}[ERROR]${NC} bpftool not found in PATH." >&2
    echo -e "        Install via: sudo apt install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r)" >&2
    exit 1
fi

# 2. Verify /sys/kernel/btf/vmlinux is present and readable
if [ ! -r "$BTF_SOURCE" ]; then
    echo -e "${RED}[ERROR]${NC} Cannot read BTF file at $BTF_SOURCE." >&2
    exit 1
fi

# 3. Ensure target directory exists
mkdir -p "$(dirname "$OUTPUT_FILE")"

# 4. Dump BTF format c into temporary file first for atomic replacement
TEMP_OUTPUT="${OUTPUT_FILE}.tmp.$$"
echo -e "${BLUE}[INFO]${NC} Dumping BTF from $BTF_SOURCE using bpftool..."
bpftool btf dump file "$BTF_SOURCE" format c > "$TEMP_OUTPUT"

# 5. Sanity check: Ensure non-empty and contains critical kernel structures
if [ ! -s "$TEMP_OUTPUT" ]; then
    echo -e "${RED}[ERROR]${NC} Generated BTF file is empty." >&2
    rm -f "$TEMP_OUTPUT"
    exit 1
fi

if ! grep -q "struct task_struct {" "$TEMP_OUTPUT"; then
    echo -e "${RED}[ERROR]${NC} Generated BTF file does not contain 'struct task_struct'." >&2
    rm -f "$TEMP_OUTPUT"
    exit 1
fi

# Atomic move
mv "$TEMP_OUTPUT" "$OUTPUT_FILE"

FILE_SIZE=$(du -h "$OUTPUT_FILE" | cut -f1)
LINE_COUNT=$(wc -l < "$OUTPUT_FILE")

echo -e "${GREEN}[PASS]${NC} Generated ${BOLD}$OUTPUT_FILE${NC} ($FILE_SIZE, $LINE_COUNT lines)"
echo -e "${GREEN}[PASS]${NC} Kernel BTF header verified: contains 'struct task_struct'."
exit 0
