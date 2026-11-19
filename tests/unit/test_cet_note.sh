#!/usr/bin/env bash
# NullGate - Automated Intel CET (IBT + SHSTK) & NX Stack Verification Test
# Audits ELF binaries and shared libraries to ensure hardware CET and NX stack flags are intact.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

ERRORS=0

verify_target() {
    local target="$1"

    if [ ! -f "$target" ]; then
        echo -e "${RED}[FAIL]${NC} Target not found: $target"
        ((ERRORS++)) || true
        return
    fi

    local target_name
    target_name=$(basename "$target")
    echo -e "${BLUE}[AUDIT]${NC} Inspecting $target_name..."

    local notes
    notes=$(readelf -n "$target" 2>&1 || true)

    # 1. Check for IBT (Indirect Branch Tracking)
    if echo "$notes" | grep -q "IBT"; then
        echo -e "       ${GREEN}[PASS]${NC} Intel CET IBT note confirmed"
    else
        echo -e "       ${RED}[FAIL]${NC} Missing Intel CET IBT note!"
        ((ERRORS++)) || true
    fi

    # 2. Check for SHSTK (User Shadow Stack)
    if echo "$notes" | grep -q "SHSTK"; then
        echo -e "       ${GREEN}[PASS]${NC} Intel CET User Shadow Stack (SHSTK) note confirmed"
    else
        echo -e "       ${RED}[FAIL]${NC} Missing Intel CET User Shadow Stack (SHSTK) note!"
        ((ERRORS++)) || true
    fi

    # 3. Check for Non-Executable Stack (NX: GNU_STACK has RW flags, not executable)
    local stack_line
    stack_line=$(readelf -l "$target" 2>&1 | grep -A 1 "GNU_STACK" || true)
    if echo "$stack_line" | grep -q "RW" && ! echo "$stack_line" | grep -q "E"; then
        echo -e "       ${GREEN}[PASS]${NC} GNU_STACK is non-executable (RW)"
    else
        echo -e "       ${RED}[FAIL]${NC} GNU_STACK is executable or invalid!"
        ((ERRORS++)) || true
    fi
}

echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD}       NullGate: Intel CET & Stack Security ELF Audit           ${NC}"
echo -e "${BOLD}================================================================${NC}"

TARGETS=()
if [ "$#" -gt 0 ]; then
    TARGETS=("$@")
else
    # Default Phase 1 targets
    TARGETS=(
        "${BUILD_DIR}/src/daemon/nullgate-daemon"
        "${BUILD_DIR}/src/libnullgate/libnullgate.so"
    )
fi

for t in "${TARGETS[@]}"; do
    verify_target "$t"
done

echo -e "${BOLD}================================================================${NC}"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}ALL CET & NX AUDITS PASSED${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}CET AUDIT FAILED ($ERRORS errors detected)${NC}"
    exit 1
fi
