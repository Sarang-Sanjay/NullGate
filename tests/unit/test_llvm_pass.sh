#!/usr/bin/env bash
# NullGate - LLVM 18 Compiler Pass Plugin Verification Test
# Pillar 4: Gadget Elimination & Static Binary Sanitization
#
# Validates:
#   1. Clang 18 loads libNullGatePass.so and compiles clean code with exit 0.
#   2. Rejection of inline assembly containing 'wrpkru' with fatal error.
#   3. Rejection of intrinsic/builtin PKRU modification (_writepkru).
#   4. Rejection of direct calls to domain-annotated functions from untrusted callers.
#   5. Permitted calls to domain-annotated functions via authorized dispatchers (ng_enter).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

PLUGIN_PATH="${1:-${BUILD_DIR}/src/llvm-pass/libNullGatePass.so}"

if [ ! -f "${PLUGIN_PATH}" ]; then
    echo -e "${RED}[FAIL]${NC} Pass plugin shared object not found at: ${PLUGIN_PATH}"
    exit 1
fi

CLANG_BIN=""
if command -v clang-18 >/dev/null 2>&1; then
    CLANG_BIN="clang-18"
elif command -v clang >/dev/null 2>&1; then
    CLANG_BIN="clang"
else
    echo -e "${RED}[FAIL]${NC} Neither clang-18 nor clang found in PATH."
    exit 1
fi

TMP_DIR=$(mktemp -d /tmp/nullgate_llvm_test_XXXXXX)
trap 'rm -rf "${TMP_DIR}"' EXIT

echo -e "${BLUE}${BOLD}====================================================================${NC}"
echo -e "${BLUE}${BOLD}       NullGate — LLVM 18 Compiler Pass Verification Test Suite     ${NC}"
echo -e "${BLUE}${BOLD}       Pillar 4: Zero-Tolerance WRPKRU Gadget Elimination           ${NC}"
echo -e "${BLUE}${BOLD}====================================================================${NC}"
echo -e "${BLUE}[INFO]${NC} Using Clang binary: $(which "${CLANG_BIN}")"
echo -e "${BLUE}[INFO]${NC} Using Pass Plugin:  ${PLUGIN_PATH}"

FAILURES=0

# --- Test 1: Positive Baseline Compilation ---
echo -e "\n${BLUE}[TEST 1]${NC} Compiling clean C baseline program..."
cat << 'EOF' > "${TMP_DIR}/test_clean.c"
#include <stdio.h>
int main(void) {
    return 0;
}
EOF

if "${CLANG_BIN}" -fpass-plugin="${PLUGIN_PATH}" "${TMP_DIR}/test_clean.c" -o "${TMP_DIR}/test_clean.bin" 2>"${TMP_DIR}/test_clean.log"; then
    echo -e "         ${GREEN}[PASS]${NC} Clean baseline program compiled successfully."
else
    echo -e "         ${RED}[FAIL]${NC} Clean baseline program failed to compile!"
    cat "${TMP_DIR}/test_clean.log"
    ((FAILURES++))
fi

# --- Test 2: Negative Inline Assembly (WRPKRU) ---
echo -e "\n${BLUE}[TEST 2]${NC} Testing inline assembly 'wrpkru' interception..."
cat << 'EOF' > "${TMP_DIR}/test_inline_wrpkru.c"
int main(void) {
    __asm__ volatile ("wrpkru");
    return 0;
}
EOF

if "${CLANG_BIN}" -fpass-plugin="${PLUGIN_PATH}" "${TMP_DIR}/test_inline_wrpkru.c" -o "${TMP_DIR}/test_inline.bin" >"${TMP_DIR}/test_inline.log" 2>&1; then
    echo -e "         ${RED}[FAIL]${NC} Compiler erroneously permitted inline assembly 'wrpkru'!"
    ((FAILURES++))
else
    if grep -q "Direct emission of 'wrpkru' instruction in inline assembly is strictly forbidden" "${TMP_DIR}/test_inline.log"; then
        echo -e "         ${GREEN}[PASS]${NC} Inline assembly 'wrpkru' successfully intercepted and aborted."
    else
        echo -e "         ${RED}[FAIL]${NC} Compilation aborted, but expected diagnostic message not found!"
        cat "${TMP_DIR}/test_inline.log"
        ((FAILURES++))
    fi
fi

# --- Test 3: Negative Target Intrinsic / Builtin (_writepkru) ---
echo -e "\n${BLUE}[TEST 3]${NC} Testing compiler intrinsic '_writepkru' interception..."
cat << 'EOF' > "${TMP_DIR}/test_intrinsic.c"
void _writepkru(unsigned int pkru);
int main(void) {
    _writepkru(0);
    return 0;
}
EOF

if "${CLANG_BIN}" -fpass-plugin="${PLUGIN_PATH}" "${TMP_DIR}/test_intrinsic.c" -o "${TMP_DIR}/test_intrinsic.bin" >"${TMP_DIR}/test_intrinsic.log" 2>&1; then
    echo -e "         ${RED}[FAIL]${NC} Compiler erroneously permitted '_writepkru' intrinsic!"
    ((FAILURES++))
else
    if grep -q "Direct invocation of PKRU modifier function '_writepkru' is strictly forbidden" "${TMP_DIR}/test_intrinsic.log"; then
        echo -e "         ${GREEN}[PASS]${NC} Target intrinsic '_writepkru' successfully intercepted and aborted."
    else
        echo -e "         ${RED}[FAIL]${NC} Compilation aborted, but expected diagnostic message not found!"
        cat "${TMP_DIR}/test_intrinsic.log"
        ((FAILURES++))
    fi
fi

# --- Test 4: Negative Direct Domain Call Bypass ---
echo -e "\n${BLUE}[TEST 4]${NC} Testing unauthorized direct call to domain-annotated function..."
cat << 'EOF' > "${TMP_DIR}/test_domain_bypass.c"
__attribute__((annotate("nullgate_domain")))
void secure_vault(void) {}

void untrusted_worker(void) {
    secure_vault(); /* Unauthorized direct call */
}

int main(void) {
    untrusted_worker();
    return 0;
}
EOF

if "${CLANG_BIN}" -fpass-plugin="${PLUGIN_PATH}" "${TMP_DIR}/test_domain_bypass.c" -o "${TMP_DIR}/test_domain.bin" >"${TMP_DIR}/test_domain.log" 2>&1; then
    echo -e "         ${RED}[FAIL]${NC} Compiler erroneously permitted direct cross-domain call without call-gate!"
    ((FAILURES++))
else
    if grep -q "Direct call to domain-isolated function 'secure_vault' from untrusted caller 'untrusted_worker' is forbidden" "${TMP_DIR}/test_domain.log"; then
        echo -e "         ${GREEN}[PASS]${NC} Direct cross-domain call bypass successfully intercepted and blocked."
    else
        echo -e "         ${RED}[FAIL]${NC} Compilation aborted, but expected domain diagnostic message not found!"
        cat "${TMP_DIR}/test_domain.log"
        ((FAILURES++))
    fi
fi

# --- Test 5: Positive Authorized Dispatcher Routing ---
echo -e "\n${BLUE}[TEST 5]${NC} Testing authorized call-gate dispatcher routing (ng_enter)..."
cat << 'EOF' > "${TMP_DIR}/test_domain_auth.c"
__attribute__((annotate("nullgate_domain")))
void secure_vault(void) {}

void ng_enter(void) {
    secure_vault(); /* Authorized dispatcher */
}

int main(void) {
    ng_enter();
    return 0;
}
EOF

if "${CLANG_BIN}" -fpass-plugin="${PLUGIN_PATH}" "${TMP_DIR}/test_domain_auth.c" -o "${TMP_DIR}/test_auth.bin" 2>"${TMP_DIR}/test_auth.log"; then
    echo -e "         ${GREEN}[PASS]${NC} Authorized callgate dispatcher compilation succeeded cleanly."
else
    echo -e "         ${RED}[FAIL]${NC} Authorized callgate dispatcher failed to compile!"
    cat "${TMP_DIR}/test_auth.log"
    ((FAILURES++))
fi

# --- Test 6: Negative Inline Assembly Raw Byte Emission (.byte 0x0f, 0x01, 0xef) (Fix MED-03) ---
echo -e "\n${BLUE}[TEST 6]${NC} Testing inline assembly raw byte WRPKRU (.byte 0x0f, 0x01, 0xef) interception..."
cat << 'EOF' > "${TMP_DIR}/test_inline_raw_bytes.c"
int main(void) {
    __asm__ volatile (".byte 0x0f, 0x01, 0xef");
    return 0;
}
EOF

if "${CLANG_BIN}" -fpass-plugin="${PLUGIN_PATH}" "${TMP_DIR}/test_inline_raw_bytes.c" -o "${TMP_DIR}/test_raw.bin" >"${TMP_DIR}/test_raw.log" 2>&1; then
    echo -e "         ${RED}[FAIL]${NC} Compiler erroneously permitted inline assembly raw byte WRPKRU!"
    ((FAILURES++))
else
    if grep -q "Raw byte emission of 'WRPKRU' opcode" "${TMP_DIR}/test_raw.log"; then
        echo -e "         ${GREEN}[PASS]${NC} Inline assembly raw byte WRPKRU successfully intercepted and aborted."
    else
        echo -e "         ${RED}[FAIL]${NC} Compilation aborted, but expected diagnostic message not found!"
        cat "${TMP_DIR}/test_raw.log"
        ((FAILURES++))
    fi
fi

# --- Test 7: Negative Inline Assembly Ascii / String Escapes (.ascii "\x0f\x01\xef") (Fix LOW-03) ---
echo -e "\n${BLUE}[TEST 7]${NC} Testing inline assembly ascii/string WRPKRU (.ascii \"\\x0f\\x01\\xef\") interception..."
cat << 'EOF' > "${TMP_DIR}/test_inline_ascii_escapes.c"
int main(void) {
    __asm__ volatile (".ascii \"\\x0f\\x01\\xef\"");
    return 0;
}
EOF

if "${CLANG_BIN}" -fpass-plugin="${PLUGIN_PATH}" "${TMP_DIR}/test_inline_ascii_escapes.c" -o "${TMP_DIR}/test_ascii.bin" >"${TMP_DIR}/test_ascii.log" 2>&1; then
    echo -e "         ${RED}[FAIL]${NC} Compiler erroneously permitted inline assembly ascii/string WRPKRU!"
    ((FAILURES++))
else
    if grep -q "Raw byte emission of 'WRPKRU' opcode" "${TMP_DIR}/test_ascii.log"; then
        echo -e "         ${GREEN}[PASS]${NC} Inline assembly ascii/string WRPKRU successfully intercepted and aborted."
    else
        echo -e "         ${RED}[FAIL]${NC} Compilation aborted, but expected diagnostic message not found!"
        cat "${TMP_DIR}/test_ascii.log"
        ((FAILURES++))
    fi
fi

echo -e "\n${BLUE}${BOLD}====================================================================${NC}"
if [ "${FAILURES}" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}[PASS] All 7 LLVM 18 Compiler Pass Plugin test cases passed successfully!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}[FAIL] ${FAILURES} test case(s) failed in LLVM Pass Plugin test suite.${NC}"
    exit 1
fi
