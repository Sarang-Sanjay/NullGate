#!/usr/bin/env bash
# NullGate - Pre-Flight Environment Diagnostic Script (Step 1)
# Verifies Linux kernel 6.8+, BTF, BPF LSM, CPU PKU/CET features, and LLVM 18+ toolchain.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
    ((WARNINGS++)) || true
}

fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((ERRORS++)) || true
}

remediation() {
    echo -e "       ${BOLD}Remediation:${NC} $*"
}

echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD}       NullGate: Pre-Flight Host Environment Verification       ${NC}"
echo -e "${BOLD}================================================================${NC}"

# 1. Kernel Version Check (>= 6.8)
info "Checking Linux kernel version..."
KERNEL_RELEASE=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_RELEASE" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_RELEASE" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 6 ] || { [ "$KERNEL_MAJOR" -eq 6 ] && [ "$KERNEL_MINOR" -ge 8 ]; }; then
    pass "Kernel version is $KERNEL_RELEASE (>= 6.8 required)"
else
    fail "Kernel version is $KERNEL_RELEASE (< 6.8 required)"
    remediation "Upgrade to Linux 6.8+ on Ubuntu 24.04/Linux Mint 22.x: sudo apt update && sudo apt install -y linux-generic-hwe-24.04"
fi

# 2. Kernel BTF Check (/sys/kernel/btf/vmlinux)
info "Checking Kernel BTF support (/sys/kernel/btf/vmlinux)..."
if [ -r "/sys/kernel/btf/vmlinux" ]; then
    pass "Kernel BTF is available and readable (/sys/kernel/btf/vmlinux)"
else
    fail "Kernel BTF not found or not readable at /sys/kernel/btf/vmlinux"
    remediation "Ensure kernel was built with CONFIG_DEBUG_INFO_BTF=y. If file exists but is unreadable, check permissions."
fi

# 3. Active BPF LSM Check (/sys/kernel/security/lsm)
info "Checking active LSMs in /sys/kernel/security/lsm..."
if [ ! -f "/sys/kernel/security/lsm" ]; then
    warn "/sys/kernel/security/lsm does not exist. Checking if securityfs is mounted..."
    if ! grep -q "securityfs" /proc/mounts; then
        warn "securityfs is not mounted. Attempting diagnosis..."
        remediation "Mount securityfs: sudo mount -t securityfs securityfs /sys/kernel/security"
    fi
fi

if [ -f "/sys/kernel/security/lsm" ]; then
    ACTIVE_LSMS=$(cat /sys/kernel/security/lsm)
    if echo "$ACTIVE_LSMS" | grep -qw "bpf"; then
        pass "BPF LSM is active: $ACTIVE_LSMS"
    else
        fail "BPF LSM is not listed in active LSMs: '$ACTIVE_LSMS'"
        remediation "Enable bpf in GRUB: Add 'lsm=landlock,lockdown,yama,integrity,apparmor,bpf' to GRUB_CMDLINE_LINUX in /etc/default/grub, then run 'sudo update-grub' and reboot."
    fi
else
    fail "Cannot verify active LSMs (securityfs missing or unreadable)."
fi

# 4. Kernel Config (CONFIG_BPF_LSM=y)
info "Checking CONFIG_BPF_LSM in kernel configuration..."
KCONFIG_FOUND=0
if [ -f "/boot/config-$KERNEL_RELEASE" ]; then
    KCONFIG_FILE="/boot/config-$KERNEL_RELEASE"
    KCONFIG_FOUND=1
elif [ -f "/proc/config.gz" ]; then
    KCONFIG_FILE="/proc/config.gz"
    KCONFIG_FOUND=2
fi

if [ "$KCONFIG_FOUND" -eq 1 ]; then
    if grep -q "^CONFIG_BPF_LSM=y" "$KCONFIG_FILE"; then
        pass "CONFIG_BPF_LSM=y found in $KCONFIG_FILE"
    else
        warn "CONFIG_BPF_LSM is not '=y' in $KCONFIG_FILE"
    fi
elif [ "$KCONFIG_FOUND" -eq 2 ]; then
    if zcat "$KCONFIG_FILE" | grep -q "^CONFIG_BPF_LSM=y"; then
        pass "CONFIG_BPF_LSM=y found in /proc/config.gz"
    else
        warn "CONFIG_BPF_LSM is not '=y' in /proc/config.gz"
    fi
else
    if [ -f "/sys/kernel/security/lsm" ] && grep -qw "bpf" "/sys/kernel/security/lsm"; then
        pass "Kernel config file not on disk, but BPF LSM is confirmed active via /sys/kernel/security/lsm"
    else
        warn "Could not locate kernel config file to verify CONFIG_BPF_LSM"
    fi
fi

# 5. CPU Hardware Features Check (PKU, OSPKE, CET: IBT + SHSTK)
info "Checking CPU hardware features in /proc/cpuinfo..."
CPUINFO="/proc/cpuinfo"

# PKU check
if grep -qw "pku" "$CPUINFO"; then
    pass "CPU feature 'pku' (Memory Protection Keys) is supported by hardware"
else
    fail "CPU feature 'pku' missing from /proc/cpuinfo"
    remediation "Ensure running on an Intel CPU with PKU support (Intel Ice Lake / Tiger Lake / Core Ultra) and nested virtualization allows PKU if in a VM."
fi

# OSPKE check
if grep -qw "ospke" "$CPUINFO"; then
    pass "CPU feature 'ospke' (OS enabled Protection Keys / CR4.PKE) is active"
else
    fail "CPU feature 'ospke' missing from /proc/cpuinfo (Kernel has not enabled CR4.PKE)"
    remediation "Boot kernel with pku enabled. Verify kernel config CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=y."
fi

# CET IBT check
if grep -qw "ibt" "$CPUINFO"; then
    pass "CPU feature 'ibt' (Indirect Branch Tracking) is supported"
else
    warn "CPU feature 'ibt' missing from /proc/cpuinfo flags"
fi

# CET User Shadow Stack check
if grep -qw "user_shstk" "$CPUINFO" || grep -qw "arch_cet" "$CPUINFO" || grep -qw "shstk" "$CPUINFO"; then
    pass "CPU feature User Shadow Stack ('user_shstk' / 'arch_cet') is supported"
else
    warn "CPU feature 'user_shstk' / 'arch_cet' not directly exposed in cpuinfo flags (verifying kernel user_shstk support)"
fi

# 6. Toolchain and Development Libraries Check
info "Checking compiler toolchain and developer headers..."

# Clang / LLVM version (>= 18)
CLANG_BIN=""
if command -v clang-18 >/dev/null 2>&1; then
    CLANG_BIN="clang-18"
elif command -v clang >/dev/null 2>&1; then
    CLANG_BIN="clang"
fi

if [ -n "$CLANG_BIN" ]; then
    CLANG_VER=$($CLANG_BIN --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    CLANG_MAJOR=$(echo "$CLANG_VER" | cut -d. -f1)
    if [ "$CLANG_MAJOR" -ge 18 ]; then
        pass "Clang compiler: $CLANG_BIN version $CLANG_VER (>= 18 required)"
    else
        fail "Clang compiler: $CLANG_BIN is version $CLANG_VER (< 18 required)"
        remediation "Install Clang 18: sudo apt install -y clang-18 llvm-18 llvm-18-dev lld-18"
    fi
else
    fail "Clang compiler not found"
    remediation "Install Clang 18: sudo apt install -y clang-18 llvm-18 llvm-18-dev lld-18"
fi

# llvm-config-18 & LLVMConfig.cmake
LLVM_CONFIG_BIN=""
if command -v llvm-config-18 >/dev/null 2>&1; then
    LLVM_CONFIG_BIN="llvm-config-18"
elif command -v llvm-config >/dev/null 2>&1; then
    LLVM_CONFIG_BIN="llvm-config"
fi

if [ -n "$LLVM_CONFIG_BIN" ]; then
    LLVM_CMAKEDIR=$($LLVM_CONFIG_BIN --cmakedir 2>/dev/null || true)
    if [ -d "$LLVM_CMAKEDIR" ] && [ -f "$LLVM_CMAKEDIR/LLVMConfig.cmake" ]; then
        pass "LLVM CMake directory found: $LLVM_CMAKEDIR (LLVMConfig.cmake present)"
    else
        warn "LLVMConfig.cmake not found at '$LLVM_CMAKEDIR'"
        remediation "Install LLVM 18 development files: sudo apt install -y llvm-18-dev"
    fi
else
    fail "llvm-config not found"
    remediation "Install LLVM 18: sudo apt install -y llvm-18-dev"
fi

# bpftool (>= 7.0)
if command -v bpftool >/dev/null 2>&1; then
    BPFTOOL_VER=$(bpftool version | head -n1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | sed 's/v//' || echo "7.0.0")
    pass "bpftool found: version $BPFTOOL_VER"
else
    fail "bpftool command not found in PATH"
    remediation "Install bpftool: sudo apt install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r)"
fi

# libbpf and <bpf/libbpf.h>
if [ -f "/usr/include/bpf/libbpf.h" ] || [ -f "/usr/local/include/bpf/libbpf.h" ]; then
    pass "libbpf C headers found (<bpf/libbpf.h> present)"
else
    fail "libbpf headers missing (<bpf/libbpf.h> not found)"
    remediation "Install libbpf development library: sudo apt install -y libbpf-dev"
fi

# GNU readelf (for CET verification)
if command -v readelf >/dev/null 2>&1; then
    pass "GNU readelf found: $(readelf --version | head -n1)"
else
    fail "readelf command not found"
    remediation "Install binutils: sudo apt install -y binutils"
fi

# CMake
if command -v cmake >/dev/null 2>&1; then
    CMAKE_VER=$(cmake --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    pass "CMake found: version $CMAKE_VER"
else
    fail "cmake command not found"
    remediation "Install CMake: sudo apt install -y cmake"
fi

echo -e "${BOLD}================================================================${NC}"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}Pre-Flight Environment Check PASSED${NC} (${WARNINGS} warnings, 0 critical errors)"
    exit 0
else
    echo -e "${RED}${BOLD}Pre-Flight Environment Check FAILED${NC} (${ERRORS} errors, ${WARNINGS} warnings)"
    echo -e "Please address the remediation steps above before proceeding."
    exit 1
fi
