#!/usr/bin/env bash
# NullGate — Production Setup and Systemd Integration Script
# Pillar 3, 6, 8: Production Daemon Management, Ambient Capabilities & Security

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}====================================================================${NC}"
echo -e "${CYAN}${BOLD}       NullGate — Production Systemd Setup & Prerequisites          ${NC}"
echo -e "${CYAN}${BOLD}====================================================================${NC}\n"

ERRORS=0

# 1. Kernel BPF LSM Check
echo -e "${BLUE}[CHECK 1]${NC} Verifying Kernel BPF LSM Activation..."
if [ -f /sys/kernel/security/lsm ]; then
    LSM_LIST=$(cat /sys/kernel/security/lsm)
    if echo "$LSM_LIST" | grep -qw "bpf"; then
        echo -e "         ${GREEN}[PASS]${NC} BPF LSM is active in kernel: $LSM_LIST"
    else
        echo -e "         ${RED}[FAIL]${NC} BPF LSM is not in active LSM list: $LSM_LIST"
        ((ERRORS++)) || true
    fi
else
    echo -e "         ${YELLOW}[WARN]${NC} /sys/kernel/security/lsm not accessible (securityfs unmounted?)"
fi

# 2. Hardware PKU Check
echo -e "${BLUE}[CHECK 2]${NC} Verifying CPU Memory Protection Keys (PKU)..."
if grep -q "\bpku\b" /proc/cpuinfo && grep -q "\bospke\b" /proc/cpuinfo; then
    echo -e "         ${GREEN}[PASS]${NC} Hardware PKU and OS PKE enabled in CPU flags"
else
    echo -e "         ${YELLOW}[WARN]${NC} PKU/OSPKE flags not observed in /proc/cpuinfo"
fi

# 3. Systemd Unit File Syntax Verification
echo -e "${BLUE}[CHECK 3]${NC} Verifying systemd unit file syntax..."
if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify "${ROOT_DIR}/scripts/nullgate.service" 2>&1 | grep -E -v "No such file or directory"; then
        echo -e "         ${YELLOW}[WARN]${NC} Unit file warnings detected"
    else
        echo -e "         ${GREEN}[PASS]${NC} nullgate.service passed systemd-analyze verification"
    fi
else
    echo -e "         ${BLUE}[INFO]${NC} systemd-analyze not installed; skipped unit analysis"
fi

# 4. Directory & Configuration Setup
echo -e "${BLUE}[CHECK 4]${NC} Production Directories & Permissions..."
if [ "$(id -u)" -eq 0 ]; then
    mkdir -p /etc/nullgate
    mkdir -p /run/nullgate
    chmod 0755 /etc/nullgate
    chmod 0755 /run/nullgate
    echo -e "         ${GREEN}[PASS]${NC} Configured /etc/nullgate and /run/nullgate"

    if [ -f "${ROOT_DIR}/benchmarks/sqlite/sqlite_policy.json" ] && [ ! -f /etc/nullgate/policy.json ]; then
        cp "${ROOT_DIR}/benchmarks/sqlite/sqlite_policy.json" /etc/nullgate/policy.json
        chmod 0644 /etc/nullgate/policy.json
        echo -e "         ${GREEN}[PASS]${NC} Installed default policy to /etc/nullgate/policy.json"
    fi

    if [ -f "${ROOT_DIR}/build/src/daemon/nullgate-daemon" ]; then
        install -m 0755 "${ROOT_DIR}/build/src/daemon/nullgate-daemon" /usr/local/bin/nullgate-daemon
        echo -e "         ${GREEN}[PASS]${NC} Installed nullgate-daemon to /usr/local/bin/nullgate-daemon"
    fi

    if [ -f "${ROOT_DIR}/build/src/cli/nullgate-ctl" ]; then
        install -m 0755 "${ROOT_DIR}/build/src/cli/nullgate-ctl" /usr/local/bin/nullgate-ctl
        echo -e "         ${GREEN}[PASS]${NC} Installed nullgate-ctl to /usr/local/bin/nullgate-ctl"
    fi

    install -m 0644 "${ROOT_DIR}/scripts/nullgate.service" /etc/systemd/system/nullgate.service
    echo -e "         ${GREEN}[PASS]${NC} Installed systemd service to /etc/systemd/system/nullgate.service"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        echo -e "         ${GREEN}[PASS]${NC} Ran systemctl daemon-reload"
    fi
else
    echo -e "         ${BLUE}[INFO]${NC} Running as non-root user (id=$(id -u))."
    echo -e "         ${BLUE}[INFO]${NC} To install systemd service and directories, run as root:"
    echo -e "                sudo mkdir -p /etc/nullgate /run/nullgate"
    echo -e "                sudo cp ${ROOT_DIR}/scripts/nullgate.service /etc/systemd/system/"
    echo -e "                sudo systemctl daemon-reload"
fi

echo -e "\n${GREEN}${BOLD}Setup script verification completed (Errors: ${ERRORS}).${NC}"
exit ${ERRORS}
