# NullGate Security Policy & Threat Model Specification

NullGate is a high-performance intra-process systems compartmentalization platform designed to contain untrusted extensions, libraries, and parsers within the same address space.

---

## 1. Mandatory Hardware & Operating System Prerequisites

NullGate relies on hardware-enforced CPU capabilities and Linux kernel LSM interfaces. Security invariants are active and enforceable only when the host environment satisfies the following prerequisites:

| Subsystem | Requirement | Verification Command / Flag | Purpose |
| :--- | :--- | :--- | :--- |
| **CPU MPK** | Intel Memory Protection Keys | `grep -qw pku /proc/cpuinfo` | Hardware memory domains (Keys 0–15) |
| **OS PKE** | OS-Enabled Protection Keys | `grep -qw ospke /proc/cpuinfo` | Kernel CR4.PKE activation |
| **Intel CET** | Indirect Branch Tracking (IBT) | `grep -qw ibt /proc/cpuinfo` | Landing pad (`ENDBR64`) protection |
| **Intel CET** | User Shadow Stack (SHSTK) | `grep -Eqw "user_shstk\|arch_cet" /proc/cpuinfo` | Hardware return address integrity |
| **Linux Kernel** | Version >= 6.8 | `uname -r` (>= 6.8.0) | Modern BPF task storage & LSM hooks |
| **BPF LSM** | Active Kernel Security Module | `grep -q bpf /sys/kernel/security/lsm` | Kernel-level syscall mediation |

Run `scripts/check_env.sh` or `scripts/verify_nullgate.sh` to validate all prerequisites automatically.

---

## 2. In-Scope Security Threat Model (The 8 Pillars)

NullGate defends against an attacker who has achieved **arbitrary memory read, write, or native code execution inside an untrusted compartment**:

1. **Pillar 1: Hardware Memory Spatial Boundary (Intel PKU)**
   - Untrusted compartments cannot read or modify memory assigned to Key 0 (host default) or Key 1 (trusted supervisor state).
   - Any unauthorized cross-domain memory access instantly triggers a hardware `SEGV_PKUERR` trap.
2. **Pillar 2: Anti-Snooping Defense (procfs & ptrace)**
   - Untrusted code cannot read peer compartment memory or supervisor secrets via `/proc/$PID/mem`, `/proc/$PID/maps`, `/proc/$PID/pagemap`, or `/proc/$PID/auxv`.
   - `ptrace(PTRACE_ATTACH)` and `ptrace(PTRACE_TRACEME)` are intercepted and denied by eBPF LSM.
3. **Pillar 3: Anti-Self-Tampering & Execution Lockdown**
   - Untrusted compartments cannot invoke `bpf()`, `prctl()`, `keyctl()`, `capset()`, or alter seccomp filters.
   - Initial domain registration is locked permanently with `NG_TASK_LOCKED`.
4. **Pillar 4: Call-Gate Hardware Gadget Quarantine & Intel CET**
   - Zero raw `wrpkru` instructions (`0F 01 EF`) exist across C code and application binaries.
   - WRPKRU is strictly quarantined to supervisor assembly entry points in `libnullgate.so`.
   - Intel CET IBT and User Shadow Stacks prevent ROP, JOP, and call-gate dispatcher bypasses.
5. **Pillar 5: Asynchronous Signal & Altstack Safety**
   - Signals are delivered on hardware-isolated alternative stacks (`sigaltstack`).
   - Supervisor trampoline restores trusted PKRU, sanitizes the XSAVE header, and CET SHSTK blocks SROP (`rt_sigreturn`) forgery.
6. **Pillar 6: Task Lifecycle & Process Hierarchy Protection**
   - eBPF task storage security contexts are inherited across `clone()` and `fork()`.
   - Thread-local stack pool destructors cleanly reclaim isolated memory on thread exit.
7. **Pillar 7: Syscall & Kernel Asynchronous I/O Mediation**
   - Confused deputy attacks passing Key 1 pointers into kernel syscalls (`read`, `write`, `connect`) are rejected with `-EFAULT` / `-EPERM`.
   - Asynchronous `io_uring` setup, enter, register, and personality overrides are strictly blocked from untrusted compartments.
8. **Pillar 8: Dynamic Policy Engine & Lock-Free IPC**
   - Control socket enforces `SO_PEERCRED` root authentication and non-following `fstat`/`fchmod` directory creation.
   - IPC channels use private descriptors for bounds arithmetic to prevent shared-memory TOCTOU corruption.

---

## 3. Out-of-Scope Threat Vectors

The following attack vectors are explicitly **out of scope** for the NullGate intra-process isolation boundary:

1. **Physical & Hardware Attacks:**
   - Physical memory bus interposers, cold-boot memory extraction, probing of hardware pins, or JTAG debuggers.
2. **Transient-Execution & Microarchitectural Side-Channels:**
   - Speculative execution vulnerabilities (e.g., Spectre-v1/v2, Meltdown, Foreshadow, MDS, Downfall, Inception). NullGate is an architectural memory protection boundary; microarchitectural side-channels must be mitigated at the compiler, microcode, and kernel page-table level.
3. **Kernel Privilege Escalation & Compromise:**
   - Zero-day vulnerabilities in the host Linux kernel that allow an attacker to bypass the LSM layer or overwrite kernel memory directly.
4. **Fault-Injection & Hardware Glitching:**
   - Rowhammer DRAM bit-flips, voltage undervolting, and clock glitching attacks.
5. **Denial of Service (Infinite Loops):**
   - An untrusted compartment executing an infinite computation loop without invoking mediated syscalls (CPU timeouts must be managed via standard OS scheduling or watchdogs).

---

## 4. Reporting a Security Vulnerability

If you discover a security vulnerability or invariant bypass in NullGate:

1. **Do NOT open a public GitHub issue.**
2. Submit a private security report via GitHub Security Advisories:
   **[Report a vulnerability](https://github.com/Sarang-Sanjay/NullGate/security/advisories/new)**
3. Include:
   - Reproduction code or proof-of-concept (PoC).
   - Target hardware details (`/proc/cpuinfo` CPU model and flags).
   - Kernel version and active LSM modules (`cat /sys/kernel/security/lsm`).
   - Specific security pillar or invariant affected.
4. We aim to acknowledge reports within 48 hours and provide a coordinated remediation timeline prior to public disclosure.
