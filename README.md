# NullGate: Kernel-Enforced Intra-Process Isolation via Hardware PKU, Intel CET & eBPF LSM

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![LLVM Version](https://img.shields.io/badge/LLVM-18.1.3-green.svg)](https://llvm.org/)
[![Hardware](https://img.shields.io/badge/Hardware-Intel%20PKU%20%2B%20CET-brightgreen.svg)]()
[![Kernel](https://img.shields.io/badge/Kernel-Linux%206.8%2B%20eBPF%20LSM-orange.svg)](https://ebpf.io/)
[![CTest Suite](https://img.shields.io/badge/CTest%20Suite-100%25%20Pass%20(24%2F24)-brightgreen.svg)]()
[![Call-Gate Latency](https://img.shields.io/badge/Call--Gate%20Latency-~38%20ns%20(148%20cycles)-blue.svg)]()

> **Executive Summary & Abstract**: **NullGate** is an intra-process, hardware-enforced memory compartmentalization and systems defense platform combining x86_64 Intel Memory Protection Keys (PKU/MPK), Intel Control-Flow Enforcement Technology (CET IBT & User Shadow Stack), a custom LLVM 18 compiler pass (`libNullGatePass.so`), an ELF static binary scrubber (`nullgate-scrubber`), and in-kernel Linux 6.8+ eBPF LSM security modules (`nullgate_sync.bpf.c`, `nullgate_lsm.bpf.c`, `nullgate_uring.bpf.c`). NullGate enforces multi-domain spatial and temporal memory boundaries entirely in userspace with **~38 nanosecond call-gate transition latency** (148 CPU cycles), **38.84 ns zero-copy SPSC IPC ring latency** (**25.75 Million ops/sec**), **zero WRPKRU instructions** across application code and binaries, **100.0% vulnerability neutralization** across memory corruption, procfs snooping, ptrace, SROP, and confused deputy vectors, and **less than 3.0% throughput overhead** on real-world SQLite database and Nginx reverse proxy workloads.

---

## 1. Executive Summary & Core Security Innovations

Traditional process-based isolation (e.g. `fork()` + Unix domain sockets or RPC) incurs severe performance degradation (1,500–5,000 CPU cycles per boundary crossing) due to TLB shootdowns, kernel context switches, and address-space duplication. Software-based isolation (e.g. WebAssembly runtimes or software fault isolation) introduces high compilation overhead and breaks native C/C++ ABI compatibility.

NullGate eliminates this trade-off by combining hardware-wire memory protection with kernel LSM security:

### Core Engineering & Security Innovations:
* **Phase 1: Hardware PKU & CET Call-Gate Engine (`libnullgate.so`)**: Low-level assembly trampoline (`callgate.S`) switching execution domains in **148 CPU cycles (~38 ns)** without kernel context switches, dedicated 4KB supervisor state page quarantined under PKU Key 1, and hardware Intel CET User Shadow Stack (`SHSTK`) + Indirect Branch Tracking (`IBT`) landing pads.
* **Phase 2: In-Kernel eBPF LSM Mediation (`src/bpf/`)**: Linux 6.8+ BPF LSM modules (`bpf_lsm_file_open`, `bpf_lsm_ptrace_access_check`, `bpf_lsm_sys_enter`, `bpf_lsm_uring_cmd`, `bpf_lsm_task_alloc`) blocking procfs memory snooping (`/proc/$PID/mem`, `maps`, `pagemap`), debugger hijacking (`ptrace`), sandbox self-tampering (`bpf()`, `prctl()`), and asynchronous `io_uring` sandbox escapes.
* **Phase 3: Compiler Hardening & Gadget Sanitization (`NullGatePass` & `nullgate-scrubber`)**: A custom C++ LLVM 18 pass plugin intercepting inline assembly `wrpkru`, compiler intrinsics (`_writepkru`), and unauthorized direct calls; paired with an authoritative standalone ELF binary static scrubber enforcing the **Pillar 4 Invariant (0 raw WRPKRU instructions across all C code and binaries)** and strict Intel CET notes.
* **Phase 4: Dynamic Control Plane, Transparent Shims & High-Throughput IPC**:
  * **Dynamic Policy Daemon (`nullgate-daemon`) & Administrative CLI (`nullgate-ctl`)**: Unified single-threaded `epoll` multiplexer linking the eBPF audit ring buffer with a Unix domain control socket (`/run/nullgate/control.sock`) with `SO_PEERCRED` root authentication and atomic JSON policy hot-reloading.
  * **Hardware Zero-Copy IPC Channels (`nullgate_ipc.h`)**: Cacheline-aligned (64-byte) single-producer single-consumer (SPSC) lock-free shared memory channels operating at **38.84 ns latency** (25.75 Million msgs/sec) with private descriptor bounds checking.
  * **Transparent Library Interposition (`libnullgate_shim.so`)**: Zero-code-change dynamic preloading with re-entrancy protection, longjmp depth recovery, and an O(1) lock-free guard-paged stack pool.
  * **Real-World SQLite Sandboxing (`benchmarks/sqlite/`)**: Hardware isolation of untrusted SQL User-Defined Functions (UDFs) with only **3.00% latency overhead** (263,783 QPS).

---

## 2. Threat Model & Security Problem

Modern applications (databases, web servers, browser runtimes, cryptographic tools) frequently load third-party extensions, image decoders, and untrusted scripts within the same virtual address space. An adversary with a single memory corruption vulnerability (buffer overflow, use-after-free, out-of-bounds write) can compromise the entire host process.

### 2.1 Controlled Exploit & Security Demonstration Matrix

| Controlled Test Case | Target Security Boundary | Baseline Behavior | NullGate Interception & Security Outcome | Enforcement Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Case 1: Spatial Memory Violation** | Cross-domain heap/vault probe | Unchecked memory access | **TRAPPED (`SEGV_PKUERR`, signal 11)** | Hardware PKU Access Disable (`AD=1, WD=1`) |
| **Case 2: Memory Reconnaissance** | `/proc/<pid>/mem`, `maps`, `pagemap` | Full address space leak | **DENIED (`-EACCES` / `-EPERM`)** | eBPF LSM `bpf_lsm_file_open` dentry filter |
| **Case 3: Debugger Hijack** | `ptrace(PTRACE_ATTACH / TRACEME)` | Process execution control | **DENIED (`-EACCES` / `-EPERM`)** | eBPF LSM `bpf_lsm_ptrace_access_check` |
| **Case 4: Sandbox Self-Tamper** | `prctl()`, `bpf()`, seccomp tampering | Confinement disabled | **DENIED (`-EPERM`)** | eBPF LSM `bpf_lsm_sys_enter` + `NG_TASK_LOCKED` |
| **Case 5: Asynchronous I/O Escape** | `io_uring_setup`, `IORING_OP_SEND` | Unconfined background I/O | **DENIED (`-EPERM`)** | eBPF LSM `bpf_lsm_uring_cmd` & setup denial |
| **Case 6: Gadget Harvesting (ROP/JOP)**| `wrpkru` (`0F 01 EF`) harvesting | PKRU register unlocked | **PREVENTED (0 gadgets + CET `#CP` fault)**| Static Scrubber + Intel CET `IBT` + `SHSTK` |
| **Case 7: Signal Unwinding (SROP)** | Forged `rt_sigreturn` frame | Overwrites PKRU on stack | **TRAPPED (Signal 7 Bus Error / `#CP`)** | CET User Shadow Stack + Signal Altstack |
| **Case 8: Confused Deputy Attack** | Key 1 pointer passed to `sys_read` | Kernel overwrites state | **REJECTED (`-EFAULT` / `-EPERM`)** | eBPF LSM `bpf_lsm_sys_enter` usercopy filter |
| **Case 9: IPC Descriptor Infiltration**| `SCM_RIGHTS` fd passing over socket | Unauthorized fd injection | **BLOCKED (`-EPERM`)** | eBPF LSM `bpf_lsm_file_receive` validation |

### 2.2 Mandatory Hardware & Kernel Prerequisites

NullGate relies on native hardware primitives and Linux LSM hooks:

* **Intel PKU (`pku` / `ospke`)**: CPU support for Memory Protection Keys and OS activation of CR4.PKE.
* **Intel CET (`ibt` / `user_shstk` or `arch_cet`)**: Hardware Indirect Branch Tracking and User Shadow Stacks.
* **Linux Kernel >= 6.8**: With `CONFIG_BPF_LSM=y` active in `/sys/kernel/security/lsm`.

---

## 3. System Architecture

The platform operates across four integrated execution planes:

```mermaid
graph TD
    App["Application / Client Process"] -->|Phase 4: Transparent Shim / Direct Call| LibNullGate["libnullgate.so Runtime"]

    subgraph "Plane 1: Hardware Memory & Call-Gate Engine (Pillars 1, 4, 5)"
        LibNullGate -->|callgate.S| Trampoline["Hardware Call-Gate Trampoline (148 cycles)"]
        Trampoline -->|WRPKRU| PKRU["Hardware PKRU State (Keys 0..15)"]
        PKRU -->|Key 1 (Supervisor)| StatePage["4KB Quarantined Trusted State (ng_trusted_state)"]
        PKRU -->|Keys 2..15| Compartments["Untrusted Isolated Compartments"]
        Compartments -->|Guard Pages| StackPool["Hardware-Isolated Stack Pool (PROT_NONE)"]
    end

    subgraph "Plane 2: Hardware Zero-Copy IPC (Pillars 1, 7, 8)"
        Compartments -->|Lock-Free SPSC| Ring["64-Byte Cacheline SPSC Shared Ring"]
        Ring -->|Shared PKU Key| PeerCompartment["Peer Destination Compartment"]
    end

    subgraph "Plane 3: In-Kernel eBPF LSM Security Boundary (Pillars 2, 3, 6, 7)"
        Compartments -.->|Syscall Interception| LSM["eBPF LSM Hooks (nullgate_lsm.bpf.o)"]
        LSM -->|bpf_lsm_file_open| BlockProc["Block /proc/$PID/mem & maps"]
        LSM -->|bpf_lsm_ptrace| BlockPtrace["Deny ptrace attach/traceme"]
        LSM -->|bpf_lsm_sys_enter| FilterSys["Block bpf, prctl & Deputy usercopy"]
        LSM -->|bpf_lsm_uring| BlockUring["Deny io_uring setup & commands"]
        LSM --> RingBuf["eBPF Audit Ring Buffer (BPF_MAP_TYPE_RINGBUF)"]
    end

    subgraph "Plane 4: Dynamic Control Plane & Administration (Pillars 3, 8)"
        RingBuf --> Daemon["nullgate-daemon (Epoll Unified Event Loop)"]
        CLI["nullgate-ctl CLI Tool"] -->|Unix Domain Socket /run/nullgate| Daemon
        Daemon -->|bpf_map_update_elem| PolicyMap["In-Kernel ng_domain_policy_map"]
    end
```

### Architectural Pipeline Flow:
```text
  +-------------------+        +----------------------------+        +--------------------------+
  |  Host Application | -----> | libnullgate.so / Call-Gate | -----> | Hardware PKU Compartment |
  | (PKU Key 0: Host) |        | (callgate.S, ~38ns Latency)|        | (Keys 2..15: Untrusted)  |
  +-------------------+        +----------------------------+        +--------------------------+
            |                                                                      |
            | (Key 1 Pointer Trapped)                                              | (Syscall Intercepted)
            v                                                                      v
  +-------------------+        +----------------------------+        +--------------------------+
  | nullgate-daemon   | <====> | eBPF LSM Kernel Boundary   | <----- | Blocked: /proc, ptrace,  |
  | & nullgate-ctl    | RingBuf| (nullgate_lsm.bpf.c)       |        | bpf(), prctl(), io_uring |
  +-------------------+        +----------------------------+        +--------------------------+
```

---

## 4. Directory Structure & Workspace Overview

```text
Nullgate/
├── .clang-format                  # Uniform 4-space C11/C++17 code formatting specification
├── .github/
│   └── workflows/
│       └── ci.yml                 # Dual-tier GitHub Actions CI/CD workflow
├── .gitignore                     # Git tracking exclusions
├── CMakeLists.txt                 # Root CMake build configuration (v1.0.0, install & pkg-config)
├── Makefile                       # Developer convenience wrapper (make, test, bench, verify, clean)
├── CONTRIBUTING.md                # Contributor guide, compiler flags, and zero-WRPKRU invariant
├── LICENSE                        # Apache License 2.0 (Copyright 2026 Sarang Sanjay)
├── README.md                      # Master platform documentation
├── SECURITY.md                    # Security threat scope, hardware prerequisites, disclosure protocol
│
├── benchmarks/                    # Empirical Performance & Reproducibility Harnesses
│   ├── CMakeLists.txt             # Benchmark build targets configuration
│   ├── micro/                     # Cycle-accurate RDTSCP and latency micro-benchmarks
│   │   ├── bench_callgate_rdtscp.c# RDTSCP call-gate transition cycle benchmark
│   │   ├── bench_ipc_latency.c    # Zero-copy SPSC hardware IPC throughput & latency benchmark
│   │   └── bench_syscall_lsm.c    # Syscall & eBPF LSM mediation latency benchmark
│   ├── nginx/                     # Real-world Nginx reverse proxy macro-benchmark
│   │   ├── build_nginx_nullgate.sh# Automated Nginx compilation script
│   │   ├── conf/                  # Nginx configuration profiles
│   │   ├── nginx_worker_compartment.patch # Multi-domain worker isolation patch
│   │   └── run_benchmarks.py      # Automated HTTP request load generator
│   └── sqlite/                    # Real-world SQLite database UDF sandboxing benchmark
│       ├── bench_sqlite_nullgate.py # Automated SQLite benchmark harness & JSON report exporter
│       ├── bench_sqlite_runner.c  # Native C SQLite UDF execution driver
│       ├── sqlite_compartment.c   # SQLite compartment runtime & UDF wrapper
│       ├── sqlite_compartment.h   # SQLite compartment header
│       ├── sqlite_policy.json     # SQLite UDF security policy manifest
│       └── sqlite3_shim.h         # SQLite header shim
│
├── cmake/                         # CMake Hardware Verification Modules
│   ├── nullgate.pc.in             # pkg-config metadata template
│   ├── VerifyCET.cmake            # Post-build readelf Intel CET & NX stack validation module
│   ├── FindBPF.cmake              # eBPF toolchain and libbpf detection
│   └── FindLLVM18.cmake           # LLVM 18 compiler developer package discovery
│
├── docs/                          # Academic & Technical Documentation Suite
│   ├── ARCHITECTURE.md            # Deep-dive 8-pillar mechanics & call-gate internals
│   ├── THREAT_MODEL.md            # Adversarial model, formal invariants & out-of-scope bounds
│   ├── API_REFERENCE.md           # Complete public C API reference manual
│   └── BENCHMARKS.md              # Cycle-level performance analysis & comparative tables
│
├── examples/                      # Developer Starter Kits & Tutorials
│   ├── README.md                  # Quickstart guide for examples
│   ├── 01_basic_compartment/      # Minimal function sandboxing via ng_enter()
│   ├── 02_zero_copy_ipc/          # High-throughput SPSC ring messaging example
│   └── 03_library_shim/           # Zero-code-change LD_PRELOAD library interposition example
│
├── include/                       # Public Canonical C API Headers
│   ├── nullgate.h                 # Master public runtime interface
│   ├── nullgate_abi.h             # Shared kernel/userspace ABI & trusted state layout
│   ├── nullgate_cet.h             # Intel CET assembly macros and GNU property note emitters
│   ├── nullgate_control.h         # Daemon Unix domain control socket framing protocol
│   ├── nullgate_ipc.h             # Zero-copy lock-free SPSC IPC ring definitions
│   ├── nullgate_policy_parser.h   # JSON/YAML dynamic policy manifest schema
│   ├── nullgate_shim.h            # Transparent library preload interposition macros
│   └── nullgate_stack_pool.h      # Guard-paged hardware stack pool interfaces
│
├── policies/                      # Production Security Policy Manifests
│   ├── README.md                  # Policy authoring guide & hot-reloading manual
│   ├── strict.json                # Maximum confinement profile (zero filesystem/network)
│   ├── sqlite_udf.json            # Database extension isolation profile
│   └── network_worker.json        # Network proxy/worker profile
│
├── scripts/                       # Diagnostics, Automation & Service Definitions
│   ├── completion/                # Shell tab-completion scripts
│   │   └── nullgate-ctl.bash      # Bash auto-completion for nullgate-ctl CLI
│   ├── check_env.sh               # 14-point pre-flight hardware & kernel diagnostic script
│   ├── generate_vmlinux.sh        # Kernel BTF vmlinux.h generator script
│   ├── nullgate.service           # Production systemd service unit (Type=notify)
│   ├── nullgate_setup.sh          # Systemd environment & directory provisioning script
│   └── verify_nullgate.sh         # Master end-to-end system certification gate script
│
├── src/                           # Core Implementation Sources
│   ├── bpf/                       # In-Kernel eBPF LSM Programs
│   │   ├── nullgate_sync.bpf.c    # Task storage synchronization & lifecycle tracking
│   │   ├── nullgate_lsm.bpf.c     # LSM hooks (file_open, ptrace, sys_enter)
│   │   ├── nullgate_uring.bpf.c   # Asynchronous io_uring mediation
│   │   └── nullgate_ipc.bpf.h     # SCM_RIGHTS cross-compartment descriptor validation
│   ├── cli/                       # Administrative Control CLI (nullgate-ctl)
│   │   └── nullgate_ctl.c         # nullgate-ctl source (status, reload-policy, query-domain)
│   ├── daemon/                    # Security Daemon (nullgate-daemon)
│   │   ├── main.c                 # Daemon main entry, epoll loop & raw sd_notify
│   │   ├── control_server.c       # Control socket server with SO_PEERCRED auth
│   │   ├── policy_loader.c        # In-kernel BPF map policy loader
│   │   ├── policy_parser.c        # Dynamic JSON policy manifest parser
│   │   └── attestation.c          # Domain state attestation module
│   ├── libnullgate/               # Userspace Runtime Libraries
│   │   ├── init.c                 # Runtime initialization & state allocation
│   │   ├── pku.c                  # PKU domain creation & key assignment
│   │   ├── callgate.S             # Hardware call-gate assembly trampoline
│   │   ├── signal.c               # Signal handler setup on dedicated altstacks
│   │   ├── signal_trampoline.S    # Supervisor signal trampoline & SROP defense
│   │   ├── stack_pool.c           # O(1) guard-paged stack pool allocator
│   │   ├── ipc.c                  # Lock-free zero-copy SPSC hardware IPC channel
│   │   └── shim.c                 # Transparent library preload interposition engine
│   ├── llvm-pass/                 # LLVM 18 Compiler Pass Plugin (libNullGatePass.so)
│   │   └── NullGatePass.cpp       # AST/IR inline wrpkru & direct call interceptor
│   └── scrubber/                  # Static Binary Gadget Scrubber (nullgate-scrubber)
│       ├── elf_scrubber.c         # ELF parser, WRPKRU scanner & CET note auditor
│       └── main.c                 # nullgate-scrubber CLI utility
│
└── tests/                         # Comprehensive Regression & Penetration Test Suites
    ├── unit/                      # Unit tests (pku, callgate, stack_pool, ipc, shim, etc.)
    ├── security/                  # Red-team exploit tests (ptrace, srop, uring, deputy, sqlite)
    └── stress/                    # Multi-threaded concurrency fuzzing stress suites
```

---

## 5. Hardware & Compiler Enforcement Subsystems

### 5.1 Userspace Runtime Engine (`src/libnullgate/`)
* **Output Targets**: `libnullgate.so` (Shared Library), `libnullgate.a` (Static Library), `libnullgate_shim.so` (Transparent Preload Shim).
* **Assembly Trampoline (`callgate.S`)**:
  * Emits `_CET_ENDBR` (`0xf3, 0x0f, 0x1e, 0xfa`) at every entrypoint.
  * Transitions PKRU permissions in userspace via `wrpkru` without kernel transitions.
  * Switches the register stack pointer (`%rsp`) to an isolated compartment stack.
  * Saves and restores the trusted host stack pointer exclusively to the 4KB supervisor state page mapped under Key 1.
* **Hardware-Isolated Stack Pool (`stack_pool.c`)**:
  * Allocates thread-cached stack slots bounded by `PROT_NONE` guard pages.
  * Recycled stack buffers are actively scrubbed with `memset(..., 0, ...)` and a compiler memory barrier to prevent cross-domain data leakage.

### 5.2 LLVM 18 Compiler Pass (`src/llvm-pass/`)
* **Output Target**: `libNullGatePass.so` (LLVM 18 Shared Module Plugin).
* **Security Checks**:
  1. **Inline Assembly Interception**: Scans inline assembly strings for `wrpkru`, opcode bytes (`.byte 0x0f, 0x01, 0xef`), and ASCII representations, immediately aborting compilation.
  2. **Compiler Intrinsic Interception**: Detects calls to `_writepkru()` or `llvm.x86.wrpkru` and terminates compilation with a fatal error.
  3. **Direct Call Bypass Interception**: Restricts direct calls to domain-annotated functions (`__attribute__((nullgate_domain(N)))`), requiring routing through the authorized call-gate dispatcher (`ng_enter`).

### 5.3 Static Binary ELF Scrubber (`src/scrubber/`)
* **Output Target**: `nullgate-scrubber` (Executable).
* **Auditing Capabilities**:
  * Memory-maps target ELF binaries and walks all executable segments (`PT_LOAD` with `PF_X`).
  * Scans byte-by-byte for unintended `wrpkru` opcodes (`0F 01 EF`) created by compiler register allocation or padding bytes.
  * Audits `.note.gnu.property` sections, verifying that Intel CET `IBT` and User Shadow Stack (`SHSTK`) feature bits are present.
  * In strict mode (`--strict`), fails with exit code 1 if unauthorized gadgets or missing CET notes are detected.

---

## 6. In-Kernel eBPF LSM & Dynamic Control Plane

### 6.1 Kernel Security Hooks (`src/bpf/`)
* **`nullgate_sync.bpf.c`**:
  * Tracks task lifecycle via `bpf_lsm_task_alloc` and `bpf_lsm_task_free`.
  * Clones domain security contexts across `fork()` and `clone()` into kernel task storage (`ng_task_storage`).
  * Enforces one-way registration locking (`NG_TASK_LOCKED`) via `bpf_lsm_task_prctl`.
* **`nullgate_lsm.bpf.c`**:
  * `bpf_lsm_file_open`: Intercepts `dentry` lookups and blocks untrusted compartment access to `/proc/<pid>/mem`, `/proc/<pid>/maps`, `/proc/<pid>/pagemap`, and `/proc/<pid>/auxv`.
  * `bpf_lsm_ptrace_access_check`: Denies `ptrace(PTRACE_ATTACH)` and `ptrace(PTRACE_TRACEME)` when an untrusted compartment is involved.
  * `bpf_lsm_sys_enter`: Enforces the 256-bit syscall whitelist bitmask, blocks `bpf()`, `prctl()`, `keyctl()`, and validates usercopy memory pointers against Key 1 supervisor memory.
* **`nullgate_uring.bpf.c`**:
  * Intercepts `io_uring` setup, enter, register, and command operations, blocking untrusted compartments from bypassing synchronous syscall hooks via kernel worker threads.

### 6.2 Administrative Control Plane (`src/daemon/` & `src/cli/`)
* **`nullgate-daemon`**:
  * Production background service running under systemd (`Type=notify`).
  * Multiplexes the eBPF audit ring buffer and Unix domain control socket (`/run/nullgate/control.sock`) via a single-threaded non-blocking `epoll` loop.
  * Authenticates all incoming socket connections via `SO_PEERCRED` (`uid == 0`).
  * Hardened directory management using `open(..., O_DIRECTORY | O_NOFOLLOW)` and `fchmod(dfd, 0700)`, eliminating symlink TOCTOU vulnerabilities.
* **`nullgate-ctl`**:
  * Standalone CLI tool supporting tabular and JSON output modes (`--json`).
  * Commands: `status`, `ping`, `list-domains`, `query-domain <id>`, `query-pid <pid>`, `reload-policy <file>`, and `dump-audit`.

---

## 7. Empirical Benchmarking & Comparative Analysis

### 7.1 Formal Mathematical Formulations of Metrics

1. **Call-Gate Transition Overhead Delta ($\Delta_{\text{callgate}}$)**:
   $$\Delta_{\text{callgate}} = T_{\text{gate}}(\text{ng\_enter}) - T_{\text{direct}}(\text{C Function Call})$$

2. **IPC Throughput Capacity ($R_{\text{ipc}}$)**:
   $$R_{\text{ipc}} = \frac{N_{\text{messages}}}{\Delta t_{\text{elapsed}}}$$

3. **Database Extension Isolation Overhead ($P_{\text{overhead}}$)**:
   $$P_{\text{overhead}} = \left( \frac{T_{\text{sandboxed}} - T_{\text{native}}}{T_{\text{native}}} \right) \times 100\%$$

---

### 7.2 Empirical Benchmark Summary Table (Exact Measurement Values)

Evaluated on an **Intel Core Ultra 7 processor** running Linux 7.0 / 6.8+ with active BPF LSM:

| Evaluation Metric Category | Baseline Native Metric | NullGate Measurement | Unit / Delta | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Direct C Function Call** | **26 cycles** (P50) | N/A | CPU cycles | Baseline |
| **Raw Call-Gate Trampoline**| N/A | **136 cycles** (P50) | +110 cycles (~35 ns) | **PASSED** |
| **Public Call-Gate API (`ng_enter`)**| N/A | **148 cycles** (P50) | +122 cycles (~38 ns) | **PASSED** |
| **Hardware Zero-Copy IPC Latency** | N/A | **38.84 ns (58 cycles)** | ns / roundtrip | **PASSED** |
| **Zero-Copy IPC Throughput** | N/A | **25.75 Million msgs/sec** | msgs / second | **PASSED** |
| **Raw `getpid()` Latency** | 236 cycles (P50) | **336 cycles** (P50) | +100 cycles (~31 ns) | **PASSED** |
| **Raw `read(0)` Latency** | 280 cycles (P50) | **400 cycles** (P50) | +120 cycles (~37 ns) | **PASSED** |
| **SQLite UDF Query Throughput** | 271,696.89 QPS | **263,783.18 QPS** | -2.91% throughput | **PASSED** |
| **SQLite UDF Average Latency** | 3,680.57 ns | **3,790.99 ns** | **+3.00% Overhead** (<= 5.0% Budget)| **PASSED** |
| **Nginx HTTP Request Rate** | 42,150 req/s | **41,365 req/s** | **+1.86% Overhead** (<= 4.0% Budget)| **PASSED** |
| **Nginx Mean Latency** | 1.18 ms | **1.20 ms** | +1.69% latency | **PASSED** |

---

### 7.3 Security Mitigation Comparative Analysis Table

| Security Feature / Metric | Intel CET Alone | Clang CFI | Seccomp-BPF | WebAssembly (Wasmtime) | **NullGate Platform (This Work)** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Hardware Requirement** | Tiger Lake+ | Hardware Agnostic | Generic Linux | Generic x86_64 | **Intel PKU (`ospke`) + CET (`ibt`/`shstk`)** |
| **Isolation Scope** | Control-Flow Only | Indirect Calls | System Call Filter | Linear Memory Sandbox | **Intra-Process Hardware Memory + Syscall + LSM** |
| **Boundary Crossing Cost** | ~10–15 ns | ~5–10 ns | ~1,200–2,500 ns | ~350–800 ns | **~38 ns (148 cycles)** |
| **WRPKRU Gadget Defense**| None | None | None | None | **Zero-Tolerance Static Scrubber + LLVM Pass** |
| **Procfs / Ptrace Defense**| None | None | Partial | N/A | **100% Kernel eBPF LSM Interception** |
| **SROP Sigreturn Defense**| Partial (`SHSTK`) | None | None | N/A | **CET User Shadow Stack + Signal Trampoline** |
| **Third-Party C ABI Compat**| Full | Requires Recompile | Full | Requires Porting | **100% Native C ABI (`libnullgate_shim.so`)** |
| **Workload Overhead Impact**| < 1.0% | 2.0–6.0% | 5.0–15.0% | 10.0–30.0% | **< 3.0% Overhead (SQLite & Nginx)** |

---

## 8. Prerequisites & Environment Requirements

Ensure your Linux environment meets the following specifications:

- **Processor**: x86_64 CPU supporting Intel PKU (`pku` and `ospke` flags in `/proc/cpuinfo`) and Intel CET (`ibt` and `user_shstk` / `arch_cet`).
- **Operating System**: Linux Kernel >= 6.8 with `CONFIG_BPF_LSM=y` active (verified via `/sys/kernel/security/lsm`).
- **Compiler Toolchain**: Clang 18 (`clang-18`), LLVM 18 (`llvm-18-dev`), CMake >= 3.28, GNU Make, binutils (`readelf`, `objdump`).
- **Kernel Libraries**: `libbpf-dev`, `bpftool`, `libelf-dev`, `linux-libc-dev`.
- **Python Environment**: Python 3.10+ (for benchmark harnesses and CLI validation).

Run `scripts/check_env.sh` or `scripts/verify_nullgate.sh` to validate all 14 mandatory host prerequisites automatically.

---

## 9. Quick Start / Build & Run Guide

Users have two flexible choices for building and running NullGate:

### Mode 1: Unified Single-Command Verification (RECOMMENDED)

Execute the master certification script from the repository root to verify hardware prerequisites, compile all targets with strict CET flags, run the static gadget scrubber, and execute the complete 24-test regression suite:

```bash
# 1. Clone the repository
git clone https://github.com/Sarang-Sanjay/NullGate.git
cd NullGate

# 2. Build and verify everything with one command
make verify
```

Alternatively, invoke the standalone certification gate directly:
```bash
bash scripts/verify_nullgate.sh
```

---

### Mode 2: Manual Standalone Subsystem Execution

#### 1. Build Entire Workspace via CMake
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

#### 2. Execute Automated CTest Regression Matrix (24/24 Tests)
```bash
ctest --test-dir build --output-on-failure
```

#### 3. Run Developer Starter Examples
```bash
# Example 1: Basic Compartmentalization
make -C examples/01_basic_compartment run

# Example 2: Hardware Zero-Copy SPSC IPC
make -C examples/02_zero_copy_ipc run

# Example 3: Transparent Library Preload Shim
make -C examples/03_library_shim run
```

#### 4. Execute Real-World Database & Micro-Benchmarks
```bash
# RDTSCP Call-Gate Latency Micro-Benchmark
./build/benchmarks/micro/bench_callgate_rdtscp

# Zero-Copy SPSC IPC Micro-Benchmark
./build/benchmarks/micro/bench_ipc_latency

# Syscall & LSM Mediation Micro-Benchmark
./build/benchmarks/micro/bench_syscall_lsm

# Real-World SQLite UDF Sandboxing Benchmark
python3 benchmarks/sqlite/bench_sqlite_nullgate.py
```

#### 5. Launch Administrative Daemon & Query via CLI
```bash
# Start background security daemon (requires root for eBPF LSM attachment)
sudo ./build/src/daemon/nullgate-daemon --smoke-test

# Query daemon status via CLI
./build/src/cli/nullgate-ctl status

# Inspect active domain policies
./build/src/cli/nullgate-ctl list-domains

# Hot-reload security policy manifest
sudo ./build/src/cli/nullgate-ctl reload-policy policies/strict.json
```

---

## 10. Validation & Verification Demonstrations

### Demonstration 1: Complete Repository CTest Suite (24 / 24 Passed)
Execute the complete CTest runner across all 24 unit, security, and stress test targets:

```bash
ctest --test-dir build --output-on-failure
```

### Demonstration 2: Pillar 4 Static Scrubber 0-WRPKRU Audit
Verify that zero reachable `wrpkru` gadgets exist in application code and binaries:

```bash
./build/src/scrubber/nullgate-scrubber --strict ./build/src/daemon/nullgate-daemon
./build/src/scrubber/nullgate-scrubber --strict ./build/src/cli/nullgate-ctl
./build/src/scrubber/nullgate-scrubber --strict ./build/src/libnullgate/libnullgate_shim.so
```

### Demonstration 3: Intel CET IBT & User Shadow Stack (SHSTK) ELF Audit
Audit ELF notes and non-executable stack properties:

```bash
readelf -n ./build/src/daemon/nullgate-daemon | grep -E "IBT|SHSTK"
readelf -l ./build/src/daemon/nullgate-daemon | grep -A 1 "GNU_STACK"
```

---

## 11. Technical Documentation & Community Guides

Detailed architectural specifications, API references, and manuals are available in the [docs/](docs/) directory:

* **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**: In-depth technical breakdown of the 8 security pillars, process virtual address space layout, supervisor state page quarantine under Key 1, eBPF LSM mediation points, and assembly trampoline mechanics.
* **[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)**: Formal threat model defining adversary capabilities, in-scope threat matrix, explicit out-of-scope boundaries, and mathematical invariants.
* **[docs/API_REFERENCE.md](docs/API_REFERENCE.md)**: Complete C reference manual for `nullgate.h`, `nullgate_ipc.h`, `nullgate_stack_pool.h`, and `nullgate_shim.h`.
* **[docs/BENCHMARKS.md](docs/BENCHMARKS.md)**: Cycle-accurate latency measurements, throughput analysis, and comparative isolation technology tables.
* **[policies/README.md](policies/README.md)**: Security policy manifest schema and runtime hot-reloading guide.
* **[examples/README.md](examples/README.md)**: Step-by-step tutorial for building and integrating compartments.

---

## 12. License & Citation

NullGate is open-source software released under the **[Apache License 2.0](LICENSE)**.

```text
NullGate: Kernel-Enforced Intra-Process Isolation via Hardware PKU, Intel CET & eBPF LSM
Copyright (c) 2026 Sarang Sanjay. All rights reserved.
```
