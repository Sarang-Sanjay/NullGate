# NullGate Architectural Specification

NullGate is an intra-process, hardware-enforced memory compartmentalization platform for x86_64 Linux. It provides near-zero overhead (< 40 ns) spatial and temporal isolation between software components residing within the same address space.

---

## 1. High-Level Architecture Overview

Traditional process-based isolation (e.g. `fork()` + Unix domain sockets or RPC) incurs heavy performance costs (1,000–5,000 CPU cycles per boundary crossing) due to TLB shootdowns, kernel context switches, and page-table swaps. 

NullGate eliminates this overhead by enforcing isolation at hardware wire-speed using **Intel Memory Protection Keys (PKU/MPK)**, while sealing all user-kernel and intra-process escape vectors using **Intel Control-Flow Enforcement Technology (CET)**, **Linux eBPF LSM**, and **compiler-level gadget scrubbing**.

```
+---------------------------------------------------------------------------------------------------+
|                                  NullGate Process Address Space                                   |
+---------------------------------------------------------------------------------------------------+
|  Domain 0: Host / Application Runtime (PKU Key 0: Default read/write)                             |
|  - Main event loop, business logic, public APIs, libc runtime                                     |
+---------------------------------------------------------------------------------------------------+
|  Supervisor State Page (PKU Key 1: 4096-byte dedicated page, PROT_READ | PROT_WRITE)               |
|  - struct ng_trusted_state (Active domain ID, saved trusted RSP, monotonic violation counter)     |
|  - INVARIANT: Key 1 is strictly disabled (AD=1, WD=1 in PKRU) whenever untrusted code executes    |
+---------------------------------------------------------------------------------------------------+
|  Domain 1..15: Untrusted Sandboxed Compartments (PKU Keys 2..15)                                  |
|  - Isolated stacks bounded by PROT_NONE guard pages                                              |
|  - Zero-Copy IPC SPSC Ring Buffers mapped under negotiated shared PKU keys                        |
|  - Unmodified third-party libraries (JSON parsers, image decoders, SQLite UDFs)                   |
+---------------------------------------------------------------------------------------------------+
                                            | Hardware Call-Gate (ng_enter / callgate.S)
                                            v
+---------------------------------------------------------------------------------------------------+
|                                      Kernel Space & eBPF LSM                                      |
+---------------------------------------------------------------------------------------------------+
|  eBPF Task Storage (ng_task_storage): Task registration locked permanently via NG_TASK_LOCKED      |
|  eBPF LSM Hooks:                                                                                  |
|  - bpf_lsm_file_open: Blocks /proc/<pid>/mem, /proc/<pid>/maps, /proc/<pid>/pagemap reconnaissance|
|  - bpf_lsm_ptrace_access_check: Denies ptrace attach/traceme                                      |
|  - bpf_lsm_sys_enter: Blocks bpf(), prctl(), keyctl(), and validates usercopy pointers           |
|  - bpf_lsm_uring_cmd: Denies asynchronous io_uring setup and SQPOLL personality injection         |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. The 8 Security Pillars

### Pillar 1: Hardware Memory Spatial Boundary (Intel PKU/MPK)
* **Mechanisms:** Leverages the 32-bit user-accessible `PKRU` register (`CR4.PKE`). Each 4KB page in the page table encodes a 4-bit Protection Key (0–15).
* **Domain Allocation:**
  * **Key 0:** Default host application memory.
  * **Key 1:** Dedicated supervisor state page (`struct ng_trusted_state`). Aligned to 4096 bytes and sized to exactly 4096 bytes.
  * **Keys 2–15:** Assigned dynamically to untrusted compartments.
* **Invariant:** While executing inside an untrusted compartment ($d \ge 1$), Key 1 and Key 0 are revoked in the PKRU register (`AD=1, WD=1`). Any attempt to access unauthorized memory raises a hardware `#PF` decoded as `SEGV_PKUERR` (`si_code == 2`).

### Pillar 2: Anti-Snooping Defense (procfs & ptrace)
* **Threat:** Malicious compartment code attempts to read host memory or supervisor keys via `/proc/self/mem`, inspect page tables via `/proc/self/pagemap`, or attach via `ptrace(PTRACE_ATTACH)`.
* **Mitigation:**
  * eBPF LSM hooks `bpf_lsm_file_open` and `bpf_lsm_file_receive` inspect path dentries against the calling task's active domain ID. Any open request for `/proc/<pid>/mem`, `/proc/<pid>/maps`, `/proc/<pid>/pagemap`, or `/proc/<pid>/auxv` from an untrusted domain returns `-EACCES`.
  * `bpf_lsm_ptrace_access_check` and `bpf_lsm_ptrace_traceme` block tracing when either the tracer or tracee is in an untrusted domain.

### Pillar 3: Anti-Self-Tampering & Execution Lockdown
* **Threat:** Malicious compartment code attempts to load rogue eBPF programs, alter seccomp filters, or replay `PRCTL_MAGIC_REGISTER` to clear its confinement flags.
* **Mitigation:**
  * `bpf_lsm_sys_enter` intercepts `__NR_bpf`, `__NR_prctl`, `__NR_keyctl`, and `__NR_capset`, returning `-EPERM` when domain ID $\ge 1$.
  * Initial registration sets `NG_TASK_LOCKED (1ULL << 0)` in kernel task storage. Subsequent registration attempts are rejected.

### Pillar 4: Call-Gate Hardware Gadget Quarantine & Intel CET
* **Pillar 4 Invariant:** **Zero `wrpkru` instructions (`0F 01 EF`) across all C code and binaries.**
* **Supervisor Assembly Quarantine:** `wrpkru` is quarantined strictly to supervisor assembly entry points:
  * `__ng_callgate_drop_privs` and `__ng_callgate_restore_privs` in `src/libnullgate/callgate.S`.
  * `ng_signal_trampoline` in `src/libnullgate/signal_trampoline.S`.
* **Hardware CET Compliance:**
  * All binaries compile with `-fcf-protection=full -mshstk`.
  * Every ELF file enforces Indirect Branch Tracking (`_CET_ENDBR` / `0xf3 0x0f 0x1e 0xfa`) and User Shadow Stack (`SHSTK`), validated post-build by `cmake/VerifyCET.cmake`.
  * The static binary scrubber `nullgate-scrubber --strict` audits all segments for unintended gadget sequences.

### Pillar 5: Asynchronous Signal & Altstack Safety
* **Threat:** Asynchronous signals arriving during untrusted execution could execute sighandlers on a dirty untrusted stack, or an adversary could forge a signal frame (`ucontext_t`) to execute SROP (`rt_sigreturn`) and overwrite the PKRU register.
* **Mitigation:**
  * Dedicated hardware-isolated signal alternative stack (`sigaltstack`) configured with `SS_ONSTACK`.
  * Supervisor signal trampoline restores trusted PKRU, sanitizes the XSAVE header (zeroing untrusted PKRU overrides), and CET SHSTK blocks SROP (`rt_sigreturn`) forgery.
  * Controlled instruction pointer skip recovery on `SEGV_PKUERR` allows graceful trap recovery without process crashes.

### Pillar 6: Task Lifecycle & Process Hierarchy Protection
* **Threat:** An untrusted compartment forks or spawns threads to escape confinement or inherit uninitialized security contexts.
* **Mitigation:**
  * eBPF LSM `bpf_lsm_task_alloc` and `bpf_lsm_task_free` hook process creation and termination. Child processes and threads automatically inherit parent security contexts and domain policy restrictions.
  * Thread-local stack pool destructors (`pthread_key_create(&g_pool_key, thread_destructor)`) automatically release and `munmap()` isolated stack slots upon thread exit, preventing thread resource leaks.

### Pillar 7: System Call & Kernel Asynchronous I/O Mediation
* **Threat:**
  * Confused deputy pointer infiltration: Untrusted code passes pointers to trusted Key 1 state into system calls like `read()`, `write()`, or `connect()`.
  * Asynchronous `io_uring` bypass: Untrusted code sets up an `io_uring` instance or registers SQPOLL kernel threads to bypass synchronous syscall hooks.
* **Mitigation:**
  * `bpf_lsm_sys_enter` validates user pointers for `sys_read`, `sys_write`, `sys_connect`, `sys_open`, and `sys_sendto`. Pointers within the Key 1 trusted range fail with `-EFAULT` / `-EPERM`.
  * eBPF LSM `bpf_lsm_uring_cmd`, `bpf_lsm_socket_connect`, and `bpf_lsm_file_open` strictly deny `io_uring_setup`, `io_uring_enter`, and `io_uring_register` operations from untrusted domains.

### Pillar 8: Dynamic Policy Engine, IPC & Transparent Interposition
* **Dynamic Policy Engine:** JSON/YAML policy manifests validated by `policy_parser.c`. Administrative Unix domain control socket (`/run/nullgate/control.sock`) with `SO_PEERCRED` root validation and `epoll` multiplexing against the eBPF audit ring buffer.
* **Zero-Copy Lock-Free IPC:** Cacheline-aligned (64-byte) single-producer single-consumer (SPSC) lock-free ring buffers mapped under shared PKU keys. Bounds arithmetic relies exclusively on private descriptors (`chan->capacity`), preventing shared-memory TOCTOU corruption.
* **Transparent Library Preload Shim (`libnullgate_shim.so`):** Interposition macros (`NG_INTERPOSE_FUNC_*`, `NG_INTERPOSE_VOID_FUNC_*`) enable zero-code-change wrapping of third-party libraries. Re-entrancy guarded via runtime hardware domain check (`ng_get_active_domain() == dom_id`) and automatic depth reset (`ng_shim_reset_depth()`) on `ng_enter` return.

---

## 3. Hardware Call-Gate Sequence (`callgate.S`)

The hardware call-gate transition executes entirely in userspace without kernel context switches:

```
HOST RUNTIME (Domain 0)                         COMPARTMENT (Domain D)
  |                                                  |
  |-- 1. Call ng_enter(dom_id, func, arg)            |
  |-- 2. Lookup thread trusted state (FS:t_state)    |
  |-- 3. Save host RSP to state->trusted_rsp         |
  |-- 4. Switch RSP to isolated compartment stack    |
  |-- 5. Set state->current_domain = dom_id          |
  |-- 6. Load target PKRU into %eax                  |
  |-- 7. Execute WRPKRU (Key 0 & 1 revoked) -------->|
                                                     |-- 8. Execute untrusted function
                                                     |-- 9. Complete computation
  |<-- 10. Call-gate return path --------------------|
  |-- 11. Clear %eax (Restore trusted PKRU)          |
  |-- 12. Execute WRPKRU (Supervisor privs restored) |
  |-- 13. Restore host RSP from state->trusted_rsp   |
  |-- 14. Reset state->current_domain = 0            |
  |-- 15. Return result to caller                    |
  v                                                  v
```
