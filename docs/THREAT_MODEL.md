# NullGate Threat Model & Security Invariants

NullGate is engineered to enforce intra-process least-privilege compartmentalization under an adversarial model where software components executing within a compartment are assumed to be malicious, compromised, or vulnerable to memory corruption.

---

## 1. Adversary Model & Capabilities

We assume an adversary with the following capabilities:

* **Full In-Compartment Control:** The adversary has achieved arbitrary read, write, and execution capabilities inside an untrusted compartment (e.g., via buffer overflow, use-after-free, or malicious extension source code).
* **Knowledge of Address Space Layout:** The adversary knows the full virtual memory layout, symbols, libc addresses, and code pointers of the host process (i.e. ASLR bypass is assumed).
* **Hardware Architecture Access:** The adversary can execute any unprivileged x86_64 assembly instruction, including system calls (`syscall`), control-flow instructions, and floating-point/vector operations.
* **Intra-Process Concurrency:** The adversary may spawn concurrent threads or cooperate with peer threads executing in other untrusted compartments to mount race conditions or time-of-check to time-of-use (TOCTOU) attacks.

---

## 2. In-Scope Security Threat Matrix

NullGate guarantees containment against the following attack vectors:

| Threat Category | Specific Attack Vector | NullGate Defense Mechanism |
| :--- | :--- | :--- |
| **Spatial Memory Violation** | Untrusted code attempting to read or overwrite host memory or supervisor state | Hardware PKU tags on pages. Key 0 (host default) and Key 1 (trusted state) are revoked (`AD=1, WD=1`) during compartment execution. Traps with hardware `SEGV_PKUERR`. |
| **Memory Snooping via OS** | Reading peer memory via `/proc/$PID/mem`, `/proc/$PID/maps`, `/proc/$PID/pagemap`, or `ptrace(PTRACE_ATTACH)` | eBPF LSM `bpf_lsm_file_open` and `bpf_lsm_ptrace_access_check` inspect the calling task's domain storage and deny access with `-EACCES`. |
| **Sandbox Self-Tampering** | Overriding seccomp filters, replaying registration, or calling `prctl()` / `bpf()` | eBPF LSM `bpf_lsm_sys_enter` filters syscall numbers, blocking `bpf`, `prctl`, `keyctl`, and `capset`. Registration is locked permanently with `NG_TASK_LOCKED`. |
| **Hardware Gadget Harvesting** | Searching code segments for unintended `wrpkru` byte sequences (`0F 01 EF`) to unlock PKRU permissions | Pillar 4 static binary scrubber `nullgate-scrubber --strict` scans all executable segments; LLVM compiler pass blocks IR assembly injection; Intel CET IBT requires valid `_CET_ENDBR` landing pads. |
| **Control-Flow Hijacking (ROP/JOP)** | Overwriting stack return addresses or function pointers to jump into supervisor code | Intel CET User Shadow Stack (`SHSTK`) prevents return address forgery; CET IBT restricts indirect branch targets to authorized entry points. |
| **Signal-Based Unwinding (SROP)** | Forging a fake `ucontext_t` on the stack and calling `rt_sigreturn` to overwrite the PKRU register | CET User Shadow Stack validates signal frame integrity; supervisor signal trampoline sanitizes XSAVE PKRU state before dispatch. |
| **Asynchronous I/O Bypass** | Registering `io_uring` SQPOLL kernel threads to perform unauthorized I/O asynchronously | eBPF LSM hooks on `io_uring_setup`, `io_uring_enter`, and `io_uring_register` strictly deny `io_uring` creation or personality registration from untrusted domains. |
| **Confused Deputy Infiltration** | Passing pointers to supervisor Key 1 memory into system calls (`read`, `write`, `connect`) | eBPF LSM `bpf_lsm_sys_enter` validates usercopy memory addresses against the Key 1 range, failing suspicious calls with `-EFAULT` / `-EPERM`. |
| **Shared-Memory TOCTOU** | Mutating IPC ring buffer capacity or message lengths concurrently to cause OOB reads | Channel capacity is stored exclusively in private unshared heap descriptors (`chan->capacity`), completely ignoring mutable shared-memory capacity fields. |
| **Cross-Domain Secret Leaks** | Re-using stack slots or IPC channels containing remnants of sensitive peer compartment data | Recycled stack frames are actively scrubbed with `memset(..., 0, ...)` and a compiler memory barrier before assignment to new domains. |

---

## 3. Out-of-Scope Threat Vectors

The following vectors are outside NullGate's defense scope:

1. **Hardware & Physical Access:**
   * Physical DRAM probing, bus interposers, cold-boot attacks, and JTAG hardware debuggers.
2. **Transient-Execution Side-Channels:**
   * Speculative execution attacks (Spectre, Meltdown, Foreshadow, MDS, Downfall). NullGate enforces architectural protection; microarchitectural isolation must be provided by the CPU microcode and kernel page-table isolation.
3. **Kernel Zero-Days:**
   * Exploits that corrupt kernel data structures directly or compromise the eBPF LSM subsystem.
4. **Hardware Glitching & Fault-Injection:**
   * Rowhammer bit-flips, voltage undervolting, or clock glitching.
5. **Pure Computation Denial of Service:**
   * An untrusted compartment entering an infinite CPU loop without invoking system calls (must be mitigated via OS CPU quotas or external watchdog timers).

---

## 4. Formal Security Invariants

NullGate maintains the following mathematical invariants:

$$\forall \text{ thread } T \text{ in domain } D \ge 1, \quad \text{PKRU}[2 \cdot \text{key}_1 : 2 \cdot \text{key}_1 + 1] = 11_b \quad (\text{Access Denied, Write Disabled})$$

$$\forall \text{ untrusted domain } D \ge 1, \quad \text{PKU-Key}(D) \in \{2, 3, \dots, 15\} \quad (\text{Key 0 and Key 1 are strictly reserved})$$

$$\forall \text{ instruction } I \in \text{Executable-Segments}(P), \quad I \neq \texttt{0F 01 EF}_{16} \iff I \in \{\text{callgate.S}, \text{signal-trampoline.S}\}$$
