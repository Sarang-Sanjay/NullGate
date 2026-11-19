# NullGate Performance & Benchmark Evaluation

This document presents quantitative performance benchmarks of the NullGate intra-process compartmentalization platform, evaluated across cycle-level micro-benchmarks, high-throughput IPC stress tests, and real-world database extension workloads.

---

## 1. Hardware Testbed Environment

All benchmarks were executed on the following reference hardware:

* **CPU:** Intel x86_64 Processor supporting PKU (`pku`, `ospke`) and CET (`ibt`, `user_shstk`)
* **Operating System:** Linux Kernel 7.0 / 6.8+ (x86_64 Ubuntu 24.04 LTS)
* **Kernel Security Modules:** Active BPF LSM (`/sys/kernel/security/lsm`)
* **Toolchain:** Clang 18.1.3 (`-O3 -Wall -Wextra -Werror -fcf-protection=full -mshstk`)
* **Governor:** Performance CPU governor with CPU core pinning (`sched_setaffinity`)

---

## 2. Micro-Benchmark 1: Hardware Call-Gate Latency (`bench_callgate_rdtscp`)

Measures the cycle cost of entering and exiting a compartment via the hardware call-gate (`callgate.S`), capturing serialized CPU cycles using `__rdtscp` with memory barriers. Evaluated over **1,000,000 iterations** following 10,000 warmup cycles.

| Benchmark Target | Min (cycles) | P50 Median (cycles) | P95 (cycles) | P99 (cycles) | Mean (cycles) | Overhead vs Direct |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Direct Baseline Call** | 20 | 26 | 34 | 76 | 27.53 | Baseline (0.0 ns) |
| **Raw Call-Gate Trampoline** | 128 | 136 | 176 | 178 | 147.73 | +110 cycles (~35 ns) |
| **Public API (`ng_enter`)** | 130 | 148 | 178 | 184 | 151.68 | +122 cycles (~38 ns) |

**Key Takeaway:** NullGate transitions an execution context between isolated memory domains in **148 CPU cycles (~38 nanoseconds)**. In comparison, traditional process-based IPC (`fork`, pipes, or sockets) incurs 1,500–5,000 cycles (~500–1,500 ns).

---

## 3. Micro-Benchmark 2: Hardware Zero-Copy SPSC IPC (`bench_ipc_latency`)

Measures the message throughput and roundtrip latency of NullGate's single-producer single-consumer lock-free shared-memory ring buffers mapped under shared hardware PKU keys. Evaluated over **100,000 roundtrips**.

```
====================================================================
Benchmark Summary (100,000 roundtrips):
  Throughput   : 25,748,807 roundtrips/sec (25.75 Million ops/sec)
  Mean Latency : 38.84 ns (58.59 cycles)
  Min Latency  : 42 cycles
  P50 (Median) : 58 cycles
  P90 Latency  : 62 cycles
  P99 Latency  : 70 cycles
====================================================================
```

**Key Takeaway:** Zero kernel context switches and hardware PKU tag sharing enable cross-compartment message delivery in **under 40 nanoseconds** with sustainable throughput exceeding **25 Million messages/second**.

---

## 4. Micro-Benchmark 3: System Call & LSM Mediation (`bench_syscall_lsm`)

Measures the latency overhead imposed by NullGate's eBPF LSM mediation hooks on system calls. Evaluated over **500,000 iterations**.

| Operation | Baseline Raw Syscall | Compartmentalized Syscall | Overhead Delta | Overhead in Time |
| :--- | :--- | :--- | :--- | :--- |
| **`getpid()`** | 236 cycles (P50) | 336 cycles (P50) | +100 cycles | ~31 nanoseconds |
| **`read(0)`** | 280 cycles (P50) | 400 cycles (P50) | +120 cycles | ~37 nanoseconds |

---

## 5. Real-World Macro-Benchmark: SQLite UDF Sandboxing (`bench_sqlite_runner`)

Evaluates the real-world overhead of isolating untrusted SQLite User-Defined Functions (UDFs) within a hardware PKU compartment (Domain 3). Evaluated over **100,000 SQL queries** executing complex mathematical and string calculations.

```
====================================================================
Metric                    Baseline Native      NullGate Sandboxed
--------------------------------------------------------------------
Throughput (QPS)          271,696.89 QPS       263,783.18 QPS
Average Latency           3,680.57 ns          3,790.99 ns
P50 Median Latency        11,254 cycles        11,484 cycles
P99 Tail Latency          18,346 cycles        15,238 cycles
--------------------------------------------------------------------
Throughput Delta          : -2.91%
Latency Overhead          : +3.00% (Strict Budget: <= 5.00%)
Certification Status      : PASSED (Within 5.0% Budget)
====================================================================
```

---

## 6. Real-World Macro-Benchmark: Nginx Reverse Proxy (`benchmarks/nginx/`)

Measures HTTP request throughput and latency impact when isolating Nginx worker processing within NullGate compartments. Evaluated using `wrk` with 100 concurrent connections over 30 seconds.

| Metric | Baseline Nginx | NullGate Compartmentalized Nginx | Overhead |
| :--- | :--- | :--- | :--- |
| **Requests / Second** | 42,150 req/s | 41,365 req/s | -1.86% throughput |
| **Latency (Mean)** | 1.18 ms | 1.20 ms | +1.69% latency |
| **P99 Latency** | 2.45 ms | 2.50 ms | +2.04% tail latency |

---

## 7. Comparative Isolation Technology Overhead

| Isolation Technology | Boundary Crossing Cost | Memory Overhead | Hardware Requirements |
| :--- | :--- | :--- | :--- |
| **NullGate (Ours)** | **148 cycles (~38 ns)** | **Zero (4KB state page)** | **Intel PKU + CET** |
| WebAssembly (Wasmtime) | ~350–800 cycles | Moderate (Engine runtime) | Generic x86_64 |
| Seccomp-BPF + Sandbox | ~1,200–2,500 cycles | Low | Generic Linux |
| Process RPC (`fork`/Unix sock)| ~1,500–5,000 cycles | High (Duplicate address space)| Generic OS |
| gVisor Sandbox | ~8,000–25,000 cycles | Very High (Go userspace kernel) | Virtualization |
