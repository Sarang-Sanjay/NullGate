# NullGate Security Policy Manifests

This directory contains production security policy manifests for the NullGate platform. Policies define fine-grained memory quotas, PKU hardware key assignments, security defense flags, and syscall whitelist bitmasks for all 16 domains.

---

## Manifest Schema Overview

```json
{
  "magic": 1313296463,       // "NGPO" (0x4E47504F)
  "version": 1,              // Manifest schema version
  "num_domains": 16,         // Authoritative domain count (always 16)
  "flags": 0,
  "domains": [
    {
      "id": 1,               // Domain ID (0..15)
      "name": "worker",      // Human-readable identifier (up to 32 chars)
      "pku_key": 2,          // Hardware PKU key (Keys 2..15 for untrusted domains)
      "max_memory_pages": 1024, // Quota in 4KB hardware pages (0 = unconstrained)
      "flags": [             // Active defense invariants
        "STRICT_WX",         // Enforces Write-XOR-Execute memory protection
        "BLOCK_PTRACE",      // Intercepts and denies ptrace attach/traceme
        "BLOCK_PROCFS",      // Denies /proc/<pid>/mem, maps, and pagemap access
        "BLOCK_BPF",         // Blocks rogue eBPF program loading and maps
        "BLOCK_URING",       // Denies asynchronous io_uring setup and commands
        "DEPUTY_GUARD",      // Traps kernel usercopy pointer infiltration
        "STRICT_SYSCALL"     // Enforces strict whitelist bitmask below
      ],
      "allowed_syscalls": [  // Whitelist of allowed x86_64 syscall numbers
        0, 1, 3, 60, 231
      ]
    }
  ]
}
```

---

## Built-In Security Profiles

1. **`strict.json`:**
   * Maximum confinement profile for pure compute engines, crypto modules, and text parsers.
   * Zero filesystem access, zero networking, zero ptrace, zero io_uring.
2. **`sqlite_udf.json`:**
   * Tailored profile for database user-defined function (UDF) extensions.
   * Isolates extension execution under hardware PKU Key 3 with memory isolation and zero unmediated OS writes.
3. **`network_worker.json`:**
   * Profile for high-throughput network proxies and web workers.
   * Allows socket I/O, connect, and epoll while preventing memory inspection, ptrace snooping, and kernel self-tampering.

---

## Hot-Reloading Policies at Runtime

Security policies can be reloaded dynamically without restarting the application or stopping the daemon:

```bash
# Atomically reload and apply a new policy via the administrative CLI
nullgate-ctl reload-policy /etc/nullgate/policies/strict.json

# Verify active domain policies
nullgate-ctl list-domains
```
