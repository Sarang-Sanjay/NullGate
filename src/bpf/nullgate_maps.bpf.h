/*
 * NullGate — eBPF Maps Header
 * Defines BPF_MAP_TYPE_TASK_STORAGE, BPF_MAP_TYPE_RINGBUF, and BPF_MAP_TYPE_ARRAY policy map.
 */

#ifndef NULLGATE_MAPS_BPF_H
#define NULLGATE_MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "nullgate_abi.h"
#include "nullgate_policy.h"

/*
 * ng_task_storage:
 * Per-task local storage holding the authoritative domain state (active_domain,
 * allowed pkey_mask, verified userspace trusted_state_addr, and locked flag).
 * Automatically freed when task_struct is destroyed by the kernel.
 */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct ng_task_ctx);
} ng_task_storage SEC(".maps") __attribute__((weak));

/*
 * ng_audit_ringbuf:
 * Lockless MPSC ring buffer for high-throughput streaming of audit events,
 * policy violations, and domain transitions to the userspace daemon.
 * Size: 1MB (1,048,576 bytes).
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} ng_audit_ringbuf SEC(".maps") __attribute__((weak));

/*
 * ng_domain_policy_map:
 * Global policy array indexed by domain ID (0 to NG_MAX_DOMAINS - 1).
 * Read by BPF LSM hooks to enforce W^X, allowed syscalls, and domain restrictions.
 * Populated by userspace security daemon via policy_loader.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NG_MAX_DOMAINS);
    __type(key, __u32);
    __type(value, struct ng_domain_policy);
} ng_domain_policy_map SEC(".maps") __attribute__((weak));

#endif /* NULLGATE_MAPS_BPF_H */
