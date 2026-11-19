/*
 * NullGate — Canonical Shared ABI Header
 * Shared kernel (CO-RE eBPF) and userspace definitions.
 */

#ifndef NULLGATE_ABI_H
#define NULLGATE_ABI_H

#ifdef __BPF__
#ifndef __VMLINUX_H__
typedef unsigned char          __u8;
typedef unsigned short         __u16;
typedef unsigned int           __u32;
typedef long long unsigned int __u64;
typedef int                    __s32;
#endif
#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif
#else /* !__BPF__ */
#include <stdint.h>
#include <stddef.h>
#include <linux/types.h>
#endif /* __BPF__ */

/* Constants */
#define NG_MAX_DOMAINS              16
#define NG_DOMAIN_TRUSTED           0
#define NG_DOMAIN_DEFAULT           1

/* Custom PRCTL command for one-shot domain registration */
#define NG_PRCTL_MAGIC_REGISTER     0x4e475247U /* 'NGRG' */

/* Task Context Flags */
#define NG_TASK_LOCKED              (1ULL << 0)

/* Domain Policy Bitmasks (Phase 2) */
#define NG_POLICY_STRICT_WX         (1U << 0)
#define NG_POLICY_BLOCK_PTRACE      (1U << 1)
#define NG_POLICY_BLOCK_PROCFS      (1U << 2)
#define NG_POLICY_BLOCK_BPF         (1U << 3)
#define NG_POLICY_INHERIT_FORK      (1U << 4)

/* Audit Event Types */
#define NG_EVENT_REGISTER           1
#define NG_EVENT_VIOLATION          2
#define NG_EVENT_DOMAIN_ENTER       3
#define NG_EVENT_DOMAIN_EXIT        4
#define NG_EVENT_SNOOP_ATTEMPT      5
#define NG_EVENT_BPF_ATTEMPT        6
#define NG_EVENT_MMAP_VIOLATION     7
#define NG_EVENT_FORK_INHERIT       8

/*
 * struct ng_trusted_state:
 * Userspace page holding trusted callgate state, protected by PKU Key 1.
 * Must be exactly 4096 bytes (one hardware page) so pkey_mprotect covers
 * exclusively this structure without interfering with adjacent allocations.
 */
struct ng_trusted_state {
    __u64 trusted_rsp;          /* Offset 0: Saved trusted stack pointer across domain transitions */
    __u32 current_domain;        /* Offset 8: Live active domain ID */
    __u32 pad0;                  /* Offset 12: Explicit padding for 64-bit alignment */
    __u64 violation_count;      /* Offset 16: Monotonic violation counter */
    __u64 hmac_seq;             /* Offset 24: Ring-buffer HMAC sequence tracker */
    __u8  _reserved[4096 - 32]; /* Offset 32: Pads structure to exactly one 4KB page */
} __attribute__((aligned(4096)));

/*
 * struct ng_task_ctx:
 * Kernel-side BPF_MAP_TYPE_TASK_STORAGE schema.
 * Bound to the task_struct upon NG_PRCTL_MAGIC_REGISTER.
 */
struct ng_task_ctx {
    __u32 active_domain;        /* Offset 0: Live active domain ID tracked by kernel */
    __u32 pku_key_mask;         /* Offset 4: Allowed PKU keys bitmask */
    __u64 trusted_state_addr;   /* Offset 8: Verified userspace address of struct ng_trusted_state */
    __u64 flags;                /* Offset 16: Status flags (e.g. NG_TASK_LOCKED) */
    __u64 domain_policy_mask;   /* Offset 24: Active security policy bitmask */
    __u64 monotonic_seq;        /* Offset 32: Atomic monotonic sequence counter */
    __u64 dropped_events;       /* Offset 40: Ring-buffer dropped events counter */
    __u32 parent_pid;           /* Offset 48: Parent PID (inherited across fork) */
    __u32 is_thread_clone;      /* Offset 52: 1 if cloned with CLONE_VM, 0 if process fork */
};

/*
 * struct ng_audit_event:
 * BPF_MAP_TYPE_RINGBUF schema for cryptographic audit logging.
 */
struct ng_audit_event {
    __u64 timestamp_ns;         /* Offset 0: Kernel bpf_ktime_get_ns() */
    __u32 pid;                  /* Offset 8: Userspace process ID */
    __u32 tgid;                 /* Offset 12: Thread group ID */
    __u32 domain_id;            /* Offset 16: Domain ID active during event */
    __u32 event_type;           /* Offset 20: NG_EVENT_* */
    __s32 return_code;          /* Offset 24: Syscall or operation return/error code */
    union {
        __u32 pad;              /* Offset 28: Alignment padding (legacy alias) */
        __u32 dropped_events;   /* Offset 28: Ring-buffer dropped events counter */
    };
    __u64 monotonic_seq;        /* Offset 32: Monotonic sequence counter */
    __u8  sha256_digest[32];    /* Offset 40: SHA-256 HMAC hash-chain digest */
};

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct ng_trusted_state) == 4096, "ng_trusted_state must be exactly 4096 bytes");
_Static_assert(offsetof(struct ng_trusted_state, trusted_rsp) == 0, "trusted_rsp offset must be 0");
_Static_assert(offsetof(struct ng_trusted_state, current_domain) == 8, "current_domain offset must be 8");
_Static_assert(sizeof(struct ng_task_ctx) == 56, "ng_task_ctx size must be exactly 56 bytes");
_Static_assert(offsetof(struct ng_task_ctx, active_domain) == 0, "active_domain offset must be 0");
_Static_assert(offsetof(struct ng_task_ctx, trusted_state_addr) == 8, "trusted_state_addr offset must be 8");
_Static_assert(offsetof(struct ng_task_ctx, domain_policy_mask) == 24, "domain_policy_mask offset must be 24");
_Static_assert(offsetof(struct ng_task_ctx, monotonic_seq) == 32, "monotonic_seq offset must be 32");
_Static_assert(offsetof(struct ng_task_ctx, dropped_events) == 40, "dropped_events offset must be 40");
_Static_assert(offsetof(struct ng_task_ctx, parent_pid) == 48, "parent_pid offset must be 48");
_Static_assert(offsetof(struct ng_task_ctx, is_thread_clone) == 52, "is_thread_clone offset must be 52");
_Static_assert(sizeof(struct ng_audit_event) == 72, "ng_audit_event size must be exactly 72 bytes");
_Static_assert(offsetof(struct ng_audit_event, dropped_events) == 28, "dropped_events offset must be 28");
#endif

#endif /* NULLGATE_ABI_H */
