/*
 * NullGate — eBPF Verifier-Safe Inline Helpers
 * Provides safe task storage retrieval, live domain resolution, ring buffer submission, and domain checks.
 */

#ifndef NULLGATE_HELPERS_BPF_H
#define NULLGATE_HELPERS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nullgate_abi.h"
#include "nullgate_policy.h"
#include "nullgate_maps.bpf.h"

/**
 * ng_get_task_ctx - Safely retrieve or create task storage context.
 * @task: Pointer to task_struct
 *
 * Calls bpf_task_storage_get with BPF_LOCAL_STORAGE_GET_F_CREATE.
 * The caller MUST check for NULL before dereferencing the returned pointer.
 */
static __always_inline struct ng_task_ctx *ng_get_task_ctx(struct task_struct *task)
{
    if (!task)
        return NULL;
    return bpf_task_storage_get(&ng_task_storage, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/**
 * ng_get_task_ctx_ro - Read-only retrieval of task storage context without allocating.
 * @task: Pointer to task_struct
 */
static __always_inline struct ng_task_ctx *ng_get_task_ctx_ro(struct task_struct *task)
{
    if (!task)
        return NULL;
    return bpf_task_storage_get(&ng_task_storage, task, 0, 0);
}

/**
 * ng_is_task_registered - Returns true if task storage exists and is locked.
 */
static __always_inline bool ng_is_task_registered(struct ng_task_ctx *ctx)
{
    return ctx && (ctx->flags & NG_TASK_LOCKED);
}

/**
 * ng_is_trusted_domain - Returns true if current active domain is NG_DOMAIN_TRUSTED.
 */
static __always_inline bool ng_is_trusted_domain(struct ng_task_ctx *ctx)
{
    return ctx && (ctx->active_domain == NG_DOMAIN_TRUSTED);
}

/**
 * ng_get_live_domain - Safely resolve active domain from RAM-locked userspace state.
 * @ctx: Pointer to task context
 *
 * In non-sleepable LSM hooks, bpf_probe_read_user reads the current task's
 * g_trusted_state->current_domain (pinned in RAM via mlock()).
 * Fails closed to NG_DOMAIN_DEFAULT if unreadable, uninitialized, or out of range.
 */
static __always_inline __u32 ng_get_live_domain(struct ng_task_ctx *ctx)
{
    /* Fail-closed: unmanaged or uninitialized tasks default to untrusted domain */
    if (!ctx || !ctx->trusted_state_addr)
        return NG_DOMAIN_DEFAULT;

    __u32 live_dom = NG_DOMAIN_DEFAULT;
    if (bpf_probe_read_user(&live_dom, sizeof(live_dom),
                            (void *)(ctx->trusted_state_addr + 8 /* current_domain */)) != 0 ||
        live_dom >= NG_MAX_DOMAINS) {
        /* Fail closed: treat unreadable or out-of-range domain as untrusted */
        return NG_DOMAIN_DEFAULT;
    }
    /* Opportunistically sync cached active_domain */
    ctx->active_domain = live_dom;
    return live_dom;
}

/**
 * ng_get_domain_policy - Lookup domain policy in BPF map.
 * @domain_id: Domain ID (0 to NG_MAX_DOMAINS - 1)
 */
static __always_inline struct ng_domain_policy *ng_get_domain_policy(__u32 domain_id)
{
    if (domain_id >= NG_MAX_DOMAINS)
        return NULL;
    return bpf_map_lookup_elem(&ng_domain_policy_map, &domain_id);
}

/**
 * ng_emit_audit_event - Atomically reserve and emit an audit event with sequence counter.
 * @ctx: Pointer to task context (for monotonic_seq advancement and dropped_events tracking)
 * @domain_id: Active domain ID
 * @event_type: NG_EVENT_* code
 * @return_code: Operation result or error code
 *
 * Returns 0 on success, or negative on allocation failure.
 */
static __always_inline int ng_emit_audit_event(struct ng_task_ctx *ctx, __u32 domain_id, __u32 event_type, __s32 return_code)
{
    struct ng_audit_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 seq = 0;
    __u32 dropped = 0;

    if (ctx) {
        seq = __sync_fetch_and_add(&ctx->monotonic_seq, 1);
        dropped = (__u32)ctx->dropped_events;
    }

    event = bpf_ringbuf_reserve(&ng_audit_ringbuf, sizeof(*event), 0);
    if (!event) {
        if (ctx) {
            __sync_fetch_and_add(&ctx->dropped_events, 1);
        }
        return -1;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (__u32)(pid_tgid >> 32);
    event->tgid = (__u32)pid_tgid;
    event->domain_id = domain_id;
    event->event_type = event_type;
    event->return_code = return_code;
    event->dropped_events = dropped;
    event->monotonic_seq = seq;
    __builtin_memset(event->sha256_digest, 0, sizeof(event->sha256_digest));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/**
 * ng_ringbuf_emit - Reserve and submit an audit event (legacy wrapper for Phase 1 callers).
 */
static __always_inline int ng_ringbuf_emit(__u32 domain_id, __u32 event_type, __s32 return_code, __u64 monotonic_seq)
{
    struct ng_audit_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&ng_audit_ringbuf, sizeof(*event), 0);
    if (!event)
        return -1;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = (__u32)(pid_tgid >> 32);
    event->tgid = (__u32)pid_tgid;
    event->domain_id = domain_id;
    event->event_type = event_type;
    event->return_code = return_code;
    event->dropped_events = 0;
    event->monotonic_seq = monotonic_seq;
    __builtin_memset(event->sha256_digest, 0, sizeof(event->sha256_digest));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

#endif /* NULLGATE_HELPERS_BPF_H */
