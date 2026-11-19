/*
 * NullGate — Self-Tampering & Security Lockdown Subsystem (Pillar 3)
 * Locks down bpf() syscall operations, BPF maps/progs, and security prctls from untrusted compartments.
 */

#ifndef NULLGATE_TAMPER_BPF_H
#define NULLGATE_TAMPER_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nullgate_abi.h"
#include "nullgate_policy.h"
#include "nullgate_maps.bpf.h"
#include "nullgate_helpers.bpf.h"

#ifndef EPERM
#define EPERM 1
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

/*
 * SEC("lsm/bpf"):
 * Hook called by Linux security_bpf() on every sys_bpf invocation.
 * Enforces that untrusted compartments can never issue BPF syscall commands
 * (e.g. BPF_PROG_LOAD, BPF_MAP_CREATE, BPF_LINK_CREATE, BPF_MAP_UPDATE_ELEM).
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*bpf)(int cmd, union bpf_attr *attr, unsigned int size, bool kernel);
 */
SEC("lsm/bpf")
int BPF_PROG(ng_bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel)
{
    (void)cmd;
    (void)attr;
    (void)size;

    /* Internal kernel invocations are permitted */
    if (kernel)
        return 0;

    /* Early exit for unmanaged OS tasks */
    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(curr);
    if (!curr_ctx || !(curr_ctx->flags & NG_TASK_LOCKED))
        return 0;

    /* Untrusted compartments are strictly blocked from invoking bpf() */
    __u32 live_dom = ng_get_live_domain(curr_ctx);
    if (live_dom != NG_DOMAIN_TRUSTED) {
        ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_BPF_ATTEMPT, -EPERM);
        return -EPERM;
    }

    return 0;
}

/*
 * SEC("lsm/bpf_map"):
 * Hook called by Linux security_bpf_map() on BPF map operations.
 * Enforces that untrusted compartments cannot perform operations on BPF map descriptors.
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*bpf_map)(struct bpf_map *map, fmode_t fmode);
 */
SEC("lsm/bpf_map")
int BPF_PROG(ng_bpf_map, struct bpf_map *map, fmode_t fmode)
{
    (void)map;
    (void)fmode;

    /* Early exit for unmanaged OS tasks */
    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(curr);
    if (!curr_ctx || !(curr_ctx->flags & NG_TASK_LOCKED))
        return 0;

    /* Untrusted compartments are strictly blocked from BPF map operations */
    __u32 live_dom = ng_get_live_domain(curr_ctx);
    if (live_dom != NG_DOMAIN_TRUSTED) {
        ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_BPF_ATTEMPT, -EPERM);
        return -EPERM;
    }

    return 0;
}

/*
 * SEC("lsm/bpf_prog"):
 * Hook called by Linux security_bpf_prog() on BPF program operations.
 * Enforces that untrusted compartments cannot perform operations on BPF program descriptors.
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*bpf_prog)(struct bpf_prog *prog);
 */
SEC("lsm/bpf_prog")
int BPF_PROG(ng_bpf_prog, struct bpf_prog *prog)
{
    (void)prog;

    /* Early exit for unmanaged OS tasks */
    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(curr);
    if (!curr_ctx || !(curr_ctx->flags & NG_TASK_LOCKED))
        return 0;

    /* Untrusted compartments are strictly blocked from BPF program operations */
    __u32 live_dom = ng_get_live_domain(curr_ctx);
    if (live_dom != NG_DOMAIN_TRUSTED) {
        ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_BPF_ATTEMPT, -EPERM);
        return -EPERM;
    }

    return 0;
}

#pragma clang diagnostic pop

#endif /* NULLGATE_TAMPER_BPF_H */
