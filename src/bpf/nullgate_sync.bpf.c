/*
 * NullGate — eBPF Synchronous Syscall Mediation & Confused Deputy Prevention
 * Pillar 7: io_uring Restriction & Syscall Attack-Surface Reduction
 *
 * Implements synchronous syscall interception, domain policy whitelist checks,
 * and kernel-boundary Confused Deputy protection blocking unauthorized access
 * to Key 1 (trusted state) and cross-domain memory pointers.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nullgate_abi.h"
#include "nullgate_policy.h"
#include "nullgate_maps.bpf.h"
#include "nullgate_helpers.bpf.h"
#include "nullgate_ipc.bpf.h"

#ifndef EPERM
#define EPERM   1
#endif

#ifndef SIGSEGV
#define SIGSEGV 11
#endif

#ifndef SIGSYS
#define SIGSYS  31
#endif

#ifndef __NR_socket
#define __NR_socket 41
#endif

#ifndef __NR_connect
#define __NR_connect 42
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

char LICENSE[] SEC("license") = "GPL";

/*
 * 1. SEC("lsm/socket_create"):
 * Intercepts socket() syscall creation.
 */
SEC("lsm/socket_create")
int BPF_PROG(ng_socket_create, int family, int type, int protocol, int kern)
{
    if (kern)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
    if (pol && !ng_policy_is_syscall_allowed(pol, __NR_socket)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_SYSCALL_DENIED, -EPERM);
        return -EPERM;
    }

    return 0;
}

/*
 * 2. SEC("lsm/socket_connect"):
 * Intercepts connect() syscall and performs Confused Deputy validation on sockaddr pointer.
 */
SEC("lsm/socket_connect")
int BPF_PROG(ng_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    /* Confused Deputy Check: Verify sockaddr does not point into trusted state */
    if (address && tctx->trusted_state_addr) {
        __u64 addr_val = (__u64)(unsigned long)address;
        if (addr_val >= tctx->trusted_state_addr && addr_val < tctx->trusted_state_addr + 4096) {
            ng_emit_audit_event(tctx, live_dom, NG_EVENT_DEPUTY_VIOLATION, -EPERM);
            return -EPERM;
        }
    }

    struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
    if (pol && (pol->policy_flags & NG_POLICY_DEPUTY_GUARD)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_DEPUTY_VIOLATION, -EPERM);
        return -EPERM;
    }

    if (pol && !ng_policy_is_syscall_allowed(pol, __NR_connect)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_SYSCALL_DENIED, -EPERM);
        return -EPERM;
    }

    return 0;
}

/*
 * 2b. SEC("lsm/socket_bind"):
 * Intercepts socket bind operations and blocks unauthorized network operations.
 */
SEC("lsm/socket_bind")
int BPF_PROG(ng_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
    if (pol && (pol->policy_flags & NG_POLICY_DEPUTY_GUARD)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_DEPUTY_VIOLATION, -EPERM);
        return -EPERM;
    }
    return 0;
}

/*
 * 2c. SEC("lsm/socket_sendmsg"):
 * Intercepts socket transmission and blocks unauthorized I/O from untrusted compartments.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(ng_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
    if (pol && (pol->policy_flags & NG_POLICY_DEPUTY_GUARD)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_DEPUTY_VIOLATION, -EPERM);
        return -EPERM;
    }
    return 0;
}

/*
 * 2d. SEC("lsm/socket_recvmsg"):
 * Intercepts socket receipt and blocks unauthorized I/O into untrusted compartments.
 */
SEC("lsm/socket_recvmsg")
int BPF_PROG(ng_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int flags)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
    if (pol && (pol->policy_flags & NG_POLICY_DEPUTY_GUARD)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_DEPUTY_VIOLATION, -EPERM);
        return -EPERM;
    }
    return 0;
}

/*
 * 3. SEC("lsm/file_permission"):
 * Intercepts file operations and validates write restrictions.
 */
SEC("lsm/file_permission")
int BPF_PROG(ng_file_permission, struct file *file, int mask)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    if ((tctx->domain_policy_mask & NG_POLICY_STRICT_SYSCALL) && (mask & 0x02 /* MAY_WRITE */)) {
        struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
        if (pol && (pol->policy_flags & NG_POLICY_STRICT_SYSCALL)) {
            ng_emit_audit_event(tctx, live_dom, NG_EVENT_SYSCALL_DENIED, -EPERM);
            return -EPERM;
        }
    }

    return 0;
}

/*
 * 4. SEC("tracepoint/raw_syscalls/sys_enter"):
 * Evaluates syscall whitelist and performs 6-argument Confused Deputy checks.
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int ng_trace_raw_sys_enter(struct trace_event_raw_sys_enter *ctx_raw)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    long syscall_id = ctx_raw->id;
    if (syscall_id < 0)
        return 0;

    /* Confused Deputy Check across all 6 syscall arguments */
    if (tctx->trusted_state_addr) {
        __u64 ts_start = tctx->trusted_state_addr;
        __u64 ts_end = ts_start + 4096;

        __u64 a0 = ctx_raw->args[0];
        __u64 a1 = ctx_raw->args[1];
        __u64 a2 = ctx_raw->args[2];
        __u64 a3 = ctx_raw->args[3];
        __u64 a4 = ctx_raw->args[4];
        __u64 a5 = ctx_raw->args[5];

        if ((a0 >= ts_start && a0 < ts_end) ||
            (a1 >= ts_start && a1 < ts_end) ||
            (a2 >= ts_start && a2 < ts_end) ||
            (a3 >= ts_start && a3 < ts_end) ||
            (a4 >= ts_start && a4 < ts_end) ||
            (a5 >= ts_start && a5 < ts_end)) {
            ng_emit_audit_event(tctx, live_dom, NG_EVENT_DEPUTY_VIOLATION, -EPERM);
            bpf_send_signal(SIGSEGV);
            return 0;
        }
    }

    /* Syscall Whitelist Verification */
    struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
    if (pol && (pol->policy_flags & NG_POLICY_STRICT_SYSCALL)) {
        if (!ng_policy_is_syscall_allowed(pol, (__u32)syscall_id)) {
            ng_emit_audit_event(tctx, live_dom, NG_EVENT_SYSCALL_DENIED, -EPERM);
            bpf_send_signal(SIGSYS);
            return 0;
        }
    }

    return 0;
}

#pragma clang diagnostic pop
