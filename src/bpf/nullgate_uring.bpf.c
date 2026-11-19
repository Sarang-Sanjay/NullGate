/*
 * NullGate — eBPF LSM & Tracepoint io_uring Restriction Subsystem
 * Pillar 7: io_uring Restriction & Syscall Attack-Surface Reduction
 *
 * Implements Linux 6.8+ kernel enforcement blocking asynchronous io_uring
 * operations, SQPOLL thread creation, passthrough commands, and credential
 * overrides for compartmentalized domains.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nullgate_abi.h"
#include "nullgate_policy.h"
#include "nullgate_maps.bpf.h"
#include "nullgate_helpers.bpf.h"

#ifndef EPERM
#define EPERM   1
#endif

#ifndef SIGSEGV
#define SIGSEGV 11
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

char LICENSE[] SEC("license") = "GPL";

/*
 * ng_check_uring_blocked:
 * Helper checking if io_uring is prohibited for calling task and active domain.
 * Returns true if blocked (with active tctx and live_domain populated).
 */
static __always_inline bool ng_check_uring_blocked(struct ng_task_ctx **out_tctx, __u32 *out_dom)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return false;

    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return false;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return false;

    /*
     * Enforce io_uring restriction:
     * Untrusted domains are prohibited from invoking io_uring if NG_POLICY_BLOCK_URING
     * is set, or by fail-closed default for unprivileged compartments.
     */
    if ((tctx->domain_policy_mask & NG_POLICY_BLOCK_URING) || live_dom != NG_DOMAIN_TRUSTED) {
        if (out_tctx)
            *out_tctx = tctx;
        if (out_dom)
            *out_dom = live_dom;
        return true;
    }

    return false;
}

/*
 * 1. SEC("lsm/uring_override_creds"):
 * Blocks unauthorized credential/personality manipulation inside io_uring.
 */
SEC("lsm/uring_override_creds")
int BPF_PROG(ng_uring_override_creds, const struct cred *cred)
{
    struct ng_task_ctx *tctx = NULL;
    __u32 live_dom = NG_DOMAIN_DEFAULT;

    if (ng_check_uring_blocked(&tctx, &live_dom)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_URING_ATTEMPT, -EPERM);
        return -EPERM;
    }
    return 0;
}

/*
 * 2. SEC("lsm/uring_sqpoll"):
 * Blocks creation of asynchronous kernel polling threads (IORING_SETUP_SQPOLL).
 */
SEC("lsm/uring_sqpoll")
int BPF_PROG(ng_uring_sqpoll)
{
    struct ng_task_ctx *tctx = NULL;
    __u32 live_dom = NG_DOMAIN_DEFAULT;

    if (ng_check_uring_blocked(&tctx, &live_dom)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_URING_ATTEMPT, -EPERM);
        return -EPERM;
    }
    return 0;
}

/*
 * 3. SEC("lsm/uring_cmd"):
 * Intercepts asynchronous io_uring passthrough commands.
 */
SEC("lsm/uring_cmd")
int BPF_PROG(ng_uring_cmd, struct io_uring_cmd *ioucmd)
{
    struct ng_task_ctx *tctx = NULL;
    __u32 live_dom = NG_DOMAIN_DEFAULT;

    if (ng_check_uring_blocked(&tctx, &live_dom)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_URING_ATTEMPT, -EPERM);
        return -EPERM;
    }
    return 0;
}

/*
 * 4. SEC("tp_btf/io_uring_submit_req"):
 * Intercepts asynchronous I/O submission via kernel BTF tracepoint.
 */
SEC("tp_btf/io_uring_submit_req")
int BPF_PROG(ng_uring_submit_req, struct io_kiocb *req)
{
    struct ng_task_ctx *tctx = NULL;
    __u32 live_dom = NG_DOMAIN_DEFAULT;

    if (ng_check_uring_blocked(&tctx, &live_dom)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_URING_ATTEMPT, -EPERM);
        bpf_send_signal(SIGSEGV);
    }
    return 0;
}

/*
 * 5. SEC("tracepoint/syscalls/sys_enter_io_uring_setup"):
 * Intercepts io_uring_setup() syscall invocations.
 */
SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int ng_trace_io_uring_setup(struct trace_event_raw_sys_enter *ctx_raw)
{
    struct ng_task_ctx *tctx = NULL;
    __u32 live_dom = NG_DOMAIN_DEFAULT;

    if (ng_check_uring_blocked(&tctx, &live_dom)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_URING_ATTEMPT, -EPERM);
        bpf_send_signal(SIGSEGV);
    }
    return 0;
}

/*
 * 6. SEC("tracepoint/syscalls/sys_enter_io_uring_enter"):
 * Intercepts io_uring_enter() syscall invocations.
 */
SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int ng_trace_io_uring_enter(struct trace_event_raw_sys_enter *ctx_raw)
{
    struct ng_task_ctx *tctx = NULL;
    __u32 live_dom = NG_DOMAIN_DEFAULT;

    if (ng_check_uring_blocked(&tctx, &live_dom)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_URING_ATTEMPT, -EPERM);
        bpf_send_signal(SIGSEGV);
    }
    return 0;
}

/*
 * 7. SEC("tracepoint/syscalls/sys_enter_io_uring_register"):
 * Intercepts io_uring_register() syscall invocations.
 */
SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int ng_trace_io_uring_register(struct trace_event_raw_sys_enter *ctx_raw)
{
    struct ng_task_ctx *tctx = NULL;
    __u32 live_dom = NG_DOMAIN_DEFAULT;

    if (ng_check_uring_blocked(&tctx, &live_dom)) {
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_URING_ATTEMPT, -EPERM);
        bpf_send_signal(SIGSEGV);
    }
    return 0;
}

#pragma clang diagnostic pop
