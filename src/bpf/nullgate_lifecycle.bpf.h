/*
 * NullGate — Lifecycle & Task Inheritance Subsystem (Pillar 6)
 * Automatically inherits locked security context across fork() and clone().
 */

#ifndef NULLGATE_LIFECYCLE_BPF_H
#define NULLGATE_LIFECYCLE_BPF_H

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

#ifndef ENOMEM
#define ENOMEM 12
#endif

#ifndef CLONE_VM
#define CLONE_VM 0x00000100ULL
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

/*
 * SEC("lsm/task_alloc"):
 * Hook called by Linux security_task_alloc(task, clone_flags) when allocating
 * a child task struct during fork(), clone(), or clone3().
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*task_alloc)(struct task_struct *task, u64 clone_flags);
 */
SEC("lsm/task_alloc")
int BPF_PROG(ng_task_alloc, struct task_struct *task, u64 clone_flags)
{
    /*
     * 1. Early Exit for Unmanaged Tasks & Kernel Threads:
     * Check if parent task (current) is registered under NullGate.
     * If parent is unmanaged, return 0 immediately WITHOUT allocating
     * task storage for the child. This guarantees zero overhead for
     * unmanaged processes across the system.
     */
    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *parent_ctx = ng_get_task_ctx_ro(curr);
    if (!parent_ctx || !(parent_ctx->flags & NG_TASK_LOCKED))
        return 0;

    /*
     * 2. Verifier BTF Safety:
     * Pass child `task` argument directly as trusted BTF pointer to allocate
     * task storage for the child.
     */
    struct ng_task_ctx *child_ctx = ng_get_task_ctx(task);
    if (!child_ctx) {
        /*
         * Failing closed: if task storage cannot be allocated for a child of
         * a locked task, return -ENOMEM to abort the fork, preventing unconfined
         * process leaks.
         */
        return -ENOMEM;
    }

    /*
     * 3. Inherit Base Security State:
     */
    child_ctx->active_domain = parent_ctx->active_domain;
    child_ctx->pku_key_mask = parent_ctx->pku_key_mask;
    child_ctx->flags = parent_ctx->flags | NG_TASK_LOCKED;
    child_ctx->domain_policy_mask = parent_ctx->domain_policy_mask;
    child_ctx->monotonic_seq = 0;
    child_ctx->dropped_events = 0;
    child_ctx->parent_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    /*
     * 4. Discrimination: CLONE_VM Threads vs. Process fork():
     * - If CLONE_VM is NOT set (process fork, e.g. Nginx master spawning workers):
     *   The child process has an identical copy-on-write virtual address space,
     *   so inheriting the parent's trusted_state_addr is safe and valid.
     *   child_ctx->is_thread_clone = 0;
     * - If CLONE_VM IS set (pthread_create thread):
     *   The child thread shares the address space with parent. To prevent
     *   threads from clobbering each other's trusted_rsp on the same page,
     *   each thread must allocate its own thread-local trusted_state page.
     *   Mark child_ctx->is_thread_clone = 1 and clear trusted_state_addr = 0.
     *   The thread will register its state page via NG_PRCTL_MAGIC_REGISTER.
     */
    __u32 live_dom = ng_get_live_domain(parent_ctx);
    if (live_dom != NG_DOMAIN_TRUSTED) {
        if (clone_flags & CLONE_VM) {
            /* Untrusted compartments cannot spawn unmanaged threads */
            ng_emit_audit_event(parent_ctx, live_dom, NG_EVENT_VIOLATION, -EPERM);
            return -EPERM;
        }
        /* Verify domain policy permits fork() / process spawning */
        struct ng_domain_policy *pol = ng_get_domain_policy(live_dom);
        if (!pol || !(pol->policy_flags & NG_POLICY_INHERIT_FORK)) {
            ng_emit_audit_event(parent_ctx, live_dom, NG_EVENT_VIOLATION, -EPERM);
            return -EPERM;
        }
    }

    if (clone_flags & CLONE_VM) {
        child_ctx->is_thread_clone = 1;
        child_ctx->trusted_state_addr = 0;
    } else {
        child_ctx->is_thread_clone = 0;
        child_ctx->trusted_state_addr = parent_ctx->trusted_state_addr;
    }

    /*
     * 5. Emit Audit Event for Inheritance Tracking:
     */
    ng_emit_audit_event(child_ctx, child_ctx->active_domain, NG_EVENT_FORK_INHERIT, 0);

    return 0;
}

/*
 * SEC("lsm/task_free"):
 * Hook called by Linux security_task_free(task) when freeing a task_struct.
 * Performs task termination auditing for NullGate managed tasks.
 *
 * Prototype in Linux 6.8+ BTF:
 *     void (*task_free)(struct task_struct *task);
 */
SEC("lsm/task_free")
void BPF_PROG(ng_task_free, struct task_struct *task)
{
    if (!task)
        return;

    /*
     * Check if the terminating task was managed by NullGate.
     * Early exit if unmanaged or unlocked.
     */
    struct ng_task_ctx *task_ctx = ng_get_task_ctx_ro(task);
    if (!task_ctx || !(task_ctx->flags & NG_TASK_LOCKED))
        return;

    /*
     * Emit termination audit event.
     * Note: BPF task storage is automatically reclaimed by the kernel
     * when the task_struct is released.
     */
    ng_emit_audit_event(task_ctx, task_ctx->active_domain, NG_EVENT_DOMAIN_EXIT, 0);
}

/*
 * SEC("lsm/bprm_check_security"):
 * Hook called by Linux security_bprm_check_security() before loading a binary image.
 * Guarantees untrusted compartments cannot break out of intra-process isolation via execve.
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*bprm_check_security)(struct linux_binprm *bprm);
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(ng_bprm_check_security, struct linux_binprm *bprm)
{
    (void)bprm;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return 0;

    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !(tctx->flags & NG_TASK_LOCKED))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom != NG_DOMAIN_TRUSTED) {
        /* Untrusted compartments are strictly forbidden from execve breakout */
        ng_emit_audit_event(tctx, live_dom, NG_EVENT_SYSCALL_DENIED, -EPERM);
        return -EPERM;
    }

    return 0;
}

#pragma clang diagnostic pop

#endif /* NULLGATE_LIFECYCLE_BPF_H */
