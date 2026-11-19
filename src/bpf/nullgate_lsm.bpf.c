/*
 * NullGate — eBPF LSM Hooks (Phase 1 Baseline)
 * Enforces one-shot domain registration and seccomp self-tampering lockdown.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nullgate_abi.h"
#include "nullgate_policy.h"
#include "nullgate_maps.bpf.h"
#include "nullgate_helpers.bpf.h"
#include "nullgate_snoop.bpf.h"
#include "nullgate_tamper.bpf.h"
#include "nullgate_lifecycle.bpf.h"
#include "nullgate_mprotect.bpf.h"

/* Standard Linux errnos */
#ifndef EPERM
#define EPERM   1
#endif
#ifndef ENOMEM
#define ENOMEM  12
#endif
#ifndef EINVAL
#define EINVAL  22
#endif
#ifndef ENOSYS
#define ENOSYS  38
#endif

/* prctl options for security lockdown */
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

/*
 * SEC("lsm/task_prctl"):
 * Hook called by Linux security_task_prctl() on every sys_prctl invocation.
 *
 * CRITICAL KERNEL INVARIANT:
 * In Linux kernel/sys.c:
 *     error = security_task_prctl(option, arg2, arg3, arg4, arg5);
 *     if (error != -ENOSYS)
 *         return error;
 *
 * Any return code other than -ENOSYS short-circuits the entire syscall.
 * Therefore, for all options not explicitly handled, we MUST return -ENOSYS.
 */
SEC("lsm/task_prctl")
int BPF_PROG(ng_task_prctl, int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    (void)arg3;
    (void)arg4;
    (void)arg5;

    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return -ENOSYS;

    /*
     * 1. One-Shot Domain Registration: NG_PRCTL_MAGIC_REGISTER
     * Called by libnullgate runtime constructor to bind struct ng_trusted_state
     * and lock the task context permanently.
     */
    if (option == (int)NG_PRCTL_MAGIC_REGISTER) {
        struct ng_task_ctx *curr_ctx = ng_get_task_ctx(task);
        if (!curr_ctx)
            return -ENOMEM;

        /*
         * One-Shot Registration Guard with Thread-Clone Support:
         * Allow registration ONLY if:
         *   1. Initial process registration: !(curr_ctx->flags & NG_TASK_LOCKED)
         *   2. First-time per-thread state page binding for a CLONE_VM thread:
         *      (curr_ctx->flags & NG_TASK_LOCKED) && curr_ctx->is_thread_clone && (curr_ctx->trusted_state_addr == 0)
         * Deny all other attempts with -EPERM.
         */
        bool is_initial_reg = !(curr_ctx->flags & NG_TASK_LOCKED);
        bool is_thread_reg = (curr_ctx->flags & NG_TASK_LOCKED) && curr_ctx->is_thread_clone && (curr_ctx->trusted_state_addr == 0);

        if (!is_initial_reg && !is_thread_reg)
            return -EPERM;

        /*
         * Validate trusted_state address:
         * Must be non-null, 4KB page aligned, and within canonical userspace
         * address range (< 0x800000000000 on x86_64).
         */
        if (!arg2 || (arg2 & 0xFFFULL) || arg2 >= 0x800000000000ULL)
            return -EINVAL;

        curr_ctx->active_domain = NG_DOMAIN_TRUSTED;
        curr_ctx->pku_key_mask = 0x3; /* Key 0 (default) + Key 1 (trusted) */
        curr_ctx->trusted_state_addr = (__u64)arg2;
        curr_ctx->flags |= NG_TASK_LOCKED;

        /* Stream registration audit event to userspace daemon */
        ng_emit_audit_event(curr_ctx, NG_DOMAIN_TRUSTED, NG_EVENT_REGISTER, 0);

        /* Return 0 indicating successfully handled by NullGate */
        return 0;
    }

    /*
     * 2. Security Prctl Tampering Lockdown (Pillar 3):
     * - PR_SET_SECCOMP: Block modifying or disabling seccomp filter policies.
     * - PR_SET_DUMPABLE: Block modifying dumpability to prevent core dumping isolated memory.
     * - PR_SET_NO_NEW_PRIVS: Block unauthorized privilege tampering.
     *
     * If the task is registered under NullGate, untrusted compartments cannot
     * alter security prctl configurations.
     */
    if (option == PR_SET_SECCOMP || option == PR_SET_DUMPABLE || option == PR_SET_NO_NEW_PRIVS) {
        struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(task);
        if (curr_ctx && (curr_ctx->flags & NG_TASK_LOCKED)) {
            __u32 live_dom = ng_get_live_domain(curr_ctx);
            if (live_dom != NG_DOMAIN_TRUSTED) {
                ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_VIOLATION, -EPERM);
                return -EPERM;
            }
        }
        /* Allow normal kernel processing if unmanaged or in trusted domain */
        return -ENOSYS;
    }

    /* Pass through all other prctl options to the kernel */
    return -ENOSYS;
}

#pragma clang diagnostic pop

char _license[] SEC("license") = "GPL";
