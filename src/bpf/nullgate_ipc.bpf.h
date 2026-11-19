/*
 * NullGate — Cross-Compartment Channel Guard eBPF LSM Subsystem
 * Pillar 7: Confused Deputy Prevention & Syscall Attack-Surface Reduction
 *
 * Implements kernel-boundary validation of shared memory IPC channels:
 * - SEC("lsm/file_receive"): Blocks unauthorized cross-compartment file-descriptor
 *   passing (via SCM_RIGHTS unix sockets).
 * - SEC("lsm/ipc_permission"): Validates SysV / POSIX IPC mechanisms across domains,
 *   blocking untrusted compartments from bypassing PKU isolation.
 *
 * CRITICAL SAFEGUARD 3:
 * This header strictly implements only file_receive and ipc_permission hooks.
 * Absolutely zero duplicate W^X memory protection hooks exist here; W^X hooks
 * are exclusively quarantined to nullgate_mprotect.bpf.h.
 */

#ifndef NULLGATE_IPC_BPF_H
#define NULLGATE_IPC_BPF_H

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
 * SEC("lsm/file_receive"):
 * Hook called by Linux security_file_receive() when a file descriptor is being
 * received over an AF_UNIX domain socket (SCM_RIGHTS).
 * Blocks unauthorized fd-passing into untrusted compartments to prevent
 * Confused Deputy privilege escalation and channel hijacking.
 */
SEC("lsm/file_receive")
int BPF_PROG(ng_file_receive, struct file *file)
{
    (void)file;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return 0;

    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    /*
     * Untrusted Compartment Restriction:
     * Untrusted compartments cannot receive injected file descriptors.
     */
    ng_emit_audit_event(tctx, live_dom, NG_EVENT_DEPUTY_VIOLATION, -EPERM);
    return -EPERM;
}

/*
 * SEC("lsm/ipc_permission"):
 * Hook called by Linux security_ipc_permission() on SysV IPC operations
 * (shmat/shmget, msgsnd/msgrcv, semop/semget).
 * NullGate provides hardware-isolated PKU zero-copy channels; legacy SysV IPC
 * is strictly forbidden in untrusted compartments to prevent out-of-band memory leaks.
 */
SEC("lsm/ipc_permission")
int BPF_PROG(ng_ipc_permission, struct kern_ipc_perm *ipcp, short int flag)
{
    (void)ipcp;
    (void)flag;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return 0;

    struct ng_task_ctx *tctx = ng_get_task_ctx_ro(task);
    if (!tctx || !ng_is_task_registered(tctx))
        return 0;

    __u32 live_dom = ng_get_live_domain(tctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    /*
     * Untrusted Compartment Restriction:
     * Legacy SysV IPC mechanisms bypass PKU protection and are blocked.
     */
    ng_emit_audit_event(tctx, live_dom, NG_EVENT_SYSCALL_DENIED, -EPERM);
    return -EPERM;
}

#pragma clang diagnostic pop

#endif /* NULLGATE_IPC_BPF_H */
