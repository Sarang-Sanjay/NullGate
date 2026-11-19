/*
 * NullGate — Memory & Page-Table Protection LSM Subsystem (Pillar 8)
 * Enforces kernel-level W^X memory policies and prevents tampering with
 * PKU-isolated memory allocations.
 */

#ifndef NULLGATE_MPROTECT_BPF_H
#define NULLGATE_MPROTECT_BPF_H

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

#ifndef PROT_READ
#define PROT_READ 0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC 0x4
#endif

#ifndef VM_WRITE
#define VM_WRITE 0x00000002UL
#endif
#ifndef VM_EXEC
#define VM_EXEC  0x00000004UL
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

/*
 * SEC("lsm/mmap_file"):
 * Hook called by Linux security_mmap_file() on sys_mmap invocations.
 * Enforces strict W^X policy natively blocking both file-backed and anonymous
 * W^X requests before page tables are constructed.
 *
 * CRITICAL INVARIANT:
 * In Linux security_mmap_file(), `file` is NULL for MAP_ANONYMOUS mappings!
 * Therefore, `file` must never be unconditionally dereferenced.
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*mmap_file)(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags);
 */
SEC("lsm/mmap_file")
int BPF_PROG(ng_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
    (void)file;
    (void)reqprot;
    (void)flags;

    /* Early exit for unmanaged OS tasks */
    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(curr);
    if (!curr_ctx || !(curr_ctx->flags & NG_TASK_LOCKED))
        return 0;

    /* 1. Global W^X Enforcement across all managed tasks */
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        ng_emit_audit_event(curr_ctx, curr_ctx->active_domain, NG_EVENT_MMAP_VIOLATION, -EPERM);
        return -EPERM;
    }

    /* 2. Untrusted Compartment Restriction: Deny any executable mapping */
    __u32 live_dom = ng_get_live_domain(curr_ctx);
    if (live_dom != NG_DOMAIN_TRUSTED) {
        if (prot & PROT_EXEC) {
            ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_MMAP_VIOLATION, -EPERM);
            return -EPERM;
        }
    }

    return 0;
}

/*
 * SEC("lsm/file_mprotect"):
 * Hook called by Linux security_file_mprotect() on sys_mprotect and sys_pkey_mprotect.
 * Enforces dynamic W^X policy and protects struct ng_trusted_state from being
 * un-keyed or modified by untrusted compartments.
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*file_mprotect)(struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot);
 */
SEC("lsm/file_mprotect")
int BPF_PROG(ng_file_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
    (void)reqprot;

    if (!vma)
        return 0;

    /* Early exit for unmanaged OS tasks */
    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(curr);
    if (!curr_ctx || !(curr_ctx->flags & NG_TASK_LOCKED))
        return 0;

    /* 1. Dynamic W^X Enforcement: Deny PROT_WRITE | PROT_EXEC */
    if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
        ng_emit_audit_event(curr_ctx, curr_ctx->active_domain, NG_EVENT_MMAP_VIOLATION, -EPERM);
        return -EPERM;
    }

    /* 2. Deny converting existing writable VMAs to executable */
    unsigned long vm_flags = BPF_CORE_READ(vma, vm_flags);
    if ((prot & PROT_EXEC) && (vm_flags & VM_WRITE)) {
        ng_emit_audit_event(curr_ctx, curr_ctx->active_domain, NG_EVENT_MMAP_VIOLATION, -EPERM);
        return -EPERM;
    }

    __u32 live_dom = ng_get_live_domain(curr_ctx);

    /* 3. Untrusted Compartment Restrictions */
    if (live_dom != NG_DOMAIN_TRUSTED) {
        /* Deny marking any page executable from untrusted compartment */
        if (prot & PROT_EXEC) {
            ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_MMAP_VIOLATION, -EPERM);
            return -EPERM;
        }

        /*
         * 4. Trusted State Page Tampering Guard:
         * Prevent untrusted compartments from calling mprotect or pkey_mprotect
         * on the address range covering struct ng_trusted_state.
         */
        if (curr_ctx->trusted_state_addr) {
            unsigned long vm_start = BPF_CORE_READ(vma, vm_start);
            unsigned long vm_end = BPF_CORE_READ(vma, vm_end);
            if (vm_start <= curr_ctx->trusted_state_addr && curr_ctx->trusted_state_addr < vm_end) {
                ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_VIOLATION, -EPERM);
                return -EPERM;
            }
        }
    }

    return 0;
}

#pragma clang diagnostic pop

#endif /* NULLGATE_MPROTECT_BPF_H */
