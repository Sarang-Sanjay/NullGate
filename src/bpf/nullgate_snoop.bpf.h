/*
 * NullGate — Anti-Snooping eBPF LSM Subsystem (Pillar 2)
 * Blocks ptrace, process_vm_readv/writev, and procfs memory inspection.
 */

#ifndef NULLGATE_SNOOP_BPF_H
#define NULLGATE_SNOOP_BPF_H

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
#ifndef EACCES
#define EACCES 13
#endif
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0ULL
#endif

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

/*
 * SEC("lsm/ptrace_access_check"):
 * Hook called by Linux security_ptrace_access_check() whenever a process
 * attempts ptrace attach/read, process_vm_readv/writev, or opens /proc/<pid>/mem.
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*ptrace_access_check)(struct task_struct *child, unsigned int mode);
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(ng_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
    (void)mode;

    if (!child)
        return 0;

    /*
     * 1. Protect Target Task (child):
     * Pass 'child' directly as a trusted BTF pointer into bpf_task_storage_get.
     * If the target is locked under NullGate, block all external tracing/inspection.
     */
    struct ng_task_ctx *child_ctx = bpf_task_storage_get(&ng_task_storage, child, 0, 0);
    struct task_struct *curr = bpf_get_current_task_btf();
    struct ng_task_ctx *curr_ctx = curr ? ng_get_task_ctx_ro(curr) : NULL;

    if (child_ctx && (child_ctx->flags & NG_TASK_LOCKED)) {
        if (curr == child) {
            /*
             * Same task accessing self (e.g. /proc/self/mem).
             * Block if executing in an untrusted compartment to prevent PKU bypass.
             */
            __u32 live_dom = ng_get_live_domain(curr_ctx);
            if (live_dom != NG_DOMAIN_TRUSTED) {
                ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_SNOOP_ATTEMPT, -EPERM);
                return -EPERM;
            }
        } else {
            /* External task attempting to trace or inspect locked NullGate task */
            ng_emit_audit_event(child_ctx, child_ctx->active_domain, NG_EVENT_SNOOP_ATTEMPT, -EPERM);
            return -EPERM;
        }
    }

    /*
     * 2. Protect From Untrusted Caller (curr):
     * If caller belongs to a NullGate task and is executing in an untrusted
     * compartment, block tracing or inspecting any other task.
     */
    if (curr_ctx && (curr_ctx->flags & NG_TASK_LOCKED)) {
        __u32 live_dom = ng_get_live_domain(curr_ctx);
        if (live_dom != NG_DOMAIN_TRUSTED) {
            ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_SNOOP_ATTEMPT, -EPERM);
            return -EPERM;
        }
    }

    return 0;
}

/*
 * SEC("lsm/ptrace_traceme"):
 * Hook called by Linux security_ptrace_traceme() when a process invokes ptrace(PTRACE_TRACEME).
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*ptrace_traceme)(struct task_struct *parent);
 */
SEC("lsm/ptrace_traceme")
int BPF_PROG(ng_ptrace_traceme, struct task_struct *parent)
{
    (void)parent;

    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(curr);
    if (curr_ctx && (curr_ctx->flags & NG_TASK_LOCKED)) {
        /*
         * A NullGate-managed process or an untrusted compartment inside it
         * must NEVER surrender control to an external debugger/tracer via PTRACE_TRACEME.
         */
        __u32 live_dom = ng_get_live_domain(curr_ctx);
        ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_SNOOP_ATTEMPT, -EPERM);
        return -EPERM;
    }

    return 0;
}

/*
 * SEC("lsm/file_open"):
 * Hook called by Linux security_file_open() on every file open.
 * Protects against /proc introspection by untrusted compartments.
 *
 * Prototype in Linux 6.8+ BTF:
 *     int (*file_open)(struct file *file);
 */
SEC("lsm/file_open")
int BPF_PROG(ng_file_open, struct file *file)
{
    if (!file)
        return 0;

    /*
     * 1. Fast Path: Superblock Magic Check
     * Exit immediately for all non-procfs files without overhead.
     */
    unsigned long s_magic = BPF_CORE_READ(file, f_path.dentry, d_sb, s_magic);
    if (s_magic != PROC_SUPER_MAGIC)
        return 0;

    /*
     * 2. Early Exit for Unmanaged Tasks
     * System processes and unmanaged tasks open /proc normally.
     */
    struct task_struct *curr = bpf_get_current_task_btf();
    if (!curr)
        return 0;

    struct ng_task_ctx *curr_ctx = ng_get_task_ctx_ro(curr);
    if (!curr_ctx || !(curr_ctx->flags & NG_TASK_LOCKED))
        return 0;

    /*
     * 3. Domain Check:
     * Trusted domain 0 is permitted to inspect /proc.
     */
    __u32 live_dom = ng_get_live_domain(curr_ctx);
    if (live_dom == NG_DOMAIN_TRUSTED)
        return 0;

    /*
     * 4. Untrusted Compartment Lockdown:
     * Untrusted compartments are blocked from accessing sensitive procfs nodes.
     * Use bounded, loop-free string comparisons against dentry name.
     */
    const unsigned char *name_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!name_ptr)
        return 0;

    char name[16] = {0};
    long len = bpf_probe_read_kernel_str(name, sizeof(name), name_ptr);
    if (len <= 0)
        return 0;

    bool is_sensitive = false;
    if (len == 4 && name[0] == 'm' && name[1] == 'e' && name[2] == 'm' && name[3] == '\0') {
        is_sensitive = true;
    } else if (len == 5 && name[0] == 'm' && name[1] == 'a' && name[2] == 'p' && name[3] == 's' && name[4] == '\0') {
        is_sensitive = true;
    } else if (len == 6 && __builtin_memcmp(name, "smaps", 6) == 0) {
        is_sensitive = true;
    } else if (len == 6 && __builtin_memcmp(name, "stack", 6) == 0) {
        is_sensitive = true;
    } else if (len == 8 && __builtin_memcmp(name, "pagemap", 8) == 0) {
        is_sensitive = true;
    } else if (len == 11 && __builtin_memcmp(name, "clear_refs", 11) == 0) {
        is_sensitive = true;
    } else if (len == 8 && __builtin_memcmp(name, "cmdline", 8) == 0) {
        is_sensitive = true;
    } else if (len == 8 && __builtin_memcmp(name, "environ", 8) == 0) {
        is_sensitive = true;
    }

    if (is_sensitive) {
        ng_emit_audit_event(curr_ctx, live_dom, NG_EVENT_SNOOP_ATTEMPT, -EACCES);
        return -EACCES;
    }

    return 0;
}

#pragma clang diagnostic pop

#endif /* NULLGATE_SNOOP_BPF_H */
