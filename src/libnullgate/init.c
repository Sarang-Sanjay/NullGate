/*
 * NullGate — Userspace Runtime Initialization & Domain Management
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <errno.h>
#include <unistd.h>

#include <pthread.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "pku.h"
#include "callgate.h"

static pthread_mutex_t g_domain_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ng_domain_desc {
    void *stack_base;
    size_t stack_size;
    void *stack_top;
    int pkey;
    uint32_t target_pkru;
    bool allocated;
};

static struct ng_domain_desc g_domains[NG_MAX_DOMAINS];
__attribute__((visibility("hidden")))
struct ng_trusted_state *g_trusted_state = NULL;
static bool g_rt_initialized = false;
static bool g_bpf_registered = false;

/*
 * POSIX pthread_atfork handlers:
 * Synchronize domain state across fork() calls (e.g. Nginx master spawning workers).
 */
static void ng_atfork_prepare(void)
{
    pthread_mutex_lock(&g_domain_mutex);
}

static void ng_atfork_parent(void)
{
    pthread_mutex_unlock(&g_domain_mutex);
}

static void ng_atfork_child(void)
{
    /* Re-initialize mutex in the freshly created child process */
    pthread_mutex_init(&g_domain_mutex, NULL);

    /*
     * POSIX specifies that mlock() memory locks are NOT inherited
     * across fork(). Re-lock g_trusted_state in physical RAM to maintain
     * the fail-closed RAM-locked reader invariant for BPF LSM.
     */
    if (g_trusted_state) {
        (void)mlock(g_trusted_state, 4096);
    }
}

int ng_init(void)
{
    pthread_mutex_lock(&g_domain_mutex);
    if (g_rt_initialized) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_SUCCESS;
    }

    /* 1. Initialize hardware PKU subsystem and pre-allocate Key 1 */
    int ret = pku_init();
    if (ret != NG_SUCCESS) {
        pthread_mutex_unlock(&g_domain_mutex);
        return ret;
    }

    /* 2. Map dedicated 4KB page for struct ng_trusted_state */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_NOMEM;
    }

    g_trusted_state = (struct ng_trusted_state *)page;
    memset(g_trusted_state, 0, sizeof(struct ng_trusted_state));
    g_trusted_state->current_domain = NG_DOMAIN_TRUSTED;

    /* 3. Protect trusted state page with Key 1 */
    int key1 = pku_get_trusted_key();
    if (key1 < 0) {
        munmap(page, 4096);
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_PKU;
    }

    if (pkey_mprotect(g_trusted_state, 4096, PROT_READ | PROT_WRITE, key1) != 0) {
        munmap(page, 4096);
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_PKU;
    }

    /*
     * Lock trusted state page in physical RAM (RAM-locked reader invariant).
     * Prevents page faults when eBPF LSM performs bpf_probe_read_user.
     */
    (void)mlock(g_trusted_state, 4096);

    /* 4. Register with eBPF LSM via custom one-shot prctl */
    long prctl_ret = prctl((int)NG_PRCTL_MAGIC_REGISTER, (unsigned long)g_trusted_state, 0, 0, 0);
    if (prctl_ret == 0) {
        g_bpf_registered = true;
    } else if (errno == EPERM) {
        /* Task context already locked */
        munmap(page, 4096);
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_LOCKED;
    } else {
        /*
         * In standalone unit test or offline mode (daemon not attached),
         * kernel returns -ENOSYS or -EINVAL for unhandled prctl.
         * PKU and CET call-gates remain active.
         */
        g_bpf_registered = false;
    }

    /* 5. Initialize Domain 0 (Default OS / Runtime Domain) */
    g_domains[NG_DOMAIN_TRUSTED].allocated = true;
    g_domains[NG_DOMAIN_TRUSTED].pkey = NG_PKEY_DEFAULT;
    g_domains[NG_DOMAIN_TRUSTED].target_pkru = pku_build_pkru_mask(NG_DOMAIN_TRUSTED);

    /* 6. Register pthread_atfork handlers for multi-process safety across fork() */
    pthread_atfork(ng_atfork_prepare, ng_atfork_parent, ng_atfork_child);

    g_rt_initialized = true;
    pthread_mutex_unlock(&g_domain_mutex);
    return NG_SUCCESS;
}

__attribute__((constructor))
static void ng_rt_init(void)
{
    (void)ng_init();
}

int ng_domain_create(uint32_t domain_id, void *stack_base, size_t stack_size)
{
    if (!g_rt_initialized) {
        int ret = ng_init();
        if (ret != NG_SUCCESS)
            return ret;
    }

    pthread_mutex_lock(&g_domain_mutex);

    if (domain_id == NG_DOMAIN_TRUSTED || domain_id >= NG_MAX_DOMAINS) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    /* Prevent domain re-creation or configuration hijacking */
    if (g_domains[domain_id].allocated) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_LOCKED;
    }

    if (!stack_base || stack_size < 4096) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    /* Check for pointer arithmetic overflow */
    if ((uintptr_t)stack_base + stack_size < (uintptr_t)stack_base) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    /*
     * Downward-Growing Stack Arithmetic:
     * x86_64 stacks grow downward. stack_top must point to the high address
     * of the allocated buffer, aligned to 16 bytes.
     */
    void *stack_top = (void *)(((uintptr_t)stack_base + stack_size) & ~0xFULL);

    /* Allocate dedicated hardware PKU key */
    int pkey = pku_alloc_domain_key(domain_id);
    if (pkey < 0) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_PKU;
    }

    /* Precompute target domain PKRU rights mask */
    uint32_t target_pkru = pku_build_pkru_mask(domain_id);

    g_domains[domain_id].stack_base = stack_base;
    g_domains[domain_id].stack_size = stack_size;
    g_domains[domain_id].stack_top = stack_top;
    g_domains[domain_id].pkey = pkey;
    g_domains[domain_id].target_pkru = target_pkru;
    g_domains[domain_id].allocated = true;

    pthread_mutex_unlock(&g_domain_mutex);
    return NG_SUCCESS;
}

int ng_domain_protect(uint32_t domain_id, void *addr, size_t len, int prot)
{
    if (!g_rt_initialized)
        return NG_ERR_INVALID;

    pthread_mutex_lock(&g_domain_mutex);

    if (domain_id >= NG_MAX_DOMAINS || !g_domains[domain_id].allocated) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    if (!addr || !len) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    /* Enforce 4KB page alignment for address and length */
    if (((uintptr_t)addr & 0xFFFULL) != 0 || (len & 0xFFFULL) != 0) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    uintptr_t req_start = (uintptr_t)addr;
    uintptr_t req_end = req_start + len;

    /* Check for pointer arithmetic wrap-around */
    if (req_end < req_start) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    /* Enforce non-executable policy on data pages (strict W^X) */
    if (prot & PROT_EXEC) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_PERM;
    }

    /*
     * Security Defense in Depth:
     * Never allow re-keying or tampering with the g_trusted_state page!
     */
    if (g_trusted_state) {
        uintptr_t ts_start = (uintptr_t)g_trusted_state;
        uintptr_t ts_end = ts_start + 4096;
        if (req_start < ts_end && req_end > ts_start) {
            pthread_mutex_unlock(&g_domain_mutex);
            return NG_ERR_PERM;
        }
    }

    /* Block overlap with any allocated domain execution stack */
    for (uint32_t d = 0; d < NG_MAX_DOMAINS; d++) {
        if (g_domains[d].allocated && g_domains[d].stack_base && g_domains[d].stack_size) {
            uintptr_t stack_start = (uintptr_t)g_domains[d].stack_base;
            uintptr_t stack_end = stack_start + g_domains[d].stack_size;
            if (req_start < stack_end && req_end > stack_start) {
                pthread_mutex_unlock(&g_domain_mutex);
                return NG_ERR_PERM;
            }
        }
    }

    int pkey = g_domains[domain_id].pkey;
    if (pkey_mprotect(addr, len, prot, pkey) != 0) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_PKU;
    }

    pthread_mutex_unlock(&g_domain_mutex);
    return NG_SUCCESS;
}

uint64_t ng_enter(uint32_t domain_id, ng_compartment_fn fn, void *arg)
{
    if (!g_rt_initialized) {
        if (ng_init() != NG_SUCCESS)
            return (uint64_t)-1;
    }

    if (domain_id == NG_DOMAIN_TRUSTED || domain_id >= NG_MAX_DOMAINS)
        return (uint64_t)-1;

    if (!g_domains[domain_id].allocated || !fn)
        return (uint64_t)-1;

    void *stack_top = g_domains[domain_id].stack_top;
    uint32_t target_pkru = g_domains[domain_id].target_pkru;

    /*
     * Dispatch atomic call-gate transition:
     * Drops privileges via WRPKRU, invokes fn(arg) on compartment stack,
     * restores trusted PKRU (0x0), and returns the 64-bit result.
     * Synchronized via g_domain_mutex to guarantee thread-safety across concurrent callers.
     */
    pthread_mutex_lock(&g_domain_mutex);
    uint64_t res = ng_callgate_invoke(domain_id, fn, arg, stack_top, target_pkru, g_trusted_state);
    pthread_mutex_unlock(&g_domain_mutex);
    return res;
}

uint32_t ng_get_active_domain(void)
{
    if (!g_trusted_state)
        return NG_DOMAIN_TRUSTED;
    return g_trusted_state->current_domain;
}

const char *ng_strerror(int err)
{
    switch (err) {
    case NG_SUCCESS:     return "Success";
    case NG_ERR_PKU:     return "PKU hardware or key allocation failure";
    case NG_ERR_CET:     return "Intel CET violation or unsupported feature";
    case NG_ERR_BPF:     return "eBPF LSM registration or attachment failure";
    case NG_ERR_INVALID: return "Invalid argument or domain ID";
    case NG_ERR_LOCKED:  return "Domain configuration is permanently locked";
    case NG_ERR_NOMEM:   return "Out of memory";
    case NG_ERR_PERM:    return "Operation prohibited by security policy";
    default:             return "Unknown error";
    }
}
