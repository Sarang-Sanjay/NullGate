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
#include "signal.h"

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

/* Per-Thread Trusted State & Altstack (Fix HIGH-01, HIGH-03) */
__thread struct ng_trusted_state *t_trusted_state __attribute__((tls_model("initial-exec"))) = NULL;
static __thread void *t_altstack_buf = NULL;

static bool g_rt_initialized = false;
static bool g_bpf_registered = false;

struct ng_trusted_state *ng_get_thread_state(void)
{
    if (__builtin_expect(t_trusted_state != NULL, 1)) {
        return t_trusted_state;
    }

    /* 1. Allocate dedicated 4KB page for this thread's ng_trusted_state */
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        return NULL;
    }

    struct ng_trusted_state *ts = (struct ng_trusted_state *)page;
    memset(ts, 0, sizeof(*ts));
    ts->current_domain = NG_DOMAIN_TRUSTED;

    int key1 = pku_get_trusted_key();
    if (key1 >= 0) {
        (void)pkey_mprotect(page, 4096, PROT_READ | PROT_WRITE, key1);
    }
    (void)mlock(page, 4096);

    /* 2. Allocate and register per-thread alternate signal stack (Fix HIGH-01) */
    void *altstack = mmap(NULL, NG_SIGNAL_ALTSTACK_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (altstack != MAP_FAILED) {
        stack_t ss;
        memset(&ss, 0, sizeof(ss));
        ss.ss_sp = altstack;
        ss.ss_size = NG_SIGNAL_ALTSTACK_SIZE;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) == 0) {
            t_altstack_buf = altstack;
            ts->altstack_base = (uint64_t)(uintptr_t)altstack;
            ts->altstack_size = (uint64_t)NG_SIGNAL_ALTSTACK_SIZE;
        } else {
            munmap(altstack, NG_SIGNAL_ALTSTACK_SIZE);
        }
    }

    /* 3. Register thread's state page with eBPF LSM via prctl */
    long prctl_ret = prctl((int)NG_PRCTL_MAGIC_REGISTER, (unsigned long)page, 0, 0, 0);
    if (prctl_ret == 0) {
        g_bpf_registered = true;
    }

    t_trusted_state = ts;
    if (g_trusted_state == NULL) {
        g_trusted_state = ts;
    }
    return ts;
}

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

    /* 2. Initialize main thread trusted state & per-thread altstack */
    struct ng_trusted_state *main_ts = ng_get_thread_state();
    if (!main_ts) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_NOMEM;
    }
    g_trusted_state = main_ts;

    /* 3. Initialize Domain 0 (Default OS / Runtime Domain) */
    g_domains[NG_DOMAIN_TRUSTED].allocated = true;
    g_domains[NG_DOMAIN_TRUSTED].pkey = NG_PKEY_DEFAULT;
    g_domains[NG_DOMAIN_TRUSTED].target_pkru = pku_build_pkru_mask(NG_DOMAIN_TRUSTED);

    /* 4. Register pthread_atfork handlers for multi-process safety across fork() */
    pthread_atfork(ng_atfork_prepare, ng_atfork_parent, ng_atfork_child);

    /* 5. Initialize asynchronous signal interception subsystem */
    ret = ng_signal_subsystem_init();
    if (ret != NG_SUCCESS) {
        pthread_mutex_unlock(&g_domain_mutex);
        return ret;
    }

    g_rt_initialized = true;
    pthread_mutex_unlock(&g_domain_mutex);
    return NG_SUCCESS;
}

__attribute__((constructor))
static void ng_rt_init(void)
{
    (void)ng_init();
}

__attribute__((destructor))
static void ng_rt_fini(void)
{
    ng_signal_subsystem_cleanup();
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

    /* Require 4096-byte page alignment for stack_base and stack_size */
    if (((uintptr_t)stack_base & 0xFFFULL) != 0 || (stack_size & 0xFFFULL) != 0) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    /* Check for pointer arithmetic overflow */
    if ((uintptr_t)stack_base + stack_size < (uintptr_t)stack_base) {
        pthread_mutex_unlock(&g_domain_mutex);
        return NG_ERR_INVALID;
    }

    uintptr_t req_start = (uintptr_t)stack_base;
    uintptr_t req_end = req_start + stack_size;

    /* Verify no overlap with g_trusted_state */
    if (g_trusted_state) {
        uintptr_t ts_start = (uintptr_t)g_trusted_state;
        uintptr_t ts_end = ts_start + 4096;
        if (req_start < ts_end && req_end > ts_start) {
            pthread_mutex_unlock(&g_domain_mutex);
            return NG_ERR_PERM;
        }
    }

    /* Verify no overlap with existing domain stacks */
    for (uint32_t d = 0; d < NG_MAX_DOMAINS; d++) {
        if (g_domains[d].allocated && g_domains[d].stack_base && g_domains[d].stack_size) {
            uintptr_t d_start = (uintptr_t)g_domains[d].stack_base;
            uintptr_t d_end = d_start + g_domains[d].stack_size;
            if (req_start < d_end && req_end > d_start) {
                pthread_mutex_unlock(&g_domain_mutex);
                return NG_ERR_PERM;
            }
        }
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

    /*
     * Hardware Compartment Stack Isolation (Fix CRIT-02):
     * Tag stack memory with the domain's dedicated PKU key.
     */
    if (pkey_mprotect(stack_base, stack_size, PROT_READ | PROT_WRITE, pkey) != 0) {
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

void ng_domain_refresh_pkru(uint32_t domain_id)
{
    if (domain_id < NG_MAX_DOMAINS) {
        pthread_mutex_lock(&g_domain_mutex);
        if (g_domains[domain_id].allocated) {
            g_domains[domain_id].target_pkru = pku_build_pkru_mask(domain_id);
        }
        pthread_mutex_unlock(&g_domain_mutex);
    }
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

extern void ng_shim_reset_depth(void) __attribute__((weak));

uint64_t ng_enter(uint32_t domain_id, ng_compartment_fn fn, void *arg)
{
    if (!g_rt_initialized) {
        if (ng_init() != NG_SUCCESS)
            return (uint64_t)-1;
    }

    if (domain_id == NG_DOMAIN_TRUSTED || domain_id >= NG_MAX_DOMAINS)
        return (uint64_t)-1;

    struct ng_trusted_state *tstate = ng_get_thread_state();
    if (!tstate)
        return (uint64_t)-1;

    if (!g_domains[domain_id].allocated || !fn)
        return (uint64_t)-1;

    void *stack_top = g_domains[domain_id].stack_top;
    uint32_t target_pkru = g_domains[domain_id].target_pkru;

    /*
     * Dispatch atomic call-gate transition:
     * Drops privileges via WRPKRU, invokes fn(arg) on compartment stack,
     * restores trusted PKRU (0x0), and returns the 64-bit result.
     * Concurrency is fully parallel per thread without global mutex serialization!
     */
    uint64_t res = ng_callgate_invoke(domain_id, fn, arg, stack_top, target_pkru, tstate);
    if (ng_shim_reset_depth) {
        ng_shim_reset_depth();
    }
    return res;
}

uint32_t ng_get_active_domain(void)
{
    if (t_trusted_state)
        return t_trusted_state->current_domain;
    if (g_trusted_state)
        return g_trusted_state->current_domain;
    return NG_DOMAIN_TRUSTED;
}

uintptr_t ng_get_trusted_state_addr(void)
{
    if (t_trusted_state)
        return (uintptr_t)t_trusted_state;
    return (uintptr_t)g_trusted_state;
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
