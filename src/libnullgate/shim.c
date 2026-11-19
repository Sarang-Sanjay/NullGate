/*
 * NullGate — Transparent Dynamic Library Preload Interposition Engine (shim.c)
 * Enables transparent compartmentalization of third-party libraries without source code changes.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <dlfcn.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "nullgate_shim.h"

/* Initial-Exec TLS re-entrancy depth counter */
__thread uint32_t t_shim_depth __attribute__((tls_model("initial-exec"))) = 0;

static bool g_shim_initialized = false;

/*
 * ng_shim_resolve_symbol:
 * Uses dlsym(RTLD_NEXT) to dynamically locate the real underlying library function.
 */
void *ng_shim_resolve_symbol(const char *symbol_name)
{
    if (!symbol_name)
        return NULL;

    /* Clear any existing dlerror */
    (void)dlerror();

    void *sym = dlsym(RTLD_NEXT, symbol_name);
    if (!sym) {
        sym = dlsym(RTLD_DEFAULT, symbol_name);
    }
    if (!sym) {
        const char *err = dlerror();
        fprintf(stderr, "[NULLGATE SHIM ERROR] Failed to resolve symbol '%s': %s\n",
                symbol_name, err ? err : "unknown error");
        abort();
    }

    return sym;
}

/*
 * ng_shim_get_depth - Query current re-entrancy depth for the calling thread.
 */
uint32_t ng_shim_get_depth(void)
{
    return t_shim_depth;
}

/*
 * ng_shim_inc_depth - Increment re-entrancy depth.
 */
void ng_shim_inc_depth(void)
{
    t_shim_depth++;
}

/*
 * ng_shim_dec_depth - Decrement re-entrancy depth.
 */
void ng_shim_dec_depth(void)
{
    if (t_shim_depth > 0)
        t_shim_depth--;
}

/*
 * ng_shim_reset_depth - Unconditionally reset re-entrancy depth counter.
 * Invoked on call-gate return to prevent desynchronization after longjmp/signals.
 */
extern void ng_enter_recover_stack_lease(void) __attribute__((weak));

void ng_shim_reset_depth(void)
{
    t_shim_depth = 0;
    if (ng_enter_recover_stack_lease) {
        ng_enter_recover_stack_lease();
    }
}

/*
 * ng_shim_dispatch_func:
 * Dispatches a non-void function into the designated domain via ng_enter.
 * Cleans vector registers before and after call to prevent AVX/SSE leak or penalties.
 */
uint64_t ng_shim_dispatch_func(uint32_t domain_id, ng_compartment_fn adapter, void *pack)
{
    if (!adapter)
        return 0;

    t_shim_depth++;
    __asm__ __volatile__("vzeroupper" ::: "memory");
    uint64_t res = ng_enter(domain_id, adapter, pack);
    __asm__ __volatile__("vzeroupper" ::: "memory");
    ng_shim_dec_depth();

    return res;
}

/*
 * ng_shim_dispatch_void_func:
 * Dispatches a void function into the designated domain via ng_enter.
 */
void ng_shim_dispatch_void_func(uint32_t domain_id, ng_compartment_fn adapter, void *pack)
{
    if (!adapter)
        return;

    t_shim_depth++;
    __asm__ __volatile__("vzeroupper" ::: "memory");
    (void)ng_enter(domain_id, adapter, pack);
    __asm__ __volatile__("vzeroupper" ::: "memory");
    ng_shim_dec_depth();
}

/*
 * Default / test interposed symbols for verifying transparent shimming
 */
int ng_shim_mock_add(int a, int b)
{
    return a + b;
}

void ng_shim_mock_clear(int *ptr)
{
    if (ptr)
        *ptr = 0;
}

/*
 * Constructor: Automatically initializes NullGate runtime when libnullgate_shim.so is preloaded.
 */
void ng_shim_init(void)
{
    if (g_shim_initialized)
        return;

    int ret = ng_init();
    if (ret != NG_SUCCESS && ret != -EEXIST) {
        /* If not running with hardware PKU, log warning but do not crash host binary */
        fprintf(stderr, "[NULLGATE SHIM] Warning: Hardware PKU runtime init returned %d\n", ret);
    }

    g_shim_initialized = true;
}
