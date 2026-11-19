/*
 * NullGate — Transparent Library Interposition & Shim Framework Header
 * Defines the interposition ABI, Initial-Exec TLS re-entrancy guard, and macros.
 */

#ifndef NULLGATE_SHIM_H
#define NULLGATE_SHIM_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <dlfcn.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Per-thread Initial-Exec TLS re-entrancy counter.
 * Using initial-exec TLS model for maximum performance (%fs:offset) inside call-gates.
 */
extern __thread uint32_t t_shim_depth __attribute__((tls_model("initial-exec")));

/**
 * ng_shim_resolve_symbol - Lazy resolver for the real underlying symbol.
 * @symbol_name: Name of symbol to look up via RTLD_NEXT
 *
 * Returns function pointer to real symbol, or aborts if unresolved.
 */
void *ng_shim_resolve_symbol(const char *symbol_name);

/**
 * ng_shim_reset_depth - Unconditionally reset re-entrancy depth counter.
 */
void ng_shim_reset_depth(void);

/**
 * ng_shim_init - Initialize the transparent interposition subsystem.
 *
 * Automatically invoked via GCC constructor before main().
 */
void ng_shim_init(void) __attribute__((constructor));

/* =========================================================================
 * Non-Void Function Interposition Macros (NG_INTERPOSE_FUNC_*)
 * Strictly typed, captures return value and propagates errno.
 * ========================================================================= */

/* 0 Arguments */
#define NG_INTERPOSE_FUNC_0(ret_type, func_name, dom_id) \
    typedef ret_type (*__ng_fn_##func_name##_t)(void); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        ret_type ret; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        p->ret = __ng_real_##func_name(); \
        p->saved_errno = errno; \
        return 0; \
    } \
    ret_type func_name(void) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            return __ng_real_##func_name(); \
        } \
        struct __ng_pack_##func_name pack; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
        return pack.ret; \
    }

/* 1 Argument */
#define NG_INTERPOSE_FUNC_1(ret_type, func_name, dom_id, t1, a1) \
    typedef ret_type (*__ng_fn_##func_name##_t)(t1); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        t1 a1; \
        ret_type ret; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        p->ret = __ng_real_##func_name(p->a1); \
        p->saved_errno = errno; \
        return 0; \
    } \
    ret_type func_name(t1 a1) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            return __ng_real_##func_name(a1); \
        } \
        struct __ng_pack_##func_name pack; \
        pack.a1 = a1; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
        return pack.ret; \
    }

/* 2 Arguments */
#define NG_INTERPOSE_FUNC_2(ret_type, func_name, dom_id, t1, a1, t2, a2) \
    typedef ret_type (*__ng_fn_##func_name##_t)(t1, t2); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        t1 a1; \
        t2 a2; \
        ret_type ret; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        p->ret = __ng_real_##func_name(p->a1, p->a2); \
        p->saved_errno = errno; \
        return 0; \
    } \
    ret_type func_name(t1 a1, t2 a2) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            return __ng_real_##func_name(a1, a2); \
        } \
        struct __ng_pack_##func_name pack; \
        pack.a1 = a1; \
        pack.a2 = a2; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
        return pack.ret; \
    }

/* 3 Arguments */
#define NG_INTERPOSE_FUNC_3(ret_type, func_name, dom_id, t1, a1, t2, a2, t3, a3) \
    typedef ret_type (*__ng_fn_##func_name##_t)(t1, t2, t3); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        t1 a1; \
        t2 a2; \
        t3 a3; \
        ret_type ret; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        p->ret = __ng_real_##func_name(p->a1, p->a2, p->a3); \
        p->saved_errno = errno; \
        return 0; \
    } \
    ret_type func_name(t1 a1, t2 a2, t3 a3) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            return __ng_real_##func_name(a1, a2, a3); \
        } \
        struct __ng_pack_##func_name pack; \
        pack.a1 = a1; \
        pack.a2 = a2; \
        pack.a3 = a3; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
        return pack.ret; \
    }

/* 4 Arguments */
#define NG_INTERPOSE_FUNC_4(ret_type, func_name, dom_id, t1, a1, t2, a2, t3, a3, t4, a4) \
    typedef ret_type (*__ng_fn_##func_name##_t)(t1, t2, t3, t4); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        t1 a1; \
        t2 a2; \
        t3 a3; \
        t4 a4; \
        ret_type ret; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        p->ret = __ng_real_##func_name(p->a1, p->a2, p->a3, p->a4); \
        p->saved_errno = errno; \
        return 0; \
    } \
    ret_type func_name(t1 a1, t2 a2, t3 a3, t4 a4) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            return __ng_real_##func_name(a1, a2, a3, a4); \
        } \
        struct __ng_pack_##func_name pack; \
        pack.a1 = a1; \
        pack.a2 = a2; \
        pack.a3 = a3; \
        pack.a4 = a4; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
        return pack.ret; \
    }


/* =========================================================================
 * Void Function Interposition Macros (NG_INTERPOSE_VOID_FUNC_*)
 * Zero void return variable declarations; eliminates compiler warnings.
 * ========================================================================= */

/* 0 Arguments */
#define NG_INTERPOSE_VOID_FUNC_0(func_name, dom_id) \
    typedef void (*__ng_fn_##func_name##_t)(void); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        __ng_real_##func_name(); \
        p->saved_errno = errno; \
        return 0; \
    } \
    void func_name(void) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            __ng_real_##func_name(); \
            return; \
        } \
        struct __ng_pack_##func_name pack; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
    }

/* 1 Argument */
#define NG_INTERPOSE_VOID_FUNC_1(func_name, dom_id, t1, a1) \
    typedef void (*__ng_fn_##func_name##_t)(t1); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        t1 a1; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        __ng_real_##func_name(p->a1); \
        p->saved_errno = errno; \
        return 0; \
    } \
    void func_name(t1 a1) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            __ng_real_##func_name(a1); \
            return; \
        } \
        struct __ng_pack_##func_name pack; \
        pack.a1 = a1; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
    }

/* 2 Arguments */
#define NG_INTERPOSE_VOID_FUNC_2(func_name, dom_id, t1, a1, t2, a2) \
    typedef void (*__ng_fn_##func_name##_t)(t1, t2); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        t1 a1; \
        t2 a2; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        __ng_real_##func_name(p->a1, p->a2); \
        p->saved_errno = errno; \
        return 0; \
    } \
    void func_name(t1 a1, t2 a2) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            __ng_real_##func_name(a1, a2); \
            return; \
        } \
        struct __ng_pack_##func_name pack; \
        pack.a1 = a1; \
        pack.a2 = a2; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
    }

/* 3 Arguments */
#define NG_INTERPOSE_VOID_FUNC_3(func_name, dom_id, t1, a1, t2, a2, t3, a3) \
    typedef void (*__ng_fn_##func_name##_t)(t1, t2, t3); \
    static __ng_fn_##func_name##_t __ng_real_##func_name = NULL; \
    struct __ng_pack_##func_name { \
        t1 a1; \
        t2 a2; \
        t3 a3; \
        int saved_errno; \
    }; \
    static uint64_t __ng_adapter_##func_name(void *raw_pack) { \
        struct __ng_pack_##func_name *p = (struct __ng_pack_##func_name *)raw_pack; \
        errno = 0; \
        __ng_real_##func_name(p->a1, p->a2, p->a3); \
        p->saved_errno = errno; \
        return 0; \
    } \
    void func_name(t1 a1, t2 a2, t3 a3) { \
        if (!__ng_real_##func_name) { \
            __ng_real_##func_name = (__ng_fn_##func_name##_t)ng_shim_resolve_symbol(#func_name); \
        } \
        if (ng_get_active_domain() == (dom_id)) { \
            __ng_real_##func_name(a1, a2, a3); \
            return; \
        } \
        struct __ng_pack_##func_name pack; \
        pack.a1 = a1; \
        pack.a2 = a2; \
        pack.a3 = a3; \
        pack.saved_errno = 0; \
        t_shim_depth++; \
        (void)ng_enter((dom_id), __ng_adapter_##func_name, &pack); \
        t_shim_depth = 0; \
        if (pack.saved_errno) \
            errno = pack.saved_errno; \
    }

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_SHIM_H */
