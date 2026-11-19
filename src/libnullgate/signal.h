/*
 * NullGate — Asynchronous Signal Interception & Altstack Subsystem Header
 * Pillar 5: Asynchronous Signal Safety & Sigreturn Defense
 */

#ifndef NULLGATE_SIGNAL_H
#define NULLGATE_SIGNAL_H

#define _GNU_SOURCE
#include "/usr/include/signal.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants for Signal Subsystem
 */
#define NG_SIGNAL_ALTSTACK_SIZE     65536U  /* 64KB dedicated page-aligned alternate signal stack */
#define NG_SIGNAL_MAGIC             0x4e475347U /* "NGSG" */
#define NG_MAX_SIGNALS              32U

/*
 * struct ng_sigframe_ctx:
 * Trusted signal context frame maintained on the alternate signal stack.
 * Captures domain context before dispatching to userspace signal handlers.
 */
struct ng_sigframe_ctx {
    uint32_t magic;                 /* NG_SIGNAL_MAGIC */
    uint32_t interrupted_domain;    /* Domain ID active when signal interrupted thread */
    uint32_t saved_pkru;            /* Hardware PKU register value at moment of signal delivery */
    uint32_t signum;                /* Delivered POSIX signal number */
    uint64_t interrupted_rsp;       /* Data stack pointer of interrupted compartment */
    uint64_t altstack_sp;           /* Local alternate stack frame pointer */
    void    *ucontext;              /* Pointer to kernel ucontext_t passed by rt_sigaction */
    uint8_t  mac[32];               /* Cryptographic verification MAC / integrity tag */
};

/**
 * ng_signal_subsystem_init - Initialize dedicated altstack and hook asynchronous signals.
 * Allocates per-thread trusted alternate signal stack, records boundaries in g_trusted_state,
 * and installs the CET-safe assembly trampoline for SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGALRM, etc.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int ng_signal_subsystem_init(void);

/**
 * ng_signal_register_handler - Register a domain-aware signal handler.
 * @signum: POSIX signal number (e.g. SIGALRM, SIGUSR1)
 * @handler: Signal handler function taking (signum, siginfo, ucontext)
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int ng_signal_register_handler(int signum, void (*handler)(int, siginfo_t *, void *));

/**
 * ng_signal_get_altstack - Query configured alternate signal stack boundaries.
 * @base: Output pointer to receive altstack base address
 * @size: Output pointer to receive altstack size in bytes
 */
int ng_signal_get_altstack(void **base, size_t *size);

/**
 * ng_signal_get_violation_count - Query total hardware PKU memory violations observed.
 */
uint64_t ng_signal_get_violation_count(void);

/**
 * ng_signal_trampoline - Low-level CET-safe assembly trampoline entry point.
 * Intercepts signal delivery, restores Key 1 access, bounds-checks %rsp, and calls
 * ng_signal_dispatch() before returning via `ret` into glibc's __restore_rt restorer.
 */
void ng_signal_trampoline(int signum, siginfo_t *info, void *ucontext);

/**
 * ng_signal_dispatch - C dispatcher invoked by ng_signal_trampoline on trusted altstack.
 * Dispatches to registered application handler, intercepts SEGV_PKUERR, and sanitizes
 * the saved PKRU value in ucontext_t XSAVE state before sigreturn.
 */
void ng_signal_dispatch(int signum, siginfo_t *info, void *ucontext);

/**
 * ng_signal_subsystem_cleanup - Unregister signal handlers and deallocate altstack.
 */
void ng_signal_subsystem_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_SIGNAL_H */
