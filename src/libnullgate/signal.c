/*
 * NullGate — Userspace Signal Interception & Altstack Subsystem
 * Pillar 5: Asynchronous Signal Safety & Sigreturn Defense
 *
 * Implements dedicated alternate signal stack allocation, signal hooking via
 * CET-safe trampoline, SROP / sigreturn PKRU sanitization, and domain memory
 * violation diagnosis.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <cpuid.h>
#include <errno.h>
#include <unistd.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "signal.h"
#include "pku.h"

#ifndef FP_XSTATE_MAGIC1
#define FP_XSTATE_MAGIC1 0x46505853U
#endif

/*
 * Signals intercepted and routed to the NullGate alternate signal stack.
 * Covers synchronous architectural faults and common asynchronous signals.
 */
static const int g_monitored_signals[] = {
    SIGSEGV,
    SIGBUS,
    SIGILL,
    SIGFPE,
    SIGALRM,
    SIGUSR1,
    SIGUSR2
};
#define NUM_MONITORED_SIGNALS (sizeof(g_monitored_signals) / sizeof(g_monitored_signals[0]))

/* Subsystem state */
static void *g_altstack_buf = NULL;
static stack_t g_orig_sigaltstack;
static struct sigaction g_orig_sigactions[NG_MAX_SIGNALS];
static void (*g_user_handlers[NG_MAX_SIGNALS])(int, siginfo_t *, void *) = {0};
static uint32_t g_pkru_xstate_offset = 0;
static bool g_sig_subsystem_initialized = false;

/* Reference to global trusted runtime state and per-thread TLS state defined in init.c */
extern struct ng_trusted_state *g_trusted_state __attribute__((visibility("hidden")));
extern __thread struct ng_trusted_state *t_trusted_state __attribute__((tls_model("initial-exec"), visibility("hidden")));
extern void ng_enter_recover_stack_lease(void) __attribute__((visibility("hidden")));

static inline struct ng_trusted_state *get_active_trusted_state(void)
{
    if (__builtin_expect(t_trusted_state != NULL, 1)) {
        return t_trusted_state;
    }
    return g_trusted_state;
}

/**
 * init_pkru_offset - Discover PKRU offset in XSAVE frame via CPUID leaf 0xD subleaf 9.
 */
static void init_pkru_offset(void)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __cpuid_count(0xd, 9, eax, ebx, ecx, edx);
    if (ebx != 0) {
        g_pkru_xstate_offset = ebx;
    } else {
        /* Standard architectural fallback for x86_64 XSAVE */
        g_pkru_xstate_offset = 2688;
    }
}

int ng_signal_subsystem_init(void)
{
    if (g_sig_subsystem_initialized) {
        return NG_SUCCESS;
    }

    if (!g_trusted_state) {
        return NG_ERR_INVALID;
    }

    init_pkru_offset();

    /* 1. Allocate dedicated page-aligned alternate signal stack */
    g_altstack_buf = mmap(NULL, NG_SIGNAL_ALTSTACK_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_altstack_buf == MAP_FAILED) {
        g_altstack_buf = NULL;
        return NG_ERR_NOMEM;
    }

    /* 2. Configure kernel alternate signal stack for calling thread */
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = g_altstack_buf;
    ss.ss_size = NG_SIGNAL_ALTSTACK_SIZE;
    ss.ss_flags = 0;

    if (sigaltstack(&ss, &g_orig_sigaltstack) != 0) {
        munmap(g_altstack_buf, NG_SIGNAL_ALTSTACK_SIZE);
        g_altstack_buf = NULL;
        return NG_ERR_INVALID;
    }

    /* 3. Record altstack boundaries in g_trusted_state */
    g_trusted_state->altstack_base = (uint64_t)(uintptr_t)g_altstack_buf;
    g_trusted_state->altstack_size = (uint64_t)NG_SIGNAL_ALTSTACK_SIZE;
    g_trusted_state->in_signal_handler = 0;

    /* 4. Install signal handler trampoline for monitored signals */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = ng_signal_trampoline;
    sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
    sigfillset(&sa.sa_mask);

    for (size_t i = 0; i < NUM_MONITORED_SIGNALS; i++) {
        int sig = g_monitored_signals[i];
        if (sig > 0 && (uint32_t)sig < NG_MAX_SIGNALS) {
            if (sigaction(sig, &sa, &g_orig_sigactions[sig]) != 0) {
                /* Rollback previously hooked signals */
                for (size_t j = 0; j < i; j++) {
                    int prev_sig = g_monitored_signals[j];
                    sigaction(prev_sig, &g_orig_sigactions[prev_sig], NULL);
                }
                sigaltstack(&g_orig_sigaltstack, NULL);
                munmap(g_altstack_buf, NG_SIGNAL_ALTSTACK_SIZE);
                g_altstack_buf = NULL;
                g_trusted_state->altstack_base = 0;
                g_trusted_state->altstack_size = 0;
                return NG_ERR_INVALID;
            }
        }
    }

    g_sig_subsystem_initialized = true;
    return NG_SUCCESS;
}

int ng_signal_register_handler(int signum, void (*handler)(int, siginfo_t *, void *))
{
    if (signum <= 0 || (uint32_t)signum >= NG_MAX_SIGNALS) {
        return NG_ERR_INVALID;
    }

    g_user_handlers[signum] = handler;
    return NG_SUCCESS;
}

int ng_signal_get_altstack(void **base, size_t *size)
{
    struct ng_trusted_state *ts = get_active_trusted_state();
    if (!base || !size || !ts) {
        return NG_ERR_INVALID;
    }
    *base = (void *)(uintptr_t)ts->altstack_base;
    *size = (size_t)ts->altstack_size;
    return NG_SUCCESS;
}

uint64_t ng_signal_get_violation_count(void)
{
    struct ng_trusted_state *ts = get_active_trusted_state();
    if (!ts) {
        return 0;
    }
    return ts->violation_count;
}

/**
 * sanitize_ucontext_pkru - Inspect and sanitize saved PKRU in ucontext_t XSAVE frame.
 * SROP & Sigreturn Defense:
 * When Linux delivers a signal, it saves the extended CPU state in uc_mcontext.fpregs.
 * Before sigreturn restores this state, verify and sanitize the saved PKRU value
 * to match the interrupted domain mask. This prevents attackers from forging
 * permissive PKRU values on stack (SROP attack) to regain access to Key 1 (trusted state)
 * or other compartments upon return.
 */
/* Callgate trampoline entry/exit boundary symbols defined in callgate.S */
extern char __ng_callgate_enter_start[] __attribute__((visibility("hidden")));
extern char __ng_callgate_drop_privs_end[] __attribute__((visibility("hidden")));
extern char __ng_callgate_restore_privs[] __attribute__((visibility("hidden")));
extern char __ng_callgate_restore_privs_end[] __attribute__((visibility("hidden")));
extern char __ng_callgate_enter_end[] __attribute__((visibility("hidden")));

static void sanitize_ucontext_pkru(void *ucontext)
{
    struct ng_trusted_state *ts = get_active_trusted_state();
    uint32_t active_domain = (ts != NULL) ?
                             ts->current_domain : NG_DOMAIN_TRUSTED;

    if (ucontext != NULL) {
        ucontext_t *uc = (ucontext_t *)ucontext;
        uintptr_t rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
        if ((rip >= (uintptr_t)__ng_callgate_enter_start &&
             rip < (uintptr_t)__ng_callgate_drop_privs_end) ||
            (rip >= (uintptr_t)__ng_callgate_restore_privs &&
             rip < (uintptr_t)__ng_callgate_restore_privs_end)) {
            /* Interrupted inside entry or exit trampoline where PKRU 0x0 is active or being restored */
            active_domain = NG_DOMAIN_TRUSTED;
        }
    }

    if (active_domain == NG_DOMAIN_TRUSTED) {
        if (ucontext != NULL) {
            ucontext_t *uc = (ucontext_t *)ucontext;
            uint8_t *fp = (uint8_t *)uc->uc_mcontext.fpregs;
            if (fp != NULL) {
                struct _fpx_sw_bytes *sw = (struct _fpx_sw_bytes *)(fp + 464);
                if (sw->magic1 == FP_XSTATE_MAGIC1 && (sw->xstate_bv & (1ULL << 9))) {
                    if (g_pkru_xstate_offset > 0) {
                        uint32_t *saved_pkru_ptr = (uint32_t *)(fp + g_pkru_xstate_offset);
                        *saved_pkru_ptr = 0;
                    }
                }
            }
        }
        return;
    }

    /*
     * In an untrusted compartment:
     * CRITICAL SECURITY INVARIANT (Fix CRIT-01):
     * The XSAVE frame MUST be present and valid. If missing or corrupted,
     * immediately terminate to prevent SROP / XSAVE tampering bypass.
     */
    if (ucontext == NULL) {
        raise(SIGKILL);
        abort();
    }

    ucontext_t *uc = (ucontext_t *)ucontext;
    uint8_t *fp = (uint8_t *)uc->uc_mcontext.fpregs;
    if (fp == NULL) {
        raise(SIGKILL);
        abort();
    }

    struct _fpx_sw_bytes *sw = (struct _fpx_sw_bytes *)(fp + 464);
    if (sw->magic1 != FP_XSTATE_MAGIC1) {
        /* Missing extended XSAVE header or deliberately corrupted magic */
        raise(SIGKILL);
        abort();
    }

    if (g_pkru_xstate_offset == 0) {
        init_pkru_offset();
    }

    /*
     * Force xstate_bv bit 9 (PKRU) to 1.
     * This prevents attackers from clearing bit 9 so XRSTOR resets PKRU to 0x0.
     */
    sw->xstate_bv |= (1ULL << 9);

    /* Unconditionally write the restrictive domain PKRU mask */
    uint32_t *saved_pkru_ptr = (uint32_t *)(fp + g_pkru_xstate_offset);
    *saved_pkru_ptr = pku_build_pkru_mask(active_domain);
}

void ng_signal_dispatch(int signum, siginfo_t *info, void *ucontext)
{
    if (signum <= 0 || (uint32_t)signum >= NG_MAX_SIGNALS) {
        return;
    }

    struct ng_trusted_state *ts = get_active_trusted_state();

    /*
     * 1. Check for Hardware PKU Violation (SIGSEGV with SEGV_PKUERR)
     */
    if (signum == SIGSEGV && info != NULL && info->si_code == SEGV_PKUERR) {
        if (ts != NULL) {
            ts->violation_count++;
        }
    }

    /* Record authentic domain and RIP upon signal arrival */
    uint32_t orig_domain = (ts != NULL) ? ts->current_domain : NG_DOMAIN_TRUSTED;
    uintptr_t orig_rip = 0;
    if (ucontext != NULL) {
        orig_rip = (uintptr_t)((ucontext_t *)ucontext)->uc_mcontext.gregs[REG_RIP];
    }

    /*
     * 2. Inspect and Sanitize Saved PKRU in ucontext_t XSAVE State
     */
    sanitize_ucontext_pkru(ucontext);

    /*
     * 3. Forward to registered user signal handler if present
     */
    if (g_user_handlers[signum] != NULL) {
        g_user_handlers[signum](signum, info, ucontext);

        /*
         * Post-handler re-sanitization & SROP / Sigreturn Forgery Verification:
         * If the signal interrupted an untrusted compartment (orig_domain != NG_DOMAIN_TRUSTED):
         * The user handler MUST NOT be allowed to hijack REG_RIP into the supervisor callgate
         * trampoline (__ng_callgate_restore_privs) or trick the kernel into restoring PKRU=0.
         */
        if (ucontext != NULL && orig_domain != NG_DOMAIN_TRUSTED) {
            ucontext_t *uc = (ucontext_t *)ucontext;
            uintptr_t new_rip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
            if (new_rip != orig_rip &&
                new_rip >= (uintptr_t)__ng_callgate_enter_start &&
                new_rip < (uintptr_t)__ng_callgate_enter_end) {
                fprintf(stderr,
                        "[NULLGATE SROP TRAP] Untrusted domain %u attempted to forge RIP into callgate trampoline (%p)\n",
                        orig_domain, (void *)new_rip);
                raise(SIGKILL);
                abort();
            }
        }

        sanitize_ucontext_pkru(ucontext);
        return;
    }

    /*
     * 4. Default Handling:
     * For unhandled synchronous fault signals, print diagnostic, unblock the signal,
     * restore default disposition, and re-raise so the process terminates with
     * the authentic architectural signal (e.g. SIGSEGV 11).
     */
    if (signum == SIGSEGV || signum == SIGBUS || signum == SIGILL || signum == SIGFPE) {
        if (signum == SIGSEGV && info != NULL && info->si_code == SEGV_PKUERR) {
            fprintf(stderr,
                    "[NULLGATE] PKU violation in Domain %u: faulting addr %p, total violations %llu\n",
                    (ts != NULL) ? (unsigned int)ts->current_domain : 0U,
                    info->si_addr,
                    (ts != NULL) ? (unsigned long long)ts->violation_count : 1ULL);
        }
        sigset_t unblock_set;
        sigemptyset(&unblock_set);
        sigaddset(&unblock_set, signum);
        sigprocmask(SIG_UNBLOCK, &unblock_set, NULL);

        ng_enter_recover_stack_lease();
        signal(signum, SIG_DFL);
        raise(signum);
        abort();
    }
}

void ng_signal_subsystem_cleanup(void)
{
    if (!g_sig_subsystem_initialized) {
        return;
    }

    /* 1. Restore original signal actions */
    for (size_t i = 0; i < NUM_MONITORED_SIGNALS; i++) {
        int sig = g_monitored_signals[i];
        if (sig > 0 && (uint32_t)sig < NG_MAX_SIGNALS) {
            sigaction(sig, &g_orig_sigactions[sig], NULL);
            g_user_handlers[sig] = NULL;
        }
    }

    /* 2. Restore original alternate signal stack */
    sigaltstack(&g_orig_sigaltstack, NULL);

    /* 3. Unmap allocated altstack buffer */
    if (g_altstack_buf != NULL) {
        munmap(g_altstack_buf, NG_SIGNAL_ALTSTACK_SIZE);
        g_altstack_buf = NULL;
    }

    struct ng_trusted_state *ts = get_active_trusted_state();
    if (ts != NULL) {
        ts->altstack_base = 0;
        ts->altstack_size = 0;
        ts->in_signal_handler = 0;
    }

    g_sig_subsystem_initialized = false;
}
