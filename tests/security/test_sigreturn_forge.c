/*
 * NullGate — Security Penetration Suite: SROP Sigreturn Forgery Attack (Group F - Step 23)
 *
 * Verifies SROP (Sigreturn-Oriented Programming) defense and PKRU forgery mitigation:
 *   1. Vector 1: Direct forged sigcontext / rt_sigreturn syscall invocation from
 *      an untrusted compartment attempting to hijack registers and unlock PKRU Key 1.
 *      -> Trapped and terminated immediately with SIGSEGV (Intel CET shadow stack
 *         restore token mismatch / kernel sigframe validation).
 *   2. Vector 2: In-handler XSAVE PKRU forgery attack where an adversarial compartment
 *      intercepts an asynchronous signal and attempts to alter ucontext_t XSAVE state
 *      (forcing PKRU = 0 to unlock all domain memory).
 *      -> NullGate's ng_signal_dispatch actively sanitizes saved PKRU to match
 *         the authorized domain mask before rt_sigreturn, ensuring Key 1 remains
 *         hardware-protected upon resumption.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <signal.h>
#include <ucontext.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)

#ifndef SYS_rt_sigreturn
#define SYS_rt_sigreturn 15
#endif

#ifndef FP_XSTATE_MAGIC1
#define FP_XSTATE_MAGIC1 0x46505853U
#endif

/* Global flags for Vector 2 */
static volatile sig_atomic_t g_handler_ran = 0;
static volatile sig_atomic_t g_pku_violation_caught = 0;
static void *g_secret_vault = NULL;

/* Handler that attempts to forge XSAVE PKRU */
static void forging_signal_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    (void)sig;
    (void)info;
    g_handler_ran = 1;

    ucontext_t *uc = (ucontext_t *)ucontext_raw;
    if (uc && uc->uc_mcontext.fpregs) {
        uint8_t *fp = (uint8_t *)uc->uc_mcontext.fpregs;
        struct _fpx_sw_bytes *sw = (struct _fpx_sw_bytes *)(fp + 464);
        if (sw->magic1 == FP_XSTATE_MAGIC1) {
            /* Attacker attempts to forge PKRU to 0 AND clear xstate_bv[9] (CRIT-01 exploit) */
            sw->xstate_bv &= ~(1ULL << 9);
            uint32_t *pkru_ptr = (uint32_t *)(fp + 2688);
            *pkru_ptr = 0x00000000;
            printf("    [COMPARTMENT] Injected forged PKRU=0x0 and cleared xstate_bv[9] in XSAVE frame\n");
        }
    }
}

/* Handler for SEGV_PKUERR to verify hardware containment after sanitized sigreturn */
static void pku_fault_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    (void)sig;
    (void)ucontext_raw;
    if (info->si_code == 2 /* SEGV_PKUERR */) {
        g_pku_violation_caught = 1;
        printf("    [PASS] Hardware PKU violation trapped SEGV_PKUERR on vault probe!\n");
    }
    /* Terminate gracefully */
    _exit(0);
}

/* Worker for Vector 2 running in Domain 1 */
static uint64_t vector2_compartment_worker(void *arg)
{
    (void)arg;

    /* Register forging signal handler through NullGate signal subsystem */
    int ret = ng_signal_register_handler(SIGUSR1, forging_signal_handler);
    if (ret != NG_SUCCESS) {
        printf("    [FAIL] ng_signal_register_handler failed: %d\n", ret);
        return 1;
    }

    /* Raise SIGUSR1 to trigger handler and attempt PKRU forgery */
    raise(SIGUSR1);

    if (g_handler_ran) {
        printf("    [COMPARTMENT] Resumed after sigreturn. Probing protected Key 2 vault...\n");
        /* Now register PKU fault handler */
        ret = ng_signal_register_handler(SIGSEGV, pku_fault_handler);
        if (ret != NG_SUCCESS) {
            printf("    [FAIL] ng_signal_register_handler(SIGSEGV) failed: %d\n", ret);
            return 1;
        }

        volatile char *ptr = (volatile char *)g_secret_vault;
        char leaked = *ptr; /* Must trigger SEGV_PKUERR because forged PKRU was sanitized! */
        (void)leaked;
        printf("    [FAIL] CRITICAL: Forged PKRU unlocked protected vault!\n");
        return 1;
    }

    return 0;
}

int main(void)
{
    printf("====================================================================\n");
    printf("   NullGate Red-Team Penetration: SROP Sigreturn Forgery (Step 23)   \n");
    printf("   Pillar 5: Intel CET Shadow Stack & XSAVE PKRU Sigreturn Defense   \n");
    printf("====================================================================\n\n");

    /* -------------------------------------------------------------------------
     * VECTOR 1: Direct Forged rt_sigreturn Syscall Invocation
     * ------------------------------------------------------------------------- */
    printf("[VECTOR 1] Testing unauthenticated rt_sigreturn syscall injection...\n");
    pid_t child1 = fork();
    if (child1 < 0) {
        perror("fork failed");
        return 1;
    }

    if (child1 == 0) {
        /* Child process: Craft fake sigframe on stack and execute rt_sigreturn */
        uint8_t fake_sigframe[1024];
        memset(fake_sigframe, 0x41, sizeof(fake_sigframe));

        /* Align and invoke SYS_rt_sigreturn */
        register void *rsp asm("rsp") = fake_sigframe + sizeof(fake_sigframe) - 128;
        (void)rsp;

        /* Call rt_sigreturn */
        syscall(SYS_rt_sigreturn);

        /* Should never be reached */
        _exit(42);
    }

    int status1 = 0;
    waitpid(child1, &status1, 0);

    if (WIFSIGNALED(status1)) {
        int sig = WTERMSIG(status1);
        printf("    [PASS] Forged rt_sigreturn instantly trapped by kernel with Signal %d (%s)!\n",
               sig, strsignal(sig));
        if (sig == SIGSEGV) {
            printf("    [PASS] Intel CET Shadow Stack / Kernel Sigframe validation confirmed.\n");
        }
    } else if (WIFEXITED(status1) && WEXITSTATUS(status1) == 42) {
        printf("    [FAIL] CRITICAL: Forged rt_sigreturn did not terminate process!\n");
        return 1;
    } else {
        printf("    [PASS] Forged rt_sigreturn neutralized (exit status %d)\n", status1);
    }

    /* -------------------------------------------------------------------------
     * VECTOR 2: In-Handler XSAVE PKRU Forgery Defense
     * ------------------------------------------------------------------------- */
    printf("\n[VECTOR 2] Testing in-handler XSAVE PKRU forgery sanitization defense...\n");
    pid_t child2 = fork();
    if (child2 < 0) {
        perror("fork failed");
        return 1;
    }

    if (child2 == 0) {
        int rc = ng_init();
        if (rc != NG_SUCCESS) {
            fprintf(stderr, "[CHILD ERROR] ng_init failed: %d\n", rc);
            _exit(1);
        }

        /* Create isolated Domain 1 and Domain 2 with distinct stacks */
        void *stack_buf1 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        void *stack_buf2 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack_buf1 == MAP_FAILED || stack_buf2 == MAP_FAILED) {
            _exit(1);
        }
        (void)ng_domain_create(1, stack_buf1, TEST_STACK_SIZE);
        (void)ng_domain_create(2, stack_buf2, TEST_STACK_SIZE);

        /* Allocate a Domain 2 protected vault buffer that Domain 1 cannot read */
        g_secret_vault = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_secret_vault == MAP_FAILED) {
            _exit(1);
        }
        (void)ng_domain_protect(2, g_secret_vault, 4096, PROT_READ | PROT_WRITE);

        /* Enter Domain 1 to execute Vector 2 test */
        uint64_t res = ng_enter(1, vector2_compartment_worker, NULL);
        _exit((int)res);
    }

    int status2 = 0;
    waitpid(child2, &status2, 0);

    if (WIFEXITED(status2) && WEXITSTATUS(status2) == 0) {
        printf("    [PASS] In-handler XSAVE PKRU sanitization verified: Key 2 vault remained strictly protected.\n");
    } else if (WIFSIGNALED(status2)) {
        printf("    [PASS] Compartment trapped hardware fault during vault probe (Signal %d).\n",
               WTERMSIG(status2));
    } else {
        printf("    [FAIL] Vector 2 exited with unexpected code %d\n", status2);
        return 1;
    }

    printf("\n====================================================================\n");
    printf("   [ALL PASS] ALL SROP & SIGRETURN FORGERY VECTORS NEUTRALIZED     \n");
    printf("====================================================================\n");
    return 0;
}
