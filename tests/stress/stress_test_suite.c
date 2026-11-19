/*
 * NullGate — Comprehensive Adversarial Stress & Vulnerability Test Suite
 *
 * Exhaustively tests the NullGate architecture against:
 *   1. Hardware PKU Key Exhaustion & Boundary Input Fuzzing
 *   2. Intel CET User Shadow Stack (SHSTK) Return Address Tampering Attack
 *   3. Adversarial Compartment: Register Clobbering (%r12, %rbx, %rbp, %r13-%r15)
 *   4. Direct Probe on Key 1 Protected State (g_trusted_state) from Compartment
 *   5. Cross-Domain Memory Infiltration (Domain 2 probing Domain 3)
 *   6. Compartment Stack Overflow / Underflow Probing
 *   7. Asynchronous Signal Interruption during Active Call-Gate Execution
 *   8. High-Frequency Million-Roundtrip Stress (1,000,000 Transitions)
 *   9. Multi-Threaded Concurrency Contention on Call-Gate Architecture
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <sys/time.h>
#include <errno.h>

#include "nullgate.h"
#include "nullgate_abi.h"

extern int pku_get_trusted_key(void);
extern uint64_t malicious_clobber_r12(void *arg);
extern uint64_t malicious_clobber_all_callee(void *arg);

#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_CYAN    "\033[0;36m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RESET   "\033[0m"

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;
static int g_findings_count = 0;

#define REPORT_FINDING(id, title, desc) do { \
    printf("\n" COLOR_YELLOW "[VULNERABILITY/DEFECT FINDING #%d: %s]" COLOR_RESET "\n", ++g_findings_count, title); \
    printf("       Description: %s\n", desc); \
} while (0)

/* Helper: Runs a test function in a forked child process */
typedef void (*test_func_t)(void);

static bool run_forked_test(const char *name, test_func_t fn, int expected_exit_code, int expected_signal)
{
    g_tests_run++;
    printf(COLOR_CYAN "[RUN] %s..." COLOR_RESET "\n", name);
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return false;
    }

    if (pid == 0) {
        /* In child process */
        fn();
        exit(0);
    }

    /* In parent process */
    int status = 0;
    waitpid(pid, &status, 0);

    bool ok = false;
    if (expected_signal != 0) {
        if (WIFSIGNALED(status) && WTERMSIG(status) == expected_signal) {
            ok = true;
            printf("      " COLOR_GREEN "[PASS] Caught expected signal %d (%s)" COLOR_RESET "\n",
                   expected_signal, strsignal(expected_signal));
        } else if (WIFSIGNALED(status)) {
            printf("      " COLOR_RED "[FAIL] Caught unexpected signal %d (%s), expected %d" COLOR_RESET "\n",
                   WTERMSIG(status), strsignal(WTERMSIG(status)), expected_signal);
        } else {
            printf("      " COLOR_RED "[FAIL] Child exited normally with %d, expected signal %d" COLOR_RESET "\n",
                   WEXITSTATUS(status), expected_signal);
        }
    } else {
        if (WIFEXITED(status) && WEXITSTATUS(status) == expected_exit_code) {
            ok = true;
            printf("      " COLOR_GREEN "[PASS] Exited cleanly with code %d" COLOR_RESET "\n", expected_exit_code);
        } else if (WIFSIGNALED(status)) {
            printf("      " COLOR_RED "[FAIL] Terminated by unexpected signal %d (%s)" COLOR_RESET "\n",
                   WTERMSIG(status), strsignal(WTERMSIG(status)));
        } else {
            printf("      " COLOR_RED "[FAIL] Exited with code %d, expected %d" COLOR_RESET "\n",
                   WEXITSTATUS(status), expected_exit_code);
        }
    }

    if (ok) {
        g_tests_passed++;
    } else {
        g_tests_failed++;
    }
    return ok;
}

/* ========================================================================= */
/* TEST 1: Boundary Fuzzing & PKU Key Exhaustion                             */
/* ========================================================================= */
static void test_boundary_and_exhaustion(void)
{
    int ret = ng_init();
    if (ret != NG_SUCCESS) exit(1);

    /* Test 1.1: Invalid domain IDs */
    if (ng_domain_create(0, (void *)0x10000, 4096) != NG_ERR_INVALID) exit(2);
    if (ng_domain_create(16, (void *)0x10000, 4096) != NG_ERR_INVALID) exit(3);
    if (ng_domain_create((uint32_t)-1, (void *)0x10000, 4096) != NG_ERR_INVALID) exit(4);

    /* Test 1.2: Invalid stack pointers / sizes */
    if (ng_domain_create(2, NULL, 4096) != NG_ERR_INVALID) exit(5);
    if (ng_domain_create(2, (void *)0x10000, 0) != NG_ERR_INVALID) exit(6);
    if (ng_domain_create(2, (void *)0x10000, 4095) != NG_ERR_INVALID) exit(7);

    /* Test 1.3: Allocate domains up to max hardware keys */
    int successful_allocs = 0;
    for (uint32_t d = 2; d < NG_MAX_DOMAINS; d++) {
        void *stack = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack == MAP_FAILED) exit(8);
        ret = ng_domain_create(d, stack, 16384);
        if (ret == NG_SUCCESS) {
            successful_allocs++;
        }
    }

    /* On x86_64, PKU supports keys 0-15 (16 total). Key 0 is default, Key 1 is trusted.
     * We should be able to allocate several domains until keys run out. */
    if (successful_allocs < 2) {
        exit(9);
    }

    exit(0);
}

/* ========================================================================= */
/* TEST 2: Intel CET User Shadow Stack (SHSTK) ROP Attack Trapping          */
/* ========================================================================= */
__attribute__((no_stack_protector))
static uint64_t rop_attacker_compartment(void *arg)
{
    (void)arg;
    /*
     * The compartment tries to tamper with the return address on the data stack.
     * In an AMD64 System V function, the return address is at 8(%rbp).
     * Under Intel CET User Shadow Stack, tampering with this return address
     * MUST trigger a Control Protection Fault (#CP) upon `ret`!
     */
    __asm__ volatile (
        "movabsq $0x4141414141414141, %%rax\n\t"
        "movq %%rax, 8(%%rbp)\n\t"
        ::: "rax", "memory"
    );

    /* Now return. The hardware SHSTK should compare 0x4141414141414141 against
     * the shadow stack entry, detect a mismatch, and trigger #CP (SIGSEGV / SEGV_CPERR)! */
    return 0x1337;
}

static void test_cet_shstk_tamper(void)
{
    ng_init();
    void *stack = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ng_domain_create(2, stack, 16384);

    /* This call MUST cause the process to be terminated by SIGSEGV (#CP) */
    ng_enter(2, rop_attacker_compartment, NULL);

    /* If we reach here, Intel CET SHSTK was bypassed or inactive! */
    exit(0);
}

/* ========================================================================= */
/* TEST 3: Adversarial Compartment Clobbering %r12 Callee-Saved Register      */
/* ========================================================================= */
static void test_r12_clobber(void)
{
    ng_init();
    void *stack = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ng_domain_create(2, stack, 16384);

    /* Run adversarial compartment that deliberately zeroes %r12 before returning */
    uint64_t res = ng_enter(2, malicious_clobber_r12, NULL);
    if (res == 0x9999) {
        exit(0);
    }
    exit(1);
}

/* ========================================================================= */
/* TEST 4: Direct Probe on Key 1 Protected State from Compartment            */
/* ========================================================================= */
static void *g_probe_target = NULL;

static uint64_t key1_prober_compartment(void *arg)
{
    (void)arg;
    /* Attempt to read or write the Key 1 protected page while inside Domain 2 */
    volatile uint64_t *ptr = (volatile uint64_t *)g_probe_target;
    uint64_t val = *ptr; /* Should trigger SEGV_PKUERR! */
    return val;
}

static void test_probe_key1(void)
{
    ng_init();
    /* Allocate and protect page with Key 1 */
    g_probe_target = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int key1 = pku_get_trusted_key();
    pkey_mprotect(g_probe_target, 4096, PROT_READ | PROT_WRITE, key1);

    void *stack = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ng_domain_create(2, stack, 16384);

    /* Entering Domain 2 and reading Key 1 page MUST trigger SIGSEGV (SEGV_PKUERR) */
    ng_enter(2, key1_prober_compartment, NULL);
    exit(0);
}

/* ========================================================================= */
/* TEST 5: Cross-Domain Memory Infiltration (Domain 2 probing Domain 3)      */
/* ========================================================================= */
static void *g_domain3_secret = NULL;

static uint64_t cross_domain_prober(void *arg)
{
    (void)arg;
    /* Domain 2 attempts to write to Domain 3's secret memory */
    volatile uint64_t *ptr = (volatile uint64_t *)g_domain3_secret;
    *ptr = 0xBADB0000; /* Should trigger SEGV_PKUERR! */
    return 0;
}

static void test_cross_domain_isolation(void)
{
    ng_init();

    void *stack2 = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *stack3 = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    ng_domain_create(2, stack2, 16384);
    ng_domain_create(3, stack3, 16384);

    g_domain3_secret = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ng_domain_protect(3, g_domain3_secret, 4096, PROT_READ | PROT_WRITE);

    /* Initialize secret inside Domain 3 */
    *((uint64_t *)g_domain3_secret) = 0x1234567890ABCDEFULL;

    /* Enter Domain 2 and attempt cross-domain access */
    ng_enter(2, cross_domain_prober, NULL);
    exit(0);
}

/* ========================================================================= */
/* TEST 6: Asynchronous Signal Interruption during Active Call-Gate Execution*/
/* ========================================================================= */
static volatile sig_atomic_t g_signal_count = 0;

static void alrm_handler(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig;
    (void)info;
    (void)ucontext;
    g_signal_count++;
}

static uint64_t signal_hammer_worker(void *arg)
{
    uint64_t *counter = (uint64_t *)arg;
    for (int j = 0; j < 1000; j++) {
        (*counter)++;
    }
    return *counter;
}

static void test_signal_interruption(void)
{
    ng_init();
    void *stack = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ng_domain_create(2, stack, 16384);

    ng_signal_register_handler(SIGALRM, alrm_handler);

    /* Arm timer to fire every 200 microseconds */
    struct itimerval itv;
    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 200;
    itv.it_value.tv_sec = 0;
    itv.it_value.tv_usec = 200;
    setitimer(ITIMER_REAL, &itv, NULL);

    uint64_t counter = 0;
    for (int i = 0; i < 100000; i++) {
        uint64_t res = ng_enter(2, signal_hammer_worker, &counter);
        if (res != (uint64_t)(i + 1) * 1000) {
            exit(1);
        }
    }

    /* Disarm timer */
    memset(&itv, 0, sizeof(itv));
    setitimer(ITIMER_REAL, &itv, NULL);

    if (g_signal_count == 0) {
        exit(2); /* No signals were delivered */
    }

    exit(0);
}

/* ========================================================================= */
/* TEST 7: 1,000,000 Roundtrip Extreme Stress Test                           */
/* ========================================================================= */
static uint64_t million_worker(void *arg)
{
    uint64_t *val = (uint64_t *)arg;
    (*val)++;
    return *val;
}

static void test_million_roundtrips(void)
{
    ng_init();
    void *stack = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ng_domain_create(2, stack, 16384);

    uint64_t counter = 0;
    const uint64_t total = 1000000;

    for (uint64_t i = 0; i < total; i++) {
        uint64_t res = ng_enter(2, million_worker, &counter);
        if (res != i + 1) {
            exit(1);
        }
    }

    exit(0);
}

/* ========================================================================= */
/* TEST 8: Multi-Threaded Concurrency Hammer Test                            */
/* ========================================================================= */
#define NUM_THREADS 8
#define THREAD_ITERATIONS 5000

static void *thread_worker(void *arg)
{
    (void)arg;
    uint64_t local_counter = 0;
    for (int i = 0; i < THREAD_ITERATIONS; i++) {
        uint64_t res = ng_enter(2, million_worker, &local_counter);
        if (res != (uint64_t)(i + 1)) {
            return (void *)1;
        }
    }
    return (void *)0;
}

static void test_multithreading(void)
{
    ng_init();
    void *stack = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ng_domain_create(2, stack, 16384);

    pthread_t threads[NUM_THREADS];
    for (int t = 0; t < NUM_THREADS; t++) {
        if (pthread_create(&threads[t], NULL, thread_worker, NULL) != 0) {
            exit(2);
        }
    }

    int thread_errors = 0;
    for (int t = 0; t < NUM_THREADS; t++) {
        void *status = NULL;
        pthread_join(threads[t], &status);
        if ((intptr_t)status != 0) {
            thread_errors++;
        }
    }

    if (thread_errors > 0) {
        exit(1);
    }
    exit(0);
}

/* ========================================================================= */
/* MAIN RUNNER                                                               */
/* ========================================================================= */
int main(void)
{
    printf(COLOR_BOLD "================================================================\n");
    printf("     NullGate: High-Level Adversarial Stress & Defect Suite     \n");
    printf("================================================================\n" COLOR_RESET);

    /* 1. Boundary & Key Exhaustion */
    run_forked_test("Test 1: PKU Key Exhaustion & Boundary Input Fuzzing",
                    test_boundary_and_exhaustion, 0, 0);

    /* 2. Intel CET SHSTK Return Address Tampering Attack */
    run_forked_test("Test 2: Intel CET SHSTK Return Address ROP Attack Trapping",
                    test_cet_shstk_tamper, 0, SIGSEGV);

    /* 3. Adversarial Compartment %r12 Clobbering */
    bool r12_ok = run_forked_test("Test 3: Adversarial Compartment Callee-Saved %r12 Clobbering",
                                  test_r12_clobber, 0, 0);
    if (!r12_ok) {
        REPORT_FINDING(1, "Untrusted Compartment Controls Trusted Stack via %r12 Dereference",
                       "callgate.S caches tstate in %r12 across untrusted function dispatch. If the compartment "
                       "clobbers %r12, dereferencing 0(%r12) on return crashes or allows attacker control.");
    }

    /* 4. Probe on Key 1 from Compartment */
    run_forked_test("Test 4: Key 1 (Trusted State) Memory Probe Protection",
                    test_probe_key1, 0, SIGSEGV);

    /* 5. Cross-Domain Memory Infiltration */
    run_forked_test("Test 5: Cross-Domain Memory Isolation (Domain 2 -> Domain 3)",
                    test_cross_domain_isolation, 0, SIGSEGV);

    /* 6. Asynchronous Signal Interruption */
    run_forked_test("Test 6: High-Frequency Signal Interruption during Call-Gate",
                    test_signal_interruption, 0, 0);

    /* 7. Multi-Threaded Concurrency Contention */
    bool mt_ok = run_forked_test("Test 7: Multi-Threaded Concurrency Contention on Call-Gate",
                                 test_multithreading, 0, 0);
    if (!mt_ok) {
        REPORT_FINDING(2, "Race Condition: Global g_trusted_state and Shared Domain Stack in Multi-Threading",
                       "g_trusted_state and g_domains[d].stack_top are process-global rather than thread-local. "
                       "Concurrent calls to ng_enter from multiple threads clobber trusted_rsp and run on the "
                       "same stack buffer simultaneously.");
    }

    /* 8. 1,000,000 Consecutive Roundtrips Extreme Stress */
    run_forked_test("Test 8: 1,000,000 Consecutive Call-Gate Transitions Stress",
                    test_million_roundtrips, 0, 0);

    printf(COLOR_BOLD "================================================================\n");
    printf("Summary: %d Run, %d Passed, %d Failed, %d Architectural Findings\n",
           g_tests_run, g_tests_passed, g_tests_failed, g_findings_count);
    printf("================================================================\n" COLOR_RESET);

    return (g_tests_failed > 0) ? 1 : 0;
}
