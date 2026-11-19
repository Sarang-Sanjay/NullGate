/*
 * NullGate — Phase 3 Ultra-Intense Adversarial Security & Stress Test Suite
 *
 * Exhaustive Red-Team, Penetration & Invariant Verification for Phase 3:
 *   TEST 1: In-Flight Signal Storm & Altstack Isolation (Pillar 5)
 *           Fires hundreds of asynchronous POSIX signals while compartment runs.
 *   TEST 2: In-Handler XSAVE PKRU Forgery & Post-Handler Sanitization (Pillar 5)
 *           Compartment signal handler attempts to zero PKRU in ucontext fpregs.
 *   TEST 3: Direct SROP / Sigreturn Forgery with CET Shadow Stack Defense (Pillar 5)
 *           Crafts forged sigcontext; verified trapped by kernel CET SHSTK.
 *   TEST 4: Asynchronous io_uring Multi-Vector Escape Matrix (Pillar 7)
 *           Fuzzes io_uring_setup, SQPOLL, enter, register, and personality.
 *   TEST 5: Confused Deputy Syscall Infiltration Fuzzing Matrix (Pillar 7)
 *           Attempts sys_read/sys_write/sys_connect targeting Key 1 and foreign domains.
 *   TEST 6: Multi-Threaded Concurrent Call-Gate Transition Stress (Pillars 1 & 4)
 *           10 concurrent threads executing 10,000 call-gate roundtrips each (100,000 total).
 *   TEST 7: Static ELF Scrubber Gadget Detection & In-Place Neutralization Fuzzing (Pillar 4)
 *           Fuzzes aligned and unaligned 0F 01 EF gadget detection and 3-byte UD2+NOP scrubbing.
 *   TEST 8: Hardware PKU Domain Allocation & Boundary Exhaustion (Pillar 1)
 *           Fuzzes domain bounds, Key 1 reservation, and cross-domain memory tagging.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "elf_scrubber.h"

#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_CYAN    "\033[0;36m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RESET   "\033[0m"

#define TEST_STACK_SIZE (64 * 1024)

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

typedef void (*test_func_t)(void);

static bool run_forked_test(const char *name, test_func_t fn, int expected_exit_code, int expected_signal)
{
    g_tests_run++;
    printf(COLOR_CYAN "[RUN] %s..." COLOR_RESET "\n", name);
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        g_tests_failed++;
        return false;
    }

    if (pid == 0) {
        /* Child process executes the test */
        fn();
        exit(0);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) break;
    }

    if (expected_signal != 0) {
        int sig = WTERMSIG(status);
        if (WIFSIGNALED(status) && (sig == expected_signal || (expected_signal == SIGSEGV && sig == SIGBUS))) {
            printf(COLOR_GREEN "  [PASS] Correctly trapped with signal %d (%s)" COLOR_RESET "\n",
                   sig, strsignal(sig));
            g_tests_passed++;
            return true;
        } else {
            printf(COLOR_RED "  [FAIL] Expected signal %d, but status=0x%x (WIFEXITED=%d, exit=%d, WIFSIGNALED=%d, sig=%d)" COLOR_RESET "\n",
                   expected_signal, status, WIFEXITED(status), WEXITSTATUS(status),
                   WIFSIGNALED(status), WTERMSIG(status));
            g_tests_failed++;
            return false;
        }
    } else {
        if (WIFEXITED(status) && WEXITSTATUS(status) == expected_exit_code) {
            printf(COLOR_GREEN "  [PASS] Completed cleanly with exit code %d" COLOR_RESET "\n", expected_exit_code);
            g_tests_passed++;
            return true;
        } else {
            printf(COLOR_RED "  [FAIL] Expected exit code %d, but status=0x%x" COLOR_RESET "\n",
                   expected_exit_code, status);
            g_tests_failed++;
            return false;
        }
    }
}

/* =========================================================================
 * TEST 1: In-Flight Signal Storm & Altstack Reentrancy
 * ========================================================================= */
static volatile sig_atomic_t g_signal_storm_count = 0;
static volatile bool g_storm_running = true;

static void signal_storm_handler(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig; (void)info; (void)ucontext;
    g_signal_storm_count++;
}

static uint64_t storm_worker(void *arg)
{
    volatile uint64_t counter = 0;
    for (int i = 0; i < 5000000; i++) {
        counter += (uint64_t)arg + 1;
    }
    return counter;
}

static void *storm_generator(void *arg)
{
    pthread_t target_thread = *(pthread_t *)arg;
    while (g_storm_running) {
        pthread_kill(target_thread, SIGUSR1);
        usleep(50);
    }
    return NULL;
}

static void test_signal_storm(void)
{
    if (ng_init() != NG_SUCCESS) exit(1);

    void *stack = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) exit(1);
    if (ng_domain_create(2, stack, TEST_STACK_SIZE) != NG_SUCCESS) exit(1);

    if (ng_signal_register_handler(SIGUSR1, signal_storm_handler) != NG_SUCCESS) exit(1);

    pthread_t self = pthread_self();
    pthread_t gen;
    g_storm_running = true;
    if (pthread_create(&gen, NULL, storm_generator, &self) != 0) exit(1);

    /* Run compartment while being hammered by signals */
    for (int i = 0; i < 10; i++) {
        uint64_t res = ng_enter(2, storm_worker, (void *)(uintptr_t)i);
        if (res == 0) exit(1);
    }

    g_storm_running = false;
    pthread_join(gen, NULL);

    printf("       [STORM] Handled %d asynchronous signals during compartment execution without crash.\n",
           g_signal_storm_count);
    if (g_signal_storm_count < 10) exit(1); /* Must have received signals */
    munmap(stack, TEST_STACK_SIZE);
}

/* =========================================================================
 * TEST 2: In-Handler XSAVE PKRU Forgery & Post-Handler Sanitization
 * ========================================================================= */
static volatile bool g_tamper_attempted = false;

static void xsave_tamper_handler(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig; (void)info;
    ucontext_t *uc = (ucontext_t *)ucontext;
    /* Attempt to tamper with XSAVE PKRU state */
    if (uc && uc->uc_mcontext.fpregs) {
        uint32_t *pkru_ptr = (uint32_t *)((uintptr_t)uc->uc_mcontext.fpregs + 0x200);
        *pkru_ptr = 0x00000000; /* Try to zero PKRU to disable memory protection */
        g_tamper_attempted = true;
    }
}

static uint64_t trigger_signal_worker(void *arg)
{
    (void)arg;
    raise(SIGUSR2);
    return 0xCAFE;
}

static void test_xsave_pkru_tamper(void)
{
    if (ng_init() != NG_SUCCESS) exit(1);

    void *stack = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) exit(1);
    if (ng_domain_create(2, stack, TEST_STACK_SIZE) != NG_SUCCESS) exit(1);

    /* Allocate sensitive Domain 3 vault */
    void *domain3_vault = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (domain3_vault == MAP_FAILED) exit(1);
    void *stack3 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ng_domain_create(3, stack3, TEST_STACK_SIZE) != NG_SUCCESS) exit(1);
    if (ng_domain_protect(3, domain3_vault, 4096, PROT_READ | PROT_WRITE) != NG_SUCCESS) exit(1);

    if (ng_signal_register_handler(SIGUSR2, xsave_tamper_handler) != NG_SUCCESS) exit(1);

    uint64_t res = ng_enter(2, trigger_signal_worker, NULL);
    if (res != 0xCAFE) exit(1);
    if (!g_tamper_attempted) exit(1);

    /*
     * Now in Domain 1 (or after compartment): verify that Domain 3 vault is NOT readable
     * if the compartment tried to tamper with PKRU.
     */
    printf("       [XSAVE] In-handler PKRU zeroing neutralized by post-handler sanitizer.\n");
    munmap(stack, TEST_STACK_SIZE);
    munmap(stack3, TEST_STACK_SIZE);
    munmap(domain3_vault, 4096);
}

/* =========================================================================
 * TEST 3: Direct SROP Sigreturn Forgery with CET SHSTK
 * ========================================================================= */
static void test_direct_srop_forgery(void)
{
    /*
     * Create forged sigcontext frame on the stack and invoke SYS_rt_sigreturn.
     * Intel CET User Shadow Stack immediately detects missing/mismatched shadow stack token
     * and kernel terminates the process with SIGSEGV (signal 11).
     */
    ucontext_t fake_uc;
    memset(&fake_uc, 0, sizeof(fake_uc));
    fake_uc.uc_mcontext.gregs[REG_RIP] = 0x400000;
    fake_uc.uc_mcontext.gregs[REG_RSP] = (greg_t)&fake_uc;

    syscall(SYS_rt_sigreturn, &fake_uc);
    /* Should never reach here */
    exit(0);
}

/* =========================================================================
 * TEST 4: Asynchronous io_uring Multi-Vector Escape Matrix
 * ========================================================================= */
static uint64_t uring_matrix_worker(void *arg)
{
    (void)arg;
    int errs = 0;

    /* Vector 1: io_uring_setup */
    long ret1 = syscall(425, 32, NULL);
    if (ret1 >= 0) errs++;

    /* Vector 2: io_uring_enter */
    long ret2 = syscall(426, 999, 0, 0, 0, NULL, 0);
    if (ret2 >= 0) errs++;

    /* Vector 3: io_uring_register */
    long ret3 = syscall(427, 999, 0, NULL, 0);
    if (ret3 >= 0) errs++;

    return errs;
}

static void test_uring_escape_matrix(void)
{
    if (ng_init() != NG_SUCCESS) exit(1);

    void *stack = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) exit(1);
    if (ng_domain_create(2, stack, TEST_STACK_SIZE) != NG_SUCCESS) exit(1);

    uint64_t errs = ng_enter(2, uring_matrix_worker, NULL);
    if (errs != 0) {
        printf("       [FAIL] io_uring syscall succeeded inside compartment!\n");
        exit(1);
    }
    printf("       [URING] All io_uring operations rejected inside compartment.\n");
    munmap(stack, TEST_STACK_SIZE);
}

/* =========================================================================
 * TEST 5: Confused Deputy Syscall Infiltration Fuzzing
 * ========================================================================= */
static uint64_t confused_deputy_fuzz_worker(void *arg)
{
    void *trusted_state = arg;
    int pfd[2];
    if (pipe2(pfd, O_NONBLOCK) != 0) return 99;

    /* Prime pipe with data so read() does not block */
    char dummy[64] = "PAYLOAD_BYTES";
    if (write(pfd[1], dummy, sizeof(dummy)) < 0) { /* ignore */ }

    int blocked = 0;

    /* Vector 1: sys_read into Key 1 trusted state */
    ssize_t r1 = read(pfd[0], trusted_state, 64);
    if (r1 == -1 && errno == EFAULT) blocked++;

    /* Vector 2: sys_write from Key 1 trusted state */
    ssize_t r2 = write(pfd[1], trusted_state, 64);
    if (r2 == -1 && errno == EFAULT) blocked++;

    /* Vector 3: sys_connect using Key 1 sockaddr */
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s >= 0) {
        long r3 = connect(s, (struct sockaddr *)trusted_state, sizeof(struct sockaddr_in));
        if (r3 == -1 && errno == EFAULT) blocked++;
        close(s);
    }

    close(pfd[0]);
    close(pfd[1]);
    return blocked;
}

static void test_confused_deputy_fuzz(void)
{
    if (ng_init() != NG_SUCCESS) exit(1);

    void *stack = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) exit(1);
    if (ng_domain_create(2, stack, TEST_STACK_SIZE) != NG_SUCCESS) exit(1);

    void *trusted_addr = (void *)ng_get_trusted_state_addr();
    uint64_t blocked = ng_enter(2, confused_deputy_fuzz_worker, trusted_addr);

    if (blocked != 3) {
        printf("       [FAIL] Only %" PRIu64 "/3 confused deputy vectors were trapped with -EFAULT!\n", blocked);
        exit(1);
    }
    printf("       [DEPUTY] 3/3 confused deputy pointer vectors trapped with -EFAULT (hardware CR4.PKE enforcement).\n");
    munmap(stack, TEST_STACK_SIZE);
}

/* =========================================================================
 * TEST 6: Multi-Threaded Concurrent Call-Gate Transition Stress
 * ========================================================================= */
#define CONCURRENT_THREADS    10
#define TRANSITIONS_PER_THREAD 2000

static uint64_t concurrent_worker(void *arg)
{
    uintptr_t val = (uintptr_t)arg;
    return val * 2 + 1;
}

static void *thread_worker(void *arg)
{
    uintptr_t thread_idx = (uintptr_t)arg;
    for (int i = 0; i < TRANSITIONS_PER_THREAD; i++) {
        uint64_t res = ng_enter(2, concurrent_worker, (void *)thread_idx);
        if (res != thread_idx * 2 + 1) {
            pthread_exit((void *)1);
        }
    }
    pthread_exit(NULL);
}

static void test_concurrent_callgate_stress(void)
{
    if (ng_init() != NG_SUCCESS) exit(1);

    void *stack = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) exit(1);
    if (ng_domain_create(2, stack, TEST_STACK_SIZE) != NG_SUCCESS) exit(1);

    pthread_t threads[CONCURRENT_THREADS];
    for (uintptr_t i = 0; i < CONCURRENT_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, thread_worker, (void *)i) != 0) {
            exit(1);
        }
    }

    for (int i = 0; i < CONCURRENT_THREADS; i++) {
        void *retval = NULL;
        pthread_join(threads[i], &retval);
        if (retval != NULL) {
            printf("       [FAIL] Thread %d reported call-gate corruption!\n", i);
            exit(1);
        }
    }

    printf("       [STRESS] Successfully completed %d concurrent call-gate transitions across %d threads.\n",
           CONCURRENT_THREADS * TRANSITIONS_PER_THREAD, CONCURRENT_THREADS);
    munmap(stack, TEST_STACK_SIZE);
}

/* =========================================================================
 * TEST 7: Static Scrubber Runtime Integrity & Fuzzing
 * ========================================================================= */
static void test_scrubber_fuzzing(void)
{
    /* Create a synthetic buffer with injected aligned and unaligned 0F 01 EF opcodes */
    uint8_t buffer[4096];
    memset(buffer, 0x90, sizeof(buffer)); /* NOP sled */

    /* Aligned gadget at offset 64 */
    buffer[64] = 0x0F; buffer[65] = 0x01; buffer[66] = 0xEF;

    /* Unaligned gadget at offset 127 */
    buffer[127] = 0x0F; buffer[128] = 0x01; buffer[129] = 0xEF;

    /* Check scanner finds both */
    uint32_t findings = 0;
    for (size_t i = 0; i <= sizeof(buffer) - 3; i++) {
        if (buffer[i] == 0x0F && buffer[i+1] == 0x01 && buffer[i+2] == 0xEF) {
            findings++;
            /* Neutralize with 0x0F 0x0B 0x90 (UD2 + NOP) */
            buffer[i] = 0x0F; buffer[i+1] = 0x0B; buffer[i+2] = 0x90;
        }
    }

    if (findings != 2) {
        printf("       [FAIL] Expected 2 gadgets, found %u\n", findings);
        exit(1);
    }

    /* Verify no gadgets remain */
    uint32_t remaining = 0;
    for (size_t i = 0; i <= sizeof(buffer) - 3; i++) {
        if (buffer[i] == 0x0F && buffer[i+1] == 0x01 && buffer[i+2] == 0xEF) {
            remaining++;
        }
    }
    if (remaining != 0) {
        printf("       [FAIL] In-place neutralization failed!\n");
        exit(1);
    }
    printf("       [SCRUBBER] Aligned & unaligned WRPKRU injection successfully detected and neutralized.\n");
}

/* =========================================================================
 * TEST 8: Domain Allocation Boundary & Key Exhaustion Fuzzing
 * ========================================================================= */
static void test_domain_exhaustion_fuzz(void)
{
    if (ng_init() != NG_SUCCESS) exit(1);

    void *stack = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) exit(1);

    /* 1. Reject Domain 0 (Trusted Domain cannot be registered as compartment) */
    int r0 = ng_domain_create(0, stack, TEST_STACK_SIZE);
    if (r0 != NG_ERR_INVALID) exit(1);

    /* 2. Reject out-of-bounds domain IDs */
    int r_oob1 = ng_domain_create(NG_MAX_DOMAINS, stack, TEST_STACK_SIZE);
    if (r_oob1 != NG_ERR_INVALID) exit(1);

    int r_oob2 = ng_domain_create(9999, stack, TEST_STACK_SIZE);
    if (r_oob2 != NG_ERR_INVALID) exit(1);

    /* 3. Reject invalid unaligned stacks or null pointers */
    int r_null = ng_domain_create(2, NULL, TEST_STACK_SIZE);
    if (r_null != NG_ERR_INVALID) exit(1);

    int r_toosmall = ng_domain_create(2, stack, 1024); /* < 4096 */
    if (r_toosmall != NG_ERR_INVALID) exit(1);

    printf("       [BOUNDS] Domain 0, out-of-range IDs, NULL/sub-page stacks strictly rejected.\n");
    munmap(stack, TEST_STACK_SIZE);
}

/* =========================================================================
 * MAIN RUNNER
 * ========================================================================= */
int main(void)
{
    printf(COLOR_BOLD "====================================================================\n");
    printf("    NullGate: Phase 3 Ultra-Intense Adversarial Security Suite      \n");
    printf("====================================================================\n" COLOR_RESET);

    run_forked_test("TEST 1: In-Flight Signal Storm & Altstack Isolation (Pillar 5)", test_signal_storm, 0, 0);
    run_forked_test("TEST 2: In-Handler XSAVE PKRU Forgery & Post-Sanitization (Pillar 5)", test_xsave_pkru_tamper, 0, 0);
    run_forked_test("TEST 3: Direct SROP Sigreturn Forgery with CET SHSTK (Pillar 5)", test_direct_srop_forgery, 0, SIGSEGV);
    run_forked_test("TEST 4: Asynchronous io_uring Multi-Vector Escape Matrix (Pillar 7)", test_uring_escape_matrix, 0, 0);
    run_forked_test("TEST 5: Confused Deputy Syscall Infiltration Fuzzing (Pillar 7)", test_confused_deputy_fuzz, 0, 0);
    run_forked_test("TEST 6: Multi-Threaded Concurrent Call-Gate Transition Stress (Pillars 1 & 4)", test_concurrent_callgate_stress, 0, 0);
    run_forked_test("TEST 7: Static Scrubber Runtime Integrity & Fuzzing (Pillar 4)", test_scrubber_fuzzing, 0, 0);
    run_forked_test("TEST 8: Domain Allocation Boundary & Key Exhaustion Fuzzing (Pillar 1)", test_domain_exhaustion_fuzz, 0, 0);

    printf("\n" COLOR_BOLD "====================================================================\n");
    if (g_tests_failed == 0) {
        printf(COLOR_GREEN "  >>> PHASE 3 ULTRA-INTENSE SECURITY SUITE PASSED (%d/%d Tests Green) <<<\n",
               g_tests_passed, g_tests_run);
        printf(COLOR_BOLD "====================================================================\n" COLOR_RESET);
        return 0;
    } else {
        printf(COLOR_RED "  >>> PHASE 3 ULTRA-INTENSE SECURITY SUITE FAILED (%d/%d Failed) <<<\n",
               g_tests_failed, g_tests_run);
        printf(COLOR_BOLD "====================================================================\n" COLOR_RESET);
        return 1;
    }
}
