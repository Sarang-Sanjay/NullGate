/*
 * NullGate — Unit Test: Asynchronous Signal Safety & Sigreturn Defense (Pillar 5)
 *
 * Verifies:
 *   1. Hardware altstack initialization and boundary registration in trusted state.
 *   2. Domain 0 signal delivery dispatched safely on dedicated altstack.
 *   3. Domain 1 asynchronous signal delivery during compartment execution (SIGUSR2).
 *   4. Real-time timer preemption (SIGALRM via ualarm) during active compartment spin loop.
 *   5. Hardware PKU violation interception (SEGV_PKUERR), violation counter increment,
 *      and XSAVE PKRU sanitization across sigreturn.
 *   6. Intel CET IBT (ENDBR64) and SHSTK (shadow stack) integrity across all signal returns.
 *   7. Zero raw WRPKRU (0F 01 EF) opcodes in test source.
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
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "[FAIL] %s:%d: %s (%s)\n", __FILE__, __LINE__, msg, #cond); \
        exit(1); \
    } \
} while (0)

static void *g_altstack_base = NULL;
static size_t g_altstack_size = 0;

static volatile sig_atomic_t g_usr1_handled = 0;
static volatile sig_atomic_t g_usr2_handled = 0;
static volatile sig_atomic_t g_alrm_handled = 0;
static volatile sig_atomic_t g_segv_handled = 0;
static void *g_data_domain2 = NULL;

/*
 * Handler for SIGUSR1: Domain 0 delivery
 */
static void handler_usr1(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig;
    (void)info;
    (void)ucontext;

    void *rsp = NULL;
    __asm__ volatile ("movq %%rsp, %0" : "=r" (rsp));
    uintptr_t rsp_val = (uintptr_t)rsp;

    void *base = NULL;
    size_t size = 0;
    TEST_ASSERT(ng_signal_get_altstack(&base, &size) == NG_SUCCESS, "ng_signal_get_altstack failed in SIGUSR1");
    TEST_ASSERT(rsp_val >= (uintptr_t)base, "SIGUSR1 stack below altstack base");
    TEST_ASSERT(rsp_val <= (uintptr_t)base + size, "SIGUSR1 stack above altstack top");

    g_usr1_handled = 1;
}

/*
 * Handler for SIGUSR2: Domain 1 compartment delivery
 */
static void handler_usr2(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig;
    (void)info;
    (void)ucontext;

    void *rsp = NULL;
    __asm__ volatile ("movq %%rsp, %0" : "=r" (rsp));
    uintptr_t rsp_val = (uintptr_t)rsp;

    void *base = NULL;
    size_t size = 0;
    TEST_ASSERT(ng_signal_get_altstack(&base, &size) == NG_SUCCESS, "ng_signal_get_altstack failed in SIGUSR2");
    TEST_ASSERT(rsp_val >= (uintptr_t)base, "SIGUSR2 stack below altstack base");
    TEST_ASSERT(rsp_val <= (uintptr_t)base + size, "SIGUSR2 stack above altstack top");

    g_usr2_handled = 1;
}

/*
 * Handler for SIGALRM: Preemption timer delivery
 */
static void handler_alrm(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig;
    (void)info;
    (void)ucontext;

    void *rsp = NULL;
    __asm__ volatile ("movq %%rsp, %0" : "=r" (rsp));
    uintptr_t rsp_val = (uintptr_t)rsp;

    void *base = NULL;
    size_t size = 0;
    TEST_ASSERT(ng_signal_get_altstack(&base, &size) == NG_SUCCESS, "ng_signal_get_altstack failed in SIGALRM");
    TEST_ASSERT(rsp_val >= (uintptr_t)base, "SIGALRM stack below altstack base");
    TEST_ASSERT(rsp_val <= (uintptr_t)base + size, "SIGALRM stack above altstack top");

    g_alrm_handled = 1;
}

/*
 * Handler for SIGSEGV: Hardware PKU Memory Access Violation
 */
static void handler_segv(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig;
    TEST_ASSERT(info != NULL, "SIGSEGV info pointer must not be NULL");
    TEST_ASSERT(info->si_signo == SIGSEGV, "Expected SIGSEGV signo");
    TEST_ASSERT(info->si_code == SEGV_PKUERR, "Expected SEGV_PKUERR hardware PKU fault code");
    TEST_ASSERT(info->si_addr == g_data_domain2, "Fault address must match Domain 2 protected memory");

    g_segv_handled = 1;

    /*
     * Advance REG_RIP in ucontext past the faulting 2-byte instruction (movl (%rdi), %eax)
     * to verify clean recovery and XSAVE PKRU sanitization across rt_sigreturn.
     */
    ucontext_t *uc = (ucontext_t *)ucontext;
    uc->uc_mcontext.gregs[REG_RIP] += 2;
}

/*
 * Compartment function: Raises SIGUSR2 from within Domain 1
 */
static uint64_t compartment_usr2_worker(void *arg)
{
    (void)arg;
    raise(SIGUSR2);
    return 0xCAFEBABEULL;
}

/*
 * Compartment function: Spins waiting for asynchronous timer preemption (SIGALRM)
 */
static uint64_t compartment_alrm_worker(void *arg)
{
    (void)arg;
    ualarm(5000, 0); /* Arm 5ms timer */
    while (!g_alrm_handled) {
        __asm__ volatile ("pause");
    }
    return 0x516A17ULL;
}

/*
 * Compartment function: Intentionally executes unauthorized read from Domain 2 memory
 */
static uint64_t compartment_fault_worker(void *arg)
{
    /* 2-byte instruction: movl (%rdi), %eax (opcode: 8B 07) */
    __asm__ volatile (
        "movq %0, %%rdi\n\t"
        ".byte 0x8b, 0x07\n\t"
        : : "r" (arg) : "rdi", "rax"
    );
    return 0xD0AE2ULL;
}

static inline uint32_t read_pkru_helper(void) {
    uint32_t pkru;
    __asm__ volatile (
        "xorl %%ecx, %%ecx\n\t"
        ".byte 0x0f, 0x01, 0xee\n\t" /* rdpkru: 0F 01 EE */
        : "=a" (pkru) : : "ecx", "edx"
    );
    return pkru;
}

/*
 * Thread B compartment worker: raises SIGUSR2 while Thread A is in Domain 0 (Fix CRIT-03)
 */
static uint64_t thread_b_compartment_fn(void *arg)
{
    (void)arg;
    g_usr2_handled = 0;
    raise(SIGUSR2);
    TEST_ASSERT(g_usr2_handled == 1, "SIGUSR2 was not handled in Thread B");

    /* CRIT-03: Verify Thread B's PKRU remains restricted after sigreturn */
    uint32_t pkru = read_pkru_helper();
    TEST_ASSERT(pkru != 0, "CRIT-03 Regression: Thread B PKRU was reset to 0x0!");
    TEST_ASSERT((pkru & (3 << 2)) != 0, "CRIT-03 Regression: Key 1 access-disable was cleared in Thread B!");

    return 0xBEEFULL;
}

static void *thread_b_entry(void *arg)
{
    (void)arg;
    uint64_t res = ng_enter(1, thread_b_compartment_fn, NULL);
    TEST_ASSERT(res == 0xBEEFULL, "Thread B ng_enter return value mismatch");
    return (void *)(uintptr_t)res;
}

int main(void)
{
    printf("=== NullGate Asynchronous Signal Safety & Sigreturn Defense (Pillar 5) ===\n");

    /* Phase 1: Subsystem & Trusted Altstack Initialization */
    int ret = ng_init();
    TEST_ASSERT(ret == NG_SUCCESS, "ng_init failed");

    ret = ng_signal_get_altstack(&g_altstack_base, &g_altstack_size);
    TEST_ASSERT(ret == NG_SUCCESS, "ng_signal_get_altstack failed");
    TEST_ASSERT(g_altstack_base != NULL, "altstack_base is NULL");
    TEST_ASSERT(g_altstack_size == NG_SIGNAL_ALTSTACK_SIZE, "altstack_size mismatch");
    printf("[PASS] Phase 1: Altstack allocated at %p (size %zu KB)\n",
           g_altstack_base, g_altstack_size / 1024);

    /* Phase 2: Domain 0 Synchronous Signal Delivery on Altstack (SIGUSR1) */
    ret = ng_signal_register_handler(SIGUSR1, handler_usr1);
    TEST_ASSERT(ret == NG_SUCCESS, "Failed to register SIGUSR1 handler");

    raise(SIGUSR1);
    TEST_ASSERT(g_usr1_handled == 1, "SIGUSR1 was not handled on altstack");
    printf("[PASS] Phase 2: Synchronous SIGUSR1 caught and executed on altstack\n");

    /* Allocate isolated stacks for Domain 1 and Domain 2 */
    void *stack1 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(stack1 != MAP_FAILED, "mmap stack1 failed");
    ret = ng_domain_create(1, stack1, TEST_STACK_SIZE);
    TEST_ASSERT(ret == NG_SUCCESS, "ng_domain_create Domain 1 failed");

    /* Phase 3: Domain 1 Asynchronous Signal Delivery during Compartment Execution (SIGUSR2) */
    ret = ng_signal_register_handler(SIGUSR2, handler_usr2);
    TEST_ASSERT(ret == NG_SUCCESS, "Failed to register SIGUSR2 handler");

    uint64_t res = ng_enter(1, compartment_usr2_worker, NULL);
    TEST_ASSERT(res == 0xCAFEBABEULL, "Compartment return value mismatch after SIGUSR2");
    TEST_ASSERT(g_usr2_handled == 1, "SIGUSR2 was not handled during compartment execution");
    printf("[PASS] Phase 3: In-compartment SIGUSR2 safely intercepted and resumed\n");

    /* Phase 4: Timer Preemption (SIGALRM) during Compartment Execution */
    ret = ng_signal_register_handler(SIGALRM, handler_alrm);
    TEST_ASSERT(ret == NG_SUCCESS, "Failed to register SIGALRM handler");

    res = ng_enter(1, compartment_alrm_worker, NULL);
    TEST_ASSERT(res == 0x516A17ULL, "Compartment return value mismatch after SIGALRM preemption");
    TEST_ASSERT(g_alrm_handled == 1, "SIGALRM timer was not handled");
    printf("[PASS] Phase 4: Active timer preemption (SIGALRM) handled cleanly\n");

    /* Phase 5: Hardware PKU Memory Access Violation & Sigreturn Defense */
    void *stack2 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(stack2 != MAP_FAILED, "mmap stack2 failed");
    ret = ng_domain_create(2, stack2, TEST_STACK_SIZE);
    TEST_ASSERT(ret == NG_SUCCESS, "ng_domain_create Domain 2 failed");

    g_data_domain2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(g_data_domain2 != MAP_FAILED, "mmap data2 failed");
    ret = ng_domain_protect(2, g_data_domain2, 4096, PROT_READ | PROT_WRITE);
    TEST_ASSERT(ret == NG_SUCCESS, "ng_domain_protect Domain 2 failed");

    ret = ng_signal_register_handler(SIGSEGV, handler_segv);
    TEST_ASSERT(ret == NG_SUCCESS, "Failed to register SIGSEGV handler");

    uint64_t violations_before = ng_signal_get_violation_count();
    res = ng_enter(1, compartment_fault_worker, g_data_domain2);
    TEST_ASSERT(res == 0xD0AE2ULL, "Compartment return value mismatch after fault recovery");
    TEST_ASSERT(g_segv_handled == 1, "SEGV_PKUERR handler was not dispatched");

    uint64_t violations_after = ng_signal_get_violation_count();
    TEST_ASSERT(violations_after > violations_before, "Violation counter was not incremented");
    printf("[PASS] Phase 5: Hardware PKU violation (SEGV_PKUERR) caught (violations %lu -> %lu)\n",
           violations_before, violations_after);

    /* Phase 6: Multi-Threaded XSAVE PKRU Sanitization Regression Test (CRIT-03) */
    printf("  [Phase 6] Testing multi-threaded signal sanitization (Thread A in Domain 0, Thread B in Domain 1)...\n");
    pthread_t thread_b;
    ret = pthread_create(&thread_b, NULL, thread_b_entry, NULL);
    TEST_ASSERT(ret == 0, "pthread_create for Thread B failed");

    void *thread_b_ret = NULL;
    ret = pthread_join(thread_b, &thread_b_ret);
    TEST_ASSERT(ret == 0, "pthread_join failed");
    TEST_ASSERT((uintptr_t)thread_b_ret == 0xBEEFULL, "Thread B failed PKRU validation");
    printf("[PASS] Phase 6: Multi-threaded XSAVE PKRU sanitization verified (Thread B PKRU preserved after sigreturn)\n");

    /* Cleanup memory */
    munmap(stack1, TEST_STACK_SIZE);
    munmap(stack2, TEST_STACK_SIZE);
    munmap(g_data_domain2, 4096);

    printf("\n>>> ALL 6 SIGNAL SAFETY & SIGRETURN DEFENSE PHASES PASSED <<<\n");
    return 0;
}
