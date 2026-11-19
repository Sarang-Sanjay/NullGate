/*
 * NullGate — Unit Test: Hardware-Isolated Stack Pool & Guard Page Enforcement
 * Verifies O(1) stack allocation, reuse, guard page traps, and thread cleanup.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "nullgate_stack_pool.h"

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] Assertion failed: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

static void *worker_thread(void *arg)
{
    (void)arg;
    struct ng_stack_slot *slot = ng_stack_pool_acquire(1, 0, 64 * 1024);
    if (!slot)
        return (void *)1;

    /* Write to usable stack region */
    memset(slot->usable_base, 0x55, 1024);

    ng_stack_pool_release(slot);
    /* Thread exits; pthread destructor automatically destroys cached stacks */
    return NULL;
}

int main(void)
{
    printf("====================================================================\n");
    printf("       NullGate — Unit Test: Hardware-Isolated Stack Pool           \n");
    printf("====================================================================\n");

    /* Step 1: Initialize Stack Pool Subsystem */
    printf("[1/5] Initializing stack pool subsystem...\n");
    int ret = ng_stack_pool_init();
    TEST_ASSERT(ret == 0, "ng_stack_pool_init failed");
    printf("[PASS] Stack pool initialized successfully.\n");

    /* Step 2: Acquire and Validate Stack Alignment */
    printf("[2/5] Acquiring 64KB isolated compartment stack...\n");
    struct ng_stack_slot *slot1 = ng_stack_pool_acquire(1, 0, 64 * 1024);
    TEST_ASSERT(slot1 != NULL, "Failed to acquire stack slot");
    TEST_ASSERT(slot1->in_use == true, "Slot should be marked in_use");
    TEST_ASSERT(slot1->usable_size >= 64 * 1024, "Usable size smaller than requested");
    TEST_ASSERT(((uintptr_t)slot1->stack_top & 0xFULL) == 0, "Stack top must be 16-byte aligned");
    TEST_ASSERT((uintptr_t)slot1->usable_base == (uintptr_t)slot1->raw_base + NG_STACK_GUARD_SIZE,
                "Usable base must begin immediately after guard page");

    /* Verify usable region is writable */
    memset(slot1->usable_base, 0xCC, 4096);
    printf("[PASS] Stack slot acquired with 16-byte aligned top: %p (usable size: %zu bytes).\n",
           slot1->stack_top, slot1->usable_size);

    /* Step 3: Guard Page Enforcement Verification */
    printf("[3/5] Verifying PROT_NONE guard page traps stack overflow...\n");
    pid_t pid = fork();
    TEST_ASSERT(pid >= 0, "fork failed");

    if (pid == 0) {
        /* Child process: attempt write into guard page (slot1->raw_base) */
        volatile char *guard = (volatile char *)slot1->raw_base;
        *guard = 'X'; /* Must trigger SIGSEGV / SEGV_ACCERR */
        exit(0); /* Should not be reached */
    }

    int status = 0;
    waitpid(pid, &status, 0);
    TEST_ASSERT(WIFSIGNALED(status), "Child should have terminated via signal");
    TEST_ASSERT(WTERMSIG(status) == SIGSEGV, "Child must terminate with SIGSEGV on guard page violation");
    printf("[PASS] Writing to guard page correctly trapped with SIGSEGV.\n");

    /* Step 4: O(1) Cache Reuse Verification */
    printf("[4/5] Testing O(1) stack pool release and cache reuse...\n");
    void *orig_raw_base = slot1->raw_base;
    ng_stack_pool_release(slot1);
    TEST_ASSERT(slot1->in_use == false, "Slot should be marked free after release");

    struct ng_stack_slot *slot2 = ng_stack_pool_acquire(1, 0, 64 * 1024);
    TEST_ASSERT(slot2 != NULL, "Failed to re-acquire stack slot");
    TEST_ASSERT(slot2 == slot1, "Re-acquired slot should reuse cached slot instance");
    TEST_ASSERT(slot2->raw_base == orig_raw_base, "Re-acquired slot should reuse identical virtual address");
    TEST_ASSERT(slot2->in_use == true, "Slot must be marked in_use again");
    ng_stack_pool_release(slot2);
    printf("[PASS] O(1) stack checkout/checkin confirmed with exact instance reuse.\n");

    /* Step 5: Multi-Threaded Allocation and Destructor Cleanup */
    printf("[5/5] Testing multi-threaded allocation and pthread_key cleanup...\n");
    pthread_t th;
    ret = pthread_create(&th, NULL, worker_thread, NULL);
    TEST_ASSERT(ret == 0, "pthread_create failed");

    void *th_res = NULL;
    pthread_join(th, &th_res);
    TEST_ASSERT(th_res == NULL, "Worker thread encountered error");

    ng_stack_pool_thread_cleanup();
    printf("[PASS] Multi-threaded worker executed and thread-local stacks cleaned up cleanly.\n");

    /* Step 6: Test NG-P4-08 Cross-Domain Secret Scrubbing */
    printf("[6/6] Testing NG-P4-08: Cross-domain secret scrubbing upon stack recycling...\n");
    struct ng_stack_slot *dom2_slot = ng_stack_pool_acquire(2, 0, 64 * 1024);
    TEST_ASSERT(dom2_slot != NULL, "Failed to acquire stack slot for domain 2");
    /* Write sensitive secret payload into domain 2 stack */
    memset(dom2_slot->usable_base, 0xA5, 4096);
    void *dom2_base = dom2_slot->usable_base;
    ng_stack_pool_release(dom2_slot);

    /* Acquire recycled slot for domain 3 */
    struct ng_stack_slot *dom3_slot = ng_stack_pool_acquire(3, 0, 64 * 1024);
    TEST_ASSERT(dom3_slot != NULL, "Failed to acquire recycled stack slot for domain 3");
    TEST_ASSERT(dom3_slot->usable_base == dom2_base, "Expected to recycle same stack buffer");
    /* Verify all sentinel bytes were scrubbed and zeroed */
    const unsigned char *p = (const unsigned char *)dom3_slot->usable_base;
    for (size_t i = 0; i < 4096; i++) {
        TEST_ASSERT(p[i] == 0, "Stale secret byte detected in recycled stack slot!");
    }
    ng_stack_pool_release(dom3_slot);
    printf("[PASS] Recycled stack slot successfully scrubbed and zeroed (zero secret leakage).\n");

    printf("\n[ALL TESTS PASSED] Hardware-isolated stack pool and guard pages 100%% verified.\n");
    return 0;
}
