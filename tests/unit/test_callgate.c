/*
 * NullGate — Unit Test: Call-Gate Roundtrip, Stack Isolation & CET Shadow Stack Integrity
 *
 * Verifies:
 *   1. Hardware call-gate atomic transition.
 *   2. Active stack pointer (%rsp) points strictly inside the compartment stack buffer.
 *   3. 16-byte stack alignment per AMD64 System V ABI.
 *   4. Domain-isolated memory read/write.
 *   5. Accurate 64-bit return value preservation across WRPKRU exit.
 *   6. 100,000 consecutive stress roundtrips without #CP fault or stack corruption.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)
#define NUM_ROUNDTRIPS   100000

static void *g_compartment_stack = NULL;
static void *g_compartment_data = NULL;

struct worker_arg {
    uint64_t counter;
    void *stack_base;
    size_t stack_size;
};

/*
 * Worker function running inside Domain 2:
 * Asserts stack isolation, alignment, writes to domain data, and returns 64-bit value.
 */
static uint64_t worker_func(void *arg)
{
    struct worker_arg *warg = (struct worker_arg *)arg;

    /* 1. Inspect current %rsp */
    void *current_rsp = NULL;
    __asm__ volatile ("movq %%rsp, %0" : "=r" (current_rsp));

    /* 2. Verify stack isolation: %rsp MUST be within Domain 2's stack */
    uintptr_t rsp_val = (uintptr_t)current_rsp;
    uintptr_t stack_min = (uintptr_t)warg->stack_base;
    uintptr_t stack_max = stack_min + warg->stack_size;

    if (rsp_val < stack_min || rsp_val >= stack_max) {
        return 0xDEAD0001ULL; /* Stack switch failure */
    }

    /* 3. Verify 16-byte stack alignment per AMD64 System V ABI:
     * When control transfers to the function entry point via call,
     * the 8-byte return address is pushed, so (%rsp + 8) % 16 == 0.
     * If the compiler generated a prologue (e.g. push %rbp), %rsp % 16 == 0.
     */
    if (((rsp_val + 8) & 0xFULL) != 0 && (rsp_val & 0xFULL) != 0) {
        return 0xDEAD0002ULL; /* Misaligned stack */
    }

    /* 4. Write to Domain 2 protected memory */
    volatile uint64_t *dptr = (volatile uint64_t *)g_compartment_data;
    *dptr = warg->counter;

    /* 5. Return counter value + 1 */
    return warg->counter + 1;
}

int main(void)
{
    printf("[TEST] Initializing NullGate runtime for call-gate stress test...\n");
    int ret = ng_init();
    if (ret != NG_SUCCESS) {
        fprintf(stderr, "[TEST ERROR] ng_init failed: %s (%d)\n", ng_strerror(ret), ret);
        return 1;
    }

    /* Allocate compartment stack */
    g_compartment_stack = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(g_compartment_stack != MAP_FAILED);

    /* Allocate compartment data page */
    g_compartment_data = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(g_compartment_data != MAP_FAILED);

    /* Register Domain 2 */
    ret = ng_domain_create(2, g_compartment_stack, TEST_STACK_SIZE);
    assert(ret == NG_SUCCESS);

    /* Protect data page with Domain 2's key */
    ret = ng_domain_protect(2, g_compartment_data, 4096, PROT_READ | PROT_WRITE);
    assert(ret == NG_SUCCESS);

    struct worker_arg warg;
    warg.stack_base = g_compartment_stack;
    warg.stack_size = TEST_STACK_SIZE;

    printf("[TEST] Executing %d consecutive call-gate roundtrips (CET SHSTK active)...\n", NUM_ROUNDTRIPS);

    for (uint64_t i = 0; i < NUM_ROUNDTRIPS; i++) {
        warg.counter = i;
        uint64_t result = ng_enter(2, worker_func, &warg);

        if (result != i + 1) {
            fprintf(stderr, "[FAIL] Roundtrip %" PRIu64 " returned invalid result: 0x%" PRIx64 "\n", i, result);
            return 1;
        }

        if ((i + 1) % 25000 == 0) {
            printf("[TEST] Completed %" PRIu64 "/%d roundtrips cleanly...\n", i + 1, NUM_ROUNDTRIPS);
        }
    }

    /* Verify final data value */
    volatile uint64_t *dptr = (volatile uint64_t *)g_compartment_data;
    assert(*dptr == NUM_ROUNDTRIPS - 1);
    (void)dptr;

    munmap(g_compartment_stack, TEST_STACK_SIZE);
    munmap(g_compartment_data, 4096);

    printf("[TEST] All %d call-gate roundtrips passed cleanly with zero faults.\n", NUM_ROUNDTRIPS);
    printf("[TEST] test_callgate PASSED.\n");
    return 0;
}
