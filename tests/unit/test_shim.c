/*
 * NullGate — Unit Test: Transparent Dynamic Library Interposition & Re-Entrancy
 * Verifies non-void & void interposition, errno propagation, re-entrancy depth guard, and ABI marshaling.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <setjmp.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "nullgate_shim.h"
#include "nullgate_stack_pool.h"

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] Assertion failed: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

/* Interpose mock target library functions */
NG_INTERPOSE_FUNC_2(int, mock_target_calc, 1, int, a, int, b)
NG_INTERPOSE_VOID_FUNC_2(mock_target_reset, 1, int *, ptr, int, val)
NG_INTERPOSE_FUNC_1(int, mock_target_recurse, 1, int, depth)
NG_INTERPOSE_FUNC_4(int, mock_target_multi, 1, int, a, int, b, int, c, int, d)

int main(void)
{
    printf("====================================================================\n");
    printf("       NullGate — Unit Test: Transparent Library Interposition      \n");
    printf("====================================================================\n");

    /* Step 1: Initialize NullGate Runtime & Domain 1 Stack */
    printf("[1/5] Initializing runtime and setting up compartment Domain 1...\n");
    int ret = ng_init();
    TEST_ASSERT(ret == NG_SUCCESS || ret == -EEXIST, "ng_init failed");

    struct ng_stack_slot *stk = ng_stack_pool_acquire(1, 0, 64 * 1024);
    TEST_ASSERT(stk != NULL, "Failed to acquire compartment stack from pool");

    ret = ng_domain_create(1, stk->usable_base, stk->usable_size);
    TEST_ASSERT(ret == NG_SUCCESS || ret == -EEXIST, "ng_domain_create failed");
    printf("[PASS] Runtime initialized and Domain 1 active with pooled stack.\n");

    /* Step 2: Test Non-Void Function Interposition and Errno Propagation */
    printf("[2/5] Testing non-void interposition (mock_target_calc)...\n");
    errno = 0;
    int res = mock_target_calc(5, 7);
    TEST_ASSERT(res == 57, "mock_target_calc(5, 7) returned incorrect value");
    printf("[PASS] Non-void function returned expected result: %d.\n", res);

    errno = 0;
    res = mock_target_calc(-1, 0);
    TEST_ASSERT(res == -1, "mock_target_calc(-1, 0) should return -1 on error");
    TEST_ASSERT(errno == EDOM, "errno should be EDOM after failed calculation");
    printf("[PASS] Authentically captured errno propagation across call-gate boundary (errno=EDOM).\n");

    /* Step 3: Test Void Function Interposition */
    printf("[3/5] Testing void function interposition (mock_target_reset)...\n");
    int test_target_val = 999;
    mock_target_reset(&test_target_val, 42);
    TEST_ASSERT(test_target_val == 42, "mock_target_reset failed to write value through call-gate");
    printf("[PASS] Void function interposition succeeded without return value clobbering (val=42).\n");

    /* Step 4: Test Multi-Level Re-Entrancy & Depth Guard */
    printf("[4/5] Testing multi-level re-entrant calls and Initial-Exec TLS depth guard...\n");
    TEST_ASSERT(t_shim_depth == 0, "Initial t_shim_depth must be 0");
    res = mock_target_recurse(5);
    TEST_ASSERT(res == 105, "mock_target_recurse(5) returned incorrect value");
    TEST_ASSERT(t_shim_depth == 0, "t_shim_depth must unwind cleanly to 0 after re-entrant calls");
    printf("[PASS] 5-level recursive call completed cleanly via depth bypass (result: %d).\n", res);

    /* Step 5: Test 4-Argument ABI Marshaling */
    printf("[5/6] Testing 4-argument ABI packing and dispatch (mock_target_multi)...\n");
    res = mock_target_multi(10, 20, 30, 40);
    TEST_ASSERT(res == 100, "mock_target_multi(10, 20, 30, 40) returned incorrect value");
    printf("[PASS] 4-argument pack marshaled and returned expected sum: %d.\n", res);

    /* Step 6: Test NG-P4-02: corrupted/unwound t_shim_depth recovery */
    printf("[6/6] Testing NG-P4-02: corrupted/unwound t_shim_depth recovery...\n");
    t_shim_depth = 5; /* Simulate stack unwinding having skipped t_shim_depth-- */
    /* Because interposition checks ng_get_active_domain() rather than blindly checking t_shim_depth,
     * the call must still enter domain 1 rather than bypassing compartmentalization! */
    res = mock_target_calc(20, 30);
    TEST_ASSERT(res == 230, "mock_target_calc must execute inside domain 1 even if t_shim_depth was non-zero");
    TEST_ASSERT(t_shim_depth == 0, "t_shim_depth must be cleanly reset to 0 after call-gate return");
    printf("[PASS] Compartmentalized call succeeded with active domain check and depth auto-reset (result: %d).\n", res);

    /* Clean up */
    ng_stack_pool_release(stk);

    printf("\n[ALL TESTS PASSED] Transparent library interposition & re-entrancy 100%% verified.\n");
    return 0;
}
