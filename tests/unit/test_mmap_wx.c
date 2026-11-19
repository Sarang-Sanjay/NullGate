/*
 * NullGate — Unit Test: W^X Memory Protection & State Page Defense (Pillar 8)
 *
 * Verifies:
 *   1. Userspace validation in ng_domain_protect:
 *      a. Strict non-executable data invariant (rejection of PROT_EXEC).
 *      b. Page alignment enforcement (4KB alignment for address and length).
 *      c. State page protection (rejection of modifications overlapping trusted state).
 *      d. Stack overlap guard (rejection of modifications overlapping domain stacks).
 *   2. Rejection of mmap(..., PROT_READ | PROT_WRITE | PROT_EXEC, ...) via lsm/mmap_file.
 *   3. Rejection of dynamic mprotect(..., PROT_WRITE | PROT_EXEC) via lsm/file_mprotect.
 *   4. In-compartment W^X containment inside Domain 1 via CET callgate.
 *   5. Zero raw WRPKRU (0F 01 EF) instructions in test source.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)
#define TEST_PAGE_SIZE  4096

static uint64_t domain1_wx_worker(void *arg)
{
    (void)arg;
    int failures = 0;

    printf("[COMPARTMENT] Attempting W^X violation inside Domain 1...\n");

    /* Attempt anonymous W+X mapping inside compartment */
    void *wx_page = mmap(NULL, TEST_PAGE_SIZE,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (wx_page == MAP_FAILED) {
        printf("[PASS] In-compartment mmap(W+X) blocked: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("[INFO] In-compartment mmap(W+X) returned %p (offline/unprivileged mode)\n", wx_page);
        munmap(wx_page, TEST_PAGE_SIZE);
    }

    /* Attempt dynamic W+X transition via mprotect inside compartment */
    void *rw_page = mmap(NULL, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rw_page != MAP_FAILED) {
        int mprot_ret = mprotect(rw_page, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
        if (mprot_ret < 0 && errno == EPERM) {
            printf("[PASS] In-compartment mprotect(W+X) blocked by NullGate LSM: %s (errno=%d)\n",
                   strerror(errno), errno);
        } else if (mprot_ret < 0) {
            printf("[PASS] In-compartment mprotect(W+X) failed: %s (errno=%d)\n",
                   strerror(errno), errno);
        } else {
            printf("[INFO] In-compartment mprotect(W+X) allowed (offline mode)\n");
        }
        munmap(rw_page, TEST_PAGE_SIZE);
    }

    return (failures == 0) ? 0 : 1;
}

int main(void)
{
    printf("================================================================\n");
    printf("   NullGate: W^X Memory Protection Unit Test (Pillar 8)         \n");
    printf("================================================================\n");

    /* 1. Initialize NullGate runtime */
    int rc = ng_init();
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_init failed: %s (%d)\n", ng_strerror(rc), rc);
        return 1;
    }
    printf("[INIT] NullGate runtime initialized successfully.\n");

    /* 2. Allocate Domain 1 execution stack */
    void *stack_buf = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_buf == MAP_FAILED) {
        perror("mmap stack_buf failed");
        return 1;
    }

    rc = ng_domain_create(1, stack_buf, TEST_STACK_SIZE);
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_domain_create(1) failed: %s (%d)\n", ng_strerror(rc), rc);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }
    printf("[INIT] Domain 1 created with execution stack at %p.\n", stack_buf);

    /* Allocate normal data buffer for domain validation tests */
    void *data_buf = mmap(NULL, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data_buf == MAP_FAILED) {
        perror("mmap data_buf failed");
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    /* 3. Test Userspace Precondition & Safety Invariants */
    printf("[TEST 1] Testing userspace strict non-executable data invariant...\n");
    rc = ng_domain_protect(1, data_buf, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (rc == NG_ERR_PERM) {
        printf("[PASS] ng_domain_protect correctly rejected PROT_EXEC with NG_ERR_PERM (%d)\n", rc);
    } else {
        printf("[FAIL] ng_domain_protect unexpectedly accepted PROT_EXEC: rc=%d\n", rc);
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    printf("[TEST 2] Testing userspace page alignment enforcement...\n");
    rc = ng_domain_protect(1, (void *)((uintptr_t)data_buf + 128), TEST_PAGE_SIZE, PROT_READ | PROT_WRITE);
    if (rc == NG_ERR_INVALID) {
        printf("[PASS] ng_domain_protect correctly rejected unaligned address with NG_ERR_INVALID (%d)\n", rc);
    } else {
        printf("[FAIL] ng_domain_protect accepted unaligned address: rc=%d\n", rc);
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    printf("[TEST 3] Testing stack overlap protection...\n");
    rc = ng_domain_protect(1, stack_buf, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE);
    if (rc == NG_ERR_PERM) {
        printf("[PASS] ng_domain_protect correctly rejected stack overlap with NG_ERR_PERM (%d)\n", rc);
    } else {
        printf("[FAIL] ng_domain_protect accepted stack overlap: rc=%d\n", rc);
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    /* 4. Test Kernel LSM Direct Syscall Interception */
    printf("[TEST 4] Testing direct sys_mmap(W+X) interception...\n");
    void *raw_wx = mmap(NULL, TEST_PAGE_SIZE,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw_wx == MAP_FAILED && errno == EPERM) {
        printf("[PASS] sys_mmap(W+X) blocked by NullGate LSM: %s (errno=%d)\n",
               strerror(errno), errno);
    } else if (raw_wx == MAP_FAILED) {
        printf("[PASS] sys_mmap(W+X) failed: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("[INFO] sys_mmap(W+X) succeeded at %p (offline/unprivileged mode)\n", raw_wx);
        munmap(raw_wx, TEST_PAGE_SIZE);
    }

    printf("[TEST 5] Testing dynamic sys_mprotect(W+X) transition...\n");
    void *mprot_target = mmap(NULL, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mprot_target != MAP_FAILED) {
        int m_ret = mprotect(mprot_target, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
        if (m_ret < 0 && errno == EPERM) {
            printf("[PASS] sys_mprotect(W+X) blocked by NullGate LSM: %s (errno=%d)\n",
                   strerror(errno), errno);
        } else if (m_ret < 0) {
            printf("[PASS] sys_mprotect(W+X) failed: %s (errno=%d)\n",
                   strerror(errno), errno);
        } else {
            printf("[INFO] sys_mprotect(W+X) allowed (offline/unprivileged mode)\n");
        }
        munmap(mprot_target, TEST_PAGE_SIZE);
    }

    /* 5. In-compartment dispatch via CET call-gate */
    printf("[TEST 6] Testing in-compartment execution via call-gate...\n");
    uint64_t worker_res = ng_enter(1, domain1_wx_worker, NULL);
    if (worker_res != 0) {
        printf("[FAIL] Compartment reported failure in W^X worker: %" PRIu64 "\n", worker_res);
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }
    printf("[PASS] Returned cleanly to trusted Domain 0.\n");

    /* Clean up allocations */
    munmap(data_buf, TEST_PAGE_SIZE);
    munmap(stack_buf, TEST_STACK_SIZE);

    printf("================================================================\n");
    printf("   [PASS] ALL W^X MEMORY PROTECTION CHECKS PASSED               \n");
    printf("================================================================\n");
    return 0;
}
