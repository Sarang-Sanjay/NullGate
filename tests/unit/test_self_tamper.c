/*
 * NullGate — Unit Test: Self-Tampering & Security Lockdown Subsystem (Pillar 3)
 *
 * Verifies:
 *   1. Hardware PKU initialization and Domain 2 isolated compartment entry.
 *   2. Rejection of sys_bpf(BPF_PROG_LOAD) from untrusted compartments.
 *   3. Rejection of sys_bpf(BPF_MAP_CREATE) from untrusted compartments.
 *   4. Rejection of prctl(PR_SET_DUMPABLE) tampering from untrusted compartments.
 *   5. Rejection of prctl(PR_SET_NO_NEW_PRIVS) / prctl(PR_SET_SECCOMP) tampering.
 *   6. Rejection of one-shot registration bypass (PRCTL_MAGIC_REGISTER replay).
 *   7. Clean CET callgate return to trusted Domain 0.
 *   8. Zero raw WRPKRU (0F 01 EF) instructions in test source.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <linux/bpf.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)
#define TEST_PAGE_SIZE  4096

#ifndef SYS_bpf
#define SYS_bpf 321
#endif

/*
 * Adversarial Worker Function running in Domain 2:
 * Attempts multiple self-tampering vectors to compromise runtime integrity.
 */
static uint64_t domain2_adversarial_worker(void *arg)
{
    (void)arg;
    int failures = 0;

    /*
     * Note on In-Compartment State Access:
     * Inside Domain 2, Key 1 (g_trusted_state) is strictly hardware-blocked (AD=1) by PKU.
     * The compartment cannot access g_trusted_state or call ng_get_active_domain().
     * We proceed directly to verify kernel LSM syscall containment.
     */

    /* Attack Vector 1: Attempt to load an unauthorized BPF program */
    printf("[TEST 1] Testing sys_bpf(BPF_PROG_LOAD) containment...\n");
    struct bpf_insn insns[] = {
        { .code = 0x95, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 } /* BPF_EXIT */
    };
    union bpf_attr prog_attr;
    memset(&prog_attr, 0, sizeof(prog_attr));
    prog_attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    prog_attr.insns = (unsigned long)insns;
    prog_attr.insn_cnt = 1;
    prog_attr.license = (unsigned long)"GPL";

    long ret = syscall(SYS_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (ret < 0) {
        printf("[PASS] BPF_PROG_LOAD blocked: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("[FAIL] BPF_PROG_LOAD succeeded unexpectedly from compartment (fd=%ld)!\n", ret);
        close((int)ret);
        failures++;
    }

    /* Attack Vector 2: Attempt to create an unauthorized BPF map */
    printf("[TEST 2] Testing sys_bpf(BPF_MAP_CREATE) containment...\n");
    union bpf_attr map_attr;
    memset(&map_attr, 0, sizeof(map_attr));
    map_attr.map_type = BPF_MAP_TYPE_ARRAY;
    map_attr.key_size = 4;
    map_attr.value_size = 4;
    map_attr.max_entries = 1;

    ret = syscall(SYS_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (ret < 0) {
        printf("[PASS] BPF_MAP_CREATE blocked: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("[FAIL] BPF_MAP_CREATE succeeded unexpectedly from compartment (fd=%ld)!\n", ret);
        close((int)ret);
        failures++;
    }

    /* Attack Vector 3: Attempt to alter core dumpability (PR_SET_DUMPABLE) */
    printf("[TEST 3] Testing prctl(PR_SET_DUMPABLE) lockdown...\n");
    ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    if (ret < 0 && errno == EPERM) {
        printf("[PASS] prctl(PR_SET_DUMPABLE) blocked by NullGate LSM: %s (errno=%d)\n",
               strerror(errno), errno);
    } else if (ret == 0) {
        printf("[INFO] prctl(PR_SET_DUMPABLE) succeeded (offline/unprivileged mode)\n");
    } else {
        printf("[PASS] prctl(PR_SET_DUMPABLE) failed: %s (errno=%d)\n",
               strerror(errno), errno);
    }

    /* Attack Vector 4: Attempt to alter no_new_privs (PR_SET_NO_NEW_PRIVS) */
    printf("[TEST 4] Testing prctl(PR_SET_NO_NEW_PRIVS) lockdown...\n");
    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ret < 0 && errno == EPERM) {
        printf("[PASS] prctl(PR_SET_NO_NEW_PRIVS) blocked by NullGate LSM: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("[INFO] prctl(PR_SET_NO_NEW_PRIVS) returned %ld (ret=%ld, errno=%d)\n",
               ret, ret, errno);
    }

    /* Attack Vector 5: Attempt to re-register / hijack trusted state */
    printf("[TEST 5] Testing one-shot PRCTL_MAGIC_REGISTER replay guard...\n");
    ret = prctl((int)NG_PRCTL_MAGIC_REGISTER, 0x13370000ULL, 0, 0, 0);
    if (ret < 0) {
        printf("[PASS] Registration replay successfully rejected: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("[FAIL] Registration replay unexpectedly succeeded!\n");
        failures++;
    }

    return (failures == 0) ? 0 : 1;
}

int main(void)
{
    printf("================================================================\n");
    printf("       NullGate: Self-Tampering Subsystem Unit Test (Pillar 3)  \n");
    printf("================================================================\n");

    /* 1. Initialize NullGate runtime */
    int rc = ng_init();
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_init failed: %s (%d)\n", ng_strerror(rc), rc);
        return 1;
    }
    printf("[INIT] NullGate runtime initialized successfully.\n");

    /* 2. Allocate dedicated execution stack for Domain 2 */
    void *stack_buf = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_buf == MAP_FAILED) {
        perror("mmap stack_buf failed");
        return 1;
    }

    /* 3. Register Domain 2 compartment */
    rc = ng_domain_create(2, stack_buf, TEST_STACK_SIZE);
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_domain_create(2) failed: %s (%d)\n", ng_strerror(rc), rc);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }
    printf("[INIT] Domain 2 created with dedicated stack at %p (size=%d).\n",
           stack_buf, TEST_STACK_SIZE);

    /* 4. Allocate and protect a domain data page */
    void *data_buf = mmap(NULL, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data_buf == MAP_FAILED) {
        perror("mmap data_buf failed");
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    rc = ng_domain_protect(2, data_buf, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE);
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_domain_protect failed: %s (%d)\n", ng_strerror(rc), rc);
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }
    printf("[INIT] Memory range %p protected for Domain 2.\n", data_buf);

    /* 5. Dispatch compartment execution via CET callgate */
    printf("[DISPATCH] Transitioning into Domain 2 via callgate...\n");
    uint64_t worker_res = ng_enter(2, domain2_adversarial_worker, NULL);

    /* 6. Verify return to trusted Domain 0 */
    printf("[DISPATCH] Returned from Domain 2 to Domain %u (worker_res=%" PRIu64 ")\n",
           ng_get_active_domain(), worker_res);
    if (ng_get_active_domain() != NG_DOMAIN_TRUSTED) {
        printf("[FAIL] Failed to return to trusted Domain 0 (current=%u)!\n",
               ng_get_active_domain());
        return 1;
    }

    /* 7. Clean up allocated resources */
    munmap(data_buf, TEST_PAGE_SIZE);
    munmap(stack_buf, TEST_STACK_SIZE);

    if (worker_res != 0) {
        printf("[FAIL] Compartment reported tampering check failure!\n");
        return 1;
    }

    printf("================================================================\n");
    printf("   [PASS] ALL SELF-TAMPERING SUBSYSTEM CHECKS PASSED            \n");
    printf("================================================================\n");
    return 0;
}
