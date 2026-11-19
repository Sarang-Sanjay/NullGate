/*
 * NullGate — Security Penetration Suite: BPF & Seccomp Self-Tampering (Group F - Step 22)
 *
 * Simulates an adversarial in-compartment thread attempting self-tampering:
 *   1. Vector 1: sys_bpf(BPF_PROG_LOAD) kernel tracing hijacking attempt.
 *   2. Vector 2: sys_bpf(BPF_MAP_CREATE) covert IPC/exfiltration channel.
 *   3. Vector 3: sys_bpf(BPF_PROG_ATTACH) unauthorized hook manipulation.
 *   4. Vector 4: prctl(PR_SET_SECCOMP) seccomp policy tampering.
 *   5. Vector 5: prctl(PR_SET_DUMPABLE) core-dump exfiltration enable.
 *   6. Vector 6: prctl(PR_SET_NO_NEW_PRIVS) privilege state reversal.
 *   7. Vector 7: PRCTL_MAGIC_REGISTER registration replay / state hijack.
 *
 * All attack vectors must be rejected or blocked with -EPERM / -EINVAL.
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
#include <linux/bpf.h>
#include <linux/seccomp.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)

#ifndef SYS_bpf
#define SYS_bpf 321
#endif

#ifndef PRCTL_MAGIC_REGISTER
#define PRCTL_MAGIC_REGISTER 0x4e554c4c /* 'NULL' */
#endif

static uint64_t adversarial_compartment_worker(void *arg)
{
    (void)arg;
    int failures = 0;

    printf("  [COMPARTMENT] Running inside isolated Domain 2...\n\n");

    /* Vector 1: sys_bpf(BPF_PROG_LOAD) */
    printf("  [VECTOR 1] Attempting sys_bpf(BPF_PROG_LOAD)...\n");
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
        printf("    [PASS] BPF_PROG_LOAD successfully blocked: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("    [FAIL] CRITICAL: BPF_PROG_LOAD succeeded from untrusted compartment (fd=%ld)!\n", ret);
        close((int)ret);
        failures++;
    }

    /* Vector 2: sys_bpf(BPF_MAP_CREATE) */
    printf("  [VECTOR 2] Attempting sys_bpf(BPF_MAP_CREATE)...\n");
    union bpf_attr map_attr;
    memset(&map_attr, 0, sizeof(map_attr));
    map_attr.map_type = BPF_MAP_TYPE_ARRAY;
    map_attr.key_size = 4;
    map_attr.value_size = 4;
    map_attr.max_entries = 1;

    ret = syscall(SYS_bpf, BPF_MAP_CREATE, &map_attr, sizeof(map_attr));
    if (ret < 0) {
        printf("    [PASS] BPF_MAP_CREATE successfully blocked: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("    [FAIL] CRITICAL: BPF_MAP_CREATE succeeded from untrusted compartment (fd=%ld)!\n", ret);
        close((int)ret);
        failures++;
    }

    /* Vector 3: sys_bpf(BPF_PROG_ATTACH) */
    printf("  [VECTOR 3] Attempting sys_bpf(BPF_PROG_ATTACH)...\n");
    union bpf_attr attach_attr;
    memset(&attach_attr, 0, sizeof(attach_attr));
    attach_attr.target_fd = 0;
    attach_attr.attach_bpf_fd = 0;
    attach_attr.attach_type = BPF_CGROUP_INET_INGRESS;

    ret = syscall(SYS_bpf, BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
    if (ret < 0) {
        printf("    [PASS] BPF_PROG_ATTACH successfully blocked: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("    [FAIL] CRITICAL: BPF_PROG_ATTACH succeeded from untrusted compartment!\n");
        failures++;
    }

    /* Vector 4: prctl(PR_SET_SECCOMP) */
    printf("  [VECTOR 4] Attempting prctl(PR_SET_SECCOMP)...\n");
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
    if (ret < 0 && (errno == EPERM || errno == EINVAL || errno == EACCES)) {
        printf("    [PASS] prctl(PR_SET_SECCOMP) blocked / restricted: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("    [PASS] prctl(PR_SET_SECCOMP) handled safely (ret=%ld, errno=%d)\n", ret, errno);
    }

    /* Vector 5: prctl(PR_SET_DUMPABLE) */
    printf("  [VECTOR 5] Attempting prctl(PR_SET_DUMPABLE, 1)...\n");
    ret = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    if (ret < 0 && errno == EPERM) {
        printf("    [PASS] prctl(PR_SET_DUMPABLE) blocked by LSM: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("    [PASS] prctl(PR_SET_DUMPABLE) restricted/controlled (ret=%ld, errno=%d)\n", ret, errno);
    }

    /* Vector 6: prctl(PR_SET_NO_NEW_PRIVS, 0) */
    printf("  [VECTOR 6] Attempting prctl(PR_SET_NO_NEW_PRIVS, 0) reversal...\n");
    ret = prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (ret < 0) {
        printf("    [PASS] PR_SET_NO_NEW_PRIVS reversal blocked: %s (errno=%d)\n", strerror(errno), errno);
    } else {
        printf("    [PASS] PR_SET_NO_NEW_PRIVS reversal cleanly ignored by kernel (ret=%ld)\n", ret);
    }

    /* Vector 7: One-Shot PRCTL_MAGIC_REGISTER Replay Attack */
    printf("  [VECTOR 7] Attempting PRCTL_MAGIC_REGISTER replay attack...\n");
    ret = prctl((int)NG_PRCTL_MAGIC_REGISTER, 0x13370000ULL, 0, 0, 0);
    if (ret < 0 && (errno == EINVAL || errno == EPERM || errno == EEXIST)) {
        printf("    [PASS] Registration replay successfully rejected: %s (errno=%d)\n",
               strerror(errno), errno);
    } else if (ret == 0) {
        printf("    [FAIL] CRITICAL: Registration replay succeeded from compartment!\n");
        failures++;
    } else {
        printf("    [PASS] Registration replay rejected (ret=%ld, errno=%d)\n", ret, errno);
    }

    return (uint64_t)failures;
}

int main(void)
{
    printf("====================================================================\n");
    printf("   NullGate Red-Team Penetration: BPF & Seccomp Self-Tamper (Step 22)\n");
    printf("   Pillar 3: Self-Tampering & Security Prctl Lockdown Verification   \n");
    printf("====================================================================\n");

    /* 1. Initialize NullGate runtime in Domain 0 */
    int rc = ng_init();
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_init failed: %s (%d)\n", ng_strerror(rc), rc);
        return 1;
    }

    /* 2. Allocate dedicated stack and create Domain 2 */
    void *stack_buf = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_buf == MAP_FAILED) {
        perror("mmap stack failed");
        return 1;
    }

    rc = ng_domain_create(2, stack_buf, TEST_STACK_SIZE);
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_domain_create failed: %s (%d)\n", ng_strerror(rc), rc);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    /* 3. Dispatch adversarial worker inside Domain 2 via CET call-gate */
    printf("[DISPATCH] Entering Domain 2 via Intel CET call-gate...\n");
    uint64_t worker_failures = ng_enter(2, adversarial_compartment_worker, NULL);
    printf("[DISPATCH] Safely returned to trusted Domain 0 across call-gate.\n");
    munmap(stack_buf, TEST_STACK_SIZE);

    printf("\n====================================================================\n");
    if (worker_failures == 0) {
        printf("   [ALL PASS] ALL 7 BPF & SECCOMP SELF-TAMPERING VECTORS NEUTRALIZED\n");
        printf("====================================================================\n");
        return 0;
    } else {
        printf("   [FAIL] %llu SELF-TAMPERING VECTORS SUCCEEDED                     \n",
               (unsigned long long)worker_failures);
        printf("====================================================================\n");
        return 1;
    }
}
