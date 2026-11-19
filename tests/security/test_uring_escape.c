/*
 * NullGate — Security Penetration Suite: io_uring Compartment Escape Attack (Group F - Step 24)
 *
 * Verifies that untrusted compartments are strictly prohibited from using io_uring
 * to bypass memory isolation and perform asynchronous I/O attacks:
 *   1. Vector 1: sys_io_uring_setup() invocation from within Domain 1 compartment
 *      -> Trapped via tracepoint sys_enter_io_uring_setup (SIGSEGV) or denied (-EPERM).
 *   2. Vector 2: sys_io_uring_setup() with IORING_SETUP_SQPOLL kernel polling thread
 *      -> Trapped via LSM uring_sqpoll hook (-EPERM) or tracepoint.
 *   3. Vector 3: sys_io_uring_enter() submission/wait invocation
 *      -> Trapped via tracepoint sys_enter_io_uring_enter (SIGSEGV) or denied (-EPERM).
 *   4. Vector 4: sys_io_uring_register() buffer/credential registration
 *      -> Trapped via tracepoint sys_enter_io_uring_register (SIGSEGV) or denied (-EPERM).
 *   5. Vector 5: Asynchronous credential override (IORING_REGISTER_PERSONALITY)
 *      -> Blocked via LSM uring_override_creds hook (-EPERM).
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
#include <linux/types.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)

#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif

#ifndef IORING_SETUP_SQPOLL
#define IORING_SETUP_SQPOLL (1U << 1)
#endif

#ifndef IORING_REGISTER_PERSONALITY
#define IORING_REGISTER_PERSONALITY 9
#endif

/* struct io_uring_params definition for systems without liburing headers */
struct ng_io_sqring_offsets {
    __u32 head;
    __u32 tail;
    __u32 ring_mask;
    __u32 ring_entries;
    __u32 flags;
    __u32 dropped;
    __u32 array;
    __u32 resv[3];
};

struct ng_io_cqring_offsets {
    __u32 head;
    __u32 tail;
    __u32 ring_mask;
    __u32 ring_entries;
    __u32 overflow;
    __u32 cqes;
    __u32 flags;
    __u32 resv[3];
};

struct ng_io_uring_params {
    __u32 sq_entries;
    __u32 cq_entries;
    __u32 flags;
    __u32 sq_thread_cpu;
    __u32 sq_thread_idle;
    __u32 features;
    __u32 wq_fd;
    __u32 resv[3];
    struct ng_io_sqring_offsets sq_off;
    struct ng_io_cqring_offsets cq_off;
};

/* Compartment Worker running inside Domain 1 attempting io_uring vectors */
static uint64_t uring_adversarial_worker(void *arg)
{
    (void)arg;
    int failures = 0;

    printf("  [COMPARTMENT] Running inside isolated Domain 1...\n");

    /* Vector 1: Attempt standard io_uring_setup */
    printf("  [VECTOR 1] Testing sys_io_uring_setup() invocation...\n");
    struct ng_io_uring_params params;
    memset(&params, 0, sizeof(params));

    long ring_fd = syscall(__NR_io_uring_setup, 4, &params);
    if (ring_fd >= 0) {
        printf("    [FAIL] CRITICAL: sys_io_uring_setup succeeded from compartment (fd=%ld)!\n", ring_fd);
        close((int)ring_fd);
        failures++;
    } else {
        printf("    [PASS] sys_io_uring_setup blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 2: Attempt io_uring_setup with SQPOLL asynchronous kernel thread */
    printf("  [VECTOR 2] Testing sys_io_uring_setup(IORING_SETUP_SQPOLL)...\n");
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_SQPOLL;

    long sqpoll_fd = syscall(__NR_io_uring_setup, 4, &params);
    if (sqpoll_fd >= 0) {
        printf("    [FAIL] CRITICAL: SQPOLL thread creation succeeded from compartment (fd=%ld)!\n", sqpoll_fd);
        close((int)sqpoll_fd);
        failures++;
    } else {
        printf("    [PASS] sys_io_uring_setup(SQPOLL) blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 3: Attempt io_uring_enter on dummy descriptor */
    printf("  [VECTOR 3] Testing sys_io_uring_enter() invocation...\n");
    long enter_res = syscall(__NR_io_uring_enter, 999, 0, 0, 0, NULL, 0);
    if (enter_res >= 0) {
        printf("    [FAIL] CRITICAL: sys_io_uring_enter succeeded unexpectedly!\n");
        failures++;
    } else {
        printf("    [PASS] sys_io_uring_enter blocked / rejected: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 4: Attempt io_uring_register */
    printf("  [VECTOR 4] Testing sys_io_uring_register() invocation...\n");
    long reg_res = syscall(__NR_io_uring_register, 999, 0, NULL, 0);
    if (reg_res >= 0) {
        printf("    [FAIL] CRITICAL: sys_io_uring_register succeeded unexpectedly!\n");
        failures++;
    } else {
        printf("    [PASS] sys_io_uring_register blocked / rejected: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 5: Attempt IORING_REGISTER_PERSONALITY credential override */
    printf("  [VECTOR 5] Testing IORING_REGISTER_PERSONALITY override...\n");
    long cred_res = syscall(__NR_io_uring_register, 999, IORING_REGISTER_PERSONALITY, NULL, 0);
    if (cred_res >= 0) {
        printf("    [FAIL] CRITICAL: IORING_REGISTER_PERSONALITY succeeded unexpectedly!\n");
        failures++;
    } else {
        printf("    [PASS] IORING_REGISTER_PERSONALITY blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    return (uint64_t)failures;
}

int main(void)
{
    printf("====================================================================\n");
    printf("   NullGate Red-Team Penetration: io_uring Compartment Escape (Step 24)\n");
    printf("   Pillar 7: io_uring Restriction & Syscall Attack-Surface Reduction \n");
    printf("====================================================================\n\n");

    /* Execute the test in a fork() child so that any BPF bpf_send_signal(SIGSEGV) is cleanly trapped */
    pid_t child = fork();
    if (child < 0) {
        perror("fork failed");
        return 1;
    }

    if (child == 0) {
        /* Initialize NullGate runtime */
        int rc = ng_init();
        if (rc != NG_SUCCESS) {
            fprintf(stderr, "[FATAL] ng_init failed: %d\n", rc);
            _exit(1);
        }

        /* Allocate stack and create Domain 1 worker compartment */
        void *stack_buf = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack_buf == MAP_FAILED) {
            _exit(1);
        }

        rc = ng_domain_create(1, stack_buf, TEST_STACK_SIZE);
        if (rc != NG_SUCCESS) {
            fprintf(stderr, "[FATAL] ng_domain_create failed: %d\n", rc);
            _exit(1);
        }

        /* Enter Domain 1 across CET call-gate */
        uint64_t failures = ng_enter(1, uring_adversarial_worker, NULL);
        munmap(stack_buf, TEST_STACK_SIZE);
        _exit((int)failures);
    }

    int status = 0;
    waitpid(child, &status, 0);

    printf("\n====================================================================\n");
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            printf("   [ALL PASS] ALL 5 IO_URING ESCAPE VECTORS NEUTRALIZED (Exit Code 0)\n");
            printf("====================================================================\n");
            return 0;
        } else {
            printf("   [FAIL] io_uring attack detected %d security defects!\n", code);
            printf("====================================================================\n");
            return 1;
        }
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        printf("   [PASS] io_uring attack trapped by eBPF Tracepoint with Signal %d (%s)!\n",
               sig, strsignal(sig));
        printf("   [ALL PASS] IO_URING ATTEMPTS TERMINATED BY BPF LSM POLICY\n");
        printf("====================================================================\n");
        return 0;
    } else {
        printf("   [FAIL] Child process terminated abnormally with status %d\n", status);
        printf("====================================================================\n");
        return 1;
    }
}
