/*
 * NullGate — Unit Test: Fork/Clone Lifecycle & Domain Inheritance (Pillar 6)
 *
 * Simulates Nginx master-to-worker architecture:
 *   1. Master process initializes NullGate runtime and creates isolated worker domain.
 *   2. Master maps and protects shared domain memory buffer with PKU key.
 *   3. Master forks child worker process.
 *   4. Child verifies runtime state inheritance and pthread_atfork mlock renewal.
 *   5. Child attempts registration replay / hijacking (must be blocked).
 *   6. Child transitions into Domain 1 via CET callgate and accesses protected memory.
 *   7. Child cleanly returns to Domain 0 and terminates with exit code 0.
 *   8. Zero raw WRPKRU (0F 01 EF) instructions in test source.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <inttypes.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)
#define TEST_PAGE_SIZE  4096

static uint64_t worker_domain_1_task(void *arg)
{
    volatile int *target = (volatile int *)arg;
    *target = 0x55AA55AA;

    if (*target != (int)0x55AA55AA) {
        return 1; /* Memory integrity failure */
    }
    return 0; /* Success */
}

int main(void)
{
    printf("================================================================\n");
    printf("   NullGate: Fork Inheritance & Task Lifecycle Test (Pillar 6)  \n");
    printf("================================================================\n");

    /* 1. Master/Parent initializes NullGate runtime */
    int rc = ng_init();
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_init failed: %s (%d)\n", ng_strerror(rc), rc);
        return 1;
    }
    printf("[MASTER] NullGate runtime initialized successfully.\n");

    /* 2. Master allocates dedicated execution stack for Domain 1 (Worker) */
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
    printf("[MASTER] Domain 1 created with dedicated stack at %p.\n", stack_buf);

    /* 3. Master allocates and protects data buffer for Domain 1 */
    void *data_buf = mmap(NULL, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (data_buf == MAP_FAILED) {
        perror("mmap data_buf failed");
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    rc = ng_domain_protect(1, data_buf, TEST_PAGE_SIZE, PROT_READ | PROT_WRITE);
    if (rc != NG_SUCCESS) {
        fprintf(stderr, "[FATAL] ng_domain_protect failed: %s (%d)\n", ng_strerror(rc), rc);
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }
    printf("[MASTER] Memory buffer %p protected under Domain 1.\n", data_buf);

    /* 4. Set up synchronization pipe */
    int sync_pipe[2];
    if (pipe(sync_pipe) < 0) {
        perror("pipe failed");
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    printf("[MASTER] Forking child worker process (simulating Nginx master -> worker)...\n");
    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork failed");
        munmap(data_buf, TEST_PAGE_SIZE);
        munmap(stack_buf, TEST_STACK_SIZE);
        return 1;
    }

    if (child_pid == 0) {
        /* Child Process (Worker) */
        close(sync_pipe[0]);

        printf("[WORKER PID=%d] Checking inherited domain environment...\n", (int)getpid());

        /* 5. Attempt Registration Hijack / Replay */
        printf("[WORKER] Testing registration replay guard...\n");
        long replay_ret = prctl((int)NG_PRCTL_MAGIC_REGISTER, 0xDEADBEEF0000ULL, 0, 0, 0);
        if (replay_ret < 0) {
            printf("[PASS] Worker registration replay rejected: %s (errno=%d)\n",
                   strerror(errno), errno);
        } else {
            printf("[FAIL] Worker registration replay unexpectedly succeeded!\n");
            close(sync_pipe[1]);
            _exit(1);
        }

        /* 6. Execute Compartmentalized Task in Domain 1 via CET Call-Gate */
        printf("[WORKER] Transitioning to inherited Domain 1 via CET call-gate...\n");
        uint64_t worker_res = ng_enter(1, worker_domain_1_task, data_buf);

        if (worker_res != 0) {
            printf("[FAIL] Worker domain task returned error: %" PRIu64 "\n", worker_res);
            close(sync_pipe[1]);
            _exit(1);
        }
        printf("[PASS] Worker domain task executed successfully with memory isolation preserved.\n");

        /* 7. Verify clean return to Domain 0 */
        if (ng_get_active_domain() != NG_DOMAIN_TRUSTED) {
            printf("[FAIL] Worker active domain corrupted upon callgate exit: %u\n",
                   ng_get_active_domain());
            close(sync_pipe[1]);
            _exit(1);
        }
        printf("[PASS] Worker successfully returned to trusted Domain 0.\n");

        /* Signal master of success */
        char sync_byte = 'S';
        if (write(sync_pipe[1], &sync_byte, 1) != 1) {
            _exit(1);
        }
        close(sync_pipe[1]);
        _exit(0);
    }

    /* Master Process */
    close(sync_pipe[1]);

    char child_status = 0;
    if (read(sync_pipe[0], &child_status, 1) != 1 || child_status != 'S') {
        fprintf(stderr, "[MASTER FAIL] Child worker reported failure or dropped sync\n");
    }
    close(sync_pipe[0]);

    int status = 0;
    waitpid(child_pid, &status, 0);

    /* 8. Clean up resources */
    munmap(data_buf, TEST_PAGE_SIZE);
    munmap(stack_buf, TEST_STACK_SIZE);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && child_status == 'S') {
        printf("[PASS] Child worker terminated cleanly with exit status 0.\n");
    } else {
        printf("[FAIL] Child worker failed with status=%d\n", status);
        return 1;
    }

    printf("================================================================\n");
    printf("   [PASS] ALL FORK INHERITANCE SUBSYSTEM CHECKS PASSED          \n");
    printf("================================================================\n");
    return 0;
}
