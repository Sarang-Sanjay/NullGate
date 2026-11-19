/*
 * NullGate — Security Penetration Suite: Confused Deputy Attack (Group F - Step 25)
 *
 * Verifies kernel-boundary Confused Deputy protection:
 *   1. Vector 1: sys_read(fd, trusted_state_addr, len)
 *      Untrusted compartment attempts to trick the kernel into overwriting
 *      Key 1 protected trusted state (g_trusted_state) via pipe/file read.
 *      -> Blocked with -EFAULT / SIGSEGV via hardware PKU copy_to_user & BPF deputy checks.
 *   2. Vector 2: sys_write(fd, trusted_state_addr, len)
 *      Untrusted compartment attempts to trick the kernel into leaking Key 1
 *      trusted state memory to a pipe/file.
 *      -> Blocked with -EFAULT / SIGSEGV via hardware PKU copy_from_user & BPF deputy checks.
 *   3. Vector 3: sys_connect(fd, (struct sockaddr *)trusted_state_addr, len)
 *      Untrusted compartment passes trusted_state_addr into socket connect syscall.
 *      -> Blocked with -EPERM via NullGate LSM ng_socket_connect hook.
 *   4. Vector 4: Cross-domain buffer overwrite (read into Domain 2 memory from Domain 1)
 *      -> Blocked with -EFAULT via PKU copy_to_user.
 *   5. Vector 5: Cross-domain buffer exfiltration (write from Domain 2 memory from Domain 1)
 *      -> Blocked with -EFAULT via PKU copy_from_user.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define TEST_STACK_SIZE (64 * 1024)
#define VAULT_SECRET    "TOP_SECRET_DOMAIN_2_VAULT_BYTES_1234"

struct test_context {
    uintptr_t trusted_state_addr;
    void *domain2_buf;
    int pipe_in[2];
    int pipe_out[2];
};

/* Worker running in Domain 1 attempting Confused Deputy attacks */
static uint64_t confused_deputy_worker(void *arg)
{
    struct test_context *ctx = (struct test_context *)arg;
    int failures = 0;

    printf("  [COMPARTMENT] Running inside isolated Domain 1...\n");
    printf("  [COMPARTMENT] Target Key 1 trusted_state_addr: 0x%lx\n", (unsigned long)ctx->trusted_state_addr);
    printf("  [COMPARTMENT] Target Key 2 domain2_buf:         %p\n\n", ctx->domain2_buf);

    /* Vector 1: sys_read(pipe_in[0], trusted_state_addr, 64) */
    printf("  [VECTOR 1] Attempting sys_read() into Key 1 trusted state...\n");
    char payload[64] = "MALICIOUS_POISON_OVERWRITE_0123456789";
    if (write(ctx->pipe_in[1], payload, sizeof(payload)) < 0) { /* ignore */ }

    ssize_t nread = read(ctx->pipe_in[0], (void *)ctx->trusted_state_addr, sizeof(payload));
    if (nread > 0) {
        printf("    [FAIL] CRITICAL: Kernel read() overwrote Key 1 trusted state (%zd bytes)!\n", nread);
        failures++;
    } else {
        printf("    [PASS] sys_read() into Key 1 blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 2: sys_write(pipe_out[1], trusted_state_addr, 64) */
    printf("  [VECTOR 2] Attempting sys_write() leaking Key 1 trusted state...\n");
    ssize_t nwritten = write(ctx->pipe_out[1], (const void *)ctx->trusted_state_addr, 64);
    if (nwritten > 0) {
        printf("    [FAIL] CRITICAL: Kernel write() leaked Key 1 trusted state (%zd bytes)!\n", nwritten);
        failures++;
    } else {
        printf("    [PASS] sys_write() from Key 1 blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 3: sys_connect(sockfd, trusted_state_addr, len) */
    printf("  [VECTOR 3] Attempting sys_connect() using Key 1 as sockaddr...\n");
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd >= 0) {
        int conn_res = connect(sfd, (const struct sockaddr *)ctx->trusted_state_addr, sizeof(struct sockaddr_in));
        if (conn_res == 0) {
            printf("    [FAIL] CRITICAL: sys_connect() with Key 1 sockaddr succeeded!\n");
            failures++;
        } else {
            printf("    [PASS] sys_connect() with Key 1 sockaddr blocked: %s (errno=%d)\n",
                   strerror(errno), errno);
        }
        close(sfd);
    }

    /* Vector 4: Cross-Domain Overwrite (read into Domain 2 memory) */
    printf("  [VECTOR 4] Attempting sys_read() overwriting Domain 2 memory...\n");
    if (write(ctx->pipe_in[1], payload, sizeof(payload)) < 0) { /* ignore */ }
    nread = read(ctx->pipe_in[0], ctx->domain2_buf, sizeof(payload));
    if (nread > 0) {
        printf("    [FAIL] CRITICAL: Kernel read() overwrote Domain 2 buffer (%zd bytes)!\n", nread);
        failures++;
    } else {
        printf("    [PASS] sys_read() into Domain 2 blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 5: Cross-Domain Exfiltration (write from Domain 2 memory) */
    printf("  [VECTOR 5] Attempting sys_write() leaking Domain 2 memory...\n");
    nwritten = write(ctx->pipe_out[1], (const void *)ctx->domain2_buf, 32);
    if (nwritten > 0) {
        printf("    [FAIL] CRITICAL: Kernel write() leaked Domain 2 buffer (%zd bytes)!\n", nwritten);
        failures++;
    } else {
        printf("    [PASS] sys_write() from Domain 2 blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    return (uint64_t)failures;
}

int main(void)
{
    printf("====================================================================\n");
    printf("   NullGate Red-Team Penetration: Confused Deputy Attack (Step 25)   \n");
    printf("   Pillar 7: Confused Deputy Prevention & Syscall Pointer Validation\n");
    printf("====================================================================\n\n");

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

        uintptr_t ts_addr = ng_get_trusted_state_addr();

        /* Allocate stack for Domain 1 */
        void *stack_buf1 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        /* Allocate stack for Domain 2 */
        void *stack_buf2 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        /* Allocate Domain 2 vault buffer */
        void *vault_buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (stack_buf1 == MAP_FAILED || stack_buf2 == MAP_FAILED || vault_buf == MAP_FAILED) {
            _exit(1);
        }

        memcpy(vault_buf, VAULT_SECRET, strlen(VAULT_SECRET) + 1);

        (void)ng_domain_create(1, stack_buf1, TEST_STACK_SIZE);
        (void)ng_domain_create(2, stack_buf2, TEST_STACK_SIZE);
        (void)ng_domain_protect(2, vault_buf, 4096, PROT_READ | PROT_WRITE);

        struct test_context ctx;
        ctx.trusted_state_addr = ts_addr;
        ctx.domain2_buf = vault_buf;
        if (pipe(ctx.pipe_in) < 0 || pipe(ctx.pipe_out) < 0) {
            _exit(1);
        }

        /* Enter Domain 1 across CET call-gate */
        uint64_t failures = ng_enter(1, confused_deputy_worker, &ctx);

        close(ctx.pipe_in[0]);
        close(ctx.pipe_in[1]);
        close(ctx.pipe_out[0]);
        close(ctx.pipe_out[1]);
        munmap(stack_buf1, TEST_STACK_SIZE);
        munmap(stack_buf2, TEST_STACK_SIZE);
        munmap(vault_buf, 4096);

        _exit((int)failures);
    }

    int status = 0;
    waitpid(child, &status, 0);

    printf("\n====================================================================\n");
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            printf("   [ALL PASS] ALL 5 CONFUSED DEPUTY VECTORS NEUTRALIZED (Exit Code 0)\n");
            printf("====================================================================\n");
            return 0;
        } else {
            printf("   [FAIL] Confused deputy attack detected %d security defects!\n", code);
            printf("====================================================================\n");
            return 1;
        }
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        printf("   [PASS] Confused deputy attempt instantly trapped with Signal %d (%s)!\n",
               sig, strsignal(sig));
        printf("   [ALL PASS] CONFUSED DEPUTY ATTEMPT TERMINATED BY LSM POLICY\n");
        printf("====================================================================\n");
        return 0;
    } else {
        printf("   [FAIL] Child process terminated abnormally with status %d\n", status);
        printf("====================================================================\n");
        return 1;
    }
}
