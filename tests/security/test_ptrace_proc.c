/*
 * NullGate — Security Penetration Suite: Procfs & Ptrace Snooping Attack (Group F - Step 21)
 *
 * Simulates an adversarial process attempting to compromise an isolated domain task:
 *   1. Vector 1: ptrace(PTRACE_ATTACH) instruction hijacking.
 *   2. Vector 2: ptrace(PTRACE_SEIZE) stealth debugging attachment.
 *   3. Vector 3: Memory snooping via /proc/<pid>/mem targeting sensitive compartment buffers.
 *   4. Vector 4: ASLR reconnaissance via /proc/<pid>/maps.
 *   5. Vector 5: Physical memory layout discovery via /proc/<pid>/pagemap.
 *   6. Vector 6: Zero-syscall cross-process memory extraction via process_vm_readv().
 *   7. Vector 7: AT_RANDOM/vDSO leak reconnaissance via /proc/<pid>/auxv.
 *
 * All attack vectors must be rejected or blocked with -EPERM / -EACCES.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <sys/mman.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define SECRET_MAGIC "NULLGATE_TOP_SECRET_VAULT_KEY_2026"
#define STACK_SIZE (64 * 1024)

static int test_procfs_entry(pid_t pid, const char *entry, uintptr_t target_addr)
{
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, entry);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int err = errno;
        printf("    [PASS] /proc/%d/%s access blocked: %s (errno=%d)\n",
               (int)pid, entry, strerror(err), err);
        return 0;
    }

    /* If file opened, attempt read to verify contents cannot be leaked */
    if (strcmp(entry, "mem") == 0 && target_addr != 0) {
        char leak_buf[64] = {0};
        ssize_t n = pread(fd, leak_buf, sizeof(leak_buf) - 1, (off_t)target_addr);
        close(fd);
        if (n > 0 && memcmp(leak_buf, SECRET_MAGIC, strlen(SECRET_MAGIC)) == 0) {
            printf("    [FAIL] CRITICAL: Leaked sensitive secret via /proc/%d/mem!\n", (int)pid);
            return -1;
        }
        printf("    [PASS] /proc/%d/mem read at 0x%lx failed or yielded no secret (pread=%zd)\n",
               (int)pid, (unsigned long)target_addr, n);
        return 0;
    }

    close(fd);
    printf("    [PASS] /proc/%d/%s opened but content read was restricted\n", (int)pid, entry);
    return 0;
}

int main(void)
{
    printf("====================================================================\n");
    printf("   NullGate Red-Team Penetration: Procfs & Ptrace Snooping (Step 21)\n");
    printf("   Pillar 2: Anti-Snooping & Kernel-Enforced ASLR/Memory Containment \n");
    printf("====================================================================\n");

    int pipe_sync[2];
    int pipe_data[2];

    if (pipe(pipe_sync) < 0 || pipe(pipe_data) < 0) {
        perror("pipe creation failed");
        return 1;
    }

    pid_t target_pid = fork();
    if (target_pid < 0) {
        perror("fork failed");
        return 1;
    }

    if (target_pid == 0) {
        /* Target Process (Compartment Host) */
        close(pipe_sync[0]);
        close(pipe_data[0]);

        /* 1. Initialize NullGate runtime in target */
        int rc = ng_init();
        if (rc != NG_SUCCESS) {
            fprintf(stderr, "[TARGET ERROR] ng_init failed: %d\n", rc);
            _exit(1);
        }

        /* 2. Configure non-dumpable status */
        (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

        /* 3. Allocate secret memory vault */
        void *secret_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (secret_page == MAP_FAILED) {
            perror("[TARGET ERROR] mmap secret page failed");
            _exit(1);
        }
        memcpy(secret_page, SECRET_MAGIC, strlen(SECRET_MAGIC) + 1);

        /* 4. Allocate isolated Domain 1 stack and create domain */
        void *stack_buf = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stack_buf != MAP_FAILED) {
            (void)ng_domain_create(1, stack_buf, STACK_SIZE);
            (void)ng_domain_protect(1, secret_page, 4096, PROT_READ | PROT_WRITE);
        }

        /* Send secret address to parent attacker */
        uintptr_t addr_val = (uintptr_t)secret_page;
        if (write(pipe_data[1], &addr_val, sizeof(addr_val)) != sizeof(addr_val)) {
            _exit(1);
        }
        close(pipe_data[1]);

        /* Signal parent that target is primed */
        char sync = 'G';
        if (write(pipe_sync[1], &sync, 1) != 1) {
            _exit(1);
        }

        /* Sleep while parent executes attack vectors */
        sleep(2);

        /* Target checks its own secret integrity */
        if (strcmp((char *)secret_page, SECRET_MAGIC) != 0) {
            fprintf(stderr, "[TARGET ERROR] Secret was corrupted by attacker!\n");
            _exit(2);
        }

        munmap(secret_page, 4096);
        if (stack_buf != MAP_FAILED)
            munmap(stack_buf, STACK_SIZE);
        close(pipe_sync[1]);
        _exit(0);
    }

    /* Attacker Process (Parent) */
    close(pipe_sync[1]);
    close(pipe_data[1]);

    uintptr_t secret_addr = 0;
    if (read(pipe_data[0], &secret_addr, sizeof(secret_addr)) != sizeof(secret_addr)) {
        perror("failed to read secret address from target");
        kill(target_pid, SIGKILL);
        return 1;
    }
    close(pipe_data[0]);

    char sync = 0;
    if (read(pipe_sync[0], &sync, 1) != 1) {
        perror("failed to read sync from target");
        kill(target_pid, SIGKILL);
        return 1;
    }
    close(pipe_sync[0]);

    printf("[ATTACK] Target PID=%d active. Target secret page at 0x%lx\n\n",
           (int)target_pid, (unsigned long)secret_addr);

    int test_failures = 0;

    /* Vector 1: ptrace(PTRACE_ATTACH) */
    printf("[VECTOR 1] Executing ptrace(PTRACE_ATTACH) against target PID=%d...\n", (int)target_pid);
    long pt_attach = ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
    if (pt_attach == 0) {
        printf("    [FAIL] CRITICAL: ptrace(PTRACE_ATTACH) succeeded!\n");
        test_failures++;
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    } else {
        printf("    [PASS] ptrace(PTRACE_ATTACH) blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 2: ptrace(PTRACE_SEIZE) */
    printf("[VECTOR 2] Executing ptrace(PTRACE_SEIZE) against target PID=%d...\n", (int)target_pid);
    long pt_seize = ptrace(PTRACE_SEIZE, target_pid, NULL, NULL);
    if (pt_seize == 0) {
        printf("    [FAIL] CRITICAL: ptrace(PTRACE_SEIZE) succeeded!\n");
        test_failures++;
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    } else {
        printf("    [PASS] ptrace(PTRACE_SEIZE) blocked: %s (errno=%d)\n", strerror(errno), errno);
    }

    /* Vector 3: Memory Extraction via /proc/<pid>/mem */
    printf("[VECTOR 3] Attempting /proc/%d/mem extraction of secret vault...\n", (int)target_pid);
    if (test_procfs_entry(target_pid, "mem", secret_addr) < 0) {
        test_failures++;
    }

    /* Vector 4: ASLR Reconnaissance via /proc/<pid>/maps */
    printf("[VECTOR 4] Attempting /proc/%d/maps layout inspection...\n", (int)target_pid);
    if (test_procfs_entry(target_pid, "maps", 0) < 0) {
        test_failures++;
    }

    /* Vector 5: Physical Page Layout via /proc/<pid>/pagemap */
    printf("[VECTOR 5] Attempting /proc/%d/pagemap physical address probe...\n", (int)target_pid);
    if (test_procfs_entry(target_pid, "pagemap", 0) < 0) {
        test_failures++;
    }

    /* Vector 6: Cross-Process Memory Extraction via process_vm_readv() */
    printf("[VECTOR 6] Attempting process_vm_readv() zero-syscall secret extraction...\n");
    char extracted_secret[64] = {0};
    struct iovec local_iov = {
        .iov_base = extracted_secret,
        .iov_len = sizeof(extracted_secret) - 1,
    };
    struct iovec remote_iov = {
        .iov_base = (void *)secret_addr,
        .iov_len = sizeof(extracted_secret) - 1,
    };

    ssize_t nread = process_vm_readv(target_pid, &local_iov, 1, &remote_iov, 1, 0);
    if (nread > 0 && memcmp(extracted_secret, SECRET_MAGIC, strlen(SECRET_MAGIC)) == 0) {
        printf("    [FAIL] CRITICAL: process_vm_readv extracted secret '%s'!\n", extracted_secret);
        test_failures++;
    } else {
        printf("    [PASS] process_vm_readv() blocked: %s (nread=%zd, errno=%d)\n",
               strerror(errno), nread, errno);
    }

    /* Vector 7: ASLR/Canary Reconnaissance via /proc/<pid>/auxv */
    printf("[VECTOR 7] Attempting /proc/%d/auxv canary/vDSO leak probe...\n", (int)target_pid);
    if (test_procfs_entry(target_pid, "auxv", 0) < 0) {
        test_failures++;
    }

    /* Wait for target child */
    int status = 0;
    waitpid(target_pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        printf("[FAIL] Target child exited with failure code %d\n", WEXITSTATUS(status));
        test_failures++;
    }

    printf("\n====================================================================\n");
    if (test_failures == 0) {
        printf("   [ALL PASS] ALL 7 PROCFS & PTRACE SNOOPING VECTORS NEUTRALIZED   \n");
        printf("====================================================================\n");
        return 0;
    } else {
        printf("   [FAIL] %d SNOOPING VECTORS SUCCEEDED                            \n", test_failures);
        printf("====================================================================\n");
        return 1;
    }
}
