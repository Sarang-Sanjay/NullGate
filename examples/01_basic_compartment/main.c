/*
 * NullGate Example 1: Basic Intra-Process Memory Compartment
 * Demonstrates hardware-isolated compartment execution using ng_enter().
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <nullgate.h>

#define COMPARTMENT_STACK_SIZE (64 * 1024)

/* Untrusted computation executed inside isolated Domain 2 */
static uint64_t untrusted_computation(void *arg)
{
    uint64_t val = (uint64_t)(uintptr_t)arg;
    /* Compute without touching unmapped host memory */
    return val * val + 42;
}

int main(void)
{
    printf("=== NullGate Example 1: Basic Compartment ===\n");

    /* 1. Initialize NullGate runtime */
    if (ng_init() != NG_SUCCESS) {
        fprintf(stderr, "Failed to initialize NullGate (check CPU PKU/CET support)\n");
        return 1;
    }
    printf("[+] NullGate runtime initialized (Host Domain: %u)\n", ng_get_active_domain());

    /* 2. Allocate isolated stack for Domain 2 */
    void *stack = mmap(NULL, COMPARTMENT_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    if (ng_domain_create(2, stack, COMPARTMENT_STACK_SIZE) != NG_SUCCESS) {
        fprintf(stderr, "Failed to create compartment for Domain 2\n");
        return 1;
    }
    printf("[+] Created isolated Domain 2 with 64KB dedicated stack\n");

    /* 3. Invoke untrusted code through the hardware call-gate */
    uint64_t input = 10;
    printf("[*] Entering Domain 2 via hardware call-gate with input: %lu...\n", input);
    uint64_t result = ng_enter(2, untrusted_computation, (void *)(uintptr_t)input);

    printf("[+] Returned cleanly to trusted Domain %u! Result: %lu\n",
           ng_get_active_domain(), result);

    /* 4. Cleanup */
    munmap(stack, COMPARTMENT_STACK_SIZE);
    printf("=== Example 1 Completed Successfully ===\n");
    return 0;
}
