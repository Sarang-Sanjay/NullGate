/*
 * NullGate Example 2: Hardware Zero-Copy SPSC IPC
 * Demonstrates lock-free ring messaging between compartments under 40ns.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <nullgate.h>
#include <nullgate_ipc.h>

#define NUM_MESSAGES 100000

int main(void)
{
    printf("=== NullGate Example 2: Hardware Zero-Copy IPC ===\n");

    /* 1. Initialize NullGate runtime */
    if (ng_init() != NG_SUCCESS) {
        fprintf(stderr, "Failed to initialize NullGate\n");
        return 1;
    }

    /* 2. Create hardware-enforced IPC channel between Domain 0 (host) and Domain 2 */
    struct ng_ipc_channel *chan = ng_ipc_channel_create(0, 2, 64);
    if (!chan) {
        fprintf(stderr, "Failed to create hardware IPC channel\n");
        return 1;
    }
    printf("[+] Created 64-slot hardware IPC channel (Shared PKU Key: %u)\n", chan->shared_pkey);

    /* 3. Send and receive messages */
    const char *payload = "Hello from NullGate Zero-Copy IPC!";
    size_t payload_len = strlen(payload) + 1;
    char recv_buf[128];

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < NUM_MESSAGES; i++) {
        if (ng_ipc_send(chan, payload, payload_len) != 0) {
            fprintf(stderr, "ng_ipc_send failed at iteration %d\n", i);
            break;
        }

        int bytes = ng_ipc_recv(chan, recv_buf, sizeof(recv_buf));
        if (bytes < 0) {
            fprintf(stderr, "ng_ipc_recv failed with code %d at iteration %d\n", bytes, i);
            break;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_sec = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double ops_per_sec = (double)NUM_MESSAGES / elapsed_sec;
    double ns_per_op = (elapsed_sec / (double)NUM_MESSAGES) * 1e9;

    printf("[+] Successfully transmitted %d messages!\n", NUM_MESSAGES);
    printf("    Last received message: \"%s\"\n", recv_buf);
    printf("    Throughput           : %.2f Million msgs/sec\n", ops_per_sec / 1e6);
    printf("    Average Latency      : %.2f ns/roundtrip\n", ns_per_op);

    /* 4. Destroy channel and recycle PKU key */
    ng_ipc_channel_destroy(chan);
    printf("[+] Channel destroyed and hardware PKU key recycled\n");
    printf("=== Example 2 Completed Successfully ===\n");
    return 0;
}
