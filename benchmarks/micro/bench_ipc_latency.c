/*
 * NullGate — Hardware Zero-Copy SPSC IPC Latency Micro-benchmark
 *
 * Measures nanosecond & CPU cycle latency of zero-copy shared memory messaging
 * across hardware PKU-isolated compartments.
 *
 * Methodology:
 *   1. Hardware thread pinning via sched_setaffinity to minimize core migration jitter.
 *   2. Serialized RDTSCP timing around ng_ipc_send() and ng_ipc_recv().
 *   3. Warmup phase: 10,000 iterations.
 *   4. Measurement phase: 100,000 iterations.
 *   5. Statistical profiling: Min, P50 (Median), P90, P99, Max, Mean.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <math.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "nullgate_ipc.h"

#define WARMUP_ROUNDS   10000
#define BENCH_ROUNDS    100000
#define RING_CAPACITY   1024

static inline uint64_t rdtscp_start(void)
{
    uint32_t lo, hi;
    __asm__ volatile (
        "lfence\n\t"
        "rdtscp\n\t"
        : "=a" (lo), "=d" (hi)
        :
        : "%rcx"
    );
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtscp_end(void)
{
    uint32_t lo, hi;
    __asm__ volatile (
        "rdtscp\n\t"
        "lfence\n\t"
        : "=a" (lo), "=d" (hi)
        :
        : "%rcx"
    );
    return ((uint64_t)hi << 32) | lo;
}

static int compare_u64(const void *a, const void *b)
{
    uint64_t arg1 = *(const uint64_t *)a;
    uint64_t arg2 = *(const uint64_t *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

int main(void)
{
    /* Pin to Core 0 for measurement stability */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    printf("====================================================================\n");
    printf("   NullGate — Hardware Zero-Copy SPSC IPC Micro-benchmark            \n");
    printf("   Pillar 1: Hardware-Enforced Compartmentalization & Zero-Copy IPC  \n");
    printf("====================================================================\n");

    int ret = ng_init();
    assert(ret == NG_SUCCESS);
    (void)ret;

    struct ng_ipc_channel *chan = ng_ipc_channel_create(2, 3, RING_CAPACITY);
    assert(chan != NULL);

    const char test_payload[] = "NullGate Zero-Copy Micro-benchmark 32B";
    size_t payload_len = sizeof(test_payload);
    char recv_buf[64];

    /* Warmup Phase */
    for (int i = 0; i < WARMUP_ROUNDS; i++) {
        int s = ng_ipc_send(chan, test_payload, payload_len);
        assert(s == NG_IPC_OK);
        (void)s;
        int r = ng_ipc_recv(chan, recv_buf, sizeof(recv_buf));
        assert(r == (int)payload_len);
        (void)r;
    }

    /* Measurement Phase */
    uint64_t *samples_cycles = malloc(BENCH_ROUNDS * sizeof(uint64_t));
    assert(samples_cycles != NULL);

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    for (int i = 0; i < BENCH_ROUNDS; i++) {
        uint64_t t0 = rdtscp_start();

        /* SPSC Send + Recv Roundtrip */
        ng_ipc_send(chan, test_payload, payload_len);
        ng_ipc_recv(chan, recv_buf, sizeof(recv_buf));

        uint64_t t1 = rdtscp_end();
        samples_cycles[i] = (t1 > t0) ? (t1 - t0) : 0;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    double total_sec = (double)(ts_end.tv_sec - ts_start.tv_sec) +
                       (double)(ts_end.tv_nsec - ts_start.tv_nsec) * 1e-9;
    double ops_per_sec = (double)BENCH_ROUNDS / total_sec;
    double avg_ns = (total_sec / (double)BENCH_ROUNDS) * 1e9;

    /* Sort cycle samples for percentile calculation */
    qsort(samples_cycles, BENCH_ROUNDS, sizeof(uint64_t), compare_u64);

    uint64_t min_cyc = samples_cycles[0];
    uint64_t p50_cyc = samples_cycles[(size_t)(BENCH_ROUNDS * 0.50)];
    uint64_t p90_cyc = samples_cycles[(size_t)(BENCH_ROUNDS * 0.90)];
    uint64_t p99_cyc = samples_cycles[(size_t)(BENCH_ROUNDS * 0.99)];
    uint64_t max_cyc = samples_cycles[BENCH_ROUNDS - 1];

    uint64_t sum_cyc = 0;
    for (int i = 0; i < BENCH_ROUNDS; i++) {
        sum_cyc += samples_cycles[i];
    }
    double mean_cyc = (double)sum_cyc / (double)BENCH_ROUNDS;

    printf("\nBenchmark Summary (%d round-trips):\n", BENCH_ROUNDS);
    printf("  Throughput   : %.2f round-trips/sec (%.2f M ops/sec)\n", ops_per_sec, ops_per_sec / 1e6);
    printf("  Mean Latency : %.2f ns (%.2f cycles)\n", avg_ns, mean_cyc);
    printf("  Min Latency  : %" PRIu64 " cycles\n", min_cyc);
    printf("  P50 (Median) : %" PRIu64 " cycles\n", p50_cyc);
    printf("  P90 Latency  : %" PRIu64 " cycles\n", p90_cyc);
    printf("  P99 Latency  : %" PRIu64 " cycles\n", p99_cyc);
    printf("  Max Latency  : %" PRIu64 " cycles\n", max_cyc);
    printf("====================================================================\n\n");

    free(samples_cycles);
    ng_ipc_channel_destroy(chan);

    return 0;
}
