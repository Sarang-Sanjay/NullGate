/*
 * NullGate — High-Precision Serialized RDTSCP Call-Gate Micro-benchmark
 *
 * Measures nanosecond / CPU cycle transition latency across Intel CET
 * call-gate boundaries (WRPKRU + LFENCE + stack switch + ENDBR64).
 *
 * Methodology:
 *   1. Hardware thread pinning via sched_setaffinity to isolate CPU jitter.
 *   2. Serialized cycle counting via lfence; rdtscp.
 *   3. Warmup phase: 10,000 unmeasured iterations to prime L1i/L1d caches.
 *   4. Measurement phase: 1,000,000 transitions.
 *   5. Statistical profiling: Min, P50 (Median), P95, P99, P99.9, Max, Mean, Stdev.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>
#include <math.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define WARMUP_ITERATIONS   10000
#define BENCH_ITERATIONS    1000000
#define STACK_SIZE          (64 * 1024)

extern uint32_t pku_build_pkru_mask(uint32_t active_domain);

extern uint64_t ng_callgate_invoke(uint32_t domain_id,
                                   ng_compartment_fn fn,
                                   void *arg,
                                   void *stack_top,
                                   uint32_t target_pkru,
                                   struct ng_trusted_state *tstate);

/* Serialized RDTSCP timing primitives */
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

/* Benchmark worker function */
static uint64_t bench_target_fn(void *arg)
{
    uintptr_t val = (uintptr_t)arg;
    return val + 1;
}

/* Baseline direct function */
static uint64_t __attribute__((noinline)) baseline_direct_fn(void *arg)
{
    uintptr_t val = (uintptr_t)arg;
    return val + 1;
}

/* Statistics container */
struct bench_stats {
    uint64_t min;
    uint64_t max;
    uint64_t p50;
    uint64_t p95;
    uint64_t p99;
    uint64_t p999;
    double mean;
    double stdev;
};

static int cmp_u64(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

static void compute_stats(uint64_t *samples, size_t n, struct bench_stats *out)
{
    qsort(samples, n, sizeof(uint64_t), cmp_u64);

    out->min = samples[0];
    out->max = samples[n - 1];
    out->p50 = samples[n / 2];
    out->p95 = samples[(size_t)(n * 0.95)];
    out->p99 = samples[(size_t)(n * 0.99)];
    out->p999 = samples[(size_t)(n * 0.999)];

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum += (double)samples[i];
    }
    out->mean = sum / (double)n;

    double sum_sq = 0.0;
    for (size_t i = 0; i < n; i++) {
        double diff = (double)samples[i] - out->mean;
        sum_sq += diff * diff;
    }
    out->stdev = sqrt(sum_sq / (double)n);
}

static void print_report(const char *name, const struct bench_stats *s)
{
    printf("\n===============================================================\n");
    printf(" BENCHMARK: %s\n", name);
    printf(" Iterations: %d (after %d warmup cycles)\n", BENCH_ITERATIONS, WARMUP_ITERATIONS);
    printf("---------------------------------------------------------------\n");
    printf(" Min Latency:         %6" PRIu64 " cycles\n", s->min);
    printf(" P50 (Median):        %6" PRIu64 " cycles\n", s->p50);
    printf(" P95 Latency:         %6" PRIu64 " cycles\n", s->p95);
    printf(" P99 Latency:         %6" PRIu64 " cycles\n", s->p99);
    printf(" P99.9 Latency:       %6" PRIu64 " cycles\n", s->p999);
    printf(" Max Latency:         %6" PRIu64 " cycles\n", s->max);
    printf(" Mean Latency:        %9.2f cycles\n", s->mean);
    printf(" Std Deviation:       %9.2f cycles\n", s->stdev);
    printf("===============================================================\n");
}

int main(void)
{
    printf("[+] NullGate RDTSCP Call-Gate Micro-benchmark Initializing...\n");

    /* 1. Hardware CPU Pinning */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("[-] sched_setaffinity warning (proceeding unpinned)");
    } else {
        printf("[+] Thread successfully pinned to CPU Core 0\n");
    }

    /* 2. Initialize NullGate Runtime */
    if (ng_init() != NG_SUCCESS) {
        fprintf(stderr, "[-] ng_init() failed\n");
        return 1;
    }

    /* 3. Setup Domain 2 Stack */
    void *stack_base = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_base == MAP_FAILED) {
        perror("[-] mmap compartment stack");
        return 1;
    }

    if (ng_domain_create(2, stack_base, STACK_SIZE) != NG_SUCCESS) {
        fprintf(stderr, "[-] ng_domain_create(2) failed\n");
        return 1;
    }

    uint64_t *samples = (uint64_t *)malloc(BENCH_ITERATIONS * sizeof(uint64_t));
    if (!samples) {
        fprintf(stderr, "[-] Out of memory allocating samples buffer\n");
        return 1;
    }

    struct bench_stats stats_direct, stats_raw, stats_enter;

    /* =========================================================
     * Benchmark 1: Baseline Direct C Function Call
     * ========================================================= */
    printf("[*] Warming up baseline direct call (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        (void)baseline_direct_fn((void *)(uintptr_t)i);
    }

    printf("[*] Measuring baseline direct call (%d iterations)...\n", BENCH_ITERATIONS);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = rdtscp_start();
        (void)baseline_direct_fn((void *)(uintptr_t)i);
        uint64_t t1 = rdtscp_end();
        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    compute_stats(samples, BENCH_ITERATIONS, &stats_direct);
    print_report("Baseline Direct C Function Call", &stats_direct);

    /* =========================================================
     * Benchmark 2: Raw ng_callgate_invoke Trampoline
     * (WRPKRU + Stack Switch + ENDBR64 + LFENCE + RET)
     * ========================================================= */
    void *stack_top = (void *)(((uintptr_t)stack_base + STACK_SIZE) & ~0xFULL);
    struct ng_trusted_state *tstate = (struct ng_trusted_state *)ng_get_trusted_state_addr();
    uint32_t target_pkru = pku_build_pkru_mask(2); /* Authorized Domain 2 mask (Key 0 and Key 2 enabled, Key 1 disabled) */

    printf("[*] Warming up raw callgate trampoline (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        (void)ng_callgate_invoke(2, bench_target_fn, (void *)(uintptr_t)i,
                                 stack_top, target_pkru, tstate);
    }

    printf("[*] Measuring raw callgate trampoline (%d iterations)...\n", BENCH_ITERATIONS);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = rdtscp_start();
        (void)ng_callgate_invoke(2, bench_target_fn, (void *)(uintptr_t)i,
                                 stack_top, target_pkru, tstate);
        uint64_t t1 = rdtscp_end();
        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    compute_stats(samples, BENCH_ITERATIONS, &stats_raw);
    print_report("Raw Call-Gate Trampoline (ng_callgate_invoke)", &stats_raw);

    /* =========================================================
     * Benchmark 3: Public ng_enter API Call-Gate
     * (Validation + Domain Lookup + Mutex + Trampoline)
     * ========================================================= */
    printf("[*] Warming up public ng_enter API (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        (void)ng_enter(2, bench_target_fn, (void *)(uintptr_t)i);
    }

    printf("[*] Measuring public ng_enter API (%d iterations)...\n", BENCH_ITERATIONS);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = rdtscp_start();
        (void)ng_enter(2, bench_target_fn, (void *)(uintptr_t)i);
        uint64_t t1 = rdtscp_end();
        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    compute_stats(samples, BENCH_ITERATIONS, &stats_enter);
    print_report("Public Call-Gate API (ng_enter)", &stats_enter);

    /* Summary Overhead Comparison */
    printf("\n=== SUMMARY OVERHEAD ANALYSIS =================================\n");
    printf(" Direct Baseline Call:     Median %5" PRIu64 " cycles | Mean %7.2f cycles\n",
           stats_direct.p50, stats_direct.mean);
    printf(" Raw Hardware Call-Gate:   Median %5" PRIu64 " cycles | Mean %7.2f cycles (Delta: +%.1f cycles)\n",
           stats_raw.p50, stats_raw.mean, stats_raw.mean - stats_direct.mean);
    printf(" Public Compartment API:   Median %5" PRIu64 " cycles | Mean %7.2f cycles (Delta: +%.1f cycles)\n",
           stats_enter.p50, stats_enter.mean, stats_enter.mean - stats_direct.mean);
    printf("===============================================================\n");

    free(samples);
    munmap(stack_base, STACK_SIZE);
    return 0;
}
