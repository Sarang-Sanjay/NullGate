/*
 * NullGate — Syscall Latency & LSM Mediation Micro-benchmark
 *
 * Measures CPU cycle and nanosecond latency of standard Linux syscalls
 * (e.g. getpid, read) in baseline unconfined execution vs inside a
 * NullGate-isolated compartment.
 *
 * Methodology:
 *   1. Hardware thread pinning via sched_setaffinity to eliminate CPU migration jitter.
 *   2. Serialized cycle counting via lfence; rdtscp.
 *   3. Warmup phase: 10,000 iterations.
 *   4. Measurement phase: 500,000 iterations.
 *   5. Statistical profiling: Min, P50 (Median), P95, P99, Max, Mean, Stdev.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <math.h>

#include "nullgate.h"
#include "nullgate_abi.h"

#define WARMUP_ITERATIONS   10000
#define BENCH_ITERATIONS    500000
#define STACK_SIZE          (64 * 1024)

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

/* Worker functions inside domain */
static uint64_t compartment_getpid(void *arg)
{
    (void)arg;
    return (uint64_t)getpid();
}

static int g_bench_pipe[2];

static uint64_t compartment_read(void *arg)
{
    char *buf = (char *)arg;
    return (uint64_t)read(g_bench_pipe[0], buf, 0);
}

/* Statistics container */
struct bench_stats {
    uint64_t min;
    uint64_t max;
    uint64_t p50;
    uint64_t p95;
    uint64_t p99;
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
    printf(" Max Latency:         %6" PRIu64 " cycles\n", s->max);
    printf(" Mean Latency:        %9.2f cycles\n", s->mean);
    printf(" Std Deviation:       %9.2f cycles\n", s->stdev);
    printf("===============================================================\n");
}

int main(void)
{
    printf("[+] NullGate Syscall Latency & LSM Mediation Micro-benchmark Initializing...\n");

    /* 1. Hardware CPU Pinning */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("[-] sched_setaffinity warning (proceeding unpinned)");
    } else {
        printf("[+] Thread successfully pinned to CPU Core 0\n");
    }

    /* 2. Setup pipe for 0-byte read benchmarks */
    if (pipe2(g_bench_pipe, O_NONBLOCK) != 0) {
        perror("[-] pipe2");
        return 1;
    }

    /* 3. Initialize NullGate Runtime */
    if (ng_init() != NG_SUCCESS) {
        fprintf(stderr, "[-] ng_init() failed\n");
        return 1;
    }

    /* 4. Setup Domain 2 Stack & Data Buffer */
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

    char dummy_buf[64] __attribute__((aligned(16)));

    uint64_t *samples = (uint64_t *)malloc(BENCH_ITERATIONS * sizeof(uint64_t));
    if (!samples) {
        fprintf(stderr, "[-] Out of memory allocating samples buffer\n");
        return 1;
    }

    struct bench_stats stats_raw_getpid, stats_domain_getpid;
    struct bench_stats stats_raw_read, stats_domain_read;

    /* =========================================================
     * Benchmark 1: Baseline Raw getpid()
     * ========================================================= */
    printf("[*] Warming up baseline getpid (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        (void)getpid();
    }

    printf("[*] Measuring baseline getpid (%d iterations)...\n", BENCH_ITERATIONS);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = rdtscp_start();
        (void)getpid();
        uint64_t t1 = rdtscp_end();
        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    compute_stats(samples, BENCH_ITERATIONS, &stats_raw_getpid);
    print_report("Baseline Raw getpid()", &stats_raw_getpid);

    /* =========================================================
     * Benchmark 2: Compartmentalized getpid()
     * ========================================================= */
    printf("[*] Warming up compartmentalized getpid (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        (void)ng_enter(2, compartment_getpid, NULL);
    }

    printf("[*] Measuring compartmentalized getpid (%d iterations)...\n", BENCH_ITERATIONS);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = rdtscp_start();
        (void)ng_enter(2, compartment_getpid, NULL);
        uint64_t t1 = rdtscp_end();
        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    compute_stats(samples, BENCH_ITERATIONS, &stats_domain_getpid);
    print_report("Compartmentalized getpid() [Call-Gate + Syscall]", &stats_domain_getpid);

    /* =========================================================
     * Benchmark 3: Baseline Raw read() (0-byte)
     * ========================================================= */
    printf("[*] Warming up baseline read (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        (void)read(g_bench_pipe[0], dummy_buf, 0);
    }

    printf("[*] Measuring baseline read (%d iterations)...\n", BENCH_ITERATIONS);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = rdtscp_start();
        (void)read(g_bench_pipe[0], dummy_buf, 0);
        uint64_t t1 = rdtscp_end();
        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    compute_stats(samples, BENCH_ITERATIONS, &stats_raw_read);
    print_report("Baseline Raw read(0-byte)", &stats_raw_read);

    /* =========================================================
     * Benchmark 4: Compartmentalized read() (0-byte)
     * ========================================================= */
    printf("[*] Warming up compartmentalized read (%d iterations)...\n", WARMUP_ITERATIONS);
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        (void)ng_enter(2, compartment_read, dummy_buf);
    }

    printf("[*] Measuring compartmentalized read (%d iterations)...\n", BENCH_ITERATIONS);
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        uint64_t t0 = rdtscp_start();
        (void)ng_enter(2, compartment_read, dummy_buf);
        uint64_t t1 = rdtscp_end();
        samples[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    compute_stats(samples, BENCH_ITERATIONS, &stats_domain_read);
    print_report("Compartmentalized read(0-byte) [Call-Gate + Syscall]", &stats_domain_read);

    /* Summary Comparison */
    printf("\n=== SUMMARY SYSCALL COMPARISON ================================\n");
    printf(" Raw getpid():                 Median %5" PRIu64 " cycles | Mean %7.2f cycles\n",
           stats_raw_getpid.p50, stats_raw_getpid.mean);
    printf(" Compartment getpid():         Median %5" PRIu64 " cycles | Mean %7.2f cycles (Delta: +%.1f cycles)\n",
           stats_domain_getpid.p50, stats_domain_getpid.mean, stats_domain_getpid.mean - stats_raw_getpid.mean);
    printf(" Raw read(0):                  Median %5" PRIu64 " cycles | Mean %7.2f cycles\n",
           stats_raw_read.p50, stats_raw_read.mean);
    printf(" Compartment read(0):          Median %5" PRIu64 " cycles | Mean %7.2f cycles (Delta: +%.1f cycles)\n",
           stats_domain_read.p50, stats_domain_read.mean, stats_domain_read.mean - stats_raw_read.mean);
    printf("===============================================================\n");

    close(g_bench_pipe[0]);
    close(g_bench_pipe[1]);
    free(samples);
    munmap(stack_base, STACK_SIZE);
    return 0;
}
