/*
 * NullGate — Self-Contained SQLite UDF Sandboxing Compartment Implementation
 *
 * CRITICAL PILLAR 4 GADGET HYGIENE INVARIANT:
 * This translation unit strictly implements argument marshaling and invocation.
 * Absolutely zero WRPKRU instructions (opcode 0F 01 EF) exist in this file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sqlite_compartment.h"

static uint32_t g_sqlite_domain = NG_SQLITE_DEFAULT_DOMAIN;
static void *g_sqlite_stack_base = NULL;
static size_t g_sqlite_stack_size = 0;
static bool g_sqlite_initialized = false;
static pthread_mutex_t g_sqlite_lock = PTHREAD_MUTEX_INITIALIZER;

struct ng_sqlite_scalar_pack {
    sqlite3_context *ctx;
    int argc;
    sqlite3_value **argv;
    sqlite3_scalar_func fn;
};

struct ng_sqlite_step_pack {
    sqlite3_context *ctx;
    int argc;
    sqlite3_value **argv;
    sqlite3_step_func fn;
};

struct ng_sqlite_final_pack {
    sqlite3_context *ctx;
    sqlite3_final_func fn;
};

static uint64_t worker_scalar(void *arg)
{
    struct ng_sqlite_scalar_pack *pack = (struct ng_sqlite_scalar_pack *)arg;
    if (pack && pack->fn) {
        pack->fn(pack->ctx, pack->argc, pack->argv);
    }
    return 0;
}

static uint64_t worker_step(void *arg)
{
    struct ng_sqlite_step_pack *pack = (struct ng_sqlite_step_pack *)arg;
    if (pack && pack->fn) {
        pack->fn(pack->ctx, pack->argc, pack->argv);
    }
    return 0;
}

static uint64_t worker_final(void *arg)
{
    struct ng_sqlite_final_pack *pack = (struct ng_sqlite_final_pack *)arg;
    if (pack && pack->fn) {
        pack->fn(pack->ctx);
    }
    return 0;
}

int ng_sqlite_compartment_init(uint32_t domain_id, size_t stack_size)
{
    pthread_mutex_lock(&g_sqlite_lock);
    if (g_sqlite_initialized) {
        pthread_mutex_unlock(&g_sqlite_lock);
        return NG_SUCCESS;
    }

    int ret = ng_init();
    if (ret != NG_SUCCESS) {
        pthread_mutex_unlock(&g_sqlite_lock);
        return ret;
    }

    if (domain_id == 0 || domain_id >= NG_MAX_DOMAINS) {
        pthread_mutex_unlock(&g_sqlite_lock);
        return NG_ERR_INVALID;
    }

    if (stack_size == 0) {
        stack_size = NG_SQLITE_DEFAULT_STACK_SIZE;
    }

    /* Allocate dedicated downward-growing execution stack */
    void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        pthread_mutex_unlock(&g_sqlite_lock);
        return NG_ERR_NOMEM;
    }

    ret = ng_domain_create(domain_id, stack, stack_size);
    if (ret != NG_SUCCESS) {
        munmap(stack, stack_size);
        pthread_mutex_unlock(&g_sqlite_lock);
        return ret;
    }

    g_sqlite_domain = domain_id;
    g_sqlite_stack_base = stack;
    g_sqlite_stack_size = stack_size;
    g_sqlite_initialized = true;

    pthread_mutex_unlock(&g_sqlite_lock);
    return NG_SUCCESS;
}

void ng_sqlite_compartment_teardown(void)
{
    pthread_mutex_lock(&g_sqlite_lock);
    if (!g_sqlite_initialized) {
        pthread_mutex_unlock(&g_sqlite_lock);
        return;
    }

    if (g_sqlite_stack_base && g_sqlite_stack_size) {
        munmap(g_sqlite_stack_base, g_sqlite_stack_size);
        g_sqlite_stack_base = NULL;
        g_sqlite_stack_size = 0;
    }

    g_sqlite_initialized = false;
    pthread_mutex_unlock(&g_sqlite_lock);
}

int ng_sqlite_invoke_scalar(sqlite3_context *ctx, int argc, sqlite3_value **argv, sqlite3_scalar_func fn)
{
    if (!g_sqlite_initialized || !fn) {
        if (ctx) sqlite3_result_error(ctx, "SQLite compartment uninitialized", -1);
        return -1;
    }

    struct ng_sqlite_scalar_pack pack;
    pack.ctx = ctx;
    pack.argc = argc;
    pack.argv = argv;
    pack.fn = fn;

    uint64_t ret = ng_enter(g_sqlite_domain, worker_scalar, &pack);
    if (ret == (uint64_t)-1) {
        if (ctx) sqlite3_result_error(ctx, "Call-gate transition error", -1);
        return -1;
    }

    return 0;
}

int ng_sqlite_invoke_step(sqlite3_context *ctx, int argc, sqlite3_value **argv, sqlite3_step_func fn)
{
    if (!g_sqlite_initialized || !fn) {
        if (ctx) sqlite3_result_error(ctx, "SQLite compartment uninitialized", -1);
        return -1;
    }

    struct ng_sqlite_step_pack pack;
    pack.ctx = ctx;
    pack.argc = argc;
    pack.argv = argv;
    pack.fn = fn;

    uint64_t ret = ng_enter(g_sqlite_domain, worker_step, &pack);
    if (ret == (uint64_t)-1) {
        if (ctx) sqlite3_result_error(ctx, "Call-gate step error", -1);
        return -1;
    }

    return 0;
}

int ng_sqlite_invoke_final(sqlite3_context *ctx, sqlite3_final_func fn)
{
    if (!g_sqlite_initialized || !fn) {
        if (ctx) sqlite3_result_error(ctx, "SQLite compartment uninitialized", -1);
        return -1;
    }

    struct ng_sqlite_final_pack pack;
    pack.ctx = ctx;
    pack.fn = fn;

    uint64_t ret = ng_enter(g_sqlite_domain, worker_final, &pack);
    if (ret == (uint64_t)-1) {
        if (ctx) sqlite3_result_error(ctx, "Call-gate final error", -1);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Standard Real-World Workload UDF Implementations                    */
/* ------------------------------------------------------------------ */

/* 1. Crypto Hash: 64-bit FNV-1a hash over text/integer input */
void udf_crypto_hash(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc < 1 || !argv[0]) {
        sqlite3_result_null(ctx);
        return;
    }

    uint64_t hash = 0xcbf29ce484222325ULL; /* FNV offset basis */
    const unsigned char *text = sqlite3_value_text(argv[0]);
    if (text) {
        size_t len = (size_t)sqlite3_value_bytes(argv[0]);
        for (size_t i = 0; i < len; i++) {
            hash ^= (uint64_t)text[i];
            hash *= 0x100000001b3ULL; /* FNV prime */
        }
    } else {
        int64_t val = sqlite3_value_int64(argv[0]);
        hash ^= (uint64_t)val;
        hash *= 0x100000001b3ULL;
    }

    sqlite3_result_int64(ctx, (int64_t)hash);
}

/* 2. Wildcard Match: simple prefix/suffix wildcard matching */
void udf_wildcard_match(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc < 2 || !argv[0] || !argv[1]) {
        sqlite3_result_int(ctx, 0);
        return;
    }

    const unsigned char *pat = sqlite3_value_text(argv[0]);
    const unsigned char *str = sqlite3_value_text(argv[1]);

    if (!pat || !str) {
        sqlite3_result_int(ctx, 0);
        return;
    }

    /* Substring match */
    if (strstr((const char *)str, (const char *)pat) != NULL) {
        sqlite3_result_int(ctx, 1);
    } else {
        sqlite3_result_int(ctx, 0);
    }
}

/* 3. Polynomial Evaluation: y = a*x^2 + b*x + c */
void udf_polynomial_eval(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (argc < 4) {
        sqlite3_result_double(ctx, 0.0);
        return;
    }

    double a = sqlite3_value_double(argv[0]);
    double b = sqlite3_value_double(argv[1]);
    double c = sqlite3_value_double(argv[2]);
    double x = sqlite3_value_double(argv[3]);

    double res = a * x * x + b * x + c;
    sqlite3_result_double(ctx, res);
}
