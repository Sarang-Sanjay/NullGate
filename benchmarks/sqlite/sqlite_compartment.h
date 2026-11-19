/*
 * NullGate — Self-Contained SQLite UDF Sandboxing Compartment Header
 * Pillar 1: Hardware-Enforced Compartmentalization & Low-Overhead Call Gate
 */

#ifndef NULLGATE_SQLITE_COMPARTMENT_H
#define NULLGATE_SQLITE_COMPARTMENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "sqlite3_shim.h"
#include "nullgate.h"
#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NG_SQLITE_DEFAULT_DOMAIN        3
#define NG_SQLITE_DEFAULT_STACK_SIZE    (64 * 1024)

/**
 * ng_sqlite_compartment_init - Initialize dedicated SQLite UDF sandbox compartment.
 * @domain_id: Target compartment domain ID (typically 3)
 * @stack_size: Byte size of isolated compartment execution stack (e.g. 64KB)
 *
 * Allocates stack, tags with PKU key, registers domain.
 * Returns NG_SUCCESS on success, negative error code on failure.
 */
int ng_sqlite_compartment_init(uint32_t domain_id, size_t stack_size);

/**
 * ng_sqlite_compartment_teardown - Tear down SQLite sandbox compartment and free stack.
 */
void ng_sqlite_compartment_teardown(void);

/**
 * ng_sqlite_invoke_scalar - Dispatch a scalar SQLite UDF across the hardware call-gate.
 * @ctx: SQLite context
 * @argc: Number of arguments
 * @argv: Array of argument pointers
 * @fn: Untrusted scalar function callback
 *
 * Wraps call into ng_enter() running on isolated compartment stack under PKU Key 3.
 * Returns 0 on success, or -1 on fault/error.
 */
int ng_sqlite_invoke_scalar(sqlite3_context *ctx, int argc, sqlite3_value **argv, sqlite3_scalar_func fn);

/**
 * ng_sqlite_invoke_step - Dispatch an aggregate step UDF across the hardware call-gate.
 */
int ng_sqlite_invoke_step(sqlite3_context *ctx, int argc, sqlite3_value **argv, sqlite3_step_func fn);

/**
 * ng_sqlite_invoke_final - Dispatch an aggregate finalizer UDF across the hardware call-gate.
 */
int ng_sqlite_invoke_final(sqlite3_context *ctx, sqlite3_final_func fn);

/* Benchmark Sample UDFs */
void udf_crypto_hash(sqlite3_context *ctx, int argc, sqlite3_value **argv);
void udf_wildcard_match(sqlite3_context *ctx, int argc, sqlite3_value **argv);
void udf_polynomial_eval(sqlite3_context *ctx, int argc, sqlite3_value **argv);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_SQLITE_COMPARTMENT_H */
