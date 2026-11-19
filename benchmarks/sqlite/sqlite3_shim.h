/*
 * NullGate — Self-Contained SQLite 3 ABI Shim
 *
 * Provides standalone, zero-external-dependency definitions of the SQLite 3
 * C API data types and function signatures necessary for User-Defined Functions (UDFs).
 */

#ifndef NULLGATE_SQLITE3_SHIM_H
#define NULLGATE_SQLITE3_SHIM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SQLite Status Codes */
#define SQLITE_OK           0
#define SQLITE_ERROR        1
#define SQLITE_INTERNAL     2
#define SQLITE_PERM         3
#define SQLITE_ABORT        4
#define SQLITE_BUSY         5
#define SQLITE_LOCKED       6
#define SQLITE_NOMEM        7
#define SQLITE_READONLY     8
#define SQLITE_INTERRUPT    9
#define SQLITE_IOERR       10
#define SQLITE_CORRUPT     11
#define SQLITE_NOTFOUND    12
#define SQLITE_FULL        13
#define SQLITE_CANTOPEN    14
#define SQLITE_PROTOCOL    15
#define SQLITE_EMPTY       16
#define SQLITE_SCHEMA      17
#define SQLITE_TOOBIG      18
#define SQLITE_CONSTRAINT  19
#define SQLITE_MISMATCH    20
#define SQLITE_MISUSE      21

/* SQLite Fundamental Datatypes */
#define SQLITE_INTEGER  1
#define SQLITE_FLOAT    2
#define SQLITE_TEXT     3
#define SQLITE_BLOB     4
#define SQLITE_NULL     5

/* Forward declarations */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_context sqlite3_context;
typedef struct sqlite3_value sqlite3_value;

/* UDF Function Pointer Signatures */
typedef void (*sqlite3_scalar_func)(sqlite3_context *ctx, int argc, sqlite3_value **argv);
typedef void (*sqlite3_step_func)(sqlite3_context *ctx, int argc, sqlite3_value **argv);
typedef void (*sqlite3_final_func)(sqlite3_context *ctx);
typedef void (*sqlite3_destructor_type)(void *);

#define SQLITE_STATIC      ((sqlite3_destructor_type)0)
#define SQLITE_TRANSIENT   ((sqlite3_destructor_type)-1)

/* In-memory representation of SQLite Value */
struct sqlite3_value {
    int type;
    int64_t i_val;
    double f_val;
    char text[512];
    size_t len;
};

/* In-memory representation of SQLite Function Execution Context */
struct sqlite3_context {
    struct sqlite3_value result;
    int is_error;
    int err_code;
    char err_msg[256];
    void *user_data;
    void *aggregate_context;
    size_t aggregate_context_size;
};

/* Value Inspection Accessors */
static inline int sqlite3_value_type(sqlite3_value *val)
{
    return val ? val->type : SQLITE_NULL;
}

static inline int64_t sqlite3_value_int64(sqlite3_value *val)
{
    if (!val) return 0;
    if (val->type == SQLITE_INTEGER) return val->i_val;
    if (val->type == SQLITE_FLOAT) return (int64_t)val->f_val;
    return 0;
}

static inline int sqlite3_value_int(sqlite3_value *val)
{
    return (int)sqlite3_value_int64(val);
}

static inline double sqlite3_value_double(sqlite3_value *val)
{
    if (!val) return 0.0;
    if (val->type == SQLITE_FLOAT) return val->f_val;
    if (val->type == SQLITE_INTEGER) return (double)val->i_val;
    return 0.0;
}

static inline const unsigned char *sqlite3_value_text(sqlite3_value *val)
{
    if (!val || val->type != SQLITE_TEXT) return NULL;
    return (const unsigned char *)val->text;
}

static inline int sqlite3_value_bytes(sqlite3_value *val)
{
    return val ? (int)val->len : 0;
}

/* Result Setting Accessors */
static inline void sqlite3_result_int64(sqlite3_context *ctx, int64_t val)
{
    if (!ctx) return;
    ctx->result.type = SQLITE_INTEGER;
    ctx->result.i_val = val;
    ctx->is_error = 0;
}

static inline void sqlite3_result_int(sqlite3_context *ctx, int val)
{
    sqlite3_result_int64(ctx, (int64_t)val);
}

static inline void sqlite3_result_double(sqlite3_context *ctx, double val)
{
    if (!ctx) return;
    ctx->result.type = SQLITE_FLOAT;
    ctx->result.f_val = val;
    ctx->is_error = 0;
}

static inline void sqlite3_result_text(sqlite3_context *ctx, const char *text, int len, sqlite3_destructor_type dtor)
{
    (void)dtor;
    if (!ctx) return;
    ctx->result.type = SQLITE_TEXT;
    if (!text) {
        ctx->result.text[0] = '\0';
        ctx->result.len = 0;
        return;
    }
    size_t copy_len = (len < 0) ? strlen(text) : (size_t)len;
    if (copy_len >= sizeof(ctx->result.text)) {
        copy_len = sizeof(ctx->result.text) - 1;
    }
    memcpy(ctx->result.text, text, copy_len);
    ctx->result.text[copy_len] = '\0';
    ctx->result.len = copy_len;
    ctx->is_error = 0;
}

static inline void sqlite3_result_null(sqlite3_context *ctx)
{
    if (!ctx) return;
    ctx->result.type = SQLITE_NULL;
    ctx->result.len = 0;
    ctx->is_error = 0;
}

static inline void sqlite3_result_error(sqlite3_context *ctx, const char *msg, int len)
{
    if (!ctx) return;
    ctx->is_error = 1;
    ctx->err_code = SQLITE_ERROR;
    if (msg) {
        size_t copy_len = (len < 0) ? strlen(msg) : (size_t)len;
        if (copy_len >= sizeof(ctx->err_msg)) {
            copy_len = sizeof(ctx->err_msg) - 1;
        }
        memcpy(ctx->err_msg, msg, copy_len);
        ctx->err_msg[copy_len] = '\0';
    } else {
        ctx->err_msg[0] = '\0';
    }
}

static inline void *sqlite3_user_data(sqlite3_context *ctx)
{
    return ctx ? ctx->user_data : NULL;
}

static inline void *sqlite3_aggregate_context(sqlite3_context *ctx, int nbytes)
{
    if (!ctx || nbytes <= 0) return NULL;
    if (!ctx->aggregate_context) {
        ctx->aggregate_context = calloc(1, (size_t)nbytes);
        ctx->aggregate_context_size = (size_t)nbytes;
    }
    return ctx->aggregate_context;
}

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_SQLITE3_SHIM_H */
