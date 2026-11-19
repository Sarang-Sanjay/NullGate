/*
 * NullGate — Security Penetration Suite: SQLite UDF Multi-Vector Escape Defense
 *
 * Verifies that untrusted SQLite User-Defined Functions (UDFs) running in
 * hardware PKU compartments cannot escape their sandbox or compromise host security:
 *   1. Legitimate Workload Execution: Verifies scalar hashing, string matching,
 *      and polynomial math execute cleanly with zero faults.
 *   2. Attack Vector 1: UDF attempting to read/tamper with host database memory pages
 *      (isolated under Key 2) -> Trapped by hardware SEGV_PKUERR.
 *   3. Attack Vector 2: UDF attempting unauthorized filesystem access (/root/.ssh/id_rsa)
 *      -> Blocked with -EACCES / -EPERM.
 *   4. Attack Vector 3: UDF attempting runtime privilege escalation via prctl/bpf
 *      -> Blocked with -EPERM / error.
 *   5. Attack Vector 4: UDF attempting to tamper with Key 1 trusted state (t_trusted_state)
 *      -> Trapped by hardware SEGV_PKUERR.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <setjmp.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/bpf.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "sqlite3_shim.h"
#include "sqlite_compartment.h"

#define TEST_STACK_SIZE (64 * 1024)

#ifndef SYS_bpf
#define SYS_bpf 321
#endif

#ifndef PRCTL_MAGIC_REGISTER
#define PRCTL_MAGIC_REGISTER 0x4e554c4c /* 'NULL' */
#endif

static sigjmp_buf g_jmpbuf;
static volatile sig_atomic_t g_segv_caught = 0;
static volatile sig_atomic_t g_segv_is_pku = 0;

static void segv_handler(int sig, siginfo_t *si, void *ucontext)
{
    (void)sig;
    (void)ucontext;

    g_segv_caught = 1;
    if (si && si->si_code == SEGV_PKUERR) {
        g_segv_is_pku = 1;
    }

    siglongjmp(g_jmpbuf, 1);
}

/* Malicious UDF Vector 1: Attempting to read host database memory pages */
static void udf_malicious_snoop_host_db(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    (void)argc;
    (void)argv;
    void *host_db_page = sqlite3_user_data(ctx);

    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        /* Reading host database page tagged with Key 2 must trigger SEGV_PKUERR */
        volatile uint32_t *ptr = (volatile uint32_t *)host_db_page;
        volatile uint32_t val = *ptr;
        (void)val;
        *ptr = 0xDEADBEEF;
        sqlite3_result_int(ctx, 0); /* Exploit succeeded (FAIL) */
        return;
    }

    /* Trapped and recovered via signal handler */
    sqlite3_result_int(ctx, 0xCAFE);
}

/* Malicious UDF Vector 2: Attempting unauthorized filesystem access */
static void udf_malicious_fs_escape(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    (void)argc;
    (void)argv;

    int fd = open("/root/.ssh/id_rsa", O_RDONLY);
    if (fd >= 0) {
        close(fd);
        sqlite3_result_int(ctx, 1); /* Exploit succeeded (FAIL) */
    } else {
        sqlite3_result_int(ctx, -errno); /* Blocked (PASS) */
    }
}

/* Malicious UDF Vector 3: Attempting prctl registration hijack / BPF load */
static void udf_malicious_priv_escalation(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    (void)argc;
    (void)argv;

    int failures = 0;

    /* 1. Attempt BPF map creation */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;

    long bpf_ret = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (bpf_ret >= 0) {
        close((int)bpf_ret);
        failures++;
    }

    /* 2. Attempt NullGate registration replay */
    int prctl_ret = prctl(PRCTL_MAGIC_REGISTER, 0x70000000ULL, 0, 0, 0);
    if (prctl_ret == 0) {
        failures++;
    }

    sqlite3_result_int(ctx, failures);
}

/* Malicious UDF Vector 4: Attempting to tamper with Key 1 trusted state */
static void udf_malicious_trusted_state_tamper(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    (void)argc;
    (void)argv;
    void *trusted_state_addr = sqlite3_user_data(ctx);

    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        /* Reading or writing Key 1 protected trusted state must trigger SEGV_PKUERR */
        volatile uint64_t *ptr = (volatile uint64_t *)trusted_state_addr;
        volatile uint64_t val = *ptr;
        (void)val;
        *ptr = 0x0ULL;
        sqlite3_result_int(ctx, 0); /* Exploit succeeded (FAIL) */
        return;
    }

    /* Trapped and recovered via signal handler */
    sqlite3_result_int(ctx, 0xCAFE);
}

int main(void)
{
    printf("====================================================================\n");
    printf("   NullGate — SQLite UDF Multi-Vector Escape Penetration Test       \n");
    printf("   Group D: Real-World Database Compartmentalization & Attack Defense\n");
    printf("====================================================================\n\n");

    /* Initialize NullGate runtime */
    int ret = ng_init();
    assert(ret == NG_SUCCESS);
    (void)ret;

    /* Install SIGSEGV handler via NullGate signal subsystem */
    ret = ng_signal_register_handler(SIGSEGV, segv_handler);
    assert(ret == NG_SUCCESS);
    (void)ret;

    /* Initialize SQLite compartment (Domain 3, 64KB stack) */
    ret = ng_sqlite_compartment_init(3, TEST_STACK_SIZE);
    assert(ret == NG_SUCCESS);
    (void)ret;

    /* ------------------------------------------------------------------ */
    /* Phase 1: Legitimate Real-World UDF Execution                       */
    /* ------------------------------------------------------------------ */
    printf("[PHASE 1] Testing legitimate UDF workload execution in sandbox...\n");

    /* 1. Crypto Hash UDF */
    sqlite3_value val_text;
    val_text.type = SQLITE_TEXT;
    strcpy(val_text.text, "SELECT * FROM transactions WHERE amount > 1000;");
    val_text.len = strlen(val_text.text);
    sqlite3_value *argv1[1] = { &val_text };

    sqlite3_context ctx1;
    memset(&ctx1, 0, sizeof(ctx1));
    ret = ng_sqlite_invoke_scalar(&ctx1, 1, argv1, udf_crypto_hash);
    assert(ret == 0);
    assert(ctx1.is_error == 0);
    assert(ctx1.result.type == SQLITE_INTEGER);
    assert(ctx1.result.i_val != 0);
    printf("         -> udf_crypto_hash succeeded: 0x%016llx\n", (unsigned long long)ctx1.result.i_val);

    /* 2. Wildcard Match UDF */
    sqlite3_value val_pat, val_target;
    val_pat.type = SQLITE_TEXT;
    strcpy(val_pat.text, "transactions");
    val_pat.len = strlen(val_pat.text);

    val_target.type = SQLITE_TEXT;
    strcpy(val_target.text, "SELECT * FROM transactions WHERE amount > 1000;");
    val_target.len = strlen(val_target.text);

    sqlite3_value *argv2[2] = { &val_pat, &val_target };
    sqlite3_context ctx2;
    memset(&ctx2, 0, sizeof(ctx2));
    ret = ng_sqlite_invoke_scalar(&ctx2, 2, argv2, udf_wildcard_match);
    assert(ret == 0);
    assert(ctx2.is_error == 0);
    assert(ctx2.result.i_val == 1);
    printf("         -> udf_wildcard_match succeeded: match found (1)\n");

    /* 3. Polynomial Evaluation UDF: y = 2*x^2 + 3*x + 5 at x=4 => 49.0 */
    sqlite3_value val_a = { .type = SQLITE_FLOAT, .f_val = 2.0, .i_val = 2, .len = 0, .text = {0} };
    sqlite3_value val_b = { .type = SQLITE_FLOAT, .f_val = 3.0, .i_val = 3, .len = 0, .text = {0} };
    sqlite3_value val_c = { .type = SQLITE_FLOAT, .f_val = 5.0, .i_val = 5, .len = 0, .text = {0} };
    sqlite3_value val_x = { .type = SQLITE_FLOAT, .f_val = 4.0, .i_val = 4, .len = 0, .text = {0} };
    sqlite3_value *argv3[4] = { &val_a, &val_b, &val_c, &val_x };

    sqlite3_context ctx3;
    memset(&ctx3, 0, sizeof(ctx3));
    ret = ng_sqlite_invoke_scalar(&ctx3, 4, argv3, udf_polynomial_eval);
    assert(ret == 0);
    assert(ctx3.is_error == 0);
    assert(ctx3.result.type == SQLITE_FLOAT);
    assert(ctx3.result.f_val == 49.0);
    printf("         -> udf_polynomial_eval succeeded: y = %.1f (expected 49.0)\n\n", ctx3.result.f_val);

    /* ------------------------------------------------------------------ */
    /* Phase 2: Attack Vector 1 — Host Database Memory Snooping / Tamper   */
    /* ------------------------------------------------------------------ */
    printf("[PHASE 2] Attack Vector 1: Host Database Memory Snooping/Tampering...\n");

    /* Allocate and protect host DB page under Domain 2 */
    void *host_db_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(host_db_page != MAP_FAILED);
    void *stack2 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack2 != MAP_FAILED);

    ret = ng_domain_create(2, stack2, TEST_STACK_SIZE);
    assert(ret == NG_SUCCESS);
    ret = ng_domain_protect(2, host_db_page, 4096, PROT_READ | PROT_WRITE);
    assert(ret == NG_SUCCESS);
    (void)ret;

    /* Write secret records into host DB page */
    strcpy((char *)host_db_page, "CONFIDENTIAL_HOST_DATABASE_TABLE_ACCOUNTS_1337");

    g_segv_caught = 0;
    g_segv_is_pku = 0;

    sqlite3_context ctx_snoop;
    memset(&ctx_snoop, 0, sizeof(ctx_snoop));
    ctx_snoop.user_data = host_db_page;

    /* Invoke malicious UDF inside Domain 3 */
    ret = ng_sqlite_invoke_scalar(&ctx_snoop, 0, NULL, udf_malicious_snoop_host_db);
    assert(ret == 0);
    assert(ctx_snoop.result.i_val == 0xCAFE);
    assert(g_segv_caught == 1);
    assert(g_segv_is_pku == 1);
    printf("         -> [DEFENDED] Hardware SEGV_PKUERR trapped: Host DB page access denied by PKU\n\n");

    /* ------------------------------------------------------------------ */
    /* Phase 3: Attack Vector 2 — Unauthorized Filesystem Access          */
    /* ------------------------------------------------------------------ */
    printf("[PHASE 3] Attack Vector 2: Unauthorized Filesystem Exfiltration...\n");
    sqlite3_context ctx_fs;
    memset(&ctx_fs, 0, sizeof(ctx_fs));

    ret = ng_sqlite_invoke_scalar(&ctx_fs, 0, NULL, udf_malicious_fs_escape);
    assert(ret == 0);
    assert(ctx_fs.result.i_val < 0); /* open() must return < 0 */
    printf("         -> [DEFENDED] /root/.ssh/id_rsa open() blocked with errno=%lld\n\n",
           (long long)-ctx_fs.result.i_val);

    /* ------------------------------------------------------------------ */
    /* Phase 4: Attack Vector 3 — Privilege Escalation / Prctl Tamper     */
    /* ------------------------------------------------------------------ */
    printf("[PHASE 4] Attack Vector 3: Privilege Escalation & Registration Hijack...\n");
    sqlite3_context ctx_priv;
    memset(&ctx_priv, 0, sizeof(ctx_priv));

    ret = ng_sqlite_invoke_scalar(&ctx_priv, 0, NULL, udf_malicious_priv_escalation);
    assert(ret == 0);
    assert(ctx_priv.result.i_val == 0); /* 0 failures tolerated */
    printf("         -> [DEFENDED] BPF map creation and registration replay rejected\n\n");

    /* ------------------------------------------------------------------ */
    /* Phase 5: Attack Vector 4 — Key 1 Trusted State Tamper Resistance   */
    /* ------------------------------------------------------------------ */
    printf("[PHASE 5] Attack Vector 4: Key 1 Trusted State Tamper Resistance...\n");
    uintptr_t ts_addr = ng_get_trusted_state_addr();
    assert(ts_addr != 0);

    g_segv_caught = 0;
    g_segv_is_pku = 0;

    sqlite3_context ctx_ts;
    memset(&ctx_ts, 0, sizeof(ctx_ts));
    ctx_ts.user_data = (void *)ts_addr;

    ret = ng_sqlite_invoke_scalar(&ctx_ts, 0, NULL, udf_malicious_trusted_state_tamper);
    assert(ret == 0);
    assert(ctx_ts.result.i_val == 0xCAFE);
    assert(g_segv_caught == 1);
    assert(g_segv_is_pku == 1);
    printf("         -> [DEFENDED] Hardware SEGV_PKUERR trapped: Key 1 trusted state protected\n\n");

    /* ------------------------------------------------------------------ */
    /* Phase 6: Teardown & Clean Shutdown                                 */
    /* ------------------------------------------------------------------ */
    printf("[PHASE 6] Tearing down SQLite UDF sandbox compartment...\n");
    munmap(host_db_page, 4096);
    munmap(stack2, TEST_STACK_SIZE);
    ng_sqlite_compartment_teardown();
    printf("         -> Compartment torn down cleanly\n\n");

    printf("[SUCCESS] All 4 SQLite UDF attack vectors Neutralized & Defended.\n");
    return 0;
}
