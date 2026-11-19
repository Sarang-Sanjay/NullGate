/*
 * NullGate — Unit Test: Zero-Copy Hardware PKU SPSC IPC Subsystem
 *
 * Verifies:
 *   1. Channel creation, parameter bounds checking, power-of-2 capacity.
 *   2. Single-Producer Single-Consumer lock-free ring messaging with data integrity.
 *   3. Ring boundary conditions: NG_IPC_ERR_FULL and NG_IPC_ERR_EMPTY.
 *   4. Multi-domain isolation: Unauthorized domain (Domain 4) attempting to
 *      read/write channel memory immediately triggers hardware SEGV_PKUERR.
 *   5. Hardware PKU key recycling (Safeguard 2): Repeated channel creation
 *      and destruction does not exhaust Intel's 16 hardware keys.
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
#include <sys/mman.h>
#include <unistd.h>

#include "nullgate.h"
#include "nullgate_abi.h"
#include "nullgate_ipc.h"

#define TEST_STACK_SIZE (64 * 1024)

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

/* Domain 2 worker: Sends a message into IPC channel */
static uint64_t worker_domain_2_send(void *arg)
{
    struct ng_ipc_channel *chan = (struct ng_ipc_channel *)arg;
    const char msg[] = "NullGate Domain 2 -> Domain 3 IPC Payload";
    int ret = ng_ipc_send(chan, msg, sizeof(msg));
    return (ret == NG_IPC_OK) ? 1ULL : 0ULL;
}

/* Domain 3 worker: Receives a message from IPC channel */
static uint64_t worker_domain_3_recv(void *arg)
{
    struct ng_ipc_channel *chan = (struct ng_ipc_channel *)arg;
    char buf[64] = {0};
    int ret = ng_ipc_recv(chan, buf, sizeof(buf));
    if (ret <= 0) {
        return 0ULL;
    }
    const char expected[] = "NullGate Domain 2 -> Domain 3 IPC Payload";
    if (strcmp(buf, expected) != 0) {
        return 0ULL;
    }
    return 1ULL;
}

/* Domain 4 worker: Unauthorized compartment attempting to tamper with IPC ring */
static uint64_t worker_domain_4_tamper(void *arg)
{
    volatile uint32_t *magic_ptr = (volatile uint32_t *)arg;

    if (sigsetjmp(g_jmpbuf, 1) == 0) {
        /* Reading or writing this must trigger hardware SEGV_PKUERR */
        volatile uint32_t val = *magic_ptr;
        (void)val;
        *magic_ptr = 0xDEADBEEF;
        return 0ULL;
    }

    /* Reached via siglongjmp from segv_handler */
    return 0xCAFEULL;
}

int main(void)
{
    printf("====================================================================\n");
    printf("       NullGate — Zero-Copy Hardware IPC Unit Test                  \n");
    printf("====================================================================\n\n");

    /* Initialize NullGate runtime */
    int ret = ng_init();
    assert(ret == NG_SUCCESS);
    (void)ret;

    /* Install SIGSEGV handler via NullGate signal trampoline */
    ret = ng_signal_register_handler(SIGSEGV, segv_handler);
    assert(ret == NG_SUCCESS);
    (void)ret;

    /* Allocate compartment stacks for domains 2, 3, 4 */
    void *stack2 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *stack3 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *stack4 = mmap(NULL, TEST_STACK_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(stack2 != MAP_FAILED && stack3 != MAP_FAILED && stack4 != MAP_FAILED);
    (void)stack2; (void)stack3; (void)stack4;

    ret = ng_domain_create(2, stack2, TEST_STACK_SIZE);
    assert(ret == NG_SUCCESS);
    ret = ng_domain_create(3, stack3, TEST_STACK_SIZE);
    assert(ret == NG_SUCCESS);
    ret = ng_domain_create(4, stack4, TEST_STACK_SIZE);
    assert(ret == NG_SUCCESS);
    (void)ret;

    /* ------------------------------------------------------------------ */
    /* Stage 1: Parameter validation                                      */
    /* ------------------------------------------------------------------ */
    printf("[STAGE 1] Testing parameter bounds and capacity validation...\n");
    assert(ng_ipc_channel_create(99, 3, 1024) == NULL);  /* Invalid sender */
    assert(ng_ipc_channel_create(2, 99, 1024) == NULL);  /* Invalid receiver */
    assert(ng_ipc_channel_create(2, 3, 0) == NULL);      /* Zero capacity */
    assert(ng_ipc_channel_create(2, 3, 1000) == NULL);   /* Non power-of-2 */
    assert(ng_ipc_channel_create(2, 3, 1ULL << 32) == NULL); /* NG-P4-10: 64-bit overflow/truncation */
    assert(ng_ipc_channel_create(2, 3, (1024U * 1024U) * 2) == NULL); /* NG-P4-10: Exceeds max slots */

    struct ng_ipc_channel *chan = ng_ipc_channel_create(2, 3, 1024);
    assert(chan != NULL);
    printf("         -> Successfully created 1024-slot IPC channel between Dom 2 and Dom 3\n");

    /* ------------------------------------------------------------------ */
    /* Stage 2: SPSC Data Transfer across Compartments                    */
    /* ------------------------------------------------------------------ */
    printf("[STAGE 2] Testing cross-compartment SPSC messaging...\n");
    /* Send from Domain 2 */
    uint64_t send_res = ng_enter(2, worker_domain_2_send, chan);
    assert(send_res == 1ULL);
    (void)send_res;

    /* Recv in Domain 3 */
    uint64_t recv_res = ng_enter(3, worker_domain_3_recv, chan);
    assert(recv_res == 1ULL);
    (void)recv_res;
    printf("         -> Cross-domain payload verified with full data integrity\n");

    /* ------------------------------------------------------------------ */
    /* Stage 3: Ring Boundary Conditions (Full & Empty)                   */
    /* ------------------------------------------------------------------ */
    printf("[STAGE 3] Testing ring boundary conditions (Full & Empty)...\n");
    struct ng_ipc_channel *small_chan = ng_ipc_channel_create(2, 3, 8);
    assert(small_chan != NULL);

    char test_msg[8] = "TESTMSG";
    for (int i = 0; i < 8; i++) {
        int s = ng_ipc_send(small_chan, test_msg, sizeof(test_msg));
        assert(s == NG_IPC_OK);
        (void)s;
    }
    /* 9th message must fail with NG_IPC_ERR_FULL */
    int full_res = ng_ipc_send(small_chan, test_msg, sizeof(test_msg));
    assert(full_res == NG_IPC_ERR_FULL);
    (void)full_res;
    (void)test_msg;

    /* Drain all 8 messages */
    char recv_buf[16];
    for (int i = 0; i < 8; i++) {
        int r = ng_ipc_recv(small_chan, recv_buf, sizeof(recv_buf));
        assert(r == (int)sizeof(test_msg));
        (void)r;
    }
    /* 9th receive must fail with NG_IPC_ERR_EMPTY */
    int empty_res = ng_ipc_recv(small_chan, recv_buf, sizeof(recv_buf));
    assert(empty_res == NG_IPC_ERR_EMPTY);
    (void)empty_res;
    (void)recv_buf;

    ng_ipc_channel_destroy(small_chan);
    printf("         -> Full and empty boundaries strictly enforced\n");

    /* ------------------------------------------------------------------ */
    /* Stage 4: Multi-Domain Isolation (Unauthorized Domain Access)       */
    /* ------------------------------------------------------------------ */
    printf("[STAGE 4] Testing unauthorized third-party compartment isolation...\n");
    g_segv_caught = 0;
    g_segv_is_pku = 0;

    void *ring_buf = ng_ipc_get_ring_buffer(chan);
    assert(ring_buf != NULL);

    uint64_t tamper_res = ng_enter(4, worker_domain_4_tamper, ring_buf);
    assert(tamper_res == 0xCAFEULL);
    (void)tamper_res;
    assert(g_segv_caught == 1);
    assert(g_segv_is_pku == 1);
    printf("         -> SEGV_PKUERR confirmed: Domain 4 access denied by Intel PKU\n");

    /* ------------------------------------------------------------------ */
    /* Stage 5: Hardware PKU Key Recycling (Safeguard 2)                  */
    /* ------------------------------------------------------------------ */
    printf("[STAGE 5] Testing hardware PKU key recycling (Safeguard 2)...\n");
    ng_ipc_channel_destroy(chan);

    /*
     * Intel CPUs feature exactly 16 hardware PKU keys.
     * Creating 64 consecutive channels would fail on key exhaustion if
     * ng_ipc_channel_destroy() did not recycle keys via pkey_free().
     */
    for (int i = 0; i < 64; i++) {
        struct ng_ipc_channel *c = ng_ipc_channel_create(2, 3, 16);
        assert(c != NULL);
        assert(ng_ipc_send(c, "KEY_TEST", 8) == NG_IPC_OK);
        ng_ipc_channel_destroy(c);
    }
    printf("         -> 64 channel create/destroy cycles succeeded: Zero hardware PKU key leak\n");

    /* ------------------------------------------------------------------ */
    /* Stage 6: Regression NG-P4-01 Hostile Shared-Memory Tampering       */
    /* ------------------------------------------------------------------ */
    printf("[STAGE 6] Testing NG-P4-01: Hostile shared-memory capacity & length corruption...\n");
    struct ng_ipc_channel *vuln_chan = ng_ipc_channel_create(2, 3, 16);
    assert(vuln_chan != NULL);

    /* Send legitimate message */
    const char safe_msg[] = "SafeMessagePayload";
    int ret_send = ng_ipc_send(vuln_chan, safe_msg, sizeof(safe_msg));
    assert(ret_send == NG_IPC_OK);
    (void)ret_send;
    (void)safe_msg;

    /* Simulate hostile peer corrupting ring->capacity to 0xFFFFFFFF and slot->len to 0xFFFF */
    struct ng_ipc_ring *raw_ring = (struct ng_ipc_ring *)ng_ipc_get_ring_buffer(vuln_chan);
    assert(raw_ring != NULL);
    raw_ring->capacity = 0xFFFFFFFFU;
    raw_ring->slots[0].len = 0xFFFFU;

    /* Receiver reading with 4KB buffer must clamp to NG_IPC_MAX_DATA_PER_SLOT and stay in bounds */
    char large_buf[4096];
    memset(large_buf, 0xCC, sizeof(large_buf));
    int recvd = ng_ipc_recv(vuln_chan, large_buf, sizeof(large_buf));
    assert(recvd == NG_IPC_MAX_DATA_PER_SLOT);
    (void)recvd;
    /* Verify memory immediately past NG_IPC_MAX_DATA_PER_SLOT in large_buf was untouched */
    assert((unsigned char)large_buf[NG_IPC_MAX_DATA_PER_SLOT] == 0xCC);
    printf("         -> ng_ipc_recv safely clamped forged slot->len to max slot size (%d bytes)\n", recvd);

    /* Verify subsequent send uses private chan->capacity and stays in bounds */
    raw_ring->capacity = 0xDEADBEEFU;
    int rc = ng_ipc_send(vuln_chan, "NextSafeMsg", 11);
    assert(rc == NG_IPC_OK);
    (void)rc;
    printf("         -> ng_ipc_send safely used private unshared chan->capacity\n");

    ng_ipc_channel_destroy(vuln_chan);

    printf("\n[SUCCESS] All 6 IPC unit test stages PASSED.\n");
    return 0;
}
