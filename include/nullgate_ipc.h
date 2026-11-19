/*
 * NullGate — Hardware Zero-Copy SPSC Shared Memory IPC Subsystem Header
 * Defines cacheline-separated lock-free SPSC ring buffer ABI and multi-key interfaces.
 */

#ifndef NULLGATE_IPC_H
#define NULLGATE_IPC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IPC Magic & Versioning */
#define NG_IPC_MAGIC                0x4E474950U /* 'NGIP' */
#define NG_IPC_VERSION_1            1U
#define NG_IPC_CURRENT_VERSION      NG_IPC_VERSION_1

#define NG_IPC_DEFAULT_SLOTS        1024U       /* Must be power of 2 */
#define NG_IPC_SLOT_SIZE            64U         /* Exactly one 64-byte cacheline */
#define NG_IPC_MAX_DATA_PER_SLOT    56U

/* Status and Error Codes */
enum ng_ipc_status {
    NG_IPC_OK                       =  0,
    NG_IPC_ERR_INVALID              = -1, /* Invalid NULL pointer or domain ID */
    NG_IPC_ERR_FULL                 = -2, /* Ring buffer full on send */
    NG_IPC_ERR_EMPTY                = -3, /* Ring buffer empty on recv */
    NG_IPC_ERR_MSG_TOO_LARGE        = -4, /* Payload exceeds slot capacity */
    NG_IPC_ERR_PKEY_EXHAUSTED       = -5, /* Hardware PKU keys exhausted */
    NG_IPC_ERR_NOMEM                = -6  /* Memory mapping failed */
};

/*
 * struct ng_ipc_slot:
 * Exactly 64 bytes (1 cacheline). Eliminates split-cacheline transfers.
 */
struct ng_ipc_slot {
    uint32_t seq;
    uint32_t len;
    uint8_t  data[NG_IPC_MAX_DATA_PER_SLOT];
} __attribute__((aligned(64)));

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct ng_ipc_slot) == 64, "ng_ipc_slot must be exactly 64 bytes");
#endif

/*
 * struct ng_ipc_ring:
 * Cacheline-separated Single-Producer Single-Consumer (SPSC) ring buffer.
 *
 * Cacheline separation layout:
 *   - Offset 0..63   (Cacheline 0): Read-only channel configuration metadata.
 *   - Offset 64..127 (Cacheline 1): Producer head index (written only by Sender).
 *   - Offset 128..191(Cacheline 2): Consumer tail index (written only by Receiver).
 *   - Offset 192+    (Cacheline 3+): Contiguous slot array.
 *
 * This layout eliminates cache ping-pong false sharing across producer and consumer cores.
 */
struct ng_ipc_ring {
    /* Cacheline 0: Channel Metadata (64 bytes) */
    uint32_t magic;                     /* Offset 0:  NG_IPC_MAGIC */
    uint16_t version;                   /* Offset 4:  NG_IPC_CURRENT_VERSION */
    uint16_t reserved;                  /* Offset 6:  Reserved alignment padding */
    uint32_t capacity;                  /* Offset 8:  Total slots (power of 2) */
    uint32_t sender_domain;             /* Offset 12: Sender compartment domain ID */
    uint32_t receiver_domain;           /* Offset 16: Receiver compartment domain ID */
    int32_t  shared_pkey;               /* Offset 20: Hardware PKU key protecting channel */
    uint8_t  pad0[40];                  /* Offset 24: Pad to full 64 bytes */

    /* Cacheline 1: Producer State (64 bytes) */
    uint64_t head __attribute__((aligned(64))); /* Offset 64:  Producer write index */
    uint8_t  pad1[56];                          /* Offset 72:  Pad to full 64 bytes */

    /* Cacheline 2: Consumer State (64 bytes) */
    uint64_t tail __attribute__((aligned(64))); /* Offset 128: Consumer read index */
    uint8_t  pad2[56];                          /* Offset 136: Pad to full 64 bytes */

    /* Cacheline 3+: Ring Payload Slots (192 bytes offset) */
    struct ng_ipc_slot slots[] __attribute__((aligned(64)));
};

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(offsetof(struct ng_ipc_ring, magic) == 0, "magic must be at offset 0");
_Static_assert(offsetof(struct ng_ipc_ring, head) == 64, "head must be isolated on Cacheline 1 (offset 64)");
_Static_assert(offsetof(struct ng_ipc_ring, tail) == 128, "tail must be isolated on Cacheline 2 (offset 128)");
_Static_assert(offsetof(struct ng_ipc_ring, slots) == 192, "slots must begin on Cacheline 3 (offset 192)");
#endif

/* IPC channel descriptor */
struct ng_ipc_channel {
    struct ng_ipc_ring *ring;
    size_t ring_bytes;
    uint32_t capacity;          /* Unshared private validated slot count (power of 2) */
    uint32_t sender_dom;
    uint32_t receiver_dom;
    int shared_pkey;
};

/**
 * ng_ipc_get_ring_buffer - Return pointer to underlying shared memory ring buffer.
 * @chan: IPC channel descriptor
 */
void *ng_ipc_get_ring_buffer(struct ng_ipc_channel *chan);

/**
 * ng_ipc_channel_create - Create a hardware-isolated zero-copy IPC channel between domains.
 * @sender_dom: Sender compartment domain ID (0..15)
 * @receiver_dom: Receiver compartment domain ID (0..15)
 * @num_slots: Number of 64-byte slots (must be a power of 2, e.g. 1024)
 *
 * Allocates shared memory page, allocates a dedicated hardware PKU key,
 * grants shared access to sender and receiver domains via pku_grant_shared_key(),
 * and protects the channel memory range via pkey_mprotect.
 *
 * Returns pointer to channel descriptor, or NULL on error.
 */
struct ng_ipc_channel *ng_ipc_channel_create(uint32_t sender_dom, uint32_t receiver_dom, size_t num_slots);

/**
 * ng_ipc_send - Send a zero-copy message into the SPSC channel.
 * @chan: IPC channel descriptor
 * @data: Pointer to message payload
 * @len: Payload length in bytes (max 56 bytes per single slot)
 *
 * Uses release memory ordering (__ATOMIC_RELEASE) and memory fences.
 * Returns NG_IPC_OK on success, NG_IPC_ERR_FULL if ring is full.
 */
int ng_ipc_send(struct ng_ipc_channel *chan, const void *data, size_t len);

/**
 * ng_ipc_recv - Receive a message from the SPSC channel.
 * @chan: IPC channel descriptor
 * @buf: Destination buffer for received payload
 * @max_len: Buffer capacity
 *
 * Uses acquire memory ordering (__ATOMIC_ACQUIRE) and memory fences.
 * Returns bytes copied into buf, or NG_IPC_ERR_EMPTY if no message pending.
 */
int ng_ipc_recv(struct ng_ipc_channel *chan, void *buf, size_t max_len);

/**
 * ng_ipc_channel_destroy - Tear down IPC channel and recycle hardware PKU key.
 * @chan: IPC channel descriptor
 *
 * Unmaps shared memory, revokes shared key from sender and receiver domains via
 * pku_revoke_shared_key(), and frees the hardware key via pkey_free() to ensure
 * multi-threaded tests never exhaust Intel's 16 hardware keys.
 */
void ng_ipc_channel_destroy(struct ng_ipc_channel *chan);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_IPC_H */
