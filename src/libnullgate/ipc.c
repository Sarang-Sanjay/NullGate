/*
 * NullGate — Hardware Zero-Copy Compartment IPC Implementation
 *
 * CRITICAL PILLAR 4 GADGET HYGIENE INVARIANT:
 * This translation unit strictly implements lock-free SPSC queue logic.
 * Absolutely zero WRPKRU instructions (opcode 0F 01 EF) exist in this file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "nullgate_ipc.h"
#include "nullgate_abi.h"
#include "pku.h"

void *ng_ipc_get_ring_buffer(struct ng_ipc_channel *chan)
{
    return chan ? (void *)chan->ring : NULL;
}

struct ng_ipc_channel *ng_ipc_channel_create(uint32_t sender_dom, uint32_t receiver_dom, size_t num_slots)
{
    /* Ensure PKU subsystem is initialized */
    if (pku_init() != 0) {
        return NULL;
    }

    if (sender_dom >= NG_MAX_DOMAINS || receiver_dom >= NG_MAX_DOMAINS) {
        return NULL;
    }

    /* Slot capacity must be positive, power of 2, and bounded to prevent overflow (NG-P4-10) */
    if (num_slots == 0 || num_slots > (1024U * 1024U) || (num_slots & (num_slots - 1)) != 0) {
        return NULL;
    }

    /* Allocate channel descriptor */
    struct ng_ipc_channel *chan = calloc(1, sizeof(*chan));
    if (!chan) {
        return NULL;
    }

    /* Calculate total memory needed for ring buffer including slots */
    size_t raw_size = sizeof(struct ng_ipc_ring) + num_slots * sizeof(struct ng_ipc_slot);
    size_t page_sz = (size_t)sysconf(_SC_PAGESIZE);
    if (page_sz == 0) {
        page_sz = 4096;
    }
    size_t ring_bytes = (raw_size + page_sz - 1) & ~(page_sz - 1);

    /* Allocate shared anonymous memory pages */
    void *mem = mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        free(chan);
        return NULL;
    }

    /* Allocate dedicated hardware PKU protection key */
    int shared_pkey = pkey_alloc(0, 0);
    if (shared_pkey < 0) {
        munmap(mem, ring_bytes);
        free(chan);
        return NULL;
    }

    /* Grant shared key to sender domain */
    if (pku_grant_shared_key(sender_dom, shared_pkey) != 0) {
        pkey_free(shared_pkey);
        munmap(mem, ring_bytes);
        free(chan);
        return NULL;
    }

    /* Grant shared key to receiver domain if different */
    if (receiver_dom != sender_dom) {
        if (pku_grant_shared_key(receiver_dom, shared_pkey) != 0) {
            pku_revoke_shared_key(sender_dom, shared_pkey);
            pkey_free(shared_pkey);
            munmap(mem, ring_bytes);
            free(chan);
            return NULL;
        }
    }

    /* Protect the shared memory region with the dedicated PKU key */
    if (pkey_mprotect(mem, ring_bytes, PROT_READ | PROT_WRITE, shared_pkey) != 0) {
        pku_revoke_shared_key(sender_dom, shared_pkey);
        if (receiver_dom != sender_dom) {
            pku_revoke_shared_key(receiver_dom, shared_pkey);
        }
        pkey_free(shared_pkey);
        munmap(mem, ring_bytes);
        free(chan);
        return NULL;
    }

    /* Initialize ring structure */
    struct ng_ipc_ring *ring = (struct ng_ipc_ring *)mem;
    memset(ring, 0, sizeof(*ring));
    ring->magic = NG_IPC_MAGIC;
    ring->version = NG_IPC_CURRENT_VERSION;
    ring->capacity = (uint32_t)num_slots;
    ring->sender_domain = sender_dom;
    ring->receiver_domain = receiver_dom;
    ring->shared_pkey = shared_pkey;
    ring->head = 0;
    ring->tail = 0;

    chan->ring = ring;
    chan->ring_bytes = ring_bytes;
    chan->capacity = (uint32_t)num_slots;
    chan->sender_dom = sender_dom;
    chan->receiver_dom = receiver_dom;
    chan->shared_pkey = shared_pkey;

    return chan;
}

int ng_ipc_send(struct ng_ipc_channel *chan, const void *data, size_t len)
{
    if (!chan || !chan->ring || !data) {
        return NG_IPC_ERR_INVALID;
    }

    if (len > NG_IPC_MAX_DATA_PER_SLOT) {
        return NG_IPC_ERR_MSG_TOO_LARGE;
    }

    /* Use private unshared capacity to prevent TOCTOU attack on shared memory */
    uint32_t cap = chan->capacity;
    if (cap == 0) {
        return NG_IPC_ERR_INVALID;
    }

    struct ng_ipc_ring *ring = chan->ring;
    uint64_t head = __atomic_load_n(&ring->head, __ATOMIC_RELAXED);
    uint64_t tail = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);

    if (head - tail >= cap) {
        return NG_IPC_ERR_FULL;
    }

    uint32_t idx = (uint32_t)(head & (cap - 1));
    struct ng_ipc_slot *slot = &ring->slots[idx];

    slot->seq = (uint32_t)head;
    slot->len = (uint32_t)len;
    if (len > 0) {
        memcpy(slot->data, data, len);
    }

    __atomic_store_n(&ring->head, head + 1, __ATOMIC_RELEASE);
    return NG_IPC_OK;
}

int ng_ipc_recv(struct ng_ipc_channel *chan, void *buf, size_t max_len)
{
    if (!chan || !chan->ring || !buf) {
        return NG_IPC_ERR_INVALID;
    }

    /* Use private unshared capacity to prevent TOCTOU attack on shared memory */
    uint32_t cap = chan->capacity;
    if (cap == 0) {
        return NG_IPC_ERR_INVALID;
    }

    struct ng_ipc_ring *ring = chan->ring;
    uint64_t tail = __atomic_load_n(&ring->tail, __ATOMIC_RELAXED);
    uint64_t head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);

    if (tail >= head) {
        return NG_IPC_ERR_EMPTY;
    }

    uint32_t idx = (uint32_t)(tail & (cap - 1));
    struct ng_ipc_slot *slot = &ring->slots[idx];

    /* Clamp copy_len to both NG_IPC_MAX_DATA_PER_SLOT and caller's max_len */
    size_t copy_len = slot->len;
    if (copy_len > NG_IPC_MAX_DATA_PER_SLOT) {
        copy_len = NG_IPC_MAX_DATA_PER_SLOT;
    }
    if (copy_len > max_len) {
        copy_len = max_len;
    }

    if (copy_len > 0) {
        memcpy(buf, slot->data, copy_len);
    }

    __atomic_store_n(&ring->tail, tail + 1, __ATOMIC_RELEASE);
    return (int)copy_len;
}

void ng_ipc_channel_destroy(struct ng_ipc_channel *chan)
{
    if (!chan) {
        return;
    }

    /* Unmap shared ring pages */
    if (chan->ring && chan->ring_bytes > 0) {
        munmap(chan->ring, chan->ring_bytes);
        chan->ring = NULL;
    }

    /*
     * Safeguard 2: Revoke shared key permissions and free hardware PKU key
     * to prevent exhaustion of Intel's 16 hardware keys during multi-threaded tests.
     */
    if (chan->shared_pkey > 1 && chan->shared_pkey < 16) {
        pku_revoke_shared_key(chan->sender_dom, chan->shared_pkey);
        if (chan->receiver_dom != chan->sender_dom) {
            pku_revoke_shared_key(chan->receiver_dom, chan->shared_pkey);
        }
        pkey_free(chan->shared_pkey);
        chan->shared_pkey = -1;
    }

    free(chan);
}
