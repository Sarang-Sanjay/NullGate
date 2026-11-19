/*
 * NullGate — Hardware-Isolated Compartment Stack Pool Header
 * High-performance per-thread stack pool with PROT_NONE guard pages and thread cleanup.
 */

#ifndef NULLGATE_STACK_POOL_H
#define NULLGATE_STACK_POOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NG_STACK_DEFAULT_SIZE   (64 * 1024) /* 64KB */
#define NG_STACK_GUARD_SIZE     4096        /* 4KB PROT_NONE guard page */
#define NG_STACK_POOL_MAX_CACHED 16         /* Max cached stacks per thread */

/*
 * struct ng_stack_slot:
 * Descriptor representing a hardware-isolated compartment stack.
 */
struct ng_stack_slot {
    void *raw_base;             /* Base address of the mmap allocation */
    size_t total_size;          /* Total size in bytes (usable + guard page) */
    void *usable_base;          /* raw_base + NG_STACK_GUARD_SIZE */
    size_t usable_size;         /* Usable bytes available for compartment stack */
    void *stack_top;            /* 16-byte aligned downward-growing stack pointer */
    int pkey;                   /* Hardware PKU key assigned to usable region */
    uint32_t domain_id;         /* Compartment domain ID */
    bool in_use;                /* Allocation state */
    struct ng_stack_slot *next; /* Next pointer in free list */
};

/**
 * ng_stack_pool_init - Initialize stack pool subsystem and register pthread destructor.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int ng_stack_pool_init(void);

/**
 * ng_stack_pool_acquire - Checkout an isolated compartment stack.
 * @domain_id: Target compartment domain ID
 * @pkey: Hardware PKU protection key
 * @desired_size: Desired usable stack size in bytes (or 0 for default 64KB)
 *
 * Checks thread-local cache first (O(1)). If cache empty, allocates via mmap,
 * sets bottom page to PROT_NONE, and tags usable pages under pkey.
 *
 * Returns pointer to stack slot on success, or NULL on allocation failure.
 */
struct ng_stack_slot *ng_stack_pool_acquire(uint32_t domain_id, int pkey, size_t desired_size);

/**
 * ng_stack_pool_release - Return an isolated stack slot to the pool for reuse.
 * @slot: Stack slot to release
 */
void ng_stack_pool_release(struct ng_stack_slot *slot);

/**
 * ng_stack_pool_thread_cleanup - Destroy all thread-local cached stacks.
 *
 * Automatically called via pthread_key destructor upon thread termination.
 */
void ng_stack_pool_thread_cleanup(void);

/**
 * ng_stack_pool_destroy - Clean up all resources allocated by the stack pool subsystem.
 */
void ng_stack_pool_destroy(void);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_STACK_POOL_H */
