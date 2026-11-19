/*
 * NullGate — Hardware-Isolated Compartment Stack Pool Implementation
 * Provides high-performance per-thread stack caching with PROT_NONE guard pages and thread cleanup.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "nullgate_stack_pool.h"
#include "pku.h"

struct thread_stack_pool {
    struct ng_stack_slot *slots[NG_STACK_POOL_MAX_CACHED];
    size_t count;
    struct ng_stack_slot *all_slots; /* Singly-linked list tracking all allocated slots */
};

static pthread_key_t g_pool_key;
static pthread_once_t g_pool_once = PTHREAD_ONCE_INIT;
static bool g_pool_initialized = false;

static __thread struct thread_stack_pool *t_pool = NULL;

static void thread_destructor(void *arg)
{
    struct thread_stack_pool *pool = (struct thread_stack_pool *)arg;
    if (!pool)
        return;

    /* Cleanly unmap and free every slot allocated by this thread */
    struct ng_stack_slot *curr = pool->all_slots;
    while (curr) {
        struct ng_stack_slot *next = curr->next;
        if (curr->raw_base && curr->total_size > 0) {
            (void)munmap(curr->raw_base, curr->total_size);
        }
        free(curr);
        curr = next;
    }

    free(pool);
    t_pool = NULL;
}

static void make_pool_key(void)
{
    (void)pthread_key_create(&g_pool_key, thread_destructor);
    g_pool_initialized = true;
}

int ng_stack_pool_init(void)
{
    (void)pthread_once(&g_pool_once, make_pool_key);
    return g_pool_initialized ? 0 : -errno;
}

static struct thread_stack_pool *get_or_create_thread_pool(void)
{
    if (__builtin_expect(t_pool != NULL, 1)) {
        return t_pool;
    }

    (void)ng_stack_pool_init();

    t_pool = (struct thread_stack_pool *)calloc(1, sizeof(*t_pool));
    if (!t_pool)
        return NULL;

    (void)pthread_setspecific(g_pool_key, t_pool);
    return t_pool;
}

struct ng_stack_slot *ng_stack_pool_acquire(uint32_t domain_id, int pkey, size_t desired_size)
{
    struct thread_stack_pool *pool = get_or_create_thread_pool();
    if (!pool)
        return NULL;

    if (desired_size == 0)
        desired_size = NG_STACK_DEFAULT_SIZE;

    /* Align desired usable stack size up to 4096-byte page boundary */
    desired_size = (desired_size + 0xFFFULL) & ~0xFFFULL;

    /* Check thread-local cache for available matching stack (O(1)) */
    for (size_t i = 0; i < pool->count; i++) {
        struct ng_stack_slot *slot = pool->slots[i];
        if (!slot->in_use && slot->usable_size >= desired_size) {
            /* If hardware key changed, update protection */
            if (slot->pkey != pkey && pkey >= 0) {
                if (pkey_mprotect(slot->usable_base, slot->usable_size,
                                  PROT_READ | PROT_WRITE, pkey) != 0) {
                    continue; /* Key update failed, try next or allocate new */
                }
                slot->pkey = pkey;
            }

            /* Zero stack buffer to prevent cross-domain information disclosure (NG-P4-08) */
            memset(slot->usable_base, 0, slot->usable_size);
            __asm__ volatile("" : : "r"(slot->usable_base) : "memory");

            slot->domain_id = domain_id;
            slot->in_use = true;
            return slot;
        }
    }

    /* No cached stack available; allocate new memory range */
    size_t total_size = desired_size + NG_STACK_GUARD_SIZE;
    void *raw = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (raw == MAP_FAILED)
        return NULL;

    /* Guard Page Enforcement: bottom 4096-byte page marked PROT_NONE to trap overflows */
    if (mprotect(raw, NG_STACK_GUARD_SIZE, PROT_NONE) != 0) {
        (void)munmap(raw, total_size);
        return NULL;
    }

    void *usable = (char *)raw + NG_STACK_GUARD_SIZE;

    /* Hardware PKU Key Isolation: protect usable stack pages under domain pkey */
    if (pkey > 0) {
        if (pkey_mprotect(usable, desired_size, PROT_READ | PROT_WRITE, pkey) != 0) {
            (void)munmap(raw, total_size);
            return NULL;
        }
    }

    struct ng_stack_slot *slot = (struct ng_stack_slot *)calloc(1, sizeof(*slot));
    if (!slot) {
        (void)munmap(raw, total_size);
        return NULL;
    }

    slot->raw_base = raw;
    slot->total_size = total_size;
    slot->usable_base = usable;
    slot->usable_size = desired_size;
    /* 16-byte stack top alignment per System V AMD64 ABI */
    slot->stack_top = (void *)(((uintptr_t)raw + total_size) & ~0xFULL);
    slot->pkey = pkey;
    slot->domain_id = domain_id;
    slot->in_use = true;

    slot->next = pool->all_slots;
    pool->all_slots = slot;

    /* Cache slot in thread pool if capacity permits */
    if (pool->count < NG_STACK_POOL_MAX_CACHED) {
        pool->slots[pool->count++] = slot;
    }

    return slot;
}

void ng_stack_pool_release(struct ng_stack_slot *slot)
{
    if (slot) {
        slot->in_use = false;
    }
}

void ng_stack_pool_thread_cleanup(void)
{
    if (!t_pool)
        return;

    thread_destructor(t_pool);
    t_pool = NULL;
    (void)pthread_setspecific(g_pool_key, NULL);
}

void ng_stack_pool_destroy(void)
{
    ng_stack_pool_thread_cleanup();
}
