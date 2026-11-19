/*
 * NullGate — Userspace Memory Protection Keys (PKU) Subsystem
 *
 * CRITICAL PILLAR 4 GADGET HYGIENE INVARIANT:
 * This translation unit strictly implements RDPKRU only.
 * Absolutely zero WRPKRU instructions (opcode 0F 01 EF) exist in this file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <cpuid.h>
#include <pthread.h>
#include <errno.h>

#include "pku.h"
#include "nullgate.h"
#include "nullgate_abi.h"

static int g_domain_keys[NG_MAX_DOMAINS];
static uint16_t g_shared_key_masks[NG_MAX_DOMAINS];
static pthread_mutex_t g_pku_key_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_trusted_key = -1;
static uint32_t g_xsave_pkru_offset = 0;
static bool g_pku_initialized = false;

int pku_get_xsave_pkru_offset(void)
{
    if (g_xsave_pkru_offset == 0) {
        unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
        __cpuid_count(0xd, 9, eax, ebx, ecx, edx);
        g_xsave_pkru_offset = (ebx != 0) ? ebx : 2688;
    }
    return (int)g_xsave_pkru_offset;
}

int pku_init(void)
{
    if (g_pku_initialized)
        return NG_SUCCESS;

    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

    /*
     * Query CPUID.(EAX=7, ECX=0):
     * - ECX Bit 3: PKU hardware support
     * - ECX Bit 4: OSPKE enabled by OS (CR4.PKE)
     */
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return NG_ERR_PKU;
    }

    if (!((ecx >> 3) & 1U)) {
        return NG_ERR_PKU; /* Hardware does not support PKU */
    }

    if (!((ecx >> 4) & 1U)) {
        return NG_ERR_PKU; /* Linux kernel has not enabled OSPKE */
    }

    /* Initialize domain-to-pkey mappings */
    g_domain_keys[NG_DOMAIN_TRUSTED] = NG_PKEY_DEFAULT; /* Domain 0 uses default pkey 0 */
    for (uint32_t i = 1; i < NG_MAX_DOMAINS; i++) {
        g_domain_keys[i] = -1;
    }

    /* Pre-allocate Key 1 exclusively for trusted runtime state (struct ng_trusted_state) */
    int key1 = pkey_alloc(0, 0);
    if (key1 < 0) {
        return NG_ERR_PKU;
    }

    g_trusted_key = key1;
    /*
     * CRITICAL SECURITY ISOLATION:
     * Key 1 is exclusively reserved for g_trusted_state and MUST NOT be assigned
     * to any user domain. User domains allocate distinct hardware keys (Keys 2-15).
     */
    g_pku_initialized = true;
    return NG_SUCCESS;
}

int pku_get_trusted_key(void)
{
    return g_trusted_key;
}

int pku_alloc_domain_key(uint32_t domain_id)
{
    if (!g_pku_initialized) {
        int ret = pku_init();
        if (ret != NG_SUCCESS)
            return ret;
    }

    if (domain_id == NG_DOMAIN_TRUSTED)
        return NG_PKEY_DEFAULT;

    if (domain_id >= NG_MAX_DOMAINS)
        return NG_ERR_INVALID;

    pthread_mutex_lock(&g_pku_key_mutex);
    if (g_domain_keys[domain_id] >= 0) {
        int existing = g_domain_keys[domain_id];
        pthread_mutex_unlock(&g_pku_key_mutex);
        return existing;
    }

    int key = pkey_alloc(0, 0);
    if (key < 0) {
        pthread_mutex_unlock(&g_pku_key_mutex);
        return NG_ERR_PKU;
    }

    g_domain_keys[domain_id] = key;
    pthread_mutex_unlock(&g_pku_key_mutex);
    return key;
}

int pku_get_domain_key(uint32_t domain_id)
{
    if (domain_id == NG_DOMAIN_TRUSTED)
        return NG_PKEY_DEFAULT;

    if (domain_id >= NG_MAX_DOMAINS)
        return NG_ERR_INVALID;

    return g_domain_keys[domain_id];
}

uint32_t pku_read_pkru(void)
{
    unsigned int pkru_val = 0;

    /*
     * RDPKRU: Read Protection Key Rights for User Pages
     * Opcode: 0F 01 EE (distinct from WRPKRU 0F 01 EF)
     * Reads PKRU into EAX:EDX (EDX zeroed on return) with ECX = 0.
     */
    __asm__ volatile (
        "xorl %%ecx, %%ecx\n\t"
        "rdpkru\n\t"
        : "=a" (pkru_val)
        :
        : "ecx", "edx"
    );

    return pkru_val;
}

uint32_t pku_build_pkru_mask(uint32_t active_domain)
{
    /* Start with all compartment keys (1..15) fully disabled (AD=1, WD=1) */
    uint32_t mask = 0;
    for (unsigned int k = 1; k < 16; k++) {
        mask |= PKRU_DISABLE_ALL(k);
    }

    if (active_domain == NG_DOMAIN_TRUSTED) {
        /* In trusted domain: enable access to Key 1 (trusted state) */
        if (g_trusted_key >= 0 && g_trusted_key < 16) {
            mask &= ~PKRU_DISABLE_ALL(g_trusted_key);
        }
    } else {
        /*
         * In untrusted compartment:
         * Key 1 (trusted state) REMAINS DISABLED (AD=1, WD=1).
         * Enable access only to this compartment's assigned key.
         */
        if (active_domain < NG_MAX_DOMAINS) {
            int dkey = g_domain_keys[active_domain];
            if (dkey >= 0 && dkey < 16) {
                mask &= ~PKRU_DISABLE_ALL(dkey);
            }
        }
    }

    /* Unmask any shared keys granted to this domain (e.g. for IPC channels) */
    if (active_domain < NG_MAX_DOMAINS) {
        pthread_mutex_lock(&g_pku_key_mutex);
        uint16_t shared = g_shared_key_masks[active_domain];
        pthread_mutex_unlock(&g_pku_key_mutex);

        for (unsigned int k = 2; k < 16; k++) {
            if ((shared & (1U << k)) && ((int)k != g_trusted_key)) {
                mask &= ~PKRU_DISABLE_ALL(k);
            }
        }
    }

    /* Key 0 (default memory) always remains enabled (bits 0 and 1 are 0) */
    return mask;
}

int pku_grant_shared_key(uint32_t domain_id, int shared_pkey)
{
    if (domain_id >= NG_MAX_DOMAINS)
        return -EINVAL;

    /* Key 1 (trusted runtime state) is strictly forbidden from being shared */
    if (shared_pkey <= 1 || shared_pkey >= 16)
        return -EINVAL;

    if (shared_pkey == g_trusted_key)
        return -EINVAL;

    pthread_mutex_lock(&g_pku_key_mutex);
    g_shared_key_masks[domain_id] |= (uint16_t)(1U << shared_pkey);
    pthread_mutex_unlock(&g_pku_key_mutex);

    ng_domain_refresh_pkru(domain_id);
    return 0;
}

int pku_revoke_shared_key(uint32_t domain_id, int shared_pkey)
{
    if (domain_id >= NG_MAX_DOMAINS)
        return -EINVAL;

    if (shared_pkey <= 1 || shared_pkey >= 16)
        return -EINVAL;

    pthread_mutex_lock(&g_pku_key_mutex);
    g_shared_key_masks[domain_id] &= (uint16_t)~(1U << shared_pkey);
    pthread_mutex_unlock(&g_pku_key_mutex);

    ng_domain_refresh_pkru(domain_id);
    return 0;
}

int pku_free_domain_key(uint32_t domain_id)
{
    if (domain_id == NG_DOMAIN_TRUSTED || domain_id >= NG_MAX_DOMAINS)
        return -EINVAL;

    pthread_mutex_lock(&g_pku_key_mutex);
    int key = g_domain_keys[domain_id];
    if (key > 1 && key < 16) {
        bool in_use = false;
        for (uint32_t d = 1; d < NG_MAX_DOMAINS; d++) {
            if (d != domain_id && g_domain_keys[d] == key) {
                in_use = true;
                break;
            }
        }
        if (!in_use) {
            pkey_free(key);
        }
        g_domain_keys[domain_id] = -1;
    }
    g_shared_key_masks[domain_id] = 0;
    pthread_mutex_unlock(&g_pku_key_mutex);

    ng_domain_refresh_pkru(domain_id);
    return 0;
}
