/*
 * NullGate — Userspace Memory Protection Keys (PKU) Subsystem Header
 *
 * CRITICAL PILLAR 4 GADGET HYGIENE INVARIANT:
 * This header and C translation units intentionally DO NOT define or declare
 * pku_write_pkru(). Zero WRPKRU (0F 01 EF) opcodes may exist in compiled C units.
 * All WRPKRU instructions are strictly quarantined to callgate.S in
 * .section .text.nullgate_callgate.
 */

#ifndef NULLGATE_PKU_H
#define NULLGATE_PKU_H

#include <stdint.h>
#include <stddef.h>
#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PKRU Bitmask Bit Definitions:
 * Each PKU hardware key k (0..15) occupies 2 bits in the 32-bit PKRU register:
 *   - Bit 2*k     : Access Disable (AD) - Blocks both reads and writes
 *   - Bit 2*k + 1 : Write Disable (WD)  - Blocks writes only
 */
#define PKRU_AD_BIT(key)            (2U * (unsigned int)(key))
#define PKRU_WD_BIT(key)            (2U * (unsigned int)(key) + 1U)

#define PKRU_AD(key)                (1U << PKRU_AD_BIT(key))
#define PKRU_WD(key)                (1U << PKRU_WD_BIT(key))
#define PKRU_DISABLE_ALL(key)       (PKRU_AD(key) | PKRU_WD(key))

/* Predefined keys */
#define NG_PKEY_DEFAULT             0   /* OS and default library allocations */
#define NG_PKEY_TRUSTED_STATE       1   /* Reserved for struct ng_trusted_state */

/**
 * pku_init - Detect CPU hardware and kernel PKU support via CPUID and test allocation.
 *
 * Verifies that CPUID.(EAX=7, ECX=0):ECX has both Bit 3 (PKU) and Bit 4 (OSPKE) set.
 * Pre-allocates Key 1 for trusted runtime state protection.
 *
 * Returns 0 on success, or a negative NG_ERR_* error code.
 */
int pku_init(void);

/**
 * pku_get_trusted_key - Return the hardware protection key assigned to Key 1 (trusted state).
 */
int pku_get_trusted_key(void);

/**
 * pku_alloc_domain_key - Allocate a hardware protection key for a compartment domain.
 * @domain_id: Domain identifier (1 .. NG_MAX_DOMAINS - 1)
 *
 * Calls pkey_alloc(0, 0) and maps the key to the domain.
 *
 * Returns assigned hardware key (>= 0), or negative on error.
 */
int pku_alloc_domain_key(uint32_t domain_id);

/**
 * pku_get_xsave_pkru_offset - Return the XSAVE byte offset for state component 9 (PKRU).
 */
int pku_get_xsave_pkru_offset(void);

/**
 * pku_get_domain_key - Query the hardware key assigned to a domain.
 * @domain_id: Domain identifier
 *
 * Returns hardware key (>= 0), or negative if unassigned.
 */
int pku_get_domain_key(uint32_t domain_id);

/**
 * pku_read_pkru - Read current thread PKRU register using inline RDPKRU.
 *
 * Safe userspace read instruction (0F 01 EE).
 */
uint32_t pku_read_pkru(void);

/**
 * pku_build_pkru_mask - Compute 32-bit PKRU value for a given active domain.
 * @active_domain: Target domain to activate
 *
 * Computes a mask where:
 * - Key 0 (default memory) is accessible (AD=0, WD=0).
 * - Key 1 (trusted state) is accessible ONLY if active_domain == NG_DOMAIN_TRUSTED.
 * - Key for active_domain is accessible (AD=0, WD=0).
 * - All other compartment keys are completely disabled (AD=1, WD=1).
 */
uint32_t pku_build_pkru_mask(uint32_t active_domain);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_PKU_H */
