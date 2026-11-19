/*
 * NullGate — Domain Policy Schema Header
 * Defines userspace and eBPF shared security policies, memory limits, and syscall filters.
 */

#ifndef NULLGATE_POLICY_H
#define NULLGATE_POLICY_H

#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NG_POLICY_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define NG_POLICY_INLINE static inline __attribute__((always_inline))
#else
#define NG_POLICY_INLINE static inline
#endif
#endif

/*
 * struct ng_domain_policy:
 * Authoritative security policy for an intra-process domain.
 * Exactly 64 bytes (one hardware cache line) to prevent false sharing and optimize BPF map lookups.
 */
struct ng_domain_policy {
    __u32 domain_id;                /* Offset 0: Domain ID (0 to NG_MAX_DOMAINS - 1) */
    __u32 pku_key;                  /* Offset 4: Hardware PKU key allocated (0 to 15) */
    __u32 policy_flags;             /* Offset 8: NG_POLICY_* bitmask */
    __u32 max_memory_pages;         /* Offset 12: Memory quota in 4KB pages (0 = unlimited) */
    __u64 allowed_syscall_mask[4];   /* Offset 16: 256-bit O(1) syscall whitelist bitmap */
    __u8  domain_name[16];          /* Offset 48: Human-readable domain name (null-terminated) */
};

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct ng_domain_policy) == 64, "ng_domain_policy size must be exactly 64 bytes");
_Static_assert(offsetof(struct ng_domain_policy, domain_id) == 0, "domain_id offset must be 0");
_Static_assert(offsetof(struct ng_domain_policy, pku_key) == 4, "pku_key offset must be 4");
_Static_assert(offsetof(struct ng_domain_policy, policy_flags) == 8, "policy_flags offset must be 8");
_Static_assert(offsetof(struct ng_domain_policy, max_memory_pages) == 12, "max_memory_pages offset must be 12");
_Static_assert(offsetof(struct ng_domain_policy, allowed_syscall_mask) == 16, "allowed_syscall_mask offset must be 16");
_Static_assert(offsetof(struct ng_domain_policy, domain_name) == 48, "domain_name offset must be 48");
#endif

/**
 * ng_policy_allow_syscall - Whitelist a syscall number in the 256-bit bitmap.
 */
NG_POLICY_INLINE void ng_policy_allow_syscall(struct ng_domain_policy *pol, __u32 nr)
{
    if (pol && nr < 256) {
        pol->allowed_syscall_mask[nr / 64] |= (1ULL << (nr % 64));
    }
}

/**
 * ng_policy_is_syscall_allowed - Test if a syscall number is whitelisted in the bitmap.
 * Returns 1 if permitted, 0 if blocked.
 */
NG_POLICY_INLINE int ng_policy_is_syscall_allowed(const struct ng_domain_policy *pol, __u32 nr)
{
    if (pol && nr < 256) {
        return (pol->allowed_syscall_mask[nr / 64] & (1ULL << (nr % 64))) != 0;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_POLICY_H */
