/*
 * NullGate — Security Daemon Policy Loader Header
 * Declares domain policy structures, dynamic BPF map loading interfaces, and cache management.
 */

#ifndef NULLGATE_POLICY_LOADER_H
#define NULLGATE_POLICY_LOADER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "nullgate_abi.h"
#include "nullgate_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration for BPF skeleton */
struct nullgate_bpf;

/**
 * ng_daemon_init_policies - Initialize security policies for domain compartmentalization.
 * Sets up default in-memory policy tables for Domains 0 (Master), 1 (Worker), and 2 (Isolated).
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int ng_daemon_init_policies(void);

/**
 * ng_daemon_set_skeleton - Bind active BPF skeleton to the policy loader engine.
 * Syncs any pre-configured in-memory domain policies into skel->maps.ng_domain_policy_map.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int ng_daemon_set_skeleton(struct nullgate_bpf *skel);

/**
 * ng_daemon_load_domain_policy - Load or update a security policy for a domain.
 * Updates the in-memory policy table and, if a skeleton is bound, updates
 * skel->maps.ng_domain_policy_map in the kernel.
 *
 * @domain_id: Target domain index (0 to NG_MAX_DOMAINS - 1)
 * @pol: Pointer to authoritative domain policy structure
 *
 * Returns 0 on success, or negative errno on failure (-EINVAL, -EBADF, etc.).
 */
int ng_daemon_load_domain_policy(uint32_t domain_id, const struct ng_domain_policy *pol);

/**
 * ng_daemon_load_domain_policy_skel - Load or update policy directly with explicit skeleton.
 *
 * @skel: Loaded BPF skeleton instance (may be NULL to update cache only)
 * @domain_id: Target domain index (0 to NG_MAX_DOMAINS - 1)
 * @pol: Pointer to authoritative domain policy structure
 *
 * Returns 0 on success, or negative errno on failure.
 */
int ng_daemon_load_domain_policy_skel(struct nullgate_bpf *skel, uint32_t domain_id, const struct ng_domain_policy *pol);

/**
 * ng_daemon_get_cached_policy - Retrieve locally cached policy for a domain.
 *
 * @domain_id: Target domain index
 * @out_pol: Output buffer to store policy
 *
 * Returns 0 on success, or -EINVAL on invalid domain.
 */
int ng_daemon_get_cached_policy(uint32_t domain_id, struct ng_domain_policy *out_pol);

/**
 * ng_daemon_sync_policies - Push all loaded cached policies into kernel BPF map.
 *
 * @skel: Loaded BPF skeleton instance
 *
 * Returns 0 on success, or negative error code on failure.
 */
int ng_daemon_sync_policies(struct nullgate_bpf *skel);

/**
 * ng_daemon_cleanup_policies - Free resources associated with loaded policies.
 */
void ng_daemon_cleanup_policies(void);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_POLICY_LOADER_H */
