/*
 * NullGate — Security Daemon Policy Loader Implementation
 * Dynamically loads and updates domain security policies into the kernel BPF map.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "nullgate.skel.h"
#include "policy_loader.h"

static struct ng_domain_policy g_domain_policies[NG_MAX_DOMAINS];
static struct nullgate_bpf *g_bpf_skel = NULL;
static bool g_policies_initialized = false;

int ng_daemon_init_policies(void)
{
    memset(g_domain_policies, 0, sizeof(g_domain_policies));

    /* Domain 0: Trusted Supervisor / Master Process */
    g_domain_policies[0].domain_id = 0;
    g_domain_policies[0].pku_key = 0;
    g_domain_policies[0].policy_flags = NG_POLICY_INHERIT_FORK;
    g_domain_policies[0].max_memory_pages = 0; /* Unlimited */
    strncpy((char *)g_domain_policies[0].domain_name, "master", sizeof(g_domain_policies[0].domain_name) - 1);
    memset(g_domain_policies[0].allowed_syscall_mask, 0xFF, sizeof(g_domain_policies[0].allowed_syscall_mask));

    /* Domain 1: Default Worker Compartment */
    g_domain_policies[1].domain_id = 1;
    g_domain_policies[1].pku_key = 2;
    g_domain_policies[1].policy_flags = NG_POLICY_STRICT_WX |
                                        NG_POLICY_BLOCK_PTRACE |
                                        NG_POLICY_BLOCK_PROCFS |
                                        NG_POLICY_BLOCK_BPF |
                                        NG_POLICY_INHERIT_FORK;
    g_domain_policies[1].max_memory_pages = 1024; /* 4MB */
    strncpy((char *)g_domain_policies[1].domain_name, "worker", sizeof(g_domain_policies[1].domain_name) - 1);
    memset(g_domain_policies[1].allowed_syscall_mask, 0xFF, sizeof(g_domain_policies[1].allowed_syscall_mask));

    /* Domain 2: Adversarial / Isolated Compartment */
    g_domain_policies[2].domain_id = 2;
    g_domain_policies[2].pku_key = 3;
    g_domain_policies[2].policy_flags = NG_POLICY_STRICT_WX |
                                        NG_POLICY_BLOCK_PTRACE |
                                        NG_POLICY_BLOCK_PROCFS |
                                        NG_POLICY_BLOCK_BPF |
                                        NG_POLICY_INHERIT_FORK;
    g_domain_policies[2].max_memory_pages = 512; /* 2MB */
    strncpy((char *)g_domain_policies[2].domain_name, "isolated", sizeof(g_domain_policies[2].domain_name) - 1);
    memset(g_domain_policies[2].allowed_syscall_mask, 0xFF, sizeof(g_domain_policies[2].allowed_syscall_mask));

    /* Initialize remaining domains (3..15) with strict containment by default */
    for (uint32_t d = 3; d < NG_MAX_DOMAINS; d++) {
        g_domain_policies[d].domain_id = d;
        g_domain_policies[d].pku_key = (d < 16) ? d : 15;
        g_domain_policies[d].policy_flags = NG_POLICY_STRICT_WX |
                                            NG_POLICY_BLOCK_PTRACE |
                                            NG_POLICY_BLOCK_PROCFS |
                                            NG_POLICY_BLOCK_BPF |
                                            NG_POLICY_INHERIT_FORK;
        g_domain_policies[d].max_memory_pages = 256; /* 1MB */
        snprintf((char *)g_domain_policies[d].domain_name, sizeof(g_domain_policies[d].domain_name), "domain_%u", d);
        memset(g_domain_policies[d].allowed_syscall_mask, 0xFF, sizeof(g_domain_policies[d].allowed_syscall_mask));
    }

    g_policies_initialized = true;
    return 0;
}

int ng_daemon_sync_policies(struct nullgate_bpf *skel)
{
    if (!skel || !skel->maps.ng_domain_policy_map)
        return -EINVAL;

    int fd = bpf_map__fd(skel->maps.ng_domain_policy_map);
    if (fd < 0)
        return -EBADF;

    if (!g_policies_initialized) {
        int err = ng_daemon_init_policies();
        if (err < 0)
            return err;
    }

    for (uint32_t d = 0; d < NG_MAX_DOMAINS; d++) {
        if (bpf_map_update_elem(fd, &d, &g_domain_policies[d], BPF_ANY) < 0)
            return -errno;
    }

    return 0;
}

int ng_daemon_set_skeleton(struct nullgate_bpf *skel)
{
    g_bpf_skel = skel;
    if (skel)
        return ng_daemon_sync_policies(skel);
    return 0;
}

int ng_daemon_load_domain_policy_skel(struct nullgate_bpf *skel, uint32_t domain_id, const struct ng_domain_policy *pol)
{
    if (!pol || domain_id >= NG_MAX_DOMAINS)
        return -EINVAL;
    if (pol->domain_id != domain_id)
        return -EINVAL;
    if (pol->pku_key >= 16)
        return -EINVAL;

    g_domain_policies[domain_id] = *pol;

    if (skel) {
        if (!skel->maps.ng_domain_policy_map)
            return -ENODEV;
        int fd = bpf_map__fd(skel->maps.ng_domain_policy_map);
        if (fd < 0)
            return -EBADF;
        if (bpf_map_update_elem(fd, &domain_id, pol, BPF_ANY) < 0)
            return -errno;
    }

    return 0;
}

int ng_daemon_load_domain_policy(uint32_t domain_id, const struct ng_domain_policy *pol)
{
    return ng_daemon_load_domain_policy_skel(g_bpf_skel, domain_id, pol);
}

int ng_daemon_get_cached_policy(uint32_t domain_id, struct ng_domain_policy *out_pol)
{
    if (!out_pol || domain_id >= NG_MAX_DOMAINS)
        return -EINVAL;

    if (!g_policies_initialized) {
        int err = ng_daemon_init_policies();
        if (err < 0)
            return err;
    }

    *out_pol = g_domain_policies[domain_id];
    return 0;
}

void ng_daemon_cleanup_policies(void)
{
    memset(g_domain_policies, 0, sizeof(g_domain_policies));
    g_bpf_skel = NULL;
    g_policies_initialized = false;
}
