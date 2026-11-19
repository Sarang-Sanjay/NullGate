/*
 * NullGate — Security Daemon Main Entrypoint
 * Loads BPF skeleton, syncs domain policies, attaches LSM hooks, and consumes audit ring buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "nullgate.skel.h"
#include "policy_loader.h"
#include "attestation.h"

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -s, --smoke-test    Attach BPF LSM hooks, verify integrity, and exit immediately\n");
    printf("  -h, --help          Show this help message\n");
}

int main(int argc, char **argv)
{
    bool smoke_test = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--smoke-test") == 0) {
            smoke_test = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Bump RLIMIT_MEMLOCK to allow BPF map allocations */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    (void)setrlimit(RLIMIT_MEMLOCK, &rlim);

    /* Set libbpf log callback */
    libbpf_set_print(libbpf_print_fn);

    /* Initialize policies and attestation subsystems */
    if (ng_daemon_init_policies() != 0) {
        fprintf(stderr, "[DAEMON ERROR] Failed to initialize security policies\n");
        return 1;
    }

    if (ng_daemon_init_attestation() != 0) {
        fprintf(stderr, "[DAEMON ERROR] Failed to initialize attestation engine\n");
        ng_daemon_cleanup_policies();
        return 1;
    }

    /* Open and load BPF skeleton */
    struct nullgate_bpf *skel = nullgate_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[DAEMON ERROR] Failed to open and load NullGate BPF skeleton: %s\n", strerror(errno));
        if (geteuid() != 0) {
            fprintf(stderr, "[DAEMON HINT] Loading BPF LSM programs requires root privileges (CAP_BPF + CAP_SYS_ADMIN).\n");
        }
        ng_daemon_cleanup_policies();
        ng_daemon_cleanup_attestation();
        return 1;
    }

    /* Bind skeleton to policy loader engine and synchronize domain policies to BPF map */
    int err = ng_daemon_set_skeleton(skel);
    if (err) {
        fprintf(stderr, "[DAEMON ERROR] Failed to synchronize domain policies to BPF map: %d\n", err);
        nullgate_bpf__destroy(skel);
        ng_daemon_cleanup_policies();
        ng_daemon_cleanup_attestation();
        return 1;
    }
    fprintf(stdout, "[DAEMON] Domain policies successfully synchronized to kernel BPF map.\n");

    /* Attach all 11 Phase 2 LSM hook programs via skeleton */
    err = nullgate_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[DAEMON ERROR] Failed to attach NullGate BPF LSM hooks: %d\n", err);
        nullgate_bpf__destroy(skel);
        ng_daemon_cleanup_policies();
        ng_daemon_cleanup_attestation();
        return 1;
    }

    fprintf(stdout, "[DAEMON] NullGate BPF LSM hooks successfully attached to kernel (all 11 programs active).\n");

    /* If smoke test requested, clean up and exit cleanly */
    if (smoke_test) {
        fprintf(stdout, "[DAEMON] Smoke test successful: BPF LSM hooks active and verified.\n");
        nullgate_bpf__destroy(skel);
        ng_daemon_cleanup_policies();
        ng_daemon_cleanup_attestation();
        return 0;
    }

    /* Register signal handlers for clean teardown */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Set up ring buffer consumer */
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ng_audit_ringbuf),
                                              ng_daemon_handle_audit_event,
                                              NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[DAEMON ERROR] Failed to create ring buffer consumer: %s\n", strerror(errno));
        nullgate_bpf__destroy(skel);
        ng_daemon_cleanup_policies();
        ng_daemon_cleanup_attestation();
        return 1;
    }

    fprintf(stdout, "[DAEMON] Polling security audit ring buffer... (Press Ctrl+C to terminate)\n");

    while (!g_stop) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[DAEMON ERROR] Ring buffer polling error: %d\n", err);
            break;
        }
    }

    fprintf(stdout, "\n[DAEMON] Terminating... detaching LSM hooks.\n");
    ring_buffer__free(rb);
    nullgate_bpf__destroy(skel);
    ng_daemon_cleanup_policies();
    ng_daemon_cleanup_attestation();
    fprintf(stdout, "[DAEMON] Shutdown complete.\n");
    return 0;
}
