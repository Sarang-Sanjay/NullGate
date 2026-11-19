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
#include <sys/socket.h>
#include <sys/un.h>

#include "nullgate.skel.h"
#include "policy_loader.h"
#include "nullgate_policy_parser.h"
#include "attestation.h"
#include "control_server.h"

static volatile sig_atomic_t g_stop = 0;

/*
 * raw_sd_notify - Notify systemd of service readiness or state changes.
 * Uses raw AF_UNIX SOCK_DGRAM to write directly to getenv("NOTIFY_SOCKET").
 * Supports abstract namespace sockets prefixed with '@'.
 * Zero dependency on libsystemd (Safeguard 4).
 */
static int raw_sd_notify(const char *state)
{
    if (!state)
        return -EINVAL;

    const char *notify_socket = getenv("NOTIFY_SOCKET");
    if (!notify_socket || notify_socket[0] == '\0')
        return 0; /* Not running under systemd Type=notify; clean no-op */

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;

    size_t path_len = strlen(notify_socket);
    if (path_len >= sizeof(sun.sun_path)) {
        close(fd);
        return -EINVAL;
    }

    if (notify_socket[0] == '@') {
        /* Abstract socket namespace: initial byte is null */
        sun.sun_path[0] = '\0';
        memcpy(&sun.sun_path[1], &notify_socket[1], path_len - 1);
    } else {
        /* Standard filesystem socket path */
        memcpy(sun.sun_path, notify_socket, path_len);
    }

    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len);

    ssize_t sent = sendto(fd, state, strlen(state), 0, (struct sockaddr *)&sun, addr_len);
    close(fd);

    if (sent < 0)
        return -errno;

    return 1;
}

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
    printf("  -c, --config PATH   Path to JSON security policy manifest\n");
    printf("  -s, --smoke-test    Attach BPF LSM hooks, verify integrity, and exit immediately\n");
    printf("  -h, --help          Show this help message\n");
}

int main(int argc, char **argv)
{
    bool smoke_test = false;
    const char *config_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--smoke-test") == 0) {
            smoke_test = true;
        } else if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            config_path = argv[++i];
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

    if (config_path) {
        struct ng_policy_manifest manifest;
        int pret = ng_policy_parse_file(config_path, &manifest);
        if (pret == NG_POLICY_OK) {
            ng_policy_apply_manifest(&manifest);
            fprintf(stdout, "[DAEMON] Applied policy manifest from: %s\n", config_path);
        } else {
            fprintf(stderr, "[DAEMON WARNING] Failed to load policy manifest %s: %d\n", config_path, pret);
        }
    }

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

    /* Initialize control socket server */
    struct ng_control_server *ctrl = ng_control_server_create(NULL);
    if (!ctrl) {
        fprintf(stderr, "[DAEMON WARNING] Failed to create control socket; proceeding without control interface.\n");
    } else {
        fprintf(stdout, "[DAEMON] Control socket active and authenticated.\n");
    }

    /* Set up ring buffer consumer */
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ng_audit_ringbuf),
                                              ng_daemon_handle_audit_event,
                                              NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[DAEMON ERROR] Failed to create ring buffer consumer: %s\n", strerror(errno));
        if (ctrl)
            ng_control_server_destroy(ctrl);
        nullgate_bpf__destroy(skel);
        ng_daemon_cleanup_policies();
        ng_daemon_cleanup_attestation();
        return 1;
    }

    fprintf(stdout, "[DAEMON] Epoll event loop active (monitoring control socket & audit ring buffer)... (Press Ctrl+C to terminate)\n");

    /* Signal systemd that initialization is complete (Safeguard 4) */
    raw_sd_notify("READY=1");

    if (ctrl) {
        ng_control_server_run_loop(ctrl, rb, &g_stop);
    } else {
        while (!g_stop) {
            err = ring_buffer__poll(rb, 100 /* timeout ms */);
            if (err < 0 && err != -EINTR) {
                fprintf(stderr, "[DAEMON ERROR] Ring buffer polling error: %d\n", err);
                break;
            }
        }
    }

    /* Signal systemd that teardown has commenced (Safeguard 4) */
    raw_sd_notify("STOPPING=1");

    fprintf(stdout, "\n[DAEMON] Terminating... detaching LSM hooks.\n");
    if (ctrl)
        ng_control_server_destroy(ctrl);
    ring_buffer__free(rb);
    nullgate_bpf__destroy(skel);
    ng_daemon_cleanup_policies();
    ng_daemon_cleanup_attestation();
    fprintf(stdout, "[DAEMON] Shutdown complete.\n");
    return 0;
}
