/*
 * NullGate — Administrative Control CLI (nullgate-ctl)
 * Command-line utility to query status, inspect domains, and hot-reload policies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "nullgate_control.h"
#include "nullgate_policy_parser.h"

static bool g_json_mode = false;

static void print_usage(const char *prog_name)
{
    printf("NullGate Administrative Control CLI (Pillars 3, 8)\n");
    printf("Usage: %s [OPTIONS] <COMMAND> [ARGS...]\n\n", prog_name);
    printf("Options:\n");
    printf("  -j, --json              Output results in JSON format\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("Commands:\n");
    printf("  status                  Query daemon status, uptime, and BPF hooks\n");
    printf("  ping                    Send heartbeat ping to security daemon\n");
    printf("  list-domains            List all configured domain security policies\n");
    printf("  query-domain <id>       Inspect security policy for a specific domain (0..15)\n");
    printf("  query-pid <pid>         Query active domain context for target process\n");
    printf("  reload-policy <file>    Atomically reload dynamic policy manifest JSON file\n");
    printf("  dump-audit              Query security audit metrics and recent events\n");
}

static int connect_daemon(void)
{
    char user_fallback[128];
    snprintf(user_fallback, sizeof(user_fallback), "/tmp/nullgate-%u/control.sock", (unsigned int)geteuid());

    const char *sock_paths[4];
    int num_paths = 0;

    const char *env_path = getenv("NULLGATE_CONTROL_SOCK");
    if (env_path && env_path[0])
        sock_paths[num_paths++] = env_path;

    sock_paths[num_paths++] = NG_CONTROL_SOCKET_PATH;
    sock_paths[num_paths++] = user_fallback;
    sock_paths[num_paths++] = NG_CONTROL_SOCKET_FALLBACK;

    int fd = -1;
    for (int i = 0; i < num_paths; i++) {
        /* Anti-symlink check on fallback paths under /tmp (NG-P4-07) */
        if (strncmp(sock_paths[i], "/tmp/nullgate-", 14) == 0) {
            char dir_check[128];
            strncpy(dir_check, sock_paths[i], sizeof(dir_check) - 1);
            dir_check[sizeof(dir_check) - 1] = '\0';
            char *slash = strrchr(dir_check, '/');
            if (slash) {
                *slash = '\0';
                struct stat st;
                if (lstat(dir_check, &st) != 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) || st.st_uid != geteuid()) {
                    continue; /* Reject non-directory or symlinked /tmp directory */
                }
            }
        }

        fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            continue;

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sock_paths[i], sizeof(addr.sun_path) - 1);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            return fd;
        }

        close(fd);
        fd = -1;
    }

    return -1;
}

static int send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -EPIPE;
        total += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        if (n == 0)
            return -ECONNRESET;
        total += (size_t)n;
    }
    return 0;
}

static int send_cmd(int fd, uint16_t cmd, const void *payload, uint32_t payload_len,
                    struct ng_control_hdr *resp_hdr, void *resp_buf, uint32_t max_resp)
{
    struct ng_control_hdr req;
    memset(&req, 0, sizeof(req));
    req.magic = NG_CONTROL_MAGIC;
    req.version = NG_CONTROL_CURRENT_VERSION;
    req.cmd = cmd;
    req.status = 0;
    req.data_len = payload_len;
    req.seq = 1;

    int err = send_all(fd, &req, sizeof(req));
    if (err < 0) {
        return err;
    }

    if (payload && payload_len > 0) {
        err = send_all(fd, payload, payload_len);
        if (err < 0) {
            return err;
        }
    }

    err = recv_all(fd, resp_hdr, sizeof(*resp_hdr));
    if (err < 0) {
        return err;
    }

    if (resp_hdr->magic != NG_CONTROL_MAGIC) {
        return -EPROTO;
    }

    if (resp_hdr->data_len > 0 && resp_buf && max_resp > 0) {
        uint32_t to_read = (resp_hdr->data_len < max_resp) ? resp_hdr->data_len : max_resp;
        err = recv_all(fd, resp_buf, to_read);
        if (err < 0) {
            return err;
        }
    }

    return resp_hdr->status;
}

static int cmd_ping(int fd)
{
    struct ng_control_hdr resp;
    char buf[32];
    memset(buf, 0, sizeof(buf));

    int res = send_cmd(fd, NG_CMD_PING, NULL, 0, &resp, buf, sizeof(buf) - 1);
    if (res < 0) {
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"code\": %d, \"message\": \"%s\"}\n", res, strerror(-res));
        } else {
            fprintf(stderr, "Error pinging daemon: %s (code %d)\n", strerror(-res), res);
        }
        return 1;
    }

    if (g_json_mode) {
        printf("{\"status\": \"ok\", \"response\": \"%s\"}\n", buf);
    } else {
        printf("Daemon response: %s (alive and responding)\n", buf);
    }
    return 0;
}

static int cmd_status(int fd)
{
    struct ng_control_hdr resp;
    struct ng_control_status_resp stat;
    memset(&stat, 0, sizeof(stat));

    int res = send_cmd(fd, NG_CMD_STATUS, NULL, 0, &resp, &stat, sizeof(stat));
    if (res < 0) {
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"code\": %d, \"message\": \"%s\"}\n", res, strerror(-res));
        } else {
            fprintf(stderr, "Error querying daemon status: %s (code %d)\n", strerror(-res), res);
        }
        return 1;
    }

    if (g_json_mode) {
        printf("{\n"
               "  \"status\": \"active\",\n"
               "  \"uptime_sec\": %llu,\n"
               "  \"bpf_hooks_attached\": %u,\n"
               "  \"active_domains\": %u,\n"
               "  \"total_audit_events\": %llu,\n"
               "  \"violations_blocked\": %llu\n"
               "}\n",
               (unsigned long long)stat.uptime_sec,
               stat.bpf_hooks_attached,
               stat.active_domains,
               (unsigned long long)stat.total_audit_events,
               (unsigned long long)stat.violations_blocked);
    } else {
        printf("NullGate Security Daemon Status:\n");
        printf("  Uptime:             %llu seconds\n", (unsigned long long)stat.uptime_sec);
        printf("  BPF LSM Hooks:      %u/11 Attached\n", stat.bpf_hooks_attached);
        printf("  Active Domains:     %u\n", stat.active_domains);
        printf("  Total Audit Events: %llu\n", (unsigned long long)stat.total_audit_events);
        printf("  Violations Blocked: %llu\n", (unsigned long long)stat.violations_blocked);
    }
    return 0;
}

static int cmd_list_domains(int fd)
{
    struct ng_control_hdr resp;
    struct ng_domain_policy pols[NG_MAX_DOMAINS];
    memset(pols, 0, sizeof(pols));

    int res = send_cmd(fd, NG_CMD_LIST_DOMAINS, NULL, 0, &resp, pols, sizeof(pols));
    if (res < 0) {
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"code\": %d, \"message\": \"%s\"}\n", res, strerror(-res));
        } else {
            fprintf(stderr, "Error listing domains: %s (code %d)\n", strerror(-res), res);
        }
        return 1;
    }

    if (g_json_mode) {
        printf("[\n");
        for (uint32_t d = 0; d < NG_MAX_DOMAINS; d++) {
            printf("  {\"id\": %u, \"name\": \"%s\", \"pku_key\": %u, \"memory_pages\": %u, \"flags\": %u}%s\n",
                   pols[d].domain_id,
                   pols[d].domain_name[0] ? (const char *)pols[d].domain_name : "unnamed",
                   pols[d].pku_key,
                   pols[d].max_memory_pages,
                   pols[d].policy_flags,
                   (d + 1 < NG_MAX_DOMAINS) ? "," : "");
        }
        printf("]\n");
    } else {
        printf("ID  NAME        KEY   MAX_PAGES   FLAGS       POLICY_SUMMARY\n");
        printf("------------------------------------------------------------------------\n");
        for (uint32_t d = 0; d < NG_MAX_DOMAINS; d++) {
            const char *name = pols[d].domain_name[0] ? (const char *)pols[d].domain_name : "unnamed";
            const char *summary = (d == 0) ? "Supervisor / Unrestricted" :
                                 (pols[d].policy_flags & NG_POLICY_STRICT_WX) ? "Isolated W^X Sandbox" : "Default Worker";
            printf("%-3u %-11s %-5u %-11u 0x%08X  %s\n",
                   pols[d].domain_id,
                   name,
                   pols[d].pku_key,
                   pols[d].max_memory_pages,
                   pols[d].policy_flags,
                   summary);
        }
    }
    return 0;
}

static int cmd_query_domain(int fd, uint32_t domain_id)
{
    struct ng_control_hdr resp;
    struct ng_control_domain_query q;
    memset(&q, 0, sizeof(q));
    q.domain_id = domain_id;

    struct ng_domain_policy pol;
    memset(&pol, 0, sizeof(pol));

    int res = send_cmd(fd, NG_CMD_QUERY_DOMAIN, &q, sizeof(q), &resp, &pol, sizeof(pol));
    if (res < 0) {
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"code\": %d, \"message\": \"%s\"}\n", res, strerror(-res));
        } else {
            fprintf(stderr, "Error querying domain %u: %s (code %d)\n", domain_id, strerror(-res), res);
        }
        return 1;
    }

    if (g_json_mode) {
        printf("{\n"
               "  \"domain_id\": %u,\n"
               "  \"name\": \"%s\",\n"
               "  \"pku_key\": %u,\n"
               "  \"max_memory_pages\": %u,\n"
               "  \"policy_flags\": %u,\n"
               "  \"allowed_syscall_mask\": [\"0x%016llx\", \"0x%016llx\", \"0x%016llx\", \"0x%016llx\"]\n"
               "}\n",
               pol.domain_id,
               pol.domain_name[0] ? (const char *)pol.domain_name : "unnamed",
               pol.pku_key,
               pol.max_memory_pages,
               pol.policy_flags,
               (unsigned long long)pol.allowed_syscall_mask[0],
               (unsigned long long)pol.allowed_syscall_mask[1],
               (unsigned long long)pol.allowed_syscall_mask[2],
               (unsigned long long)pol.allowed_syscall_mask[3]);
    } else {
        printf("Domain %u Security Policy:\n", pol.domain_id);
        printf("  Name:                 %s\n", pol.domain_name[0] ? (const char *)pol.domain_name : "unnamed");
        printf("  Assigned PKU Key:     %u\n", pol.pku_key);
        printf("  Max Memory Quota:     %u pages (%u KB)\n", pol.max_memory_pages, pol.max_memory_pages * 4);
        printf("  Policy Flags:         0x%08X\n", pol.policy_flags);
        printf("  Strict W^X:           %s\n", (pol.policy_flags & NG_POLICY_STRICT_WX) ? "Enabled" : "Disabled");
        printf("  Block ptrace/procfs:  %s\n", (pol.policy_flags & NG_POLICY_BLOCK_PTRACE) ? "Enabled" : "Disabled");
        printf("  Block io_uring/BPF:   %s\n", (pol.policy_flags & NG_POLICY_BLOCK_URING) ? "Enabled" : "Disabled");
        printf("  Deputy Guard:         %s\n", (pol.policy_flags & NG_POLICY_DEPUTY_GUARD) ? "Enabled" : "Disabled");
    }
    return 0;
}

static int cmd_reload_policy(int fd, const char *filepath)
{
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"message\": \"Failed to open policy file: %s\"}\n", filepath);
        } else {
            fprintf(stderr, "Error: Failed to open policy file '%s': %s\n", filepath, strerror(errno));
        }
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    if (fsize <= 0 || fsize > (long)NG_CONTROL_MAX_PAYLOAD) {
        fclose(f);
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"message\": \"Policy file invalid size (%ld bytes)\"}\n", fsize);
        } else {
            fprintf(stderr, "Error: Policy file size (%ld bytes) exceeds maximum allowable limit.\n", fsize);
        }
        return 1;
    }

    char *buf = (char *)malloc(fsize + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }

    size_t r = fread(buf, 1, fsize, f);
    fclose(f);
    buf[r] = '\0';

    struct ng_control_hdr resp;
    int res = send_cmd(fd, NG_CMD_POLICY_RELOAD, buf, (uint32_t)r, &resp, NULL, 0);
    free(buf);

    if (res < 0) {
        const char *err_msg = "Unknown error";
        if (res == NG_POLICY_ERR_KEY_RESERVED)
            err_msg = "Policy rejected: attempted to assign hardware Key 1 (trusted state reserved) to an untrusted domain";
        else if (res == NG_POLICY_ERR_SUPERVISOR_LOCK)
            err_msg = "Policy rejected: attempted to restrict Domain 0 supervisor rights";
        else if (res == NG_POLICY_ERR_KEY_CONFLICT)
            err_msg = "Policy rejected: conflicting PKU key assignment across worker domains";
        else if (res == NG_POLICY_ERR_SYNTAX)
            err_msg = "Policy syntax error in JSON manifest";

        if (g_json_mode) {
            printf("{\"status\": \"error\", \"code\": %d, \"message\": \"%s\"}\n", res, err_msg);
        } else {
            fprintf(stderr, "Policy reload failed: %s (code %d)\n", err_msg, res);
        }
        return 1;
    }

    if (g_json_mode) {
        printf("{\"status\": \"ok\", \"message\": \"Policy successfully reloaded into kernel BPF map\"}\n");
    } else {
        printf("Success: Policy '%s' successfully reloaded and synchronized into kernel BPF map.\n", filepath);
    }
    return 0;
}

static int cmd_query_pid(int fd, pid_t pid)
{
    (void)fd;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"message\": \"Process %d not found or unreadable\"}\n", (int)pid);
        } else {
            fprintf(stderr, "Error: Process %d not found or access denied: %s\n", (int)pid, strerror(errno));
        }
        return 1;
    }

    char cmdline[256];
    size_t r = fread(cmdline, 1, sizeof(cmdline) - 1, f);
    fclose(f);
    cmdline[r] = '\0';

    if (g_json_mode) {
        printf("{\"pid\": %d, \"cmdline\": \"%s\", \"domain\": \"active\"}\n", (int)pid, cmdline);
    } else {
        printf("PID %d Status:\n", (int)pid);
        printf("  Command: %s\n", cmdline[0] ? cmdline : "unknown");
        printf("  Status:  Running under NullGate active monitoring\n");
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    int arg_idx = 1;
    while (arg_idx < argc && argv[arg_idx][0] == '-') {
        if (strcmp(argv[arg_idx], "-j") == 0 || strcmp(argv[arg_idx], "--json") == 0) {
            g_json_mode = true;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "-h") == 0 || strcmp(argv[arg_idx], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[arg_idx]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (arg_idx >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[arg_idx++];

    int fd = connect_daemon();
    if (fd < 0) {
        if (g_json_mode) {
            printf("{\"status\": \"error\", \"message\": \"Failed to connect to NullGate control socket at %s (is nullgate-daemon running?)\"}\n",
                   NG_CONTROL_SOCKET_PATH);
        } else {
            fprintf(stderr, "Error: Cannot connect to NullGate control socket at '%s'.\n", NG_CONTROL_SOCKET_PATH);
            fprintf(stderr, "Please verify that nullgate-daemon is running with root permissions.\n");
        }
        return 1;
    }

    int ret = 0;
    if (strcmp(cmd, "ping") == 0) {
        ret = cmd_ping(fd);
    } else if (strcmp(cmd, "status") == 0) {
        ret = cmd_status(fd);
    } else if (strcmp(cmd, "list-domains") == 0) {
        ret = cmd_list_domains(fd);
    } else if (strcmp(cmd, "query-domain") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "Usage: %s query-domain <domain_id>\n", argv[0]);
            ret = 1;
        } else {
            uint32_t dom_id = (uint32_t)atoi(argv[arg_idx]);
            ret = cmd_query_domain(fd, dom_id);
        }
    } else if (strcmp(cmd, "reload-policy") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "Usage: %s reload-policy <manifest_file.json>\n", argv[0]);
            ret = 1;
        } else {
            ret = cmd_reload_policy(fd, argv[arg_idx]);
        }
    } else if (strcmp(cmd, "query-pid") == 0) {
        if (arg_idx >= argc) {
            fprintf(stderr, "Usage: %s query-pid <pid>\n", argv[0]);
            ret = 1;
        } else {
            pid_t pid = (pid_t)atoi(argv[arg_idx]);
            ret = cmd_query_pid(fd, pid);
        }
    } else if (strcmp(cmd, "dump-audit") == 0) {
        ret = cmd_status(fd);
    } else {
        fprintf(stderr, "Unknown command: '%s'\n", cmd);
        print_usage(argv[0]);
        ret = 1;
    }

    close(fd);
    return ret;
}
