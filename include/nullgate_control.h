/*
 * NullGate — Security Daemon Control Socket Protocol Header
 * Defines the Unix domain control socket protocol, framing, command opcodes, and structures.
 */

#ifndef NULLGATE_CONTROL_H
#define NULLGATE_CONTROL_H

#include <stdint.h>
#include <stddef.h>

#include "nullgate_abi.h"
#include "nullgate_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Magic & Protocol Versioning */
#define NG_CONTROL_MAGIC            0x4E474354U /* 'NGCT' */
#define NG_CONTROL_VERSION_1        1U
#define NG_CONTROL_CURRENT_VERSION  NG_CONTROL_VERSION_1

/* Socket Paths */
#define NG_CONTROL_SOCKET_PATH      "/run/nullgate/control.sock"
#define NG_CONTROL_SOCKET_FALLBACK  "/tmp/nullgate_control.sock"
#define NG_CONTROL_MAX_PAYLOAD      (128 * 1024) /* 128KB max payload */

/* Control Command Opcodes */
enum ng_control_cmd {
    NG_CMD_PING             = 1, /* Heartbeat ping/pong */
    NG_CMD_STATUS           = 2, /* Daemon health and metrics */
    NG_CMD_POLICY_RELOAD    = 3, /* Zero-downtime policy reload (JSON manifest payload) */
    NG_CMD_DUMP_AUDIT       = 4, /* Dump recent security audit events */
    NG_CMD_QUERY_DOMAIN     = 5, /* Query specific domain policy */
    NG_CMD_LIST_DOMAINS     = 6, /* List all configured domain policies */
    NG_CMD_QUERY_PID        = 7  /* Query live domain for a given PID */
};

/*
 * struct ng_control_hdr:
 * 64-byte fixed framing header for all requests and responses over the control socket.
 */
struct ng_control_hdr {
    uint32_t magic;         /* Offset 0:  NG_CONTROL_MAGIC */
    uint16_t version;       /* Offset 4:  NG_CONTROL_CURRENT_VERSION */
    uint16_t cmd;           /* Offset 6:  enum ng_control_cmd */
    int32_t  status;        /* Offset 8:  0 on success, negative error code on failure */
    uint32_t data_len;      /* Offset 12: Byte length of following payload data */
    uint64_t seq;           /* Offset 16: Client sequence number (echoed in response) */
    uint8_t  reserved[40];  /* Offset 24: Reserved for future expansion (padded to 64 bytes) */
};

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct ng_control_hdr) == 64, "ng_control_hdr must be exactly 64 bytes");
_Static_assert(offsetof(struct ng_control_hdr, magic) == 0, "magic offset must be 0");
_Static_assert(offsetof(struct ng_control_hdr, version) == 4, "version offset must be 4");
_Static_assert(offsetof(struct ng_control_hdr, cmd) == 6, "cmd offset must be 6");
_Static_assert(offsetof(struct ng_control_hdr, status) == 8, "status offset must be 8");
_Static_assert(offsetof(struct ng_control_hdr, data_len) == 12, "data_len offset must be 12");
_Static_assert(offsetof(struct ng_control_hdr, seq) == 16, "seq offset must be 16");
_Static_assert(offsetof(struct ng_control_hdr, reserved) == 24, "reserved offset must be 24");
#endif

/*
 * struct ng_control_status_resp:
 * Response payload structure for NG_CMD_STATUS.
 */
struct ng_control_status_resp {
    uint64_t uptime_sec;
    uint32_t bpf_hooks_attached;
    uint32_t active_domains;
    uint64_t total_audit_events;
    uint64_t violations_blocked;
    uint8_t  reserved[32];
};

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct ng_control_status_resp) == 64, "ng_control_status_resp must be exactly 64 bytes");
#endif

/*
 * struct ng_control_domain_query:
 * Request payload for NG_CMD_QUERY_DOMAIN.
 */
struct ng_control_domain_query {
    uint32_t domain_id;
    uint8_t  reserved[28];
};

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct ng_control_domain_query) == 32, "ng_control_domain_query must be exactly 32 bytes");
#endif

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_CONTROL_H */
