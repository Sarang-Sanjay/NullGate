/*
 * NullGate — Cryptographic Attestation & Audit Implementation
 * Consumes, verifies, and logs tamper-evident audit events from the BPF LSM ring buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include "attestation.h"

#define SEQ_TRACKER_SLOTS 512

struct ng_seq_entry {
    uint32_t pid;
    uint32_t tgid;
    uint64_t last_seq;
    bool active;
};

static struct ng_seq_entry g_seq_tracker[SEQ_TRACKER_SLOTS];
static uint8_t g_running_hash_chain[32] = {0};
static uint64_t g_total_events_processed = 0;

static struct ng_seq_entry *get_seq_entry(uint32_t pid, uint32_t tgid)
{
    uint32_t hash = (pid ^ (tgid << 5) ^ (tgid >> 2)) % SEQ_TRACKER_SLOTS;
    for (int i = 0; i < SEQ_TRACKER_SLOTS; i++) {
        uint32_t idx = (hash + i) % SEQ_TRACKER_SLOTS;
        if (g_seq_tracker[idx].active && g_seq_tracker[idx].pid == pid && g_seq_tracker[idx].tgid == tgid) {
            return &g_seq_tracker[idx];
        }
    }
    for (int i = 0; i < SEQ_TRACKER_SLOTS; i++) {
        uint32_t idx = (hash + i) % SEQ_TRACKER_SLOTS;
        if (!g_seq_tracker[idx].active) {
            g_seq_tracker[idx].pid = pid;
            g_seq_tracker[idx].tgid = tgid;
            g_seq_tracker[idx].last_seq = 0;
            g_seq_tracker[idx].active = true;
            return &g_seq_tracker[idx];
        }
    }
    return &g_seq_tracker[hash];
}

static void update_hash_chain(const struct ng_audit_event *event)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx) {
        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) == 1) {
            EVP_DigestUpdate(mdctx, g_running_hash_chain, sizeof(g_running_hash_chain));
            EVP_DigestUpdate(mdctx, event, offsetof(struct ng_audit_event, sha256_digest));
            unsigned int out_len = 0;
            EVP_DigestFinal_ex(mdctx, g_running_hash_chain, &out_len);
        }
        EVP_MD_CTX_free(mdctx);
    }
}

int ng_daemon_init_attestation(void)
{
    memset(g_seq_tracker, 0, sizeof(g_seq_tracker));
    memset(g_running_hash_chain, 0, sizeof(g_running_hash_chain));
    g_total_events_processed = 0;
    return 0;
}

void ng_daemon_cleanup_attestation(void)
{
    memset(g_seq_tracker, 0, sizeof(g_seq_tracker));
    memset(g_running_hash_chain, 0, sizeof(g_running_hash_chain));
    g_total_events_processed = 0;
}

int ng_daemon_handle_audit_event(void *ctx, void *data, size_t len)
{
    (void)ctx;

    if (!data || len < sizeof(struct ng_audit_event))
        return 0;

    const struct ng_audit_event *event = (const struct ng_audit_event *)data;
    g_total_events_processed++;

    /* Update running cryptographic SHA-256 hash chain (Pillar 9) */
    update_hash_chain(event);

    /* Report kernel ring-buffer dropped events if present */
    if (event->dropped_events > 0) {
        fprintf(stderr, "[AUDIT WARNING] Ring buffer backpressure: %u events dropped by kernel\n",
                (unsigned int)event->dropped_events);
    }

    /* Verify per-task monotonic sequence advancement (Fix LOW-01) */
    struct ng_seq_entry *entry = get_seq_entry(event->pid, event->tgid);
    if (entry->last_seq > 0 && (uint64_t)event->monotonic_seq > entry->last_seq + 1) {
        uint64_t gap = (uint64_t)event->monotonic_seq - (entry->last_seq + 1);
        fprintf(stderr, "[AUDIT WARNING] Monotonic audit sequence gap on PID=%u TGID=%u: %llu events missed (last=%llu, curr=%llu)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned long long)gap,
                (unsigned long long)entry->last_seq,
                (unsigned long long)event->monotonic_seq);
    }
    if ((uint64_t)event->monotonic_seq > entry->last_seq) {
        entry->last_seq = (uint64_t)event->monotonic_seq;
    }

    switch (event->event_type) {
    case NG_EVENT_REGISTER:
        fprintf(stdout, "[AUDIT] Domain registration: PID=%u TGID=%u Domain=%u Seq=%llu\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_VIOLATION:
        fprintf(stderr, "[SECURITY ALERT] Policy violation: PID=%u TGID=%u Domain=%u RetCode=%d Seq=%llu\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (int)event->return_code,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_DOMAIN_ENTER:
        fprintf(stdout, "[AUDIT] Domain enter: PID=%u Domain=%u Seq=%llu\n",
                (unsigned int)event->pid, (unsigned int)event->domain_id,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_DOMAIN_EXIT:
        fprintf(stdout, "[AUDIT] Domain exit: PID=%u Domain=%u Seq=%llu\n",
                (unsigned int)event->pid, (unsigned int)event->domain_id,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_SNOOP_ATTEMPT:
        fprintf(stderr, "[SECURITY ALERT] Anti-snoop violation: PID=%u TGID=%u Domain=%u RetCode=%d Seq=%llu (ptrace/procfs access blocked)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (int)event->return_code,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_BPF_ATTEMPT:
        fprintf(stderr, "[SECURITY ALERT] Self-tamper violation: PID=%u TGID=%u Domain=%u RetCode=%d Seq=%llu (unauthorized bpf/prctl blocked)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (int)event->return_code,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_MMAP_VIOLATION:
        fprintf(stderr, "[SECURITY ALERT] Memory protection violation: PID=%u TGID=%u Domain=%u RetCode=%d Seq=%llu (W^X / state page tampering blocked)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (int)event->return_code,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_FORK_INHERIT:
        fprintf(stdout, "[AUDIT] Task lifecycle inherit: PID=%u TGID=%u Domain=%u Seq=%llu (child task storage context bound)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_URING_ATTEMPT:
        fprintf(stderr, "[SECURITY ALERT] io_uring violation: PID=%u TGID=%u Domain=%u RetCode=%d Seq=%llu (unauthorized io_uring operation blocked)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (int)event->return_code,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_SYSCALL_DENIED:
        fprintf(stderr, "[SECURITY ALERT] Syscall denied: PID=%u TGID=%u Domain=%u RetCode=%d Seq=%llu (unauthorized syscall denied by whitelist policy)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (int)event->return_code,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_DEPUTY_VIOLATION:
        fprintf(stderr, "[SECURITY ALERT] Confused deputy violation: PID=%u TGID=%u Domain=%u RetCode=%d Seq=%llu (pointer into Key 1 trusted state blocked)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (int)event->return_code,
                (unsigned long long)event->monotonic_seq);
        break;

    case NG_EVENT_SIGNAL_RECOVERY:
        fprintf(stdout, "[AUDIT] Signal altstack recovery: PID=%u TGID=%u Domain=%u Seq=%llu (altstack signal transition and PKRU restoration)\n",
                (unsigned int)event->pid, (unsigned int)event->tgid,
                (unsigned int)event->domain_id, (unsigned long long)event->monotonic_seq);
        break;

    default:
        fprintf(stdout, "[AUDIT] Generic event: Type=%u PID=%u TGID=%u Domain=%u Seq=%llu\n",
                (unsigned int)event->event_type, (unsigned int)event->pid,
                (unsigned int)event->tgid, (unsigned int)event->domain_id,
                (unsigned long long)event->monotonic_seq);
        break;
    }

    fflush(stdout);
    fflush(stderr);
    return 0;
}
