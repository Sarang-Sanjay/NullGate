/*
 * NullGate — Cryptographic Attestation & Audit Implementation
 * Consumes, verifies, and logs tamper-evident audit events from the BPF LSM ring buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "attestation.h"

static uint64_t g_last_seen_seq = 0;
static uint64_t g_total_events_processed = 0;

int ng_daemon_init_attestation(void)
{
    g_last_seen_seq = 0;
    g_total_events_processed = 0;
    return 0;
}

void ng_daemon_cleanup_attestation(void)
{
    g_last_seen_seq = 0;
    g_total_events_processed = 0;
}

int ng_daemon_handle_audit_event(void *ctx, void *data, size_t len)
{
    (void)ctx;

    if (!data || len < sizeof(struct ng_audit_event))
        return 0;

    const struct ng_audit_event *event = (const struct ng_audit_event *)data;
    g_total_events_processed++;

    /* Report kernel ring-buffer dropped events (backpressure) if present */
    if (event->dropped_events > 0) {
        fprintf(stderr, "[AUDIT WARNING] Ring buffer backpressure: %u events dropped by kernel\n",
                (unsigned int)event->dropped_events);
    }

    /* Verify monotonic sequence advancement and detect sequence gaps */
    if (g_last_seen_seq > 0 && (uint64_t)event->monotonic_seq > g_last_seen_seq + 1) {
        uint64_t gap = (uint64_t)event->monotonic_seq - (g_last_seen_seq + 1);
        fprintf(stderr, "[AUDIT WARNING] Monotonic audit sequence gap: %llu sequence numbers missed (last=%llu, curr=%llu)\n",
                (unsigned long long)gap,
                (unsigned long long)g_last_seen_seq,
                (unsigned long long)event->monotonic_seq);
    }
    if ((uint64_t)event->monotonic_seq > g_last_seen_seq) {
        g_last_seen_seq = (uint64_t)event->monotonic_seq;
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
