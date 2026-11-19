/*
 * NullGate — Cryptographic Attestation & Audit Header
 */

#ifndef NULLGATE_ATTESTATION_H
#define NULLGATE_ATTESTATION_H

#include <stdint.h>
#include <stddef.h>
#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ng_daemon_init_attestation - Initialize cryptographic attestation state.
 *
 * Prepares HMAC secret keys and sequence counter state for hash-chained
 * tamper-evident audit logging.
 */
int ng_daemon_init_attestation(void);

/**
 * ng_daemon_cleanup_attestation - Tear down attestation state.
 */
void ng_daemon_cleanup_attestation(void);

/**
 * ng_daemon_handle_audit_event - Ring buffer sample callback for audit events.
 * @ctx: Context pointer passed to ring_buffer__new
 * @data: Raw event buffer
 * @len: Event length in bytes
 *
 * Consumes struct ng_audit_event, verifies monotonic sequence numbers,
 * and records events.
 */
int ng_daemon_handle_audit_event(void *ctx, void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_ATTESTATION_H */
