/*
 * NullGate — Dynamic Domain Policy Manifest Parser Header
 * Defines the policy manifest schema, versioning, parser API, and safety invariants.
 */

#ifndef NULLGATE_POLICY_PARSER_H
#define NULLGATE_POLICY_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "nullgate_abi.h"
#include "nullgate_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Policy Manifest Magic and Versioning */
#define NG_POLICY_MAGIC             0x4E47504FU /* 'NGPO' */
#define NG_POLICY_VERSION_1         1U
#define NG_POLICY_CURRENT_VERSION   NG_POLICY_VERSION_1

/* Maximum Manifest File and Buffer Bounds */
#define NG_POLICY_MAX_JSON_SIZE     (64 * 1024) /* 64KB */

/* Policy Parser Status and Error Codes */
enum ng_policy_status {
    NG_POLICY_OK                    =  0,
    NG_POLICY_ERR_INVALID           = -1, /* Invalid NULL pointer or zero length */
    NG_POLICY_ERR_SYNTAX            = -2, /* JSON syntax error or unexpected token */
    NG_POLICY_ERR_KEY_RESERVED      = -3, /* Policy assigned reserved Key 1 to untrusted domain */
    NG_POLICY_ERR_KEY_CONFLICT      = -4, /* Conflicting PKU keys across distinct worker domains */
    NG_POLICY_ERR_DOMAIN_BOUNDS     = -5, /* Domain ID out of range [0, NG_MAX_DOMAINS - 1] */
    NG_POLICY_ERR_SUPERVISOR_LOCK   = -6, /* Attempted to restrict Domain 0 supervisor rights */
    NG_POLICY_ERR_OVERFLOW          = -7, /* Value overflow (memory pages or syscall nr >= 256) */
    NG_POLICY_ERR_IO                = -8, /* File access or read error */
    NG_POLICY_ERR_NOMEM             = -9  /* Buffer too small for JSON export */
};

/*
 * struct ng_policy_manifest:
 * In-memory representation of a complete NullGate policy configuration.
 * Contains domain policies for up to NG_MAX_DOMAINS (16) domains.
 * Exact binary layout: 1040 bytes (16-byte header + 16 * 64-byte domain policies).
 */
struct ng_policy_manifest {
    uint32_t magic;                                     /* Offset 0: NG_POLICY_MAGIC */
    uint32_t version;                                   /* Offset 4: NG_POLICY_CURRENT_VERSION */
    uint32_t num_domains;                               /* Offset 8: Number of configured domains */
    uint32_t flags;                                     /* Offset 12: Manifest global flags */
    struct ng_domain_policy domains[NG_MAX_DOMAINS];    /* Offset 16: Array of domain policies (1024 bytes) */
};

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct ng_policy_manifest) == 1040, "ng_policy_manifest size must be exactly 1040 bytes");
_Static_assert(offsetof(struct ng_policy_manifest, magic) == 0, "magic offset must be 0");
_Static_assert(offsetof(struct ng_policy_manifest, version) == 4, "version offset must be 4");
_Static_assert(offsetof(struct ng_policy_manifest, num_domains) == 8, "num_domains offset must be 8");
_Static_assert(offsetof(struct ng_policy_manifest, flags) == 12, "flags offset must be 12");
_Static_assert(offsetof(struct ng_policy_manifest, domains) == 16, "domains offset must be 16");
#endif

/**
 * ng_policy_manifest_init - Initialize a policy manifest structure with safe defaults.
 * @manifest: Pointer to manifest structure
 *
 * Configures Domain 0 as unrestricted supervisor and domains 1..15 as strict workers.
 */
void ng_policy_manifest_init(struct ng_policy_manifest *manifest);

/**
 * ng_policy_parse_json - Parse a JSON string into a validated policy manifest.
 * @json_str: Null-terminated or bounded JSON string
 * @json_len: Length of JSON string (or 0 if null-terminated)
 * @manifest: Pointer to output manifest structure
 *
 * Enforces all policy invariants (no Key 1 assignment, Domain 0 unconfined).
 * Returns NG_POLICY_OK on success, or a negative ng_policy_status error code.
 */
int ng_policy_parse_json(const char *json_str, size_t json_len, struct ng_policy_manifest *manifest);

/**
 * ng_policy_parse_file - Load and parse a JSON policy manifest file from disk.
 * @filepath: Filesystem path to the JSON manifest file
 * @manifest: Pointer to output manifest structure
 *
 * Returns NG_POLICY_OK on success, or a negative ng_policy_status error code.
 */
int ng_policy_parse_file(const char *filepath, struct ng_policy_manifest *manifest);

/**
 * ng_policy_validate - Verify policy manifest against all security invariants.
 * @manifest: Pointer to manifest structure to validate
 *
 * Validates:
 *   1. magic == NG_POLICY_MAGIC and version == NG_POLICY_CURRENT_VERSION.
 *   2. Domain 0 is present, pku_key == 0, and all syscalls allowed.
 *   3. No untrusted domain (1..15) is assigned PKU Key 1 (reserved for trusted state).
 *   4. No two active untrusted domains share the same PKU key unless explicitly permitted.
 *
 * Returns NG_POLICY_OK on success, or a negative ng_policy_status error code.
 */
int ng_policy_validate(const struct ng_policy_manifest *manifest);

/**
 * ng_policy_export_json - Serialize a policy manifest into formatted JSON text.
 * @manifest: Pointer to input manifest structure
 * @out_buf: Output buffer for serialized JSON
 * @out_len: Maximum capacity of out_buf
 *
 * Returns number of bytes written, or NG_POLICY_ERR_NOMEM if out_buf is too small.
 */
int ng_policy_export_json(const struct ng_policy_manifest *manifest, char *out_buf, size_t out_len);

/**
 * ng_policy_apply_manifest - Apply a validated policy manifest to the kernel via the daemon.
 * @manifest: Pointer to input manifest structure
 *
 * Atomically updates all configured domain policies in the daemon's cache and BPF map.
 * Returns NG_POLICY_OK on success, or a negative ng_policy_status / errno code.
 */
int ng_policy_apply_manifest(const struct ng_policy_manifest *manifest);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_POLICY_PARSER_H */
