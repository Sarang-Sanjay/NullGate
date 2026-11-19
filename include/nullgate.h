/*
 * NullGate — Public Application Programming Interface
 * Intra-process memory isolation and domain compartmentalization.
 */

#ifndef NULLGATE_H
#define NULLGATE_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Status and Error Codes */
#define NG_SUCCESS               0
#define NG_ERR_PKU              -1  /* Hardware PKU/OSPKE unsupported or key allocation failure */
#define NG_ERR_CET              -2  /* Intel CET IBT/SHSTK unsupported or violation detected */
#define NG_ERR_BPF              -3  /* BPF LSM attachment or registration failed */
#define NG_ERR_INVALID          -4  /* Invalid argument or out-of-range domain ID */
#define NG_ERR_LOCKED           -5  /* Domain configuration is locked */
#define NG_ERR_NOMEM            -6  /* Out of memory */
#define NG_ERR_PERM             -7  /* Permission denied by BPF LSM policy */

/* Alternate Signal Stack Configuration */
#define NG_SIGNAL_ALTSTACK_SIZE  65536U

/* Callback type for compartmentalized functions */
typedef uint64_t (*ng_compartment_fn)(void *arg);

/**
 * ng_init - Initialize the NullGate userspace runtime.
 *
 * Verifies CPU hardware features (PKU, CET), allocates and protects the
 * trusted runtime state page with PKU Key 1, and registers with the kernel
 * eBPF LSM via one-shot task_prctl.
 *
 * Returns NG_SUCCESS (0) on success, or a negative NG_ERR_* code on failure.
 */
int ng_init(void);

/**
 * ng_domain_create - Register a new isolated domain with dedicated stack.
 * @domain_id: Domain identifier (1 .. NG_MAX_DOMAINS - 1)
 * @stack_base: Base address of the domain's allocated data stack
 * @stack_size: Size in bytes of the stack buffer
 *
 * Calculates the downward-growing aligned stack top, allocates a hardware
 * PKU protection key, and precomputes the domain PKRU mask.
 *
 * Returns NG_SUCCESS (0) on success, or a negative NG_ERR_* code on failure.
 */
int ng_domain_create(uint32_t domain_id, void *stack_base, size_t stack_size);

/**
 * ng_domain_destroy - Safely tear down an isolated domain and recycle its resources.
 * @domain_id: Target domain identifier (1 .. NG_MAX_DOMAINS - 1)
 *
 * Resets stack protection to default Key 0, recycles hardware PKU keys,
 * and clears the domain descriptor. Fails with NG_ERR_LOCKED if domain is active.
 *
 * Returns NG_SUCCESS (0) on success, or a negative NG_ERR_* code on failure.
 */
int ng_domain_destroy(uint32_t domain_id);

/**
 * ng_domain_protect - Tag a memory range with a domain's PKU key.
 * @domain_id: Target domain ID (0 .. NG_MAX_DOMAINS - 1)
 * @addr: Page-aligned memory address
 * @len: Length of region in bytes (multiple of page size)
 * @prot: Memory protection flags (PROT_READ, PROT_WRITE, etc.)
 *
 * Assigns the domain's hardware pkey to the virtual memory area via pkey_mprotect.
 *
 * Returns NG_SUCCESS (0) on success, or a negative NG_ERR_* code on failure.
 */
int ng_domain_protect(uint32_t domain_id, void *addr, size_t len, int prot);

/**
 * ng_enter - Execute a function inside an isolated domain via CET call-gate.
 * @domain_id: Target compartment domain ID
 * @fn: Function pointer to execute (uint64_t (*)(void *))
 * @arg: Single argument passed to fn
 *
 * Atomically transitions to the compartment:
 * 1. Pushes callee-saved registers to trusted stack.
 * 2. Switches %rsp to domain isolated stack (16-byte aligned).
 * 3. Switches hardware PKRU via WRPKRU + LFENCE.
 * 4. Dispatches target function fn(arg).
 * 5. Restores trusted PKRU and trusted stack upon return.
 *
 * Returns the 64-bit return value from fn.
 */
uint64_t ng_enter(uint32_t domain_id, ng_compartment_fn fn, void *arg);

/**
 * ng_get_active_domain - Return the current active domain ID for the calling thread.
 */
uint32_t ng_get_active_domain(void);

/**
 * ng_signal_register_handler - Register a domain-aware signal handler.
 * @signum: POSIX signal number (e.g. SIGALRM, SIGUSR1)
 * @handler: Signal handler function taking (signum, siginfo, ucontext)
 *
 * Returns NG_SUCCESS (0) on success, or a negative NG_ERR_* code on failure.
 */
int ng_signal_register_handler(int signum, void (*handler)(int, siginfo_t *, void *));

/**
 * ng_signal_get_altstack - Query configured alternate signal stack boundaries.
 * @base: Output pointer to receive altstack base address
 * @size: Output pointer to receive altstack size in bytes
 *
 * Returns NG_SUCCESS (0) on success, or a negative NG_ERR_* code on failure.
 */
int ng_signal_get_altstack(void **base, size_t *size);

/**
 * ng_signal_get_violation_count - Query total hardware PKU memory violations observed.
 */
uint64_t ng_signal_get_violation_count(void);

/**
 * ng_get_trusted_state_addr - Retrieve virtual memory address of Key 1 protected state.
 */
uintptr_t ng_get_trusted_state_addr(void);

/**
 * ng_strerror - Return human-readable string for an error code.
 */
const char *ng_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_H */
