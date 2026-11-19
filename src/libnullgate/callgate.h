/*
 * NullGate — CET-Compliant Atomic Call-Gate Header
 *
 * Declares the single unified assembly call-gate trampoline.
 * Avoids split enter/exit stubs so C code never runs in a half-switched state.
 */

#ifndef NULLGATE_CALLGATE_H
#define NULLGATE_CALLGATE_H

#include <stdint.h>
#include <stddef.h>
#include "nullgate_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ng_callgate_invoke - Atomic low-overhead hardware call-gate transition.
 * @domain_id: Target compartment domain ID
 * @fn: Compartment entry function pointer (uint64_t (*)(void *))
 * @arg: Argument passed to fn in %rdi
 * @stack_top: Top of pre-allocated compartment stack buffer (16-byte aligned)
 * @target_pkru: Precomputed PKRU mask with rights restricted to target domain
 * @tstate: Pointer to struct ng_trusted_state (protected by PKU Key 1)
 *
 * System V AMD64 ABI Register Mapping:
 *   %rdi  = domain_id
 *   %rsi  = fn
 *   %rdx  = arg
 *   %rcx  = stack_top
 *   %r8d  = target_pkru
 *   %r9   = tstate
 *
 * Transition Invariants:
 *   1. Hardware IBT: Begins with ENDBR64.
 *   2. Registers: Pushes caller callee-saved registers (%rbx, %rbp, %r12-%r15) to trusted stack.
 *   3. Pointers: Preserves %r9 (tstate) in callee-saved %r12 across target function dispatch.
 *   4. Stack: Saves %rsp to tstate->trusted_rsp; switches %rsp to stack_top with 'andq $-16, %rsp'.
 *   5. WRPKRU: Clears %ecx, %edx, loads target_pkru into %eax, executes wrpkru + lfence.
 *   6. Dispatch: Moves arg to %rdi, calls *fn.
 *   7. Return Value: Preserves 64-bit %rax in %r10 across exit wrpkru sequence.
 *   8. Privilege Restoration: Restores trusted PKRU (0x0) + lfence FIRST before reading tstate.
 *   9. Stack Restoration: Restores trusted %rsp from 0(%r12), pops callee-saved registers.
 *  10. Shadow Stack: Returns with RET, validated cleanly by Intel CET user_shstk.
 *
 * Returns: 64-bit return value from fn.
 */
uint64_t ng_callgate_invoke(uint32_t domain_id,
                            uint64_t (*fn)(void *),
                            void *arg,
                            void *stack_top,
                            uint32_t target_pkru,
                            struct ng_trusted_state *tstate);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_CALLGATE_H */
