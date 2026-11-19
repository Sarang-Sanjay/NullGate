/*
 * NullGate — Adversarial Compartment Assembly Payloads
 */

#include "nullgate_cet.h"

NG_EMIT_GNU_PROPERTY_NOTE

.section .text.adversarial, "ax", @progbits

/*
 * Adversarial payload: Intentionally clobbers callee-saved %r12
 * without saving or restoring it.
 */
.globl malicious_clobber_r12
.type malicious_clobber_r12, @function
malicious_clobber_r12:
    NG_ENDBR64
    xorq    %r12, %r12
    movq    $0x9999, %rax
    ret
.size malicious_clobber_r12, . - malicious_clobber_r12

/*
 * Adversarial payload: Intentionally clobbers all callee-saved registers
 * (%rbx, %rbp, %r12, %r13, %r14, %r15).
 */
.globl malicious_clobber_all_callee
.type malicious_clobber_all_callee, @function
malicious_clobber_all_callee:
    NG_ENDBR64
    xorq    %rbx, %rbx
    xorq    %rbp, %rbp
    xorq    %r12, %r12
    xorq    %r13, %r13
    xorq    %r14, %r14
    xorq    %r15, %r15
    movq    $0x8888, %rax
    ret
.size malicious_clobber_all_callee, . - malicious_clobber_all_callee
