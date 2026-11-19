/*
 * NullGate — CET-Safe Atomic Call-Gate Trampoline
 *
 * Implements the atomic hardware domain switch:
 *   - Callee-saved register preservation on trusted stack
 *   - Isolated data stack switch (16-byte aligned)
 *   - WRPKRU privilege drop + LFENCE
 *   - Target dispatch with shadow-stack return tracking
 *   - %rax return value preservation
 *   - WRPKRU privilege restoration + LFENCE
 *   - Trusted stack restoration and clean RET
 */

#include "nullgate_cet.h"

/* Emit ELF GNU Property Note for CET IBT and User Shadow Stack (SHSTK) */
NG_EMIT_GNU_PROPERTY_NOTE

.section .text.nullgate_callgate, "ax", @progbits
.p2align 4, 0x90
.globl ng_callgate_invoke
.type ng_callgate_invoke, @function

ng_callgate_invoke:
    /*
     * 1. Intel CET Indirect Branch Tracking (IBT) Landing Pad
     */
    NG_ENDBR64

    /*
     * 2. Save Caller Callee-Saved Registers onto the Trusted Stack
     */
    pushq   %rbx
    pushq   %rbp
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15

    /*
     * 3. Preserve tstate Pointer in Callee-Saved %r12
     * %r9 contains (struct ng_trusted_state *tstate).
     * Since %r12 is callee-saved, any ABI-compliant function invoked
     * must preserve %r12, allowing reliable access on return.
     */
    movq    %r9, %r12

    /*
     * 4. Save Trusted %rsp and Record Target Domain in Trusted State
     * Offset 0: trusted_rsp (64-bit)
     * Offset 8: current_domain (32-bit)
     */
    movq    %rsp, 0(%r12)
    movl    %edi, 8(%r12)

    /*
     * 5. Switch to Isolated Compartment Data Stack
     * %rcx contains stack_top.
     * Enforce strict 16-byte alignment per AMD64 System V ABI.
     */
    movq    %rcx, %rsp
    andq    $-16, %rsp

    /*
     * 6. Preserve Function Pointer and Argument in Scratch Registers
     * %rsi contains fn.
     * %rdx contains arg.
     */
    movq    %rsi, %r10
    movq    %rdx, %r11

    /*
     * 7. Drop Privileges via Hardware WRPKRU
     * %r8d contains precomputed target domain PKRU mask.
     * WRPKRU requires %ecx=0, %edx=0, and rights mask in %eax.
     * Followed immediately by LFENCE to halt speculative execution.
     */
    movl    %r8d, %eax
    xorl    %ecx, %ecx
    xorl    %edx, %edx
    wrpkru
    lfence

    /*
     * 8. Scratch Register Sanitization (Anti-ASLR Leak):
     * Clear registers that previously held sensitive pointers (stack_top,
     * target_pkru, tstate) to prevent information disclosure to the compartment.
     */
    xorl    %eax, %eax
    xorq    %r8, %r8
    xorq    %r9, %r9
    xorq    %rsi, %rsi

    /*
     * 9. Dispatch Target Function Inside the Compartment
     * Place arg into %rdi and execute indirect call.
     * Hardware User Shadow Stack automatically records return address!
     */
    movq    %r11, %rdi
    xorq    %r11, %r11
    call    *%r10
    xorq    %r10, %r10

    /*
     * 10. Preserve 64-Bit Return Value & Enforce System V Direction Flag
     * Target function returned its result in %rax; preserve in %r10.
     * Execute CLD to guarantee DF=0 (countering malicious STD gadgets).
     */
    movq    %rax, %r10
    cld

    /*
     * 11. Restore Trusted PKRU State (0x0)
     * CRITICAL ORDERING:
     * We MUST restore trusted PKRU rights before attempting to access
     * tstate or read trusted_rsp, because Key 1 is inaccessible while
     * in the untrusted compartment domain.
     */
    xorl    %eax, %eax
    xorl    %ecx, %ecx
    xorl    %edx, %edx
    wrpkru
    lfence

    /*
     * 11. Restore Trusted Stack and Reset Domain Status
     * SECURITY DEFENSE IN DEPTH:
     * We MUST NOT trust %r12 to have been preserved by untrusted compartment code!
     * Load the verified g_trusted_state pointer directly from RIP-relative storage.
     */
    movq    g_trusted_state(%rip), %r12
    movq    0(%r12), %rsp
    movl    $0, 8(%r12)

    /*
     * 12. Restore Target Return Value into %rax
     * Sanitize scratch registers (%r10, %r11) to avoid leaking compartment state.
     */
    movq    %r10, %rax
    xorq    %r10, %r10
    xorq    %r11, %r11

    /*
     * 13. Pop Callee-Saved Registers from Trusted Stack
     */
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbp
    popq    %rbx

    /*
     * 14. Return to Caller
     * Hardware User Shadow Stack (user_shstk) validates return address!
     */
    ret

.size ng_callgate_invoke, . - ng_callgate_invoke
