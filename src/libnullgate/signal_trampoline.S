/*
 * NullGate — CET-Safe Asynchronous Signal Trampoline
 * Pillar 5: Asynchronous Signal Safety & Sigreturn Defense
 *
 * Implements low-level signal interception on dedicated alternate stack:
 *   1. Hardware indirect landing pad (NG_ENDBR64).
 *   2. Argument preservation on alternate stack.
 *   3. Immediate hardware Key 1 restoration via WRPKRU (recovering trusted state).
 *   4. Strict altstack boundary validation (%rsp within [altstack_base, top]).
 *   5. Trusted state handler flag tracking (in_signal_handler).
 *   6. Dispatch to C handler (ng_signal_dispatch).
 *   7. State clearing and clean RET into glibc __restore_rt restorer.
 */

#include "nullgate_cet.h"

/* Emit ELF GNU Property Note for CET IBT and User Shadow Stack (SHSTK) */
NG_EMIT_GNU_PROPERTY_NOTE

.section .text.nullgate_signal, "ax", @progbits
.p2align 4, 0x90
.globl ng_signal_trampoline
.type ng_signal_trampoline, @function

ng_signal_trampoline:
    .cfi_startproc
    /*
     * 1. Intel CET Indirect Branch Tracking (IBT) Landing Pad
     */
    NG_ENDBR64

    /*
     * 2. Preserve incoming signal arguments, callee-saved %r12, and frame pointer on alternate stack
     * %rdi = int signum
     * %rsi = siginfo_t *info
     * %rdx = void *ucontext
     */
    pushq   %rdi
    .cfi_def_cfa_offset 16
    pushq   %rsi
    .cfi_def_cfa_offset 24
    pushq   %rdx
    .cfi_def_cfa_offset 32
    pushq   %r12
    .cfi_def_cfa_offset 40
    .cfi_offset %r12, -40
    pushq   %rbp
    .cfi_def_cfa_offset 48
    .cfi_offset %rbp, -48
    movq    %rsp, %rbp
    .cfi_def_cfa_register %rbp

    /*
     * 3. Critical Signal Entry Invariant:
     * When Linux delivers a signal to an interrupted untrusted compartment,
     * the thread's hardware PKRU has Key 1 (ng_trusted_state) marked Access-Disabled.
     * We MUST immediately clear PKRU to restore full access to Key 1 before
     * dereferencing g_trusted_state.
     * WRPKRU requires %eax = low 32-bits, %edx = high 32-bits (0), %ecx = 0.
     */
    xorl    %eax, %eax
    xorl    %edx, %edx
    xorl    %ecx, %ecx
    wrpkru
    lfence

    /*
     * 4. Load Per-Thread Trusted State Pointer via Initial-Exec TLS
     */
    movq    t_trusted_state@gottpoff(%rip), %r12
    movq    %fs:(%r12), %r12
    testq   %r12, %r12
    jz      .Lfault_trap

    /*
     * 5. Bounds-Check Stack Pointer (%rsp) against Altstack Range
     * Offset 32: altstack_base
     * Offset 40: altstack_size
     */
    movq    32(%r12), %r8               /* altstack_base */
    movq    40(%r12), %r9               /* altstack_size */
    testq   %r8, %r8
    jz      .Lfault_trap
    testq   %r9, %r9
    jz      .Lfault_trap

    addq    %r8, %r9                    /* %r9 = altstack_top */
    cmpq    %r8, %rsp
    jb      .Lfault_trap                /* Fail if %rsp < altstack_base */
    cmpq    %r9, %rsp
    ja      .Lfault_trap                /* Fail if %rsp > altstack_top */

    /*
     * 6. Increment in_signal_handler nesting depth counter in Trusted State
     * Offset 48: in_signal_handler (depth counter)
     */
    incl    48(%r12)

    /*
     * 7. Dispatch to C Handler (ng_signal_dispatch)
     * Arguments restored from frame:
     * %rdi = signum (32(%rbp))
     * %rsi = info   (24(%rbp))
     * %rdx = ucontext (16(%rbp))
     */
    movq    32(%rbp), %rdi
    movq    24(%rbp), %rsi
    movq    16(%rbp), %rdx

    /* 16-byte stack alignment per AMD64 System V ABI */
    subq    $8, %rsp
    call    ng_signal_dispatch
    addq    $8, %rsp

    /*
     * 8. Reload Trusted State and Decrement in_signal_handler Nesting Counter
     */
    movq    t_trusted_state@gottpoff(%rip), %r12
    movq    %fs:(%r12), %r12
    testq   %r12, %r12
    jz      .Lfault_trap
    decl    48(%r12)

    /*
     * 9. Restore Frame and Registers
     */
    movq    %rbp, %rsp
    popq    %rbp
    .cfi_restore %rbp
    popq    %r12
    .cfi_restore %r12
    popq    %rdx
    popq    %rsi
    popq    %rdi

    /*
     * 10. CET Shadow Stack Safe Return:
     * Return via `ret` into glibc's __restore_rt restorer stub.
     * The `ret` instruction pops __restore_rt from both the data stack
     * and the hardware CET shadow stack (user_shstk), properly maintaining
     * shadow stack balance and preventing #CP faults.
     * __restore_rt will then invoke SYS_rt_sigreturn to restore the interrupted context.
     */
    ret
    .cfi_endproc

.Lfault_trap:
    /* Invalid stack, corrupted state, or domain violation: trigger hard trap */
    ud2

.size ng_signal_trampoline, .-ng_signal_trampoline
