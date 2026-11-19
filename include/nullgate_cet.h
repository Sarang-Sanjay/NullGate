/*
 * NullGate — Intel CET (IBT + User Shadow Stack) Definitions
 * Ensures all compilation units and assembly stubs preserve hardware CET notes
 * and non-executable stack (.note.GNU-stack) properties.
 */

#ifndef NULLGATE_CET_H
#define NULLGATE_CET_H

#define NG_GNU_PROPERTY_X86_FEATURE_1_AND   0xc0000002
#define NG_GNU_PROPERTY_X86_FEATURE_1_IBT   (1U << 0)
#define NG_GNU_PROPERTY_X86_FEATURE_1_SHSTK (1U << 1)
#define NG_CET_FEATURES                     (NG_GNU_PROPERTY_X86_FEATURE_1_IBT | NG_GNU_PROPERTY_X86_FEATURE_1_SHSTK)

#ifdef __ASSEMBLER__

/*
 * NG_ENDBR64:
 * Emits the 4-byte Intel CET Indirect Branch Tracking (IBT) landing pad:
 * Opcode: F3 0F 1E FA (endbr64)
 */
#define NG_ENDBR64 endbr64

/*
 * NG_EMIT_GNU_PROPERTY_NOTE:
 * Emits the .note.gnu.property ELF section marking the object as supporting
 * both Intel CET IBT and User Shadow Stack (SHSTK), and emits .note.GNU-stack
 * to enforce a non-executable data stack (NX).
 */
#define NG_EMIT_GNU_PROPERTY_NOTE                       \
    .section .note.gnu.property, "a", @note ;          \
    .p2align 3, 0x0 ;                                   \
    .long 4 ;               /* Name length: 'GNU\0' */  \
    .long 16 ;              /* Descriptor length */     \
    .long 5 ;               /* NT_GNU_PROPERTY_TYPE_0 */\
    .asciz "GNU" ;                                      \
    .long 0xc0000002 ;      /* X86_FEATURE_1_AND */     \
    .long 4 ;               /* Data size */             \
    .long 3 ;               /* IBT (1) | SHSTK (2) */   \
    .p2align 3, 0x0 ;                                   \
    .section .note.GNU-stack, "", @progbits ;           \
    .text

#else /* !__ASSEMBLER__ */

#include <stdint.h>

#if defined(__x86_64__)
#define NG_ENDBR64() __asm__ volatile ("endbr64" ::: "memory")
#else
#define NG_ENDBR64() do {} while (0)
#endif

#endif /* __ASSEMBLER__ */

#endif /* NULLGATE_CET_H */
