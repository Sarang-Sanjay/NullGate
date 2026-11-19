/*
 * NullGate — Static ELF Scrubber & Binary Sanitizer Header
 * Pillar 4: Gadget Elimination & Static Binary Sanitization
 */

#ifndef NULLGATE_ELF_SCRUBBER_H
#define NULLGATE_ELF_SCRUBBER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <elf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes */
#define NG_SCRUB_SUCCESS            0
#define NG_SCRUB_GADGET_FOUND       1
#define NG_SCRUB_CET_MISSING        2
#define NG_SCRUB_ERR_IO             3
#define NG_SCRUB_ERR_FORMAT         4

/* Scanner operation flags */
#define NG_SCRUB_AUDIT_ONLY         (1U << 0)
#define NG_SCRUB_NEUTRALIZE_PADDING (1U << 1)
#define NG_SCRUB_VERBOSE            (1U << 2)

/* Intel CET note constants (GNU Property Note) */
#ifndef GNU_PROPERTY_X86_FEATURE_1_AND
#define GNU_PROPERTY_X86_FEATURE_1_AND  0xc0000002U
#endif
#ifndef GNU_PROPERTY_X86_FEATURE_1_IBT
#define GNU_PROPERTY_X86_FEATURE_1_IBT  (1U << 0)
#endif
#ifndef GNU_PROPERTY_X86_FEATURE_1_SHSTK
#define GNU_PROPERTY_X86_FEATURE_1_SHSTK (1U << 1)
#endif

/* Machine instruction byte sequence definitions */
#define NG_WRPKRU_OPCODE_BYTE0      0x0FU
#define NG_WRPKRU_OPCODE_BYTE1      0x01U
#define NG_WRPKRU_OPCODE_BYTE2      0xEFU

#define NG_UD2_OPCODE_BYTE0         0x0FU
#define NG_UD2_OPCODE_BYTE1         0x0BU
#define NG_NOP_OPCODE_BYTE          0x90U

#define NG_ENDBR64_BYTE0            0xF3U
#define NG_ENDBR64_BYTE1            0x0FU
#define NG_ENDBR64_BYTE2            0x1EU
#define NG_ENDBR64_BYTE3            0xFAU

/* Maximum tracked findings */
#define NG_SCRUB_MAX_FINDINGS       256

/*
 * struct ng_scrub_finding:
 * Records location and classification of a detected opcode gadget.
 */
struct ng_scrub_finding {
    size_t file_offset;         /* File offset of the finding */
    uint64_t vaddr;             /* Virtual address (if mapped) */
    uint32_t segment_idx;       /* ELF PT_LOAD segment index */
    bool is_padding;            /* True if identified as inter-function alignment padding */
    bool neutralized;           /* True if safely rewritten with 0x0F, 0x0B, 0x90 */
    uint8_t original_bytes[3];  /* Original byte sequence */
};

/*
 * struct ng_elf_scanner:
 * State container for an active ELF binary memory mapping and scan.
 */
struct ng_elf_scanner {
    int fd;
    void *mapped_data;
    size_t mapped_size;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;
    Elf64_Phdr *phdrs;
    uint16_t phnum;
    uint16_t shnum;
    uint32_t wrpkru_findings;
    uint32_t cet_violations;
    int flags;
    struct ng_scrub_finding findings[NG_SCRUB_MAX_FINDINGS];
};

/**
 * ng_elf_open - Open and memory-map target ELF binary.
 * @scanner: Target scanner structure
 * @filepath: Path to ELF binary on disk
 * @flags: NG_SCRUB_* control flags
 *
 * Returns NG_SCRUB_SUCCESS on success, or NG_SCRUB_ERR_* on failure.
 */
int ng_elf_open(struct ng_elf_scanner *scanner, const char *filepath, int flags);

/**
 * ng_elf_close - Unmap and close ELF binary, synchronizing changes if neutralized.
 * @scanner: Active scanner structure
 */
void ng_elf_close(struct ng_elf_scanner *scanner);

/**
 * ng_elf_scan_wrpkru - Scan executable segments for WRPKRU (0F 01 EF) opcodes.
 * @scanner: Active scanner structure
 *
 * Returns NG_SCRUB_SUCCESS if clean, or NG_SCRUB_GADGET_FOUND if gadgets detected.
 */
int ng_elf_scan_wrpkru(struct ng_elf_scanner *scanner);

/**
 * ng_elf_scan_cet - Audit ELF binary for Intel CET IBT and SHSTK compliance.
 * @scanner: Active scanner structure
 *
 * Checks .note.gnu.property and verifies ENDBR64 landing pads on STT_FUNC symbols.
 * Returns NG_SCRUB_SUCCESS if compliant, or NG_SCRUB_CET_MISSING on violation.
 */
int ng_elf_scan_cet(struct ng_elf_scanner *scanner);

/**
 * ng_elf_neutralize_padding_gadget - Overwrite padding gadget with strict 3-byte UD2+NOP.
 * @scanner: Active scanner structure
 * @offset: Exact byte offset in mapped ELF binary
 *
 * Writes 0x0F, 0x0B, 0x90 ensuring file offsets and instruction alignments never drift.
 * Returns NG_SCRUB_SUCCESS on success, or NG_SCRUB_ERR_* on failure.
 */
int ng_elf_neutralize_padding_gadget(struct ng_elf_scanner *scanner, size_t offset);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_ELF_SCRUBBER_H */
