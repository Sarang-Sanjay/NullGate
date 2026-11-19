/*
 * NullGate — Static ELF Scrubber & Binary Sanitizer Implementation
 * Pillar 4: Gadget Elimination & Static Binary Sanitization
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <elf.h>

#include "elf_scrubber.h"

#ifndef NT_GNU_PROPERTY_TYPE_0
#define NT_GNU_PROPERTY_TYPE_0 5
#endif

/*
 * vaddr_to_file_offset - Resolve a virtual memory address to its physical file offset.
 */
static ssize_t vaddr_to_file_offset(const struct ng_elf_scanner *scanner, uint64_t vaddr)
{
    if (!scanner || !scanner->phdrs)
        return -1;

    for (uint16_t i = 0; i < scanner->phnum; i++) {
        const Elf64_Phdr *ph = &scanner->phdrs[i];
        if (ph->p_type == PT_LOAD) {
            if (vaddr >= ph->p_vaddr && vaddr < (ph->p_vaddr + ph->p_filesz)) {
                size_t offset = ph->p_offset + (vaddr - ph->p_vaddr);
                if (offset < scanner->mapped_size)
                    return (ssize_t)offset;
            }
        }
    }
    return -1;
}

/*
 * is_inter_function_padding - Determines if an offset is inter-function alignment padding.
 */
static bool is_inter_function_padding(const struct ng_elf_scanner *scanner, size_t offset, uint64_t vaddr)
{
    if (!scanner || !scanner->mapped_data)
        return false;

    /*
     * 1. Section Headers & Symbol Table Analysis (when unstripped)
     */
    if (scanner->shdrs && scanner->shnum > 0) {
        bool symbol_table_found = false;
        bool inside_any_function = false;

        for (uint16_t i = 0; i < scanner->shnum; i++) {
            const Elf64_Shdr *sh = &scanner->shdrs[i];
            if (sh->sh_type == SHT_SYMTAB || sh->sh_type == SHT_DYNSYM) {
                if (sh->sh_offset > scanner->mapped_size ||
                    sh->sh_size > scanner->mapped_size - sh->sh_offset ||
                    sh->sh_entsize < sizeof(Elf64_Sym))
                    continue;

                symbol_table_found = true;
                size_t num_syms = sh->sh_size / sh->sh_entsize;
                const Elf64_Sym *syms = (const Elf64_Sym *)((const uint8_t *)scanner->mapped_data + sh->sh_offset);

                for (size_t s = 0; s < num_syms; s++) {
                    const Elf64_Sym *sym = &syms[s];
                    if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC && sym->st_size > 0 && sym->st_value != 0) {
                        if (vaddr >= sym->st_value && vaddr < (sym->st_value + sym->st_size)) {
                            inside_any_function = true;
                            break;
                        }
                    }
                }
                if (inside_any_function)
                    break;
            }
        }

        /* If inside any known function, it is reachable code, NOT padding */
        if (inside_any_function)
            return false;

        /* If symbol tables verified the address is between functions, it is padding */
        if (symbol_table_found)
            return true;
    }

    /*
     * 2. Heuristic Context Analysis for Stripped Binaries
     */
    const uint8_t *data = (const uint8_t *)scanner->mapped_data;
    if (offset >= 1) {
        uint8_t prev = data[offset - 1];
        /* Common function epilogue terminators: RET (0xC3), INT3 (0xCC), NOP (0x90), UD2 (0x0B) */
        if (prev == 0xC3 || prev == 0xCC || prev == 0x90 || prev == 0x0B) {
            if (offset + 3 < scanner->mapped_size) {
                uint8_t next = data[offset + 3];
                if (next == 0x90 || next == 0xCC || next == 0x00 ||
                    (offset + 6 < scanner->mapped_size &&
                     data[offset + 3] == NG_ENDBR64_BYTE0 &&
                     data[offset + 4] == NG_ENDBR64_BYTE1 &&
                     data[offset + 5] == NG_ENDBR64_BYTE2 &&
                     data[offset + 6] == NG_ENDBR64_BYTE3)) {
                    return true;
                }
            }
        }
    }

    return false;
}

int ng_elf_open(struct ng_elf_scanner *scanner, const char *filepath, int flags)
{
    if (!scanner || !filepath)
        return NG_SCRUB_ERR_IO;

    memset(scanner, 0, sizeof(*scanner));
    scanner->fd = -1;
    scanner->flags = flags;

    int open_flags = (flags & NG_SCRUB_NEUTRALIZE_PADDING) ? O_RDWR : O_RDONLY;
    scanner->fd = open(filepath, open_flags);
    if (scanner->fd < 0) {
        if (open_flags == O_RDWR && errno == EACCES && !(flags & NG_SCRUB_NEUTRALIZE_PADDING)) {
            scanner->fd = open(filepath, O_RDONLY);
        }
        if (scanner->fd < 0)
            return NG_SCRUB_ERR_IO;
    }

    struct stat st;
    if (fstat(scanner->fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(scanner->fd);
        scanner->fd = -1;
        return NG_SCRUB_ERR_FORMAT;
    }

    scanner->mapped_size = (size_t)st.st_size;
    int prot = PROT_READ | ((flags & NG_SCRUB_NEUTRALIZE_PADDING) ? PROT_WRITE : 0);
    scanner->mapped_data = mmap(NULL, scanner->mapped_size, prot, MAP_SHARED, scanner->fd, 0);
    if (scanner->mapped_data == MAP_FAILED) {
        close(scanner->fd);
        scanner->fd = -1;
        scanner->mapped_data = NULL;
        return NG_SCRUB_ERR_IO;
    }

    /* Validate ELF Header */
    scanner->ehdr = (Elf64_Ehdr *)scanner->mapped_data;
    if (memcmp(scanner->ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
        scanner->ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        scanner->ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        scanner->ehdr->e_machine != EM_X86_64) {
        ng_elf_close(scanner);
        return NG_SCRUB_ERR_FORMAT;
    }

    /* Program Headers (Fix MED-04: overflow-safe subtraction bounds checks) */
    size_t ph_size = (size_t)scanner->ehdr->e_phnum * sizeof(Elf64_Phdr);
    if (scanner->ehdr->e_phoff == 0 || scanner->ehdr->e_phnum == 0 ||
        scanner->ehdr->e_phoff > scanner->mapped_size ||
        ph_size > scanner->mapped_size - scanner->ehdr->e_phoff) {
        ng_elf_close(scanner);
        return NG_SCRUB_ERR_FORMAT;
    }

    scanner->phnum = scanner->ehdr->e_phnum;
    scanner->phdrs = (Elf64_Phdr *)((uint8_t *)scanner->mapped_data + scanner->ehdr->e_phoff);

    /* Section Headers (optional for stripped binaries) */
    size_t sh_size = (size_t)scanner->ehdr->e_shnum * sizeof(Elf64_Shdr);
    if (scanner->ehdr->e_shoff != 0 && scanner->ehdr->e_shnum != 0 &&
        scanner->ehdr->e_shoff <= scanner->mapped_size &&
        sh_size <= scanner->mapped_size - scanner->ehdr->e_shoff) {
        scanner->shnum = scanner->ehdr->e_shnum;
        scanner->shdrs = (Elf64_Shdr *)((uint8_t *)scanner->mapped_data + scanner->ehdr->e_shoff);
    } else {
        scanner->shnum = 0;
        scanner->shdrs = NULL;
    }

    return NG_SCRUB_SUCCESS;
}

void ng_elf_close(struct ng_elf_scanner *scanner)
{
    if (!scanner)
        return;

    if (scanner->mapped_data && scanner->mapped_size > 0) {
        if (scanner->flags & NG_SCRUB_NEUTRALIZE_PADDING) {
            (void)msync(scanner->mapped_data, scanner->mapped_size, MS_SYNC);
        }
        (void)munmap(scanner->mapped_data, scanner->mapped_size);
        scanner->mapped_data = NULL;
    }

    if (scanner->fd >= 0) {
        close(scanner->fd);
        scanner->fd = -1;
    }
}

int ng_elf_neutralize_padding_gadget(struct ng_elf_scanner *scanner, size_t offset)
{
    if (!scanner || !scanner->mapped_data)
        return NG_SCRUB_ERR_IO;

    if (offset + 3 > scanner->mapped_size)
        return NG_SCRUB_ERR_FORMAT;

    uint8_t *bytes = (uint8_t *)scanner->mapped_data + offset;

    /* Verify WRPKRU pattern */
    if (bytes[0] != NG_WRPKRU_OPCODE_BYTE0 ||
        bytes[1] != NG_WRPKRU_OPCODE_BYTE1 ||
        bytes[2] != NG_WRPKRU_OPCODE_BYTE2) {
        return NG_SCRUB_ERR_FORMAT;
    }

    /*
     * Strict 3-byte safe neutralization:
     * Overwrite with UD2 (0x0F, 0x0B) + NOP (0x90).
     * Preserves instruction alignment and prevents any byte shift.
     */
    bytes[0] = NG_UD2_OPCODE_BYTE0;
    bytes[1] = NG_UD2_OPCODE_BYTE1;
    bytes[2] = NG_NOP_OPCODE_BYTE;

    return NG_SCRUB_SUCCESS;
}

int ng_elf_scan_wrpkru(struct ng_elf_scanner *scanner)
{
    if (!scanner || !scanner->mapped_data || !scanner->phdrs)
        return NG_SCRUB_ERR_IO;

    scanner->wrpkru_findings = 0;
    bool fatal_gadget_found = false;
    const uint8_t *data = (const uint8_t *)scanner->mapped_data;

    for (uint16_t p = 0; p < scanner->phnum; p++) {
        const Elf64_Phdr *ph = &scanner->phdrs[p];

        /* Only scan executable PT_LOAD segments */
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X))
            continue;

        if (ph->p_offset > scanner->mapped_size ||
            ph->p_filesz > scanner->mapped_size - ph->p_offset)
            continue;

        size_t seg_start = ph->p_offset;
        size_t seg_end = ph->p_offset + ph->p_filesz;

        if (seg_end < 3)
            continue;

        for (size_t i = seg_start; i <= seg_end - 3; i++) {
            if (data[i] == NG_WRPKRU_OPCODE_BYTE0 &&
                data[i + 1] == NG_WRPKRU_OPCODE_BYTE1 &&
                data[i + 2] == NG_WRPKRU_OPCODE_BYTE2) {

                uint64_t vaddr = ph->p_vaddr + (i - ph->p_offset);
                bool is_pad = is_inter_function_padding(scanner, i, vaddr);

                uint32_t idx = scanner->wrpkru_findings;
                if (idx < NG_SCRUB_MAX_FINDINGS) {
                    scanner->findings[idx].file_offset = i;
                    scanner->findings[idx].vaddr = vaddr;
                    scanner->findings[idx].segment_idx = p;
                    scanner->findings[idx].is_padding = is_pad;
                    scanner->findings[idx].neutralized = false;
                    scanner->findings[idx].original_bytes[0] = data[i];
                    scanner->findings[idx].original_bytes[1] = data[i + 1];
                    scanner->findings[idx].original_bytes[2] = data[i + 2];
                }
                scanner->wrpkru_findings++;

                if (is_pad && (scanner->flags & NG_SCRUB_NEUTRALIZE_PADDING)) {
                    if (ng_elf_neutralize_padding_gadget(scanner, i) == NG_SCRUB_SUCCESS) {
                        if (idx < NG_SCRUB_MAX_FINDINGS) {
                            scanner->findings[idx].neutralized = true;
                        }
                    } else {
                        fatal_gadget_found = true;
                    }
                } else {
                    /* Gadget in live code stream or audit mode without neutralization */
                    fatal_gadget_found = true;
                }
            }
        }
    }

    if (fatal_gadget_found)
        return NG_SCRUB_GADGET_FOUND;

    return NG_SCRUB_SUCCESS;
}

int ng_elf_scan_cet(struct ng_elf_scanner *scanner)
{
    if (!scanner || !scanner->mapped_data)
        return NG_SCRUB_ERR_IO;

    scanner->cet_violations = 0;
    const uint8_t *data = (const uint8_t *)scanner->mapped_data;
    bool found_ibt = false;
    bool found_shstk = false;

    /*
     * 1. Check PT_NOTE segments for GNU Property Notes
     */
    for (uint16_t p = 0; p < scanner->phnum; p++) {
        const Elf64_Phdr *ph = &scanner->phdrs[p];
        if (ph->p_type != PT_NOTE ||
            ph->p_offset > scanner->mapped_size ||
            ph->p_filesz > scanner->mapped_size - ph->p_offset)
            continue;

        size_t offset = ph->p_offset;
        size_t note_end = ph->p_offset + ph->p_filesz;

        while (offset + sizeof(Elf64_Nhdr) <= note_end) {
            const Elf64_Nhdr *nh = (const Elf64_Nhdr *)(data + offset);
            size_t namesz = nh->n_namesz;
            size_t descsz = nh->n_descsz;
            size_t n_type = nh->n_type;

            size_t name_offset = offset + sizeof(Elf64_Nhdr);
            if (name_offset + namesz > note_end)
                break;

            if (n_type == NT_GNU_PROPERTY_TYPE_0 && namesz == 4 &&
                memcmp(data + name_offset, "GNU", 4) == 0) {

                /* Determine descriptor alignment: 8-byte standard or 4-byte */
                size_t desc_offset = name_offset + ((namesz + 7) & ~7);
                if (desc_offset + 8 > note_end ||
                    *(const uint32_t *)(data + desc_offset) != GNU_PROPERTY_X86_FEATURE_1_AND) {
                    desc_offset = name_offset + ((namesz + 3) & ~3);
                }

                if (desc_offset + descsz <= note_end) {
                    size_t prop_offset = desc_offset;
                    size_t desc_end = desc_offset + descsz;

                    while (prop_offset + 8 <= desc_end) {
                        uint32_t pr_type = *(const uint32_t *)(data + prop_offset);
                        uint32_t pr_datasz = *(const uint32_t *)(data + prop_offset + 4);
                        if (pr_type == GNU_PROPERTY_X86_FEATURE_1_AND && pr_datasz >= 4 &&
                            prop_offset + 8 + pr_datasz <= desc_end) {
                            uint32_t features = *(const uint32_t *)(data + prop_offset + 8);
                            if (features & GNU_PROPERTY_X86_FEATURE_1_IBT)
                                found_ibt = true;
                            if (features & GNU_PROPERTY_X86_FEATURE_1_SHSTK)
                                found_shstk = true;
                        }
                        size_t pr_step = 8 + ((pr_datasz + 7) & ~7);
                        if (pr_step < 8)
                            break;
                        prop_offset += pr_step;
                    }
                }
            }

            size_t note_step = sizeof(Elf64_Nhdr) + ((namesz + 3) & ~3) + ((descsz + 3) & ~3);
            if (note_step < sizeof(Elf64_Nhdr))
                break;
            offset += note_step;
        }
    }

    if (!found_ibt || !found_shstk) {
        scanner->cet_violations++;
    }

    /*
     * 2. Validate ENDBR64 at Binary Entry Point
     */
    if (scanner->ehdr->e_entry != 0) {
        ssize_t entry_off = vaddr_to_file_offset(scanner, scanner->ehdr->e_entry);
        if (entry_off >= 0 && (size_t)entry_off + 4 <= scanner->mapped_size) {
            const uint8_t *ep = data + entry_off;
            if (ep[0] != NG_ENDBR64_BYTE0 || ep[1] != NG_ENDBR64_BYTE1 ||
                ep[2] != NG_ENDBR64_BYTE2 || ep[3] != NG_ENDBR64_BYTE3) {
                scanner->cet_violations++;
            }
        }
    }

    /*
     * 3. Validate ENDBR64 Landing Pads on Exported Functions (if Symbol Table present)
     */
    if (scanner->shdrs && scanner->shnum > 0) {
        for (uint16_t i = 0; i < scanner->shnum; i++) {
            const Elf64_Shdr *sh = &scanner->shdrs[i];
            if (sh->sh_type != SHT_DYNSYM && sh->sh_type != SHT_SYMTAB)
                continue;

            if (sh->sh_offset + sh->sh_size > scanner->mapped_size || sh->sh_entsize < sizeof(Elf64_Sym))
                continue;

            size_t num_syms = sh->sh_size / sh->sh_entsize;
            const Elf64_Sym *syms = (const Elf64_Sym *)(data + sh->sh_offset);

            for (size_t s = 0; s < num_syms; s++) {
                const Elf64_Sym *sym = &syms[s];
                if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC &&
                    (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL || ELF64_ST_BIND(sym->st_info) == STB_WEAK) &&
                    sym->st_shndx != SHN_UNDEF && sym->st_value != 0) {

                    ssize_t func_off = vaddr_to_file_offset(scanner, sym->st_value);
                    if (func_off >= 0 && (size_t)func_off + 4 <= scanner->mapped_size) {
                        const uint8_t *fp = data + func_off;
                        if (fp[0] != NG_ENDBR64_BYTE0 || fp[1] != NG_ENDBR64_BYTE1 ||
                            fp[2] != NG_ENDBR64_BYTE2 || fp[3] != NG_ENDBR64_BYTE3) {
                            scanner->cet_violations++;
                        }
                    }
                }
            }
        }
    }

    if (scanner->cet_violations > 0)
        return NG_SCRUB_CET_MISSING;

    return NG_SCRUB_SUCCESS;
}
