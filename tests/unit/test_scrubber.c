/*
 * NullGate — Unit Test: Static ELF Scrubber & Binary Sanitizer
 * Pillar 4: Gadget Elimination & Static Binary Sanitization
 *
 * Verifies:
 *   1. Clean binary audit on self (/proc/self/exe) confirms zero WRPKRU opcodes and valid CET notes.
 *   2. Detection of synthetic WRPKRU (0F 01 EF) gadget injected into alignment padding.
 *   3. Safe in-place 3-byte neutralization (0x0F, 0x0B, 0x90 = UD2+NOP) with zero offset drift.
 *   4. Post-neutralization audit confirms complete gadget elimination.
 *   5. Preserves exact file size and execution properties.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "elf_scrubber.h"

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] Assertion failed: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

static int copy_file(const char *src_path, const char *dst_path)
{
    int src_fd = open(src_path, O_RDONLY);
    if (src_fd < 0)
        return -1;

    int dst_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dst_fd < 0) {
        close(src_fd);
        return -1;
    }

    char buf[8192];
    ssize_t n;
    while ((n = read(src_fd, buf, sizeof(buf))) > 0) {
        if (write(dst_fd, buf, (size_t)n) != n) {
            close(src_fd);
            close(dst_fd);
            return -1;
        }
    }

    close(src_fd);
    close(dst_fd);
    return 0;
}

int main(void)
{
    printf("[TEST] Starting Static ELF Scrubber Unit Test Suite (Pillar 4)...\n");

    /*
     * Phase 1: Self-Audit on /proc/self/exe
     */
    printf("  [Phase 1] Auditing clean binary (/proc/self/exe)...\n");
    struct ng_elf_scanner scanner;
    int ret = ng_elf_open(&scanner, "/proc/self/exe", NG_SCRUB_AUDIT_ONLY);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_open on clean binary must succeed");

    ret = ng_elf_scan_wrpkru(&scanner);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_scan_wrpkru on clean binary must return SUCCESS");
    TEST_ASSERT(scanner.wrpkru_findings == 0, "Clean binary must have 0 findings");

    ret = ng_elf_scan_cet(&scanner);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_scan_cet on clean binary must return SUCCESS");
    TEST_ASSERT(scanner.cet_violations == 0, "Clean binary must have 0 CET violations");

    ng_elf_close(&scanner);
    printf("    -> Clean binary verified: 0 gadgets, CET IBT & SHSTK intact.\n");

    /*
     * Phase 2: Create temporary test copy and find padding in executable segment
     */
    printf("  [Phase 2] Preparing synthetic gadget test binary...\n");
    char tmp_template[] = "/tmp/ng_scrub_test_XXXXXX";
    int tmp_fd = mkstemp(tmp_template);
    TEST_ASSERT(tmp_fd >= 0, "mkstemp must succeed");
    close(tmp_fd);

    ret = copy_file("/proc/self/exe", tmp_template);
    TEST_ASSERT(ret == 0, "copy_file must succeed");

    struct stat st_before;
    TEST_ASSERT(stat(tmp_template, &st_before) == 0, "stat before modification must succeed");

    ret = ng_elf_open(&scanner, tmp_template, NG_SCRUB_AUDIT_ONLY);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_open on temporary copy must succeed");

    size_t padding_offset = 0;
    bool found_padding = false;
    const uint8_t *data = (const uint8_t *)scanner.mapped_data;

    for (uint16_t p = 0; p < scanner.phnum; p++) {
        const Elf64_Phdr *ph = &scanner.phdrs[p];
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) {
            size_t seg_start = ph->p_offset;
            size_t seg_end = ph->p_offset + ph->p_filesz;

            for (size_t i = seg_start + 1; i + 4 < seg_end; i++) {
                if (data[i - 1] == 0xC3 &&
                    (data[i] == 0x90 || data[i] == 0xCC || data[i] == 0x00) &&
                    (data[i + 1] == 0x90 || data[i + 1] == 0xCC || data[i + 1] == 0x00) &&
                    (data[i + 2] == 0x90 || data[i + 2] == 0xCC || data[i + 2] == 0x00)) {
                    padding_offset = i;
                    found_padding = true;
                    break;
                }
            }
        }
        if (found_padding)
            break;
    }

    ng_elf_close(&scanner);
    TEST_ASSERT(found_padding, "Failed to locate alignment padding in executable segment");
    printf("    -> Located alignment padding at file offset 0x%zx.\n", padding_offset);

    /*
     * Phase 3: Inject synthetic WRPKRU (0F 01 EF) into padding
     */
    printf("  [Phase 3] Injecting synthetic WRPKRU (0F 01 EF) into alignment padding...\n");
    int mod_fd = open(tmp_template, O_RDWR);
    TEST_ASSERT(mod_fd >= 0, "open temporary copy for injection must succeed");
    TEST_ASSERT(lseek(mod_fd, (off_t)padding_offset, SEEK_SET) == (off_t)padding_offset, "lseek to padding must succeed");

    /*
     * Dynamically compute bytes to avoid embedding the literal contiguous
     * 0x0F, 0x01, 0xEF opcode sequence inside the test binary's own .text stream.
     */
    uint8_t wrpkru_bytes[3];
    volatile uint8_t b0 = 0x0E;
    volatile uint8_t b1 = 0x00;
    volatile uint8_t b2 = 0xEE;
    wrpkru_bytes[0] = (uint8_t)(b0 + 1); /* 0x0F */
    wrpkru_bytes[1] = (uint8_t)(b1 + 1); /* 0x01 */
    wrpkru_bytes[2] = (uint8_t)(b2 + 1); /* 0xEF */
    TEST_ASSERT(write(mod_fd, wrpkru_bytes, 3) == 3, "write WRPKRU bytes must succeed");
    close(mod_fd);

    /* Audit mode scan must detect gadget */
    ret = ng_elf_open(&scanner, tmp_template, NG_SCRUB_AUDIT_ONLY);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_open after injection must succeed");

    ret = ng_elf_scan_wrpkru(&scanner);
    TEST_ASSERT(ret == NG_SCRUB_GADGET_FOUND, "ng_elf_scan_wrpkru must return GADGET_FOUND");
    TEST_ASSERT(scanner.wrpkru_findings == 1, "Findings count must be 1");
    TEST_ASSERT(scanner.findings[0].file_offset == padding_offset, "Finding offset must match injected offset");
    TEST_ASSERT(scanner.findings[0].is_padding == true, "Finding must be classified as padding");
    TEST_ASSERT(scanner.findings[0].neutralized == false, "Finding must not be neutralized in audit mode");

    ng_elf_close(&scanner);
    printf("    -> Gadget detected in audit mode at expected offset.\n");

    /*
     * Phase 4: Neutralize gadget with strict 3-byte UD2+NOP sequence
     */
    printf("  [Phase 4] Executing in-place 3-byte neutralization (UD2+NOP)...\n");
    ret = ng_elf_open(&scanner, tmp_template, NG_SCRUB_NEUTRALIZE_PADDING);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_open in neutralize mode must succeed");

    ret = ng_elf_scan_wrpkru(&scanner);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_scan_wrpkru must return SUCCESS after neutralization");
    TEST_ASSERT(scanner.wrpkru_findings == 1, "Findings count recorded");
    TEST_ASSERT(scanner.findings[0].neutralized == true, "Finding must be marked neutralized");

    ng_elf_close(&scanner);

    /* Verify file size is unchanged (strict zero offset drift) */
    struct stat st_after;
    TEST_ASSERT(stat(tmp_template, &st_after) == 0, "stat after neutralization must succeed");
    TEST_ASSERT(st_before.st_size == st_after.st_size, "File size must not change (zero drift)");

    /* Inspect physical file bytes at injection offset */
    int verify_fd = open(tmp_template, O_RDONLY);
    TEST_ASSERT(verify_fd >= 0, "open temporary copy for verification must succeed");
    TEST_ASSERT(lseek(verify_fd, (off_t)padding_offset, SEEK_SET) == (off_t)padding_offset, "lseek must succeed");

    uint8_t patched_bytes[3];
    TEST_ASSERT(read(verify_fd, patched_bytes, 3) == 3, "read patched bytes must succeed");
    close(verify_fd);

    TEST_ASSERT(patched_bytes[0] == 0x0F, "Byte 0 must be 0x0F (UD2 byte 1)");
    TEST_ASSERT(patched_bytes[1] == 0x0B, "Byte 1 must be 0x0B (UD2 byte 2)");
    TEST_ASSERT(patched_bytes[2] == 0x90, "Byte 2 must be 0x90 (NOP)");
    printf("    -> Physical file verified: bytes successfully replaced with [0F 0B 90]. Size preserved.\n");

    /*
     * Phase 5: Re-scan neutralized binary in audit mode
     */
    printf("  [Phase 5] Re-auditing neutralized binary in audit mode...\n");
    ret = ng_elf_open(&scanner, tmp_template, NG_SCRUB_AUDIT_ONLY);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_open for re-audit must succeed");

    ret = ng_elf_scan_wrpkru(&scanner);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_scan_wrpkru re-audit must return SUCCESS");
    TEST_ASSERT(scanner.wrpkru_findings == 0, "Re-audited binary must have 0 findings");

    ng_elf_close(&scanner);
    printf("    -> Re-audit clean: 0 WRPKRU gadgets remaining.\n");

    /* Cleanup temporary file */
    unlink(tmp_template);

    /*
     * Phase 6: Unaligned Instruction-Boundary Gadget Detection Test (Fix LOW-04)
     */
    printf("  [Phase 6] Testing unaligned gadget spanning multi-instruction boundary...\n");
    char tmp_unaligned[] = "/tmp/ng_scrub_unaligned_XXXXXX";
    int unaligned_fd = mkstemp(tmp_unaligned);
    TEST_ASSERT(unaligned_fd >= 0, "mkstemp for unaligned test must succeed");
    close(unaligned_fd);

    ret = copy_file("/proc/self/exe", tmp_unaligned);
    TEST_ASSERT(ret == 0, "copy_file for unaligned test must succeed");

    /*
     * Simulate two adjacent instructions where WRPKRU (0F 01 EF) appears unaligned:
     * Instruction 1 (2 bytes): B0 0F        (mov $0x0f, %al) -> ends with 0x0F
     * Instruction 2 (3 bytes): 01 EF 90     (add %ebp, %edi; nop) -> starts with 0x01 0xEF
     * Byte stream: B0 [0F 01 EF] 90 -> unaligned WRPKRU across boundary!
     */
    int u_fd = open(tmp_unaligned, O_RDWR);
    TEST_ASSERT(u_fd >= 0, "open unaligned test file must succeed");
    TEST_ASSERT(lseek(u_fd, (off_t)padding_offset, SEEK_SET) == (off_t)padding_offset, "lseek must succeed");

    volatile uint8_t u_b0 = 0x0E;
    volatile uint8_t u_b1 = 0x00;
    volatile uint8_t u_b2 = 0xEE;
    uint8_t unaligned_stream[5];
    unaligned_stream[0] = 0xB0;
    unaligned_stream[1] = (uint8_t)(u_b0 + 1); /* 0x0F */
    unaligned_stream[2] = (uint8_t)(u_b1 + 1); /* 0x01 */
    unaligned_stream[3] = (uint8_t)(u_b2 + 1); /* 0xEF */
    unaligned_stream[4] = 0x90;

    TEST_ASSERT(write(u_fd, unaligned_stream, 5) == 5, "write unaligned stream must succeed");
    close(u_fd);

    ret = ng_elf_open(&scanner, tmp_unaligned, NG_SCRUB_AUDIT_ONLY);
    TEST_ASSERT(ret == NG_SCRUB_SUCCESS, "ng_elf_open for unaligned test must succeed");

    ret = ng_elf_scan_wrpkru(&scanner);
    TEST_ASSERT(ret == NG_SCRUB_GADGET_FOUND, "ng_elf_scan_wrpkru must detect unaligned boundary gadget");
    TEST_ASSERT(scanner.wrpkru_findings == 1, "Must find exactly 1 unaligned gadget");
    TEST_ASSERT(scanner.findings[0].file_offset == padding_offset + 1, "Finding offset must match unaligned offset +1");

    ng_elf_close(&scanner);
    unlink(tmp_unaligned);
    printf("    -> Unaligned multi-instruction boundary gadget successfully intercepted!\n");

    printf("[PASS] Static ELF Scrubber unit test suite completed successfully (All 6 phases PASSED).\n");
    return 0;
}
