/*
 * NullGate — Standalone ELF Scrubber CLI Tool
 * Pillar 4: Gadget Elimination & Static Binary Sanitization
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>

#include "elf_scrubber.h"

static bool g_use_color = true;

#define C_RESET   (g_use_color ? "\033[0m" : "")
#define C_RED     (g_use_color ? "\033[1;31m" : "")
#define C_GREEN   (g_use_color ? "\033[1;32m" : "")
#define C_YELLOW  (g_use_color ? "\033[1;33m" : "")
#define C_BLUE    (g_use_color ? "\033[1;34m" : "")
#define C_CYAN    (g_use_color ? "\033[1;36m" : "")
#define C_BOLD    (g_use_color ? "\033[1m" : "")

static void print_banner(void)
{
    printf("%s%s", C_CYAN, C_BOLD);
    printf("====================================================================\n");
    printf("       NullGate — Binary Static Scrubber & CET Sanitizer            \n");
    printf("       Pillar 4: Zero-Tolerance WRPKRU Gadget Elimination           \n");
    printf("====================================================================\n");
    printf("%s", C_RESET);
}

static void print_usage(const char *progname)
{
    printf("Usage: %s [OPTIONS] <elf-binary>\n\n", progname);
    printf("Operating Modes:\n");
    printf("  -s, --scan <binary>        Audit mode: inspect for WRPKRU opcodes and CET notes\n");
    printf("  -n, --neutralize <binary>  Neutralize padding gadgets in-place with 3-byte UD2+NOP\n\n");
    printf("Options:\n");
    printf("  --strict                   Strict mode: fail if Intel CET (IBT/SHSTK) is missing\n");
    printf("  -v, --verbose              Verbose segment diagnostic output\n");
    printf("  -h, --help                 Display this help message and exit\n\n");
    printf("Exit Codes:\n");
    printf("  0  Clean binary certified (or all padding gadgets successfully neutralized)\n");
    printf("  1  Security violation: live WRPKRU gadget or missing CET in strict mode\n");
    printf("  2  Command-line or file I/O error\n");
}

int main(int argc, char *argv[])
{
    if (!isatty(STDOUT_FILENO))
        g_use_color = false;

    const char *target_file = NULL;
    int flags = NG_SCRUB_AUDIT_ONLY;
    bool strict_mode = false;

    static struct option long_options[] = {
        {"scan",       required_argument, 0, 's'},
        {"neutralize", required_argument, 0, 'n'},
        {"strict",     no_argument,       0, 'S'},
        {"verbose",    no_argument,       0, 'v'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "s:n:Svh", long_options, &option_index)) != -1) {
        switch (opt) {
        case 's':
            target_file = optarg;
            flags &= ~NG_SCRUB_NEUTRALIZE_PADDING;
            flags |= NG_SCRUB_AUDIT_ONLY;
            break;
        case 'n':
            target_file = optarg;
            flags &= ~NG_SCRUB_AUDIT_ONLY;
            flags |= NG_SCRUB_NEUTRALIZE_PADDING;
            break;
        case 'S':
            strict_mode = true;
            break;
        case 'v':
            flags |= NG_SCRUB_VERBOSE;
            break;
        case 'h':
            print_banner();
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 2;
        }
    }

    /* Fallback to positional argument if not provided via -s or -n */
    if (!target_file && optind < argc) {
        target_file = argv[optind];
    }

    if (!target_file) {
        fprintf(stderr, "%sError:%s Target ELF binary path must be specified.\n", C_RED, C_RESET);
        print_usage(argv[0]);
        return 2;
    }

    print_banner();
    printf("[%sINFO%s] Inspecting target: %s%s%s (Mode: %s)\n",
           C_BLUE, C_RESET, C_BOLD, target_file, C_RESET,
           (flags & NG_SCRUB_NEUTRALIZE_PADDING) ? "In-Place Neutralize" : "Audit Only");

    struct ng_elf_scanner scanner;
    int open_ret = ng_elf_open(&scanner, target_file, flags);
    if (open_ret != NG_SCRUB_SUCCESS) {
        fprintf(stderr, "%sError:%s Failed to open/map ELF binary '%s' (code: %d)\n",
                C_RED, C_RESET, target_file, open_ret);
        return 2;
    }

    if (flags & NG_SCRUB_VERBOSE) {
        printf("[%sINFO%s] ELF Type: %s, Machine: x86_64, Program Headers: %u, Section Headers: %u\n",
               C_BLUE, C_RESET,
               scanner.ehdr->e_type == ET_DYN ? "Shared Library / PIE (ET_DYN)" : "Executable (ET_EXEC)",
               scanner.phnum, scanner.shnum);
    }

    /* 1. Scan for WRPKRU opcodes */
    int wrpkru_ret = ng_elf_scan_wrpkru(&scanner);

    /* 2. Audit Intel CET compliance */
    int cet_ret = ng_elf_scan_cet(&scanner);

    /* 3. Output Findings */
    if (scanner.wrpkru_findings > 0) {
        printf("\n%s--- Scan Findings (%u detected) ---%s\n", C_BOLD, scanner.wrpkru_findings, C_RESET);
        printf("%-12s %-18s %-14s %-20s %-20s\n",
               "Segment", "Virtual Addr", "File Offset", "Classification", "Action / Status");
        printf("-------------------------------------------------------------------------------------\n");

        for (uint32_t i = 0; i < scanner.wrpkru_findings && i < NG_SCRUB_MAX_FINDINGS; i++) {
            const struct ng_scrub_finding *f = &scanner.findings[i];
            const char *class_str = f->is_padding ? "Padding Gadget" : "Reachable Code";
            const char *action_str;

            if (f->neutralized) {
                action_str = "Neutralized (UD2+NOP)";
            } else if (f->is_padding) {
                action_str = (flags & NG_SCRUB_NEUTRALIZE_PADDING) ? "Failed Neutralize" : "Detected (Audit)";
            } else {
                action_str = "FATAL VIOLATION";
            }

            printf("PT_LOAD[%u]  0x%016lx 0x%08lx    %-20s %s%-20s%s\n",
                   f->segment_idx,
                   (unsigned long)f->vaddr,
                   (unsigned long)f->file_offset,
                   class_str,
                   f->neutralized ? C_GREEN : (f->is_padding ? C_YELLOW : C_RED),
                   action_str,
                   C_RESET);
        }
    } else {
        printf("[%sPASS%s] Zero WRPKRU (0F 01 EF) byte patterns detected across all executable segments.\n",
               C_GREEN, C_RESET);
    }

    /* 4. Output CET status */
    printf("\n%s--- Intel CET (IBT + SHSTK) Audit ---%s\n", C_BOLD, C_RESET);
    if (cet_ret == NG_SCRUB_SUCCESS) {
        printf("  [%sPASS%s] Intel CET IBT & User Shadow Stack (SHSTK) notes and landing pads confirmed.\n",
               C_GREEN, C_RESET);
    } else {
        printf("  [%sWARN%s] Intel CET non-compliance detected (%u violations: missing notes or ENDBR64).\n",
               strict_mode ? C_RED : C_YELLOW, C_RESET, scanner.cet_violations);
    }

    int final_exit = 0;
    if (wrpkru_ret != NG_SCRUB_SUCCESS) {
        printf("\n[%sFAIL%s] Binary contains unauthorized reachable WRPKRU instructions! Build blocked.\n",
               C_RED, C_RESET);
        final_exit = 1;
    } else if (strict_mode && cet_ret != NG_SCRUB_SUCCESS) {
        printf("\n[%sFAIL%s] Binary failed Intel CET requirements under strict enforcement!\n",
               C_RED, C_RESET);
        final_exit = 1;
    } else {
        printf("\n[%sCERTIFIED CLEAN%s] Binary complies with NullGate Pillar 4 binary sanitization.\n",
               C_GREEN, C_RESET);
        final_exit = 0;
    }

    ng_elf_close(&scanner);
    return final_exit;
}
