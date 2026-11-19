/*
 * NullGate — Dynamic Domain Policy Manifest Parser Implementation
 * Zero-dependency, memory-safe JSON parser and validator for domain policies.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "nullgate_policy_parser.h"
#include "policy_loader.h"

/* JSON Parser internal types */
enum json_token_type {
    TOK_EOF = 0,
    TOK_LBRACE,     /* { */
    TOK_RBRACE,     /* } */
    TOK_LBRACKET,   /* [ */
    TOK_RBRACKET,   /* ] */
    TOK_COLON,      /* : */
    TOK_COMMA,      /* , */
    TOK_STRING,     /* "..." */
    TOK_NUMBER,     /* 123, 0x12 */
    TOK_BOOL,       /* true, false */
    TOK_NULL,       /* null */
    TOK_ERROR
};

struct json_token {
    enum json_token_type type;
    char text[64];
    long long num_val;
    bool bool_val;
};

struct json_scanner {
    const char *src;
    size_t len;
    size_t cursor;
    int err;
};

/* Forward declarations */
static void scan_skip_whitespace_and_comments(struct json_scanner *s);
static struct json_token scan_next_token(struct json_scanner *s);

static void scan_skip_whitespace_and_comments(struct json_scanner *s)
{
    while (s->cursor < s->len) {
        char c = s->src[s->cursor];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            s->cursor++;
            continue;
        }
        /* Single-line comment // */
        if (c == '/' && s->cursor + 1 < s->len && s->src[s->cursor + 1] == '/') {
            s->cursor += 2;
            while (s->cursor < s->len && s->src[s->cursor] != '\n')
                s->cursor++;
            continue;
        }
        /* Multi-line comment */
        if (c == '/' && s->cursor + 1 < s->len && s->src[s->cursor + 1] == '*') {
            s->cursor += 2;
            while (s->cursor + 1 < s->len && !(s->src[s->cursor] == '*' && s->src[s->cursor + 1] == '/'))
                s->cursor++;
            if (s->cursor + 1 < s->len)
                s->cursor += 2;
            continue;
        }
        break;
    }
}

static struct json_token scan_next_token(struct json_scanner *s)
{
    struct json_token tok;
    memset(&tok, 0, sizeof(tok));

    scan_skip_whitespace_and_comments(s);

    if (s->cursor >= s->len) {
        tok.type = TOK_EOF;
        return tok;
    }

    char c = s->src[s->cursor];

    switch (c) {
    case '{': tok.type = TOK_LBRACE; s->cursor++; return tok;
    case '}': tok.type = TOK_RBRACE; s->cursor++; return tok;
    case '[': tok.type = TOK_LBRACKET; s->cursor++; return tok;
    case ']': tok.type = TOK_RBRACKET; s->cursor++; return tok;
    case ':': tok.type = TOK_COLON; s->cursor++; return tok;
    case ',': tok.type = TOK_COMMA; s->cursor++; return tok;
    case '"': {
        s->cursor++; /* skip open quote */
        size_t t_idx = 0;
        while (s->cursor < s->len && s->src[s->cursor] != '"') {
            if (s->src[s->cursor] == '\\' && s->cursor + 1 < s->len) {
                s->cursor++;
            }
            if (t_idx + 1 < sizeof(tok.text)) {
                tok.text[t_idx++] = s->src[s->cursor];
            }
            s->cursor++;
        }
        tok.text[t_idx] = '\0';
        if (s->cursor < s->len && s->src[s->cursor] == '"') {
            s->cursor++; /* skip close quote */
            tok.type = TOK_STRING;
        } else {
            tok.type = TOK_ERROR;
            s->err = NG_POLICY_ERR_SYNTAX;
        }
        return tok;
    }
    default:
        break;
    }

    /* Scan number (decimal or hex) */
    if (isdigit((unsigned char)c) || c == '-' || (c == '0' && s->cursor + 1 < s->len && (s->src[s->cursor + 1] == 'x' || s->src[s->cursor + 1] == 'X'))) {
        char num_buf[32];
        size_t n_idx = 0;
        while (s->cursor < s->len && (isxdigit((unsigned char)s->src[s->cursor]) || s->src[s->cursor] == 'x' || s->src[s->cursor] == 'X' || s->src[s->cursor] == '-')) {
            if (n_idx + 1 < sizeof(num_buf)) {
                num_buf[n_idx++] = s->src[s->cursor];
            }
            s->cursor++;
        }
        num_buf[n_idx] = '\0';
        char *endptr = NULL;
        tok.num_val = strtoll(num_buf, &endptr, 0);
        strncpy(tok.text, num_buf, sizeof(tok.text) - 1);
        tok.type = TOK_NUMBER;
        return tok;
    }

    /* Scan identifiers: true, false, null */
    if (isalpha((unsigned char)c)) {
        char id_buf[32];
        size_t i_idx = 0;
        while (s->cursor < s->len && isalpha((unsigned char)s->src[s->cursor])) {
            if (i_idx + 1 < sizeof(id_buf)) {
                id_buf[i_idx++] = s->src[s->cursor];
            }
            s->cursor++;
        }
        id_buf[i_idx] = '\0';
        if (strcmp(id_buf, "true") == 0) {
            tok.type = TOK_BOOL;
            tok.bool_val = true;
            return tok;
        } else if (strcmp(id_buf, "false") == 0) {
            tok.type = TOK_BOOL;
            tok.bool_val = false;
            return tok;
        } else if (strcmp(id_buf, "null") == 0) {
            tok.type = TOK_NULL;
            return tok;
        }
        strncpy(tok.text, id_buf, sizeof(tok.text) - 1);
        tok.type = TOK_STRING;
        return tok;
    }

    /* Unrecognized character */
    tok.type = TOK_ERROR;
    s->err = NG_POLICY_ERR_SYNTAX;
    s->cursor++;
    return tok;
}

static uint32_t parse_flag_string(const char *str)
{
    if (strcmp(str, "STRICT_WX") == 0) return NG_POLICY_STRICT_WX;
    if (strcmp(str, "STRICT_SYSCALL") == 0) return NG_POLICY_STRICT_SYSCALL;
    if (strcmp(str, "BLOCK_PTRACE") == 0) return NG_POLICY_BLOCK_PTRACE;
    if (strcmp(str, "BLOCK_PROCFS") == 0) return NG_POLICY_BLOCK_PROCFS;
    if (strcmp(str, "BLOCK_BPF") == 0) return NG_POLICY_BLOCK_BPF;
    if (strcmp(str, "INHERIT_FORK") == 0) return NG_POLICY_INHERIT_FORK;
    if (strcmp(str, "BLOCK_URING") == 0) return NG_POLICY_BLOCK_URING;
    if (strcmp(str, "DEPUTY_GUARD") == 0) return NG_POLICY_DEPUTY_GUARD;
    return 0;
}

void ng_policy_manifest_init(struct ng_policy_manifest *manifest)
{
    if (!manifest)
        return;

    memset(manifest, 0, sizeof(*manifest));
    manifest->magic = NG_POLICY_MAGIC;
    manifest->version = NG_POLICY_CURRENT_VERSION;
    manifest->num_domains = NG_MAX_DOMAINS;
    manifest->flags = 0;

    /* Domain 0: Trusted Supervisor (unrestricted) */
    manifest->domains[0].domain_id = 0;
    manifest->domains[0].pku_key = 0;
    manifest->domains[0].policy_flags = NG_POLICY_INHERIT_FORK;
    manifest->domains[0].max_memory_pages = 0; /* Unlimited */
    strncpy((char *)manifest->domains[0].domain_name, "master", sizeof(manifest->domains[0].domain_name) - 1);
    memset(manifest->domains[0].allowed_syscall_mask, 0xFF, sizeof(manifest->domains[0].allowed_syscall_mask));

    /* Domains 1..15: Standard isolated workers with distinct PKU keys */
    for (uint32_t d = 1; d < NG_MAX_DOMAINS; d++) {
        manifest->domains[d].domain_id = d;
        /* Key 1 is strictly reserved for trusted state! Skip Key 1: Domain 1 gets Key 2, etc. */
        manifest->domains[d].pku_key = (d == 1) ? 2 : ((d < 15) ? (d + 1) : 15);
        manifest->domains[d].policy_flags = NG_POLICY_STRICT_WX |
                                           NG_POLICY_BLOCK_PTRACE |
                                           NG_POLICY_BLOCK_PROCFS |
                                           NG_POLICY_BLOCK_BPF |
                                           NG_POLICY_INHERIT_FORK |
                                           NG_POLICY_BLOCK_URING |
                                           NG_POLICY_DEPUTY_GUARD;
        manifest->domains[d].max_memory_pages = (d == 1) ? 1024 : 512;
        snprintf((char *)manifest->domains[d].domain_name, sizeof(manifest->domains[d].domain_name), "domain_%u", d);
        memset(manifest->domains[d].allowed_syscall_mask, 0xFF, sizeof(manifest->domains[d].allowed_syscall_mask));
    }
}

static int parse_domain_object(struct json_scanner *s, struct ng_domain_policy *pol)
{
    struct json_token tok;
    bool has_id = false;

    while (s->cursor < s->len) {
        tok = scan_next_token(s);
        if (tok.type == TOK_RBRACE) {
            break; /* End of domain object */
        }
        if (tok.type == TOK_COMMA) {
            continue;
        }
        if (tok.type != TOK_STRING) {
            return NG_POLICY_ERR_SYNTAX;
        }

        char key_name[64];
        strncpy(key_name, tok.text, sizeof(key_name) - 1);
        key_name[sizeof(key_name) - 1] = '\0';

        tok = scan_next_token(s);
        if (tok.type != TOK_COLON) {
            return NG_POLICY_ERR_SYNTAX;
        }

        if (strcmp(key_name, "id") == 0 || strcmp(key_name, "domain_id") == 0) {
            tok = scan_next_token(s);
            if (tok.type != TOK_NUMBER || tok.num_val < 0 || tok.num_val >= NG_MAX_DOMAINS)
                return NG_POLICY_ERR_DOMAIN_BOUNDS;
            pol->domain_id = (uint32_t)tok.num_val;
            has_id = true;
        } else if (strcmp(key_name, "name") == 0 || strcmp(key_name, "domain_name") == 0) {
            tok = scan_next_token(s);
            if (tok.type != TOK_STRING)
                return NG_POLICY_ERR_SYNTAX;
            strncpy((char *)pol->domain_name, tok.text, sizeof(pol->domain_name) - 1);
            pol->domain_name[sizeof(pol->domain_name) - 1] = '\0';
        } else if (strcmp(key_name, "pku_key") == 0 || strcmp(key_name, "key") == 0) {
            tok = scan_next_token(s);
            if (tok.type != TOK_NUMBER || tok.num_val < 0 || tok.num_val >= 16)
                return NG_POLICY_ERR_SYNTAX;
            pol->pku_key = (uint32_t)tok.num_val;
        } else if (strcmp(key_name, "max_memory_pages") == 0 || strcmp(key_name, "memory_pages") == 0) {
            tok = scan_next_token(s);
            if (tok.type != TOK_NUMBER || tok.num_val < 0)
                return NG_POLICY_ERR_SYNTAX;
            pol->max_memory_pages = (uint32_t)tok.num_val;
        } else if (strcmp(key_name, "flags") == 0) {
            tok = scan_next_token(s);
            if (tok.type == TOK_NUMBER) {
                pol->policy_flags = (uint32_t)tok.num_val;
            } else if (tok.type == TOK_LBRACKET) {
                uint32_t flags = 0;
                while (s->cursor < s->len) {
                    tok = scan_next_token(s);
                    if (tok.type == TOK_RBRACKET)
                        break;
                    if (tok.type == TOK_COMMA)
                        continue;
                    if (tok.type == TOK_STRING) {
                        flags |= parse_flag_string(tok.text);
                    } else if (tok.type == TOK_NUMBER) {
                        flags |= (uint32_t)tok.num_val;
                    }
                }
                pol->policy_flags = flags;
            }
        } else if (strcmp(key_name, "allowed_syscalls") == 0 || strcmp(key_name, "syscalls") == 0) {
            tok = scan_next_token(s);
            if (tok.type == TOK_STRING) {
                if (strcmp(tok.text, "all") == 0 || strcmp(tok.text, "*") == 0) {
                    memset(pol->allowed_syscall_mask, 0xFF, sizeof(pol->allowed_syscall_mask));
                } else if (strcmp(tok.text, "none") == 0) {
                    memset(pol->allowed_syscall_mask, 0, sizeof(pol->allowed_syscall_mask));
                    pol->policy_flags |= NG_POLICY_STRICT_SYSCALL;
                }
            } else if (tok.type == TOK_LBRACKET) {
                /* Explicit array of allowed syscall numbers */
                memset(pol->allowed_syscall_mask, 0, sizeof(pol->allowed_syscall_mask));
                pol->policy_flags |= NG_POLICY_STRICT_SYSCALL;
                while (s->cursor < s->len) {
                    tok = scan_next_token(s);
                    if (tok.type == TOK_RBRACKET)
                        break;
                    if (tok.type == TOK_COMMA)
                        continue;
                    if (tok.type == TOK_NUMBER) {
                        if (tok.num_val >= 0 && tok.num_val < 256) {
                            uint32_t nr = (uint32_t)tok.num_val;
                            pol->allowed_syscall_mask[nr / 64] |= (1ULL << (nr % 64));
                        } else {
                            return NG_POLICY_ERR_OVERFLOW;
                        }
                    }
                }
            }
        } else {
            /* Skip unknown scalar or nested value */
            tok = scan_next_token(s);
            if (tok.type == TOK_LBRACKET || tok.type == TOK_LBRACE) {
                int depth = 1;
                while (s->cursor < s->len && depth > 0) {
                    tok = scan_next_token(s);
                    if (tok.type == TOK_LBRACKET || tok.type == TOK_LBRACE)
                        depth++;
                    else if (tok.type == TOK_RBRACKET || tok.type == TOK_RBRACE)
                        depth--;
                }
            }
        }
    }

    return has_id ? NG_POLICY_OK : NG_POLICY_ERR_SYNTAX;
}

int ng_policy_parse_json(const char *json_str, size_t json_len, struct ng_policy_manifest *manifest)
{
    if (!json_str || !manifest)
        return NG_POLICY_ERR_INVALID;

    if (json_len == 0)
        json_len = strlen(json_str);

    if (json_len > NG_POLICY_MAX_JSON_SIZE)
        return NG_POLICY_ERR_OVERFLOW;

    /* Initialize with baseline defaults */
    ng_policy_manifest_init(manifest);

    struct json_scanner s;
    s.src = json_str;
    s.len = json_len;
    s.cursor = 0;
    s.err = 0;

    struct json_token tok = scan_next_token(&s);
    if (tok.type != TOK_LBRACE)
        return NG_POLICY_ERR_SYNTAX;

    while (s.cursor < s.len) {
        tok = scan_next_token(&s);
        if (tok.type == TOK_RBRACE || tok.type == TOK_EOF)
            break;
        if (tok.type == TOK_COMMA)
            continue;
        if (tok.type != TOK_STRING)
            return NG_POLICY_ERR_SYNTAX;

        char key[64];
        strncpy(key, tok.text, sizeof(key) - 1);
        key[sizeof(key) - 1] = '\0';

        tok = scan_next_token(&s);
        if (tok.type != TOK_COLON)
            return NG_POLICY_ERR_SYNTAX;

        if (strcmp(key, "magic") == 0) {
            tok = scan_next_token(&s);
            if (tok.type == TOK_NUMBER) {
                manifest->magic = (uint32_t)tok.num_val;
            }
        } else if (strcmp(key, "version") == 0) {
            tok = scan_next_token(&s);
            if (tok.type == TOK_NUMBER) {
                manifest->version = (uint32_t)tok.num_val;
            }
        } else if (strcmp(key, "flags") == 0) {
            tok = scan_next_token(&s);
            if (tok.type == TOK_NUMBER) {
                manifest->flags = (uint32_t)tok.num_val;
            }
        } else if (strcmp(key, "domains") == 0) {
            tok = scan_next_token(&s);
            if (tok.type != TOK_LBRACKET)
                return NG_POLICY_ERR_SYNTAX;

            while (s.cursor < s.len) {
                tok = scan_next_token(&s);
                if (tok.type == TOK_RBRACKET)
                    break;
                if (tok.type == TOK_COMMA)
                    continue;
                if (tok.type != TOK_LBRACE)
                    return NG_POLICY_ERR_SYNTAX;

                struct ng_domain_policy parsed_domain;
                memset(&parsed_domain, 0, sizeof(parsed_domain));
                parsed_domain.domain_id = 0xFF; /* unset */

                int res = parse_domain_object(&s, &parsed_domain);
                if (res != NG_POLICY_OK)
                    return res;

                if (parsed_domain.domain_id < NG_MAX_DOMAINS) {
                    manifest->domains[parsed_domain.domain_id] = parsed_domain;
                }
            }
        } else {
            /* Skip unknown token */
            tok = scan_next_token(&s);
        }
    }

    return ng_policy_validate(manifest);
}

int ng_policy_parse_file(const char *filepath, struct ng_policy_manifest *manifest)
{
    if (!filepath || !manifest)
        return NG_POLICY_ERR_INVALID;

    FILE *f = fopen(filepath, "rb");
    if (!f)
        return NG_POLICY_ERR_IO;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NG_POLICY_ERR_IO;
    }

    long fsize = ftell(f);
    if (fsize < 0 || fsize > (long)NG_POLICY_MAX_JSON_SIZE) {
        fclose(f);
        return NG_POLICY_ERR_OVERFLOW;
    }

    rewind(f);

    char *buf = (char *)malloc(fsize + 1);
    if (!buf) {
        fclose(f);
        return NG_POLICY_ERR_NOMEM;
    }

    size_t bytes_read = fread(buf, 1, fsize, f);
    fclose(f);

    if (bytes_read != (size_t)fsize) {
        free(buf);
        return NG_POLICY_ERR_IO;
    }
    buf[fsize] = '\0';

    int ret = ng_policy_parse_json(buf, bytes_read, manifest);
    free(buf);
    return ret;
}

int ng_policy_validate(const struct ng_policy_manifest *manifest)
{
    if (!manifest)
        return NG_POLICY_ERR_INVALID;

    if (manifest->magic != NG_POLICY_MAGIC)
        return NG_POLICY_ERR_SYNTAX;

    if (manifest->version != NG_POLICY_CURRENT_VERSION)
        return NG_POLICY_ERR_SYNTAX;

    /* Invariant 1: Domain 0 (Supervisor) integrity */
    const struct ng_domain_policy *d0 = &manifest->domains[0];
    if (d0->domain_id != 0)
        return NG_POLICY_ERR_SUPERVISOR_LOCK;
    if (d0->pku_key != 0)
        return NG_POLICY_ERR_SUPERVISOR_LOCK;
    if (d0->policy_flags & NG_POLICY_STRICT_SYSCALL)
        return NG_POLICY_ERR_SUPERVISOR_LOCK;

    /* Verify Domain 0 has unrestricted syscall bitmask (all 256 bits set) */
    for (int i = 0; i < 4; i++) {
        if (d0->allowed_syscall_mask[i] != 0xFFFFFFFFFFFFFFFFULL)
            return NG_POLICY_ERR_SUPERVISOR_LOCK;
    }

    /* Invariant 2: Hardware PKU Key 0 & Key 1 Reservation (NG-P4-04 & NG-P4-09) */
    /* Key 0 is host unconfined; Key 1 is strictly dedicated to trusted state.
     * All declared untrusted domains (domain_id >= 1) must allocate distinct keys in [2..15]
     * unless explicitly an unassigned placeholder. */
    for (uint32_t d = 1; d < NG_MAX_DOMAINS; d++) {
        const struct ng_domain_policy *pol = &manifest->domains[d];
        if (pol->domain_id == d) {
            if (pol->pku_key == 1) {
                /* Attack detected: attempting to bind domain to trusted state key */
                return NG_POLICY_ERR_KEY_RESERVED;
            }
            bool is_unassigned = (strncmp((const char *)pol->domain_name, "unassigned", 10) == 0 &&
                                  pol->max_memory_pages == 0);
            if (!is_unassigned && (pol->pku_key < 2 || pol->pku_key > 15)) {
                /* Attack detected: declared untrusted domain attempting to claim Key 0 */
                return NG_POLICY_ERR_KEY_RESERVED;
            }
        }
    }

    /* Invariant 3: Conflicting active keys across distinct isolated domains */
    for (uint32_t i = 1; i < NG_MAX_DOMAINS; i++) {
        if (manifest->domains[i].pku_key == 0)
            continue; /* Inactive or unassigned */
        for (uint32_t j = i + 1; j < NG_MAX_DOMAINS; j++) {
            if (manifest->domains[j].pku_key == 0)
                continue;
            if (manifest->domains[i].pku_key == manifest->domains[j].pku_key) {
                return NG_POLICY_ERR_KEY_CONFLICT;
            }
        }
    }

    return NG_POLICY_OK;
}

int ng_policy_export_json(const struct ng_policy_manifest *manifest, char *out_buf, size_t out_len)
{
    if (!manifest || !out_buf || out_len == 0)
        return NG_POLICY_ERR_INVALID;

    size_t written = 0;
    int n = snprintf(out_buf + written, out_len - written,
                     "{\n"
                     "  \"magic\": \"0x%08X\",\n"
                     "  \"version\": %u,\n"
                     "  \"num_domains\": %u,\n"
                     "  \"flags\": %u,\n"
                     "  \"domains\": [\n",
                     manifest->magic, manifest->version, manifest->num_domains, manifest->flags);
    if (n < 0 || (size_t)n >= out_len - written)
        return NG_POLICY_ERR_NOMEM;
    written += (size_t)n;

    for (uint32_t d = 0; d < manifest->num_domains && d < NG_MAX_DOMAINS; d++) {
        const struct ng_domain_policy *pol = &manifest->domains[d];
        n = snprintf(out_buf + written, out_len - written,
                     "    {\n"
                     "      \"id\": %u,\n"
                     "      \"name\": \"%s\",\n"
                     "      \"pku_key\": %u,\n"
                     "      \"max_memory_pages\": %u,\n"
                     "      \"flags\": %u,\n"
                     "      \"allowed_syscall_mask\": [\"0x%016llx\", \"0x%016llx\", \"0x%016llx\", \"0x%016llx\"]\n"
                     "    }%s\n",
                     pol->domain_id,
                     pol->domain_name[0] ? (const char *)pol->domain_name : "unnamed",
                     pol->pku_key,
                     pol->max_memory_pages,
                     pol->policy_flags,
                     (unsigned long long)pol->allowed_syscall_mask[0],
                     (unsigned long long)pol->allowed_syscall_mask[1],
                     (unsigned long long)pol->allowed_syscall_mask[2],
                     (unsigned long long)pol->allowed_syscall_mask[3],
                     (d + 1 < manifest->num_domains && d + 1 < NG_MAX_DOMAINS) ? "," : "");
        if (n < 0 || (size_t)n >= out_len - written)
            return NG_POLICY_ERR_NOMEM;
        written += (size_t)n;
    }

    n = snprintf(out_buf + written, out_len - written, "  ]\n}\n");
    if (n < 0 || (size_t)n >= out_len - written)
        return NG_POLICY_ERR_NOMEM;
    written += (size_t)n;

    return (int)written;
}

int ng_policy_apply_manifest(const struct ng_policy_manifest *manifest)
{
    if (!manifest)
        return NG_POLICY_ERR_INVALID;

    int valid = ng_policy_validate(manifest);
    if (valid != NG_POLICY_OK)
        return valid;

    for (uint32_t d = 0; d < NG_MAX_DOMAINS; d++) {
        int err = ng_daemon_load_domain_policy(d, &manifest->domains[d]);
        if (err < 0)
            return err;
    }

    return NG_POLICY_OK;
}
