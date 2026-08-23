#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_utils.h"
#include "../dns_wire.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

typedef struct { int alg_num; const char *name; const char *status; } dnssec_alg_info_t;

static const dnssec_alg_info_t KNOWN_DNSSEC_ALGS[] = {
    {1,  "RSAMD5",              "MUST NOT (非推奨・危殆化)"},
    {3,  "DSA",                 "MUST NOT (非推奨)"},
    {5,  "RSASHA1",             "NOT RECOMMENDED"},
    {6,  "DSA-NSEC3-SHA1",      "MUST NOT (非推奨)"},
    {7,  "RSASHA1-NSEC3-SHA1",  "NOT RECOMMENDED"},
    {8,  "RSASHA256",           "MUST"},
    {10, "RSASHA512",           "NOT RECOMMENDED"},
    {12, "ECC-GOST",            "MUST NOT (非推奨)"},
    {13, "ECDSAP256SHA256",     "MUST"},
    {14, "ECDSAP384SHA384",     "MAY"},
    {15, "ED25519",             "RECOMMENDED"},
    {16, "ED448",               "MAY"},
};

static void check_dnssec_algorithm(int alg_num, const char *rec_name, const char *rec_type, int flags, int protocol) {
    // RFC 8078 §4: CDNSKEY delete signal (flags=0, protocol=3, algorithm=0)
    if (strcmp(rec_type, "CDNSKEY") == 0 && alg_num == 0 && flags == 0 && protocol == 3) {
        return;
    }
    for (size_t i = 0; i < sizeof(KNOWN_DNSSEC_ALGS)/sizeof(KNOWN_DNSSEC_ALGS[0]); i++) {
        if (KNOWN_DNSSEC_ALGS[i].alg_num == alg_num) {
            if (strstr(KNOWN_DNSSEC_ALGS[i].status, "MUST NOT") ||
                strstr(KNOWN_DNSSEC_ALGS[i].status, "NOT RECOMMENDED")) {
                fprintf(stderr, "[WARNING] %s '%s': DNSSEC algorithm %d (%s) is %s (RFC 8624)\n",
                        rec_type, rec_name, alg_num, KNOWN_DNSSEC_ALGS[i].name, KNOWN_DNSSEC_ALGS[i].status);
            }
            return;
        }
    }
    fprintf(stderr, "[WARNING] %s '%s': unknown DNSSEC algorithm number %d\n", rec_type, rec_name, alg_num);
}

typedef struct { int digest_type; const char *name; const char *status; } ds_digest_info_t;
static const ds_digest_info_t KNOWN_DS_DIGESTS[] = {
    {1, "SHA-1",            "MUST NOT (非推奨・危殆化, RFC 8624 §3.3)"},
    {2, "SHA-256",          "MUST"},
    {3, "GOST R 34.11-94",  "MUST NOT (非推奨, RFC 8624 §3.3)"},
    {4, "SHA-384",          "MAY"},
};

static void check_ds_digest_type(int digest_type, int algorithm, int key_tag,
                                 const char *rec_name, const char *rec_type) {
    // RFC 8078 §4: CDS delete signal (digest_type=0, algorithm=0, key_tag=0)
    if (strcmp(rec_type, "CDS") == 0 && digest_type == 0 &&
        algorithm == 0 && key_tag == 0) {
        return; // RFC 8078 delete signal: 正当、警告不要
    }
    if (digest_type == 0) {
        fprintf(stderr, "[WARNING] %s '%s': digest type 0 (NULL) is invalid outside of the RFC 8078 CDS delete signal\n",
                rec_type, rec_name);
        return;
    }
    for (size_t i = 0; i < sizeof(KNOWN_DS_DIGESTS)/sizeof(KNOWN_DS_DIGESTS[0]); i++) {
        if (KNOWN_DS_DIGESTS[i].digest_type == digest_type) {
            if (strstr(KNOWN_DS_DIGESTS[i].status, "MUST NOT")) {
                fprintf(stderr, "[WARNING] %s '%s': DS digest type %d (%s) is %s\n",
                        rec_type, rec_name, digest_type,
                        KNOWN_DS_DIGESTS[i].name, KNOWN_DS_DIGESTS[i].status);
            }
            return;
        }
    }
    fprintf(stderr, "[WARNING] %s '%s': unknown DS digest type %d\n", rec_type, rec_name, digest_type);
}

// Stub for open_via_dir_cache used by dns_config_parser.c
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

// Helper to read entire file
static char *read_file_or_die(const char *path, bool *out_failed) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Could not open file: %s (%s)\n", path, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Could not read file: %s\n", path);
        return NULL;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Out of memory reading file: %s\n", path);
        return NULL;
    }
    size_t read_bytes = fread(buf, 1, len, f);
    buf[read_bytes] = '\0';
    fclose(f);
    if (out_failed) *out_failed = false;
    return buf;
}

static char *karicheck_load_file_cb(parse_context_t *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    
    if (out_dev || out_ino) {
        struct stat st;
        if (stat(rel_path, &st) == 0) {
            if (out_dev) *out_dev = st.st_dev;
            if (out_ino) *out_ino = st.st_ino;
        } else {
            return NULL; // fstat failed, fail-closed
        }
    }
    
    return read_file_or_die(rel_path, NULL);
}


// Print error context with caret
static void print_error_context(const char *root_file_path, const char *root_buf, const parse_error_t *err, zone_arena_t *arena) {
    const char *file_path = root_file_path;
    const char *buf = root_buf;

    if (err->file_path) {
        bool found = false;
        for (int i = 0; i < arena->file_buf_count; i++) {
            if (arena->file_paths[i] && strcmp(arena->file_paths[i], err->file_path) == 0) {
                file_path = err->file_path;
                buf = arena->display_bufs[i];
                found = true;
                break;
            }
        }
        if (!found) {
            file_path = root_file_path;
            buf = root_buf;
        }
    }
    if (!buf) return;
    size_t offset = err->error_offset;
    size_t buf_len = strlen(buf);
    if (offset > buf_len) offset = buf_len;

    int line = 1;
    const char *line_start = buf;
    for (size_t i = 0; i < offset; i++) {
        if (buf[i] == '\n') {
            line++;
            line_start = buf + i + 1;
        }
    }

    const char *line_end = line_start;
    while (*line_end && *line_end != '\n' && *line_end != '\r') line_end++;

    fprintf(stderr, "[ERROR] Syntax error in %s at line %d\n", file_path, line);
    fprintf(stderr, "Reason: %s\n\n", err->error_message);

    // Limit line length to 80 chars
    size_t len = line_end - line_start;
    const char *print_start = line_start;
    int caret_pos = offset - (line_start - buf);
    bool clipped_start = false;
    bool clipped_end = false;

    if (len > 80) {
        if (caret_pos > 40) {
            print_start = line_start + caret_pos - 35;
            clipped_start = true;
        }
        if (line_end - print_start > 80) {
            len = 80;
            clipped_end = true;
        } else {
            len = line_end - print_start;
        }
        caret_pos = offset - (print_start - buf);
    }

    fprintf(stderr, "%4d | ", line);
    if (clipped_start) fprintf(stderr, "... ");
    for (size_t i = 0; i < len; i++) {
        char c = print_start[i];
        if (c == '\r' || c == '\n' || c == '\0') break;
        fputc(c, stderr);
    }
    if (clipped_end) fprintf(stderr, " ...");
    fprintf(stderr, "\n");

    fprintf(stderr, "       ");
    if (clipped_start) fprintf(stderr, "    ");
    for (int i = 0; i < caret_pos; i++) fputc(' ', stderr);
    fprintf(stderr, "\033[1;31m^");
    for (size_t i = 1; i < err->token_length && i < 20; i++) fputc('~', stderr);
    fprintf(stderr, "\033[0m\n\n");
}

// Full transitive total order over (canonical name, type, canonical RDATA bytes).
// Because this is a true total order, RRs that compare equal (i.e. true duplicates)
// are guaranteed to be contiguous after qsort(), regardless of qsort's stability.
// Adjacent-after-sort duplicate detection in verify_zonemd() is therefore complete,
// not merely a common-case heuristic. See KariDNS_RFC_GUIDELINE.md, RFC 8976 entry.
static int cmp_canonical_rr(const void *a, const void *b) {
    dns_record_t *r1 = *(dns_record_t **)a;
    dns_record_t *r2 = *(dns_record_t **)b;
    
    int c = compare_canonical_name(r1->name, r2->name);
    if (c != 0) return c;
    
    if (r1->type_code != r2->type_code) return r1->type_code - r2->type_code;
    
    // Same name and type, sort by RDATA canonical format
    uint8_t w1[65535];
    uint8_t w2[65535];
    uint16_t o1 = 0, o2 = 0;
    serialize_dns_record(w1, sizeof(w1), &o1, r1, NULL, NULL, 0xFFFFFFFF);
    serialize_dns_record(w2, sizeof(w2), &o2, r2, NULL, NULL, 0xFFFFFFFF);
    
    // Find RDATA offset by skipping the uncompressed name
    uint16_t idx = 0;
    while(idx < o1 && w1[idx] != 0) {
        idx += w1[idx] + 1;
    }
    idx++; // skip null byte
    idx += 10; // skip Type, Class, TTL, RDLEN
    
    int len1 = o1 > idx ? o1 - idx : 0;
    int len2 = o2 > idx ? o2 - idx : 0;
    int min_len = len1 < len2 ? len1 : len2;
    if (min_len > 0) {
        int mem_c = memcmp(w1 + idx, w2 + idx, min_len);
        if (mem_c != 0) return mem_c;
    }
    return len1 - len2;
}

static bool validate_zonemd_scheme_halg(const dns_record_t *zm, uint8_t *out_scheme,
                                        uint8_t *out_halg, bool warn) {
    if (!zm || zm->rdata_count < 3 || !zm->rdata[1] || !zm->rdata[2]) return false;
    char *scheme_endptr, *halg_endptr;
    long scheme_val = strtol(zm->rdata[1], &scheme_endptr, 10);
    long halg_val = strtol(zm->rdata[2], &halg_endptr, 10);
    if (*scheme_endptr != '\0' || scheme_val < 0 || scheme_val > 255) {
        if (warn) {
            fprintf(stderr, "[WARNING] ZONEMD scheme '%s' is not a valid number (0-255) for name '%s'\n",
                    zm->rdata[1], zm->name);
        }
        return false;
    }
    if (*halg_endptr != '\0' || halg_val < 0 || halg_val > 255) {
        if (warn) {
            fprintf(stderr, "[WARNING] ZONEMD hash algorithm '%s' is not a valid number (0-255) for name '%s'\n",
                    zm->rdata[2], zm->name);
        }
        return false;
    }
    if (out_scheme) *out_scheme = (uint8_t)scheme_val;
    if (out_halg) *out_halg = (uint8_t)halg_val;
    return true;
}

static bool verify_zonemd(const char *domain, zone_arena_t *arena) {
    dns_record_t *zonemds[16];
    int zonemd_count = 0;
    for (size_t i = 0; i < arena->count; i++) {
        if (arena->records[i].type_code == 63 && strcasecmp(arena->records[i].name, domain) == 0) {
            if (zonemd_count < 16) {
                zonemds[zonemd_count++] = &arena->records[i];
            }
        }
    }
    
    if (zonemd_count == 0) return true; // ZONEMD がなければ検証スキップ (OK)
    
    dns_record_t **sorted = malloc(sizeof(dns_record_t *) * arena->count);
    if (!sorted) return false;
    
    size_t valid_count = 0;
    for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *r = &arena->records[i];
        if (r->type_code == 63) continue; // ZONEMD 自身は除外
        
        // Exclude RRSIG covering ZONEMD at apex (RFC 8976 section 3.2)
        if (r->type_code == 46 && strcasecmp(r->name, domain) == 0 &&
            r->rdata_count > 0 && get_type_code(r->rdata[0]) == 63) continue;

        size_t name_len = strlen(r->name);
        size_t domain_len = strlen(domain);
        bool in_bailiwick =
            (name_len == domain_len && strcasecmp(r->name, domain) == 0) ||
            (name_len > domain_len &&
             strcasecmp(r->name + (name_len - domain_len), domain) == 0 &&
             r->name[name_len - domain_len - 1] == '.');
        if (!in_bailiwick) {
            fprintf(stderr, "[WARNING] Zone '%s': out-of-zone record '%s' excluded from ZONEMD digest calculation (RFC 8976 SIMPLE scheme)\n", domain, r->name);
            continue;
        }

        sorted[valid_count++] = r;
    }
    
    qsort(sorted, valid_count, sizeof(dns_record_t *), cmp_canonical_rr);
    
    bool all_valid = true;
    for (int z = 0; z < zonemd_count; z++) {
        dns_record_t *zm = zonemds[z];
        if (zm->rdata_count < 4) {
            continue;
        }
        uint8_t scheme, halg;
        if (!validate_zonemd_scheme_halg(zm, &scheme, &halg, false)) {
            continue;
        }
        
        if (scheme != 1) continue; 
        if (halg != 1 && halg != 2) continue; 
        
        const EVP_MD *md_type = (halg == 1) ? EVP_sha384() : EVP_sha512();
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md_type, NULL);
        
        uint8_t wire_buf[65535];
        uint8_t prev_wire_buf[65535];
        uint16_t prev_offset = 0;
        for (size_t i = 0; i < valid_count; i++) {
            uint16_t offset = 0;
            if (serialize_dns_record(wire_buf, sizeof(wire_buf), &offset, sorted[i], NULL, NULL, 0xFFFFFFFF) == 0) {
                if (prev_offset > 0 && prev_offset == offset && memcmp(prev_wire_buf, wire_buf, offset) == 0) {
                    continue;
                }
                EVP_DigestUpdate(mdctx, wire_buf, offset);
                memcpy(prev_wire_buf, wire_buf, offset);
                prev_offset = offset;
            }
        }
        
        uint8_t hash_out[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        EVP_DigestFinal_ex(mdctx, hash_out, &hash_len);
        EVP_MD_CTX_free(mdctx);
        
        uint8_t expected[EVP_MAX_MD_SIZE];
        char hex[2048] = "";
        size_t hex_len = 0;
        for (int i = 3; i < zm->rdata_count; i++) {
            size_t flen = strlen(zm->rdata[i]);
            if (hex_len + flen >= sizeof(hex)) break;
            memcpy(hex + hex_len, zm->rdata[i], flen);
            hex_len += flen;
            hex[hex_len] = '\0';
        }
        
        size_t exp_len = hex_decode(hex, expected, sizeof(expected));
        
        if (exp_len == hash_len && memcmp(hash_out, expected, hash_len) == 0) {
            fprintf(stdout, "[OK] ZONEMD (Scheme %d, Hash %d) for '%s' is VALID.\n", scheme, halg, domain);
        } else {
            fprintf(stderr, "[FAIL] ZONEMD (Scheme %d, Hash %d) for '%s' is INVALID.\n", scheme, halg, domain);
            fprintf(stderr, "       Expected: %s\n", hex);
            fprintf(stderr, "       Computed: ");
            for (unsigned int j = 0; j < hash_len; j++) fprintf(stderr, "%02x", hash_out[j]);
            fprintf(stderr, "\n");
            all_valid = false;
        }
    }
    
    free(sorted);
    return all_valid;
}

static bool is_cname(zone_arena_t *arena, const char *name) {
    if (!arena->hash_table || arena->hash_size == 0) return false;
    uint32_t hash = calc_fnv1a_str(name);
    size_t idx = hash & (arena->hash_size - 1);
    for (int j = arena->hash_table[idx]; j != -1; j = arena->records[j].next_record) {
        if (arena->records[j].type_code == 5 && strcasecmp(arena->records[j].name, name) == 0) {
            return true;
        }
    }
    return false;
}

static void normalize_domain_fqdn(const char *in, char *out, size_t out_cap) {
    size_t len = strlen(in);
    if (len > 0 && in[len - 1] != '.' && len + 1 < out_cap) {
        memcpy(out, in, len);
        out[len] = '.';
        out[len + 1] = '\0';
    } else {
        snprintf(out, out_cap, "%s", in);
    }
}

static int check_zone(const char *domain_raw, const char *file_path, bool is_standalone, bool is_catalog) {
    // Normalize domain to FQDN: append trailing dot if missing.
    // Without this, "example.com" wouldn't match records expanded to "example.com."
    char domain_buf[256];
    normalize_domain_fqdn(domain_raw, domain_buf, sizeof(domain_buf));
    const char *domain = domain_buf;

    if (is_standalone) {
        if (file_path[0] == '/' || strstr(file_path, "../")) {
            fprintf(stderr, "[WARNING] The zone file path given on the command line is absolute "
                             "or contains '../'. This is resolved directly against the host "
                             "filesystem in standalone karicheck, but the real server resolves "
                             "zone 'file' paths relative to its sandboxed base directory under "
                             "KariDNS's Capsicum sandbox — behavior may differ there.\n");
        }
    }

    bool failed = false;
    char *buf = read_file_or_die(file_path, &failed);
    if (failed || !buf) return 1;

    char *mutable_buf = strdup(buf);
    if (!mutable_buf) {
        free(buf);
        fprintf(stderr, "[ERROR] Out of memory\n");
        return 1;
    }

    zone_arena_t arena;
    zone_arena_init(&arena);

    arena.file_bufs[0] = mutable_buf;
    arena.display_bufs[0] = (char*)buf;
    arena.file_paths[0] = strdup(file_path);
    if (!arena.file_paths[0]) {
        free(mutable_buf);
        return 1;
    }
    arena.file_buf_count = 1;

    parse_error_t err = {0};
    char *root_ttl = NULL;
    char *visited_paths[16];
    dev_t visited_devs[16];
    ino_t visited_inos[16];
    char *root_path = realpath(file_path, NULL);
    if (!root_path) root_path = strdup(file_path);

    char *base_dir = get_base_dir(file_path);
    if (!base_dir) {
        fprintf(stderr, "[ERROR] Out of memory allocating base_dir\n");
        free(root_path);
        return 1;
    }
    
    dev_t root_dev = 0;
    ino_t root_ino = 0;
    struct stat root_st;
    if (stat(file_path, &root_st) == 0) {
        root_dev = root_st.st_dev;
        root_ino = root_st.st_ino;
    } else {
        fprintf(stderr, "Failed to stat root zone file: %s\n", file_path);
        free((void*)base_dir);
        free(root_path);
        return 1;
    }

    parse_context_t ctx = {
        .base_dir = base_dir,
        .default_origin = domain,
        .is_standalone_mode = is_standalone,
        .err_out = &err,
        .current_depth = 0,
        .visited_paths = visited_paths,
        .visited_devs = visited_devs,
        .visited_inos = visited_inos,
        .visited_count = 1,
        .visited_cap = 16,
        .load_file_cb = karicheck_load_file_cb,
        .shared_ttl_io = &root_ttl
    };
    ctx.visited_paths[0] = root_path;
    ctx.visited_devs[0] = root_dev;
    ctx.visited_inos[0] = root_ino;

    int res = parse_zone_fast(mutable_buf, strlen(mutable_buf), &arena, &ctx);
    if (res < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    if (arena.count == 0) {
        fprintf(stderr, "[ERROR] No records found in zone '%s' (%s)\n", domain, file_path);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    if (build_zone_index(&arena) != 0) {
        fprintf(stderr, "[ERROR] Memory allocation failed during index build for '%s'\n", domain);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }
    if (validate_zone_dname(&arena, &err) < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }
    if (validate_zone_name_lengths(&arena, &err) < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    fprintf(stdout, "[OK] Zone '%s' parsed successfully (%zu records)\n", domain, arena.count);
    bool has_soa = false;
    bool error_found = false;
    for (size_t i = 0; i < arena.count; i++) {
        uint16_t tcode = arena.records[i].type_code;
        int rcount = arena.records[i].rdata_count;
        char **rdata = arena.records[i].rdata;

        if (tcode == 1) { // A
            if (rcount != 1) {
                fprintf(stderr, "[ERROR] A record must have exactly 1 parameter for name '%s' in zone '%s'\n", arena.records[i].name, domain);
                error_found = true;
            } else {
                struct in_addr tmp;
                if (inet_pton(AF_INET, rdata[0], &tmp) != 1) {
                    fprintf(stderr, "[ERROR] Invalid IPv4 address '%s' for name '%s' in zone '%s'\n", rdata[0], arena.records[i].name, domain);
                    error_found = true;
                }
            }
        }
        if (tcode == 28) { // AAAA
            if (rcount != 1) {
                fprintf(stderr, "[ERROR] AAAA record must have exactly 1 parameter for name '%s' in zone '%s'\n", arena.records[i].name, domain);
                error_found = true;
            } else {
                struct in6_addr tmp;
                if (inet_pton(AF_INET6, rdata[0], &tmp) != 1) {
                    fprintf(stderr, "[ERROR] Invalid IPv6 address '%s' for name '%s' in zone '%s'\n", rdata[0], arena.records[i].name, domain);
                    error_found = true;
                }
            }
        }

        if (tcode == 6 && strcasecmp(arena.records[i].name, domain) == 0) {
            has_soa = true;
        }
        if (tcode == 62) { // CSYNC
            for (int j = 2; j < rcount; j++) {
                if (get_type_code(rdata[j]) == 0) {
                    fprintf(stderr, "[WARNING] CSYNC record contains unknown type '%s' in zone '%s' (%s)\n", rdata[j], domain, file_path);
                }
            }
        }
        if (tcode == 64 || tcode == 65) { // SVCB / HTTPS
            if (rcount > 1) {
                const char *target = rdata[1];
                size_t len = strlen(target);
                if (len > 0 && target[len - 1] != '.' && strcmp(target, ".") != 0) {
                    fprintf(stderr, "[WARNING] %s record TargetName '%s' does not end with a dot in zone '%s' (%s)\n",
                            tcode == 64 ? "SVCB" : "HTTPS",
                            target, domain, file_path);
                }
            }
        }
        
        // --- Add specific field validations ---
        if (tcode == 63) { // ZONEMD
            if (strcasecmp(arena.records[i].name, domain) != 0) {
                fprintf(stderr, "[WARNING] ZONEMD record '%s' is not at the zone apex '%s' (RFC 8976 section 2.1)\n",
                        arena.records[i].name, domain);
            }
            if (rcount < 4) {
                fprintf(stderr, "[WARNING] ZONEMD record for '%s' has fewer than 4 fields "
                                "(serial, scheme, hash-algorithm, digest)\n", arena.records[i].name);
            } else {
                validate_zonemd_scheme_halg(&arena.records[i], NULL, NULL, true);
            }
        }
        if (tcode == 48 || tcode == 60) { // DNSKEY / CDNSKEY
            if (rcount >= 3) {
                int flags = (int)strtol(rdata[0], NULL, 10);
                int protocol = (int)strtol(rdata[1], NULL, 10);
                int alg = (int)strtol(rdata[2], NULL, 10);
                check_dnssec_algorithm(alg, arena.records[i].name, tcode == 48 ? "DNSKEY" : "CDNSKEY", flags, protocol);
            }
        }
        if (tcode == 43 || tcode == 59) { // DS / CDS
            if (rcount >= 4) {
                int key_tag = (int)strtol(rdata[0], NULL, 10);
                int algorithm = (int)strtol(rdata[1], NULL, 10);
                int digest_type = (int)strtol(rdata[2], NULL, 10);
                check_ds_digest_type(digest_type, algorithm, key_tag,
                                     arena.records[i].name, tcode == 43 ? "DS" : "CDS");
            }
        }
        if (tcode == 46) { // RRSIG
            if (rcount >= 2) {
                check_dnssec_algorithm((int)strtol(rdata[1], NULL, 10), arena.records[i].name, "RRSIG", -1, -1);
            }
        }
        if (tcode == 55) { // HIP
            if (rcount < 3) {
                fprintf(stderr, "[WARNING] HIP record requires at least 3 fields: HIT algorithm, HIT (hex), and public key (base64) for name '%s'\n", arena.records[i].name);
            }
        }
        if (tcode == 11) { // WKS
            if (rcount >= 2) {
                char *endptr;
                long proto = strtol(rdata[1], &endptr, 10);
                if (*endptr != '\0' || proto < 0 || proto > 255) {
                    fprintf(stderr, "[WARNING] WKS record protocol '%s' is not a valid number (0-255) for name '%s'\n", rdata[1], arena.records[i].name);
                }
            }
        }
        if (tcode == 27 && rcount < 3) { // GPOS
            fprintf(stderr, "[WARNING] GPOS record requires exactly 3 fields (Longitude, Latitude, Altitude) for name '%s'\n", arena.records[i].name);
        }
        if (tcode == 19 && rcount < 1) { // X25
            fprintf(stderr, "[WARNING] X25 record requires at least 1 field for name '%s'\n", arena.records[i].name);
        }

        // --- RFC 1912 Operational Checks ---
        if (tcode == 15 && rcount >= 2) { // MX
            if (is_cname(&arena, rdata[1])) {
                fprintf(stderr, "[WARNING] MX record for '%s' points to a CNAME '%s' (RFC 1912)\n", arena.records[i].name, rdata[1]);
            }
        }
        if (tcode == 2 && rcount >= 1) { // NS
            if (is_cname(&arena, rdata[0])) {
                fprintf(stderr, "[WARNING] NS record for '%s' points to a CNAME '%s' (RFC 1912)\n", arena.records[i].name, rdata[0]);
            }
        }
        if (tcode == 6 && rcount >= 2) { // SOA
            if (is_cname(&arena, rdata[0])) {
                fprintf(stderr, "[WARNING] SOA MNAME for '%s' points to a CNAME '%s' (RFC 1912)\n", arena.records[i].name, rdata[0]);
            }
        }
        if (tcode == 5) { // CNAME
            if (arena.hash_table && arena.hash_size > 0) {
                uint32_t hash = calc_fnv1a_str(arena.records[i].name);
                size_t idx = hash & (arena.hash_size - 1);
                for (int j = arena.hash_table[idx]; j != -1; j = arena.records[j].next_record) {
                    if (i != (size_t)j && strcasecmp(arena.records[j].name, arena.records[i].name) == 0) {
                        uint16_t other = arena.records[j].type_code;
                        // Ignore DNSSEC records
                        if (other != 5 && other != 46 && other != 47 && other != 50) {
                            fprintf(stderr, "[WARNING] CNAME '%s' co-exists with other records (type %d) (RFC 1912)\n", arena.records[i].name, other);
                            break;
                        }
                    }
                }
            }
        }
        
        if (tcode == 20 && (rcount < 1 || rcount > 2)) { // ISDN
            fprintf(stderr, "[WARNING] ISDN record requires 1 or 2 fields for name '%s'\n", arena.records[i].name);
        }
        if (tcode == 108 || tcode == 109) { // EUI48 / EUI64
            if (rcount >= 1) {
                int dashes = 0;
                for (const char *p = rdata[0]; *p; p++) {
                    if (*p == '-') dashes++;
                }
                if (tcode == 108 && dashes != 5) {
                    fprintf(stderr, "[WARNING] EUI48 requires 6 octets (5 dashes) for name '%s'\n", arena.records[i].name);
                } else if (tcode == 109 && dashes != 7) {
                    fprintf(stderr, "[WARNING] EUI64 requires 8 octets (7 dashes) for name '%s'\n", arena.records[i].name);
                }
            }
        }

        // NXNAME (128, RFC 9824) is a Meta-Type: must NOT appear as standalone RRset.
        if (tcode == 128) {
            fprintf(stderr, "[ERROR] NXNAME (128) is a meta-type (RFC 9824) and must not appear "
                    "as a standalone RRset in zone '%s' (name '%s')\n", domain, arena.records[i].name);
            error_found = true;
        }

        // DSYNC (66, RFC 9859): validate RRtype mnemonic
        if (tcode == 66 && rcount >= 1) {
            if (get_type_code(rdata[0]) == 0) {
                fprintf(stderr, "[WARNING] DSYNC record has unknown RRtype mnemonic '%s' for name '%s'\n",
                        rdata[0], arena.records[i].name);
            }
        }

        if (tcode == 50 || tcode == 51) { // NSEC3 / NSEC3PARAM
            if (rcount >= 3) {
                int algo = (int)strtol(rdata[0], NULL, 10);
                int flags = (int)strtol(rdata[1], NULL, 10);
                int iterations = (int)strtol(rdata[2], NULL, 10);
                if (algo != 1) {
                    fprintf(stderr, "[WARNING] NSEC3/NSEC3PARAM hash algorithm should be 1 (SHA-1); other values are undefined (RFC 5155) for name '%s'\n", arena.records[i].name);
                }
                if (flags & ~0x01) {
                    fprintf(stderr, "[WARNING] NSEC3/NSEC3PARAM flags field has reserved bits set; only bit 0 (opt-out) is defined (RFC 5155 Section 3.1.2) for name '%s'\n", arena.records[i].name);
                }
                if (tcode == 50 && (flags & 0x01)) {
                    fprintf(stderr, "[WARNING] NSEC3 opt-out is set; RFC 9276 recommends opt-out only for large, sparsely-signed zones for name '%s'\n", arena.records[i].name);
                }
                if (tcode == 51 && (flags & 0x01)) {
                    fprintf(stderr, "[ERROR] NSEC3PARAM must not have the opt-out flag set (RFC 5155 Section 11); it is only meaningful on NSEC3 records for name '%s'\n", arena.records[i].name);
                    error_found = true;
                }
                if (iterations > 0) {
                    fprintf(stderr, "[WARNING] NSEC3/NSEC3PARAM iterations should be 0 (RFC 9276); non-zero iterations increase CPU-exhaustion DoS risk with little security benefit for name '%s'\n", arena.records[i].name);
                }
                if (iterations > 100) {
                    fprintf(stderr, "[ERROR] NSEC3/NSEC3PARAM iterations value is excessively high and may cause severe performance/DoS issues for name '%s'\n", arena.records[i].name);
                    error_found = true;
                }
            }
        }

        // --- Dry-run serialize_dns_record ---
        uint8_t scratch[65535];
        uint16_t scratch_offset = 0;
        compress_ctx_t comp_ctx;
        memset(&comp_ctx, 0, sizeof(comp_ctx));
        compress_ctx_init_packet(&comp_ctx);
        int wire_result = serialize_dns_record(
            scratch, sizeof(scratch), &scratch_offset,
            &arena.records[i], &comp_ctx,
            NULL,          // owner_name: NULL
            0xFFFFFFFF     // override_ttl: use record TTL
        );
        if (wire_result < 0) {
            fprintf(stderr,
                "[ERROR] Record '%s %s' at index %zu cannot be serialized to wire format "
                "(this record would fail or be dropped when the server answers a real query). "
                "Check field count and value ranges for this record type.\n",
                arena.records[i].name, arena.records[i].type, i);
            error_found = true;
        }
    }

    if (!has_soa) {
        fprintf(stderr, "[ERROR] No SOA record found in zone '%s' (%s) at origin\n", domain, file_path);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    if (is_catalog) {
        char version_txt[256];
        snprintf(version_txt, sizeof(version_txt), "version.%s", domain);
        bool found_version = false;
        for (size_t i = 0; i < arena.count; i++) {
            if (arena.records[i].type_code == 16 && strcasecmp(arena.records[i].name, version_txt) == 0) {
                if (arena.records[i].rdata_count > 0 && strcmp(arena.records[i].rdata[0], "2") == 0) {
                    found_version = true;
                    break;
                }
            }
        }
        if (!found_version) {
            fprintf(stderr, "[ERROR] Catalog zone '%s' is missing '%s TXT \"2\"'\n", domain, version_txt);
            error_found = true;
        }

        // Check for orphaned group TXT records
        char group_prefix[10] = "group.";
        char zones_suffix[256];
        snprintf(zones_suffix, sizeof(zones_suffix), ".zones.%s", domain);
        size_t zones_suffix_len = strlen(zones_suffix);
        for (size_t i = 0; i < arena.count; i++) {
            if (arena.records[i].type_code == 16) { // TXT
                size_t name_len = strlen(arena.records[i].name);
                if (name_len > 6 && strncasecmp(arena.records[i].name, group_prefix, 6) == 0) {
                    if (name_len > zones_suffix_len && strcasecmp(arena.records[i].name + name_len - zones_suffix_len, zones_suffix) == 0) {
                        // This is a group.<unique-N>.zones.$CATZ record. Check if PTR exists for <unique-N>.zones.$CATZ
                        size_t ptr_name_len = name_len - 6;
                        char ptr_name[512];
                        if (ptr_name_len >= sizeof(ptr_name)) {
                            fprintf(stderr,
                                    "[ERROR] Catalog zone '%s': owner name '%s' is too long to process (unique-id part exceeds %zu bytes); skipping orphan check for this record\n",
                                    domain, arena.records[i].name, sizeof(ptr_name) - 1);
                            error_found = true;
                            continue; // このTXTレコードについてはスキップし、境界外書き込みを回避
                        }
                        strncpy(ptr_name, arena.records[i].name + 6, ptr_name_len);
                        ptr_name[ptr_name_len] = '\0';
                        
                        bool has_ptr = false;
                        for (size_t j = 0; j < arena.count; j++) {
                            if (arena.records[j].type_code == 12 && strcasecmp(arena.records[j].name, ptr_name) == 0) {
                                has_ptr = true;
                                break;
                            }
                        }
                        if (!has_ptr) {
                            fprintf(stderr, "[WARNING] Orphaned group TXT record '%s' (no corresponding PTR record '%s')\n", arena.records[i].name, ptr_name);
                        }
                    }
                }
            }
        }
    }

    if (error_found) {
        fprintf(stderr, "[FAIL] Zone '%s' contains invalid records.\n", domain);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena); // frees mutable_buf via arena.file_bufs[0]; do not free() it again here
        free(root_path);
        return 1;
    }

    if (!verify_zonemd(domain, &arena)) {
        fprintf(stderr, "[FAIL] Zone '%s' failed ZONEMD verification.\n", domain);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    printf("[OK] Zone '%s' is valid.\n", domain);
    free((void*)ctx.base_dir);
    zone_arena_destroy(&arena);
    free(root_path);
    return 0;
}

static int check_config(const char *config_path, server_config_t *cfg) {
    printf("[INFO] Loading config %s...\n", config_path);
    bool failed = false;
    char *buf = read_file_or_die(config_path, &failed);
    if (failed || !buf) return 1;

    if (parse_named_conf_ext(buf, config_path, cfg) != 0) {
        fprintf(stderr, "[ERROR] Syntax error in config file: %s\n", config_path);
        free(buf);
        return 1;
    }
    printf("[OK] Config file %s is valid.\n", config_path);
    free(buf);
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s conf [config_path]\n", prog);
    fprintf(stderr, "  %s zones [config_path]\n", prog);
    fprintf(stderr, "  %s zone <domain> [config_path]\n", prog);
    fprintf(stderr, "  %s zone <domain> <zone_file_path>\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *default_config = "/usr/local/etc/karidns.conf";

    if (strcmp(cmd, "conf") == 0) {
        const char *cfg_path = (argc >= 3) ? argv[2] : default_config;
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        return check_config(cfg_path, &cfg);
    } else if (strcmp(cmd, "zones") == 0) {
        const char *cfg_path = (argc >= 3) ? argv[2] : default_config;
        server_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        if (check_config(cfg_path, &cfg) != 0) return 1;

        int error_count = 0;
        int checked = 0;
        zone_config_t *z = cfg.zones;
        while (z) {
            if (!z->type || (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0)) {
                if (check_zone(z->domain, z->file, false, z->is_catalog) != 0) {
                    error_count++;
                }
                checked++;
            }
            z = z->next;
        }
        printf("[INFO] Checked %d zones. Errors: %d\n", checked, error_count);
        return (error_count > 0) ? 1 : 0;
    } else if (strcmp(cmd, "zone") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        const char *domain = argv[2];
        if (argc >= 4 && strstr(argv[3], ".conf") == NULL && strstr(argv[3], "/") != NULL) {
            // Standalone mode: karicheck zone <domain> <zone_file_path>
            return check_zone(domain, argv[3], true, false);
        } else {
            // From config: karicheck zone <domain> [config_path]
            const char *cfg_path = (argc >= 4) ? argv[3] : default_config;
            server_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            if (check_config(cfg_path, &cfg) != 0) return 1;

            // Normalize domain for comparison (config parser adds trailing dot)
            char norm_domain[256];
            normalize_domain_fqdn(domain, norm_domain, sizeof(norm_domain));

            zone_config_t *z = cfg.zones;
            while (z) {
                if (strcasecmp(z->domain, norm_domain) == 0) {
                    return check_zone(z->domain, z->file, false, z->is_catalog);
                }
                z = z->next;
            }
            fprintf(stderr, "[ERROR] Zone '%s' not found in config %s\n", domain, cfg_path);
            return 1;
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}
