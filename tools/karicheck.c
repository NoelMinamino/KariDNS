#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
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
#include "karidns_tool_linkage.h"

/* K-04: ゾーンの検査中に出す [ERROR] / [WARNING] は全て kc_error() / kc_warning() を通して数え、
 * [RESULT] の件数を出力した行と一致させる。t == NULL なら数えずに出力だけする。 */
typedef struct { int errors; int warnings; } kc_tally_t;

static void kc_vreport(int *counter, const char *tag, const char *fmt, va_list ap) {
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, ap);
    if (counter) (*counter)++;
}

KARIDNS_TOOL_FN void kc_error(kc_tally_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
KARIDNS_TOOL_FN void kc_error(kc_tally_t *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vreport(t ? &t->errors : NULL, "ERROR", fmt, ap);
    va_end(ap);
}

KARIDNS_TOOL_FN void kc_warning(kc_tally_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
KARIDNS_TOOL_FN void kc_warning(kc_tally_t *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vreport(t ? &t->warnings : NULL, "WARNING", fmt, ap);
    va_end(ap);
}

/* [T6] RFC 2181 §5.2 TTL不整合検出用ソート比較関数
 * build_zone_index() 実行前の生データを qsort で正規化前に冗丸を検出する */
KARIDNS_TOOL_FN int cmp_rec_by_name_type(const void *pa, const void *pb) {
    const dns_record_t *ra = *(const dns_record_t **)pa;
    const dns_record_t *rb = *(const dns_record_t **)pb;
    if (!ra->name || !rb->name) return ra->name ? 1 : (rb->name ? -1 : 0);
    int c = strcasecmp(ra->name, rb->name);
    if (c != 0) return c;
    if (ra->type_code != rb->type_code) return (ra->type_code < rb->type_code) ? -1 : 1;
    return 0;
}

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
    {18, "MLDSA44",             "MAY"},  // draft-westerbaan-dnssec-mldsa (IANA: MAY for signing and validation)
};

KARIDNS_TOOL_FN void check_dnssec_algorithm(kc_tally_t *t, int alg_num, const char *rec_name, const char *rec_type, int flags, int protocol) {
    // RFC 8078 §4: CDNSKEY delete signal (flags=0, protocol=3, algorithm=0)
    if (strcmp(rec_type, "CDNSKEY") == 0 && alg_num == 0 && flags == 0 && protocol == 3) {
        return;
    }
    for (size_t i = 0; i < sizeof(KNOWN_DNSSEC_ALGS)/sizeof(KNOWN_DNSSEC_ALGS[0]); i++) {
        if (KNOWN_DNSSEC_ALGS[i].alg_num == alg_num) {
            if (strstr(KNOWN_DNSSEC_ALGS[i].status, "MUST NOT") ||
                strstr(KNOWN_DNSSEC_ALGS[i].status, "NOT RECOMMENDED")) {
                kc_warning(t, "%s '%s': DNSSEC algorithm %d (%s) is %s (RFC 8624)\n",
                        rec_type, rec_name, alg_num, KNOWN_DNSSEC_ALGS[i].name, KNOWN_DNSSEC_ALGS[i].status);
            }
            return;
        }
    }
    kc_warning(t, "%s '%s': unknown DNSSEC algorithm number %d\n", rec_type, rec_name, alg_num);
}

/* Decoded length of base64 text split over several fields (whitespace inside the value is allowed), or -1 when the
 * text is not a whole number of base64 quanta. */
static long b64_fields_decoded_len(char *const *fields, int count) {
    size_t chars = 0, pad = 0;
    for (int i = 0; i < count; i++) {
        for (const char *c = fields[i]; *c; c++) {
            if (*c == '=') pad++;
            else if (isalnum((unsigned char)*c) || *c == '+' || *c == '/') { if (pad) return -1; }
            else return -1;
            chars++;
        }
    }
    if (chars == 0 || chars % 4 != 0 || pad > 2) return -1;
    return (long)(chars / 4 * 3 - pad);
}

/* Algorithms whose public key / signature has a fixed size: a DNSKEY or RRSIG of another size cannot validate.
 * ML-DSA-44 (algorithm 18, draft-westerbaan-dnssec-mldsa): 1312-octet public key, 2420-octet signature. */
KARIDNS_TOOL_FN void check_dnssec_blob_length(kc_tally_t *t, int alg_num, const char *rec_name, const char *rec_type,
                                              bool is_signature, char *const *fields, int count) {
    long want;
    if (alg_num == 18) want = is_signature ? 2420 : 1312;
    else return;
    long got = b64_fields_decoded_len(fields, count);
    if (got < 0) {
        kc_warning(t, "%s '%s': %s is not valid base64\n", rec_type, rec_name, is_signature ? "signature" : "public key");
    } else if (got != want) {
        kc_warning(t, "%s '%s': algorithm %d (MLDSA44) %s must be %ld octets, found %ld "
                      "(draft-westerbaan-dnssec-mldsa)\n",
                   rec_type, rec_name, alg_num, is_signature ? "signature" : "public key", want, got);
    }
}

typedef struct { int digest_type; const char *name; const char *status; } ds_digest_info_t;
static const ds_digest_info_t KNOWN_DS_DIGESTS[] = {
    {1, "SHA-1",            "MUST NOT (非推奨・危殆化, RFC 8624 §3.3)"},
    {2, "SHA-256",          "MUST"},
    {3, "GOST R 34.11-94",  "MUST NOT (非推奨, RFC 8624 §3.3)"},
    {4, "SHA-384",          "MAY"},
};

KARIDNS_TOOL_FN void check_ds_digest_type(kc_tally_t *t, int digest_type, int algorithm, int key_tag,
                                 const char *rec_name, const char *rec_type) {
    // RFC 8078 §4: CDS delete signal (digest_type=0, algorithm=0, key_tag=0)
    if (strcmp(rec_type, "CDS") == 0 && digest_type == 0 &&
        algorithm == 0 && key_tag == 0) {
        return; // RFC 8078 delete signal: 正当、警告不要
    }
    if (digest_type == 0) {
        kc_warning(t, "%s '%s': digest type 0 (NULL) is invalid outside of the RFC 8078 CDS delete signal\n",
                rec_type, rec_name);
        return;
    }
    for (size_t i = 0; i < sizeof(KNOWN_DS_DIGESTS)/sizeof(KNOWN_DS_DIGESTS[0]); i++) {
        if (KNOWN_DS_DIGESTS[i].digest_type == digest_type) {
            if (strstr(KNOWN_DS_DIGESTS[i].status, "MUST NOT")) {
                kc_warning(t, "%s '%s': DS digest type %d (%s) is %s\n",
                        rec_type, rec_name, digest_type,
                        KNOWN_DS_DIGESTS[i].name, KNOWN_DS_DIGESTS[i].status);
            }
            return;
        }
    }
    kc_warning(t, "%s '%s': unknown DS digest type %d\n", rec_type, rec_name, digest_type);
}

// Stub for open_via_dir_cache used by dns_config_parser.c
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

// Helper to read entire file
KARIDNS_TOOL_FN char *read_file_or_die(const char *path, bool *out_failed) {
    FILE *f = fopen(path, "r");
    if (!f) {
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Could not open file: %s (%s)\n", path, strerror(errno));
        return NULL;
    }
    /* A directory (or FIFO/device) opens fine on some systems, but its ftell()
     * result is meaningless (e.g. LONG_MAX for a directory on Linux), which
     * would overflow the "len + 1" allocation below. Require a regular file. */
    struct stat st;
    if (fstat(fileno(f), &st) != 0 || !S_ISREG(st.st_mode)) {
        fclose(f);
        if (out_failed) *out_failed = true;
        fprintf(stderr, "[ERROR] Not a regular file: %s\n", path);
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

KARIDNS_TOOL_FN char *karicheck_load_file_cb(parse_context_t *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino) {
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
KARIDNS_TOOL_FN void print_error_context(const char *root_file_path, const char *root_buf, const parse_error_t *err, zone_arena_t *arena) {
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

/* RFC 4034 §6.2 の正規形の RR 1 件 (名前は非圧縮、所有者名と item 3 の型の RDATA 内の名前は小文字)。 */
typedef struct {
    const dns_record_t *rec;
    uint8_t *wire;      /* 所有者名, TYPE, CLASS, TTL, RDLENGTH, RDATA */
    uint16_t len;
    uint16_t rdata_off;
} kc_canon_rr_t;

KARIDNS_TOOL_FN bool kc_canonical_rr(const dns_record_t *rec, kc_canon_rr_t *out) {
    uint8_t buf[65535];
    uint16_t len = 0;
    /* owner_name を渡すと所有者名は write_uncompressed_name() で小文字の非圧縮形になる
     * (rec->name_wire は元の大文字小文字のまま) */
    if (serialize_dns_record(buf, sizeof(buf), &len, rec, NULL, rec->name, 0xFFFFFFFF) != 0) return false;
    size_t owner = 0;
    while (owner < len && buf[owner] != 0) owner += 1 + (size_t)buf[owner];
    owner++;
    if (owner + 10 > len) return false;
    size_t rdlen = ((size_t)buf[owner + 8] << 8) | buf[owner + 9];
    if (owner + 10 + rdlen != len) return false;
    /* RFC 4034 §6.2 item 3 の型の RDATA 内の名前を小文字に (K-01。共通関数は dns_wire.c) */
    dns_canonical_downcase_rdata(rec->type_code, buf + owner + 10, rdlen);
    out->wire = malloc(len);
    if (!out->wire) return false;
    memcpy(out->wire, buf, len);
    out->rec = rec;
    out->len = len;
    out->rdata_off = (uint16_t)(owner + 10);
    return true;
}

/* RFC 4034 §6.1 (所有者名)、RFC 8976 §3.3.1 (同じ所有者名の RRset は TYPE の昇順)、RFC 4034 §6.3 (RDATA を
 * 左詰めのオクテット列として比べ、短い方が先)。全順序なので、重複した RR は qsort() 後に必ず隣り合う。 */
KARIDNS_TOOL_FN int kc_cmp_canon_rr(const void *a, const void *b) {
    const kc_canon_rr_t *x = a, *y = b;
    int c = compare_canonical_name(x->rec->name, y->rec->name);
    if (c != 0) return c;
    if (x->rec->type_code != y->rec->type_code) return x->rec->type_code < y->rec->type_code ? -1 : 1;
    size_t lx = (size_t)(x->len - x->rdata_off), ly = (size_t)(y->len - y->rdata_off);
    int m = memcmp(x->wire + x->rdata_off, y->wire + y->rdata_off, lx < ly ? lx : ly);
    if (m != 0) return m;
    return lx < ly ? -1 : (lx > ly ? 1 : 0);
}

KARIDNS_TOOL_FN bool validate_zonemd_scheme_halg(const dns_record_t *zm, uint8_t *out_scheme,
                                        uint8_t *out_halg, bool warn, kc_tally_t *t) {
    if (!zm || zm->rdata_count < 3 || !zm->rdata[1] || !zm->rdata[2]) return false;
    char *scheme_endptr, *halg_endptr;
    long scheme_val = strtol(zm->rdata[1], &scheme_endptr, 10);
    long halg_val = strtol(zm->rdata[2], &halg_endptr, 10);
    if (*scheme_endptr != '\0' || scheme_val < 0 || scheme_val > 255) {
        if (warn) {
            kc_warning(t, "ZONEMD scheme '%s' is not a valid number (0-255) for name '%s'\n",
                    zm->rdata[1], zm->name);
        }
        return false;
    }
    if (*halg_endptr != '\0' || halg_val < 0 || halg_val > 255) {
        if (warn) {
            kc_warning(t, "ZONEMD hash algorithm '%s' is not a valid number (0-255) for name '%s'\n",
                    zm->rdata[2], zm->name);
        }
        return false;
    }
    if (out_scheme) *out_scheme = (uint8_t)scheme_val;
    if (out_halg) *out_halg = (uint8_t)halg_val;
    return true;
}

/* RFC 8976 §3.3.1 の SIMPLE scheme でゾーンのダイジェストを計算する。halg 1 = SHA-384, 2 = SHA-512。 */
static bool kc_zone_digest(const kc_canon_rr_t *rrs, size_t n, uint8_t halg, uint8_t *md, unsigned int *md_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;
    bool ok = EVP_DigestInit_ex(mdctx, halg == 1 ? EVP_sha384() : EVP_sha512(), NULL) == 1;
    for (size_t i = 0; ok && i < n; i++) {
        /* RFC 8976 §3.3.1.1 / RFC 4034 §6.3: 所有者名・CLASS・TYPE・RDATA が等しい重複は 1 回だけ含める */
        if (i > 0 && kc_cmp_canon_rr(&rrs[i - 1], &rrs[i]) == 0 &&
            rrs[i - 1].rec->class_val == rrs[i].rec->class_val) continue;
        ok = EVP_DigestUpdate(mdctx, rrs[i].wire, rrs[i].len) == 1;
    }
    if (ok) ok = EVP_DigestFinal_ex(mdctx, md, md_len) == 1;
    EVP_MD_CTX_free(mdctx);
    return ok;
}

/* RFC 8976 §4: apex の ZONEMD を全て検証する。対応している scheme と hash algorithm の ZONEMD は全て一致しなければ
 * エラーとする (§4 の注記は「どれか 1 つが一致すれば十分」だが、karicheck は公開する側の検査なので、受け手が
 * 扱えるどの ZONEMD も正しいことを求める)。 */
KARIDNS_TOOL_FN bool verify_zonemd(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
    const dns_record_t *soa = NULL;
    size_t zm_count = 0;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        if (!domain_names_match_ci(r->name, domain)) continue;
        if (r->type_code == 63) zm_count++;
        if (r->type_code == 6 && !soa) soa = r;
    }
    if (zm_count == 0) return true; // ZONEMD がなければ検証しない

    uint32_t soa_serial = 0;
    if (soa && soa->is_cached) {
        soa_serial = soa->cache.soa.serial;
    } else if (soa && soa->rdata_count >= 3 && soa->rdata[2]) {
        soa_serial = (uint32_t)strtoul(soa->rdata[2], NULL, 10);
    }

    kc_canon_rr_t *rrs = calloc(arena->count, sizeof(*rrs));
    if (!rrs) {
        kc_error(t, "Out of memory computing the ZONEMD digest of zone '%s'\n", domain);
        return false;
    }
    size_t n = 0;
    bool canon_ok = true;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        bool at_apex = domain_names_match_ci(r->name, domain);
        /* RFC 8976 §3.3.1.1: apex の ZONEMD とそれを覆う RRSIG は含めない。apex 以外の ZONEMD は普通の RR として
         * 含める (Appendix A.2 の non-apex)。ゾーン外のデータは zone_arena_drop_out_of_zone() で除いてある。 */
        if (at_apex && r->type_code == 63) continue;
        if (at_apex && r->type_code == 46 && r->rdata_count > 0 && get_type_code(r->rdata[0]) == 63) continue;
        if (!kc_canonical_rr(r, &rrs[n])) {
            kc_error(t, "Record '%s %s' cannot be converted to canonical wire form; the ZONEMD digest of zone '%s' "
                        "is not computed\n", r->name, r->type ? r->type : "", domain);
            canon_ok = false;
            break;
        }
        n++;
    }
    if (canon_ok) qsort(rrs, n, sizeof(*rrs), kc_cmp_canon_rr);

    bool all_valid = canon_ok;
    bool have_md[3] = {false, false, false};
    uint8_t md[3][EVP_MAX_MD_SIZE];
    unsigned int md_len[3] = {0, 0, 0};
    for (size_t i = 0; canon_ok && i < arena->count; i++) {
        const dns_record_t *zm = &arena->records[i];
        if (zm->type_code != 63 || !domain_names_match_ci(zm->name, domain)) continue;
        uint8_t scheme, halg;
        /* フィールドの不足や範囲外は check_zone() の RR ごとの検査で警告済み */
        if (zm->rdata_count < 4 || !validate_zonemd_scheme_halg(zm, &scheme, &halg, false, NULL)) continue;

        /* RFC 8976 §4 step 5a */
        uint32_t zm_serial = (uint32_t)strtoul(zm->rdata[0], NULL, 10);
        if (soa && zm_serial != soa_serial) {
            kc_error(t, "ZONEMD serial %u does not match SOA serial %u in zone '%s'\n", zm_serial, soa_serial, domain);
            all_valid = false;
            continue;
        }
        /* step 5b, 5c */
        if (scheme != 1 || (halg != 1 && halg != 2)) {
            printf("[INFO] ZONEMD (Scheme %d, Hash %d) for '%s' is not verified: unsupported scheme or hash "
                   "algorithm (RFC 8976 section 4)\n", scheme, halg, domain);
            continue;
        }
        /* step 4: 同じ (Scheme, Hash Algorithm) の ZONEMD が複数あれば、それらでの検証は成功としない */
        bool dup_before = false, dup_after = false;
        for (size_t j = 0; j < arena->count; j++) {
            const dns_record_t *o = &arena->records[j];
            uint8_t os, oh;
            if (j == i || o->type_code != 63 || !domain_names_match_ci(o->name, domain) || o->rdata_count < 4 ||
                !validate_zonemd_scheme_halg(o, &os, &oh, false, NULL) || os != scheme || oh != halg) continue;
            if (j < i) dup_before = true;
            else dup_after = true;
        }
        if (dup_before) continue; // 最初の 1 件で報告済み
        if (dup_after) {
            kc_error(t, "Zone '%s' has more than one ZONEMD with Scheme %d and Hash %d; none of them can be "
                        "verified (RFC 8976 section 4, step 4)\n", domain, scheme, halg);
            all_valid = false;
            continue;
        }
        /* step 5d: ダイジェストの長さはハッシュの出力長 (SHA-384 は 48、SHA-512 は 64 オクテット) */
        char hex[2048] = "";
        size_t hex_len = 0;
        bool hex_overflow = false;
        for (int k = 3; k < zm->rdata_count; k++) {
            size_t flen = strlen(zm->rdata[k]);
            if (hex_len + flen >= sizeof(hex)) {
                hex_overflow = true;
                break;
            }
            memcpy(hex + hex_len, zm->rdata[k], flen);
            hex_len += flen;
            hex[hex_len] = '\0';
        }
        uint8_t expected[EVP_MAX_MD_SIZE];
        size_t exp_len = hex_overflow ? (size_t)-1 : hex_decode(hex, expected, sizeof(expected));
        size_t want = halg == 1 ? 48 : 64;
        if (exp_len != want) {
            kc_error(t, "ZONEMD (Scheme %d, Hash %d) for '%s': the digest is not %zu octets "
                        "(RFC 8976 section 4, step 5d)\n", scheme, halg, domain, want);
            all_valid = false;
            continue;
        }
        if (!have_md[halg]) {
            if (!kc_zone_digest(rrs, n, halg, md[halg], &md_len[halg])) {
                kc_error(t, "Computing the ZONEMD digest (Hash %d) of zone '%s' failed\n", halg, domain);
                all_valid = false;
                continue;
            }
            have_md[halg] = true;
        }
        if (md_len[halg] == exp_len && memcmp(md[halg], expected, exp_len) == 0) {
            fprintf(stdout, "[OK] ZONEMD (Scheme %d, Hash %d) for '%s' is VALID.\n", scheme, halg, domain);
        } else {
            kc_error(t, "ZONEMD (Scheme %d, Hash %d) for '%s' is INVALID.\n", scheme, halg, domain);
            fprintf(stderr, "       Expected: %s\n", hex);
            fprintf(stderr, "       Computed: ");
            for (unsigned int j = 0; j < md_len[halg]; j++) fprintf(stderr, "%02x", md[halg][j]);
            fprintf(stderr, "\n");
            all_valid = false;
        }
    }

    for (size_t i = 0; i < n; i++) free(rrs[i].wire);
    free(rrs);
    return all_valid;
}

KARIDNS_TOOL_FN bool is_cname(zone_arena_t *arena, const char *name) {
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

KARIDNS_TOOL_FN void normalize_domain_fqdn(const char *in, char *out, size_t out_cap) {
    size_t len = strlen(in);
    if (len > 0 && dns_name_len_no_root(in, len) == len && len + 1 < out_cap) {
        memcpy(out, in, len);
        out[len] = '.';
        out[len + 1] = '\0';
    } else {
        snprintf(out, out_cap, "%s", in);
    }
}

KARIDNS_TOOL_FN bool validate_cidr_syntax(const char *cidr) {
    if (!cidr) return false;
    char buf[128];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    if (!slash) return false;
    *slash = '\0';
    const char *ip_part = buf;
    const char *prefix_part = slash + 1;
    if (*prefix_part == '\0') return false;
    char *endptr = NULL;
    long prefix = strtol(prefix_part, &endptr, 10);
    if (*endptr != '\0' || prefix < 0) return false;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ip_part, &a4) == 1) {
        return prefix <= 32;
    } else if (inet_pton(AF_INET6, ip_part, &a6) == 1) {
        return prefix <= 128;
    }
    return false;
}

/* 以下 2 つは名前 (ゾーンパーサが作る正規形) のラベル単位の包含判定。ラベル境界はエスケープ
 * されない '.' だけ (R-29 / O-08 と同じ規則。domain_name_is_at_or_below() を使う)。 */
KARIDNS_TOOL_FN bool is_subdomain_of(const char *name, const char *parent) {
    if (!name || !parent) return false;
    return domain_name_is_at_or_below(name, parent);
}

KARIDNS_TOOL_FN bool is_strict_subdomain_of(const char *name, const char *parent) {
    if (!name || !parent) return false;
    return domain_name_is_at_or_below(name, parent) && !domain_names_match_ci(name, parent);
}

/* NS のターゲットに名前があり、そのアドレスがこのゾーンに無ければ委任/ゾーンが引けない (ERROR、RFC 9471 は委任の
 * グルー)。MX/SRV のターゲットにアドレスを求める RFC はないので警告にとどめる (K-02、RFC 8976 Appendix A.2)。
 * 重複の検査は NS と MX/SRV で分ける (同じ名前の MX が先にあっても NS のエラーを隠さない)。 */
KARIDNS_TOOL_FN void lint_glue_consistency(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
    char checked_targets[2][64][256];
    int checked_count[2] = {0, 0};

    for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *rec = &arena->records[i];
        const char *target = NULL;
        const char *type_str = NULL;
        if (rec->type_code == 2 && rec->rdata_count >= 1) {
            target = rec->rdata[0];
            type_str = "NS";
        } else if (rec->type_code == 15 && rec->rdata_count >= 2) {
            target = rec->rdata[1];
            type_str = "MX";
        } else if (rec->type_code == 33 && rec->rdata_count >= 4) {
            target = rec->rdata[3];
            type_str = "SRV";
        }
        if (!target || !is_subdomain_of(target, domain)) continue;
        int kind = rec->type_code == 2 ? 0 : 1;

        bool already_checked = false;
        for (int c = 0; c < checked_count[kind]; c++) {
            if (domain_names_match_ci(checked_targets[kind][c], target)) {
                already_checked = true;
                break;
            }
        }
        if (already_checked) continue;
        if (checked_count[kind] < 64) {
            snprintf(checked_targets[kind][checked_count[kind]++], sizeof(checked_targets[kind][0]), "%s", target);
        }

        // If target points to a CNAME, it will be flagged as ERROR by lint_cname_targets (RFC 2181 §10.3).
        bool target_is_cname = false;
        for (size_t j = 0; j < arena->count; j++) {
            if (arena->records[j].type_code == 5 && domain_names_match_ci(arena->records[j].name, target)) {
                target_is_cname = true;
                break;
            }
        }
        if (target_is_cname) continue;

        bool found_address = false;
        for (size_t j = 0; j < arena->count; j++) {
            dns_record_t *ar = &arena->records[j];
            if ((ar->type_code == 1 || ar->type_code == 28) && domain_names_match_ci(ar->name, target)) {
                found_address = true;
                break;
            }
        }
        if (found_address) continue;
        if (kind == 0) {
            kc_error(t, "In-bailiwick NS target '%s' lacks A/AAAA glue record in zone '%s'\n", target, domain);
        } else {
            kc_warning(t, "In-bailiwick %s target '%s' has no A/AAAA record in zone '%s'\n", type_str, target, domain);
        }
    }
    /* グルーのアドレスの書式はゾーンパーサが検査済み。ゾーン外のアドレス (ゾーン外のターゲットのグルー) は
     * check_zone() の zone_arena_drop_out_of_zone() で報告して除いてある (R-27)。 */
}

KARIDNS_TOOL_FN void lint_cname_coexistence(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
    (void)domain;
    for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *r1 = &arena->records[i];
        if (r1->type_code != 5) continue; // CNAME
        for (size_t j = 0; j < arena->count; j++) {
            if (i == j) continue;
            dns_record_t *r2 = &arena->records[j];
            if (!domain_names_match_ci(r1->name, r2->name)) continue;
            // Exceptions: RRSIG (46), NSEC (47), NSEC3 (50), SIG (24), KEY (25)
            if (r2->type_code == 46 || r2->type_code == 47 || r2->type_code == 50 ||
                r2->type_code == 24 || r2->type_code == 25) continue;
            if (r2->type_code == 5) continue;
            kc_error(t, "CNAME record at '%s' coexists with other record type '%s'\n",
                    r1->name, r2->type ? r2->type : "<unknown>");
            break;
        }
    }
}

KARIDNS_TOOL_FN void lint_delegation_occlusion(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
    for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *del_ns = &arena->records[i];
        if (del_ns->type_code != 2) continue; // NS
        if (domain_names_match_ci(del_ns->name, domain)) continue; // apex NS is not child delegation

        const char *del_name = del_ns->name;
        for (size_t j = 0; j < arena->count; j++) {
            dns_record_t *r = &arena->records[j];
            if (!is_strict_subdomain_of(r->name, del_name)) continue;

            bool is_glue = false;
            if (r->type_code == 1 || r->type_code == 28) {
                for (size_t k = 0; k < arena->count; k++) {
                    dns_record_t *ns = &arena->records[k];
                    if (ns->type_code == 2 && domain_names_match_ci(ns->name, del_name)) {
                        if (ns->rdata_count >= 1 && domain_names_match_ci(r->name, ns->rdata[0])) {
                            is_glue = true;
                            break;
                        }
                    }
                }
            }
            if (!is_glue) {
                kc_warning(t, "Record '%s %s' is occluded by delegation at '%s'\n",
                        r->name, r->type ? r->type : "<type>", del_name);
            }
        }
    }
}

KARIDNS_TOOL_FN void lint_cname_targets(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
    (void)domain;
    // 1. RFC 2181 section 10.3: NS and MX targets must not point to CNAME (ERROR)
    for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *rec = &arena->records[i];
        const char *target = NULL;
        const char *type_name = NULL;
        if (rec->type_code == 2 && rec->rdata_count >= 1) {
            target = rec->rdata[0];
            type_name = "NS";
        } else if (rec->type_code == 15 && rec->rdata_count >= 2) {
            target = rec->rdata[1];
            type_name = "MX";
        }
        if (!target) continue;

        for (size_t j = 0; j < arena->count; j++) {
            dns_record_t *c = &arena->records[j];
            if (c->type_code == 5 && domain_names_match_ci(c->name, target)) {
                kc_error(t, "%s record '%s' points to CNAME target '%s' (RFC 2181 section 10.3)\n",
                        type_name, rec->name, target);
                break;
            }
        }
    }

    /* X-39: RFC 2782 "Target": the name "MUST NOT be an alias". BIND の check-srv-cname の既定 (warn) に合わせて
     * 警告にする。"." はサービスが無いことを表す (同じ節) ので調べない。 */
    for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *rec = &arena->records[i];
        if (rec->type_code != 33 || rec->rdata_count < 4 || !rec->rdata[3] || strcmp(rec->rdata[3], ".") == 0) continue;
        for (size_t j = 0; j < arena->count; j++) {
            dns_record_t *c = &arena->records[j];
            if (c->type_code == 5 && domain_names_match_ci(c->name, rec->rdata[3])) {
                kc_warning(t, "SRV record '%s' points to CNAME target '%s' (RFC 2782)\n", rec->name, rec->rdata[3]);
                break;
            }
        }
    }

    // 2. CNAME loops (ERROR) and CNAME chains (WARNING)
    for (size_t i = 0; i < arena->count; i++) {
        dns_record_t *cname = &arena->records[i];
        if (cname->type_code != 5) continue;
        if (cname->rdata_count < 1 || !cname->rdata[0]) continue;
        const char *target = cname->rdata[0];

        if (domain_names_match_ci(cname->name, target)) {
            kc_error(t, "CNAME loop detected: '%s' points to itself\n", cname->name);
            continue;
        }

        for (size_t j = 0; j < arena->count; j++) {
            if (i == j) continue;
            dns_record_t *t_rec = &arena->records[j];
            if (t_rec->type_code == 5 && domain_names_match_ci(t_rec->name, target)) {
                kc_warning(t, "CNAME chain detected: '%s' points to CNAME '%s'\n",
                        cname->name, target);
                break;
            }
        }
    }
}

/* 表示用: NSEC3 の salt ("" と "-" は salt なし) */
static const char *kc_salt_text(const char *salt) {
    return (!salt || salt[0] == '\0') ? "-" : salt;
}

static bool kc_has_salt(const char *salt) {
    return salt && salt[0] != '\0' && strcmp(salt, "-") != 0;
}

/* K-05: NSEC3PARAM (RFC 5155 §4、RFC 9276 §3.1) と NSEC3 チェーン。チェーンはサーバーと同じ build_zone_index() の
 * 索引 (arena->nsec3_chains) と、サーバーが選んだ NSEC3PARAM (arena->nsec3_active、R-31) を使う。NSEC3 の警告は
 * RR ごとではなくチェーンごとに 1 回出す (署名済みゾーンの全 NSEC3 RR で同じ警告を繰り返さない)。 */
KARIDNS_TOOL_FN void lint_nsec3(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
    size_t params = 0, usable = 0;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        if (r->type_code != 51 || r->rdata_count < 4) continue; // 欠けたフィールドはシリアライズの試行で報告される
        if (!domain_names_match_ci(r->name, domain)) {
            kc_warning(t, "NSEC3PARAM '%s' is not at the zone apex '%s'; the owner name of an NSEC3PARAM is the zone "
                          "apex (RFC 5155 section 4), so the server ignores it\n", r->name, domain);
            continue;
        }
        params++;
        int algo = (int)strtol(r->rdata[0], NULL, 10);
        int flags = (int)strtol(r->rdata[1], NULL, 10);
        long iterations = strtol(r->rdata[2], NULL, 10);
        uint8_t salt_buf[255];
        bool salt_ok = hex_to_bytes(r->rdata[3], salt_buf, sizeof(salt_buf)) != (size_t)-1;
        if (algo != 1) {
            kc_warning(t, "NSEC3PARAM for '%s' uses hash algorithm %d; only 1 (SHA-1) is defined "
                          "(RFC 5155 section 4.1.1), so the server ignores this NSEC3PARAM\n", r->name, algo);
        }
        if (flags != 0) {
            kc_error(t, "NSEC3PARAM for '%s' has Flags %d; the Flags field must be 0 (the opt-out flag is only "
                        "meaningful in NSEC3 records) and an NSEC3PARAM with other Flags MUST be ignored "
                        "(RFC 5155 section 4.1.2), so the server ignores it\n", r->name, flags);
        }
        if (iterations > 100) {
            kc_error(t, "NSEC3PARAM for '%s': iterations value is excessively high (%ld) and may cause severe "
                        "performance/DoS issues\n", r->name, iterations);
        } else if (iterations != 0) {
            kc_warning(t, "NSEC3PARAM for '%s': iterations %ld; the iteration count MUST be 0 (RFC 9276 section 3.1)\n",
                       r->name, iterations);
        }
        if (kc_has_salt(r->rdata[3])) {
            kc_warning(t, "NSEC3PARAM for '%s' uses salt %s; operators SHOULD NOT use a salt (RFC 9276 section 3.1)\n",
                       r->name, r->rdata[3]);
        }
        if (algo == 1 && flags == 0 && salt_ok) usable++;
    }
    if (params > 0 && usable == 0) {
        kc_warning(t, "None of the %zu NSEC3PARAM RRs of zone '%s' is usable (Flags 0, hash algorithm 1); the server "
                      "does not use NSEC3 for denial of existence\n", params, domain);
    }
    const nsec3_params_t *active = &arena->nsec3_active;
    if (active->param && !active->chain) {
        kc_warning(t, "Zone '%s' has no NSEC3 RRs with the parameters of the NSEC3PARAM the server uses "
                      "(1 0 %u %s); the zone MUST contain a complete NSEC3 chain with these parameters (RFC 5155 section 4)\n",
                   domain, active->iterations, kc_salt_text(active->param->rdata[3]));
    }

    for (size_t c = 0; c < arena->nsec3_chain_count; c++) {
        const nsec3_chain_t *ch = &arena->nsec3_chains[c];
        size_t optout = 0, reserved = 0;
        for (size_t k = 0; k < ch->count; k++) {
            int flags = (int)strtol(ch->entries[k].rec->rdata[1], NULL, 10);
            if (flags & 0x01) optout++;
            if (flags & ~0x01) reserved++;
        }
        bool matched = false;
        for (size_t i = 0; i < arena->count && !matched; i++) {
            const dns_record_t *p = &arena->records[i];
            if (p->type_code != 51 || p->rdata_count < 4 || !domain_names_match_ci(p->name, domain)) continue;
            if (strtol(p->rdata[1], NULL, 10) != 0) continue; // RFC 5155 §4.1.2: 無視される NSEC3PARAM
            matched = zone_find_nsec3_chain(arena, p) == ch;
        }
        const char *salt = kc_salt_text(ch->salt);
        if (ch->algorithm != 1) {
            kc_warning(t, "NSEC3 chain (hash algorithm %u, iterations %u, salt %s; %zu RRs) in zone '%s': only hash "
                          "algorithm 1 (SHA-1) is defined (RFC 5155 section 3.1.1)\n",
                       ch->algorithm, ch->iterations, salt, ch->count, domain);
        }
        if (reserved > 0) {
            kc_warning(t, "%zu NSEC3 RR(s) of the chain (iterations %u, salt %s) in zone '%s' have reserved Flags bits "
                          "set; only bit 0 (opt-out) is defined (RFC 5155 section 3.1.2)\n",
                       reserved, ch->iterations, salt, domain);
        }
        if (optout > 0) {
            kc_warning(t, "NSEC3 opt-out is set on %zu RR(s) of the chain (iterations %u, salt %s) in zone '%s'; "
                          "RFC 9276 section 3.1 recommends opt-out only for very large, sparsely signed zones\n",
                       optout, ch->iterations, salt, domain);
        }
        if (ch->iterations > 100) {
            kc_error(t, "NSEC3 chain (iterations %u, salt %s; %zu RRs) in zone '%s': iterations value is excessively "
                        "high and may cause severe performance/DoS issues\n", ch->iterations, salt, ch->count, domain);
        } else if (ch->iterations != 0) {
            kc_warning(t, "NSEC3 chain (iterations %u, salt %s; %zu RRs) in zone '%s': the iteration count MUST be 0 "
                          "(RFC 9276 section 3.1)\n", ch->iterations, salt, ch->count, domain);
        }
        if (kc_has_salt(ch->salt)) {
            kc_warning(t, "NSEC3 chain (iterations %u, salt %s; %zu RRs) in zone '%s' uses a salt; operators SHOULD NOT "
                          "use a salt (RFC 9276 section 3.1)\n", ch->iterations, salt, ch->count, domain);
        }
        if (!matched) {
            kc_warning(t, "NSEC3 chain (hash algorithm %u, iterations %u, salt %s; %zu RRs) in zone '%s' matches no "
                          "NSEC3PARAM with Flags 0 at the apex; the server does not use it (RFC 5155 section 4)\n",
                       ch->algorithm, ch->iterations, salt, ch->count, domain);
        }
    }
}

typedef struct { const char *zone; kc_tally_t *tally; } kc_out_of_zone_ud_t;

static void karicheck_report_out_of_zone(const dns_record_t *rec, void *ud) {
    const kc_out_of_zone_ud_t *u = ud;
    kc_warning(u->tally, "Zone '%s': out-of-zone record '%s' %s ignored (not at or below the zone apex; "
                         "the server does not load it)\n",
               u->zone, rec->name ? rec->name : "", rec->type ? rec->type : "");
}

KARIDNS_TOOL_FN int check_zone(const char *domain_raw, const char *file_path, bool is_standalone, bool is_catalog, const char *file_format, const zone_config_t *zcfg, const server_config_t *cfg, const view_config_t *view) {
    // Normalize domain to FQDN: append trailing dot if missing.
    // Without this, "example.com" wouldn't match records expanded to "example.com."
    char domain_buf[256];
    normalize_domain_fqdn(domain_raw, domain_buf, sizeof(domain_buf));
    const char *domain = domain_buf;
    kc_tally_t tally = {0, 0};

    /* D-24: karidns は相対パス ("../" を含むものも) を起動時のディレクトリから、絶対パスはそのまま
     * 開くので、standalone モードでも絶対パスや "../" を警告しない */

    bool failed = false;
    char *buf = read_file_or_die(file_path, &failed);
    if (failed || !buf) return 1;

    char *mutable_buf = strdup(buf);
    if (!mutable_buf) {
        free(buf);
        kc_error(&tally, "Out of memory\n");
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
    char *root_ecs_tag = NULL;
    char *root_loc_tag = NULL;
    char *visited_paths[16];
    dev_t visited_devs[16];
    ino_t visited_inos[16];
    char *root_path = realpath(file_path, NULL);
    if (!root_path) root_path = strdup(file_path);

    char *base_dir = get_base_dir(file_path);
    if (!base_dir) {
        kc_error(&tally, "Out of memory allocating base_dir\n");
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
        .shared_ttl_io = &root_ttl,
        .shared_ecs_tag_io = &root_ecs_tag,
        .shared_loc_tag_io = &root_loc_tag
    };
    ctx.visited_paths[0] = root_path;
    ctx.visited_devs[0] = root_dev;
    ctx.visited_inos[0] = root_ino;
    ctx.source_mtime = root_st.st_mtime; /* tinydns の SOA serial (サーバーと同じくファイルの mtime) */

    /* サーバー (reload_master_zone) と同じく、tinydns の親子ゾーンの振り分けには
     * このゾーンと同じ view のゾーン名を使う */
    const char **view_zone_ptrs = NULL;
    int view_zone_cnt = 0;
    if (view) {
        /* 件数の上限は置かない (O-11: サーバーと同じく view の全ゾーン) */
        size_t n = 0;
        for (const zone_config_t *vz = view->zones; vz; vz = vz->next) n++;
        view_zone_ptrs = n > 0 ? calloc(n, sizeof(*view_zone_ptrs)) : NULL;
        if (n > 0 && !view_zone_ptrs) {
            kc_error(&tally, "Out of memory\n");
            free((void*)ctx.base_dir);
            zone_arena_destroy(&arena);
            free(root_path);
            return 1;
        }
        for (const zone_config_t *vz = view->zones; vz; vz = vz->next) {
            if (vz->domain) view_zone_ptrs[view_zone_cnt++] = vz->domain;
        }
    }
    ctx.all_zone_names = view_zone_cnt > 0 ? view_zone_ptrs : NULL;
    ctx.all_zone_count = view_zone_cnt;

    int res;
    if (file_format && strcasecmp(file_format, "tinydns") == 0) {
        res = parse_tinydns_data(mutable_buf, strlen(mutable_buf), &arena, &ctx);
    } else {
        res = parse_zone_fast(mutable_buf, strlen(mutable_buf), &arena, &ctx);
    }
    free(view_zone_ptrs);
    ctx.all_zone_names = NULL;
    if (res < 0) {
        print_error_context(file_path, buf, &err, &arena);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    /* R-27: サーバーと同じく、ゾーン外のデータは警告して読み込まない (RFC 1034 §4.2) */
    kc_out_of_zone_ud_t ooz = {domain, &tally};
    zone_arena_drop_out_of_zone(&arena, domain, karicheck_report_out_of_zone, &ooz);
    if (ctx.out_of_zone_count > 0) {
        kc_warning(&tally, "Zone '%s': %zu tinydns record(s) belong to no zone configured in the same "
                        "view and are ignored (first: '%s')\n",
                domain, ctx.out_of_zone_count, ctx.first_out_of_zone ? ctx.first_out_of_zone : "");
    }

    if (arena.count == 0) {
        kc_error(&tally, "No records found in zone '%s' (%s)\n", domain, file_path);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }

    /* [T6] RFC 2181 §5.2: build_zone_index() による TTL 自動正規化が行われる"前"に、
     * ソースゾーンファイル上の生データで RRset 内 TTL 不整合を検出し警告する。
     * (正規化後に検査すると値が湰っているため、必ずこの位置で実施すること) */
    if (arena.count > 0) {
        dns_record_t **sorted = malloc(sizeof(dns_record_t *) * arena.count);
        if (sorted) {
            for (size_t k = 0; k < arena.count; k++) sorted[k] = &arena.records[k];
            qsort(sorted, arena.count, sizeof(dns_record_t *), cmp_rec_by_name_type);
            for (size_t k = 0; k + 1 < arena.count; k++) {
                if (!sorted[k]->name || !sorted[k + 1]->name) continue;
                /* RRSIG(46)同士の比較は被覆タイプが異なる場合に誤検知する可能性があるため除外 */
                if (sorted[k]->type_code == 46 && sorted[k + 1]->type_code == 46) continue;
                if (sorted[k]->type_code == sorted[k + 1]->type_code &&
                    strcasecmp(sorted[k]->name, sorted[k + 1]->name) == 0 &&
                    sorted[k]->ttl_value != sorted[k + 1]->ttl_value) {
                    kc_warning(&tally,
                        "RRset '%s' type %d has inconsistent TTLs (%u vs %u) in the source "
                        "zone file; RFC 2181 §5.2 requires all RRs in an RRset to share the same TTL. "
                        "KariDNS will normalize this to the minimum value at load time, "
                        "but the zone file should be corrected.\n",
                        sorted[k]->name, sorted[k]->type_code,
                        sorted[k]->ttl_value, sorted[k + 1]->ttl_value);
                }
            }
            free(sorted);
        }
    }

    if (build_zone_index(&arena, true) != 0) {
        kc_error(&tally, "Memory allocation failed during index build for '%s'\n", domain);
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
    int soa_count = 0; /* [T3] SOA重複検出用 */
    bool has_apex_ns = false;

    if (arena.is_tinydns_format) {
        for (int i = 0; i < arena.location_count; i++) {
            const tinydns_location_entry_t *loc = &arena.locations[i];
            if (loc->prefix_bits > 32) {
                kc_error(&tally, "Location prefix length /%u exceeds /32 for location '%.2s' in zone '%s'\n",
                        loc->prefix_bits, loc->code, domain);
            }
            for (int j = i + 1; j < arena.location_count; j++) {
                if (arena.locations[j].code[0] == loc->code[0] &&
                    arena.locations[j].code[1] == loc->code[1]) {
                    kc_warning(&tally, "Duplicate location code '%.2s' in zone '%s' (%s)\n",
                            loc->code, domain, file_path);
                    break;
                }
            }
        }

        // Tinydns third-party patch syntax validations on raw lines
        size_t linestart = 0;
        size_t buflen = strlen(buf);
        unsigned long linenum = 1;
        while (linestart < buflen) {
            size_t lineend = linestart;
            while (lineend < buflen && buf[lineend] != '\n') lineend++;
            size_t linelen = lineend - linestart;
            const char *line = buf + linestart;

            while (linelen > 0 && (line[linelen - 1] == ' ' || line[linelen - 1] == '\t' ||
                                   line[linelen - 1] == '\n' || line[linelen - 1] == '\r')) {
                linelen--;
            }

            if (linelen > 0 && line[0] != '#' && line[0] != '-') {
                char ch = line[0];
                if (ch == '3' || ch == '6' || ch == 'S' || ch == 'N' || ch == '_') {
                    // Extract fields separated by ':'
                    char fld[12][256];
                    size_t flen[12];
                    int fcount = 0;
                    size_t j = 1;
                    while (fcount < 12 && j <= linelen) {
                        size_t k = j;
                        while (k < linelen && line[k] != ':') k++;
                        size_t clen = k - j;
                        if (clen >= sizeof(fld[fcount])) clen = sizeof(fld[fcount]) - 1;
                        memcpy(fld[fcount], line + j, clen);
                        fld[fcount][clen] = '\0';
                        flen[fcount] = clen;
                        fcount++;
                        j = k + 1;
                    }
                    while (fcount < 12) {
                        fld[fcount][0] = '\0';
                        flen[fcount] = 0;
                        fcount++;
                    }

                    if (ch == '3' || ch == '6') {
                        // f[1] is ip6: must be 32 hex chars
                        bool hex_ok = (flen[1] == 32);
                        if (hex_ok) {
                            for (size_t x = 0; x < 32; x++) {
                                if (hex_char_to_val(fld[1][x]) < 0) {
                                    hex_ok = false;
                                    break;
                                }
                            }
                        }
                        if (!hex_ok) {
                            kc_error(&tally, "Zone '%s' (line %lu): type '%c' requires a 32-character hexadecimal IPv6 address, got '%.*s'\n",
                                    domain, linenum, ch, (int)flen[1], fld[1]);
                        }
                        if (ch == '6') {
                            fprintf(stdout, "[INFO] Zone '%s' (line %lu): type '6' generates deprecated PTR in 'ip6.int'; consider using type '3' with explicit '^' PTR record instead\n",
                                    domain, linenum);
                        }
                    } else if (ch == 'S') {
                        // Sfqdn:ip:x:port:weight:priority:ttl:timestamp:lo
                        if (flen[3] > 0) {
                            char *endp;
                            unsigned long p = strtoul(fld[3], &endp, 10);
                            if (*endp != '\0' || p > 65535) {
                                kc_error(&tally, "Zone '%s' (line %lu): SRV port '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[3]);
                            }
                        }
                        if (flen[4] > 0) {
                            char *endp;
                            unsigned long w = strtoul(fld[4], &endp, 10);
                            if (*endp != '\0' || w > 65535) {
                                kc_error(&tally, "Zone '%s' (line %lu): SRV weight '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[4]);
                            }
                        }
                        if (flen[5] > 0) {
                            char *endp;
                            unsigned long prio = strtoul(fld[5], &endp, 10);
                            if (*endp != '\0' || prio > 65535) {
                                kc_error(&tally, "Zone '%s' (line %lu): SRV priority '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[5]);
                            }
                        }
                    } else if (ch == 'N') {
                        // Nfqdn:order:pref:flags:service:regexp:replacement:ttl:timestamp:lo
                        if (flen[1] > 0) {
                            char *endp;
                            unsigned long ord = strtoul(fld[1], &endp, 10);
                            if (*endp != '\0' || ord > 65535) {
                                kc_error(&tally, "Zone '%s' (line %lu): NAPTR order '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[1]);
                            }
                        }
                        if (flen[2] > 0) {
                            char *endp;
                            unsigned long pref = strtoul(fld[2], &endp, 10);
                            if (*endp != '\0' || pref > 65535) {
                                kc_error(&tally, "Zone '%s' (line %lu): NAPTR preference '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[2]);
                            }
                        }
                    } else if (ch == '_') {
                        // _fqdn:algorithm:fp_type:fingerprint:ttl:timestamp:lo
                        if (flen[1] > 0) {
                            char *endp;
                            unsigned long alg = strtoul(fld[1], &endp, 10);
                            if (*endp != '\0' || alg > 255) {
                                kc_error(&tally, "Zone '%s' (line %lu): SSHFP algorithm '%s' out of range (0-255)\n",
                                        domain, linenum, fld[1]);
                            } else if (alg == 0 || alg > 4) {
                                kc_warning(&tally, "Zone '%s' (line %lu): SSHFP algorithm '%lu' is outside standard RFC assignments (1-4)\n",
                                        domain, linenum, alg);
                            }
                        }
                        if (flen[2] > 0) {
                            char *endp;
                            unsigned long fpt = strtoul(fld[2], &endp, 10);
                            if (*endp != '\0' || fpt > 255) {
                                kc_error(&tally, "Zone '%s' (line %lu): SSHFP fp_type '%s' out of range (0-255)\n",
                                        domain, linenum, fld[2]);
                            } else if (fpt == 0 || fpt > 2) {
                                kc_warning(&tally, "Zone '%s' (line %lu): SSHFP fp_type '%lu' is outside standard RFC assignments (1-2)\n",
                                        domain, linenum, fpt);
                            }
                        }
                        uint8_t fp_bin[64];
                        size_t dec_len = hex_decode(fld[3], fp_bin, sizeof(fp_bin));
                        if (flen[3] == 0 || dec_len == 0 || dec_len == (size_t)-1) {
                            kc_error(&tally, "Zone '%s' (line %lu): SSHFP invalid fingerprint hex string '%s'\n",
                                    domain, linenum, fld[3]);
                        }
                    }
                }
            }

            linestart = lineend + 1;
            linenum++;
        }
    }

    ecs_tag_def_t *active_ecs_tags = (arena.bind_ecs_tags && arena.bind_ecs_tag_count > 0) ? arena.bind_ecs_tags :
                                     ((zcfg && zcfg->ecs_tags) ? zcfg->ecs_tags : (cfg ? cfg->ecs_tags : NULL));
    int active_ecs_tag_count = (arena.bind_ecs_tags && arena.bind_ecs_tag_count > 0) ? arena.bind_ecs_tag_count :
                               ((zcfg && zcfg->ecs_tags) ? zcfg->ecs_tag_count : (cfg ? cfg->ecs_tag_count : 0));

    ecs_tag_def_t *active_loc_tags = (arena.bind_location_tags && arena.bind_location_tag_count > 0) ? arena.bind_location_tags :
                                     ((zcfg && zcfg->location_tags) ? zcfg->location_tags : (cfg ? cfg->location_tags : NULL));
    int active_loc_tag_count = (arena.bind_location_tags && arena.bind_location_tag_count > 0) ? arena.bind_location_tag_count :
                               ((zcfg && zcfg->location_tags) ? zcfg->location_tag_count : (cfg ? cfg->location_tag_count : 0));

    for (size_t i = 0; i < arena.count; i++) {
        if (arena.records[i].ecs_subnet_tag != NULL) {
            bool tag_found = false;
            for (int ti = 0; ti < active_ecs_tag_count; ti++) {
                if (strcasecmp(active_ecs_tags[ti].tag, arena.records[i].ecs_subnet_tag) == 0) {
                    tag_found = true;
                    break;
                }
            }
            if (!tag_found) {
                kc_error(&tally, "Zone '%s': record '%s' references undefined ECS subnet tag '%s'\n",
                        domain, arena.records[i].name, arena.records[i].ecs_subnet_tag);
            }
        }

        if (arena.records[i].bind_location_tag != NULL) {
            bool tag_found = false;
            for (int ti = 0; ti < active_loc_tag_count; ti++) {
                if (strcasecmp(active_loc_tags[ti].tag, arena.records[i].bind_location_tag) == 0) {
                    tag_found = true;
                    break;
                }
            }
            if (!tag_found) {
                kc_error(&tally, "Zone '%s': record '%s' references undefined location tag '%s'\n",
                        domain, arena.records[i].name, arena.records[i].bind_location_tag);
            }
        }

        uint16_t tcode = arena.records[i].type_code;
        int rcount = arena.records[i].rdata_count;
        char **rdata = arena.records[i].rdata;

        if (tcode == 1) { // A
            if (rcount != 1) {
                kc_error(&tally, "A record must have exactly 1 parameter for name '%s' in zone '%s'\n", arena.records[i].name, domain);
            } else {
                struct in_addr tmp;
                if (inet_pton(AF_INET, rdata[0], &tmp) != 1) {
                    kc_error(&tally, "Invalid IPv4 address '%s' for name '%s' in zone '%s'\n", rdata[0], arena.records[i].name, domain);
                }
            }
        }
        if (tcode == 28) { // AAAA
            if (rcount != 1) {
                kc_error(&tally, "AAAA record must have exactly 1 parameter for name '%s' in zone '%s'\n", arena.records[i].name, domain);
            } else {
                struct in6_addr tmp;
                if (inet_pton(AF_INET6, rdata[0], &tmp) != 1) {
                    kc_error(&tally, "Invalid IPv6 address '%s' for name '%s' in zone '%s'\n", rdata[0], arena.records[i].name, domain);
                }
            }
        }

        if (tcode == 6 && strcasecmp(arena.records[i].name, domain) == 0) {
            has_soa = true;
            /* [T3] SOA重複検出: apexに2度以上の SOAは破損ゾーンファイル */
            soa_count++;
        }
        if (tcode == 2 && strcasecmp(arena.records[i].name, domain) == 0) {
            has_apex_ns = true;
        }
        if (tcode == 62) { // CSYNC
            for (int j = 2; j < rcount; j++) {
                if (get_type_code(rdata[j]) == 0) {
                    kc_warning(&tally, "CSYNC record contains unknown type '%s' in zone '%s' (%s)\n", rdata[j], domain, file_path);
                }
            }
        }
        if (tcode == 64 || tcode == 65) { // SVCB / HTTPS
            if (rcount > 1) {
                const char *target = rdata[1];
                size_t len = strlen(target);
                if (len > 0 && target[len - 1] != '.' && strcmp(target, ".") != 0) {
                    kc_warning(&tally, "%s record TargetName '%s' does not end with a dot in zone '%s' (%s)\n",
                            tcode == 64 ? "SVCB" : "HTTPS",
                            target, domain, file_path);
                }
            }
        }
        
        // --- Add specific field validations ---
        if (tcode == 63) { // ZONEMD
            if (strcasecmp(arena.records[i].name, domain) != 0) {
                kc_warning(&tally, "ZONEMD record '%s' is not at the zone apex '%s' (RFC 8976 section 2.1)\n",
                        arena.records[i].name, domain);
            }
            if (rcount < 4) {
                kc_warning(&tally, "ZONEMD record for '%s' has fewer than 4 fields "
                                "(serial, scheme, hash-algorithm, digest)\n", arena.records[i].name);
            } else {
                validate_zonemd_scheme_halg(&arena.records[i], NULL, NULL, true, &tally);
            }
        }
        if (tcode == 48 || tcode == 60) { // DNSKEY / CDNSKEY
            if (rcount >= 3) {
                int flags = (int)strtol(rdata[0], NULL, 10);
                int protocol = (int)strtol(rdata[1], NULL, 10);
                int alg = (int)strtol(rdata[2], NULL, 10);
                check_dnssec_algorithm(&tally, alg, arena.records[i].name, tcode == 48 ? "DNSKEY" : "CDNSKEY", flags, protocol);
                if (rcount >= 4)
                    check_dnssec_blob_length(&tally, alg, arena.records[i].name, tcode == 48 ? "DNSKEY" : "CDNSKEY",
                                             false, &rdata[3], rcount - 3);
            }
        }
        if (tcode == 43 || tcode == 59) { // DS / CDS
            if (rcount >= 4) {
                int key_tag = (int)strtol(rdata[0], NULL, 10);
                int algorithm = (int)strtol(rdata[1], NULL, 10);
                int digest_type = (int)strtol(rdata[2], NULL, 10);
                check_ds_digest_type(&tally, digest_type, algorithm, key_tag,
                                     arena.records[i].name, tcode == 43 ? "DS" : "CDS");
            }
        }
        if (tcode == 46) { // RRSIG
            if (rcount >= 2) {
                check_dnssec_algorithm(&tally, (int)strtol(rdata[1], NULL, 10), arena.records[i].name, "RRSIG", -1, -1);
                if (rcount >= 9)
                    check_dnssec_blob_length(&tally, (int)strtol(rdata[1], NULL, 10), arena.records[i].name, "RRSIG",
                                             true, &rdata[8], rcount - 8);
            }
        }
        if (tcode == 55) { // HIP
            if (rcount < 3) {
                kc_warning(&tally, "HIP record requires at least 3 fields: HIT algorithm, HIT (hex), and public key (base64) for name '%s'\n", arena.records[i].name);
            } else {
                /* Reconstruct the concatenated public-key base64 token the same way
                 * the server's serializer does, and reject lengths that are not a
                 * non-zero multiple of 4: such input makes EVP_DecodeBlock's
                 * returned length smaller than the base64 padding count, which
                 * underflows the RR's public-key length field at response time. */
                size_t pk_b64_len = 0;
                bool pk_finished = false;
                for (int r_idx = 2; r_idx < rcount && !pk_finished; r_idx++) {
                    if (strchr(rdata[r_idx], '.') != NULL) break;
                    size_t tlen = strlen(rdata[r_idx]);
                    pk_b64_len += tlen;
                    if (tlen > 0 && rdata[r_idx][tlen - 1] == '=') pk_finished = true;
                }
                if (pk_b64_len == 0 || (pk_b64_len % 4) != 0) {
                    kc_error(&tally, "HIP record public key for name '%s' is not valid base64 (length %zu is not a non-zero multiple of 4) in zone '%s'\n",
                            arena.records[i].name, pk_b64_len, domain);
                }
            }
        }
        if (tcode == 11) { // WKS
            /* K-03: プロトコルはサーバーのシリアライザと同じ規則で読む (番号 0-255、または TCP/UDP) */
            uint8_t proto = 0;
            if (rcount >= 2 && !dns_wks_protocol_from_text(rdata[1], &proto)) {
                kc_warning(&tally, "WKS record protocol '%s' is neither a number (0-255) nor TCP/UDP for name '%s'\n",
                           rdata[1], arena.records[i].name);
            }
            /* X-38: ポート名はサーバーと同じ固定表で引く。読めないポートがあるとレコードは書けない (下の試し書き) */
            for (int j = 2; j < rcount; j++) {
                uint16_t port;
                if (!dns_wks_port_from_text(rdata[j], proto, &port)) {
                    kc_warning(&tally, "WKS record port '%s' for name '%s' is neither a number (0-65535) nor a known "
                                       "service name for protocol %u\n", rdata[j], arena.records[i].name, proto);
                }
            }
        }
        if (tcode == 27 && rcount < 3) { // GPOS
            kc_warning(&tally, "GPOS record requires exactly 3 fields (Longitude, Latitude, Altitude) for name '%s'\n", arena.records[i].name);
        }
        if (tcode == 19 && rcount < 1) { // X25
            kc_warning(&tally, "X25 record requires at least 1 field for name '%s'\n", arena.records[i].name);
        }
        if (tcode == 33) { // SRV
            if (rcount < 4) {
                kc_error(&tally, "SRV record requires 4 fields (priority, weight, port, target) for name '%s' in zone '%s'\n",
                        arena.records[i].name, domain);
            } else {
                char *endp;
                unsigned long prio = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || prio > 65535) {
                    kc_error(&tally, "SRV priority '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[0], arena.records[i].name, domain);
                }
                unsigned long weight = strtoul(rdata[1], &endp, 10);
                if (*endp != '\0' || weight > 65535) {
                    kc_error(&tally, "SRV weight '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[1], arena.records[i].name, domain);
                }
                unsigned long port = strtoul(rdata[2], &endp, 10);
                if (*endp != '\0' || port > 65535) {
                    kc_error(&tally, "SRV port '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[2], arena.records[i].name, domain);
                }
            }
        }
        if (tcode == 35) { // NAPTR
            if (rcount < 6) {
                kc_error(&tally, "NAPTR record requires 6 fields (order, preference, flags, service, regexp, replacement) for name '%s' in zone '%s'\n",
                        arena.records[i].name, domain);
            } else {
                char *endp;
                unsigned long ord = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || ord > 65535) {
                    kc_error(&tally, "NAPTR order '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[0], arena.records[i].name, domain);
                }
                unsigned long pref = strtoul(rdata[1], &endp, 10);
                if (*endp != '\0' || pref > 65535) {
                    kc_error(&tally, "NAPTR preference '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[1], arena.records[i].name, domain);
                }
                /* [T5] RFC 3403 §4.1: flags は [A-Za-z0-9] のみ許容 */
                const char *naptr_flags = rdata[2];
                size_t naptr_flags_len = strlen(naptr_flags);
                bool naptr_flags_ok = true;
                for (size_t fi = 0; fi < naptr_flags_len; fi++) {
                    char c = naptr_flags[fi];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
                        naptr_flags_ok = false;
                        break;
                    }
                }
                if (!naptr_flags_ok) {
                    kc_error(&tally, "NAPTR flags '%s' for name '%s' in zone '%s' must contain only "
                            "[A-Za-z0-9] characters (RFC 3403 §4.1)\n",
                            naptr_flags, arena.records[i].name, domain);
                }
                /* [T5] RFC 2915 §2: regexp と replacement は同時に非空であってはならない */
                bool naptr_has_regexp = (strlen(rdata[4]) > 0);
                bool naptr_has_replacement = (strlen(rdata[5]) > 0 && strcmp(rdata[5], ".") != 0);
                if (naptr_has_regexp && naptr_has_replacement) {
                    kc_error(&tally, "NAPTR record for '%s' in zone '%s' sets both a regexp and a "
                            "non-root replacement field; RFC 2915 requires exactly one of them to be empty\n",
                            arena.records[i].name, domain);
                }
            }
        }
        if (tcode == 257) { // CAA (RFC 8659)
            /* [T4] RFC 8659 CAAレコード検証 */
            if (rcount < 3) {
                kc_error(&tally, "CAA record requires 3 fields (flags, tag, value) for name '%s' in zone '%s'\n",
                        arena.records[i].name, domain);
            } else {
                char *endp;
                unsigned long caa_flags = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || caa_flags > 255) {
                    kc_error(&tally, "CAA flags '%s' out of range (0-255) for name '%s' in zone '%s'\n",
                            rdata[0], arena.records[i].name, domain);
                } else if ((caa_flags & ~0x80UL) != 0) {
                    /* RFC 8659 §4: bit0(critical=0x80)以外の未定義ビット */
                    kc_warning(&tally, "CAA record for '%s' sets undefined flag bits (0x%02lx); "
                            "only the critical bit (0x80) is defined by RFC 8659\n",
                            arena.records[i].name, caa_flags);
                }
                const char *caa_tag = rdata[1];
                size_t caa_tag_len = strlen(caa_tag);
                bool caa_tag_ok = (caa_tag_len >= 1 && caa_tag_len <= 15);
                for (size_t ti = 0; caa_tag_ok && ti < caa_tag_len; ti++) {
                    char c = caa_tag[ti];
                    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')))
                        caa_tag_ok = false;
                }
                if (!caa_tag_ok) {
                    kc_error(&tally, "CAA tag '%s' for name '%s' does not match RFC 8659 syntax "
                            "(1-15 chars, [a-zA-Z0-9] only)\n",
                            caa_tag, arena.records[i].name);
                } else {
                    bool known_tag = (strcasecmp(caa_tag, "issue") == 0 ||
                                      strcasecmp(caa_tag, "issuewild") == 0 ||
                                      strcasecmp(caa_tag, "iodef") == 0 ||
                                      strcasecmp(caa_tag, "contactemail") == 0 ||
                                      strcasecmp(caa_tag, "contactphone") == 0);
                    if (!known_tag) {
                        bool is_critical = ((strtoul(rdata[0], NULL, 10) & 0x80) != 0);
                        if (is_critical) {
                            kc_error(&tally, "CAA record for '%s' has unknown tag '%s' with the critical flag set; "
                                    "RFC 8659 requires issuers to refuse issuance\n",
                                    arena.records[i].name, caa_tag);
                        } else {
                            kc_warning(&tally, "CAA record for '%s' has unrecognized tag '%s' "
                                    "(not one of issue/issuewild/iodef/contactemail/contactphone)\n",
                                    arena.records[i].name, caa_tag);
                        }
                    }
                }
            }
        }
        if (tcode == 44) { // SSHFP
            if (rcount < 3) {
                kc_error(&tally, "SSHFP record requires 3 fields (algorithm, fp_type, fingerprint) for name '%s' in zone '%s'\n",
                        arena.records[i].name, domain);
            } else {
                char *endp;
                unsigned long alg = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || alg > 255) {
                    kc_error(&tally, "SSHFP algorithm '%s' out of range (0-255) for name '%s' in zone '%s'\n",
                            rdata[0], arena.records[i].name, domain);
                } else if (alg == 0 || alg > 4) {
                    kc_warning(&tally, "SSHFP record for '%s' uses algorithm '%lu' which is outside standard RFC assignments (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519)\n",
                            arena.records[i].name, alg);
                }
                unsigned long fpt = strtoul(rdata[1], &endp, 10);
                if (*endp != '\0' || fpt > 255) {
                    kc_error(&tally, "SSHFP fp_type '%s' out of range (0-255) for name '%s' in zone '%s'\n",
                            rdata[1], arena.records[i].name, domain);
                } else if (fpt == 0 || fpt > 2) {
                    kc_warning(&tally, "SSHFP record for '%s' uses fp_type '%lu' which is outside standard RFC assignments (1=SHA-1, 2=SHA-256)\n",
                            arena.records[i].name, fpt);
                }
                uint8_t fp_bin[64];
                size_t dec_len = hex_decode(rdata[2], fp_bin, sizeof(fp_bin));
                if (dec_len == 0 || dec_len == (size_t)-1) {
                    kc_error(&tally, "SSHFP invalid fingerprint hex string '%s' for name '%s' in zone '%s'\n",
                            rdata[2], arena.records[i].name, domain);
                }
            }
        }

        // --- RFC 1912 Operational Checks ---
        /* in-bailiwick の NS ターゲットのアドレスは lint_glue_consistency() が ERROR として検査する */
        if (tcode == 6 && rcount >= 2) { // SOA
            if (is_cname(&arena, rdata[0])) {
                kc_warning(&tally, "SOA MNAME for '%s' points to a CNAME '%s' (RFC 1912)\n", arena.records[i].name, rdata[0]);
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
                            kc_warning(&tally, "CNAME '%s' co-exists with other records (type %d) (RFC 1912)\n", arena.records[i].name, other);
                            break;
                        }
                    }
                }
            }
        }
        
        if (tcode == 20 && (rcount < 1 || rcount > 2)) { // ISDN
            kc_warning(&tally, "ISDN record requires 1 or 2 fields for name '%s'\n", arena.records[i].name);
        }
        if (tcode == 108 || tcode == 109) { // EUI48 / EUI64
            if (rcount >= 1) {
                int dashes = 0;
                for (const char *p = rdata[0]; *p; p++) {
                    if (*p == '-') dashes++;
                }
                if (tcode == 108 && dashes != 5) {
                    kc_warning(&tally, "EUI48 requires 6 octets (5 dashes) for name '%s'\n", arena.records[i].name);
                } else if (tcode == 109 && dashes != 7) {
                    kc_warning(&tally, "EUI64 requires 8 octets (7 dashes) for name '%s'\n", arena.records[i].name);
                }
            }
        }

        // Meta-types (OPT/TKEY/TSIG/IXFR/AXFR/MAILB/MAILA/ANY, and NXNAME
        // per RFC 9824) must NOT appear as standalone RRsets in zone data.
        // Shared with the runtime loader's check in dns_zone_parser.c so
        // karicheck and the actual server never disagree on this.
        if (is_meta_rrtype(tcode)) {
            kc_error(&tally, "type %u is a meta-type and must not appear "
                    "as a standalone RRset in zone '%s' (name '%s')\n", tcode, domain, arena.records[i].name);
        }

        // DSYNC (66, RFC 9859): validate RRtype mnemonic
        if (tcode == 66 && rcount >= 1) {
            if (get_type_code(rdata[0]) == 0) {
                kc_warning(&tally, "DSYNC record has unknown RRtype mnemonic '%s' for name '%s'\n",
                        rdata[0], arena.records[i].name);
            }
        }

        /* NSEC3 / NSEC3PARAM は lint_nsec3() でチェーンごとに検査する (K-05) */

        // --- Dry-run serialize_dns_record ---
        uint8_t scratch[65535];
        uint16_t scratch_offset = 0;
        compress_ctx_t comp_ctx = {0};
        compress_ctx_init_packet(&comp_ctx);
        int wire_result = serialize_dns_record(
            scratch, sizeof(scratch), &scratch_offset,
            &arena.records[i], &comp_ctx,
            NULL,          // owner_name: NULL
            0xFFFFFFFF     // override_ttl: use record TTL
        );
        if (wire_result < 0) {
            kc_error(&tally,
                "Record '%s %s' at index %zu cannot be serialized to wire format "
                "(the server leaves this record out with a warning when it loads the zone). "
                "Check field count and value ranges for this record type.\n",
                arena.records[i].name, arena.records[i].type, i);
        }
    }

    if (!has_soa) {
        kc_error(&tally, "No SOA record found in zone '%s' (%s) at origin\n", domain, file_path);
        printf("[RESULT] Zone '%s': %d error(s), %d warning(s)\n", domain, tally.errors, tally.warnings);
        fprintf(stderr, "[FAIL] Zone '%s' contains invalid records.\n", domain);
        free((void*)ctx.base_dir);
        zone_arena_destroy(&arena);
        free(root_path);
        return 1;
    }
    /* [T3] SOA重複検出: apexに 2以上の SOAは失敗 */
    if (soa_count > 1) {
        kc_error(&tally, "Zone '%s' (%s) has %d SOA records at the apex; "
                "exactly one SOA record is required\n",
                domain, file_path, soa_count);
    }

    if (!has_apex_ns) {
        kc_error(&tally, "No NS record found at zone apex '%s' (%s); this zone cannot be properly delegated\n", domain, file_path);
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
            kc_error(&tally, "Catalog zone '%s' is missing '%s TXT \"2\"'\n", domain, version_txt);
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
                            kc_error(&tally,
                                    "Catalog zone '%s': owner name '%s' is too long to process (unique-id part exceeds %zu bytes); skipping orphan check for this record\n",
                                    domain, arena.records[i].name, sizeof(ptr_name) - 1);
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
                            kc_warning(&tally, "Orphaned group TXT record '%s' (no corresponding PTR record '%s')\n", arena.records[i].name, ptr_name);
                        }
                    }
                }
            }
        }
    }

    lint_glue_consistency(domain, &arena, &tally);
    lint_cname_coexistence(domain, &arena, &tally);
    lint_delegation_occlusion(domain, &arena, &tally);
    lint_cname_targets(domain, &arena, &tally);
    lint_nsec3(domain, &arena, &tally);
    /* K-02: 他のエラーがあっても ZONEMD は検証する (結果は件数に入る) */
    verify_zonemd(domain, &arena, &tally);

    printf("[RESULT] Zone '%s': %d error(s), %d warning(s)\n", domain, tally.errors, tally.warnings);
    free((void*)ctx.base_dir);
    zone_arena_destroy(&arena); // frees mutable_buf via arena.file_bufs[0]; do not free() it again here
    free(root_path);
    if (tally.errors > 0) {
        fprintf(stderr, "[FAIL] Zone '%s' contains invalid records.\n", domain);
        return 1;
    }
    printf("[OK] Zone '%s' is valid.\n", domain);
    return 0;
}

KARIDNS_TOOL_FN int check_config(const char *config_path, server_config_t *cfg) {
    printf("[INFO] Loading config %s...\n", config_path);
    bool failed = false;
    char *buf = read_file_or_die(config_path, &failed);
    if (failed || !buf) return 1;

    if (parse_named_conf_ext(buf, config_path, cfg) != 0) {
        fprintf(stderr, "[ERROR] Syntax error in config file: %s\n", config_path);
        free(buf);
        return 1;
    }

    int program_zone_count = 0;
    zone_config_t *z = cfg->zones;
    while (z) {
        if (z->type && strcasecmp(z->type, "program") == 0) {
            program_zone_count++;
            if (z->program_path) {
                if (cfg->user && !z->program_user) {
                    z->program_user = strdup(cfg->user);
                }
                if (z->program_path[0] != '/') {
                    fprintf(stderr,
                        "[ERROR] Zone '%s': 'program' must be an absolute path (got '%s'). "
                        "A relative name would be resolved via $PATH at runtime, which is "
                        "not deterministic for a network-facing daemon.\n",
                        z->domain, z->program_path);
                    free(buf);
                    return 1;
                }
                if (access(z->program_path, X_OK) != 0) {
                    fprintf(stderr, "[WARNING] Zone '%s' program '%s' is not executable (access X_OK failed: %s)\n",
                            z->domain, z->program_path, strerror(errno));
                }
                if (z->program_user && cfg->user &&
                    strcasecmp(z->program_user, cfg->user) != 0) {
                    fprintf(stderr,
                        "[WARNING] Zone '%s': program-user '%s' differs from options.user '%s'. "
                        "This only works if karidns itself starts as root (no prior privilege drop); "
                        "if karidns is started as a non-root user, it refuses to start "
                        "(setuid to a different non-root user is not permitted by the OS).\n",
                        z->domain, z->program_user, cfg->user);
                }
                if (z->program_args_count > 62) {
                    fprintf(stderr,
                        "[ERROR] Zone '%s': program-args has %d entries, but only 62 are "
                        "supported (argv[] is fixed-size in spawn_one_program_plugin()). "
                        "Reduce the argument count.\n",
                        z->domain, z->program_args_count);
                    free(buf);
                    return 1;
                }
            } else {
                fprintf(stderr, "[ERROR] Zone '%s' has type 'program' but no 'program' path specified\n", z->domain);
                free(buf);
                return 1;
            }
        } else if (z->type && strcasecmp(z->type, "forward") == 0) {
            if (z->forwarders_count == 0) {
                fprintf(stderr, "[ERROR] Zone '%s' has type 'forward' but no 'forwarders' specified\n",
                        z->domain);
                free(buf);
                return 1;
            }
            // 自己ループ検知: forwarders のいずれかが自分自身の
            // bind-address:port と一致していないか確認する
            for (int fi = 0; fi < z->forwarders_count; fi++) {
                if (cfg->bind_addresses) {
                    for (int bi = 0; bi < cfg->bind_address_count; bi++) {
                        if (strcmp(z->forwarders[fi].ip, cfg->bind_addresses[bi]) == 0 &&
                            (z->forwarders[fi].port == cfg->port || z->forwarders[fi].port == 0)) {
                            fprintf(stderr,
                                "[WARNING] Zone '%s': forwarder '%s:%d' appears to point back "
                                "at this server itself (self-loop risk).\n",
                                z->domain, z->forwarders[fi].ip, z->forwarders[fi].port);
                        }
                    }
                }
            }
        }
        z = z->next;
    }

    if (program_zone_count > 0 && !cfg->allow_program_zones) {
        fprintf(stderr, "[ERROR] Config contains %d type 'program' zone(s), but 'allow-program-zones' is not enabled in options{}\n",
                program_zone_count);
        free(buf);
        return 1;
    }

    bool ecs_error = false;
    bool has_ecs_tags = (cfg->ecs_tag_count > 0);
    for (int ti = 0; ti < cfg->ecs_tag_count; ti++) {
        for (int ci = 0; ci < cfg->ecs_tags[ti].cidr_count; ci++) {
            if (!validate_cidr_syntax(cfg->ecs_tags[ti].cidrs[ci].cidr)) {
                fprintf(stderr, "[ERROR] Invalid CIDR '%s' in options.ecs-tags tag '%s'\n",
                        cfg->ecs_tags[ti].cidrs[ci].cidr, cfg->ecs_tags[ti].tag);
                ecs_error = true;
            }
        }
    }
    for (int ti = 0; ti < cfg->location_tag_count; ti++) {
        for (int ci = 0; ci < cfg->location_tags[ti].cidr_count; ci++) {
            if (!validate_cidr_syntax(cfg->location_tags[ti].cidrs[ci].cidr)) {
                fprintf(stderr, "[ERROR] Invalid CIDR '%s' in options.location-tags tag '%s'\n",
                        cfg->location_tags[ti].cidrs[ci].cidr, cfg->location_tags[ti].tag);
                ecs_error = true;
            }
        }
    }
    for (zone_config_t *zc = cfg->zones; zc; zc = zc->next) {
        if (zc->ecs_tag_count > 0) has_ecs_tags = true;
        for (int ti = 0; ti < zc->ecs_tag_count; ti++) {
            for (int ci = 0; ci < zc->ecs_tags[ti].cidr_count; ci++) {
                if (!validate_cidr_syntax(zc->ecs_tags[ti].cidrs[ci].cidr)) {
                    fprintf(stderr, "[ERROR] Zone '%s': Invalid CIDR '%s' in ecs-tags tag '%s'\n",
                            zc->domain, zc->ecs_tags[ti].cidrs[ci].cidr, zc->ecs_tags[ti].tag);
                    ecs_error = true;
                }
            }
        }
        for (int ti = 0; ti < zc->location_tag_count; ti++) {
            for (int ci = 0; ci < zc->location_tags[ti].cidr_count; ci++) {
                if (!validate_cidr_syntax(zc->location_tags[ti].cidrs[ci].cidr)) {
                    fprintf(stderr, "[ERROR] Zone '%s': Invalid CIDR '%s' in location-tags tag '%s'\n",
                            zc->domain, zc->location_tags[ti].cidrs[ci].cidr, zc->location_tags[ti].tag);
                    ecs_error = true;
                }
            }
        }
    }
    if (has_ecs_tags && !cfg->ecs_enable) {
        fprintf(stderr, "[WARNING] ecs-tags defined, but ecs-enable is not set to 'yes' in options{}\n");
    }
    if (ecs_error) {
        free(buf);
        return 1;
    }

    printf("[OK] Config file %s is valid.\n", config_path);
    free(buf);
    return 0;
}

KARIDNS_TOOL_FN void print_usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-v | --version]\n", prog);
    fprintf(stderr, "  %s conf [config_path]\n", prog);
    fprintf(stderr, "  %s zones [config_path]\n", prog);
    fprintf(stderr, "  %s zone <domain> [config_path]\n", prog);
    fprintf(stderr, "  %s zone <domain> <zone_file_path>\n", prog);
}

#if defined(KARIDNS_COVERAGE_LINKAGE) && !defined(main)
/* Coverage builds: the tests #include this file with "#define main karicheck_main",
 * so the body below is named karicheck_main here as well; llvm-cov then merges the
 * counters of every binary that runs it (see karidns_tool_linkage.h). */
int karicheck_main(int argc, char **argv);
int main(int argc, char **argv) { return karicheck_main(argc, argv); }
#define main karicheck_main
#endif
int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("karicheck %s\n", KARIDNS_VERSION);
        return 0;
    }

    const char *cmd = argv[1];
    const char *default_config = "/usr/local/etc/karidns/karidns.conf";
    if (access(default_config, F_OK) != 0 && access("/usr/local/etc/karidns.conf", F_OK) == 0) {
        default_config = "/usr/local/etc/karidns.conf";
    }

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
        int skipped = 0;
        for (view_config_t *v = cfg.views; v; v = v->next) {
            for (zone_config_t *z = v->zones; z; z = z->next) {
                /* 型名はパーサが小文字の master/slave/forward/program に正規化している (D-23) */
                if (!z->type || strcmp(z->type, "master") == 0) {
                    if (check_zone(z->domain, z->file, false, z->is_catalog, z->file_format, z, &cfg, v) != 0) {
                        error_count++;
                    }
                    checked++;
                } else {
                    printf("[INFO] Skipping zone '%s' (type %s): no zone file to check\n", z->domain, z->type);
                    skipped++;
                }
            }
        }
        printf("[INFO] Checked %d zones (%d skipped). Errors: %d\n", checked, skipped, error_count);
        return (error_count > 0) ? 1 : 0;
    } else if (strcmp(cmd, "zone") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        const char *domain = argv[2];
        if (argc >= 4 && strstr(argv[3], ".conf") == NULL) {
            // Standalone mode: karicheck zone <domain> <zone_file_path>
            return check_zone(domain, argv[3], true, false, NULL, NULL, NULL, NULL);
        } else {
            // From config: karicheck zone <domain> [config_path]
            const char *cfg_path = (argc >= 4) ? argv[3] : default_config;
            server_config_t cfg;
            memset(&cfg, 0, sizeof(cfg));
            if (check_config(cfg_path, &cfg) != 0) return 1;

            // Normalize domain for comparison (config parser adds trailing dot)
            char norm_domain[256];
            normalize_domain_fqdn(domain, norm_domain, sizeof(norm_domain));

            /* 同じゾーン名が複数の view にあれば、それぞれの view の定義を検査する (R-26) */
            int found = 0;
            int failed = 0;
            for (view_config_t *v = cfg.views; v; v = v->next) {
                for (zone_config_t *z = v->zones; z; z = z->next) {
                    if (strcasecmp(z->domain, norm_domain) != 0) continue;
                    found++;
                    if (z->type && strcasecmp(z->type, "program") == 0) {
                        printf("[INFO] Zone '%s' is type 'program'; skipping file validation.\n", z->domain);
                    } else if (check_zone(z->domain, z->file, false, z->is_catalog, z->file_format, z, &cfg, v) != 0) {
                        failed++;
                    }
                    break;
                }
            }
            if (found == 0) {
                fprintf(stderr, "[ERROR] Zone '%s' not found in config %s\n", domain, cfg_path);
                return 1;
            }
            return failed > 0 ? 1 : 0;
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}
