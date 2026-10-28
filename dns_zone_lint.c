/*
 * dns_zone_lint.c - the zone checks of karicheck that work on a parsed zone (see dns_zone_lint.h).
 *
 * Moved out of tools/karicheck.c in B12 so that `karidns-dbloader --check` can run them on a zone built from database rows.
 * Behaviour and message texts are those of `karicheck zone`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include "dns_zone_lint.h"
#include "dns_utils.h"
#include "dns_wire.h"

/* K-04: every [ERROR] / [WARNING] a zone check prints goes through kc_error() / kc_warning(), which count it, so that the [RESULT]
 * numbers equal the lines printed.  t == NULL: print without counting.  With t->sink the text goes to the sink instead. */
static void kc_vreport(kc_tally_t *t, int *counter, char level, FILE *fp, const char *tag, const char *fmt, va_list ap) {
    if (t && t->sink) {
        char buf[2048];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        size_t n = strlen(buf);
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
        t->sink(t->sink_ud, level, buf);
    } else {
        if (tag) fprintf(fp, "[%s] ", tag);
        vfprintf(fp, fmt, ap);
    }
    if (counter) (*counter)++;
}

void kc_error(kc_tally_t *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vreport(t, t ? &t->errors : NULL, 'E', stderr, "ERROR", fmt, ap);
    va_end(ap);
}

void kc_warning(kc_tally_t *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vreport(t, t ? &t->warnings : NULL, 'W', stderr, "WARNING", fmt, ap);
    va_end(ap);
}

void kc_info(kc_tally_t *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vreport(t, NULL, 'I', stdout, "INFO", fmt, ap);
    va_end(ap);
}

void kc_ok(kc_tally_t *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vreport(t, NULL, 'O', stdout, "OK", fmt, ap);
    va_end(ap);
}

/* ---- The check-* policy as text, for karidns-dbloader --check (--zone-checks): "mx-cname=warn,integrity=fail,names=ignore".  `names` is check-names
 * of a primary zone (the zone type of a database zone). ---- */
static const struct { const char *name; int chk; } k_lint_policy_names[] = {
    {"names", ZC_NAMES_PRIMARY}, {"dup-records", ZC_DUP_RECORDS}, {"integrity", ZC_INTEGRITY}, {"mx", ZC_MX}, {"mx-cname", ZC_MX_CNAME},
    {"sibling", ZC_SIBLING}, {"spf", ZC_SPF}, {"srv-cname", ZC_SRV_CNAME}, {"svcb", ZC_SVCB}, {"wildcard", ZC_WILDCARD},
};
static const char *const k_lint_sev_names[] = { "fail", "warn", "ignore" };

int zone_lint_policy_parse(const char *spec, uint8_t chk[ZC_N], uint8_t *names, char *err, size_t errlen) {
    for (int i = 0; i < ZC_N; i++) chk[i] = CHK_DEFAULT;
    *names = CHK_DEFAULT;
    const char *p = spec;
    while (p && *p) {
        const char *comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        const char *eq = memchr(p, '=', n);
        int ci = -1, sev = -1;
        if (eq) {
            for (size_t i = 0; i < sizeof(k_lint_policy_names) / sizeof(k_lint_policy_names[0]); i++)
                if (strlen(k_lint_policy_names[i].name) == (size_t)(eq - p) && strncmp(k_lint_policy_names[i].name, p, (size_t)(eq - p)) == 0) ci = k_lint_policy_names[i].chk;
            for (int i = 0; i < 3; i++)
                if (strlen(k_lint_sev_names[i]) == n - (size_t)(eq - p) - 1 && strncmp(k_lint_sev_names[i], eq + 1, n - (size_t)(eq - p) - 1) == 0) sev = i;
        }
        if (ci < 0 || sev < 0) {
            snprintf(err, errlen, "invalid check policy '%.*s' (expected name=fail|warn|ignore)", (int)n, p);
            return -1;
        }
        if (ci == ZC_NAMES_PRIMARY) *names = (uint8_t)sev;
        else chk[ci] = (uint8_t)sev;
        p = comma ? comma + 1 : NULL;
    }
    return 0;
}

size_t zone_lint_policy_format(const uint8_t chk[ZC_N], uint8_t names, char *out, size_t cap) {
    size_t len = 0;
    if (cap) out[0] = '\0';
    for (size_t i = 0; i < sizeof(k_lint_policy_names) / sizeof(k_lint_policy_names[0]); i++) {
        uint8_t sev = k_lint_policy_names[i].chk == ZC_NAMES_PRIMARY ? names : chk[k_lint_policy_names[i].chk];
        if (sev > CHK_IGNORE) continue;   /* CHK_DEFAULT: nothing written */
        int w = snprintf(out + len, cap - len, "%s%s=%s", len ? "," : "", k_lint_policy_names[i].name, k_lint_sev_names[sev]);
        if (w < 0 || (size_t)w >= cap - len) break;
        len += (size_t)w;
    }
    return len;
}

/* A finding of a check whose severity the configuration may set (check-* options, batch 7): sev is CHK_FAIL (an error), CHK_WARN (a warning),
 * CHK_IGNORE (nothing), or CHK_DEFAULT, which keeps the severity KariDNS always gave the finding: dflt = 'E', 'W' or 'N' (nothing). */
void kc_finding(kc_tally_t *t, uint8_t sev, char dflt, const char *fmt, ...) {
    char lvl = sev == CHK_FAIL ? 'E' : sev == CHK_WARN ? 'W' : sev == CHK_IGNORE ? 'N' : dflt;
    if (lvl == 'N') return;
    va_list ap;
    va_start(ap, fmt);
    if (lvl == 'E') kc_vreport(t, t ? &t->errors : NULL, 'E', stderr, "ERROR", fmt, ap);
    else kc_vreport(t, t ? &t->warnings : NULL, 'W', stderr, "WARNING", fmt, ap);
    va_end(ap);
}

/* a continuation line of the finding before it (stderr, no tag; the text carries its own indent) */
void kc_detail(kc_tally_t *t, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vreport(t, NULL, 'D', stderr, NULL, fmt, ap);
    va_end(ap);
}

/* [T6] RFC 2181 §5.2 TTL不整合検出用ソート比較関数
 * build_zone_index() 実行前の生データを qsort で正規化前に冗丸を検出する */
static int cmp_rec_by_name_type(const void *pa, const void *pb) {
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

static void check_dnssec_algorithm(kc_tally_t *t, int alg_num, const char *rec_name, const char *rec_type, int flags, int protocol) {
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
static void check_dnssec_blob_length(kc_tally_t *t, int alg_num, const char *rec_name, const char *rec_type,
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

static void check_ds_digest_type(kc_tally_t *t, int digest_type, int algorithm, int key_tag,
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

/* RFC 4034 §6.2 の正規形の RR 1 件 (名前は非圧縮、所有者名と item 3 の型の RDATA 内の名前は小文字)。 */
typedef struct {
    const dns_record_t *rec;
    uint8_t *wire;      /* 所有者名, TYPE, CLASS, TTL, RDLENGTH, RDATA */
    uint16_t len;
    uint16_t rdata_off;
} kc_canon_rr_t;

static bool kc_canonical_rr(const dns_record_t *rec, kc_canon_rr_t *out) {
    uint8_t buf[65535];
    uint16_t len = 0;
    /* owner_name を渡すと所有者名は非圧縮形で書かれる (rec->name_wire は元の大文字小文字のまま)。D17-4 以降
     * serialize_dns_record() は名前の大文字小文字を変えないので、正規形 (RFC 4034 §6.2) の小文字化はここで行う */
    if (serialize_dns_record(buf, sizeof(buf), &len, rec, NULL, rec->name, 0xFFFFFFFF) != 0) return false;
    size_t owner = 0;
    while (owner < len && buf[owner] != 0) owner += 1 + (size_t)buf[owner];
    owner++;
    if (owner + 10 > len) return false;
    dns_canonical_downcase_rdata(2 /* one name */, buf, owner);
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
static int kc_cmp_canon_rr(const void *a, const void *b) {
    const kc_canon_rr_t *x = a, *y = b;
    int c = compare_canonical_name(x->rec->name, y->rec->name);
    if (c != 0) return c;
    if (x->rec->type_code != y->rec->type_code) return x->rec->type_code < y->rec->type_code ? -1 : 1;
    size_t lx = (size_t)(x->len - x->rdata_off), ly = (size_t)(y->len - y->rdata_off);
    int m = memcmp(x->wire + x->rdata_off, y->wire + y->rdata_off, lx < ly ? lx : ly);
    if (m != 0) return m;
    return lx < ly ? -1 : (lx > ly ? 1 : 0);
}

static bool validate_zonemd_scheme_halg(const dns_record_t *zm, uint8_t *out_scheme,
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
static bool verify_zonemd(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
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
            kc_info(t, "ZONEMD (Scheme %d, Hash %d) for '%s' is not verified: unsupported scheme or hash "
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
            kc_ok(t, "ZONEMD (Scheme %d, Hash %d) for '%s' is VALID.\n", scheme, halg, domain);
        } else {
            kc_error(t, "ZONEMD (Scheme %d, Hash %d) for '%s' is INVALID.\n", scheme, halg, domain);
            char got[2 * EVP_MAX_MD_SIZE + 1];
            for (unsigned int j = 0; j < md_len[halg]; j++) snprintf(got + 2 * j, sizeof(got) - 2 * j, "%02x", md[halg][j]);
            kc_detail(t, "       Expected: %s\n", hex);
            kc_detail(t, "       Computed: %s\n", got);
            all_valid = false;
        }
    }

    for (size_t i = 0; i < n; i++) free(rrs[i].wire);
    free(rrs);
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

/* 以下 2 つは名前 (ゾーンパーサが作る正規形) のラベル単位の包含判定。ラベル境界はエスケープ
 * されない '.' だけ (R-29 / O-08 と同じ規則。domain_name_is_at_or_below() を使う)。 */
static bool is_subdomain_of(const char *name, const char *parent) {
    if (!name || !parent) return false;
    return domain_name_is_at_or_below(name, parent);
}

static bool is_strict_subdomain_of(const char *name, const char *parent) {
    if (!name || !parent) return false;
    return domain_name_is_at_or_below(name, parent) && !domain_names_match_ci(name, parent);
}

/* NS のターゲットに名前があり、そのアドレスがこのゾーンに無ければ委任/ゾーンが引けない (ERROR、RFC 9471 は委任の
 * グルー)。MX/SRV のターゲットにアドレスを求める RFC はないので警告にとどめる (K-02、RFC 8976 Appendix A.2)。
 * 重複の検査は NS と MX/SRV で分ける (同じ名前の MX が先にあっても NS のエラーを隠さない)。 */
static uint8_t lint_sev(const zone_lint_in_t *in, int c) { return (in && in->chk) ? in->chk[c] : CHK_DEFAULT; }

static void lint_glue_consistency(const zone_lint_in_t *in, const char *domain, zone_arena_t *arena, kc_tally_t *t) {
    if (lint_sev(in, ZC_INTEGRITY) == CHK_IGNORE) return;   /* check-integrity no: neither the NS glue nor the MX / SRV addresses are looked for */
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

static void lint_cname_coexistence(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
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

static void lint_delegation_occlusion(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
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

static void lint_cname_targets(const zone_lint_in_t *in, const char *domain, zone_arena_t *arena, kc_tally_t *t) {
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
                /* an NS target that is an alias always fails; check-mx-cname sets the severity of an MX target (BIND default warn, here error) */
                kc_finding(t, rec->type_code == 15 ? lint_sev(in, ZC_MX_CNAME) : (uint8_t)CHK_DEFAULT, 'E',
                           "%s record '%s' points to CNAME target '%s' (RFC 2181 section 10.3)\n", type_name, rec->name, target);
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
                kc_finding(t, lint_sev(in, ZC_SRV_CNAME), 'W', "SRV record '%s' points to CNAME target '%s' (RFC 2782)\n", rec->name, rec->rdata[3]);
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

/* ---- Batch 7: checks selected by check-wildcard, check-dup-records, check-mx and check-names (BIND 9.20 bin/named/zoneconf.c, lib/dns/master.c,
 * lib/dns/zone.c).  Their default (check-* not written) is "no finding": KariDNS has never reported these, so a zone that karicheck passed
 * yesterday still passes; BIND's own defaults (warn, warn, warn, fail) apply only to what the configuration writes. ---- */

/* an owner name with a `*` label that is not the leftmost one: BIND dns_name_internalwildcard() ("ownername '%s' contains a non-terminal wildcard") */
static bool lint_internal_wildcard(const char *name) {
    size_t n = dns_name_len_no_root(name, strlen(name));
    for (size_t i = 0; i < n; i++) {
        if (name[i] == '\\') { i++; continue; }
        if (name[i] != '*') continue;
        bool lstart = i == 0 || name[i - 1] == '.';
        bool lend = i + 1 == n || name[i + 1] == '.';
        if (lstart && lend && i != 0) return true;   /* a whole label `*` that is not the first label */
    }
    return false;
}

static void lint_wildcard(const zone_lint_in_t *in, zone_arena_t *arena, kc_tally_t *t) {
    uint8_t sev = lint_sev(in, ZC_WILDCARD);
    if (sev == CHK_DEFAULT || sev == CHK_IGNORE) return;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        if (!r->name || !lint_internal_wildcard(r->name)) continue;
        bool seen = false;   /* once per name */
        for (size_t j = 0; j < i && !seen; j++) seen = arena->records[j].name && domain_names_match_ci(arena->records[j].name, r->name);
        if (!seen) kc_finding(t, CHK_WARN, 'W', "ownername '%s' contains a non-terminal wildcard (check-wildcard)\n", r->name);
    }
}

/* the same RR twice in one RRset (BIND check-dup-records: "<name>: <type>/<class> has duplicate rdata" at load) */
static void lint_dup_records(const zone_lint_in_t *in, zone_arena_t *arena, kc_tally_t *t) {
    uint8_t sev = lint_sev(in, ZC_DUP_RECORDS);
    if (sev == CHK_DEFAULT || sev == CHK_IGNORE || !arena->hash_table || arena->hash_size == 0) return;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *a = &arena->records[i];
        if (!a->name) continue;
        size_t slot = calc_fnv1a_str(a->name) & (arena->hash_size - 1);
        for (int j = arena->hash_table[slot]; j != -1; j = arena->records[j].next_record) {
            const dns_record_t *b = &arena->records[j];
            if ((size_t)j <= i || !b->name || b->type_code != a->type_code || !domain_names_match_ci(a->name, b->name)) continue;
            if (!compare_records(a, b, true)) continue;
            kc_finding(t, sev, 'W', "'%s' %s has duplicate rdata (check-dup-records)\n", a->name, a->type ? a->type : "(type)");
            break;   /* one finding per record that has a later twin */
        }
    }
}

/* an MX whose target is an IP address: the target must be a host name (RFC 1035 §3.3.9, RFC 5321 §5.1; BIND check-mx: "MX is an address") */
static void lint_mx_address(const zone_lint_in_t *in, zone_arena_t *arena, kc_tally_t *t) {
    uint8_t sev = lint_sev(in, ZC_MX);
    if (sev == CHK_DEFAULT || sev == CHK_IGNORE) return;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        if (r->type_code != 15 || r->rdata_count < 2 || !r->rdata[1]) continue;
        uint8_t b[16];
        size_t tl = dns_name_len_no_root(r->rdata[1], strlen(r->rdata[1]));
        char tmp[64];
        if (tl == 0 || tl >= sizeof(tmp)) continue;
        memcpy(tmp, r->rdata[1], tl);
        tmp[tl] = '\0';
        if (inet_pton(AF_INET, tmp, b) == 1 || inet_pton(AF_INET6, tmp, b) == 1)
            kc_finding(t, sev, 'W', "MX record '%s' has the IP address '%s' as its target (check-mx)\n", r->name, tmp);
    }
}

/* check-names: a host name is letters, digits and hyphens, no label starting or ending with a hyphen (RFC 952, RFC 1123 §2.1; BIND
 * dns_name_ishostname()).  A leading `*` label is allowed in an owner name.  `\` escapes make a name something else than a host name. */
static bool lint_is_hostname(const char *name, bool wildcard_ok) {
    size_t n = dns_name_len_no_root(name, strlen(name));
    if (n == 0) return true;   /* the root */
    size_t label_start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && name[i] != '.') {
            char c = name[i];
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
                      (c == '*' && wildcard_ok && i == 0 && (n == 1 || name[1] == '.'));
            if (!ok) return false;
            continue;
        }
        if (i == label_start) return false;   /* an empty label */
        if (name[label_start] == '-' || name[i - 1] == '-') return false;
        label_start = i + 1;
    }
    return true;
}

static void lint_check_names(const zone_lint_in_t *in, zone_arena_t *arena, kc_tally_t *t) {
    uint8_t sev = in ? in->chk_names : (uint8_t)CHK_DEFAULT;
    if (sev == CHK_DEFAULT || sev == CHK_IGNORE) return;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        if (!r->name) continue;
        const char *target = NULL;
        bool owner = r->type_code == 1 || r->type_code == 28 || r->type_code == 15;   /* A, AAAA, MX: the owner is a host */
        if (r->type_code == 2 && r->rdata_count >= 1) target = r->rdata[0];
        else if (r->type_code == 15 && r->rdata_count >= 2) target = r->rdata[1];
        else if (r->type_code == 33 && r->rdata_count >= 4) target = r->rdata[3];
        else if (r->type_code == 6 && r->rdata_count >= 1) target = r->rdata[0];
        if (owner && !lint_is_hostname(r->name, true))
            kc_finding(t, sev, 'E', "%s record owner '%s' is not a valid host name (check-names)\n", r->type ? r->type : "?", r->name);
        if (target && strcmp(target, ".") != 0 && !lint_is_hostname(target, false))
            kc_finding(t, sev, 'E', "%s record '%s': the name '%s' is not a valid host name (check-names)\n", r->type ? r->type : "?", r->name, target);
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
static void lint_nsec3(const char *domain, zone_arena_t *arena, kc_tally_t *t) {
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



/* ------------------------------------------------------------------------------------------------------------- */
/* checks on a whole parsed zone (called by karicheck zone and karidns-dbloader --check)                          */
/* ------------------------------------------------------------------------------------------------------------- */

void zone_lint_ttl(const zone_arena_t *arena_in, const char *what, kc_tally_t *t) {
    const zone_arena_t *arena = arena_in;
    if (arena->count > 0) {
        dns_record_t **sorted = malloc(sizeof(dns_record_t *) * arena->count);
        if (sorted) {
            for (size_t k = 0; k < arena->count; k++) sorted[k] = &arena->records[k];
            qsort(sorted, arena->count, sizeof(dns_record_t *), cmp_rec_by_name_type);
            /* B8t-2: the TTLs of an RRset are harmonized (lowest wins) among the RRs that have the same visibility only (location, time
             * stamp, tag); an RR that only some clients see keeps its TTL, so an unrestricted RR and a restricted RR of one name and type
             * with different TTLs make a client that sees both get an RRset with differing TTLs (tinydns serves them that way). */
            for (size_t k = 0; k < arena->count;) {
                size_t e = k + 1;
                while (e < arena->count && sorted[e]->name && sorted[k]->name && sorted[e]->type_code == sorted[k]->type_code &&
                       strcasecmp(sorted[e]->name, sorted[k]->name) == 0)
                    e++;
                if (!sorted[k]->name || sorted[k]->type_code == 46 || e - k < 2) {
                    k = e;
                    continue;
                }
                size_t lim = e - k > 64 ? k + 64 : e;     /* a very large RRset: compare the first 64 */
                bool warned_norm = false, warned_covis = false;
                for (size_t a = k; a < lim; a++) {
                    for (size_t b = a + 1; b < lim; b++) {
                        if (sorted[a]->ttl_value == sorted[b]->ttl_value) continue;
                        if (dns_record_same_visibility(sorted[a], sorted[b])) {
                            if (warned_norm) continue;
                            warned_norm = true;
                            kc_warning(t,
                                "RRset '%s' type %d has inconsistent TTLs (%u vs %u) in the source "
                                "%s; RFC 2181 §5.2 requires all RRs in an RRset to share the same TTL. "
                                "KariDNS will normalize this to the minimum value at load time, "
                                "but the %s should be corrected.\n",
                                sorted[a]->name, sorted[a]->type_code, sorted[a]->ttl_value, sorted[b]->ttl_value, what, what);
                        } else if (dns_record_is_restricted(sorted[a]) != dns_record_is_restricted(sorted[b])) {
                            if (warned_covis) continue;
                            warned_covis = true;
                            kc_warning(t,
                                "RRset '%s' type %d: an RR that every client sees and an RR with a location, time stamp or tag have "
                                "different TTLs (%u vs %u). A client that sees both gets an RRset with differing TTLs (RFC 2181 §5.2); "
                                "KariDNS keeps the TTL written on each RR, as tinydns does.\n",
                                sorted[a]->name, sorted[a]->type_code, sorted[a]->ttl_value, sorted[b]->ttl_value);
                        }
                    }
                }
                k = e;
            }
            free(sorted);
        }
    }
}

/* B9a (design 3.6b): the notes about PowerDNS ALIAS and LUA records of a zone */
void zone_lint_pdns_types(const zone_arena_t *arena, const char *domain, kc_tally_t *t) {
    size_t n_alias = 0, n_lua = 0;
    for (size_t i = 0; i < arena->count; i++) {
        const dns_record_t *r = &arena->records[i];
        if (r->class_val != 1 && r->class_val != 0) continue;
        if (r->type_code == DNS_TYPE_PDNS_ALIAS) n_alias++;
        else if (r->type_code == DNS_TYPE_PDNS_LUA) n_lua++;
    }
    if (n_alias > 0)
        kc_info(t, "Zone '%s': %zu ALIAS record(s); A/AAAA at those names are NODATA unless an alias-resolver { } is configured for the zone (design 3.6b)\n",
                domain, n_alias);
    if (n_lua > 0)
        kc_warning(t, "Zone '%s': %zu LUA record(s) are kept for zone transfers and never answered (PowerDNS enable-lua-records=no behaviour; LUA records are not executed)\n",
                   domain, n_lua);
}

void zone_lint_records(zone_arena_t *arena, const zone_lint_in_t *in, kc_tally_t *t) {
    const char *domain = in->domain;
    const char *raw = in->raw_text;
    bool has_soa = false;
    int soa_count = 0; /* [T3] SOA重複検出用 */
    int soa_plain_count = 0; /* B8t-1: apex SOA RRs that every client sees (no location, time stamp or tag) */
    bool has_apex_ns = false;

    if (arena->is_tinydns_format) {
        for (int i = 0; i < arena->location_count; i++) {
            const tinydns_location_entry_t *loc = &arena->locations[i];
            if (loc->prefix_bits > 32) {
                kc_error(t, "Location prefix length /%u exceeds /32 for location '%.2s' in zone '%s'\n",
                        loc->prefix_bits, loc->code, domain);
            }
            for (int j = i + 1; j < arena->location_count; j++) {
                if (arena->locations[j].code[0] == loc->code[0] &&
                    arena->locations[j].code[1] == loc->code[1]) {
                    kc_warning(t, "Duplicate location code '%.2s' in zone '%s' (%s)\n",
                            loc->code, domain, in->src);
                    break;
                }
            }
        }

        // Tinydns third-party patch syntax validations on raw lines
        size_t linestart = 0;
        size_t buflen = raw ? strlen(raw) : 0;
        unsigned long linenum = 1;
        while (linestart < buflen) {
            size_t lineend = linestart;
            while (lineend < buflen && raw[lineend] != '\n') lineend++;
            size_t linelen = lineend - linestart;
            const char *line = raw + linestart;

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
                            kc_error(t, "Zone '%s' (line %lu): type '%c' requires a 32-character hexadecimal IPv6 address, got '%.*s'\n",
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
                                kc_error(t, "Zone '%s' (line %lu): SRV port '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[3]);
                            }
                        }
                        if (flen[4] > 0) {
                            char *endp;
                            unsigned long w = strtoul(fld[4], &endp, 10);
                            if (*endp != '\0' || w > 65535) {
                                kc_error(t, "Zone '%s' (line %lu): SRV weight '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[4]);
                            }
                        }
                        if (flen[5] > 0) {
                            char *endp;
                            unsigned long prio = strtoul(fld[5], &endp, 10);
                            if (*endp != '\0' || prio > 65535) {
                                kc_error(t, "Zone '%s' (line %lu): SRV priority '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[5]);
                            }
                        }
                    } else if (ch == 'N') {
                        // Nfqdn:order:pref:flags:service:regexp:replacement:ttl:timestamp:lo
                        if (flen[1] > 0) {
                            char *endp;
                            unsigned long ord = strtoul(fld[1], &endp, 10);
                            if (*endp != '\0' || ord > 65535) {
                                kc_error(t, "Zone '%s' (line %lu): NAPTR order '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[1]);
                            }
                        }
                        if (flen[2] > 0) {
                            char *endp;
                            unsigned long pref = strtoul(fld[2], &endp, 10);
                            if (*endp != '\0' || pref > 65535) {
                                kc_error(t, "Zone '%s' (line %lu): NAPTR preference '%s' out of range (0-65535)\n",
                                        domain, linenum, fld[2]);
                            }
                        }
                    } else if (ch == '_') {
                        // _fqdn:algorithm:fp_type:fingerprint:ttl:timestamp:lo
                        if (flen[1] > 0) {
                            char *endp;
                            unsigned long alg = strtoul(fld[1], &endp, 10);
                            if (*endp != '\0' || alg > 255) {
                                kc_error(t, "Zone '%s' (line %lu): SSHFP algorithm '%s' out of range (0-255)\n",
                                        domain, linenum, fld[1]);
                            } else if (alg == 0 || alg > 4) {
                                kc_warning(t, "Zone '%s' (line %lu): SSHFP algorithm '%lu' is outside standard RFC assignments (1-4)\n",
                                        domain, linenum, alg);
                            }
                        }
                        if (flen[2] > 0) {
                            char *endp;
                            unsigned long fpt = strtoul(fld[2], &endp, 10);
                            if (*endp != '\0' || fpt > 255) {
                                kc_error(t, "Zone '%s' (line %lu): SSHFP fp_type '%s' out of range (0-255)\n",
                                        domain, linenum, fld[2]);
                            } else if (fpt == 0 || fpt > 2) {
                                kc_warning(t, "Zone '%s' (line %lu): SSHFP fp_type '%lu' is outside standard RFC assignments (1-2)\n",
                                        domain, linenum, fpt);
                            }
                        }
                        uint8_t fp_bin[64];
                        size_t dec_len = hex_decode(fld[3], fp_bin, sizeof(fp_bin));
                        if (flen[3] == 0 || dec_len == 0 || dec_len == (size_t)-1) {
                            kc_error(t, "Zone '%s' (line %lu): SSHFP invalid fingerprint hex string '%s'\n",
                                    domain, linenum, fld[3]);
                        }
                    }
                }
            }

            linestart = lineend + 1;
            linenum++;
        }
    }

    const ecs_tag_def_t *active_ecs_tags = (arena->bind_ecs_tags && arena->bind_ecs_tag_count > 0) ? arena->bind_ecs_tags : in->ecs_tags;
    int active_ecs_tag_count = (arena->bind_ecs_tags && arena->bind_ecs_tag_count > 0) ? arena->bind_ecs_tag_count : in->ecs_tag_count;
    const ecs_tag_def_t *active_loc_tags = (arena->bind_location_tags && arena->bind_location_tag_count > 0) ? arena->bind_location_tags : in->loc_tags;
    int active_loc_tag_count = (arena->bind_location_tags && arena->bind_location_tag_count > 0) ? arena->bind_location_tag_count : in->loc_tag_count;

    for (size_t i = 0; i < arena->count; i++) {
        if (arena->records[i].ecs_subnet_tag != NULL) {
            bool tag_found = false;
            for (int ti = 0; ti < active_ecs_tag_count; ti++) {
                if (strcasecmp(active_ecs_tags[ti].tag, arena->records[i].ecs_subnet_tag) == 0) {
                    tag_found = true;
                    break;
                }
            }
            if (!tag_found) {
                kc_error(t, "Zone '%s': record '%s' references undefined ECS subnet tag '%s'\n",
                        domain, arena->records[i].name, arena->records[i].ecs_subnet_tag);
            }
        }

        if (arena->records[i].bind_location_tag != NULL) {
            bool tag_found = false;
            for (int ti = 0; ti < active_loc_tag_count; ti++) {
                if (strcasecmp(active_loc_tags[ti].tag, arena->records[i].bind_location_tag) == 0) {
                    tag_found = true;
                    break;
                }
            }
            if (!tag_found) {
                kc_error(t, "Zone '%s': record '%s' references undefined location tag '%s'\n",
                        domain, arena->records[i].name, arena->records[i].bind_location_tag);
            }
        }

        uint16_t tcode = arena->records[i].type_code;
        int rcount = arena->records[i].rdata_count;
        char **rdata = arena->records[i].rdata;

        if (tcode == 1) { // A
            if (rcount != 1) {
                kc_error(t, "A record must have exactly 1 parameter for name '%s' in zone '%s'\n", arena->records[i].name, domain);
            } else {
                struct in_addr tmp;
                if (inet_pton(AF_INET, rdata[0], &tmp) != 1) {
                    kc_error(t, "Invalid IPv4 address '%s' for name '%s' in zone '%s'\n", rdata[0], arena->records[i].name, domain);
                }
            }
        }
        if (tcode == 28) { // AAAA
            if (rcount != 1) {
                kc_error(t, "AAAA record must have exactly 1 parameter for name '%s' in zone '%s'\n", arena->records[i].name, domain);
            } else {
                struct in6_addr tmp;
                if (inet_pton(AF_INET6, rdata[0], &tmp) != 1) {
                    kc_error(t, "Invalid IPv6 address '%s' for name '%s' in zone '%s'\n", rdata[0], arena->records[i].name, domain);
                }
            }
        }

        if (tcode == 6 && strcasecmp(arena->records[i].name, domain) == 0) {
            has_soa = true;
            /* [T3] SOA重複検出: apexに2度以上の SOAは破損ゾーンファイル */
            soa_count++;
            if (!dns_record_is_restricted(&arena->records[i])) soa_plain_count++;
        }
        if (tcode == 2 && strcasecmp(arena->records[i].name, domain) == 0) {
            has_apex_ns = true;
        }
        if (tcode == 62) { // CSYNC
            for (int j = 2; j < rcount; j++) {
                if (get_type_code(rdata[j]) == 0) {
                    kc_warning(t, "CSYNC record contains unknown type '%s' in zone '%s' (%s)\n", rdata[j], domain, in->src);
                }
            }
        }
        if (tcode == 64 || tcode == 65) { // SVCB / HTTPS
            if (rcount > 1) {
                const char *target = rdata[1];
                size_t len = strlen(target);
                if (len > 0 && target[len - 1] != '.' && strcmp(target, ".") != 0) {
                    kc_warning(t, "%s record TargetName '%s' does not end with a dot in zone '%s' (%s)\n",
                            tcode == 64 ? "SVCB" : "HTTPS",
                            target, domain, in->src);
                }
            }
        }
        
        // --- Add specific field validations ---
        if (tcode == 63) { // ZONEMD
            if (strcasecmp(arena->records[i].name, domain) != 0) {
                kc_warning(t, "ZONEMD record '%s' is not at the zone apex '%s' (RFC 8976 section 2.1)\n",
                        arena->records[i].name, domain);
            }
            if (rcount < 4) {
                kc_warning(t, "ZONEMD record for '%s' has fewer than 4 fields "
                                "(serial, scheme, hash-algorithm, digest)\n", arena->records[i].name);
            } else {
                validate_zonemd_scheme_halg(&arena->records[i], NULL, NULL, true, t);
            }
        }
        if (tcode == 48 || tcode == 60) { // DNSKEY / CDNSKEY
            if (rcount >= 3) {
                int flags = (int)strtol(rdata[0], NULL, 10);
                int protocol = (int)strtol(rdata[1], NULL, 10);
                int alg = (int)strtol(rdata[2], NULL, 10);
                check_dnssec_algorithm(t, alg, arena->records[i].name, tcode == 48 ? "DNSKEY" : "CDNSKEY", flags, protocol);
                if (rcount >= 4)
                    check_dnssec_blob_length(t, alg, arena->records[i].name, tcode == 48 ? "DNSKEY" : "CDNSKEY",
                                             false, &rdata[3], rcount - 3);
            }
        }
        if (tcode == 43 || tcode == 59) { // DS / CDS
            if (rcount >= 4) {
                int key_tag = (int)strtol(rdata[0], NULL, 10);
                int algorithm = (int)strtol(rdata[1], NULL, 10);
                int digest_type = (int)strtol(rdata[2], NULL, 10);
                check_ds_digest_type(t, digest_type, algorithm, key_tag,
                                     arena->records[i].name, tcode == 43 ? "DS" : "CDS");
            }
        }
        if (tcode == 46) { // RRSIG
            if (rcount >= 2) {
                check_dnssec_algorithm(t, (int)strtol(rdata[1], NULL, 10), arena->records[i].name, "RRSIG", -1, -1);
                if (rcount >= 9)
                    check_dnssec_blob_length(t, (int)strtol(rdata[1], NULL, 10), arena->records[i].name, "RRSIG",
                                             true, &rdata[8], rcount - 8);
            }
        }
        if (tcode == 55) { // HIP
            if (rcount < 3) {
                kc_warning(t, "HIP record requires at least 3 fields: HIT algorithm, HIT (hex), and public key (base64) for name '%s'\n", arena->records[i].name);
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
                    kc_error(t, "HIP record public key for name '%s' is not valid base64 (length %zu is not a non-zero multiple of 4) in zone '%s'\n",
                            arena->records[i].name, pk_b64_len, domain);
                }
            }
        }
        if (tcode == 11) { // WKS
            /* K-03: プロトコルはサーバーのシリアライザと同じ規則で読む (番号 0-255、または TCP/UDP) */
            uint8_t proto = 0;
            if (rcount >= 2 && !dns_wks_protocol_from_text(rdata[1], &proto)) {
                kc_warning(t, "WKS record protocol '%s' is neither a number (0-255) nor TCP/UDP for name '%s'\n",
                           rdata[1], arena->records[i].name);
            }
            /* X-38: ポート名はサーバーと同じ固定表で引く。読めないポートがあるとレコードは書けない (下の試し書き) */
            for (int j = 2; j < rcount; j++) {
                uint16_t port;
                if (!dns_wks_port_from_text(rdata[j], proto, &port)) {
                    kc_warning(t, "WKS record port '%s' for name '%s' is neither a number (0-65535) nor a known "
                                       "service name for protocol %u\n", rdata[j], arena->records[i].name, proto);
                }
            }
        }
        if (tcode == 27 && rcount < 3) { // GPOS
            kc_warning(t, "GPOS record requires exactly 3 fields (Longitude, Latitude, Altitude) for name '%s'\n", arena->records[i].name);
        }
        if (tcode == 19 && rcount < 1) { // X25
            kc_warning(t, "X25 record requires at least 1 field for name '%s'\n", arena->records[i].name);
        }
        if (tcode == 33) { // SRV
            if (rcount < 4) {
                kc_error(t, "SRV record requires 4 fields (priority, weight, port, target) for name '%s' in zone '%s'\n",
                        arena->records[i].name, domain);
            } else {
                char *endp;
                unsigned long prio = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || prio > 65535) {
                    kc_error(t, "SRV priority '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[0], arena->records[i].name, domain);
                }
                unsigned long weight = strtoul(rdata[1], &endp, 10);
                if (*endp != '\0' || weight > 65535) {
                    kc_error(t, "SRV weight '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[1], arena->records[i].name, domain);
                }
                unsigned long port = strtoul(rdata[2], &endp, 10);
                if (*endp != '\0' || port > 65535) {
                    kc_error(t, "SRV port '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[2], arena->records[i].name, domain);
                }
            }
        }
        if (tcode == 35) { // NAPTR
            if (rcount < 6) {
                kc_error(t, "NAPTR record requires 6 fields (order, preference, flags, service, regexp, replacement) for name '%s' in zone '%s'\n",
                        arena->records[i].name, domain);
            } else {
                char *endp;
                unsigned long ord = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || ord > 65535) {
                    kc_error(t, "NAPTR order '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[0], arena->records[i].name, domain);
                }
                unsigned long pref = strtoul(rdata[1], &endp, 10);
                if (*endp != '\0' || pref > 65535) {
                    kc_error(t, "NAPTR preference '%s' out of range (0-65535) for name '%s' in zone '%s'\n",
                            rdata[1], arena->records[i].name, domain);
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
                    kc_error(t, "NAPTR flags '%s' for name '%s' in zone '%s' must contain only "
                            "[A-Za-z0-9] characters (RFC 3403 §4.1)\n",
                            naptr_flags, arena->records[i].name, domain);
                }
                /* [T5] RFC 2915 §2: regexp と replacement は同時に非空であってはならない */
                bool naptr_has_regexp = (strlen(rdata[4]) > 0);
                bool naptr_has_replacement = (strlen(rdata[5]) > 0 && strcmp(rdata[5], ".") != 0);
                if (naptr_has_regexp && naptr_has_replacement) {
                    kc_error(t, "NAPTR record for '%s' in zone '%s' sets both a regexp and a "
                            "non-root replacement field; RFC 2915 requires exactly one of them to be empty\n",
                            arena->records[i].name, domain);
                }
            }
        }
        if (tcode == 257) { // CAA (RFC 8659)
            /* [T4] RFC 8659 CAAレコード検証 */
            if (rcount < 3) {
                kc_error(t, "CAA record requires 3 fields (flags, tag, value) for name '%s' in zone '%s'\n",
                        arena->records[i].name, domain);
            } else {
                char *endp;
                unsigned long caa_flags = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || caa_flags > 255) {
                    kc_error(t, "CAA flags '%s' out of range (0-255) for name '%s' in zone '%s'\n",
                            rdata[0], arena->records[i].name, domain);
                } else if ((caa_flags & ~0x80UL) != 0) {
                    /* RFC 8659 §4: bit0(critical=0x80)以外の未定義ビット */
                    kc_warning(t, "CAA record for '%s' sets undefined flag bits (0x%02lx); "
                            "only the critical bit (0x80) is defined by RFC 8659\n",
                            arena->records[i].name, caa_flags);
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
                    kc_error(t, "CAA tag '%s' for name '%s' does not match RFC 8659 syntax "
                            "(1-15 chars, [a-zA-Z0-9] only)\n",
                            caa_tag, arena->records[i].name);
                } else {
                    bool known_tag = (strcasecmp(caa_tag, "issue") == 0 ||
                                      strcasecmp(caa_tag, "issuewild") == 0 ||
                                      strcasecmp(caa_tag, "iodef") == 0 ||
                                      strcasecmp(caa_tag, "contactemail") == 0 ||
                                      strcasecmp(caa_tag, "contactphone") == 0);
                    if (!known_tag) {
                        bool is_critical = ((strtoul(rdata[0], NULL, 10) & 0x80) != 0);
                        if (is_critical) {
                            kc_error(t, "CAA record for '%s' has unknown tag '%s' with the critical flag set; "
                                    "RFC 8659 requires issuers to refuse issuance\n",
                                    arena->records[i].name, caa_tag);
                        } else {
                            kc_warning(t, "CAA record for '%s' has unrecognized tag '%s' "
                                    "(not one of issue/issuewild/iodef/contactemail/contactphone)\n",
                                    arena->records[i].name, caa_tag);
                        }
                    }
                }
            }
        }
        if (tcode == 44) { // SSHFP
            if (rcount < 3) {
                kc_error(t, "SSHFP record requires 3 fields (algorithm, fp_type, fingerprint) for name '%s' in zone '%s'\n",
                        arena->records[i].name, domain);
            } else {
                char *endp;
                unsigned long alg = strtoul(rdata[0], &endp, 10);
                if (*endp != '\0' || alg > 255) {
                    kc_error(t, "SSHFP algorithm '%s' out of range (0-255) for name '%s' in zone '%s'\n",
                            rdata[0], arena->records[i].name, domain);
                } else if (alg == 0 || alg > 4) {
                    kc_warning(t, "SSHFP record for '%s' uses algorithm '%lu' which is outside standard RFC assignments (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519)\n",
                            arena->records[i].name, alg);
                }
                unsigned long fpt = strtoul(rdata[1], &endp, 10);
                if (*endp != '\0' || fpt > 255) {
                    kc_error(t, "SSHFP fp_type '%s' out of range (0-255) for name '%s' in zone '%s'\n",
                            rdata[1], arena->records[i].name, domain);
                } else if (fpt == 0 || fpt > 2) {
                    kc_warning(t, "SSHFP record for '%s' uses fp_type '%lu' which is outside standard RFC assignments (1=SHA-1, 2=SHA-256)\n",
                            arena->records[i].name, fpt);
                }
                uint8_t fp_bin[64];
                size_t dec_len = hex_decode(rdata[2], fp_bin, sizeof(fp_bin));
                if (dec_len == 0 || dec_len == (size_t)-1) {
                    kc_error(t, "SSHFP invalid fingerprint hex string '%s' for name '%s' in zone '%s'\n",
                            rdata[2], arena->records[i].name, domain);
                }
            }
        }

        // --- RFC 1912 Operational Checks ---
        /* in-bailiwick の NS ターゲットのアドレスは lint_glue_consistency() が ERROR として検査する */
        if (tcode == 6 && rcount >= 2) { // SOA
            if (is_cname(arena, rdata[0])) {
                kc_warning(t, "SOA MNAME for '%s' points to a CNAME '%s' (RFC 1912)\n", arena->records[i].name, rdata[0]);
            }
        }
        if (tcode == 5) { // CNAME
            if (arena->hash_table && arena->hash_size > 0) {
                uint32_t hash = calc_fnv1a_str(arena->records[i].name);
                size_t idx = hash & (arena->hash_size - 1);
                for (int j = arena->hash_table[idx]; j != -1; j = arena->records[j].next_record) {
                    if (i != (size_t)j && strcasecmp(arena->records[j].name, arena->records[i].name) == 0) {
                        uint16_t other = arena->records[j].type_code;
                        // Ignore DNSSEC records
                        if (other != 5 && other != 46 && other != 47 && other != 50) {
                            kc_warning(t, "CNAME '%s' co-exists with other records (type %d) (RFC 1912)\n", arena->records[i].name, other);
                            break;
                        }
                    }
                }
            }
        }
        
        if (tcode == 20 && (rcount < 1 || rcount > 2)) { // ISDN
            kc_warning(t, "ISDN record requires 1 or 2 fields for name '%s'\n", arena->records[i].name);
        }
        if (tcode == 108 || tcode == 109) { // EUI48 / EUI64
            if (rcount >= 1) {
                int dashes = 0;
                for (const char *p = rdata[0]; *p; p++) {
                    if (*p == '-') dashes++;
                }
                if (tcode == 108 && dashes != 5) {
                    kc_warning(t, "EUI48 requires 6 octets (5 dashes) for name '%s'\n", arena->records[i].name);
                } else if (tcode == 109 && dashes != 7) {
                    kc_warning(t, "EUI64 requires 8 octets (7 dashes) for name '%s'\n", arena->records[i].name);
                }
            }
        }

        // Meta-types (OPT/TKEY/TSIG/IXFR/AXFR/MAILB/MAILA/ANY, and NXNAME
        // per RFC 9824) must NOT appear as standalone RRsets in zone data.
        // Shared with the runtime loader's check in dns_zone_parser.c so
        // karicheck and the actual server never disagree on this.
        if (is_meta_rrtype(tcode)) {
            kc_error(t, "type %u is a meta-type and must not appear "
                    "as a standalone RRset in zone '%s' (name '%s')\n", tcode, domain, arena->records[i].name);
        }

        // DSYNC (66, RFC 9859): validate RRtype mnemonic
        if (tcode == 66 && rcount >= 1) {
            if (get_type_code(rdata[0]) == 0) {
                kc_warning(t, "DSYNC record has unknown RRtype mnemonic '%s' for name '%s'\n",
                        rdata[0], arena->records[i].name);
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
            &arena->records[i], &comp_ctx,
            NULL,          // owner_name: NULL
            0xFFFFFFFF     // override_ttl: use record TTL
        );
        if (wire_result < 0) {
            kc_error(t,
                "Record '%s %s' at index %zu cannot be serialized to wire format "
                "(the server leaves this record out with a warning when it loads the zone). "
                "Check field count and value ranges for this record type.\n",
                arena->records[i].name, arena->records[i].type, i);
        }
    }

    if (!has_soa) {
        kc_error(t, "No SOA record found in zone '%s' (%s) at origin\n", domain, in->src);
        return;                                         /* the rest of the checks need the SOA */
    }
    /* [T3] SOA重複検出: apexに 2以上の SOAは失敗 */
    /* B8t-1: a tinydns zone (one Z line per location) and a zone with $LOCATION / $ECS-SUBNET tags may hold several SOA RRs when the
     * others are restricted; at most one is for everybody, and all have one serial */
    if (soa_plain_count > 1) {
        kc_error(t, "Zone '%s' (%s) has %d SOA records at the apex that every client sees; "
                "exactly one SOA record is required (more only with a location, time stamp or tag on the others)\n",
                domain, in->src, soa_plain_count);
    }
    (void)soa_count;
    {
        char soa_err[320];
        if (zone_arena_check_soa_set(arena, domain, soa_err, sizeof(soa_err)) < 0)
            kc_error(t, "%s (%s)\n", soa_err, in->src);
        /* a SOA that no client can see: a location the zone does not define, or a countdown time stamp that is over (tdlookup.c) */
        time_t soa_now = time(NULL);
        for (size_t i = 0; i < arena->count; i++) {
            const dns_record_t *sr = &arena->records[i];
            if (sr->type_code != 6 || !sr->name || strcasecmp(sr->name, domain) != 0 || !dns_record_is_restricted(sr)) continue;
            bool defined = true;
            if (sr->tinydns_loc[0] || sr->tinydns_loc[1]) {
                defined = false;
                for (int li = 0; li < arena->location_count; li++)
                    if (arena->locations[li].code[0] == sr->tinydns_loc[0] && arena->locations[li].code[1] == sr->tinydns_loc[1]) defined = true;
            }
            if (!defined)
                kc_warning(t, "The SOA record of zone '%s' (%s) is restricted to location '%.2s', which the zone does not define: no client sees it\n",
                        domain, in->src, sr->tinydns_loc);
            else if (sr->tinydns_ttd != 0 && sr->tinydns_ttl_countdown && sr->tinydns_ttd < soa_now)
                kc_warning(t, "The SOA record of zone '%s' (%s) has expired (countdown time stamp in the past): no client sees it\n",
                        domain, in->src);
        }
    }

    if (!has_apex_ns) {
        kc_error(t, "No NS record found at zone apex '%s' (%s); this zone cannot be properly delegated\n", domain, in->src);
    }

    if (in->is_catalog) {
        char version_txt[256];
        snprintf(version_txt, sizeof(version_txt), "version.%s", domain);
        bool found_version = false;
        for (size_t i = 0; i < arena->count; i++) {
            if (arena->records[i].type_code == 16 && strcasecmp(arena->records[i].name, version_txt) == 0) {
                if (arena->records[i].rdata_count > 0 && strcmp(arena->records[i].rdata[0], "2") == 0) {
                    found_version = true;
                    break;
                }
            }
        }
        if (!found_version) {
            kc_error(t, "Catalog zone '%s' is missing '%s TXT \"2\"'\n", domain, version_txt);
        }

        // Check for orphaned group TXT records
        char group_prefix[10] = "group.";
        char zones_suffix[256];
        snprintf(zones_suffix, sizeof(zones_suffix), ".zones.%s", domain);
        size_t zones_suffix_len = strlen(zones_suffix);
        for (size_t i = 0; i < arena->count; i++) {
            if (arena->records[i].type_code == 16) { // TXT
                size_t name_len = strlen(arena->records[i].name);
                if (name_len > 6 && strncasecmp(arena->records[i].name, group_prefix, 6) == 0) {
                    if (name_len > zones_suffix_len && strcasecmp(arena->records[i].name + name_len - zones_suffix_len, zones_suffix) == 0) {
                        // This is a group.<unique-N>.zones.$CATZ record. Check if PTR exists for <unique-N>.zones.$CATZ
                        size_t ptr_name_len = name_len - 6;
                        char ptr_name[512];
                        if (ptr_name_len >= sizeof(ptr_name)) {
                            kc_error(t,
                                    "Catalog zone '%s': owner name '%s' is too long to process (unique-id part exceeds %zu bytes); skipping orphan check for this record\n",
                                    domain, arena->records[i].name, sizeof(ptr_name) - 1);
                            continue; // このTXTレコードについてはスキップし、境界外書き込みを回避
                        }
                        strncpy(ptr_name, arena->records[i].name + 6, ptr_name_len);
                        ptr_name[ptr_name_len] = '\0';
                        
                        bool has_ptr = false;
                        for (size_t j = 0; j < arena->count; j++) {
                            if (arena->records[j].type_code == 12 && strcasecmp(arena->records[j].name, ptr_name) == 0) {
                                has_ptr = true;
                                break;
                            }
                        }
                        if (!has_ptr) {
                            kc_warning(t, "Orphaned group TXT record '%s' (no corresponding PTR record '%s')\n", arena->records[i].name, ptr_name);
                        }
                    }
                }
            }
        }
    }

    lint_glue_consistency(in, domain, arena, t);
    lint_cname_coexistence(domain, arena, t);
    lint_delegation_occlusion(domain, arena, t);
    lint_cname_targets(in, domain, arena, t);
    lint_wildcard(in, arena, t);
    lint_dup_records(in, arena, t);
    lint_mx_address(in, arena, t);
    lint_check_names(in, arena, t);
    lint_nsec3(domain, arena, t);
    /* K-02: 他のエラーがあっても ZONEMD は検証する (結果は件数に入る) */
    verify_zonemd(domain, arena, t);
}
