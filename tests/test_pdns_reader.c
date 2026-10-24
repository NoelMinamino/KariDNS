/*
 * test_pdns_reader.c - PowerDNS 5.1 reader core (dns_pdns_reader.c) and the test importer (tests/db/zone2sql.c).
 *
 *  1. every zone file under tests/zones/ that the zone parser loads: file -> zone2sql rows (in memory) -> reader ->
 *     arena.  Comparison rule: the RRs are compared one by one, in order, in a canonical form (owner in lowercase
 *     because PowerDNS lowercases owners, type, class, TTL, RDATA in canonical wire form of
 *     dns_record_canonical_rdata()).  Then KDB1 encoding -> B1 framer / decoder / state machine ->
 *     parse_xfr_packet() -> the same RRs as a multiset (the AXFR order puts the SOA first).
 *  2. a corpus of PowerDNS-format rows per RR type with the expected RDATA wire (by hand, RFC 1035 3.3 / 3.4.1 /
 *     3.3.9 / RFC 2782 / RFC 8659 / RFC 3597) or, for the long types, the RDATA the zone file parser makes of the
 *     same record written in presentation format.
 *  3. one test per rejection rule, each also checking that the error names the zone and records.id.
 *  4. domainmetadata -> settings text, and the text parsed by the configuration parser.
 *  5. KDB1 encoding details (message size, SOA first and last, digest, determinism, refusals).
 *
 * `test_pdns_reader --gen-corpus DIR` writes the seed corpora of fuzz_pdns_content and fuzz_pdns_metadata.
 * Usage: test_pdns_reader [zones-dir]   (default tests/zones)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>
#include <syslog.h>
#include <sys/stat.h>

#include "../dns_pdns_reader.h"
#include "../dns_config_parser.h"
#include "../dns_utils.h"
#include "db/zone2sql.h"
#include "db/xfr_mocks.h"
#include "db/pdns_roundtrip.h"
#include "db/pdns_confcheck.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define CHECK_STR(actual, expected) do { g_checks++; const char *a_ = (actual); const char *e_ = (expected); \
    if (!a_ || strcmp(a_, e_) != 0) { g_failed++; printf("  [FAIL] %s:%d: %s == \"%s\" (got \"%s\")\n", \
        __FILE__, __LINE__, #actual, e_, a_ ? a_ : "(null)"); } } while (0)
#define CHECK_HAS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || !strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%s\" lacks \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)

static const char *g_zones_dir = "tests/zones";

/* ------------------------------------------------------------------ row helpers */
static db_record_row_t R(int64_t id, const char *name, const char *type, const char *content, int64_t ttl, int64_t prio) {
    db_record_row_t r;
    memset(&r, 0, sizeof(r));
    r.id = id; r.name = name; r.type = type; r.content = content; r.ttl = ttl; r.prio = prio;
    return r;
}
static db_record_row_t SOA(void) {
    return R(1, "z.test", "SOA", "ns1.z.test hostmaster.z.test 2024010101 7200 3600 1209600 300", 3600, 0);
}
static db_meta_row_t M(const char *kind, const char *content) {
    db_meta_row_t m;
    m.domain_id = 1; m.kind = kind; m.content = content;
    return m;
}

/* zone "z.test" with the SOA row and the given rows; returns the zone (already finished or failed) */
static pdns_zone_t *build(const db_record_row_t *rows, size_t n, const db_meta_row_t *meta, size_t nm, const pdns_opts_t *o) {
    pdns_zone_t *z = pdns_zone_new("z.test", o);
    if (!z) return NULL;
    db_record_row_t soa = SOA();
    pdns_zone_add_record(z, &soa);
    for (size_t i = 0; i < n; i++) pdns_zone_add_record(z, &rows[i]);
    for (size_t i = 0; i < nm; i++) pdns_zone_add_meta(z, &meta[i]);
    pdns_zone_finish(z);
    return z;
}

static void hex_of(const uint8_t *b, long n, char *out) {
    for (long i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[n < 0 ? 0 : 2 * n] = '\0';
}

/* RDATA hex of record idx of a finished zone */
static void rdata_hex(const pdns_zone_t *z, size_t idx, char *out, size_t cap) {
    static uint8_t buf[65535];
    out[0] = '\0';
    if (idx >= z->arena.count) return;
    long n = dns_record_canonical_rdata(&z->arena.records[idx], buf, sizeof(buf));
    if (n < 0 || (size_t)n * 2 + 1 > cap) { snprintf(out, cap, "ERR"); return; }
    hex_of(buf, n, out);
}

/* RDATA hex the zone file parser makes of "x.z.test. 300 IN <type> <text>" (names absolute in text) */
static bool file_rdata_hex(const char *type, const char *text, char *out, size_t cap) {
    char line[4096];
    snprintf(line, sizeof(line), "$ORIGIN .\nx.z.test. 300 IN %s %s\n", type, text);
    zone_arena_t a;
    zone_arena_init(&a);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = ".";
    int rc = parse_zone_fast(line, strlen(line), &a, &ctx);
    bool ok = rc == 1;
    if (ok) {
        static uint8_t buf[65535];
        long n = dns_record_canonical_rdata(&a.records[0], buf, sizeof(buf));
        ok = n >= 0 && (size_t)n * 2 + 1 <= cap;
        if (ok) hex_of(buf, n, out);
    }
    zone_arena_destroy(&a);
    return ok;
}

/* ------------------------------------------------------------------ 1. zone files */
static int cmp_names(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void test_zone_files(void) {
    printf("zone files (%s)\n", g_zones_dir);
    DIR *d = opendir(g_zones_dir);
    if (!d) {
        printf("  [FAIL] cannot open %s\n", g_zones_dir);
        g_failed++;
        return;
    }
    char *names[256];
    size_t nn = 0;
    struct dirent *e;
    while ((e = readdir(d)) && nn < 256) {
        size_t l = strlen(e->d_name);
        if (l > 5 && strcmp(e->d_name + l - 5, ".zone") == 0) names[nn++] = strdup(e->d_name);
        else if (e->d_name[0] != '.') printf("  [SKIP] %s: not a .zone file (include fragment, dnskey or hosts data)\n", e->d_name);
    }
    closedir(d);
    qsort(names, nn, sizeof(char *), cmp_names);

    size_t tested = 0, skipped = 0;
    for (size_t k = 0; k < nn; k++) {
        char path[1024], apex[DNS_NAME_TEXT_SIZE], err[500];
        snprintf(path, sizeof(path), "%s/%s", g_zones_dir, names[k]);
        zone_arena_t fa;
        if (!z2s_load_zone_file(path, NULL, &fa, apex, sizeof(apex), err, sizeof(err))) {
            printf("  [SKIP] %s: the zone parser rejects it (%s)\n", names[k], err);
            skipped++;
            free(names[k]);
            continue;
        }
        bool non_in = false;
        for (size_t i = 0; i < fa.count; i++)
            if (fa.records[i].class_val > 1) non_in = true;
        if (fa.is_tinydns_format || non_in) {
            printf("  [SKIP] %s: %s\n", names[k], fa.is_tinydns_format ? "tinydns data" : "non-IN class records");
            zone_arena_destroy(&fa);
            skipped++;
            free(names[k]);
            continue;
        }
        z2s_rows_t rows;
        if (!z2s_rows_from_arena(&fa, apex, &rows, err, sizeof(err))) {
            printf("  [SKIP] %s: zone2sql cannot represent it (%s)\n", names[k], err);
            zone_arena_destroy(&fa);
            skipped++;
            free(names[k]);
            continue;
        }
        tested++;
        pdns_zone_t *z = pdns_zone_new(rows.zone, NULL);
        CHECK(z != NULL);
        db_meta_row_t meta[2];
        size_t nmeta = 0;
        if (rows.presigned) meta[nmeta++] = M("PRESIGNED", "1");
        if (rows.nsec3param) meta[nmeta++] = M("NSEC3PARAM", rows.nsec3param);
        int rc = z ? 0 : -1;
        for (size_t i = 0; rc == 0 && i < rows.n; i++)
            if (pdns_zone_add_record(z, &rows.rows[i]) != 0) rc = -1;
        for (size_t i = 0; rc == 0 && i < nmeta; i++)
            if (pdns_zone_add_meta(z, &meta[i]) != 0) rc = -1;
        if (rc == 0 && z2s_feed_ext(&rows, z) != 0) rc = -1;           // B8: tags, tinydns attributes, tag definitions
        if (rc == 0) rc = pdns_zone_finish(z);
        CHECK_MSG(rc == 0, "%s: reader: %s", names[k], z ? z->error : "(null)");
        if (rc == 0) {
            CHECK_MSG(z->arena.count == fa.count, "%s: %zu RRs from rows, %zu in the file", names[k], z->arena.count, fa.count);
            /* The RRs must be the file's.  A presigned zone (NSEC3 / NSEC chain rebuilt, B5) has its synthesized RRs
             * at the end, so the two sides are compared as sorted sets of canonical lines. */
            size_t bad = 0, nw = 0, ng = 0;
            char **want = rt_sorted_lines(&fa, &nw), **got = rt_sorted_lines(&z->arena, &ng);
            CHECK(want && got && nw == ng);
            for (size_t i = 0; want && got && i < nw && i < ng; i++)
                if (strcmp(want[i], got[i]) != 0 && bad++ < 3)
                    printf("    %s RR differs:\n      file   %.200s\n      reader %.200s\n", names[k], want[i], got[i]);
            if (want) rt_free_lines(want, nw);
            if (got) rt_free_lines(got, ng);
            CHECK_MSG(bad == 0, "%s: %zu RRs differ", names[k], bad);
            // B8: the zone level tables of the file (tag definitions, as the database holds them) are the reader's
            {
                char *tf = rt_flat_tables(&fa), *tr = rt_flat_tables(&z->arena);
                CHECK_MSG(tf && tr && strcmp(tf, tr) == 0, "%s: tag definitions differ:\n%s--\n%s", names[k], tf ? tf : "?", tr ? tr : "?");
                free(tf);
                free(tr);
                if (z->has_ext) printf("  [info] %s: tags / definitions carried (%d location, %d ECS definitions)\n", names[k], z->arena.bind_location_tag_count, z->arena.bind_ecs_tag_count);
            }
            if (rows.presigned) {
                CHECK_MSG(z->presigned_mode == (rows.nsec3param ? PS_NSEC3 : PS_NSEC), "%s: presigned mode %d", names[k], (int)z->presigned_mode);
                CHECK(z->n_synth > 0);
                printf("  [info] %s: presigned layout, %zu NSEC3/NSEC RRs rebuilt\n", names[k], z->n_synth);
            }
            CHECK(z->n_warnings == 0);
            rt_info_t info;
            char why[400];
            bool ok = pdns_roundtrip(z, &info, why, sizeof(why));
            CHECK_MSG(ok, "%s: KDB1 round trip: %s", names[k], why);
            if (ok) {
                CHECK(info.rr_count == fa.count + 1 + (z->has_ext ? (info.rr_count - fa.count - 1) : 0));      /* B8: the extension RRs are counted */
                CHECK(info.max_body <= KDB_MAX_ZONE_DATA);
                printf("  [ OK ] %-34s %6zu RRs, %zu ZONE_DATA, zone %s\n", names[k], fa.count, info.n_zone_data, rows.zone);
            }
        }
        pdns_zone_free(z);
        z2s_rows_free(&rows);
        zone_arena_destroy(&fa);
        free(names[k]);
    }
    printf("  %zu zone files tested, %zu skipped\n", tested, skipped);
    CHECK(tested >= 15);
}

/* ------------------------------------------------------------------ 2. corpus */
typedef struct {
    const char *type, *content;
    int64_t prio;           /* the prio column */
    const char *hex;        /* expected RDATA (hand-made); NULL: derive from file_text */
    const char *file_text;  /* the same RDATA in zone file presentation (absolute names) */
} corpus_t;

static const corpus_t k_corpus[] = {
    { "A", "192.0.2.1", 0, "c0000201", NULL },
    { "AAAA", "2001:db8::1", 0, "20010db8000000000000000000000001", NULL },
    { "NS", "ns1.z.test", 0, "036e7331017a047465737400", NULL },
    { "CNAME", "www.z.test", 0, "03777777017a047465737400", NULL },
    { "PTR", "host.z.test", 0, "04686f7374017a047465737400", NULL },
    { "MX", "mail.z.test", 10, "000a046d61696c017a047465737400", NULL },               /* PowerDNS 5.1: prio column */
    { "MX", "10 mail.z.test", 0, "000a046d61696c017a047465737400", NULL },             /* prio in the content */
    { "MX", ".", 0, "000000", NULL },                                                  /* null MX "0 ." (RFC 7505) */
    { "SRV", "2 5060 sip.z.test", 1, "0001000213c403736970017a047465737400", NULL },   /* RFC 2782 */
    { "SRV", "1 2 5060 sip.z.test", 0, "0001000213c403736970017a047465737400", NULL },
    { "TXT", "\"hello world\"", 0, "0b68656c6c6f20776f726c64", NULL },
    { "TXT", "\"a;b\"", 0, "03613b62", NULL },                                         /* ';' inside quotes */
    { "TXT", "\"a\\\"b\"", 0, "03612262", NULL },                                      /* \" */
    { "TXT", "\"\\065bc\"", 0, "03416263", NULL },                                     /* \DDD */
    { "TXT", "\"ab\" \"cd\"", 0, "026162026364", NULL },
    { "TXT", "\"(x)\"", 0, "03287829", NULL },                                         /* parentheses inside quotes */
    { "TXT", "foo", 0, "03666f6f", NULL },
    { "CAA", "0 issue \"ca.test\"", 0, "0005697373756563612e74657374", NULL },         /* RFC 8659 */
    { "HINFO", "\"x86\" \"linux\"", 0, "03783836056c696e7578", NULL },
    { "SOA", "ns1.z.test hostmaster.z.test 1 7200 3600 1209600 300", 0,
      "036e7331017a0474657374000a686f73746d6173746572017a047465737400"
      "00000001" "00001c20" "00000e10" "00127500" "0000012c", NULL },
    { "TYPE65534", "\\# 3 010203", 0, "010203", NULL },                                /* RFC 3597 */
    { "type65534", "\\# 0", 0, "", NULL },
    { "NAPTR", "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.z.test", 0, NULL,
      "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.z.test." },
    { "SSHFP", "1 1 123456789abcdef67890123456789abcdef67890", 0, NULL, "1 1 123456789abcdef67890123456789abcdef67890" },
    { "TLSA", "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 0, NULL,
      "3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
    { "SVCB", "1 svc.z.test alpn=\"h2,h3\" port=8443", 0, NULL, "1 svc.z.test. alpn=\"h2,h3\" port=8443" },
    { "HTTPS", "1 . alpn=h2", 0, NULL, "1 . alpn=h2" },
    { "DS", "12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 0, NULL,
      "12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
    { "DNSKEY", "257 3 8 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o", 0, NULL,
      "257 3 8 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o" },
    { "RRSIG", "A 8 3 300 20300101000000 20200101000000 12345 z.test AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o", 0, NULL,
      "A 8 3 300 20300101000000 20200101000000 12345 z.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o" },
    { "NSEC", "next.z.test A RRSIG NSEC", 0, NULL, "next.z.test. A RRSIG NSEC" },
    { "NSEC3", "1 0 5 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG", 0, NULL, "1 0 5 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG" },
    { "NSEC3PARAM", "1 0 5 AABB", 0, NULL, "1 0 5 AABB" },
    { "LOC", "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m", 0, NULL, "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m" },
    { "DNAME", "target.z.test", 0, NULL, "target.z.test." },
    { "SPF", "\"v=spf1 -all\"", 0, NULL, "\"v=spf1 -all\"" },
    { "URI", "10 1 \"https://z.test/\"", 0, NULL, "10 1 \"https://z.test/\"" },
    { "CDS", "12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 0, NULL,
      "12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
    /* content exactly as PowerDNS 5.1.4 stores it (host check with pdnsutil load-zone): the text as typed in the zone
     * file with the names it keeps absolute, uppercase hex, uncompressed IPv6, blanks that were line breaks */
    { "AAAA", "2001:DB8:0:0:0:0:0:1", 0, "20010db8000000000000000000000001", NULL },
    { "TXT", "\"a\\\"b\\\\c\\065\"", 0, "066122625c6341", NULL },
    { "SSHFP", "1 1 123456789ABCDEF67890123456789ABCDEF67890", 0, NULL, "1 1 123456789ABCDEF67890123456789ABCDEF67890" },
    { "NAPTR", "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.z.test.", 0, NULL, "100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.z.test." },
    { "SVCB", "1 svc.z.test. alpn=\"h2,h3\" port=8443", 0, NULL, "1 svc.z.test. alpn=\"h2,h3\" port=8443" },
    { "RRSIG", "A 8 3 300 20300101000000 20200101000000 12345 z.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o", 0, NULL,
      "A 8 3 300 20300101000000 20200101000000 12345 z.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o" },
    { "NSEC", "next.z.test. A RRSIG NSEC", 0, NULL, "next.z.test. A RRSIG NSEC" },
    { "ZONEMD", "2018031900 1 1  62e6cf51b02e54b9 b5f967d547ce4313 6792901f9f88e637 493daaf401c92c27 9dd10f0edb1c56f8 080211f8480ee306", 0, NULL,
      "2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306" },
    { "ZONEMD", "2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306", 0, NULL,
      "2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306" },
    { "RP", "admin.z.test txt.z.test", 0, NULL, "admin.z.test. txt.z.test." },
    { "AFSDB", "1 afs.z.test", 0, NULL, "1 afs.z.test." },
    { "KX", "10 kx.z.test.", 0, NULL, "10 kx.z.test." },
    { "LP", "10 l.z.test.", 0, NULL, "10 l.z.test." },
    { "MINFO", "rm.z.test. em.z.test.", 0, NULL, "rm.z.test. em.z.test." },
    { "CSYNC", "66 3 A NS AAAA", 0, NULL, "66 3 A NS AAAA" },
    { "EUI48", "00-00-5e-00-53-2a", 0, NULL, "00-00-5e-00-53-2a" },
    { "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=", 0, NULL, "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=" },
    { "L32", "10 192.0.2.1", 0, NULL, "10 192.0.2.1" },
    { "L64", "10 2001:db8:1:2", 0, NULL, "10 2001:db8:1:2" },
    { "NID", "10 2001:db8:1:2", 0, NULL, "10 2001:db8:1:2" },
    { "OPENPGPKEY", "AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o", 0, NULL, "AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o" },
    { "CERT", "1 2 3 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o", 0, NULL, "1 2 3 AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o" },
    { "IPSECKEY", "10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==", 0, NULL,
      "10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==" },
    { "SMIMEA", "3 1 1 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 0, NULL,
      "3 1 1 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" },
    /* types PowerDNS 5.1.4 cannot hold (pdnsutil rejects them) that the KariDNS zone parser accepts */
    { "HIP", "2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs1.example.com.",
      0, NULL, "2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs1.example.com." },
    { "ISDN", "\"150862028003217\" \"004\"", 0, NULL, "\"150862028003217\" \"004\"" },
    { "PX", "10 map822.z.test. mapx400.z.test.", 0, NULL, "10 map822.z.test. mapx400.z.test." },
    { "RT", "10 rt.z.test.", 0, NULL, "10 rt.z.test." },
};

static void test_corpus(void) {
    printf("corpus: one row per RR type\n");
    for (size_t i = 0; i < sizeof(k_corpus) / sizeof(k_corpus[0]); i++) {
        const corpus_t *c = &k_corpus[i];
        db_record_row_t rows[1] = { R(2, "x.z.test", c->type, c->content, 300, c->prio) };
        bool is_soa = strcmp(c->type, "SOA") == 0;
        pdns_zone_t *z;
        if (is_soa) {                                  /* the zone own SOA row */
            rows[0] = R(1, "z.test", "SOA", c->content, 300, 0);
            z = pdns_zone_new("z.test", NULL);
            pdns_zone_add_record(z, &rows[0]);
            pdns_zone_finish(z);
        } else {
            z = build(rows, 1, NULL, 0, NULL);
        }
        CHECK_MSG(!z->failed, "%s '%s': %s", c->type, c->content, z->error);
        if (!z->failed) {
            char want[1024], got[2048];
            if (c->hex) snprintf(want, sizeof(want), "%s", c->hex);
            else CHECK_MSG(file_rdata_hex(c->type, c->file_text, want, sizeof(want)), "%s: file parse of '%s'", c->type, c->file_text);
            size_t idx = z->arena.count - 1;
            rdata_hex(z, idx, got, sizeof(got));
            CHECK_MSG(strcmp(got, want) == 0, "%s '%s': got %s want %s", c->type, c->content, got, want);
            CHECK(z->arena.records[idx].ttl_value == 300);
            CHECK(domain_names_match_ci(z->arena.records[idx].name, is_soa ? "z.test." : "x.z.test."));
            CHECK(z->arena.records[idx].class_val == 1);
            rt_info_t info;
            char why[300];
            CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s: round trip: %s", c->type, why);
        }
        pdns_zone_free(z);
    }
}

/* an owner that is the apex, an uppercase owner, a wildcard, an escaped owner */
static void test_owners(void) {
    printf("owners\n");
    db_record_row_t rows[] = {
        R(2, "z.test", "NS", "ns1.z.test", 300, 0),
        R(3, "WWW.Z.TEST", "A", "192.0.2.1", 300, 0),
        R(4, "*.z.test", "A", "192.0.2.2", 300, 0),
        R(5, "a\\032b.z.test", "A", "192.0.2.3", 300, 0),
        R(6, "x.z.test.", "A", "192.0.2.4", 300, 0),              /* a trailing dot is tolerated */
    };
    pdns_zone_t *z = build(rows, 5, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s", z->error);
    CHECK(z->arena.count == 6);
    CHECK_STR(z->arena.records[2].name, "WWW.Z.TEST.");            /* case is kept: the comparison is case-insensitive */
    CHECK_STR(z->arena.records[4].name, "a\\032b.z.test.");
    pdns_zone_free(z);

    /* escaped characters that the zone-file tokenizer gives a meaning (RFC 1035 5.1): the canonical owner holds them
     * unescaped, the line must escape them again (fuzz_pdns_content: "\;" made the line a comment, the row vanished) */
    db_record_row_t sp[] = {
        R(2, "a\\;b.z.test", "A", "192.0.2.5", 300, 0),
        R(3, "\\;x.z.test", "A", "192.0.2.6", 300, 0),
        R(4, "\\$x.z.test", "A", "192.0.2.7", 300, 0),
        R(5, "\\@.z.test", "A", "192.0.2.8", 300, 0),
        R(6, "p\\(q\\).z.test", "A", "192.0.2.9", 300, 0),
    };
    z = build(sp, 5, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s", z->error);
    CHECK(z->arena.count == 6);
    if (z->arena.count == 6) {
        CHECK_STR(z->arena.records[1].name, "a;b.z.test.");
        CHECK_STR(z->arena.records[2].name, ";x.z.test.");
        CHECK_STR(z->arena.records[3].name, "$x.z.test.");
        CHECK_STR(z->arena.records[4].name, "@.z.test.");
        CHECK_STR(z->arena.records[5].name, "p(q).z.test.");
    }
    pdns_zone_free(z);
}

/* ------------------------------------------------------------------ 3. rejections */
/* A zone with the SOA row and `row` (id 50) must fail with `needle` in the error, naming zone and row 50. */
static void reject(const char *label, db_record_row_t row, const char *needle) {
    row.id = 50;
    pdns_zone_t *z = build(&row, 1, NULL, 0, NULL);
    CHECK_MSG(z->failed, "%s: expected a failure", label);
    if (z->failed) {
        CHECK_MSG(strstr(z->error, "zone 'z.test.'") != NULL, "%s: error lacks the zone: %s", label, z->error);
        CHECK_MSG(strstr(z->error, "records.id 50") != NULL, "%s: error lacks the row id: %s", label, z->error);
        CHECK_MSG(strstr(z->error, needle) != NULL, "%s: error lacks '%s': %s", label, needle, z->error);
        CHECK(z->error_has_row && z->error_row_id == 50);
    }
    pdns_zone_free(z);
}

static void accept_row(const char *label, db_record_row_t row) {
    row.id = 50;
    pdns_zone_t *z = build(&row, 1, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s: %s", label, z->error);
    pdns_zone_free(z);
}

static void test_text_check(void) {
    printf("line safety (pdns_text_check)\n");
    static const struct { const char *s; size_t len; bool owner; bool safe; } t[] = {
        { "192.0.2.1", 9, false, true },
        { "\"a;b\"", 5, false, true },                     /* ';' inside quotes */
        { "a\\;b", 4, false, true },                       /* escaped ';' */
        { "\"(x)\"", 5, false, true },
        { "( 10 mail )", 11, false, true },                /* balanced group on one line */
        { "10\tmail.z.test", 14, false, true },            /* TAB is a blank */
        { "\"a\\\"b\"", 6, false, true },                  /* quote escaped inside quotes */
        { "a\\\\", 3, false, true },                       /* escaped backslash at the end: fine */
        { "a;b", 3, false, false },                        /* comment */
        { "a ; b", 5, false, false },
        { "a\nb", 3, false, false },
        { "a\rb", 3, false, false },
        { "a\0b", 3, false, false },                       /* NUL */
        { "a\vb", 3, false, false },                       /* other control characters */
        { "a\x7f", 2, false, false },
        { "$ORIGIN x.", 10, false, false },                /* directive */
        { "  $TTL 5", 8, false, false },
        { "\"abc", 4, false, false },                      /* unbalanced quote */
        { "abc\"", 4, false, false },
        { "\"abc\\\"", 6, false, false },                  /* the escaped quote does not close it */
        { "( 1 2", 5, false, false },                      /* group stays open: swallows the next row */
        { "1 2 )", 5, false, false },
        { ") (", 3, false, false },
        { "( ( 1 )", 7, false, false },                    /* nested */
        { "foo\\", 4, false, false },                      /* lone trailing backslash eats the newline */
        { "\"foo\\", 5, false, false },
        { "@", 1, false, false },                          /* origin shorthand */
        { "10 @", 4, false, false },
        { "\"@\"", 3, false, true },                       /* quoted: text */
        { "a@b", 3, false, true },
        /* owners */
        { "www.z.test", 10, true, true },
        { "a\\032b.z.test", 13, true, true },
        { "a b.z.test", 10, true, false },
        { "a\tb", 3, true, false },
        { "a\"b", 3, true, false },
        { "a(b", 3, true, false },
        { "a)b", 3, true, false },
        { "a;b", 3, true, false },
        { "$x.z.test", 9, true, false },
        { "x.z.test\\", 9, true, false },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        const char *why = pdns_text_check(t[i].s, t[i].len, t[i].owner);
        CHECK_MSG((why == NULL) == t[i].safe, "case %zu '%.20s' owner=%d: %s", i, t[i].s, t[i].owner, why ? why : "accepted");
    }
}

static void test_rejections(void) {
    printf("rejection rules\n");
    /* content */
    reject("newline", R(0, "x.z.test", "TXT", "\"a\"\nw.z.test. 300 IN A 192.0.2.9", 300, 0), "line break");
    reject("carriage return", R(0, "x.z.test", "TXT", "\"a\"\rb", 300, 0), "line break");
    reject("comment", R(0, "x.z.test", "A", "192.0.2.1 ; hide", 300, 0), "';'");
    reject("directive", R(0, "x.z.test", "TXT", "$INCLUDE /etc/passwd", 300, 0), "'$'");
    reject("leading blanks then directive", R(0, "x.z.test", "TXT", "  $ORIGIN evil.", 300, 0), "'$'");
    reject("unbalanced quote", R(0, "x.z.test", "TXT", "\"abc", 300, 0), "unbalanced double quote");
    reject("open group", R(0, "x.z.test", "TXT", "\"a\" (", 300, 0), "unbalanced parenthesis");
    reject("close without open", R(0, "x.z.test", "TXT", "\"a\" )", 300, 0), "without '('");
    reject("nested group", R(0, "x.z.test", "TXT", "( ( \"a\" ) )", 300, 0), "nested");
    reject("trailing backslash", R(0, "x.z.test", "TXT", "\"a\" b\\", 300, 0), "backslash");
    reject("bare at", R(0, "x.z.test", "CNAME", "@", 300, 0), "'@'");
    reject("control char", R(0, "x.z.test", "TXT", "\"a\x01\"", 300, 0), "control");
    reject("empty content", R(0, "x.z.test", "A", "", 300, 0), "empty content");
    reject("blank content", R(0, "x.z.test", "A", "   ", 300, 0), "empty content");
    reject("NULL content", R(0, "x.z.test", "A", NULL, 300, 0), "empty content");
    {
        char *big = malloc(PDNS_MAX_CONTENT + 10);
        memset(big, 'a', PDNS_MAX_CONTENT + 9);
        big[PDNS_MAX_CONTENT + 9] = '\0';
        reject("content too long", R(0, "x.z.test", "TXT", big, 300, 0), "longer than");
        free(big);
    }
    /* owner */
    reject("owner space", R(0, "x y.z.test", "A", "192.0.2.1", 300, 0), "whitespace");
    reject("owner quote", R(0, "x\"y.z.test", "A", "192.0.2.1", 300, 0), "double quote");
    reject("owner semicolon", R(0, "x;y.z.test", "A", "192.0.2.1", 300, 0), "';'");
    reject("owner paren", R(0, "x(y.z.test", "A", "192.0.2.1", 300, 0), "'('");
    reject("owner newline", R(0, "x\n.z.test", "A", "192.0.2.1", 300, 0), "line break");
    reject("owner dollar", R(0, "$origin.z.test", "A", "192.0.2.1", 300, 0), "'$'");
    reject("owner empty", R(0, "", "A", "192.0.2.1", 300, 0), "empty owner");
    reject("owner NULL", R(0, NULL, "A", "192.0.2.1", 300, 0), "empty owner");
    reject("owner trailing backslash", R(0, "x.z.test\\", "A", "192.0.2.1", 300, 0), "backslash");
    reject("owner bad escape", R(0, "x\\300.z.test", "A", "192.0.2.1", 300, 0), "not a valid domain name");
    reject("owner empty label", R(0, "x..z.test", "A", "192.0.2.1", 300, 0), "not a valid domain name");
    {
        char lab[80];
        memset(lab, 'l', 64);
        strcpy(lab + 64, ".z.test");
        reject("owner label 64", R(0, lab, "A", "192.0.2.1", 300, 0), "not a valid domain name");
    }
    /* owner outside the zone (compared in C, label boundary, case-insensitive) */
    reject("outside: other zone", R(0, "x.other.test", "A", "192.0.2.1", 300, 0), "outside the zone");
    reject("outside: suffix without label boundary", R(0, "xz.test", "A", "192.0.2.1", 300, 0), "outside the zone");
    reject("outside: parent", R(0, "test", "A", "192.0.2.1", 300, 0), "outside the zone");
    reject("outside: escaped dot is not a boundary", R(0, "a\\.z.test", "A", "192.0.2.1", 300, 0), "outside the zone");
    {
        db_record_row_t ent = R(0, "x.other.test", NULL, NULL, 0, 0);
        reject("outside: ENT row", ent, "outside the zone");
    }
    accept_row("inside: uppercase", R(0, "X.Z.TEST", "A", "192.0.2.1", 300, 0));
    accept_row("inside: apex", R(0, "Z.test", "NS", "ns1.z.test", 300, 0));
    /* type token */
    reject("type empty", R(0, "x.z.test", "", "192.0.2.1", 300, 0), "type token");
    reject("type with a space", R(0, "x.z.test", "A B", "192.0.2.1", 300, 0), "type token");
    reject("type digit first", R(0, "x.z.test", "1A", "192.0.2.1", 300, 0), "type token");
    reject("type semicolon", R(0, "x.z.test", "A;", "192.0.2.1", 300, 0), "type token");
    reject("type newline", R(0, "x.z.test", "A\n", "192.0.2.1", 300, 0), "type token");
    reject("type too long", R(0, "x.z.test", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "192.0.2.1", 300, 0), "type token");
    reject("type unknown to the parser", R(0, "x.z.test", "FOOBAR", "192.0.2.1", 300, 0), "Unknown record type");
    reject("type meta (AXFR)", R(0, "x.z.test", "AXFR", "192.0.2.1", 300, 0), "Meta-type");
    reject("type OPT", R(0, "x.z.test", "OPT", "0", 300, 0), "Meta-type");
    /* ttl */
    reject("ttl negative", R(0, "x.z.test", "A", "192.0.2.1", -1, 0), "ttl -1");
    reject("ttl 2^31", R(0, "x.z.test", "A", "192.0.2.1", 2147483648LL, 0), "ttl 2147483648");
    reject("ttl huge", R(0, "x.z.test", "A", "192.0.2.1", 9000000000000LL, 0), "outside 0..");
    accept_row("ttl 0", R(0, "x.z.test", "A", "192.0.2.1", 0, 0));
    accept_row("ttl 2^31-1", R(0, "x.z.test", "A", "192.0.2.1", 2147483647, 0));
    /* prio */
    reject("MX two fields and prio", R(0, "x.z.test", "MX", "10 mail.z.test", 300, 5), "ambiguous");
    reject("SRV four fields and prio", R(0, "x.z.test", "SRV", "1 2 5060 sip.z.test", 300, 1), "ambiguous");
    reject("MX prio too large", R(0, "x.z.test", "MX", "mail.z.test", 300, 70000), "prio 70000");
    reject("MX prio negative", R(0, "x.z.test", "MX", "mail.z.test", 300, -1), "prio -1");
    reject("SRV prio too large", R(0, "x.z.test", "SRV", "2 5060 sip.z.test", 300, 65536), "prio 65536");
    accept_row("MX two fields and prio 0", R(0, "x.z.test", "MX", "10 mail.z.test", 300, 0));
    accept_row("MX one field and prio 65535", R(0, "x.z.test", "MX", "mail.z.test", 300, 65535));
    /* the parser's own errors, mapped back to the row */
    reject("bad A", R(0, "x.z.test", "A", "999.1.1.1", 300, 0), "IPv4");
    reject("bad AAAA", R(0, "x.z.test", "AAAA", "nonsense", 300, 0), "IPv6");
    reject("generic length mismatch", R(0, "x.z.test", "TYPE65534", "\\# 5 0102", 300, 0), "length");
    /* RFC 3597 5 (D15-2): the zone parser itself refuses generic RDATA that is not valid for a known type; the
     * reader's own wire check (wire_check_all) stays behind it as defence in depth */
    reject("generic empty PTR", R(0, "x.z.test", "PTR", "\\# 0", 300, 0), "RDATA");
    reject("generic NS with garbage", R(0, "x.z.test", "NS", "\\# 3 010203", 300, 0), "RDATA");
    reject("generic empty MX", R(0, "x.z.test", "MX", "\\# 1 00", 300, 0), "RDATA");
    accept_row("generic A is fine", R(0, "x.z.test", "A", "\\# 4 c0000201", 300, 0));
    accept_row("generic NS with a name", R(0, "x.z.test", "NS", "\\# 4 026e7300", 300, 0));
    reject("generic odd digits", R(0, "x.z.test", "TYPE65534", "\\# 1 012", 300, 0), "odd");
    reject("too many fields", R(0, "x.z.test", "TXT",
        "\"1\" \"2\" \"3\" \"4\" \"5\" \"6\" \"7\" \"8\" \"9\" \"10\" \"11\" \"12\" \"13\" \"14\" \"15\" \"16\" \"17\" \"18\" \"19\" \"20\" "
        "\"21\" \"22\" \"23\" \"24\" \"25\" \"26\" \"27\" \"28\" \"29\" \"30\" \"31\" \"32\" \"33\" \"34\" \"35\" \"36\" \"37\" \"38\" \"39\" "
        "\"40\" \"41\" \"42\" \"43\" \"44\" \"45\" \"46\" \"47\" \"48\" \"49\" \"50\"", 300, 0), "MAX_RDATA");
}

/* prio rules that are accepted */
static void test_prio_rules(void) {
    printf("prio rules\n");
    db_record_row_t rows[] = {
        R(2, "m.z.test", "MX", "mail.z.test", 300, 10),                 /* prepend */
        R(3, "m2.z.test", "MX", "20 mail.z.test", 300, 0),              /* as is */
        R(4, "s.z.test", "SRV", "2 5060 sip.z.test", 300, 1),           /* prepend */
        R(5, "a.z.test", "A", "192.0.2.1", 300, 7),                     /* ignored, warning */
        R(6, "a2.z.test", "A", "192.0.2.2", 300, 8),                    /* ignored, same warning */
        R(7, "n.z.test", "MX", "mail.z.test", 300, 0),
    };
    rows[5].prio_null = true;
    pdns_zone_t *z = build(rows, 6, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s", z->error);
    CHECK(z->arena.count == 7);
    CHECK(z->arena.records[1].cache.mx.pref == 10);
    CHECK(z->arena.records[2].cache.mx.pref == 20);
    CHECK(z->arena.records[3].cache.srv.priority == 1 && z->arena.records[3].cache.srv.weight == 2);
    CHECK(z->arena.records[6].cache.mx.pref == 0);
    CHECK(z->n_warnings == 1);                       /* aggregated */
    if (z->n_warnings) {
        CHECK_HAS(z->warnings[0], "records.id 5");
        CHECK_HAS(z->warnings[0], "2 record(s)");
    }
    pdns_zone_free(z);
}

static void test_ttl_rules(void) {
    printf("ttl rules\n");
    db_record_row_t rows[] = { R(2, "a.z.test", "A", "192.0.2.1", 0, 0), R(3, "b.z.test", "A", "192.0.2.2", 0, 0),
                               R(4, "c.z.test", "A", "192.0.2.3", 77, 0) };
    rows[0].ttl_null = rows[1].ttl_null = true;
    pdns_opts_t o = { 1800, 0, 0, 0 };
    pdns_zone_t *z = build(rows, 3, NULL, 0, &o);
    CHECK_MSG(!z->failed, "%s", z->error);
    CHECK(z->arena.records[1].ttl_value == 1800 && z->arena.records[2].ttl_value == 1800 && z->arena.records[3].ttl_value == 77);
    CHECK(z->n_warnings == 1);                        /* once per zone, not per row */
    if (z->n_warnings) CHECK_HAS(z->warnings[0], "2 record(s) have a NULL ttl");
    pdns_zone_free(z);
    z = build(rows, 3, NULL, 0, NULL);                /* default-ttl 3600 */
    CHECK(z->arena.records[1].ttl_value == 3600);
    pdns_zone_free(z);
}

/* B9a: ALIAS and LUA rows are read (TYPE65401 / TYPE65402, PowerDNS's own transfer form); their zone rules are checked */
static void test_b9a_alias_lua(void) {
    printf("ALIAS and LUA rows (B9a)\n");
    {
        db_record_row_t rows[] = {
            R(10, "a.z.test", "ALIAS", "target.example.net.", 120, 0),
            R(11, "l.z.test", "LUA", "A \";return {'192.0.2.1'}\"", 120, 0),
            R(12, "l.z.test", "TXT", "\"x\"", 120, 0),
            R(13, "rel.z.test", "ALIAS", "Rel", 120, 0),                     /* a name without a trailing dot is relative to the root in PowerDNS content: here too */
        };
        pdns_zone_t *z = build(rows, 4, NULL, 0, NULL);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK(z->arena.count == 5);
        if (z->arena.count == 5) {
            char hex[256];
            CHECK(z->arena.records[1].type_code == 65401 && z->arena.records[1].class_val == 1);
            rdata_hex(z, 1, hex, sizeof(hex));
            CHECK_STR(hex, "06746172676574076578616d706c65036e657400");
            CHECK(z->arena.records[2].type_code == 65402);
            rdata_hex(z, 2, hex, sizeof(hex));
            CHECK_STR(hex, "0001153b72657475726e207b273139322e302e322e31277d");
            rdata_hex(z, 4, hex, sizeof(hex));
            CHECK_STR(hex, "0352656c00");
        }
        rt_info_t info;
        char why[300];
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);     /* KDB1 encoding -> Backend decoder -> the same RRs */
        pdns_zone_free(z);
    }
    {   /* the zone rules */
        db_record_row_t both[] = { R(10, "a.z.test", "ALIAS", "t.example.net.", 120, 0), R(11, "A.z.test", "AAAA", "2001:db8::1", 120, 0) };
        pdns_zone_t *z = build(both, 2, NULL, 0, NULL);
        CHECK(z->failed);
        CHECK_HAS(z->error, "an A or AAAA record");
        pdns_zone_free(z);
        db_record_row_t sig[] = { R(10, "a.z.test", "ALIAS", "t.example.net.", 120, 0),
                                  R(11, "z.test", "DNSKEY", "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==", 120, 0) };
        z = build(sig, 2, NULL, 0, NULL);
        CHECK(z->failed);
        CHECK_HAS(z->error, "DNSSEC");
        pdns_zone_free(z);
        db_meta_row_t pre[] = { M("PRESIGNED", "1") };
        db_record_row_t one[] = { R(10, "a.z.test", "ALIAS", "t.example.net.", 120, 0) };
        z = build(one, 1, pre, 1, NULL);                                   /* a presigned zone carries NSEC3PARAM / signatures, or fails for another reason: never loads with an ALIAS */
        CHECK(z->failed);
        pdns_zone_free(z);
        db_record_row_t txt[] = { R(10, "a.z.test", "ALIAS", "t.example.net.", 120, 0), R(11, "a.z.test", "TXT", "\"x\"", 120, 0) };
        z = build(txt, 2, NULL, 0, NULL);
        CHECK_MSG(!z->failed, "%s", z->error);
        pdns_zone_free(z);
        db_record_row_t badalias[] = { R(10, "a.z.test", "ALIAS", "two names.example.", 120, 0) };
        z = build(badalias, 1, NULL, 0, NULL);
        CHECK(z->failed);
        pdns_zone_free(z);
    }
    {   /* ENABLE-LUA-RECORDS=1: LUA is not run here, so the zone is refused; 0 or no row is fine */
        db_meta_row_t on[] = { M("ENABLE-LUA-RECORDS", "1") };
        pdns_zone_t *z = build(NULL, 0, on, 1, NULL);
        CHECK(z->failed);
        CHECK_HAS(z->error, "ENABLE-LUA-RECORDS");
        pdns_zone_free(z);
        db_meta_row_t off[] = { M("ENABLE-LUA-RECORDS", "0") };
        z = build(NULL, 0, off, 1, NULL);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK(z->n_warnings == 0);
        pdns_zone_free(z);
    }
}

static void test_disabled_and_ent(void) {
    printf("disabled rows and empty non-terminals\n");
    db_record_row_t rows[] = {
        R(2, "bad name", "TXT", "\"unterminated", 300, 0),       /* disabled: nothing about it is checked */
        R(3, "a.b.z.test", "A", "192.0.2.1", 300, 0),
        R(4, "b.z.test", NULL, NULL, 0, 0),                      /* ENT */
        R(5, "ent2.z.test", NULL, "", 0, 0),
        R(6, "off.z.test", NULL, NULL, 0, 0),                    /* disabled ENT */
        R(7, "x.z.test", "ALIAS", "t.z.test", 300, 0),           /* disabled ALIAS: skipped */
    };
    rows[0].disabled = true;
    rows[2].ordername = "ABCDEF";
    rows[4].disabled = true;
    rows[5].disabled = true;
    pdns_zone_t *z = build(rows, 6, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s", z->error);
    CHECK(z->arena.count == 2);                                   /* SOA + A */
    CHECK(z->n_ents == 2);
    if (z->n_ents == 2) {
        CHECK_STR(z->ents[0].name, "b.z.test.");
        CHECK_STR(z->ents[0].ordername, "ABCDEF");
        CHECK(z->ents[0].row_id == 4);
        CHECK_STR(z->ents[1].name, "ent2.z.test.");
        CHECK(z->ents[1].ordername == NULL);
    }
    pdns_zone_free(z);
}

static void test_zone_level(void) {
    printf("zone level rules\n");
    pdns_zone_t *z;
    /* no SOA */
    z = pdns_zone_new("z.test", NULL);
    db_record_row_t ns = R(2, "z.test", "NS", "ns1.z.test", 300, 0);
    pdns_zone_add_record(z, &ns);
    CHECK(pdns_zone_finish(z) != 0);
    CHECK_HAS(z->error, "no enabled SOA");
    CHECK_HAS(z->error, "zone 'z.test.'");
    CHECK(!z->error_has_row);
    pdns_zone_free(z);
    /* disabled SOA = no SOA */
    z = pdns_zone_new("z.test", NULL);
    db_record_row_t soa = SOA();
    soa.disabled = true;
    pdns_zone_add_record(z, &soa);
    CHECK(pdns_zone_finish(z) != 0);
    pdns_zone_free(z);
    /* B8t-1: several SOAs (a tinydns zone has one per location) must have one serial (RFC 2181 s6.1) */
    db_record_row_t two[] = { R(9, "z.test", "SOA", "ns1.z.test hostmaster.z.test 2 7200 3600 1209600 300", 3600, 0) };
    z = build(two, 1, NULL, 0, NULL);
    CHECK(z->failed);
    CHECK_HAS(z->error, "records.id 1");
    CHECK_HAS(z->error, "different serials");
    pdns_zone_free(z);
    /* ... with one serial the reader accepts them: the reference SOA (not restricted, else the first row) gives the serial.
     * B8t-2: the KDB1 stream is the version 3 encoding: frame SOA, SOA_SET, both SOAs as wrapped body RRs, frame SOA */
    db_record_row_t two_ok[] = { R(9, "z.test", "SOA", "ns2.z.test hostmaster.z.test 2024010101 7200 3600 1209600 300", 3600, 0) };
    z = build(two_ok, 1, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s", z->error);
    CHECK(z->n_soa == 2 && z->serial == 2024010101u && z->arena.records[z->soa_index].type_code == 6);
    {
        rt_info_t info;
        char why[300];
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
        CHECK(info.flags == KDB_ZF_EXTENDED);
    }
    pdns_zone_free(z);
    /* SOA not at the apex */
    reject("SOA below the apex", R(0, "sub.z.test", "SOA", "ns1.z.test hostmaster.z.test 2 7200 3600 1209600 300", 3600, 0), "not at the zone apex");
    /* SOA serials */
    static const struct { const char *content; bool ok; } ser[] = {
        { "ns1.z.test h.z.test 0 7200 3600 1209600 300", true },
        { "ns1.z.test h.z.test 4294967295 7200 3600 1209600 300", true },
        { "ns1.z.test h.z.test 4294967296 7200 3600 1209600 300", false },
        { "ns1.z.test h.z.test -1 7200 3600 1209600 300", false },
        { "ns1.z.test h.z.test +1 7200 3600 1209600 300", false },
        { "ns1.z.test h.z.test 1a 7200 3600 1209600 300", false },
        { "ns1.z.test h.z.test 0x10 7200 3600 1209600 300", false },
        { "ns1.z.test h.z.test", false },
    };
    for (size_t i = 0; i < sizeof(ser) / sizeof(ser[0]); i++) {
        uint32_t s = 77;
        bool r = pdns_soa_serial(ser[i].content, &s);
        CHECK_MSG(r == ser[i].ok, "serial case %zu", i);
    }
    {
        uint32_t s = 0;
        CHECK(pdns_soa_serial("  ns1.z.test\th.z.test   42  1 2 3 4 ", &s) && s == 42);
        CHECK(pdns_soa_serial("a b 4294967295", &s) && s == 4294967295u);
        CHECK(!pdns_soa_serial(NULL, &s) && !pdns_soa_serial("", &s));
    }
    {   /* the zone's only SOA has a serial the DB column could not hold in a 32-bit field */
        z = pdns_zone_new("z.test", NULL);
        db_record_row_t bad = R(50, "z.test", "SOA", "ns1.z.test hostmaster.z.test 4294967296 1 2 3 4", 3600, 0);
        CHECK(pdns_zone_add_record(z, &bad) != 0);
        CHECK_HAS(z->error, "records.id 50");
        CHECK_HAS(z->error, "serial");
        pdns_zone_free(z);
    }
    /* serial from the SOA row */
    {
        db_record_row_t rows[1] = { R(2, "z.test", "NS", "ns1.z.test", 300, 0) };
        z = build(rows, 1, NULL, 0, NULL);
        CHECK(!z->failed && z->serial == 2024010101u);
        pdns_zone_free(z);
    }
    /* limits */
    {
        pdns_opts_t o = { 0, 4, 0, 0 };            /* SOA + 3 rows + the closing SOA = 5 RRs > 4 */
        db_record_row_t rows[] = { R(2, "a.z.test", "A", "192.0.2.1", 300, 0), R(3, "b.z.test", "A", "192.0.2.2", 300, 0),
                                   R(4, "c.z.test", "A", "192.0.2.3", 300, 0) };
        z = build(rows, 3, NULL, 0, &o);
        CHECK(z->failed);
        CHECK_HAS(z->error, "records.id 4");
        CHECK_HAS(z->error, "max-zone-records");
        pdns_zone_free(z);
        pdns_opts_t o2 = { 0, 0, 200, 0 };
        z = build(rows, 3, NULL, 0, &o2);
        CHECK(z->failed);
        CHECK_HAS(z->error, "size limit");
        pdns_zone_free(z);
    }
    /* a record under a DNAME (RFC 6672): zone check, no single row */
    {
        db_record_row_t rows[] = { R(2, "d.z.test", "DNAME", "other.test", 300, 0), R(3, "www.d.z.test", "A", "192.0.2.1", 300, 0) };
        z = build(rows, 2, NULL, 0, NULL);
        CHECK(z->failed);
        CHECK_HAS(z->error, "DNAME");
        pdns_zone_free(z);
    }
    /* unusable zone names: a failed zone object, one error path */
    static const char *const bad[] = { "", ".", "a b", "a..b", "a\\", NULL };
    for (size_t i = 0; bad[i]; i++) {
        z = pdns_zone_new(bad[i], NULL);
        CHECK_MSG(z && z->failed, "zone name '%s'", bad[i]);
        if (z) {
            db_record_row_t soa2 = SOA();
            CHECK(pdns_zone_add_record(z, &soa2) != 0);
            CHECK(pdns_zone_finish(z) != 0);
        }
        pdns_zone_free(z);
    }
    z = pdns_zone_new("Z.Test.", NULL);               /* trailing dot and case are accepted */
    CHECK(z && !z->failed);
    CHECK_STR(z->name, "Z.Test.");
    pdns_zone_free(z);
    /* the first failing row wins and later rows do not change the message */
    {
        db_record_row_t rows[] = { R(5, "x.z.test", "A", "bad", 300, 0), R(6, "y.z.test", "A", "alsobad", 300, 0) };
        z = build(rows, 2, NULL, 0, NULL);
        CHECK(z->failed);
        CHECK(z->error_row_id == 5);
        pdns_zone_free(z);
    }
}

/* One failing row never lets text of another row change meaning: the number of lines of the generated zone text
 * is the number of rows, and an accepted tricky row leaves its neighbours intact. */
static void test_isolation(void) {
    printf("rows are isolated\n");
    db_record_row_t rows[] = {
        R(2, "a.z.test", "TXT", "\"x\" \\\\", 300, 0),           /* ends with an escaped backslash: fine */
        R(3, "b.z.test", "A", "192.0.2.1", 300, 0),
        R(4, "c.z.test", "TXT", "\"semi;colon\" \"par(en)\"", 300, 0),
        R(5, "d.z.test", "A", "192.0.2.2", 300, 0),
        R(6, "e.z.test", "TXT", "( \"grouped\" )", 300, 0),
        R(7, "f.z.test", "A", "192.0.2.3", 300, 0),
        R(8, "g.z.test", "TXT", "\"a\\\" b\" ", 300, 0),          /* escaped quote, trailing blank */
        R(9, "h.z.test", "A", "192.0.2.4", 300, 0),
    };
    pdns_zone_t *z = build(rows, 8, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s", z->error);
    if (!z->failed) {
        CHECK(z->arena.count == 9);
        CHECK(z->n_rows == 9);
        for (size_t i = 0; i < 8; i++) {
            const char *want = rows[i].name;
            CHECK_MSG(domain_names_match_ci(z->arena.records[i + 1].name, want), "row %zu is '%s'", i, z->arena.records[i + 1].name);
        }
    }
    pdns_zone_free(z);
}

/* ------------------------------------------------------------------ 4. metadata -> settings */
static void expect_settings(const char *label, const db_meta_row_t *meta, size_t nm, const char *want, size_t want_warnings) {
    pdns_zone_t *z = build(NULL, 0, meta, nm, NULL);
    CHECK_MSG(!z->failed, "%s: %s", label, z->error);
    if (!z->failed) {
        CHECK_MSG(strcmp(z->settings, want) == 0, "%s: settings '%s', want '%s'", label, z->settings, want);
        CHECK_MSG(z->n_warnings == want_warnings, "%s: %zu warnings (want %zu), first: %s", label, z->n_warnings, want_warnings,
                  z->n_warnings ? z->warnings[0] : "-");
    }
    pdns_zone_free(z);
}

static void test_metadata(void) {
    printf("domainmetadata -> settings text\n");
    expect_settings("no metadata", NULL, 0, "", 0);
    {
        db_meta_row_t m[] = { M("PRESIGNED", "1"), M("API-RECTIFY", "1"), M("SOA-EDIT-API", "DEFAULT"), M("SOA-EDIT-DNSUPDATE", "DEFAULT"), M("FOO", "x") };
        pdns_zone_t *z = build(NULL, 0, m, 5, NULL);
        CHECK(!z->failed && (z->flags & PDNS_F_PRESIGNED) && !(z->flags & PDNS_F_TINYDNS));
        CHECK_STR(z->settings, "");
        CHECK(z->n_warnings == 0);            /* API-RECTIFY, SOA-EDIT-API, SOA-EDIT-DNSUPDATE and FOO do not change answers */
        pdns_zone_free(z);
    }
    {
        db_meta_row_t m[] = { M("PRESIGNED", "0") };
        pdns_zone_t *z = build(NULL, 0, m, 1, NULL);
        CHECK(!z->failed && !(z->flags & PDNS_F_PRESIGNED));
        pdns_zone_free(z);
        db_meta_row_t m2[] = { M("PRESIGNED", "yes") };
        z = build(NULL, 0, m2, 1, NULL);
        CHECK(!z->failed && !(z->flags & PDNS_F_PRESIGNED) && z->n_warnings == 1);
        pdns_zone_free(z);
    }
    {
        db_meta_row_t m[] = { M("X-KARIDNS-FORMAT", "tinydns"), M("X-KARIDNS-PROFILE", "web-default"), M("NSEC3PARAM", "1 0 5 AABB") };
        pdns_zone_t *z = build(NULL, 0, m, 3, NULL);
        CHECK(!z->failed && (z->flags & PDNS_F_TINYDNS));
        CHECK_STR(z->profile, "web-default");
        CHECK_STR(z->nsec3param, "1 0 5 AABB");
        pdns_zone_free(z);
    }
    {   /* profile names are restricted: no way to smuggle syntax through the profile TLV */
        db_meta_row_t m[] = { M("X-KARIDNS-PROFILE", "bad name\"; x") };
        pdns_zone_t *z = build(NULL, 0, m, 1, NULL);
        CHECK(!z->failed && z->profile[0] == '\0' && z->n_warnings == 1);
        pdns_zone_free(z);
    }
    {
        db_meta_row_t m[] = { M("ALLOW-AXFR-FROM", "192.0.2.1"), M("ALLOW-AXFR-FROM", "2001:db8::/32"), M("ALLOW-AXFR-FROM", "192.0.2.1") };
        expect_settings("allow-transfer addresses", m, 3, "allow-transfer { 192.0.2.1; 2001:db8::/32; };", 0);
    }
    {
        db_meta_row_t m[] = { M("TSIG-ALLOW-AXFR", "xfr-key"), M("TSIG-ALLOW-AXFR", "k2.example") };
        expect_settings("allow-transfer keys", m, 2, "allow-transfer { key \"xfr-key\"; key \"k2.example\"; };", 0);
    }
    {
        db_meta_row_t m[] = { M("TSIG-ALLOW-AXFR", "xfr"), M("ALLOW-AXFR-FROM", "192.0.2.0/24") };
        /* D14 (B7a): PowerDNS accepts an address or a key; the text says so (karidns.conf alone would need both) */
        expect_settings("allow-transfer both", m, 2, "allow-transfer { 192.0.2.0/24; key \"xfr\"; }; transfer-acl-match any;", 0);
    }
    {   /* AUTO-NS and garbage cannot be expressed; the list must not become wider than the metadata: none */
        db_meta_row_t m[] = { M("ALLOW-AXFR-FROM", "AUTO-NS"), M("ALLOW-AXFR-FROM", "1.2.3.4; any") };
        expect_settings("allow-transfer unsupported", m, 2, "allow-transfer { none; };", 2);
    }
    {
        db_meta_row_t m[] = { M("ALSO-NOTIFY", "192.0.2.53"), M("ALSO-NOTIFY", "192.0.2.54:5300"), M("ALSO-NOTIFY", "2001:db8::53"),
                              M("ALSO-NOTIFY", "[2001:db8::54]:5301"), M("ALSO-NOTIFY", "bogus"), M("ALSO-NOTIFY", "192.0.2.1:99999") };
        expect_settings("also-notify", m, 6,
                        "also-notify { 192.0.2.53; 192.0.2.54 port 5300; 2001:db8::53; 2001:db8::54 port 5301; };", 2);
    }
    {
        db_meta_row_t m[] = { M("ALLOW-DNSUPDATE-FROM", "192.0.2.0/24") };
        expect_settings("allow-update addresses", m, 1, "allow-update { 192.0.2.0/24; };", 0);
        db_meta_row_t m2[] = { M("TSIG-ALLOW-DNSUPDATE", "upd") };
        expect_settings("allow-update keys", m2, 1, "allow-update { key \"upd\"; };", 0);
        /* PowerDNS requires address AND key (D14, B7a): update-acl-match all, no warning, not closed */
        db_meta_row_t m3[] = { M("TSIG-ALLOW-DNSUPDATE", "upd"), M("ALLOW-DNSUPDATE-FROM", "192.0.2.0/24") };
        expect_settings("allow-update both", m3, 2, "allow-update { 192.0.2.0/24; key \"upd\"; }; update-acl-match all;", 0);
    }
    {
        db_meta_row_t m[] = { M("AXFR-MASTER-TSIG", "master-key"), M("AXFR-MASTER-TSIG", "other") };
        expect_settings("tsig-key", m, 2, "tsig-key \"master-key\";", 1);
    }
    {
        db_meta_row_t m[] = { M("X-KARIDNS-IXFR-HISTORY", "8"), M("X-KARIDNS-NOTIFY-RETRIES", "3"), M("X-KARIDNS-ADDITIONAL-FROM-AUTH", "in-domain"),
                              M("X-KARIDNS-ZONE-UDP-BUFSIZE", "1232"), M("X-KARIDNS-NOTIFY-RETRY-BACKOFF", "exponential"),
                              M("X-KARIDNS-DISABLE-AUTO-TC-FLAG", "yes"), M("X-KARIDNS-ZONE-TCP-WINDOW", "64k") };
        expect_settings("options", m, 7,
                        "notify-retries 3; notify-retry-backoff exponential; ixfr-history 8; additional-from-auth in-domain; "
                        "disable-auto-tc-flag yes; zone-udp-bufsize 1232; zone-tcp-window 64k;", 0);
    }
    {   /* invalid option values and unknown options are dropped with a warning, never passed on */
        db_meta_row_t m[] = { M("X-KARIDNS-IXFR-HISTORY", "999"), M("X-KARIDNS-IXFR-HISTORY", "4"), M("X-KARIDNS-NOTIFY-RETRIES", "3; allow-update { any; }"),
                              M("X-KARIDNS-FILE", "/etc/passwd"), M("X-KARIDNS-ZONE-UDP-BUFSIZE", "511"), M("X-KARIDNS-ZONE-TCP-MSS", "65496"),
                              M("X-KARIDNS-ADDITIONAL-FROM-AUTH", "maybe") };
        expect_settings("bad options", m, 7, "", 7);
    }
    {   /* a key name cannot carry quotes or semicolons */
        db_meta_row_t m[] = { M("TSIG-ALLOW-AXFR", "k\"; allow-transfer { any; }; x \""), M("AXFR-MASTER-TSIG", "a b") };
        expect_settings("hostile key names", m, 2, "allow-transfer { none; };", 2);
    }
    {   /* three lists of 1000 addresses: the settings text would pass 65535 bytes (a KDB1 TLV length): the zone fails, the
         * text is never cut */
        enum { N = 1000 };
        static char addr[3][N][40];
        static db_meta_row_t m[3 * N];
        static const char *const kinds[3] = { "ALLOW-AXFR-FROM", "ALLOW-DNSUPDATE-FROM", "ALSO-NOTIFY" };
        for (int k = 0; k < 3; k++)
            for (int i = 0; i < N; i++) {
                snprintf(addr[k][i], sizeof(addr[k][i]), "2001:db8:1:2:3:4:%x:%x", k + 1, i + 1);
                m[k * N + i] = M(kinds[k], addr[k][i]);
            }
        pdns_zone_t *z = build(NULL, 0, m, 3 * N, NULL);
        CHECK(z->failed);
        CHECK_HAS(z->error, "longer than 65535");
        pdns_zone_free(z);
        pdns_zone_t *z2 = build(NULL, 0, m, N, NULL);          /* one list fits */
        CHECK(!z2->failed && strlen(z2->settings) > 20000 && strlen(z2->settings) <= PDNS_MAX_SETTINGS);
        pdns_zone_free(z2);
    }
    {   /* DB text echoed in a warning or an error carries no control character (log injection) */
        db_meta_row_t m[] = { M("X-KARIDNS-A\nINJECT\r\x1b[31m", "1") };
        pdns_zone_t *z = build(NULL, 0, m, 1, NULL);
        CHECK(!z->failed && z->n_warnings == 1);
        bool clean = true;
        for (size_t w = 0; w < z->n_warnings; w++)
            for (const char *p = z->warnings[w]; *p; p++)
                if ((unsigned char)*p < 0x20 || (unsigned char)*p >= 0x7F) clean = false;
        CHECK(clean);
        pdns_zone_free(z);
    }
    {   /* found by fuzz_pdns_metadata: allow-update keeps a key as a bare name, which the configuration parser reads as a
         * built-in ACL name or an address first.  Such key names are refused, so a key reference cannot change meaning. */
        db_meta_row_t m[] = { M("TSIG-ALLOW-DNSUPDATE", "any"), M("TSIG-ALLOW-DNSUPDATE", "aNy"), M("TSIG-ALLOW-DNSUPDATE", "None"),
                              M("TSIG-ALLOW-DNSUPDATE", "localnets."), M("TSIG-ALLOW-DNSUPDATE", "192.0.2.1"), M("TSIG-ALLOW-DNSUPDATE", "10.0.0.0"),
                              M("TSIG-ALLOW-AXFR", "localhost"), M("AXFR-MASTER-TSIG", "any") };
        expect_settings("key names that are ACL names", m, 8, "allow-transfer { none; }; allow-update { none; };", 8);
        db_meta_row_t ok[] = { M("TSIG-ALLOW-DNSUPDATE", "anyone"), M("TSIG-ALLOW-DNSUPDATE", "k1") };
        expect_settings("key names near ACL names", ok, 2, "allow-update { key \"anyone\"; key \"k1\"; };", 0);
        pdns_zone_t *z = build(NULL, 0, ok, 2, NULL);
        server_config_t cfg;
        CHECK(pdns_settings_parse(z->settings, &cfg));
        free_server_config_fields(&cfg);
        pdns_zone_free(z);
    }
    {
        db_meta_row_t m[] = { M("SOA-EDIT", "INCEPTION-INCREMENT"), M("SOA-EDIT", "EPOCH"), M("LUA-AXFR-SCRIPT", "x"), M("NSEC3NARROW", "1"),
                              M("PUBLISH-CDS", "2") };
        expect_settings("answer-changing kinds warn once per kind", m, 5, "", 4);
    }
    /* deterministic order whatever the row order */
    {
        db_meta_row_t a[] = { M("ALSO-NOTIFY", "192.0.2.53"), M("X-KARIDNS-IXFR-HISTORY", "2"), M("ALLOW-DNSUPDATE-FROM", "192.0.2.9"),
                              M("TSIG-ALLOW-AXFR", "k"), M("AXFR-MASTER-TSIG", "m") };
        expect_settings("order", a, 5,
                        "tsig-key \"m\"; allow-transfer { key \"k\"; }; also-notify { 192.0.2.53; }; allow-update { 192.0.2.9; }; ixfr-history 2;", 0);
    }
    /* the generated text parses with the configuration parser (wrapped as the design says) */
    {
        db_meta_row_t m[] = { M("ALLOW-AXFR-FROM", "192.0.2.1"), M("ALLOW-AXFR-FROM", "2001:db8::/32"), M("TSIG-ALLOW-AXFR", "xfr"),
                              M("ALSO-NOTIFY", "192.0.2.53"), M("ALSO-NOTIFY", "[2001:db8::54]:5301"), M("TSIG-ALLOW-DNSUPDATE", "upd"),
                              M("AXFR-MASTER-TSIG", "master-key"), M("X-KARIDNS-IXFR-HISTORY", "8"), M("X-KARIDNS-NOTIFY-RETRIES", "3"),
                              M("X-KARIDNS-NOTIFY-RETRY-INTERVAL", "30"), M("X-KARIDNS-NOTIFY-RETRY-BACKOFF", "exponential"),
                              M("X-KARIDNS-ADDITIONAL-FROM-AUTH", "in-zone"), M("X-KARIDNS-DISABLE-AUTO-TC-FLAG", "true"),
                              M("X-KARIDNS-ZONE-UDP-BUFSIZE", "1232"), M("X-KARIDNS-ZONE-TCP-MSS", "1400"), M("X-KARIDNS-ZONE-TCP-WINDOW", "1m"),
                              M("X-KARIDNS-ZONE-TCP-SNDBUF", "65536") };
        pdns_zone_t *z = build(NULL, 0, m, sizeof(m) / sizeof(m[0]), NULL);
        CHECK_MSG(!z->failed, "%s", z->error);
        server_config_t cfg;
        bool ok = pdns_settings_parse(z->settings, &cfg);
        CHECK_MSG(ok, "configuration parser rejects: %s", z->settings);
        if (ok) {
            const zone_config_t *zc = config_find_zone_any_view(&cfg, "z.test.");
            const zone_ext_t *x = zext(zc);
            CHECK(x->allow_transfer_count == 2 && x->tsig_keys_count == 1);
            CHECK(x->also_notify_count == 2 && x->also_notify[1].port == 5301);
            CHECK(x->allow_update_count == 1);
            CHECK(x->tsig_key && strcmp(x->tsig_key, "master-key") == 0);
            CHECK(x->ixfr_history_set && x->ixfr_history == 8);
            CHECK(x->notify_retry.retries_set && x->notify_retry.retries == 3 && x->notify_retry.interval == 30);
            CHECK(x->disable_auto_tc_flag && x->additional_from_auth_specified);
            CHECK(x->zone_udp_bufsize == 1232 && x->zone_tcp_mss == 1400 && x->zone_tcp_window == 1024 * 1024 &&
                  x->zone_tcp_sndbuf == 65536);
        }
        free_server_config_fields(&cfg);
        pdns_zone_free(z);
    }
    {   /* every accepted and every dropped form together: the text always parses */
        db_meta_row_t m[] = { M("ALLOW-AXFR-FROM", "AUTO-NS"), M("ALLOW-DNSUPDATE-FROM", "10.0.0.0/8"), M("TSIG-ALLOW-DNSUPDATE", "u"),
                              M("ALSO-NOTIFY", "x"), M("X-KARIDNS-IXFR-HISTORY", "-1") };
        pdns_zone_t *z = build(NULL, 0, m, 5, NULL);
        server_config_t cfg;
        CHECK(!z->failed && pdns_settings_parse(z->settings, &cfg));
        free_server_config_fields(&cfg);
        pdns_zone_free(z);
    }
}

/* ------------------------------------------------------------------ 5. KDB1 encoding */
static int stop_emit(void *ud, const uint8_t *m, size_t n) { (void)ud; (void)m; (void)n; return -1; }

typedef struct { int calls; uint32_t serial; uint8_t digest[KDB_DIGEST_LEN]; int answer; } gate_seen_t;
static int test_gate(void *ud, uint32_t serial, const uint8_t digest[KDB_DIGEST_LEN]) {
    gate_seen_t *g = ud;
    g->calls++;
    g->serial = serial;
    memcpy(g->digest, digest, KDB_DIGEST_LEN);
    return g->answer;
}

static void test_kdb(void) {
    printf("KDB1 encoding\n");
    /* many records: several ZONE_DATA messages, SOA first and last, every message <= 65535 */
    {
        size_t n = 2500;
        db_record_row_t *rows = calloc(n, sizeof(*rows));
        char (*names)[40] = calloc(n, 40);
        char (*txt)[100] = calloc(n, 100);
        for (size_t i = 0; i < n; i++) {
            snprintf(names[i], 40, "h%zu.z.test", i);
            snprintf(txt[i], 100, "\"%0*zu padding padding padding padding padding\"", 40, i);
            rows[i] = R((int64_t)i + 2, names[i], "TXT", txt[i], 300, 0);
        }
        pdns_zone_t *z = build(rows, n, NULL, 0, NULL);
        CHECK_MSG(!z->failed, "%s", z->error);
        rt_info_t info;
        char why[300];
        bool ok = pdns_roundtrip(z, &info, why, sizeof(why));
        CHECK_MSG(ok, "%s", why);
        CHECK(info.n_zone_data >= 3);
        CHECK(info.max_body <= 65535 && info.max_body > 60000);
        CHECK(info.rr_count == n + 2);                  /* SOA, n TXT, SOA */
        CHECK(info.serial == 2024010101u);
        CHECK(info.flags == 0);

        /* determinism: the same rows give the same bytes */
        rt_buf_t b1 = {0}, b2 = {0};
        pdns_kdb_params_t kp = { 1, 9, KDB_ZK_PRIMARY, "prof", NULL, NULL, NULL };
        char err[200];
        CHECK(pdns_zone_encode_kdb(z, &kp, rt_emit, &b1, err, sizeof(err)) == 0);
        pdns_zone_t *z2 = build(rows, n, NULL, 0, NULL);
        CHECK(pdns_zone_encode_kdb(z2, &kp, rt_emit, &b2, err, sizeof(err)) == 0);
        CHECK(b1.len == b2.len && b1.len > 0 && memcmp(b1.buf, b2.buf, b1.len) == 0);
        /* the first message is ZONE_BEGIN, the last ZONE_END */
        CHECK(memcmp(b1.buf, "KDB1", 4) == 0 && b1.buf[5] == KDB_T_ZONE_BEGIN);
        CHECK(memcmp(b1.buf + b1.len - 24, "KDB1", 4) == 0 && b1.buf[b1.len - 24 + 5] == KDB_T_ZONE_END);
        /* changing one row changes the digest */
        rows[17].content = "\"changed\"";
        pdns_zone_t *z3 = build(rows, n, NULL, 0, NULL);
        rt_info_t i3;
        CHECK(pdns_roundtrip(z3, &i3, why, sizeof(why)));
        CHECK(memcmp(i3.digest, info.digest, KDB_DIGEST_LEN) != 0);
        /* the sink can stop the encoding */
        CHECK(pdns_zone_encode_kdb(z, &kp, stop_emit, NULL, err, sizeof(err)) != 0);
        /* B6a: the gate sees the serial and the digest ZONE_BEGIN carries, and can keep the zone back (returns 1, emits nothing) */
        {
            gate_seen_t gs = { 0, 0, { 0 }, 0 };
            pdns_kdb_params_t gp = { 1, 9, KDB_ZK_PRIMARY, "prof", test_gate, &gs, NULL };
            rt_buf_t b4 = {0};
            gs.answer = 1;
            CHECK(pdns_zone_encode_kdb(z, &gp, rt_emit, &b4, err, sizeof(err)) == 1);
            CHECK(b4.len == 0 && gs.calls == 1 && gs.serial == 2024010101u);
            /* B7a: the profile name is part of the digest; without a profile it is the digest of the data alone */
            CHECK(memcmp(gs.digest, info.digest, KDB_DIGEST_LEN) != 0);
            uint8_t with_prof[KDB_DIGEST_LEN];
            memcpy(with_prof, gs.digest, KDB_DIGEST_LEN);
            pdns_kdb_params_t gn = { 1, 9, KDB_ZK_PRIMARY, "", test_gate, &gs, NULL };
            CHECK(pdns_zone_encode_kdb(z, &gn, rt_emit, &b4, err, sizeof(err)) == 1);
            CHECK(memcmp(gs.digest, info.digest, KDB_DIGEST_LEN) == 0);
            /* ... and so is the text of the profile: editing a profile makes every zone that names it new */
            pdns_kdb_params_t gt = { 1, 9, KDB_ZK_PRIMARY, "prof", test_gate, &gs, "allow-transfer { 192.0.2.1; };" };
            CHECK(pdns_zone_encode_kdb(z, &gt, rt_emit, &b4, err, sizeof(err)) == 1);
            CHECK(memcmp(gs.digest, with_prof, KDB_DIGEST_LEN) != 0 && memcmp(gs.digest, info.digest, KDB_DIGEST_LEN) != 0);
            uint8_t with_text[KDB_DIGEST_LEN];
            memcpy(with_text, gs.digest, KDB_DIGEST_LEN);
            gt.profile_text = "allow-transfer { 192.0.2.2; };";
            CHECK(pdns_zone_encode_kdb(z, &gt, rt_emit, &b4, err, sizeof(err)) == 1);
            CHECK(memcmp(gs.digest, with_text, KDB_DIGEST_LEN) != 0);
            CHECK(b4.len == 0);
            gs.answer = 0;
            CHECK(pdns_zone_encode_kdb(z, &gp, rt_emit, &b4, err, sizeof(err)) == 0);
            CHECK(b4.len == b1.len && memcmp(b4.buf, b1.buf, b1.len) == 0 && gs.calls == 5);
            free(b4.buf);
        }
        free(b1.buf); free(b2.buf);
        pdns_zone_free(z); pdns_zone_free(z2); pdns_zone_free(z3);
        free(rows); free(names); free(txt);
    }
    {   /* B7a: a metadata-only edit changes the digest (the settings text is part of it), the same metadata does not */
        db_meta_row_t m1[] = { M("ALLOW-AXFR-FROM", "192.0.2.1") }, m2[] = { M("ALLOW-AXFR-FROM", "192.0.2.2") };
        pdns_zone_t *za = build(NULL, 0, NULL, 0, NULL), *zb = build(NULL, 0, m1, 1, NULL), *zc = build(NULL, 0, m2, 1, NULL),
                    *zd = build(NULL, 0, m1, 1, NULL);
        gate_seen_t ga = { 0, 0, { 0 }, 1 }, gb = ga, gc = ga, gd = ga;
        pdns_kdb_params_t pa = { 0, 1, KDB_ZK_PRIMARY, NULL, test_gate, &ga, NULL }, pb = pa, pc = pa, pd = pa;
        pb.gate_ud = &gb; pc.gate_ud = &gc; pd.gate_ud = &gd;
        char err[200];
        rt_buf_t nb = {0};
        CHECK(pdns_zone_encode_kdb(za, &pa, rt_emit, &nb, err, sizeof(err)) == 1);
        CHECK(pdns_zone_encode_kdb(zb, &pb, rt_emit, &nb, err, sizeof(err)) == 1);
        CHECK(pdns_zone_encode_kdb(zc, &pc, rt_emit, &nb, err, sizeof(err)) == 1);
        CHECK(pdns_zone_encode_kdb(zd, &pd, rt_emit, &nb, err, sizeof(err)) == 1);
        CHECK(memcmp(ga.digest, gb.digest, KDB_DIGEST_LEN) != 0);
        CHECK(memcmp(gb.digest, gc.digest, KDB_DIGEST_LEN) != 0);
        CHECK(memcmp(gb.digest, gd.digest, KDB_DIGEST_LEN) == 0);
        pdns_zone_free(za); pdns_zone_free(zb); pdns_zone_free(zc); pdns_zone_free(zd);
    }
    /* big RDATA through the generic form (one token, up to 65535 octets): messages are filled to the limit, an RR is
     * never split, and one that cannot fit a message of its own is refused with its row id */
    {
        size_t fits = 65450, nofit = 65520;
        char *hex = malloc(nofit * 2 + 32);
        char *content = malloc(nofit * 2 + 32);
        memset(hex, 'a', nofit * 2);
        hex[nofit * 2] = '\0';
        snprintf(content, nofit * 2 + 32, "\\# %zu %.*s", fits, (int)(fits * 2), hex);
        db_record_row_t rows[1] = { R(2, "big.z.test", "TYPE65534", content, 300, 0) };
        pdns_zone_t *z = build(rows, 1, NULL, 0, NULL);
        CHECK_MSG(!z->failed, "%s", z->error);
        if (!z->failed) {
            rt_info_t info;
            char why[300];
            CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
            CHECK(info.n_zone_data == 3);              /* SOA | big RR | closing SOA: no two of them fit together */
            CHECK(info.max_body <= 65535 && info.max_body > 65000);
        }
        pdns_zone_free(z);
        snprintf(content, nofit * 2 + 32, "\\# %zu %.*s", nofit, (int)(nofit * 2), hex);
        db_record_row_t big = R(60, "big.z.test", "TYPE65534", content, 300, 0);
        z = build(&big, 1, NULL, 0, NULL);
        /* 12 + owner + 10 + 65520 does not fit a ZONE_DATA message: the zone fails here, naming the row */
        CHECK(z->failed);
        CHECK_HAS(z->error, "records.id 60");
        CHECK_HAS(z->error, "does not fit");
        pdns_zone_free(z);
        free(hex);
        free(content);
    }
    /* refusals */
    {
        char err[300];
        rt_buf_t b = {0};
        db_meta_row_t m[] = { M("X-KARIDNS-FORMAT", "tinydns") };
        pdns_zone_t *z = build(NULL, 0, m, 1, NULL);
        /* B8: a tinydns zone is encoded (also without any time stamp or location): ZONE_BEGIN carries the tinydns flag only */
        rt_info_t tinfo;
        char twhy[300];
        CHECK_MSG(pdns_roundtrip(z, &tinfo, twhy, sizeof(twhy)), "%s", twhy);
        CHECK(tinfo.flags == KDB_ZF_TINYDNS);
        pdns_zone_free(z);
        db_meta_row_t m2[] = { M("PRESIGNED", "1"), M("NSEC3PARAM", "1 0 5 AABB") };
        z = build(NULL, 0, m2, 2, NULL);                              /* B5: NSEC3PARAM without any RRSIG(NSEC3) cannot be rebuilt */
        CHECK(z->failed);
        CHECK_HAS(z->error, "no RRSIG(NSEC3) rows");
        CHECK(pdns_zone_encode_kdb(z, &(pdns_kdb_params_t){0, 1, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL }, rt_emit, &b, err, sizeof(err)) != 0);
        pdns_zone_free(z);
        db_meta_row_t m3[] = { M("PRESIGNED", "1") };               /* presigned without NSEC3PARAM: encoded, flag set */
        z = build(NULL, 0, m3, 1, NULL);
        rt_info_t info;
        char why[300];
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
        CHECK(info.flags == KDB_ZF_PRESIGNED);
        pdns_zone_free(z);
        /* a failed zone is not encoded */
        db_record_row_t bad[1] = { R(2, "x.z.test", "A", "nope", 300, 0) };
        z = build(bad, 1, NULL, 0, NULL);
        CHECK(pdns_zone_encode_kdb(z, &(pdns_kdb_params_t){0, 1, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL }, rt_emit, &b, err, sizeof(err)) != 0);
        pdns_zone_free(z);
        /* size limit */
        pdns_opts_t o = { 0, 0, 0, 100 };
        z = build(NULL, 0, NULL, 0, &o);
        CHECK(!z->failed);
        CHECK(pdns_zone_encode_kdb(z, &(pdns_kdb_params_t){0, 1, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL }, rt_emit, &b, err, sizeof(err)) != 0);
        CHECK_HAS(err, "limit");
        pdns_zone_free(z);
        free(b.buf);
    }
    /* settings and profile reach ZONE_BEGIN */
    {
        db_meta_row_t m[] = { M("ALLOW-AXFR-FROM", "192.0.2.1"), M("X-KARIDNS-PROFILE", "p1") };
        pdns_zone_t *z = build(NULL, 0, m, 2, NULL);
        rt_buf_t b = {0};
        char err[200];
        CHECK(pdns_zone_encode_kdb(z, &(pdns_kdb_params_t){5, 42, KDB_ZK_SECONDARY, NULL, NULL, NULL, NULL }, rt_emit, &b, err, sizeof(err)) == 0);
        static uint8_t fb[KDB_MAX_BODY];
        kdb_framer_t f;
        kdb_framer_init(&f, KDB_FROM_LOADER, fb, sizeof(fb));
        CHECK(kdb_framer_feed(&f, b.buf, b.len) == KDB_OK);
        kdb_frame_t fr;
        CHECK(kdb_framer_next(&f, &fr) == KDB_OK && fr.type == KDB_T_ZONE_BEGIN);
        kdb_msg_t msg;
        char why[200];
        CHECK(kdb_decode(&fr, KDB_VIEWS_ANY, &msg, why, sizeof(why)) == KDB_OK);
        CHECK(msg.u.zone_begin.view == 5 && msg.u.zone_begin.source_id == 42 && msg.u.zone_begin.zone_kind == KDB_ZK_SECONDARY);
        CHECK(msg.u.zone_begin.settings.p && msg.u.zone_begin.settings.len == strlen(z->settings) &&
              memcmp(msg.u.zone_begin.settings.p, z->settings, msg.u.zone_begin.settings.len) == 0);
        CHECK(msg.u.zone_begin.profile.len == 2 && memcmp(msg.u.zone_begin.profile.p, "p1", 2) == 0);
        free(b.buf);
        pdns_zone_free(z);
    }
}

/* ------------------------------------------------------------------ B7b: SLAVE and CONSUMER zones */
static pdns_zone_t *build_sec(uint8_t kind, const char *master, const db_meta_row_t *meta, size_t nm) {
    pdns_zone_t *z = pdns_zone_new("s.test", NULL);
    CHECK(z != NULL);
    CHECK(pdns_zone_set_secondary(z, kind, master) == 0);
    for (size_t i = 0; i < nm; i++) pdns_zone_add_meta(z, &meta[i]);
    pdns_zone_finish(z);
    return z;
}

static void sec_digest(const pdns_zone_t *z, uint8_t out[KDB_DIGEST_LEN], uint32_t *serial) {
    gate_seen_t g = { 0, 0, { 0 }, 1 };
    pdns_kdb_params_t p = { 0, 7, KDB_ZK_PRIMARY, NULL, test_gate, &g, NULL };
    char err[200];
    rt_buf_t nb = {0};
    CHECK(pdns_zone_encode_kdb(z, &p, rt_emit, &nb, err, sizeof(err)) == 1 && g.calls == 1);
    memcpy(out, g.digest, KDB_DIGEST_LEN);
    if (serial) *serial = g.serial;
}

static void test_secondary(void) {
    printf("SLAVE / CONSUMER zones (B7b): domains.master, settings, KDB1 without data, digest\n");
    struct { const char *master, *want; } ok[] = {
        { "192.0.2.1", "masters { 192.0.2.1; };" },
        { "192.0.2.1:5353", "masters { 192.0.2.1 port 5353; };" },
        { "[2001:db8::1]:5353", "masters { 2001:db8::1 port 5353; };" },
        { "2001:db8::1", "masters { 2001:db8::1; };" },
        { "[2001:db8::1]", "masters { 2001:db8::1; };" },
        { "192.0.2.1,192.0.2.2:53", "masters { 192.0.2.1; 192.0.2.2 port 53; };" },
        { " 192.0.2.1 , 2001:db8::2 \t192.0.2.1 ", "masters { 192.0.2.1; 2001:db8::2; };" },     /* blanks tolerated, a repeated address once */
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        pdns_zone_t *z = build_sec(KDB_ZK_SECONDARY, ok[i].master, NULL, 0);
        CHECK_MSG(!z->failed, "%s: %s", ok[i].master, z->error);
        CHECK_STR(z->settings, ok[i].want);
        char err[200];
        zone_ext_shared_t *sh = db_settings_parse(z->settings, strlen(z->settings), err, sizeof(err));
        CHECK_MSG(sh != NULL, "%s: %s", ok[i].want, err);
        if (sh) zone_ext_shared_unref(sh);
        pdns_zone_free(z);
    }
    const char *bad[] = { NULL, "", "   ", ",", "ns1.example.net", "192.0.2.1,ns1.example.net", "192.0.2.1:0", "192.0.2.1:65536", "192.0.2.1:x",
                          "[2001:db8::1", "[2001:db8::1]:", "[192.0.2.1]:53", "2001:db8::1:53x", "192.0.2.1;",
                          "192.0.2.1 }; file \"/etc/passwd\"; masters {", "fe80::1%em0" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        pdns_zone_t *z = build_sec(KDB_ZK_SECONDARY, bad[i], NULL, 0);
        CHECK_MSG(z->failed, "master %s was accepted", bad[i] ? bad[i] : "(NULL)");
        CHECK_HAS(z->error, "zone 's.test.'");
        CHECK_HAS(z->error, "domains.master");
        pdns_zone_free(z);
    }
    {   /* more than 16 masters: the rest is ignored with a warning */
        char many[600] = "";
        for (int i = 1; i <= 20; i++) {
            char one[24];
            snprintf(one, sizeof(one), "%s192.0.2.%d", i > 1 ? "," : "", i);
            strcat(many, one);
        }
        pdns_zone_t *z = build_sec(KDB_ZK_SECONDARY, many, NULL, 0);
        CHECK(!z->failed && z->n_warnings == 1);
        CHECK_HAS(z->settings, "192.0.2.16;");
        CHECK(strstr(z->settings, "192.0.2.17") == NULL);
        pdns_zone_free(z);
    }
    {   /* the key, the usual settings and a profile ride along; the records of a SLAVE are not needed (no SOA row either) */
        db_meta_row_t m[] = { M("AXFR-MASTER-TSIG", "k1"), M("ALLOW-AXFR-FROM", "192.0.2.9"), M("ALSO-NOTIFY", "192.0.2.50:5353"),
                              M("X-KARIDNS-PROFILE", "p1"), M("PRESIGNED", "1") };
        pdns_zone_t *z = build_sec(KDB_ZK_CATALOG, "192.0.2.1", m, 5);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK_STR(z->settings, "masters { 192.0.2.1; }; tsig-key \"k1\"; allow-transfer { 192.0.2.9; }; also-notify { 192.0.2.50 port 5353; };");
        CHECK(z->profile[0] == 'p' && z->serial == 0);
        char err[200];
        zone_ext_shared_t *sh = db_settings_parse(z->settings, strlen(z->settings), err, sizeof(err));
        CHECK_MSG(sh != NULL, "%s", err);
        if (sh) {
            CHECK(sh->ext.masters_count == 1 && sh->ext.tsig_key && strcmp(sh->ext.tsig_key, "k1") == 0 && sh->ext.allow_transfer_count == 1);
            zone_ext_shared_unref(sh);
        }
        /* KDB1: ZONE_BEGIN (catalog kind, serial 0, flags 0, rr_count 0, the settings, the profile) and ZONE_END, nothing between */
        rt_buf_t b = {0};
        pdns_kdb_params_t kp = { 3, 77, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL };       /* the zone's own kind wins */
        CHECK(pdns_zone_encode_kdb(z, &kp, rt_emit, &b, err, sizeof(err)) == 0 && b.n_msgs == 2);
        static uint8_t fb[KDB_MAX_BODY];
        kdb_framer_t f;
        kdb_framer_init(&f, KDB_FROM_LOADER, fb, sizeof(fb));
        CHECK(kdb_framer_feed(&f, b.buf, b.len) == KDB_OK);
        kdb_frame_t fr;
        kdb_msg_t msg;
        char why[200];
        CHECK(kdb_framer_next(&f, &fr) == KDB_OK && fr.type == KDB_T_ZONE_BEGIN && kdb_decode(&fr, KDB_VIEWS_ANY, &msg, why, sizeof(why)) == KDB_OK);
        CHECK(msg.u.zone_begin.view == 3 && msg.u.zone_begin.source_id == 77 && msg.u.zone_begin.zone_kind == KDB_ZK_CATALOG);
        CHECK(msg.u.zone_begin.serial == 0 && msg.u.zone_begin.flags == 0 && msg.u.zone_begin.rr_count == 0);
        CHECK(msg.u.zone_begin.settings.len == strlen(z->settings) && memcmp(msg.u.zone_begin.settings.p, z->settings, strlen(z->settings)) == 0);
        CHECK(msg.u.zone_begin.profile.len == 2);
        CHECK(kdb_framer_next(&f, &fr) == KDB_OK && fr.type == KDB_T_ZONE_END && kdb_decode(&fr, KDB_VIEWS_ANY, &msg, why, sizeof(why)) == KDB_OK);
        CHECK(msg.u.zone_end.rr_count == 0 && kdb_framer_next(&f, &fr) == KDB_MORE);
        free(b.buf);
        pdns_zone_free(z);
    }
    {   /* the digest covers the settings: masters, key, kind, profile and ACLs change it; the same input gives the same digest */
        uint8_t d0[KDB_DIGEST_LEN], d1[KDB_DIGEST_LEN];
        db_meta_row_t k1[] = { M("AXFR-MASTER-TSIG", "k1") }, k2[] = { M("AXFR-MASTER-TSIG", "k2") }, acl[] = { M("ALLOW-AXFR-FROM", "192.0.2.9") },
                      pr[] = { M("X-KARIDNS-PROFILE", "p1") };
        pdns_zone_t *za = build_sec(KDB_ZK_SECONDARY, "192.0.2.1", NULL, 0), *zb = build_sec(KDB_ZK_SECONDARY, "192.0.2.1", NULL, 0);
        uint32_t ser = 9;
        sec_digest(za, d0, &ser);
        CHECK(ser == 0);
        sec_digest(zb, d1, NULL);
        CHECK(memcmp(d0, d1, KDB_DIGEST_LEN) == 0);
        pdns_zone_t *others[] = { build_sec(KDB_ZK_SECONDARY, "192.0.2.2", NULL, 0), build_sec(KDB_ZK_SECONDARY, "192.0.2.1:5353", NULL, 0),
                                  build_sec(KDB_ZK_CATALOG, "192.0.2.1", NULL, 0), build_sec(KDB_ZK_SECONDARY, "192.0.2.1", k1, 1),
                                  build_sec(KDB_ZK_SECONDARY, "192.0.2.1", k2, 1), build_sec(KDB_ZK_SECONDARY, "192.0.2.1", acl, 1),
                                  build_sec(KDB_ZK_SECONDARY, "192.0.2.1", pr, 1) };
        for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
            sec_digest(others[i], d1, NULL);
            CHECK_MSG(memcmp(d0, d1, KDB_DIGEST_LEN) != 0, "variant %zu has the digest of the plain zone", i);
            for (size_t j = 0; j < i; j++) {
                uint8_t dj[KDB_DIGEST_LEN];
                sec_digest(others[j], dj, NULL);
                CHECK_MSG(memcmp(dj, d1, KDB_DIGEST_LEN) != 0, "variants %zu and %zu share a digest", i, j);
            }
        }
        for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++) pdns_zone_free(others[i]);
        pdns_zone_free(za);
        pdns_zone_free(zb);
        /* a primary zone has no masters statement even when it has the key */
        pdns_zone_t *zp = build(NULL, 0, k1, 1, NULL);
        CHECK(!zp->failed && strstr(zp->settings, "masters") == NULL);
        pdns_zone_free(zp);
    }
}

/* ------------------------------------------------------------------ zone2sql */
/* D17-4 (found by the B4b file vs DB comparison of the lab zones, MINFO; RP / AFSDB / RT / KX and others answered in lower
 * case too): the RDATA names keep the case as written (RFC 4343 s2-s4) in the KDB1 stream and in the file zone alike;
 * only dns_record_canonical_rdata() (RFC 4034 s6.2 item 3) lower-cases them */
static const struct { const char *type, *content, *file_text; int64_t prio; } k_case[] = {
    { "MINFO", "RM.Z.TEST. EM.z.Test.", "RM.Z.TEST. EM.z.Test.", 0 },
    { "RP", "Mbox.Z.TEST. Txt.z.Test.", "Mbox.Z.TEST. Txt.z.Test.", 0 },
    { "AFSDB", "1 AFS.Z.test.", "1 AFS.Z.test.", 0 },
    { "RT", "10 Rt.Z.TEST.", "10 Rt.Z.TEST.", 0 },
    { "KX", "10 Kx.Z.TEST.", "10 Kx.Z.TEST.", 0 },
    { "LP", "10 L.Z.TEST.", "10 L.Z.TEST.", 0 },
    { "PX", "10 Map822.Z.test. MapX400.z.TEST.", "10 Map822.Z.test. MapX400.z.TEST.", 0 },
    { "MX", "MAIL.Z.Test.", "10 MAIL.Z.Test.", 10 },
    { "NS", "NS9.Z.Test.", "NS9.Z.Test.", 0 },
    { "SRV", "1 2 5060 SIP.Z.Test.", "1 2 5060 SIP.Z.Test.", 0 },
    { "NAPTR", "100 10 \"S\" \"SIP+D2U\" \"\" _SIP._udp.Z.Test.", "100 10 \"S\" \"SIP+D2U\" \"\" _SIP._udp.Z.Test.", 0 },
    { "DNAME", "Target.Z.Test.", "Target.Z.Test.", 0 },
};

static size_t upper_count(const uint8_t *p, size_t n) {
    size_t c = 0;
    for (size_t k = 0; k < n; k++) c += (p[k] >= 'A' && p[k] <= 'Z');
    return c;
}

static void test_kdb_name_case(void) {
    printf("RDATA names keep their case (D17-4): file zone, DB zone, KDB1 stream; canonical form lower case\n");
    enum { N = sizeof(k_case) / sizeof(k_case[0]) };
    static db_record_row_t rows[N];
    char *text = malloc(8192);
    size_t tl = (size_t)snprintf(text, 8192, "$ORIGIN .\n");
    for (size_t i = 0; i < N; i++) {
        char owner[40];
        snprintf(owner, sizeof(owner), "t%zu.z.test", i);
        rows[i] = R((int64_t)i + 2, strdup(owner), k_case[i].type, k_case[i].content, 300, k_case[i].prio);
        tl += (size_t)snprintf(text + tl, 8192 - tl, "%s. 300 IN %s %s\n", owner, k_case[i].type, k_case[i].file_text);
    }
    pdns_zone_t *z = build(rows, N, NULL, 0, NULL);
    CHECK_MSG(!z->failed, "%s", z->error);
    zone_arena_t fa;
    zone_arena_init(&fa);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = ".";
    parse_error_t perr = {0};
    ctx.err_out = &perr;
    int prc = parse_zone_fast(text, tl, &fa, &ctx);
    CHECK_MSG(prc == (int)N, "rc %d: %s (offset %zu)", prc, perr.error_message ? perr.error_message : "-", perr.error_offset);
    CHECK(fa.count == N);
    rt_buf_t b = {0};
    char err[200];
    if (!z->failed) CHECK(pdns_zone_encode_kdb(z, &(pdns_kdb_params_t){0, 1, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL }, rt_emit, &b, err, sizeof(err)) == 0);
    for (size_t i = 0; i < N && !z->failed && i < fa.count; i++) {
        const dns_record_t *dbrec = NULL;
        for (size_t k = 0; k < z->arena.count; k++)
            if (z->arena.records[k].type_code == fa.records[i].type_code && strcmp(z->arena.records[k].name, fa.records[i].name) == 0)
                dbrec = &z->arena.records[k];
        CHECK_MSG(dbrec != NULL, "%s: not in the DB zone", k_case[i].type);
        if (!dbrec) continue;
        uint8_t wa[1024], wb[1024], wc[1024];
        uint16_t oa = 0, ob = 0, oc = 12;
        CHECK(serialize_dns_record(wa, sizeof(wa), &oa, &fa.records[i], NULL, NULL, 0xFFFFFFFFu) == 0);
        CHECK(serialize_dns_record(wb, sizeof(wb), &ob, dbrec, NULL, NULL, 0xFFFFFFFFu) == 0);
        CHECK_MSG(oa == ob && memcmp(wa, wb, oa) == 0, "%s: file zone and DB zone serialize differently", k_case[i].type);
        compress_ctx_t cc;
        compress_ctx_init(&cc);
        CHECK(serialize_dns_record(wc, sizeof(wc), &oc, &fa.records[i], &cc, NULL, 0xFFFFFFFFu) == 0);
        /* upper-case letters of the names survive, with and without a compression context (NAPTR also has the
         * character-strings "S" and "SIP+D2U", which are never case-folded) */
        CHECK_MSG(upper_count(wa, oa) > 0, "%s: RDATA names were lower-cased without a context", k_case[i].type);
        CHECK_MSG(upper_count(wc + 12, (size_t)oc - 12) > 0, "%s: RDATA names were lower-cased with a context", k_case[i].type);
        /* the canonical form is lower case where RFC 4034 s6.2 item 3 lists the type (not LP, RFC 6742) */
        uint8_t cn[1024];
        long cl = dns_record_canonical_rdata(&fa.records[i], cn, sizeof(cn));
        CHECK(cl > 0);
        size_t uc = upper_count(cn, cl > 0 ? (size_t)cl : 0);
        if (fa.records[i].type_code == 35) CHECK(uc == 6);               /* NAPTR: only the letters of "S" and "SIP+D2U" */
        else if (fa.records[i].type_code == 107) CHECK(uc > 0);           /* LP */
        else CHECK_MSG(uc == 0, "%s: canonical RDATA has upper-case octets", k_case[i].type);
    }
    /* the stream carries the names as written */
    static const uint8_t minfo[] = { 2, 'R', 'M', 1, 'Z', 4, 'T', 'E', 'S', 'T', 0, 2, 'E', 'M', 1, 'z', 4, 'T', 'e', 's', 't', 0 };
    static const uint8_t rp[] = { 4, 'M', 'b', 'o', 'x', 1, 'Z', 4, 'T', 'E', 'S', 'T', 0, 3, 'T', 'x', 't' };
    static const uint8_t afsdb[] = { 0, 1, 3, 'A', 'F', 'S', 1, 'Z', 4, 't', 'e', 's', 't', 0 };
    static const uint8_t rt[] = { 0, 10, 2, 'R', 't', 1, 'Z', 4, 'T', 'E', 'S', 'T', 0 };
    static const uint8_t kx[] = { 0, 10, 2, 'K', 'x', 1, 'Z', 4, 'T', 'E', 'S', 'T', 0 };
    static const uint8_t mx[] = { 0, 10, 4, 'M', 'A', 'I', 'L', 1, 'Z', 4, 'T', 'e', 's', 't', 0 };
    CHECK(b.buf && memmem(b.buf, b.len, minfo, sizeof(minfo)) != NULL);
    CHECK(b.buf && memmem(b.buf, b.len, rp, sizeof(rp)) != NULL);
    CHECK(b.buf && memmem(b.buf, b.len, afsdb, sizeof(afsdb)) != NULL);
    CHECK(b.buf && memmem(b.buf, b.len, rt, sizeof(rt)) != NULL);
    CHECK(b.buf && memmem(b.buf, b.len, kx, sizeof(kx)) != NULL);
    CHECK(b.buf && memmem(b.buf, b.len, mx, sizeof(mx)) != NULL);
    free(b.buf);
    zone_arena_destroy(&fa);
    free(text);
    for (size_t i = 0; i < N; i++) free((void *)rows[i].name);
    pdns_zone_free(z);
}

static void test_zone2sql(void) {
    printf("zone2sql\n");
    char path[600];
    snprintf(path, sizeof(path), "%s/example.com.zone", g_zones_dir);
    zone_arena_t a;
    char apex[DNS_NAME_TEXT_SIZE], err[400];
    if (!z2s_load_zone_file(path, NULL, &a, apex, sizeof(apex), err, sizeof(err))) {
        printf("  [SKIP] %s\n", err);
        return;
    }
    z2s_rows_t rows;
    CHECK(z2s_rows_from_arena(&a, apex, &rows, err, sizeof(err)));
    CHECK_STR(rows.zone, "example.com");
    bool saw_mx = false, saw_srv = false, saw_txt = false;
    for (size_t i = 0; i < rows.n; i++) {
        const db_record_row_t *r = &rows.rows[i];
        CHECK(r->id == (int64_t)i + 1);
        if (!r->type) continue;                                        /* ENT row of a presigned zone */
        CHECK(r->name[strlen(r->name) - 1] != '.');
        for (const char *p = r->name; *p; p++) CHECK(!(*p >= 'A' && *p <= 'Z'));
        if (strcmp(r->type, "MX") == 0 && !saw_mx) {
            saw_mx = true;
            CHECK(r->prio > 0);
            CHECK(r->content[strlen(r->content) - 1] != '.');
        }
        if (strcmp(r->type, "SRV") == 0 && !saw_srv) {
            saw_srv = true;
            CHECK(r->content[strlen(r->content) - 1] != '.');
        }
        if (strcmp(r->type, "TXT") == 0) saw_txt = true;
        if (strcmp(r->type, "SOA") == 0) {
            CHECK(r->content[strlen(r->content) - 1] != '.');
            uint32_t s;
            CHECK(pdns_soa_serial(r->content, &s));
        }
        CHECK(r->prio == 0 || strcmp(r->type, "MX") == 0 || strcmp(r->type, "SRV") == 0);
    }
    CHECK(saw_mx && saw_srv && saw_txt);
    /* SQL, both dialects */
    for (int d = 0; d < 2; d++) {
        char *buf = NULL;
        size_t sz = 0;
        FILE *fp = open_memstream(&buf, &sz);
        z2s_print_sql(fp, d == 0 ? Z2S_SQLITE3 : Z2S_PGSQL, &rows);
        fclose(fp);
        CHECK(strstr(buf, "INSERT INTO domains (name, type) VALUES ('example.com', 'NATIVE');") != NULL);
        CHECK((strstr(buf, "SET standard_conforming_strings") != NULL) == (d == 1));
        CHECK((strstr(buf, ", 0, false, true, NULL);") != NULL) == (d == 1));
        CHECK((strstr(buf, ", 0, 0, 1, NULL);") != NULL) == (d == 0));
        size_t ins = 0;
        for (const char *p = buf; (p = strstr(p, "INSERT INTO records")) != NULL; p++) ins++;
        CHECK(ins == rows.n);
        free(buf);
    }
    z2s_rows_free(&rows);
    zone_arena_destroy(&a);
}

/* ------------------------------------------------------------------ seed corpora for the fuzzers */
#define RS "\x1e"
#define FS "\x1f"

static void write_file(const char *dir, const char *name, const char *data, size_t len) {
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *fp = fopen(path, "wb");
    if (!fp) { perror(path); return; }
    fwrite(data, 1, len, fp);
    fclose(fp);
}

static int gen_corpus(const char *dir) {
    /* fuzz_pdns_content: byte 0 = selector (bit0 = add the SOA row); rows separated by 0x1E, fields by 0x1F:
     * owner, type, content, prio, ttl  (prio / ttl empty = NULL) */
    /* the corpus rows in seeds of at most ~3.5 KB (libFuzzer's default max_len is 4096) */
    char seed[8192];
    size_t n = 0, nseed = 0;
    for (size_t i = 0; i < sizeof(k_corpus) / sizeof(k_corpus[0]); i++) {
        char row[2400], name[64];
        if (strcmp(k_corpus[i].type, "SOA") == 0) continue;     /* the zone has its own SOA row (selector bit0) */
        size_t rl = (size_t)snprintf(row, sizeof(row), "x%zu.fuzz.test" FS "%s" FS "%s" FS "%lld" FS "300", i,
                                     k_corpus[i].type, k_corpus[i].content, (long long)k_corpus[i].prio);
        if (rl >= sizeof(row)) continue;
        if (n > 1 && n + rl + 1 > 3500) {
            snprintf(name, sizeof(name), "content_corpus_%zu.bin", nseed++);
            write_file(dir, name, seed, n);
            n = 0;
        }
        if (n == 0) seed[n++] = 1;
        else if (n > 1) seed[n++] = 0x1E;
        memcpy(seed + n, row, rl);
        n += rl;
    }
    if (n > 1) {
        char name[64];
        snprintf(name, sizeof(name), "content_corpus_%zu.bin", nseed++);
        write_file(dir, name, seed, n);
    }
    const char *hostile[] = {
        "\x01" "a.fuzz.test" FS "TXT" FS "\"x\"\nb.fuzz.test. 300 IN A 192.0.2.1" FS FS "300",
        "\x01" "a.fuzz.test" FS "TXT" FS "\"a\" (" RS "b.fuzz.test" FS "A" FS "192.0.2.1" FS FS "300",
        "\x01" "a.fuzz.test" FS "TXT" FS "x\\" RS "b.fuzz.test" FS "A" FS "192.0.2.1" FS FS "300",
        "\x01" "a.fuzz.test" FS "MX" FS "mail.fuzz.test" FS "10" FS "300" RS "b.fuzz.test" FS "SRV" FS "1 2 mail.fuzz.test" FS "3" FS "",
        "\x01" "fuzz.test" FS "NS" FS "ns1.fuzz.test" FS FS "300" RS "p.fuzz.test" FS "" FS "" FS FS RS "q.p.fuzz.test" FS "A" FS "192.0.2.7" FS FS "0",
        "\x01" "a.fuzz.test" FS "ALIAS" FS "t.fuzz.test" FS FS "300",
        "\x01" "l.fuzz.test" FS "LUA" FS "A \";return {'192.0.2.1'}\"" FS FS "300",
        "\x01" "a.fuzz.test" FS "ALIAS" FS "t.fuzz.test" FS FS "300" RS "a.fuzz.test" FS "A" FS "192.0.2.1" FS FS "300",
        "\x01" "l.fuzz.test" FS "LUA" FS "TXT \"a\" \"b\" \"c\"" FS FS "300" RS "l.fuzz.test" FS "TXT" FS "\"x\"" FS FS "300",
    };
    char name[64];
    for (size_t i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++) {
        snprintf(name, sizeof(name), "content_hostile_%zu.bin", i);
        write_file(dir, name, hostile[i], strlen(hostile[i]) ? strlen(hostile[i]) : 1);
    }
    {   /* selector 0: no SOA row added, the input brings its own */
        static const char s[] = "\x00" "fuzz.test" FS "SOA" FS "ns.fuzz.test h.fuzz.test 5 1 2 3 4" FS FS "300";
        write_file(dir, "content_own_soa.bin", s, sizeof(s) - 1);
    }

    /* fuzz_pdns_metadata: rows 0x1E, fields 0x1F: kind, content */
    const char *meta =
        "ALLOW-AXFR-FROM" FS "192.0.2.1" RS "ALLOW-AXFR-FROM" FS "2001:db8::/32" RS "TSIG-ALLOW-AXFR" FS "xfr" RS
        "ALSO-NOTIFY" FS "192.0.2.53" RS "ALSO-NOTIFY" FS "[2001:db8::54]:5301" RS "TSIG-ALLOW-DNSUPDATE" FS "upd" RS
        "AXFR-MASTER-TSIG" FS "master-key" RS "X-KARIDNS-IXFR-HISTORY" FS "8" RS "X-KARIDNS-NOTIFY-RETRIES" FS "3" RS
        "X-KARIDNS-NOTIFY-RETRY-INTERVAL" FS "30" RS "X-KARIDNS-NOTIFY-RETRY-BACKOFF" FS "exponential" RS
        "X-KARIDNS-ADDITIONAL-FROM-AUTH" FS "in-zone" RS "X-KARIDNS-DISABLE-AUTO-TC-FLAG" FS "true" RS
        "X-KARIDNS-ZONE-UDP-BUFSIZE" FS "1232" RS "X-KARIDNS-ZONE-TCP-MSS" FS "1400" RS "X-KARIDNS-ZONE-TCP-WINDOW" FS "1m" RS
        "X-KARIDNS-ZONE-TCP-SNDBUF" FS "65536" RS "X-KARIDNS-PROFILE" FS "web" RS "PRESIGNED" FS "1" RS "SOA-EDIT" FS "EPOCH";
    write_file(dir, "metadata_all.bin", meta, strlen(meta));
    const char *meta2 = "ALLOW-DNSUPDATE-FROM" FS "10.0.0.0/8" RS "TSIG-ALLOW-DNSUPDATE" FS "u" RS "ALLOW-AXFR-FROM" FS "AUTO-NS" RS
                        "ALSO-NOTIFY" FS "bogus" RS "X-KARIDNS-IXFR-HISTORY" FS "-1" RS "TSIG-ALLOW-AXFR" FS "k\"; x \"";
    write_file(dir, "metadata_dropped.bin", meta2, strlen(meta2));
    const char *meta3 = "ALLOW-AXFR-FROM" FS "1.2.3.4; any" RS "AXFR-MASTER-TSIG" FS "a b" RS "X-KARIDNS-NOTIFY-RETRIES" FS "3; x";
    write_file(dir, "metadata_hostile.bin", meta3, strlen(meta3));
    return 0;
}

/* ------------------------------------------------------------------ B8: Extended AXFR attributes */
static pdns_zone_t *build_ext(const db_record_row_t *rows, size_t n, const db_meta_row_t *meta, size_t nm, const db_tag_row_t *tags,
                              size_t nt, const db_tinydns_row_t *td, size_t ntd, const db_tagdef_row_t *defs, size_t nd) {
    pdns_zone_t *z = pdns_zone_new("z.test", NULL);
    db_record_row_t soa = SOA();
    pdns_zone_add_record(z, &soa);
    for (size_t i = 0; i < n; i++) pdns_zone_add_record(z, &rows[i]);
    for (size_t i = 0; i < nm; i++) pdns_zone_add_meta(z, &meta[i]);
    for (size_t i = 0; i < nt; i++) pdns_zone_add_tags(z, &tags[i]);
    for (size_t i = 0; i < ntd; i++) pdns_zone_add_tinydns(z, &td[i]);
    for (size_t i = 0; i < nd; i++) pdns_zone_add_tagdef(z, &defs[i]);
    pdns_zone_finish(z);
    return z;
}

static const db_record_row_t k_ext_rows[] = {
    { 2, 300, 0, false, false, false, "www.z.test", "A", "192.0.2.1", NULL },
    { 3, 300, 0, false, false, false, "www.z.test", "A", "192.0.2.10", NULL },
    { 4, 300, 0, false, false, false, "mail.z.test", "A", "192.0.2.11", NULL },
};
static const db_tag_row_t k_ext_tags[] = { { 3, "lan", NULL }, { 4, "wan", "east" } };
static const db_tagdef_row_t k_ext_defs[] = {
    { "location", "lan", "127.0.0.2/32" }, { "location", "lan", "127.0.0.3/32" }, { "location", "wan", "10.0.0.0/8" },
    { "ecs", "east", "198.51.100.0/24" },
};

static void zone_digest(pdns_zone_t *z, uint8_t out[KDB_DIGEST_LEN]) {
    rt_info_t info;
    char why[300];
    memset(out, 0, KDB_DIGEST_LEN);
    if (z && !z->failed && pdns_roundtrip(z, &info, why, sizeof(why))) memcpy(out, info.digest, KDB_DIGEST_LEN);
}

static void expect_ext_fail(const char *label, const db_tag_row_t *t, const db_tinydns_row_t *d, const db_tagdef_row_t *g, const char *needle) {
    pdns_zone_t *z = build_ext(k_ext_rows, 3, NULL, 0, t, t ? 1 : 0, d, d ? 1 : 0, g, g ? 1 : 0);
    CHECK_MSG(z->failed, "%s: accepted", label);
    if (z->failed) CHECK_MSG(strstr(z->error, "zone 'z.test.'") && strstr(z->error, needle), "%s: error '%s' lacks '%s'", label, z->error, needle);
    pdns_zone_free(z);
}

static void test_ext(void) {
    printf("Extended AXFR attributes (tags, tinydns, definitions)\n");
    {   /* tags and definitions: attached to the records, carried, counted */
        pdns_zone_t *z = build_ext(k_ext_rows, 3, NULL, 0, k_ext_tags, 2, NULL, 0, k_ext_defs, 4);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK(z->has_ext && z->arena.count == 4);
        CHECK(z->arena.records[2].bind_location_tag && strcmp(z->arena.records[2].bind_location_tag, "lan") == 0);
        CHECK(z->arena.records[3].bind_location_tag && z->arena.records[3].ecs_subnet_tag && strcmp(z->arena.records[3].ecs_subnet_tag, "east") == 0);
        CHECK(z->arena.records[1].bind_location_tag == NULL);
        CHECK(z->arena.bind_location_tag_count == 2 && z->arena.bind_location_tags[0].cidr_count == 2);   /* the rows of one tag are one definition */
        CHECK(z->arena.bind_ecs_tag_count == 1);
        rt_info_t info;
        char why[300];
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
        CHECK(info.flags == KDB_ZF_EXTENDED);
        /* 2 SOA + 3 rows + 3 definitions + LOC lan, LOC wan, ECS east + 2 resets */
        CHECK_MSG(info.rr_count == 13, "rr_count %llu", (unsigned long long)info.rr_count);
        pdns_zone_free(z);
    }
    {   /* B8t-1: attributes on the apex SOA (row 1) are read like any other (the B8 interim rejection is gone); B8t-2: the KDB1 stream
         * is the version 3 encoding, which carries them (the SOA is a wrapped body RR, the frame is the reference SOA) */
        db_tag_row_t ts[] = { { 1, "lan", NULL } };
        pdns_zone_t *z = build_ext(k_ext_rows, 3, NULL, 0, ts, 1, NULL, 0, k_ext_defs, 4);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK(z->arena.records[z->soa_index].bind_location_tag && strcmp(z->arena.records[z->soa_index].bind_location_tag, "lan") == 0);
        rt_info_t info;
        char why[300];
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
        pdns_zone_free(z);
        db_tinydns_row_t tds[] = { { 1, false, 10, "l2", false } };
        db_tagdef_row_t td_defs[] = { { "tinydns", "l2", "127.0.0.2/32" } };
        z = build_ext(k_ext_rows, 3, NULL, 0, NULL, 0, tds, 1, td_defs, 1);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK(z->arena.records[z->soa_index].tinydns_ttd == 10 && z->arena.records[z->soa_index].tinydns_loc[0] == 'l');
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
        pdns_zone_free(z);
        /* a tag on a second SOA row: the SOA without attributes is the reference, the serial is the one of both */
        db_record_row_t soa2[] = { R(9, "z.test", "SOA", "ns2.z.test hostmaster.z.test 2024010101 7200 3600 1209600 300", 3600, 0) };
        db_tag_row_t ts2[] = { { 1, "lan", NULL } };
        z = pdns_zone_new("z.test", NULL);
        db_record_row_t first = SOA();
        pdns_zone_add_record(z, &first);
        pdns_zone_add_record(z, &soa2[0]);
        pdns_zone_add_tags(z, &ts2[0]);
        for (size_t i = 0; i < 3; i++) pdns_zone_add_record(z, &k_ext_rows[i]);
        for (size_t i = 0; i < 4; i++) pdns_zone_add_tagdef(z, &k_ext_defs[i]);
        pdns_zone_finish(z);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK(z->arena.records[z->soa_index].bind_location_tag == NULL && strncmp(z->arena.records[z->soa_index].rdata[0], "ns2.z.test", 10) == 0);
        pdns_zone_free(z);
    }
    {   /* the digest covers the attributes */
        uint8_t d0[KDB_DIGEST_LEN], d1[KDB_DIGEST_LEN], d2[KDB_DIGEST_LEN], d3[KDB_DIGEST_LEN], d4[KDB_DIGEST_LEN], d5[KDB_DIGEST_LEN];
        pdns_zone_t *z = build_ext(k_ext_rows, 3, NULL, 0, k_ext_tags, 2, NULL, 0, k_ext_defs, 4);
        zone_digest(z, d0);
        pdns_zone_free(z);
        z = build_ext(k_ext_rows, 3, NULL, 0, k_ext_tags, 2, NULL, 0, k_ext_defs, 4);
        zone_digest(z, d1);
        pdns_zone_free(z);
        CHECK(memcmp(d0, d1, KDB_DIGEST_LEN) == 0);
        z = build_ext(k_ext_rows, 3, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
        zone_digest(z, d2);
        pdns_zone_free(z);
        CHECK(memcmp(d0, d2, KDB_DIGEST_LEN) != 0);
        db_tag_row_t t2[] = { { 3, "lan", NULL }, { 4, "wan", "west" } };
        z = build_ext(k_ext_rows, 3, NULL, 0, t2, 2, NULL, 0, k_ext_defs, 4);
        zone_digest(z, d3);
        pdns_zone_free(z);
        CHECK(memcmp(d0, d3, KDB_DIGEST_LEN) != 0);
        db_tagdef_row_t g2[] = { { "location", "lan", "127.0.0.2/32" }, { "location", "lan", "127.0.0.4/32" }, { "location", "wan", "10.0.0.0/8" }, { "ecs", "east", "198.51.100.0/24" } };
        z = build_ext(k_ext_rows, 3, NULL, 0, k_ext_tags, 2, NULL, 0, g2, 4);
        zone_digest(z, d4);
        pdns_zone_free(z);
        CHECK(memcmp(d0, d4, KDB_DIGEST_LEN) != 0);
        db_meta_row_t tm[] = { M("X-KARIDNS-FORMAT", "tinydns") };
        z = build_ext(k_ext_rows, 3, tm, 1, k_ext_tags, 2, NULL, 0, k_ext_defs, 4);
        zone_digest(z, d5);
        pdns_zone_free(z);
        CHECK(memcmp(d0, d5, KDB_DIGEST_LEN) != 0);        /* the tinydns flag alone */
    }
    {   /* tinydns: time stamps, countdown, locations; flags extended + tinydns */
        db_tinydns_row_t td[] = { { 2, false, 2147483647, "l2", true }, { 3, false, 10, NULL, false }, { 4, true, 0, "lw", false } };
        db_tagdef_row_t defs[] = { { "tinydns", "l2", "127.0.0.2/32" }, { "tinydns", "lw", "127.0.0.9/24" } };
        db_meta_row_t tm[] = { M("X-KARIDNS-FORMAT", "tinydns") };
        pdns_zone_t *z = build_ext(k_ext_rows, 3, tm, 1, NULL, 0, td, 3, defs, 2);
        CHECK_MSG(!z->failed, "%s", z->error);
        CHECK(z->arena.records[1].tinydns_ttd == 2147483647 && z->arena.records[1].tinydns_ttl_countdown && z->arena.records[1].tinydns_loc[0] == 'l');
        CHECK(z->arena.records[3].tinydns_ttd == 0 && z->arena.records[3].tinydns_loc[1] == 'w');
        CHECK(z->arena.location_count == 2 && z->arena.locations[1].prefix_bits == 24 && z->arena.locations[1].prefix[3] == 0);   /* network part only */
        rt_info_t info;
        char why[300];
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
        CHECK(info.flags == (KDB_ZF_EXTENDED | KDB_ZF_TINYDNS));
        pdns_zone_free(z);
        z = build_ext(k_ext_rows, 3, NULL, 0, NULL, 0, td, 3, NULL, 0);       /* attributes without the metadata: still carried */
        CHECK_MSG(pdns_roundtrip(z, &info, why, sizeof(why)), "%s", why);
        CHECK(info.flags == KDB_ZF_EXTENDED);
        pdns_zone_free(z);
    }
    /* rejections: the zone fails, the error names the zone and the row */
    {
        db_tag_row_t t1 = { 3, "none", NULL }, t2 = { 3, "Default", NULL }, t3 = { 3, "a b", NULL }, t4 = { 3, NULL, "this-tag-is-much-too-long-this-tag-is-much-too-long-this-tag-is-much" };
        expect_ext_fail("tag none", &t1, NULL, NULL, "records.id 3");
        expect_ext_fail("tag default", &t2, NULL, NULL, "reserved");
        expect_ext_fail("tag with a blank", &t3, NULL, NULL, "tag name");
        expect_ext_fail("tag longer than 63", &t4, NULL, NULL, "tag name");
        db_tinydns_row_t d1 = { 3, false, -5, NULL, false }, d2 = { 3, true, 0, NULL, true }, d3 = { 3, true, 0, "abc", false }, d4 = { 3, true, 0, "a b", false };
        expect_ext_fail("negative ttd", NULL, &d1, NULL, "negative");
        expect_ext_fail("countdown without ttd", NULL, &d2, NULL, "countdown");
        expect_ext_fail("location code of 3 characters", NULL, &d3, NULL, "location code");
        expect_ext_fail("location code with a blank", NULL, &d4, NULL, "location code");
        db_tagdef_row_t g1 = { "location", "lan", "300.0.0.0/8" }, g2 = { "ecs", "east", "any" }, g3 = { "tinydns", "l2", "2001:db8::/32" }, g4 = { "location", "none", "192.0.2.0/24" },
                        g5 = { "tinydns", "l2", "garbage" };
        expect_ext_fail("bad CIDR", NULL, NULL, &g1, "not an address or prefix");
        expect_ext_fail("any as a CIDR", NULL, NULL, &g2, "not an address or prefix");
        expect_ext_fail("IPv6 tinydns location", NULL, NULL, &g3, "IPv4");
        expect_ext_fail("reserved tag in a definition", NULL, NULL, &g4, "tag name");
        expect_ext_fail("garbage tinydns location", NULL, NULL, &g5, "not an address or prefix");
        db_tag_row_t two[] = { { 3, "lan", NULL }, { 3, "wan", NULL } };
        pdns_zone_t *z = build_ext(k_ext_rows, 3, NULL, 0, two, 2, NULL, 0, NULL, 0);
        CHECK(z->failed && strstr(z->error, "two rows"));
        pdns_zone_free(z);
        /* warnings only: a row of an unknown kind, a row of no enabled record */
        db_tagdef_row_t gu = { "foo", "x", "192.0.2.0/24" };
        db_tag_row_t ts[] = { { 99, "lan", NULL } };
        z = build_ext(k_ext_rows, 3, NULL, 0, ts, 1, NULL, 0, &gu, 1);
        CHECK_MSG(!z->failed && z->n_warnings == 2, "%s (%zu warnings)", z->error, z->n_warnings);
        pdns_zone_free(z);
        /* rows after pdns_zone_finish() */
        z = build_ext(k_ext_rows, 3, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
        db_tag_row_t late = { 3, "lan", NULL };
        CHECK(pdns_zone_add_tags(z, &late) != 0);
        pdns_zone_free(z);
    }
    printf("X-KARIDNS-ECS-TRUSTED-RESOLVERS -> ecs-trusted-resolvers\n");
    {
        db_meta_row_t m[] = { M("X-KARIDNS-ECS-TRUSTED-RESOLVERS", "127.0.0.2, 127.0.0.5") };
        expect_settings("trusted resolvers, comma and blank", m, 1, "ecs-trusted-resolvers { 127.0.0.2; 127.0.0.5; };", 0);
        db_meta_row_t m2[] = { M("X-KARIDNS-ECS-TRUSTED-RESOLVERS", "!192.0.2.0/25"), M("x-karidns-ecs-trusted-resolvers", "192.0.2.0/24 2001:db8::/32"), M("X-KARIDNS-ECS-TRUSTED-RESOLVERS", "192.0.2.0/24") };
        expect_settings("several rows, exclusion, duplicates dropped", m2, 3, "ecs-trusted-resolvers { !192.0.2.0/25; 192.0.2.0/24; 2001:db8::/32; };", 0);
        db_meta_row_t m3[] = { M("X-KARIDNS-ECS-TRUSTED-RESOLVERS", "   ") };
        expect_settings("empty list", m3, 1, "", 0);
        db_meta_row_t bad[] = { M("X-KARIDNS-ECS-TRUSTED-RESOLVERS", "127.0.0.2 resolver.example") };
        pdns_zone_t *z = build(NULL, 0, bad, 1, NULL);
        CHECK(z->failed);
        CHECK_HAS(z->error, "X-KARIDNS-ECS-TRUSTED-RESOLVERS entry 'resolver.example'");
        pdns_zone_free(z);
        db_meta_row_t bad2[] = { M("X-KARIDNS-ECS-TRUSTED-RESOLVERS", "127.0.0.2; any") };
        z = build(NULL, 0, bad2, 1, NULL);
        CHECK(z->failed);
        pdns_zone_free(z);
        db_meta_row_t any[] = { M("X-KARIDNS-ECS-TRUSTED-RESOLVERS", "any") };
        z = build(NULL, 0, any, 1, NULL);
        CHECK(z->failed);
        pdns_zone_free(z);
    }
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--gen-corpus") == 0) return gen_corpus(argv[2]);
    if (argc == 2) g_zones_dir = argv[1];
    test_text_check();
    test_corpus();
    test_owners();
    test_rejections();
    test_prio_rules();
    test_ttl_rules();
    test_disabled_and_ent();
    test_b9a_alias_lua();
    test_zone_level();
    test_isolation();
    test_metadata();
    test_ext();
    test_kdb();
    test_secondary();
    test_kdb_name_case();
    test_zone2sql();
    test_zone_files();
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
