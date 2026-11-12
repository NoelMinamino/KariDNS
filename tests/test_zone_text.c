/*
 * test_zone_text.c - the zone-file writer of the ZoneExporter (dns_zone_text.c) and the shared field table of dns_zone_rows.c.
 *
 *  1. every RR type the zone parser knows: text -> parse -> write -> parse gives the same records; the file is the same when the records
 *     come in another order (canonical order, RFC 4034 section 6); streaming (no_verify) gives the same bytes.
 *  2. the BIND format byte for byte: $ORIGIN, $TTL, owners relative to the zone, names in RDATA relative or absolute, TTL and class only when
 *     they differ, escapes in owners and strings, canonical order.
 *  3. $LOCATION / $ECS-SUBNET tags and their definitions.
 *  4. hostile content: nothing in an owner, a name, a string or a tag can end a line, start a directive or a comment, or change the record
 *     set; what the format cannot hold makes the writer fail and name the record.
 *  5. the tinydns data file: every line type, time stamps, countdown TTLs, location codes and % lines; the BIND format refuses what only
 *     the data file can say.
 *  6. database zones: rows -> reader -> writer (a presigned NSEC3 zone made with the signer tools when they are installed, a tinydns zone).
 *  7. dns_zone_text_same_zone() reports each kind of difference; sinks that fail; the field table.
 *
 * Usage: test_zone_text [tests-dir]   (default tests; reads tests/db/tdz.test.data)
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
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>

#include "../dns_zone_render.h"
#include "../dns_zone_text.h"
#include "../dns_zone_rows.h"
#include "../dns_pdns_reader.h"
#include "../dns_utils.h"
#include "db/zrows_feed.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

/* defined in dns_server_core.c / dns_priv_sandbox.c in the server (the configuration parser of the reader calls it) */
int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)path; (void)flags; (void)mode; (void)writable;
    return -1;
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define CHECK_STR(actual, expected) do { g_checks++; const char *a_ = (actual); const char *e_ = (expected); \
    if (!a_ || strcmp(a_, e_) != 0) { g_failed++; printf("  [FAIL] %s:%d: %s\n    expected:\n%s\n    got:\n%s\n", \
        __FILE__, __LINE__, #actual, e_, a_ ? a_ : "(null)"); } } while (0)
#define CHECK_HAS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || !strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%s\" lacks \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)
#define CHECK_LACKS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%s\" has \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)

static const char *g_tests_dir = "tests";

/* ------------------------------------------------------------------ helpers */
typedef struct { char *p; size_t len, cap; int calls, fail_at; } sinkbuf_t;

static int sink_collect(void *ud, const char *d, size_t n) {
    sinkbuf_t *s = ud;
    s->calls++;
    if (s->fail_at && s->calls >= s->fail_at) return -1;
    if (s->len + n + 1 > s->cap) {
        s->cap = (s->len + n + 1) * 2;
        s->p = realloc(s->p, s->cap);
    }
    memcpy(s->p + s->len, d, n);
    s->len += n;
    s->p[s->len] = '\0';
    return 0;
}

/* the text of a zone; NULL (and err) when the writer fails.  Caller frees. */
static char *write_text(const zone_arena_t *a, const char *apex, dzt_format_t fmt, bool no_verify, char *err, size_t errlen) {
    sinkbuf_t s = { 0 };
    dzt_opts_t o = { fmt, no_verify };
    err[0] = '\0';
    if (!dns_zone_text_write(a, apex, &o, sink_collect, &s, err, errlen)) {
        free(s.p);
        return NULL;
    }
    if (!s.p) s.p = strdup("");
    return s.p;
}

static bool parse_bind(const char *text, zone_arena_t *a, char *err, size_t errlen) {
    zone_arena_init(a);
    char *buf = strdup(text);
    if (!buf || zone_arena_add_file(a, buf, strdup(text), strdup("test")) != 0) {
        snprintf(err, errlen, "out of memory");
        return false;
    }
    parse_error_t perr;
    memset(&perr, 0, sizeof(perr));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = ".";
    ctx.err_out = &perr;
    int rc = parse_zone_fast(buf, strlen(buf), a, &ctx);
    if (rc < 0) snprintf(err, errlen, "%s", perr.error_message ? perr.error_message : "parse error");
    return rc >= 0;
}

static bool parse_tdns(const char *text, const char *apex, zone_arena_t *a, char *err, size_t errlen) {
    zone_arena_init(a);
    char *buf = strdup(text);
    if (!buf || zone_arena_add_file(a, buf, strdup(text), strdup("test")) != 0) {
        snprintf(err, errlen, "out of memory");
        return false;
    }
    parse_error_t perr;
    memset(&perr, 0, sizeof(perr));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = apex;
    ctx.err_out = &perr;
    ctx.source_mtime = 1700000000;
    int rc = parse_tinydns_data(buf, strlen(buf), a, &ctx);
    if (rc < 0) snprintf(err, errlen, "%s", perr.error_message ? perr.error_message : "parse error");
    return rc >= 0;
}

static size_t count_char(const char *s, char c) {
    size_t n = 0;
    for (; *s; s++) n += *s == c;
    return n;
}

static void reverse_records(zone_arena_t *a) {
    for (size_t i = 0, j = a->count; i + 1 < j; i++, j--) {
        dns_record_t t = a->records[i];
        a->records[i] = a->records[j - 1];
        a->records[j - 1] = t;
    }
}

/* text -> parse -> write -> parse: the same zone; the file does not depend on the order of the records, nor on streaming.  Returns the
 * file (caller frees) or NULL. */
static char *roundtrip(const char *label, const char *text, const char *apex, dzt_format_t fmt) {
    char err[600], why[400];
    zone_arena_t a, b;
    if (!parse_bind(text, &a, err, sizeof(err))) {
        CHECK_MSG(false, "%s: the test zone does not parse: %s", label, err);
        zone_arena_destroy(&a);
        return NULL;
    }
    char *w1 = write_text(&a, apex, fmt, false, err, sizeof(err));
    CHECK_MSG(w1 != NULL, "%s: write: %s", label, err);
    if (!w1) {
        zone_arena_destroy(&a);
        return NULL;
    }
    if (parse_bind(w1, &b, err, sizeof(err))) {
        CHECK_MSG(dns_zone_text_same_zone(&a, &b, why, sizeof(why)), "%s: read back: %s\n%s", label, why, w1);
        char *w2 = write_text(&b, apex, fmt, false, err, sizeof(err));
        CHECK_MSG(w2 && strcmp(w1, w2) == 0, "%s: a second round gives another file", label);
        free(w2);
    } else {
        CHECK_MSG(false, "%s: the file does not parse: %s\n%s", label, err, w1);
    }
    zone_arena_destroy(&b);
    char *w3 = write_text(&a, apex, fmt, true, err, sizeof(err));
    CHECK_MSG(w3 && strcmp(w1, w3) == 0, "%s: streaming gives other bytes", label);
    free(w3);
    reverse_records(&a);
    char *w4 = write_text(&a, apex, fmt, false, err, sizeof(err));
    CHECK_MSG(w4 && strcmp(w1, w4) == 0, "%s: the file depends on the order of the records", label);
    free(w4);
    zone_arena_destroy(&a);
    return w1;
}

/* ------------------------------------------------------------------ 1. every RR type */
typedef struct { const char *type, *rdata; } sample_t;

#define B64 "AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o"
#define HEX32 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static const sample_t k_samples[] = {
    { "A", "192.0.2.1" },
    { "NS", "ns1" },
    { "MD", "md.example.net." },
    { "MF", "mf" },
    { "CNAME", "www" },
    { "SOA", "ns1 hostmaster.example.org. 2024010101 1h 30m 1w 5m" },
    { "MB", "mb" },
    { "MG", "mg.example.test." },
    { "MR", "mr" },
    { "NULL", "\\# 2 dead" },
    { "WKS", "192.0.2.1 TCP 25 80" },
    { "PTR", "host.example.net." },
    { "HINFO", "\"x86\" \"lin;ux\"" },
    { "MINFO", "rm em.example.net." },
    { "MX", "10 mail" },
    { "MX", "0 ." },
    { "TXT", "\"hello world\" \"a;b\" \"q\\\"uote\" \"back\\\\slash\" \"(x)\" \"\" \"ctl\\001\\010x\" \"high\\200\\255\"" },
    { "RP", "admin txt.example.net." },
    { "AFSDB", "1 afs" },
    { "X25", "\"311061700956\"" },
    { "ISDN", "\"150862028003217\" \"004\"" },
    { "RT", "10 rt" },
    { "NSAP", "0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00" },
    { "NSAP-PTR", "nsap" },
    { "SIG", "A 8 0 300 20300101000000 20200101000000 12345 example.test. " B64 },
    { "KEY", "256 3 8 " B64 },
    { "PX", "10 map822 mapx400.example.net." },
    { "GPOS", "-32.882333 116.8 10.0" },
    { "AAAA", "2001:db8::1" },
    { "LOC", "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m" },
    { "NXT", "next A MX" },
    { "EID", "0102 0304 05" },
    { "NIMLOC", "0A0b0c" },
    { "SRV", "1 2 5060 sip" },
    { "ATMA", "+61.2.1234.5678" },
    { "NAPTR", "100 10 \"S\" \"SIP+D2U\" \"!^.*$!sip:x@example.test!\" _sip._udp" },
    { "KX", "10 kx" },
    { "CERT", "1 2 3 " B64 },
    { "A6", "64 ::1:2:3:4 pfx" },
    { "DNAME", "target" },
    { "SINK", "1 2 3 " B64 },
    { "APL", "1:192.0.2.0/24 !2:2001:db8::/32" },
    { "DS", "12345 8 2 " HEX32 },
    { "SSHFP", "1 1 123456789abcdef67890123456789abcdef67890" },
    { "IPSECKEY", "10 3 2 gw " B64 },
    { "IPSECKEY", "10 1 2 192.0.2.38 " B64 },
    { "RRSIG", "A 8 3 300 20300101000000 20200101000000 12345 example.test. AwEAAcvPyrbeMXE2CxVF Jhnp JAWoJJJMiqpbRVvIgN0o" },
    { "NSEC", "next A RRSIG NSEC" },
    { "RRSIG", "A 8 3 300 20300101000000 20200101000000 12345 example.test " B64 },
    { "DNSKEY", "257 3 8 " B64 },
    { "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=" },
    { "NSEC3", "1 0 5 AABB 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG" },
    { "NSEC3PARAM", "1 0 5 AABB" },
    { "TLSA", "3 1 1 " HEX32 },
    { "SMIMEA", "3 1 1 " HEX32 },
    { "HIP", "2 200100107B1A74DF365639CC39F1D578 " B64 " rvs.example.net." },
    { "NINFO", "\"zs\"" },
    { "RKEY", "0 3 5 " B64 },
    { "TALINK", "prev next.example.net." },
    { "CDS", "12345 8 2 " HEX32 },
    { "CDNSKEY", "257 3 8 " B64 },
    { "OPENPGPKEY", B64 },
    { "CSYNC", "66 3 A NS AAAA" },
    { "ZONEMD", "2018031900 1 1 62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637493daaf401c92c279dd10f0edb1c56f8080211f8480ee306" },
    { "SVCB", "1 svc alpn=\"h2,h3\" port=8443" },
    { "SVCB", "0 ." },
    { "HTTPS", "1 . alpn=h2" },
    { "HTTPS", "1 www.example.test. alpn=h2" },
    { "DSYNC", "CDS NOTIFY 5359 target.example.net." },
    { "HHIT", B64 },
    { "BRID", B64 },
    { "SPF", "\"v=spf1 -all\"" },
    { "UINFO", "\\# 5 616c696365" },
    { "UID", "\\# 4 000003E8" },
    { "GID", "\\# 4 000003E9" },
    { "UNSPEC", "\\# 2 0102" },
    { "NID", "10 2001:db8:1:2" },
    { "L32", "10 192.0.2.1" },
    { "L64", "10 2001:db8:1:2" },
    { "LP", "10 l" },
    { "EUI48", "00-00-5e-00-53-2a" },
    { "EUI64", "00-00-5e-ef-10-00-00-2a" },
    { "URI", "10 1 \"https://example.test/\"" },
    { "CAA", "0 issue \"ca.test\"" },
    { "AVC", "\"app=1\"" },
    { "DOA", "1 2 3 \"text/plain\" " B64 },
    { "AMTRELAY", "10 0 3 relay" },
    { "AMTRELAY", "10 0 1 192.0.2.5" },
    { "RESINFO", "\"qnamemin\" \"exterr=15-17\"" },
    { "WALLET", "\"btc\" \"bc1qexample\"" },
    { "TA", "12345 8 2 " HEX32 },
    { "DLV", "12345 8 2 " HEX32 },
    { "TYPE65534", "\\# 3 010203" },
    { "TYPE1234", "\\# 0" },
    { "ALIAS", "target.example.net." },
    { "LUA", "A \"return '192.0.2.1'\"" },
};

static const char k_head[] = "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ NS ns1\nns1 A 192.0.2.1\n";

static bool sample_listed(const char *name) {
    for (size_t i = 0; i < sizeof(k_samples) / sizeof(k_samples[0]); i++)
        if (strcasecmp(k_samples[i].type, name) == 0) return true;
    return false;
}

static void test_every_type(void) {
    printf("every RR type the parser knows\n");
    for (size_t i = 0; i < sizeof(k_samples) / sizeof(k_samples[0]); i++) {
        const sample_t *s = &k_samples[i];
        char zone[4096], label[100];
        snprintf(label, sizeof(label), "%s %.40s", s->type, s->rdata);
        if (strcmp(s->type, "SOA") == 0) snprintf(zone, sizeof(zone), "$ORIGIN example.test.\n$TTL 300\n@ SOA %s\n@ NS ns1\n", s->rdata);
        else snprintf(zone, sizeof(zone), "%st 7200 IN %s %s\n", k_head, s->type, s->rdata);
        char *w = roundtrip(label, zone, "example.test.", DZT_AUTO);
        if (!w) continue;
        if (strcmp(s->type, "SOA") != 0) {
            char want[200];
            snprintf(want, sizeof(want), "\nt 7200 %s ", strcmp(s->type, "ALIAS") == 0 ? "TYPE65401" : strcmp(s->type, "LUA") == 0 ? "TYPE65402" : s->type);
            if (strcasecmp(s->type, "EID") != 0 && strcasecmp(s->type, "NIMLOC") != 0) CHECK_HAS(w, want);
        }
        /* NSAP is written with its "0x" (RFC 1706 section 5; BIND refuses the bare digits), 0.6.2 */
        if (strcmp(s->type, "NSAP") == 0) CHECK_HAS(w, " NSAP 0x47000580005a0000000001e133ffffff00016100\n");
        free(w);
    }
    /* every type with a name is in the table (meta types cannot be zone data) */
    int missing = 0;
    for (unsigned c = 1; c <= 33000; c++) {
        const char *n = dns_type_to_string((uint16_t)c);
        if (strncmp(n, "TYPE", 4) == 0 || get_type_code(n) != c || is_meta_rrtype((uint16_t)c)) continue;
        if (!sample_listed(n)) {
            printf("  [FAIL] type %s (%u) has no sample\n", n, c);
            missing++;
        }
    }
    CHECK(missing == 0);
}

/* ------------------------------------------------------------------ 2. the BIND format byte for byte */
static void test_format(void) {
    printf("BIND format\n");
    const char *in =
        "$ORIGIN example.test.\n$TTL 300\n"
        "@ 3600 SOA ns1 hostmaster.example.org. 2024010101 7200 3600 1209600 300\n"
        "@ NS ns1\n@ NS ns2.example.org.\n@ MX 10 mail\n@ TXT \"v=spf1 -all\"\n"
        "ns1 A 192.0.2.1\nns1 AAAA 2001:db8::1\nmail A 192.0.2.2\nwww CNAME ns1.example.test.\n"
        "*.wild A 192.0.2.9\n"
        "a\\.b A 192.0.2.3\nsp\\032ace A 192.0.2.4\nx.y.z A 192.0.2.5\n"
        "\\;semi\\(paren\\)\\$dollar\\@at\\\"quote TXT \"a\\\"b\" \"c\\\\d\" \"e\\010f\" \"\\200\"\n"
        "other.example.net. 60 A 192.0.2.6\n"
        "EXAMPLE.test. 300 TXT \"upper owner\"\n"
        "Mixed.Example.Test. 300 A 192.0.2.7\n"
        "srv SRV 1 2 5060 sip.example.test.\nsip A 192.0.2.8\n"
        "ch 300 CH TXT \"in the CH class\"\n";
    char err[400];
    zone_arena_t a;
    CHECK(parse_bind(in, &a, err, sizeof(err)) == false);        /* a zone has one class: the CH record is refused */
    zone_arena_destroy(&a);
    in = "$ORIGIN example.test.\n$TTL 300\n"
         "@ 3600 SOA ns1 hostmaster.example.org. 2024010101 7200 3600 1209600 300\n"
         "@ NS ns1\n@ NS ns2.example.org.\n@ MX 10 mail\n@ TXT \"v=spf1 -all\"\n"
         "ns1 A 192.0.2.1\nns1 AAAA 2001:db8::1\nmail A 192.0.2.2\nwww CNAME ns1.example.test.\n"
         "*.wild A 192.0.2.9\n"
         "a\\.b A 192.0.2.3\nsp\\032ace A 192.0.2.4\nx.y.z A 192.0.2.5\n"
         "\\;semi\\(paren\\)\\$dollar\\@at\\\"quote TXT \"a\\\"b\" \"c\\\\d\" \"e\\010f\" \"\\200\"\n"
         "other.example.net. 60 A 192.0.2.6\n"
         "EXAMPLE.test. 300 TXT \"upper owner\"\n"
         "Mixed.Example.Test. 300 A 192.0.2.7\n"
         "srv SRV 1 2 5060 sip.example.test.\nsip A 192.0.2.8\n";
    char *w = roundtrip("format", in, "example.test.", DZT_BIND);
    const char *want =
        "$ORIGIN example.test.\n$TTL 300\n"
        "other.example.net. 60 A 192.0.2.6\n"                    /* net sorts before test (RFC 4034 section 6.1) */
        "@ NS ns1\n"                                              /* type 2 before 6 */
        "@ NS ns2.example.org.\n"
        "@ 3600 SOA ns1 hostmaster.example.org. 2024010101 7200 3600 1209600 300\n"
        "@ MX 10 mail\n"
        "EXAMPLE.test. TXT \"upper owner\"\n"                     /* the same name, another spelling: not the exact suffix, so absolute */
        "@ TXT \"v=spf1 -all\"\n"
        "\\;semi\\(paren\\)\\$dollar\\@at\\\"quote TXT \"a\\\"b\" \"c\\\\d\" \"e\\010f\" \"\\200\"\n"
        "a\\.b A 192.0.2.3\n"
        "mail A 192.0.2.2\n"
        "Mixed.Example.Test. A 192.0.2.7\n"
        "ns1 A 192.0.2.1\n"
        "ns1 AAAA 2001:db8::1\n"
        "sip A 192.0.2.8\n"
        "sp\\032ace A 192.0.2.4\n"
        "srv SRV 1 2 5060 sip\n"
        "*.wild A 192.0.2.9\n"
        "www CNAME ns1\n"
        "x.y.z A 192.0.2.5\n";
    if (w) CHECK_STR(w, want);
    free(w);
}

/* the file for a zone written under another apex notation, the root zone, and a zone with nothing in it */
static void test_apex(void) {
    printf("apex forms\n");
    const char *in = "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n";
    char *w1 = roundtrip("apex with dot", in, "example.test.", DZT_BIND);
    char *w2 = roundtrip("apex without dot", in, "example.test", DZT_BIND);
    CHECK(w1 && w2 && strcmp(w1, w2) == 0);
    free(w1);
    free(w2);
    /* the root zone: nothing is relative, "@" is the root */
    char *w = roundtrip("root", "$ORIGIN .\n$TTL 300\n. SOA a.root-servers.test. nstld.test. 1 2 3 4 5\n. NS a.root-servers.test.\ntest. NS ns.test.\nns.test. A 192.0.2.1\n", ".", DZT_BIND);
    if (w) {
        CHECK_HAS(w, "$ORIGIN .\n");
        CHECK_HAS(w, "@ SOA a.root-servers.test. nstld.test. 1 2 3 4 5\n");
        CHECK_HAS(w, "test. NS ns.test.\n");
    }
    free(w);
    /* a name that only looks like a suffix of the apex, and an escaped dot in front of it */
    w = roundtrip("suffix", "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nxexample.test. A 192.0.2.1\na\\.example.test. A 192.0.2.2\n@ CNAME xexample.test.\n", "example.test.", DZT_BIND);
    if (w) {
        CHECK_HAS(w, "xexample.test. A 192.0.2.1\n");
        CHECK_HAS(w, "\na\\.example.test. A 192.0.2.2\n");      /* "a.example" is a label of test., not of example.test. */
    }
    free(w);
    /* the names the parser keeps escaped since review fix L4 (IPSECKEY / AMTRELAY gateway of type 3, SVCB / HTTPS target, HIP Rendezvous
     * Servers), outside the apex with an escape from the $ORIGIN (\199) and with an escaped dot: written as names, read back the same
     * (fuzz_zone_text found the IPSECKEY one written as a quoted token, which read back as another name) */
    w = roundtrip("escaped names in the RDATA",
                  "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\n$ORIGIN tes\\199t.\n"
                  "t1 IPSECKEY 10 3 2 gw " B64 "\nt2 AMTRELAY 10 0 3 re\\.lay\nt3 SVCB 1 s\\.vc\nt4 HTTPS 1 svc\n"
                  "t5 HIP 2 200100107B1A74DF365639CC39F1D578 " B64 " rv\\.s rvs2\n",
                  "example.test.", DZT_BIND);
    if (w) {
        CHECK_HAS(w, "IPSECKEY 10 3 2 gw.tes\\199t. ");
        CHECK_HAS(w, "AMTRELAY 10 0 3 re\\.lay.tes\\199t.\n");
        CHECK_HAS(w, "SVCB 1 s\\.vc.tes\\199t.\n");
    }
    free(w);
    /* an empty zone */
    zone_arena_t a;
    char err[300];
    zone_arena_init(&a);
    w = write_text(&a, "example.test.", DZT_BIND, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "%s", err);
    if (w) CHECK_STR(w, "$ORIGIN example.test.\n$TTL 3600\n");
    free(w);
    w = write_text(&a, "example.test.", DZT_TINYDNS, false, err, sizeof(err));
    CHECK_MSG(w != NULL && w[0] == '\0', "an empty data file: %s", err);
    free(w);
    CHECK(write_text(&a, "", DZT_BIND, false, err, sizeof(err)) == NULL);
    CHECK_HAS(err, "zone name");
    CHECK(write_text(&a, "a..b", DZT_BIND, false, err, sizeof(err)) == NULL);
    CHECK(write_text(&a, NULL, DZT_BIND, false, err, sizeof(err)) == NULL);
    zone_arena_destroy(&a);
}

/* the most common TTL is the $TTL, a class other than IN is written, the TTL of an explicit 0 */
static void test_ttl_class(void) {
    printf("TTL and class\n");
    char *w = roundtrip("ttl", "$ORIGIN example.test.\n$TTL 300\n@ 3600 SOA ns1 h 1 2 3 4 5\n@ 60 NS ns1\na 60 A 192.0.2.1\nb 60 A 192.0.2.2\nc 0 A 192.0.2.3\nd 2147483647 A 192.0.2.4\ne 7200 A 192.0.2.5\n", "example.test.", DZT_BIND);
    if (w) {
        CHECK_HAS(w, "$TTL 60\n");
        CHECK_HAS(w, "@ 3600 SOA ");
        CHECK_HAS(w, "\nc 0 A 192.0.2.3\n");
        CHECK_HAS(w, "\nd 2147483647 A 192.0.2.4\n");
        CHECK_HAS(w, "\na A 192.0.2.1\n");
    }
    free(w);
    w = roundtrip("class", "$ORIGIN example.test.\n$TTL 300\n@ CH SOA ns1 h 1 2 3 4 5\n@ CH NS ns1\nx CH TXT \"hi\"\n", "example.test.", DZT_BIND);
    if (w) CHECK_HAS(w, "@ CH SOA ");
    free(w);
    w = roundtrip("class number", "$ORIGIN example.test.\n$TTL 300\n@ CLASS200 SOA ns1 h 1 2 3 4 5\nx CLASS200 TXT \"hi\"\n", "example.test.", DZT_BIND);
    if (w) CHECK_HAS(w, "@ CLASS200 SOA ");
    free(w);
}

/* ------------------------------------------------------------------ 3. tags */
static void test_tags(void) {
    printf("$LOCATION / $ECS-SUBNET tags\n");
    const char *in =
        "$ORIGIN tagz.test.\n$TTL 300\n"
        "@ SOA ns1 hostmaster ( 2026102401 3600 600 86400 300 )\n@ NS ns1\nns1 A 192.0.2.53\n"
        "$LOCATION-TAG lan 127.0.0.2/32 127.0.0.3/32\n$LOCATION-TAG wan 127.0.0.4/32 10.0.0.0/8\n$LOCATION-TAG lo6 ::1/128\n"
        "$ECS-SUBNET-TAG east 198.51.100.0/24 2001:db8:1::/48\n$ECS-SUBNET-TAG west 203.0.113.0/24\n"
        "www A 192.0.2.1\n$LOCATION lan\nwww A 192.0.2.10\nmail A 192.0.2.11\n$LOCATION wan\nwww A 192.0.2.20\nwww AAAA 2001:db8::20\n"
        "$LOCATION none\n$ECS-SUBNET east\ngeo A 192.0.2.30\n$ECS-SUBNET west\ngeo A 192.0.2.40\n$ECS-SUBNET\ngeo A 192.0.2.50\n"
        "$LOCATION lan\n$ECS-SUBNET east\nboth TXT \"lan and east\"\n$LOCATION wan\n$ECS-SUBNET\nboth TXT \"wan only\"\n$LOCATION\nboth TXT \"everybody\"\n";
    char *w = roundtrip("tags", in, "tagz.test.", DZT_BIND);
    if (w) {
        CHECK_HAS(w, "$LOCATION-TAG lan 127.0.0.2/32 127.0.0.3/32\n$LOCATION-TAG wan 127.0.0.4/32 10.0.0.0/8\n$LOCATION-TAG lo6 ::1/128\n"
                     "$ECS-SUBNET-TAG east 198.51.100.0/24 2001:db8:1::/48\n$ECS-SUBNET-TAG west 203.0.113.0/24\n");
        CHECK_HAS(w, "$LOCATION lan\nmail A 192.0.2.11\n");
        CHECK_HAS(w, "$LOCATION wan\n");
        CHECK_HAS(w, "$LOCATION none\n");
        CHECK_HAS(w, "$ECS-SUBNET none\n");
        /* the same as the checked-in zone of the DB tags test */
        char path[600];
        snprintf(path, sizeof(path), "%s/db/tagz.test.zone", g_tests_dir);
        zone_arena_t fa;
        char err[400], apex[DNS_NAME_TEXT_SIZE];
        if (zrows_load_zone_file(path, NULL, &fa, apex, sizeof(apex), err, sizeof(err))) {
            char *w2 = write_text(&fa, apex, DZT_BIND, false, err, sizeof(err));
            CHECK_MSG(w2 != NULL, "%s: %s", path, err);
            free(w2);
            zone_arena_destroy(&fa);
        } else {
            CHECK_MSG(false, "%s: %s", path, err);
        }
    }
    free(w);
    /* the same record with another TTL, tag or ECS tag: they differ in nothing else, the order is still total (untagged first, a lower TTL first) */
    w = roundtrip("same data", "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n"
                               "$LOCATION lan\nwww A 192.0.2.5\n$ECS-SUBNET east\nwww A 192.0.2.5\n$LOCATION none\n$ECS-SUBNET none\n"
                               "www 60 A 192.0.2.5\nwww A 192.0.2.5\n", "example.test.", DZT_BIND);
    if (w) {
        CHECK_HAS(w, "\nwww 60 A 192.0.2.5\nwww A 192.0.2.5\n$LOCATION lan\nwww A 192.0.2.5\n$ECS-SUBNET east\nwww A 192.0.2.5\n");
    }
    free(w);
}

/* ------------------------------------------------------------------ 4. hostile content */
static void hostile_base(zone_arena_t *a) {
    char err[300];
    CHECK(parse_bind("$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nt TXT \"x\"\nc CNAME ns1\n", a, err, sizeof(err)));
}

static void expect_fail(const char *label, const zone_arena_t *a, dzt_format_t fmt, const char *needle) {
    char err[600];
    char *w = write_text(a, "example.test.", fmt, false, err, sizeof(err));
    CHECK_MSG(w == NULL, "%s: the writer accepted it:\n%s", label, w ? w : "");
    if (!w) {
        CHECK_MSG(strstr(err, needle) != NULL, "%s: the message lacks '%s': %s", label, needle, err);
        CHECK_MSG(strstr(err, "record") != NULL || strstr(err, "definition") != NULL || strstr(err, "zone"), "%s: it names nothing: %s", label, err);
    }
    free(w);
}

static void test_hostile(void) {
    printf("hostile content\n");
    char err[600], why[300];
    /* escapes that stand for the bytes the lexer reads as structure: in an owner, in a name, in strings */
    zone_arena_t a, b;
    const char *in = "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n"
         "ev\\010il\\;x\\(y\\)\\$z\\@w\\\"q\\ \\\\ A 192.0.2.7\n"
         "c CNAME ev\\010il\\;x\\(y\\)\\$z\\@w\\\"q\\ \\\\\n"
         "t TXT \"line1\\010$INCLUDE /etc/passwd\" \"semi;colon\" \"paren(\" \")x\" \"quote\\\"s\" \"back\\\\slash\" \"hi\\200\" \"\\013\\013\"\n"
         "n TXT \"nul\\000x\"\n"      /* a NUL octet: the RDATA is kept as the octets, so the writer prints the RFC 3597 form (review low L4) */
         "\\$INCLUDE TXT \"no\"\n\\$ORIGIN TXT \"no\"\n\\;x TXT \"no\"\n";
    char *w = roundtrip("hostile escapes", in, "example.test.", DZT_BIND);
    if (w) {
        /* one line per record, the two header lines, and no other directive or comment */
        CHECK_MSG(count_char(w, '\n') == 2 + 10, "%zu lines", count_char(w, '\n'));
        CHECK_LACKS(w, "\n$INCLUDE");
        CHECK_LACKS(w, "\n$ORIGIN");
        CHECK_LACKS(w, "\n;");
        CHECK_HAS(w, "\\$INCLUDE TXT \"no\"\n");
        CHECK_HAS(w, "\"line1\\010$INCLUDE /etc/passwd\"");
        CHECK(parse_bind(w, &b, err, sizeof(err)));
        CHECK_MSG(b.count == 10, "%zu records", b.count);
        CHECK_HAS(w, "n TXT \\# 6 056e756c0078");
        zone_arena_destroy(&b);
    }
    free(w);

    /* values no parser would make, put in by hand (hostile_base(): 0 SOA, 1 NS, 2 ns1 A, 3 t TXT, 4 c CNAME): a raw newline or a directive
     * in a string is escaped, in a name it is refused */
    hostile_base(&a);
    a.records[3].rdata[0] = "raw\n$INCLUDE /etc/passwd\n; and \"quotes\" ( ) \\ done"; a.records[3].is_cached = false;
    w = write_text(&a, "example.test.", DZT_BIND, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "a string with raw control characters: %s", err);
    if (w) {
        CHECK_MSG(count_char(w, '\n') == 2 + 5, "%zu lines", count_char(w, '\n'));
        CHECK_LACKS(w, "\n$INCLUDE");
        CHECK(parse_bind(w, &b, err, sizeof(err)));
        CHECK(dns_zone_text_same_zone(&a, &b, why, sizeof(why)));
        zone_arena_destroy(&b);
    }
    free(w);
    a.records[3].rdata[0] = "x"; a.records[3].is_cached = false;
    a.records[2].name = "evil\n$INCLUDE /etc/passwd\nx.example.test.";
    expect_fail("owner with a newline", &a, DZT_BIND, "record 3");
    a.records[2].name = "ns1.example.test.";
    a.records[4].rdata[0] = "x\n$INCLUDE y.example.test."; a.records[4].is_cached = false;
    expect_fail("name with a newline", &a, DZT_BIND, "record 5");
    a.records[4].rdata[0] = "ns1.example.test."; a.records[4].is_cached = false;
    a.records[2].name = "a b.example.test.";
    expect_fail("owner with a blank", &a, DZT_BIND, "record 3");
    a.records[2].name = "ns1.example.test.";
    a.records[2].rdata[0] = "192.0.2.1 ; 198.51.100.1"; a.records[2].is_cached = false;
    expect_fail("an address that is not one", &a, DZT_BIND, "record 3");
    a.records[2].rdata[0] = "192.0.2.1"; a.records[2].is_cached = false;
    a.records[3].rdata[0] = NULL; a.records[3].is_cached = false;
    expect_fail("a missing field", &a, DZT_BIND, "record 4");
    a.records[3].rdata[0] = "x"; a.records[3].is_cached = false;
    a.records[3].rdata_count = 0;
    expect_fail("no RDATA", &a, DZT_BIND, "record 4");
    a.records[3].rdata_count = 1;
    zone_arena_destroy(&a);

    /* tags: a name the lexer would split or end the line at */
    static const char *bad_tags[] = { "x y", "x;y", "x\ny", "ev\"il", "a(b", "a\\b", "none", "DEFAULT", "", "0123456789012345678901234567890123456789012345678901234567890123" };
    for (size_t i = 0; i < sizeof(bad_tags) / sizeof(bad_tags[0]); i++) {
        hostile_base(&a);
        a.records[2].bind_location_tag = (char *)bad_tags[i];
        expect_fail("location tag", &a, DZT_BIND, "tag");
        a.records[2].bind_location_tag = NULL;
        a.records[2].ecs_subnet_tag = (char *)bad_tags[i];
        expect_fail("ecs tag", &a, DZT_BIND, "tag");
        zone_arena_destroy(&a);
    }
    hostile_base(&a);
    a.records[2].bind_location_tag = "ok-tag_1.2";
    a.records[2].ecs_subnet_tag = "ECS:tag";
    w = write_text(&a, "example.test.", DZT_BIND, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "%s", err);
    if (w) CHECK_HAS(w, "c CNAME ns1\n$LOCATION ok-tag_1.2\n$ECS-SUBNET ECS:tag\nns1 A 192.0.2.1\n$LOCATION none\n$ECS-SUBNET none\nt TXT \"x\"\n");
    free(w);
    a.records[2].bind_location_tag = NULL;
    a.records[2].ecs_subnet_tag = NULL;
    /* tag definitions */
    ecs_cidr_entry_t cd[2];
    memset(cd, 0, sizeof(cd));
    cd[0].cidr = "10.0.0.0/8";
    cd[1].cidr = "10.0.0.0/8; $INCLUDE x";
    ecs_tag_def_t def = { "lan", cd, 1 };
    a.bind_location_tags = &def;
    a.bind_location_tag_count = 1;
    w = write_text(&a, "example.test.", DZT_BIND, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "%s", err);
    if (w) CHECK_HAS(w, "$LOCATION-TAG lan 10.0.0.0/8\n");
    free(w);
    def.cidr_count = 2;
    expect_fail("a CIDR with a directive", &a, DZT_BIND, "CIDR 2");
    def.cidr_count = 0;
    expect_fail("a definition without a CIDR", &a, DZT_BIND, "definition 1");
    def.cidr_count = 1;
    def.tag = "bad tag";
    expect_fail("a bad definition name", &a, DZT_BIND, "definition 1");
    a.bind_location_tags = NULL;
    a.bind_location_tag_count = 0;
    a.bind_ecs_tags = &def;
    a.bind_ecs_tag_count = 1;
    expect_fail("a bad ECS definition name", &a, DZT_BIND, "$ECS-SUBNET-TAG");
    a.bind_ecs_tags = NULL;
    a.bind_ecs_tag_count = 0;
    /* a record the encoder refuses is a failure that names it, not a file with a hole */
    a.records[2].rdata[0] = "not-an-address"; a.records[2].is_cached = false;
    expect_fail("unencodable RDATA", &a, DZT_BIND, "record 3");
    a.records[2].rdata[0] = "192.0.2.1"; a.records[2].is_cached = false;
    a.records[2].name = NULL;
    expect_fail("no owner", &a, DZT_BIND, "record 3");
    zone_arena_destroy(&a);

    /* without the verification the text is not parsed again (the fuzz harness does that itself) */
    hostile_base(&a);
    w = write_text(&a, "example.test.", DZT_BIND, true, err, sizeof(err));
    CHECK(w != NULL);
    free(w);
    zone_arena_destroy(&a);
}

/* ------------------------------------------------------------------ 5. the tinydns data file */
static const char k_tdns[] =
    "Zt.test:ns1.t.test:hostmaster.t.test:2026110501:3600:600:86400:300:300\n"
    "&t.test::ns1.t.test:300\n"
    "&sub.t.test::ns.other.example.:3600:400000000000000a:l2\n"
    "+ns1.t.test:192.0.2.53:300\n"
    "%l2:127.0.0.2\n%lw:10.0.0.0/8\n%ab:192.0.2.0/24\n%c:203.0.113.7\n"
    "+www.t.test:192.0.2.1:300\n+www.t.test:192.0.2.12:300::l2\n+www.t.test:192.0.2.14:300::lw\n"
    "+cd.t.test:192.0.2.20:0:400000007fffffff\n+cd2.t.test:192.0.2.25:0:400000007fffffff:l2\n"
    "+act.t.test:192.0.2.21:300:400000000000000a\n+both.t.test:192.0.2.23:300:400000000000000a:ab\n"
    "+a\\056b.t.test:192.0.2.30:300::l2\n"
    "+dup.t.test:192.0.2.77:300\n+dup.t.test:192.0.2.77:300::l2\n+dup.t.test:192.0.2.77:300:400000000000000a\n"
    "@t.test::mail.t.test:10:300\n+mail.t.test:192.0.2.60:300\n"
    "'txt.t.test:v=spf1 -all\\072 \\134 end:300\n"
    "'long.t.test:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:300\n"
    "'empty.t.test::300\n"
    "Cc.t.test:www.t.test:300\n^ptr.t.test:host.example.:300\n"
    "3ip6.t.test:20010db8000000000000000000000001:300\n"
    ":gen.t.test:65280:\\001\\002\\072colon:300:400000000000000a:ab\n"
    "Ssrv.t.test:192.0.2.9:sip.t.test:5060:1:10:300\n"
    "Nnaptr.t.test:100:10:s:SIP+D2U:!^.*$!sip\\072x!:.:300\n"
    "_ssh.t.test:1:1:123456789abcdef0:300\n";

static void test_tinydns(void) {
    printf("tinydns data file\n");
    char err[600], why[300];
    zone_arena_t a, b;
    if (!parse_tdns(k_tdns, "t.test.", &a, err, sizeof(err))) {
        CHECK_MSG(false, "the data file does not parse: %s", err);
        zone_arena_destroy(&a);
        return;
    }
    CHECK(a.is_tinydns_format && a.location_count == 4);
    char *w = write_text(&a, "t.test.", DZT_AUTO, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "%s", err);
    if (w) {
        CHECK(parse_tdns(w, "t.test.", &b, err, sizeof(err)));
        CHECK_MSG(dns_zone_text_same_zone(&a, &b, why, sizeof(why)), "read back: %s\n%s", why, w);
        CHECK(b.is_tinydns_format && b.location_count == 4);
        char *w2 = write_text(&b, "t.test.", DZT_TINYDNS, false, err, sizeof(err));
        CHECK_MSG(w2 && strcmp(w, w2) == 0, "a second round gives another file");
        free(w2);
        zone_arena_destroy(&b);
        /* what the lines look like */
        CHECK_HAS(w, "%l2:127.0.0.2/32\n%lw:10.0.0.0/8\n%ab:192.0.2.0/24\n%c:203.0.113.7/32\n");
        CHECK_HAS(w, "Zt.test.:ns1.t.test.:hostmaster.t.test.:2026110501:3600:600:86400:300:300::\n");
        CHECK_HAS(w, "+www.t.test.:192.0.2.12:300::l2\n");
        CHECK_HAS(w, "+cd.t.test.:192.0.2.20:0:400000007fffffff:\n");
        CHECK_HAS(w, "+both.t.test.:192.0.2.23:300:400000000000000a:ab\n");
        CHECK_HAS(w, "+a\\056b.t.test.:192.0.2.30:300::l2\n");
        CHECK_HAS(w, "&sub.t.test.::ns.other.example.:3600:400000000000000a:l2\n");
        CHECK_HAS(w, "@t.test.::mail.t.test.:10:300::\n");
        CHECK_HAS(w, "'txt.t.test.:v=spf1\\040-all\\072\\040\\134\\040end:300::\n");
        CHECK_HAS(w, "3ip6.t.test.:20010db8000000000000000000000001:300::\n");
        CHECK_HAS(w, "^ptr.t.test.:host.example.:300::\n");
        CHECK_HAS(w, "Cc.t.test.:www.t.test.:300::\n");
        CHECK_HAS(w, ":srv.t.test.:33:");              /* SRV, NAPTR and SSHFP are generic lines */
        CHECK_HAS(w, ":gen.t.test.:65280:\\001\\002\\072colon:300:400000000000000a:ab\n");
        CHECK_MSG(count_char(w, '\n') == 4 + 28, "%zu lines", count_char(w, '\n'));
    }
    free(w);
    /* the data file zone in the BIND format: refused for its location definitions, and for the first record with an attribute */
    expect_fail("locations in BIND", &a, DZT_BIND, "location definitions");
    free(a.locations);
    a.locations = NULL;
    a.location_count = 0;
    expect_fail("time stamp in BIND", &a, DZT_BIND, "tinydns");
    zone_arena_destroy(&a);
    for (const char *line = "+x.t.test:192.0.2.1:300:400000000000000a\n"; line; line = NULL) {
        char text[300];
        snprintf(text, sizeof(text), "Zt.test:ns1.t.test:h.t.test:1:2:3:4:5:6\n%s", line);
        CHECK(parse_tdns(text, "t.test.", &a, err, sizeof(err)));
        expect_fail("time stamp in BIND", &a, DZT_BIND, "record 2");
        zone_arena_destroy(&a);
    }
    for (const char *line = "+x.t.test:192.0.2.1:300::l2\n"; line; line = NULL) {
        char text[300];
        snprintf(text, sizeof(text), "Zt.test:ns1.t.test:h.t.test:1:2:3:4:5:6\n%s", line);
        CHECK(parse_tdns(text, "t.test.", &a, err, sizeof(err)));
        expect_fail("location code in BIND", &a, DZT_BIND, "record 2");
        zone_arena_destroy(&a);
    }
    /* a data file zone without attributes can be written in the BIND format */
    CHECK(parse_tdns("Zt.test:ns1.t.test:h.t.test:1:2:3:4:5:6\n&t.test::ns1.t.test:300\n+ns1.t.test:192.0.2.53:300\n", "t.test.", &a, err, sizeof(err)));
    w = write_text(&a, "t.test.", DZT_BIND, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "%s", err);
    if (w) CHECK_HAS(w, "\nns1 A 192.0.2.53\n");
    free(w);
    w = write_text(&a, "t.test.", DZT_AUTO, false, err, sizeof(err));
    CHECK(w != NULL && w[0] == '&');
    free(w);
    zone_arena_destroy(&a);

    /* a zone of the BIND parser written as a data file: TXT strings that are not what the data file makes of the text, and the other
     * types, are generic lines; what cannot be written is refused */
    const char *in = "$ORIGIN t.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nt TXT \"a\" \"b\"\nu TXT \"\"\nv TXT \"x\"\n"
         "s SRV 1 2 5060 ns1\nm MX 10 ns1\nn NAPTR 1 2 \"s\" \"x\" \"\" ns1\nss SSHFP 1 1 aabb\nh HINFO \"a\" \"b c\"\n"
         "w TXT \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n"
         "x A \\# 4 c0000201\nl 7 AAAA 2001:db8::1\n";
    CHECK_MSG(parse_bind(in, &a, err, sizeof(err)), "%s", err);
    w = write_text(&a, "t.test.", DZT_TINYDNS, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "%s", err);
    if (w) {
        CHECK_HAS(w, ":t.t.test.:16:\\001a\\001b:300::\n");
        CHECK_HAS(w, "'u.t.test.::300::\n");
        CHECK_HAS(w, "'v.t.test.:x:300::\n");
    }
    free(w);
    zone_arena_destroy(&a);
}

/* ------------------------------------------------------------------ 6. loaders and database zones */
static char g_dir[512];

static bool tool(const char *name) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "command -v %s >/dev/null 2>&1", name);
    return system(cmd) == 0;
}

static void put_file(const char *name, const char *text, char *path, size_t pathlen) {
    snprintf(path, pathlen, "%s/%s", g_dir, name);
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

static void test_loaders(void) {
    printf("zone file and data file loaders (dns_zone_rows.c)\n");
    char err[600], apex[DNS_NAME_TEXT_SIZE], p1[700], p2[700], p3[700];
    zone_arena_t a;
    put_file("main.zone", "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\n$INCLUDE inc.zone\nout.example.net. A 192.0.2.99\n", p1, sizeof(p1));
    put_file("inc.zone", "ns1 A 192.0.2.1\nwww A 192.0.2.2\n", p2, sizeof(p2));
    CHECK_MSG(zrows_load_zone_file(p1, NULL, &a, apex, sizeof(apex), err, sizeof(err)), "%s", err);
    CHECK_STR(apex, "example.test.");
    CHECK_MSG(a.count == 4, "%zu records (the one outside the zone is dropped)", a.count);
    char *w = write_text(&a, apex, DZT_BIND, false, err, sizeof(err));
    CHECK_MSG(w != NULL, "%s", err);
    if (w) CHECK_HAS(w, "www A 192.0.2.2\n");
    free(w);
    zrows_t rows;
    CHECK_MSG(zrows_from_arena(&a, apex, &rows, err, sizeof(err)), "%s", err);
    CHECK(rows.n == 4);
    CHECK_STR(rows.zone, "example.test");
    zrows_free(&rows);
    zone_arena_destroy(&a);
    /* NSAP: the row content is "0x" and the digits (RFC 1706 section 5), 0.6.2; the bare digits of older rows still read */
    put_file("nsap.zone", "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nosi NSAP 0x47.0005.80.005a00\n", p3, sizeof(p3));
    CHECK_MSG(zrows_load_zone_file(p3, NULL, &a, apex, sizeof(apex), err, sizeof(err)), "%s", err);
    CHECK_MSG(zrows_from_arena(&a, apex, &rows, err, sizeof(err)), "%s", err);
    bool nsap_seen = false;
    for (size_t i = 0; i < rows.n; i++)
        if (rows.rows[i].type && strcmp(rows.rows[i].type, "NSAP") == 0) { CHECK_STR(rows.rows[i].content, "0x47000580005a00"); nsap_seen = true; }
    CHECK(nsap_seen);
    zrows_free(&rows);
    zone_arena_destroy(&a);
    CHECK_MSG(zrows_load_zone_file(p1, "example.test.", &a, apex, sizeof(apex), err, sizeof(err)), "%s", err);
    zone_arena_destroy(&a);
    CHECK(!zrows_load_zone_file("/nonexistent/dir/x.zone", NULL, &a, apex, sizeof(apex), err, sizeof(err)));
    CHECK_HAS(err, "cannot read");
    put_file("bad.zone", "$ORIGIN x.test.\n@ SOA ns1 h 1 2 3 4 5\nfoo bar baz\n", p3, sizeof(p3));
    CHECK(!zrows_load_zone_file(p3, NULL, &a, apex, sizeof(apex), err, sizeof(err)));
    put_file("nosoa.zone", "$ORIGIN x.test.\n@ NS ns1\n", p3, sizeof(p3));
    CHECK(!zrows_load_zone_file(p3, NULL, &a, apex, sizeof(apex), err, sizeof(err)));
    CHECK_HAS(err, "no SOA");
    CHECK(!zrows_from_arena(&a, "", &rows, err, sizeof(err)));      /* a bad zone name */

    /* the tinydns data file of the DB tests */
    char tdz[700];
    char **names = NULL;
    int nn = 0;
    snprintf(tdz, sizeof(tdz), "%s/db/tdz.test.data", g_tests_dir);
    CHECK_MSG(zrows_tinydns_apexes(tdz, &names, &nn, err, sizeof(err)), "%s", err);
    CHECK(nn == 1 && names && strcmp(names[0], "tdz.test.") == 0);
    for (int i = 0; i < nn; i++) free(names[i]);
    free(names);
    CHECK_MSG(zrows_load_tinydns_file(tdz, NULL, NULL, 0, &a, apex, sizeof(apex), err, sizeof(err)), "%s", err);
    CHECK_STR(apex, "tdz.test.");
    CHECK(a.is_tinydns_format && a.location_count == 3);
    zone_arena_destroy(&a);
    const char *zones[] = { "tdz.test." };
    CHECK_MSG(zrows_load_tinydns_file(tdz, "tdz.test", zones, 1, &a, apex, sizeof(apex), err, sizeof(err)), "%s", err);
    zone_arena_destroy(&a);
    CHECK(!zrows_tinydns_apexes("/nonexistent/dir/x.data", &names, &nn, err, sizeof(err)));
    CHECK_HAS(err, "cannot read");
    put_file("nosoa.data", "+a.t.test:192.0.2.1:300\n", p3, sizeof(p3));
    CHECK(!zrows_tinydns_apexes(p3, &names, &nn, err, sizeof(err)));
    CHECK_HAS(err, "no SOA");
    CHECK(!zrows_load_tinydns_file(p3, NULL, NULL, 0, &a, apex, sizeof(apex), err, sizeof(err)));
    put_file("two.data", "Za.test:ns.a.test:h.a.test:1:2:3:4:5:6\nZA.test:ns.a.test:h.a.test:1:2:3:4:5:6\nZb.test:ns.b.test:h.b.test:1:2:3:4:5:6\n", p3, sizeof(p3));
    CHECK_MSG(zrows_tinydns_apexes(p3, &names, &nn, err, sizeof(err)), "%s", err);
    CHECK_MSG(nn == 2, "%d apexes (a name once)", nn);
    for (int i = 0; i < nn; i++) free(names[i]);
    free(names);
}

/* a zone file's rows through the reader: the arena the exporter gets from a database zone.  NULL: err says why */
static pdns_zone_t *through_reader(const zone_arena_t *fa, const char *apex, char *err, size_t errlen) {
    zrows_t rows;
    if (!zrows_from_arena((zone_arena_t *)fa, apex, &rows, err, errlen)) return NULL;
    pdns_zone_t *z = pdns_zone_new(rows.zone, NULL);
    db_meta_row_t meta[2];
    size_t nmeta = 0;
    if (rows.presigned) meta[nmeta++] = (db_meta_row_t){ 1, "PRESIGNED", "1" };
    if (rows.nsec3param) meta[nmeta++] = (db_meta_row_t){ 1, "NSEC3PARAM", rows.nsec3param };
    int rc = z ? 0 : -1;
    for (size_t k = 0; rc == 0 && k < rows.n; k++) rc = pdns_zone_add_record(z, &rows.rows[k]);
    for (size_t k = 0; rc == 0 && k < nmeta; k++) rc = pdns_zone_add_meta(z, &meta[k]);
    if (rc == 0) rc = zrows_feed_ext(&rows, z);
    if (rc == 0) rc = pdns_zone_finish(z);
    if (rc != 0) {
        snprintf(err, errlen, "%s", z ? z->error : "out of memory");
        pdns_zone_free(z);
        z = NULL;
    }
    zrows_free(&rows);
    return z;
}

static void test_db_zones(void) {
    printf("zones that come from database rows\n");
    char err[600], why[300], apex[DNS_NAME_TEXT_SIZE], path[700];
    zone_arena_t fa, b;
    /* $LOCATION / $ECS-SUBNET tags */
    snprintf(path, sizeof(path), "%s/db/tagz.test.zone", g_tests_dir);
    if (zrows_load_zone_file(path, NULL, &fa, apex, sizeof(apex), err, sizeof(err))) {
        pdns_zone_t *z = through_reader(&fa, apex, err, sizeof(err));
        CHECK_MSG(z != NULL, "%s", err);
        if (z) {
            CHECK_MSG(dns_zone_text_same_zone(&fa, &z->arena, why, sizeof(why)), "file against rows: %s", why);
            char *w = write_text(&z->arena, apex, DZT_AUTO, false, err, sizeof(err));
            CHECK_MSG(w != NULL, "%s", err);
            if (w) {
                CHECK(parse_bind(w, &b, err, sizeof(err)));
                CHECK_MSG(dns_zone_text_same_zone(&z->arena, &b, why, sizeof(why)), "%s", why);
                zone_arena_destroy(&b);
            }
            free(w);
            pdns_zone_free(z);
        }
        zone_arena_destroy(&fa);
    } else {
        CHECK_MSG(false, "%s: %s", path, err);
    }
    /* a tinydns data file: time stamps, countdown TTLs, location codes and the % lines come back from the rows */
    snprintf(path, sizeof(path), "%s/db/tdz.test.data", g_tests_dir);
    if (zrows_load_tinydns_file(path, NULL, NULL, 0, &fa, apex, sizeof(apex), err, sizeof(err))) {
        pdns_zone_t *z = through_reader(&fa, apex, err, sizeof(err));
        CHECK_MSG(z != NULL, "%s", err);
        if (z) {
            CHECK(z->arena.is_tinydns_format && z->arena.location_count == 3);
            CHECK_MSG(dns_zone_text_same_zone(&fa, &z->arena, why, sizeof(why)), "file against rows: %s", why);
            char *w = write_text(&z->arena, apex, DZT_AUTO, false, err, sizeof(err));
            CHECK_MSG(w != NULL, "%s", err);
            if (w) {
                CHECK(w[0] == '%');
                CHECK(parse_tdns(w, apex, &b, err, sizeof(err)));
                CHECK_MSG(dns_zone_text_same_zone(&fa, &b, why, sizeof(why)), "data file written from the rows against the file: %s", why);
                zone_arena_destroy(&b);
            }
            free(w);
            expect_fail("rows of a data file in BIND", &z->arena, DZT_BIND, "tinydns");
            pdns_zone_free(z);
        }
        zone_arena_destroy(&fa);
    } else {
        CHECK_MSG(false, "%s: %s", path, err);
    }
}

/* a signed zone (NSEC and NSEC3) as the database holds it: rows, reader (which rebuilds NSEC3PARAM / NSEC3 / NSEC), writer.  The file must
 * be the zone the signer made, and BIND's dnssec-verify must accept it: the file alone serves the zone. */
static const char k_signed_zone[] =
    "$ORIGIN %s.\n$TTL 300\n"
    "@ IN SOA ns1 hostmaster 2026101301 3600 600 86400 300\n"
    "@ IN NS ns1\n@ IN NS ns2\n@ IN MX 10 mail\n@ IN TXT \"v=spf1 -all\"\n"
    "ns1 IN A 192.0.2.53\nns1 IN AAAA 2001:db8::53\nns2 IN A 192.0.2.54\n"
    "mail IN A 192.0.2.25\nwww IN A 192.0.2.80\nw2 IN CNAME www\ndn IN DNAME target\ntarget IN A 192.0.2.99\n"
    "*.wild IN A 192.0.2.100\nx.y.z.ent IN A 192.0.2.110\n"
    "sec IN NS ns1.sec\nsec IN DS 12345 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\nns1.sec IN A 192.0.2.131\n"
    "ins IN NS ns1.ins\nns1.ins IN A 192.0.2.141\n";

static void test_signed(const char *z, const char *opts) {
    char cmd[1600], path[700], err[600], why[300], apex[DNS_NAME_TEXT_SIZE];
    snprintf(path, sizeof(path), "%s/%s.zone", g_dir, z);
    FILE *fp = fopen(path, "w");
    CHECK(fp != NULL);
    if (!fp) return;
    fprintf(fp, k_signed_zone, z);
    fclose(fp);
    snprintf(cmd, sizeof(cmd),
             "cd %s && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK %s >/dev/null 2>&1 && dnssec-keygen -q -a ECDSAP256SHA256 %s >/dev/null 2>&1 && "
             "dnssec-signzone -q -S -K . %s -o %s -f %s.signed %s.zone >/dev/null 2>&1",
             g_dir, z, z, opts, z, z, z);
    if (system(cmd) != 0) {
        CHECK_MSG(false, "%s: the signer failed", z);
        return;
    }
    snprintf(path, sizeof(path), "%s/%s.signed", g_dir, z);
    zone_arena_t fa, b;
    if (!zrows_load_zone_file(path, NULL, &fa, apex, sizeof(apex), err, sizeof(err))) {
        CHECK_MSG(false, "%s: %s", path, err);
        return;
    }
    pdns_zone_t *pz = through_reader(&fa, apex, err, sizeof(err));
    CHECK_MSG(pz != NULL, "%s: %s", z, err);
    if (pz) {
        CHECK_MSG(pz->presigned_mode != PS_NONE && pz->n_synth > 0, "%s: the reader rebuilt no chain", z);
        char *w = write_text(&pz->arena, apex, DZT_AUTO, false, err, sizeof(err));
        CHECK_MSG(w != NULL, "%s: %s", z, err);
        if (w) {
            CHECK(parse_bind(w, &b, err, sizeof(err)));
            CHECK_MSG(dns_zone_text_same_zone(&pz->arena, &b, why, sizeof(why)), "%s: %s", z, why);
            CHECK_MSG(dns_zone_text_same_zone(&fa, &b, why, sizeof(why)), "%s: the file against the signer's: %s", z, why);
            zone_arena_destroy(&b);
            CHECK_HAS(w, " NSEC");
            if (tool("dnssec-verify")) {
                snprintf(path, sizeof(path), "%s/%s.out", g_dir, z);
                FILE *o = fopen(path, "w");
                if (o) {
                    fputs(w, o);
                    fclose(o);
                }
                snprintf(cmd, sizeof(cmd), "dnssec-verify -q -o %s %s > %s/%s.verify 2>&1", z, path, g_dir, z);
                CHECK_MSG(system(cmd) == 0, "%s: dnssec-verify refuses the exported file (see %s/%s.verify)", z, g_dir, z);
            } else {
                printf("  [note] %s: dnssec-verify is not installed, the exported file was not verified by BIND\n", z);
            }
        }
        free(w);
        pdns_zone_free(pz);
    }
    zone_arena_destroy(&fa);
}

/* the presigned layout of an NSEC3 Opt-Out zone written by hand (no signer tool needed: the signatures are never checked here): an empty
 * non-terminal below a name two labels deep, an insecure delegation (no DS: no ordername with Opt-Out), a name below it (occluded: auth 0),
 * a secure delegation (DS: hashed), the NSEC3 / NSEC3PARAM rows dropped and turned into metadata */
static const db_record_row_t *find_row(const zrows_t *r, const char *name, const char *type, size_t *idx) {
    for (size_t i = 0; i < r->n; i++) {
        const char *t = r->rows[i].type;
        if (strcmp(r->rows[i].name, name) == 0 && ((!type && !t) || (type && t && strcmp(t, type) == 0))) {
            if (idx) *idx = i;
            return &r->rows[i];
        }
    }
    return NULL;
}

static void test_presigned_rows(void) {
    printf("presigned rows of a hand-written NSEC3 Opt-Out zone (dns_zone_rows.c)\n");
    char err[600];
    zone_arena_t a;
    const char *text =
        "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\n@ NSEC3PARAM 1 0 0 -\nns1 A 192.0.2.1\n"
        "a.b A 192.0.2.2\nsub NS ns.sub\nns.sub A 192.0.2.3\nsec NS ns1\n"
        "sec DS 12345 8 2 0000000000000000000000000000000000000000000000000000000000000000\n"
        "0123456789abcdefghijklmnopqrstuv NSEC3 1 1 0 - 0123456789abcdefghijklmnopqrstuu A RRSIG\n"
        "0123456789abcdefghijklmnopqrstuv RRSIG NSEC3 8 3 300 20300101000000 20200101000000 12345 example.test. AAAA\n";
    CHECK_MSG(parse_bind(text, &a, err, sizeof(err)), "%s", err);
    zrows_t rows;
    if (!zrows_from_arena(&a, "example.test.", &rows, err, sizeof(err))) {
        CHECK_MSG(false, "%s", err);
        zone_arena_destroy(&a);
        return;
    }
    CHECK(rows.presigned);
    CHECK_MSG(rows.nsec3param && strcmp(rows.nsec3param, "1 1 0 -") == 0, "NSEC3PARAM metadata '%s' (flags of the NSEC3 RR)",
              rows.nsec3param ? rows.nsec3param : "(null)");
    CHECK(!find_row(&rows, "example.test", "NSEC3PARAM", NULL));
    CHECK(!find_row(&rows, "0123456789abcdefghijklmnopqrstuv.example.test", "NSEC3", NULL));
    CHECK(find_row(&rows, "0123456789abcdefghijklmnopqrstuv.example.test", "RRSIG", NULL));
    size_t i = 0;
    const db_record_row_t *r = find_row(&rows, "b.example.test", NULL, &i);
    CHECK_MSG(r && r->ordername && strlen(r->ordername) == 32 && rows.auth[i] == 1, "the empty non-terminal b.example.test");
    r = find_row(&rows, "a.b.example.test", "A", &i);
    CHECK(r && r->ordername && rows.auth[i] == 1);
    r = find_row(&rows, "sub.example.test", "NS", &i);
    CHECK_MSG(r && !r->ordername && rows.auth[i] == 0, "the insecure delegation: no ordername (Opt-Out), auth 0");
    r = find_row(&rows, "ns.sub.example.test", "A", &i);
    CHECK_MSG(r && !r->ordername && rows.auth[i] == 0, "below the delegation: occluded, auth 0");
    r = find_row(&rows, "sec.example.test", "NS", &i);
    CHECK_MSG(r && r->ordername && rows.auth[i] == 0, "the secure delegation: hashed, auth 0");
    r = find_row(&rows, "sec.example.test", "DS", &i);
    CHECK(r && r->ordername && rows.auth[i] == 1);
    CHECK(!find_row(&rows, "sub.example.test", NULL, NULL));       /* a delegation point is an owner, not an ENT */
    zrows_free(&rows);
    zone_arena_destroy(&a);
}

static void test_presigned_zones(void) {
    printf("presigned zones (signer tools)\n");
    if (!tool("dnssec-signzone") || !tool("dnssec-keygen")) {
        printf("  [note] dnssec-signzone / dnssec-keygen are not installed: no signed zone is exported here\n");
        return;
    }
    test_signed("zt-nsec.test", "");
    test_signed("zt-n3.test", "-3 AABBCCDD -H 3");
    test_signed("zt-oo.test", "-3 - -H 0 -A");
}

/* ------------------------------------------------------------------ 7. the comparison, the sinks, the field table */
static void test_same_zone(void) {
    printf("dns_zone_text_same_zone, sinks, write_file\n");
    char err[600], why[300];
    zone_arena_t a, b;
    const char *base = "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nwww TXT \"x\"\n";
    CHECK(parse_bind(base, &a, err, sizeof(err)));
    CHECK(parse_bind(base, &b, err, sizeof(err)));
    CHECK_MSG(dns_zone_text_same_zone(&a, &b, why, sizeof(why)), "%s", why);
    zone_arena_destroy(&b);
    static const struct { const char *text, *needle; } diffs[] = {
        { "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n", "records" },
        { "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.2\nwww TXT \"x\"\n", "differs" },
        { "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nwww TXT \"y\"\n", "differs" },
        { "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nwww 301 TXT \"x\"\n", "differs" },
        { "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nWWW TXT \"x\"\n", "differs" },
        { "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n$LOCATION lan\nwww TXT \"x\"\n", "differs" },
        { "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n$ECS-SUBNET e\nwww TXT \"x\"\n", "differs" },
        { "$ORIGIN example.test.\n$TTL 300\n$LOCATION-TAG lan 10.0.0.0/8\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nwww TXT \"x\"\n", "$LOCATION-TAG" },
        { "$ORIGIN example.test.\n$TTL 300\n$ECS-SUBNET-TAG e 10.0.0.0/8\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\nwww TXT \"x\"\n", "$ECS-SUBNET-TAG" },
    };
    for (size_t i = 0; i < sizeof(diffs) / sizeof(diffs[0]); i++) {
        CHECK(parse_bind(diffs[i].text, &b, err, sizeof(err)));
        CHECK_MSG(!dns_zone_text_same_zone(&a, &b, why, sizeof(why)), "difference %zu not seen", i);
        CHECK_MSG(strstr(why, diffs[i].needle) != NULL, "difference %zu: '%s' lacks '%s'", i, why, diffs[i].needle);
        zone_arena_destroy(&b);
    }
    /* the same tag definitions with another CIDR, another tag, another number; the same locations or not */
    const char *d1 = "$ORIGIN example.test.\n$TTL 300\n$LOCATION-TAG lan 10.0.0.0/8\n@ SOA ns1 h 1 2 3 4 5\n";
    const char *d2 = "$ORIGIN example.test.\n$TTL 300\n$LOCATION-TAG lan 10.0.0.0/9\n@ SOA ns1 h 1 2 3 4 5\n";
    const char *d3 = "$ORIGIN example.test.\n$TTL 300\n$LOCATION-TAG wan 10.0.0.0/8\n@ SOA ns1 h 1 2 3 4 5\n";
    const char *d4 = "$ORIGIN example.test.\n$TTL 300\n$LOCATION-TAG lan 10.0.0.0/8 11.0.0.0/8\n@ SOA ns1 h 1 2 3 4 5\n";
    zone_arena_t c;
    CHECK(parse_bind(d1, &c, err, sizeof(err)));
    const char *others[] = { d2, d3, d4 };
    for (size_t i = 0; i < 3; i++) {
        CHECK(parse_bind(others[i], &b, err, sizeof(err)));
        CHECK_MSG(!dns_zone_text_same_zone(&c, &b, why, sizeof(why)), "definition difference %zu not seen", i);
        zone_arena_destroy(&b);
    }
    zone_arena_destroy(&c);
    zone_arena_t t1, t2;
    CHECK(parse_tdns("%l2:127.0.0.2\n+a.t.test:192.0.2.1:300\n", "t.test.", &t1, err, sizeof(err)));
    CHECK(parse_tdns("%l2:127.0.0.3\n+a.t.test:192.0.2.1:300\n", "t.test.", &t2, err, sizeof(err)));
    CHECK(!dns_zone_text_same_zone(&t1, &t2, why, sizeof(why)));
    CHECK_HAS(why, "location");
    zone_arena_destroy(&t2);
    CHECK(parse_tdns("%l2:127.0.0.2\n+a.t.test:192.0.2.1:300::l2\n", "t.test.", &t2, err, sizeof(err)));
    CHECK(!dns_zone_text_same_zone(&t1, &t2, why, sizeof(why)));            /* a location code on the record */
    zone_arena_destroy(&t2);
    CHECK(parse_tdns("%l2:127.0.0.2\n+a.t.test:192.0.2.1:300:400000000000000a\n", "t.test.", &t2, err, sizeof(err)));
    CHECK(!dns_zone_text_same_zone(&t1, &t2, why, sizeof(why)));            /* a time stamp */
    zone_arena_destroy(&t2);
    zone_arena_destroy(&t1);
    /* a record that cannot be encoded makes the comparison fail, not crash */
    CHECK(parse_bind(base, &b, err, sizeof(err)));
    b.records[2].rdata[0] = "nonsense";
    b.records[2].is_cached = false;
    CHECK(!dns_zone_text_same_zone(&a, &b, why, sizeof(why)));
    CHECK_HAS(why, "record 3");
    zone_arena_destroy(&b);

    /* sinks: a failing one stops the write, with and without verification; a file */
    sinkbuf_t s = { 0 };
    dzt_opts_t o = { DZT_AUTO, false };
    s.fail_at = 1;
    CHECK(!dns_zone_text_write(&a, "example.test.", &o, sink_collect, &s, err, sizeof(err)));
    CHECK_HAS(err, "could not be written");
    o.no_verify = true;
    CHECK(!dns_zone_text_write(&a, "example.test.", &o, sink_collect, &s, err, sizeof(err)));
    zone_arena_destroy(&a);
    /* more than DZT_FLUSH_AT bytes are handed over in pieces when the text is not verified, and one failing piece stops the write */
    char *big = malloc(2 << 20), *p;
    CHECK(big != NULL);
    p = big;
    p += sprintf(p, "$ORIGIN example.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\n");
    for (int i = 0; i < 3000; i++) p += sprintf(p, "h%d TXT \"%0100d\"\n", i, i);
    CHECK_MSG(parse_bind(big, &a, err, sizeof(err)), "%s", err);
    free(big);
    memset(&s, 0, sizeof(s));
    CHECK(dns_zone_text_write(&a, "example.test.", &o, sink_collect, &s, err, sizeof(err)));
    CHECK_MSG(s.calls >= 3 && s.len > 300000, "%d pieces, %zu bytes", s.calls, s.len);
    char *whole = write_text(&a, "example.test.", DZT_BIND, false, err, sizeof(err));
    CHECK(whole && s.p && strcmp(whole, s.p) == 0);
    free(whole);
    free(s.p);
    memset(&s, 0, sizeof(s));
    s.fail_at = 2;
    CHECK(!dns_zone_text_write(&a, "example.test.", &o, sink_collect, &s, err, sizeof(err)));
    CHECK_HAS(err, "could not be written");
    free(s.p);
    FILE *tf = tmpfile();
    CHECK(tf != NULL);
    if (tf) {
        CHECK_MSG(dns_zone_text_write_file(&a, "example.test.", NULL, tf, err, sizeof(err)), "%s", err);
        CHECK(ftell(tf) > 300000);
        fclose(tf);
    }
    zone_arena_destroy(&a);
}

/* ---- 8. dns_zone_render.c: stored records as the text a change set takes (karidns-zone render; 0.6.0 item F) ---- */

/* the text of line i of the input, or NULL */
static char *render_one(const char *zone, const char *line, char *err, size_t errlen) {
    zr_result_t *r = NULL;
    size_t n = 0;
    char *out = NULL;
    if (zr_render(zone, line, strlen(line), &r, &n, err, errlen) != 0 || n != 1) return NULL;
    if (r[0].rdata) out = strdup(r[0].rdata);
    else snprintf(err, errlen, "%s", r[0].err);
    zr_free(r, n);
    return out;
}

#define RENDERS(line, want) do { char e_[300] = ""; char *t_ = render_one("example.test", line, e_, sizeof(e_)); \
    CHECK_MSG(t_ != NULL && strcmp(t_, want) == 0, "%s: got \"%s\" (%s)", line, t_ ? t_ : "(none)", e_); free(t_); } while (0)
#define REFUSES(line, needle) do { char e_[300] = ""; char *t_ = render_one("example.test", line, e_, sizeof(e_)); \
    CHECK_MSG(t_ == NULL && strstr(e_, needle) != NULL, "%s: got \"%s\" / \"%s\"", line, t_ ? t_ : "(none)", e_); free(t_); } while (0)

static void test_render(void) {
    /* names absolute, the priority of MX and SRV in front (as the exporter and the diff of `apply` write them) */
    RENDERS("example.test\tMX\t10\tmail.example.test", "10 mail.example.test.");
    RENDERS("example.test\tMX\t-\tmail", "0 mail.");                               /* NULL prio is 0; a name without a dot is relative to the root, as PowerDNS means it */
    RENDERS("example.test\tMX\t0\t10 mail.example.test", "10 mail.example.test.");  /* the preference is in the content and the column says 0: the content stands */
    RENDERS("_sip._tcp.example.test\tSRV\t20\t5 5060 sip.example.test", "20 5 5060 sip.example.test.");
    RENDERS("_sip._tcp.example.test\tsrv\t-\t0 5 5060 sip.example.test", "0 5 5060 sip.example.test.");
    RENDERS("www.example.test\tA\t-\t192.0.2.1", "192.0.2.1");
    RENDERS("osi.example.test\tNSAP\t-\t0x47.0005.80.005a00", "0x47000580005a00");   /* 0.6.2: with its "0x" (RFC 1706 section 5) */
    RENDERS("osi.example.test\tNSAP\t-\t47000580005a00", "0x47000580005a00");        /* the bare digits of rows written before 0.6.2 */
    REFUSES("osi.example.test\tNSAP\t-\t0.x47000580005a00", "NSAP");
    RENDERS("www.example.test\tAAAA\t0\t2001:DB8:0:0::1", "2001:DB8:0:0::1");        /* the text as it was parsed: the zone-file writer does not rewrite an address */
    RENDERS("www.example.test\tCNAME\t-\tTarget.Example.TEST", "Target.Example.TEST.");
    RENDERS("example.test\tNS\t0\tns1.example.test.", "ns1.example.test.");
    RENDERS("example.test\tSOA\t0\tns1.example.test hostmaster.example.test 10 7200 3600 1209600 300", "ns1.example.test. hostmaster.example.test. 10 7200 3600 1209600 300");
    /* strings: quoted, escaped as the zone-file writer does; a TAB is part of the content */
    RENDERS("t.example.test\tTXT\t-\t\"hello\" \"wor ld\"", "\"hello\" \"wor ld\"");
    RENDERS("t.example.test\tTXT\t-\thello", "\"hello\"");
    RENDERS("t.example.test\tTXT\t-\t\"a;b\" \"c\\\"d\"", "\"a;b\" \"c\\\"d\"");
    RENDERS("t.example.test\tTXT\t-\t\"a\tb\"", "\"a\\009b\"");
    RENDERS("example.test\tCAA\t-\t0 issue \"ca.example.test\"", "0 issue \"ca.example.test\"");
    RENDERS("t.example.test\tTYPE65400\t-\t\\# 4 deadbeef", "\\# 4 deadbeef");
    /* the root name is "." (a null MX, RFC 7505; no service, RFC 2782): "@" would be the origin of the zone the line is read for */
    RENDERS("n.example.test\tMX\t-\t0 .", "0 .");
    RENDERS("n.example.test\tSRV\t-\t0 0 0 .", "0 0 0 .");
    RENDERS("n.example.test\tMX\t0\t.", "0 .");
    {
        char e[300] = "";
        char *t = render_one("example.test", "n.example.test\tNAPTR\t-\t100 10 \"\" \"\" \"\" .", e, sizeof(e));
        CHECK_MSG(t != NULL && t[strlen(t) - 1] == '.' && strchr(t, '@') == NULL, "NAPTR: %s", t ? t : e);
        free(t);
    }
    /* the others are refused one by one and say why; the reader's own row id and zone name are not in the message */
    REFUSES("www.example.test\tA\t-\tnot-an-address", "IPv4");
    REFUSES("www.example.test\tALIAS\t-\ttarget.example.test", "shown as stored");
    REFUSES("www.example.test\tlua\t-\tA \"return 1\"", "shown as stored");
    REFUSES("www.example.test\tMX\t7\t10 mail", "ambiguous");
    REFUSES("www.example.test\tMX\t70000\tmail", "outside 0..65535");
    REFUSES("www.example.test\tTXT\t-\ta;b", "comment");
    REFUSES("www.example.test\tTXT\t-\t\"open", "quote");
    REFUSES("www.example.test\tTXT\t-\t$INCLUDE x", "directive");
    REFUSES("www.example.test\tTXT\t-\t(a", "parenthesis");
    REFUSES("www.example.test\tTXT\t-\ta\rb", "line break");
    REFUSES("www.example.test\tTXT\t-\t \t", "empty");
    REFUSES("www.example.test\tTXT\t-\t", "empty");
    REFUSES("www.other.test\tA\t-\t192.0.2.1", "outside the zone");
    REFUSES("www.example.test\tSOA\t-\tns1 h 1 2 3 4 5", "not at the zone apex");
    REFUSES("www.example.test\tbad_type\t-\tx", "type");
    REFUSES("a b.example.test\tA\t-\t192.0.2.1", "owner");
    { char e[300] = ""; char *t = render_one("example.test", "www.example.test\tA\t-\tx", e, sizeof(e)); CHECK(t == NULL); CHECK(strstr(e, "records.id") == NULL && strstr(e, "zone '") == NULL); free(t); }

    /* the whole input: results in the order of the lines, one bad record does not touch the others, the last line needs no LF, nothing is an empty list */
    {
        const char in[] = "a.example.test\tA\t-\t192.0.2.1\nb.example.test\tA\t-\tbad\nc.example.test\tA\t-\t192.0.2.3";
        zr_result_t *r = NULL;
        size_t n = 0;
        char err[200];
        CHECK(zr_render("example.test.", in, sizeof(in) - 1, &r, &n, err, sizeof(err)) == 0 && n == 3);          /* the zone with its final dot */
        CHECK(n == 3 && r[0].rdata && !r[1].rdata && r[2].rdata);
        CHECK(n == 3 && r[1].err[0] != '\0');
        CHECK_STR(n == 3 ? r[2].rdata : NULL, "192.0.2.3");
        zr_free(r, n);
        CHECK(zr_render("example.test", "", 0, &r, &n, err, sizeof(err)) == 0 && n == 0);
        zr_free(r, n);
        zr_free(NULL, 0);
    }
    /* a NUL inside a field: the record is refused (a C string would end there), the input is not */
    {
        const char in[] = "a.example.test\tTXT\t-\tab\0cd\n";
        zr_result_t *r = NULL;
        size_t n = 0;
        char err[200];
        CHECK(zr_render("example.test", in, sizeof(in) - 1, &r, &n, err, sizeof(err)) == 0 && n == 1 && !r[0].rdata);
        CHECK(n == 1 && strstr(r[0].err, "NUL") != NULL);
        zr_free(r, n);
    }
    /* an input that is not in the form is refused as a whole, with the line */
    {
        const char *bad[] = { "only-owner\n", "a\tb\tc\n", "\tA\t-\t1.2.3.4\n", "a.example.test\t\t-\t1\n", "a.example.test\tA\t1x\t1.2.3.4\n", "a.example.test\tA\t\t1.2.3.4\n",
                              "a.example.test\tA\t-\t1.2.3.4\n\n", "a.example.test\tA\t1234567890123456789\t1.2.3.4\n", "a.example.test\tA\t-\t1.2.3.4\nzzz\n" };
        for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
            zr_result_t *r = (zr_result_t *)1;
            size_t n = 7;
            char err[200] = "";
            CHECK_MSG(zr_render("example.test", bad[i], strlen(bad[i]), &r, &n, err, sizeof(err)) == -1 && r == NULL && n == 0 && strstr(err, "line ") != NULL, "bad input %zu: \"%s\"", i, err);
        }
        char err[200] = "";
        zr_result_t *r = NULL;
        size_t n = 0;
        CHECK(zr_render("example.test", "a.example.test\tA\t-\t1.2.3.4\nzzz\n", 32, &r, &n, err, sizeof(err)) == -1 && strstr(err, "line 2") != NULL);
        char *many = malloc(ZR_MAX_RECORDS + 2);
        CHECK(many != NULL);
        if (many) {
            memset(many, '\n', ZR_MAX_RECORDS + 1);
            CHECK(zr_render("example.test", many, ZR_MAX_RECORDS + 1, &r, &n, err, sizeof(err)) == -1 && strstr(err, "more than") != NULL);
            free(many);
        }
    }
    /* a zone that is not a zone: every record is refused with the reader's reason */
    {
        zr_result_t *r = NULL;
        size_t n = 0;
        char err[200];
        CHECK(zr_render("a..b", "a.b\tA\t-\t192.0.2.1\n", 18, &r, &n, err, sizeof(err)) == 0 && n == 1 && !r[0].rdata && r[0].err[0]);
        zr_free(r, n);
    }
    /* what is rendered is a fixed point: the text as the content (the priority is in it now, the column is NULL) renders to itself (the round trip of the GUI) */
    {
        const char *samples[] = {
            "example.test\tMX\t10\tmail.example.test", "_sip._tcp.example.test\tSRV\t1\t2 3 sip.example.test", "t.example.test\tTXT\t-\t\"a\" \"b c\" \"\\\"q\\\"\" \"\\092\"",
            "example.test\tSOA\t-\tns1.example.test hostmaster.example.test 1 2 3 4 5", "example.test\tCAA\t-\t128 issuewild \"x;y\"", "w.example.test\tAAAA\t-\t::ffff:192.0.2.1",
            "w.example.test\tCNAME\t-\ta.b", "w.example.test\tNAPTR\t-\t100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:x@example.test!\" .", "w.example.test\tHINFO\t-\t\"PC\" \"Linux\"",
            "w.example.test\tSSHFP\t-\t4 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", "w.example.test\tTYPE65401\t-\t\\# 3 016100",
            "n.example.test\tMX\t-\t0 .", "n.example.test\tSRV\t-\t0 0 0 .", "n.example.test\tNAPTR\t-\t100 10 \"u\" \"E2U+sip\" \"\" .",
            "example.test\tDNAME\t-\ttarget.example.test", "w.example.test\tTLSA\t-\t3 1 1 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        };
        for (size_t i = 0; i < sizeof(samples) / sizeof(*samples); i++) {
            char e1[300] = "", e2[300] = "", line[2048];
            char *t1 = render_one("example.test", samples[i], e1, sizeof(e1));
            CHECK_MSG(t1 != NULL, "%s: %s", samples[i], e1);
            if (!t1) continue;
            const char *tab1 = strchr(samples[i], '\t');
            const char *tab2 = tab1 ? strchr(tab1 + 1, '\t') : NULL;
            snprintf(line, sizeof(line), "%.*s\t-\t%s", (int)(tab2 - samples[i]), samples[i], t1);
            char *t2 = render_one("example.test", line, e2, sizeof(e2));
            CHECK_MSG(t2 != NULL && strcmp(t1, t2) == 0, "%s: \"%s\" renders to \"%s\" (%s)", samples[i], t1, t2 ? t2 : "(none)", e2);
            free(t1);
            free(t2);
        }
    }
}

static void test_field_table(void) {
    printf("field table\n");
    dns_record_t r;
    memset(&r, 0, sizeof(r));
    char *rd[MAX_RDATA];
    memset(rd, 0, sizeof(rd));
    r.rdata = rd;
    /* names: PowerDNS stores these without the dot; the zone parser expands relative names in all of them */
    r.type_code = 2;
    CHECK(zrows_field_flags(&r, 0) == (ZF_NAME | ZF_EXPAND | ZF_NODOT));
    r.type_code = 15;
    CHECK(zrows_field_flags(&r, 0) == 0 && zrows_field_flags(&r, 1) == (ZF_NAME | ZF_EXPAND | ZF_NODOT));
    r.type_code = 35;
    CHECK(zrows_field_flags(&r, 5) == (ZF_NAME | ZF_EXPAND) && zrows_field_flags(&r, 2) == ZF_STRING);
    r.type_code = 46;
    CHECK(zrows_field_flags(&r, 7) == (ZF_NODOT | ZF_ABS));
    r.type_code = 47;
    CHECK(zrows_field_flags(&r, 0) == ZF_ABS);
    r.type_code = 16;
    CHECK(zrows_field_flags(&r, 0) == ZF_STRING && zrows_field_flags(&r, 40) == ZF_STRING);
    r.type_code = 1;
    CHECK(zrows_field_flags(&r, 0) == 0);
    /* the fields whose meaning depends on another field */
    rd[0] = "64";
    r.type_code = 38;
    CHECK(zrows_field_flags(&r, 2) == (ZF_NAME | ZF_EXPAND));
    rd[0] = "0";
    CHECK(zrows_field_flags(&r, 2) == 0);
    r.type_code = 45;
    rd[1] = "3";
    CHECK(zrows_field_flags(&r, 3) == (ZF_NAME | ZF_EXPAND));
    rd[1] = "1";
    CHECK(zrows_field_flags(&r, 3) == 0);
    r.type_code = 260;
    rd[2] = "3";
    CHECK(zrows_field_flags(&r, 3) == (ZF_NAME | ZF_EXPAND));
    rd[2] = "x";
    CHECK(zrows_field_flags(&r, 3) == 0);
    r.type_code = 65;
    rd[1] = "svc.example.";
    CHECK(zrows_field_flags(&r, 1) == (ZF_NAME | ZF_EXPAND));
    rd[1] = ".";
    CHECK(zrows_field_flags(&r, 1) == 0);
    CHECK(zrows_blob_lead(46) == 8 && zrows_blob_lead(48) == 3 && zrows_blob_lead(49) == 0 && zrows_blob_lead(1) == -1);
}

/* ------------------------------------------------------------------ main */
/* test_zone_text --dump APEX FILE [bind|tinydns]: the file (a BIND zone, or a tinydns data file when it ends in .data) as the writer makes it */
static int dump(const char *apex, const char *path, dzt_format_t fmt) {
    char err[600];
    FILE *f = fopen(path, "rb");
    if (!f) return 2;
    char *text = calloc(1, 1 << 22);
    size_t n = fread(text, 1, (1 << 22) - 1, f);
    fclose(f);
    text[n] = '\0';
    zone_arena_t a;
    size_t pl = strlen(path);
    bool ok = pl > 5 && strcmp(path + pl - 5, ".data") == 0 ? parse_tdns(text, apex, &a, err, sizeof(err)) : parse_bind(text, &a, err, sizeof(err));
    free(text);
    if (!ok) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }
    ok = dns_zone_text_write_file(&a, apex, &(dzt_opts_t){ fmt, false }, stdout, err, sizeof(err));
    if (!ok) fprintf(stderr, "%s\n", err);
    zone_arena_destroy(&a);
    return ok ? 0 : 1;
}

/* test_zone_text --gen-corpus DIR: the seed corpus of fuzz_zone_text (origin fuzz.test.) */
static int gen_corpus(const char *dir) {
    char path[700];
    FILE *f;
    snprintf(path, sizeof(path), "%s/seed_types.zone", dir);
    if (!(f = fopen(path, "w"))) return 2;
    fprintf(f, "$ORIGIN fuzz.test.\n$TTL 300\n");
    fputs("@ SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ NS ns1\nns1 A 192.0.2.1\n", f);
    for (size_t i = 0; i < sizeof(k_samples) / sizeof(k_samples[0]); i++)
        if (strcmp(k_samples[i].type, "SOA") != 0) fprintf(f, "t%zu %zu IN %s %s\n", i, 100 + i, k_samples[i].type, k_samples[i].rdata);
    fclose(f);
    snprintf(path, sizeof(path), "%s/seed_tags.zone", dir);
    if (!(f = fopen(path, "w"))) return 2;
    fputs("$ORIGIN fuzz.test.\n$TTL 300\n@ SOA ns1 hostmaster ( 2026102401 3600 600 86400 300 )\n@ NS ns1\nns1 A 192.0.2.53\n"
          "$LOCATION-TAG lan 127.0.0.2/32 127.0.0.3/32\n$ECS-SUBNET-TAG east 198.51.100.0/24 2001:db8:1::/48\n"
          "www A 192.0.2.1\n$LOCATION lan\nwww A 192.0.2.10\n$ECS-SUBNET east\nwww TXT \"lan and east\"\n$LOCATION none\n$ECS-SUBNET none\nmail A 192.0.2.11\n", f);
    fclose(f);
    snprintf(path, sizeof(path), "%s/seed_hostile.zone", dir);
    if (!(f = fopen(path, "w"))) return 2;
    fputs("$ORIGIN fuzz.test.\n$TTL 300\n@ SOA ns1 h 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n"
          "ev\\010il\\;x\\(y\\)\\$z\\@w\\\"q\\ \\\\ A 192.0.2.7\nc CNAME ev\\010il\\;x\\(y\\)\\$z\\@w\\\"q\\ \\\\\n"
          "t TXT \"line1\\010$INCLUDE /etc/passwd\" \"semi;colon\" \"paren(\" \"quote\\\"s\" \"back\\\\slash\" \"nul\\000x\" \"hi\\200\"\n"
          "\\$INCLUDE TXT \"no\"\n\\;x TXT \"no\"\n", f);
    fclose(f);
    snprintf(path, sizeof(path), "%s/seed_tinydns.data", dir);
    if (!(f = fopen(path, "w"))) return 2;
    for (const char *p = k_tdns; *p;) {
        if (strncmp(p, "t.test", 6) == 0) {
            fputs("fuzz.test", f);
            p += 6;
        } else {
            fputc(*p++, f);
        }
    }
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "--gen-corpus") == 0) return gen_corpus(argv[2]);
    if (argc > 3 && strcmp(argv[1], "--dump") == 0)
        return dump(argv[2], argv[3], argc > 4 ? (strcmp(argv[4], "tinydns") == 0 ? DZT_TINYDNS : DZT_BIND) : DZT_AUTO);
    if (argc > 1) g_tests_dir = argv[1];
    test_every_type();
    test_format();
    test_apex();
    test_ttl_class();
    test_tags();
    test_hostile();
    test_tinydns();
    test_same_zone();
    test_render();
    test_field_table();
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/test_zone_text.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(g_dir)) {
        printf("[FAIL] mkdtemp\n");
        return 1;
    }
    test_loaders();
    test_db_zones();
    test_presigned_rows();
    test_presigned_zones();
    if (getenv("KARI_KEEP")) {
        printf("kept %s\n", g_dir);
    } else {
        char cmd[600];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
        if (system(cmd) != 0) printf("  (could not remove %s)\n", g_dir);
    }
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
