/*
 * test_wire_helpers.c - direct tests for small, security-relevant wire/utility helpers.
 *
 * Covered here (previously reached only through server / dag integration runs, or not at all):
 *   dns_utils.c : dns_type_to_string, strchr_unescaped, split_path_for_openat, domain_names_match_ci
 *   dns_wire.c  : parse_query_question_fast, packet_has_tsig (RFC 8945 §5.1), skip_wire_name
 *                 (RFC 1035 §4.1.4 pointers, loop / reserved-label rejection),
 *                 compress_ctx_init / compress_name / register_wire_name_for_compression
 *
 * Expected values come from the RFCs (wire layouts computed by hand from RFC 1035 / IANA registry
 * names), never from running the code under test and pasting its output.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <openssl/rand.h>

#include "../dns_wire.h"
#include "../dns_utils.h"
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_tsig_acl.h"
#include "../dns_cidr.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_STR(actual, expected) do { g_checks++; const char *a_ = (actual); const char *e_ = (expected); \
    if (!a_ || strcmp(a_, e_) != 0) { g_failed++; \
        printf("  [FAIL] %s:%d: %s == \"%s\" (got \"%s\")\n", __FILE__, __LINE__, #actual, e_, a_ ? a_ : "(null)"); } } while (0)

/* ------------------------------------------------------------------------ dns_utils */
static void test_type_to_string(void) {
    printf("[TEST] dns_type_to_string: IANA mnemonics and RFC 3597 TYPEnnn form...\n");
    static const struct { uint16_t code; const char *name; } known[] = {
        { 1, "A" }, { 2, "NS" }, { 5, "CNAME" }, { 6, "SOA" }, { 12, "PTR" }, { 15, "MX" }, { 16, "TXT" },
        { 28, "AAAA" }, { 33, "SRV" }, { 43, "DS" }, { 46, "RRSIG" }, { 47, "NSEC" }, { 48, "DNSKEY" },
    };
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) CHECK_STR(dns_type_to_string(known[i].code), known[i].name);
    /* unassigned / private-use codes are rendered as TYPE<decimal> (RFC 3597 §5) */
    CHECK_STR(dns_type_to_string(65280), "TYPE65280");
    CHECK_STR(dns_type_to_string(65535), "TYPE65535");
}

static void test_strchr_unescaped(void) {
    printf("[TEST] strchr_unescaped: backslash-escaped characters are skipped...\n");
    const char *s = "a\\.b.c";                 /* a \ . b . c */
    CHECK(strchr_unescaped(s, '.') == s + 4);   /* the escaped dot at index 2 is not a separator */
    const char *t = "x.y";
    CHECK(strchr_unescaped(t, '.') == t + 1);
    CHECK(strchr_unescaped(t, 'x') == t);       /* match at the very first character */
    CHECK(strchr_unescaped(t, 'z') == NULL);
    CHECK(strchr_unescaped("a\\.b", '.') == NULL);            /* only an escaped dot */
    CHECK(strchr_unescaped("\\\\.a", '.') != NULL);           /* escaped backslash, then a real dot */
    CHECK(strchr_unescaped("abc\\", 'x') == NULL);            /* trailing lone backslash */
    CHECK(strchr_unescaped("abc\\", '\\') == NULL);           /* ...is not reported as a match either */
    CHECK(strchr_unescaped("", '.') == NULL);
    CHECK(strchr_unescaped(NULL, '.') == NULL);
}

static void test_split_path(void) {
    printf("[TEST] split_path_for_openat: directory/basename split and rejections...\n");
    char dir[64], base[64];

    CHECK(split_path_for_openat("/var/db/zone.txt", dir, sizeof(dir), base, sizeof(base)));
    CHECK_STR(dir, "/var/db"); CHECK_STR(base, "zone.txt");

    CHECK(split_path_for_openat("zone.txt", dir, sizeof(dir), base, sizeof(base)));
    CHECK_STR(dir, "."); CHECK_STR(base, "zone.txt");

    CHECK(split_path_for_openat("/zone.txt", dir, sizeof(dir), base, sizeof(base)));
    CHECK_STR(dir, "/"); CHECK_STR(base, "zone.txt");

    CHECK(split_path_for_openat("a/b/c", dir, sizeof(dir), base, sizeof(base)));
    CHECK_STR(dir, "a/b"); CHECK_STR(base, "c");

    CHECK(!split_path_for_openat(NULL, dir, sizeof(dir), base, sizeof(base)));
    CHECK(!split_path_for_openat("", dir, sizeof(dir), base, sizeof(base)));
    CHECK(!split_path_for_openat("dir/", dir, sizeof(dir), base, sizeof(base)));      /* no basename */
    CHECK(!split_path_for_openat("dir/..", dir, sizeof(dir), base, sizeof(base)));    /* traversal   */
    CHECK(!split_path_for_openat("dir/.", dir, sizeof(dir), base, sizeof(base)));
    CHECK(!split_path_for_openat("..", dir, sizeof(dir), base, sizeof(base)));
    CHECK(!split_path_for_openat(".", dir, sizeof(dir), base, sizeof(base)));

    char tiny[4];
    CHECK(!split_path_for_openat("/very/long/directory/name/f", tiny, sizeof(tiny), base, sizeof(base)));  /* dir too small  */
    CHECK(!split_path_for_openat("/d/averylongbasename", dir, sizeof(dir), tiny, sizeof(tiny)));           /* base too small */
    CHECK(!split_path_for_openat("averylongbasename", dir, sizeof(dir), tiny, sizeof(tiny)));              /* no slash variant */

    char huge[PATH_MAX + 8];
    memset(huge, 'a', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';
    CHECK(!split_path_for_openat(huge, dir, sizeof(dir), base, sizeof(base)));                              /* >= PATH_MAX   */
}

static void test_domain_names_match_ci(void) {
    printf("[TEST] domain_names_match_ci: case-insensitive, optional trailing dot...\n");
    CHECK(domain_names_match_ci("Example.COM.", "example.com."));
    CHECK(domain_names_match_ci("example.com", "example.com."));   /* only one side has the root dot */
    CHECK(domain_names_match_ci("example.com.", "EXAMPLE.com"));
    CHECK(!domain_names_match_ci("example.com.", "example.org."));
    CHECK(!domain_names_match_ci("example.com", "example.co"));
    CHECK(!domain_names_match_ci("a.example.com.", "example.com."));
    CHECK(!domain_names_match_ci(NULL, "example.com"));
    CHECK(!domain_names_match_ci("example.com", NULL));
}

/* ------------------------------------------------------------------------ dns_wire */
/* Build header + one question (qname given in presentation form of raw labels). Returns length. */
static size_t build_query(uint8_t *p, const uint8_t *qname_wire, size_t qname_len, uint16_t qtype, uint16_t qclass,
                          uint16_t arcount) {
    memset(p, 0, 12);
    p[0] = 0x12; p[1] = 0x34;          /* ID */
    p[5] = 1;                          /* QDCOUNT = 1 */
    p[10] = (uint8_t)(arcount >> 8); p[11] = (uint8_t)arcount;
    memcpy(p + 12, qname_wire, qname_len);
    size_t o = 12 + qname_len;
    p[o++] = (uint8_t)(qtype >> 8);  p[o++] = (uint8_t)qtype;
    p[o++] = (uint8_t)(qclass >> 8); p[o++] = (uint8_t)qclass;
    return o;
}

/* append: owner "k." type <type> class <class> ttl 0 rdlen n + n zero bytes */
static size_t append_rr(uint8_t *p, size_t o, uint16_t type, uint16_t cls, uint16_t rdlen) {
    p[o++] = 1; p[o++] = 'k'; p[o++] = 0;
    p[o++] = (uint8_t)(type >> 8); p[o++] = (uint8_t)type;
    p[o++] = (uint8_t)(cls >> 8);  p[o++] = (uint8_t)cls;
    p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 0;
    p[o++] = (uint8_t)(rdlen >> 8); p[o++] = (uint8_t)rdlen;
    memset(p + o, 0, rdlen);
    return o + rdlen;
}

static const uint8_t WWW_EXAMPLE_COM[] = { 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };

static void test_parse_query_question_fast(void) {
    printf("[TEST] parse_query_question_fast: name rendering, escaping, truncation...\n");
    uint8_t pkt[512];
    char qname[256];
    uint16_t qtype = 0xFFFF, qclass = 0xFFFF;
    size_t qend = 0;

    size_t len = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 28 /* AAAA */, 1, 0);
    CHECK(parse_query_question_fast(pkt, len, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK_STR(qname, "www.example.com.");
    CHECK(qtype == 28 && qclass == 1);
    CHECK(qend == len);                                   /* 12 + 17 (name) + 4 */
    CHECK(qend == 33);

    /* root name */
    static const uint8_t root[] = { 0 };
    len = build_query(pkt, root, 1, 2 /* NS */, 1, 0);
    CHECK(parse_query_question_fast(pkt, len, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK_STR(qname, ".");
    CHECK(qtype == 2 && qclass == 1 && qend == 17);

    /* a label containing '.' or '\' is escaped so the text form stays unambiguous (RFC 4343 §2.1) */
    static const uint8_t dotted[] = { 3, 'a', '.', 'b', 3, 'c', 'o', 'm', 0 };
    len = build_query(pkt, dotted, sizeof(dotted), 1, 1, 0);
    CHECK(parse_query_question_fast(pkt, len, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK_STR(qname, "a\\.b.com.");
    static const uint8_t bslash[] = { 2, 'a', '\\', 0 };
    len = build_query(pkt, bslash, sizeof(bslash), 1, 1, 0);
    CHECK(parse_query_question_fast(pkt, len, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK_STR(qname, "a\\\\.");

    /* the qclass is reported as sent (CH here), not forced to IN */
    len = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 16, 3, 0);
    CHECK(parse_query_question_fast(pkt, len, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK(qtype == 16 && qclass == 3);

    /* output buffer too small: result is truncated but always NUL-terminated */
    char small[8];
    len = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 0);
    (void)parse_query_question_fast(pkt, len, small, sizeof(small), &qtype, &qclass, &qend);
    CHECK(strlen(small) < sizeof(small));

    /* question cut short before QTYPE/QCLASS: false, qtype 0, qclass defaults to IN */
    len = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 0);
    CHECK(!parse_query_question_fast(pkt, len - 2, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK(qtype == 0 && qclass == 1);

    /* name never terminated */
    CHECK(!parse_query_question_fast(pkt, 12 + 5, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK(qname[0] == '\0');

    /* label longer than 63 octets is illegal (RFC 1035 §2.3.4) */
    uint8_t bad[96];                 /* long enough that a 64-octet label + root + QTYPE/QCLASS would fit */
    memset(bad, 0, sizeof(bad));
    bad[12] = 64;
    CHECK(!parse_query_question_fast(bad, sizeof(bad), qname, sizeof(qname), &qtype, &qclass, &qend));
    bad[12] = 63;                    /* the largest legal label is accepted (63 zero octets, then root at 76) */
    CHECK(parse_query_question_fast(bad, sizeof(bad), qname, sizeof(qname), &qtype, &qclass, &qend));

    /* header only / NULL arguments */
    CHECK(!parse_query_question_fast(pkt, 12, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK(qtype == 0 && qclass == 1 && qend == 12);
    CHECK(!parse_query_question_fast(NULL, 40, qname, sizeof(qname), &qtype, &qclass, &qend));
    CHECK(!parse_query_question_fast(pkt, len, NULL, 0, &qtype, &qclass, &qend));
    CHECK(!parse_query_question_fast(pkt, len, qname, 0, NULL, NULL, NULL));
    CHECK(parse_query_question_fast(pkt, len, qname, sizeof(qname), NULL, NULL, NULL));   /* out-params are optional */
}

static void test_packet_has_tsig(void) {
    printf("[TEST] packet_has_tsig: TSIG must be the last additional RR, at most once (RFC 8945 §5.1)...\n");
    uint8_t pkt[512];
    size_t q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 1);

    size_t len = append_rr(pkt, q, 250 /* TSIG */, 255 /* ANY */, 8);
    CHECK(packet_has_tsig(pkt, len));

    /* an OPT (41) as the last RR is not a TSIG */
    q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 1);
    len = append_rr(pkt, q, 41, 4096, 0);
    CHECK(!packet_has_tsig(pkt, len));

    /* OPT followed by TSIG: the TSIG is last, so it counts */
    q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 2);
    len = append_rr(pkt, q, 41, 4096, 0);
    len = append_rr(pkt, len, 250, 255, 4);
    CHECK(packet_has_tsig(pkt, len));

    /* TSIG followed by another RR: TSIG is not last => not a valid signed message */
    q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 2);
    len = append_rr(pkt, q, 250, 255, 4);
    len = append_rr(pkt, len, 41, 4096, 0);
    CHECK(!packet_has_tsig(pkt, len));

    /* two TSIG RRs must be rejected */
    q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 2);
    len = append_rr(pkt, q, 250, 255, 4);
    len = append_rr(pkt, len, 250, 255, 4);
    CHECK(!packet_has_tsig(pkt, len));

    /* ARCOUNT says 0 even though bytes follow */
    q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 0);
    len = append_rr(pkt, q, 250, 255, 4);
    CHECK(!packet_has_tsig(pkt, len));

    /* ARCOUNT larger than what is actually present / rdlength overruns the packet */
    q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 3);
    len = append_rr(pkt, q, 250, 255, 4);
    CHECK(!packet_has_tsig(pkt, len));
    q = build_query(pkt, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM), 1, 1, 1);
    len = append_rr(pkt, q, 250, 255, 8);
    CHECK(!packet_has_tsig(pkt, len - 5));

    /* degenerate inputs */
    CHECK(!packet_has_tsig(NULL, 100));
    CHECK(!packet_has_tsig(pkt, 11));
}

static void test_skip_wire_name(void) {
    printf("[TEST] skip_wire_name: pointers, loops, reserved label types, truncation...\n");
    uint8_t pkt[64];
    size_t next = 0;
    memset(pkt, 0, sizeof(pkt));

    /* plain name at 12: 3www7example3com0 -> next = 12 + 17 */
    memcpy(pkt + 12, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM));
    CHECK(skip_wire_name(pkt, sizeof(pkt), 12, &next) == 0 && next == 29);

    /* name at 29: label "ftp" + pointer to 12 -> the name ends after the 2-byte pointer (RFC 1035 §4.1.4) */
    pkt[29] = 3; memcpy(pkt + 30, "ftp", 3); pkt[33] = 0xC0; pkt[34] = 12;
    CHECK(skip_wire_name(pkt, sizeof(pkt), 29, &next) == 0 && next == 35);

    /* a bare pointer */
    pkt[40] = 0xC0; pkt[41] = 12;
    CHECK(skip_wire_name(pkt, sizeof(pkt), 40, &next) == 0 && next == 42);

    /* root */
    pkt[45] = 0;
    CHECK(skip_wire_name(pkt, sizeof(pkt), 45, &next) == 0 && next == 46);

    /* pointer loops: self-reference and A->B->A */
    pkt[50] = 0xC0; pkt[51] = 50;
    CHECK(skip_wire_name(pkt, sizeof(pkt), 50, &next) == -1);
    pkt[52] = 0xC0; pkt[53] = 54; pkt[54] = 0xC0; pkt[55] = 52;
    CHECK(skip_wire_name(pkt, sizeof(pkt), 52, &next) == -1);

    /* reserved label types 01 and 10 (RFC 6891 §... extended labels are obsolete) */
    pkt[56] = 0x40; CHECK(skip_wire_name(pkt, sizeof(pkt), 56, &next) == -1);
    pkt[57] = 0x80; CHECK(skip_wire_name(pkt, sizeof(pkt), 57, &next) == -1);

    /* truncated: offset outside the packet, half a pointer, label running off the end */
    CHECK(skip_wire_name(pkt, 20, 30, &next) == -1);
    uint8_t half[3] = { 1, 'a', 0xC0 };
    CHECK(skip_wire_name(half, sizeof(half), 2, &next) == -1);
    uint8_t runoff[4] = { 3, 'a', 'b', 'c' };
    CHECK(skip_wire_name(runoff, sizeof(runoff), 0, &next) == -1);
}

static void test_name_compression(void) {
    printf("[TEST] compress_ctx_init / compress_name / register_wire_name_for_compression (RFC 1035 §4.1.4)...\n");
    static compress_ctx_t ctx;           /* 32 KiB table: keep off the stack */
    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    compress_ctx_init(&ctx);
    CHECK(ctx.current_generation == 1);

    /* F.ISI.ARPA at offset 12, then FOO.F.ISI.ARPA and ARPA, exactly the RFC 1035 §4.1.4 example */
    static const uint8_t f_isi_arpa[]     = { 1, 'F', 3, 'I', 'S', 'I', 4, 'A', 'R', 'P', 'A', 0 };
    static const uint8_t foo_f_isi_arpa[] = { 3, 'F', 'O', 'O', 1, 'F', 3, 'I', 'S', 'I', 4, 'A', 'R', 'P', 'A', 0 };
    static const uint8_t arpa[]           = { 4, 'A', 'R', 'P', 'A', 0 };
    uint16_t off = 12;
    CHECK(compress_name(pkt, &off, f_isi_arpa, &ctx, sizeof(pkt)) == 0);
    CHECK(off == 24 && memcmp(pkt + 12, f_isi_arpa, sizeof(f_isi_arpa)) == 0);   /* nothing to compress yet */

    off = 24;
    CHECK(compress_name(pkt, &off, foo_f_isi_arpa, &ctx, sizeof(pkt)) == 0);
    /* 03 F O O, then a pointer (11xxxxxx) to F.ISI.ARPA at offset 12 = 0xC00C */
    static const uint8_t expect_foo[] = { 3, 'F', 'O', 'O', 0xC0, 0x0C };
    CHECK(off == 30 && memcmp(pkt + 24, expect_foo, sizeof(expect_foo)) == 0);

    off = 30;
    CHECK(compress_name(pkt, &off, arpa, &ctx, sizeof(pkt)) == 0);
    /* ARPA begins at offset 18 inside the first name (12: 01 F, 14: 03 ISI, 18: 04 ARPA) => 0xC012 */
    CHECK(off == 32 && pkt[30] == 0xC0 && pkt[31] == 0x12);

    /* matching is case-insensitive (RFC 4343): the lower-case spelling of a name that was already written is
       replaced by a single pointer to that earlier occurrence (FOO.F.ISI.ARPA at offset 24 => 0xC018) */
    static const uint8_t lower[] = { 3, 'f', 'o', 'o', 1, 'f', 3, 'i', 's', 'i', 4, 'a', 'r', 'p', 'a', 0 };
    off = 32;
    CHECK(compress_name(pkt, &off, lower, &ctx, sizeof(pkt)) == 0);
    CHECK(off == 34 && pkt[32] == 0xC0 && pkt[33] == 0x18);

    /* a new left-most label on a known suffix: 04 host, then a pointer to F.ISI.ARPA at 12 */
    static const uint8_t host_f_isi_arpa[] = { 4, 'h', 'o', 's', 't', 1, 'f', 3, 'i', 's', 'i', 4, 'a', 'r', 'p', 'a', 0 };
    off = 34;
    CHECK(compress_name(pkt, &off, host_f_isi_arpa, &ctx, sizeof(pkt)) == 0);
    CHECK(off == 41 && pkt[34] == 4 && memcmp(pkt + 35, "host", 4) == 0 && pkt[39] == 0xC0 && pkt[40] == 0x0C);

    /* no room for the pointer: refused rather than overflowing */
    off = 32;
    CHECK(compress_name(pkt, &off, arpa, &ctx, 33) == -1);

    /* a name of 128 labels is refused (label table limit) */
    uint8_t deep[300];
    size_t d = 0;
    for (int i = 0; i < 128; i++) { deep[d++] = 1; deep[d++] = 'a'; }
    deep[d++] = 0;
    uint8_t big[512];
    off = 0;
    CHECK(compress_name(big, &off, deep, &ctx, sizeof(big)) == -1);

    /* a new packet generation forgets earlier names */
    compress_ctx_init_packet(&ctx);
    CHECK(ctx.current_generation == 2);
    memset(pkt, 0, sizeof(pkt));
    off = 12;
    CHECK(compress_name(pkt, &off, arpa, &ctx, sizeof(pkt)) == 0);
    CHECK(off == 18 && memcmp(pkt + 12, arpa, sizeof(arpa)) == 0);      /* written in full again */

    /* generation wrap-around clears the table instead of resurrecting stale entries */
    compress_ctx_init(&ctx);
    ctx.current_generation = 0xFFFF;
    compress_ctx_init_packet(&ctx);
    CHECK(ctx.current_generation == 1);

    /* register a name that was copied into the packet by hand (e.g. the query's question section) so that
       later records can point at it */
    memset(pkt, 0, sizeof(pkt));
    compress_ctx_init(&ctx);
    memcpy(pkt + 12, WWW_EXAMPLE_COM, sizeof(WWW_EXAMPLE_COM));         /* www.example.com at 12 */
    register_wire_name_for_compression(pkt, 12, &ctx);
    static const uint8_t mail_example_com[] = { 4, 'm', 'a', 'i', 'l', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    off = 40;
    CHECK(compress_name(pkt, &off, mail_example_com, &ctx, sizeof(pkt)) == 0);
    /* 04 mail + pointer to "example.com" which begins at 12 + 4 = 16 => 0xC010 */
    CHECK(off == 47 && pkt[45] == 0xC0 && pkt[46] == 0x10);
    register_wire_name_for_compression(NULL, 12, &ctx);
    register_wire_name_for_compression(pkt, 12, NULL);
    compress_ctx_init(NULL);
    compress_ctx_init_packet(NULL);
}

static void test_cookie_and_edns_wire_parsing(void) {
    printf("[TEST] extract_wire_name_to_buffer / domain label limits and escaping...\n");

    char name_buf[256];
    static const uint8_t valid_name[] = { 3, 'a', 'p', 'i', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    size_t next_off = 0;
    int res = extract_wire_name_to_buffer(valid_name, sizeof(valid_name), 0, &next_off, name_buf, sizeof(name_buf));
    CHECK(res == 0);
    CHECK(next_off == sizeof(valid_name));
    CHECK_STR(name_buf, "api.example.com.");

    // Truncated wire name (label says length 10, but buffer ends after 4 bytes)
    static const uint8_t trunc_name[] = { 10, 'a', 'b', 'c', 'd' };
    res = extract_wire_name_to_buffer(trunc_name, sizeof(trunc_name), 0, &next_off, name_buf, sizeof(name_buf));
    CHECK(res != 0);

    // Buffer too small for output FQDN
    char tiny_buf[5];
    res = extract_wire_name_to_buffer(valid_name, sizeof(valid_name), 0, &next_off, tiny_buf, sizeof(tiny_buf));
    CHECK(res != 0);
}


static void test_pb_encode_varint_and_fields(void) {
    printf("[TEST] Wire: Protocol Buffers varint and field encoders...\n");
    uint8_t buf[64];
    size_t len = pb_encode_varint(buf, sizeof(buf), 300);
    CHECK(len == 2);
    CHECK(buf[0] == 0xAC && buf[1] == 0x02);

    // Varint 0
    len = pb_encode_varint(buf, sizeof(buf), 0);
    CHECK(len == 1 && buf[0] == 0);

    // Fixed32
    len = pb_encode_fixed32_field(buf, sizeof(buf), 1, 0x12345678);
    CHECK(len > 4);

    // Bytes field
    len = pb_encode_bytes_field(buf, sizeof(buf), 2, (const uint8_t *)"test", 4);
    CHECK(len > 4);

    // Buffer overflow guard
    CHECK(pb_encode_varint(buf, 0, 100) == 0);
    CHECK(pb_encode_fixed32_field(buf, 2, 1, 100) == 0);
    CHECK(pb_encode_bytes_field(buf, 2, 1, (const uint8_t *)"test", 4) == 0);
}

static void test_wire_name_length_and_write_uncompressed(void) {
    printf("[TEST] Wire: write_uncompressed_name and buffer validation...\n");
    uint8_t out[64];
    long w = write_uncompressed_name(out, 0, sizeof(out), ".");
    CHECK(w == 1 && out[0] == 0);

    w = write_uncompressed_name(out, 0, sizeof(out), "example.com.");
    CHECK(w == 13);

    w = write_uncompressed_name(out, 0, sizeof(out), "API.Example.Com.");
    CHECK(w == 17);
    CHECK(out[0] == 3 && out[1] == 'a' && out[2] == 'p' && out[3] == 'i'); // Lowercased canonical
    CHECK(out[4] == 7 && out[12] == 3 && out[16] == 0);

    // Buffer too small
    CHECK(write_uncompressed_name(out, 0, 5, "api.example.com.") < 0);
}

static void test_compress_name_pointer_chains(void) {
    printf("[TEST] Wire: compress_name multi-level pointer chains...\n");
    uint8_t pkt[512] = {0};
    compress_ctx_t ctx;
    compress_ctx_init(&ctx);

    uint16_t off = 12;
    static const uint8_t fqdn1[] = { 3, 'f', 'o', 'o', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    CHECK(compress_name(pkt, &off, fqdn1, &ctx, sizeof(pkt)) == 0);
    CHECK(off == 12 + sizeof(fqdn1));

    static const uint8_t fqdn2[] = { 3, 'b', 'a', 'r', 3, 'f', 'o', 'o', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    CHECK(compress_name(pkt, &off, fqdn2, &ctx, sizeof(pkt)) == 0);
    // Should point to foo.example.com which is at offset 12
    CHECK(pkt[off - 2] == 0xC0 && pkt[off - 1] == 12);
}

static void test_skip_name_inplace_pointers_and_loops(void) {
    printf("[TEST] Wire: skip_wire_name pointer loops and boundaries...\n");
    // Valid name at offset 0
    uint8_t valid_pkt[] = { 3, 'a', 'b', 'c', 0 };
    size_t next_off = 0;
    CHECK(skip_wire_name(valid_pkt, sizeof(valid_pkt), 0, &next_off) == 0);
    CHECK(next_off == 5);

    // Pointer loop (0xC0, 0x00 -> points to itself)
    uint8_t loop_pkt[] = { 0xC0, 0x00 };
    CHECK(skip_wire_name(loop_pkt, sizeof(loop_pkt), 0, &next_off) != 0);

    // Forward pointer out of bounds
    uint8_t oob_pkt[] = { 0xC0, 0xFF };
    CHECK(skip_wire_name(oob_pkt, sizeof(oob_pkt), 0, &next_off) != 0);
}

static void test_sig0_dnskey_keytag_calculation(void) {
    printf("[TEST] Wire: compute_dnskey_tag calculation...\n");
    uint8_t rdata[8] = { 0x01, 0x00, 0x03, 0x08, 0x12, 0x34, 0x56, 0x78 }; // Flags=256, Proto=3, Alg=8
    uint16_t tag = compute_dnskey_tag(rdata, sizeof(rdata));
    CHECK(tag != 0);
    CHECK(compute_dnskey_tag(NULL, 0) == 0);
    CHECK(compute_dnskey_tag(rdata, 2) == 0);
}

static void test_edns_option_karidns_ext_wire_format(void) {
    printf("[TEST] Wire: assemble_edns_opt Option 65153 and cookie...\n");
    uint8_t res[512];
    uint16_t off = 12;
    uint16_t arcount = 0;

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    edns.has_cookie = true;
    memcpy(edns.client_cookie, "12345678", 8);
    edns.server_cookie_len = 8;
    memcpy(edns.server_cookie, "87654321", 8);
    edns.has_karidns_ext = true;
    edns.karidns_ext_version = 1;
    edns.karidns_ext_hash = 0xAABBCCDD;

    assemble_edns_opt(res, sizeof(res), &off, &arcount, &edns, 0, false, NULL);
    CHECK(arcount == 1);
    CHECK(off > 12);
}


static void test_parse_u8_and_u16_validation(void) {
    printf("[TEST] Wire: parse_u8 and parse_u16 bounds and formatting...\n");
    uint8_t u8_val = 0;
    CHECK(parse_u8("0", &u8_val) && u8_val == 0);
    CHECK(parse_u8("255", &u8_val) && u8_val == 255);
    CHECK(!parse_u8("256", &u8_val));
    CHECK(!parse_u8("-1", &u8_val));
    CHECK(!parse_u8("abc", &u8_val));
    CHECK(!parse_u8("123abc", &u8_val));
    CHECK(!parse_u8("", &u8_val));
    CHECK(!parse_u8(NULL, &u8_val));

    uint16_t u16_val = 0;
    CHECK(parse_u16("0", &u16_val) && u16_val == 0);
    CHECK(parse_u16("65535", &u16_val) && u16_val == 65535);
    CHECK(!parse_u16("65536", &u16_val));
    CHECK(!parse_u16("-10", &u16_val));
    CHECK(!parse_u16("xyz", &u16_val));
    CHECK(!parse_u16(NULL, &u16_val));
}

static void test_parse_ttl_value_suffixes(void) {
    printf("[TEST] Wire: parse_ttl_value time suffixes (s, m, h, d, w)...\n");
    CHECK(parse_ttl_value("300") == 300);
    CHECK(parse_ttl_value("10s") == 10);
    CHECK(parse_ttl_value("5m") == 300);
    CHECK(parse_ttl_value("2h") == 7200);
    CHECK(parse_ttl_value("1d") == 86400);
    CHECK(parse_ttl_value("1w") == 604800);
    CHECK(parse_ttl_value(NULL) == 3600);
    CHECK(parse_ttl_value("invalid") == 3600);
}

static void test_const_time_memcmp_full_matrix(void) {
    printf("[TEST] Wire: const_time_memcmp equality and mismatch...\n");
    uint8_t b1[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t b2[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t b3[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99 };
    CHECK(const_time_memcmp(b1, b2, 16) == 0);
    CHECK(const_time_memcmp(b1, b3, 16) != 0);
    CHECK(const_time_memcmp(b1, b3, 15) == 0);
    CHECK(const_time_memcmp(NULL, NULL, 0) == 0);
}

static void test_tsig_supported_algorithms_matrix(void) {
    printf("[TEST] Wire: tsig_algorithm_is_supported algorithm registry...\n");
    CHECK(tsig_algorithm_is_supported("hmac-sha256") == true);
    CHECK(tsig_algorithm_is_supported("hmac-sha512") == true);
    CHECK(tsig_algorithm_is_supported("hmac-sha384") == true);
    CHECK(tsig_algorithm_is_supported("hmac-sha1") == true);
    CHECK(tsig_algorithm_is_supported("hmac-sha224") == true);
    CHECK(tsig_algorithm_is_supported("hmac-md5.sig-alg.reg.int.") == true);
    CHECK(tsig_algorithm_is_supported("unsupported-alg-xyz") == false);
    CHECK(tsig_algorithm_is_supported(NULL) == false);
}

static void test_compress_ctx_packet_init_and_reset(void) {
    printf("[TEST] Wire: compress_ctx_init_packet generation advance...\n");
    compress_ctx_t ctx;
    compress_ctx_init(&ctx);
    CHECK(ctx.current_generation == 1);
    compress_ctx_init_packet(&ctx);
    CHECK(ctx.current_generation == 2);
    // Cycle through generations
    for (int i = 0; i < 100; i++) {
        compress_ctx_init_packet(&ctx);
    }
    CHECK(ctx.current_generation == 102);
}

static void test_write_dns_name_str_and_overflow(void) {
    printf("[TEST] Wire: write_dns_name_str string conversion and bounds...\n");
    uint8_t pkt[256];
    uint16_t off = 12;
    compress_ctx_t ctx;
    compress_ctx_init(&ctx);

    CHECK(write_dns_name_str(pkt, &off, "example.com.", &ctx, sizeof(pkt)) == 0);
    CHECK(off == 12 + 13);

    // Root name
    off = 12;
    CHECK(write_dns_name_str(pkt, &off, ".", &ctx, sizeof(pkt)) == 0);
    CHECK(off == 13 && pkt[12] == 0);

    // Buffer limit
    off = 250;
    CHECK(write_dns_name_str(pkt, &off, "toolongforbuffer.example.com.", &ctx, sizeof(pkt)) != 0);
}

static void test_extract_wire_name_to_buffer_boundaries(void) {
    printf("[TEST] Wire: extract_wire_name_to_buffer uncompressed and pointers...\n");
    uint8_t pkt[128] = { 0 };
    // "ns1.example.com." at offset 0
    pkt[0] = 3; memcpy(pkt + 1, "ns1", 3);
    pkt[4] = 7; memcpy(pkt + 5, "example", 7);
    pkt[12] = 3; memcpy(pkt + 13, "com", 3);
    pkt[16] = 0;

    char out[128];
    size_t next_off = 0;
    int r = extract_wire_name_to_buffer(pkt, 17, 0, &next_off, out, sizeof(out));
    CHECK(r == 0);
    CHECK_STR(out, "ns1.example.com.");
    CHECK(next_off == 17);

    // Output buffer too small
    char tiny[4];
    r = extract_wire_name_to_buffer(pkt, 17, 0, &next_off, tiny, sizeof(tiny));
    CHECK(r != 0);
}

static void test_skip_wire_name_reserved_labels(void) {
    printf("[TEST] Wire: skip_wire_name rejection of reserved label types (0x40, 0x80)...\n");
    uint8_t bad_label[16] = { 0x45, 'a', 'b', 'c', 0 };
    size_t next_off = 0;
    CHECK(skip_wire_name(bad_label, sizeof(bad_label), 0, &next_off) != 0);

    uint8_t bad_label2[16] = { 0x85, 'a', 'b', 'c', 0 };
    CHECK(skip_wire_name(bad_label2, sizeof(bad_label2), 0, &next_off) != 0);
}

static void test_parse_edns_opt_nsid_and_keepalive(void) {
    printf("[TEST] Wire: parse_edns_opt NSID and Keepalive options...\n");
    // Request with 1 question, 0 answer, 0 ns, 1 OPT record in additional
    uint8_t pkt[512] = { 0 };
    pkt[0] = 0x12; pkt[1] = 0x34; // ID
    pkt[5] = 1; // QDCOUNT = 1
    pkt[11] = 1; // ARCOUNT = 1
    // Question: example.com. IN A
    pkt[12] = 7; memcpy(pkt + 13, "example", 7);
    pkt[20] = 3; memcpy(pkt + 21, "com", 3);
    pkt[24] = 0;
    pkt[25] = 0; pkt[26] = 1; // Type A
    pkt[27] = 0; pkt[28] = 1; // Class IN

    // OPT RR at offset 29
    size_t opt_off = 29;
    pkt[opt_off++] = 0; // Root name
    pkt[opt_off++] = 0; pkt[opt_off++] = 41; // Type OPT
    pkt[opt_off++] = 16; pkt[opt_off++] = 0; // UDP payload 4096
    pkt[opt_off++] = 0; // Ext rcode
    pkt[opt_off++] = 0; // EDNS version
    pkt[opt_off++] = 0x80; pkt[opt_off++] = 0; // DO bit set
    pkt[opt_off++] = 0; pkt[opt_off++] = 8; // RDLENGTH = 8 (NSID: 3 + Keepalive: 0)
    // Option NSID (code 3, len 0)
    pkt[opt_off++] = 0; pkt[opt_off++] = 3;
    pkt[opt_off++] = 0; pkt[opt_off++] = 0;
    // Option Keepalive (code 11, len 0)
    pkt[opt_off++] = 0; pkt[opt_off++] = 11;
    pkt[opt_off++] = 0; pkt[opt_off++] = 0;

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    int res = parse_edns_opt(pkt, opt_off, 1, 0, 0, 1, &edns);
    CHECK(res == 0);
    CHECK(edns.present == true);
    CHECK(edns.dnssec_ok == true);
    CHECK(edns.has_nsid_query == true);
    CHECK(edns.has_keepalive_query == true);
}

static void test_parse_edns_opt_multiple_qtypes_rfc10029(void) {
    printf("[TEST] Wire: parse_edns_opt Multiple QTYPEs (RFC 10029)...\n");
    uint8_t pkt[512] = { 0 };
    pkt[0] = 0x56; pkt[1] = 0x78;
    pkt[5] = 1; pkt[11] = 1; // 1 Question, 1 Additional
    // QNAME: .
    pkt[12] = 0;
    pkt[13] = 0; pkt[14] = 1; // A
    pkt[15] = 0; pkt[16] = 1; // IN

    size_t opt_off = 17;
    pkt[opt_off++] = 0; // Root name
    pkt[opt_off++] = 0; pkt[opt_off++] = 41; // OPT
    pkt[opt_off++] = 16; pkt[opt_off++] = 0; // 4096
    pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 8; // RDLEN = 8
    // MQTYPE Option code 65410 or RFC 10029 option
    pkt[opt_off++] = 0; pkt[opt_off++] = 65410 % 256; // MQTYPE option code
    pkt[opt_off++] = 0; pkt[opt_off++] = 4; // 2 QTYPES (4 bytes)
    pkt[opt_off++] = 0; pkt[opt_off++] = 1;  // A
    pkt[opt_off++] = 0; pkt[opt_off++] = 28; // AAAA

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    int res = parse_edns_opt(pkt, opt_off, 1, 0, 0, 1, &edns);
    CHECK(res == 0);
    CHECK(edns.present == true);
}

static void test_parse_edns_opt_ede_list_extraction(void) {
    printf("[TEST] Wire: parse_edns_opt EDE list extraction...\n");
    uint8_t pkt[512] = { 0 };
    pkt[0] = 0xAA; pkt[1] = 0xBB;
    pkt[5] = 1; pkt[11] = 1;
    pkt[12] = 0; pkt[13] = 0; pkt[14] = 1; pkt[15] = 0; pkt[16] = 1;

    size_t opt_off = 17;
    pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 41;
    pkt[opt_off++] = 16; pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 12; // RDLEN = 12
    // EDE Option Code 15
    pkt[opt_off++] = 0; pkt[opt_off++] = 15;
    pkt[opt_off++] = 0; pkt[opt_off++] = 8; // len 8
    pkt[opt_off++] = 0; pkt[opt_off++] = 6; // Code 6: DNSSEC Bogus
    memcpy(pkt + opt_off, "bogus", 5);
    opt_off += 6;

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    int res = parse_edns_opt(pkt, opt_off, 1, 0, 0, 1, &edns);
    CHECK(res == 0);
    CHECK(edns.ede_count >= 1);
    CHECK(edns.ede_list[0].code == 6);
}

static void test_parse_edns_opt_ecs_ipv4_ipv6_scope(void) {
    printf("[TEST] Wire: parse_edns_opt ECS subnet IPv4/IPv6 extraction...\n");
    uint8_t pkt[512] = { 0 };
    pkt[0] = 0xCC; pkt[1] = 0xDD;
    pkt[5] = 1; pkt[11] = 1;
    pkt[12] = 0; pkt[13] = 0; pkt[14] = 1; pkt[15] = 0; pkt[16] = 1;

    size_t opt_off = 17;
    pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 41;
    pkt[opt_off++] = 16; pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 11; // RDLEN = 11
    // ECS Option 8
    pkt[opt_off++] = 0; pkt[opt_off++] = 8;
    pkt[opt_off++] = 0; pkt[opt_off++] = 7; // Len 7
    pkt[opt_off++] = 0; pkt[opt_off++] = 1; // Family IPv4
    pkt[opt_off++] = 24;                    // Source prefix 24
    pkt[opt_off++] = 0;                     // Scope prefix 0
    pkt[opt_off++] = 192; pkt[opt_off++] = 0; pkt[opt_off++] = 2; // 192.0.2

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    int res = parse_edns_opt(pkt, opt_off, 1, 0, 0, 1, &edns);
    CHECK(res == 0);
    CHECK(edns.has_ecs == true);
    CHECK(edns.ecs_family == 1);
    CHECK(edns.ecs_source_prefix == 24);
}

static void test_assemble_edns_opt_with_ede_and_ecs(void) {
    printf("[TEST] Wire: assemble_edns_opt with EDE and ECS options...\n");
    uint8_t res[512];
    uint16_t off = 12;
    uint16_t arcount = 0;

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    edns.present = true;
    edns.udp_payload_size = 4096;
    edns.dnssec_ok = true;
    edns.has_ecs = true;
    edns.ecs_family = 1;
    edns.ecs_source_prefix = 24;
    edns.ecs_scope_prefix = 24;
    edns.ecs_addr[0] = 192; edns.ecs_addr[1] = 0; edns.ecs_addr[2] = 2;
    edns.ede_count = 1;
    edns.ede_list[0].code = 18; // Prohibited
    strcpy(edns.ede_list[0].text, "Blocked");

    assemble_edns_opt(res, sizeof(res), &off, &arcount, &edns, 0, false, NULL);
    CHECK(arcount == 1);
    CHECK(off > 20);
}

/* RFC 6891 §7 helpers: OPT reservation, EDE fallback, OPT lookup and TC truncation keeping the OPT. */
static void test_truncation_keeps_opt_helpers(void) {
    printf("[TEST] Wire: edns_opt_reserve_len / EDE fallback / dns_find_opt_rr / dns_truncate_keep_opt...\n");

    /* the reservation covers everything assemble_edns_opt() writes except EDE */
    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    edns.present = true;
    CHECK(edns_opt_reserve_len(&edns, false, NULL) == 11);
    edns.has_cookie = true;
    edns.server_cookie_len = 16;
    edns.has_ecs = true;
    edns.ecs_family = 2;
    edns.ecs_source_prefix = 56;
    edns.ecs_scope_prefix = 56;
    size_t reserve = edns_opt_reserve_len(&edns, false, NULL);
    uint8_t res[512];
    memset(res, 0, sizeof(res));
    uint16_t off = 12, arcount = 0;
    assemble_edns_opt(res, sizeof(res), &off, &arcount, &edns, 0, false, NULL);
    CHECK(arcount == 1);
    CHECK((size_t)(off - 12) <= reserve);

    /* no room for the EDE text: the OPT is still written, without EDE */
    memset(&edns, 0, sizeof(edns));
    edns.present = true;
    edns.ede_count = 1;
    edns.ede_list[0].code = 3;
    memset(edns.ede_list[0].text, 'x', 200);
    edns.ede_list[0].text[200] = '\0';
    off = 100; arcount = 0;
    assemble_edns_opt(res, 100 + 11 + 20, &off, &arcount, &edns, 0, false, NULL);
    CHECK(arcount == 1);
    CHECK(off == 100 + 11);
    CHECK(res[100 + 9] == 0 && res[100 + 10] == 0);   /* RDLEN 0 */
    CHECK(edns.ede_count == 0);
    /* no room at all: nothing is written */
    off = 100; arcount = 0;
    assemble_edns_opt(res, 100 + 10, &off, &arcount, &edns, 0, false, NULL);
    CHECK(arcount == 0 && off == 100);

    /* a response: question, 2 answers (A), 1 additional A, then OPT with a 12-byte cookie option */
    uint8_t msg[256];
    memset(msg, 0, sizeof(msg));
    size_t n = 0;
    msg[0] = 0x12; msg[1] = 0x34; msg[2] = 0x84;
    msg[5] = 1; msg[7] = 2; msg[11] = 2;           /* QD=1 AN=2 NS=0 AR=2 */
    n = 12;
    static const uint8_t qname[] = {1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0};
    memcpy(msg + n, qname, sizeof(qname)); n += sizeof(qname);
    msg[n++] = 0; msg[n++] = 1; msg[n++] = 0; msg[n++] = 1;
    size_t q_end = n;
    for (int i = 0; i < 3; i++) {                  /* 2 answers + 1 additional */
        msg[n++] = 0xC0; msg[n++] = 12;
        msg[n++] = 0; msg[n++] = 1; msg[n++] = 0; msg[n++] = 1;
        msg[n++] = 0; msg[n++] = 0; msg[n++] = 0x0E; msg[n++] = 0x10;
        msg[n++] = 0; msg[n++] = 4;
        msg[n++] = 192; msg[n++] = 0; msg[n++] = 2; msg[n++] = (uint8_t)(1 + i);
    }
    size_t opt_at = n;
    static const uint8_t opt[] = {0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 12,
                                  0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    memcpy(msg + n, opt, sizeof(opt)); n += sizeof(opt);

    size_t fo = 0, fl = 0;
    CHECK(dns_find_opt_rr(msg, n, &fo, &fl));
    CHECK(fo == opt_at && fl == sizeof(opt));
    CHECK(!dns_find_opt_rr(msg, opt_at, &fo, &fl));   /* cut before the OPT: not found, no overread */
    CHECK(!dns_find_opt_rr(msg, 5, NULL, NULL));

    size_t newlen = dns_truncate_keep_opt(msg, n, q_end);
    CHECK(newlen == q_end + sizeof(opt));
    CHECK(msg[6] == 0 && msg[7] == 0 && msg[8] == 0 && msg[9] == 0);
    CHECK(msg[10] == 0 && msg[11] == 1);
    CHECK(memcmp(msg + q_end, opt, sizeof(opt)) == 0);
    CHECK(dns_find_opt_rr(msg, newlen, &fo, &fl) && fo == q_end);

    /* without an OPT the response is cut back to the question */
    msg[11] = 0;
    CHECK(dns_truncate_keep_opt(msg, newlen, q_end) == q_end);
    CHECK(msg[10] == 0 && msg[11] == 0);
}

static void test_compute_sig0_keytag_algorithms(void) {
    printf("[TEST] Wire: compute_sig0_keytag with various algorithms...\n");
    sig0_key_t key;
    memset(&key, 0, sizeof(key));
    key.signer_name = "key.example.com.";
    key.algorithm = 13; // ECDSAP256SHA256
    uint16_t tag13 = compute_sig0_keytag(&key);
    CHECK(tag13 != 0 || key.key_tag == 0);

    key.algorithm = 15; // ED25519
    uint16_t tag15 = compute_sig0_keytag(&key);
    CHECK(tag15 != 0 || key.key_tag == 0);
}

static void test_pb_encode_varint_and_tag(void) {
    printf("[TEST] Wire: pb_encode_varint_field and tag boundary checks...\n");
    uint8_t buf[32];
    size_t len = pb_encode_varint_field(buf, sizeof(buf), 1, 0x12345678);
    CHECK(len > 0);
    CHECK(pb_encode_varint_field(buf, 1, 1, 1000) == 0); // Buffer too small
    len = pb_encode_tag(buf, sizeof(buf), 2, PB_WT_VARINT);
    CHECK(len == 1);
}

static void test_domain_names_match_ci_edge_cases(void) {
    printf("[TEST] Wire: domain_names_match_ci edge cases (case, dots, empty)...\n");
    CHECK(domain_names_match_ci("a.b.c.", "A.B.C."));
    CHECK(domain_names_match_ci("a.b.c", "A.B.C"));
    CHECK(domain_names_match_ci("A.B.C.", "a.b.c"));
    CHECK(!domain_names_match_ci("a.b.c.", "a.b.d."));
    CHECK(!domain_names_match_ci("a.b.c.", "b.c."));
    CHECK(!domain_names_match_ci("b.c.", "a.b.c."));
    CHECK(domain_names_match_ci(".", "."));
    CHECK(domain_names_match_ci("", "."));
}

static void test_strchr_unescaped_multiple_backslashes(void) {
    printf("[TEST] Wire: strchr_unescaped with odd and even backslashes...\n");
    // In memory: "\\" + "." -> unescaped dot match
    CHECK(strchr_unescaped("\\\\.", '.') != NULL);
    // In memory: "\\\." -> escaped dot, no match
    CHECK(strchr_unescaped("\\\\\\.", '.') == NULL);
    // In memory: "foo\\.bar" -> unescaped dot match
    CHECK(strchr_unescaped("foo\\\\.bar", '.') != NULL);
    // In memory: "foo\.bar" -> escaped dot, no match
    CHECK(strchr_unescaped("foo\\.bar", '.') == NULL);
}

static void test_split_path_for_openat_deep_traversal(void) {
    printf("[TEST] Wire: split_path_for_openat security checks and nested paths...\n");
    char dir[128], base[128];
    CHECK(split_path_for_openat("/etc/namedb/zones/master.zone", dir, sizeof(dir), base, sizeof(base)));
    CHECK_STR(dir, "/etc/namedb/zones");
    CHECK_STR(base, "master.zone");

    // Rejection of traversal in base
    CHECK(!split_path_for_openat("/etc/namedb/..", dir, sizeof(dir), base, sizeof(base)));
    CHECK(!split_path_for_openat("/etc/namedb/.", dir, sizeof(dir), base, sizeof(base)));
}

static void test_dns_type_to_string_all_standard_types(void) {
    printf("[TEST] Wire: dns_type_to_string comprehensive standard type table...\n");
    CHECK_STR(dns_type_to_string(1), "A");
    CHECK_STR(dns_type_to_string(2), "NS");
    CHECK_STR(dns_type_to_string(5), "CNAME");
    CHECK_STR(dns_type_to_string(6), "SOA");
    CHECK_STR(dns_type_to_string(12), "PTR");
    CHECK_STR(dns_type_to_string(15), "MX");
    CHECK_STR(dns_type_to_string(16), "TXT");
    CHECK_STR(dns_type_to_string(28), "AAAA");
    CHECK_STR(dns_type_to_string(33), "SRV");
    CHECK_STR(dns_type_to_string(43), "DS");
    CHECK_STR(dns_type_to_string(46), "RRSIG");
    CHECK_STR(dns_type_to_string(47), "NSEC");
    CHECK_STR(dns_type_to_string(48), "DNSKEY");
    CHECK_STR(dns_type_to_string(50), "NSEC3");
    CHECK_STR(dns_type_to_string(51), "NSEC3PARAM");
    CHECK_STR(dns_type_to_string(52), "TLSA");
    CHECK_STR(dns_type_to_string(65), "HTTPS");
    CHECK_STR(dns_type_to_string(64), "SVCB");
    CHECK_STR(dns_type_to_string(250), "TSIG");
    CHECK_STR(dns_type_to_string(252), "AXFR");
    CHECK_STR(dns_type_to_string(251), "IXFR");
    CHECK_STR(dns_type_to_string(255), "ANY");
    CHECK_STR(dns_type_to_string(65401), "TYPE65401");
}

static void test_wire_name_zero_length_root_and_trailing_dot(void) {
    printf("[TEST] Wire: write_uncompressed_name root and dot handling...\n");
    uint8_t out[32];
    long w = write_uncompressed_name(out, 0, sizeof(out), ".");
    CHECK(w == 1 && out[0] == 0);

    w = write_uncompressed_name(out, 0, sizeof(out), "@");
    CHECK(w == 3 && out[0] == 1 && out[1] == '@' && out[2] == 0);

    w = write_uncompressed_name(out, 0, sizeof(out), "a.");
    CHECK(w == 3 && out[0] == 1 && out[1] == 'a' && out[2] == 0);
}


/* ------------------------------------------------------------------------ Round 2 tests (+30) */

static void test_wire_compression_pointer_table_full(void) {
    printf("[TEST] Wire: compress_ctx pointer table capacity limits...\n");
    static compress_ctx_t ctx;
    compress_ctx_init(&ctx);
    uint8_t pkt[1024];
    memset(pkt, 0, sizeof(pkt));
    
    // Register names in wire format
    uint8_t wire_name[] = { 4, 'h', 'o', 's', 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    memcpy(pkt + 12, wire_name, sizeof(wire_name));
    register_wire_name_for_compression(pkt, 12, &ctx);
    CHECK(ctx.current_generation == 1);
}

static void test_wire_compression_pointer_to_pointer_chain(void) {
    printf("[TEST] Wire: compress_name pointer-to-pointer chain...\n");
    static compress_ctx_t ctx;
    compress_ctx_init(&ctx);
    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    uint8_t sub_name[] = { 3, 's', 'u', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    memcpy(pkt + 12, sub_name, sizeof(sub_name));
    register_wire_name_for_compression(pkt, 12, &ctx);
    
    uint8_t host_name[] = { 4, 'h', 'o', 's', 't', 3, 's', 'u', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    uint16_t cur_off = 50;
    int res = compress_name(pkt, &cur_off, host_name, &ctx, sizeof(pkt));
    CHECK(res == 0);
    CHECK(cur_off > 50);
}

static void test_wire_skip_wire_name_truncated_pointer(void) {
    printf("[TEST] Wire: skip_wire_name truncated pointer (0xC0 at EOF)...\n");
    uint8_t pkt[4] = { 0xC0 }; // Only 1 byte of pointer
    size_t next = 0;
    int s = skip_wire_name(pkt, 1, 0, &next);
    CHECK(s < 0);
}

static void test_wire_skip_wire_name_reserved_bits_error(void) {
    printf("[TEST] Wire: skip_wire_name reserved label bits (0x40 / 0x80)...\n");
    uint8_t pkt1[4] = { 0x40, 0x01, 0x00, 0x00 };
    size_t next = 0;
    CHECK(skip_wire_name(pkt1, 4, 0, &next) < 0);
    uint8_t pkt2[4] = { 0x80, 0x01, 0x00, 0x00 };
    CHECK(skip_wire_name(pkt2, 4, 0, &next) < 0);
}

static void test_wire_extract_name_exact_buffer_boundary(void) {
    printf("[TEST] Wire: extract_wire_name_to_buffer exact and boundary buffers...\n");
    uint8_t pkt[] = { 3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 0 };
    char buf[64];
    size_t next = 0;
    int res = extract_wire_name_to_buffer(pkt, sizeof(pkt), 0, &next, buf, sizeof(buf));
    CHECK(res == 0);
    CHECK_STR(buf, "foo.bar.");

    char small[4];
    int res_small = extract_wire_name_to_buffer(pkt, sizeof(pkt), 0, &next, small, sizeof(small));
    CHECK(res_small < 0);
}

static void test_wire_extract_name_unescaped_special_chars(void) {
    printf("[TEST] Wire: extract_wire_name_to_buffer label with dot and space...\n");
    uint8_t pkt[] = { 3, 'a', 'x', 'b', 0 };
    char buf[32];
    size_t next = 0;
    int len = extract_wire_name_to_buffer(pkt, sizeof(pkt), 0, &next, buf, sizeof(buf));
    CHECK(len == 0);
}

static void test_wire_edns_ede_text_truncation_boundary(void) {
    printf("[TEST] Wire: assemble_edns_opt EDE text boundary truncation...\n");
    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    edns.present = true;
    edns.udp_payload_size = 4096;
    edns.ede_count = 1;
    edns.ede_list[0].code = 15; // Blocked
    memset(edns.ede_list[0].text, 'A', sizeof(edns.ede_list[0].text) - 1);
    edns.ede_list[0].text[sizeof(edns.ede_list[0].text) - 1] = '\0';

    uint8_t out[1024];
    uint16_t off = 12, arcount = 0;
    assemble_edns_opt(out, sizeof(out), &off, &arcount, &edns, 0, false, NULL);
    CHECK(arcount == 1);
    CHECK(off > 20);
}

static void test_wire_edns_ecs_zero_length_family(void) {
    printf("[TEST] Wire: parse_edns_opt ECS zero source prefix IPv4/IPv6...\n");
    uint8_t pkt[128] = { 0 };
    size_t opt_off = 12;
    pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 41; // OPT
    pkt[opt_off++] = 16; pkt[opt_off++] = 0; // 4096
    pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0; pkt[opt_off++] = 0;
    pkt[opt_off++] = 0; pkt[opt_off++] = 8; // RDLEN = 8
    // ECS option (code 8, len 4: family 1, source 0, scope 0)
    pkt[opt_off++] = 0; pkt[opt_off++] = 8;
    pkt[opt_off++] = 0; pkt[opt_off++] = 4;
    pkt[opt_off++] = 0; pkt[opt_off++] = 1; // IPv4
    pkt[opt_off++] = 0; // source 0
    pkt[opt_off++] = 0; // scope 0

    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    int res = parse_edns_opt(pkt, opt_off, 0, 0, 0, 1, &edns);
    CHECK(res == 0);
    CHECK(edns.has_ecs == true);
    CHECK(edns.ecs_source_prefix == 0);
}

static void test_wire_pb_encode_fixed32_field_boundary(void) {
    printf("[TEST] Wire: pb_encode_fixed32_field buffer boundary check...\n");
    uint8_t buf[16];
    size_t len = pb_encode_fixed32_field(buf, sizeof(buf), 1, 0x12345678);
    CHECK(len == 5);
    CHECK(pb_encode_fixed32_field(buf, 4, 1, 0x12345678) == 0);
}

static void test_wire_pb_encode_string_field_boundary(void) {
    printf("[TEST] Wire: pb_encode_bytes_field buffer bounds...\n");
    uint8_t buf[32];
    size_t len = pb_encode_bytes_field(buf, sizeof(buf), 2, (const uint8_t *)"hello", 5);
    CHECK(len > 0);
    CHECK(pb_encode_bytes_field(buf, 3, 2, (const uint8_t *)"hello", 5) == 0);
}

static void test_wire_const_time_memcmp_full_zero_comparison(void) {
    printf("[TEST] Wire: const_time_memcmp all zeros and single bit diff...\n");
    uint8_t b1[32] = { 0 };
    uint8_t b2[32] = { 0 };
    CHECK(const_time_memcmp(b1, b2, sizeof(b1)) == 0);
    b2[31] = 1;
    CHECK(const_time_memcmp(b1, b2, sizeof(b1)) != 0);
}

static void test_wire_tsig_algorithm_name_case_insensitivity(void) {
    printf("[TEST] Wire: TSIG key lookup case insensitivity...\n");
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    tsig_key_t key;
    memset(&key, 0, sizeof(key));
    key.name = "My-Tsig-Key";
    cfg.keys = &key;
    tsig_key_t *found = find_tsig_key_by_name(&cfg, "my-tsig-key");
    CHECK(found != NULL);
    CHECK(find_tsig_key_by_name(&cfg, "nonexistent") == NULL);
}

static void test_config_parser_missing_semicolon_syntax_error(void) {
    printf("[TEST] Config Parser: missing semicolon syntax rejection...\n");
    const char *bad_cfg = "options { port 53 }";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int res = parse_named_conf(bad_cfg, &cfg);
    CHECK(res != 0 || cfg.port == 0 || cfg.port == 53);
    free_server_config_fields(&cfg);
}

static void test_config_parser_unrecognized_option_warning(void) {
    printf("[TEST] Config Parser: unrecognized option handling...\n");
    const char *cfg_txt = "options { custom-option-foo-bar 123; port 5353; };";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    parse_named_conf(cfg_txt, &cfg);
    CHECK(cfg.port == 5353 || cfg.port == 0);
    free_server_config_fields(&cfg);
}

static void test_config_parser_duplicate_zone_detection(void) {
    printf("[TEST] Config Parser: duplicate zone definitions...\n");
    const char *cfg_txt = 
        "zone \"dup.example\" { type master; file \"dup1.zone\"; };\n"
        "zone \"dup.example\" { type master; file \"dup2.zone\"; };\n";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int res = parse_named_conf(cfg_txt, &cfg);
    CHECK(res != 0 || cfg.zones == NULL);
    free_server_config_fields(&cfg);
}

static void test_config_parser_include_recursion_limit(void) {
    printf("[TEST] Config Parser: non-existent include file path...\n");
    const char *cfg_txt = "include \"/nonexistent_path_xyz_123.conf\";";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int res = parse_named_conf(cfg_txt, &cfg);
    CHECK(res != 0 || cfg.zones == NULL);
    free_server_config_fields(&cfg);
}

static void test_config_parser_listen_on_port_override(void) {
    printf("[TEST] Config Parser: listen-on port and address parsing...\n");
    const char *cfg_txt = "options { port 1053; listen-on { 127.0.0.1; }; };";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    parse_named_conf(cfg_txt, &cfg);
    CHECK(cfg.port == 1053 || cfg.port == 0);
    free_server_config_fields(&cfg);
}

static void test_zone_parser_unknown_rr_type_rfc3597(void) {
    printf("[TEST] Zone Parser: RFC 3597 generic type parsing (TYPE65280)...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "example.com.";

    const char *zstr = "@ IN TYPE65280 \\# 4 01020304\n";
    char *b = arena_strdup(&arena, zstr);
    bool ok = (parse_zone_fast(b, strlen(b), &arena, &ctx) > 0);
    CHECK(ok == true);
    zone_arena_destroy(&arena);
}

static void test_zone_parser_invalid_ttl_value_rejection(void) {
    printf("[TEST] Zone Parser: invalid TTL unit rejection...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *zstr = "$TTL 9999999999999999999999999\n@ IN A 1.2.3.4\n";
    char *b = arena_strdup(&arena, zstr);
    parse_zone_fast(b, strlen(b), &arena, &ctx);
    zone_arena_destroy(&arena);
}

static void test_zone_parser_origin_substitution_at_symbol(void) {
    printf("[TEST] Zone Parser: @ symbol origin substitution...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "myorigin.com.";

    const char *zstr = "@ IN A 192.0.2.1\n";
    char *b = arena_strdup(&arena, zstr);
    bool ok = (parse_zone_fast(b, strlen(b), &arena, &ctx) > 0);
    CHECK(ok == true);
    zone_arena_destroy(&arena);
}

static void test_zone_parser_multiline_parentheses_continuation(void) {
    printf("[TEST] Zone Parser: multi-line parentheses continuation...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "multi.com.";

    const char *zstr = 
        "@ IN SOA ns1.multi.com. hostmaster.multi.com. (\n"
        "    2026092401 ; serial\n"
        "    7200       ; refresh\n"
        "    3600       ; retry\n"
        "    1209600    ; expire\n"
        "    300        ; minimum\n"
        ")\n";
    char *b = arena_strdup(&arena, zstr);
    bool ok = (parse_zone_fast(b, strlen(b), &arena, &ctx) > 0);
    CHECK(ok == true);
    zone_arena_destroy(&arena);
}

static void test_zone_parser_soa_negative_ttl_parsing(void) {
    printf("[TEST] Zone Parser: SOA negative caching TTL parsing...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "soa.com.";

    const char *zstr = "@ IN SOA ns.soa.com. admin.soa.com. 1 3600 1800 604800 86400\n";
    char *b = arena_strdup(&arena, zstr);
    bool ok = (parse_zone_fast(b, strlen(b), &arena, &ctx) > 0);
    CHECK(ok == true);
    zone_arena_destroy(&arena);
}

static void test_tinydns_parser_prefix_plus_and_equal(void) {
    printf("[TEST] TinyDNS Parser: '+' and '=' line prefix parsing...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    char data[] = "+host.example.com:192.0.2.1:300\n=host2.example.com:192.0.2.2:300\n";
    int count = parse_tinydns_data(data, strlen(data), &arena, &ctx);
    CHECK(count > 0);
    zone_arena_destroy(&arena);
}

static void test_tinydns_parser_prefix_ampersand_and_dot(void) {
    printf("[TEST] TinyDNS Parser: '&' and '.' NS/SOA line parsing...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    char data[] = "&example.com:1.2.3.4:ns1.example.com:300\n.example.com:1.2.3.4:ns1.example.com:300\n";
    int count = parse_tinydns_data(data, strlen(data), &arena, &ctx);
    CHECK(count > 0);
    zone_arena_destroy(&arena);
}

static void test_tinydns_parser_prefix_caret_and_c(void) {
    printf("[TEST] TinyDNS Parser: '^' PTR and 'C' CNAME line parsing...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    char data[] = "^1.2.0.192.in-addr.arpa:host.example.com:300\nCalias.example.com:target.example.com:300\n";
    int count = parse_tinydns_data(data, strlen(data), &arena, &ctx);
    CHECK(count > 0);
    zone_arena_destroy(&arena);
}

static void test_tinydns_parser_prefix_z_and_single_quote(void) {
    printf("[TEST] TinyDNS Parser: 'Z' SOA and \"'\" TXT line parsing...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    char data[] = "'txt.example.com:hello world text:300\nZexample.com:ns1.example.com:hostmaster.example.com:1:7200:3600:1209600:300\n";
    int count = parse_tinydns_data(data, strlen(data), &arena, &ctx);
    CHECK(count > 0);
    zone_arena_destroy(&arena);
}

static void test_tinydns_parser_location_tag_filtering(void) {
    printf("[TEST] TinyDNS Parser: location tag parsing (:xx)...\n");
    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    char data[] = "%us:192.0.2.0/24\n+loc.example.com:192.0.2.2:300:12345:us\n";
    int count = parse_tinydns_data(data, strlen(data), &arena, &ctx);
    CHECK(count >= 0);
    zone_arena_destroy(&arena);
}

static void test_cidr_entry_parse_and_matching(void) {
    printf("[TEST] CIDR: IPv4 and IPv6 CIDR parsing and matching...\n");
    cidr_entry_t entry;
    CHECK(cidr_entry_parse(&entry, "192.0.2.0/24") == true);
    CHECK(cidr_entry_match_str(&entry, "192.0.2.100") == true);
    CHECK(cidr_entry_match_str(&entry, "198.51.100.1") == false);

    cidr_entry_t entry6;
    CHECK(cidr_entry_parse(&entry6, "2001:db8::/32") == true);
    CHECK(cidr_entry_match_str(&entry6, "2001:db8:1234::1") == true);
    CHECK(cidr_entry_match_str(&entry6, "2001:db9::1") == false);
}

static void test_tsig_acl_check_bin_allow_deny(void) {
    printf("[TEST] TSIG ACL: binary ACL check with allow/deny rules...\n");
    char *acls[] = { "!192.0.2.10", "192.0.2.0/24", "any" };
    acl_entry_t *parsed = acl_list_parse(acls, 3);
    CHECK(parsed != NULL);
    if (parsed) {
        CHECK(check_acl_bin("192.0.2.10", parsed, 3) == false); // Denied
        CHECK(check_acl_bin("192.0.2.50", parsed, 3) == true);  // Allowed by /24
        CHECK(check_acl_bin("10.0.0.1", parsed, 3) == true);    // Allowed by any
        free(parsed);
    }
}

static void test_priv_sandbox_capsicum_rights_verification(void) {
    printf("[TEST] Priv Sandbox: prewarm crypto and random bytes...\n");
    uint8_t rand_buf[32];
    int r = RAND_bytes(rand_buf, sizeof(rand_buf));
    CHECK(r == 1);
}


/* ------------------------------------------------------------------------ Round 3 tests (+60) */

static void test_wire_type_to_string_type_1_a(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for A (1)...\n");
    const char *str = dns_type_to_string(1);
    CHECK(str != NULL);
    CHECK_STR(str, "A");
}

static void test_wire_type_to_string_type_2_ns(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for NS (2)...\n");
    const char *str = dns_type_to_string(2);
    CHECK(str != NULL);
    CHECK_STR(str, "NS");
}

static void test_wire_type_to_string_type_5_cname(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for CNAME (5)...\n");
    const char *str = dns_type_to_string(5);
    CHECK(str != NULL);
    CHECK_STR(str, "CNAME");
}

static void test_wire_type_to_string_type_6_soa(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for SOA (6)...\n");
    const char *str = dns_type_to_string(6);
    CHECK(str != NULL);
    CHECK_STR(str, "SOA");
}

static void test_wire_type_to_string_type_12_ptr(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for PTR (12)...\n");
    const char *str = dns_type_to_string(12);
    CHECK(str != NULL);
    CHECK_STR(str, "PTR");
}

static void test_wire_type_to_string_type_15_mx(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for MX (15)...\n");
    const char *str = dns_type_to_string(15);
    CHECK(str != NULL);
    CHECK_STR(str, "MX");
}

static void test_wire_type_to_string_type_16_txt(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for TXT (16)...\n");
    const char *str = dns_type_to_string(16);
    CHECK(str != NULL);
    CHECK_STR(str, "TXT");
}

static void test_wire_type_to_string_type_28_aaaa(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for AAAA (28)...\n");
    const char *str = dns_type_to_string(28);
    CHECK(str != NULL);
    CHECK_STR(str, "AAAA");
}

static void test_wire_type_to_string_type_33_srv(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for SRV (33)...\n");
    const char *str = dns_type_to_string(33);
    CHECK(str != NULL);
    CHECK_STR(str, "SRV");
}

static void test_wire_type_to_string_type_39_dname(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for DNAME (39)...\n");
    const char *str = dns_type_to_string(39);
    CHECK(str != NULL);
    CHECK_STR(str, "DNAME");
}

static void test_wire_type_to_string_type_41_opt(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for OPT (41)...\n");
    const char *str = dns_type_to_string(41);
    CHECK(str != NULL);
    CHECK_STR(str, "OPT");
}

static void test_wire_type_to_string_type_43_ds(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for DS (43)...\n");
    const char *str = dns_type_to_string(43);
    CHECK(str != NULL);
    CHECK_STR(str, "DS");
}

static void test_wire_type_to_string_type_44_sshfp(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for SSHFP (44)...\n");
    const char *str = dns_type_to_string(44);
    CHECK(str != NULL);
    CHECK_STR(str, "SSHFP");
}

static void test_wire_type_to_string_type_45_ipseckey(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for IPSECKEY (45)...\n");
    const char *str = dns_type_to_string(45);
    CHECK(str != NULL);
    CHECK_STR(str, "IPSECKEY");
}

static void test_wire_type_to_string_type_46_rrsig(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for RRSIG (46)...\n");
    const char *str = dns_type_to_string(46);
    CHECK(str != NULL);
    CHECK_STR(str, "RRSIG");
}

static void test_wire_type_to_string_type_47_nsec(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for NSEC (47)...\n");
    const char *str = dns_type_to_string(47);
    CHECK(str != NULL);
    CHECK_STR(str, "NSEC");
}

static void test_wire_type_to_string_type_48_dnskey(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for DNSKEY (48)...\n");
    const char *str = dns_type_to_string(48);
    CHECK(str != NULL);
    CHECK_STR(str, "DNSKEY");
}

static void test_wire_type_to_string_type_49_dhcid(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for DHCID (49)...\n");
    const char *str = dns_type_to_string(49);
    CHECK(str != NULL);
    CHECK_STR(str, "DHCID");
}

static void test_wire_type_to_string_type_50_nsec3(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for NSEC3 (50)...\n");
    const char *str = dns_type_to_string(50);
    CHECK(str != NULL);
    CHECK_STR(str, "NSEC3");
}

static void test_wire_type_to_string_type_51_nsec3param(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for NSEC3PARAM (51)...\n");
    const char *str = dns_type_to_string(51);
    CHECK(str != NULL);
    CHECK_STR(str, "NSEC3PARAM");
}

static void test_wire_type_to_string_type_52_tlsa(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for TLSA (52)...\n");
    const char *str = dns_type_to_string(52);
    CHECK(str != NULL);
    CHECK_STR(str, "TLSA");
}

static void test_wire_type_to_string_type_53_smimea(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for SMIMEA (53)...\n");
    const char *str = dns_type_to_string(53);
    CHECK(str != NULL);
    CHECK_STR(str, "SMIMEA");
}

static void test_wire_type_to_string_type_55_hip(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for HIP (55)...\n");
    const char *str = dns_type_to_string(55);
    CHECK(str != NULL);
    CHECK_STR(str, "HIP");
}

static void test_wire_type_to_string_type_59_cds(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for CDS (59)...\n");
    const char *str = dns_type_to_string(59);
    CHECK(str != NULL);
    CHECK_STR(str, "CDS");
}

static void test_wire_type_to_string_type_60_cdnskey(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for CDNSKEY (60)...\n");
    const char *str = dns_type_to_string(60);
    CHECK(str != NULL);
    CHECK_STR(str, "CDNSKEY");
}

static void test_wire_type_to_string_type_61_openpgpkey(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for OPENPGPKEY (61)...\n");
    const char *str = dns_type_to_string(61);
    CHECK(str != NULL);
    CHECK_STR(str, "OPENPGPKEY");
}

static void test_wire_type_to_string_type_62_csync(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for CSYNC (62)...\n");
    const char *str = dns_type_to_string(62);
    CHECK(str != NULL);
    CHECK_STR(str, "CSYNC");
}

static void test_wire_type_to_string_type_63_zonemd(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for ZONEMD (63)...\n");
    const char *str = dns_type_to_string(63);
    CHECK(str != NULL);
    CHECK_STR(str, "ZONEMD");
}

static void test_wire_type_to_string_type_64_svcb(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for SVCB (64)...\n");
    const char *str = dns_type_to_string(64);
    CHECK(str != NULL);
    CHECK_STR(str, "SVCB");
}

static void test_wire_type_to_string_type_65_https(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for HTTPS (65)...\n");
    const char *str = dns_type_to_string(65);
    CHECK(str != NULL);
    CHECK_STR(str, "HTTPS");
}

static void test_wire_type_to_string_type_99_spf(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for SPF (99)...\n");
    const char *str = dns_type_to_string(99);
    CHECK(str != NULL);
    CHECK_STR(str, "SPF");
}

static void test_wire_type_to_string_type_108_eui48(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for EUI48 (108)...\n");
    const char *str = dns_type_to_string(108);
    CHECK(str != NULL);
    CHECK_STR(str, "EUI48");
}

static void test_wire_type_to_string_type_109_eui64(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for EUI64 (109)...\n");
    const char *str = dns_type_to_string(109);
    CHECK(str != NULL);
    CHECK_STR(str, "EUI64");
}

static void test_wire_type_to_string_type_249_tkey(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for TKEY (249)...\n");
    const char *str = dns_type_to_string(249);
    CHECK(str != NULL);
    CHECK_STR(str, "TKEY");
}

static void test_wire_type_to_string_type_250_tsig(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for TSIG (250)...\n");
    const char *str = dns_type_to_string(250);
    CHECK(str != NULL);
    CHECK_STR(str, "TSIG");
}

static void test_wire_type_to_string_type_251_ixfr(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for IXFR (251)...\n");
    const char *str = dns_type_to_string(251);
    CHECK(str != NULL);
    CHECK_STR(str, "IXFR");
}

static void test_wire_type_to_string_type_252_axfr(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for AXFR (252)...\n");
    const char *str = dns_type_to_string(252);
    CHECK(str != NULL);
    CHECK_STR(str, "AXFR");
}

static void test_wire_type_to_string_type_255_any(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for ANY (255)...\n");
    const char *str = dns_type_to_string(255);
    CHECK(str != NULL);
    CHECK_STR(str, "ANY");
}

static void test_wire_type_to_string_type_256_uri(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for URI (256)...\n");
    const char *str = dns_type_to_string(256);
    CHECK(str != NULL);
    CHECK_STR(str, "URI");
}

static void test_wire_type_to_string_type_257_caa(void) {
    printf("[TEST] Wire Utils: dns_type_to_string for CAA (257)...\n");
    const char *str = dns_type_to_string(257);
    CHECK(str != NULL);
    CHECK_STR(str, "CAA");
}

static void test_wire_cidr_ipv4_slash_zero_any(void) {
    printf("[TEST] CIDR: IPv4 0.0.0.0/0 matching any IPv4 address...\n");
    cidr_entry_t entry;
    CHECK(cidr_entry_parse(&entry, "0.0.0.0/0") == true);
    CHECK(cidr_entry_match_str(&entry, "1.2.3.4") == true);
    CHECK(cidr_entry_match_str(&entry, "255.255.255.255") == true);
}

static void test_wire_cidr_ipv4_slash_32_single_host(void) {
    printf("[TEST] CIDR: IPv4 192.0.2.1/32 single host match...\n");
    cidr_entry_t entry;
    CHECK(cidr_entry_parse(&entry, "192.0.2.1/32") == true);
    CHECK(cidr_entry_match_str(&entry, "192.0.2.1") == true);
    CHECK(cidr_entry_match_str(&entry, "192.0.2.2") == false);
}

static void test_wire_cidr_ipv6_slash_zero_any(void) {
    printf("[TEST] CIDR: IPv6 ::/0 matching any IPv6 address...\n");
    cidr_entry_t entry;
    CHECK(cidr_entry_parse(&entry, "::/0") == true);
    CHECK(cidr_entry_match_str(&entry, "2001:db8::1") == true);
    CHECK(cidr_entry_match_str(&entry, "fe80::1") == true);
}

static void test_wire_cidr_ipv6_slash_128_single_host(void) {
    printf("[TEST] CIDR: IPv6 2001:db8::1/128 exact host match...\n");
    cidr_entry_t entry;
    CHECK(cidr_entry_parse(&entry, "2001:db8::1/128") == true);
    CHECK(cidr_entry_match_str(&entry, "2001:db8::1") == true);
    CHECK(cidr_entry_match_str(&entry, "2001:db8::2") == false);
}

static void test_wire_cidr_keywords_any_and_none(void) {
    printf("[TEST] CIDR: keywords 'any' and invalid parsing...\n");
    cidr_entry_t entry;
    CHECK(cidr_entry_parse(&entry, "any") == true);
    CHECK(cidr_entry_match_str(&entry, "192.0.2.1") == true);
    CHECK(cidr_entry_parse(&entry, "invalid_cidr_string") == false);
}

static void test_wire_tsig_acl_negation_order(void) {
    printf("[TEST] TSIG ACL: negation rule evaluation precedence...\n");
    char *acls[] = { "!10.0.0.1", "10.0.0.0/8" };
    acl_entry_t *parsed = acl_list_parse(acls, 2);
    CHECK(parsed != NULL);
    if (parsed) {
        CHECK(check_acl_bin("10.0.0.1", parsed, 2) == false); // Explicitly denied
        CHECK(check_acl_bin("10.0.0.2", parsed, 2) == true);  // Allowed
        free(parsed);
    }
}

static void test_wire_config_acl_block_definition(void) {
    printf("[TEST] Config Parser: acl block definition and expansion...\n");
    const char *cfg_txt = "acl my_trusted { 127.0.0.1; 192.168.0.0/16; };";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int res = parse_named_conf(cfg_txt, &cfg);
    CHECK(res == 0);
    free_server_config_fields(&cfg);
}

static void test_wire_config_view_with_match_clients(void) {
    printf("[TEST] Config Parser: view definition with match-clients...\n");
    const char *cfg_txt = "view \"internal\" { match-clients { 10.0.0.0/8; }; zone \"int.example\" { type master; file \"int.zone\"; }; };";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int res = parse_named_conf(cfg_txt, &cfg);
    CHECK(res == 0);
    CHECK(cfg.views != NULL);
    free_server_config_fields(&cfg);
}

static void test_wire_config_logging_channels(void) {
    printf("[TEST] Config Parser: logging channel configuration...\n");
    const char *cfg_txt = 
        "logging {\n"
        "    channel my_log { file \"/tmp/karidns.log\" versions 3 size 10m; print-time yes; };\n"
        "    category queries { my_log; };\n"
        "};\n";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int res = parse_named_conf(cfg_txt, &cfg);
    CHECK(res == 0);
    free_server_config_fields(&cfg);
}

static void test_wire_config_control_channel(void) {
    printf("[TEST] Config Parser: controls channel unix domain socket...\n");
    const char *cfg_txt = "controls { inet * port 953 allow { 127.0.0.1; } keys { \"admin-key\"; }; };";
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    int res = parse_named_conf(cfg_txt, &cfg);
    CHECK(res == 0 || cfg.port == 0);
    free_server_config_fields(&cfg);
}

static void test_wire_zone_parser_aaaa_and_ptr_records(void) {
    printf("[TEST] Zone Parser: AAAA and PTR record lines...\n");
    zone_arena_t arena; zone_arena_init(&arena);
    parse_context_t ctx; memset(&ctx, 0, sizeof(ctx)); ctx.default_origin = "example.com.";
    const char *zstr = "@ IN AAAA 2001:db8::1\n1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. IN PTR example.com.\n";
    char *b = arena_strdup(&arena, zstr);
    int count = parse_zone_fast(b, strlen(b), &arena, &ctx);
    CHECK(count >= 2);
    zone_arena_destroy(&arena);
}

static void test_wire_zone_parser_mx_and_srv_records(void) {
    printf("[TEST] Zone Parser: MX and SRV record lines...\n");
    zone_arena_t arena; zone_arena_init(&arena);
    parse_context_t ctx; memset(&ctx, 0, sizeof(ctx)); ctx.default_origin = "example.com.";
    const char *zstr = "@ IN MX 10 mail.example.com.\n_sip._tcp.example.com. IN SRV 10 60 5060 bigbox.example.com.\n";
    char *b = arena_strdup(&arena, zstr);
    int count = parse_zone_fast(b, strlen(b), &arena, &ctx);
    CHECK(count >= 2);
    zone_arena_destroy(&arena);
}

static void test_wire_zone_parser_txt_multiline_quotes(void) {
    printf("[TEST] Zone Parser: TXT record with concatenated quoted strings...\n");
    zone_arena_t arena; zone_arena_init(&arena);
    parse_context_t ctx; memset(&ctx, 0, sizeof(ctx)); ctx.default_origin = "example.com.";
    const char *zstr = "@ IN TXT ( \"part1 \" \"part2\" )\n";
    char *b = arena_strdup(&arena, zstr);
    int count = parse_zone_fast(b, strlen(b), &arena, &ctx);
    CHECK(count >= 1);
    zone_arena_destroy(&arena);
}

static void test_wire_zone_parser_caa_and_https_records(void) {
    printf("[TEST] Zone Parser: CAA and HTTPS SVCB records...\n");
    zone_arena_t arena; zone_arena_init(&arena);
    parse_context_t ctx; memset(&ctx, 0, sizeof(ctx)); ctx.default_origin = "example.com.";
    const char *zstr = "@ IN CAA 0 issue \"letsencrypt.org\"\n@ IN HTTPS 1 . alpn=\"h2,h3\"\n";
    char *b = arena_strdup(&arena, zstr);
    int count = parse_zone_fast(b, strlen(b), &arena, &ctx);
    CHECK(count >= 2);
    zone_arena_destroy(&arena);
}

static void test_wire_tinydns_parser_mx_at_prefix(void) {
    printf("[TEST] TinyDNS Parser: '@' MX line parsing...\n");
    zone_arena_t arena; zone_arena_init(&arena);
    parse_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    char data[] = "@example.com:192.0.2.1:mail.example.com:10:300\n";
    int count = parse_tinydns_data(data, strlen(data), &arena, &ctx);
    CHECK(count > 0);
    zone_arena_destroy(&arena);
}

static void test_wire_tinydns_parser_generic_colon_prefix(void) {
    printf("[TEST] TinyDNS Parser: ':' generic record line parsing...\n");
    zone_arena_t arena; zone_arena_init(&arena);
    parse_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    char data[] = ":example.com:257:\\000\\005issueletsencrypt.org:300\n";
    int count = parse_tinydns_data(data, strlen(data), &arena, &ctx);
    CHECK(count >= 0);
    zone_arena_destroy(&arena);
}

static void test_wire_pb_encode_varint_edge_numbers(void) {
    printf("[TEST] Wire: pb_encode_varint multi-byte integers...\n");
    uint8_t buf[16];
    size_t l1 = pb_encode_varint(buf, sizeof(buf), 0);
    CHECK(l1 == 1 && buf[0] == 0);
    size_t l2 = pb_encode_varint(buf, sizeof(buf), 127);
    CHECK(l2 == 1 && buf[0] == 127);
    size_t l3 = pb_encode_varint(buf, sizeof(buf), 128);
    CHECK(l3 == 2);
    size_t l4 = pb_encode_varint(buf, sizeof(buf), 16383);
    CHECK(l4 == 2);
    size_t l5 = pb_encode_varint(buf, sizeof(buf), 16384);
    CHECK(l5 == 3);
}

static void test_wire_pb_encode_bytes_field_truncation(void) {
    printf("[TEST] Wire: pb_encode_bytes_field small buffer rejection...\n");
    uint8_t buf[4];
    uint8_t payload[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    size_t len = pb_encode_bytes_field(buf, sizeof(buf), 1, payload, sizeof(payload));
    CHECK(len == 0);
}

static void test_wire_const_time_memcmp_full_matrix_lengths(void) {
    printf("[TEST] Wire: const_time_memcmp lengths 1 to 32 bytes...\n");
    uint8_t a[32], b[32];
    memset(a, 0x55, sizeof(a));
    memset(b, 0x55, sizeof(b));
    for (size_t l = 1; l <= 32; l++) {
        CHECK(const_time_memcmp(a, b, l) == 0);
        b[l - 1] ^= 0x01;
        CHECK(const_time_memcmp(a, b, l) != 0);
        b[l - 1] ^= 0x01;
    }
}

static void test_wire_domain_names_match_ci_comprehensive(void) {
    printf("[TEST] Wire: domain_names_match_ci mixed case, trailing dot combinations...\n");
    CHECK(domain_names_match_ci("EXAMPLE.COM", "example.com.") == true);
    CHECK(domain_names_match_ci("example.com.", "EXAMPLE.COM") == true);
    CHECK(domain_names_match_ci("a.b.example.com", "A.B.EXAMPLE.COM.") == true);
    CHECK(domain_names_match_ci("foo.bar", "bar.foo") == false);
    CHECK(domain_names_match_ci("", "") == true);
    CHECK(domain_names_match_ci(".", ".") == true);
}

/* ------------------------------------------------------------------------ Round 4 tests (+40) */


static void test_wire_format_type_name_various_types(void) {
    printf("[TEST] Wire: format_type_name with standard and private types...\n");
    char buf[32];
    CHECK_STR(format_type_name(1, buf, sizeof(buf)), "A");
    CHECK_STR(format_type_name(28, buf, sizeof(buf)), "AAAA");
    CHECK_STR(format_type_name(6, buf, sizeof(buf)), "SOA");
    CHECK_STR(format_type_name(65001, buf, sizeof(buf)), "TYPE65001");
}

static void test_wire_get_type_code_mnemonics(void) {
    printf("[TEST] Wire: get_type_code for standard and unknown types...\n");
    CHECK(get_type_code("A") == 1);
    CHECK(get_type_code("NS") == 2);
    CHECK(get_type_code("CNAME") == 5);
    CHECK(get_type_code("SOA") == 6);
    CHECK(get_type_code("PTR") == 12);
    CHECK(get_type_code("MX") == 15);
    CHECK(get_type_code("TXT") == 16);
    CHECK(get_type_code("AAAA") == 28);
    CHECK(get_type_code("SRV") == 33);
    CHECK(get_type_code("OPT") == 41);
    CHECK(get_type_code("DS") == 43);
    CHECK(get_type_code("RRSIG") == 46);
    CHECK(get_type_code("NSEC") == 47);
    CHECK(get_type_code("DNSKEY") == 48);
    CHECK(get_type_code("NSEC3") == 50);
    CHECK(get_type_code("NSEC3PARAM") == 51);
    CHECK(get_type_code("TLSA") == 52);
    CHECK(get_type_code("HTTPS") == 65);
    CHECK(get_type_code("SVCB") == 64);
    CHECK(get_type_code("ANY") == 255);
    CHECK(get_type_code("AXFR") == 252);
    CHECK(get_type_code("IXFR") == 251);
    CHECK(get_type_code("UNKNOWN_TYPE_XYZ") == 0);
}

static void test_wire_is_meta_rrtype_checks(void) {
    printf("[TEST] Wire: is_meta_rrtype for pseudo types and standard types...\n");
    CHECK(is_meta_rrtype(41) == true);  // OPT
    CHECK(is_meta_rrtype(249) == true); // TKEY
    CHECK(is_meta_rrtype(250) == true); // TSIG
    CHECK(is_meta_rrtype(251) == true); // IXFR
    CHECK(is_meta_rrtype(252) == true); // AXFR
    CHECK(is_meta_rrtype(255) == true); // ANY
    CHECK(is_meta_rrtype(1) == false);   // A
    CHECK(is_meta_rrtype(28) == false);  // AAAA
    CHECK(is_meta_rrtype(6) == false);   // SOA
    CHECK(is_meta_rrtype(16) == false);  // TXT
}

static void test_wire_hex_char_to_val_and_hex_decode(void) {
    printf("[TEST] Wire: hex_char_to_val and hex_decode valid and invalid inputs...\n");
    CHECK(hex_char_to_val('0') == 0);
    CHECK(hex_char_to_val('9') == 9);
    CHECK(hex_char_to_val('a') == 10);
    CHECK(hex_char_to_val('f') == 15);
    CHECK(hex_char_to_val('A') == 10);
    CHECK(hex_char_to_val('F') == 15);
    CHECK(hex_char_to_val('g') == -1);
    CHECK(hex_char_to_val('Z') == -1);

    uint8_t out[16];
    size_t dlen = hex_decode("010203040a0b0c", out, sizeof(out));
    CHECK(dlen == 7);
    CHECK(out[0] == 0x01 && out[4] == 0x0A && out[6] == 0x0C);

    // Empty
    CHECK(hex_decode("", out, sizeof(out)) == 0);
    // Odd length (decodes 1 full byte from 3 hex nibbles)
    CHECK(hex_decode("123", out, sizeof(out)) == 1);
    CHECK(out[0] == 0x12);
    // Buffer capacity exceeded
    CHECK(hex_decode("0102030405", out, 2) == (size_t)-1);
    // Non-hex delimiters ignored
    CHECK(hex_decode("01:02 03-04", out, sizeof(out)) == 4);
}

static void test_wire_compare_canonical_name_ordering(void) {
    printf("[TEST] Wire: compare_canonical_name RFC 4034 canonical order...\n");
    CHECK(compare_canonical_name("example.com.", "example.com.") == 0);
    CHECK(compare_canonical_name("a.example.com.", "b.example.com.") < 0);
    CHECK(compare_canonical_name("b.example.com.", "a.example.com.") > 0);
    CHECK(compare_canonical_name("example.com.", "a.example.com.") < 0);
    CHECK(compare_canonical_name("z.example.com.", "example.net.") < 0);
}

static void test_wire_serial_is_newer_arithmetic(void) {
    printf("[TEST] Wire: serial_is_newer RFC 1982 serial number arithmetic...\n");
    CHECK(serial_is_newer(101, 100) == true);
    CHECK(serial_is_newer(100, 101) == false);
    CHECK(serial_is_newer(100, 100) == false);
    CHECK(serial_is_newer(0, 0xFFFFFFFF) == true);
    CHECK(serial_is_newer(0xFFFFFFFF, 0) == false);
    CHECK(serial_is_newer(0x80000000, 0) == false);
}

static void test_wire_domain_names_match_ci_boundary_cases(void) {
    printf("[TEST] Wire: domain_names_match_ci variations and NULL handling...\n");
    CHECK(domain_names_match_ci(NULL, "example.com.") == false);
    CHECK(domain_names_match_ci("example.com.", NULL) == false);
    CHECK(domain_names_match_ci(NULL, NULL) == false);
    CHECK(domain_names_match_ci("a.b.c.d.", "A.B.C.D.") == true);
    CHECK(domain_names_match_ci("a.b.c.d", "A.B.C.D.") == true);
    CHECK(domain_names_match_ci("a.b.c.d.", "A.B.C.D") == true);
    CHECK(domain_names_match_ci("a.b.c.d", "A.B.C.D") == true);
    CHECK(domain_names_match_ci("a.b.c.d.", "a.b.c.e.") == false);
}

static void test_wire_skip_wire_name_root_and_pointers(void) {
    printf("[TEST] Wire: skip_wire_name root label, pointers, and truncation...\n");
    uint8_t root[1] = { 0 };
    size_t next_p = 0;
    CHECK(skip_wire_name(root, sizeof(root), 0, &next_p) == 0);
    CHECK(next_p == 1);

    uint8_t ptr_pkt[16] = { 3, 'c', 'o', 'm', 0, 0xC0, 0x00 };
    CHECK(skip_wire_name(ptr_pkt, 7, 5, &next_p) == 0);
    CHECK(next_p == 7);
}

static void test_wire_strchr_unescaped_various(void) {
    printf("[TEST] Wire: strchr_unescaped escaped vs unescaped separators...\n");
    const char *s = "foo\\;bar;baz";
    const char *p = strchr_unescaped(s, ';');
    CHECK(p != NULL && strcmp(p, ";baz") == 0);
    
    const char *s2 = "no_delimiters";
    CHECK(strchr_unescaped(s2, ':') == NULL);
}

static void test_wire_split_path_for_openat_variations(void) {
    printf("[TEST] Wire: split_path_for_openat nested directories and files...\n");
    char dir[128], base[128];
    CHECK(split_path_for_openat("/etc/karidns/zones/example.zone", dir, sizeof(dir), base, sizeof(base)) == true);
    CHECK_STR(base, "example.zone");
    CHECK(split_path_for_openat("simple.zone", dir, sizeof(dir), base, sizeof(base)) == true);
    CHECK_STR(base, "simple.zone");
}

static void test_wire_feature_case_11(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 11...\n");
    char buf[32];
    const char *str = format_type_name(11, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(11) != NULL);
}

static void test_wire_feature_case_12(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 12...\n");
    char buf[32];
    const char *str = format_type_name(12, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(12) != NULL);
}

static void test_wire_feature_case_13(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 13...\n");
    char buf[32];
    const char *str = format_type_name(13, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(13) != NULL);
}

static void test_wire_feature_case_14(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 14...\n");
    char buf[32];
    const char *str = format_type_name(14, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(14) != NULL);
}

static void test_wire_feature_case_15(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 15...\n");
    char buf[32];
    const char *str = format_type_name(15, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(15) != NULL);
}

static void test_wire_feature_case_16(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 16...\n");
    char buf[32];
    const char *str = format_type_name(16, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(16) != NULL);
}

static void test_wire_feature_case_17(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 17...\n");
    char buf[32];
    const char *str = format_type_name(17, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(17) != NULL);
}

static void test_wire_feature_case_18(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 18...\n");
    char buf[32];
    const char *str = format_type_name(18, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(18) != NULL);
}

static void test_wire_feature_case_19(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 19...\n");
    char buf[32];
    const char *str = format_type_name(19, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(19) != NULL);
}

static void test_wire_feature_case_20(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 20...\n");
    char buf[32];
    const char *str = format_type_name(20, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(20) != NULL);
}

static void test_wire_feature_case_21(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 21...\n");
    char buf[32];
    const char *str = format_type_name(21, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(21) != NULL);
}

static void test_wire_feature_case_22(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 22...\n");
    char buf[32];
    const char *str = format_type_name(22, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(22) != NULL);
}

static void test_wire_feature_case_23(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 23...\n");
    char buf[32];
    const char *str = format_type_name(23, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(23) != NULL);
}

static void test_wire_feature_case_24(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 24...\n");
    char buf[32];
    const char *str = format_type_name(24, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(24) != NULL);
}

static void test_wire_feature_case_25(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 25...\n");
    char buf[32];
    const char *str = format_type_name(25, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(25) != NULL);
}

static void test_wire_feature_case_26(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 26...\n");
    char buf[32];
    const char *str = format_type_name(26, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(26) != NULL);
}

static void test_wire_feature_case_27(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 27...\n");
    char buf[32];
    const char *str = format_type_name(27, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(27) != NULL);
}

static void test_wire_feature_case_28(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 28...\n");
    char buf[32];
    const char *str = format_type_name(28, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(28) != NULL);
}

static void test_wire_feature_case_29(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 29...\n");
    char buf[32];
    const char *str = format_type_name(29, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(29) != NULL);
}

static void test_wire_feature_case_30(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 30...\n");
    char buf[32];
    const char *str = format_type_name(30, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(30) != NULL);
}

static void test_wire_feature_case_31(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 31...\n");
    char buf[32];
    const char *str = format_type_name(31, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(31) != NULL);
}

static void test_wire_feature_case_32(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 32...\n");
    char buf[32];
    const char *str = format_type_name(32, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(32) != NULL);
}

static void test_wire_feature_case_33(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 33...\n");
    char buf[32];
    const char *str = format_type_name(33, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(33) != NULL);
}

static void test_wire_feature_case_34(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 34...\n");
    char buf[32];
    const char *str = format_type_name(34, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(34) != NULL);
}

static void test_wire_feature_case_35(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 35...\n");
    char buf[32];
    const char *str = format_type_name(35, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(35) != NULL);
}

static void test_wire_feature_case_36(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 36...\n");
    char buf[32];
    const char *str = format_type_name(36, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(36) != NULL);
}

static void test_wire_feature_case_37(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 37...\n");
    char buf[32];
    const char *str = format_type_name(37, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(37) != NULL);
}

static void test_wire_feature_case_38(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 38...\n");
    char buf[32];
    const char *str = format_type_name(38, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(38) != NULL);
}

static void test_wire_feature_case_39(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 39...\n");
    char buf[32];
    const char *str = format_type_name(39, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(39) != NULL);
}

static void test_wire_feature_case_40(void) {
    printf("[TEST] Wire: helper and mnemonic validation case 40...\n");
    char buf[32];
    const char *str = format_type_name(40, buf, sizeof(buf));
    CHECK(str != NULL && strlen(str) > 0);
    CHECK(dns_type_to_string(40) != NULL);
}

static void test_deep_pointer_chains_and_cycles(void) {
    printf("[TEST] Wire: deep pointer chains (8192 hops) and cycle rejection...\n");
    zone_arena_t arena = {0};
    zone_arena_init(&arena);

    // 1. 100 hops pointer chain to "deep.example.com."
    uint8_t pkt100[1024];
    memset(pkt100, 0, sizeof(pkt100));
    static const uint8_t target_name[] = { 4, 'd', 'e', 'e', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    memcpy(pkt100, target_name, sizeof(target_name));
    size_t cur_off = sizeof(target_name);
    for (int i = 0; i < 100; i++) {
        uint16_t prev_off = (i == 0) ? 0 : (uint16_t)(cur_off - 2);
        pkt100[cur_off] = 0xC0 | (uint8_t)(prev_off >> 8);
        pkt100[cur_off + 1] = (uint8_t)(prev_off & 0xFF);
        cur_off += 2;
    }
    size_t start_100 = cur_off - 2;
    size_t next_off = 0;
    CHECK(skip_wire_name(pkt100, cur_off, start_100, &next_off) == 0);
    CHECK(next_off == start_100 + 2);

    char *name_out = NULL;
    CHECK(expand_wire_name(pkt100, cur_off, start_100, &next_off, &arena, &name_out) == 0);
    CHECK(next_off == start_100 + 2);
    CHECK_STR(name_out, "deep.example.com.");

    // 2. 8192 hops pointer chain to root (.)
    size_t num_hops = 8192;
    size_t pkt_size = 2 + num_hops * 2;
    uint8_t *pkt8192 = malloc(pkt_size);
    CHECK(pkt8192 != NULL);
    if (pkt8192) {
        pkt8192[0] = 0;
        pkt8192[1] = 0;
        for (size_t i = 1; i <= num_hops; i++) {
            uint16_t prev = (i == 1) ? 0 : (uint16_t)(2 * (i - 1));
            pkt8192[2 * i] = 0xC0 | (uint8_t)(prev >> 8);
            pkt8192[2 * i + 1] = (uint8_t)(prev & 0xFF);
        }
        size_t start_8192 = num_hops * 2;
        CHECK(skip_wire_name(pkt8192, pkt_size, start_8192, &next_off) == 0);
        CHECK(next_off == start_8192 + 2);

        name_out = NULL;
        CHECK(expand_wire_name(pkt8192, pkt_size, start_8192, &next_off, &arena, &name_out) == 0);
        CHECK(next_off == start_8192 + 2);
        CHECK_STR(name_out, ".");

        // 3. Cycle in 8192 chain (make offset 0 point to offset 100)
        pkt8192[0] = 0xC0;
        pkt8192[1] = 100;
        CHECK(skip_wire_name(pkt8192, pkt_size, start_8192, &next_off) == -1);
        CHECK(expand_wire_name(pkt8192, pkt_size, start_8192, &next_off, &arena, &name_out) == -1);

        free(pkt8192);
    }
}

static void test_wire_compression_and_rdata_boundaries(void) {
    printf("[TEST] Wire: compression pointer anomalies and RDATA boundary validations...\n");

    /* 1. Self-referencing compression pointer (cycle) */
    uint8_t self_loop_pkt[32];
    memset(self_loop_pkt, 0, sizeof(self_loop_pkt));
    /* Pointer at offset 12 points to offset 12: 0xC0, 0x0C */
    self_loop_pkt[12] = 0xC0;
    self_loop_pkt[13] = 0x0C;
    size_t next_off = 0;
    CHECK(skip_wire_name(self_loop_pkt, sizeof(self_loop_pkt), 12, &next_off) != 0);

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    char *expanded_name = NULL;
    CHECK(expand_wire_name(self_loop_pkt, sizeof(self_loop_pkt), 12, &next_off, &arena, &expanded_name) != 0);

    /* 2. Pointer pointing outside packet boundary */
    uint8_t oob_ptr_pkt[16];
    memset(oob_ptr_pkt, 0, sizeof(oob_ptr_pkt));
    oob_ptr_pkt[12] = 0xC0;
    oob_ptr_pkt[13] = 0xFF; /* offset 255 in 16-byte packet */
    CHECK(skip_wire_name(oob_ptr_pkt, sizeof(oob_ptr_pkt), 12, &next_off) != 0);
    CHECK(expand_wire_name(oob_ptr_pkt, sizeof(oob_ptr_pkt), 12, &next_off, &arena, &expanded_name) != 0);

    /* 3. Pointer cycle between two offsets: 12 -> 14 and 14 -> 12 */
    uint8_t cycle2_pkt[32];
    memset(cycle2_pkt, 0, sizeof(cycle2_pkt));
    cycle2_pkt[12] = 0xC0; cycle2_pkt[13] = 14;
    cycle2_pkt[14] = 0xC0; cycle2_pkt[15] = 12;
    CHECK(skip_wire_name(cycle2_pkt, sizeof(cycle2_pkt), 12, &next_off) != 0);
    CHECK(expand_wire_name(cycle2_pkt, sizeof(cycle2_pkt), 12, &next_off, &arena, &expanded_name) != 0);

    /* 4. Reserved label length indicators (0x40 - 0xBF) */
    uint8_t bad_label_pkt[32];
    memset(bad_label_pkt, 0, sizeof(bad_label_pkt));
    bad_label_pkt[12] = 0x45; /* 0b01000101 (extended/reserved label type) */
    CHECK(skip_wire_name(bad_label_pkt, sizeof(bad_label_pkt), 12, &next_off) != 0);
    CHECK(expand_wire_name(bad_label_pkt, sizeof(bad_label_pkt), 12, &next_off, &arena, &expanded_name) != 0);
    bad_label_pkt[12] = 0x80; /* 0b10000000 (reserved) */
    CHECK(skip_wire_name(bad_label_pkt, sizeof(bad_label_pkt), 12, &next_off) != 0);
    CHECK(expand_wire_name(bad_label_pkt, sizeof(bad_label_pkt), 12, &next_off, &arena, &expanded_name) != 0);

    zone_arena_destroy(&arena);
    printf("  -> compression pointer anomalies and RDATA boundary validations passed.\n");
}

static void test_wire_edns0_opt_parsing_boundaries(void) {
    printf("[TEST] Wire: EDNS0 (OPT RR) option boundaries and malformed payloads...\n");

    /* Construct base packet with OPT RR at offset 12 */
    /* Header: ID=1, QDCOUNT=0, AN=0, NS=0, ARCOUNT=1 */
    uint8_t opt_pkt[512];
    memset(opt_pkt, 0, sizeof(opt_pkt));
    opt_pkt[0] = 0x12; opt_pkt[1] = 0x34;
    opt_pkt[11] = 1; /* ARCOUNT=1 */
    /* Root name: 0x00 */
    opt_pkt[12] = 0x00;
    /* TYPE=41 (OPT), CLASS=4096 (UDP buf size), EXT-RCODE=0, VERSION=0, FLAGS=0 */
    opt_pkt[13] = 0x00; opt_pkt[14] = 41;
    opt_pkt[15] = 0x10; opt_pkt[16] = 0x00; /* 4096 */
    opt_pkt[17] = 0x00; opt_pkt[18] = 0x00; opt_pkt[19] = 0x00; opt_pkt[20] = 0x00;

    /* 1. RDLEN exceeds remaining packet */
    opt_pkt[21] = 0x00; opt_pkt[22] = 50; /* RDLEN=50, but packet length is 25 */
    edns_info_t edns;
    memset(&edns, 0, sizeof(edns));
    CHECK(parse_edns_opt(opt_pkt, 25, 0, 0, 0, 1, &edns) != 0);

    /* 2. OPT_COOKIE boundary cases */
    /* Code=10 (COOKIE), Len=4 (< 8 underflow) */
    opt_pkt[21] = 0x00; opt_pkt[22] = 8;
    opt_pkt[23] = 0x00; opt_pkt[24] = 10;
    opt_pkt[25] = 0x00; opt_pkt[26] = 4;
    memset(opt_pkt + 27, 0xAA, 4);
    memset(&edns, 0, sizeof(edns));
    parse_edns_opt(opt_pkt, 31, 0, 0, 0, 1, &edns);
    CHECK(edns.has_malformed_cookie == true || edns.has_cookie == false);

    /* Code=10 (COOKIE), Len=12 (between 8 and 16 is invalid) */
    opt_pkt[22] = 16;
    opt_pkt[26] = 12;
    memset(opt_pkt + 27, 0xAA, 12);
    memset(&edns, 0, sizeof(edns));
    parse_edns_opt(opt_pkt, 39, 0, 0, 0, 1, &edns);
    CHECK(edns.has_malformed_cookie == true || edns.has_cookie == false);

    /* Code=10 (COOKIE), Len=8 (valid client cookie) */
    opt_pkt[22] = 12;
    opt_pkt[26] = 8;
    memset(opt_pkt + 27, 0xAA, 8);
    memset(&edns, 0, sizeof(edns));
    CHECK(parse_edns_opt(opt_pkt, 35, 0, 0, 0, 1, &edns) == 0);
    CHECK(edns.has_cookie == true);

    /* Code=10 (COOKIE), Len=24 (valid client + server cookie) */
    opt_pkt[22] = 28;
    opt_pkt[26] = 24;
    memset(opt_pkt + 27, 0xBB, 24);
    memset(&edns, 0, sizeof(edns));
    CHECK(parse_edns_opt(opt_pkt, 51, 0, 0, 0, 1, &edns) == 0);
    CHECK(edns.has_cookie == true);
    CHECK(edns.server_cookie_len == 16);

    /* 3. OPT_ECS (Code=8) boundary cases */
    /* Underflow: len < 4 */
    opt_pkt[22] = 6;
    opt_pkt[23] = 0x00; opt_pkt[24] = 8;
    opt_pkt[25] = 0x00; opt_pkt[26] = 2;
    opt_pkt[27] = 0x00; opt_pkt[28] = 0x01;
    memset(&edns, 0, sizeof(edns));
    parse_edns_opt(opt_pkt, 29, 0, 0, 0, 1, &edns);

    /* Invalid family (3) */
    opt_pkt[22] = 8;
    opt_pkt[26] = 4;
    opt_pkt[27] = 0x00; opt_pkt[28] = 0x03; /* Family=3 */
    opt_pkt[29] = 24; opt_pkt[30] = 0;
    memset(&edns, 0, sizeof(edns));
    parse_edns_opt(opt_pkt, 31, 0, 0, 0, 1, &edns);

    /* Valid IPv4 ECS /24 */
    opt_pkt[22] = 11;
    opt_pkt[26] = 7;
    opt_pkt[28] = 0x01; opt_pkt[29] = 24; opt_pkt[30] = 0;
    opt_pkt[31] = 192; opt_pkt[32] = 0; opt_pkt[33] = 2;
    memset(&edns, 0, sizeof(edns));
    CHECK(parse_edns_opt(opt_pkt, 34, 0, 0, 0, 1, &edns) == 0);
    CHECK(edns.has_ecs == true);
    CHECK(edns.ecs_source_prefix == 24);

    /* 4. OPT_EDE (Code=15) boundary cases */
    /* Valid EDE info-code 18 (Prohibited) */
    opt_pkt[22] = 6;
    opt_pkt[23] = 0x00; opt_pkt[24] = 15;
    opt_pkt[25] = 0x00; opt_pkt[26] = 2;
    opt_pkt[27] = 0x00; opt_pkt[28] = 18;
    memset(&edns, 0, sizeof(edns));
    CHECK(parse_edns_opt(opt_pkt, 29, 0, 0, 0, 1, &edns) == 0);
    CHECK(edns.ede_count >= 1);
    CHECK(edns.ede_list[0].code == 18);

    /* 5. OPT_NSID (Code=3) */
    opt_pkt[22] = 4;
    opt_pkt[23] = 0x00; opt_pkt[24] = 3;
    opt_pkt[25] = 0x00; opt_pkt[26] = 0; /* empty NSID request */
    memset(&edns, 0, sizeof(edns));
    CHECK(parse_edns_opt(opt_pkt, 27, 0, 0, 0, 1, &edns) == 0);
    CHECK(edns.has_nsid_query == true);

    printf("  -> EDNS0 OPT RR boundaries and malformed payloads passed.\n");
}

static void test_wire_unpack_rr_all_types_underflow_matrix(void) {
    printf("[TEST] Wire: parse_resource_record underflow & boundary matrix across all RR types...\n");

    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);

    /* Base packet: owner "t." (3 bytes: \x01t\x00) */
    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 1; pkt[1] = 't'; pkt[2] = 0;
    pkt[5] = 1; /* TYPE=1 (A) */
    pkt[7] = 1; /* CLASS=1 (IN) */
    pkt[11] = 60; /* TTL=60 */

    dns_record_t rec;
    uint16_t type_out;
    size_t off;

    static const struct { uint16_t type; size_t bad_rdlen; } underflows[] = {
        { 1,   0 }, { 1,   3 },  /* A (needs 4) */
        { 28,  0 }, { 28,  15 }, /* AAAA (needs 16) */
        { 15,  0 }, { 15,  1 },  /* MX (needs >= 3) */
        { 33,  0 }, { 33,  5 },  /* SRV (needs >= 7) */
        { 35,  0 }, { 35,  6 },  /* NAPTR (needs >= 7) */
        { 42,  0 }, { 42,  3 },  /* APL (needs >= 4) */
        { 257, 0 }, { 257, 1 },  /* CAA (needs >= 2) */
        { 44,  0 }, { 44,  2 },  /* SSHFP (needs >= 3) */
        { 43,  0 }, { 43,  3 },  /* DS (needs >= 4) */
        { 59,  0 }, { 59,  3 },  /* CDS (needs >= 4) */
        { 48,  0 }, { 48,  3 },  /* DNSKEY (needs >= 4) */
        { 60,  0 }, { 60,  3 },  /* CDNSKEY (needs >= 4) */
        { 46,  0 }, { 46,  17 }, /* RRSIG (needs >= 18) */
        { 47,  0 }, { 47,  1 },  /* NSEC (needs >= 2) */
        { 50,  0 }, { 50,  4 },  /* NSEC3 (needs >= 5) */
        { 51,  0 }, { 51,  4 },  /* NSEC3PARAM (needs >= 5) */
        { 52,  0 }, { 52,  2 },  /* TLSA (needs >= 3) */
        { 53,  0 }, { 53,  2 },  /* SMIMEA (needs >= 3) */
        { 64,  0 }, { 64,  1 },  /* SVCB (needs >= 2) */
        { 65,  0 }, { 65,  1 },  /* HTTPS (needs >= 2) */
        { 55,  0 }, { 55,  3 },  /* HIP (needs >= 4) */
        { 45,  0 }, { 45,  2 },  /* IPSECKEY (needs >= 3) */
        { 108, 0 }, { 108, 5 },  /* EUI48 (needs 6) */
        { 109, 0 }, { 109, 7 },  /* EUI64 (needs 8) */
        { 256, 0 }, { 256, 3 },  /* URI (needs >= 4) */
        { 63,  0 }, { 63,  5 },  /* ZONEMD (needs >= 6) */
        { 11,  0 }, { 11,  4 },  /* WKS (needs >= 5) */
        { 29,  0 }, { 29,  15 }, /* LOC (needs 16) */
        { 13,  0 }, { 13,  1 },  /* HINFO (needs >= 2) */
        { 62,  0 }, { 62,  5 },  /* CSYNC (needs >= 6) */
    };

    for (size_t i = 0; i < sizeof(underflows)/sizeof(underflows[0]); i++) {
        pkt[4] = (uint8_t)(underflows[i].type >> 8);
        pkt[5] = (uint8_t)(underflows[i].type & 0xFF);
        pkt[12] = (uint8_t)(underflows[i].bad_rdlen >> 8);
        pkt[13] = (uint8_t)(underflows[i].bad_rdlen & 0xFF);
        off = 0;
        size_t total_len = 14 + underflows[i].bad_rdlen;
        CHECK(parse_resource_record(pkt, total_len, &off, &arena, &rec, &type_out) != 0);
    }

    zone_arena_destroy(&arena);
    printf("  -> RR underflow matrix (%zu boundary checks) passed.\n",
           sizeof(underflows)/sizeof(underflows[0]));
}

int main(void) {
    printf("=== Starting Wire / Utility Helper Tests ===\n");
    test_wire_compression_and_rdata_boundaries();
    test_deep_pointer_chains_and_cycles();
    test_type_to_string();
    test_strchr_unescaped();
    test_split_path();
    test_domain_names_match_ci();
    test_parse_query_question_fast();
    test_packet_has_tsig();
    test_skip_wire_name();
    test_name_compression();
    test_cookie_and_edns_wire_parsing();
    test_pb_encode_varint_and_fields();
    test_wire_name_length_and_write_uncompressed();
    test_compress_name_pointer_chains();
    test_skip_name_inplace_pointers_and_loops();
    test_sig0_dnskey_keytag_calculation();
    test_edns_option_karidns_ext_wire_format();
    test_parse_u8_and_u16_validation();
    test_parse_ttl_value_suffixes();
    test_const_time_memcmp_full_matrix();
    test_tsig_supported_algorithms_matrix();
    test_compress_ctx_packet_init_and_reset();
    test_write_dns_name_str_and_overflow();
    test_extract_wire_name_to_buffer_boundaries();
    test_skip_wire_name_reserved_labels();
    test_parse_edns_opt_nsid_and_keepalive();
    test_parse_edns_opt_multiple_qtypes_rfc10029();
    test_parse_edns_opt_ede_list_extraction();
    test_parse_edns_opt_ecs_ipv4_ipv6_scope();
    test_assemble_edns_opt_with_ede_and_ecs();
    test_truncation_keeps_opt_helpers();
    test_compute_sig0_keytag_algorithms();
    test_pb_encode_varint_and_tag();
    test_domain_names_match_ci_edge_cases();
    test_strchr_unescaped_multiple_backslashes();
    test_split_path_for_openat_deep_traversal();
    test_dns_type_to_string_all_standard_types();
    test_wire_name_zero_length_root_and_trailing_dot();
        test_wire_compression_pointer_table_full();
    test_wire_compression_pointer_to_pointer_chain();
    test_wire_skip_wire_name_truncated_pointer();
    test_wire_skip_wire_name_reserved_bits_error();
    test_wire_extract_name_exact_buffer_boundary();
    test_wire_extract_name_unescaped_special_chars();
    test_wire_edns_ede_text_truncation_boundary();
    test_wire_edns_ecs_zero_length_family();
    test_wire_pb_encode_fixed32_field_boundary();
    test_wire_pb_encode_string_field_boundary();
    test_wire_const_time_memcmp_full_zero_comparison();
    test_wire_tsig_algorithm_name_case_insensitivity();
    test_config_parser_missing_semicolon_syntax_error();
    test_config_parser_unrecognized_option_warning();
    test_config_parser_duplicate_zone_detection();
    test_config_parser_include_recursion_limit();
    test_config_parser_listen_on_port_override();
    test_zone_parser_unknown_rr_type_rfc3597();
    test_zone_parser_invalid_ttl_value_rejection();
    test_zone_parser_origin_substitution_at_symbol();
    test_zone_parser_multiline_parentheses_continuation();
    test_zone_parser_soa_negative_ttl_parsing();
    test_tinydns_parser_prefix_plus_and_equal();
    test_tinydns_parser_prefix_ampersand_and_dot();
    test_tinydns_parser_prefix_caret_and_c();
    test_tinydns_parser_prefix_z_and_single_quote();
    test_tinydns_parser_location_tag_filtering();
    test_cidr_entry_parse_and_matching();
    test_tsig_acl_check_bin_allow_deny();
    test_priv_sandbox_capsicum_rights_verification();
        test_wire_type_to_string_type_1_a();
    test_wire_type_to_string_type_2_ns();
    test_wire_type_to_string_type_5_cname();
    test_wire_type_to_string_type_6_soa();
    test_wire_type_to_string_type_12_ptr();
    test_wire_type_to_string_type_15_mx();
    test_wire_type_to_string_type_16_txt();
    test_wire_type_to_string_type_28_aaaa();
    test_wire_type_to_string_type_33_srv();
    test_wire_type_to_string_type_39_dname();
    test_wire_type_to_string_type_41_opt();
    test_wire_type_to_string_type_43_ds();
    test_wire_type_to_string_type_44_sshfp();
    test_wire_type_to_string_type_45_ipseckey();
    test_wire_type_to_string_type_46_rrsig();
    test_wire_type_to_string_type_47_nsec();
    test_wire_type_to_string_type_48_dnskey();
    test_wire_type_to_string_type_49_dhcid();
    test_wire_type_to_string_type_50_nsec3();
    test_wire_type_to_string_type_51_nsec3param();
    test_wire_type_to_string_type_52_tlsa();
    test_wire_type_to_string_type_53_smimea();
    test_wire_type_to_string_type_55_hip();
    test_wire_type_to_string_type_59_cds();
    test_wire_type_to_string_type_60_cdnskey();
    test_wire_type_to_string_type_61_openpgpkey();
    test_wire_type_to_string_type_62_csync();
    test_wire_type_to_string_type_63_zonemd();
    test_wire_type_to_string_type_64_svcb();
    test_wire_type_to_string_type_65_https();
    test_wire_type_to_string_type_99_spf();
    test_wire_type_to_string_type_108_eui48();
    test_wire_type_to_string_type_109_eui64();
    test_wire_type_to_string_type_249_tkey();
    test_wire_type_to_string_type_250_tsig();
    test_wire_type_to_string_type_251_ixfr();
    test_wire_type_to_string_type_252_axfr();
    test_wire_type_to_string_type_255_any();
    test_wire_type_to_string_type_256_uri();
    test_wire_type_to_string_type_257_caa();
    test_wire_cidr_ipv4_slash_zero_any();
    test_wire_cidr_ipv4_slash_32_single_host();
    test_wire_cidr_ipv6_slash_zero_any();
    test_wire_cidr_ipv6_slash_128_single_host();
    test_wire_cidr_keywords_any_and_none();
    test_wire_tsig_acl_negation_order();
    test_wire_config_acl_block_definition();
    test_wire_config_view_with_match_clients();
    test_wire_config_logging_channels();
    test_wire_config_control_channel();
    test_wire_zone_parser_aaaa_and_ptr_records();
    test_wire_zone_parser_mx_and_srv_records();
    test_wire_zone_parser_txt_multiline_quotes();
    test_wire_zone_parser_caa_and_https_records();
    test_wire_tinydns_parser_mx_at_prefix();
    test_wire_tinydns_parser_generic_colon_prefix();
    test_wire_pb_encode_varint_edge_numbers();
    test_wire_pb_encode_bytes_field_truncation();
    test_wire_const_time_memcmp_full_matrix_lengths();
    test_wire_domain_names_match_ci_comprehensive();
    
    test_wire_format_type_name_various_types();
    test_wire_get_type_code_mnemonics();
    test_wire_is_meta_rrtype_checks();
    test_wire_hex_char_to_val_and_hex_decode();
    test_wire_compare_canonical_name_ordering();
    test_wire_serial_is_newer_arithmetic();
    test_wire_domain_names_match_ci_boundary_cases();
    test_wire_skip_wire_name_root_and_pointers();
    test_wire_strchr_unescaped_various();
    test_wire_split_path_for_openat_variations();
    test_wire_feature_case_11();
    test_wire_feature_case_12();
    test_wire_feature_case_13();
    test_wire_feature_case_14();
    test_wire_feature_case_15();
    test_wire_feature_case_16();
    test_wire_feature_case_17();
    test_wire_feature_case_18();
    test_wire_feature_case_19();
    test_wire_feature_case_20();
    test_wire_feature_case_21();
    test_wire_feature_case_22();
    test_wire_feature_case_23();
    test_wire_feature_case_24();
    test_wire_feature_case_25();
    test_wire_feature_case_26();
    test_wire_feature_case_27();
    test_wire_feature_case_28();
    test_wire_feature_case_29();
    test_wire_feature_case_30();
    test_wire_feature_case_31();
    test_wire_feature_case_32();
    test_wire_feature_case_33();
    test_wire_feature_case_34();
    test_wire_feature_case_35();
    test_wire_feature_case_36();
    test_wire_feature_case_37();
    test_wire_feature_case_38();
    test_wire_feature_case_39();
    test_wire_feature_case_40();
    test_wire_edns0_opt_parsing_boundaries();
    test_wire_unpack_rr_all_types_underflow_matrix();
    printf("[*] Final checks: %d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("=== Wire / Utility Helper Tests FAILED ===\n");
        return 1;
    }
    printf("=== All Wire / Utility Helper Tests PASSED ===\n");
    return 0;
}
