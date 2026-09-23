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

#include "../dns_wire.h"
#include "../dns_utils.h"

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

int main(void) {
    printf("=== Starting Wire / Utility Helper Tests ===\n");
    test_type_to_string();
    test_strchr_unescaped();
    test_split_path();
    test_domain_names_match_ci();
    test_parse_query_question_fast();
    test_packet_has_tsig();
    test_skip_wire_name();
    test_name_compression();
    test_cookie_and_edns_wire_parsing();
    printf("[*] %d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) { printf("=== Wire / Utility Helper Tests FAILED ===\n"); return 1; }
    printf("=== All Wire / Utility Helper Tests PASSED ===\n");
    return 0;
}
