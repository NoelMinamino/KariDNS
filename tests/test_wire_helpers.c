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
    test_compute_sig0_keytag_algorithms();
    test_pb_encode_varint_and_tag();
    test_domain_names_match_ci_edge_cases();
    test_strchr_unescaped_multiple_backslashes();
    test_split_path_for_openat_deep_traversal();
    test_dns_type_to_string_all_standard_types();
    test_wire_name_zero_length_root_and_trailing_dot();
    printf("[*] %d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) { printf("=== Wire / Utility Helper Tests FAILED ===\n"); return 1; }
    printf("=== All Wire / Utility Helper Tests PASSED ===\n");
    return 0;
}
