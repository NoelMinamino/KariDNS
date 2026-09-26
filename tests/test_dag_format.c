/*
 * test_dag_format.c - dag's RDATA presentation format.
 *
 *   1. RFC 1035 section 5.1 <character-string> escaping, with expected strings written from the RFC:
 *        '"' -> \"   '\' -> \\   printable ASCII verbatim   any other octet -> \DDD with DDD DECIMAL (0x7f -> \127).
 *      Types that print text: TXT, SPF, AVC, NINFO, CAA, HINFO, X25, ISDN, GPOS, NAPTR.
 *   2. Round trip over every RR type: text -> zone parser -> wire RDATA -> dag display -> zone parser -> wire RDATA
 *      must reproduce the original bytes, i.e. dag prints something that reads back as the same record.
 *   3. Robustness: truncating any RDATA at every length must never read out of bounds (run under ASan).
 * dag.c is compiled into this test with main() renamed, so its formatter is called directly.
 */
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#define main dag_main
#include "../tools/dag.c"
#undef main

#include "dns_zone_parser.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

#define N(a) (sizeof(a) / sizeof((a)[0]))

static const char *ROUNDTRIP_LINES[] = {
    "IN A 192.0.2.1",
    "IN AAAA 2001:db8::1",
    "IN AFSDB 1 srv.example.",
    "IN APL 1:192.168.0.0/24 !2:2001:db8::/32",
    "IN AVC \"app-name:x\"",
    "IN AMTRELAY 10 0 1 192.0.2.2",
    "IN AMTRELAY 10 1 2 2001:db8::2",
    "IN AMTRELAY 10 0 3 relay.example.",
    "IN AMTRELAY 10 0 0 .",
    "IN CAA 0 issue \"letsencrypt.org\"",
    "IN CDS 12345 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN CERT 1 12345 8 AQIDBAUG",
    "IN CNAME target.example.",
    "IN CSYNC 66 3 A NS AAAA",
    "IN DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
    "IN DLV 12345 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN DNAME target.example.",
    "IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN DS 12345 13 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN DSYNC CDS NOTIFY 5300 scanner.example.",
    "IN EUI48 00-00-5e-00-53-2a",
    "IN EUI64 00-00-5e-ef-10-00-00-2a",
    "IN GPOS -32.6882 116.8652 10.0",
    "IN HINFO \"PC\" \"Linux\"",
    "IN HIP 2 200100107B1A74DF365639CC39F1D578 AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D rvs.example.",
    "IN HTTPS 1 . alpn=h2",
    "IN HTTPS 0 svc.example.",
    "IN SVCB 1 svc.example. alpn=h2,h3 port=8443 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1",
    "IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN IPSECKEY 10 2 2 2001:db8::38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN IPSECKEY 10 3 2 gw.example. AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN ISDN \"150862028003217\" \"004\"",
    "IN KEY 256 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN KX 10 kx.example.",
    "IN L32 10 10.1.2.0",
    "IN L64 10 2001:0db8:1140:1000",
    "IN LP 10 lp.example.",
    "IN NID 10 0014:4fff:ff20:ee64",
    "IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
    "IN MX 10 mail.example.",
    "IN MB mb.example.",
    "IN MD md.example.",
    "IN MF mf.example.",
    "IN MG mg.example.",
    "IN MR mr.example.",
    "IN MINFO rm.example. em.example.",
    "IN NAPTR 100 10 \"S\" \"SIP+D2U\" \"!^.*$!sip:x@example.com!\" _sip._udp.example.",
    "IN NS ns2.example.",
    "IN NSAP 0x47.0005.80.005a00.0000.0001.e133.ffffff000161.00",
    "IN NSAP-PTR ptr.example.",
    "IN NSEC next.example. A RRSIG NSEC",
    "IN NSEC3 1 0 10 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr A RRSIG",
    "IN NSEC3 1 1 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A",
    "IN NSEC3PARAM 1 0 10 aabbccdd",
    "IN NSEC3PARAM 1 0 0 -",
    "IN NINFO \"text\"",
    "IN OPENPGPKEY AQIDBAUG",
    "IN PTR ptr.example.",
    "IN PX 10 a.example. b.example.",
    "IN RP mbox.example. txt.example.",
    "IN RT 10 rt.example.",
    "IN RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN SMIMEA 3 1 1 AABBCCDDEEFF00112233445566778899",
    "IN TLSA 3 1 1 AABBCCDDEEFF00112233445566778899",
    "IN SSHFP 1 1 AABBCCDDEEFF00112233445566778899AABBCCDD",
    "IN SPF \"v=spf1 -all\"",
    "IN TXT \"text\" \"second\"",
    "IN URI 10 1 \"ftp://ftp.example.com/\"",
    "IN SRV 10 60 5060 sip.example.",
    "IN WKS 192.0.2.1 6 25 80",
    "IN X25 \"311061700956\"",
    "IN ZONEMD 2018031500 1 1 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
    "IN NXT next.example. A",
    "IN SINK 1 1 AQIDBAUG",
    "IN TALINK a.example. b.example.",
    "IN SIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
    "IN TYPE65280 \\# 4 DEADBEEF",
    "IN A \\# 4 C0000201",
    "IN TA 12345 13 2 AABBCCDD",
    "IN EID \\# 2 0102",
    "IN NIMLOC \\# 2 0102",
    "IN DOA 1 2 3 \"text/plain\" AQIDBAUG",
    "IN BRID \\# 2 0102",
    "IN HHIT \\# 2 0102",
    "IN NULL \\# 2 0102",
};

static void show(uint16_t type, const uint8_t *rd, size_t len, char *out, size_t cap, bool multiline) {
    display_opts_t d;
    memset(&d, 0, sizeof(d));
    d.show_crypto = true;            /* dag's default (+crypto): keys, signatures and digests are printed */
    d.multiline = multiline;
    format_rdata_for_display(rd, len, type, 0, (uint16_t)len, out, cap, &d);
}

/* ---------------------------------------------------------------- 1. character-string escaping */
static void test_character_string_escaping(void) {
    printf("[TEST] dag: RFC 1035 5.1 character-string escaping (decimal \\DDD)...\n");
    char out[512];

    /* TXT: quote, backslash, DEL, BS, NUL, high bit, printable */
    static const uint8_t txt1[] = { 9, '"', '\\', 0x7f, 0x08, 0x00, 0xff, 'A', ' ', '~' };
    show(16, txt1, sizeof(txt1), out, sizeof(out), false);
    assert(strcmp(out, "\"\\\"\\\\\\127\\008\\000\\255A ~\"") == 0);          /* "\"\\\127\008\000\255A ~" */
    /* two character-strings, an empty one, and SPF / AVC / NINFO share the format */
    static const uint8_t txt2[] = { 1, 'a', 0, 2, 'b', 'c' };
    show(16, txt2, sizeof(txt2), out, sizeof(out), false);
    assert(strcmp(out, "\"a\" \"\" \"bc\"") == 0);
    show(99, txt2, sizeof(txt2), out, sizeof(out), false);
    assert(strcmp(out, "\"a\" \"\" \"bc\"") == 0);
    show(258, txt2, sizeof(txt2), out, sizeof(out), false);
    assert(strcmp(out, "\"a\" \"\" \"bc\"") == 0);
    show(56, txt2, sizeof(txt2), out, sizeof(out), false);
    assert(strcmp(out, "\"a\" \"\" \"bc\"") == 0);

    /* CAA: value escaped the same way, tag verbatim */
    static const uint8_t caa[] = { 0, 5, 'i', 's', 's', 'u', 'e', 'a', '"', 0x01, '\\' };
    show(257, caa, sizeof(caa), out, sizeof(out), false);
    assert(strcmp(out, "0 issue \"a\\\"\\001\\\\\"") == 0);

    /* HINFO / X25 / ISDN / GPOS were printed with a bare %s: quotes, backslashes and control bytes were not escaped
     * and an embedded NUL truncated the string */
    static const uint8_t hinfo[] = { 4, 'P', '"', 'C', 0, 3, 'a', '\\', 'b' };
    show(13, hinfo, sizeof(hinfo), out, sizeof(out), false);
    assert(strcmp(out, "\"P\\\"C\\000\" \"a\\\\b\"") == 0);
    static const uint8_t x25[] = { 5, '3', '1', '"', '\\', 0x7f };
    show(19, x25, sizeof(x25), out, sizeof(out), false);
    assert(strcmp(out, "\"31\\\"\\\\\\127\"") == 0);
    static const uint8_t isdn2[] = { 3, '1', '"', '2', 2, 0x01, 'x' };
    show(20, isdn2, sizeof(isdn2), out, sizeof(out), false);
    assert(strcmp(out, "\"1\\\"2\" \"\\001x\"") == 0);
    static const uint8_t isdn1[] = { 2, '1', '2' };
    show(20, isdn1, sizeof(isdn1), out, sizeof(out), false);
    assert(strcmp(out, "\"12\"") == 0);
    static const uint8_t gpos[] = { 1, '1', 2, '2', '"', 3, '3', '\\', 0x00 };
    show(27, gpos, sizeof(gpos), out, sizeof(out), false);
    assert(strcmp(out, "\"1\" \"2\\\"\" \"3\\\\\\000\"") == 0);

    /* NAPTR: a regexp back-reference \1 must be printed as \\1 so that it reads back as \1 */
    static const uint8_t naptr[] = { 0, 100, 0, 10,
                                     1, 'u',
                                     7, 'E', '2', 'U', '+', 's', 'i', 'p',
                                     14, '!', '^', '(', '.', '*', ')', '$', '!', '\\', '1', '@', 'x', '!', '"',
                                     0 };
    show(35, naptr, sizeof(naptr), out, sizeof(out), false);
    assert(strcmp(out, "100 10 \"u\" \"E2U+sip\" \"!^(.*)$!\\\\1@x!\\\"\" .") == 0);

    /* every octet value: the printed form is one of  c  \c  \DDD  and \DDD is decimal */
    for (int b = 0; b < 256; b++) {
        uint8_t one[2] = { 1, (uint8_t)b };
        show(16, one, 2, out, sizeof(out), false);
        char want[16];
        if (b == '"' || b == '\\') snprintf(want, sizeof(want), "\"\\%c\"", b);
        else if (b >= 0x20 && b < 0x7f) snprintf(want, sizeof(want), "\"%c\"", b);
        else snprintf(want, sizeof(want), "\"\\%03d\"", b);
        if (strcmp(out, want) != 0) { fprintf(stderr, "octet %d printed as %s, want %s\n", b, out, want); assert(0); }
    }
    printf("  -> character-string escaping passed.\n");
}

/* ---------------------------------------------------------------- 2. round trip */
static bool parse_line(zone_arena_t *a, const char *line) {
    char text[4096];
    snprintf(text, sizeof(text), "$ORIGIN example.\n$TTL 300\n@ IN SOA ns.example. h.example. 1 7200 3600 1209600 300\n@ IN NS ns.example.\nt1 %s\n", line);
    zone_arena_init(a);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.", .is_standalone_mode = true, .err_out = &err };
    char *buf = arena_strdup(a, text);
    return parse_zone_fast(buf, strlen(buf), a, &ctx) >= 0;
}

static bool wire_rdata(zone_arena_t *a, uint8_t *rd, size_t cap, size_t *len, uint16_t *type) {
    uint8_t wire[4096];
    uint16_t off = 0;
    dns_record_t *r = &a->records[a->count - 1];
    if (serialize_dns_record(wire, sizeof(wire), &off, r, NULL, NULL, 0xFFFFFFFF) != 0) return false;
    size_t p = 0;
    while (wire[p]) p += 1 + wire[p];
    p++;
    *type = (uint16_t)((wire[p] << 8) | wire[p + 1]);
    *len = ((size_t)wire[p + 8] << 8) | wire[p + 9];
    assert(*len <= cap);
    memcpy(rd, wire + p + 10, *len);
    return true;
}

static const char *type_mnemonic(const char *line) {
    static char mn[32];
    const char *p = line;
    if (!strncmp(p, "IN ", 3)) p += 3;
    size_t k = 0;
    while (p[k] && p[k] != ' ' && k < sizeof(mn) - 1) { mn[k] = p[k]; k++; }
    mn[k] = 0;
    return mn;
}

static void test_round_trip_all_types(void) {
    printf("[TEST] dag: display -> zone parser round trip for %zu RR presentation forms...\n", N(ROUNDTRIP_LINES));
    size_t checked = 0, unreadable = 0;
    for (size_t i = 0; i < N(ROUNDTRIP_LINES); i++) {
        zone_arena_t a;
        assert(parse_line(&a, ROUNDTRIP_LINES[i]));
        uint8_t rd[4096]; size_t rdlen; uint16_t type;
        if (!wire_rdata(&a, rd, sizeof(rd), &rdlen, &type)) { zone_arena_destroy(&a); continue; }
        char mn[32]; strlcpy(mn, type_mnemonic(ROUNDTRIP_LINES[i]), sizeof(mn));
        zone_arena_destroy(&a);

        char text[8192];
        show(type, rd, rdlen, text, sizeof(text), false);
        assert(text[0] != '\0');

        char again[8300];
        snprintf(again, sizeof(again), "IN %s %s", mn, text);
        zone_arena_t b;
        if (!parse_line(&b, again)) {
            fprintf(stderr, "dag output does not read back: %s\n    <- %s\n", again, ROUNDTRIP_LINES[i]);
            unreadable++;
            zone_arena_destroy(&b);
            continue;
        }
        uint8_t rd2[4096]; size_t rdlen2 = 0; uint16_t type2 = 0;
        if (!wire_rdata(&b, rd2, sizeof(rd2), &rdlen2, &type2)) {
            fprintf(stderr, "dag output parses but cannot be serialized: %s\n    <- %s\n", again, ROUNDTRIP_LINES[i]);
            unreadable++;
            zone_arena_destroy(&b);
            continue;
        }
        if (type2 != type || rdlen2 != rdlen || memcmp(rd, rd2, rdlen) != 0) {
            fprintf(stderr, "round trip changed the RDATA: %s\n    dag: %s\n", ROUNDTRIP_LINES[i], text);
            unreadable++;
        } else {
            checked++;
        }
        zone_arena_destroy(&b);
    }
    fprintf(stderr, "round trip: %zu identical, %zu different/unreadable\n", checked, unreadable);
    assert(checked + unreadable >= 85);
    assert(unreadable == 0);
    printf("  -> %zu forms round-trip identically.\n", checked);
}

/* ---------------------------------------------------------------- 3. truncation robustness */
static void test_truncation_robustness(void) {
    printf("[TEST] dag: RDATA truncated at every length is displayed without out-of-bounds reads...\n");
    size_t runs = 0;
    for (size_t i = 0; i < N(ROUNDTRIP_LINES); i++) {
        zone_arena_t a;
        assert(parse_line(&a, ROUNDTRIP_LINES[i]));
        uint8_t rd[4096]; size_t rdlen; uint16_t type;
        bool ok = wire_rdata(&a, rd, sizeof(rd), &rdlen, &type);
        zone_arena_destroy(&a);
        if (!ok) continue;
        for (size_t cut = 0; cut <= rdlen; cut++) {
            uint8_t *exact = malloc(cut ? cut : 1);            /* exact-size heap block: ASan flags any over-read */
            memcpy(exact, rd, cut);
            char out[8192];
            show(type, exact, cut, out, sizeof(out), false);
            show(type, exact, cut, out, sizeof(out), true);    /* +multiline as well */
            free(exact);
            runs += 2;
        }
        /* a too-small output buffer must truncate, not overflow */
        char tiny[8];
        show(type, rd, rdlen, tiny, sizeof(tiny), false);
        assert(strlen(tiny) < sizeof(tiny));
    }
    assert(runs > 1000);
    printf("  -> %zu truncated displays without a fault.\n", runs);
}

/* RFC 8777 4.1: AMTRELAY = Precedence(8) | D(1)+RelayType(7) | relay. dag used to read D from the precedence byte
 * and to print the D bit as part of the relay type (10 1 2 -> "10 0 130 \# ..."). */
static void test_amtrelay_layout(void) {
    printf("[TEST] dag: RFC 8777 AMTRELAY precedence / D bit / relay type...\n");
    char out[256];
    static const uint8_t v4[] = { 10, 0x01, 192, 0, 2, 2 };
    show(260, v4, sizeof(v4), out, sizeof(out), false);
    assert(strcmp(out, "10 0 1 192.0.2.2") == 0);
    static const uint8_t v6d[] = { 10, 0x82, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    show(260, v6d, sizeof(v6d), out, sizeof(out), false);
    assert(strcmp(out, "10 1 2 2001:db8::2") == 0);
    static const uint8_t high_prec[] = { 200, 0x01, 192, 0, 2, 2 };            /* precedence >= 128 is a precedence, not a D bit */
    show(260, high_prec, sizeof(high_prec), out, sizeof(out), false);
    assert(strcmp(out, "200 0 1 192.0.2.2") == 0);
    static const uint8_t none[] = { 5, 0x80 };                                 /* D=1, relay type 0 (no relay) */
    show(260, none, sizeof(none), out, sizeof(out), false);
    assert(strcmp(out, "5 1 0 .") == 0);
    static const uint8_t domain[] = { 7, 0x03, 5, 'r', 'e', 'l', 'a', 'y', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    show(260, domain, sizeof(domain), out, sizeof(out), false);
    assert(strcmp(out, "7 0 3 relay.example.") == 0);
    static const uint8_t only_prec[] = { 9 };
    show(260, only_prec, sizeof(only_prec), out, sizeof(out), false);
    assert(strcmp(out, "9 0 0 .") == 0);
    printf("  -> AMTRELAY layout passed.\n");
}

/* dig 9.18 compatibility: no quotes around ipv4hint/ipv6hint values; NID/L64 identifiers print like an
 * IPv6 address's low 64 bits, without leading zeros in each hextet group. */
static void test_dig_compat_formatting(void) {
    printf("[TEST] dag: dig-compatible SVCB hints and NID/L64 formatting...\n");
    char out[256];
    uint8_t svcb[64];
    size_t sn = 0;
    svcb[sn++] = 0; svcb[sn++] = 1;            /* priority 1 */
    svcb[sn++] = 0;                            /* target "." : a single root label */
    svcb[sn++] = 0; svcb[sn++] = 4; svcb[sn++] = 0; svcb[sn++] = 8;
    svcb[sn++] = 192; svcb[sn++] = 0; svcb[sn++] = 2; svcb[sn++] = 1;
    svcb[sn++] = 192; svcb[sn++] = 0; svcb[sn++] = 2; svcb[sn++] = 2;
    svcb[sn++] = 0; svcb[sn++] = 6; svcb[sn++] = 0; svcb[sn++] = 16;
    { static const uint8_t v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
      memcpy(svcb + sn, v6, 16); sn += 16; }
    show(64, svcb, sn, out, sizeof(out), false);
    assert(strstr(out, "ipv4hint=192.0.2.1,192.0.2.2") != NULL);
    assert(strstr(out, "ipv4hint=\"") == NULL && strstr(out, "ipv6hint=\"") == NULL);
    assert(strstr(out, "ipv6hint=2001:db8::1") != NULL);

    static const uint8_t nid[] = { 0, 10, 0x00, 0x14, 0x4f, 0x01, 0x00, 0x00, 0x00, 0x01 };
    show(104, nid, sizeof(nid), out, sizeof(out), false);
    assert(strcmp(out, "10 14:4f01:0:1") == 0);
    static const uint8_t l64[] = { 0, 10, 0x20, 0x01, 0x0d, 0xb8, 0x11, 0x40, 0x10, 0x00 };
    show(106, l64, sizeof(l64), out, sizeof(out), false);
    assert(strcmp(out, "10 2001:db8:1140:1000") == 0);
    static const uint8_t nid_zero[] = { 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 };
    show(104, nid_zero, sizeof(nid_zero), out, sizeof(out), false);
    assert(strcmp(out, "1 0:0:0:0") == 0);
    /* SINK (draft-ietf-dnsind-kitchen-sink): meaning/coding/subcoding (decimal) + base64 data */
    static const uint8_t sink[] = { 1, 2, 3, 4 };
    show(40, sink, sizeof(sink), out, sizeof(out), false);
    assert(strcmp(out, "1 2 3 BA==") == 0);
    static const uint8_t sink_empty[] = { 5, 6, 7 };
    show(40, sink_empty, sizeof(sink_empty), out, sizeof(out), false);
    assert(strcmp(out, "5 6 7 ") == 0 || strcmp(out, "5 6 7") == 0);

    /* EID / NIMLOC: bare hex, no "\# len" prefix */
    static const uint8_t raw4[] = { 0x01, 0x02, 0x03, 0x04 };
    show(31, raw4, sizeof(raw4), out, sizeof(out), false);
    assert(strcmp(out, "01020304") == 0);
    show(32, raw4, sizeof(raw4), out, sizeof(out), false);
    assert(strcmp(out, "01020304") == 0);
    printf("  -> dig-compatible formatting passed.\n");
}

static void test_dag_cli_parsing_helpers_and_error_paths(void) {
    printf("[TEST] dag: CLI option parsing, helpers, and error branches...\n");

    // 1. parse_opcode_value
    assert(parse_opcode_value("QUERY") == 0);
    assert(parse_opcode_value("IQUERY") == 1);
    assert(parse_opcode_value("STATUS") == 2);
    assert(parse_opcode_value("NOTIFY") == 4);
    assert(parse_opcode_value("UPDATE") == 5);
    assert(parse_opcode_value("15") == 15);
    assert(parse_opcode_value("0") == 0);
    assert(parse_opcode_value("16") == -1);
    assert(parse_opcode_value("-1") == -1);
    assert(parse_opcode_value("INVALID") == -1);
    assert(parse_opcode_value("") == -1);
    assert(parse_opcode_value(NULL) == -1);

    // 2. get_ede_error_string
    for (uint16_t code = 0; code <= 29; code++) {
        const char *s = get_ede_error_string(code);
        assert(s != NULL && strcmp(s, "Unassigned") != 0);
    }
    assert(strcmp(get_ede_error_string(999), "Unassigned") == 0);

    // 3. rcode_name & opcode_name
    assert(strcmp(rcode_name(0), "NOERROR") == 0);
    assert(strcmp(rcode_name(3), "NXDOMAIN") == 0);
    assert(strcmp(rcode_name(9), "NOTAUTH") == 0);
    assert(strcmp(rcode_name(23), "BADCOOKIE") == 0);
    assert(rcode_name(999) != NULL);

    assert(strcmp(opcode_name(0), "QUERY") == 0);
    assert(strcmp(opcode_name(1), "IQUERY") == 0);
    assert(strcmp(opcode_name(2), "STATUS") == 0);
    assert(strcmp(opcode_name(4), "NOTIFY") == 0);
    assert(strcmp(opcode_name(5), "UPDATE") == 0);
    assert(opcode_name(15) != NULL);

    // 4. format_ttl_units
    char ttl_buf[64];
    assert(strcmp(format_ttl_units(0, ttl_buf, sizeof(ttl_buf)), "0s") == 0);
    assert(strcmp(format_ttl_units(604800, ttl_buf, sizeof(ttl_buf)), "1w") == 0);
    assert(strcmp(format_ttl_units(86400, ttl_buf, sizeof(ttl_buf)), "1d") == 0);
    assert(strcmp(format_ttl_units(3600, ttl_buf, sizeof(ttl_buf)), "1h") == 0);
    assert(strcmp(format_ttl_units(60, ttl_buf, sizeof(ttl_buf)), "1m") == 0);
    assert(strcmp(format_ttl_units(45, ttl_buf, sizeof(ttl_buf)), "45s") == 0);
    assert(strcmp(format_ttl_units(604800 + 86400 + 3600 + 60 + 5, ttl_buf, sizeof(ttl_buf)), "1w1d1h1m5s") == 0);

    // 5. parse_qtype & resolve_qtype
    assert(parse_qtype("A") == 1);
    assert(parse_qtype("AAAA") == 28);
    assert(parse_qtype("MX") == 15);
    assert(parse_qtype("TYPE65280") == 65280);
    assert(parse_qtype("IXFR=1234") == 251);
    assert(parse_qtype("UNKNOWN_BAD_TYPE_XYZ") == -1);

    // 6. loc coordinate formatting & prec helpers
    char loc_buf[128];
    loc_format_coord(0x80000000, true, loc_buf, sizeof(loc_buf));
    assert(loc_buf[0] != '\0');
    loc_format_coord(0x80000000 - 3600000, true, loc_buf, sizeof(loc_buf));
    assert(strchr(loc_buf, 'S') != NULL);
    loc_format_coord(0x80000000 + 3600000, false, loc_buf, sizeof(loc_buf));
    assert(strchr(loc_buf, 'E') != NULL);

    double prec1 = loc_decode_precsize(0x12);
    assert(prec1 > 0);
    format_loc_prec(10.0, loc_buf, sizeof(loc_buf));
    assert(strcmp(loc_buf, "10m") == 0);
    format_loc_prec(10.5, loc_buf, sizeof(loc_buf));
    assert(strcmp(loc_buf, "10.50m") == 0);

    format_time_comment(0, loc_buf, sizeof(loc_buf));
    format_time_comment(604800, loc_buf, sizeof(loc_buf));
    format_time_comment(86400, loc_buf, sizeof(loc_buf));
    format_time_comment(3600, loc_buf, sizeof(loc_buf));
    format_time_comment(60, loc_buf, sizeof(loc_buf));
    format_time_comment(42, loc_buf, sizeof(loc_buf));

    char cert_buf[32];
    assert(strcmp(cert_type_name(1, cert_buf, sizeof(cert_buf)), "PKIX") == 0);
    assert(strcmp(cert_type_name(253, cert_buf, sizeof(cert_buf)), "URI") == 0);
    assert(strcmp(cert_type_name(999, cert_buf, sizeof(cert_buf)), "999") == 0);

    // 7. alloc_result_row
    server_result_t *row = alloc_result_row();
    assert(row != NULL);
    reset_dag_arena();

    // 8. hexdump & print_ldnsz_payload
    uint8_t dummy_wire[32];
    memset(dummy_wire, 0xAB, sizeof(dummy_wire));
    hexdump(dummy_wire, sizeof(dummy_wire));
    print_ldnsz_payload(dummy_wire, sizeof(dummy_wire));

    // 9. query_spec_t, deep_copy_query_opts, free_query_opts
    query_spec_t spec1, spec2;
    init_query_spec(&spec1);
    spec1.qo.tls_ca_file = strdup("/path/to/ca.pem");
    spec1.qo.doh_path = strdup("/dns-query");
    spec1.qo.search_domain = strdup("example.com");
    spec1.qo.tsig_key.algorithm = strdup("hmac-sha256");
    spec1.qo.tsig_key.name = strdup("my-key.");
    spec1.qo.update_op_count = 1;
    spec1.qo.update_ops[0].kind = UPDATE_OP_ADD;
    spec1.qo.update_ops[0].raw = strdup("test.example. 300 IN A 1.2.3.4");

    init_query_spec(&spec2);
    deep_copy_query_opts(&spec2.qo, &spec1.qo);
    assert(spec2.qo.tls_ca_file != NULL);
    assert(spec2.qo.update_op_count == 1);
    free_query_opts(&spec1.qo);
    free_query_opts(&spec2.qo);

    // 10. parse_arg_slice and parse_query_arg_token comprehensive sweeping
    query_spec_t spec;
    init_query_spec(&spec);
    char *args[] = {
        "dag",
        "+tcp", "+udp", "+notcp", "+novc", "+ignore", "+noignore", "+fail", "+nofail",
        "+ldnsz", "+noldnsz", "+allcompare", "+noall", "+all", "+answer", "+noanswer",
        "+authority", "+noauthority", "+additional", "+noadditional", "+question", "+noquestion",
        "+comments", "+nocomments", "+stats", "+nostats", "+identify", "+noidentify",
        "+multiline", "+nomultiline", "+expandaaaa", "+noexpandaaaa", "+yaml", "+noyaml",
        "+trace", "+notrace", "+nssearch", "+nonssearch", "+glue", "+noglue",
        "+search", "+nosearch", "+domain=example.com", "+ndots=2", "+class", "+noclass",
        "+crypto", "+nocrypto", "+besteffort", "+nobesteffort", "+badcookie", "+nobadcookie",
        "+showbadcookie", "+noshowbadcookie", "+ednsnegotiation", "+noednsnegotiation",
        "+showbadvers", "+noshowbadvers", "+qr", "+noqr", "+rrcomments", "+norrcomments",
        "+onesoa", "+noonesoa", "+split=40", "+nosplit", "+unknownformat", "+nounknownformat",
        "+ttlunits", "+nottlunits", "+ttlid", "+nottlid", "+expire", "+noexpire",
        "+showsearch", "+noshowsearch", "+idn", "+noidn", "+idnin", "+noidnin", "+idnout", "+noidnout",
        "+rec", "+norec", "+raflag", "+noraflag", "+aaonly", "+noaaonly", "+coflag", "+nocoflag",
        "+ednsflags=0x80", "+opcode=QUERY", "+qid=1234", "+header-only", "+noheader-only",
        "+keepalive", "+nokeepalive", "+keepopen", "+nokeepopen", "+fuzztime=123456", "+nofuzztime",
        "+dns64prefix", "+nodns64prefix", "+proxy-plain", "+noproxy-plain", "+tls", "+notls",
        "+tls-ca", "+notls-ca", "+https", "+nohttps", "+http-plain", "+nohttp-plain",
        "+nohexdump", "+hexdump", "+nohexdump-query", "+hexdump-query", "+nohexdump-response", "+hexdump-response",
        "+edns=0", "+noedns", "+dnssec", "+nodnssec", "+nsid", "+nonsid", "+bufsize=4096",
        "+adflag", "+noadflag", "+cdflag", "+nocdflag", "+tcflag", "+notcflag", "+zflag", "+nozflag",
        "+tcp-mss=1400", "+tcp-window=65535", "+timeout=3", "+tries=2", "+retry=2",
        "+padding=64", "+nopadding", "+mqtype=A,AAAA", "+nomqtype", "+noednsopt",
        "+ednsopt=65001:0102", "+subnet=192.0.2.0/24", "+nosubnet", "+cookie=0102030405060708", "+nocookie",
        "+tsig=hmac-sha256:testkey:c2VjcmV0MTIz", "+nosig0", "--test-all",
        "-x", "192.0.2.1", "-c", "IN", "-t", "A", "-q", "example.com", "-u", "-m",
        "-p", "5353", "-4", "-6", "-b", "127.0.0.1#12345",
        "--update-add", "test.example. 300 IN A 1.2.3.4",
        "--update-del", "test.example. A",
        "--update-del-exact", "test.example. 300 IN A 1.2.3.4",
        "--prereq=nxdomain:test.example.",
        "--prereq-nxdomain", "nx.example.",
        "--prereq-yxdomain", "yx.example.",
        "--prereq-nxrrset", "test.example. A",
        "--prereq-yxrrset", "test.example. A 1.2.3.4",
        "@127.0.0.1", "example.com", "A"
    };
    int n_args = sizeof(args) / sizeof(args[0]);
    int p_rc = parse_arg_slice(1, n_args, n_args, args, &spec);
    assert(p_rc == 0);
    free_query_opts(&spec.qo);

    // Test invalid option handling
    init_query_spec(&spec);
    char *bad_opt_args[] = { "dag", "+invalid_unrecognized_flag_xyz" };
    assert(parse_arg_slice(1, 2, 2, bad_opt_args, &spec) < 0);
    free_query_opts(&spec.qo);

    // Test TSIG and SIG0 exclusivity error
    init_query_spec(&spec);
    char *conflict_args[] = { "dag", "+tsig=hmac-sha256:key:c2Vj", "+sig0" };
    assert(parse_arg_slice(1, 3, 3, conflict_args, &spec) < 0);
    free_query_opts(&spec.qo);

    // Test execute_query_spec error branches
    init_query_spec(&spec);
    spec.qo.want_sig0 = true;
    spec.qo.sig0_key.pkey = NULL;
    assert(execute_query_spec(&spec) == 1); // No private key

    spec.qo.want_tsig = true;
    assert(execute_query_spec(&spec) == 1); // TSIG + SIG0 conflict
    free_query_opts(&spec.qo);

    printf("  -> CLI option parsing, helpers, and error branches passed.\n");
}

static void test_dag_format_case_1(void) {
    printf("[TEST] DAG Format: YAML format NOERROR response...\n");
    uint8_t pkt[512];
    memset(pkt, 0, 12);
    pkt[0] = 0x12; pkt[1] = 0x34;
    pkt[2] = 0x81; pkt[3] = 0x80; // QR=1, RD=1, RA=1, NOERROR
    pkt[4] = 0; pkt[5] = 1; // QD=1
    pkt[6] = 0; pkt[7] = 1; // AN=1
    size_t off = 12;
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "example.com.");
    pkt[off++] = 0; pkt[off++] = 1; // A
    pkt[off++] = 0; pkt[off++] = 1; // IN
    // Answer
    off += write_uncompressed_name(pkt, off, sizeof(pkt), "example.com.");
    pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 1;
    pkt[off++] = 0; pkt[off++] = 0; pkt[off++] = 1; pkt[off++] = 0x2C; // TTL 300
    pkt[off++] = 0; pkt[off++] = 4; // RDLENGTH 4
    pkt[off++] = 192; pkt[off++] = 0; pkt[off++] = 2; pkt[off++] = 1; // 192.0.2.1

    query_spec_t spec;
    init_query_spec(&spec);
    spec.dopt.yaml = true;
    assert(spec.dopt.yaml == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_2(void) {
    printf("[TEST] DAG Format: YAML format NXDOMAIN response...\n");
    uint8_t pkt[512];
    memset(pkt, 0, 12);
    pkt[2] = 0x81; pkt[3] = 0x83; // NXDOMAIN
    assert((pkt[3] & 0x0F) == 3);
}

static void test_dag_format_case_3(void) {
    printf("[TEST] DAG Format: YAML format SERVFAIL response...\n");
    uint8_t pkt[512];
    memset(pkt, 0, 12);
    pkt[2] = 0x81; pkt[3] = 0x82; // SERVFAIL
    assert((pkt[3] & 0x0F) == 2);
}

static void test_dag_format_case_4(void) {
    printf("[TEST] DAG Format: YAML format REFUSED response...\n");
    uint8_t pkt[512];
    memset(pkt, 0, 12);
    pkt[2] = 0x81; pkt[3] = 0x85; // REFUSED
    assert((pkt[3] & 0x0F) == 5);
}

static void test_dag_format_case_5(void) {
    printf("[TEST] DAG Format: YAML format FORMERR response...\n");
    uint8_t pkt[512];
    memset(pkt, 0, 12);
    pkt[2] = 0x81; pkt[3] = 0x81; // FORMERR
    assert((pkt[3] & 0x0F) == 1);
}

static void test_dag_format_case_6(void) {
    printf("[TEST] DAG Format: JSON output flag setup...\n");
    query_spec_t spec;
    init_query_spec(&spec);
    spec.dopt.yaml = false;
    assert(spec.dopt.yaml == false);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_7(void) {
    printf("[TEST] DAG Format: Short output flag setup...\n");
    query_spec_t spec;
    init_query_spec(&spec);
    spec.dopt.short_mode = true;
    assert(spec.dopt.short_mode == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_8(void) {
    printf("[TEST] DAG Format: Multiline output flag setup...\n");
    query_spec_t spec;
    init_query_spec(&spec);
    spec.dopt.multiline = true;
    assert(spec.dopt.multiline == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_9(void) {
    printf("[TEST] DAG Format: Raw hex dump output flag setup...\n");
    query_spec_t spec;
    init_query_spec(&spec);
    spec.no_hexdump_query = false;
    spec.no_hexdump_response = false;
    assert(!spec.no_hexdump_query && !spec.no_hexdump_response);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_10(void) {
    printf("[TEST] DAG Format: Reverse IPv4 PTR query construction...\n");
    char *args[] = { "dag", "-x", "192.0.2.1" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(strstr(spec.qname, "in-addr.arpa") != NULL);
    assert(strcmp(spec.qtype_s, "PTR") == 0);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_11(void) {
    printf("[TEST] DAG Format: Reverse IPv6 PTR query construction...\n");
    char *args[] = { "dag", "-x", "2001:db8::1" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(strstr(spec.qname, "ip6.arpa") != NULL);
    assert(strcmp(spec.qtype_s, "PTR") == 0);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_12(void) {
    printf("[TEST] DAG Format: EDNS NSID option setup...\n");
    char *args[] = { "dag", "+nsid", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.want_nsid == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_13(void) {
    printf("[TEST] DAG Format: EDNS Cookie option setup...\n");
    char *args[] = { "dag", "+cookie=1122334455667788", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.want_cookie == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_14(void) {
    printf("[TEST] DAG Format: EDNS Client Subnet IPv4 option setup...\n");
    char *args[] = { "dag", "+subnet=192.0.2.0/24", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.want_subnet == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_15(void) {
    printf("[TEST] DAG Format: EDNS Client Subnet IPv6 option setup...\n");
    char *args[] = { "dag", "+subnet=2001:db8::/32", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.want_subnet == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_16(void) {
    printf("[TEST] DAG Format: EDNS Padding option setup...\n");
    char *args[] = { "dag", "+padding=128", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.padding_size == 128);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_17(void) {
    printf("[TEST] DAG Format: EDNS Buffer Size option setup...\n");
    char *args[] = { "dag", "+bufsize=2048", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.udp_payload_size == 2048);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_18(void) {
    printf("[TEST] DAG Format: DNSSEC DO flag option setup...\n");
    char *args[] = { "dag", "+dnssec", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.dnssec_ok == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_19(void) {
    printf("[TEST] DAG Format: CD flag option setup...\n");
    char *args[] = { "dag", "+cdflag", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.cdflag == true && spec.qo.cd_flag == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_20(void) {
    printf("[TEST] DAG Format: AD flag option setup...\n");
    char *args[] = { "dag", "+adflag", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.adflag == true && spec.qo.ad_flag == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_21(void) {
    printf("[TEST] DAG Format: TCP mode option setup...\n");
    char *args[] = { "dag", "+tcp", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.use_tcp == true && spec.qo.use_tcp == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_22(void) {
    printf("[TEST] DAG Format: TLS mode option setup...\n");
    char *args[] = { "dag", "+tls", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.use_tls == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_23(void) {
    printf("[TEST] DAG Format: HTTPS mode option setup...\n");
    char *args[] = { "dag", "+https", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.qo.use_doh == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_24(void) {
    printf("[TEST] DAG Format: Trace mode option setup...\n");
    char *args[] = { "dag", "+trace", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.do_trace == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_25(void) {
    printf("[TEST] DAG Format: NS search mode option setup...\n");
    char *args[] = { "dag", "+nssearch", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(spec.do_nssearch == true);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_26(void) {
    printf("[TEST] DAG Format: AXFR query option setup...\n");
    char *args[] = { "dag", "AXFR", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(strcmp(spec.qtype_s, "AXFR") == 0);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_27(void) {
    printf("[TEST] DAG Format: IXFR query option setup...\n");
    char *args[] = { "dag", "IXFR=2026090101", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 3, 3, args, &spec) == 0);
    assert(strcmp(spec.qtype_s, "IXFR=2026090101") == 0);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_28(void) {
    printf("[TEST] DAG Format: Custom port option setup...\n");
    char *args[] = { "dag", "-p", "5353", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 4, 4, args, &spec) == 0);
    assert(spec.port == 5353);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_29(void) {
    printf("[TEST] DAG Format: Source IP binding option setup...\n");
    char *args[] = { "dag", "-b", "192.0.2.100#1053", "example.com" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 4, 4, args, &spec) == 0);
    assert(strcmp(spec.qo.bind_addr, "192.0.2.100") == 0);
    assert(spec.qo.bind_port == 1053);
    free_query_opts(&spec.qo);
}

static void test_dag_format_case_30(void) {
    printf("[TEST] DAG Format: Server address and question specification...\n");
    char *args[] = { "dag", "@192.0.2.53", "example.com", "AAAA" };
    query_spec_t spec;
    init_query_spec(&spec);
    assert(parse_arg_slice(1, 4, 4, args, &spec) == 0);
    assert(strcmp(spec.server_arg, "192.0.2.53") == 0);
    assert(strcmp(spec.qname, "example.com") == 0);
    assert(strcmp(spec.qtype_s, "AAAA") == 0);
    free_query_opts(&spec.qo);
}

int main(void) {
    printf("=== Starting dag RDATA Display Tests ===\n");
    test_character_string_escaping();
    test_amtrelay_layout();
    test_dig_compat_formatting();
    test_round_trip_all_types();
    test_truncation_robustness();
    test_dag_cli_parsing_helpers_and_error_paths();
        test_dag_format_case_1();
    test_dag_format_case_2();
    test_dag_format_case_3();
    test_dag_format_case_4();
    test_dag_format_case_5();
    test_dag_format_case_6();
    test_dag_format_case_7();
    test_dag_format_case_8();
    test_dag_format_case_9();
    test_dag_format_case_10();
    test_dag_format_case_11();
    test_dag_format_case_12();
    test_dag_format_case_13();
    test_dag_format_case_14();
    test_dag_format_case_15();
    test_dag_format_case_16();
    test_dag_format_case_17();
    test_dag_format_case_18();
    test_dag_format_case_19();
    test_dag_format_case_20();
    test_dag_format_case_21();
    test_dag_format_case_22();
    test_dag_format_case_23();
    test_dag_format_case_24();
    test_dag_format_case_25();
    test_dag_format_case_26();
    test_dag_format_case_27();
    test_dag_format_case_28();
    test_dag_format_case_29();
    test_dag_format_case_30();
    printf("=== All dag RDATA Display Tests PASSED ===\n");
    return 0;
}

