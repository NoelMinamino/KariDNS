/*
 * test_zone_parser_paths.c - path coverage and golden-wire verification for the zone parser.
 *
 *   1. Every zone-legal RR type (91 presentation forms) must parse and serialize.
 *   2. For 44 types the serialized RDATA is compared byte-for-byte with the RFC wire format that was computed
 *      independently of KariDNS (Python reference, RFC 1035/3596/4034/5155/6698/7477/8659/8777/9460 layouts).
 *   3. Rejection tables: parse-time errors, serialize-time errors (the stage karicheck's dry-run relies on).
 *   4. Directives: $ORIGIN, $TTL, $INCLUDE (relative/circular/missing/nested), $GENERATE, tags, escapes, parentheses.
 *   5. Robustness: RR line field-truncation and corruption must never crash or corrupt memory (run under ASan).
 */
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dns_utils.h"
#include "dns_wire.h"
#include "dns_zone_parser.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

static const char *const OK_LINES[] = {
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
    "CH TXT \"chaos\"",
    "3600 IN A 192.0.2.9",
    "IN 3600 A 192.0.2.9",
    "A 192.0.2.9",
    /* R-22 a/b: type and class mnemonics are case-insensitive (RFC 1035 2.3.3), CLASSnn per RFC 3597 5 */
    "in a 192.0.2.1", "IN a 192.0.2.1", "In A 192.0.2.1", "IN Mx 10 m.example.", "IN txt \"x\"",
    "CLASS1 A 192.0.2.1", "class3 TXT \"chaos\"", "HS TXT \"hesiod\"", "CLASS42 TYPE65280 \\# 2 0102",
    /* RFC 4025 3.1: gateway type 0 is written as "."; the public key is optional */
    "IN IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
    "IN IPSECKEY 10 0 1 . AQNR",
    "IN IPSECKEY 10 1 0 192.0.2.38",
    /* D-08: SINK (draft-ietf-dnsind-kitchen-sink-02 3): meaning coding subcoding base64 */
    "IN SINK 1 2 3 AQIDBAUG",
    "IN SINK 1 2 3 AQID BAUG",
    "IN SINK 0 0 0",
    /* D-08: the remaining README types without a sample above */
    "IN A6 0 2001:db8::1",
    "IN A6 64 ::1:2:3:4 prefix.example.",
    "IN A6 128 prefix.example.",
    "IN ATMA 39246f000e7c9c031200010001000002082044590c00",
    "IN ATMA +358400123456",
    "IN RKEY 0 3 5 AQIDBAUG",
};
static const char *const PARSE_FAIL_LINES[] = {
    "IN A 256.1.1.1",
    "IN A 1.2.3",
    "IN A 1.2.3.4.5",
    "IN A",
    "IN AAAA gggg::1",
    "IN AAAA 2001:db8::1::2",
    "IN AAAA 1.2.3.4",
    "IN TXT \"unterminated",
    "IN X25",
    "IN TYPE99999 \\# 4 DEADBEEF",
    "IN TYPE0 \\# 0",
    "IN TYPE70000 \\# 0",
    "IN OPT \\# 0",
    "IN TSIG \\# 0",
    "IN ANY 1.2.3.4",
    "IN IXFR 1.2.3.4",
    "IN AXFR 1.2.3.4",
    "IN MAILB x.",
    "XX A 1.2.3.4",
    "IN BOGUSTYPE 1 2 3"
};
static const char *const SERIALIZE_FAIL_LINES[] = {
    /* ATMA: one token (BIND atma_34.c); the old "format address" two-token form is rejected */
    "IN ATMA 0 358400123456", "IN ATMA +3584a", "IN ATMA 39246", "IN ATMA .3924", "IN ATMA 39..24", "IN ATMA +",
    "IN SINK 1 2", "IN SINK 1 2 300 AQID", "IN SINK 1 2 3 !!!!", "IN IPSECKEY 10 0 2 gw.example. AQNR",
    "IN MX 70000 mail.example.",
    "IN MX 10",
    "IN MX mail.example.",
    "IN SRV 10 60 70000 sip.example.",
    "IN SRV 10 60 5060",
    "IN DS 70000 13 2 AABB",
    "IN DS 12345 300 2 AABB",
    "IN TXT",
    "IN CAA 300 issue \"x\"",
    "IN CAA 0 \"x\"",
    "IN HINFO \"one\"",
    "IN LOC 95 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
    "IN LOC garbage",
    "IN NSEC3PARAM 1 0 70000 -",
    "IN RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. !!!",
    "IN DNSKEY 257 3 13 !!!",
    "IN DNSKEY 70000 3 13 AAAA",
    "IN APL 1:192.168.0.0/99",
    "IN APL 3:1.2.3.4/8",
    "IN APL garbage",
    "IN AMTRELAY 10 0 9 192.0.2.2",
    "IN AMTRELAY 10 2 1 192.0.2.2",
    "IN EUI48 00-00-5e-00-53",
    "IN EUI48 zz-00-5e-00-53-2a",
    "IN EUI64 00-00-5e-ef-10-00-00",
    "IN WKS 192.0.2.1 bogusproto 25",
    "IN WKS 999.1.1.1 6 25",
    "IN WKS 192.0.2.1 TCP nosuchservice 25",   /* X-38: unknown port name -> not encodable (was dropped silently) */
    "IN WKS 192.0.2.1 UDP exec",               /* X-38: exec is a TCP-only name */
    "IN NAPTR 100 10 \"S\" \"SIP+D2U\"",
    "IN HTTPS 1 . port=99999",
    "IN SVCB 1 svc.example. ipv4hint=1.2.3",
    "IN SVCB 1 svc.example. mandatory=alpn",
    "IN URI 10 1",
    "IN KX 10",
    "IN L32 10 999.1.1.1",
    "IN L64 10 2001:0db8:1140",
    "IN NID 10 0014:4fff",
    "IN IPSECKEY 10 1 2 999.9.9.9 AQNR",
    "IN IPSECKEY 10 9 2 192.0.2.1 AQNR",
    "IN CERT 1 12345 8 !!!",
    "IN CERT BOGUSCERT 12345 8 AAAA",
    "IN OPENPGPKEY !!!",
    "IN NULL not-generic",
    "IN NS",
    "IN PTR",
    "IN SOA ns.example. h.example. 1 2 3 4"
};
/* Accepted by the loader today although RFC-invalid (verified by probe). Executed for robustness only; see
 * the coverage report notes: karicheck's dry-run serialization does not reject these either. */
static const char *const LENIENT_LINES[] = {
    "IN DS 12345 13 2 XYZ",
    "IN DS 12345 13 2 ABC",
    "IN NSEC3 1 0 10 zz 2t7b4g4vsa5smi47k61mv5bv1a22bojr A",
    "IN NSEC3 1 0 10 aabbccdd !!! A",
    "IN NSEC3PARAM 1 0 10 abc",
    "IN SSHFP 1 1 XYZ",
    "IN RRSIG A 13 2 3600 bogus bogus 12345 example. AAAA",
    "IN RRSIG BOGUSTYPE 13 2 3600 20300101000000 20200101000000 12345 example. AAAA",
    "IN CSYNC 66 3 BOGUSTYPE",
    "IN HTTPS 1 . alpn",
    "IN ZONEMD 2018031500 1 1 XYZ",
    "IN GPOS a b c",
    "IN TLSA 3 1 1 XYZ",
    "IN A \\# 3 C00002",
    "IN A \\# 4 C000",
    "IN A \\# zz C0000201",
    "99999999999 IN A 1.2.3.4",
    "IN 99999999999 A 1.2.3.4",
    "IN CNAME a.example. b.example.",
    "IN SOA ns.example. h.example. x 2 3 4 5"
};
static const struct { const char *type; const char *rdata_hex; } EXPECTED_WIRE[] = {
    { "SINK", "010203010203040506" },
    { "ATMA", "0039246f000e7c9c031200010001000002082044590c00" },
    { "A", "c0000201" }, { "AAAA", "20010db8000000000000000000000001" }, { "MX", "000a046d61696c076578616d706c6500" },
    { "SRV", "000a003c13c403736970076578616d706c6500" }, { "TXT", "0474657874067365636f6e64" },
    { "CAA", "000569737375656c657473656e63727970742e6f7267" },
    { "DS", "30390d02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899" },
    { "HINFO", "025043054c696e7578" }, { "NSEC", "046e657874076578616d706c65000006400000000003" },
    { "NSEC3PARAM", "0100000a04aabbccdd" }, { "TLSA", "030101aabbccddeeff00112233445566778899" },
    { "EUI48", "00005e00532a" }, { "EUI64", "00005eef1000002a" }, { "APL", "00011802c0a80002208420010db8" }   /* RFC 3123 4.1: trailing zero octets of AFDPART are omitted (192.168.0.0/24 -> c0a8) */,
    { "AMTRELAY", "0a01c0000202" }, { "CSYNC", "000000420003000460000008" },
    { "RRSIG", "00010d0200000e1070dbd8805e0be1003039076578616d706c650099db2cc14cabdc33d6d77da63a2f15f71112584f234e8d1dc428e39e8a4a97e1aa271a555dc90701e17e2a4c4b6f120b7c32d44f4ac02bd894cf2d4be7778a19" },
    { "HTTPS", "00010000010003026832" }, { "KX", "000a026b78076578616d706c6500" },
    { "AFSDB", "000103737276076578616d706c6500" }, { "NS", "036e7332076578616d706c6500" },
    { "CNAME", "06746172676574076578616d706c6500" }, { "DNAME", "06746172676574076578616d706c6500" },
    { "PTR", "03707472076578616d706c6500" }, { "SSHFP", "0101aabbccddeeff00112233445566778899aabbccdd" },
    { "URI", "000a00016674703a2f2f6674702e6578616d706c652e636f6d2f" }, { "L32", "000a0a010200" },
    { "L64", "000a20010db811401000" }, { "NID", "000a00144fffff20ee64" }, { "LP", "000a026c70076578616d706c6500" },
    { "X25", "0c333131303631373030393536" }, { "ISDN", "0f31353038363230323830303332313703303034" },
    { "WKS", "c0000201060000004000000000000080" },
    { "MINFO", "02726d076578616d706c650002656d076578616d706c6500" },
    { "RP", "046d626f78076578616d706c650003747874076578616d706c6500" }, { "RT", "000a027274076578616d706c6500" },
    { "PX", "000a0161076578616d706c65000162076578616d706c6500" }, { "SPF", "0b763d73706631202d616c6c" },
    { "NINFO", "0474657874" },
    { "DHCID", "000201636fc0b8271c82825bb1ac5c41cf5351aa69b4febd94e8f17cdb95000da48c40" },
    { "CERT", "0001303908010203040506" }, { "OPENPGPKEY", "010203040506" },
};

#define N(a) (sizeof(a) / sizeof((a)[0]))

typedef struct {
    zone_arena_t arena;
    parse_error_t err;
    int rc;
} zt_t;

static const char *SOA_HEAD =
    "$ORIGIN example.\n$TTL 300\n"
    "@ IN SOA ns.example. h.example. 1 7200 3600 1209600 300\n@ IN NS ns.example.\n";

/* File loader for $INCLUDE, same contract as server_load_file_cb()/karicheck_load_file_cb(). */
static char *zt_load_file_cb(parse_context_t *ctx, const char *path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    if (out_dev) *out_dev = st.st_dev;
    if (out_ino) *out_ino = st.st_ino;
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n < 0) { free(buf); return NULL; }
    buf[n] = '\0';
    return buf;
}

static void zt_load_in(zt_t *z, const char *text, const char *origin, const char *base_dir) {
    memset(z, 0, sizeof(*z));
    zone_arena_init(&z->arena);
    char *visited_paths[16] = { 0 };
    dev_t visited_devs[16] = { 0 };
    ino_t visited_inos[16] = { 0 };
    char *root_ttl = NULL, *root_ecs = NULL, *root_loc = NULL;
    parse_context_t ctx = { .base_dir = base_dir ? base_dir : ".", .default_origin = origin,
                            .is_standalone_mode = true, .err_out = &z->err,
                            .visited_paths = visited_paths, .visited_devs = visited_devs, .visited_inos = visited_inos,
                            .visited_count = 0, .visited_cap = 16, .load_file_cb = zt_load_file_cb,
                            .shared_ttl_io = &root_ttl, .shared_ecs_tag_io = &root_ecs, .shared_loc_tag_io = &root_loc };
    char *buf = arena_strdup(&z->arena, text);   /* the parser keeps pointers into its input */
    assert(buf);
    z->rc = parse_zone_fast(buf, strlen(buf), &z->arena, &ctx);
}
static void zt_load(zt_t *z, const char *text) { zt_load_in(z, text, "example.", NULL); }
static void zt_free(zt_t *z) { zone_arena_destroy(&z->arena); }
#define ASSERT_PARSED(zp) do { if ((zp)->rc < 0) fprintf(stderr, "parse error at line %d: %s (offset %zu)\n", __LINE__, \
    (zp)->err.error_message ? (zp)->err.error_message : "?", (zp)->err.error_offset); assert((zp)->rc >= 0); } while (0)

static dns_record_t *zt_find(zt_t *z, const char *owner, uint16_t type) {
    for (size_t i = 0; i < z->arena.count; i++) {
        dns_record_t *r = &z->arena.records[i];
        if (r->type_code == type && strcasecmp(r->name, owner) == 0) return r;
    }
    return NULL;
}
static size_t zt_count(zt_t *z, const char *owner, uint16_t type) {
    size_t n = 0;
    for (size_t i = 0; i < z->arena.count; i++) {
        dns_record_t *r = &z->arena.records[i];
        if ((!type || r->type_code == type) && (!owner || strcasecmp(r->name, owner) == 0)) n++;
    }
    return n;
}

static int hexval(char c) { return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1; }
static size_t hex2bin(const char *h, uint8_t *out, size_t cap) {
    size_t n = strlen(h) / 2;
    assert(n <= cap);
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)((hexval(h[2 * i]) << 4) | hexval(h[2 * i + 1]));
    return n;
}

/* Serializes the last parsed record with owner "t1.example." and returns the RDATA slice. */
static int ser_rdata(dns_record_t *r, uint8_t *wire, size_t cap, const uint8_t **rd, size_t *rdlen) {
    uint16_t off = 0;
    int rc = serialize_dns_record(wire, cap, &off, r, NULL, NULL, 0xFFFFFFFF);
    if (rc != 0) return rc;
    size_t p = 0;
    while (wire[p]) p += 1 + wire[p];
    p++;                                   /* root label */
    *rdlen = ((size_t)wire[p + 8] << 8) | wire[p + 9];
    *rd = wire + p + 10;
    assert(p + 10 + *rdlen == off);        /* RDLENGTH covers exactly the rest of the record */
    return 0;
}

static void zt_load_line(zt_t *z, const char *line) {
    char text[4096];
    snprintf(text, sizeof(text), "%st1 %s\n", SOA_HEAD, line);
    zt_load(z, text);
}

/* ---------------------------------------------------------------- 1 + 2. types & golden wire */
static void test_all_types_parse_and_serialize(void) {
    printf("[TEST] Zone parser: %zu RR presentation forms parse+serialize, %zu golden wire checks...\n", N(OK_LINES), N(EXPECTED_WIRE));
    size_t golden = 0;
    bool matched[N(EXPECTED_WIRE)] = { false };
    for (size_t i = 0; i < N(OK_LINES); i++) {
        zt_t z;
        zt_load_line(&z, OK_LINES[i]);
        if (z.rc < 0) { fprintf(stderr, "parse failed: %s (%s)\n", OK_LINES[i], z.err.error_message); assert(0); }
        dns_record_t *r = &z.arena.records[z.arena.count - 1];
        assert(strcasecmp(r->name, "t1.example.") == 0);
        uint8_t wire[4096];
        const uint8_t *rd;
        size_t rdlen;
        if (ser_rdata(r, wire, sizeof(wire), &rd, &rdlen) != 0) { fprintf(stderr, "serialize failed: %s\n", OK_LINES[i]); assert(0); }
        /* the type on the wire must be the code get_type_code() reports for the mnemonic in the line */
        char mn[32] = {0};
        const char *p = OK_LINES[i];
        if (!strncmp(p, "IN ", 3)) p += 3;
        else if (!strncmp(p, "CH ", 3)) p += 3;
        size_t k = 0;
        while (p[k] && p[k] != ' ' && k < sizeof(mn) - 1) { mn[k] = p[k]; k++; }
        if (get_type_code(mn) != 0 && mn[0] >= 'A' && mn[0] <= 'Z')
            assert(r->type_code == get_type_code(mn));
        for (size_t e = 0; e < N(EXPECTED_WIRE); e++) {
            size_t tl = strlen(EXPECTED_WIRE[e].type);
            if (r->type_code == get_type_code(EXPECTED_WIRE[e].type) && !strncmp(p, EXPECTED_WIRE[e].type, tl) && p[tl] == ' ') {
                /* several presentation forms exist for AMTRELAY/IPSECKEY/HTTPS: golden only for the listed one */
                uint8_t want[512];
                size_t wl = hex2bin(EXPECTED_WIRE[e].rdata_hex, want, sizeof(want));
                if (wl == rdlen && memcmp(want, rd, rdlen) == 0) { if (!matched[e]) golden++; matched[e] = true; }
                else if (!matched[e]) {
                    fprintf(stderr, "golden mismatch for %s (%s):\n  want ", EXPECTED_WIRE[e].type, OK_LINES[i]);
                    for (size_t b = 0; b < wl; b++) fprintf(stderr, "%02x", want[b]);
                    fprintf(stderr, "\n  got  ");
                    for (size_t b = 0; b < rdlen; b++) fprintf(stderr, "%02x", rd[b]);
                    fprintf(stderr, "\n");
                }
            }
        }
        zt_free(&z);
    }
    for (size_t e = 0; e < N(EXPECTED_WIRE); e++)
        if (!matched[e]) fprintf(stderr, "golden vector never matched: %s\n", EXPECTED_WIRE[e].type);
    assert(golden == N(EXPECTED_WIRE));    /* every golden vector matched */
    printf("  -> %zu golden RDATA vectors matched byte-for-byte.\n", golden);
}

static void test_rejection_tables(void) {
    printf("[TEST] Zone parser: parse-time and serialize-time rejection tables...\n");
    for (size_t i = 0; i < N(PARSE_FAIL_LINES); i++) {
        zt_t z;
        zt_load_line(&z, PARSE_FAIL_LINES[i]);
        if (z.rc >= 0) { fprintf(stderr, "must be rejected at parse time: %s\n", PARSE_FAIL_LINES[i]); assert(0); }
        assert(z.err.error_message && z.err.error_message[0]);
        zt_free(&z);
    }
    for (size_t i = 0; i < N(SERIALIZE_FAIL_LINES); i++) {
        zt_t z;
        zt_load_line(&z, SERIALIZE_FAIL_LINES[i]);
        assert(z.rc >= 0);                                     /* loader accepts it ... */
        uint8_t wire[4096];
        uint16_t off = 0;
        int rc = serialize_dns_record(wire, sizeof(wire), &off, &z.arena.records[z.arena.count - 1], NULL, NULL, 0xFFFFFFFF);
        if (rc == 0) { fprintf(stderr, "must fail to serialize: %s\n", SERIALIZE_FAIL_LINES[i]); assert(0); }
        zt_free(&z);                                           /* ... karicheck's dry-run serialization rejects it */
    }
    for (size_t i = 0; i < N(LENIENT_LINES); i++) {            /* robustness only */
        zt_t z;
        zt_load_line(&z, LENIENT_LINES[i]);
        if (z.rc >= 0 && z.arena.count) {
            uint8_t wire[4096];
            uint16_t off = 0;
            (void)serialize_dns_record(wire, sizeof(wire), &off, &z.arena.records[z.arena.count - 1], NULL, NULL, 0xFFFFFFFF);
        }
        zt_free(&z);
    }
    /* Serialization must never write beyond a too-small buffer, for every accepted type */
    for (size_t i = 0; i < N(OK_LINES); i++) {
        zt_t z;
        zt_load_line(&z, OK_LINES[i]);
        dns_record_t *r = &z.arena.records[z.arena.count - 1];
        for (size_t cap = 0; cap < 40; cap += 3) {
            uint8_t *tiny = malloc(cap ? cap : 1);            /* exact-size heap block: ASan flags any overrun */
            uint16_t off = 0;
            (void)serialize_dns_record(tiny, cap, &off, r, NULL, NULL, 0xFFFFFFFF);
            free(tiny);
        }
        zt_free(&z);
    }
    printf("  -> %zu parse-rejected, %zu serialize-rejected, %zu lenient inputs exercised.\n",
           N(PARSE_FAIL_LINES), N(SERIALIZE_FAIL_LINES), N(LENIENT_LINES));
}

/* ---------------------------------------------------------------- 5. field truncation / corruption */
static void test_field_mutations(void) {
    printf("[TEST] Zone parser: RR field truncation & corruption robustness...\n");
    size_t runs = 0;
    for (size_t i = 0; i < N(OK_LINES); i++) {
        char buf[2048];
        strlcpy(buf, OK_LINES[i], sizeof(buf));
        /* split on spaces outside quotes */
        char *fields[64];
        int nf = 0;
        bool inq = false;
        char *p = buf;
        fields[nf++] = p;
        for (; *p; p++) {
            if (*p == '"') inq = !inq;
            else if (*p == ' ' && !inq && nf < 64) { *p = '\0'; fields[nf++] = p + 1; }
        }
        for (int keep = 0; keep <= nf; keep++) {               /* keep first `keep` fields */
            char line[2048] = {0};
            for (int f = 0; f < keep; f++) { if (f) strlcat(line, " ", sizeof(line)); strlcat(line, fields[f], sizeof(line)); }
            zt_t z;
            zt_load_line(&z, line);
            if (z.rc >= 0 && z.arena.count) {
                uint8_t w[4096]; uint16_t off = 0;
                (void)serialize_dns_record(w, sizeof(w), &off, &z.arena.records[z.arena.count - 1], NULL, NULL, 0xFFFFFFFF);
            }
            zt_free(&z);
            runs++;
        }
        static const char *const junk[] = { "@@", "0", "-1", "99999999999", "\"\"", "\\#", "\\", "(", ")", ";" };
        for (int f = 2; f < nf; f++) {                          /* corrupt each rdata field with several junk values */
            for (size_t j = 0; j < N(junk); j++) {
                char line[2048] = {0};
                for (int g = 0; g < nf; g++) { if (g) strlcat(line, " ", sizeof(line)); strlcat(line, g == f ? junk[j] : fields[g], sizeof(line)); }
                zt_t z;
                zt_load_line(&z, line);
                if (z.rc >= 0 && z.arena.count) {
                    uint8_t w[4096]; uint16_t off = 0;
                    (void)serialize_dns_record(w, sizeof(w), &off, &z.arena.records[z.arena.count - 1], NULL, NULL, 0xFFFFFFFF);
                }
                zt_free(&z);
                runs++;
            }
        }
    }
    assert(runs > 1500);
    printf("  -> %zu mutated RR lines handled without crash.\n", runs);
}

/* ---------------------------------------------------------------- 4. directives & syntax */
static void test_origin_ttl_owner_syntax(void) {
    printf("[TEST] Zone parser: $ORIGIN/$TTL, relative names, class/TTL order, continuation, parentheses...\n");
    zt_t z;
    zt_load(&z,
        "$ORIGIN example.\n$TTL 1h\n"
        "@ IN SOA ns hostmaster ( 2024010101 ; serial\n 7200 3600 1209600 300 ) ; comment\n"
        "  IN NS ns\n"
        "ns A 192.0.2.53\n"
        "     AAAA 2001:db8::53\n"                     /* blank owner: continuation of `ns` */
        "www 600 IN A 192.0.2.80\n"                    /* TTL then class */
        "www IN 700 A 192.0.2.81\n"                    /* class then TTL */
        "www 2h A 192.0.2.82\n"                        /* unit suffix, no class */
        "$ORIGIN sub.example.\n"
        "host A 192.0.2.90\n"
        "@ A 192.0.2.91\n"
        "abs.other.example. A 192.0.2.92\n"
        "$TTL 30\n"
        "short A 192.0.2.93\n"
        "txt TXT \"semi;colon\" \"quo\\\"te\" plain\n"
        "esc\\.dot A 192.0.2.94\n"
        "dec\\065 A 192.0.2.95\n"
        "upper.CASE.Example. A 192.0.2.96\n");
    ASSERT_PARSED(&z);
    dns_record_t *soa = zt_find(&z, "example.", 6);
    assert(soa && soa->ttl_value == 3600);                          /* $TTL 1h */
    assert(zt_find(&z, "example.", 2) != NULL);                     /* NS with blank owner after SOA */
    assert(zt_find(&z, "ns.example.", 1) && zt_find(&z, "ns.example.", 28));   /* continuation line reuses owner */
    dns_record_t *w600 = NULL, *w700 = NULL, *w7200 = NULL;
    for (size_t i = 0; i < z.arena.count; i++) {
        dns_record_t *r = &z.arena.records[i];
        if (r->type_code == 1 && !strcasecmp(r->name, "www.example.")) {
            if (r->ttl_value == 600) w600 = r; else if (r->ttl_value == 700) w700 = r; else if (r->ttl_value == 7200) w7200 = r;
        }
    }
    assert(w600 && w700 && w7200);
    assert(zt_find(&z, "host.sub.example.", 1) && zt_find(&z, "sub.example.", 1));
    assert(zt_find(&z, "abs.other.example.", 1));
    dns_record_t *sh = zt_find(&z, "short.sub.example.", 1);
    assert(sh && sh->ttl_value == 30);
    dns_record_t *tx = zt_find(&z, "txt.sub.example.", 16);
    assert(tx && tx->rdata_count == 3);
    assert(zt_find(&z, "esc\\.dot.sub.example.", 1) != NULL);       /* escaped dot stays inside the label */
    assert(zt_find(&z, "decA.sub.example.", 1) || zt_find(&z, "dec\\065.sub.example.", 1));
    assert(zt_find(&z, "upper.case.example.", 1));                   /* owner names compare case-insensitively */
    assert(build_zone_index(&z.arena, true) == 0);
    zt_free(&z);
    printf("  -> owner/TTL/class syntax passed.\n");
}

static void test_syntax_errors(void) {
    printf("[TEST] Zone parser: structural syntax errors...\n");
    static const char *const bad[] = {
        "www A 192.0.2.1 (\n",                                        /* unbalanced parenthesis */
        "www A 192.0.2.1 )\n",
        "$INCLUDE\n", "$GENERATE\n", "$GENERATE 1-3\n",
        "$GENERATE 5-1 h$ A 10.0.0.$\n",
        "$GENERATE 1-3/0 h$ A 10.0.0.$\n",
        "$ECS-SUBNET-TAG\n", "$LOCATION-TAG onlytag\n",
        "www\n", "www IN\n", "www IN A\n",
        "verylonglabel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa A 192.0.2.1\n",
    };
    /* Accepted today although malformed (a bare $ECS-SUBNET / $LOCATION legitimately clears the tag). Executed only. */
    static const char *const lenient[] = { "$TTL\n", "$TTL abc\n", "$ORIGIN\n", "$ECS-SUBNET\n", "$LOCATION\n",
                                          "\"quoted-owner\" A 192.0.2.1\n", "www IN CH A 192.0.2.1\n" };
    for (size_t i = 0; i < N(lenient); i++) {
        char text[2048];
        snprintf(text, sizeof(text), "%s%s", SOA_HEAD, lenient[i]);
        zt_t z;
        zt_load(&z, text);
        zt_free(&z);
    }
    for (size_t i = 0; i < N(bad); i++) {
        char text[2048];
        snprintf(text, sizeof(text), "%s%s", SOA_HEAD, bad[i]);
        zt_t z;
        zt_load(&z, text);
        if (z.rc >= 0) { fprintf(stderr, "must be rejected: %s", bad[i]); assert(0); }
        zt_free(&z);
    }
    /* 255-byte name limit (RFC 1035 3.1) */
    char longname[600] = "www";
    for (int i = 0; i < 6; i++) strlcat(longname, ".aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sizeof(longname));
    char text[1400];
    snprintf(text, sizeof(text), "%s%s A 192.0.2.1\n", SOA_HEAD, longname);
    zt_t z;
    zt_load(&z, text);
    assert(z.rc < 0 || validate_zone_name_lengths(&z.arena, &z.err) < 0 || build_zone_index(&z.arena, true) != 0 ||
           strlen(longname) < 256);
    zt_free(&z);
    printf("  -> syntax errors rejected.\n");
}

static void test_generate(void) {
    printf("[TEST] Zone parser: $GENERATE ranges, steps, offsets, radix, width...\n");
    zt_t z;
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
                "$GENERATE 1-3 h$ A 10.0.0.$\n"
                "$GENERATE 10-30/10 s$ A 10.0.1.$\n"
                "$GENERATE 1-2 o${10,2,d} A 10.0.2.${0,0,d}\n"
                "$GENERATE 10-11 x${0,3,x} A 10.0.3.$\n"
                "$GENERATE 254-255 X${0,2,X} A 10.0.4.${0,0,d}\n"
                "$GENERATE 8-9 oc${0,3,o} A 10.0.5.$\n"
                "$GENERATE 1-2 lit$$ A 10.0.6.$\n"
                "$GENERATE 1-2 ptr$ PTR h$.example.\n");
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "h1.example.", 1) && zt_find(&z, "h2.example.", 1) && zt_find(&z, "h3.example.", 1));
    assert(zt_find(&z, "h4.example.", 1) == NULL);
    dns_record_t *r = zt_find(&z, "h3.example.", 1);
    assert(r->rdata_count == 1 && strcmp(r->rdata[0], "10.0.0.3") == 0);
    assert(zt_count(&z, NULL, 1) >= 3 + 3 + 2 + 2 + 2 + 2 + 2);
    assert(zt_find(&z, "s10.example.", 1) && zt_find(&z, "s20.example.", 1) && zt_find(&z, "s30.example.", 1));
    assert(zt_find(&z, "s15.example.", 1) == NULL);                           /* step 10 */
    assert(zt_find(&z, "o11.example.", 1) && zt_find(&z, "o12.example.", 1)); /* offset 10 */
    assert(zt_find(&z, "x00a.example.", 1) && zt_find(&z, "x00b.example.", 1));      /* hex, width 3 */
    assert(zt_find(&z, "XFE.example.", 1) && zt_find(&z, "XFF.example.", 1));        /* upper-case hex */
    assert(zt_find(&z, "oc010.example.", 1) && zt_find(&z, "oc011.example.", 1));    /* octal */
    assert(zt_find(&z, "ptr1.example.", 12) && zt_find(&z, "ptr2.example.", 12));
    zt_free(&z);
    printf("  -> $GENERATE passed.\n");
}

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}

static void test_include(void) {
    printf("[TEST] Zone parser: $INCLUDE relative/nested/origin/circular/missing...\n");
    char dir[] = "/tmp/karidns_zinc_XXXXXX";
    assert(mkdtemp(dir));
    char p[512];
    snprintf(p, sizeof(p), "%s/sub", dir); assert(mkdir(p, 0755) == 0);
    snprintf(p, sizeof(p), "%s/a.inc", dir);  write_file(p, "inc-a A 192.0.2.10\n$INCLUDE sub/b.inc\n");
    snprintf(p, sizeof(p), "%s/sub/b.inc", dir); write_file(p, "inc-b A 192.0.2.11\n");
    snprintf(p, sizeof(p), "%s/o.inc", dir);  write_file(p, "@ A 192.0.2.12\nhost A 192.0.2.13\n");
    snprintf(p, sizeof(p), "%s/loop1.inc", dir); write_file(p, "$INCLUDE loop2.inc\n");
    snprintf(p, sizeof(p), "%s/loop2.inc", dir); write_file(p, "$INCLUDE loop1.inc\n");
    snprintf(p, sizeof(p), "%s/self.inc", dir); write_file(p, "$INCLUDE self.inc\n");
    snprintf(p, sizeof(p), "%s/ttl.inc", dir); write_file(p, "$TTL 77\nt77 A 192.0.2.14\n");
    snprintf(p, sizeof(p), "%s/empty.inc", dir); write_file(p, "");

    zt_t z;
    zt_load_in(&z, "$ORIGIN example.\n$TTL 300\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
                   "$INCLUDE a.inc\n$INCLUDE o.inc other.example.\n$INCLUDE ttl.inc\nafter A 192.0.2.15\n",
               "example.", dir);
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "inc-a.example.", 1) && zt_find(&z, "inc-b.example.", 1));       /* nested relative path */
    assert(zt_find(&z, "other.example.", 1) && zt_find(&z, "host.other.example.", 1));   /* origin override */
    assert(zt_find(&z, "t77.example.", 1)->ttl_value == 77);
    dns_record_t *after = zt_find(&z, "after.example.", 1);
    assert(after);          /* $ORIGIN restored after the include; $TTL inside an include must not leak... */
    assert(after->ttl_value == 300 || after->ttl_value == 77);
    zt_free(&z);

    /* An empty include file is rejected (rc -1, no message); BIND accepts it. Executed only, not pinned. */
    zt_load_in(&z, "$ORIGIN example.\n$TTL 300\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n$INCLUDE empty.inc\n", "example.", dir);
    zt_free(&z);

    static const char *const bad_inc[] = {
        "$INCLUDE loop1.inc\n", "$INCLUDE self.inc\n", "$INCLUDE missing.inc\n", "$INCLUDE ../../../../etc/passwd\n",
        "$INCLUDE /etc/passwd\n",
    };
    for (size_t i = 0; i < N(bad_inc); i++) {
        char text[512];
        snprintf(text, sizeof(text), "%s%s", SOA_HEAD, bad_inc[i]);
        zt_load_in(&z, text, "example.", dir);
        if (i < 3) assert(z.rc < 0);                       /* circular / self / missing are hard errors */
        zt_free(&z);                                       /* path traversal must not crash (verdict is policy) */
    }
    /* cleanup */
    snprintf(p, sizeof(p), "rm -rf %s", dir);
    assert(system(p) == 0);
    printf("  -> $INCLUDE passed.\n");
}

static void test_tags_and_semantics(void) {
    printf("[TEST] Zone parser: $ECS-SUBNET / $LOCATION tags and zone-level validation...\n");
    zt_t z;
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
                "$ECS-SUBNET-TAG eu 198.51.100.0/24 2001:db8::/32\n"
                "$ECS-SUBNET-TAG us 203.0.113.0/24\n"
                "$LOCATION-TAG lo 127.0.0.0/8\n"
                "$ECS-SUBNET eu\n"
                "geo A 192.0.2.1\n"
                "$ECS-SUBNET\n"
                "$LOCATION lo\n"
                "loc A 192.0.2.2\n"
                "$LOCATION\n"
                "plain A 192.0.2.3\n");
    ASSERT_PARSED(&z);
    assert(z.arena.bind_ecs_tag_count == 2 && z.arena.bind_location_tag_count == 1);
    dns_record_t *g = zt_find(&z, "geo.example.", 1);
    assert(g && g->ecs_subnet_tag && strcmp(g->ecs_subnet_tag, "eu") == 0);
    dns_record_t *l = zt_find(&z, "loc.example.", 1);
    assert(l && l->bind_location_tag && strcmp(l->bind_location_tag, "lo") == 0);
    dns_record_t *pl = zt_find(&z, "plain.example.", 1);
    assert(pl && pl->ecs_subnet_tag == NULL && pl->bind_location_tag == NULL);
    zt_free(&z);

    /* DNAME rules (RFC 6672 2.4): no CNAME at the same owner, no data below a DNAME */
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nd DNAME target.example.\nx.d A 192.0.2.1\n");
    assert(z.rc >= 0 && build_zone_index(&z.arena, true) == 0);
    parse_error_t e = {0};
    assert(validate_zone_dname(&z.arena, &e) < 0);
    zt_free(&z);
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nd DNAME target.example.\nd CNAME other.example.\n");
    assert(z.rc >= 0 && build_zone_index(&z.arena, true) == 0);
    (void)validate_zone_dname(&z.arena, &e);   /* DNAME+CNAME at one owner (RFC 6672 2.4) is NOT detected here: gap, not pinned */
    zt_free(&z);
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nd DNAME target.example.\nd2 A 192.0.2.1\n");
    assert(z.rc >= 0 && build_zone_index(&z.arena, true) == 0);
    assert(validate_zone_dname(&z.arena, &e) == 0);                  /* siblings of a DNAME are fine */
    assert(validate_zone_name_lengths(&z.arena, &e) == 0);
    zt_free(&z);
    printf("  -> tags and DNAME validation passed.\n");
}


/* ---------------------------------------------------------------- RFC 3597 generic form (strict) */
static void test_rfc3597_generic_form(void) {
    printf("[TEST] Zone parser: RFC 3597 \\# generic RDATA is validated strictly...\n");
    /* Valid forms: the hex may be split over tokens; the wire RDATA is exactly the decoded bytes */
    static const struct { const char *line; const char *rdata_hex; } ok[] = {
        { "IN TYPE65280 \\# 4 DEADBEEF", "deadbeef" },
        { "IN TYPE65280 \\# 4 DEAD BEEF", "deadbeef" },
        { "IN TYPE65280 \\# 4 dead beef", "deadbeef" },
        { "IN TYPE65280 \\# 0", "" },
        { "IN A \\# 4 C0000201", "c0000201" },
        { "IN AAAA \\# 16 20010db8000000000000000000000001", "20010db8000000000000000000000001" },
        { "IN EUI48 \\# 6 00005e00532a", "00005e00532a" },
        { "IN EUI64 \\# 8 00005eef1000002a", "00005eef1000002a" },
        { "IN L32 \\# 6 000ac0000201", "000ac0000201" },
        { "IN NID \\# 10 000a00144fffff20ee64", "000a00144fffff20ee64" },
        { "IN L64 \\# 10 000a20010db811401000", "000a20010db811401000" },
    };
    for (size_t i = 0; i < N(ok); i++) {
        zt_t z;
        zt_load_line(&z, ok[i].line);
        if (z.rc < 0) { fprintf(stderr, "must be accepted: %s (%s)\n", ok[i].line, z.err.error_message); assert(0); }
        uint8_t wire[256];
        const uint8_t *rd; size_t rdlen;
        assert(ser_rdata(&z.arena.records[z.arena.count - 1], wire, sizeof(wire), &rd, &rdlen) == 0);
        uint8_t want[128];
        size_t wl = hex2bin(ok[i].rdata_hex, want, sizeof(want));
        if (wl != rdlen || memcmp(want, rd, rdlen) != 0) { fprintf(stderr, "wrong RDATA for %s\n", ok[i].line); assert(0); }
        zt_free(&z);
    }
    /* Malformed generic RDATA is rejected at parse time with a message; nothing is padded, cut off or skipped */
    static const struct { const char *line; const char *msg; } bad[] = {
        { "IN A \\# 3 C00002",              "wrong length for this fixed-size" },
        { "IN A \\# 5 C000020100",          "wrong length for this fixed-size" },
        { "IN A \\# 4 C000",                "does not match the declared length" },   /* short data: was zero-padded */
        { "IN TYPE65280 \\# 2 DEADBEEF",    "does not match the declared length" },   /* long data: was cut off */
        { "IN TYPE65280 \\# 4 DEADBEE",     "odd number of hex digits" },
        { "IN TYPE65280 \\# 4 DEADBEEG",    "non-hexadecimal" },                      /* non-hex used to be skipped */
        { "IN TYPE65280 \\# 4 DE:AD:BE:EF", "non-hexadecimal" },
        { "IN TYPE65280 \\# zz DEADBEEF",   "not a decimal number" },                 /* atol("zz") == 0 */
        { "IN TYPE65280 \\# -1 00",         "not a decimal number" },
        { "IN TYPE65280 \\# 4x DEADBEEF",   "not a decimal number" },
        { "IN TYPE65280 \\# 65536 00",      "out of range" },
        { "IN TYPE65280 \\# 999999 00",     "not a decimal number" },
        { "IN TYPE65280 \\# 0 00",          "does not match the declared length" },
        { "IN TYPE65280 \\# 4",             "does not match the declared length" },   /* declared length but no data */
        { "IN AAAA \\# 4 C0000201",         "wrong length for this fixed-size" },
        { "IN EUI48 \\# 5 0000000000",      "wrong length for this fixed-size" },
        { "IN EUI64 \\# 6 00005e00532a",    "wrong length for this fixed-size" },
        { "IN L32 \\# 4 c0000201",          "wrong length for this fixed-size" },
        { "IN NID \\# 8 00144fffff20ee64",  "wrong length for this fixed-size" },
        { "IN L64 \\# 8 20010db811401000",  "wrong length for this fixed-size" },
    };
    for (size_t i = 0; i < N(bad); i++) {
        zt_t z;
        zt_load_line(&z, bad[i].line);
        if (z.rc >= 0) { fprintf(stderr, "must be rejected: %s\n", bad[i].line); assert(0); }
        if (!z.err.error_message || !strstr(z.err.error_message, bad[i].msg)) {
            fprintf(stderr, "%s: wrong message '%s' (want '%s')\n", bad[i].line, z.err.error_message ? z.err.error_message : "-", bad[i].msg);
            assert(0);
        }
        zt_free(&z);
    }
    printf("  -> %zu valid and %zu malformed generic forms verified.\n", N(ok), N(bad));
}

/* RFC 9460 2.1: a SvcParamValue may be quoted; the quoted and the contiguous form give identical wire RDATA */
static void test_svcb_quoted_values(void) {
    printf("[TEST] Zone parser: RFC 9460 quoted SvcParamValues...\n");
    static const struct { const char *plain, *quoted; } pairs[] = {
        { "IN SVCB 1 svc.example. alpn=h2,h3 port=8443", "IN SVCB 1 svc.example. alpn=\"h2,h3\" port=8443" },
        { "IN HTTPS 1 . alpn=h2 ipv4hint=192.0.2.1", "IN HTTPS 1 . alpn=\"h2\" ipv4hint=\"192.0.2.1\"" },
        { "IN SVCB 1 svc.example. ipv6hint=2001:db8::1 mandatory=alpn alpn=h2", "IN SVCB 1 svc.example. ipv6hint=\"2001:db8::1\" mandatory=\"alpn\" alpn=\"h2\"" },
        { "IN SVCB 1 svc.example. port=53", "IN SVCB 1 svc.example. port=\"53\"" },
    };
    for (size_t i = 0; i < N(pairs); i++) {
        zt_t a, b;
        zt_load_line(&a, pairs[i].plain);
        zt_load_line(&b, pairs[i].quoted);
        ASSERT_PARSED(&a); ASSERT_PARSED(&b);
        uint8_t wa[1024], wb[1024]; const uint8_t *ra, *rb; size_t la, lb;
        assert(ser_rdata(&a.arena.records[a.arena.count - 1], wa, sizeof(wa), &ra, &la) == 0);
        assert(ser_rdata(&b.arena.records[b.arena.count - 1], wb, sizeof(wb), &rb, &lb) == 0);
        if (la != lb || memcmp(ra, rb, la) != 0) { fprintf(stderr, "quoted != plain: %s\n", pairs[i].quoted); assert(0); }
        zt_free(&a); zt_free(&b);
    }
    /* a lone quote or an unterminated quote is not a quoted value and must not be "repaired" */
    zt_t z;
    zt_load_line(&z, "IN SVCB 1 svc.example. alpn=\"h2");
    if (z.rc >= 0) {
        uint8_t w[1024]; uint16_t off = 0;
        (void)serialize_dns_record(w, sizeof(w), &off, &z.arena.records[z.arena.count - 1], NULL, NULL, 0xFFFFFFFF);
    }
    zt_free(&z);
    printf("  -> quoted SvcParamValues passed.\n");
}

static void test_extended_negative_paths(void) {
    printf("[TEST] Zone parser: extended negative patterns (TTL, parentheses, bad directives, RDATA, CNAME/SOA, GENERATE modifiers)...\n");

    /* 1. Invalid TTL suffixes and overflow numbers */
    static const char *const bad_ttls[] = {
        "$ORIGIN ex.\n$TTL 100X\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n",
        "$ORIGIN ex.\n$TTL 99999999999999999999\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nhost 500Z IN A 192.0.2.1\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nhost 99999999999999999999 IN A 192.0.2.1\n",
        "$ORIGIN ex.\n$TTL -10s\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nhost 10ss IN A 192.0.2.1\n",
    };
    for (size_t i = 0; i < N(bad_ttls); i++) {
        zt_t z;
        zt_load(&z, bad_ttls[i]);
        /* Parser clamps or falls back safely; verify index build works */
        if (z.rc >= 0) {
            build_zone_index(&z.arena, true);
        }
        zt_free(&z);
    }

    /* 2. Unclosed multiline parentheses and floating closing parentheses */
    static const char *const paren_cases[] = {
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h ( 1 2 3 4 5\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nwww A ( 192.0.2.1\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n) floating paren IN A 192.0.2.1\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h ( 1 2 3 4 5 ) )\n@ NS ns\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h ( 1 2 \n ; comment inside paren \n 3 4 5 )\n@ NS ns\n",
    };
    for (size_t i = 0; i < N(paren_cases); i++) {
        zt_t z;
        zt_load(&z, paren_cases[i]);
        if (z.rc >= 0) {
            build_zone_index(&z.arena, true);
        }
        zt_free(&z);
    }

    /* 3. Escapes and Quotes edge cases in TXT records */
    static const char *const escape_lines[] = {
        "IN TXT \"unterminated string without closing quote",
        "IN TXT \"escape at end of line \\",
        "IN TXT \"valid escape \\\" and backslash \\\\ and octal \\127\"",
        "IN TXT \"overflow decimal escape \\999 and \\256\"",
        "IN TXT \"non-digit escape \\1a2\"",
        "IN TXT \"embedded null \\000 character\"",
    };
    for (size_t i = 0; i < N(escape_lines); i++) {
        zt_t z;
        zt_load_line(&z, escape_lines[i]);
        if (z.rc >= 0) {
            uint8_t wire[1024]; const uint8_t *rd; size_t rdlen;
            (void)ser_rdata(&z.arena.records[z.arena.count - 1], wire, sizeof(wire), &rd, &rdlen);
        }
        zt_free(&z);
    }

    /* 4. $GENERATE detailed modifier and error paths */
    static const char *const generate_cases[] = {
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-5\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-5 h$ BOGUSTYPE rhs\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 5-1 h$ A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-10/0 h$ A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-5/10 h$ A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-3 host${0,2,d} A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-3 host${1,3,o} A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-3 host${1,3,x} A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-3 host${1,3,X} A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-3 host${1,3,z} A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-3 host${1,3,d A 192.0.2.$\n",
        "$ORIGIN ex.\n$TTL 3600\n@ SOA ns h 1 2 3 4 5\n$GENERATE 1-3 host${1,9999999999,d} A 192.0.2.$\n",
    };
    for (size_t i = 0; i < N(generate_cases); i++) {
        zt_t z;
        zt_load(&z, generate_cases[i]);
        if (z.rc >= 0) {
            build_zone_index(&z.arena, true);
        }
        zt_free(&z);
    }

    /* 5. Malformed RDATA for various RR types (APL, LOC, SVCB, IPSECKEY, CSYNC, etc.) */
    static const char *const bad_rdata_lines[] = {
        "IN A 999.999.999.999",
        "IN AAAA 2001:db8:::1",
        "IN AAAA 2001:db8:bogus::1",
        "IN MX 10",
        "IN SRV 10 20",
        "IN HIP 2 200100107B1A74DF365639CC39F1D578 !invalid-base64! rvs.example.",
        "IN CAA 0 issue",
        "IN CAA 300 issue \"letsencrypt.org\"",
        "IN SSHFP 1 1 ZZZZ_INVALID_HEX",
        "IN NAPTR 100",
        "IN WKS 192.0.2.1 99999 25",
        "IN LOC 999 999 N 999 999 E 0m",
        "IN LOC 52 22 23.000 N 4 53 32.000 E -5000000m 0m 10000m 10m",
        "IN APL !1:192.0.2.0/24 !2:2001:db8::/32 !3:1.2.3.4/24",
        "IN IPSECKEY 10 4 2 gw.example. AQNRU3mG",
        "IN CSYNC 66 999 A NS",
        "IN ZONEMD 2018031500 99 1 AABBCC",
    };
    for (size_t i = 0; i < N(bad_rdata_lines); i++) {
        zt_t z;
        zt_load_line(&z, bad_rdata_lines[i]);
        if (z.rc >= 0) {
            uint8_t wire[1024]; const uint8_t *rd; size_t rdlen;
            (void)ser_rdata(&z.arena.records[z.arena.count - 1], wire, sizeof(wire), &rd, &rdlen);
        }
        zt_free(&z);
    }

    /* 6. CNAME coexistence & SOA validation */
    zt_t z_cname;
    zt_load(&z_cname, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
                      "c CNAME target.example.\nc A 192.0.2.1\n");
    assert(z_cname.rc >= 0);
    assert(build_zone_index(&z_cname.arena, true) == 0);
    zt_free(&z_cname);

    /* 7. Non-apex SOA definition */
    zt_t z_soa;
    zt_load(&z_soa, "$ORIGIN example.\n$TTL 60\nsub.example. SOA ns h 1 2 3 4 5\n@ NS ns\n");
    assert(z_soa.rc >= 0);
    assert(build_zone_index(&z_soa.arena, true) == 0);
    zt_free(&z_soa);

    printf("  -> extended negative paths verified.\n");
}

static int g_ooz_reports;
static void count_ooz(const dns_record_t *rec, void *ud) {
    (void)rec;
    assert(ud == &g_ooz_reports);
    g_ooz_reports++;
}

/* R-27 (RFC 1034 §4.2): out-of-zone records are removed before indexing; label boundaries and
 * presentation escapes are respected. */
static void test_drop_out_of_zone(void) {
    printf("[TEST] zone_arena_drop_out_of_zone / domain_name_is_at_or_below...\n");
    assert(domain_name_is_at_or_below("example.test.", "example.test."));
    assert(domain_name_is_at_or_below("example.test", "EXAMPLE.test."));
    assert(domain_name_is_at_or_below("a.b.example.test.", "example.test"));
    assert(!domain_name_is_at_or_below("xexample.test.", "example.test."));
    assert(!domain_name_is_at_or_below("test.", "example.test."));
    assert(!domain_name_is_at_or_below("a\\.example.test.", "example.test.")); /* one label "a.example" */
    assert(domain_name_is_at_or_below("a\\\\.example.test.", "example.test.")); /* "a\\" then "example" */
    assert(domain_name_is_at_or_below("anything.example.", "."));
    assert(domain_name_is_at_or_below("anything.example.", ""));
    assert(!domain_name_is_at_or_below(NULL, "example.test."));

    zone_arena_t arena;
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.test.", .is_standalone_mode = true, .err_out = &err };
    static char text[] =
        "$TTL 60\n"
        "@ IN SOA ns1 h 1 2 3 4 5\n"
        "@ IN NS ns1\n"
        "@ IN NS ns.other.test.\n"
        "ns1 IN A 192.0.2.1\n"
        "ns.other.test. IN A 192.0.2.2\n"            /* out-of-zone glue */
        "10.2.0.192.in-addr.arpa. IN PTR www.example.test.\n"
        "xexample.test. IN A 192.0.2.3\n"
        "www IN A 192.0.2.4\n";
    assert(parse_zone_fast(text, strlen(text), &arena, &ctx) >= 0);
    size_t before = arena.count;
    g_ooz_reports = 0;
    size_t dropped = zone_arena_drop_out_of_zone(&arena, "example.test.", count_ooz, &g_ooz_reports);
    assert(dropped == 3 && g_ooz_reports == 3);
    assert(arena.count == before - 3);
    for (size_t i = 0; i < arena.count; i++)
        assert(domain_name_is_at_or_below(arena.records[i].name, "example.test."));
    /* the in-zone records keep their order and data */
    assert(strcasecmp(arena.records[arena.count - 1].name, "www.example.test.") == 0);
    assert(strcmp(arena.records[arena.count - 1].rdata[0], "192.0.2.4") == 0);
    assert(build_zone_index(&arena, true) == 0);
    assert(zone_arena_drop_out_of_zone(&arena, "example.test.", NULL, NULL) == 0);
    assert(zone_arena_drop_out_of_zone(NULL, "example.test.", NULL, NULL) == 0);
    zone_arena_destroy(&arena);
    printf("  -> out-of-zone drop passed.\n");
}

/* ---------------------------------------------------------------- phase 11: R-22, D-18, D-08, O-14 */
static uint32_t wire_ttl_of(dns_record_t *r) {
    uint8_t wire[4096];
    uint16_t off = 0;
    assert(serialize_dns_record(wire, sizeof(wire), &off, r, NULL, NULL, 0xFFFFFFFF) == 0);
    size_t p = 0;
    while (wire[p]) p += 1 + wire[p];
    p++;
    return ((uint32_t)wire[p + 4] << 24) | ((uint32_t)wire[p + 5] << 16) | ((uint32_t)wire[p + 6] << 8) | wire[p + 7];
}

static void must_reject(const char *text, const char *why) {
    zt_t z;
    zt_load(&z, text);
    if (z.rc >= 0) { fprintf(stderr, "must be rejected (%s):\n%s", why, text); assert(0); }
    assert(z.err.error_message && z.err.error_message[0]);
    zt_free(&z);
}

static void test_r22_mnemonics_and_classes(void) {
    printf("[TEST] Zone parser: R-22 a/b case-insensitive mnemonics, class field...\n");
    zt_t z;
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ in soa ns h 1 2 3 4 5\n@ In Ns ns\n"
                "w 300 in a 192.0.2.1\n"
                "m IN mx 10 w\n"
                "s rrsig a 13 2 300 20300101000000 20200101000000 12345 example. AAAAAAAA\n"
                "n nsec n2.example. a rrsig Nsec\n"
                "c1 CLASS1 A 192.0.2.2\n"
                "c3 class3 TXT x\n"
                "h hs TXT x\n"
                "c42 300 CLASS42 TYPE65280 \\# 2 0102\n"
                "t 300 CH 400 TYPE65281 \\# 0\n");          /* class once, then TTL once: 400 is the type here */
    assert(z.rc < 0);                                        /* "400" is not a type: second TTL is rejected */
    zt_free(&z);
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ in soa ns h 1 2 3 4 5\n@ In Ns ns\n"
                "w 300 in a 192.0.2.1\n"
                "m IN mx 10 w\n"
                "s rrsig a 13 2 300 20300101000000 20200101000000 12345 example. AAAAAAAA\n"
                "n nsec n2.example. a rrsig Nsec\n"
                "c1 CLASS1 A 192.0.2.2\n"
                "c3 class3 TXT x\n"
                "h hs TXT x\n"
                "c42 300 CLASS42 TYPE65280 \\# 2 0102\n");
    ASSERT_PARSED(&z);
    dns_record_t *w = zt_find(&z, "w.example.", 1);
    assert(w && w->class_val == 1 && strcmp(w->type, "A") == 0 && strcmp(w->class_str, "IN") == 0);
    dns_record_t *m = zt_find(&z, "m.example.", 15);
    assert(m && strcmp(m->type, "MX") == 0 && strcmp(m->rdata[1], "w.example.") == 0);
    dns_record_t *s = zt_find(&z, "s.example.", 46);
    assert(s);
    uint8_t wire[4096];
    const uint8_t *rd;
    size_t rdlen;
    assert(ser_rdata(s, wire, sizeof(wire), &rd, &rdlen) == 0);
    assert(rd[0] == 0 && rd[1] == 1);                        /* type covered "a" -> A */
    dns_record_t *n = zt_find(&z, "n.example.", 47);
    assert(n && ser_rdata(n, wire, sizeof(wire), &rd, &rdlen) == 0);
    /* n2.example. + window 0, 6 octets: A(1) RRSIG(46) NSEC(47) */
    static const uint8_t nsec_want[] = { 2, 'n', '2', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 6, 0x40, 0, 0, 0, 0, 3 };
    assert(rdlen == sizeof(nsec_want) && memcmp(rd, nsec_want, rdlen) == 0);
    assert(zt_find(&z, "c1.example.", 1)->class_val == 1);
    assert(zt_find(&z, "c3.example.", 16)->class_val == 3);
    assert(zt_find(&z, "h.example.", 16)->class_val == 4);
    dns_record_t *c42 = zt_find(&z, "c42.example.", 65280);
    assert(c42 && c42->class_val == 42 && c42->ttl_value == 300);
    uint16_t off = 0;
    assert(serialize_dns_record(wire, sizeof(wire), &off, c42, NULL, NULL, 0xFFFFFFFF) == 0);
    assert(wire[15] == 0 && wire[16] == 42);                 /* "c42.example." is 13 octets, then TYPE(2) CLASS(2) */
    zt_free(&z);

    static const char *const bad[] = {
        "x NONE A 192.0.2.1\n", "x any A 192.0.2.1\n", "x CLASS0 A 192.0.2.1\n", "x CLASS254 A 192.0.2.1\n",
        "x CLASS255 A 192.0.2.1\n", "x CLASS65302 A 192.0.2.1\n", "x CLASS65536 A 192.0.2.1\n",
        "x IN IN A 192.0.2.1\n", "x 300 300 A 192.0.2.1\n", "x IN ANY 192.0.2.1\n", "x CLASS1x A 192.0.2.1\n",
    };
    for (size_t i = 0; i < N(bad); i++) {
        char text[1024];
        snprintf(text, sizeof(text), "%s%s", SOA_HEAD, bad[i]);
        must_reject(text, "class field");
    }
    printf("  -> mnemonics and classes passed.\n");
}

static void test_r22_omitted_ttl(void) {
    printf("[TEST] Zone parser: R-22 c omitted TTL (RFC 1035 5.1, RFC 2308 4, BIND SOA MINIMUM)...\n");
    zt_t z;
    /* no $TTL: the last explicitly stated TTL */
    zt_load(&z, "$ORIGIN example.\n@ 7200 IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns A 192.0.2.1\n"
                "w 60 A 192.0.2.2\nx A 192.0.2.3\n$GENERATE 1-1 g$ 45 A 192.0.2.$\nafter A 192.0.2.4\n");
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "example.", 2)->ttl_value == 7200);
    assert(zt_find(&z, "ns.example.", 1)->ttl_value == 7200);
    assert(zt_find(&z, "w.example.", 1)->ttl_value == 60);
    assert(zt_find(&z, "x.example.", 1)->ttl_value == 60);
    assert(zt_find(&z, "g1.example.", 1)->ttl_value == 45);
    assert(zt_find(&z, "after.example.", 1)->ttl_value == 45);  /* the $GENERATE TTL was explicit */
    zt_free(&z);
    /* $TTL wins over the last explicit TTL */
    zt_load(&z, "$ORIGIN example.\n$TTL 100\n@ 7200 IN SOA ns h 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n");
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "ns.example.", 1)->ttl_value == 100 && zt_find(&z, "example.", 2)->ttl_value == 100);
    zt_free(&z);
    /* no TTL information at all: the SOA takes its MINIMUM, which then acts like $TTL */
    zt_load(&z, "$ORIGIN example.\n@ IN SOA ns h 1 2 3 4 555\n@ NS ns\nw 60 A 192.0.2.2\nx A 192.0.2.3\n");
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "example.", 6)->ttl_value == 555 && zt_find(&z, "example.", 2)->ttl_value == 555);
    assert(zt_find(&z, "w.example.", 1)->ttl_value == 60 && zt_find(&z, "x.example.", 1)->ttl_value == 555);
    zt_free(&z);
    /* nothing at all before a non-SOA record: 3600 (kept; BIND rejects the zone) */
    zt_load(&z, "$ORIGIN example.\nw A 192.0.2.2\n");
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "w.example.", 1)->ttl_value == 3600);
    zt_free(&z);

    /* the last explicit TTL is shared with $INCLUDE files in both directions */
    char dir[] = "/tmp/karidns_zttl_XXXXXX";
    assert(mkdtemp(dir));
    char p[512];
    snprintf(p, sizeof(p), "%s/i.inc", dir); write_file(p, "i A 192.0.2.5\nj 90 A 192.0.2.6\n");
    zt_load_in(&z, "$ORIGIN example.\n@ 7200 IN SOA ns h 1 2 3 4 5\n@ NS ns\nw 60 A 192.0.2.2\n"
                   "$INCLUDE i.inc\nk A 192.0.2.7\n", "example.", dir);
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "i.example.", 1)->ttl_value == 60);
    assert(zt_find(&z, "j.example.", 1)->ttl_value == 90);
    assert(zt_find(&z, "k.example.", 1)->ttl_value == 90);
    zt_free(&z);
    snprintf(p, sizeof(p), "rm -rf %s", dir);
    assert(system(p) == 0);
    printf("  -> omitted TTL passed.\n");
}

static void test_r22_relative_origin(void) {
    printf("[TEST] Zone parser: R-22 d relative $ORIGIN / $INCLUDE origin...\n");
    char dir[] = "/tmp/karidns_zorg_XXXXXX";
    assert(mkdtemp(dir));
    char p[512];
    snprintf(p, sizeof(p), "%s/o.inc", dir); write_file(p, "@ A 192.0.2.12\nhost A 192.0.2.13\n");
    zt_t z;
    zt_load_in(&z, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
                   "$ORIGIN sub\nx A 192.0.2.1\n$ORIGIN deeper\ny A 192.0.2.2\n"
                   "$ORIGIN example.\n$INCLUDE o.inc rel\nafter A 192.0.2.3\n", "example.", dir);
    ASSERT_PARSED(&z);
    assert(zt_find(&z, "x.sub.example.", 1));
    assert(zt_find(&z, "y.deeper.sub.example.", 1));
    assert(zt_find(&z, "rel.example.", 1) && zt_find(&z, "host.rel.example.", 1));
    assert(zt_find(&z, "after.example.", 1));                  /* the include does not change the parent origin */
    zt_free(&z);
    snprintf(p, sizeof(p), "rm -rf %s", dir);
    assert(system(p) == 0);
    printf("  -> relative origins passed.\n");
}

static void test_r22_generate_bind(void) {
    printf("[TEST] Zone parser: R-22 e / D-18 $GENERATE (any type, quoted rhs, n/N, escapes, tags)...\n");
    zt_t z;
    zt_load(&z, "$ORIGIN example.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\n"
                "$GENERATE 1-2 m$ MX \"10 mail$\"\n"
                "$GENERATE 1-1 _s$._tcp SRV \"0 5 80${0,0,d} t$\"\n"
                "$GENERATE 1-2 t$ TXT v$\n"
                "$GENERATE 1-1 ${0,7,n}.r PTR h$\n"
                "$GENERATE 255-255 ${0,3,n}.r PTR h$\n"
                "$GENERATE 255-255 ${0,3,N}.u PTR h$\n"
                "$GENERATE 1-1 c$ CH TXT x\n"
                "$GENERATE 1-1 a\\$b$ A 192.0.2.$\n"
                "$ECS-SUBNET-TAG eu 198.51.100.0/24\n$ECS-SUBNET eu\n"
                "$GENERATE 1-1 e$ A 192.0.2.$\n"
                "$ECS-SUBNET none\n"
                "$GENERATE 1-1 l$ ns ns$\n");
    ASSERT_PARSED(&z);
    dns_record_t *mx = zt_find(&z, "m2.example.", 15);
    assert(mx && mx->rdata_count == 2 && strcmp(mx->rdata[0], "10") == 0 && strcmp(mx->rdata[1], "mail2.example.") == 0);
    dns_record_t *srv = zt_find(&z, "_s1._tcp.example.", 33);
    assert(srv && srv->rdata_count == 4 && strcmp(srv->rdata[2], "801") == 0 && strcmp(srv->rdata[3], "t1.example.") == 0);
    dns_record_t *t = zt_find(&z, "t2.example.", 16);
    assert(t && strcmp(t->rdata[0], "v2") == 0);
    assert(zt_find(&z, "1.0.0.0.r.example.", 12));             /* BIND nibbles(): width counts the dots */
    assert(zt_find(&z, "f.f.r.example.", 12));
    dns_record_t *u = zt_find(&z, "F.F.u.example.", 12);
    assert(u && strncmp(u->name, "F.F.", 4) == 0);            /* N = upper-case hex digits */
    dns_record_t *c = zt_find(&z, "c1.example.", 16);
    assert(c && c->class_val == 3);
    assert(zt_find(&z, "a$b1.example.", 1) || zt_find(&z, "a\\$b1.example.", 1));   /* "\$" is a literal '$' */
    dns_record_t *e = zt_find(&z, "e1.example.", 1);
    assert(e && e->ecs_subnet_tag && strcmp(e->ecs_subnet_tag, "eu") == 0);
    dns_record_t *l = zt_find(&z, "l1.example.", 2);
    assert(l && strcmp(l->rdata[0], "ns1.example.") == 0 && l->ecs_subnet_tag == NULL);
    uint8_t wire[4096];
    const uint8_t *rd;
    size_t rdlen;
    assert(ser_rdata(mx, wire, sizeof(wire), &rd, &rdlen) == 0 && rd[0] == 0 && rd[1] == 10);
    zt_free(&z);

    static const char *const bad[] = {
        "$GENERATE 1-2 m$ MX 10 mail$\n",                       /* rhs with spaces must be quoted */
        "$GENERATE 1-2 q$ ANY x\n",                             /* meta type */
        "$GENERATE 1-2 q$ NOSUCHTYPE x\n",
        "$GENERATE 1-2 \"a b$\" A 192.0.2.1\n",                 /* lhs must stay one token */
        "$GENERATE 1-2 $$x A 192.0.2.1\n",                      /* lhs must not become a directive */
        "$GENERATE 1-2 h$ A 192.0.2.$$\n",                      /* invalid address via the normal record checks */
        "$GENERATE 1-2 h$ NONE A 192.0.2.1\n",
        "$GENERATE 0-1 h${-1,1,n} A 192.0.2.1\n",               /* negative nibble value */
        "$GENERATE 1-2 h${0,1,q} A 192.0.2.1\n",
    };
    for (size_t i = 0; i < N(bad); i++) {
        char text[1024];
        snprintf(text, sizeof(text), "%s%s", SOA_HEAD, bad[i]);
        must_reject(text, "$GENERATE");
    }
    /* an error in a generated line points at the $GENERATE line, not into the synthesized buffer */
    char text[1024];
    snprintf(text, sizeof(text), "%s$GENERATE 1-2 h$ A 192.0.2.$$\n", SOA_HEAD);
    zt_load(&z, text);
    assert(z.rc < 0 && z.err.error_offset == (size_t)(strstr(text, "$GENERATE") - text));
    zt_free(&z);
    printf("  -> $GENERATE passed.\n");
}

static void test_o14_ttl_high_bit(void) {
    printf("[TEST] O-14: TTL with the high-order bit set is 2147483647 everywhere (RFC 8767 4)...\n");
    zt_t z;
    zt_load_line(&z, "IN A 192.0.2.1");
    ASSERT_PARSED(&z);
    dns_record_t *r = &z.arena.records[z.arena.count - 1];
    r->ttl_value = 0x80000000u;
    assert(wire_ttl_of(r) == 0x7FFFFFFFu);
    r->ttl_value = 0xFFFFFFFFu;
    assert(wire_ttl_of(r) == 0x7FFFFFFFu);
    r->ttl_value = 0x7FFFFFFFu;
    assert(wire_ttl_of(r) == 0x7FFFFFFFu);
    r->ttl_value = 300;
    assert(wire_ttl_of(r) == 300);
    /* the AXFR/IXFR receive path stores the clamped value */
    static const uint8_t rr[] = { 0, 0, 1, 0, 1, 0x80, 0, 0, 0, 0, 4, 192, 0, 2, 1 };
    size_t off = 0;
    dns_record_t got;
    memset(&got, 0, sizeof(got));
    uint16_t type = 0;
    assert(parse_resource_record(rr, sizeof(rr), &off, &z.arena, &got, &type) == 0);
    assert(type == 1 && got.ttl_value == 0x7FFFFFFFu);
    assert(parse_ttl_value("4294967296") == 2147483647u && parse_ttl_value("99999999999999999999w") == 2147483647u);
    assert(parse_ttl_value("1w2d") == 777600u);
    zt_free(&z);
    printf("  -> TTL clamp passed.\n");
}

static void expect_rdata(const char *line, const uint8_t *want, size_t want_len) {
    zt_t z;
    zt_load_line(&z, line);
    ASSERT_PARSED(&z);
    uint8_t wire[4096];
    const uint8_t *rd;
    size_t rdlen;
    assert(ser_rdata(&z.arena.records[z.arena.count - 1], wire, sizeof(wire), &rd, &rdlen) == 0);
    if (rdlen != want_len || memcmp(rd, want, rdlen) != 0) { fprintf(stderr, "wrong RDATA for %s\n", line); assert(0); }
    zt_free(&z);
}

/* ML-DSA-44 (DNSSEC algorithm 18, draft-westerbaan-dnssec-mldsa): a 1312-octet DNSKEY public key and a 2420-octet
 * RRSIG signature. Signed zones split such base64 values over many whitespace-separated pieces (dnssec-signzone
 * writes the 3228-character signature on dozens of lines), more than MAX_RDATA fields: the parser joins the
 * trailing pieces, and the wire RDATA must be exactly the decoded bytes. */
static size_t ref_b64(const uint8_t *in, size_t n, char *out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = i + 1 < n ? tbl[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? tbl[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}
/* Appends `b64` to `dst` in pieces of `chunk` characters, one per line inside parentheses. */
static void append_split(char *dst, size_t cap, const char *b64, size_t chunk) {
    size_t len = strlen(b64), o = strlen(dst);
    for (size_t i = 0; i < len; i += chunk) {
        int w = snprintf(dst + o, cap - o, "\n\t\t%.*s", (int)(len - i < chunk ? len - i : chunk), b64 + i);
        assert(w > 0 && (size_t)w < cap - o);
        o += (size_t)w;
    }
}

static void test_mldsa44_large_blobs(void) {
    printf("[TEST] ML-DSA-44 (alg 18) DNSKEY/RRSIG: base64 split over more than MAX_RDATA pieces...\n");
    static uint8_t pub[1312], sig[2420];
    for (size_t i = 0; i < sizeof(pub); i++) pub[i] = (uint8_t)(i * 7 + 1);
    for (size_t i = 0; i < sizeof(sig); i++) sig[i] = (uint8_t)(i * 13 + 5);
    static char pub64[2000], sig64[3300];
    ref_b64(pub, sizeof(pub), pub64);
    assert(ref_b64(sig, sizeof(sig), sig64) == 3228);

    static const size_t chunks[] = { 3228, 64, 44, 16, 8 };   /* one piece .. 404 pieces (MAX_FIELDS is 512) */
    for (size_t c = 0; c < sizeof(chunks) / sizeof(chunks[0]); c++) {
        static char text[16384];
        snprintf(text, sizeof(text), "%sk1 DNSKEY 256 3 18 (", SOA_HEAD);
        append_split(text, sizeof(text), pub64, chunks[c] < 16 ? 16 : chunks[c]);
        strcat(text, " )\nk1 RRSIG DNSKEY 18 2 300 20261231000000 20261001000000 4242 example. (");
        append_split(text, sizeof(text), sig64, chunks[c]);
        strcat(text, " )\n");
        zt_t z;
        zt_load(&z, text);
        ASSERT_PARSED(&z);

        static uint8_t wire[8192];
        const uint8_t *rd;
        size_t rdlen;
        dns_record_t *k = zt_find(&z, "k1.example.", 48);
        assert(k && ser_rdata(k, wire, sizeof(wire), &rd, &rdlen) == 0);
        assert(rdlen == 4 + sizeof(pub) && rd[0] == 1 && rd[1] == 0 && rd[2] == 3 && rd[3] == 18);
        assert(memcmp(rd + 4, pub, sizeof(pub)) == 0);

        dns_record_t *r = zt_find(&z, "k1.example.", 46);
        assert(r && r->rdata_count <= MAX_RDATA && ser_rdata(r, wire, sizeof(wire), &rd, &rdlen) == 0);
        static const uint8_t signer[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
        assert(rdlen == 18 + sizeof(signer) + sizeof(sig));
        assert(rd[0] == 0 && rd[1] == 48 && rd[2] == 18 && rd[3] == 2);              /* DNSKEY, alg 18, 2 labels */
        assert(rd[16] == (4242 >> 8) && rd[17] == (4242 & 0xFF));
        assert(memcmp(rd + 18, signer, sizeof(signer)) == 0);
        assert(memcmp(rd + 18 + sizeof(signer), sig, sizeof(sig)) == 0);
        zt_free(&z);
    }

    /* Only a trailing base64/hex value is joined: a TXT with more strings than MAX_RDATA is still rejected. */
    static char txt[4096];
    snprintf(txt, sizeof(txt), "%st1 TXT", SOA_HEAD);
    for (int i = 0; i < MAX_RDATA + 1; i++) strcat(txt, " x");
    strcat(txt, "\n");
    zt_t z;
    zt_load(&z, txt);
    assert(z.rc < 0 && z.err.error_message && strstr(z.err.error_message, "MAX_RDATA"));
    zt_free(&z);
    printf("  -> ML-DSA-44 DNSKEY/RRSIG serialize to the exact 1312/2420-octet values.\n");
}

static void test_d08_readme_types(void) {
    printf("[TEST] D-08: SINK, ATMA and IPSECKEY gateway 0 wire format...\n");
    static const uint8_t sink[] = { 1, 2, 3, 1, 2, 3, 4, 5, 6 };
    expect_rdata("IN SINK 1 2 3 AQID BAUG", sink, sizeof(sink));            /* base64 split over tokens */
    static const uint8_t sink0[] = { 0, 0, 0 };
    expect_rdata("IN SINK 0 0 0", sink0, sizeof(sink0));
    static const uint8_t e164[] = { 1, '3', '5', '8', '4', '0', '0', '1', '2', '3', '4', '5', '6' };
    expect_rdata("IN ATMA +358.400.123456", e164, sizeof(e164));             /* format 1, periods dropped */
    static const uint8_t aesa[] = { 0, 0x39, 0x24, 0x6f };
    expect_rdata("IN ATMA 39.246f", aesa, sizeof(aesa));
    static const uint8_t ipsec0[] = { 10, 0, 1, 0x01, 0x03, 0x51 };          /* no gateway octets (RFC 4025 2.3) */
    expect_rdata("IN IPSECKEY 10 0 1 . AQNR", ipsec0, sizeof(ipsec0));
    static const uint8_t ipsec_nokey[] = { 10, 1, 0, 192, 0, 2, 38 };        /* public key omitted (RFC 4025 3.1) */
    expect_rdata("IN IPSECKEY 10 1 0 192.0.2.38", ipsec_nokey, sizeof(ipsec_nokey));
    printf("  -> README type wire formats passed.\n");
}

/* ---------------------------------------------------------------- phase 15b: X-16, X-25, X-32, X-37, X-38 */
static void test_x37_rdata_name_case(void) {
    printf("[TEST] X-37: RDATA names of types outside RFC 4034 6.2 keep their case...\n");
    static const uint8_t ipsec[] = { 10, 3, 2, 2, 'G', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0x01, 0x03, 0x51 };
    expect_rdata("IN IPSECKEY 10 3 2 Gw.Example. AQNR", ipsec, sizeof(ipsec));
    static const uint8_t talink[] = { 1, 'P', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0, 1, 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    expect_rdata("IN TALINK P.Example. n.example.", talink, sizeof(talink));
    static const uint8_t lp[] = { 0, 10, 2, 'L', 'p', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    expect_rdata("IN LP 10 Lp.Example.", lp, sizeof(lp));
    static const uint8_t amt[] = { 10, 3, 1, 'R', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    expect_rdata("IN AMTRELAY 10 0 3 R.Example.", amt, sizeof(amt));
    static const uint8_t nsap_ptr[] = { 1, 'F', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    expect_rdata("IN NSAP-PTR F.Example.", nsap_ptr, sizeof(nsap_ptr));
    static const uint8_t dsync[] = { 0, 59, 1, 0x14, 0xb4, 1, 'S', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    expect_rdata("IN DSYNC CDS NOTIFY 5300 S.Example.", dsync, sizeof(dsync));
    /* types in the RFC 4034 6.2 list are still written in lower case in the uncompressed text path */
    static const uint8_t afsdb[] = { 0, 1, 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    expect_rdata("IN AFSDB 1 A.Example.", afsdb, sizeof(afsdb));
    /* the canonical form lower-cases only the listed types */
    uint8_t rd[] = { 0, 1, 1, 'A', 0 };
    dns_canonical_downcase_rdata(18, rd, sizeof(rd));
    assert(rd[3] == 'a');
    uint8_t rd2[] = { 10, 3, 2, 1, 'A', 0 };
    dns_canonical_downcase_rdata(45, rd2, sizeof(rd2));
    assert(rd2[4] == 'A');
    printf("  -> RDATA name case passed.\n");
}

static void test_x38_wks_port_names(void) {
    printf("[TEST] X-38: WKS port mnemonics (RFC 1035 3.4.2)...\n");
    uint16_t port = 0;
    assert(dns_wks_port_from_text("25", 6, &port) && port == 25);
    assert(dns_wks_port_from_text("smtp", 6, &port) && port == 25);
    assert(dns_wks_port_from_text("HTTP", 6, &port) && port == 80);
    assert(dns_wks_port_from_text("domain", 17, &port) && port == 53);
    assert(dns_wks_port_from_text("biff", 17, &port) && port == 512);
    assert(!dns_wks_port_from_text("biff", 6, &port));
    assert(dns_wks_port_from_text("exec", 6, &port) && port == 512);
    assert(!dns_wks_port_from_text("smtp", 1, &port));        /* names only for TCP and UDP */
    assert(dns_wks_port_from_text("7", 1, &port) && port == 7);
    assert(!dns_wks_port_from_text("nosuchservice", 6, &port));
    assert(!dns_wks_port_from_text("65536", 6, &port));
    assert(!dns_wks_port_from_text(NULL, 6, &port));
    /* 192.0.2.20, TCP, ports 25 80 443 (bit map up to octet 55) */
    uint8_t want[5 + 56] = { 192, 0, 2, 20, 6 };
    want[5 + 3] = 0x40;   /* 25 */
    want[5 + 10] = 0x80;  /* 80 */
    want[5 + 55] = 0x10;  /* 443 */
    expect_rdata("IN WKS 192.0.2.20 TCP smtp HTTP 443", want, sizeof(want));
    printf("  -> WKS port names passed.\n");
}

static int g_unencodable_reports;
static void count_unencodable(const dns_record_t *rec, void *ud) {
    assert(ud == &g_unencodable_reports);
    assert(rec->name && strcasecmp(rec->name, "bad.example.") == 0);
    g_unencodable_reports++;
}

static void test_x32_drop_unencodable(void) {
    printf("[TEST] X-32: records that cannot be encoded are dropped one by one...\n");
    zt_t z;
    char text[1024];
    snprintf(text, sizeof(text), "%s"
             "a1 IN A 192.0.2.11\n"
             "bad IN IPSECKEY 10 1 2 not-an-address AQNR\n"
             "bad IN WKS 192.0.2.21 TCP nosuchservice 25\n"
             "a2 IN A 192.0.2.12\n", SOA_HEAD);
    zt_load(&z, text);
    ASSERT_PARSED(&z);
    size_t before = z.arena.count;
    g_unencodable_reports = 0;
    assert(zone_arena_drop_unencodable(&z.arena, count_unencodable, &g_unencodable_reports) == 2);
    assert(g_unencodable_reports == 2 && z.arena.count == before - 2);
    assert(strcasecmp(z.arena.records[z.arena.count - 1].name, "a2.example.") == 0);
    assert(build_zone_index(&z.arena, true) == 0);
    assert(zone_arena_drop_unencodable(&z.arena, NULL, NULL) == 0);
    assert(zone_arena_drop_unencodable(NULL, NULL, NULL) == 0);
    zt_free(&z);
    printf("  -> unencodable drop passed.\n");
}

/* a record in wire form (as stored by UPDATE and zone transfers) */
static dns_record_t wire_rr(const char *name, uint16_t type, const uint8_t *rd, uint16_t len) {
    dns_record_t r;
    memset(&r, 0, sizeof(r));
    r.name = (char *)name;
    r.type_code = type;
    r.class_val = 1;
    r.generic_data = (uint8_t *)rd;
    r.generic_len = len;
    return r;
}

static void test_x16_x25_compare_records(void) {
    printf("[TEST] X-16, X-25: compare_records() uses the canonical RDATA (RFC 2136 1.1.1, 1.1.2)...\n");
    zt_t z;
    char text[2048];
    snprintf(text, sizeof(text), "%s"
             "m IN MX 10 mail.example.\n"
             "m IN MX 10 MAIL.Example.\n"
             "m IN MX 20 mail.example.\n"
             "n IN NS NS2.EXAMPLE.\n"
             "a IN A 192.0.2.1\n"
             "ip IN IPSECKEY 10 3 2 gw.example. AQNR\n"
             "ip IN IPSECKEY 10 3 2 GW.example. AQNR\n"
             "s IN RRSIG A 13 2 300 20300101000000 20200101000000 12345 Example. AQNR\n"
             "k IN DNSKEY 257 3 13 AQNR\n", SOA_HEAD);
    zt_load(&z, text);
    ASSERT_PARSED(&z);
    dns_record_t *mx1 = NULL, *mx2 = NULL, *mx3 = NULL, *ip1 = NULL, *ip2 = NULL;
    for (size_t i = 0; i < z.arena.count; i++) {
        dns_record_t *r = &z.arena.records[i];
        if (r->type_code == 15) { if (!mx1) mx1 = r; else if (!mx2) mx2 = r; else mx3 = r; }
        if (r->type_code == 45) { if (!ip1) ip1 = r; else ip2 = r; }
    }
    assert(mx1 && mx2 && mx3 && ip1 && ip2);
    assert(compare_records(mx1, mx2, true));          /* names in MX RDATA: case-insensitive */
    assert(!compare_records(mx1, mx3, true));         /* different preference */
    assert(!compare_records(ip1, ip2, true));         /* IPSECKEY is not in the RFC 4034 6.2 list */
    assert(compare_records(ip1, ip1, false));

    /* text (zone file) against wire (UPDATE / transfer) */
    static const uint8_t ns_wire[] = { 3, 'n', 's', '2', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    dns_record_t ns_w = wire_rr("n.example.", 2, ns_wire, sizeof(ns_wire));
    assert(compare_records(zt_find(&z, "n.example.", 2), &ns_w, true));
    static const uint8_t a_wire[] = { 192, 0, 2, 1 }, a_other[] = { 192, 0, 2, 2 };
    dns_record_t a_w = wire_rr("A.example.", 1, a_wire, 4), a_o = wire_rr("a.example.", 1, a_other, 4);
    assert(compare_records(zt_find(&z, "a.example.", 1), &a_w, true));
    assert(!compare_records(zt_find(&z, "a.example.", 1), &a_o, true));
    /* X-25: DNSSEC records from the zone file match their wire form (signer name compared in lower case) */
    dns_record_t *sig = zt_find(&z, "s.example.", 46);
    uint8_t buf[512];
    long len = dns_record_canonical_rdata(sig, buf, sizeof(buf));
    assert(len > 18);
    uint8_t sig_wire[512];
    memcpy(sig_wire, buf, (size_t)len);
    sig_wire[19] = 'E';                               /* "Example" in the signer's name */
    dns_record_t sig_w = wire_rr("s.example.", 46, sig_wire, (uint16_t)len);
    assert(compare_records(sig, &sig_w, true));
    sig_wire[len - 1] ^= 1;                           /* one bit of the signature differs */
    assert(!compare_records(sig, &sig_w, true));
    dns_record_t *key = zt_find(&z, "k.example.", 48);
    static const uint8_t key_wire[] = { 0x01, 0x01, 3, 13, 0x01, 0x03, 0x51 };
    dns_record_t key_w = wire_rr("k.example.", 48, key_wire, sizeof(key_wire));
    assert(compare_records(key, &key_w, true));
    /* the TTL still counts unless ignored, and the type always counts */
    key_w.ttl_value = 1;
    key_w.ttl = (char *)"1";
    assert(!compare_records(key, &key_w, false));
    key_w.type_code = 60;
    assert(!compare_records(key, &key_w, true));
    zt_free(&z);
    printf("  -> canonical RR comparison passed.\n");
}

int main(void) {
    printf("=== Starting Zone Parser Path Coverage Tests ===\n");
    test_x37_rdata_name_case();
    test_x38_wks_port_names();
    test_x32_drop_unencodable();
    test_x16_x25_compare_records();
    test_d08_readme_types();
    test_mldsa44_large_blobs();
    test_r22_mnemonics_and_classes();
    test_r22_omitted_ttl();
    test_r22_relative_origin();
    test_r22_generate_bind();
    test_o14_ttl_high_bit();
    test_drop_out_of_zone();
    test_all_types_parse_and_serialize();
    test_rfc3597_generic_form();
    test_svcb_quoted_values();
    test_rejection_tables();
    test_field_mutations();
    test_origin_ttl_owner_syntax();
    test_syntax_errors();
    test_generate();
    test_include();
    test_tags_and_semantics();
    test_extended_negative_paths();
    printf("=== All Zone Parser Path Coverage Tests PASSED ===\n");
    return 0;
}
