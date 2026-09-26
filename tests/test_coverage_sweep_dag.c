/*
 * test_coverage_sweep_dag.c - systematic branch-coverage sweeps for dag.
 *
 *   1. Every command-line option token (bare, "no" form, "=value" with valid,
 *      empty, out-of-range and garbage values, with and without a following
 *      argument) is fed to parse_query_arg_token().
 *   2. print_response() renders synthetic responses (all sections, every
 *      header flag / rcode, EDNS options, TSIG) under every display-option
 *      combination, then the same packets truncated and byte-mutated.
 *   3. dns64 prefix detection and SVCB parameter rendering corner cases.
 * dag.c is compiled into this test with main() renamed (same as test_dag_format).
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
#include "sweep_watchdog.h"
#include <fcntl.h>
#undef main

#include "dns_zone_parser.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

#define N(a) (sizeof(a) / sizeof((a)[0]))

static const char *OPTS[] = {
    "+aaflag",
    "+aaonly",
    "+additional",
    "+adflag",
    "+all",
    "+allcompare",
    "+answer",
    "+authority",
    "+badcookie",
    "+besteffort",
    "+bufsize=",
    "+cdflag",
    "+class",
    "+cmd",
    "+co",
    "+coflag",
    "+comments",
    "+cookie",
    "+cookie=",
    "+crypto",
    "+defname",
    "+dns64prefix",
    "+dnssec",
    "+do",
    "+domain=",
    "+edns",
    "+edns=",
    "+ednsflags",
    "+ednsflags=",
    "+ednsnegotiation",
    "+ednsopt=",
    "+expandaaaa",
    "+expire",
    "+fail",
    "+fuzztime",
    "+fuzztime=",
    "+glue",
    "+header-only",
    "+hexdump",
    "+hexdump-query",
    "+hexdump-response",
    "+http",
    "+http-get",
    "+http-get=",
    "+http-plain",
    "+http-plain-get",
    "+http-plain-get=",
    "+http-plain-post",
    "+http-plain-post=",
    "+http-plain=",
    "+http-post",
    "+http-post=",
    "+http=",
    "+https",
    "+https-get",
    "+https-get=",
    "+https-post",
    "+https-post=",
    "+https=",
    "+identify",
    "+idn",
    "+idnin",
    "+idnout",
    "+ignore",
    "+keepalive",
    "+keepopen",
    "+ldnsz",
    "+mqtype=",
    "+multi",
    "+multiline",
    "+ndots=",
    "+noaaflag",
    "+noaaonly",
    "+noadditional",
    "+noadflag",
    "+noall",
    "+noanswer",
    "+noauthority",
    "+nobadcookie",
    "+nobesteffort",
    "+nocdflag",
    "+noclass",
    "+nocmd",
    "+noco",
    "+nocoflag",
    "+nocomments",
    "+nocookie",
    "+nocrypto",
    "+nodefname",
    "+nodns64prefix",
    "+nodnssec",
    "+nodo",
    "+noedns",
    "+noednsflags",
    "+noednsnegotiation",
    "+noednsopt",
    "+noexpandaaaa",
    "+noexpire",
    "+nofail",
    "+nofuzztime",
    "+noglue",
    "+noheader-only",
    "+nohexdump",
    "+nohexdump-query",
    "+nohexdump-response",
    "+nohttp",
    "+nohttp-plain",
    "+nohttps",
    "+noidentify",
    "+noidn",
    "+noidnin",
    "+noidnout",
    "+noignore",
    "+nokeepalive",
    "+nokeepopen",
    "+noldnsz",
    "+nomqtype",
    "+nomulti",
    "+nomultiline",
    "+nonsid",
    "+nonssearch",
    "+noonesoa",
    "+noopcode",
    "+nopadding",
    "+noproxy",
    "+noproxy-plain",
    "+noqr",
    "+noquestion",
    "+noraflag",
    "+nordflag",
    "+norec",
    "+norecurse",
    "+norrcomments",
    "+nosearch",
    "+noshort",
    "+noshowbadcookie",
    "+noshowbadvers",
    "+noshowsearch",
    "+nosig0",
    "+nosplit",
    "+nostats",
    "+nosubnet",
    "+notcflag",
    "+notcp",
    "+notls",
    "+notls-ca",
    "+notrace",
    "+nottlid",
    "+nottlunits",
    "+nounknownformat",
    "+novc",
    "+noyaml",
    "+nozflag",
    "+nsid",
    "+nssearch",
    "+onesoa",
    "+opcode=",
    "+padding",
    "+padding=",
    "+proxy",
    "+proxy-plain",
    "+proxy-plain=",
    "+proxy=",
    "+qid=",
    "+qr",
    "+question",
    "+raflag",
    "+rdflag",
    "+rec",
    "+recurse",
    "+retry=",
    "+rrcomments",
    "+search",
    "+short",
    "+showbadcookie",
    "+showbadvers",
    "+showsearch",
    "+sig0",
    "+sig0-alg=",
    "+sig0-keytag=",
    "+sig0-name=",
    "+sig0-pkey=",
    "+split=",
    "+stats",
    "+subnet=",
    "+tcflag",
    "+tcp",
    "+tcp-mss=",
    "+tcp-window=",
    "+time=",
    "+timeout=",
    "+tls",
    "+tls-ca",
    "+tls-ca=",
    "+tls-certfile=",
    "+tls-hostname=",
    "+tls-keyfile=",
    "+trace",
    "+tries=",
    "+tsig=",
    "+ttlid",
    "+ttlunits",
    "+udp",
    "+unknownformat",
    "+vc",
    "+yaml",
    "+zflag",
    "--break",
    "--hex",
    "--hex=",
    "--prereq-nxdomain",
    "--prereq-nxrrset",
    "--prereq-yxdomain",
    "--prereq-yxrrset",
    "--prereq=",
    "--tcp",
    "--test-all",
    "--update-add",
    "--update-del",
    "--update-del-exact",
    "-4",
    "-6",
    "-b",
    "-c",
    "-f",
    "-k",
    "-m",
    "-p",
    "-q",
    "-r",
    "-t",
    "-u",
    "-x",
    "-y"
};

static const char *VALS[] = { "", "0", "1", "3", "10", "512", "4096", "65535", "65536", "-1", "abc", "1.5",
    "10:0102", "10", "0x10", "192.0.2.0/24", "2001:db8::/48", "0/0", "1.2.3.4/33", "hmac-sha256:k:c2VjcmV0",
    "k:c2VjcmV0", "c2VjcmV0", "0011223344556677", "00112233445566778899aabbccddeeff00112233",
    "A", "AAAA,TXT", "TYPE99", "https://x/dns-query", "/dns-query", "notify", "update", "15", "SIG", "ECDSAP256SHA256" };

static int run_parse(int argc, char **argv) {
    query_spec_t spec;
    init_query_spec(&spec);
    int rc = 0;
    for (int i = 0; i < argc && rc >= 0;) {
        rc = parse_query_arg_token(argc, argv, i, &spec);
        if (rc <= 0) break;
        i += rc;
    }
    (void)get_arg_consume_count(argc, argv, 0);
    free_query_opts(&spec.qo);
    return rc;
}

static void test_option_sweep(void) {
    printf("[TEST] dag sweep: every option token x value forms...\n");
    /* dag reports every rejected token with a usage line on stderr: tens of
     * thousands of lines (~575 KB) that only bloat the CI log. Mute stderr
     * for the sweep (SWEEP_VERBOSE=1 keeps it). */
    fflush(stderr);
    int saved_err = -1;
    if (!getenv("SWEEP_VERBOSE")) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { saved_err = dup(2); dup2(dn, 2); close(dn); }
    }
    size_t calls = 0;
    for (size_t o = 0; o < N(OPTS); o++) {
        const char *opt = OPTS[o];
        size_t ol = strlen(opt);
        bool takes_eq = ol > 0 && opt[ol - 1] == '=';
        char a0[256], a1[64] = "next-arg";
        char *argv3[3] = { a0, a1, (char *)"A" };
        /* bare token, with a following argument, and at the end of argv */
        snprintf(a0, sizeof(a0), "%s", opt);
        run_parse(1, argv3); run_parse(3, argv3); calls += 2;
        for (size_t v = 0; v < N(VALS); v++) {
            if (takes_eq) snprintf(a0, sizeof(a0), "%s%s", opt, VALS[v]);
            else snprintf(a0, sizeof(a0), "%s", opt);
            snprintf(a1, sizeof(a1), "%s", VALS[v]);
            run_parse(2, argv3); run_parse(3, argv3); calls += 2;
            if (!takes_eq && opt[0] == '+') {           /* "+opt=value" for boolean options too */
                snprintf(a0, sizeof(a0), "%s=%s", opt, VALS[v]);
                run_parse(1, argv3); calls++;
            }
        }
        /* abbreviated forms (dig accepts unique prefixes) */
        if (opt[0] == '+' && ol > 4) {
            snprintf(a0, sizeof(a0), "%.*s", (int)(ol > 5 ? 5 : ol - 1), opt);
            run_parse(1, argv3); calls++;
        }
    }
    /* whole command lines through the prescan + slice parser */
    char *lines[][16] = {
        { "dag", "+short", "+yaml", "+noall", "+answer", "example.", "A", NULL },
        { "dag", "-x", "192.0.2.1", "-x", "2001:db8::1", "-x", "bogus", NULL },
        { "dag", "-c", "CH", "-c", "HS", "-c", "NONE", "-c", "ANY", "-c", "CLASS9", NULL },
        { "dag", "-t", "IXFR=123", "-t", "TYPE65535", "-t", "bogus", "-q", "x.example.", NULL },
        { "dag", "@192.0.2.1", "-p", "5300", "-b", "127.0.0.1#5301", "-4", "-6", NULL },
        { "dag", "--hex", "000001000001", "--hex=zz", "--test-all", NULL },
        { "dag", "--update-add", "a.example. 300 A 192.0.2.1", "--update-del", "b.example. A", NULL },
        { "dag", "--prereq-nxrrset", "a.example.", "A", "--prereq-yxrrset", "a.example.", "A", "192.0.2.1", NULL },
        { "dag", "--prereq-nxdomain", "c.example.", "--prereq-yxdomain", "d.example.", "--prereq=bogus", NULL },
        { "dag", "-y", "hmac-sha512:k:c2VjcmV0", "-k", "/nonexistent/key", "+sig0-alg=13", NULL },
    };
    for (size_t l = 0; l < N(lines); l++) {
        int argc = 0; while (lines[l][argc]) argc++;
        query_spec_t g; init_query_spec(&g);
        prescan_always_global_options(argc, lines[l], &g);
        query_spec_t spec; init_query_spec(&spec);
        (void)parse_arg_slice(1, argc, argc, lines[l], &spec);
        query_spec_t copy; init_query_spec(&copy);
        deep_copy_query_opts(&copy.qo, &spec.qo);
        free_query_opts(&copy.qo); free_query_opts(&spec.qo); free_query_opts(&g.qo);
    }
    const char *types[] = { "A", "a", "TYPE1", "TYPE65535", "TYPE65536", "TYPE", "TYPEx", "IXFR=5", "ANY", "NSEC3PARAM",
                            "", "CLASS1", "NONE", "SPF", "ZONEMD", "DLV", "bogus" };
    for (size_t t = 0; t < N(types); t++) { uint16_t out; (void)resolve_qtype(types[t], &out); (void)parse_qtype(types[t]); }
    fflush(stderr);
    if (saved_err >= 0) { dup2(saved_err, 2); close(saved_err); }
    printf("  -> %zu option parses done.\n", calls);
}

/* ---- print_response over synthetic packets ---------------------------- */
static size_t put_name(uint8_t *p, size_t o, const char *n) { return o + (size_t)write_uncompressed_name(p, o, 4096, n); }
static size_t put_rr(uint8_t *p, size_t o, const char *name, uint16_t t, uint16_t c, uint32_t ttl, const uint8_t *rd, uint16_t rl) {
    o = put_name(p, o, name);
    p[o++] = (uint8_t)(t >> 8); p[o++] = (uint8_t)t; p[o++] = (uint8_t)(c >> 8); p[o++] = (uint8_t)c;
    p[o++] = (uint8_t)(ttl >> 24); p[o++] = (uint8_t)(ttl >> 16); p[o++] = (uint8_t)(ttl >> 8); p[o++] = (uint8_t)ttl;
    p[o++] = (uint8_t)(rl >> 8); p[o++] = (uint8_t)rl; memcpy(p + o, rd, rl); return o + rl;
}

static size_t build_resp(uint8_t *p, int variant) {
    memset(p, 0, 12);
    p[0] = 0x12; p[1] = 0x34;
    p[2] = (uint8_t)(0x80 | ((variant & 7) << 3) | (variant & 8 ? 0x04 : 0) | (variant & 16 ? 0x02 : 0) | 0x01);
    p[3] = (uint8_t)((variant & 32 ? 0x80 : 0) | (variant & 64 ? 0x20 : 0) | (variant & 128 ? 0x10 : 0) | (variant % 11));
    size_t o = 12;
    p[5] = 1; o = put_name(p, o, "www.example."); p[o++] = 0; p[o++] = (variant & 256) ? 252 : 1; p[o++] = 0; p[o++] = 1;
    uint8_t a[4] = { 192, 0, 2, 1 }, aaaa[16] = { 0x20, 1, 0xd, 0xb8, [12] = 0xC0, [13] = 0, [14] = 0, [15] = 0xAA };
    uint8_t soa[64]; size_t sl = 0;
    sl = (size_t)write_uncompressed_name(soa, 0, 64, "ns.example."); sl += (size_t)write_uncompressed_name(soa, sl, 64, "h.example.");
    for (int i = 0; i < 20; i++) soa[sl++] = (uint8_t)(i * 7);
    uint8_t txt[] = { 5, 'h', 'e', '\"', 'l', 0x7f, 0 };
    uint8_t rrsig[] = { 0, 1, 13, 2, 0, 0, 14, 16, 0x70, 0, 0, 0, 0x60, 0, 0, 0, 0x30, 0x39, 7, 'e','x','a','m','p','l','e', 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    uint16_t an = 0, ns = 0, ar = 0;
    o = put_rr(p, o, "www.example.", 1, 1, 300, a, 4); an++;
    o = put_rr(p, o, "www.example.", 28, 1, 86400 * 8, aaaa, 16); an++;
    o = put_rr(p, o, "www.example.", 16, 1, 0, txt, sizeof(txt) - 1); an++;
    o = put_rr(p, o, "www.example.", 46, 1, 3600, rrsig, sizeof(rrsig)); an++;
    if (variant & 256) { o = put_rr(p, o, "example.", 6, 1, 300, soa, (uint16_t)sl); an++; }
    o = put_rr(p, o, "example.", 6, 1, 300, soa, (uint16_t)sl); ns++;
    o = put_rr(p, o, "example.", 2, 3, 300, (const uint8_t *)"\2ns\7example\0", 12); ns++;
    o = put_rr(p, o, "ns.example.", 1, 1, 300, a, 4); ar++;
    /* OPT with cookie, EDE, NSID, ECS, keepalive, padding, expire, unknown */
    uint8_t opt[200]; size_t ol = 0;
    const uint8_t cookie[] = { 0, 10, 0, 24, 1,2,3,4,5,6,7,8, 1,0,0,0, 0x60,0,0,0, 9,9,9,9,9,9,9,9 };
    const uint8_t ede[] = { 0, 15, 0, 7, 0, 18, 'b', 'l', 'o', 'c', 'k' };
    const uint8_t nsid[] = { 0, 3, 0, 4, 'n', 's', 0x01, 'x' };
    const uint8_t ecs[] = { 0, 8, 0, 7, 0, 1, 24, 16, 198, 51, 100 };
    const uint8_t ka[] = { 0, 11, 0, 2, 0, 100 };
    const uint8_t pad[] = { 0, 12, 0, 3, 0, 0, 0 };
    const uint8_t exp[] = { 0, 9, 0, 4, 0, 0, 1, 0 };
    const uint8_t unk[] = { 0x12, 0x34, 0, 2, 0xAB, 0xCD };
    const uint8_t mq[] = { 0, 21, 0, 2, 0, 28 };
    const uint8_t ext[] = { 0xFE, 0x81, 0, 5, 1, 0, 0, 0, 1 };
    const uint8_t *os[] = { cookie, ede, nsid, ecs, ka, pad, exp, unk, mq, ext };
    const size_t osz[] = { sizeof(cookie), sizeof(ede), sizeof(nsid), sizeof(ecs), sizeof(ka), sizeof(pad), sizeof(exp), sizeof(unk), sizeof(mq), sizeof(ext) };
    for (size_t i = 0; i < N(os); i++) if ((variant >> (i % 9)) & 1 || variant > 400) { memcpy(opt + ol, os[i], osz[i]); ol += osz[i]; }
    p[o++] = 0; p[o++] = 0; p[o++] = 41; p[o++] = 0x10; p[o++] = 0;
    p[o++] = (uint8_t)(variant & 0x100 ? 1 : 0); p[o++] = (uint8_t)(variant & 0x200 ? 1 : 0);
    p[o++] = (uint8_t)((variant & 1) ? 0x80 : 0); p[o++] = 0;
    p[o++] = (uint8_t)(ol >> 8); p[o++] = (uint8_t)ol; memcpy(p + o, opt, ol); o += ol; ar++;
    if (variant & 512) {   /* TSIG record */
        uint8_t ts[64]; size_t tl = (size_t)write_uncompressed_name(ts, 0, 64, "hmac-sha256.");
        const uint8_t tail[] = { 0, 0, 0x60, 0, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4, 0x12, 0x34, 0, 16, 0, 0 };
        memcpy(ts + tl, tail, sizeof(tail)); tl += sizeof(tail);
        o = put_rr(p, o, "key.", 250, 255, 0, ts, (uint16_t)tl); ar++;
    }
    p[7] = (uint8_t)an; p[9] = (uint8_t)ns; p[11] = (uint8_t)ar;
    return o;
}

static void test_print_response_sweep(void) {
    printf("[TEST] dag sweep: print_response over flags x rcodes x options x display modes...\n");
    fflush(stdout);
    int saved = dup(1);
    int dn = open("/dev/null", O_WRONLY);
    dup2(dn, 1);
    uint8_t pkt[4096], m[4096];
    for (int variant = 0; variant < 1024; variant += 3) {
        size_t len = build_resp(pkt, variant);
        for (int d = 0; d < 24; d++) {
            display_opts_t o; memset(&o, 0, sizeof(o));
            o.show_question = o.show_answer = o.show_authority = o.show_additional = !(d == 5);
            o.show_comments = d != 6; o.show_stats = true; o.show_cmd = d & 1;
            o.short_mode = d == 1; o.identify = d == 2 || d == 1; o.multiline = d == 3 || d == 10; o.yaml = d == 4 || d == 11;
            o.ttlid = d != 7; o.ttlunits = d == 8; o.show_class = d != 9; o.show_crypto = d != 12; o.rrcomments = d == 10 || d == 13;
            o.onesoa = d == 14; o.show_badcookie_msg = d == 15; o.show_badvers_msg = d == 15; o.expandaaaa = d == 16;
            o.split_width = d == 17 ? 4 : 0; o.force_unknown_format = d == 18; o.expire = d == 19; o.idnout = d == 20;
            o.besteffort = d == 21; o.check_dns64prefix = d == 22; o.show_query_message = d == 23;
            o.has_expected_client_cookie = d & 2; memcpy(o.expected_client_cookie, "\1\2\3\4\5\6\7\x08", 8);
            axfr_state_t st; memset(&st, 0, sizeof(st)); st.is_axfr = variant & 256;
            print_response(pkt, len, (d & 4) ? &st : NULL, &o);
        }
        if (variant % 9 == 0) {
            display_opts_t o; memset(&o, 0, sizeof(o));
            o.show_question = o.show_answer = o.show_authority = o.show_additional = o.show_comments = true;
            for (size_t cut = 0; cut < len; cut++) print_response(pkt, cut, NULL, &o);
            for (size_t pos = 0; pos < len; pos++) { memcpy(m, pkt, len); m[pos] ^= 0xFF; print_response(m, len, NULL, &o); o.yaml = pos & 1; }
        }
    }
    fflush(stdout);
    dup2(saved, 1); close(saved); close(dn);
    printf("  -> print_response sweep passed.\n");
}

static void test_dns64_and_svcb(void) {
    printf("[TEST] dag sweep: dns64 prefix detection and SVCB params...\n");
    char ps[64]; int pl;
    int hits = 0;
    for (int pos = 4; pos <= 12; pos++) for (int wk = 0; wk < 3; wk++) {
        uint8_t a[16] = { 0x20, 1, 0xd, 0xb8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc };
        a[pos] = 0xC0; if (pos + 1 < 16) a[pos + 1] = 0; if (pos + 2 < 16) a[pos + 2] = 0;
        if (pos + 3 < 16) a[pos + 3] = wk == 0 ? 0xAA : wk == 1 ? 0xAB : 0x01;
        if (pos >= 5 && pos <= 7) { a[8] = 0; }
        if (pos >= 5 && pos <= 8) { a[pos + 1] = 0; a[pos + 2] = pos < 8 ? 0 : a[pos + 2]; }
        if (detect_dns64_prefix_from_aaaa(a, ps, sizeof(ps), &pl)) hits++;
        a[8] = 0; a[9] = 0xC0; a[10] = 0; a[11] = 0; a[12] = (uint8_t)(wk ? 0xAB : 0xAA);
        if (detect_dns64_prefix_from_aaaa(a, ps, sizeof(ps), &pl)) hits++;
        uint8_t b[16] = { 0 }; b[8] = 0; b[(size_t)(pos > 8 ? 7 : pos)] = 0xC0;
        (void)detect_dns64_prefix_from_aaaa(b, ps, sizeof(ps), &pl);
    }
    /* SVCB: every key id 0..9 + unknown, valid and malformed values, mandatory lists */
    char out[4096];
    display_opts_t d; memset(&d, 0, sizeof(d)); d.show_crypto = true;
    for (int key = 0; key <= 10; key++) {
        for (int vlen = 0; vlen < 20; vlen++) {
            uint8_t rd[64]; size_t o = 0;
            rd[o++] = 0; rd[o++] = 1; rd[o++] = 0;                /* priority 1, target "." */
            rd[o++] = 0; rd[o++] = (uint8_t)(key == 10 ? 99 : key);
            rd[o++] = 0; rd[o++] = (uint8_t)vlen;
            for (int i = 0; i < vlen; i++) rd[o++] = (uint8_t)(i == 0 ? 2 : 'a' + i);
            for (size_t cut = 3; cut <= o; cut++) {
                format_rdata_for_display(rd, cut, 64, 0, (uint16_t)cut, out, sizeof(out), &d);
                format_rdata_for_display(rd, cut, 65, 0, (uint16_t)cut, out, 16, &d);
            }
            d.multiline = vlen & 1;
        }
    }
    printf("  -> dns64/svcb passed (%d dns64 prefixes detected).\n", hits);
}

int main(void) {
    wd_start("test_coverage_sweep_dag", 300);
    printf("=== dag Coverage Sweep Tests ===\n");
    WD_PHASE("test_option_sweep"); test_option_sweep();
    WD_PHASE("test_dns64_and_svcb"); test_dns64_and_svcb();
    WD_PHASE("test_print_response_sweep"); test_print_response_sweep();
    printf("=== All dag Coverage Sweep Tests PASSED ===\n");
    return 0;
}
