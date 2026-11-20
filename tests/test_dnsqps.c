/* Unit tests of dnsqps (tools/dnsqps_*.c): the encoder, the options, the query table and the generator, the answer parser, the histogram, the frames of
 * the kernel-bypass paths (checksums, parse, ARP, neighbor discovery, reflector), and the socket paths against the loopback reflector.  No server needed;
 * portable (Linux, FreeBSD, macOS).  Built with the sources of the modules (tools/dnsqps.c, the engine, has its own tests in run_dnsqps_test.sh). */
#include "../tools/dnsqps.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail, g_checks;
#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void test_names(void) {
    uint8_t w[256];
    CHECK(dq_name_to_wire("a.example.test", w, sizeof w) == 16);
    CHECK(w[0] == 1 && w[1] == 'a' && w[2] == 7 && w[15] == 0);
    CHECK(dq_name_to_wire("a.example.test.", w, sizeof w) == 16);
    CHECK(dq_name_to_wire(".", w, sizeof w) == 1 && w[0] == 0);
    CHECK(dq_name_to_wire("", w, sizeof w) == 1);
    CHECK(dq_name_to_wire("a..b", w, sizeof w) == 0);
    CHECK(dq_name_to_wire(".a", w, sizeof w) == 0);
    CHECK(dq_name_to_wire("a\\.b.test", w, sizeof w) == 10 && w[0] == 3 && w[2] == '.');
    CHECK(dq_name_to_wire("a\\046b", w, sizeof w) == 5 && w[2] == '.');
    CHECK(dq_name_to_wire("a\\999", w, sizeof w) == 0);
    CHECK(dq_name_to_wire("a\\", w, sizeof w) == 0);
    char big[300];
    memset(big, 'a', 64);
    big[64] = '\0';
    CHECK(dq_name_to_wire(big, w, sizeof w) == 0);   /* a label of 64 */
    memset(big, 'a', 63);
    big[63] = '\0';
    CHECK(dq_name_to_wire(big, w, sizeof w) == 65);
    char longname[400] = "";
    for (int i = 0; i < 5; i++) { strcat(longname, big); strcat(longname, "."); }
    CHECK(dq_name_to_wire(longname, w, sizeof w) == 0);   /* 5 x 64 + 1 > 255 */
    CHECK(dq_name_to_wire("a.example.test", w, 10) == 0);
}

static size_t make_query(const dq_qopts_t *o, const char *name, uint16_t qtype, uint8_t *out, size_t cap) {
    dq_prof_t p;
    uint8_t w[256];
    size_t nl = dq_name_to_wire(name, w, sizeof w);
    CHECK(dq_prof_make(&p, o));
    return dq_compose(out, cap, &p, w, nl, qtype);
}

static void test_compose(void) {
    dq_qopts_t o;
    uint8_t q[DQ_MAXQ];
    char err[100];
    dq_qopts_default(&o);
    size_t n = make_query(&o, "a.example.test", 1, q, sizeof q);
    CHECK(n == 32);
    CHECK(q[2] == 0x01 && q[3] == 0 && q[4] == 0 && q[5] == 1 && q[11] == 0);   /* RD, one question, no OPT */
    CHECK(q[28] == 0 && q[29] == 1 && q[30] == 0 && q[31] == 1);                  /* A IN */
    CHECK(dq_qopts_parse_tok(&o, "+dnssec", err, sizeof err) == 0);
    n = make_query(&o, "a.example.test", 28, q, sizeof q);
    CHECK(n == 43 && q[11] == 1 && q[28] == 0 && q[29] == 28);
    CHECK(q[32] == 0 && q[33] == 0 && q[34] == 41 && q[35] == 0x04 && q[36] == 0xD0 && q[39] == 0x80);   /* OPT, 1232, DO */
    CHECK(dq_qopts_parse_tok(&o, "+noedns", err, sizeof err) == 0);
    n = make_query(&o, "a.example.test", 1, q, sizeof q);
    CHECK(n == 32 && q[11] == 0);
    CHECK(dq_qopts_parse_tok(&o, "+bufsize=4096", err, sizeof err) == 0 && o.edns);
    CHECK(dq_qopts_parse_tok(&o, "+nsid", err, sizeof err) == 0);
    n = make_query(&o, "a.example.test", 1, q, sizeof q);
    CHECK(n == 32 + 11 + 4 && q[35] == 0x10 && q[36] == 0x00 && q[43] == 0 && q[44] == 3 && q[45] == 0 && q[46] == 0);
    CHECK(dq_qopts_parse_tok(&o, "+cookie", err, sizeof err) == 0);
    n = make_query(&o, "a.example.test", 1, q, sizeof q);
    CHECK(n == 32 + 11 + 4 + 12);
    CHECK(dq_qopts_parse_tok(&o, "+subnet=192.0.2.77/24", err, sizeof err) == 0 && o.sn_family == 1 && o.sn_prefix == 24 && o.sn_addr[2] == 2 && o.sn_addr[3] == 0);
    n = make_query(&o, "a.example.test", 1, q, sizeof q);
    CHECK(n == 32 + 11 + 4 + 12 + 8 + 3);
    CHECK(dq_qopts_parse_tok(&o, "+padding=128", err, sizeof err) == 0);
    n = make_query(&o, "a.example.test", 1, q, sizeof q);
    CHECK(n % 128 == 0 && n >= 32 + 11 + 4 + 12 + 11 + 4);
    size_t rd = ((size_t)q[32 + 9] << 8) | q[32 + 10];
    CHECK(rd == n - 32 - 11);   /* RDLEN covers every option, the padding included */
    n = make_query(&o, "a.example.test", 1, q, 40);
    CHECK(n == 0);   /* does not fit */
    /* header flags */
    dq_qopts_default(&o);
    CHECK(dq_qopts_parse_tok(&o, "+nord", err, sizeof err) == 0 && dq_qopts_parse_tok(&o, "+cd", err, sizeof err) == 0 &&
          dq_qopts_parse_tok(&o, "+ad", err, sizeof err) == 0 && dq_qopts_parse_tok(&o, "+aa", err, sizeof err) == 0 &&
          dq_qopts_parse_tok(&o, "+opcode=4", err, sizeof err) == 0 && dq_qopts_parse_tok(&o, "+class=CH", err, sizeof err) == 0);
    n = make_query(&o, "a.example.test", 16, q, sizeof q);
    CHECK(q[2] == ((4 << 3) | 0x04) && q[3] == 0x30 && q[30] == 0 && q[31] == 3);
    /* the bad ones */
    CHECK(dq_qopts_parse_tok(&o, "+bogus", err, sizeof err) == -1 && strstr(err, "unknown"));
    CHECK(dq_qopts_parse_tok(&o, "+bufsize", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+bufsize=70000", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+opcode=16", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+subnet=zzz", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+subnet=192.0.2.0/33", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+padding=0", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+rd=1", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+class=XX", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "edns", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+", err, sizeof err) == -1);
    CHECK(dq_qopts_parse_tok(&o, "+subnet=2001:db8:1:2::/48", err, sizeof err) == 0 && o.sn_family == 2 && o.sn_addr[5] == 1 && o.sn_addr[7] == 0);
    CHECK(dq_qopts_parse_tok(&o, "+nosubnet", err, sizeof err) == 0 && !o.subnet);
    CHECK(dq_qopts_parse_tok(&o, "+nopadding", err, sizeof err) == 0 && o.padding == 0);
}

static void test_resp(void) {
    dq_qopts_t o;
    uint8_t q[DQ_MAXQ];
    char err[100];
    dq_qopts_default(&o);
    dq_qopts_parse_tok(&o, "+dnssec", err, sizeof err);
    size_t n = make_query(&o, "a.example.test", 1, q, sizeof q);
    dq_resp_t r;
    CHECK(dq_resp_parse(q, n, &r) == -1);   /* QR clear: a query is not an answer */
    q[2] |= 0x80;
    q[0] = 0x12; q[1] = 0x34; q[3] |= 3;
    CHECK(dq_resp_parse(q, n, &r) == 0 && r.id == 0x1234 && r.rcode == 3 && r.opt && r.qd == 1 && r.ar == 1);
    q[32 + 5] = 1;   /* the extended RCODE of the OPT record */
    CHECK(dq_resp_parse(q, n, &r) == 0 && r.rcode == 19);
    for (size_t k = 0; k < n; k++) {   /* every cut of the answer: no crash, a verdict */
        int v = dq_resp_parse(q, k, &r);
        CHECK(v == -1 || v == 1 || v == 0);
        if (k < 12) CHECK(v == -1);
    }
    CHECK(dq_resp_parse(q, n - 1, &r) == 1);
    uint8_t bad[40];
    memcpy(bad, q, 32);
    bad[12] = 0x80;   /* a reserved label type */
    CHECK(dq_resp_parse(bad, 32, &r) == 1);
    memcpy(bad, q, 32);
    bad[12] = 0xC0; bad[13] = 0x0C;   /* a pointer to itself is not followed */
    CHECK(dq_resp_parse(bad, 32, &r) != -1);
}

static void test_hist(void) {
    dq_hist_t h;
    dq_hist_init(&h);
    CHECK(dq_hist_pct(&h, 50) == 0);
    for (uint64_t v = 0; v < 70000; v += 7) {
        size_t b = dq_hist_bucket(v), b2 = dq_hist_bucket(v + 1);
        CHECK(b <= b2 && b < DQ_HBUCKETS && dq_hist_bucket_hi(b) >= v);
    }
    CHECK(dq_hist_bucket(UINT64_MAX) == DQ_HBUCKETS - 1);
    CHECK(dq_hist_bucket(15) == 15 && dq_hist_bucket(16) == 16);
    for (uint64_t v = 1; v <= 1000; v++) dq_hist_add(&h, v * 1000);
    uint64_t p50 = dq_hist_pct(&h, 50), p99 = dq_hist_pct(&h, 99), p999 = dq_hist_pct(&h, 99.9);
    CHECK(p50 >= 500000 * 0.9 && p50 <= 500000 * 1.12);
    CHECK(p99 >= 990000 * 0.9 && p99 <= 1000000);
    CHECK(p999 <= h.max_ns && p999 >= p99);
    CHECK(h.min_ns == 1000 && h.max_ns == 1000000 && h.count == 1000);
    dq_hist_t h2;
    dq_hist_init(&h2);
    dq_hist_add(&h2, 5);
    dq_hist_merge(&h2, &h);
    CHECK(h2.count == 1001 && h2.min_ns == 5);

    dq_report_t rep;
    memset(&rep, 0, sizeof rep);
    rep.h = h;
    rep.c.sent = 1100;
    rep.c.completed = 1000;
    rep.c.lost = 100;
    rep.c.rcode[0] = 900;
    rep.c.rcode[3] = 100;
    rep.run_s = 2.0;
    rep.io_name = "sendto";
    rep.threads = 2;
    rep.sockets = 1;
    snprintf(rep.server, sizeof rep.server, "192.0.2.1:53 \"x\"");
    FILE *f = tmpfile();
    if (f) {
        dq_print_text(f, &rep);
        dq_print_json(f, &rep);
        dq_print_interval(f, 1.0, 1.0, 10, 9, 1, 9000, 9);
        rewind(f);
        char buf[8192];
        size_t got = fread(buf, 1, sizeof buf - 1, f);
        buf[got] = '\0';
        fclose(f);
        CHECK(strstr(buf, "Queries sent:         1100"));
        CHECK(strstr(buf, "Queries lost:         100 (9.09%)"));
        CHECK(strstr(buf, "NOERROR 900 (90.00%), NXDOMAIN 100 (10.00%)"));
        CHECK(strstr(buf, "Queries per second:   500.0"));
        CHECK(strstr(buf, "\"sent\":1100") && strstr(buf, "\"qps\":500.000") && strstr(buf, "\"NXDOMAIN\":100"));
        CHECK(strstr(buf, "\"server\":\"192.0.2.1:53 \\\"x\\\"\""));
        CHECK(strstr(buf, "[Interval] t=1.0s sent=10"));
    }
}

static void test_opts(void) {
    dq_cfg_t c;
    char err[300];
    dq_cfg_default(&c);
    char *a1[] = { "-s", "192.0.2.1", "-p5300", "-Q", "50k", "+dnssec", "@192.0.2.9", "--io=sendto", "-d", "q.txt", "-T", "3", "--json", "-r", "-S", "0.5" };
    CHECK(dq_parse_args(&c, 16, a1, err, sizeof err) == 0);
    CHECK(!strcmp(c.server, "192.0.2.9") && c.port == 5300 && c.rate == 50000 && c.qo.dnssec && c.qo.edns && c.io == DQ_IO_SENDTO && c.threads == 3 && c.json &&
          c.ignore_rc && c.interval == 0.5);
    CHECK(dq_cfg_check(&c, err, sizeof err) == 0 && c.duration == 30);
    dq_cfg_default(&c);
    char *a2[] = { "--rate", "5M", "--timeout=2.5", "--null-target=sink", "--zipf", "0.8", "--miss", "0.25", "--qtypes", "A:7,MX", "--next-hop-mac", "02:00:00:00:00:01",
                   "--next-hop", "192.0.2.254", "--xdp-mode", "skb", "--queue", "2", "--sport-base", "41000", "--seed", "42", "--no-pin", "-v" };
    CHECK(dq_parse_args(&c, 24, a2, err, sizeof err) == 0);
    CHECK(c.rate == 5000000 && c.timeout == 2.5 && c.null_target && c.null_sink && c.zipf == 0.8 && c.miss == 0.25 && !strcmp(c.qtypes, "A:7,MX") && c.queue == 2 &&
          c.sport_base == 41000 && c.seed == 42 && c.no_pin && c.verbose && !strcmp(c.xdp_mode, "skb"));
    CHECK(dq_cfg_check(&c, err, sizeof err) < 0);   /* no queries */
    char *bad[][3] = { { "-Z", NULL, NULL }, { "--rate", NULL, NULL }, { "-Q", "0", NULL }, { "+bogus", NULL, NULL }, { "--io", "rio", NULL }, { "-p", "70000", NULL },
                       { "--rate=", NULL, NULL }, { "--json=1", NULL, NULL }, { "-jv", NULL, NULL }, { "stray", NULL, NULL }, { "--xdp-mode", "fast", NULL },
                       { "--next-hop-mac", "zz", NULL }, { "--qtypes", "A:0", NULL }, { "--qtypes", "NOSUCH", NULL }, { "--null-target=x", NULL, NULL },
                       { "--reflect", "70000", NULL }, { "-t", "-1", NULL }, { "--time", "nan", NULL }, { "-T", "0", NULL }, { "-c", "65", NULL }, { "-B", "1025", NULL },
                       { "@", NULL, NULL }, { "--miss", "1.5", NULL }, { "--sport-base", "80", NULL }, { "-q", NULL, NULL } };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        int n = bad[i][1] ? 2 : 1;
        dq_cfg_default(&c);
        CHECK(dq_parse_args(&c, n, bad[i], err, sizeof err) == -1 && err[0]);
    }
    dq_cfg_default(&c);
    c.qfile[0] = 'q';
    c.zfile[0] = 'z';
    CHECK(dq_cfg_check(&c, err, sizeof err) < 0);
    c.zfile[0] = 0;
    c.miss = 0.1;
    CHECK(dq_cfg_check(&c, err, sizeof err) < 0);
    c.miss = 0;
    c.null_target = true;
    c.io = DQ_IO_XDP;
    CHECK(dq_cfg_check(&c, err, sizeof err) < 0);
    dq_cfg_default(&c);
    c.zfile[0] = 'z';
    c.runs = 2;
    CHECK(dq_cfg_check(&c, err, sizeof err) < 0);
    /* the rc file */
    dq_cfg_default(&c);
    const char *rc = "# defaults\n-T 2 +dnssec\n'--server' \"192.0.2.7\"   # comment\n-h\n";
    CHECK(dq_parse_rc_buf(&c, rc, strlen(rc), err, sizeof err) == 0);
    CHECK(c.threads == 2 && c.qo.dnssec && !strcmp(c.server, "192.0.2.7") && !c.help);
    CHECK(dq_parse_rc_buf(&c, "'unterminated", 13, err, sizeof err) == -1);
    CHECK(dq_parse_rc_buf(&c, "--bogus", 7, err, sizeof err) == -1);
    char *huge = malloc(70000);
    memset(huge, 'a', 70000);
    CHECK(dq_parse_rc_buf(&c, huge, 70000, err, sizeof err) == -1);
    free(huge);
    char many[3000];
    many[0] = 0;
    for (int i = 0; i < 400; i++) strcat(many, "-v ");
    CHECK(dq_parse_rc_buf(&c, many, strlen(many), err, sizeof err) == -1);
    /* small parsers */
    uint64_t u;
    CHECK(dq_parse_u64("12", &u, 100) && u == 12 && dq_parse_u64("3k", &u, 1000000) && u == 3000 && dq_parse_u64("2M", &u, 1000000000) && u == 2000000);
    CHECK(!dq_parse_u64("101", &u, 100) && !dq_parse_u64("-1", &u, 100) && !dq_parse_u64("", &u, 100) && !dq_parse_u64("1x", &u, 100) && !dq_parse_u64("99999999999999999999", &u, UINT64_MAX));
    CHECK(!dq_parse_u64("20000000000G", &u, UINT64_MAX));
    double d;
    CHECK(dq_parse_dbl("0.5", &d, 0, 1) && d == 0.5 && !dq_parse_dbl("2", &d, 0, 1) && !dq_parse_dbl("x", &d, 0, 1) && !dq_parse_dbl("inf", &d, 0, 1) && !dq_parse_dbl("1e999", &d, 0, 1e300));
    uint8_t mac[6], ip[16];
    int fam;
    CHECK(dq_parse_mac("02:aa:BB:00:10:ff", mac) && mac[0] == 2 && mac[2] == 0xBB && mac[5] == 0xFF && dq_parse_mac("02-aa-bb-00-10-ff", mac));
    CHECK(!dq_parse_mac("02:aa:bb:00:10", mac) && !dq_parse_mac("02:aa:bb:00:10:ff:", mac) && !dq_parse_mac("0g:aa:bb:00:10:ff", mac));
    CHECK(dq_parse_ip("192.0.2.1", ip, &fam) && fam == 1 && ip[3] == 1 && dq_parse_ip("2001:db8::2", ip, &fam) && fam == 2 && ip[15] == 2 && !dq_parse_ip("host", ip, &fam));
    uint16_t ty[DQ_MAXTYPES];
    uint32_t wt[DQ_MAXTYPES];
    CHECK(dq_parse_qtypes("A:70,AAAA:20,MX", ty, wt, err, sizeof err) == 3 && ty[0] == 1 && ty[1] == 28 && ty[2] == 15 && wt[0] == 70 && wt[2] == 1);
    CHECK(dq_parse_qtypes("a,type65280", ty, wt, err, sizeof err) == 2 && ty[1] == 65280);
    CHECK(dq_parse_qtypes("", ty, wt, err, sizeof err) == -1);
    char host[64];
    int port;
    CHECK(dq_split_hostport("5300", host, sizeof host, &port) && !strcmp(host, "127.0.0.1") && port == 5300);
    CHECK(dq_split_hostport("192.0.2.1:53", host, sizeof host, &port) && !strcmp(host, "192.0.2.1") && port == 53);
    CHECK(dq_split_hostport("[2001:db8::1]:5353", host, sizeof host, &port) && !strcmp(host, "2001:db8::1") && port == 5353);
    CHECK(dq_split_hostport("2001:db8::1", host, sizeof host, &port) && port == 53);
    CHECK(dq_split_hostport("192.0.2.1", host, sizeof host, &port) && port == 53);
    CHECK(!dq_split_hostport("", host, sizeof host, &port) && !dq_split_hostport("[::1", host, sizeof host, &port) && !dq_split_hostport("1.2.3.4:0", host, sizeof host, &port) &&
          !dq_split_hostport("[::1]x", host, sizeof host, &port) && !dq_split_hostport("1.2.3.4:99999", host, sizeof host, &port));
}

static void test_table(void) {
    dq_cfg_t c;
    char err[200];
    dq_cfg_default(&c);
    const char *txt = "a.example.test A\nb.example.test MX +dnssec\n# comment\n; another\n\nc.example.test TYPE65280 +nord\r\nd.example.test\ne.example.test +cd\n";
    dq_qtab_t t;
    CHECK(dq_qtab_from_lines(&t, &c, txt, strlen(txt), err, sizeof err) == 0);
    CHECK(t.n == 5 && t.nprof == 4);
    CHECK(t.ents[0].prof == t.ents[3].prof && t.ents[1].qtype == 15 && t.ents[2].qtype == 65280 && t.ents[3].qtype == 1 && t.ents[4].qtype == 1);
    uint8_t q[DQ_MAXQ];
    dq_cur_t cur;
    dq_cur_init(&cur, &t, 0, 1, 1);
    size_t l = dq_next_query(&t, &cur, q, sizeof q, 1);
    CHECK(l == 32 && q[11] == 0 && q[2] == 1);
    l = dq_next_query(&t, &cur, q, sizeof q, 1);
    CHECK(l == 43 && q[11] == 1 && q[29] == 15);
    l = dq_next_query(&t, &cur, q, sizeof q, 1);
    CHECK(l == 32 && q[2] == 0 && q[28] == 0xFF && q[29] == 0);   /* +nord, TYPE65280 */
    CHECK(dq_next_query(&t, &cur, q, sizeof q, 1) == 32);
    CHECK(dq_next_query(&t, &cur, q, sizeof q, 1) == 32 && (q[3] & 0x10));
    CHECK(dq_next_query(&t, &cur, q, sizeof q, 1) == 0);   /* one pass */
    /* two workers share a pass by stride */
    dq_cur_t c0, c1;
    dq_cur_init(&c0, &t, 0, 2, 1);
    dq_cur_init(&c1, &t, 1, 2, 1);
    int n0 = 0, n1 = 0;
    while (dq_next_query(&t, &c0, q, sizeof q, 1)) n0++;
    while (dq_next_query(&t, &c1, q, sizeof q, 1)) n1++;
    CHECK(n0 == 3 && n1 == 2);
    /* two passes, and unlimited passes wrap */
    dq_cur_init(&c0, &t, 0, 1, 1);
    int n = 0;
    while (dq_next_query(&t, &c0, q, sizeof q, 2)) n++;
    CHECK(n == 10);
    dq_cur_init(&c0, &t, 0, 1, 1);
    for (int i = 0; i < 23; i++) CHECK(dq_next_query(&t, &c0, q, sizeof q, 0) != 0);
    /* a worker without entries ends at once */
    dq_cur_init(&c0, &t, 7, 8, 1);
    CHECK(dq_next_query(&t, &c0, q, sizeof q, 0) == 0);
    dq_qtab_free(&t);
    /* errors */
    const char *bad[] = { "a..b A\n", "a.example.test NOSUCHTYPE\n", "a.example.test A +bogus\n", "a.example.test A extra\n", "\n\n# only comments\n" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) CHECK(dq_qtab_from_lines(&t, &c, bad[i], strlen(bad[i]), err, sizeof err) == -1);
    char longline[1100];
    memset(longline, 'a', sizeof longline);
    CHECK(dq_qtab_from_lines(&t, &c, longline, sizeof longline, err, sizeof err) == -1);
    char manyopts[1000] = "a.example.test A";
    for (int i = 0; i < 30; i++) strcat(manyopts, " +rd");
    CHECK(dq_qtab_from_lines(&t, &c, manyopts, strlen(manyopts), err, sizeof err) == -1);   /* too many fields */
    /* more option sets than the table keeps */
    char *prof = malloc(20000);
    prof[0] = 0;
    for (int i = 0; i < DQ_MAXPROF + 2; i++) {
        char ln[80];
        snprintf(ln, sizeof ln, "a.example.test A +bufsize=%d\n", 600 + i);
        strcat(prof, ln);
    }
    CHECK(dq_qtab_from_lines(&t, &c, prof, strlen(prof), err, sizeof err) == -1 && strstr(err, "option sets"));
    free(prof);
}

static void test_generated(void) {
    const char *path = "dnsqps_test_names.tmp";
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (!f) return;
    for (int i = 0; i < 1000; i++) fprintf(f, "host%d.zone%d.example.test.  3600 IN A 192.0.2.1\n", i, i % 7);
    fprintf(f, "# comment\n\n");
    fclose(f);
    dq_cfg_t c;
    char err[200];
    dq_cfg_default(&c);
    snprintf(c.zfile, sizeof c.zfile, "%s", path);
    c.miss = 0.2;
    c.zipf = 1.0;
    c.seed = 42;
    snprintf(c.qtypes, sizeof c.qtypes, "A:3,AAAA:1");
    dq_qtab_t t;
    CHECK(dq_qtab_load(&t, &c, err, sizeof err) == 0);
    CHECK(t.gen && t.nhit == 1000 && t.nmiss == 65536 && t.ntypes == 2);
    uint8_t q[DQ_MAXQ], first[DQ_MAXQ];
    dq_cur_t cur, cur2;
    dq_cur_init(&cur, &t, 0, 1, c.seed);
    dq_cur_init(&cur2, &t, 0, 1, c.seed);
    int miss = 0, a = 0, hot = 0, total = 20000;
    uint8_t w0[256];
    size_t w0l = dq_name_to_wire("host0.zone0.example.test.", w0, sizeof w0);
    for (int i = 0; i < total; i++) {
        size_t l = dq_next_query(&t, &cur, q, sizeof q, 0), l2 = dq_next_query(&t, &cur2, first, sizeof first, 0);
        CHECK(l > 0 && l == l2 && memcmp(q, first, l) == 0);   /* the same seed, the same queries */
        if (q[13] == 'n' && q[14] == 'x') miss++;
        uint16_t qt = (uint16_t)((q[l - 4] << 8) | q[l - 3]);
        if (qt == 1) a++;
        else CHECK(qt == 28);
        if (l == 12 + w0l + 4 && memcmp(q + 12, w0, w0l) == 0) hot++;
    }
    CHECK(miss > total * 0.15 && miss < total * 0.25);
    CHECK(a > total * 0.70 && a < total * 0.80);
    CHECK(hot > total * 0.05);   /* the most popular name: about 13 % of the hits */
    dq_qtab_free(&t);
    c.miss = 0;
    c.zipf = 0;
    c.qtypes[0] = 0;
    CHECK(dq_qtab_load(&t, &c, err, sizeof err) == 0 && t.nmiss == 0);
    dq_cur_init(&cur, &t, 0, 1, 7);
    int h0 = 0;
    for (int i = 0; i < total; i++) {
        size_t l = dq_next_query(&t, &cur, q, sizeof q, 0);
        CHECK(q[l - 3] == 1);
        if (l == 12 + w0l + 4 && memcmp(q + 12, w0, w0l) == 0) h0++;
    }
    CHECK(h0 < total / 200);   /* uniform: 0.1 % */
    dq_qtab_free(&t);
    snprintf(c.zfile, sizeof c.zfile, "dnsqps_no_such_file.tmp");
    CHECK(dq_qtab_load(&t, &c, err, sizeof err) == -1);
    c.zfile[0] = 0;
    CHECK(dq_qtab_load(&t, &c, err, sizeof err) == -1);
    remove(path);
}

static void test_frames(void) {
    const uint8_t smac[6] = { 2, 0, 0, 0, 0, 1 }, dmac[6] = { 2, 0, 0, 0, 0, 2 };
    const uint8_t sip[4] = { 192, 0, 2, 1 }, dip[4] = { 192, 0, 2, 2 };
    uint8_t payload[100], fr[2048], out[2048];
    for (int i = 0; i < 100; i++) payload[i] = (uint8_t)(i * 7 + 3);
    payload[2] = 0;
    dq_frame_tpl_t t;
    dq_frame_tpl_init(&t, smac, dmac, false, sip, dip, 40001, 5300);
    for (size_t pl = 12; pl <= 100; pl += 17) {   /* odd and even lengths */
        size_t n = dq_frame_build(&t, fr, sizeof fr, payload, pl);
        CHECK(n == 42 + pl);
        CHECK(dq_csum_fold(dq_csum_add(0, fr + 14, 20)) == 0xFFFF);   /* the IPv4 header sums to all ones */
        uint32_t s = dq_csum_add(0, sip, 4);
        s = dq_csum_add(s, dip, 4) + 17 + (uint32_t)(8 + pl);
        CHECK(dq_csum_fold(dq_csum_add(s, fr + 34, 8 + pl)) == 0xFFFF);   /* and so does the UDP checksum with its pseudo header */
        dq_udp_view_t v;
        CHECK(dq_frame_parse_udp(fr, n, false, dip, &v) == 0 && v.sport == 40001 && v.dport == 5300 && v.plen == pl && memcmp(v.payload, payload, pl) == 0);
        CHECK(!memcmp(v.sip, sip, 4) && !memcmp(v.smac, smac, 6));
        CHECK(dq_frame_parse_udp(fr, n, false, sip, &v) == -1);   /* not addressed to us */
        CHECK(dq_frame_parse_udp(fr, n, true, dip, &v) == -1);
        for (size_t k = 0; k < n; k++) dq_frame_parse_udp(fr, k, false, dip, &v);   /* every cut: no read past the end */
    }
    CHECK(dq_frame_build(&t, fr, 40, payload, 20) == 0);
    /* a fragment, a bad header length, a VLAN tag */
    size_t n = dq_frame_build(&t, fr, sizeof fr, payload, 30);
    dq_udp_view_t v;
    uint8_t m[2048];
    memcpy(m, fr, n);
    m[14 + 6] |= 0x20;   /* more fragments */
    CHECK(dq_frame_parse_udp(m, n, false, dip, &v) == -1);
    memcpy(m, fr, n);
    m[14] = 0x44;
    CHECK(dq_frame_parse_udp(m, n, false, dip, &v) == -1);
    memcpy(m, fr, n);
    m[14 + 9] = 6;   /* TCP */
    CHECK(dq_frame_parse_udp(m, n, false, dip, &v) == -1);
    memcpy(m, fr, 12);
    m[12] = 0x81; m[13] = 0x00; m[14] = 0; m[15] = 5; m[16] = 0x08; m[17] = 0;
    memcpy(m + 18, fr + 14, n - 14);
    CHECK(dq_frame_parse_udp(m, n + 4, false, dip, &v) == 0 && v.plen == 30);
    /* the reflector: the frame comes back as the answer */
    size_t rn = dq_frame_reflect(fr, n, false, dip, dmac, 5300, out, sizeof out);
    CHECK(rn == n);
    CHECK(dq_frame_parse_udp(out, rn, false, sip, &v) == 0 && v.sport == 5300 && v.dport == 40001 && (v.payload[2] & 0x80) && !memcmp(v.smac, dmac, 6));
    CHECK(dq_csum_fold(dq_csum_add(0, out + 14, 20)) == 0xFFFF);
    CHECK(dq_frame_reflect(fr, n, false, dip, dmac, 5301, out, sizeof out) == 0);   /* another port */
    CHECK(dq_frame_reflect(fr, n, false, sip, dmac, 5300, out, sizeof out) == 0);   /* another address */
    /* ARP */
    uint8_t arp[128], mac[6];
    size_t an = dq_arp_request(arp, sizeof arp, smac, sip, dip);
    CHECK(an == 60 && arp[0] == 0xFF && arp[12] == 8 && arp[13] == 6 && arp[21] == 1);
    CHECK(dq_arp_request(arp, 50, smac, sip, dip) == 0);
    size_t rn2 = dq_frame_reflect(arp, an, false, dip, dmac, 5300, out, sizeof out);
    CHECK(rn2 == 60 && dq_arp_reply_parse(out, rn2, dip, mac) && !memcmp(mac, dmac, 6));
    CHECK(!dq_arp_reply_parse(out, rn2, sip, mac) && !dq_arp_reply_parse(out, 30, dip, mac));
    CHECK(dq_frame_reflect(arp, an, false, sip, dmac, 5300, out, sizeof out) == 0);   /* asks for someone else */
    /* IPv6 */
    uint8_t s6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, d6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    dq_frame_tpl_t t6;
    dq_frame_tpl_init(&t6, smac, dmac, true, s6, d6, 40002, 5300);
    n = dq_frame_build(&t6, fr, sizeof fr, payload, 31);
    CHECK(n == 62 + 31);
    uint32_t s = dq_csum_add(dq_csum_add(0, s6, 16), d6, 16) + 17 + (uint32_t)(8 + 31);
    CHECK(dq_csum_fold(dq_csum_add(s, fr + 54, 8 + 31)) == 0xFFFF);
    CHECK(dq_frame_parse_udp(fr, n, true, d6, &v) == 0 && v.v6 && v.plen == 31 && v.sport == 40002 && !memcmp(v.sip, s6, 16));
    for (size_t k = 0; k < n; k++) dq_frame_parse_udp(fr, k, true, d6, &v);
    rn = dq_frame_reflect(fr, n, true, d6, dmac, 5300, out, sizeof out);
    CHECK(rn == n && dq_frame_parse_udp(out, rn, true, s6, &v) == 0 && v.dport == 40002);
    /* neighbor discovery: the solicitation is for the solicited-node address; the advertisement is read for its target */
    size_t nn = dq_nd_solicit(arp, sizeof arp, smac, s6, d6);
    CHECK(nn == 86 && arp[0] == 0x33 && arp[1] == 0x33 && arp[2] == 0xFF && arp[5] == 2 && arp[14 + 7] == 255 && arp[14 + 40] == 135);
    CHECK(dq_nd_solicit(arp, 50, smac, s6, d6) == 0);
    uint8_t na[128];
    memset(na, 0, sizeof na);
    memcpy(na + 6, dmac, 6);
    na[12] = 0x86; na[13] = 0xDD;
    na[14] = 0x60; na[14 + 5] = 32; na[14 + 6] = 58; na[14 + 7] = 255;
    na[54] = 136;
    memcpy(na + 54 + 8, d6, 16);
    na[54 + 24] = 2; na[54 + 25] = 1;
    memcpy(na + 54 + 26, dmac, 6);
    CHECK(dq_nd_adv_parse(na, 86, d6, mac) && !memcmp(mac, dmac, 6));
    CHECK(!dq_nd_adv_parse(na, 86, s6, mac) && !dq_nd_adv_parse(na, 60, d6, mac));
    na[14 + 7] = 254;   /* RFC 4861: hop limit 255 only */
    CHECK(!dq_nd_adv_parse(na, 86, d6, mac));
    na[14 + 7] = 255;
    na[54 + 25] = 0;   /* an option of length 0 ends the walk; the sender of the frame is the answer */
    CHECK(dq_nd_adv_parse(na, 86, d6, mac) && !memcmp(mac, dmac, 6));
    for (size_t k = 0; k < 90; k++) dq_nd_adv_parse(na, k, d6, mac);
}

typedef struct { bool ok; uint8_t reply[2048]; unsigned rlen; uint8_t our_ip[4]; uint8_t our_mac[6]; } fakeif_t;

static int fake_tx(void *ctx, const uint8_t *f, unsigned len) {
    fakeif_t *x = ctx;
    x->rlen = (unsigned)dq_frame_reflect(f, len, false, x->our_ip, x->our_mac, 1, x->reply, sizeof x->reply);
    return 0;
}

static int fake_rx(void *ctx, const uint8_t **f, unsigned *len, unsigned wait_ms) {
    fakeif_t *x = ctx;
    (void)wait_ms;
    if (!x->rlen) return 0;
    *f = x->reply;
    *len = x->rlen;
    x->rlen = 0;
    return 1;
}

static void test_resolve(void) {
    fakeif_t x;
    memset(&x, 0, sizeof x);
    x.our_ip[0] = 192; x.our_ip[2] = 2; x.our_ip[3] = 2;
    memcpy(x.our_mac, "\x02\x00\x00\x00\x00\x09", 6);
    dq_rawif_t r = { fake_tx, fake_rx, &x };
    dq_target_t tg;
    char err[200];
    memset(&tg, 0, sizeof tg);
    memcpy(tg.src_mac, "\x02\x00\x00\x00\x00\x01", 6);
    tg.src_ip[0] = 192; tg.src_ip[2] = 2; tg.src_ip[3] = 1;
    memcpy(tg.hop_ip, x.our_ip, 4);
    CHECK(dq_raw_resolve_mac(&r, &tg, err, sizeof err) == 0 && tg.have_dst_mac && !memcmp(tg.dst_mac, x.our_mac, 6));
    CHECK(dq_raw_resolve_mac(&r, &tg, err, sizeof err) == 0);   /* already known: nothing is sent */
}

/* ---------------------------------------------------------------- sockets against the reflector */
typedef struct { dq_sock_t s; atomic_bool stop; bool mmsg; } refl_arg_t;

static void *refl_thread(void *p) {
    refl_arg_t *a = p;
    dq_reflect_loop(a->s, &a->stop, a->mmsg);
    return NULL;
}

static void run_io(const dq_io_ops_t *ops, bool mmsg) {
    refl_arg_t ra;
    char err[200];
    int port;
    ra.mmsg = mmsg;
    atomic_init(&ra.stop, false);
    CHECK(dq_reflect_socket("127.0.0.1", 0, &ra.s, &port, err, sizeof err) == 0);
    pthread_t th;
    pthread_create(&th, NULL, refl_thread, &ra);
    dq_cfg_t c;
    dq_cfg_default(&c);
    c.batch = 16;
    dq_target_t tg;
    CHECK(dq_target_resolve(&tg, &c, "127.0.0.1", port, err, sizeof err) == 0);
    dq_io_t *io = NULL;
    CHECK(ops->open(&io, &c, &tg, 0, 2, err, sizeof err) == 0);
    if (io) {
        uint8_t pk[8][40];
        dq_tx_t tx[8];
        for (int i = 0; i < 8; i++) {
            memset(pk[i], 0, sizeof pk[i]);
            pk[i][1] = (uint8_t)(i + 1);
            pk[i][5] = 1;
            tx[i].buf = pk[i];
            tx[i].len = 40;
        }
        CHECK(ops->send(io, 1, tx, 8) == 8);
        CHECK(ops->send(io, 0, tx, 2) == 2);
        dq_rx_t rx[16];
        int got = 0, on1 = 0, on0 = 0;
        for (int tries = 0; tries < 200 && got < 10; tries++) {
            int g = ops->recv(io, rx, 16, 50000);
            CHECK(g >= 0);
            for (int i = 0; i < g; i++) {
                CHECK(rx[i].len == 40 && (rx[i].buf[2] & 0x80) && rx[i].buf[1] >= 1 && rx[i].buf[1] <= 8);
                if (rx[i].chan == 1) on1++; else on0++;
            }
            got += g > 0 ? g : 0;
        }
        CHECK(got == 10 && on1 == 8 && on0 == 2);
        CHECK(ops->recv(io, rx, 16, 0) == 0);
        ops->close(io);
    }
    atomic_store(&ra.stop, true);
    pthread_join(th, NULL);
}

static void test_io(void) {
    const char *why;
    run_io(&dq_io_sendto, false);
    const dq_io_ops_t *mm = dq_io_for(DQ_IO_MMSG, &why);
#if defined(__linux__) || defined(__FreeBSD__)
    CHECK(mm != NULL);
    if (mm) run_io(mm, true);
#else
    CHECK(mm == NULL && why[0]);
#endif
    CHECK(dq_io_for(DQ_IO_SENDTO, &why) == &dq_io_sendto);
#ifndef HAVE_XDP
    CHECK(dq_io_for(DQ_IO_XDP, &why) == NULL && why[0]);
#endif
#ifndef __FreeBSD__
    CHECK(dq_io_for(DQ_IO_NETMAP, &why) == NULL && why[0]);
#endif
    CHECK(dq_io_for(99, &why) == NULL);
    /* a sink target: sent, never answered */
    dq_sock_t sink;
    int port;
    char err[200];
    CHECK(dq_reflect_socket("127.0.0.1", 0, &sink, &port, err, sizeof err) == 0);
    dq_cfg_t c;
    dq_cfg_default(&c);
    c.null_sink = true;
    dq_target_t tg;
    CHECK(dq_target_resolve(&tg, &c, "127.0.0.1", port, err, sizeof err) == 0);
    dq_io_t *io = NULL;
    CHECK(dq_io_sendto.open(&io, &c, &tg, 0, 1, err, sizeof err) == 0);
    uint8_t pk[20] = { 0 };
    dq_tx_t tx = { pk, 20 };
    CHECK(dq_io_sendto.send(io, 0, &tx, 1) == 1);
    dq_io_sendto.close(io);
}

int main(void) {
    dq_net_init();
    test_names();
    test_compose();
    test_resp();
    test_hist();
    test_opts();
    test_table();
    test_generated();
    test_frames();
    test_resolve();
    test_io();
    CHECK(dq_now_ns() > 0 && dq_ncpus() >= 1);
    dq_sleep_us(1000);
    if (g_fail) {
        fprintf(stderr, "dnsqps unit tests: %d of %d checks failed\n", g_fail, g_checks);
        return 1;
    }
    printf("dnsqps unit tests: all %d checks passed\n", g_checks);
    return 0;
}
