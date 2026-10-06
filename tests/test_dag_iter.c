/*
 * test_dag_iter.c - dag +trace2 (反復解決) の単体テスト
 *
 *   1. 名前ヘルパ: ラベル数・末尾 n ラベルの切り出し (エスケープされたドットを含む)
 *   2. 応答の分類 dag_iter_classify(): referral / 回答 / CNAME・DNAME / NXDOMAIN / NODATA /
 *      lame (上向き・横向き referral, REFUSED) / 不正応答、bailiwick 外 glue の除外
 *   3. 途中で切れた応答をすべての長さで分類しても範囲外アクセスしないこと (ASan で実行)
 *   4. ルートヒント: 内蔵ヒントと named.root 形式の解析
 *   5. CLI: +trace2 / +qmin / +roothints / +trace2-maxqueries の解析
 *
 * dag.c は main() を改名して取り込み、内部関数を直接呼ぶ。
 */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define main dag_main
#include "../tools/dag.c"
#undef main

#include "../tools/dag_iter.h"
#include "../tools/dag_roothints.h"

static int g_fail = 0;

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); g_fail++; } \
} while (0)

/* ------------------------------------------------------------------ */
/* パケット組み立て                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t b[4096];
    size_t len;
    int an, ns, ar;
} pkt_t;

static void put16(pkt_t *p, uint16_t v) { p->b[p->len++] = (uint8_t)(v >> 8); p->b[p->len++] = (uint8_t)v; }
static void put32(pkt_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p, (uint16_t)v); }

static void put_name(pkt_t *p, const char *name) {
    const char *s = name;
    while (*s && strcmp(s, ".") != 0) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        p->b[p->len++] = (uint8_t)l;
        memcpy(p->b + p->len, s, l);
        p->len += l;
        s += l;
        if (*s == '.') s++;
    }
    p->b[p->len++] = 0;
}

/* flags: QR/AA などヘッダ 16bit (rcode 含む) */
static void pkt_begin(pkt_t *p, uint16_t flags, const char *qname, uint16_t qtype) {
    memset(p, 0, sizeof(*p));
    put16(p, 0x1234);
    put16(p, flags);
    put16(p, 1);
    put16(p, 0); put16(p, 0); put16(p, 0);
    put_name(p, qname);
    put16(p, qtype);
    put16(p, 1);
}

static void pkt_counts(pkt_t *p) {
    p->b[6] = (uint8_t)(p->an >> 8); p->b[7] = (uint8_t)p->an;
    p->b[8] = (uint8_t)(p->ns >> 8); p->b[9] = (uint8_t)p->ns;
    p->b[10] = (uint8_t)(p->ar >> 8); p->b[11] = (uint8_t)p->ar;
}

enum { SEC_AN, SEC_NS, SEC_AR };

static void rr_hdr(pkt_t *p, int sec, const char *owner, uint16_t type) {
    put_name(p, owner);
    put16(p, type);
    put16(p, 1);
    put32(p, 3600);
    if (sec == SEC_AN) p->an++;
    else if (sec == SEC_NS) p->ns++;
    else p->ar++;
}

static void rr_name(pkt_t *p, int sec, const char *owner, uint16_t type, const char *target) {
    rr_hdr(p, sec, owner, type);
    size_t rdl = p->len;
    put16(p, 0);
    size_t start = p->len;
    put_name(p, target);
    uint16_t l = (uint16_t)(p->len - start);
    p->b[rdl] = (uint8_t)(l >> 8); p->b[rdl + 1] = (uint8_t)l;
}

static void rr_a(pkt_t *p, int sec, const char *owner, const char *addr) {
    rr_hdr(p, sec, owner, 1);
    put16(p, 4);
    inet_pton(AF_INET, addr, p->b + p->len);
    p->len += 4;
}

static void rr_aaaa(pkt_t *p, int sec, const char *owner, const char *addr) {
    rr_hdr(p, sec, owner, 28);
    put16(p, 16);
    inet_pton(AF_INET6, addr, p->b + p->len);
    p->len += 16;
}

static void rr_soa(pkt_t *p, int sec, const char *owner) {
    rr_hdr(p, sec, owner, 6);
    size_t rdl = p->len;
    put16(p, 0);
    size_t start = p->len;
    put_name(p, "ns.invalid.");
    put_name(p, "hostmaster.invalid.");
    put32(p, 1); put32(p, 3600); put32(p, 900); put32(p, 604800); put32(p, 300);
    uint16_t l = (uint16_t)(p->len - start);
    p->b[rdl] = (uint8_t)(l >> 8); p->b[rdl + 1] = (uint8_t)l;
}

#define QR 0x8000
#define AA 0x0400

static it_resp_kind_t classify(pkt_t *p, const char *qname, uint16_t qtype, const char *zone, it_resp_t *r) {
    pkt_counts(p);
    it_resp_kind_t k = dag_iter_classify(p->b, p->len, qname, qtype, zone, r);
    reset_dag_arena();
    return k;
}

/* ------------------------------------------------------------------ */

static void test_name_helpers(void) {
    printf("[TEST] name helpers\n");
    char out[256];
    CHECK(dag_iter_label_count(".") == 0);
    CHECK(dag_iter_label_count("") == 0);
    CHECK(dag_iter_label_count("com.") == 1);
    CHECK(dag_iter_label_count("www.example.com") == 3);
    CHECK(dag_iter_label_count("a\\.b.example.") == 2);

    dag_iter_name_suffix("www.example.com.", 1, out, sizeof(out));
    CHECK(strcmp(out, "com.") == 0);
    dag_iter_name_suffix("www.example.com.", 2, out, sizeof(out));
    CHECK(strcmp(out, "example.com.") == 0);
    dag_iter_name_suffix("www.example.com", 3, out, sizeof(out));
    CHECK(strcmp(out, "www.example.com.") == 0);
    dag_iter_name_suffix("www.example.com.", 9, out, sizeof(out));
    CHECK(strcmp(out, "www.example.com.") == 0);
    dag_iter_name_suffix("www.example.com.", 0, out, sizeof(out));
    CHECK(strcmp(out, ".") == 0);
    dag_iter_name_suffix("a\\.b.example.", 2, out, sizeof(out));
    CHECK(strcmp(out, "a\\.b.example.") == 0);

    const char *kinds[] = { "BAD", "ANSWER", "CNAME", "NXDOMAIN", "NODATA", "REFERRAL", "LAME", "SERVFAIL", "FORMERR" };
    for (int k = IT_RESP_BAD; k <= IT_RESP_FORMERR; k++) {
        CHECK(strcmp(dag_iter_kind_name((it_resp_kind_t)k), kinds[k]) == 0);
    }
    CHECK(strcmp(dag_iter_kind_name((it_resp_kind_t)99), "?") == 0);
}

static void test_classify_referral(void) {
    printf("[TEST] classify: referral and glue bailiwick\n");
    pkt_t p;
    it_resp_t r;

    /* test. のサーバが example.test. へ委任。glue のうち test. 配下のものだけ採用 */
    pkt_begin(&p, QR, "www.example.test.", 1);
    rr_name(&p, SEC_NS, "example.test.", 2, "ns1.example.test.");
    rr_name(&p, SEC_NS, "example.test.", 2, "ns.other.alt.");
    rr_name(&p, SEC_NS, "example.test.", 2, "ns.sibling.test.");
    rr_a(&p, SEC_AR, "ns1.example.test.", "192.0.2.1");
    rr_aaaa(&p, SEC_AR, "ns1.example.test.", "2001:db8::1");
    rr_a(&p, SEC_AR, "ns.other.alt.", "192.0.2.66");     /* bailiwick 外: 捨てる */
    rr_a(&p, SEC_AR, "ns.sibling.test.", "192.0.2.3");   /* sibling glue: bailiwick 内 */
    rr_a(&p, SEC_AR, "unrelated.test.", "192.0.2.99");   /* NS 名でない: 捨てる */
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_REFERRAL);
    CHECK(strcmp(r.cut, "example.test.") == 0);
    CHECK(r.nns == 3);
    CHECK(r.nglue == 3);
    int in_domain = 0, sibling = 0;
    for (int i = 0; i < r.nglue; i++) {
        CHECK(strcmp(r.glue[i].addr, "192.0.2.66") != 0);
        CHECK(strcmp(r.glue[i].addr, "192.0.2.99") != 0);
        if (r.glue[i].in_domain) in_domain++;
        if (strcmp(r.glue[i].addr, "192.0.2.3") == 0) { sibling++; CHECK(!r.glue[i].in_domain); }
    }
    CHECK(in_domain == 2);
    CHECK(sibling == 1);
    /* 捨てた bailiwick 外の glue は NS 名に一致するものだけ記録される */
    CHECK(r.noob_glue == 1);
    CHECK(strcmp(r.oob_glue[0], "ns.other.alt.") == 0);
    CHECK(strcmp(r.zone, "test.") == 0);

    /* 上向きの referral (example.test. のサーバが test. を返す) は lame */
    pkt_begin(&p, QR, "www.example.test.", 1);
    rr_name(&p, SEC_NS, "test.", 2, "ns.tld.");
    CHECK(classify(&p, "www.example.test.", 1, "example.test.", &r) == IT_RESP_LAME);

    /* 同じゾーンを繰り返す referral も lame */
    pkt_begin(&p, QR, "www.example.test.", 1);
    rr_name(&p, SEC_NS, "example.test.", 2, "ns1.example.test.");
    CHECK(classify(&p, "www.example.test.", 1, "example.test.", &r) == IT_RESP_LAME);

    /* 横向き (無関係なゾーン) の referral も lame */
    pkt_begin(&p, QR, "www.example.test.", 1);
    rr_name(&p, SEC_NS, "evil.test.", 2, "ns.evil.test.");
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_LAME);
}

/* T-10: 1 セクションの RR 数に上限 (以前は 96) を設けず、後ろの RR も読む */
static void test_classify_many_rrs(void) {
    printf("[TEST] classify: sections with more than 96 RRs\n");
    pkt_t p;
    it_resp_t r;

    /* 無関係な A 120 個の後ろに問い合わせた名前の A */
    pkt_begin(&p, QR | AA, "www.example.test.", 1);
    for (int i = 0; i < 120; i++) rr_a(&p, SEC_AN, "o.example.test.", "192.0.2.200");
    rr_a(&p, SEC_AN, "www.example.test.", "192.0.2.10");
    CHECK(classify(&p, "www.example.test.", 1, "example.test.", &r) == IT_RESP_ANSWER);
    CHECK(r.naddr == 1);
    CHECK(r.naddr == 1 && strcmp(r.addrs[0], "192.0.2.10") == 0);

    /* ADDITIONAL の 120 個目より後ろにある glue */
    pkt_begin(&p, QR, "www.example.test.", 1);
    rr_name(&p, SEC_NS, "example.test.", 2, "ns1.example.test.");
    for (int i = 0; i < 120; i++) rr_a(&p, SEC_AR, "o.test.", "192.0.2.200");
    rr_a(&p, SEC_AR, "ns1.example.test.", "192.0.2.1");
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_REFERRAL);
    CHECK(r.nglue == 1);
    CHECK(r.nglue == 1 && strcmp(r.glue[0].addr, "192.0.2.1") == 0);

    /* ANCOUNT がパケットに入りきらない値でも範囲外を読まずに不正応答とする */
    pkt_begin(&p, QR | AA, "www.example.test.", 1);
    rr_a(&p, SEC_AN, "www.example.test.", "192.0.2.10");
    p.an = 65535;
    CHECK(classify(&p, "www.example.test.", 1, "example.test.", &r) == IT_RESP_BAD);
}

/* T-06: 比較表は同じ質問 (QNAME は大文字小文字を区別しない) への応答どうしだけを比べる */
static void test_comparison_rows(void) {
    printf("[TEST] comparison summary: rows are compared only for the same question\n");
    static server_result_t a, b;
    pkt_t p;
    pkt_begin(&p, QR, "www.example.test.", 1);
    memset(&a, 0, sizeof(a));
    memcpy(a.resp_buf, p.b, p.len); a.resp_len = (ssize_t)p.len; a.qdcount = 1; a.msg_index = 1;
    pkt_begin(&p, QR, "WWW.Example.TEST.", 1);
    memset(&b, 0, sizeof(b));
    memcpy(b.resp_buf, p.b, p.len); b.resp_len = (ssize_t)p.len; b.qdcount = 1; b.msg_index = 1;
    CHECK(results_comparable(&a, &b));
    b.msg_index = 2;                                   /* AXFR の別メッセージ */
    CHECK(!results_comparable(&a, &b));
    pkt_begin(&p, QR, "www.example.test.", 28);        /* QTYPE が違う */
    memcpy(b.resp_buf, p.b, p.len); b.msg_index = 1;
    CHECK(!results_comparable(&a, &b));
    pkt_begin(&p, QR, "example.test.", 1);             /* +trace の別の段 / -f の別の行 */
    memcpy(b.resp_buf, p.b, p.len); b.resp_len = (ssize_t)p.len;
    CHECK(!results_comparable(&a, &b));
    b.resp_len = 5;                                    /* 短すぎる応答 */
    CHECK(!results_comparable(&a, &b));
    reset_dag_arena();
}

static void test_classify_answers(void) {
    printf("[TEST] classify: answers, aliases and negative responses\n");
    pkt_t p;
    it_resp_t r;

    pkt_begin(&p, QR | AA, "www.example.test.", 1);
    rr_a(&p, SEC_AN, "www.example.test.", "192.0.2.1");
    rr_a(&p, SEC_AN, "www.example.test.", "192.0.2.2");
    CHECK(classify(&p, "www.example.test.", 1, "example.test.", &r) == IT_RESP_ANSWER);
    CHECK(r.nanswer == 2 && r.naddr == 2);
    CHECK(strcmp(r.addrs[0], "192.0.2.1") == 0);

    /* 大文字小文字は区別しない */
    pkt_begin(&p, QR | AA, "WWW.Example.TEST.", 1);
    rr_a(&p, SEC_AN, "www.example.test.", "192.0.2.1");
    CHECK(classify(&p, "www.example.test.", 1, "example.test.", &r) == IT_RESP_ANSWER);

    /* ゾーン内の CNAME を辿って回答 */
    pkt_begin(&p, QR | AA, "alias.example.test.", 1);
    rr_name(&p, SEC_AN, "alias.example.test.", 5, "www.example.test.");
    rr_a(&p, SEC_AN, "www.example.test.", "192.0.2.1");
    CHECK(classify(&p, "alias.example.test.", 1, "example.test.", &r) == IT_RESP_ANSWER);
    CHECK(strcmp(r.target, "www.example.test.") == 0);

    /* ゾーン外への CNAME: 付いてきた A は信用せず target から再開 */
    pkt_begin(&p, QR | AA, "alias.example.test.", 1);
    rr_name(&p, SEC_AN, "alias.example.test.", 5, "www.other.alt.");
    rr_a(&p, SEC_AN, "www.other.alt.", "192.0.2.66");
    CHECK(classify(&p, "alias.example.test.", 1, "example.test.", &r) == IT_RESP_CNAME);
    CHECK(strcmp(r.target, "www.other.alt.") == 0);
    CHECK(r.naddr == 0);

    /* qtype=CNAME なら CNAME 自体が回答 */
    pkt_begin(&p, QR | AA, "alias.example.test.", 5);
    rr_name(&p, SEC_AN, "alias.example.test.", 5, "www.other.alt.");
    CHECK(classify(&p, "alias.example.test.", 5, "example.test.", &r) == IT_RESP_ANSWER);

    /* DNAME 置換 */
    pkt_begin(&p, QR | AA, "x.dn.example.test.", 1);
    rr_name(&p, SEC_AN, "dn.example.test.", 39, "other.alt.");
    CHECK(classify(&p, "x.dn.example.test.", 1, "example.test.", &r) == IT_RESP_CNAME);
    CHECK(strcmp(r.target, "x.other.alt.") == 0);

    /* CNAME ループ */
    pkt_begin(&p, QR | AA, "a.example.test.", 1);
    rr_name(&p, SEC_AN, "a.example.test.", 5, "b.example.test.");
    rr_name(&p, SEC_AN, "b.example.test.", 5, "a.example.test.");
    CHECK(classify(&p, "a.example.test.", 1, "example.test.", &r) == IT_RESP_CNAME);
    CHECK(r.cname_loop);

    /* NXDOMAIN (AA) / 権威のない NXDOMAIN は lame */
    pkt_begin(&p, QR | AA | 3, "nx.example.test.", 1);
    rr_soa(&p, SEC_NS, "example.test.");
    CHECK(classify(&p, "nx.example.test.", 1, "example.test.", &r) == IT_RESP_NXDOMAIN);
    pkt_begin(&p, QR | 3, "nx.example.test.", 1);
    CHECK(classify(&p, "nx.example.test.", 1, "example.test.", &r) == IT_RESP_LAME);

    /* NODATA (SOA 付き) */
    pkt_begin(&p, QR | AA, "www.example.test.", 16);
    rr_soa(&p, SEC_NS, "example.test.");
    CHECK(classify(&p, "www.example.test.", 16, "example.test.", &r) == IT_RESP_NODATA);

    /* 権威のない空応答は lame */
    pkt_begin(&p, QR, "www.example.test.", 1);
    CHECK(classify(&p, "www.example.test.", 1, "example.test.", &r) == IT_RESP_LAME);

    /* bailiwick 外の SOA では NODATA にしない */
    pkt_begin(&p, QR, "www.example.test.", 16);
    rr_soa(&p, SEC_NS, "other.alt.");
    CHECK(classify(&p, "www.example.test.", 16, "example.test.", &r) == IT_RESP_LAME);

    /* プライミング: ". NS" の回答から NS と glue を集める */
    pkt_begin(&p, QR | AA, ".", 2);
    rr_name(&p, SEC_AN, ".", 2, "a.root-servers.net.");
    rr_name(&p, SEC_AN, ".", 2, "b.root-servers.net.");
    rr_a(&p, SEC_AR, "a.root-servers.net.", "198.41.0.4");
    rr_aaaa(&p, SEC_AR, "b.root-servers.net.", "2801:1b8:10::b");
    CHECK(classify(&p, ".", 2, ".", &r) == IT_RESP_ANSWER);
    CHECK(r.nns == 2 && r.nglue == 2);
}

static void test_classify_errors(void) {
    printf("[TEST] classify: error responses\n");
    pkt_t p;
    it_resp_t r;

    pkt_begin(&p, QR | 5, "www.example.test.", 1);
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_LAME);   /* REFUSED */
    pkt_begin(&p, QR | 2, "www.example.test.", 1);
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_SERVFAIL);
    pkt_begin(&p, QR | 1, "www.example.test.", 1);
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_FORMERR);
    pkt_begin(&p, QR | 4, "www.example.test.", 1);
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_FORMERR);

    /* QR=0 / 質問の不一致 / QDCOUNT 異常は BAD */
    pkt_begin(&p, AA, "www.example.test.", 1);
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_BAD);
    pkt_begin(&p, QR | AA, "www.evil.test.", 1);
    rr_a(&p, SEC_AN, "www.evil.test.", "192.0.2.66");
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_BAD);
    pkt_begin(&p, QR | AA, "www.example.test.", 28);
    CHECK(classify(&p, "www.example.test.", 1, "test.", &r) == IT_RESP_BAD);
    pkt_begin(&p, QR | AA, "www.example.test.", 1);
    pkt_counts(&p);
    p.b[5] = 0; /* QDCOUNT=0 */
    CHECK(dag_iter_classify(p.b, p.len, "www.example.test.", 1, "test.", &r) == IT_RESP_BAD);
    CHECK(dag_iter_classify(p.b, 5, "www.example.test.", 1, "test.", &r) == IT_RESP_BAD);
    CHECK(dag_iter_classify(NULL, 0, "www.example.test.", 1, "test.", &r) == IT_RESP_BAD);
    reset_dag_arena();
}

static void test_classify_truncation(void) {
    printf("[TEST] classify: truncated packets at every length\n");
    pkt_t p;
    it_resp_t r;
    pkt_begin(&p, QR, "www.example.test.", 1);
    rr_name(&p, SEC_NS, "example.test.", 2, "ns1.example.test.");
    rr_name(&p, SEC_NS, "example.test.", 2, "ns2.example.test.");
    rr_a(&p, SEC_AR, "ns1.example.test.", "192.0.2.1");
    rr_aaaa(&p, SEC_AR, "ns2.example.test.", "2001:db8::2");
    pkt_counts(&p);
    for (size_t l = 0; l <= p.len; l++) {
        uint8_t *copy = malloc(l ? l : 1);
        memcpy(copy, p.b, l);
        (void)dag_iter_classify(copy, l, "www.example.test.", 1, "test.", &r);
        reset_dag_arena();
        free(copy);
    }
    CHECK(dag_iter_classify(p.b, p.len, "www.example.test.", 1, "test.", &r) == IT_RESP_REFERRAL);
    reset_dag_arena();
}

static void test_roothints(void) {
    printf("[TEST] root hints\n");
    roothints_t *rh = malloc(sizeof(*rh));
    char err[256];

    roothints_load_builtin(rh);
    CHECK(rh->count == 26);
    bool have_a = false, have_b6 = false;
    for (int i = 0; i < rh->count; i++) {
        if (strcmp(rh->h[i].addr, "198.41.0.4") == 0 && strcmp(rh->h[i].name, "a.root-servers.net.") == 0) have_a = true;
        if (strcmp(rh->h[i].addr, "2801:1b8:10::b") == 0) have_b6 = true;
    }
    CHECK(have_a && have_b6);

    const char *named_root =
        ";       This file holds the information on root name servers\n"
        ".                        3600000      NS    A.ROOT-SERVERS.NET.\n"
        "A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4\n"
        "A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30\n"
        "; not listed as NS for '.', must be ignored\n"
        "X.EXAMPLE.               3600000 IN   A     192.0.2.1\n"
        "\n";
    CHECK(roothints_parse_text(named_root, rh, err, sizeof(err)) == 2);
    CHECK(strcmp(rh->h[0].name, "a.root-servers.net.") == 0);

    CHECK(roothints_parse_text("a.root.test. 127.0.0.1\nb.root.test. ::1\n", rh, err, sizeof(err)) == 2);
    CHECK(roothints_parse_text("a.root.test. A 2001:db8::1\n", rh, err, sizeof(err)) == -1);
    CHECK(strstr(err, "invalid A address") != NULL);
    CHECK(roothints_parse_text("; only comments\n", rh, err, sizeof(err)) == -1);
    CHECK(roothints_parse_text("a.root.test. A\n", rh, err, sizeof(err)) == -1);
    CHECK(roothints_load_file("/nonexistent/named.root", rh, err, sizeof(err)) == -1);

    /* ファイルからの読み込み: 正常系と 1MB 超の拒否 */
    char path[] = "/tmp/test_dag_iter_rootsXXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd >= 0) {
        FILE *fp = fdopen(fd, "w");
        fputs(named_root, fp);
        fclose(fp);
        CHECK(roothints_load_file(path, rh, err, sizeof(err)) == 2);
        fp = fopen(path, "w");
        for (int i = 0; i < 40000; i++) fputs("; padding line to exceed the one megabyte limit\n", fp);
        fclose(fp);
        CHECK(roothints_load_file(path, rh, err, sizeof(err)) == -1);
        CHECK(strstr(err, "file too large") != NULL);
        unlink(path);
    }
    free(rh);
}

static int parse_args(query_spec_t *spec, int argc, char **argv) {
    init_query_spec(spec);
    return parse_arg_slice(1, argc, argc, argv, spec);
}

static void test_cli(void) {
    printf("[TEST] CLI options\n");
    query_spec_t *spec = malloc(sizeof(*spec));
    {
        char *argv[] = { "dag", "+trace2", NULL };
        CHECK(parse_args(spec, 2, argv) >= 0);
        CHECK(spec->do_trace2 && spec->trace2.verbosity == TRACE2_NORMAL);
        CHECK(spec->trace2.qmin == TRACE2_QMIN_OFF);
        CHECK(!spec->dopt.show_additional);
    }
    {
        char *argv[] = { "dag", "+trace2=verbose", "+qmin", "+roothints=/tmp/named.root", "+trace2-maxqueries=50", NULL };
        CHECK(parse_args(spec, 5, argv) >= 0);
        CHECK(spec->trace2.verbosity == TRACE2_VERBOSE);
        CHECK(spec->trace2.qmin == TRACE2_QMIN_A);
        CHECK(spec->trace2.roothints_file && strcmp(spec->trace2.roothints_file, "/tmp/named.root") == 0);
        CHECK(spec->trace2.max_queries == 50);
    }
    {
        char *argv[] = { "dag", "+trace2=brief", "+qmin=ns", "+noqmin", "+qmin=ns", "+notrace2", NULL };
        CHECK(parse_args(spec, 6, argv) >= 0);
        CHECK(!spec->do_trace2 && spec->trace2.verbosity == TRACE2_BRIEF && spec->trace2.qmin == TRACE2_QMIN_NS);
    }
    {
        char *argv[] = { "dag", "+noglue", NULL };
        CHECK(parse_args(spec, 2, argv) >= 0);
        CHECK(spec->qo.glue_specified && !spec->qo.use_glue);
    }
    const char *bad[] = { "+trace2=loud", "+qmin=aaaa", "+roothints=", "+trace2-maxqueries=0", "+trace2-maxqueries=x" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char *argv[] = { "dag", (char *)bad[i], NULL };
        CHECK(parse_args(spec, 2, argv) < 0);
    }
    free(spec);
}

int main(void) {
    printf("=== dag +trace2 unit tests ===\n");
    test_name_helpers();
    test_classify_referral();
    test_classify_answers();
    test_classify_many_rrs();
    test_comparison_rows();
    test_classify_errors();
    test_classify_truncation();
    test_roothints();
    test_cli();
    if (g_fail) {
        printf("=== %d check(s) FAILED ===\n", g_fail);
        return 1;
    }
    printf("=== all dag +trace2 unit tests passed ===\n");
    return 0;
}
