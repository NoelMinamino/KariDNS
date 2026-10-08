#include "dag_iter.h"
#include "dag_roothints.h"
#include "dag_trace_common.h"
#include "dag_output_yaml.h"
#include "dag_axfr_client.h"
#include "dag_transport.h"

/*
 * +trace2 反復解決エンジン
 *
 *   run_trace2_query
 *     └ it_prime            ルートヒント (または @server) へ ". NS" を問い合わせてルートを得る
 *     └ it_resolve          CNAME を辿りつつ (qname, qtype) を解決する
 *         └ it_iterate      キャッシュ上の最も近いゾーンカットから referral を辿る
 *             └ it_query_zone   ゾーンの NS から問い合わせ先を選んで送る
 *                 └ it_resolve_ns_addrs   glue のない NS 名を it_resolve で再帰解決する
 *                 └ it_exchange           1 回の送受信と応答の分類・表示
 *
 * 再帰解決の深さ (IT_DEFAULT_MAX_DEPTH)、問い合わせ総数 (max_queries)、
 * 解決中の (name, type) のスタック (inflight) で無限ループと依存ループを防ぐ。
 * パケットから取り出した文字列は g_dag_arena 上にあるため、呼び出しをまたいで
 * 保持するものはすべて固定長バッファへコピーする (arena はいつでもリセットしてよい)。
 */

#define IT_DEFAULT_MAX_QUERIES 200
#define IT_DEFAULT_MAX_DEPTH   8
#define IT_INFLIGHT_CAP        32
#define IT_MAX_REFERRALS       32
#define IT_MAX_CNAME           16
#define IT_MAX_QMIN_QUERIES    10   /* RFC 9156 MAX_MINIMISE_COUNT */
#define IT_BUF_SIZE            65535

/* ------------------------------------------------------------------ */
/* 名前のヘルパ                                                          */
/* ------------------------------------------------------------------ */

/* 末尾ドットを付けて dst にコピーする */
static void it_name_copy(char *dst, size_t cap, const char *src) {
    if (!src || !*src) {
        snprintf(dst, cap, ".");
        return;
    }
    size_t n = strlen(src);
    if (src[n - 1] == '.') snprintf(dst, cap, "%s", src);
    else snprintf(dst, cap, "%s.", src);
}

/* 表示用: 末尾ドットを除いた長さ (root は "." のまま) */
static int it_disp_len(const char *name) {
    size_t n = strlen(name);
    if (n > 1 && name[n - 1] == '.') n--;
    return (int)n;
}

/* name の各ラベルの開始位置を求める (末尾ドットは除く)。戻り値はラベル数 */
static int it_label_starts(const char *name, size_t starts[], int cap, size_t *len_out) {
    size_t len = strlen(name);
    if (len > 0 && name[len - 1] == '.' && !(len >= 2 && name[len - 2] == '\\')) len--;
    *len_out = len;
    if (len == 0) return 0;
    int n = 0;
    if (cap > 0) starts[0] = 0;
    n = 1;
    for (size_t i = 0; i < len; i++) {
        if (name[i] == '\\') {
            i++;
            continue;
        }
        if (name[i] == '.') {
            if (n < cap) starts[n] = i + 1;
            n++;
        }
    }
    return n;
}

int dag_iter_label_count(const char *name) {
    size_t starts[128], len;
    return it_label_starts(name, starts, 128, &len);
}

void dag_iter_name_suffix(const char *name, int n, char *out, size_t out_cap) {
    size_t starts[128], len;
    int total = it_label_starts(name, starts, 128, &len);
    if (n <= 0 || total <= 0) {
        snprintf(out, out_cap, ".");
        return;
    }
    if (total > 128) total = 128;
    if (n > total) n = total;
    size_t start = starts[total - n];
    snprintf(out, out_cap, "%.*s.", (int)(len - start), name + start);
}

const char *dag_iter_kind_name(it_resp_kind_t k) {
    switch (k) {
    case IT_RESP_BAD:      return "BAD";
    case IT_RESP_ANSWER:   return "ANSWER";
    case IT_RESP_CNAME:    return "CNAME";
    case IT_RESP_NXDOMAIN: return "NXDOMAIN";
    case IT_RESP_NODATA:   return "NODATA";
    case IT_RESP_REFERRAL: return "REFERRAL";
    case IT_RESP_LAME:     return "LAME";
    case IT_RESP_SERVFAIL: return "SERVFAIL";
    case IT_RESP_FORMERR:  return "FORMERR";
    }
    return "?";
}

/* ------------------------------------------------------------------ */
/* 応答の分類                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    char owner[256];
    char rdata[256];
    uint16_t type;
} it_rr_t;

/* count 個の RR を読み、先頭 cap 個を out に写す。解析に失敗したら *err を立てて
 * それまでに読めた数を返す。 */
static int it_read_section(const uint8_t *pkt, size_t len, size_t *off, int count,
                           it_rr_t *out, int cap, bool *err) {
    int n = 0;
    *err = false;
    for (int i = 0; i < count; i++) {
        dns_record_t rec;
        uint16_t type;
        if (parse_resource_record(pkt, len, off, &g_dag_arena, &rec, &type) != 0) {
            *err = true;
            break;
        }
        if (n < cap) {
            it_name_copy(out[n].owner, sizeof(out[n].owner), rec.name);
            snprintf(out[n].rdata, sizeof(out[n].rdata), "%s",
                     (rec.rdata_count > 0 && rec.rdata[0]) ? rec.rdata[0] : "");
            out[n].type = type;
            n++;
        }
    }
    return n;
}

/* DNAME 置換: cur (owner の配下) の owner 部分を target に置き換える */
static bool it_dname_substitute(const char *cur, const char *owner, const char *target, char *out, size_t cap) {
    int cl = it_disp_len(cur);
    int ol = (strcmp(owner, ".") == 0) ? 0 : it_disp_len(owner);
    int prefix = (ol == 0) ? cl : cl - ol - 1;
    if (prefix <= 0) return false;
    char tmp[512];
    if (strcmp(target, ".") == 0) {
        snprintf(tmp, sizeof(tmp), "%.*s.", prefix, cur);
    } else {
        snprintf(tmp, sizeof(tmp), "%.*s.%s", prefix, cur, target);
    }
    if (strlen(tmp) > 254) return false;
    it_name_copy(out, cap, tmp);
    return true;
}

static void it_collect_glue(it_resp_t *out, const it_rr_t *ad, int nad, const char *zone) {
    for (int i = 0; i < nad && out->nglue < IT_MAX_GLUE; i++) {
        if (ad[i].type != 1 && ad[i].type != 28) continue;
        /* bailiwick: 問い合わせたゾーンの配下にない A/AAAA は信用しない (RFC 2181 §5.4.1)。
         * NS 名に一致するものは、捨てたことを表示できるよう owner を記録する */
        if (!trace_name_is_subdomain(ad[i].owner, zone)) {
            bool is_ns = false, seen = false;
            for (int j = 0; j < out->nns && !is_ns; j++) is_ns = trace_name_equal(ad[i].owner, out->ns[j]);
            for (int j = 0; j < out->noob_glue && !seen; j++) seen = trace_name_equal(ad[i].owner, out->oob_glue[j]);
            if (is_ns && !seen && out->noob_glue < IT_MAX_NS) {
                snprintf(out->oob_glue[out->noob_glue++], sizeof(out->oob_glue[0]), "%s", ad[i].owner);
            }
            continue;
        }
        for (int j = 0; j < out->nns; j++) {
            if (!trace_name_equal(ad[i].owner, out->ns[j])) continue;
            it_glue_t *g = &out->glue[out->nglue++];
            snprintf(g->owner, sizeof(g->owner), "%s", ad[i].owner);
            snprintf(g->addr, sizeof(g->addr), "%s", ad[i].rdata);
            g->in_domain = trace_name_is_subdomain(ad[i].owner, out->cut);
            break;
        }
    }
}

it_resp_kind_t dag_iter_classify(const uint8_t *pkt, size_t len, const char *qname, uint16_t qtype,
                                 const char *zone, it_resp_t *out) {
    memset(out, 0, sizeof(*out));
    it_name_copy(out->target, sizeof(out->target), qname);
    it_name_copy(out->zone, sizeof(out->zone), zone);
    it_rr_t *secs = NULL;

#define IT_RET(k, ...) do { out->kind = (k); snprintf(out->why, sizeof(out->why), __VA_ARGS__); goto done; } while (0)

    if (!pkt || len < 12) IT_RET(IT_RESP_BAD, "short response (%zu bytes)", len);
    if (!(pkt[2] & 0x80)) IT_RET(IT_RESP_BAD, "QR bit not set");
    if (((pkt[2] >> 3) & 0x0F) != 0) IT_RET(IT_RESP_BAD, "unexpected opcode %d", (pkt[2] >> 3) & 0x0F);
    out->aa = (pkt[2] & 0x04) != 0;
    out->rcode = pkt[3] & 0x0F;
    if (out->rcode == 1 || out->rcode == 4) IT_RET(IT_RESP_FORMERR, "%s", rcode_name(out->rcode));

    int qd = (pkt[4] << 8) | pkt[5];
    int an = (pkt[6] << 8) | pkt[7];
    int ns = (pkt[8] << 8) | pkt[9];
    int ar = (pkt[10] << 8) | pkt[11];
    if (qd != 1) IT_RET(IT_RESP_BAD, "unexpected QDCOUNT %d", qd);

    size_t off = 12;
    char *qn = NULL;
    if (expand_wire_name(pkt, len, off, &off, &g_dag_arena, &qn) != 0 || off + 4 > len) {
        IT_RET(IT_RESP_BAD, "malformed question section");
    }
    uint16_t qt = (uint16_t)((pkt[off] << 8) | pkt[off + 1]);
    off += 4;
    if (!trace_name_equal(qn, qname) || qt != qtype) IT_RET(IT_RESP_BAD, "question mismatch");

    if (out->rcode == 2) IT_RET(IT_RESP_SERVFAIL, "SERVFAIL");
    if (out->rcode == 5) IT_RET(IT_RESP_LAME, "REFUSED");
    if (out->rcode != 0 && out->rcode != 3) IT_RET(IT_RESP_LAME, "rcode %s", rcode_name(out->rcode));

    /* 全 RR を読む (上限で黙って捨てない)。RR は最短でも 11 オクテット (root owner + TYPE/CLASS/TTL/RDLENGTH)
     * なので、パケットに入りうる数で確保量を抑える。 */
    size_t fit = (len - off) / 11;
    size_t an_cap = (size_t)an < fit ? (size_t)an : fit;
    size_t ns_cap = (size_t)ns < fit ? (size_t)ns : fit;
    size_t ar_cap = (size_t)ar < fit ? (size_t)ar : fit;
    secs = calloc(an_cap + ns_cap + ar_cap + 1, sizeof(it_rr_t));
    if (!secs) IT_RET(IT_RESP_BAD, "out of memory");
    it_rr_t *ans = secs, *auth = secs + an_cap, *add = secs + an_cap + ns_cap;
    bool err = false;
    int nan = it_read_section(pkt, len, &off, an, ans, (int)an_cap, &err);
    if (err) IT_RET(IT_RESP_BAD, "malformed answer section");
    int nau = it_read_section(pkt, len, &off, ns, auth, (int)ns_cap, &err);
    if (err) IT_RET(IT_RESP_BAD, "malformed authority section");
    int nad = it_read_section(pkt, len, &off, ar, add, (int)ar_cap, &err); /* 追加部の破損は致命的でない */

    /* ANSWER の CNAME/DNAME を辿る。ゾーン外の名前に出たらそこで止める。 */
    char cur[256];
    char visited[IT_MAX_CNAME + 2][256];
    int nvisited = 0;
    it_name_copy(cur, sizeof(cur), qname);
    for (int hops = 0; hops <= IT_MAX_CNAME; hops++) {
        if (!trace_name_is_subdomain(cur, zone)) break;
        for (int v = 0; v < nvisited; v++) {
            if (trace_name_equal(visited[v], cur)) out->cname_loop = true;
        }
        if (out->cname_loop) break;
        snprintf(visited[nvisited++], sizeof(visited[0]), "%s", cur);
        int matched = 0;
        for (int i = 0; i < nan; i++) {
            if (!trace_name_equal(ans[i].owner, cur)) continue;
            if (ans[i].type != qtype && qtype != 255 /* ANY */) continue;
            matched++;
            if ((ans[i].type == 1 || ans[i].type == 28) && out->naddr < IT_MAX_ADDRS) {
                snprintf(out->addrs[out->naddr++], sizeof(out->addrs[0]), "%s", ans[i].rdata);
            }
        }
        if (matched > 0) {
            out->nanswer = matched;
            break;
        }
        bool moved = false;
        for (int i = 0; i < nan && !moved; i++) {
            if (ans[i].type == 5 /* CNAME */ && trace_name_equal(ans[i].owner, cur)) {
                it_name_copy(cur, sizeof(cur), ans[i].rdata);
                moved = true;
            }
        }
        for (int i = 0; i < nan && !moved; i++) {
            if (ans[i].type == 39 /* DNAME */ && trace_name_is_subdomain(cur, ans[i].owner) &&
                !trace_name_equal(cur, ans[i].owner) && trace_name_is_subdomain(ans[i].owner, zone)) {
                char next[256];
                if (it_dname_substitute(cur, ans[i].owner, ans[i].rdata, next, sizeof(next))) {
                    snprintf(cur, sizeof(cur), "%s", next);
                    moved = true;
                }
            }
        }
        if (!moved) break;
    }
    snprintf(out->target, sizeof(out->target), "%s", cur);
    bool chained = !trace_name_equal(cur, qname);
    if (out->cname_loop) {
        IT_RET(IT_RESP_CNAME, "CNAME/DNAME loop at %.*s", it_disp_len(cur), cur);
    }

    if (out->nanswer > 0) {
        if (qtype == 2 /* NS */) {
            snprintf(out->cut, sizeof(out->cut), "%s", cur);
            for (int i = 0; i < nan && out->nns < IT_MAX_NS; i++) {
                if (ans[i].type == 2 && trace_name_equal(ans[i].owner, cur)) {
                    it_name_copy(out->ns[out->nns++], sizeof(out->ns[0]), ans[i].rdata);
                }
            }
            it_collect_glue(out, add, nad, zone);
        }
        IT_RET(IT_RESP_ANSWER, "%d record(s)", out->nanswer);
    }

    if (chained && !trace_name_is_subdomain(cur, zone)) {
        IT_RET(IT_RESP_CNAME, "alias to out-of-zone name");
    }

    bool has_soa = false;
    for (int i = 0; i < nau; i++) {
        if (auth[i].type == 6 && trace_name_is_subdomain(cur, auth[i].owner) &&
            trace_name_is_subdomain(auth[i].owner, zone)) {
            has_soa = true;
            break;
        }
    }

    if (out->rcode == 3) {
        if (out->aa || has_soa) IT_RET(IT_RESP_NXDOMAIN, "NXDOMAIN");
        IT_RET(IT_RESP_LAME, "non-authoritative NXDOMAIN");
    }

    /* referral: cur の祖先を owner とする NS */
    const char *cut = NULL;
    for (int i = 0; i < nau; i++) {
        if (auth[i].type == 2 && trace_name_is_subdomain(cur, auth[i].owner)) {
            cut = auth[i].owner;
            break;
        }
    }
    bool sideways = false;
    if (!cut) {
        for (int i = 0; i < nau; i++) {
            if (auth[i].type == 2) { sideways = true; break; }
        }
    }
    if (cut && trace_name_is_subdomain(cut, zone) && !trace_name_equal(cut, zone) && !(out->aa && has_soa)) {
        snprintf(out->cut, sizeof(out->cut), "%s", cut);
        for (int i = 0; i < nau && out->nns < IT_MAX_NS; i++) {
            if (auth[i].type == 2 && trace_name_equal(auth[i].owner, cut)) {
                it_name_copy(out->ns[out->nns++], sizeof(out->ns[0]), auth[i].rdata);
            }
        }
        it_collect_glue(out, add, nad, zone);
        IT_RET(IT_RESP_REFERRAL, "referral to %s", out->cut);
    }

    if (has_soa || out->aa) IT_RET(IT_RESP_NODATA, "NODATA");
    if (cut) {
        IT_RET(IT_RESP_LAME, "referral to %.*s is not below %.*s", it_disp_len(cut), cut, it_disp_len(zone), zone);
    }
    if (sideways) IT_RET(IT_RESP_LAME, "referral to unrelated zone");
    if (chained) IT_RET(IT_RESP_CNAME, "non-authoritative alias");
    IT_RET(IT_RESP_LAME, "non-authoritative empty answer");

#undef IT_RET
done:
    free(secs);
    return out->kind;
}

/* ------------------------------------------------------------------ */
/* キャッシュとコンテキスト                                               */
/* ------------------------------------------------------------------ */

#define IT_NS_ADDRS 8

typedef struct {
    char name[256];
    char addrs[IT_NS_ADDRS][64];
    int naddr;
    bool tried_resolve;  /* 再帰解決を試みた (成功・失敗を問わない) */
} it_ns_t;

typedef struct {
    char zone[256];
    it_ns_t ns[IT_MAX_NS];
    int nns;
} it_zone_t;

typedef struct {
    char name[256];
    uint16_t type;
    bool ok;
    char addrs[IT_MAX_ADDRS][64];
    int naddr;
} it_acache_t;

enum { IT_BAD_TIMEOUT = 1, IT_BAD_LAME, IT_BAD_NOEDNS, IT_BAD_UNROUTABLE };

typedef struct {
    char addr[64];
    char zone[256];  /* IT_BAD_LAME のときだけ意味を持つ */
    int kind;
} it_bad_t;

typedef struct {
    it_resp_kind_t status;   /* ANSWER / NXDOMAIN / NODATA / CNAME / BAD(=失敗) */
    char final_name[256];
    char addrs[IT_MAX_ADDRS][64];
    int naddr;
    char why[160];
} it_result_t;

typedef struct {
    const query_opts_t *qo;
    const display_opts_t *dopt;
    display_opts_t hop_dopt;
    int verbosity;
    int qmin;
    int port;
    bool use_tcp;
    bool indomain_glue_only;
    bool no_hexdump_query;
    bool no_hexdump_response;
    bool v6_broken;

    it_zone_t **zones;   /* 各要素は個別に確保し、ポインタを安定させる */
    int nzones, zones_cap;
    it_acache_t *ac;
    int nac, ac_cap;
    it_bad_t *bad;
    int nbad, bad_cap;

    struct { char name[256]; uint16_t type; } inflight[IT_INFLIGHT_CAP];
    int ninflight;
    int depth;           /* 0 = 本筋, 1 以上 = NS 名の再帰解決 */
    int max_depth;
    int max_queries;

    int queries;
    int sub_queries;
    int subres;
    int lame;
    int timeouts;
    bool budget_exhausted;
    char loop_ns[256];   /* 依存ループを起こした NS 名 */

    uint8_t *qbuf;
    uint8_t *rbuf;
    uint8_t *last_resp;  /* 本筋で最後に受け取った応答 (+short 表示用) */
    size_t last_len;
} it_ctx_t;

static bool it_out_enabled(const it_ctx_t *ctx) {
    return !ctx->dopt->yaml && !ctx->dopt->short_mode;
}

/* 本筋の hop、または +trace2=verbose のときの再帰解決の hop を表示するか */
static bool it_show_hop(const it_ctx_t *ctx) {
    return ctx->depth == 0 || ctx->verbosity >= TRACE2_VERBOSE;
}

/* 注記 (lame / timeout など) を表示するか */
static bool it_show_note(const it_ctx_t *ctx) {
    return it_out_enabled(ctx) && it_show_hop(ctx);
}

static int it_family_of(const char *addr) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, addr, &a4) == 1) return AF_INET;
    if (inet_pton(AF_INET6, addr, &a6) == 1) return AF_INET6;
    return AF_UNSPEC;
}

static bool it_bad_find(const it_ctx_t *ctx, const char *addr, const char *zone, int kind) {
    for (int i = 0; i < ctx->nbad; i++) {
        const it_bad_t *b = &ctx->bad[i];
        if (b->kind != kind || strcmp(b->addr, addr) != 0) continue;
        if (kind == IT_BAD_LAME && !trace_name_equal(b->zone, zone)) continue;
        return true;
    }
    return false;
}

static void it_bad_add(it_ctx_t *ctx, const char *addr, const char *zone, int kind) {
    if (it_bad_find(ctx, addr, zone, kind)) return;
    if (ctx->nbad == ctx->bad_cap) {
        int ncap = ctx->bad_cap ? ctx->bad_cap * 2 : 32;
        it_bad_t *nb = realloc(ctx->bad, (size_t)ncap * sizeof(*nb));
        if (!nb) return;
        ctx->bad = nb;
        ctx->bad_cap = ncap;
    }
    it_bad_t *b = &ctx->bad[ctx->nbad++];
    snprintf(b->addr, sizeof(b->addr), "%s", addr);
    snprintf(b->zone, sizeof(b->zone), "%s", zone ? zone : "");
    b->kind = kind;
}

/* UDP ソケットの connect() だけを行い、経路があるかを調べる (パケットは送らない) */
static bool it_addr_routable(it_ctx_t *ctx, const char *addr) {
    if (it_bad_find(ctx, addr, NULL, IT_BAD_UNROUTABLE)) return false;
    struct sockaddr_storage ss;
    socklen_t sl;
    int fam = AF_UNSPEC;
    if (!resolve_server_addr(addr, ctx->port, AF_UNSPEC, &ss, &sl, &fam, false)) return false;
    int s = (int)socket(fam, SOCK_DGRAM, 0);
    if (s < 0) {
        it_bad_add(ctx, addr, NULL, IT_BAD_UNROUTABLE);
        return false;
    }
    int rc = connect(s, (struct sockaddr *)&ss, sl);
    close(s);
    if (rc != 0) {
        it_bad_add(ctx, addr, NULL, IT_BAD_UNROUTABLE);
        return false;
    }
    return true;
}

/* -4 / -6 と到達性に照らして使えるアドレスか */
static bool it_addr_usable(it_ctx_t *ctx, const char *addr) {
    int fam = it_family_of(addr);
    if (fam == AF_UNSPEC) return false;
    if (ctx->qo->pref_family != AF_UNSPEC && ctx->qo->pref_family != fam) return false;
    if (fam == AF_INET6 && ctx->v6_broken) return false;
    return it_addr_routable(ctx, addr);
}

static bool it_want_family(const it_ctx_t *ctx, int fam) {
    if (ctx->qo->pref_family != AF_UNSPEC && ctx->qo->pref_family != fam) return false;
    if (fam == AF_INET6 && ctx->v6_broken) return false;
    return true;
}

static it_zone_t *it_zone_get(it_ctx_t *ctx, const char *zone) {
    for (int i = 0; i < ctx->nzones; i++) {
        if (trace_name_equal(ctx->zones[i]->zone, zone)) return ctx->zones[i];
    }
    return NULL;
}

/* qname を含む最も深いキャッシュ済みゾーン。DS はゾーンカットの親側にあるため
 * strict_parent のときは qname 自身と一致するゾーンを除く。 */
static it_zone_t *it_zone_closest(it_ctx_t *ctx, const char *qname, bool strict_parent) {
    it_zone_t *best = NULL;
    int best_labels = -1;
    for (int i = 0; i < ctx->nzones; i++) {
        it_zone_t *z = ctx->zones[i];
        if (!trace_name_is_subdomain(qname, z->zone)) continue;
        if (strict_parent && trace_name_equal(qname, z->zone) && strcmp(z->zone, ".") != 0) continue;
        int l = dag_iter_label_count(z->zone);
        if (l > best_labels) {
            best = z;
            best_labels = l;
        }
    }
    return best;
}

static void it_ns_add_addr(it_ns_t *n, const char *addr) {
    for (int i = 0; i < n->naddr; i++) {
        if (strcmp(n->addrs[i], addr) == 0) return;
    }
    if (n->naddr < IT_NS_ADDRS) snprintf(n->addrs[n->naddr++], sizeof(n->addrs[0]), "%s", addr);
}

static const it_acache_t *it_acache_get(const it_ctx_t *ctx, const char *name, uint16_t type) {
    for (int i = 0; i < ctx->nac; i++) {
        if (ctx->ac[i].type == type && trace_name_equal(ctx->ac[i].name, name)) return &ctx->ac[i];
    }
    return NULL;
}

static void it_acache_put(it_ctx_t *ctx, const char *name, uint16_t type, const it_result_t *res) {
    if (it_acache_get(ctx, name, type)) return;
    if (ctx->nac == ctx->ac_cap) {
        int ncap = ctx->ac_cap ? ctx->ac_cap * 2 : 32;
        it_acache_t *na = realloc(ctx->ac, (size_t)ncap * sizeof(*na));
        if (!na) return;
        ctx->ac = na;
        ctx->ac_cap = ncap;
    }
    it_acache_t *e = &ctx->ac[ctx->nac++];
    memset(e, 0, sizeof(*e));
    it_name_copy(e->name, sizeof(e->name), name);
    e->type = type;
    e->ok = (res->status == IT_RESP_ANSWER);
    for (int i = 0; i < res->naddr && i < IT_MAX_ADDRS; i++) {
        snprintf(e->addrs[e->naddr++], sizeof(e->addrs[0]), "%s", res->addrs[i]);
    }
}

/* キャッシュ済みの A/AAAA を NS エントリへ反映する */
static void it_ns_apply_acache(const it_ctx_t *ctx, it_ns_t *n) {
    const uint16_t types[2] = { 1, 28 };
    int resolved = 0;
    for (int t = 0; t < 2; t++) {
        const it_acache_t *e = it_acache_get(ctx, n->name, types[t]);
        if (!e) continue;
        resolved++;
        for (int i = 0; i < e->naddr; i++) it_ns_add_addr(n, e->addrs[i]);
    }
    if (resolved > 0) n->tried_resolve = true;
}

/* 再帰解決の結果を、同じ NS 名を持つ全ゾーンへ反映する */
static void it_propagate_ns_addrs(it_ctx_t *ctx, const char *name) {
    for (int i = 0; i < ctx->nzones; i++) {
        it_zone_t *z = ctx->zones[i];
        for (int j = 0; j < z->nns; j++) {
            if (trace_name_equal(z->ns[j].name, name)) it_ns_apply_acache(ctx, &z->ns[j]);
        }
    }
}

/* referral (または priming の NS 応答) をゾーンとしてキャッシュする。
 * 既にあるゾーンは、呼び出し元が走査中の可能性があるので NS を置き換えずに
 * アドレスだけ追加する。 */
static it_zone_t *it_zone_store(it_ctx_t *ctx, const it_resp_t *r) {
    it_zone_t *z = it_zone_get(ctx, r->cut);
    bool fresh = false;
    if (!z) {
        if (ctx->nzones == ctx->zones_cap) {
            int ncap = ctx->zones_cap ? ctx->zones_cap * 2 : 16;
            it_zone_t **nz = realloc(ctx->zones, (size_t)ncap * sizeof(*nz));
            if (!nz) return NULL;
            ctx->zones = nz;
            ctx->zones_cap = ncap;
        }
        z = calloc(1, sizeof(*z));
        if (!z) return NULL;
        it_name_copy(z->zone, sizeof(z->zone), r->cut);
        ctx->zones[ctx->nzones++] = z;
        fresh = true;
    }
    if (fresh) {
        for (int i = 0; i < r->nns && z->nns < IT_MAX_NS; i++) {
            it_ns_t *n = &z->ns[z->nns++];
            memset(n, 0, sizeof(*n));
            snprintf(n->name, sizeof(n->name), "%s", r->ns[i]);
        }
    }
    for (int g = 0; g < r->noob_glue; g++) {
        if (it_show_note(ctx)) {
            printf(";; ignoring out-of-bailiwick glue for '%.*s' (not under %.*s)\n",
                   it_disp_len(r->oob_glue[g]), r->oob_glue[g], it_disp_len(r->zone), r->zone);
        }
    }
    for (int g = 0; g < r->nglue; g++) {
        const it_glue_t *gl = &r->glue[g];
        if (ctx->indomain_glue_only && !gl->in_domain) {
            if (it_show_note(ctx)) {
                printf(";; ignoring out-of-domain glue for '%.*s' (NS of '%.*s')\n",
                       it_disp_len(gl->owner), gl->owner, it_disp_len(r->cut), r->cut);
            }
            continue;
        }
        for (int j = 0; j < z->nns; j++) {
            if (trace_name_equal(z->ns[j].name, gl->owner)) it_ns_add_addr(&z->ns[j], gl->addr);
        }
    }
    for (int j = 0; j < z->nns; j++) {
        if (z->ns[j].naddr == 0) it_ns_apply_acache(ctx, &z->ns[j]);
    }
    return z;
}

/* ------------------------------------------------------------------ */
/* 送受信                                                               */
/* ------------------------------------------------------------------ */

#define IT_EX_TIMEOUT  (-1)
#define IT_EX_BUDGET   (-2)
#define IT_EX_DEPLOOP  (-3)   /* NS 名の解決が自分自身の解決を必要としている */

static bool it_inflight_name(const it_ctx_t *ctx, const char *name) {
    for (int i = 0; i < ctx->ninflight; i++) {
        if (trace_name_equal(ctx->inflight[i].name, name)) return true;
    }
    return false;
}

static void it_print_hop_header(const it_ctx_t *ctx, const char *qname, uint16_t qtype,
                                const char *addr, const char *nsname, const char *zone) {
    if (ctx->depth == 0 || !it_out_enabled(ctx)) return;
    char tbuf[32];
    const char *tname = dag_type_name(qtype, tbuf, sizeof(tbuf));
    printf(";; [sub %d] %.*s/%s @%s(%.*s) for %.*s\n", ctx->depth,
           it_disp_len(qname), qname, tname, addr,
           it_disp_len(nsname), nsname, it_disp_len(zone), zone);
}

/* 1 回の送受信。戻り値は応答の分類、または IT_EX_TIMEOUT / IT_EX_BUDGET */
static int it_exchange(it_ctx_t *ctx, const char *addr, const char *nsname, const char *zone,
                       const char *qname, uint16_t qtype, bool use_tsig, it_resp_t *r) {
    if (it_family_of(addr) == AF_UNSPEC) return IT_EX_TIMEOUT; /* IP リテラル以外は送らない (getaddrinfo を使わない) */

    query_opts_t q = *ctx->qo;
    q.rd_flag = false;
    q.want_tsig = use_tsig && ctx->qo->want_tsig;
    if (it_bad_find(ctx, addr, NULL, IT_BAD_NOEDNS)) q.want_opt = false;

    int tries = ctx->qo->tries < 1 ? 1 : ctx->qo->tries;
    for (int attempt = 0; attempt < tries; attempt++) {
        if (ctx->queries >= ctx->max_queries) {
            ctx->budget_exhausted = true;
            return IT_EX_BUDGET;
        }
        /* 反復解決では毎回 ID を変える (RFC 5452 オフパス偽装対策)。+qid=N 指定時はそれに従う */
        q.query_id = (uint16_t)(arc4random() & 0xFFFF);
        uint8_t req_mac[64];
        size_t req_mac_len = 0;
        size_t qlen = build_and_sign_query(ctx->qbuf, IT_BUF_SIZE, qname, qtype, &q, req_mac, &req_mac_len);
        if (qlen == 0) return IT_EX_TIMEOUT;

        bool show = it_show_hop(ctx) && !ctx->dopt->short_mode;
        if (show) it_print_hop_header(ctx, qname, qtype, addr, nsname, zone);
        if (show && !ctx->no_hexdump_query && !ctx->dopt->yaml) {
            printf("Query (%zu bytes):\n", qlen);
            hexdump(ctx->qbuf, qlen);
            printf("\n");
        }

        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        ssize_t n = do_dns_exchange_auto(addr, ctx->port, &q, ctx->qbuf, qlen, ctx->rbuf, IT_BUF_SIZE,
                                         q.timeout_sec, ctx->use_tcp);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int ms = timespec_diff_ms(&t0, &t1);
        ctx->queries++;
        if (ctx->depth > 0) ctx->sub_queries++;

        if (n <= 0) {
            ctx->timeouts++;
            /* 即座に失敗した IPv6 は経路がないとみなし、以降 IPv6 を使わない */
            if (it_family_of(addr) == AF_INET6 && ms < 200) ctx->v6_broken = true;
            if (it_show_note(ctx)) {
                printf(";; connection to %s#%d(%.*s) for %.*s failed; trying next server\n",
                       addr, ctx->port, it_disp_len(nsname), nsname, it_disp_len(zone), zone);
            }
            continue;
        }

        if (ctx->depth == 0) {
            trace_record_result(addr, n, ctx->rbuf, ms, ctx->use_tcp ? "TCP" : "UDP");
        }
        if (show && !ctx->no_hexdump_response && !ctx->dopt->yaml) {
            printf("Response (%zd bytes):\n", n);
            hexdump(ctx->rbuf, (size_t)n);
            printf("\n");
        }
        if (show) {
            if (ctx->dopt->yaml) {
                if (ctx->depth == 0) print_response_yaml(ctx->rbuf, (size_t)n, addr, (uint16_t)ctx->port, ctx->use_tcp, ctx->dopt);
            } else if (!ctx->dopt->short_mode) {
                axfr_state_t dummy_axfr = {0};
                print_response(ctx->rbuf, (size_t)n, &dummy_axfr, &ctx->hop_dopt);
                trace_print_received(n, addr, ctx->port, nsname, ms);
            }
        }

        if (ctx->depth == 0 && ctx->last_resp) {
            memcpy(ctx->last_resp, ctx->rbuf, (size_t)n);
            ctx->last_len = (size_t)n;
        }
        it_resp_kind_t kind = dag_iter_classify(ctx->rbuf, (size_t)n, qname, qtype, zone, r);
        reset_dag_arena();
        if (kind == IT_RESP_FORMERR && q.want_opt) {
            /* EDNS 非対応サーバ: EDNS なしで送り直す */
            it_bad_add(ctx, addr, NULL, IT_BAD_NOEDNS);
            q.want_opt = false;
            if (it_show_note(ctx)) printf(";; %s from %s, retrying without EDNS\n", r->why, addr);
            attempt--;
            continue;
        }
        return (int)kind;
    }
    return IT_EX_TIMEOUT;
}

static void it_result_fail(it_result_t *res, const char *fmt, ...) {
    res->status = IT_RESP_BAD;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(res->why, sizeof(res->why), fmt, ap);
    va_end(ap);
}

static void it_resolve(it_ctx_t *ctx, const char *qname, uint16_t qtype, it_result_t *res);

/* glue のない NS 名のアドレスを反復解決する。
 * アドレスが得られず、その原因が依存ループだったときは true を返す */
static bool it_resolve_ns_addrs(it_ctx_t *ctx, const char *nsname) {
    int q0 = ctx->queries;
    char found[2 * IT_MAX_ADDRS][64];
    int nfound = 0;
    char fail_why[160] = "";
    bool loop = false;
    const uint16_t types[2] = { 1, 28 };
    const int fams[2] = { AF_INET, AF_INET6 };

    ctx->subres++;
    ctx->depth++;
    for (int t = 0; t < 2; t++) {
        if (!it_want_family(ctx, fams[t])) continue;
        const it_acache_t *e = it_acache_get(ctx, nsname, types[t]);
        if (e) {
            for (int i = 0; i < e->naddr && nfound < 2 * IT_MAX_ADDRS; i++) snprintf(found[nfound++], 64, "%s", e->addrs[i]);
            continue;
        }
        it_result_t r;
        memset(&r, 0, sizeof(r));
        it_resolve(ctx, nsname, types[t], &r);
        it_acache_put(ctx, nsname, types[t], &r);
        if (r.status == IT_RESP_ANSWER) {
            for (int i = 0; i < r.naddr && nfound < 2 * IT_MAX_ADDRS; i++) snprintf(found[nfound++], 64, "%s", r.addrs[i]);
        } else {
            if (r.status == IT_RESP_BAD && strncmp(r.why, "dependency loop", 15) == 0) loop = true;
            if (!fail_why[0]) {
                if (r.status == IT_RESP_BAD) snprintf(fail_why, sizeof(fail_why), "%s", r.why);
                else snprintf(fail_why, sizeof(fail_why), "%s", dag_iter_kind_name(r.status));
            }
        }
        if (ctx->budget_exhausted) break;
    }
    ctx->depth--;
    it_propagate_ns_addrs(ctx, nsname);

    if (ctx->depth == 0 && ctx->verbosity >= TRACE2_NORMAL && it_out_enabled(ctx)) {
        int used = ctx->queries - q0;
        if (nfound > 0) {
            printf(";; [sub] %.*s ->", it_disp_len(nsname), nsname);
            for (int i = 0; i < nfound; i++) printf("%s%s", i ? ", " : " ", found[i]);
            printf(" (%d quer%s)\n", used, used == 1 ? "y" : "ies");
        } else {
            printf(";; [sub] couldn't get address for '%.*s': %s (%d quer%s)\n",
                   it_disp_len(nsname), nsname, fail_why[0] ? fail_why : "no address",
                   used, used == 1 ? "y" : "ies");
        }
    }
    return nfound == 0 && loop;
}

/* ゾーン z の NS に問い合わせる。使える応答を得たら 0、全滅なら -1、予算切れなら IT_EX_BUDGET */
static int it_query_zone(it_ctx_t *ctx, it_zone_t *z, const char *qname, uint16_t qtype, it_resp_t *r) {
    int nns = z->nns;
    if (nns == 0) return -1;
    int start = (int)(arc4random() % (uint32_t)nns);
    bool dep_loop = false;

    for (int pass = 0; pass < 2; pass++) {
        for (int k = 0; k < nns; k++) {
            it_ns_t *n = &z->ns[(start + k) % nns];
            if (pass == 1) {
                /* 2 周目: アドレス未知の NS 名を 1 つずつ解決しては試す */
                if (n->naddr > 0) continue;
                if (n->tried_resolve) {
                    /* 外側のフレームで解決中の名前 = 依存ループ */
                    if (it_inflight_name(ctx, n->name)) {
                        dep_loop = true;
                        snprintf(ctx->loop_ns, sizeof(ctx->loop_ns), "%s", n->name);
                    }
                    continue;
                }
                n->tried_resolve = true;
                if (trace_name_is_subdomain(n->name, z->zone)) {
                    /* in-domain の NS は glue がなければ解決できない (解決にこのゾーン自身が要る) */
                    if (it_show_note(ctx)) {
                        printf(";; no glue for in-domain nameserver '%.*s' of '%.*s'\n",
                               it_disp_len(n->name), n->name, it_disp_len(z->zone), z->zone);
                    }
                    continue;
                }
                if (it_resolve_ns_addrs(ctx, n->name)) dep_loop = true;
                if (ctx->budget_exhausted) return IT_EX_BUDGET;
            }
            /* IPv4 を先に試す */
            for (int fam_pass = 0; fam_pass < 2; fam_pass++) {
                for (int a = 0; a < n->naddr; a++) {
                    const char *addr = n->addrs[a];
                    if ((it_family_of(addr) == AF_INET6) != (fam_pass == 1)) continue;
                    if (!it_addr_usable(ctx, addr)) continue;
                    if (it_bad_find(ctx, addr, NULL, IT_BAD_TIMEOUT)) continue;
                    if (it_bad_find(ctx, addr, z->zone, IT_BAD_LAME)) continue;
                    int rc = it_exchange(ctx, addr, n->name, z->zone, qname, qtype, false, r);
                    if (rc == IT_EX_BUDGET) return IT_EX_BUDGET;
                    if (rc == IT_EX_TIMEOUT) {
                        it_bad_add(ctx, addr, NULL, IT_BAD_TIMEOUT);
                        continue;
                    }
                    if (rc == IT_RESP_LAME || rc == IT_RESP_SERVFAIL || rc == IT_RESP_BAD || rc == IT_RESP_FORMERR) {
                        ctx->lame++;
                        it_bad_add(ctx, addr, z->zone, IT_BAD_LAME);
                        if (it_show_note(ctx)) {
                            printf(";; lame server %s(%.*s) for %.*s: %s; trying next server\n",
                                   addr, it_disp_len(n->name), n->name, it_disp_len(z->zone), z->zone, r->why);
                        }
                        continue;
                    }
                    return 0;
                }
            }
        }
    }
    return dep_loop ? IT_EX_DEPLOOP : -1;
}

/* キャッシュ上の最も近いゾーンカットから referral を辿り、終端の応答まで進める */
static void it_iterate(it_ctx_t *ctx, const char *qname, uint16_t qtype, it_result_t *res) {
    it_zone_t *z = it_zone_closest(ctx, qname, qtype == 43 /* DS */);
    if (!z) {
        it_result_fail(res, "no root nameservers");
        return;
    }
    it_resp_t *r = malloc(sizeof(*r));
    if (!r) {
        it_result_fail(res, "out of memory");
        return;
    }
    bool qmin_on = ctx->qmin != TRACE2_QMIN_OFF;
    int qmin_k = 1;
    int qmin_count = 0;
    char tbuf[32];

    for (int step = 0; step < IT_MAX_REFERRALS + IT_MAX_QMIN_QUERIES; step++) {
        const char *send_name = qname;
        uint16_t send_type = qtype;
        char mname[256];
        if (qmin_on && qmin_count < IT_MAX_QMIN_QUERIES) {
            int target = dag_iter_label_count(z->zone) + qmin_k;
            if (target < dag_iter_label_count(qname)) {
                dag_iter_name_suffix(qname, target, mname, sizeof(mname));
                send_name = mname;
                send_type = (ctx->qmin == TRACE2_QMIN_NS) ? 2 : 1;
            }
        }
        bool minimised = (send_name != qname);

        int rc = it_query_zone(ctx, z, send_name, send_type, r);
        if (rc == IT_EX_BUDGET) {
            it_result_fail(res, "query budget exhausted (%d queries)", ctx->max_queries);
            goto out;
        }
        if (rc == IT_EX_DEPLOOP) {
            it_result_fail(res, "dependency loop on %.*s (nameservers of %.*s)",
                           it_disp_len(ctx->loop_ns), ctx->loop_ns, it_disp_len(z->zone), z->zone);
            goto out;
        }
        if (rc != 0) {
            it_result_fail(res, "all nameservers for %.*s failed", it_disp_len(z->zone), z->zone);
            goto out;
        }

        if (minimised) {
            qmin_count++;
            if (r->kind == IT_RESP_REFERRAL && trace_name_is_subdomain(qname, r->cut)) {
                it_zone_t *nz = it_zone_store(ctx, r);
                if (!nz) { it_result_fail(res, "out of memory"); goto out; }
                z = nz;
                qmin_k = 1;
                continue;
            }
            if (r->kind == IT_RESP_ANSWER || r->kind == IT_RESP_NODATA ||
                (r->kind == IT_RESP_CNAME) || (r->kind == IT_RESP_REFERRAL)) {
                /* 同じゾーン内の名前 (空の非終端を含む): ラベルを 1 つ増やす */
                qmin_k++;
                continue;
            }
            /* NXDOMAIN などは壊れた実装もあるため、完全な名前で問い直す (relaxed) */
            if (it_show_note(ctx)) {
                printf(";; qname minimisation: %s for %.*s/%s, retrying with full name\n",
                       dag_iter_kind_name(r->kind), it_disp_len(send_name), send_name,
                       dag_type_name(send_type, tbuf, sizeof(tbuf)));
            }
            qmin_on = false;
            continue;
        }

        switch (r->kind) {
        case IT_RESP_ANSWER:
            res->status = IT_RESP_ANSWER;
            snprintf(res->final_name, sizeof(res->final_name), "%s", r->target);
            for (int i = 0; i < r->naddr; i++) snprintf(res->addrs[res->naddr++], sizeof(res->addrs[0]), "%s", r->addrs[i]);
            goto out;
        case IT_RESP_NXDOMAIN:
        case IT_RESP_NODATA:
            res->status = r->kind;
            snprintf(res->final_name, sizeof(res->final_name), "%s", r->target);
            goto out;
        case IT_RESP_CNAME:
            if (r->cname_loop) {
                it_result_fail(res, "%s", r->why);
                goto out;
            }
            res->status = IT_RESP_CNAME;
            snprintf(res->final_name, sizeof(res->final_name), "%s", r->target);
            goto out;
        case IT_RESP_REFERRAL:
            if (!trace_name_equal(r->target, qname)) {
                /* ゾーン内で CNAME を辿った先がさらに委任されている: 別名として解決し直す */
                res->status = IT_RESP_CNAME;
                snprintf(res->final_name, sizeof(res->final_name), "%s", r->target);
                goto out;
            }
            if (qtype == 43 && trace_name_equal(r->cut, qname)) {
                it_result_fail(res, "unexpected referral for DS at %.*s", it_disp_len(qname), qname);
                goto out;
            }
            {
                it_zone_t *nz = it_zone_store(ctx, r);
                if (!nz) { it_result_fail(res, "out of memory"); goto out; }
                z = nz;
            }
            qmin_k = 1;
            continue;
        default:
            it_result_fail(res, "%s", r->why);
            goto out;
        }
    }
    it_result_fail(res, "too many referrals");
out:
    free(r);
}

static void it_resolve(it_ctx_t *ctx, const char *qname, uint16_t qtype, it_result_t *res) {
    memset(res, 0, sizeof(*res));
    it_name_copy(res->final_name, sizeof(res->final_name), qname);
    if (ctx->depth > ctx->max_depth) {
        it_result_fail(res, "maximum recursion depth (%d) exceeded", ctx->max_depth);
        return;
    }
    for (int i = 0; i < ctx->ninflight; i++) {
        if (ctx->inflight[i].type == qtype && trace_name_equal(ctx->inflight[i].name, qname)) {
            it_result_fail(res, "dependency loop on %.*s", it_disp_len(qname), qname);
            return;
        }
    }
    if (ctx->ninflight >= IT_INFLIGHT_CAP) {
        it_result_fail(res, "resolution stack full");
        return;
    }
    it_name_copy(ctx->inflight[ctx->ninflight].name, sizeof(ctx->inflight[0].name), qname);
    ctx->inflight[ctx->ninflight].type = qtype;
    ctx->ninflight++;

    char cur[256];
    char seen[IT_MAX_CNAME + 1][256];
    int nseen = 0;
    it_name_copy(cur, sizeof(cur), qname);
    for (int hop = 0;; hop++) {
        snprintf(seen[nseen++], sizeof(seen[0]), "%s", cur);
        it_result_t step;
        memset(&step, 0, sizeof(step));
        it_iterate(ctx, cur, qtype, &step);
        if (!step.final_name[0]) snprintf(step.final_name, sizeof(step.final_name), "%s", cur);
        if (step.status != IT_RESP_CNAME) {
            *res = step;
            break;
        }
        if (hop >= IT_MAX_CNAME) {
            it_result_fail(res, "CNAME chain too long");
            break;
        }
        bool loop = false;
        for (int i = 0; i < nseen; i++) {
            if (trace_name_equal(seen[i], step.final_name)) loop = true;
        }
        if (loop) {
            it_result_fail(res, "CNAME loop at %.*s", it_disp_len(step.final_name), step.final_name);
            break;
        }
        if (it_show_note(ctx)) {
            printf(";; following alias %.*s -> %.*s\n\n", it_disp_len(cur), cur,
                   it_disp_len(step.final_name), step.final_name);
        }
        snprintf(cur, sizeof(cur), "%s", step.final_name);
    }
    ctx->ninflight--;
}

/* ------------------------------------------------------------------ */
/* プライミング                                                          */
/* ------------------------------------------------------------------ */

static void it_cache_clear(it_ctx_t *ctx) {
    for (int i = 0; i < ctx->nzones; i++) free(ctx->zones[i]);
    ctx->nzones = 0;
    ctx->nac = 0;
}

/* 指定アドレス群 (ヒント) を使うルートゾーンを作る。プライミング前の仮のもの */
static it_zone_t *it_zone_from_hints(it_ctx_t *ctx, const roothints_t *rh) {
    it_resp_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    snprintf(r->cut, sizeof(r->cut), ".");
    for (int i = 0; i < rh->count; i++) {
        bool have = false;
        for (int j = 0; j < r->nns; j++) {
            if (trace_name_equal(r->ns[j], rh->h[i].name)) have = true;
        }
        if (!have && r->nns < IT_MAX_NS) it_name_copy(r->ns[r->nns++], sizeof(r->ns[0]), rh->h[i].name);
        if (r->nglue < IT_MAX_GLUE) {
            it_glue_t *g = &r->glue[r->nglue++];
            it_name_copy(g->owner, sizeof(g->owner), rh->h[i].name);
            snprintf(g->addr, sizeof(g->addr), "%s", rh->h[i].addr);
            g->in_domain = true;
        }
    }
    bool saved = ctx->indomain_glue_only;
    ctx->indomain_glue_only = false;
    it_zone_t *z = it_zone_store(ctx, r);
    ctx->indomain_glue_only = saved;
    free(r);
    return z;
}

/* ヒントの順番を混ぜる (特定のルートサーバへの集中を避ける) */
static void it_shuffle_hints(roothints_t *rh) {
    for (int i = rh->count - 1; i > 0; i--) {
        int j = (int)(arc4random() % (uint32_t)(i + 1));
        roothint_t tmp = rh->h[i];
        rh->h[i] = rh->h[j];
        rh->h[j] = tmp;
    }
}

/* ". NS" を問い合わせ、応答の NS と glue でルートゾーンを作る。成功で 0 */
static int it_prime(it_ctx_t *ctx, const roothints_t *hints_in, bool explicit_server) {
    roothints_t *rh = malloc(sizeof(*rh));
    it_resp_t *r = malloc(sizeof(*r));
    if (!rh || !r) {
        free(rh);
        free(r);
        return -1;
    }
    *rh = *hints_in;
    if (!explicit_server) it_shuffle_hints(rh);

    int ret = -1;
    int usable = 0;
    for (int i = 0; i < rh->count; i++) {
        const char *addr = rh->h[i].addr;
        if (!it_addr_usable(ctx, addr)) continue;
        usable++;
        int rc = it_exchange(ctx, addr, rh->h[i].name, ".", ".", 2 /* NS */, explicit_server, r);
        if (rc == IT_EX_BUDGET) break;
        if (rc != IT_RESP_ANSWER || r->nns == 0) {
            if (rc >= 0 && it_show_note(ctx)) {
                printf(";; priming query to %s failed: %s\n", addr,
                       r->why[0] ? r->why : dag_iter_kind_name((it_resp_kind_t)rc));
            }
            continue;
        }
        it_cache_clear(ctx);
        snprintf(r->cut, sizeof(r->cut), ".");
        it_zone_t *z = it_zone_store(ctx, r);
        if (!z) break;
        /* 応答に glue がなければヒントのアドレスで補い、それもなければ
         * プライミング先そのものをルートとして使う */
        bool any = false;
        for (int j = 0; j < z->nns; j++) {
            if (z->ns[j].naddr == 0) {
                for (int h = 0; h < rh->count; h++) {
                    if (trace_name_equal(rh->h[h].name, z->ns[j].name)) it_ns_add_addr(&z->ns[j], rh->h[h].addr);
                }
            }
            if (z->ns[j].naddr > 0) any = true;
        }
        if (!any && z->nns < IT_MAX_NS) {
            it_ns_t *n = &z->ns[z->nns++];
            memset(n, 0, sizeof(*n));
            it_name_copy(n->name, sizeof(n->name), rh->h[i].name);
            it_ns_add_addr(n, addr);
        }
        ret = 0;
        break;
    }
    if (usable == 0 && it_out_enabled(ctx)) {
        printf(";; no usable root server address (check -4/-6 and network reachability)\n");
    }
    free(rh);
    free(r);
    return ret;
}

/* ------------------------------------------------------------------ */
/* エントリポイント                                                       */
/* ------------------------------------------------------------------ */

static void it_print_short(const uint8_t *pkt, size_t len, const display_opts_t *dopt) {
    int qd = (pkt[4] << 8) | pkt[5];
    int an = (pkt[6] << 8) | pkt[7];
    size_t off = 12;
    for (int i = 0; i < qd; i++) {
        size_t next;
        if (skip_wire_name(pkt, len, off, &next) != 0 || next + 4 > len) return;
        off = next + 4;
    }
    char *rdtext = malloc(65536);
    if (!rdtext) return;
    for (int i = 0; i < an; i++) {
        size_t next;
        if (skip_wire_name(pkt, len, off, &next) != 0 || next + 10 > len) break;
        uint16_t type = (uint16_t)((pkt[next] << 8) | pkt[next + 1]);
        uint32_t ttl = ((uint32_t)pkt[next + 4] << 24) | ((uint32_t)pkt[next + 5] << 16) |
                       ((uint32_t)pkt[next + 6] << 8) | pkt[next + 7];
        uint16_t rdlen = (uint16_t)((pkt[next + 8] << 8) | pkt[next + 9]);
        if (next + 10 + rdlen > len) break;
        format_rdata_for_display(pkt, len, type, next + 10, rdlen, rdtext, 65536, dopt);
        if (dopt->explicit_ttlid) {
            char ttl_str[32];
            if (dopt->ttlunits) printf("%s ", format_ttl_units(ttl, ttl_str, sizeof(ttl_str)));
            else printf("%u ", ttl);
        }
        printf("%s\n", rdtext);
        off = next + 10 + rdlen;
    }
    free(rdtext);
}

static const char *it_status_text(const it_result_t *res) {
    switch (res->status) {
    case IT_RESP_ANSWER:   return "NOERROR";
    case IT_RESP_NXDOMAIN: return "NXDOMAIN";
    case IT_RESP_NODATA:   return "NOERROR (no data)";
    default:               return "SERVFAIL";
    }
}

int run_trace2_query(const char *qname, const char *server, bool server_explicit, const char *qtype_s,
                     int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response,
                     const query_opts_t *qo, const display_opts_t *dopt, const trace2_opts_t *t2) {
    int qtype_val = parse_qtype(qtype_s);
    if (qtype_val < 0) return 1;

    it_ctx_t *ctx = calloc(1, sizeof(*ctx));
    roothints_t *rh = calloc(1, sizeof(*rh));
    if (!ctx || !rh) {
        fprintf(stderr, "Error: Failed to allocate memory for +trace2\n");
        free(ctx);
        free(rh);
        return 1;
    }
    ctx->qbuf = malloc(IT_BUF_SIZE);
    ctx->rbuf = malloc(IT_BUF_SIZE);
    ctx->last_resp = malloc(IT_BUF_SIZE);
    int ret = 0;
    if (!ctx->qbuf || !ctx->rbuf || !ctx->last_resp) {
        fprintf(stderr, "Error: Failed to allocate memory for +trace2\n");
        ret = 1;
        goto cleanup;
    }

    ctx->qo = qo;
    ctx->dopt = dopt;
    ctx->hop_dopt = *dopt;
    ctx->hop_dopt.show_comments = false;
    ctx->hop_dopt.show_question = false;
    ctx->hop_dopt.show_stats = false;
    ctx->verbosity = t2 ? t2->verbosity : TRACE2_NORMAL;
    ctx->qmin = t2 ? t2->qmin : TRACE2_QMIN_OFF;
    ctx->port = port;
    ctx->use_tcp = !force_udp && use_tcp;
    /* glue: 既定・+glue は bailiwick 内すべて、+glue=indomain / +noglue は in-domain のみ
     * (in-domain glue は委任に必須なので +noglue でも使う: RFC 9471) */
    ctx->indomain_glue_only = qo->glue_specified && (qo->glue_indomain || !qo->use_glue);
    ctx->no_hexdump_query = no_hexdump_query;
    ctx->no_hexdump_response = no_hexdump_response;
    ctx->max_queries = (t2 && t2->max_queries > 0) ? t2->max_queries : IT_DEFAULT_MAX_QUERIES;
    ctx->max_depth = IT_DEFAULT_MAX_DEPTH;

    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    /* ヒントの決定: @server > +roothints=FILE > 内蔵 */
    char err[256];
    if (t2 && t2->roothints_file) {
        if (roothints_load_file(t2->roothints_file, rh, err, sizeof(err)) < 0) {
            fprintf(stderr, "dag: +roothints: %s\n", err);
            ret = 1;
            goto cleanup;
        }
    } else {
        roothints_load_builtin(rh);
    }

    if (server_explicit && server) {
        if (it_family_of(server) != AF_UNSPEC) {
            rh->count = 0;
            snprintf(rh->h[0].name, sizeof(rh->h[0].name), "%s", server);
            snprintf(rh->h[0].addr, sizeof(rh->h[0].addr), "%s", server);
            rh->count = 1;
        } else {
            /* ホスト名の @server もシステムリゾルバを使わず、ヒントから反復解決する */
            if (!it_zone_from_hints(ctx, rh)) {
                ret = 1;
                goto cleanup;
            }
            char srv[256];
            it_name_copy(srv, sizeof(srv), server);
            it_ns_t probe;
            memset(&probe, 0, sizeof(probe));
            snprintf(probe.name, sizeof(probe.name), "%s", srv);
            ctx->depth = 1;
            for (int t = 0; t < 2; t++) {
                uint16_t ty = t == 0 ? 1 : 28;
                if (!it_want_family(ctx, t == 0 ? AF_INET : AF_INET6)) continue;
                it_result_t r;
                it_resolve(ctx, srv, ty, &r);
                for (int i = 0; i < r.naddr; i++) it_ns_add_addr(&probe, r.addrs[i]);
            }
            ctx->depth = 0;
            if (probe.naddr == 0) {
                if (it_out_enabled(ctx)) printf(";; couldn't get address for '%s'\n", server);
                ret = 9;
                goto cleanup;
            }
            it_cache_clear(ctx);
            rh->count = 0;
            for (int i = 0; i < probe.naddr && rh->count < ROOTHINT_MAX; i++) {
                snprintf(rh->h[rh->count].name, sizeof(rh->h[0].name), "%s", server);
                snprintf(rh->h[rh->count].addr, sizeof(rh->h[0].addr), "%s", probe.addrs[i]);
                rh->count++;
            }
        }
    }

    if (it_prime(ctx, rh, server_explicit) != 0) {
        if (dopt->yaml) {
            printf("- type: DIG_ERROR\n  message: |\n    no servers could be reached\n");
        } else {
            printf(";; no root servers could be reached (priming failed)\n");
        }
        ret = 9;
        goto cleanup;
    }

    it_result_t res;
    it_resolve(ctx, qname, (uint16_t)qtype_val, &res);
    clock_gettime(CLOCK_MONOTONIC, &t_end);

    if (dopt->short_mode) {
        /* +short: 最後に得た回答の ANSWER を通常の +short と同じ形式 (RDATA のみ) で出す */
        if (res.status == IT_RESP_ANSWER && ctx->last_len > 12) {
            it_print_short(ctx->last_resp, ctx->last_len, dopt);
        }
    } else if (it_out_enabled(ctx)) {
        if (res.status == IT_RESP_BAD) {
            printf(";; resolution failed: %s\n", res.why);
        }
        if (dopt->show_stats) {
            printf(";; trace2: %s for %.*s: %d quer%s (%d in %d sub-resolution%s), %d lame, %d timeout%s, %d ms\n",
                   it_status_text(&res), it_disp_len(res.final_name), res.final_name,
                   ctx->queries, ctx->queries == 1 ? "y" : "ies",
                   ctx->sub_queries, ctx->subres, ctx->subres == 1 ? "" : "s",
                   ctx->lame, ctx->timeouts, ctx->timeouts == 1 ? "" : "s",
                   timespec_diff_ms(&t_start, &t_end));
        }
    }

cleanup:
    it_cache_clear(ctx);
    free(ctx->zones);
    free(ctx->ac);
    free(ctx->bad);
    free(ctx->qbuf);
    free(ctx->rbuf);
    free(ctx->last_resp);
    free(ctx);
    free(rh);
    return ret;
}
