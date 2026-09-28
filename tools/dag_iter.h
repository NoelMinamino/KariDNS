#ifndef DAG_ITER_H
#define DAG_ITER_H

#include "dag_internal.h"

/*
 * +trace2: フルリゾルバ (BIND / Unbound) と同様の反復解決。
 *
 * +trace はルート NS の取得と NS 名のアドレス解決を @server / システムリゾルバに
 * 任せるが、+trace2 はルートヒントからプライミングし、glue のない NS 名も
 * 自前でルート (またはキャッシュ済みの最も近いゾーンカット) から反復解決する。
 * システムリゾルバ (/etc/resolv.conf, getaddrinfo) には一切依存しない。
 */

#define IT_MAX_NS     16   /* 1 ゾーンカットあたりの NS 数 */
#define IT_MAX_GLUE   32   /* 1 応答から拾う glue 数 */
#define IT_MAX_ADDRS  16   /* 1 名前あたりのアドレス数 */

typedef enum {
    IT_RESP_BAD = 0,   /* 不正な応答 (QR=0 / 質問不一致 / 解析不能) */
    IT_RESP_ANSWER,    /* qtype に一致する RR を得た */
    IT_RESP_CNAME,     /* CNAME/DNAME を辿った先がこのゾーンの外 (target から再開する) */
    IT_RESP_NXDOMAIN,
    IT_RESP_NODATA,
    IT_RESP_REFERRAL,  /* 下位ゾーンへの委任 */
    IT_RESP_LAME,      /* REFUSED / 上向き・横向きの referral / 権威のない空応答 */
    IT_RESP_SERVFAIL,
    IT_RESP_FORMERR,   /* FORMERR / NOTIMP: EDNS なしで再試行する */
} it_resp_kind_t;

typedef struct {
    char owner[256];
    char addr[64];
    bool in_domain;    /* glue の owner が委任先ゾーン (cut) の配下 */
} it_glue_t;

typedef struct {
    it_resp_kind_t kind;
    bool aa;
    uint8_t rcode;
    char target[256];              /* 応答内の CNAME/DNAME を辿った後の名前 (辿らなければ qname) */
    char cut[256];                 /* REFERRAL: 委任先ゾーン / qtype=NS の ANSWER: owner */
    char ns[IT_MAX_NS][256];       /* REFERRAL の NS / qtype=NS の ANSWER の NS */
    int nns;
    it_glue_t glue[IT_MAX_GLUE];   /* ns[] に対応する bailiwick 内の A/AAAA */
    int nglue;
    char addrs[IT_MAX_ADDRS][64];  /* ANSWER の A/AAAA */
    int naddr;
    int nanswer;                   /* qtype に一致した RR 数 */
    bool cname_loop;               /* 応答内の CNAME/DNAME が循環している */
    char why[160];                 /* LAME / BAD などの理由 */
} it_resp_t;

/* ゾーン zone のサーバに (qname, qtype) を問い合わせて得た応答 pkt を分類する。
 * bailiwick 外 (zone の配下にない) のデータは無視する。 */
it_resp_kind_t dag_iter_classify(const uint8_t *pkt, size_t len, const char *qname, uint16_t qtype,
                                 const char *zone, it_resp_t *out);

const char *dag_iter_kind_name(it_resp_kind_t k);

/* 名前のラベル数 ("." は 0) */
int dag_iter_label_count(const char *name);

/* name の末尾 n ラベルを out に書く (末尾ドット付き)。n=0 なら "." */
void dag_iter_name_suffix(const char *name, int n, char *out, size_t out_cap);

int run_trace2_query(const char *qname, const char *server, bool server_explicit, const char *qtype_s,
                     int port, bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response,
                     const query_opts_t *qo, const display_opts_t *dopt, const trace2_opts_t *t2);

#endif /* DAG_ITER_H */
