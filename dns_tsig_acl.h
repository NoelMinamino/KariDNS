#ifndef DNS_TSIG_ACL_H
#define DNS_TSIG_ACL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dns_config_parser.h"

bool check_acl(const char *client_ip, char **acl_list, int acl_count);
acl_entry_t *acl_list_parse(char **acl_list, int count);
bool check_acl_bin(const char *client_ip, const acl_entry_t *parsed, int count);
tsig_key_t *find_tsig_key_by_name(const server_config_t *cfg, const char *key_name);

/* ---- BIND address match lists (BIND 9.20 ARM, "Address Match Lists" and "acl Block Definition and Usage") ----
 * An aml_t is a list of elements.  Elements are tried in order and the first one that matches decides: a non-negated match allows,
 * a negated match denies, and a list in which nothing matches denies ("If there is no match, access is denied").  An element is
 * an address or prefix, any, none, localhost, localnets, `key <name>` (the request is signed with a TSIG key of that name,
 * RFC 8945), the name of an acl { } block, or a nested { } list; each can be negated with "!".  A nested list matches only when
 * its own first match is a non-negated one (a negative match inside it counts as "no match", so `!{ !a; any; }` is the usual way
 * to say "only a"; BIND's lib/dns/acl.c does the same).  Lists are immutable once the configuration is published and are
 * shared by reference counting (the settings of a zone, a view and options all point to the lists they were written with). */
enum { AML_E_ANY = 0, AML_E_NONE, AML_E_NET, AML_E_KEY, AML_E_LIST, AML_E_LOCALHOST, AML_E_LOCALNETS, AML_E_NAME };
typedef struct {
    uint8_t kind;
    bool neg;
    char *text;      /* the element as written: NET / NAME (before it is resolved) / KEY (the key name) */
    char *loc;       /* "file:line" of a NAME or KEY element, until the parse has resolved it (NULL afterwards) */
    union {
        cidr_entry_t net;   /* AML_E_NET */
        aml_t *list;        /* AML_E_LIST: a nested list or the list of a named acl (a reference) */
    } u;
} aml_elem_t;

#define AML_MAX_DEPTH 32   /* nesting of lists and acl references that one match may follow */
struct aml {
    _Atomic uint32_t refs;
    int count;
    int cap;
    aml_elem_t *elems;
    uint8_t depth;     /* 1 + the deepest nested list (set when the names are resolved) */
    bool has_addr;     /* some non-key element can match (an address, any, none, localhost ... or a nested list that has one) */
    bool has_key;      /* some key element, also inside nested lists */
    bool has_neg_key;  /* a negated key element somewhere (the flat lists of transfer-acl-match cannot say that) */
};

aml_t *aml_new(void);
bool aml_push(aml_t *l, const aml_elem_t *e);      /* e's strings and list are moved into l on success */
aml_t *aml_ref(aml_t *l);
void aml_unref(aml_t *l);                          /* NULL is fine */

/* Who is asked: an address (family AF_INET / AF_INET6, network byte order; addr NULL = unknown, only "any" matches) and the TSIG
 * key the request was verified with (NULL = not signed). */
typedef struct {
    int family;
    const uint8_t *addr;
    const char *key;
} aml_subject_t;
/* ip: text address; buf receives the bytes.  false when ip is not an address. */
bool aml_subject_from_ip(aml_subject_t *s, uint8_t buf[16], const char *ip, const char *key);
/* sa: struct sockaddr_in / sockaddr_in6 (NULL or another family: unknown address) */
void aml_subject_from_sockaddr(aml_subject_t *s, const void *sa, const char *key);

/* > 0: the first element that matched is not negated; < 0: it is negated; 0: nothing matched.  No allocation (query path). */
int aml_match(const aml_t *l, const aml_subject_t *s);
bool aml_allows(const aml_t *l, const aml_subject_t *s);   /* aml_match() > 0 */
/* the address elements alone (key elements never match): what transfer-acl-match / update-acl-match any / all call "the addresses" */
bool aml_allows_addr(const aml_t *l, const aml_subject_t *s);
/* does the list name this TSIG key in a non-negated key element? */
bool aml_key_listed(const aml_t *l, const char *key_name);

/* localhost and localnets (BIND 9.20 ARM acl block): the addresses of the interfaces of this host, and the networks they are on.
 * One snapshot of getifaddrs(), taken at start-up before the Backend enters capability mode (which does not allow the query);
 * aml_set_interfaces() replaces it (tests; the table is never freed, it is a few hundred bytes). */
typedef struct {
    uint8_t family;      /* AF_INET / AF_INET6 */
    uint8_t addr[16];
    uint8_t mask[16];    /* the netmask of the interface (all ones when the system does not tell) */
} aml_iface_t;
size_t aml_collect_interfaces(aml_iface_t *out, size_t max);   /* getifaddrs(); returns the number written */
void aml_set_interfaces(const aml_iface_t *v, size_t n);
size_t aml_get_interfaces(const aml_iface_t **v);
/* take the snapshot of this host and install it (start-up) */
void aml_init_interfaces(void);

/* the statements of the levels; which = AML_ACL_* */
enum { AML_ACL_QUERY = 0, AML_ACL_QUERY_ON, AML_ACL_TRANSFER, AML_ACL_UPDATE, AML_ACL_NOTIFY };
/* The list that applies to a zone for a statement: the zone's own, else its view's (view_name; NULL or "" = no view), else options'.
 * NULL = written nowhere.  zone may be NULL. */
const aml_t *config_acl_for(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, int which);
/* Is the query allowed by allow-query and allow-query-on?  key: the TSIG key the request was signed with, local: the address the
 * query came to (sockaddr, or NULL when unknown: allow-query-on then only matches "any").  Always true when none is written. */
bool query_acl_permits(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const char *client_ip,
                       const char *key, const void *local);
/* the same, with the client's address as the transport has it (client_sa: sockaddr_in / sockaddr_in6, NULL = parse client_ip) */
bool query_acl_permits_sa(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const char *client_ip,
                          const void *client_sa, const char *key, const void *local);
/* allow-notify applies to the secondary zones; true when the list (zone, view or options) allows the sender */
bool zone_notify_acl_allows(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const char *client_ip,
                            const char *key_name);

/* Is a transfer (AXFR/IXFR) / a dynamic update from client_ip allowed by the ACLs of the zone?  key_name is the TSIG key the
 * request was verified with, NULL when it was not signed (RFC 8945 §5.2).  transfer: allow-transfer addresses and keys, as
 * transfer-acl-match says (default all: address AND key when both are written; any: address OR key).  update: allow-update,
 * as update-acl-match says (default any: the address matches or the key is named; all: every kind of entry that is written
 * must match).  A zone whose settings come from a database (zone_ext_t.db_acl_ceiling) is also bounded by
 * options { database { acl-ceiling } }: the client must be inside it too, and with no ceiling configured nobody is.  Inside the
 * ceiling = its address matches or the request is signed with a listed key (acl-ceiling-match any, the default); with
 * acl-ceiling-match all and both kinds listed, both (B7b). */
bool zone_transfer_acl_allows(const server_config_t *cfg, const zone_config_t *zcfg, const char *client_ip,
                              const char *key_name);
bool zone_update_acl_allows(const server_config_t *cfg, const zone_config_t *zcfg, const char *client_ip,
                            const char *key_name);
/* The same with the statements of the view and of options taken into account (BIND 9.20 ARM: a zone's allow-transfer / allow-update overrides the
 * view's, which overrides options').  Written in a configuration file with no transfer-acl-match / update-acl-match, the list is evaluated in BIND's
 * way (first match decides, `key` is "signed with that key", ! negates); with the statement written, as the flat lists above say. */
bool zone_transfer_acl_allows_in_view(const server_config_t *cfg, const zone_config_t *zcfg, const char *view_name, const char *client_ip,
                                      const char *key_name);
bool zone_update_acl_allows_in_view(const server_config_t *cfg, const zone_config_t *zcfg, const char *view_name, const char *client_ip,
                                    const char *key_name);
/* B8: is client_ip inside the address entries of options { database { acl-ceiling } } ("!" excludes, first match decides)?  Used for the
 * ecs-trusted-resolvers list of a database zone: a resolver is trusted only when the zone's list and the ceiling both accept its address
 * (keys of the ceiling do not count: ECS trust has no key).  No ceiling configured: nobody. */
bool db_ceiling_allows_address(const server_config_t *cfg, const char *client_ip);
/* 鍵名 (DNS 名) が同じか。大文字小文字と末尾のドットは区別しない (RFC 4343 §2、D-03) */
bool tsig_key_names_equal(const char *a, const char *b);

/* 要求の TSIG を調べた結果 (RFC 8945 §5.2)。サーバーは全ての応答をこの結果で仕上げる。 */
typedef enum {
    TSIG_REQ_NONE = 0,  /* TSIG なし */
    TSIG_REQ_VALID,     /* 検証できた。応答は同じ鍵で署名する (§5.3) */
    TSIG_REQ_ERROR,     /* 鍵・MAC・時刻・切り詰めのエラー。NOTAUTH + error (§5.2.1-§5.2.4) */
    TSIG_REQ_FORMERR    /* TSIG が解釈できない。TSIG なしの FORMERR (§5.2、§5.2.2.1) */
} tsig_req_status_t;

typedef struct {
    tsig_req_status_t status;
    uint16_t error;                    /* TSIG_REQ_ERROR: 16 BADSIG, 17 BADKEY, 18 BADTIME, 22 BADTRUNC */
    tsig_key_t *key;                   /* VALID、BADTIME、BADTRUNC: 要求を署名した鍵 (設定スナップショット内) */
    size_t stripped_len;               /* TSIG RR を除いた要求の長さ (VALID、ERROR) */
    uint8_t mac[64];                   /* 検証できた要求の MAC (VALID、BADTIME、BADTRUNC) */
    size_t mac_len;
    uint64_t time_signed;              /* 要求の Time Signed と Fudge (BADTIME の応答に使う) */
    uint16_t fudge;
    size_t res_limit;                  /* 応答の上限 (UDP ではクライアントの EDNS サイズ)。エンジンが決める */
    char key_name[DNS_NAME_TEXT_SIZE]; /* 要求の鍵名とアルゴリズム名 (無署名のエラー応答に写す。§5.3.2) */
    char alg_name[DNS_NAME_TEXT_SIZE];
} tsig_request_t;

/* 要求の TSIG を、要求が名乗る鍵名とアルゴリズムで設定の鍵から探して検証する。
 * 切り詰めた MAC は、切り詰めを設定する手段がないので BADTRUNC とする (BIND の既定と同じ。§5.2.4)。
 * client_ip はログ用 (NULL 可)。 */
void tsig_check_request(const server_config_t *cfg, const uint8_t *req, size_t req_len, const char *client_ip,
                        tsig_request_t *t);
/* 応答に付ける TSIG RR の最大バイト数 (VALID と BADTIME/BADTRUNC のときに応答の上限から差し引く)。 */
size_t tsig_response_reserve(const tsig_request_t *t);
/* 応答 res[0..res_len) に t に従って TSIG を付ける。NONE と FORMERR はそのまま。
 * 入りきらないときは質問だけにして TC=1、NOERROR で署名する (RFC 8945 §5.3)。
 * 戻り値は新しい長さ。署名できなければ -1。 */
int tsig_finish_response(uint8_t *res, size_t res_len, size_t max_len, const tsig_request_t *t);

#endif /* DNS_TSIG_ACL_H */
