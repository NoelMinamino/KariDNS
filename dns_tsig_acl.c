#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_tsig_acl.h"
#include "dns_server_internal.h"
#include "dns_log.h"
#include "dns_utils.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

bool check_acl(const char *client_ip, char **acl_list, int acl_count) {
    if (!client_ip || !acl_list || acl_count <= 0) return false;
    for (int i = 0; i < acl_count; i++) {
        char *rule = acl_list[i];
        /* [L-2] NULL エントリーに対する防御的チェック */
        if (!rule) continue;
        bool is_deny = (rule[0] == '!');
        const char *target = is_deny ? rule + 1 : rule;
        if (match_cidr(client_ip, target)) {
            return !is_deny;
        }
    }
    return false;
}

acl_entry_t *acl_list_parse(char **acl_list, int count) {
    if (!acl_list || count <= 0) return NULL;
    acl_entry_t *entries = calloc(count, sizeof(acl_entry_t));
    if (!entries) return NULL;
    for (int i = 0; i < count; i++) {
        char *rule = acl_list[i];
        if (!rule) continue;
        bool is_deny = (rule[0] == '!');
        const char *target = is_deny ? rule + 1 : rule;
        entries[i].is_deny = is_deny;
        cidr_entry_parse(&entries[i].cidr, target);
    }
    return entries;
}

bool check_acl_bin(const char *client_ip, const acl_entry_t *parsed, int count) {
    if (!client_ip || !parsed || count <= 0) return false;
    struct in_addr addr4;
    struct in6_addr addr6;
    int family = 0;
    const uint8_t *addr_bytes = NULL;
    if (inet_pton(AF_INET, client_ip, &addr4) == 1) {
        family = AF_INET;
        addr_bytes = (const uint8_t *)&addr4.s_addr;
    } else if (inet_pton(AF_INET6, client_ip, &addr6) == 1) {
        family = AF_INET6;
        addr_bytes = (const uint8_t *)&addr6.s6_addr;
    } else {
        return false;
    }

    for (int i = 0; i < count; i++) {
        if (!parsed[i].cidr.valid) continue;
        if (cidr_entry_match(&parsed[i].cidr, family, addr_bytes)) {
            return !parsed[i].is_deny;
        }
    }
    return false;
}

/* ---- zone ACLs: allow-transfer, allow-update, transfer-acl-match / update-acl-match, acl-ceiling (B7a, D14) ---- */

/* RFC 8945 §5.2: key_name is the key the request was verified with (NULL: no TSIG, or one that did not verify) */
static bool addr_list_match(const char *client_ip, char **list, const acl_entry_t *parsed, int count) {
    if (count <= 0) return false;
    return parsed ? check_acl_bin(client_ip, parsed, count) : check_acl(client_ip, list, count);
}

/* Is the client inside options { database { acl-ceiling } }?  The ceiling is a list of addresses and key names: a client is
 * inside when its address matches an address entry (a "!" entry excludes, first match decides, like every address list) or
 * the request is signed with a listed key.  No ceiling configured (or no database block) = nobody is inside. */
static bool ceiling_allows(const server_config_t *cfg, const char *client_ip, const char *key_name) {
    if (!db_acl_ceiling_configured(cfg)) return false;
    const database_config_t *d = &cfg->database;
    bool addr_in = client_ip && addr_list_match(client_ip, d->acl_ceiling, d->acl_ceiling_parsed, d->acl_ceiling_count);
    bool key_in = false;
    for (int i = 0; key_name && i < d->acl_ceiling_keys_count && !key_in; i++)
        key_in = tsig_key_names_equal(key_name, d->acl_ceiling_keys[i]);
    /* acl-ceiling-match all (B7b): both kinds of entry must match, so a request must come from a listed address and be
     * signed with a listed key (BIND's ACLs cannot say that).  With only one kind listed that kind decides, and so it does
     * for "any", which is the meaning B7a had. */
    if (d->acl_ceiling_match == ACL_MATCH_ALL && d->acl_ceiling_count > 0 && d->acl_ceiling_keys_count > 0)
        return addr_in && key_in;
    return addr_in || key_in;
}

bool db_ceiling_allows_address(const server_config_t *cfg, const char *client_ip) {
    if (!db_acl_ceiling_configured(cfg) || !client_ip) return false;
    const database_config_t *d = &cfg->database;
    return addr_list_match(client_ip, d->acl_ceiling, d->acl_ceiling_parsed, d->acl_ceiling_count);
}

bool zone_transfer_acl_allows(const server_config_t *cfg, const zone_config_t *zcfg, const char *client_ip,
                              const char *key_name) {
    if (!zcfg || !client_ip) return false;
    const zone_ext_t *x = zext(zcfg);
    /* the zone's tsig-key is the key of the primary of a secondary zone; for a file zone it has always also been a key that
     * may transfer, for a DB zone (PowerDNS: AXFR-MASTER-TSIG) it is not */
    bool zone_key_counts = x->tsig_key != NULL && !x->db_acl_ceiling;
    /* a database ACL that names a key karidns.conf does not (or no longer) define refuses everybody (design 1.3) */
    for (int i = 0; x->db_acl_ceiling && i < x->tsig_keys_count; i++)
        if (!find_tsig_key_by_name(cfg, x->tsig_keys[i])) return false;
    bool has_acl = x->allow_transfer_count > 0;
    bool has_keys = x->tsig_keys_count > 0 || zone_key_counts;
    bool acl_ok = has_acl && addr_list_match(client_ip, x->allow_transfer, x->allow_transfer_parsed, x->allow_transfer_count);
    bool key_ok = false;
    for (int i = 0; key_name && i < x->tsig_keys_count && !key_ok; i++)
        key_ok = tsig_key_names_equal(key_name, x->tsig_keys[i]);
    if (key_name && !key_ok && zone_key_counts) key_ok = tsig_key_names_equal(key_name, x->tsig_key);
    bool allowed = false;
    if (has_acl && has_keys)         /* both kinds of entry: AND unless the zone says "any" (D14) */
        allowed = x->transfer_acl_match == ACL_MATCH_ANY ? (acl_ok || key_ok) : (acl_ok && key_ok);
    else if (has_acl)
        allowed = acl_ok;
    else if (has_keys)
        allowed = key_ok;
    if (allowed && x->db_acl_ceiling) allowed = ceiling_allows(cfg, client_ip, key_name);
    return allowed;
}

/* an allow-update entry is a key name when it is no address, prefix, any or none (the list keeps both kinds) */
static bool update_entry_is_key(const char *e, const acl_entry_t *parsed, int i) {
    if (!e || e[0] == '!' || e[0] == '\0' || strcmp(e, "none") == 0) return false;
    if (parsed) return !parsed[i].cidr.valid;
    cidr_entry_t tmp;
    return !cidr_entry_parse(&tmp, e);
}

bool zone_update_acl_allows(const server_config_t *cfg, const zone_config_t *zcfg, const char *client_ip,
                            const char *key_name) {
    if (!zcfg || !client_ip) return false;
    const zone_ext_t *x = zext(zcfg);
    if (x->allow_update_count <= 0) return false;
    for (int i = 0; x->db_acl_ceiling && i < x->allow_update_count; i++)       /* as for transfers: a key that is not defined */
        if (update_entry_is_key(x->allow_update[i], x->allow_update_parsed, i) && !find_tsig_key_by_name(cfg, x->allow_update[i]))
            return false;
    bool addr_ok = addr_list_match(client_ip, x->allow_update, x->allow_update_parsed, x->allow_update_count);
    bool any_key_ok = false;                 /* the signing key is named by an entry (any entry: the file zone rule since R-30) */
    bool addr_present = false, key_present = false, key_ok = false;
    for (int i = 0; i < x->allow_update_count; i++) {
        const char *e = x->allow_update[i];
        bool is_key = update_entry_is_key(e, x->allow_update_parsed, i);
        if (is_key) key_present = true;
        else addr_present = true;
        if (key_name && e && tsig_key_names_equal(key_name, e)) {
            any_key_ok = true;
            if (is_key) key_ok = true;
        }
    }
    bool allowed;
    if (x->update_acl_match == ACL_MATCH_ALL)    /* every kind of entry that is there must match (PowerDNS: address and key) */
        allowed = addr_present && key_present ? (addr_ok && key_ok) : (addr_present ? addr_ok : key_ok);
    else                                         /* the default: the address matches, or the signing key is named */
        allowed = addr_ok || any_key_ok;
    if (allowed && x->db_acl_ceiling) allowed = ceiling_allows(cfg, client_ip, key_name);
    return allowed;
}

tsig_key_t *find_tsig_key_by_name(const server_config_t *cfg, const char *key_name) {
    if (!cfg || !key_name || !*key_name) return NULL;
    for (tsig_key_t *k = cfg->keys; k; k = k->next) {
        if (k->name && tsig_key_names_equal(k->name, key_name)) return k;
    }
    return NULL;
}

/* the keys only the view view_name has (NULL: none) */
static tsig_key_t *view_own_keys(const server_config_t *cfg, const char *view_name) {
    if (!cfg || !view_name || !*view_name) return NULL;
    for (const view_config_t *v = cfg->views; v; v = v->next)
        if (v->name && strcasecmp(v->name, view_name) == 0) return v->keys;
    return NULL;
}

tsig_key_t *find_tsig_key_in_view(const server_config_t *cfg, const char *view_name, const char *key_name) {
    if (!cfg || !key_name || !*key_name) return NULL;
    for (tsig_key_t *k = view_own_keys(cfg, view_name); k; k = k->next)
        if (k->name && tsig_key_names_equal(k->name, key_name)) return k;
    return find_tsig_key_by_name(cfg, key_name);
}

bool tsig_key_names_equal(const char *a, const char *b) {
    return domain_names_match_ci(a, b);
}

static const char *tsig_error_name(uint16_t error) {
    switch (error) {
    case 16: return "BADSIG";
    case 17: return "BADKEY";
    case 18: return "BADTIME";
    case 22: return "BADTRUNC";
    default: return "FORMERR";
    }
}

void tsig_check_request(const server_config_t *cfg, const char *view_name, const uint8_t *req, size_t req_len, const char *client_ip,
                        tsig_request_t *t) {
    t->status = TSIG_REQ_NONE;
    t->error = 0;
    t->key = NULL;
    t->mac_len = 0;
    t->stripped_len = req_len;
    if (!req || req_len < DNS_HEADER_SIZE || (req[10] == 0 && req[11] == 0)) return;

    tsig_rr_t rr;
    int pr = tsig_parse_rr(req, req_len, &rr);
    if (pr == 0) return;
    if (pr < 0) {
        t->status = TSIG_REQ_FORMERR;
    } else {
        t->stripped_len = rr.rr_offset;
        t->time_signed = rr.time_signed;
        t->fudge = rr.fudge;
        strlcpy(t->key_name, rr.key_name, sizeof(t->key_name));
        strlcpy(t->alg_name, rr.alg_name, sizeof(t->alg_name));
        /* RFC 8945 §5.2.1: 要求が名乗る鍵名とアルゴリズムで鍵を決める。知らなければ BADKEY */
        const struct evp_md_st *md = tsig_algorithm_evp_md(rr.alg_name);
        tsig_key_t *k = NULL;
        /* the view's own keys, then the global ones (a name is in one of them only: the configuration refuses a second key of a name) */
        tsig_key_t *lists[2] = { view_own_keys(cfg, view_name), cfg ? cfg->keys : NULL };
        for (int li = 0; li < 2 && !k && md; li++) {
            for (tsig_key_t *c = lists[li]; c; c = c->next) {
                if (tsig_key_names_equal(c->name, rr.key_name) &&
                    tsig_algorithm_evp_md(c->algorithm ? c->algorithm : "hmac-sha256") == md) {
                    k = c;
                    break;
                }
            }
        }
        if (!k) {
            t->status = TSIG_REQ_ERROR;
            t->error = 17;
        } else {
            tsig_verify_info_t info;
            int err = tsig_verify_packet_ex(req, req_len, k, NULL, 0, NULL, 0, false, t->mac, &t->mac_len, &info);
            if (err == 0 && info.truncated) {
                /* RFC 8945 §5.2.4: 切り詰めを設定する手段がないので、完全な長さより短い MAC は方針違反 */
                t->status = TSIG_REQ_ERROR;
                t->error = 22;
                t->key = k;
            } else if (err == 0) {
                t->status = TSIG_REQ_VALID;
                t->key = k;
            } else if (err == 18) {
                t->status = TSIG_REQ_ERROR;
                t->error = 18;
                t->key = k;          /* §5.2.3: BADTIME の応答は同じ鍵で署名する */
            } else if (err == 16 || err == 17) {
                t->status = TSIG_REQ_ERROR;
                t->error = (uint16_t)err;
                t->mac_len = 0;
            } else {
                t->status = TSIG_REQ_FORMERR;
                t->mac_len = 0;
            }
        }
    }
    if (t->status != TSIG_REQ_VALID) {
        /* RFC 8945 §5.2.1-§5.2.4: the server SHOULD log the error */
        syslog(LOG_INFO, "[TSIG] request from %s with key '%s': %s",
               client_ip ? client_ip : "?", t->status == TSIG_REQ_FORMERR ? "?" : t->key_name,
               tsig_error_name(t->status == TSIG_REQ_FORMERR ? 0 : t->error));
    }
}

size_t tsig_response_reserve(const tsig_request_t *t) {
    if (!t || !t->key || (t->status != TSIG_REQ_VALID && t->status != TSIG_REQ_ERROR)) return 0;
    return tsig_rr_wire_size(t->key->name, t->key->algorithm ? t->key->algorithm : "hmac-sha256",
                             t->status == TSIG_REQ_VALID ? 0 : t->error);
}

int tsig_finish_response(uint8_t *res, size_t res_len, size_t max_len, const tsig_request_t *t) {
    if (!t || t->status == TSIG_REQ_NONE || t->status == TSIG_REQ_FORMERR || res_len < DNS_HEADER_SIZE)
        return (int)res_len;
    uint16_t error = t->status == TSIG_REQ_VALID ? 0 : t->error;
    tsig_key_t echo;
    tsig_key_t *key = t->key;
    if (error == 16 || error == 17) {
        /* RFC 8945 §5.3.2: 鍵と MAC のエラーは無署名。鍵名とアルゴリズムは要求のものを写す */
        memset(&echo, 0, sizeof(echo));
        echo.name = (char *)t->key_name;
        echo.algorithm = (char *)t->alg_name;
        key = &echo;
    }
    if (!key) return -1;
    /* BADTIME: Time Signed と Fudge はクライアントの値 (§5.2.3) */
    tsig_sign_times_t times = { t->time_signed, t->fudge };
    const tsig_sign_times_t *tp = (error == 18) ? &times : NULL;
    for (int attempt = 0; attempt < 2; attempt++) {
        /* 応答の MAC は要求の MAC (検証できたときだけ) から計算する (§4.3.1、§5.3.2) */
        uint8_t mac[64];
        size_t mac_len = (error == 16 || error == 17) ? 0 : t->mac_len;
        if (mac_len > 0) memcpy(mac, t->mac, mac_len);
        size_t len = res_len;
        if (tsig_sign_packet_ex(res, &len, max_len, key, error, mac, &mac_len, NULL, 0, false, tp) == 0)
            return (int)len;
        if (attempt == 1) break;
        /* RFC 8945 §5.3: TSIG が入らなければ、質問と TSIG だけ、TC=1、NOERROR の応答にする */
        uint16_t qdcount = (res[4] << 8) | res[5];
        size_t q_end = DNS_HEADER_SIZE;
        for (uint16_t i = 0; i < qdcount; i++) {
            size_t next;
            if (skip_wire_name(res, res_len, q_end, &next) != 0 || next + 4 > res_len) return -1;
            q_end = next + 4;
        }
        res[2] |= 0x02;
        res[3] &= 0xF0;
        res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0;
        res_len = q_end;
    }
    return -1;
}

/* ---- BIND address match lists (dns_tsig_acl.h) ---- */

aml_t *aml_new(void) {
    aml_t *l = calloc(1, sizeof(*l));
    if (l) atomic_init(&l->refs, 1);
    return l;
}

bool aml_push(aml_t *l, const aml_elem_t *e) {
    if (l->count == l->cap) {
        int ncap = l->cap ? l->cap * 2 : 4;
        aml_elem_t *n = realloc(l->elems, (size_t)ncap * sizeof(*n));
        if (!n) return false;
        l->elems = n;
        l->cap = ncap;
    }
    l->elems[l->count++] = *e;
    return true;
}

aml_t *aml_ref(aml_t *l) {
    if (l) atomic_fetch_add_explicit(&l->refs, 1, memory_order_relaxed);
    return l;
}

void aml_unref(aml_t *l) {
    if (!l) return;
    if (atomic_fetch_sub_explicit(&l->refs, 1, memory_order_acq_rel) != 1) return;
    for (int i = 0; i < l->count; i++) {
        free(l->elems[i].text);
        free(l->elems[i].loc);
        if (l->elems[i].kind == AML_E_LIST) aml_unref(l->elems[i].u.list);
    }
    free(l->elems);
    free(l);
}

bool aml_subject_from_ip(aml_subject_t *s, uint8_t buf[16], const char *ip, const char *key) {
    s->key = key;
    s->addr = NULL;
    s->family = 0;
    if (!ip) return false;
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ip, &a4) == 1) {
        memcpy(buf, &a4, 4);
        s->family = AF_INET;
    } else if (inet_pton(AF_INET6, ip, &a6) == 1) {
        memcpy(buf, &a6, 16);
        s->family = AF_INET6;
    } else {
        return false;
    }
    s->addr = buf;
    return true;
}

void aml_subject_from_sockaddr(aml_subject_t *s, const void *sa, const char *key) {
    s->key = key;
    s->addr = NULL;
    s->family = 0;
    if (!sa) return;
    const struct sockaddr *p = (const struct sockaddr *)sa;
    if (p->sa_family == AF_INET) {
        s->family = AF_INET;
        s->addr = (const uint8_t *)&((const struct sockaddr_in *)sa)->sin_addr;
    } else if (p->sa_family == AF_INET6) {
        s->family = AF_INET6;
        s->addr = ((const struct sockaddr_in6 *)sa)->sin6_addr.s6_addr;
    }
}

struct aml_iface_set {
    size_t n;
    aml_iface_t v[];
};
static _Atomic(const struct aml_iface_set *) g_aml_ifaces;

size_t aml_collect_interfaces(aml_iface_t *out, size_t max) {
    struct ifaddrs *ifa = NULL, *p;
    size_t n = 0;
    if (getifaddrs(&ifa) != 0) return 0;
    for (p = ifa; p && n < max; p = p->ifa_next) {
        if (!p->ifa_addr || !(p->ifa_flags & IFF_UP)) continue;
        aml_iface_t *e = &out[n];
        memset(e, 0, sizeof(*e));
        if (p->ifa_addr->sa_family == AF_INET) {
            e->family = AF_INET;
            memcpy(e->addr, &((struct sockaddr_in *)(void *)p->ifa_addr)->sin_addr, 4);
            memset(e->mask, 0xff, 4);
            if (p->ifa_netmask) memcpy(e->mask, &((struct sockaddr_in *)(void *)p->ifa_netmask)->sin_addr, 4);
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            e->family = AF_INET6;
            memcpy(e->addr, ((struct sockaddr_in6 *)(void *)p->ifa_addr)->sin6_addr.s6_addr, 16);
            memset(e->mask, 0xff, 16);
            if (p->ifa_netmask) memcpy(e->mask, ((struct sockaddr_in6 *)(void *)p->ifa_netmask)->sin6_addr.s6_addr, 16);
            /* KAME embeds the scope in bytes 2-3 of a link-local address; a client's address carries none */
            if (e->addr[0] == 0xfe && (e->addr[1] & 0xc0) == 0x80) e->addr[2] = e->addr[3] = 0;
        } else {
            continue;
        }
        n++;
    }
    freeifaddrs(ifa);
    return n;
}

void aml_set_interfaces(const aml_iface_t *v, size_t n) {
    struct aml_iface_set *s = malloc(sizeof(*s) + n * sizeof(aml_iface_t));
    if (!s) return;
    s->n = n;
    if (n) memcpy(s->v, v, n * sizeof(aml_iface_t));
    atomic_store_explicit(&g_aml_ifaces, s, memory_order_release);   /* the previous table is not freed: readers may hold it */
}

size_t aml_get_interfaces(const aml_iface_t **v) {
    const struct aml_iface_set *s = atomic_load_explicit(&g_aml_ifaces, memory_order_acquire);
    if (!s) {
        *v = NULL;
        return 0;
    }
    *v = s->v;
    return s->n;
}

void aml_init_interfaces(void) {
    aml_iface_t tmp[256];
    size_t n = aml_collect_interfaces(tmp, sizeof(tmp) / sizeof(tmp[0]));
    aml_set_interfaces(tmp, n);
}

static bool aml_iface_match(const aml_subject_t *s, bool nets) {
    const aml_iface_t *v;
    size_t n = aml_get_interfaces(&v);
    if (!s->addr) return false;
    size_t len = s->family == AF_INET ? 4 : 16;
    for (size_t i = 0; i < n; i++) {
        if (v[i].family != s->family) continue;
        bool eq = true;
        for (size_t k = 0; k < len && eq; k++) {
            uint8_t m = nets ? v[i].mask[k] : 0xff;
            if ((s->addr[k] & m) != (v[i].addr[k] & m)) eq = false;
        }
        if (eq) return true;
    }
    return false;
}

static int aml_match_depth(const aml_t *l, const aml_subject_t *s, int depth) {
    if (!l || depth > AML_MAX_DEPTH) return 0;
    for (int i = 0; i < l->count; i++) {
        const aml_elem_t *e = &l->elems[i];
        bool m = false;
        switch (e->kind) {
        case AML_E_ANY:
            m = true;
            break;
        case AML_E_NET:
            m = s->addr && cidr_entry_match(&e->u.net, s->family, s->addr);
            break;
        case AML_E_KEY:
            m = s->key && e->text && tsig_key_names_equal(s->key, e->text);
            break;
        case AML_E_LIST:
            /* a negative match inside a nested list is "no match" (BIND, lib/dns/acl.c dns_aclelement_match()): `!{ !a; any; }` is not a surprise positive for a */
            m = aml_match_depth(e->u.list, s, depth + 1) > 0;
            break;
        case AML_E_LOCALHOST:
            m = aml_iface_match(s, false);
            break;
        case AML_E_LOCALNETS:
            m = aml_iface_match(s, true);
            break;
        default:   /* none, and a name that was never resolved: nothing */
            break;
        }
        if (m) return e->neg ? -1 : 1;
    }
    return 0;
}

int aml_match(const aml_t *l, const aml_subject_t *s) {
    return aml_match_depth(l, s, 0);
}

bool aml_allows(const aml_t *l, const aml_subject_t *s) {
    return aml_match_depth(l, s, 0) > 0;
}

bool aml_allows_addr(const aml_t *l, const aml_subject_t *s) {
    aml_subject_t a = *s;
    a.key = NULL;
    return aml_match_depth(l, &a, 0) > 0;
}

static bool aml_key_listed_d(const aml_t *l, const char *key, bool neg, int depth) {
    if (!l || depth > AML_MAX_DEPTH) return false;
    for (int i = 0; i < l->count; i++) {
        const aml_elem_t *e = &l->elems[i];
        bool en = neg != e->neg;
        if (e->kind == AML_E_KEY && !en && e->text && tsig_key_names_equal(key, e->text)) return true;
        if (e->kind == AML_E_LIST && aml_key_listed_d(e->u.list, key, en, depth + 1)) return true;
    }
    return false;
}

bool aml_key_listed(const aml_t *l, const char *key_name) {
    return key_name && aml_key_listed_d(l, key_name, false, 0);
}

static aml_t *acl_set_get(const acl_set_t *s, int which) {
    switch (which) {
    case AML_ACL_QUERY: return s->query;
    case AML_ACL_QUERY_ON: return s->query_on;
    case AML_ACL_TRANSFER: return s->transfer;
    case AML_ACL_UPDATE: return s->update;
    default: return s->notify;
    }
}

static const acl_set_t *view_acl_set(const server_config_t *cfg, const char *view_name) {
    if (!view_name || !view_name[0]) return NULL;
    for (const view_config_t *v = cfg->views; v; v = v->next)
        if (strcasecmp(v->name, view_name) == 0) return &v->acl;
    return NULL;
}

/* zone, else view, else options (BIND 9.20 ARM: the lower level "overrides" the higher one) */
static const aml_t *acl_pick(const server_config_t *cfg, const acl_set_t *zs, const acl_set_t *vs, int which) {
    aml_t *a = acl_set_get(zs, which);
    if (a) return a;
    if (vs && (a = acl_set_get(vs, which)) != NULL) return a;
    return cfg ? acl_set_get(&cfg->acl, which) : NULL;
}

const aml_t *config_acl_for(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, int which) {
    const acl_set_t *zs = &zext(zone)->acl;
    if (!cfg) return acl_set_get(zs, which);
    return acl_pick(cfg, zs, view_acl_set(cfg, view_name), which);
}

bool query_acl_permits_sa(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const char *client_ip,
                          const void *client_sa, const char *key, const void *local) {
    if (!cfg || !cfg->acl_query_active) return true;
    const acl_set_t *zs = &zext(zone)->acl, *vs = view_acl_set(cfg, view_name);   /* one walk over the views for both statements */
    const aml_t *q = acl_pick(cfg, zs, vs, AML_ACL_QUERY);
    const aml_t *qo = acl_pick(cfg, zs, vs, AML_ACL_QUERY_ON);
    if (!q && !qo) return true;
    if (q) {
        aml_subject_t s;
        uint8_t b[16];
        if (client_sa) {   /* the transport has the address in binary: no text to parse on the query path */
            aml_subject_from_sockaddr(&s, client_sa, key);
            if (!s.addr) return false;
        } else if (!aml_subject_from_ip(&s, b, client_ip, key)) {
            return false;
        }
        if (aml_match(q, &s) <= 0) return false;
    }
    if (qo) {
        /* ARM allow-query-on: "A query must be allowed by both ACLs, or it is refused." */
        aml_subject_t d;
        aml_subject_from_sockaddr(&d, local, key);
        if (aml_match(qo, &d) <= 0) return false;
    }
    return true;
}

bool query_acl_permits(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const char *client_ip,
                       const char *key, const void *local) {
    return query_acl_permits_sa(cfg, zone, view_name, client_ip, NULL, key, local);
}

bool zone_notify_acl_allows(const server_config_t *cfg, const zone_config_t *zone, const char *view_name, const char *client_ip,
                            const char *key_name) {
    const aml_t *l = config_acl_for(cfg, zone, view_name, AML_ACL_NOTIFY);
    aml_subject_t s;
    uint8_t b[16];
    if (!l || !aml_subject_from_ip(&s, b, client_ip, key_name)) return false;
    return aml_allows(l, &s);
}

bool zone_transfer_acl_allows_in_view(const server_config_t *cfg, const zone_config_t *zcfg, const char *view_name,
                                      const char *client_ip, const char *key_name) {
    if (!zcfg || !client_ip) return false;
    const zone_ext_t *x = zext(zcfg);
    /* the flat lists of a database zone, of settings received from a primary and of a zone built by hand are evaluated as before */
    bool flat_own = (x->allow_transfer_count > 0 || x->tsig_keys_count > 0) && !x->acl.transfer;
    if (x->db_acl_ceiling || flat_own) return zone_transfer_acl_allows(cfg, zcfg, client_ip, key_name);
    const aml_t *l = config_acl_for(cfg, zcfg, view_name, AML_ACL_TRANSFER);
    aml_subject_t s;
    uint8_t b[16];
    if (!aml_subject_from_ip(&s, b, client_ip, key_name)) return false;
    /* the zone's tsig-key has always been a key that may transfer (a file zone), and with addresses in the list a request had to carry
     * one of the keys as well (address AND key).  That is not something BIND's lists say, so it is left as it was: the order of the
     * list decides who matches, and a zone that has a tsig-key and a list with addresses still needs a request signed with the
     * tsig-key or a key of the list; without addresses in the list the tsig-key is one more way in. */
    const char *zk = x->tsig_key;
    bool zk_signed = zk && key_name && tsig_key_names_equal(key_name, zk);
    if (x->transfer_acl_match == ACL_MATCH_DEFAULT) {
        int m = l ? aml_match(l, &s) : 0;
        if (!zk) return m > 0;
        if (l && l->has_addr) return m > 0 && (zk_signed || aml_key_listed(l, key_name));
        return m > 0 || zk_signed;
    }
    bool has_acl = l && l->has_addr;
    bool has_keys = (l && l->has_key) || zk;
    bool acl_ok = has_acl && aml_allows_addr(l, &s);
    bool key_ok = zk_signed || (l && aml_key_listed(l, key_name));
    if (has_acl && has_keys) return x->transfer_acl_match == ACL_MATCH_ANY ? (acl_ok || key_ok) : (acl_ok && key_ok);
    if (has_acl) return acl_ok;
    if (has_keys) return key_ok;
    return false;
}

bool zone_update_acl_allows_in_view(const server_config_t *cfg, const zone_config_t *zcfg, const char *view_name,
                                    const char *client_ip, const char *key_name) {
    if (!zcfg || !client_ip) return false;
    const zone_ext_t *x = zext(zcfg);
    bool flat_own = x->allow_update_count > 0 && !x->acl.update;
    if (x->db_acl_ceiling || flat_own) return zone_update_acl_allows(cfg, zcfg, client_ip, key_name);
    const aml_t *l = config_acl_for(cfg, zcfg, view_name, AML_ACL_UPDATE);
    if (!l) return false;
    aml_subject_t s;
    uint8_t b[16];
    if (!aml_subject_from_ip(&s, b, client_ip, key_name)) return false;
    if (x->update_acl_match == ACL_MATCH_DEFAULT) return aml_allows(l, &s);
    bool addr_ok = aml_allows_addr(l, &s);
    bool key_ok = aml_key_listed(l, key_name);
    if (x->update_acl_match == ACL_MATCH_ALL) {   /* every kind of entry that is written must match */
        if (l->has_addr && l->has_key) return addr_ok && key_ok;
        return l->has_addr ? addr_ok : key_ok;
    }
    return addr_ok || key_ok;                     /* update-acl-match any: what allow-update always meant */
}
