#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_tsig_acl.h"
#include "dns_server_internal.h"
#include "dns_utils.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
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
    if (client_ip && addr_list_match(client_ip, d->acl_ceiling, d->acl_ceiling_parsed, d->acl_ceiling_count)) return true;
    for (int i = 0; key_name && i < d->acl_ceiling_keys_count; i++)
        if (tsig_key_names_equal(key_name, d->acl_ceiling_keys[i])) return true;
    return false;
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

void tsig_check_request(const server_config_t *cfg, const uint8_t *req, size_t req_len, const char *client_ip,
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
        for (tsig_key_t *c = cfg ? cfg->keys : NULL; c && md; c = c->next) {
            if (tsig_key_names_equal(c->name, rr.key_name) &&
                tsig_algorithm_evp_md(c->algorithm ? c->algorithm : "hmac-sha256") == md) {
                k = c;
                break;
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
