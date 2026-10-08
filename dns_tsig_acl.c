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
