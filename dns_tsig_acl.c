#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_tsig_acl.h"
#include "dns_server_internal.h"
#include "dns_utils.h"

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
        if (strcasecmp(k->name, key_name) == 0) return k;
    }
    return NULL;
}
