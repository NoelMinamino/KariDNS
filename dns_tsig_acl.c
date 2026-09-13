#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_tsig_acl.h"
#include "dns_server_internal.h"
#include "dns_utils.h"

#include <string.h>
#include <strings.h>

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

tsig_key_t *find_tsig_key_by_name(const server_config_t *cfg, const char *key_name) {
    if (!cfg || !key_name || !*key_name) return NULL;
    for (tsig_key_t *k = cfg->keys; k; k = k->next) {
        if (strcasecmp(k->name, key_name) == 0) return k;
    }
    return NULL;
}
