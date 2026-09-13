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

#endif /* DNS_TSIG_ACL_H */
