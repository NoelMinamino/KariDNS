#ifndef DAG_TSIG_CLIENT_H
#define DAG_TSIG_CLIENT_H

#include "dag_internal.h"

void parse_tsig_str(char *tsig_str, query_opts_t *qo);
void parse_tsig_keyfile(const char *path, query_opts_t *qo);
bool load_bind_sig0_private_key(const char *path, sig0_key_t *key);
bool load_sig0_pkey(const char *path, sig0_key_t *key);

#endif /* DAG_TSIG_CLIENT_H */
