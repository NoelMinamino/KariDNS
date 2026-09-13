#ifndef DAG_OUTPUT_YAML_H
#define DAG_OUTPUT_YAML_H

#include "dag_internal.h"

void yaml_single_quote_escape(const char *src, char *dst, size_t dst_cap);
void yaml_double_quote_escape(const char *src, char *dst, size_t dst_cap);
void print_response_yaml(const uint8_t *pkt, size_t pkt_len, const char *server, uint16_t port, bool is_tcp, const display_opts_t *dopt);
void print_response_yaml_dns64(const uint8_t *pkt, size_t pkt_len, const char *server, uint16_t port, bool is_tcp);

#endif /* DAG_OUTPUT_YAML_H */
