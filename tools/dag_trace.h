#ifndef DAG_TRACE_H
#define DAG_TRACE_H

#include "dag_internal.h"
#include "dag_axfr_client.h"

#define TRACE_MAX_CNAME_DEPTH 16

int run_trace_query(const char *qname, const char *server, const char *qtype_s, int port,
                    bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response,
                    const query_opts_t *qo, const char *hex_payload, const display_opts_t *dopt);

int run_nssearch(const char *qname, const char *server, int port,
                 bool use_tcp, bool force_udp, bool no_hexdump_query, bool no_hexdump_response,
                 query_opts_t qo, const char *hex_payload, const display_opts_t *dopt);

#endif /* DAG_TRACE_H */
