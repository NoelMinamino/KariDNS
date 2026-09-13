#ifndef DAG_AXFR_CLIENT_H
#define DAG_AXFR_CLIENT_H

#include "dag_internal.h"

typedef struct {
    bool is_axfr;
    bool is_ixfr;
    char first_soa_name[256];
    uint8_t first_soa_norm[1024];
    size_t first_soa_norm_len;
    int soa_seen_count;
    bool axfr_complete;
} axfr_state_t;

void check_axfr_soa(axfr_state_t *state, const uint8_t *pkt, size_t pkt_len, const char *name, const uint8_t *hdr, uint16_t rdlen);
ssize_t do_axfr_recv_next(int tcp_sock, const query_opts_t *qo, uint8_t *resp, size_t resp_cap);

#endif /* DAG_AXFR_CLIENT_H */
