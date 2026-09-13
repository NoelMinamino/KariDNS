#include "dag_axfr_client.h"

ssize_t do_axfr_recv_next(int tcp_sock, const query_opts_t *qo, uint8_t *resp, size_t resp_cap) {
    if (qo && qo->use_tls) {
        if (g_cached_conn.is_tls && g_cached_conn.ssl) {
            return do_tls_recv_response(g_cached_conn.ssl, resp, resp_cap);
        }
        return -1;
    } else if (qo && qo->use_doh) {
        if (g_cached_conn.is_tls && g_cached_conn.ssl) {
            return do_tls_recv_response(g_cached_conn.ssl, resp, resp_cap);
        } else if (g_cached_conn.sock >= 0) {
            return do_tcp_recv_response(g_cached_conn.sock, resp, resp_cap);
        }
        return -1;
    } else {
        if (tcp_sock >= 0) {
            return do_tcp_recv_response(tcp_sock, resp, resp_cap);
        } else if (g_cached_conn.sock >= 0 && !g_cached_conn.is_tls) {
            return do_tcp_recv_response(g_cached_conn.sock, resp, resp_cap);
        }
        return -1;
    }
}

void check_axfr_soa(axfr_state_t *state, const uint8_t *pkt, size_t pkt_len, const char *name, const uint8_t *hdr, uint16_t rdlen) {
    if (!state || !state->is_axfr) return;
    const uint8_t *rdata = hdr + 10;

    char *mname = NULL, *rname = NULL;
    size_t next1, next2;
    if (expand_wire_name(pkt, pkt_len, rdata - pkt, &next1, &g_dag_arena, &mname) != 0) return;
    if (expand_wire_name(pkt, pkt_len, next1, &next2, &g_dag_arena, &rname) != 0) return;
    if (next2 + 20 > (size_t)(rdata - pkt) + rdlen) return;

    size_t mlen = strlen(mname);
    size_t rlen = strlen(rname);
    size_t norm_len = mlen + 1 + rlen + 1 + 20;
    if (norm_len > sizeof(state->first_soa_norm)) return;

    uint8_t norm[1024];
    memcpy(norm, mname, mlen + 1);
    memcpy(norm + mlen + 1, rname, rlen + 1);
    memcpy(norm + mlen + 1 + rlen + 1, pkt + next2, 20);

    if (state->soa_seen_count == 0) {
        snprintf(state->first_soa_name, sizeof(state->first_soa_name), "%s", name);
        memcpy(state->first_soa_norm, norm, norm_len);
        state->first_soa_norm_len = norm_len;
        state->soa_seen_count = 1;
    } else {
        if (strcasecmp(state->first_soa_name, name) == 0 &&
            norm_len == state->first_soa_norm_len &&
            memcmp(norm, state->first_soa_norm, norm_len) == 0) {
            state->axfr_complete = true;
        }
        state->soa_seen_count++;
    }
}
