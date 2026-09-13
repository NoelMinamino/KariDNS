#ifndef DAG_TRANSPORT_H
#define DAG_TRANSPORT_H

#include "dag_internal.h"

bool parse_proxy_arg(const char *arg, query_opts_t *qo);
size_t build_proxyv2_header(uint8_t *buf, size_t buf_cap, const query_opts_t *qo, bool is_tcp);
void send_proxyv2_if_enabled(int sock, const query_opts_t *qo, bool is_tcp);

bool resolve_server_addr(const char *server, int port, int pref_family,
                         struct sockaddr_storage *dest, socklen_t *dest_len,
                         int *family_out, bool update_global_ip);
int get_server_addr_count(const char *server, int port, int pref_family);

int connect_udp(const char *server, int port, int pref_family, const char *bind_addr, int bind_port, struct sockaddr_storage *dest, socklen_t *dest_len);
int connect_tcp(const char *server, int port, const query_opts_t *qo, int timeout_sec);
void close_cached_tcp(void);

int do_tcp_send_request(const char *server, int port, const query_opts_t *qo,
                        const uint8_t *pkt, size_t pkt_len, int timeout_sec);
ssize_t do_tcp_recv_response(int sock, uint8_t *resp, size_t resp_cap);
ssize_t do_tls_recv_response(SSL *ssl, uint8_t *resp, size_t resp_cap);

ssize_t do_udp_exchange(const char *server, int port, const query_opts_t *qo,
                        const uint8_t *pkt, size_t pkt_len,
                        uint8_t *resp, size_t resp_cap, int timeout_sec);
ssize_t do_tcp_exchange(const char *server, int port, const query_opts_t *qo,
                        const uint8_t *pkt, size_t pkt_len,
                        uint8_t *resp, size_t resp_cap, int timeout_sec);
ssize_t do_tls_exchange(const char *server, int port, const query_opts_t *qo,
                        const uint8_t *pkt, size_t pkt_len,
                        uint8_t *resp, size_t resp_cap, int timeout_sec);
ssize_t do_doh_exchange(const char *server, int port, const query_opts_t *qo,
                        const uint8_t *pkt, size_t pkt_len,
                        uint8_t *resp, size_t resp_cap, int timeout_sec);
ssize_t do_dns_exchange_by_transport(const char *server, int port, const query_opts_t *qo,
                                     bool use_tcp, const uint8_t *pkt, size_t pkt_len,
                                     uint8_t *resp, size_t resp_cap, int timeout_sec);
ssize_t do_dns_exchange_auto(const char *server, int port, const query_opts_t *qo,
                             const uint8_t *pkt, size_t pkt_len,
                             uint8_t *resp, size_t resp_cap, int timeout_sec,
                             bool force_tcp);

#endif /* DAG_TRANSPORT_H */
