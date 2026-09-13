#include "dag_transport.h"
#include "dag_internal.h"

bool parse_proxy_arg(const char *arg, query_opts_t *qo) {
    if (!arg || !*arg) {
        qo->proxy_use_local_cmd = true;
        return true;
    }
    char buf[256];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *dash = strchr(buf, '-');
    if (!dash) {
        fprintf(stderr, "Invalid +proxy format '%s': expected src_addr[#src_port]-dst_addr[#dst_port]\n", arg);
        return false;
    }
    *dash = '\0';
    char *src_part = buf;
    char *dst_part = dash + 1;

    qo->proxy_src_port = 0;
    qo->proxy_dst_port = 53;

    char *src_hash = strchr(src_part, '#');
    if (src_hash) {
        *src_hash = '\0';
        qo->proxy_src_port = atoi(src_hash + 1);
    }
    char *dst_hash = strchr(dst_part, '#');
    if (dst_hash) {
        *dst_hash = '\0';
        qo->proxy_dst_port = atoi(dst_hash + 1);
    }

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, src_part, &a4) == 1 && inet_pton(AF_INET, dst_part, &a4) == 1) {
        qo->proxy_family = AF_INET;
        snprintf(qo->proxy_src_addr, sizeof(qo->proxy_src_addr), "%.63s", src_part);
        snprintf(qo->proxy_dst_addr, sizeof(qo->proxy_dst_addr), "%.63s", dst_part);
        return true;
    }
    if (inet_pton(AF_INET6, src_part, &a6) == 1 && inet_pton(AF_INET6, dst_part, &a6) == 1) {
        qo->proxy_family = AF_INET6;
        snprintf(qo->proxy_src_addr, sizeof(qo->proxy_src_addr), "%.63s", src_part);
        snprintf(qo->proxy_dst_addr, sizeof(qo->proxy_dst_addr), "%.63s", dst_part);
        return true;
    }
    fprintf(stderr, "Invalid +proxy address format '%s': IP address parse failed\n", arg);
    return false;
}

size_t build_proxyv2_header(uint8_t *buf, size_t buf_cap, const query_opts_t *qo, bool is_tcp) {
    if (!qo->use_proxy || buf_cap < 52) return 0;
    static const uint8_t v2sig[12] = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };
    memcpy(buf, v2sig, 12);
    size_t off = 12;

    if (qo->proxy_use_local_cmd) {
        buf[off++] = 0x20; // v2 + LOCAL command
        buf[off++] = 0x00; // AF_UNSPEC
        buf[off++] = 0x00; // len msb
        buf[off++] = 0x00; // len lsb
        return off;
    }

    buf[off++] = 0x21; // v2 + PROXY command
    if (qo->proxy_family == AF_INET6) {
        buf[off++] = is_tcp ? 0x21 : 0x22; // AF_INET6, STREAM or DGRAM
        uint16_t addr_len = 36;
        buf[off++] = addr_len >> 8;
        buf[off++] = addr_len & 0xFF;
        struct in6_addr s6, d6;
        inet_pton(AF_INET6, qo->proxy_src_addr[0] ? qo->proxy_src_addr : "::1", &s6);
        inet_pton(AF_INET6, qo->proxy_dst_addr[0] ? qo->proxy_dst_addr : "::1", &d6);
        memcpy(buf + off, &s6, 16); off += 16;
        memcpy(buf + off, &d6, 16); off += 16;
        uint16_t sp = (uint16_t)qo->proxy_src_port;
        uint16_t dp = (uint16_t)qo->proxy_dst_port;
        buf[off++] = sp >> 8; buf[off++] = sp & 0xFF;
        buf[off++] = dp >> 8; buf[off++] = dp & 0xFF;
    } else {
        buf[off++] = is_tcp ? 0x11 : 0x12; // AF_INET, STREAM or DGRAM
        uint16_t addr_len = 12;
        buf[off++] = addr_len >> 8;
        buf[off++] = addr_len & 0xFF;
        struct in_addr s4, d4;
        inet_pton(AF_INET, qo->proxy_src_addr[0] ? qo->proxy_src_addr : "127.0.0.1", &s4);
        inet_pton(AF_INET, qo->proxy_dst_addr[0] ? qo->proxy_dst_addr : "127.0.0.1", &d4);
        memcpy(buf + off, &s4, 4); off += 4;
        memcpy(buf + off, &d4, 4); off += 4;
        uint16_t sp = (uint16_t)qo->proxy_src_port;
        uint16_t dp = (uint16_t)qo->proxy_dst_port;
        buf[off++] = sp >> 8; buf[off++] = sp & 0xFF;
        buf[off++] = dp >> 8; buf[off++] = dp & 0xFF;
    }
    return off;
}

void send_proxyv2_if_enabled(int sock, const query_opts_t *qo, bool is_tcp) {
    if (qo && qo->use_proxy) {
        uint8_t pbuf[64];
        size_t plen = build_proxyv2_header(pbuf, sizeof(pbuf), qo, is_tcp);
        if (plen > 0) send(sock, pbuf, plen, 0);
    }
}


/* ========================================================================
 * 6. Networking
 * ==================================================================== */
int g_last_socket_family = AF_INET;

/*
 * server引数(IPv4リテラル / IPv6リテラル / FQDN)をsockaddr_storageへ解決する。
 * まずinet_pton()でIPリテラルとしての解釈を試み(DNS解決を伴わない高速パス)、
 * どちらにも一致しなければFQDNとみなしgetaddrinfo()でシステムリゾルバに問い合わせる。
 */
bool resolve_server_addr(const char *server, int port, int pref_family,
                                 struct sockaddr_storage *dest, socklen_t *dest_len,
                                 int *family_out, bool update_global_ip) {
    memset(dest, 0, sizeof(*dest));
    struct sockaddr_in *d4 = (struct sockaddr_in *)dest;
    struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)dest;

    if (inet_pton(AF_INET, server, &d4->sin_addr) == 1) {
        d4->sin_family = AF_INET; d4->sin_port = htons((uint16_t)port);
        *dest_len = sizeof(*d4);
        if (family_out) *family_out = AF_INET;
        if (update_global_ip) snprintf(g_last_server_ip, sizeof(g_last_server_ip), "%s", server);
        return true;
    }
    if (inet_pton(AF_INET6, server, &d6->sin6_addr) == 1) {
        d6->sin6_family = AF_INET6; d6->sin6_port = htons((uint16_t)port);
        *dest_len = sizeof(*d6);
        if (family_out) *family_out = AF_INET6;
        if (update_global_ip) snprintf(g_last_server_ip, sizeof(g_last_server_ip), "%s", server);
        return true;
    }

    /* IPリテラルとして解釈できなかった場合はFQDNとみなし、システムリゾルバへ問い合わせる */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = pref_family;
    hints.ai_socktype = SOCK_DGRAM; /* UDP/TCPどちらでも使うアドレスなので0でも良いが、重複エントリ抑制のため指定 */
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    int rc = getaddrinfo(server, portbuf, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "Cannot resolve server '%s': %s\n", server,
                rc != 0 ? gai_strerror(rc) : "no addresses returned");
        if (res) freeaddrinfo(res);
        return false;
    }
    if (res->ai_addrlen > sizeof(*dest)) {
        fprintf(stderr, "Resolved address for '%s' is unexpectedly large\n", server);
        freeaddrinfo(res);
        return false;
    }
    /* 複数レコードが返る場合もあるが、digやBIND互換ツールと同様に先頭(リゾルバの優先順位)を採用する */
    memcpy(dest, res->ai_addr, res->ai_addrlen);
    *dest_len = (socklen_t)res->ai_addrlen;
    if (family_out) *family_out = res->ai_family;
    if (update_global_ip) {
        if (res->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, g_last_server_ip, sizeof(g_last_server_ip));
        } else if (res->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, g_last_server_ip, sizeof(g_last_server_ip));
        }
    }
    freeaddrinfo(res);
    return true;
}

int get_server_addr_count(const char *server, int port, int pref_family) {
    struct sockaddr_in d4;
    struct sockaddr_in6 d6;
    if (inet_pton(AF_INET, server, &d4.sin_addr) == 1) return 1;
    if (inet_pton(AF_INET6, server, &d6.sin6_addr) == 1) return 1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = pref_family;
    hints.ai_socktype = SOCK_DGRAM;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);
    if (getaddrinfo(server, portbuf, &hints, &res) == 0 && res != NULL) {
        int cnt = 0;
        for (struct addrinfo *p = res; p != NULL; p = p->ai_next) cnt++;
        freeaddrinfo(res);
        return cnt > 0 ? cnt : 1;
    }
    return 1;
}

int connect_udp(const char *server, int port, int pref_family, const char *bind_addr, int bind_port, struct sockaddr_storage *dest, socklen_t *dest_len) {
    int family = AF_INET;
    if (!resolve_server_addr(server, port, pref_family, dest, dest_len, &family, true)) return -1;
    g_last_socket_family = family;
    int sock = socket(family, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    if (bind_addr && bind_addr[0] != '\0') {
        struct sockaddr_storage baddr; socklen_t blen; int bfam = family;
        if (!resolve_server_addr(bind_addr, bind_port, AF_UNSPEC, &baddr, &blen, &bfam, false)) {
            fprintf(stderr, "Error: -b address '%s' could not be resolved\n", bind_addr);
            close(sock);
            return -1;
        }
        if (bfam != family) {
            fprintf(stderr, "Error: -b address '%s' is %s, but destination server '%s' resolved to %s; "
                            "the source address family must match the destination\n",
                    bind_addr, bfam == AF_INET6 ? "IPv6" : "IPv4",
                    server, family == AF_INET6 ? "IPv6" : "IPv4");
            close(sock);
            return -1;
        }
        if (bind(sock, (struct sockaddr *)&baddr, blen) != 0) {
            fprintf(stderr, ";; UDP setup with %s#%d(%s) failed: %s.\n", server, port, server, strerror(errno));
            close(sock);
            return -1;
        }
    }
    /*
     * RFC 5452 §9.1: Connect UDP socket to the destination address/port.
     * This instructs the OS kernel to automatically filter and discard any
     * incoming UDP datagrams originating from unauthorized sources/ports.
     */
    if (connect(sock, (struct sockaddr *)dest, *dest_len) != 0) {
        fprintf(stderr, ";; connect to %s#%d failed: %s\n", server, port, strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

int connect_tcp(const char *server, int port, const query_opts_t *qo, int timeout_sec) {
    const char *bind_addr = (qo && qo->bind_addr[0]) ? qo->bind_addr : NULL;
    int bind_port = qo ? qo->bind_port : 0;
    int pref_family = qo ? qo->pref_family : AF_UNSPEC;
    struct sockaddr_storage dest; socklen_t dest_len; int family = AF_INET;
    if (!resolve_server_addr(server, port, pref_family, (struct sockaddr_storage *)&dest, &dest_len, &family, true)) return -1;
    g_last_socket_family = family;
    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }

    if (qo && qo->tcp_mss > 0) {
        int mss = qo->tcp_mss;
#ifdef TCP_MAXSEG
        setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, (const char *)&mss, sizeof(mss));
#endif
    }
    if (qo && qo->tcp_window > 0) {
        int wsize = qo->tcp_window;
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&wsize, sizeof(wsize));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&wsize, sizeof(wsize));
    }

    if (bind_addr && bind_addr[0] != '\0') {
        struct sockaddr_storage baddr; socklen_t blen; int bfam = family;
        if (!resolve_server_addr(bind_addr, bind_port, AF_UNSPEC, &baddr, &blen, &bfam, false)) {
            fprintf(stderr, "Error: -b address '%s' could not be resolved\n", bind_addr);
            close(sock);
            return -1;
        }
        if (bfam != family) {
            fprintf(stderr, "Error: -b address '%s' is %s, but destination server '%s' resolved to %s; "
                            "the source address family must match the destination\n",
                    bind_addr, bfam == AF_INET6 ? "IPv6" : "IPv4",
                    server, family == AF_INET6 ? "IPv6" : "IPv4");
            close(sock);
            return -1;
        }
        if (bind(sock, (struct sockaddr *)&baddr, blen) != 0) {
            perror("bind (tcp)");
            close(sock);
            return -1;
        }
    }

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

    int res = connect(sock, (struct sockaddr *)&dest, dest_len);
    if (res != 0) {
        bool in_progress = false;
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) in_progress = true;
#else
        if (errno == EINPROGRESS) in_progress = true;
#endif
        if (in_progress) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
            struct timeval tv = { .tv_sec = (timeout_sec > 0) ? timeout_sec : 5, .tv_usec = 0 };
            int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
            if (sel <= 0) {
                fprintf(stderr, ";; connection to %s#%d timed out after %ds\n", server, port, (timeout_sec > 0) ? timeout_sec : 5);
                close(sock); return -1;
            }
            int sock_err = 0; socklen_t err_len = sizeof(sock_err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&sock_err, &err_len) < 0 || sock_err != 0) {
                fprintf(stderr, ";; connect to %s#%d failed: %s\n", server, port, strerror(sock_err ? sock_err : errno));
                close(sock); return -1;
            }
        } else {
            fprintf(stderr, ";; connect to %s#%d failed: %s\n", server, port, strerror(errno));
            close(sock); return -1;
        }
    }

#ifdef _WIN32
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    if (flags >= 0) fcntl(sock, F_SETFL, flags);
#endif

    set_socket_timeouts(sock, timeout_sec);
    return sock;
}

ssize_t do_udp_exchange(const char *server, int port, const query_opts_t *qo,
                                const uint8_t *pkt, size_t pkt_len,
                                uint8_t *resp, size_t resp_cap, int timeout_sec) {
    struct sockaddr_storage dest; socklen_t dest_len;
    int pref_family = qo ? qo->pref_family : AF_UNSPEC;
    const char *bind_addr = (qo && qo->bind_addr[0]) ? qo->bind_addr : NULL;
    int bind_port = qo ? qo->bind_port : 0;
    int sock = connect_udp(server, port, pref_family, bind_addr, bind_port, &dest, &dest_len);
    if (sock < 0) return -1;

    uint8_t stack_buf[2048];
    uint8_t *wire_buf = stack_buf;
    size_t needed = pkt_len + 64;
    if (needed > sizeof(stack_buf)) {
        wire_buf = malloc(needed);
        if (!wire_buf) {
            close(sock);
            return -1;
        }
    }
    size_t wire_len = 0;
    if (qo && qo->use_proxy) {
        wire_len = build_proxyv2_header(wire_buf, needed, qo, false);
    }
    size_t send_len = pkt_len;
    long short_len = 3;
    if (has_break(BRK_TOO_SHORT, &short_len, NULL)) {
        if (short_len < 0) short_len = 3;
        if (send_len > (size_t)short_len) send_len = (size_t)short_len;
    }
    memcpy(wire_buf + wire_len, pkt, send_len);
    wire_len += send_len;

    ssize_t send_rc = send(sock, wire_buf, wire_len, 0);
    if (wire_buf != stack_buf) {
        free(wire_buf);
    }
    if (send_rc < 0) {
        fprintf(stderr, ";; UDP setup with %s#%d(%s) failed: %s\n", server, port, server, strerror(errno));
        close(sock); return -1;
    }

    int eff_timeout = (timeout_sec > 0) ? timeout_sec : 5;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += eff_timeout;

    uint16_t sent_id = (pkt_len >= 2) ? ((pkt[0] << 8) | pkt[1]) : 0;
    bool skip_id_check = has_break(BRK_QR_BIT, NULL, NULL) || has_break(BRK_TOO_SHORT, NULL, NULL);

    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long remain_sec = deadline.tv_sec - now.tv_sec;
        long remain_usec = (deadline.tv_nsec - now.tv_nsec) / 1000;
        if (remain_usec < 0) {
            remain_sec -= 1;
            remain_usec += 1000000;
        }
        if (remain_sec < 0 || (remain_sec == 0 && remain_usec <= 0)) {
            close(sock);
            return -1; // Timeout
        }

#ifdef _WIN32
        DWORD dw_timeout = (DWORD)(remain_sec * 1000 + (remain_usec / 1000));
        if (dw_timeout == 0) dw_timeout = 1;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&dw_timeout, sizeof(dw_timeout));
#else
        struct timeval tv;
        tv.tv_sec = (time_t)remain_sec;
        tv.tv_usec = (long)remain_usec;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#endif

        ssize_t n = recv(sock, resp, resp_cap, 0);
        if (n < 0) {
            if (errno == ECONNREFUSED) {
                printf(";; communications error to %s#%d: connection refused\n", server, port);
            }
            close(sock);
            return -1; // Timeout or network error
        }
        if (n < 2) {
            // Malformed/too short response, discard and keep waiting
            continue;
        }

        if (!skip_id_check) {
            uint16_t resp_id = (resp[0] << 8) | resp[1];
            if (resp_id != sent_id) {
                fprintf(stderr, ";; Warning: ID mismatch: expected %u, got %u\n", sent_id, resp_id);
                continue; // Discard spoofed / stray packet and wait for matching response (RFC 5452)
            }
        }

        // RFC 7873 §5.2: Client Cookie Echo Verification
        if (qo && qo->want_cookie && n >= 12 && !skip_id_check) {
            uint16_t r_qd = (resp[4] << 8) | resp[5];
            uint16_t r_an = (resp[6] << 8) | resp[7];
            uint16_t r_ns = (resp[8] << 8) | resp[9];
            uint16_t r_ar = (resp[10] << 8) | resp[11];
            edns_info_t chk_edns;
            if (parse_edns_opt(resp, (size_t)n, r_qd, r_an, r_ns, r_ar, &chk_edns) == 0 &&
                chk_edns.present && chk_edns.has_cookie) {
                if (memcmp(qo->client_cookie, chk_edns.client_cookie, 8) != 0) {
                    fprintf(stderr, ";; Warning: Client COOKIE mismatch\n");
                    continue; // Discard spoofed or stale response and wait for matching cookie (RFC 7873 §5.2)
                }
            }
        }

        close(sock);
        return n;
    }
}

tcp_conn_cache_t g_cached_conn = {
    .sock = -1,
    .ssl = NULL,
    .server = {0},
    .port = 0,
    .pref_family = AF_UNSPEC,
    .family = AF_INET,
    .bind_addr = {0},
    .bind_port = 0,
    .is_tls = false
};

void close_cached_tcp(void) {
    if (g_cached_conn.ssl) {
        SSL_shutdown(g_cached_conn.ssl);
        SSL_free(g_cached_conn.ssl);
        g_cached_conn.ssl = NULL;
    }
    if (g_cached_conn.sock >= 0) {
        close(g_cached_conn.sock);
        g_cached_conn.sock = -1;
    }
    g_cached_conn.server[0] = '\0';
    g_cached_conn.port = 0;
    g_cached_conn.is_tls = false;
}

int do_tcp_send_request(const char *server, int port, const query_opts_t *qo, const uint8_t *pkt, size_t pkt_len, int timeout_sec) {
    int sock = connect_tcp(server, port, qo, timeout_sec);
    if (sock < 0) return -1;

    send_proxyv2_if_enabled(sock, qo, true);

    long idle_secs = 20; bool idle_hold = has_break(BRK_TCP_IDLE_HOLD, &idle_secs, NULL);
    long overclaim = 0; bool overclaim_break = has_break(BRK_TCP_LENGTH_OVERCLAIM, &overclaim, NULL);
    bool zero_len_break = has_break(BRK_TCP_ZERO_LENGTH, NULL, NULL);
    long short_len = 3;
    bool too_short = has_break(BRK_TOO_SHORT, &short_len, NULL);

    size_t body_len = pkt_len;
    if (too_short) {
        if (short_len < 0) short_len = 3;
        if (body_len > (size_t)short_len) body_len = (size_t)short_len;
    }

    uint16_t prefix_value;
    if (zero_len_break) prefix_value = 0;
    else if (overclaim_break) prefix_value = (uint16_t)(body_len + overclaim);
    else prefix_value = (uint16_t)body_len;

    uint8_t len_prefix[2] = { prefix_value >> 8, prefix_value & 0xFF };
    if (send(sock, len_prefix, 2, 0) < 0) { perror("send(len prefix)"); close(sock); return -1; }

    if (idle_hold) {
        printf(";; --break tcp-idle-hold: sent only the length prefix, holding connection open for up to %lds...\n", idle_secs);
        time_t start = time(NULL);
        while (time(NULL) - start < idle_secs) {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(sock, &rfds);
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
            int r = select(sock + 1, &rfds, NULL, NULL, &tv);
            if (r > 0) {
                uint8_t tmp[1];
                ssize_t n = recv(sock, tmp, sizeof(tmp), MSG_PEEK);
                if (n == 0) {
                    printf(";; server closed the connection after ~%lds (idle timeout appears to work)\n",
                           (long)(time(NULL) - start));
                    close(sock);
                    return -1;
                }
            }
        }
        printf(";; connection still OPEN after %lds -- no idle timeout observed\n", idle_secs);
        close(sock);
        return -1;
    }

    if (zero_len_break) {
        /* prefix already claims 0 bytes; send no body at all */
    } else if (!(too_short && body_len == 0)) {
        if (send(sock, pkt, body_len, 0) < 0) { perror("send(body)"); close(sock); return -1; }
    }

    set_socket_timeouts(sock, timeout_sec);

    return sock;
}

ssize_t do_tcp_recv_response(int sock, uint8_t *resp, size_t resp_cap) {
    uint8_t rlen_buf[2];
    size_t got_len = 0;
    while (got_len < 2) {
        ssize_t n = recv(sock, rlen_buf + got_len, 2 - got_len, 0);
        if (n <= 0) return -1;
        got_len += (size_t)n;
    }
    uint16_t rlen = (rlen_buf[0] << 8) | rlen_buf[1];
    if (rlen > resp_cap) {
        // バッファ超過時はTCPストリームの同期崩れを防ぐため直ちに切断する
        return -1;
    }

    size_t got = 0;
    while (got < rlen) {
        ssize_t r = recv(sock, resp + got, rlen - got, 0);
        if (r <= 0) {
            // 宣言された長さに満たないまま受信が終了した。
            // ストリームの同期が崩れている可能性が高いため、
            // 呼び出し元が必ず接続を破棄できるよう -1 を返す。
            return -1;
        }
        got += r;
    }
    return (ssize_t)got;
}

static SSL_CTX *g_ssl_ctx = NULL;

static SSL *establish_tls(int tcp_sock, const query_opts_t *qo, const char *server, int port) {
    if (!g_ssl_ctx) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ssl_ctx) return NULL;
    }
    if (qo->tls_ca_file) {
        if (SSL_CTX_load_verify_locations(g_ssl_ctx, qo->tls_ca_file, NULL) != 1) {
            fprintf(stderr, ";; Error: could not load TLS CA file '%s'\n", qo->tls_ca_file);
            return NULL;
        }
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else if (qo->tls_verify_default_store) {
        SSL_CTX_set_default_verify_paths(g_ssl_ctx);
        static const char *const default_ca_locations[] = {
            "/etc/ssl/cert.pem",
            "/usr/local/etc/ssl/cert.pem",
            "/usr/local/share/certs/ca-root-nss.crt",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            NULL
        };
        for (int i = 0; default_ca_locations[i]; i++) {
            if (access(default_ca_locations[i], R_OK) == 0) {
                SSL_CTX_load_verify_locations(g_ssl_ctx, default_ca_locations[i], NULL);
                break;
            }
        }
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
        static bool warned_no_verify = false;
        if (!warned_no_verify) {
            fprintf(stderr,
                ";; WARNING: TLS certificate verification is disabled (opportunistic TLS). "
                "Use +tls-ca[=file] to verify the server certificate.\n");
            warned_no_verify = true;
        }
    }
    if (qo->tls_certfile && qo->tls_keyfile) {
        SSL_CTX_use_certificate_file(g_ssl_ctx, qo->tls_certfile, SSL_FILETYPE_PEM);
        SSL_CTX_use_PrivateKey_file(g_ssl_ctx, qo->tls_keyfile, SSL_FILETYPE_PEM);
    }
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) return NULL;
    SSL_set_fd(ssl, tcp_sock);

    const char *raw_sni_host = qo->tls_hostname ? qo->tls_hostname : server;
    char clean_sni_host[256];
    const char *check_host = raw_sni_host;

    if (raw_sni_host) {
        size_t slen = strlen(raw_sni_host);
        if (raw_sni_host[0] == '[' && slen > 2 && raw_sni_host[slen - 1] == ']') {
            size_t inner_len = slen - 2;
            if (inner_len < sizeof(clean_sni_host)) {
                memcpy(clean_sni_host, raw_sni_host + 1, inner_len);
                clean_sni_host[inner_len] = '\0';
                check_host = clean_sni_host;
            }
        } else if (slen > 1 && raw_sni_host[slen - 1] == '.') {
            // RFC 6066 §3: The hostname specification for SNI MUST NOT end with a trailing dot
            size_t inner_len = slen - 1;
            if (inner_len < sizeof(clean_sni_host)) {
                memcpy(clean_sni_host, raw_sni_host, inner_len);
                clean_sni_host[inner_len] = '\0';
                check_host = clean_sni_host;
            }
        }
    }

    struct in_addr a4; struct in6_addr a6;
    bool sni_is_ip = (inet_pton(AF_INET, check_host, &a4) == 1 || inet_pton(AF_INET6, check_host, &a6) == 1);
    if (!sni_is_ip && check_host) {
        SSL_set_tlsext_host_name(ssl, check_host);
    }

    // RFC 7858 §3.1: DoT クライアントは ALPN "dot" を送信する (DoH時は除く)
    if (qo && !qo->use_doh) {
        SSL_set_alpn_protos(ssl, (const unsigned char *)"\x03dot", 4);
    }

    /* 証明書検証を行うモード(tls_ca_fileまたはtls_verify_default_store指定時)
       のみ、ホスト名検証パラメータを明示的に設定する */
    if (qo->tls_ca_file || qo->tls_verify_default_store) {
        if (sni_is_ip) {
            X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set1_ip_asc(vpm, check_host);
        } else if (check_host) {
            SSL_set1_host(ssl, check_host);
        }
    }

    if (SSL_connect(ssl) <= 0) {
        if (qo->tls_ca_file || qo->tls_verify_default_store) {
            long vres = SSL_get_verify_result(ssl);
            if (vres != X509_V_OK) {
                fprintf(stderr, ";; TLS peer certificate verification for %s#%d failed: %s\n",
                        server, port, X509_verify_cert_error_string(vres));
                SSL_free(ssl);
                return NULL;
            }
        }
        // 証明書検証の有無によらず、ハンドシェイク自体の失敗理由を必ず表示する
        unsigned long ssl_err = ERR_get_error();
        if (ssl_err != 0) {
            fprintf(stderr, ";; TLS handshake with %s#%d failed: %s\n",
                    server, port, ERR_reason_error_string(ssl_err));
        } else {
            int sslerr = SSL_get_error(ssl, 0);
            fprintf(stderr, ";; TLS handshake with %s#%d failed (SSL error code %d)\n",
                    server, port, sslerr);
        }
        SSL_free(ssl);
        return NULL;
    }

    /* ハンドシェイク成功後も、検証結果を明示的に再確認する */
    if ((qo->tls_ca_file || qo->tls_verify_default_store) &&
        SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, ";; TLS peer certificate verification for %s#%d failed: %s\n",
                server, port, X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

ssize_t do_tls_recv_response(SSL *ssl, uint8_t *resp, size_t resp_cap) {
    if (!ssl) return -1;
    uint8_t rlen_buf[2];
    int got = 0;
    while (got < 2) {
        int r = SSL_read(ssl, rlen_buf + got, 2 - got);
        if (r <= 0) return -1;
        got += r;
    }
    uint16_t rlen = (rlen_buf[0] << 8) | rlen_buf[1];
    if (rlen > resp_cap) {
        return -1;
    }
    size_t total_read = 0;
    while (total_read < rlen) {
        int r = SSL_read(ssl, resp + total_read, (int)(rlen - total_read));
        if (r <= 0) return -1;
        total_read += r;
    }
    return (ssize_t)total_read;
}

ssize_t do_tls_exchange(const char *server, int port, const query_opts_t *qo,
                               const uint8_t *pkt, size_t pkt_len,
                               uint8_t *resp, size_t resp_cap, int timeout_sec) {
    SSL *ssl = NULL;
    int sock = -1;
    bool reused = false;

    if (qo && qo->keep_tcp_open) {
        if (g_cached_conn.sock >= 0 && g_cached_conn.is_tls && g_cached_conn.ssl &&
            strcmp(g_cached_conn.server, server) == 0 && g_cached_conn.port == port &&
            g_cached_conn.pref_family == qo->pref_family &&
            strcmp(g_cached_conn.bind_addr, qo->bind_addr) == 0 &&
            g_cached_conn.bind_port == qo->bind_port) {
            sock = g_cached_conn.sock;
            ssl = g_cached_conn.ssl;
            g_last_socket_family = g_cached_conn.family;
            reused = true;
        } else {
            close_cached_tcp();
        }
    } else {
        close_cached_tcp();
    }

    if (!ssl) {
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        set_socket_timeouts(sock, timeout_sec);
        send_proxyv2_if_enabled(sock, qo, true);
        ssl = establish_tls(sock, qo, server, port);
        if (!ssl) {
            close(sock);
            return -1;
        }
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = ssl;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = true;
        }
    }

    uint8_t len_prefix[2] = { (uint8_t)(pkt_len >> 8), (uint8_t)(pkt_len & 0xFF) };
    bool write_ok = (SSL_write(ssl, len_prefix, 2) > 0 && SSL_write(ssl, pkt, (int)pkt_len) > 0);
    if (!write_ok && reused) {
        close_cached_tcp();
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        set_socket_timeouts(sock, timeout_sec);
        send_proxyv2_if_enabled(sock, qo, true);
        ssl = establish_tls(sock, qo, server, port);
        if (!ssl) { close(sock); return -1; }
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = ssl;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = true;
        }
        if (SSL_write(ssl, len_prefix, 2) <= 0 || SSL_write(ssl, pkt, (int)pkt_len) <= 0) {
            close_cached_tcp();
            return -1;
        }
    } else if (!write_ok) {
        close_cached_tcp();
        if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
        return -1;
    }

    uint8_t rlen_buf[2];
    int got = 0;
    while (got < 2) {
        int r = SSL_read(ssl, rlen_buf + got, 2 - got);
        if (r <= 0) break;
        got += r;
    }
    if (got < 2) {
        if (reused) {
            close_cached_tcp();
            printf(";; communications error to %s#%d: end of file\n", server, port);
            sock = connect_tcp(server, port, qo, timeout_sec);
            if (sock < 0) return -1;
            set_socket_timeouts(sock, timeout_sec);
            send_proxyv2_if_enabled(sock, qo, true);
            ssl = establish_tls(sock, qo, server, port);
            if (!ssl) { close(sock); return -1; }
            if (qo && qo->keep_tcp_open) {
                g_cached_conn.sock = sock;
                g_cached_conn.ssl = ssl;
                snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
                g_cached_conn.port = port;
                g_cached_conn.pref_family = qo->pref_family;
                snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
                g_cached_conn.bind_port = qo->bind_port;
                g_cached_conn.is_tls = true;
            }
            if (SSL_write(ssl, len_prefix, 2) <= 0 || SSL_write(ssl, pkt, (int)pkt_len) <= 0) {
                close_cached_tcp();
                return -1;
            }
            got = 0;
            while (got < 2) {
                int r = SSL_read(ssl, rlen_buf + got, 2 - got);
                if (r <= 0) { close_cached_tcp(); return -1; }
                got += r;
            }
        } else {
            close_cached_tcp();
            if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
            return -1;
        }
    }
    uint16_t rlen = (rlen_buf[0] << 8) | rlen_buf[1];
    if (rlen > resp_cap) {
        // TLSストリームの同期崩れを防ぐため直ちに切断する
        close_cached_tcp();
        if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
        return -1;
    }
    size_t total_read = 0;
    while (total_read < rlen) {
        int r = SSL_read(ssl, resp + total_read, (int)(rlen - total_read));
        if (r <= 0) break;
        total_read += r;
    }

    if (total_read < (size_t)rlen) {
        if (reused) {
            close_cached_tcp();
            printf(";; communications error to %s#%d: end of file\n", server, port);
            sock = connect_tcp(server, port, qo, timeout_sec);
            if (sock < 0) return -1;
            set_socket_timeouts(sock, timeout_sec);
            send_proxyv2_if_enabled(sock, qo, true);
            ssl = establish_tls(sock, qo, server, port);
            if (!ssl) { close(sock); return -1; }
            if (qo && qo->keep_tcp_open) {
                g_cached_conn.sock = sock;
                g_cached_conn.ssl = ssl;
                snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
                g_cached_conn.port = port;
                g_cached_conn.pref_family = qo->pref_family;
                snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
                g_cached_conn.bind_port = qo->bind_port;
                g_cached_conn.is_tls = true;
            }
            if (SSL_write(ssl, len_prefix, 2) <= 0 || SSL_write(ssl, pkt, (int)pkt_len) <= 0) {
                close_cached_tcp();
                return -1;
            }
            uint8_t rlen_buf2[2];
            int got2 = 0;
            while (got2 < 2) {
                int r = SSL_read(ssl, rlen_buf2 + got2, 2 - got2);
                if (r <= 0) { close_cached_tcp(); return -1; }
                got2 += r;
            }
            uint16_t rlen2 = (rlen_buf2[0] << 8) | rlen_buf2[1];
            if (rlen2 > resp_cap) {
                // TLSストリームの同期崩れを防ぐため直ちに切断する
                close_cached_tcp();
                if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
                return -1;
            }
            total_read = 0;
            while (total_read < rlen2) {
                int r = SSL_read(ssl, resp + total_read, (int)(rlen2 - total_read));
                if (r <= 0) break;
                total_read += r;
            }
            if (total_read < (size_t)rlen2) {
                close_cached_tcp();
                return -1;
            }
        } else {
            close_cached_tcp();
            if (!(qo && qo->keep_tcp_open)) { SSL_shutdown(ssl); SSL_free(ssl); close(sock); }
            return -1;
        }
    }

    if (!(qo && qo->keep_tcp_open)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
    }
    return (ssize_t)total_read;
}

static void base64url_encode(const uint8_t *data, size_t len, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    static const char b64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t out_len = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = (uint32_t)data[i] << 16;
        if (i + 1 < len) val |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) val |= data[i + 2];

        if (out_len + 1 < out_cap) out[out_len++] = b64url[(val >> 18) & 0x3F];
        if (out_len + 1 < out_cap) out[out_len++] = b64url[(val >> 12) & 0x3F];
        if (i + 1 < len && out_len + 1 < out_cap) out[out_len++] = b64url[(val >> 6) & 0x3F];
        if (i + 2 < len && out_len + 1 < out_cap) out[out_len++] = b64url[val & 0x3F];
    }
    out[out_len] = '\0';
}

// HTTP Chunked 転送の次のチャンクを解析するヘルパー関数 (RFC 7230 §4.1)
static bool parse_http_chunk(const uint8_t *buf, size_t buf_len, size_t *inout_offset,
                             size_t *out_data_offset, size_t *out_chunk_len, bool *out_is_final) {
    if (!buf || !inout_offset || !out_data_offset || !out_chunk_len || !out_is_final) return false;
    if (*inout_offset >= buf_len) return false;

    const uint8_t *p = buf + *inout_offset;
    size_t rem = buf_len - *inout_offset;

    const uint8_t *line_end = memmem(p, rem, "\r\n", 2);
    if (!line_end) return false;

    // chunk-size (1*HEXDIG) を line_end の手前まで安全にパース
    const uint8_t *cur = p;
    while (cur < line_end && (*cur == ' ' || *cur == '\t')) cur++;
    if (cur == line_end) return false;

    size_t chunk_sz = 0;
    int hex_digits = 0;
    while (cur < line_end) {
        uint8_t c = *cur;
        int val = -1;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
        else break; // chunk-ext (;name=val) または空白

        if (chunk_sz > (SIZE_MAX / 16)) return false;
        chunk_sz = chunk_sz * 16 + (size_t)val;
        cur++;
        hex_digits++;
    }
    if (hex_digits == 0) return false;

    // chunk-sizeの直後: 空白スキップ後、行末かまたは ';' で始まる chunk-ext のみ許容 (RFC 7230 §4.1)
    while (cur < line_end && (*cur == ' ' || *cur == '\t')) cur++;
    if (cur < line_end && *cur != ';') return false;

    size_t data_start = (size_t)(line_end - buf) + 2;
    if (chunk_sz == 0) {
        *out_data_offset = data_start;
        *out_chunk_len = 0;
        *out_is_final = true;
        size_t after_line = (size_t)(line_end - p);
        if (after_line + 2 > rem) return false;
        // 最終チャンク: line_end から始まるトレイラーヘッダ終端 (\r\n\r\n) を探索
        const uint8_t *final_end = memmem(line_end, rem - after_line, "\r\n\r\n", 4);
        if (final_end) {
            *inout_offset = (size_t)(final_end - buf) + 4;
            return true;
        }
        return false;
    }

    // chunk_data + CRLF (2バイト) がバッファ内に収まるかを安全に検証 (オーバーフロー防止)
    if (data_start > buf_len || buf_len - data_start < 2) return false;
    if (chunk_sz > buf_len - data_start - 2) return false;

    size_t data_end = data_start + chunk_sz;
    // RFC 7230 §4.1: chunk-data の直後は必ず CRLF
    if (buf[data_end] != '\r' || buf[data_end + 1] != '\n') return false;

    *out_data_offset = data_start;
    *out_chunk_len = chunk_sz;
    *out_is_final = false;
    *inout_offset = data_end + 2;
    return true;
}

// HTTPレスポンスのステータスコードを安全に抽出 (バッファ境界チェック付き、NUL終端非依存)
static int parse_http_status_code(const uint8_t *buf, size_t len) {
    if (!buf || len < 12) return -1;
    if (strncmp((const char *)buf, "HTTP/", 5) != 0) return -1;
    const uint8_t *p = buf + 5;
    const uint8_t *end = buf + len;
    // HTTPバージョン文字列 (例: "1.1", "2") をスキップ
    while (p < end && *p != ' ' && *p != '\r' && *p != '\n') p++;
    // ステータスコード直前の空白をスキップ
    while (p < end && *p == ' ') p++;
    int code = 0, digits = 0;
    while (p < end && *p >= '0' && *p <= '9' && digits < 3) {
        code = code * 10 + (*p - '0');
        p++;
        digits++;
    }
    if (digits < 3) return -1;
    if (p < end && *p >= '0' && *p <= '9') return -1; // 4桁以上は無効
    if (p < end && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') return -1;
    return code;
}

// HTTPレスポンス(ヘッダ+ボディ)からDNSメッセージをデコードする純粋関数 (RFC 7230 / RFC 8484)
// http_buf/http_len: 受信済みの生HTTPレスポンス
// resp/resp_cap: デコード結果(DNSメッセージ)の出力バッファ
// 戻り値: 成功時はデコードしたバイト数(>=0)。未完了・不正フォーマット時は -1。
static ssize_t decode_http_response_body(const uint8_t *http_buf, size_t http_len,
                                          uint8_t *resp, size_t resp_cap) {
    if (!http_buf || http_len < 16 || !resp || resp_cap == 0) return -1;

    const uint8_t *hdr_end_u8 = memmem(http_buf, http_len, "\r\n\r\n", 4);
    if (!hdr_end_u8) return -1;

    size_t header_len = (size_t)(hdr_end_u8 - http_buf);
    size_t body_offset = header_len + 4;
    size_t body_len = http_len - body_offset;

    // RFC 8484 §4.2.1: HTTP 200 OK の検証
    int status_code = parse_http_status_code(http_buf, header_len);
    if (status_code != 200) return -1;

    // RFC 7230 §3.3.3: Transfer-Encoding takes precedence over Content-Length
    bool is_chunked = false;
    for (size_t i = 0; i + 18 <= header_len; i++) {
        if ((i == 0 || http_buf[i - 1] == '\n') &&
            strncasecmp((const char *)http_buf + i, "Transfer-Encoding:", 18) == 0) {
            for (size_t j = i + 18; j + 7 <= header_len; j++) {
                if (http_buf[j] == '\r' || http_buf[j] == '\n') break;
                bool prev_delim = (j == i + 18 || http_buf[j - 1] == ' ' || http_buf[j - 1] == '\t' || http_buf[j - 1] == ',');
                if (prev_delim && strncasecmp((const char *)http_buf + j, "chunked", 7) == 0) {
                    bool next_delim = (j + 7 == header_len || http_buf[j + 7] == ' ' || http_buf[j + 7] == '\t' ||
                                       http_buf[j + 7] == '\r' || http_buf[j + 7] == '\n' || http_buf[j + 7] == ',' ||
                                       http_buf[j + 7] == ';');
                    if (next_delim) {
                        is_chunked = true;
                        break;
                    }
                }
            }
            if (is_chunked) break;
        }
    }

    if (is_chunked) {
        size_t src = body_offset;
        size_t dst = 0;
        bool chunk_complete = false;
        size_t data_off, chunk_len;
        bool is_final = false;
        while (parse_http_chunk(http_buf, http_len, &src, &data_off, &chunk_len, &is_final)) {
            if (is_final) {
                chunk_complete = true;
                break;
            }
            if (data_off > http_len || chunk_len > http_len - data_off) {
                return -1;
            }
            if (dst > resp_cap || chunk_len > resp_cap - dst) {
                return -1;
            }
            if (chunk_len > 0) {
                memcpy(resp + dst, http_buf + data_off, chunk_len);
                dst += chunk_len;
            }
        }
        if (!chunk_complete) return -1;
        return (ssize_t)dst;
    }

    // Content-Length の判定
    size_t cl_val = 0;
    bool found_cl = false;
    for (size_t i = 0; i + 15 <= header_len; i++) {
        if ((i == 0 || http_buf[i - 1] == '\n') &&
            strncasecmp((const char *)http_buf + i, "Content-Length:", 15) == 0) {
            const uint8_t *cur = http_buf + i + 15;
            const uint8_t *end = http_buf + header_len;
            while (cur < end && (*cur == ' ' || *cur == '\t')) cur++;
            size_t val = 0;
            bool has_digits = false;
            while (cur < end && *cur >= '0' && *cur <= '9') {
                if (val > (SIZE_MAX / 10)) { val = SIZE_MAX; break; }
                val = val * 10 + (*cur - '0');
                cur++;
                has_digits = true;
            }
            if (has_digits) {
                while (cur < end && (*cur == ' ' || *cur == '\t')) cur++;
                if (cur < end && *cur != '\r' && *cur != '\n') {
                    return -1; // 不正なContent-Length値
                }
                if (found_cl && cl_val != val) {
                    return -1; // RFC 7230 §3.3.2: 異なるContent-Lengthの重複
                }
                cl_val = val;
                found_cl = true;
            } else {
                return -1; // 数字の無いContent-Lengthヘッダは不正
            }
        }
    }
    if (found_cl) {
        if (cl_val > resp_cap) return -1;
        if (body_len < cl_val) return -1;
        if (cl_val < body_len) body_len = cl_val;
    }

    if (body_len > resp_cap) return -1;
    if (body_offset > http_len || body_len > http_len - body_offset) return -1;
    memcpy(resp, http_buf + body_offset, body_len);
    return (ssize_t)body_len;
}

ssize_t do_doh_exchange(const char *server, int port, const query_opts_t *qo,
                               const uint8_t *pkt, size_t pkt_len,
                               uint8_t *resp, size_t resp_cap, int timeout_sec) {
    int sock = -1;
    SSL *ssl = NULL;
    ssize_t ret_len = -1;

    if (qo && qo->keep_tcp_open) {
        if (g_cached_conn.sock >= 0 && g_cached_conn.is_tls == qo->doh_tls &&
            (!qo->doh_tls || g_cached_conn.ssl) &&
            strcmp(g_cached_conn.server, server) == 0 && g_cached_conn.port == port &&
            g_cached_conn.pref_family == qo->pref_family &&
            strcmp(g_cached_conn.bind_addr, qo->bind_addr) == 0 &&
            g_cached_conn.bind_port == qo->bind_port) {
            sock = g_cached_conn.sock;
            ssl = g_cached_conn.ssl;
            g_last_socket_family = g_cached_conn.family;
        } else {
            close_cached_tcp();
        }
    } else {
        close_cached_tcp();
    }

    if (sock < 0) {
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        set_socket_timeouts(sock, timeout_sec);
        send_proxyv2_if_enabled(sock, qo, true);
        if (qo->doh_tls) {
            ssl = establish_tls(sock, qo, server, port);
            if (!ssl) { close(sock); return -1; }
        }
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = ssl;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = qo->doh_tls;
        }
    }

    const char *path = (qo->doh_path && qo->doh_path[0]) ? qo->doh_path : "/dns-query";
    char req_hdr[16384];
    int req_hdr_len = 0;

    if (qo->doh_method == DOH_GET) {
        char b64_dns[8192];
        size_t b64_needed = ((pkt_len + 2) / 3) * 4 + 1;
        if (b64_needed > sizeof(b64_dns)) {
            fprintf(stderr, ";; Query too large for +https-get (use +https-post or +https instead)\n");
            goto cleanup;
        }
        base64url_encode(pkt, pkt_len, b64_dns, sizeof(b64_dns));
        const char *separator = strchr(path, '?') ? "&" : "?";
        req_hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "GET %s%sdns=%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Accept: application/dns-message\r\n"
            "User-Agent: KariDNS-dag/1.0\r\n"
            "Connection: %s\r\n\r\n",
            path, separator, b64_dns, server, (qo && qo->keep_tcp_open) ? "keep-alive" : "close");
    } else {
        req_hdr_len = snprintf(req_hdr, sizeof(req_hdr),
            "POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/dns-message\r\n"
            "Accept: application/dns-message\r\n"
            "Content-Length: %zu\r\n"
            "User-Agent: KariDNS-dag/1.0\r\n"
            "Connection: %s\r\n\r\n",
            path, server, pkt_len, (qo && qo->keep_tcp_open) ? "keep-alive" : "close");
    }

    if (ssl) {
        if (SSL_write(ssl, req_hdr, req_hdr_len) <= 0) goto cleanup;
        if (qo->doh_method == DOH_POST) {
            if (SSL_write(ssl, pkt, (int)pkt_len) <= 0) goto cleanup;
        }
    } else {
        if (send(sock, req_hdr, req_hdr_len, 0) < 0) goto cleanup;
        if (qo->doh_method == DOH_POST) {
            if (send(sock, pkt, pkt_len, 0) < 0) goto cleanup;
        }
    }

    uint8_t http_buf[65535 + 4096];
    size_t http_len = 0;
    http_buf[0] = '\0';
    bool framing_complete = false;
    while (http_len + 1 < sizeof(http_buf)) {
        int r = 0;
        if (ssl) r = SSL_read(ssl, http_buf + http_len, (int)(sizeof(http_buf) - http_len - 1));
        else r = (int)recv(sock, http_buf + http_len, sizeof(http_buf) - http_len - 1, 0);
        if (r <= 0) break;
        http_len += r;
        http_buf[http_len] = '\0';

        // Content-Length または Transfer-Encoding: chunked を動的にチェックしてループを抜ける
        if (memmem(http_buf, http_len, "\r\n\r\n", 4)) {
            uint8_t *hdr_end = memmem(http_buf, http_len, "\r\n\r\n", 4);
            int status_code = parse_http_status_code(http_buf, (size_t)(hdr_end - http_buf));
            if (status_code > 0 && status_code != 200) {
                framing_complete = true;
                break;
            }
            ret_len = decode_http_response_body(http_buf, http_len, resp, resp_cap);
            if (ret_len >= 0) {
                framing_complete = true;
                break;
            }
        }
    }

    if (http_len < 16) goto cleanup;
    uint8_t *hdr_end_u8 = memmem(http_buf, http_len, "\r\n\r\n", 4);
    if (!hdr_end_u8) goto cleanup;
    size_t header_len = (size_t)(hdr_end_u8 - http_buf);

    // RFC 8484 §4.2.1: HTTP 200 OK の検証
    int status_code = parse_http_status_code(http_buf, header_len);
    if (status_code != 200) {
        if (status_code > 0) {
            fprintf(stderr, ";; DoH server returned HTTP status %d (expected 200 OK)\n", status_code);
        }
        goto cleanup;
    }

    if (ret_len < 0) {
        ret_len = decode_http_response_body(http_buf, http_len, resp, resp_cap);
        if (ret_len < 0) goto cleanup;
    }

cleanup:
    if (ret_len <= 0 || !(qo && qo->keep_tcp_open) || !framing_complete) {
        close_cached_tcp();
        if (!(qo && qo->keep_tcp_open)) {
            if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
            if (sock >= 0) close(sock);
        }
    }
    return ret_len;
}

ssize_t do_tcp_exchange(const char *server, int port, const query_opts_t *qo,
                               const uint8_t *pkt, size_t pkt_len,
                               uint8_t *resp, size_t resp_cap, int timeout_sec) {
    int sock = -1;
    bool reused = false;

    if (qo && qo->keep_tcp_open) {
        if (g_cached_conn.sock >= 0 && !g_cached_conn.is_tls &&
            strcmp(g_cached_conn.server, server) == 0 && g_cached_conn.port == port &&
            g_cached_conn.pref_family == qo->pref_family &&
            strcmp(g_cached_conn.bind_addr, qo->bind_addr) == 0 &&
            g_cached_conn.bind_port == qo->bind_port) {
            sock = g_cached_conn.sock;
            g_last_socket_family = g_cached_conn.family;
            reused = true;
        } else {
            close_cached_tcp();
        }
    } else {
        close_cached_tcp();
    }

    if (sock < 0) {
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        send_proxyv2_if_enabled(sock, qo, true);
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = NULL;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = false;
        }
    }

    set_socket_timeouts(sock, timeout_sec);

    uint16_t prefix_value = (uint16_t)pkt_len;
    uint8_t len_prefix[2] = { (uint8_t)(prefix_value >> 8), (uint8_t)(prefix_value & 0xFF) };

    bool send_ok = (send(sock, len_prefix, 2, 0) == 2 && send(sock, pkt, pkt_len, 0) == (ssize_t)pkt_len);
    if (!send_ok && reused) {
        close_cached_tcp();
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        send_proxyv2_if_enabled(sock, qo, true);
        set_socket_timeouts(sock, timeout_sec);
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = NULL;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = false;
        }
        if (send(sock, len_prefix, 2, 0) != 2 || send(sock, pkt, pkt_len, 0) != (ssize_t)pkt_len) {
            close_cached_tcp();
            return -1;
        }
    } else if (!send_ok) {
        close_cached_tcp();
        return -1;
    }

    ssize_t n = do_tcp_recv_response(sock, resp, resp_cap);
    if (n < 0 && reused) {
        printf(";; communications error to %s#%d: end of file\n", server, port);
        close_cached_tcp();
        sock = connect_tcp(server, port, qo, timeout_sec);
        if (sock < 0) return -1;
        send_proxyv2_if_enabled(sock, qo, true);
        set_socket_timeouts(sock, timeout_sec);
        if (qo && qo->keep_tcp_open) {
            g_cached_conn.sock = sock;
            g_cached_conn.ssl = NULL;
            snprintf(g_cached_conn.server, sizeof(g_cached_conn.server), "%s", server);
            g_cached_conn.port = port;
            g_cached_conn.pref_family = qo->pref_family;
            g_cached_conn.family = g_last_socket_family;
            snprintf(g_cached_conn.bind_addr, sizeof(g_cached_conn.bind_addr), "%s", qo->bind_addr);
            g_cached_conn.bind_port = qo->bind_port;
            g_cached_conn.is_tls = false;
        }
        if (send(sock, len_prefix, 2, 0) == 2 && send(sock, pkt, pkt_len, 0) == (ssize_t)pkt_len) {
            n = do_tcp_recv_response(sock, resp, resp_cap);
        }
    }
    if (n < 0 || !(qo && qo->keep_tcp_open)) {
        close_cached_tcp();
        if (!(qo && qo->keep_tcp_open)) close(sock);
    }
    return n;
}

ssize_t do_dns_exchange_by_transport(const char *server, int port, const query_opts_t *qo,
                                      bool use_tcp, const uint8_t *pkt, size_t pkt_len,
                                      uint8_t *resp, size_t resp_cap, int timeout_sec) {
    if (qo && qo->use_doh) {
        return do_doh_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    } else if (qo && qo->use_tls) {
        return do_tls_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    } else if (use_tcp) {
        return do_tcp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    } else {
        return do_udp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    }
}


ssize_t do_dns_exchange_auto(const char *server, int port, const query_opts_t *qo,
                                     const uint8_t *pkt, size_t pkt_len,
                                     uint8_t *resp, size_t resp_cap, int timeout_sec,
                                     bool force_tcp) {
    if (force_tcp || (qo && (qo->use_doh || qo->use_tls))) {
        return do_dns_exchange_by_transport(server, port, qo, force_tcp, pkt, pkt_len, resp, resp_cap, timeout_sec);
    }
    ssize_t n = do_udp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
    if (n >= 4 && (resp[2] & 0x02) != 0 && (!qo || !qo->ignore_tc)) { // TC bit detected (truncation)
        ssize_t tn = do_tcp_exchange(server, port, qo, pkt, pkt_len, resp, resp_cap, timeout_sec);
        if (tn > 0) return tn;
    }
    return n;
}
