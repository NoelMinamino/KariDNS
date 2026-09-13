#include "dns_dnstap.h"
#include "dns_server_internal.h"

int g_dnstap_sock = -1;
_Atomic bool g_dnstap_connected = ATOMIC_VAR_INIT(false);
_Atomic uint64_t g_dnstap_truncated_total = ATOMIC_VAR_INIT(0);
dnstap_aux_ring_t g_aux_dnstap_ring;

static const char DNSTAP_CONTENT_TYPE[] = "protobuf:dnstap.Dnstap";
static char g_dnstap_identity[256];
static char g_dnstap_version[256];

int dnstap_connect_and_handshake(const char *socket_path, const char *identity, const char *version) {
    if (!socket_path || !*socket_path) return -1;
    if (identity) {
        strncpy(g_dnstap_identity, identity, sizeof(g_dnstap_identity) - 1);
        g_dnstap_identity[sizeof(g_dnstap_identity) - 1] = '\0';
    } else {
        g_dnstap_identity[0] = '\0';
    }
    if (version) {
        strncpy(g_dnstap_version, version, sizeof(g_dnstap_version) - 1);
        g_dnstap_version[sizeof(g_dnstap_version) - 1] = '\0';
    } else {
        g_dnstap_version[0] = '\0';
    }
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, socket_path, sizeof(sun.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        close(sock);
        return -1;
    }

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Send READY frame: escape(4B, 0) + len(4B, 34) + type(4B, 4) + field(4B, 1) + ct_len(4B, 22) + "protobuf:dnstap.Dnstap" (22B)
    uint32_t ct_len = (uint32_t)(sizeof(DNSTAP_CONTENT_TYPE) - 1);
    uint32_t payload_len = 4 + 4 + 4 + ct_len;
    uint32_t ready_hdr[5];
    ready_hdr[0] = htonl(FSTRM_CONTROL_ESCAPE);
    ready_hdr[1] = htonl(payload_len);
    ready_hdr[2] = htonl(FSTRM_CONTROL_READY);
    ready_hdr[3] = htonl(FSTRM_CONTROL_FIELD_CONTENT_TYPE);
    ready_hdr[4] = htonl(ct_len);

    struct iovec r_iov[2];
    r_iov[0].iov_base = ready_hdr;
    r_iov[0].iov_len = sizeof(ready_hdr);
    r_iov[1].iov_base = (void *)DNSTAP_CONTENT_TYPE;
    r_iov[1].iov_len = ct_len;

    if (writev(sock, r_iov, 2) < 0) {
        close(sock);
        return -1;
    }

    // Receive ACCEPT frame
    uint32_t esc = 0, acc_len_be = 0;
    if (recv(sock, &esc, 4, MSG_WAITALL) != 4 || ntohl(esc) != FSTRM_CONTROL_ESCAPE) {
        close(sock);
        return -1;
    }
    if (recv(sock, &acc_len_be, 4, MSG_WAITALL) != 4) {
        close(sock);
        return -1;
    }
    uint32_t acc_len = ntohl(acc_len_be);
    if (acc_len < 4 || acc_len > 1024) {
        close(sock);
        return -1;
    }
    uint8_t acc_buf[1024];
    if (recv(sock, acc_buf, acc_len, MSG_WAITALL) != (ssize_t)acc_len) {
        close(sock);
        return -1;
    }
    uint32_t acc_type = ntohl(*(uint32_t *)acc_buf);
    if (acc_type != FSTRM_CONTROL_ACCEPT) {
        close(sock);
        return -1;
    }

    // Send START frame: escape(4B, 0) + len(4B, 34) + type(4B, 2) + field(4B, 1) + ct_len(4B, 22) + "protobuf:dnstap.Dnstap" (22B)
    uint32_t start_hdr[5];
    start_hdr[0] = htonl(FSTRM_CONTROL_ESCAPE);
    start_hdr[1] = htonl(payload_len);
    start_hdr[2] = htonl(FSTRM_CONTROL_START);
    start_hdr[3] = htonl(FSTRM_CONTROL_FIELD_CONTENT_TYPE);
    start_hdr[4] = htonl(ct_len);

    struct iovec s_iov[2];
    s_iov[0].iov_base = start_hdr;
    s_iov[0].iov_len = sizeof(start_hdr);
    s_iov[1].iov_base = (void *)DNSTAP_CONTENT_TYPE;
    s_iov[1].iov_len = ct_len;

    if (writev(sock, s_iov, 2) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

size_t dnstap_build_message(const dnstap_event_meta_t *meta,
                            const uint8_t *wire, size_t wire_len,
                            uint8_t *out_buf, size_t out_cap) {
    uint8_t msg_buf[65535 + 256];
    size_t msg_offset = 0;

    // Message.type (field 1, required, varint): 1 = AUTH_QUERY, 2 = AUTH_RESPONSE
    msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 1, meta->message_type);

    // Message.socket_family (field 2, varint): 1 = INET, 2 = INET6
    uint32_t fam = (meta->client_addr.ss_family == AF_INET6) ? 2 : 1;
    msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 2, fam);

    // Message.socket_protocol (field 3, varint): 1 = UDP, 2 = TCP
    uint32_t proto = (meta->protocol == IPPROTO_TCP) ? 2 : 1;
    msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 3, proto);

    // Message.query_address (field 4, bytes) & query_port (field 6, varint)
    if (meta->client_addr.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&meta->client_addr;
        msg_offset += pb_encode_bytes_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 4,
                                            (const uint8_t *)&sin->sin_addr, 4);
        msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 6,
                                             ntohs(sin->sin_port));
    } else if (meta->client_addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&meta->client_addr;
        msg_offset += pb_encode_bytes_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 4,
                                            (const uint8_t *)&sin6->sin6_addr, 16);
        msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 6,
                                             ntohs(sin6->sin6_port));
    }

    // Message.response_address (field 5, bytes) & response_port (field 7, varint)
    if (meta->has_server_addr) {
        if (meta->server_addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&meta->server_addr;
            msg_offset += pb_encode_bytes_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 5,
                                                (const uint8_t *)&sin->sin_addr, 4);
            if (sin->sin_port != 0) {
                msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 7,
                                                     ntohs(sin->sin_port));
            }
        } else if (meta->server_addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&meta->server_addr;
            msg_offset += pb_encode_bytes_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 5,
                                                (const uint8_t *)&sin6->sin6_addr, 16);
            if (sin6->sin6_port != 0) {
                msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 7,
                                                     ntohs(sin6->sin6_port));
            }
        }
    }

    if (meta->message_type == 1 /* AUTH_QUERY */) {
        msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 8, (uint64_t)meta->ts.tv_sec);
        msg_offset += pb_encode_fixed32_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 9, (uint32_t)meta->ts.tv_nsec);
        msg_offset += pb_encode_bytes_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 10, wire, wire_len);
    } else { // AUTH_RESPONSE
        msg_offset += pb_encode_varint_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 12, (uint64_t)meta->ts.tv_sec);
        msg_offset += pb_encode_fixed32_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 13, (uint32_t)meta->ts.tv_nsec);
        msg_offset += pb_encode_bytes_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 14, wire, wire_len);
    }

    // Top-level Dnstap: field 1 (identity), field 2 (version), field 15 (type = 1, MESSAGE, required), field 14 (message)
    size_t out_offset = 0;
    if (g_dnstap_identity[0]) {
        out_offset += pb_encode_bytes_field(out_buf + out_offset, out_cap - out_offset, 1,
                                            (const uint8_t *)g_dnstap_identity, strlen(g_dnstap_identity));
    }
    if (g_dnstap_version[0]) {
        out_offset += pb_encode_bytes_field(out_buf + out_offset, out_cap - out_offset, 2,
                                            (const uint8_t *)g_dnstap_version, strlen(g_dnstap_version));
    }
    out_offset += pb_encode_varint_field(out_buf + out_offset, out_cap - out_offset, 15, 1);
    out_offset += pb_encode_bytes_field(out_buf + out_offset, out_cap - out_offset, 14, msg_buf, msg_offset);

    return out_offset;
}

bool dnstap_send_frame(const dnstap_event_meta_t *meta,
                       const uint8_t *wire, size_t wire_len,
                       uint8_t *scratch_buf, size_t scratch_cap) {
    if (g_dnstap_sock < 0) return false;
    size_t plen = dnstap_build_message(meta, wire, wire_len, scratch_buf, scratch_cap);
    if (plen == 0) return true;

    uint32_t be_len = htonl((uint32_t)plen);
    struct iovec iov[2];
    iov[0].iov_base = &be_len;
    iov[0].iov_len = 4;
    iov[1].iov_base = scratch_buf;
    iov[1].iov_len = plen;

    size_t total_written = 0;
    size_t total_to_write = 4 + plen;
    while (total_written < total_to_write) {
        ssize_t w = writev(g_dnstap_sock, iov, 2);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        total_written += w;
        if (total_written < 4) {
            iov[0].iov_base = (uint8_t *)&be_len + total_written;
            iov[0].iov_len = 4 - total_written;
        } else {
            iov[0].iov_len = 0;
            iov[1].iov_base = scratch_buf + (total_written - 4);
            iov[1].iov_len = plen - (total_written - 4);
        }
    }
    return true;
}

void fill_dnstap_event(dnstap_event_meta_t *meta,
                       uint8_t *wire_dst, size_t wire_dst_cap, size_t *out_wire_len,
                       uint8_t message_type,
                       const uint8_t *wire_src, size_t wire_src_len,
                       const struct sockaddr_storage *client_addr,
                       socklen_t client_addr_len,
                       const struct sockaddr_storage *server_addr,
                       bool has_server_addr, uint8_t protocol) {
    clock_gettime(CLOCK_REALTIME, &meta->ts);
    meta->message_type = message_type;
    meta->protocol = protocol;
    if (client_addr) {
        memcpy(&meta->client_addr, client_addr, sizeof(*client_addr));
        meta->client_addr_len = client_addr_len;
    } else {
        memset(&meta->client_addr, 0, sizeof(meta->client_addr));
        meta->client_addr_len = 0;
    }
    meta->has_server_addr = has_server_addr;
    if (has_server_addr && server_addr) {
        memcpy(&meta->server_addr, server_addr, sizeof(*server_addr));
        meta->server_addr_len = sizeof(*server_addr);
    } else {
        memset(&meta->server_addr, 0, sizeof(meta->server_addr));
        meta->server_addr_len = 0;
    }
    size_t copy_len = wire_src_len;
    if (copy_len > wire_dst_cap) {
        copy_len = wire_dst_cap;
        atomic_fetch_add_explicit(&g_dnstap_truncated_total, 1, memory_order_relaxed);
    }
    memcpy(wire_dst, wire_src, copy_len);
    *out_wire_len = copy_len;
}

void write_dnstap_event(worker_ctx_t *ctx, uint8_t message_type,
                        const uint8_t *wire, size_t wire_len,
                        const struct sockaddr_storage *client_addr,
                        socklen_t client_addr_len,
                        const struct sockaddr_storage *server_addr,
                        bool has_server_addr, uint8_t protocol) {
    if (!atomic_load_explicit(&g_dnstap_connected, memory_order_relaxed)) return;

    if (ctx) {
        // Fast path: Worker-local SPSC ring buffer (no locks, no CAS, zero contention)
        dnstap_ring_t *ring = &ctx->dnstap_ring;
        if (!ring->events) return;

        uint32_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
        uint32_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);
        if (h - t >= ring->size) {
            atomic_fetch_add_explicit(&ring->dropped, 1, memory_order_relaxed);
            return;
        }
        dnstap_event_t *ev = &ring->events[h & ring->mask];
        fill_dnstap_event(&ev->meta, ev->wire, sizeof(ev->wire), &ev->wire_len,
                          message_type, wire, wire_len, client_addr, client_addr_len,
                          server_addr, has_server_addr, protocol);
        atomic_store_explicit(&ring->head, h + 1, memory_order_release);
    } else {
        // Aux path: MPSC ring buffer for non-worker threads (AXFR streaming, async I/O)
        if (!g_aux_dnstap_ring.events) return;

        uint32_t h = atomic_load_explicit(&g_aux_dnstap_ring.head, memory_order_relaxed);
        for (;;) {
            // CASのリトライ毎にtailを読み直す。stale tailによる
            // "満杯判定漏れ→未送信スロット上書き" を防止するため、
            // headだけでなくtailも毎回最新値で判定する。
            uint32_t t = atomic_load_explicit(&g_aux_dnstap_ring.tail, memory_order_acquire);
            if (h - t >= g_aux_dnstap_ring.size) {
                atomic_fetch_add_explicit(&g_aux_dnstap_ring.dropped, 1, memory_order_relaxed);
                return;
            }
            if (atomic_compare_exchange_weak_explicit(&g_aux_dnstap_ring.head, &h, h + 1,
                                                       memory_order_acq_rel, memory_order_relaxed)) {
                break; // スロット予約成功。h は予約したインデックス。
            }
            // CAS失敗時、hには最新のhead値が書き戻されるので、次のループでtailを
            // 読み直してから再判定する。
        }

        dnstap_aux_event_t *ev = &g_aux_dnstap_ring.events[h & g_aux_dnstap_ring.mask];
        fill_dnstap_event(&ev->meta, ev->wire, sizeof(ev->wire), &ev->wire_len,
                          message_type, wire, wire_len, client_addr, client_addr_len,
                          server_addr, has_server_addr, protocol);
        atomic_store_explicit(&ev->ready, true, memory_order_release);
    }
}

void *dnstap_sender_thread_func(void *arg) {
    (void)arg;
    static uint8_t g_dnstap_scratch_buf[65535 + 128]; // 送信スレッドは1本のみなので競合しない
    while (1) {
        bool any_work = false;
        int num_workers = g_worker_count;
        worker_ctx_t *workers = g_worker_ctxs;
        if (atomic_load_explicit(&g_dnstap_connected, memory_order_relaxed)) {
            if (num_workers > 0 && workers) {
                for (int w = 0; w < num_workers; w++) {
                    dnstap_ring_t *ring = &workers[w].dnstap_ring;
                    if (!ring->events) continue;
                    uint32_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
                    uint32_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
                    while (t != h) {
                        dnstap_event_t *ev = &ring->events[t & ring->mask];
                        any_work = true;
                        if (!dnstap_send_frame(&ev->meta, ev->wire, ev->wire_len,
                                               g_dnstap_scratch_buf, sizeof(g_dnstap_scratch_buf))) {
                            atomic_store_explicit(&g_dnstap_connected, false, memory_order_release);
                            if (g_dnstap_sock >= 0) {
                                close(g_dnstap_sock);
                                g_dnstap_sock = -1;
                            }
                            syslog(LOG_WARNING, "[dnstap] write failed, disabling dnstap until restart: %s",
                                   strerror(errno));
                            fprintf(stderr, "[dnstap] write failed: %s\n", strerror(errno));
                            break;
                        }
                        t++;
                    }
                    atomic_store_explicit(&ring->tail, t, memory_order_release);
                    if (!atomic_load_explicit(&g_dnstap_connected, memory_order_relaxed)) break;
                }
            }
            if (atomic_load_explicit(&g_dnstap_connected, memory_order_relaxed) && g_aux_dnstap_ring.events) {
                uint32_t t = atomic_load_explicit(&g_aux_dnstap_ring.tail, memory_order_relaxed);
                uint32_t h = atomic_load_explicit(&g_aux_dnstap_ring.head, memory_order_acquire);
                while (t != h) {
                    dnstap_aux_event_t *ev = &g_aux_dnstap_ring.events[t & g_aux_dnstap_ring.mask];
                    if (!atomic_load_explicit(&ev->ready, memory_order_acquire)) {
                        break;
                    }
                    any_work = true;
                    if (!dnstap_send_frame(&ev->meta, ev->wire, ev->wire_len,
                                           g_dnstap_scratch_buf, sizeof(g_dnstap_scratch_buf))) {
                        atomic_store_explicit(&g_dnstap_connected, false, memory_order_release);
                        if (g_dnstap_sock >= 0) {
                            close(g_dnstap_sock);
                            g_dnstap_sock = -1;
                        }
                        syslog(LOG_WARNING, "[dnstap] write failed, disabling dnstap until restart: %s",
                               strerror(errno));
                        fprintf(stderr, "[dnstap] write failed: %s\n", strerror(errno));
                        break;
                    }
                    atomic_store_explicit(&ev->ready, false, memory_order_release);
                    t++;
                }
                atomic_store_explicit(&g_aux_dnstap_ring.tail, t, memory_order_release);
            }
        } else {
            if (num_workers > 0 && workers) {
                for (int w = 0; w < num_workers; w++) {
                    dnstap_ring_t *ring = &workers[w].dnstap_ring;
                    if (!ring->events) continue;
                    uint32_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
                    atomic_store_explicit(&ring->tail, h, memory_order_relaxed);
                }
            }
            if (g_aux_dnstap_ring.events) {
                uint32_t h = atomic_load_explicit(&g_aux_dnstap_ring.head, memory_order_relaxed);
                atomic_store_explicit(&g_aux_dnstap_ring.tail, h, memory_order_relaxed);
            }
        }
        usleep(any_work ? 1000 : 10000);
    }
    return NULL;
}
