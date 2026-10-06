#include "dns_dnstap.h"
#include "dns_server_internal.h"

#include <sys/capsicum.h>

int g_dnstap_sock = -1;
_Atomic bool g_dnstap_connected = ATOMIC_VAR_INIT(false);
_Atomic uint64_t g_dnstap_truncated_total = ATOMIC_VAR_INIT(0);
_Atomic uint32_t g_dnstap_message_mask =
    ATOMIC_VAR_INIT((1u << DNSTAP_MSG_AUTH_QUERY) | (1u << DNSTAP_MSG_AUTH_RESPONSE));

void dnstap_set_message_types(bool log_auth_query, bool log_auth_response) {
    uint32_t mask = 0;
    if (log_auth_query) mask |= 1u << DNSTAP_MSG_AUTH_QUERY;
    if (log_auth_response) mask |= 1u << DNSTAP_MSG_AUTH_RESPONSE;
    atomic_store_explicit(&g_dnstap_message_mask, mask, memory_order_relaxed);
}
dnstap_aux_ring_t g_aux_dnstap_ring;

static const char DNSTAP_CONTENT_TYPE[] = "protobuf:dnstap.Dnstap";
static char g_dnstap_identity[256];
static char g_dnstap_version[256];
static bool dnstap_handshake(int sock);

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
    return dnstap_handshake(sock) ? sock : -1;
}

/* Frame Streams の双方向ハンドシェイク (READY -> ACCEPT -> START)。失敗したら sock を閉じる。 */
static bool dnstap_handshake(int sock) {
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
        return false;
    }

    // Receive ACCEPT frame
    uint32_t esc = 0, acc_len_be = 0;
    if (recv(sock, &esc, 4, MSG_WAITALL) != 4 || ntohl(esc) != FSTRM_CONTROL_ESCAPE) {
        close(sock);
        return false;
    }
    if (recv(sock, &acc_len_be, 4, MSG_WAITALL) != 4) {
        close(sock);
        return false;
    }
    uint32_t acc_len = ntohl(acc_len_be);
    if (acc_len < 4 || acc_len > 1024) {
        close(sock);
        return false;
    }
    uint8_t acc_buf[1024];
    if (recv(sock, acc_buf, acc_len, MSG_WAITALL) != (ssize_t)acc_len) {
        close(sock);
        return false;
    }
    uint32_t acc_type = ((uint32_t)acc_buf[0] << 24) | ((uint32_t)acc_buf[1] << 16) |
                        ((uint32_t)acc_buf[2] << 8) | (uint32_t)acc_buf[3];
    if (acc_type != FSTRM_CONTROL_ACCEPT) {
        close(sock);
        return false;
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
        return false;
    }

    return true;
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
    // Message.query_zone (field 11, bytes): クエリが属するゾーンのワイヤ形式の名前 (dnstap.proto)
    if (meta->query_zone_len > 0 && meta->query_zone_len <= sizeof(meta->query_zone)) {
        msg_offset += pb_encode_bytes_field(msg_buf + msg_offset, sizeof(msg_buf) - msg_offset, 11,
                                            meta->query_zone, meta->query_zone_len);
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
                       const void *client_addr,
                       socklen_t client_addr_len,
                       const void *server_addr,
                       bool has_server_addr, uint8_t protocol) {
    clock_gettime(CLOCK_REALTIME, &meta->ts);
    meta->message_type = message_type;
    meta->protocol = protocol;
    meta->query_zone_len = 0; /* 送信スレッドが送る直前に埋める (dnstap_set_zone_filler) */
    if (client_addr && client_addr_len > 0) {
        size_t copy_len = client_addr_len < sizeof(meta->client_addr) ? client_addr_len : sizeof(meta->client_addr);
        memcpy(&meta->client_addr, client_addr, copy_len);
        if (copy_len < sizeof(meta->client_addr)) {
            memset((uint8_t *)&meta->client_addr + copy_len, 0, sizeof(meta->client_addr) - copy_len);
        }
        meta->client_addr_len = client_addr_len;
    } else {
        memset(&meta->client_addr, 0, sizeof(meta->client_addr));
        meta->client_addr_len = 0;
    }
    meta->has_server_addr = has_server_addr;
    if (has_server_addr && server_addr) {
        /* server_addr carries no length. TCP callers pass a full sockaddr_storage
         * but the UDP path passes the compact ipc_sockaddr_t (max 28 bytes), so
         * copying sizeof(sockaddr_storage) over-reads the caller's object.
         * Copy only what the address family guarantees to be present. */
        const struct sockaddr *sa = (const struct sockaddr *)server_addr;
        size_t copy_len = (sa->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6)
                                                       : sizeof(struct sockaddr_in);
        memset(&meta->server_addr, 0, sizeof(meta->server_addr));
        memcpy(&meta->server_addr, server_addr, copy_len);
        meta->server_addr_len = (socklen_t)copy_len;
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
                        const void *client_addr,
                        socklen_t client_addr_len,
                        const void *server_addr,
                        bool has_server_addr, uint8_t protocol) {
    if (!atomic_load_explicit(&g_dnstap_connected, memory_order_relaxed)) return;
    if (message_type >= 32 ||
        !(atomic_load_explicit(&g_dnstap_message_mask, memory_order_relaxed) & (1u << message_type))) return;

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

/* O-03: 再接続先 (起動時に設定された socket) と、終了要求の状態 */
static char g_dnstap_reconnect_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
static _Atomic int g_dnstap_stop_state = 0; /* 0 = 稼働, 1 = 終了要求, 2 = 終了済み */

void dnstap_enable_reconnect(const char *socket_path) {
    if (!socket_path) return;
    strlcpy(g_dnstap_reconnect_path, socket_path, sizeof(g_dnstap_reconnect_path));
}

bool dnstap_shutdown(int timeout_ms) {
    int expected = 0;
    atomic_compare_exchange_strong(&g_dnstap_stop_state, &expected, 1);
    for (int waited = 0; waited < timeout_ms; waited += 10) {
        if (atomic_load_explicit(&g_dnstap_stop_state, memory_order_acquire) == 2) return true;
        usleep(10000);
    }
    return atomic_load_explicit(&g_dnstap_stop_state, memory_order_acquire) == 2;
}

static void (*g_dnstap_zone_filler)(dnstap_event_meta_t *, const uint8_t *, size_t);

void dnstap_set_zone_filler(void (*fn)(dnstap_event_meta_t *, const uint8_t *, size_t)) {
    g_dnstap_zone_filler = fn;
}

static void dnstap_fill_zone(dnstap_event_meta_t *meta, const uint8_t *wire, size_t wire_len) {
    meta->query_zone_len = 0;
    if (g_dnstap_zone_filler) g_dnstap_zone_filler(meta, wire, wire_len);
}

/* 書き込みに失敗した接続を閉じる。再接続先があれば後で繋ぎ直す (O-03)。 */
static void dnstap_drop_connection(void) {
    int err = errno;
    atomic_store_explicit(&g_dnstap_connected, false, memory_order_release);
    if (g_dnstap_sock >= 0) {
        close(g_dnstap_sock);
        g_dnstap_sock = -1;
    }
    syslog(LOG_WARNING, "[dnstap] write failed, %s: %s",
           g_dnstap_reconnect_path[0] ? "reconnecting" : "dnstap disabled until restart", strerror(err));
    fprintf(stderr, "[dnstap] write failed: %s\n", strerror(err));
}

/* 全リングの溜まっているイベントを送る。送れなくなったら false (接続は閉じてある)。 */
static bool dnstap_drain_rings(uint8_t *scratch, size_t scratch_cap, bool *any_work) {
    int num_workers = atomic_load_explicit(&g_worker_count, memory_order_acquire);
    worker_ctx_t *workers = atomic_load_explicit(&g_worker_ctxs, memory_order_acquire);
    if (num_workers > 0 && workers) {
        for (int w = 0; w < num_workers; w++) {
            dnstap_ring_t *ring = &workers[w].dnstap_ring;
            if (!ring->events) continue;
            uint32_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
            uint32_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
            bool ok = true;
            while (t != h) {
                dnstap_event_t *ev = &ring->events[t & ring->mask];
                *any_work = true;
                dnstap_fill_zone(&ev->meta, ev->wire, ev->wire_len);
                if (!dnstap_send_frame(&ev->meta, ev->wire, ev->wire_len, scratch, scratch_cap)) {
                    ok = false;
                    break;
                }
                t++;
            }
            atomic_store_explicit(&ring->tail, t, memory_order_release);
            if (!ok) {
                dnstap_drop_connection();
                return false;
            }
        }
    }
    if (g_aux_dnstap_ring.events) {
        uint32_t t = atomic_load_explicit(&g_aux_dnstap_ring.tail, memory_order_relaxed);
        uint32_t h = atomic_load_explicit(&g_aux_dnstap_ring.head, memory_order_acquire);
        bool ok = true;
        while (t != h) {
            dnstap_aux_event_t *ev = &g_aux_dnstap_ring.events[t & g_aux_dnstap_ring.mask];
            if (!atomic_load_explicit(&ev->ready, memory_order_acquire)) {
                break;
            }
            *any_work = true;
            dnstap_fill_zone(&ev->meta, ev->wire, ev->wire_len);
            if (!dnstap_send_frame(&ev->meta, ev->wire, ev->wire_len, scratch, scratch_cap)) {
                ok = false;
                break;
            }
            atomic_store_explicit(&ev->ready, false, memory_order_release);
            t++;
        }
        atomic_store_explicit(&g_aux_dnstap_ring.tail, t, memory_order_release);
        if (!ok) {
            dnstap_drop_connection();
            return false;
        }
    }
    return true;
}

/* 接続していない間に溜まったイベントは捨てる (リングを詰まらせない) */
static void dnstap_discard_rings(void) {
    int num_workers = atomic_load_explicit(&g_worker_count, memory_order_acquire);
    worker_ctx_t *workers = atomic_load_explicit(&g_worker_ctxs, memory_order_acquire);
    if (num_workers > 0 && workers) {
        for (int w = 0; w < num_workers; w++) {
            dnstap_ring_t *ring = &workers[w].dnstap_ring;
            if (!ring->events) continue;
            uint32_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
            atomic_store_explicit(&ring->tail, h, memory_order_release);
        }
    }
    if (g_aux_dnstap_ring.events) {
        uint32_t t = atomic_load_explicit(&g_aux_dnstap_ring.tail, memory_order_relaxed);
        uint32_t h = atomic_load_explicit(&g_aux_dnstap_ring.head, memory_order_acquire);
        /* 書き込み途中のスロットは書き手が後で ready を立てるので、立っているものだけ下ろす */
        while (t != h) {
            dnstap_aux_event_t *ev = &g_aux_dnstap_ring.events[t & g_aux_dnstap_ring.mask];
            if (!atomic_load_explicit(&ev->ready, memory_order_acquire)) break;
            atomic_store_explicit(&ev->ready, false, memory_order_release);
            t++;
        }
        atomic_store_explicit(&g_aux_dnstap_ring.tail, t, memory_order_release);
    }
}

/* Frame Streams の双方向プロトコルの終わり: STOP を送り、受信側の FINISH を待つ
 * (SO_RCVTIMEO はハンドシェイクで 2 秒に設定済み)。 */
static void dnstap_send_stop(int sock) {
    uint32_t stop_frame[3] = { htonl(FSTRM_CONTROL_ESCAPE), htonl(4), htonl(FSTRM_CONTROL_STOP) };
    if (send(sock, stop_frame, sizeof(stop_frame), 0) != (ssize_t)sizeof(stop_frame)) return;
    uint32_t fin[3];
    if (recv(sock, fin, sizeof(fin), MSG_WAITALL) == (ssize_t)sizeof(fin) &&
        ntohl(fin[0]) == FSTRM_CONTROL_ESCAPE && ntohl(fin[1]) == 4 && ntohl(fin[2]) == FSTRM_CONTROL_FINISH) {
        syslog(LOG_NOTICE, "[dnstap] stream closed (STOP/FINISH)");
    } else {
        syslog(LOG_WARNING, "[dnstap] no FINISH from the collector after STOP");
    }
}

/* 起動後の再接続はブローカーに AF_UNIX ソケットを繋がせる (Backend は Capsicum の中で
 * パス名を開けない。Rule 2)。ブローカーは起動時に設定された dnstap ソケットにしか繋がない。 */
static int dnstap_reconnect(void) {
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strlcpy(sun.sun_path, g_dnstap_reconnect_path, sizeof(sun.sun_path));
    tcp_sockopts_t copts = { .connect_timeout_ms = 2000 };
    int sock = broker_connect_opts(AF_UNIX, SOCK_STREAM, (struct sockaddr *)&sun, sizeof(sun), &copts);
    if (sock < 0) return -1;
    if (!dnstap_handshake(sock)) return -1;
    cap_rights_t rights;
    cap_rights_init(&rights, CAP_READ, CAP_RECV, CAP_WRITE, CAP_SEND, CAP_EVENT, CAP_GETSOCKOPT,
                    CAP_SETSOCKOPT, CAP_FCNTL, CAP_SHUTDOWN);
    cap_rights_limit(sock, &rights);
    return sock;
}

static int64_t dnstap_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void *dnstap_sender_thread_func(void *arg) {
    (void)arg;
    static uint8_t g_dnstap_scratch_buf[65535 + 128]; // 送信スレッドは1本のみなので競合しない
    int64_t next_retry_ms = 0;
    int backoff_ms = 1000;
    while (1) {
        bool any_work = false;
        bool connected = atomic_load_explicit(&g_dnstap_connected, memory_order_acquire);
        if (atomic_load_explicit(&g_dnstap_stop_state, memory_order_acquire) == 1) {
            /* O-03: 終了要求。溜まっているイベントを送り切ってから STOP / FINISH */
            if (connected && dnstap_drain_rings(g_dnstap_scratch_buf, sizeof(g_dnstap_scratch_buf), &any_work)) {
                dnstap_send_stop(g_dnstap_sock);
                atomic_store_explicit(&g_dnstap_connected, false, memory_order_release);
                close(g_dnstap_sock);
                g_dnstap_sock = -1;
            }
            atomic_store_explicit(&g_dnstap_stop_state, 2, memory_order_release);
            return NULL;
        }
        if (connected) {
            if (!dnstap_drain_rings(g_dnstap_scratch_buf, sizeof(g_dnstap_scratch_buf), &any_work)) {
                backoff_ms = 1000;
                next_retry_ms = dnstap_now_ms() + backoff_ms;
            }
        } else {
            dnstap_discard_rings();
            /* O-03: 切れた接続はブローカー経由で繋ぎ直す (1 秒から 60 秒まで倍々で間隔を空ける) */
            if (g_dnstap_reconnect_path[0] != '\0' && dnstap_now_ms() >= next_retry_ms) {
                int sock = dnstap_reconnect();
                if (sock >= 0) {
                    g_dnstap_sock = sock;
                    atomic_store_explicit(&g_dnstap_connected, true, memory_order_release);
                    syslog(LOG_NOTICE, "[dnstap] reconnected to %s", g_dnstap_reconnect_path);
                    backoff_ms = 1000;
                } else {
                    next_retry_ms = dnstap_now_ms() + backoff_ms;
                    backoff_ms = backoff_ms >= 30000 ? 60000 : backoff_ms * 2;
                }
            }
        }
        usleep(any_work ? 1000 : 10000);
    }
    return NULL;
}
