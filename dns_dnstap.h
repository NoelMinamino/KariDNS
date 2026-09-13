#ifndef DNS_DNSTAP_H
#define DNS_DNSTAP_H

#include <stdint.h>
#include <stdbool.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#include "dns_wire.h"

#define FSTRM_CONTROL_ESCAPE               0x00000000U
#define FSTRM_CONTROL_ACCEPT               0x00000001U
#define FSTRM_CONTROL_START                0x00000002U
#define FSTRM_CONTROL_STOP                 0x00000003U
#define FSTRM_CONTROL_READY                0x00000004U
#define FSTRM_CONTROL_FINISH               0x00000005U
#define FSTRM_CONTROL_FIELD_CONTENT_TYPE   0x00000001U

// dnstapイベントの共通メタデータ部分。wireバッファのサイズに依存しないため、
// worker用リング(dnstap_event_t)とaux用リング(dnstap_aux_event_t)の双方で共有する。
typedef struct {
    struct timespec ts;
    uint8_t message_type;   // 1 = AUTH_QUERY, 2 = AUTH_RESPONSE
    uint8_t protocol;       // IPPROTO_UDP or IPPROTO_TCP
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    struct sockaddr_storage server_addr;
    socklen_t server_addr_len;
    bool has_server_addr;
} dnstap_event_meta_t;

// dnstap用イベント: UDPワーカーのSPSCリング専用。
typedef struct {
    dnstap_event_meta_t meta;
    size_t wire_len;
    uint8_t wire[UDP_DEFAULT_MAX_RES_LEN > 4096 ? UDP_DEFAULT_MAX_RES_LEN : 4096];
} dnstap_event_t;

typedef struct {
    dnstap_event_t *events;
    uint32_t size;
    uint32_t mask;
    alignas(64) _Atomic uint32_t head;
    alignas(64) _Atomic uint32_t tail;
    alignas(64) _Atomic uint64_t dropped;
} dnstap_ring_t;

// dnstap用イベント: AXFR/非同期I/Oスレッド用のMPSC aux リング専用。
typedef struct {
    dnstap_event_meta_t meta;
    size_t wire_len;
    uint8_t wire[65535];
    alignas(8) _Atomic bool ready;
} dnstap_aux_event_t;

typedef struct {
    dnstap_aux_event_t *events;
    uint32_t size;
    uint32_t mask;
    alignas(64) _Atomic uint32_t head;
    alignas(64) _Atomic uint32_t tail;
    alignas(64) _Atomic uint64_t dropped;
} dnstap_aux_ring_t;

// Forward declaration of worker_ctx_t
struct worker_ctx;
typedef struct worker_ctx worker_ctx_t;

extern int g_dnstap_sock;
extern _Atomic bool g_dnstap_connected;
extern _Atomic uint64_t g_dnstap_truncated_total;
extern dnstap_aux_ring_t g_aux_dnstap_ring;

int dnstap_connect_and_handshake(const char *socket_path, const char *identity, const char *version);

size_t dnstap_build_message(const dnstap_event_meta_t *meta,
                            const uint8_t *wire, size_t wire_len,
                            uint8_t *out_buf, size_t out_cap);

bool dnstap_send_frame(const dnstap_event_meta_t *meta,
                       const uint8_t *wire, size_t wire_len,
                       uint8_t *scratch_buf, size_t scratch_cap);

void fill_dnstap_event(dnstap_event_meta_t *meta,
                       uint8_t *wire_dst, size_t wire_dst_cap, size_t *out_wire_len,
                       uint8_t message_type,
                       const uint8_t *wire_src, size_t wire_src_len,
                       const struct sockaddr_storage *client_addr,
                       socklen_t client_addr_len,
                       const struct sockaddr_storage *server_addr,
                       bool has_server_addr, uint8_t protocol);

void write_dnstap_event(worker_ctx_t *ctx, uint8_t message_type,
                        const uint8_t *wire, size_t wire_len,
                        const struct sockaddr_storage *client_addr,
                        socklen_t client_addr_len,
                        const struct sockaddr_storage *server_addr,
                        bool has_server_addr, uint8_t protocol);

void *dnstap_sender_thread_func(void *arg);

#endif /* DNS_DNSTAP_H */
