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
    // Message.query_zone (field 11): クエリが属するゾーンの名前 (ワイヤ形式)。送信スレッドが
    // 送る直前に埋める (O-03)。0 なら付けない。
    uint16_t query_zone_len;
    uint8_t query_zone[255];
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

// 出力する dnstap Message.type のビットマスク (bit N = type N)。
// dnstap { log-queries; log-responses; } から dnstap_set_message_types() で設定する。
#define DNSTAP_MSG_AUTH_QUERY    1
#define DNSTAP_MSG_AUTH_RESPONSE 2
extern _Atomic uint32_t g_dnstap_message_mask;
void dnstap_set_message_types(bool log_auth_query, bool log_auth_response);
extern dnstap_aux_ring_t g_aux_dnstap_ring;

int dnstap_connect_and_handshake(const char *socket_path, const char *identity, const char *version);

/* O-03: 書き込みに失敗して切断したら、送信スレッドがブローカー経由でこのソケットへ再接続する
 * (1 秒から 60 秒まで間隔を倍にしながら)。起動時に接続を試みた後で呼ぶ。 */
void dnstap_enable_reconnect(const char *socket_path);

/* O-03: 送信スレッドにリングを送り切らせ、STOP を送って FINISH を待たせる (Frame Streams の
 * 双方向プロトコル)。終わるか timeout_ms が過ぎたら戻る。終わっていれば true。 */
#define DNSTAP_SHUTDOWN_WAIT_MS 3000
bool dnstap_shutdown(int timeout_ms);

/* 送信スレッドが送る直前に meta->query_zone を埋める関数を登録する (起動時、main())。
 * 実体は dns_query_engine.c の dnstap_fill_query_zone() (ゾーン DB を引く)。 */
void dnstap_set_zone_filler(void (*fn)(dnstap_event_meta_t *meta, const uint8_t *wire, size_t wire_len));
void dnstap_fill_query_zone(dnstap_event_meta_t *meta, const uint8_t *wire, size_t wire_len);

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
                       const void *client_addr,
                       socklen_t client_addr_len,
                       const void *server_addr,
                       bool has_server_addr, uint8_t protocol);

void write_dnstap_event(worker_ctx_t *ctx, uint8_t message_type,
                        const uint8_t *wire, size_t wire_len,
                        const void *client_addr,
                        socklen_t client_addr_len,
                        const void *server_addr,
                        bool has_server_addr, uint8_t protocol);

void *dnstap_sender_thread_func(void *arg);

#endif /* DNS_DNSTAP_H */
