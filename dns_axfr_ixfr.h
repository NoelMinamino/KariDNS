#ifndef DNS_AXFR_IXFR_H
#define DNS_AXFR_IXFR_H

#include "dns_server_internal.h"
#include "dns_tsig_acl.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* axfr_bg_thread_func は detached スレッドとして動作するため、
 * 引数 ctx 以外のヒープ・スタック構造体へのアクセスを避け、
 * tsig_key_t など呼び出し元のメモリを直接参照しないように
 * ポインタ参照を一切排除する。*/
typedef struct {
  char master_ip[64];
  int master_port;
  char domain[256];
  zone_db_entry_t *entry;
  zone_db_snapshot_t *snap;
  /* tsig_key_t の内容を値コピーして保持 (ポインタ参照排除) */
  bool has_tsig;
  char tsig_name[256];
  char tsig_algorithm[64];
  uint8_t tsig_secret_decoded[256];
  size_t tsig_secret_decoded_len;
  /* マスターへの TCP 接続に使う zone-tcp-* / tcp-* (xfr_tcp_sockopts()) */
  tcp_sockopts_t tcp_opts;
} axfr_bg_ctx_t;

typedef struct {
  int client_fd;
  char client_ip[INET6_ADDRSTRLEN];
  int client_port;
  struct sockaddr_storage client_addr;
  socklen_t client_len;
  struct sockaddr_storage server_addr;
  socklen_t server_len;
  bool has_server_addr;
  char qname[DNS_NAME_TEXT_SIZE];
  uint16_t qclass;
  uint16_t qtype;
  bool has_edns;
  bool dnssec_ok;
  uint8_t req[BUFFER_SIZE];
  uint16_t req_len;
  bool has_tsig;
  char tsig_name[256];
  char tsig_algorithm[64];
  uint8_t tsig_secret_decoded[256];
  size_t tsig_secret_decoded_len;
  uint8_t tsig_mac[64]; /* >= EVP_MAX_MD_SIZE */
  size_t tsig_mac_len;
  zone_db_entry_t *entry;
  zone_db_snapshot_t *snap;
} axfr_worker_args_t;

int parse_xfr_packet(const uint8_t *packet, size_t packet_len,
                     zone_arena_t *standby, const zone_version_t *active,
                     axfr_session_t *session, const char *domain);
/* R-19: 転送応答の1通のヘッダーと質問を session->query_id / query_type / domain と照合する
 * (RFC 5936 §2.2.1、§2.2.2)。0 = 問題なし、-1 = 応答として受け付けない (ログ済み)、
 * 1 = エラーの RCODE (session->rcode に設定、ログ済み)。 */
int xfr_check_response_header(const uint8_t *msg, size_t msg_len, axfr_session_t *session, const char *domain);

int handle_axfr_event(int tcp_fd, zone_db_entry_t *entry,
                      tcp_stream_ctx_t *stream_ctx, axfr_session_t *session,
                      tsig_key_t *tsig_key,
                      const uint8_t *req_mac, size_t req_mac_len);

/* RFC 7314 §4: 転送 / 最新確認の結果からセカンダリの expire タイマー期限を決める (0 = SOA EXPIRE で数える) */
time_t xfr_expire_deadline(bool transferred, bool has_expire, uint32_t expire_opt,
                           uint32_t soa_expire, time_t cur_deadline, time_t now);

/* B8t-2: which Extended AXFR version a primary speaks, as a secondary learns it (kept per zone, in memory).  The secondary asks for
 * version 3; a standard transfer in answer may come from a primary that speaks version 2 only (it ignores a version it does not know), so
 * the transfer is asked again with version 2 (no SOA_SET, no settings, as before) and the result is remembered: XFR_EXT_V2 = version 2,
 * XFR_EXT_STANDARD = no extension at all (asked with version 3, accepted as it comes, no second request).  Both are forgotten after
 * XFR_EXT_REPROBE_SECS, so an upgraded primary is found; XFR_EXT_V3 and XFR_EXT_UNKNOWN ask for version 3 and fall back when the answer
 * is a standard transfer. */
enum { XFR_EXT_UNKNOWN = 0, XFR_EXT_STANDARD = 1, XFR_EXT_V2 = 2, XFR_EXT_V3 = 3 };
#define XFR_EXT_REPROBE_SECS (6 * 3600)
uint8_t xfr_ext_effective(uint8_t state, time_t set_at, time_t now);   /* the state to act on: STANDARD and V2 expire to UNKNOWN */
uint8_t xfr_ext_request_version(uint8_t state);                        /* 2 for V2, else 3 */
bool xfr_ext_probe(uint8_t state);                                      /* may a standard answer to version 3 mean "ask with version 2"? */
uint8_t xfr_ext_learn(bool answered_extended, uint8_t answered_version); /* the state after a transfer that finished */

void *axfr_bg_thread_func(void *arg);

void send_axfr_response(int client_fd, const char *qname __attribute__((unused)), uint8_t *req,
                        uint16_t req_len, tsig_key_t *tsig_key, zone_db_entry_t *entry,
                        uint8_t *req_mac, size_t req_mac_len,
                        const struct sockaddr_storage *client_addr, socklen_t client_len,
                        const struct sockaddr_storage *server_addr, bool has_server_addr);

void *axfr_worker_thread(void *arg);

bool wait_for_active_axfr(zone_db_entry_t *entry, int timeout_ms);

#endif /* DNS_AXFR_IXFR_H */
