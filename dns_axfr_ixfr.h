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
  /* tsig_key_t の内容を値コピーして保持 (ポインタ参照排除) */
  bool has_tsig;
  char tsig_name[256];
  char tsig_algorithm[64];
  uint8_t tsig_secret_decoded[256];
  size_t tsig_secret_decoded_len;
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
  char qname[256];
  uint16_t qclass;
  uint16_t qtype;
  bool has_edns;
  bool dnssec_ok;
  uint8_t req[UDP_DEFAULT_MAX_RES_LEN];
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
                     zone_arena_t *standby, zone_arena_t *active,
                     axfr_session_t *session, const char *domain);

int handle_axfr_event(int tcp_fd, zone_db_entry_t *entry,
                      tcp_stream_ctx_t *stream_ctx, axfr_session_t *session,
                      tsig_key_t *tsig_key,
                      const uint8_t *req_mac, size_t req_mac_len);

void *axfr_bg_thread_func(void *arg);

void send_axfr_response(int client_fd, const char *qname __attribute__((unused)), uint8_t *req,
                        uint16_t req_len, tsig_key_t *tsig_key, zone_db_entry_t *entry,
                        uint8_t *req_mac, size_t req_mac_len,
                        const struct sockaddr_storage *client_addr, socklen_t client_len,
                        const struct sockaddr_storage *server_addr, bool has_server_addr);

void *axfr_worker_thread(void *arg);

#endif /* DNS_AXFR_IXFR_H */
