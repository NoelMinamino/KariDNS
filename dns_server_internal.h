#ifndef DNS_SERVER_INTERNAL_H
#define DNS_SERVER_INTERNAL_H

#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_zone_parser.h"
#include "dns_config_parser.h"
#include "dns_wire.h"
#include "dns_utils.h"

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/uio.h>

#include "dns_dnstap.h"
#include "dns_edns_ecs.h"
#include "dns_rrl.h"
#include "dns_tsig_acl.h"
#include "dns_priv_sandbox.h"

extern int g_cwd_fd;
extern int g_control_kq;
extern int g_notify_ipc[2];
extern char g_startup_cwd[PATH_MAX];

#define DNS_PORT 53
#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096
#define MAX_BIND_ADDRS 64

#define MAX_IXFR_HISTORY 32
#define MAX_ZONE_AXFR 4
#define MAX_TCP_CLIENTS 1000

// Frontend/Backendプロセス間のUDPパケット受け渡し用ヘッダ
typedef struct {
  int sock_fd_idx;
  socklen_t addr_len;
  struct sockaddr_storage client_addr;
  struct sockaddr_storage source_addr;
  bool has_source_addr;
  uint16_t payload_len;
} udp_ipc_t;

#define UDP_BATCH_SIZE 16
#define UDP_IPC_BUFFER_SIZE (sizeof(udp_ipc_t) + BUFFER_SIZE)

// ワーカーローカル用 UDPバッチコンテキスト (ヒープ保持)
typedef struct {
  struct mmsghdr rx_msgs[UDP_BATCH_SIZE];
  struct iovec   rx_iov[UDP_BATCH_SIZE];
  uint8_t        rx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];
  struct sockaddr_storage rx_addrs[UDP_BATCH_SIZE];

  struct mmsghdr tx_msgs[UDP_BATCH_SIZE];
  struct iovec   tx_iov[UDP_BATCH_SIZE];
  uint8_t        tx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];
} udp_batch_ctx_t;

// Frontend ルーター用 UDP制御メッセージバッファ共用体
#define ROUTER_CMSG_BUF_SIZE 128
typedef union {
  struct cmsghdr cmsg;
  uint8_t buf[ROUTER_CMSG_BUF_SIZE];
} router_cmsg_buf_t;

// Frontend ルーター用 UDPバッチコンテキスト
typedef struct {
  struct mmsghdr rx_msgs[UDP_BATCH_SIZE];
  struct iovec   rx_iov[UDP_BATCH_SIZE];
  uint8_t        rx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];
  struct sockaddr_storage rx_addrs[UDP_BATCH_SIZE];
  router_cmsg_buf_t rx_cbuf[UDP_BATCH_SIZE];

  struct mmsghdr ipc_tx_msgs[UDP_BATCH_SIZE];
  struct iovec   ipc_tx_iov[UDP_BATCH_SIZE];

  struct mmsghdr ipc_rx_msgs[UDP_BATCH_SIZE];
  struct iovec   ipc_rx_iov[UDP_BATCH_SIZE];
  uint8_t        ipc_rx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];

  struct mmsghdr cli_tx_msgs[UDP_BATCH_SIZE];
  struct iovec   cli_tx_iov[UDP_BATCH_SIZE];
  struct sockaddr_storage cli_tx_addrs[UDP_BATCH_SIZE];
  router_cmsg_buf_t cli_tx_cbuf[UDP_BATCH_SIZE];
} frontend_router_ctx_t;

// TCPストリーム解析ステート
typedef enum { TCP_STATE_READ_LEN, TCP_STATE_READ_BODY } tcp_state_t;
typedef struct {
  tcp_state_t state;
  uint8_t buf[65536 + 2];
  size_t accumulated;
  uint16_t msg_len;
  char client_ip[INET6_ADDRSTRLEN];
  struct sockaddr_storage client_addr;
  socklen_t client_len;
  struct sockaddr_storage server_addr;
  socklen_t server_len;
  bool has_server_addr;
  bool quota_yield;
} tcp_stream_ctx_t;

typedef struct {
  bool is_finished;
  bool is_ixfr;
  bool is_deleting;
  int soa_count;
  uint32_t initial_soa_serial;
  uint32_t client_serial;
  char initial_soa_name[256];
  bool is_extended_mode;
  char current_loc_tag[64];
  bool has_current_loc_tag;
  char current_ecs_tag[64];
  bool has_current_ecs_tag;
} axfr_session_t;

// クエリログ用 固定長イベント構造体 (バイナリ保持)
typedef struct {
    struct timespec ts;
    struct sockaddr_storage client_addr;
    socklen_t addr_len;
    uint16_t qtype;
    uint16_t qclass;
    uint8_t  rcode;
    uint8_t  flags;
    uint8_t  protocol; // IPPROTO_UDP or IPPROTO_TCP
    bool     has_edns;
    bool     dnssec_ok;
    char     qname[256];
} qlog_event_t;

// Per-Worker SPSC (Single-Producer Single-Consumer) リングバッファ
typedef struct {
    qlog_event_t *events;
    uint32_t size;
    uint32_t mask;
    alignas(64) _Atomic uint32_t head;
    alignas(64) _Atomic uint32_t tail;
    alignas(64) _Atomic uint64_t dropped_count;
} qlog_ring_t;

typedef struct {
  _Atomic(zone_arena_t *) active;
  zone_arena_t arena_a;
  zone_arena_t arena_b;
} zone_rcu_t;

struct worker_ctx {
  int thread_id;
  int core_id;
  zone_rcu_t *rcu_db;
  qlog_ring_t qlog_ring;
  dnstap_ring_t dnstap_ring;
  alignas(64) _Atomic uint64_t query_count;

  time_t log_current_sec;
  uint32_t log_emitted_this_sec;

  udp_batch_ctx_t batch;
};

extern worker_ctx_t *g_worker_ctxs;
extern int g_worker_count;

typedef struct {
  uint32_t old_serial;
  uint32_t new_serial;
  dns_record_t *deleted;
  int deleted_count;
  dns_record_t *added;
  int added_count;
  _Atomic int ref_count;
  zone_arena_t arena;
} ixfr_txn_t;

typedef struct {
  ixfr_txn_t *entries[MAX_IXFR_HISTORY];
  int head;
  int count;
  pthread_mutex_t lock;
} ixfr_history_t;

typedef struct {
  char unique_id[256];
  char domain[256];
  char **groups;
  int group_count;
  char coo_target[256];
} catalog_member_id_t;

typedef struct {
  _Atomic uint64_t queries_total;
  _Atomic uint64_t responses_noerror;
  _Atomic uint64_t responses_nxdomain;
  _Atomic uint64_t responses_nodata;
  _Atomic uint64_t responses_servfail;
  _Atomic uint64_t responses_refused;
  _Atomic uint64_t tcp_queries;
  _Atomic uint64_t ecs_queries;
  _Atomic uint64_t edns_queries;
  _Atomic uint64_t dnssec_do_queries;
  _Atomic uint64_t rrl_dropped;
  _Atomic uint64_t rrl_slipped;
  _Atomic uint64_t notify_sent;
  _Atomic uint64_t notify_ack;
  _Atomic uint64_t axfr_success;
  _Atomic uint64_t ixfr_success;
  _Atomic time_t   last_transfer_time;
  _Atomic time_t   last_notify_time;
} zone_observatory_t;

typedef struct {
  char domain[256];
  char view_name[64];
  zone_rcu_t rcu;
  pthread_mutex_t writer_lock;
  _Atomic(uint32_t) serial;
  _Atomic(uint32_t) refresh;
  _Atomic(uint32_t) retry;
  _Atomic(uint32_t) expire;
  _Atomic(time_t) next_check;
  _Atomic bool refresh_now;
  _Atomic bool notify_now;
  _Atomic bool is_transferring;
  _Atomic(int) active_axfr;
  _Atomic int snapshot_refs;
  ixfr_history_t ixfr_history;
  zone_observatory_t observatory;
  catalog_member_id_t *catalog_members;
  int catalog_member_count;
  bool is_catalog_member;
  bool is_secondary;
  char catalog_member_unique_id[256];
  char **groups;
  int group_count;
  char cached_master_ip[64];
  int cached_master_port;
  char cached_tsig_key_name[64];
  char owning_catalog_domain[256];
  _Atomic(time_t) last_successful_transfer;
  _Atomic(time_t) last_stale_log_time;
  time_t last_loaded_mtime;
} zone_db_entry_t;

typedef struct {
  char *name;
  char **match_clients;
  int match_clients_count;
  acl_entry_t *match_clients_parsed;
  zone_db_entry_t **entries;
  size_t zone_count;
  int *hash_table;
  int *chain_next;
  size_t hash_size;
  int *suffix_hash_table;
  int *suffix_chain_next;
  size_t suffix_hash_size;
} view_snapshot_t;

typedef struct {
  view_snapshot_t *views;
  size_t view_count;
  _Atomic(int) reader_count;
} zone_db_snapshot_t;

typedef struct {
  _Atomic(server_config_t *) active;
  server_config_t config_a;
  server_config_t config_b;
} config_rcu_t;

extern config_rcu_t g_config_db;

typedef struct {
  char domain[256];
  char old_catalog[256];
  char new_catalog[256];
} pending_coo_t;

typedef struct program_plugin {
  char domain[256];      /* zone_db_entry_t->domain と同じ形式(FQDN, 末尾ドット) */
  pid_t pid;
  int stdin_fd;           /* karidns -> script への書き込み側 */
  int stdout_fd;          /* script -> karidns への読み込み側 */
  pthread_mutex_t lock;    /* 1子プロセスを複数workerから同時に叩かないための直列化 */
  uint32_t timeout_ms;
  uint32_t max_failures;
  _Atomic unsigned int consecutive_failures;
  _Atomic bool dead;        /* max_failures超過、またはexec失敗でtrueになったら以後SERVFAIL固定 */
  char config_fingerprint[512]; /* M-4: reload時の設定変更検知用 */
} program_plugin_t;

extern program_plugin_t *g_program_plugins;
extern int g_program_plugins_count;

#define RESP_LOG_RING_SIZE 8192

typedef enum {
    LOG_ACT_SENT,
    LOG_ACT_DROP_RRL,
    LOG_ACT_DROP_MALFORMED
} log_action_t;

typedef struct {
    _Atomic bool ready;
    struct timespec ts;
    log_action_t action;
    char client_ip[INET6_ADDRSTRLEN];
    int client_port;
    char qname[256];
    uint16_t qclass;
    uint16_t qtype;
    uint8_t rcode;
    bool has_edns;
    bool dnssec_ok;
} resp_log_entry_t;

extern _Atomic int g_xfers_running;

// Shared internal function prototypes
server_config_t *acquire_config_snapshot(void);
void release_config_snapshot(server_config_t *snap);
zone_db_snapshot_t *acquire_zone_snapshot(void);
void release_zone_snapshot(zone_db_snapshot_t *snap);
zone_config_t *find_zone_config_in_view(server_config_t *cfg, const char *view_name, const char *domain);
zone_db_snapshot_t *rebuild_zone_db_snapshot(server_config_t *config,
                                             const char *target_view_name,
                                             zone_db_entry_t *catalog_entry_to_update,
                                             zone_config_t *catalog_cfg,
                                             catalog_member_id_t *new_desired_members,
                                             int new_desired_count);

void wait_for_readers(zone_arena_t *arena);
void clone_zone_arena(zone_arena_t *src, zone_arena_t *dst);
void zone_arena_clear_data_pools(zone_arena_t *arena);
void compute_ixfr_diff(zone_db_entry_t *entry, zone_arena_t *old_arena, zone_arena_t *new_arena);
void free_ixfr_txn(ixfr_txn_t *txn);
zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname);
void prelink_zone_additional_glue(zone_arena_t *current_zone,
                                  const char *zone_domain,
                                  zone_db_snapshot_t *snap,
                                  view_snapshot_t *view,
                                  additional_from_auth_t policy);

int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *msg_len_out);
ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len);
const char *strchr_unescaped(const char *s, char c);
void dec_tcp_clients(void);
void inc_tcp_clients(void);
void submit_response_log(log_action_t action, const char *client_ip, int client_port, const char *qname,
                        uint16_t qclass, uint16_t qtype, uint8_t rcode,
                        bool has_edns, bool dnssec_ok);
int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len);
size_t resolve_ip_port_to_sockaddr(const char *ip, int port, struct sockaddr_storage *out);

#endif /* DNS_SERVER_INTERNAL_H */
