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

#if defined(__APPLE__)
/* macOS has no recvmmsg/sendmmsg and no struct mmsghdr. The server itself is
 * FreeBSD-only, but portable modules (e.g. dns_tsig_acl.c, built on macOS for
 * the portable unit tests) include this header for its shared types. */
struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int msg_len;
};
#endif

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

// Frontend/Backendプロセス間のUDPパケット受け渡し用コンパクトソケットアドレス (IPv4: 16B, IPv6: 28B, 8B aligned)
typedef union {
  alignas(8) struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  struct {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    uint8_t ss_len;
    sa_family_t ss_family;
#else
    sa_family_t ss_family;
#endif
  };
} ipc_sockaddr_t;

// Frontend/Backendプロセス間のUDPパケット受け渡し用ヘッダ (80 bytes, 8B aligned)
typedef struct {
  int32_t sock_fd_idx;
  uint16_t addr_len;
  uint16_t payload_len;
  bool has_source_addr;
  uint8_t reserved[7];
  alignas(8) ipc_sockaddr_t client_addr;
  alignas(8) ipc_sockaddr_t source_addr;
} udp_ipc_t;

#define UDP_BATCH_SIZE 16
#define UDP_IPC_PAYLOAD_MAX 65535
#define UDP_IPC_BUFFER_SIZE ((sizeof(udp_ipc_t) + UDP_IPC_PAYLOAD_MAX + 7) & ~7)

// ワーカーローカル用 UDPバッチコンテキスト (ヒープ保持)
typedef struct {
  struct mmsghdr rx_msgs[UDP_BATCH_SIZE];
  struct iovec   rx_iov[UDP_BATCH_SIZE];
  alignas(8) uint8_t rx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];
  struct sockaddr_storage rx_addrs[UDP_BATCH_SIZE];

  struct mmsghdr tx_msgs[UDP_BATCH_SIZE];
  struct iovec   tx_iov[UDP_BATCH_SIZE];
  alignas(8) uint8_t tx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];
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
  alignas(8) uint8_t rx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];
  struct sockaddr_storage rx_addrs[UDP_BATCH_SIZE];
  router_cmsg_buf_t rx_cbuf[UDP_BATCH_SIZE];

  struct mmsghdr ipc_tx_msgs[UDP_BATCH_SIZE];
  struct iovec   ipc_tx_iov[UDP_BATCH_SIZE];

  struct mmsghdr ipc_rx_msgs[UDP_BATCH_SIZE];
  struct iovec   ipc_rx_iov[UDP_BATCH_SIZE];
  alignas(8) uint8_t ipc_rx_buffers[UDP_BATCH_SIZE][UDP_IPC_BUFFER_SIZE];

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
  struct timespec connect_time;
  /* zone-tcp-* の適用状態 (apply_zone_tcp_opts)。0 = 未適用 / 未取得 */
  int applied_mss;
  int applied_rcvbuf;
  int applied_sndbuf;
  int orig_rcvbuf;   /* ゾーン値を当てる前の SO_RCVBUF (未指定ゾーンへ戻すため)。-1 = 取得失敗 */
  int orig_sndbuf;
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
  uint64_t retire_epoch;
} zone_rcu_t;

struct worker_ctx {
  int thread_id;
  int core_id;
  zone_rcu_t *rcu_db;
  qlog_ring_t qlog_ring;
  dnstap_ring_t dnstap_ring;
  alignas(64) _Atomic uint64_t query_count;
  alignas(64) _Atomic uint64_t rcu_observed_epoch;

  time_t log_current_sec;
  uint32_t log_emitted_this_sec;

  udp_batch_ctx_t batch;
};

#include "dns_epoch_rcu.h"

extern _Atomic(worker_ctx_t *) g_worker_ctxs;
extern _Atomic int g_worker_count;

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
  _Atomic uint64_t wirecache_hits;
  _Atomic uint64_t wirecache_misses;
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
  uint64_t retire_epoch;
} zone_db_snapshot_t;

typedef struct {
  _Atomic(server_config_t *) active;
  server_config_t config_a;
  server_config_t config_b;
  uint64_t retire_epoch;
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
  bool disable_auto_tc_flag;
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

server_config_t *acquire_config_snapshot(void);
void release_config_snapshot(server_config_t *snap);
zone_db_snapshot_t *acquire_zone_snapshot(void);
void retain_zone_snapshot(zone_db_snapshot_t *snap);
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

void escape_qname_for_log(const char *src, char *dst, size_t dst_size);
void fast_ipv4_to_str(uint32_t ip_be, char *dst);
uint32_t get_effective_query_log_max_qps(const server_config_t *cfg);
void log_write_rotated(log_channel_t *ch, const char *log_buf, int len, struct tm *tm_info);
void fill_observatory_snapshot(const zone_db_entry_t *e, server_config_t *cfg, zone_observatory_snapshot_t *out);
bool is_zone_synthetic_type(zone_db_snapshot_t *snap, const char *client_ip, const char *qname);
bool ensure_priv_dir_safe(const char *dir_buf);
void init_logging_channels(server_config_t *cfg);
const char *find_configured_domain(const char *arg, char *out_buf, size_t out_size);
void write_query_log(worker_ctx_t *ctx, const void *client_addr, socklen_t addr_len,
                     const char *qname, uint16_t qclass, uint16_t qtype,
                     bool has_edns, bool dnssec_ok, uint8_t protocol, uint32_t max_qps);
void *control_thread_func(void *arg);
void *response_logger_thread_func(void *arg);
void *query_logger_thread_func(void *arg);
void init_async_io_pool(void);
int open_router_udp_sockets(server_config_t *cfg, int out_fds[MAX_BIND_ADDRS], bool out_is_wildcard[MAX_BIND_ADDRS]);
void setup_udp_socket_buffers(int fd, int desired_rcv, int desired_snd);
void apply_tcp_listen_opts(int fd, const server_config_t *cfg, bool verbose);
void apply_tcp_mss(int fd, tcp_stream_ctx_t *c, int mss);
void apply_zone_tcp_opts(int fd, tcp_stream_ctx_t *c, const zone_config_t *zcfg);

#define ASYNC_IO_POOL_SIZE 16
#define ASYNC_IO_QUEUE_CAPACITY 4096

typedef struct {
  bool is_tcp;
  int active_fd; // For UDP, IPC socket to frontend
  int client_fd; // For TCP, client socket
  udp_ipc_t ipc_hdr;
  uint8_t *req_buf;
  size_t req_buf_cap;
  size_t req_len;
  char client_ip[INET6_ADDRSTRLEN];
  int client_port;
  struct sockaddr_storage client_addr;
  socklen_t client_len;
  struct sockaddr_storage server_addr;
  socklen_t server_len;
  bool has_server_addr;
  char qname[256];
  uint16_t qtype;
  uint16_t qclass;
  bool has_edns;
  bool dnssec_ok;
  size_t question_end;
  zone_db_snapshot_t *snap;
} async_io_task_t;

typedef struct {
  async_io_task_t queue[ASYNC_IO_QUEUE_CAPACITY];
  size_t head;
  size_t tail;
  size_t count;
  pthread_mutex_t lock;
  pthread_cond_t cond_not_empty;
  pthread_t threads[ASYNC_IO_POOL_SIZE];
  bool running;
} async_io_pool_t;

extern async_io_pool_t g_async_io_pool;

#ifdef KARIDNS_UNIT_TEST
extern const char *g_config_path;
extern int g_broker_sock;
extern pid_t g_broker_pid;
void start_connect_broker(void);
extern int g_num_workers;
extern int g_num_frontend_routers;
extern int g_ipc_fds[4][128][2];
extern pid_t g_supervisor_pid;
extern int g_pid_fd;
extern char g_pid_file_path[1024];
extern volatile sig_atomic_t g_supervisor_should_exit;
extern volatile sig_atomic_t g_supervisor_got_sighup;
extern volatile sig_atomic_t g_backend_should_exit;

bool enqueue_async_io_task(const async_io_task_t *task);
void *async_io_worker_func(void *arg);
void reload_all_zones(void);
void perform_config_reload(void);
void perform_config_reload_ext(bool skip_unchanged);
void escape_qname_for_log(const char *src, char *dst, size_t dst_size);
void write_query_log(worker_ctx_t *ctx, const void *client_addr, socklen_t addr_len,
                     const char *qname, uint16_t qclass, uint16_t qtype,
                     bool has_edns, bool dnssec_ok, uint8_t protocol,
                     uint32_t max_qps);
void fill_observatory_snapshot(const zone_db_entry_t *e, server_config_t *cfg,
                               zone_observatory_snapshot_t *out);
bool is_zone_synthetic_type(zone_db_snapshot_t *snap, const char *client_ip, const char *qname);
const char *find_configured_domain(const char *arg, char *out_buf, size_t out_size);
void setup_udp_socket_buffers(int fd, int desired_rcv, int desired_snd);
void backend_sig_handler(int sig);
void supervisor_sig_handler(int sig);
void cleanup_pid_file(void);
void daemonize(void);
void setup_ipc_tables(int num_workers);
void run_frontend_router(pid_t backend_pid, int router_id);
void *worker_thread_func(void *arg);
#endif


extern config_rcu_t g_config_db;
extern int g_control_sock;
extern int g_control_kq;
extern time_t g_boot_time;
extern time_t g_last_configured_time;
extern _Atomic int g_tcp_clients;
extern _Atomic int g_tcp_high_water;
extern _Atomic int g_bound_workers;
extern _Atomic bool g_frontend_alive;
extern _Atomic bool g_privilege_drop_complete;
extern _Atomic bool g_qlog_circuit_broken;
extern resp_log_entry_t g_resp_log_ring[RESP_LOG_RING_SIZE];
extern _Atomic uint64_t g_resp_log_tail;
extern _Atomic uint64_t g_resp_log_head;

#endif /* DNS_SERVER_INTERNAL_H */
