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
#include <strings.h>
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
extern _Atomic int g_control_kq;
extern int g_notify_ipc[2];
extern int g_notify_resp_ipc[2];
extern char g_startup_cwd[PATH_MAX];

#define DNS_PORT 53
#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096
#define MAX_BIND_ADDRS 64

/* IXFR history (RFC 1995 §4): the most diffs one zone keeps. The configured depth (ixfr-history, 0..MAX_IXFR_HISTORY, default
 * IXFR_HISTORY_DEFAULT; dns_config_parser.h) is the number of versions a secondary may lag behind and still get an
 * incremental transfer. */
#define MAX_IXFR_HISTORY IXFR_HISTORY_MAX
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
  /* 次のメッセージを受け取り終えるべき時刻 (CLOCK_MONOTONIC, ms)。accept 時に
   * tcp-initial-timeout、メッセージを1つ受け取り終えるたびに tcp-idle-timeout で決め、
   * メッセージの一部を受け取っても延ばさない (RFC 7766 §6.2.3)。 */
  int64_t idle_deadline_ms;
  /* buf は最後に置く: プールから払い出すときはこの手前までだけを 0 にする (D-04) */
  uint8_t buf[65536 + 2];
} tcp_stream_ctx_t;

/* D-04: 平文 TCP の接続コンテキストは Backend 起動時に MAX_TCP_CLIENTS 個を確保し、
 * ロックフリーのフリーリストで使い回す (accept のたびに calloc しない)。 */
bool tcp_pool_init(void);
tcp_stream_ctx_t *tcp_ctx_alloc(void);
void tcp_ctx_free(tcp_stream_ctx_t *ctx);

/* DNS メッセージを 2 バイトの長さと一緒に1回の sendmsg() で送る (RFC 7766 §8)。
 * 送り切れなければ書き込み可能になるのを待って続ける。戻り値は送ったメッセージ長、失敗時 -1。 */
ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len);

typedef struct {
  bool is_finished;
  bool is_ixfr;
  bool is_deleting;
  int soa_count;
  uint32_t initial_soa_serial;
  uint32_t client_serial;
  char initial_soa_name[256];
  bool is_extended_mode;
  bool has_expire;        /* RFC 7314: 最初の応答に付いていた EXPIRE の値 */
  uint32_t expire;
  char current_loc_tag[64];
  bool has_current_loc_tag;
  char current_ecs_tag[64];
  bool has_current_ecs_tag;
  uint32_t out_of_zone_skipped; /* R-27: 読み飛ばしたゾーン外 RR の数 */
  bool trailing_rrs;      /* AXFR: 終わりの SOA の後ろに同じメッセージの RR が続いていた (取り込み側は拒否する) */
  uint16_t query_id;      /* R-19: 送った要求の ID と QTYPE (xfr_check_response_header() が照合する) */
  uint16_t query_type;
  bool got_first_msg;
  uint8_t rcode;          /* エラーの RCODE で転送が終わったときの値 (0 = エラー応答ではない) */
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

/* S5 B-3: the published version of a zone is a heap zone_version_t (image + glue + flags); a writer builds a new one and
 * publishes it with zone_publish(), the old one goes on the retire stack. Before the first publish `active` is
 * &zone_version_empty. */
typedef struct {
  _Atomic(zone_version_t *) active;
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
  _Atomic bool startup_failed; /* X-33: このワーカーは起動に失敗して終わった (main() が join する) */

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

/* S5 B-3: the ring is allocated on the first stored diff (a zone that never changes after loading pays nothing) with `cap` =
 * the configured depth at that time. A depth change trims the oldest diffs at once (ixfr_history_set_depth) and grows the
 * ring at the next diff. depth_p1 is the configured depth + 1; 0 (a zeroed entry) means IXFR_HISTORY_DEFAULT. */
typedef struct {
  ixfr_txn_t **entries;   /* NULL or `cap` slots: a ring, `count` diffs ending before `head` */
  pthread_mutex_t lock;
  uint8_t cap;
  uint8_t head;
  uint8_t count;
  uint8_t depth_p1;
} ixfr_history_t;

static inline int ixfr_history_depth(const ixfr_history_t *h) {
  return h->depth_p1 ? (int)h->depth_p1 - 1 : IXFR_HISTORY_DEFAULT;
}

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

/* ゾーンの役割。リロードで既存エントリを再利用してよいかの判定に使う (O-13) */
typedef enum {
  ZONE_KIND_OTHER = 0,
  ZONE_KIND_PRIMARY,
  ZONE_KIND_SECONDARY,
  ZONE_KIND_FORWARD,
  ZONE_KIND_PROGRAM,
} zone_kind_t;

static inline zone_kind_t zone_kind_from_type(const char *type) {
  if (!type) return ZONE_KIND_OTHER;
  if (strcasecmp(type, "master") == 0 || strcasecmp(type, "primary") == 0) return ZONE_KIND_PRIMARY;
  if (strcasecmp(type, "slave") == 0 || strcasecmp(type, "secondary") == 0) return ZONE_KIND_SECONDARY;
  if (strcasecmp(type, "forward") == 0) return ZONE_KIND_FORWARD;
  if (strcasecmp(type, "program") == 0) return ZONE_KIND_PROGRAM;
  return ZONE_KIND_OTHER;
}

/* B-3: the primary a catalog member zone is transferred from (copied from the catalog zone's config when the member is added) */
typedef struct {
  char ip[64];
  int port;
  char tsig_key[64];
} catalog_master_t;

/* ゾーンエントリの出どころ (zone_db_entry_t.source)。ZONE_SRC_DB はまだ使われない */
typedef enum {
  ZONE_SRC_CONFIG = 0, /* karidns.conf の zone {} */
  ZONE_SRC_CATALOG,    /* カタログゾーンのメンバー */
  ZONE_SRC_DB,         /* データベースから取り込んだゾーン */
} zone_source_t;

typedef struct {
  char domain[256];
  char view_name[KARIDNS_VIEW_NAME_MAX];
  zone_kind_t kind;
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
  uint8_t source; /* zone_source_t: どこから来たゾーンか。作成時に決まり、変わらない */
  char *catalog_member_unique_id; /* S5: malloc。カタログのメンバーでなければ NULL (読むときは zone_entry_catalog_uid) */
  char **groups;
  int group_count;
  catalog_master_t *catalog_master; /* B-3: malloc, catalog members only (primary and TSIG key of the catalog zone) */
  char *owning_catalog_domain;    /* S5: malloc。同上 (読むときは zone_entry_catalog_owner) */
  /* source == ZONE_SRC_DB のゾーンの設定 (それ以外は NULL)。読むのは zone_entry_config() だけ。
   * 差し替えは新しい物を公開してから、古い物を zone_retire_object() で積む */
  _Atomic(const zone_config_t *) dbcfg;
  _Atomic(time_t) last_successful_transfer;
  /* RFC 7314 §4: セカンダリの expire タイマーが切れる時刻。0 なら
   * last_successful_transfer + expire (従来どおり SOA EXPIRE で数える)。 */
  _Atomic(time_t) expire_at;
  _Atomic(time_t) last_stale_log_time;
  time_t last_loaded_mtime;
  /* 他のゾーンがこのゾーンの名前をグルーに使っている (prelink が印を付ける)。公開時に
   * 制御スレッドへ依存するゾーンのグルーの作り直しを頼む */
  _Atomic bool glue_provider;
  /* エントリごとに一意 (アドレスの再利用と区別する)。グルーの作り直しの判定に使う */
  uint64_t id;
  /* 最後に公開したときの全体の公開カウンタ */
  _Atomic uint64_t publish_order;
} zone_db_entry_t;
/* 制御チャネルで送る統計 (dns_wire.h、karictl も読む) も同じ長さで view 名を持つ */
_Static_assert(sizeof(((zone_observatory_snapshot_t *)0)->view_name) == KARIDNS_VIEW_NAME_MAX,
               "view name buffers must match KARIDNS_VIEW_NAME_MAX");

/* S5: カタログ関連の文字列は非カタログのゾーンでは NULL。比較や表示には空文字列として読む */
static inline const char *zone_entry_catalog_uid(const zone_db_entry_t *e) {
  return e->catalog_member_unique_id ? e->catalog_member_unique_id : "";
}
static inline const char *zone_entry_catalog_owner(const zone_db_entry_t *e) {
  return e->owning_catalog_domain ? e->owning_catalog_domain : "";
}

/* セカンダリゾーンが期限切れになる時刻。期限が無い (プライマリ、未転送) なら 0。 */
static inline time_t zone_expire_deadline(zone_db_entry_t *e) {
  time_t at = atomic_load_explicit(&e->expire_at, memory_order_acquire);
  if (at > 0) return at;
  time_t last_ok = atomic_load_explicit(&e->last_successful_transfer, memory_order_acquire);
  uint32_t expire = atomic_load_explicit(&e->expire, memory_order_acquire);
  if (last_ok > 0 && expire > 0) return last_ok + (time_t)expire;
  return 0;
}

/* RFC 7314 §3: EXPIRE オプションで返す値。プライマリは SOA EXPIRE、セカンダリは
 * expire タイマーの残り秒数 (期限切れなら 0)。 */
static inline uint32_t zone_expire_option_value(zone_db_entry_t *e, time_t now) {
  uint32_t expire = atomic_load_explicit(&e->expire, memory_order_acquire);
  if (!e->is_secondary) return expire;
  time_t deadline = zone_expire_deadline(e);
  if (deadline == 0) return expire;
  if (deadline <= now) return 0;
  time_t left = deadline - now;
  return (left > (time_t)expire && expire > 0) ? expire : (uint32_t)left;
}

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
  bool standby_pending; /* 退いた設定 (standby) がまだ確保されている。制御スレッドだけが読み書きする */
  uint64_t standby_freed;  /* 解放した退いた設定の数 (テスト用の計数) */
} config_rcu_t;

extern config_rcu_t g_config_db;

typedef struct {
  char domain[256];
  char old_catalog[256];
  char new_catalog[256];
} pending_coo_t;

typedef struct program_plugin {
  char domain[256];      /* zone_db_entry_t->domain と同じ形式(FQDN, 末尾ドット) */
  char view_name[KARIDNS_VIEW_NAME_MAX]; /* 同じゾーン名が別の view にもあり得るので view と組で引く (O-12) */
  pid_t pid;
  int proc_fd;            /* FreeBSD: pdfork() のプロセス記述子 (CAP_PDKILL のみ)。-1 = なし。
                           * capability mode では kill(pid) ができないので pdkill() で止める (X-11) */
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
/* 退いた設定 (standby) を、読み手が全員抜けていれば解放する。wait なら最大 10 秒待つ。
 * 解放した (または解放するものが無い) とき true。制御スレッド専用 */
bool config_standby_reap(bool wait);
void release_config_snapshot(server_config_t *snap);
zone_db_snapshot_t *acquire_zone_snapshot(void);
void retain_zone_snapshot(zone_db_snapshot_t *snap);
zone_db_snapshot_t *acquire_retained_zone_snapshot(void);
void release_zone_snapshot(zone_db_snapshot_t *snap);
zone_config_t *find_zone_config_in_view(server_config_t *cfg, const char *view_name, const char *domain);
/* ゾーンエントリの設定。DB のゾーンは entry->dbcfg、それ以外は cfg の索引 (find_zone_config_in_view)。
 * 無ければ NULL。返した物は cfg を保持している間 (DB のゾーンは読み取り区間の中) だけ有効 */
static inline const zone_config_t *zone_entry_config(server_config_t *cfg, const zone_db_entry_t *entry) {
  if (entry->source == ZONE_SRC_DB) return atomic_load_explicit(&entry->dbcfg, memory_order_acquire);
  return find_zone_config_in_view(cfg, entry->view_name, entry->domain);
}
zone_db_snapshot_t *rebuild_zone_db_snapshot(server_config_t *config,
                                             const char *target_view_name,
                                             zone_db_entry_t *catalog_entry_to_update,
                                             const zone_config_t *catalog_cfg,
                                             catalog_member_id_t *new_desired_members,
                                             int new_desired_count);

int thaw_zone_arena(const zone_version_t *src, zone_arena_t *dst);
void zone_arena_clear_data_pools(zone_arena_t *arena);
void compute_ixfr_diff(zone_db_entry_t *entry, const zone_version_t *old_ver, const zone_version_t *new_ver);
void free_ixfr_txn(ixfr_txn_t *txn);
/* B-3: set the IXFR history depth of a zone (0..MAX_IXFR_HISTORY); a lower depth drops the oldest diffs now */
void ixfr_history_set_depth(zone_db_entry_t *entry, int depth);
/* frees the diffs and the ring */
void ixfr_history_clear(ixfr_history_t *h);
zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname);
zone_db_entry_t *find_zone_for_query(view_snapshot_t *view, const char *qname, uint16_t qtype);
zone_db_entry_t *find_zone_exact_in_view(view_snapshot_t *view, const char *domain);
view_snapshot_t *snapshot_find_view(zone_db_snapshot_t *snap, const char *view_name);
zone_db_entry_t *snapshot_get_zone_in_view(zone_db_snapshot_t *snap, const char *view_name, const char *domain);
void zone_glue_track_build(zone_version_t *ver, const char *zone_domain, view_snapshot_t *view,
                           additional_from_auth_t policy);
size_t zone_drop_unencodable_logged(zone_arena_t *a, const char *zone, const char *from);
/* S2: 公開、解放待ちの処理、兄弟ゾーンの変更に伴うグルーの作り直し (dns_snapshot_rcu.c) */
void zone_publish(zone_db_entry_t *entry, zone_version_t *next);
void zone_retire_process(bool wait);
bool zone_retire_object(zone_db_entry_t *entry, void *obj, void (*free_fn)(void *), uint64_t epoch);
/* builder を新しい版として公開する (dns_axfr_ixfr.c)。entry->writer_lock を持って呼ぶ。約束は定義の前の注釈に */
int zone_install_builder(zone_db_entry_t *entry, zone_arena_t *builder, const char *what);
/* 公開直前に呼ぶ: 応答キャッシュに入れてよいか (rcache_ok) を決める。ゾーンの設定は zone_entry_config(cfg, entry)
 * (DB のゾーンは dbcfg)。entry は view_name、domain、source (と DB のゾーンなら dbcfg) だけを読む */
void build_zone_response_cache(zone_version_t *ver, server_config_t *cfg, const zone_db_entry_t *entry);
void zone_glue_refresh_dependents(bool force);
uint64_t zone_entry_next_id(void);

/* ---- DB zone registry and view delta (beta design 4.2, 4.4; implemented in dns_snapshot_rcu.c) ----
 * The registry is the source of truth for which DB zones exist.  Per view (by name) it maps a zone name to
 * {entry, source id, serial, digest, last result, shadowed}.  Everything below takes g_zone_db_rebuild_lock itself
 * (the "_locked" ones expect it to be held); the ingest threads and the full-configuration rebuild are the only
 * writers, queries never touch it.  The registry holds one snapshot_refs reference of each entry it knows; every
 * snapshot that lists the entry holds another.  Callers on aux threads must rcu_aux_thread_pin() first (the
 * commit reads the configuration inside the lock). */
extern pthread_mutex_t g_zone_db_rebuild_lock;

typedef struct dbreg_zone {
  struct dbreg_zone *next;     /* hash chain */
  zone_db_entry_t *entry;      /* NULL: the zone has never been applied (only a rejection is recorded) */
  char *error;                 /* last rejection / loader error, malloc; NULL = none */
  int64_t source_id;
  uint32_t serial;
  uint32_t hash;
  uint8_t digest[32];
  uint8_t last_result;         /* DBREG_APPLIED or DBREG_REJECTED (the last version offered) */
  bool shadowed;               /* a zone of karidns.conf (D-PRIO) or a catalog member (D17-1) with this name hides it */
  uint8_t shadow_by;           /* DBREG_SH_*, meaningful while shadowed */
  char name[];                 /* canonical absolute name, lower case, with the trailing dot */
} dbreg_zone_t;
enum { DBREG_APPLIED = 0, DBREG_REJECTED = 1 };
enum { DBREG_SH_NONE = 0, DBREG_SH_CONFIG = 1, DBREG_SH_CATALOG = 2 };

/* Commit an installed zone.  entry is either a new entry (created = true, the registry takes over its initial
 * reference and the entry is queued to enter the view snapshot, unless a configured zone shadows it) or the entry
 * already registered under name.  *shadowed tells whether a zone of karidns.conf hides it.  0, or -1 (out of
 * memory: the caller keeps ownership of a new entry). */
int dbreg_commit(const char *view, const char *name, zone_db_entry_t *entry, bool created, int64_t source_id,
                 uint32_t serial, const uint8_t digest[32], bool *shadowed);
/* The entry registered for (view, name) or NULL.  Valid while the caller is the only ingest thread working on that
 * name (the ingest thread serializes zones of the same name). */
zone_db_entry_t *dbreg_lookup_entry(const char *view, const char *name);
/* Record that the version offered for (view, name) was rejected (an existing entry keeps serving its last good
 * version; without one only the error is recorded).  false: out of memory. */
bool dbreg_reject(const char *view, const char *name, int64_t source_id, const char *reason);
/* ZONE_DELETE: forget the zone; its entry leaves the view snapshot with the next snapshot_apply_db_delta().  1:
 * removed, 0: not registered or registered with another source id (nothing done). */
int dbreg_delete(const char *view, const char *name, int64_t source_id);
/* Publish the queued additions and removals as one new snapshot (beta design 4.4): per view the entry array is
 * copied without the removed and with the added entries and its hash tables are rebuilt.  The other views are copied
 * too (view_snapshot_t has no reference count to share them by).  Returns the number of entries added plus removed,
 * or -1 (out of memory, the queue is kept). */
int snapshot_apply_db_delta(void);
/* Number of queued changes (cheap, no lock) */
size_t dbreg_pending_count(void);

typedef struct { size_t view, bucket, skip; } dbreg_cursor_t;
/* Walk the registry from *cur; cb returns false to stop (the cursor then points at the zone that was refused).
 * Returns true when the end was reached. */
typedef bool (*dbreg_walk_cb)(void *ud, const char *view, const dbreg_zone_t *z);
bool dbreg_walk(dbreg_cursor_t *cur, dbreg_walk_cb cb, void *ud);
/* counts: zones with an entry (applied+shadowed), rejected-only records and shadowed ones */
void dbreg_counts(size_t *total, size_t *rejected, size_t *shadowed);
/* the same, with the shadowed zones told apart: by a zone of karidns.conf, by a catalog member (D17-1) */
void dbreg_counts2(size_t *total, size_t *rejected, size_t *shadowed_config, size_t *shadowed_catalog);
/* What the registry knows about a zone, copied under the lock (control commands, D17-2). */
typedef struct {
  char view[KARIDNS_VIEW_NAME_MAX];
  int64_t source_id;
  uint32_t serial;             /* the serial of the version served (0 without an entry) */
  uint32_t refresh;            /* SOA refresh of that version */
  bool has_entry;              /* a version was installed */
  bool shadowed;
  uint8_t shadow_by;           /* DBREG_SH_* */
  uint8_t last_result;         /* DBREG_APPLIED / DBREG_REJECTED: the last version offered */
  char error[160];             /* last rejection / loader error, "" = none */
} dbreg_info_t;
/* The registry records of the zone `name` (any case, with or without the trailing dot) in the view `view` (NULL: every
 * view), at most max of them copied to out.  Returns how many there are. */
int dbreg_find_info(const char *view, const char *name, dbreg_info_t *out, int max);
/* The entry of the DB zone (view, name) when it is in the active snapshot, i.e. served (not shadowed), else NULL.  Valid
 * while the caller holds the snapshot (acquire_retained_zone_snapshot()). */
zone_db_entry_t *dbreg_snapshot_entry(zone_db_snapshot_t *snap, const char *view, const char *name);
/* Publish new settings for a DB zone; the old ones are freed after a grace period (zone_retire_object()).  cfg is
 * owned by the entry afterwards (freed with it). */
void db_entry_set_config(zone_db_entry_t *entry, const zone_config_t *cfg);
/* The same in two steps, so that settings can be taken back when the data that came with them is refused: swap publishes
 * cfg and returns the previous block without retiring it; retire hands a block (the previous one, or the one that was
 * taken back) to the S2 retire stack with the epoch swap returned. */
const zone_config_t *db_entry_swap_config(zone_db_entry_t *entry, const zone_config_t *cfg, uint64_t *epoch);
void db_entry_retire_config(zone_db_entry_t *entry, const zone_config_t *old, uint64_t epoch);
/* A zone_config_t for a DB zone: type "master", the zone name, and (B7a) the interned settings `shared` (may be NULL:
 * no options); the zone takes its own reference of shared. */
zone_config_t *db_zone_config_new(const char *domain, zone_ext_shared_t *shared);
/* B7b: kind 0 primary, 1 secondary (a SLAVE), 2 catalog consumer (a CONSUMER) */
zone_config_t *db_zone_config_new_kind(const char *domain, zone_ext_shared_t *shared, int kind);
/* Interned settings of DB zones (B7a, design 4.2).  The key is what makes two settings the same (profile name, profile text,
 * zone text).  find: a new reference of the object with this key, or NULL.  intern: enters `fresh` (refs 1, hash and key
 * set) into the table, or, when an equal object is there already, drops fresh and returns that one; the result carries a
 * reference for the caller.  Unused objects are dropped by a later intern. */
uint64_t db_settings_hash(const char *key, size_t len);
zone_ext_shared_t *db_settings_find(const char *key, size_t len);
zone_ext_shared_t *db_settings_intern(zone_ext_shared_t *fresh);
size_t db_settings_count(void);
void db_settings_reset(void);
/* true once any DB zone's settings carry zone-tcp-mss / zone-tcp-window / zone-tcp-sndbuf (cfg->any_zone_tcp_opts only
 * knows the zones of karidns.conf) */
extern _Atomic bool g_db_zone_tcp_opts;
/* Free every registry record and queued change (unit tests, fuzzers).  Entries lose the registry's reference. */
void dbreg_reset(void);

int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *msg_len_out);
ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len);
const char *strchr_unescaped(const char *s, char c);
void dec_tcp_clients(void);
void inc_tcp_clients(void);
void submit_response_log(log_action_t action, const char *client_ip, int client_port, const char *qname,
                        uint16_t qclass, uint16_t qtype, uint8_t rcode,
                        bool has_edns, bool dnssec_ok);
/* broker_connect_opts() がブローカー側で TCP ソケットへ設定する値 (0 = 未指定)。
 * rcvbuf / sndbuf は connect() 前に設定するので SYN で通知する初期ウィンドウから効く。
 * mss は FreeBSD では未接続ソケットに mssdflt (既定 536) を超える値を設定できないため、
 * connect() 成功後に設定する (送信 MSS を下げる方向のみ)。
 * connect_timeout_ms は接続完了を待つ上限 (0 = BROKER_CONNECT_TIMEOUT_MS)。待つのは
 * 要求側で、ブローカーは非ブロッキングの connect() を始めた fd をすぐに返す (O-04)。 */
typedef struct {
  int mss;
  int rcvbuf;
  int sndbuf;
  int connect_timeout_ms;
} tcp_sockopts_t;
#define BROKER_CONNECT_TIMEOUT_MS 4000

/* ブローカーへの connect 代行要求 (要求側と子プロセスで共有する唯一の定義) */
typedef struct {
  int family;
  int type;
  struct sockaddr_storage addr;
  tcp_sockopts_t tcp_opts;
} broker_req_t;

/* family は AF_INET / AF_INET6、または AF_UNIX (起動時に設定された dnstap ソケットだけ。
 * dnstap の再接続用)。戻り値は接続済みでブロッキングモードの fd、失敗時 -1。 */
int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len);
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts);
size_t resolve_ip_port_to_sockaddr(const char *ip, int port, struct sockaddr_storage *out);

void escape_qname_for_log(const char *src, char *dst, size_t dst_size);
void fast_ipv4_to_str(uint32_t ip_be, char *dst);
uint32_t get_effective_query_log_max_qps(const server_config_t *cfg);
void log_write_rotated(log_channel_t *ch, const char *log_buf, int len, struct tm *tm_info);
void fill_observatory_snapshot(const zone_db_entry_t *e, server_config_t *cfg, zone_observatory_snapshot_t *out);
bool is_zone_synthetic_type(zone_db_snapshot_t *snap, const char *client_ip, const char *qname, uint16_t qtype);
bool ensure_priv_dir_safe(const char *dir_buf);
bool init_logging_channels(server_config_t *cfg);
bool init_logging_channels_ex(server_config_t *cfg, bool hand_off);
void hand_off_logging_channels(server_config_t *cfg);
const char *bind_error_hint(int err, int port);
int parse_cli_port_arg(const char *val, int *port_out);
const char *find_configured_domain(const char *arg, char *out_buf, size_t out_size);
void write_query_log(worker_ctx_t *ctx, const void *client_addr, socklen_t addr_len,
                     const char *qname, uint16_t qclass, uint16_t qtype,
                     bool has_edns, bool dnssec_ok, uint8_t protocol, uint32_t max_qps);
void *control_thread_func(void *arg);
void *response_logger_thread_func(void *arg);
void *query_logger_thread_func(void *arg);
bool init_async_io_pool(void);
int open_router_udp_sockets(server_config_t *cfg, int out_fds[MAX_BIND_ADDRS], bool out_is_wildcard[MAX_BIND_ADDRS]);
void setup_udp_socket_buffers(int fd, int desired_rcv, int desired_snd);
void apply_tcp_listen_opts(int fd, const server_config_t *cfg, bool verbose);
void apply_tcp_mss(int fd, tcp_stream_ctx_t *c, int mss);
tcp_sockopts_t xfr_tcp_sockopts(const server_config_t *cfg, const zone_config_t *zcfg);
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
  char qname[DNS_NAME_TEXT_SIZE];
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

/* D-13 / O-05: 設定の再読み込みの結果。karictl reload / reconfig の応答に使う */
typedef enum {
  CONFIG_RELOAD_OK = 0,
  CONFIG_RELOAD_ZONE_ERRORS, /* 設定は反映した。zones_failed 個のゾーンが読み込めなかった */
  CONFIG_RELOAD_READ_ERROR,  /* 設定ファイルを読めない。反映していない */
  CONFIG_RELOAD_PARSE_ERROR, /* 設定の誤り。反映していない */
  CONFIG_RELOAD_REJECTED,    /* 設定は正しいが適用できない (detail に理由)。反映していない */
  CONFIG_RELOAD_POSTPONED    /* 前の設定の読み手が残っている。制御スレッドが後で再試行する */
} config_reload_status_t;

typedef struct {
  config_reload_status_t status;
  int zones_failed;
  char detail[384];         /* 失敗したゾーン名、または拒否の理由 */
  char restart_needed[192]; /* O-09: 変わったが再起動まで反映されない設定 ("port, bind-address") */
} config_reload_result_t;

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
extern _Atomic int g_backend_should_exit;

bool enqueue_async_io_task(const async_io_task_t *task);
void *async_io_worker_func(void *arg);
config_reload_result_t reload_all_zones(void);
config_reload_result_t perform_config_reload(void);
config_reload_result_t perform_config_reload_ext(bool skip_unchanged);
void escape_qname_for_log(const char *src, char *dst, size_t dst_size);
void write_query_log(worker_ctx_t *ctx, const void *client_addr, socklen_t addr_len,
                     const char *qname, uint16_t qclass, uint16_t qtype,
                     bool has_edns, bool dnssec_ok, uint8_t protocol,
                     uint32_t max_qps);
void fill_observatory_snapshot(const zone_db_entry_t *e, server_config_t *cfg,
                               zone_observatory_snapshot_t *out);
bool is_zone_synthetic_type(zone_db_snapshot_t *snap, const char *client_ip, const char *qname, uint16_t qtype);
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
extern _Atomic int g_control_kq;
extern time_t g_boot_time;
extern time_t g_last_configured_time;
extern _Atomic int g_tcp_clients;
extern _Atomic int g_tcp_high_water;
extern _Atomic int g_bound_workers;
extern _Atomic bool g_frontend_alive;
extern _Atomic bool g_privilege_drop_complete;
/* Backend の通常の終了 (dnstap の STOP/FINISH の後に _exit)。O-03 / O-15 */
__attribute__((noreturn)) void backend_shutdown(int code);
extern _Atomic bool g_qlog_circuit_broken;
extern resp_log_entry_t g_resp_log_ring[RESP_LOG_RING_SIZE];
extern _Atomic uint64_t g_resp_log_tail;
extern _Atomic uint64_t g_resp_log_head;

#endif /* DNS_SERVER_INTERNAL_H */
