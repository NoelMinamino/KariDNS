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
  /* D1a milestone 2, a request parked for a zone that is not in memory (dns_park.h): the request stays in buf; the connection's read events are
   * ignored while it waits (parked); a wake-up sets resume_pending and starts a short timer, whose event runs the request again from the
   * top of the connection loop, where resume_len says "the message in buf is the one to answer" */
  bool parked, resume_pending, not_ready_now;
  uint16_t resume_len;
  int64_t park_deadline_ms;         /* of the request that was parked first (0: none); a second park of the same request keeps it */
  /* buf は最後に置く: プールから払い出すときはこの手前までだけを 0 にする (D-04) */
  uint8_t buf[65536 + 2];
  uint32_t gen;                     /* changes every time the context is given out (after buf: not cleared); a parked entry names (slot, gen) */
} tcp_stream_ctx_t;

/* D-04: 平文 TCP の接続コンテキストは Backend 起動時に MAX_TCP_CLIENTS 個を確保し、
 * ロックフリーのフリーリストで使い回す (accept のたびに calloc しない)。 */
bool tcp_pool_init(void);
tcp_stream_ctx_t *tcp_ctx_alloc(void);
void tcp_ctx_free(tcp_stream_ctx_t *ctx);

/* DNS メッセージを 2 バイトの長さと一緒に1回の sendmsg() で送る (RFC 7766 §8)。
 * 送り切れなければ書き込み可能になるのを待って続ける。戻り値は送ったメッセージ長、失敗時 -1。 */
ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len);
/* max-transfer-time-out / max-transfer-idle-out of the outbound AXFR/IXFR this thread serves (0 = none); defined in dns_axfr_ixfr.c */
extern _Thread_local time_t g_tcp_send_deadline_secs;
extern _Thread_local uint32_t g_tcp_send_idle_secs;

typedef struct {
  bool is_finished;
  bool is_ixfr;
  bool is_deleting;
  int soa_count;
  uint32_t initial_soa_serial;
  uint32_t client_serial;
  /* I1 (RFC 1995 §4): the serial the next deletion sequence must start from: the client's serial for the first
   * sequence, then the serial of the SOA that ended the previous (addition) sequence */
  uint32_t ixfr_expected_serial;
  bool ixfr_bad_sequence;   /* the IXFR did not start from our serial or the sequences did not chain: ask for an AXFR */
  /* I2: the limits of one inbound transfer (0 = none; xfr_attempt() sets them from the zone / options): the RRs of the
   * zone being built and the octets of the messages read (the unsigned messages kept for TSIG are among them) */
  uint64_t max_records;
  uint64_t max_bytes;
  uint64_t tagdef_cidrs;    /* I3: CIDRs read in LOC_TAGDEF / ECS_TAGDEF records so far (XFR_TAGDEF_CIDR_MAX) */
  int loc_tagdef_cap, ecs_tagdef_cap; /* I3: the capacity of the builder's tag arrays (unpack_tag_def_rdata() grows them geometrically) */
  /* I4: an escaped apex name can take up to DNS_NAME_TEXT_SIZE - 1 characters in text form */
  char initial_soa_name[DNS_NAME_TEXT_SIZE];
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
  uint64_t ext_records;   /* B8: number of Extended AXFR marker / definition RRs (65401-65405, 65407) read: they count as RRs but are not kept, so the database loader's declared count is checked against them */
  uint64_t ext_wrapped;   /* B8: TINYDNS_WRAP (65406) records read; each is a normal RR in the zone (already in the RR count) */
  uint8_t ext_version;    /* B8t-2: the Extended AXFR version of the stream (2 or 3) the primary answered with; 0 = not extended */
  bool soa_set;           /* B8t-2 (v3): SOA_SET (TYPE 65409) was read: the opening and closing SOA is not zone data, and the apex SOA RRs follow as wrappers */
  uint32_t soa_set_expected, soa_set_seen; /* the number of body SOA RRs SOA_SET announced, and read */
  bool frame_valid;       /* soa_set: the numbers of the frame SOA (the reference SOA) that was not stored */
  uint32_t frame_refresh, frame_retry, frame_expire;
  bool has_settings;      /* B8t-2 (v3): a SETTINGS record (TYPE 65408) was read; its text is in settings_text */
  char settings_text[KARIDNS_SETTINGS_MAX + 1]; /* NUL terminated; not in the transfer's arena: an IXFR rebuilds the arena after the SETTINGS record */
  size_t settings_len;
  bool ext_probe;         /* B8t-2: version 3 was asked for and a standard answer means "try version 2" (xfr_ext_probe()) */
  bool no_ext_answer;     /* set when handle_axfr_event() stopped for that reason */
  bool db_stream;         /* B8: the messages come from the database loader (ZONE_DATA): the Extended AXFR records are checked strictly (a malformed definition, state or wrapper record rejects the zone) and ECS_TRUSTED (65407) is refused: the trusted resolvers come from the settings text only, inside acl-ceiling */
  /* batch 4 (BIND 9.20 zone.c refresh_callback(), zone_xfrdone()) */
  bool serial_behind;     /* the primary's serial is older than ours: "serial number received from primary < ours" -- not a failure, the next primary is asked */
  const xfr_eff_t *eff;   /* the transfer / timer options of the zone (NULL: the SOA timers are stored as received, no time limit) */
  time_t deadline;        /* max-transfer-time-in: the time at which the transfer is given up (0 = none) */
  uint32_t idle_secs;     /* max-transfer-idle-in: the longest wait for the next message (0 = none) */
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

/* D1a milestone 2: what one pass over a batch of UDP requests needs besides the request (udp_one() in dns_server_core.c): the worker's state, and
 * how a request that was parked comes back (the park table is dns_park.h's) */
struct park_table;
typedef struct {
  worker_ctx_t *ctx;
  udp_batch_ctx_t *batch;
  compress_ctx_t *cc;
  int active_fd;
  int n_tx;                          /* answers in the batch of datagrams to send */
  bool qlog_enabled, rlog_enabled, blackhole_on;
  uint32_t eff_max_qps;
  /* parking (park == NULL: this worker never parks) */
  struct park_table *park;
  int worker_idx;
  uint32_t park_timeout_ms;
  bool woken;                        /* this request was parked before: its deadline is the old one, and it asks no fetch again */
  int64_t woken_deadline_ms;
  bool not_ready;                    /* answer SERVFAIL + EDE 14 (the time is up, or the fetch failed) */
} udp_pass_t;

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
  size_t bytes;       /* D1a (8.1): what the difference holds; counted in the zone memory totals while it is in a history (acct) */
  int8_t acct;        /* 0 = not counted, else 1 + the ZBYTES_* class it was counted in */
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

/* B-3: the primary a catalog member zone is transferred from (copied from the catalog zone's config when the member is added).  The two keys are
 * kept apart so that the precedence of batch 5 holds here too (peer_key_name()): `key` (written on the primaries element), then the key of the
 * `server` statement that covers the primary, then `zone_key` (the catalog zone's tsig-key).  port 0 = options { port } (config_target_port()). */
typedef struct {
  char ip[64];
  int port;
  char key[64];
  char zone_key[64];
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
  time_t notify_next;             /* notify-delay: the time before which the next set of NOTIFY messages for the zone is not sent (the control thread only) */
  _Atomic bool is_transferring;
  _Atomic(int) active_axfr;
  _Atomic int snapshot_refs;
  ixfr_history_t ixfr_history;
  size_t evicted_bytes;           /* D1a step 5: the bytes of the version served that were moved to the retired total when the zone was evicted (0: not evicted) */
  bool evicted;                   /* the zone was taken out of memory (set under writer_lock): a writer that waited for the lock must not change this entry, the change would be lost */
  bool updated;                   /* a dynamic UPDATE changed this DB zone since it was read from the database (set under writer_lock): it is not taken out of memory, the change would be lost; the next install from the database clears it */
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
  /* B8t-2: the settings the primary sent with the zone (Extended AXFR v3).  rxcfg is the zone configuration in force: a copy of the
   * zone's own block (karidns.conf zone {}, or dbcfg) in which the statements the secondary did not write itself come from the
   * received settings (zone_config_with_received()); NULL = no received settings in force.  Read by zone_entry_config(); replaced
   * through the S2 retire stack.  rx_sh (the parsed text), rx_base, rx_gen and rx_note belong to the writers (entry->writer_lock) */
  uint8_t xfr_ext_state;          /* B8t-2: what the primary speaks (XFR_EXT_*, dns_axfr_ixfr.h); written by the transfer thread only */
  time_t xfr_ext_set;             /* when it was learned */
  _Atomic(const zone_config_t *) rxcfg;
  zone_ext_shared_t *rx_sh;
  _Atomic bool rx_present;        /* rx_sh != NULL (read without the lock by the control thread's tick) */
  const zone_config_t *rx_base;   /* the block rxcfg was made from (compared, never dereferenced) */
  uint64_t rx_gen;                /* server_config_t.generation of that merge */
  char rx_note[160];              /* why part of the received settings is not in force ("" = all of it is) */
  _Atomic(time_t) last_successful_transfer;
  /* RFC 7314 §4: セカンダリの expire タイマーが切れる時刻。0 なら
   * last_successful_transfer + expire (従来どおり SOA EXPIRE で数える)。 */
  _Atomic(time_t) expire_at;
  _Atomic(time_t) last_stale_log_time;
  time_t last_loaded_mtime;
  off_t last_loaded_size;        /* with the mtime: a reload re-reads a file only when one of them changed (reload_master_zone()) */
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

/* ---- The zone directory (D1a, design 3.1, 3.2) ----
 * Every view has one directory: the list of the zones it can answer for, one element per zone name.  An element is the
 * DB zone registry's record of a zone (dbreg_zone_t is the same type), and the zones that do not come from the database
 * (zone { } blocks, catalog members, zones shared with another view by `in-view`) have elements too, as directory-owned,
 * always resident ones, so one index serves all of them.  The index of a view (find_zone_in_view() and its relatives) is an
 * open-addressing table of element pointers (zdir_tab_t); it is looked at without a lock, in an RCU read section or on a
 * retained snapshot, and changed in place by the writers (the ingest threads, a rebuild of the snapshot), who hold
 * g_zone_db_rebuild_lock and publish a new snapshot (a thin copy: names, match-clients and a reference of each directory)
 * after every change.  A directory is shared by the snapshots that follow each other until the configuration changes the
 * set of zones; a rebuild of that kind builds new directories.
 *
 * What a reader may rely on: a pointer it got from a lookup (an element, an entry) stays valid until it leaves its read
 * section or releases its retained snapshot.  What a writer takes out of an index (an element, a table that was replaced by a
 * bigger one, a tick list, a reference of an entry) goes on the garbage list of the snapshot that is retired by the next
 * publish, and is released when that snapshot and every older one are drained (see gc_snapshot_thread()).
 *
 * The entry of an element is read with zdir_entry().  In this milestone every element is resident, so it is never NULL
 * for an element a lookup returned; a later milestone returns elements whose zone is not in memory, and then NULL. */
typedef struct zdir_elem zdir_elem_t;
typedef struct zdir_tab zdir_tab_t;
typedef struct zdir_tick zdir_tick_t;
typedef struct zdir zdir_t;

/* zdir_elem_t.state */
enum { ZDIR_ST_ABSENT = 0, ZDIR_ST_RESIDENT, ZDIR_ST_LOADING, ZDIR_ST_ERROR };
/* zdir_elem_t.flags */
#define ZDIR_F_PRESIGNED 0x0001u   /* the image holds a DNSSEC chain (NSEC / NSEC3): a presigned zone */
#define ZDIR_F_ALIAS     0x0002u   /* the image has an ALIAS RRset */
#define ZDIR_F_WILDCARD  0x0004u   /* the image has a wildcard owner */
#define ZDIR_F_PIN       0x0008u   /* never evicted (reserved: set by a later milestone) */
#define ZDIR_F_NOCACHE   0x0010u   /* never kept resident after an answer (reserved) */
#define ZDIR_F_PARTIAL   0x0020u   /* only part of the zone is resident (reserved for D1b) */
#define ZDIR_F_EVICT_NEXT 0x0040u  /* take out of memory first (as soon as the queries it was loaded for are answered): a zone that was admitted against the frequency order, or a no-cache zone */
#define ZDIR_F_WARM      0x0100u   /* the zone is in the ingest thread's list of zones to read before a query asks (pins): once, whatever the number of summaries */
#define ZDIR_F_BUSY      0x0080u   /* the ingest thread is installing a new version into the zone's entry (dbreg_lookup_entry_busy() .. dbreg_commit() / dbreg_reject()): it is not taken out of memory meanwhile */
#define ZDIR_F_QUEUED    0x1000u   /* a registry element waiting in the queue of additions */
#define ZDIR_F_DELETED   0x2000u   /* a registry element that left the registry (waiting to leave the index) */
#define ZDIR_F_TICK      0x4000u   /* the control thread's tick looks at the zone (secondary, catalog member) */
/* (flags are changed under g_zone_db_rebuild_lock; a reader that needs one while a writer may change it reads it with an atomic load of
 * the whole word, a later milestone's job.  What a reader looks at today is in `kind`, which never changes.) */
/* zdir_elem_t.kind: what the element is, fixed when it is made (readers look at it without a lock) */
#define ZDIR_K_OWNED     0x01u     /* owned by the directory it is in (not by the registry): released with it */
#define ZDIR_K_STATIC    0x02u     /* the zone of a zone { } block of karidns.conf */
#define ZDIR_K_SHARED    0x04u     /* a zone shared from another view by `in-view`: the entry is the owner view's */
#define ZDIR_K_BORROWED  0x08u     /* the element holds no reference of its entry (unit tests, fuzzers) */

/* D1a step 6 (design 12-12): the apex of a zone that is not in memory, from its summary: what the answer to an SOA question at the apex is made of
 * (RFC 1035 3.3.13, 3.3.11).  Names are wire names without compression (RFC 3597 4 does not apply: SOA and NS are well-known types).  data: MNAME,
 * RNAME, then n_ns NS targets one after the other, then glue_len octets of glue: the addresses of NS targets that are inside the zone, records of
 * ns index u8 | type u8 (1 A, 28 AAAA) | ttl u32 | address (4 or 16 octets), the indexes not decreasing, at most ZDIR_APEX_GLUE_PER_NS records for one (the
 * Additional section of the answer, RFC 2181 9).  `serial` is the serial of the version it describes; the block is not used for another one. */
typedef struct zdir_apex {
  uint32_t serial, soa_ttl, refresh, retry, expire, minimum, ns_ttl;
  uint16_t mname_len, rname_len, ns_len, glue_len;
  uint8_t n_ns;
  uint8_t data[];
} zdir_apex_t;
#define ZDIR_APEX_NS_MAX 8        /* NS targets of an apex (= KDB_APEX_NS_MAX, dns_db_stream.h; dns_db_ingest.c checks) */
#define ZDIR_APEX_GLUE_PER_NS 8   /* addresses of one NS target (= KDB_APEX_GLUE_PER_NS) */
#define ZDIR_APEX_GLUE_MAX (ZDIR_APEX_NS_MAX * ZDIR_APEX_GLUE_PER_NS * 22)   /* (= KDB_APEX_GLUE_BYTES with room to spare) */
#define ZDIR_APEX_MAX (sizeof(zdir_apex_t) + 2 * 255 + ZDIR_APEX_NS_MAX * 255 + ZDIR_APEX_GLUE_MAX)
struct zdir_elem {
  struct zdir_elem *next;      /* the registry's hash chain; once the element is on a garbage list, that list */
  _Atomic(zone_db_entry_t *) entry;   /* the entry that answers for the name (RCU-published); the element holds a reference */
  char *error;                 /* last rejection / loader error, malloc; NULL = none */
  int64_t source_id;           /* DB: the domain id of the zone; directory-owned elements: the listing order */
  _Atomic uint32_t serial;     /* DB: the serial of the version offered last (the SOA of the entry for a secondary).  Written under g_zone_db_rebuild_lock; a worker reads it (build_apex_soa_answer()): zdir_serial() */
  uint32_t refresh, retry, expire;   /* the SOA timers of the version served */
  uint32_t hash;               /* calc_fnv1a_strn(name, klen): the index hash */
  _Atomic uint32_t freq;       /* D1a step 5: how often the zone is asked for (GDSF, cache admission).  Non-resident zone: +1 per query that parks; the cache manager folds the queries of a resident zone in (observatory counter) and halves it at each round */
  uint32_t qseen;              /* D1a step 5: the zone entry's query counter (low 32 bits) when the cache manager last folded it into freq */
  uint32_t t_load;             /* D1a step 5: when the data came into memory (ms of a monotonic clock, 32 bits): a zone is not taken out again before its queries are answered */
  _Atomic uint8_t state;       /* ZDIR_ST_*: written under g_zone_db_rebuild_lock, read without it (a worker looks at it before it parks a query) */
  uint8_t last_result;         /* DBREG_APPLIED or DBREG_REJECTED (the last version offered) */
  bool shadowed;               /* a zone of karidns.conf (D-PRIO) or a catalog member (D17-1) with this name hides it: hidden elements are not in the index */
  uint8_t shadow_by;           /* DBREG_SH_*, meaningful while shadowed */
  uint16_t flags;              /* ZDIR_F_* (changed under g_zone_db_rebuild_lock) */
  uint8_t klen;                /* the name without the trailing dot */
  uint8_t kind;                /* ZDIR_K_* (never changes) */
  uint8_t *digest;             /* DB: the 32-byte digest the loader sent, in a block of its own that only a zone with data in memory has (malloc, freed with the element; NULL = none) */
  _Atomic(zdir_apex_t *) apex;       /* D1a step 6: the apex of the zone, from a summary (NULL: none).  Replaced under g_zone_db_rebuild_lock; the old block is given back with the garbage of the retired snapshot (a worker may be reading it). */
  _Atomic(zone_ext_shared_t *) sh;   /* DB: the interned settings of the zone (one reference), set when its data leaves memory: a query for the zone while it is out of memory
                                      * is checked against the zone's allow-query from it, before it parks (a zone in memory has its settings in the entry, dbcfg).  Replaced
                                      * by the next eviction; the old one is given back with the garbage of the retired snapshot, as a reader may hold it. */
  char name[];                 /* canonical absolute name, lower case, with the trailing dot */
};
/* Where a zone's settings (dbcfg) live when its data is not in memory (D1a, decision of milestone 2): the zone_config_t of an entry (169 bytes of
 * per-zone fields) is made again from the zone name and the interned settings when the entry is made, so what has to outlive the entry is the
 * interned zone_ext_shared_t (db_settings_intern(): one object for every zone with the same settings text, 8 bytes per zone for the pointer).
 * A later milestone adds that pointer to this element, next to the digest block; until then every element is resident and dbcfg stays in the
 * entry (zone_entry_config()). */
typedef zdir_elem_t dbreg_zone_t;
enum { DBREG_APPLIED = 0, DBREG_REJECTED = 1 };
enum { DBREG_SH_NONE = 0, DBREG_SH_CONFIG = 1, DBREG_SH_CATALOG = 2 };

/* the open-addressing index of a directory: a power-of-two array of element pointers, NULL = empty, ZDIR_TOMB = removed */
struct zdir_tab {
  zdir_tab_t *gnext;           /* garbage list */
  size_t cap, mask;
  _Atomic(zdir_elem_t *) slot[];
};
/* the elements the control thread's one-second tick must look at (zone_entry_ticks(): secondaries and catalog members, for their
 * refresh / expire timers and the settings received from the primary); replaced as a whole when the set changes.  The tick walks
 * every element only for a pending NOTIFY request (g_zone_notify_pending), so a million primary zones from the database cost
 * the tick nothing. */
struct zdir_tick {
  zdir_tick_t *gnext;
  size_t n;
  zdir_elem_t *e[];
};
struct zdir {
  _Atomic(zdir_tab_t *) tab;   /* NULL until the first element */
  _Atomic(zdir_tick_t *) tick;
  _Atomic int refs;            /* the views (snapshots) that point to the directory */
  /* the writers' counters (under g_zone_db_rebuild_lock; relaxed atomics for the readers who print them) */
  size_t used;                 /* slots that are not empty, tombstones included */
  _Atomic size_t live;         /* elements in the index (the shared ones included) */
  _Atomic size_t n_static;     /* of them the zones of zone { } blocks: a reload whose zone { } blocks all map to these reuses the directory (snapshot_views_reusable()) */
  _Atomic size_t n_shared;     /* of them the zones shared from another view (view_owns_elem() tells) */
};

/* what a retired snapshot keeps alive until it and every older snapshot are drained */
typedef struct zdir_gent {
  struct zdir_gent *next;
  zone_db_entry_t *entry;      /* one reference to give back (NULL: none) */
  bool served;                 /* (a replaced entry) it was the one in the index when it was replaced */
  zone_ext_shared_t *sh_old;   /* one reference of settings to give back (an eviction replaced the element's), NULL = none */
  zdir_apex_t *apex_old;       /* an apex block that was replaced (free() it), NULL = none */
} zdir_gent_t;
typedef struct {
  zdir_elem_t *elems;          /* chained through ->next */
  zdir_tab_t *tabs;            /* chained through ->gnext */
  zdir_tick_t *ticks;
  zdir_gent_t *ents;
} zdir_garbage_t;

typedef struct {
  char *name;
  char **match_clients;
  int match_clients_count;
  acl_entry_t *match_clients_parsed;
  /* Non-NULL when the view's match-clients has a `key` element (BIND get_matching_view_sync()): select_view_req() evaluates this list with the TSIG key
   * the request was verified with (this view's key ring), and the flat lists above are empty.  A reference (aml_ref()); released with the snapshot. */
  aml_t *match_aml;
  /* the zones of the view (one reference of the directory per snapshot that lists the view).  NULL: a view without zones */
  zdir_t *dir;
} view_snapshot_t;

/* Is the element a zone of this view, rather than a zone shared with an earlier view through zone { in-view } (the same
 * zone_db_entry_t as in the owner view; entry->view_name is the owner's)?  Anything that walks the zones of every view once per
 * zone must skip the shared ones. */
static inline bool view_owns_elem(const zdir_elem_t *e) { return !(e->kind & ZDIR_K_SHARED); }

typedef struct zone_db_snapshot {
  view_snapshot_t *views;
  size_t view_count;
  _Atomic(int) reader_count;
  uint64_t retire_epoch;
  int ixfr_history;   /* options { ixfr-history } the entries' depth was set with (a reused view redoes it when it changed) */
  /* removed from the directories while this snapshot was the current one (see the top of this section) */
  zdir_garbage_t garb;
  struct zone_db_snapshot *gc_next;   /* the retired snapshots that are not drained yet, oldest first (g_gc_lock) */
  bool gc_queued;
  bool gc_started;                    /* its cleanup thread was started (or is being started); false = a start failed and is tried again (g_gc_lock) */
  bool gc_drained;
} zone_db_snapshot_t;

/* A long walk over every zone (a rebuild at a million zones, the glue refresh, the registry walks of the ingest thread)
 * runs on the control or ingest thread, which shares its CPU with a pinned router or worker thread; ULE lets it run on
 * until its quantum ends, so queries on that CPU stall for the whole walk (sched_yield() does not give the CPU up).  The
 * walks call burst_yield() per item: every BURST_YIELD_CHECK items it looks at the clock, and after BURST_YIELD_MS of
 * running it sleeps BURST_YIELD_NS, which puts the thread at the back of the run queue.  The cost is one nanosleep (a
 * tick, about 1 ms) per BURST_YIELD_MS of work: a full rebuild at 1,000,000 database zones (a zone { } added) took 2.1 s
 * and takes 2.5 s; a reload that changes no zone set does not walk the zones at all (30 ms). */
#define BURST_YIELD_CHECK 256
#define BURST_YIELD_MS 4
#define BURST_YIELD_NS 500000L
typedef struct {
  unsigned n;
  int64_t since_ms;   /* when the burst started, CLOCK_MONOTONIC in ms; 0 = not started */
} burst_yield_t;
static inline int64_t burst_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static inline void burst_yield(burst_yield_t *y) {
  if (++y->n < BURST_YIELD_CHECK) return;
  y->n = 0;
  int64_t now = burst_now_ms();
  if (y->since_ms == 0) {
    y->since_ms = now;
  } else if (now - y->since_ms >= BURST_YIELD_MS) {
    struct timespec ts = { 0, BURST_YIELD_NS };
    nanosleep(&ts, NULL);
    y->since_ms = burst_now_ms();
  }
}
/* for a loop whose items are big (a zone installed, an inventory chunk): look at the clock every time */
static inline void burst_yield_check(burst_yield_t *y) {
  y->n = BURST_YIELD_CHECK - 1;
  burst_yield(y);
}
#define BURST_YIELD_INIT { 0, 0 }

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
/* the entries the control thread's tick looks at every second (view_snapshot_t.tick_entries) */
static inline bool zone_entry_ticks(const zone_db_entry_t *e) { return e->is_secondary || e->is_catalog_member; }
/* NOTIFY requests (karictl notify, UPDATE) made since the control thread's tick last walked every zone: the flag
 * notify_now can be set on any zone, so a pending request makes the next tick walk all of them once */
extern _Atomic uint32_t g_zone_notify_pending;
static inline void zone_notify_request(zone_db_entry_t *e) {
  atomic_store_explicit(&e->notify_now, true, memory_order_release);
  atomic_fetch_add_explicit(&g_zone_notify_pending, 1, memory_order_release);
}
zone_config_t *find_zone_config_in_view(server_config_t *cfg, const char *view_name, const char *domain);
/* ゾーンエントリの設定。DB のゾーンは entry->dbcfg、それ以外は cfg の索引 (find_zone_config_in_view)。
 * 無ければ NULL。返した物は cfg を保持している間 (DB のゾーンは読み取り区間の中) だけ有効 */
static inline const zone_config_t *zone_entry_config(server_config_t *cfg, const zone_db_entry_t *entry) {
  const zone_config_t *rx = atomic_load_explicit(&entry->rxcfg, memory_order_acquire); /* B8t-2 */
  if (rx) return rx;
  if (entry->source == ZONE_SRC_DB) return atomic_load_explicit(&entry->dbcfg, memory_order_acquire);
  return find_zone_config_in_view(cfg, entry->view_name, entry->domain);
}
/* B8t-2: the settings a primary sent with the zone.  zone_rx_settings_parse() reads the text with the restricted parser (NULL when
 * there is none, or it is not accepted: logged; the text is never trusted).  zone_rx_settings_apply_locked() makes sh (ownership
 * moves to the entry; NULL = none) the settings in force: it merges them with the zone's own configuration and publishes the result,
 * and returns the settings that were in force (the caller unrefs them, or puts them back when the data cannot be installed).  The
 * caller holds entry->writer_lock; the data is installed after the settings, so that the glue and the response cache of the new
 * version are built with them.  zone_rx_settings_refresh() redoes the merge when karidns.conf (or the settings block of a database
 * zone) changed under it (control thread, once per tick; skips the zone when a writer holds the entry). */
zone_ext_shared_t *zone_rx_settings_parse(const char *zone, const char *text, size_t len);
zone_ext_shared_t *zone_rx_settings_apply_locked(zone_db_entry_t *entry, zone_ext_shared_t *sh);
void zone_rx_settings_refresh(zone_db_entry_t *entry, server_config_t *cfg);
/* are received settings in force for the zone?  note (cap octets, may be NULL) gets why not all of them are ("" if all are, or when a writer
 * holds the entry at the moment) */
bool zone_rx_settings_status(zone_db_entry_t *entry, char *note, size_t cap);
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
/* The same, and the directory element of the zone the answer comes from in *elem_out (NULL: no zone).  When the element has no data in memory
 * (zdir_entry() == NULL) the return value is NULL and *elem_out is that element: the worker parks the query (dns_park.h). */
zone_db_entry_t *find_zone_for_query_ex(view_snapshot_t *view, const char *qname, uint16_t qtype, zdir_elem_t **elem_out);
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
/* the size limits of the zone (max-records, ...) checked on a built zone before it is installed; 0 = ok (see dns_axfr_ixfr.c) */
int zone_limits_gate(zone_db_entry_t *entry, zone_arena_t *builder, const char *what);
/* 公開直前に呼ぶ: 応答キャッシュに入れてよいか (rcache_ok) を決める。ゾーンの設定は zone_entry_config(cfg, entry)
 * (DB のゾーンは dbcfg)。entry は view_name、domain、source (と DB のゾーンなら dbcfg) だけを読む */
void build_zone_response_cache(zone_version_t *ver, server_config_t *cfg, const zone_db_entry_t *entry);
void zone_glue_refresh_dependents(bool force);
uint64_t zone_entry_next_id(void);

/* ---- zone memory accounting (D1a, design 8.1; dns_snapshot_rcu.c) ----
 * The bytes of the zone versions that zones serve (the version, its image, its glue block) and of the IXFR differences they keep, and of
 * the versions that were replaced and are not freed yet (still on the retire stack: a reader or a transfer may hold them), per kind of
 * zone: those that come from the database, and the others (zone { } blocks, catalog members).  Read only: nothing limits them yet.
 * A version's size is recorded when it is frozen (zone_version_new(), zone_glue_track_build()); zone_publish() moves it from resident to
 * retired when a newer one replaces it, and the retire stack gives it back when it is freed.  An entry that goes takes its resident
 * bytes with it.  Scope: the version structure, its image and its glue block, and the data pools of an IXFR delta (its records, its arena);
 * not the zone entry, its observatory counters, the response cache or the settings blocks.  A delta that left the history is still counted
 * (resident) until the last transfer that reads it releases it (free_ixfr_txn()). */
enum { ZBYTES_DB = 0, ZBYTES_OTHER = 1, ZBYTES_CLASSES = 2 };
typedef struct {
  uint64_t resident;   /* what the zones serve now, IXFR differences included */
  uint64_t retired;    /* replaced versions that are not freed yet */
} zone_bytes_t;
void zone_bytes_get(int cls, zone_bytes_t *out);
int zone_bytes_class(const zone_db_entry_t *e);
/* for the IXFR history (dns_axfr_ixfr.c): a difference was stored in / left the history of a zone of class cls */
void zone_bytes_resident_add(int cls, int64_t delta);

/* ---- DB zone registry and view delta (beta design 4.2, 4.4; implemented in dns_snapshot_rcu.c) ----
 * The registry is the source of truth for which DB zones exist: per view (by name) the zone directory's elements of the
 * database zones (zdir_elem_t, above), found by name.  Everything below takes g_zone_db_rebuild_lock itself (the "_locked" ones
 * expect it to be held); the ingest threads and the full-configuration rebuild are the only writers, queries never touch the
 * registry.  The registry's element holds one snapshot_refs reference of its entry; a directory-owned element holds one of
 * its own.  Callers on aux threads must rcu_aux_thread_pin() first (the commit reads the configuration inside the lock). */
extern pthread_mutex_t g_zone_db_rebuild_lock;

/* The entry of an element: the one that answers for the name (RCU-published; NULL when the zone is not resident, which no
 * element of a directory is in this milestone).  Valid as long as the element is. */
static inline zone_db_entry_t *zdir_entry(const zdir_elem_t *e) {
  return e ? atomic_load_explicit((_Atomic(zone_db_entry_t *) *)&e->entry, memory_order_acquire) : NULL;
}
/* the serial of the version the element describes (relaxed: a reader compares it with the serial of the apex block it loaded with acquire; the writer stores the serial before the block) */
static inline uint32_t zdir_serial(const zdir_elem_t *e) { return atomic_load_explicit(&((zdir_elem_t *)e)->serial, memory_order_relaxed); }
/* the longest-suffix match of qname (the zone that holds the name), and the zone named exactly domain, in the directory of the
 * view: the element, which a later milestone may return for a zone that is not in memory (then zdir_entry() is NULL).
 * find_zone_in_view() / find_zone_exact_in_view() / find_zone_for_query() return the entry of that element. */
zdir_elem_t *zdir_find_suffix(const view_snapshot_t *view, const char *qname);
zdir_elem_t *zdir_find_exact(const view_snapshot_t *view, const char *domain);
/* Walk the index of a view (slot order; the shared zones too).  An element that is inserted or removed meanwhile may or may not
 * be seen; one that is in the index for the whole walk is seen once. */
typedef struct { const zdir_tab_t *tab; size_t i; } zdir_iter_t;
void zdir_iter_init(zdir_iter_t *it, const view_snapshot_t *view);
zdir_elem_t *zdir_iter_next(zdir_iter_t *it);
/* the same, by slot number (a walk that does not start at the first slot, the control thread's tick): the number of slots of the table
 * the iterator holds, and the element in slot i (NULL: none, or i is beyond the table) */
int zdir_listing_cmp(const void *a, const void *b);   /* qsort() order of a list of zdir_elem_t *: the zones of zone { } blocks and the catalog members in the order of the configuration, then the rest */
size_t zdir_iter_slots(const zdir_iter_t *it);
zdir_elem_t *zdir_iter_at(const zdir_iter_t *it, size_t i);
/* the number of elements of the index, of those the zones that belong to the view (the shared ones left out), the zone { } blocks
 * among them, and the zones shared with another view (zdir_count() = owned + shared) */
static inline size_t zdir_count(const view_snapshot_t *view) {
  return (view && view->dir) ? atomic_load_explicit(&view->dir->live, memory_order_relaxed) : 0;
}
static inline size_t zdir_count_shared(const view_snapshot_t *view) {
  return (view && view->dir) ? atomic_load_explicit(&view->dir->n_shared, memory_order_relaxed) : 0;
}
static inline size_t zdir_count_static(const view_snapshot_t *view) {
  return (view && view->dir) ? atomic_load_explicit(&view->dir->n_static, memory_order_relaxed) : 0;
}
static inline size_t zdir_count_owned(const view_snapshot_t *view) { return zdir_count(view) - zdir_count_shared(view); }
/* Is the entry a zone of this view, rather than one shared from an earlier view (the owner view's name is in entry->view_name)? */
static inline bool view_owns_entry(const view_snapshot_t *vs, const zone_db_entry_t *e) {
  return zdir_count_shared(vs) == 0 || strcasecmp(e->view_name, vs->name) == 0;
}
/* the ticking zones of the view (zone_entry_ticks()): *n of them; valid while the caller is in a read section or holds the snapshot */
zdir_elem_t *const *zdir_tick_list(const view_snapshot_t *view, size_t *n);
/* unit tests and fuzzers: make the directory of `view` list the given entries (no reference is taken of them and they are not freed
 * with the view); directory-owned elements named after entries[i]->domain.  false: out of memory. */
bool view_set_entries(view_snapshot_t *view, zone_db_entry_t *const *entries, size_t n);
/* free the directory of a view built by view_set_entries() (and any other); the entries stay */
void view_clear_dir(view_snapshot_t *view);


/* Commit an installed zone.  entry is either a new entry (created = true, the registry takes over its initial
 * reference and the entry is queued to enter the view snapshot, unless a configured zone shadows it) or the entry
 * already registered under name.  *shadowed tells whether a zone of karidns.conf hides it.  0, or -1 (out of
 * memory: the caller keeps ownership of a new entry). */
int dbreg_commit(const char *view, const char *name, zone_db_entry_t *entry, bool created, int64_t source_id,
                 uint32_t serial, const uint8_t digest[32], bool *shadowed);
/* The entry registered for (view, name) or NULL.  Valid while the caller is the only ingest thread working on that
 * name (the ingest thread serializes zones of the same name). */
zone_db_entry_t *dbreg_lookup_entry(const char *view, const char *name);
/* the same for the ingest thread that is about to install a new version into the entry: the zone is marked busy (ZDIR_F_BUSY) until dbreg_commit() or dbreg_reject() for it, and is not taken out of memory meanwhile */
zone_db_entry_t *dbreg_lookup_entry_busy(const char *view, const char *name);
uint64_t zone_bytes_underflows(void);                             /* times a byte total would have gone below zero (a bug; 0) */
/* Record that the version offered for (view, name) was rejected (an existing entry keeps serving its last good
 * version; without one only the error is recorded).  false: out of memory. */
bool dbreg_reject(const char *view, const char *name, int64_t source_id, const char *reason);
/* ZONE_DELETE: forget the zone; its entry leaves the view snapshot with the next snapshot_apply_db_delta().  1:
 * removed, 0: not registered or registered with another source id (nothing done). */
int dbreg_delete(const char *view, const char *name, int64_t source_id);
/* Publish the queued additions and removals (beta design 4.4, D1a): the directory of each view is changed in place, element by
 * element (no copy of the index unless it has to grow), and a new snapshot that shares the directories is published; what left
 * the index is freed once the readers that can still see it are gone.  Returns the number of elements added plus removed,
 * or -1 (out of memory, the queue is kept and nothing was changed). */
int snapshot_apply_db_delta(void);
/* Number of queued changes (cheap, no lock) */
size_t dbreg_pending_count(void);

typedef struct { size_t view, bucket, skip; } dbreg_cursor_t;
/* Walk the registry from *cur; cb returns false to stop (the cursor then points at the zone that was refused).
 * Returns true when the end was reached. */
typedef bool (*dbreg_walk_cb)(void *ud, const char *view, const dbreg_zone_t *z);
bool dbreg_walk(dbreg_cursor_t *cur, dbreg_walk_cb cb, void *ud);
/* What the directory costs (D1a, design 3.1), in bytes as requested from malloc: the registry's elements and hash tables (*registry_bytes,
 * *elements of them), and the index tables of the active snapshot's views with their tick lists (*index_bytes).  The entries and images are not in it. */
void dbreg_dir_bytes(size_t *elements, size_t *registry_bytes, size_t *index_bytes);
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
/* D1a step 5: the cache manager (memory-limit of database { }).  dbreg_cache_round() takes zones out of memory when the database zones hold more
 * than the high mark of the limit; the ingest thread's cache thread calls it every 100 ms. */
typedef struct {
  uint64_t limit, resident, retired, inflight;   /* bytes: the limit (0 = none), the version bytes in memory, replaced / evicted but not freed, evicted but not freed */
  uint64_t evictions, rounds, cold, marked, misses;
  uint64_t pinned_bytes, peak;
  uint32_t victim_freq;
} dbreg_cache_stats_t;
void dbreg_cache_set_limit(uint64_t limit);
uint64_t dbreg_cache_limit(void);
uint32_t dbreg_cache_round(void);
void dbreg_cache_stats(dbreg_cache_stats_t *out);
#ifdef KARIDNS_UNIT_TEST
void dbreg_cache_test_pause(bool on);                              /* TEST ONLY: the manager does nothing while paused */
void dbreg_cache_test_set_victim_freq(uint32_t f);                 /* TEST ONLY: the frequency a zone that is loaded now is compared with */
#endif
void dbreg_cache_note_miss(void);                                 /* a query had to wait for a zone (the worker) */
bool dbreg_cache_over_high(uint64_t extra);                        /* would the zone databases be above the high mark with `extra` more bytes? (false without a limit) */
bool dbreg_cache_over_limit(void);                                 /* are the database zones above the limit itself? */
/* A zone of a batch that is not kept in memory because the limit is reached: the directory element with the serial and the digest the loader sent,
 * no data (the next query for it fetches it).  0 on success. */
int dbreg_commit_cold(const char *view, const char *name, int64_t source_id, uint32_t serial, const uint8_t digest[32], zone_ext_shared_t *shared);
#define DBREG_COLD_RESIDENT 1     /* dbreg_commit_cold(): the zone has its data in memory (a fetch brought it), nothing was recorded */
void dbreg_set_pending_notify(void (*cb)(void));                  /* called (lock held) when a change is queued without the ingest thread: it wakes the thread */
size_t dbreg_count_updated(void);                                 /* zones changed by a dynamic UPDATE: pinned in memory until the next load from the database */
uint64_t dbreg_evictions(void);                                  /* zones evicted since the start */
uint64_t dbreg_evict_inflight(void);                              /* bytes of evicted zones whose entries are not freed yet (in the retired total) */
#if defined(KARIDNS_TEST_EVICT) || defined(KARIDNS_UNIT_TEST)
bool dbreg_test_evict(const char *view, const char *name);        /* TEST ONLY, see dns_snapshot_rcu.c */
#endif
/* D1a milestone 2: the fetch of a zone whose element is in the directory without its data.  dbreg_fetch_begin(): ABSENT -> LOADING under the
 * registry lock (DBREG_FETCH_STARTED: the caller asks the loader), or why not: the zone is in memory, a fetch is on its way, it is not in the
 * registry.  dbreg_fetch_end(): LOADING -> ABSENT again for an element that still has no data (the fetch failed or brought a summary; a fetch
 * that brought the data has made it resident through dbreg_commit()).  dbreg_apply_summary(): what a summary tells (serial, SOA timers) goes into
 * an element that has no data and the same source id; false when there is none such. */
enum { DBREG_FETCH_STARTED = 0, DBREG_FETCH_RESIDENT, DBREG_FETCH_BUSY, DBREG_FETCH_NONE };
int dbreg_fetch_begin(const char *view, const char *zone);
void dbreg_fetch_end(const char *view, const char *zone);
bool dbreg_apply_summary(const char *view, const char *zone, int64_t source_id, uint32_t serial, bool has_timers, uint32_t refresh,
                         uint32_t retry, uint32_t expire);
enum { DBREG_SUM_NONE = 0, DBREG_SUM_SAME, DBREG_SUM_DIFFERS };
/* D1a step 6: give the element of a zone that has no data (same source id) the apex a summary brought (NULL: it brought none, the old one goes).  true: the
 * element took the block (the caller must not free it); false: the block is the caller's. */
bool dbreg_set_apex(const char *view, const char *zone, int64_t source_id, uint32_t serial, zdir_apex_t *apex);
/* The list of zones to read before a query asks (ingest thread): dbreg_warm_mark() puts a zone in it (false: it is there already, or the zone is not a registry zone),
 * dbreg_warm_take() takes it out again: true when it is still worth a read (no data, not deleted, and pinned or without an apex); *whole: the zone is pinned and is
 * read whole, else only its summary (for the apex) is asked for. */
bool dbreg_warm_mark(const char *view, const char *zone);
bool dbreg_warm_take(const char *view, const char *zone, bool *whole);
/* D1a step 6 (design 12-12): does the zone keep the apex of its summary (notify or allow-transfer)?  The _cfg form takes the configuration the caller holds in a
 * read section.  dbreg_settings_ref(): the settings the registry kept for a zone out of memory, one reference (zone_ext_shared_unref()). */
bool dbreg_apex_wanted(const char *view, const char *zone, const zone_ext_shared_t *sh);
bool dbreg_apex_wanted_cfg(const server_config_t *cfg, const char *view, const char *zone, const zone_ext_shared_t *sh);
zone_ext_shared_t *dbreg_settings_ref(const char *view, const char *zone);
int dbreg_summary_check(const char *view, const char *zone, int64_t source_id, uint32_t serial);
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
  /* transfer-source / primaries source (batch 4): the local address the connect broker binds (port 0) before connect(); the family is the
   * request's.  The broker refuses an address that was not in the configuration when the server started (config_xfr_source_allowed()). */
  uint8_t has_src;
  uint8_t src[16];
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
bool ensure_priv_dir_safe(const char *dir_buf);
/* dns_server_core.c: open the files of the channels in `list` (the other kinds of channel need nothing).  0 = all open; 1 = nothing wrong but a
 * file in a directory the sandbox cannot reach any more (a reload that names a new directory: it takes effect after a restart); -1 = a
 * file could not be opened or is refused (logged).  hand_off: give the files to the run user (the start-up does that later, see
 * hand_off_logging_channels()). */
int log_open_channels(log_channel_t *list, bool hand_off);
/* the files of the installed runtime: give them to the run user (root start-up with `user`), and take away the fchown right */
void hand_off_logging_channels(void);
void logging_drop_fchown(void);

/* dns_log.c: the operational log (see the top of that file) */
typedef struct log_runtime log_runtime_t;
typedef enum { LOGRT_OK = 0, LOGRT_RESTART, LOGRT_ERROR } logrt_status_t;
typedef enum { KLOG_ROLE_BACKEND = 0, KLOG_ROLE_AUX } klog_role_t;
typedef struct {
  char buf[32768];
  size_t len;
} klog_batch_t;
/* Build the runtime of a parsed `logging` statement and open its files.  NULL with *status LOGRT_RESTART: only a new directory stood in the way
 * (keep the runtime in use and report "restart needed"); LOGRT_ERROR: a file could not be opened (reject the configuration). */
log_runtime_t *log_runtime_build(const logging_config_t *lc, bool hand_off, logrt_status_t *status);
bool log_runtime_install(log_runtime_t *rt);   /* false: the runtime before the previous one is still in use; rt is not installed */
void log_runtime_free(log_runtime_t *rt);
void log_channel_free(log_channel_t *ch);
log_runtime_t *log_runtime_acquire(void);
void log_runtime_release(log_runtime_t *rt);
log_channel_t *log_runtime_current_channels(void);
log_channel_t *const *log_runtime_route(const log_runtime_t *rt, int cat, int *n);
void klog_set_role(klog_role_t role);
bool klog_guard_enter(void);
void klog_guard_leave(bool prev);
int klog_category_for_message(const char *fmt);
int klog_level_from_priority(int prio);
bool klog_level_passes(int channel_level, int level);
size_t klog_build_line(const log_channel_t *ch, int cat, int level, const struct timespec *ts, const char *msg, char *out, size_t n);
void klog_channel_emit(log_channel_t *ch, int cat, int level, const struct timespec *ts, const char *msg);
void klog_record(log_runtime_t *rt, int cat, int level, const struct timespec *ts, const char *msg);
void klog_batch_add(klog_batch_t *b, log_channel_t *ch, int cat, int level, const struct timespec *ts, const char *msg);
void klog_batch_flush(klog_batch_t *b, log_channel_t *ch);
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
