#include "dns_zone_parser.h"
#include "dns_config_parser.h"
#include "dns_utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h> // PATH_MAX, NAME_MAX
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <pwd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capsicum.h> // Capsicum capability mode / rights
#include <sys/cpuset.h>   // cpuset
#include <sys/file.h>     // flock
#include <sys/event.h>    // kqueue
#include <sys/param.h>    // cpuset
#include <sys/procctl.h>  // PROC_TRAPCAP
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/ucred.h>

#include "dns_wire.h" // 分離したワイヤーフォーマット操作用ヘッダ

// karidns
// Copyright (c) 2026 Noel Minamino
// Lisence: MIT
// All codes are developed by Gemini Pro, Claude Sonnet with Human Idea and
// test.

// ============================================================================
// 1. 定数・マクロ・IPC定義
// ============================================================================
#define DNS_PORT 53
#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096


#define MAX_BIND_ADDRS 32

// Frontend/Backendプロセス間のUDPパケット受け渡し用ヘッダ
typedef struct {
  int sock_fd_idx; // 返信に使用するFrontend側のUDPソケットインデックス (-1 =
                   // 動的生成/NOTIFY用)
  socklen_t addr_len;
  struct sockaddr_storage client_addr;
  uint16_t payload_len;
  // この構造体の直後にパケットのペイロードが続く
} udp_ipc_t;

// ============================================================================
// 2. データ構造定義
// ============================================================================

// Zoneデータメモリプール (アリーナ)

typedef struct {
  _Atomic(zone_arena_t *) active;
  zone_arena_t arena_a;
  zone_arena_t arena_b;
} zone_rcu_t;

#define MAX_IXFR_HISTORY 32
#define MAX_ZONE_AXFR 4
#define MAX_TCP_CLIENTS 1000

typedef struct {
  uint32_t old_serial;
  uint32_t new_serial;
  dns_record_t *deleted;
  int deleted_count;
  dns_record_t *added;
  int added_count;
  _Atomic int ref_count;
  zone_arena_t arena; // mini-arena for strings/blob
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
  catalog_member_id_t *catalog_members;
  int catalog_member_count;
  bool is_catalog_member;
  char catalog_member_unique_id[256];
  char **groups;
  int group_count;
  char cached_master_ip[64];
  int cached_master_port;
  char cached_tsig_key_name[64];
  // LOCK-ONLY FIELD: 読み書きは g_zone_db_rebuild_lock 保持区間内でのみ行うこと。
  // クエリ処理・バックグラウンドスケジューラなど、スナップショットをロックフリーで
  // 読む経路からは絶対に参照しないこと(catalog_members/groups と同じ規約)。
  char owning_catalog_domain[256];
  _Atomic(time_t) last_successful_transfer;
  _Atomic(time_t) last_stale_log_time;
} zone_db_entry_t;

// TCPストリーム解析ステート
typedef enum { TCP_STATE_READ_LEN, TCP_STATE_READ_BODY } tcp_state_t;
typedef struct {
  tcp_state_t state;
  uint8_t buf[65536 + 2];
  size_t accumulated;
  uint16_t msg_len;
  char client_ip[INET6_ADDRSTRLEN];
} tcp_stream_ctx_t;

typedef struct {
  bool is_finished;
  bool is_ixfr;
  bool is_deleting;
  int soa_count;
  uint32_t initial_soa_serial;
  uint32_t client_serial;
  char initial_soa_name[256];
} axfr_session_t;

typedef struct {
  int thread_id;
  int core_id;
  zone_rcu_t *rcu_db;
} worker_ctx_t;

typedef struct {
  _Atomic(server_config_t *) active;
  server_config_t config_a;
  server_config_t config_b;
} config_rcu_t;

pthread_mutex_t g_zone_db_rebuild_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char domain[256];
    char old_catalog[256];
    char new_catalog[256];
} pending_coo_t;

// Protected by g_zone_db_rebuild_lock
pending_coo_t *g_pending_coo = NULL;
int g_pending_coo_count = 0;
int g_pending_coo_capacity = 0;

typedef enum {
  RRL_RESP_NOERROR,
  RRL_RESP_NODATA,
  RRL_RESP_NXDOMAIN,
  RRL_RESP_ERROR
} rrl_response_class_t;

#define RRL_TABLE_SIZE 65536

typedef struct {
  atomic_flag lock;
  _Atomic uint64_t client_hash;
  _Atomic int64_t last_refill_ms[4];
  _Atomic int32_t tokens[4];
  _Atomic uint32_t slip_counter;
} rrl_bucket_t;
static rrl_bucket_t g_rrl_table[RRL_TABLE_SIZE];

_Atomic uint64_t g_rrl_dropped_total = 0;
_Atomic uint64_t g_rrl_slip_total = 0;
_Atomic uint64_t g_ede_prohibited_total = 0;
_Atomic uint64_t g_ede_not_authoritative_total = 0;
_Atomic uint64_t g_ede_not_supported_total = 0;
_Atomic uint64_t g_ede_other_total = 0;

static uint64_t g_rrl_hash_key[2];

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND do { \
    v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32); \
    v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32); \
} while (0)

static uint64_t siphash24(const uint8_t *in, size_t inlen, const uint64_t k[2]) {
    uint64_t v0 = 0x736f6d6570736575ULL ^ k[0];
    uint64_t v1 = 0x646f72616e646f6dULL ^ k[1];
    uint64_t v2 = 0x6c7967656e657261ULL ^ k[0];
    uint64_t v3 = 0x7465646279746573ULL ^ k[1];
    uint64_t b = ((uint64_t)inlen) << 56;
    const uint8_t *end = in + (inlen & ~7);
    for (; in != end; in += 8) {
        uint64_t m; memcpy(&m, in, 8);
        v3 ^= m; SIPROUND; SIPROUND; v0 ^= m;
    }
    uint64_t t = 0;
    switch (inlen & 7) {
        case 7: t |= ((uint64_t)in[6]) << 48; // fallthrough
        case 6: t |= ((uint64_t)in[5]) << 40; // fallthrough
        case 5: t |= ((uint64_t)in[4]) << 32; // fallthrough
        case 4: t |= ((uint64_t)in[3]) << 24; // fallthrough
        case 3: t |= ((uint64_t)in[2]) << 16; // fallthrough
        case 2: t |= ((uint64_t)in[1]) << 8;  // fallthrough
        case 1: t |= ((uint64_t)in[0]);
    }
    b |= t;
    v3 ^= b; SIPROUND; SIPROUND; v0 ^= b;
    v2 ^= 0xff; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static rrl_response_class_t get_rrl_class(const uint8_t *res_buf, size_t res_len) {
  if (res_len < DNS_HEADER_SIZE) return RRL_RESP_ERROR;
  uint8_t rcode = res_buf[3] & 0x0F;
  uint16_t ancount = (res_buf[6] << 8) | res_buf[7];
  if (rcode == 3) return RRL_RESP_NXDOMAIN;
  if (rcode == 0) {
    if (ancount > 0) return RRL_RESP_NOERROR;
    return RRL_RESP_NODATA;
  }
  return RRL_RESP_ERROR;
}

static bool rrl_check(const struct sockaddr_storage *client_addr, rrl_response_class_t cls, const rate_limit_config_t *cfg, bool *out_slip) {
  *out_slip = false;
  if (!cfg || !cfg->configured) return true;

  uint32_t rate = 0;
  switch (cls) {
    case RRL_RESP_NOERROR: rate = cfg->responses_per_second; break;
    case RRL_RESP_NODATA:  rate = cfg->responses_per_second; break;
    case RRL_RESP_NXDOMAIN: rate = cfg->nxdomains_per_second; break;
    case RRL_RESP_ERROR:   rate = cfg->errors_per_second; break;
  }
  if (rate == 0) return true; // 0 means no limit

  char ip_str[INET6_ADDRSTRLEN] = {0};
  if (client_addr->ss_family == AF_INET) {
    inet_ntop(AF_INET, &((const struct sockaddr_in *)client_addr)->sin_addr, ip_str, INET_ADDRSTRLEN);
  } else if (client_addr->ss_family == AF_INET6) {
    inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, ip_str, INET6_ADDRSTRLEN);
  }

  if (cfg->exempt_clients_count > 0) {
    for (int i = 0; i < cfg->exempt_clients_count; i++) {
      if (match_cidr(ip_str, cfg->exempt_clients[i].ip)) return true;
    }
  }

  uint64_t hash = 0;
  uint64_t full_hash = 0;
  if (client_addr->ss_family == AF_INET) {
    uint32_t ip = ((const struct sockaddr_in *)client_addr)->sin_addr.s_addr;
    ip &= htonl(0xFFFFFF00); // /24 mask
    hash = siphash24((const uint8_t *)&ip, 4, g_rrl_hash_key);
    full_hash = hash;
  } else if (client_addr->ss_family == AF_INET6) {
    uint8_t ip6[16];
    memcpy(ip6, &((const struct sockaddr_in6 *)client_addr)->sin6_addr, 16);
    memset(&ip6[7], 0, 9); // /56 mask (7 bytes)
    hash = siphash24(ip6, 16, g_rrl_hash_key);
    full_hash = hash;
  }

  size_t idx = hash & (RRL_TABLE_SIZE - 1);
  rrl_bucket_t *b = &g_rrl_table[idx];
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

  while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) {
#if defined(__x86_64__) || defined(__i386__)
      __asm__ volatile("pause" ::: "memory");
#else
      sched_yield();
#endif
  }

  if (b->client_hash != full_hash) {
    // Hash collision or new entry
    // Only reset if it's older than 1 second to prevent hash-collision DoS
    if (now_ms - b->last_refill_ms[cls] > 1000) {
      b->client_hash = full_hash;
      for (int i = 0; i < 4; i++) {
          b->last_refill_ms[i] = now_ms;
      }
      b->tokens[0] = cfg->responses_per_second;
      b->tokens[1] = cfg->responses_per_second;
      b->tokens[2] = cfg->nxdomains_per_second;
      b->tokens[3] = cfg->errors_per_second;
      b->slip_counter = 0;
    } else {
      // It's a recent collision. Share the limit instead of resetting.
      // This mitigates spoofed IPs from resetting other users' buckets.
    }
  } else {
    uint32_t rates[4] = {
      cfg->responses_per_second,
      cfg->responses_per_second,
      cfg->nxdomains_per_second,
      cfg->errors_per_second
    };
    for(int i=0; i<4; i++) {
      if (rates[i] == 0) continue;
      int64_t elapsed_ms = now_ms - b->last_refill_ms[i];
      if (elapsed_ms > 0) {
        uint64_t add_t = ((uint64_t)elapsed_ms * rates[i]) / 1000;
        if (add_t > 0) {
          b->tokens[i] += (int32_t)add_t;
          if (b->tokens[i] > (int32_t)rates[i]) b->tokens[i] = rates[i];
          b->last_refill_ms[i] = now_ms;
        }
      }
    }
  }

  bool allow = false;
  if (b->tokens[cls] > 0) {
    b->tokens[cls]--;
    allow = true;
  } else {
    b->slip_counter++;
    if (cfg->slip > 0 && (b->slip_counter % cfg->slip) == 0) {
      *out_slip = true;
    }
  }
  atomic_flag_clear_explicit(&b->lock, memory_order_release);

  if (!allow && !*out_slip) {
    atomic_fetch_add_explicit(&g_rrl_dropped_total, 1, memory_order_relaxed);
  } else if (!allow && *out_slip) {
    atomic_fetch_add_explicit(&g_rrl_slip_total, 1, memory_order_relaxed);
  }

  if (cfg->log_only && !allow) {
    syslog(LOG_INFO, "[RRL] would rate-limit %s (log-only)", ip_str);
    return true; // allow anyway
  }

  return allow;
}

typedef struct {
  char *name;
  char **match_clients;
  int match_clients_count;
  zone_db_entry_t **entries;
  size_t zone_count;
} view_snapshot_t;

typedef struct {
  view_snapshot_t *views;
  size_t view_count;
  _Atomic(int) reader_count;
} zone_db_snapshot_t;
static _Atomic(zone_db_snapshot_t *) g_zone_db_active = ATOMIC_VAR_INIT(NULL);
static config_rcu_t g_config_db;
int g_control_kq = -1;
int g_cwd_fd = -1;
static const char *g_config_path = NULL;
static _Atomic int g_bound_workers = 0;
#define MAX_ZONE_AXFR 4

// Frontend/Backend IPC用グローバル変数
static int g_udp_fds[MAX_BIND_ADDRS];
static int g_num_udp_fds = 0;
static int (*g_ipc_fds)[2] = NULL;
char g_startup_cwd[PATH_MAX] = "";
static int g_num_ipc = 0;
static int g_notify_ipc[2];
static int g_control_sock = -1;
static _Atomic(bool) g_frontend_alive = true;

time_t g_boot_time = 0;
time_t g_last_configured_time = 0;
_Atomic int g_xfers_running = ATOMIC_VAR_INIT(0);
_Atomic int g_tcp_clients = ATOMIC_VAR_INIT(0);
_Atomic int g_tcp_high_water = ATOMIC_VAR_INIT(0);

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

static resp_log_entry_t g_resp_log_ring[RESP_LOG_RING_SIZE];
static _Atomic uint64_t g_resp_log_tail = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t g_resp_log_head = ATOMIC_VAR_INIT(0);

static inline void inc_tcp_clients(void) {
    int current = atomic_fetch_add_explicit(&g_tcp_clients, 1, memory_order_relaxed) + 1;
    int high = atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed);
    while (current > high) {
        if (atomic_compare_exchange_weak_explicit(&g_tcp_high_water, &high, current, memory_order_relaxed, memory_order_relaxed)) {
            break;
        }
    }
}
static inline void dec_tcp_clients(void) {
    atomic_fetch_sub_explicit(&g_tcp_clients, 1, memory_order_relaxed);
}


// Broker
static int g_broker_sock = -1;
static void start_connect_broker(void) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return;
  pid_t pid = fork();
  if (pid < 0)
    return;
  if (pid == 0) {
    close(sv[0]);
    struct {
      int family;
      int type;
      struct sockaddr_storage addr;
    } req;
    while (recv(sv[1], &req, sizeof(req), MSG_WAITALL) == sizeof(req)) {
      int sock = socket(req.family, req.type, 0);
      if (sock >= 0) {
        size_t addr_len = (req.family == AF_INET) ? sizeof(struct sockaddr_in)
                                                  : sizeof(struct sockaddr_in6);
        if (connect(sock, (struct sockaddr *)&req.addr, addr_len) == 0) {
          struct msghdr msg = {0};
          struct cmsghdr *cmsg;
          char buf[CMSG_SPACE(sizeof(int))];
          char data[1] = {0};
          struct iovec io = {.iov_base = data, .iov_len = 1};
          msg.msg_iov = &io;
          msg.msg_iovlen = 1;
          msg.msg_control = buf;
          msg.msg_controllen = sizeof(buf);
          cmsg = CMSG_FIRSTHDR(&msg);
          cmsg->cmsg_level = SOL_SOCKET;
          cmsg->cmsg_type = SCM_RIGHTS;
          cmsg->cmsg_len = CMSG_LEN(sizeof(int));
          *(int *)CMSG_DATA(cmsg) = sock;
          sendmsg(sv[1], &msg, 0);
        } else {
          char data[1] = {1};
          struct iovec io = {.iov_base = data, .iov_len = 1};
          struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1};
          sendmsg(sv[1], &msg, 0);
        }
        close(sock);
      } else {
        char data[1] = {1};
        struct iovec io = {.iov_base = data, .iov_len = 1};
        struct msghdr msg = {.msg_iov = &io, .msg_iovlen = 1};
        sendmsg(sv[1], &msg, 0);
      }
    }
    exit(0);
  }
  close(sv[1]);
  g_broker_sock = sv[0];
}

static int broker_connect(int family, int type, struct sockaddr *addr,
                          size_t addr_len) {
  if (g_broker_sock < 0)
    return -1;
  struct {
    int family;
    int type;
    struct sockaddr_storage addr;
  } req;
  memset(&req, 0, sizeof(req));
  req.family = family;
  req.type = type;
  memcpy(&req.addr, addr, addr_len);
  static pthread_mutex_t broker_lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&broker_lock);
  if (send(g_broker_sock, &req, sizeof(req), 0) != sizeof(req)) {
    pthread_mutex_unlock(&broker_lock);
    return -1;
  }
  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  char buf[CMSG_SPACE(sizeof(int))];
  char data[1] = {1};
  struct iovec io = {.iov_base = data, .iov_len = 1};
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);
  if (recvmsg(g_broker_sock, &msg, 0) < 0 || data[0] != 0) {
    pthread_mutex_unlock(&broker_lock);
    return -1;
  }
  int fd = -1;
  cmsg = CMSG_FIRSTHDR(&msg);
  if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
    fd = *(int *)CMSG_DATA(cmsg);
  pthread_mutex_unlock(&broker_lock);
  return fd;
}

// ============================================================================
// Capsicum capability-mode support
// ============================================================================
typedef struct dir_fd_entry {
  char *dirpath;
  int fd;
  struct dir_fd_entry *next;
} dir_fd_entry_t;
static dir_fd_entry_t *g_dir_fd_table = NULL;
static pthread_mutex_t g_dir_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool g_capsicum_enabled = false;

static bool split_path_for_openat(const char *path, char *dir_out,
                                  size_t dir_out_sz, char *base_out,
                                  size_t base_out_sz) {
  if (!path || !*path)
    return false;
  size_t plen = strlen(path);
  if (plen >= PATH_MAX)
    return false;
  const char *slash = strrchr(path, '/');
  if (!slash) {
    if (strlen(path) >= base_out_sz)
      return false;
    if (snprintf(dir_out, dir_out_sz, ".") >= (int)dir_out_sz)
      return false;
    memcpy(base_out, path, plen + 1);
  } else {
    size_t dir_len = (size_t)(slash - path);
    if (dir_len == 0)
      dir_len = 1;
    if (dir_len >= dir_out_sz)
      return false;
    memcpy(dir_out, path, dir_len);
    dir_out[dir_len] = '\0';
    const char *base = slash + 1;
    size_t base_len = strlen(base);
    if (base_len == 0 || base_len >= base_out_sz)
      return false;
    memcpy(base_out, base, base_len + 1);
  }
  if (strcmp(base_out, "..") == 0 || strcmp(base_out, ".") == 0)
    return false;
  if (strstr(base_out, "/") != NULL)
    return false;
  return true;
}

static int get_or_open_dir_fd(const char *dirpath, bool writable) {
  pthread_mutex_lock(&g_dir_fd_lock);
  for (dir_fd_entry_t *e = g_dir_fd_table; e; e = e->next) {
    if (strcmp(e->dirpath, dirpath) == 0) {
      int fd = e->fd;
      pthread_mutex_unlock(&g_dir_fd_lock);
      return fd;
    }
  }
  if (atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire)) {
    pthread_mutex_unlock(&g_dir_fd_lock);
    errno = ENOTCAPABLE;
    return -1;
  }
  int fd;
  if (dirpath[0] == '/')
    fd = open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  else
    fd = (g_cwd_fd >= 0)
             ? openat(g_cwd_fd, dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY)
             : open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  if (fd < 0) {
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  cap_rights_t rights;
  if (writable)
    cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_CREATE,
                    CAP_FSTAT, CAP_FSTATFS, CAP_FTRUNCATE, CAP_SEEK,
                    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET, CAP_UNLINKAT,
                    CAP_FCNTL);
  else
    cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_FSTATFS,
                    CAP_SEEK, CAP_FCNTL);
  if (cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) {
    close(fd);
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  dir_fd_entry_t *e = calloc(1, sizeof(*e));
  if (!e) {
    close(fd);
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  e->dirpath = strdup(dirpath);
  if (!e->dirpath) {
    free(e);
    close(fd);
    pthread_mutex_unlock(&g_dir_fd_lock);
    return -1;
  }
  e->fd = fd;
  e->next = g_dir_fd_table;
  g_dir_fd_table = e;
  pthread_mutex_unlock(&g_dir_fd_lock);
  return fd;
}

#ifndef O_RESOLVE_BENEATH
#define O_RESOLVE_BENEATH 0
#endif

int open_via_dir_cache(const char *path, int flags, mode_t mode,
                              bool writable) {
  char dirbuf[PATH_MAX], basebuf[PATH_MAX];
  if (!split_path_for_openat(path, dirbuf, sizeof(dirbuf), basebuf,
                             sizeof(basebuf))) {
    errno = EINVAL;
    return -1;
  }
  int dfd = get_or_open_dir_fd(dirbuf, writable);
  if (dfd < 0)
    return -1;
  return openat(dfd, basebuf, flags | O_RESOLVE_BENEATH, mode);
}

static int renameat_via_dir_cache(const char *old_path, const char *new_path) {
  char odir[PATH_MAX], obase[PATH_MAX], ndir[PATH_MAX], nbase[PATH_MAX];
  if (!split_path_for_openat(old_path, odir, sizeof(odir), obase,
                             sizeof(obase)))
    return -1;
  if (!split_path_for_openat(new_path, ndir, sizeof(ndir), nbase,
                             sizeof(nbase)))
    return -1;
  int ofd = get_or_open_dir_fd(odir, true);
  int nfd = get_or_open_dir_fd(ndir, true);
  if (ofd < 0 || nfd < 0)
    return -1;
  return renameat(ofd, obase, nfd, nbase);
}

static void limit_server_socket_rights(int fd, bool is_listening_tcp) {
  cap_rights_t rights;
  if (is_listening_tcp)
    cap_rights_init(&rights, CAP_ACCEPT, CAP_RECV, CAP_SEND, CAP_FCNTL,
                    CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN,
                    CAP_GETSOCKNAME, CAP_GETPEERNAME);
  else
    cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_CONNECT, CAP_EVENT,
                    CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN,
                    CAP_GETSOCKNAME, CAP_GETPEERNAME);
  cap_rights_limit(fd, &rights);
}

static void limit_client_socket_rights(int fd) {
  cap_rights_t rights;
  cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_FCNTL, CAP_EVENT,
                  CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_SHUTDOWN, CAP_GETSOCKNAME,
                  CAP_GETPEERNAME);
  cap_rights_limit(fd, &rights);
}

static void enter_capsicum_sandbox(void) {
#ifndef SANITIZER_BUILD
  int trapmode = PROC_TRAPCAP_CTL_ENABLE;
  procctl(P_PID, 0, PROC_TRAPCAP_CTL, &trapmode);
  if (cap_enter() != 0) {
    if (errno == ENOSYS)
      return;
    exit(EXIT_FAILURE);
  }
#endif
  atomic_store_explicit(&g_capsicum_enabled, true, memory_order_release);
}

// ============================================================================
// 3. パーサー・各種ユーティリティ
// ============================================================================

zone_db_snapshot_t *acquire_zone_snapshot(void) {
  zone_db_snapshot_t *snap = NULL;
  do {
    snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    if (!snap)
      return NULL;
    atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
    if (snap == atomic_load_explicit(&g_zone_db_active, memory_order_acquire))
      break;
    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
  } while (1);
  return snap;
}

void release_zone_snapshot(zone_db_snapshot_t *snap) {
  if (snap)
    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
}

static zone_config_t *find_zone_config_in_view(server_config_t *cfg,
                                               const char *view_name,
                                               const char *domain) {
  if (!cfg || !view_name || !domain) return NULL;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    if (strcasecmp(v->name, view_name) != 0) continue;
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (strcasecmp(z->domain, domain) == 0) return z;
    }
    return NULL;
  }
  return NULL;
}

typedef struct {
  zone_db_entry_t *entry;
  zone_config_t *zcfg;
  const char *view_name;
} zone_lookup_result_t;

// domainに一致するゾーンを、view_nameが指定されていればそのview内だけを、
// NULLなら全view横断で検索する。戻り値は一致したview数(0/1/2以上)。
// 1件のみ一致した場合にresultへ結果を格納する。
static int lookup_zone_across_views(zone_db_snapshot_t *snap, server_config_t *cfg,
                                    const char *domain, const char *view_name,
                                    zone_lookup_result_t *result) {
  int matches = 0;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    if (view_name && strcasecmp(v->name, view_name) != 0) continue;
    zone_config_t *zcfg = NULL;
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (strcasecmp(z->domain, domain) == 0) { zcfg = z; break; }
    }
    if (!zcfg) continue;

    zone_db_entry_t *entry = NULL;
    if (snap) {
      for (size_t sv = 0; sv < snap->view_count; sv++) {
        if (strcasecmp(snap->views[sv].name, v->name) != 0) continue;
        for (size_t i = 0; i < snap->views[sv].zone_count; i++) {
          if (strcasecmp(snap->views[sv].entries[i]->domain, domain) == 0) {
            entry = snap->views[sv].entries[i];
            break;
          }
        }
        break;
      }
    }
    matches++;
    if (matches == 1) {
      result->entry = entry;
      result->zcfg = zcfg;
      result->view_name = v->name;
    }
  }
  return matches;
}

zone_db_entry_t *snapshot_get_zone(zone_db_snapshot_t *snap, const char *domain) {
  if (!snap) return NULL;
  for (size_t v = 0; v < snap->view_count; v++) {
    for (size_t i = 0; i < snap->views[v].zone_count; i++) {
      if (strcasecmp(snap->views[v].entries[i]->domain, domain) == 0) {
        return snap->views[v].entries[i];
      }
    }
  }
  return NULL;
}

static inline void rcu_exponential_backoff(int *retries, useconds_t *sleep_time) {
  if (*retries < 100) {
    sched_yield();
  } else {
    usleep(*sleep_time);
    if (*sleep_time < 100000) *sleep_time *= 2;
  }
  (*retries)++;
}

static void wait_for_snapshot_readers(zone_db_snapshot_t *snap) {
  int retries = 0;
  useconds_t sleep_time = 1;
  while (atomic_load_explicit(&snap->reader_count, memory_order_acquire) > 0) {
    rcu_exponential_backoff(&retries, &sleep_time);
    if (sleep_time >= 100000 && (retries % 10) == 0) {
      syslog(LOG_WARNING, "[RCU] wait_for_snapshot_readers stalled");
    }
#if defined(SANITIZER_BUILD)
    if (retries > 170) {
      syslog(LOG_ERR, "[RCU] FATAL: reader_count leak detected (stalled > 5s). Aborting.");
      abort();
    }
#endif
  }
}

static zone_db_entry_t *create_new_zone_entry(const char *domain, const char *view_name) {
  zone_db_entry_t *z = calloc(1, sizeof(zone_db_entry_t));
  if (!z) return NULL;
  atomic_init(&z->active_axfr, 0);
  atomic_init(&z->snapshot_refs, 1);
  strncpy(z->domain, domain, sizeof(z->domain) - 1);
  z->domain[sizeof(z->domain) - 1] = 0;
  strncpy(z->view_name, view_name, sizeof(z->view_name) - 1);
  z->view_name[sizeof(z->view_name) - 1] = 0;
  pthread_mutex_init(&z->writer_lock, NULL);
  pthread_mutex_init(&z->ixfr_history.lock, NULL);
  z->ixfr_history.count = 0;
  z->ixfr_history.head = 0;
  zone_arena_init(&z->rcu.arena_a);
  zone_arena_init(&z->rcu.arena_b);
  atomic_init(&z->rcu.active, &z->rcu.arena_a);
  return z;
}

static void wait_for_readers(zone_arena_t *arena) {
  int retries = 0;
  useconds_t sleep_time = 1;
  while (atomic_load_explicit(&arena->reader_count, memory_order_acquire) > 0) {
    rcu_exponential_backoff(&retries, &sleep_time);
    if (sleep_time >= 100000 && (retries % 10) == 0)
      syslog(LOG_WARNING, "[RCU] wait_for_readers stalled");
  }
}

void free_zone_db_entry(zone_db_entry_t *entry) {
  if (!entry) return;
  if (entry->groups) {
    for (int i = 0; i < entry->group_count; i++) {
      free(entry->groups[i]);
    }
    free(entry->groups);
  }
  int axfr_retries = 0;
  useconds_t axfr_sleep = 1;
  while (atomic_load(&entry->active_axfr) > 0) {
    rcu_exponential_backoff(&axfr_retries, &axfr_sleep);
  }
  wait_for_readers(&entry->rcu.arena_a);
  wait_for_readers(&entry->rcu.arena_b);
  pthread_mutex_destroy(&entry->writer_lock);
  pthread_mutex_destroy(&entry->ixfr_history.lock);
  for (int i = 0; i < entry->ixfr_history.count; i++) {
    int idx = (entry->ixfr_history.head + MAX_IXFR_HISTORY - entry->ixfr_history.count + i) % MAX_IXFR_HISTORY;
    ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
    if (txn) {
      if (txn->deleted) free(txn->deleted);
      if (txn->added) free(txn->added);
      free(txn);
    }
  }
  zone_arena_t *arenas[2] = {&entry->rcu.arena_a, &entry->rcu.arena_b};
  for (int i = 0; i < 2; i++) {
    zone_arena_t *a = arenas[i];
    for (int p = 0; p < a->data_pool_count; p++) {
      if (a->data_pools[p]) free(a->data_pools[p]);
    }
    zone_arena_free_include_buffers(a);
    if (a->records) free(a->records);
    if (a->hash_table) free(a->hash_table);
  }
  free(entry);
}

static void *gc_snapshot_thread(void *arg) {
  zone_db_snapshot_t *snap = (zone_db_snapshot_t *)arg;
  wait_for_snapshot_readers(snap);
  for (size_t v = 0; v < snap->view_count; v++) {
    for (size_t i = 0; i < snap->views[v].zone_count; i++) {
      zone_db_entry_t *entry = snap->views[v].entries[i];
      if (atomic_fetch_sub_explicit(&entry->snapshot_refs, 1, memory_order_acq_rel) == 1) {
        syslog(LOG_INFO, "[GC] Freeing deleted zone '%s'", entry->domain);
        free_zone_db_entry(entry);
      }
    }
    free(snap->views[v].entries);
    free(snap->views[v].name);
    if (snap->views[v].match_clients) {
      for (int i = 0; i < snap->views[v].match_clients_count; i++) {
        free(snap->views[v].match_clients[i]);
      }
      free(snap->views[v].match_clients);
    }
  }
  free(snap->views);
  free(snap);
  return NULL;
}

static void free_ixfr_txn(ixfr_txn_t *txn) {
  if (!txn) return;
  zone_arena_destroy(&txn->arena);
  if (txn->deleted) free(txn->deleted);
  if (txn->added) free(txn->added);
  free(txn);
}

static void compute_ixfr_diff(zone_db_entry_t *entry, zone_arena_t *old_arena, zone_arena_t *new_arena) {
  if (!old_arena->hash_table || !new_arena->hash_table) return;
  uint32_t old_serial = 0, new_serial = 0;
  for (size_t i = 0; i < old_arena->count; i++) {
    if (old_arena->records[i].type_code == 6 && old_arena->records[i].rdata_count >= 3 && old_arena->records[i].rdata[2]) {
      old_serial = strtoul(old_arena->records[i].rdata[2], NULL, 10);
      break;
    }
  }
  for (size_t i = 0; i < new_arena->count; i++) {
    if (new_arena->records[i].type_code == 6 && new_arena->records[i].rdata_count >= 3 && new_arena->records[i].rdata[2]) {
      new_serial = strtoul(new_arena->records[i].rdata[2], NULL, 10);
      break;
    }
  }
  if (old_serial == 0 || new_serial == 0) return;
  if ((int32_t)(new_serial - old_serial) <= 0) return;

  size_t del_count = 0, add_count = 0;
  for (size_t i = 0; i < old_arena->count; i++) {
    if (!record_exists_in_arena(new_arena, &old_arena->records[i])) del_count++;
  }
  for (size_t i = 0; i < new_arena->count; i++) {
    if (!record_exists_in_arena(old_arena, &new_arena->records[i])) add_count++;
  }
  
  if (del_count + add_count > 10000) return;
  
  ixfr_txn_t *txn = malloc(sizeof(ixfr_txn_t));
  if (!txn) return;
  memset(txn, 0, sizeof(ixfr_txn_t));

  if (del_count > SIZE_MAX / sizeof(dns_record_t) || add_count > SIZE_MAX / sizeof(dns_record_t)) {
      free(txn);
      return;
  }
  if (del_count > 0) {
    txn->deleted = malloc(sizeof(dns_record_t) * del_count);
    if (!txn->deleted) { free(txn); return; }
  }
  if (add_count > 0) {
    txn->added = malloc(sizeof(dns_record_t) * add_count);
    if (!txn->added) { if (txn->deleted) free(txn->deleted); free(txn); return; }
  }

  txn->old_serial = old_serial;
  txn->new_serial = new_serial;
  txn->deleted_count = del_count;
  txn->added_count = add_count;
  atomic_init(&txn->ref_count, 1);
  zone_arena_init(&txn->arena);

  int d_idx = 0;
  for (size_t i = 0; i < old_arena->count; i++) {
    if (!record_exists_in_arena(new_arena, &old_arena->records[i])) {
      txn->deleted[d_idx] = old_arena->records[i];
      txn->deleted[d_idx].name = arena_strdup(&txn->arena, old_arena->records[i].name);
      txn->deleted[d_idx].ttl = arena_strdup(&txn->arena, old_arena->records[i].ttl);
      txn->deleted[d_idx].class_str = arena_strdup(&txn->arena, old_arena->records[i].class_str);
      txn->deleted[d_idx].type = arena_strdup(&txn->arena, old_arena->records[i].type);
      for (int j = 0; j < old_arena->records[i].rdata_count; j++) {
         txn->deleted[d_idx].rdata[j] = arena_strdup(&txn->arena, old_arena->records[i].rdata[j]);
      }
      if (old_arena->records[i].generic_len > 0) {
         txn->deleted[d_idx].generic_data = arena_alloc(&txn->arena, old_arena->records[i].generic_len);
         memcpy(txn->deleted[d_idx].generic_data, old_arena->records[i].generic_data, old_arena->records[i].generic_len);
      }
      d_idx++;
    }
  }

  int a_idx = 0;
  for (size_t i = 0; i < new_arena->count; i++) {
    if (!record_exists_in_arena(old_arena, &new_arena->records[i])) {
      txn->added[a_idx] = new_arena->records[i];
      txn->added[a_idx].name = arena_strdup(&txn->arena, new_arena->records[i].name);
      txn->added[a_idx].ttl = arena_strdup(&txn->arena, new_arena->records[i].ttl);
      txn->added[a_idx].class_str = arena_strdup(&txn->arena, new_arena->records[i].class_str);
      txn->added[a_idx].type = arena_strdup(&txn->arena, new_arena->records[i].type);
      for (int j = 0; j < new_arena->records[i].rdata_count; j++) {
         txn->added[a_idx].rdata[j] = arena_strdup(&txn->arena, new_arena->records[i].rdata[j]);
      }
      if (new_arena->records[i].generic_len > 0) {
         txn->added[a_idx].generic_data = arena_alloc(&txn->arena, new_arena->records[i].generic_len);
         memcpy(txn->added[a_idx].generic_data, new_arena->records[i].generic_data, new_arena->records[i].generic_len);
      }
      a_idx++;
    }
  }

  pthread_mutex_lock(&entry->ixfr_history.lock);
  
  int new_head = entry->ixfr_history.head;
  if (entry->ixfr_history.count == MAX_IXFR_HISTORY) {
    ixfr_txn_t *old_txn = entry->ixfr_history.entries[new_head];
    if (old_txn) {
      if (atomic_fetch_sub_explicit(&old_txn->ref_count, 1, memory_order_acq_rel) == 1) {
        free_ixfr_txn(old_txn);
      }
    }
  } else {
    entry->ixfr_history.count++;
  }

  entry->ixfr_history.entries[new_head] = txn;
  entry->ixfr_history.head = (new_head + 1) % MAX_IXFR_HISTORY;
  pthread_mutex_unlock(&entry->ixfr_history.lock);
}


static char *server_load_file_cb(parse_context_t *ctx, const char *rel_path) {
    (void)ctx;
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
    int fd = open_via_dir_cache(rel_path, O_RDONLY | O_NOFOLLOW, 0, false);
    if (fd < 0) {
        return NULL;
    }
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0 || len > KARIDNS_MAX_CONFIG_FILE_SIZE) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t read_len = fread(buf, 1, len, f);
    buf[read_len] = '\0';
    fclose(f);
    return buf;
}

typedef enum {
    RELOAD_OK = 0,
    RELOAD_ERR_FILE_READ = -1,
    RELOAD_ERR_PARSE = -2,
    RELOAD_ERR_MISSING_SOA = -3,
} reload_result_t;

static reload_result_t reload_master_zone(zone_db_entry_t *entry, const char *file) {
  char *buf = read_entire_file(file);
  if (!buf) {
    syslog(LOG_ERR, "[Zone] Failed to read file '%s' for zone '%s'.", file, entry->domain);
    return RELOAD_ERR_FILE_READ;
  }
  pthread_mutex_lock(&entry->writer_lock);
  zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
  wait_for_readers(z_standby);

  zone_arena_free_include_buffers(z_standby);
  z_standby->count = 0;
  z_standby->data_pool_count = 0;
  z_standby->current_pool_cap = 0;
  z_standby->current_pool_idx = 0;
  z_standby->file_buf_count = 0;
  z_standby->file_bufs[z_standby->file_buf_count] = buf;
  z_standby->file_paths[z_standby->file_buf_count] = strdup(file);
  z_standby->file_buf_count++;

  char *root_ttl = NULL;
  char *visited_paths[16];
  
  char abs_file[PATH_MAX];
  if (file[0] != '/' && g_startup_cwd[0] != '\0') {
      snprintf(abs_file, sizeof(abs_file), "%s/%s", g_startup_cwd, file);
  } else {
      snprintf(abs_file, sizeof(abs_file), "%s", file);
  }
  
  char *root_path = strdup(abs_file);

  parse_error_t parse_err = {0};
  parse_context_t ctx = {0};
  ctx.default_origin = entry->domain;
  ctx.base_dir = get_base_dir(root_path);
  ctx.is_standalone_mode = false;
  ctx.load_file_cb = server_load_file_cb;
  ctx.shared_ttl_io = &root_ttl;
  ctx.visited_paths = visited_paths;
  ctx.visited_cap = 16;
  ctx.visited_count = 1;
  ctx.visited_paths[0] = root_path;
  ctx.err_out = &parse_err;

  int count = parse_zone_fast(buf, strlen(buf), z_standby, &ctx);
  free((void*)ctx.base_dir);
  free(root_path);

  if (count < 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      if (parse_err.error_message) {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s': %s (offset=%zu, file=%s)",
                 entry->domain, file, parse_err.error_message,
                 parse_err.error_offset,
                 parse_err.file_path ? parse_err.file_path : file);
      } else {
          syslog(LOG_ERR, "[Zone] Parse error reloading zone '%s' from '%s'", entry->domain, file);
      }
      return RELOAD_ERR_PARSE;
  }

  if (build_zone_index(z_standby) != 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after reload for '%s'", entry->domain);
      return RELOAD_ERR_PARSE;
  }
  if (validate_zone_dname(z_standby, &parse_err) < 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] DNAME validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  bool has_soa = false;
  uint32_t hash = calc_fnv1a_str(entry->domain);
  size_t idx = hash & (z_standby->hash_size - 1);
  for (int i = z_standby->hash_table[idx]; i != -1; i = z_standby->records[i].next_record) {
      if (z_standby->records[i].type_code == 6 && strcasecmp(z_standby->records[i].name, entry->domain) == 0) {
          has_soa = true; break;
      }
  }
  if (!has_soa) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Missing SOA reloading zone '%s' from '%s'", entry->domain, file);
      return RELOAD_ERR_MISSING_SOA;
  }

  compute_ixfr_diff(entry, z_active, z_standby);
  atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
  pthread_mutex_unlock(&entry->writer_lock);
  syslog(LOG_NOTICE, "[Zone] Reload successful for '%s'", entry->domain);
  return RELOAD_OK;
}

void free_catalog_member_ids(catalog_member_id_t *arr, int count) {
  if (!arr) return;
  for (int i = 0; i < count; i++) {
    if (arr[i].groups) {
      for (int j = 0; j < arr[i].group_count; j++) {
        free(arr[i].groups[j]);
      }
      free(arr[i].groups);
    }
  }
  free(arr);
}

zone_db_entry_t *find_catalog_parent_in_snapshot(view_snapshot_t *view, const char *catalog_domain) {
    if (!view || !catalog_domain) return NULL;
    for (size_t i = 0; i < view->zone_count; i++) {
        if (strcasecmp(view->entries[i]->domain, catalog_domain) == 0) {
            return view->entries[i];
        }
    }
    return NULL;
}

void remove_member_from_catalog_bookkeeping(zone_db_entry_t *catalog_entry, const char *unique_id, const char *domain) {
    if (!catalog_entry || !catalog_entry->catalog_members) return;
    for (int i = 0; i < catalog_entry->catalog_member_count; i++) {
        if (strcasecmp(catalog_entry->catalog_members[i].domain, domain) == 0 && 
            strcmp(catalog_entry->catalog_members[i].unique_id, unique_id) == 0) {
            
            // Explicitly free the dynamically allocated `groups` strings of the targeted element
            if (catalog_entry->catalog_members[i].groups) {
                for (int g = 0; g < catalog_entry->catalog_members[i].group_count; g++) {
                    free(catalog_entry->catalog_members[i].groups[g]);
                }
                free(catalog_entry->catalog_members[i].groups);
            }
            
            // Shift the remaining elements forward
            int elements_after = catalog_entry->catalog_member_count - i - 1;
            if (elements_after > 0) {
                memmove(&catalog_entry->catalog_members[i], 
                        &catalog_entry->catalog_members[i + 1], 
                        elements_after * sizeof(catalog_member_id_t));
            }
            catalog_entry->catalog_member_count--;
            break;
        }
    }
}

zone_db_snapshot_t *rebuild_zone_db_snapshot(
    server_config_t *active_config, 
    const char *catalog_view_name,
    zone_db_entry_t *catalog_entry_to_update,
    zone_config_t *catalog_cfg,
    catalog_member_id_t *new_desired_members, int new_desired_count) 
{
    pthread_mutex_lock(&g_zone_db_rebuild_lock);
    zone_db_snapshot_t *old_snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    zone_db_snapshot_t *new_snap = calloc(1, sizeof(zone_db_snapshot_t));
    
    if (active_config) {
        // MODE: Full Config Reload
        
        int max_valid_members = 0;
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (entry->catalog_member_count > 0) {
                        max_valid_members += entry->catalog_member_count;
                    }
                }
            }
        }
        catalog_member_id_t *valid_members = max_valid_members > 0 ? calloc(max_valid_members, sizeof(catalog_member_id_t)) : NULL;
        int valid_member_count = 0;
        
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (entry->catalog_member_count > 0) {
                        zone_config_t *zcfg = find_zone_config_in_view(active_config, entry->view_name, entry->domain);
                        if (zcfg && zcfg->is_catalog) {
                            for (int k = 0; k < entry->catalog_member_count; k++) {
                                valid_members[valid_member_count++] = entry->catalog_members[k];
                            }
                        } else {
                            free_catalog_member_ids(entry->catalog_members, entry->catalog_member_count);
                            entry->catalog_members = NULL;
                            entry->catalog_member_count = 0;
                            
                            int p = 0;
                            while (p < g_pending_coo_count) {
                                if (strcasecmp(g_pending_coo[p].old_catalog, entry->domain) == 0) {
                                    if (p < g_pending_coo_count - 1) {
                                        g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
                                    }
                                    g_pending_coo_count--;
                                } else {
                                    p++;
                                }
                            }
                        }
                    }
                }
            }
        }

        int view_count = 0;
        for (view_config_t *v = active_config->views; v; v = v->next) view_count++;
        
        new_snap->view_count = view_count;
        new_snap->views = calloc(view_count, sizeof(view_snapshot_t));
        atomic_init(&new_snap->reader_count, 0);

        int vidx = 0;
        for (view_config_t *v = active_config->views; v; v = v->next, vidx++) {
            view_snapshot_t *vs = &new_snap->views[vidx];
            vs->name = strdup(v->name);
            vs->match_clients_count = v->match_clients_count;
            if (v->match_clients_count > 0) {
                vs->match_clients = calloc(v->match_clients_count, sizeof(char *));
                for (int i = 0; i < v->match_clients_count; i++) {
                    vs->match_clients[i] = strdup(v->match_clients[i]);
                }
            } else {
                vs->match_clients = NULL;
            }

            int static_count = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) static_count++;
            
            int dynamic_count = 0;
            if (old_snap) {
                for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                    if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                        for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                            zone_db_entry_t *entry = old_snap->views[ov].entries[oi];
                            if (entry->is_catalog_member) {
                                bool is_valid = false;
                                for (int k = 0; k < valid_member_count; k++) {
                                    if (strcasecmp(valid_members[k].domain, entry->domain) == 0 &&
                                        strcmp(valid_members[k].unique_id, entry->catalog_member_unique_id) == 0) {
                                        is_valid = true; break;
                                    }
                                }
                                if (is_valid) {
                                    bool overridden = false;
                                    for (zone_config_t *z = v->zones; z; z = z->next) {
                                        if (strcasecmp(z->domain, entry->domain) == 0) {
                                            overridden = true; break;
                                        }
                                    }
                                    if (!overridden) dynamic_count++;
                                }
                            }
                        }
                        break;
                    }
                }
            }

            vs->zone_count = static_count + dynamic_count;
            vs->entries = calloc(vs->zone_count, sizeof(zone_db_entry_t *));
            
            int zidx = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) {
                zone_db_entry_t *entry = NULL;
                if (old_snap) {
                    for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                        if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                            for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                                if (strcasecmp(old_snap->views[ov].entries[oi]->domain, z->domain) == 0) {
                                    entry = old_snap->views[ov].entries[oi];
                                    atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
                if (!entry) {
                    zone_db_entry_t *create_new_zone_entry(const char *domain, const char *view_name);
                    entry = create_new_zone_entry(z->domain, v->name);
                    if (entry && z->type && (strcasecmp(z->type, "master") == 0 || strcasecmp(z->type, "primary") == 0) && z->file) {
                        reload_master_zone(entry, z->file);
                    }
                }
                vs->entries[zidx++] = entry;
            }

            if (old_snap) {
                for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                    if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                        for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                            zone_db_entry_t *entry = old_snap->views[ov].entries[oi];
                            if (entry->is_catalog_member) {
                                bool is_valid = false;
                                for (int k = 0; k < valid_member_count; k++) {
                                    if (strcasecmp(valid_members[k].domain, entry->domain) == 0 &&
                                        strcmp(valid_members[k].unique_id, entry->catalog_member_unique_id) == 0) {
                                        is_valid = true; break;
                                    }
                                }
                                if (is_valid) {
                                    bool overridden = false;
                                    for (zone_config_t *z = v->zones; z; z = z->next) {
                                        if (strcasecmp(z->domain, entry->domain) == 0) {
                                            overridden = true; break;
                                        }
                                    }
                                    if (!overridden) {
                                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                                        vs->entries[zidx++] = entry;
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        if (valid_members) free(valid_members);

    } else {
        // MODE: Catalog Delta Update
        
        // Step A: Update Pending CoO Intentions (acting as $OLDCATZ)
        if (catalog_entry_to_update) {
            int p = 0;
            while (p < g_pending_coo_count) {
                if (strcasecmp(g_pending_coo[p].old_catalog, catalog_entry_to_update->domain) == 0) {
                    if (p < g_pending_coo_count - 1) {
                        g_pending_coo[p] = g_pending_coo[g_pending_coo_count - 1];
                    }
                    g_pending_coo_count--;
                } else {
                    p++;
                }
            }
            for (int i = 0; i < new_desired_count; i++) {
                if (strlen(new_desired_members[i].coo_target) > 0) {
                    if (g_pending_coo_count >= g_pending_coo_capacity) {
                        g_pending_coo_capacity = g_pending_coo_capacity == 0 ? 16 : g_pending_coo_capacity * 2;
                        g_pending_coo = realloc(g_pending_coo, g_pending_coo_capacity * sizeof(pending_coo_t));
                    }
                    strncpy(g_pending_coo[g_pending_coo_count].domain, new_desired_members[i].domain, 255);
                    strncpy(g_pending_coo[g_pending_coo_count].old_catalog, catalog_entry_to_update->domain, 255);
                    strncpy(g_pending_coo[g_pending_coo_count].new_catalog, new_desired_members[i].coo_target, 255);
                    g_pending_coo_count++;
                }
            }
        }

        int added_count = 0;
        int removed_count = 0;
        catalog_member_id_t *added_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *removed_members = calloc(catalog_entry_to_update->catalog_member_count > 0 ? catalog_entry_to_update->catalog_member_count : 1, sizeof(catalog_member_id_t));
        catalog_member_id_t *coo_evicted_members = calloc(new_desired_count > 0 ? new_desired_count : 1, sizeof(catalog_member_id_t));
        int coo_evicted_count = 0;

        int filtered_count = 0;
        view_snapshot_t *target_view = NULL;
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                if (strcasecmp(old_snap->views[v].name, catalog_view_name) == 0) {
                    target_view = &old_snap->views[v];
                    break;
                }
            }
        }

        for (int i = 0; i < new_desired_count; i++) {
            bool found = false;
            for (int j = 0; j < catalog_entry_to_update->catalog_member_count; j++) {
                if (strcasecmp(new_desired_members[i].domain, catalog_entry_to_update->catalog_members[j].domain) == 0 &&
                    strcmp(new_desired_members[i].unique_id, catalog_entry_to_update->catalog_members[j].unique_id) == 0) {
                    bool groups_match = (new_desired_members[i].group_count == catalog_entry_to_update->catalog_members[j].group_count);
                    if (groups_match) {
                        for (int k = 0; k < new_desired_members[i].group_count; k++) {
                            if (strcmp(new_desired_members[i].groups[k], catalog_entry_to_update->catalog_members[j].groups[k]) != 0) {
                                groups_match = false; break;
                            }
                        }
                    }
                    if (groups_match) {
                        found = true; break;
                    }
                }
            }
            
            bool member_accepted = true;
            bool needs_creation = true;

            if (!found) {
                if (target_view) {
                    zone_db_entry_t *existing = find_catalog_parent_in_snapshot(target_view, new_desired_members[i].domain);
                    if (existing && existing->is_catalog_member) {
                        if (strcasecmp(existing->owning_catalog_domain, catalog_entry_to_update->domain) != 0) {
                            bool valid_coo = false;
                            for (int p = 0; p < g_pending_coo_count; p++) {
                                if (strcasecmp(g_pending_coo[p].domain, new_desired_members[i].domain) == 0 &&
                                    strcasecmp(g_pending_coo[p].old_catalog, existing->owning_catalog_domain) == 0 &&
                                    strcasecmp(g_pending_coo[p].new_catalog, catalog_entry_to_update->domain) == 0) {
                                    valid_coo = true; break;
                                }
                            }
                            if (valid_coo) {
                                zone_db_entry_t *old_catalog_entry = find_catalog_parent_in_snapshot(target_view, existing->owning_catalog_domain);
                                if (old_catalog_entry) {
                                    remove_member_from_catalog_bookkeeping(old_catalog_entry, existing->catalog_member_unique_id, new_desired_members[i].domain);
                                }
                                if (strcmp(existing->catalog_member_unique_id, new_desired_members[i].unique_id) == 0) {
                                    // Retain state
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: retained state for '%s' (unique-id: %s), owner %s -> %s",
                                           existing->domain, existing->catalog_member_unique_id, existing->owning_catalog_domain, catalog_entry_to_update->domain);
                                    strncpy(existing->owning_catalog_domain, catalog_entry_to_update->domain, sizeof(existing->owning_catalog_domain) - 1);
                                    
                                    // Deep copy new groups in-place
                                    if (existing->groups) {
                                        for (int g = 0; g < existing->group_count; g++) {
                                            free(existing->groups[g]);
                                        }
                                        free(existing->groups);
                                        existing->groups = NULL;
                                    }
                                    existing->group_count = new_desired_members[i].group_count;
                                    if (existing->group_count > 0) {
                                        existing->groups = calloc(existing->group_count, sizeof(char*));
                                        for (int g = 0; g < existing->group_count; g++) {
                                            existing->groups[g] = strdup(new_desired_members[i].groups[g]);
                                        }
                                    }
                                    needs_creation = false;
                                } else {
                                    // State reset
                                    syslog(LOG_INFO, "[Catalog] CoO transfer: evicted old state for '%s' (old unique-id: %s, new unique-id: %s)",
                                           existing->domain, existing->catalog_member_unique_id, new_desired_members[i].unique_id);
                                    strncpy(coo_evicted_members[coo_evicted_count].unique_id, existing->catalog_member_unique_id, sizeof(coo_evicted_members[coo_evicted_count].unique_id) - 1);
                                    strncpy(coo_evicted_members[coo_evicted_count].domain, existing->domain, sizeof(coo_evicted_members[coo_evicted_count].domain) - 1);
                                    coo_evicted_count++;
                                }
                            } else {
                                syslog(LOG_WARNING, "[Catalog] Name collision for '%s' between '%s' and '%s'. Ignoring.", 
                                       new_desired_members[i].domain, existing->owning_catalog_domain, catalog_entry_to_update->domain);
                                member_accepted = false;
                            }
                        }
                    }
                }
            } else {
                needs_creation = false; // Already existed exactly in our catalog
            }

            if (member_accepted) {
                if (filtered_count != i) {
                    new_desired_members[filtered_count] = new_desired_members[i];
                }
                filtered_count++;
                if (needs_creation) {
                    added_members[added_count++] = new_desired_members[i];
                }
            } else {
                if (new_desired_members[i].groups) {
                    for (int g = 0; g < new_desired_members[i].group_count; g++) {
                        free(new_desired_members[i].groups[g]);
                    }
                    free(new_desired_members[i].groups);
                }
            }
        }
        new_desired_count = filtered_count;

        for (int i = 0; i < catalog_entry_to_update->catalog_member_count; i++) {
            bool found = false;
            for (int j = 0; j < new_desired_count; j++) {
                if (strcasecmp(catalog_entry_to_update->catalog_members[i].domain, new_desired_members[j].domain) == 0 &&
                    strcmp(catalog_entry_to_update->catalog_members[i].unique_id, new_desired_members[j].unique_id) == 0) {
                    bool groups_match = (catalog_entry_to_update->catalog_members[i].group_count == new_desired_members[j].group_count);
                    if (groups_match) {
                        for (int k = 0; k < catalog_entry_to_update->catalog_members[i].group_count; k++) {
                            if (strcmp(catalog_entry_to_update->catalog_members[i].groups[k], new_desired_members[j].groups[k]) != 0) {
                                groups_match = false; break;
                            }
                        }
                    }
                    if (groups_match) {
                        found = true; break;
                    }
                }
            }
            if (!found) {
                removed_members[removed_count++] = catalog_entry_to_update->catalog_members[i];
            }
        }

        zone_db_entry_t **new_entries = calloc(added_count > 0 ? added_count : 1, sizeof(zone_db_entry_t*));
        for (int i = 0; i < added_count; i++) {
            zone_db_entry_t *create_new_zone_entry(const char *domain, const char *view_name);
            zone_db_entry_t *entry = create_new_zone_entry(added_members[i].domain, catalog_view_name);
            strncpy(entry->owning_catalog_domain, catalog_entry_to_update->domain, sizeof(entry->owning_catalog_domain) - 1);
            syslog(LOG_INFO, "[Catalog] Added new member '%s' (unique-id: %s) owned by %s", added_members[i].domain, added_members[i].unique_id, catalog_entry_to_update->domain);
            entry->is_catalog_member = true;
            strncpy(entry->catalog_member_unique_id, added_members[i].unique_id, sizeof(entry->catalog_member_unique_id) - 1);
            if (added_members[i].group_count > 0) {
                entry->groups = calloc(added_members[i].group_count, sizeof(char*));
                entry->group_count = added_members[i].group_count;
                for (int g = 0; g < added_members[i].group_count; g++) {
                    entry->groups[g] = strdup(added_members[i].groups[g]);
                }
            }
            if (catalog_cfg->masters_count > 0 && catalog_cfg->masters[0].ip != NULL) {
                strncpy(entry->cached_master_ip, catalog_cfg->masters[0].ip, sizeof(entry->cached_master_ip) - 1);
                entry->cached_master_port = catalog_cfg->masters[0].port;
            }
            if (catalog_cfg->tsig_key) {
                strncpy(entry->cached_tsig_key_name, catalog_cfg->tsig_key, sizeof(entry->cached_tsig_key_name) - 1);
            }
            atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
            new_entries[i] = entry;
        }

        new_snap->view_count = old_snap ? old_snap->view_count : 0;
        if (new_snap->view_count > 0) {
            new_snap->views = calloc(new_snap->view_count, sizeof(view_snapshot_t));
            atomic_init(&new_snap->reader_count, 0);

            for (size_t v = 0; v < old_snap->view_count; v++) {
                view_snapshot_t *vs = &new_snap->views[v];
                vs->name = strdup(old_snap->views[v].name);
                vs->match_clients_count = old_snap->views[v].match_clients_count;
                if (vs->match_clients_count > 0) {
                    vs->match_clients = calloc(vs->match_clients_count, sizeof(char *));
                    for (int i = 0; i < vs->match_clients_count; i++) {
                        vs->match_clients[i] = strdup(old_snap->views[v].match_clients[i]);
                    }
                }

                if (strcasecmp(vs->name, catalog_view_name) == 0) {
                    int keep_count = 0;
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        bool is_removed = false;
                        for (int j = 0; j < removed_count; j++) {
                            if (strcasecmp(old_snap->views[v].entries[i]->domain, removed_members[j].domain) == 0 &&
                                strcmp(old_snap->views[v].entries[i]->catalog_member_unique_id, removed_members[j].unique_id) == 0) {
                                is_removed = true; break;
                            }
                        }
                        if (!is_removed) {
                            for (int j = 0; j < coo_evicted_count; j++) {
                                if (strcasecmp(old_snap->views[v].entries[i]->domain, coo_evicted_members[j].domain) == 0 &&
                                    strcmp(old_snap->views[v].entries[i]->catalog_member_unique_id, coo_evicted_members[j].unique_id) == 0) {
                                    is_removed = true; break;
                                }
                            }
                        }
                        if (!is_removed) keep_count++;
                    }
                    
                    vs->zone_count = keep_count + added_count;
                    vs->entries = calloc(vs->zone_count, sizeof(zone_db_entry_t *));
                    
                    int zidx = 0;
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        bool is_removed = false;
                        for (int j = 0; j < removed_count; j++) {
                            if (strcasecmp(old_snap->views[v].entries[i]->domain, removed_members[j].domain) == 0 &&
                                strcmp(old_snap->views[v].entries[i]->catalog_member_unique_id, removed_members[j].unique_id) == 0) {
                                is_removed = true; break;
                            }
                        }
                        if (!is_removed) {
                            for (int j = 0; j < coo_evicted_count; j++) {
                                if (strcasecmp(old_snap->views[v].entries[i]->domain, coo_evicted_members[j].domain) == 0 &&
                                    strcmp(old_snap->views[v].entries[i]->catalog_member_unique_id, coo_evicted_members[j].unique_id) == 0) {
                                    is_removed = true; break;
                                }
                            }
                        }
                        if (!is_removed) {
                            zone_db_entry_t *entry = old_snap->views[v].entries[i];
                            atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                            vs->entries[zidx++] = entry;
                        }
                    }
                    
                    for (int i = 0; i < added_count; i++) {
                        vs->entries[zidx++] = new_entries[i];
                    }
                } else {
                    vs->zone_count = old_snap->views[v].zone_count;
                    vs->entries = calloc(vs->zone_count, sizeof(zone_db_entry_t *));
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        zone_db_entry_t *entry = old_snap->views[v].entries[i];
                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                        vs->entries[i] = entry;
                    }
                }
            }
        }

        free(added_members);
        free(removed_members);
        free(coo_evicted_members);
        free(new_entries);

        if (catalog_entry_to_update) {
            // handled above
            if (catalog_entry_to_update->catalog_members) free_catalog_member_ids(catalog_entry_to_update->catalog_members, catalog_entry_to_update->catalog_member_count);
            catalog_entry_to_update->catalog_members = new_desired_members;
            catalog_entry_to_update->catalog_member_count = new_desired_count;
        }
    }

    atomic_store_explicit(&g_zone_db_active, new_snap, memory_order_release);
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);

    if (old_snap) {
        void *gc_snapshot_thread(void *arg);
        pthread_t gc_tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&gc_tid, &attr, gc_snapshot_thread, old_snap);
        pthread_attr_destroy(&attr);
    }

    return new_snap;
}


static void normalize_domain_fqdn_local(const char *in, char *out, size_t out_cap) {
    size_t len = strlen(in);
    if (len > 0 && in[len - 1] != '.' && len + 1 < out_cap) {
        memcpy(out, in, len);
        out[len] = '.';
        out[len + 1] = '\0';
    } else {
        snprintf(out, out_cap, "%s", in);
    }
}

static void free_catalog_desired_list(catalog_member_id_t *list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        if (list[i].groups) {
            for (int j = 0; j < list[i].group_count; j++) {
                if (list[i].groups[j]) free(list[i].groups[j]);
            }
            free(list[i].groups);
        }
    }
    free(list);
}

void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name) {
    if (!catalog_entry || !catalog_cfg) return;

    zone_arena_t *arena = atomic_load_explicit(&catalog_entry->rcu.active, memory_order_acquire);
    if (!arena) return;

    atomic_fetch_add_explicit(&arena->reader_count, 1, memory_order_acquire);

    // Verify version.<catalog_zone>. TXT "2"
    char version_txt[256];
    snprintf(version_txt, sizeof(version_txt), "version.%s", catalog_entry->domain);
    bool found_version = false;
    for (size_t i = 0; i < arena->count; i++) {
        if (arena->records[i].type_code == 16 && strcasecmp(arena->records[i].name, version_txt) == 0) {
            if (arena->records[i].rdata_count > 0 && strcmp(arena->records[i].rdata[0], "2") == 0) {
                found_version = true;
                break;
            }
        }
    }

    if (!found_version) {
        syslog(LOG_ERR, "[Catalog] Zone '%s' is missing '%s TXT \"2\"', aborting catalog update", catalog_entry->domain, version_txt);
        atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
        return;
    }

    // Build desired members list
    int max_possible = arena->count;
    catalog_member_id_t *new_desired = calloc(max_possible, sizeof(catalog_member_id_t));
    if (!new_desired) {
        syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory building member list", catalog_entry->domain);
        atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
        return;
    }
    int new_desired_count = 0;

    char suffix[256];
    snprintf(suffix, sizeof(suffix), ".zones.%s", catalog_entry->domain);
    size_t suffix_len = strlen(suffix);

    for (size_t i = 0; i < arena->count; i++) {
        if (arena->records[i].type_code == 12) { // PTR
            size_t name_len = strlen(arena->records[i].name);
            if (name_len > suffix_len && strcasecmp(arena->records[i].name + name_len - suffix_len, suffix) == 0) {
                if (arena->records[i].rdata_count > 0) {
                    char *target = arena->records[i].rdata[0];
                    char norm_target[256];
                    normalize_domain_fqdn_local(target, norm_target, sizeof(norm_target));
                    
                    // Collision check with static config
                    server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
                    zone_config_t *zcfg = find_zone_config_in_view(cfg, view_name, norm_target);
                    if (zcfg) {
                        syslog(LOG_WARNING, "[Catalog] Zone '%s' generated member '%s' which collides with static config. Skipping.", catalog_entry->domain, norm_target);
                        continue;
                    }
                    
                    // Extract unique_id
                    size_t prefix_len = name_len - suffix_len;
                    if (prefix_len < sizeof(new_desired[new_desired_count].unique_id)) {
                        strncpy(new_desired[new_desired_count].unique_id, arena->records[i].name, prefix_len);
                        new_desired[new_desired_count].unique_id[prefix_len] = '\0';
                        strncpy(new_desired[new_desired_count].domain, norm_target, sizeof(new_desired[new_desired_count].domain) - 1);
                        new_desired_count++;
                    }
                }
            }
        }
    }

    for (int d = 0; d < new_desired_count; d++) {
        char group_name[512];
        snprintf(group_name, sizeof(group_name), "group.%s.zones.%s", new_desired[d].unique_id, catalog_entry->domain);
        
        int grp_count = 0;
        for (size_t i = 0; i < arena->count; i++) {
            if (arena->records[i].type_code == 16 && strcasecmp(arena->records[i].name, group_name) == 0) {
                grp_count++;
            }
        }
        
        if (grp_count > 0) {
            new_desired[d].groups = calloc(grp_count, sizeof(char *));
            if (!new_desired[d].groups) {
                syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory building group list for member '%s'", catalog_entry->domain, new_desired[d].domain);
                free_catalog_desired_list(new_desired, new_desired_count);
                atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
                return;
            }
            new_desired[d].group_count = 0;
            for (size_t i = 0; i < arena->count; i++) {
                if (arena->records[i].type_code == 16 && strcasecmp(arena->records[i].name, group_name) == 0) {
                    if (arena->records[i].rdata_count > 0) {
                        char *g = strdup(arena->records[i].rdata[0]);
                        if (!g) {
                            syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory duplicating group string", catalog_entry->domain);
                            free_catalog_desired_list(new_desired, new_desired_count);
                            atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
                            return;
                        }
                        new_desired[d].groups[new_desired[d].group_count++] = g;
                    }
                }
            }
            for (int i = 0; i < new_desired[d].group_count - 1; i++) {
                for (int j = i + 1; j < new_desired[d].group_count; j++) {
                    if (strcmp(new_desired[d].groups[i], new_desired[d].groups[j]) > 0) {
                        char *tmp = new_desired[d].groups[i];
                        new_desired[d].groups[i] = new_desired[d].groups[j];
                        new_desired[d].groups[j] = tmp;
                    }
                }
            }
        }
        char coo_name[512];
        snprintf(coo_name, sizeof(coo_name), "coo.%s.zones.%s", new_desired[d].unique_id, catalog_entry->domain);
        
        int coo_count = 0;
        char coo_rdata[256] = {0};
        for (size_t i = 0; i < arena->count; i++) {
            if (arena->records[i].type_code == 12 && strcasecmp(arena->records[i].name, coo_name) == 0) {
                if (arena->records[i].rdata_count > 0) {
                    strncpy(coo_rdata, arena->records[i].rdata[0], sizeof(coo_rdata) - 1);
                }
                coo_count++;
            }
        }
        
        if (coo_count == 1) {
            normalize_domain_fqdn_local(coo_rdata, new_desired[d].coo_target, sizeof(new_desired[d].coo_target));
        } else if (coo_count > 1) {
            syslog(LOG_WARNING, "[Catalog] Multiple coo PTR records found for member '%s' in catalog '%s'. Ignoring coo property.", new_desired[d].domain, catalog_entry->domain);
            new_desired[d].coo_target[0] = '\0';
        } else {
            new_desired[d].coo_target[0] = '\0';
        }
    }

    if (new_desired_count > 0) {
        catalog_member_id_t *shrunk = calloc(new_desired_count, sizeof(catalog_member_id_t));
        if (!shrunk) {
            syslog(LOG_ERR, "[Catalog] Zone '%s': out of memory finalizing member list", catalog_entry->domain);
            free_catalog_desired_list(new_desired, new_desired_count);
            atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
            return;
        }
        for (int i = 0; i < new_desired_count; i++) shrunk[i] = new_desired[i];
        free(new_desired);
        new_desired = shrunk;
    } else {
        free(new_desired);
        new_desired = NULL;
    }

    atomic_fetch_sub_explicit(&arena->reader_count, 1, memory_order_release);
    rebuild_zone_db_snapshot(NULL, view_name, catalog_entry, catalog_cfg, new_desired, new_desired_count);
    syslog(LOG_INFO, "[Catalog] Processed membership for '%s', desired members: %d", catalog_entry->domain, new_desired_count);
}
void rebuild_zone_db_from_config(server_config_t *config) {
    zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(config, NULL, NULL, NULL, NULL, 0);

    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            zone_db_entry_t *entry = snapshot_get_zone(new_snap, z->domain);
            if (entry && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                reload_master_zone(entry, z->file);
                if (z->is_catalog) {
                    void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name);
                    catalog_process_membership(entry, z, v->name);
                }
            }
        }
    }
}

int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out,
                         uint16_t *len_out) {
  while (1) {
    if (ctx->state == TCP_STATE_READ_LEN) {
      ssize_t n =
          recv(fd, &ctx->buf[ctx->accumulated], 2 - ctx->accumulated, 0);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return 0;
        return -1;
      }
      if (n == 0)
        return -1;
      ctx->accumulated += n;
      if (ctx->accumulated == 2) {
        ctx->msg_len = (ctx->buf[0] << 8) | ctx->buf[1];
        ctx->accumulated = 0;
        if (ctx->msg_len == 0) {
          *msg_out = &ctx->buf[2];
          *len_out = 0;
          ctx->state = TCP_STATE_READ_LEN;
          return 1;
        }
        ctx->state = TCP_STATE_READ_BODY;
      }
    }
    if (ctx->state == TCP_STATE_READ_BODY) {
      ssize_t n = recv(fd, &ctx->buf[2 + ctx->accumulated],
                       ctx->msg_len - ctx->accumulated, 0);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return 0;
        return -1;
      }
      if (n == 0)
        return -1;
      ctx->accumulated += n;
      if (ctx->accumulated == ctx->msg_len) {
        *msg_out = &ctx->buf[2];
        *len_out = ctx->msg_len;
        ctx->state = TCP_STATE_READ_LEN;
        ctx->accumulated = 0;
        return 1;
      }
    }
  }
}

static void clone_zone_arena(zone_arena_t *src, zone_arena_t *dst) {
  for (int i = 0; i < dst->data_pool_count; i++) {
    if (dst->data_pools[i])
      free(dst->data_pools[i]);
  }
  dst->count = 0;
  dst->data_pool_count = 0;
  dst->current_pool_cap = 0;
  dst->current_pool_idx = 0;
  for (size_t i = 0; i < src->count; i++) {
    if (dst->count >= dst->records_cap) {
      size_t new_cap = dst->records_cap == 0 ? 16 : dst->records_cap * 2;
      if (new_cap > SIZE_MAX / sizeof(dns_record_t)) break;
      dns_record_t *new_records =
          realloc(dst->records, new_cap * sizeof(dns_record_t));
      if (!new_records)
        break;
      memset(new_records + dst->records_cap, 0,
             (new_cap - dst->records_cap) * sizeof(dns_record_t));
      dst->records = new_records;
      dst->records_cap = new_cap;
    }
    dns_record_t *s_rec = &src->records[i];
    dns_record_t *d_rec = &dst->records[dst->count++];
    d_rec->name = arena_strdup(dst, s_rec->name);
    d_rec->ttl = arena_strdup(dst, s_rec->ttl);
    d_rec->class_str =
        s_rec->class_str ? arena_strdup(dst, s_rec->class_str) : NULL;
    d_rec->type = s_rec->type ? arena_strdup(dst, s_rec->type) : NULL;
    d_rec->type_code = s_rec->type_code;
    d_rec->rdata_count = s_rec->rdata_count;
    for (int j = 0; j < s_rec->rdata_count; j++)
      d_rec->rdata[j] = arena_strdup(dst, s_rec->rdata[j]);
    d_rec->generic_len = s_rec->generic_len;
    if (s_rec->generic_len > 0 && s_rec->generic_data) {
      d_rec->generic_data = (uint8_t *)arena_alloc(dst, s_rec->generic_len);
      if (d_rec->generic_data)
        memcpy(d_rec->generic_data, s_rec->generic_data, s_rec->generic_len);
    } else
      d_rec->generic_data = NULL;
    d_rec->next_record = -1;
  }
}

int parse_xfr_packet(const uint8_t *packet, size_t packet_len,
                     zone_arena_t *standby, zone_arena_t *active,
                     axfr_session_t *session, const char *domain) {
  if (packet_len < DNS_HEADER_SIZE)
    return -1;
  uint16_t qdcount = (packet[4] << 8) | packet[5],
           ancount = (packet[6] << 8) | packet[7];
  size_t offset = DNS_HEADER_SIZE;
  for (int i = 0; i < qdcount; i++) {
    size_t next_offset;
    if (skip_wire_name(packet, packet_len, offset, &next_offset) != 0)
      return -1;
    offset = next_offset + 4;
  }
  size_t domain_len = strlen(domain);
  for (int i = 0; i < ancount; i++) {
    if (standby->count >= standby->records_cap) {
      size_t new_cap =
          standby->records_cap == 0 ? 16 : standby->records_cap * 2;
      if (new_cap > SIZE_MAX / sizeof(dns_record_t)) return -1;
      dns_record_t *new_records =
          realloc(standby->records, new_cap * sizeof(dns_record_t));
      if (!new_records)
        return -1;
      memset(new_records + standby->records_cap, 0,
             (new_cap - standby->records_cap) * sizeof(dns_record_t));
      standby->records = new_records;
      standby->records_cap = new_cap;
    }
    dns_record_t *rec = &standby->records[standby->count];
    uint16_t type;
    if (parse_resource_record(packet, packet_len, &offset, standby, rec,
                              &type) != 0)
      return -1;
    standby->count++;
    size_t name_len = strlen(rec->name);
    if (name_len < domain_len ||
        strcasecmp(rec->name + name_len - domain_len, domain) != 0)
      return -1;
    if (name_len > domain_len && rec->name[name_len - domain_len - 1] != '.')
      return -1;
    if (type == 6) {
      session->soa_count++;
      uint32_t current_serial = strtoul(rec->rdata[2], NULL, 10);
      if (session->soa_count == 1) {
        strncpy(session->initial_soa_name, rec->name,
                sizeof(session->initial_soa_name) - 1);
        session->initial_soa_serial = current_serial;
        if (session->is_ixfr && ancount == 1 &&
            current_serial == session->client_serial) {
          session->is_finished = true;
          standby->count = 0;
          return 0;
        }
      } else if (session->soa_count == 2 && session->is_ixfr) {
        standby->count = 0;
        standby->data_pool_count = 0;
        standby->current_pool_cap = 0;
        standby->current_pool_idx = 0;
        clone_zone_arena(active, standby);
        session->is_deleting = true;
      } else if (session->is_ixfr &&
                 current_serial == session->initial_soa_serial) {
        session->is_finished = true;
        standby->count--;
      } else if (session->is_ixfr) {
        session->is_deleting = !session->is_deleting;
        standby->count--;
      } else {
        if (strcasecmp(session->initial_soa_name, rec->name) == 0 &&
            session->initial_soa_serial == current_serial) {
          session->is_finished = true;
          standby->count--;
        }
      }
    } else {
      if (session->soa_count == 1 && session->is_ixfr)
        session->is_ixfr = false;
      if (session->is_ixfr && session->is_deleting) {
        standby->count--;
        for (size_t k = 0; k < standby->count; k++) {
          if (compare_records(&standby->records[k], rec, true)) {
            standby->records[k] = standby->records[--standby->count];
            break;
          }
        }
      }
    }
  }
  return 0;
}

int handle_axfr_event(int tcp_fd, zone_db_entry_t *entry,
                      tcp_stream_ctx_t *stream_ctx, axfr_session_t *session,
                      tsig_key_t *tsig_key) {
  uint8_t *msg;
  uint16_t msg_len;
  pthread_mutex_lock(&entry->writer_lock);
  zone_arena_t *active =
      atomic_load_explicit(&entry->rcu.active, memory_order_relaxed);
  zone_arena_t *standby = (active == &entry->rcu.arena_a) ? &entry->rcu.arena_b
                                                          : &entry->rcu.arena_a;
  if (session->soa_count == 0) {
    standby->count = 0;
    standby->data_pool_count = 0;
    standby->current_pool_cap = 0;
    standby->current_pool_idx = 0;
    session->is_finished = false;
  }
  while (1) {
    int ret = read_dns_tcp_message(tcp_fd, stream_ctx, &msg, &msg_len);
    if (ret < 0 || ret == 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      return -1;
    }
    if (tsig_key && tsig_verify_packet(msg, msg_len, tsig_key, NULL, NULL) != 0) {
      syslog(LOG_ERR, "[AXFR] TSIG failed");
      pthread_mutex_unlock(&entry->writer_lock);
      return -1;
    }
    if (parse_xfr_packet(msg, msg_len, standby, active, session,
                         entry->domain) != 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      return -1;
    }
    if (session->is_finished) {
      int ret_code = 1;
      if (standby->count > 0) {
        for (size_t k = 0; k < standby->count; k++) {
          if (standby->records[k].type_code == 6 &&
              standby->records[k].rdata_count >= 7) {
            entry->serial = strtoul(standby->records[k].rdata[2], NULL, 10);
            entry->refresh = strtoul(standby->records[k].rdata[3], NULL, 10);
            entry->retry = strtoul(standby->records[k].rdata[4], NULL, 10);
            entry->expire = strtoul(standby->records[k].rdata[5], NULL, 10);
            atomic_store_explicit(&entry->next_check, time(NULL) + entry->refresh, memory_order_release);
            atomic_store_explicit(&entry->last_successful_transfer, time(NULL), memory_order_release);
            break;
          }
        }
        if (build_zone_index(standby) != 0) {
            pthread_mutex_unlock(&entry->writer_lock);
            syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after XFR for '%s'", entry->domain);
            return -1;
        }
        compute_ixfr_diff(entry, active, standby);
        atomic_store_explicit(&entry->rcu.active, standby,
                              memory_order_release);
        wait_for_readers(active);
        void send_notify_to_all(const char *domain, const char *view_name);
        send_notify_to_all(entry->domain, entry->view_name);
      } else {
        atomic_store_explicit(&entry->next_check, time(NULL) + entry->refresh, memory_order_release);
        atomic_store_explicit(&entry->last_successful_transfer, time(NULL), memory_order_release);
        ret_code = 2;
      }
      pthread_mutex_unlock(&entry->writer_lock);

      // Hook for catalog zone processing
      server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
      zone_config_t *zcfg = find_zone_config_in_view(cfg, entry->view_name, entry->domain);
      if (zcfg && zcfg->is_catalog) {
          void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name);
          catalog_process_membership(entry, zcfg, entry->view_name);
      }
      return ret_code;
    }
  }
}

static bool attach_covering_rrsig(zone_arena_t *zone, size_t hash_idx,
                                  const char *match_name,
                                  const char *owner_name_override,
                                  uint16_t type_covered, uint8_t *res,
                                  size_t max_res_len, uint16_t *offset,
                                  compress_ctx_t *comp_ctx, uint16_t *count) {
  for (int i = zone->hash_table[hash_idx]; i != -1;
       i = zone->records[i].next_record) {
    dns_record_t *rec = &zone->records[i];
    if (rec->type_code != 46 /* RRSIG */ ||
        strcasecmp(rec->name, match_name) != 0)
      continue;
    if (rec->rdata_count < 9) // Type Covered..Signatureまでの必須フィールド数
      continue; // 壊れたRRSIGは無視してスキップ(致命的にしない)
    if (get_type_code(rec->rdata[0]) != type_covered)
      continue;
    if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                             owner_name_override, 0xFFFFFFFF) < 0)
      return false; // バッファ溢れのみ呼び出し元に伝える
    (*count)++;
    // 鍵ロールオーバー中は同一タイプに複数のRRSIGが存在し得るためbreakしない
  }
  return true;
}

static bool zone_uses_nsec3(zone_arena_t *zone, const char *apex_name) {
  uint32_t apex_hash = calc_fnv1a_str(apex_name);
  size_t apex_idx = apex_hash & (zone->hash_size - 1);
  for (int i = zone->hash_table[apex_idx]; i != -1;
       i = zone->records[i].next_record) {
    dns_record_t *rec = &zone->records[i];
    if (rec->type_code == 51 /* NSEC3PARAM */ &&
        strcasecmp(rec->name, apex_name) == 0)
      return true;
  }
  return false;
}

static bool is_non_data_rrtype(uint16_t t) {
    switch (t) {
        case 41: case 249: case 250: case 251: case 252: case 253: case 254: case 255:
            return true;
        default:
            return false;
    }
}

typedef struct {
    uint16_t offset;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} resolve_checkpoint_t;

static resolve_checkpoint_t save_checkpoint(uint16_t *offset, uint16_t *ancount,
                                             uint16_t *nscount, uint16_t *arcount) {
    resolve_checkpoint_t cp = { *offset, *ancount, *nscount, *arcount };
    return cp;
}

static void restore_checkpoint(const resolve_checkpoint_t *cp, uint16_t *offset,
                                uint16_t *ancount, uint16_t *nscount, uint16_t *arcount) {
    *offset = cp->offset;
    *ancount = cp->ancount;
    *nscount = cp->nscount;
    *arcount = cp->arcount;
}

static bool append_glue_records(zone_arena_t *current_zone, const char *target,
                                const char *zone_apex, uint8_t *res,
                                size_t max_res_len, uint16_t *offset,
                                compress_ctx_t *comp_ctx, uint16_t *arcount) {
  size_t t_len = strlen(target), a_len = strlen(zone_apex);
  if (t_len >= a_len &&
      strcasecmp(target + t_len - a_len, zone_apex) == 0 &&
      (t_len == a_len || target[t_len - a_len - 1] == '.')) {
    uint32_t tgt_hash = calc_fnv1a_str(target);
    size_t tgt_idx = tgt_hash & (current_zone->hash_size - 1);
    for (int j = current_zone->hash_table[tgt_idx]; j != -1;
         j = current_zone->records[j].next_record) {
      if ((current_zone->records[j].type_code == 1 ||
           current_zone->records[j].type_code == 28) &&
          strcasecmp(current_zone->records[j].name, target) == 0) {
        if (serialize_dns_record(res, max_res_len, offset,
                                 &current_zone->records[j], comp_ctx,
                                 NULL, 0xFFFFFFFF) < 0) {
          res[2] |= 0x02;
          return false;
        } else
          (*arcount)++;
      }
    }
  }
  return true;
}

static bool find_delegation(zone_arena_t *current_zone, const char *qname,
                            const char *zone_apex, uint8_t *res,
                            size_t max_res_len, uint16_t *offset,
                            compress_ctx_t *comp_ctx, uint16_t *nscount,
                            uint16_t *arcount) {
  if (!current_zone || current_zone->hash_size == 0 ||
      !current_zone->hash_table)
    return false;
  const char *name = qname;
  while (name && strcasecmp(name, zone_apex) != 0) {
    uint32_t hash = calc_fnv1a_str(name);
    size_t idx = hash & (current_zone->hash_size - 1);
    bool delegated = false;
    for (int i = current_zone->hash_table[idx]; i != -1;
         i = current_zone->records[i].next_record) {
      if (current_zone->records[i].type_code == 2 &&
          strcasecmp(current_zone->records[i].name, name) == 0) {
        delegated = true;
        if (serialize_dns_record(res, max_res_len, offset,
                                 &current_zone->records[i], comp_ctx, NULL,
                                 0xFFFFFFFF) < 0) {
          res[2] |= 0x02;
          return true;
        } else
          (*nscount)++;
      }
    }
    if (delegated) {
      res[2] &= ~0x04; // Clear AA
      for (int i = current_zone->hash_table[idx]; i != -1;
           i = current_zone->records[i].next_record) {
        if (current_zone->records[i].type_code == 2 &&
            strcasecmp(current_zone->records[i].name, name) == 0 &&
            current_zone->records[i].rdata_count > 0) {
          const char *target = current_zone->records[i].rdata[0];
          if (!append_glue_records(current_zone, target, zone_apex, res,
                                   max_res_len, offset, comp_ctx, arcount)) {
            return true;
          }
        }
      }
      return true;
    }
    name = strchr(name, '.');
    if (name)
      name++;
  }
  return false;
}

static void resolve_name(const char *qname, const uint16_t *qtypes, int num_qtypes,
                         zone_db_entry_t **db_entry_ptr,
                         zone_arena_t **current_zone_ptr, uint8_t *res,
                         size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *ancount,
                         uint16_t *nscount, uint16_t *arcount,
                         bool minimal_responses,
                         bool minimal_any, uint32_t minimal_any_ttl, bool dnssec_ok,
                         view_snapshot_t *view, uint32_t *qtx_included_out) {
  if (qtx_included_out) *qtx_included_out = 0;
  char current_qname[256];
  strncpy(current_qname, qname, sizeof(current_qname));
  current_qname[255] = '\0';
  bool chain_exhausted = true;
  for (int depth = 0; depth < 16; depth++) {
    zone_db_entry_t *db_entry = *db_entry_ptr;
    zone_arena_t *current_zone = *current_zone_ptr;
    if (!current_zone || current_zone->hash_size == 0 ||
        !current_zone->hash_table) {
      res[3] |= 0x02;
      return;
    }
    if (find_delegation(current_zone, current_qname, db_entry->domain, res,
                        max_res_len, offset, comp_ctx, nscount, arcount))
      return;
    bool found = false, type_matched = false, cname_followed = false;
    uint32_t hash = calc_fnv1a_str(current_qname);
    size_t idx = hash & (current_zone->hash_size - 1);
    bool has_any = (qtypes[0] == 255);
    if (has_any && minimal_any) {
      bool name_exists = false, has_cname = false, has_rrsig = false;
      for (int i = current_zone->hash_table[idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (strcasecmp(rec->name, current_qname) == 0) {
          name_exists = true;
          if (rec->type_code == 5) has_cname = true;   // CNAME
          if (rec->type_code == 46) has_rrsig = true;  // RRSIG
        }
      }
      bool skip_synthesis = dnssec_ok && has_rrsig;
      if (name_exists && !has_cname && !skip_synthesis) {
        dns_record_t hinfo_rec;
        memset(&hinfo_rec, 0, sizeof(hinfo_rec));
        hinfo_rec.name = (char *)current_qname;
        hinfo_rec.type_code = 13; // HINFO
        char ttl_str[32];
        snprintf(ttl_str, sizeof(ttl_str), "%u", minimal_any_ttl);
        hinfo_rec.ttl = ttl_str;
        hinfo_rec.rdata[0] = "RFC8482";
        hinfo_rec.rdata[1] = "";
        hinfo_rec.rdata_count = 2;
        if (serialize_dns_record(res, max_res_len, offset, &hinfo_rec, comp_ctx,
                                 NULL, 0xFFFFFFFF) < 0) {
          res[2] |= 0x02;
          return;
        }
        (*ancount)++;
        found = true;
        chain_exhausted = false;
        break;
      }
    }

    for (int i = current_zone->hash_table[idx]; i != -1;
         i = current_zone->records[i].next_record) {
      dns_record_t *rec = &current_zone->records[i];
      if (strcasecmp(rec->name, current_qname) == 0) {
        found = true;
        uint16_t rec_type = rec->type_code;
        bool follow_cname = false;
        if (rec_type == 5) {
          if (qtypes[0] != 5 && qtypes[0] != 255) { follow_cname = true; }
        }
        if (follow_cname) {
          if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            res[2] |= 0x02;
            return;
          } else
            (*ancount)++;
          if (dnssec_ok) {
            if (!attach_covering_rrsig(current_zone, idx, current_qname, NULL, 5,
                                      res, max_res_len, offset, comp_ctx, ancount)) {
              res[2] |= 0x02;
              return;
            }
          }
          if (rec->rdata_count > 0) {
            strncpy(current_qname, rec->rdata[0], sizeof(current_qname));
            current_qname[255] = '\0';
            cname_followed = true;
          }
          break;
        } else {
          if (qtypes[0] == 255 || qtypes[0] == rec_type) {
            type_matched = true;
            if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                     NULL, 0xFFFFFFFF) < 0) {
              res[2] |= 0x02;
              return;
            }
            (*ancount)++;
            if (dnssec_ok && rec_type != 46 && qtypes[0] != 255) {
              if (!attach_covering_rrsig(current_zone, idx, current_qname, NULL, rec_type,
                                        res, max_res_len, offset, comp_ctx, ancount)) {
                res[2] |= 0x02;
                return;
              }
            }
          }
        }
      }
    }
    if (!found) {
      bool dname_found = false;
      const char *dname_parent = current_qname;
      while ((dname_parent = strchr(dname_parent, '.')) != NULL) {
        dname_parent++;
        if (*dname_parent == '\0') break;
        uint32_t p_hash = calc_fnv1a_str(dname_parent);
        size_t p_idx = p_hash & (current_zone->hash_size - 1);
        for (int i = current_zone->hash_table[p_idx]; i != -1; i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          if (rec->type_code == 39 && strcasecmp(rec->name, dname_parent) == 0) {
            dname_found = true;
            size_t prefix_len = dname_parent - current_qname;
            if (rec->rdata_count == 0) break;
            size_t target_len = strlen(rec->rdata[0]);
            if (prefix_len + target_len > 255) { res[3] |= 6; return; }
            if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) { res[2] |= 0x02; return; }
            (*ancount)++;
            if (dnssec_ok) {
              if (!attach_covering_rrsig(current_zone, p_idx, dname_parent, NULL, 39, res, max_res_len, offset, comp_ctx, ancount)) { res[2] |= 0x02; return; }
            }
            char synth_name[256];
            memcpy(synth_name, current_qname, prefix_len);
            int written = snprintf(synth_name + prefix_len, sizeof(synth_name) - prefix_len, "%s", rec->rdata[0]);
            if (written < 0 || (size_t)written >= sizeof(synth_name) - prefix_len) {
                res[3] |= 6; // YXDomain/error for truncation
                return;
            }
            dns_record_t synth_cname;
            memset(&synth_cname, 0, sizeof(synth_cname));
            synth_cname.name = (char *)current_qname;
            synth_cname.type_code = 5;
            synth_cname.ttl = rec->ttl;
            synth_cname.rdata_count = 1;
            synth_cname.rdata[0] = synth_name;
            if (serialize_dns_record(res, max_res_len, offset, &synth_cname, comp_ctx, NULL, 0xFFFFFFFF) < 0) { res[2] |= 0x02; return; }
            (*ancount)++;
            strncpy(current_qname, synth_name, sizeof(current_qname));
            current_qname[255] = '\0';
            cname_followed = true; found = true; break;
          }
        }
        if (dname_found) break;
      }
      if (!dname_found) {
        const char *parent = current_qname;
        char wc_name[256];
        wc_name[0] = '*';
        wc_name[1] = '.';
        while ((parent = strchr(parent, '.')) != NULL) {
          parent++;
          if (*parent == '\0') break;
          size_t parent_len = strlen(parent);
          if (parent_len + 3 > sizeof(wc_name)) break;
          memcpy(&wc_name[2], parent, parent_len + 1);
          uint32_t wc_hash = calc_fnv1a_str(wc_name);
        size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
        bool wc_found = false;
        for (int i = current_zone->hash_table[wc_idx]; i != -1;
             i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          if (strcasecmp(rec->name, wc_name) == 0) {
            found = true;
            wc_found = true;
            uint16_t rec_type = rec->type_code;
            bool follow_cname = false;
            if (rec_type == 5) {
              if (qtypes[0] != 5 && qtypes[0] != 255) { follow_cname = true; }
            }
            if (follow_cname) {
              if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                       current_qname, 0xFFFFFFFF) < 0) {
                res[2] |= 0x02;
                return;
              } else
                (*ancount)++;
              if (dnssec_ok) {
                if (!attach_covering_rrsig(current_zone, wc_idx, wc_name, current_qname, 5,
                                          res, max_res_len, offset, comp_ctx, ancount)) {
                  res[2] |= 0x02;
                  return;
                }
              }
              if (rec->rdata_count > 0) {
                strncpy(current_qname, rec->rdata[0], sizeof(current_qname));
                current_qname[255] = '\0';
                cname_followed = true;
              }
              break;
            } else {
              if (qtypes[0] == 255 || qtypes[0] == rec_type) {
                type_matched = true;
                if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                         current_qname, 0xFFFFFFFF) < 0) {
                  res[2] |= 0x02;
                  return;
                } else
                  (*ancount)++;
                if (dnssec_ok && rec_type != 46 && qtypes[0] != 255) {
                  if (!attach_covering_rrsig(current_zone, wc_idx, wc_name, current_qname, rec_type,
                                            res, max_res_len, offset, comp_ctx, ancount)) {
                    res[2] |= 0x02;
                    return;
                  }
                }
              }
            }
          }
        }
        if (wc_found)
          break;
        }
      }
    }
    if (cname_followed) {
      size_t cq_len = strlen(current_qname), z_len = strlen(db_entry->domain);
      bool in_zone = false;
      if (cq_len >= z_len &&
          strcasecmp(current_qname + cq_len - z_len, db_entry->domain) == 0 &&
          (cq_len == z_len || current_qname[cq_len - z_len - 1] == '.'))
        in_zone = true;
      if (in_zone)
        continue;
      else {
        zone_db_entry_t *new_db_entry = NULL;
        size_t longest_match_len = 0;
        if (view) {
          for (size_t i = 0; i < view->zone_count; i++) {
            size_t check_z_len = strlen(view->entries[i]->domain);
            bool match = false;
            if (cq_len == check_z_len &&
                strcasecmp(current_qname, view->entries[i]->domain) == 0)
              match = true;
            else if (cq_len > check_z_len &&
                     current_qname[cq_len - check_z_len - 1] == '.' &&
                     strcasecmp(current_qname + cq_len - check_z_len,
                                view->entries[i]->domain) == 0)
              match = true;
            if (match && check_z_len > longest_match_len) {
              longest_match_len = check_z_len;
              new_db_entry = view->entries[i];
            }
          }
        }
        if (new_db_entry) {
          zone_arena_t *new_zone = NULL;
          do {
            new_zone = atomic_load_explicit(&new_db_entry->rcu.active,
                                            memory_order_acquire);
            atomic_fetch_add_explicit(&new_zone->reader_count, 1,
                                      memory_order_acquire);
            if (new_zone == atomic_load_explicit(&new_db_entry->rcu.active,
                                                 memory_order_acquire))
              break;
            atomic_fetch_sub_explicit(&new_zone->reader_count, 1,
                                      memory_order_release);
          } while (1);
          atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                    memory_order_release);
          *db_entry_ptr = new_db_entry;
          *current_zone_ptr = new_zone;
          continue;
        } else
          return;
      }
    }
    bool all_matched = type_matched;
    uint32_t included_mask = 0;
    if (found && num_qtypes > 1) {
      uint32_t final_hash = calc_fnv1a_str(current_qname);
      size_t final_idx = final_hash & (current_zone->hash_size - 1);
      for (int j = 1; j < num_qtypes; j++) {
        uint16_t qtx = qtypes[j];
        bool this_qtx_failed = false;
        bool qtx_matched = false;
        resolve_checkpoint_t cp = save_checkpoint(offset, ancount, nscount, arcount);

        for (int i = current_zone->hash_table[final_idx]; i != -1; i = current_zone->records[i].next_record) {
          dns_record_t *rec = &current_zone->records[i];
          if (strcasecmp(rec->name, current_qname) == 0 && rec->type_code == qtx) {
            qtx_matched = true;
            if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
              this_qtx_failed = true; break;
            }
            (*ancount)++;
            if (dnssec_ok && qtx != 46) {
              if (!attach_covering_rrsig(current_zone, final_idx, current_qname, NULL, qtx, res, max_res_len, offset, comp_ctx, ancount)) {
                this_qtx_failed = true; break;
              }
            }
          }
        }

        if (!qtx_matched && !this_qtx_failed) {
          const char *parent = current_qname;
          char wc_name[256];
          wc_name[0] = '*'; wc_name[1] = '.';
          while ((parent = strchr(parent, '.')) != NULL) {
            parent++; if (*parent == '\0') break;
            size_t parent_len = strlen(parent);
            if (parent_len + 3 > sizeof(wc_name)) break;
            memcpy(&wc_name[2], parent, parent_len + 1);
            uint32_t wc_hash = calc_fnv1a_str(wc_name);
            size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
            bool wc_found = false;
            for (int i = current_zone->hash_table[wc_idx]; i != -1; i = current_zone->records[i].next_record) {
              dns_record_t *rec = &current_zone->records[i];
              if (strcasecmp(rec->name, wc_name) == 0 && rec->type_code == qtx) {
                wc_found = true; qtx_matched = true;
                if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, current_qname, 0xFFFFFFFF) < 0) {
                  this_qtx_failed = true; break;
                }
                (*ancount)++;
                if (dnssec_ok && qtx != 46) {
                  if (!attach_covering_rrsig(current_zone, wc_idx, wc_name, current_qname, qtx, res, max_res_len, offset, comp_ctx, ancount)) {
                    this_qtx_failed = true; break;
                  }
                }
              }
            }
            if (wc_found || this_qtx_failed) break;
          }
        }

        if (this_qtx_failed) {
          restore_checkpoint(&cp, offset, ancount, nscount, arcount);
          break;
        } else {
          if (!qtx_matched) all_matched = false;
          included_mask |= (1 << j);
        }
      }
    }
    if (qtx_included_out) *qtx_included_out = included_mask;

    if (!found || !type_matched) {
      if (!found)
        res[3] |= 3;
      else
        res[3] &= ~3;
      uint32_t apex_hash = calc_fnv1a_str(db_entry->domain);
      size_t apex_idx = apex_hash & (current_zone->hash_size - 1);
      for (int i = current_zone->hash_table[apex_idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (rec->type_code == 6 &&
            strcasecmp(rec->name, db_entry->domain) == 0) {
          uint32_t minimum_ttl = 3600;
          if (rec->rdata_count >= 7)
            minimum_ttl = strtoul(rec->rdata[6], NULL, 10);
          if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                   NULL, minimum_ttl) < 0) {
            res[2] |= 0x02;
            return;
          } else
            (*nscount)++;
          break;
        }
      }
    }
    
    resolve_checkpoint_t nsec_cp = save_checkpoint(offset, ancount, nscount, arcount);
    bool nsec_failed = false;
    if (found && !all_matched && dnssec_ok && !zone_uses_nsec3(current_zone, db_entry->domain)) {
      for (int i = current_zone->hash_table[idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (rec->type_code == 47 /* NSEC */ &&
            strcasecmp(rec->name, current_qname) == 0) {
          printf("DEBUG: Found NSEC record!\\n");
          if (rec->rdata_count < 1) break; // 壊れたNSECは無視
          if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            nsec_failed = true; break;
          }
          (*nscount)++;
          if (!attach_covering_rrsig(current_zone, idx, current_qname, NULL, 47,
                                     res, max_res_len, offset, comp_ctx, nscount)) {
            nsec_failed = true; break;
          }
          break;
        }
      }
    }
    
    if (nsec_failed) {
      restore_checkpoint(&nsec_cp, offset, ancount, nscount, arcount);
    }
    
    bool needs_ns = false;
    if (qtypes[0] != 2 && qtypes[0] != 255) { needs_ns = true; }
    if (type_matched && !minimal_responses && needs_ns) {
      uint32_t apex_hash = calc_fnv1a_str(db_entry->domain);
      size_t apex_idx = apex_hash & (current_zone->hash_size - 1);
      for (int i = current_zone->hash_table[apex_idx]; i != -1;
           i = current_zone->records[i].next_record) {
        dns_record_t *rec = &current_zone->records[i];
        if (rec->type_code == 2 &&
            strcasecmp(rec->name, db_entry->domain) == 0) {
          if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            res[2] |= 0x02;
            return;
          } else {
            (*nscount)++;
            if (rec->rdata_count > 0) {
              const char *target = rec->rdata[0];
              if (!append_glue_records(current_zone, target, db_entry->domain, res,
                                       max_res_len, offset, comp_ctx, arcount)) {
                return;
              }
            }
          }
        }
      }
    }
    chain_exhausted = false;
    break;
  }
  if (chain_exhausted)
    res[3] |= 0x02;
}

// ============================================================================
// Server Cookie 生成 (RFC 9018準拠)
// ============================================================================
static uint8_t g_server_cookie_secret[16];

static void generate_server_cookie(const char *client_ip, const uint8_t client_cookie[8], uint8_t server_cookie[16], uint32_t timestamp) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    unsigned int hash_len = 0;
    
    server_cookie[0] = 1; // Version
    server_cookie[1] = 0; // Reserved
    server_cookie[2] = 0;
    server_cookie[3] = 0;
    server_cookie[4] = (timestamp >> 24) & 0xFF;
    server_cookie[5] = (timestamp >> 16) & 0xFF;
    server_cookie[6] = (timestamp >> 8) & 0xFF;
    server_cookie[7] = timestamp & 0xFF;

    uint8_t data[64];
    size_t data_len = 0;
    
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    if (inet_pton(AF_INET, client_ip, &((struct sockaddr_in *)&addr)->sin_addr) == 1) {
        memcpy(data, &((struct sockaddr_in *)&addr)->sin_addr, 4);
        data_len = 4;
    } else if (inet_pton(AF_INET6, client_ip, &((struct sockaddr_in6 *)&addr)->sin6_addr) == 1) {
        memcpy(data, &((struct sockaddr_in6 *)&addr)->sin6_addr, 16);
        data_len = 16;
    }
    memcpy(data + data_len, client_cookie, 8);
    data_len += 8;
    memcpy(data + data_len, server_cookie, 8); // Include Version, Reserved, Timestamp
    data_len += 8;
    
    HMAC(EVP_sha256(), g_server_cookie_secret, sizeof(g_server_cookie_secret),
         data, data_len, hash, &hash_len);
    
    memcpy(server_cookie + 8, hash, 8);
}

static void add_ede(edns_info_t *edns, bool enabled, uint16_t code, const char *text) {
    if (!enabled || !edns->present) return;
    if (edns->ede_count >= MAX_EDE_COUNT) return;

    edns->ede_list[edns->ede_count].code = code;
    if (text) {
        strncpy(edns->ede_list[edns->ede_count].text, text, sizeof(edns->ede_list[0].text) - 1);
        edns->ede_list[edns->ede_count].text[sizeof(edns->ede_list[0].text) - 1] = '\0';
    } else {
        edns->ede_list[edns->ede_count].text[0] = '\0';
    }
    edns->ede_count++;

    switch (code) {
        case 18: atomic_fetch_add_explicit(&g_ede_prohibited_total, 1, memory_order_relaxed); break;
        case 20: atomic_fetch_add_explicit(&g_ede_not_authoritative_total, 1, memory_order_relaxed); break;
        case 21: atomic_fetch_add_explicit(&g_ede_not_supported_total, 1, memory_order_relaxed); break;
        case 0:  atomic_fetch_add_explicit(&g_ede_other_total, 1, memory_order_relaxed); break;
    }
}

static size_t get_question_end_offset(const uint8_t *pkt, size_t len, uint16_t qdcount) {
    size_t offset = DNS_HEADER_SIZE;
    for (int k = 0; k < qdcount; k++) {
        while (offset < len) {
            uint8_t l = pkt[offset];
            if (l == 0) { offset++; break; }
            if ((l & 0xC0) == 0xC0) { offset += 2; break; }
            offset += l + 1;
        }
        offset += 4; // QTYPE, QCLASS
    }
    return (offset <= len) ? offset : len;
}

static void bump_soa_serial_in_arena(zone_arena_t *arena) {
  for (size_t i = 0; i < arena->count; i++) {
    if (arena->records[i].type_code == 6 && arena->records[i].rdata_count >= 3) {
      if (arena->records[i].rdata[2]) {
        uint32_t serial = strtoul(arena->records[i].rdata[2], NULL, 10);
        serial++;
        char buf[32];
        snprintf(buf, sizeof(buf), "%u", serial);
        arena->records[i].rdata[2] = arena_strdup(arena, buf);
      }
      break;
    }
  }
}

static int handle_dynamic_update(const uint8_t *req, size_t req_len,
                                  zone_db_entry_t *entry,
                                  const char *client_ip,
                                  const char *matched_key_name) {
  pthread_mutex_lock(&entry->writer_lock);

  zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
  wait_for_readers(z_standby);

  clone_zone_arena(z_active, z_standby);

  int prcount = 0, upcount = 0;
  int rcode = process_update_sections(req, req_len, entry->domain, z_standby, &prcount, &upcount);
  if (rcode != 0) {
    pthread_mutex_unlock(&entry->writer_lock);
    return rcode;
  }

  bump_soa_serial_in_arena(z_standby);

  if (build_zone_index(z_standby) != 0) {
    pthread_mutex_unlock(&entry->writer_lock);
    syslog(LOG_ERR, "[Zone] Memory allocation failed while building index after Update for '%s'", entry->domain);
    return 2; // SERVFAIL
  }

  compute_ixfr_diff(entry, z_active, z_standby);

  atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
  pthread_mutex_unlock(&entry->writer_lock);

  atomic_store_explicit(&entry->notify_now, true, memory_order_release);
  if (g_control_kq != -1) {
    struct kevent ev;
    EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
  }

  syslog(LOG_NOTICE,
         "[Update] client=%s key=%s zone='%s' prcount=%d upcount=%d "
         "(in-memory only, will revert on reload)",
         client_ip, matched_key_name, entry->domain, prcount, upcount);

  return 0; // NOERROR
}

static bool check_acl(const char *client_ip, char **acl_list, int acl_count);

static view_snapshot_t *select_view(zone_db_snapshot_t *snap, const char *client_ip) {
  for (size_t i = 0; i < snap->view_count; i++) {
    if (check_acl(client_ip, snap->views[i].match_clients, snap->views[i].match_clients_count)) {
      return &snap->views[i];
    }
  }
  return NULL;
}

int process_dns_query(const uint8_t *req, size_t req_len, uint8_t *res,
                      size_t max_res_len, const char *qname, uint16_t qtype,
                      const char *client_ip, compress_ctx_t *comp_ctx,
                      bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                      zone_db_snapshot_t *snap) {
  uint8_t tsig_mac[64];
  size_t tsig_mac_len = 0;
  char current_qname[256];
  strncpy(current_qname, qname, 255);
  current_qname[255] = '\0';
  size_t q_len = strlen(current_qname);
  zone_arena_t *current_zone = NULL;
  zone_db_entry_t *db_entry = NULL;
  size_t longest_match_len = 0;
  view_snapshot_t *view = NULL;

  if (snap) {
    view = select_view(snap, client_ip);
    if (view) {
      for (size_t i = 0; i < view->zone_count; i++) {
        size_t z_len = strlen(view->entries[i]->domain);
        bool match = false;
        
        if (q_len == z_len &&
            strcasecmp(current_qname, view->entries[i]->domain) == 0)
          match = true;
        else if (q_len > z_len && current_qname[q_len - z_len - 1] == '.' &&
                 strcasecmp(current_qname + q_len - z_len,
                            view->entries[i]->domain) == 0)
          match = true;
        if (match && z_len > longest_match_len) {
          longest_match_len = z_len;
          db_entry = view->entries[i];
        }
      }
    }
  }

  if (out_rrl_cfg) {
    server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    *out_rrl_cfg = &cfg->rrl;
    if (db_entry && view) {
      zone_config_t *zcfg = find_zone_config_in_view(cfg, view->name, db_entry->domain);
      if (zcfg && zcfg->rrl.configured) {
        *out_rrl_cfg = &zcfg->rrl;
      }
    }
  }

  if (req_len < DNS_HEADER_SIZE) {
    return -1;
  }
  
  uint16_t qdcount = (req[4] << 8) | req[5],
           ancount_req = (req[6] << 8) | req[7],
           nscount_req = (req[8] << 8) | req[9],
           arcount_req = (req[10] << 8) | req[11];

  edns_info_t edns;
  memset(&edns, 0, sizeof(edns));
  edns.present = false;
  if (parse_edns_opt(req, req_len, qdcount, ancount_req, nscount_req, arcount_req, &edns) < 0) {
    memcpy(res, req, DNS_HEADER_SIZE);
    res[2] |= 0x80;
    res[3] = (res[3] & 0x0F) | 0x01; // FORMERR
    memset(&res[4], 0, 8); // qdcount, ancount, nscount, arcount = 0
    return DNS_HEADER_SIZE;
  }
  edns.ede_count = 0; // 反射防止

  server_config_t *cfg_for_ede = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  
  if (!cfg_for_ede || !cfg_for_ede->rfc10029_mqtype_enable) {
    edns.has_mqtype_query = false;
    edns.saw_invalid_mqtype_response_in_query = false;
    edns.mqtype_count = 0;
  }

  if (edns.saw_invalid_mqtype_response_in_query) {
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 1; // FORMERR
    res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0;
    uint16_t offset = DNS_HEADER_SIZE;
    uint16_t arcount = 0;
    if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    res[10] = arcount >> 8; res[11] = arcount & 0xFF;
    return offset;
  }

  if (edns.present && edns.version > 0) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80; // QR=1
    res[3] &= 0xF0; // RCODE=0 (Base RCODE)
    
    // 質問セクション以降をクリア
    res[6] = 0; res[7] = 0; // ANCOUNT=0
    res[8] = 0; res[9] = 0; // NSCOUNT=0
    
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    uint16_t arcount = 0;
    
    // RFC 6891: 応答にはサーバーがサポートする最大のバージョン(0)をセットする
    edns.version = 0;
    
    // rcode_ext = 1 (1 << 4 | Base 0 = 16 = BADVERS)
    assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 1);
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  uint8_t opcode = (req[2] >> 3) & 0x0F;
  if (opcode != 0 && opcode != 4 && opcode != 5) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 0x04; // NOTIMP
    add_ede(&edns, cfg_for_ede->send_extended_errors, 21, "This opcode is not supported by this server");
    
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  // RFC 9619: OPCODE=0(QUERY) allows QDCOUNT 0 or 1; only QDCOUNT>1 is FORMERR.
  // OPCODE=4(NOTIFY)/5(UPDATE) still require QDCOUNT==1.
  bool qdcount_invalid = (opcode == 0) ? (qdcount > 1) : (qdcount != 1);
  if (qdcount_invalid) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0x0F) | 0x01; // FORMERR
    add_ede(&edns, cfg_for_ede->send_extended_errors, 0, NULL);
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  // RFC 9619: QDCOUNT=0 QUERY – no question section, return minimal response.
  if (opcode == 0 && qdcount == 0) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80; // QR=1
    res[3] &= 0xF0; // NOERROR
    res[6] = 0; res[7] = 0; // ANCOUNT=0
    res[8] = 0; res[9] = 0; // NSCOUNT=0
    uint16_t offset0 = DNS_HEADER_SIZE;
    uint16_t arcount0 = 0;
    if (edns.present) {
      if (edns.has_cookie) {
        // Refresh server cookie for cookie-only probes (RFC 7873 §5.4)
        edns.server_cookie_len = 16;
        generate_server_cookie(client_ip, edns.client_cookie, edns.server_cookie, time(NULL));
      }
      assemble_edns_opt(res, max_res_len, &offset0, &arcount0, &edns, 0);
    }
    res[10] = arcount0 >> 8;
    res[11] = arcount0 & 0xFF;
    return offset0;
  }

  if (opcode == 4) { // NOTIFY
    if (edns.has_mqtype_query) {
      res[2] |= 0x80; res[3] = (res[3] & 0xF0) | 1;
      res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0;
      return DNS_HEADER_SIZE;
    }
    bool auth = false;
    tsig_key_t *matched_key = NULL;
    tsig_key_t *attempted_key = NULL;
    int tsig_error_code = 0;
    
    if (db_entry && view) {
      server_config_t *cfg =
          atomic_load_explicit(&g_config_db.active, memory_order_acquire);
      zone_config_t *zcfg = find_zone_config_in_view(cfg, view->name, db_entry->domain);
      if (zcfg && zcfg->masters_count > 0) {
        for (int k = 0; k < zcfg->masters_count; k++) {
          if (strcmp(client_ip, zcfg->masters[k].ip) == 0) {
            auth = true;
            break;
          }
        }
        if (auth && zcfg->tsig_key && zcfg->tsig_key[0] != '\0') {
          tsig_key_t *k = cfg->keys;
          while (k) {
            if (strcmp(k->name, zcfg->tsig_key) == 0) {
              matched_key = k;
              break;
            }
            k = k->next;
          }
          if (!matched_key) {
            auth = false;
          } else {
            attempted_key = matched_key;
            int err = tsig_verify_packet(req, req_len, matched_key, tsig_mac, &tsig_mac_len);
            if (err != 0) {
              auth = false;
              tsig_error_code = err > 0 ? err : 16;
            }
          }
        }
      }
    }
      
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x84; // QR=1, AA=1
    
    if (auth) {
      res[3] &= 0x0F;
      atomic_store_explicit(&db_entry->refresh_now, true, memory_order_release);
      if (g_control_kq != -1) {
        struct kevent ev;
        EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
      }
    } else {
      if (attempted_key) {
          res[3] = (res[3] & 0xF0) | 9; // NOTAUTH
          add_ede(&edns, cfg_for_ede->send_extended_errors, 18, "Invalid TSIG");
      } else {
          res[3] = (res[3] & 0xF0) | 5; // REFUSED
          add_ede(&edns, cfg_for_ede->send_extended_errors, 18, "Query refused due to access control");
      }
    }
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    
    tsig_key_t *sign_key = auth ? matched_key : attempted_key;
    if (sign_key) {
      size_t sign_len = offset;
      tsig_sign_packet(res, &sign_len, max_res_len, sign_key, auth ? 0 : tsig_error_code, tsig_mac, &tsig_mac_len, false);
      offset = sign_len;
    }
    return offset;
  }

  if (opcode == 5) { // UPDATE
    if (edns.has_mqtype_query) {
      res[2] |= 0x80; res[3] = (res[3] & 0xF0) | 1;
      res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0;
      return DNS_HEADER_SIZE;
    }
    bool auth = false;
    tsig_key_t *matched_key = NULL;
    tsig_key_t *attempted_key = NULL;
    int tsig_error_code = 0;
    if (db_entry && view) {
      server_config_t *cfg =
          atomic_load_explicit(&g_config_db.active, memory_order_acquire);
      zone_config_t *zcfg = find_zone_config_in_view(cfg, view->name, db_entry->domain);
      if (zcfg && zcfg->allow_update_count > 0) {
        tsig_key_t *k = cfg->keys;
        while (k) {
          bool key_allowed = false;
          for (int i = 0; i < zcfg->allow_update_count; i++) {
            if (strcmp(k->name, zcfg->allow_update[i]) == 0) {
              key_allowed = true;
              break;
            }
          }
          if (key_allowed) {
            attempted_key = k;
            int err = tsig_verify_packet(req, req_len, k, tsig_mac, &tsig_mac_len);
            if (err == 0) {
              matched_key = k;
              auth = true;
              break;
            } else {
              tsig_error_code = err > 0 ? err : 16;
            }
          }
          k = k->next;
        }
      }
    }
    
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80; // QR=1
    
    int rcode = 5; // REFUSED
    if (auth) {
      rcode = handle_dynamic_update(req, req_len, db_entry, client_ip, matched_key->name);
    } else {
      if (attempted_key) {
        rcode = 9; // NOTAUTH
        add_ede(&edns, cfg_for_ede->send_extended_errors, 18, "Invalid TSIG");
      } else {
        add_ede(&edns, cfg_for_ede->send_extended_errors, 18, "Query refused due to access control");
      }
    }
    
    // Some rcodes like FORMERR (1) shouldn't leak the RCODE logic into res[3] directly without properly mapping
    res[3] = (res[3] & 0xF0) | (rcode & 0x0F);
    
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    
    tsig_key_t *sign_key = auth ? matched_key : attempted_key;
    if (sign_key) {
      size_t sign_len = offset;
      tsig_sign_packet(res, &sign_len, max_res_len, sign_key, auth ? 0 : tsig_error_code, tsig_mac, &tsig_mac_len, false);
      offset = sign_len;
    }
    return offset;
  }

  if (db_entry) {
    do {
      current_zone =
          atomic_load_explicit(&db_entry->rcu.active, memory_order_acquire);
      atomic_fetch_add_explicit(&current_zone->reader_count, 1,
                                memory_order_acquire);
      if (current_zone ==
          atomic_load_explicit(&db_entry->rcu.active, memory_order_acquire))
        break;
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                memory_order_release);
    } while (1);
  }
  compress_ctx_init_packet(comp_ctx);

  if (edns.present && max_res_len == UDP_DEFAULT_MAX_RES_LEN) {
    if (edns.udp_payload_size > 1232)
      edns.udp_payload_size = 1232;
    if (edns.udp_payload_size > UDP_DEFAULT_MAX_RES_LEN)
      max_res_len = edns.udp_payload_size;
  }

  uint8_t ext_rcode_out = 0;
  bool is_badcookie = false;
  
  if (edns.has_cookie) {
      if (edns.server_cookie_len == 0) {
          edns.server_cookie_len = 16;
          generate_server_cookie(client_ip, edns.client_cookie, edns.server_cookie, time(NULL));
      } else {
          bool valid = false;
          if (edns.server_cookie_len == 16 && edns.server_cookie[0] == 1) {
              uint32_t ts = ((uint32_t)edns.server_cookie[4] << 24) |
                            ((uint32_t)edns.server_cookie[5] << 16) |
                            ((uint32_t)edns.server_cookie[6] << 8) |
                            edns.server_cookie[7];
              uint32_t now = time(NULL);
              if ((now >= ts && now - ts <= 3600) || (now < ts && ts - now <= 300)) {
                  uint8_t expected_server_cookie[16];
                  generate_server_cookie(client_ip, edns.client_cookie, expected_server_cookie, ts);
                  if (memcmp(edns.server_cookie + 8, expected_server_cookie + 8, 8) == 0) {
                      valid = true;
                  }
              }
          }
          if (!valid) {
              is_badcookie = true;
              ext_rcode_out = 1; // BADCOOKIE = combined RCODE 23 = (ext=1 << 4) | base=7
              edns.server_cookie_len = 16;
              generate_server_cookie(client_ip, edns.client_cookie, edns.server_cookie, time(NULL));
          }
      }
  }

  size_t q_offset = DNS_HEADER_SIZE;
  if (skip_wire_name(req, req_len, q_offset, &q_offset) != 0) {
    if (current_zone)
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
    return -1;
  }
  if (q_offset + 4 > req_len) {
    if (current_zone)
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                memory_order_release);
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0x0F) | 0x01;
    add_ede(&edns, cfg_for_ede->send_extended_errors, 0, NULL);
    uint16_t offset = copy_len;
    uint16_t arcount = 0;
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }
    if (db_entry && db_entry->expire > 0) {
        time_t last_ok = atomic_load_explicit(&db_entry->last_successful_transfer, memory_order_acquire);
        if (last_ok > 0 && (time(NULL) - last_ok) > (time_t)db_entry->expire) {
            if (!cfg_for_ede->serve_stale) {
                if (current_zone)
                    atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
                size_t copy_len = q_offset + 4 > max_res_len ? max_res_len : q_offset + 4;
                memcpy(res, req, copy_len);
                res[2] |= 0x80;
                res[3] = (res[3] & 0x0F) | 0x02; // SERVFAIL
                add_ede(&edns, cfg_for_ede->send_extended_errors, 3, "Zone expired (SOA EXPIRE exceeded)");
                uint16_t offset = copy_len;
                uint16_t arcount = 0;
                res[6] = 0; res[7] = 0; // ANCOUNT = 0
                res[8] = 0; res[9] = 0; // NSCOUNT = 0
                if (edns.present) {
                    assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
                }
                res[10] = arcount >> 8;
                res[11] = arcount & 0xFF;
                return offset;
            } else {
                add_ede(&edns, cfg_for_ede->send_extended_errors, 3, "Stale Answer (Zone EXPIRED)");
            }
        }
    }

    uint16_t qclass = (req[q_offset + 2] << 8) | req[q_offset + 3];

    // UDP経由(is_tcp == 0)でAXFR(252)を受信した場合はRFC 5936違反のためFORMERRを返す
    if (!is_tcp && qtype == 252) {
      if (current_zone)
        atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                  memory_order_release);
      size_t copy_len = q_offset + 4 > max_res_len ? max_res_len : q_offset + 4;
      memcpy(res, req, copy_len);
      res[2] |= 0x80; // QR = 1
      res[3] = (res[3] & 0xF0) | 1; // RCODE = 1 (FORMERR)
      res[4] = 0; res[5] = 1; // QDCOUNT = 1
      res[6] = 0; res[7] = 0; // ANCOUNT = 0
      res[8] = 0; res[9] = 0; // NSCOUNT = 0
      res[10] = 0; res[11] = 0; // ARCOUNT = 0
      return copy_len;
    }

    if (qclass != 1 && qclass != 255) {
    if (current_zone)
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                memory_order_release);
    size_t copy_len = q_offset + 4 > max_res_len ? max_res_len : q_offset + 4;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0x0F) | 0x05;
    add_ede(&edns, cfg_for_ede->send_extended_errors, 0, NULL);
    uint16_t offset = copy_len;
    uint16_t arcount = 0;
    res[6] = 0; res[7] = 0; // ANCOUNT = 0
    res[8] = 0; res[9] = 0; // NSCOUNT = 0
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }
  q_offset += 4;
  memcpy(res, req, q_offset);
  res[2] |= 0x84;
  res[3] &= 0x0F;
  uint16_t *res_ancount = (uint16_t *)&res[6],
           *res_nscount = (uint16_t *)&res[8],
           *res_arcount = (uint16_t *)&res[10];
  *res_ancount = 0;
  *res_nscount = 0;
  *res_arcount = 0;
  if (!current_zone) {
    res[3] |= 5;
    if (!view) {
      add_ede(&edns, cfg_for_ede->send_extended_errors, 18, "Query refused due to access control (no view matched)");
    } else {
      add_ede(&edns, cfg_for_ede->send_extended_errors, 20, "This server is not authoritative for the queried zone");
    }
    uint16_t offset = q_offset;
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out);
      *res_arcount = htons(arcount);
    }
    return offset;
  }

  if (current_zone->count == 0) {
    res[3] |= 2; // SERVFAIL
    add_ede(&edns, cfg_for_ede->send_extended_errors, 14, "Zone not ready (empty)");
    uint16_t offset = q_offset;
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out);
      *res_arcount = htons(arcount);
    }
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
    return offset;
  }

  uint16_t offset = q_offset, ancount = 0, nscount = 0, arcount = 0;

  if (is_badcookie) {
    res[3] = (res[3] & 0xF0) | 0x07;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out);
    }
    *res_arcount = htons(arcount);
    if (current_zone)
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
    return offset;
  }

  uint16_t qtypes[17];
  int num_qtypes = 1;
  qtypes[0] = qtype;

  if (edns.has_mqtype_query) {
    if (edns.mqtype_count == 0 || is_non_data_rrtype(qtype)) {
      if (current_zone)
        atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
      res[2] |= 0x80;
      res[3] = (res[3] & 0xF0) | 1; // FORMERR
      res[6] = 0; res[7] = 0;
      res[8] = 0; res[9] = 0;
      offset = q_offset;
      arcount = 0;
      if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
      *res_arcount = htons(arcount);
      return offset;
    }
    int limit = cfg_for_ede ? cfg_for_ede->max_mqtypes : 4;
    for (int i = 0; i < edns.mqtype_count && num_qtypes <= limit; i++) {
       uint16_t mq = edns.mqtypes[i];
       if (is_non_data_rrtype(mq)) {
          if (current_zone)
            atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
          res[2] |= 0x80;
          res[3] = (res[3] & 0xF0) | 1;
          res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0;
          offset = q_offset; arcount = 0;
          if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
          *res_arcount = htons(arcount);
          return offset;
       }
       bool dup = false;
       for (int j = 0; j < num_qtypes; j++) { if (qtypes[j] == mq) { dup = true; break; } }
       if (dup) {
          if (current_zone)
            atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
          res[2] |= 0x80;
          res[3] = (res[3] & 0xF0) | 1;
          res[6] = 0; res[7] = 0; res[8] = 0; res[9] = 0;
          offset = q_offset; arcount = 0;
          if (edns.present) assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
          *res_arcount = htons(arcount);
          return offset;
       }
       qtypes[num_qtypes++] = mq;
    }
    edns.mqtype_count = num_qtypes - 1;
    for (int i = 0; i < edns.mqtype_count; i++) edns.mqtypes[i] = qtypes[i+1];
  }

  uint32_t qtx_included = 0;
  resolve_name(current_qname, qtypes, num_qtypes, &db_entry, &current_zone, res, max_res_len,
               &offset, comp_ctx, &ancount, &nscount, &arcount,
               cfg_for_ede ? cfg_for_ede->minimal_responses : false,
               cfg_for_ede ? cfg_for_ede->minimal_any : false,
               cfg_for_ede ? cfg_for_ede->minimal_any_ttl : 86400,
               edns.dnssec_ok, view, &qtx_included);

  if (edns.has_mqtype_query) {
    if (res[2] & 0x02) {
      edns.mqtype_count = 0;
    } else {
      int new_count = 0;
      for (int i = 1; i < num_qtypes; i++) {
        if (qtx_included & (1 << i)) {
          edns.mqtypes[new_count++] = qtypes[i];
        }
      }
      edns.mqtype_count = new_count;
    }
  }

  if (edns.present) {
    assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out);
  }

  *res_ancount = htons(ancount);
  *res_nscount = htons(nscount);
  *res_arcount = htons(arcount);
  if (current_zone)
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
  return offset;
}

// ============================================================================
// 9. AXFR専用バックグラウンドスレッド (Detached)
// ============================================================================
typedef struct {
  char master_ip[64];
  int master_port;
  char domain[256];
  zone_db_entry_t *entry;
  tsig_key_t *tsig_key;
} axfr_bg_ctx_t;

void *axfr_bg_thread_func(void *arg) {
  atomic_fetch_add_explicit(&g_xfers_running, 1, memory_order_relaxed);
  axfr_bg_ctx_t *ctx = (axfr_bg_ctx_t *)arg;
  struct sockaddr_storage master_addr;
  memset(&master_addr, 0, sizeof(master_addr));
  int domain_family = AF_INET;
  if (inet_pton(AF_INET, ctx->master_ip,
                &((struct sockaddr_in *)&master_addr)->sin_addr) == 1) {
    domain_family = AF_INET;
    master_addr.ss_family = AF_INET;
    ((struct sockaddr_in *)&master_addr)->sin_port =
        htons(ctx->master_port > 0 ? ctx->master_port : 53);
  } else if (inet_pton(AF_INET6, ctx->master_ip,
                       &((struct sockaddr_in6 *)&master_addr)->sin6_addr) ==
             1) {
    domain_family = AF_INET6;
    master_addr.ss_family = AF_INET6;
    ((struct sockaddr_in6 *)&master_addr)->sin6_port =
        htons(ctx->master_port > 0 ? ctx->master_port : 53);
  } else {
    syslog(LOG_ERR, "[AXFR] Invalid master IP address format: '%s'", ctx->master_ip);
    if (ctx->entry)
      atomic_store_explicit(&ctx->entry->is_transferring, false, memory_order_release);
    free(ctx);
    atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
    pthread_exit(NULL);
  }

  size_t addr_len = (domain_family == AF_INET) ? sizeof(struct sockaddr_in)
                                               : sizeof(struct sockaddr_in6);
  int tcp_fd = broker_connect(domain_family, SOCK_STREAM,
                              (struct sockaddr *)&master_addr, addr_len);
  if (tcp_fd >= 0) {
    limit_client_socket_rights(tcp_fd);
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
    tcp_stream_ctx_t stream_ctx = {0};
    axfr_session_t session = {0};
    uint8_t axfr_req[2048];
    uint16_t req_len = 0;
    uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
    axfr_req[2] = id >> 8;
    axfr_req[3] = id & 0xFF;
    axfr_req[4] = 0x00;
    axfr_req[5] = 0x00;
    axfr_req[6] = 0x00;
    axfr_req[7] = 0x01;
    axfr_req[8] = 0x00;
    axfr_req[9] = 0x00;
    axfr_req[10] = 0x00;
    axfr_req[11] = 0x00;
    axfr_req[DNS_HEADER_SIZE] = 0x00;
    axfr_req[13] = 0x01;
    req_len = 14;
    const char *d = ctx->domain;
    while (*d) {
      const char *dot = strchr(d, '.');
      size_t len = dot ? (size_t)(dot - d) : strlen(d);
      if (len > 63)
        len = 63;
      if (req_len + len + 2 > sizeof(axfr_req) - UDP_DEFAULT_MAX_RES_LEN)
        break;
      axfr_req[req_len++] = (uint8_t)len;
      memcpy(&axfr_req[req_len], d, len);
      req_len += len;
      if (!dot)
        break;
      d = dot + 1;
    }
    axfr_req[req_len++] = 0;
    uint32_t active_serial = ctx->entry ? ctx->entry->serial : 0;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = active_serial ? 251 : 252;
    session.is_ixfr = active_serial ? true : false;
    session.client_serial = active_serial;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 1;
    if (active_serial) {
      axfr_req[10] = 0;
      axfr_req[11] = 1;
      axfr_req[req_len++] = 0xC0;
      axfr_req[req_len++] = 0x0C;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 6;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 1;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0x00;
      axfr_req[req_len++] = 22;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = 0;
      axfr_req[req_len++] = active_serial >> 24;
      axfr_req[req_len++] = (active_serial >> 16) & 0xFF;
      axfr_req[req_len++] = (active_serial >> 8) & 0xFF;
      axfr_req[req_len++] = active_serial & 0xFF;
      for (int i = 0; i < 16; i++)
        axfr_req[req_len++] = 0;
    }
    axfr_req[req_len++] = 0;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 41;
    axfr_req[req_len++] = 0x10;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    axfr_req[req_len++] = 0x00;
    if (ctx->tsig_key) {
      size_t p_len = req_len - 2;
      tsig_sign_packet(&axfr_req[2], &p_len, sizeof(axfr_req) - 2,
                       ctx->tsig_key, 0, NULL, NULL, false);
      req_len = p_len + 2;
    }
    uint16_t msg_len = req_len - 2;
    axfr_req[0] = msg_len >> 8;
    axfr_req[1] = msg_len & 0xFF;
    if (send(tcp_fd, axfr_req, req_len, 0) == req_len) {
      int axfr_res = handle_axfr_event(tcp_fd, ctx->entry, &stream_ctx, &session, ctx->tsig_key);
      if (axfr_res == 1) {
        syslog(LOG_NOTICE, "[AXFR] Successfully transferred zone %s from %s", ctx->domain, ctx->master_ip);
      } else if (axfr_res == 2) {
        // Zone is up to date. Do not log to avoid spam on short refresh intervals.
      } else {
        syslog(LOG_ERR, "[AXFR] Failed to transfer zone %s from %s", ctx->domain, ctx->master_ip);
      }
    } else {
      syslog(LOG_ERR, "[AXFR] Failed to send request for zone %s to %s", ctx->domain, ctx->master_ip);
    }
    close(tcp_fd);
  } else {
    syslog(LOG_ERR, "[AXFR] Failed to connect to %s for zone %s", ctx->master_ip, ctx->domain);
  }
  if (ctx->entry)
    atomic_store_explicit(&ctx->entry->is_transferring, false,
                          memory_order_release);
  free(ctx);
  atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
  pthread_exit(NULL);
}

void send_notify_to_all(const char *domain, const char *view_name) {
  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  if (!active)
    return;
  zone_config_t *zone = find_zone_config_in_view(active, view_name, domain);
  if (!zone || zone->also_notify_count == 0)
    return;

  uint8_t req[UDP_DEFAULT_MAX_RES_LEN];
  memset(req, 0, DNS_HEADER_SIZE);
  uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
  req[0] = id >> 8;
  req[1] = id & 0xFF;
  req[2] = 0x20;
  req[3] = 0;
  req[4] = 0;
  req[5] = 1;
  size_t offset = DNS_HEADER_SIZE;
  long w = write_uncompressed_name(req, offset, sizeof(req), domain);
  if (w > 0) offset += (size_t)w;
  req[offset++] = 0;
  req[offset++] = 6;
  req[offset++] = 0;
  req[offset++] = 1;

  for (int i = 0; i < zone->also_notify_count; i++) {
    struct sockaddr_storage dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    int domain_family = AF_INET;
    if (inet_pton(AF_INET, zone->also_notify[i].ip,
                  &((struct sockaddr_in *)&dest_addr)->sin_addr) == 1) {
      domain_family = AF_INET;
      dest_addr.ss_family = AF_INET;
      ((struct sockaddr_in *)&dest_addr)->sin_port =
          htons(zone->also_notify[i].port);
    } else if (inet_pton(AF_INET6, zone->also_notify[i].ip,
                         &((struct sockaddr_in6 *)&dest_addr)->sin6_addr) ==
               1) {
      domain_family = AF_INET6;
      dest_addr.ss_family = AF_INET6;
      ((struct sockaddr_in6 *)&dest_addr)->sin6_port =
          htons(zone->also_notify[i].port);
    } else
      continue;

    udp_ipc_t msg;
    msg.sock_fd_idx = -1; // -1 = NOTIFY / Dynamic UDP
    msg.client_addr = dest_addr;
    msg.addr_len = (domain_family == AF_INET) ? sizeof(struct sockaddr_in)
                                              : sizeof(struct sockaddr_in6);
    msg.payload_len = offset;

    uint8_t buf[2048];
    memcpy(buf, &msg, sizeof(msg));
    memcpy(buf + sizeof(msg), req, offset);
    send(g_notify_ipc[1], buf, sizeof(msg) + offset, 0);
  }
}

// ============================================================================
// 10. Logging
// ============================================================================

static void init_logging_channels(server_config_t *cfg) {
  log_channel_t *ch = cfg->logging.channels;
  while (ch) {
    if (ch->file_path) {
      ch->fd = open_via_dir_cache(ch->file_path, O_WRONLY | O_CREAT | O_APPEND,
                                  0644, true);
      if (ch->fd >= 0) {
        struct stat st;
        if (fstat(ch->fd, &st) == 0)
          ch->current_size = st.st_size;
      }
      time_t now = time(NULL);
      struct tm tm_info;
      localtime_r(&now, &tm_info);
      ch->current_date = (tm_info.tm_year + 1900) * 10000 +
                         (tm_info.tm_mon + 1) * 100 + tm_info.tm_mday;
    }
    ch = ch->next;
  }
}

static void free_logging_channels(server_config_t *cfg) {
  log_channel_t *ch = cfg->logging.channels;
  while (ch) {
    log_channel_t *next = ch->next;
    if (ch->fd >= 0)
      close(ch->fd);
    if (ch->name)
      free(ch->name);
    if (ch->file_path)
      free(ch->file_path);
    free(ch);
    ch = next;
  }
  cfg->logging.channels = NULL;
  cfg->logging.queries_channel = NULL;
  if (cfg->logging.queries_channel_name) {
    free(cfg->logging.queries_channel_name);
    cfg->logging.queries_channel_name = NULL;
  }
  cfg->logging.responses_channel = NULL;
  if (cfg->logging.responses_channel_name) {
    free(cfg->logging.responses_channel_name);
    cfg->logging.responses_channel_name = NULL;
  }
}

static void submit_response_log(log_action_t action, const char *client_ip, int client_port, const char *qname, 
                                uint16_t qclass, uint16_t qtype, uint8_t rcode, 
                                bool has_edns, bool dnssec_ok) {
    server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    if (!cfg || !cfg->logging.responses_channel) return;

    uint64_t t = atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit(&g_resp_log_head, memory_order_acquire);
    
    // ロックフリー CAS ループ (バッファフル時はDDoS状態とみなし、潔くログをドロップする)
    do {
        if (t - h >= RESP_LOG_RING_SIZE) return; 
    } while (!atomic_compare_exchange_weak_explicit(&g_resp_log_tail, &t, t + 1, 
                                                    memory_order_acq_rel, memory_order_relaxed));
    
    uint32_t idx = t & (RESP_LOG_RING_SIZE - 1);
    resp_log_entry_t *entry = &g_resp_log_ring[idx];
    
    clock_gettime(CLOCK_REALTIME, &entry->ts);
    entry->action = action;
    strncpy(entry->client_ip, client_ip, INET6_ADDRSTRLEN - 1);
    entry->client_ip[INET6_ADDRSTRLEN - 1] = '\0';
    entry->client_port = client_port;
    strncpy(entry->qname, qname, 255);
    entry->qname[255] = '\0';
    entry->qclass = qclass;
    entry->qtype = qtype;
    entry->rcode = rcode;
    entry->has_edns = has_edns;
    entry->dnssec_ok = dnssec_ok;
    
    // データ書き込み完了をConsumerに通知
    atomic_store_explicit(&entry->ready, true, memory_order_release);
}


static void log_write_rotated(log_channel_t *ch, const char *log_buf, int len, struct tm *tm_info) {
    int today = (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 + tm_info->tm_mday;
    pthread_mutex_lock(&ch->lock);
    bool rotate = false;
    if (ch->size_limit > 0 && ch->current_size + len > ch->size_limit)
        rotate = true;
    else if (ch->suffix_timestamp && ch->current_date != today)
        rotate = true;
    if (rotate) {
        if (ch->fd >= 0) {
            close(ch->fd);
        }
        ch->fd = -1;
        int reopen_flags = O_WRONLY | O_CREAT | O_APPEND;
        if (ch->suffix_timestamp) {
            char new_name[600];
            int r = snprintf(new_name, sizeof(new_name), "%s.%08d", ch->file_path, ch->current_date);
            if (r > 0 && r < (int)sizeof(new_name))
                renameat_via_dir_cache(ch->file_path, new_name);
        } else if (ch->versions > 0) {
            for (int i = ch->versions - 1; i >= 0; i--) {
                char old_name[600], new_name[600];
                int r1 = (i == 0)
                             ? snprintf(old_name, sizeof(old_name), "%s", ch->file_path)
                             : snprintf(old_name, sizeof(old_name), "%s.%d", ch->file_path, i - 1);
                int r2 = snprintf(new_name, sizeof(new_name), "%s.%d", ch->file_path, i);
                if (r1 > 0 && r2 > 0)
                    renameat_via_dir_cache(old_name, new_name);
            }
        } else {
            reopen_flags |= O_TRUNC;
        }
        ch->fd = open_via_dir_cache(ch->file_path, reopen_flags, 0644, true);
        ch->current_size = 0;
        ch->current_date = today;
    }
    if (ch->fd >= 0) {
        ssize_t w = write(ch->fd, log_buf, len);
        if (w > 0)
            ch->current_size += w;
    }
    pthread_mutex_unlock(&ch->lock);
}

void *response_logger_thread_func(void *arg) {
    (void)arg;
    while (1) {
        uint64_t h = atomic_load_explicit(&g_resp_log_head, memory_order_relaxed);
        uint32_t idx = h & (RESP_LOG_RING_SIZE - 1);
        
        if (atomic_load_explicit(&g_resp_log_ring[idx].ready, memory_order_acquire)) {
            resp_log_entry_t *entry = &g_resp_log_ring[idx];
            server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
            
            if (cfg && cfg->logging.responses_channel) {
                log_channel_t *ch = cfg->logging.responses_channel;
                
                // 1. 時刻のフォーマット (ミリ秒対応)
                struct tm tm_info;
                localtime_r(&entry->ts.tv_sec, &tm_info);
                char time_str[64] = "";
                if (ch->print_time) {
                    char buf[32];
                    strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S", &tm_info);
                    snprintf(time_str, sizeof(time_str), "%s.%03ld ", buf, entry->ts.tv_nsec / 1000000);
                }

                // 2. クラスとタイプの文字列化
                char class_str[16];
                if (entry->qclass == 1) snprintf(class_str, sizeof(class_str), "IN");
                else if (entry->qclass == 255) snprintf(class_str, sizeof(class_str), "ANY");
                else snprintf(class_str, sizeof(class_str), "CLASS%d", entry->qclass);
                
                char type_str[32];
                const char *type_str_tmp = format_type_name(entry->qtype, type_str, sizeof(type_str));

                // 3. EDNSとRCODEの文字列化
                char edns_str[16] = "";
                if (entry->has_edns) snprintf(edns_str, sizeof(edns_str), "+E(0)%s", entry->dnssec_ok ? "D" : "K");
                
                const char *rcode_strs[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"};
                const char *rcode_str = (entry->rcode <= 10) ? rcode_strs[entry->rcode] : "UNKNOWN";
                
                // 4. BIND互換フォーマットへの組み立てと書き込み
                const char *action_str = "";
                if (entry->action == LOG_ACT_DROP_RRL) action_str = " [DROP:RRL]";
                else if (entry->action == LOG_ACT_DROP_MALFORMED) action_str = " [DROP:MALFORMED]";

                char log_buf[1024];
                int len = snprintf(log_buf, sizeof(log_buf), 
                                   "%s%s%sclient %s#%d (%s): response: %s %s %s %s -> %s%s\n", 
                                   time_str,
                                   ch->print_category ? "responses: " : "",
                                   ch->print_severity ? "info: " : "", 
                                   entry->client_ip, entry->client_port,
                                   entry->qname, entry->qname, class_str, type_str_tmp, edns_str, rcode_str, action_str);
                
                if (len > 0) {
                    if (len >= (int)sizeof(log_buf)) len = sizeof(log_buf) - 1;
                    log_write_rotated(ch, log_buf, len, &tm_info);
                }
            }
            
            // Consumerのポインタを進める
            atomic_store_explicit(&entry->ready, false, memory_order_release);
            atomic_fetch_add_explicit(&g_resp_log_head, 1, memory_order_release);
        } else {
            usleep(1000); // データ未着時は1msスリープしてCPU負荷を下げる
        }
    }
    return NULL;
}

static void write_query_log(const char *client_ip, int client_port,
                            const char *qname, uint16_t qclass, uint16_t qtype,
                            bool has_edns, bool dnssec_ok) {
  server_config_t *cfg =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  if (!cfg || !cfg->logging.queries_channel)
    return;
  log_channel_t *ch = cfg->logging.queries_channel;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm_info;
  localtime_r(&ts.tv_sec, &tm_info);
  
  char time_str[64] = "";
  if (ch->print_time) {
    char buf[32];
    strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S", &tm_info);
    snprintf(time_str, sizeof(time_str), "%s.%03ld ", buf,
             ts.tv_nsec / 1000000);
  }
  char class_str[16];
  if (qclass == 1)
    snprintf(class_str, sizeof(class_str), "IN");
  else if (qclass == 255)
    snprintf(class_str, sizeof(class_str), "ANY");
  else
    snprintf(class_str, sizeof(class_str), "CLASS%d", qclass);
  char type_str[32];
  const char *type_str_tmp = format_type_name(qtype, type_str, sizeof(type_str));
  char edns_str[16] = "";
  if (has_edns)
    snprintf(edns_str, sizeof(edns_str), "+E(0)%s", dnssec_ok ? "D" : "K");
  char log_buf[1024];
  int len = snprintf(log_buf, sizeof(log_buf),
                     "%s%s%sclient %s#%d (%s): query: %s %s %s %s\n", time_str,
                     ch->print_category ? "queries: " : "",
                     ch->print_severity ? "info: " : "", client_ip, client_port,
                     qname, qname, class_str, type_str_tmp, edns_str);
  if (len <= 0)
    return;
  if (len >= (int)sizeof(log_buf))
    len = sizeof(log_buf) - 1;
  log_write_rotated(ch, log_buf, len, &tm_info);
}

// ============================================================================
// 11. TCP & Worker Threads (サンドボックス内)
// ============================================================================

typedef struct {
  int client_fd;
  char client_ip[INET6_ADDRSTRLEN];
  int client_port;
  char qname[256];
  uint16_t qclass;
  uint16_t qtype;
  bool has_edns;
  bool dnssec_ok;
  uint8_t req[UDP_DEFAULT_MAX_RES_LEN];
  uint16_t req_len;
  tsig_key_t *tsig_key;
  uint8_t tsig_mac[64];
  size_t tsig_mac_len;
  zone_db_entry_t *entry;
  zone_db_snapshot_t *snap;
} axfr_worker_args_t;

static ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t n = send(fd, buf + sent, len - sent, 0);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        if (poll(&pfd, 1, 30000) <= 0)
          return -1;
        continue;
      }
      return -1;
    }
    if (n == 0)
      return -1;
    sent += n;
  }
  return sent;
}

void send_axfr_response(int client_fd, const char *qname __attribute__((unused)), uint8_t *req,
                        uint16_t req_len, tsig_key_t *tsig_key, zone_db_entry_t *entry,
                        uint8_t *req_mac, size_t req_mac_len) {
  if (!entry) {
    uint8_t res_buf[UDP_DEFAULT_MAX_RES_LEN];
    size_t copy_len = req_len > UDP_DEFAULT_MAX_RES_LEN ? UDP_DEFAULT_MAX_RES_LEN : req_len;
    memcpy(res_buf, req, copy_len);
    res_buf[2] |= 0x84;
    res_buf[3] |= 0x05;
    uint8_t len_prefix[2] = {copy_len >> 8, copy_len & 0xFF};
    send(client_fd, len_prefix, 2, 0);
    send(client_fd, res_buf, copy_len, 0);
    return;
  }
  zone_arena_t *current_zone = NULL;
  do {
    current_zone =
        atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
    atomic_fetch_add_explicit(&current_zone->reader_count, 1,
                              memory_order_acquire);
    if (current_zone ==
        atomic_load_explicit(&entry->rcu.active, memory_order_acquire))
      break;
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
  } while (1);
  if (!current_zone || current_zone->count == 0) {
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
    return;
  }

  uint8_t *res = malloc(65535);
  if (!res) {
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
    return;
  }
  size_t q_offset = DNS_HEADER_SIZE;
  if (skip_wire_name(req, req_len, q_offset, &q_offset) != 0) {
      free(res);
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
      return;
  }
  if (q_offset + 4 > req_len) {
    q_offset = req_len;
  } else {
    q_offset += 4;
  }
  uint16_t qtype = (q_offset >= 4) ? ((req[q_offset - 4] << 8) | req[q_offset - 3]) : 0;
  bool is_ixfr = (qtype == 251);
  uint32_t client_serial = 0;
  if (is_ixfr) {
    uint16_t nscount = (req[8] << 8) | req[9];
    if (nscount > 0) {
      size_t p = q_offset;
      size_t next_p;
      if (skip_wire_name(req, req_len, p, &next_p) == 0) {
        p = next_p;
        if (p + 10 <= req_len) {
          uint16_t auth_type = (req[p] << 8) | req[p+1];
          uint16_t auth_rdlen = (req[p+8] << 8) | req[p+9];
          p += 10;
          if (auth_type == 6 && p + auth_rdlen <= req_len) {
            size_t rp = p;
            if (skip_wire_name(req, req_len, rp, &next_p) == 0) {
              rp = next_p;
              if (skip_wire_name(req, req_len, rp, &next_p) == 0) {
                rp = next_p;
                if (rp + 4 <= p + auth_rdlen) {
                  client_serial = ((uint32_t)req[rp] << 24) | ((uint32_t)req[rp+1] << 16) | ((uint32_t)req[rp+2] << 8) | req[rp+3];
                }
              }
            }
          }
        }
      }
    }
  }
  uint16_t offset = q_offset;
  uint16_t answers = 0;
  uint16_t *res_ancount = (uint16_t *)&res[6];
  memset(res, 0, 65535);
  memcpy(res, req, q_offset);
  res[2] |= 0x84;
  res[3] &= 0x0F;
  res[8] = 0;
  res[9] = 0;
  res[10] = 0;
  res[11] = 0;
  compress_ctx_t comp_ctx;
  memset(&comp_ctx, 0, sizeof(comp_ctx));
  compress_ctx_init_packet(&comp_ctx);
  uint8_t tsig_mac[64];
  size_t tsig_mac_len = req_mac_len;
  if (req_mac_len > 0) memcpy(tsig_mac, req_mac, req_mac_len);
  bool is_subsequent = false;
  int soa_idx = -1;
  for (size_t i = 0; i < current_zone->count; i++) {
    if (current_zone->records[i].type_code == 6 &&
        strcasecmp(current_zone->records[i].name, entry->domain) == 0) {
      soa_idx = i;
      break;
    }
  }
  if (soa_idx < 0) {
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                              memory_order_release);
    free(res);
    return;
  }

  bool send_ixfr = false;
  ixfr_txn_t *txn_list[MAX_IXFR_HISTORY];
  int txn_count = 0;
  uint32_t current_serial = strtoul(current_zone->records[soa_idx].rdata[2], NULL, 10);

  if (is_ixfr && client_serial == current_serial) {
    send_ixfr = true;
  } else if (is_ixfr) {
    pthread_mutex_lock(&entry->ixfr_history.lock);
    if (entry->ixfr_history.count > 0) {
    int start_idx = (entry->ixfr_history.head + MAX_IXFR_HISTORY - entry->ixfr_history.count) % MAX_IXFR_HISTORY;
    int found_idx = -1;
    for (int i = 0; i < entry->ixfr_history.count; i++) {
      int idx = (start_idx + i) % MAX_IXFR_HISTORY;
      ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
      //syslog(LOG_NOTICE, "[DEBUG-IXFR] history[%d] old_serial: %u", i, txn->old_serial);
      if (txn && txn->old_serial == client_serial) {
        found_idx = i;
        break;
      }
    }
    if (found_idx >= 0) {
      bool continuous = true;
      uint32_t expected_serial = client_serial;
      for (int i = found_idx; i < entry->ixfr_history.count; i++) {
        int idx = (start_idx + i) % MAX_IXFR_HISTORY;
        ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
        if (!txn || txn->old_serial != expected_serial) {
          continuous = false;
          break;
        }
        expected_serial = txn->new_serial;
      }
      if (continuous && expected_serial == current_serial) {
        send_ixfr = true;
        for (int i = found_idx; i < entry->ixfr_history.count; i++) {
          int idx = (start_idx + i) % MAX_IXFR_HISTORY;
          ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
          if (txn) {
            atomic_fetch_add_explicit(&txn->ref_count, 1, memory_order_acquire);
            txn_list[txn_count++] = txn;
          }
        }
      }
      }
    }
    pthread_mutex_unlock(&entry->ixfr_history.lock);
  }

#define SERIALIZE_ADD_RECORD(rec_ptr) do { \
  uint16_t prev_offset = offset; \
  if (serialize_dns_record(res, 65000, &offset, (rec_ptr), &comp_ctx, NULL, 0xFFFFFFFF) < 0) { \
    *res_ancount = htons(answers); \
    if (tsig_key) { \
      size_t sign_len = prev_offset; \
      tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, tsig_mac, &tsig_mac_len, is_subsequent); \
      is_subsequent = true; \
      prev_offset = sign_len; \
    } \
    uint8_t len_prefix[2] = {prev_offset >> 8, prev_offset & 0xFF}; \
    if (send_tcp_robust(client_fd, len_prefix, 2) < 0) goto axfr_error; \
    if (send_tcp_robust(client_fd, res, prev_offset) < 0) goto axfr_error; \
    offset = q_offset; \
    answers = 0; \
    memset(res, 0, 65535); \
    memcpy(res, req, q_offset); \
    memset(&comp_ctx, 0, sizeof(comp_ctx)); \
    compress_ctx_init_packet(&comp_ctx); \
    res[2] |= 0x84; res[3] &= 0x0F; \
    res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0; \
    if (serialize_dns_record(res, 65000, &offset, (rec_ptr), &comp_ctx, NULL, 0xFFFFFFFF) < 0) { \
      syslog(LOG_ERR, "[AXFR] Record too large to fit in any TCP message (name=%s type=%u), aborting transfer", \
             (rec_ptr)->name ? (rec_ptr)->name : "(null)", (rec_ptr)->type_code); \
      goto axfr_error; \
    } \
  } \
  answers++; \
} while (0)

  if (send_ixfr) {
    SERIALIZE_ADD_RECORD(&current_zone->records[soa_idx]);
    for (int t = 0; t < txn_count; t++) {
      ixfr_txn_t *txn = txn_list[t];
      int soa_del_idx = -1;
      for (int i = 0; i < txn->deleted_count; i++) {
        if (txn->deleted[i].type_code == 6) { soa_del_idx = i; break; }
      }
      if (soa_del_idx >= 0) SERIALIZE_ADD_RECORD(&txn->deleted[soa_del_idx]);
      for (int i = 0; i < txn->deleted_count; i++) {
        if (i == soa_del_idx) continue;
        SERIALIZE_ADD_RECORD(&txn->deleted[i]);
      }
      int soa_add_idx = -1;
      for (int i = 0; i < txn->added_count; i++) {
        if (txn->added[i].type_code == 6) { soa_add_idx = i; break; }
      }
      if (soa_add_idx >= 0) SERIALIZE_ADD_RECORD(&txn->added[soa_add_idx]);
      for (int i = 0; i < txn->added_count; i++) {
        if (i == soa_add_idx) continue;
        SERIALIZE_ADD_RECORD(&txn->added[i]);
      }
    }
    if (txn_count > 0) {
      SERIALIZE_ADD_RECORD(&current_zone->records[soa_idx]);
    }
  } else {
    for (int step = 0; step < 3; step++) {
      size_t start_idx = 0, end_idx = 0;
      if (step == 0) {
        start_idx = soa_idx;
        end_idx = soa_idx + 1;
      } else if (step == 1) {
        start_idx = 0;
        end_idx = current_zone->count;
      } else if (step == 2) {
        start_idx = soa_idx;
        end_idx = soa_idx + 1;
      }
      for (size_t i = start_idx; i < end_idx; i++) {
        if (step == 1 && (int)i == soa_idx)
          continue;
        SERIALIZE_ADD_RECORD(&current_zone->records[i]);
      }
    }
  }
  if (answers > 0) {
    *res_ancount = htons(answers);
    if (tsig_key) {
      size_t sign_len = offset;
      tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, tsig_mac,
                       &tsig_mac_len, is_subsequent);
      offset = sign_len;
    }
    uint8_t len_prefix[2] = {offset >> 8, offset & 0xFF};
    if (send_tcp_robust(client_fd, len_prefix, 2) < 0)
      goto axfr_error;
    if (send_tcp_robust(client_fd, res, offset) < 0)
      goto axfr_error;
  }

  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
  atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
  return;

axfr_error:
  for (int t = 0; t < txn_count; t++) {
    if (atomic_fetch_sub_explicit(&txn_list[t]->ref_count, 1, memory_order_acq_rel) == 1) {
       free_ixfr_txn(txn_list[t]);
    }
  }
  if (res) free(res);
  atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
}

void *axfr_worker_thread(void *arg) {
  atomic_fetch_add_explicit(&g_xfers_running, 1, memory_order_relaxed);
  axfr_worker_args_t *args = (axfr_worker_args_t *)arg;
  zone_db_entry_t *entry = args->entry;
  send_axfr_response(args->client_fd, args->qname, args->req, args->req_len,
                     args->tsig_key, entry, args->tsig_mac, args->tsig_mac_len);
  
  submit_response_log(LOG_ACT_SENT, args->client_ip, args->client_port, args->qname, 
                      args->qclass, args->qtype, 0, args->has_edns, args->dnssec_ok);
  
  close(args->client_fd);
  dec_tcp_clients();
  zone_db_snapshot_t *worker_snap = args->snap;
  free(args);
  if (entry)
    atomic_fetch_sub(&entry->active_axfr, 1);
  release_zone_snapshot(worker_snap);
  atomic_fetch_sub_explicit(&g_xfers_running, 1, memory_order_relaxed);
  pthread_exit(NULL);
}

static bool check_acl(const char *client_ip, char **acl_list, int acl_count) {
    for (int i = 0; i < acl_count; i++) {
        char *rule = acl_list[i];
        bool is_deny = (rule[0] == '!');
        const char *target = is_deny ? rule + 1 : rule;
        if (match_cidr(client_ip, target)) {
            return !is_deny;
        }
    }
    return false;
}

void *worker_thread_func(void *arg) {
  worker_ctx_t *ctx = (worker_ctx_t *)arg;
  cpuset_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(ctx->core_id, &cpuset);
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t),
                         &cpuset) != 0)
    goto worker_startup_failed;

  int kq = kqueue();
  if (kq < 0)
    goto worker_startup_failed;
  int opt = 1;
  server_config_t *active_cfg =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  int port = active_cfg && active_cfg->port > 0 ? active_cfg->port : DNS_PORT;
  int bind_count = active_cfg ? active_cfg->bind_address_count : 0;

  for (int i = 0; i < (bind_count > 0 ? bind_count : 1); i++) {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    bool is_v4 = false;
    bool is_v6 = false;
    memset(&addr4, 0, sizeof(addr4));
    memset(&addr6, 0, sizeof(addr6));
    if (bind_count == 0) {
      addr4.sin_family = AF_INET;
      addr4.sin_addr.s_addr = INADDR_ANY;
      addr4.sin_port = htons(port);
      addr6.sin6_family = AF_INET6;
      addr6.sin6_addr = in6addr_any;
      addr6.sin6_port = htons(port);
      is_v4 = true;
      is_v6 = true;
    } else {
      if (inet_pton(AF_INET, active_cfg->bind_addresses[i], &addr4.sin_addr) ==
          1) {
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        is_v4 = true;
      } else if (inet_pton(AF_INET6, active_cfg->bind_addresses[i],
                           &addr6.sin6_addr) == 1) {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        is_v6 = true;
      }
    }

    if (is_v4) {
      int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (tcp_fd >= 0) {
        int flags = fcntl(tcp_fd, F_GETFL, 0);
        fcntl(tcp_fd, F_SETFL, flags | O_NONBLOCK);
#ifdef SO_REUSEPORT_LB
        setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
#else
        setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
        if (bind(tcp_fd, (struct sockaddr *)&addr4, sizeof(addr4)) == 0) {
          listen(tcp_fd, 1024);
          limit_server_socket_rights(tcp_fd, true);
          struct kevent ev;
          EV_SET(&ev, tcp_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)2);
          kevent(kq, &ev, 1, NULL, 0, NULL);
        } else
          close(tcp_fd);
      }
    }
    if (is_v6) {
      int tcp_fd = socket(AF_INET6, SOCK_STREAM, 0);
      if (tcp_fd >= 0) {
        int flags = fcntl(tcp_fd, F_GETFL, 0);
        fcntl(tcp_fd, F_SETFL, flags | O_NONBLOCK);
        setsockopt(tcp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
#ifdef SO_REUSEPORT_LB
        setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
#else
        setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
        if (bind(tcp_fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0) {
          listen(tcp_fd, 1024);
          limit_server_socket_rights(tcp_fd, true);
          struct kevent ev;
          EV_SET(&ev, tcp_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)2);
          kevent(kq, &ev, 1, NULL, 0, NULL);
        } else
          close(tcp_fd);
      }
    }
  }

  // FrontendからのUDP転送を受け取るIPCパイプをkqueueに登録 (udata=1)
  int my_ipc_fd = g_ipc_fds[ctx->thread_id][1];
  cap_rights_t ipc_rights;
  cap_rights_init(&ipc_rights, CAP_EVENT, CAP_READ, CAP_WRITE, CAP_RECV, CAP_SEND);
  cap_rights_limit(my_ipc_fd, &ipc_rights);
  struct kevent ev_ipc;
  EV_SET(&ev_ipc, my_ipc_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)1);
  kevent(kq, &ev_ipc, 1, NULL, 0, NULL);

  atomic_fetch_add(&g_bound_workers, 1);
  goto worker_startup_success;

worker_startup_failed:
  atomic_fetch_add(&g_bound_workers, 1);
  pthread_exit(NULL);

worker_startup_success:;
  compress_ctx_t thread_compress_ctx = {0};
  struct kevent ev_list[MAX_EVENTS];

  while (1) {
    int n_events = kevent(kq, NULL, 0, ev_list, MAX_EVENTS, NULL);
    if (n_events < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    for (int i = 0; i < n_events; i++) {
      if (ev_list[i].filter == EVFILT_TIMER) {
        int client_fd = ev_list[i].ident;
        tcp_stream_ctx_t *ctx_tcp = (tcp_stream_ctx_t *)ev_list[i].udata;
        close(client_fd);
        dec_tcp_clients();
        free(ctx_tcp);
      } else if (ev_list[i].udata == (void *)1) {
        // UDP (IPC経由)
        int active_fd = ev_list[i].ident; // my_ipc_fd
        while (1) {
          uint8_t req_buf_full[BUFFER_SIZE + sizeof(udp_ipc_t)];
          ssize_t received =
              recv(active_fd, req_buf_full, sizeof(req_buf_full), 0);
          if (received <= 0) {
            if (received == 0) atomic_store(&g_frontend_alive, false);
            break;
          }
          if (received < (ssize_t)sizeof(udp_ipc_t))
            continue;

          udp_ipc_t *ipc_msg = (udp_ipc_t *)req_buf_full;
          if (ipc_msg->payload_len > received - (ssize_t)sizeof(udp_ipc_t))
            continue;
          uint8_t *req_buf = req_buf_full + sizeof(udp_ipc_t);
          ssize_t payload_received = ipc_msg->payload_len;
          struct sockaddr_storage *client_addr = &ipc_msg->client_addr;

          char client_ip[INET6_ADDRSTRLEN] = "";
          if (client_addr->ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)client_addr)->sin_addr,
                      client_ip, INET6_ADDRSTRLEN);
          else if (client_addr->ss_family == AF_INET6)
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *)client_addr)->sin6_addr,
                      client_ip, INET6_ADDRSTRLEN);

          char qname[256] = "";
          uint16_t qtype = 0;
          if (payload_received > DNS_HEADER_SIZE) {
            size_t offset = DNS_HEADER_SIZE;
            size_t recv_len = (size_t)payload_received;
            size_t written = 0;
            while (offset < recv_len) {
              uint8_t len = req_buf[offset];
              if (len == 0 || (len & 0xC0) == 0xC0) {
                offset += (len == 0) ? 1 : 2;
                break;
              }
              if (offset + len + 1 > recv_len) break;
              offset++;
              if (written > 0 && qname[written - 1] != '.') {
                if (written < 255)
                  qname[written++] = '.';
              }
              if (offset + len <= recv_len) {
                size_t copy_len = len;
                if (written >= 255)
                  copy_len = 0;
                else if (written + copy_len > 255)
                  copy_len = 255 - written;
                if (copy_len > 0) {
                  memcpy(&qname[written], &req_buf[offset], copy_len);
                  written += copy_len;
                }
              }
              offset += len;
            }
            if (offset + 1 < recv_len)
              qtype = (req_buf[offset] << 8) | req_buf[offset + 1];
            if (written == 0 || (written > 0 && qname[written - 1] != '.')) {
              if (written < 255)
                qname[written++] = '.';
            }
            qname[written] = '\0';
          }

          int client_port = 0;
          if (client_addr->ss_family == AF_INET)
            client_port = ntohs(((struct sockaddr_in *)client_addr)->sin_port);
          else if (client_addr->ss_family == AF_INET6)
            client_port =
                ntohs(((struct sockaddr_in6 *)client_addr)->sin6_port);
          uint16_t qclass = 1;
          bool has_edns = false;
          bool dnssec_ok = false;
          size_t question_end = DNS_HEADER_SIZE; // default fallback
          if (payload_received > DNS_HEADER_SIZE) {
            size_t offset = DNS_HEADER_SIZE;
            while (offset < (size_t)payload_received) {
              uint8_t len = req_buf[offset];
              if (len == 0 || (len & 0xC0) == 0xC0) {
                offset += (len == 0) ? 1 : 2;
                break;
              }
              if (offset + len + 1 > (size_t)payload_received) break;
              offset += len + 1;
            }
            question_end = offset + 4;
            if (offset + 3 < (size_t)payload_received)
              qclass = (req_buf[offset + 2] << 8) | req_buf[offset + 3];
            uint16_t arcount = (req_buf[10] << 8) | req_buf[11];
            if (arcount > 0) {
              size_t o = DNS_HEADER_SIZE;
              uint16_t qd = (req_buf[4] << 8) | req_buf[5];
              uint16_t an = (req_buf[6] << 8) | req_buf[7];
              uint16_t ns = (req_buf[8] << 8) | req_buf[9];
              for (int k = 0; k < qd; k++) {
                while (o < (size_t)payload_received && req_buf[o] != 0 &&
                       (req_buf[o] & 0xC0) != 0xC0) {
                  if (o + req_buf[o] + 1 > (size_t)payload_received) break;
                  o += req_buf[o] + 1;
                }
                if (o < (size_t)payload_received && (req_buf[o] & 0xC0) == 0xC0)
                  o += 2;
                else
                  o++;
                o += 4;
              }
              for (int k = 0; k < an + ns + arcount; k++) {
                if (o >= (size_t)payload_received)
                  break;
                while (o < (size_t)payload_received && req_buf[o] != 0 &&
                       (req_buf[o] & 0xC0) != 0xC0) {
                  if (o + req_buf[o] + 1 > (size_t)payload_received) break;
                  o += req_buf[o] + 1;
                }
                if (o < (size_t)payload_received && (req_buf[o] & 0xC0) == 0xC0)
                  o += 2;
                else
                  o++;
                if (o + 10 <= (size_t)payload_received) {
                  uint16_t rt = (req_buf[o] << 8) | req_buf[o + 1];
                  uint32_t ttl = ((uint32_t)req_buf[o + 4] << 24) |
                                 ((uint32_t)req_buf[o + 5] << 16) |
                                 ((uint32_t)req_buf[o + 6] << 8) |
                                 req_buf[o + 7];
                  uint16_t rdl = (req_buf[o + 8] << 8) | req_buf[o + 9];
                  if (rt == 41) {
                    has_edns = true;
                    if (ttl & 0x00008000)
                      dnssec_ok = true;
                    break;
                  }
                  o += 10 + rdl;
                } else
                  break;
              }
            }
          }
          write_query_log(client_ip, client_port, qname, qclass, qtype,
                          has_edns, dnssec_ok);

          uint8_t res_buf_full[BUFFER_SIZE + sizeof(udp_ipc_t)];
          uint8_t *res_buf = res_buf_full + sizeof(udp_ipc_t);
          rate_limit_config_t *rrl_cfg = NULL;
          zone_db_snapshot_t *snap = acquire_zone_snapshot();
          int res_len =
              process_dns_query(req_buf, payload_received, res_buf, UDP_DEFAULT_MAX_RES_LEN, qname,
                                qtype, client_ip, &thread_compress_ctx, false, &rrl_cfg, snap);
          release_zone_snapshot(snap);
          if (res_len > 0) {
            bool slip_triggered = false;
            rrl_response_class_t cls = get_rrl_class(res_buf, res_len);
            if (rrl_check((struct sockaddr_storage *)&ipc_msg->client_addr, cls, rrl_cfg, &slip_triggered)) {
              submit_response_log(LOG_ACT_SENT, client_ip, client_port, qname, qclass, qtype,
                                  res_buf[3] & 0x0F, has_edns, dnssec_ok);
              udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
              *res_msg = *ipc_msg;
              res_msg->payload_len = res_len;
              send(active_fd, res_buf_full, sizeof(udp_ipc_t) + res_len, 0);
            } else if (slip_triggered) {
              submit_response_log(LOG_ACT_SENT, client_ip, client_port, qname, qclass, qtype,
                                  res_buf[3] & 0x0F, has_edns, dnssec_ok);
              res_buf[2] |= 0x02; // Set TC bit
              res_buf[6] = 0; res_buf[7] = 0; // ANCOUNT = 0
              res_buf[8] = 0; res_buf[9] = 0; // NSCOUNT = 0
              res_buf[10] = 0; res_buf[11] = 0; // ARCOUNT = 0
              
              int qlen = (int)question_end;
              if (qlen > res_len) qlen = res_len; // Safe fallback
              if (qlen > payload_received) qlen = payload_received;
              
              udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
              *res_msg = *ipc_msg;
              res_msg->payload_len = qlen;
              send(active_fd, res_buf_full, sizeof(udp_ipc_t) + qlen, 0);
            } else {
              submit_response_log(LOG_ACT_DROP_RRL, client_ip, client_port, qname, 
                                  qclass, qtype, res_buf[3] & 0x0F, has_edns, dnssec_ok);
            }
          } else {
            submit_response_log(LOG_ACT_DROP_MALFORMED, client_ip, client_port, "<malformed>", 
                                0, 0, 0, false, false);
          }
        }
      } else if (ev_list[i].udata == (void *)2) {
        // TCP
        int active_tcp_fd = ev_list[i].ident;
        int accept_count = 0;
        while (accept_count < 100) {
          struct sockaddr_storage client_addr;
          socklen_t client_len = sizeof(client_addr);
          int client_fd = accept(active_tcp_fd, (struct sockaddr *)&client_addr,
                                 &client_len);
          if (client_fd < 0) {
            if (errno == EMFILE || errno == ENFILE) {
              // FD exhaustion: backoff to prevent accept storm
              usleep(10000); // 10ms
            }
            break;
          }
          accept_count++;

          if (atomic_load_explicit(&g_tcp_clients, memory_order_acquire) >= MAX_TCP_CLIENTS) {
            close(client_fd);
            continue;
          }

          inc_tcp_clients();

          limit_client_socket_rights(client_fd);
          int cflags = fcntl(client_fd, F_GETFL, 0);
          fcntl(client_fd, F_SETFL, cflags | O_NONBLOCK);
          tcp_stream_ctx_t *ctx_tcp = calloc(1, sizeof(tcp_stream_ctx_t));
          if (!ctx_tcp) {
            close(client_fd);
            dec_tcp_clients();
            continue;
          }
          struct kevent ev_timeout;
          EV_SET(&ev_timeout, client_fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
                 10000, ctx_tcp);
          kevent(kq, &ev_timeout, 1, NULL, 0, NULL);

          if (client_addr.ss_family == AF_INET)
            inet_ntop(AF_INET, &((struct sockaddr_in *)&client_addr)->sin_addr,
                      ctx_tcp->client_ip, INET6_ADDRSTRLEN);
          else if (client_addr.ss_family == AF_INET6)
            inet_ntop(AF_INET6,
                      &((struct sockaddr_in6 *)&client_addr)->sin6_addr,
                      ctx_tcp->client_ip, INET6_ADDRSTRLEN);
          struct kevent ev_client;
          EV_SET(&ev_client, client_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
                 ctx_tcp);
          kevent(kq, &ev_client, 1, NULL, 0, NULL);
        }
      } else {
        // TCP 既存処理
        int client_fd = ev_list[i].ident;
        tcp_stream_ctx_t *ctx_tcp = (tcp_stream_ctx_t *)ev_list[i].udata;
        uint8_t *msg;
        uint16_t msg_len;
        int ret = read_dns_tcp_message(client_fd, ctx_tcp, &msg, &msg_len);
        if (ret < 0) {
          struct kevent ev_del;
          EV_SET(&ev_del, client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
          kevent(kq, &ev_del, 1, NULL, 0, NULL);
          close(client_fd);
          dec_tcp_clients();
          free(ctx_tcp);
        } else if (ret == 1) {
          struct kevent ev_del;
          EV_SET(&ev_del, client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
          kevent(kq, &ev_del, 1, NULL, 0, NULL);
          char qname[256] = "";
          uint16_t qtype = 0;
          if (msg_len > DNS_HEADER_SIZE) {
            size_t offset = DNS_HEADER_SIZE;
            size_t written = 0;
            while (offset < msg_len) {
              uint8_t len = msg[offset];
              if (len == 0 || (len & 0xC0) == 0xC0) {
                offset++;
                break;
              }
              offset++;
              if (written > 0 && qname[written - 1] != '.') {
                if (written < 255)
                  qname[written++] = '.';
              }
              if (offset + len <= msg_len) {
                size_t copy_len = len;
                if (written >= 255)
                  copy_len = 0;
                else if (written + copy_len > 255)
                  copy_len = 255 - written;
                if (copy_len > 0) {
                  memcpy(&qname[written], &msg[offset], copy_len);
                  written += copy_len;
                }
              }
              offset += len;
            }
            if (offset + 1 < msg_len)
              qtype = (msg[offset] << 8) | msg[offset + 1];
            if (written == 0 || (written > 0 && qname[written - 1] != '.')) {
              if (written < 255)
                qname[written++] = '.';
            }
            qname[written] = '\0';
          }
          struct sockaddr_storage client_addr;
          socklen_t c_len = sizeof(client_addr);
          getpeername(client_fd, (struct sockaddr *)&client_addr, &c_len);
          int client_port = 0;
          if (client_addr.ss_family == AF_INET)
            client_port = ntohs(((struct sockaddr_in *)&client_addr)->sin_port);
          else if (client_addr.ss_family == AF_INET6)
            client_port =
                ntohs(((struct sockaddr_in6 *)&client_addr)->sin6_port);
          uint16_t qclass = 1;
          edns_info_t edns;
          memset(&edns, 0, sizeof(edns));
          edns.present = false;
          if (msg_len >= DNS_HEADER_SIZE) {
            size_t offset = DNS_HEADER_SIZE;
            while (offset < msg_len) {
              uint8_t len = msg[offset];
              if (len == 0 || (len & 0xC0) == 0xC0) {
                offset += (len == 0) ? 1 : 2;
                break;
              }
              if (offset + len + 1 > msg_len) break;
              offset += len + 1;
            }
            if (offset + 3 < msg_len)
              qclass = (msg[offset + 2] << 8) | msg[offset + 3];

            uint16_t qd = (msg[4] << 8) | msg[5];
            uint16_t an = (msg[6] << 8) | msg[7];
            uint16_t ns = (msg[8] << 8) | msg[9];
            uint16_t ar = (msg[10] << 8) | msg[11];
            if (parse_edns_opt(msg, msg_len, qd, an, ns, ar, &edns) == 0) {
              edns.ede_count = 0; // 反射防止
            }
          }
          bool has_edns = edns.present;
          bool dnssec_ok = edns.dnssec_ok;
          write_query_log(ctx_tcp->client_ip, client_port, qname, qclass, qtype,
                          has_edns, dnssec_ok);

          zone_db_snapshot_t *snap = acquire_zone_snapshot();
          if (qtype == 252 || qtype == 251) {
            view_snapshot_t *xfr_view = select_view(snap, ctx_tcp->client_ip);
            server_config_t *cfg =
                atomic_load_explicit(&g_config_db.active, memory_order_acquire);
            zone_config_t *zcfg = xfr_view
                ? find_zone_config_in_view(cfg, xfr_view->name, qname)
                : NULL;
            bool allowed = false;
            uint16_t tsig_error = 0;
            tsig_key_t *matched_key = NULL;
            uint8_t tsig_mac[64];
            size_t tsig_mac_len = 0;
            if (zcfg) {
              bool has_acl = (zcfg->allow_transfer_count > 0);
              bool has_tsig = (zcfg->tsig_key != NULL);
              
              bool acl_ok = has_acl ? check_acl(ctx_tcp->client_ip, zcfg->allow_transfer, zcfg->allow_transfer_count) : false;
              bool tsig_ok = false;
              
              if (has_tsig) {
                tsig_key_t *k = cfg->keys;
                while (k) {
                  if (strcmp(k->name, zcfg->tsig_key) == 0) {
                    matched_key = k;
                    break;
                  }
                  k = k->next;
                }
                if (!matched_key) {
                  tsig_error = 17;
                } else {
                  int err = tsig_verify_packet(msg, msg_len, matched_key, tsig_mac, &tsig_mac_len);
                  if (err != 0) {
                    tsig_error = err > 0 ? err : 16;
                  } else {
                    tsig_ok = true;
                  }
                }
              }
              
              if (has_acl && has_tsig) {
                  allowed = (acl_ok && tsig_ok);
              } else if (has_acl) {
                  allowed = acl_ok;
              } else if (has_tsig) {
                  allowed = tsig_ok;
              }
            }
            zone_db_entry_t *entry = NULL;
            if (xfr_view) {
              for (size_t i = 0; i < xfr_view->zone_count; i++) {
                if (strcasecmp(xfr_view->entries[i]->domain, qname) == 0) {
                  entry = xfr_view->entries[i];
                  break;
                }
              }
            }
            if (allowed && entry) {
              if (atomic_fetch_add(&entry->active_axfr, 1) >= MAX_ZONE_AXFR) {
                atomic_fetch_sub(&entry->active_axfr, 1);
                allowed = false;
              } else {
                axfr_worker_args_t *args = malloc(sizeof(axfr_worker_args_t));
                if (args) {
                  args->client_fd = client_fd;
                  strncpy(args->client_ip, ctx_tcp->client_ip, INET6_ADDRSTRLEN);
                  args->client_port = client_port;
                  strncpy(args->qname, qname, 255);
                  args->qname[255] = '\0';
                  args->qclass = qclass;
                  args->qtype = qtype;
                  args->has_edns = has_edns;
                  args->dnssec_ok = dnssec_ok;
                  args->req_len = msg_len > UDP_DEFAULT_MAX_RES_LEN ? UDP_DEFAULT_MAX_RES_LEN : msg_len;
                  memcpy(args->req, msg, args->req_len);
                  args->tsig_key = matched_key;
                  args->tsig_mac_len = tsig_mac_len;
                  if (tsig_mac_len > 0) memcpy(args->tsig_mac, tsig_mac, tsig_mac_len);
                  args->entry = entry;
                  args->snap = snap;
                  atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
                  int cflags = fcntl(client_fd, F_GETFL, 0);
                  fcntl(client_fd, F_SETFL, cflags & ~O_NONBLOCK);
                  pthread_t t;
                  if (pthread_create(&t, NULL, axfr_worker_thread, args) != 0) {
                    free(args);
                    atomic_fetch_sub(&entry->active_axfr, 1);
                    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
                    allowed = false;
                  } else {
                    pthread_detach(t);
                  }
                } else {
                  atomic_fetch_sub(&entry->active_axfr, 1);
                  allowed = false;
                }
              }
            }
            if (!allowed || !entry) {
              uint8_t res_buf[1024];
              size_t copy_len = msg_len > UDP_DEFAULT_MAX_RES_LEN ? UDP_DEFAULT_MAX_RES_LEN : msg_len;
              memcpy(res_buf, msg, copy_len);
              if (tsig_error) {
                res_buf[2] |= 0x84;
                res_buf[3] |= 0x09;
                add_ede(&edns, cfg->send_extended_errors, 18, "Query refused due to access control");
                
                uint16_t qd = (msg[4] << 8) | msg[5];
                uint16_t offset = (uint16_t)get_question_end_offset(res_buf, copy_len, qd);
                uint16_t arcount = 0;
                if (edns.present) {
                  assemble_edns_opt(res_buf, sizeof(res_buf), &offset, &arcount, &edns, 0);
                }
                res_buf[6] = 0; res_buf[7] = 0;
                res_buf[8] = 0; res_buf[9] = 0;
                res_buf[10] = arcount >> 8;
                res_buf[11] = arcount & 0xFF;
                copy_len = offset;

                if (matched_key)
                  tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf),
                                   matched_key, tsig_error, tsig_mac, &tsig_mac_len, false);
                else {
                  tsig_key_t dummy = {0};
                  dummy.name = zcfg->tsig_key;
                  dummy.algorithm = "hmac-sha256";
                  tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf), &dummy,
                                   17, tsig_mac, &tsig_mac_len, false);
                }
              } else {
                res_buf[2] |= 0x84;
                res_buf[3] |= 0x05;
                add_ede(&edns, cfg->send_extended_errors, 18, "Query refused due to access control");
                
                uint16_t qd = (msg[4] << 8) | msg[5];
                uint16_t offset = (uint16_t)get_question_end_offset(res_buf, copy_len, qd);
                uint16_t arcount = 0;
                if (edns.present) {
                  assemble_edns_opt(res_buf, sizeof(res_buf), &offset, &arcount, &edns, 0);
                }
                res_buf[6] = 0; res_buf[7] = 0;
                res_buf[8] = 0; res_buf[9] = 0;
                res_buf[10] = arcount >> 8;
                res_buf[11] = arcount & 0xFF;
                copy_len = offset;
              }
              release_zone_snapshot(snap);
              uint8_t len_prefix[2] = {copy_len >> 8, copy_len & 0xFF};
              send(client_fd, len_prefix, 2, 0);
              send(client_fd, res_buf, copy_len, 0);
              
              submit_response_log(LOG_ACT_SENT, ctx_tcp->client_ip, client_port, qname, 
                                  qclass, qtype, res_buf[3] & 0x0F, has_edns, dnssec_ok);

              close(client_fd);
              dec_tcp_clients();
            } else {
              release_zone_snapshot(snap);
            }
            free(ctx_tcp);
          } else {
            uint8_t *tcp_res = malloc(65535);
            if (tcp_res) {
              int res_len = process_dns_query(msg, msg_len, tcp_res, 65535,
                                              qname, qtype, ctx_tcp->client_ip,
                                              &thread_compress_ctx, true, NULL, snap);
              release_zone_snapshot(snap);
              if (res_len > 0) {
                submit_response_log(LOG_ACT_SENT, ctx_tcp->client_ip, client_port, qname, qclass, qtype,
                                    tcp_res[3] & 0x0F, has_edns, dnssec_ok);
                uint8_t len_prefix[2] = {res_len >> 8, res_len & 0xFF};
                send(client_fd, len_prefix, 2, 0);
                send(client_fd, tcp_res, res_len, 0);
              } else {
                submit_response_log(LOG_ACT_DROP_MALFORMED, ctx_tcp->client_ip, client_port, "<malformed>", 
                                    0, 0, 0, false, false);
              }
              free(tcp_res);
            } else {
              release_zone_snapshot(snap);
            }
            
            server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
            if (cfg && cfg->tcp_connection_reuse) {
              ctx_tcp->state = TCP_STATE_READ_LEN;
              ctx_tcp->accumulated = 0;
              ctx_tcp->msg_len = 0;
              
              struct kevent ev_timeout;
              EV_SET(&ev_timeout, client_fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
                     cfg->tcp_idle_timeout > 0 ? cfg->tcp_idle_timeout : 10000, ctx_tcp);
              kevent(kq, &ev_timeout, 1, NULL, 0, NULL);
              
              // Event EVFILT_READ is already added with EV_ADD | EV_CLEAR
            } else {
              close(client_fd);
              dec_tcp_clients();
              free(ctx_tcp);
            }
          }
        }
      }
    }
  }
  close(kq);
  pthread_exit(NULL);
}

// ============================================================================
// 12. Control Thread
// ============================================================================
typedef enum {
  CTRL_STATE_NEW,
  CTRL_STATE_AUTH_WAIT,
  CTRL_STATE_CMD_WAIT
} ctrl_state_t;

typedef struct ctrl_client {
  int fd;
  ctrl_state_t state;
  char challenge[65];
  char buf[1024];
  size_t buf_len;
  struct ctrl_client *next;
} ctrl_client_t;

static ctrl_client_t *g_ctrl_clients = NULL;

static void free_ctrl_client(int fd) {
  ctrl_client_t **p = &g_ctrl_clients;
  while (*p) {
    if ((*p)->fd == fd) {
      ctrl_client_t *c = *p;
      *p = c->next;
      close(c->fd);
      free(c);
      return;
    }
    p = &(*p)->next;
  }
}

static ctrl_client_t *get_ctrl_client(int fd) {
  ctrl_client_t *p = g_ctrl_clients;
  while (p) {
    if (p->fd == fd) return p;
    p = p->next;
  }
  return NULL;
}

static void reload_all_zones(void) {
  zone_db_snapshot_t *snap = acquire_zone_snapshot();
  server_config_t *active_cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  
  for (size_t v = 0; v < snap->view_count; v++) {
    for (size_t i = 0; i < snap->views[v].zone_count; i++) {
      zone_db_entry_t *entry = snap->views[v].entries[i];
      zone_config_t *zcfg = NULL;
      view_config_t *vcfg = NULL;
      for (view_config_t *vc = active_cfg->views; vc; vc = vc->next) {
        if (strcasecmp(vc->name, snap->views[v].name) == 0) {
          vcfg = vc;
          break;
        }
      }
      if (vcfg) {
        zcfg = vcfg->zones;
        while (zcfg) {
          if (strcasecmp(zcfg->domain, entry->domain) == 0) {
            if (zcfg->type && (strcasecmp(zcfg->type, "master") == 0 || strcasecmp(zcfg->type, "primary") == 0) && zcfg->file) {
              syslog(LOG_NOTICE, "[Control] Reloading master zone: %s", entry->domain);
              reload_result_t rr = reload_master_zone(entry, zcfg->file);
              if (rr == RELOAD_OK && zcfg->is_catalog) {
                void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name);
                catalog_process_membership(entry, zcfg, vcfg->name);
              }
            } else if (zcfg->type && strcasecmp(zcfg->type, "slave") == 0) {
              syslog(LOG_NOTICE, "[Control] Triggering retransfer for slave zone: %s", entry->domain);
              atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
            }
            break;
          }
          zcfg = zcfg->next;
        }
      }
    }
  }
  release_zone_snapshot(snap);
}

static void free_server_config_fields(server_config_t *cfg) {
  for (int j = 0; j < cfg->bind_address_count; j++)
    free(cfg->bind_addresses[j]);
  free(cfg->bind_addresses);
  cfg->bind_addresses = NULL;
  cfg->bind_address_count = 0;

  zone_config_t *curr_flat = cfg->zones;
  while (curr_flat) {
    zone_config_t *next = curr_flat->next;
    free(curr_flat);
    curr_flat = next;
  }
  cfg->zones = NULL;

  view_config_t *v = cfg->views;
  while (v) {
    view_config_t *next_v = v->next;
    if (v->name) free(v->name);
    for (int i = 0; i < v->match_clients_count; i++) free(v->match_clients[i]);
    if (v->match_clients) free(v->match_clients);
    zone_config_t *curr = v->zones;
    while (curr) {
      zone_config_t *next = curr->next;
      free_zone_config(curr);
      curr = next;
    }
    free(v);
    v = next_v;
  }
  cfg->views = NULL;

  tsig_key_t *k = cfg->keys;
  while (k) {
    tsig_key_t *next_k = k->next;
    free(k->name); free(k->algorithm); free(k->secret);
    free(k);
    k = next_k;
  }
  cfg->keys = NULL;

  if (cfg->control.algorithm) free(cfg->control.algorithm);
  if (cfg->control.secret) free(cfg->control.secret);
  memset(&cfg->control, 0, sizeof(control_channel_config_t));
  free_rate_limit_config(&cfg->rrl);
  memset(&cfg->rrl, 0, sizeof(rate_limit_config_t));
  free_logging_channels(cfg);
}

static void perform_config_reload(void) {
  g_last_configured_time = time(NULL);
  char *config_str = read_entire_file(g_config_path);
  if (!config_str)
    return;
  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  server_config_t *standby = (active == &g_config_db.config_a)
                                 ? &g_config_db.config_b
                                 : &g_config_db.config_a;
  
  free_server_config_fields(standby);
  if (parse_named_conf(config_str, standby) == 0) {
    init_logging_channels(standby);
    atomic_store_explicit(&g_config_db.active, standby,
                          memory_order_release);
    rebuild_zone_db_from_config(standby);
    syslog(LOG_NOTICE, "Configuration and zones reloaded successfully.");
  } else {
    syslog(LOG_ERR, "Failed to reload configuration: parse error.");
  }
  free(config_str);
}

static const char *find_configured_domain(const char *arg) {
  server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  zone_config_t *zcfg = active->zones;
  size_t arg_len = strlen(arg);
  while (zcfg) {
    size_t z_len = strlen(zcfg->domain);
    if (strcasecmp(zcfg->domain, arg) == 0) return zcfg->domain;
    if (arg_len + 1 == z_len && zcfg->domain[z_len - 1] == '.' && strncasecmp(zcfg->domain, arg, arg_len) == 0) return zcfg->domain;
    if (z_len + 1 == arg_len && arg[arg_len - 1] == '.' && strncasecmp(zcfg->domain, arg, z_len) == 0) return zcfg->domain;
    zcfg = zcfg->next;
  }
  return arg;
}

void *control_thread_func(void *arg) {
  (void)arg;
  int kq = kqueue();
  if (kq < 0)
    pthread_exit(NULL);
  g_control_kq = kq;
  struct kevent ev_set[3];
  EV_SET(&ev_set[0], SIGHUP, EVFILT_SIGNAL, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev_set[1], 1, EVFILT_TIMER, EV_ADD | EV_CLEAR, 0, 1000, NULL);
  EV_SET(&ev_set[2], 2, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  if (kevent(kq, ev_set, 3, NULL, 0, NULL) == -1) {
    close(kq);
    pthread_exit(NULL);
  }
  if (g_control_sock >= 0) {
    EV_SET(&ev_set[0], g_control_sock, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent(kq, ev_set, 1, NULL, 0, NULL) == -1) {
      close(kq);
      pthread_exit(NULL);
    }
  }

  struct kevent ev_list[4];
  while (1) {
    int n = kevent(kq, NULL, 0, ev_list, 4, NULL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    for (int i = 0; i < n; i++) {
      if (g_control_sock >= 0 && ev_list[i].ident == (uintptr_t)g_control_sock) {
        struct sockaddr_un cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cfd = accept(g_control_sock, (struct sockaddr *)&cli_addr, &cli_len);
        if (cfd >= 0) {
          struct xucred cr;
          socklen_t cr_len = sizeof(cr);
          if (getsockopt(cfd, 0, LOCAL_PEERCRED, &cr, &cr_len) == 0 && cr.cr_version == XUCRED_VERSION) {
            bool allowed = false;
            uid_t my_uid = geteuid();
            if (cr.cr_uid == my_uid || cr.cr_uid == 0) {
              allowed = true;
            }
            if (!allowed) {
              close(cfd);
              continue;
            }
          } else {
            close(cfd);
            continue;
          }

          fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL, 0) | O_NONBLOCK);
          cap_rights_t rights;
          cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_EVENT, CAP_GETSOCKOPT);
          cap_rights_limit(cfd, &rights);
          
          ctrl_client_t *c = calloc(1, sizeof(ctrl_client_t));
          c->fd = cfd;
          c->state = CTRL_STATE_NEW;
          c->next = g_ctrl_clients;
          g_ctrl_clients = c;
          
          struct kevent ev_c;
          EV_SET(&ev_c, cfd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void*)1);
          kevent(g_control_kq, &ev_c, 1, NULL, 0, NULL);
          
          uint8_t rand_bytes[32];
          arc4random_buf(rand_bytes, 32);
          for(int k=0; k<32; k++) snprintf(&c->challenge[k*2], 3, "%02x", rand_bytes[k]);
          c->challenge[64] = '\0';
          
          char msg[128];
          int mlen = snprintf(msg, sizeof(msg), "CHALLENGE %s\n", c->challenge);
          send(cfd, msg, mlen, 0);
          c->state = CTRL_STATE_AUTH_WAIT;
        }
      } else if (ev_list[i].udata == (void*)1) {
        int cfd = ev_list[i].ident;
        ctrl_client_t *c = get_ctrl_client(cfd);
        if (!c) continue;
        if (ev_list[i].flags & EV_EOF) {
          free_ctrl_client(cfd);
          continue;
        }
        size_t space_left = sizeof(c->buf) - c->buf_len - 1;
        if (space_left == 0) {
            send(cfd, "ERROR buffer overflow\n", 22, 0);
            syslog(LOG_ERR, "[Control] Command buffer overflow, dropping client");
            free_ctrl_client(cfd);
            continue;
        }
        ssize_t r = recv(cfd, c->buf + c->buf_len, space_left, 0);
        if (r <= 0) {
          free_ctrl_client(cfd);
          continue;
        }
        c->buf_len += r;
        c->buf[c->buf_len] = '\0';
        
        char *nl = strchr(c->buf, '\n');
        if (nl) {
          *nl = '\0';
          if (c->state == CTRL_STATE_AUTH_WAIT) {
            server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
            if (strncmp(c->buf, "AUTH ", 5) == 0 && cfg->control.enabled && cfg->control.secret_decoded_len > 0) {
              char *client_hmac = c->buf + 5;
              unsigned char md[EVP_MAX_MD_SIZE];
              unsigned int md_len;
              HMAC(EVP_sha256(), cfg->control.secret_decoded, cfg->control.secret_decoded_len, 
                   (unsigned char*)c->challenge, 64, md, &md_len);
              char expected[65];
              for(unsigned int k=0; k<md_len; k++) snprintf(&expected[k*2], 3, "%02x", md[k]);
              
              if (strlen(client_hmac) == strlen(expected) &&
                  const_time_memcmp(client_hmac, expected, strlen(expected)) == 0) {
                send(cfd, "OK\n", 3, 0);
                c->state = CTRL_STATE_CMD_WAIT;
              } else {
                send(cfd, "AUTH_FAILED\n", 12, 0);
                free_ctrl_client(cfd);
                continue;
              }
            } else {
              send(cfd, "AUTH_FAILED\n", 12, 0);
              free_ctrl_client(cfd);
              continue;
            }
          } else if (c->state == CTRL_STATE_CMD_WAIT) {
            char *cmd = c->buf;
            char *arg = strchr(cmd, ' ');
            if (arg) { *arg = '\0'; arg++; }
            
            char *view_arg = NULL;
            if (arg) {
              char *sp = strchr(arg, ' ');
              if (sp) {
                *sp = '\0';
                view_arg = sp + 1;
                while (*view_arg == ' ') view_arg++;
                if (*view_arg == '\0') view_arg = NULL;
              }
            }
            
            if (strcmp(cmd, "reload") == 0) {
              if (arg && strlen(arg) > 0) {
                const char *canon_arg = find_configured_domain(arg);
                zone_db_snapshot_t *snap = acquire_zone_snapshot();
                server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
                zone_lookup_result_t lr = {0};
                int nmatches = lookup_zone_across_views(snap, active, canon_arg, view_arg, &lr);
                if (nmatches == 0) {
                  syslog(LOG_ERR, "[Control] Command 'reload' failed: zone '%s' not found", canon_arg);
                  send(cfd, "ERROR zone not found\n", 21, 0);
                } else if (nmatches > 1) {
                  send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'reload <zone> <view>')\n", 82, 0);
                } else if (lr.entry && lr.zcfg) {
                  syslog(LOG_NOTICE, "[Control] Received targeted reload command for zone: %s", canon_arg);
                  if (lr.zcfg->type && (strcmp(lr.zcfg->type, "master") == 0 || strcmp(lr.zcfg->type, "primary") == 0)) {
                    reload_result_t rr = reload_master_zone(lr.entry, lr.zcfg->file);
                    switch (rr) {
                        case RELOAD_OK:
                            syslog(LOG_NOTICE, "[Control] Targeted reload successful for %s", lr.zcfg->domain);
                            if (lr.zcfg->is_catalog) {
                                void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name);
                                catalog_process_membership(lr.entry, lr.zcfg, lr.view_name);
                            }
                            send(cfd, "OK reloaded\n", 12, 0);
                            break;
                        case RELOAD_ERR_FILE_READ:
                            send(cfd, "ERROR file read error\n", 22, 0);
                            break;
                        case RELOAD_ERR_PARSE:
                            send(cfd, "ERROR parse error\n", 18, 0);
                            break;
                        case RELOAD_ERR_MISSING_SOA:
                            send(cfd, "ERROR missing SOA\n", 18, 0);
                            break;
                    }
                  } else if (lr.zcfg->type && strcasecmp(lr.zcfg->type, "slave") == 0) {
                    syslog(LOG_NOTICE, "[Control] Triggering retransfer for slave zone %s on reload", lr.zcfg->domain);
                    atomic_store_explicit(&lr.entry->refresh_now, true, memory_order_release);
                    send(cfd, "OK reloaded (slave)\n", 20, 0);
                  } else {
                    send(cfd, "ERROR unknown zone type\n", 24, 0);
                  }
                } else {
                  send(cfd, "ERROR zone not found\n", 21, 0);
                }
                release_zone_snapshot(snap);
              } else {
                syslog(LOG_NOTICE, "[Control] Received full reload command");
                reload_all_zones();
                send(cfd, "OK reloaded\n", 12, 0);
              }
            } else if (strcmp(cmd, "reconfig") == 0) {
              syslog(LOG_NOTICE, "[Control] Received reconfig command");
              perform_config_reload();
              send(cfd, "OK\n", 3, 0);
            } else if (strcmp(cmd, "stop") == 0) {
              syslog(LOG_NOTICE, "[Control] Received stop command");
              udp_ipc_t msg;
              memset(&msg, 0, sizeof(msg));
              msg.sock_fd_idx = -2;
              uint8_t pkt[sizeof(msg)];
              memcpy(pkt, &msg, sizeof(msg));
              send(g_notify_ipc[1], pkt, sizeof(pkt), 0);
              send(cfd, "OK stopping\n", 12, 0);
              exit(0);
            } else if (strcmp(cmd, "status") == 0) {
              karidns_status_t st;
              memset(&st, 0, sizeof(st));
              st.boot_time = g_boot_time;
              st.last_configured_time = g_last_configured_time;
              
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              if (snap) {
                for (size_t v = 0; v < snap->view_count; v++) {
                  st.num_zones += snap->views[v].zone_count;
                }
              } else {
                st.num_zones = 0;
              }
              release_zone_snapshot(snap);

              st.xfers_running = atomic_load_explicit(&g_xfers_running, memory_order_relaxed);
              st.tcp_clients = atomic_load_explicit(&g_tcp_clients, memory_order_relaxed);
              st.tcp_high_water = atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed);
              st.worker_threads = atomic_load(&g_bound_workers);
              
              if (g_config_path) {
                  strncpy(st.config_file, g_config_path, sizeof(st.config_file) - 1);
              }
              st.frontend_alive = atomic_load(&g_frontend_alive);
              
              server_config_t *active_cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
              st.query_logging = (active_cfg && active_cfg->logging.queries_channel != NULL);
              st.response_logging = (active_cfg && active_cfg->logging.responses_channel != NULL);
              
              st.rrl_dropped = atomic_load_explicit(&g_rrl_dropped_total, memory_order_relaxed);
              st.rrl_slipped = atomic_load_explicit(&g_rrl_slip_total, memory_order_relaxed);
              st.ede_proh = atomic_load_explicit(&g_ede_prohibited_total, memory_order_relaxed);
              st.ede_na = atomic_load_explicit(&g_ede_not_authoritative_total, memory_order_relaxed);
              st.ede_ns = atomic_load_explicit(&g_ede_not_supported_total, memory_order_relaxed);
              st.ede_oth = atomic_load_explicit(&g_ede_other_total, memory_order_relaxed);
              
              struct iovec iov[2];
              iov[0].iov_base = "OK ";
              iov[0].iov_len = 3;
              iov[1].iov_base = &st;
              iov[1].iov_len = sizeof(st);
              
              struct msghdr msg;
              memset(&msg, 0, sizeof(msg));
              msg.msg_iov = iov;
              msg.msg_iovlen = 2;
              sendmsg(cfd, &msg, 0);
            } else if (strcmp(cmd, "zonestatus") == 0 && arg) {
              const char *canon_arg = find_configured_domain(arg);
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              server_config_t *active_cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
              zone_lookup_result_t lr = {0};
              int nmatches = lookup_zone_across_views(snap, active_cfg, canon_arg, view_arg, &lr);
              if (nmatches == 0) {
                syslog(LOG_ERR, "[Control] Command 'zonestatus' failed: zone '%s' not found", canon_arg);
                send(cfd, "ERROR zone not found\n", 21, 0);
              } else if (nmatches > 1) {
                send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'zonestatus <zone> <view>')\n", 86, 0);
              } else if (lr.entry) {
                char smsg[256];
                int slen = snprintf(smsg, sizeof(smsg), "OK serial=%u refresh=%u\n", (uint32_t)lr.entry->serial, (uint32_t)lr.entry->refresh);
                send(cfd, smsg, slen, 0);
              } else {
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "notify") == 0 && arg) {
              const char *canon_arg = find_configured_domain(arg);
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              server_config_t *active_cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
              zone_lookup_result_t lr = {0};
              int nmatches = lookup_zone_across_views(snap, active_cfg, canon_arg, view_arg, &lr);
              if (nmatches == 0) {
                syslog(LOG_ERR, "[Control] Command 'notify' failed: zone '%s' not found", canon_arg);
                send(cfd, "ERROR zone not found\n", 21, 0);
              } else if (nmatches > 1) {
                send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'notify <zone> <view>')\n", 82, 0);
              } else if (lr.entry) {
                syslog(LOG_NOTICE, "[Control] Received notify command for zone: %s", canon_arg);
                atomic_store_explicit(&lr.entry->notify_now, true, memory_order_release);
                send(cfd, "OK\n", 3, 0);
              } else {
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "retransfer") == 0 && arg) {
              const char *canon_arg = find_configured_domain(arg);
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              server_config_t *active_cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
              zone_lookup_result_t lr = {0};
              int nmatches = lookup_zone_across_views(snap, active_cfg, canon_arg, view_arg, &lr);
              if (nmatches == 0) {
                syslog(LOG_ERR, "[Control] Command 'retransfer' failed: zone '%s' not found", canon_arg);
                send(cfd, "ERROR zone not found\n", 21, 0);
              } else if (nmatches > 1) {
                send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'retransfer <zone> <view>')\n", 86, 0);
              } else if (lr.entry) {
                syslog(LOG_NOTICE, "[Control] Received retransfer command for zone: %s", canon_arg);
                atomic_store_explicit(&lr.entry->refresh_now, true, memory_order_release);
                send(cfd, "OK\n", 3, 0);
              } else {
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_zone_snapshot(snap);
            } else {
              syslog(LOG_ERR, "[Control] Received unknown command: %s", cmd);
              send(cfd, "ERROR unknown command\n", 22, 0);
            }
            free_ctrl_client(cfd);
            continue;
          }
          size_t rem = c->buf_len - (nl + 1 - c->buf);
          memmove(c->buf, nl + 1, rem);
          c->buf_len = rem;
        } else if (c->buf_len >= sizeof(c->buf) - 1) {
          free_ctrl_client(cfd);
        }
      } else if (ev_list[i].filter == EVFILT_SIGNAL && ev_list[i].ident == SIGHUP) {
        perform_config_reload();
      } else if (ev_list[i].filter == EVFILT_TIMER ||
                 ev_list[i].filter == EVFILT_USER) {
        time_t now = time(NULL);
        server_config_t *active =
            atomic_load_explicit(&g_config_db.active, memory_order_acquire);
        zone_db_snapshot_t *snap = acquire_zone_snapshot();
        if (snap) {
            for (size_t v = 0; v < snap->view_count; v++) {
                for (size_t i = 0; i < snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = snap->views[v].entries[i];

                    if (atomic_exchange_explicit(&entry->notify_now, false, memory_order_acquire)) {
                        syslog(LOG_INFO, "[Control] Executing manual NOTIFY for %s", entry->domain);
                        send_notify_to_all(entry->domain, entry->view_name);
                    }

                    bool is_slave = false;
                    char master_ip[64] = {0};
                    int master_port = 53;
                    char tsig_key_name[64] = {0};
                    
                    if (entry->is_catalog_member) {
                        is_slave = true;
                        strncpy(master_ip, entry->cached_master_ip, sizeof(master_ip) - 1);
                        master_port = entry->cached_master_port;
                        strncpy(tsig_key_name, entry->cached_tsig_key_name, sizeof(tsig_key_name) - 1);
                    } else {
                        zone_config_t *zcfg = find_zone_config_in_view(active, entry->view_name, entry->domain);
                        if (zcfg && zcfg->type && strcasecmp(zcfg->type, "slave") == 0 &&
                            zcfg->masters_count > 0 && zcfg->masters[0].ip != NULL) {
                            is_slave = true;
                            strncpy(master_ip, zcfg->masters[0].ip, sizeof(master_ip) - 1);
                            master_port = zcfg->masters[0].port;
                            if (zcfg->tsig_key) {
                                strncpy(tsig_key_name, zcfg->tsig_key, sizeof(tsig_key_name) - 1);
                            }
                        }
                    }

                    if (is_slave && master_ip[0] != '\0') {
                        time_t last_ok = atomic_load_explicit(&entry->last_successful_transfer, memory_order_acquire);
                        uint32_t expire = atomic_load_explicit(&entry->expire, memory_order_acquire);
                        if (last_ok > 0 && expire > 0 && (now - last_ok) > expire) {
                            time_t last_log = atomic_load_explicit(&entry->last_stale_log_time, memory_order_acquire);
                            if (now - last_log > 900) {
                                if (active->serve_stale) {
                                    syslog(LOG_WARNING, "[Zone] Zone %s is expired (master unreachable), serving stale data", entry->domain);
                                } else {
                                    syslog(LOG_ERR, "[Zone] Zone %s is expired (master unreachable), returning SERVFAIL", entry->domain);
                                }
                                atomic_store_explicit(&entry->last_stale_log_time, now, memory_order_release);
                            }
                        }

                        bool force = atomic_exchange_explicit(&entry->refresh_now, false, memory_order_acquire);
                        time_t entry_next_check = atomic_load_explicit(&entry->next_check, memory_order_acquire);
                        if (force || entry_next_check == 0 || (entry_next_check > 0 && now >= entry_next_check)) {
                            bool expected = false;
                            if (atomic_compare_exchange_strong_explicit(
                                    &entry->is_transferring, &expected, true,
                                    memory_order_acquire, memory_order_relaxed)) {
                                uint32_t retry = atomic_load_explicit(&entry->retry, memory_order_acquire);
                                atomic_store_explicit(&entry->next_check, now + (retry ? retry : 60), memory_order_release);
                                
                                axfr_bg_ctx_t *bg_ctx = calloc(1, sizeof(axfr_bg_ctx_t));
                                if (bg_ctx) {
                                    strncpy(bg_ctx->master_ip, master_ip, sizeof(bg_ctx->master_ip) - 1);
                                    bg_ctx->master_port = master_port;
                                    strncpy(bg_ctx->domain, entry->domain, sizeof(bg_ctx->domain) - 1);
                                    bg_ctx->entry = entry;
                                    
                                    if (tsig_key_name[0] != '\0') {
                                        tsig_key_t *k = active->keys;
                                        while (k) {
                                            if (strcmp(k->name, tsig_key_name) == 0) {
                                                bg_ctx->tsig_key = k;
                                                break;
                                            }
                                            k = k->next;
                                        }
                                    }
                                    
                                    pthread_t bg_thread;
                                    pthread_attr_t attr;
                                    pthread_attr_init(&attr);
                                    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                                    if (pthread_create(&bg_thread, &attr, axfr_bg_thread_func, bg_ctx) != 0) {
                                        free(bg_ctx);
                                        atomic_store_explicit(&entry->is_transferring, false, memory_order_release);
                                    }
                                    pthread_attr_destroy(&attr);
                                } else {
                                    atomic_store_explicit(&entry->is_transferring, false, memory_order_release);
                                }
                            }
                        }
                    }
                }
            }
            release_zone_snapshot(snap);
        }
      }
    }
  }
  close(kq);
  pthread_exit(NULL);
}

// ============================================================================
// 13. Frontend Router Thread (特権維持・UDP送受信ルーティング)
// ============================================================================

static void run_frontend_router(pid_t backend_pid) {
  if (g_control_sock >= 0) {
    close(g_control_sock);
    g_control_sock = -1;
  }
  server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  if (cfg->user) {
    struct passwd *pwd = getpwnam(cfg->user);
    if (!pwd) {
      syslog(LOG_ERR, "[Frontend] user '%s' not found, aborting privilege drop", cfg->user);
      exit(EXIT_FAILURE);
    }
    gid_t target_gid = pwd->pw_gid;
    if (cfg->group) {
      struct group *grp = getgrnam(cfg->group);
      if (!grp) {
        syslog(LOG_ERR, "[Frontend] group '%s' not found, aborting privilege drop", cfg->group);
        exit(EXIT_FAILURE);
      }
      target_gid = grp->gr_gid;
    }
    if (setgroups(0, NULL) != 0) { syslog(LOG_ERR, "[Frontend] setgroups failed: %m"); exit(EXIT_FAILURE); }
    if (setgid(target_gid) != 0) { syslog(LOG_ERR, "[Frontend] setgid failed: %m"); exit(EXIT_FAILURE); }
    if (setuid(pwd->pw_uid) != 0) { syslog(LOG_ERR, "[Frontend] setuid failed: %m"); exit(EXIT_FAILURE); }
    
    if (getuid() != pwd->pw_uid || geteuid() != pwd->pw_uid || getgid() != target_gid || getegid() != target_gid) {
      syslog(LOG_ERR, "[Frontend] privilege drop verification failed");
      exit(EXIT_FAILURE);
    }
  } else if (cfg->group) {
    struct group *grp = getgrnam(cfg->group);
    if (!grp) {
      syslog(LOG_ERR, "[Frontend] group '%s' not found, aborting privilege drop", cfg->group);
      exit(EXIT_FAILURE);
    }
    if (setgroups(0, NULL) != 0) { syslog(LOG_ERR, "[Frontend] setgroups failed: %m"); exit(EXIT_FAILURE); }
    if (setgid(grp->gr_gid) != 0) { syslog(LOG_ERR, "[Frontend] setgid failed: %m"); exit(EXIT_FAILURE); }
    
    if (getgid() != grp->gr_gid || getegid() != grp->gr_gid) {
      syslog(LOG_ERR, "[Frontend] privilege drop verification failed (group only)");
      exit(EXIT_FAILURE);
    }
  }

  int kq = kqueue();
  if (kq < 0)
    exit(1);

  for (int i = 0; i < g_num_udp_fds; i++) {
    struct kevent ev;
    EV_SET(&ev, g_udp_fds[i], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
           (void *)(uintptr_t)i);
    kevent(kq, &ev, 1, NULL, 0, NULL);
  }
  for (int i = 0; i < g_num_ipc; i++) {
    struct kevent ev;
    EV_SET(&ev, g_ipc_fds[i][0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
           (void *)(uintptr_t)(MAX_BIND_ADDRS + i));
    kevent(kq, &ev, 1, NULL, 0, NULL);
  }
  signal(SIGCHLD, SIG_DFL);
  struct kevent ev_notify;
  EV_SET(&ev_notify, g_notify_ipc[0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
         (void *)(uintptr_t)999);
  kevent(kq, &ev_notify, 1, NULL, 0, NULL);

  struct kevent ev_proc;
  EV_SET(&ev_proc, backend_pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, (void *)1000);
  kevent(kq, &ev_proc, 1, NULL, 0, NULL);

  uint8_t buffer[65536];
  int rr = 0; // ラウンドロビン分配用
  struct kevent ev_list[128];
  syslog(LOG_NOTICE, "[Frontend] UDP Router process started.");

  while (1) {
    int n = kevent(kq, NULL, 0, ev_list, 128, NULL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    for (int i = 0; i < n; i++) {
      uintptr_t ud = (uintptr_t)ev_list[i].udata;
      if (ud == 1000) {
        while (1) {
          ssize_t len = recv(g_notify_ipc[0], buffer, sizeof(buffer), MSG_DONTWAIT);
          if (len < 0) break; // キューが空になった (EAGAIN等)
          if (len >= (ssize_t)sizeof(udp_ipc_t)) {
            udp_ipc_t *msg = (udp_ipc_t *)buffer;
            if (msg->sock_fd_idx == -2) {
              syslog(LOG_NOTICE, "[Frontend] Received stop command from backend. Shutting down cleanly.");
              exit(0);
            }
          }
        }
        syslog(LOG_CRIT, "[Frontend] Backend process (pid=%d) exited unexpectedly. Shutting down.", backend_pid);
        exit(1);
      }
      if (ud < MAX_BIND_ADDRS) {
        // (1) UDP Inbound -> IPC to Backend Worker
        int fd = g_udp_fds[ud];
        while (1) {
          udp_ipc_t *msg = (udp_ipc_t *)buffer;
          msg->addr_len = sizeof(struct sockaddr_storage);
          ssize_t len =
              recvfrom(fd, buffer + sizeof(udp_ipc_t),
                       BUFFER_SIZE, 0,
                       (struct sockaddr *)&msg->client_addr, &msg->addr_len);
          if (len < 0)
            break; // EAGAIN

          msg->sock_fd_idx = ud;
          msg->payload_len = len;
          send(g_ipc_fds[rr][0], buffer, sizeof(udp_ipc_t) + len, 0);
          rr = (rr + 1) % g_num_ipc;
        }
      } else if (ud == 999) {
        // (2) Notify Outbound -> Dynamic UDP Socket
        while (1) {
          ssize_t len = recv(g_notify_ipc[0], buffer, sizeof(buffer), 0);
          if (len < (ssize_t)sizeof(udp_ipc_t))
            break; // EAGAIN

          udp_ipc_t *msg = (udp_ipc_t *)buffer;
          if (msg->sock_fd_idx == -2) {
            syslog(LOG_NOTICE, "[Frontend] Received stop command from backend. Shutting down cleanly.");
            exit(0);
          }
          int sock = socket(msg->client_addr.ss_family, SOCK_DGRAM, 0);
          if (sock >= 0) {
            sendto(sock, buffer + sizeof(udp_ipc_t), msg->payload_len, 0,
                   (struct sockaddr *)&msg->client_addr, msg->addr_len);
            close(sock);
          }
        }
      } else {
        // (3) IPC Inbound from Backend -> UDP Outbound
        int worker_idx = ud - MAX_BIND_ADDRS;
        int fd = g_ipc_fds[worker_idx][0];
        while (1) {
          ssize_t len = recv(fd, buffer, sizeof(buffer), 0);
          if (len < (ssize_t)sizeof(udp_ipc_t))
            break; // EAGAIN
          udp_ipc_t *msg = (udp_ipc_t *)buffer;
          ssize_t max_valid_payload = len - (ssize_t)sizeof(udp_ipc_t);
          if (msg->payload_len > max_valid_payload) {
            syslog(LOG_WARNING, "[Frontend] Dropping backend reply with inconsistent payload_len");
          } else if (msg->sock_fd_idx >= 0 && msg->sock_fd_idx < g_num_udp_fds) {
            sendto(g_udp_fds[msg->sock_fd_idx], buffer + sizeof(udp_ipc_t),
                   msg->payload_len, 0, (struct sockaddr *)&msg->client_addr,
                   msg->addr_len);
          }
        }
      }
    }
  }
}

// ============================================================================
// 14. メインエントリーポイント & UDP/IPC 初期化
// ============================================================================

static void daemonize(void) {
  pid_t pid = fork();
  if (pid < 0)
    exit(EXIT_FAILURE);
  if (pid > 0)
    exit(EXIT_SUCCESS);
  if (setsid() < 0)
    exit(EXIT_FAILURE);
  pid = fork();
  if (pid < 0)
    exit(EXIT_FAILURE);
  if (pid > 0)
    exit(EXIT_SUCCESS);
  if (chdir("/") < 0)
    exit(EXIT_FAILURE);
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  int fd = open("/dev/null", O_RDWR);
  if (fd != STDIN_FILENO)
    return;
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  cap_rights_t io_rights;
  cap_rights_init(&io_rights, CAP_READ, CAP_WRITE, CAP_FSTAT);
  for (int stdio_fd = STDIN_FILENO; stdio_fd <= STDERR_FILENO; stdio_fd++)
    cap_rights_limit(stdio_fd, &io_rights);
}

static void setup_udp_and_ipc(server_config_t *cfg, int num_workers) {
  g_num_ipc = num_workers;
  g_ipc_fds = calloc(num_workers, sizeof(int[2]));
  for (int i = 0; i < num_workers; i++) {
    socketpair(AF_UNIX, SOCK_DGRAM, 0, g_ipc_fds[i]);
    fcntl(g_ipc_fds[i][0], F_SETFL,
          fcntl(g_ipc_fds[i][0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(g_ipc_fds[i][1], F_SETFL,
          fcntl(g_ipc_fds[i][1], F_GETFL, 0) | O_NONBLOCK);
    int bufsize = 2 * 1024 * 1024; // 2MB
    setsockopt(g_ipc_fds[i][0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(g_ipc_fds[i][0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(g_ipc_fds[i][1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(g_ipc_fds[i][1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
  }

  socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc);
  fcntl(g_notify_ipc[0], F_SETFL,
        fcntl(g_notify_ipc[0], F_GETFL, 0) | O_NONBLOCK);
  fcntl(g_notify_ipc[1], F_SETFL,
        fcntl(g_notify_ipc[1], F_GETFL, 0) | O_NONBLOCK);
  int nbufsize = 1024 * 1024; // 1MB
  setsockopt(g_notify_ipc[0], SOL_SOCKET, SO_RCVBUF, &nbufsize, sizeof(nbufsize));
  setsockopt(g_notify_ipc[0], SOL_SOCKET, SO_SNDBUF, &nbufsize, sizeof(nbufsize));
  setsockopt(g_notify_ipc[1], SOL_SOCKET, SO_RCVBUF, &nbufsize, sizeof(nbufsize));
  setsockopt(g_notify_ipc[1], SOL_SOCKET, SO_SNDBUF, &nbufsize, sizeof(nbufsize));

  int port = cfg->port > 0 ? cfg->port : DNS_PORT;
  int bind_count = cfg->bind_address_count;
  int opt = 1;

  for (int i = 0; i < (bind_count > 0 ? bind_count : 1); i++) {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    bool is_v4 = false;
    bool is_v6 = false;
    memset(&addr4, 0, sizeof(addr4));
    memset(&addr6, 0, sizeof(addr6));
    if (bind_count == 0) {
      addr4.sin_family = AF_INET;
      addr4.sin_addr.s_addr = INADDR_ANY;
      addr4.sin_port = htons(port);
      addr6.sin6_family = AF_INET6;
      addr6.sin6_addr = in6addr_any;
      addr6.sin6_port = htons(port);
      is_v4 = true;
      is_v6 = true;
    } else {
      if (inet_pton(AF_INET, cfg->bind_addresses[i], &addr4.sin_addr) == 1) {
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        is_v4 = true;
      } else if (inet_pton(AF_INET6, cfg->bind_addresses[i],
                           &addr6.sin6_addr) == 1) {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        is_v6 = true;
      }
    }

    if (is_v4 && g_num_udp_fds < MAX_BIND_ADDRS) {
      int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
      if (udp_fd >= 0) {
        fcntl(udp_fd, F_SETFL, fcntl(udp_fd, F_GETFL, 0) | O_NONBLOCK);
        if (bind(udp_fd, (struct sockaddr *)&addr4, sizeof(addr4)) == 0)
          g_udp_fds[g_num_udp_fds++] = udp_fd;
        else
          close(udp_fd);
      }
    }
    if (is_v6 && g_num_udp_fds < MAX_BIND_ADDRS) {
      int udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
      if (udp_fd >= 0) {
        fcntl(udp_fd, F_SETFL, fcntl(udp_fd, F_GETFL, 0) | O_NONBLOCK);
        setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        if (bind(udp_fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0)
          g_udp_fds[g_num_udp_fds++] = udp_fd;
        else
          close(udp_fd);
      }
    }
  }
}

int main(int argc, char **argv) {
  arc4random_buf(g_server_cookie_secret, sizeof(g_server_cookie_secret));
  arc4random_buf(g_rrl_hash_key, sizeof(g_rrl_hash_key));
  // SipHash-2-4 self-test against official reference test vector
  // Key: 00010203...0f, Message: 000102...0e (15 bytes)
  // Expected output: 0xa129ca6149be45e5
  {
    static const uint64_t tv_key[2] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};
    uint8_t tv_msg[15];
    for (int i = 0; i < 15; i++) tv_msg[i] = (uint8_t)i;
    uint64_t tv_result = siphash24(tv_msg, sizeof(tv_msg), tv_key);
    if (tv_result != 0xa129ca6149be45e5ULL) {
      syslog(LOG_CRIT, "FATAL: SipHash-2-4 self-test failed (got %016llx, expected a129ca6149be45e5)",
             (unsigned long long)tv_result);
      abort();
    }
  }
  tzset();
  g_boot_time = time(NULL);
  g_last_configured_time = g_boot_time;
  
  // Force OpenSSL lazy initialization before entering Capsicum sandbox
  uint8_t dummy_cookie[16];
  generate_server_cookie("127.0.0.1", (const uint8_t *)"12345678", dummy_cookie, time(NULL));

  bool foreground = false;
  const char *config_file = NULL;

  for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-f") == 0) {
          foreground = true;
      } else {
          config_file = argv[i];
      }
  }

  if (!config_file) {
    syslog(LOG_ERR, "Usage: %s [-f] <config_file>", argv[0]);
    return 1;
  }
  if (!getcwd(g_startup_cwd, sizeof(g_startup_cwd))) {
    g_startup_cwd[0] = '\0';
  }
  signal(SIGPIPE, SIG_IGN);
  g_cwd_fd = open(".", O_DIRECTORY | O_CLOEXEC | O_RDONLY);
  if (g_cwd_fd >= 0) {
    cap_rights_t cwd_rights;
    cap_rights_init(&cwd_rights, CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_CREATE,
                    CAP_FSTAT, CAP_FSTATFS, CAP_FTRUNCATE, CAP_SEEK,
                    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET, CAP_UNLINKAT,
                    CAP_FCNTL);
    cap_rights_limit(g_cwd_fd, &cwd_rights);
  }

  g_config_path = config_file;
  openlog("KariDNS", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
  start_connect_broker();
  if (!foreground) {
    daemonize();
  }

  // Prevent multiple instances using a pidfile lock
  mkdir("/var/run/karidns", 0755);
  int pid_fd = open("/var/run/karidns/karidns.pid", O_RDWR | O_CREAT, 0644);
  if (pid_fd < 0) {
    syslog(LOG_ERR, "Failed to open pidfile /var/run/karidns/karidns.pid: %s", strerror(errno));
    return 1;
  }
  if (flock(pid_fd, LOCK_EX | LOCK_NB) < 0) {
    syslog(LOG_ERR, "Another KariDNS instance is already running (pidfile locked)");
    fprintf(stderr, "Another KariDNS instance is already running.\n");
    return 1;
  }
  ftruncate(pid_fd, 0);
  char pid_str[32];
  snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
  write(pid_fd, pid_str, strlen(pid_str));
  // Keep pid_fd open; the lock will be automatically released upon process exit.

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGHUP);
  sigprocmask(SIG_BLOCK, &set, NULL);

  char *config_str = read_entire_file(g_config_path);
  if (!config_str)
    return 1;
  if (parse_named_conf(config_str, &g_config_db.config_a) != 0) {
    free(config_str);
    return 1;
  }
  free(config_str);
  init_logging_channels(&g_config_db.config_a);
  atomic_init(&g_config_db.active, &g_config_db.config_a);
  rebuild_zone_db_from_config(&g_config_db.config_a);

  int num_workers = sysconf(_SC_NPROCESSORS_ONLN);
  if (num_workers <= 0)
    num_workers = 2;

  setup_udp_and_ipc(&g_config_db.config_a, num_workers);

  if (g_config_db.config_a.control.enabled) {
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, "/var/run/karidns/control.sock", sizeof(un.sun_path) - 1);
    mkdir("/var/run/karidns", 0755);
    unlink(un.sun_path);
    g_control_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_control_sock >= 0) {
      mode_t old_mask = umask(0177);
      if (bind(g_control_sock, (struct sockaddr *)&un, sizeof(un)) == 0) {
        listen(g_control_sock, 5);
        server_config_t *cfg = &g_config_db.config_a;
        if (cfg->user) {
          struct passwd *pwd = getpwnam(cfg->user);
          if (pwd) {
            uid_t target_uid = pwd->pw_uid;
            gid_t target_gid = pwd->pw_gid;
            if (cfg->group) {
              struct group *grp = getgrnam(cfg->group);
              if (grp) target_gid = grp->gr_gid;
            }
            chown(un.sun_path, target_uid, target_gid);
          }
        }
        fcntl(g_control_sock, F_SETFL, fcntl(g_control_sock, F_GETFL, 0) | O_NONBLOCK);
        cap_rights_t ctrl_rights;
        cap_rights_init(&ctrl_rights, CAP_ACCEPT, CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_FCNTL, CAP_RECV, CAP_SEND);
        cap_rights_limit(g_control_sock, &ctrl_rights);
      } else {
        syslog(LOG_ERR, "Failed to bind control socket: %m");
        close(g_control_sock);
        g_control_sock = -1;
      }
      umask(old_mask);
    }
  }

  pid_t pid = fork();
  if (pid < 0) {
    syslog(LOG_ERR, "fork for frontend router failed");
    exit(1);
  }

  if (pid > 0) {
    run_frontend_router(pid);
    exit(0);
  }

  for (int i = 0; i < g_num_ipc; i++)
    close(g_ipc_fds[i][0]);
  for (int i = 0; i < g_num_udp_fds; i++)
    close(g_udp_fds[i]);
  close(g_notify_ipc[0]);

  pthread_t control_thread;
  if (pthread_create(&control_thread, NULL, control_thread_func, NULL) != 0)
    exit(1);

  pthread_t *threads = calloc(num_workers, sizeof(pthread_t));
  worker_ctx_t *ctxs = calloc(num_workers, sizeof(worker_ctx_t));
  if (!threads || !ctxs)
    exit(1);
  for (int i = 0; i < num_workers; i++) {
    ctxs[i].thread_id = i;
    ctxs[i].core_id = i % num_workers;
    if (pthread_create(&threads[i], NULL, worker_thread_func, &ctxs[i]) != 0)
      exit(EXIT_FAILURE);
  }
  while (atomic_load(&g_bound_workers) < num_workers)
    sched_yield();

  server_config_t *cfg = &g_config_db.config_a;
  if (cfg->user) {
    struct passwd *pwd = getpwnam(cfg->user);
    if (!pwd)
      exit(EXIT_FAILURE);
    gid_t target_gid = pwd->pw_gid;
    if (cfg->group) {
      struct group *grp = getgrnam(cfg->group);
      if (!grp)
        exit(EXIT_FAILURE);
      target_gid = grp->gr_gid;
    }
    if (setgroups(0, NULL) != 0)
      exit(EXIT_FAILURE);
    if (setgid(target_gid) != 0)
      exit(EXIT_FAILURE);
    if (setuid(pwd->pw_uid) != 0)
      exit(EXIT_FAILURE);
  } else if (cfg->group) {
    struct group *grp = getgrnam(cfg->group);
    if (!grp)
      exit(EXIT_FAILURE);
    if (setgroups(0, NULL) != 0)
      exit(EXIT_FAILURE);
    if (setgid(grp->gr_gid) != 0)
      exit(EXIT_FAILURE);
  }

  // 重要: この行より後(Capsicumサンドボックス突入後)にワーカースレッド等から
  // 呼ばれるコードで、tzset()が内部的に別のTZ設定を要求する関数
  // (timegm()や、明示的にsetenv("TZ",...)する処理など)を新たに追加しないこと。
  // サンドボックス下でのタイムゾーンDBへの追加アクセスはECAPMODEでクラッシュする。
  // UTC固定の日時変換が必要な場合は、タイムゾーンDBに依存しない純計算
  // (parse_dnssec_time()のような日数計算アルゴリズム)を使うこと。
  tzset();
  pthread_t response_logger_thread;
  if (pthread_create(&response_logger_thread, NULL, response_logger_thread_func, NULL) != 0) exit(1);
  
  enter_capsicum_sandbox(); // サンドボックス突入！

  for (int i = 0; i < num_workers; i++)
    pthread_join(threads[i], NULL);
  pthread_join(control_thread, NULL);

  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  free_server_config_fields(active);
  return 0;
}