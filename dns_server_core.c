#include "dns_zone_parser.h"
#include "dns_config_parser.h"
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

#define MAX_FIELDS 64

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_NEWLINE(c) ((c) == '\n' || (c) == '\r')

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
  char domain[256];
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

typedef enum {
  RRL_RESP_NOERROR,
  RRL_RESP_NODATA,
  RRL_RESP_NXDOMAIN,
  RRL_RESP_ERROR
} rrl_response_class_t;

#define RRL_TABLE_SIZE 4096

typedef struct {
  atomic_flag lock;
  _Atomic uint32_t client_hash;
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



static rrl_response_class_t get_rrl_class(const uint8_t *res_buf, size_t res_len) {
  if (res_len < 12) return RRL_RESP_ERROR;
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

  uint32_t hash = 0;
  uint32_t full_hash = 0;
  if (client_addr->ss_family == AF_INET) {
    uint32_t ip = ((const struct sockaddr_in *)client_addr)->sin_addr.s_addr;
    ip &= htonl(0xFFFFFF00); // /24 mask
    full_hash = ip;
    hash = ip ^ (ip >> 16);
  } else if (client_addr->ss_family == AF_INET6) {
    const uint32_t *w = (const uint32_t *)((const struct sockaddr_in6 *)client_addr)->sin6_addr.s6_addr;
    uint32_t w0 = w[0], w1 = w[1];
    w1 &= htonl(0xFFFFFF00); // /56 mask
    full_hash = w0 ^ w1;
    hash = w0 ^ w1 ^ (w1 >> 16);
  }

  size_t idx = hash & (RRL_TABLE_SIZE - 1);
  rrl_bucket_t *b = &g_rrl_table[idx];
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int64_t now_ms = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

  while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) {}

  if (b->client_hash != full_hash) {
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
  zone_db_entry_t **entries;
  size_t count;
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
static int g_num_ipc = 0;
static int g_notify_ipc[2];
static int g_control_sock = -1;
static _Atomic(bool) g_frontend_alive = true;

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
  return openat(dfd, basebuf, flags, mode);
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
  } while (1);
  return snap;
}

void release_zone_snapshot(zone_db_snapshot_t *snap) {
  if (snap)
    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
}

zone_db_entry_t *snapshot_get_zone(zone_db_snapshot_t *snap, const char *domain) {
  if (!snap) return NULL;
  for (size_t i = 0; i < snap->count; i++) {
    if (strcasecmp(snap->entries[i]->domain, domain) == 0) {
      return snap->entries[i];
    }
  }
  return NULL;
}

static void wait_for_snapshot_readers(zone_db_snapshot_t *snap) {
  int retries = 0;
  while (atomic_load_explicit(&snap->reader_count, memory_order_acquire) > 0) {
    usleep(1000);
    if (++retries % 1000 == 0)
      syslog(LOG_WARNING, "[RCU] wait_for_snapshot_readers stalled");
  }
}

static zone_db_entry_t *create_new_zone_entry(const char *domain) {
  zone_db_entry_t *z = calloc(1, sizeof(zone_db_entry_t));
  if (!z) return NULL;
  atomic_init(&z->active_axfr, 0);
  atomic_init(&z->snapshot_refs, 1);
  strncpy(z->domain, domain, sizeof(z->domain) - 1);
  z->domain[sizeof(z->domain) - 1] = 0;
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
  while (atomic_load_explicit(&arena->reader_count, memory_order_acquire) > 0) {
    usleep(1000);
    if (++retries % 1000 == 0)
      syslog(LOG_WARNING, "[RCU] wait_for_readers stalled");
  }
}

void free_zone_db_entry(zone_db_entry_t *entry) {
  if (!entry) return;
  while (atomic_load(&entry->active_axfr) > 0) {
    usleep(1000);
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
    for (int p = 0; p < a->file_buf_count; p++) {
      if (a->file_bufs[p]) free(a->file_bufs[p]);
    }
    if (a->records) free(a->records);
    if (a->hash_table) free(a->hash_table);
  }
  free(entry);
}

static void *gc_snapshot_thread(void *arg) {
  zone_db_snapshot_t *snap = (zone_db_snapshot_t *)arg;
  wait_for_snapshot_readers(snap);
  for (size_t i = 0; i < snap->count; i++) {
    zone_db_entry_t *entry = snap->entries[i];
    if (atomic_fetch_sub_explicit(&entry->snapshot_refs, 1, memory_order_acq_rel) == 1) {
      syslog(LOG_INFO, "[GC] Freeing deleted zone '%s'", entry->domain);
      free_zone_db_entry(entry);
    }
  }
  free(snap->entries);
  free(snap);
  return NULL;
}

static char *arena_strdup(zone_arena_t *arena, const char *str);

static bool compare_records(const dns_record_t *a, const dns_record_t *b) {
  if (a->type_code != b->type_code) return false;
  if ((a->name == NULL) != (b->name == NULL)) return false;
  if (a->name && b->name && strcasecmp(a->name, b->name) != 0) return false;
  if ((a->ttl == NULL) != (b->ttl == NULL)) return false;
  if (a->ttl && b->ttl && strcmp(a->ttl, b->ttl) != 0) return false;
  if (a->rdata_count != b->rdata_count) return false;
  for (int i = 0; i < a->rdata_count; i++) {
    if ((a->rdata[i] == NULL) != (b->rdata[i] == NULL)) return false;
    if (a->rdata[i] && b->rdata[i] && strcmp(a->rdata[i], b->rdata[i]) != 0) return false;
  }
  if (a->generic_len != b->generic_len) return false;
  if (a->generic_len > 0 && memcmp(a->generic_data, b->generic_data, a->generic_len) != 0) return false;
  return true;
}

static bool record_exists_in_arena(zone_arena_t *arena, const dns_record_t *target) {
  if (!arena->hash_table) return false;
  if (!target->name) return false;
  uint32_t hash = calc_fnv1a_str(target->name);
  size_t idx = hash & (arena->hash_size - 1);
  for (int i = arena->hash_table[idx]; i != -1; i = arena->records[i].next_record) {
    if (compare_records(&arena->records[i], target)) return true;
  }
  return false;
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

  int del_count = 0, add_count = 0;
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

static void reload_master_zone(zone_db_entry_t *entry, const char *file) {
  char *buf = read_entire_file(file);
  if (!buf) {
    syslog(LOG_ERR, "[Zone] Failed to read file '%s' for zone '%s'.", file, entry->domain);
    return;
  }
  pthread_mutex_lock(&entry->writer_lock);
  zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
  wait_for_readers(z_standby);
  for (int i = 0; i < z_standby->file_buf_count; i++) free(z_standby->file_bufs[i]);
  z_standby->count = 0;
  z_standby->data_pool_count = 0;
  z_standby->current_pool_cap = 0;
  z_standby->current_pool_idx = 0;
  z_standby->file_buf_count = 0;
  z_standby->file_bufs[z_standby->file_buf_count++] = buf;
  parse_context_t ctx = {0};
  ctx.default_origin = entry->domain;
  int count = parse_zone_fast(buf, strlen(buf), z_standby, &ctx);
  if (count >= 0) {
    build_zone_index(z_standby);
    bool has_soa = false;
    uint32_t hash = calc_fnv1a_str(entry->domain);
    size_t idx = hash & (z_standby->hash_size - 1);
    for (int i = z_standby->hash_table[idx]; i != -1; i = z_standby->records[i].next_record) {
      if (z_standby->records[i].type_code == 6 && strcasecmp(z_standby->records[i].name, entry->domain) == 0) {
        has_soa = true;
        break;
      }
    }
    if (has_soa) {
      compute_ixfr_diff(entry, z_active, z_standby);
      atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
    }
  }
  pthread_mutex_unlock(&entry->writer_lock);
}

void rebuild_zone_db_from_config(server_config_t *config) {
  int new_count = 0;
  for (zone_config_t *z = config->zones; z; z = z->next) new_count++;
  zone_db_snapshot_t *new_snap = calloc(1, sizeof(zone_db_snapshot_t));
  new_snap->count = new_count;
  new_snap->entries = calloc(new_count, sizeof(zone_db_entry_t *));
  atomic_init(&new_snap->reader_count, 0);

  zone_db_snapshot_t *old_snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
  
  int idx = 0;
  for (zone_config_t *z = config->zones; z; z = z->next) {
    zone_db_entry_t *entry = NULL;
    if (old_snap) {
      for (size_t i = 0; i < old_snap->count; i++) {
        if (strcasecmp(old_snap->entries[i]->domain, z->domain) == 0) {
          entry = old_snap->entries[i];
          atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
          break;
        }
      }
    }
    if (!entry) {
      entry = create_new_zone_entry(z->domain);
    }
    new_snap->entries[idx++] = entry;
    
    if (entry && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
      reload_master_zone(entry, z->file);
    }
  }

  atomic_store_explicit(&g_zone_db_active, new_snap, memory_order_release);

  if (old_snap) {
    pthread_t gc_tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&gc_tid, &attr, gc_snapshot_thread, old_snap);
    pthread_attr_destroy(&attr);
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
        ctx->state = TCP_STATE_READ_BODY;
        ctx->accumulated = 0;
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

static char *arena_strdup(zone_arena_t *arena, const char *str) {
  if (!str)
    return NULL;
  size_t len = strlen(str);
  char *dup = arena_alloc(arena, len + 1);
  if (dup) {
    memcpy(dup, str, len);
    dup[len] = '\0';
  }
  return dup;
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
  if (packet_len < 12)
    return -1;
  uint16_t qdcount = (packet[4] << 8) | packet[5],
           ancount = (packet[6] << 8) | packet[7];
  size_t offset = 12;
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
          dns_record_t *s = &standby->records[k];
          if (s->type_code == type && strcasecmp(s->name, rec->name) == 0 &&
              s->rdata_count == rec->rdata_count) {
            bool rdata_match = true;
            for (int r = 0; r < s->rdata_count; r++) {
              if (strcmp(s->rdata[r], rec->rdata[r]) != 0) {
                rdata_match = false;
                break;
              }
            }
            if (rdata_match) {
              standby->records[k] = standby->records[--standby->count];
              break;
            }
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
    if (tsig_key && tsig_verify_packet(msg, msg_len, tsig_key) != 0) {
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
      if (standby->count > 0) {
        for (size_t k = 0; k < standby->count; k++) {
          if (standby->records[k].type_code == 6 &&
              standby->records[k].rdata_count >= 7) {
            entry->serial = strtoul(standby->records[k].rdata[2], NULL, 10);
            entry->refresh = strtoul(standby->records[k].rdata[3], NULL, 10);
            entry->retry = strtoul(standby->records[k].rdata[4], NULL, 10);
            entry->expire = strtoul(standby->records[k].rdata[5], NULL, 10);
            entry->next_check = time(NULL) + entry->refresh;
            break;
          }
        }
        build_zone_index(standby);
        compute_ixfr_diff(entry, active, standby);
        atomic_store_explicit(&entry->rcu.active, standby,
                              memory_order_release);
        wait_for_readers(active);
        void send_notify_to_all(const char *domain);
        send_notify_to_all(entry->domain);
      }
      pthread_mutex_unlock(&entry->writer_lock);
      return 1;
    }
  }
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
                  return true;
                } else
                  (*arcount)++;
              }
            }
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

static void resolve_name(const char *qname, uint16_t qtype,
                         zone_db_entry_t **db_entry_ptr,
                         zone_arena_t **current_zone_ptr, uint8_t *res,
                         size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *ancount,
                         uint16_t *nscount, uint16_t *arcount) {
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
    for (int i = current_zone->hash_table[idx]; i != -1;
         i = current_zone->records[i].next_record) {
      dns_record_t *rec = &current_zone->records[i];
      if (strcasecmp(rec->name, current_qname) == 0) {
        found = true;
        uint16_t rec_type = rec->type_code;
        if (rec_type == 5 && qtype != 5 && qtype != 255) {
          if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            res[2] |= 0x02;
            return;
          } else
            (*ancount)++;
          if (rec->rdata_count > 0) {
            strncpy(current_qname, rec->rdata[0], sizeof(current_qname));
            current_qname[255] = '\0';
            cname_followed = true;
          }
          break;
        } else if (qtype == 255 || qtype == rec_type) {
          type_matched = true;
          if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                   NULL, 0xFFFFFFFF) < 0) {
            res[2] |= 0x02;
            return;
          }
          (*ancount)++;
        }
      }
    }
    if (!found) {
      const char *parent = current_qname;
      char wc_name[256];
      while ((parent = strchr(parent, '.')) != NULL) {
        parent++;
        if (*parent == '\0')
          break;
        snprintf(wc_name, sizeof(wc_name), "*.%s", parent);
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
            if (rec_type == 5 && qtype != 5 && qtype != 255) {
              if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                       current_qname, 0xFFFFFFFF) < 0) {
                res[2] |= 0x02;
                return;
              } else
                (*ancount)++;
              if (rec->rdata_count > 0) {
                strncpy(current_qname, rec->rdata[0], sizeof(current_qname));
                current_qname[255] = '\0';
                cname_followed = true;
              }
              break;
            } else if (qtype == 255 || qtype == rec_type) {
              type_matched = true;
              if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx,
                                       current_qname, 0xFFFFFFFF) < 0) {
                res[2] |= 0x02;
                return;
              } else
                (*ancount)++;
            }
          }
        }
        if (wc_found)
          break;
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
        zone_db_snapshot_t *snap = NULL;
        do {
          snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
          if (!snap)
            break;
          atomic_fetch_add_explicit(&snap->reader_count, 1,
                                    memory_order_acquire);
          if (snap ==
              atomic_load_explicit(&g_zone_db_active, memory_order_acquire))
            break;
          atomic_fetch_sub_explicit(&snap->reader_count, 1,
                                    memory_order_release);
        } while (1);
        if (snap) {
          for (size_t i = 0; i < snap->count; i++) {
            size_t check_z_len = strlen(snap->entries[i]->domain);
            bool match = false;
            if (cq_len == check_z_len &&
                strcasecmp(current_qname, snap->entries[i]->domain) == 0)
              match = true;
            else if (cq_len > check_z_len &&
                     current_qname[cq_len - check_z_len - 1] == '.' &&
                     strcasecmp(current_qname + cq_len - check_z_len,
                                snap->entries[i]->domain) == 0)
              match = true;
            if (match && check_z_len > longest_match_len) {
              longest_match_len = check_z_len;
              new_db_entry = snap->entries[i];
            }
          }
          atomic_fetch_sub_explicit(&snap->reader_count, 1,
                                    memory_order_release);
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
    size_t offset = 12;
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

int process_dns_query(const uint8_t *req, size_t req_len, uint8_t *res,
                      size_t max_res_len, const char *qname, uint16_t qtype,
                      const char *client_ip, compress_ctx_t *comp_ctx,
                      bool is_tcp, rate_limit_config_t **out_rrl_cfg,
                      zone_db_snapshot_t *snap) {
  char current_qname[256];
  strncpy(current_qname, qname, 255);
  current_qname[255] = '\0';
  size_t q_len = strlen(current_qname);
  zone_arena_t *current_zone = NULL;
  zone_db_entry_t *db_entry = NULL;
  size_t longest_match_len = 0;

  if (snap) {
    for (size_t i = 0; i < snap->count; i++) {
      size_t z_len = strlen(snap->entries[i]->domain);
      bool match = false;
      if (q_len == z_len &&
          strcasecmp(current_qname, snap->entries[i]->domain) == 0)
        match = true;
      else if (q_len > z_len && current_qname[q_len - z_len - 1] == '.' &&
               strcasecmp(current_qname + q_len - z_len,
                          snap->entries[i]->domain) == 0)
        match = true;
      if (match && z_len > longest_match_len) {
        longest_match_len = z_len;
        db_entry = snap->entries[i];
      }
    }
  }

  if (out_rrl_cfg) {
    server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    *out_rrl_cfg = &cfg->rrl;
    if (db_entry) {
      zone_config_t *zcfg = cfg->zones;
      while (zcfg) {
        if (strcasecmp(zcfg->domain, db_entry->domain) == 0) {
          if (zcfg->rrl.configured) {
            *out_rrl_cfg = &zcfg->rrl;
          }
          break;
        }
        zcfg = zcfg->next;
      }
    }
  }

  if (req_len < 12) {
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
    memcpy(res, req, 12);
    res[2] |= 0x80;
    res[3] = (res[3] & 0x0F) | 0x01; // FORMERR
    memset(&res[4], 0, 8); // qdcount, ancount, nscount, arcount = 0
    return 12;
  }
  edns.ede_count = 0; // 反射防止

  server_config_t *cfg_for_ede = atomic_load_explicit(&g_config_db.active, memory_order_acquire);

  uint8_t opcode = (req[2] >> 3) & 0x0F;
  if (opcode != 0 && opcode != 4) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0xF0) | 0x04; // NOTIMP
    add_ede(&edns, cfg_for_ede->send_extended_errors, 21, "This opcode is not supported by this server");
    
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  if (qdcount != 1) {
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0x0F) | 0x01; // FORMERR
    add_ede(&edns, cfg_for_ede->send_extended_errors, 0, NULL);
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }

  if (opcode == 4) { // NOTIFY
    bool auth = false;
    if (db_entry) {
      server_config_t *cfg =
          atomic_load_explicit(&g_config_db.active, memory_order_acquire);
      zone_config_t *zcfg = cfg->zones;
      while (zcfg) {
        if (strcasecmp(zcfg->domain, db_entry->domain) == 0)
          break;
        zcfg = zcfg->next;
      }
      if (zcfg && zcfg->masters_count > 0) {
        for (int k = 0; k < zcfg->masters_count; k++) {
          if (strcmp(client_ip, zcfg->masters[k].ip) == 0) {
            auth = true;
            break;
          }
        }
        if (auth && zcfg->tsig_key) {
          tsig_key_t *k = cfg->keys, *matched_key = NULL;
          while (k) {
            if (strcmp(k->name, zcfg->tsig_key) == 0) {
              matched_key = k;
              break;
            }
            k = k->next;
          }
          if (!matched_key ||
              tsig_verify_packet(req, req_len, matched_key) != 0)
            auth = false;
        }
      }
    }
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x84;
    if (auth) {
      res[3] &= 0x0F;
      atomic_store_explicit(&db_entry->refresh_now, true, memory_order_release);
      if (g_control_kq != -1) {
        struct kevent ev;
        EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
      }
    } else {
      res[3] |= 0x05;
      add_ede(&edns, cfg_for_ede->send_extended_errors, 18, "Query refused due to access control");
    }
    uint16_t offset = (uint16_t)get_question_end_offset(res, copy_len, qdcount);
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
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

  if (edns.present && max_res_len == 512) {
    if (edns.udp_payload_size > 1232)
      edns.udp_payload_size = 1232;
    if (edns.udp_payload_size > 512)
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

  size_t q_offset = 12;
  while (q_offset < req_len) {
    uint8_t len = req[q_offset];
    if (len == 0) {
      q_offset++;
      break;
    }
    if ((len & 0xC0) == 0xC0) {
      q_offset += 2;
      break;
    }
    q_offset += len + 1;
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
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, 0);
    }
    res[10] = arcount >> 8;
    res[11] = arcount & 0xFF;
    return offset;
  }
  uint16_t qclass = (req[q_offset + 2] << 8) | req[q_offset + 3];
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
  if (!is_tcp && qtype == 255) {
    res[2] |= 0x02;
    if (current_zone)
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                memory_order_release);
    return q_offset;
  }
  if (!current_zone) {
    res[3] |= 5;
    add_ede(&edns, cfg_for_ede->send_extended_errors, 20, "This server is not authoritative for the queried zone");
    uint16_t offset = q_offset;
    uint16_t arcount = 0;
    if (edns.present) {
      assemble_edns_opt(res, max_res_len, &offset, &arcount, &edns, ext_rcode_out);
      *res_arcount = htons(arcount);
    }
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

  resolve_name(current_qname, qtype, &db_entry, &current_zone, res, max_res_len,
               &offset, comp_ctx, &ancount, &nscount, &arcount);

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
    free(ctx);
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
    axfr_req[12] = 0x00;
    axfr_req[13] = 0x01;
    req_len = 14;
    const char *d = ctx->domain;
    while (*d) {
      const char *dot = strchr(d, '.');
      size_t len = dot ? (size_t)(dot - d) : strlen(d);
      if (len > 63)
        len = 63;
      if (req_len + len + 2 > sizeof(axfr_req) - 512)
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
                       ctx->tsig_key, 0, NULL, NULL);
      req_len = p_len + 2;
    }
    uint16_t msg_len = req_len - 2;
    axfr_req[0] = msg_len >> 8;
    axfr_req[1] = msg_len & 0xFF;
    if (send(tcp_fd, axfr_req, req_len, 0) == req_len) {
      if (handle_axfr_event(tcp_fd, ctx->entry, &stream_ctx, &session, ctx->tsig_key) > 0) {
        syslog(LOG_NOTICE, "[AXFR] Successfully transferred zone %s from %s", ctx->domain, ctx->master_ip);
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
  pthread_exit(NULL);
}

void send_notify_to_all(const char *domain) {
  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  if (!active)
    return;
  zone_config_t *zone = active->zones;
  while (zone) {
    if (strcasecmp(zone->domain, domain) == 0)
      break;
    zone = zone->next;
  }
  if (!zone || zone->also_notify_count == 0)
    return;

  uint8_t req[512];
  memset(req, 0, 12);
  uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
  req[0] = id >> 8;
  req[1] = id & 0xFF;
  req[2] = 0x20;
  req[3] = 0;
  req[4] = 0;
  req[5] = 1;
  size_t offset = 12;
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
}

static void write_query_log(const char *client_ip, int client_port,
                            const char *qname, uint16_t qclass, uint16_t qtype,
                            bool has_edns, bool dnssec_ok) {
  server_config_t *cfg =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  if (!cfg || !cfg->logging.queries_channel ||
      cfg->logging.queries_channel->fd < 0)
    return;
  log_channel_t *ch = cfg->logging.queries_channel;
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tm_info;
  localtime_r(&ts.tv_sec, &tm_info);
  int today = (tm_info.tm_year + 1900) * 10000 + (tm_info.tm_mon + 1) * 100 +
              tm_info.tm_mday;
  char time_str[64] = "";
  if (ch->print_time) {
    char buf[32];
    strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S", &tm_info);
    snprintf(time_str, sizeof(time_str), "%s.%03ld ", buf,
             ts.tv_nsec / 1000000);
  }
  char class_str[16];
  if (qclass == 1)
    strcpy(class_str, "IN");
  else if (qclass == 255)
    strcpy(class_str, "ANY");
  else
    snprintf(class_str, sizeof(class_str), "CLASS%d", qclass);
  const char *type_str_tmp = get_type_str(qtype, NULL);
  char type_str[32];
  if (type_str_tmp) {
    strncpy(type_str, type_str_tmp, sizeof(type_str) - 1);
    type_str[sizeof(type_str) - 1] = '\0';
    if (strncmp(type_str_tmp, "TYPE", 4) == 0)
      free((void *)type_str_tmp);
  } else
    snprintf(type_str, sizeof(type_str), "TYPE%d", qtype);
  char edns_str[16] = "";
  if (has_edns)
    snprintf(edns_str, sizeof(edns_str), "+E(0)%s", dnssec_ok ? "D" : "K");
  char log_buf[1024];
  int len = snprintf(log_buf, sizeof(log_buf),
                     "%s%s%sclient %s#%d (%s): query: %s %s %s %s\n", time_str,
                     ch->print_category ? "queries: " : "",
                     ch->print_severity ? "info: " : "", client_ip, client_port,
                     qname, qname, class_str, type_str, edns_str);
  if (len <= 0)
    return;
  if (len >= (int)sizeof(log_buf))
    len = sizeof(log_buf) - 1;
  pthread_mutex_lock(&ch->lock);
  bool rotate = false;
  if (ch->size_limit > 0 && ch->current_size + len > ch->size_limit)
    rotate = true;
  else if (ch->suffix_timestamp && ch->current_date != today)
    rotate = true;
  if (rotate) {
    close(ch->fd);
    ch->fd = -1;
    int reopen_flags = O_WRONLY | O_CREAT | O_APPEND;
    if (ch->suffix_timestamp) {
      char new_name[600];
      int r = snprintf(new_name, sizeof(new_name), "%s.%08d", ch->file_path,
                       ch->current_date);
      if (r > 0 && r < (int)sizeof(new_name))
        renameat_via_dir_cache(ch->file_path, new_name);
    } else if (ch->versions > 0) {
      for (int i = ch->versions - 1; i >= 0; i--) {
        char old_name[600], new_name[600];
        int r1 = (i == 0)
                     ? snprintf(old_name, sizeof(old_name), "%s", ch->file_path)
                     : snprintf(old_name, sizeof(old_name), "%s.%d",
                                ch->file_path, i - 1);
        int r2 =
            snprintf(new_name, sizeof(new_name), "%s.%d", ch->file_path, i);
        if (r1 > 0 && r2 > 0)
          renameat_via_dir_cache(old_name, new_name);
      }
    } else
      reopen_flags |= O_TRUNC;
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

// ============================================================================
// 11. TCP & Worker Threads (サンドボックス内)
// ============================================================================

typedef struct {
  int client_fd;
  char qname[256];
  uint8_t req[512];
  uint16_t req_len;
  tsig_key_t *tsig_key;
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
                        uint16_t req_len, tsig_key_t *tsig_key, zone_db_entry_t *entry) {
  if (!entry) {
    uint8_t res_buf[512];
    size_t copy_len = req_len > 512 ? 512 : req_len;
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
  size_t q_offset = 12;
  while (q_offset < req_len) {
    uint8_t len = req[q_offset];
    if (len == 0) {
      q_offset++;
      break;
    }
    if ((len & 0xC0) == 0xC0) {
      q_offset += 2;
      break;
    }
    q_offset += len + 1;
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
  uint8_t prior_mac[64] = {0};
  size_t prior_mac_len = 0;
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
      tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, prior_mac, &prior_mac_len); \
      prev_offset = sign_len; \
    } \
    uint8_t len_prefix[2] = {prev_offset >> 8, prev_offset & 0xFF}; \
    if (send_tcp_robust(client_fd, len_prefix, 2) < 0) goto axfr_error; \
    if (send_tcp_robust(client_fd, res, prev_offset) < 0) goto axfr_error; \
    offset = q_offset; \
    answers = 0; \
    memset(res, 0, 65535); \
    memcpy(res, req, q_offset); \
    res[2] |= 0x84; res[3] &= 0x0F; \
    res[8] = 0; res[9] = 0; res[10] = 0; res[11] = 0; \
    memset(&comp_ctx, 0, sizeof(comp_ctx)); \
    compress_ctx_init_packet(&comp_ctx); \
    if (serialize_dns_record(res, 65000, &offset, (rec_ptr), &comp_ctx, NULL, 0xFFFFFFFF) < 0) \
      continue; \
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
      tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, prior_mac,
                       &prior_mac_len);
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
  axfr_worker_args_t *args = (axfr_worker_args_t *)arg;
  zone_db_entry_t *entry = args->entry;
  send_axfr_response(args->client_fd, args->qname, args->req, args->req_len,
                     args->tsig_key, entry);
  close(args->client_fd);
  zone_db_snapshot_t *worker_snap = args->snap;
  free(args);
  if (entry)
    atomic_fetch_sub(&entry->active_axfr, 1);
  release_zone_snapshot(worker_snap);
  pthread_exit(NULL);
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
          if (payload_received > 12) {
            size_t offset = 12;
            size_t recv_len = (size_t)payload_received;
            size_t written = 0;
            while (offset < recv_len) {
              uint8_t len = req_buf[offset];
              if (len == 0 || (len & 0xC0) == 0xC0) {
                offset += (len == 0) ? 1 : 2;
                break;
              }
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
          size_t question_end = 12; // default fallback
          if (payload_received > 12) {
            size_t offset = 12;
            while (offset < (size_t)payload_received) {
              uint8_t len = req_buf[offset];
              if (len == 0 || (len & 0xC0) == 0xC0) {
                offset += (len == 0) ? 1 : 2;
                break;
              }
              offset += len + 1;
            }
            question_end = offset + 4;
            if (offset + 3 < (size_t)payload_received)
              qclass = (req_buf[offset + 2] << 8) | req_buf[offset + 3];
            uint16_t arcount = (req_buf[10] << 8) | req_buf[11];
            if (arcount > 0) {
              size_t o = 12;
              uint16_t qd = (req_buf[4] << 8) | req_buf[5];
              uint16_t an = (req_buf[6] << 8) | req_buf[7];
              uint16_t ns = (req_buf[8] << 8) | req_buf[9];
              for (int k = 0; k < qd; k++) {
                while (o < (size_t)payload_received && req_buf[o] != 0 &&
                       (req_buf[o] & 0xC0) != 0xC0)
                  o += req_buf[o] + 1;
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
                       (req_buf[o] & 0xC0) != 0xC0)
                  o += req_buf[o] + 1;
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
              process_dns_query(req_buf, payload_received, res_buf, 512, qname,
                                qtype, client_ip, &thread_compress_ctx, false, &rrl_cfg, snap);
          release_zone_snapshot(snap);
          if (res_len > 0) {
            bool slip_triggered = false;
            rrl_response_class_t cls = get_rrl_class(res_buf, res_len);
            if (rrl_check((struct sockaddr_storage *)&ipc_msg->client_addr, cls, rrl_cfg, &slip_triggered)) {
              udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
              *res_msg = *ipc_msg;
              res_msg->payload_len = res_len;
              send(active_fd, res_buf_full, sizeof(udp_ipc_t) + res_len, 0);
            } else if (slip_triggered) {
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
            }
          }
        }
      } else if (ev_list[i].udata == (void *)2) {
        // TCP
        int active_tcp_fd = ev_list[i].ident;
        while (1) {
          struct sockaddr_storage client_addr;
          socklen_t client_len = sizeof(client_addr);
          int client_fd = accept(active_tcp_fd, (struct sockaddr *)&client_addr,
                                 &client_len);
          if (client_fd < 0)
            break;

          limit_client_socket_rights(client_fd);
          int cflags = fcntl(client_fd, F_GETFL, 0);
          fcntl(client_fd, F_SETFL, cflags | O_NONBLOCK);
          tcp_stream_ctx_t *ctx_tcp = calloc(1, sizeof(tcp_stream_ctx_t));
          if (!ctx_tcp) {
            close(client_fd);
            continue;
          }
          struct kevent ev_timeout;
          EV_SET(&ev_timeout, client_fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
                 15000, ctx_tcp);
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
          free(ctx_tcp);
        } else if (ret == 1) {
          struct kevent ev_del;
          EV_SET(&ev_del, client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
          kevent(kq, &ev_del, 1, NULL, 0, NULL);
          char qname[256] = "";
          uint16_t qtype = 0;
          if (msg_len > 12) {
            size_t offset = 12;
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
          if (msg_len >= 12) {
            size_t offset = 12;
            while (offset < msg_len) {
              uint8_t len = msg[offset];
              if (len == 0 || (len & 0xC0) == 0xC0) {
                offset += (len == 0) ? 1 : 2;
                break;
              }
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
            server_config_t *cfg =
                atomic_load_explicit(&g_config_db.active, memory_order_acquire);
            zone_config_t *zcfg = cfg->zones;
            while (zcfg) {
              if (strcasecmp(zcfg->domain, qname) == 0)
                break;
              zcfg = zcfg->next;
            }
            bool allowed = false;
            uint16_t tsig_error = 0;
            tsig_key_t *matched_key = NULL;
            if (zcfg) {
              if (zcfg->tsig_key) {
                tsig_key_t *k = cfg->keys;
                while (k) {
                  if (strcmp(k->name, zcfg->tsig_key) == 0) {
                    matched_key = k;
                    break;
                  }
                  k = k->next;
                }
                if (!matched_key)
                  tsig_error = 17;
                else {
                  int err = tsig_verify_packet(msg, msg_len, matched_key);
                  if (err != 0)
                    tsig_error = err > 0 ? err : 16;
                  else
                    allowed = true;
                }
              } else if (zcfg->allow_transfer_count > 0) {
                for (int k = 0; k < zcfg->allow_transfer_count; k++) {
                  if (match_cidr(ctx_tcp->client_ip, zcfg->allow_transfer[k])) {
                    allowed = true;
                    break;
                  }
                }
              }
            }
            zone_db_entry_t *entry = snapshot_get_zone(snap, qname);
            if (allowed && entry) {
              if (atomic_fetch_add(&entry->active_axfr, 1) >= MAX_ZONE_AXFR) {
                atomic_fetch_sub(&entry->active_axfr, 1);
                allowed = false;
              } else {
                axfr_worker_args_t *args = malloc(sizeof(axfr_worker_args_t));
                if (args) {
                  args->client_fd = client_fd;
                  strncpy(args->qname, qname, 255);
                  args->qname[255] = '\0';
                  args->req_len = msg_len > 512 ? 512 : msg_len;
                  memcpy(args->req, msg, args->req_len);
                  args->tsig_key = matched_key;
                  args->entry = entry;
                  args->snap = snap;
                  atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
                  int cflags = fcntl(client_fd, F_GETFL, 0);
                  fcntl(client_fd, F_SETFL, cflags & ~O_NONBLOCK);
                  pthread_t t;
                  if (pthread_create(&t, NULL, axfr_worker_thread, args) != 0) {
                    free(args);
                    atomic_fetch_sub(&entry->active_axfr, 1);
                    close(client_fd);
                  } else
                    pthread_detach(t);
                } else {
                  atomic_fetch_sub(&entry->active_axfr, 1);
                  close(client_fd);
                }
              }
            }
            if (!allowed || !entry) {
              uint8_t res_buf[1024];
              size_t copy_len = msg_len > 512 ? 512 : msg_len;
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
                                   matched_key, tsig_error, NULL, NULL);
                else {
                  tsig_key_t dummy = {0};
                  dummy.name = zcfg->tsig_key;
                  dummy.algorithm = "hmac-sha256";
                  tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf), &dummy,
                                   17, NULL, NULL);
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
              close(client_fd);
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
                uint8_t len_prefix[2] = {res_len >> 8, res_len & 0xFF};
                send(client_fd, len_prefix, 2, 0);
                send(client_fd, tcp_res, res_len, 0);
              }
              free(tcp_res);
            } else {
              release_zone_snapshot(snap);
            }
            close(client_fd);
            free(ctx_tcp);
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
  
  for (size_t i = 0; i < snap->count; i++) {
    zone_db_entry_t *entry = snap->entries[i];
    zone_config_t *zcfg = active_cfg->zones;
    while (zcfg) {
      if (strcasecmp(zcfg->domain, entry->domain) == 0) {
        if (zcfg->type && (strcasecmp(zcfg->type, "master") == 0 || strcasecmp(zcfg->type, "primary") == 0) && zcfg->file) {
          syslog(LOG_NOTICE, "[Control] Reloading master zone: %s", entry->domain);
          reload_master_zone(entry, zcfg->file);
        } else if (zcfg->type && strcasecmp(zcfg->type, "slave") == 0) {
          syslog(LOG_NOTICE, "[Control] Triggering retransfer for slave zone: %s", entry->domain);
          atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
        }
        break;
      }
      zcfg = zcfg->next;
    }
  }
  release_zone_snapshot(snap);
}

static void perform_config_reload(void) {
  char *config_str = read_entire_file(g_config_path);
  if (!config_str)
    return;
  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  server_config_t *standby = (active == &g_config_db.config_a)
                                 ? &g_config_db.config_b
                                 : &g_config_db.config_a;
  for (int j = 0; j < standby->bind_address_count; j++)
    free(standby->bind_addresses[j]);
  free(standby->bind_addresses);
  standby->bind_addresses = NULL;
  standby->bind_address_count = 0;
  zone_config_t *curr = standby->zones;
  while (curr) {
    zone_config_t *next = curr->next;
    free_zone_config(curr);
    curr = next;
  }
  tsig_key_t *k = standby->keys;
  while (k) {
    tsig_key_t *next_k = k->next;
    free(k->name); free(k->algorithm); free(k->secret);
    free(k);
    k = next_k;
  }
  standby->zones = NULL;
  standby->keys = NULL;
  if (standby->control.algorithm) free(standby->control.algorithm);
  if (standby->control.secret) free(standby->control.secret);
  memset(&standby->control, 0, sizeof(control_channel_config_t));
  free_rate_limit_config(&standby->rrl);
  memset(&standby->rrl, 0, sizeof(rate_limit_config_t));
  free_logging_channels(standby);
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
        ssize_t r = recv(cfd, c->buf + c->buf_len, sizeof(c->buf) - c->buf_len - 1, 0);
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
            
            if (strcmp(cmd, "reload") == 0) {
              if (arg && strlen(arg) > 0) {
                const char *canon_arg = find_configured_domain(arg);
                server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
                zone_config_t *zcfg = active->zones;
                while (zcfg) {
                  if (strcasecmp(zcfg->domain, canon_arg) == 0) break;
                  zcfg = zcfg->next;
                }
                if (zcfg) {
                  syslog(LOG_NOTICE, "[Control] Received targeted reload command for zone: %s", canon_arg);
                  zone_db_snapshot_t *snap = acquire_zone_snapshot();
                  zone_db_entry_t *entry = snapshot_get_zone(snap, zcfg->domain);
                  if (entry) {
                    if (zcfg->type && (strcmp(zcfg->type, "master") == 0 || strcmp(zcfg->type, "primary") == 0)) {
                      char *buf = read_entire_file(zcfg->file);
                      if (buf) {
                        pthread_mutex_lock(&entry->writer_lock);
                        zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
                        zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
                        wait_for_readers(z_standby);
                        for (int i = 0; i < z_standby->file_buf_count; i++) free(z_standby->file_bufs[i]);
                        z_standby->count = 0;
                        z_standby->data_pool_count = 0;
                        z_standby->current_pool_cap = 0;
                        z_standby->current_pool_idx = 0;
                        z_standby->file_buf_count = 0;
                        z_standby->file_bufs[z_standby->file_buf_count++] = buf;
                        parse_context_t ctx = {0};
                        ctx.default_origin = zcfg->domain;
                        int count = parse_zone_fast(buf, strlen(buf), z_standby, &ctx);
                        if (count >= 0) {
                          build_zone_index(z_standby);
                          bool has_soa = false;
                          uint32_t hash = calc_fnv1a_str(zcfg->domain);
                          size_t idx = hash & (z_standby->hash_size - 1);
                          for (int i = z_standby->hash_table[idx]; i != -1; i = z_standby->records[i].next_record) {
                            if (z_standby->records[i].type_code == 6 && strcasecmp(z_standby->records[i].name, zcfg->domain) == 0) {
                              has_soa = true; break;
                            }
                          }
                          if (has_soa) {
                            compute_ixfr_diff(entry, z_active, z_standby);
                            atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
                            syslog(LOG_NOTICE, "[Control] Targeted reload successful for %s", zcfg->domain);
                            send(cfd, "OK reloaded\n", 12, 0);
                          } else {
                            syslog(LOG_ERR, "[Control] Targeted reload failed for %s: missing SOA", zcfg->domain);
                            send(cfd, "ERROR missing SOA\n", 18, 0);
                          }
                        } else {
                          syslog(LOG_ERR, "[Control] Targeted reload failed for %s: parse error", zcfg->domain);
                          send(cfd, "ERROR parse error\n", 18, 0);
                        }
                        pthread_mutex_unlock(&entry->writer_lock);
                      } else {
                        syslog(LOG_ERR, "[Control] Targeted reload failed for %s: file read error", zcfg->domain);
                        send(cfd, "ERROR file read error\n", 22, 0);
                      }
                    } else if (zcfg->type && strcasecmp(zcfg->type, "slave") == 0) {
                      syslog(LOG_NOTICE, "[Control] Triggering retransfer for slave zone %s on reload", zcfg->domain);
                      atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
                      send(cfd, "OK reloaded (slave)\n", 20, 0);
                    } else {
                      send(cfd, "ERROR unknown zone type\n", 24, 0);
                    }
                  }
                  release_zone_snapshot(snap);
                } else {
                  syslog(LOG_ERR, "[Control] Command 'reload' failed: zone '%s' not found", canon_arg);
                  send(cfd, "ERROR zone not found\n", 21, 0);
                }
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
              char smsg[512];
              bool frontend_alive = atomic_load(&g_frontend_alive);
              uint64_t dropped = atomic_load_explicit(&g_rrl_dropped_total, memory_order_relaxed);
              uint64_t slipped = atomic_load_explicit(&g_rrl_slip_total, memory_order_relaxed);
              uint64_t ede_proh = atomic_load_explicit(&g_ede_prohibited_total, memory_order_relaxed);
              uint64_t ede_na = atomic_load_explicit(&g_ede_not_authoritative_total, memory_order_relaxed);
              uint64_t ede_ns = atomic_load_explicit(&g_ede_not_supported_total, memory_order_relaxed);
              uint64_t ede_oth = atomic_load_explicit(&g_ede_other_total, memory_order_relaxed);
              int slen = snprintf(smsg, sizeof(smsg), "OK frontend_alive=%d pid=%d RRL_Dropped=%" PRIu64 " RRL_Slipped=%" PRIu64 " EDE_Prohibited=%" PRIu64 " EDE_NotAuthoritative=%" PRIu64 " EDE_NotSupported=%" PRIu64 " EDE_Other=%" PRIu64 "\n", 
                                  frontend_alive, getpid(), dropped, slipped, ede_proh, ede_na, ede_ns, ede_oth);
              send(cfd, smsg, slen, 0);
            } else if (strcmp(cmd, "zonestatus") == 0 && arg) {
              const char *canon_arg = find_configured_domain(arg);
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              zone_db_entry_t *entry = snapshot_get_zone(snap, canon_arg);
              if (entry) {
                char smsg[256];
                int slen = snprintf(smsg, sizeof(smsg), "OK serial=%u refresh=%u\n", (uint32_t)entry->serial, (uint32_t)entry->refresh);
                send(cfd, smsg, slen, 0);
              } else {
                syslog(LOG_ERR, "[Control] Command 'zonestatus' failed: zone '%s' not found", canon_arg);
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "notify") == 0 && arg) {
              const char *canon_arg = find_configured_domain(arg);
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              zone_db_entry_t *entry = snapshot_get_zone(snap, canon_arg);
              if (entry) {
                syslog(LOG_NOTICE, "[Control] Received notify command for zone: %s", canon_arg);
                atomic_store_explicit(&entry->notify_now, true, memory_order_release);
                send(cfd, "OK\n", 3, 0);
              } else {
                syslog(LOG_ERR, "[Control] Command 'notify' failed: zone '%s' not found", canon_arg);
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "retransfer") == 0 && arg) {
              const char *canon_arg = find_configured_domain(arg);
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              zone_db_entry_t *entry = snapshot_get_zone(snap, canon_arg);
              if (entry) {
                syslog(LOG_NOTICE, "[Control] Received retransfer command for zone: %s", canon_arg);
                atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
                send(cfd, "OK\n", 3, 0);
              } else {
                syslog(LOG_ERR, "[Control] Command 'retransfer' failed: zone '%s' not found", canon_arg);
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
        zone_config_t *zone = active->zones;
        zone_db_snapshot_t *snap = acquire_zone_snapshot();
        int check_count = 0;
        while (zone) {
          if (++check_count % 50 == 0) {
            release_zone_snapshot(snap);
            snap = acquire_zone_snapshot();
          }
          zone_db_entry_t *entry = snapshot_get_zone(snap, zone->domain);
          if (entry) {
            if (atomic_exchange_explicit(&entry->notify_now, false, memory_order_acquire)) {
              syslog(LOG_INFO, "[Control] Executing manual NOTIFY for %s", entry->domain);
              send_notify_to_all(entry->domain);
            }
          }
          if (zone->type && strcasecmp(zone->type, "slave") == 0 &&
              zone->masters_count > 0 && zone->masters[0].ip != NULL) {
            if (entry) {
              bool force = atomic_exchange_explicit(&entry->refresh_now, false,
                                                    memory_order_acquire);
              if (force || entry->next_check == 0 ||
                  (entry->next_check > 0 && now >= entry->next_check)) {
                bool expected = false;
                if (atomic_compare_exchange_strong_explicit(
                        &entry->is_transferring, &expected, true,
                        memory_order_acquire, memory_order_relaxed)) {
                  entry->next_check = now + (entry->retry ? entry->retry : 60);
                  axfr_bg_ctx_t *bg_ctx = calloc(1, sizeof(axfr_bg_ctx_t));
                  if (bg_ctx) {
                    strncpy(bg_ctx->master_ip, zone->masters[0].ip,
                            sizeof(bg_ctx->master_ip) - 1);
                    bg_ctx->master_port = zone->masters[0].port;
                    if (zone->domain)
                      strncpy(bg_ctx->domain, zone->domain,
                              sizeof(bg_ctx->domain) - 1);
                    bg_ctx->entry = entry;
                    if (zone->tsig_key) {
                      tsig_key_t *k = active->keys;
                      while (k) {
                        if (strcmp(k->name, zone->tsig_key) == 0) {
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
                    if (pthread_create(&bg_thread, &attr, axfr_bg_thread_func,
                                       bg_ctx) != 0) {
                      free(bg_ctx);
                      atomic_store_explicit(&entry->is_transferring, false,
                                            memory_order_release);
                    }
                    pthread_attr_destroy(&attr);
                  } else
                    atomic_store_explicit(&entry->is_transferring, false,
                                          memory_order_release);
                }
              }
            }
          }
          zone = zone->next;
        }
        release_zone_snapshot(snap);
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
    if (pwd) {
      gid_t target_gid = pwd->pw_gid;
      if (cfg->group) {
        struct group *grp = getgrnam(cfg->group);
        if (grp) target_gid = grp->gr_gid;
      }
      setgroups(0, NULL);
      setgid(target_gid);
      setuid(pwd->pw_uid);
    }
  } else if (cfg->group) {
    struct group *grp = getgrnam(cfg->group);
    if (grp) {
      setgroups(0, NULL);
      setgid(grp->gr_gid);
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
  tzset();
  
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
  openlog("KariDNS", LOG_PID | LOG_NDELAY, LOG_DAEMON);
  start_connect_broker();
  if (!foreground) {
    daemonize();
  }
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

  tzset();
  enter_capsicum_sandbox(); // サンドボックス突入！

  for (int i = 0; i < num_workers; i++)
    pthread_join(threads[i], NULL);
  pthread_join(control_thread, NULL);

  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  for (int i = 0; i < active->bind_address_count; i++)
    free(active->bind_addresses[i]);
  free(active->bind_addresses);
  active->bind_address_count = 0;
  zone_config_t *curr = active->zones;
  while (curr) {
    zone_config_t *next = curr->next;
    free_zone_config(curr);
    curr = next;
  }
  return 0;
}