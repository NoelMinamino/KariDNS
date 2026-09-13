#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "dns_zone_parser.h"
#include "dns_config_parser.h"
#include "dns_utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
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
#include <stdalign.h>
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
#include <sys/uio.h>

#include "dns_wire.h" // 分離したワイヤーフォーマット操作用ヘッダ
#include "dns_server_internal.h"
#include "dns_catalog_zone.h"
#include "dns_edns_ecs.h"
#include "dns_rrl.h"
#include "dns_tsig_acl.h"
#include "dns_priv_sandbox.h"
#include "dns_dynamic_update.h"
#include "dns_axfr_ixfr.h"
#include "dns_query_engine.h"

// karidns
// Copyright (c) 2026 Noel Minamino. Made with AI Assistance(Gemini, Claude)
// License: MIT
// All codes are developed by Gemini Pro, Claude Sonnet with Human Idea and
// test.

// ============================================================================
// 1. 定数・マクロ・IPC定義
// ============================================================================
#define DNS_PORT 53
#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096


#define MAX_BIND_ADDRS 64


pthread_mutex_t g_zone_db_rebuild_lock = PTHREAD_MUTEX_INITIALIZER;

// Protected by g_zone_db_rebuild_lock
pending_coo_t *g_pending_coo = NULL;
int g_pending_coo_count = 0;
int g_pending_coo_capacity = 0;

static _Atomic(zone_db_snapshot_t *) g_zone_db_active = ATOMIC_VAR_INIT(NULL);
config_rcu_t g_config_db;

server_config_t *acquire_config_snapshot(void) {
  server_config_t *snap = NULL;
  do {
    snap = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    if (!snap) return NULL;
    atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
    if (snap == atomic_load_explicit(&g_config_db.active, memory_order_acquire)) break;
    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
  } while (1);
  return snap;
}

void release_config_snapshot(server_config_t *snap) {
  if (snap) atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
}
int g_control_kq = -1;
int g_cwd_fd = -1;
static const char *g_config_path = NULL;
static int g_cli_port_override = 0;
static _Atomic int g_bound_workers = 0;
static _Atomic bool g_privilege_drop_complete = false;
#define MAX_ZONE_AXFR 4

#define NUM_FRONTEND_ROUTERS 2
#define MAX_FRONTEND_ROUTERS 4
#define MAX_WORKERS 128

// Frontend/Backend IPC用グローバル変数
static int g_num_frontend_routers = NUM_FRONTEND_ROUTERS;
static int g_ipc_fds[MAX_FRONTEND_ROUTERS][MAX_WORKERS][2];
static int g_num_workers = 0;
char g_startup_cwd[PATH_MAX] = "";
int g_notify_ipc[2];
static int g_control_sock = -1;
static _Atomic(bool) g_frontend_alive = true;

time_t g_boot_time = 0;
time_t g_last_configured_time = 0;
_Atomic int g_xfers_running = ATOMIC_VAR_INIT(0);
_Atomic int g_tcp_clients = ATOMIC_VAR_INIT(0);
_Atomic int g_tcp_high_water = ATOMIC_VAR_INIT(0);

#define response_log_enabled(cfg) ((cfg) && (cfg)->logging.responses_channel != NULL)

static resp_log_entry_t g_resp_log_ring[RESP_LOG_RING_SIZE];
static _Atomic uint64_t g_resp_log_tail = ATOMIC_VAR_INIT(0);
static _Atomic uint64_t g_resp_log_head = ATOMIC_VAR_INIT(0);

static _Atomic bool g_qlog_circuit_broken = ATOMIC_VAR_INIT(false);
worker_ctx_t *g_worker_ctxs = NULL;
int g_worker_count = 0;

static inline uint32_t get_effective_query_log_max_qps(const server_config_t *cfg) {
    if (!cfg) return 0;
    // チャンネル側に 0 より大きい値が明示されている場合のみそれを採用
    if (cfg->logging.queries_channel && 
        cfg->logging.queries_channel->max_qps_specified && 
        cfg->logging.queries_channel->max_qps > 0) {
        return cfg->logging.queries_channel->max_qps;
    }
    // それ以外は options の query_log_max_qps を採用
    return cfg->query_log_max_qps;
}

void inc_tcp_clients(void) {
    int current = atomic_fetch_add_explicit(&g_tcp_clients, 1, memory_order_relaxed) + 1;
    int high = atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed);
    while (current > high) {
        if (atomic_compare_exchange_weak_explicit(&g_tcp_high_water, &high, current, memory_order_relaxed, memory_order_relaxed)) {
            break;
        }
    }
}
void dec_tcp_clients(void) {
    atomic_fetch_sub_explicit(&g_tcp_clients, 1, memory_order_relaxed);
}


// Broker
static int g_broker_sock = -1;
static pid_t g_broker_pid = -1;
static void start_connect_broker(void) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return;
  pid_t pid = fork();
  if (pid < 0) {
    close(sv[0]);
    close(sv[1]);
    return;
  }
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
        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
        int ret = connect(sock, (struct sockaddr *)&req.addr, addr_len);
        if (ret < 0 && errno == EINPROGRESS) {
          struct pollfd pfd = { .fd = sock, .events = POLLOUT };
          if (poll(&pfd, 1, 4000) > 0) {
            int so_error = 0;
            socklen_t elen = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &elen) == 0 && so_error == 0) {
              ret = 0;
            }
          }
        }
        if (ret == 0) {
          fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);
          struct msghdr msg = {0};
          struct cmsghdr *cmsg;
          char buf[CMSG_SPACE(sizeof(int))];
          memset(buf, 0, sizeof(buf));
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
    close(sv[1]);
    exit(0);
  }
  close(sv[1]);
  g_broker_sock = sv[0];
  g_broker_pid = pid;
  cap_rights_t broker_rights;
  cap_rights_init(&broker_rights, CAP_SEND, CAP_RECV, CAP_EVENT, CAP_FCNTL);
  cap_rights_limit(g_broker_sock, &broker_rights);
}

int broker_connect(int family, int type, struct sockaddr *addr,
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
  memset(buf, 0, sizeof(buf));
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

/* ip_port_t(文字列IP+ポート)を sockaddr_storage へ変換する共通ヘルパー。
 * 戻り値: 成功時 sockaddr の実サイズ(sizeof(sockaddr_in) 等)、
 *         IPアドレスとして解釈できなければ 0。 */
size_t resolve_ip_port_to_sockaddr(const char *ip, int port,
                                   struct sockaddr_storage *out) {
  memset(out, 0, sizeof(*out));
  if (inet_pton(AF_INET, ip, &((struct sockaddr_in *)out)->sin_addr) == 1) {
    out->ss_family = AF_INET;
    ((struct sockaddr_in *)out)->sin_port = htons(port > 0 ? port : 53);
    return sizeof(struct sockaddr_in);
  }
  if (inet_pton(AF_INET6, ip, &((struct sockaddr_in6 *)out)->sin6_addr) == 1) {
    out->ss_family = AF_INET6;
    ((struct sockaddr_in6 *)out)->sin6_port = htons(port > 0 ? port : 53);
    return sizeof(struct sockaddr_in6);
  }
  return 0;
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

zone_config_t *find_zone_config_in_view(server_config_t *cfg,
                                        const char *view_name,
                                        const char *domain) {
  if (!cfg || !domain) return NULL;
  if (cfg->views) {
    if (!view_name) return NULL;
    for (view_config_t *v = cfg->views; v; v = v->next) {
      if (strcasecmp(v->name, view_name) != 0) continue;
      for (zone_config_t *z = v->zones; z; z = z->next) {
        if (strcasecmp(z->domain, domain) == 0) return z;
      }
      return NULL;
    }
  } else {
    for (zone_config_t *z = cfg->zones; z; z = z->next) {
      if (strcasecmp(z->domain, domain) == 0) return z;
    }
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
        if (snap->views[sv].hash_size > 0 && snap->views[sv].hash_table) {
          uint32_t hash = calc_fnv1a_str(domain);
          size_t idx = hash & (snap->views[sv].hash_size - 1);
          for (int i = snap->views[sv].hash_table[idx]; i != -1; i = snap->views[sv].chain_next[i]) {
            if (strcasecmp(snap->views[sv].entries[i]->domain, domain) == 0) {
              entry = snap->views[sv].entries[i];
              break;
            }
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
    if (snap->views[v].hash_size > 0 && snap->views[v].hash_table) {
      uint32_t hash = calc_fnv1a_str(domain);
      size_t idx = hash & (snap->views[v].hash_size - 1);
      for (int i = snap->views[v].hash_table[idx]; i != -1; i = snap->views[v].chain_next[i]) {
        if (strcasecmp(snap->views[v].entries[i]->domain, domain) == 0) {
          return snap->views[v].entries[i];
        }
      }
    }
  }
  return NULL;
}

static inline uint32_t calc_fnv1a_strn(const char *str, size_t len) {
  uint32_t hash = 2166136261u;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = (uint8_t)str[i];
    if (c >= 'A' && c <= 'Z')
      c |= 0x20;
    hash ^= c;
    hash *= 16777619u;
  }
  return hash;
}

static zone_db_entry_t *view_suffix_hash_lookup(view_snapshot_t *view, const char *key, size_t key_len) {
  if (!view || !view->suffix_hash_table || !view->suffix_chain_next || view->suffix_hash_size == 0) {
    return NULL;
  }
  uint32_t hash = calc_fnv1a_strn(key, key_len);
  size_t idx = hash & (view->suffix_hash_size - 1);
  for (int i = view->suffix_hash_table[idx]; i != -1; i = view->suffix_chain_next[i]) {
    zone_db_entry_t *entry = view->entries[i];
    if (!entry) continue;
    size_t z_len = strlen(entry->domain);
    while (z_len > 0 && entry->domain[z_len - 1] == '.') z_len--;
    if (z_len == key_len && strncasecmp(entry->domain, key, key_len) == 0) {
      return entry;
    }
  }
  return NULL;
}

zone_db_entry_t *find_zone_in_view(view_snapshot_t *view, const char *qname) {
  if (!view || !qname) return NULL;
  if (!view->suffix_hash_table || !view->suffix_chain_next || view->suffix_hash_size == 0) {
    // Suffix hash table not built (e.g. manually constructed mock view in fuzzers/tests)
    // Fall back to linear scan
    size_t q_len = strlen(qname);
    while (q_len > 0 && qname[q_len - 1] == '.') q_len--;

    zone_db_entry_t *best_entry = NULL;
    size_t longest_match_len = 0;
    for (size_t i = 0; i < view->zone_count; i++) {
      zone_db_entry_t *entry = view->entries[i];
      if (!entry) continue;
      size_t z_len = strlen(entry->domain);
      while (z_len > 0 && entry->domain[z_len - 1] == '.') z_len--;

      bool match = false;
      if (z_len == 0 && (strcmp(entry->domain, ".") == 0 || entry->domain[0] == '\0')) {
        match = true;
      } else if (q_len == z_len && strncasecmp(qname, entry->domain, z_len) == 0) {
        match = true;
      } else if (q_len > z_len && qname[q_len - z_len - 1] == '.' &&
                 strncasecmp(qname + (q_len - z_len), entry->domain, z_len) == 0) {
        match = true;
      }
      if (match && (!best_entry || z_len > longest_match_len)) {
        longest_match_len = z_len;
        best_entry = entry;
      }
    }
    return best_entry;
  }

  size_t q_len = strlen(qname);
  while (q_len > 0 && qname[q_len - 1] == '.') q_len--;

  const char *cursor = qname;
  size_t remaining = q_len;
  while (remaining > 0) {
    zone_db_entry_t *hit = view_suffix_hash_lookup(view, cursor, remaining);
    if (hit) return hit;
    // 次のラベル境界まで進める（cursor内、remaining文字の範囲でドットを探す）
    const char *dot = memchr(cursor, '.', remaining);
    if (!dot) break;
    remaining -= (size_t)(dot - cursor) + 1;
    cursor = dot + 1;
  }
  // ルートゾーン（"." または空文字列）へのフォールバック
  return view_suffix_hash_lookup(view, "", 0);
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
  int stall_count = 0;
  int last_reader_count = -1;
  int total_seconds = 0;

  while (true) {
    int current_readers = atomic_load_explicit(&snap->reader_count, memory_order_acquire);
    if (current_readers <= 0) break;

    rcu_exponential_backoff(&retries, &sleep_time);

    // After exponential backoff maxes out at 100000us (0.1s), we check progress every 1s (10 retries)
    if (sleep_time >= 100000 && (retries % 10) == 0) {
      total_seconds++;
      syslog(LOG_WARNING, "[RCU] wait_for_snapshot_readers stalled (readers=%d, no_progress=%ds, total=%ds)",
             current_readers, stall_count, total_seconds);

      if (last_reader_count == current_readers) {
        stall_count++;
      } else {
        stall_count = 0; // Progress made
      }
      last_reader_count = current_readers;

#if defined(SANITIZER_BUILD)
      if (stall_count >= 10) {
        syslog(LOG_ERR, "[RCU] FATAL: reader_count leak detected (stalled > 10s with no progress). Aborting.");
        abort();
      }
      if (total_seconds >= 60) {
        syslog(LOG_ERR, "[RCU] FATAL: absolute timeout reached (60s). Aborting.");
        abort();
      }
#endif
    }
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

void wait_for_readers(zone_arena_t *arena) {
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
  for (int idx = 0; idx < MAX_IXFR_HISTORY; idx++) {
    ixfr_txn_t *txn = entry->ixfr_history.entries[idx];
    if (txn) {
      free_ixfr_txn(txn);
    }
  }
  zone_arena_destroy(&entry->rcu.arena_a);
  zone_arena_destroy(&entry->rcu.arena_b);
  free(entry);
}

static void *gc_snapshot_thread(void *arg) {
  zone_db_snapshot_t *snap = (zone_db_snapshot_t *)arg;
  if (!snap) return NULL;
  wait_for_snapshot_readers(snap);
  if (snap->views) {
    for (size_t v = 0; v < snap->view_count; v++) {
      if (snap->views[v].entries) {
        for (size_t i = 0; i < snap->views[v].zone_count; i++) {
          zone_db_entry_t *entry = snap->views[v].entries[i];
          if (entry) {
            if (atomic_fetch_sub_explicit(&entry->snapshot_refs, 1, memory_order_acq_rel) == 1) {
              syslog(LOG_INFO, "[GC] Freeing deleted zone '%s'", entry->domain);
              free_zone_db_entry(entry);
            }
          }
        }
        free(snap->views[v].entries);
      }
      if (snap->views[v].name) free(snap->views[v].name);
      if (snap->views[v].match_clients) {
        for (int i = 0; i < snap->views[v].match_clients_count; i++) {
          if (snap->views[v].match_clients[i]) free(snap->views[v].match_clients[i]);
        }
        free(snap->views[v].match_clients);
      }
      if (snap->views[v].hash_table) free(snap->views[v].hash_table);
      if (snap->views[v].chain_next) free(snap->views[v].chain_next);
      if (snap->views[v].suffix_hash_table) free(snap->views[v].suffix_hash_table);
      if (snap->views[v].suffix_chain_next) free(snap->views[v].suffix_chain_next);
    }
    free(snap->views);
  }
  free(snap);
  return NULL;
}




static char *server_load_file_cb(parse_context_t *ctx, const char *rel_path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
    int fd = open_via_dir_cache(rel_path, O_RDONLY | O_NOFOLLOW, 0, false);
    if (fd < 0) {
        return NULL;
    }
    
    if (out_dev || out_ino) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (out_dev) *out_dev = st.st_dev;
            if (out_ino) *out_ino = st.st_ino;
        } else {
            close(fd);
            return NULL; // fstat failed, fail-closed
        }
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

#define MAX_PRELINK_TARGETS 256
#define MAX_MATCH_RECS 32

void prelink_zone_additional_glue(zone_arena_t *current_zone,
                                         const char *zone_domain,
                                         zone_db_snapshot_t *snap,
                                         view_snapshot_t *view,
                                         additional_from_auth_t policy) {
  if (!current_zone || current_zone->count == 0 || !zone_domain || policy == ADDITIONAL_AUTH_NO) {
    if (current_zone) {
      current_zone->prelinked_glue = NULL;
      current_zone->prelinked_glue_count = 0;
    }
    return;
  }

  if (snap && !view) {
    for (size_t v = 0; v < snap->view_count; v++) {
      for (size_t i = 0; i < snap->views[v].zone_count; i++) {
        if (snap->views[v].entries[i] &&
            domain_names_match_ci(snap->views[v].entries[i]->domain, zone_domain)) {
          view = &snap->views[v];
          break;
        }
      }
      if (view) break;
    }
    if (!view && snap->view_count > 0) {
      view = &snap->views[0];
    }
  }

  const char *raw_targets[MAX_PRELINK_TARGETS];
  int raw_target_count = 0;

  for (size_t i = 0; i < current_zone->count; i++) {
    dns_record_t *rec = &current_zone->records[i];
    const char *tgt = NULL;
    if (rec->type_code == 2 && rec->rdata_count >= 1) {
      tgt = rec->rdata[0];
    } else if (rec->type_code == 15 && rec->rdata_count >= 2) {
      tgt = rec->rdata[1];
    } else if (rec->type_code == 33 && rec->rdata_count >= 4) {
      tgt = rec->rdata[3];
    }
    if (!tgt || *tgt == '\0') continue;

    bool dup = false;
    for (int k = 0; k < raw_target_count; k++) {
      if (domain_names_match_ci(raw_targets[k], tgt)) {
        dup = true;
        break;
      }
    }
    if (!dup && raw_target_count < MAX_PRELINK_TARGETS) {
      raw_targets[raw_target_count++] = tgt;
    }
  }

  if (raw_target_count == 0) {
    current_zone->prelinked_glue = NULL;
    current_zone->prelinked_glue_count = 0;
    return;
  }

  prelinked_glue_entry_t entries[MAX_PRELINK_TARGETS];
  int entry_count = 0;

  size_t z_len = strlen(zone_domain);
  while (z_len > 0 && zone_domain[z_len - 1] == '.') z_len--;

  for (int t = 0; t < raw_target_count; t++) {
    const char *tgt = raw_targets[t];
    size_t t_len = strlen(tgt);
    while (t_len > 0 && tgt[t_len - 1] == '.') t_len--;

    bool in_domain = false;
    if (t_len >= z_len) {
      if (strncasecmp(tgt + (t_len - z_len), zone_domain, z_len) == 0) {
        if (t_len == z_len || tgt[t_len - z_len - 1] == '.') {
          in_domain = true;
        }
      }
    }

    if (policy == ADDITIONAL_AUTH_IN_DOMAIN && !in_domain) {
      continue;
    }

    dns_record_t *found_recs[MAX_MATCH_RECS];
    int found_count = 0;

    // 1. Search current_zone first
    if (current_zone->hash_size > 0 && current_zone->hash_table) {
      uint32_t hashes[2];
      int h_count = 1;
      hashes[0] = calc_fnv1a_str(tgt);
      char alt_tgt[256];
      size_t raw_len = strlen(tgt);
      if (raw_len > 0 && tgt[raw_len - 1] == '.') {
        snprintf(alt_tgt, sizeof(alt_tgt), "%.*s", (int)(raw_len - 1), tgt);
        hashes[1] = calc_fnv1a_str(alt_tgt);
        h_count = 2;
      } else if (raw_len > 0 && raw_len + 1 < sizeof(alt_tgt)) {
        snprintf(alt_tgt, sizeof(alt_tgt), "%s.", tgt);
        hashes[1] = calc_fnv1a_str(alt_tgt);
        h_count = 2;
      }

      for (int h = 0; h < h_count; h++) {
        size_t idx = hashes[h] & (current_zone->hash_size - 1);
        for (int j = current_zone->hash_table[idx]; j != -1;
             j = current_zone->records[j].next_record) {
          dns_record_t *r = &current_zone->records[j];
          if ((r->type_code == 1 || r->type_code == 28) &&
              domain_names_match_ci(r->name, tgt)) {
            bool rdup = false;
            for (int f = 0; f < found_count; f++) {
              if (found_recs[f] == r) { rdup = true; break; }
            }
            if (!rdup && found_count < MAX_MATCH_RECS) {
              found_recs[found_count++] = r;
            }
          }
        }
      }
    }

    // 2. Search sibling authoritative zones in view if policy == ADDITIONAL_AUTH_YES
    if (policy == ADDITIONAL_AUTH_YES && view) {
      zone_db_entry_t *sib_entry = find_zone_in_view(view, tgt);
      if (sib_entry) {
        zone_arena_t *sib_arena = atomic_load_explicit(&sib_entry->rcu.active, memory_order_acquire);
        if (sib_arena && sib_arena != current_zone && sib_arena->hash_size > 0 && sib_arena->hash_table) {
          uint32_t hashes[2];
          int h_count = 1;
          hashes[0] = calc_fnv1a_str(tgt);
          char alt_tgt[256];
          size_t raw_len = strlen(tgt);
          if (raw_len > 0 && tgt[raw_len - 1] == '.') {
            snprintf(alt_tgt, sizeof(alt_tgt), "%.*s", (int)(raw_len - 1), tgt);
            hashes[1] = calc_fnv1a_str(alt_tgt);
            h_count = 2;
          } else if (raw_len > 0 && raw_len + 1 < sizeof(alt_tgt)) {
            snprintf(alt_tgt, sizeof(alt_tgt), "%s.", tgt);
            hashes[1] = calc_fnv1a_str(alt_tgt);
            h_count = 2;
          }
          for (int h = 0; h < h_count; h++) {
            size_t idx = hashes[h] & (sib_arena->hash_size - 1);
            for (int j = sib_arena->hash_table[idx]; j != -1;
                 j = sib_arena->records[j].next_record) {
              dns_record_t *r = &sib_arena->records[j];
              if ((r->type_code == 1 || r->type_code == 28) &&
                  domain_names_match_ci(r->name, tgt)) {
                bool rdup = false;
                for (int f = 0; f < found_count; f++) {
                  if (found_recs[f]->type_code == r->type_code &&
                      found_recs[f]->rdata_count == r->rdata_count) {
                    bool match_all = true;
                    for (int rc = 0; rc < r->rdata_count; rc++) {
                      if (strcasecmp(found_recs[f]->rdata[rc], r->rdata[rc]) != 0) {
                        match_all = false; break;
                      }
                    }
                    if (match_all) { rdup = true; break; }
                  }
                }
                if (!rdup && found_count < MAX_MATCH_RECS) {
                  found_recs[found_count++] = r;
                }
              }
            }
          }
        }
      }
    }

    if (found_count > 0) {
      dns_record_t **copied_recs = (dns_record_t **)arena_alloc(current_zone, found_count * sizeof(dns_record_t *));
      if (!copied_recs) continue;

      int copied_count = 0;
      for (int f = 0; f < found_count; f++) {
        dns_record_t *src_rec = found_recs[f];
        dns_record_t *d_rec = (dns_record_t *)arena_alloc(current_zone, sizeof(dns_record_t));
        if (!d_rec) break;
        *d_rec = *src_rec;
        d_rec->name = arena_strdup(current_zone, src_rec->name);
        d_rec->ttl = src_rec->ttl ? arena_strdup(current_zone, src_rec->ttl) : NULL;
        d_rec->class_str = src_rec->class_str ? arena_strdup(current_zone, src_rec->class_str) : NULL;
        d_rec->type = src_rec->type ? arena_strdup(current_zone, src_rec->type) : NULL;
        d_rec->ecs_subnet_tag = src_rec->ecs_subnet_tag ? arena_strdup(current_zone, src_rec->ecs_subnet_tag) : NULL;
        d_rec->bind_location_tag = src_rec->bind_location_tag ? arena_strdup(current_zone, src_rec->bind_location_tag) : NULL;
        for (int r = 0; r < src_rec->rdata_count && r < MAX_RDATA; r++) {
          d_rec->rdata[r] = src_rec->rdata[r] ? arena_strdup(current_zone, src_rec->rdata[r]) : NULL;
        }
        if (src_rec->generic_len > 0 && src_rec->generic_data) {
          d_rec->generic_data = (uint8_t *)arena_alloc(current_zone, src_rec->generic_len);
          if (d_rec->generic_data)
            memcpy(d_rec->generic_data, src_rec->generic_data, src_rec->generic_len);
        } else if (src_rec->generic_data) {
          d_rec->generic_data = (uint8_t *)"";
        } else {
          d_rec->generic_data = NULL;
        }
        d_rec->next_record = -1;
        d_rec->is_cached = false;
        dns_record_preparse_cache(current_zone, d_rec);
        copied_recs[copied_count++] = d_rec;
      }

      if (copied_count > 0) {
        entries[entry_count].target_name = arena_strdup(current_zone, tgt);
        entries[entry_count].records = copied_recs;
        entries[entry_count].record_count = copied_count;
        entry_count++;
      }
    }
  }

  if (entry_count > 0) {
    current_zone->prelinked_glue = (prelinked_glue_entry_t *)arena_alloc(current_zone, entry_count * sizeof(prelinked_glue_entry_t));
    if (current_zone->prelinked_glue) {
      memcpy(current_zone->prelinked_glue, entries, entry_count * sizeof(prelinked_glue_entry_t));
      current_zone->prelinked_glue_count = entry_count;
    } else {
      current_zone->prelinked_glue_count = 0;
    }
  } else {
    current_zone->prelinked_glue = NULL;
    current_zone->prelinked_glue_count = 0;
  }
}

static reload_result_t reload_master_zone(zone_db_entry_t *entry, zone_config_t *zcfg) {
  if (!entry || !zcfg || !zcfg->file) return RELOAD_ERR_FILE_READ;
  const char *file = zcfg->file;
  dev_t root_dev = 0;
  ino_t root_ino = 0;
  char *buf = read_entire_file(file, &root_dev, &root_ino);
  if (!buf) {
    syslog(LOG_ERR, "[Zone] Failed to read file '%s' for zone '%s'.", file, entry->domain);
    return RELOAD_ERR_FILE_READ;
  }
  pthread_mutex_lock(&entry->writer_lock);
  zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
  zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
  wait_for_readers(z_standby);

  zone_arena_free_include_buffers(z_standby);
  free(z_standby->locations);
  z_standby->locations = NULL;
  z_standby->location_count = 0;
  free_ecs_tags_array(z_standby->bind_location_tags, z_standby->bind_location_tag_count);
  z_standby->bind_location_tags = NULL;
  z_standby->bind_location_tag_count = 0;
  free_ecs_tags_array(z_standby->bind_ecs_tags, z_standby->bind_ecs_tag_count);
  z_standby->bind_ecs_tags = NULL;
  z_standby->bind_ecs_tag_count = 0;
  if (z_standby->bind_ecs_trusted_resolvers) {
    for (int i = 0; i < z_standby->bind_ecs_trusted_resolver_count; i++) {
      free(z_standby->bind_ecs_trusted_resolvers[i]);
    }
    free(z_standby->bind_ecs_trusted_resolvers);
    z_standby->bind_ecs_trusted_resolvers = NULL;
    z_standby->bind_ecs_trusted_resolver_count = 0;
  }
  z_standby->count = 0;
  z_standby->data_pool_count = 0;
  z_standby->current_pool_cap = 0;
  z_standby->current_pool_idx = 0;
  z_standby->file_buf_count = 0;
  z_standby->file_bufs[z_standby->file_buf_count] = buf;
  z_standby->file_paths[z_standby->file_buf_count] = strdup(file);
  z_standby->file_buf_count++;

  char *root_ttl = NULL;
  char *root_ecs_tag = NULL;
  char *root_loc_tag = NULL;
  char *visited_paths[16];
  dev_t visited_devs[16];
  ino_t visited_inos[16];
  
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
  if (!ctx.base_dir) {
      syslog(LOG_ERR, "[ZoneLoader] Out of memory allocating base_dir for zone '%s'", entry->domain);
      free(root_path);
      pthread_mutex_unlock(&entry->writer_lock);
      return RELOAD_ERR_PARSE;
  }
  ctx.is_standalone_mode = false;
  ctx.load_file_cb = server_load_file_cb;
  ctx.shared_ttl_io = &root_ttl;
  ctx.shared_ecs_tag_io = &root_ecs_tag;
  ctx.shared_loc_tag_io = &root_loc_tag;
  ctx.visited_paths = visited_paths;
  ctx.visited_devs = visited_devs;
  ctx.visited_inos = visited_inos;
  ctx.visited_cap = 16;
  ctx.visited_count = 1;
  ctx.visited_paths[0] = root_path;
  ctx.visited_devs[0] = root_dev;
  ctx.visited_inos[0] = root_ino;
  ctx.err_out = &parse_err;

  server_config_t *active_cfg = acquire_config_snapshot();
  const char *all_zone_ptrs[256];
  int all_zone_cnt = 0;
  if (active_cfg) {
      for (zone_config_t *zc = active_cfg->zones; zc; zc = zc->next) {
          if (zc->domain) {
              if (all_zone_cnt < 256) {
                  all_zone_ptrs[all_zone_cnt++] = zc->domain;
              } else {
                  syslog(LOG_WARNING, "[ZoneLoader] Configured zones exceed 256; parent-child delegation filtering may be degraded for '%s'", entry->domain);
                  break;
              }
          }
      }
  }
  ctx.all_zone_names = (all_zone_cnt > 0) ? all_zone_ptrs : NULL;
  ctx.all_zone_count = all_zone_cnt;

  int count;
  if (zcfg->file_format && strcasecmp(zcfg->file_format, "tinydns") == 0) {
      count = parse_tinydns_data(buf, strlen(buf), z_standby, &ctx);
  } else {
      count = parse_zone_fast(buf, strlen(buf), z_standby, &ctx);
  }
  release_config_snapshot(active_cfg);
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

  if (build_zone_index(z_standby, true) != 0) {
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
  if (validate_zone_name_lengths(z_standby, &parse_err) < 0) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Name length validation error reloading zone '%s' from '%s': %s",
             entry->domain, file, parse_err.error_message);
      return RELOAD_ERR_PARSE;
  }
  bool has_soa = false;
  uint32_t hash = calc_fnv1a_str(entry->domain);
  size_t idx = hash & (z_standby->hash_size - 1);
  for (int i = z_standby->hash_table[idx]; i != -1; i = z_standby->records[i].next_record) {
      if (z_standby->records[i].type_code == 6 && strcasecmp(z_standby->records[i].name, entry->domain) == 0) {
          has_soa = true;
          if (z_standby->records[i].rdata_count >= 7) {
              entry->serial = strtoul(z_standby->records[i].rdata[2], NULL, 10);
              entry->refresh = parse_ttl_value(z_standby->records[i].rdata[3]);
              entry->retry = parse_ttl_value(z_standby->records[i].rdata[4]);
              entry->expire = parse_ttl_value(z_standby->records[i].rdata[5]);
          }
          break;
      }
  }
  if (!has_soa) {
      pthread_mutex_unlock(&entry->writer_lock);
      syslog(LOG_ERR, "[Zone] Missing SOA reloading zone '%s' from '%s'", entry->domain, file);
      return RELOAD_ERR_MISSING_SOA;
  }

  zone_db_snapshot_t *cur_snap = acquire_zone_snapshot();
  server_config_t *active_cfg_prelink = acquire_config_snapshot();
  additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                      ? zcfg->additional_from_auth
                                      : (active_cfg_prelink ? active_cfg_prelink->additional_from_auth : ADDITIONAL_AUTH_YES);
  release_config_snapshot(active_cfg_prelink);
  prelink_zone_additional_glue(z_standby, entry->domain, cur_snap, NULL, policy);
  if (cur_snap) release_zone_snapshot(cur_snap);

  compute_ixfr_diff(entry, z_active, z_standby);
  atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
  struct stat st_loaded;
  if (stat_via_dir_cache(file, &st_loaded) == 0) {
    entry->last_loaded_mtime = st_loaded.st_mtime;
    if (entry->is_secondary) {
      atomic_store_explicit(&entry->last_successful_transfer, (time_t)st_loaded.st_mtime, memory_order_release);
    }
  }
  pthread_mutex_unlock(&entry->writer_lock);
  syslog(LOG_NOTICE, "[Zone] Reload successful for '%s'", entry->domain);
  return RELOAD_OK;
}

static void abort_rebuild_snapshot(zone_db_snapshot_t *new_snap, const char *reason) {
    syslog(LOG_ERR, "[Core] Memory allocation failed during snapshot rebuild (%s), aborting", reason);
    if (new_snap) {
        gc_snapshot_thread(new_snap);
    }
    pthread_mutex_unlock(&g_zone_db_rebuild_lock);
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
    if (!new_snap) {
        abort_rebuild_snapshot(NULL, "new_snap");
        return NULL;
    }
    
    if (active_config) {
        // MODE: Full Config Reload
        
        int max_valid_members = 0;
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (!entry) continue;
                    if (entry->catalog_member_count > 0) {
                        max_valid_members += entry->catalog_member_count;
                    }
                }
            }
        }
        catalog_member_id_t *valid_members = max_valid_members > 0 ? calloc(max_valid_members, sizeof(catalog_member_id_t)) : NULL;
        if (max_valid_members > 0 && !valid_members) {
            abort_rebuild_snapshot(new_snap, "valid_members");
            return NULL;
        }
        int valid_member_count = 0;
        
        if (old_snap) {
            for (size_t v = 0; v < old_snap->view_count; v++) {
                for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                    zone_db_entry_t *entry = old_snap->views[v].entries[i];
                    if (!entry) continue;
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
        if (view_count > 0) {
            new_snap->views = calloc(view_count, sizeof(view_snapshot_t));
            if (!new_snap->views) {
                if (valid_members) free(valid_members);
                abort_rebuild_snapshot(new_snap, "new_snap->views");
                return NULL;
            }
        }
        atomic_init(&new_snap->reader_count, 0);

        int vidx = 0;
        for (view_config_t *v = active_config->views; v; v = v->next, vidx++) {
            view_snapshot_t *vs = &new_snap->views[vidx];
            vs->name = strdup(v->name);
            vs->match_clients_count = v->match_clients_count;
            if (v->match_clients_count > 0) {
                vs->match_clients = calloc(v->match_clients_count, sizeof(char *));
                if (!vs->match_clients) {
                    if (valid_members) free(valid_members);
                    abort_rebuild_snapshot(new_snap, "vs->match_clients");
                    return NULL;
                }
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
                            if (!entry) continue;
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
            if (vs->zone_count > 0) {
                vs->entries = calloc(vs->zone_count, sizeof(zone_db_entry_t *));
                if (!vs->entries) {
                    if (valid_members) free(valid_members);
                    abort_rebuild_snapshot(new_snap, "vs->entries");
                    return NULL;
                }
            }
            
            int zidx = 0;
            for (zone_config_t *z = v->zones; z; z = z->next) {
                zone_db_entry_t *entry = NULL;
                if (old_snap) {
                    for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                        if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                            for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                                if (!old_snap->views[ov].entries[oi]) continue;
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
                    if (entry && z->type && (strcasecmp(z->type, "slave") == 0 || strcasecmp(z->type, "secondary") == 0)) {
                        entry->is_secondary = true;
                    }
                    if (entry && z->file) {
                        reload_master_zone(entry, z);
                    }
                }
                if (!entry) {
                    syslog(LOG_ERR, "[Core] Failed to allocate memory for zone '%s' in view '%s', skipping this zone this reload cycle",
                           z->domain, v->name);
                    continue;
                }
                vs->entries[zidx++] = entry;
            }

            if (old_snap) {
                for (size_t ov = 0; ov < old_snap->view_count; ov++) {
                    if (strcasecmp(old_snap->views[ov].name, v->name) == 0) {
                        for (size_t oi = 0; oi < old_snap->views[ov].zone_count; oi++) {
                            zone_db_entry_t *entry = old_snap->views[ov].entries[oi];
                            if (!entry) continue;
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
            vs->zone_count = zidx;
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
                        size_t old_cap = g_pending_coo_capacity;
                        size_t new_cap = old_cap == 0 ? 16 : old_cap * 2;
                        pending_coo_t *tmp = realloc(g_pending_coo, new_cap * sizeof(pending_coo_t));
                        if (!tmp) {
                            syslog(LOG_ERR, "[Catalog] Failed to allocate memory for g_pending_coo (domain=%s); skipping CoO tracking for this member", new_desired_members[i].domain);
                            continue;
                        }
                        g_pending_coo = tmp;
                        g_pending_coo_capacity = new_cap;
                        memset(&g_pending_coo[old_cap], 0, (new_cap - old_cap) * sizeof(pending_coo_t));
                    }
                    snprintf(g_pending_coo[g_pending_coo_count].domain, sizeof(g_pending_coo[0].domain), "%s", new_desired_members[i].domain);
                    snprintf(g_pending_coo[g_pending_coo_count].old_catalog, sizeof(g_pending_coo[0].old_catalog), "%s", catalog_entry_to_update->domain);
                    snprintf(g_pending_coo[g_pending_coo_count].new_catalog, sizeof(g_pending_coo[0].new_catalog), "%s", new_desired_members[i].coo_target);
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

        // Ephemeral hash table for catalog_entry_to_update->catalog_members
        int *cur_hash_table = NULL;
        int *cur_chain_next = NULL;
        size_t cur_hash_size = 0;
        int cur_count = catalog_entry_to_update->catalog_member_count;
        if (cur_count > 0 && catalog_entry_to_update->catalog_members) {
            size_t p = 256;
            while (p < (size_t)cur_count * 2) p <<= 1;
            cur_hash_size = p;
            cur_hash_table = malloc(cur_hash_size * sizeof(int));
            cur_chain_next = malloc(cur_count * sizeof(int));
            if (cur_hash_table && cur_chain_next) {
                for (size_t k = 0; k < cur_hash_size; k++) cur_hash_table[k] = -1;
                for (int j = 0; j < cur_count; j++) {
                    uint32_t h = calc_catalog_member_hash(catalog_entry_to_update->catalog_members[j].domain,
                                                          catalog_entry_to_update->catalog_members[j].unique_id);
                    size_t idx = h & (cur_hash_size - 1);
                    cur_chain_next[j] = cur_hash_table[idx];
                    cur_hash_table[idx] = j;
                }
            } else {
                if (cur_hash_table) { free(cur_hash_table); cur_hash_table = NULL; }
                if (cur_chain_next) { free(cur_chain_next); cur_chain_next = NULL; }
                cur_hash_size = 0;
            }
        }

        for (int i = 0; i < new_desired_count; i++) {
            bool found = false;
            if (cur_hash_table && cur_chain_next) {
                uint32_t h = calc_catalog_member_hash(new_desired_members[i].domain, new_desired_members[i].unique_id);
                size_t idx = h & (cur_hash_size - 1);
                for (int j = cur_hash_table[idx]; j != -1; j = cur_chain_next[j]) {
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
            } else {
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
        if (cur_hash_table) free(cur_hash_table);
        if (cur_chain_next) free(cur_chain_next);
        new_desired_count = filtered_count;

        // Ephemeral hash table for new_desired_members
        int *des_hash_table = NULL;
        int *des_chain_next = NULL;
        size_t des_hash_size = 0;
        if (new_desired_count > 0) {
            size_t p = 256;
            while (p < (size_t)new_desired_count * 2) p <<= 1;
            des_hash_size = p;
            des_hash_table = malloc(des_hash_size * sizeof(int));
            des_chain_next = malloc(new_desired_count * sizeof(int));
            if (des_hash_table && des_chain_next) {
                for (size_t k = 0; k < des_hash_size; k++) des_hash_table[k] = -1;
                for (int j = 0; j < new_desired_count; j++) {
                    uint32_t h = calc_catalog_member_hash(new_desired_members[j].domain, new_desired_members[j].unique_id);
                    size_t idx = h & (des_hash_size - 1);
                    des_chain_next[j] = des_hash_table[idx];
                    des_hash_table[idx] = j;
                }
            } else {
                if (des_hash_table) { free(des_hash_table); des_hash_table = NULL; }
                if (des_chain_next) { free(des_chain_next); des_chain_next = NULL; }
                des_hash_size = 0;
            }
        }

        for (int i = 0; i < catalog_entry_to_update->catalog_member_count; i++) {
            bool found = false;
            if (des_hash_table && des_chain_next) {
                uint32_t h = calc_catalog_member_hash(catalog_entry_to_update->catalog_members[i].domain,
                                                      catalog_entry_to_update->catalog_members[i].unique_id);
                size_t idx = h & (des_hash_size - 1);
                for (int j = des_hash_table[idx]; j != -1; j = des_chain_next[j]) {
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
            } else {
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
            }
            if (!found) {
                removed_members[removed_count++] = catalog_entry_to_update->catalog_members[i];
            }
        }
        if (des_hash_table) free(des_hash_table);
        if (des_chain_next) free(des_chain_next);

        zone_db_entry_t **new_entries = calloc(added_count > 0 ? added_count : 1, sizeof(zone_db_entry_t*));
        if (!new_entries) {
            free(added_members); free(removed_members); free(coo_evicted_members);
            abort_rebuild_snapshot(new_snap, "catalog new_entries");
            return NULL;
        }
        int actual_added_count = 0;
        for (int i = 0; i < added_count; i++) {
            zone_db_entry_t *entry = create_new_zone_entry(added_members[i].domain, catalog_view_name);
            if (!entry) {
                syslog(LOG_ERR, "[Catalog] Failed to allocate memory for member '%s' owned by %s, skipping",
                       added_members[i].domain, catalog_entry_to_update->domain);
                continue;
            }
            strncpy(entry->owning_catalog_domain, catalog_entry_to_update->domain, sizeof(entry->owning_catalog_domain) - 1);
            syslog(LOG_INFO, "[Catalog] Added new member '%s' (unique-id: %s) owned by %s", added_members[i].domain, added_members[i].unique_id, catalog_entry_to_update->domain);
            entry->is_catalog_member = true;
            entry->is_secondary = true;
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
            new_entries[actual_added_count++] = entry;
        }
        added_count = actual_added_count;

        new_snap->view_count = old_snap ? old_snap->view_count : 0;
        if (new_snap->view_count > 0) {
            new_snap->views = calloc(new_snap->view_count, sizeof(view_snapshot_t));
            if (!new_snap->views) {
                free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                abort_rebuild_snapshot(new_snap, "catalog new_snap->views");
                return NULL;
            }
            atomic_init(&new_snap->reader_count, 0);

            // Build ephemeral hash table for deleted members (removed + coo_evicted)
            int total_deleted = removed_count + coo_evicted_count;
            int *del_hash_table = NULL;
            int *del_chain_next = NULL;
            size_t del_hash_size = 0;
            if (total_deleted > 0) {
                size_t p = 256;
                while (p < (size_t)total_deleted * 2) p <<= 1;
                del_hash_size = p;
                del_hash_table = malloc(del_hash_size * sizeof(int));
                del_chain_next = malloc(total_deleted * sizeof(int));
                if (del_hash_table && del_chain_next) {
                    for (size_t k = 0; k < del_hash_size; k++) del_hash_table[k] = -1;
                    for (int j = 0; j < total_deleted; j++) {
                        const catalog_member_id_t *del = (j < removed_count) ? 
                            &removed_members[j] : &coo_evicted_members[j - removed_count];
                        uint32_t h = calc_catalog_member_hash(del->domain, del->unique_id);
                        size_t idx = h & (del_hash_size - 1);
                        del_chain_next[j] = del_hash_table[idx];
                        del_hash_table[idx] = j;
                    }
                } else {
                    if (del_hash_table) { free(del_hash_table); del_hash_table = NULL; }
                    if (del_chain_next) { free(del_chain_next); del_chain_next = NULL; }
                    del_hash_size = 0;
                }
            }

            for (size_t v = 0; v < old_snap->view_count; v++) {
                view_snapshot_t *vs = &new_snap->views[v];
                vs->name = strdup(old_snap->views[v].name);
                vs->match_clients_count = old_snap->views[v].match_clients_count;
                if (vs->match_clients_count > 0) {
                    vs->match_clients = calloc(vs->match_clients_count, sizeof(char *));
                    if (!vs->match_clients) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog vs->match_clients");
                        return NULL;
                    }
                    for (int i = 0; i < vs->match_clients_count; i++) {
                        vs->match_clients[i] = strdup(old_snap->views[v].match_clients[i]);
                    }
                }

                if (strcasecmp(vs->name, catalog_view_name) == 0) {
                    size_t max_zones = old_snap->views[v].zone_count + added_count;
                    vs->entries = calloc(max_zones > 0 ? max_zones : 1, sizeof(zone_db_entry_t *));
                    if (!vs->entries) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog vs->entries");
                        return NULL;
                    }
                    
                    int zidx = 0;
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        zone_db_entry_t *entry = old_snap->views[v].entries[i];
                        bool is_removed = false;
                        if (entry->is_catalog_member && del_hash_table && del_chain_next) {
                            uint32_t h = calc_catalog_member_hash(entry->domain, entry->catalog_member_unique_id);
                            size_t idx = h & (del_hash_size - 1);
                            for (int j = del_hash_table[idx]; j != -1; j = del_chain_next[j]) {
                                const catalog_member_id_t *del = (j < removed_count) ? 
                                    &removed_members[j] : &coo_evicted_members[j - removed_count];
                                if (strcasecmp(entry->domain, del->domain) == 0 &&
                                    strcmp(entry->catalog_member_unique_id, del->unique_id) == 0) {
                                    is_removed = true;
                                    break;
                                }
                            }
                        } else if (entry->is_catalog_member && total_deleted > 0) {
                            for (int j = 0; j < removed_count; j++) {
                                if (strcasecmp(entry->domain, removed_members[j].domain) == 0 &&
                                    strcmp(entry->catalog_member_unique_id, removed_members[j].unique_id) == 0) {
                                    is_removed = true; break;
                                }
                            }
                            if (!is_removed) {
                                for (int j = 0; j < coo_evicted_count; j++) {
                                    if (strcasecmp(entry->domain, coo_evicted_members[j].domain) == 0 &&
                                        strcmp(entry->catalog_member_unique_id, coo_evicted_members[j].unique_id) == 0) {
                                        is_removed = true; break;
                                    }
                                }
                            }
                        }
                        if (!is_removed) {
                            atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                            vs->entries[zidx++] = entry;
                        }
                    }
                    
                    for (int i = 0; i < added_count; i++) {
                        vs->entries[zidx++] = new_entries[i];
                    }
                    vs->zone_count = zidx;
                } else {
                    vs->zone_count = old_snap->views[v].zone_count;
                    vs->entries = calloc(vs->zone_count > 0 ? vs->zone_count : 1, sizeof(zone_db_entry_t *));
                    if (!vs->entries) {
                        if (del_hash_table) free(del_hash_table);
                        if (del_chain_next) free(del_chain_next);
                        free(added_members); free(removed_members); free(coo_evicted_members); free(new_entries);
                        abort_rebuild_snapshot(new_snap, "catalog other vs->entries");
                        return NULL;
                    }
                    for (size_t i = 0; i < old_snap->views[v].zone_count; i++) {
                        zone_db_entry_t *entry = old_snap->views[v].entries[i];
                        atomic_fetch_add_explicit(&entry->snapshot_refs, 1, memory_order_release);
                        vs->entries[i] = entry;
                    }
                }
            }
            if (del_hash_table) free(del_hash_table);
            if (del_chain_next) free(del_chain_next);
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

    for (size_t v = 0; v < new_snap->view_count; v++) {
        view_snapshot_t *vs = &new_snap->views[v];
        size_t p = 256;
        while (p < vs->zone_count * 2) p <<= 1;
        vs->hash_size = p;
        if (vs->hash_size > 0) {
            vs->hash_table = malloc(vs->hash_size * sizeof(int));
            if (vs->hash_table) {
                for (size_t i = 0; i < vs->hash_size; i++) vs->hash_table[i] = -1;
            }
        }
        if (vs->zone_count > 0) {
            vs->chain_next = malloc(vs->zone_count * sizeof(int));
            if (vs->chain_next) {
                for (size_t i = 0; i < vs->zone_count; i++) vs->chain_next[i] = -1;
            }
        }

        vs->suffix_hash_size = p;
        if (vs->suffix_hash_size > 0) {
            vs->suffix_hash_table = malloc(vs->suffix_hash_size * sizeof(int));
            if (vs->suffix_hash_table) {
                for (size_t i = 0; i < vs->suffix_hash_size; i++) vs->suffix_hash_table[i] = -1;
            }
        }
        if (vs->zone_count > 0) {
            vs->suffix_chain_next = malloc(vs->zone_count * sizeof(int));
            if (vs->suffix_chain_next) {
                for (size_t i = 0; i < vs->zone_count; i++) vs->suffix_chain_next[i] = -1;
            }
        }
        
        if ((vs->hash_size > 0 && !vs->hash_table) || (vs->zone_count > 0 && !vs->chain_next) ||
            (vs->suffix_hash_size > 0 && !vs->suffix_hash_table) || (vs->zone_count > 0 && !vs->suffix_chain_next)) {
            syslog(LOG_ERR, "[Core] Hash table allocation failed for view '%s', aborting snapshot rebuild", vs->name);
            void *gc_snapshot_thread(void *arg);
            gc_snapshot_thread(new_snap); // Clean up the new snapshot cleanly
            pthread_mutex_unlock(&g_zone_db_rebuild_lock);
            return NULL;
        }

        if (vs->hash_table && vs->chain_next) {
            for (size_t i = 0; i < vs->zone_count; i++) {
                if (!vs->entries[i]) continue;
                uint32_t hash = calc_fnv1a_str(vs->entries[i]->domain);
                size_t idx = hash & (vs->hash_size - 1);
                vs->chain_next[i] = vs->hash_table[idx];
                vs->hash_table[idx] = i;
            }
        }

        if (vs->suffix_hash_table && vs->suffix_chain_next) {
            for (size_t i = 0; i < vs->zone_count; i++) {
                if (!vs->entries[i]) continue;
                size_t z_len = strlen(vs->entries[i]->domain);
                while (z_len > 0 && vs->entries[i]->domain[z_len - 1] == '.') z_len--;
                uint32_t hash = calc_fnv1a_strn(vs->entries[i]->domain, z_len);
                size_t idx = hash & (vs->suffix_hash_size - 1);
                vs->suffix_chain_next[i] = vs->suffix_hash_table[idx];
                vs->suffix_hash_table[idx] = i;
            }
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

void rebuild_zone_db_from_config(server_config_t *config, bool skip_unchanged) {
    zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(config, NULL, NULL, NULL, NULL, 0);
    if (!new_snap) {
        syslog(LOG_ERR, "[Core] Failed to rebuild zone DB snapshot from config due to allocation failure. Reload aborted.");
        return;
    }

    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            zone_db_snapshot_t *snap = acquire_zone_snapshot();
            if (snap) {
                zone_db_entry_t *entry = snapshot_get_zone(snap, z->domain);
                if (entry && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                    struct stat st;
                    if (skip_unchanged && stat_via_dir_cache(z->file, &st) == 0 && entry->last_loaded_mtime != 0 && st.st_mtime == entry->last_loaded_mtime) {
                        syslog(LOG_DEBUG, "[Config] zone '%s' file unchanged (mtime match), skipping reload", z->domain);
                    } else {
                        reload_master_zone(entry, z);
                    }
                }
                release_zone_snapshot(snap);
            }
        }
    }

    for (view_config_t *v = config->views; v; v = v->next) {
        for (zone_config_t *z = v->zones; z; z = z->next) {
            if (z->is_catalog && z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
                zone_db_snapshot_t *snap = acquire_zone_snapshot();
                if (snap) {
                    zone_db_entry_t *entry = snapshot_get_zone(snap, z->domain);
                    if (entry) {
                        void catalog_process_membership(zone_db_entry_t *catalog_entry, zone_config_t *catalog_cfg, const char *view_name);
                        catalog_process_membership(entry, z, v->name);
                    }
                    release_zone_snapshot(snap);
                }
            }
        }
    }

    // Pass 2: Pre-link additional glue across authoritative zones in each view
    zone_db_snapshot_t *relink_snap = acquire_zone_snapshot();
    if (relink_snap) {
        for (size_t v = 0; v < relink_snap->view_count; v++) {
            view_snapshot_t *view = &relink_snap->views[v];
            for (size_t i = 0; i < view->zone_count; i++) {
                zone_db_entry_t *entry = view->entries[i];
                if (!entry) continue;
                pthread_mutex_lock(&entry->writer_lock);
                zone_arena_t *z_active = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
                if (z_active && z_active->count > 0) {
                    zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;
                    wait_for_readers(z_standby);
                    clone_zone_arena(z_active, z_standby);
                    build_zone_index(z_standby, true);
                    zone_config_t *zcfg = find_zone_config_in_view(config, view->name, entry->domain);
                    additional_from_auth_t policy = (zcfg && zcfg->additional_from_auth_specified)
                                                        ? zcfg->additional_from_auth
                                                        : (config ? config->additional_from_auth : ADDITIONAL_AUTH_YES);
                    prelink_zone_additional_glue(z_standby, entry->domain, relink_snap, view, policy);
                    atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
                }
                pthread_mutex_unlock(&entry->writer_lock);
            }
        }
        release_zone_snapshot(relink_snap);
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

void zone_arena_clear_data_pools(zone_arena_t *arena) {
  if (!arena) return;
  for (int i = 0; i < arena->data_pool_count; i++) {
    if (arena->data_pools[i]) {
      free(arena->data_pools[i]);
      arena->data_pools[i] = NULL;
    }
  }
  if (arena->nsec_records) {
    free(arena->nsec_records);
    arena->nsec_records = NULL;
    arena->nsec_count = 0;
  }
  if (arena->sorted_unique_names) {
    free(arena->sorted_unique_names);
    arena->sorted_unique_names = NULL;
    arena->sorted_unique_count = 0;
  }
  if (arena->locations) {
    free(arena->locations);
    arena->locations = NULL;
    arena->location_count = 0;
  }
  if (arena->bind_location_tags) {
    free_ecs_tags_array(arena->bind_location_tags, arena->bind_location_tag_count);
    arena->bind_location_tags = NULL;
    arena->bind_location_tag_count = 0;
  }
  if (arena->bind_ecs_tags) {
    free_ecs_tags_array(arena->bind_ecs_tags, arena->bind_ecs_tag_count);
    arena->bind_ecs_tags = NULL;
    arena->bind_ecs_tag_count = 0;
  }
  if (arena->bind_ecs_trusted_resolvers) {
    for (int i = 0; i < arena->bind_ecs_trusted_resolver_count; i++) {
      free(arena->bind_ecs_trusted_resolvers[i]);
    }
    free(arena->bind_ecs_trusted_resolvers);
    arena->bind_ecs_trusted_resolvers = NULL;
    arena->bind_ecs_trusted_resolver_count = 0;
  }
  arena->prelinked_glue = NULL;
  arena->prelinked_glue_count = 0;
  arena->count = 0;
  arena->data_pool_count = 0;
  arena->current_pool_cap = 0;
  arena->current_pool_idx = 0;
}

void clone_zone_arena(zone_arena_t *src, zone_arena_t *dst) {
  zone_arena_clear_data_pools(dst);
  dst->is_tinydns_format = src->is_tinydns_format;
  if (src->location_count > 0 && src->locations) {
    dst->locations = malloc(src->location_count * sizeof(tinydns_location_entry_t));
    if (dst->locations) {
      memcpy(dst->locations, src->locations, src->location_count * sizeof(tinydns_location_entry_t));
      dst->location_count = src->location_count;
    }
  }
  if (src->bind_location_tag_count > 0 && src->bind_location_tags) {
    dst->bind_location_tags = clone_ecs_tags_array(src->bind_location_tags, src->bind_location_tag_count);
    if (dst->bind_location_tags) {
      dst->bind_location_tag_count = src->bind_location_tag_count;
    }
  }
  if (src->bind_ecs_tag_count > 0 && src->bind_ecs_tags) {
    dst->bind_ecs_tags = clone_ecs_tags_array(src->bind_ecs_tags, src->bind_ecs_tag_count);
    if (dst->bind_ecs_tags) {
      dst->bind_ecs_tag_count = src->bind_ecs_tag_count;
    }
  }
  if (src->bind_ecs_trusted_resolver_count > 0 && src->bind_ecs_trusted_resolvers) {
    dst->bind_ecs_trusted_resolvers = malloc(src->bind_ecs_trusted_resolver_count * sizeof(char *));
    if (dst->bind_ecs_trusted_resolvers) {
      dst->bind_ecs_trusted_resolver_count = 0;
      for (int i = 0; i < src->bind_ecs_trusted_resolver_count; i++) {
        if (src->bind_ecs_trusted_resolvers[i]) {
          dst->bind_ecs_trusted_resolvers[dst->bind_ecs_trusted_resolver_count] = strdup(src->bind_ecs_trusted_resolvers[i]);
          if (dst->bind_ecs_trusted_resolvers[dst->bind_ecs_trusted_resolver_count]) {
            dst->bind_ecs_trusted_resolver_count++;
          }
        }
      }
    }
  }
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
    memset(d_rec, 0, sizeof(*d_rec));
    d_rec->name = arena_strdup(dst, s_rec->name);
    d_rec->ttl = s_rec->ttl ? arena_strdup(dst, s_rec->ttl) : NULL;
    d_rec->ttl_value = s_rec->ttl_value;
    d_rec->class_str =
        s_rec->class_str ? arena_strdup(dst, s_rec->class_str) : NULL;
    d_rec->class_val = s_rec->class_val;
    d_rec->type = s_rec->type ? arena_strdup(dst, s_rec->type) : NULL;
    d_rec->type_code = s_rec->type_code;
    d_rec->tinydns_ttd = s_rec->tinydns_ttd;
    d_rec->tinydns_ttl_countdown = s_rec->tinydns_ttl_countdown;
    d_rec->tinydns_loc[0] = s_rec->tinydns_loc[0];
    d_rec->tinydns_loc[1] = s_rec->tinydns_loc[1];
    d_rec->ecs_subnet_tag = s_rec->ecs_subnet_tag ? arena_strdup(dst, s_rec->ecs_subnet_tag) : NULL;
    d_rec->bind_location_tag = s_rec->bind_location_tag ? arena_strdup(dst, s_rec->bind_location_tag) : NULL;
    d_rec->rdata_count = s_rec->rdata_count;
    for (int j = 0; j < s_rec->rdata_count; j++)
      d_rec->rdata[j] = s_rec->rdata[j] ? arena_strdup(dst, s_rec->rdata[j]) : NULL;
    d_rec->generic_len = s_rec->generic_len;
    if (s_rec->generic_len > 0 && s_rec->generic_data) {
      d_rec->generic_data = (uint8_t *)arena_alloc(dst, s_rec->generic_len);
      if (d_rec->generic_data)
        memcpy(d_rec->generic_data, s_rec->generic_data, s_rec->generic_len);
    } else if (s_rec->generic_data) {
      d_rec->generic_data = (uint8_t *)"";
    } else {
      d_rec->generic_data = NULL;
    }
    d_rec->next_record = -1;
    d_rec->is_cached = false;
    dns_record_preparse_cache(dst, d_rec);
  }
}

const char *strchr_unescaped(const char *s, char c) {
  if (!s) return NULL;
  for (const char *p = s; *p != '\0'; p++) {
    if (*p == '\\') {
      if (*(p + 1) == '\0') {
        break; // Trailing backslash at end of string
      }
      p++; // Skip escaped character
      continue;
    }
    if (*p == c) {
      return p;
    }
  }
  return NULL;
}


// ============================================================================
// 9. AXFR専用バックグラウンドスレッド (Detached)


// ============================================================================
// 10. Logging
// ============================================================================

static void init_logging_channels(server_config_t *cfg) {
  uid_t target_uid = (uid_t)-1;
  gid_t target_gid = (gid_t)-1;
  if (geteuid() == 0 && cfg->user) {
    struct passwd *pwd = getpwnam(cfg->user);
    if (pwd) {
      target_uid = pwd->pw_uid;
      target_gid = pwd->pw_gid;
      if (cfg->group) {
        struct group *grp = getgrnam(cfg->group);
        if (grp) target_gid = grp->gr_gid;
      }
    }
  }

  log_channel_t *ch = cfg->logging.channels;
  while (ch) {
    if (ch->file_path) {
      if (geteuid() == 0) {
        char dirbuf[PATH_MAX], basebuf[PATH_MAX];
        if (split_path_for_openat(ch->file_path, dirbuf, sizeof(dirbuf), basebuf, sizeof(basebuf))) {
          if (dirbuf[0] != '\0' && strcmp(dirbuf, ".") != 0) {
            struct stat d_st;
            if (stat(dirbuf, &d_st) != 0) {
              mkdir(dirbuf, 0755);
            }
            if (target_uid != (uid_t)-1 &&
                strcmp(dirbuf, "/") != 0 && strcmp(dirbuf, "/var") != 0 &&
                strcmp(dirbuf, "/var/log") != 0 && strcmp(dirbuf, "/tmp") != 0 &&
                strcmp(dirbuf, "/etc") != 0) {
              chown(dirbuf, target_uid, target_gid);
            }
          }
        }
      }

      ch->fd = open_via_dir_cache(ch->file_path, O_WRONLY | O_CREAT | O_APPEND,
                                  0644, true);
      if (ch->fd >= 0) {
        if (geteuid() == 0 && target_uid != (uid_t)-1) {
          fchown(ch->fd, target_uid, target_gid);
        }
        struct stat st;
        if (fstat(ch->fd, &st) == 0)
          ch->current_size = st.st_size;
      } else {
        syslog(LOG_ERR, "[Logging] Failed to open log file '%s': %m", ch->file_path);
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


void submit_response_log(log_action_t action, const char *client_ip, int client_port, const char *qname, 
                                uint16_t qclass, uint16_t qtype, uint8_t rcode, 
                                bool has_edns, bool dnssec_ok) {
    server_config_t *cfg = acquire_config_snapshot();
    if (!cfg) return;
    bool enabled = (cfg->logging.responses_channel != NULL);
    release_config_snapshot(cfg);
    if (!enabled) return;

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
static void escape_qname_for_log(const char *src, char *dst, size_t dst_size) {
  if (!dst || dst_size == 0) return;
  if (!src) {
    dst[0] = '\0';
    return;
  }

  size_t di = 0;
  for (size_t si = 0; src[si] != '\0' && di + 4 < dst_size; si++) {
    uint8_t c = (uint8_t)src[si];
    if (c >= 0x21 && c <= 0x7E && c != '\\' && c != '"' && c != ';') {
      dst[di++] = (char)c;
    } else if (c == '\\') {
      dst[di++] = '\\';
      dst[di++] = '\\';
    } else if (c == '"') {
      dst[di++] = '\\';
      dst[di++] = '"';
    } else {
      // 改行(\n, \r)、タブ、スペース、制御文字、非ASCII文字を RFC 1035 §5.1 / BIND互換の \DDD 形式にエスケープ
      int n = snprintf(&dst[di], dst_size - di, "\\%03u", c);
      if (n > 0) {
          if ((size_t)n < dst_size - di) {
              di += (size_t)n;
          } else {
              di = dst_size - 1;
          }
      }
    }
  }
  dst[di < dst_size ? di : dst_size - 1] = '\0';
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
        int old_fd = ch->fd;
        int reopen_flags = O_WRONLY | O_CREAT | O_APPEND;
        bool rotate_rename_failed = false;

        if (ch->suffix_timestamp) {
            char new_name[600];
            int r = snprintf(new_name, sizeof(new_name), "%s.%08d", ch->file_path, ch->current_date);
            if (r > 0 && r < (int)sizeof(new_name)) {
                if (renameat_via_dir_cache(ch->file_path, new_name) != 0) {
                    rotate_rename_failed = true;
                    syslog(LOG_ERR, "[Logging] Failed to rotate log file '%s' to '%s': %m", ch->file_path, new_name);
                }
            }
        } else if (ch->versions > 0) {
            for (int i = ch->versions - 1; i >= 0; i--) {
                char old_name[600], new_name[600];
                int r1 = (i == 0)
                             ? snprintf(old_name, sizeof(old_name), "%s", ch->file_path)
                             : snprintf(old_name, sizeof(old_name), "%s.%d", ch->file_path, i - 1);
                int r2 = snprintf(new_name, sizeof(new_name), "%s.%d", ch->file_path, i);
                if (r1 > 0 && r2 > 0) {
                    if (renameat_via_dir_cache(old_name, new_name) != 0 && i == 0) {
                        rotate_rename_failed = true;
                        syslog(LOG_ERR, "[Logging] Failed to rotate active log file '%s' to '%s': %m", old_name, new_name);
                    }
                }
            }
        } else {
            reopen_flags |= O_TRUNC;
        }

        if (!rotate_rename_failed || (reopen_flags & O_TRUNC)) {
            if (old_fd >= 0) close(old_fd);
            ch->fd = open_via_dir_cache(ch->file_path, reopen_flags, 0644, true);
            if (ch->fd >= 0) {
                struct stat st;
                ch->current_size = (fstat(ch->fd, &st) == 0) ? st.st_size : 0;
                ch->current_date = today;
            } else {
                syslog(LOG_ERR, "[Logging] Failed to reopen log file '%s' after rotation: %m", ch->file_path);
                ch->current_size = 0;
            }
        } else {
            // リネーム失敗時: 古いFDが有効であれば維持してログ欠損を防ぎ、実ファイルサイズと同期
            if (old_fd >= 0) {
                struct stat st;
                if (fstat(old_fd, &st) == 0)
                    ch->current_size = st.st_size;
            } else {
                ch->fd = open_via_dir_cache(ch->file_path, O_WRONLY | O_APPEND, 0644, true);
                if (ch->fd >= 0) {
                    struct stat st;
                    if (fstat(ch->fd, &st) == 0)
                        ch->current_size = st.st_size;
                }
            }
        }
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
            server_config_t *cfg = acquire_config_snapshot();
            
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
                else if (entry->qclass == 3) snprintf(class_str, sizeof(class_str), "CH");
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

                char safe_qname[512];
                escape_qname_for_log(entry->qname, safe_qname, sizeof(safe_qname));

                char log_buf[1024];
                int len = snprintf(log_buf, sizeof(log_buf), 
                                   "%s%s%sclient %s#%d (%s): response: %s %s %s %s -> %s%s\n", 
                                   time_str,
                                   ch->print_category ? "responses: " : "",
                                   ch->print_severity ? "info: " : "", 
                                   entry->client_ip, entry->client_port,
                                   safe_qname, safe_qname, class_str, type_str_tmp, edns_str, rcode_str, action_str);
                
                if (len > 0) {
                    if (len >= (int)sizeof(log_buf)) len = sizeof(log_buf) - 1;
                    log_write_rotated(ch, log_buf, len, &tm_info);
                }
            }
            release_config_snapshot(cfg);
            
            // Consumerのポインタを進める
            atomic_store_explicit(&entry->ready, false, memory_order_release);
            atomic_fetch_add_explicit(&g_resp_log_head, 1, memory_order_release);
        } else {
            usleep(1000); // データ未着時は1msスリープしてCPU負荷を下げる
        }
    }
    return NULL;
}

static inline void write_query_log(worker_ctx_t *ctx,
                                   const struct sockaddr_storage *client_addr,
                                   socklen_t addr_len,
                                   const char *qname, uint16_t qclass, uint16_t qtype,
                                   bool has_edns, bool dnssec_ok, uint8_t protocol,
                                   uint32_t max_qps) {
    if (!ctx) return;

    // 1. サーキットブレーカーが発動している場合は1命令で完全スキップ
    if (__builtin_expect(atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed), 0)) {
        return;
    }

    // 2. max_qps による即時レートリミット (max_qps が 0 の場合でも暴走防止のためデフォルト5000で制限)
    uint32_t limit = (max_qps > 0) ? max_qps : 5000;
    time_t now_sec = time(NULL);
    if (ctx->log_current_sec != now_sec) {
        ctx->log_current_sec = now_sec;
        ctx->log_emitted_this_sec = 0;
    }
    uint32_t quota = (limit >= (uint32_t)g_worker_count && g_worker_count > 0)
                     ? (limit / g_worker_count) : 1;
    if (ctx->log_emitted_this_sec >= quota) {
        // 閾値超過: リングバッファ操作やメモリコピーを一切行わず即座にリターン
        return;
    }
    ctx->log_emitted_this_sec++;

    // 3. リングバッファへのプッシュ
    qlog_ring_t *ring = &ctx->qlog_ring;
    if (!ring->events) return;

    uint32_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint32_t t = atomic_load_explicit(&ring->tail, memory_order_acquire);

    // バッファが80%以上埋まったら即座にブレーカーを発動させてクエリスレッドを保護
    if (h - t >= (ring->size * 8 / 10)) {
        atomic_store_explicit(&g_qlog_circuit_broken, true, memory_order_relaxed);
        atomic_fetch_add_explicit(&ring->dropped_count, 1, memory_order_relaxed);
        return;
    }

    uint32_t idx = h & ring->mask;
    qlog_event_t *ev = &ring->events[idx];

#ifdef CLOCK_REALTIME_FAST
    clock_gettime(CLOCK_REALTIME_FAST, &ev->ts);
#else
    clock_gettime(CLOCK_REALTIME, &ev->ts);
#endif

    if (client_addr) {
        memcpy(&ev->client_addr, client_addr, sizeof(struct sockaddr_storage));
    } else {
        memset(&ev->client_addr, 0, sizeof(struct sockaddr_storage));
    }
    ev->addr_len = addr_len;
    ev->qtype = qtype;
    ev->qclass = qclass;
    ev->rcode = 0;
    ev->flags = 0;
    ev->protocol = protocol;
    ev->has_edns = has_edns;
    ev->dnssec_ok = dnssec_ok;

    if (qname) {
        strlcpy(ev->qname, qname, sizeof(ev->qname));
    } else {
        ev->qname[0] = '\0';
    }

    atomic_store_explicit(&ring->head, h + 1, memory_order_release);
}

void *query_logger_thread_func(void *arg) {
    (void)arg;
    static char batch_buf[65536];
    size_t batch_len = 0;
    struct tm batch_tm;
    memset(&batch_tm, 0, sizeof(batch_tm));

    time_t cached_sec = 0;
    char cached_time_prefix[64] = "";
    struct tm cached_tm;
    memset(&cached_tm, 0, sizeof(cached_tm));

    time_t last_drop_report_time = time(NULL);
    uint64_t last_reported_dropped = 0;

    while (1) {
        server_config_t *cfg = acquire_config_snapshot();
        log_channel_t *ch = (cfg && cfg->logging.queries_channel) ? cfg->logging.queries_channel : NULL;

        int num_workers = g_worker_count;
        worker_ctx_t *workers = g_worker_ctxs;
        bool any_work = false;

        if (ch && num_workers > 0 && workers) {
            for (int w = 0; w < num_workers; w++) {
                qlog_ring_t *ring = &workers[w].qlog_ring;
                if (!ring->events) continue;

                uint32_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
                uint32_t h = atomic_load_explicit(&ring->head, memory_order_acquire);

                while (t != h) {
                    qlog_event_t *ev = &ring->events[t & ring->mask];
                    any_work = true;

                    // 時刻キャッシュ (秒単位でフォーマットし、ミリ秒のみ追記)
                    if (ev->ts.tv_sec != cached_sec) {
                        cached_sec = ev->ts.tv_sec;
                        localtime_r(&cached_sec, &cached_tm);
                        strftime(cached_time_prefix, sizeof(cached_time_prefix), "%d-%b-%Y %H:%M:%S", &cached_tm);
                        batch_tm = cached_tm;
                    }

                    char time_str[64] = "";
                    if (ch->print_time) {
                        snprintf(time_str, sizeof(time_str), "%s.%03ld ", cached_time_prefix,
                                 ev->ts.tv_nsec / 1000000);
                    }

                    char class_str[16];
                    if (ev->qclass == 1)
                        snprintf(class_str, sizeof(class_str), "IN");
                    else if (ev->qclass == 255)
                        snprintf(class_str, sizeof(class_str), "ANY");
                    else if (ev->qclass == 3)
                        snprintf(class_str, sizeof(class_str), "CH");
                    else
                        snprintf(class_str, sizeof(class_str), "CLASS%d", ev->qclass);

                    char type_str[32];
                    const char *type_str_tmp = format_type_name(ev->qtype, type_str, sizeof(type_str));

                    char edns_str[16] = "";
                    if (ev->has_edns)
                        snprintf(edns_str, sizeof(edns_str), "+E(0)%s", ev->dnssec_ok ? "D" : "K");

                    char safe_qname[512];
                    escape_qname_for_log(ev->qname, safe_qname, sizeof(safe_qname));

                    char client_ip[INET6_ADDRSTRLEN] = "unknown";
                    int client_port = 0;
                    if (ev->client_addr.ss_family == AF_INET) {
                        struct sockaddr_in *sin = (struct sockaddr_in *)&ev->client_addr;
                        inet_ntop(AF_INET, &sin->sin_addr, client_ip, sizeof(client_ip));
                        client_port = ntohs(sin->sin_port);
                    } else if (ev->client_addr.ss_family == AF_INET6) {
                        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ev->client_addr;
                        inet_ntop(AF_INET6, &sin6->sin6_addr, client_ip, sizeof(client_ip));
                        client_port = ntohs(sin6->sin6_port);
                    }

                    char line_buf[1024];
                    int len = snprintf(line_buf, sizeof(line_buf),
                                       "%s%s%sclient %s#%d (%s): query: %s %s %s %s\n", time_str,
                                       ch->print_category ? "queries: " : "",
                                       ch->print_severity ? "info: " : "", client_ip, client_port,
                                       safe_qname, safe_qname, class_str, type_str_tmp, edns_str);

                    if (len > 0) {
                        if (len >= (int)sizeof(line_buf)) len = sizeof(line_buf) - 1;
                        if (batch_len + len > sizeof(batch_buf)) {
                            log_write_rotated(ch, batch_buf, (int)batch_len, &batch_tm);
                            batch_len = 0;
                        }
                        memcpy(batch_buf + batch_len, line_buf, len);
                        batch_len += len;
                    }

                    t++;
                }

                atomic_store_explicit(&ring->tail, t, memory_order_release);
            }

            if (batch_len > 0) {
                log_write_rotated(ch, batch_buf, (int)batch_len, &batch_tm);
                batch_len = 0;
            }

            // サーキットブレーカー自動復帰判定 (リングバッファ滞留率10%未満)
            bool all_empty = true;
            for (int w = 0; w < num_workers; w++) {
                uint32_t t = atomic_load_explicit(&workers[w].qlog_ring.tail, memory_order_relaxed);
                uint32_t h = atomic_load_explicit(&workers[w].qlog_ring.head, memory_order_relaxed);
                if (h - t > (workers[w].qlog_ring.size / 10)) {
                    all_empty = false;
                    break;
                }
            }
            if (all_empty && atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed)) {
                atomic_store_explicit(&g_qlog_circuit_broken, false, memory_order_release);
            }

            // 定期的なドロップ統計レポート (5秒間隔)
            time_t now = time(NULL);
            if (now - last_drop_report_time >= 5) {
                last_drop_report_time = now;
                uint64_t total_dropped = 0;
                for (int w = 0; w < num_workers; w++) {
                    total_dropped += atomic_load_explicit(&workers[w].qlog_ring.dropped_count, memory_order_relaxed);
                }
                if (total_dropped > last_reported_dropped) {
                    uint64_t diff = total_dropped - last_reported_dropped;
                    last_reported_dropped = total_dropped;
                    syslog(LOG_WARNING, "[QueryLog] Dropped %" PRIu64 " queries due to ring buffer overflow (high load)", diff);
                }
            }
        } else if (num_workers > 0 && workers) {
            // クエリロギング未設定時はエントリを破棄してCPU消費を防ぐ
            for (int w = 0; w < num_workers; w++) {
                qlog_ring_t *ring = &workers[w].qlog_ring;
                if (!ring->events) continue;
                uint32_t h = atomic_load_explicit(&ring->head, memory_order_relaxed);
                atomic_store_explicit(&ring->tail, h, memory_order_relaxed);
            }
        }

        if (cfg) release_config_snapshot(cfg);

        // 常に数ミリ秒休止してワーカースレッドにCPUを完全に明け渡す
        usleep(any_work ? 1000 : 10000);
    }
    return NULL;
}

static void fill_observatory_snapshot(const zone_db_entry_t *e, server_config_t *cfg, zone_observatory_snapshot_t *out) {
    if (!e || !out) return;
    strlcpy(out->domain, e->domain, sizeof(out->domain));
    strlcpy(out->view_name, e->view_name, sizeof(out->view_name));
    out->is_secondary = e->is_secondary;
    out->soa_serial = (uint32_t)atomic_load_explicit(&e->serial, memory_order_relaxed);

    zone_config_t *zc = find_zone_config_in_view(cfg, e->view_name, e->domain);
    out->slaves_configured = zc ? zc->also_notify_count : 0;

    out->last_notify_time = atomic_load_explicit(&e->observatory.last_notify_time, memory_order_relaxed);
    out->last_transfer_time = atomic_load_explicit(&e->observatory.last_transfer_time, memory_order_relaxed);
    if (out->last_transfer_time == 0) {
        out->last_transfer_time = atomic_load_explicit(&e->last_successful_transfer, memory_order_relaxed);
    }

    out->queries_total = atomic_load_explicit(&e->observatory.queries_total, memory_order_relaxed);
    out->tcp_queries = atomic_load_explicit(&e->observatory.tcp_queries, memory_order_relaxed);
    out->responses_noerror = atomic_load_explicit(&e->observatory.responses_noerror, memory_order_relaxed);
    out->responses_nxdomain = atomic_load_explicit(&e->observatory.responses_nxdomain, memory_order_relaxed);
    out->responses_nodata = atomic_load_explicit(&e->observatory.responses_nodata, memory_order_relaxed);
    out->responses_servfail = atomic_load_explicit(&e->observatory.responses_servfail, memory_order_relaxed);
    out->responses_refused = atomic_load_explicit(&e->observatory.responses_refused, memory_order_relaxed);
    out->edns_queries = atomic_load_explicit(&e->observatory.edns_queries, memory_order_relaxed);
    out->dnssec_do_queries = atomic_load_explicit(&e->observatory.dnssec_do_queries, memory_order_relaxed);
    out->ecs_queries = atomic_load_explicit(&e->observatory.ecs_queries, memory_order_relaxed);
    out->rrl_dropped = atomic_load_explicit(&e->observatory.rrl_dropped, memory_order_relaxed);
    out->rrl_slipped = atomic_load_explicit(&e->observatory.rrl_slipped, memory_order_relaxed);
    out->notify_sent = atomic_load_explicit(&e->observatory.notify_sent, memory_order_relaxed);
    out->notify_ack = atomic_load_explicit(&e->observatory.notify_ack, memory_order_relaxed);
    out->axfr_success = atomic_load_explicit(&e->observatory.axfr_success, memory_order_relaxed);
    out->ixfr_success = atomic_load_explicit(&e->observatory.ixfr_success, memory_order_relaxed);
}

// ============================================================================
// 11. TCP & Worker Threads (サンドボックス内)
// ============================================================================

ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len) {
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

#define ASYNC_IO_POOL_SIZE 16
#define ASYNC_IO_QUEUE_CAPACITY 4096

typedef struct {
  bool is_tcp;
  int active_fd; // For UDP, IPC socket to frontend
  int client_fd; // For TCP, client socket
  udp_ipc_t ipc_hdr;
  uint8_t req_buf[UDP_DEFAULT_MAX_RES_LEN];
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

static async_io_pool_t g_async_io_pool;

static bool enqueue_async_io_task(const async_io_task_t *task) {
  pthread_mutex_lock(&g_async_io_pool.lock);
  if (!g_async_io_pool.running || g_async_io_pool.count >= ASYNC_IO_QUEUE_CAPACITY) {
    pthread_mutex_unlock(&g_async_io_pool.lock);
    return false;
  }
  g_async_io_pool.queue[g_async_io_pool.tail] = *task;
  g_async_io_pool.tail = (g_async_io_pool.tail + 1) % ASYNC_IO_QUEUE_CAPACITY;
  g_async_io_pool.count++;
  pthread_cond_signal(&g_async_io_pool.cond_not_empty);
  pthread_mutex_unlock(&g_async_io_pool.lock);
  return true;
}

static void *async_io_worker_func(void *arg) {
  (void)arg;
  compress_ctx_t thread_compress_ctx = {0};
  while (1) {
    pthread_mutex_lock(&g_async_io_pool.lock);
    while (g_async_io_pool.running && g_async_io_pool.count == 0) {
      pthread_cond_wait(&g_async_io_pool.cond_not_empty, &g_async_io_pool.lock);
    }
    if (!g_async_io_pool.running && g_async_io_pool.count == 0) {
      pthread_mutex_unlock(&g_async_io_pool.lock);
      break;
    }
    async_io_task_t task = g_async_io_pool.queue[g_async_io_pool.head];
    g_async_io_pool.head = (g_async_io_pool.head + 1) % ASYNC_IO_QUEUE_CAPACITY;
    g_async_io_pool.count--;
    pthread_mutex_unlock(&g_async_io_pool.lock);

    if (!task.is_tcp) {
      // UDP async resolution
      uint8_t res_buf_full[BUFFER_SIZE + sizeof(udp_ipc_t)];
      uint8_t *res_buf = res_buf_full + sizeof(udp_ipc_t);
      rate_limit_config_t *rrl_cfg = NULL;
      int res_len = process_dns_query(task.req_buf, task.req_len, res_buf, UDP_DEFAULT_MAX_RES_LEN,
                                      task.qname, task.qtype, task.client_ip,
                                      &thread_compress_ctx, false, &rrl_cfg, task.snap);
      release_zone_snapshot(task.snap);

      if (res_len > 0) {
        bool slip_triggered = false;
        rrl_response_class_t cls = get_rrl_class(res_buf, res_len);
        if (rrl_check((struct sockaddr_storage *)&task.ipc_hdr.client_addr, cls, rrl_cfg, &slip_triggered)) {
          submit_response_log(LOG_ACT_SENT, task.client_ip, task.client_port, task.qname, task.qclass, task.qtype,
                              res_buf[3] & 0x0F, task.has_edns, task.dnssec_ok);
          write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res_buf, res_len,
                             &task.client_addr, task.client_len,
                             task.has_server_addr ? &task.server_addr : NULL, task.has_server_addr, IPPROTO_UDP);
          udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
          *res_msg = task.ipc_hdr;
          res_msg->payload_len = res_len;
          send(task.active_fd, res_buf_full, sizeof(udp_ipc_t) + res_len, 0);
        } else if (slip_triggered) {
          submit_response_log(LOG_ACT_SENT, task.client_ip, task.client_port, task.qname, task.qclass, task.qtype,
                              res_buf[3] & 0x0F, task.has_edns, task.dnssec_ok);
          res_buf[2] |= 0x02; // Set TC bit
          res_buf[6] = 0; res_buf[7] = 0;
          res_buf[8] = 0; res_buf[9] = 0;
          res_buf[10] = 0; res_buf[11] = 0;
          int qlen = (int)task.question_end;
          if (qlen > res_len) qlen = res_len;
          if (qlen > (int)task.req_len) qlen = (int)task.req_len;
          write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res_buf, qlen,
                             &task.client_addr, task.client_len,
                             task.has_server_addr ? &task.server_addr : NULL, task.has_server_addr, IPPROTO_UDP);
          udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
          *res_msg = task.ipc_hdr;
          res_msg->payload_len = qlen;
          send(task.active_fd, res_buf_full, sizeof(udp_ipc_t) + qlen, 0);
        } else {
          submit_response_log(LOG_ACT_DROP_RRL, task.client_ip, task.client_port, task.qname,
                              task.qclass, task.qtype, res_buf[3] & 0x0F, task.has_edns, task.dnssec_ok);
        }
      } else {
        submit_response_log(LOG_ACT_DROP_MALFORMED, task.client_ip, task.client_port, "<malformed>",
                            0, 0, 0, false, false);
      }
    } else {
      // TCP async resolution
      uint8_t *tcp_res = malloc(65535);
      if (tcp_res) {
        int res_len = process_dns_query(task.req_buf, task.req_len, tcp_res, 65535,
                                        task.qname, task.qtype, task.client_ip,
                                        &thread_compress_ctx, true, NULL, task.snap);
        release_zone_snapshot(task.snap);
        if (res_len > 0) {
          submit_response_log(LOG_ACT_SENT, task.client_ip, task.client_port, task.qname, task.qclass, task.qtype,
                              tcp_res[3] & 0x0F, task.has_edns, task.dnssec_ok);
          write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, tcp_res, res_len,
                             &task.client_addr, task.client_len,
                             task.has_server_addr ? &task.server_addr : NULL, task.has_server_addr, IPPROTO_TCP);
          uint8_t len_prefix[2] = {res_len >> 8, res_len & 0xFF};
          send_tcp_robust(task.client_fd, len_prefix, 2);
          send_tcp_robust(task.client_fd, tcp_res, res_len);
        } else {
          submit_response_log(LOG_ACT_DROP_MALFORMED, task.client_ip, task.client_port, "<malformed>",
                              0, 0, 0, false, false);
        }
        free(tcp_res);
      } else {
        release_zone_snapshot(task.snap);
      }
      close(task.client_fd);
      dec_tcp_clients();
    }
  }
  return NULL;
}

static void init_async_io_pool(void) {
  memset(&g_async_io_pool, 0, sizeof(g_async_io_pool));
  pthread_mutex_init(&g_async_io_pool.lock, NULL);
  pthread_cond_init(&g_async_io_pool.cond_not_empty, NULL);
  g_async_io_pool.running = true;
  for (int i = 0; i < ASYNC_IO_POOL_SIZE; i++) {
    pthread_create(&g_async_io_pool.threads[i], NULL, async_io_worker_func, NULL);
  }
}

static bool is_zone_synthetic_type(zone_db_snapshot_t *snap, const char *client_ip, const char *qname) {
  if (!snap || !qname) return false;
  view_snapshot_t *view = select_view(snap, client_ip);
  if (!view) return false;
  server_config_t *cfg = acquire_config_snapshot();
  if (!cfg) return false;

  bool is_synth = false;
  zone_db_entry_t *entry = find_zone_in_view(view, qname);
  if (entry) {
    zone_config_t *zcfg = find_zone_config_in_view(cfg, view->name, entry->domain);
    if (zcfg && zcfg->type && (strcasecmp(zcfg->type, "program") == 0 || strcasecmp(zcfg->type, "forward") == 0)) {
      is_synth = true;
    }
  }
  release_config_snapshot(cfg);
  return is_synth;
}

static inline void fast_ipv4_to_str(uint32_t ip_be, char *dst) {
  uint8_t *p = (uint8_t *)&ip_be;
  for (int i = 0; i < 4; i++) {
    uint8_t v = p[i];
    if (v >= 100) {
      *dst++ = '0' + (v / 100);
      v %= 100;
      *dst++ = '0' + (v / 10);
      *dst++ = '0' + (v % 10);
    } else if (v >= 10) {
      *dst++ = '0' + (v / 10);
      *dst++ = '0' + (v % 10);
    } else {
      *dst++ = '0' + v;
    }
    if (i < 3) *dst++ = '.';
  }
  *dst = '\0';
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
  server_config_t *active_cfg = acquire_config_snapshot();
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
  release_config_snapshot(active_cfg);

  // 全FrontendからのUDP転送を受け取るIPCパイプをkqueueに登録 (udata=1)
  int w = ctx->thread_id;
  cap_rights_t ipc_rights;
  cap_rights_init(&ipc_rights, CAP_EVENT, CAP_READ, CAP_WRITE, CAP_RECV, CAP_SEND);
  for (int f = 0; f < g_num_frontend_routers; f++) {
    int my_ipc_fd = g_ipc_fds[f][w][1];
    cap_rights_limit(my_ipc_fd, &ipc_rights);
    struct kevent ev_ipc;
    EV_SET(&ev_ipc, my_ipc_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)1);
    kevent(kq, &ev_ipc, 1, NULL, 0, NULL);
  }

  pid_t parent_pid = getppid();
  struct kevent ev_parent;
  EV_SET(&ev_parent, parent_pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, (void *)(uintptr_t)1001);
  kevent(kq, &ev_parent, 1, NULL, 0, NULL);

  atomic_fetch_add(&g_bound_workers, 1);
  goto worker_startup_success;

worker_startup_failed:
  atomic_fetch_add(&g_bound_workers, 1);
  pthread_exit(NULL);

worker_startup_success:;
  // 特権分離(setuid/setgid/Capsicum)が完了するまで、
  // イベントループ(=信頼できないネットワーク入力の処理)を開始しない。
  while (!atomic_load_explicit(&g_privilege_drop_complete, memory_order_acquire))
    sched_yield();
  if (getppid() != parent_pid)
    _exit(0);
  compress_ctx_t thread_compress_ctx = {0};
  struct kevent ev_list[MAX_EVENTS];

  udp_batch_ctx_t *batch = &ctx->batch;
  for (int k = 0; k < UDP_BATCH_SIZE; k++) {
    memset(&batch->rx_msgs[k], 0, sizeof(batch->rx_msgs[k]));
    batch->rx_iov[k].iov_base = batch->rx_buffers[k];
    batch->rx_iov[k].iov_len = sizeof(batch->rx_buffers[k]);
    batch->rx_msgs[k].msg_hdr.msg_iov = &batch->rx_iov[k];
    batch->rx_msgs[k].msg_hdr.msg_iovlen = 1;

    memset(&batch->tx_msgs[k], 0, sizeof(batch->tx_msgs[k]));
    batch->tx_msgs[k].msg_hdr.msg_iov = &batch->tx_iov[k];
    batch->tx_msgs[k].msg_hdr.msg_iovlen = 1;
  }

  while (1) {
    int n_events = kevent(kq, NULL, 0, ev_list, MAX_EVENTS, NULL);
    if (n_events < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    server_config_t *active = acquire_config_snapshot();
    bool qlog_enabled = (active && active->logging.queries_channel != NULL);
    uint32_t eff_max_qps = qlog_enabled ? get_effective_query_log_max_qps(active) : 0;
    bool rlog_enabled = response_log_enabled(active);
    release_config_snapshot(active);

    for (int i = 0; i < n_events; i++) {
      if (ev_list[i].udata == (void *)(uintptr_t)1001) {
        _exit(0);
      } else if (ev_list[i].filter == EVFILT_TIMER) {
        int client_fd = ev_list[i].ident;
        tcp_stream_ctx_t *ctx_tcp = (tcp_stream_ctx_t *)ev_list[i].udata;
        if (!ctx_tcp) continue;
        if (ctx_tcp->quota_yield) {
          ctx_tcp->quota_yield = false;
          goto process_tcp_client;
        }
        // RFC 7766 §6.2.3: Idle timeout expired; close connection immediately
        struct kevent ev_del[2];
        EV_SET(&ev_del[0], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
        EV_SET(&ev_del[1], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        kevent(kq, ev_del, 2, NULL, 0, NULL);
        close(client_fd);
        dec_tcp_clients();
        free(ctx_tcp);
        for (int j = i + 1; j < n_events; j++) {
          if (ev_list[j].ident == (uintptr_t)client_fd) {
            ev_list[j].udata = NULL;
            ev_list[j].filter = 0;
          }
        }
      } else if (ev_list[i].udata == (void *)1) {
        // UDP (IPC経由: recvmmsg / sendmmsg によるバッチ送受信)
        int active_fd = ev_list[i].ident; // my_ipc_fd
        while (1) {
          for (int k = 0; k < UDP_BATCH_SIZE; k++) {
            batch->rx_iov[k].iov_len = sizeof(batch->rx_buffers[k]);
          }
          int n_recv = recvmmsg(active_fd, batch->rx_msgs, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);
          if (n_recv <= 0) {
            if (n_recv == 0) {
              atomic_store(&g_frontend_alive, false);
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
              atomic_store(&g_frontend_alive, false);
            }
            break;
          }

          zone_db_snapshot_t *snap = acquire_zone_snapshot();
          int n_tx = 0;
          for (int p = 0; p < n_recv; p++) {
            ssize_t received = (ssize_t)batch->rx_msgs[p].msg_len;
            if (received < (ssize_t)sizeof(udp_ipc_t))
              continue;

            udp_ipc_t *ipc_msg = (udp_ipc_t *)batch->rx_buffers[p];
            if (ipc_msg->payload_len > received - (ssize_t)sizeof(udp_ipc_t) ||
                ipc_msg->payload_len < DNS_HEADER_SIZE)
              continue;
            uint8_t *req_buf = batch->rx_buffers[p] + sizeof(udp_ipc_t);
            ssize_t payload_received = ipc_msg->payload_len;
            struct sockaddr_storage *client_addr = &ipc_msg->client_addr;

            // クエリパケットの検証: QRビットが0(クエリ)であることを期待
            uint8_t flags = req_buf[2];
            if (!__builtin_expect((flags & 0x80) == 0, 1)) {
              continue;
            }

            char client_ip[INET6_ADDRSTRLEN] = "";
            if (__builtin_expect(client_addr->ss_family == AF_INET, 1)) {
              fast_ipv4_to_str(((struct sockaddr_in *)client_addr)->sin_addr.s_addr, client_ip);
            } else if (client_addr->ss_family == AF_INET6) {
              inet_ntop(AF_INET6,
                        &((struct sockaddr_in6 *)client_addr)->sin6_addr,
                        client_ip, INET6_ADDRSTRLEN);
            }

            // --- 高速ワンパス走査 ---
            char qname[256] = "";
            uint16_t qtype = 0;
            uint16_t qclass = 1;
            size_t question_end = DNS_HEADER_SIZE;
            bool has_edns = false;
            bool dnssec_ok = false;

            if (payload_received > DNS_HEADER_SIZE) {
              size_t offset = DNS_HEADER_SIZE;
              size_t recv_len = (size_t)payload_received;
              size_t written = 0;

              // 1回のループで qname と question_end を同時に確定
              while (offset < recv_len) {
                uint8_t len = req_buf[offset];
                if (len == 0 || (len & 0xC0) == 0xC0) {
                  offset += (len == 0) ? 1 : 2;
                  break;
                }
                if (offset + len + 1 > recv_len) break;
                offset++;
                if (written > 0 && qname[written - 1] != '.') {
                  if (written < 255) qname[written++] = '.';
                }
                if (offset + len <= recv_len) {
                  for (size_t b = 0; b < len; b++) {
                    uint8_t c = req_buf[offset + b];
                    if (written < 254) {
                      if (c == '.' || c == '\\') qname[written++] = '\\';
                      qname[written++] = (char)c;
                    }
                  }
                }
                offset += len;
              }
              if (written == 0 || (written > 0 && qname[written - 1] != '.')) {
                if (written < 255) qname[written++] = '.';
              }
              qname[written] = '\0';

              if (offset + 4 <= recv_len) {
                qtype = (req_buf[offset] << 8) | req_buf[offset + 1];
                qclass = (req_buf[offset + 2] << 8) | req_buf[offset + 3];
                offset += 4;
                question_end = offset;
              }

              // EDNSの走査 (Questionの直後から無駄なくスキャン)
              uint16_t arcount = (req_buf[10] << 8) | req_buf[11];
              if (arcount > 0 && offset < recv_len) {
                // 通常のクエリでは qd=1, an=0, ns=0 のため、offset は既に Additional Section の先頭
                if (offset + 10 <= recv_len) {
                  // OPTレコードの判定 (名前がルート 0x00 かつ TYPE 41)
                  size_t opt_offset = offset;
                  if (req_buf[opt_offset] == 0) {
                    opt_offset++;
                    if (opt_offset + 10 <= recv_len) {
                      uint16_t rt = (req_buf[opt_offset] << 8) | req_buf[opt_offset + 1];
                      if (rt == 41) {
                        has_edns = true;
                        uint32_t ttl = ((uint32_t)req_buf[opt_offset + 4] << 24) |
                                       ((uint32_t)req_buf[opt_offset + 5] << 16) |
                                       ((uint32_t)req_buf[opt_offset + 6] << 8) |
                                       req_buf[opt_offset + 7];
                        if (ttl & 0x00008000) dnssec_ok = true;
                      }
                    }
                  }
                }
              }
            }

            int client_port = 0;
            if (client_addr->ss_family == AF_INET)
              client_port = ntohs(((struct sockaddr_in *)client_addr)->sin_port);
            else if (client_addr->ss_family == AF_INET6)
              client_port =
                  ntohs(((struct sockaddr_in6 *)client_addr)->sin6_port);

            if (qlog_enabled && !__builtin_expect(atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed), 0)) {
                write_query_log(ctx, client_addr, sizeof(*client_addr),
                                qname, qclass, qtype, has_edns, dnssec_ok, IPPROTO_UDP, eff_max_qps);
            }
            write_dnstap_event(ctx, 1 /*AUTH_QUERY*/, req_buf, payload_received, client_addr, sizeof(*client_addr),
                               ipc_msg->has_source_addr ? &ipc_msg->source_addr : NULL, ipc_msg->has_source_addr, IPPROTO_UDP);

            if (is_zone_synthetic_type(snap, client_ip, qname)) {
              async_io_task_t task = {0};
              task.is_tcp = false;
              task.active_fd = active_fd;
              task.ipc_hdr = *ipc_msg;
              task.req_len = payload_received > UDP_DEFAULT_MAX_RES_LEN ? UDP_DEFAULT_MAX_RES_LEN : payload_received;
              memcpy(task.req_buf, req_buf, task.req_len);
              strncpy(task.client_ip, client_ip, sizeof(task.client_ip) - 1);
              task.client_port = client_port;
              task.client_addr = *client_addr;
              task.client_len = sizeof(*client_addr);
              task.has_server_addr = ipc_msg->has_source_addr;
              if (ipc_msg->has_source_addr) task.server_addr = ipc_msg->source_addr;
              strncpy(task.qname, qname, sizeof(task.qname) - 1);
              task.qtype = qtype;
              task.qclass = qclass;
              task.has_edns = has_edns;
              task.dnssec_ok = dnssec_ok;
              task.question_end = question_end;
              task.snap = acquire_zone_snapshot();
              if (!enqueue_async_io_task(&task)) {
                release_zone_snapshot(task.snap);
                if (rlog_enabled) {
                  submit_response_log(LOG_ACT_DROP_RRL, client_ip, client_port, qname, qclass, qtype, 2, has_edns, dnssec_ok);
                }
              }
              continue;
            }

            uint8_t *res_buf = batch->tx_buffers[n_tx] + sizeof(udp_ipc_t);
            rate_limit_config_t *rrl_cfg = NULL;
            int res_len =
                process_dns_query(req_buf, payload_received, res_buf, UDP_DEFAULT_MAX_RES_LEN, qname,
                                  qtype, client_ip, &thread_compress_ctx, false, &rrl_cfg, snap);
            if (res_len > 0) {
              bool drop_packet = false;
              bool tc_packet = false;

              if (__builtin_expect(rrl_cfg != NULL, 0)) {
                bool slip_triggered = false;
                rrl_response_class_t cls = get_rrl_class(res_buf, res_len);
                if (!rrl_check((struct sockaddr_storage *)&ipc_msg->client_addr, cls, rrl_cfg, &slip_triggered)) {
                  if (slip_triggered) {
                    tc_packet = true;
                  } else {
                    drop_packet = true;
                  }
                  view_snapshot_t *rrl_v = select_view(snap, client_ip);
                  zone_db_entry_t *rrl_z = rrl_v ? find_zone_in_view(rrl_v, qname) : NULL;
                  if (rrl_z) {
                    if (tc_packet) {
                      atomic_fetch_add_explicit(&rrl_z->observatory.rrl_slipped, 1, memory_order_relaxed);
                    } else {
                      atomic_fetch_add_explicit(&rrl_z->observatory.rrl_dropped, 1, memory_order_relaxed);
                    }
                  }
                }
              }

              if (__builtin_expect(drop_packet, 0)) {
                if (rlog_enabled) {
                  submit_response_log(LOG_ACT_DROP_RRL, client_ip, client_port, qname, 
                                      qclass, qtype, res_buf[3] & 0x0F, has_edns, dnssec_ok);
                }
                continue;
              }

              if (rlog_enabled) {
                submit_response_log(LOG_ACT_SENT, client_ip, client_port, qname, qclass, qtype,
                                    res_buf[3] & 0x0F, has_edns, dnssec_ok);
              }

              udp_ipc_t *res_msg = (udp_ipc_t *)batch->tx_buffers[n_tx];
              res_msg->sock_fd_idx = ipc_msg->sock_fd_idx;
              res_msg->addr_len = ipc_msg->addr_len;
              res_msg->has_source_addr = ipc_msg->has_source_addr;
              if (ipc_msg->has_source_addr) {
                res_msg->source_addr = ipc_msg->source_addr;
              }
              size_t copy_len = (ipc_msg->addr_len <= sizeof(res_msg->client_addr)) ? ipc_msg->addr_len : sizeof(res_msg->client_addr);
              memcpy(&res_msg->client_addr, &ipc_msg->client_addr, copy_len);

              if (__builtin_expect(tc_packet, 0)) {
                res_buf[2] |= 0x02; // Set TC bit
                res_buf[6] = 0; res_buf[7] = 0; // ANCOUNT = 0
                res_buf[8] = 0; res_buf[9] = 0; // NSCOUNT = 0
                res_buf[10] = 0; res_buf[11] = 0; // ARCOUNT = 0
                int qlen = (int)question_end;
                if (qlen > res_len) qlen = res_len;
                if (qlen > payload_received) qlen = payload_received;
                res_msg->payload_len = qlen;
                batch->tx_iov[n_tx].iov_len = sizeof(udp_ipc_t) + qlen;
              } else {
                res_msg->payload_len = res_len;
                batch->tx_iov[n_tx].iov_len = sizeof(udp_ipc_t) + res_len;
              }

              write_dnstap_event(ctx, 2 /*AUTH_RESPONSE*/, res_buf, res_msg->payload_len, client_addr, sizeof(*client_addr),
                                 ipc_msg->has_source_addr ? &ipc_msg->source_addr : NULL, ipc_msg->has_source_addr, IPPROTO_UDP);

              batch->tx_iov[n_tx].iov_base = batch->tx_buffers[n_tx];
              batch->tx_msgs[n_tx].msg_hdr.msg_name = NULL;
              batch->tx_msgs[n_tx].msg_hdr.msg_namelen = 0;
              batch->tx_msgs[n_tx].msg_hdr.msg_control = NULL;
              batch->tx_msgs[n_tx].msg_hdr.msg_controllen = 0;
              n_tx++;
              if (n_tx == UDP_BATCH_SIZE) {
                sendmmsg(active_fd, batch->tx_msgs, n_tx, MSG_DONTWAIT);
                n_tx = 0;
              }
            } else {
              if (rlog_enabled) {
                submit_response_log(LOG_ACT_DROP_MALFORMED, client_ip, client_port, "<malformed>", 
                                    0, 0, 0, false, false);
              }
            }
          }
          atomic_fetch_add_explicit(&ctx->query_count, n_recv, memory_order_relaxed);
          if (snap) {
            release_zone_snapshot(snap);
          }
          if (n_tx > 0) {
            sendmmsg(active_fd, batch->tx_msgs, n_tx, MSG_DONTWAIT);
            n_tx = 0;
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

          memcpy(&ctx_tcp->client_addr, &client_addr, sizeof(client_addr));
          ctx_tcp->client_len = client_len;
          struct sockaddr_storage saddr;
          socklen_t slen = sizeof(saddr);
          if (getsockname(client_fd, (struct sockaddr *)&saddr, &slen) == 0) {
            memcpy(&ctx_tcp->server_addr, &saddr, sizeof(saddr));
            ctx_tcp->server_len = slen;
            ctx_tcp->has_server_addr = true;
          }
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
process_tcp_client: ;
        // TCP 既存処理
        int client_fd = ev_list[i].ident;
        tcp_stream_ctx_t *ctx_tcp = (tcp_stream_ctx_t *)ev_list[i].udata;
        if (!ctx_tcp) continue;
        if (ev_list[i].flags & (EV_EOF | EV_ERROR)) {
          struct kevent ev_del[2];
          EV_SET(&ev_del[0], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
          EV_SET(&ev_del[1], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
          kevent(kq, ev_del, 2, NULL, 0, NULL);
          close(client_fd);
          dec_tcp_clients();
          free(ctx_tcp);
          for (int j = i + 1; j < n_events; j++) {
            if (ev_list[j].ident == (uintptr_t)client_fd) {
              ev_list[j].udata = NULL;
              ev_list[j].filter = 0;
            }
          }
          continue;
        }
        int processed_queries = 0;
        bool client_closed = false;

        while (processed_queries < 16) {
          uint8_t *msg = NULL;
          uint16_t msg_len = 0;
          int ret = read_dns_tcp_message(client_fd, ctx_tcp, &msg, &msg_len);
          if (ret < 0) {
            struct kevent ev_del[2];
            EV_SET(&ev_del[0], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
            EV_SET(&ev_del[1], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
            kevent(kq, ev_del, 2, NULL, 0, NULL);
            close(client_fd);
            dec_tcp_clients();
            free(ctx_tcp);
            client_closed = true;
            for (int j = i + 1; j < n_events; j++) {
              if (ev_list[j].ident == (uintptr_t)client_fd) {
                ev_list[j].udata = NULL;
                ev_list[j].filter = 0;
              }
            }
            break;
          }
          if (ret == 0) {
            break;
          }

          processed_queries++;
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
                for (size_t b = 0; b < len; b++) {
                  uint8_t c = msg[offset + b];
                  if (c == '.' || c == '\\') {
                    if (written + 2 < 255) {
                      qname[written++] = '\\';
                      qname[written++] = (char)c;
                    }
                  } else {
                    if (written < 255) {
                      qname[written++] = (char)c;
                    }
                  }
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
          atomic_fetch_add_explicit(&ctx->query_count, 1, memory_order_relaxed);
          if (qlog_enabled && !atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed)) {
              write_query_log(ctx, &ctx_tcp->client_addr, ctx_tcp->client_len,
                              qname, qclass, qtype, has_edns, dnssec_ok, IPPROTO_TCP, eff_max_qps);
          }
          write_dnstap_event(ctx, 1 /*AUTH_QUERY*/, msg, msg_len, &ctx_tcp->client_addr, ctx_tcp->client_len,
                             ctx_tcp->has_server_addr ? &ctx_tcp->server_addr : NULL,
                             ctx_tcp->has_server_addr, IPPROTO_TCP);

          zone_db_snapshot_t *snap = acquire_zone_snapshot();
          view_snapshot_t *xfr_view = select_view(snap, ctx_tcp->client_ip);
          server_config_t *cfg = acquire_config_snapshot();
          zone_config_t *zcfg = xfr_view
              ? find_zone_config_in_view(cfg, xfr_view->name, qname)
              : NULL;
          bool is_synthetic_zone = (zcfg && zcfg->type &&
                                    (strcasecmp(zcfg->type, "program") == 0 ||
                                     strcasecmp(zcfg->type, "forward") == 0));

          if ((qtype == 252 || qtype == 251) && !is_synthetic_zone) {
            bool allowed = false;
            uint16_t tsig_error = 0;
            tsig_key_t *matched_key = NULL;
            uint8_t tsig_mac[64]; /* >= EVP_MAX_MD_SIZE */
            static_assert(sizeof(tsig_mac) >= 64, "tsig_mac must be >= EVP_MAX_MD_SIZE (64)");
            size_t tsig_mac_len = 0;
            if (zcfg) {
              bool has_acl = (zcfg->allow_transfer_count > 0);
              bool has_tsig = (zcfg->tsig_keys_count > 0) || (zcfg->tsig_key != NULL);
              
              bool acl_ok = has_acl ? check_acl(ctx_tcp->client_ip, zcfg->allow_transfer, zcfg->allow_transfer_count) : false;
              bool tsig_ok = false;
              
              if (has_tsig) {
                // allow-transfer { key "A"; key "B"; ... } で指定された全キー名を候補として、
                // それぞれに対応する tsig_key_t を探し、TSIG検証が成功するものが1つでもあれば許可する。
                // (どの鍵で署名されたかはメッセージを見るまで分からないため、候補を順に試す)
                bool any_key_recognized = false;
                for (int ki = 0; ki < zcfg->tsig_keys_count && !tsig_ok; ki++) {
                  const char *cand_name = zcfg->tsig_keys[ki];
                  tsig_key_t *k = cfg->keys;
                  while (k) {
                    if (strcmp(k->name, cand_name) == 0) break;
                    k = k->next;
                  }
                  if (!k) continue; // このキー名は定義されていない。次の候補へ
                  any_key_recognized = true;
                  size_t tmp_mac_len = 0;
                  uint8_t tmp_mac[64];
                  int err = tsig_verify_packet(msg, msg_len, k, NULL, 0, NULL, 0, false, tmp_mac, &tmp_mac_len);
                  if (err == 0) {
                    matched_key = k;
                    memcpy(tsig_mac, tmp_mac, tmp_mac_len);
                    tsig_mac_len = tmp_mac_len;
                    tsig_ok = true;
                    tsig_error = 0;
                    break;
                  } else if (tsig_error == 0) {
                    tsig_error = err > 0 ? err : 16; // 最初に遭遇した検証エラーを記録
                  }
                }
                // 後方互換: 旧来の tsig-key 単一指定(allow-transfer外の標準directive)も引き続きサポートする
                if (!tsig_ok && zcfg->tsig_key) {
                  tsig_key_t *k = cfg->keys;
                  while (k) {
                    if (strcmp(k->name, zcfg->tsig_key) == 0) break;
                    k = k->next;
                  }
                  if (k) {
                    any_key_recognized = true;
                    size_t tmp_mac_len = 0;
                    uint8_t tmp_mac[64];
                    int err = tsig_verify_packet(msg, msg_len, k, NULL, 0, NULL, 0, false, tmp_mac, &tmp_mac_len);
                    if (err == 0) {
                      matched_key = k;
                      memcpy(tsig_mac, tmp_mac, tmp_mac_len);
                      tsig_mac_len = tmp_mac_len;
                      tsig_ok = true;
                      tsig_error = 0;
                    } else if (tsig_error == 0) {
                      tsig_error = err > 0 ? err : 16;
                    }
                  }
                }
                if (!any_key_recognized) {
                  tsig_error = 17; // BADKEY: 設定されているキー名のうち、どれ一つとして定義済みキーと一致しなかった
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
            release_config_snapshot(cfg);
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
                  strncpy(args->client_ip, ctx_tcp->client_ip, INET6_ADDRSTRLEN - 1);
                  args->client_ip[INET6_ADDRSTRLEN - 1] = '\0';
                  args->client_port = client_port;
                  memcpy(&args->client_addr, &ctx_tcp->client_addr, sizeof(ctx_tcp->client_addr));
                  args->client_len = ctx_tcp->client_len;
                  memcpy(&args->server_addr, &ctx_tcp->server_addr, sizeof(ctx_tcp->server_addr));
                  args->server_len = ctx_tcp->server_len;
                  args->has_server_addr = ctx_tcp->has_server_addr;
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

                  // Item 1: AXFR UAF防止 - pthread_create直前にkqueueのEVFILT_READ / EVFILT_TIMERを削除
                  struct kevent ev_del_axfr[2];
                  EV_SET(&ev_del_axfr[0], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                  EV_SET(&ev_del_axfr[1], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
                  kevent(kq, ev_del_axfr, 2, NULL, 0, NULL);

                  pthread_t t;
                  if (pthread_create(&t, NULL, axfr_worker_thread, args) != 0) {
                    free(args);
                    atomic_fetch_sub(&entry->active_axfr, 1);
                    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
                    allowed = false;
                  } else {
                    pthread_detach(t);
                    release_zone_snapshot(snap);
                    free(ctx_tcp);
                    client_closed = true;
                    for (int j = i + 1; j < n_events; j++) {
                      if (ev_list[j].ident == (uintptr_t)client_fd) {
                        ev_list[j].udata = NULL;
                        ev_list[j].filter = 0;
                      }
                    }
                    break;
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
                  assemble_edns_opt(res_buf, sizeof(res_buf), &offset, &arcount, &edns, 0, true, cfg);
                }
                res_buf[6] = 0; res_buf[7] = 0;
                res_buf[8] = 0; res_buf[9] = 0;
                res_buf[10] = arcount >> 8;
                res_buf[11] = arcount & 0xFF;
                copy_len = offset;

                if (matched_key)
                  tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf),
                                   matched_key, tsig_error, tsig_mac, &tsig_mac_len, NULL, 0, false);
                else {
                  tsig_key_t dummy = {0};
                  dummy.name = (zcfg && zcfg->tsig_keys_count > 0) ? zcfg->tsig_keys[0] : (zcfg ? zcfg->tsig_key : "unknown");
                  dummy.algorithm = "hmac-sha256";
                  tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf), &dummy,
                                   17, tsig_mac, &tsig_mac_len, NULL, 0, false);
                }
              } else {
                res_buf[2] |= 0x84;
                res_buf[3] |= 0x05;
                add_ede(&edns, cfg->send_extended_errors, 18, "Query refused due to access control");
                
                uint16_t qd = (msg[4] << 8) | msg[5];
                uint16_t offset = (uint16_t)get_question_end_offset(res_buf, copy_len, qd);
                uint16_t arcount = 0;
                if (edns.present) {
                  assemble_edns_opt(res_buf, sizeof(res_buf), &offset, &arcount, &edns, 0, true, cfg);
                }
                res_buf[6] = 0; res_buf[7] = 0;
                res_buf[8] = 0; res_buf[9] = 0;
                res_buf[10] = arcount >> 8;
                res_buf[11] = arcount & 0xFF;
                copy_len = offset;
              }
              release_zone_snapshot(snap);
              uint8_t len_prefix[2] = {copy_len >> 8, copy_len & 0xFF};
              write_dnstap_event(ctx, 2 /*AUTH_RESPONSE*/, res_buf, copy_len,
                                 &ctx_tcp->client_addr, ctx_tcp->client_len,
                                 ctx_tcp->has_server_addr ? &ctx_tcp->server_addr : NULL,
                                 ctx_tcp->has_server_addr, IPPROTO_TCP);
              if (send_tcp_robust(client_fd, len_prefix, 2) < 0 ||
                  send_tcp_robust(client_fd, res_buf, copy_len) < 0) {
                // fall through to close/free
              }
              
              submit_response_log(LOG_ACT_SENT, ctx_tcp->client_ip, client_port, qname, 
                                  qclass, qtype, res_buf[3] & 0x0F, has_edns, dnssec_ok);

              close(client_fd);
              dec_tcp_clients();
              free(ctx_tcp);
              client_closed = true;
              break;
            } else {
              release_zone_snapshot(snap);
            }
          } else {
            if (is_zone_synthetic_type(snap, ctx_tcp->client_ip, qname)) {
              struct kevent ev_del_syn[2];
              EV_SET(&ev_del_syn[0], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
              EV_SET(&ev_del_syn[1], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
              kevent(kq, ev_del_syn, 2, NULL, 0, NULL);

              async_io_task_t task = {0};
              task.is_tcp = true;
              task.client_fd = client_fd;
              task.req_len = msg_len > UDP_DEFAULT_MAX_RES_LEN ? UDP_DEFAULT_MAX_RES_LEN : msg_len;
              memcpy(task.req_buf, msg, task.req_len);
              strncpy(task.client_ip, ctx_tcp->client_ip, sizeof(task.client_ip) - 1);
              task.client_port = client_port;
              task.client_addr = ctx_tcp->client_addr;
              task.client_len = ctx_tcp->client_len;
              task.has_server_addr = ctx_tcp->has_server_addr;
              if (ctx_tcp->has_server_addr) task.server_addr = ctx_tcp->server_addr;
              strncpy(task.qname, qname, sizeof(task.qname) - 1);
              task.qtype = qtype;
              task.qclass = qclass;
              task.has_edns = has_edns;
              task.dnssec_ok = dnssec_ok;
              task.question_end = 0;
              task.snap = snap;
              free(ctx_tcp);

              if (!enqueue_async_io_task(&task)) {
                release_zone_snapshot(snap);
                close(client_fd);
                dec_tcp_clients();
              }
              client_closed = true;
              break;
            }
            uint8_t *tcp_res = malloc(65535);
            if (tcp_res) {
              int res_len = process_dns_query(msg, msg_len, tcp_res, 65535,
                                              qname, qtype, ctx_tcp->client_ip,
                                              &thread_compress_ctx, true, NULL, snap);
              release_zone_snapshot(snap);
              if (res_len > 0) {
                submit_response_log(LOG_ACT_SENT, ctx_tcp->client_ip, client_port, qname, qclass, qtype,
                                    tcp_res[3] & 0x0F, has_edns, dnssec_ok);
                write_dnstap_event(ctx, 2 /*AUTH_RESPONSE*/, tcp_res, res_len, &ctx_tcp->client_addr, ctx_tcp->client_len,
                                   ctx_tcp->has_server_addr ? &ctx_tcp->server_addr : NULL, ctx_tcp->has_server_addr, IPPROTO_TCP);
                uint8_t len_prefix[2] = {res_len >> 8, res_len & 0xFF};
                if (send_tcp_robust(client_fd, len_prefix, 2) < 0 ||
                    send_tcp_robust(client_fd, tcp_res, res_len) < 0) {
                  free(tcp_res);
                  close(client_fd);
                  dec_tcp_clients();
                  free(ctx_tcp);
                  client_closed = true;
                  break;
                }
              } else {
                submit_response_log(LOG_ACT_DROP_MALFORMED, ctx_tcp->client_ip, client_port, "<malformed>", 
                                    0, 0, 0, false, false);
              }
              free(tcp_res);
            } else {
              release_zone_snapshot(snap);
            }
            
            server_config_t *cfg = acquire_config_snapshot();
            bool reuse = (cfg && cfg->tcp_connection_reuse);
            release_config_snapshot(cfg);
            if (!reuse) {
              close(client_fd);
              dec_tcp_clients();
              free(ctx_tcp);
              client_closed = true;
              break;
            }

            ctx_tcp->state = TCP_STATE_READ_LEN;
            ctx_tcp->accumulated = 0;
            ctx_tcp->msg_len = 0;
          }
        }

        if (!client_closed) {
          server_config_t *cfg = acquire_config_snapshot();
          uint32_t idle_timeout = (cfg && cfg->tcp_idle_timeout > 0) ? cfg->tcp_idle_timeout : 10000;
          release_config_snapshot(cfg);

          struct kevent evs[2];
          uint32_t to_ms = (processed_queries >= 16) ? 1 : idle_timeout;
          ctx_tcp->quota_yield = (processed_queries >= 16);
          EV_SET(&evs[0], client_fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
                 to_ms, ctx_tcp);
          int nev = 1;
          if (processed_queries >= 16) {
            EV_SET(&evs[1], client_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, ctx_tcp);
            nev = 2;
          }
          kevent(kq, evs, nev, NULL, 0, NULL);
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

static void perform_config_reload_ext(bool skip_unchanged);

static void reload_all_zones(void) {
  perform_config_reload_ext(false);
}

static void perform_config_reload(void) {
  perform_config_reload_ext(true);
}

static void perform_config_reload_ext(bool skip_unchanged) {
  g_last_configured_time = time(NULL);
  char *config_str = read_entire_file(g_config_path, NULL, NULL);
  if (!config_str)
    return;
  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  server_config_t *standby = (active == &g_config_db.config_a)
                                 ? &g_config_db.config_b
                                 : &g_config_db.config_a;
  
  /* [H-2] 既存のリーダーが参照を終えるのを待機。
   * 最大5秒を上限とし、超過した場合は古い設定を維持して安全に中断する。*/
  int retries = 0;
  useconds_t sleep_time = 1;
  struct timespec rcu_wait_start, rcu_wait_now;
  clock_gettime(CLOCK_MONOTONIC, &rcu_wait_start);
  while (atomic_load_explicit(&standby->reader_count, memory_order_acquire) > 0) {
    if (retries < 100) sched_yield();
    else { usleep(sleep_time); if (sleep_time < 100000) sleep_time *= 2; }
    retries++;
    clock_gettime(CLOCK_MONOTONIC, &rcu_wait_now);
    int64_t elapsed_ms = (rcu_wait_now.tv_sec - rcu_wait_start.tv_sec) * 1000 +
                         (rcu_wait_now.tv_nsec - rcu_wait_start.tv_nsec) / 1000000;
    if (elapsed_ms > 5000) {
      syslog(LOG_CRIT, "[Config] RCU standby config still has readers after 5s; aborting reload to protect live traffic");
      free(config_str);
      return;
    }
  }
  
  free_server_config_fields(standby);
  if (parse_named_conf_ext(config_str, g_config_path, standby) == 0) {
    if (g_cli_port_override > 0) {
      standby->port = g_cli_port_override;
    }
    if (geteuid() == 0 && !standby->user) {
      syslog(LOG_ERR,
             "[Config] Reload rejected: running as root but new configuration has no 'user' directive in options{}.");
      fprintf(stderr,
             "[ERROR] Reload rejected: running as root but new configuration has no 'user' directive in options{}.\n");
      free_server_config_fields(standby);
      free(config_str);
      return;
    }
    init_logging_channels(standby);
    atomic_store_explicit(&g_config_db.active, standby,
                          memory_order_release);
    rebuild_zone_db_from_config(standby, skip_unchanged);
    for (view_config_t *v = standby->views; v; v = v->next) {
      for (zone_config_t *z = v->zones; z; z = z->next) {
        if (z->type && strcasecmp(z->type, "program") == 0) {
          bool already_running = false;
          for (int i = 0; i < g_program_plugins_count; i++) {
            if (strcasecmp(g_program_plugins[i].domain, z->domain) == 0) {
              already_running = true;
              /* M-4: 実行中の設定と新しい設定を比較し、変わっていれば警告 */
              char new_fingerprint[512];
              compute_program_zone_fingerprint(z, new_fingerprint, sizeof(new_fingerprint));
              if (strcmp(g_program_plugins[i].config_fingerprint, new_fingerprint) != 0) {
                syslog(LOG_WARNING, "[Plugin] zone '%s' (type program) configuration changed "
                       "(program/program-args/program-user/program-timeout/program-max-failures), "
                       "but the running plugin process cannot be restarted without a full karidns "
                       "restart (Capsicum sandbox is already active). The OLD configuration is "
                       "still in effect for this zone.", z->domain);
              }
              break;
            }
          }
          if (!already_running) {
            syslog(LOG_ERR, "[Plugin] zone '%s' (type program) was added via reload but "
                   "cannot be started without a full restart (Capsicum sandbox is already active). "
                   "This zone will return SERVFAIL until karidns is restarted.", z->domain);
          }
        }
      }
    }
    syslog(LOG_NOTICE, "Configuration and zones reloaded successfully.");
  } else {
    syslog(LOG_ERR, "Failed to reload configuration: parse error.");
  }
  free(config_str);
}

static const char *find_configured_domain(const char *arg, char *out_buf, size_t out_size) {
  if (!out_buf || out_size == 0) return arg;
  snprintf(out_buf, out_size, "%s", arg);
  server_config_t *active = acquire_config_snapshot();
  if (!active) return out_buf;
  zone_config_t *zcfg = active->zones;
  size_t arg_len = strlen(arg);
  while (zcfg) {
    size_t z_len = strlen(zcfg->domain);
    if (strcasecmp(zcfg->domain, arg) == 0) {
      snprintf(out_buf, out_size, "%s", zcfg->domain);
      break;
    }
    if (arg_len + 1 == z_len && zcfg->domain[z_len - 1] == '.' && strncasecmp(zcfg->domain, arg, arg_len) == 0) {
      snprintf(out_buf, out_size, "%s", zcfg->domain);
      break;
    }
    if (z_len + 1 == arg_len && arg[arg_len - 1] == '.' && strncasecmp(zcfg->domain, arg, z_len) == 0) {
      snprintf(out_buf, out_size, "%s", zcfg->domain);
      break;
    }
    zcfg = zcfg->next;
  }
  release_config_snapshot(active);
  return out_buf;
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
    EV_SET(&ev_set[0], g_control_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
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
        // リスニングソケットをノンブロッキング化して accept でのハングを完全防止
        int sflags = fcntl(g_control_sock, F_GETFL, 0);
        if (!(sflags & O_NONBLOCK)) {
          fcntl(g_control_sock, F_SETFL, sflags | O_NONBLOCK);
        }
        int ctrl_accept_count = 0;
        while (ctrl_accept_count < 64) {
          struct sockaddr_un cli_addr;
          socklen_t cli_len = sizeof(cli_addr);
          int cfd = accept(g_control_sock, (struct sockaddr *)&cli_addr, &cli_len);
          if (cfd < 0) {
            break;
          }
          // クライアント側ソケットも直ちにノンブロッキング化
          fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL, 0) | O_NONBLOCK);
          ctrl_accept_count++;
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

          cap_rights_t rights;
          cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_EVENT, CAP_GETSOCKOPT);
          cap_rights_limit(cfd, &rights);
          
          ctrl_client_t *c = calloc(1, sizeof(ctrl_client_t));
          if (!c) {
              syslog(LOG_ERR, "[Control] OOM allocating ctrl_client_t; dropping connection");
              close(cfd);
              continue;
          }
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
          if (nl > c->buf && *(nl - 1) == '\r') {
            *(nl - 1) = '\0';
          }
          if (c->state == CTRL_STATE_AUTH_WAIT) {
            server_config_t *cfg = acquire_config_snapshot();
            bool auth_ok = false;
            if (cfg && strncmp(c->buf, "AUTH ", 5) == 0 && cfg->control.enabled && cfg->control.secret_decoded_len > 0) {
              char *client_hmac = c->buf + 5;
              unsigned char md[EVP_MAX_MD_SIZE];
              unsigned int md_len;
              HMAC(EVP_sha256(), cfg->control.secret_decoded, cfg->control.secret_decoded_len,
                   (unsigned char*)c->challenge, 64, md, &md_len);
              char expected[65];
              for(unsigned int k=0; k<md_len; k++) snprintf(&expected[k*2], 3, "%02x", md[k]);
              /* [H-5] タイミング攻撃対策: 長さ比較も定数時間で行う。
               * client_hmac が expected と長さが異なる場合も const_time_memcmp を
               * 必ず呼んでキャッシュタイミングを均一化し、その後 len_ok で弾く。*/
              size_t clen = strlen(client_hmac);
              size_t elen = strlen(expected);
              bool len_ok = (clen == elen);
              /* 長さが異なる場合は expected の長さで比較 (ダミー比較) */
              size_t cmp_len = len_ok ? elen : elen;
              bool hmac_ok = (const_time_memcmp(client_hmac, expected,
                                                clen >= cmp_len ? cmp_len : clen) == 0);
              if (len_ok && hmac_ok) {
                auth_ok = true;
              }
            }
            release_config_snapshot(cfg);
            if (auth_ok) {
              send(cfd, "OK\n", 3, 0);
              c->state = CTRL_STATE_CMD_WAIT;
            } else {
              send(cfd, "AUTH_FAILED\n", 12, 0);
              free_ctrl_client(cfd);
              continue;
            }
          } else if (c->state == CTRL_STATE_CMD_WAIT) {
            char *cmd = c->buf;
            char *arg = strchr(cmd, ' ');
            if (arg) {
              *arg = '\0';
              arg++;
              while (*arg == ' ' || *arg == '\t') arg++;
              if (*arg == '\0') arg = NULL;
            }
            
            char *view_arg = NULL;
            if (arg) {
              char *sp = strchr(arg, ' ');
              if (sp) {
                *sp = '\0';
                view_arg = sp + 1;
                while (*view_arg == ' ' || *view_arg == '\t') view_arg++;
                if (*view_arg == '\0') view_arg = NULL;
              }
            }
            
            if (strcmp(cmd, "reload") == 0) {
              if (arg && strlen(arg) > 0) {
                char canon_buf[256];
                const char *canon_arg = find_configured_domain(arg, canon_buf, sizeof(canon_buf));
                zone_db_snapshot_t *snap = acquire_zone_snapshot();
                server_config_t *active = acquire_config_snapshot();
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
                    reload_result_t rr = reload_master_zone(lr.entry, lr.zcfg);
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
                  } else if (lr.zcfg->type && (strcasecmp(lr.zcfg->type, "slave") == 0 || strcasecmp(lr.zcfg->type, "secondary") == 0)) {
                    syslog(LOG_NOTICE, "[Control] Triggering retransfer for slave zone %s on reload", lr.zcfg->domain);
                    atomic_store_explicit(&lr.entry->serial, 0, memory_order_release);
                    atomic_store_explicit(&lr.entry->refresh_now, true, memory_order_release);
                    send(cfd, "OK reloaded (slave)\n", 20, 0);
                  } else {
                    send(cfd, "ERROR unknown zone type\n", 24, 0);
                  }
                } else {
                  send(cfd, "ERROR zone not found\n", 21, 0);
                }
                release_config_snapshot(active);
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
                release_zone_snapshot(snap);
              }

              st.xfers_running = atomic_load_explicit(&g_xfers_running, memory_order_relaxed);
              st.tcp_clients = atomic_load_explicit(&g_tcp_clients, memory_order_relaxed);
              st.tcp_high_water = atomic_load_explicit(&g_tcp_high_water, memory_order_relaxed);
              st.worker_threads = atomic_load(&g_bound_workers);
              
              if (g_config_path) {
                  strncpy(st.config_file, g_config_path, sizeof(st.config_file) - 1);
              }
              st.frontend_alive = atomic_load(&g_frontend_alive);
              
              server_config_t *active_cfg = acquire_config_snapshot();
              st.query_logging = (active_cfg && active_cfg->logging.queries_channel != NULL);
              st.response_logging = (active_cfg && active_cfg->logging.responses_channel != NULL);
              release_config_snapshot(active_cfg);
              
              st.rrl_dropped = atomic_load_explicit(&g_rrl_dropped_total, memory_order_relaxed);
              st.rrl_slipped = atomic_load_explicit(&g_rrl_slip_total, memory_order_relaxed);
              st.ede_proh = atomic_load_explicit(&g_ede_prohibited_total, memory_order_relaxed);
              st.ede_na = atomic_load_explicit(&g_ede_not_authoritative_total, memory_order_relaxed);
              st.ede_ns = atomic_load_explicit(&g_ede_not_supported_total, memory_order_relaxed);
              st.ede_oth = atomic_load_explicit(&g_ede_other_total, memory_order_relaxed);
              st.dnstap_truncated = atomic_load_explicit(&g_dnstap_truncated_total, memory_order_relaxed);
              
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
              char canon_buf[256];
              const char *canon_arg = find_configured_domain(arg, canon_buf, sizeof(canon_buf));
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
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
              release_config_snapshot(active_cfg);
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "observatory") == 0) {
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
              char canon_buf[256];
              const char *canon_arg = (arg && strlen(arg) > 0) ? find_configured_domain(arg, canon_buf, sizeof(canon_buf)) : NULL;

              uint32_t match_count = 0;
              if (snap) {
                for (size_t v = 0; v < snap->view_count; v++) {
                  if (view_arg && strcasecmp(snap->views[v].name, view_arg) != 0) continue;
                  for (size_t z = 0; z < snap->views[v].zone_count; z++) {
                    zone_db_entry_t *e = snap->views[v].entries[z];
                    if (!e) continue;
                    if (canon_arg && !domain_names_match_ci(e->domain, canon_arg)) continue;
                    match_count++;
                  }
                }
              }

              char resp_hdr[64];
              int hlen = snprintf(resp_hdr, sizeof(resp_hdr), "OK %u\n", match_count);
              send(cfd, resp_hdr, hlen, 0);

              if (snap && match_count > 0) {
                for (size_t v = 0; v < snap->view_count; v++) {
                  if (view_arg && strcasecmp(snap->views[v].name, view_arg) != 0) continue;
                  for (size_t z = 0; z < snap->views[v].zone_count; z++) {
                    zone_db_entry_t *e = snap->views[v].entries[z];
                    if (!e) continue;
                    if (canon_arg && !domain_names_match_ci(e->domain, canon_arg)) continue;
                    zone_observatory_snapshot_t snap_item;
                    memset(&snap_item, 0, sizeof(snap_item));
                    fill_observatory_snapshot(e, active_cfg, &snap_item);
                    send(cfd, &snap_item, sizeof(snap_item), 0);
                  }
                }
              }
              if (active_cfg) release_config_snapshot(active_cfg);
              if (snap) release_zone_snapshot(snap);
            } else if (strcmp(cmd, "notify") == 0 && arg) {
              char canon_buf[256];
              const char *canon_arg = find_configured_domain(arg, canon_buf, sizeof(canon_buf));
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
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
              release_config_snapshot(active_cfg);
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "retransfer") == 0 && arg) {
              char canon_buf[256];
              const char *canon_arg = find_configured_domain(arg, canon_buf, sizeof(canon_buf));
              zone_db_snapshot_t *snap = acquire_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
              zone_lookup_result_t lr = {0};
              int nmatches = lookup_zone_across_views(snap, active_cfg, canon_arg, view_arg, &lr);
              if (nmatches == 0) {
                syslog(LOG_ERR, "[Control] Command 'retransfer' failed: zone '%s' not found", canon_arg);
                send(cfd, "ERROR zone not found\n", 21, 0);
              } else if (nmatches > 1) {
                send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'retransfer <zone> <view>')\n", 86, 0);
              } else if (lr.entry) {
                syslog(LOG_NOTICE, "[Control] Received retransfer command for zone: %s", canon_arg);
                atomic_store_explicit(&lr.entry->serial, 0, memory_order_release);
                atomic_store_explicit(&lr.entry->refresh_now, true, memory_order_release);
                send(cfd, "OK\n", 3, 0);
              } else {
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_config_snapshot(active_cfg);
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
        server_config_t *active = acquire_config_snapshot();
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
                        if (zcfg && zcfg->type && (strcasecmp(zcfg->type, "slave") == 0 || strcasecmp(zcfg->type, "secondary") == 0) &&
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
                                if (active && active->serve_stale) {
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
                                    
                                    /* [H-4] config ポインタをそのまま渡すと UAF になるため、
                                     * TSIG キーのデータをスレッド起動前に bg_ctx へ値コピーする。*/
                                    if (tsig_key_name[0] != '\0' && active) {
                                        tsig_key_t *k = active->keys;
                                        while (k) {
                                            if (strcmp(k->name, tsig_key_name) == 0) {
                                                bg_ctx->has_tsig = true;
                                                strncpy(bg_ctx->tsig_name, k->name,
                                                        sizeof(bg_ctx->tsig_name) - 1);
                                                strncpy(bg_ctx->tsig_algorithm,
                                                        k->algorithm ? k->algorithm : "hmac-sha256",
                                                        sizeof(bg_ctx->tsig_algorithm) - 1);
                                                size_t copy_len = k->secret_decoded_len;
                                                if (copy_len > sizeof(bg_ctx->tsig_secret_decoded))
                                                    copy_len = sizeof(bg_ctx->tsig_secret_decoded);
                                                memcpy(bg_ctx->tsig_secret_decoded,
                                                       k->secret_decoded, copy_len);
                                                bg_ctx->tsig_secret_decoded_len = copy_len;
                                                break;
                                            }
                                            k = k->next;
                                        }
                                    }
                                    
                                    pthread_t bg_thread;
                                    pthread_attr_t attr;
                                    pthread_attr_init(&attr);
                                    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                                    pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
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
        release_config_snapshot(active);
      }
    }
  }
  close(kq);
  pthread_exit(NULL);
}

// ============================================================================
// 13. Frontend Router Process (マルチプロセス UDP送受信ルーティング)
// ============================================================================

static void setup_udp_socket_buffers(int fd, int desired_rcv, int desired_snd) {
  if (desired_rcv > 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &desired_rcv, sizeof(desired_rcv)) != 0) {
      syslog(LOG_WARNING, "[Network] Failed to set SO_RCVBUF to %d: %m", desired_rcv);
    } else {
      int actual_rcv = 0;
      socklen_t optlen = sizeof(actual_rcv);
      if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &actual_rcv, &optlen) == 0) {
        if (actual_rcv < desired_rcv) {
          syslog(LOG_WARNING,
                 "[Network] UDP SO_RCVBUF truncated by OS: requested %d bytes, got %d bytes "
                 "(consider increasing kern.ipc.maxsockbuf sysctl)",
                 desired_rcv, actual_rcv);
        }
      }
    }
  }
  if (desired_snd > 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &desired_snd, sizeof(desired_snd)) != 0) {
      syslog(LOG_WARNING, "[Network] Failed to set SO_SNDBUF to %d: %m", desired_snd);
    } else {
      int actual_snd = 0;
      socklen_t optlen = sizeof(actual_snd);
      if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &actual_snd, &optlen) == 0) {
        if (actual_snd < desired_snd) {
          syslog(LOG_WARNING,
                 "[Network] UDP SO_SNDBUF truncated by OS: requested %d bytes, got %d bytes "
                 "(consider increasing kern.ipc.maxsockbuf sysctl)",
                 desired_snd, actual_snd);
        }
      }
    }
  }
}

static int open_router_udp_sockets(server_config_t *cfg, int out_fds[MAX_BIND_ADDRS], bool out_is_wildcard[MAX_BIND_ADDRS]) {
  int num_fds = 0;
  int port = cfg->port > 0 ? cfg->port : DNS_PORT;
  int bind_count = cfg->bind_address_count;
  int opt = 1;
  int rcvbuf_size = cfg->udp_recvbuf_size > 0 ? cfg->udp_recvbuf_size : 4 * 1024 * 1024;
  int sndbuf_size = cfg->udp_sndbuf_size > 0 ? cfg->udp_sndbuf_size : 4 * 1024 * 1024;

  for (int i = 0; i < (bind_count > 0 ? bind_count : 1); i++) {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    bool is_v4 = false;
    bool is_v6 = false;
    bool is_wildcard = false;
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
      is_wildcard = true;
    } else {
      if (inet_pton(AF_INET, cfg->bind_addresses[i], &addr4.sin_addr) == 1) {
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons(port);
        is_v4 = true;
        if (addr4.sin_addr.s_addr == INADDR_ANY) is_wildcard = true;
      } else if (inet_pton(AF_INET6, cfg->bind_addresses[i],
                           &addr6.sin6_addr) == 1) {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        is_v6 = true;
        if (IN6_IS_ADDR_UNSPECIFIED(&addr6.sin6_addr)) is_wildcard = true;
      }
    }

    if (is_v4 && num_fds < MAX_BIND_ADDRS) {
      int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
      if (udp_fd >= 0) {
        setup_udp_socket_buffers(udp_fd, rcvbuf_size, sndbuf_size);
        fcntl(udp_fd, F_SETFL, fcntl(udp_fd, F_GETFL, 0) | O_NONBLOCK);
#ifdef SO_REUSEPORT_LB
        int opt_lb = 1;
        if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt_lb, sizeof(opt_lb)) < 0) {
          int opt_reuse = 1;
          setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt_reuse, sizeof(opt_reuse));
        }
#else
        int opt_reuse = 1;
        setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt_reuse, sizeof(opt_reuse));
#endif
        int opt_dst = 1;
#ifdef IP_RECVDSTADDR
        setsockopt(udp_fd, IPPROTO_IP, IP_RECVDSTADDR, &opt_dst, sizeof(opt_dst));
#elif defined(IP_PKTINFO)
        setsockopt(udp_fd, IPPROTO_IP, IP_PKTINFO, &opt_dst, sizeof(opt_dst));
#endif
        if (bind(udp_fd, (struct sockaddr *)&addr4, sizeof(addr4)) == 0) {
          out_is_wildcard[num_fds] = is_wildcard;
          out_fds[num_fds++] = udp_fd;
        } else {
          syslog(LOG_CRIT, "[Frontend] Failed to bind UDPv4 socket to %s:%d: %m",
                 (bind_count > 0 ? cfg->bind_addresses[i] : "0.0.0.0"), port);
          close(udp_fd);
          exit(EXIT_FAILURE);
        }
      }
    }
    if (is_v6 && num_fds < MAX_BIND_ADDRS) {
      int udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
      if (udp_fd >= 0) {
        setup_udp_socket_buffers(udp_fd, rcvbuf_size, sndbuf_size);
        fcntl(udp_fd, F_SETFL, fcntl(udp_fd, F_GETFL, 0) | O_NONBLOCK);
        setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
#ifdef SO_REUSEPORT_LB
        int opt_lb = 1;
        if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt_lb, sizeof(opt_lb)) < 0) {
          int opt_reuse = 1;
          setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt_reuse, sizeof(opt_reuse));
        }
#else
        int opt_reuse = 1;
        setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt_reuse, sizeof(opt_reuse));
#endif
        int opt_pktinfo = 1;
#ifdef IPV6_RECVPKTINFO
        setsockopt(udp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt_pktinfo, sizeof(opt_pktinfo));
#elif defined(IPV6_PKTINFO)
        setsockopt(udp_fd, IPPROTO_IPV6, IPV6_PKTINFO, &opt_pktinfo, sizeof(opt_pktinfo));
#endif
        if (bind(udp_fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0) {
          out_is_wildcard[num_fds] = is_wildcard;
          out_fds[num_fds++] = udp_fd;
        } else {
          syslog(LOG_CRIT, "[Frontend] Failed to bind UDPv6 socket to %s:%d: %m",
                 (bind_count > 0 ? cfg->bind_addresses[i] : "::"), port);
          close(udp_fd);
          exit(EXIT_FAILURE);
        }
      }
    }
  }
  return num_fds;
}

static void run_frontend_router(pid_t backend_pid, int router_id) {
  cpuset_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(router_id, &cpuset);
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(cpuset), &cpuset) < 0) {
    syslog(LOG_WARNING, "[Frontend %d] Failed to set CPU affinity: %m", router_id);
  }

  if (g_control_sock >= 0) {
    close(g_control_sock);
    g_control_sock = -1;
  }
  if (g_broker_sock >= 0) {
    close(g_broker_sock);
    g_broker_sock = -1;
  }

  // 自身が使用しない不要なIPCソケット端点を確実にクローズ (指示2)
  for (int f = 0; f < g_num_frontend_routers; f++) {
    for (int w = 0; w < g_num_workers; w++) {
      if (f != router_id) {
        close(g_ipc_fds[f][w][0]);
        close(g_ipc_fds[f][w][1]);
      } else {
        close(g_ipc_fds[f][w][1]); // 自身のWorker側端点をクローズ
      }
    }
  }
  if (router_id != 0) {
    close(g_notify_ipc[0]);
  }
  close(g_notify_ipc[1]);

  server_config_t *cfg = acquire_config_snapshot();

  // 特権破棄前に、外部UDPソケットをSO_REUSEPORT_LBでオープン・バインド (指示1: インデックス整合性の完全統一)
  int local_udp_fds[MAX_BIND_ADDRS];
  bool local_udp_is_wildcard[MAX_BIND_ADDRS];
  int local_num_udp_fds = open_router_udp_sockets(cfg, local_udp_fds, local_udp_is_wildcard);

  // 特権破棄 (setgid / setuid)
  if (cfg && cfg->user) {
    struct passwd *pwd = getpwnam(cfg->user);
    if (!pwd) {
      syslog(LOG_ERR, "[Frontend %d] user '%s' not found, aborting privilege drop", router_id, cfg->user);
      release_config_snapshot(cfg);
      exit(EXIT_FAILURE);
    }
    gid_t target_gid = pwd->pw_gid;
    if (cfg->group) {
      struct group *grp = getgrnam(cfg->group);
      if (!grp) {
        syslog(LOG_ERR, "[Frontend %d] group '%s' not found, aborting privilege drop", router_id, cfg->group);
        release_config_snapshot(cfg);
        exit(EXIT_FAILURE);
      }
      target_gid = grp->gr_gid;
    }
    if (setgroups(0, NULL) != 0) { syslog(LOG_ERR, "[Frontend %d] setgroups failed: %m", router_id); release_config_snapshot(cfg); exit(EXIT_FAILURE); }
    if (setgid(target_gid) != 0) { syslog(LOG_ERR, "[Frontend %d] setgid failed: %m", router_id); release_config_snapshot(cfg); exit(EXIT_FAILURE); }
    if (setuid(pwd->pw_uid) != 0) { syslog(LOG_ERR, "[Frontend %d] setuid failed: %m", router_id); release_config_snapshot(cfg); exit(EXIT_FAILURE); }
    
    if (getuid() != pwd->pw_uid || geteuid() != pwd->pw_uid || getgid() != target_gid || getegid() != target_gid) {
      syslog(LOG_ERR, "[Frontend %d] privilege drop verification failed", router_id);
      release_config_snapshot(cfg);
      exit(EXIT_FAILURE);
    }
  } else if (cfg && cfg->group) {
    struct group *grp = getgrnam(cfg->group);
    if (!grp) {
      syslog(LOG_ERR, "[Frontend %d] group '%s' not found, aborting privilege drop", router_id, cfg->group);
      release_config_snapshot(cfg);
      exit(EXIT_FAILURE);
    }
    if (setgroups(0, NULL) != 0) { syslog(LOG_ERR, "[Frontend %d] setgroups failed: %m", router_id); release_config_snapshot(cfg); exit(EXIT_FAILURE); }
    if (setgid(grp->gr_gid) != 0) { syslog(LOG_ERR, "[Frontend %d] setgid failed: %m", router_id); release_config_snapshot(cfg); exit(EXIT_FAILURE); }
    
    if (getgid() != grp->gr_gid || getegid() != grp->gr_gid) {
      syslog(LOG_ERR, "[Frontend %d] privilege drop verification failed (group only)", router_id);
      release_config_snapshot(cfg);
      exit(EXIT_FAILURE);
    }
  } else if (geteuid() == 0) {
    syslog(LOG_ERR, "[Frontend %d] Running as root with no 'user'/'group' configured; refusing to continue without privilege drop", router_id);
    fprintf(stderr, "[ERROR] [Frontend %d] Running as root with no 'user'/'group' configured; refusing to continue without privilege drop\n", router_id);
    release_config_snapshot(cfg);
    exit(EXIT_FAILURE);
  }
  release_config_snapshot(cfg);

  int kq = kqueue();
  if (kq < 0)
    exit(1);

  int notify_v4_sock = -1;
  int notify_v6_sock = -1;
  for (int i = 0; i < local_num_udp_fds; i++) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getsockname(local_udp_fds[i], (struct sockaddr *)&ss, &slen) == 0) {
      if (ss.ss_family == AF_INET) {
        if (notify_v4_sock == -1 || local_udp_is_wildcard[i]) {
          notify_v4_sock = local_udp_fds[i];
        }
      } else if (ss.ss_family == AF_INET6) {
        if (notify_v6_sock == -1 || local_udp_is_wildcard[i]) {
          notify_v6_sock = local_udp_fds[i];
        }
      }
    }
  }

  for (int i = 0; i < local_num_udp_fds; i++) {
    struct kevent ev;
    EV_SET(&ev, local_udp_fds[i], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
           (void *)(uintptr_t)i);
    kevent(kq, &ev, 1, NULL, 0, NULL);
  }
  for (int i = 0; i < g_num_workers; i++) {
    struct kevent ev;
    EV_SET(&ev, g_ipc_fds[router_id][i][0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
           (void *)(uintptr_t)(MAX_BIND_ADDRS + i));
    kevent(kq, &ev, 1, NULL, 0, NULL);
  }
  signal(SIGCHLD, SIG_DFL);
  if (router_id == 0) {
    struct kevent ev_notify;
    EV_SET(&ev_notify, g_notify_ipc[0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
           (void *)(uintptr_t)999);
    kevent(kq, &ev_notify, 1, NULL, 0, NULL);
  }

  pid_t parent_pid = getppid();
  struct kevent ev_proc;
  EV_SET(&ev_proc, backend_pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, (void *)1000);
  kevent(kq, &ev_proc, 1, NULL, 0, NULL);
  struct kevent ev_parent;
  EV_SET(&ev_parent, parent_pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, (void *)1001);
  kevent(kq, &ev_parent, 1, NULL, 0, NULL);
  if (getppid() != parent_pid) {
    exit(0);
  }

  frontend_router_ctx_t *fctx = calloc(1, sizeof(*fctx));
  if (!fctx) {
    syslog(LOG_CRIT, "[Frontend %d] Failed to allocate router context", router_id);
    exit(1);
  }
  for (int k = 0; k < UDP_BATCH_SIZE; k++) {
    udp_ipc_t *msg = (udp_ipc_t *)fctx->rx_buffers[k];
    fctx->rx_iov[k].iov_base = fctx->rx_buffers[k] + sizeof(udp_ipc_t);
    fctx->rx_iov[k].iov_len = BUFFER_SIZE;
    fctx->rx_msgs[k].msg_hdr.msg_iov = &fctx->rx_iov[k];
    fctx->rx_msgs[k].msg_hdr.msg_iovlen = 1;
    fctx->rx_msgs[k].msg_hdr.msg_name = &msg->client_addr;
    fctx->rx_msgs[k].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
    fctx->rx_msgs[k].msg_hdr.msg_control = fctx->rx_cbuf[k].buf;
    fctx->rx_msgs[k].msg_hdr.msg_controllen = sizeof(fctx->rx_cbuf[k].buf);

    fctx->ipc_tx_msgs[k].msg_hdr.msg_iov = &fctx->ipc_tx_iov[k];
    fctx->ipc_tx_msgs[k].msg_hdr.msg_iovlen = 1;
    fctx->ipc_tx_msgs[k].msg_hdr.msg_name = NULL;
    fctx->ipc_tx_msgs[k].msg_hdr.msg_namelen = 0;
    fctx->ipc_tx_msgs[k].msg_hdr.msg_control = NULL;
    fctx->ipc_tx_msgs[k].msg_hdr.msg_controllen = 0;

    fctx->ipc_rx_iov[k].iov_base = fctx->ipc_rx_buffers[k];
    fctx->ipc_rx_iov[k].iov_len = sizeof(fctx->ipc_rx_buffers[k]);
    fctx->ipc_rx_msgs[k].msg_hdr.msg_iov = &fctx->ipc_rx_iov[k];
    fctx->ipc_rx_msgs[k].msg_hdr.msg_iovlen = 1;
    fctx->ipc_rx_msgs[k].msg_hdr.msg_name = NULL;
    fctx->ipc_rx_msgs[k].msg_hdr.msg_namelen = 0;
    fctx->ipc_rx_msgs[k].msg_hdr.msg_control = NULL;
    fctx->ipc_rx_msgs[k].msg_hdr.msg_controllen = 0;

    fctx->cli_tx_msgs[k].msg_hdr.msg_iov = &fctx->cli_tx_iov[k];
    fctx->cli_tx_msgs[k].msg_hdr.msg_iovlen = 1;
    fctx->cli_tx_msgs[k].msg_hdr.msg_control = NULL;
    fctx->cli_tx_msgs[k].msg_hdr.msg_controllen = 0;
  }

  uint8_t buffer[65536];
  int rr = 0; // ラウンドロビン分配用
  struct kevent ev_list[128];
  syslog(LOG_NOTICE, "[Frontend %d] UDP Router process started.", router_id);

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
        if (router_id == 0) {
          while (1) {
            ssize_t len = recv(g_notify_ipc[0], buffer, sizeof(buffer), MSG_DONTWAIT);
            if (len < 0) break; // キューが空になった (EAGAIN等)
            if (len >= (ssize_t)sizeof(udp_ipc_t)) {
              udp_ipc_t *msg = (udp_ipc_t *)buffer;
              if (msg->sock_fd_idx == -2) {
                syslog(LOG_NOTICE, "[Frontend %d] Received stop command from backend. Shutting down cleanly.", router_id);
                exit(0);
              }
            }
          }
        }
        syslog(LOG_CRIT, "[Frontend %d] Backend process (pid=%d) exited unexpectedly. Shutting down.", router_id, backend_pid);
        exit(1);
      }
      if (ud == 1001) {
        syslog(LOG_NOTICE, "[Frontend %d] Parent supervisor process exited. Shutting down.", router_id);
        exit(0);
      }
      if (ud < MAX_BIND_ADDRS) {
        // (1) UDP Inbound -> IPC to Backend Worker (recvmmsg / sendmmsg バッチ化)
        int fd = local_udp_fds[ud];
        while (1) {
          for (int k = 0; k < UDP_BATCH_SIZE; k++) {
            fctx->rx_iov[k].iov_len = BUFFER_SIZE;
            fctx->rx_msgs[k].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
            fctx->rx_msgs[k].msg_hdr.msg_control = fctx->rx_cbuf[k].buf;
            fctx->rx_msgs[k].msg_hdr.msg_controllen = sizeof(fctx->rx_cbuf[k].buf);
          }
          int n_recv = recvmmsg(fd, fctx->rx_msgs, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);
          if (n_recv <= 0)
            break; // EAGAIN

          int tx_count = 0;
          for (int k = 0; k < n_recv; k++) {
            ssize_t len = (ssize_t)fctx->rx_msgs[k].msg_len;
            if (len >= DNS_HEADER_SIZE) {
              udp_ipc_t *msg = (udp_ipc_t *)fctx->rx_buffers[k];
              msg->sock_fd_idx = ud;
              msg->addr_len = fctx->rx_msgs[k].msg_hdr.msg_namelen;
              msg->has_source_addr = false;
              memset(&msg->source_addr, 0, sizeof(msg->source_addr));
              msg->payload_len = (uint16_t)len;

              for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&fctx->rx_msgs[k].msg_hdr);
                   cmsg != NULL;
                   cmsg = CMSG_NXTHDR(&fctx->rx_msgs[k].msg_hdr, cmsg)) {
#ifdef IP_RECVDSTADDR
                if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_addr))) {
                  struct sockaddr_in *sin = (struct sockaddr_in *)&msg->source_addr;
                  sin->sin_family = AF_INET;
                  memcpy(&sin->sin_addr, CMSG_DATA(cmsg), sizeof(struct in_addr));
                  msg->has_source_addr = true;
                  break;
                }
#endif
#ifdef IP_PKTINFO
                if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
                  struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
                  struct sockaddr_in *sin = (struct sockaddr_in *)&msg->source_addr;
                  sin->sin_family = AF_INET;
                  sin->sin_addr = pi->ipi_addr;
                  msg->has_source_addr = true;
                  break;
                }
#endif
#ifdef IPV6_PKTINFO
                if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
                  struct in6_pktinfo *pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
                  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg->source_addr;
                  sin6->sin6_family = AF_INET6;
                  sin6->sin6_addr = pi6->ipi6_addr;
                  msg->has_source_addr = true;
                  break;
                }
#endif
              }

              fctx->ipc_tx_iov[tx_count].iov_base = fctx->rx_buffers[k];
              fctx->ipc_tx_iov[tx_count].iov_len = sizeof(udp_ipc_t) + len;
              tx_count++;
            }
          }
          if (tx_count > 0 && g_num_workers > 0) {
            int target_worker = rr;
            sendmmsg(g_ipc_fds[router_id][target_worker][0], fctx->ipc_tx_msgs, tx_count, MSG_DONTWAIT);
            rr = (rr + 1) % g_num_workers;
          }
        }
      } else if (ud == 999 && router_id == 0) {
        // (2) Notify Outbound -> Pre-opened UDP Sockets (Capsicum safe)
        while (1) {
          ssize_t len = recv(g_notify_ipc[0], buffer, sizeof(buffer), MSG_DONTWAIT);
          if (len < (ssize_t)sizeof(udp_ipc_t))
            break; // EAGAIN

          udp_ipc_t *msg = (udp_ipc_t *)buffer;
          if (msg->sock_fd_idx == -2) {
            syslog(LOG_NOTICE, "[Frontend %d] Received stop command from backend. Shutting down cleanly.", router_id);
            exit(0);
          }
          int target_sock = -1;
          int target_sock_idx = -1;
          if (msg->has_source_addr) {
            for (int k = 0; k < local_num_udp_fds; k++) {
              struct sockaddr_storage ss;
              socklen_t slen = sizeof(ss);
              if (getsockname(local_udp_fds[k], (struct sockaddr *)&ss, &slen) == 0 &&
                  ss.ss_family == msg->source_addr.ss_family) {
                if (ss.ss_family == AF_INET) {
                  struct sockaddr_in *sin1 = (struct sockaddr_in *)&ss;
                  struct sockaddr_in *sin2 = (struct sockaddr_in *)&msg->source_addr;
                  if (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr) {
                    target_sock = local_udp_fds[k];
                    target_sock_idx = k;
                    break;
                  }
                } else if (ss.ss_family == AF_INET6) {
                  struct sockaddr_in6 *sin1 = (struct sockaddr_in6 *)&ss;
                  struct sockaddr_in6 *sin2 = (struct sockaddr_in6 *)&msg->source_addr;
                  if (memcmp(&sin1->sin6_addr, &sin2->sin6_addr, sizeof(struct in6_addr)) == 0) {
                    target_sock = local_udp_fds[k];
                    target_sock_idx = k;
                    break;
                  }
                }
              }
            }
          }
          if (target_sock < 0) {
            if (msg->client_addr.ss_family == AF_INET) {
              target_sock = notify_v4_sock;
            } else if (msg->client_addr.ss_family == AF_INET6) {
              target_sock = notify_v6_sock;
            }
            if (target_sock >= 0) {
              for (int k = 0; k < local_num_udp_fds; k++) {
                if (local_udp_fds[k] == target_sock) {
                  target_sock_idx = k;
                  break;
                }
              }
            }
          }
          if (target_sock >= 0) {
            bool is_wildcard = (target_sock_idx >= 0 && target_sock_idx < local_num_udp_fds) ? local_udp_is_wildcard[target_sock_idx] : false;
            struct msghdr out_msg;
            memset(&out_msg, 0, sizeof(out_msg));
            struct iovec out_iov;
            out_iov.iov_base = buffer + sizeof(udp_ipc_t);
            out_iov.iov_len = msg->payload_len;
            out_msg.msg_iov = &out_iov;
            out_msg.msg_iovlen = 1;
            out_msg.msg_name = &msg->client_addr;
            out_msg.msg_namelen = msg->addr_len;

            router_cmsg_buf_t cbuf;
            memset(&cbuf, 0, sizeof(cbuf));

#ifdef IP_SENDSRCADDR
            if (is_wildcard && msg->has_source_addr && msg->source_addr.ss_family == AF_INET) {
              struct cmsghdr *cmsg = (struct cmsghdr *)cbuf.buf;
              cmsg->cmsg_level = IPPROTO_IP;
              cmsg->cmsg_type = IP_SENDSRCADDR;
              cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
              struct in_addr *src = (struct in_addr *)CMSG_DATA(cmsg);
              *src = ((struct sockaddr_in *)&msg->source_addr)->sin_addr;
              out_msg.msg_control = cbuf.buf;
              out_msg.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
            }
#elif defined(IP_PKTINFO)
            if (is_wildcard && msg->has_source_addr && msg->source_addr.ss_family == AF_INET) {
              struct cmsghdr *cmsg = (struct cmsghdr *)cbuf.buf;
              cmsg->cmsg_level = IPPROTO_IP;
              cmsg->cmsg_type = IP_PKTINFO;
              cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
              struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
              memset(pi, 0, sizeof(*pi));
              pi->ipi_spec_dst = ((struct sockaddr_in *)&msg->source_addr)->sin_addr;
              out_msg.msg_control = cbuf.buf;
              out_msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
            }
#endif
#ifdef IPV6_PKTINFO
            else if (is_wildcard && msg->has_source_addr && msg->source_addr.ss_family == AF_INET6) {
              struct cmsghdr *cmsg = (struct cmsghdr *)cbuf.buf;
              cmsg->cmsg_level = IPPROTO_IPV6;
              cmsg->cmsg_type = IPV6_PKTINFO;
              cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
              struct in6_pktinfo *pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
              memset(pi6, 0, sizeof(*pi6));
              pi6->ipi6_addr = ((struct sockaddr_in6 *)&msg->source_addr)->sin6_addr;
              out_msg.msg_control = cbuf.buf;
              out_msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
            }
#endif
            if (out_msg.msg_control != NULL) {
              sendmsg(target_sock, &out_msg, 0);
            } else {
              sendto(target_sock, buffer + sizeof(udp_ipc_t), msg->payload_len, 0,
                     (struct sockaddr *)&msg->client_addr, msg->addr_len);
            }
          } else {
            syslog(LOG_WARNING, "[Frontend %d] No suitable socket found to send NOTIFY (family=%d)",
                   router_id, (int)msg->client_addr.ss_family);
          }
        }
      } else if (ud >= MAX_BIND_ADDRS && ud < 999) {
        // (3) IPC Inbound from Backend -> UDP Outbound (recvmmsg / sendmmsg バッチ化)
        int worker_idx = ud - MAX_BIND_ADDRS;
        int fd = g_ipc_fds[router_id][worker_idx][0];
        while (1) {
          for (int k = 0; k < UDP_BATCH_SIZE; k++) {
            fctx->ipc_rx_iov[k].iov_len = sizeof(fctx->ipc_rx_buffers[k]);
          }
          int n_recv = recvmmsg(fd, fctx->ipc_rx_msgs, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);
          if (n_recv <= 0)
            break; // EAGAIN

          int cur_sock_idx = -1;
          int tx_count = 0;

          for (int k = 0; k < n_recv; k++) {
            ssize_t len = (ssize_t)fctx->ipc_rx_msgs[k].msg_len;
            if (len < (ssize_t)sizeof(udp_ipc_t))
              continue;
            udp_ipc_t *msg = (udp_ipc_t *)fctx->ipc_rx_buffers[k];
            ssize_t max_valid_payload = len - (ssize_t)sizeof(udp_ipc_t);
            if (msg->payload_len > max_valid_payload) {
              syslog(LOG_WARNING, "[Frontend %d] Dropping backend reply with inconsistent payload_len", router_id);
              continue;
            }
            if (msg->sock_fd_idx < 0 || msg->sock_fd_idx >= local_num_udp_fds) {
              continue;
            }

            if (cur_sock_idx != -1 && msg->sock_fd_idx != cur_sock_idx && tx_count > 0) {
              sendmmsg(local_udp_fds[cur_sock_idx], fctx->cli_tx_msgs, tx_count, MSG_DONTWAIT);
              tx_count = 0;
            }
            cur_sock_idx = msg->sock_fd_idx;

            fctx->cli_tx_iov[tx_count].iov_base = fctx->ipc_rx_buffers[k] + sizeof(udp_ipc_t);
            fctx->cli_tx_iov[tx_count].iov_len = msg->payload_len;
            memcpy(&fctx->cli_tx_addrs[tx_count], &msg->client_addr, msg->addr_len);
            fctx->cli_tx_msgs[tx_count].msg_hdr.msg_name = &fctx->cli_tx_addrs[tx_count];
            fctx->cli_tx_msgs[tx_count].msg_hdr.msg_namelen = msg->addr_len;

            bool is_wildcard = (cur_sock_idx >= 0 && cur_sock_idx < local_num_udp_fds) ? local_udp_is_wildcard[cur_sock_idx] : false;
#ifdef IP_SENDSRCADDR
            if (is_wildcard && msg->has_source_addr && msg->source_addr.ss_family == AF_INET) {
              memset(&fctx->cli_tx_cbuf[tx_count], 0, sizeof(fctx->cli_tx_cbuf[tx_count]));
              struct cmsghdr *cmsg = (struct cmsghdr *)fctx->cli_tx_cbuf[tx_count].buf;
              cmsg->cmsg_level = IPPROTO_IP;
              cmsg->cmsg_type = IP_SENDSRCADDR;
              cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
              struct in_addr *src = (struct in_addr *)CMSG_DATA(cmsg);
              *src = ((struct sockaddr_in *)&msg->source_addr)->sin_addr;
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_control = fctx->cli_tx_cbuf[tx_count].buf;
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
            }
#elif defined(IP_PKTINFO)
            if (is_wildcard && msg->has_source_addr && msg->source_addr.ss_family == AF_INET) {
              memset(&fctx->cli_tx_cbuf[tx_count], 0, sizeof(fctx->cli_tx_cbuf[tx_count]));
              struct cmsghdr *cmsg = (struct cmsghdr *)fctx->cli_tx_cbuf[tx_count].buf;
              cmsg->cmsg_level = IPPROTO_IP;
              cmsg->cmsg_type = IP_PKTINFO;
              cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
              struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
              memset(pi, 0, sizeof(*pi));
              pi->ipi_spec_dst = ((struct sockaddr_in *)&msg->source_addr)->sin_addr;
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_control = fctx->cli_tx_cbuf[tx_count].buf;
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
            }
#endif
#ifdef IPV6_PKTINFO
            else if (is_wildcard && msg->has_source_addr && msg->source_addr.ss_family == AF_INET6) {
              memset(&fctx->cli_tx_cbuf[tx_count], 0, sizeof(fctx->cli_tx_cbuf[tx_count]));
              struct cmsghdr *cmsg = (struct cmsghdr *)fctx->cli_tx_cbuf[tx_count].buf;
              cmsg->cmsg_level = IPPROTO_IPV6;
              cmsg->cmsg_type = IPV6_PKTINFO;
              cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
              struct in6_pktinfo *pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
              memset(pi6, 0, sizeof(*pi6));
              pi6->ipi6_addr = ((struct sockaddr_in6 *)&msg->source_addr)->sin6_addr;
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_control = fctx->cli_tx_cbuf[tx_count].buf;
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
            }
#endif
            else {
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_control = NULL;
              fctx->cli_tx_msgs[tx_count].msg_hdr.msg_controllen = 0;
            }
            tx_count++;
          }
          if (tx_count > 0 && cur_sock_idx >= 0 && cur_sock_idx < local_num_udp_fds) {
            sendmmsg(local_udp_fds[cur_sock_idx], fctx->cli_tx_msgs, tx_count, MSG_DONTWAIT);
            tx_count = 0;
          }
        }
      }
    }
  }
}

// ============================================================================
// 14. メインエントリーポイント & UDP/IPC 初期化
// ============================================================================

static pid_t g_supervisor_pid = 0;
static char g_pid_file_path[1024] = "";
static int g_pid_fd = -1;
static volatile sig_atomic_t g_supervisor_should_exit = 0;

static void supervisor_sig_handler(int sig) {
  (void)sig;
  g_supervisor_should_exit = 1;
}

static void cleanup_pid_file(void) {
  if (g_supervisor_pid != 0 && getpid() == g_supervisor_pid) {
    if (g_pid_fd >= 0) {
      close(g_pid_fd);
      g_pid_fd = -1;
    }
    if (g_pid_file_path[0] != '\0') {
      unlink(g_pid_file_path);
      g_pid_file_path[0] = '\0';
    }
  }
}

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
  if (fd < 0)
    return; // /dev/null を開けなければ諦める
  if (fd != STDIN_FILENO) {
    /* [L-1] fd が stdin でない場合は dup2 で stdin に持ってきて元の fd を閉じる */
    dup2(fd, STDIN_FILENO);
    close(fd);
    fd = STDIN_FILENO;
  }
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  cap_rights_t io_rights;
  cap_rights_init(&io_rights, CAP_READ, CAP_WRITE, CAP_FSTAT);
  for (int stdio_fd = STDIN_FILENO; stdio_fd <= STDERR_FILENO; stdio_fd++)
    cap_rights_limit(stdio_fd, &io_rights);
}

static void setup_ipc_tables(int num_workers) {
  g_num_workers = num_workers;
  for (int f = 0; f < g_num_frontend_routers; f++) {
    for (int w = 0; w < num_workers; w++) {
      if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_ipc_fds[f][w]) < 0) {
        syslog(LOG_CRIT, "[IPC] Failed to create socketpair for router %d worker %d: %m", f, w);
        exit(1);
      }
      fcntl(g_ipc_fds[f][w][0], F_SETFL,
            fcntl(g_ipc_fds[f][w][0], F_GETFL, 0) | O_NONBLOCK);
      fcntl(g_ipc_fds[f][w][1], F_SETFL,
            fcntl(g_ipc_fds[f][w][1], F_GETFL, 0) | O_NONBLOCK);
      int bufsize = 4 * 1024 * 1024; // 4MB
      setsockopt(g_ipc_fds[f][w][0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
      setsockopt(g_ipc_fds[f][w][0], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
      setsockopt(g_ipc_fds[f][w][1], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
      setsockopt(g_ipc_fds[f][w][1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }
  }

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc) < 0) {
    syslog(LOG_CRIT, "[IPC] Failed to create notify socketpair: %m");
    exit(1);
  }
  fcntl(g_notify_ipc[0], F_SETFL,
        fcntl(g_notify_ipc[0], F_GETFL, 0) | O_NONBLOCK);
  fcntl(g_notify_ipc[1], F_SETFL,
        fcntl(g_notify_ipc[1], F_GETFL, 0) | O_NONBLOCK);
  int nbufsize = 1024 * 1024; // 1MB
  setsockopt(g_notify_ipc[0], SOL_SOCKET, SO_RCVBUF, &nbufsize, sizeof(nbufsize));
  setsockopt(g_notify_ipc[0], SOL_SOCKET, SO_SNDBUF, &nbufsize, sizeof(nbufsize));
  setsockopt(g_notify_ipc[1], SOL_SOCKET, SO_RCVBUF, &nbufsize, sizeof(nbufsize));
  setsockopt(g_notify_ipc[1], SOL_SOCKET, SO_SNDBUF, &nbufsize, sizeof(nbufsize));
  cap_rights_t n_rights_0, n_rights_1;
  cap_rights_init(&n_rights_0, CAP_RECV, CAP_EVENT);
  cap_rights_limit(g_notify_ipc[0], &n_rights_0);
  cap_rights_init(&n_rights_1, CAP_SEND, CAP_EVENT, CAP_FCNTL);
  cap_rights_limit(g_notify_ipc[1], &n_rights_1);
}

int main(int argc, char **argv) {
  assert(calc_fnv1a_str("*.") == FNV1A_WILDCARD_PREFIX_HASH);
  init_server_cookie_secret();
  rrl_init();
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
  {
    SHA_CTX dummy_sha;
    uint8_t dummy_digest[20];
    SHA1_Init(&dummy_sha);
    SHA1_Update(&dummy_sha, "dummy", 5);
    SHA1_Final(dummy_digest, &dummy_sha);
  }

  bool foreground = false;
  const char *config_file = NULL;
  const char *cli_pid_file = NULL;

  for (int i = 1; i < argc; i++) {
      if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
          printf("KariDNS %s\n", KARIDNS_VERSION);
          return 0;
      } else if (strcmp(argv[i], "-f") == 0) {
          foreground = true;
      } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
          config_file = argv[++i];
      } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
          const char *val = argv[++i];
          if (isdigit((unsigned char)val[0])) {
              g_cli_port_override = atoi(val);
          } else {
              cli_pid_file = val;
          }
      } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
          cli_pid_file = argv[++i];
      } else {
          config_file = argv[i];
      }
  }

  if (!config_file) {
    fprintf(stderr, "Usage: %s [-v | --version] [-f] [-p <port|pid_file>] [-P <pid_file>] [-c <config_file> | <config_file>]\n", argv[0]);
    syslog(LOG_ERR, "Usage: %s [-v | --version] [-f] [-p <port|pid_file>] [-P <pid_file>] [-c <config_file> | <config_file>]", argv[0]);
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
  syslog(LOG_INFO, "Starting KariDNS %s...", KARIDNS_VERSION);

  char *config_str = read_entire_file(g_config_path, NULL, NULL);
  if (!config_str)
    return 1;
  if (parse_named_conf_ext(config_str, g_config_path, &g_config_db.config_a) != 0) {
    free(config_str);
    return 1;
  }
  free(config_str);

  if (g_cli_port_override > 0) {
    g_config_db.config_a.port = g_cli_port_override;
  }

  if (!foreground) {
    daemonize();
  }
  start_connect_broker();

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGHUP);
  sigprocmask(SIG_BLOCK, &set, NULL);

  const char *effective_pid_file = NULL;
  if (cli_pid_file) {
    effective_pid_file = cli_pid_file;
  } else if (g_config_db.config_a.pid_file) {
    effective_pid_file = g_config_db.config_a.pid_file;
  } else if (!foreground) {
    effective_pid_file = "/var/run/karidns/karidns.pid";
  }

  if (effective_pid_file && strcmp(effective_pid_file, "none") != 0 && effective_pid_file[0] != '\0') {
    strncpy(g_pid_file_path, effective_pid_file, sizeof(g_pid_file_path) - 1);
    g_pid_file_path[sizeof(g_pid_file_path) - 1] = '\0';
    g_supervisor_pid = getpid();
    atexit(cleanup_pid_file);

    char dir_buf[1024];
    strncpy(dir_buf, effective_pid_file, sizeof(dir_buf) - 1);
    dir_buf[sizeof(dir_buf) - 1] = '\0';
    char *slash = strrchr(dir_buf, '/');
    if (slash && slash != dir_buf) {
      *slash = '\0';
      mkdir(dir_buf, 0755);
    }
    g_pid_fd = open(effective_pid_file, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (g_pid_fd < 0) {
      syslog(LOG_ERR, "Failed to open pidfile %s: %s", effective_pid_file, strerror(errno));
      fprintf(stderr, "Failed to open pidfile %s: %s\n", effective_pid_file, strerror(errno));
      cleanup_pid_file();
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
    if (flock(g_pid_fd, LOCK_EX | LOCK_NB) < 0) {
      syslog(LOG_ERR, "Another KariDNS instance is already running (pidfile %s locked)", effective_pid_file);
      fprintf(stderr, "Another KariDNS instance is already running (pidfile %s locked).\n", effective_pid_file);
      cleanup_pid_file();
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
    ftruncate(g_pid_fd, 0);
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", (int)getpid());
    write(g_pid_fd, pid_str, strlen(pid_str));
  }

  // 特権分離が本サーバの前提とするセキュリティモデルであるため、
  // rootとして起動された場合は user の明示的指定を必須とする。
  if (geteuid() == 0 && !g_config_db.config_a.user) {
    syslog(LOG_ERR,
           "[Config] Server started as root but no 'user' directive is set in options{}. "
           "Refusing to start: running as root without privilege drop is not permitted. "
           "Add 'user \"named\";' (and optionally 'group \"named\";') to the options block.");
    fprintf(stderr,
           "[ERROR] Server started as root but no 'user' directive is set in options{}. "
           "Refusing to start: running as root without privilege drop is not permitted. "
           "Add 'user \"named\";' (and optionally 'group \"named\";') to the options block.\n");
    cleanup_pid_file();
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }

  init_logging_channels(&g_config_db.config_a);
  atomic_init(&g_config_db.active, &g_config_db.config_a);
  rebuild_zone_db_from_config(&g_config_db.config_a, false);

  int total_cores = sysconf(_SC_NPROCESSORS_ONLN);
  if (total_cores <= 0)
    total_cores = 1;
  int num_workers = 1;
  if (total_cores <= 3) {
    g_num_frontend_routers = 1;
    num_workers = (total_cores >= 3) ? 2 : 1;
  } else if (total_cores <= 6) {
    g_num_frontend_routers = 2;
    num_workers = total_cores - 2;
  } else {
    g_num_frontend_routers = 2;
    num_workers = total_cores - 2;
  }
  if (g_num_frontend_routers > MAX_FRONTEND_ROUTERS)
    g_num_frontend_routers = MAX_FRONTEND_ROUTERS;
  if (num_workers > MAX_WORKERS)
    num_workers = MAX_WORKERS;

  setup_ipc_tables(num_workers);

  if (g_config_db.config_a.control.enabled) {
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    const char *sock_path = g_config_db.config_a.control.socket_path ?
                            g_config_db.config_a.control.socket_path :
                            "/var/run/karidns/control.sock";
    if (strlen(sock_path) >= sizeof(un.sun_path)) {
      syslog(LOG_ERR, "Control socket path too long (max %zu bytes): %s", sizeof(un.sun_path) - 1, sock_path);
      fprintf(stderr, "Control socket path too long (max %zu bytes): %s\n", sizeof(un.sun_path) - 1, sock_path);
      cleanup_pid_file();
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
    char dir_buf[1024];
    strncpy(dir_buf, sock_path, sizeof(dir_buf) - 1);
    dir_buf[sizeof(dir_buf) - 1] = '\0';
    char *slash = strrchr(dir_buf, '/');
    if (slash && slash != dir_buf) {
      *slash = '\0';
      mkdir(dir_buf, 0755);
    }
    strncpy(un.sun_path, sock_path, sizeof(un.sun_path) - 1);
    unlink(un.sun_path);
    g_control_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_control_sock >= 0) {
      mode_t old_mask = umask(0177);
      if (bind(g_control_sock, (struct sockaddr *)&un, sizeof(un)) == 0) {
        fcntl(g_control_sock, F_SETFL, fcntl(g_control_sock, F_GETFL, 0) | O_NONBLOCK);
        listen(g_control_sock, 128);
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

  pid_t backend_pid = fork();
  if (backend_pid < 0) {
    syslog(LOG_CRIT, "fork for backend process failed: %m");
    if (g_broker_pid > 0) kill(g_broker_pid, SIGTERM);
    cleanup_pid_file();
    exit(1);
  }

  if (backend_pid > 0) {
    // === Parent Process (Process Manager / Supervisor) ===
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    pid_t router_pids[MAX_FRONTEND_ROUTERS];
    for (int r = 0; r < g_num_frontend_routers; r++) {
      pid_t rpid = fork();
      if (rpid < 0) {
        syslog(LOG_CRIT, "fork for frontend router %d failed: %m", r);
        kill(backend_pid, SIGTERM);
        for (int k = 0; k < r; k++) kill(router_pids[k], SIGTERM);
        if (g_broker_pid > 0) kill(g_broker_pid, SIGTERM);
        cleanup_pid_file();
        exit(1);
      }
      if (rpid == 0) {
        // Frontend Router Process
        g_pid_file_path[0] = '\0';
        if (g_pid_fd >= 0) {
          close(g_pid_fd);
          g_pid_fd = -1;
        }
        if (g_broker_sock >= 0) {
          close(g_broker_sock);
          g_broker_sock = -1;
        }
        run_frontend_router(backend_pid, r);
        exit(0);
      }
      router_pids[r] = rpid;
    }

    // 親プロセス（Manager）はすべての不要なIPCソケット・制御ソケットを確実にクローズ (指示2)
    for (int f = 0; f < g_num_frontend_routers; f++) {
      for (int w = 0; w < num_workers; w++) {
        close(g_ipc_fds[f][w][0]);
        close(g_ipc_fds[f][w][1]);
      }
    }
    close(g_notify_ipc[0]);
    close(g_notify_ipc[1]);
    if (g_control_sock >= 0) {
      close(g_control_sock);
      g_control_sock = -1;
    }
    if (g_broker_sock >= 0) {
      close(g_broker_sock);
      g_broker_sock = -1;
    }

    // 子プロセスの死活監視ループ (いずれかの子プロセスが終了した場合は全子プロセスを停止)
    pid_t dead = 0;
    int child_exit_code = 0;
    while (!g_supervisor_should_exit) {
      int status;
      dead = wait(&status);
      if (dead > 0) {
        if (WIFEXITED(status)) {
          int code = WEXITSTATUS(status);
          if (code != 0) child_exit_code = code;
          syslog(code == 0 ? LOG_NOTICE : LOG_CRIT,
                 "[Manager] Child process %d exited (status=%d). Terminating all children.", dead, code);
        } else if (WIFSIGNALED(status)) {
          child_exit_code = 128 + WTERMSIG(status);
          syslog(LOG_CRIT, "[Manager] Child process %d killed by signal %d. Terminating all children.", dead, WTERMSIG(status));
        } else {
          child_exit_code = 1;
        }
        break;
      }
      if (dead < 0 && errno == ECHILD) {
        break;
      }
      if (dead < 0 && errno == EINTR) {
        continue;
      }
    }
    if (g_supervisor_should_exit && dead <= 0) {
      syslog(LOG_INFO, "[Manager] Received termination signal. Shutting down children.");
    }
    kill(backend_pid, SIGTERM);
    for (int r = 0; r < g_num_frontend_routers; r++) {
      kill(router_pids[r], SIGTERM);
    }
    if (g_broker_pid > 0) {
      kill(g_broker_pid, SIGTERM);
    }
    while (1) {
      int status;
      pid_t w = wait(&status);
      if (w > 0) {
        if (WIFEXITED(status)) {
          int code = WEXITSTATUS(status);
          if (code != 0) {
            if (w == backend_pid || child_exit_code == 0) {
              child_exit_code = code;
            }
          }
        } else if (WIFSIGNALED(status)) {
          if (child_exit_code == 0 && WTERMSIG(status) != SIGTERM) {
            child_exit_code = 128 + WTERMSIG(status);
          }
        }
        continue;
      }
      if (w < 0 && errno == EINTR) continue;
      break;
    }
    if (!g_supervisor_should_exit && child_exit_code == 0) {
      child_exit_code = 1;
    }
    cleanup_pid_file();
    exit(child_exit_code);
  }

  // === Backend Process (backend_pid == 0) ===
  g_pid_file_path[0] = '\0';
  if (g_pid_fd >= 0) {
    close(g_pid_fd);
    g_pid_fd = -1;
  }

  // 指示2: Backendプロセス側もFrontend用端点を直ちにclose
  for (int f = 0; f < g_num_frontend_routers; f++) {
    for (int w = 0; w < num_workers; w++) {
      close(g_ipc_fds[f][w][0]); // Frontend側端点をクローズ
    }
  }
  close(g_notify_ipc[0]); // Frontend側端点をクローズ
  init_async_io_pool();

  pthread_t control_thread;
  if (pthread_create(&control_thread, NULL, control_thread_func, NULL) != 0)
    exit(1);

  server_config_t *cfg = &g_config_db.config_a;
  uint32_t qlog_buf_size = cfg->query_log_buffer_size;
  if (qlog_buf_size < 1024 || (qlog_buf_size & (qlog_buf_size - 1)) != 0) {
    qlog_buf_size = 32768;
  }

  pthread_t *threads = calloc(num_workers, sizeof(pthread_t));
  worker_ctx_t *ctxs = calloc(num_workers, sizeof(worker_ctx_t));
  if (!threads || !ctxs)
    exit(1);
  g_worker_ctxs = ctxs;
  g_worker_count = num_workers;
  for (int i = 0; i < num_workers; i++) {
    ctxs[i].thread_id = i;
    ctxs[i].core_id = (g_num_frontend_routers + i) % total_cores;
    ctxs[i].qlog_ring.size = qlog_buf_size;
    ctxs[i].qlog_ring.mask = qlog_buf_size - 1;
    ctxs[i].qlog_ring.events = calloc(qlog_buf_size, sizeof(qlog_event_t));
    atomic_init(&ctxs[i].qlog_ring.head, 0);
    atomic_init(&ctxs[i].qlog_ring.tail, 0);
    atomic_init(&ctxs[i].qlog_ring.dropped_count, 0);

    uint32_t dnstap_buf_size = (cfg->dnstap.queue_size >= 64) ? cfg->dnstap.queue_size : 4096;
    if ((dnstap_buf_size & (dnstap_buf_size - 1)) != 0) {
      uint32_t p = 1;
      while (p < dnstap_buf_size) p <<= 1;
      dnstap_buf_size = p;
    }
    ctxs[i].dnstap_ring.size = dnstap_buf_size;
    ctxs[i].dnstap_ring.mask = dnstap_buf_size - 1;
    ctxs[i].dnstap_ring.events = calloc(dnstap_buf_size, sizeof(dnstap_event_t));
    atomic_init(&ctxs[i].dnstap_ring.head, 0);
    atomic_init(&ctxs[i].dnstap_ring.tail, 0);
    atomic_init(&ctxs[i].dnstap_ring.dropped, 0);

    atomic_init(&ctxs[i].query_count, 0);
    if (!ctxs[i].qlog_ring.events || !ctxs[i].dnstap_ring.events)
      exit(EXIT_FAILURE);
    if (pthread_create(&threads[i], NULL, worker_thread_func, &ctxs[i]) != 0)
      exit(EXIT_FAILURE);
  }

  uint32_t dnstap_aux_buf_size = (cfg->dnstap.queue_size >= 64) ? cfg->dnstap.queue_size : 4096;
  if ((dnstap_aux_buf_size & (dnstap_aux_buf_size - 1)) != 0) {
    uint32_t p = 1;
    while (p < dnstap_aux_buf_size) p <<= 1;
    dnstap_aux_buf_size = p;
  }
  g_aux_dnstap_ring.size = dnstap_aux_buf_size;
  g_aux_dnstap_ring.mask = dnstap_aux_buf_size - 1;
  g_aux_dnstap_ring.events = calloc(dnstap_aux_buf_size, sizeof(dnstap_aux_event_t));
  atomic_init(&g_aux_dnstap_ring.head, 0);
  atomic_init(&g_aux_dnstap_ring.tail, 0);
  atomic_init(&g_aux_dnstap_ring.dropped, 0);

  while (atomic_load(&g_bound_workers) < num_workers)
    sched_yield();

  // 重要: type "program" ゾーンの子プロセスへの権限降格(program-user)は
  // fork元(karidns自身)がまだroot権限を持っている間でなければ成立しない
  // (POSIXでは非root→別の非rootユーザへのsetuid()は許可されない)。
  // そのため、必ずkaridns自身のsetuid/setgid(直後のブロック)より前に
  // プラグインをspawnすること。この順序を変更してはならない。
  spawn_program_zone_plugins(&g_config_db.config_a);

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

    if (getuid() != pwd->pw_uid || geteuid() != pwd->pw_uid ||
        getgid() != target_gid || getegid() != target_gid) {
      syslog(LOG_ERR, "[Backend] privilege drop verification failed");
      exit(EXIT_FAILURE);
    }
  } else if (cfg->group) {
    struct group *grp = getgrnam(cfg->group);
    if (!grp)
      exit(EXIT_FAILURE);
    if (setgroups(0, NULL) != 0)
      exit(EXIT_FAILURE);
    if (setgid(grp->gr_gid) != 0)
      exit(EXIT_FAILURE);

    if (getgid() != grp->gr_gid || getegid() != grp->gr_gid) {
      syslog(LOG_ERR, "[Backend] privilege drop verification failed (group only)");
      exit(EXIT_FAILURE);
    }
  } else if (geteuid() == 0) {
    syslog(LOG_ERR, "[Backend] Running as root with no 'user'/'group' configured; refusing to continue without privilege drop");
    fprintf(stderr, "[ERROR] [Backend] Running as root with no 'user'/'group' configured; refusing to continue without privilege drop\n");
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
  pthread_t query_logger_thread;
  if (pthread_create(&query_logger_thread, NULL, query_logger_thread_func, NULL) != 0) exit(1);

  if (cfg->dnstap.enabled && cfg->dnstap.socket_path) {
    g_dnstap_sock = dnstap_connect_and_handshake(cfg->dnstap.socket_path, cfg->dnstap.identity, cfg->dnstap.version);
    if (g_dnstap_sock >= 0) {
      atomic_store_explicit(&g_dnstap_connected, true, memory_order_release);
      syslog(LOG_NOTICE, "[dnstap] connected and handshaked to %s", cfg->dnstap.socket_path);
      fprintf(stderr, "[dnstap] connected and handshaked to %s\n", cfg->dnstap.socket_path);
    } else {
      syslog(LOG_WARNING, "[dnstap] failed to connect to %s, dnstap disabled", cfg->dnstap.socket_path);
      fprintf(stderr, "[dnstap] failed to connect to %s, dnstap disabled\n", cfg->dnstap.socket_path);
      if (cfg->dnstap.require_connect) {
        syslog(LOG_ERR, "[dnstap] require-connect is enabled and connection failed, aborting startup");
        fprintf(stderr, "[dnstap] require-connect is enabled and connection failed, aborting startup\n");
        exit(EXIT_FAILURE);
      }
    }
  }
  pthread_t dnstap_sender_thread;
  if (pthread_create(&dnstap_sender_thread, NULL, dnstap_sender_thread_func, NULL) != 0) {
    syslog(LOG_ERR, "[dnstap] failed to create sender thread");
    exit(1);
  }
  
  enter_capsicum_sandbox(); // サンドボックス突入

  // 特権分離(setuid+Capsicum)が完了したため、各Workerスレッドにクエリ処理の開始を許可する
  atomic_store_explicit(&g_privilege_drop_complete, true, memory_order_release);

  for (int i = 0; i < num_workers; i++)
    pthread_join(threads[i], NULL);
  pthread_join(control_thread, NULL);

  // シャットダウン前にリングバッファ内の未送信dnstapイベントを確実にドレイン
  if (atomic_load_explicit(&g_dnstap_connected, memory_order_relaxed)) {
    uint8_t shutdown_scratch_buf[65535 + 128];
    if (num_workers > 0 && ctxs) {
      for (int w = 0; w < num_workers; w++) {
        dnstap_ring_t *ring = &ctxs[w].dnstap_ring;
        if (!ring->events) continue;
        uint32_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
        uint32_t h = atomic_load_explicit(&ring->head, memory_order_acquire);
        while (t != h) {
          dnstap_event_t *ev = &ring->events[t & ring->mask];
          dnstap_send_frame(&ev->meta, ev->wire, ev->wire_len, shutdown_scratch_buf, sizeof(shutdown_scratch_buf));
          t++;
        }
        atomic_store_explicit(&ring->tail, t, memory_order_release);
      }
    }
    if (g_aux_dnstap_ring.events) {
      uint32_t t = atomic_load_explicit(&g_aux_dnstap_ring.tail, memory_order_relaxed);
      uint32_t h = atomic_load_explicit(&g_aux_dnstap_ring.head, memory_order_acquire);
      while (t != h) {
        dnstap_aux_event_t *ev = &g_aux_dnstap_ring.events[t & g_aux_dnstap_ring.mask];
        if (atomic_load_explicit(&ev->ready, memory_order_acquire)) {
          dnstap_send_frame(&ev->meta, ev->wire, ev->wire_len, shutdown_scratch_buf, sizeof(shutdown_scratch_buf));
          atomic_store_explicit(&ev->ready, false, memory_order_release);
        }
        t++;
      }
      atomic_store_explicit(&g_aux_dnstap_ring.tail, t, memory_order_release);
    }
  }

  for (int i = 0; i < num_workers; i++) {
    if (ctxs[i].qlog_ring.events) {
      free(ctxs[i].qlog_ring.events);
      ctxs[i].qlog_ring.events = NULL;
    }
    if (ctxs[i].dnstap_ring.events) {
      free(ctxs[i].dnstap_ring.events);
      ctxs[i].dnstap_ring.events = NULL;
    }
  }
  if (g_aux_dnstap_ring.events) {
    free(g_aux_dnstap_ring.events);
    g_aux_dnstap_ring.events = NULL;
  }
  if (g_dnstap_sock >= 0) {
    close(g_dnstap_sock);
    g_dnstap_sock = -1;
  }
  free(ctxs);
  free(threads);

  server_config_t *active = acquire_config_snapshot();
  if (active) {
    release_config_snapshot(active);
    while (atomic_load_explicit(&active->reader_count, memory_order_acquire) > 0) {
      sched_yield();
    }
    free_server_config_fields(active);
  }
  return 0;
}