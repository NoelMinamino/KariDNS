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
#define MAX_RDATA 48
#define MAX_JUMPS 16

#define COMPRESS_HASH_SIZE 4096
#define COMPRESS_HASH_MASK (COMPRESS_HASH_SIZE - 1)
#define MAX_PROBE_DEPTH 8

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

typedef struct {
  char *name;
  char *ttl;
  char *class_str;
  char *type;
  uint16_t type_code;
  char *rdata[MAX_RDATA];
  int rdata_count;
  uint16_t generic_len;
  uint8_t *generic_data;
  int next_record;
} dns_record_t;

typedef struct {
  dns_record_t *records;
  size_t count;
  size_t records_cap;
  char *data_pools[128];
  int data_pool_count;
  size_t current_pool_cap;
  size_t current_pool_idx;
  char *file_bufs[32];
  int file_buf_count;
  int *hash_table;
  size_t hash_size;
  _Atomic int reader_count;
} zone_arena_t;

typedef struct {
  _Atomic(zone_arena_t *) active;
  zone_arena_t arena_a;
  zone_arena_t arena_b;
} zone_rcu_t;

typedef struct {
  char domain[256];
  zone_rcu_t rcu;
  pthread_mutex_t writer_lock;
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  time_t next_check;
  _Atomic bool refresh_now;
  _Atomic bool is_transferring;
  _Atomic(int) active_axfr;
} zone_db_entry_t;

typedef struct {
  uint32_t hash;
  uint16_t offset;
  uint16_t generation;
} compress_entry_t;
typedef struct {
  compress_entry_t table[COMPRESS_HASH_SIZE];
  uint16_t current_generation;
} compress_ctx_t;

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
  char *ip;
  int port;
} ip_port_t;

typedef struct zone_config {
  char *domain;
  char *file;
  char *type;
  ip_port_t *masters;
  int masters_count;
  char *tsig_key;
  ip_port_t *also_notify;
  int also_notify_count;
  char *notify_source;
  char **allow_transfer;
  int allow_transfer_count;
  struct zone_config *next;
} zone_config_t;

typedef struct tsig_key {
  char *name;
  char *algorithm;
  char *secret;
  uint8_t secret_decoded[256];
  size_t secret_decoded_len;
  struct tsig_key *next;
} tsig_key_t;

typedef struct log_channel {
  char *name;
  char *file_path;
  int versions;
  size_t size_limit;
  bool suffix_timestamp;
  bool print_time;
  bool print_category;
  bool print_severity;
  int fd;
  size_t current_size;
  int current_date;
  pthread_mutex_t lock;
  struct log_channel *next;
} log_channel_t;

typedef struct {
  log_channel_t *channels;
  char *queries_channel_name;
  log_channel_t *queries_channel;
} logging_config_t;

typedef struct {
  int port;
  char **bind_addresses;
  int bind_address_count;
  char *user;
  char *group;
  zone_config_t *zones;
  tsig_key_t *keys;
  logging_config_t logging;
} server_config_t;

typedef enum {
  TOKEN_EOF,
  TOKEN_STRING,
  TOKEN_LBRACE,
  TOKEN_RBRACE,
  TOKEN_SEMICOLON
} token_type_t;
typedef struct {
  token_type_t type;
  char *value;
} token_t;
typedef struct {
  const char *src;
  size_t pos;
  size_t len;
} token_ctx_t;

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

// RRL
#define RRL_TABLE_SIZE 4096
#define RRL_RATE 50
#define RRL_BURST 100
typedef struct {
  atomic_flag lock;
  uint64_t last_update;
  int tokens;
} rrl_bucket_t;
static rrl_bucket_t g_rrl_table[RRL_TABLE_SIZE];

static bool rrl_check(const struct sockaddr *client_addr) {
  uint32_t hash = 0;
  if (client_addr->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)client_addr;
    uint32_t ip = sin->sin_addr.s_addr;
    hash = ip ^ (ip >> 16);
  } else if (client_addr->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)client_addr;
    const uint32_t *w = (const uint32_t *)sin6->sin6_addr.s6_addr;
    hash = w[0] ^ w[1] ^ w[2] ^ w[3];
  }
  size_t idx = hash & (RRL_TABLE_SIZE - 1);
  rrl_bucket_t *b = &g_rrl_table[idx];
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t now_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

  while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) {
  }
  uint64_t elapsed_ms =
      (now_ms > b->last_update) ? (now_ms - b->last_update) : 0;
  if (b->last_update == 0) {
    b->tokens = RRL_BURST;
    b->last_update = now_ms;
  } else {
    uint64_t add_tokens_u64 = (elapsed_ms * RRL_RATE) / 1000;
    int add_tokens =
        (add_tokens_u64 > RRL_BURST) ? RRL_BURST : (int)add_tokens_u64;
    b->tokens += add_tokens;
    if (b->tokens > RRL_BURST)
      b->tokens = RRL_BURST;
    if (add_tokens > 0)
      b->last_update = now_ms;
  }
  bool allow = false;
  if (b->tokens > 0) {
    b->tokens--;
    allow = true;
  }
  atomic_flag_clear_explicit(&b->lock, memory_order_release);
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

static int open_via_dir_cache(const char *path, int flags, mode_t mode,
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
  int trapmode = PROC_TRAPCAP_CTL_ENABLE;
  procctl(P_PID, 0, PROC_TRAPCAP_CTL, &trapmode);
  if (cap_enter() != 0) {
    if (errno == ENOSYS)
      return;
    exit(EXIT_FAILURE);
  }
  atomic_store_explicit(&g_capsicum_enabled, true, memory_order_release);
}

// ============================================================================
// 3. パーサー・各種ユーティリティ (中略なし・既存実装維持)
// ============================================================================

static void skip_spaces_and_comments(token_ctx_t *ctx) {
  while (ctx->pos < ctx->len) {
    char c = ctx->src[ctx->pos];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
      ctx->pos++;
    else if (c == '#')
      while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '\n')
        ctx->pos++;
    else if (c == '/' && ctx->pos + 1 < ctx->len &&
             ctx->src[ctx->pos + 1] == '/') {
      ctx->pos += 2;
      while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '\n')
        ctx->pos++;
    } else if (c == '/' && ctx->pos + 1 < ctx->len &&
               ctx->src[ctx->pos + 1] == '*') {
      ctx->pos += 2;
      while (ctx->pos + 1 < ctx->len &&
             !(ctx->src[ctx->pos] == '*' && ctx->src[ctx->pos + 1] == '/'))
        ctx->pos++;
      if (ctx->pos + 1 < ctx->len)
        ctx->pos += 2;
    } else
      break;
  }
}

token_t get_next_token(token_ctx_t *ctx) {
  token_t tok = {TOKEN_EOF, NULL};
  skip_spaces_and_comments(ctx);
  if (ctx->pos >= ctx->len)
    return tok;
  char c = ctx->src[ctx->pos];
  if (c == '{') {
    tok.type = TOKEN_LBRACE;
    ctx->pos++;
    return tok;
  }
  if (c == '}') {
    tok.type = TOKEN_RBRACE;
    ctx->pos++;
    return tok;
  }
  if (c == ';') {
    tok.type = TOKEN_SEMICOLON;
    ctx->pos++;
    return tok;
  }
  if (c == '"') {
    ctx->pos++;
    size_t start = ctx->pos;
    while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '"')
      ctx->pos++;
    size_t str_len = ctx->pos - start;
    if (str_len > 4096)
      str_len = 4096;
    tok.type = TOKEN_STRING;
    tok.value = malloc(str_len + 1);
    memcpy(tok.value, &ctx->src[start], str_len);
    tok.value[str_len] = '\0';
    if (ctx->pos < ctx->len && ctx->src[ctx->pos] == '"')
      ctx->pos++;
    return tok;
  }
  size_t start = ctx->pos;
  while (ctx->pos < ctx->len) {
    char nc = ctx->src[ctx->pos];
    if (nc == ' ' || nc == '\t' || nc == '\n' || nc == '\r' || nc == '{' ||
        nc == '}' || nc == ';' || nc == '#')
      break;
    if (nc == '/' && ctx->pos + 1 < ctx->len &&
        (ctx->src[ctx->pos + 1] == '/' || ctx->src[ctx->pos + 1] == '*'))
      break;
    ctx->pos++;
  }
  size_t str_len = ctx->pos - start;
  if (str_len > 4096)
    str_len = 4096;
  tok.type = TOKEN_STRING;
  tok.value = malloc(str_len + 1);
  memcpy(tok.value, &ctx->src[start], str_len);
  tok.value[str_len] = '\0';
  return tok;
}

void free_token(token_t *tok) {
  if (tok->value) {
    free(tok->value);
    tok->value = NULL;
  }
}

void free_zone_config(zone_config_t *zone) {
  if (!zone)
    return;
  free(zone->domain);
  free(zone->type);
  free(zone->file);
  for (int i = 0; i < zone->masters_count; i++)
    free(zone->masters[i].ip);
  free(zone->masters);
  free(zone->tsig_key);
  for (int i = 0; i < zone->also_notify_count; i++)
    free(zone->also_notify[i].ip);
  free(zone->also_notify);
  free(zone->notify_source);
  for (int i = 0; i < zone->allow_transfer_count; i++)
    free(zone->allow_transfer[i]);
  free(zone->allow_transfer);
  free(zone);
}

static char *read_entire_file(const char *path) {
  int fd = open_via_dir_cache(path, O_RDONLY, 0, false);
  if (fd < 0)
    return NULL;
  FILE *f = fdopen(fd, "rb");
  if (!f) {
    close(fd);
    return NULL;
  }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsize < 0 || fsize > 256 * 1024 * 1024) {
    fclose(f);
    return NULL;
  }
  char *str = malloc(fsize + 1);
  if (!str) {
    fclose(f);
    return NULL;
  }
  if (fread(str, 1, fsize, f) != (size_t)fsize) {
    free(str);
    fclose(f);
    return NULL;
  }
  str[fsize] = '\0';
  fclose(f);
  return str;
}

static void skip_unknown_block(token_ctx_t *ctx) {
  int brace_level = 0;
  while (1) {
    token_t tok = get_next_token(ctx);
    if (tok.type == TOKEN_EOF) {
      free_token(&tok);
      break;
    }
    if (tok.type == TOKEN_LBRACE)
      brace_level++;
    else if (tok.type == TOKEN_RBRACE)
      brace_level--;
    else if (tok.type == TOKEN_SEMICOLON && brace_level <= 0) {
      free_token(&tok);
      break;
    }
    free_token(&tok);
  }
}

static bool match_cidr(const char *client_ip_str, const char *cidr_str) {
  if (strcmp(cidr_str, "any") == 0 || strcmp(cidr_str, "any;") == 0)
    return true;
  char cidr_copy[256];
  strncpy(cidr_copy, cidr_str, sizeof(cidr_copy) - 1);
  cidr_copy[sizeof(cidr_copy) - 1] = '\0';
  char *slash = strchr(cidr_copy, '/');
  int prefix = -1;
  if (slash) {
    *slash = '\0';
    prefix = atoi(slash + 1);
  }
  struct in_addr client_addr_v4, net_addr_v4;
  struct in6_addr client_addr_v6, net_addr_v6;
  if (inet_pton(AF_INET, client_ip_str, &client_addr_v4) == 1 &&
      inet_pton(AF_INET, cidr_copy, &net_addr_v4) == 1) {
    if (prefix == -1)
      prefix = 32;
    if (prefix < 0 || prefix > 32)
      return false;
    uint32_t mask = prefix == 0 ? 0 : (~0U) << (32 - prefix);
    mask = htonl(mask);
    return (client_addr_v4.s_addr & mask) == (net_addr_v4.s_addr & mask);
  } else if (inet_pton(AF_INET6, client_ip_str, &client_addr_v6) == 1 &&
             inet_pton(AF_INET6, cidr_copy, &net_addr_v6) == 1) {
    if (prefix == -1)
      prefix = 128;
    if (prefix < 0 || prefix > 128)
      return false;
    for (int i = 0; i < 16; i++) {
      int bits = prefix - (i * 8);
      if (bits >= 8) {
        if (client_addr_v6.s6_addr[i] != net_addr_v6.s6_addr[i])
          return false;
      } else if (bits > 0) {
        uint8_t mask = (0xFF << (8 - bits)) & 0xFF;
        if ((client_addr_v6.s6_addr[i] & mask) !=
            (net_addr_v6.s6_addr[i] & mask))
          return false;
      } else
        break;
    }
    return true;
  }
  return false;
}

static int parse_string_list(token_ctx_t *ctx, char ***list, int *count,
                             const char *dir_name) {
  (void)dir_name;
  token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  while (1) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    *list = realloc(*list, sizeof(char *) * (*count + 1));
    (*list)[*count] = strdup(tok.value);
    (*count)++;
    free_token(&tok);
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) {
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

static int parse_ip_port_list(token_ctx_t *ctx, ip_port_t **list, int *count,
                              const char *dir_name) {
  (void)dir_name;
  token_t tok = get_next_token(ctx);
  if (tok.type != TOKEN_LBRACE) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  while (1) {
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_RBRACE) {
      free_token(&tok);
      break;
    }
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    *list = realloc(*list, sizeof(ip_port_t) * (*count + 1));
    (*list)[*count].ip = strdup(tok.value);
    (*list)[*count].port = 53;
    free_token(&tok);
    size_t saved_pos = ctx->pos;
    tok = get_next_token(ctx);
    if (tok.type == TOKEN_STRING && strcmp(tok.value, "port") == 0) {
      free_token(&tok);
      tok = get_next_token(ctx);
      if (tok.type == TOKEN_STRING)
        (*list)[*count].port = atoi(tok.value);
      else {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tok = get_next_token(ctx);
    } else {
      ctx->pos = saved_pos;
      free_token(&tok);
      tok = get_next_token(ctx);
    }
    (*count)++;
    if (tok.type != TOKEN_SEMICOLON) {
      free_token(&tok);
      return -1;
    }
    free_token(&tok);
  }
  tok = get_next_token(ctx);
  if (tok.type != TOKEN_SEMICOLON) {
    free_token(&tok);
    return -1;
  }
  free_token(&tok);
  return 0;
}

int parse_named_conf(const char *config_str, server_config_t *config) {
  token_ctx_t ctx = {config_str, 0, strlen(config_str)};
  config->port = 53;
  config->bind_addresses = NULL;
  config->bind_address_count = 0;
  config->zones = NULL;
  config->user = NULL;
  config->group = NULL;
  zone_config_t *last_zone = NULL;
  while (1) {
    token_t tok = get_next_token(&ctx);
    if (tok.type == TOKEN_EOF)
      break;
    if (tok.type != TOKEN_STRING) {
      free_token(&tok);
      return -1;
    }
    if (strcmp(tok.value, "options") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free_token(&tok);
          return -1;
        }
        char *key = strdup(tok.value);
        free_token(&tok);
        if (strcmp(key, "port") == 0 || strcmp(key, "user") == 0 ||
            strcmp(key, "group") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key, "port") == 0)
            config->port = atoi(val);
          else if (strcmp(key, "user") == 0)
            config->user = val;
          else
            config->group = val;
        } else if (strcmp(key, "bind-address") == 0) {
          size_t saved_pos = ctx.pos;
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_LBRACE) {
            ctx.pos = saved_pos;
            free_token(&tok);
            if (parse_string_list(&ctx, &config->bind_addresses,
                                  &config->bind_address_count,
                                  "bind-address") != 0) {
              free(key);
              return -1;
            }
          } else if (tok.type == TOKEN_STRING) {
            config->bind_addresses =
                realloc(config->bind_addresses,
                        sizeof(char *) * (config->bind_address_count + 1));
            config->bind_addresses[config->bind_address_count++] =
                strdup(tok.value);
            free_token(&tok);
            tok = get_next_token(&ctx);
            if (tok.type != TOKEN_SEMICOLON) {
              free(key);
              free_token(&tok);
              return -1;
            }
            free_token(&tok);
          } else {
            free(key);
            free_token(&tok);
            return -1;
          }
        } else
          skip_unknown_block(&ctx);
        free(key);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
    } else if (strcmp(tok.value, "zone") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_STRING) {
        free_token(&tok);
        return -1;
      }
      zone_config_t *zone = calloc(1, sizeof(zone_config_t));
      zone->domain = strdup(tok.value);
      free_token(&tok);
      size_t dl = strlen(zone->domain);
      if (dl > 0 && zone->domain[dl - 1] != '.') {
        char *norm = malloc(dl + 2);
        if (norm) {
          memcpy(norm, zone->domain, dl);
          norm[dl] = '.';
          norm[dl + 1] = '\0';
          free(zone->domain);
          zone->domain = norm;
        }
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free_zone_config(zone);
          free_token(&tok);
          return -1;
        }
        char *key = strdup(tok.value);
        free_token(&tok);
        if (strcmp(key, "masters") == 0) {
          if (parse_ip_port_list(&ctx, &zone->masters, &zone->masters_count,
                                 "masters") != 0) {
            free(key);
            free_zone_config(zone);
            return -1;
          }
        } else if (strcmp(key, "also-notify") == 0) {
          if (parse_ip_port_list(&ctx, &zone->also_notify,
                                 &zone->also_notify_count,
                                 "also-notify") != 0) {
            free(key);
            free_zone_config(zone);
            return -1;
          }
        } else if (strcmp(key, "allow-transfer") == 0) {
          if (parse_string_list(&ctx, &zone->allow_transfer,
                                &zone->allow_transfer_count,
                                "allow-transfer") != 0) {
            free(key);
            free_zone_config(zone);
            return -1;
          }
        } else if (strcmp(key, "type") == 0 || strcmp(key, "file") == 0 ||
                   strcmp(key, "tsig-key") == 0 ||
                   strcmp(key, "notify-source") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(key);
            free_zone_config(zone);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key);
            free(val);
            free_zone_config(zone);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key, "type") == 0)
            zone->type = val;
          else if (strcmp(key, "file") == 0)
            zone->file = val;
          else if (strcmp(key, "tsig-key") == 0)
            zone->tsig_key = val;
          else
            zone->notify_source = val;
        } else
          skip_unknown_block(&ctx);
        free(key);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_zone_config(zone);
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      if (!config->zones)
        config->zones = zone;
      else
        last_zone->next = zone;
      last_zone = zone;
    } else if (strcmp(tok.value, "key") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_STRING) {
        free_token(&tok);
        return -1;
      }
      tsig_key_t *tsig = calloc(1, sizeof(tsig_key_t));
      tsig->name = strdup(tok.value);
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free_token(&tok);
          return -1;
        }
        char *key_prop = strdup(tok.value);
        free_token(&tok);
        if (strcmp(key_prop, "algorithm") == 0 ||
            strcmp(key_prop, "secret") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(key_prop);
            free_token(&tok);
            return -1;
          }
          char *val = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_SEMICOLON) {
            free(key_prop);
            free(val);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          if (strcmp(key_prop, "algorithm") == 0)
            tsig->algorithm = val;
          else {
            tsig->secret = val;
            int len = EVP_DecodeBlock(tsig->secret_decoded,
                                      (const unsigned char *)tsig->secret,
                                      strlen(tsig->secret));
            int padding = 0;
            size_t slen = strlen(tsig->secret);
            if (slen > 0 && tsig->secret[slen - 1] == '=')
              padding++;
            if (slen > 1 && tsig->secret[slen - 2] == '=')
              padding++;
            tsig->secret_decoded_len = len - padding;
          }
        } else
          skip_unknown_block(&ctx);
        free(key_prop);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      tsig->next = config->keys;
      config->keys = tsig;
    } else if (strcmp(tok.value, "logging") == 0) {
      free_token(&tok);
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_LBRACE) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      while (1) {
        tok = get_next_token(&ctx);
        if (tok.type == TOKEN_RBRACE) {
          free_token(&tok);
          break;
        }
        if (tok.type != TOKEN_STRING) {
          free_token(&tok);
          return -1;
        }
        char *dir = strdup(tok.value);
        free_token(&tok);
        if (strcmp(dir, "channel") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          log_channel_t *ch = calloc(1, sizeof(log_channel_t));
          ch->name = strdup(tok.value);
          free_token(&tok);
          ch->fd = -1;
          pthread_mutex_init(&ch->lock, NULL);
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_LBRACE) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          free_token(&tok);
          while (1) {
            tok = get_next_token(&ctx);
            if (tok.type == TOKEN_RBRACE) {
              free_token(&tok);
              break;
            }
            if (tok.type != TOKEN_STRING) {
              free_token(&tok);
              return -1;
            }
            char *opt = strdup(tok.value);
            free_token(&tok);
            if (strcmp(opt, "file") == 0) {
              tok = get_next_token(&ctx);
              if (tok.type != TOKEN_STRING) {
                free(opt);
                free_token(&tok);
                return -1;
              }
              ch->file_path = strdup(tok.value);
              free_token(&tok);
              while (1) {
                size_t saved = ctx.pos;
                tok = get_next_token(&ctx);
                if (tok.type == TOKEN_SEMICOLON) {
                  free_token(&tok);
                  break;
                }
                if (tok.type == TOKEN_STRING &&
                    strcmp(tok.value, "versions") == 0) {
                  free_token(&tok);
                  tok = get_next_token(&ctx);
                  if (tok.type == TOKEN_STRING)
                    ch->versions = atoi(tok.value);
                  free_token(&tok);
                } else if (tok.type == TOKEN_STRING &&
                           strcmp(tok.value, "size") == 0) {
                  free_token(&tok);
                  tok = get_next_token(&ctx);
                  if (tok.type == TOKEN_STRING) {
                    size_t mult = 1;
                    size_t len = strlen(tok.value);
                    if (len > 0) {
                      char last = tok.value[len - 1];
                      if (last == 'M' || last == 'm')
                        mult = 1024 * 1024;
                      else if (last == 'K' || last == 'k')
                        mult = 1024;
                      else if (last == 'G' || last == 'g')
                        mult = 1024 * 1024 * 1024;
                      ch->size_limit = strtoull(tok.value, NULL, 10) * mult;
                    }
                  }
                  free_token(&tok);
                } else if (tok.type == TOKEN_STRING &&
                           strcmp(tok.value, "suffix") == 0) {
                  free_token(&tok);
                  tok = get_next_token(&ctx);
                  if (tok.type == TOKEN_STRING &&
                      strcmp(tok.value, "timestamp") == 0)
                    ch->suffix_timestamp = true;
                  free_token(&tok);
                } else {
                  ctx.pos = saved;
                  free_token(&tok);
                  tok = get_next_token(&ctx);
                  if (tok.type == TOKEN_SEMICOLON) {
                    free_token(&tok);
                    break;
                  }
                }
              }
            } else if (strcmp(opt, "print-time") == 0 ||
                       strcmp(opt, "print-category") == 0 ||
                       strcmp(opt, "print-severity") == 0) {
              tok = get_next_token(&ctx);
              bool val =
                  (tok.type == TOKEN_STRING && strcmp(tok.value, "yes") == 0);
              free_token(&tok);
              tok = get_next_token(&ctx);
              if (tok.type == TOKEN_SEMICOLON)
                free_token(&tok);
              if (strcmp(opt, "print-time") == 0)
                ch->print_time = val;
              else if (strcmp(opt, "print-category") == 0)
                ch->print_category = val;
              else
                ch->print_severity = val;
            } else
              skip_unknown_block(&ctx);
            free(opt);
          }
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_SEMICOLON)
            free_token(&tok);
          ch->next = config->logging.channels;
          config->logging.channels = ch;
        } else if (strcmp(dir, "category") == 0) {
          tok = get_next_token(&ctx);
          if (tok.type != TOKEN_STRING) {
            free(dir);
            free_token(&tok);
            return -1;
          }
          char *cat_name = strdup(tok.value);
          free_token(&tok);
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_LBRACE) {
            free_token(&tok);
            tok = get_next_token(&ctx);
            if (strcmp(cat_name, "queries") == 0 && tok.type == TOKEN_STRING)
              config->logging.queries_channel_name = strdup(tok.value);
            free_token(&tok);
            tok = get_next_token(&ctx);
            if (tok.type == TOKEN_SEMICOLON)
              free_token(&tok);
            tok = get_next_token(&ctx);
            if (tok.type == TOKEN_RBRACE)
              free_token(&tok);
          }
          free(cat_name);
          tok = get_next_token(&ctx);
          if (tok.type == TOKEN_SEMICOLON)
            free_token(&tok);
        } else
          skip_unknown_block(&ctx);
        free(dir);
      }
      tok = get_next_token(&ctx);
      if (tok.type != TOKEN_SEMICOLON) {
        free_token(&tok);
        return -1;
      }
      free_token(&tok);
      if (config->logging.queries_channel_name) {
        log_channel_t *ch = config->logging.channels;
        while (ch) {
          if (strcmp(ch->name, config->logging.queries_channel_name) == 0) {
            config->logging.queries_channel = ch;
            break;
          }
          ch = ch->next;
        }
      }
    } else {
      free_token(&tok);
      skip_unknown_block(&ctx);
    }
  }
  return 0;
}

static uint16_t get_type_code(const char *type_str) {
  if (!type_str)
    return 0;
  switch (type_str[0]) {
  case 'A':
    if (strcmp(type_str, "A") == 0)
      return 1;
    if (strcmp(type_str, "AAAA") == 0)
      return 28;
    if (strcmp(type_str, "AFSDB") == 0)
      return 18;
    if (strcmp(type_str, "ATMA") == 0)
      return 34;
    if (strcmp(type_str, "A6") == 0)
      return 38;
    if (strcmp(type_str, "APL") == 0)
      return 42;
    if (strcmp(type_str, "ANY") == 0)
      return 255;
    if (strcmp(type_str, "AVC") == 0)
      return 258;
    if (strcmp(type_str, "AMTRELAY") == 0)
      return 260;
    if (strcmp(type_str, "AXFR") == 0)
      return 252;
    break;
  case 'C':
    if (strcmp(type_str, "CNAME") == 0)
      return 5;
    if (strcmp(type_str, "CERT") == 0)
      return 37;
    if (strcmp(type_str, "CDS") == 0)
      return 59;
    if (strcmp(type_str, "CDNSKEY") == 0)
      return 60;
    if (strcmp(type_str, "CSYNC") == 0)
      return 62;
    if (strcmp(type_str, "CAA") == 0)
      return 257;
    break;
  case 'D':
    if (strcmp(type_str, "DS") == 0)
      return 43;
    if (strcmp(type_str, "DNAME") == 0)
      return 39;
    if (strcmp(type_str, "DNSKEY") == 0)
      return 48;
    if (strcmp(type_str, "DHCID") == 0)
      return 49;
    if (strcmp(type_str, "DOA") == 0)
      return 259;
    if (strcmp(type_str, "DLV") == 0)
      return 32769;
    break;
  case 'E':
    if (strcmp(type_str, "EID") == 0)
      return 31;
    if (strcmp(type_str, "EUI48") == 0)
      return 108;
    if (strcmp(type_str, "EUI64") == 0)
      return 109;
    break;
  case 'G':
    if (strcmp(type_str, "GPOS") == 0)
      return 27;
    break;
  case 'H':
    if (strcmp(type_str, "HINFO") == 0)
      return 13;
    if (strcmp(type_str, "HTTPS") == 0)
      return 65;
    if (strcmp(type_str, "HIP") == 0)
      return 55;
    break;
  case 'I':
    if (strcmp(type_str, "ISDN") == 0)
      return 20;
    if (strcmp(type_str, "IPSECKEY") == 0)
      return 45;
    if (strcmp(type_str, "IXFR") == 0)
      return 251;
    break;
  case 'K':
    if (strcmp(type_str, "KEY") == 0)
      return 25;
    if (strcmp(type_str, "KX") == 0)
      return 36;
    break;
  case 'L':
    if (strcmp(type_str, "LOC") == 0)
      return 29;
    if (strcmp(type_str, "L32") == 0)
      return 105;
    if (strcmp(type_str, "L64") == 0)
      return 106;
    if (strcmp(type_str, "LP") == 0)
      return 107;
    break;
  case 'M':
    if (strcmp(type_str, "MX") == 0)
      return 15;
    if (strcmp(type_str, "MD") == 0)
      return 3;
    if (strcmp(type_str, "MF") == 0)
      return 4;
    if (strcmp(type_str, "MB") == 0)
      return 7;
    if (strcmp(type_str, "MG") == 0)
      return 8;
    if (strcmp(type_str, "MR") == 0)
      return 9;
    if (strcmp(type_str, "MINFO") == 0)
      return 14;
    if (strcmp(type_str, "MAILB") == 0)
      return 253;
    if (strcmp(type_str, "MAILA") == 0)
      return 254;
    break;
  case 'N':
    if (strcmp(type_str, "NS") == 0)
      return 2;
    if (strcmp(type_str, "NULL") == 0)
      return 10;
    if (strcmp(type_str, "NSAP") == 0)
      return 22;
    if (strcmp(type_str, "NSAP-PTR") == 0)
      return 23;
    if (strcmp(type_str, "NXT") == 0)
      return 30;
    if (strcmp(type_str, "NIMLOC") == 0)
      return 32;
    if (strcmp(type_str, "NAPTR") == 0)
      return 35;
    if (strcmp(type_str, "NSEC") == 0)
      return 47;
    if (strcmp(type_str, "NSEC3") == 0)
      return 50;
    if (strcmp(type_str, "NSEC3PARAM") == 0)
      return 51;
    if (strcmp(type_str, "NID") == 0)
      return 104;
    break;
  case 'O':
    if (strcmp(type_str, "OPT") == 0)
      return 41;
    if (strcmp(type_str, "OPENPGPKEY") == 0)
      return 61;
    break;
  case 'P':
    if (strcmp(type_str, "PTR") == 0)
      return 12;
    if (strcmp(type_str, "PX") == 0)
      return 26;
    break;
  case 'R':
    if (strcmp(type_str, "RP") == 0)
      return 17;
    if (strcmp(type_str, "RT") == 0)
      return 21;
    if (strcmp(type_str, "RRSIG") == 0)
      return 46;
    break;
  case 'S':
    if (strcmp(type_str, "SOA") == 0)
      return 6;
    if (strcmp(type_str, "SRV") == 0)
      return 33;
    if (strcmp(type_str, "SIG") == 0)
      return 24;
    if (strcmp(type_str, "SINK") == 0)
      return 40;
    if (strcmp(type_str, "SSHFP") == 0)
      return 44;
    if (strcmp(type_str, "SMIMEA") == 0)
      return 53;
    if (strcmp(type_str, "SVCB") == 0)
      return 64;
    if (strcmp(type_str, "SPF") == 0)
      return 99;
    break;
  case 'T':
    if (strcmp(type_str, "TXT") == 0)
      return 16;
    if (strcmp(type_str, "TLSA") == 0)
      return 52;
    if (strcmp(type_str, "TKEY") == 0)
      return 249;
    if (strcmp(type_str, "TSIG") == 0)
      return 250;
    if (strcmp(type_str, "TA") == 0)
      return 32768;
    if (strncmp(type_str, "TYPE", 4) == 0)
      return (uint16_t)atoi(type_str + 4);
    break;
  case 'U':
    if (strcmp(type_str, "URI") == 0)
      return 256;
    break;
  case 'W':
    if (strcmp(type_str, "WKS") == 0)
      return 11;
    break;
  case 'X':
    if (strcmp(type_str, "X25") == 0)
      return 19;
    break;
  case 'Z':
    if (strcmp(type_str, "ZONEMD") == 0)
      return 63;
    break;
  }
  return 0;
}

static int hex_char_to_val(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static inline void *arena_alloc(zone_arena_t *arena, size_t size) {
  if (arena->current_pool_idx + size > arena->current_pool_cap ||
      arena->data_pool_count == 0) {
    if (arena->data_pool_count >= 128)
      return NULL;
    if (arena->data_pool_count == 0)
      arena->current_pool_cap = 64 * 1024;
    else {
      arena->current_pool_cap *= 2;
      if (arena->current_pool_cap > 64 * 1024 * 1024)
        arena->current_pool_cap = 64 * 1024 * 1024;
    }
    if (size > arena->current_pool_cap)
      arena->current_pool_cap = size + (1024 * 1024);
    arena->data_pools[arena->data_pool_count] = malloc(arena->current_pool_cap);
    if (!arena->data_pools[arena->data_pool_count])
      return NULL;
    arena->current_pool_idx = 0;
    arena->data_pool_count++;
  }
  void *ptr =
      &arena->data_pools[arena->data_pool_count - 1][arena->current_pool_idx];
  arena->current_pool_idx += size;
  return ptr;
}

static char *expand_domain_name(char *name, const char *origin,
                                zone_arena_t *arena) {
  if (!name)
    return name;
  size_t n_len = strlen(name);
  if (n_len > 0 && name[n_len - 1] == '.')
    return name;
  if (strcmp(name, "@") == 0) {
    if (!origin)
      return name;
    size_t o_len = strlen(origin);
    if (o_len > 0 && origin[o_len - 1] == '.')
      return (char *)origin;
    char *fqdn = (char *)arena_alloc(arena, o_len + 2);
    if (!fqdn)
      return (char *)origin;
    memcpy(fqdn, origin, o_len);
    fqdn[o_len] = '.';
    fqdn[o_len + 1] = '\0';
    return fqdn;
  }
  if (!origin) {
    char *fqdn = (char *)arena_alloc(arena, n_len + 2);
    if (!fqdn)
      return name;
    memcpy(fqdn, name, n_len);
    fqdn[n_len] = '.';
    fqdn[n_len + 1] = '\0';
    return fqdn;
  }
  size_t o_len = strlen(origin);
  bool origin_has_dot = (o_len > 0 && origin[o_len - 1] == '.');
  size_t total_len = n_len + 1 + o_len + (origin_has_dot ? 0 : 1);
  char *fqdn = (char *)arena_alloc(arena, total_len + 1);
  if (!fqdn)
    return name;
  memcpy(fqdn, name, n_len);
  fqdn[n_len] = '.';
  memcpy(fqdn + n_len + 1, origin, o_len);
  if (!origin_has_dot)
    fqdn[n_len + 1 + o_len] = '.';
  fqdn[total_len] = '\0';
  return fqdn;
}

int parse_zone_fast(char *buf, size_t size, zone_arena_t *arena,
                    char **prev_owner_io, char **origin_io,
                    char **default_ttl_str_io) {
  if (!buf || size == 0 || !arena)
    return -1;
  char *p = buf, *end = buf + size;
  int in_parens = 0, in_quotes = 0, field_idx = 0;
  char *fields[MAX_FIELDS], *token_start = NULL;

STATE_START_LINE:
  if (p >= end)
    goto DONE;
  field_idx = 0;
  in_quotes = 0;
  if (IS_SPACE(*p)) {
    if (*prev_owner_io)
      fields[field_idx++] = *prev_owner_io;
    goto SKIP_WHITESPACE;
  }
STATE_FIND_TOKEN:
  if (p >= end)
    goto PROCESS_RECORD;
  if (IS_SPACE(*p))
    goto SKIP_WHITESPACE;
  if (IS_NEWLINE(*p)) {
    *p++ = '\0';
    if (in_parens)
      goto STATE_FIND_TOKEN;
    goto PROCESS_RECORD;
  }
  if (*p == ';') {
    char *nl = memchr(p, '\n', end - p);
    if (!nl)
      goto PROCESS_RECORD;
    p = nl;
    goto STATE_FIND_TOKEN;
  }
  if (*p == '(') {
    in_parens = 1;
    *p++ = '\0';
    goto STATE_FIND_TOKEN;
  }
  if (*p == ')') {
    in_parens = 0;
    *p++ = '\0';
    goto STATE_FIND_TOKEN;
  }
  token_start = p;
  while (p < end) {
    if (*p == '\\') {
      p++;
      if (p < end)
        p++;
      continue;
    }
    if (*p == '"') {
      in_quotes = !in_quotes;
      p++;
      continue;
    }
    if (!in_quotes) {
      if (IS_SPACE(*p) || IS_NEWLINE(*p) || *p == ';' || *p == '(' || *p == ')')
        break;
    } else {
      if (IS_NEWLINE(*p))
        break;
    }
    p++;
  }
  if (field_idx < MAX_FIELDS)
    fields[field_idx++] = token_start;
  if (p >= end)
    goto PROCESS_RECORD;
  char delimiter = *p;
  *p++ = '\0';
  if (field_idx > 0 && fields[field_idx - 1][0] == '"') {
    fields[field_idx - 1]++;
    size_t t_len = strlen(fields[field_idx - 1]);
    if (t_len > 0 && fields[field_idx - 1][t_len - 1] == '"')
      fields[field_idx - 1][t_len - 1] = '\0';
  }
  if (IS_SPACE(delimiter))
    goto SKIP_WHITESPACE;
  if (IS_NEWLINE(delimiter)) {
    if (in_parens)
      goto STATE_FIND_TOKEN;
    goto PROCESS_RECORD;
  }
  if (delimiter == '(') {
    in_parens = 1;
    goto STATE_FIND_TOKEN;
  }
  if (delimiter == ')') {
    in_parens = 0;
    goto STATE_FIND_TOKEN;
  }
  if (delimiter == ';') {
    char *nl = memchr(p, '\n', end - p);
    if (!nl)
      goto PROCESS_RECORD;
    p = nl;
    goto STATE_FIND_TOKEN;
  }
SKIP_WHITESPACE:
  while (p < end && IS_SPACE(*p))
    p++;
  goto STATE_FIND_TOKEN;
PROCESS_RECORD:
  if (field_idx == 0) {
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
  if (fields[0][0] == '$' && strcasecmp(fields[0], "$ORIGIN") == 0) {
    if (field_idx > 1)
      *origin_io = fields[1];
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
  if (fields[0][0] == '$' && strcasecmp(fields[0], "$TTL") == 0) {
    if (field_idx > 1)
      *default_ttl_str_io = fields[1];
    if (p < end)
      goto STATE_START_LINE;
    goto DONE;
  }
  if (arena->count >= arena->records_cap) {
    size_t new_cap = arena->records_cap == 0 ? 16 : arena->records_cap * 2;
    dns_record_t *new_records =
        realloc(arena->records, new_cap * sizeof(dns_record_t));
    if (!new_records)
      return -1;
    memset(new_records + arena->records_cap, 0,
           (new_cap - arena->records_cap) * sizeof(dns_record_t));
    arena->records = new_records;
    arena->records_cap = new_cap;
  }
  dns_record_t *rec = &arena->records[arena->count++];
  rec->name = expand_domain_name(fields[0], *origin_io, arena);
  *prev_owner_io = rec->name;
  rec->ttl = *default_ttl_str_io;
  rec->class_str = NULL;
  rec->type = NULL;
  rec->rdata_count = 0;
  int i = 1;
  while (i < field_idx) {
    char first_char = fields[i][0];
    if (first_char >= '0' && first_char <= '9')
      rec->ttl = fields[i];
    else if ((first_char == 'I' && fields[i][1] == 'N' &&
              fields[i][2] == '\0') ||
             strcmp(fields[i], "CH") == 0)
      rec->class_str = fields[i];
    else {
      rec->type = fields[i];
      i++;
      break;
    }
    i++;
  }
  while (i < field_idx && rec->rdata_count < MAX_RDATA)
    rec->rdata[rec->rdata_count++] = fields[i++];
  rec->type_code = get_type_code(rec->type);
  rec->generic_len = 0;
  rec->generic_data = NULL;
  if (rec->rdata_count >= 2 && strcmp(rec->rdata[0], "\\#") == 0) {
    rec->generic_len = atoi(rec->rdata[1]);
    if (rec->generic_len > 0 && rec->rdata_count > 2) {
      uint8_t *blob = (uint8_t *)arena_alloc(arena, rec->generic_len);
      if (blob) {
        size_t b_idx = 0;
        int high_nibble = -1;
        for (int j = 2; j < rec->rdata_count; j++) {
          for (char *h = rec->rdata[j]; *h; h++) {
            int val = hex_char_to_val(*h);
            if (val < 0)
              continue;
            if (high_nibble < 0)
              high_nibble = val;
            else {
              if (b_idx < rec->generic_len)
                blob[b_idx++] = (high_nibble << 4) | val;
              high_nibble = -1;
            }
          }
        }
        rec->generic_data = blob;
      }
    }
  } else if (rec->type) {
    if (rec->type_code == 5 || rec->type_code == 12 || rec->type_code == 2) {
      if (rec->rdata_count > 0)
        rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
    } else if (rec->type_code == 6) {
      if (rec->rdata_count > 0)
        rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
    } else if (rec->type_code == 15) {
      if (rec->rdata_count > 1)
        rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
    } else if (rec->type_code == 33) {
      if (rec->rdata_count > 3)
        rec->rdata[3] = expand_domain_name(rec->rdata[3], *origin_io, arena);
    }
  }
  if (p < end)
    goto STATE_START_LINE;
DONE:
  return arena->count;
}

void zone_arena_init(zone_arena_t *arena) {
  arena->records_cap = 0;
  arena->records = NULL;
  arena->data_pool_count = 0;
  arena->current_pool_cap = 0;
  arena->current_pool_idx = 0;
  arena->count = 0;
  arena->file_buf_count = 0;
  arena->hash_size = 0;
  arena->hash_table = NULL;
  atomic_init(&arena->reader_count, 0);
}
void zone_arena_destroy(zone_arena_t *arena) {
  free(arena->records);
  for (int i = 0; i < arena->data_pool_count; i++)
    free(arena->data_pools[i]);
  free(arena->hash_table);
  for (int i = 0; i < arena->file_buf_count; i++)
    free(arena->file_bufs[i]);
  arena->file_buf_count = 0;
}
static inline uint32_t calc_fnv1a_str(const char *str) {
  uint32_t hash = 2166136261u;
  for (const char *p = str; *p; p++) {
    uint8_t c = *p;
    if (c >= 'A' && c <= 'Z')
      c |= 0x20;
    hash ^= c;
    hash *= 16777619u;
  }
  return hash;
}
static size_t next_pow2(size_t n) {
  size_t p = 256;
  while (p < n)
    p <<= 1;
  return p;
}
void build_zone_index(zone_arena_t *arena) {
  if (arena->hash_table) {
    free(arena->hash_table);
    arena->hash_table = NULL;
  }
  arena->hash_size = next_pow2(arena->count * 2);
  arena->hash_table = malloc(sizeof(int) * arena->hash_size);
  for (size_t i = 0; i < arena->hash_size; i++)
    arena->hash_table[i] = -1;
  for (int i = (int)arena->count - 1; i >= 0; i--) {
    dns_record_t *rec = &arena->records[i];
    if (!rec->name)
      continue;
    uint32_t hash = calc_fnv1a_str(rec->name);
    size_t idx = hash & (arena->hash_size - 1);
    rec->next_record = arena->hash_table[idx];
    arena->hash_table[idx] = i;
  }
}

zone_db_entry_t *get_zone(const char *domain) {
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
  zone_db_entry_t *result = NULL;
  for (size_t i = 0; i < snap->count; i++) {
    if (strcasecmp(snap->entries[i]->domain, domain) == 0) {
      result = snap->entries[i];
      break;
    }
  }
  atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
  return result;
}

static void wait_for_snapshot_readers(zone_db_snapshot_t *snap) {
  int retries = 0;
  while (atomic_load_explicit(&snap->reader_count, memory_order_acquire) > 0) {
    usleep(1000);
    if (++retries % 1000 == 0)
      syslog(LOG_WARNING, "[RCU] wait_for_snapshot_readers stalled");
  }
}

zone_db_entry_t *get_or_create_zone(const char *domain) {
  zone_db_snapshot_t *snap = NULL;
  do {
    snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    if (snap) {
      atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
      if (snap == atomic_load_explicit(&g_zone_db_active, memory_order_acquire))
        break;
      atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
    } else
      break;
  } while (1);
  if (snap) {
    zone_db_entry_t *result = NULL;
    for (size_t i = 0; i < snap->count; i++) {
      if (strcasecmp(snap->entries[i]->domain, domain) == 0) {
        result = snap->entries[i];
        break;
      }
    }
    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
    if (result)
      return result;
  }
  zone_db_entry_t *z = calloc(1, sizeof(zone_db_entry_t));
  if (!z)
    return NULL;
  atomic_init(&z->active_axfr, 0);
  strncpy(z->domain, domain, sizeof(z->domain) - 1);
  z->domain[sizeof(z->domain) - 1] = '\0';
  pthread_mutex_init(&z->writer_lock, NULL);
  zone_arena_init(&z->rcu.arena_a);
  zone_arena_init(&z->rcu.arena_b);
  atomic_init(&z->rcu.active, &z->rcu.arena_a);
  zone_db_snapshot_t *new_snap = calloc(1, sizeof(zone_db_snapshot_t));
  new_snap->count = snap ? snap->count + 1 : 1;
  new_snap->entries = calloc(new_snap->count, sizeof(zone_db_entry_t *));
  if (snap) {
    for (size_t i = 0; i < snap->count; i++)
      new_snap->entries[i] = snap->entries[i];
  }
  new_snap->entries[new_snap->count - 1] = z;
  atomic_init(&new_snap->reader_count, 0);
  atomic_store_explicit(&g_zone_db_active, new_snap, memory_order_release);
  if (snap) {
    wait_for_snapshot_readers(snap);
    free(snap->entries);
    free(snap);
  }
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

void load_zones_from_config(server_config_t *config) {
  zone_config_t *z = config->zones;
  while (z) {
    if (z->type &&
        (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) &&
        z->file) {
      zone_db_entry_t *entry = get_or_create_zone(z->domain);
      if (!entry) {
        z = z->next;
        continue;
      }
      char *buf = read_entire_file(z->file);
      if (buf) {
        pthread_mutex_lock(&entry->writer_lock);
        zone_arena_t *z_active =
            atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
        zone_arena_t *z_standby = (z_active == &entry->rcu.arena_a)
                                      ? &entry->rcu.arena_b
                                      : &entry->rcu.arena_a;
        wait_for_readers(z_standby);
        for (int i = 0; i < z_standby->file_buf_count; i++)
          free(z_standby->file_bufs[i]);
        z_standby->count = 0;
        z_standby->data_pool_count = 0;
        z_standby->current_pool_cap = 0;
        z_standby->current_pool_idx = 0;
        z_standby->file_buf_count = 0;
        z_standby->file_bufs[z_standby->file_buf_count++] = buf;
        char *prev_owner = NULL, *origin = z->domain, *default_ttl_str = NULL;
        int count = parse_zone_fast(buf, strlen(buf), z_standby, &prev_owner,
                                    &origin, &default_ttl_str);
        if (count >= 0) {
          build_zone_index(z_standby);
          bool has_soa = false;
          uint32_t hash = calc_fnv1a_str(z->domain);
          size_t idx = hash & (z_standby->hash_size - 1);
          for (int i = z_standby->hash_table[idx]; i != -1;
               i = z_standby->records[i].next_record) {
            if (z_standby->records[i].type_code == 6 &&
                strcasecmp(z_standby->records[i].name, z->domain) == 0) {
              has_soa = true;
              break;
            }
          }
          if (has_soa)
            atomic_store_explicit(&entry->rcu.active, z_standby,
                                  memory_order_release);
        }
        pthread_mutex_unlock(&entry->writer_lock);
      }
    }
    z = z->next;
  }
}

static inline void compress_ctx_init_packet(compress_ctx_t *ctx) {
  ctx->current_generation++;
  if (ctx->current_generation == 0) {
    memset(ctx->table, 0, sizeof(ctx->table));
    ctx->current_generation = 1;
  }
}
static inline uint32_t calc_fnv1a_suffix(const uint8_t *name) {
  uint32_t hash = 2166136261u;
  const uint8_t *p = name;
  while (*p != 0) {
    uint8_t len = *p++;
    hash ^= len;
    hash *= 16777619u;
    for (uint8_t i = 0; i < len; i++) {
      uint8_t c = *p++;
      if (c >= 'A' && c <= 'Z')
        c |= 0x20;
      hash ^= c;
      hash *= 16777619u;
    }
  }
  return hash;
}
static inline bool suffix_equals(const uint8_t *packet_buf, uint16_t offset,
                                 const uint8_t *name) {
  const uint8_t *p = packet_buf + offset, *n = name;
  int jump_count = 0;
  while (*n != 0) {
    if ((*p & 0xC0) == 0xC0) {
      if (++jump_count > MAX_JUMPS)
        return false;
      uint16_t next_offset = ((*p & 0x3F) << 8) | *(p + 1);
      if (next_offset >= offset)
        return false;
      offset = next_offset;
      p = packet_buf + offset;
      continue;
    }
    if (*p != *n)
      return false;
    uint8_t len = *p;
    p++;
    n++;
    for (uint8_t i = 0; i < len; i++) {
      uint8_t c1 = *p++, c2 = *n++;
      if (c1 >= 'A' && c1 <= 'Z')
        c1 |= 0x20;
      if (c2 >= 'A' && c2 <= 'Z')
        c2 |= 0x20;
      if (c1 != c2)
        return false;
    }
  }
  jump_count = 0;
  while ((*p & 0xC0) == 0xC0) {
    if (++jump_count > MAX_JUMPS)
      return false;
    uint16_t next_offset = ((*p & 0x3F) << 8) | *(p + 1);
    if (next_offset >= offset)
      return false;
    offset = next_offset;
    p = packet_buf + offset;
  }
  return *p == 0;
}

int compress_name(uint8_t *packet_buf, uint16_t *offset, const uint8_t *name,
                  compress_ctx_t *ctx) {
  const uint8_t *s = name;
  while (*s != 0) {
    if (*offset >= 0x3FFF)
      return -1;
    uint32_t hash = calc_fnv1a_suffix(s), idx = hash & COMPRESS_HASH_MASK;
    for (int i = 0; i < MAX_PROBE_DEPTH; i++) {
      compress_entry_t *entry = &ctx->table[(idx + i) & COMPRESS_HASH_MASK];
      if (entry->generation != ctx->current_generation)
        break;
      if (entry->hash == hash && suffix_equals(packet_buf, entry->offset, s)) {
        uint16_t ptr = 0xC000 | entry->offset;
        packet_buf[(*offset)++] = ptr >> 8;
        packet_buf[(*offset)++] = ptr & 0xFF;
        return 0;
      }
    }
    for (int i = 0; i < MAX_PROBE_DEPTH; i++) {
      compress_entry_t *entry = &ctx->table[(idx + i) & COMPRESS_HASH_MASK];
      if (entry->generation != ctx->current_generation) {
        entry->generation = ctx->current_generation;
        entry->hash = hash;
        entry->offset = *offset;
        break;
      }
    }
    uint8_t len = *s;
    packet_buf[(*offset)++] = *s++;
    for (uint8_t i = 0; i < len; i++)
      packet_buf[(*offset)++] = *s++;
  }
  packet_buf[(*offset)++] = 0;
  return 0;
}

int skip_wire_name(const uint8_t *packet, size_t packet_len,
                   size_t current_offset, size_t *next_offset) {
  size_t p = current_offset;
  int jump_count = 0;
  bool jumped = false;
  size_t jumped_offset = 0;
  while (1) {
    if (p >= packet_len)
      return -1;
    uint8_t len = packet[p];
    if ((len & 0xC0) == 0xC0) {
      if (p + 1 >= packet_len)
        return -1;
      if (++jump_count > MAX_JUMPS)
        return -1;
      uint16_t ptr = ((len & 0x3F) << 8) | packet[p + 1];
      if (!jumped) {
        jumped_offset = p + 2;
        jumped = true;
      }
      if (ptr >= p && jumped)
        return -1;
      p = ptr;
      continue;
    }
    if (len == 0) {
      p++;
      break;
    }
    p += 1 + len;
  }
  *next_offset = jumped ? jumped_offset : p;
  return 0;
}

int expand_wire_name(const uint8_t *packet, size_t packet_len,
                     size_t current_offset, size_t *next_offset,
                     zone_arena_t *arena, char **name_out) {
  size_t p = current_offset, jumped_offset = 0;
  bool jumped = false;
  int jump_count = 0;
  char buf[256];
  size_t written = 0;
  while (1) {
    if (p >= packet_len)
      return -1;
    uint8_t len = packet[p];
    if ((len & 0xC0) == 0xC0) {
      if (p + 1 >= packet_len || ++jump_count > MAX_JUMPS)
        return -1;
      uint16_t ptr = ((len & 0x3F) << 8) | packet[p + 1];
      if (!jumped) {
        jumped_offset = p + 2;
        jumped = true;
      }
      if (ptr >= p && jumped)
        return -1;
      p = ptr;
      continue;
    }
    p++;
    if (len == 0) {
      if (written == 0 || buf[written - 1] != '.') {
        if (written >= 256)
          return -1;
        buf[written++] = '.';
      }
      buf[written++] = '\0';
      break;
    }
    if (written > 0 && buf[written - 1] != '.') {
      if (written >= 256)
        return -1;
      buf[written++] = '.';
    }
    if (written + len >= 256)
      return -1;
    memcpy(&buf[written], &packet[p], len);
    written += len;
    p += len;
  }
  *next_offset = jumped ? jumped_offset : p;
  char *dst = arena_alloc(arena, written);
  if (!dst)
    return -1;
  memcpy(dst, buf, written);
  *name_out = dst;
  return 0;
}

static const char *get_type_str(uint16_t type, zone_arena_t *arena) {
  switch (type) {
  case 1:
    return "A";
  case 2:
    return "NS";
  case 5:
    return "CNAME";
  case 6:
    return "SOA";
  case 15:
    return "MX";
  case 16:
    return "TXT";
  case 28:
    return "AAAA";
  case 33:
    return "SRV";
  case 250:
    return "TSIG";
  case 252:
    return "AXFR";
  default: {
    if (arena == NULL) {
      static __thread char tl_buf[16];
      snprintf(tl_buf, 16, "TYPE%d", type);
      return tl_buf;
    }
    char *buf = arena_alloc(arena, 16);
    if (buf)
      snprintf(buf, 16, "TYPE%d", type);
    return buf ? buf : "UNKNOWN";
  }
  }
}

int parse_resource_record(const uint8_t *packet, size_t packet_len,
                          size_t *offset, zone_arena_t *arena,
                          dns_record_t *rec, uint16_t *type_out) {
  char *name;
  if (expand_wire_name(packet, packet_len, *offset, offset, arena, &name) != 0)
    return -1;
  rec->name = name;
  if (*offset + 10 > packet_len)
    return -1;
  uint16_t type = (packet[*offset] << 8) | packet[*offset + 1];
  uint16_t class_val = (packet[*offset + 2] << 8) | packet[*offset + 3];
  uint32_t ttl = ((uint32_t)packet[*offset + 4] << 24) |
                 ((uint32_t)packet[*offset + 5] << 16) |
                 ((uint32_t)packet[*offset + 6] << 8) | packet[*offset + 7];
  uint16_t rdlen = (packet[*offset + 8] << 8) | packet[*offset + 9];
  *offset += 10;
  if (*offset + rdlen > packet_len)
    return -1;
  *type_out = type;
  rec->type_code = type;
  rec->class_str = (class_val == 1) ? "IN" : "CH";
  rec->type = (char *)get_type_str(type, arena);
  char *ttl_buf = arena_alloc(arena, 16);
  if (!ttl_buf)
    return -1;
  snprintf(ttl_buf, 16, "%u", ttl);
  rec->ttl = ttl_buf;
  rec->rdata_count = 0;
  if (type == 6) {
    size_t rdata_p = *offset;
    char *mname, *rname;
    if (expand_wire_name(packet, packet_len, rdata_p, &rdata_p, arena,
                         &mname) != 0)
      return -1;
    if (expand_wire_name(packet, packet_len, rdata_p, &rdata_p, arena,
                         &rname) != 0)
      return -1;
    rec->rdata[0] = mname;
    rec->rdata[1] = rname;
    rec->rdata_count = 2;
    for (int j = 0; j < 5; j++) {
      if (rdata_p + 4 > *offset + rdlen)
        return -1;
      uint32_t val = ((uint32_t)packet[rdata_p] << 24) |
                     ((uint32_t)packet[rdata_p + 1] << 16) |
                     ((uint32_t)packet[rdata_p + 2] << 8) | packet[rdata_p + 3];
      char *val_buf = arena_alloc(arena, 16);
      if (!val_buf)
        return -1;
      snprintf(val_buf, 16, "%u", val);
      rec->rdata[rec->rdata_count++] = val_buf;
      rdata_p += 4;
    }
  } else if (type == 1) {
    if (rdlen != 4)
      return -1;
    char *ip_buf = arena_alloc(arena, 16);
    if (!ip_buf)
      return -1;
    snprintf(ip_buf, 16, "%d.%d.%d.%d", packet[*offset], packet[*offset + 1],
             packet[*offset + 2], packet[*offset + 3]);
    rec->rdata[0] = ip_buf;
    rec->rdata_count = 1;
  } else if (type == 2 || type == 5 || type == 12) {
    size_t rdata_p = *offset;
    char *target;
    if (expand_wire_name(packet, packet_len, rdata_p, &rdata_p, arena,
                         &target) != 0)
      return -1;
    rec->rdata[0] = target;
    rec->rdata_count = 1;
  } else {
    uint8_t *blob = (uint8_t *)arena_alloc(arena, rdlen);
    if (!blob)
      return -1;
    memcpy(blob, &packet[*offset], rdlen);
    rec->generic_data = blob;
    rec->generic_len = rdlen;
    rec->rdata_count = 0;
  }
  *offset += rdlen;
  return 0;
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
  for (int i = 1; i < dst->data_pool_count; i++) {
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
                 current_serial == session->initial_soa_serial)
        session->is_finished = true;
      else if (session->is_ixfr) {
        session->is_deleting = !session->is_deleting;
        standby->count--;
      } else {
        if (strcmp(session->initial_soa_name, rec->name) == 0 &&
            session->initial_soa_serial == current_serial)
          session->is_finished = true;
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

static int const_time_memcmp(const void *a, const void *b, size_t len) {
  const unsigned char *p1 = a;
  const unsigned char *p2 = b;
  unsigned char res = 0;
  for (size_t i = 0; i < len; i++)
    res |= p1[i] ^ p2[i];
  return res == 0 ? 0 : 1;
}
static size_t write_uncompressed_name(uint8_t *buf, const char *name) {
  size_t w_len = 0;
  const char *p = name;
  while (*p) {
    const char *dot = strchr(p, '.');
    if (!dot) {
      size_t len = strlen(p);
      buf[w_len++] = len;
      for (size_t i = 0; i < len; i++)
        buf[w_len++] = (p[i] >= 'A' && p[i] <= 'Z') ? (p[i] | 0x20) : p[i];
      break;
    } else {
      size_t len = dot - p;
      if (len > 0) {
        buf[w_len++] = len;
        for (size_t i = 0; i < len; i++)
          buf[w_len++] = (p[i] >= 'A' && p[i] <= 'Z') ? (p[i] | 0x20) : p[i];
      }
      p = dot + 1;
    }
  }
  buf[w_len++] = 0;
  return w_len;
}

int tsig_sign_packet(uint8_t *packet, size_t *packet_len, size_t max_len,
                     tsig_key_t *key, uint16_t tsig_error, uint8_t *prior_mac,
                     size_t *prior_mac_len) {
  if (!key || *packet_len + 512 > max_len)
    return -1;
  size_t pre_mac_len = *packet_len;
  size_t pre_mac_cap =
      pre_mac_len + 512 + (key->algorithm ? strlen(key->algorithm) : 11) +
      strlen(key->name) +
      (prior_mac_len && *prior_mac_len > 0 ? *prior_mac_len + 2 : 0);
  uint8_t *pre_mac = malloc(pre_mac_cap);
  if (!pre_mac)
    return -1;
  size_t offset = 0;
  if (prior_mac_len && *prior_mac_len > 0) {
    pre_mac[offset++] = *prior_mac_len >> 8;
    pre_mac[offset++] = *prior_mac_len & 0xFF;
    memcpy(&pre_mac[offset], prior_mac, *prior_mac_len);
    offset += *prior_mac_len;
  }
  memcpy(&pre_mac[offset], packet, pre_mac_len);
  offset += pre_mac_len;
  offset += write_uncompressed_name(&pre_mac[offset], key->name);
  pre_mac[offset++] = 0x00;
  pre_mac[offset++] = 0xFF;
  pre_mac[offset++] = 0x00;
  pre_mac[offset++] = 0x00;
  pre_mac[offset++] = 0x00;
  pre_mac[offset++] = 0x00;
  const char *alg = key->algorithm ? key->algorithm : "hmac-sha256";
  offset += write_uncompressed_name(&pre_mac[offset], alg);
  uint64_t now = time(NULL);
  pre_mac[offset++] = 0;
  pre_mac[offset++] = 0;
  pre_mac[offset++] = (now >> 24) & 0xFF;
  pre_mac[offset++] = (now >> 16) & 0xFF;
  pre_mac[offset++] = (now >> 8) & 0xFF;
  pre_mac[offset++] = now & 0xFF;
  uint16_t fudge = 300;
  pre_mac[offset++] = fudge >> 8;
  pre_mac[offset++] = fudge & 0xFF;
  pre_mac[offset++] = tsig_error >> 8;
  pre_mac[offset++] = tsig_error & 0xFF;
  if (tsig_error == 18) {
    pre_mac[offset++] = 0;
    pre_mac[offset++] = 6;
    uint64_t now_48 = time(NULL);
    pre_mac[offset++] = (now_48 >> 40) & 0xFF;
    pre_mac[offset++] = (now_48 >> 32) & 0xFF;
    pre_mac[offset++] = (now_48 >> 24) & 0xFF;
    pre_mac[offset++] = (now_48 >> 16) & 0xFF;
    pre_mac[offset++] = (now_48 >> 8) & 0xFF;
    pre_mac[offset++] = now_48 & 0xFF;
  } else {
    pre_mac[offset++] = 0;
    pre_mac[offset++] = 0;
  }
  unsigned int mac_len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  if (key->secret_decoded_len > 0) {
    const EVP_MD *evp_md = EVP_sha256();
    if (strstr(alg, "sha1"))
      evp_md = EVP_sha1();
    else if (strstr(alg, "sha512"))
      evp_md = EVP_sha512();
    else if (strstr(alg, "md5"))
      evp_md = EVP_md5();
    HMAC(evp_md, key->secret_decoded, key->secret_decoded_len, pre_mac, offset,
         mac, &mac_len);
  }
  free(pre_mac);
  if (prior_mac_len && prior_mac) {
    *prior_mac_len = mac_len;
    if (mac_len > 0)
      memcpy(prior_mac, mac, mac_len);
  }
  size_t p_offset = *packet_len;
  p_offset += write_uncompressed_name(&packet[p_offset], key->name);
  packet[p_offset++] = 0x00;
  packet[p_offset++] = 250;
  packet[p_offset++] = 0x00;
  packet[p_offset++] = 0xFF;
  packet[p_offset++] = 0x00;
  packet[p_offset++] = 0x00;
  packet[p_offset++] = 0x00;
  packet[p_offset++] = 0x00;
  size_t rdata_len_idx = p_offset;
  p_offset += 2;
  p_offset += write_uncompressed_name(&packet[p_offset], alg);
  packet[p_offset++] = 0;
  packet[p_offset++] = 0;
  packet[p_offset++] = (now >> 24) & 0xFF;
  packet[p_offset++] = (now >> 16) & 0xFF;
  packet[p_offset++] = (now >> 8) & 0xFF;
  packet[p_offset++] = now & 0xFF;
  packet[p_offset++] = fudge >> 8;
  packet[p_offset++] = fudge & 0xFF;
  packet[p_offset++] = mac_len >> 8;
  packet[p_offset++] = mac_len & 0xFF;
  memcpy(&packet[p_offset], mac, mac_len);
  p_offset += mac_len;
  packet[p_offset++] = packet[0];
  packet[p_offset++] = packet[1];
  packet[p_offset++] = tsig_error >> 8;
  packet[p_offset++] = tsig_error & 0xFF;
  if (tsig_error == 18) {
    packet[p_offset++] = 0;
    packet[p_offset++] = 6;
    uint64_t now_48 = time(NULL);
    packet[p_offset++] = (now_48 >> 40) & 0xFF;
    packet[p_offset++] = (now_48 >> 32) & 0xFF;
    packet[p_offset++] = (now_48 >> 24) & 0xFF;
    packet[p_offset++] = (now_48 >> 16) & 0xFF;
    packet[p_offset++] = (now_48 >> 8) & 0xFF;
    packet[p_offset++] = now_48 & 0xFF;
  } else {
    packet[p_offset++] = 0;
    packet[p_offset++] = 0;
  }
  uint16_t rdlen = p_offset - rdata_len_idx - 2;
  packet[rdata_len_idx] = rdlen >> 8;
  packet[rdata_len_idx + 1] = rdlen & 0xFF;
  uint16_t arcount = (packet[10] << 8) | packet[11];
  arcount++;
  packet[10] = arcount >> 8;
  packet[11] = arcount & 0xFF;
  *packet_len = p_offset;
  return 0;
}

int tsig_verify_packet(const uint8_t *packet, size_t packet_len,
                       tsig_key_t *key) {
  if (!key || packet_len < 12)
    return -1;
  uint16_t arcount = (packet[10] << 8) | packet[11];
  if (arcount == 0)
    return -1;
  size_t offset = 12;
  uint16_t qdcount = (packet[4] << 8) | packet[5],
           ancount = (packet[6] << 8) | packet[7],
           nscount = (packet[8] << 8) | packet[9];
  for (int i = 0; i < qdcount; i++) {
    while (offset < packet_len && packet[offset] != 0 &&
           (packet[offset] & 0xC0) != 0xC0)
      offset += packet[offset] + 1;
    if (offset < packet_len && (packet[offset] & 0xC0) == 0xC0)
      offset += 2;
    else
      offset++;
    offset += 4;
  }
  size_t last_rr_offset = 0;
  for (int i = 0; i < ancount + nscount + arcount; i++) {
    if (i == qdcount + ancount + nscount + arcount - 1)
      last_rr_offset = offset;
    if (offset >= packet_len)
      return -1;
    while (offset < packet_len && packet[offset] != 0 &&
           (packet[offset] & 0xC0) != 0xC0)
      offset += packet[offset] + 1;
    if (offset < packet_len && (packet[offset] & 0xC0) == 0xC0)
      offset += 2;
    else
      offset++;
    if (offset + 10 > packet_len)
      return -1;
    uint16_t rdlen = (packet[offset + 8] << 8) | packet[offset + 9];
    offset += 10 + rdlen;
  }
  if (last_rr_offset == 0 || offset > packet_len)
    return -1;
  size_t tsig_p = last_rr_offset;
  while (tsig_p < packet_len && packet[tsig_p] != 0 &&
         (packet[tsig_p] & 0xC0) != 0xC0)
    tsig_p += packet[tsig_p] + 1;
  if (tsig_p < packet_len && (packet[tsig_p] & 0xC0) == 0xC0)
    tsig_p += 2;
  else
    tsig_p++;
  if (tsig_p + 10 > packet_len)
    return -1;
  uint16_t type = (packet[tsig_p] << 8) | packet[tsig_p + 1];
  if (type != 250)
    return -1;
  tsig_p += 10;
  while (tsig_p < packet_len && packet[tsig_p] != 0)
    tsig_p += packet[tsig_p] + 1;
  tsig_p++;
  if (tsig_p + 16 > packet_len)
    return -1;
  size_t time_fudge_start = tsig_p;
  uint64_t time_signed = ((uint64_t)packet[time_fudge_start] << 40) |
                         ((uint64_t)packet[time_fudge_start + 1] << 32) |
                         ((uint64_t)packet[time_fudge_start + 2] << 24) |
                         ((uint64_t)packet[time_fudge_start + 3] << 16) |
                         ((uint64_t)packet[time_fudge_start + 4] << 8) |
                         (uint64_t)packet[time_fudge_start + 5];
  uint16_t fudge =
      (packet[time_fudge_start + 6] << 8) | packet[time_fudge_start + 7];
  uint64_t now = time(NULL);
  if (now > time_signed + fudge || now + fudge < time_signed)
    return 18;
  tsig_p += 8;
  uint16_t mac_size = (packet[tsig_p] << 8) | packet[tsig_p + 1];
  tsig_p += 2;
  if (tsig_p + mac_size + 6 > packet_len)
    return -1;
  const uint8_t *mac = &packet[tsig_p];
  tsig_p += mac_size;
  uint16_t orig_id = (packet[tsig_p] << 8) | packet[tsig_p + 1];
  tsig_p += 2;
  uint16_t err = (packet[tsig_p] << 8) | packet[tsig_p + 1];
  tsig_p += 2;
  uint16_t other_len = (packet[tsig_p] << 8) | packet[tsig_p + 1];
  tsig_p += 2;
  if (tsig_p + other_len > packet_len)
    return -1;
  size_t pre_mac_cap = last_rr_offset + 512 + other_len;
  uint8_t *pre_mac = malloc(pre_mac_cap);
  if (!pre_mac)
    return -1;
  memcpy(pre_mac, packet, last_rr_offset);
  pre_mac[0] = orig_id >> 8;
  pre_mac[1] = orig_id & 0xFF;
  uint16_t new_arcount = arcount - 1;
  pre_mac[10] = new_arcount >> 8;
  pre_mac[11] = new_arcount & 0xFF;
  size_t p_offset = last_rr_offset;
  p_offset += write_uncompressed_name(&pre_mac[p_offset], key->name);
  pre_mac[p_offset++] = 0x00;
  pre_mac[p_offset++] = 0xFF;
  pre_mac[p_offset++] = 0x00;
  pre_mac[p_offset++] = 0x00;
  pre_mac[p_offset++] = 0x00;
  pre_mac[p_offset++] = 0x00;
  const char *alg = key->algorithm ? key->algorithm : "hmac-sha256";
  p_offset += write_uncompressed_name(&pre_mac[p_offset], alg);
  memcpy(&pre_mac[p_offset], &packet[time_fudge_start], 8);
  p_offset += 8;
  pre_mac[p_offset++] = err >> 8;
  pre_mac[p_offset++] = err & 0xFF;
  pre_mac[p_offset++] = other_len >> 8;
  pre_mac[p_offset++] = other_len & 0xFF;
  if (other_len > 0) {
    memcpy(&pre_mac[p_offset], &packet[tsig_p], other_len);
    p_offset += other_len;
  }
  unsigned int calc_mac_len = 0;
  unsigned char calc_mac[EVP_MAX_MD_SIZE];
  const EVP_MD *evp_md = EVP_sha256();
  if (strstr(alg, "sha1"))
    evp_md = EVP_sha1();
  else if (strstr(alg, "sha512"))
    evp_md = EVP_sha512();
  else if (strstr(alg, "md5"))
    evp_md = EVP_md5();
  HMAC(evp_md, key->secret_decoded, key->secret_decoded_len, pre_mac, p_offset,
       calc_mac, &calc_mac_len);
  free(pre_mac);
  if (calc_mac_len != mac_size)
    return 16;
  if (const_time_memcmp(calc_mac, mac, mac_size) != 0)
    return 16;
  return 0;
}

// ============================================================================
// （これ以降のDNS処理ロジックも継続）
// ============================================================================

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

static int write_dns_name_str(uint8_t *packet_buf, uint16_t *offset,
                              const char *name, compress_ctx_t *ctx) {
  uint8_t wire[256];
  size_t w_len = 0;
  const char *p = name;
  while (*p) {
    const char *dot = strchr(p, '.');
    if (!dot) {
      size_t len = strlen(p);
      if (len > 63 || w_len + len + 1 > 255)
        return -1;
      wire[w_len++] = len;
      memcpy(&wire[w_len], p, len);
      w_len += len;
      break;
    } else {
      size_t len = dot - p;
      if (len > 63)
        return -1;
      if (len > 0) {
        if (w_len + len + 1 > 255)
          return -1;
        wire[w_len++] = len;
        memcpy(&wire[w_len], p, len);
        w_len += len;
      }
      p = dot + 1;
    }
  }
  if (w_len + 1 > 255)
    return -1;
  wire[w_len++] = 0;
  return compress_name(packet_buf, offset, wire, ctx);
}

static int serialize_dns_record(uint8_t *res, size_t max_res_len,
                                uint16_t *offset_ptr, dns_record_t *rec,
                                compress_ctx_t *comp_ctx,
                                const char *owner_name, uint32_t override_ttl) {
  uint16_t offset = *offset_ptr;
  uint16_t rec_type = rec->type_code;
  if (offset + 12 > max_res_len)
    return -1;
  if (write_dns_name_str(res, &offset, owner_name ? owner_name : rec->name,
                         comp_ctx) != 0)
    return -1;
  if (offset + 10 > max_res_len)
    return -1;
  res[offset++] = rec_type >> 8;
  res[offset++] = rec_type & 0xFF;
  res[offset++] = 0;
  res[offset++] = 1;
  uint32_t ttl = rec->ttl ? (uint32_t)strtoul(rec->ttl, NULL, 10) : 3600;
  if (override_ttl != 0xFFFFFFFF && override_ttl < ttl)
    ttl = override_ttl;
  res[offset++] = ttl >> 24;
  res[offset++] = (ttl >> 16) & 0xFF;
  res[offset++] = (ttl >> 8) & 0xFF;
  res[offset++] = ttl & 0xFF;
  uint16_t rdlength_idx = offset;
  offset += 2;
  if (rec->generic_data && rec->generic_len > 0) {
    if (offset + rec->generic_len > max_res_len)
      return -1;
    memcpy(&res[offset], rec->generic_data, rec->generic_len);
    offset += rec->generic_len;
  } else if (rec_type == 1 && rec->rdata_count > 0) {
    if (offset + 4 > max_res_len)
      return -1;
    struct in_addr addr;
    inet_pton(AF_INET, rec->rdata[0], &addr);
    memcpy(&res[offset], &addr.s_addr, 4);
    offset += 4;
  } else if (rec_type == 28 && rec->rdata_count > 0) {
    if (offset + 16 > max_res_len)
      return -1;
    struct in6_addr addr;
    inet_pton(AF_INET6, rec->rdata[0], &addr);
    memcpy(&res[offset], &addr.s6_addr, 16);
    offset += 16;
  } else if ((rec_type == 2 || rec_type == 5 || rec_type == 12) &&
             rec->rdata_count > 0) {
    if (write_dns_name_str(res, &offset, rec->rdata[0], comp_ctx) != 0 ||
        offset > max_res_len)
      return -1;
  } else if (rec_type == 15 && rec->rdata_count >= 2) {
    if (offset + 2 > max_res_len)
      return -1;
    uint16_t pref = atoi(rec->rdata[0]);
    res[offset++] = pref >> 8;
    res[offset++] = pref & 0xFF;
    if (write_dns_name_str(res, &offset, rec->rdata[1], comp_ctx) != 0 ||
        offset > max_res_len)
      return -1;
  } else if (rec_type == 33 && rec->rdata_count >= 4) {
    if (offset + 6 > max_res_len)
      return -1;
    uint16_t prio = atoi(rec->rdata[0]);
    uint16_t weight = atoi(rec->rdata[1]);
    uint16_t port = atoi(rec->rdata[2]);
    res[offset++] = prio >> 8;
    res[offset++] = prio & 0xFF;
    res[offset++] = weight >> 8;
    res[offset++] = weight & 0xFF;
    res[offset++] = port >> 8;
    res[offset++] = port & 0xFF;
    if (write_dns_name_str(res, &offset, rec->rdata[3], comp_ctx) != 0 ||
        offset > max_res_len)
      return -1;
  } else if (rec_type == 6 && rec->rdata_count >= 7) {
    if (write_dns_name_str(res, &offset, rec->rdata[0], comp_ctx) != 0 ||
        write_dns_name_str(res, &offset, rec->rdata[1], comp_ctx) != 0)
      return -1;
    if (offset + 20 > max_res_len)
      return -1;
    for (int j = 2; j < 7; j++) {
      uint32_t val = strtoul(rec->rdata[j], NULL, 10);
      res[offset++] = val >> 24;
      res[offset++] = (val >> 16) & 0xFF;
      res[offset++] = (val >> 8) & 0xFF;
      res[offset++] = val & 0xFF;
    }
  } else if (rec_type == 16 && rec->rdata_count > 0) {
    size_t req = 0;
    for (int j = 0; j < rec->rdata_count; j++) {
      size_t len = strlen(rec->rdata[j]);
      size_t chunks = (len + 254) / 255;
      if (chunks == 0)
        chunks = 1;
      req += chunks + len;
    }
    if (offset + req > max_res_len)
      return -1;
    for (int j = 0; j < rec->rdata_count; j++) {
      size_t len = strlen(rec->rdata[j]);
      const char *str = rec->rdata[j];
      if (len == 0)
        res[offset++] = 0;
      else {
        while (len > 0) {
          size_t chunk_len = (len > 255) ? 255 : len;
          res[offset++] = chunk_len;
          memcpy(&res[offset], str, chunk_len);
          offset += chunk_len;
          str += chunk_len;
          len -= chunk_len;
        }
      }
    }
  }
  uint16_t rdlength = offset - rdlength_idx - 2;
  res[rdlength_idx] = rdlength >> 8;
  res[rdlength_idx + 1] = rdlength & 0xFF;
  *offset_ptr = offset;
  return 0;
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

int process_dns_query(const uint8_t *req, size_t req_len, uint8_t *res,
                      size_t max_res_len, const char *qname, uint16_t qtype,
                      const char *client_ip, compress_ctx_t *comp_ctx,
                      bool is_tcp) {
  char current_qname[256];
  strncpy(current_qname, qname, 255);
  current_qname[255] = '\0';
  size_t q_len = strlen(current_qname);
  zone_arena_t *current_zone = NULL;
  zone_db_entry_t *db_entry = NULL;
  size_t longest_match_len = 0;
  zone_db_snapshot_t *snap = NULL;
  do {
    snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    if (!snap)
      break;
    atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
    if (snap == atomic_load_explicit(&g_zone_db_active, memory_order_acquire))
      break;
    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
  } while (1);
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
    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
  }

  if (req_len >= 12 && ((req[2] >> 3) & 0x0F) == 4) { // NOTIFY
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
    } else
      res[3] |= 0x05;
    return copy_len;
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
  if (req_len < 12) {
    if (current_zone)
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                memory_order_release);
    return -1;
  }
  uint16_t qdcount = (req[4] << 8) | req[5],
           ancount_req = (req[6] << 8) | req[7],
           nscount_req = (req[8] << 8) | req[9],
           arcount_req = (req[10] << 8) | req[11];
  if (qdcount != 1) {
    if (current_zone)
      atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                                memory_order_release);
    size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
    memcpy(res, req, copy_len);
    res[2] |= 0x80;
    res[3] = (res[3] & 0x0F) | 0x01;
    return copy_len;
  }

  uint16_t client_payload_size = 512;
  bool has_edns = false;
  size_t scan_offset = 12;
  for (int i = 0; i < qdcount + ancount_req + nscount_req + arcount_req; i++) {
    if (scan_offset >= req_len)
      break;
    bool is_opt = (i >= qdcount + ancount_req + nscount_req);
    while (scan_offset < req_len) {
      uint8_t len = req[scan_offset];
      if (len == 0) {
        scan_offset++;
        break;
      }
      if ((len & 0xC0) == 0xC0) {
        scan_offset += 2;
        break;
      }
      scan_offset += len + 1;
    }
    if (i < qdcount)
      scan_offset += 4;
    else {
      if (scan_offset + 10 <= req_len) {
        uint16_t rtype = (req[scan_offset] << 8) | req[scan_offset + 1];
        uint16_t rclass = (req[scan_offset + 2] << 8) | req[scan_offset + 3];
        uint16_t rdlen = (req[scan_offset + 8] << 8) | req[scan_offset + 9];
        if (is_opt && rtype == 41) {
          has_edns = true;
          client_payload_size = rclass;
          break;
        }
        scan_offset += 10 + rdlen;
      }
    }
  }
  if (has_edns && max_res_len == 512) {
    if (client_payload_size > 1232)
      client_payload_size = 1232;
    if (client_payload_size > 512)
      max_res_len = client_payload_size;
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
    return copy_len;
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
    return copy_len;
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
    res[3] |= 3;
    return q_offset;
  }

  uint16_t offset = q_offset, ancount = 0, nscount = 0, arcount = 0;
  resolve_name(current_qname, qtype, &db_entry, &current_zone, res, max_res_len,
               &offset, comp_ctx, &ancount, &nscount, &arcount);
  if (has_edns && offset + 11 <= max_res_len) {
    res[offset++] = 0;
    res[offset++] = 0;
    res[offset++] = 41;
    res[offset++] = 1232 >> 8;
    res[offset++] = 1232 & 0xFF;
    res[offset++] = 0;
    res[offset++] = 0;
    res[offset++] = 0;
    res[offset++] = 0;
    res[offset++] = 0;
    res[offset++] = 0;
    arcount++;
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
    if (send(tcp_fd, axfr_req, req_len, 0) == req_len)
      handle_axfr_event(tcp_fd, ctx->entry, &stream_ctx, &session,
                        ctx->tsig_key);
    close(tcp_fd);
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
  uint16_t id = (uint16_t)(time(NULL) & 0xFFFF);
  req[0] = id >> 8;
  req[1] = id & 0xFF;
  req[2] = 0x20;
  req[3] = 0;
  req[4] = 0;
  req[5] = 1;
  size_t offset = 12;
  offset += write_uncompressed_name(&req[offset], domain);
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

    // Capsicum対応：動的UDPソケット生成を避け、FrontendへIPC転送して送信を依頼する
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
      struct tm *tm_info = localtime(&now);
      ch->current_date = (tm_info->tm_year + 1900) * 10000 +
                         (tm_info->tm_mon + 1) * 100 + tm_info->tm_mday;
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
  struct tm *tm_info = localtime(&ts.tv_sec);
  int today = (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 +
              tm_info->tm_mday;
  char time_str[64] = "";
  if (ch->print_time) {
    char buf[32];
    strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S", tm_info);
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

void send_axfr_response(int client_fd, const char *qname, uint8_t *req,
                        uint16_t req_len, tsig_key_t *tsig_key) {
  zone_db_entry_t *entry = get_zone(qname);
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
  q_offset += 4;
  if (q_offset > req_len)
    q_offset = req_len;
  uint16_t offset = q_offset;
  uint16_t answers = 0;
  uint16_t *res_ancount = (uint16_t *)&res[6];
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
      dns_record_t *rec = &current_zone->records[i];
      uint16_t prev_offset = offset;
      if (serialize_dns_record(res, 65000, &offset, rec, &comp_ctx, NULL,
                               0xFFFFFFFF) < 0) {
        *res_ancount = htons(answers);
        if (tsig_key) {
          size_t sign_len = prev_offset;
          tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, prior_mac,
                           &prior_mac_len);
          prev_offset = sign_len;
        }
        uint8_t len_prefix[2] = {prev_offset >> 8, prev_offset & 0xFF};
        if (send_tcp_robust(client_fd, len_prefix, 2) < 0)
          goto axfr_error;
        if (send_tcp_robust(client_fd, res, prev_offset) < 0)
          goto axfr_error;
        offset = q_offset;
        answers = 0;
        memcpy(res, req, q_offset);
        res[2] |= 0x84;
        res[3] &= 0x0F;
        res[8] = 0;
        res[9] = 0;
        res[10] = 0;
        res[11] = 0;
        memset(&comp_ctx, 0, sizeof(comp_ctx));
        compress_ctx_init_packet(&comp_ctx);
        if (serialize_dns_record(res, 65000, &offset, rec, &comp_ctx, NULL,
                                 0xFFFFFFFF) < 0)
          continue;
      }
      answers++;
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
axfr_error:
  if (res)
    free(res);
  atomic_fetch_sub_explicit(&current_zone->reader_count, 1,
                            memory_order_release);
}

void *axfr_worker_thread(void *arg) {
  axfr_worker_args_t *args = (axfr_worker_args_t *)arg;
  zone_db_entry_t *entry = get_zone(args->qname);
  send_axfr_response(args->client_fd, args->qname, args->req, args->req_len,
                     args->tsig_key);
  close(args->client_fd);
  free(args);
  if (entry)
    atomic_fetch_sub(&entry->active_axfr, 1);
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

  int created_sockets = 0;

  // 【変更点】 WorkerではTCPのみバインドする (UDPはFrontendが担当)
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
          created_sockets++;
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
          created_sockets++;
        } else
          close(tcp_fd);
      }
    }
  }

  if (created_sockets == 0) {
    syslog(LOG_WARNING,
           "[Worker %d] No TCP listener could be bound; TCP queries/AXFR will "
           "not be served by this worker",
           ctx->thread_id);
  }

  // FrontendからのUDP転送を受け取るIPCパイプをkqueueに登録 (udata=1)
  int my_ipc_fd = g_ipc_fds[ctx->thread_id][1];
  struct kevent ev_ipc;
  EV_SET(&ev_ipc, my_ipc_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)1);
  kevent(kq, &ev_ipc, 1, NULL, 0, NULL);

  // (TCPリスナーが開けなくてもIPCでUDP処理は可能なのでエラー終了しない)
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
        // 【変更点】 UDP (IPC経由)
        int active_fd = ev_list[i].ident; // my_ipc_fd
        while (1) {
          uint8_t req_buf_full[BUFFER_SIZE + sizeof(udp_ipc_t)];
          ssize_t received =
              recv(active_fd, req_buf_full, sizeof(req_buf_full), 0);
          if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
              break;
            break;
          }
          if (received < (ssize_t)sizeof(udp_ipc_t))
            continue;

          udp_ipc_t *ipc_msg = (udp_ipc_t *)req_buf_full;
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
                offset++;
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
          int res_len =
              process_dns_query(req_buf, payload_received, res_buf, 512, qname,
                                qtype, client_ip, &thread_compress_ctx, false);
          if (res_len > 0) {
            if (rrl_check((struct sockaddr *)client_addr)) {
              udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
              *res_msg = *ipc_msg;
              res_msg->payload_len = res_len;
              send(active_fd, res_buf_full, sizeof(udp_ipc_t) + res_len,
                   0); // IPCでFrontendに送り返す
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
          bool has_edns = false;
          bool dnssec_ok = false;
          if (msg_len > 12) {
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
            uint16_t arcount = (msg[10] << 8) | msg[11];
            if (arcount > 0) {
              size_t o = 12;
              uint16_t qd = (msg[4] << 8) | msg[5];
              uint16_t an = (msg[6] << 8) | msg[7];
              uint16_t ns = (msg[8] << 8) | msg[9];
              for (int k = 0; k < qd; k++) {
                while (o < msg_len && msg[o] != 0 && (msg[o] & 0xC0) != 0xC0)
                  o += msg[o] + 1;
                if (o < msg_len && (msg[o] & 0xC0) == 0xC0)
                  o += 2;
                else
                  o++;
                o += 4;
              }
              for (int k = 0; k < an + ns + arcount; k++) {
                if (o >= msg_len)
                  break;
                while (o < msg_len && msg[o] != 0 && (msg[o] & 0xC0) != 0xC0)
                  o += msg[o] + 1;
                if (o < msg_len && (msg[o] & 0xC0) == 0xC0)
                  o += 2;
                else
                  o++;
                if (o + 10 <= msg_len) {
                  uint16_t rt = (msg[o] << 8) | msg[o + 1];
                  uint32_t ttl = ((uint32_t)msg[o + 4] << 24) |
                                 ((uint32_t)msg[o + 5] << 16) |
                                 ((uint32_t)msg[o + 6] << 8) | msg[o + 7];
                  uint16_t rdl = (msg[o + 8] << 8) | msg[o + 9];
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
          write_query_log(ctx_tcp->client_ip, client_port, qname, qclass, qtype,
                          has_edns, dnssec_ok);

          if (qtype == 252 || qtype == 251) {
            uint32_t req_serial = 0;
            (void)
                req_serial; // TODO:
                            // IXFR応答(差分転送)を実装する際にここで使う。現状は常にフルAXFRを返す
            if (qtype == 251) {
              size_t offset = 12;
              uint16_t qdcount = (msg[4] << 8) | msg[5];
              uint16_t nscount = (msg[8] << 8) | msg[9];
              for (int k = 0; k < qdcount; k++) {
                while (offset < msg_len && msg[offset] != 0 &&
                       (msg[offset] & 0xC0) != 0xC0)
                  offset += msg[offset] + 1;
                if (offset < msg_len && (msg[offset] & 0xC0) == 0xC0)
                  offset += 2;
                else
                  offset++;
                offset += 4;
              }
              if (nscount > 0 && offset + 10 <= msg_len) {
                while (offset < msg_len && msg[offset] != 0 &&
                       (msg[offset] & 0xC0) != 0xC0)
                  offset += msg[offset] + 1;
                if (offset < msg_len && (msg[offset] & 0xC0) == 0xC0)
                  offset += 2;
                else
                  offset++;
                uint16_t rr_type = (msg[offset] << 8) | msg[offset + 1];
                offset += 8;
                uint16_t rdlen = (msg[offset] << 8) | msg[offset + 1];
                offset += 2;
                if (rr_type == 6 && offset + rdlen <= msg_len) {
                  size_t ptr = offset;
                  while (ptr < msg_len && msg[ptr] != 0 &&
                         (msg[ptr] & 0xC0) != 0xC0)
                    ptr += msg[ptr] + 1;
                  if (ptr < msg_len && (msg[ptr] & 0xC0) == 0xC0)
                    ptr += 2;
                  else
                    ptr++;
                  while (ptr < msg_len && msg[ptr] != 0 &&
                         (msg[ptr] & 0xC0) != 0xC0)
                    ptr += msg[ptr] + 1;
                  if (ptr < msg_len && (msg[ptr] & 0xC0) == 0xC0)
                    ptr += 2;
                  else
                    ptr++;
                  if (ptr + 4 <= msg_len)
                    req_serial = (msg[ptr] << 24) | (msg[ptr + 1] << 16) |
                                 (msg[ptr + 2] << 8) | msg[ptr + 3];
                }
              }
            }
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
            zone_db_entry_t *entry = get_zone(qname);
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
              }
              uint8_t len_prefix[2] = {copy_len >> 8, copy_len & 0xFF};
              send(client_fd, len_prefix, 2, 0);
              send(client_fd, res_buf, copy_len, 0);
              close(client_fd);
            }
            free(ctx_tcp);
          } else {
            uint8_t *tcp_res = malloc(65535);
            if (tcp_res) {
              int res_len = process_dns_query(msg, msg_len, tcp_res, 65535,
                                              qname, qtype, ctx_tcp->client_ip,
                                              &thread_compress_ctx, true);
              if (res_len > 0) {
                uint8_t len_prefix[2] = {res_len >> 8, res_len & 0xFF};
                send(client_fd, len_prefix, 2, 0);
                send(client_fd, tcp_res, res_len, 0);
              }
              free(tcp_res);
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
  struct kevent ev_list[4];
  while (1) {
    int n = kevent(kq, NULL, 0, ev_list, 4, NULL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    for (int i = 0; i < n; i++) {
      if (ev_list[i].filter == EVFILT_SIGNAL && ev_list[i].ident == SIGHUP) {
        char *config_str = read_entire_file(g_config_path);
        if (!config_str)
          continue;
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
        standby->zones = NULL;
        free_logging_channels(standby);
        tsig_key_t *k = standby->keys;
        while (k) {
          tsig_key_t *next_k = k->next;
          free(k->name);
          free(k->algorithm);
          free(k->secret);
          free(k);
          k = next_k;
        }
        standby->keys = NULL;
        if (parse_named_conf(config_str, standby) == 0) {
          init_logging_channels(standby);
          atomic_store_explicit(&g_config_db.active, standby,
                                memory_order_release);
          load_zones_from_config(standby);
        }
        free(config_str);
      } else if (ev_list[i].filter == EVFILT_TIMER ||
                 ev_list[i].filter == EVFILT_USER) {
        time_t now = time(NULL);
        server_config_t *active =
            atomic_load_explicit(&g_config_db.active, memory_order_acquire);
        zone_config_t *zone = active->zones;
        while (zone) {
          if (zone->type && strcasecmp(zone->type, "slave") == 0 &&
              zone->masters_count > 0 && zone->masters[0].ip != NULL) {
            zone_db_entry_t *entry = get_or_create_zone(zone->domain);
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
        syslog(LOG_CRIT,
               "[Frontend] Backend process (pid=%d) exited unexpectedly. "
               "Shutting down.",
               backend_pid);
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
                       sizeof(buffer) - sizeof(udp_ipc_t), 0,
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
          sendto(g_udp_fds[msg->sock_fd_idx], buffer + sizeof(udp_ipc_t),
                 msg->payload_len, 0, (struct sockaddr *)&msg->client_addr,
                 msg->addr_len);
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
  }

  socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_ipc);
  fcntl(g_notify_ipc[0], F_SETFL,
        fcntl(g_notify_ipc[0], F_GETFL, 0) | O_NONBLOCK);
  fcntl(g_notify_ipc[1], F_SETFL,
        fcntl(g_notify_ipc[1], F_GETFL, 0) | O_NONBLOCK);

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
  if (argc < 2) {
    syslog(LOG_ERR, "Usage: %s <config_file>", argv[0]);
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

  g_config_path = argv[1];
  openlog("KariDNS", LOG_PID | LOG_NDELAY, LOG_DAEMON);
  start_connect_broker();
  daemonize();
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
  load_zones_from_config(&g_config_db.config_a);

  int num_workers = sysconf(_SC_NPROCESSORS_ONLN);
  if (num_workers <= 0)
    num_workers = 2;

  // 【追加】プロセス分岐前のUDP・IPCソケット初期化
  setup_udp_and_ipc(&g_config_db.config_a, num_workers);

  // 【追加】プロセスの分離
  pid_t pid = fork();
  if (pid < 0) {
    syslog(LOG_ERR, "fork for frontend router failed");
    exit(1);
  }

  if (pid > 0) {
    // --- 親プロセス (Frontend UDP Router) ---
    run_frontend_router(pid);
    exit(0);
  }

  // --- 子プロセス (Backend DNS Workers) ---
  // Frontend用FDのクローズ
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
    setgroups(0, NULL);
    setgid(target_gid);
    setuid(pwd->pw_uid);
  } else if (cfg->group) {
    struct group *grp = getgrnam(cfg->group);
    if (!grp)
      exit(EXIT_FAILURE);
    setgroups(0, NULL);
    setgid(grp->gr_gid);
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