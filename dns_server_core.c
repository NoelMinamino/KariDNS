#define OPENSSL_SUPPRESS_DEPRECATED 1
#define STATIC_TEST
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
#include <netinet/tcp.h> // TCP_MAXSEG
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
#include "dns_log.h"
#include <time.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#include <sys/utsname.h>

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
#include "dns_snapshot_rcu.h"
#include "dns_db_supervisor.h"
#include "dns_db_ingest.h"
#include "dns_alias.h"

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
_Static_assert(KARIDNS_LISTEN_MAX == MAX_BIND_ADDRS, "the parser's limit on listen addresses is the number of Frontend sockets");


config_rcu_t g_config_db;

server_config_t *acquire_config_snapshot(void) {
  return atomic_load_explicit(&g_config_db.active, memory_order_acquire);
}

void release_config_snapshot(server_config_t *snap) {
  (void)snap;
}

/* S6a: 退いた設定の解放。公開した設定の入れ替え (制御スレッドだけが行う) で退いた設定は、retire_epoch 以下の
 * 世代で読み取り区間に入ったスレッドがいなくなれば誰からも見えない (ワーカー、ロガー、ゾーン転送スレッドなど
 * 制御スレッド以外は設定を読み取り区間の中でだけ読み、ポインタを区間の外へ持ち出さない)。
 * 以前は次のリロードまで退いた設定を持ち続けて 2 世代ぶん確保していた。 */
bool config_standby_reap(bool wait) {
  if (!g_config_db.standby_pending) return true;
  if (wait ? !rcu_writer_wait_until_safe(g_config_db.retire_epoch, 10000)
           : !rcu_writer_is_safe(g_config_db.retire_epoch))
    return false;
  server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  server_config_t *standby = (active == &g_config_db.config_a) ? &g_config_db.config_b : &g_config_db.config_a;
  free_server_config_fields(standby);
  g_config_db.standby_pending = false;
  g_config_db.standby_freed++;
  return true;
}
/* written once by the control thread (release); the workers and transfer threads read it (acquire) */
_Atomic int g_control_kq = -1;
int g_cwd_fd = -1;
STATIC_TEST const char *g_config_path = NULL;
static int g_cli_port_override = 0;
_Atomic int g_bound_workers = 0;
STATIC_TEST _Atomic bool g_privilege_drop_complete = false;
// 制御スレッドが SIGTERM / SIGINT を EVFILT_SIGNAL で受けられるようになった (backend_sig_handler)
STATIC_TEST _Atomic bool g_control_signals_ready = false;
// P5: バックエンドを fork したマネージャーの PID。SIGHUP はマネージャーから転送されたものだけでリロードする
static pid_t g_manager_pid = 0;

#define NUM_FRONTEND_ROUTERS 2
#define MAX_FRONTEND_ROUTERS 4
#define MAX_WORKERS 128

// Frontend/Backend IPC用グローバル変数
STATIC_TEST int g_num_frontend_routers = NUM_FRONTEND_ROUTERS;
STATIC_TEST int g_ipc_fds[MAX_FRONTEND_ROUTERS][MAX_WORKERS][2];
STATIC_TEST int g_num_workers = 0;
char g_startup_cwd[PATH_MAX] = "";
int g_notify_ipc[2];
/* NOTIFY の応答 (QR=1, OPCODE=4) を UDP ワーカーから制御スレッドへ渡す (Backend の中だけで使う) */
int g_notify_resp_ipc[2] = {-1, -1};
int g_control_sock = -1;
_Atomic(bool) g_frontend_alive = true;

time_t g_boot_time = 0;
time_t g_last_configured_time = 0;

/* D-12: karictl status に返す karidns 自身の値。起動時 (サンドボックスの前) に1回だけ取る */
static struct {
  struct utsname un;
  int ncpus;
} g_host_status_info;

STATIC_TEST void capture_host_status_info(void) {
  if (uname(&g_host_status_info.un) != 0) memset(&g_host_status_info.un, 0, sizeof(g_host_status_info.un));
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  g_host_status_info.ncpus = n > 0 ? (int)n : 1;
}
_Atomic int g_xfers_running = ATOMIC_VAR_INIT(0);
_Atomic int g_tcp_clients = ATOMIC_VAR_INIT(0);
_Atomic int g_tcp_high_water = ATOMIC_VAR_INIT(0);

#define response_log_enabled(cfg) ((cfg) && (cfg)->logging.responses_enabled)

resp_log_entry_t g_resp_log_ring[RESP_LOG_RING_SIZE];
_Atomic uint64_t g_resp_log_tail = ATOMIC_VAR_INIT(0);
_Atomic uint64_t g_resp_log_head = ATOMIC_VAR_INIT(0);

_Atomic bool g_qlog_circuit_broken = ATOMIC_VAR_INIT(false);
_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);

uint32_t get_effective_query_log_max_qps(const server_config_t *cfg) {
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


// -p の値の判定。全体が 10 進数字だけのときだけポート番号として扱う
// (先頭1文字だけで判定すると "1.pid" のような PID ファイル名がポートになる)。
// 戻り値: 1 = ポート (*port_out に格納), 0 = 数字以外を含む (PID ファイル), -1 = 範囲外のポート番号
int parse_cli_port_arg(const char *val, int *port_out) {
  if (!val || !*val) return 0;
  for (const char *p = val; *p; p++) {
    if (!isdigit((unsigned char)*p)) return 0;
  }
  char *end = NULL;
  errno = 0;
  long v = strtol(val, &end, 10);
  if (errno != 0 || *end != '\0' || v < 1 || v > 65535) return -1;
  if (port_out) *port_out = (int)v;
  return 1;
}

// リスニングソケットの bind() 失敗時にログへ添えるヒント。
const char *bind_error_hint(int err, int port) {
  if (err == EACCES && port > 0 && port < 1024)
    return " (ports below 1024 require root privileges: start karidns as root, "
           "or use a port >= 1024 such as 'port 10053;' / -p 10053)";
  if (err == EADDRINUSE)
    return " (address already in use by another process)";
  if (err == EADDRNOTAVAIL)
    return " (address is not configured on this host)";
  return "";
}

/* The socket address of one entry of server_config_t.listen (config_build_listen()).  The UDP sockets of the Frontend, the TCP sockets
 * of the workers and the start-up check all open the addresses of that list and nothing else. */
static socklen_t listen_addr_sockaddr(const listen_addr_t *la, struct sockaddr_storage *ss) {
  memset(ss, 0, sizeof(*ss));
  if (la->family == AF_INET) {
    struct sockaddr_in *a4 = (struct sockaddr_in *)ss;
    a4->sin_family = AF_INET;
    memcpy(&a4->sin_addr, la->addr, 4);
    a4->sin_port = htons(la->port);
    return sizeof(*a4);
  }
  struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ss;
  a6->sin6_family = AF_INET6;
  memcpy(&a6->sin6_addr, la->addr, 16);
  a6->sin6_port = htons(la->port);
  return sizeof(*a6);
}

// ワーカースレッドのTCPリスニングソケットの bind() 失敗数。
// Backendは全ワーカーのbind完了後にこれを確認し、1件でもあれば起動を中止する。
STATIC_TEST _Atomic int g_tcp_bind_failures = 0;
// 起動に失敗したワーカースレッドの数 (X-33)。1 本でもあれば起動を中止する。
STATIC_TEST _Atomic int g_worker_start_failures = 0;

// Broker
STATIC_TEST int g_broker_sock = -1;
STATIC_TEST pid_t g_broker_pid = -1;
__attribute__((unused)) STATIC_TEST void start_connect_broker(void) {
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return;

  /* [SEC] このブローカー子プロセスが行うのは socket()+connect() の代行
   * だけであり、いずれもroot権限を必要としない。しかし従来はfork時点の
   * 実効ユーザー(多くの構成ではroot)のまま無期限に稼働し続けていた。
   * ブローカーはCapsicumサンドボックス突入後のワーカーからも
   * (family, type, addr) を渡すだけで任意の相手へconnect()させられる
   * ため、万一呼び出し側(サンドボックス内のワーカー)が何らかのバグで
   * 攻撃者に汚染された場合、本来Capsicumが塞ぐはずの「新規ソケット
   * 作成」をroot権限のまま代行してしまう"特権エスカレーション用の
   * オラクル"になり得る。connect()自体に特権は不要なため、fork直後・
   * 要求ループ開始前に、サーバ本体と同じ実行ユーザーへ降格する。
   * 降格に失敗した場合は稼働を継続させず終了する(fail-closed)。 */
  /* 降格先は main() が起動時に解決した g_run_identity (O-18: ここで名前を引き直さない) */
  bool need_drop = (geteuid() == 0);

  gc_snapshot_wait_idle();
  pid_t pid = fork();
  if (pid < 0) {
    close(sv[0]);
    close(sv[1]);
    return;
  }
  if (pid == 0) {
    klog_set_role(KLOG_ROLE_AUX);
    close(sv[0]);
    if (need_drop) {
      char id_err[256];
      if (!g_run_identity.privileged || !g_run_identity.has_user ||
          !apply_run_identity_id(&g_run_identity, id_err, sizeof(id_err))) {
        syslog(LOG_ERR, "[Broker] Failed to drop privileges; refusing to run as root");
        close(sv[1]);
        _exit(1);
      }
    }
    logging_drop_fchown();
    /* AF_UNIX で connect してよいのは起動時に設定された dnstap ソケットだけ (再接続用)。
     * それ以外のローカルソケットへ実行ユーザーとして接続させる口にはしない。 */
    char allowed_unix_path[sizeof(((struct sockaddr_un *)0)->sun_path)] = "";
    if (g_config_db.config_a.dnstap.enabled && g_config_db.config_a.dnstap.socket_path)
      strlcpy(allowed_unix_path, g_config_db.config_a.dnstap.socket_path, sizeof(allowed_unix_path));
    broker_req_t req;
    while (recv(sv[1], &req, sizeof(req), MSG_WAITALL) == sizeof(req)) {
      size_t addr_len = 0;
      if (req.family == AF_INET)
        addr_len = sizeof(struct sockaddr_in);
      else if (req.family == AF_INET6)
        addr_len = sizeof(struct sockaddr_in6);
      else if (req.family == AF_UNIX && req.type == SOCK_STREAM && allowed_unix_path[0] != '\0') {
        struct sockaddr_un *sun = (struct sockaddr_un *)&req.addr;
        sun->sun_path[sizeof(sun->sun_path) - 1] = '\0';
        if (sun->sun_family == AF_UNIX && strcmp(sun->sun_path, allowed_unix_path) == 0)
          addr_len = sizeof(struct sockaddr_un);
      }
      int sock = addr_len > 0 ? socket(req.family, req.type, 0) : -1;
      int ret = -1;
      if (sock >= 0) {
        if (req.type == SOCK_STREAM && req.family != AF_UNIX) {
          /* zone-tcp-window / zone-tcp-sndbuf (または tcp-window): connect() 前なので
           * SYN で通知する初期ウィンドウから効く */
          if (req.tcp_opts.rcvbuf > 0)
            setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &req.tcp_opts.rcvbuf, sizeof(int));
          if (req.tcp_opts.sndbuf > 0)
            setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &req.tcp_opts.sndbuf, sizeof(int));
        }
        /* O-04: 接続の完了はここでは待たない。非ブロッキングで connect() を始めた fd を
         * すぐ返し、完了待ち (と TCP_MAXSEG) は要求側が自分の期限で行う。待っている間に
         * 他の要求 (別のゾーン転送や forward) がブローカーで止まらない。 */
        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
        /* transfer-source / primaries source (batch 4): bind the local address (port 0) before connect().  Only an address that was in the
         * configuration when the server started is accepted -- the broker must not bind whatever a compromised Backend names -- and a bind
         * that fails fails the connection (the transfer is not made from another address than the operator asked for). */
        bool src_ok = true;
        if (req.type == SOCK_STREAM && req.family != AF_UNIX && req.tcp_opts.has_src) {
          /* a transfer source, or a NOTIFY source (a NOTIFY over TCP leaves from the address of the UDP one) */
          if (!config_xfr_source_allowed(req.family, req.tcp_opts.src, true) && !config_xfr_source_allowed(req.family, req.tcp_opts.src, false)) {
            src_ok = false;
          } else if (req.family == AF_INET) {
            struct sockaddr_in sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            memcpy(&sin.sin_addr, req.tcp_opts.src, sizeof(sin.sin_addr));
            src_ok = bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == 0;
          } else {
            struct sockaddr_in6 sin6;
            memset(&sin6, 0, sizeof(sin6));
            sin6.sin6_family = AF_INET6;
            memcpy(&sin6.sin6_addr, req.tcp_opts.src, sizeof(sin6.sin6_addr));
            src_ok = bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)) == 0;
          }
        }
        if (src_ok) {
          ret = connect(sock, (struct sockaddr *)&req.addr, addr_len);
          if (ret < 0 && errno == EINPROGRESS)
            ret = 0;
        }
      }
      if (ret == 0) {
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
      if (sock >= 0)
        close(sock);
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
  return broker_connect_opts(family, type, addr, addr_len, NULL);
}

/* ブローカーから受け取った、接続を始めたばかりの fd の完了を待つ。
 * 成功時は TCP_MAXSEG を当て、ブロッキングモードへ戻して true。 */
static bool broker_finish_connect(int fd, int type, const tcp_sockopts_t *tcp_opts) {
  int timeout_ms = (tcp_opts && tcp_opts->connect_timeout_ms > 0) ? tcp_opts->connect_timeout_ms
                                                                    : BROKER_CONNECT_TIMEOUT_MS;
  struct pollfd pfd = { .fd = fd, .events = POLLOUT };
  int pr;
  do {
    pr = poll(&pfd, 1, timeout_ms);
  } while (pr < 0 && errno == EINTR);
  if (pr <= 0)
    return false;
  int so_error = 0;
  socklen_t elen = sizeof(so_error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &elen) != 0 || so_error != 0)
    return false;
#ifdef TCP_MAXSEG
  /* zone-tcp-mss / tcp-mss: 確立後に送信 MSS を下げる (apply_tcp_mss() と同じ理由) */
  if (type == SOCK_STREAM && tcp_opts && tcp_opts->mss > 0)
    setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &tcp_opts->mss, sizeof(int));
#else
  (void)type;
#endif
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
  return true;
}

int broker_connect_opts(int family, int type, struct sockaddr *addr,
                        size_t addr_len, const tcp_sockopts_t *tcp_opts) {
  if (g_broker_sock < 0)
    return -1;
  if (addr_len > sizeof(struct sockaddr_storage))
    return -1;
  broker_req_t req;
  memset(&req, 0, sizeof(req));
  req.family = family;
  req.type = type;
  memcpy(&req.addr, addr, addr_len);
  if (tcp_opts) req.tcp_opts = *tcp_opts;
  /* 要求と応答の対応を保つためだけの排他。ブローカーは connect() の完了を待たずに
   * 応答するので、保持するのは2回のシステムコールの間だけ (O-04)。 */
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
  if (fd >= 0 && !broker_finish_connect(fd, type, tcp_opts)) {
    close(fd);
    return -1;
  }
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

// ============================================================================
// 9. AXFR専用バックグラウンドスレッド (Detached)


// ============================================================================
// 10. Logging
// ============================================================================

/* 実行ユーザー(options { user / group })へ引き渡すログの所有者を求める。
 * root起動かつ user 指定時以外は (uid_t)-1 (所有者変更なし)。
 * O-18: main() が起動時に解決した g_run_identity を使う (user/group の変更は再起動が
 * 必要な設定なので、reload 時の設定から引き直さない)。 */
static void resolve_log_owner(uid_t *uid, gid_t *gid) {
  *uid = (uid_t)-1;
  *gid = (gid_t)-1;
  if (geteuid() == 0 && g_run_identity.has_user) {
    *uid = g_run_identity.uid;
    *gid = g_run_identity.gid;
  }
}

/* root起動時: ログファイルの親ディレクトリが無ければ作成し、このとき作ったディレクトリだけを
 * target_uid の所有にする。既にあるディレクトリの所有者は変えない (P2: 運用者が用意した
 * ディレクトリを root 権限で実行ユーザーのものにしない。BIND と同じく、既存のディレクトリは
 * 運用者が実行ユーザーが書ける状態にしておく。docs/karidns.md "logging")。 */
/* The directories this process created (startup opens the logs first and hands them over later, hand_off_logging_channels():
 * the second call finds the directory there and must still know that it made it). */
#define LOG_DIRS_CREATED_MAX 64
static char g_log_dirs_created[LOG_DIRS_CREATED_MAX][PATH_MAX];
static int g_log_dirs_created_n;

static bool log_dir_was_created(const char *dir) {
  for (int i = 0; i < g_log_dirs_created_n; i++)
    if (strcmp(g_log_dirs_created[i], dir) == 0) return true;
  return false;
}

static void prepare_log_dir(const char *file_path, uid_t target_uid, gid_t target_gid) {
  if (geteuid() != 0)
    return;
  char dirbuf[PATH_MAX], basebuf[PATH_MAX];
  if (split_path_for_openat(file_path, dirbuf, sizeof(dirbuf), basebuf, sizeof(basebuf))) {
    if (dirbuf[0] != '\0' && strcmp(dirbuf, ".") != 0) {
      /* [SEC] 以前は stat(dirbuf) -> mkdir(dirbuf) -> chown(dirbuf) と
       * パス文字列を都度再解決していたため、各呼び出しの間に
       * dirbuf を(攻撃者が書き込み可能な親ディレクトリ経由で)
       * シンボリックリンクへ差し替えられると、root権限で任意の
       * パス(例: /etc 配下)の所有者をサービス実行ユーザーへ
       * 変更されてしまうTOCTOUレースが存在した(CWE-367)。
       * ここでは親ディレクトリのfdを取得した上でmkdirat/openatを
       * 用い、最終的にO_NOFOLLOWで開いたディレクトリfdに対して
       * のみfchown()する。シンボリックリンクが置かれていた場合は
       * openatがELOOPで失敗し、所有者変更は行われない
       * (fail-closed)。 */
      char parent_buf[PATH_MAX], leaf_buf[PATH_MAX];
      int pfd = -1;
      const char *leaf = NULL;
      if (strcmp(dirbuf, "/") == 0) {
        pfd = -1; /* ルートは対象外 */
      } else if (split_path_for_openat(dirbuf, parent_buf, sizeof(parent_buf), leaf_buf, sizeof(leaf_buf))) {
        const char *popen_path = parent_buf[0] ? parent_buf : "/";
        pfd = open(popen_path, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
        leaf = leaf_buf;
      }
      if (pfd >= 0 && leaf) {
        /* P2: only a directory this call made is handed to the run user; an existing one (EEXIST, or a
         * failure that openat below then explains) keeps its owner */
        bool created = mkdirat(pfd, leaf, 0755) == 0;
        if (created && g_log_dirs_created_n < LOG_DIRS_CREATED_MAX && strlen(dirbuf) < PATH_MAX)
          strcpy(g_log_dirs_created[g_log_dirs_created_n++], dirbuf);
        bool mine = created || log_dir_was_created(dirbuf);
        int ddfd = openat(pfd, leaf, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_RDONLY);
        if (ddfd >= 0) {
          if (mine && target_uid != (uid_t)-1)
            fchown(ddfd, target_uid, target_gid);
          close(ddfd);
        }
        close(pfd);
      }
    }
  }
}

/* log_open_channels() (below) opens every channel of the runtime that has a file.  Start-up: a file that cannot be opened stops the
 * start, a reload that cannot open one is refused.  hand_off=false: the owner of directories and files is not changed.
 * 起動時は daemonize() 前にこれで open だけを済ませ、所有者の引き渡しは
 * pid file / 制御ソケットのディレクトリ検証 (ensure_priv_dir_safe) の後に
 * hand_off_logging_channels() で行う (ログと pid file が同じディレクトリの
 * 場合、先に実行ユーザーへ chown すると検証が失敗するため)。 */
/* P3: a log file that was just opened (O_CREAT | O_APPEND, through the directory fd) is written to, and as root
 * handed to the run user with fchown().  Only a plain file with one link whose owner is root, the user karidns runs
 * as now, or the run user it will drop to is accepted: a hard link planted at the log path would otherwise let the
 * file it points to be appended to and handed over.  Returns the file's size, or -1 (logged) when it is refused. */
static off_t log_file_accept(int fd, const char *path, uid_t target_uid) {
  struct stat st;
  const char *why = NULL;
  char detail[96] = "";
  if (fstat(fd, &st) != 0) {
    snprintf(detail, sizeof(detail), "fstat: %s", strerror(errno));
    why = detail;
  } else if (!S_ISREG(st.st_mode)) {
    why = "not a regular file";
  } else if (st.st_nlink != 1) {
    snprintf(detail, sizeof(detail), "it has %u links (a hard link?)", (unsigned)st.st_nlink);
    why = detail;
  } else if (st.st_uid != 0 && st.st_uid != geteuid() && (target_uid == (uid_t)-1 || st.st_uid != target_uid)) {
    snprintf(detail, sizeof(detail), "owned by uid %u, neither root nor the user karidns runs as", (unsigned)st.st_uid);
    why = detail;
  }
  if (why) {
    syslog(LOG_ERR, "[Logging] Refusing to use log file '%s': %s", path, why);
    fprintf(stderr, "[ERROR] [Logging] Refusing to use log file '%s': %s\n", path, why);
    return -1;
  }
  return st.st_size;
}

int log_open_channels(log_channel_t *list, bool hand_off) {
  bool hard = false, restart = false;
  uid_t target_uid = (uid_t)-1;
  gid_t target_gid = (gid_t)-1;
  uid_t run_uid, run_gid;
  resolve_log_owner(&run_uid, &run_gid);   /* the run user: the owner of a log file from an earlier start (P3) */
  if (hand_off) {
    target_uid = run_uid;
    target_gid = run_gid;
  }

  for (log_channel_t *ch = list; ch; ch = ch->next) {
    if (ch->dest != LOGDEST_FILE || !ch->file_path)
      continue;
    prepare_log_dir(ch->file_path, target_uid, target_gid);

    ch->fd = open_via_dir_cache(ch->file_path, O_WRONLY | O_CREAT | O_APPEND, 0644, true);
    if (ch->fd >= 0) {
      off_t size = log_file_accept(ch->fd, ch->file_path, run_uid);
      if (size < 0) {
        close(ch->fd);
        ch->fd = -1;
        hard = true;
      } else {
        if (geteuid() == 0 && target_uid != (uid_t)-1) {
          fchown(ch->fd, target_uid, target_gid);
        }
        ch->current_size = size;
      }
    } else {
      int open_errno = errno;
#ifdef ENOTCAPABLE
      /* a reload names a directory that was not opened before the sandbox: nothing can open it now, a restart can */
      if (open_errno == ENOTCAPABLE && atomic_load_explicit(&g_capsicum_enabled, memory_order_acquire)) {
        syslog(LOG_WARNING, "[Logging] Log file '%s' is in a directory that was not opened at start-up; it is used after a restart "
                            "(until then the logging configuration in use stays as it is)", ch->file_path);
        restart = true;
        continue;
      }
#endif
      const char *hint = (open_errno == EACCES || open_errno == EPERM || open_errno == EROFS)
          ? " (not writable by the user karidns runs as; choose a log path in a directory that user can write to)"
          : "";
      syslog(LOG_ERR, "[Logging] Failed to open log file '%s': %s%s",
             ch->file_path, strerror(open_errno), hint);
      fprintf(stderr, "[ERROR] [Logging] Failed to open log file '%s': %s%s\n",
              ch->file_path, strerror(open_errno), hint);
      hard = true;
    }
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    ch->current_date = (tm_info.tm_year + 1900) * 10000 +
                       (tm_info.tm_mon + 1) * 100 + tm_info.tm_mday;
  }
  return hard ? -1 : restart ? 1 : 0;
}

/* The files of the runtime installed at start-up (log_runtime_install()) are handed to the run user (root start-up with `user`); the
 * directory and the files were opened before, by log_open_channels(hand_off = false), so that the pid file / control socket checks
 * (ensure_priv_dir_safe) see the directories as root owned. */
void hand_off_logging_channels(void) {
  uid_t target_uid;
  gid_t target_gid;
  resolve_log_owner(&target_uid, &target_gid);
  for (log_channel_t *ch = log_runtime_current_channels(); ch; ch = ch->next) {
    if (ch->dest != LOGDEST_FILE || !ch->file_path || ch->fd < 0)
      continue;
    if (target_uid != (uid_t)-1) {
      prepare_log_dir(ch->file_path, target_uid, target_gid);
      /* P3: the file was accepted when it was opened; a link added since would make the chown reach another name */
      if (log_file_accept(ch->fd, ch->file_path, target_uid) >= 0 && fchown(ch->fd, target_uid, target_gid) != 0)
        syslog(LOG_WARNING, "[Logging] Could not hand log file '%s' to the run user: %s", ch->file_path, strerror(errno));
    }
  }
  logging_drop_fchown();
}

/* The log files and the writable directory fds keep CAP_FCHOWN only until the hand-off above (also called by a child
 * forked before it). */
void logging_drop_fchown(void) {
  for (log_channel_t *ch = log_runtime_current_channels(); ch; ch = ch->next)
    fd_drop_fchown(ch->fd);
  dir_fd_cache_drop_fchown();
}

void submit_response_log(log_action_t action, const char *client_ip, int client_port, const char *qname, 
                                uint16_t qclass, uint16_t qtype, uint8_t rcode, 
                                bool has_edns, bool dnssec_ok) {
    server_config_t *cfg = acquire_config_snapshot();
    if (!cfg) return;
    bool enabled = cfg->logging.responses_enabled;
    release_config_snapshot(cfg);
    if (!enabled) return;

    uint64_t t = atomic_load_explicit(&g_resp_log_tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit(&g_resp_log_head, memory_order_acquire);
    
    // ロックフリー CAS ループ (バッファフルまたはConsumer未処理時は安全にドロップ)
    while (1) {
        if (t - h >= RESP_LOG_RING_SIZE) return; 
        uint32_t idx = t & (RESP_LOG_RING_SIZE - 1);
        if (atomic_load_explicit(&g_resp_log_ring[idx].ready, memory_order_acquire)) {
            return;
        }
        if (atomic_compare_exchange_weak_explicit(&g_resp_log_tail, &t, t + 1, 
                                                  memory_order_acq_rel, memory_order_relaxed)) {
            break;
        }
        h = atomic_load_explicit(&g_resp_log_head, memory_order_acquire);
    }
    
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
void escape_qname_for_log(const char *src, char *dst, size_t dst_size) {
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
      // qname は正規形 (dns_wire.h) で、エスケープ (\., \\, \DDD) 済み。二重にエスケープしない
      dst[di++] = '\\';
      if (src[si + 1] != '\0') dst[di++] = src[++si];
      else dst[di++] = '\\';
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

/* 同じ日付の日付付きログの連番の上限 (<path>.YYYYMMDD.1 .. .9999) */
#define LOG_TS_MAX_SEQ 9999

typedef struct {
    const char *base;  /* ログファイルのベース名 */
    size_t base_len;
    uint64_t *keys;    /* 日付 * 10000 + 連番 */
    size_t count, cap;
} ts_log_scan_t;

/* "<base>.YYYYMMDD" と "<base>.YYYYMMDD.N" (N は 1..9999) だけを数える。それ以外は消さない */
static void ts_log_scan_cb(const char *name, void *ud) {
    ts_log_scan_t *s = ud;
    if (strncmp(name, s->base, s->base_len) != 0 || name[s->base_len] != '.') return;
    const char *p = name + s->base_len + 1;
    uint64_t date = 0, seq = 0;
    for (int i = 0; i < 8; i++, p++) {
        if (!isdigit((unsigned char)*p)) return;
        date = date * 10 + (uint64_t)(*p - '0');
    }
    if (*p == '.') {
        p++;
        if (*p == '0') return; /* 作るのは先頭が 0 でない連番だけ */
        int n = 0;
        for (; isdigit((unsigned char)*p) && n < 5; p++, n++) seq = seq * 10 + (uint64_t)(*p - '0');
        if (n == 0 || n > 4 || seq == 0) return;
    }
    if (*p != '\0') return;
    if (s->count == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 32;
        uint64_t *nk = realloc(s->keys, ncap * sizeof(*nk));
        if (!nk) return;
        s->keys = nk;
        s->cap = ncap;
    }
    s->keys[s->count++] = date * 10000 + seq;
}

static int ts_key_desc(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x < y) - (x > y);
}

/* D-21: suffix timestamp と versions <n> を併用したときは、日付付きのファイルを新しい順に n 個だけ残す
 * (BIND lib/isc/log.c の roll_timestamp() / remove_old_tsversions() と同じ。versions を省略した
 * ときは削除しない)。ロガースレッドだけが呼ぶ (クエリ処理のホットパスではない)。 */
static void prune_timestamped_logs(const char *file_path, int versions) {
    const char *slash = strrchr(file_path, '/');
    ts_log_scan_t s = { .base = slash ? slash + 1 : file_path };
    s.base_len = strlen(s.base);
    if (list_dir_via_dir_cache(file_path, ts_log_scan_cb, &s) != 0) {
        syslog(LOG_ERR, "[Logging] Cannot list the directory of '%s' to remove old log files: %m", file_path);
        free(s.keys);
        return;
    }
    if (s.count > (size_t)versions) {
        qsort(s.keys, s.count, sizeof(*s.keys), ts_key_desc);
        for (size_t i = (size_t)versions; i < s.count; i++) {
            char old_name[600];
            unsigned date = (unsigned)(s.keys[i] / 10000), seq = (unsigned)(s.keys[i] % 10000);
            int r = seq ? snprintf(old_name, sizeof(old_name), "%s.%08u.%u", file_path, date, seq)
                        : snprintf(old_name, sizeof(old_name), "%s.%08u", file_path, date);
            if (r > 0 && r < (int)sizeof(old_name) && unlink_via_dir_cache(old_name) != 0 && errno != ENOENT)
                syslog(LOG_ERR, "[Logging] Failed to remove old log file '%s': %m", old_name);
        }
    }
    free(s.keys);
}

/* BIND ISC_LOG_ROLLNEVER with a size (lib/isc/log.c isc_log_open(), isc_log_doit() FILE_MAXREACHED): a file with `size` but no `versions`
 * (and the default increment suffix) is never rolled.  When the next line does not fit, nothing more is written until the file is removed
 * or shorter than the limit -- BIND looks at every message, this looks about once a second.  Returns whether the line may be written.
 * ch->lock is held. */
static bool log_size_gate(log_channel_t *ch, int len) {
    if (ch->size_reached) {
        time_t now = time(NULL);
        if (now == ch->size_recheck) return false;
        ch->size_recheck = now;
        struct stat st;
        if (stat_via_dir_cache(ch->file_path, &st) == 0 && (uint64_t)st.st_size >= ch->size_limit) return false;
        if (ch->fd >= 0) close(ch->fd);
        ch->fd = open_via_dir_cache(ch->file_path, O_WRONLY | O_CREAT | O_APPEND, 0644, true);
        off_t size = ch->fd >= 0 ? log_file_accept(ch->fd, ch->file_path, (uid_t)-1) : -1;   /* P3 */
        if (ch->fd >= 0 && size < 0) {
            close(ch->fd);
            ch->fd = -1;
        }
        if (ch->fd < 0) return false;
        ch->current_size = size;
        ch->size_reached = false;
    }
    if (ch->current_size + (size_t)len <= ch->size_limit) return true;
    ch->size_reached = true;
    ch->size_recheck = time(NULL);
    syslog(LOG_WARNING, "[Logging] Log file '%s' reached its size limit of %zu bytes and has no 'versions': no more lines are written to it "
                        "until it is removed or shorter (add 'versions <n>' to keep old files)", ch->file_path, ch->size_limit);
    return false;
}

void log_write_rotated(log_channel_t *ch, const char *log_buf, int len, struct tm *tm_info) {
    int today = (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 + tm_info->tm_mday;
    bool guard = klog_guard_enter();   /* what is logged below must not come back to this channel (its lock is held) */
    pthread_mutex_lock(&ch->lock);
    bool rotate = false;
    if (ch->size_limit > 0 && ch->versions == LOG_VERSIONS_UNSET && !ch->suffix_timestamp) {
        if (!log_size_gate(ch, len)) {
            pthread_mutex_unlock(&ch->lock);
            klog_guard_leave(guard);
            return;
        }
    } else if (ch->size_limit > 0 && ch->current_size + len > ch->size_limit)
        rotate = true;
    else if (ch->suffix_timestamp && ch->current_date != today)
        rotate = true;

    if (rotate) {
        int old_fd = ch->fd;
        int reopen_flags = O_WRONLY | O_CREAT | O_APPEND;
        bool rotate_rename_failed = false;

        if (ch->suffix_timestamp) {
            /* D-21: 同じ日に2回目以降のローテーションでは <path>.YYYYMMDD.N にして上書きしない */
            char new_name[600];
            struct stat ex;
            int r = snprintf(new_name, sizeof(new_name), "%s.%08d", ch->file_path, ch->current_date);
            for (int seq = 1; r > 0 && r < (int)sizeof(new_name) && seq <= LOG_TS_MAX_SEQ &&
                              stat_via_dir_cache(new_name, &ex) == 0; seq++)
                r = snprintf(new_name, sizeof(new_name), "%s.%08d.%d", ch->file_path, ch->current_date, seq);
            if (r <= 0 || r >= (int)sizeof(new_name) || stat_via_dir_cache(new_name, &ex) == 0) {
                rotate_rename_failed = true;
                syslog(LOG_ERR, "[Logging] Cannot rotate log file '%s': no free name for date %08d", ch->file_path,
                       ch->current_date);
            } else if (renameat_via_dir_cache(ch->file_path, new_name) != 0) {
                rotate_rename_failed = true;
                syslog(LOG_ERR, "[Logging] Failed to rotate log file '%s' to '%s': %m", ch->file_path, new_name);
            } else if (ch->versions > 0) {
                prune_timestamped_logs(ch->file_path, ch->versions);
            }
        } else if (ch->versions > 0 || ch->versions == LOG_VERSIONS_UNLIMITED) {
            /* .0 .. .(top-1) are kept (`versions <n>`: top = n - 1; unlimited: as many as exist) and shifted up by one; the files above the
             * first one that is missing do not move (BIND greatest_version() looks for the largest one instead) */
            int top = ch->versions > 0 ? ch->versions - 1 : INT_MAX;
            int m = 0;
            for (; m < top; m++) {
                char probe[600];
                struct stat ex;
                if (snprintf(probe, sizeof(probe), "%s.%d", ch->file_path, m) >= (int)sizeof(probe) ||
                    stat_via_dir_cache(probe, &ex) != 0)
                    break;
            }
            for (int i = m; i >= 0; i--) {
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
            off_t size = ch->fd >= 0 ? log_file_accept(ch->fd, ch->file_path, (uid_t)-1) : -1;   /* P3 */
            if (ch->fd >= 0 && size < 0) {
                close(ch->fd);
                ch->fd = -1;
            }
            if (ch->fd >= 0) {
                ch->current_size = size;
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
                    off_t size = log_file_accept(ch->fd, ch->file_path, (uid_t)-1);   /* P3 */
                    if (size < 0) {
                        close(ch->fd);
                        ch->fd = -1;
                    } else {
                        ch->current_size = size;
                    }
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
    klog_guard_leave(guard);
}

/* class and type of a logged query in the text BIND prints: IN / CH / ANY / CLASSn, and the type mnemonic */
static void query_log_class_type(uint16_t qclass, uint16_t qtype, char *class_str, size_t class_sz, char *type_buf, size_t type_sz,
                                 const char **type_str) {
    if (qclass == 1) snprintf(class_str, class_sz, "IN");
    else if (qclass == 255) snprintf(class_str, class_sz, "ANY");
    else if (qclass == 3) snprintf(class_str, class_sz, "CH");
    else snprintf(class_str, class_sz, "CLASS%d", qclass);
    *type_str = format_type_name(qtype, type_buf, type_sz);
}

void *response_logger_thread_func(void *arg) {
    (void)arg;
    while (1) {
        uint64_t h = atomic_load_explicit(&g_resp_log_head, memory_order_relaxed);
        uint32_t idx = h & (RESP_LOG_RING_SIZE - 1);

        if (atomic_load_explicit(&g_resp_log_ring[idx].ready, memory_order_acquire)) {
            resp_log_entry_t *entry = &g_resp_log_ring[idx];
            rcu_slot_reader_enter(&g_resp_logger_rcu_ctx);
            server_config_t *cfg = acquire_config_snapshot();
            bool enabled = cfg && cfg->logging.responses_enabled;
            release_config_snapshot(cfg);
            rcu_slot_reader_exit(&g_resp_logger_rcu_ctx);
            /* the unit tests stop this thread with pthread_cancel(): not while it holds the runtime (it would never be put back) */
            int cancel_state;
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
            log_runtime_t *rt = enabled ? log_runtime_acquire() : NULL;

            if (rt) {
                char class_str[16];
                char type_str[32];
                const char *type_str_tmp;
                query_log_class_type(entry->qclass, entry->qtype, class_str, sizeof(class_str), type_str, sizeof(type_str), &type_str_tmp);

                // EDNSとRCODEの文字列化
                char edns_str[16] = "";
                if (entry->has_edns) snprintf(edns_str, sizeof(edns_str), "+E(0)%s", entry->dnssec_ok ? "D" : "K");

                const char *rcode_strs[] = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"};
                const char *rcode_str = (entry->rcode <= 10) ? rcode_strs[entry->rcode] : "UNKNOWN";

                const char *action_str = "";
                if (entry->action == LOG_ACT_DROP_RRL) action_str = " [DROP:RRL]";
                else if (entry->action == LOG_ACT_DROP_MALFORMED) action_str = " [DROP:MALFORMED]";

                char safe_qname[512];
                escape_qname_for_log(entry->qname, safe_qname, sizeof(safe_qname));

                /* the text after "<time> responses: info: "; the channels add their own prefix (klog_record()) */
                char msg[1024];
                snprintf(msg, sizeof(msg), "client %s#%d (%s): response: %s %s %s %s -> %s%s",
                         entry->client_ip, entry->client_port,
                         safe_qname, safe_qname, class_str, type_str_tmp, edns_str, rcode_str, action_str);
                klog_record(rt, LOGC_RESPONSES, LOG_LVL_INFO, &entry->ts, msg);
            }
            log_runtime_release(rt);
            pthread_setcancelstate(cancel_state, NULL);

            // Consumerのポインタを進める
            atomic_store_explicit(&entry->ready, false, memory_order_release);
            atomic_fetch_add_explicit(&g_resp_log_head, 1, memory_order_release);
        } else {
            usleep(1000); // データ未着時は1msスリープしてCPU負荷を下げる
        }
    }
    return NULL;
}

void write_query_log(worker_ctx_t *ctx,
                                   const void *client_addr,
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
    int nw = atomic_load_explicit(&g_worker_count, memory_order_relaxed);
    uint32_t quota = (nw > 0 && limit >= (uint32_t)nw)
                     ? (limit / (uint32_t)nw) : 1;
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

    if (client_addr && addr_len > 0) {
        size_t copy_len = addr_len < sizeof(ev->client_addr) ? addr_len : sizeof(ev->client_addr);
        memcpy(&ev->client_addr, client_addr, copy_len);
        if (copy_len < sizeof(ev->client_addr)) {
            memset((uint8_t *)&ev->client_addr + copy_len, 0, sizeof(ev->client_addr) - copy_len);
        }
    } else {
        memset(&ev->client_addr, 0, sizeof(ev->client_addr));
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
    static klog_batch_t batches[LOG_ROUTE_MAX];   /* one per channel of the category: the lines of a drain of the rings, written at once */
    time_t last_drop_report_time = time(NULL);
    uint64_t last_reported_dropped = 0;

    while (1) {
        rcu_slot_reader_enter(&g_query_logger_rcu_ctx);
        server_config_t *cfg = acquire_config_snapshot();
        bool enabled = cfg && cfg->logging.queries_enabled;
        release_config_snapshot(cfg);
        rcu_slot_reader_exit(&g_query_logger_rcu_ctx);

        int cancel_state;   /* as in the response logger: no cancellation while the runtime is held */
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
        log_runtime_t *rt = enabled ? log_runtime_acquire() : NULL;
        int nch = 0;
        log_channel_t *const *route = rt ? log_runtime_route(rt, LOGC_QUERIES, &nch) : NULL;

        int num_workers = atomic_load_explicit(&g_worker_count, memory_order_acquire);
        worker_ctx_t *workers = atomic_load_explicit(&g_worker_ctxs, memory_order_acquire);
        bool any_work = false;

        if (rt && num_workers > 0 && workers) {
            for (int w = 0; w < num_workers; w++) {
                qlog_ring_t *ring = &workers[w].qlog_ring;
                if (!ring->events) continue;

                uint32_t t = atomic_load_explicit(&ring->tail, memory_order_relaxed);
                uint32_t h = atomic_load_explicit(&ring->head, memory_order_acquire);

                while (t != h) {
                    qlog_event_t *ev = &ring->events[t & ring->mask];
                    any_work = true;

                    char class_str[16];
                    char type_buf[32];
                    const char *type_str;
                    query_log_class_type(ev->qclass, ev->qtype, class_str, sizeof(class_str), type_buf, sizeof(type_buf), &type_str);

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

                    /* the text after "<time> queries: info: "; each channel adds its own prefix (klog_build_line()) */
                    char msg[1024];
                    snprintf(msg, sizeof(msg), "client %s#%d (%s): query: %s %s %s %s", client_ip, client_port,
                             safe_qname, safe_qname, class_str, type_str, edns_str);
                    for (int i = 0; i < nch; i++)
                        if (klog_level_passes(route[i]->level, LOG_LVL_INFO))
                            klog_batch_add(&batches[i], route[i], LOGC_QUERIES, LOG_LVL_INFO, &ev->ts, msg);

                    t++;
                }

                atomic_store_explicit(&ring->tail, t, memory_order_release);
            }

            for (int i = 0; i < nch; i++)
                klog_batch_flush(&batches[i], route[i]);

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

        log_runtime_release(rt);
        pthread_setcancelstate(cancel_state, NULL);

        // 常に数ミリ秒休止してワーカースレッドにCPUを完全に明け渡す
        usleep(any_work ? 1000 : 10000);
    }
    return NULL;
}

void fill_observatory_snapshot(const zone_db_entry_t *e, server_config_t *cfg, zone_observatory_snapshot_t *out) {
    if (!e || !out) return;
    strlcpy(out->domain, e->domain, sizeof(out->domain));
    strlcpy(out->view_name, e->view_name, sizeof(out->view_name));
    out->is_secondary = e->is_secondary;
    out->soa_serial = (uint32_t)atomic_load_explicit(&e->serial, memory_order_relaxed);

    const zone_config_t *zc = zone_entry_config(cfg, e);
    const notify_target_t *an = NULL;
    out->slaves_configured = also_notify_effective(cfg, zc, e->view_name, &an); /* the zone's, the view's or options' list */

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

    out->wirecache_hits = atomic_load_explicit(&e->observatory.wirecache_hits, memory_order_relaxed);
    out->wirecache_misses = atomic_load_explicit(&e->observatory.wirecache_misses, memory_order_relaxed);

    /* 応答キャッシュは全ゾーン共有 (response_cache_init) なので、ゾーンごとの件数は持たない */
    zone_version_t *active_arena = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
    out->wirecache_enabled = active_arena && active_arena->rcache_ok;
    out->wirecache_entries = 0;
    out->wirecache_bytes = 0;
    out->shared_views[0] = '\0';
    if (cfg && cfg->any_in_view) (void)config_in_view_sharers(cfg, e->view_name, e->domain, out->shared_views, sizeof(out->shared_views));
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

ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len) {
  if (len > 65535)
    return -1;
  uint8_t prefix[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
  struct iovec iov[2] = {{.iov_base = prefix, .iov_len = 2},
                         {.iov_base = (void *)(uintptr_t)msg, .iov_len = len}};
  struct iovec *cur = iov;
  int cnt = 2;
  /* sendmsg(): クライアント fd の権限は CAP_SEND で、writev() の CAP_WRITE は無い */
  /* max-transfer-time-out / max-transfer-idle-out (an outbound AXFR/IXFR thread sets them): the transfer is given up after the deadline, or when the
   * client takes nothing for the idle time (the socket is blocking with SO_SNDTIMEO = idle, so EAGAIN here is the timeout) */
  if (g_tcp_send_deadline_secs && time(NULL) > g_tcp_send_deadline_secs)
    return -1;
  while (cnt > 0) {
    struct msghdr mh = {.msg_iov = cur, .msg_iovlen = cnt};
    ssize_t n = sendmsg(fd, &mh, 0);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (g_tcp_send_idle_secs)
          return -1;
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        if (poll(&pfd, 1, 30000) <= 0)
          return -1;
        continue;
      }
      return -1;
    }
    if (n == 0)
      return -1;
    while (cnt > 0 && (size_t)n >= cur->iov_len) {
      n -= (ssize_t)cur->iov_len;
      cur++;
      cnt--;
    }
    if (cnt > 0) {
      cur->iov_base = (uint8_t *)cur->iov_base + n;
      cur->iov_len -= (size_t)n;
    }
  }
  return (ssize_t)len;
}

// D-04: 平文 TCP の接続コンテキストのプール。フリーリストの先頭は (世代 << 32) | (添字 + 1)
// で、世代を CAS のたびに進めて ABA を防ぐ。払い出しと返却はどのワーカーからでもよい。
static tcp_stream_ctx_t *g_tcp_pool;
static _Atomic uint32_t *g_tcp_pool_next; /* 次の空きの 添字 + 1 (0 = 終端) */
static _Atomic uint64_t g_tcp_pool_head;

bool tcp_pool_init(void) {
  if (g_tcp_pool)
    return true;
  /* 約 66 KB × MAX_TCP_CLIENTS。ページは実際に使われるまで割り当てられない */
  g_tcp_pool = calloc(MAX_TCP_CLIENTS, sizeof(tcp_stream_ctx_t));
  g_tcp_pool_next = calloc(MAX_TCP_CLIENTS, sizeof(*g_tcp_pool_next));
  if (!g_tcp_pool || !g_tcp_pool_next) {
    free(g_tcp_pool);
    free(g_tcp_pool_next);
    g_tcp_pool = NULL;
    g_tcp_pool_next = NULL;
    return false;
  }
  for (uint32_t i = 0; i < MAX_TCP_CLIENTS; i++)
    atomic_init(&g_tcp_pool_next[i], i + 1 < MAX_TCP_CLIENTS ? i + 2 : 0);
  atomic_store_explicit(&g_tcp_pool_head, 1, memory_order_release);
  return true;
}

tcp_stream_ctx_t *tcp_ctx_alloc(void) {
  if (!g_tcp_pool)
    return NULL;
  uint64_t old = atomic_load_explicit(&g_tcp_pool_head, memory_order_acquire);
  for (;;) {
    uint32_t top = (uint32_t)old;
    if (top == 0)
      return NULL; /* MAX_TCP_CLIENTS 本すべて使用中 */
    uint32_t next = atomic_load_explicit(&g_tcp_pool_next[top - 1], memory_order_relaxed);
    uint64_t nw = (((old >> 32) + 1) << 32) | next;
    if (atomic_compare_exchange_weak_explicit(&g_tcp_pool_head, &old, nw, memory_order_acq_rel,
                                              memory_order_acquire)) {
      tcp_stream_ctx_t *c = &g_tcp_pool[top - 1];
      memset(c, 0, offsetof(tcp_stream_ctx_t, buf));
      return c;
    }
  }
}

void tcp_ctx_free(tcp_stream_ctx_t *c) {
  if (!c || !g_tcp_pool)
    return;
  uint32_t idx = (uint32_t)(c - g_tcp_pool);
  uint64_t old = atomic_load_explicit(&g_tcp_pool_head, memory_order_relaxed);
  for (;;) {
    atomic_store_explicit(&g_tcp_pool_next[idx], (uint32_t)old, memory_order_relaxed);
    uint64_t nw = (((old >> 32) + 1) << 32) | (idx + 1);
    if (atomic_compare_exchange_weak_explicit(&g_tcp_pool_head, &old, nw, memory_order_release,
                                              memory_order_relaxed))
      return;
  }
}

/* TCP クライアントのコンテキストをプールへ返す。同じ kevent() で受け取った後続のイベントの
 * うち、この接続のもの (ident と udata が一致) は無効にする (返したコンテキストを見ないように)。
 * kevent の登録は呼び出し側が先に外しておくこと。 */
static void tcp_client_forget(int client_fd, tcp_stream_ctx_t *ctx_tcp,
                              struct kevent *ev_list, int from, int n_events) {
  for (int j = from + 1; j < n_events; j++) {
    if (ev_list[j].ident == (uintptr_t)client_fd && ev_list[j].udata == ctx_tcp &&
        (ev_list[j].filter == EVFILT_READ || ev_list[j].filter == EVFILT_TIMER)) {
      ev_list[j].udata = NULL;
      ev_list[j].filter = 0;
    }
  }
  tcp_ctx_free(ctx_tcp);
}

/* TCP クライアントの接続を閉じる共通処理 (D-04: 以前は約10か所に複製され、後続イベントを
 * 無効にしない箇所があった)。 */
static void tcp_client_close(int kq, int client_fd, tcp_stream_ctx_t *ctx_tcp,
                             struct kevent *ev_list, int from, int n_events) {
  struct kevent ev_del[2];
  /* READ を先に: 期限切れで消えた ONESHOT タイマーの削除が失敗しても READ は外れる */
  EV_SET(&ev_del[0], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  EV_SET(&ev_del[1], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
  kevent(kq, ev_del, 2, NULL, 0, NULL);
  close(client_fd);
  dec_tcp_clients();
  tcp_client_forget(client_fd, ctx_tcp, ev_list, from, n_events);
}

/* 次のメッセージの期限までの時間 (ms、最小 1)。RFC 7766 §6.2.3 */
static uint32_t tcp_ms_until(int64_t deadline_ms, int64_t now_ms) {
  return deadline_ms > now_ms ? (uint32_t)(deadline_ms - now_ms) : 1;
}

// UDP / IPC 送信失敗のログ。ホットパスで syslog が溢れないよう、スレッドごとに
// 1 秒 1 回へ間引き、間引いた件数を次のログにまとめて出す。
// is_ipc: Frontend/Backend 間の AF_UNIX SOCK_DGRAM (EMSGSIZE は net.local.dgram.maxdgram 超過)
static void log_udp_send_drop(const char *path, bool is_ipc, int err, int dropped) {
  static _Thread_local time_t last_log;
  static _Thread_local unsigned long suppressed;
  time_t now = time(NULL);
  if (now == last_log) {
    suppressed += (unsigned long)dropped;
    return;
  }
  last_log = now;
  syslog(LOG_WARNING, "[%s] dropped %d UDP message(s): %s%s (+%lu suppressed in the last second)",
         path, dropped, strerror(err),
         (is_ipc && err == EMSGSIZE) ? "; reply exceeds net.local.dgram.maxdgram - IPC header" : "",
         suppressed);
  suppressed = 0;
}

// sendmmsg() は途中の 1 通が失敗するとそこで止まり、送れた件数だけを返す
// (失敗した 1 通以降は送られない)。戻り値を無視すると、過大な応答 (EMSGSIZE) や
// 到達不能な宛先 (EHOSTUNREACH 等) 1 通のために同じバッチの他クライアント宛て応答まで
// 捨ててしまうため、失敗した 1 通だけを飛ばして残りを送り直す。
// EAGAIN / ENOBUFS (非ブロッキングで送信バッファ満杯) は送り直しても失敗するので
// 従来どおり残りを破棄する。戻り値: 破棄した件数。
STATIC_TEST int sendmmsg_skip_failed(int fd, struct mmsghdr *msgs, int n, const char *path, bool is_ipc) {
  int off = 0;
  int dropped = 0;
  int last_err = 0;
  while (off < n) {
    int r = sendmmsg(fd, msgs + off, (unsigned int)(n - off), MSG_DONTWAIT);
    if (r > 0) {
      off += r;
      continue;
    }
    if (r < 0 && errno == EINTR)
      continue;
    last_err = (r < 0) ? errno : EIO;
    if (last_err == EAGAIN || last_err == EWOULDBLOCK || last_err == ENOBUFS) {
      dropped += n - off;
      break;
    }
    dropped++;  // msgs[off] だけを破棄して続行
    off++;
  }
  if (dropped > 0)
    log_udp_send_drop(path, is_ipc, last_err, dropped);
  return dropped;
}

async_io_pool_t g_async_io_pool;

STATIC_TEST bool enqueue_async_io_task(const async_io_task_t *task) {
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

STATIC_TEST void *async_io_worker_func(void *arg) {
  int thread_idx = (int)(uintptr_t)arg;
  if (thread_idx < 0 || thread_idx >= MAX_ASYNC_IO_RCU_WORKERS) {
    thread_idx = 0;
  }
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

    rcu_slot_reader_enter(&g_async_io_rcu_ctxs[thread_idx]);
    if (!task.is_tcp) {
      // UDP async resolution
      alignas(udp_ipc_t) uint8_t res_buf_full[UDP_IPC_BUFFER_SIZE];
      uint8_t *res_buf = res_buf_full + sizeof(udp_ipc_t);
      const rate_limit_config_t *rrl_cfg = NULL;
      size_t max_res = task.has_edns ? BUFFER_SIZE : UDP_DEFAULT_MAX_RES_LEN;
      query_set_client_addr(&task.client_addr);
      query_set_local_addr(task.has_server_addr ? &task.server_addr : NULL);   /* allow-query-on */
      int res_len = process_dns_query_cap(task.req_buf, task.req_len, res_buf, max_res,
                                          UDP_IPC_BUFFER_SIZE - sizeof(udp_ipc_t),
                                          task.qname, task.qtype, task.client_ip,
                                      &thread_compress_ctx, false, &rrl_cfg, task.snap);
      free(task.req_buf);

      // rrl_cfg は設定の中を指し、submit_response_log() も設定を読むので、
      // 応答の送出まで読み取り区間を保つ (IPC への send は非ブロッキング)。
      if (res_len > 0) {
        bool slip_triggered = false;
        /* D-05: ワーカーの UDP 経路と同じキー */
        rrl_key_t rrl_key;
        char rrl_name[DNS_NAME_TEXT_SIZE];
        rrl_make_key(&rrl_key, res_buf, (size_t)res_len, task.qname, task.qtype, task.qclass,
                     t_query_rrl_info.zone, t_query_rrl_info.wildcard, rrl_name, sizeof(rrl_name));
        if (rrl_check_key(&task.ipc_hdr.client_addr, &rrl_key, rrl_cfg, &slip_triggered)) {
          submit_response_log(LOG_ACT_SENT, task.client_ip, task.client_port, task.qname, task.qclass, task.qtype,
                              res_buf[3] & 0x0F, task.has_edns, task.dnssec_ok);
          write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res_buf, res_len,
                             &task.client_addr, task.client_len,
                             task.has_server_addr ? &task.server_addr : NULL, task.has_server_addr, IPPROTO_UDP);
          udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
          *res_msg = task.ipc_hdr;
          res_msg->payload_len = res_len;
          if (send(task.active_fd, res_buf_full, sizeof(udp_ipc_t) + res_len, 0) < 0)
            log_udp_send_drop("Backend->Frontend IPC", true, errno, 1);
        } else if (slip_triggered) {
          submit_response_log(LOG_ACT_SENT, task.client_ip, task.client_port, task.qname, task.qclass, task.qtype,
                              res_buf[3] & 0x0F, task.has_edns, task.dnssec_ok);
          /* TC=1、質問と OPT だけ。署名付きの要求なら署名し直す (X-20) */
          int qlen = (int)dns_rrl_slip_response(res_buf, (size_t)res_len, UDP_IPC_BUFFER_SIZE - sizeof(udp_ipc_t));
          write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, res_buf, qlen,
                             &task.client_addr, task.client_len,
                             task.has_server_addr ? &task.server_addr : NULL, task.has_server_addr, IPPROTO_UDP);
          udp_ipc_t *res_msg = (udp_ipc_t *)res_buf_full;
          *res_msg = task.ipc_hdr;
          res_msg->payload_len = qlen;
          if (send(task.active_fd, res_buf_full, sizeof(udp_ipc_t) + qlen, 0) < 0)
            log_udp_send_drop("Backend->Frontend IPC", true, errno, 1);
        } else {
          submit_response_log(LOG_ACT_DROP_RRL, task.client_ip, task.client_port, task.qname,
                              task.qclass, task.qtype, res_buf[3] & 0x0F, task.has_edns, task.dnssec_ok);
        }
      } else {
        submit_response_log(LOG_ACT_DROP_MALFORMED, task.client_ip, task.client_port, "<malformed>",
                            0, 0, 0, false, false);
      }
      rcu_slot_reader_exit(&g_async_io_rcu_ctxs[thread_idx]);
      release_zone_snapshot(task.snap);
    } else {
      // TCP async resolution
      uint8_t *tcp_res = malloc(65535);
      if (tcp_res) {
        query_set_client_addr(&task.client_addr);
        query_set_local_addr(task.has_server_addr ? &task.server_addr : NULL);   /* allow-query-on */
        int res_len = process_dns_query(task.req_buf, task.req_len, tcp_res, 65535,
                                        task.qname, task.qtype, task.client_ip,
                                        &thread_compress_ctx, true, NULL, task.snap);
        free(task.req_buf);
        // submit_response_log() は設定を読むので読み取り区間の中で呼ぶ。
        // send_tcp_robust() はブロックしうるので区間の外で行う。
        if (res_len > 0) {
          submit_response_log(LOG_ACT_SENT, task.client_ip, task.client_port, task.qname, task.qclass, task.qtype,
                              tcp_res[3] & 0x0F, task.has_edns, task.dnssec_ok);
        } else {
          submit_response_log(LOG_ACT_DROP_MALFORMED, task.client_ip, task.client_port, "<malformed>",
                              0, 0, 0, false, false);
        }
        rcu_slot_reader_exit(&g_async_io_rcu_ctxs[thread_idx]);
        release_zone_snapshot(task.snap);
        if (res_len > 0) {
          write_dnstap_event(NULL, 2 /*AUTH_RESPONSE*/, tcp_res, res_len,
                             &task.client_addr, task.client_len,
                             task.has_server_addr ? &task.server_addr : NULL, task.has_server_addr, IPPROTO_TCP);
          (void)send_tcp_dns_message(task.client_fd, tcp_res, (size_t)res_len); /* RFC 7766 §8 */
        }
        free(tcp_res);
      } else {
        rcu_slot_reader_exit(&g_async_io_rcu_ctxs[thread_idx]);
        release_zone_snapshot(task.snap);
        free(task.req_buf);
      }
      close(task.client_fd);
      dec_tcp_clients();
    }
  }
  return NULL;
}

/* 1本でも起動できなければ false (起動中止。O-15: 呼び出し側は backend_exit() で終わる) */
bool init_async_io_pool(void) {
  memset(&g_async_io_pool, 0, sizeof(g_async_io_pool));
  pthread_mutex_init(&g_async_io_pool.lock, NULL);
  pthread_cond_init(&g_async_io_pool.cond_not_empty, NULL);
  g_async_io_pool.running = true;
  for (int i = 0; i < ASYNC_IO_POOL_SIZE; i++) {
    if (pthread_create(&g_async_io_pool.threads[i], NULL, async_io_worker_func, (void *)(uintptr_t)i) != 0) {
      syslog(LOG_ERR, "[Backend] Failed to start async I/O thread %d: %m", i);
      return false;
    }
  }
  return true;
}

void fast_ipv4_to_str(uint32_t ip_be, char *dst) {
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

/* セカンダリゾーンがマスターから転送を受ける TCP 接続の値。ゾーン指定
 * (zone-tcp-mss / zone-tcp-window / zone-tcp-sndbuf) があればそれを、なければ
 * グローバルの tcp-mss / tcp-window を使う。受信側なので rcvbuf が主に効く。 */
STATIC_TEST tcp_sockopts_t xfr_tcp_sockopts(const server_config_t *cfg, const zone_config_t *zcfg) {
  tcp_sockopts_t o = {0};
  if (cfg) {
    o.mss = cfg->tcp_mss;
    o.rcvbuf = cfg_tcp_rcvbuf(cfg);
    o.sndbuf = cfg_tcp_sndbuf(cfg);
  }
  if (zcfg) {
    if (zext(zcfg)->zone_tcp_mss > 0) o.mss = zext(zcfg)->zone_tcp_mss;
    if (zext(zcfg)->zone_tcp_window > 0) o.rcvbuf = zext(zcfg)->zone_tcp_window;
    if (zext(zcfg)->zone_tcp_sndbuf > 0) o.sndbuf = zext(zcfg)->zone_tcp_sndbuf;
  }
  return o;
}

/* serial-query-rate: the budget of refresh checks a second (the control thread only) */
static xfr_rl_t g_serial_query_rl;
/* where the walk of the secondaries starts in this tick (the control thread only); see the loop */
static size_t g_tick_rotor;

/* Copies the TSIG key `name` as the view sees it (the view's own keys, then the global ones) into p by value ([H-4]: the thread must not
 * point into the configuration) */
static void xfr_primary_copy_key(const server_config_t *active, const char *view_name, const char *name, xfr_primary_t *p) {
  if (!name || !name[0] || !active) return;
  const tsig_key_t *k = find_tsig_key_in_view(active, view_name, name);
  if (!k) return;
  p->has_tsig = true;
  strlcpy(p->tsig_name, k->name, sizeof(p->tsig_name));
  strlcpy(p->tsig_algorithm, k->algorithm ? k->algorithm : "hmac-sha256", sizeof(p->tsig_algorithm));
  size_t copy_len = k->secret_decoded_len;
  if (copy_len > sizeof(p->tsig_secret_decoded)) copy_len = sizeof(p->tsig_secret_decoded);
  memcpy(p->tsig_secret_decoded, k->secret_decoded, copy_len);
  p->tsig_secret_decoded_len = copy_len;
}

/* What the `server` statement that covers primary p (NULL: none) says about the requests to it (batch 5): its request-ixfr, request-expire,
 * transfers, edns, edns-udp-size, edns-version and request-nsid (BIND lib/dns/zone.c soa_query(), xfrin.c, zmgr_start_xfrin_ifquota()). */
static void xfr_primary_apply_server(const server_stmt_t *srv, xfr_primary_t *p) {
  if (!srv) return;
  if (srv->xo.set & XO_B_REQUEST_IXFR) p->srv_request_ixfr = (srv->xo.bools & XO_B_REQUEST_IXFR) ? 1 : 2;
  if (srv->xo.set & XO_B_REQUEST_EXPIRE) p->srv_request_expire = (srv->xo.bools & XO_B_REQUEST_EXPIRE) ? 1 : 2;
  if (srv->set & SV_TRANSFERS) {
    p->per_ns_set = true;
    p->per_ns = srv->transfers;
  }
  if ((srv->set & SV_B_EDNS) && !(srv->bools & SV_B_EDNS)) p->no_edns = true;
  if ((srv->set & SV_B_REQUEST_NSID) && (srv->bools & SV_B_REQUEST_NSID)) p->request_nsid = true;
  if (srv->set & SV_EDNS_VERSION) p->edns_version = (uint8_t)srv->edns_version;
  if (srv->set & SV_EDNS_UDP_SIZE) p->edns_udp_size = (uint16_t)srv->edns_udp_size;
}

/* The local address of the connection to p: the `source` of the primaries list it is written in, else transfer-source(-v6) (BIND zone.c
 * soa_query(): the list's source unless it is `*`, then the zone's xfrsource).  Only an address the server had at start-up can be bound (the
 * connect broker was told then); another one is ignored with a warning, once per address, until a restart. */
static void xfr_primary_set_source(const xfr_eff_t *eff, const notify_target_t *t, xfr_primary_t *p, const char *domain) {
  struct in_addr a4;
  int fam = inet_pton(AF_INET, p->ip, &a4) == 1 ? AF_INET : AF_INET6;
  uint8_t src[16];
  if (!xfr_source_for(eff, t, fam, true, src)) return;
  if (config_xfr_source_allowed(fam, src, true)) {
    p->has_src = true;
    memcpy(p->src, src, sizeof(p->src));
    return;
  }
  static _Atomic uint32_t warned;
  if (atomic_fetch_add_explicit(&warned, 1, memory_order_relaxed) < 16) {
    char txt[INET6_ADDRSTRLEN];
    inet_ntop(fam, src, txt, sizeof(txt));
    syslog(LOG_WARNING, "[AXFR] zone %s: the transfer source address %s was not in the configuration at start-up; it is used after a restart "
                        "(until then the system chooses the source address)", domain, txt);
  }
}

/* Everything that depends on who the primary is (batch 5): the `server` statement that covers its address (the view's, else the top-level ones)
 * gives the TSIG key unless the primaries element has one of its own (BIND soa_query(): the element's key, then dns_view_getpeertsig(); the
 * zone's tsig-key after both, KariDNS), the source address (above the list's `source`), request-ixfr / request-expire, transfers and the
 * EDNS options of the requests.  element_key is the key written on the primaries element, zone_key the zone's tsig-key. */
static void xfr_primary_setup(const server_config_t *active, const zone_config_t *zone, const char *view_name, const char *element_key,
                              const char *zone_key, const notify_target_t *t, xfr_primary_t *p, axfr_bg_ctx_t *ctx) {
  const server_stmt_t *srv = config_server_find_ip(active, view_name, p->ip);
  xfr_primary_copy_key(active, view_name, peer_key_name(element_key, srv, zone_key), p);
  xfr_primary_apply_server(srv, p);
  xfr_eff_t peff;
  xfr_opts_effective_peer(active, zone, view_name, srv, &peff);
  xfr_primary_set_source(&peff, t, p, ctx->domain);
}

/* The primaries a secondary zone is refreshed from, in order, and the options that govern the refresh (batch 4).  A configured secondary
 * and a database secondary list them in their zone settings; a catalog member takes the primaries of its catalog zone (all of them; the
 * single copy kept in the entry when the member was created is the fallback).  The options (timers, multi-master, request-ixfr, sources)
 * are those of the zone, else of the catalog zone for a member, then the view's and options'. */
STATIC_TEST void xfr_build_primaries(server_config_t *active, zone_db_snapshot_t *snap, const zone_db_entry_t *entry,
                                     const zone_config_t *zcfg, axfr_bg_ctx_t *ctx) {
  const zone_config_t *mcfg = zcfg;
  if (entry->is_catalog_member) {
    mcfg = NULL;
    if (entry->owning_catalog_domain && snap) {
      view_snapshot_t *vs = snapshot_find_view(snap, entry->view_name);
      zone_db_entry_t *cat = vs ? find_zone_in_view(vs, entry->owning_catalog_domain) : NULL;
      const zone_config_t *cc = cat ? zone_entry_config(active, cat) : NULL;
      if (cc && zext(cc)->masters_count > 0) mcfg = cc;
    }
  }
  xfr_opts_effective(active, mcfg, entry->view_name, &ctx->eff);
  ctx->has_eff = true;
  ctx->per_ns_limit = xfr_cfg_limit(active, XL_TRANSFERS_PER_NS);
  int n = 0;
  if (mcfg) {
    const zone_ext_t *x = zext(mcfg);
    for (int i = 0; i < x->masters_count && n < XFR_PRIMARIES_MAX; i++) {
      if (!x->masters[i].ip) continue;
      xfr_primary_t *p = &ctx->prim[n++];
      strlcpy(p->ip, x->masters[i].ip, sizeof(p->ip));
      p->port = config_target_port(active, x->masters[i].port);   /* a database zone leaves 0 for an element without a port: options { port } */
      xfr_primary_setup(active, mcfg, entry->view_name, x->masters[i].key, x->tsig_key, &x->masters[i], p, ctx);
    }
    if (x->masters_count > XFR_PRIMARIES_MAX)
      syslog(LOG_WARNING, "[AXFR] zone %s: %d primaries are listed; only the first %d are used", ctx->domain, x->masters_count, XFR_PRIMARIES_MAX);
  } else if (entry->catalog_master && entry->catalog_master->ip[0]) {
    xfr_primary_t *p = &ctx->prim[n++];
    strlcpy(p->ip, entry->catalog_master->ip, sizeof(p->ip));
    p->port = config_target_port(active, entry->catalog_master->port);
    /* the same ranking as for a listed primary (peer_key_name()): the key of the primaries element, the key of the server statement, the catalog zone's tsig-key */
    xfr_primary_setup(active, NULL, entry->view_name, entry->catalog_master->key, entry->catalog_master->zone_key, NULL, p, ctx);
  }
  ctx->nprim = n;
}

/* tcp-window: listen() 前に listen ソケットの SO_RCVBUF / SO_SNDBUF を設定する。
 * accept 済みソケットはこの値を引き継ぐため、SYN-ACK で通知する初期ウィンドウから効く。
 * listen ソケットは reload で作り直さないので、変更の反映には再起動が必要。
 * (tcp-mss はここでは設定しない。FreeBSD の TCP_MAXSEG は現在の t_maxseg 以下しか
 * 受け付けず、未接続ソケットの t_maxseg は net.inet.tcp.mssdflt (既定 536) なので
 * 通常の値は EINVAL になるうえ、SYN-ACK の MSS は経路 MTU から決まり引き継がれない。
 * accept 直後に apply_tcp_mss() で各接続へ当てる。)
 * ワーカーごとに listen ソケットを作るので、ログは verbose なワーカーだけが出す。 */
STATIC_TEST void apply_tcp_listen_opts(int fd, const server_config_t *cfg, bool verbose) {
  if (!cfg || (cfg_tcp_rcvbuf(cfg) <= 0 && cfg_tcp_sndbuf(cfg) <= 0)) return;
  static const int opts[2] = { SO_RCVBUF, SO_SNDBUF };
  static const char *const names[2] = { "SO_RCVBUF", "SO_SNDBUF" };
  for (int k = 0; k < 2; k++) {
    int want = k == 0 ? cfg_tcp_rcvbuf(cfg) : cfg_tcp_sndbuf(cfg);   /* tcp-window, or tcp-receive-buffer / tcp-send-buffer */
    if (want <= 0) continue;
    if (setsockopt(fd, SOL_SOCKET, opts[k], &want, sizeof(want)) != 0) {
      if (verbose)
        syslog(LOG_WARNING, "[Network] Failed to set TCP %s to %d (tcp-window): %m", names[k], want);
      continue;
    }
    int actual = 0;
    socklen_t optlen = sizeof(actual);
    if (verbose && getsockopt(fd, SOL_SOCKET, opts[k], &actual, &optlen) == 0 && actual < want)
      syslog(LOG_WARNING,
             "[Network] TCP %s truncated by OS: requested %d bytes (tcp-window), got %d bytes "
             "(raise kern.ipc.maxsockbuf)", names[k], want, actual);
  }
}

/* tcp-mss / zone-tcp-mss: 確立済み接続の送信 MSS を下げる。FreeBSD の TCP_MAXSEG は
 * 現在の MSS を超える値を EINVAL にし、相手へ通知済みの MSS も変わらないため、
 * 一度下げた値は接続が終わるまで残る (複数の値が当たる場合は最小値が勝つ)。 */
STATIC_TEST void apply_tcp_mss(int fd, tcp_stream_ctx_t *c, int mss) {
#ifdef TCP_MAXSEG
  if (mss <= 0 || (c->applied_mss != 0 && mss >= c->applied_mss)) return;
  setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
  c->applied_mss = mss;
#else
  (void)fd; (void)c; (void)mss;
#endif
}

/* zone-tcp-window / zone-tcp-sndbuf の1項目分。want == 0 (このゾーンは未指定) なら、
 * 以前のクエリで別ゾーンの値を当てていた場合に限り元の値へ戻す。 */
static void apply_zone_sockbuf(int fd, int opt, int want, int *applied, int *orig) {
  if (want > 0) {
    if (*applied == want) return;
    if (*orig == 0) {
      socklen_t optlen = sizeof(*orig);
      if (getsockopt(fd, SOL_SOCKET, opt, orig, &optlen) != 0 || *orig <= 0) *orig = -1;
    }
    setsockopt(fd, SOL_SOCKET, opt, &want, sizeof(want));
    *applied = want;
  } else if (*applied != 0) {
    if (*orig > 0) setsockopt(fd, SOL_SOCKET, opt, orig, sizeof(*orig));
    *applied = 0;
  }
}

/* zone-tcp-mss / zone-tcp-window / zone-tcp-sndbuf を accept 済みソケットへ適用する。
 * ゾーンはクエリを読むまで分からないため、1接続で複数ゾーンへ問い合わせると
 * クエリごとに切り替わる (値が変わるときだけ setsockopt する)。MSS だけは
 * apply_tcp_mss() の通り下げる方向のみで、戻さない。 */
STATIC_TEST void apply_zone_tcp_opts(int fd, tcp_stream_ctx_t *c, const zone_config_t *zcfg) {
  if (zcfg) apply_tcp_mss(fd, c, zext(zcfg)->zone_tcp_mss);
  apply_zone_sockbuf(fd, SO_RCVBUF, zcfg ? zext(zcfg)->zone_tcp_window : 0, &c->applied_rcvbuf, &c->orig_rcvbuf);
  apply_zone_sockbuf(fd, SO_SNDBUF, zcfg ? zext(zcfg)->zone_tcp_sndbuf : 0, &c->applied_sndbuf, &c->orig_sndbuf);
}

/* Is the peer sa (sockaddr_in / sockaddr_in6) matched by options { blackhole }?  Reads the list from the current configuration snapshot
 * (a reload that adds or removes it applies at once); the list is a plain aml_t, so there is no allocation. */
static bool blackhole_drops(worker_ctx_t *ctx, const void *sa) {
  bool drop = false;
  rcu_reader_enter(ctx);
  server_config_t *cfg = acquire_config_snapshot();
  if (cfg && cfg->blackhole) {
    aml_subject_t subj;
    aml_subject_from_sockaddr(&subj, sa, NULL);
    drop = aml_allows(cfg->blackhole, &subj);
  }
  release_config_snapshot(cfg);
  rcu_reader_exit(ctx);
  return drop;
}

void *worker_thread_func(void *arg) {
  worker_ctx_t *ctx = (worker_ctx_t *)arg;
  uint8_t *tcp_res_buf = NULL;
#ifndef CPU_SETSIZE
#define CPU_SETSIZE 256
#endif
  cpuset_t cpuset;
  CPU_ZERO(&cpuset);
  if (ctx->core_id >= 0 && ctx->core_id < (int)CPU_SETSIZE) {
    CPU_SET(ctx->core_id, &cpuset);
  }
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t),
                         &cpuset) != 0)
    goto worker_startup_failed;

  /* D-04: TCP 応答の組み立て用バッファはワーカーごとに起動時に1つ確保する
   * (以前はクエリごとに malloc(65535))。 */
  tcp_res_buf = malloc(65535);
  if (!tcp_res_buf)
    goto worker_startup_failed;
  int kq = kqueue();
  if (kq < 0)
    goto worker_startup_failed;
  int opt = 1;
  rcu_reader_enter(ctx);
  server_config_t *active_cfg = acquire_config_snapshot();
  int bind_count = active_cfg ? active_cfg->listen_count : 0;

  for (int i = 0; i < bind_count; i++) {
    const listen_addr_t *la = &active_cfg->listen[i];
    struct sockaddr_storage addr;
    socklen_t addr_len = listen_addr_sockaddr(la, &addr);
    int tcp_fd = socket(la->family, SOCK_STREAM, 0);
    if (tcp_fd < 0) continue;
    int flags = fcntl(tcp_fd, F_GETFL, 0);
    fcntl(tcp_fd, F_SETFL, flags | O_NONBLOCK);
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (la->family == AF_INET6) setsockopt(tcp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
#ifdef SO_REUSEPORT_LB
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
#else
    setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    apply_tcp_listen_opts(tcp_fd, active_cfg, ctx->thread_id == 0);
    if (bind(tcp_fd, (struct sockaddr *)&addr, addr_len) == 0) {
      listen(tcp_fd, 1024);
      limit_server_socket_rights(tcp_fd, true);
      struct kevent ev;
      EV_SET(&ev, tcp_fd, EVFILT_READ, EV_ADD, 0, 0, (void *)2);
      kevent(kq, &ev, 1, NULL, 0, NULL);
    } else {
      int bind_errno = errno;
      syslog(LOG_CRIT, "[Backend] Failed to bind TCP%s socket to %s:%d: %s%s", la->family == AF_INET ? "v4" : "v6", la->text, (int)la->port,
             strerror(bind_errno), bind_error_hint(bind_errno, la->port));
      atomic_fetch_add(&g_tcp_bind_failures, 1);
      close(tcp_fd);
    }
  }
  release_config_snapshot(active_cfg);
  rcu_reader_exit(ctx);

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
  free(tcp_res_buf);
  /* X-33: 起動できなかったワーカーを main() に知らせる (このワーカーの IPC を読む者が
   * いなくなり、そこへ振り分けられた UDP クエリが黙って捨てられるのを防ぐ) */
  atomic_store_explicit(&ctx->startup_failed, true, memory_order_release);
  atomic_fetch_add(&g_worker_start_failures, 1);
  atomic_fetch_add(&g_bound_workers, 1);
  pthread_exit(NULL);

worker_startup_success:;
  // 特権分離(setuid/setgid/Capsicum)が完了するまで、
  // イベントループ(=信頼できないネットワーク入力の処理)を開始しない。
  while (!atomic_load_explicit(&g_privilege_drop_complete, memory_order_acquire))
    sched_yield();
  if (getppid() != parent_pid)
    backend_shutdown(0); /* O-15: スレッドが動いているので exit() は使わない */
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

    rcu_reader_enter(ctx);
    server_config_t *active = acquire_config_snapshot();
    bool qlog_enabled = (active && active->logging.queries_enabled);
    uint32_t eff_max_qps = qlog_enabled ? get_effective_query_log_max_qps(active) : 0;
    bool rlog_enabled = response_log_enabled(active);
    bool blackhole_on = (active && active->blackhole);   /* options { blackhole }: read from the snapshot per packet, below */
    /* D-06 / RFC 7766 §6.2.3: 最初のメッセージまでの待ち時間と、メッセージ間の待ち時間 */
    uint32_t tcp_initial_ms = (active && active->tcp_initial_timeout > 0) ? active->tcp_initial_timeout : 10000;
    uint32_t tcp_idle_ms = (active && active->tcp_idle_timeout > 0) ? active->tcp_idle_timeout : 10000;
    release_config_snapshot(active);
    rcu_reader_exit(ctx);

    for (int i = 0; i < n_events; i++) {
      if (ev_list[i].udata == (void *)(uintptr_t)1001) {
        backend_shutdown(0); /* Supervisor が終了した (O-15: exit() は使わない) */
      } else if (ev_list[i].filter == EVFILT_TIMER) {
        int client_fd = ev_list[i].ident;
        tcp_stream_ctx_t *ctx_tcp = (tcp_stream_ctx_t *)ev_list[i].udata;
        if (!ctx_tcp) continue;
        if (ctx_tcp->quota_yield) {
          ctx_tcp->quota_yield = false;
          goto process_tcp_client;
        }
        // RFC 7766 §6.2.3: 次のメッセージの期限が過ぎた。接続を閉じる
        tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
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
            ipc_sockaddr_t *client_addr = &ipc_msg->client_addr;

            /* options { blackhole } (BIND 9.20 lib/ns/client.c: "dropped request: blackholed peer"; the list's first match for the
             * source address is not negated): dropped before anything else looks at the packet, the response cache and the logs included,
             * and a NOTIFY answer from such an address is not passed on either.  No allocation: the subject lives on the stack. */
            if (__builtin_expect(blackhole_on, 0) && blackhole_drops(ctx, client_addr)) continue;

            // クエリパケットの検証: QRビットが0(クエリ)であることを期待
            uint8_t flags = req_buf[2];
            if (!__builtin_expect((flags & 0x80) == 0, 1)) {
              /* RFC 1996 §3.6, §4.8: 送った NOTIFY の応答は制御スレッドが照合して再送を止める */
              if (((flags >> 3) & 0x0F) == 4)
                send(g_notify_resp_ipc[1], ipc_msg, sizeof(udp_ipc_t) + (size_t)ipc_msg->payload_len, MSG_DONTWAIT);
              continue;
            }

            char client_ip[INET6_ADDRSTRLEN] = "";
            rcu_reader_enter(ctx);
            zone_db_snapshot_t *snap = acquire_zone_snapshot();
            if (__builtin_expect(client_addr->ss_family == AF_INET, 1)) {
              fast_ipv4_to_str(client_addr->sin.sin_addr.s_addr, client_ip);
            } else if (client_addr->ss_family == AF_INET6) {
              inet_ntop(AF_INET6,
                        &client_addr->sin6.sin6_addr,
                        client_ip, INET6_ADDRSTRLEN);
            }

            // --- 高速ワンパス走査 ---
            char qname[DNS_NAME_TEXT_SIZE] = "";
            uint16_t qtype = 0;
            uint16_t qclass = 1;
            size_t question_end = DNS_HEADER_SIZE;
            bool has_edns = false;
            bool dnssec_ok = false;

            if (payload_received > DNS_HEADER_SIZE) {
              parse_query_question_fast(req_buf, (size_t)payload_received, qname, sizeof(qname),
                                        &qtype, &qclass, &question_end);
              size_t offset = question_end;
              size_t recv_len = (size_t)payload_received;

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
              client_port = ntohs(client_addr->sin.sin_port);
            else if (client_addr->ss_family == AF_INET6)
              client_port =
                  ntohs(client_addr->sin6.sin6_port);

            if (qlog_enabled && !__builtin_expect(atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed), 0)) {
                write_query_log(ctx, client_addr, ipc_msg->addr_len,
                                qname, qclass, qtype, has_edns, dnssec_ok, IPPROTO_UDP, eff_max_qps);
            }
            write_dnstap_event(ctx, 1 /*AUTH_QUERY*/, req_buf, payload_received, client_addr, ipc_msg->addr_len,
                               ipc_msg->has_source_addr ? &ipc_msg->source_addr : NULL, ipc_msg->has_source_addr, IPPROTO_UDP);

            /* E2: the view and the zone are looked up here once; process_dns_query_cap_routed() takes them instead of looking
             * them up again. */
            query_route_t route;
            tsig_request_t route_tsig;   /* written only when a view with `match-clients { key ...; }` has checked the TSIG (select_view_req()) */
            bool route_tsig_done;
            route.view = select_view_req(snap, acquire_config_snapshot(), client_ip, req_buf, (size_t)payload_received, &route_tsig, &route_tsig_done);
            route.tsig = route_tsig_done ? &route_tsig : NULL;
            route.entry = route.view ? find_zone_for_query(route.view, qname, ((req_buf[2] >> 3) & 0x0F) == 0 ? qtype : 0) : NULL;
            if (route.entry && (route.entry->kind == ZONE_KIND_PROGRAM || route.entry->kind == ZONE_KIND_FORWARD)) {
              uint8_t *heap_req = malloc((size_t)payload_received);
              if (!heap_req) {
                if (rlog_enabled) {
                  submit_response_log(LOG_ACT_DROP_RRL, client_ip, client_port, qname, qclass, qtype, 2, has_edns, dnssec_ok);
                }
                rcu_reader_exit(ctx);
                continue;
              }
              memcpy(heap_req, req_buf, (size_t)payload_received);

              async_io_task_t task = {0};
              task.is_tcp = false;
              task.active_fd = active_fd;
              task.ipc_hdr = *ipc_msg;
              task.req_buf = heap_req;
              task.req_buf_cap = (size_t)payload_received;
              task.req_len = (size_t)payload_received;
              strncpy(task.client_ip, client_ip, sizeof(task.client_ip) - 1);
              task.client_port = client_port;
              memcpy(&task.client_addr, client_addr, ipc_msg->addr_len <= sizeof(task.client_addr) ? ipc_msg->addr_len : sizeof(task.client_addr));
              task.client_len = ipc_msg->addr_len;
              task.has_server_addr = ipc_msg->has_source_addr;
              if (ipc_msg->has_source_addr) {
                memcpy(&task.server_addr, &ipc_msg->source_addr, sizeof(ipc_msg->source_addr));
              }
              strncpy(task.qname, qname, sizeof(task.qname) - 1);
              task.qtype = qtype;
              task.qclass = qclass;
              task.has_edns = has_edns;
              task.dnssec_ok = dnssec_ok;
              task.question_end = question_end;
              task.snap = acquire_zone_snapshot();
              retain_zone_snapshot(task.snap);
              if (!enqueue_async_io_task(&task)) {
                release_zone_snapshot(task.snap);
                free(task.req_buf);
                if (rlog_enabled) {
                  submit_response_log(LOG_ACT_DROP_RRL, client_ip, client_port, qname, qclass, qtype, 2, has_edns, dnssec_ok);
                }
              }
              rcu_reader_exit(ctx);
              continue;
            }

            uint8_t *res_buf = batch->tx_buffers[n_tx] + sizeof(udp_ipc_t);
            const rate_limit_config_t *rrl_cfg = NULL;
            query_set_client_addr(client_addr);
            query_set_local_addr(ipc_msg->has_source_addr ? &ipc_msg->source_addr : NULL);   /* allow-query-on */
            int res_len =
                process_dns_query_cap_routed(req_buf, payload_received, res_buf, UDP_DEFAULT_MAX_RES_LEN,
                                             UDP_IPC_BUFFER_SIZE - sizeof(udp_ipc_t), qname,
                                             qtype, client_ip, &thread_compress_ctx, false, &rrl_cfg, snap, &route);
            if (res_len > 0) {
              bool drop_packet = false;
              bool tc_packet = false;

              if (__builtin_expect(rrl_cfg != NULL && rrl_cfg->configured, 0)) {
                bool slip_triggered = false;
                /* D-05: BIND と同じキー (クライアントのプレフィックス + 応答の種類 + 名前) */
                rrl_key_t rrl_key;
                char rrl_name[DNS_NAME_TEXT_SIZE];
                rrl_make_key(&rrl_key, res_buf, (size_t)res_len, qname, qtype, qclass, t_query_rrl_info.zone,
                             t_query_rrl_info.wildcard, rrl_name, sizeof(rrl_name));
                if (!rrl_check_key(&ipc_msg->client_addr, &rrl_key, rrl_cfg, &slip_triggered)) {
                  if (slip_triggered) {
                    tc_packet = true;
                  } else {
                    drop_packet = true;
                  }
                  zone_db_entry_t *rrl_z = route.entry; /* the zone the query was answered from (E2) */
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
                rcu_reader_exit(ctx);
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
                /* TC=1、質問と OPT だけ。署名付きの要求なら署名し直す (X-20) */
                int qlen = (int)dns_rrl_slip_response(res_buf, (size_t)res_len,
                                                      UDP_IPC_BUFFER_SIZE - sizeof(udp_ipc_t));
                res_msg->payload_len = qlen;
                batch->tx_iov[n_tx].iov_len = sizeof(udp_ipc_t) + qlen;
              } else {
                res_msg->payload_len = res_len;
                batch->tx_iov[n_tx].iov_len = sizeof(udp_ipc_t) + res_len;
              }

              write_dnstap_event(ctx, 2 /*AUTH_RESPONSE*/, res_buf, res_msg->payload_len, client_addr, ipc_msg->addr_len,
                                 ipc_msg->has_source_addr ? &ipc_msg->source_addr : NULL, ipc_msg->has_source_addr, IPPROTO_UDP);

              batch->tx_iov[n_tx].iov_base = batch->tx_buffers[n_tx];
              batch->tx_msgs[n_tx].msg_hdr.msg_name = NULL;
              batch->tx_msgs[n_tx].msg_hdr.msg_namelen = 0;
              batch->tx_msgs[n_tx].msg_hdr.msg_control = NULL;
              batch->tx_msgs[n_tx].msg_hdr.msg_controllen = 0;
              n_tx++;
              if (n_tx == UDP_BATCH_SIZE) {
                sendmmsg_skip_failed(active_fd, batch->tx_msgs, n_tx, "Backend->Frontend IPC", true);
                n_tx = 0;
              }
              rcu_reader_exit(ctx);
            } else {
              if (rlog_enabled) {
                submit_response_log(LOG_ACT_DROP_MALFORMED, client_ip, client_port, "<malformed>", 
                                    0, 0, 0, false, false);
              }
              rcu_reader_exit(ctx);
            }
          }
          atomic_fetch_add_explicit(&ctx->query_count, n_recv, memory_order_relaxed);
          if (n_tx > 0) {
            sendmmsg_skip_failed(active_fd, batch->tx_msgs, n_tx, "Backend->Frontend IPC", true);
            n_tx = 0;
          }
        }
      } else if (ev_list[i].udata == (void *)2) {
        // TCP
        int active_tcp_fd = ev_list[i].ident;
        int accept_count = 0;
        int accept_tcp_mss = 0;
        rcu_reader_enter(ctx);
        server_config_t *accept_cfg = acquire_config_snapshot();
        if (accept_cfg) accept_tcp_mss = accept_cfg->tcp_mss;
        release_config_snapshot(accept_cfg);
        rcu_reader_exit(ctx);
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

          /* options { blackhole }: BIND refuses the connection of a blackholed peer (lib/ns/client.c, ns_client_checkaccept()); closed here
           * before a context is taken, so it is not read, answered or counted */
          if (__builtin_expect(blackhole_on, 0) && blackhole_drops(ctx, &client_addr)) {
            close(client_fd);
            continue;
          }

          /* 上限は開いている TCP 接続の数で数える (AXFR スレッドや非同期 I/O スレッドへ渡した
           * 接続はプールのコンテキストを返しているが、閉じるまで g_tcp_clients に数えられる) */
          if (atomic_load_explicit(&g_tcp_clients, memory_order_acquire) >= MAX_TCP_CLIENTS) {
            close(client_fd);
            continue;
          }
          /* D-04: コンテキストは起動時に確保したプールから取る */
          tcp_stream_ctx_t *ctx_tcp = tcp_ctx_alloc();
          if (!ctx_tcp) {
            close(client_fd);
            continue;
          }
          inc_tcp_clients();

          limit_client_socket_rights(client_fd);
          int cflags = fcntl(client_fd, F_GETFL, 0);
          fcntl(client_fd, F_SETFL, cflags | O_NONBLOCK);
          clock_gettime(CLOCK_MONOTONIC, &ctx_tcp->connect_time);
          apply_tcp_mss(client_fd, ctx_tcp, accept_tcp_mss);
          /* D-06: 最初のメッセージの期限は tcp-initial-timeout (RFC 7766 §6.2.3) */
          ctx_tcp->idle_deadline_ms = (int64_t)ctx_tcp->connect_time.tv_sec * 1000 +
                                      ctx_tcp->connect_time.tv_nsec / 1000000 + tcp_initial_ms;
          struct kevent ev_timeout;
          EV_SET(&ev_timeout, client_fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
                 tcp_initial_ms, ctx_tcp);
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
          tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
          continue;
        }

        // [Slowloris対策] TCP接続全体の最大生存時間チェック (60秒)
        struct timespec now_mono;
        clock_gettime(CLOCK_MONOTONIC, &now_mono);
        int64_t elapsed_sec = (int64_t)(now_mono.tv_sec - ctx_tcp->connect_time.tv_sec);
        if (elapsed_sec >= 60) {
          tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
          continue;
        }

        int processed_queries = 0;
        bool client_closed = false;

        while (processed_queries < 16) {
          uint8_t *msg = NULL;
          uint16_t msg_len = 0;
          int ret = read_dns_tcp_message(client_fd, ctx_tcp, &msg, &msg_len);
          if (ret < 0) {
            tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
            client_closed = true;
            break;
          }
          if (ret == 0) {
            break;
          }

          if (msg_len < DNS_HEADER_SIZE) {
            tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
            client_closed = true;
            break;
          }

          // [RFC 1035 §4.1.1 / RFC 5452] QR=1 (レスポンスパケット) の破棄
          if (msg_len >= DNS_HEADER_SIZE && (msg[2] & 0x80) != 0) {
            submit_response_log(LOG_ACT_DROP_MALFORMED, ctx_tcp->client_ip, 0, "<response-on-query-port>", 0, 0, 0, false, false);
            tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
            client_closed = true;
            break;
          }

          processed_queries++;
          /* メッセージを1つ受け取り終えたので、次のメッセージの期限を tcp-idle-timeout で決め直す
           * (RFC 7766 §6.2.3) */
          ctx_tcp->idle_deadline_ms = (int64_t)now_mono.tv_sec * 1000 + now_mono.tv_nsec / 1000000 + tcp_idle_ms;
          struct kevent ev_del;
          EV_SET(&ev_del, client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
          kevent(kq, &ev_del, 1, NULL, 0, NULL);

          char qname[DNS_NAME_TEXT_SIZE] = "";
          uint16_t qtype = 0;
          uint16_t qclass = 1;
          size_t question_end = DNS_HEADER_SIZE;
          if (msg_len > DNS_HEADER_SIZE) {
            parse_query_question_fast(msg, msg_len, qname, sizeof(qname),
                                      &qtype, &qclass, &question_end);
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
          edns_info_t edns;
          edns_info_reset(&edns); /* E11: the same as in process_query_body() */
          edns.present = false;
          if (msg_len >= DNS_HEADER_SIZE) {
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
          rcu_reader_enter(ctx);
          atomic_fetch_add_explicit(&ctx->query_count, 1, memory_order_relaxed);
          if (qlog_enabled && !atomic_load_explicit(&g_qlog_circuit_broken, memory_order_relaxed)) {
              write_query_log(ctx, &ctx_tcp->client_addr, ctx_tcp->client_len,
                              qname, qclass, qtype, has_edns, dnssec_ok, IPPROTO_TCP, eff_max_qps);
          }
          write_dnstap_event(ctx, 1 /*AUTH_QUERY*/, msg, msg_len, &ctx_tcp->client_addr, ctx_tcp->client_len,
                             ctx_tcp->has_server_addr ? &ctx_tcp->server_addr : NULL,
                             ctx_tcp->has_server_addr, IPPROTO_TCP);

          zone_db_snapshot_t *snap = acquire_zone_snapshot();
          server_config_t *cfg = acquire_config_snapshot();
          /* the view of the request (a view whose match-clients has a `key` is matched with the TSIG key, select_view_req()); xfr_tsig is the
           * check of the TSIG against that view's key ring when it was made, so the transfer below does not verify the MAC twice */
          tsig_request_t xfr_tsig;
          bool xfr_tsig_done;
          view_snapshot_t *xfr_view = select_view_req(snap, cfg, ctx_tcp->client_ip, msg, msg_len, &xfr_tsig, &xfr_tsig_done);
          const zone_config_t *zcfg = xfr_view
              ? find_zone_config_in_view(cfg, xfr_view->name, qname)
              : NULL;
          if (xfr_view && (qtype == 252 || qtype == 251)) {
            /* a DB zone has settings of its own (dbcfg), and a secondary may have settings received from its primary (B8t-2: rxcfg,
             * the zone's own statements first): the transfer checks below read them like a configured zone's */
            zone_db_entry_t *xfr_entry = find_zone_exact_in_view(xfr_view, qname);
            if (xfr_entry && (!zcfg || xfr_entry->source == ZONE_SRC_DB || atomic_load_explicit(&xfr_entry->rxcfg, memory_order_acquire))) {
              const zone_config_t *ec = zone_entry_config(cfg, xfr_entry);
              if (ec) zcfg = ec;
            }
          }
          bool is_synthetic_zone = (zcfg && zcfg->type &&
                                    (strcasecmp(zcfg->type, "program") == 0 ||
                                     strcasecmp(zcfg->type, "forward") == 0));

          /* zone-tcp-*: zcfg は QNAME がゾーン頂点と一致したときだけ見つかるので
           * (AXFR/IXFR 用)、それ以外は QNAME を含む最も近いゾーンを引き直す。
           * どのゾーンにも指定がなければ検索自体を省く。AXFR ワーカーへ渡す前に
           * 適用しておくことで、転送スレッドもこの値で送信する。 */
          if (cfg && (cfg->any_zone_tcp_opts || atomic_load_explicit(&g_db_zone_tcp_opts, memory_order_relaxed))) {
            const zone_config_t *tcp_zcfg = zcfg;
            if (!tcp_zcfg && xfr_view) {
              zone_db_entry_t *tcp_entry = find_zone_in_view(xfr_view, qname);
              if (tcp_entry)
                tcp_zcfg = zone_entry_config(cfg, tcp_entry);
            }
            apply_zone_tcp_opts(client_fd, ctx_tcp, tcp_zcfg);
          }

          if ((qtype == 252 || qtype == 251) && !is_synthetic_zone) {
            /* R-07, R-10: TSIG を先に検証する (鍵は要求の鍵名とアルゴリズムで決める。RFC 8945 §5.2)。
             * TSIG のエラーは NOTAUTH、解釈できない TSIG は FORMERR。その後に allow-transfer を調べ、
             * 拒否は REFUSED。応答は tsig_finish_response() で署名する (検証できた要求には同じ鍵で)。 */
            tsig_request_t tsig;
            if (xfr_tsig_done) tsig = xfr_tsig;
            else tsig_check_request(cfg, xfr_view ? xfr_view->name : NULL, msg, msg_len, ctx_tcp->client_ip, &tsig);
            tsig_key_t *matched_key = (tsig.status == TSIG_REQ_VALID) ? tsig.key : NULL;
            /* X-28, RFC 6891 §6.1.3: 実装していない EDNS VERSION は、クエリ経路と同じく TSIG の検証の後、
             * allow-transfer より前に BADVERS (TSIG が正しければ署名する) */
            bool badvers = tsig.status != TSIG_REQ_ERROR && tsig.status != TSIG_REQ_FORMERR &&
                           edns_version_unsupported(&edns);
            bool allowed = false;
            if (zcfg && !badvers && tsig.status != TSIG_REQ_ERROR && tsig.status != TSIG_REQ_FORMERR) {
              /* allow-transfer のアドレスと鍵 (鍵名は DNS 名として比較 D-03)、zone の tsig-key、transfer-acl-match、
               * DB ゾーンの acl-ceiling は zone_transfer_acl_allows() が見る (dns_tsig_acl.c) */
              allowed = zone_transfer_acl_allows_in_view(cfg, zcfg, xfr_view ? xfr_view->name : NULL, ctx_tcp->client_ip,
                                                         matched_key ? matched_key->name : NULL);
            }
            uint8_t tsig_mac[64]; /* >= EVP_MAX_MD_SIZE */
            static_assert(sizeof(tsig_mac) >= sizeof(tsig.mac), "tsig_mac must hold the request MAC");
            size_t tsig_mac_len = matched_key ? tsig.mac_len : 0;
            if (tsig_mac_len > 0) memcpy(tsig_mac, tsig.mac, tsig_mac_len);
            zone_db_entry_t *entry = xfr_view ? find_zone_in_view(xfr_view, qname) : NULL;
            if (allowed && entry) {
              /* transfers-out and max-transfer-time-out / max-transfer-idle-out (BIND 9.20), read before the configuration is released */
              uint32_t out_limit = xfr_cfg_limit(cfg, XL_TRANSFERS_OUT);
              xfr_eff_t out_eff;
              /* the settings of the view that owns the zone, not of the view the client came through (a zone shared with in-view is one object) */
              xfr_opts_effective(cfg, zcfg, entry->view_name, &out_eff);
              release_config_snapshot(cfg);
              if (!xfr_counter_acquire(&g_xfr_out_active, out_limit)) {
                allowed = false; /* "Zone transfer requests in excess of the limit are refused" (ARM transfers-out) */
              } else {
                atomic_fetch_add(&entry->active_axfr, 1);
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
                  strlcpy(args->qname, qname, sizeof(args->qname));
                  args->qclass = qclass;
                  args->qtype = qtype;
                  args->has_edns = has_edns;
                  args->dnssec_ok = dnssec_ok;
                  args->req_len = msg_len > sizeof(args->req) ? sizeof(args->req) : msg_len;
                  memcpy(args->req, msg, args->req_len);
                  if (matched_key) {
                    args->has_tsig = true;
                    strncpy(args->tsig_name, matched_key->name ? matched_key->name : "", sizeof(args->tsig_name) - 1);
                    args->tsig_name[sizeof(args->tsig_name) - 1] = '\0';
                    strncpy(args->tsig_algorithm, matched_key->algorithm ? matched_key->algorithm : "", sizeof(args->tsig_algorithm) - 1);
                    args->tsig_algorithm[sizeof(args->tsig_algorithm) - 1] = '\0';
                    args->tsig_secret_decoded_len = matched_key->secret_decoded_len;
                    if (args->tsig_secret_decoded_len > sizeof(args->tsig_secret_decoded))
                      args->tsig_secret_decoded_len = sizeof(args->tsig_secret_decoded);
                    memcpy(args->tsig_secret_decoded, matched_key->secret_decoded, args->tsig_secret_decoded_len);
                  } else {
                    args->has_tsig = false;
                    args->tsig_secret_decoded_len = 0;
                  }
                  args->tsig_mac_len = tsig_mac_len;
                  if (tsig_mac_len > 0) memcpy(args->tsig_mac, tsig_mac, tsig_mac_len);
                  args->entry = entry;
                  args->idle_out_secs = out_eff.xfer_idle_out;
                  args->time_out_secs = out_eff.xfer_time_out;
                  args->snap = snap;
                  retain_zone_snapshot(args->snap);
                  int cflags = fcntl(client_fd, F_GETFL, 0);
                  fcntl(client_fd, F_SETFL, cflags & ~O_NONBLOCK);

                  // Item 1: AXFR UAF防止 - pthread_create直前にkqueueのEVFILT_READ / EVFILT_TIMERを削除
                  struct kevent ev_del_axfr[2];
                  EV_SET(&ev_del_axfr[0], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
                  EV_SET(&ev_del_axfr[1], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
                  kevent(kq, ev_del_axfr, 2, NULL, 0, NULL);

                  pthread_t t;
                  if (pthread_create(&t, NULL, axfr_worker_thread, args) != 0) {
                    release_zone_snapshot(args->snap);
                    free(args);
                    atomic_fetch_sub(&entry->active_axfr, 1);
                    xfr_counter_release(&g_xfr_out_active);
                    allowed = false;
                  } else {
                    pthread_detach(t);
                    /* fd は AXFR スレッドのもの。kevent は上で外してある */
                    tcp_client_forget(client_fd, ctx_tcp, ev_list, i, n_events);
                    client_closed = true;
                    rcu_reader_exit(ctx);
                    break;
                  }
                } else {
                  atomic_fetch_sub(&entry->active_axfr, 1);
                  xfr_counter_release(&g_xfr_out_active);
                  allowed = false;
                }
              }
            }
            if (!allowed || !entry) {
              uint8_t res_buf[1024];
              uint8_t rcode = 5; /* REFUSED: 方針による拒否 (RFC 1035 §4.1.1、RFC 5936 §5)。AA=0 (R-06) */
              int built;
              if (badvers) {
                built = dns_build_badvers_response(msg, msg_len, res_buf, sizeof(res_buf), 1, &edns, true, cfg);
              } else {
                if (tsig.status == TSIG_REQ_FORMERR) {
                  rcode = 1;       /* RFC 8945 §5.2: 解釈できない TSIG */
                } else if (tsig.status == TSIG_REQ_ERROR) {
                  rcode = 9;       /* RFC 8945 §5.2.1-§5.2.4: TSIG のエラーは NOTAUTH */
                  add_ede(&edns, cfg ? cfg->send_extended_errors : false, 18, "Invalid TSIG");
                } else {
                  add_ede(&edns, cfg ? cfg->send_extended_errors : false, 18, "Query refused due to access control");
                }
                /* 質問セクションまで (Rule 3)。TSIG なしの要求への応答は署名しない (RFC 8945 §5.3) */
                built = dns_build_error_response(msg, msg_len, res_buf, sizeof(res_buf), rcode, 0, 1,
                                                 &edns, true, cfg);
              }
              int signed_len = tsig_finish_response(res_buf, (size_t)built, sizeof(res_buf), &tsig);
              if (signed_len < DNS_HEADER_SIZE) {
                release_config_snapshot(cfg);
                tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
                client_closed = true;
                rcu_reader_exit(ctx);
                break;
              }
              size_t copy_len = (size_t)signed_len;
              release_config_snapshot(cfg);
              write_dnstap_event(ctx, 2 /*AUTH_RESPONSE*/, res_buf, copy_len,
                                 &ctx_tcp->client_addr, ctx_tcp->client_len,
                                 ctx_tcp->has_server_addr ? &ctx_tcp->server_addr : NULL,
                                 ctx_tcp->has_server_addr, IPPROTO_TCP);
              (void)send_tcp_dns_message(client_fd, res_buf, copy_len); /* 失敗しても下で閉じる */

              submit_response_log(LOG_ACT_SENT, ctx_tcp->client_ip, client_port, qname,
                                  qclass, qtype, res_buf[3] & 0x0F, has_edns, dnssec_ok);

              tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
              client_closed = true;
              rcu_reader_exit(ctx);
              break;
            }
          } else {
            /* E2: same as the UDP path above */
            query_route_t route;
            tsig_request_t route_tsig;   /* as in the UDP path above */
            bool route_tsig_done;
            route.view = select_view_req(snap, acquire_config_snapshot(), ctx_tcp->client_ip, msg, msg_len, &route_tsig, &route_tsig_done);
            route.tsig = route_tsig_done ? &route_tsig : NULL;
            route.entry = route.view ? find_zone_for_query(route.view, qname, ((msg[2] >> 3) & 0x0F) == 0 ? qtype : 0) : NULL;
            if (route.entry && (route.entry->kind == ZONE_KIND_PROGRAM || route.entry->kind == ZONE_KIND_FORWARD)) {
              /* forward / program ゾーン: 非同期 I/O スレッドへ渡すために要求を複製する
               * (D-04 で文書化した例外。平文 TCP のホットパスではない) */
              uint8_t *heap_req = malloc(msg_len);
              if (!heap_req) {
                tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
                client_closed = true;
                rcu_reader_exit(ctx);
                break;
              }
              memcpy(heap_req, msg, msg_len);

              struct kevent ev_del_syn[2];
              EV_SET(&ev_del_syn[0], client_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
              EV_SET(&ev_del_syn[1], client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
              kevent(kq, ev_del_syn, 2, NULL, 0, NULL);

              async_io_task_t task = {0};
              task.is_tcp = true;
              task.client_fd = client_fd;
              task.req_buf = heap_req;
              task.req_buf_cap = msg_len;
              task.req_len = msg_len;
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
              retain_zone_snapshot(task.snap);
              /* fd は非同期 I/O スレッドのもの。kevent は上で外してある */
              tcp_client_forget(client_fd, ctx_tcp, ev_list, i, n_events);

              rcu_reader_exit(ctx);
              if (!enqueue_async_io_task(&task)) {
                release_zone_snapshot(task.snap);
                free(task.req_buf);
                close(client_fd);
                dec_tcp_clients();
              }
              client_closed = true;
              break;
            }
            /* D-04: 応答はワーカーごとのバッファ (起動時に確保) に組み立てる */
            query_set_client_addr(&ctx_tcp->client_addr);
            query_set_local_addr(ctx_tcp->has_server_addr ? &ctx_tcp->server_addr : NULL);   /* allow-query-on */
            int res_len = process_dns_query_cap_routed(msg, msg_len, tcp_res_buf, 65535, 0,
                                                       qname, qtype, ctx_tcp->client_ip,
                                                       &thread_compress_ctx, true, NULL, snap, &route);
            if (res_len > 0) {
              submit_response_log(LOG_ACT_SENT, ctx_tcp->client_ip, client_port, qname, qclass, qtype,
                                  tcp_res_buf[3] & 0x0F, has_edns, dnssec_ok);
              write_dnstap_event(ctx, 2 /*AUTH_RESPONSE*/, tcp_res_buf, res_len, &ctx_tcp->client_addr, ctx_tcp->client_len,
                                 ctx_tcp->has_server_addr ? &ctx_tcp->server_addr : NULL, ctx_tcp->has_server_addr, IPPROTO_TCP);
              if (send_tcp_dns_message(client_fd, tcp_res_buf, (size_t)res_len) < 0) {
                tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
                client_closed = true;
                rcu_reader_exit(ctx);
                break;
              }
            } else {
              submit_response_log(LOG_ACT_DROP_MALFORMED, ctx_tcp->client_ip, client_port, "<malformed>",
                                  0, 0, 0, false, false);
            }

            server_config_t *cfg = acquire_config_snapshot();
            bool reuse = (cfg && cfg->tcp_connection_reuse);
            release_config_snapshot(cfg);
            if (!reuse) {
              tcp_client_close(kq, client_fd, ctx_tcp, ev_list, i, n_events);
              client_closed = true;
              rcu_reader_exit(ctx);
              break;
            }

            rcu_reader_exit(ctx);
            ctx_tcp->state = TCP_STATE_READ_LEN;
            ctx_tcp->accumulated = 0;
            ctx_tcp->msg_len = 0;
          }
        }

        if (!client_closed) {
          /* RFC 7766 §6.2.3: 期限はメッセージを受け取り終えたときにだけ延ばす (上で更新)。
           * メッセージの一部が届いても延ばさないので、少しずつ送り続けても居座れない。 */
          struct timespec ts_now;
          clock_gettime(CLOCK_MONOTONIC, &ts_now);
          int64_t now_ms = (int64_t)ts_now.tv_sec * 1000 + ts_now.tv_nsec / 1000000;

          struct kevent evs[2];
          uint32_t to_ms = (processed_queries >= 16) ? 1 : tcp_ms_until(ctx_tcp->idle_deadline_ms, now_ms);
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
  free(tcp_res_buf);
  pthread_exit(NULL);
}

// ============================================================================
// 12. Control Thread
// ============================================================================
typedef enum {
  CTRL_STATE_NEW,
  CTRL_STATE_AUTH_WAIT,
  CTRL_STATE_CMD_WAIT,
  CTRL_STATE_PARKED  /* B6a: `reload <zone>` of a database zone, waiting for the loader's answer (see db_ingest_reload) */
} ctrl_state_t;

typedef struct ctrl_client {
  int fd;
  ctrl_state_t state;
  time_t connect_time;
  time_t last_active;
  char challenge[65];
  char buf[1024];
  size_t buf_len;
  uint64_t req_id;       /* PARKED: the reload request this client waits for */
  time_t park_deadline;  /* PARKED: answer "timeout" at this time (db-reload-timeout) */
  struct ctrl_client *next;
} ctrl_client_t;

static ctrl_client_t *g_ctrl_clients = NULL;
#define CTRL_PARK_MAX 32 /* parked clients: bounded, so the request rings never fill (dns_db_ingest.c) */
static int g_ctrl_parked = 0;

static void free_ctrl_client(int fd) {
  ctrl_client_t **p = &g_ctrl_clients;
  while (*p) {
    if ((*p)->fd == fd) {
      ctrl_client_t *c = *p;
      *p = c->next;
      if (c->state == CTRL_STATE_PARKED) {
        g_ctrl_parked--;
        db_ingest_reload_cancel(c->req_id);
      }
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

STATIC_TEST config_reload_result_t perform_config_reload_ext(bool skip_unchanged);

STATIC_TEST config_reload_result_t reload_all_zones(void) {
  return perform_config_reload_ext(false);
}

STATIC_TEST config_reload_result_t perform_config_reload(void) {
  return perform_config_reload_ext(true);
}

/* "a, b" の形で item を足す (重複は足さない)。入りきらなければ足さない */
static void append_list_item(char *buf, size_t sz, const char *item) {
  size_t used = strlen(buf);
  if (strstr(buf, item)) return;
  snprintf(buf + used, sz - used, "%s%s", used ? ", " : "", item);
}

static bool str_differs(const char *a, const char *b) {
  if (!a || !b) return a != b;
  return strcmp(a, b) != 0;
}

/* O-09: 起動時にだけ使う設定 (docs/karidns.md "General syntax") が変わっていれば名前を並べる */
static void collect_restart_only_changes(const server_config_t *o, const server_config_t *n, char *buf, size_t sz) {
  if (o->port != n->port) append_list_item(buf, sz, "port");
  bool addrs_differ = o->bind_address_count != n->bind_address_count;
  for (int i = 0; !addrs_differ && i < n->bind_address_count; i++)
    addrs_differ = str_differs(o->bind_addresses[i], n->bind_addresses[i]);
  if (addrs_differ) append_list_item(buf, sz, "bind-address");
  /* listen-on / listen-on-v6 (and the union with bind-address): the sockets are opened once, so a different set of addresses or ports
   * is a restart.  blackhole is a plain list the workers read from the snapshot, so it is applied by the reload. */
  bool listen_differs = o->listen_count != n->listen_count;
  for (int i = 0; !listen_differs && i < n->listen_count; i++)
    listen_differs = o->listen[i].family != n->listen[i].family || o->listen[i].port != n->listen[i].port ||
                     memcmp(o->listen[i].addr, n->listen[i].addr, 16) != 0;
  if (listen_differs && !strstr(buf, "port") && !strstr(buf, "bind-address")) append_list_item(buf, sz, "listen-on");
  /* notify-source / transfer-source / primaries source: the Router pre-binds its NOTIFY sockets and the connect broker learns the transfer
   * sources at start-up, so an address that was not in the configuration then needs a restart (until then the system chooses the source).
   * Compared with the start-up set, not with the previous reload, so that every reload keeps saying so. */
  for (int i = 0; i < n->xfr_source_count; i++) {
    const xfr_source_t *s = &n->xfr_sources[i];
    if ((s->notify && !config_xfr_source_allowed(s->family, s->addr, false)) || (s->xfer && !config_xfr_source_allowed(s->family, s->addr, true))) {
      syslog(LOG_WARNING, "[Config] %s: %s %s was not in the configuration when the server started; it is used after a restart (until then the "
                          "system chooses the source address)", s->loc[0] ? s->loc : "configuration", s->what, s->text);
      if (!strstr(buf, "source-address")) append_list_item(buf, sz, "source-address");
    }
  }
  if (str_differs(o->user, n->user)) append_list_item(buf, sz, "user");
  if (str_differs(o->group, n->group)) append_list_item(buf, sz, "group");
  if (str_differs(o->pid_file, n->pid_file)) append_list_item(buf, sz, "pid-file");
  if (n->directory_changed) append_list_item(buf, sz, "directory");
  if (o->udp_recvbuf_size != n->udp_recvbuf_size) append_list_item(buf, sz, "udp-recvbuf-size");
  if (o->udp_sndbuf_size != n->udp_sndbuf_size) append_list_item(buf, sz, "udp-sndbuf-size");
  if (o->tcp_window != n->tcp_window) append_list_item(buf, sz, "tcp-window");
  if (cfg_tcp_rcvbuf(o) != cfg_tcp_rcvbuf(n) || cfg_tcp_sndbuf(o) != cfg_tcp_sndbuf(n)) append_list_item(buf, sz, "tcp-receive-buffer / tcp-send-buffer");
  if (o->response_cache_size != n->response_cache_size) append_list_item(buf, sz, "response-cache-size");
  if (o->control.enabled != n->control.enabled || str_differs(o->control.socket_path, n->control.socket_path))
    append_list_item(buf, sz, "control-channel socket");
  if (o->dnstap.enabled != n->dnstap.enabled || str_differs(o->dnstap.socket_path, n->dnstap.socket_path))
    append_list_item(buf, sz, "dnstap socket");
  /* beta design 7.1: the loader is started once by the supervisor, so adding or removing the database block and
   * these four options take effect only after a restart (everything else in the block reloads) */
  if (o->database.enabled != n->database.enabled) {
    append_list_item(buf, sz, "database block");
  } else if (o->database.enabled) {
    if (str_differs(o->database.driver, n->database.driver)) append_list_item(buf, sz, "database driver");
    if (str_differs(o->database.loader_user, n->database.loader_user)) append_list_item(buf, sz, "database loader-user");
    if (str_differs(o->database.loader_group, n->database.loader_group)) append_list_item(buf, sz, "database loader-group");
    if (str_differs(db_loader_path(o), db_loader_path(n))) append_list_item(buf, sz, "database loader-path");
  }
}

STATIC_TEST config_reload_result_t perform_config_reload_ext(bool skip_unchanged) {
  config_reload_result_t res;
  memset(&res, 0, sizeof(res));
  char *config_str = read_entire_file(g_config_path, NULL, NULL);
  if (!config_str) {
    res.status = CONFIG_RELOAD_READ_ERROR;
    snprintf(res.detail, sizeof(res.detail), "cannot read %s", g_config_path ? g_config_path : "(no configuration file)");
    syslog(LOG_ERR, "[Config] Reload failed: %s; keeping the current configuration.", res.detail);
    return res;
  }
  server_config_t *active =
      atomic_load_explicit(&g_config_db.active, memory_order_acquire);
  server_config_t *standby = (active == &g_config_db.config_a)
                                 ? &g_config_db.config_b
                                 : &g_config_db.config_a;

  /* [H-2] 既存のリーダーが参照を終えるのを待機。
   * standby は前回の公開で退いた設定で、retire_epoch はその公開で得た値
   * (公開してから世代を進めるので、これ以下の世代のリーダーだけが standby を持ちうる)。
   * 設定の writer は制御スレッドだけで、ワーカー以外のスレッドも設定は
   * 読み取り区間の中で読むので、この待機の後は standby を解放してよい。*/
  if (!rcu_writer_wait_until_safe(g_config_db.retire_epoch, 10000)) {
    syslog(LOG_WARNING, "[Config] Reload postponed: existing readers still active on previous configuration (timeout 10s).");
    res.status = CONFIG_RELOAD_POSTPONED;
    snprintf(res.detail, sizeof(res.detail), "readers of the previous configuration are still active");
    free(config_str);
    return res;
  }
  config_standby_reap(false); /* 周期処理がまだ解放していなければここで (待ったので必ず解放できる) */

  free_server_config_fields(standby);
  if (parse_named_conf_ext(config_str, g_config_path, standby) != 0) {
    res.status = CONFIG_RELOAD_PARSE_ERROR;
    snprintf(res.detail, sizeof(res.detail), "configuration error in %s (see syslog)", g_config_path);
    syslog(LOG_ERR, "Failed to reload configuration: parse error.");
    free(config_str);
    return res;
  }
  free(config_str);
  if (g_cli_port_override > 0) {
    standby->port = g_cli_port_override;
  }
  if (geteuid() == 0 && !standby->user) {
    syslog(LOG_ERR,
           "[Config] Reload rejected: running as root but new configuration has no 'user' directive in options{}.");
    fprintf(stderr,
           "[ERROR] Reload rejected: running as root but new configuration has no 'user' directive in options{}.\n");
    free_server_config_fields(standby);
    res.status = CONFIG_RELOAD_REJECTED;
    snprintf(res.detail, sizeof(res.detail), "running as root but the configuration has no 'user' in options{}");
    return res;
  }
  /* P4 is not checked here: the Backend runs in capability mode and cannot resolve names (getpwnam() would open the user
   * database and trap).  user / group, loader-user / loader-group and the program-user of a program zone take effect only
   * after a restart (the plugins are started at startup, the identities are resolved then); the start refuses a root one
   * (resolve_run_identity(), validate_program_zone_users()) and karicheck conf shows it before. */
  /* The new logging runtime (channels, files, the table of categories) is built before the configuration is published, so a file that
   * cannot be opened rejects the reload.  A file in a directory that was not opened before the sandbox cannot be opened by anyone now:
   * the logging in use stays as it is and a restart brings the new one (not a failure of the reload). */
  logrt_status_t log_status;
  log_runtime_t *new_rt = log_runtime_build(&standby->logging, true, &log_status);
  if (!new_rt && log_status != LOGRT_RESTART) {
    syslog(LOG_ERR, "[Config] Reload rejected: one or more log files could not be opened; "
                    "keeping the current configuration.");
    fprintf(stderr, "[ERROR] Reload rejected: one or more log files could not be opened; "
                    "keeping the current configuration.\n");
    free_server_config_fields(standby);
    res.status = CONFIG_RELOAD_REJECTED;
    snprintf(res.detail, sizeof(res.detail), "one or more log files could not be opened");
    return res;
  }
  if (active) collect_restart_only_changes(active, standby, res.restart_needed, sizeof(res.restart_needed));
  if (!new_rt || !log_runtime_install(new_rt)) {
    if (new_rt) log_runtime_free(new_rt);
    append_list_item(res.restart_needed, sizeof(res.restart_needed), "logging (a log file in a directory not opened at start-up)");
  }
  /* 応答キャッシュの鍵に入る: 設定が変われば以前の応答 (minimal-responses 等に依存) は引かれない */
  standby->generation = (active ? active->generation : 0) + 1;
  g_config_db.retire_epoch = rcu_writer_publish(&g_config_db.active, standby);
  g_config_db.standby_pending = true; /* 退いた設定 (旧 active) は猶予期間の後で config_standby_reap() が解放する */
  g_last_configured_time = time(NULL);
  // dnstap の接続先は起動時のみだが、出力するメッセージ種別はリロードで反映できる
  if (standby->dnstap.enabled) {
    dnstap_set_message_types(standby->dnstap.log_auth_query, standby->dnstap.log_auth_response);
  }
  res.zones_failed = rebuild_zone_db_from_config_ext(standby, skip_unchanged, res.detail, sizeof(res.detail));
  /* beta design 4.5: the loader gets a CONFIG with the new generation.  After the snapshot: the ingest thread answers it
   * with a walk of the registry (reeval_settings()) under the rebuild lock, which the rebuild would otherwise wait for. */
  db_ingest_config_changed();
  if (res.zones_failed < 0) {
    res.zones_failed = 0;
    snprintf(res.detail, sizeof(res.detail), "zone database could not be rebuilt (out of memory)");
    res.status = CONFIG_RELOAD_ZONE_ERRORS;
  } else if (res.zones_failed > 0) {
    res.status = CONFIG_RELOAD_ZONE_ERRORS;
  }
  for (view_config_t *v = standby->views; v; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (z->type && strcasecmp(z->type, "program") == 0) {
        program_plugin_t *running = find_program_plugin(v->name, z->domain);
        if (running) {
          /* M-4: 実行中の設定と新しい設定を比較し、変わっていれば警告 */
          char new_fingerprint[512];
          compute_program_zone_fingerprint(z, new_fingerprint, sizeof(new_fingerprint));
          if (strcmp(running->config_fingerprint, new_fingerprint) != 0) {
            syslog(LOG_WARNING, "[Plugin] zone '%s' in view '%s' (type program) configuration changed "
                   "(program/program-args/program-user/program-timeout/program-max-failures), "
                   "but the running plugin process cannot be restarted without a full karidns "
                   "restart (Capsicum sandbox is already active). The OLD configuration is "
                   "still in effect for this zone.", z->domain, v->name);
            append_list_item(res.restart_needed, sizeof(res.restart_needed), "type program zone settings");
          }
        } else {
          syslog(LOG_ERR, "[Plugin] zone '%s' in view '%s' (type program) was added via reload but "
                 "cannot be started without a full restart (Capsicum sandbox is already active). "
                 "This zone will return SERVFAIL until karidns is restarted.", z->domain, v->name);
          append_list_item(res.restart_needed, sizeof(res.restart_needed), "new type program zones");
        }
      }
    }
  }
  if (res.restart_needed[0])
    syslog(LOG_WARNING, "[Config] Reload: changed settings take effect only after a restart: %s", res.restart_needed);
  if (res.status == CONFIG_RELOAD_ZONE_ERRORS)
    syslog(LOG_ERR, "[Config] Configuration reloaded, but %d zone(s) failed to load: %s",
           res.zones_failed, res.detail);
  else
    syslog(LOG_NOTICE, "Configuration and zones reloaded successfully.");
  return res;
}

/* O-10: 延期したリロード。制御スレッドだけが読み書きする */
static bool g_reload_pending = false;
static bool g_reload_pending_full = false; /* 延期したものに全ゾーンの再読み込みが含まれる */

static config_reload_result_t run_config_reload(bool skip_unchanged) {
  bool full = !skip_unchanged || g_reload_pending_full;
  config_reload_result_t r = perform_config_reload_ext(!full);
  if (r.status == CONFIG_RELOAD_POSTPONED) {
    g_reload_pending = true;
    g_reload_pending_full = full;
  } else {
    g_reload_pending = false;
    g_reload_pending_full = false;
  }
  return r;
}

#define CTRL_RELOAD_REPLY_SIZE 768

/* D-13: reload / reconfig の応答。失敗は "ERROR ..." にして karictl が終了コード 3 を返せるようにする */
static int format_reload_reply(const config_reload_result_t *r, const char *ok_text, char *buf, size_t sz) {
  char note[sizeof(r->restart_needed) + 32] = "";
  if (r->restart_needed[0])
    snprintf(note, sizeof(note), " (restart needed for: %s)", r->restart_needed);
  int n;
  switch (r->status) {
  case CONFIG_RELOAD_OK:
    n = snprintf(buf, sz, "%s%s\n", ok_text, note);
    break;
  case CONFIG_RELOAD_ZONE_ERRORS:
    n = snprintf(buf, sz, "ERROR configuration applied, but %d zone(s) failed to load: %s%s\n", r->zones_failed,
                 r->detail, note);
    break;
  case CONFIG_RELOAD_POSTPONED:
    n = snprintf(buf, sz, "ERROR reload postponed: %s; it is retried automatically\n", r->detail);
    break;
  default:
    n = snprintf(buf, sz, "ERROR configuration not applied: %s\n", r->detail);
    break;
  }
  if (n < 0) n = 0;
  if ((size_t)n >= sz) {
    n = (int)sz - 1;
    buf[n - 1] = '\n';
  }
  return n;
}

const char *find_configured_domain(const char *arg, char *out_buf, size_t out_size) {
  if (!out_buf || out_size == 0) return arg;
  /* karictl の引数も設定のゾーン名と同じ正規形 (dns_wire.h) にしてから比べる
   * ("sp\032ace.test" と "c\(p.test" などのエスケープの書き方の違いを吸収する)。 */
  char norm[DNS_NAME_TEXT_SIZE];
  if (dns_name_normalize(arg, norm, sizeof(norm)) != (size_t)-1) arg = norm;
  snprintf(out_buf, out_size, "%s", arg);
  server_config_t *active = acquire_config_snapshot();
  if (!active) return out_buf;
  const zone_config_t *zcfg = config_find_zone_any_view(active, arg);
  if (zcfg) snprintf(out_buf, out_size, "%s", zcfg->domain);
  release_config_snapshot(active);
  return out_buf;
}

/* B6a: an answer of the database loader for a parked `reload <zone>` client (control thread) */
static void control_db_results(void) {
  db_reload_result_t r;
  while (db_ingest_reload_result(&r)) {
    ctrl_client_t *c = g_ctrl_clients;
    while (c && !(c->state == CTRL_STATE_PARKED && c->req_id == r.id)) c = c->next;
    if (!c) continue; /* the client left or timed out: nothing to do */
    char reply[sizeof(r.text) + 16];
    int n = snprintf(reply, sizeof(reply), "%s %s\n", r.ok ? "OK" : "ERROR", r.text);
    if (n > 0) (void)send(c->fd, reply, (size_t)n, 0);
    syslog(LOG_NOTICE, "[Control] reload of a database zone answered: %s", r.text);
    c->state = CTRL_STATE_CMD_WAIT; /* it is no longer waiting: free_ctrl_client() must not cancel the finished request */
    g_ctrl_parked--;
    free_ctrl_client(c->fd);
  }
}

/* B6a: parked clients whose db-reload-timeout has passed get an error; the request is forgotten */
static void control_park_timeouts(time_t now) {
  ctrl_client_t *c = g_ctrl_clients;
  while (c) {
    ctrl_client_t *next = c->next;
    if (c->state == CTRL_STATE_PARKED && now >= c->park_deadline) {
      static const char msg[] = "ERROR timeout: the database loader did not answer within db-reload-timeout; "
                                "the reload may still be applied (see 'karictl dbstatus')\n";
      (void)send(c->fd, msg, sizeof(msg) - 1, 0);
      syslog(LOG_WARNING, "[Control] reload of a database zone timed out (request %llu)", (unsigned long long)c->req_id);
      free_ctrl_client(c->fd); /* cancels the request */
    }
    c = next;
  }
}

/* D17-2 / B6a: a command about a zone that is not in karidns.conf, which may be a zone of the database.  Returns true
 * when it was answered (or the client was parked), false when there is no such DB zone ("zone not found").  The registry
 * is looked at without any wait for the loader; `reload` hands the request to the ingest thread and parks the client. */
static bool db_zone_command(ctrl_client_t *c, const char *cmd, const char *zone, const char *view_arg, bool force) {
  int cfd = c->fd;
  server_config_t *cfg = acquire_config_snapshot();
  bool enabled = cfg && cfg->database.enabled;
  uint32_t tmo = cfg && cfg->database.db_reload_timeout ? cfg->database.db_reload_timeout : 30;
  release_config_snapshot(cfg);
  if (!enabled || !db_ingest_enabled()) return false;
  bool is_reload = strcmp(cmd, "reload") == 0;
  dbreg_info_t info[2];
  int n = dbreg_find_info(view_arg, zone, info, 2);
  /* B6b: `reload <zone>` with several views that take database zones and none named asks every one of them: a mapping
   * (karidns_domain_views) may have moved the zone to another view, which only the loader can tell */
  bool all_views = false;
  char view[KARIDNS_VIEW_NAME_MAX];
  if (is_reload && !view_arg) {
    char why0[200];
    all_views = db_ingest_pick_view(NULL, view, sizeof(view), why0, sizeof(why0)) && !view[0];
  }
  if (n >= 2 && !all_views) {
    char m[160];
    int l = snprintf(m, sizeof(m), "ERROR zone exists in multiple views; specify view (e.g. '%s <zone> <view>')\n", cmd);
    send(cfd, m, (size_t)l, 0);
    return true;
  }
  if (n == 0 && !is_reload) return false;
  if (all_views) {
    /* view stays empty: dns_db_ingest.c asks every view that takes database zones */
  } else if (n == 1) {
    snprintf(view, sizeof(view), "%s", info[0].view);
  } else { /* not in the registry yet: a zone added to the database; ask the loader for it */
    char why[200];
    if (!db_ingest_pick_view(view_arg, view, sizeof(view), why, sizeof(why))) {
      char m[300];
      int l = snprintf(m, sizeof(m), "ERROR zone not found (%s)\n", why);
      send(cfd, m, (size_t)l, 0);
      return true;
    }
  }
  if (is_reload) {
    if (g_ctrl_parked >= CTRL_PARK_MAX) {
      static const char msg[] = "ERROR too many reloads are waiting for the database loader; try again later\n";
      send(cfd, msg, sizeof(msg) - 1, 0);
      return true;
    }
    uint64_t id = db_ingest_reload(false, view, zone, force);
    if (id == 0) {
      static const char msg[] = "ERROR cannot queue the reload request for the database loader\n";
      send(cfd, msg, sizeof(msg) - 1, 0);
      return true;
    }
    syslog(LOG_NOTICE, "[Control] Received reload command for database zone: %s (%s%s)%s", zone,
           all_views ? "every view" : "view ", view, force ? ", force" : "");
    c->state = CTRL_STATE_PARKED;
    c->req_id = id;
    c->park_deadline = time(NULL) + (time_t)tmo;
    g_ctrl_parked++;
    return true;
  }
  const dbreg_info_t *zi = &info[0];
  if (strcmp(cmd, "zonestatus") == 0) {
    char m[600];
    const char *res = zi->shadowed ? (zi->shadow_by == DBREG_SH_CATALOG ? "shadowed (hidden by a catalog member)"
                                                                         : "shadowed (hidden by a zone in karidns.conf)")
                                   : (zi->last_result == DBREG_REJECTED ? "rejected" : "applied");
    /* B8t-2: a database secondary with settings received from its primary */
    bool rx_on = false;
    {
      zone_db_snapshot_t *zsnap = acquire_retained_zone_snapshot();
      zone_db_entry_t *ze = zsnap ? dbreg_snapshot_entry(zsnap, zi->view, zone) : NULL;
      if (ze) rx_on = zone_rx_settings_status(ze, NULL, 0);
      if (zsnap) release_zone_snapshot(zsnap);
    }
    int l = snprintf(m, sizeof(m), "OK serial=%u refresh=%u source=database view=%s id=%lld result=%s%s%s%s%s\n", zi->serial,
                     zi->refresh, zi->view, (long long)zi->source_id, res, zi->has_entry ? "" : " (no version loaded)",
                     zi->error[0] ? " last-error: " : "", zi->error, rx_on ? " settings=primary" : "");
    if (l >= (int)sizeof(m)) l = (int)sizeof(m) - 1, m[l - 1] = '\n';
    send(cfd, m, (size_t)l, 0);
    return true;
  }
  if (strcmp(cmd, "notify") == 0) {
    zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
    zone_db_entry_t *e = snap ? dbreg_snapshot_entry(snap, zi->view, zone) : NULL;
    if (e) {
      syslog(LOG_NOTICE, "[Control] Received notify command for zone: %s (database zone, view %s)", zone, zi->view);
      zone_notify_request(e);
      send(cfd, "OK\n", 3, 0);
    } else {
      static const char msg[] = "ERROR zone is not served from the database (hidden by another zone of the same name)\n";
      send(cfd, msg, sizeof(msg) - 1, 0);
    }
    if (snap) release_zone_snapshot(snap);
    return true;
  }
  /* retransfer: a SLAVE / CONSUMER zone of the database (B7b) transfers again from its masters, as a configured secondary does;
   * a primary zone's data comes from the loader, not from a primary server */
  zone_db_snapshot_t *rsnap = acquire_retained_zone_snapshot();
  zone_db_entry_t *re = rsnap ? dbreg_snapshot_entry(rsnap, zi->view, zone) : NULL;
  if (re && re->is_secondary) {
    syslog(LOG_NOTICE, "[Control] Received retransfer command for zone: %s (database zone, view %s)", zone, zi->view);
    atomic_store_explicit(&re->serial, 0, memory_order_release);
    atomic_store_explicit(&re->refresh_now, true, memory_order_release);
    send(cfd, "OK\n", 3, 0);
  } else {
    static const char msg[] = "ERROR zone is a primary zone from the database; read it again with 'karictl reload <zone>'\n";
    send(cfd, msg, sizeof(msg) - 1, 0);
  }
  if (rsnap) release_zone_snapshot(rsnap);
  return true;
}

/* P5: SIGHUP はバックエンドの全スレッドでブロックされ、保留のまま EVFILT_SIGNAL で通知される。
 * 保留分を sigtimedwait() で取り出して送信元を見る。pkill -HUP karidns のように全プロセスへ
 * 送られると、直接届いたものとマネージャーが転送したものの2つになり、両方でリロードすると
 * 2回になる。マネージャーからのもの (転送) だけをリロードの合図にし、それ以外は無視する。
 * 何も取り出せなかった (どこかのスレッドがブロックしておらずハンドラで消費された) 場合は
 * 送信元が分からないので従来どおりリロードする。 */
static bool sighup_from_manager(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGHUP);
  const struct timespec zero = {0, 0};
  siginfo_t si;
  int drained = 0;
  bool from_manager = false;
  pid_t other = 0;
  while (sigtimedwait(&set, &si, &zero) == SIGHUP) {
    drained++;
    if (g_manager_pid > 0 && si.si_pid == g_manager_pid)
      from_manager = true;
    else
      other = si.si_pid;
  }
  if (drained == 0 || from_manager)
    return true;
  syslog(LOG_NOTICE, "[Config] SIGHUP from pid %d sent to the backend directly is ignored; "
                     "the manager forwards SIGHUP (send it to the manager or use karictl reload)",
         (int)other);
  return false;
}

void *control_thread_func(void *arg) {
  (void)arg;
  /* 制御スレッドは設定・ゾーン DB・arena の writer で、ロックを持ったまま
   * 読み取り区間に入るので、スロットを常時確保しておく (空き待ちを起こさない)。
   * 設定の writer はこのスレッドだけなので、ここでの設定の読み取りは区間不要。*/
  rcu_aux_thread_pin();
  int kq = kqueue();
  if (kq < 0)
    pthread_exit(NULL);
  atomic_store_explicit(&g_control_kq, kq, memory_order_release);
  struct kevent ev_set[6];
  EV_SET(&ev_set[0], SIGHUP, EVFILT_SIGNAL, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev_set[1], 1, EVFILT_TIMER, EV_ADD | EV_CLEAR, 0, 1000, NULL);
  EV_SET(&ev_set[2], 2, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
  /* SIGTERM / SIGINT: シグナルハンドラは起動後は何もせずに戻り、ここで受けた制御スレッドが
   * backend_shutdown() する (EVFILT_SIGNAL はハンドラがあっても配送を記録する) */
  EV_SET(&ev_set[3], SIGTERM, EVFILT_SIGNAL, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev_set[4], SIGINT, EVFILT_SIGNAL, EV_ADD | EV_CLEAR, 0, 0, NULL);
  EV_SET(&ev_set[5], DB_INGEST_CTL_EVENT, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL); /* B6a: an answer of the DB loader */
  if (kevent(kq, ev_set, 6, NULL, 0, NULL) == -1) {
    close(kq);
    pthread_exit(NULL);
  }
  atomic_store_explicit(&g_control_signals_ready, true, memory_order_release);
  if (g_control_sock >= 0) {
    EV_SET(&ev_set[0], g_control_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, ev_set, 1, NULL, 0, NULL) == -1) {
      close(kq);
      pthread_exit(NULL);
    }
  }
  if (g_notify_resp_ipc[0] >= 0) {
    EV_SET(&ev_set[0], g_notify_resp_ipc[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, ev_set, 1, NULL, 0, NULL) == -1)
      syslog(LOG_ERR, "[Control] Cannot watch NOTIFY answers: %m (outbound NOTIFY is not retransmitted correctly)");
  }

  /* O-18: main() の起動処理 (権限降格・Capsicum 突入) が終わるまで、制御コマンド・SIGHUP・
   * タイマーを処理しない。reload は設定の読み込みやログの所有者の引き渡しを行うので、
   * 起動途中の main() と並行して走らせない。kqueue の登録は済ませてあるので、その間の
   * 接続や SIGHUP は待たされるだけで失われない。 */
  while (!atomic_load_explicit(&g_privilege_drop_complete, memory_order_acquire))
    usleep(1000);

  struct kevent ev_list[4];
  while (1) {
    int n = kevent(kq, NULL, 0, ev_list, 4, NULL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    for (int i = 0; i < n; i++) {
      if (ev_list[i].filter == EVFILT_USER && ev_list[i].ident == DB_INGEST_CTL_EVENT) {
        control_db_results();
        continue;
      }
      if (ev_list[i].filter == EVFILT_READ && g_notify_resp_ipc[0] >= 0 &&
          ev_list[i].ident == (uintptr_t)g_notify_resp_ipc[0]) {
        /* UDP ワーカーが回してきた NOTIFY の応答 (udp_ipc_t + DNS メッセージ) */
        uint8_t nbuf[sizeof(udp_ipc_t) + 4096];
        ssize_t nlen;
        while ((nlen = recv(g_notify_resp_ipc[0], nbuf, sizeof(nbuf), MSG_DONTWAIT)) >= (ssize_t)sizeof(udp_ipc_t)) {
          udp_ipc_t *im = (udp_ipc_t *)nbuf;
          if (im->payload_len > nlen - (ssize_t)sizeof(udp_ipc_t)) continue;
          notify_handle_response(nbuf + sizeof(udp_ipc_t), im->payload_len, (const struct sockaddr *)&im->client_addr);
        }
        continue;
      }
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
          c->connect_time = time(NULL);
          c->last_active = c->connect_time;
          c->next = g_ctrl_clients;
          g_ctrl_clients = c;
          
          struct kevent ev_c;
          EV_SET(&ev_c, cfd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void*)1);
          kevent(kq, &ev_c, 1, NULL, 0, NULL);
          
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
        if (c->state == CTRL_STATE_PARKED) { /* waiting for the loader: nothing more is expected; a closed socket frees it */
          char junk[128];
          ssize_t pr = recv(cfd, junk, sizeof(junk), 0);
          if (pr == 0 || (pr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) free_ctrl_client(cfd);
          continue;
        }
        /* 行の処理後は buf_len < sizeof(c->buf) - 1 (改行の無いまま満杯になったクライアントは下で切断する) */
        size_t space_left = sizeof(c->buf) - c->buf_len - 1;
        ssize_t r = recv(cfd, c->buf + c->buf_len, space_left, 0);
        if (r <= 0) {
          free_ctrl_client(cfd);
          continue;
        }
        c->last_active = time(NULL);
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
              unsigned int md_len = 0;
              /* control-channel { algorithm } で指定した HMAC を使う (省略時 hmac-sha256)。
               * 名前は設定読込時に tsig_algorithm_is_supported() で検証済み。 */
              const EVP_MD *ctrl_md = cfg->control.algorithm ? tsig_algorithm_evp_md(cfg->control.algorithm)
                                                             : EVP_sha256();
              char expected[2 * EVP_MAX_MD_SIZE + 1];
              expected[0] = '\0';
              if (ctrl_md &&
                  HMAC(ctrl_md, cfg->control.secret_decoded, cfg->control.secret_decoded_len,
                       (unsigned char*)c->challenge, 64, md, &md_len) != NULL) {
                for (unsigned int k = 0; k < md_len; k++) snprintf(&expected[k*2], 3, "%02x", md[k]);
              }
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
              /* elen == 0 は HMAC 計算失敗。空の AUTH と一致させない (fail-closed) */
              if (len_ok && hmac_ok && elen > 0) {
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
            
            bool want_force = false; /* `reload <zone> [<view>] [force]` (B6a): force is the last word */
            if (strcmp(cmd, "reload") == 0 && view_arg) {
              char *fw = strrchr(view_arg, ' ');
              if (strcmp(view_arg, "force") == 0) {
                want_force = true;
                view_arg = NULL;
              } else if (fw && strcmp(fw + 1, "force") == 0) {
                want_force = true;
                while (fw > view_arg && fw[-1] == ' ') fw--;
                *fw = '\0';
              }
            }

            if (strcmp(cmd, "reload") == 0) {
              if (arg && strlen(arg) > 0) {
                char canon_buf[256];
                const char *canon_arg = find_configured_domain(arg, canon_buf, sizeof(canon_buf));
                zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
                server_config_t *active = acquire_config_snapshot();
                zone_lookup_result_t lr = {0};
                int nmatches = lookup_zone_across_views(snap, active, canon_arg, view_arg, &lr);
                if (nmatches == 0) {
                  if (db_zone_command(c, cmd, canon_arg, view_arg, want_force)) {
                    /* answered or parked (D17-2) */
                  } else {
                    syslog(LOG_ERR, "[Control] Command 'reload' failed: zone '%s' not found", canon_arg);
                    send(cfd, "ERROR zone not found\n", 21, 0);
                  }
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
                                void catalog_process_membership(zone_db_entry_t *catalog_entry, const zone_config_t *catalog_cfg, const char *view_name);
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
                        case RELOAD_ERR_BUSY:
                            send(cfd, "ERROR busy (AXFR in progress)\n", 30, 0);
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
                config_reload_result_t rr = run_config_reload(false);
                char reply[CTRL_RELOAD_REPLY_SIZE];
                int rlen = format_reload_reply(&rr, "OK reloaded", reply, sizeof(reply));
                /* B6a (design 5.2): after the configuration, ask the loader to compare its sources with the zones served;
                 * the answer is not waited for (karictl dbstatus shows the batch) */
                if ((rr.status == CONFIG_RELOAD_OK || rr.status == CONFIG_RELOAD_ZONE_ERRORS) && db_ingest_enabled()) {
                  uint64_t rid = db_ingest_reload(true, NULL, NULL, false);
                  if (rid && rlen > 0 && reply[rlen - 1] == '\n' && (size_t)rlen + 64 < sizeof(reply)) {
                    rlen--;
                    rlen += snprintf(reply + rlen, sizeof(reply) - (size_t)rlen, "; DB reload requested (request %llu)\n",
                                     (unsigned long long)rid);
                  }
                }
                send(cfd, reply, (size_t)rlen, 0);
              }
            } else if (strcmp(cmd, "reconfig") == 0) {
              syslog(LOG_NOTICE, "[Control] Received reconfig command");
              config_reload_result_t rr = run_config_reload(true);
              char reply[CTRL_RELOAD_REPLY_SIZE];
              int rlen = format_reload_reply(&rr, "OK", reply, sizeof(reply));
              send(cfd, reply, (size_t)rlen, 0);
            } else if (strcmp(cmd, "stop") == 0) {
              syslog(LOG_NOTICE, "[Control] Received stop command");
              udp_ipc_t msg;
              memset(&msg, 0, sizeof(msg));
              msg.sock_fd_idx = -2;
              uint8_t pkt[sizeof(msg)];
              memcpy(pkt, &msg, sizeof(msg));
              send(g_notify_ipc[1], pkt, sizeof(pkt), 0);
              send(cfd, "OK stopping\n", 12, 0);
              backend_shutdown(0); /* O-15: exit() は他スレッドと並行して atexit を走らせる */
            } else if (strcmp(cmd, "status") == 0) {
              karidns_status_t st;
              memset(&st, 0, sizeof(st));
              st.boot_time = g_boot_time;
              st.last_configured_time = g_last_configured_time;
              
              zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
              if (snap) {
                for (size_t v = 0; v < snap->view_count; v++) {
                  st.num_zones += snap->views[v].zone_count - snap->views[v].shared_count;   /* a zone shared with another view (in-view) is one zone */
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
              st.query_logging = (active_cfg && active_cfg->logging.queries_enabled);
              st.response_logging = (active_cfg && active_cfg->logging.responses_enabled);
              release_config_snapshot(active_cfg);
              
              st.rrl_dropped = atomic_load_explicit(&g_rrl_dropped_total, memory_order_relaxed);
              st.rrl_slipped = atomic_load_explicit(&g_rrl_slip_total, memory_order_relaxed);
              st.ede_proh = atomic_load_explicit(&g_ede_prohibited_total, memory_order_relaxed);
              st.ede_na = atomic_load_explicit(&g_ede_not_authoritative_total, memory_order_relaxed);
              st.ede_ns = atomic_load_explicit(&g_ede_not_supported_total, memory_order_relaxed);
              st.ede_oth = atomic_load_explicit(&g_ede_other_total, memory_order_relaxed);
              st.dnstap_truncated = atomic_load_explicit(&g_dnstap_truncated_total, memory_order_relaxed);
              snprintf(st.version, sizeof(st.version), "%s", KARIDNS_VERSION);
              snprintf(st.hostname, sizeof(st.hostname), "%s", g_host_status_info.un.nodename);
              snprintf(st.os_name, sizeof(st.os_name), "%s", g_host_status_info.un.sysname);
              snprintf(st.os_release, sizeof(st.os_release), "%s", g_host_status_info.un.release);
              snprintf(st.machine, sizeof(st.machine), "%s", g_host_status_info.un.machine);
              st.ncpus = g_host_status_info.ncpus;
              
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
              zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
              zone_lookup_result_t lr = {0};
              int nmatches = lookup_zone_across_views(snap, active_cfg, canon_arg, view_arg, &lr);
              if (nmatches == 0) {
                if (!db_zone_command(c, cmd, canon_arg, view_arg, false)) {
                  syslog(LOG_ERR, "[Control] Command 'zonestatus' failed: zone '%s' not found", canon_arg);
                  send(cfd, "ERROR zone not found\n", 21, 0);
                }
              } else if (nmatches > 1) {
                send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'zonestatus <zone> <view>')\n", 86, 0);
              } else if (lr.entry) {
                char smsg[384];
                char rx_note[160];
                /* B8t-2: a secondary says that settings received from its primary are in force (and which part is not) */
                bool rx_on = zone_rx_settings_status(lr.entry, rx_note, sizeof(rx_note));
                /* refresh, retry and expire are the values the zone uses: a secondary holds the SOA's to min/max-refresh-time and
                 * min/max-retry-time (batch 4) */
                int slen = snprintf(smsg, sizeof(smsg), "OK serial=%u refresh=%u retry=%u expire=%u%s%s%s\n", (uint32_t)lr.entry->serial,
                                    (uint32_t)lr.entry->refresh, (uint32_t)lr.entry->retry, (uint32_t)lr.entry->expire,
                                    rx_on ? " settings=primary" : "", rx_note[0] ? " note: " : "", rx_note);
                if (slen >= (int)sizeof(smsg)) slen = (int)sizeof(smsg) - 1, smsg[slen - 1] = '\n';
                send(cfd, smsg, slen, 0);
              } else {
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_config_snapshot(active_cfg);
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "observatory") == 0) {
              zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
              char canon_buf[256];
              const char *canon_arg = (arg && strlen(arg) > 0) ? find_configured_domain(arg, canon_buf, sizeof(canon_buf)) : NULL;

              uint32_t match_count = 0;
              if (snap) {
                for (size_t v = 0; v < snap->view_count; v++) {
                  if (view_arg && strcasecmp(snap->views[v].name, view_arg) != 0) continue;
                  for (size_t z = 0; z < snap->views[v].zone_count; z++) {
                    zone_db_entry_t *e = snap->views[v].entries[z];
                    if (!e || !view_owns_entry(&snap->views[v], e)) continue;   /* a shared zone is listed once, in its owner view */
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
                    if (!e || !view_owns_entry(&snap->views[v], e)) continue;   /* a shared zone is listed once, in its owner view */
                    if (canon_arg && !domain_names_match_ci(e->domain, canon_arg)) continue;
                    zone_observatory_snapshot_t snap_item;
                    memset(&snap_item, 0, sizeof(snap_item));
                    // active arena を読むので読み取り区間に入れる (send は区間の外)
                    rcu_aux_read_lock();
                    fill_observatory_snapshot(e, active_cfg, &snap_item);
                    rcu_aux_read_unlock();
                    send(cfd, &snap_item, sizeof(snap_item), 0);
                  }
                }
              }
              if (active_cfg) release_config_snapshot(active_cfg);
              if (snap) release_zone_snapshot(snap);
            } else if (strcmp(cmd, "notify") == 0 && arg) {
              char canon_buf[256];
              const char *canon_arg = find_configured_domain(arg, canon_buf, sizeof(canon_buf));
              zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
              zone_lookup_result_t lr = {0};
              int nmatches = lookup_zone_across_views(snap, active_cfg, canon_arg, view_arg, &lr);
              if (nmatches == 0) {
                if (!db_zone_command(c, cmd, canon_arg, view_arg, false)) {
                  syslog(LOG_ERR, "[Control] Command 'notify' failed: zone '%s' not found", canon_arg);
                  send(cfd, "ERROR zone not found\n", 21, 0);
                }
              } else if (nmatches > 1) {
                send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'notify <zone> <view>')\n", 82, 0);
              } else if (lr.entry) {
                syslog(LOG_NOTICE, "[Control] Received notify command for zone: %s", canon_arg);
                zone_notify_request(lr.entry);
                send(cfd, "OK\n", 3, 0);
              } else {
                send(cfd, "ERROR zone not found\n", 21, 0);
              }
              release_config_snapshot(active_cfg);
              release_zone_snapshot(snap);
            } else if (strcmp(cmd, "retransfer") == 0 && arg) {
              char canon_buf[256];
              const char *canon_arg = find_configured_domain(arg, canon_buf, sizeof(canon_buf));
              zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
              server_config_t *active_cfg = acquire_config_snapshot();
              zone_lookup_result_t lr = {0};
              int nmatches = lookup_zone_across_views(snap, active_cfg, canon_arg, view_arg, &lr);
              if (nmatches == 0) {
                if (!db_zone_command(c, cmd, canon_arg, view_arg, false)) {
                  syslog(LOG_ERR, "[Control] Command 'retransfer' failed: zone '%s' not found", canon_arg);
                  send(cfd, "ERROR zone not found\n", 21, 0);
                }
              } else if (nmatches > 1) {
                send(cfd, "ERROR zone exists in multiple views; specify view (e.g. 'retransfer <zone> <view>')\n", 86, 0);
              } else if (lr.entry && !lr.entry->is_secondary) {
                /* O-06: 転送元を持つのはセカンダリ (カタログのメンバーを含む) だけ。プライマリの
                 * シリアルを 0 にすると UDP IXFR や karictl zonestatus の値が壊れる。 */
                syslog(LOG_ERR, "[Control] Command 'retransfer' failed: zone '%s' is not a secondary", canon_arg);
                send(cfd, "ERROR zone is not a secondary\n", 30, 0);
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
            } else if (strcmp(cmd, "dbstatus") == 0) {
              /* beta design 5.2: the loader, the batches and the DB zones of the registry */
              char dbbuf[4096];
              size_t dblen = db_ingest_status(arg, view_arg, dbbuf, sizeof(dbbuf));
              if (dblen == 0) send(cfd, "ERROR no database block is configured\n", 38, 0);
              else send(cfd, dbbuf, dblen, 0);
            } else {
              syslog(LOG_ERR, "[Control] Received unknown command: %s", cmd);
              send(cfd, "ERROR unknown command\n", 22, 0);
            }
            if (c->state != CTRL_STATE_PARKED) free_ctrl_client(cfd); /* a parked client waits for the loader's answer */
            continue;
          }
          size_t rem = c->buf_len - (nl + 1 - c->buf);
          memmove(c->buf, nl + 1, rem);
          c->buf_len = rem;
        } else if (c->buf_len >= sizeof(c->buf) - 1) {
          /* X-47: 1 行がバッファ (1023 バイト + NUL) に収まらない。理由を返してから切断する */
          send(cfd, "ERROR buffer overflow\n", 22, 0);
          syslog(LOG_ERR, "[Control] Command buffer overflow, dropping client");
          free_ctrl_client(cfd);
        }
      } else if (ev_list[i].filter == EVFILT_SIGNAL && ev_list[i].ident == SIGHUP) {
        /* O-10: EVFILT_SIGNAL (EV_CLEAR) は前回の取り出し以降の SIGHUP をまとめて1件にし、
         * data に回数を入れる。リロード中に届いた SIGHUP は次の1回のリロードにまとめる */
        if (ev_list[i].data > 1)
          syslog(LOG_NOTICE, "[Config] %ld SIGHUP signals arrived while busy; reloading once", (long)ev_list[i].data);
        if (sighup_from_manager())
          run_config_reload(true);
      } else if (ev_list[i].filter == EVFILT_SIGNAL &&
                 (ev_list[i].ident == SIGTERM || ev_list[i].ident == SIGINT)) {
        /* O-03: 起動後の SIGTERM / SIGINT はここで受け、dnstap を閉じてから終了する */
        syslog(LOG_NOTICE, "[Backend] Received signal %d; shutting down", (int)ev_list[i].ident);
        backend_shutdown(0);
      } else if (ev_list[i].filter == EVFILT_TIMER ||
                 ev_list[i].filter == EVFILT_USER) {
        time_t now = time(NULL);
        /* S2: 兄弟ゾーンの公開 (転送、UPDATE、個別の reload) を、そのアドレスをグルーに使うゾーンの応答の版に反映し、
         * 公開で不要になった古い版を猶予期間の後で解放する */
        zone_glue_refresh_dependents(false);
        zone_retire_process(false);
        config_standby_reap(false);
        if (g_reload_pending) {
          /* O-10: 読み手が残っていて延期したリロードを捨てずにやり直す */
          syslog(LOG_NOTICE, "[Config] Retrying the postponed reload");
          run_config_reload(!g_reload_pending_full);
        }
        // Check control clients timeout: 5s unauthenticated or 15s inactive
        ctrl_client_t *curr_c = g_ctrl_clients;
        while (curr_c) {
          ctrl_client_t *next_c = curr_c->next;
          bool timed_out = false;
          if (curr_c->state == CTRL_STATE_PARKED) {
            curr_c = next_c;                             /* control_park_timeouts() below */
            continue;
          }
          if (curr_c->state != CTRL_STATE_CMD_WAIT) {
            if (now - curr_c->connect_time >= 5) {
              timed_out = true;
            }
          } else {
            if (now - curr_c->last_active >= 15) {
              timed_out = true;
            }
          }
          if (timed_out) {
            syslog(LOG_WARNING, "[Control] Disconnecting idle/unauthenticated control client fd %d", curr_c->fd);
            free_ctrl_client(curr_c->fd);
          }
          curr_c = next_c;
        }

        control_db_results(); /* an answer whose wake-up was missed */
        control_park_timeouts(now);
        notify_retransmit_due(now); /* RFC 1996 §3.6: 応答の無い NOTIFY の再送 */

        server_config_t *active = acquire_config_snapshot();
        zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
        if (snap) {
            /* B7a: the settings block of a DB zone (entry->dbcfg) is replaced when the zone's metadata change and freed after a
             * grace period, so zone_entry_config() below must be read inside a read section (the blocks of file zones belong
             * to the configuration snapshot held in `active`).
             * Only the secondaries and catalog members (the view's tick list) have timers to look at; every zone is walked
             * only when a NOTIFY was requested since the last full walk (notify_now can be set on any zone).  A walk of every
             * entry costs about 100-250 ms with 1,000,000 database zones, during which this thread answers no karictl and the
             * read section held here blocks the grace period of the ingest thread's batch (zone_retire_process(true)). */
            bool walk_all = atomic_exchange_explicit(&g_zone_notify_pending, 0, memory_order_acq_rel) != 0;
            rcu_aux_read_lock();
            for (size_t v = 0; v < snap->view_count; v++) {
                zone_db_entry_t **list = walk_all ? snap->views[v].entries : snap->views[v].tick_entries;
                size_t count = walk_all ? snap->views[v].zone_count : snap->views[v].tick_count;
                /* transfers-in and serial-query-rate leave a refresh that is over the limit for a later tick; the walk starts one entry
                 * further each tick so that the zones at the end of the list are not always the ones that wait (BIND queues them in order) */
                size_t rot = count ? g_tick_rotor % count : 0;
                for (size_t kk = 0; kk < count; kk++) {
                    size_t i = (kk + rot) % count;
                    zone_db_entry_t *entry = list[i];
                    if (!entry || !view_owns_entry(&snap->views[v], entry)) continue;   /* a zone shared with another view (in-view) is looked at in its owner view, once */

                    /* B8t-2: settings received from the primary follow a changed karidns.conf (a secondary's own statements win) */
                    if (atomic_load_explicit(&entry->rx_present, memory_order_relaxed)) zone_rx_settings_refresh(entry, active);

                    if (atomic_exchange_explicit(&entry->notify_now, false, memory_order_acquire)) {
                        /* notify-delay (BIND 9.20 ARM): the delay between two sets of NOTIFY messages for a zone; a request inside it waits */
                        if (now < entry->notify_next) {
                            atomic_store_explicit(&entry->notify_now, true, memory_order_release);
                            atomic_fetch_add_explicit(&g_zone_notify_pending, 1, memory_order_release);
                        } else {
                            xfr_eff_t nd;
                            xfr_opts_effective(active, zone_entry_config(active, entry), entry->view_name, &nd);
                            entry->notify_next = now + (time_t)nd.notify_delay;
                            syslog(LOG_INFO, "[Control] Executing manual NOTIFY for %s", entry->domain);
                            send_notify_to_all(entry);
                        }
                    }

                    bool is_slave = false;
                    bool have_primary = false;
                    const zone_config_t *slave_zcfg = NULL; /* カタログのメンバーゾーンは zone{} を持たない */

                    if (entry->is_catalog_member) {
                        is_slave = true;
                        have_primary = entry->catalog_master != NULL && entry->catalog_master->ip[0] != '\0';
                    } else {
                        const zone_config_t *zcfg = zone_entry_config(active, entry);
                        slave_zcfg = zcfg;
                        if (zcfg && zcfg->type && (strcasecmp(zcfg->type, "slave") == 0 || strcasecmp(zcfg->type, "secondary") == 0) &&
                            zext(zcfg)->masters_count > 0 && zext(zcfg)->masters[0].ip != NULL) {
                            is_slave = true;
                            have_primary = true;
                        }
                    }

                    if (is_slave && have_primary) {
                        time_t deadline = zone_expire_deadline(entry);
                        if (deadline > 0 && now > deadline) {
                            time_t last_log = atomic_load_explicit(&entry->last_stale_log_time, memory_order_acquire);
                            if (now - last_log > 900) {
                                if (active && active->serve_stale) {
                                    kdns_logc(LOGC_GENERAL, LOG_WARNING, "[Zone] Zone %s is expired (master unreachable), serving stale data", entry->domain);
                                } else {
                                    kdns_logc(LOGC_GENERAL, LOG_ERR, "[Zone] Zone %s is expired (master unreachable), returning SERVFAIL", entry->domain);
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
                                /* transfers-in (concurrent inbound transfers) and serial-query-rate (refresh checks a second): a refresh over
                                 * a limit waits for a later tick, with its timers untouched (BIND queues the zone) */
                                bool admitted = xfr_counter_acquire(&g_xfr_in_active, xfr_cfg_limit(active, XL_TRANSFERS_IN));
                                if (admitted && !xfr_rl_take(&g_serial_query_rl, xfr_cfg_limit(active, XL_SERIAL_QUERY_RATE), now)) {
                                    xfr_counter_release(&g_xfr_in_active);
                                    admitted = false;
                                }
                                if (!admitted) {
                                    atomic_store_explicit(&entry->is_transferring, false, memory_order_release);
                                    if (force) atomic_store_explicit(&entry->refresh_now, true, memory_order_release);
                                    continue;
                                }
                                uint32_t retry = atomic_load_explicit(&entry->retry, memory_order_acquire);
                                atomic_store_explicit(&entry->next_check, now + (retry ? retry : 60), memory_order_release);

                                axfr_bg_ctx_t *bg_ctx = calloc(1, sizeof(axfr_bg_ctx_t));
                                if (bg_ctx) {
                                    strncpy(bg_ctx->domain, entry->domain, sizeof(bg_ctx->domain) - 1);
                                    bg_ctx->entry = entry;
                                    bg_ctx->snap = snap;   /* retained below, once the thread is certain to start */
                                    bg_ctx->tcp_opts = xfr_tcp_sockopts(active, slave_zcfg);
                                    xfr_zone_limits(active, slave_zcfg, &bg_ctx->max_records, &bg_ctx->max_bytes); /* I2 */
                                    /* the primaries in order, with their keys copied by value ([H-4]: a pointer into the configuration would
                                     * dangle after a reload) and the options of the zone */
                                    xfr_build_primaries(active, snap, entry, slave_zcfg, bg_ctx);
                                    pthread_t bg_thread;
                                    pthread_attr_t attr;
                                    pthread_attr_init(&attr);
                                    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                                    pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
                                    retain_zone_snapshot(snap);
                                    if (bg_ctx->nprim == 0 || pthread_create(&bg_thread, &attr, axfr_bg_thread_func, bg_ctx) != 0) {
                                        release_zone_snapshot(snap);
                                        free(bg_ctx);
                                        xfr_counter_release(&g_xfr_in_active);
                                        atomic_store_explicit(&entry->is_transferring, false, memory_order_release);
                                    }
                                    pthread_attr_destroy(&attr);
                                } else {
                                    xfr_counter_release(&g_xfr_in_active);
                                    atomic_store_explicit(&entry->is_transferring, false, memory_order_release);
                                }
                            }
                        }
                    }
                }
            }
            g_tick_rotor++;
            rcu_aux_read_unlock();
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

void setup_udp_socket_buffers(int fd, int desired_rcv, int desired_snd) {
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

int open_router_udp_sockets(server_config_t *cfg, int out_fds[MAX_BIND_ADDRS], bool out_is_wildcard[MAX_BIND_ADDRS]) {
  int num_fds = 0;
  int opt = 1;
  int rcvbuf_size = cfg->udp_recvbuf_size > 0 ? cfg->udp_recvbuf_size : 4 * 1024 * 1024;
  int sndbuf_size = cfg->udp_sndbuf_size > 0 ? cfg->udp_sndbuf_size : 4 * 1024 * 1024;

  for (int i = 0; i < cfg->listen_count; i++) {
    const listen_addr_t *la = &cfg->listen[i];
    struct sockaddr_storage addr;
    socklen_t addr_len = listen_addr_sockaddr(la, &addr);
    bool is_wildcard = la->wildcard;
    if (num_fds >= MAX_BIND_ADDRS) break;
    int udp_fd = socket(la->family, SOCK_DGRAM, 0);
    if (udp_fd < 0) continue;
    setup_udp_socket_buffers(udp_fd, rcvbuf_size, sndbuf_size);
    fcntl(udp_fd, F_SETFL, fcntl(udp_fd, F_GETFL, 0) | O_NONBLOCK);
    if (la->family == AF_INET6) setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
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
    if (la->family == AF_INET) {
      int opt_dst = 1;
#ifdef IP_RECVDSTADDR
      setsockopt(udp_fd, IPPROTO_IP, IP_RECVDSTADDR, &opt_dst, sizeof(opt_dst));
#elif defined(IP_PKTINFO)
      setsockopt(udp_fd, IPPROTO_IP, IP_PKTINFO, &opt_dst, sizeof(opt_dst));
#endif
    } else {
      int opt_pktinfo = 1;
#ifdef IPV6_RECVPKTINFO
      setsockopt(udp_fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt_pktinfo, sizeof(opt_pktinfo));
#elif defined(IPV6_PKTINFO)
      setsockopt(udp_fd, IPPROTO_IPV6, IPV6_PKTINFO, &opt_pktinfo, sizeof(opt_pktinfo));
#endif
    }
    if (bind(udp_fd, (struct sockaddr *)&addr, addr_len) == 0) {
      out_is_wildcard[num_fds] = is_wildcard;
      out_fds[num_fds++] = udp_fd;
    } else {
      int bind_errno = errno;
      syslog(LOG_CRIT, "[Frontend] Failed to bind UDP%s socket to %s:%d: %s%s", la->family == AF_INET ? "v4" : "v6", la->text, (int)la->port,
             strerror(bind_errno), bind_error_hint(bind_errno, la->port));
      fprintf(stderr, "[ERROR] [Frontend] Failed to bind UDP%s socket to %s:%d: %s%s\n", la->family == AF_INET ? "v4" : "v6", la->text,
              (int)la->port, strerror(bind_errno), bind_error_hint(bind_errno, la->port));
      close(udp_fd);
      exit(EXIT_FAILURE);
    }
  }

  // Pre-bind the NOTIFY source addresses of the configuration (notify-source, notify-source-v6, the `source` of also-notify lists: every
  // distinct address in cfg->xfr_sources with notify set, from options, views, zones and lists) that no listening socket has yet.
  // The socket gets an ephemeral port (BIND 9.20 notify-source has no port): it only sends the NOTIFY and receives the answer, so it is
  // not another listening port of the server -- the old pre-bind used cfg->port (and its "already bound" test looked at the address
  // only), which made the server answer queries on the source address at the default port whatever listen-on said.  An address that a
  // listening socket has, at whatever port that statement gave it, is used as it is: the NOTIFY leaves from that socket.
  if (cfg) {
    for (int xi = 0; xi < cfg->xfr_source_count && num_fds < MAX_BIND_ADDRS; xi++) {
      const xfr_source_t *xs = &cfg->xfr_sources[xi];
      if (!xs->notify) continue;
      bool already_bound = false;
      for (int k = 0; k < num_fds && !already_bound; k++) {
        struct sockaddr_storage ss = {0};
        socklen_t slen = sizeof(ss);
        if (getsockname(out_fds[k], (struct sockaddr *)&ss, &slen) != 0 || ss.ss_family != xs->family) continue;
        if (xs->family == AF_INET)
          already_bound = memcmp(&((struct sockaddr_in *)&ss)->sin_addr, xs->addr, 4) == 0;
        else
          already_bound = memcmp(&((struct sockaddr_in6 *)&ss)->sin6_addr, xs->addr, 16) == 0;
      }
      if (already_bound) continue;
      int udp_fd = socket(xs->family, SOCK_DGRAM, 0);
      if (udp_fd < 0) continue;
      setup_udp_socket_buffers(udp_fd, rcvbuf_size, sndbuf_size);
      fcntl(udp_fd, F_SETFL, fcntl(udp_fd, F_GETFL, 0) | O_NONBLOCK);
      struct sockaddr_storage bs;
      memset(&bs, 0, sizeof(bs));
      socklen_t bl;
      if (xs->family == AF_INET) {
        struct sockaddr_in *b4 = (struct sockaddr_in *)&bs;
        b4->sin_family = AF_INET;
        memcpy(&b4->sin_addr, xs->addr, 4);
        bl = sizeof(*b4);
      } else {
        struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)&bs;
        setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        b6->sin6_family = AF_INET6;
        memcpy(&b6->sin6_addr, xs->addr, 16);
        bl = sizeof(*b6);
      }
      if (bind(udp_fd, (struct sockaddr *)&bs, bl) == 0) {
        out_is_wildcard[num_fds] = false;
        out_fds[num_fds++] = udp_fd;
      } else {
        // start-up already bound this address once (preflight_xfr_sources()), so this is rare; the NOTIFY then leaves from the system's choice
        int bind_errno = errno;
        syslog(LOG_WARNING, "[Frontend] %s: could not pre-bind the NOTIFY source %s: %s", xs->loc[0] ? xs->loc : "configuration", xs->text,
               strerror(bind_errno));
        close(udp_fd);
      }
    }
  }
  return num_fds;
}

STATIC_TEST void run_frontend_router(pid_t backend_pid, int router_id) {
  (void)backend_pid;
  cpuset_t cpuset;
  CPU_ZERO(&cpuset);
  if (router_id >= 0 && router_id < (int)CPU_SETSIZE) {
    CPU_SET(router_id, &cpuset);
  }
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
  close(g_notify_resp_ipc[0]);
  close(g_notify_resp_ipc[1]);

  server_config_t *cfg = acquire_config_snapshot();

  // 特権破棄前に、外部UDPソケットをSO_REUSEPORT_LBでオープン・バインド (指示1: インデックス整合性の完全統一)
  int local_udp_fds[MAX_BIND_ADDRS];
  bool local_udp_is_wildcard[MAX_BIND_ADDRS];
  int local_num_udp_fds = open_router_udp_sockets(cfg, local_udp_fds, local_udp_is_wildcard);

  // 特権破棄 (setgid / setuid)。非root起動で user/group が実行ユーザー自身を
  // 指している場合は降格不要としてそのまま続行する (resolve_run_identity 参照)。
  // 降格先は main() が起動時に解決した g_run_identity (O-18)。
  {
    char id_err[512];
    if (!apply_run_identity_id(&g_run_identity, id_err, sizeof(id_err))) {
      syslog(LOG_ERR, "[Frontend %d] %s", router_id, id_err);
      fprintf(stderr, "[ERROR] [Frontend %d] %s\n", router_id, id_err);
      release_config_snapshot(cfg);
      exit(EXIT_FAILURE);
    }
  }
  release_config_snapshot(cfg);

  int kq = kqueue();
  if (kq < 0)
    exit(1);

  int notify_v4_sock = -1;
  int notify_v6_sock = -1;
  for (int i = 0; i < local_num_udp_fds; i++) {
    struct sockaddr_storage ss = {0};
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
  /* SIGTERM / SIGINT / SIGCHLD / SIGHUP were reset by the fork site in main() before anything else ran; the calls
   * stay as the router's own statement of what it expects */
  signal(SIGCHLD, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGINT, SIG_DFL);
  signal(SIGHUP, SIG_IGN);
  if (router_id == 0) {
    struct kevent ev_notify;
    EV_SET(&ev_notify, g_notify_ipc[0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0,
           (void *)(uintptr_t)999);
    kevent(kq, &ev_notify, 1, NULL, 0, NULL);
  }

  pid_t parent_pid = getppid();
  struct kevent ev_proc;
  EV_SET(&ev_proc, backend_pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, (void *)1000);
  /* A failed registration means the process is already gone (ESRCH: exited and reaped), so no NOTE_EXIT will ever
   * arrive: the router would wait for it forever and keep the UDP port. */
  if (kevent(kq, &ev_proc, 1, NULL, 0, NULL) < 0) {
    syslog(LOG_NOTICE, "[Frontend %d] Backend already exited (%m); router exiting.", router_id);
    exit(0);
  }
  struct kevent ev_parent;
  EV_SET(&ev_parent, parent_pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, (void *)1001);
  if (kevent(kq, &ev_parent, 1, NULL, 0, NULL) < 0 || getppid() != parent_pid) {
    syslog(LOG_NOTICE, "[Frontend %d] Manager already exited; router exiting.", router_id);
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
    fctx->rx_msgs[k].msg_hdr.msg_namelen = sizeof(msg->client_addr);
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

  alignas(udp_ipc_t) uint8_t buffer[UDP_IPC_BUFFER_SIZE];
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
        syslog(LOG_NOTICE, "[Frontend %d] Backend process (pid=%d) terminated. Shutting down.", router_id, backend_pid);
        exit(0);
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
            udp_ipc_t *msg = (udp_ipc_t *)fctx->rx_buffers[k];
            fctx->rx_iov[k].iov_len = BUFFER_SIZE;
            fctx->rx_msgs[k].msg_hdr.msg_namelen = sizeof(msg->client_addr);
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
              msg->addr_len = (uint16_t)fctx->rx_msgs[k].msg_hdr.msg_namelen;
              msg->has_source_addr = false;
              memset(&msg->source_addr, 0, sizeof(msg->source_addr));
              msg->payload_len = (uint16_t)len;

              for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&fctx->rx_msgs[k].msg_hdr);
                   cmsg != NULL;
                   cmsg = CMSG_NXTHDR(&fctx->rx_msgs[k].msg_hdr, cmsg)) {
#ifdef IP_RECVDSTADDR
                if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVDSTADDR &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_addr))) {
                  msg->source_addr.sin.sin_family = AF_INET;
                  memcpy(&msg->source_addr.sin.sin_addr, CMSG_DATA(cmsg), sizeof(struct in_addr));
                  msg->has_source_addr = true;
                  break;
                }
#endif
#ifdef IP_PKTINFO
                if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
                  struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
                  msg->source_addr.sin.sin_family = AF_INET;
                  msg->source_addr.sin.sin_addr = pi->ipi_addr;
                  msg->has_source_addr = true;
                  break;
                }
#endif
#ifdef IPV6_PKTINFO
                if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
                  struct in6_pktinfo *pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
                  msg->source_addr.sin6.sin6_family = AF_INET6;
                  msg->source_addr.sin6.sin6_addr = pi6->ipi6_addr;
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
            sendmmsg_skip_failed(g_ipc_fds[router_id][target_worker][0], fctx->ipc_tx_msgs, tx_count,
                                 "Frontend->Backend IPC", true);
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
          ssize_t max_valid_payload = len - (ssize_t)sizeof(udp_ipc_t);
          if (msg->payload_len > max_valid_payload) {
            syslog(LOG_WARNING, "[Frontend %d] Dropping NOTIFY message with inconsistent payload_len (%u > %zd)",
                   router_id, msg->payload_len, max_valid_payload);
            continue;
          }
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
                  struct sockaddr_in *sin2 = &msg->source_addr.sin;
                  if (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr) {
                    target_sock = local_udp_fds[k];
                    target_sock_idx = k;
                    break;
                  }
                } else if (ss.ss_family == AF_INET6) {
                  struct sockaddr_in6 *sin1 = (struct sockaddr_in6 *)&ss;
                  struct sockaddr_in6 *sin2 = &msg->source_addr.sin6;
                  if (memcmp(&sin1->sin6_addr, &sin2->sin6_addr, sizeof(struct in6_addr)) == 0) {
                    target_sock = local_udp_fds[k];
                    target_sock_idx = k;
                    break;
                  }
                }
              }
            }
          }
          if (target_sock < 0 && msg->has_source_addr) {
            for (int k = 0; k < local_num_udp_fds; k++) {
              if (local_udp_is_wildcard[k]) {
                struct sockaddr_storage ss;
                socklen_t slen = sizeof(ss);
                if (getsockname(local_udp_fds[k], (struct sockaddr *)&ss, &slen) == 0 &&
                    ss.ss_family == msg->source_addr.ss_family) {
                  target_sock = local_udp_fds[k];
                  target_sock_idx = k;
                  break;
                }
              }
            }
          }
          if (target_sock < 0 && msg->has_source_addr) {
            int s = socket(msg->source_addr.ss_family, SOCK_DGRAM, 0);
            if (s >= 0) {
              int opt_reuse = 1;
              setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt_reuse, sizeof(opt_reuse));
#ifdef SO_REUSEPORT
              setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt_reuse, sizeof(opt_reuse));
#endif
#ifdef SO_REUSEPORT_LB
              setsockopt(s, SOL_SOCKET, SO_REUSEPORT_LB, &opt_reuse, sizeof(opt_reuse));
#endif
              /* the source address is one the Backend found in the start-up configuration but the Router could not pre-bind (rare): a one-off
               * socket with an ephemeral port.  If even that cannot be bound the NOTIFY is not sent from another address than the operator named. */
              struct sockaddr_storage bind_sa;
              memset(&bind_sa, 0, sizeof(bind_sa));
              socklen_t b_len = 0;
              if (msg->source_addr.ss_family == AF_INET) {
                struct sockaddr_in *b_in = (struct sockaddr_in *)&bind_sa;
                b_in->sin_family = AF_INET;
                b_in->sin_addr = msg->source_addr.sin.sin_addr;
                b_len = sizeof(struct sockaddr_in);
              } else if (msg->source_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *b_in6 = (struct sockaddr_in6 *)&bind_sa;
                b_in6->sin6_family = AF_INET6;
                b_in6->sin6_addr = msg->source_addr.sin6.sin6_addr;
                b_len = sizeof(struct sockaddr_in6);
              }
              if (b_len > 0 && bind(s, (struct sockaddr *)&bind_sa, b_len) < 0) {
                syslog(LOG_WARNING, "[Frontend %d] Cannot bind the NOTIFY source address: %m; NOTIFY not sent", router_id);
                close(s);
                continue;
              }
              sendto(s, buffer + sizeof(udp_ipc_t), msg->payload_len, 0,
                     (struct sockaddr *)&msg->client_addr, msg->addr_len);
              close(s);
              continue;
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
              *src = msg->source_addr.sin.sin_addr;
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
              pi->ipi_spec_dst = msg->source_addr.sin.sin_addr;
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
              pi6->ipi6_addr = msg->source_addr.sin6.sin6_addr;
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
              sendmmsg_skip_failed(local_udp_fds[cur_sock_idx], fctx->cli_tx_msgs, tx_count, "Frontend UDP", false);
              tx_count = 0;
            }
            cur_sock_idx = msg->sock_fd_idx;

            fctx->cli_tx_iov[tx_count].iov_base = fctx->ipc_rx_buffers[k] + sizeof(udp_ipc_t);
            fctx->cli_tx_iov[tx_count].iov_len = msg->payload_len;
            size_t copy_len = (msg->addr_len <= sizeof(fctx->cli_tx_addrs[tx_count])) ? msg->addr_len : sizeof(fctx->cli_tx_addrs[tx_count]);
            memcpy(&fctx->cli_tx_addrs[tx_count], &msg->client_addr, copy_len);
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
              *src = msg->source_addr.sin.sin_addr;
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
              pi->ipi_spec_dst = msg->source_addr.sin.sin_addr;
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
              pi6->ipi6_addr = msg->source_addr.sin6.sin6_addr;
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
            sendmmsg_skip_failed(local_udp_fds[cur_sock_idx], fctx->cli_tx_msgs, tx_count, "Frontend UDP", false);
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

STATIC_TEST pid_t g_supervisor_pid = 0;
STATIC_TEST char g_pid_file_path[1024] = "";
STATIC_TEST int g_pid_fd = -1;
STATIC_TEST volatile sig_atomic_t g_supervisor_should_exit = 0;
STATIC_TEST volatile sig_atomic_t g_supervisor_got_sighup = 0;
STATIC_TEST volatile sig_atomic_t g_supervisor_term_count = 0; /* SIGTERM / SIGINT taken by the handler (not by sigtimedwait) */
#define SHUTDOWN_KILL_MS 10000   /* the manager SIGKILLs the children that ignore SIGTERM for this long */
#define SHUTDOWN_GIVEUP_MS 5000  /* ... and stops waiting for those that do not die from SIGKILL either */

/* X-01: ハンドラはどのスレッドでも動くので、volatile sig_atomic_t ではなくロックフリーの
 * atomic にする (C11 7.14.1.1 はハンドラと割り込まれたコードの間しか定めない)。 */
STATIC_TEST _Atomic int g_backend_should_exit = 0;
/* SIGTERM / SIGINT。起動が終わって制御スレッドがシグナルを受けられるようになった後は、
 * 制御スレッドが dnstap に STOP を送ってから終了する (O-03) ので、ここでは何もしない。
 * 起動中と、2回目のシグナル (終了処理が止まっている場合) はすぐに終了する。 */
STATIC_TEST void backend_sig_handler(int sig) {
  (void)sig;
  int already = atomic_exchange_explicit(&g_backend_should_exit, 1, memory_order_acq_rel);
  if (!already &&
      atomic_load_explicit(&g_privilege_drop_complete, memory_order_acquire) &&
      atomic_load_explicit(&g_control_signals_ready, memory_order_acquire)) {
    return;
  }
  backend_profile_flush();
  _exit(0);
}

/* P5: バックエンドの SIGHUP。保留させるためだけのハンドラ (sighup_from_manager())。SIG_IGN だと届いた時点で捨てられて
 * 送信元が取り出せず、SIG_DFL だとブロックしていないスレッドに届いたときにプロセスが終わる。全スレッドがブロックして
 * いる間は実行されない (保留のまま sigtimedwait() が取り出す) ので、単体テストが直接呼び、実際に配って確かめる。 */
STATIC_TEST void backend_sighup_noop(int sig) {
  (void)sig;
}

/* Backend の通常の終了 (SIGTERM、karictl stop、Supervisor の終了)。dnstap のリングを
 * 送り切って STOP / FINISH を交わしてから _exit() する (O-03、O-15)。複数のスレッドから
 * 同時に呼ばれたら、最初の1つだけが進み、残りはプロセスの終了を待つ。 */
static _Atomic bool g_backend_shutting_down = false;
__attribute__((noreturn)) void backend_shutdown(int code) {
  if (atomic_exchange_explicit(&g_backend_shutting_down, true, memory_order_acq_rel)) {
    for (;;)
      sleep(1);
  }
  syslog(LOG_NOTICE, "[Backend] Shutting down");
  dnstap_shutdown(DNSTAP_SHUTDOWN_WAIT_MS);
  backend_exit(code);
}

STATIC_TEST void supervisor_sig_handler(int sig) {
  if (sig == SIGHUP) {
    g_supervisor_got_sighup = 1;
  } else {
    g_supervisor_should_exit = 1;
    g_supervisor_term_count++;
  }
}

/* SIGCHLD only has to stay pending for the supervisor's sigtimedwait(); the children are collected with waitpid() */
STATIC_TEST void supervisor_sigchld_handler(int sig) {
  (void)sig;
}

STATIC_TEST void cleanup_pid_file(void) {
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

STATIC_TEST void daemonize(void) {
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
  /* No chdir("/") here (BIND's named_os_daemonize() does not either): the daemon keeps the directory it was started in, or options
   * { directory } (main() chdir()s there once), so that a relative UNIX socket path (control-channel, dnstap) means the same after this
   * point as before it.  A pid file and the other files are opened through absolute names or the directory fd cache anyway.  The cost is
   * the one BIND has: that directory's file system stays busy, and a core dump is written there. */
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

STATIC_TEST void setup_ipc_tables(int num_workers) {
  g_num_workers = num_workers;
  server_config_t *cfg = &g_config_db.config_a;
  int rcvbuf_size = (cfg && cfg->udp_recvbuf_size > 0) ? cfg->udp_recvbuf_size : 4 * 1024 * 1024;
  int sndbuf_size = (cfg && cfg->udp_sndbuf_size > 0) ? cfg->udp_sndbuf_size : 4 * 1024 * 1024;

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
      setsockopt(g_ipc_fds[f][w][0], SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
      setsockopt(g_ipc_fds[f][w][0], SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size));
      setsockopt(g_ipc_fds[f][w][1], SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));
      setsockopt(g_ipc_fds[f][w][1], SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size));
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

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_notify_resp_ipc) < 0) {
    syslog(LOG_CRIT, "[IPC] Failed to create NOTIFY response socketpair: %m");
    exit(1);
  }
  fcntl(g_notify_resp_ipc[0], F_SETFL, fcntl(g_notify_resp_ipc[0], F_GETFL, 0) | O_NONBLOCK);
  fcntl(g_notify_resp_ipc[1], F_SETFL, fcntl(g_notify_resp_ipc[1], F_GETFL, 0) | O_NONBLOCK);
  cap_rights_limit(g_notify_resp_ipc[0], &n_rights_0);
  cap_rights_limit(g_notify_resp_ipc[1], &n_rights_1);
}

/* 非root起動時に、path (pid file / 制御ソケット) を作成できるかを
 * daemonize() 前に検査する。root起動時は ensure_priv_dir_safe() が
 * ディレクトリを用意するため対象外。daemonize() は cwd を変えないので、
 * 相対パスもデーモン起動時を含め、実際に使われるときと同じ cwd (起動ディレクトリ、
 * または options { directory }) で検査する。
 * check_existing: 既存ファイルを上書きオープンする場合 (pid file) は
 * ファイル自体の書き込み権も検査する。 */
STATIC_TEST bool preflight_writable_path(const char *path, const char *what, bool foreground,
                                         bool check_existing, const char *hint) {
  (void)foreground;
  if (!path || path[0] == '\0' || strcmp(path, "none") == 0 || geteuid() == 0)
    return true;

  char dir[PATH_MAX];
  if (strlen(path) >= sizeof(dir))
    return true; /* 長すぎるパスは後段の実処理がエラーにする */
  strcpy(dir, path);
  char *slash = strrchr(dir, '/');
  if (!slash)
    strcpy(dir, ".");
  else if (slash == dir)
    dir[1] = '\0';
  else
    *slash = '\0';

  const char *problem = NULL;
  int err = 0;
  if (access(dir, W_OK | X_OK) != 0) {
    err = errno;
    problem = dir;
  } else if (check_existing && access(path, F_OK) == 0 && access(path, W_OK) != 0) {
    err = errno;
    problem = path;
  }
  if (!problem)
    return true;
  syslog(LOG_ERR, "[Startup] Cannot create %s '%s': '%s' is not writable by uid %u (%s). %s",
         what, path, problem, (unsigned)geteuid(), strerror(err), hint);
  fprintf(stderr, "[ERROR] Cannot create %s '%s': '%s' is not writable by uid %u (%s). %s\n",
          what, path, problem, (unsigned)geteuid(), strerror(err), hint);
  return false;
}

/* A UNIX socket path (control-channel, dnstap) must fit sun_path.  Checked before daemonize() so that the message reaches the terminal
 * (the later bind() / connect() would cut the name or fail with ENAMETOOLONG after stderr is gone).  The name is used as written: a relative
 * one resolves against the working directory, which is options { directory } when that is set (main() chdir()s there). */
STATIC_TEST bool check_unix_socket_path(const char *path, const char *what) {
  struct sockaddr_un un;
  if (!path || strlen(path) < sizeof(un.sun_path))
    return true;
  syslog(LOG_ERR, "[Config] Refusing to start: the %s '%.40s...' is %zu bytes long; a UNIX socket path holds at most %zu bytes (sun_path). "
         "Use a shorter name: a relative one is resolved against options { directory } or the directory karidns was started in.",
         what, path, strlen(path), sizeof(un.sun_path) - 1);
  fprintf(stderr, "[ERROR] Refusing to start: the %s '%.40s...' is %zu bytes long; a UNIX socket path holds at most %zu bytes (sun_path). "
          "Use a shorter name: a relative one is resolved against options { directory } or the directory karidns was started in.\n",
          what, path, strlen(path), sizeof(un.sun_path) - 1);
  return false;
}

/* 非root起動時、type "program" ゾーンの program-user (未指定なら options.user を
 * 継承) が実行ユーザーと異なると、プラグイン子プロセスは setuid できず
 * 応答不能のまま動き続けてしまう。起動前に検出して起動を中止する。 */
STATIC_TEST bool validate_program_zone_users(server_config_t *cfg) {
  if (!cfg)
    return true;
  for (view_config_t *v = cfg->views; v; v = v->next) {
    for (zone_config_t *z = v->zones; z; z = z->next) {
      if (!z->type || strcasecmp(z->type, "program") != 0 || !zext(z)->program_user)
        continue;
      uid_t puid;
      gid_t pgid;
      bool found = lookup_user_ids(zext(z)->program_user, &puid, &pgid);
      /* P4: a program-user that is root by another name (uid 0, or the root group as its primary group) is refused,
       * as a start as root with no program-user is not run either (spawn_one_program_plugin()) */
      char id_err[256];
      if (identity_names_root(zext(z)->program_user, NULL, id_err, sizeof(id_err))) {
        syslog(LOG_ERR, "[Config] Refusing: zone '%s': program-user: %s", z->domain, id_err);
        fprintf(stderr, "[ERROR] Refusing: zone '%s': program-user: %s\n", z->domain, id_err);
        return false;
      }
      if (geteuid() == 0)
        continue;
      if (found && puid == geteuid() && puid == getuid())
        continue;
      syslog(LOG_ERR, "[Config] Refusing to start: zone '%s': program-user '%s' %s; a non-root "
                      "process (uid %u) cannot switch to another user. Start karidns as root, or "
                      "set program-user to the user karidns runs as.",
             z->domain, zext(z)->program_user, found ? "differs from the running user" : "not found",
             (unsigned)geteuid());
      fprintf(stderr, "[ERROR] Refusing to start: zone '%s': program-user '%s' %s; a non-root "
                      "process (uid %u) cannot switch to another user. Start karidns as root, or "
                      "set program-user to the user karidns runs as.\n",
              z->domain, zext(z)->program_user, found ? "differs from the running user" : "not found",
              (unsigned)geteuid());
      return false;
    }
  }
  return true;
}

/* 待受アドレス/ポートへ UDP・TCP を実際に bind できるかを daemonize() 前に
 * 試す。ソケットオプションは open_router_udp_sockets() / worker_thread_func()
 * の実処理と揃え、結果が食い違わないようにする。確認後は即 close する
 * (実際の待受ソケットは Frontend / Backend 子プロセスが開く)。 */
STATIC_TEST bool preflight_listen_ports(server_config_t *cfg) {
  int opt = 1;

  for (int i = 0; i < cfg->listen_count; i++) {
    const listen_addr_t *la = &cfg->listen[i];
    struct sockaddr_storage addr;
    socklen_t addr_len = listen_addr_sockaddr(la, &addr);
    int family = la->family;
    for (int t = 0; t < 2; t++) {
      int type = (t == 0) ? SOCK_DGRAM : SOCK_STREAM;
      int fd = socket(family, type, 0);
      if (fd < 0)
        continue; /* 実処理と同じく、未対応のアドレスファミリは対象外 */
      if (type == SOCK_STREAM)
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
      if (family == AF_INET6)
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
#ifdef SO_REUSEPORT_LB
      if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt)) < 0)
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#else
      setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
      if (bind(fd, (struct sockaddr *)&addr, addr_len) != 0) {
        int err = errno;
        close(fd);
        const char *proto = (type == SOCK_DGRAM) ? "UDP" : "TCP";
        syslog(LOG_ERR, "[Startup] Refusing to start: cannot bind %s port %d on %s: %s%s",
               proto, (int)la->port, la->text, strerror(err), bind_error_hint(err, la->port));
        fprintf(stderr, "[ERROR] Refusing to start: cannot bind %s port %d on %s: %s%s\n",
                proto, (int)la->port, la->text, strerror(err), bind_error_hint(err, la->port));
        return false;
      }
      close(fd);
    }
  }
  /* a configuration that selects no address (listen-on { none; } and the like) would start a server that answers nobody */
  if (cfg->listen_count == 0) {
    syslog(LOG_ERR, "[Startup] Refusing to start: listen-on, listen-on-v6 and bind-address select no address to listen on");
    fprintf(stderr, "[ERROR] Refusing to start: listen-on, listen-on-v6 and bind-address select no address to listen on\n");
    return false;
  }
  return true;
}

/* notify-source / transfer-source (and their -v6 forms) and the `source` of primaries / also-notify lists: BIND refuses to start a
 * server whose source address it cannot bind.  Every distinct address of the configuration (server_config_t.xfr_sources, with the
 * place where it is written) is bound once, UDP for a NOTIFY source and TCP for a transfer source, with port 0, and closed again;
 * the sockets that are used are made later by the Router (NOTIFY) and the connect broker (transfers). */
STATIC_TEST bool preflight_xfr_sources(server_config_t *cfg) {
  for (int i = 0; i < cfg->xfr_source_count; i++) {
    const xfr_source_t *s = &cfg->xfr_sources[i];
    for (int t = 0; t < 2; t++) {
      if (t == 0 ? !s->notify : !s->xfer) continue;
      int fd = socket(s->family, t == 0 ? SOCK_DGRAM : SOCK_STREAM, 0);
      if (fd < 0) continue;
      struct sockaddr_storage ss;
      memset(&ss, 0, sizeof(ss));
      socklen_t sl;
      if (s->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, s->addr, sizeof(sin->sin_addr));
        sl = sizeof(*sin);
      } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, s->addr, sizeof(sin6->sin6_addr));
        sl = sizeof(*sin6);
      }
      if (bind(fd, (struct sockaddr *)&ss, sl) != 0) {
        int err = errno;
        close(fd);
        syslog(LOG_ERR, "[Startup] Refusing to start: %s: %s %s: cannot use it as a source address: %s", s->loc[0] ? s->loc : "configuration",
               s->what, s->text, strerror(err));
        fprintf(stderr, "[ERROR] Refusing to start: %s: %s %s: cannot use it as a source address: %s\n", s->loc[0] ? s->loc : "configuration",
                s->what, s->text, strerror(err));
        return false;
      }
      close(fd);
    }
  }
  return true;
}

/* [SEC] pidfile / control-socket 用ディレクトリの安全性検証。
 *
 * mkdir(dir_buf, 0755) 自体はシンボリックリンクを追跡しないため作成時の
 * 攻撃は受けないが、そのディレクトリが「既に存在していた」場合(mkdirが
 * EEXISTで返る場合)には何も検証していなかった。root権限で起動する前に、
 * 非rootユーザーがコンテナの共有ボリューム等を通じてそのパスへ罠の
 * ディレクトリ(自ユーザー所有・group/other書き込み可)を事前に用意して
 * いても、そのまま使ってしまう。
 *
 * ここではO_NOFOLLOW付きでディレクトリ自体をオープンし、そのfdに対して
 * fstat()することでシンボリックリンク追跡やTOCTOUなしに実体を検査する。
 * root所有でなく、group/otherに書き込み可能な場合は「事前に仕込まれた
 * ディレクトリ」の可能性があるため、起動をfail-closedで拒否する。
 * geteuid()!=0(非root実行)の場合は特権境界を跨がないため検証しない。 */
bool ensure_priv_dir_safe(const char *dir_buf) {
  if (!dir_buf || dir_buf[0] == '\0')
    return true;
  if (geteuid() != 0)
    return true; /* 非root実行では特権昇格の懸念がないため検証不要 */

  if (mkdir(dir_buf, 0755) != 0 && errno != EEXIST) {
    /* 作成失敗時は後続のopen()/bind()が本来のエラーを報告するので
     * ここではブロックしない。 */
    return true;
  }

  int dfd = open(dir_buf, O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_RDONLY);
  if (dfd < 0) {
    syslog(LOG_ERR, "[Startup] Failed to verify directory '%s': %s", dir_buf, strerror(errno));
    fprintf(stderr, "[ERROR] Failed to verify directory '%s': %s\n", dir_buf, strerror(errno));
    return false;
  }
  struct stat st;
  bool ok = (fstat(dfd, &st) == 0) && S_ISDIR(st.st_mode) &&
            st.st_uid == 0 && !(st.st_mode & (S_IWGRP | S_IWOTH));
  close(dfd);
  if (!ok) {
    syslog(LOG_ERR, "[Startup] Refusing to use directory '%s': not root-owned and non-writable by "
                     "group/other (possible pre-planted directory attack)", dir_buf);
    fprintf(stderr, "[ERROR] Refusing to use directory '%s': not root-owned and non-writable by "
                     "group/other (possible pre-planted directory attack)\n", dir_buf);
  }
  return ok;
}

#ifndef KARIDNS_UNIT_TEST
int main(int argc, char **argv) {
  assert(calc_fnv1a_str("*.") == FNV1A_WILDCARD_PREFIX_HASH);
  init_server_cookie_secret();
  // SipHash-2-4 self-test against official reference test vector
  // Key: 00010203...0f, Message: 000102...0e (15 bytes)
  // Expected output: 0xa129ca6149be45e5
  {
    static const uint64_t tv_key[2] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};
    uint8_t tv_msg[15];
    for (int i = 0; i < 15; i++) tv_msg[i] = (uint8_t)i;
    uint64_t tv_result = siphash24(tv_msg, sizeof(tv_msg), tv_key);
    if (tv_result != 0xa129ca6149be45e5ULL) {
      /* LCOV_EXCL_START */
      syslog(LOG_CRIT, "FATAL: SipHash-2-4 self-test failed (got %016llx, expected a129ca6149be45e5)",
             (unsigned long long)tv_result);
      abort();
      /* LCOV_EXCL_STOP */
    }
  }
  tzset();
  g_boot_time = time(NULL);
  g_last_configured_time = g_boot_time;
  capture_host_status_info();

  // Force OpenSSL lazy initialization before entering Capsicum sandbox.
  // NOTE: RFC 9018 Server Cookie は SipHash-2-4 (OpenSSL非依存) になったため、従来のように
  // generate_server_cookie() を呼んでもOpenSSLは初期化されない。かつてはその内部の
  // HMAC(EVP_sha256) が副作用として初期化を済ませていたが、それに依存してはならない。
  // 初期化を怠ると、cap_enter() 後の最初のHMAC (TSIG検証/署名, karictl制御チャネルのAUTH) が
  // openssl.cnf を open() しようとして ECAPMODE -> SIGTRAP となりbackendが死ぬ。
  // 明示的に全TSIGアルゴリズムのHMACを事前実行する。
  const bool crypto_prewarm_ok = tsig_prewarm_crypto();  // 警告はopenlog()後に出す
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
          int port = 0;
          int kind = parse_cli_port_arg(val, &port);
          if (kind == 1) {
              g_cli_port_override = port;
              config_set_port_override(port);   /* the parse computes the listen addresses with it, and a reload keeps it */
          } else if (kind < 0) {
              fprintf(stderr, "[ERROR] Invalid port '%s' for -p (expected 1-65535)\n", val);
              return 2;
          } else {
              // 互換のため PID ファイル指定も受け付けるが、-P を案内する
              fprintf(stderr, "[WARNING] '-p %s' is taken as a PID file path; use -P <pid_file> for PID files "
                              "(-p <number> sets the port)\n", val);
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
    return 2;
  }
  if (!getcwd(g_startup_cwd, sizeof(g_startup_cwd))) {
    g_startup_cwd[0] = '\0';
  }
  /* the parser makes the paths that the loader child (started from "/") and the pid file use absolute against this directory (or options { directory }) */
  config_set_base_cwd(g_startup_cwd[0] == '/' ? g_startup_cwd : NULL);
  signal(SIGPIPE, SIG_IGN);
  /* SIGHUP/SIGUSR1/SIGUSR2 の既定動作はプロセス終了。fork する全子プロセス (ブローカー・
   * フロントエンドルーター・バックエンド) のために fork 前に無視にしておく。pkill -HUP karidns の
   * ように全プロセスへ届いても、マネージャーが「子が signal 1 で死んだ」として全体を止めない。
   * リロードを行うマネージャーは後で SIGHUP のハンドラを設定し、バックエンドは kqueue の
   * EVFILT_SIGNAL (無視・ブロックされていても通知される) で受ける。 */
  signal(SIGHUP, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
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
  if (!crypto_prewarm_ok) {
    syslog(LOG_WARNING, "[Startup] OpenSSL HMAC pre-warm incomplete: some TSIG algorithms are unavailable in this OpenSSL build (e.g. FIPS mode)");
  }

  /* localhost / localnets in address match lists (BIND 9.20 ARM acl): the interfaces of this host, once, here.  The Backend
   * inherits the table through fork() and cannot ask again in capability mode; a reload keeps it (docs/karidns.md "localhost and
   * localnets"). */
  aml_init_interfaces();

  char *config_str = read_entire_file(g_config_path, NULL, NULL);
  if (!config_str)
    return 1;
  if (parse_named_conf_ext(config_str, g_config_path, &g_config_db.config_a) != 0) {
    free(config_str);
    return 1;
  }
  free(config_str);
  /* options { directory }: opened once, here, before any sandbox; a reload keeps using it (config_pin_directory) and reports a changed
   * value as needing a restart.  Its sub-directories (zone files below it, $INCLUDE files) are reached through this fd afterwards. */
  config_pin_directory(g_config_db.config_a.directory);
  if (g_config_db.config_a.directory && !dir_fd_cache_add_root(g_config_db.config_a.directory)) {
    syslog(LOG_ERR, "[Config] Refusing to start: options { directory \"%s\"; } cannot be opened: %s", g_config_db.config_a.directory,
           strerror(errno));
    fprintf(stderr, "[ERROR] Refusing to start: options { directory \"%s\"; } cannot be opened: %s\n", g_config_db.config_a.directory,
            strerror(errno));
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }
  /* BIND changes into the directory as soon as it has read the statement (directory_callback in bin/named/server.c).  Done once here, before
   * the start-up checks and daemonize() (which no longer leaves the directory): a relative control-channel or dnstap socket path is then
   * looked for in the same place by the pre-flight check, bind() and connect().  A reload never changes directory. */
  if (g_config_db.config_a.directory && chdir(g_config_db.config_a.directory) != 0) {
    syslog(LOG_ERR, "[Config] Refusing to start: cannot change to options { directory \"%s\"; }: %s", g_config_db.config_a.directory,
           strerror(errno));
    fprintf(stderr, "[ERROR] Refusing to start: cannot change to options { directory \"%s\"; }: %s\n", g_config_db.config_a.directory,
            strerror(errno));
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }
  g_config_db.config_a.generation = 1;
  /* 共有の応答キャッシュ: 起動時に 1 回だけ確保する (大きさの変更は再起動で反映) */
  if (g_config_db.config_a.response_cache_size > 0 &&
      response_cache_init(g_config_db.config_a.response_cache_size) == 0)
    syslog(LOG_WARNING, "[Startup] response-cache-size %zu is too small or could not be allocated; response cache disabled",
           g_config_db.config_a.response_cache_size);

  if (g_cli_port_override > 0) {
    g_config_db.config_a.port = g_cli_port_override;
  }

  const char *effective_pid_file = NULL;
  if (cli_pid_file) {
    effective_pid_file = cli_pid_file;
  } else if (g_config_db.config_a.pid_file) {
    effective_pid_file = g_config_db.config_a.pid_file;
  } else if (!foreground) {
    effective_pid_file = "/var/run/karidns/karidns.pid";
  }
  /* A relative pid file name from -P / -p is made absolute against the startup directory here, like the one from the configuration
   * (config_set_base_cwd): with options { directory } the process is in that directory by now, and -P is relative to where the command
   * was typed.  A name that does not fit g_pid_file_path is an error, never a truncated path. */
  char cli_pid_abs[sizeof(g_pid_file_path)];
  if (effective_pid_file && effective_pid_file == cli_pid_file && effective_pid_file[0] != '/' &&
      strcmp(effective_pid_file, "none") != 0 && effective_pid_file[0] != '\0' && g_startup_cwd[0] == '/') {
    int pn = snprintf(cli_pid_abs, sizeof(cli_pid_abs), "%s/%s", g_startup_cwd, effective_pid_file);
    if (pn < 0 || (size_t)pn >= sizeof(cli_pid_abs)) {
      syslog(LOG_ERR, "[Config] Refusing to start: the PID file '%.64s' is %d bytes long once it is made absolute against the directory "
             "karidns was started in (at most %zu); use a shorter path or an absolute one", effective_pid_file, pn, sizeof(cli_pid_abs) - 1);
      fprintf(stderr, "[ERROR] Refusing to start: the PID file '%.64s' is %d bytes long once it is made absolute against the directory "
              "karidns was started in (at most %zu); use a shorter path or an absolute one\n", effective_pid_file, pn, sizeof(cli_pid_abs) - 1);
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
    effective_pid_file = cli_pid_abs;
  }
  if (effective_pid_file && strlen(effective_pid_file) >= sizeof(g_pid_file_path)) {
    syslog(LOG_ERR, "[Config] Refusing to start: the PID file path is %zu bytes long (at most %zu)", strlen(effective_pid_file),
           sizeof(g_pid_file_path) - 1);
    fprintf(stderr, "[ERROR] Refusing to start: the PID file path is %zu bytes long (at most %zu)\n", strlen(effective_pid_file),
            sizeof(g_pid_file_path) - 1);
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }

  // ---- 起動前検証 ----------------------------------------------------------
  // 失敗を端末(stderr)と終了コードで確実に返せるよう、daemonize() より前に行う。
  // (daemonize() 後は親プロセスが即 exit(0) し、stderr も /dev/null になるため)

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
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }

  // user/group がこのプロセスで適用可能か (非root起動なら実行ユーザー自身か)。
  // O-18: 解決はここ (スレッドを作る前) の1回だけで、以後の降格 (frontend / backend /
  // broker) とログ・制御ソケットの所有者の引き渡しは g_run_identity を使う。
  {
    char id_err[512];
    if (!resolve_run_identity(g_config_db.config_a.user, g_config_db.config_a.group,
                              &g_run_identity, id_err, sizeof(id_err))) {
      syslog(LOG_ERR, "[Config] Refusing to start: %s", id_err);
      fprintf(stderr, "[ERROR] Refusing to start: %s\n", id_err);
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
  }
  if (!validate_program_zone_users(&g_config_db.config_a) ||
      (g_config_db.config_a.control.enabled &&
       !check_unix_socket_path(g_config_db.config_a.control.socket_path ? g_config_db.config_a.control.socket_path :
                                   "/var/run/karidns/control.sock", "control-channel socket path")) ||
      (g_config_db.config_a.dnstap.enabled &&
       !check_unix_socket_path(g_config_db.config_a.dnstap.socket_path, "dnstap socket path")) ||
      !preflight_writable_path(effective_pid_file, "pid file", foreground, true,
                               "Use -P <path> or options { pid-file \"<path>\"; } to point it at a "
                               "directory you can write to, or pid-file \"none\".") ||
      (g_config_db.config_a.control.enabled &&
       !preflight_writable_path(g_config_db.config_a.control.socket_path ?
                                    g_config_db.config_a.control.socket_path :
                                    "/var/run/karidns/control.sock",
                                "control socket", foreground, false,
                                "Set control-channel { socket \"<path>\"; } to a path in a directory you "
                                "can write to, or disable the control channel."))) {
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }

  // beta design 1.2: loader-user / loader-group and loader-path are checked once, here, where stderr still
  // reaches the terminal.  Without a database block dbsup.enabled is false and nothing below touches it.
  db_sup_t dbsup;
  {
    char db_err[512];
    if (!db_sup_init(&dbsup, &g_config_db.config_a, db_err, sizeof(db_err))) {
      syslog(LOG_ERR, "[Config] Refusing to start: %s", db_err);
      fprintf(stderr, "[ERROR] Refusing to start: %s\n", db_err);
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
  }

  // ログファイルを開く (開けなければ起動しない)。fd は daemonize() 後も引き継がれる。
  // 実行ユーザーへの所有者の引き渡しは pid file / 制御ソケットのディレクトリ検証の
  // 後 (hand_off_logging_channels) に行う。
  // From here on the messages of the server follow the logging statement (categories and channels, dns_log.c).
  {
    logrt_status_t log_status;
    log_runtime_t *start_rt = log_runtime_build(&g_config_db.config_a.logging, false, &log_status);
    if (!start_rt || !log_runtime_install(start_rt)) {
      if (start_rt) log_runtime_free(start_rt);
      syslog(LOG_ERR, "[Startup] Refusing to start: one or more log files could not be opened.");
      fprintf(stderr, "[ERROR] Refusing to start: one or more log files could not be opened.\n");
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
  }

  // 待受ポートを実際に bind できるか確認する (実際の bind は子プロセスで行う)。
  if (!preflight_listen_ports(&g_config_db.config_a)) {
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }
  // notify-source / transfer-source / primaries の source: ここで bind できなければ起動しない (file:line 付き)。
  // 起動時の集合は子プロセス (Router、connect broker、Backend) が fork で引き継ぐ。リロードで増えた送信元は再起動まで使えない。
  if (!preflight_xfr_sources(&g_config_db.config_a)) {
    free_server_config_fields(&g_config_db.config_a);
    return 1;
  }
  config_set_startup_xfr_sources(&g_config_db.config_a);
  // ---------------------------------------------------------------------------

  if (!foreground) {
    daemonize();
  }
  start_connect_broker();

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGHUP);
  sigprocmask(SIG_BLOCK, &set, NULL);

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
      if (!ensure_priv_dir_safe(dir_buf)) {
        cleanup_pid_file();
        free_server_config_fields(&g_config_db.config_a);
        return 1;
      }
    }
    /* [SEC] O_NOFOLLOW必須: pidfileはroot権限(特権降格前)でO_CREAT|O_RDWR
     * オープンされ、直後にftruncate(0)してPIDを書き込む。もしこのパスの
     * 最終コンポーネントが(攻撃者が書き込み可能な親ディレクトリ経由で
     * 事前に設置された)シンボリックリンクであった場合、O_NOFOLLOWが
     * 無いとリンク先を追跡してオープン・0バイトへtruncate・上書きして
     * しまい、root権限による任意ファイル破壊/上書きプリミティブとなる。
     * O_NOFOLLOWを付与し、シンボリックリンクなら即座にELOOPで失敗させる
     * (fail-closed)。 */
    g_pid_fd = open(effective_pid_file, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (g_pid_fd < 0) {
      if (errno == ELOOP) {
        syslog(LOG_ERR, "Refusing to open pidfile %s: path is a symlink (possible attack)", effective_pid_file);
        fprintf(stderr, "Refusing to open pidfile %s: path is a symlink (possible attack)\n", effective_pid_file);
      }
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

  atomic_init(&g_config_db.active, &g_config_db.config_a);
  {
    char failed_zones[384];
    int nfailed = rebuild_zone_db_from_config_ext(&g_config_db.config_a, false, failed_zones, sizeof(failed_zones));
    if (nfailed > 0)
      syslog(LOG_ERR, "[Startup] %d zone(s) failed to load and answer SERVFAIL until reloaded: %s", nfailed,
             failed_zones);
  }

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
    const char *leaf_name = sock_path;
    int dir_fd = -1;
    if (slash && slash != dir_buf) {
      *slash = '\0';
      leaf_name = strrchr(sock_path, '/') + 1;
      if (!ensure_priv_dir_safe(dir_buf)) {
        cleanup_pid_file();
        free_server_config_fields(&g_config_db.config_a);
        return 1;
      }
      dir_fd = open(dir_buf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else if (slash == dir_buf) {
      leaf_name = sock_path + 1;
      dir_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else {
      dir_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    strncpy(un.sun_path, sock_path, sizeof(un.sun_path) - 1);
    unlink(un.sun_path);
    g_control_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_control_sock >= 0) {
      mode_t old_mask = umask(0177);
      if (bind(g_control_sock, (struct sockaddr *)&un, sizeof(un)) == 0) {
        fcntl(g_control_sock, F_SETFL, fcntl(g_control_sock, F_GETFL, 0) | O_NONBLOCK);
        listen(g_control_sock, 128);
        if (g_run_identity.has_user) {
          /* [SEC] ソケットFDに対する fchown() は FreeBSD で EINVAL となるため、
           * 事前に O_DIRECTORY で開いた安全なディレクトリFD (dir_fd) と
           * AT_SYMLINK_NOFOLLOW を用いて fchownat() を実行し、
           * TOCTOU/シンボリックリンク攻撃を防ぎつつ所有者を変更する。 */
          if (dir_fd >= 0) {
            fchownat(dir_fd, leaf_name, g_run_identity.uid, g_run_identity.gid, AT_SYMLINK_NOFOLLOW);
          }
        }
        if (dir_fd >= 0) {
          close(dir_fd);
          dir_fd = -1;
        }
        fcntl(g_control_sock, F_SETFL, fcntl(g_control_sock, F_GETFL, 0) | O_NONBLOCK);
        cap_rights_t ctrl_rights;
        cap_rights_init(&ctrl_rights, CAP_ACCEPT, CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT, CAP_FCNTL, CAP_RECV, CAP_SEND);
        cap_rights_limit(g_control_sock, &ctrl_rights);
      } else {
        // control-channel 有効時に制御ソケットを bind できなければ起動しない
        int bind_errno = errno;
        const char *hint = (bind_errno == EACCES || bind_errno == EPERM || bind_errno == EROFS ||
                            bind_errno == ENOENT)
            ? " (set control-channel { socket \"<path>\"; } to a path in a directory the user "
              "karidns runs as can write to, or remove the control-channel block)"
            : "";
        syslog(LOG_ERR, "[Startup] Failed to bind control socket '%s': %s%s",
               sock_path, strerror(bind_errno), hint);
        fprintf(stderr, "[ERROR] Failed to bind control socket '%s': %s%s\n",
                sock_path, strerror(bind_errno), hint);
        umask(old_mask);
        close(g_control_sock);
        g_control_sock = -1;
        if (dir_fd >= 0)
          close(dir_fd);
        cleanup_pid_file();
        free_server_config_fields(&g_config_db.config_a);
        return 1;
      }
      umask(old_mask);
    } else {
      int sock_errno = errno;
      syslog(LOG_ERR, "[Startup] Failed to create control socket: %s", strerror(sock_errno));
      fprintf(stderr, "[ERROR] Failed to create control socket: %s\n", strerror(sock_errno));
      if (dir_fd >= 0)
        close(dir_fd);
      cleanup_pid_file();
      free_server_config_fields(&g_config_db.config_a);
      return 1;
    }
  }

  // pid file / 制御ソケットのディレクトリを ensure_priv_dir_safe() で検証し終えた
  // 後で、ログのディレクトリとファイルを実行ユーザーへ引き渡す。先に chown すると、
  // ログと同じディレクトリに置いた pid file 等の検証が「root所有でない」として失敗する。
  hand_off_logging_channels();

  // beta design 1.2 step 2: the loader sockets exist before the Backend is forked
  {
    char db_err[512];
    if (!db_sup_open_pairs(&dbsup, db_err, sizeof(db_err))) {
      syslog(LOG_CRIT, "[Startup] %s", db_err);
      if (g_broker_pid > 0) kill(g_broker_pid, SIGTERM);
      cleanup_pid_file();
      exit(1);
    }
  }

  gc_snapshot_wait_idle(); // GC threads of the startup configuration must be gone: the Backend is forked from one thread
  pid_t backend_pid = fork();
  if (backend_pid < 0) {
    syslog(LOG_CRIT, "fork for backend process failed: %m");
    if (g_broker_pid > 0) kill(g_broker_pid, SIGTERM);
    cleanup_pid_file();
    exit(1);
  }

  if (backend_pid > 0) {
    // === Parent Process (Process Manager / Supervisor) ===
    klog_set_role(KLOG_ROLE_AUX);   // the Backend rolls the log files; this process appends to them by name
    db_sup_after_fork_supervisor(&dbsup); // the Backend's ends of the loader sockets belong to the Backend
    sigset_t unblock_set;
    sigemptyset(&unblock_set);
    sigaddset(&unblock_set, SIGHUP);
    sigprocmask(SIG_UNBLOCK, &unblock_set, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = supervisor_sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* A router must not run the handlers above: they only set a flag, so a SIGTERM that the manager sends while a
     * router is still starting up (before run_frontend_router() resets it) would be lost.  The signals are blocked
     * across the forks; the child resets the dispositions and then unblocks, so a signal that arrived meanwhile
     * stays pending and is delivered with its default action.  The parent unblocks after the last fork. */
    sigset_t fork_block, fork_orig;
    sigemptyset(&fork_block);
    sigaddset(&fork_block, SIGTERM);
    sigaddset(&fork_block, SIGINT);
    sigaddset(&fork_block, SIGHUP);
    sigaddset(&fork_block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &fork_block, &fork_orig);

    pid_t router_pids[MAX_FRONTEND_ROUTERS];
    for (int r = 0; r < g_num_frontend_routers; r++) {
      gc_snapshot_wait_idle();
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
        klog_set_role(KLOG_ROLE_AUX);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_IGN);
        signal(SIGCHLD, SIG_DFL);
        sigprocmask(SIG_SETMASK, &fork_orig, NULL);
        g_pid_file_path[0] = '\0';
        if (g_pid_fd >= 0) {
          close(g_pid_fd);
          g_pid_fd = -1;
        }
        if (g_broker_sock >= 0) {
          close(g_broker_sock);
          g_broker_sock = -1;
        }
        db_sup_close_supervisor_ends(&dbsup);
        run_frontend_router(backend_pid, r);
        exit(0);
      }
      router_pids[r] = rpid;
    }
    sigprocmask(SIG_SETMASK, &fork_orig, NULL);

    // 親プロセス（Manager）はすべての不要なIPCソケット・制御ソケットを確実にクローズ (指示2)
    for (int f = 0; f < g_num_frontend_routers; f++) {
      for (int w = 0; w < num_workers; w++) {
        close(g_ipc_fds[f][w][0]);
        close(g_ipc_fds[f][w][1]);
      }
    }
    close(g_notify_ipc[0]);
    close(g_notify_ipc[1]);
    close(g_notify_resp_ipc[0]);
    close(g_notify_resp_ipc[1]);
    if (g_control_sock >= 0) {
      close(g_control_sock);
      g_control_sock = -1;
    }
    if (g_broker_sock >= 0) {
      close(g_broker_sock);
      g_broker_sock = -1;
    }

    // beta design 1.2 step 4: the loader is started last, when the Backend and the routers exist
    if (dbsup.enabled) db_sup_spawn(&dbsup);
    // The loop keeps SIGCHLD / SIGTERM / SIGINT / SIGHUP blocked and takes them synchronously with sigtimedwait(),
    // so a signal cannot slip in between the checks and the sleep, and no handler runs inside the loop (handlers
    // that run late, as under ThreadSanitizer, left the supervisor deaf to SIGTERM with the earlier ppoll() wait).
    // SIGCHLD gets a handler that does nothing: with its default action (ignore) a blocked SIGCHLD may be discarded
    // instead of staying pending (POSIX leaves it unspecified).
    {
      struct sigaction ca;
      memset(&ca, 0, sizeof(ca));
      ca.sa_handler = supervisor_sigchld_handler;
      sigemptyset(&ca.sa_mask);
      ca.sa_flags = SA_NOCLDSTOP;
      sigaction(SIGCHLD, &ca, NULL);
    }
    sigset_t loop_block, loop_orig;
    sigemptyset(&loop_block);
    sigaddset(&loop_block, SIGCHLD);
    sigaddset(&loop_block, SIGTERM);
    sigaddset(&loop_block, SIGINT);
    sigaddset(&loop_block, SIGHUP);
    sigprocmask(SIG_BLOCK, &loop_block, &loop_orig);

    // 子プロセスの死活監視ループ (いずれかの子プロセスが終了した場合は全子プロセスを停止。
    // ただし karidns-dbloader の終了は致命的ではなく、待ち時間を置いて起動し直す)
    pid_t dead = 0;
    int child_exit_code = 0;
    while (!g_supervisor_should_exit) {
      if (g_supervisor_got_sighup) {
        g_supervisor_got_sighup = 0;
        syslog(LOG_INFO, "[Manager] Received SIGHUP. Forwarding to backend process %d", backend_pid);
        kill(backend_pid, SIGHUP);
      }
      int status;
      pid_t w;
      bool child_died = false;
      while ((w = waitpid(-1, &status, WNOHANG)) > 0) {
        if (db_sup_child_exited(&dbsup, w, status)) continue;
        dead = w;
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
        child_died = true;
        break;
      }
      if (child_died) break;
      if (w < 0 && errno == ECHILD) {
        break;
      }
      db_sup_tick(&dbsup);
      struct timespec nap;
      int nap_ms = db_sup_timeout_ms(&dbsup);
      nap.tv_sec = nap_ms / 1000;
      nap.tv_nsec = (long)(nap_ms % 1000) * 1000000L;
      siginfo_t si;
      int sig = nap_ms >= 0 ? sigtimedwait(&loop_block, &si, &nap) : sigwaitinfo(&loop_block, &si);
      if (sig == SIGHUP)
        g_supervisor_got_sighup = 1;
      else if (sig == SIGTERM || sig == SIGINT)
        g_supervisor_should_exit = 1;
      /* SIGCHLD, a timeout (the loader restart time) or EINTR: the top of the loop collects children and restarts */
    }
    sigprocmask(SIG_SETMASK, &loop_orig, NULL);
    if (g_supervisor_should_exit && dead <= 0) {
      syslog(LOG_INFO, "[Manager] Received termination signal. Shutting down children.");
    }
    /* The children that have not been collected yet (the loader is tracked by dbsup).  A pid that was reaped is never
     * signalled again: it could belong to another process by now. */
    pid_t kids[MAX_FRONTEND_ROUTERS + 2];
    int nkids = 0;
    kids[nkids++] = backend_pid;
    for (int r = 0; r < g_num_frontend_routers; r++) kids[nkids++] = router_pids[r];
    if (g_broker_pid > 0) kids[nkids++] = g_broker_pid;
    for (int k = 0; k < nkids; k++) {
      if (kids[k] == dead) kids[k] = 0;
      else kill(kids[k], SIGTERM);
    }
    db_sup_signal(&dbsup, SIGTERM);
    /* The wait is bounded: a child that does not end on SIGTERM (stuck in a database call, a start-up that missed the
     * signal) is killed after SHUTDOWN_KILL_MS, and at once by a second SIGTERM / SIGINT to the manager.  Those
     * signals are taken by the handler now (the mask was restored above), which counts them. */
    const int shutdown_term_count = g_supervisor_term_count;
    int64_t shutdown_start_ms = 0, kill_sent_ms = 0;
    while (1) {
      int status;
      pid_t w = waitpid(-1, &status, WNOHANG);
      if (w == 0 || (w < 0 && errno == EINTR)) {
        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);
        int64_t now_ms = (int64_t)now_ts.tv_sec * 1000 + now_ts.tv_nsec / 1000000;
        if (shutdown_start_ms == 0) shutdown_start_ms = now_ms;
        if (kill_sent_ms == 0 &&
            (now_ms - shutdown_start_ms >= SHUTDOWN_KILL_MS || g_supervisor_term_count != shutdown_term_count)) {
          kill_sent_ms = now_ms;
          for (int k = 0; k < nkids; k++) {
            if (kids[k] == 0) continue;
            syslog(LOG_WARNING, "[Manager] Child process %d did not stop; killing it", (int)kids[k]);
            kill(kids[k], SIGKILL);
          }
          if (dbsup.enabled && dbsup.pid > 0) {
            syslog(LOG_WARNING, "[Manager] Database loader (pid %d) did not stop; killing it", (int)dbsup.pid);
            db_sup_signal(&dbsup, SIGKILL);
          }
        } else if (kill_sent_ms != 0 && now_ms - kill_sent_ms >= SHUTDOWN_GIVEUP_MS) {
          /* a process that does not die even from SIGKILL (a hung kernel call): do not hold the pid file forever */
          syslog(LOG_CRIT, "[Manager] Child processes did not end after SIGKILL; giving up waiting");
          if (child_exit_code == 0) child_exit_code = 1;
          break;
        }
        usleep(20000);
        continue;
      }
      if (w > 0 && dbsup.enabled && w == dbsup.pid) {
        dbsup.pid = 0; // the loader's own status does not decide the exit code of the server
        continue;
      }
      if (w > 0) {
        for (int k = 0; k < nkids; k++)
          if (kids[k] == w) kids[k] = 0;
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
      break; // ECHILD: everything is collected
    }
    cleanup_pid_file();
    exit(child_exit_code);
  }

  // === Backend Process (backend_pid == 0) ===
  gc_snapshot_detach_only();
  struct sigaction b_sa;
  memset(&b_sa, 0, sizeof(b_sa));
  b_sa.sa_handler = backend_sig_handler;
  sigemptyset(&b_sa.sa_mask);
  b_sa.sa_flags = 0;
  sigaction(SIGTERM, &b_sa, NULL);
  sigaction(SIGINT, &b_sa, NULL);
  /* P5: SIGHUP は fork 前からブロックされている。SIG_IGN のままだと届いた時点で捨てられて
   * sigtimedwait() で送信元を取り出せないので、何もしないハンドラにして保留させる
   * (sighup_from_manager())。ブロックしていないスレッドに配られてもハンドラで消えるだけ */
  struct sigaction hup_sa;
  memset(&hup_sa, 0, sizeof(hup_sa));
  hup_sa.sa_handler = backend_sighup_noop;
  sigemptyset(&hup_sa.sa_mask);
  sigaction(SIGHUP, &hup_sa, NULL);
  g_manager_pid = getppid();

  g_pid_file_path[0] = '\0';
  if (g_pid_fd >= 0) {
    close(g_pid_fd);
    g_pid_fd = -1;
  }
  db_sup_close_supervisor_ends(&dbsup); // the loader sockets: the Backend keeps only its own ends

  // 指示2: Backendプロセス側もFrontend用端点を直ちにclose
  for (int f = 0; f < g_num_frontend_routers; f++) {
    for (int w = 0; w < num_workers; w++) {
      close(g_ipc_fds[f][w][0]); // Frontend側端点をクローズ
    }
  }
  close(g_notify_ipc[0]); // Frontend側端点をクローズ
  // O-15: ここから先はスレッドが動いているので、致命的なエラーは backend_exit() (_exit) で終える
  if (!init_async_io_pool()) {
    fprintf(stderr, "[ERROR] [Backend] Failed to start the async I/O threads; aborting startup\n");
    backend_exit(EXIT_FAILURE);
  }
  if (!tcp_pool_init()) { /* D-04 */
    syslog(LOG_ERR, "[Backend] Cannot allocate the TCP connection pool; aborting startup");
    fprintf(stderr, "[ERROR] [Backend] Cannot allocate the TCP connection pool; aborting startup\n");
    backend_exit(EXIT_FAILURE);
  }
  rrl_init();

  server_config_t *cfg = &g_config_db.config_a;
  uint32_t qlog_buf_size = cfg->query_log_buffer_size;
  if (qlog_buf_size < 1024 || (qlog_buf_size & (qlog_buf_size - 1)) != 0) {
    qlog_buf_size = 32768;
  }

  pthread_t *threads = calloc(num_workers, sizeof(pthread_t));
  worker_ctx_t *ctxs = calloc(num_workers, sizeof(worker_ctx_t));
  if (!threads || !ctxs)
    backend_exit(1);
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
    atomic_init(&ctxs[i].rcu_observed_epoch, RCU_EPOCH_IDLE);
    if (!ctxs[i].qlog_ring.events || !ctxs[i].dnstap_ring.events)
      backend_exit(EXIT_FAILURE);
  }

  atomic_store_explicit(&g_worker_ctxs, ctxs, memory_order_release);
  atomic_store_explicit(&g_worker_count, num_workers, memory_order_release);

  pthread_t control_thread;
  if (pthread_create(&control_thread, NULL, control_thread_func, NULL) != 0)
    backend_exit(1);

  for (int i = 0; i < num_workers; i++) {
    if (pthread_create(&threads[i], NULL, worker_thread_func, &ctxs[i]) != 0)
      backend_exit(EXIT_FAILURE);
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

  // TCPリスニングソケットの bind() に失敗したワーカーがあれば起動を中止する
  // (UDP側の open_router_udp_sockets() と同じく fail-closed)。
  if (atomic_load(&g_tcp_bind_failures) > 0) {
    syslog(LOG_ERR, "[Backend] Failed to bind TCP listening socket(s); aborting startup");
    fprintf(stderr, "[ERROR] [Backend] Failed to bind TCP listening socket(s); aborting startup\n");
    backend_exit(EXIT_FAILURE);
  }
  // X-33: 起動できなかったワーカー (cpuset / kqueue / バッファの確保の失敗) があれば中止する。
  // 以前はそのワーカーが受け持つ IPC を誰も読まないまま稼働していた。
  int failed_workers = atomic_load(&g_worker_start_failures);
  if (failed_workers > 0) {
    syslog(LOG_ERR, "[Backend] %d worker thread(s) failed to start; aborting startup", failed_workers);
    fprintf(stderr, "[ERROR] [Backend] %d worker thread(s) failed to start; aborting startup\n", failed_workers);
    for (int i = 0; i < num_workers; i++) {
      if (atomic_load_explicit(&ctxs[i].startup_failed, memory_order_acquire))
        pthread_join(threads[i], NULL); /* 終わったスレッドを回収する (O-15: _exit の前に) */
    }
    backend_exit(EXIT_FAILURE);
  }

  // 重要: type "program" ゾーンの子プロセスへの権限降格(program-user)は
  // fork元(karidns自身)がまだroot権限を持っている間でなければ成立しない
  // (POSIXでは非root→別の非rootユーザへのsetuid()は許可されない)。
  // そのため、必ずkaridns自身のsetuid/setgid(直後のブロック)より前に
  // プラグインをspawnすること。この順序を変更してはならない。
  spawn_program_zone_plugins(&g_config_db.config_a);

  {
    char id_err[512];
    if (!apply_run_identity_id(&g_run_identity, id_err, sizeof(id_err))) {
      syslog(LOG_ERR, "[Backend] %s", id_err);
      fprintf(stderr, "[ERROR] [Backend] %s\n", id_err);
      backend_exit(EXIT_FAILURE);
    }
  }

  // 重要: この行より後(Capsicumサンドボックス突入後)にワーカースレッド等から
  // 呼ばれるコードで、tzset()が内部的に別のTZ設定を要求する関数
  // (timegm()や、明示的にsetenv("TZ",...)する処理など)を新たに追加しないこと。
  // サンドボックス下でのタイムゾーンDBへの追加アクセスはECAPMODEでクラッシュする。
  // UTC固定の日時変換が必要な場合は、タイムゾーンDBに依存しない純計算
  // (parse_dnssec_time()のような日数計算アルゴリズム)を使うこと。
  tzset();
  pthread_t response_logger_thread;
  if (pthread_create(&response_logger_thread, NULL, response_logger_thread_func, NULL) != 0) backend_exit(1);
  pthread_t query_logger_thread;
  if (pthread_create(&query_logger_thread, NULL, query_logger_thread_func, NULL) != 0) backend_exit(1);

  if (cfg->dnstap.enabled && cfg->dnstap.socket_path) {
    dnstap_set_message_types(cfg->dnstap.log_auth_query, cfg->dnstap.log_auth_response);
    /* O-03: 切れた (または起動時に繋がらなかった) ときはブローカー経由で繋ぎ直す */
    dnstap_enable_reconnect(cfg->dnstap.socket_path);
    /* O-03: Message.query_zone は送信スレッドがゾーン DB から埋める */
    dnstap_set_zone_filler(dnstap_fill_query_zone);
    g_dnstap_sock = dnstap_connect_and_handshake(cfg->dnstap.socket_path, cfg->dnstap.identity, cfg->dnstap.version);
    if (g_dnstap_sock >= 0) {
      atomic_store_explicit(&g_dnstap_connected, true, memory_order_release);
      syslog(LOG_NOTICE, "[dnstap] connected and handshaked to %s", cfg->dnstap.socket_path);
      fprintf(stderr, "[dnstap] connected and handshaked to %s\n", cfg->dnstap.socket_path);
    } else {
      syslog(LOG_WARNING, "[dnstap] failed to connect to %s; retrying in the background", cfg->dnstap.socket_path);
      fprintf(stderr, "[dnstap] failed to connect to %s; retrying in the background\n", cfg->dnstap.socket_path);
      if (cfg->dnstap.require_connect) {
        syslog(LOG_ERR, "[dnstap] require-connect is enabled and connection failed, aborting startup");
        fprintf(stderr, "[dnstap] require-connect is enabled and connection failed, aborting startup\n");
        backend_exit(EXIT_FAILURE);
      }
    }
  }
  pthread_t dnstap_sender_thread;
  if (pthread_create(&dnstap_sender_thread, NULL, dnstap_sender_thread_func, NULL) != 0) {
    syslog(LOG_ERR, "[dnstap] failed to create sender thread");
    backend_exit(1);
  }
  /* 送信スレッドは終了時 (dnstap_shutdown) に自分で戻る。誰も join しない */
  pthread_detach(dnstap_sender_thread);

  // B9a: the thread that resolves the targets of ALIAS records (dns_alias.h).  It resolves through the broker like the forwarders of a
  // type forward zone and does nothing while no zone has an ALIAS record and an alias-resolver.
  if (!alias_start())
    syslog(LOG_ERR, "[Backend] Cannot start the ALIAS resolver thread; ALIAS records are not expanded");

  // beta design 1.3 / 1.5: the db ingest thread.  It limits the rights of the two descriptors the supervisor made
  // (stream, control) and uses only them (read / write / recvmsg / kevent) once the sandbox is on.
  if (cfg->database.enabled && !db_ingest_start(g_db_stream_fd, g_db_ctrl_fd)) {
    syslog(LOG_ERR, "[Backend] Cannot start the database ingest thread; aborting startup");
    fprintf(stderr, "[ERROR] [Backend] Cannot start the database ingest thread; aborting startup\n");
    backend_exit(EXIT_FAILURE);
  }

  enter_capsicum_sandbox(); // サンドボックス突入

  // 特権分離(setuid+Capsicum)が完了したため、各Workerスレッドにクエリ処理の開始を許可する
  atomic_store_explicit(&g_privilege_drop_complete, true, memory_order_release);

  for (int i = 0; i < num_workers; i++)
    pthread_join(threads[i], NULL);
  pthread_join(control_thread, NULL);

  // ワーカーと制御スレッドが通常終わることはない (終了は backend_shutdown() の _exit)。
  // ここへ来るのは全スレッドの kevent() が失敗したときだけ。dnstap の送信スレッドや
  // 非同期 I/O スレッドはまだ動いているので、リングや設定は解放せずに同じ終了処理を通す
  // (以前はここで送信スレッドと並行してリングを読み、解放していた)。
  syslog(LOG_ERR, "[Backend] All worker threads have stopped; shutting down");
  backend_shutdown(EXIT_FAILURE);
}
#endif /* !KARIDNS_UNIT_TEST */
