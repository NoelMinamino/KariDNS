#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/event.h>   // kqueue
#include <sys/time.h>
#include <sys/param.h>   // cpuset
#include <sys/cpuset.h>  // cpuset
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <pwd.h>
#include <grp.h>
#include <poll.h>
#include <limits.h>       // PATH_MAX, NAME_MAX
#include <sys/capsicum.h> // Capsicum capability mode / rights
#include "dns_wire.h"
#include <sys/procctl.h>  // PROC_TRAPCAP (diagnostics for capsicum violations)

// karidns
// Copyright (c) 2026 Noel Minamino
// Lisence: MIT
// All codes are developed by Gemini Pro, Claude Sonnet with Human Idea and test.

// ============================================================================
// 1. 定数・マクロ定義
// ============================================================================
#define DNS_PORT 53
#define MAX_EVENTS 1024
#define BUFFER_SIZE 4096

#define MAX_FIELDS 64

#define IS_SPACE(c) ((c) == ' ' || (c) == '\t')
#define IS_NEWLINE(c) ((c) == '\n' || (c) == '\r')

// ============================================================================
// 2. データ構造定義
// ============================================================================

// Zoneデータメモリプール (アリーナ)
typedef struct zone_arena_s {
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

// RCU (Read-Copy-Update) 管理構造体
typedef struct {
    _Atomic(zone_arena_t *) active;
    zone_arena_t arena_a;
    zone_arena_t arena_b;
} zone_rcu_t;

// ゾーン管理エントリ
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

// TCPストリーム解析ステート
typedef enum {
    TCP_STATE_READ_LEN,
    TCP_STATE_READ_BODY
} tcp_state_t;

typedef struct {
    tcp_state_t state;
    uint8_t buf[65536 + 2];
    size_t accumulated;
    uint16_t msg_len;
    char client_ip[INET6_ADDRSTRLEN];
} tcp_stream_ctx_t;

// AXFR転送セッション状態
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

// ゾーン設定構造体
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
    
    // AXFR ACL
    char **allow_transfer;
    int allow_transfer_count;
    
    struct zone_config *next;
} zone_config_t;

// ロギング設定構造体
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
    int current_date; // YYYYMMDD
    pthread_mutex_t lock;
    struct log_channel *next;
} log_channel_t;

typedef struct {
    log_channel_t *channels;
    char *queries_channel_name;
    log_channel_t *queries_channel;
} logging_config_t;

// サーバー全体設定構造体
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

// トークナイザー用
typedef enum { TOKEN_EOF, TOKEN_STRING, TOKEN_LBRACE, TOKEN_RBRACE, TOKEN_SEMICOLON } token_type_t;
typedef struct { token_type_t type; char *value; } token_t;
typedef struct { const char *src; size_t pos; size_t len; } token_ctx_t;

// スレッドコンテキスト
typedef struct {
    int thread_id;
    int core_id;
    zone_rcu_t *rcu_db;
} worker_ctx_t;


// コンフィグRCU
typedef struct {
    _Atomic(server_config_t *) active;
    server_config_t config_a;
    server_config_t config_b;
} config_rcu_t;


// UDP Response Rate Limiting (RRL)
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
    
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    
    while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire)) { }
    
    uint64_t elapsed_ms = (now_ms > b->last_update) ? (now_ms - b->last_update) : 0;
    if (b->last_update == 0) {
        b->tokens = RRL_BURST;
        b->last_update = now_ms;
    } else {
        uint64_t add_tokens_u64 = (elapsed_ms * RRL_RATE) / 1000;
        int add_tokens = (add_tokens_u64 > RRL_BURST) ? RRL_BURST : (int)add_tokens_u64;
        b->tokens += add_tokens;
        if (b->tokens > RRL_BURST) b->tokens = RRL_BURST;
        if (add_tokens > 0) b->last_update = now_ms;
    }
    
    bool allow = false;
    if (b->tokens > 0) {
        b->tokens--;
        allow = true;
    }
    atomic_flag_clear_explicit(&b->lock, memory_order_release);
    return allow;
}

// グローバルインスタンス
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

// ============================================================================
// Capsicum capability-mode support
//
// Design summary:
//   Every path-based filesystem access in this program (named.conf, zone
//   master files, log files/rotation) is funneled through a small cache of
//   *directory* file descriptors, resolved with openat(2)/renameat(2)
//   relative to those directory fds. Directories are only ever opened while
//   running in "normal" (non-capability) mode, i.e. during startup and
//   during config/zone reload triggered from files that were already known
//   before we entered capability mode. Once cap_enter() has been called
//   (see enter_capsicum_sandbox() in main()), any attempt to resolve a
//   directory that isn't already cached is refused by this code *before*
//   the kernel would refuse it, so we get a clear log message instead of a
//   bare ENOTCAPABLE/EPERM failure buried in the kernel path lookup.
//
//   This also fixes a pre-existing weakness where read_entire_file() opened
//   absolute paths directly with open(2), bypassing any notion of a
//   filesystem boundary. All file opens now go through open_via_dir_cache(),
//   so an attacker who can influence a *value* inside named.conf (but not
//   the file itself) cannot use it to reach arbitrary files outside of the
//   directories that were legitimately referenced at startup.
// ============================================================================

typedef struct dir_fd_entry {
    char *dirpath;
    int fd;
    struct dir_fd_entry *next;
} dir_fd_entry_t;

static dir_fd_entry_t *g_dir_fd_table = NULL;
static pthread_mutex_t g_dir_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool g_capsicum_enabled = false;

// Splits `path` into a directory component (dir_out) and a single final
// path component (base_out). No ".." or embedded '/' can survive in
// base_out by construction; we additionally reject ".." defensively.
// Returns false on any malformed/oversized/suspicious input.
static bool split_path_for_openat(const char *path, char *dir_out, size_t dir_out_sz,
                                   char *base_out, size_t base_out_sz) {
    if (!path || !*path) return false;
    size_t plen = strlen(path);
    if (plen >= PATH_MAX) return false;

    const char *slash = strrchr(path, '/');
    if (!slash) {
        if (strlen(path) >= base_out_sz) return false;
        if (snprintf(dir_out, dir_out_sz, ".") >= (int)dir_out_sz) return false;
        memcpy(base_out, path, plen + 1);
    } else {
        size_t dir_len = (size_t)(slash - path);
        if (dir_len == 0) dir_len = 1; // "/file" -> dir "/"
        if (dir_len >= dir_out_sz) return false;
        memcpy(dir_out, path, dir_len);
        dir_out[dir_len] = '\0';

        const char *base = slash + 1;
        size_t base_len = strlen(base);
        if (base_len == 0 || base_len >= base_out_sz) return false; // trailing '/' - not a file
        memcpy(base_out, base, base_len + 1);
    }
    if (strcmp(base_out, "..") == 0 || strcmp(base_out, ".") == 0) return false;
    if (strstr(base_out, "/") != NULL) return false; // impossible by construction, kept as a hard invariant check
    return true;
}

// Returns a cached, rights-limited directory descriptor for `dirpath`
// (never to be close()'d by the caller). Opens and caches it on first use.
// `writable` selects a rights profile that additionally permits creating,
// writing, truncating, and renaming files within the directory (used for
// log directories); read-only directories (zone/config files) get a
// strictly smaller right set.
//
// Once g_capsicum_enabled is true, only directories already present in the
// cache can be resolved -- opening a *new* directory at that point would
// require escaping the sandbox, so we refuse it outright.
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
        syslog(LOG_ERR, "[Capsicum] Refusing to open new directory '%s' after entering "
                         "capability mode; all zone/log/config directories must be "
                         "reachable at startup time.", dirpath);
        errno = ENOTCAPABLE;
        return -1;
    }

    int fd;
    if (dirpath[0] == '/') {
        fd = open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
    } else {
        fd = (g_cwd_fd >= 0) ? openat(g_cwd_fd, dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY)
                              : open(dirpath, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
    }
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open directory '%s': %s", dirpath, strerror(errno));
        pthread_mutex_unlock(&g_dir_fd_lock);
        return -1;
    }

    cap_rights_t rights;
    if (writable) {
        cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_WRITE, CAP_CREATE,
                         CAP_FSTAT, CAP_FSTATFS, CAP_FTRUNCATE, CAP_SEEK,
                         CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET, CAP_UNLINKAT);
    } else {
        cap_rights_init(&rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT, CAP_FSTATFS, CAP_SEEK);
    }
    if (cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) {
        syslog(LOG_WARNING, "cap_rights_limit failed for directory '%s': %s", dirpath, strerror(errno));
        close(fd);
        pthread_mutex_unlock(&g_dir_fd_lock);
        return -1;
    }

    dir_fd_entry_t *e = calloc(1, sizeof(*e));
    if (!e) { close(fd); pthread_mutex_unlock(&g_dir_fd_lock); return -1; }
    e->dirpath = strdup(dirpath);
    if (!e->dirpath) { free(e); close(fd); pthread_mutex_unlock(&g_dir_fd_lock); return -1; }
    e->fd = fd;
    e->next = g_dir_fd_table;
    g_dir_fd_table = e;
    pthread_mutex_unlock(&g_dir_fd_lock);
    return fd;
}

// Capability-mode-safe replacement for open(2)/openat(2) by arbitrary path.
// `path` may be absolute or relative (relative paths are resolved against
// the original startup working directory, g_cwd_fd, exactly like before).
static int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    char dirbuf[PATH_MAX];
    char basebuf[PATH_MAX];
    if (!split_path_for_openat(path, dirbuf, sizeof(dirbuf), basebuf, sizeof(basebuf))) {
        syslog(LOG_ERR, "Rejecting malformed or unsafe path: %s", path ? path : "(null)");
        errno = EINVAL;
        return -1;
    }
    int dfd = get_or_open_dir_fd(dirbuf, writable);
    if (dfd < 0) return -1;
    return openat(dfd, basebuf, flags, mode);
}

// Capability-mode-safe replacement for rename(2)/truncate(2)-by-path for
// two paths that must live in already-known (registered) directories, e.g.
// log rotation ("queries.log" -> "queries.log.0"). Both directories are
// resolved independently so this also works across differently-spelled
// (but equal) directory strings.
static int renameat_via_dir_cache(const char *old_path, const char *new_path) {
    char odir[PATH_MAX], obase[PATH_MAX];
    char ndir[PATH_MAX], nbase[PATH_MAX];
    if (!split_path_for_openat(old_path, odir, sizeof(odir), obase, sizeof(obase))) return -1;
    if (!split_path_for_openat(new_path, ndir, sizeof(ndir), nbase, sizeof(nbase))) return -1;
    int ofd = get_or_open_dir_fd(odir, true);
    int nfd = get_or_open_dir_fd(ndir, true);
    if (ofd < 0 || nfd < 0) return -1;
    return renameat(ofd, obase, nfd, nbase);
}

// Applies a minimal capability right set to a bound-and-listening (or
// about-to-listen) UDP/TCP server socket. Called right after bind()/listen()
// succeeds, before the socket is ever exposed to untrusted network input.
static void limit_server_socket_rights(int fd, bool is_listening_tcp) {
    cap_rights_t rights;
    if (is_listening_tcp) {
        cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT,
                         CAP_SHUTDOWN, CAP_GETSOCKNAME, CAP_GETPEERNAME);
    } else {
        cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT,
                         CAP_SHUTDOWN, CAP_GETSOCKNAME, CAP_GETPEERNAME);
    }
    if (cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) {
        syslog(LOG_WARNING, "cap_rights_limit failed for server socket fd=%d: %s", fd, strerror(errno));
    }
}

// Applies a minimal capability right set to a freshly-accept()ed TCP client
// socket, or to an AXFR/NOTIFY client socket right after connect(2) returns.
static void limit_client_socket_rights(int fd) {
    cap_rights_t rights;
    cap_rights_init(&rights, CAP_RECV, CAP_SEND, CAP_EVENT, CAP_GETSOCKOPT, CAP_SETSOCKOPT,
                     CAP_SHUTDOWN, CAP_GETSOCKNAME, CAP_GETPEERNAME);
    if (cap_rights_limit(fd, &rights) != 0 && errno != ENOSYS) {
        syslog(LOG_WARNING, "cap_rights_limit failed for client socket fd=%d: %s", fd, strerror(errno));
    }
}

// Enters Capsicum capability mode for the whole process (all threads).
// Must be called only after: (1) all listening sockets are created & bound,
// (2) all files that need to be read/written at startup have been opened at
// least once (so their directories are cached), and (3) privilege drop
// (setuid/setgid) has already happened, since capability mode does not
// itself restrict credential syscalls but we want defense-in-depth ordered
// correctly regardless.
static void enter_capsicum_sandbox(void) {
    // Ask the kernel to deliver SIGTRAP on capability violations during
    // testing/diagnostics; harmless in production (default is to just
    // return ENOTCAPABLE/EPERM to the offending syscall).
    int trapmode = PROC_TRAPCAP_CTL_ENABLE;
    procctl(P_PID, 0, PROC_TRAPCAP_CTL, &trapmode);

    if (cap_enter() != 0) {
        if (errno == ENOSYS) {
            syslog(LOG_WARNING, "[Capsicum] Kernel does not support capability mode; running unsandboxed.");
            return;
        }
        syslog(LOG_ERR, "[Capsicum] cap_enter() failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    atomic_store_explicit(&g_capsicum_enabled, true, memory_order_release);
    syslog(LOG_NOTICE, "[Capsicum] Entered capability mode; process is now sandboxed.");

    if (!cap_sandboxed()) {
        syslog(LOG_WARNING, "[Capsicum] cap_enter() succeeded but cap_sandboxed() reports false.");
    }
}


// ============================================================================

// 3. BIND風コンフィグファイル (named.conf) パーサー

// ============================================================================

static void skip_spaces_and_comments(token_ctx_t *ctx) {

    while (ctx->pos < ctx->len) {

        char c = ctx->src[ctx->pos];

        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {

            ctx->pos++;

        } else if (c == '#') {

            while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '\n') ctx->pos++;

        } else if (c == '/' && ctx->pos + 1 < ctx->len && ctx->src[ctx->pos + 1] == '/') {

            ctx->pos += 2;

            while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '\n') ctx->pos++;

        } else if (c == '/' && ctx->pos + 1 < ctx->len && ctx->src[ctx->pos + 1] == '*') {

            ctx->pos += 2;

            while (ctx->pos + 1 < ctx->len && !(ctx->src[ctx->pos] == '*' && ctx->src[ctx->pos + 1] == '/')) ctx->pos++;

            if (ctx->pos + 1 < ctx->len) ctx->pos += 2;

        } else {

            break;

        }

    }

}



token_t get_next_token(token_ctx_t *ctx) {
    token_t tok = { TOKEN_EOF, NULL };
    skip_spaces_and_comments(ctx);
    if (ctx->pos >= ctx->len) return tok;

    char c = ctx->src[ctx->pos];
    if (c == '{') { tok.type = TOKEN_LBRACE; ctx->pos++; return tok; }
    if (c == '}') { tok.type = TOKEN_RBRACE; ctx->pos++; return tok; }
    if (c == ';') { tok.type = TOKEN_SEMICOLON; ctx->pos++; return tok; }

    if (c == '"') {
        ctx->pos++;
        size_t start = ctx->pos;
        while (ctx->pos < ctx->len && ctx->src[ctx->pos] != '"') ctx->pos++;
        size_t str_len = ctx->pos - start;
        if (str_len > 4096) str_len = 4096; // Cap token length
        tok.type = TOKEN_STRING;
        tok.value = malloc(str_len + 1);
        memcpy(tok.value, &ctx->src[start], str_len);
        tok.value[str_len] = '\0';
        if (ctx->pos < ctx->len && ctx->src[ctx->pos] == '"') ctx->pos++;
        return tok;
    }

    size_t start = ctx->pos;
    while (ctx->pos < ctx->len) {
        char nc = ctx->src[ctx->pos];
        if (nc == ' ' || nc == '\t' || nc == '\n' || nc == '\r' || nc == '{' || nc == '}' || nc == ';' || nc == '#') break;
        if (nc == '/' && ctx->pos + 1 < ctx->len && (ctx->src[ctx->pos + 1] == '/' || ctx->src[ctx->pos + 1] == '*')) break;
        ctx->pos++;
    }
    size_t str_len = ctx->pos - start;
    if (str_len > 4096) str_len = 4096; // Cap token length
    tok.type = TOKEN_STRING;
    tok.value = malloc(str_len + 1);
    memcpy(tok.value, &ctx->src[start], str_len);
    tok.value[str_len] = '\0';
    return tok;
}

void free_token(token_t *tok) { if (tok->value) { free(tok->value); tok->value = NULL; } }

void free_zone_config(zone_config_t *zone) {
    if (!zone) return;
    free(zone->domain); free(zone->type); free(zone->file);
    for (int i = 0; i < zone->masters_count; i++) free(zone->masters[i].ip);
    free(zone->masters); 
    free(zone->tsig_key);
    for (int i = 0; i < zone->also_notify_count; i++) free(zone->also_notify[i].ip);
    free(zone->also_notify);
    free(zone->notify_source);
    for (int i = 0; i < zone->allow_transfer_count; i++) free(zone->allow_transfer[i]);
    free(zone->allow_transfer);
    free(zone);
}

static char *read_entire_file(const char *path) {
    // All reads go through the directory-fd cache (see get_or_open_dir_fd()
    // above) so that: (1) we never issue a raw open() by absolute path at
    // runtime once running in Capsicum capability mode, and (2) the
    // directory boundary implied by "known at startup" is actually
    // enforced, rather than being a no-op as in earlier revisions of this
    // function.
    int fd = open_via_dir_cache(path, O_RDONLY, 0, false);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "rb");
    if (!f) { close(fd); return NULL; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 0 || fsize > 256 * 1024 * 1024) { 
        fclose(f); 
        syslog(LOG_ERR, "File size out of bounds (max 256MB): %s", path);
        return NULL; 
    }
    char *str = malloc(fsize + 1);
    if (!str) { fclose(f); return NULL; }
    if (fread(str, 1, fsize, f) != (size_t)fsize) { free(str); fclose(f); return NULL; }
    str[fsize] = '\0';
    fclose(f);
    return str;
}

static void skip_unknown_block(token_ctx_t *ctx) {
    int brace_level = 0;
    while (1) {
        token_t tok = get_next_token(ctx);
        if (tok.type == TOKEN_EOF) { free_token(&tok); break; }
        if (tok.type == TOKEN_LBRACE) brace_level++;
        else if (tok.type == TOKEN_RBRACE) brace_level--;
        else if (tok.type == TOKEN_SEMICOLON && brace_level <= 0) {
            free_token(&tok);
            break;
        }
        free_token(&tok);
    }
}

static bool match_cidr(const char *client_ip_str, const char *cidr_str) {
    if (strcmp(cidr_str, "any") == 0 || strcmp(cidr_str, "any;") == 0) return true;
    
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
    
    if (inet_pton(AF_INET, client_ip_str, &client_addr_v4) == 1 && inet_pton(AF_INET, cidr_copy, &net_addr_v4) == 1) {
        if (prefix == -1) prefix = 32;
        if (prefix < 0 || prefix > 32) return false;
        uint32_t mask = prefix == 0 ? 0 : (~0U) << (32 - prefix);
        mask = htonl(mask);
        return (client_addr_v4.s_addr & mask) == (net_addr_v4.s_addr & mask);
    } else if (inet_pton(AF_INET6, client_ip_str, &client_addr_v6) == 1 && inet_pton(AF_INET6, cidr_copy, &net_addr_v6) == 1) {
        if (prefix == -1) prefix = 128;
        if (prefix < 0 || prefix > 128) return false;
        
        for (int i = 0; i < 16; i++) {
            int bits = prefix - (i * 8);
            if (bits >= 8) {
                if (client_addr_v6.s6_addr[i] != net_addr_v6.s6_addr[i]) return false;
            } else if (bits > 0) {
                uint8_t mask = (0xFF << (8 - bits)) & 0xFF;
                if ((client_addr_v6.s6_addr[i] & mask) != (net_addr_v6.s6_addr[i] & mask)) return false;
            } else {
                break;
            }
        }
        return true;
    }
    return false;
}

static int parse_string_list(token_ctx_t *ctx, char ***list, int *count, const char *dir_name) {
    token_t tok = get_next_token(ctx);
    if (tok.type != TOKEN_LBRACE) { syslog(LOG_ERR, "[Config Error] Expected '{' for %s", dir_name); free_token(&tok); return -1; }
    free_token(&tok);
    while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
        if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
        *list = realloc(*list, sizeof(char*) * (*count + 1));
        (*list)[*count] = strdup(tok.value);
        (*count)++;
        free_token(&tok);
        tok = get_next_token(ctx);
        if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
        free_token(&tok);
    }
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
    free_token(&tok);
    return 0;
}

static int parse_ip_port_list(token_ctx_t *ctx, ip_port_t **list, int *count, const char *dir_name) {
    token_t tok = get_next_token(ctx);
    if (tok.type != TOKEN_LBRACE) { syslog(LOG_ERR, "[Config Error] Expected '{' for %s", dir_name); free_token(&tok); return -1; }
    free_token(&tok);
    while (1) {
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
        if (tok.type != TOKEN_STRING) { free_token(&tok); return -1; }
        *list = realloc(*list, sizeof(ip_port_t) * (*count + 1));
        (*list)[*count].ip = strdup(tok.value);
        (*list)[*count].port = 53;
        free_token(&tok);
        
        size_t saved_pos = ctx->pos;
        tok = get_next_token(ctx);
        if (tok.type == TOKEN_STRING && strcmp(tok.value, "port") == 0) {
            free_token(&tok);
            tok = get_next_token(ctx);
            if (tok.type == TOKEN_STRING) {
                (*list)[*count].port = atoi(tok.value);
            } else {
                free_token(&tok); return -1;
            }
            free_token(&tok);
            tok = get_next_token(ctx);
        } else {
            // Revert position
            ctx->pos = saved_pos;
            free_token(&tok);
            tok = get_next_token(ctx);
        }
        (*count)++;
        if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
        free_token(&tok);
    }
    tok = get_next_token(ctx);
    if (tok.type != TOKEN_SEMICOLON) { free_token(&tok); return -1; }
    free_token(&tok);
    return 0;
}

int parse_named_conf(const char *config_str, server_config_t *config) {
    token_ctx_t ctx = { config_str, 0, strlen(config_str) };
    config->port = 53; config->bind_addresses = NULL; config->bind_address_count = 0; config->zones = NULL;
    config->user = NULL; config->group = NULL;
    zone_config_t *last_zone = NULL;

    while (1) {
        token_t tok = get_next_token(&ctx);
        if (tok.type == TOKEN_EOF) break;
        if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected top-level directive string"); free_token(&tok); return -1; }

        if (strcmp(tok.value, "options") == 0) {
            free_token(&tok); tok = get_next_token(&ctx);
            if (tok.type != TOKEN_LBRACE) { syslog(LOG_ERR, "[Config Error] Expected '{' after 'options'"); free_token(&tok); return -1; }
            free_token(&tok);
            while (1) {
                tok = get_next_token(&ctx);
                if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
                if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected option key string"); free_token(&tok); return -1; }
                char *key = strdup(tok.value); free_token(&tok);
                
                if (strcmp(key, "port") == 0 || strcmp(key, "user") == 0 || strcmp(key, "group") == 0) {
                    tok = get_next_token(&ctx);
                    if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected value string for option '%s'", key); free(key); free_token(&tok); return -1; }
                    char *val = strdup(tok.value); free_token(&tok);
                    tok = get_next_token(&ctx);
                    if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';' after option '%s' '%s'", key, val); free(key); free(val); free_token(&tok); return -1; }
                    free_token(&tok);

                    if (strcmp(key, "port") == 0) config->port = atoi(val);
                    else if (strcmp(key, "user") == 0) config->user = val;
                    else config->group = val;
                } else if (strcmp(key, "bind-address") == 0) {
                    // Peek ahead to see if it's a list or a single string
                    size_t saved_pos = ctx.pos;
                    tok = get_next_token(&ctx);
                    if (tok.type == TOKEN_LBRACE) {
                        ctx.pos = saved_pos;
                        free_token(&tok);
                        if (parse_string_list(&ctx, &config->bind_addresses, &config->bind_address_count, "bind-address") != 0) { free(key); return -1; }
                    } else if (tok.type == TOKEN_STRING) {
                        config->bind_addresses = realloc(config->bind_addresses, sizeof(char*) * (config->bind_address_count + 1));
                        config->bind_addresses[config->bind_address_count++] = strdup(tok.value);
                        free_token(&tok);
                        tok = get_next_token(&ctx);
                        if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';'"); free(key); free_token(&tok); return -1; }
                        free_token(&tok);
                    } else {
                        syslog(LOG_ERR, "[Config Error] Expected '{' or string for bind-address"); free(key); free_token(&tok); return -1;
                    }
                } else {
                    syslog(LOG_ERR, "[Config Warning] Unknown option '%s', skipping.", key);
                    skip_unknown_block(&ctx);
                }
                free(key);
            }
            tok = get_next_token(&ctx); if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';' after options block"); free_token(&tok); return -1; }
            free_token(&tok);
        } else if (strcmp(tok.value, "zone") == 0) {
            free_token(&tok); tok = get_next_token(&ctx);
            if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected string domain after 'zone'"); free_token(&tok); return -1; }
            zone_config_t *zone = calloc(1, sizeof(zone_config_t));
            zone->domain = strdup(tok.value); free_token(&tok);
            size_t dl = strlen(zone->domain);
            if (dl > 0 && zone->domain[dl - 1] != '.') {
                char *norm = malloc(dl + 2);
                if (norm) {
                    memcpy(norm, zone->domain, dl);
                    norm[dl] = '.'; norm[dl + 1] = '\0';
                    free(zone->domain);
                    zone->domain = norm;
                }
            }
            tok = get_next_token(&ctx); if (tok.type != TOKEN_LBRACE) { syslog(LOG_ERR, "[Config Error] Expected '{' for zone '%s'", zone->domain); free_zone_config(zone); free_token(&tok); return -1; }
            free_token(&tok);
            while (1) {
                tok = get_next_token(&ctx);
                if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
                if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected zone property string in zone '%s'", zone->domain); free_zone_config(zone); free_token(&tok); return -1; }
                char *key = strdup(tok.value); free_token(&tok);

                if (strcmp(key, "masters") == 0) {
                    if (parse_ip_port_list(&ctx, &zone->masters, &zone->masters_count, "masters") != 0) { free(key); free_zone_config(zone); return -1; }
                } else if (strcmp(key, "also-notify") == 0) {
                    if (parse_ip_port_list(&ctx, &zone->also_notify, &zone->also_notify_count, "also-notify") != 0) { free(key); free_zone_config(zone); return -1; }
                } else if (strcmp(key, "allow-transfer") == 0) {
                    if (parse_string_list(&ctx, &zone->allow_transfer, &zone->allow_transfer_count, "allow-transfer") != 0) { free(key); free_zone_config(zone); return -1; }
                } else if (strcmp(key, "type") == 0 || strcmp(key, "file") == 0 || strcmp(key, "tsig-key") == 0 || strcmp(key, "notify-source") == 0) {
                    tok = get_next_token(&ctx);
                    if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected value string for zone property '%s'", key); free(key); free_zone_config(zone); free_token(&tok); return -1; }
                    char *val = strdup(tok.value); free_token(&tok);
                    tok = get_next_token(&ctx); if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';' after zone property '%s'", key); free(key); free(val); free_zone_config(zone); free_token(&tok); return -1; }
                    free_token(&tok);
                    if (strcmp(key, "type") == 0) zone->type = val;
                    else if (strcmp(key, "file") == 0) zone->file = val;
                    else if (strcmp(key, "tsig-key") == 0) zone->tsig_key = val;
                    else zone->notify_source = val;
                } else {
                    syslog(LOG_ERR, "[Config Warning] Unknown zone property '%s', skipping.", key);
                    skip_unknown_block(&ctx);
                }
                free(key);
            }
            tok = get_next_token(&ctx); if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';' after zone '%s' block", zone->domain); free_zone_config(zone); free_token(&tok); return -1; }
            free_token(&tok);
            if (!config->zones) config->zones = zone; else last_zone->next = zone;
            last_zone = zone;
        } else if (strcmp(tok.value, "key") == 0) {
            free_token(&tok); tok = get_next_token(&ctx);
            if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected key name after 'key'"); free_token(&tok); return -1; }
            tsig_key_t *tsig = calloc(1, sizeof(tsig_key_t));
            tsig->name = strdup(tok.value); free_token(&tok);
            tok = get_next_token(&ctx); if (tok.type != TOKEN_LBRACE) { syslog(LOG_ERR, "[Config Error] Expected '{' for key '%s'", tsig->name); free_token(&tok); return -1; }
            free_token(&tok);
            while (1) {
                tok = get_next_token(&ctx);
                if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
                if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected key property string"); free_token(&tok); return -1; }
                char *key_prop = strdup(tok.value); free_token(&tok);
                if (strcmp(key_prop, "algorithm") == 0 || strcmp(key_prop, "secret") == 0) {
                    tok = get_next_token(&ctx);
                    if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected value for '%s'", key_prop); free(key_prop); free_token(&tok); return -1; }
                    char *val = strdup(tok.value); free_token(&tok);
                    tok = get_next_token(&ctx); if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';'"); free(key_prop); free(val); free_token(&tok); return -1; }
                    free_token(&tok);
                    if (strcmp(key_prop, "algorithm") == 0) tsig->algorithm = val;
                    else {
                        tsig->secret = val;
                        int len = EVP_DecodeBlock(tsig->secret_decoded, (const unsigned char *)tsig->secret, strlen(tsig->secret));
                        int padding = 0; size_t slen = strlen(tsig->secret);
                        if (slen > 0 && tsig->secret[slen-1] == '=') padding++;
                        if (slen > 1 && tsig->secret[slen-2] == '=') padding++;
                        tsig->secret_decoded_len = len - padding;
                    }
                } else { skip_unknown_block(&ctx); }
                free(key_prop);
            }
            tok = get_next_token(&ctx); if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';' after key block"); free_token(&tok); return -1; }
            free_token(&tok);
            tsig->next = config->keys; config->keys = tsig;
        } else if (strcmp(tok.value, "logging") == 0) {
            free_token(&tok); tok = get_next_token(&ctx);
            if (tok.type != TOKEN_LBRACE) { syslog(LOG_ERR, "[Config Error] Expected '{' after 'logging'"); free_token(&tok); return -1; }
            free_token(&tok);
            while (1) {
                tok = get_next_token(&ctx);
                if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
                if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected logging directive"); free_token(&tok); return -1; }
                char *dir = strdup(tok.value); free_token(&tok);
                if (strcmp(dir, "channel") == 0) {
                    tok = get_next_token(&ctx);
                    if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected channel name"); free(dir); free_token(&tok); return -1; }
                    log_channel_t *ch = calloc(1, sizeof(log_channel_t));
                    ch->name = strdup(tok.value); free_token(&tok);
                    ch->fd = -1;
                    pthread_mutex_init(&ch->lock, NULL);
                    
                    tok = get_next_token(&ctx);
                    if (tok.type != TOKEN_LBRACE) { syslog(LOG_ERR, "[Config Error] Expected '{' for channel"); free(dir); free_token(&tok); return -1; }
                    free_token(&tok);
                    while (1) {
                        tok = get_next_token(&ctx);
                        if (tok.type == TOKEN_RBRACE) { free_token(&tok); break; }
                        if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected channel option"); free_token(&tok); return -1; }
                        char *opt = strdup(tok.value); free_token(&tok);
                        if (strcmp(opt, "file") == 0) {
                            tok = get_next_token(&ctx);
                            if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected file path"); free(opt); free_token(&tok); return -1; }
                            ch->file_path = strdup(tok.value); free_token(&tok);
                            
                            while (1) {
                                size_t saved = ctx.pos;
                                tok = get_next_token(&ctx);
                                if (tok.type == TOKEN_SEMICOLON) { free_token(&tok); break; }
                                if (tok.type == TOKEN_STRING && strcmp(tok.value, "versions") == 0) {
                                    free_token(&tok);
                                    tok = get_next_token(&ctx);
                                    if (tok.type == TOKEN_STRING) ch->versions = atoi(tok.value);
                                    free_token(&tok);
                                } else if (tok.type == TOKEN_STRING && strcmp(tok.value, "size") == 0) {
                                    free_token(&tok);
                                    tok = get_next_token(&ctx);
                                    if (tok.type == TOKEN_STRING) {
                                        size_t mult = 1;
                                        size_t len = strlen(tok.value);
                                        if (len > 0) {
                                            char last = tok.value[len-1];
                                            if (last == 'M' || last == 'm') mult = 1024 * 1024;
                                            else if (last == 'K' || last == 'k') mult = 1024;
                                            else if (last == 'G' || last == 'g') mult = 1024 * 1024 * 1024;
                                            ch->size_limit = strtoull(tok.value, NULL, 10) * mult;
                                        }
                                    }
                                    free_token(&tok);
                                } else if (tok.type == TOKEN_STRING && strcmp(tok.value, "suffix") == 0) {
                                    free_token(&tok);
                                    tok = get_next_token(&ctx);
                                    if (tok.type == TOKEN_STRING && strcmp(tok.value, "timestamp") == 0) ch->suffix_timestamp = true;
                                    free_token(&tok);
                                } else {
                                    ctx.pos = saved;
                                    free_token(&tok);
                                    tok = get_next_token(&ctx);
                                    if (tok.type == TOKEN_SEMICOLON) { free_token(&tok); break; }
                                }
                            }
                        } else if (strcmp(opt, "print-time") == 0 || strcmp(opt, "print-category") == 0 || strcmp(opt, "print-severity") == 0) {
                            tok = get_next_token(&ctx);
                            bool val = (tok.type == TOKEN_STRING && strcmp(tok.value, "yes") == 0);
                            free_token(&tok);
                            tok = get_next_token(&ctx); if (tok.type == TOKEN_SEMICOLON) free_token(&tok);
                            if (strcmp(opt, "print-time") == 0) ch->print_time = val;
                            else if (strcmp(opt, "print-category") == 0) ch->print_category = val;
                            else ch->print_severity = val;
                        } else {
                            skip_unknown_block(&ctx);
                        }
                        free(opt);
                    }
                    tok = get_next_token(&ctx); if (tok.type == TOKEN_SEMICOLON) free_token(&tok);
                    ch->next = config->logging.channels;
                    config->logging.channels = ch;
                } else if (strcmp(dir, "category") == 0) {
                    tok = get_next_token(&ctx);
                    if (tok.type != TOKEN_STRING) { syslog(LOG_ERR, "[Config Error] Expected category name"); free(dir); free_token(&tok); return -1; }
                    char *cat_name = strdup(tok.value); free_token(&tok);
                    tok = get_next_token(&ctx);
                    if (tok.type == TOKEN_LBRACE) {
                        free_token(&tok);
                        tok = get_next_token(&ctx);
                        if (strcmp(cat_name, "queries") == 0 && tok.type == TOKEN_STRING) {
                            config->logging.queries_channel_name = strdup(tok.value);
                        }
                        free_token(&tok);
                        tok = get_next_token(&ctx); if (tok.type == TOKEN_SEMICOLON) free_token(&tok);
                        tok = get_next_token(&ctx); if (tok.type == TOKEN_RBRACE) free_token(&tok);
                    }
                    free(cat_name);
                    tok = get_next_token(&ctx); if (tok.type == TOKEN_SEMICOLON) free_token(&tok);
                } else {
                    skip_unknown_block(&ctx);
                }
                free(dir);
            }
            tok = get_next_token(&ctx); if (tok.type != TOKEN_SEMICOLON) { syslog(LOG_ERR, "[Config Error] Expected ';' after logging block"); free_token(&tok); return -1; }
            free_token(&tok);
            
            // Resolve queries channel
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
            syslog(LOG_ERR, "[Config Warning] Unknown top-level directive: '%s', skipping.", tok.value);
            free_token(&tok);
            skip_unknown_block(&ctx);
        }
    }
    return 0;
}

// ============================================================================
// 4. 高速マスターZoneファイルパーサー (手書きステートマシン)
// ============================================================================
static uint16_t get_type_code(const char *type_str) {
    if (!type_str) return 0;
    switch(type_str[0]) {
        case 'A':
            if (strcmp(type_str, "A") == 0) return 1;
            if (strcmp(type_str, "AAAA") == 0) return 28;
            if (strcmp(type_str, "AFSDB") == 0) return 18;
            if (strcmp(type_str, "ATMA") == 0) return 34;
            if (strcmp(type_str, "A6") == 0) return 38;
            if (strcmp(type_str, "APL") == 0) return 42;
            if (strcmp(type_str, "ANY") == 0) return 255;
            if (strcmp(type_str, "AVC") == 0) return 258;
            if (strcmp(type_str, "AMTRELAY") == 0) return 260;
            if (strcmp(type_str, "AXFR") == 0) return 252;
            break;
        case 'C':
            if (strcmp(type_str, "CNAME") == 0) return 5;
            if (strcmp(type_str, "CERT") == 0) return 37;
            if (strcmp(type_str, "CDS") == 0) return 59;
            if (strcmp(type_str, "CDNSKEY") == 0) return 60;
            if (strcmp(type_str, "CSYNC") == 0) return 62;
            if (strcmp(type_str, "CAA") == 0) return 257;
            break;
        case 'D':
            if (strcmp(type_str, "DS") == 0) return 43;
            if (strcmp(type_str, "DNAME") == 0) return 39;
            if (strcmp(type_str, "DNSKEY") == 0) return 48;
            if (strcmp(type_str, "DHCID") == 0) return 49;
            if (strcmp(type_str, "DOA") == 0) return 259;
            if (strcmp(type_str, "DLV") == 0) return 32769;
            break;
        case 'E':
            if (strcmp(type_str, "EID") == 0) return 31;
            if (strcmp(type_str, "EUI48") == 0) return 108;
            if (strcmp(type_str, "EUI64") == 0) return 109;
            break;
        case 'G':
            if (strcmp(type_str, "GPOS") == 0) return 27;
            break;
        case 'H':
            if (strcmp(type_str, "HINFO") == 0) return 13;
            if (strcmp(type_str, "HTTPS") == 0) return 65;
            if (strcmp(type_str, "HIP") == 0) return 55;
            break;
        case 'I':
            if (strcmp(type_str, "ISDN") == 0) return 20;
            if (strcmp(type_str, "IPSECKEY") == 0) return 45;
            if (strcmp(type_str, "IXFR") == 0) return 251;
            break;
        case 'K':
            if (strcmp(type_str, "KEY") == 0) return 25;
            if (strcmp(type_str, "KX") == 0) return 36;
            break;
        case 'L':
            if (strcmp(type_str, "LOC") == 0) return 29;
            if (strcmp(type_str, "L32") == 0) return 105;
            if (strcmp(type_str, "L64") == 0) return 106;
            if (strcmp(type_str, "LP") == 0) return 107;
            break;
        case 'M':
            if (strcmp(type_str, "MX") == 0) return 15;
            if (strcmp(type_str, "MD") == 0) return 3;
            if (strcmp(type_str, "MF") == 0) return 4;
            if (strcmp(type_str, "MB") == 0) return 7;
            if (strcmp(type_str, "MG") == 0) return 8;
            if (strcmp(type_str, "MR") == 0) return 9;
            if (strcmp(type_str, "MINFO") == 0) return 14;
            if (strcmp(type_str, "MAILB") == 0) return 253;
            if (strcmp(type_str, "MAILA") == 0) return 254;
            break;
        case 'N':
            if (strcmp(type_str, "NS") == 0) return 2;
            if (strcmp(type_str, "NULL") == 0) return 10;
            if (strcmp(type_str, "NSAP") == 0) return 22;
            if (strcmp(type_str, "NSAP-PTR") == 0) return 23;
            if (strcmp(type_str, "NXT") == 0) return 30;
            if (strcmp(type_str, "NIMLOC") == 0) return 32;
            if (strcmp(type_str, "NAPTR") == 0) return 35;
            if (strcmp(type_str, "NSEC") == 0) return 47;
            if (strcmp(type_str, "NSEC3") == 0) return 50;
            if (strcmp(type_str, "NSEC3PARAM") == 0) return 51;
            if (strcmp(type_str, "NID") == 0) return 104;
            break;
        case 'O':
            if (strcmp(type_str, "OPT") == 0) return 41;
            if (strcmp(type_str, "OPENPGPKEY") == 0) return 61;
            break;
        case 'P':
            if (strcmp(type_str, "PTR") == 0) return 12;
            if (strcmp(type_str, "PX") == 0) return 26;
            break;
        case 'R':
            if (strcmp(type_str, "RP") == 0) return 17;
            if (strcmp(type_str, "RT") == 0) return 21;
            if (strcmp(type_str, "RRSIG") == 0) return 46;
            break;
        case 'S':
            if (strcmp(type_str, "SOA") == 0) return 6;
            if (strcmp(type_str, "SRV") == 0) return 33;
            if (strcmp(type_str, "SIG") == 0) return 24;
            if (strcmp(type_str, "SINK") == 0) return 40;
            if (strcmp(type_str, "SSHFP") == 0) return 44;
            if (strcmp(type_str, "SMIMEA") == 0) return 53;
            if (strcmp(type_str, "SVCB") == 0) return 64;
            if (strcmp(type_str, "SPF") == 0) return 99;
            break;
        case 'T':
            if (strcmp(type_str, "TXT") == 0) return 16;
            if (strcmp(type_str, "TLSA") == 0) return 52;
            if (strcmp(type_str, "TKEY") == 0) return 249;
            if (strcmp(type_str, "TSIG") == 0) return 250;
            if (strcmp(type_str, "TA") == 0) return 32768;
            if (strncmp(type_str, "TYPE", 4) == 0) return (uint16_t)atoi(type_str + 4);
            break;
        case 'U':
            if (strcmp(type_str, "URI") == 0) return 256;
            break;
        case 'W':
            if (strcmp(type_str, "WKS") == 0) return 11;
            break;
        case 'X':
            if (strcmp(type_str, "X25") == 0) return 19;
            break;
        case 'Z':
            if (strcmp(type_str, "ZONEMD") == 0) return 63;
            break;
    }
    return 0;
}

static int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void *arena_alloc(zone_arena_t *arena, size_t size) {
    if (arena->current_pool_idx + size > arena->current_pool_cap || arena->data_pool_count == 0) {
        if (arena->data_pool_count >= 128) return NULL;
        if (arena->data_pool_count == 0) {
            arena->current_pool_cap = 64 * 1024; // 64KB init
        } else {
            arena->current_pool_cap *= 2;
            if (arena->current_pool_cap > 64 * 1024 * 1024) arena->current_pool_cap = 64 * 1024 * 1024;
        }
        if (size > arena->current_pool_cap) arena->current_pool_cap = size + (1024 * 1024);
        arena->data_pools[arena->data_pool_count] = malloc(arena->current_pool_cap);
        if (!arena->data_pools[arena->data_pool_count]) return NULL;
        arena->current_pool_idx = 0;
        arena->data_pool_count++;
    }
    int p_idx = arena->data_pool_count - 1;
    void *ptr = &arena->data_pools[p_idx][arena->current_pool_idx];
    arena->current_pool_idx += size;
    return ptr;
}

static char *expand_domain_name(char *name, const char *origin, zone_arena_t *arena) {
    if (!name) return name;
    
    // Check if name already has a trailing dot (absolute FQDN)
    size_t n_len = strlen(name);
    if (n_len > 0 && name[n_len - 1] == '.') return name;
    
    // Handle "@" expansion
    if (strcmp(name, "@") == 0) {
        if (!origin) return name;
        size_t o_len = strlen(origin);
        if (o_len > 0 && origin[o_len - 1] == '.') return (char *)origin;
        // Origin needs a trailing dot
        char *fqdn = (char*)arena_alloc(arena, o_len + 2);
        if (!fqdn) return (char *)origin;
        memcpy(fqdn, origin, o_len);
        fqdn[o_len] = '.'; fqdn[o_len+1] = '\0';
        return fqdn;
    }
    
    // Relative name expansion
    if (!origin) {
        // Just add trailing dot
        char *fqdn = (char*)arena_alloc(arena, n_len + 2);
        if (!fqdn) return name;
        memcpy(fqdn, name, n_len);
        fqdn[n_len] = '.'; fqdn[n_len+1] = '\0';
        return fqdn;
    }
    
    size_t o_len = strlen(origin);
    bool origin_has_dot = (o_len > 0 && origin[o_len - 1] == '.');
    
    size_t total_len = n_len + 1 + o_len + (origin_has_dot ? 0 : 1);
    char *fqdn = (char*)arena_alloc(arena, total_len + 1);
    if (!fqdn) return name;
    
    memcpy(fqdn, name, n_len);
    fqdn[n_len] = '.';
    memcpy(fqdn + n_len + 1, origin, o_len);
    if (!origin_has_dot) fqdn[n_len + 1 + o_len] = '.';
    fqdn[total_len] = '\0';
    
    return fqdn;
}

int parse_zone_fast(char *buf, size_t size, zone_arena_t *arena, char **prev_owner_io, char **origin_io, char **default_ttl_str_io) {
    if (!buf || size == 0 || !arena) return -1;
    char *p = buf, *end = buf + size;
    int in_parens = 0, in_quotes = 0, field_idx = 0;
    char *fields[MAX_FIELDS], *token_start = NULL;

STATE_START_LINE:
    if (p >= end) goto DONE;
    field_idx = 0; in_quotes = 0;
    if (IS_SPACE(*p)) { if (*prev_owner_io) fields[field_idx++] = *prev_owner_io; goto SKIP_WHITESPACE; }

STATE_FIND_TOKEN:
    if (p >= end) goto PROCESS_RECORD;
    if (IS_SPACE(*p)) goto SKIP_WHITESPACE;
    if (IS_NEWLINE(*p)) { *p++ = '\0'; if (in_parens) goto STATE_FIND_TOKEN; goto PROCESS_RECORD; }
    if (*p == ';') { char *nl = memchr(p, '\n', end - p); if (!nl) goto PROCESS_RECORD; p = nl; goto STATE_FIND_TOKEN; }
    if (*p == '(') { in_parens = 1; *p++ = '\0'; goto STATE_FIND_TOKEN; }
    if (*p == ')') { in_parens = 0; *p++ = '\0'; goto STATE_FIND_TOKEN; }
    token_start = p;

    while (p < end) {
        if (*p == '\\') { p++; if (p < end) p++; continue; }
        if (*p == '"') { in_quotes = !in_quotes; p++; continue; }
        if (!in_quotes) { if (IS_SPACE(*p) || IS_NEWLINE(*p) || *p == ';' || *p == '(' || *p == ')') break; }
        else { if (IS_NEWLINE(*p)) break; }
        p++;
    }
    if (field_idx < MAX_FIELDS) fields[field_idx++] = token_start;
    if (p >= end) goto PROCESS_RECORD;

    char delimiter = *p; *p++ = '\0';
    
    if (field_idx > 0 && fields[field_idx - 1][0] == '"') {
        fields[field_idx - 1]++;
        size_t t_len = strlen(fields[field_idx - 1]);
        if (t_len > 0 && fields[field_idx - 1][t_len - 1] == '"') {
            fields[field_idx - 1][t_len - 1] = '\0';
        }
    }

    if (IS_SPACE(delimiter)) goto SKIP_WHITESPACE;
    if (IS_NEWLINE(delimiter)) { if (in_parens) goto STATE_FIND_TOKEN; goto PROCESS_RECORD; }
    if (delimiter == '(') { in_parens = 1; goto STATE_FIND_TOKEN; }
    if (delimiter == ')') { in_parens = 0; goto STATE_FIND_TOKEN; }
    if (delimiter == ';') { char *nl = memchr(p, '\n', end - p); if (!nl) goto PROCESS_RECORD; p = nl; goto STATE_FIND_TOKEN; }

SKIP_WHITESPACE:
    while (p < end && IS_SPACE(*p)) p++;
    goto STATE_FIND_TOKEN;

PROCESS_RECORD:
    if (field_idx == 0) { if (p < end) goto STATE_START_LINE; goto DONE; }
    if (fields[0][0] == '$' && strcasecmp(fields[0], "$ORIGIN") == 0) {
        if (field_idx > 1) *origin_io = fields[1];
        if (p < end) goto STATE_START_LINE; goto DONE;
    }
    if (fields[0][0] == '$' && strcasecmp(fields[0], "$TTL") == 0) {
        if (field_idx > 1) *default_ttl_str_io = fields[1];
        if (p < end) goto STATE_START_LINE; goto DONE;
    }
    if (arena->count >= arena->records_cap) {
        size_t new_cap = arena->records_cap == 0 ? 16 : arena->records_cap * 2;
        dns_record_t *new_records = realloc(arena->records, new_cap * sizeof(dns_record_t));
        if (!new_records) return -1;
        memset(new_records + arena->records_cap, 0, (new_cap - arena->records_cap) * sizeof(dns_record_t));
        arena->records = new_records;
        arena->records_cap = new_cap;
    }
    dns_record_t *rec = &arena->records[arena->count++];
    rec->name = expand_domain_name(fields[0], *origin_io, arena);
    *prev_owner_io = rec->name;
    rec->ttl = *default_ttl_str_io; rec->class_str = NULL; rec->type = NULL; rec->rdata_count = 0;

    int i = 1;
    while (i < field_idx) {
        char first_char = fields[i][0];
        if (first_char >= '0' && first_char <= '9') rec->ttl = fields[i];
        else if ((first_char == 'I' && fields[i][1] == 'N' && fields[i][2] == '\0') || strcmp(fields[i], "CH") == 0) rec->class_str = fields[i];
        else { rec->type = fields[i]; i++; break; }
        i++;
    }
    while (i < field_idx && rec->rdata_count < MAX_RDATA) rec->rdata[rec->rdata_count++] = fields[i++];
    
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
                    char *hex = rec->rdata[j];
                    for (char *h = hex; *h; h++) {
                        int val = hex_char_to_val(*h);
                        if (val < 0) continue;
                        if (high_nibble < 0) { high_nibble = val; }
                        else {
                            if (b_idx < rec->generic_len) {
                                blob[b_idx++] = (high_nibble << 4) | val;
                            }
                            high_nibble = -1;
                        }
                    }
                }
                rec->generic_data = blob;
            }
        }
    } else if (rec->type) {
        if (rec->type_code == 5 || rec->type_code == 12 || rec->type_code == 2) {
            if (rec->rdata_count > 0) rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
        } else if (rec->type_code == 6) {
            if (rec->rdata_count > 0) rec->rdata[0] = expand_domain_name(rec->rdata[0], *origin_io, arena);
            if (rec->rdata_count > 1) rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
        } else if (rec->type_code == 15) { // MX
            if (rec->rdata_count > 1) rec->rdata[1] = expand_domain_name(rec->rdata[1], *origin_io, arena);
        } else if (rec->type_code == 33) { // SRV
            if (rec->rdata_count > 3) rec->rdata[3] = expand_domain_name(rec->rdata[3], *origin_io, arena);
        }
    }
    
    if (p < end) goto STATE_START_LINE;

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
    for (int i = 0; i < arena->data_pool_count; i++) {
        free(arena->data_pools[i]);
    }
    free(arena->hash_table);
    for (int i = 0; i < arena->file_buf_count; i++) free(arena->file_bufs[i]);
    arena->file_buf_count = 0;
}

static inline uint32_t calc_fnv1a_str(const char *str) {
    uint32_t hash = 2166136261u;
    for (const char *p = str; *p; p++) {
        uint8_t c = *p;
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        hash ^= c;
        hash *= 16777619u;
    }
    return hash;
}

static size_t next_pow2(size_t n) {
    size_t p = 256;
    while (p < n) p <<= 1;
    return p;
}

void build_zone_index(zone_arena_t *arena) {
    if (arena->hash_table) { free(arena->hash_table); arena->hash_table = NULL; }
    arena->hash_size = next_pow2(arena->count * 2);
    arena->hash_table = malloc(sizeof(int) * arena->hash_size);
    for (size_t i = 0; i < arena->hash_size; i++) arena->hash_table[i] = -1;
    // Insert in reverse order to keep original insertion order when traversing the list
    for (int i = (int)arena->count - 1; i >= 0; i--) {
        dns_record_t *rec = &arena->records[i];
        if (!rec->name) continue;
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
        if (!snap) return NULL;
        atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
        if (snap == atomic_load_explicit(&g_zone_db_active, memory_order_acquire)) break;
        atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
    } while(1);
    
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
        usleep(1000); // 1ms
        if (++retries % 1000 == 0) syslog(LOG_WARNING, "[RCU] wait_for_snapshot_readers stalled for %d ms", retries);
    }
}

zone_db_entry_t *get_or_create_zone(const char *domain) {
    zone_db_snapshot_t *snap = NULL;
    do {
        snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
        if (snap) {
            atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
            if (snap == atomic_load_explicit(&g_zone_db_active, memory_order_acquire)) break;
            atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
        } else {
            break;
        }
    } while(1);

    if (snap) {
        zone_db_entry_t *result = NULL;
        for (size_t i = 0; i < snap->count; i++) {
            if (strcasecmp(snap->entries[i]->domain, domain) == 0) {
                result = snap->entries[i];
                break;
            }
        }
        atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
        if (result) return result;
    }
    
    zone_db_entry_t *z = calloc(1, sizeof(zone_db_entry_t));
    if (!z) return NULL;
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
        for (size_t i = 0; i < snap->count; i++) {
            new_snap->entries[i] = snap->entries[i];
        }
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
        usleep(1000); // 1ms
        if (++retries % 1000 == 0) {
            syslog(LOG_WARNING, "[RCU] wait_for_readers stalled for %d ms", retries);
        }
    }
}

void load_zones_from_config(server_config_t *config) {
    zone_config_t *z = config->zones;
    while (z) {
        if (z->type && (strcmp(z->type, "master") == 0 || strcmp(z->type, "primary") == 0) && z->file) {
            zone_db_entry_t *entry = get_or_create_zone(z->domain);
            if (!entry) {
                syslog(LOG_ERR, "Too many zones or failed to create zone %s", z->domain);
                z = z->next; continue;
            }
            char *buf = read_entire_file(z->file);
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
                char *prev_owner = NULL;
                char *origin = z->domain;
                char *default_ttl_str = NULL;
                size_t size = strlen(buf);
                int count = parse_zone_fast(buf, size, z_standby, &prev_owner, &origin, &default_ttl_str);
                
                if (count < 0) {
                    syslog(LOG_ERR, "Failed to parse zone %s from %s", z->domain, z->file);
                } else {
                    build_zone_index(z_standby);

                    bool has_soa = false;
                    uint32_t hash = calc_fnv1a_str(z->domain);
                    size_t idx = hash & (z_standby->hash_size - 1);
                    for (int i = z_standby->hash_table[idx]; i != -1; i = z_standby->records[i].next_record) {
                        if (z_standby->records[i].type_code == 6 && strcasecmp(z_standby->records[i].name, z->domain) == 0) {
                            has_soa = true;
                            break;
                        }
                    }

                    if (!has_soa) {
                        syslog(LOG_ERR, "Zone %s has no SOA record for its apex. Discarding.", z->domain);
                    } else {
                        atomic_store_explicit(&entry->rcu.active, z_standby, memory_order_release);
                        syslog(LOG_NOTICE, "Loaded zone %s from %s", z->domain, z->file);
                    }
                }
                pthread_mutex_unlock(&entry->writer_lock);
            } else {
                syslog(LOG_ERR, "Failed to load zone file: %s", z->file);
            }
        }
        z = z->next;
    }
}

// ============================================================================
// 5. 名前圧縮アルゴリズム (FNV-1a, Branchless, 無限ループ防御)
// ============================================================================
// 6. AXFR クライアント & ワイヤーデシリアライザ (スタック安全・バグ修正済)
// ============================================================================


int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *len_out) {
    while (1) {
        if (ctx->state == TCP_STATE_READ_LEN) {
            size_t needed = 2 - ctx->accumulated; ssize_t n = recv(fd, &ctx->buf[ctx->accumulated], needed, 0);
            if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; return -1; }
            if (n == 0) return -1;
            ctx->accumulated += n;
            if (ctx->accumulated == 2) { ctx->msg_len = (ctx->buf[0] << 8) | ctx->buf[1]; ctx->state = TCP_STATE_READ_BODY; ctx->accumulated = 0; }
        }
        if (ctx->state == TCP_STATE_READ_BODY) {
            size_t needed = ctx->msg_len - ctx->accumulated; ssize_t n = recv(fd, &ctx->buf[2 + ctx->accumulated], needed, 0);
            if (n < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; return -1; }
            if (n == 0) return -1;
            ctx->accumulated += n;
            if (ctx->accumulated == ctx->msg_len) { *msg_out = &ctx->buf[2]; *len_out = ctx->msg_len; ctx->state = TCP_STATE_READ_LEN; ctx->accumulated = 0; return 1; }
        }
    }
}

static char *arena_strdup(zone_arena_t *arena, const char *str) {
    if (!str) return NULL;
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
        if (dst->data_pools[i]) free(dst->data_pools[i]);
    }
    dst->count = 0;
    dst->data_pool_count = 0;
    dst->current_pool_cap = 0;
    dst->current_pool_idx = 0;
    for (size_t i = 0; i < src->count; i++) {
        if (dst->count >= dst->records_cap) {
            size_t new_cap = dst->records_cap == 0 ? 16 : dst->records_cap * 2;
            dns_record_t *new_records = realloc(dst->records, new_cap * sizeof(dns_record_t));
            if (!new_records) break;
            memset(new_records + dst->records_cap, 0, (new_cap - dst->records_cap) * sizeof(dns_record_t));
            dst->records = new_records;
            dst->records_cap = new_cap;
        }
        dns_record_t *s_rec = &src->records[i];
        dns_record_t *d_rec = &dst->records[dst->count++];
        d_rec->name = arena_strdup(dst, s_rec->name);
        d_rec->ttl = arena_strdup(dst, s_rec->ttl);
        d_rec->class_str = s_rec->class_str ? arena_strdup(dst, s_rec->class_str) : NULL;
        d_rec->type = s_rec->type ? arena_strdup(dst, s_rec->type) : NULL;
        d_rec->type_code = s_rec->type_code;
        d_rec->rdata_count = s_rec->rdata_count;
        for (int j = 0; j < s_rec->rdata_count; j++) {
            d_rec->rdata[j] = arena_strdup(dst, s_rec->rdata[j]);
        }
        d_rec->generic_len = s_rec->generic_len;
        if (s_rec->generic_len > 0 && s_rec->generic_data) {
            d_rec->generic_data = (uint8_t *)arena_alloc(dst, s_rec->generic_len);
            if (d_rec->generic_data) memcpy(d_rec->generic_data, s_rec->generic_data, s_rec->generic_len);
        } else {
            d_rec->generic_data = NULL;
        }
        d_rec->next_record = -1;
    }
}

int parse_xfr_packet(const uint8_t *packet, size_t packet_len, zone_arena_t *standby, zone_arena_t *active, axfr_session_t *session, const char *domain) {
    if (packet_len < 12) { syslog(LOG_ERR, "[AXFR] parse_xfr_packet: packet too short (<12)"); return -1; }
    uint16_t qdcount = (packet[4] << 8) | packet[5], ancount = (packet[6] << 8) | packet[7]; size_t offset = 12;

    for (int i = 0; i < qdcount; i++) {
        size_t next_offset; if (skip_wire_name(packet, packet_len, offset, &next_offset) != 0) return -1;
        offset = next_offset + 4;
    }
    
    size_t domain_len = strlen(domain);
    for (int i = 0; i < ancount; i++) {
        if (standby->count >= standby->records_cap) {
            size_t new_cap = standby->records_cap == 0 ? 16 : standby->records_cap * 2;
            dns_record_t *new_records = realloc(standby->records, new_cap * sizeof(dns_record_t));
            if (!new_records) return -1;
            memset(new_records + standby->records_cap, 0, (new_cap - standby->records_cap) * sizeof(dns_record_t));
            standby->records = new_records;
            standby->records_cap = new_cap;
        }
        dns_record_t *rec = &standby->records[standby->count]; uint16_t type;
        if (parse_resource_record(packet, packet_len, &offset, standby, rec, &type) != 0) return -1;
        standby->count++;
        
        size_t name_len = strlen(rec->name);
        if (name_len < domain_len || strcasecmp(rec->name + name_len - domain_len, domain) != 0) return -1; 
        if (name_len > domain_len && rec->name[name_len - domain_len - 1] != '.') return -1; 
        
        if (type == 6) {
            session->soa_count++;
            uint32_t current_serial = strtoul(rec->rdata[2], NULL, 10);
            if (session->soa_count == 1) {
                strncpy(session->initial_soa_name, rec->name, sizeof(session->initial_soa_name) - 1);
                session->initial_soa_serial = current_serial;
                if (session->is_ixfr && ancount == 1 && current_serial == session->client_serial) {
                    session->is_finished = true;
                    standby->count = 0;
                    return 0;
                }
            } else if (session->soa_count == 2 && session->is_ixfr) {
                standby->count = 0;
                standby->data_pool_count = 0; standby->current_pool_cap = 0;
                standby->current_pool_idx = 0;
                clone_zone_arena(active, standby);
                session->is_deleting = true;
            } else if (session->is_ixfr && current_serial == session->initial_soa_serial) {
                session->is_finished = true;
            } else if (session->is_ixfr) {
                session->is_deleting = !session->is_deleting;
                standby->count--;
            } else {
                if (strcmp(session->initial_soa_name, rec->name) == 0 && session->initial_soa_serial == current_serial) session->is_finished = true;
            }
        } else {
            if (session->soa_count == 1 && session->is_ixfr) session->is_ixfr = false;
            if (session->is_ixfr && session->is_deleting) {
                standby->count--;
                for (size_t k = 0; k < standby->count; k++) {
                    dns_record_t *s = &standby->records[k];
                    if (s->type_code == type && strcasecmp(s->name, rec->name) == 0 && s->rdata_count == rec->rdata_count) {
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


int handle_axfr_event(int tcp_fd, zone_db_entry_t *entry, tcp_stream_ctx_t *stream_ctx, axfr_session_t *session, tsig_key_t *tsig_key) {
    uint8_t *msg; uint16_t msg_len;
    pthread_mutex_lock(&entry->writer_lock);
    zone_arena_t *active = atomic_load_explicit(&entry->rcu.active, memory_order_relaxed);
    zone_arena_t *standby = (active == &entry->rcu.arena_a) ? &entry->rcu.arena_b : &entry->rcu.arena_a;

    if (session->soa_count == 0) { standby->count = 0; standby->data_pool_count = 0; standby->current_pool_cap = 0; standby->current_pool_idx = 0; session->is_finished = false; }
    while (1) {
        int ret = read_dns_tcp_message(tcp_fd, stream_ctx, &msg, &msg_len);
        if (ret < 0) { pthread_mutex_unlock(&entry->writer_lock); return -1; }
        if (ret == 0) { pthread_mutex_unlock(&entry->writer_lock); return -1; }
        if (tsig_key && tsig_verify_packet(msg, msg_len, tsig_key) != 0) {
            syslog(LOG_ERR, "[AXFR] TSIG verification failed for zone %s", entry->domain);
            pthread_mutex_unlock(&entry->writer_lock);
            return -1;
        }
        if (parse_xfr_packet(msg, msg_len, standby, active, session, entry->domain) != 0) { pthread_mutex_unlock(&entry->writer_lock); return -1; }
        if (session->is_finished) {
            if (standby->count > 0) {
                for (size_t k = 0; k < standby->count; k++) {
                    if (standby->records[k].type_code == 6) {
                        if (standby->records[k].rdata_count >= 7) {
                            entry->serial = strtoul(standby->records[k].rdata[2], NULL, 10);
                            entry->refresh = strtoul(standby->records[k].rdata[3], NULL, 10);
                            entry->retry = strtoul(standby->records[k].rdata[4], NULL, 10);
                            entry->expire = strtoul(standby->records[k].rdata[5], NULL, 10);
                            entry->next_check = time(NULL) + entry->refresh;
                        }
                        break;
                    }
                }
                build_zone_index(standby);
                atomic_store_explicit(&entry->rcu.active, standby, memory_order_release);
                wait_for_readers(active);
                syslog(LOG_INFO, "[RCU Switch] AXFR/IXFR Dynamic Update Successful. Records Active: %zu", standby->count);
                
                void send_notify_to_all(const char *domain);
                send_notify_to_all(entry->domain);
            } else {
                syslog(LOG_INFO, "[RCU Switch] IXFR Up-to-date. No changes needed.");
            }
            pthread_mutex_unlock(&entry->writer_lock);
            return 1;
        }
    }
}

// ============================================================================
// 7. インメモリDNSパケット高速処理・統合スタブ
// ============================================================================


static bool find_delegation(zone_arena_t *current_zone, const char *qname, const char *zone_apex, 
                            uint8_t *res, size_t max_res_len, uint16_t *offset, compress_ctx_t *comp_ctx,
                            uint16_t *nscount, uint16_t *arcount) {
    if (!current_zone || current_zone->hash_size == 0 || !current_zone->hash_table) return false;
    const char *name = qname;
    while (name && strcasecmp(name, zone_apex) != 0) {
        uint32_t hash = calc_fnv1a_str(name);
        size_t idx = hash & (current_zone->hash_size - 1);
        
        bool delegated = false;
        
        for (int i = current_zone->hash_table[idx]; i != -1; i = current_zone->records[i].next_record) {
            dns_record_t *rec = &current_zone->records[i];
            if (rec->type_code == 2 && strcasecmp(rec->name, name) == 0) {
                delegated = true;
                if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                    res[2] |= 0x02; // TC bit
                    return true;
                } else {
                    (*nscount)++;
                }
            }
        }
        
        if (delegated) {
            res[2] &= ~0x04; // Clear AA bit for referral
            
            for (int i = current_zone->hash_table[idx]; i != -1; i = current_zone->records[i].next_record) {
                dns_record_t *ns_rec = &current_zone->records[i];
                if (ns_rec->type_code == 2 && strcasecmp(ns_rec->name, name) == 0 && ns_rec->rdata_count > 0) {
                    const char *target = ns_rec->rdata[0];
                    size_t target_len = strlen(target);
                    size_t apex_len = strlen(zone_apex);
                    if (target_len >= apex_len && strcasecmp(target + target_len - apex_len, zone_apex) == 0) {
                        if (target_len == apex_len || target[target_len - apex_len - 1] == '.') {
                            uint32_t tgt_hash = calc_fnv1a_str(target);
                            size_t tgt_idx = tgt_hash & (current_zone->hash_size - 1);
                            for (int j = current_zone->hash_table[tgt_idx]; j != -1; j = current_zone->records[j].next_record) {
                                dns_record_t *tgt_rec = &current_zone->records[j];
                                if ((tgt_rec->type_code == 1 || tgt_rec->type_code == 28) && strcasecmp(tgt_rec->name, target) == 0) {
                                    if (serialize_dns_record(res, max_res_len, offset, tgt_rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                                        res[2] |= 0x02; // TC bit
                                        return true;
                                    } else {
                                        (*arcount)++;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return true;
        }
        name = strchr(name, '.');
        if (name) name++;
    }
    return false;
}

#define MAX_CNAME_CHAIN 16

static void resolve_name(const char *qname, uint16_t qtype, zone_db_entry_t **db_entry_ptr, zone_arena_t **current_zone_ptr, 
                         uint8_t *res, size_t max_res_len, uint16_t *offset, compress_ctx_t *comp_ctx,
                         uint16_t *ancount, uint16_t *nscount, uint16_t *arcount) {
    char current_qname[256];
    strncpy(current_qname, qname, sizeof(current_qname));
    current_qname[255] = '\0';
    
    bool chain_exhausted = true;
    for (int depth = 0; depth < MAX_CNAME_CHAIN; depth++) {
        zone_db_entry_t *db_entry = *db_entry_ptr;
        zone_arena_t *current_zone = *current_zone_ptr;
        
        if (!current_zone || current_zone->hash_size == 0 || !current_zone->hash_table) {
            res[3] |= 0x02; // SERVFAIL
            return;
        }
        
        if (find_delegation(current_zone, current_qname, db_entry->domain, res, max_res_len, offset, comp_ctx, nscount, arcount)) {
            return;
        }

        bool found = false;
        bool type_matched = false;
        bool cname_followed = false;

        // 1. Exact match
        uint32_t hash = calc_fnv1a_str(current_qname);
        size_t idx = hash & (current_zone->hash_size - 1);
        for (int i = current_zone->hash_table[idx]; i != -1; i = current_zone->records[i].next_record) {
            dns_record_t *rec = &current_zone->records[i];
            if (strcasecmp(rec->name, current_qname) == 0) {
                found = true;
                uint16_t rec_type = rec->type_code;
                
                if (rec_type == 5 && qtype != 5 && qtype != 255) {
                    if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                        res[2] |= 0x02; // TC bit
                        return;
                    } else {
                        (*ancount)++;
                    }
                    if (rec->rdata_count > 0) {
                        strncpy(current_qname, rec->rdata[0], sizeof(current_qname));
                        current_qname[255] = '\0';
                        cname_followed = true;
                    }
                    break;
                } else if (qtype == 255 || qtype == rec_type) {
                    type_matched = true;
                    if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                        res[2] |= 0x02; // TC bit
                        return;
                        break;
                    }
                    (*ancount)++;
                }
            }
        }
        
        // 2. Wildcard search (only if exact match not found)
        if (!found) {
            const char *parent = current_qname;
            char wc_name[256];
            while ((parent = strchr(parent, '.')) != NULL) {
                parent++;
                if (*parent == '\0') break;
                
                snprintf(wc_name, sizeof(wc_name), "*.%s", parent);
                uint32_t wc_hash = calc_fnv1a_str(wc_name);
                size_t wc_idx = wc_hash & (current_zone->hash_size - 1);
                
                bool wc_found = false;
                for (int i = current_zone->hash_table[wc_idx]; i != -1; i = current_zone->records[i].next_record) {
                    dns_record_t *rec = &current_zone->records[i];
                    if (strcasecmp(rec->name, wc_name) == 0) {
                        found = true;
                        wc_found = true;
                        uint16_t rec_type = rec->type_code;
                        
                        if (rec_type == 5 && qtype != 5 && qtype != 255) {
                            if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, current_qname, 0xFFFFFFFF) < 0) {
                                res[2] |= 0x02; // TC bit
                                return;
                            } else {
                                (*ancount)++;
                            }
                            if (rec->rdata_count > 0) {
                                strncpy(current_qname, rec->rdata[0], sizeof(current_qname));
                                current_qname[255] = '\0';
                                cname_followed = true;
                            }
                            break;
                        } else if (qtype == 255 || qtype == rec_type) {
                            type_matched = true;
                            if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, current_qname, 0xFFFFFFFF) < 0) {
                                res[2] |= 0x02; // TC bit
                                return;
                            } else {
                                (*ancount)++;
                            }
                        }
                    }
                }
                if (wc_found) break;
            }
        }
        
        // 3. Follow CNAME (if discovered by exact match OR wildcard)
        if (cname_followed) {
            size_t cq_len = strlen(current_qname);
            size_t z_len = strlen(db_entry->domain);
            bool in_zone = false;
            if (cq_len >= z_len && strcasecmp(current_qname + cq_len - z_len, db_entry->domain) == 0) {
                if (cq_len == z_len || current_qname[cq_len - z_len - 1] == '.') {
                    in_zone = true;
                }
            }
            
            if (in_zone) {
                continue;
            } else {
                zone_db_entry_t *new_db_entry = NULL;
                size_t longest_match_len = 0;
                zone_db_snapshot_t *snap = NULL;
                do {
                    snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
                    if (!snap) break;
                    atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
                    if (snap == atomic_load_explicit(&g_zone_db_active, memory_order_acquire)) break;
                    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
                } while(1);

                if (snap) {
                    for (size_t i = 0; i < snap->count; i++) {
                        size_t check_z_len = strlen(snap->entries[i]->domain);
                        bool match = false;
                        if (cq_len == check_z_len && strcasecmp(current_qname, snap->entries[i]->domain) == 0) {
                            match = true;
                        } else if (cq_len > check_z_len && current_qname[cq_len - check_z_len - 1] == '.') {
                            if (strcasecmp(current_qname + cq_len - check_z_len, snap->entries[i]->domain) == 0) {
                                match = true;
                            }
                        }
                        if (match && check_z_len > longest_match_len) {
                            longest_match_len = check_z_len;
                            new_db_entry = snap->entries[i];
                        }
                    }
                    atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
                }
                
                if (new_db_entry) {
                    zone_arena_t *new_zone = NULL;
                    do {
                        new_zone = atomic_load_explicit(&new_db_entry->rcu.active, memory_order_acquire);
                        atomic_fetch_add_explicit(&new_zone->reader_count, 1, memory_order_acquire);
                        if (new_zone == atomic_load_explicit(&new_db_entry->rcu.active, memory_order_acquire)) break;
                        atomic_fetch_sub_explicit(&new_zone->reader_count, 1, memory_order_release);
                    } while(1);
                    
                    atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
                    *db_entry_ptr = new_db_entry;
                    *current_zone_ptr = new_zone;
                    continue;
                } else {
                    return;
                }
            }
        }
        
        // 4. Negative Cache SOA & loop termination
        if (!found || !type_matched) {
            if (!found) {
                res[3] |= 3; // NXDOMAIN
            } else {
                res[3] &= ~3; // NODATA
            }
            
            uint32_t apex_hash = calc_fnv1a_str(db_entry->domain);
            size_t apex_idx = apex_hash & (current_zone->hash_size - 1);
            for (int i = current_zone->hash_table[apex_idx]; i != -1; i = current_zone->records[i].next_record) {
                dns_record_t *rec = &current_zone->records[i];
                if (rec->type_code == 6 && strcasecmp(rec->name, db_entry->domain) == 0) {
                    uint32_t minimum_ttl = 3600;
                    if (rec->rdata_count >= 7) {
                        minimum_ttl = strtoul(rec->rdata[6], NULL, 10);
                    }
                    if (serialize_dns_record(res, max_res_len, offset, rec, comp_ctx, NULL, minimum_ttl) < 0) {
                        res[2] |= 0x02; // TC bit
                        return;
                    } else {
                        (*nscount)++;
                    }
                    break;
                }
            }
        }
        
        chain_exhausted = false;
        break; // If we didn't follow a CNAME, we are done.
    }
    
    if (chain_exhausted) {
        res[3] |= 0x02; // SERVFAIL
    }
}

int process_dns_query(const uint8_t *req, size_t req_len, uint8_t *res, size_t max_res_len, const char *qname, uint16_t qtype, const char *client_ip, compress_ctx_t *comp_ctx, bool is_tcp) {
    char current_qname[256];
    strncpy(current_qname, qname, 255);
    current_qname[255] = '\0';
    size_t q_len = strlen(current_qname);

    zone_arena_t *current_zone = NULL;
    zone_db_entry_t *db_entry = NULL;
    size_t longest_match_len = 0;
    
    // Find matching zone in DB (longest suffix match)
    zone_db_snapshot_t *snap = NULL;
    do {
        snap = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
        if (!snap) break;
        atomic_fetch_add_explicit(&snap->reader_count, 1, memory_order_acquire);
        if (snap == atomic_load_explicit(&g_zone_db_active, memory_order_acquire)) break;
        atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
    } while(1);

    if (snap) {
        for (size_t i = 0; i < snap->count; i++) {
            size_t z_len = strlen(snap->entries[i]->domain);
            bool match = false;
            
            if (q_len == z_len && strcasecmp(current_qname, snap->entries[i]->domain) == 0) {
                match = true;
            } else if (q_len > z_len && current_qname[q_len - z_len - 1] == '.') {
                if (strcasecmp(current_qname + q_len - z_len, snap->entries[i]->domain) == 0) {
                    match = true;
                }
            }
            
            if (match && z_len > longest_match_len) {
                longest_match_len = z_len;
                db_entry = snap->entries[i];
            }
        }
        atomic_fetch_sub_explicit(&snap->reader_count, 1, memory_order_release);
    }
    
    if (req_len >= 12) {
        int opcode = (req[2] >> 3) & 0x0F;
        if (opcode == 4) { // NOTIFY
            bool auth = false;
            if (db_entry) {
                server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
                zone_config_t *zcfg = cfg->zones;
                while(zcfg) { if (strcasecmp(zcfg->domain, db_entry->domain)==0) break; zcfg = zcfg->next; }
                if (zcfg && zcfg->masters_count > 0) {
                    for(int k=0; k<zcfg->masters_count; k++) {
                        if (strcmp(client_ip, zcfg->masters[k].ip) == 0) { auth = true; break; }
                    }
                    if (auth && zcfg->tsig_key) {
                        tsig_key_t *k = cfg->keys;
                        tsig_key_t *matched_key = NULL;
                        while (k) {
                            if (strcmp(k->name, zcfg->tsig_key) == 0) { matched_key = k; break; }
                            k = k->next;
                        }
                        if (!matched_key || tsig_verify_packet(req, req_len, matched_key) != 0) {
                            auth = false;
                        }
                    }
                }
            }
            size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
            memcpy(res, req, copy_len);
            res[2] |= 0x84; // QR=1, AA=1
            if (auth) {
                res[3] &= 0x0F; // NOERROR
                atomic_store_explicit(&db_entry->refresh_now, true, memory_order_release);
                if (g_control_kq != -1) {
                    struct kevent ev;
                    EV_SET(&ev, 2, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
                    kevent(g_control_kq, &ev, 1, NULL, 0, NULL);
                }
            } else {
                res[3] |= 0x05; // REFUSED
            }
            return copy_len;
        }
    }

    if (db_entry) {
        do {
            current_zone = atomic_load_explicit(&db_entry->rcu.active, memory_order_acquire);
            atomic_fetch_add_explicit(&current_zone->reader_count, 1, memory_order_acquire);
            if (current_zone == atomic_load_explicit(&db_entry->rcu.active, memory_order_acquire)) break;
            atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        } while(1);
    }
    
    // パケット書き込みと名前圧縮の初期化
    compress_ctx_init_packet(comp_ctx);

    if (req_len < 12) {
        if (current_zone) {
            atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        }
        return -1;
    }
    
    uint16_t qdcount = (req[4] << 8) | req[5];
    uint16_t ancount_req = (req[6] << 8) | req[7];
    uint16_t nscount_req = (req[8] << 8) | req[9];
    uint16_t arcount_req = (req[10] << 8) | req[11];

    if (qdcount != 1) {
        if (current_zone) atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
        memcpy(res, req, copy_len);
        res[2] |= 0x80;
        res[3] &= 0x0F;
        res[3] |= 0x01; // FORMERR
        return copy_len;
    }

    uint16_t client_payload_size = 512;
    bool has_edns = false;
    parse_edns_opt(req, req_len, qdcount, ancount_req, nscount_req, arcount_req,
                   &has_edns, &client_payload_size);
    if (has_edns && max_res_len == 512) {
        if (client_payload_size > 1232) client_payload_size = 1232;
        if (client_payload_size > 512) max_res_len = client_payload_size;
    }

    // Skip question in req
    size_t q_offset = 12;
    while (q_offset < req_len) {
        uint8_t len = req[q_offset];
        if (len == 0) { q_offset++; break; }
        if ((len & 0xC0) == 0xC0) { q_offset += 2; break; }
        q_offset += len + 1;
    }
    
    if (q_offset + 4 > req_len) {
        if (current_zone) atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        size_t copy_len = req_len > max_res_len ? max_res_len : req_len;
        memcpy(res, req, copy_len);
        res[2] |= 0x80; // QR=1
        res[3] &= 0x0F;
        res[3] |= 0x01; // FORMERR
        return copy_len;
    }
    
    uint16_t qclass = (req[q_offset + 2] << 8) | req[q_offset + 3];
    if (qclass != 1 && qclass != 255) {
        if (current_zone) atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        size_t copy_len = q_offset + 4;
        if (copy_len > max_res_len) copy_len = max_res_len;
        memcpy(res, req, copy_len);
        res[2] |= 0x80; // QR=1
        res[3] &= 0x0F;
        res[3] |= 0x05; // REFUSED
        return copy_len;
    }

    q_offset += 4; // QTYPE + QCLASS

    memcpy(res, req, q_offset);
    res[2] |= 0x84; // QR=1, AA=1
    res[3] &= 0x0F; // clear RA, Z. Keep RCODE.

    uint16_t *res_ancount = (uint16_t *)&res[6];
    uint16_t *res_nscount = (uint16_t *)&res[8];
    uint16_t *res_arcount = (uint16_t *)&res[10];
    
    *res_ancount = 0;
    *res_nscount = 0;
    *res_arcount = 0;

    if (!is_tcp && qtype == 255) {
        res[2] |= 0x02; // TC bit
        if (current_zone) {
            atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        }
        return q_offset;
    }

    if (!current_zone) {
        res[3] |= 3; // NXDOMAIN or REFUSED
        return q_offset;
    }

    uint16_t offset = q_offset;
    uint16_t ancount = 0, nscount = 0, arcount = 0;

    resolve_name(current_qname, qtype, &db_entry, &current_zone, res, max_res_len, &offset, comp_ctx, &ancount, &nscount, &arcount);

    if (has_edns) {
        assemble_edns_opt(res, max_res_len, &offset, &arcount);
    }

    *res_ancount = htons(ancount);
    *res_nscount = htons(nscount);
    *res_arcount = htons(arcount);
    
    if (current_zone) {
        atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
    }
    
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

// TSIG functions have been moved to before handle_axfr_event

void *axfr_bg_thread_func(void *arg) {
    axfr_bg_ctx_t *ctx = (axfr_bg_ctx_t *)arg;
    
    syslog(LOG_INFO, "[AXFR BG] Starting background AXFR transfer from %s", ctx->master_ip);
    
    struct sockaddr_storage master_addr;
    memset(&master_addr, 0, sizeof(master_addr));
    int domain_family = AF_INET;
    
    if (inet_pton(AF_INET, ctx->master_ip, &((struct sockaddr_in *)&master_addr)->sin_addr) == 1) {
        domain_family = AF_INET;
        master_addr.ss_family = AF_INET;
        ((struct sockaddr_in *)&master_addr)->sin_port = htons(ctx->master_port > 0 ? ctx->master_port : 53);
    } else if (inet_pton(AF_INET6, ctx->master_ip, &((struct sockaddr_in6 *)&master_addr)->sin6_addr) == 1) {
        domain_family = AF_INET6;
        master_addr.ss_family = AF_INET6;
        ((struct sockaddr_in6 *)&master_addr)->sin6_port = htons(ctx->master_port > 0 ? ctx->master_port : 53);
    } else {
        syslog(LOG_ERR, "[AXFR BG] Invalid master IP address: %s", ctx->master_ip);
        free(ctx);
        pthread_exit(NULL);
    }

    
    int tcp_fd = socket(domain_family, SOCK_STREAM, 0);
    if (tcp_fd >= 0) {
        size_t addr_len = (domain_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (connect(tcp_fd, (struct sockaddr *)&master_addr, addr_len) == 0) {
        // Socket already connected; it no longer needs CAP_CONNECT etc.
        // Restrict it down to send/recv-class rights before any data is
        // exchanged with the remote master.
        limit_client_socket_rights(tcp_fd);
        struct timeval tv;
        tv.tv_sec = 30; tv.tv_usec = 0;
        setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

        tcp_stream_ctx_t stream_ctx = {0};
        axfr_session_t session = {0};
        
        uint8_t axfr_req[2048];

            uint16_t req_len = 0;
            
            // Header
            uint16_t id = (uint16_t)(arc4random() & 0xFFFF);
            axfr_req[2] = id >> 8; axfr_req[3] = id & 0xFF; // ID
            axfr_req[4] = 0x00; axfr_req[5] = 0x00; // Flags: Standard Query
            axfr_req[6] = 0x00; axfr_req[7] = 0x01; // QDCOUNT = 1
            axfr_req[8] = 0x00; axfr_req[9] = 0x00; // ANCOUNT
            axfr_req[10] = 0x00; axfr_req[11] = 0x00; // NSCOUNT
            axfr_req[12] = 0x00; axfr_req[13] = 0x01; // ARCOUNT
            
            req_len = 14;
            
            // QNAME (ドメイン名のワイヤーフォーマット変換)
            const char *d = ctx->domain;
            while (*d) {
                const char *dot = strchr(d, '.');
                size_t len = dot ? (size_t)(dot - d) : strlen(d);
                if (len > 63) len = 63;
                if (req_len + len + 2 > sizeof(axfr_req) - 512) break; // Reserve space for TSIG & OPT
                axfr_req[req_len++] = (uint8_t)len;
                memcpy(&axfr_req[req_len], d, len);
                req_len += len;
                if (!dot) break;
                d = dot + 1;
            }
            axfr_req[req_len++] = 0; // Terminating zero length
            
            uint32_t active_serial = 0;
            if (ctx->entry) {
                active_serial = ctx->entry->serial;
            }

            // QTYPE (IXFR = 251, AXFR = 252)
            axfr_req[req_len++] = 0x00; axfr_req[req_len++] = active_serial ? 251 : 252;
            session.is_ixfr = active_serial ? true : false;
            session.client_serial = active_serial;
            // QCLASS (IN = 1)
            axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 1;

            if (active_serial) {
                // Add SOA to authority section for IXFR
                axfr_req[10] = 0; axfr_req[11] = 1; // NSCOUNT = 1
                axfr_req[req_len++] = 0xC0; axfr_req[req_len++] = 0x0C; // Name pointer to QNAME
                axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 6; // TYPE SOA
                axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 1; // CLASS IN
                axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 0; axfr_req[req_len++] = 0; axfr_req[req_len++] = 0; // TTL 0
                axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 22; // RDLENGTH
                axfr_req[req_len++] = 0; // mname root
                axfr_req[req_len++] = 0; // rname root
                axfr_req[req_len++] = active_serial >> 24; axfr_req[req_len++] = (active_serial >> 16) & 0xFF;
                axfr_req[req_len++] = (active_serial >> 8) & 0xFF; axfr_req[req_len++] = active_serial & 0xFF;
                for(int i=0; i<16; i++) axfr_req[req_len++] = 0;
            }

            axfr_req[req_len++] = 0; // Root domain
            axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 41; // TYPE: OPT
            axfr_req[req_len++] = 0x10; axfr_req[req_len++] = 0x00; // UDP Payload Size: 4096
            axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 0x00; // Ext RCODE=0, Version=0
            axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 0x00; // DO=0
            axfr_req[req_len++] = 0x00; axfr_req[req_len++] = 0x00; // RDLENGTH=0
            
            // 先頭に2バイトのTCPプレフィックス (パケット長) をセット
            if (ctx->tsig_key) {
                size_t p_len = req_len - 2;
                tsig_sign_packet(&axfr_req[2], &p_len, sizeof(axfr_req) - 2, ctx->tsig_key, 0, NULL, NULL);
                req_len = p_len + 2;
            }
            uint16_t msg_len = req_len - 2;
            axfr_req[0] = msg_len >> 8;
            axfr_req[1] = msg_len & 0xFF;
            
            if (send(tcp_fd, axfr_req, req_len, 0) == req_len) {
                handle_axfr_event(tcp_fd, ctx->entry, &stream_ctx, &session, ctx->tsig_key);
            } else {
                syslog(LOG_ERR, "[AXFR BG] Failed to send AXFR request: %s", strerror(errno));
            }
        } else {
            syslog(LOG_ERR, "[AXFR BG] Connect to master failed: %s", strerror(errno));
        }
        close(tcp_fd);
    } else {
        syslog(LOG_ERR, "[AXFR BG] Failed to create socket: %s", strerror(errno));
    }
    
    if (ctx->entry) {
        atomic_store_explicit(&ctx->entry->is_transferring, false, memory_order_release);
    }
    free(ctx);
    pthread_exit(NULL);
}

void send_notify_to_all(const char *domain) {
    server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    if (!active) return;
    zone_config_t *zone = active->zones;
    while (zone) {
        if (strcasecmp(zone->domain, domain) == 0) break;
        zone = zone->next;
    }
    if (!zone || zone->also_notify_count == 0) return;

    uint8_t req[512];
    memset(req, 0, 12);
    uint16_t id = (uint16_t)(time(NULL) & 0xFFFF);
    req[0] = id >> 8; req[1] = id & 0xFF;
    req[2] = 0x20; // Opcode=4 (NOTIFY), AA=1
    req[3] = 0;
    req[4] = 0; req[5] = 1; // QDCOUNT=1
    
    size_t offset = 12;
    offset += write_uncompressed_name(&req[offset], domain);
    req[offset++] = 0; req[offset++] = 6; // QTYPE SOA
    req[offset++] = 0; req[offset++] = 1; // QCLASS IN

    for (int i = 0; i < zone->also_notify_count; i++) {
        struct sockaddr_storage dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        int domain_family = AF_INET;
        if (inet_pton(AF_INET, zone->also_notify[i].ip, &((struct sockaddr_in *)&dest_addr)->sin_addr) == 1) {
            domain_family = AF_INET;
            dest_addr.ss_family = AF_INET;
            ((struct sockaddr_in *)&dest_addr)->sin_port = htons(zone->also_notify[i].port);
        } else if (inet_pton(AF_INET6, zone->also_notify[i].ip, &((struct sockaddr_in6 *)&dest_addr)->sin6_addr) == 1) {
            domain_family = AF_INET6;
            dest_addr.ss_family = AF_INET6;
            ((struct sockaddr_in6 *)&dest_addr)->sin6_port = htons(zone->also_notify[i].port);
        } else {
            continue;
        }

        int sock = socket(domain_family, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        
        if (zone->notify_source) {
            struct sockaddr_storage src_addr;
            memset(&src_addr, 0, sizeof(src_addr));
            if (domain_family == AF_INET && inet_pton(AF_INET, zone->notify_source, &((struct sockaddr_in *)&src_addr)->sin_addr) == 1) {
                src_addr.ss_family = AF_INET;
                ((struct sockaddr_in *)&src_addr)->sin_port = 0;
                bind(sock, (struct sockaddr *)&src_addr, sizeof(struct sockaddr_in));
            } else if (domain_family == AF_INET6 && inet_pton(AF_INET6, zone->notify_source, &((struct sockaddr_in6 *)&src_addr)->sin6_addr) == 1) {
                src_addr.ss_family = AF_INET6;
                ((struct sockaddr_in6 *)&src_addr)->sin6_port = 0;
                bind(sock, (struct sockaddr *)&src_addr, sizeof(struct sockaddr_in6));
            }
        }
        
        sendto(sock, req, offset, 0, (struct sockaddr *)&dest_addr, (domain_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        close(sock);
    }
}

// ============================================================================
// 10. FreeBSD 高性能ネットワークコア (SO_REUSEPORT_LB + kqueue)
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
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                int ret = poll(&pfd, 1, 30000);
                if (ret <= 0) return -1;
                continue;
            }
            return -1;
        }
        if (n == 0) return -1;
        sent += n;
    }
    return sent;
}

void send_axfr_response(int client_fd, const char *qname, uint8_t *req, uint16_t req_len, tsig_key_t *tsig_key) {
    zone_db_entry_t *entry = get_zone(qname);
    if (!entry) {
        uint8_t res_buf[512];
        size_t copy_len = req_len > 512 ? 512 : req_len;
        memcpy(res_buf, req, copy_len);
        res_buf[2] |= 0x84; res_buf[3] |= 0x05; // REFUSED
        uint8_t len_prefix[2] = { copy_len >> 8, copy_len & 0xFF };
        send(client_fd, len_prefix, 2, 0); send(client_fd, res_buf, copy_len, 0);
        return;
    }
    
    zone_arena_t *current_zone = NULL;
    do {
        current_zone = atomic_load_explicit(&entry->rcu.active, memory_order_acquire);
        atomic_fetch_add_explicit(&current_zone->reader_count, 1, memory_order_acquire);
        if (current_zone == atomic_load_explicit(&entry->rcu.active, memory_order_acquire)) break;
        atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
    } while(1);
    
    if (!current_zone || current_zone->count == 0) {
        atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        return;
    }

    uint8_t *res = malloc(65535);
    
    size_t q_offset = 12;
    while (q_offset < req_len) {
        uint8_t len = req[q_offset];
        if (len == 0) { q_offset++; break; }
        if ((len & 0xC0) == 0xC0) { q_offset += 2; break; }
        q_offset += len + 1;
    }
    q_offset += 4; // QTYPE + QCLASS
    if (q_offset > req_len) q_offset = req_len; // Safe guard

    uint16_t offset = q_offset;
    uint16_t answers = 0;
    uint16_t *res_ancount = (uint16_t *)&res[6];
    
    memcpy(res, req, q_offset);
    res[2] |= 0x84; 
    res[3] &= 0x0F; 

    res[8] = 0; res[9] = 0;   // NSCOUNT = 0
    res[10] = 0; res[11] = 0; // ARCOUNT = 0 
    
    compress_ctx_t comp_ctx;
    memset(&comp_ctx, 0, sizeof(comp_ctx));
    compress_ctx_init_packet(&comp_ctx);

    uint8_t prior_mac[64] = {0};
    size_t prior_mac_len = 0;

    int soa_idx = -1;
    for (size_t i = 0; i < current_zone->count; i++) {
        if (current_zone->records[i].type_code == 6 && strcasecmp(current_zone->records[i].name, entry->domain) == 0) {
            soa_idx = i;
            break;
        }
    }
    if (soa_idx < 0) {
        atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
        if (res) free(res);
        return;
    }

    for (int step = 0; step < 3; step++) {
        size_t start_idx = 0, end_idx = 0;
        if (step == 0) { start_idx = soa_idx; end_idx = soa_idx + 1; }
        else if (step == 1) { start_idx = 0; end_idx = current_zone->count; }
        else if (step == 2) { start_idx = soa_idx; end_idx = soa_idx + 1; }
        
        for (size_t i = start_idx; i < end_idx; i++) {
            if (step == 1 && (int)i == soa_idx) continue;
            dns_record_t *rec = &current_zone->records[i];
            
            uint16_t prev_offset = offset;
            if (serialize_dns_record(res, 65000, &offset, rec, &comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                *res_ancount = htons(answers);
                if (tsig_key) {
                    size_t sign_len = prev_offset;
                    tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, prior_mac, &prior_mac_len);
                    prev_offset = sign_len;
                }
                uint8_t len_prefix[2] = { prev_offset >> 8, prev_offset & 0xFF };
                if (send_tcp_robust(client_fd, len_prefix, 2) < 0) goto axfr_error;
                if (send_tcp_robust(client_fd, res, prev_offset) < 0) goto axfr_error;
                
                offset = q_offset;
                answers = 0;
                memcpy(res, req, q_offset);
                res[2] |= 0x84;
                res[3] &= 0x0F;

                res[8] = 0; res[9] = 0;   // NSCOUNT = 0
                res[10] = 0; res[11] = 0; // ARCOUNT = 0
                
                memset(&comp_ctx, 0, sizeof(comp_ctx));
                compress_ctx_init_packet(&comp_ctx);
                
                if (serialize_dns_record(res, 65000, &offset, rec, &comp_ctx, NULL, 0xFFFFFFFF) < 0) {
                    syslog(LOG_WARNING, "[AXFR] Record %s is too large to fit in a single TCP message, skipping.", rec->name);
                    continue;
                }
            }
            answers++;
        }
    }
    
    if (answers > 0) {
        *res_ancount = htons(answers);
        if (tsig_key) {
            size_t sign_len = offset;
            tsig_sign_packet(res, &sign_len, 65535, tsig_key, 0, prior_mac, &prior_mac_len);
            offset = sign_len;
        }
        uint8_t len_prefix[2] = { offset >> 8, offset & 0xFF };
        if (send_tcp_robust(client_fd, len_prefix, 2) < 0) goto axfr_error;
        if (send_tcp_robust(client_fd, res, offset) < 0) goto axfr_error;
    }
    
axfr_error:
    if (res) free(res);
    atomic_fetch_sub_explicit(&current_zone->reader_count, 1, memory_order_release);
}

void *axfr_worker_thread(void *arg) {
    axfr_worker_args_t *args = (axfr_worker_args_t *)arg;
    zone_db_entry_t *entry = get_zone(args->qname);
    send_axfr_response(args->client_fd, args->qname, args->req, args->req_len, args->tsig_key);
    close(args->client_fd);
    free(args);
    if (entry) atomic_fetch_sub(&entry->active_axfr, 1);
    pthread_exit(NULL);
}

static void init_logging_channels(server_config_t *cfg) {
    log_channel_t *ch = cfg->logging.channels;
    while (ch) {
        if (ch->file_path) {
            ch->fd = open_via_dir_cache(ch->file_path, O_WRONLY | O_CREAT | O_APPEND, 0644, true);
            if (ch->fd >= 0) {
                struct stat st;
                if (fstat(ch->fd, &st) == 0) {
                    ch->current_size = st.st_size;
                }
            } else {
                syslog(LOG_ERR, "Failed to open log file %s: %s", ch->file_path, strerror(errno));
            }
            
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            ch->current_date = (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 + tm_info->tm_mday;
        }
        ch = ch->next;
    }
}

static void free_logging_channels(server_config_t *cfg) {
    log_channel_t *ch = cfg->logging.channels;
    while (ch) {
        log_channel_t *next = ch->next;
        if (ch->fd >= 0) close(ch->fd);
        if (ch->name) free(ch->name);
        if (ch->file_path) free(ch->file_path);
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

static void write_query_log(const char *client_ip, int client_port, const char *qname, uint16_t qclass, uint16_t qtype, bool has_edns, bool dnssec_ok) {
    server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    if (!cfg || !cfg->logging.queries_channel || cfg->logging.queries_channel->fd < 0) return;
    
    log_channel_t *ch = cfg->logging.queries_channel;
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm_info = localtime(&ts.tv_sec);
    int today = (tm_info->tm_year + 1900) * 10000 + (tm_info->tm_mon + 1) * 100 + tm_info->tm_mday;
    
    char time_str[64] = "";
    if (ch->print_time) {
        char buf[32];
        strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S", tm_info);
        snprintf(time_str, sizeof(time_str), "%s.%03ld ", buf, ts.tv_nsec / 1000000);
    }
    
    char class_str[16];
    if (qclass == 1) strcpy(class_str, "IN");
    else if (qclass == 255) strcpy(class_str, "ANY");
    else snprintf(class_str, sizeof(class_str), "CLASS%d", qclass);
    
    const char *type_str_tmp = get_type_str(qtype, NULL);
    char type_str[32];
    if (type_str_tmp) {
        strncpy(type_str, type_str_tmp, sizeof(type_str) - 1);
        type_str[sizeof(type_str) - 1] = '\0';
        if (strncmp(type_str_tmp, "TYPE", 4) == 0) free((void *)type_str_tmp);
    } else {
        snprintf(type_str, sizeof(type_str), "TYPE%d", qtype);
    }
    
    char edns_str[16] = "";
    if (has_edns) {
        snprintf(edns_str, sizeof(edns_str), "+E(0)%s", dnssec_ok ? "D" : "K");
    }
    
    char log_buf[1024];
    int len = snprintf(log_buf, sizeof(log_buf), "%s%s%sclient %s#%d (%s): query: %s %s %s %s\n",
                       time_str,
                       ch->print_category ? "queries: " : "",
                       ch->print_severity ? "info: " : "",
                       client_ip, client_port, qname, qname, class_str, type_str, edns_str);
                       
    if (len <= 0) return;
    if (len >= (int)sizeof(log_buf)) len = sizeof(log_buf) - 1; // snprintfの戻り値は切り詰め前の必要長を返すため、write()に渡す前にクランプする
    
    pthread_mutex_lock(&ch->lock);
    
    bool rotate = false;
    if (ch->size_limit > 0 && ch->current_size + len > ch->size_limit) {
        rotate = true;
    } else if (ch->suffix_timestamp && ch->current_date != today) {
        rotate = true;
    }
    
    if (rotate) {
        close(ch->fd);
        ch->fd = -1;
        int reopen_flags = O_WRONLY | O_CREAT | O_APPEND;

        if (ch->suffix_timestamp) {
            char new_name[600];
            int r = snprintf(new_name, sizeof(new_name), "%s.%08d", ch->file_path, ch->current_date);
            if (r > 0 && r < (int)sizeof(new_name)) {
                if (renameat_via_dir_cache(ch->file_path, new_name) != 0 && errno != ENOENT) {
                    syslog(LOG_WARNING, "Log rotate: rename %s -> %s failed: %s", ch->file_path, new_name, strerror(errno));
                }
            } else {
                syslog(LOG_WARNING, "Log rotate: rotated filename too long for %s, skipping rename", ch->file_path);
            }
        } else if (ch->versions > 0) {
            for (int i = ch->versions - 1; i >= 0; i--) {
                char old_name[600], new_name[600];
                int r1 = (i == 0) ? snprintf(old_name, sizeof(old_name), "%s", ch->file_path)
                                  : snprintf(old_name, sizeof(old_name), "%s.%d", ch->file_path, i - 1);
                int r2 = snprintf(new_name, sizeof(new_name), "%s.%d", ch->file_path, i);
                if (r1 > 0 && r1 < (int)sizeof(old_name) && r2 > 0 && r2 < (int)sizeof(new_name)) {
                    // ENOENT is expected/benign here: not every version slot
                    // exists yet, especially right after startup.
                    renameat_via_dir_cache(old_name, new_name);
                } else {
                    syslog(LOG_WARNING, "Log rotate: rotated filename too long for %s, skipping version %d", ch->file_path, i);
                }
            }
        } else {
            // Fold truncate(2)-by-path into the reopen itself: this avoids a
            // separate pathname-based truncate() call entirely, which is
            // both simpler and required for Capsicum capability mode
            // (truncate(2) is not capability-safe; ftruncate(2) on an
            // already-open fd would be, but we're reopening anyway).
            reopen_flags |= O_TRUNC;
        }

        ch->fd = open_via_dir_cache(ch->file_path, reopen_flags, 0644, true);
        if (ch->fd < 0) {
            syslog(LOG_ERR, "Log rotate: failed to reopen %s: %s", ch->file_path, strerror(errno));
        }
        ch->current_size = 0;
        ch->current_date = today;
    }
    
    if (ch->fd >= 0) {
        ssize_t w = write(ch->fd, log_buf, len);
        if (w > 0) ch->current_size += w;
    }
    
    pthread_mutex_unlock(&ch->lock);
}

void *worker_thread_func(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;

    // CPUピン留め
    cpuset_t cpuset; CPU_ZERO(&cpuset); CPU_SET(ctx->core_id, &cpuset);
    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &cpuset) != 0) {
        syslog(LOG_ERR, "cpuset_setaffinity failed: %s", strerror(errno)); goto worker_startup_failed;
    }
    syslog(LOG_INFO, "Worker %d pinned to Core %d", ctx->thread_id, ctx->core_id);

    int kq = kqueue();
    if (kq < 0) { syslog(LOG_ERR, "kqueue failed: %s", strerror(errno)); goto worker_startup_failed; }
    int opt = 1;
    server_config_t *active_cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    int port = active_cfg && active_cfg->port > 0 ? active_cfg->port : DNS_PORT;
    int bind_count = active_cfg ? active_cfg->bind_address_count : 0;
    
    int created_sockets = 0;
    
    for (int i = 0; i < (bind_count > 0 ? bind_count : 1); i++) {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
        bool is_v4 = false;
        bool is_v6 = false;
        
        if (bind_count == 0) {
            addr4.sin_family = AF_INET; addr4.sin_addr.s_addr = INADDR_ANY; addr4.sin_port = htons(port);
            addr6.sin6_family = AF_INET6; addr6.sin6_addr = in6addr_any; addr6.sin6_port = htons(port);
            is_v4 = true; is_v6 = true;
        } else {
            if (inet_pton(AF_INET, active_cfg->bind_addresses[i], &addr4.sin_addr) == 1) {
                addr4.sin_family = AF_INET; addr4.sin_port = htons(port);
                is_v4 = true;
            } else if (inet_pton(AF_INET6, active_cfg->bind_addresses[i], &addr6.sin6_addr) == 1) {
                addr6.sin6_family = AF_INET6; addr6.sin6_port = htons(port);
                is_v6 = true;
            } else {
                syslog(LOG_WARNING, "Invalid bind-address %s", active_cfg->bind_addresses[i]);
                continue;
            }
        }

        if (is_v4) {
            int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (udp_fd >= 0) {
                int flags = fcntl(udp_fd, F_GETFL, 0); fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK);
#ifdef SO_REUSEPORT_LB
                setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
#else
                setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
                if (bind(udp_fd, (struct sockaddr *)&addr4, sizeof(addr4)) == 0) {
                    limit_server_socket_rights(udp_fd, false);
                    struct kevent ev; EV_SET(&ev, udp_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void*)1);
                    kevent(kq, &ev, 1, NULL, 0, NULL);
                    created_sockets++;
                } else {
                    close(udp_fd);
                }
            }

            int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (tcp_fd >= 0) {
                int flags = fcntl(tcp_fd, F_GETFL, 0); fcntl(tcp_fd, F_SETFL, flags | O_NONBLOCK);
#ifdef SO_REUSEPORT_LB
                setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
#else
                setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
                if (bind(tcp_fd, (struct sockaddr *)&addr4, sizeof(addr4)) == 0) {
                    listen(tcp_fd, 1024);
                    limit_server_socket_rights(tcp_fd, true);
                    struct kevent ev; EV_SET(&ev, tcp_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void*)2);
                    kevent(kq, &ev, 1, NULL, 0, NULL);
                    created_sockets++;
                } else {
                    close(tcp_fd);
                }
            }
        }

        if (is_v6) {
            int udp_fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if (udp_fd >= 0) {
                int flags = fcntl(udp_fd, F_GETFL, 0); fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK);
                setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
#ifdef SO_REUSEPORT_LB
                setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
#else
                setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
                if (bind(udp_fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0) {
                    limit_server_socket_rights(udp_fd, false);
                    struct kevent ev; EV_SET(&ev, udp_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void*)1);
                    kevent(kq, &ev, 1, NULL, 0, NULL);
                    created_sockets++;
                } else {
                    close(udp_fd);
                }
            }

            int tcp_fd = socket(AF_INET6, SOCK_STREAM, 0);
            if (tcp_fd >= 0) {
                int flags = fcntl(tcp_fd, F_GETFL, 0); fcntl(tcp_fd, F_SETFL, flags | O_NONBLOCK);
                setsockopt(tcp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
#ifdef SO_REUSEPORT_LB
                setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT_LB, &opt, sizeof(opt));
#else
                setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
                if (bind(tcp_fd, (struct sockaddr *)&addr6, sizeof(addr6)) == 0) {
                    listen(tcp_fd, 1024);
                    limit_server_socket_rights(tcp_fd, true);
                    struct kevent ev; EV_SET(&ev, tcp_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void*)2);
                    kevent(kq, &ev, 1, NULL, 0, NULL);
                    created_sockets++;
                } else {
                    close(tcp_fd);
                }
            }
        }
    }
    
    if (created_sockets == 0) {
        syslog(LOG_ERR, "No sockets created: %s", strerror(errno)); goto worker_startup_failed;
    }

    atomic_fetch_add(&g_bound_workers, 1);
    goto worker_startup_success;

worker_startup_failed:
    atomic_fetch_add(&g_bound_workers, 1); // prevent main from hanging
    pthread_exit(NULL);

worker_startup_success:
    ;
    // 【ゼロアロケーション】スタックにバッファと名前圧縮の永続コンテキストを配置
    uint8_t req_buf[BUFFER_SIZE], res_buf[BUFFER_SIZE];
    struct sockaddr_storage client_addr; socklen_t client_len = sizeof(client_addr);
    compress_ctx_t thread_compress_ctx = {0};
    struct kevent ev_list[MAX_EVENTS];

    syslog(LOG_INFO, "Worker %d enters event loop...", ctx->thread_id);
    while (1) {
        int n_events = kevent(kq, NULL, 0, ev_list, MAX_EVENTS, NULL);
        if (n_events < 0) { if (errno == EINTR) continue; syslog(LOG_ERR, "kevent wait failed: %s", strerror(errno)); break; }

        for (int i = 0; i < n_events; i++) {
            if (ev_list[i].filter == EVFILT_TIMER) {
                int client_fd = ev_list[i].ident;
                tcp_stream_ctx_t *ctx_tcp = (tcp_stream_ctx_t *)ev_list[i].udata;
                syslog(LOG_WARNING, "[TCP] Idle timeout, closing connection from %s", ctx_tcp->client_ip);
                close(client_fd);
                free(ctx_tcp);
            } else if (ev_list[i].udata == (void*)1) {
                int active_fd = ev_list[i].ident;
                while (1) {
                    client_len = sizeof(client_addr);
                    struct iovec iov = { .iov_base = req_buf, .iov_len = BUFFER_SIZE };
                    struct msghdr msg_hdr = { .msg_name = &client_addr, .msg_namelen = client_len, .msg_iov = &iov, .msg_iovlen = 1 };
                    ssize_t received = recvmsg(active_fd, &msg_hdr, 0);
                    if (received < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; break; }
                    if (msg_hdr.msg_flags & MSG_TRUNC) continue;
                    client_len = msg_hdr.msg_namelen;

                    char client_ip[INET6_ADDRSTRLEN] = "";
                    if (client_addr.ss_family == AF_INET) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)&client_addr)->sin_addr, client_ip, INET6_ADDRSTRLEN);
                    } else if (client_addr.ss_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&client_addr)->sin6_addr, client_ip, INET6_ADDRSTRLEN);
                    }
                    
                    char qname[256] = "";
                    uint16_t qtype = 0;
                    if (received > 12) {
                        size_t offset = 12;
                        size_t recv_len = (size_t)received;
                        size_t written = 0;
                        while (offset < recv_len) {
                            uint8_t len = req_buf[offset];
                            if (len == 0 || (len & 0xC0) == 0xC0) {
                                offset++;
                                break;
                            }
                            offset++;
                            if (written > 0 && qname[written - 1] != '.') {
                                if (written < 255) qname[written++] = '.';
                            }
                            if (offset + len <= recv_len) {
                                size_t copy_len = len;
                                if (written >= 255) {
                                    copy_len = 0;
                                } else if (written + copy_len > 255) {
                                    copy_len = 255 - written;
                                }
                                if (copy_len > 0) {
                                    memcpy(&qname[written], &req_buf[offset], copy_len);
                                    written += copy_len;
                                }
                            }
                            offset += len;
                        }
                        if (offset + 1 < recv_len) {
                            qtype = (req_buf[offset] << 8) | req_buf[offset + 1];
                        }
                        if (written == 0 || (written > 0 && qname[written - 1] != '.')) {
                            if (written < 255) qname[written++] = '.';
                        }
                        qname[written] = '\0';
                    }
                    
                    int client_port = 0;
                    if (client_addr.ss_family == AF_INET) client_port = ntohs(((struct sockaddr_in *)&client_addr)->sin_port);
                    else if (client_addr.ss_family == AF_INET6) client_port = ntohs(((struct sockaddr_in6 *)&client_addr)->sin6_port);
                    uint16_t qclass = 1; bool has_edns = false; bool dnssec_ok = false;
                    if (received > 12) {
                        size_t offset = 12;
                        while (offset < (size_t)received) {
                            uint8_t len = req_buf[offset];
                            if (len == 0 || (len & 0xC0) == 0xC0) { offset += (len == 0) ? 1 : 2; break; }
                            offset += len + 1;
                        }
                        if (offset + 3 < (size_t)received) qclass = (req_buf[offset + 2] << 8) | req_buf[offset + 3];
                        uint16_t arcount = (req_buf[10] << 8) | req_buf[11];
                        if (arcount > 0) {
                            size_t o = 12; uint16_t qd = (req_buf[4]<<8)|req_buf[5]; uint16_t an = (req_buf[6]<<8)|req_buf[7]; uint16_t ns = (req_buf[8]<<8)|req_buf[9];
                            for (int k=0; k<qd; k++) { while(o<(size_t)received && req_buf[o]!=0 && (req_buf[o]&0xC0)!=0xC0) o+=req_buf[o]+1; if(o<(size_t)received&&(req_buf[o]&0xC0)==0xC0) o+=2; else o++; o+=4; }
                            for (int k=0; k<an+ns+arcount; k++) {
                                if (o>=(size_t)received) break;
                                while(o<(size_t)received && req_buf[o]!=0 && (req_buf[o]&0xC0)!=0xC0) o+=req_buf[o]+1; if(o<(size_t)received&&(req_buf[o]&0xC0)==0xC0) o+=2; else o++;
                                if (o+10<=(size_t)received) {
                                    uint16_t rt=(req_buf[o]<<8)|req_buf[o+1]; uint32_t ttl=((uint32_t)req_buf[o+4]<<24)|((uint32_t)req_buf[o+5]<<16)|((uint32_t)req_buf[o+6]<<8)|req_buf[o+7]; uint16_t rdl=(req_buf[o+8]<<8)|req_buf[o+9];
                                    if (rt==41) { has_edns=true; if(ttl&0x00008000) dnssec_ok=true; break; }
                                    o+=10+rdl;
                                } else break;
                            }
                        }
                    }
                    write_query_log(client_ip, client_port, qname, qclass, qtype, has_edns, dnssec_ok);

                    int res_len = process_dns_query(req_buf, received, res_buf, 512, qname, qtype, client_ip, &thread_compress_ctx, false);
                    if (res_len > 0) {
                        if (rrl_check((struct sockaddr *)&client_addr)) {
                            ssize_t sent = sendto(active_fd, res_buf, res_len, 0, (struct sockaddr *)&client_addr, client_len);
                            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                                syslog(LOG_ERR, "UDP sendto failed: %s", strerror(errno));
                            }
                        }
                    }
                }
            } else if (ev_list[i].udata == (void*)2) {
                int active_tcp_fd = ev_list[i].ident;
                while (1) {
                    client_len = sizeof(client_addr);
                    int client_fd = accept(active_tcp_fd, (struct sockaddr *)&client_addr, &client_len);
                    if (client_fd < 0) { if (errno == EAGAIN || errno == EWOULDBLOCK) break; break; }
                    
                    limit_client_socket_rights(client_fd);
                    int cflags = fcntl(client_fd, F_GETFL, 0); fcntl(client_fd, F_SETFL, cflags | O_NONBLOCK);
                    tcp_stream_ctx_t *ctx_tcp = calloc(1, sizeof(tcp_stream_ctx_t));
                    if (!ctx_tcp) { close(client_fd); continue; }
                    
                    struct kevent ev_timeout;
                    EV_SET(&ev_timeout, client_fd, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 15000, ctx_tcp);
                    kevent(kq, &ev_timeout, 1, NULL, 0, NULL);
                    
                    if (client_addr.ss_family == AF_INET) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)&client_addr)->sin_addr, ctx_tcp->client_ip, INET6_ADDRSTRLEN);
                    } else if (client_addr.ss_family == AF_INET6) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&client_addr)->sin6_addr, ctx_tcp->client_ip, INET6_ADDRSTRLEN);
                    }
                    struct kevent ev_client;
                    EV_SET(&ev_client, client_fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, ctx_tcp);
                    kevent(kq, &ev_client, 1, NULL, 0, NULL);
                }
            } else {
                int client_fd = ev_list[i].ident;
                tcp_stream_ctx_t *ctx_tcp = (tcp_stream_ctx_t *)ev_list[i].udata;
                uint8_t *msg; uint16_t msg_len;
                int ret = read_dns_tcp_message(client_fd, ctx_tcp, &msg, &msg_len);
                if (ret < 0) {
                    struct kevent ev_del; EV_SET(&ev_del, client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
                    kevent(kq, &ev_del, 1, NULL, 0, NULL);
                    close(client_fd); free(ctx_tcp);
                } else if (ret == 1) {
                    struct kevent ev_del; EV_SET(&ev_del, client_fd, EVFILT_TIMER, EV_DELETE, 0, 0, NULL);
                    kevent(kq, &ev_del, 1, NULL, 0, NULL);
                    char qname[256] = ""; uint16_t qtype = 0;
                    if (msg_len > 12) {
                        size_t offset = 12; size_t written = 0;
                        while (offset < msg_len) {
                            uint8_t len = msg[offset];
                            if (len == 0 || (len & 0xC0) == 0xC0) { offset++; break; }
                            offset++;
                            if (written > 0 && qname[written - 1] != '.') {
                                if (written < 255) qname[written++] = '.';
                            }
                            if (offset + len <= msg_len) {
                                size_t copy_len = len;
                                if (written >= 255) {
                                    copy_len = 0;
                                } else if (written + copy_len > 255) {
                                    copy_len = 255 - written;
                                }
                                if (copy_len > 0) {
                                    memcpy(&qname[written], &msg[offset], copy_len);
                                    written += copy_len;
                                }
                            }
                            offset += len;
                        }
                        if (offset + 1 < msg_len) qtype = (msg[offset] << 8) | msg[offset + 1];
                        if (written == 0 || (written > 0 && qname[written - 1] != '.')) {
                            if (written < 255) qname[written++] = '.';
                        }
                        qname[written] = '\0';
                    }
                    
                    int client_port = 0;
                    if (client_addr.ss_family == AF_INET) client_port = ntohs(((struct sockaddr_in *)&client_addr)->sin_port);
                    else if (client_addr.ss_family == AF_INET6) client_port = ntohs(((struct sockaddr_in6 *)&client_addr)->sin6_port);
                    uint16_t qclass = 1; bool has_edns = false; bool dnssec_ok = false;
                    if (msg_len > 12) {
                        size_t offset = 12;
                        while (offset < msg_len) {
                            uint8_t len = msg[offset];
                            if (len == 0 || (len & 0xC0) == 0xC0) { offset += (len == 0) ? 1 : 2; break; }
                            offset += len + 1;
                        }
                        if (offset + 3 < msg_len) qclass = (msg[offset + 2] << 8) | msg[offset + 3];
                        uint16_t arcount = (msg[10] << 8) | msg[11];
                        if (arcount > 0) {
                            size_t o = 12; uint16_t qd = (msg[4]<<8)|msg[5]; uint16_t an = (msg[6]<<8)|msg[7]; uint16_t ns = (msg[8]<<8)|msg[9];
                            for (int k=0; k<qd; k++) { while(o<msg_len && msg[o]!=0 && (msg[o]&0xC0)!=0xC0) o+=msg[o]+1; if(o<msg_len&&(msg[o]&0xC0)==0xC0) o+=2; else o++; o+=4; }
                            for (int k=0; k<an+ns+arcount; k++) {
                                if (o>=msg_len) break;
                                while(o<msg_len && msg[o]!=0 && (msg[o]&0xC0)!=0xC0) o+=msg[o]+1; if(o<msg_len&&(msg[o]&0xC0)==0xC0) o+=2; else o++;
                                if (o+10<=msg_len) {
                                    uint16_t rt=(msg[o]<<8)|msg[o+1]; uint32_t ttl=((uint32_t)msg[o+4]<<24)|((uint32_t)msg[o+5]<<16)|((uint32_t)msg[o+6]<<8)|msg[o+7]; uint16_t rdl=(msg[o+8]<<8)|msg[o+9];
                                    if (rt==41) { has_edns=true; if(ttl&0x00008000) dnssec_ok=true; break; }
                                    o+=10+rdl;
                                } else break;
                            }
                        }
                    }
                    write_query_log(ctx_tcp->client_ip, client_port, qname, qclass, qtype, has_edns, dnssec_ok);
                    
                    if (qtype == 252 || qtype == 251) {
                        uint32_t req_serial = 0;
                        if (qtype == 251) {
                            size_t offset = 12;
                            uint16_t qdcount = (msg[4] << 8) | msg[5];
                            uint16_t nscount = (msg[8] << 8) | msg[9];
                            for (int k = 0; k < qdcount; k++) {
                                while (offset < msg_len && msg[offset] != 0 && (msg[offset] & 0xC0) != 0xC0) offset += msg[offset] + 1;
                                if (offset < msg_len && (msg[offset] & 0xC0) == 0xC0) offset += 2; else offset++;
                                offset += 4;
                            }
                            if (nscount > 0 && offset + 10 <= msg_len) {
                                while (offset < msg_len && msg[offset] != 0 && (msg[offset] & 0xC0) != 0xC0) offset += msg[offset] + 1;
                                if (offset < msg_len && (msg[offset] & 0xC0) == 0xC0) offset += 2; else offset++;
                                uint16_t rr_type = (msg[offset] << 8) | msg[offset + 1];
                                offset += 8;
                                uint16_t rdlen = (msg[offset] << 8) | msg[offset + 1];
                                offset += 2;
                                if (rr_type == 6 && offset + rdlen <= msg_len) {
                                    size_t ptr = offset;
                                    while (ptr < msg_len && msg[ptr] != 0 && (msg[ptr] & 0xC0) != 0xC0) ptr += msg[ptr] + 1;
                                    if (ptr < msg_len && (msg[ptr] & 0xC0) == 0xC0) ptr += 2; else ptr++;
                                    while (ptr < msg_len && msg[ptr] != 0 && (msg[ptr] & 0xC0) != 0xC0) ptr += msg[ptr] + 1;
                                    if (ptr < msg_len && (msg[ptr] & 0xC0) == 0xC0) ptr += 2; else ptr++;
                                    if (ptr + 4 <= msg_len) {
                                        req_serial = (msg[ptr] << 24) | (msg[ptr+1] << 16) | (msg[ptr+2] << 8) | msg[ptr+3];
                                    }
                                }
                            }
                            syslog(LOG_NOTICE, "[IXFR->AXFR fallback] zone=%s client=%s requested_serial=%u (no incremental journal available)", qname, ctx_tcp->client_ip, req_serial);
                        }

                        server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
                        zone_config_t *zcfg = cfg->zones;
                        while(zcfg) { if (strcasecmp(zcfg->domain, qname)==0) break; zcfg = zcfg->next; }
                        
                        bool allowed = false;
                        uint16_t tsig_error = 0;
                        tsig_key_t *matched_key = NULL;

                        if (zcfg) {
                            if (zcfg->tsig_key) {
                                tsig_key_t *k = cfg->keys;
                                while (k) {
                                    if (strcmp(k->name, zcfg->tsig_key) == 0) { matched_key = k; break; }
                                    k = k->next;
                                }
                                if (!matched_key) {
                                    syslog(LOG_ERR, "Zone %s requires TSIG key '%s' but it is not defined in config", qname, zcfg->tsig_key);
                                    tsig_error = 17; // BADKEY
                                } else {
                                    int err = tsig_verify_packet(msg, msg_len, matched_key);
                                    if (err != 0) {
                                        tsig_error = err > 0 ? err : 16;
                                    } else {
                                        allowed = true;
                                    }
                                }
                            } else if (zcfg->allow_transfer_count > 0) {
                                for(int k=0; k<zcfg->allow_transfer_count; k++) {
                                    if (match_cidr(ctx_tcp->client_ip, zcfg->allow_transfer[k])) { allowed = true; break; }
                                }
                            } else {
                                allowed = false;
                            }
                        }
                        
                        zone_db_entry_t *entry = get_zone(qname);
                        if (allowed && entry) {
                            if (atomic_fetch_add(&entry->active_axfr, 1) >= MAX_ZONE_AXFR) {
                                atomic_fetch_sub(&entry->active_axfr, 1);
                                syslog(LOG_WARNING, "AXFR request dropped for zone %s: MAX_ZONE_AXFR reached", qname);
                                allowed = false; // fallthrough to REFUSED
                            } else {
                                axfr_worker_args_t *args = malloc(sizeof(axfr_worker_args_t));
                                if (args) {
                                    args->client_fd = client_fd;
                                    strncpy(args->qname, qname, 255); args->qname[255] = '\0';
                                    args->req_len = msg_len > 512 ? 512 : msg_len;
                                    memcpy(args->req, msg, args->req_len);
                                    args->tsig_key = matched_key;
                                    
                                    // Disable O_NONBLOCK for background worker so it can use standard blocking send
                                    int cflags = fcntl(client_fd, F_GETFL, 0);
                                    fcntl(client_fd, F_SETFL, cflags & ~O_NONBLOCK);
                                    
                                    pthread_t t;
                                    if (pthread_create(&t, NULL, axfr_worker_thread, args) != 0) {
                                        syslog(LOG_ERR, "Failed to spawn AXFR thread");
                                        free(args);
                                        atomic_fetch_sub(&entry->active_axfr, 1);
                                        close(client_fd);
                                    } else {
                                        pthread_detach(t);
                                    }
                                } else {
                                    atomic_fetch_sub(&entry->active_axfr, 1);
                                    close(client_fd);
                                }
                            }
                        }
                        
                        if (!allowed || !entry) {
                            if (!entry) syslog(LOG_NOTICE, "AXFR REFUSED: Zone %s not found", qname);
                            else if (tsig_error) syslog(LOG_NOTICE, "AXFR NOTAUTH: TSIG error %d for %s", tsig_error, ctx_tcp->client_ip);
                            else syslog(LOG_NOTICE, "AXFR REFUSED: Access denied for %s", ctx_tcp->client_ip);
                            
                            uint8_t res_buf[1024];
                            size_t copy_len = msg_len > 512 ? 512 : msg_len;
                            memcpy(res_buf, msg, copy_len);
                            if (tsig_error) {
                                res_buf[2] |= 0x84; res_buf[3] |= 0x09; // NOTAUTH
                                if (matched_key) {
                                    tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf), matched_key, tsig_error, NULL, NULL);
                                } else {
                                    tsig_key_t dummy = {0};
                                    dummy.name = zcfg->tsig_key;
                                    dummy.algorithm = "hmac-sha256";
                                    tsig_sign_packet(res_buf, &copy_len, sizeof(res_buf), &dummy, 17, NULL, NULL); // BADKEY
                                }
                            } else {
                                res_buf[2] |= 0x84; res_buf[3] |= 0x05; // REFUSED
                            }
                            uint8_t len_prefix[2] = { copy_len >> 8, copy_len & 0xFF };
                            send(client_fd, len_prefix, 2, 0); send(client_fd, res_buf, copy_len, 0);
                            close(client_fd);
                        }
                        free(ctx_tcp);
                    } else {
                        // Max TCP DNS length is 65535
                        uint8_t *tcp_res = malloc(65535);
                        if (tcp_res) {
                            int res_len = process_dns_query(msg, msg_len, tcp_res, 65535, qname, qtype, ctx_tcp->client_ip, &thread_compress_ctx, true);
                            if (res_len > 0) {
                                uint8_t len_prefix[2] = { res_len >> 8, res_len & 0xFF };
                                send(client_fd, len_prefix, 2, 0);
                                send(client_fd, tcp_res, res_len, 0);
                            }
                            free(tcp_res);
                        }
                        close(client_fd); free(ctx_tcp);
                    }
                }
            }
        }
    }
    close(kq); pthread_exit(NULL);
}

// ============================================================================
// 11. Control Thread
// ============================================================================
void *control_thread_func(void *arg) {
    (void)arg;
    int kq = kqueue();
    if (kq < 0) { syslog(LOG_ERR, "control thread kqueue failed: %s", strerror(errno)); pthread_exit(NULL); }
    g_control_kq = kq;

    struct kevent ev_set[3];
    EV_SET(&ev_set[0], SIGHUP, EVFILT_SIGNAL, EV_ADD | EV_CLEAR, 0, 0, NULL);
    EV_SET(&ev_set[1], 1, EVFILT_TIMER, EV_ADD | EV_CLEAR, 0, 1000, NULL); // 1 second
    EV_SET(&ev_set[2], 2, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    
    if (kevent(kq, ev_set, 3, NULL, 0, NULL) == -1) {
        syslog(LOG_ERR, "control thread kevent failed: %s", strerror(errno));
        close(kq); pthread_exit(NULL);
    }

    struct kevent ev_list[4];
    while (1) {
        int n = kevent(kq, NULL, 0, ev_list, 4, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < n; i++) {
            if (ev_list[i].filter == EVFILT_SIGNAL && ev_list[i].ident == SIGHUP) {
                syslog(LOG_INFO, "[Control] SIGHUP received. Reloading config...");
                char *config_str = read_entire_file(g_config_path);
                if (!config_str) {
                    syslog(LOG_NOTICE, "Failed to read config file on reload");
                    continue;
                }
                
                server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
                server_config_t *standby = (active == &g_config_db.config_a) ? &g_config_db.config_b : &g_config_db.config_a;
                
                for (int j = 0; j < standby->bind_address_count; j++) free(standby->bind_addresses[j]);
                free(standby->bind_addresses); standby->bind_addresses = NULL; standby->bind_address_count = 0;
                zone_config_t *curr = standby->zones;
                while(curr) { zone_config_t *next = curr->next; free_zone_config(curr); curr = next; }
                standby->zones = NULL;
                free_logging_channels(standby);
                
                if (parse_named_conf(config_str, standby) == 0) {
                    init_logging_channels(standby);
                    atomic_store_explicit(&g_config_db.active, standby, memory_order_release);
                    
                    // Zone reload
                    load_zones_from_config(standby);

                    syslog(LOG_INFO, "[Control] Config hot-reloaded successfully.");
                    syslog(LOG_NOTICE, "Config hot-reloaded successfully.");
                    zone_config_t *z = standby->zones;
                    while (z) {
                        syslog(LOG_NOTICE, "Loaded DNS zone: %s (type: %s)", z->domain, z->type ? z->type : "unknown");
                        z = z->next;
                    }
                } else {
                    syslog(LOG_INFO, "[Control] Config reload failed. Keeping old config.");
                }
                free(config_str);
            } else if (ev_list[i].filter == EVFILT_TIMER || ev_list[i].filter == EVFILT_USER) {
                time_t now = time(NULL);
                server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
                zone_config_t *zone = active->zones;
                while (zone) {
                    if (zone->type && strcasecmp(zone->type, "slave") == 0 && zone->masters_count > 0 && zone->masters[0].ip != NULL) {
                        zone_db_entry_t *entry = get_or_create_zone(zone->domain);
                        if (entry) {
                            bool force = atomic_exchange_explicit(&entry->refresh_now, false, memory_order_acquire);
                            if (force || entry->next_check == 0 || (entry->next_check > 0 && now >= entry->next_check)) {
                                bool expected = false;
                                if (atomic_compare_exchange_strong_explicit(&entry->is_transferring, &expected, true, memory_order_acquire, memory_order_relaxed)) {
                                    entry->next_check = now + (entry->retry ? entry->retry : 60);
                                    axfr_bg_ctx_t *bg_ctx = calloc(1, sizeof(axfr_bg_ctx_t));
                                    if (bg_ctx) {
                                        strncpy(bg_ctx->master_ip, zone->masters[0].ip, sizeof(bg_ctx->master_ip) - 1);
                                        bg_ctx->master_ip[sizeof(bg_ctx->master_ip) - 1] = '\0';
                                        bg_ctx->master_port = zone->masters[0].port;
                                        if (zone->domain) {
                                            strncpy(bg_ctx->domain, zone->domain, sizeof(bg_ctx->domain) - 1);
                                            bg_ctx->domain[sizeof(bg_ctx->domain) - 1] = '\0';
                                        } else {
                                            bg_ctx->domain[0] = '\0';
                                        }
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
                    zone = zone->next;
                }
            }
        }
    }
    close(kq); pthread_exit(NULL);
}

// ============================================================================
// 12. メインエントリーポイント
// ============================================================================

static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) { syslog(LOG_ERR, "fork failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
    if (pid > 0) exit(EXIT_SUCCESS); // Parent exits
    
    if (setsid() < 0) { syslog(LOG_ERR, "setsid failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
    
    pid = fork();
    if (pid < 0) { syslog(LOG_ERR, "fork 2 failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
    if (pid > 0) exit(EXIT_SUCCESS); // Parent exits
    
    if (chdir("/") < 0) { syslog(LOG_ERR, "chdir failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    int fd = open("/dev/null", O_RDWR);
    if (fd != STDIN_FILENO) return;
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);

    // Defense-in-depth: these three descriptors now only ever need to be
    // read from / written to as /dev/null placeholders, never re-opened,
    // seeked meaningfully, or used for anything socket- or path-related.
    cap_rights_t io_rights;
    cap_rights_init(&io_rights, CAP_READ, CAP_WRITE, CAP_FSTAT);
    for (int stdio_fd = STDIN_FILENO; stdio_fd <= STDERR_FILENO; stdio_fd++) {
        if (cap_rights_limit(stdio_fd, &io_rights) != 0 && errno != ENOSYS) {
            // Non-fatal: some environments may have redirected stdio to
            // something these rights don't cover; just log and continue.
            syslog(LOG_WARNING, "cap_rights_limit failed for stdio fd=%d: %s", stdio_fd, strerror(errno));
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        syslog(LOG_ERR, "Usage: %s <config_file>", argv[0]);
        return 1;
    }
    g_cwd_fd = open(".", O_DIRECTORY | O_CLOEXEC | O_RDONLY);
    if (g_cwd_fd < 0) syslog(LOG_WARNING, "Failed to open current directory, relative paths may not work");
    else {
        // g_cwd_fd is only ever used as the base for openat() when
        // resolving *other* directories referenced (directly or relatively)
        // from named.conf, during the pre-sandbox phase. Limit it to
        // lookup/read/stat now so it cannot be (mis)used for anything else,
        // and it remains a harmless, inert fd after cap_enter().
        cap_rights_t cwd_rights;
        cap_rights_init(&cwd_rights, CAP_LOOKUP, CAP_READ, CAP_FSTAT);
        if (cap_rights_limit(g_cwd_fd, &cwd_rights) != 0 && errno != ENOSYS) {
            syslog(LOG_WARNING, "cap_rights_limit failed for g_cwd_fd: %s", strerror(errno));
        }
    }
    
    g_config_path = argv[1];
    openlog("my_dns", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    daemonize();
    syslog(LOG_NOTICE, "my_dns server starting up");

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);
    sigprocmask(SIG_BLOCK, &set, NULL);

    char *config_str = read_entire_file(g_config_path);
    if (!config_str) {
        syslog(LOG_ERR, "Failed to read config file: %s", strerror(errno));
        return 1;
    }
    
    if (parse_named_conf(config_str, &g_config_db.config_a) != 0) { 
        syslog(LOG_INFO, "Config initialization failed."); 
        free(config_str);
        return 1; 
    }
    free(config_str);

    init_logging_channels(&g_config_db.config_a);

    atomic_init(&g_config_db.active, &g_config_db.config_a);
    syslog(LOG_INFO, "[Init] config loaded. Port: %d, Listen: %s", g_config_db.config_a.port, g_config_db.config_a.bind_address_count > 0 ? g_config_db.config_a.bind_addresses[0] : "ANY");
    syslog(LOG_NOTICE, "Config loaded. Port: %d, Listen: %s", g_config_db.config_a.port, g_config_db.config_a.bind_address_count > 0 ? g_config_db.config_a.bind_addresses[0] : "ANY");
    
    zone_config_t *z = g_config_db.config_a.zones;
    while (z) {
        syslog(LOG_NOTICE, "Loaded DNS zone: %s (type: %s)", z->domain, z->type ? z->type : "unknown");

        z = z->next;
    }

    // 2. RCUの初期データ設定 (初期状態では面Aを指す)
    load_zones_from_config(&g_config_db.config_a);

    // 3. ロガースレッドとコントロールスレッド生成
    pthread_t control_thread;
    if (pthread_create(&control_thread, NULL, control_thread_func, NULL) != 0) { syslog(LOG_ERR, "control thread failed: %s", strerror(errno)); exit(1); }

    // 4. ワーカースレッド群の生成・実行
    
    int num_workers = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_workers <= 0) num_workers = 2;
    pthread_t *threads = calloc(num_workers, sizeof(pthread_t));
    worker_ctx_t *ctxs = calloc(num_workers, sizeof(worker_ctx_t));
    if (!threads || !ctxs) { syslog(LOG_ERR, "Failed to alloc workers"); exit(1); }
    for (int i = 0; i < num_workers; i++) {
        ctxs[i].thread_id = i; ctxs[i].core_id = i % num_workers;

        if (pthread_create(&threads[i], NULL, worker_thread_func, &ctxs[i]) != 0) {
            syslog(LOG_ERR, "pthread_create failed: %s", strerror(errno)); exit(EXIT_FAILURE);
        }
    }

    while (atomic_load(&g_bound_workers) < num_workers) {
        sched_yield();
    }

    server_config_t *cfg = &g_config_db.config_a;
    if (cfg->user) {
        struct passwd *pwd = getpwnam(cfg->user);
        if (!pwd) { syslog(LOG_ERR, "User %s not found", cfg->user); exit(EXIT_FAILURE); }
        gid_t target_gid = pwd->pw_gid;
        if (cfg->group) {
            struct group *grp = getgrnam(cfg->group);
            if (!grp) { syslog(LOG_ERR, "Group %s not found", cfg->group); exit(EXIT_FAILURE); }
            target_gid = grp->gr_gid;
        }
        if (setgroups(0, NULL) != 0) { syslog(LOG_ERR, "setgroups failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
        if (setgid(target_gid) != 0) { syslog(LOG_ERR, "setgid failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
        if (setuid(pwd->pw_uid) != 0) { syslog(LOG_ERR, "setuid failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
    } else if (cfg->group) {
        struct group *grp = getgrnam(cfg->group);
        if (!grp) { syslog(LOG_ERR, "Group %s not found", cfg->group); exit(EXIT_FAILURE); }
        if (setgroups(0, NULL) != 0) { syslog(LOG_ERR, "setgroups failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
        if (setgid(grp->gr_gid) != 0) { syslog(LOG_ERR, "setgid failed: %s", strerror(errno)); exit(EXIT_FAILURE); }
    }
    syslog(LOG_NOTICE, "Successfully dropped privileges");

    // At this point:
    //  - every listening socket has already been created and bound (we
    //    waited on g_bound_workers above),
    //  - the initial config, all master zone files, and all log files have
    //    already been opened at least once (their directories are cached),
    //  - uid/gid have already been dropped.
    // It is now safe to enter Capsicum capability mode for the whole
    // process. Any subsequent SIGHUP config reload can still re-read
    // already-known config/zone/log files and re-open log files for
    // rotation, but cannot open any path in a directory we haven't already
    // seen (see get_or_open_dir_fd()).
    enter_capsicum_sandbox();

    // クリーンアップ用ループ待機
    for (int i = 0; i < num_workers; i++) pthread_join(threads[i], NULL);
    pthread_join(control_thread, NULL);

    // 後処理
    server_config_t *active = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    for (int i = 0; i < active->bind_address_count; i++) free(active->bind_addresses[i]);
    free(active->bind_addresses);
    active->bind_address_count = 0;
    zone_config_t *curr = active->zones;
    while(curr) { zone_config_t *next = curr->next; free_zone_config(curr); curr = next; }
    return 0;
}