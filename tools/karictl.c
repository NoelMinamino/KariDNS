#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/ucred.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../dns_wire.h"
#include "../dns_utils.h"

#ifndef explicit_bzero
#if defined(OPENSSL_VERSION_NUMBER)
#define explicit_bzero(ptr, len) OPENSSL_cleanse(ptr, len)
#else
static inline void karictl_explicit_bzero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
}
#define explicit_bzero karictl_explicit_bzero
#endif
#endif

char *karictl_read_entire_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long len = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (len < 0) { fclose(f); return NULL; }
  char *buf = malloc(len + 1);
  if (!buf) { fclose(f); return NULL; }
  fread(buf, 1, len, f);
  buf[len] = '\0';
  fclose(f);
  return buf;
}

/* 設定ファイル中で、コメント (# // /＊ ＊/) と引用符内の文字列を除いた最初の単語 word を探し、
 * その直後を返す。サンプルの説明コメントに書かれた secret "..."; や socket "..."; を拾わないため。 */
static char *karictl_find_word(char *cfg, const char *word) {
    size_t wl = strlen(word);
    char *p = cfg;
    while (*p) {
        if (*p == '#' || (*p == '/' && p[1] == '/')) {
            while (*p && *p != '\n') p++;
        } else if (*p == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(*p == '*' && p[1] == '/')) p++;
            if (*p) p += 2;
        } else if (*p == '"') {
            p++;
            while (*p && *p != '"') p++;
            if (*p) p++;
        } else if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '{' || *p == '}' || *p == ';') {
            p++;
        } else {
            char *start = p;
            while (*p && !strchr(" \t\r\n{};\"#", *p) && !(*p == '/' && (p[1] == '/' || p[1] == '*'))) p++;
            if ((size_t)(p - start) == wl && memcmp(start, word, wl) == 0) return p;
        }
    }
    return NULL;
}

char* extract_secret_from_config(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (st.st_mode & (S_IRGRP | S_IROTH)) {
            fprintf(stderr, "[WARNING] %s is readable by group/other users; "
                            "this file contains a shared secret and should be "
                            "mode 0600 (owner read/write only)\n", path);
        }
    }

    char *cfg = karictl_read_entire_file(path);
    if (!cfg) return NULL;
    
    char *secret = NULL;
    char *p = karictl_find_word(cfg, "secret");
    if (p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') {
            p++;
            char *end = strchr(p, '"');
            if (end) {
                size_t secret_len = end - p;
                if (secret_len > 4096) {
                    secret_len = 4096;
                }
                *end = '\0';
                secret = strndup(p, secret_len);
                if (!secret) {
                    free(cfg);
                    return NULL;
                }
            }
        }
    }
    free(cfg);
    return secret;
}

char* extract_socket_from_config(const char* path) {
    char *cfg = karictl_read_entire_file(path);
    if (!cfg) return NULL;
    
    char *sock = NULL;
    char *p = karictl_find_word(cfg, "socket");
    if (p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (*p == '"') {
            p++;
            char *end = strchr(p, '"');
            if (end) {
                size_t sock_len = end - p;
                if (sock_len > 1024) {
                    sock_len = 1024;
                }
                *end = '\0';
                sock = strndup(p, sock_len);
            }
        }
    }
    free(cfg);
    return sock;
}

/* karictl.conf の algorithm を読む (引用符付き・無しの両方)。未指定なら NULL。
 * secret/socket と同じく、ファイル中で最初に現れる "algorithm" の値を使う。 */
char* extract_algorithm_from_config(const char* path) {
    char *cfg = karictl_read_entire_file(path);
    if (!cfg) return NULL;

    char *alg = NULL;
    char *p = karictl_find_word(cfg, "algorithm");
    if (p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        bool quoted = (*p == '"');
        if (quoted) p++;
        size_t n = 0;
        while (p[n] && n < 64 &&
               (quoted ? p[n] != '"' : (p[n] != ';' && p[n] != ' ' && p[n] != '\t' && p[n] != '\n' && p[n] != '\r'))) {
            n++;
        }
        if (n > 0 && n < 64) alg = strndup(p, n);
    }
    free(cfg);
    return alg;
}

/* 制御チャネルの HMAC。karidns 側 (dns_wire.c の TSIG アルゴリズム表) と同じ名前を受け付ける。 */
const EVP_MD *karictl_hmac_md(const char *alg) {
    if (!alg) return EVP_sha256();
    size_t len = strlen(alg);
    if (len > 0 && alg[len - 1] == '.') len--;   // "hmac-sha256." のような FQDN 形式も許す
    static const struct { const char *name; const EVP_MD *(*fn)(void); } tbl[] = {
        { "hmac-md5.sig-alg.reg.int", EVP_md5 },
        { "hmac-md5",    EVP_md5    },
        { "hmac-sha1",   EVP_sha1   },
        { "hmac-sha224", EVP_sha224 },
        { "hmac-sha256", EVP_sha256 },
        { "hmac-sha384", EVP_sha384 },
        { "hmac-sha512", EVP_sha512 },
    };
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++) {
        if (strlen(tbl[i].name) == len && strncasecmp(alg, tbl[i].name, len) == 0) return tbl[i].fn();
    }
    return NULL;
}

/* -t: how long karictl waits for each piece of the server's reply (SO_RCVTIMEO on the control socket; rndc -t, default 60 s).  Without a
 * limit a server that accepted the connection and never answered held karictl for ever (seen in the fault-injection sweep, PR #175). */
static int g_reply_timeout = 60;
static bool g_timeout_told;
static ssize_t ctl_recv(int sock, void *buf, size_t len) {
    ssize_t r = recv(sock, buf, len, 0);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && !g_timeout_told) {
        g_timeout_told = true;
        fprintf(stderr, "karictl: no reply from the server within %d s (-t sets the limit)\n", g_reply_timeout);
    }
    return r;
}

static void karictl_usage(FILE *fp, const char *argv0) {
    fprintf(fp, "Usage: %s [-c config_path] [-f config_path] [-s socket_path] [-t seconds] [-v] <command> [args...]\n", argv0);
    fprintf(fp, "  -t seconds                  how long to wait for the server's reply (1-86400, default 60)\n");
    fprintf(fp,
        "Commands:\n"
        "  status                      server status\n"
        "  reload                      reload the configuration and the zone files, then ask the database loader to compare\n"
        "                              its databases with the zones served (the reply returns at once: karictl dbstatus)\n"
        "  reload <zone> [view] [force]\n"
        "                              read one zone again: a zone file, or a zone of the database.  For a database zone the\n"
        "                              reply is the loader's answer (applied, unchanged, hidden, deleted, rejected, failed);\n"
        "                              force sends it even when its content is the one the server already has (not a zone\n"
        "                              that is out of memory: the next query reads it anyway).  A zone that was\n"
        "                              just added to the database is found by its name; with several views that take\n"
        "                              database zones and none named, every one is asked (one reply line)\n"
        "  reconfig                    reload the configuration only\n"
        "  stop                        stop the server\n"
        "  notify <zone> [view]        send NOTIFY for the zone now (zone files and database zones)\n"
        "  retransfer <zone> [view]    transfer a secondary zone again (a database zone is a primary: use reload)\n"
        "  rollback <zone> [view] [local]\n"
        "                              publish the version that was served before the last reload of the zone file (or the\n"
        "                              last install from the database) again, with SOA serial = the current serial + 1, so\n"
        "                              that the secondaries follow (IXFR, NOTIFY).  A primary zone only; the previous\n"
        "                              version is kept for rollback-window (default 1h); a signed zone is refused (roll\n"
        "                              back in the database and sign again), except with local: the old version, with its\n"
        "                              old serial, on this server only (the secondaries do not follow).  Once per reload:\n"
        "                              a second rollback is refused.  zonestatus shows 'rolled back (serial N, from M)'\n"
        "  zonestatus <zone> [view]    serial of the zone; a database zone also shows its source id and last result\n"
        "  observatory [zone] [view]   per-zone statistics\n"
        "  stats [-f prometheus|json] [zone [view]] [--zones PATTERN] [--limit N] [--after CURSOR]\n"
        "                              the counters of the server, its views and zones as Prometheus text (default) or JSON.\n"
        "                              Zones come in pages, in the order of the server's zone tables (not alphabetical):\n"
        "                              --zones is a glob (example.*), --limit stops after N zones and prints the cursor to\n"
        "                              go on with (--after).  -f here is the format; before the command it is the\n"
        "                              configuration file\n"
        "  dbstatus [zone [view]]      the database loader, the last batch, the zones of the database\n"
        "  tsig-keygen [keyname]       print a TSIG key\n"
        "Examples:\n"
        "  karictl reload example.test\n"
        "  karictl reload example.test force\n"
        "  karictl zonestatus example.test\n"
        "  karictl rollback example.test\n"
        "  karictl stats > /var/tmp/node_exporter/karidns.prom.$$ && mv /var/tmp/node_exporter/karidns.prom.$$ /var/tmp/node_exporter/karidns.prom\n"
        "  karictl stats -f json example.test\n"
        "  karictl stats --zones '*.example.test' --limit 100\n"
        "A zone name that exists in several views needs the view name after it: reload <zone> <view> [force]\n");
}

/* Connect to the control socket and authenticate (challenge/response HMAC).  Returns the descriptor, or -1 with the exit code in *rc.
 * One connection carries one command: a command that needs several (karictl stats pages) calls this again. */
static int karictl_open_session(const char *conf_path, const char *cli_sock_path, int *rc) {
    char *secret_b64 = extract_secret_from_config(conf_path);
    if (!secret_b64) {
        fprintf(stderr, "Could not read secret from %s\n", conf_path);
        *rc = 2; return -1;
    }

    size_t b64_len = strlen(secret_b64);
    if (b64_len > 341) { // 256*4/3 safe upper bound to prevent stack-buffer-overflow
        fprintf(stderr, "Secret in config too long (max ~341 base64 chars)\n");
        explicit_bzero(secret_b64, b64_len);
        free(secret_b64);
        *rc = 2; return -1;
    }

    uint8_t secret_decoded[256];
    int len = EVP_DecodeBlock(secret_decoded, (const unsigned char *)secret_b64, (int)b64_len);
    if (len < 0) {
        fprintf(stderr, "Failed to decode base64 secret\n");
        explicit_bzero(secret_b64, b64_len);
        free(secret_b64);
        *rc = 2; return -1;
    }
    int padding = 0;
    size_t pl = b64_len;   // EVP_DecodeBlock は前後の空白を読み飛ばす: '=' は空白を除いた末尾で数える (karidns 側の b64_padding と同じ)
    while (pl > 0 && isspace((unsigned char)secret_b64[pl - 1])) pl--;
    if (pl > 0 && secret_b64[pl - 1] == '=') padding++;
    if (pl > 1 && secret_b64[pl - 2] == '=') padding++;
    size_t secret_decoded_len = len - padding;
    explicit_bzero(secret_b64, b64_len);
    free(secret_b64);

    /* karidns の control-channel { algorithm } と同じアルゴリズムを使う (省略時 hmac-sha256) */
    char *cfg_alg = extract_algorithm_from_config(conf_path);
    const EVP_MD *hmac_md = karictl_hmac_md(cfg_alg);
    if (!hmac_md) {
        fprintf(stderr, "Unsupported algorithm '%s' in %s (expected hmac-md5, hmac-sha1, hmac-sha224, "
                        "hmac-sha256, hmac-sha384 or hmac-sha512)\n", cfg_alg, conf_path);
        free(cfg_alg);
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        *rc = 2; return -1;
    }
    free(cfg_alg);

    char *cfg_sock = extract_socket_from_config(conf_path);
    const char *target_sock = cli_sock_path ? cli_sock_path :
                              (cfg_sock ? cfg_sock : "/var/run/karidns/control.sock");
    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    if (strlen(target_sock) >= sizeof(un.sun_path)) {
        fprintf(stderr, "Control socket path too long (max %zu bytes): %s\n", sizeof(un.sun_path) - 1, target_sock);
        if (cfg_sock) free(cfg_sock);
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        *rc = 1; return -1;
    }
    strncpy(un.sun_path, target_sock, sizeof(un.sun_path) - 1);
    un.sun_path[sizeof(un.sun_path) - 1] = '\0';
    if (cfg_sock) {
        free(cfg_sock);
        cfg_sock = NULL;
    }

    int sock = -1;
    int conn_res = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            explicit_bzero(secret_decoded, sizeof(secret_decoded));
            *rc = 1; return -1;
        }
        if (connect(sock, (struct sockaddr *)&un, sizeof(un)) == 0) {
            conn_res = 0;
            break;
        }
        close(sock);
        sock = -1;
        if ((errno == ECONNREFUSED || errno == EAGAIN) && attempt < 9) {
            usleep(25000); // 25ms backoff on connection congestion
            continue;
        }
        break;
    }

    if (conn_res < 0) {
        perror("connect");
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        *rc = 1; return -1;
    }
    struct timeval rtv = { .tv_sec = g_reply_timeout, .tv_usec = 0 };
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv)) != 0) {
        perror("setsockopt(SO_RCVTIMEO)");
        close(sock);
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        *rc = 1; return -1;
    }

    char buf[1024];
    ssize_t r = ctl_recv(sock, buf, sizeof(buf) - 1);
    if (r <= 0) {
        fprintf(stderr, "Failed to receive challenge\n");
        close(sock);
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        *rc = 1; return -1;
    }
    buf[r] = '\0';

    if (strncmp(buf, "CHALLENGE ", 10) != 0) {
        fprintf(stderr, "Invalid challenge format\n");
        close(sock);
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        *rc = 2; return -1;
    }

    char *challenge = buf + 10;
    char *nl = strchr(challenge, '\n');
    size_t challenge_len = (size_t)(nl ? (nl - challenge) : (buf + r - challenge));

#define EXPECTED_CHALLENGE_LEN 64
    if (challenge_len != EXPECTED_CHALLENGE_LEN) {
        fprintf(stderr, "Invalid challenge length: %zu\n", challenge_len);
        close(sock);
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        *rc = 2; return -1;
    }

    if (nl) *nl = '\0';

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (!HMAC(hmac_md, secret_decoded, secret_decoded_len,
              (unsigned char*)challenge, challenge_len, md, &md_len)) {
        fprintf(stderr, "HMAC computation failed\n");
        explicit_bzero(secret_decoded, sizeof(secret_decoded));
        close(sock);
        *rc = 2; return -1;
    }
    explicit_bzero(secret_decoded, sizeof(secret_decoded));

    char auth_msg[256];
    char expected[2 * EVP_MAX_MD_SIZE + 1];
    for(unsigned int k=0; k<md_len; k++) snprintf(&expected[k*2], 3, "%02x", md[k]);
    expected[2 * md_len] = '\0';
    
    int mlen = snprintf(auth_msg, sizeof(auth_msg), "AUTH %s\n", expected);
    send(sock, auth_msg, mlen, 0);

    r = ctl_recv(sock, buf, sizeof(buf) - 1);
    if (r <= 0) {
        fprintf(stderr, "Failed to receive auth response\n");
        close(sock);
        *rc = 2; return -1;
    }
    buf[r] = '\0';

    if (strncmp(buf, "OK", 2) != 0) {
        fprintf(stderr, "Authentication failed: %s", buf);
        close(sock);
        *rc = 2; return -1;
    }
    return sock;
}

/* ---- karictl stats (0.6.1): the counters of the server, its views and zones as Prometheus text (default; node_exporter textfile collector) or JSON ----
 * The formatting is done here from the binary snapshots the server sends (`status`, `stats`, `observatory`, `obspage`); the zones come in pages
 * (one connection each: a connection carries one command), so that a server with a million zones never builds one reply. */
#define STATS_PAGE 2000
#define STATS_VIEWS_MAX 64
#define STATS_VIEW_NAME_MAX 64
_Static_assert(sizeof(((zone_observatory_snapshot_t *)0)->view_name) == STATS_VIEW_NAME_MAX, "view name buffers must match");

typedef struct {
    bool json;
    const char *zone, *view;          /* karictl stats <zone> [view] */
    const char *pattern;              /* --zones */
    unsigned long limit;              /* --limit, 0 = all */
    const char *after;                /* --after: the cursor a truncated listing printed */
} stats_opts_t;

static bool ctl_read_full(int sock, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = ctl_recv(sock, (char *)buf + got, n - got);
        if (r <= 0) return false;
        got += (size_t)r;
    }
    return true;
}

/* one line (without the newline) of at most cap-1 bytes */
static bool ctl_read_line(int sock, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = ctl_recv(sock, buf + n, 1);
        if (r <= 0) return false;
        if (buf[n] == '\n') break;
        n++;
    }
    buf[n] = '\0';
    return true;
}

/* "OK " and a structure of len bytes (status, stats).  Prints the server's ERROR line and returns 3, or 0 and fills out. */
static int ctl_fetch_struct(const char *conf_path, const char *cli_sock, const char *cmd, void *out, size_t len) {
    int rc = 0;
    int sock = karictl_open_session(conf_path, cli_sock, &rc);
    if (sock < 0) return rc;
    char line[64];
    snprintf(line, sizeof(line), "%s\n", cmd);
    send(sock, line, strlen(line), 0);
    char *buf = malloc(3 + len);
    if (!buf) { close(sock); return 1; }
    size_t got = 0;
    while (got < 3 + len) {
        ssize_t r = ctl_recv(sock, buf + got, 3 + len - got);
        if (r <= 0) break;
        got += (size_t)r;
        if (got >= 5 && strncmp(buf, "ERROR", 5) == 0) break;   /* a refusal is a line, shorter than the structure */
    }
    int ret = 0;
    if (got >= 5 && strncmp(buf, "ERROR", 5) == 0) {
        fprintf(stderr, "karictl: %s: %.*s", cmd, (int)(got < 200 ? got : 200), buf);
        ret = 3;
    } else if (got != 3 + len || strncmp(buf, "OK ", 3) != 0) {
        fprintf(stderr, "karictl: invalid %s response (%zu bytes, expected %zu; karictl and karidns versions differ?)\n", cmd, got, 3 + len);
        ret = 3;
    } else {
        memcpy(out, buf + 3, len);
    }
    free(buf);
    close(sock);
    return ret;
}

static const char *stats_rcode_name(int r) {
    static const char *const n[16] = { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
                                       "NXRRSET", "NOTAUTH", "NOTZONE", "DSOTYPENI", "RCODE12", "RCODE13", "RCODE14", "RCODE15" };
    return n[r & 15];
}

/* Prometheus label value (text format: \\ \" and \n are escaped) */
static void prom_lv(const char *s) {
    putchar('"');
    for (; *s; s++) {
        if (*s == '\\') fputs("\\\\", stdout);
        else if (*s == '"') fputs("\\\"", stdout);
        else if (*s == '\n') fputs("\\n", stdout);
        else putchar(*s);
    }
    putchar('"');
}

static void json_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { putchar('\\'); putchar((int)c); }
        else if (c < 0x20 || c == 0x7f) printf("\\u%04x", c);
        else putchar((int)c);
    }
    putchar('"');
}

#define ULL(x) ((unsigned long long)(x))

static void prom_family(const char *name, const char *type, const char *help) {
    printf("# HELP %s %s\n# TYPE %s %s\n", name, help, name, type);
}

static void prom_server(const karidns_status_t *st, const karidns_stats_total_t *t) {
    uint64_t unzoned = 0;
    for (int r = 0; r < KARIDNS_STATS_RCODES; r++) unzoned += t->unzoned_responses[r];
    prom_family("karidns_build_info", "gauge", "The running KariDNS version (value 1).");
    printf("karidns_build_info{version="); prom_lv(st->version); printf("} 1\n");
    prom_family("karidns_boot_time_seconds", "gauge", "Start time of the server, seconds since the epoch.");
    printf("karidns_boot_time_seconds %lld\n", (long long)st->boot_time);
    prom_family("karidns_last_configured_time_seconds", "gauge", "Time the configuration was last read, seconds since the epoch.");
    printf("karidns_last_configured_time_seconds %lld\n", (long long)st->last_configured_time);
    prom_family("karidns_zones", "gauge", "Zones served (a zone shared between views counts once).");
    printf("karidns_zones %d\n", st->num_zones);
    prom_family("karidns_worker_threads", "gauge", "Worker threads of the Backend.");
    printf("karidns_worker_threads %d\n", st->worker_threads);
    prom_family("karidns_transfers_running", "gauge", "Zone transfers running now.");
    printf("karidns_transfers_running %d\n", st->xfers_running);
    prom_family("karidns_tcp_clients", "gauge", "TCP clients connected now.");
    printf("karidns_tcp_clients %d\n", st->tcp_clients);
    prom_family("karidns_tcp_clients_high_water", "gauge", "Most TCP clients connected at the same time.");
    printf("karidns_tcp_clients_high_water %d\n", st->tcp_high_water);
    prom_family("karidns_zone_bytes", "gauge", "Bytes held by zone versions and IXFR differences (resident: served; retired: replaced, not freed yet; previous: kept for rollback).");
    printf("karidns_zone_bytes{source=\"database\",state=\"resident\"} %llu\n", ULL(st->db_bytes_resident));
    printf("karidns_zone_bytes{source=\"database\",state=\"retired\"} %llu\n", ULL(st->db_bytes_retired));
    printf("karidns_zone_bytes{source=\"database\",state=\"previous\"} %llu\n", ULL(st->db_bytes_previous));
    printf("karidns_zone_bytes{source=\"other\",state=\"resident\"} %llu\n", ULL(st->other_bytes_resident));
    printf("karidns_zone_bytes{source=\"other\",state=\"retired\"} %llu\n", ULL(st->other_bytes_retired));
    printf("karidns_zone_bytes{source=\"other\",state=\"previous\"} %llu\n", ULL(st->other_bytes_previous));
    prom_family("karidns_queries_total", "counter", "Queries answered for a zone, by transport (queries no zone answered are in karidns_unzoned_responses_total).");
    printf("karidns_queries_total{proto=\"udp\"} %llu\n", ULL(t->queries_total - t->tcp_queries));
    printf("karidns_queries_total{proto=\"tcp\"} %llu\n", ULL(t->tcp_queries));
    prom_family("karidns_responses_total", "counter", "Responses, by RCODE: the zones' (NOERROR includes NODATA) and those of queries no zone answered.");
    printf("karidns_responses_total{rcode=\"NOERROR\"} %llu\n", ULL(t->responses_noerror + t->responses_nodata + t->unzoned_responses[0]));
    printf("karidns_responses_total{rcode=\"FORMERR\"} %llu\n", ULL(t->unzoned_responses[1]));
    printf("karidns_responses_total{rcode=\"SERVFAIL\"} %llu\n", ULL(t->responses_servfail + t->unzoned_responses[2]));
    printf("karidns_responses_total{rcode=\"NXDOMAIN\"} %llu\n", ULL(t->responses_nxdomain + t->unzoned_responses[3]));
    printf("karidns_responses_total{rcode=\"NOTIMP\"} %llu\n", ULL(t->unzoned_responses[4]));
    printf("karidns_responses_total{rcode=\"REFUSED\"} %llu\n", ULL(t->responses_refused + t->unzoned_responses[5]));
    for (int r = 6; r < KARIDNS_STATS_RCODES; r++)
        if (t->unzoned_responses[r]) printf("karidns_responses_total{rcode=\"%s\"} %llu\n", stats_rcode_name(r), ULL(t->unzoned_responses[r]));
    prom_family("karidns_nodata_responses_total", "counter", "NOERROR responses without data (part of the NOERROR count).");
    printf("karidns_nodata_responses_total %llu\n", ULL(t->responses_nodata));
    prom_family("karidns_unzoned_responses_total", "counter", "Responses to queries no zone answered, by RCODE.");
    for (int r = 0; r < KARIDNS_STATS_RCODES; r++)
        if (r <= 5 || t->unzoned_responses[r])
            printf("karidns_unzoned_responses_total{rcode=\"%s\"} %llu\n", stats_rcode_name(r), ULL(t->unzoned_responses[r]));
    (void)unzoned;
    prom_family("karidns_edns_queries_total", "counter", "Queries with an OPT record.");
    printf("karidns_edns_queries_total %llu\n", ULL(t->edns_queries));
    prom_family("karidns_dnssec_ok_queries_total", "counter", "Queries with the DO bit.");
    printf("karidns_dnssec_ok_queries_total %llu\n", ULL(t->dnssec_do_queries));
    prom_family("karidns_ecs_queries_total", "counter", "Queries with an EDNS Client Subnet option.");
    printf("karidns_ecs_queries_total %llu\n", ULL(t->ecs_queries));
    prom_family("karidns_rrl_responses_total", "counter", "Responses limited by rate-limit (the server's count, which includes queries no zone answered).");
    printf("karidns_rrl_responses_total{action=\"dropped\"} %llu\n", ULL(st->rrl_dropped));
    printf("karidns_rrl_responses_total{action=\"slipped\"} %llu\n", ULL(st->rrl_slipped));
    prom_family("karidns_extended_errors_total", "counter", "Responses with an Extended DNS Error, by kind.");
    printf("karidns_extended_errors_total{kind=\"prohibited\"} %llu\n", ULL(st->ede_proh));
    printf("karidns_extended_errors_total{kind=\"not_authoritative\"} %llu\n", ULL(st->ede_na));
    printf("karidns_extended_errors_total{kind=\"not_supported\"} %llu\n", ULL(st->ede_ns));
    printf("karidns_extended_errors_total{kind=\"other\"} %llu\n", ULL(st->ede_oth));
    prom_family("karidns_dnstap_truncated_total", "counter", "dnstap messages cut because they did not fit.");
    printf("karidns_dnstap_truncated_total %llu\n", ULL(st->dnstap_truncated));
    prom_family("karidns_notify_total", "counter", "NOTIFY messages sent and acknowledged.");
    printf("karidns_notify_total{event=\"sent\"} %llu\n", ULL(t->notify_sent));
    printf("karidns_notify_total{event=\"acknowledged\"} %llu\n", ULL(t->notify_ack));
    prom_family("karidns_transfers_in_total", "counter", "Zone transfers received from primaries.");
    printf("karidns_transfers_in_total{type=\"axfr\"} %llu\n", ULL(t->axfr_success));
    printf("karidns_transfers_in_total{type=\"ixfr\"} %llu\n", ULL(t->ixfr_success));
    prom_family("karidns_transfer_failures_total", "counter", "Refreshes of secondary zones that failed at every primary asked.");
    printf("karidns_transfer_failures_total %llu\n", ULL(t->xfer_failed));
    prom_family("karidns_wirecache_total", "counter", "Response cache lookups.");
    printf("karidns_wirecache_total{result=\"hit\"} %llu\n", ULL(t->wirecache_hits));
    printf("karidns_wirecache_total{result=\"miss\"} %llu\n", ULL(t->wirecache_misses));
    prom_family("karidns_reload_failures_total", "counter", "Configuration reloads that failed or left zones unloaded.");
    printf("karidns_reload_failures_total %llu\n", ULL(t->reload_failures));
    prom_family("karidns_alerts_active", "gauge", "Threshold alerts (options and zone alerts blocks) that are raised now.");
    printf("karidns_alerts_active %llu\n", ULL(t->alerts_active));
    prom_family("karidns_alerts_zones", "gauge", "Zones with an alerts block that the last check looked at.");
    printf("karidns_alerts_zones %llu\n", ULL(t->alerts_zones));
    prom_family("karidns_alerts_check_seconds", "gauge", "How long the last alerts check took.");
    printf("karidns_alerts_check_seconds %.6f\n", (double)t->alerts_check_us / 1e6);
    prom_family("karidns_alerts_build_seconds", "gauge", "How long the last build of the list of zones with an alerts block took (done when the configuration is read).");
    printf("karidns_alerts_build_seconds %.6f\n", (double)t->alerts_build_us / 1e6);
}

static void json_server(const karidns_status_t *st, const karidns_stats_total_t *t) {
    printf("\"server\":{\"version\":"); json_str(st->version);
    printf(",\"boot_time\":%lld,\"last_configured_time\":%lld,\"zones\":%d,\"worker_threads\":%d,\"transfers_running\":%d,"
           "\"tcp_clients\":%d,\"tcp_clients_high_water\":%d",
           (long long)st->boot_time, (long long)st->last_configured_time, st->num_zones, st->worker_threads, st->xfers_running,
           st->tcp_clients, st->tcp_high_water);
    printf(",\"zone_bytes\":{\"database\":{\"resident\":%llu,\"retired\":%llu,\"previous\":%llu},\"other\":{\"resident\":%llu,\"retired\":%llu,\"previous\":%llu}}",
           ULL(st->db_bytes_resident), ULL(st->db_bytes_retired), ULL(st->db_bytes_previous), ULL(st->other_bytes_resident),
           ULL(st->other_bytes_retired), ULL(st->other_bytes_previous));
    printf(",\"queries\":{\"udp\":%llu,\"tcp\":%llu}", ULL(t->queries_total - t->tcp_queries), ULL(t->tcp_queries));
    printf(",\"responses\":{\"NOERROR\":%llu,\"FORMERR\":%llu,\"SERVFAIL\":%llu,\"NXDOMAIN\":%llu,\"NOTIMP\":%llu,\"REFUSED\":%llu",
           ULL(t->responses_noerror + t->responses_nodata + t->unzoned_responses[0]), ULL(t->unzoned_responses[1]),
           ULL(t->responses_servfail + t->unzoned_responses[2]), ULL(t->responses_nxdomain + t->unzoned_responses[3]),
           ULL(t->unzoned_responses[4]), ULL(t->responses_refused + t->unzoned_responses[5]));
    for (int r = 6; r < KARIDNS_STATS_RCODES; r++)
        if (t->unzoned_responses[r]) printf(",\"%s\":%llu", stats_rcode_name(r), ULL(t->unzoned_responses[r]));
    printf("},\"nodata_responses\":%llu,\"unzoned_responses\":{", ULL(t->responses_nodata));
    for (int r = 0, first = 1; r < KARIDNS_STATS_RCODES; r++) {
        if (r > 5 && !t->unzoned_responses[r]) continue;
        printf("%s\"%s\":%llu", first ? "" : ",", stats_rcode_name(r), ULL(t->unzoned_responses[r]));
        first = 0;
    }
    printf("},\"edns_queries\":%llu,\"dnssec_ok_queries\":%llu,\"ecs_queries\":%llu", ULL(t->edns_queries), ULL(t->dnssec_do_queries), ULL(t->ecs_queries));
    printf(",\"rrl\":{\"dropped\":%llu,\"slipped\":%llu}", ULL(st->rrl_dropped), ULL(st->rrl_slipped));
    printf(",\"extended_errors\":{\"prohibited\":%llu,\"not_authoritative\":%llu,\"not_supported\":%llu,\"other\":%llu}",
           ULL(st->ede_proh), ULL(st->ede_na), ULL(st->ede_ns), ULL(st->ede_oth));
    printf(",\"dnstap_truncated\":%llu,\"notify\":{\"sent\":%llu,\"acknowledged\":%llu}", ULL(st->dnstap_truncated), ULL(t->notify_sent), ULL(t->notify_ack));
    printf(",\"transfers_in\":{\"axfr\":%llu,\"ixfr\":%llu,\"failures\":%llu}", ULL(t->axfr_success), ULL(t->ixfr_success), ULL(t->xfer_failed));
    printf(",\"wirecache\":{\"hit\":%llu,\"miss\":%llu},\"reload_failures\":%llu,\"alerts_active\":%llu,\"alerts_zones\":%llu,"
           "\"alerts_check_us\":%llu,\"alerts_build_us\":%llu}",
           ULL(t->wirecache_hits), ULL(t->wirecache_misses), ULL(t->reload_failures), ULL(t->alerts_active), ULL(t->alerts_zones),
           ULL(t->alerts_check_us), ULL(t->alerts_build_us));
}

/* The zones of a text-format listing are kept in memory, in this compact form (only what the series print, and the names), so that every metric
 * family can be written once and in one piece (Prometheus text format: all lines of a family together, HELP and TYPE once).  Records are in
 * chunks, so growing never copies them.  Memory: sizeof(zrec_t) = 184 bytes plus the zone name (about 25 bytes) per zone: about 210 MB for
 * 1,000,000 zones (JSON is streamed and keeps nothing).  --zones / --limit bound it. */
typedef struct {
    uint64_t queries_total, tcp_queries, responses_noerror, responses_nodata, responses_nxdomain, responses_servfail, responses_refused,
             edns_queries, dnssec_do_queries, ecs_queries, rrl_dropped, rrl_slipped, notify_sent, notify_ack, axfr_success, ixfr_success,
             xfer_failed, wirecache_hits, wirecache_misses;
    int64_t last_transfer_time;
    uint32_t soa_serial;
    bool is_secondary;
    const char *domain, *view_name;
} zrec_t;
#define ZCHUNK 4096
#define ZPOOL (1u << 20)
typedef struct {
    zrec_t **chunks;
    size_t nchunks, count;
    char *pool;                  /* the block names are being added to; full blocks stay where they are (the records point into them) */
    size_t pool_used;
    char **blocks;               /* every block, to free them */
    size_t nblocks;
    const char *last_view;
} zbuf_t;

static void zbuf_free(zbuf_t *b) {
    for (size_t i = 0; i < b->nchunks; i++) free(b->chunks[i]);
    for (size_t i = 0; i < b->nblocks; i++) free(b->blocks[i]);
    free(b->chunks);
    free(b->blocks);
    memset(b, 0, sizeof(*b));
}

static const char *zbuf_str(zbuf_t *b, const char *s) {
    size_t n = strlen(s) + 1;
    if (!b->pool || b->pool_used + n > ZPOOL) {
        char *blk = malloc(n > ZPOOL ? n : ZPOOL);
        char **nb = blk ? realloc(b->blocks, (b->nblocks + 1) * sizeof(*nb)) : NULL;
        if (!nb) { free(blk); return NULL; }
        b->blocks = nb;
        b->blocks[b->nblocks++] = blk;
        b->pool = blk;
        b->pool_used = 0;
    }
    char *p = b->pool + b->pool_used;
    memcpy(p, s, n);
    b->pool_used += n;
    return p;
}

static bool zbuf_add(zbuf_t *b, const zone_observatory_snapshot_t *s) {
    if (b->count == b->nchunks * ZCHUNK) {
        zrec_t **nc = realloc(b->chunks, (b->nchunks + 1) * sizeof(*nc));
        if (!nc) return false;
        b->chunks = nc;
        zrec_t *ck = malloc(ZCHUNK * sizeof(zrec_t));
        if (!ck) return false;
        b->chunks[b->nchunks++] = ck;
    }
    zrec_t *z = &b->chunks[b->count / ZCHUNK][b->count % ZCHUNK];
    z->queries_total = s->queries_total; z->tcp_queries = s->tcp_queries;
    z->responses_noerror = s->responses_noerror; z->responses_nodata = s->responses_nodata; z->responses_nxdomain = s->responses_nxdomain;
    z->responses_servfail = s->responses_servfail; z->responses_refused = s->responses_refused;
    z->edns_queries = s->edns_queries; z->dnssec_do_queries = s->dnssec_do_queries; z->ecs_queries = s->ecs_queries;
    z->rrl_dropped = s->rrl_dropped; z->rrl_slipped = s->rrl_slipped;
    z->notify_sent = s->notify_sent; z->notify_ack = s->notify_ack; z->axfr_success = s->axfr_success; z->ixfr_success = s->ixfr_success;
    z->xfer_failed = s->xfer_failed; z->wirecache_hits = s->wirecache_hits; z->wirecache_misses = s->wirecache_misses;
    z->last_transfer_time = (int64_t)s->last_transfer_time; z->soa_serial = s->soa_serial; z->is_secondary = s->is_secondary;
    z->domain = zbuf_str(b, s->domain);
    if (!z->domain) return false;
    if (!b->last_view || strcmp(b->last_view, s->view_name) != 0) {   /* (few views: the record points at the last one's copy) */
        b->last_view = zbuf_str(b, s->view_name);
        if (!b->last_view) return false;
    }
    z->view_name = b->last_view;
    b->count++;
    return true;
}

/* the zone families: one value of a zone each; label = the label that tells the series of a family apart (NULL = none) */
typedef struct {
    const char *name, *type, *help, *label, *lval;
    uint64_t (*get)(const zrec_t *);
} zone_family_t;
#define ZF(fn, expr) static uint64_t fn(const zrec_t *z) { return (uint64_t)(expr); }
ZF(zf_q_udp, z->queries_total - z->tcp_queries)
ZF(zf_q_tcp, z->tcp_queries)
ZF(zf_r_noerror, z->responses_noerror + z->responses_nodata)
ZF(zf_r_nxdomain, z->responses_nxdomain)
ZF(zf_r_servfail, z->responses_servfail)
ZF(zf_r_refused, z->responses_refused)
ZF(zf_r_nodata, z->responses_nodata)
ZF(zf_edns, z->edns_queries)
ZF(zf_do, z->dnssec_do_queries)
ZF(zf_ecs, z->ecs_queries)
ZF(zf_rrl_drop, z->rrl_dropped)
ZF(zf_rrl_slip, z->rrl_slipped)
ZF(zf_ntf_sent, z->notify_sent)
ZF(zf_ntf_ack, z->notify_ack)
ZF(zf_axfr, z->axfr_success)
ZF(zf_ixfr, z->ixfr_success)
ZF(zf_xfail, z->xfer_failed)
ZF(zf_wc_hit, z->wirecache_hits)
ZF(zf_wc_miss, z->wirecache_misses)
ZF(zf_serial, z->soa_serial)
ZF(zf_secondary, z->is_secondary ? 1 : 0)
ZF(zf_last_xfr, z->last_transfer_time > 0 ? z->last_transfer_time : 0)
static const zone_family_t k_zone_families[] = {
    { "karidns_zone_queries_total", "counter", "Queries answered for the zone, by transport.", "proto", "udp", zf_q_udp },
    { "karidns_zone_queries_total", "counter", NULL, "proto", "tcp", zf_q_tcp },
    { "karidns_zone_responses_total", "counter", "Responses of the zone, by RCODE (NOERROR includes NODATA).", "rcode", "NOERROR", zf_r_noerror },
    { "karidns_zone_responses_total", "counter", NULL, "rcode", "NXDOMAIN", zf_r_nxdomain },
    { "karidns_zone_responses_total", "counter", NULL, "rcode", "SERVFAIL", zf_r_servfail },
    { "karidns_zone_responses_total", "counter", NULL, "rcode", "REFUSED", zf_r_refused },
    { "karidns_zone_nodata_responses_total", "counter", "NOERROR responses of the zone without data (part of the NOERROR count).", NULL, NULL, zf_r_nodata },
    { "karidns_zone_edns_queries_total", "counter", "Queries for the zone with an OPT record.", NULL, NULL, zf_edns },
    { "karidns_zone_dnssec_ok_queries_total", "counter", "Queries for the zone with the DO bit.", NULL, NULL, zf_do },
    { "karidns_zone_ecs_queries_total", "counter", "Queries for the zone with an EDNS Client Subnet option.", NULL, NULL, zf_ecs },
    { "karidns_zone_rrl_responses_total", "counter", "Responses of the zone limited by rate-limit.", "action", "dropped", zf_rrl_drop },
    { "karidns_zone_rrl_responses_total", "counter", NULL, "action", "slipped", zf_rrl_slip },
    { "karidns_zone_notify_total", "counter", "NOTIFY messages for the zone.", "event", "sent", zf_ntf_sent },
    { "karidns_zone_notify_total", "counter", NULL, "event", "acknowledged", zf_ntf_ack },
    { "karidns_zone_transfers_in_total", "counter", "Transfers of the zone received from a primary.", "type", "axfr", zf_axfr },
    { "karidns_zone_transfers_in_total", "counter", NULL, "type", "ixfr", zf_ixfr },
    { "karidns_zone_transfer_failures_total", "counter", "Refreshes of the secondary zone that failed at every primary asked.", NULL, NULL, zf_xfail },
    { "karidns_zone_wirecache_total", "counter", "Response cache lookups for the zone.", "result", "hit", zf_wc_hit },
    { "karidns_zone_wirecache_total", "counter", NULL, "result", "miss", zf_wc_miss },
    { "karidns_zone_serial", "gauge", "SOA serial of the zone.", NULL, NULL, zf_serial },
    { "karidns_zone_secondary", "gauge", "1 when the zone is a secondary (or a catalog member), 0 for a primary.", NULL, NULL, zf_secondary },
    { "karidns_zone_last_transfer_time_seconds", "gauge", "Time of the last transfer received, seconds since the epoch (0: never).", NULL, NULL, zf_last_xfr },
};
#define ZONE_FAMILIES ((int)(sizeof(k_zone_families) / sizeof(k_zone_families[0])))

/* every zone, family by family: a family is written once, in one piece */
static void prom_zones(const zbuf_t *b) {
    for (int f = 0; f < ZONE_FAMILIES; f++) {
        const zone_family_t *fam = &k_zone_families[f];
        if (fam->help && b->count) prom_family(fam->name, fam->type, fam->help);
        for (size_t i = 0; i < b->count; i++) {
            const zrec_t *z = &b->chunks[i / ZCHUNK][i % ZCHUNK];
            printf("%s{zone=", fam->name);
            prom_lv(z->domain);
            printf(",view=");
            prom_lv(z->view_name[0] ? z->view_name : "default");
            if (fam->label) printf(",%s=\"%s\"", fam->label, fam->lval);
            printf("} %llu\n", ULL(fam->get(z)));
        }
    }
}

static void json_zone(const zone_observatory_snapshot_t *z) {
    printf("{\"zone\":"); json_str(z->domain);
    printf(",\"view\":"); json_str(z->view_name[0] ? z->view_name : "default");
    printf(",\"role\":\"%s\",\"serial\":%u,\"last_transfer_time\":%lld", z->is_secondary ? "secondary" : "primary", z->soa_serial,
           (long long)(z->last_transfer_time > 0 ? z->last_transfer_time : 0));
    printf(",\"queries\":{\"udp\":%llu,\"tcp\":%llu},\"responses\":{\"NOERROR\":%llu,\"NXDOMAIN\":%llu,\"SERVFAIL\":%llu,\"REFUSED\":%llu},\"nodata_responses\":%llu",
           ULL(z->queries_total - z->tcp_queries), ULL(z->tcp_queries), ULL(z->responses_noerror + z->responses_nodata),
           ULL(z->responses_nxdomain), ULL(z->responses_servfail), ULL(z->responses_refused), ULL(z->responses_nodata));
    printf(",\"edns_queries\":%llu,\"dnssec_ok_queries\":%llu,\"ecs_queries\":%llu,\"rrl\":{\"dropped\":%llu,\"slipped\":%llu}",
           ULL(z->edns_queries), ULL(z->dnssec_do_queries), ULL(z->ecs_queries), ULL(z->rrl_dropped), ULL(z->rrl_slipped));
    printf(",\"notify\":{\"sent\":%llu,\"acknowledged\":%llu},\"transfers_in\":{\"axfr\":%llu,\"ixfr\":%llu,\"failures\":%llu}",
           ULL(z->notify_sent), ULL(z->notify_ack), ULL(z->axfr_success), ULL(z->ixfr_success), ULL(z->xfer_failed));
    printf(",\"wirecache\":{\"hit\":%llu,\"miss\":%llu}}", ULL(z->wirecache_hits), ULL(z->wirecache_misses));
}

/* the sums per view, taken while the pages go by (only when every zone is listed) */
typedef struct {
    char name[STATS_VIEW_NAME_MAX];
    uint64_t zones, udp, tcp, noerror, nxdomain, servfail, refused, nodata;
} stats_view_t;

static void stats_view_add(stats_view_t *vs, size_t *nv, bool *overflow, const zone_observatory_snapshot_t *z) {
    const char *vn = z->view_name[0] ? z->view_name : "default";
    size_t i;
    for (i = 0; i < *nv; i++)
        if (strcmp(vs[i].name, vn) == 0) break;
    if (i == *nv) {
        if (*nv == STATS_VIEWS_MAX) { *overflow = true; return; }
        memset(&vs[i], 0, sizeof(vs[i]));
        snprintf(vs[i].name, sizeof(vs[i].name), "%s", vn);
        (*nv)++;
    }
    vs[i].zones++;
    vs[i].udp += z->queries_total - z->tcp_queries;
    vs[i].tcp += z->tcp_queries;
    vs[i].noerror += z->responses_noerror + z->responses_nodata;
    vs[i].nxdomain += z->responses_nxdomain;
    vs[i].servfail += z->responses_servfail;
    vs[i].refused += z->responses_refused;
    vs[i].nodata += z->responses_nodata;
}

static void prom_views(const stats_view_t *vs, size_t nv) {
    prom_family("karidns_view_zones", "gauge", "Zones of the view (each zone in its owner view).");
    for (size_t i = 0; i < nv; i++) { printf("karidns_view_zones{view="); prom_lv(vs[i].name); printf("} %llu\n", ULL(vs[i].zones)); }
    prom_family("karidns_view_queries_total", "counter", "Queries answered for the zones of the view, by transport.");
    for (size_t i = 0; i < nv; i++) {
        printf("karidns_view_queries_total{view="); prom_lv(vs[i].name); printf(",proto=\"udp\"} %llu\n", ULL(vs[i].udp));
        printf("karidns_view_queries_total{view="); prom_lv(vs[i].name); printf(",proto=\"tcp\"} %llu\n", ULL(vs[i].tcp));
    }
    prom_family("karidns_view_responses_total", "counter", "Responses of the zones of the view, by RCODE (NOERROR includes NODATA).");
    for (size_t i = 0; i < nv; i++) {
        const struct { const char *r; uint64_t v; } rows[4] = { { "NOERROR", vs[i].noerror }, { "NXDOMAIN", vs[i].nxdomain }, { "SERVFAIL", vs[i].servfail }, { "REFUSED", vs[i].refused } };
        for (int k = 0; k < 4; k++) {
            printf("karidns_view_responses_total{view="); prom_lv(vs[i].name); printf(",rcode=\"%s\"} %llu\n", rows[k].r, ULL(rows[k].v));
        }
    }
}

static void json_views(const stats_view_t *vs, size_t nv) {
    printf("\"views\":[");
    for (size_t i = 0; i < nv; i++) {
        printf("%s{\"view\":", i ? "," : ""); json_str(vs[i].name);
        printf(",\"zones\":%llu,\"queries\":{\"udp\":%llu,\"tcp\":%llu},\"responses\":{\"NOERROR\":%llu,\"NXDOMAIN\":%llu,\"SERVFAIL\":%llu,\"REFUSED\":%llu},\"nodata_responses\":%llu}",
               ULL(vs[i].zones), ULL(vs[i].udp), ULL(vs[i].tcp), ULL(vs[i].noerror), ULL(vs[i].nxdomain), ULL(vs[i].servfail), ULL(vs[i].refused), ULL(vs[i].nodata));
    }
    printf("]");
}

/* one page: `obspage` with the cursor.  0 = the page is in page[0..*n), *next is the cursor of the following page ("" = the end);
 * 4 = the cursor is stale (the zones were reloaded); other = an exit code with the message printed */
static int stats_fetch_page(const char *conf_path, const char *cli_sock, unsigned long want, const char *pattern, const char *cursor,
                            zone_observatory_snapshot_t *page, unsigned long *n, char *next, size_t next_cap) {
    int rc = 0;
    int sock = karictl_open_session(conf_path, cli_sock, &rc);
    if (sock < 0) return rc;
    char cmd[512], hdr[160];
    snprintf(cmd, sizeof(cmd), "obspage %lu %s %s\n", want, pattern ? pattern : "-", cursor ? cursor : "-");
    if (strlen(cmd) >= sizeof(cmd) - 1) { fprintf(stderr, "karictl: stats: request too long\n"); close(sock); return 2; }
    send(sock, cmd, strlen(cmd), 0);
    if (!ctl_read_line(sock, hdr, sizeof(hdr))) { fprintf(stderr, "karictl: stats: no reply\n"); close(sock); return 3; }
    if (strncmp(hdr, "ERROR cursor is stale", 21) == 0) { close(sock); return 4; }
    if (strncmp(hdr, "ERROR", 5) == 0) { fprintf(stderr, "karictl: stats: %s\n", hdr); close(sock); return 3; }
    char cur[KARIDNS_OBSPAGE_CURSOR_MAX + 8];
    if (sscanf(hdr, "OK %lu %71s", n, cur) != 2 || *n > STATS_PAGE || strlen(cur) >= next_cap) {
        fprintf(stderr, "karictl: stats: invalid reply: %s\n", hdr);
        close(sock);
        return 3;
    }
    snprintf(next, next_cap, "%s", strcmp(cur, "-") == 0 ? "" : cur);
    for (unsigned long i = 0; i < *n; i++) {
        if (!ctl_read_full(sock, &page[i], sizeof(page[i]))) { fprintf(stderr, "karictl: stats: truncated reply\n"); close(sock); return 3; }
        page[i].domain[sizeof(page[i].domain) - 1] = '\0';
        page[i].view_name[sizeof(page[i].view_name) - 1] = '\0';
        page[i].shared_views[sizeof(page[i].shared_views) - 1] = '\0';
    }
    close(sock);
    return 0;
}

static int karictl_stats(const char *conf_path, const char *cli_sock, const stats_opts_t *o) {
    karidns_status_t st;
    karidns_stats_total_t tot;
    int rc = ctl_fetch_struct(conf_path, cli_sock, "status", &st, sizeof(st));
    if (rc == 0) rc = ctl_fetch_struct(conf_path, cli_sock, "stats", &tot, sizeof(tot));
    if (rc != 0) return rc;
    st.version[sizeof(st.version) - 1] = '\0';

    const bool full = !o->zone && !o->pattern && !o->after && o->limit == 0;   /* every zone: the views can be summed */
    stats_view_t views[STATS_VIEWS_MAX];
    size_t nviews = 0;
    bool views_overflow = false;
    zone_observatory_snapshot_t *page = malloc(sizeof(*page) * STATS_PAGE);
    if (!page) { fprintf(stderr, "karictl: out of memory\n"); return 1; }
    zbuf_t zb;
    memset(&zb, 0, sizeof(zb));

    /* A listing that the zones changed under (a reload built new directories) is started again, three times at the most; the JSON listing is
     * written as it comes and cannot be, so it stops with an error there. */
    for (int attempt = 0; attempt < 3; attempt++) {
        rc = 0;
        nviews = 0;
        views_overflow = false;
        zbuf_free(&zb);
        if (o->json) { printf("{"); json_server(&st, &tot); printf(",\"zones\":["); }
        unsigned long sent = 0;
        bool first_zone = true;
        char cursor[KARIDNS_OBSPAGE_CURSOR_MAX + 8] = "", next[KARIDNS_OBSPAGE_CURSOR_MAX + 8] = "";
        if (o->after) snprintf(cursor, sizeof(cursor), "%s", o->after);
        bool more = false;
        if (o->zone) {   /* one zone: the exact lookup of observatory (the name is canonicalised by the server) */
            int srv_rc = 0;
            int sock = karictl_open_session(conf_path, cli_sock, &srv_rc);
            if (sock < 0) { rc = srv_rc; break; }
            char cmd[1024], hdr[128];
            snprintf(cmd, sizeof(cmd), "observatory %s%s%s\n", o->zone, o->view ? " " : "", o->view ? o->view : "");
            send(sock, cmd, strlen(cmd), 0);
            unsigned long n = 0;
            if (!ctl_read_line(sock, hdr, sizeof(hdr)) || strncmp(hdr, "OK ", 3) != 0 || sscanf(hdr, "OK %lu", &n) != 1 || n > 1) {
                fprintf(stderr, "karictl: stats: %s\n", hdr[0] ? hdr : "no reply");
                close(sock);
                rc = 3;
                break;
            }
            if (n == 0) { fprintf(stderr, "karictl: zone %s not found\n", o->zone); close(sock); rc = 3; break; }
            if (!ctl_read_full(sock, &page[0], sizeof(page[0]))) { fprintf(stderr, "karictl: stats: truncated reply\n"); close(sock); rc = 3; break; }
            close(sock);
            page[0].domain[sizeof(page[0].domain) - 1] = '\0';
            page[0].view_name[sizeof(page[0].view_name) - 1] = '\0';
            if (o->json) json_zone(&page[0]);
            else if (!zbuf_add(&zb, &page[0])) { fprintf(stderr, "karictl: out of memory\n"); rc = 1; }
        }
        unsigned long same_cursor = 0;
        if (!o->zone) do {
            unsigned long want = STATS_PAGE, n = 0;
            if (o->limit && o->limit - sent < want) want = o->limit - sent;
            int prc = stats_fetch_page(conf_path, cli_sock, want, o->pattern, cursor[0] ? cursor : NULL, page, &n, next, sizeof(next));
            if (prc != 0) { rc = prc; break; }
            for (unsigned long i = 0; i < n; i++) {
                if (o->json) { printf("%s", first_zone ? "" : ","); json_zone(&page[i]); first_zone = false; }
                else if (!zbuf_add(&zb, &page[i])) { fprintf(stderr, "karictl: out of memory\n"); rc = 1; break; }
                if (full) stats_view_add(views, &nviews, &views_overflow, &page[i]);
            }
            if (rc) break;
            sent += n;
            same_cursor = (n == 0 && strcmp(cursor, next) == 0) ? same_cursor + 1 : 0;
            if (same_cursor > 2) { fprintf(stderr, "karictl: stats: the server does not move on\n"); rc = 3; break; }
            snprintf(cursor, sizeof(cursor), "%s", next);
            more = cursor[0] != '\0';
        } while (more && (o->limit == 0 || sent < o->limit));
        if (rc == 4 && !o->json && !o->after && attempt < 2) {
            fprintf(stderr, "karictl: the zones were reloaded during the listing; starting again\n");
            continue;
        }
        if (rc == 4) {
            fprintf(stderr, "karictl: stats: the cursor is stale (the zones were reloaded)%s\n", o->json ? "; run the command again" : ": start without --after");
            rc = 3;
        }
        if (rc == 0) {
            bool truncated = more;   /* the limit ended the listing while zones remain */
            if (o->json) {
                printf("]");
                if (full && !views_overflow) { printf(","); json_views(views, nviews); }
                if (truncated) { printf(",\"more\":true,\"after\":"); json_str(cursor); }
                printf("}\n");
            } else {
                prom_server(&st, &tot);
                prom_zones(&zb);
                if (full && !views_overflow) prom_views(views, nviews);
                if (truncated) printf("# more zones: karictl stats --after %s\n", cursor);
            }
        }
        break;
    }
    zbuf_free(&zb);
    free(page);
    return rc;
}

#if defined(KARIDNS_COVERAGE_LINKAGE) && !defined(main)
/* Coverage builds: the tests #include this file with "#define main karictl_main",
 * so the body below is named karictl_main here as well; llvm-cov then merges the
 * counters of every binary that runs it (see karidns_tool_linkage.h). */
int karictl_main(int argc, char **argv);
int main(int argc, char **argv) { return karictl_main(argc, argv); }
#define main karictl_main
#endif
int main(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0)) {
        printf("karictl %s\n", KARIDNS_VERSION);
        return 0;
    }
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        karictl_usage(stdout, argv[0]);
        return 0;
    }
    const char *conf_path = KARIDNS_CONFDIR "/karictl.conf";
    bool conf_path_explicit = false;
    const char *cli_sock_path = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "+c:f:s:t:v")) != -1) {   /* ('+': stop at the command; its own -f is not this one) */
        switch (opt) {
            case 't': {
                char *end = NULL;
                errno = 0;
                long t = strtol(optarg, &end, 10);
                if (errno != 0 || end == optarg || *end != '\0' || t < 1 || t > 86400) {
                    fprintf(stderr, "karictl: -t: '%s' is not a number of seconds from 1 to 86400\n", optarg);
                    return 2;
                }
                g_reply_timeout = (int)t;
                break;
            }
            case 'c':
            case 'f':
                conf_path = optarg;
                conf_path_explicit = true;
                break;
            case 's':
                cli_sock_path = optarg;
                break;
            case 'v':
                printf("karictl %s\n", KARIDNS_VERSION);
                return 0;
            default:
                karictl_usage(stderr, argv[0]);
                return 2;
        }
    }
    if (optind >= argc) {
        karictl_usage(stderr, argv[0]);
        return 2;
    }
    /* notify / retransfer / zonestatus need a zone name; without one the server could only answer "unknown command" */
    if (optind + 1 >= argc && (strcmp(argv[optind], "notify") == 0 || strcmp(argv[optind], "retransfer") == 0 ||
                               strcmp(argv[optind], "zonestatus") == 0 || strcmp(argv[optind], "rollback") == 0)) {
        fprintf(stderr, "karictl: %s needs a zone name\n", argv[optind]);
        karictl_usage(stderr, argv[0]);
        return 2;
    }

    if (strcmp(argv[optind], "tsig-keygen") == 0) {
        const char *keyname = "transfer-key";
        if (optind + 1 < argc) keyname = argv[optind + 1];

        unsigned char rand_bytes[32];
        if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
            fprintf(stderr, "Failed to generate random bytes\n");
            return 1;
        }

        char b64_key[64];
        EVP_EncodeBlock((unsigned char *)b64_key, rand_bytes, sizeof(rand_bytes));

        printf("key \"%s\" {\n", keyname);
        printf("  algorithm hmac-sha256;\n");
        printf("  secret \"%s\";\n", b64_key);
        printf("};\n");
        return 0;
    }

    if (!conf_path_explicit && access(conf_path, F_OK) != 0 && access(KARIDNS_SYSCONFDIR "/karictl.conf", F_OK) == 0) {
        conf_path = KARIDNS_SYSCONFDIR "/karictl.conf";
    }

    if (strcmp(argv[optind], "stats") == 0) {
        /* karictl stats [-f prometheus|json] [zone [view]] [--zones PATTERN] [--limit N] [--after CURSOR]  (-f here is the
         * format; the -f before the command is the configuration file) */
        stats_opts_t so;
        memset(&so, 0, sizeof(so));
        int npos = 0;
        for (int i = optind + 1; i < argc; i++) {
            const char *a = argv[i];
            const char *name = NULL, *val = NULL;
            if (strcmp(a, "-f") == 0 || strcmp(a, "--format") == 0) name = "format";
            else if (strncmp(a, "--format=", 9) == 0) { name = "format"; val = a + 9; }
            else if (strcmp(a, "--zones") == 0) name = "zones";
            else if (strcmp(a, "--limit") == 0) name = "limit";
            else if (strcmp(a, "--after") == 0) name = "after";
            else if (a[0] == '-' && a[1] != '\0') {
                fprintf(stderr, "karictl: stats: unknown option %s\n", a);
                karictl_usage(stderr, argv[0]);
                return 2;
            } else {
                if (npos == 0) so.zone = a;
                else if (npos == 1) so.view = a;
                else { fprintf(stderr, "karictl: stats: too many arguments\n"); karictl_usage(stderr, argv[0]); return 2; }
                npos++;
                continue;
            }
            if (!val) {
                if (i + 1 >= argc) { fprintf(stderr, "karictl: stats: %s needs a value\n", a); return 2; }
                val = argv[++i];
            }
            if (strpbrk(val, " \t\r\n") != NULL || val[0] == '\0') {
                fprintf(stderr, "karictl: stats: the %s value must not be empty or contain white space (write a space in a name as \\032)\n", name);
                return 2;
            }
            if (strcmp(name, "format") == 0) {
                if (strcmp(val, "json") == 0) so.json = true;
                else if (strcmp(val, "prometheus") == 0) so.json = false;
                else { fprintf(stderr, "karictl: stats: the format is prometheus or json\n"); return 2; }
            } else if (strcmp(name, "zones") == 0) {
                so.pattern = val;
            } else if (strcmp(name, "limit") == 0) {
                char *end = NULL;
                unsigned long lv = strtoul(val, &end, 10);
                if (*end != '\0' || lv == 0 || val[0] == '-') { fprintf(stderr, "karictl: stats: --limit needs a number of zones above 0\n"); return 2; }
                so.limit = lv;
            } else {
                so.after = val;
            }
        }
        if (so.zone && (so.pattern || so.limit || so.after)) {
            fprintf(stderr, "karictl: stats: a zone name cannot be combined with --zones, --limit or --after\n");
            return 2;
        }
        return karictl_stats(conf_path, cli_sock_path, &so);
    }

    int rc = 0;
    int sock = karictl_open_session(conf_path, cli_sock_path, &rc);
    if (sock < 0) return rc;
    char buf[1024];
    ssize_t r;

    char cmd_msg[512];
    if (optind + 3 < argc) {                       /* reload <zone> <view> force */
        snprintf(cmd_msg, sizeof(cmd_msg), "%s %s %s %s\n", argv[optind], argv[optind + 1], argv[optind + 2], argv[optind + 3]);
    } else if (optind + 2 < argc) {
        snprintf(cmd_msg, sizeof(cmd_msg), "%s %s %s\n", argv[optind], argv[optind + 1], argv[optind + 2]);
    } else if (optind + 1 < argc) {
        snprintf(cmd_msg, sizeof(cmd_msg), "%s %s\n", argv[optind], argv[optind + 1]);
    } else {
        snprintf(cmd_msg, sizeof(cmd_msg), "%s\n", argv[optind]);
    }

    send(sock, cmd_msg, strlen(cmd_msg), 0);

    if (strcmp(argv[optind], "status") == 0) {
        size_t expected_len = 3 + sizeof(karidns_status_t);
        size_t total = 0;
        while (total < expected_len) {
            r = ctl_recv(sock, buf + total, sizeof(buf) - total);
            if (r <= 0) break;
            total += r;
        }
        if (total >= expected_len && strncmp(buf, "OK ", 3) == 0) {
            karidns_status_t st;
            memcpy(&st, buf + 3, sizeof(st));
            st.version[sizeof(st.version) - 1] = '\0';
            st.hostname[sizeof(st.hostname) - 1] = '\0';
            st.os_name[sizeof(st.os_name) - 1] = '\0';
            st.os_release[sizeof(st.os_release) - 1] = '\0';
            st.machine[sizeof(st.machine) - 1] = '\0';
            st.config_file[sizeof(st.config_file) - 1] = '\0';

            /* T-11: time_t にミリ秒は無く、strftime() は %03d を知らないので秒までにする */
            char boot_str[64], config_str[64];
            struct tm tm_info;
            /* (a time the local time cannot represent, from a damaged reply: localtime_r() fails and strftime() must not get a NULL) */
            if (!localtime_r(&st.boot_time, &tm_info) || strftime(boot_str, sizeof(boot_str), "%d-%b-%Y %H:%M:%S", &tm_info) == 0)
                snprintf(boot_str, sizeof(boot_str), "invalid (%lld)", (long long)st.boot_time);
            if (!localtime_r(&st.last_configured_time, &tm_info) || strftime(config_str, sizeof(config_str), "%d-%b-%Y %H:%M:%S", &tm_info) == 0)
                snprintf(config_str, sizeof(config_str), "invalid (%lld)", (long long)st.last_configured_time);

            /* D-12: バージョン、ホスト名、OS、CPU 数はサーバーが返した値 */
            printf("version: KariDNS %s (Authoritative)\n", st.version);
            printf("running on %s: %s %s %s\n", st.hostname, st.os_name, st.machine, st.os_release);
            printf("boot time: %s\n", boot_str);
            printf("last configured: %s\n", config_str);
            printf("configuration file: %s\n", st.config_file[0] ? st.config_file : "(unknown)");
            printf("CPUs found: %d\n", st.ncpus);
            printf("worker threads: %d\n", st.worker_threads);
            printf("number of zones: %d (0 automatic)\n", st.num_zones);
            printf("xfers running: %d\n", st.xfers_running);
            printf("query logging is %s\n", st.query_logging ? "ON" : "OFF");
            printf("response logging is %s\n", st.response_logging ? "ON" : "OFF");
            printf("tcp clients: %d (High-water: %d)\n", st.tcp_clients, st.tcp_high_water);
            /* D1a: what the zone versions hold (image, glue, IXFR differences); "retired" = replaced, not freed yet (a reader may hold it) */
            printf("zone versions and IXFR deltas, database zones: %llu bytes resident, %llu bytes retired\n",
                   (unsigned long long)st.db_bytes_resident, (unsigned long long)st.db_bytes_retired);
            printf("zone versions and IXFR deltas, other zones: %llu bytes resident, %llu bytes retired\n",
                   (unsigned long long)st.other_bytes_resident, (unsigned long long)st.other_bytes_retired);
            /* the versions zones keep for 'karictl rollback' (rollback-window): not served, freed when the window is over or the memory-limit needs the room */
            printf("zone versions kept for rollback: database zones %llu bytes, other zones %llu bytes\n",
                   (unsigned long long)st.db_bytes_previous, (unsigned long long)st.other_bytes_previous);
            printf("server is up and running%s\n", st.frontend_alive ? "" : " (Frontend is down)");
            
            printf("\n--- Security & Rate Limit Stats ---\n");
            printf("RRL dropped: %lu\n", st.rrl_dropped);
            printf("RRL slipped: %lu\n", st.rrl_slipped);
            printf("EDE Prohibited (18): %lu\n", st.ede_proh);
            printf("EDE NotAuthoritative (20): %lu\n", st.ede_na);
            printf("EDE NotSupported (21): %lu\n", st.ede_ns);
            printf("EDE Other: %lu\n", st.ede_oth);
            printf("dnstap truncated: %lu\n", (unsigned long)st.dnstap_truncated);
            printf("-----------------------------------\n");
        } else {
            /* D-13: ERROR 応答や長さの合わない応答は失敗 (終了コード 3) */
            if (total >= sizeof(buf)) total = sizeof(buf) - 1;
            buf[total] = '\0';
            if (strncmp(buf, "ERROR", 5) == 0)
                printf("%s", buf);
            else
                fprintf(stderr, "Invalid status response (%zu bytes, expected %zu; karictl and karidns versions differ?)\n",
                        total, expected_len);
            close(sock);
            return 3;
        }
    } else if (strcmp(argv[optind], "dbstatus") == 0) {
        /* the reply is text of any length; the server closes the connection after it */
        char dbuf[16384];
        size_t total = 0;
        while (total < sizeof(dbuf) - 1) {
            r = ctl_recv(sock, dbuf + total, sizeof(dbuf) - 1 - total);
            if (r <= 0) break;
            total += (size_t)r;
        }
        dbuf[total] = '\0';
        printf("%s", dbuf);
        if (total == 0 || strncmp(dbuf, "ERROR", 5) == 0) {
            close(sock);
            return 3;
        }
    } else if (strcmp(argv[optind], "observatory") == 0) {
        size_t total = 0;
        while (total < sizeof(buf) - 1) {
            r = ctl_recv(sock, buf + total, 1);
            if (r <= 0) break;
            total += r;
            if (buf[total - 1] == '\n') break;
        }
        buf[total] = '\0';
        if (strncmp(buf, "ERROR", 5) == 0) {
            printf("%s", buf);
            close(sock);
            return 3;
        }
        uint32_t count = 0;
        if (sscanf(buf, "OK %u", &count) != 1) {
            printf("Invalid response: %s", buf);
            close(sock);
            return 3;
        }
        if (count == 0) {
            printf("No matching zones found.\n");
        } else {
            for (uint32_t i = 0; i < count; i++) {
                zone_observatory_snapshot_t snap;
                size_t got = 0;
                while (got < sizeof(snap)) {
                    ssize_t n = ctl_recv(sock, (char *)&snap + got, sizeof(snap) - got);
                    if (n <= 0) break;
                    got += n;
                }
                if (got < sizeof(snap)) {
                    fprintf(stderr, "Truncated observatory response\n");
                    close(sock);
                    return 3;
                }
                char notify_time_str[64] = "never";
                if (snap.last_notify_time > 0) {
                    time_t t = (time_t)snap.last_notify_time;
                    struct tm tm_n;
                    /* (a time stamp the local time cannot represent, from a damaged reply: localtime() would return NULL) */
                    if (!localtime_r(&t, &tm_n) || strftime(notify_time_str, sizeof(notify_time_str), "%Y-%m-%d %H:%M:%S", &tm_n) == 0)
                        snprintf(notify_time_str, sizeof(notify_time_str), "invalid (%lld)", (long long)snap.last_notify_time);
                }
                char transfer_time_str[64] = "never";
                if (snap.last_transfer_time > 0) {
                    time_t t = (time_t)snap.last_transfer_time;
                    struct tm tm_x;
                    if (!localtime_r(&t, &tm_x) || strftime(transfer_time_str, sizeof(transfer_time_str), "%Y-%m-%d %H:%M:%S", &tm_x) == 0)
                        snprintf(transfer_time_str, sizeof(transfer_time_str), "invalid (%lld)", (long long)snap.last_transfer_time);
                }

                if (snap.shared_views[0])   /* in-view: one entry for the zone, in its owner view, and the views it is shared to */
                    printf("Zone: %s (view: %s, shared to views: %s)\n", snap.domain, snap.view_name[0] ? snap.view_name : "default",
                           snap.shared_views);
                else
                    printf("Zone: %s (view: %s)\n", snap.domain, snap.view_name[0] ? snap.view_name : "default");
                printf("  Role:                  %s\n", snap.is_secondary ? "secondary" : "primary");
                printf("  SOA Serial:            %u\n", snap.soa_serial);
                printf("  Queries Total:         %lu (TCP: %lu)\n", (unsigned long)snap.queries_total, (unsigned long)snap.tcp_queries);
                printf("  Responses:             NOERROR=%lu NXDOMAIN=%lu NODATA=%lu SERVFAIL=%lu REFUSED=%lu\n",
                       (unsigned long)snap.responses_noerror, (unsigned long)snap.responses_nxdomain, (unsigned long)snap.responses_nodata,
                       (unsigned long)snap.responses_servfail, (unsigned long)snap.responses_refused);
                printf("  EDNS / Extensions:     EDNS=%lu DO=%lu ECS=%lu\n",
                       (unsigned long)snap.edns_queries, (unsigned long)snap.dnssec_do_queries, (unsigned long)snap.ecs_queries);
                printf("  Rate Limiting:         Dropped=%lu Slipped=%lu\n",
                       (unsigned long)snap.rrl_dropped, (unsigned long)snap.rrl_slipped);
                if (snap.is_secondary) {
                    printf("  Transfers (In):        AXFR=%lu IXFR=%lu (Last: %s) Failed-refreshes=%lu\n",
                           (unsigned long)snap.axfr_success, (unsigned long)snap.ixfr_success, transfer_time_str,
                           (unsigned long)snap.xfer_failed);
                } else {
                    printf("  NOTIFY (Out):          Sent=%lu Configured-Slaves=%u (Last: %s)\n",
                           (unsigned long)snap.notify_sent, snap.slaves_configured, notify_time_str);
                }
                if (snap.wirecache_enabled) {
                    unsigned long wc_total = (unsigned long)snap.wirecache_hits + (unsigned long)snap.wirecache_misses;
                    double hit_rate_overall = wc_total > 0 ? (100.0 * snap.wirecache_hits / wc_total) : 0.0;
                    double hit_rate_noerror = snap.responses_noerror > 0 ? (100.0 * snap.wirecache_hits / snap.responses_noerror) : 0.0;
                    double attempt_rate = snap.queries_total > 0 ? (100.0 * wc_total / snap.queries_total) : 0.0;

                    long long other_noerror_misses = (long long)snap.wirecache_misses
                                                      - (long long)snap.responses_nxdomain
                                                      - (long long)snap.responses_nodata;
                    if (other_noerror_misses < 0) other_noerror_misses = 0; // 概算のズレで負値になった場合の保険

                    printf("  WireCache:             Hits=%lu Misses=%lu (shared response cache)\n",
                           (unsigned long)snap.wirecache_hits, (unsigned long)snap.wirecache_misses);
                    printf("                         HitRate: overall=%.1f%% / of-NOERROR=%.1f%% / cache-attempt-rate=%.1f%%\n",
                           hit_rate_overall, hit_rate_noerror, attempt_rate);
                    printf("                         Miss breakdown (approx): NXDOMAIN=%lu NODATA=%lu other-NOERROR=%lld\n",
                           (unsigned long)snap.responses_nxdomain, (unsigned long)snap.responses_nodata, other_noerror_misses);
                } else {
                    printf("  WireCache:             disabled for this zone\n");
                }
                if (i + 1 < count) printf("\n");
            }
        }
    } else {
        r = ctl_recv(sock, buf, sizeof(buf) - 1);
        if (r > 0) {
            buf[r] = '\0';
            printf("%s", buf);
            if (strncmp(buf, "ERROR", 5) == 0) {
                close(sock);
                return 3;
            }
        }
    }

    close(sock);
    return 0;
}
