/*
 * karidns-tapstat: aggregates the dnstap stream of karidns (or any dnstap sender) into periodic summaries.
 *
 * It listens on a UNIX socket as a Frame Streams receiver (the sender connects and the READY / ACCEPT / START ... STOP /
 * FINISH handshake runs), or reads a Frame Streams file, and counts per zone, query name, query type, response code and
 * client prefix in fixed-size tables.  Every -i seconds it writes the summary (text, JSON lines or a Prometheus textfile)
 * to stdout or, with -o, to a file that is replaced atomically, then starts over.  Files and stdout only: nothing is sent
 * anywhere.  See docs/karidns-tapstat.md.
 *
 * An ordinary unprivileged process (no Capsicum): run it as its own user.  Everything it receives is untrusted.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "tapstat_core.h"

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"
#endif

#define MAX_CONN 16
#define HANDSHAKE_TIMEOUT_MS 5000
#define ZONE_LIMIT 1000000

typedef struct {
    int fd;                 /* -1 = free */
    fstrm_reader_t rd;
    int64_t t_connect_ms;
} conn_t;

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void usage(FILE *fp) {
    fputs(
"Usage: karidns-tapstat (-s SOCKET | -r FILE) [options]\n"
"\n"
"Aggregates a dnstap stream into periodic summaries (per zone, query name, query type, response code, client prefix).\n"
"\n"
"Input (one of):\n"
"  -s SOCKET    listen on a UNIX socket as a Frame Streams receiver (karidns: dnstap { socket \"SOCKET\"; })\n"
"  -r FILE      read a Frame Streams file (\"-\" = standard input); one summary at the end of the file\n"
"\n"
"Options:\n"
"  -z NAMES     comma-separated zone names; the longest matching suffix of the query name is the zone (repeatable).\n"
"               Without -z the zone the server put in the message (query_zone) is used; no zone is \"other\"\n"
"  -Z FILE      zone names, one per line (# starts a comment)\n"
"  -i SECONDS   summary interval with -s, 1 to 86400 (default 60)\n"
"  -f FORMAT    text, json (one line per summary) or prom (Prometheus textfile format); default text\n"
"  -o FILE      write each summary to FILE, replacing it atomically (write to a temporary file, then rename);\n"
"               default is standard output\n"
"  -k N         keys kept per dimension, 1 to 1000000 (default 10000), Space-Saving top-K: a key that does not fit replaces the smallest one and a count may be too high (shown as error)\n"
"  -n N         entries shown per dimension (default 20, 0 = all kept)\n"
"  -t TYPE      response (default) or query: the message type counted for zone, query name, query type and client\n"
"               (response codes always come from responses)\n"
"  -4 BITS      client prefix length for IPv4 (default 24)\n"
"  -6 BITS      client prefix length for IPv6 (default 56)\n"
"  -m MODE      permission of the socket file, octal (default 660)\n"
"  -V           print the version\n"
"  -h           this help\n"
"\n"
"Examples:\n"
"  karidns-tapstat -s /var/run/karidns/tapstat.sock -z example.test,example.org -i 60 -f prom -o /var/tmp/karidns_tapstat.prom\n"
"  karidns-tapstat -r queries.fstrm -f json -n 50\n"
"\n"
"SIGINT and SIGTERM write the summary of the interval in progress and exit.\n", fp);
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool parse_uint(const char *s, unsigned long min, unsigned long max, unsigned long *out) {
    char *end;
    errno = 0;
    if (!s || !*s || *s == '-') return false;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || *end || v < min || v > max) return false;
    *out = v;
    return true;
}

/* "a.test,b.test" into the aggregator; returns false (and says which) on a bad name */
static bool add_zone_list(tapstat_t *st, char *list) {
    char *save = NULL;
    for (char *tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (tapstat_zone_count(st) >= ZONE_LIMIT) { fprintf(stderr, "karidns-tapstat: more than %d zones\n", ZONE_LIMIT); return false; }
        if (!tapstat_add_zone(st, tok)) { fprintf(stderr, "karidns-tapstat: bad zone name '%.80s'\n", tok); return false; }
    }
    return true;
}

static bool add_zone_file(tapstat_t *st, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "karidns-tapstat: %s: %s\n", path, strerror(errno)); return false; }
    char line[512];
    bool ok = true;
    while (ok && fgets(line, sizeof(line), f)) {
        char *h = strchr(line, '#');
        if (h) *h = 0;
        size_t b = strspn(line, " \t\r\n");
        char *p = line + b;
        size_t l = strlen(p);
        while (l > 0 && strchr(" \t\r\n", p[l - 1])) p[--l] = 0;
        if (l == 0) continue;
        if (tapstat_zone_count(st) >= ZONE_LIMIT) { fprintf(stderr, "karidns-tapstat: more than %d zones\n", ZONE_LIMIT); ok = false; break; }
        if (!tapstat_add_zone(st, p)) { fprintf(stderr, "karidns-tapstat: %s: bad zone name '%.80s'\n", path, p); ok = false; }
    }
    fclose(f);
    return ok;
}

/* one summary to stdout, or replace the -o file: write a temporary file next to it, then rename (RFC-free, but the
 * Prometheus textfile collector requires exactly this so that it never reads a half-written file) */
static int emit(const tapstat_t *st, tapstat_format_t fmt, const char *outpath, time_t t0, time_t t1, double secs) {
    if (!outpath) {
        tapstat_render(st, fmt, stdout, t0, t1, secs);
        fflush(stdout);
        return ferror(stdout) ? -1 : 0;
    }
    char tmp[1100];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", outpath, (long)getpid()) >= (int)sizeof(tmp)) {
        fprintf(stderr, "karidns-tapstat: output path too long\n");
        return -1;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) { fprintf(stderr, "karidns-tapstat: %s: %s\n", tmp, strerror(errno)); return -1; }
    FILE *fp = fdopen(fd, "w");
    if (!fp) { close(fd); unlink(tmp); return -1; }
    tapstat_render(st, fmt, fp, t0, t1, secs);
    int bad = fflush(fp) != 0 || ferror(fp);
    if (fclose(fp) != 0) bad = 1;
    if (bad || rename(tmp, outpath) != 0) {
        fprintf(stderr, "karidns-tapstat: %s: %s\n", outpath, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void frame_cb(void *ctx, const uint8_t *frame, size_t len) { tapstat_frame((tapstat_t *)ctx, frame, len); }

/* -r: the whole file is one interval */
static int run_file(tapstat_t *st, const char *path, tapstat_format_t fmt, const char *outpath) {
    FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    if (!f) { fprintf(stderr, "karidns-tapstat: %s: %s\n", path, strerror(errno)); return 1; }
    fstrm_reader_t rd;
    fstrm_reader_init(&rd, false);
    static uint8_t buf[65536];
    int rc = 0;
    time_t t0 = time(NULL);
    int64_t m0 = now_ms();
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        int r = fstrm_feed(&rd, buf, n, frame_cb, st);
        if (r < 0) { fprintf(stderr, "karidns-tapstat: %s: not a valid Frame Streams dnstap file (frames read so far are counted)\n", path); rc = 1; break; }
        if (r > 0) break; /* STOP */
    }
    if (ferror(f)) { fprintf(stderr, "karidns-tapstat: %s: read error\n", path); rc = 1; }
    if (f != stdin) fclose(f);
    fstrm_reader_free(&rd);
    if (emit(st, fmt, outpath, t0, time(NULL), (double)(now_ms() - m0) / 1000.0) != 0) rc = 1;
    return rc;
}

static int listen_unix(const char *path, mode_t mode) {
    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sun.sun_path)) {
        fprintf(stderr, "karidns-tapstat: socket path longer than %zu bytes\n", sizeof(sun.sun_path) - 1);
        return -1;
    }
    memcpy(sun.sun_path, path, strlen(path));
    struct stat sb;
    if (lstat(path, &sb) == 0) {
        if (!S_ISSOCK(sb.st_mode)) { fprintf(stderr, "karidns-tapstat: %s exists and is not a socket\n", path); return -1; }
        int probe = socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe >= 0) {
            if (connect(probe, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
                close(probe);
                fprintf(stderr, "karidns-tapstat: %s is in use by another process\n", path);
                return -1;
            }
            close(probe);
        }
        unlink(path); /* a stale socket file of an earlier run */
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { fprintf(stderr, "karidns-tapstat: socket: %s\n", strerror(errno)); return -1; }
    mode_t old = umask((mode_t)(~mode & 0777));
    int rc = bind(fd, (struct sockaddr *)&sun, sizeof(sun));
    umask(old);
    if (rc != 0 || listen(fd, 16) != 0) {
        fprintf(stderr, "karidns-tapstat: %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

static void conn_close(conn_t *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    fstrm_reader_free(&c->rd);
}

/* the ACCEPT / FINISH of the reader: a few dozen bytes into an empty socket buffer; a peer that cannot take them is dropped */
static bool conn_flush_reply(conn_t *c) {
    size_t off = 0;
    while (off < c->rd.reply_len) {
        ssize_t w = write(c->fd, c->rd.reply + off, c->rd.reply_len - off);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return false;
        }
        off += (size_t)w;
    }
    c->rd.reply_len = 0;
    return true;
}

static int run_socket(tapstat_t *st, const char *sockpath, mode_t mode, unsigned interval, tapstat_format_t fmt, const char *outpath) {
    int lfd = listen_unix(sockpath, mode);
    if (lfd < 0) return 1;

    conn_t conns[MAX_CONN];
    for (int i = 0; i < MAX_CONN; i++) { conns[i].fd = -1; memset(&conns[i].rd, 0, sizeof(conns[i].rd)); }
    static uint8_t buf[65536];
    int rc = 0;

    time_t wall0 = time(NULL);
    int64_t m0 = now_ms();
    int64_t deadline = m0 + (int64_t)interval * 1000;

    while (!g_stop) {
        struct pollfd pfds[MAX_CONN + 1];
        int map[MAX_CONN + 1];
        int np = 0;
        pfds[np].fd = lfd; pfds[np].events = POLLIN; map[np] = -1; np++;
        for (int i = 0; i < MAX_CONN; i++)
            if (conns[i].fd >= 0) { pfds[np].fd = conns[i].fd; pfds[np].events = POLLIN; map[np] = i; np++; }

        int64_t now = now_ms();
        int64_t wait = deadline - now;
        if (wait > 1000) wait = 1000; /* also the granularity of the handshake timeout */
        if (wait < 0) wait = 0;
        int pr = poll(pfds, (nfds_t)np, (int)wait);
        if (pr < 0 && errno != EINTR) { fprintf(stderr, "karidns-tapstat: poll: %s\n", strerror(errno)); rc = 1; break; }

        if (pr > 0) {
            for (int k = 0; k < np; k++) {
                if (!pfds[k].revents) continue;
                if (map[k] < 0) { /* a new sender */
                    int nfd = accept(lfd, NULL, NULL);
                    if (nfd < 0) continue;
                    int slot = -1;
                    for (int i = 0; i < MAX_CONN; i++) if (conns[i].fd < 0) { slot = i; break; }
                    if (slot < 0) { close(nfd); fprintf(stderr, "karidns-tapstat: too many senders, connection refused\n"); continue; }
                    int fl = fcntl(nfd, F_GETFL, 0);
                    if (fl >= 0) fcntl(nfd, F_SETFL, fl | O_NONBLOCK);
                    fcntl(nfd, F_SETFD, FD_CLOEXEC);
                    conns[slot].fd = nfd;
                    fstrm_reader_init(&conns[slot].rd, true);
                    conns[slot].t_connect_ms = now_ms();
                    continue;
                }
                conn_t *c = &conns[map[k]];
                ssize_t n = read(c->fd, buf, sizeof(buf));
                if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
                if (n <= 0) { conn_close(c); continue; } /* the sender went away; it reconnects */
                int r = fstrm_feed(&c->rd, buf, (size_t)n, frame_cb, st);
                if (c->rd.reply_len > 0 && !conn_flush_reply(c)) { conn_close(c); continue; }
                if (r < 0) {
                    fprintf(stderr, "karidns-tapstat: Frame Streams protocol error from a sender, connection closed\n");
                    conn_close(c);
                } else if (r > 0) {
                    conn_close(c); /* STOP answered with FINISH */
                }
            }
        }

        now = now_ms();
        for (int i = 0; i < MAX_CONN; i++) /* a sender that does not finish the handshake holds a slot */
            if (conns[i].fd >= 0 && conns[i].rd.state != FSTRM_ST_DATA && now - conns[i].t_connect_ms > HANDSHAKE_TIMEOUT_MS)
                conn_close(&conns[i]);

        if (now >= deadline) {
            if (emit(st, fmt, outpath, wall0, time(NULL), (double)(now - m0) / 1000.0) != 0) rc = 1;
            tapstat_reset(st);
            wall0 = time(NULL);
            m0 = now;
            deadline = now + (int64_t)interval * 1000;
        }
    }

    /* a signal: the summary of the interval in progress */
    if (emit(st, fmt, outpath, wall0, time(NULL), (double)(now_ms() - m0) / 1000.0) != 0) rc = 1;
    for (int i = 0; i < MAX_CONN; i++) conn_close(&conns[i]);
    close(lfd);
    unlink(sockpath);
    return rc;
}

int main(int argc, char **argv) {
    static const struct option longopts[] = {
        { "help", no_argument, NULL, 'h' }, { "version", no_argument, NULL, 'V' }, { NULL, 0, NULL, 0 }
    };
    const char *sockpath = NULL, *filepath = NULL, *outpath = NULL;
    tapstat_format_t fmt = TAPSTAT_TEXT;
    unsigned long interval = 60, topk = 10000, show = 20, v4 = 24, v6 = 56, mode = 0660, v;
    int count_type = 2;
    char *zlists[64];
    size_t nzl = 0;
    const char *zfiles[64];
    size_t nzf = 0;
    int c;

    while ((c = getopt_long(argc, argv, "s:r:z:Z:i:f:o:k:n:t:4:6:m:Vh", longopts, NULL)) != -1) {
        switch (c) {
        case 's': sockpath = optarg; break;
        case 'r': filepath = optarg; break;
        case 'z':
            if (nzl >= sizeof(zlists) / sizeof(zlists[0])) { fprintf(stderr, "karidns-tapstat: too many -z\n"); return 2; }
            zlists[nzl] = strdup(optarg);
            if (!zlists[nzl]) return 2;
            nzl++;
            break;
        case 'Z':
            if (nzf >= sizeof(zfiles) / sizeof(zfiles[0])) { fprintf(stderr, "karidns-tapstat: too many -Z\n"); return 2; }
            zfiles[nzf++] = optarg;
            break;
        case 'i': if (!parse_uint(optarg, 1, 86400, &interval)) { fprintf(stderr, "karidns-tapstat: -i must be 1 to 86400\n"); return 2; } break;
        case 'k': if (!parse_uint(optarg, 1, TAPSTAT_MAX_TOPK, &topk)) { fprintf(stderr, "karidns-tapstat: -k must be 1 to %u\n", TAPSTAT_MAX_TOPK); return 2; } break;
        case 'n': if (!parse_uint(optarg, 0, 1000000, &show)) { fprintf(stderr, "karidns-tapstat: -n must be 0 to 1000000\n"); return 2; } break;
        case '4': if (!parse_uint(optarg, 0, 32, &v4)) { fprintf(stderr, "karidns-tapstat: -4 must be 0 to 32\n"); return 2; } break;
        case '6': if (!parse_uint(optarg, 0, 128, &v6)) { fprintf(stderr, "karidns-tapstat: -6 must be 0 to 128\n"); return 2; } break;
        case 'm': {
            char *end;
            errno = 0;
            v = strtoul(optarg, &end, 8);
            if (errno || !*optarg || *end || v > 0777) { fprintf(stderr, "karidns-tapstat: -m must be an octal mode up to 777\n"); return 2; }
            mode = v;
            break;
        }
        case 'f':
            if (strcmp(optarg, "text") == 0) fmt = TAPSTAT_TEXT;
            else if (strcmp(optarg, "json") == 0) fmt = TAPSTAT_JSON;
            else if (strcmp(optarg, "prom") == 0) fmt = TAPSTAT_PROM;
            else { fprintf(stderr, "karidns-tapstat: -f must be text, json or prom\n"); return 2; }
            break;
        case 't':
            if (strcmp(optarg, "query") == 0) count_type = 1;
            else if (strcmp(optarg, "response") == 0) count_type = 2;
            else { fprintf(stderr, "karidns-tapstat: -t must be query or response\n"); return 2; }
            break;
        case 'o': outpath = optarg; break;
        case 'V': printf("karidns-tapstat %s\n", KARIDNS_VERSION); return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc || (!sockpath && !filepath) || (sockpath && filepath)) {
        fprintf(stderr, "karidns-tapstat: give exactly one of -s and -r\n");
        usage(stderr);
        return 2;
    }

    tapstat_opts_t o;
    memset(&o, 0, sizeof(o));
    o.topk = (uint32_t)topk;
    o.show = (uint32_t)show;
    o.count_type = count_type;
    o.v4_prefix = (int)v4;
    o.v6_prefix = (int)v6;
    if (getentropy(o.hash_key, sizeof(o.hash_key)) != 0) {
        fprintf(stderr, "karidns-tapstat: no random key: %s\n", strerror(errno));
        return 1;
    }
    tapstat_t *st = tapstat_new(&o);
    if (!st) { fprintf(stderr, "karidns-tapstat: cannot allocate the tables (-k %lu)\n", topk); return 1; }
    for (size_t i = 0; i < nzl; i++) if (!add_zone_list(st, zlists[i])) return 2;
    for (size_t i = 0; i < nzf; i++) if (!add_zone_file(st, zfiles[i])) return 2;

    if (filepath) return run_file(st, filepath, fmt, outpath);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal; /* no SA_RESTART: poll() returns and the loop sees g_stop */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    return run_socket(st, sockpath, (mode_t)mode, (unsigned)interval, fmt, outpath);
}
