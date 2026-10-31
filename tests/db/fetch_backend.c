/*
 * fetch_backend.c - a stand-in for the Backend on both streams of karidns-dbloader (tests/run_db_fetch_test.sh; D1a milestone 2).
 *
 *   fetch_backend LOADER DBFILE ITEM...
 *
 * It starts LOADER with the two streams (`-s 3 --fetch-fd 4`), answers the handshake of the first stream the way the Backend does (CONFIG for one
 * view "default" that reads DBFILE with the SQLite3 driver, an empty INVENTORY, BATCH_RESULT for every batch) and, once the startup batch is
 * through, runs the ITEMs on the fetch stream in order:
 *   req:ID:ZONE:PRIO:MODE   send FETCH_REQ (request id ID, view 0, zone ZONE, priority 0..2, mode 0 zone / 1 summary)
 *   range:ID:ZONE:LO:HI     send FETCH_REQ with a range
 *   wait:N                  read until N answers (a whole zone or a ZONE_FAILED) have come
 *   begin:ID                read until the ZONE_BEGIN of request ID has come (the loader is busy with it)
 *   sleep:MS                keep serving the streams for MS milliseconds
 *   garbage:fetch           write bytes that are not KDB1 on the fetch stream; then wait for the loader to close it
 *   badmain                 send a FETCH_REQ on the first stream (a protocol error there); then wait for the loader to end
 *   flood:N:ZONE            send N requests (ids 1000..) for ZONE at once, priority 1
 * Every answer is checked by the state machine of the fetch stream (kdb_sm_init_fetch()) and printed, in the order it arrives:
 *   ANS id=ID zone=NAME kind=primary|secondary|catalog summary=0|1 presigned=0|1 serial=N rr=N data=N timers=R,T,E|-
 *   FAILED id=ID reason=TEXT
 * and at the end `DONE answers=N loader=STATUS`.  A protocol error of the loader prints `PROTOCOL ERROR: ...` and ends with status 1.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "../../dns_db_stream.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

typedef struct {
    int fd;
    kdb_framer_t fr;
    uint8_t *body;
    bool eof;
} chan_t;

static chan_t g_main, g_fetch;
static kdb_sm_t g_fsm;
static kdb_enc_t g_enc;
static bool g_startup_done;
static unsigned g_answers;
static uint64_t g_begin_seen[64];
static unsigned g_nbegin;
static pid_t g_pid;
static bool g_child_gone;
static int g_child_status;
static const char *g_dbfile;

static void die(const char *m) {
    printf("ERROR: %s\n", m);
    fflush(stdout);
    if (g_pid > 0) kill(g_pid, SIGKILL);
    exit(2);
}

static void write_all(int fd, const uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w > 0) {
            p += w;
            n -= (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pf = { fd, POLLOUT, 0 };
            poll(&pf, 1, 100);
            continue;
        }
        return;                                       /* (the loader is gone: the checks below say so) */
    }
}

static void send_enc(int fd) {
    if (g_enc.err) die("cannot encode a message");
    write_all(fd, g_enc.buf, g_enc.len);
    kdb_enc_reset(&g_enc);
}

static void send_config(void) {
    kdb_enc_reset(&g_enc);
    kdb_enc_begin(&g_enc, KDB_T_CONFIG);
    kdb_enc_u64(&g_enc, 1, 1);
    kdb_enc_str(&g_enc, 2, "sqlite3");
    kdb_enc_nest_begin(&g_enc, 4);
    kdb_enc_u16(&g_enc, 1, 0);
    kdb_enc_str(&g_enc, 2, "default");
    kdb_enc_str(&g_enc, 3, g_dbfile);
    kdb_enc_u8(&g_enc, 5, 0);
    kdb_enc_u32(&g_enc, 6, 2);
    kdb_enc_u32(&g_enc, 7, 1000);
    kdb_enc_u64(&g_enc, 8, KDB_DEFAULT_MAX_ZONE_RECORDS);
    kdb_enc_u64(&g_enc, 9, KDB_DEFAULT_MAX_ZONE_BYTES);
    kdb_enc_nest_end(&g_enc);
    kdb_enc_u32(&g_enc, 5, 3600);
    kdb_enc_u8(&g_enc, 6, 25);
    kdb_enc_u32(&g_enc, 7, 1);
    kdb_enc_end(&g_enc);
    send_enc(g_main.fd);
}

static void main_msg(const kdb_msg_t *m) {
    switch (m->type) {
    case KDB_T_HELLO:
        send_config();
        break;
    case KDB_T_INVENTORY_REQ:
        kdb_enc_reset(&g_enc);
        kdb_enc_begin(&g_enc, KDB_T_INVENTORY_END);
        kdb_enc_u64(&g_enc, 1, 0);
        kdb_enc_u64(&g_enc, 2, 0);
        kdb_enc_end(&g_enc);
        send_enc(g_main.fd);
        break;
    case KDB_T_BATCH_END:
        kdb_enc_reset(&g_enc);
        kdb_enc_begin(&g_enc, KDB_T_BATCH_RESULT);
        kdb_enc_u64(&g_enc, 1, m->u.batch_end.batch_id);
        kdb_enc_u32(&g_enc, 3, m->u.batch_end.n_zones);
        kdb_enc_u32(&g_enc, 4, 0);
        kdb_enc_u32(&g_enc, 5, 0);
        kdb_enc_u32(&g_enc, 6, 0);
        kdb_enc_end(&g_enc);
        send_enc(g_main.fd);
        g_startup_done = true;
        break;
    default:
        break;
    }
}

/* the answer being received on the fetch stream */
static struct {
    bool open;
    uint64_t id;
    char zone[DNS_NAME_TEXT_SIZE];
    uint8_t kind;
    bool summary, presigned;
    uint32_t serial;
    uint64_t rr;
    unsigned data;
    bool timers;
    uint32_t tr, tt, te;
} g_cur;

static void fetch_msg(const kdb_msg_t *m) {
    switch (m->type) {
    case KDB_T_ZONE_BEGIN: {
        const kdb_zone_begin_t *z = &m->u.zone_begin;
        memset(&g_cur, 0, sizeof(g_cur));
        g_cur.open = true;
        g_cur.id = z->request_id;
        snprintf(g_cur.zone, sizeof(g_cur.zone), "%s", z->name);
        g_cur.kind = z->zone_kind;
        g_cur.summary = (z->flags & KDB_ZF_SUMMARY) != 0;
        g_cur.presigned = (z->flags & KDB_ZF_PRESIGNED) != 0;
        g_cur.serial = z->serial;
        g_cur.rr = z->rr_count;
        g_cur.timers = z->has_soa_timers;
        g_cur.tr = z->soa_refresh;
        g_cur.tt = z->soa_retry;
        g_cur.te = z->soa_expire;
        g_begin_seen[g_nbegin++ % (sizeof(g_begin_seen) / sizeof(g_begin_seen[0]))] = z->request_id;      /* (the last 64) */
        break;
    }
    case KDB_T_ZONE_DATA:
        g_cur.data++;
        break;
    case KDB_T_ZONE_END: {
        char t[64] = "-";
        if (g_cur.timers) snprintf(t, sizeof(t), "%u,%u,%u", g_cur.tr, g_cur.tt, g_cur.te);
        printf("ANS id=%llu zone=%s kind=%s summary=%d presigned=%d serial=%u rr=%llu data=%u timers=%s\n", (unsigned long long)g_cur.id, g_cur.zone,
               g_cur.kind == KDB_ZK_PRIMARY ? "primary" : g_cur.kind == KDB_ZK_SECONDARY ? "secondary" : "catalog", g_cur.summary ? 1 : 0,
               g_cur.presigned ? 1 : 0, g_cur.serial, (unsigned long long)g_cur.rr, g_cur.data, t);
        g_cur.open = false;
        g_answers++;
        break;
    }
    case KDB_T_ZONE_FAILED: {
        char r[260];
        size_t n = m->u.zone_failed.reason.len < sizeof(r) - 1 ? m->u.zone_failed.reason.len : sizeof(r) - 1;
        memcpy(r, m->u.zone_failed.reason.p, n);
        r[n] = '\0';
        printf("FAILED id=%llu zone=%s reason=%s\n", (unsigned long long)m->u.zone_failed.request_id, m->u.zone_failed.name, r);
        g_answers++;
        break;
    }
    default:
        break;
    }
}

static void pump(chan_t *c, bool fetch) {
    uint8_t buf[65536];
    for (;;) {
        ssize_t n = read(c->fd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) {
            c->eof = true;
            return;
        }
        if (kdb_framer_feed(&c->fr, buf, (size_t)n) != KDB_OK) {
            printf("PROTOCOL ERROR: %s\n", c->fr.reason);
            exit(1);
        }
        kdb_frame_t fr;
        for (;;) {
            kdb_rc_t rc = kdb_framer_next(&c->fr, &fr);
            if (rc == KDB_MORE) break;
            if (rc != KDB_OK) {
                printf("PROTOCOL ERROR: %s\n", c->fr.reason);
                exit(1);
            }
            kdb_msg_t m;
            if (fetch) {
                rc = kdb_sm_accept(&g_fsm, &fr, &m);
                if (rc != KDB_OK) {
                    printf("PROTOCOL ERROR: %s\n", g_fsm.reason);
                    exit(1);
                }
                fetch_msg(&m);
            } else {
                char why[KDB_REASON_LEN];
                if (kdb_decode(&fr, 1, &m, why, sizeof(why)) != KDB_OK) {
                    printf("PROTOCOL ERROR: %s\n", why);
                    exit(1);
                }
                main_msg(&m);
            }
        }
    }
}

/* serve both streams for up to ms milliseconds, or until done() */
static void service(int ms, bool (*done)(void *), void *arg) {
    int64_t end = now_ms() + ms;
    for (;;) {
        if (done && done(arg)) return;
        int64_t left = end - now_ms();
        if (left <= 0) return;
        struct pollfd pf[2] = { { g_main.fd, POLLIN, 0 }, { g_fetch.fd, POLLIN, 0 } };
        poll(pf, 2, left > 50 ? 50 : (int)left);
        if (pf[0].revents & (POLLIN | POLLHUP)) pump(&g_main, false);
        if (g_fetch.fd >= 0 && (pf[1].revents & (POLLIN | POLLHUP))) pump(&g_fetch, true);
        if (!g_child_gone && waitpid(g_pid, &g_child_status, WNOHANG) == g_pid) g_child_gone = true;
        if (g_child_gone) return;
    }
}

static bool startup_done(void *a) { (void)a; return g_startup_done; }
static bool answers_reached(void *a) { return g_answers >= *(unsigned *)a; }
static bool begin_seen(void *a) {
    unsigned n = g_nbegin < 64 ? g_nbegin : 64;
    for (unsigned i = 0; i < n; i++)
        if (g_begin_seen[i] == *(uint64_t *)a) return true;
    return false;
}
static bool fetch_eof(void *a) { (void)a; return g_fetch.eof; }
static bool child_gone(void *a) { (void)a; return g_child_gone; }

static void send_req(uint64_t id, const char *zone, int prio, int mode, const char *lo, const char *hi) {
    kdb_enc_reset(&g_enc);
    kdb_enc_begin(&g_enc, KDB_T_FETCH_REQ);
    kdb_enc_u64(&g_enc, 1, id);
    kdb_enc_u16(&g_enc, 2, 0);
    kdb_enc_name(&g_enc, 3, zone);
    kdb_enc_u8(&g_enc, 4, (uint8_t)prio);
    kdb_enc_u8(&g_enc, 5, (uint8_t)mode);
    if (lo) {
        kdb_enc_name(&g_enc, 6, lo);
        kdb_enc_name(&g_enc, 7, hi);
    }
    kdb_enc_end(&g_enc);
    send_enc(g_fetch.fd);
}

static void chan_init(chan_t *c, int fd) {
    c->fd = fd;
    c->body = malloc(KDB_MAX_BODY);
    if (!c->body) die("out of memory");
    kdb_framer_init(&c->fr, KDB_FROM_LOADER, c->body, KDB_MAX_BODY);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: fetch_backend LOADER DBFILE ITEM...\n");
        return 2;
    }
    const char *loader = argv[1];
    g_dbfile = argv[2];
    signal(SIGPIPE, SIG_IGN);
    int a[2], f[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, a) != 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, f) != 0) die("socketpair");
    g_pid = fork();
    if (g_pid < 0) die("fork");
    if (g_pid == 0) {
        int h1 = fcntl(a[1], F_DUPFD, 10), h2 = fcntl(f[1], F_DUPFD, 10);
        if (h1 < 0 || h2 < 0 || dup2(h1, 3) < 0 || dup2(h2, 4) < 0) _exit(127);
        closefrom(5);
        execl(loader, "karidns-dbloader", "-s", "3", "--fetch-fd", "4", (char *)NULL);
        _exit(127);
    }
    close(a[1]);
    close(f[1]);
    chan_init(&g_main, a[0]);
    chan_init(&g_fetch, f[0]);
    kdb_framer_init(&g_fetch.fr, KDB_FROM_LOADER, g_fetch.body, KDB_MAX_BODY);
    kdb_limits_t lim = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, 1 };
    kdb_sm_init_fetch(&g_fsm, &lim);
    kdb_enc_init(&g_enc);

    service(30000, startup_done, NULL);
    if (!g_startup_done) die("the loader did not finish its startup batch");
    printf("STARTUP done\n");
    fflush(stdout);

    for (int i = 3; i < argc; i++) {
        const char *it = argv[i];
        if (strncmp(it, "req:", 4) == 0 || strncmp(it, "range:", 6) == 0) {
            bool range = it[0] == 'r' && it[1] == 'a';
            char buf[512];
            snprintf(buf, sizeof(buf), "%s", it + (range ? 6 : 4));
            char *p[5] = { 0 };
            int n = 0;
            for (char *s = buf; s && n < 5;) {
                p[n++] = s;
                s = strchr(s, ':');
                if (s) *s++ = '\0';
            }
            if (range ? n != 4 : n != 4) die("bad req item");
            send_req(strtoull(p[0], NULL, 10), p[1], range ? 0 : atoi(p[2]), range ? 0 : atoi(p[3]), range ? p[2] : NULL, range ? p[3] : NULL);
        } else if (strncmp(it, "wait:", 5) == 0) {
            unsigned want = (unsigned)atoi(it + 5);
            service(30000, answers_reached, &want);
            if (g_answers < want) die("timed out waiting for answers");
        } else if (strncmp(it, "begin:", 6) == 0) {
            uint64_t id = strtoull(it + 6, NULL, 10);
            service(30000, begin_seen, &id);
            if (!begin_seen(&id)) die("timed out waiting for a ZONE_BEGIN");
        } else if (strncmp(it, "sleep:", 6) == 0) {
            service(atoi(it + 6), NULL, NULL);
        } else if (strcmp(it, "garbage:fetch") == 0) {
            static const uint8_t junk[] = "NOT KDB1 AT ALL, JUST BYTES THAT ARE NOT A FRAME";
            write_all(g_fetch.fd, junk, sizeof(junk));
            service(10000, fetch_eof, NULL);
            printf("FETCH %s\n", g_fetch.eof ? "closed" : "still open");
            service(10000, child_gone, NULL);                   /* (a loader whose fetch stream is gone ends, for the supervisor to start another) */
            printf("LOADER %s\n", g_child_gone ? "ended" : "still running");
        } else if (strcmp(it, "closefetch") == 0) {
            close(g_fetch.fd);                                  /* the Backend drops the fetch stream (loader protocol error, send buffer overflow, memory) */
            g_fetch.fd = -1;
            service(10000, child_gone, NULL);
            printf("LOADER %s\n", g_child_gone ? "ended" : "still running");
        } else if (strcmp(it, "badmain") == 0) {
            kdb_enc_reset(&g_enc);
            kdb_enc_begin(&g_enc, KDB_T_FETCH_REQ);
            kdb_enc_u64(&g_enc, 1, 1);
            kdb_enc_u16(&g_enc, 2, 0);
            kdb_enc_name(&g_enc, 3, "x.test.");
            kdb_enc_u8(&g_enc, 4, 0);
            kdb_enc_u8(&g_enc, 5, 0);
            kdb_enc_end(&g_enc);
            send_enc(g_main.fd);
            service(10000, child_gone, NULL);
            printf("LOADER %s\n", g_child_gone ? "ended" : "still running");
        } else if (strncmp(it, "flood:", 6) == 0) {
            char buf[300];
            snprintf(buf, sizeof(buf), "%s", it + 6);
            char *z = strchr(buf, ':');
            if (!z) die("bad flood item");
            *z++ = '\0';
            int n = atoi(buf);
            kdb_enc_reset(&g_enc);                              /* all the requests in one write: they reach the loader together */
            for (int k = 0; k < n; k++) {
                kdb_enc_begin(&g_enc, KDB_T_FETCH_REQ);
                kdb_enc_u64(&g_enc, 1, 1000 + (uint64_t)k);
                kdb_enc_u16(&g_enc, 2, 0);
                kdb_enc_name(&g_enc, 3, z);
                kdb_enc_u8(&g_enc, 4, 1);
                kdb_enc_u8(&g_enc, 5, 0);
                kdb_enc_end(&g_enc);
            }
            send_enc(g_fetch.fd);
        } else {
            die("unknown item");
        }
        fflush(stdout);
    }
    close(g_fetch.fd);
    close(g_main.fd);
    int64_t end = now_ms() + 15000;
    while (!g_child_gone && now_ms() < end) {
        if (waitpid(g_pid, &g_child_status, WNOHANG) == g_pid) g_child_gone = true;
        else usleep(20000);
    }
    if (!g_child_gone) {
        kill(g_pid, SIGKILL);
        waitpid(g_pid, &g_child_status, 0);
    }
    printf("DONE answers=%u loader=%d\n", g_answers, WIFEXITED(g_child_status) ? WEXITSTATUS(g_child_status) : 128 + WTERMSIG(g_child_status));
    return 0;
}
