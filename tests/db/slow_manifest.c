/*
 * slow_manifest.c - a stand-in for karidns-dbloader that holds a manifest pass (tests/run_db_lookup_test.sh).
 *
 * The real loader is started behind this program: the stream of the Backend (descriptor 3) is relayed to it through a socket pair, byte for byte, and so is everything the
 * loader sends, except that after the MANIFEST_BEGIN of a pass the frames that follow (the pages, the end of the pass, the batch) are kept back until the file RELEASE_FILE exists.
 * The fetch stream (--fetch-fd) and the pipe of the log are the real loader's own (they are inherited), so it answers the Backend's requests for a zone, and for the zone that encloses
 * a name, while the first pass is held.  What the test needs: a first fill whose pass has not listed the zones yet, for as long as it wants.
 *
 *   cc -DREAL_LOADER='"/path/karidns-dbloader.real"' -DRELEASE_FILE='"/path/release"' -o karidns-dbloader slow_manifest.c
 *
 * -DHELLO_MASK=3 (optional): the features of the loader's HELLO (tag 5) are ANDed with it, so that the Backend meets a loader that has fewer of them (3: KDB_FEAT_STORE | KDB_FEAT_LOOKUP, the loader of an earlier
 * version that does a lookup of a name without the body of the zone).  The server clears the environment of the loader, so this is a compile time choice.
 *
 * Started by the server as `karidns-dbloader -s 3 [--debug N] [--fetch-fd 4] [--state-file F] [--log-stderr]`, which it passes on unchanged.  SIGTERM goes to the loader, and the program ends
 * with it.  A test tool: nothing here is meant to be robust beyond the test.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef REAL_LOADER
#error "define REAL_LOADER"
#endif
#ifndef RELEASE_FILE
#error "define RELEASE_FILE"
#endif
#ifndef HELLO_MASK
#define HELLO_MASK 0xFFFFFFFFu
#endif

#define HDR 12              /* KDB1: magic(4) type(2) flags(2) length(4) */
#define T_HELLO 1
#define T_MANIFEST_BEGIN 15

typedef struct { uint8_t *p; size_t len, off, cap; } buf_t;

static void buf_add(buf_t *b, const uint8_t *d, size_t n, bool rewind) {
    if (rewind && b->off == b->len) b->off = b->len = 0;      /* (not for what the loader says: scan and fwd are offsets into it) */
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 65536;
        while (nc < b->len + n) nc *= 2;
        uint8_t *np = realloc(b->p, nc);
        if (!np) _exit(70);
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
}

/* the features of a HELLO (frame at h, body length len) ANDed with mask: the TLVs are tag(2) length(2) value */
static void mask_hello(uint8_t *h, uint32_t len, uint32_t mask) {
    uint8_t *p = h + HDR, *end = h + HDR + len;
    while (p + 4 <= end) {
        const unsigned tag = ((unsigned)p[0] << 8) | p[1], vl = ((unsigned)p[2] << 8) | p[3];
        if (p + 4 + vl > end) return;
        if (tag == 5 && vl == 4) {
            uint32_t v = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
            v &= mask;
            p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16); p[6] = (uint8_t)(v >> 8); p[7] = (uint8_t)v;
            return;
        }
        p += 4 + vl;
    }
}

static volatile sig_atomic_t g_term;
static void on_term(int sig) { (void)sig; g_term = 1; }

/* write what is pending to fd (non-blocking); false: the other side is gone */
static bool flush_to(int fd, buf_t *b, size_t limit) {
    while (b->off < limit) {
        ssize_t n = write(fd, b->p + b->off, limit - b->off);
        if (n > 0) {
            b->off += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return true;
        return false;
    }
    return true;
}

int main(int argc, char **argv) {
    (void)argc;
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return 70;
    int a = fcntl(sp[0], F_DUPFD, 20), b = fcntl(sp[1], F_DUPFD, 20);     /* (above the descriptors the supervisor handed over) */
    close(sp[0]);
    close(sp[1]);
    pid_t pid = fork();
    if (pid < 0) return 70;
    if (pid == 0) {
        close(a);
        if (dup2(b, 3) < 0) _exit(70);
        close(b);
        execv(REAL_LOADER, argv);
        _exit(127);
    }
    close(b);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    fcntl(3, F_SETFL, fcntl(3, F_GETFL, 0) | O_NONBLOCK);
    fcntl(a, F_SETFL, fcntl(a, F_GETFL, 0) | O_NONBLOCK);
    buf_t to_loader = { 0 }, from_loader = { 0 };
    size_t fwd = 0;              /* the bytes of from_loader (from its start) that may go to the Backend */
    size_t scan = 0;             /* the frames up to here have been looked at */
    int held = 0;                /* 0: nothing held yet; 1: after MANIFEST_BEGIN, holding; 2: released */
    bool backend_open = true, loader_open = true;
    uint8_t tmp[65536];
    while (backend_open || loader_open) {
        if (g_term) {
            kill(pid, SIGTERM);
            g_term = 0;
        }
        if (held == 1 && access(RELEASE_FILE, F_OK) == 0) held = 2;
        /* the frames that may be sent on */
        for (;;) {
            if (held == 1) break;
            if (from_loader.len - scan < HDR) break;
            uint8_t *h = from_loader.p + scan;
            const uint32_t len = ((uint32_t)h[8] << 24) | ((uint32_t)h[9] << 16) | ((uint32_t)h[10] << 8) | h[11];
            if (from_loader.len - scan < HDR + (size_t)len) break;
            const unsigned type = ((unsigned)h[4] << 8) | h[5];
            if (type == T_HELLO) mask_hello(h, len, HELLO_MASK);
            scan += HDR + len;
            fwd = scan;
            if (held == 0 && type == T_MANIFEST_BEGIN) held = 1;       /* (the MANIFEST_BEGIN goes, what follows waits) */
        }
        if (held == 2 || !loader_open) fwd = from_loader.len;        /* (a loader that is gone: what it said goes on, as a stream that ends) */
        struct pollfd p[2];
        p[0].fd = backend_open ? 3 : -1;
        p[0].events = POLLIN | (from_loader.off < fwd ? POLLOUT : 0);
        p[1].fd = loader_open ? a : -1;
        p[1].events = POLLIN | (to_loader.off < to_loader.len ? POLLOUT : 0);
        (void)poll(p, 2, 50);
        if (backend_open && (p[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = read(3, tmp, sizeof(tmp));
            if (n > 0) buf_add(&to_loader, tmp, (size_t)n, true);
            else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) backend_open = false;
        }
        if (loader_open && (p[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = read(a, tmp, sizeof(tmp));
            if (n > 0) buf_add(&from_loader, tmp, (size_t)n, false);
            else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) loader_open = false;
        }
        if (backend_open && !flush_to(3, &from_loader, fwd)) backend_open = false;
        if (loader_open && !flush_to(a, &to_loader, to_loader.len)) loader_open = false;
        if (!backend_open && loader_open) {            /* the Backend is gone: the loader sees the end of its stream */
            close(a);
            loader_open = false;
        }
        if (!loader_open && backend_open && from_loader.off >= from_loader.len) backend_open = false;   /* (everything the loader said has gone on) */
    }
    int st = 0;
    (void)waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
