/* dnsqps: the I/O interface (dq_io_ops_t) and its portable paths: sendto / recv on a connected UDP socket per channel (every OS), and
 * sendmmsg / recvmmsg (Linux, FreeBSD).  The kernel-bypass paths are in dnsqps_xdp.c and dnsqps_netmap.c.  Also here: the loopback reflector
 * (--null-target, --reflect), the resolution of the server, and the interface / address look-up the raw paths need. */
#include "dnsqps.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define dq_close closesocket
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#define dq_close close
#ifdef __linux__
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>
#endif
#endif
#if defined(__linux__) || defined(__FreeBSD__)
#define DQ_HAVE_MMSG 1
#include <sys/uio.h>
#endif

#ifdef _WIN32
static bool would_block(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
static int set_nonblock(dq_sock_t s) { u_long on = 1; return ioctlsocket(s, FIONBIO, &on); }
#else
static bool would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static int set_nonblock(dq_sock_t s) { int fl = fcntl(s, F_GETFL, 0); return fl < 0 ? -1 : fcntl(s, F_SETFL, fl | O_NONBLOCK); }
#endif

static void bigbuf(dq_sock_t s) {
    int sz = 4 << 20;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&sz, sizeof sz);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&sz, sizeof sz);
}

/* ---------------------------------------------------------------- the target */
int dq_target_resolve(dq_target_t *tg, const dq_cfg_t *c, const char *server, int port, char *err, size_t errlen) {
    (void)c;
    struct addrinfo hints, *res = NULL;
    char ps[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(ps, sizeof ps, "%d", port);
    int rc = getaddrinfo(server, ps, &hints, &res);
    if (rc != 0 || !res) { snprintf(err, errlen, "cannot resolve '%.100s'", server); return -1; }
    memset(tg, 0, sizeof *tg);
    memcpy(&tg->dst, res->ai_addr, res->ai_addrlen);
    tg->dlen = (socklen_t)res->ai_addrlen;
    tg->v6 = res->ai_family == AF_INET6;
    tg->dport = (uint16_t)port;
    if (tg->v6) memcpy(tg->dst_ip, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, 16);
    else memcpy(tg->dst_ip, &((struct sockaddr_in *)res->ai_addr)->sin_addr, 4);
    freeaddrinfo(res);
    return 0;
}

#ifdef _WIN32
int dq_raw_prepare(dq_target_t *tg, const dq_cfg_t *c, char *err, size_t errlen) {
    (void)tg; (void)c;
    snprintf(err, errlen, "the kernel-bypass paths are not available on Windows");
    return -1;
}
#else
/* the interface that holds addr, and its MAC (AF_PACKET on Linux, AF_LINK on the BSDs and macOS) */
static int find_iface(const dq_target_t *tg, const uint8_t *addr, char *ifname, size_t iflen, uint8_t mac[6], bool *got_mac) {
    struct ifaddrs *ifa, *p;
    if (getifaddrs(&ifa) < 0) return -1;
    char found[64] = "";
    if (ifname[0]) snprintf(found, sizeof found, "%s", ifname);
    else {
        for (p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr) continue;
            if (!tg->v6 && p->ifa_addr->sa_family == AF_INET && memcmp(&((struct sockaddr_in *)p->ifa_addr)->sin_addr, addr, 4) == 0) { snprintf(found, sizeof found, "%s", p->ifa_name); break; }
            if (tg->v6 && p->ifa_addr->sa_family == AF_INET6 && memcmp(&((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr, addr, 16) == 0) { snprintf(found, sizeof found, "%s", p->ifa_name); break; }
        }
    }
    *got_mac = false;
    if (found[0]) {
        for (p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr || strcmp(p->ifa_name, found) != 0) continue;
#ifdef __linux__
            if (p->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *ll = (struct sockaddr_ll *)p->ifa_addr;
                if (ll->sll_halen == 6) { memcpy(mac, ll->sll_addr, 6); *got_mac = true; }
            }
#else
            if (p->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *dl = (struct sockaddr_dl *)p->ifa_addr;
                if (dl->sdl_alen == 6) { memcpy(mac, LLADDR(dl), 6); *got_mac = true; }
            }
#endif
        }
    }
    freeifaddrs(ifa);
    if (!found[0]) return -1;
    snprintf(ifname, iflen, "%s", found);
    return 0;
}

int dq_raw_prepare(dq_target_t *tg, const dq_cfg_t *c, char *err, size_t errlen) {
    uint8_t sip[16];
    int fam;
    if (!c->bind[0] || !dq_parse_ip(c->bind, sip, &fam) || (fam == 2) != tg->v6) {
        snprintf(err, errlen, "a kernel-bypass path needs the source address of the same family as the server: -b ADDR");
        return -1;
    }
    memcpy(tg->src_ip, sip, 16);
    snprintf(tg->ifname, sizeof tg->ifname, "%s", c->iface);
    bool got_mac = false;
    uint8_t mac[6];
    if (find_iface(tg, sip, tg->ifname, sizeof tg->ifname, mac, &got_mac) < 0) {
        if (!c->iface[0]) { snprintf(err, errlen, "no interface has the address %.60s: give --iface", c->bind); return -1; }
        snprintf(tg->ifname, sizeof tg->ifname, "%s", c->iface);   /* a name the kernel does not list (a netmap switch port): the MAC must be given */
    }
    if (c->src_mac[0]) dq_parse_mac(c->src_mac, tg->src_mac);
    else if (got_mac) memcpy(tg->src_mac, mac, 6);
    else { snprintf(err, errlen, "cannot read the MAC address of '%.40s': give --src-mac", tg->ifname); return -1; }
    if (c->next_hop[0]) dq_parse_ip(c->next_hop, tg->hop_ip, &fam);
    else memcpy(tg->hop_ip, tg->dst_ip, 16);
    if (c->next_hop_mac[0]) { dq_parse_mac(c->next_hop_mac, tg->dst_mac); tg->have_dst_mac = true; }
    tg->sport_base = (uint16_t)c->sport_base;
    return 0;
}
#endif

/* ---------------------------------------------------------------- sockets */
typedef struct {
    dq_sock_t s[DQ_MAXCHAN];
    unsigned n, batch, rr;
    bool mmsg, sink;
    struct sockaddr_storage dst;
    socklen_t dlen;
    uint8_t *rxbuf;
#ifdef DQ_HAVE_MMSG
    struct mmsghdr *rmh, *smh;
    struct iovec *riov, *siov;
#endif
} sockio_t;

static int sock_open_common(dq_io_t **out, const dq_cfg_t *c, dq_target_t *tg, unsigned nchan, bool mmsg, char *err, size_t errlen) {
    sockio_t *io = calloc(1, sizeof *io);
    if (!io) { snprintf(err, errlen, "out of memory"); return -1; }
    io->n = nchan;
    io->batch = c->batch;
    io->mmsg = mmsg;
    io->sink = c->null_sink;
    io->dst = tg->dst;
    io->dlen = tg->dlen;
    for (unsigned i = 0; i < DQ_MAXCHAN; i++) io->s[i] = DQ_BADSOCK;
    io->rxbuf = malloc((size_t)c->batch * DQ_RXMAX);
#ifdef DQ_HAVE_MMSG
    io->rmh = calloc(c->batch, sizeof *io->rmh);
    io->smh = calloc(c->batch, sizeof *io->smh);
    io->riov = calloc(c->batch, sizeof *io->riov);
    io->siov = calloc(c->batch, sizeof *io->siov);
    if (!io->rmh || !io->smh || !io->riov || !io->siov) { snprintf(err, errlen, "out of memory"); goto fail; }
#endif
    if (!io->rxbuf) { snprintf(err, errlen, "out of memory"); goto fail; }
    for (unsigned i = 0; i < nchan; i++) {
        dq_sock_t s = socket(tg->dst.ss_family, SOCK_DGRAM, 0);
        if (s == DQ_BADSOCK) { snprintf(err, errlen, "socket() failed: %s", strerror(errno)); goto fail; }
        io->s[i] = s;
        bigbuf(s);
        if (set_nonblock(s) < 0) { snprintf(err, errlen, "cannot make the socket non-blocking"); goto fail; }
        if (c->bind[0]) {
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof hints);
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_family = tg->dst.ss_family;
            hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
            if (getaddrinfo(c->bind, "0", &hints, &res) != 0 || !res) { snprintf(err, errlen, "-b %.60s is not an address of the server's family", c->bind); goto fail; }
            int br = bind(s, res->ai_addr, (socklen_t)res->ai_addrlen);
            freeaddrinfo(res);
            if (br < 0) { snprintf(err, errlen, "cannot bind %.60s: %s", c->bind, strerror(errno)); goto fail; }
        }
        if (!io->sink && connect(s, (struct sockaddr *)&tg->dst, tg->dlen) < 0) { snprintf(err, errlen, "connect() failed: %s", strerror(errno)); goto fail; }
    }
    *out = (dq_io_t *)io;
    return 0;
fail:
    for (unsigned i = 0; i < DQ_MAXCHAN; i++) if (io->s[i] != DQ_BADSOCK) dq_close(io->s[i]);
    free(io->rxbuf);
#ifdef DQ_HAVE_MMSG
    free(io->rmh); free(io->smh); free(io->riov); free(io->siov);
#endif
    free(io);
    return -1;
}

static int sendto_open(dq_io_t **io, const dq_cfg_t *c, dq_target_t *tg, unsigned worker, unsigned nchan, char *err, size_t errlen) {
    (void)worker;
    return sock_open_common(io, c, tg, nchan, false, err, errlen);
}

static void sock_close(dq_io_t *p) {
    sockio_t *io = (sockio_t *)p;
    for (unsigned i = 0; i < io->n; i++) dq_close(io->s[i]);
    free(io->rxbuf);
#ifdef DQ_HAVE_MMSG
    free(io->rmh); free(io->smh); free(io->riov); free(io->siov);
#endif
    free(io);
}

static int sendto_send(dq_io_t *p, unsigned chan, const dq_tx_t *pk, unsigned n) {
    sockio_t *io = (sockio_t *)p;
    for (unsigned i = 0; i < n; i++) {
        int r = io->sink ? (int)sendto(io->s[chan], (const char *)pk[i].buf, pk[i].len, 0, (struct sockaddr *)&io->dst, io->dlen)
                         : (int)send(io->s[chan], (const char *)pk[i].buf, pk[i].len, 0);
        if (r < 0) {
            if (would_block()) return (int)i;
            return i ? (int)i : -1;
        }
    }
    return (int)n;
}

/* answers waiting on the sockets, without blocking */
static int sock_scan(sockio_t *io, dq_rx_t *p, unsigned max) {
    unsigned got = 0;
    for (unsigned k = 0; k < io->n && got < max; k++) {
        unsigned idx = (io->rr + k) % io->n;
#ifdef DQ_HAVE_MMSG
        if (io->mmsg) {
            unsigned want = max - got;
            for (unsigned j = 0; j < want; j++) {
                io->riov[j].iov_base = io->rxbuf + (size_t)(got + j) * DQ_RXMAX;
                io->riov[j].iov_len = DQ_RXMAX;
                memset(&io->rmh[j].msg_hdr, 0, sizeof io->rmh[j].msg_hdr);
                io->rmh[j].msg_hdr.msg_iov = &io->riov[j];
                io->rmh[j].msg_hdr.msg_iovlen = 1;
            }
            int r = (int)recvmmsg(io->s[idx], io->rmh, want, MSG_DONTWAIT, NULL);
            for (int j = 0; j < r; j++) {
                size_t l = (size_t)io->rmh[j].msg_len;
                p[got].buf = io->rxbuf + (size_t)got * DQ_RXMAX;
                p[got].len = (uint16_t)(l > DQ_RXMAX ? DQ_RXMAX : l);
                p[got].chan = (uint16_t)idx;
                got++;
            }
            continue;
        }
#endif
        while (got < max) {
            uint8_t *b = io->rxbuf + (size_t)got * DQ_RXMAX;
            int r = (int)recv(io->s[idx], (char *)b, DQ_RXMAX, 0);
            if (r < 0) break;   /* nothing waiting, or an ICMP error of an earlier datagram: not an answer */
            p[got].buf = b;
            p[got].len = (uint16_t)r;
            p[got].chan = (uint16_t)idx;
            got++;
        }
    }
    io->rr = (io->rr + 1) % io->n;
    return (int)got;
}

static int sock_recv(dq_io_t *p, dq_rx_t *pk, unsigned max, unsigned wait_us) {
    sockio_t *io = (sockio_t *)p;
    int got = sock_scan(io, pk, max);
    if (got > 0 || wait_us < 200) return got;
#ifdef _WIN32
    WSAPOLLFD pf[DQ_MAXCHAN];
#else
    struct pollfd pf[DQ_MAXCHAN];
#endif
    for (unsigned i = 0; i < io->n; i++) { pf[i].fd = io->s[i]; pf[i].events = POLLIN; pf[i].revents = 0; }
    int ms = (int)((wait_us + 999) / 1000);
#ifdef _WIN32
    WSAPoll(pf, io->n, ms);
#else
    poll(pf, io->n, ms);
#endif
    return sock_scan(io, pk, max);
}

#ifdef DQ_HAVE_MMSG
static int mmsg_send(dq_io_t *p, unsigned chan, const dq_tx_t *pk, unsigned n) {
    sockio_t *io = (sockio_t *)p;
    for (unsigned i = 0; i < n; i++) {
        io->siov[i].iov_base = (void *)(uintptr_t)pk[i].buf;
        io->siov[i].iov_len = pk[i].len;
        memset(&io->smh[i].msg_hdr, 0, sizeof io->smh[i].msg_hdr);
        io->smh[i].msg_hdr.msg_iov = &io->siov[i];
        io->smh[i].msg_hdr.msg_iovlen = 1;
        if (io->sink) {
            io->smh[i].msg_hdr.msg_name = &io->dst;
            io->smh[i].msg_hdr.msg_namelen = io->dlen;
        }
    }
    int r = (int)sendmmsg(io->s[chan], io->smh, n, 0);
    if (r < 0) return would_block() ? 0 : -1;
    return r;
}

static int mmsg_open(dq_io_t **io, const dq_cfg_t *c, dq_target_t *tg, unsigned worker, unsigned nchan, char *err, size_t errlen) {
    (void)worker;
    return sock_open_common(io, c, tg, nchan, true, err, errlen);
}
#endif

const dq_io_ops_t dq_io_sendto = { "sendto", sendto_open, sendto_send, sock_recv, sock_close };
#ifdef DQ_HAVE_MMSG
const dq_io_ops_t dq_io_mmsg = { "mmsg", mmsg_open, mmsg_send, sock_recv, sock_close };
#endif

const dq_io_ops_t *dq_io_for(int mode, const char **why) {
    *why = "";
    switch (mode) {
    case DQ_IO_SENDTO: return &dq_io_sendto;
    case DQ_IO_MMSG:
#ifdef DQ_HAVE_MMSG
        return &dq_io_mmsg;
#else
        *why = "sendmmsg / recvmmsg exist on Linux and FreeBSD only";
        return NULL;
#endif
    case DQ_IO_XDP:
#ifdef HAVE_XDP
        return &dq_io_xdp;
#elif defined(__linux__)
        *why = "this build has no AF_XDP support (install libxdp-dev and libbpf-dev, then rebuild)";
        return NULL;
#else
        *why = "AF_XDP is Linux only";
        return NULL;
#endif
    case DQ_IO_NETMAP:
#ifdef __FreeBSD__
        return &dq_io_netmap;
#else
        *why = "netmap is FreeBSD only";
        return NULL;
#endif
    }
    *why = "unknown I/O path";
    return NULL;
}

/* ---------------------------------------------------------------- the reflector */
int dq_reflect_socket(const char *addr, int port, dq_sock_t *out, int *bound_port, char *err, size_t errlen) {
    struct addrinfo hints, *res = NULL;
    char ps[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(addr, ps, &hints, &res) != 0 || !res) { snprintf(err, errlen, "'%.60s' is not an address", addr); return -1; }
    dq_sock_t s = socket(res->ai_family, SOCK_DGRAM, 0);
    if (s == DQ_BADSOCK) { freeaddrinfo(res); snprintf(err, errlen, "socket() failed: %s", strerror(errno)); return -1; }
    bigbuf(s);
    if (bind(s, res->ai_addr, (socklen_t)res->ai_addrlen) < 0) {
        snprintf(err, errlen, "cannot bind %.60s port %d: %s", addr, port, strerror(errno));
        freeaddrinfo(res);
        dq_close(s);
        return -1;
    }
    freeaddrinfo(res);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    getsockname(s, (struct sockaddr *)&ss, &sl);
    *bound_port = ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port : ((struct sockaddr_in *)&ss)->sin_port);
    set_nonblock(s);
    *out = s;
    return 0;
}

void dq_reflect_loop(dq_sock_t s, const atomic_bool *stop, bool mmsg) {
    enum { RB = 64 };
    uint8_t *buf = malloc((size_t)RB * DQ_RXMAX);
    if (!buf) return;
#ifdef DQ_HAVE_MMSG
    struct mmsghdr mh[RB];
    struct iovec iov[RB];
    struct sockaddr_storage from[RB];
#endif
    while (!atomic_load_explicit(stop, memory_order_relaxed)) {
#ifdef _WIN32
        WSAPOLLFD pf = { s, POLLIN, 0 };
        WSAPoll(&pf, 1, 100);
#else
        struct pollfd pf = { s, POLLIN, 0 };
        poll(&pf, 1, 100);
#endif
#ifdef DQ_HAVE_MMSG
        if (mmsg) {
            for (int j = 0; j < RB; j++) {
                iov[j].iov_base = buf + (size_t)j * DQ_RXMAX;
                iov[j].iov_len = DQ_RXMAX;
                memset(&mh[j].msg_hdr, 0, sizeof mh[j].msg_hdr);
                mh[j].msg_hdr.msg_iov = &iov[j];
                mh[j].msg_hdr.msg_iovlen = 1;
                mh[j].msg_hdr.msg_name = &from[j];
                mh[j].msg_hdr.msg_namelen = sizeof from[j];
            }
            int r = (int)recvmmsg(s, mh, RB, MSG_DONTWAIT, NULL);
            if (r <= 0) continue;
            int k = 0;
            for (int j = 0; j < r; j++) {
                size_t l = (size_t)mh[j].msg_len;
                uint8_t *b = buf + (size_t)j * DQ_RXMAX;
                if (l < 12) continue;
                b[2] |= 0x80;   /* QR */
                iov[k].iov_base = b;
                iov[k].iov_len = l;
                mh[k].msg_hdr = mh[j].msg_hdr;
                mh[k].msg_hdr.msg_iov = &iov[k];
                from[k] = from[j];
                mh[k].msg_hdr.msg_name = &from[k];
                k++;
            }
            if (k) sendmmsg(s, mh, (unsigned)k, MSG_DONTWAIT);
            continue;
        }
#else
        (void)mmsg;
#endif
        for (int j = 0; j < RB; j++) {
            struct sockaddr_storage fr;
            socklen_t fl = sizeof fr;
            int r = (int)recvfrom(s, (char *)buf, DQ_RXMAX, 0, (struct sockaddr *)&fr, &fl);
            if (r < 0) break;
            if (r < 12) continue;
            buf[2] |= 0x80;
            sendto(s, (const char *)buf, r, 0, (struct sockaddr *)&fr, fl);
        }
    }
    free(buf);
}
