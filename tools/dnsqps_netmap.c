/* dnsqps: the netmap path (FreeBSD; net/netmap_user.h is in the base system).
 * One netmap descriptor per worker on the ring pair (--queue + worker) of the interface, or on a VALE switch port ("vale0:name", used by the tests).  Queries
 * are copied from pre-built Ethernet / IP / UDP frames (dq_frame_emit() patches the ID, port, source address and cookie) into the transmit ring; answers are read from the receive ring and matched on
 * the source address and port and the destination port (one source port per channel).  While a NIC is in netmap mode the host stack does not see its
 * traffic: use an interface the machine does not need for anything else (docs/dnsqps.md).  The next-hop MAC comes from --next-hop-mac or an ARP / neighbor
 * request sent through the ring itself. */
#include "dnsqps.h"

#ifdef __FreeBSD__
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <net/if.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

typedef struct {
    struct nm_desc *d;
    unsigned nchan;
    bool v6;
    uint8_t our_ip[16], srv_ip[16], pfx_mask[16];   /* our_ip: our address, or the base of the source prefix (then pfx_mask: its network bits) */
    bool pfx;
    uint16_t sport0, dport;
} nmio_t;

/* "vale0:a" is used as it is; an interface becomes "netmap:IFNAME-RING" */
static void nm_name(char *out, size_t n, const char *iface, unsigned ring) {
    if (strncmp(iface, "vale", 4) == 0 || strncmp(iface, "netmap:", 7) == 0 || strchr(iface, ':')) snprintf(out, n, "%s", iface);
    else snprintf(out, n, "netmap:%s-%u", iface, ring);
}

static int nm_tx_raw(void *ctx, const uint8_t *f, unsigned len) {
    nmio_t *x = ctx;
    if (nm_inject(x->d, f, len) == 0) {
        ioctl(NETMAP_FD(x->d), NIOCTXSYNC, NULL);
        if (nm_inject(x->d, f, len) == 0) return -1;
    }
    ioctl(NETMAP_FD(x->d), NIOCTXSYNC, NULL);
    return 0;
}

static int nm_rx_raw(void *ctx, const uint8_t **f, unsigned *len, unsigned wait_ms) {
    nmio_t *x = ctx;
    struct nm_pkthdr h;
    for (int pass = 0; pass < 2; pass++) {
        ioctl(NETMAP_FD(x->d), NIOCRXSYNC, NULL);
        const uint8_t *b = nm_nextpkt(x->d, &h);
        if (b) { *f = b; *len = h.caplen; return 1; }
        if (pass == 0 && wait_ms) {
            struct pollfd pf = { NETMAP_FD(x->d), POLLIN, 0 };
            poll(&pf, 1, (int)wait_ms);
        } else {
            break;
        }
    }
    return 0;
}

static void nm_close_io(dq_io_t *p) {
    nmio_t *x = (nmio_t *)p;
    if (x->d) nm_close(x->d);
    free(x);
}

static int nm_open_io(dq_io_t **out, const dq_cfg_t *c, dq_target_t *tg, unsigned worker, unsigned nchan, char *err, size_t errlen) {
    nmio_t *x = calloc(1, sizeof *x);
    if (!x) { snprintf(err, errlen, "out of memory"); return -1; }
    char name[96];
    nm_name(name, sizeof name, tg->ifname, c->queue + worker);
    x->d = nm_open(name, NULL, 0, NULL);
    if (!x->d) {
        snprintf(err, errlen, "nm_open(%.60s) failed: %s (needs root and the netmap module: kldload netmap; the interface must exist)", name, strerror(errno));
        free(x);
        return -1;
    }
    x->nchan = nchan;
    x->v6 = tg->v6;
    x->sport0 = (uint16_t)(tg->sport_base + worker * nchan);
    x->dport = tg->dport;
    memcpy(x->our_ip, tg->src_ip, 16);
    memcpy(x->srv_ip, tg->dst_ip, 16);
    x->pfx = tg->pfx.on;
    memcpy(x->pfx_mask, tg->pfx.mask, 16);
    if (!tg->have_dst_mac) {
        dq_rawif_t rif = { nm_tx_raw, nm_rx_raw, x };
        if (dq_raw_resolve_mac(&rif, tg, err, errlen) < 0) { nm_close_io((dq_io_t *)x); return -1; }
    }
    *out = (dq_io_t *)x;
    return 0;
}

/* pre-built frames straight into the transmit ring: the frame is copied into the slot and patched there (dq_frame_emit); one NIOCTXSYNC per call.  When the
 * ring is full the kernel gets what is there and the rest is tried once more, as nm_inject() does */
static unsigned nm_fill(nmio_t *x, unsigned chan, const dq_fsend_t *pk, unsigned n) {
    struct nm_desc *d = x->d;
    unsigned sent = 0, nr = d->last_tx_ring - d->first_tx_ring + 1, ri = d->cur_tx_ring;
    for (unsigned c = 0; c < nr && sent < n; c++, ri++) {
        if (ri > d->last_tx_ring) ri = d->first_tx_ring;
        struct netmap_ring *ring = NETMAP_TXRING(d->nifp, ri);
        while (sent < n && !nm_ring_empty(ring)) {
            struct netmap_slot *sl = &ring->slot[ring->cur];
            size_t fl = dq_frame_emit((uint8_t *)NETMAP_BUF(ring, sl->buf_idx), ring->nr_buf_size, &pk[sent], x->v6, (uint16_t)(x->sport0 + chan));
            if (fl == 0) return sent;
            sl->len = (uint16_t)fl;
            sl->flags = 0;
            ring->head = ring->cur = nm_ring_next(ring, ring->cur);
            d->cur_tx_ring = ri;
            sent++;
        }
    }
    return sent;
}

static int nm_send_frames(dq_io_t *p, unsigned chan, const dq_fsend_t *pk, unsigned n) {
    nmio_t *x = (nmio_t *)p;
    unsigned sent = nm_fill(x, chan, pk, n);
    if (sent < n) {
        ioctl(NETMAP_FD(x->d), NIOCTXSYNC, NULL);
        sent += nm_fill(x, chan, pk + sent, n - sent);
    }
    ioctl(NETMAP_FD(x->d), NIOCTXSYNC, NULL);
    return sent == 0 && n > 0 ? 0 : (int)sent;
}

static unsigned nm_scan(nmio_t *x, dq_rx_t *out, unsigned max) {
    unsigned got = 0;
    struct nm_pkthdr h;
    while (got < max) {
        const uint8_t *b = nm_nextpkt(x->d, &h);
        if (!b) break;
        dq_udp_view_t v;
        if (dq_frame_parse_udp_pfx(b, h.caplen, x->v6, x->our_ip, x->pfx ? x->pfx_mask : NULL, &v) < 0 || v.sport != x->dport || memcmp(v.sip, x->srv_ip, x->v6 ? 16 : 4) != 0) continue;
        if (v.dport < x->sport0 || (unsigned)(v.dport - x->sport0) >= x->nchan) continue;
        out[got].buf = v.payload;
        out[got].len = (uint16_t)v.plen;
        out[got].chan = (uint16_t)(v.dport - x->sport0);
        got++;
    }
    return got;
}

static int nm_recv(dq_io_t *p, dq_rx_t *out, unsigned max, unsigned wait_us) {
    nmio_t *x = (nmio_t *)p;
    ioctl(NETMAP_FD(x->d), NIOCRXSYNC, NULL);   /* also hands back the buffers of the last call */
    unsigned got = nm_scan(x, out, max);
    if (got == 0 && wait_us >= 200) {
        struct pollfd pf = { NETMAP_FD(x->d), POLLIN, 0 };
        poll(&pf, 1, (int)((wait_us + 999) / 1000));
        ioctl(NETMAP_FD(x->d), NIOCRXSYNC, NULL);
        got = nm_scan(x, out, max);
    }
    return (int)got;
}

const dq_io_ops_t dq_io_netmap = { "netmap", nm_open_io, NULL, nm_recv, nm_close_io, nm_send_frames };

/* the raw reflector of the tests: --reflect ADDR:PORT --io=netmap --iface vale0:r --src-mac MAC */
int dq_netmap_reflect(const dq_cfg_t *c, const atomic_bool *stop, char *err, size_t errlen) {
    char host[128];
    int port;
    uint8_t ip[16], mac[6];
    int fam;
    if (!dq_split_hostport(c->reflect, host, sizeof host, &port) || !dq_parse_ip(host, ip, &fam)) { snprintf(err, errlen, "--reflect with netmap needs a numeric address and port"); return -1; }
    if (!c->iface[0] || !c->src_mac[0] || !dq_parse_mac(c->src_mac, mac)) { snprintf(err, errlen, "--reflect with netmap needs --iface and --src-mac (the MAC the reflector answers to)"); return -1; }
    char name[96];
    nm_name(name, sizeof name, c->iface, c->queue);
    struct nm_desc *d = nm_open(name, NULL, 0, NULL);
    if (!d) { snprintf(err, errlen, "nm_open(%.60s) failed: %s", name, strerror(errno)); return -1; }
    uint8_t out[2048];
    fprintf(stderr, "dnsqps: reflecting on %s port %d (netmap %s)\n", host, port, name);
    while (!atomic_load_explicit(stop, memory_order_relaxed)) {
        struct pollfd pf = { NETMAP_FD(d), POLLIN, 0 };
        poll(&pf, 1, 100);
        ioctl(NETMAP_FD(d), NIOCRXSYNC, NULL);
        struct nm_pkthdr h;
        const uint8_t *b;
        bool any = false;
        while ((b = nm_nextpkt(d, &h)) != NULL) {
            size_t n = dq_frame_reflect(b, h.caplen, fam == 2, ip, mac, (uint16_t)port, out, sizeof out);
            if (n && nm_inject(d, out, n)) any = true;
        }
        if (any) ioctl(NETMAP_FD(d), NIOCTXSYNC, NULL);
    }
    nm_close(d);
    return 0;
}
#else
int dq_netmap_reflect(const dq_cfg_t *c, const atomic_bool *stop, char *err, size_t errlen) {
    (void)c; (void)stop;
    snprintf(err, errlen, "netmap is FreeBSD only");
    return -1;
}
#endif
