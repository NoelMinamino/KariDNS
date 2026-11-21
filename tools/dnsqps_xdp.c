/* dnsqps: the AF_XDP path (Linux, libxdp; built when pkg-config finds libxdp, -DHAVE_XDP).
 * One XDP socket per worker on NIC queue (--queue + worker), with its own UMEM: the first half of the frames feeds the fill ring (receive), the second half is
 * the pool of transmit frames.  The queries are copied from the pre-built frames (dq_frame_emit: patched with the ID, port, source address and cookie) into the transmit frame, and the answers are read from the
 * receive ring and matched on the source address and port and the destination port (one source port per channel).  The kernel's own stack never sees
 * the traffic of that queue: use an interface (or a queue) the host does not need, and steer the answers to the queues the workers use (ethtool -N / -X, docs/dnsqps.md).
 * XDP_USE_NEED_WAKEUP is set; --xdp-mode skb forces the generic mode (veth, a NIC without native XDP).  The kernel may give a mode other than the one asked (auto: generic on a driver without
 * native XDP; copy instead of zero-copy): xdp_describe() reads what it gave and the status line shows it. */
#include "dnsqps.h"

#ifdef HAVE_XDP
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#define XFRAME  2048u
#define XNRX    2048u   /* frames of the fill ring */
#define XNTX    2048u   /* frames of the transmit pool */

typedef struct {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    struct xsk_ring_prod fq, tx;
    struct xsk_ring_cons cq, rx;
    uint8_t *area;
    size_t area_len;
    unsigned nchan;
    uint64_t txfree[XNTX];
    unsigned ntxfree;
    uint64_t held[DQ_MAXBATCH];
    unsigned nheld;
    int fd;
    bool v6;
    uint8_t our_ip[16], srv_ip[16], pfx_mask[16];   /* our_ip: our address, or the base of the source prefix (then pfx_mask: its network bits) */
    bool pfx;
    uint16_t sport0, dport;
    unsigned ifindex;
    bool want_drv;                                    /* --xdp-mode drv */
} xdpio_t;

static void xdp_kick_tx(xdpio_t *x) {
    if (xsk_ring_prod__needs_wakeup(&x->tx)) sendto(x->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static void xdp_reclaim(xdpio_t *x) {
    uint32_t idx;
    unsigned n = xsk_ring_cons__peek(&x->cq, XNTX, &idx);
    if (!n) return;
    for (unsigned i = 0; i < n; i++) {
        uint64_t a = *xsk_ring_cons__comp_addr(&x->cq, idx + i);
        if (x->ntxfree < XNTX) x->txfree[x->ntxfree++] = a & ~(uint64_t)(XFRAME - 1);
    }
    xsk_ring_cons__release(&x->cq, n);
}

/* the frames of the last receive go back to the fill ring */
static void xdp_refill(xdpio_t *x) {
    if (x->nheld) {
        uint32_t idx;
        if (xsk_ring_prod__reserve(&x->fq, x->nheld, &idx) == x->nheld) {
            for (unsigned i = 0; i < x->nheld; i++) *xsk_ring_prod__fill_addr(&x->fq, idx + i) = x->held[i];
            xsk_ring_prod__submit(&x->fq, x->nheld);
            x->nheld = 0;
        }
    }
    if (xsk_ring_prod__needs_wakeup(&x->fq)) recvfrom(x->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
}

static int xdp_tx_raw(void *ctx, const uint8_t *f, unsigned len) {
    xdpio_t *x = ctx;
    xdp_reclaim(x);
    uint32_t idx;
    if (x->ntxfree == 0 || len > XFRAME || xsk_ring_prod__reserve(&x->tx, 1, &idx) != 1) return -1;
    uint64_t a = x->txfree[--x->ntxfree];
    memcpy(xsk_umem__get_data(x->area, a), f, len);
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&x->tx, idx);
    d->addr = a;
    d->len = len;
    xsk_ring_prod__submit(&x->tx, 1);
    xdp_kick_tx(x);
    return 0;
}

static int xdp_rx_raw(void *ctx, const uint8_t **f, unsigned *len, unsigned wait_ms) {
    xdpio_t *x = ctx;
    xdp_refill(x);
    if (x->nheld >= DQ_MAXBATCH) return -1;
    uint32_t idx;
    unsigned n = xsk_ring_cons__peek(&x->rx, 1, &idx);
    if (!n && wait_ms) {
        struct pollfd pf = { x->fd, POLLIN, 0 };
        poll(&pf, 1, (int)wait_ms);
        n = xsk_ring_cons__peek(&x->rx, 1, &idx);
    }
    if (!n) return 0;
    const struct xdp_desc *d = xsk_ring_cons__rx_desc(&x->rx, idx);
    *f = xsk_umem__get_data(x->area, d->addr);
    *len = d->len;
    x->held[x->nheld++] = d->addr & ~(uint64_t)(XFRAME - 1);
    xsk_ring_cons__release(&x->rx, 1);
    return 1;
}

static void xdp_close(dq_io_t *p) {
    xdpio_t *x = (xdpio_t *)p;
    if (x->xsk) xsk_socket__delete(x->xsk);
    if (x->umem) xsk_umem__delete(x->umem);
    if (x->area) munmap(x->area, x->area_len);
    free(x);
}

static int xdp_open(dq_io_t **out, const dq_cfg_t *c, dq_target_t *tg, unsigned worker, unsigned nchan, char *err, size_t errlen) {
    xdpio_t *x = calloc(1, sizeof *x);
    if (!x) { snprintf(err, errlen, "out of memory"); return -1; }
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);   /* old kernels charge the UMEM to the memlock limit; a failure is not fatal */
    x->nchan = nchan;
    x->v6 = tg->v6;
    x->sport0 = (uint16_t)(tg->sport_base + worker * nchan);
    x->dport = tg->dport;
    memcpy(x->our_ip, tg->src_ip, 16);
    memcpy(x->srv_ip, tg->dst_ip, 16);
    x->pfx = tg->pfx.on;
    memcpy(x->pfx_mask, tg->pfx.mask, 16);
    x->area_len = (size_t)(XNRX + XNTX) * XFRAME;
    x->area = mmap(NULL, x->area_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (x->area == MAP_FAILED) { x->area = NULL; snprintf(err, errlen, "cannot map the UMEM"); goto fail; }
    struct xsk_umem_config uc;
    memset(&uc, 0, sizeof uc);
    uc.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    uc.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    uc.frame_size = XFRAME;
    int r = xsk_umem__create(&x->umem, x->area, x->area_len, &x->fq, &x->cq, &uc);
    if (r) { x->umem = NULL; snprintf(err, errlen, "xsk_umem__create: %s", strerror(-r)); goto fail; }
    struct xsk_socket_config sc;
    memset(&sc, 0, sizeof sc);
    sc.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    sc.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    sc.xdp_flags = !strcmp(c->xdp_mode, "skb") ? XDP_FLAGS_SKB_MODE : !strcmp(c->xdp_mode, "drv") ? XDP_FLAGS_DRV_MODE : 0;
    sc.bind_flags = XDP_USE_NEED_WAKEUP;
    /* the queue of a socket that was just closed (the run before) is released a moment later: EBUSY is retried for about a second */
    for (int tries = 0;; tries++) {
        r = xsk_socket__create(&x->xsk, tg->ifname, c->queue + worker, x->umem, &x->rx, &x->tx, &sc);
        if (r != -EBUSY || tries >= 20) break;
        dq_sleep_us(50000);
    }
    if (r) {
        x->xsk = NULL;
        snprintf(err, errlen, "xsk_socket__create on %.40s queue %u: %s (needs root or CAP_NET_RAW + CAP_BPF; the interface must exist and have that queue)",
                 tg->ifname, c->queue + worker, strerror(-r));
        goto fail;
    }
    x->fd = xsk_socket__fd(x->xsk);
    x->ifindex = if_nametoindex(tg->ifname);
    x->want_drv = !strcmp(c->xdp_mode, "drv");
    uint32_t idx;
    if (xsk_ring_prod__reserve(&x->fq, XNRX, &idx) != XNRX) { snprintf(err, errlen, "cannot fill the fill ring"); goto fail; }
    for (unsigned i = 0; i < XNRX; i++) *xsk_ring_prod__fill_addr(&x->fq, idx + i) = (uint64_t)i * XFRAME;
    xsk_ring_prod__submit(&x->fq, XNRX);
    for (unsigned i = 0; i < XNTX; i++) x->txfree[x->ntxfree++] = (uint64_t)(XNRX + i) * XFRAME;
    if (!tg->have_dst_mac) {
        dq_rawif_t rif = { xdp_tx_raw, xdp_rx_raw, x };
        if (dq_raw_resolve_mac(&rif, tg, err, errlen) < 0) goto fail;
    }
    *out = (dq_io_t *)x;
    return 0;
fail:
    xdp_close((dq_io_t *)x);
    return -1;
}

static int xdp_send_frames(dq_io_t *p, unsigned chan, const dq_fsend_t *pk, unsigned n) {
    xdpio_t *x = (xdpio_t *)p;
    xdp_reclaim(x);
    unsigned want = n < x->ntxfree ? n : x->ntxfree;
    uint32_t idx;
    if (want == 0 || xsk_ring_prod__reserve(&x->tx, want, &idx) != want) {
        xdp_kick_tx(x);
        return 0;
    }
    for (unsigned i = 0; i < want; i++) {
        uint64_t a = x->txfree[--x->ntxfree];
        size_t fl = dq_frame_emit(xsk_umem__get_data(x->area, a), XFRAME, &pk[i], x->v6, (uint16_t)(x->sport0 + chan));
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&x->tx, idx + i);
        d->addr = a;
        d->len = (uint32_t)fl;
    }
    xsk_ring_prod__submit(&x->tx, want);
    xdp_kick_tx(x);
    return (int)want;
}

static int xdp_recv(dq_io_t *p, dq_rx_t *out, unsigned max, unsigned wait_us) {
    xdpio_t *x = (xdpio_t *)p;
    xdp_refill(x);
    if (x->nheld >= DQ_MAXBATCH) return 0;
    if (max > DQ_MAXBATCH - x->nheld) max = DQ_MAXBATCH - x->nheld;
    uint32_t idx;
    unsigned n = xsk_ring_cons__peek(&x->rx, max, &idx);
    if (!n && wait_us >= 200) {
        struct pollfd pf = { x->fd, POLLIN, 0 };
        poll(&pf, 1, (int)((wait_us + 999) / 1000));
        n = xsk_ring_cons__peek(&x->rx, max, &idx);
    }
    unsigned got = 0;
    for (unsigned i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&x->rx, idx + i);
        const uint8_t *data = xsk_umem__get_data(x->area, d->addr);
        dq_udp_view_t v;
        x->held[x->nheld++] = d->addr & ~(uint64_t)(XFRAME - 1);
        if (dq_frame_parse_udp_pfx(data, d->len, x->v6, x->our_ip, x->pfx ? x->pfx_mask : NULL, &v) < 0 || v.sport != x->dport || memcmp(v.sip, x->srv_ip, x->v6 ? 16 : 4) != 0) continue;
        unsigned ch = (unsigned)(uint16_t)(v.dport - x->sport0);
        if (v.dport < x->sport0 || ch >= x->nchan) continue;
        out[got].buf = v.payload;
        out[got].len = (uint16_t)v.plen;
        out[got].chan = (uint16_t)ch;
        got++;
    }
    if (n) xsk_ring_cons__release(&x->rx, n);
    return (int)got;
}

/* What the kernel gave: the XDP program of the interface in hardware, driver (native) or generic (skb) mode (IFLA_XDP_*_PROG_ID through bpf_xdp_query()), and whether this socket is zero-copy
 * (getsockopt XDP_OPTIONS, XDP_OPTIONS_ZEROCOPY, Linux 5.3; Documentation/networking/af_xdp.rst).  False when --xdp-mode drv was asked and the program is not in driver mode. */
static bool xdp_describe(dq_io_t *p, char *buf, size_t len) {
    xdpio_t *x = (xdpio_t *)p;
    const char *attach = "unknown", *copy = "unknown";
    LIBBPF_OPTS(bpf_xdp_query_opts, q);
    if (x->ifindex && bpf_xdp_query((int)x->ifindex, 0, &q) == 0)
        attach = q.hw_prog_id ? "hw" : q.drv_prog_id ? "drv" : q.skb_prog_id ? "skb" : "none";
#if defined(SOL_XDP) && defined(XDP_OPTIONS)
    struct xdp_options o;
    socklen_t ol = sizeof o;
    if (getsockopt(x->fd, SOL_XDP, XDP_OPTIONS, &o, &ol) == 0) copy = (o.flags & XDP_OPTIONS_ZEROCOPY) ? "zero-copy" : "copy";
#endif
    snprintf(buf, len, "xdp %s, %s", attach, copy);
    return !x->want_drv || !strcmp(attach, "drv");
}

const dq_io_ops_t dq_io_xdp = { "xdp", xdp_open, NULL, xdp_recv, xdp_close, xdp_send_frames, xdp_describe };
#else
typedef int dq_xdp_not_built;
#endif
