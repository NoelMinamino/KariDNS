/* dnsqps: a DNS query load generator (docs/dnsqps.md).
 * Each worker thread has its own channels (sockets, or UDP source ports on a raw path), its own copy of the query cursor, a table of 65536 outstanding
 * query slots per channel (the ID is the slot: IDs are handed out in order, so the oldest outstanding query is at the tail and a timeout is found
 * without a scan), and sends and receives through one small interface (dq_io_ops_t).  Open loop: a token bucket per worker at the target rate;
 * closed loop: N queries in flight.  Nothing is allocated per query.  On the raw paths every query of the table is a frame built once at start-up;
 * a send copies it and patches the ID, the port, the source address and the cookie (dq_frame_emit).
 * run_engine() is one load run; main() calls it once, or as an agent (--agent) for every controller that comes, or as the controller (--agents) of
 * other hosts' runs (dnsqps_agent.c). */
#include "dnsqps.h"
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#define dq_close close
#else
#define dq_close closesocket
#endif

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"
#endif

#define SLOTS 65536u

static atomic_bool g_stop, g_go, g_refl_stop, g_quit;
static FILE *g_st;   /* the status lines */

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&g_stop, true);
    atomic_store(&g_refl_stop, true);
    atomic_store(&g_quit, true);
}

typedef struct {
    uint64_t *sent_ns;   /* by ID; 0 = free */
    uint32_t next, tail; /* IDs handed out, and the oldest slot that may still be busy (both count up, the slot is the low 16 bits) */
    unsigned inflight;
} chan_t;

typedef struct {
    const dq_cfg_t *cfg;
    const dq_qtab_t *tab;
    const dq_io_ops_t *ops;
    const dq_pf_t *pf;             /* the pre-built frames (raw paths), NULL: build the frame per query */
    const dq_frame_tpl_t *ftpl;
    unsigned hlen;                 /* the Ethernet + IP + UDP headers of a frame */
    dq_io_t *io;
    unsigned id, nchan;
    chan_t chan[DQ_MAXCHAN];
    uint64_t count_limit, timeout_ns, prng;
    double rate_w;
    unsigned inflight_w;
    dq_live_t live;
    dq_counts_t cnt;
    dq_hist_t hist;
    uint64_t t_start, t_last;
    uint8_t *txbuf, *fscratch;
    dq_tx_t *tx;
    dq_fsend_t *fx;
    dq_rx_t *rx;
    pthread_t th;
    atomic_bool done;
} worker_t;

static void reap(worker_t *w, uint64_t now) {
    for (unsigned c = 0; c < w->nchan; c++) {
        chan_t *ch = &w->chan[c];
        while (ch->tail != ch->next) {
            uint64_t st = ch->sent_ns[ch->tail & (SLOTS - 1)];
            if (st == 0) {
                ch->tail++;
            } else if (now > st && now - st > w->timeout_ns) {
                ch->sent_ns[ch->tail & (SLOTS - 1)] = 0;
                ch->inflight--;
                w->cnt.lost++;
                ch->tail++;
            } else {
                break;
            }
        }
    }
}

static unsigned total_inflight(const worker_t *w) {
    unsigned n = 0;
    for (unsigned c = 0; c < w->nchan; c++) n += w->chan[c].inflight;
    return n;
}

static void publish(worker_t *w) {
    atomic_store_explicit(&w->live.sent, w->cnt.sent, memory_order_relaxed);
    atomic_store_explicit(&w->live.completed, w->cnt.completed, memory_order_relaxed);
    atomic_store_explicit(&w->live.lost, w->cnt.lost, memory_order_relaxed);
    atomic_store_explicit(&w->live.lat_sum, w->hist.sum_ns, memory_order_relaxed);
    atomic_store_explicit(&w->live.lat_cnt, w->hist.count, memory_order_relaxed);
}

static void handle_answers(worker_t *w, int g, uint64_t now) {
    for (int i = 0; i < g; i++) {
        const dq_rx_t *r = &w->rx[i];
        dq_resp_t rp;
        int pr = dq_resp_parse(r->buf, r->len, &rp);
        if (pr < 0) { w->cnt.malformed++; continue; }
        if (r->chan >= w->nchan) { w->cnt.foreign++; continue; }
        chan_t *ch = &w->chan[r->chan];
        uint64_t st = ch->sent_ns[rp.id];
        if (st == 0) { w->cnt.unmatched++; continue; }   /* a late answer (counted lost already) or a duplicate */
        ch->sent_ns[rp.id] = 0;
        ch->inflight--;
        uint64_t lat = now > st ? now - st : 0;
        w->cnt.completed++;
        w->cnt.recv_bytes += r->len;
        if (pr == 1) w->cnt.malformed++;
        if (rp.tc) w->cnt.truncated++;   /* still a completed answer (its RCODE counted too); an RRL slip is one of these (TC=1, nothing else) */
        w->cnt.rcode[rp.rcode <= 15 ? rp.rcode : 16]++;
        dq_hist_add(&w->hist, lat);
        w->t_last = now;
    }
}


/* one query for the raw path: the pre-built frame, or a frame built now (the table did not fit --frame-mem) */
static bool fill_frame(worker_t *w, const dq_pick_t *pk, unsigned slot, uint16_t id) {
    dq_fsend_t *f = &w->fx[slot];
    if (w->pf) {
        f->frame = dq_pf_get(w->pf, dq_pf_index(w->tab, pk), &f->flen, &f->cookie_off);
    } else {
        uint8_t *b = w->txbuf + (size_t)slot * DQ_MAXQ, *fb = w->fscratch + (size_t)slot * DQ_FRMAX;
        size_t len = dq_compose_pick(w->tab, pk, b, DQ_MAXQ);
        size_t fl = len ? dq_frame_build(w->ftpl, fb, DQ_FRMAX, b, len) : 0;
        if (!fl) return false;
        f->frame = fb;
        f->flen = (uint16_t)fl;
        f->cookie_off = pk->cookie_poff ? (uint16_t)(w->hlen + pk->cookie_poff) : 0;
    }
    f->plen = (uint16_t)(f->flen - w->hlen);
    f->id = id;
    if (f->cookie_off) {   /* RFC 7873 4.1: a client cookie is 8 octets; a new one per query (+cookie=random), no server cookie */
        uint64_t r = dq_rng_next(&w->prng);
        memcpy(f->cookie, &r, 8);
    }
    f->set_sip = w->cfg->srcpfx.on;
    if (f->set_sip) dq_prefix_pick(&w->cfg->srcpfx, &w->prng, f->sip);
    return true;
}

static void *worker_main(void *arg) {
    worker_t *w = arg;
    const dq_cfg_t *cfg = w->cfg;
    const bool fire = cfg->null_sink, open_loop = cfg->rate > 0, raw = w->ops->send_frames != NULL;
    const unsigned batch = cfg->batch;
    if (!cfg->no_pin && dq_pin_thread(cfg->cpu_base + w->id) < 0 && cfg->verbose && w->id == 0)
        fprintf(stderr, "dnsqps: cannot pin the threads to CPUs here\n");
    while (!atomic_load(&g_go)) dq_sleep_us(200);
    dq_cur_t cur;
    dq_cur_init(&cur, w->tab, w->id, cfg->threads, cfg->seed);
    uint64_t t0 = dq_now_ns(), dur_ns = (uint64_t)(cfg->duration * 1e9);
    w->t_start = w->t_last = t0;
    uint64_t last_tok = t0;
    double tokens = 0;
    bool sending = true;
    unsigned rr = 0;
    for (;;) {
        uint64_t now = dq_now_ns();
        if (!fire) reap(w, now);
        if (sending && (atomic_load_explicit(&g_stop, memory_order_relaxed) || (dur_ns && now - t0 >= dur_ns) ||
                        (w->count_limit && w->cnt.sent >= w->count_limit)))
            sending = false;
        if (!sending && (fire || total_inflight(w) == 0)) break;

        unsigned n = 0, sent = 0;
        if (sending) {
            uint64_t cap = batch;
            if (open_loop) {
                tokens += (double)(now - last_tok) * 1e-9 * w->rate_w;
                last_tok = now;
                double tmax = 2.0 * batch > w->rate_w * 0.01 ? 2.0 * batch : w->rate_w * 0.01;
                if (tokens > tmax) tokens = tmax;
                if ((uint64_t)tokens < cap) cap = (uint64_t)tokens;
            }
            if (!fire && (!open_loop || cfg->inflight)) {
                unsigned inf = total_inflight(w);
                uint64_t room = w->inflight_w > inf ? w->inflight_w - inf : 0;
                if (room < cap) cap = room;
            }
            if (w->count_limit && w->count_limit - w->cnt.sent < cap) cap = w->count_limit - w->cnt.sent;
            chan_t *ch = &w->chan[rr % w->nchan];
            unsigned c = rr % w->nchan;
            rr++;
            if (!fire) {
                uint32_t used = ch->next - ch->tail;
                uint64_t free_ids = used < SLOTS ? SLOTS - used : 0;
                if (free_ids < cap) cap = free_ids;
            }
            n = (unsigned)cap;
            dq_cur_t saved = cur;
            unsigned built = 0;
            for (; built < n; built++) {
                dq_pick_t pk;
                if (!dq_next_pick(w->tab, &cur, &pk, cfg->runs)) break;
                uint16_t id = (uint16_t)(ch->next + built);
                if (raw) {
                    if (!fill_frame(w, &pk, built, id)) break;
                } else {
                    uint8_t *b = w->txbuf + (size_t)built * DQ_MAXQ;
                    size_t len = dq_compose_pick(w->tab, &pk, b, DQ_MAXQ);
                    if (len == 0) break;
                    if (pk.cookie_poff) {   /* +cookie=random: a new client cookie in every query */
                        uint64_t r = dq_rng_next(&w->prng);
                        memcpy(b + pk.cookie_poff, &r, 8);
                    }
                    b[0] = (uint8_t)(id >> 8);
                    b[1] = (uint8_t)id;
                    w->tx[built].buf = b;
                    w->tx[built].len = (uint16_t)len;
                }
            }
            if (built < n) {   /* the query file is used up (-n passes) */
                n = built;
                sending = false;
            }
            if (n) {
                uint64_t ts = dq_now_ns();
                if (!fire)
                    for (unsigned i = 0; i < n; i++) ch->sent_ns[(ch->next + i) & (SLOTS - 1)] = ts;
                int r = raw ? w->ops->send_frames(w->io, c, w->fx, n) : w->ops->send(w->io, c, w->tx, n);
                if (r < 0) { w->cnt.send_errs++; r = 0; }
                sent = (unsigned)r;
                if (!fire)
                    for (unsigned i = sent; i < n; i++) ch->sent_ns[(ch->next + i) & (SLOTS - 1)] = 0;
                if (sent < n) {   /* not all taken: those queries are asked again, from where the cursor was */
                    /* (inline, not a function: only a full send queue reaches it, so a test run may not, and function coverage is 100 %) */
                    dq_pick_t rp;
                    cur = saved;
                    for (unsigned i = 0; i < sent; i++) dq_next_pick(w->tab, &cur, &rp, cfg->runs);
                    sending = true;   /* the end of the query file is reached again with the cursor put back */
                }
                for (unsigned i = 0; i < sent; i++) w->cnt.sent_bytes += raw ? w->fx[i].plen : w->tx[i].len;
                ch->next += sent;
                if (!fire) ch->inflight += sent;
                w->cnt.sent += sent;
                tokens -= sent;
                if (sent) w->t_last = ts;
            }
        }
        if (!fire) {
            unsigned wait_us = 0;
            if (sent == 0) {
                wait_us = 1000;
                if (sending && open_loop && w->rate_w > 0 && tokens < 1.0) {
                    double us = (1.0 - tokens) / w->rate_w * 1e6;
                    if (us < 1000) wait_us = (unsigned)us;
                }
            }
            int g = w->ops->recv(w->io, w->rx, batch, wait_us);
            if (g < 0) w->cnt.recv_errs++;
            else if (g > 0) handle_answers(w, g, dq_now_ns());
        } else if (sent == 0) {
            dq_sleep_us(100);
        }
        publish(w);
    }
    publish(w);
    atomic_store(&w->done, true);
    return NULL;
}

/* ---------------------------------------------------------------- the reflector threads and the timer */
typedef struct { dq_sock_t s; bool mmsg; pthread_t th; const atomic_bool *stop; } refl_t;

static void *refl_main(void *arg) {
    refl_t *r = arg;
    dq_reflect_loop(r->s, r->stop, r->mmsg);
    return NULL;
}

static void *timer_main(void *arg) {
    double secs = *(double *)arg;
    uint64_t end = dq_now_ns() + (uint64_t)(secs * 1e9);
    while (!atomic_load(&g_refl_stop) && dq_now_ns() < end) dq_sleep_us(20000);
    atomic_store(&g_refl_stop, true);
    return NULL;
}

/* ---------------------------------------------------------------- help */
static void usage(FILE *f) {
    fprintf(f,
"dnsqps - a DNS query load generator\n"
"\n"
"Usage: dnsqps [@server] [options] [+query-options]\n"
"\n"
"Queries (one of):\n"
"  -d, --file FILE       query file: one \"name [type] [+option ...]\" per line (# and ; start a comment)\n"
"  -z, --zones FILE      list of names (first field of each line): queries are generated from it\n"
"      --zipf S          popularity of the names, Zipf exponent (default 1.0; 0 = uniform)\n"
"      --miss F          share of queries for names that do not exist, 0-1 (default 0)\n"
"      --miss-pool N     how many different missing names (default 65536)\n"
"      --qtypes LIST     type mix, e.g. A:70,AAAA:20,MX:10 (default A)\n"
"      --seed N          seed of the generator (default: random)\n"
"\n"
"Target and load:\n"
"  -s, --server ADDR     server (default 127.0.0.1), or @ADDR as in dig\n"
"  -p, --port N          port (default 53)\n"
"  -b, --bind ADDR       source address (needed on a host with several addresses, and by --io=xdp|netmap);\n"
"                        ADDR/LEN on the raw paths: a source address per query out of that range (--allow-any-source: see below)\n"
"  -l, --time SEC        run time (default 30 when -n and -N are not given)\n"
"  -n, --runs N          passes over the query file\n"
"  -N, --count N         total number of queries\n"
"  -Q, --rate N          open loop: N queries per second in all (k and M suffixes: 500k)\n"
"  -q, --inflight N      closed loop: N queries in flight in all (default 256 per thread); with -Q a cap\n"
"  -T, --threads N       worker threads (default: the CPUs, at most 4)\n"
"  -c, --sockets N       sockets (source ports) per thread (default 1)\n"
"  -t, --timeout SEC     a query without an answer after this is lost (default 5)\n"
"  -B, --batch N         datagrams per system call or ring pass (default 64)\n"
"      --no-pin          do not pin the threads to CPUs;  --cpu-base N: first CPU\n"
"\n"
"I/O path:\n"
"      --io MODE         auto (default), sendto, mmsg (Linux, FreeBSD), xdp (Linux, AF_XDP), netmap (FreeBSD)\n"
"      --iface NAME      interface of a kernel-bypass path (with -b; --queue N: first NIC queue)\n"
"      --next-hop-mac M, --next-hop IP, --src-mac M, --xdp-mode auto|skb|drv, --sport-base N\n"
"      --frame-mem MB    memory for the pre-built frames of the raw paths (default 1024; above it a frame is built per query)\n"
"      --allow-any-source   let -b ADDR/LEN cover more than 198.18.0.0/15, 240.0.0.0/4 and 2001:db8::/32\n"
"\n"
"Several client hosts (docs/dnsqps.md):\n"
"      --agent ADDR:PORT    wait on this address for a controller and run what it sends (one at a time)\n"
"      --agents H:P,H:P     controller: run on these agents too; -Q, -N, -q and the -b prefix are shared among the senders\n"
"      --agent-key FILE     shared secret (an agent asks for it, a controller sends the proof);  --no-local: this host sends nothing\n"
"      --agent-no-key       an agent off loopback without a key (refused otherwise: a controller can aim the agent's load anywhere)\n"
"      --agent-timeout SEC  connect, ready and answer bound of the controller (default 60)\n"
"                           an agent sends with its own --io, --iface, MACs, -T, -c, -B, ... (the controller's are not used)\n"
"  e.g. dnsqps --agents 192.0.2.41:5301 --agent-key k.txt -d queries.txt -Q 200k -l 10   (this host and the agent send 100k each)\n"
"  e.g. dnsqps --agent 192.0.2.41:5301 --agent-key k.txt   (on the other host; the controller gives --agent-key k.txt too)\n"
"\n"
"Ceiling:\n"
"      --null-target[=reflect|sink]   send to a reflector (default) or a sink inside this process on loopback\n"
"      --reflect [ADDR:]PORT          run only a reflector (answers every datagram with QR set); -l SEC stops it\n"
"\n"
"Output:\n"
"  -S, --interval SEC    a line of figures every SEC seconds\n"
"  -j, --json            the final report as one JSON object\n"
"  -v, --verbose         -r, --ignore-rc: do not read ~/.dnsqpsrc   -h, --help   -V, --version\n"
"\n"
"Query options (dig spelling; the default is no EDNS, RD set):\n"
"  +edns +noedns +bufsize=N +dnssec +nsid +cookie[=random|HEX16] +padding=N +subnet=ADDR[/LEN]\n"
"  +rd +nord +cd +ad +aa +opcode=N +class=IN|CH|HS\n"
"\n"
"Examples:\n"
"  dnsqps @127.0.0.1 -d queries.txt -l 2\n"
"  dnsqps -s 127.0.0.1 -d queries.txt -n 1 -Q 50k --json\n"
"  dnsqps -z names.txt --miss 0.1 --qtypes A:80,AAAA:15,MX:5 --zipf 1.0 -N 2000 -S 1\n"
"  dnsqps -d queries.txt +dnssec +bufsize=1232 +nsid +cookie -N 500\n"
"  dnsqps -z names.txt --null-target -l 2 -T 2\n"
"  dnsqps --reflect 127.0.0.1:15300 -l 2\n"
"  dnsqps -d queries.txt +edns +cookie=random -N 1000\n"
"\n"
"Kernel bypass (root, a NIC the machine does not need otherwise; see docs/dnsqps.md):\n"
"  dnsqps -s 198.51.100.2 -b 198.51.100.1 --io=xdp --iface eth1 -z names.txt -l 30\n"
"  dnsqps -s 198.51.100.2 -b 198.51.100.1 --io=netmap --iface em1 -z names.txt -l 30\n"
"  dnsqps -s 198.51.100.2 -b 198.18.0.0/16 --io=netmap --iface em1 -z names.txt -l 30   (a source address out of 198.18.0.0/16 per query)\n"
"\n"
"Defaults can be put in ~/.dnsqpsrc (the same options, '#' starts a comment); -r ignores it.\n"
"Exit status: 0 = ran (some answer came), 1 = no answer at all, 2 = usage or setup error, 3 = an agent was lost during the run.\n");
}


static int die(const char *msg) {
    fprintf(stderr, "dnsqps: %s\n", msg);
    return 2;
}

static void free_worker(worker_t *w, const dq_io_ops_t *ops, bool opened) {
    if (opened && w->io) ops->close(w->io);
    for (unsigned c = 0; c < DQ_MAXCHAN; c++) free(w->chan[c].sent_ns);
    free(w->txbuf); free(w->fscratch); free(w->tx); free(w->fx); free(w->rx);
}

/* ---------------------------------------------------------------- one run */
static int run_engine(dq_cfg_t *cfg, const dq_run_hooks_t *hooks, dq_report_t *rep, char *err, size_t errlen) {
    FILE *st = g_st;
    if (cfg->seed == 0) cfg->seed = dq_now_ns() ^ ((uint64_t)time(NULL) << 20);
    /* a client cookie that stays the same for the whole run (RFC 7873 4.1), unless +cookie=HEX gave one */
    if (!cfg->qo.cookie_set)
        for (int i = 0; i < 8; i++) cfg->qo.cookie_val[i] = (uint8_t)((cfg->seed >> (i * 8)) ^ (cfg->seed >> (i * 5 + 3)));
    atomic_store(&g_go, false);

    /* ----- the queries */
    dq_qtab_t tab;
    if (dq_qtab_load(&tab, cfg, err, errlen) < 0) return -1;
    unsigned nthr = cfg->threads ? cfg->threads : (dq_ncpus() < 4 ? dq_ncpus() : 4);
    if (!tab.gen && nthr > tab.n) nthr = (unsigned)tab.n;
    if (cfg->count && nthr > cfg->count) nthr = (unsigned)cfg->count;   /* every thread has a share of -N (a share of 0 would mean no limit) */
    if (nthr == 0) nthr = 1;
    cfg->threads = nthr;
    unsigned nchan = cfg->sockets;
    int rc = -1;
    dq_target_t tg;
    refl_t *refl = NULL;
    unsigned nrefl = 0;
    dq_sock_t sink_s = DQ_BADSOCK;
    int null_port = 0;
    worker_t *ws = NULL;
    dq_pf_t pf;
    memset(&pf, 0, sizeof pf);
    dq_frame_tpl_t ftpl;
    memset(&ftpl, 0, sizeof ftpl);
    atomic_bool rstop;
    atomic_init(&rstop, false);
    unsigned nopen = 0;
    const dq_io_ops_t *ops = NULL;

    /* ----- the target; --null-target: a reflector (or a sink) per thread on loopback */
    if (cfg->null_target) {
        if (cfg->null_sink) {
            if (dq_reflect_socket("127.0.0.1", 0, &sink_s, &null_port, err, errlen) < 0) goto out;
        } else {
            refl = calloc(nthr, sizeof *refl);
            if (!refl) { snprintf(err, errlen, "out of memory"); goto out; }
            for (unsigned i = 0; i < nthr; i++) {
                int p;
                if (dq_reflect_socket("127.0.0.1", 0, &refl[i].s, &p, err, errlen) < 0) goto out;
                refl[i].stop = &rstop;
                nrefl++;
            }
        }
        snprintf(cfg->server, sizeof cfg->server, "127.0.0.1");
        if (dq_target_resolve(&tg, cfg, "127.0.0.1", 1, err, errlen) < 0) goto out;
        if (cfg->null_sink) {
            tg.dport = (uint16_t)null_port;
            ((struct sockaddr_in *)&tg.dst)->sin_port = htons((uint16_t)null_port);
        }
    } else if (dq_target_resolve(&tg, cfg, cfg->server, cfg->port, err, errlen) < 0) {
        goto out;
    }

    /* ----- the I/O path */
    const char *why = "";
    bool raw_try = false;
    const char *auto_note = "";
    if (cfg->io == DQ_IO_AUTO) {
        if (cfg->iface[0] && !cfg->null_target) {
#if defined(__linux__)
            ops = dq_io_for(DQ_IO_XDP, &why);
#elif defined(__FreeBSD__)
            ops = dq_io_for(DQ_IO_NETMAP, &why);
#endif
            if (ops) raw_try = true;
            else fprintf(st, "[Status] --iface given, but no kernel-bypass path here (%s); using sockets\n", why);
        }
        if (!ops) ops = dq_io_for(DQ_IO_MMSG, &why);
        if (!ops) ops = &dq_io_sendto;
        auto_note = " (auto)";
    } else {
        ops = dq_io_for(cfg->io, &why);
        if (!ops) { snprintf(err, errlen, "--io: not available here: %s", why); goto out; }
        raw_try = cfg->io == DQ_IO_XDP || cfg->io == DQ_IO_NETMAP;
    }
    ws = calloc(nthr, sizeof *ws);
    if (!ws) { snprintf(err, errlen, "out of memory"); goto out; }
    bool opened_ok = false;
    for (int attempt = 0; attempt < 2 && !opened_ok; attempt++) {
        dq_target_t wtg0 = tg;
        if (raw_try && dq_raw_prepare(&wtg0, cfg, err, errlen) < 0) goto raw_failed;
        tg = wtg0;
        opened_ok = true;
        nopen = 0;
        for (unsigned i = 0; i < nthr; i++) {
            dq_target_t wtg = tg;
            if (cfg->null_target && !cfg->null_sink) {   /* thread i talks to reflector i */
                struct sockaddr_in *sa = (struct sockaddr_in *)&wtg.dst;
                struct sockaddr_in bs;
                socklen_t bl = sizeof bs;
                getsockname(refl[i].s, (struct sockaddr *)&bs, &bl);
                sa->sin_port = bs.sin_port;
            }
            ws[i].cfg = cfg;
            if (ops->open(&ws[i].io, cfg, &wtg, i, nchan, err, errlen) < 0) {
                for (unsigned k = 0; k < i; k++) ops->close(ws[k].io);
                nopen = 0;
                opened_ok = false;
                break;
            }
            nopen++;
            memcpy(tg.dst_mac, wtg.dst_mac, 6);   /* the first thread resolved the next hop through its queue */
            tg.have_dst_mac = wtg.have_dst_mac;
        }
        if (opened_ok) break;
raw_failed:
        if (!raw_try || cfg->io != DQ_IO_AUTO) goto out;
        fprintf(st, "[Status] %s unavailable: %s; using sockets\n", ops->name, err);
        raw_try = false;
        ops = dq_io_for(DQ_IO_MMSG, &why);
        if (!ops) ops = &dq_io_sendto;
        auto_note = " (auto, fell back)";
    }
    if (!opened_ok) goto out;
    if (cfg->srcpfx.on && !ops->send_frames) {   /* an automatic fall-back to sockets: the source prefix cannot be kept */
        snprintf(err, errlen, "-b ADDR/LEN (a source prefix) needs a kernel-bypass path, and %s is not one", ops->name);
        goto out;
    }

    /* ----- the frames of a raw path: every query of the table, built once */
    char frame_note[160] = "";
    if (ops->send_frames) {
        dq_frame_tpl_init(&ftpl, tg.src_mac, tg.dst_mac, tg.v6, tg.src_ip, tg.dst_ip, (uint16_t)cfg->sport_base, tg.dport);
        uint64_t need = dq_pf_size(&tab, &ftpl);
        if (need == UINT64_MAX) { snprintf(err, errlen, "a query does not fit a frame"); goto out; }
        if (need <= ((uint64_t)cfg->frame_mem_mb << 20)) {
            if (dq_pf_build(&pf, &tab, &ftpl, err, errlen) < 0) goto out;
            snprintf(frame_note, sizeof frame_note, ", %zu frames pre-built (%.1f MiB)", pf.n, (double)need / 1048576.0);
        } else {
            snprintf(frame_note, sizeof frame_note, ", frames built per query (%.1f MiB would be needed, --frame-mem is %u)", (double)need / 1048576.0, cfg->frame_mem_mb);
        }
    }

    /* ----- the workers */
    uint64_t inflight_total = cfg->inflight ? cfg->inflight : (uint64_t)256 * nthr;
    for (unsigned i = 0; i < nthr; i++) {
        worker_t *w = &ws[i];
        w->cfg = cfg;
        w->tab = &tab;
        w->ops = ops;
        w->pf = pf.n ? &pf : NULL;
        w->ftpl = &ftpl;
        w->hlen = ftpl.hlen;
        w->id = i;
        w->nchan = nchan;
        w->prng = (cfg->seed ^ ((uint64_t)(i + 1) * 0x9E3779B97F4A7C15ull)) | 1;
        w->timeout_ns = (uint64_t)(cfg->timeout * 1e9);
        w->count_limit = cfg->count ? cfg->count / nthr + (i < cfg->count % nthr ? 1 : 0) : 0;
        w->rate_w = (double)cfg->rate / nthr;
        w->inflight_w = (unsigned)((inflight_total + nthr - 1) / nthr);
        if (w->inflight_w > SLOTS - 1) w->inflight_w = SLOTS - 1;
        dq_hist_init(&w->hist);
        w->txbuf = malloc((size_t)cfg->batch * DQ_MAXQ);
        w->tx = calloc(cfg->batch, sizeof *w->tx);
        w->rx = calloc(cfg->batch, sizeof *w->rx);
        bool okmem = w->txbuf && w->tx && w->rx;
        if (ops->send_frames) {
            w->fx = calloc(cfg->batch, sizeof *w->fx);
            okmem = okmem && w->fx;
            if (!pf.n) { w->fscratch = malloc((size_t)cfg->batch * DQ_FRMAX); okmem = okmem && w->fscratch; }
        }
        for (unsigned c = 0; c < nchan && okmem; c++) {
            if (!cfg->null_sink) {
                w->chan[c].sent_ns = calloc(SLOTS, sizeof(uint64_t));
                okmem = w->chan[c].sent_ns != NULL;
            }
        }
        if (!okmem) { snprintf(err, errlen, "out of memory"); goto out; }
    }

    const char *mode = cfg->rate ? "open loop" : "closed loop";
    fprintf(st, "[Status] dnsqps %s: ", KARIDNS_VERSION);
    if (cfg->null_target) fprintf(st, "loopback");
    else fprintf(st, "%s port %d", cfg->server, cfg->port);
    fprintf(st, ", I/O path %s%s, %u thread(s) x %u socket(s), %s", ops->name, auto_note, nthr, nchan, mode);
    if (cfg->rate) fprintf(st, " %" PRIu64 " qps", cfg->rate);
    if (cfg->null_target) fprintf(st, ", null target (%s)", cfg->null_sink ? "sink" : "reflector");
    if (cfg->srcpfx.on) { char pb[80]; dq_prefix_format(&cfg->srcpfx, pb, sizeof pb); fprintf(st, ", source %s", pb); }
    fprintf(st, "%s\n", frame_note);
    if (ops->describe && nopen) {   /* what the kernel gave (the first thread's: the threads share the interface and its driver) */
        char given[192];
        if (ops->describe(ws[0].io, given, sizeof given)) fprintf(st, "[Status] %s\n", given);
        else fprintf(st, "[Status] warning: --xdp-mode %s was asked, the kernel gave %s: the rates are not those of the driver mode\n", cfg->xdp_mode, given);
    }
    fflush(st);

    /* ----- ready: with a controller, the others are waited for here */
    if (hooks && hooks->ready && hooks->ready(hooks->ctx) < 0) { snprintf(err, errlen, "the run was not started"); goto out; }

    for (unsigned i = 0; i < nrefl; i++) {
        refl[i].mmsg = strcmp(ops->name, "mmsg") == 0;
        pthread_create(&refl[i].th, NULL, refl_main, &refl[i]);
    }
    unsigned started = 0;
    for (unsigned i = 0; i < nthr; i++) {
        if (pthread_create(&ws[i].th, NULL, worker_main, &ws[i]) != 0) break;
        started++;
    }
    if (started < nthr) {
        atomic_store(&g_stop, true);
        atomic_store(&g_go, true);
        for (unsigned i = 0; i < started; i++) pthread_join(ws[i].th, NULL);
        atomic_store(&rstop, true);
        for (unsigned i = 0; i < nrefl; i++) pthread_join(refl[i].th, NULL);
        snprintf(err, errlen, "cannot start the worker threads");
        goto out;
    }
    uint64_t t_go = dq_now_ns();
    atomic_store(&g_go, true);

    /* ----- wait; interval lines */
    uint64_t next_tick = t_go + (uint64_t)(cfg->interval * 1e9), last_tick = t_go;
    uint64_t p_sent = 0, p_done = 0, p_lost = 0, p_ls = 0, p_lc = 0;
    for (;;) {
        unsigned ndone = 0;
        for (unsigned i = 0; i < nthr; i++) if (atomic_load(&ws[i].done)) ndone++;
        if (ndone == nthr) break;
        dq_sleep_us(10000);
        dq_livesum_t ls = { 0, 0, 0, 0, 0 };
        for (unsigned i = 0; i < nthr; i++) {
            ls.sent += atomic_load_explicit(&ws[i].live.sent, memory_order_relaxed);
            ls.done += atomic_load_explicit(&ws[i].live.completed, memory_order_relaxed);
            ls.lost += atomic_load_explicit(&ws[i].live.lost, memory_order_relaxed);
            ls.lat_sum += atomic_load_explicit(&ws[i].live.lat_sum, memory_order_relaxed);
            ls.lat_cnt += atomic_load_explicit(&ws[i].live.lat_cnt, memory_order_relaxed);
        }
        if (hooks && hooks->tick && hooks->tick(hooks->ctx, &ls)) atomic_store(&g_stop, true);   /* totals of the other senders are added here */
        if (cfg->interval > 0 && dq_now_ns() >= next_tick) {
            uint64_t now = dq_now_ns();
            dq_print_interval(st, (double)(now - t_go) / 1e9, (double)(now - last_tick) / 1e9, ls.sent - p_sent, ls.done - p_done, ls.lost - p_lost,
                              ls.lat_sum - p_ls, ls.lat_cnt - p_lc);
            p_sent = ls.sent; p_done = ls.done; p_lost = ls.lost; p_ls = ls.lat_sum; p_lc = ls.lat_cnt;
            last_tick = now;
            next_tick += (uint64_t)(cfg->interval * 1e9);
        }
    }
    for (unsigned i = 0; i < nthr; i++) pthread_join(ws[i].th, NULL);

    /* ----- the report */
    memset(rep, 0, sizeof *rep);
    dq_hist_init(&rep->h);
    uint64_t t_end = 0, t_begin = UINT64_MAX;
    for (unsigned i = 0; i < nthr; i++) {
        dq_counts_add(&rep->c, &ws[i].cnt);
        dq_hist_merge(&rep->h, &ws[i].hist);
        if (ws[i].t_last > t_end) t_end = ws[i].t_last;
        if (ws[i].t_start < t_begin) t_begin = ws[i].t_start;
    }
    rep->run_s = t_end > t_begin ? (double)(t_end - t_begin) / 1e9 : 0;
    rep->io_name = ops->name;
    rep->threads = nthr;
    rep->sockets = nchan;
    rep->sink = cfg->null_sink;
    if (cfg->null_target) snprintf(rep->server, sizeof rep->server, "null target (%s)", cfg->null_sink ? "sink" : "reflector");
    else snprintf(rep->server, sizeof rep->server, "%s:%d", cfg->server, cfg->port);
    atomic_store(&rstop, true);
    for (unsigned i = 0; i < nrefl; i++) pthread_join(refl[i].th, NULL);
    rc = 0;
out:
    atomic_store(&rstop, true);
    if (ws) {
        for (unsigned i = 0; i < nthr; i++) free_worker(&ws[i], ops, i < nopen);
        free(ws);
    }
    for (unsigned i = 0; i < nrefl; i++) dq_close(refl[i].s);
    if (sink_s != DQ_BADSOCK) dq_close(sink_s);
    free(refl);
    dq_pf_free(&pf);
    dq_qtab_free(&tab);
    return rc;
}

/* ---------------------------------------------------------------- main */
int main(int argc, char **argv) {
    dq_cfg_t cfg;
    char err[320];
    dq_cfg_default(&cfg);
    if (dq_net_init() < 0) return die("cannot start the network stack");
    bool norc = false;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--ignore-rc")) norc = true;
    if (!norc && dq_load_rc(&cfg, err, sizeof err) < 0) return die(err);
    if (dq_parse_args(&cfg, argc - 1, argv + 1, err, sizeof err) < 0) return die(err);
    if (cfg.help) { usage(stdout); return 0; }
    if (cfg.version) {
        const char *w;
        printf("dnsqps %s\nI/O paths built in:", KARIDNS_VERSION);
        for (int m = DQ_IO_SENDTO; m <= DQ_IO_NETMAP; m++) {
            const dq_io_ops_t *o = dq_io_for(m, &w);
            if (o) printf(" %s", o->name);
        }
        printf("\n");
        return 0;
    }
    if (dq_cfg_check(&cfg, err, sizeof err) < 0) return die(err);
    if (cfg.seed == 0) cfg.seed = dq_now_ns() ^ ((uint64_t)time(NULL) << 20);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    g_st = (cfg.json || cfg.agent[0]) ? stderr : stdout;   /* status lines */

    /* ----- a reflector only */
    if (cfg.reflect[0]) {
        double secs = cfg.duration;
        pthread_t tm;
        bool have_timer = false;
        if (secs > 0 && pthread_create(&tm, NULL, timer_main, &secs) == 0) have_timer = true;
        int rc = 0;
        if (cfg.io == DQ_IO_NETMAP) {
            rc = dq_netmap_reflect(&cfg, &g_refl_stop, err, sizeof err) < 0 ? die(err) : 0;
        } else {
            char host[128];
            int port, bound;
            dq_sock_t s;
            if (!dq_split_hostport(cfg.reflect, host, sizeof host, &port) || dq_reflect_socket(host, port, &s, &bound, err, sizeof err) < 0) {
                atomic_store(&g_refl_stop, true);
                if (have_timer) pthread_join(tm, NULL);
                return die(err[0] ? err : "bad --reflect address");
            }
            const char *why;
            bool mm = cfg.io != DQ_IO_SENDTO && dq_io_for(DQ_IO_MMSG, &why) != NULL;
            fprintf(stderr, "dnsqps: reflecting on %s port %d\n", host, bound);
            dq_reflect_loop(s, &g_refl_stop, mm);
        }
        atomic_store(&g_refl_stop, true);
        if (have_timer) pthread_join(tm, NULL);
        return rc;
    }

    if (cfg.agent[0]) return dq_agent_serve(&cfg, run_engine, &g_quit, &g_stop);
    if (cfg.agents[0]) return dq_controller(&cfg, argc - 1, argv + 1, run_engine, &g_stop, g_st);

    static dq_report_t rep;
    err[0] = '\0';
    if (run_engine(&cfg, NULL, &rep, err, sizeof err) < 0) return die(err);
    if (cfg.json) dq_print_json(stdout, &rep);
    else dq_print_text(stdout, &rep);
    fflush(stdout);
    int rc = (!cfg.null_sink && rep.c.sent > 0 && rep.c.completed == 0) ? 1 : 0;
    if (rc) fprintf(stderr, "dnsqps: no answer at all (is the server up at %s?)\n", rep.server);
    return rc;
}
