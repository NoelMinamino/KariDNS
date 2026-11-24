/* dnsqps: a DNS query load generator (docs/dnsqps.md).  Shared declarations of its modules:
 *   dnsqps.c        main, the workers (the send / receive loops), the report
 *   dnsqps_opts.c   the command line, the rc file, the dig-style +options
 *   dnsqps_query.c  the query table (file or generated), the encoder of a query
 *   dnsqps_resp.c   the parser of an answer from the network (untrusted input)
 *   dnsqps_stats.c  the counters, the latency histogram, the text and JSON reports
 *   dnsqps_frame.c  Ethernet / ARP / IPv4 / IPv6 / UDP frames for the kernel-bypass paths (portable, no I/O)
 *   dnsqps_io.c     the I/O interface, the sendto and sendmmsg paths, the loopback reflector
 *   dnsqps_xdp.c    AF_XDP (Linux, libxdp)        dnsqps_netmap.c  netmap (FreeBSD)
 *   dnsqps_plat.c   clock, threads, CPU pinning, Winsock start-up
 * Everything here is written for this tool on top of dns_utils (type and rcode names); no code of dnsperf or resperf. */
#ifndef DNSQPS_H
#define DNSQPS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdatomic.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET dq_sock_t;
#define DQ_BADSOCK INVALID_SOCKET
#else
#include <sys/socket.h>
#include <netinet/in.h>
typedef int dq_sock_t;
#define DQ_BADSOCK (-1)
#endif

#define DQ_MAXQ      1400   /* the largest query the encoder makes */
#define DQ_RXMAX     4096   /* the room for one answer */
#define DQ_TAILMAX   96     /* the OPT record of a profile, without the padding option */
#define DQ_MAXPROF   32     /* the distinct option sets of a query file */
#define DQ_MAXCHAN   64     /* sockets (source ports) of a worker */
#define DQ_MAXBATCH  1024
#define DQ_MAXTYPES  16
#define DQ_NRCODE    18     /* RCODE 0-15, 16 = an extended RCODE, 17 = no valid header */
#define DQ_HBUCKETS  976    /* the latency histogram: 16 steps per power of two, values from 0 ns up */

/* from dns_utils.c (its header is not included: it pulls in POSIX-only headers) */
uint16_t get_type_code(const char *type_str);
const char *dns_rcode_name(unsigned rcode);

/* ---------------------------------------------------------------- query options (dig-style) */
typedef struct {
    bool edns, dnssec, nsid, cookie, cookie_rand, cookie_set, rd, cd, ad, aa, subnet;   /* cookie_rand: a new client cookie per query; cookie_set: cookie_val was given (+cookie=HEX) */
    uint16_t bufsize, padding, qclass;
    uint8_t opcode, sn_family, sn_prefix;
    uint8_t sn_addr[16];
    uint8_t cookie_val[8];
} dq_qopts_t;

void dq_qopts_default(dq_qopts_t *o);
/* one "+opt" token (dig spelling); 0 = applied, -1 = unknown or bad value (err says which) */
int dq_qopts_parse_tok(dq_qopts_t *o, const char *tok, char *err, size_t errlen);

/* the fixed part of a query for one option set: the two flag bytes, the class and the OPT record */
typedef struct {
    uint8_t flags[2];
    bool cookie_rand;            /* the 8 cookie bytes at tail[cookie_toff] are replaced per query */
    uint16_t qclass, padding, tail_len, cookie_toff;
    uint8_t tail[DQ_TAILMAX];
} dq_prof_t;

bool dq_prof_make(dq_prof_t *p, const dq_qopts_t *o);
/* ID 0 | flags | 1 question | name | type | class | OPT (RFC 6891, with the RFC 7830 padding when asked); returns the length, 0 when it does not fit */
size_t dq_compose(uint8_t *out, size_t cap, const dq_prof_t *p, const uint8_t *wname, size_t nlen, uint16_t qtype);

/* ---------------------------------------------------------------- source prefix (-b ADDR/LEN on the raw paths) */
typedef struct {
    bool on, v6;
    unsigned len;                 /* the prefix length in bits */
    uint8_t base[16], mask[16];   /* the network address (host bits cleared) and the network bits */
} dq_srcpfx_t;

/* "198.18.0.0/16", "2001:db8::/48": the host bits of the address are cleared; false when not of that form */
bool dq_parse_prefix(const char *s, dq_srcpfx_t *p);
/* true when the whole range is inside 198.18.0.0/15 (RFC 2544), 240.0.0.0/4 or 2001:db8::/32 (RFC 3849) */
bool dq_prefix_reserved(const dq_srcpfx_t *p);
/* an address of the range: the network bits of base, random host bits (uniform) */
void dq_prefix_pick(const dq_srcpfx_t *p, uint64_t *rng, uint8_t out[16]);
/* slice i of k disjoint, equal sub-prefixes (k >= 1; the length grows by ceil(log2 k)); false when there are not enough host bits */
bool dq_prefix_slice(const dq_srcpfx_t *p, unsigned k, unsigned i, dq_srcpfx_t *out);
/* "198.18.0.0/16" */
void dq_prefix_format(const dq_srcpfx_t *p, char *buf, size_t n);
/* xorshift64* : the generator of the cookies, the source addresses and the generated queries; *s must not be 0 */
uint64_t dq_rng_next(uint64_t *s);

/* ---------------------------------------------------------------- configuration */
enum { DQ_IO_AUTO = 0, DQ_IO_SENDTO, DQ_IO_MMSG, DQ_IO_XDP, DQ_IO_NETMAP };

typedef struct {
    char server[256], bind[64], qfile[512], zfile[512], reflect[128];
    char qtypes[128], iface[64], src_mac[24], next_hop_mac[24], next_hop[64], xdp_mode[8];
    int port;
    double duration, timeout, interval, zipf, miss;
    uint64_t runs, count, rate, inflight, seed;
    unsigned threads, sockets, batch, miss_pool, queue, sport_base, cpu_base, frame_mem_mb;
    dq_srcpfx_t srcpfx;           /* -b with a /LEN */
    bool allow_any_source;
    char agent[128], agents[512], agent_key[512];   /* --agent ADDR:PORT, --agents H:P,H:P, --agent-key FILE */
    double agent_timeout;
    bool no_local;
    bool agent_no_key;   /* --agent-no-key: an agent on a non-loopback address without --agent-key */
    int io;
    bool json, null_target, null_sink, no_pin, help, version, ignore_rc, verbose;
    dq_qopts_t qo;
} dq_cfg_t;

void dq_cfg_default(dq_cfg_t *c);
/* an agent's own sending path replaces the controller's: --io, --iface, the MACs, --next-hop, --xdp-mode, -b ADDR, -T, -c, -B, --queue,
 * --sport-base, --cpu-base, --no-pin and --frame-mem describe a host, not the load (docs/dnsqps.md "Several client hosts") */
void dq_cfg_take_host(dq_cfg_t *dst, const dq_cfg_t *src);
/* argv without the program name; 0 = ok, -1 = error (err) */
int dq_parse_args(dq_cfg_t *c, int argc, char **argv, char *err, size_t errlen);
/* the text of an rc file (~/.dnsqpsrc): the same options, one or more per line, '#' starts a comment */
int dq_parse_rc_buf(dq_cfg_t *c, const char *buf, size_t len, char *err, size_t errlen);
int dq_load_rc(dq_cfg_t *c, char *err, size_t errlen);
/* the checks that need the whole command line */
int dq_cfg_check(dq_cfg_t *c, char *err, size_t errlen);
/* "A:70,AAAA:20": types and weights; returns the number of types or -1 */
int dq_parse_qtypes(const char *s, uint16_t *types, uint32_t *weights, char *err, size_t errlen);
bool dq_parse_u64(const char *s, uint64_t *out, uint64_t max);
bool dq_parse_dbl(const char *s, double *out, double min, double max);
bool dq_parse_mac(const char *s, uint8_t mac[6]);
bool dq_parse_ip(const char *s, uint8_t ip[16], int *family);
bool dq_hostport_strict(const char *s, char *host, size_t hostlen, int *port);
#define DQ_MAXAGENTS 16

/* ---------------------------------------------------------------- the query table */
typedef struct { uint32_t name_off; uint16_t qtype; uint8_t prof; uint8_t nlen; } dq_ent_t;

typedef struct {
    uint8_t *names;
    size_t names_len, names_cap;
    dq_ent_t *ents;
    size_t n, cap;
    dq_prof_t profs[DQ_MAXPROF];
    unsigned nprof;
    /* generated mode */
    bool gen;
    size_t nhit, nmiss;
    unsigned ntypes;
    uint16_t types[DQ_MAXTYPES];
    uint32_t cum[DQ_MAXTYPES];   /* cumulative weight, scaled to 2^32 */
    uint32_t miss_thr;           /* a draw below this is a miss */
    double zipf_s, zipf_pow;
} dq_qtab_t;

typedef struct { uint64_t rng; size_t pos; unsigned stride; uint64_t runs_done; } dq_cur_t;

void dq_qtab_free(dq_qtab_t *t);
/* the name of a text form ("a.example.test", "\046" escapes) to wire form; the length, 0 = invalid */
size_t dq_name_to_wire(const char *s, uint8_t *out, size_t cap);
/* build the table: from the query file, or from the name list (generated mode); 0 = ok */
int dq_qtab_load(dq_qtab_t *t, const dq_cfg_t *c, char *err, size_t errlen);
/* a table of lines in memory (tests, fuzzing) */
int dq_qtab_from_lines(dq_qtab_t *t, const dq_cfg_t *c, const char *text, size_t len, char *err, size_t errlen);
void dq_cur_init(dq_cur_t *c, const dq_qtab_t *t, unsigned worker, unsigned nworkers, uint64_t seed);
/* the next query, ID 0, into out; returns the length, 0 when the worker has run its `runs` passes (file mode) */
size_t dq_next_query(const dq_qtab_t *t, dq_cur_t *c, uint8_t *out, size_t cap, uint64_t max_runs);

/* one query of the table, before it is put together: the entry, the slot of the type (generated mode), and where its 8 client-cookie bytes are
 * in the DNS message when the profile asks for a cookie per query (0 = none) */
typedef struct { size_t ent; unsigned tidx; uint16_t qtype, cookie_poff; uint8_t prof; } dq_pick_t;
/* the next query of the cursor; false when the worker has run its `runs` passes (file mode) */
bool dq_next_pick(const dq_qtab_t *t, dq_cur_t *c, dq_pick_t *p, uint64_t max_runs);
/* the DNS message of a pick, ID 0; the length, 0 when it does not fit */
size_t dq_compose_pick(const dq_qtab_t *t, const dq_pick_t *p, uint8_t *out, size_t cap);

/* ---------------------------------------------------------------- pre-built frames (raw paths) */
#define DQ_FRMAX (DQ_MAXQ + 64)   /* the largest frame: headers + the largest query */
/* every query of the table as a whole Ethernet / IP / UDP frame, built once.  Read only after the build, so the threads share it.  Record of frame i at
 * buf + off[i]: u16 frame length, u16 offset of the cookie bytes in the frame (0 = none), the frame.  Cost per frame: 8 (off) + 4 + headers (42 or 62)
 * + the DNS message (12 + name + 4 + the OPT record and padding of the profile) */
typedef struct { uint8_t *buf; uint64_t *off; size_t n; uint64_t bytes; } dq_pf_t;


/* ---------------------------------------------------------------- answers (untrusted) */
typedef struct {
    uint16_t id, rcode;          /* rcode with the extended bits of an OPT record */
    uint16_t qd, an, ns, ar;
    bool tc, aa, opt;
} dq_resp_t;
/* -1 = not an answer (shorter than a header, QR clear), 1 = an answer whose records are cut or malformed (the header fields are set), 0 = ok */
int dq_resp_parse(const uint8_t *p, size_t n, dq_resp_t *r);

/* ---------------------------------------------------------------- statistics */
typedef struct {
    uint64_t b[DQ_HBUCKETS];
    uint64_t count, sum_ns, min_ns, max_ns;
} dq_hist_t;

typedef struct {
    uint64_t sent, completed, lost, malformed, unmatched, foreign, send_errs, recv_errs, sent_bytes, recv_bytes, truncated;   /* truncated: completed answers with TC=1 (an RRL slip, an answer too big for UDP) */
    uint64_t rcode[DQ_NRCODE];
} dq_counts_t;

typedef struct {   /* what a worker publishes while it runs (the interval lines) */
    _Atomic uint64_t sent, completed, lost, lat_sum, lat_cnt;
} dq_live_t;

typedef struct {
    dq_counts_t c;
    dq_hist_t h;
    double run_s;
    const char *io_name;
    unsigned threads, sockets;
    char server[300];
    char io_buf[24];             /* the I/O path name of a merged or received report (io_name points here) */
    bool sink;
} dq_report_t;

void dq_hist_init(dq_hist_t *h);
void dq_hist_add(dq_hist_t *h, uint64_t ns);
void dq_hist_merge(dq_hist_t *d, const dq_hist_t *s);
uint64_t dq_hist_pct(const dq_hist_t *h, double p);   /* the upper edge of the bucket the percentile falls in */
size_t dq_hist_bucket(uint64_t ns);
uint64_t dq_hist_bucket_hi(size_t idx);
void dq_counts_add(dq_counts_t *d, const dq_counts_t *s);
/* the buckets as "i:n,i:n" (the length, (size_t)-1 when cap is too small) and back; decode needs a dq_hist_init()ed histogram and sets b[] and count (sum and extremes are the caller's) */
size_t dq_hist_encode(const dq_hist_t *h, char *out, size_t cap);
bool dq_hist_decode(dq_hist_t *h, const char *s);
void dq_print_text(FILE *f, const dq_report_t *r);
void dq_print_json(FILE *f, const dq_report_t *r);
void dq_print_interval(FILE *f, double t, double dt, uint64_t sent, uint64_t done, uint64_t lost, uint64_t lat_sum, uint64_t lat_cnt);

/* ---------------------------------------------------------------- frames for the kernel-bypass paths */
typedef struct {
    uint8_t hdr[62];     /* Ethernet + IP + UDP, checksums unset */
    unsigned hlen;
    bool v6;
    uint32_t psum;       /* the pseudo-header addresses and protocol, summed; the length is added per frame */
} dq_frame_tpl_t;

typedef struct {
    const uint8_t *payload;
    unsigned plen;
    uint16_t sport, dport;
    uint8_t sip[16], smac[6];
    bool v6;
} dq_udp_view_t;

void dq_frame_tpl_init(dq_frame_tpl_t *t, const uint8_t smac[6], const uint8_t dmac[6], bool v6, const uint8_t *sip, const uint8_t *dip,
                       uint16_t sport, uint16_t dport);
/* the table as frames: the bytes needed (UINT64_MAX when a query does not fit), and the build (0 = ok) */
uint64_t dq_pf_size(const dq_qtab_t *t, const dq_frame_tpl_t *tpl);
int dq_pf_build(dq_pf_t *pf, const dq_qtab_t *t, const dq_frame_tpl_t *tpl, char *err, size_t errlen);
void dq_pf_free(dq_pf_t *pf);
size_t dq_pf_index(const dq_qtab_t *t, const dq_pick_t *p);
const uint8_t *dq_pf_get(const dq_pf_t *pf, size_t i, uint16_t *flen, uint16_t *cookie_off);

/* what one send changes in a frame of the table (or of a frame built just now) */
typedef struct {
    const uint8_t *frame;
    uint16_t flen, plen, id, cookie_off;   /* plen: the DNS message; cookie_off: the 8 cookie bytes in the frame, 0 = none */
    bool set_sip;
    uint8_t cookie[8], sip[16];
} dq_fsend_t;
/* copy the frame to dst and patch the DNS ID, the UDP source port, the source address (set_sip) and the cookie; the IPv4 header checksum and the UDP checksum
 * are updated incrementally (RFC 1624).  Returns the frame length, 0 when cap is too small */
size_t dq_frame_emit(uint8_t *dst, size_t cap, const dq_fsend_t *s, bool v6, uint16_t sport);
/* a transmit buffer of cap bytes takes every frame dnsqps builds (DQ_FRMAX); else -1 and why (a path checks it when it opens: a frame that can
 * never fit would be retried for ever) */
int dq_frame_cap_check(size_t cap, const char *what, char *err, size_t errlen);
/* header + payload with the lengths and checksums set; returns the frame length, 0 when cap is too small */
size_t dq_frame_build(const dq_frame_tpl_t *t, uint8_t *out, size_t cap, const uint8_t *payload, size_t plen);
/* a UDP datagram addressed to our_ip (4 or 16 bytes, family v6) in an Ethernet frame (one VLAN tag allowed); 0 = ok, -1 = anything else */
int dq_frame_parse_udp(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, dq_udp_view_t *v);
/* the same for a destination in a range: our_ip and mask (the network bits, 4 or 16 bytes) say which addresses are ours; mask NULL = exactly our_ip */
int dq_frame_parse_udp_pfx(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, const uint8_t *mask, dq_udp_view_t *v);
size_t dq_arp_request(uint8_t *out, size_t cap, const uint8_t smac[6], const uint8_t sip[4], const uint8_t tip[4]);
bool dq_arp_reply_parse(const uint8_t *f, size_t n, const uint8_t tip[4], uint8_t mac[6]);
size_t dq_nd_solicit(uint8_t *out, size_t cap, const uint8_t smac[6], const uint8_t sip[16], const uint8_t tip[16]);
bool dq_nd_adv_parse(const uint8_t *f, size_t n, const uint8_t tip[16], uint8_t mac[6]);
/* the reflector of the kernel-bypass test path: a frame for our_ip:port (UDP) becomes its own answer (QR set, addresses and ports swapped), an ARP request for
 * our_ip gets its reply with our_mac; returns the length written to out, 0 = not for us */
size_t dq_frame_reflect(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, const uint8_t our_mac[6], uint16_t port, uint8_t *out, size_t cap);
uint16_t dq_csum_fold(uint32_t sum);
uint32_t dq_csum_add(uint32_t sum, const uint8_t *p, size_t n);

/* ---------------------------------------------------------------- platform */
int dq_net_init(void);
uint64_t dq_now_ns(void);
void dq_sleep_us(unsigned us);
unsigned dq_ncpus(void);
int dq_pin_thread(unsigned nth);   /* the nth CPU of the allowed set; 0 = pinned, -1 = not possible here */

/* ---------------------------------------------------------------- the I/O interface */
typedef struct {
    struct sockaddr_storage dst;
    socklen_t dlen;
    bool v6;
    char ifname[64];
    uint8_t src_mac[6], dst_mac[6], src_ip[16], dst_ip[16], hop_ip[16];
    uint8_t arp_ip[16];       /* the sender address of the ARP / neighbor request: the interface address (src_ip, or the first of the prefix) */
    dq_srcpfx_t pfx;          /* -b ADDR/LEN: src_ip is its base address */
    bool have_dst_mac;
    uint16_t dport, sport_base;
    unsigned ports_per_worker;
} dq_target_t;

typedef struct { const uint8_t *buf; uint16_t len; } dq_tx_t;
typedef struct { const uint8_t *buf; uint16_t len; uint16_t chan; } dq_rx_t;
typedef struct dq_io dq_io_t;

typedef struct {
    const char *name;
    /* nchan channels (sockets, or UDP source ports); worker is the index of the worker (the NIC queue of a raw path is queue + worker) */
    int (*open)(dq_io_t **io, const dq_cfg_t *c, dq_target_t *tg, unsigned worker, unsigned nchan, char *err, size_t errlen);
    /* up to n datagrams on one channel; returns how many were taken (0 = no room now, -1 = error) */
    int (*send)(dq_io_t *io, unsigned chan, const dq_tx_t *p, unsigned n);
    /* up to max answers; waits up to wait_us when none is ready; the buffers stay valid until the next call */
    int (*recv)(dq_io_t *io, dq_rx_t *p, unsigned max, unsigned wait_us);
    void (*close)(dq_io_t *io);
    /* the raw paths: send pre-built frames instead of send() (NULL on the socket paths) */
    int (*send_frames)(dq_io_t *io, unsigned chan, const dq_fsend_t *p, unsigned n);
    /* what the kernel gave the path (xdp: the attach mode and copy or zero-copy; netmap: the rings and slots), for the status line; false when it is not what was asked (NULL: nothing to say) */
    bool (*describe)(dq_io_t *io, char *buf, size_t len);
} dq_io_ops_t;

extern const dq_io_ops_t dq_io_sendto, dq_io_mmsg, dq_io_xdp, dq_io_netmap;
/* the path for cfg->io: ops for a mode (NULL = not available here, why in *why) */
const dq_io_ops_t *dq_io_for(int mode, const char **why);
/* the loopback reflector (--null-target, --reflect): answers every datagram it gets with QR set; runs until *stop */
int dq_reflect_socket(const char *addr, int port, dq_sock_t *s, int *bound_port, char *err, size_t errlen);
void dq_reflect_loop(dq_sock_t s, const atomic_bool *stop, bool mmsg);
/* "10.0.0.1" / "[2001:db8::1]:53" / "53" for the --reflect option; false when not of that form */
bool dq_split_hostport(const char *s, char *host, size_t hostlen, int *port);
/* resolve and fill in the parts of a target every path needs */
int dq_target_resolve(dq_target_t *tg, const dq_cfg_t *c, const char *server, int port, char *err, size_t errlen);
/* the interface, the addresses and the MACs a raw path needs (the next-hop MAC is resolved by the first worker through the path itself) */
int dq_raw_prepare(dq_target_t *tg, const dq_cfg_t *c, char *err, size_t errlen);
typedef struct {
    int (*tx)(void *ctx, const uint8_t *f, unsigned len);
    int (*rx)(void *ctx, const uint8_t **f, unsigned *len, unsigned wait_ms);   /* 1 = a frame, 0 = none */
    void *ctx;
} dq_rawif_t;
int dq_raw_resolve_mac(const dq_rawif_t *r, dq_target_t *tg, char *err, size_t errlen);
/* the raw reflector of the netmap test (dnsqps --reflect with --io=netmap): returns when *stop is set */
int dq_netmap_reflect(const dq_cfg_t *c, const atomic_bool *stop, char *err, size_t errlen);

/* ---------------------------------------------------------------- the engine's hooks and the agent / controller (dnsqps_agent.c)
 * One dnsqps (the controller, --agents) drives others (--agent ADDR:PORT) over TCP: the agents take the run parameters, set up (query table, frames,
 * the I/O path), say READY, wait for GO, run, and send the result with the latency histogram, which the controller adds to its own.  A control
 * message is a 4-byte big-endian length (1 .. DQ_MSG_MAX) and that many bytes of lines: the first line is the verb, the others are key=value. */
typedef struct { uint64_t sent, done, lost, lat_sum, lat_cnt; } dq_livesum_t;
typedef struct {
    int (*ready)(void *ctx);                         /* the setup is done: 0 = start now, -1 = drop the run */
    int (*tick)(void *ctx, dq_livesum_t *live);      /* every ~10 ms while it runs; live = this process's totals, which the hook may add to; 1 = stop */
    void *ctx;
} dq_run_hooks_t;
/* runs one load (the engine of dnsqps.c): 0 = ran (rep filled), -1 = setup failed (err) */
typedef int (*dq_run_fn)(dq_cfg_t *cfg, const dq_run_hooks_t *hooks, dq_report_t *rep, char *err, size_t errlen);

#define DQ_MSG_MAX   262144u
#define DQ_MSG_MAXKV 600
#define DQ_MAXTOK    400
typedef struct { char *verb; unsigned n; char *k[DQ_MSG_MAXKV], *v[DQ_MSG_MAXKV]; } dq_msg_t;
/* buf holds len bytes and has room for one more (a NUL is put after them); it is cut up in place.  0 = ok */
int dq_msg_parse(char *buf, size_t len, dq_msg_t *m, char *err, size_t errlen);
const char *dq_msg_get(const dq_msg_t *m, const char *key);
bool dq_msg_u64(const dq_msg_t *m, const char *key, uint64_t *out);   /* decimal digits only, at most 2^58 */
typedef struct { char *p; size_t len; bool ovf; } dq_msgb_t;           /* p: 4 bytes of length, then the lines */
bool dq_msgb_init(dq_msgb_t *b, const char *verb);
bool dq_msgb_kv(dq_msgb_t *b, const char *key, const char *val);
bool dq_msgb_u64(dq_msgb_t *b, const char *key, uint64_t v);
void dq_msgb_free(dq_msgb_t *b);
/* With a key (T3-L1) every message after the HELLO carries, as its last line, mac=HMAC-SHA256(key, "dnsqps-agent-v2 DIR NONCE SEQ\n" + the lines
 * before it): DIR is c2a or a2c (a message cannot be sent back), NONCE the other side's fresh nonce (the controller's messages are bound to the
 * agent's nonce and the agent's to the controller's: no replay from another session), SEQ the number of the message in that direction (none
 * dropped, reordered or repeated).  sauth / rauth: sign what is sent, verify what is received. */
typedef struct {
    dq_sock_t s; uint8_t hdr[4]; unsigned hgot; uint32_t plen; size_t pgot; char *buf; bool done;
    const char *key; size_t klen; bool agent_side, sauth, rauth;
    char snonce[33], rnonce[33];
    uint64_t sseq, rseq;
} dq_conn_t;
/* the key of the connection (kept by the caller), and the nonce each direction is bound to (NULL: that direction is not authenticated) */
void dq_conn_auth(dq_conn_t *c, const char *key, size_t klen, bool agent_side, const char *send_nonce, const char *recv_nonce);
void dq_conn_init(dq_conn_t *c, dq_sock_t s);
void dq_conn_close(dq_conn_t *c);
int dq_conn_send(dq_conn_t *c, dq_msgb_t *b, unsigned timeout_ms);                       /* 0 = sent, -1 = error or timeout */
int dq_conn_recv(dq_conn_t *c, unsigned wait_ms, dq_msg_t *m, char *err, size_t errlen);   /* 1 = a message (valid until the next call), 0 = not yet, -1 = closed or bad */
/* the options an agent takes from a controller: nothing that starts another listener, controller or help run */
int dq_agent_check_tokens(char **t, int n, char *err, size_t errlen);
/* a result message of an agent: counters, the histogram; checked field by field (the agent is not trusted) */
int dq_result_put(dq_msgb_t *b, const dq_report_t *r);
int dq_result_get(const dq_msg_t *m, dq_report_t *r, char *err, size_t errlen);
typedef struct { char *t[DQ_MAXTOK]; int n; } dq_args_t;
void dq_args_free(dq_args_t *a);
/* the tokens for sender i of k senders: the controller's command line without the controller-only options, then this sender's share of the rate, count,
 * inflight, source prefix, and its own seed.  0 = ok */
int dq_ctl_args(const dq_cfg_t *c, int argc, char **argv, unsigned k, unsigned i, dq_args_t *a, char *err, size_t errlen);
uint64_t dq_share(uint64_t total, unsigned k, unsigned i);
/* true when c sends with netmap on its --iface and the connection s has a local address on that interface: netmap(4) takes the NIC's rings
 * from the host stack while it runs, so the control connection would stall (FreeBSD; false elsewhere) */
bool dq_ctl_over_netmap(const dq_cfg_t *c, dq_sock_t s);
/* the agent: serve until *quit; the controller: run the load on the senders and print the merged report; returns the exit status */
int dq_agent_serve(const dq_cfg_t *c, dq_run_fn run, const atomic_bool *quit, atomic_bool *stop);
int dq_controller(dq_cfg_t *c, int argc, char **argv, dq_run_fn run, atomic_bool *stop, FILE *st);

#endif
