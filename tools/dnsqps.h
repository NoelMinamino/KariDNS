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
    bool edns, dnssec, nsid, cookie, rd, cd, ad, aa, subnet;
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
    uint16_t qclass, padding, tail_len;
    uint8_t tail[DQ_TAILMAX];
} dq_prof_t;

bool dq_prof_make(dq_prof_t *p, const dq_qopts_t *o);
/* ID 0 | flags | 1 question | name | type | class | OPT (RFC 6891, with the RFC 7830 padding when asked); returns the length, 0 when it does not fit */
size_t dq_compose(uint8_t *out, size_t cap, const dq_prof_t *p, const uint8_t *wname, size_t nlen, uint16_t qtype);

/* ---------------------------------------------------------------- configuration */
enum { DQ_IO_AUTO = 0, DQ_IO_SENDTO, DQ_IO_MMSG, DQ_IO_XDP, DQ_IO_NETMAP };

typedef struct {
    char server[256], bind[64], qfile[512], zfile[512], reflect[128];
    char qtypes[128], iface[64], src_mac[24], next_hop_mac[24], next_hop[64], xdp_mode[8];
    int port;
    double duration, timeout, interval, zipf, miss;
    uint64_t runs, count, rate, inflight, seed;
    unsigned threads, sockets, batch, miss_pool, queue, sport_base, cpu_base;
    int io;
    bool json, null_target, null_sink, no_pin, help, version, ignore_rc, verbose;
    dq_qopts_t qo;
} dq_cfg_t;

void dq_cfg_default(dq_cfg_t *c);
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
    uint64_t sent, completed, lost, malformed, unmatched, foreign, send_errs, recv_errs, sent_bytes, recv_bytes;
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
    bool sink;
} dq_report_t;

void dq_hist_init(dq_hist_t *h);
void dq_hist_add(dq_hist_t *h, uint64_t ns);
void dq_hist_merge(dq_hist_t *d, const dq_hist_t *s);
uint64_t dq_hist_pct(const dq_hist_t *h, double p);   /* the upper edge of the bucket the percentile falls in */
size_t dq_hist_bucket(uint64_t ns);
uint64_t dq_hist_bucket_hi(size_t idx);
void dq_counts_add(dq_counts_t *d, const dq_counts_t *s);
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
/* header + payload with the lengths and checksums set; returns the frame length, 0 when cap is too small */
size_t dq_frame_build(const dq_frame_tpl_t *t, uint8_t *out, size_t cap, const uint8_t *payload, size_t plen);
/* a UDP datagram addressed to our_ip (4 or 16 bytes, family v6) in an Ethernet frame (one VLAN tag allowed); 0 = ok, -1 = anything else */
int dq_frame_parse_udp(const uint8_t *f, size_t n, bool v6, const uint8_t *our_ip, dq_udp_view_t *v);
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

#endif
