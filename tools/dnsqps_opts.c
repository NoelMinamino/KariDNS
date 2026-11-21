/* dnsqps: the command line, the rc file (~/.dnsqpsrc, like ~/.digrc) and the small parsers they share.  The query options (+edns, +dnssec, ...) are
 * parsed by dq_qopts_parse_tok() in dnsqps_query.c; the spellings are dig's.  Every value is checked: the rc file and the arguments are input. */
#include "dnsqps.h"
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

enum { O_SERVER = 1, O_PORT, O_BIND, O_FILE, O_ZONES, O_TIME, O_RUNS, O_COUNT, O_THREADS, O_SOCKETS, O_INFLIGHT, O_RATE, O_TIMEOUT, O_INTERVAL,
       O_BATCH, O_IO, O_JSON, O_NULL, O_REFLECT, O_ZIPF, O_MISS, O_MISSPOOL, O_QTYPES, O_SEED, O_NOPIN, O_CPUBASE, O_IFACE, O_SRCMAC, O_HOPMAC,
       O_HOP, O_QUEUE, O_SPORT, O_XDPMODE, O_VERBOSE, O_HELP, O_VERSION, O_NORC, O_ALLOWANY, O_FRAMEMEM, O_AGENT, O_AGENTS, O_AGENTKEY, O_AGENTTO, O_NOLOCAL };

typedef struct { const char *lname; char sname; int has_arg; int id; } optdef_t;   /* has_arg: 0 none, 1 required, 2 only as --name=value */

static const optdef_t OPTS[] = {
    {"server", 's', 1, O_SERVER}, {"port", 'p', 1, O_PORT}, {"bind", 'b', 1, O_BIND}, {"file", 'd', 1, O_FILE}, {"zones", 'z', 1, O_ZONES},
    {"time", 'l', 1, O_TIME}, {"runs", 'n', 1, O_RUNS}, {"count", 'N', 1, O_COUNT}, {"threads", 'T', 1, O_THREADS}, {"sockets", 'c', 1, O_SOCKETS},
    {"inflight", 'q', 1, O_INFLIGHT}, {"rate", 'Q', 1, O_RATE}, {"timeout", 't', 1, O_TIMEOUT}, {"interval", 'S', 1, O_INTERVAL},
    {"batch", 'B', 1, O_BATCH}, {"io", 0, 1, O_IO}, {"json", 'j', 0, O_JSON}, {"null-target", 0, 2, O_NULL}, {"reflect", 0, 1, O_REFLECT},
    {"zipf", 0, 1, O_ZIPF}, {"miss", 0, 1, O_MISS}, {"miss-pool", 0, 1, O_MISSPOOL}, {"qtypes", 0, 1, O_QTYPES}, {"seed", 0, 1, O_SEED},
    {"no-pin", 0, 0, O_NOPIN}, {"cpu-base", 0, 1, O_CPUBASE}, {"iface", 0, 1, O_IFACE}, {"src-mac", 0, 1, O_SRCMAC},
    {"next-hop-mac", 0, 1, O_HOPMAC}, {"next-hop", 0, 1, O_HOP}, {"queue", 0, 1, O_QUEUE}, {"sport-base", 0, 1, O_SPORT},
    {"xdp-mode", 0, 1, O_XDPMODE}, {"verbose", 'v', 0, O_VERBOSE}, {"help", 'h', 0, O_HELP}, {"version", 'V', 0, O_VERSION},
    {"ignore-rc", 'r', 0, O_NORC},
    {"allow-any-source", 0, 0, O_ALLOWANY}, {"frame-mem", 0, 1, O_FRAMEMEM}, {"agent", 0, 1, O_AGENT}, {"agents", 0, 1, O_AGENTS},
    {"agent-key", 0, 1, O_AGENTKEY}, {"agent-timeout", 0, 1, O_AGENTTO}, {"no-local", 0, 0, O_NOLOCAL},
};

/* ---------------------------------------------------------------- small parsers */
bool dq_parse_u64(const char *s, uint64_t *out, uint64_t max) {
    if (!s || *s < '0' || *s > '9') return false;
    char *e;
    errno = 0;
    unsigned long long v = strtoull(s, &e, 10);
    if (errno) return false;
    uint64_t mult = 1;
    if (*e == 'k' || *e == 'K') { mult = 1000; e++; }
    else if (*e == 'm' || *e == 'M') { mult = 1000000; e++; }
    else if (*e == 'g' || *e == 'G') { mult = 1000000000; e++; }
    if (*e) return false;
    if (v > max / mult) return false;
    *out = (uint64_t)v * mult;
    return true;
}

bool dq_parse_dbl(const char *s, double *out, double min, double max) {
    if (!s || !((*s >= '0' && *s <= '9') || *s == '.')) return false;
    char *e;
    double v = strtod(s, &e);
    if (*e || !isfinite(v) || v < min || v > max) return false;
    *out = v;
    return true;
}

bool dq_parse_mac(const char *s, uint8_t mac[6]) {
    for (int i = 0; i < 6; i++) {
        if (!isxdigit((unsigned char)s[0]) || !isxdigit((unsigned char)s[1])) return false;
        char h[3] = { s[0], s[1], 0 };
        mac[i] = (uint8_t)strtoul(h, NULL, 16);
        s += 2;
        if (i < 5) {
            if (*s != ':' && *s != '-') return false;
            s++;
        }
    }
    return *s == '\0';
}

bool dq_parse_ip(const char *s, uint8_t ip[16], int *family) {
    struct in_addr a4;
    struct in6_addr a6;
    memset(ip, 0, 16);
    if (inet_pton(AF_INET, s, &a4) == 1) { memcpy(ip, &a4, 4); if (family) *family = 1; return true; }
    if (inet_pton(AF_INET6, s, &a6) == 1) { memcpy(ip, &a6, 16); if (family) *family = 2; return true; }
    return false;
}

int dq_parse_qtypes(const char *s, uint16_t *types, uint32_t *weights, char *err, size_t errlen) {
    int n = 0;
    char buf[128];
    if (strlen(s) >= sizeof buf) { snprintf(err, errlen, "the type list is too long"); return -1; }
    strcpy(buf, s);
    char *save = buf;
    while (*save) {
        char *comma = strchr(save, ',');
        if (comma) *comma = '\0';
        char *colon = strchr(save, ':');
        uint64_t w = 1;
        if (colon) {
            *colon++ = '\0';
            if (!dq_parse_u64(colon, &w, 1000000) || w == 0) { snprintf(err, errlen, "bad weight '%.20s' in the type list", colon); return -1; }
        }
        uint16_t t = get_type_code(save);
        if (!t) { snprintf(err, errlen, "unknown type '%.20s' in the type list", save); return -1; }
        if (n >= DQ_MAXTYPES) { snprintf(err, errlen, "more than %d types in the list", DQ_MAXTYPES); return -1; }
        types[n] = t;
        weights[n] = (uint32_t)w;
        n++;
        if (!comma) break;
        save = comma + 1;
    }
    if (n == 0) { snprintf(err, errlen, "the type list is empty"); return -1; }
    return n;
}

/* "10.0.0.1:5353", "[2001:db8::1]:5353", "5353" (loopback), an address alone (port 53) */
bool dq_split_hostport(const char *s, char *host, size_t hostlen, int *port) {
    uint64_t p = 53;
    if (!*s) return false;
    if (s[0] >= '0' && s[0] <= '9' && !strchr(s, '.') && !strchr(s, ':')) {
        if (!dq_parse_u64(s, &p, 65535) || p == 0) return false;
        snprintf(host, hostlen, "127.0.0.1");
        *port = (int)p;
        return true;
    }
    const char *h = s, *pt = NULL;
    size_t hl;
    if (s[0] == '[') {
        const char *rb = strchr(s, ']');
        if (!rb) return false;
        h = s + 1;
        hl = (size_t)(rb - h);
        if (rb[1] == ':') pt = rb + 2;
        else if (rb[1]) return false;
    } else {
        const char *c1 = strchr(s, ':');
        if (c1 && !strchr(c1 + 1, ':')) { hl = (size_t)(c1 - s); pt = c1 + 1; }
        else hl = strlen(s);
    }
    if (hl == 0 || hl >= hostlen) return false;
    if (pt && (!dq_parse_u64(pt, &p, 65535) || p == 0)) return false;
    memcpy(host, h, hl);
    host[hl] = '\0';
    *port = (int)p;
    return true;
}

/* ---------------------------------------------------------------- source prefix */
static void mask_make(uint8_t mask[16], unsigned len) {
    memset(mask, 0, 16);
    for (unsigned i = 0; i < 16; i++) {
        unsigned have = len > i * 8 ? len - i * 8 : 0;
        mask[i] = have >= 8 ? 0xFF : have ? (uint8_t)(0xFFu << (8 - have)) : 0;
    }
}

bool dq_parse_prefix(const char *s, dq_srcpfx_t *p) {
    char buf[80];
    const char *sl = strchr(s, '/');
    if (!sl || (size_t)(sl - s) >= sizeof buf || !sl[1]) return false;
    memcpy(buf, s, (size_t)(sl - s));
    buf[sl - s] = '\0';
    unsigned len = 0;
    for (const char *d = sl + 1; *d; d++) {   /* digits only: dq_parse_u64 would take 16k */
        if (*d < '0' || *d > '9' || len > 1000) return false;
        len = len * 10 + (unsigned)(*d - '0');
    }
    uint8_t ip[16];
    int fam;
    if (!dq_parse_ip(buf, ip, &fam) || len > (fam == 1 ? 32u : 128u)) return false;
    memset(p, 0, sizeof *p);
    p->on = true;
    p->v6 = fam == 2;
    p->len = len;
    mask_make(p->mask, len);
    if (!p->v6) memset(p->mask + 4, 0, 12);
    for (unsigned i = 0; i < 16; i++) p->base[i] = (uint8_t)(ip[i] & p->mask[i]);
    return true;
}

bool dq_prefix_reserved(const dq_srcpfx_t *p) {
    static const uint8_t r198[4] = { 198, 18, 0, 0 }, r240[4] = { 240, 0, 0, 0 }, r2001[16] = { 0x20, 0x01, 0x0d, 0xb8 };
    const uint8_t *rb;
    unsigned rl;
    for (int k = 0; k < (p->v6 ? 1 : 2); k++) {
        if (p->v6) { rb = r2001; rl = 32; }
        else if (k == 0) { rb = r198; rl = 15; }
        else { rb = r240; rl = 4; }
        uint8_t m[16];
        mask_make(m, rl);
        bool in = p->len >= rl;
        for (unsigned i = 0; in && i < (p->v6 ? 16u : 4u); i++)
            if ((p->base[i] & m[i]) != (rb[i] & m[i])) in = false;
        if (in) return true;
    }
    return false;
}

void dq_prefix_pick(const dq_srcpfx_t *p, uint64_t *rng, uint8_t out[16]) {
    uint8_t rb[16];
    uint64_t a = dq_rng_next(rng), b = p->v6 ? dq_rng_next(rng) : 0;
    memcpy(rb, &a, 8);
    memcpy(rb + 8, &b, 8);
    for (unsigned i = 0; i < 16; i++) out[i] = (uint8_t)(p->base[i] | (rb[i] & ~p->mask[i]));
    if (!p->v6) memset(out + 4, 0, 12);
}

bool dq_prefix_slice(const dq_srcpfx_t *p, unsigned k, unsigned i, dq_srcpfx_t *out) {
    unsigned bits = 0;
    while (bits < 31 && (1u << bits) < k) bits++;
    if (k == 0 || i >= k || p->len + bits > (p->v6 ? 128u : 32u)) return false;
    *out = *p;
    out->len = p->len + bits;
    mask_make(out->mask, out->len);
    if (!p->v6) memset(out->mask + 4, 0, 12);
    for (unsigned b = 0; b < bits; b++) {
        unsigned pos = p->len + b;
        if ((i >> (bits - 1 - b)) & 1) out->base[pos / 8] |= (uint8_t)(0x80u >> (pos % 8));
    }
    return true;
}

void dq_prefix_format(const dq_srcpfx_t *p, char *buf, size_t n) {
    char a[64];
    if (!inet_ntop(p->v6 ? AF_INET6 : AF_INET, p->base, a, sizeof a)) a[0] = '\0';
    snprintf(buf, n, "%s/%u", a, p->len);
}

/* ADDR:PORT, [ADDR]:PORT or NAME:PORT, the port required (dq_split_hostport defaults it to 53) */
bool dq_hostport_strict(const char *s, char *host, size_t hostlen, int *port) {
    if (!dq_split_hostport(s, host, hostlen, port)) return false;
    if (s[0] == '[') return strstr(s, "]:") != NULL;
    const char *c = strchr(s, ':');
    return c && !strchr(c + 1, ':');
}

/* ---------------------------------------------------------------- the configuration */
void dq_cfg_default(dq_cfg_t *c) {
    memset(c, 0, sizeof *c);
    snprintf(c->server, sizeof c->server, "127.0.0.1");
    c->port = 53;
    c->timeout = 5;
    c->zipf = 1.0;
    c->sockets = 1;
    c->batch = 64;
    c->sport_base = 40000;
    c->frame_mem_mb = 1024;
    c->agent_timeout = 60;
    snprintf(c->xdp_mode, sizeof c->xdp_mode, "auto");
    dq_qopts_default(&c->qo);
}

static int bad(char *err, size_t n, const char *opt, const char *val) {
    snprintf(err, n, "bad value '%.60s' for --%s", val ? val : "", opt);
    return -1;
}

static bool cpy(char *dst, size_t n, const char *src) {
    if (strlen(src) >= n) return false;
    strcpy(dst, src);
    return true;
}

static int apply(dq_cfg_t *c, const optdef_t *d, const char *val, char *err, size_t errlen) {
    uint64_t u = 0;
    double x = 0;
    switch (d->id) {
    case O_SERVER: if (!*val || !cpy(c->server, sizeof c->server, val)) return bad(err, errlen, d->lname, val); break;
    case O_PORT: if (!dq_parse_u64(val, &u, 65535) || u == 0) return bad(err, errlen, d->lname, val); c->port = (int)u; break;
    case O_BIND:
        if (strchr(val, '/')) {   /* ADDR/LEN: a source prefix (the raw paths) */
            if (!dq_parse_prefix(val, &c->srcpfx)) return bad(err, errlen, d->lname, val);
            c->bind[0] = '\0';
        } else {
            c->srcpfx.on = false;
            if (!cpy(c->bind, sizeof c->bind, val)) return bad(err, errlen, d->lname, val);
        }
        break;
    case O_FILE: if (!*val || !cpy(c->qfile, sizeof c->qfile, val)) return bad(err, errlen, d->lname, val); break;
    case O_ZONES: if (!*val || !cpy(c->zfile, sizeof c->zfile, val)) return bad(err, errlen, d->lname, val); break;
    case O_TIME: if (!dq_parse_dbl(val, &x, 0.001, 31536000)) return bad(err, errlen, d->lname, val); c->duration = x; break;
    case O_RUNS: if (!dq_parse_u64(val, &u, 1000000000) || u == 0) return bad(err, errlen, d->lname, val); c->runs = u; break;
    case O_COUNT: if (!dq_parse_u64(val, &u, UINT64_MAX / 2) || u == 0) return bad(err, errlen, d->lname, val); c->count = u; break;
    case O_THREADS: if (!dq_parse_u64(val, &u, 256) || u == 0) return bad(err, errlen, d->lname, val); c->threads = (unsigned)u; break;
    case O_SOCKETS: if (!dq_parse_u64(val, &u, DQ_MAXCHAN) || u == 0) return bad(err, errlen, d->lname, val); c->sockets = (unsigned)u; break;
    case O_INFLIGHT: if (!dq_parse_u64(val, &u, 100000000) || u == 0) return bad(err, errlen, d->lname, val); c->inflight = u; break;
    case O_RATE: if (!dq_parse_u64(val, &u, 1000000000000ull) || u == 0) return bad(err, errlen, d->lname, val); c->rate = u; break;
    case O_TIMEOUT: if (!dq_parse_dbl(val, &x, 0.001, 3600)) return bad(err, errlen, d->lname, val); c->timeout = x; break;
    case O_INTERVAL: if (!dq_parse_dbl(val, &x, 0.1, 3600)) return bad(err, errlen, d->lname, val); c->interval = x; break;
    case O_BATCH: if (!dq_parse_u64(val, &u, DQ_MAXBATCH) || u == 0) return bad(err, errlen, d->lname, val); c->batch = (unsigned)u; break;
    case O_IO:
        if (!strcmp(val, "auto")) c->io = DQ_IO_AUTO;
        else if (!strcmp(val, "sendto")) c->io = DQ_IO_SENDTO;
        else if (!strcmp(val, "mmsg")) c->io = DQ_IO_MMSG;
        else if (!strcmp(val, "xdp")) c->io = DQ_IO_XDP;
        else if (!strcmp(val, "netmap")) c->io = DQ_IO_NETMAP;
        else { snprintf(err, errlen, "--io: '%.30s' is not one of auto, sendto, mmsg, xdp, netmap", val); return -1; }
        break;
    case O_JSON: c->json = true; break;
    case O_NULL:
        c->null_target = true;
        c->null_sink = false;
        if (val && !strcmp(val, "sink")) c->null_sink = true;
        else if (val && strcmp(val, "reflect")) { snprintf(err, errlen, "--null-target: '%.30s' is not reflect or sink", val); return -1; }
        break;
    case O_REFLECT: {
        char h[128];
        int p;
        if (!dq_split_hostport(val, h, sizeof h, &p) || !cpy(c->reflect, sizeof c->reflect, val)) return bad(err, errlen, d->lname, val);
        break;
    }
    case O_ZIPF: if (!dq_parse_dbl(val, &x, 0, 8)) return bad(err, errlen, d->lname, val); c->zipf = x; break;
    case O_MISS: if (!dq_parse_dbl(val, &x, 0, 1)) return bad(err, errlen, d->lname, val); c->miss = x; break;
    case O_MISSPOOL: if (!dq_parse_u64(val, &u, 16000000) || u == 0) return bad(err, errlen, d->lname, val); c->miss_pool = (unsigned)u; break;
    case O_QTYPES: {
        uint16_t t[DQ_MAXTYPES];
        uint32_t w[DQ_MAXTYPES];
        if (dq_parse_qtypes(val, t, w, err, errlen) < 0 || !cpy(c->qtypes, sizeof c->qtypes, val)) return err[0] ? -1 : bad(err, errlen, d->lname, val);
        break;
    }
    case O_SEED: if (!dq_parse_u64(val, &u, UINT64_MAX)) return bad(err, errlen, d->lname, val); c->seed = u; break;
    case O_NOPIN: c->no_pin = true; break;
    case O_CPUBASE: if (!dq_parse_u64(val, &u, 4096)) return bad(err, errlen, d->lname, val); c->cpu_base = (unsigned)u; break;
    case O_IFACE: if (!*val || !cpy(c->iface, sizeof c->iface, val)) return bad(err, errlen, d->lname, val); break;
    case O_SRCMAC: { uint8_t m[6]; if (!dq_parse_mac(val, m) || !cpy(c->src_mac, sizeof c->src_mac, val)) return bad(err, errlen, d->lname, val); break; }
    case O_HOPMAC: { uint8_t m[6]; if (!dq_parse_mac(val, m) || !cpy(c->next_hop_mac, sizeof c->next_hop_mac, val)) return bad(err, errlen, d->lname, val); break; }
    case O_HOP: { uint8_t ip[16]; if (!dq_parse_ip(val, ip, NULL) || !cpy(c->next_hop, sizeof c->next_hop, val)) return bad(err, errlen, d->lname, val); break; }
    case O_QUEUE: if (!dq_parse_u64(val, &u, 4096)) return bad(err, errlen, d->lname, val); c->queue = (unsigned)u; break;
    case O_SPORT: if (!dq_parse_u64(val, &u, 65000) || u < 1024) return bad(err, errlen, d->lname, val); c->sport_base = (unsigned)u; break;
    case O_XDPMODE:
        if (strcmp(val, "auto") && strcmp(val, "skb") && strcmp(val, "drv")) { snprintf(err, errlen, "--xdp-mode: '%.30s' is not auto, skb or drv", val); return -1; }
        cpy(c->xdp_mode, sizeof c->xdp_mode, val);
        break;
    case O_ALLOWANY: c->allow_any_source = true; break;
    case O_FRAMEMEM: if (!dq_parse_u64(val, &u, 1048576)) return bad(err, errlen, d->lname, val); c->frame_mem_mb = (unsigned)u; break;
    case O_AGENT: if (!*val || !cpy(c->agent, sizeof c->agent, val)) return bad(err, errlen, d->lname, val); break;
    case O_AGENTS: if (!*val || !cpy(c->agents, sizeof c->agents, val)) return bad(err, errlen, d->lname, val); break;
    case O_AGENTKEY: if (!*val || !cpy(c->agent_key, sizeof c->agent_key, val)) return bad(err, errlen, d->lname, val); break;
    case O_AGENTTO: if (!dq_parse_dbl(val, &x, 0.1, 3600)) return bad(err, errlen, d->lname, val); c->agent_timeout = x; break;
    case O_NOLOCAL: c->no_local = true; break;
    case O_VERBOSE: c->verbose = true; break;
    case O_HELP: c->help = true; break;
    case O_VERSION: c->version = true; break;
    case O_NORC: c->ignore_rc = true; break;
    }
    return 0;
}

int dq_parse_args(dq_cfg_t *c, int argc, char **argv, char *err, size_t errlen) {
    err[0] = '\0';
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        const optdef_t *d = NULL;
        const char *val = NULL;
        if (a[0] == '+') {
            if (dq_qopts_parse_tok(&c->qo, a, err, errlen) < 0) return -1;
            continue;
        }
        if (a[0] == '@') {   /* dig style: @server */
            if (!a[1] || !cpy(c->server, sizeof c->server, a + 1)) { snprintf(err, errlen, "bad server '%.60s'", a); return -1; }
            continue;
        }
        if (a[0] == '-' && a[1] == '-' && a[2]) {
            const char *name = a + 2, *eq = strchr(name, '=');
            size_t nl = eq ? (size_t)(eq - name) : strlen(name);
            for (size_t k = 0; k < sizeof OPTS / sizeof OPTS[0]; k++)
                if (strlen(OPTS[k].lname) == nl && memcmp(OPTS[k].lname, name, nl) == 0) { d = &OPTS[k]; break; }
            if (!d) { snprintf(err, errlen, "unknown option '%.60s'", a); return -1; }
            if (eq) {
                if (d->has_arg == 0) { snprintf(err, errlen, "--%s takes no value", d->lname); return -1; }
                val = eq + 1;
            } else if (d->has_arg == 1) {
                if (i + 1 >= argc) { snprintf(err, errlen, "--%s needs a value", d->lname); return -1; }
                val = argv[++i];
            }
        } else if (a[0] == '-' && a[1] && a[1] != '-') {
            for (size_t k = 0; k < sizeof OPTS / sizeof OPTS[0]; k++)
                if (OPTS[k].sname && OPTS[k].sname == a[1]) { d = &OPTS[k]; break; }
            if (!d) { snprintf(err, errlen, "unknown option '%.60s'", a); return -1; }
            if (d->has_arg == 1) {
                if (a[2]) val = a + 2;
                else if (i + 1 < argc) val = argv[++i];
                else { snprintf(err, errlen, "-%c needs a value", d->sname); return -1; }
            } else if (a[2]) {
                snprintf(err, errlen, "'%.60s': flags are not combined, write them apart", a);
                return -1;
            }
        } else {
            snprintf(err, errlen, "unexpected argument '%.60s'", a);
            return -1;
        }
        if (apply(c, d, val, err, errlen) < 0) return -1;
    }
    return 0;
}

#define RC_MAX_BYTES 65536
#define RC_MAX_TOKENS 256

int dq_parse_rc_buf(dq_cfg_t *c, const char *buf, size_t len, char *err, size_t errlen) {
    if (len > RC_MAX_BYTES) { snprintf(err, errlen, "the rc file is longer than %d bytes", RC_MAX_BYTES); return -1; }
    char *copy = malloc(len + 1);
    if (!copy) { snprintf(err, errlen, "out of memory"); return -1; }
    memcpy(copy, buf, len);
    copy[len] = '\0';
    char *toks[RC_MAX_TOKENS];
    int nt = 0;
    char *p = copy;
    int rc = 0;
    while (*p) {
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') { p++; continue; }
        if (*p == '#') { while (*p && *p != '\n') p++; continue; }
        if (nt >= RC_MAX_TOKENS) { snprintf(err, errlen, "more than %d words", RC_MAX_TOKENS); rc = -1; break; }
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            toks[nt++] = p;
            while (*p && *p != q) p++;
            if (!*p) { snprintf(err, errlen, "an unterminated quote"); rc = -1; break; }
            *p++ = '\0';
        } else {
            toks[nt++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
            if (*p) *p++ = '\0';
        }
    }
    if (rc == 0) rc = dq_parse_args(c, nt, toks, err, errlen);
    free(copy);
    c->help = c->version = false;   /* a default file must not turn into a help run */
    return rc;
}

int dq_load_rc(dq_cfg_t *c, char *err, size_t errlen) {
    const char *home = getenv("HOME");
#ifdef _WIN32
    if (!home || !*home) home = getenv("USERPROFILE");
#endif
    if (!home || !*home) return 0;
    char path[600];
    if (snprintf(path, sizeof path, "%s/.dnsqpsrc", home) >= (int)sizeof path) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *buf = malloc(RC_MAX_BYTES + 2);
    if (!buf) { fclose(f); snprintf(err, errlen, "out of memory"); return -1; }
    size_t n = fread(buf, 1, RC_MAX_BYTES + 1, f);
    fclose(f);
    char e2[200];
    int rc = dq_parse_rc_buf(c, buf, n, e2, sizeof e2);
    free(buf);
    if (rc < 0) snprintf(err, errlen, "%s: %s (-r ignores this file)", path, e2);
    return rc;
}

int dq_cfg_check(dq_cfg_t *c, char *err, size_t errlen) {
    if (c->help || c->version) return 0;
    if (c->reflect[0]) return 0;
    char hb[160];
    int hp;
    if (c->agent[0]) {   /* an agent takes its work from the controller */
        if (c->agents[0] || c->no_local || !dq_hostport_strict(c->agent, hb, sizeof hb, &hp)) { snprintf(err, errlen, "--agent needs ADDR:PORT and cannot be combined with --agents or --no-local"); return -1; }
        if (!strcmp(hb, "0.0.0.0") || !strcmp(hb, "::") || !strcmp(hb, "*")) { snprintf(err, errlen, "--agent: bind to one address of this host, not a wildcard"); return -1; }
        return 0;
    }
    if (c->agents[0]) {
        char lst[sizeof c->agents];
        strcpy(lst, c->agents);
        unsigned na = 0;
        for (char *s = lst; s; ) {
            char *comma = strchr(s, ',');
            if (comma) *comma = '\0';
            if (!dq_hostport_strict(s, hb, sizeof hb, &hp)) { snprintf(err, errlen, "--agents: '%.60s' is not HOST:PORT", s); return -1; }
            na++;
            s = comma ? comma + 1 : NULL;
        }
        if (na > DQ_MAXAGENTS) { snprintf(err, errlen, "--agents: more than %d agents", DQ_MAXAGENTS); return -1; }
    } else if (c->no_local) {
        snprintf(err, errlen, "--no-local needs --agents");
        return -1;
    }
    if (c->agent_key[0] && !c->agents[0]) { snprintf(err, errlen, "--agent-key needs --agent or --agents"); return -1; }
    if (c->qfile[0] && c->zfile[0]) { snprintf(err, errlen, "-d (query file) and -z (name list) cannot be used together"); return -1; }
    if (!c->qfile[0] && !c->zfile[0]) { snprintf(err, errlen, "no queries: give a query file (-d FILE) or a name list (-z FILE)"); return -1; }
    if (c->zfile[0] && c->runs) { snprintf(err, errlen, "-n counts passes over a query file; with -z use -l or -N"); return -1; }
    if (!c->zfile[0] && (c->miss > 0 || c->qtypes[0])) { snprintf(err, errlen, "--miss and --qtypes belong to the generated mode (-z)"); return -1; }
    if (c->null_target && (c->io == DQ_IO_XDP || c->io == DQ_IO_NETMAP)) {
        snprintf(err, errlen, "--null-target runs on loopback: use --io=sendto or mmsg (a kernel-bypass path needs a real interface; see docs/dnsqps.md)");
        return -1;
    }
    if (c->srcpfx.on) {
        if (c->null_target || c->io == DQ_IO_SENDTO || c->io == DQ_IO_MMSG || (c->io == DQ_IO_AUTO && !c->iface[0])) {
            snprintf(err, errlen, "-b ADDR/LEN (a source prefix) needs a kernel-bypass path: --io=xdp or --io=netmap with --iface");
            return -1;
        }
        if (!c->allow_any_source && !dq_prefix_reserved(&c->srcpfx)) {
            snprintf(err, errlen, "-b: the range is not inside 198.18.0.0/15, 240.0.0.0/4 or 2001:db8::/32; answers to real addresses would leave through the router as backscatter (--allow-any-source to override)");
            return -1;
        }
    }
    if (!c->duration && !c->count && !c->runs) c->duration = 30;
    return 0;
}
