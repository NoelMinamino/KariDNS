/* dnsqps: the agent and the controller (docs/dnsqps.md "Several client hosts").
 * Messages: a 4-byte big-endian length (1 .. DQ_MSG_MAX) and that many bytes of lines, "VERB\n" then "key=value\n".  Everything that arrives is untrusted:
 * the length, the number of lines, the characters of a key, every number (decimal digits, at most 2^58, so that the sums of 17 senders cannot overflow),
 * the histogram (bucket indexes in rising order), and the counts against each other (a result that does not add up is refused).
 * The agent authenticates the controller when it has a key (HMAC-SHA256 over its nonce, RFC 2104; OpenSSL, which dnsqps links already); nothing is
 * encrypted: the control port belongs on a private network.  An agent takes the same options as the command line, except those that start another
 * listener, controller or help run; none of the options writes a file or runs a command. */
#include "dnsqps.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#ifdef _WIN32
#define dq_close closesocket
#define would_block() (WSAGetLastError() == WSAEWOULDBLOCK)
#define in_progress() (WSAGetLastError() == WSAEWOULDBLOCK)
static int set_nonblock(dq_sock_t s) { u_long on = 1; return ioctlsocket(s, FIONBIO, &on); }
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#define dq_close close
#define would_block() (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
#define in_progress() (errno == EINPROGRESS || errno == EINTR)
static int set_nonblock(dq_sock_t s) { int fl = fcntl(s, F_GETFL, 0); return fl < 0 ? -1 : fcntl(s, F_SETFL, fl | O_NONBLOCK); }
#endif

#define NUM_LIM ((uint64_t)1 << 58)

/* 1 = ready, 0 = timeout or interrupted */
static int wait_sock(dq_sock_t s, bool write, int ms) {
#ifdef _WIN32
    WSAPOLLFD pf = { s, write ? POLLOUT : POLLIN, 0 };
    return WSAPoll(&pf, 1, ms) > 0;
#else
    struct pollfd pf = { s, write ? POLLOUT : POLLIN, 0 };
    return poll(&pf, 1, ms) > 0;
#endif
}

/* ---------------------------------------------------------------- messages */
static void mset(char *err, size_t n, const char *s) { if (err && n) snprintf(err, n, "%s", s); }

int dq_msg_parse(char *buf, size_t len, dq_msg_t *m, char *err, size_t errlen) {
    memset(m, 0, sizeof *m);
    if (len == 0 || len > DQ_MSG_MAX) { mset(err, errlen, "bad message length"); return -1; }
    if (memchr(buf, '\0', len)) { mset(err, errlen, "a NUL in a message"); return -1; }
    buf[len] = '\0';
    char *p = buf, *end = buf + len;
    bool first = true;
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        char *le = nl ? nl : end;
        if (le == p) { mset(err, errlen, "an empty line"); return -1; }
        *le = '\0';
        if (first) {
            size_t l = (size_t)(le - p);
            if (l > 15) { mset(err, errlen, "bad verb"); return -1; }
            for (char *q = p; q < le; q++)
                if (*q < 'A' || *q > 'Z') { mset(err, errlen, "bad verb"); return -1; }
            m->verb = p;
            first = false;
        } else {
            char *eq = strchr(p, '=');
            if (!eq || eq == p || eq - p > 32) { mset(err, errlen, "bad line"); return -1; }
            for (char *q = p; q < eq; q++)
                if (!((*q >= 'a' && *q <= 'z') || (*q >= '0' && *q <= '9') || *q == '_' || *q == '.' || *q == '-')) { mset(err, errlen, "bad key"); return -1; }
            if (m->n >= DQ_MSG_MAXKV) { mset(err, errlen, "too many lines"); return -1; }
            *eq = '\0';
            m->k[m->n] = p;
            m->v[m->n] = eq + 1;
            m->n++;
        }
        p = le + 1;
    }
    return 0;
}

const char *dq_msg_get(const dq_msg_t *m, const char *key) {
    for (unsigned i = 0; i < m->n; i++)
        if (!strcmp(m->k[i], key)) return m->v[i];
    return NULL;
}

static bool str_u64(const char *s, uint64_t *out) {
    if (*s < '0' || *s > '9') return false;
    uint64_t x = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        x = x * 10 + (uint64_t)(*s - '0');
        if (x > NUM_LIM) return false;
    }
    *out = x;
    return true;
}

bool dq_msg_u64(const dq_msg_t *m, const char *key, uint64_t *out) {
    const char *v = dq_msg_get(m, key);
    return v && str_u64(v, out);
}

static bool msgb_put(dq_msgb_t *b, const char *s, size_t n) {
    if (b->ovf || b->len + n > 4 + DQ_MSG_MAX) { b->ovf = true; return false; }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    return true;
}

bool dq_msgb_init(dq_msgb_t *b, const char *verb) {
    b->p = malloc(4 + DQ_MSG_MAX);
    b->len = 4;
    b->ovf = false;
    if (!b->p) { b->ovf = true; return false; }
    return msgb_put(b, verb, strlen(verb)) && msgb_put(b, "\n", 1);
}

bool dq_msgb_kv(dq_msgb_t *b, const char *key, const char *val) {
    if (strchr(key, '=') || strchr(key, '\n') || strchr(val, '\n') || !*key) { b->ovf = true; return false; }
    return msgb_put(b, key, strlen(key)) && msgb_put(b, "=", 1) && msgb_put(b, val, strlen(val)) && msgb_put(b, "\n", 1);
}

bool dq_msgb_u64(dq_msgb_t *b, const char *key, uint64_t v) {
    char t[24];
    snprintf(t, sizeof t, "%" PRIu64, v);
    return dq_msgb_kv(b, key, t);
}

void dq_msgb_free(dq_msgb_t *b) { free(b->p); b->p = NULL; }

/* ---------------------------------------------------------------- a connection */
void dq_conn_init(dq_conn_t *c, dq_sock_t s) {
    memset(c, 0, sizeof *c);
    c->s = s;
}

void dq_conn_close(dq_conn_t *c) {
    if (c->s != DQ_BADSOCK) dq_close(c->s);
    c->s = DQ_BADSOCK;
    free(c->buf);
    c->buf = NULL;
}

int dq_conn_send(dq_conn_t *c, dq_msgb_t *b, unsigned timeout_ms) {
    if (b->ovf || b->len <= 4 || c->s == DQ_BADSOCK) return -1;
    size_t pl = b->len - 4;
    b->p[0] = (char)(pl >> 24); b->p[1] = (char)(pl >> 16); b->p[2] = (char)(pl >> 8); b->p[3] = (char)pl;
    uint64_t end = dq_now_ns() + (uint64_t)timeout_ms * 1000000ull;
    size_t off = 0;
    while (off < b->len) {
        int r = (int)send(c->s, b->p + off, b->len - off, 0);
        if (r > 0) { off += (size_t)r; continue; }
        if (r < 0 && !would_block()) return -1;
        uint64_t now = dq_now_ns();
        if (now >= end) return -1;
        wait_sock(c->s, true, (int)((end - now) / 1000000 + 1));
    }
    return 0;
}

int dq_conn_recv(dq_conn_t *c, unsigned wait_ms, dq_msg_t *m, char *err, size_t errlen) {
    if (c->done) {   /* the message of the last call is no longer needed */
        c->hgot = 0;
        c->pgot = 0;
        c->done = false;
    }
    uint64_t end = dq_now_ns() + (uint64_t)wait_ms * 1000000ull;
    for (;;) {
        int r;
        if (c->hgot < 4) {
            r = (int)recv(c->s, (char *)c->hdr + c->hgot, 4 - c->hgot, 0);
        } else {
            r = (int)recv(c->s, c->buf + c->pgot, c->plen - c->pgot, 0);
        }
        if (r > 0) {
            if (c->hgot < 4) {
                c->hgot += (unsigned)r;
                if (c->hgot == 4) {
                    c->plen = ((uint32_t)c->hdr[0] << 24) | ((uint32_t)c->hdr[1] << 16) | ((uint32_t)c->hdr[2] << 8) | c->hdr[3];
                    if (c->plen == 0 || c->plen > DQ_MSG_MAX) { mset(err, errlen, "bad message length"); return -1; }
                    if (!c->buf && !(c->buf = malloc(DQ_MSG_MAX + 1))) { mset(err, errlen, "out of memory"); return -1; }
                }
            } else {
                c->pgot += (size_t)r;
                if (c->pgot == c->plen) {
                    c->done = true;
                    return dq_msg_parse(c->buf, c->plen, m, err, errlen) < 0 ? -1 : 1;
                }
            }
            continue;
        }
        if (r == 0) { mset(err, errlen, "connection closed"); return -1; }
        if (!would_block()) { mset(err, errlen, "receive error"); return -1; }
        uint64_t now = dq_now_ns();
        if (now >= end) return 0;
        wait_sock(c->s, false, (int)((end - now) / 1000000 + 1));
    }
}

/* ---------------------------------------------------------------- the result of one sender */
int dq_result_put(dq_msgb_t *b, const dq_report_t *r) {
    const dq_counts_t *c = &r->c;
    const dq_hist_t *h = &r->h;
    dq_msgb_u64(b, "sent", c->sent); dq_msgb_u64(b, "completed", c->completed); dq_msgb_u64(b, "lost", c->lost);
    dq_msgb_u64(b, "malformed", c->malformed); dq_msgb_u64(b, "unmatched", c->unmatched); dq_msgb_u64(b, "foreign", c->foreign);
    dq_msgb_u64(b, "send_errs", c->send_errs); dq_msgb_u64(b, "recv_errs", c->recv_errs);
    dq_msgb_u64(b, "sent_bytes", c->sent_bytes); dq_msgb_u64(b, "recv_bytes", c->recv_bytes);
    char rc[DQ_NRCODE * 21];
    size_t n = 0;
    for (int i = 0; i < DQ_NRCODE; i++) n += (size_t)snprintf(rc + n, sizeof rc - n, "%s%" PRIu64, i ? "," : "", c->rcode[i]);
    dq_msgb_kv(b, "rc", rc);
    dq_msgb_u64(b, "run_ns", (uint64_t)(r->run_s * 1e9));
    dq_msgb_u64(b, "threads", r->threads);
    dq_msgb_u64(b, "sockets", r->sockets);
    dq_msgb_kv(b, "io", r->io_name ? r->io_name : "");
    dq_msgb_u64(b, "hcount", h->count);
    dq_msgb_u64(b, "hsum", h->sum_ns);
    dq_msgb_u64(b, "hmin", h->count ? h->min_ns : 0);
    dq_msgb_u64(b, "hmax", h->max_ns);
    char *hb = malloc(DQ_HBUCKETS * 24);
    if (!hb) { b->ovf = true; return -1; }
    size_t hl = dq_hist_encode(h, hb, DQ_HBUCKETS * 24);
    if (hl == (size_t)-1) { free(hb); b->ovf = true; return -1; }
    dq_msgb_kv(b, "hb", hb);
    free(hb);
    return b->ovf ? -1 : 0;
}

int dq_result_get(const dq_msg_t *m, dq_report_t *r, char *err, size_t errlen) {
    memset(r, 0, sizeof *r);
    dq_hist_init(&r->h);
    dq_counts_t *c = &r->c;
    uint64_t run_ns, thr, sock, hmin, hmax;
    if (!dq_msg_u64(m, "sent", &c->sent) || !dq_msg_u64(m, "completed", &c->completed) || !dq_msg_u64(m, "lost", &c->lost) ||
        !dq_msg_u64(m, "malformed", &c->malformed) || !dq_msg_u64(m, "unmatched", &c->unmatched) || !dq_msg_u64(m, "foreign", &c->foreign) ||
        !dq_msg_u64(m, "send_errs", &c->send_errs) || !dq_msg_u64(m, "recv_errs", &c->recv_errs) || !dq_msg_u64(m, "sent_bytes", &c->sent_bytes) ||
        !dq_msg_u64(m, "recv_bytes", &c->recv_bytes) || !dq_msg_u64(m, "run_ns", &run_ns) || !dq_msg_u64(m, "threads", &thr) ||
        !dq_msg_u64(m, "sockets", &sock) || !dq_msg_u64(m, "hcount", &r->h.count) || !dq_msg_u64(m, "hsum", &r->h.sum_ns) ||
        !dq_msg_u64(m, "hmin", &hmin) || !dq_msg_u64(m, "hmax", &hmax)) {
        mset(err, errlen, "a result field is missing or not a number");
        return -1;
    }
    const char *rc = dq_msg_get(m, "rc"), *io = dq_msg_get(m, "io"), *hb = dq_msg_get(m, "hb");
    if (!rc || !io || !hb || strlen(io) >= sizeof r->io_buf) { mset(err, errlen, "a result field is missing"); return -1; }
    uint64_t rsum = 0;
    for (int i = 0; i < DQ_NRCODE; i++) {
        if (!*rc) { mset(err, errlen, "bad rcode list"); return -1; }
        char t[24];
        size_t l = strcspn(rc, ",");
        if (l == 0 || l >= sizeof t) { mset(err, errlen, "bad rcode list"); return -1; }
        memcpy(t, rc, l);
        t[l] = '\0';
        if (!str_u64(t, &c->rcode[i])) { mset(err, errlen, "bad rcode list"); return -1; }
        rsum += c->rcode[i];
        rc += l;
        if (i < DQ_NRCODE - 1) { if (*rc != ',') { mset(err, errlen, "bad rcode list"); return -1; } rc++; }
    }
    if (*rc) { mset(err, errlen, "bad rcode list"); return -1; }
    uint64_t hcount = r->h.count;
    if (!dq_hist_decode(&r->h, hb) || r->h.count != hcount) { mset(err, errlen, "bad histogram"); return -1; }
    r->h.sum_ns = 0;
    dq_msg_u64(m, "hsum", &r->h.sum_ns);
    if (c->completed > c->sent || c->lost > c->sent || rsum != c->completed || hcount > c->completed || (hcount && hmin > hmax)) {
        mset(err, errlen, "the counts of a result do not add up");
        return -1;
    }
    r->h.min_ns = hcount ? hmin : UINT64_MAX;
    r->h.max_ns = hmax;
    r->run_s = (double)run_ns / 1e9;
    r->threads = (unsigned)(thr > 65536 ? 65536 : thr);
    r->sockets = (unsigned)(sock > 65536 ? 65536 : sock);
    strcpy(r->io_buf, io);
    r->io_name = r->io_buf;
    return 0;
}

/* ---------------------------------------------------------------- the options of an agent and of a controller */
static bool tok_is(const char *t, const char *name) {   /* --name or --name=value */
    size_t l = strlen(name);
    return !strncmp(t, name, l) && (t[l] == '\0' || t[l] == '=');
}

int dq_agent_check_tokens(char **t, int n, char *err, size_t errlen) {
    static const char *const banned[] = { "--agent", "--agents", "--agent-key", "--agent-no-key", "--no-local", "--reflect", "--help", "--version" };
    for (int i = 0; i < n; i++) {
        for (size_t k = 0; k < sizeof banned / sizeof banned[0]; k++)
            if (tok_is(t[i], banned[k])) { snprintf(err, errlen, "the option %.40s is not taken from a controller", t[i]); return -1; }
        if (!strcmp(t[i], "-h") || !strcmp(t[i], "-V")) { snprintf(err, errlen, "the option %.40s is not taken from a controller", t[i]); return -1; }
    }
    return 0;
}

void dq_args_free(dq_args_t *a) {
    for (int i = 0; i < a->n; i++) free(a->t[i]);
    a->n = 0;
}

static int args_add(dq_args_t *a, const char *s, char *err, size_t errlen) {
    if (a->n >= DQ_MAXTOK || strchr(s, '\n') || !(a->t[a->n] = strdup(s))) { mset(err, errlen, "too many options to send, or a newline in one"); return -1; }
    a->n++;
    return 0;
}

uint64_t dq_share(uint64_t total, unsigned k, unsigned i) { return total / k + (i < total % k ? 1 : 0); }

/* the controller-only options are not sent: --agents V, --agent-key V, --agent-timeout V, --no-local, -j / --json, -S V / --interval V; -r is harmless */
int dq_ctl_args(const dq_cfg_t *c, int argc, char **argv, unsigned k, unsigned i, dq_args_t *a, char *err, size_t errlen) {
    memset(a, 0, sizeof *a);
    for (int j = 0; j < argc; j++) {
        const char *t = argv[j];
        bool skip_val = false;
        if (tok_is(t, "--agents") || tok_is(t, "--agent-key") || tok_is(t, "--agent-timeout") || tok_is(t, "--interval")) skip_val = !strchr(t, '=');
        else if (!strcmp(t, "--no-local") || !strcmp(t, "--json") || !strcmp(t, "-j")) skip_val = false;
        else if (!strcmp(t, "-S")) skip_val = true;
        else if (t[0] == '-' && t[1] == 'S' && t[2]) skip_val = false;   /* -S1 */
        else { if (args_add(a, t, err, errlen) < 0) { dq_args_free(a); return -1; } continue; }
        if (skip_val) j++;
    }
    char v[160];
    if (c->rate) { snprintf(v, sizeof v, "%" PRIu64, dq_share(c->rate, k, i)); if (args_add(a, "-Q", err, errlen) < 0 || args_add(a, v, err, errlen) < 0) goto fail; }
    if (c->count) {
        uint64_t s = dq_share(c->count, k, i);
        if (s == 0) { mset(err, errlen, "-N: fewer queries than senders"); goto fail; }
        snprintf(v, sizeof v, "%" PRIu64, s);
        if (args_add(a, "-N", err, errlen) < 0 || args_add(a, v, err, errlen) < 0) goto fail;
    }
    if (c->inflight) {
        uint64_t s = dq_share(c->inflight, k, i);
        snprintf(v, sizeof v, "%" PRIu64, s ? s : 1);
        if (args_add(a, "-q", err, errlen) < 0 || args_add(a, v, err, errlen) < 0) goto fail;
    }
    if (c->srcpfx.on) {
        dq_srcpfx_t sl;
        if (!dq_prefix_slice(&c->srcpfx, k, i, &sl)) { mset(err, errlen, "-b: the prefix is too short to be shared by the senders"); goto fail; }
        dq_prefix_format(&sl, v, sizeof v);
        if (args_add(a, "-b", err, errlen) < 0 || args_add(a, v, err, errlen) < 0) goto fail;
    }
    snprintf(v, sizeof v, "%" PRIu64, (uint64_t)(c->seed + (uint64_t)i * 0x9E3779B97F4A7C15ull));
    if (args_add(a, "--seed", err, errlen) < 0 || args_add(a, v, err, errlen) < 0) goto fail;
    return 0;
fail:
    dq_args_free(a);
    return -1;
}

/* ---------------------------------------------------------------- authentication */
static void hex(const uint8_t *p, size_t n, char *out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[p[i] >> 4]; out[2 * i + 1] = d[p[i] & 15]; }
    out[2 * n] = '\0';
}

static int key_load(const char *path, char *key, size_t cap, size_t *klen, char *err, size_t errlen) {
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, errlen, "cannot read the key file %.100s", path); return -1; }
    size_t n = fread(key, 1, cap, f);
    fclose(f);
    while (n && (key[n - 1] == '\n' || key[n - 1] == '\r' || key[n - 1] == ' ' || key[n - 1] == '\t')) n--;
    if (n < 16 || n >= cap) { snprintf(err, errlen, "the key in %.100s must be 16 to %d characters", path, (int)cap - 1); return -1; }
    *klen = n;
    return 0;
}

static void mac_hex(const char *key, size_t klen, const char *nonce, char out[65]) {
    char data[96];
    int dl = snprintf(data, sizeof data, "dnsqps-agent-v1:%s", nonce);
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned ml = 0;
    HMAC(EVP_sha256(), key, (int)klen, (const unsigned char *)data, (size_t)dl, mac, &ml);
    hex(mac, ml > 32 ? 32 : ml, out);
}

/* ---------------------------------------------------------------- sockets */
static dq_sock_t tcp_connect(const char *hostport, double timeout_s, char *err, size_t errlen) {
    char host[256];
    int port;
    if (!dq_hostport_strict(hostport, host, sizeof host, &port)) { snprintf(err, errlen, "bad agent address '%.60s'", hostport); return DQ_BADSOCK; }
    struct addrinfo hints, *res = NULL;
    char ps[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) { snprintf(err, errlen, "cannot resolve '%.100s'", host); return DQ_BADSOCK; }
    dq_sock_t s = socket(res->ai_family, SOCK_STREAM, 0);
    if (s == DQ_BADSOCK || set_nonblock(s) < 0) { snprintf(err, errlen, "socket() failed"); freeaddrinfo(res); return DQ_BADSOCK; }
    int rc = connect(s, res->ai_addr, (socklen_t)res->ai_addrlen);
    freeaddrinfo(res);
    if (rc < 0 && !in_progress()) { snprintf(err, errlen, "cannot connect to %.100s: %s", hostport, strerror(errno)); dq_close(s); return DQ_BADSOCK; }
    if (rc < 0) {
        if (!wait_sock(s, true, (int)(timeout_s * 1000))) { snprintf(err, errlen, "no connection to %.100s within %.0f s", hostport, timeout_s); dq_close(s); return DQ_BADSOCK; }
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl);
        if (soerr) { snprintf(err, errlen, "cannot connect to %.100s: %s", hostport, strerror(soerr)); dq_close(s); return DQ_BADSOCK; }
    }
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    return s;
}

static dq_sock_t tcp_listen(const char *hostport, char *err, size_t errlen) {
    char host[256];
    int port;
    if (!dq_hostport_strict(hostport, host, sizeof host, &port)) { snprintf(err, errlen, "bad --agent address '%.60s'", hostport); return DQ_BADSOCK; }
    struct addrinfo hints, *res = NULL;
    char ps[8];
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    snprintf(ps, sizeof ps, "%d", port);
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) { snprintf(err, errlen, "--agent: '%.100s' is not an address", host); return DQ_BADSOCK; }
    dq_sock_t s = socket(res->ai_family, SOCK_STREAM, 0);
    if (s == DQ_BADSOCK) { snprintf(err, errlen, "socket() failed"); freeaddrinfo(res); return DQ_BADSOCK; }
#ifndef _WIN32
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#endif
    if (bind(s, res->ai_addr, (socklen_t)res->ai_addrlen) < 0 || listen(s, 4) < 0 || set_nonblock(s) < 0) {
        snprintf(err, errlen, "cannot listen on %.100s: %s", hostport, strerror(errno));
        freeaddrinfo(res);
        dq_close(s);
        return DQ_BADSOCK;
    }
    freeaddrinfo(res);
    return s;
}

/* ---------------------------------------------------------------- the agent */
typedef struct {
    dq_conn_t *conn;
    dq_msg_t msg;
    uint64_t last_prog, deadline_go;
    double wait_s;
    atomic_bool *stop;
} agent_ctx_t;

static int agent_ready(void *p) {
    agent_ctx_t *a = p;
    dq_msgb_t b;
    char err[100];
    if (!dq_msgb_init(&b, "READY")) return -1;
    int rc = dq_conn_send(a->conn, &b, 5000);
    dq_msgb_free(&b);
    if (rc < 0) return -1;
    uint64_t end = dq_now_ns() + (uint64_t)(a->wait_s * 2e9);
    while (dq_now_ns() < end) {
        int g = dq_conn_recv(a->conn, 200, &a->msg, err, sizeof err);
        if (g < 0) return -1;
        if (g == 1) return !strcmp(a->msg.verb, "GO") ? 0 : -1;   /* ABORT, or anything else */
    }
    return -1;
}

static int agent_tick(void *p, dq_livesum_t *live) {
    agent_ctx_t *a = p;
    char err[100];
    int g = dq_conn_recv(a->conn, 0, &a->msg, err, sizeof err);
    if (g != 0) return 1;   /* ABORT, a stray message or the controller is gone: stop the load */
    uint64_t now = dq_now_ns();
    if (now - a->last_prog >= 1000000000ull) {
        dq_msgb_t b;
        a->last_prog = now;
        if (!dq_msgb_init(&b, "PROG")) return 1;
        dq_msgb_u64(&b, "sent", live->sent); dq_msgb_u64(&b, "done", live->done); dq_msgb_u64(&b, "lost", live->lost);
        dq_msgb_u64(&b, "lat_sum", live->lat_sum); dq_msgb_u64(&b, "lat_cnt", live->lat_cnt);
        int rc = dq_conn_send(a->conn, &b, 2000);
        dq_msgb_free(&b);
        if (rc < 0) return 1;
    }
    return 0;
}

static void send_err(dq_conn_t *c, const char *msg) {
    dq_msgb_t b;
    if (!dq_msgb_init(&b, "ERR")) return;
    dq_msgb_kv(&b, "msg", msg);
    dq_conn_send(c, &b, 2000);
    dq_msgb_free(&b);
}

static void agent_session(const dq_cfg_t *ac, dq_sock_t cs, dq_run_fn run, atomic_bool *stop) {
    dq_conn_t conn;
    dq_conn_init(&conn, cs);
    char err[300], key[256] = "";
    size_t klen = 0;
    if (ac->agent_key[0] && key_load(ac->agent_key, key, sizeof key, &klen, err, sizeof err) < 0) { send_err(&conn, err); dq_conn_close(&conn); return; }
    uint8_t nb[16];
    char nonce[33];
    if (RAND_bytes(nb, sizeof nb) != 1) { dq_conn_close(&conn); return; }
    hex(nb, sizeof nb, nonce);
    dq_msgb_t b;
    if (!dq_msgb_init(&b, "HELLO")) { dq_conn_close(&conn); return; }
    dq_msgb_u64(&b, "v", 1);
    dq_msgb_kv(&b, "nonce", nonce);
    dq_msgb_kv(&b, "auth", klen ? "1" : "0");
    int rc = dq_conn_send(&conn, &b, 5000);
    dq_msgb_free(&b);
    agent_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.conn = &conn;
    ctx.stop = stop;
    ctx.wait_s = ac->agent_timeout;
    int g = 0;
    uint64_t end = dq_now_ns() + 10000000000ull;
    while (rc == 0 && g == 0 && dq_now_ns() < end) g = dq_conn_recv(&conn, 200, &ctx.msg, err, sizeof err);
    if (g != 1) { dq_conn_close(&conn); return; }
    uint64_t ver = 0;
    if (strcmp(ctx.msg.verb, "RUN") || !dq_msg_u64(&ctx.msg, "v", &ver) || ver != 1) { send_err(&conn, "expected RUN v=1"); dq_conn_close(&conn); return; }
    if (klen) {
        char want[65];
        const char *mac = dq_msg_get(&ctx.msg, "mac");
        mac_hex(key, klen, nonce, want);
        if (!mac || strlen(mac) != 64 || CRYPTO_memcmp(mac, want, 64) != 0) { send_err(&conn, "authentication failed"); dq_conn_close(&conn); return; }
    }
    char *toks[DQ_MAXTOK];
    int nt = 0;
    for (unsigned i = 0; i < ctx.msg.n; i++)
        if (!strcmp(ctx.msg.k[i], "arg")) {
            if (nt >= DQ_MAXTOK) { send_err(&conn, "too many options"); dq_conn_close(&conn); return; }
            toks[nt++] = ctx.msg.v[i];
        }
    dq_cfg_t cfg;
    dq_cfg_default(&cfg);
    if (dq_agent_check_tokens(toks, nt, err, sizeof err) < 0 || dq_parse_args(&cfg, nt, toks, err, sizeof err) < 0 || dq_cfg_check(&cfg, err, sizeof err) < 0) {
        send_err(&conn, err);
        dq_conn_close(&conn);
        return;
    }
    cfg.json = false;
    cfg.interval = 0;
    atomic_store(stop, false);
    dq_run_hooks_t hk = { agent_ready, agent_tick, &ctx };
    static dq_report_t rep;
    if (run(&cfg, &hk, &rep, err, sizeof err) < 0) { send_err(&conn, err); dq_conn_close(&conn); return; }
    if (atomic_load(stop)) { dq_conn_close(&conn); return; }   /* aborted: no result */
    dq_msgb_t rb;
    if (dq_msgb_init(&rb, "RESULT") && dq_result_put(&rb, &rep) == 0) dq_conn_send(&conn, &rb, 5000);
    dq_msgb_free(&rb);
    dq_conn_close(&conn);
}

int dq_agent_serve(const dq_cfg_t *c, dq_run_fn run, const atomic_bool *quit, atomic_bool *stop) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    char err[300];
    dq_sock_t ls = tcp_listen(c->agent, err, sizeof err);
    if (ls == DQ_BADSOCK) { fprintf(stderr, "dnsqps: %s\n", err); return 2; }
    fprintf(stderr, "dnsqps: agent listening on %s%s\n", c->agent, c->agent_key[0] ? " (key required)" : " (no key: keep this port on a private network)");
    while (!atomic_load(quit)) {
        if (!wait_sock(ls, false, 200)) continue;
        dq_sock_t cs = accept(ls, NULL, NULL);
        if (cs == DQ_BADSOCK) continue;
        if (set_nonblock(cs) < 0) { dq_close(cs); continue; }
        int one = 1;
        setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
        agent_session(c, cs, run, stop);
    }
    dq_close(ls);
    return 0;
}

/* ---------------------------------------------------------------- the controller */
typedef struct {
    char name[160];
    dq_conn_t conn;
    bool ready, got_result, failed;
    dq_livesum_t prog;
    dq_report_t rep;
    char why[200];
} ctl_agent_t;

typedef struct {
    ctl_agent_t *ag;
    unsigned n;
    double ready_s;
    char fail[260];
    atomic_bool *stop;
    bool went;
} ctl_ctx_t;

static void fail_agent(ctl_ctx_t *x, ctl_agent_t *a, const char *why) {
    a->failed = true;
    snprintf(a->why, sizeof a->why, "%s", why);
    if (!x->fail[0]) snprintf(x->fail, sizeof x->fail, "agent %.100s: %.140s", a->name, why);
}

/* one look at every agent's connection; a PROG, READY or RESULT is taken, anything else fails the agent */
static void ctl_poll(ctl_ctx_t *x, unsigned wait_ms) {
    bool waited = false;
    for (unsigned i = 0; i < x->n; i++) {
        ctl_agent_t *a = &x->ag[i];
        dq_msg_t m;
        char err[120];
        if (a->failed || a->got_result) continue;
        unsigned w = waited ? 0 : wait_ms;   /* the wait is spent once, on the first agent that is still being waited for */
        waited = true;
        for (;;) {
            int g = dq_conn_recv(&a->conn, w, &m, err, sizeof err);
            w = 0;
            if (g == 0) break;
            if (g < 0) { fail_agent(x, a, err); break; }
            if (!strcmp(m.verb, "READY") && !a->ready) { a->ready = true; }
            else if (!strcmp(m.verb, "PROG") && a->ready) {
                dq_livesum_t p;
                if (!dq_msg_u64(&m, "sent", &p.sent) || !dq_msg_u64(&m, "done", &p.done) || !dq_msg_u64(&m, "lost", &p.lost) ||
                    !dq_msg_u64(&m, "lat_sum", &p.lat_sum) || !dq_msg_u64(&m, "lat_cnt", &p.lat_cnt)) { fail_agent(x, a, "bad progress message"); break; }
                a->prog = p;
            } else if (!strcmp(m.verb, "RESULT") && a->ready) {
                if (dq_result_get(&m, &a->rep, err, sizeof err) < 0) { fail_agent(x, a, err); break; }
                a->got_result = true;
                break;
            } else if (!strcmp(m.verb, "ERR")) {
                const char *w = dq_msg_get(&m, "msg");
                fail_agent(x, a, w ? w : "refused the run");
                break;
            } else { fail_agent(x, a, "unexpected message"); break; }
        }
    }
    if (!waited && wait_ms) dq_sleep_us(wait_ms * 1000);
}

static void ctl_send_all(ctl_ctx_t *x, const char *verb) {
    for (unsigned i = 0; i < x->n; i++) {
        dq_msgb_t b;
        if (x->ag[i].failed || x->ag[i].conn.s == DQ_BADSOCK || !dq_msgb_init(&b, verb)) continue;
        dq_conn_send(&x->ag[i].conn, &b, 2000);
        dq_msgb_free(&b);
    }
}

static int ctl_ready(void *p) {
    ctl_ctx_t *x = p;
    uint64_t end = dq_now_ns() + (uint64_t)(x->ready_s * 1e9);
    for (;;) {
        ctl_poll(x, 50);
        unsigned nready = 0;
        for (unsigned i = 0; i < x->n; i++) {
            if (x->ag[i].failed) return -1;
            if (x->ag[i].ready) nready++;
        }
        if (nready == x->n) break;
        if (dq_now_ns() >= end) {
            for (unsigned i = 0; i < x->n; i++)
                if (!x->ag[i].ready) { fail_agent(x, &x->ag[i], "not ready in time"); break; }
            return -1;
        }
    }
    ctl_send_all(x, "GO");
    x->went = true;
    return 0;
}

static int ctl_tick(void *p, dq_livesum_t *live) {
    ctl_ctx_t *x = p;
    ctl_poll(x, 0);
    for (unsigned i = 0; i < x->n; i++) {
        if (x->ag[i].failed) return 1;
        live->sent += x->ag[i].prog.sent;
        live->done += x->ag[i].prog.done;
        live->lost += x->ag[i].prog.lost;
        live->lat_sum += x->ag[i].prog.lat_sum;
        live->lat_cnt += x->ag[i].prog.lat_cnt;
    }
    return 0;
}

int dq_controller(dq_cfg_t *c, int argc, char **argv, dq_run_fn run, atomic_bool *stop, FILE *st) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    char err[300], list[sizeof c->agents];
    ctl_ctx_t x;
    ctl_agent_t *ag = calloc(DQ_MAXAGENTS, sizeof *ag);
    if (!ag) { fprintf(stderr, "dnsqps: out of memory\n"); return 2; }
    memset(&x, 0, sizeof x);
    x.ag = ag;
    x.ready_s = c->agent_timeout;
    x.stop = stop;
    strcpy(list, c->agents);
    for (char *s = list; s && x.n < DQ_MAXAGENTS; ) {
        char *comma = strchr(s, ',');
        if (comma) *comma = '\0';
        snprintf(ag[x.n].name, sizeof ag[x.n].name, "%s", s);
        dq_conn_init(&ag[x.n].conn, DQ_BADSOCK);
        x.n++;
        s = comma ? comma + 1 : NULL;
    }
    unsigned k = x.n + (c->no_local ? 0 : 1), first = c->no_local ? 0 : 1;
    char key[256] = "";
    size_t klen = 0;
    int rcx = 2;
    if (c->agent_key[0] && key_load(c->agent_key, key, sizeof key, &klen, err, sizeof err) < 0) { fprintf(stderr, "dnsqps: %s\n", err); goto done; }

    /* connect, hello, run: the agents start their set-up while the others are still being asked */
    for (unsigned i = 0; i < x.n; i++) {
        ctl_agent_t *a = &ag[i];
        dq_sock_t s = tcp_connect(a->name, c->agent_timeout, err, sizeof err);
        if (s == DQ_BADSOCK) { fprintf(stderr, "dnsqps: agent %s: %s\n", a->name, err); goto done; }
        dq_conn_init(&a->conn, s);
        dq_msg_t m;
        int g = 0;
        uint64_t end = dq_now_ns() + (uint64_t)(c->agent_timeout * 1e9);
        while (g == 0 && dq_now_ns() < end) g = dq_conn_recv(&a->conn, 100, &m, err, sizeof err);
        uint64_t ver = 0;
        const char *nonce;
        if (g != 1 || strcmp(m.verb, "HELLO") || !dq_msg_u64(&m, "v", &ver) || ver != 1 || !(nonce = dq_msg_get(&m, "nonce")) || strlen(nonce) != 32) {
            fprintf(stderr, "dnsqps: agent %s: no valid HELLO%s%s\n", a->name, g < 0 ? ": " : "", g < 0 ? err : "");
            goto done;
        }
        const char *auth = dq_msg_get(&m, "auth");
        if (auth && auth[0] == '1' && !klen) { fprintf(stderr, "dnsqps: agent %s wants a key: give --agent-key FILE\n", a->name); goto done; }
        dq_args_t args;
        if (dq_ctl_args(c, argc, argv, k, first + i, &args, err, sizeof err) < 0) { fprintf(stderr, "dnsqps: %s\n", err); goto done; }
        dq_msgb_t b;
        bool ok = dq_msgb_init(&b, "RUN") && dq_msgb_u64(&b, "v", 1);
        if (klen) { char mac[65]; mac_hex(key, klen, nonce, mac); ok = ok && dq_msgb_kv(&b, "mac", mac); }
        for (int j = 0; ok && j < args.n; j++) ok = dq_msgb_kv(&b, "arg", args.t[j]);
        dq_args_free(&args);
        int srv = ok ? dq_conn_send(&a->conn, &b, 5000) : -1;
        dq_msgb_free(&b);
        if (srv < 0) { fprintf(stderr, "dnsqps: agent %s: cannot send the run\n", a->name); goto done; }
    }

    /* this host's share, and the run: the hooks wait for every agent's READY, send GO and add the agents' progress */
    dq_report_t local;
    memset(&local, 0, sizeof local);
    dq_hist_init(&local.h);
    local.io_name = "";
    int lrc = 0;
    if (!c->no_local) {
        dq_cfg_t lc = *c;
        dq_args_t la;
        if (dq_ctl_args(c, argc, argv, k, 0, &la, err, sizeof err) < 0) { fprintf(stderr, "dnsqps: %s\n", err); goto done; }
        /* the same shares the agents get, applied to this process's configuration */
        if (c->rate) lc.rate = dq_share(c->rate, k, 0);
        if (c->count) lc.count = dq_share(c->count, k, 0);
        if (c->inflight) lc.inflight = dq_share(c->inflight, k, 0) ? dq_share(c->inflight, k, 0) : 1;
        if (c->srcpfx.on) dq_prefix_slice(&c->srcpfx, k, 0, &lc.srcpfx);
        dq_args_free(&la);
        lc.agents[0] = '\0';
        dq_run_hooks_t hk = { ctl_ready, ctl_tick, &x };
        lrc = run(&lc, &hk, &local, err, sizeof err);
        if (lrc < 0) {
            if (!x.fail[0]) fprintf(stderr, "dnsqps: %s\n", err);
            goto abort_all;
        }
    } else {
        if (ctl_ready(&x) < 0) goto abort_all;
        uint64_t p_sent = 0, p_done = 0, p_lost = 0, p_ls = 0, p_lc = 0, t0 = dq_now_ns(), last = t0, next = t0 + (uint64_t)(c->interval * 1e9);
        for (;;) {
            unsigned have = 0;
            for (unsigned i = 0; i < x.n; i++) have += x.ag[i].got_result ? 1u : 0u;
            if (have == x.n || x.fail[0] || atomic_load(stop)) break;
            dq_livesum_t s = { 0, 0, 0, 0, 0 };
            ctl_tick(&x, &s);
            if (c->interval > 0 && dq_now_ns() >= next) {
                uint64_t now = dq_now_ns();
                dq_print_interval(st, (double)(now - t0) / 1e9, (double)(now - last) / 1e9, s.sent - p_sent, s.done - p_done, s.lost - p_lost, s.lat_sum - p_ls, s.lat_cnt - p_lc);
                p_sent = s.sent; p_done = s.done; p_lost = s.lost; p_ls = s.lat_sum; p_lc = s.lat_cnt;
                last = now;
                next += (uint64_t)(c->interval * 1e9);
            }
            ctl_poll(&x, 10);
        }
    }

    /* the results of the agents: they finish about when this host does; the bound is the query timeout and then some */
    {
        uint64_t end = dq_now_ns() + (uint64_t)((c->timeout + 30.0) * 1e9);
        for (;;) {
            unsigned have = 0;
            for (unsigned i = 0; i < x.n; i++) have += x.ag[i].got_result ? 1u : 0u;
            if (have == x.n || x.fail[0]) break;
            if (dq_now_ns() >= end) {
                for (unsigned i = 0; i < x.n; i++)
                    if (!x.ag[i].got_result) { fail_agent(&x, &x.ag[i], "no result in time"); break; }
                break;
            }
            ctl_poll(&x, 100);
        }
    }
    if (x.fail[0]) goto abort_all;

    /* the merged report: sums of the counters, the histograms added (the buckets are the same everywhere: exact), the longest run time */
    {
        static dq_report_t rep;
        memset(&rep, 0, sizeof rep);
        dq_hist_init(&rep.h);
        char iob[24] = "";
        bool same_io = true;
        unsigned nsend = 0;
        if (!c->no_local) {
            dq_counts_add(&rep.c, &local.c);
            dq_hist_merge(&rep.h, &local.h);
            rep.run_s = local.run_s;
            rep.threads = local.threads;
            snprintf(iob, sizeof iob, "%s", local.io_name ? local.io_name : "");
            nsend++;
        }
        for (unsigned i = 0; i < x.n; i++) {
            const dq_report_t *r = &x.ag[i].rep;
            dq_counts_add(&rep.c, &r->c);
            dq_hist_merge(&rep.h, &r->h);
            if (r->run_s > rep.run_s) rep.run_s = r->run_s;
            rep.threads += r->threads;
            if (!iob[0]) snprintf(iob, sizeof iob, "%s", r->io_name);
            else if (strcmp(iob, r->io_name)) same_io = false;
            nsend++;
        }
        snprintf(rep.io_buf, sizeof rep.io_buf, "%s", same_io ? iob : "mixed");
        rep.io_name = rep.io_buf;
        rep.sockets = c->sockets;
        snprintf(rep.server, sizeof rep.server, "%.200s:%d, %u senders", c->server, c->port, nsend);
        for (unsigned i = 0; i < x.n; i++) {
            const dq_report_t *r = &x.ag[i].rep;
            fprintf(st, "[Agent %s] sent %" PRIu64 ", completed %" PRIu64 ", lost %" PRIu64 ", %.1f qps, I/O path %s\n", x.ag[i].name, r->c.sent, r->c.completed, r->c.lost,
                    r->run_s > 0 ? (double)r->c.completed / r->run_s : 0.0, r->io_name);
        }
        if (!c->no_local)
            fprintf(st, "[Local] sent %" PRIu64 ", completed %" PRIu64 ", lost %" PRIu64 ", %.1f qps, I/O path %s\n", local.c.sent, local.c.completed, local.c.lost,
                    local.run_s > 0 ? (double)local.c.completed / local.run_s : 0.0, local.io_name ? local.io_name : "");
        fflush(st);
        if (c->json) dq_print_json(stdout, &rep);
        else dq_print_text(stdout, &rep);
        fflush(stdout);
        rcx = (rep.c.sent > 0 && rep.c.completed == 0) ? 1 : 0;
        if (rcx) fprintf(stderr, "dnsqps: no answer at all (is the server up at %s:%d?)\n", c->server, c->port);
        goto done;
    }
abort_all:
    atomic_store(stop, true);
    ctl_send_all(&x, "ABORT");
    fprintf(stderr, "dnsqps: aborted: %s\n", x.fail[0] ? x.fail : "the local run did not start");
    rcx = x.went ? 3 : 2;
done:
    for (unsigned i = 0; i < x.n; i++) dq_conn_close(&ag[i].conn);
    free(ag);
    return rcx;
}
