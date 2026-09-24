#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_query_engine.h"
#include "dns_server_internal.h"
#include "dns_dynamic_update.h"

// Prototypes for internal query engine functions under test
void restore_checkpoint(const resolve_checkpoint_t *cp, uint16_t *offset,
                        uint16_t *ancount, uint16_t *nscount, uint16_t *arcount);
bool nsec_covers_name(const dns_record_t *rec, const char *name);
dns_record_t *find_covering_nsec(zone_arena_t *zone, const char *name);
size_t hex_to_bytes(const char *hex, uint8_t *out, size_t max_out);
int64_t monotonic_ms(void);
uint32_t remaining_ms(int64_t deadline);
int build_synthetic_servfail(const uint8_t *req, size_t req_len,
                             uint8_t *res, size_t max_res_len);
ssize_t write_all_timeout(int fd, const uint8_t *buf, size_t len, uint32_t timeout_ms);
ssize_t read_all_timeout(int fd, uint8_t *buf, size_t len, uint32_t timeout_ms);
int dispatch_to_program_zone(const char *domain, const uint8_t *req, size_t req_len,
                             uint8_t *res, size_t max_res_len,
                             const char *client_ip, bool is_tcp);
bool question_section_matches(const uint8_t *resp, size_t resp_len,
                              const uint8_t *req, size_t req_len);
int dispatch_forward_zone(zone_config_t *zcfg, const uint8_t *req, size_t req_len,
                          uint8_t *res, size_t max_res_len);
size_t name_to_canonical_wire(const char *name, uint8_t *wire, size_t max_wire);
bool compute_nsec3_hash(const char *name, uint8_t algo, uint16_t iterations,
                        const uint8_t *salt, size_t salt_len,
                        char *out_b32, size_t out_b32_sz);
bool nsec3_covers_hash(const char *owner_hash, const char *next_hash, const char *target_hash);
dns_record_t *find_matching_nsec3(zone_arena_t *zone, const char *hash_b32, const char *apex);
dns_record_t *find_covering_nsec3(zone_arena_t *zone, const char *target_hash);
bool find_next_closer_name(const char *qname, const char *encloser, char *out, size_t out_sz);
bool attach_nsec3_record(zone_arena_t *zone, dns_record_t *rec,
                         uint8_t *res, size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *nscount,
                         dns_record_t **attached, int *attached_count);
bool name_exists_in_zone(zone_arena_t *zone, const char *name, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag);
const char *find_closest_encloser(zone_arena_t *zone, const char *qname, const char *zone_apex, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag);
program_plugin_t *find_program_plugin(const char *domain);
ssize_t forward_via_tcp(const struct sockaddr_storage *ss, size_t ss_len,
                        const uint8_t *query, size_t query_len,
                        uint8_t *resp_out, size_t resp_out_cap,
                        uint32_t timeout_ms);

// Mock globals
int g_control_kq = -1;
int g_notify_ipc[2] = {-1, -1};
int g_broker_sock = -1;
config_rcu_t g_config_db;
_Atomic int g_xfers_running = 0;
_Atomic int g_worker_count = ATOMIC_VAR_INIT(0);
_Atomic(worker_ctx_t *) g_worker_ctxs = ATOMIC_VAR_INIT(NULL);
int g_cwd_fd = -1;
char g_startup_cwd[PATH_MAX] = "";

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

server_config_t *acquire_config_snapshot(void) {
    return atomic_load_explicit(&g_config_db.active, memory_order_acquire);
}
void release_config_snapshot(server_config_t *snap) { (void)snap; }

int broker_connect(int family, int type, struct sockaddr *addr, size_t addr_len) {
    (void)family; (void)type; (void)addr; (void)addr_len; return -1;
}

ssize_t send_tcp_robust(int fd, const uint8_t *buf, size_t len) {
    (void)fd; (void)buf; return len;
}

int read_dns_tcp_message(int fd, tcp_stream_ctx_t *ctx, uint8_t **msg_out, uint16_t *msg_len_out) {
    (void)fd; (void)ctx; (void)msg_out; (void)msg_len_out; return -1;
}

void submit_response_log(log_action_t action, const char *client_ip, int client_port,
                        const char *qname, uint16_t qclass, uint16_t qtype,
                        uint8_t rcode, bool has_edns, bool dnssec_ok) {
    (void)action; (void)client_ip; (void)client_port; (void)qname;
    (void)qclass; (void)qtype; (void)rcode; (void)has_edns; (void)dnssec_ok;
}

void dec_tcp_clients(void) {}
void inc_tcp_clients(void) {}

size_t resolve_ip_port_to_sockaddr(const char *ip, int port, struct sockaddr_storage *out) {
    (void)ip; (void)port; (void)out; return 0;
}

// ----------------------------------------------------------------------------
// RFC 4592 §2.2.1 / §3.3.2 wildcard "golden" test.
// Unlike test_all_rr_types_and_resolution() (which only checks RCODE and
// ANCOUNT >= N), this parses the response and checks owner names, RDATA, the
// AA flag and section placement against the outcomes RFC 4592 prescribes.
// ----------------------------------------------------------------------------
typedef struct {
    char name[256];
    uint16_t type;
    uint32_t ttl;        // for OPT: extended RCODE | version | flags
    size_t rdoff, rdlen;
    int sect;            // 1 = ANSWER, 2 = AUTHORITY, 3 = ADDITIONAL
} gr_rr_t;

typedef struct {
    const uint8_t *msg;
    size_t len;
    uint8_t rcode;
    bool aa;
    uint16_t counts[3];
    gr_rr_t rr[64];
    int nrr;
} gr_resp_t;

// Decodes a (possibly compressed) name at `off`; returns offset after it in the
// original position, or 0 on malformed input. Output has a trailing dot, e.g. "host3.example."
static size_t gr_read_name(const uint8_t *m, size_t len, size_t off, char *out, size_t cap) {
    size_t o = 0, next = 0;
    int jumps = 0;
    bool jumped = false;
    while (1) {
        if (off >= len) return 0;
        uint8_t l = m[off];
        if ((l & 0xC0) == 0xC0) {
            if (off + 1 >= len || ++jumps > 16) return 0;
            if (!jumped) next = off + 2;
            jumped = true;
            off = (size_t)(((l & 0x3F) << 8) | m[off + 1]);
            continue;
        }
        if (l == 0) { if (!jumped) next = off + 1; break; }
        if ((l & 0xC0) != 0 || off + 1 + l > len || o + l + 2 > cap) return 0;
        memcpy(out + o, m + off + 1, l); o += l; out[o++] = '.';
        off += 1u + l;
    }
    if (o == 0) { out[o++] = '.'; }
    out[o] = '\0';
    return next;
}

static bool gr_parse(const uint8_t *m, size_t len, gr_resp_t *r) {
    memset(r, 0, sizeof(*r));
    if (len < 12) return false;
    r->msg = m; r->len = len;
    r->rcode = m[3] & 0x0F;
    r->aa = (m[2] & 0x04) != 0;
    uint16_t qd = (uint16_t)((m[4] << 8) | m[5]);
    r->counts[0] = (uint16_t)((m[6] << 8) | m[7]);
    r->counts[1] = (uint16_t)((m[8] << 8) | m[9]);
    r->counts[2] = (uint16_t)((m[10] << 8) | m[11]);
    size_t off = 12;
    char tmp[256];
    for (uint16_t i = 0; i < qd; i++) {
        off = gr_read_name(m, len, off, tmp, sizeof(tmp));
        if (!off || off + 4 > len) return false;
        off += 4;
    }
    for (int sect = 0; sect < 3; sect++) {
        for (uint16_t i = 0; i < r->counts[sect]; i++) {
            if (r->nrr >= 64) return false;
            gr_rr_t *rr = &r->rr[r->nrr++];
            off = gr_read_name(m, len, off, rr->name, sizeof(rr->name));
            if (!off || off + 10 > len) return false;
            rr->type = (uint16_t)((m[off] << 8) | m[off + 1]);
            rr->ttl = ((uint32_t)m[off + 4] << 24) | ((uint32_t)m[off + 5] << 16) |
                      ((uint32_t)m[off + 6] << 8) | m[off + 7];
            rr->rdlen = (size_t)((m[off + 8] << 8) | m[off + 9]);
            off += 10;
            if (off + rr->rdlen > len) return false;
            rr->rdoff = off;
            rr->sect = sect + 1;
            off += rr->rdlen;
        }
    }
    return true;
}

static int gr_count(const gr_resp_t *r, int sect, int type /* -1 = any */) {
    int n = 0;
    for (int i = 0; i < r->nrr; i++)
        if (r->rr[i].sect == sect && (type < 0 || r->rr[i].type == type)) n++;
    return n;
}

static const gr_rr_t *gr_first(const gr_resp_t *r, int sect, int type) {
    for (int i = 0; i < r->nrr; i++)
        if (r->rr[i].sect == sect && r->rr[i].type == type) return &r->rr[i];
    return NULL;
}

static struct {
    zone_arena_t arena;
    zone_db_entry_t entry;
    zone_db_entry_t *entries[1];
    char *acl[1];
    view_snapshot_t view;
    zone_db_snapshot_t snap;
    server_config_t cfg;
    uint8_t res[4096];
} g_gr;

static void gr_setup(const char *origin, const char *zone_text) {
    memset(&g_gr, 0, sizeof(g_gr));
    zone_arena_init(&g_gr.arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = origin,
                            .is_standalone_mode = true, .err_out = &err };
    // parse_zone_fast() keeps pointers into its input (zero-copy), so the text must
    // live as long as the arena: give it arena lifetime instead of free()ing it.
    char *buf = arena_strdup(&g_gr.arena, zone_text);
    assert(buf != NULL);
    assert(parse_zone_fast(buf, strlen(buf), &g_gr.arena, &ctx) >= 0);
    assert(build_zone_index(&g_gr.arena, true) == 0);
    strncpy(g_gr.entry.domain, origin, sizeof(g_gr.entry.domain) - 1);
    atomic_store_explicit(&g_gr.entry.rcu.active, &g_gr.arena, memory_order_release);
    g_gr.entries[0] = &g_gr.entry;
    g_gr.acl[0] = (char *)"any";
    g_gr.view.name = "default";
    g_gr.view.entries = g_gr.entries;
    g_gr.view.zone_count = 1;
    g_gr.view.match_clients = g_gr.acl;
    g_gr.view.match_clients_count = 1;
    g_gr.snap.views = &g_gr.view;
    g_gr.snap.view_count = 1;
}

static void gr_query_raw(const uint8_t *req, size_t req_len, const char *qname, uint16_t qtype,
                         const char *client_ip, bool is_tcp, gr_resp_t *out);

static void gr_query_raw(const uint8_t *req, size_t req_len, const char *qname, uint16_t qtype,
                         const char *client_ip, bool is_tcp, gr_resp_t *out) {
    compress_ctx_t comp;
    memset(&comp, 0, sizeof(comp));
    compress_ctx_init_packet(&comp);
    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched = NULL;
    int n = process_dns_query_impl(req, req_len, g_gr.res, sizeof(g_gr.res), qname, qtype,
                                   client_ip, &comp, is_tcp, &rrl_out,
                                   &g_gr.snap, &g_gr.cfg, &matched);
    assert(n >= DNS_HEADER_SIZE);
    assert(gr_parse(g_gr.res, (size_t)n, out));
    assert(g_gr.res[0] == 0x45 && g_gr.res[1] == 0x92);   // ID echoed
}


static void dump_resp(const gr_resp_t *r) {
    fprintf(stderr, "  response: rcode=%d aa=%d tc=%d counts an=%d ns=%d ar=%d\n", r->rcode, r->aa, (r->msg[2] & 0x02) != 0, r->counts[0], r->counts[1], r->counts[2]);
    for (int i = 0; i < r->nrr; i++) fprintf(stderr, "    sect%d %-40s type %u ttl %u\n", r->rr[i].sect, r->rr[i].name, r->rr[i].type, r->rr[i].ttl);
}
#define CHECK(r, cond) do { if (!(cond)) { fprintf(stderr, "CHECK failed at line %d: %s\n", __LINE__, #cond); dump_resp(r); assert(0); } } while (0)

/* Raw request builder ------------------------------------------------------------------------------- */
typedef struct { uint8_t b[4096]; size_t n; } req_t;
static void put16(req_t *q, uint16_t v) { q->b[q->n++] = (uint8_t)(v >> 8); q->b[q->n++] = (uint8_t)v; }
static void put32(req_t *q, uint32_t v) { put16(q, (uint16_t)(v >> 16)); put16(q, (uint16_t)v); }
static void put_name(req_t *q, const char *name) {
    for (const char *p = name; *p; ) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0) break;
        q->b[q->n++] = (uint8_t)l; memcpy(q->b + q->n, p, l); q->n += l;
        p += l + (dot ? 1 : 0);
    }
    q->b[q->n++] = 0;
}
static void put_hdr(req_t *q, uint16_t id, uint16_t flags, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
    q->n = 0; put16(q, id); put16(q, flags); put16(q, qd); put16(q, an); put16(q, ns); put16(q, ar);
}
static void put_question(req_t *q, const char *name, uint16_t type, uint16_t cls) { put_name(q, name); put16(q, type); put16(q, cls); }
static void put_opt(req_t *q, uint8_t ext_rcode, uint8_t version, uint16_t flags, const uint8_t *opts, size_t olen) {
    q->b[q->n++] = 0; put16(q, 41); put16(q, 4096); q->b[q->n++] = ext_rcode; q->b[q->n++] = version; put16(q, flags);
    put16(q, (uint16_t)olen); if (olen) { memcpy(q->b + q->n, opts, olen); q->n += olen; }
}
static void ask(const req_t *q, const char *qname, uint16_t qtype, const char *ip, bool tcp, gr_resp_t *r) {
    gr_query_raw(q->b, q->n, qname, qtype, ip, tcp, r);
}

// Returns pointer to the COOKIE option payload in the response's OPT RR (NULL if absent).
static const uint8_t *gr_find_cookie(const gr_resp_t *r, size_t *len_out, uint32_t *opt_ttl_out) {
    for (int i = 0; i < r->nrr; i++) {
        if (r->rr[i].sect != 3 || r->rr[i].type != 41) continue;
        if (opt_ttl_out) *opt_ttl_out = r->rr[i].ttl;
        size_t off = r->rr[i].rdoff, end = off + r->rr[i].rdlen;
        while (off + 4 <= end) {
            uint16_t code = (uint16_t)((r->msg[off] << 8) | r->msg[off + 1]);
            uint16_t len = (uint16_t)((r->msg[off + 2] << 8) | r->msg[off + 3]);
            if (off + 4 + len > end) return NULL;
            if (code == 10) { *len_out = len; return r->msg + off + 4; }
            off += 4 + (size_t)len;
        }
    }
    return NULL;
}


/* -------------------------------------------------------------------------------------------------- */
static void put_soa_rr(req_t *q, const char *owner, uint32_t serial) {
    put_name(q, owner); put16(q, 6); put16(q, 1); put32(q, 60);
    size_t rl = q->n; put16(q, 0); size_t rs = q->n;
    put_name(q, "ns.example."); put_name(q, "h.example."); put32(q, serial); put32(q, 2); put32(q, 3); put32(q, 4); put32(q, 5);
    q->b[rl] = (uint8_t)((q->n - rs) >> 8); q->b[rl + 1] = (uint8_t)(q->n - rs);
}

static const char *ZONE_TXT =
    "$ORIGIN example.\n$TTL 60\n@ SOA ns h 5 2 3 4 5\n@ NS ns\nns A 192.0.2.1\nwww A 192.0.2.10\n";

static void test_protocol_anomalies(void) {
    printf("[TEST] Query engine: RFC 6891 BADVERS, RFC 9619 FORMERR, NOTIMP opcodes, foreign classes...\n");
    gr_setup("example.", ZONE_TXT);
    gr_resp_t r;
    req_t q;

    /* RFC 6891 6.1.3: unsupported EDNS version -> BADVERS (extended RCODE 16), OPT advertises version 0 */
    put_hdr(&q, 0x4592, 0x0100, 1, 0, 0, 1); put_question(&q, "www.example.", 1, 1); put_opt(&q, 0, 1, 0, NULL, 0);
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0 && r.counts[0] == 0 && r.counts[2] == 1);
    const gr_rr_t *opt = gr_first(&r, 3, 41);
    CHECK(&r, opt && (opt->ttl >> 24) == 1 && ((opt->ttl >> 16) & 0xFF) == 0);      /* ext-RCODE 1 (=> 16), version 0 */

    /* RFC 9619: a QUERY with QDCOUNT > 1 is FORMERR; NOTIFY/UPDATE need exactly one question */
    put_hdr(&q, 0x4592, 0x0100, 2, 0, 0, 0); put_question(&q, "www.example.", 1, 1); put_question(&q, "ns.example.", 1, 1);
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 1 && r.counts[0] == 0);
    put_hdr(&q, 0x4592, 0x2800, 0, 0, 0, 0);                                      /* UPDATE, QDCOUNT 0 */
    ask(&q, "example.", 6, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 1);
    put_hdr(&q, 0x4592, 0x2000, 0, 0, 0, 0);                                      /* NOTIFY, QDCOUNT 0 */
    ask(&q, "example.", 6, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 1);
    /* a question that is cut off in the middle of a label */
    put_hdr(&q, 0x4592, 0x0100, 1, 0, 0, 0); q.b[q.n++] = 3; q.b[q.n++] = 'w';
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 1);
    /* RFC 5936: AXFR has no UDP transport */
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 0, 0); put_question(&q, "example.", 252, 1);
    ask(&q, "example.", 252, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 1);

    /* RFC 1035 opcodes other than QUERY/NOTIFY/UPDATE: IQUERY(1), STATUS(2), unassigned(3,6..15) -> NOTIMP */
    for (int op = 1; op <= 15; op++) {
        if (op == 4 || op == 5) continue;
        put_hdr(&q, 0x4592, (uint16_t)(op << 11), 1, 0, 0, 0); put_question(&q, "www.example.", 1, 1);
        ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
        CHECK(&r, r.rcode == 4 && r.counts[0] == 0);
    }

    /* Foreign classes are not served: CH / HS -> REFUSED; QCLASS=ANY (*) is answered from the IN data */
    put_hdr(&q, 0x4592, 0x0100, 1, 0, 0, 0); put_question(&q, "version.bind.", 16, 3);
    ask(&q, "version.bind.", 16, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 5 && r.counts[0] == 0);
    put_hdr(&q, 0x4592, 0x0100, 1, 0, 0, 0); put_question(&q, "www.example.", 1, 4);
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 5);
    put_hdr(&q, 0x4592, 0x0100, 1, 0, 0, 0); put_question(&q, "www.example.", 1, 255);
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 1) == 1);

    /* RFC 1995 2: IXFR over UDP. Client already current -> the single SOA; older client -> SOA + TC so it retries via TCP */
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 1, 0); put_question(&q, "example.", 251, 1); put_soa_rr(&q, "example.", 5);
    ask(&q, "example.", 251, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0 && r.aa && r.counts[0] == 1 && gr_count(&r, 1, 6) == 1 && (r.msg[2] & 0x02) == 0);
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 1, 0); put_question(&q, "example.", 251, 1); put_soa_rr(&q, "example.", 1);
    ask(&q, "example.", 251, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 6) == 1 && (r.msg[2] & 0x02) != 0);
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 0, 0); put_question(&q, "example.", 251, 1);      /* IXFR without a client SOA */
    ask(&q, "example.", 251, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0 || r.rcode == 1);

    /* RFC 7873: a COOKIE that cannot be bound to a (parsable) client address is not answered with a server cookie */
    uint8_t opt_ck[12] = { 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    put_hdr(&q, 0x4592, 0x0100, 1, 0, 0, 1); put_question(&q, "www.example.", 1, 1); put_opt(&q, 0, 0, 0, opt_ck, sizeof(opt_ck));
    ask(&q, "www.example.", 1, "not-an-ip", false, &r);
    size_t clen; uint32_t ottl;
    CHECK(&r, r.rcode == 0 && gr_find_cookie(&r, &clen, &ottl) == NULL);
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);                                /* same request, valid address */
    const uint8_t *ck = gr_find_cookie(&r, &clen, &ottl);
    CHECK(&r, r.rcode == 0 && ck && clen == 24);
    zone_arena_destroy(&g_gr.arena);
    printf("  -> protocol anomaly handling passed.\n");
}

static void test_expired_secondary_zone(void) {
    printf("[TEST] Query engine: SOA EXPIRE exceeded -> SERVFAIL (or serve-stale)...\n");
    gr_setup("example.", ZONE_TXT);
    gr_resp_t r;
    req_t q;
    put_hdr(&q, 0x4592, 0x0100, 1, 0, 0, 0); put_question(&q, "www.example.", 1, 1);

    atomic_store(&g_gr.entry.expire, 100);
    atomic_store(&g_gr.entry.last_successful_transfer, time(NULL) - 50);                  /* within EXPIRE */
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 1) == 1);

    atomic_store(&g_gr.entry.last_successful_transfer, time(NULL) - 1000);                /* long past EXPIRE */
    g_gr.cfg.serve_stale = false;
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 2 && r.counts[0] == 0);                                          /* RFC 1035 3.3.13 */
    g_gr.cfg.serve_stale = true;                                                          /* RFC 8767 serve-stale */
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 1) == 1);
    atomic_store(&g_gr.entry.last_successful_transfer, 0);                                /* never transferred: not "expired" */
    g_gr.cfg.serve_stale = false;
    ask(&q, "www.example.", 1, "192.0.2.100", false, &r);
    CHECK(&r, r.rcode == 0);
    zone_arena_destroy(&g_gr.arena);
    printf("  -> expired-zone handling passed.\n");
}

/* ---------------------------------------------------------------- NOTIFY + TSIG */
static server_config_t *notify_cfg(const char *zone_stmt) {
    char text[2048];
    snprintf(text, sizeof(text),
        "options { allow-program-zones yes; };\n"
        "key \"k1\" { algorithm hmac-sha256; secret \"c2VjcmV0LWtleS1vbmUtMTIzNDU2Nzg5MDEyMzQ1Ng==\"; };\n"
        "key \"k2\" { algorithm hmac-sha256; secret \"c2VjcmV0LWtleS10d28tMTIzNDU2Nzg5MDEyMzQ1Ng==\"; };\n%s\n", zone_stmt);
    server_config_t *c = calloc(1, sizeof(*c));
    assert(c && parse_named_conf(text, c) == 0);
    return c;
}

static tsig_key_t *cfg_key(server_config_t *c, const char *name) {
    for (tsig_key_t *k = c->keys; k; k = k->next) if (strcmp(k->name, name) == 0) return k;
    return NULL;
}

static void build_notify(req_t *q, const char *zone, tsig_key_t *sign_with) {
    put_hdr(q, 0x4592, 0x2400, 1, 0, 0, 0);                    /* NOTIFY, AA */
    put_question(q, zone, 6, 1);
    if (sign_with) {
        size_t len = q->n;
        assert(tsig_sign_packet(q->b, &len, sizeof(q->b), sign_with, 0, NULL, NULL, NULL, 0, false) == 0);
        q->n = len;
    }
}

static void test_notify_authorization(void) {
    printf("[TEST] Query engine: RFC 1996 NOTIFY authorization with RFC 8945 TSIG...\n");
    static const char *MASTER = "192.0.2.100";
    static const char *STRANGER = "203.0.113.9";
    gr_resp_t r;
    req_t q;

    /* --- secondary zone that requires TSIG key k1 from master 192.0.2.100 --- */
    server_config_t *cfg = notify_cfg("zone \"example.\" { type slave; file \"x\"; masters { 192.0.2.100; }; tsig-key \"k1\"; };");
    tsig_key_t *k1 = cfg_key(cfg, "k1"), *k2 = cfg_key(cfg, "k2");
    assert(k1 && k2);
    gr_setup("example.", ZONE_TXT);
    g_gr.cfg = *cfg;
    g_gr.view.name = "__default__";     /* implicit view the config parser creates for view-less configs */

    /* valid TSIG from the master: accepted, AA set, refresh scheduled, response signed with the same key */
    atomic_store(&g_gr.entry.refresh_now, false);
    build_notify(&q, "example.", k1);
    ask(&q, "example.", 6, MASTER, false, &r);
    CHECK(&r, r.rcode == 0 && r.aa && (r.msg[2] & 0x80));
    const gr_rr_t *tsig = gr_first(&r, 3, 250);
    CHECK(&r, tsig && strcasecmp(tsig->name, "k1.") == 0);
    CHECK(&r, atomic_load(&g_gr.entry.refresh_now) == true);
    /* the response's TSIG verifies against the request MAC (RFC 8945 5.3.1) */
    {
        uint8_t req_mac[64], resp_mac[64];
        size_t req_mac_len = 0, resp_mac_len = 0;
        req_t q2 = q;
        assert(tsig_verify_packet(q2.b, q2.n, k1, NULL, 0, NULL, 0, false, req_mac, &req_mac_len) == 0);
        assert(tsig_verify_packet(g_gr.res, r.len, k1, req_mac, req_mac_len, NULL, 0, false, resp_mac, &resp_mac_len) == 0);
    }

    /* the same TSIG-signed NOTIFY from an address that is not a master: NOTAUTH, no refresh */
    atomic_store(&g_gr.entry.refresh_now, false);
    build_notify(&q, "example.", k1);
    ask(&q, "example.", 6, STRANGER, false, &r);
    CHECK(&r, r.rcode == 9 && !atomic_load(&g_gr.entry.refresh_now));

    /* right address but no TSIG although the zone requires one: NOTAUTH */
    build_notify(&q, "example.", NULL);
    ask(&q, "example.", 6, MASTER, false, &r);
    CHECK(&r, r.rcode == 9 && !atomic_load(&g_gr.entry.refresh_now));

    /* signed with a key that is known but not the zone's key */
    build_notify(&q, "example.", k2);
    ask(&q, "example.", 6, MASTER, false, &r);
    CHECK(&r, r.rcode == 9 && !atomic_load(&g_gr.entry.refresh_now));

    /* corrupted MAC */
    build_notify(&q, "example.", k1);
    q.b[q.n - 30] ^= 0x01;                                    /* inside the TSIG RDATA (MAC) */
    ask(&q, "example.", 6, MASTER, false, &r);
    CHECK(&r, r.rcode == 9 && !atomic_load(&g_gr.entry.refresh_now));

    /* MQTYPE-Query is meaningless in a NOTIFY */
    {
        uint8_t mq[4] = { 0xFD, 0x4E, 0, 0 };     /* placeholder option code; only shape matters for robustness */
        put_hdr(&q, 0x4592, 0x2400, 1, 0, 0, 1); put_question(&q, "example.", 6, 1); put_opt(&q, 0, 0, 0, mq, sizeof(mq));
        ask(&q, "example.", 6, MASTER, false, &r);
        CHECK(&r, r.rcode == 9 || r.rcode == 1 || r.rcode == 5);
    }
    free_server_config_fields(cfg); free(cfg);
    zone_arena_destroy(&g_gr.arena);

    /* --- secondary zone without TSIG: master address alone authorizes; strangers are REFUSED --- */
    cfg = notify_cfg("zone \"example.\" { type slave; file \"x\"; masters { 192.0.2.100; }; };");
    gr_setup("example.", ZONE_TXT);
    g_gr.cfg = *cfg;
    g_gr.view.name = "__default__";     /* implicit view the config parser creates for view-less configs */
    atomic_store(&g_gr.entry.refresh_now, false);
    build_notify(&q, "example.", NULL);
    ask(&q, "example.", 6, MASTER, false, &r);
    CHECK(&r, r.rcode == 0 && r.aa && atomic_load(&g_gr.entry.refresh_now));
    atomic_store(&g_gr.entry.refresh_now, false);
    ask(&q, "example.", 6, STRANGER, false, &r);
    CHECK(&r, r.rcode == 5 && !atomic_load(&g_gr.entry.refresh_now));
    /* RFC 8945 5.4: a TSIG that fails verification is fatal even when the source address is an authorized master */
    tsig_key_t *bad = calloc(1, sizeof(*bad));
    bad->name = strdup("nokey."); bad->algorithm = strdup("hmac-sha256");
    memcpy(bad->secret_decoded, "0123456789abcdef0123456789abcdef", 32); bad->secret_decoded_len = 32;
    build_notify(&q, "example.", bad);
    ask(&q, "example.", 6, MASTER, false, &r);
    CHECK(&r, r.rcode == 9 && !atomic_load(&g_gr.entry.refresh_now));
    free(bad->name); free(bad->algorithm); free(bad);
    free_server_config_fields(cfg); free(cfg);
    zone_arena_destroy(&g_gr.arena);

    /* --- zones that cannot be notified: forward and program zones answer NOTIMP --- */
    static const char *const zs[] = {
        "zone \"example.\" { type forward; forwarders { 192.0.2.53; }; };",
        "zone \"example.\" { type program; program \"/bin/true\"; };",
    };
    for (size_t i = 0; i < 2; i++) {
        cfg = notify_cfg(zs[i]);
        gr_setup("example.", ZONE_TXT);
        g_gr.cfg = *cfg;
    g_gr.view.name = "__default__";     /* implicit view the config parser creates for view-less configs */
        build_notify(&q, "example.", NULL);
        ask(&q, "example.", 6, MASTER, false, &r);
        CHECK(&r, r.rcode == 4);
        free_server_config_fields(cfg); free(cfg);
        zone_arena_destroy(&g_gr.arena);
    }
    printf("  -> NOTIFY authorization matrix passed.\n");
}

static void test_rfc8482_minimal_any_synthesis(void) {
    printf("[TEST] Query Engine: RFC 8482 minimal-any ANY->HINFO synthesis...\n");
    static const char *zone_any =
        "$ORIGIN any.example.\n"
        "$TTL 3600\n"
        "@ IN SOA ns1.any.example. admin.any.example. 100 7200 3600 1209600 300\n"
        "@ IN NS ns1.any.example.\n"
        "ns1 IN A 192.0.2.1\n"
        "host IN A 192.0.2.53\n"
        "host IN TXT \"hello world\"\n"
        "alias IN CNAME host.any.example.\n";

    gr_setup("any.example.", zone_any);
    g_gr.cfg.minimal_any = true;
    g_gr.cfg.minimal_any_ttl = 300;

    req_t q;
    gr_resp_t r;

    // 1. DO=0 ANY query on "host.any.example." -> synthesizes HINFO "RFC8482"
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 0, 0);
    put_question(&q, "host.any.example.", 255, 1); // ANY
    ask(&q, "host.any.example.", 255, "192.0.2.10", false, &r);
    CHECK(&r, r.rcode == 0 && r.aa && r.counts[0] == 1);
    const gr_rr_t *hinfo = gr_first(&r, 1, 13); // HINFO in ANSWER
    assert(hinfo != NULL);
    assert(hinfo->ttl == 300);

    // 2. ANY query on CNAME record "alias.any.example." -> CNAME followed, no HINFO synthesis
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 0, 0);
    put_question(&q, "alias.any.example.", 255, 1);
    ask(&q, "alias.any.example.", 255, "192.0.2.10", false, &r);
    CHECK(&r, r.rcode == 0 && r.aa);
    const gr_rr_t *cname = gr_first(&r, 1, 5); // CNAME in ANSWER
    assert(cname != NULL);

    // 3. ANY query on apex "any.example."
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 0, 0);
    put_question(&q, "any.example.", 255, 1);
    ask(&q, "any.example.", 255, "192.0.2.10", false, &r);
    CHECK(&r, r.rcode == 0 && r.aa);

    zone_arena_destroy(&g_gr.arena);
    printf("  -> RFC 8482 minimal-any synthesis passed.\n");
}

static void test_sibling_zone_additional_glue_and_limits(void) {
    printf("[TEST] Query Engine: Sibling zone additional search & alternate hash...\n");
    zone_arena_t arena_prim, arena_sib;
    zone_arena_init(&arena_prim);
    zone_arena_init(&arena_sib);

    parse_error_t err = {0};
    parse_context_t ctx1 = { .base_dir = ".", .default_origin = "prim.example.", .is_standalone_mode = true, .err_out = &err };
    const char *prim_text =
        "$ORIGIN prim.example.\n"
        "$TTL 3600\n"
        "@ IN SOA ns1.sib.example. admin.prim.example. 100 7200 3600 1209600 300\n"
        "@ IN NS ns1.sib.example.\n"
        "sub IN NS ns1.sib.example.\n";
    char *p_buf = arena_strdup(&arena_prim, prim_text);
    parse_zone_fast(p_buf, strlen(p_buf), &arena_prim, &ctx1);
    build_zone_index(&arena_prim, true);

    parse_context_t ctx2 = { .base_dir = ".", .default_origin = "sib.example.", .is_standalone_mode = true, .err_out = &err };
    const char *sib_text =
        "$ORIGIN sib.example.\n"
        "$TTL 3600\n"
        "@ IN SOA ns1.sib.example. admin.sib.example. 100 7200 3600 1209600 300\n"
        "@ IN NS ns1.sib.example.\n"
        "ns1 IN A 198.51.100.1\n"
        "ns1 IN AAAA 2001:db8::1\n";
    char *s_buf = arena_strdup(&arena_sib, sib_text);
    parse_zone_fast(s_buf, strlen(s_buf), &arena_sib, &ctx2);
    build_zone_index(&arena_sib, true);

    zone_db_entry_t entry_prim, entry_sib;
    memset(&entry_prim, 0, sizeof(entry_prim));
    memset(&entry_sib, 0, sizeof(entry_sib));
    strlcpy(entry_prim.domain, "prim.example.", sizeof(entry_prim.domain));
    strlcpy(entry_sib.domain, "sib.example.", sizeof(entry_sib.domain));
    atomic_store_explicit(&entry_prim.rcu.active, &arena_prim, memory_order_release);
    atomic_store_explicit(&entry_sib.rcu.active, &arena_sib, memory_order_release);

    zone_db_entry_t *entries[2] = { &entry_prim, &entry_sib };
    char *acl_any[1] = { (char *)"any" };
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    view.entries = entries;
    view.zone_count = 2;
    view.match_clients = acl_any;
    view.match_clients_count = 1;

    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;

    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.additional_from_auth = ADDITIONAL_AUTH_YES;

    uint8_t res[4096];
    compress_ctx_t comp;
    memset(&comp, 0, sizeof(comp));
    compress_ctx_init_packet(&comp);
    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched = NULL;

    req_t q;
    put_hdr(&q, 0x4592, 0x0000, 1, 0, 0, 0);
    put_question(&q, "sub.prim.example.", 1, 1);

    int n = process_dns_query_impl(q.b, q.n, res, sizeof(res), "sub.prim.example.", 1,
                                   "192.0.2.10", &comp, false, &rrl_out,
                                   &snap, &cfg, &matched);
    assert(n >= DNS_HEADER_SIZE);
    gr_resp_t r;
    assert(gr_parse(res, (size_t)n, &r));
    CHECK(&r, r.counts[2] >= 1);

    zone_arena_destroy(&arena_prim);
    zone_arena_destroy(&arena_sib);
    printf("  -> Sibling zone additional glue passed.\n");
}

static void test_eff_ttl_resolution_and_clamp(void) {
    printf("[TEST] Query Engine: Effective TTL resolution & tinydns clamp...\n");
    dns_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.ttl_value = 86400;
    rec.tinydns_ttd = 0;

    uint32_t eff_ttl = 0;
    bool valid = tinydns_record_currently_valid(&rec, 0, NULL, NULL, NULL, &eff_ttl);
    assert(valid == true);
    assert(eff_ttl == 86400);

    // Countdown TTL
    rec.tinydns_ttd = 1000000;
    rec.tinydns_ttl_countdown = true;
    valid = tinydns_record_currently_valid(&rec, 999900, NULL, NULL, NULL, &eff_ttl);
    assert(valid == true);
    assert(eff_ttl == 100);

    // Expired TTL
    valid = tinydns_record_currently_valid(&rec, 1000001, NULL, NULL, NULL, &eff_ttl);
    assert(valid == false);

    printf("  -> Effective TTL resolution & tinydns clamp passed.\n");
}

int main(void) {
    printf("=== Starting Query Engine Protocol Tests ===\n");
    test_protocol_anomalies();
    test_expired_secondary_zone();
    test_notify_authorization();
    test_rfc8482_minimal_any_synthesis();
    test_sibling_zone_additional_glue_and_limits();
    test_eff_ttl_resolution_and_clamp();
    printf("=== All Query Engine Protocol Tests PASSED ===\n");
    return 0;
}
