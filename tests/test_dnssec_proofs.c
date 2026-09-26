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

static void build_dns_query(uint8_t *buf, size_t *out_len, uint16_t txid, const char *qname, uint16_t qtype, bool dnssec_ok) {
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
    buf[2] = 0x01; // RD=1
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
    buf[6] = 0; buf[7] = 0;
    buf[8] = 0; buf[9] = 0;
    buf[10] = 0; buf[11] = dnssec_ok ? 0x01 : 0x00; // ARCOUNT

    long wlen = write_uncompressed_name(buf, 12, 256, qname);
    assert(wlen > 0);
    size_t off = 12 + (size_t)wlen;
    buf[off++] = (uint8_t)(qtype >> 8);
    buf[off++] = (uint8_t)(qtype & 0xFF);
    buf[off++] = 0x00;
    buf[off++] = 0x01; // IN class

    if (dnssec_ok) {
        buf[off++] = 0x00; // Root
        buf[off++] = 0x00; buf[off++] = 41; // OPT
        buf[off++] = 0x10; buf[off++] = 0x00; // UDP 4096
        buf[off++] = 0x00; buf[off++] = 0x00;
        buf[off++] = 0x80; buf[off++] = 0x00; // DO=1
        buf[off++] = 0x00; buf[off++] = 0x00;
    }
    *out_len = off;
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

static void gr_query(const char *qname, uint16_t qtype, bool dnssec_ok, gr_resp_t *out) {
    uint8_t req[512];
    size_t req_len = 0;
    build_dns_query(req, &req_len, 0x4592, qname, qtype, dnssec_ok);
    gr_query_raw(req, req_len, qname, qtype, "192.0.2.100", false, out);
}

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

/* ------------------------------------------------------------------------------------------------
 * DNSSEC negative-response proofs, checked against the worked examples of
 *   RFC 5155 Appendix A/B (NSEC3, opt-out chain, salt aabbccdd, 12 iterations)
 *   RFC 4035 Appendix A/B (NSEC)
 * Both zones are the RFCs' example zones. Signatures are dummies (the server serves pre-signed data, it
 * never validates), so what is asserted is WHICH records the server selects: the set of NSEC/NSEC3 owners in
 * the AUTHORITY section. The hashed owner names below were computed by an independent SHA-1/base32hex
 * implementation and match the values published in RFC 5155.
 * ---------------------------------------------------------------------------------------------- */
static const char *ZONE_NSEC3 =
    "$ORIGIN example.\n"
    "$TTL 3600\n"
    "example. SOA ns1.example. bugs.x.w.example. 1 3600 600 604800 3600\n"
    "example. NS ns1.example.\n"
    "example. NS ns2.example.\n"
    "example. MX 1 xx.example.\n"
    "example. DNSKEY 256 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. NSEC3PARAM 1 0 12 aabbccdd\n"
    "a.example. NS ns1.a.example.\n"
    "a.example. NS ns2.a.example.\n"
    "a.example. DS 58470 5 1 3079F1593EBAD6DC121E202A8B766A6A4837206C\n"
    "ns1.a.example. A 192.0.2.5\n"
    "ns2.a.example. A 192.0.2.6\n"
    "ai.example. A 192.0.2.9\n"
    "ai.example. HINFO \"KLH-10\" \"ITS\"\n"
    "ai.example. AAAA 2001:db8::f00:baa9\n"
    "c.example. NS ns1.c.example.\n"
    "c.example. NS ns2.c.example.\n"
    "ns1.c.example. A 192.0.2.7\n"
    "ns2.c.example. A 192.0.2.8\n"
    "ns1.example. A 192.0.2.1\n"
    "ns2.example. A 192.0.2.2\n"
    "w.example. MX 1 ai.example.\n"
    "*.w.example. MX 1 ai.example.\n"
    "x.w.example. MX 1 xx.example.\n"
    "x.y.w.example. MX 1 xx.example.\n"
    "xx.example. A 192.0.2.10\n"
    "xx.example. HINFO \"KLH-10\" \"TOPS-20\"\n"
    "xx.example. AAAA 2001:db8::f00:baaa\n"
    "example. RRSIG SOA 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG NS 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG MX 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG DNSKEY 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG NSEC3PARAM 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "a.example. RRSIG DS 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ai.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ai.example. RRSIG HINFO 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ai.example. RRSIG AAAA 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ns1.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ns2.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "w.example. RRSIG MX 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "*.w.example. RRSIG MX 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "x.w.example. RRSIG MX 13 3 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "x.y.w.example. RRSIG MX 13 4 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "xx.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "xx.example. RRSIG HINFO 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "xx.example. RRSIG AAAA 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr SOA NS MX DNSKEY NSEC3PARAM RRSIG\n"
    "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. NSEC3 1 1 12 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG\n"
    "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "2vptu5timamqttgl4luu9kg21e0aor3s.example. NSEC3 1 1 12 aabbccdd 35mthgpgcu1qg68fab165klnsnk3dpvl MX RRSIG\n"
    "2vptu5timamqttgl4luu9kg21e0aor3s.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "35mthgpgcu1qg68fab165klnsnk3dpvl.example. NSEC3 1 1 12 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG\n"
    "35mthgpgcu1qg68fab165klnsnk3dpvl.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "b4um86eghhds6nea196smvmlo4ors995.example. NSEC3 1 1 12 aabbccdd gjeqe526plbf1g8mklp59enfd789njgi MX RRSIG\n"
    "b4um86eghhds6nea196smvmlo4ors995.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "gjeqe526plbf1g8mklp59enfd789njgi.example. NSEC3 1 1 12 aabbccdd ji6neoaepv8b5o6k4ev33abha8ht9fgc A HINFO AAAA RRSIG\n"
    "gjeqe526plbf1g8mklp59enfd789njgi.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. NSEC3 1 1 12 aabbccdd k8udemvp1j2f7eg6jebps17vp3n8i58h\n"
    "ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "k8udemvp1j2f7eg6jebps17vp3n8i58h.example. NSEC3 1 1 12 aabbccdd q04jkcevqvmu85r014c7dkba38o0ji5r MX RRSIG\n"
    "k8udemvp1j2f7eg6jebps17vp3n8i58h.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "q04jkcevqvmu85r014c7dkba38o0ji5r.example. NSEC3 1 1 12 aabbccdd r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG\n"
    "q04jkcevqvmu85r014c7dkba38o0ji5r.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. NSEC3 1 1 12 aabbccdd t644ebqk9bibcna874givr6joj62mlhv MX RRSIG\n"
    "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "t644ebqk9bibcna874givr6joj62mlhv.example. NSEC3 1 1 12 aabbccdd 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom A HINFO AAAA RRSIG\n"
    "t644ebqk9bibcna874givr6joj62mlhv.example. RRSIG NSEC3 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n";

static const char *ZONE_NSEC =
    "$ORIGIN example.\n"
    "$TTL 3600\n"
    "@ SOA ns1 bugs.x.w.example. 1081539377 3600 300 3600000 3600\n"
    "@ NS ns1\n"
    "@ NS ns2\n"
    "@ MX 1 xx\n"
    "@ DNSKEY 256 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "a NS ns1.a\n"
    "a NS ns2.a\n"
    "a DS 57855 5 1 B6DCD485719ADCA18E5F3D48A2331627FDD3636B\n"
    "ns1.a A 192.0.2.5\n"
    "ns2.a A 192.0.2.6\n"
    "ai A 192.0.2.9\n"
    "ai HINFO \"KLH-10\" \"ITS\"\n"
    "ai AAAA 2001:db8::f00:baa9\n"
    "b NS ns1.b\n"
    "b NS ns2.b\n"
    "ns1.b A 192.0.2.7\n"
    "ns2.b A 192.0.2.8\n"
    "ns1 A 192.0.2.1\n"
    "ns2 A 192.0.2.2\n"
    "*.w MX 1 ai\n"
    "x.w MX 1 xx\n"
    "x.y.w MX 1 xx\n"
    "xx A 192.0.2.10\n"
    "xx HINFO \"KLH-10\" \"TOPS-20\"\n"
    "xx AAAA 2001:db8::f00:baaa\n"
    "example. NSEC a.example. NS SOA MX RRSIG NSEC DNSKEY\n"
    "a.example. NSEC ai.example. NS DS RRSIG NSEC\n"
    "ai.example. NSEC b.example. A HINFO AAAA RRSIG NSEC\n"
    "b.example. NSEC ns1.example. NS RRSIG NSEC\n"
    "ns1.example. NSEC ns2.example. A RRSIG NSEC\n"
    "ns2.example. NSEC *.w.example. A RRSIG NSEC\n"
    "*.w.example. NSEC x.w.example. MX RRSIG NSEC\n"
    "x.w.example. NSEC x.y.w.example. MX RRSIG NSEC\n"
    "x.y.w.example. NSEC xx.example. MX RRSIG NSEC\n"
    "xx.example. NSEC example. A HINFO AAAA RRSIG NSEC\n"
    "example. RRSIG SOA 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG NS 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG MX 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG DNSKEY 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "a.example. RRSIG DS 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ai.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ai.example. RRSIG HINFO 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ai.example. RRSIG AAAA 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ns1.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ns2.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "*.w.example. RRSIG MX 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "x.w.example. RRSIG MX 13 3 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "x.y.w.example. RRSIG MX 13 4 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "xx.example. RRSIG A 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "xx.example. RRSIG HINFO 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "xx.example. RRSIG AAAA 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "example. RRSIG NSEC 13 1 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "a.example. RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ai.example. RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "b.example. RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ns1.example. RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "ns2.example. RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "*.w.example. RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "x.w.example. RRSIG NSEC 13 3 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "x.y.w.example. RRSIG NSEC 13 4 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n"
    "xx.example. RRSIG NSEC 13 2 3600 20300101000000 20200101000000 12345 example. mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==\n";

/* RFC 5155 hashed owner labels (without ".example.") */
#define H_EXAMPLE  "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
#define H_NS1      "2t7b4g4vsa5smi47k61mv5bv1a22bojr"
#define H_XYW      "2vptu5timamqttgl4luu9kg21e0aor3s"
#define H_A        "35mthgpgcu1qg68fab165klnsnk3dpvl"
#define H_XW       "b4um86eghhds6nea196smvmlo4ors995"
#define H_AI       "gjeqe526plbf1g8mklp59enfd789njgi"
#define H_YW       "ji6neoaepv8b5o6k4ev33abha8ht9fgc"
#define H_W        "k8udemvp1j2f7eg6jebps17vp3n8i58h"
#define H_NS2      "q04jkcevqvmu85r014c7dkba38o0ji5r"
#define H_WILDW    "r53bq7cc2uvmubfu5ocmm6pers9tk9en"
#define H_XX       "t644ebqk9bibcna874givr6joj62mlhv"

static void dump_resp(const gr_resp_t *r) {
    fprintf(stderr, "  response: rcode=%d aa=%d counts an=%d ns=%d ar=%d\n", r->rcode, r->aa, r->counts[0], r->counts[1], r->counts[2]);
    for (int i = 0; i < r->nrr; i++) fprintf(stderr, "    sect%d %-60s type %u\n", r->rr[i].sect, r->rr[i].name, r->rr[i].type);
}
#define CHECK(r, cond) do { if (!(cond)) { fprintf(stderr, "CHECK failed at line %d: %s\n", __LINE__, #cond); dump_resp(r); assert(0); } } while (0)

static bool owner_matches(const char *have, const char *want, bool want_is_hash) {
    if (want_is_hash) {
        size_t l = strlen(want);
        return strncasecmp(have, want, l) == 0 && strcasecmp(have + l, ".example.") == 0;
    }
    return strcasecmp(have, want) == 0;
}

/* The set of owners of RRs of `type` in section `sect` must equal `want` (order-insensitive, no extras). */
static void expect_owner_set(const gr_resp_t *r, int sect, int type, const char *const *want, size_t n, bool hashed, const char *what) {
    size_t have_n = 0;
    for (int i = 0; i < r->nrr; i++) {
        if (r->rr[i].sect != sect || r->rr[i].type != type) continue;
        have_n++;
        bool found = false;
        for (size_t k = 0; k < n; k++) if (owner_matches(r->rr[i].name, want[k], hashed)) found = true;
        if (!found) { fprintf(stderr, "%s: unexpected type-%d owner %s\n", what, type, r->rr[i].name); dump_resp(r); assert(0); }
    }
    for (size_t k = 0; k < n; k++) {
        bool found = false;
        for (int i = 0; i < r->nrr; i++)
            if (r->rr[i].sect == sect && r->rr[i].type == type && owner_matches(r->rr[i].name, want[k], hashed)) found = true;
        if (!found) { fprintf(stderr, "%s: missing type-%d owner %s\n", what, type, want[k]); dump_resp(r); assert(0); }
    }
    if (have_n != n) { fprintf(stderr, "%s: expected %zu type-%d RRs, got %zu\n", what, n, type, have_n); dump_resp(r); assert(0); }
}
/* Like expect_owner_set(), but `extra` owners are tolerated (RFC-permitted surplus proof records). */
static void expect_owner_set_plus(const gr_resp_t *r, int sect, int type, const char *const *req, size_t nreq,
                                  const char *const *extra, size_t nextra, bool hashed, const char *what) {
    for (int i = 0; i < r->nrr; i++) {
        if (r->rr[i].sect != sect || r->rr[i].type != type) continue;
        bool ok = false;
        for (size_t k = 0; k < nreq; k++) if (owner_matches(r->rr[i].name, req[k], hashed)) ok = true;
        for (size_t k = 0; k < nextra; k++) if (owner_matches(r->rr[i].name, extra[k], hashed)) ok = true;
        if (!ok) { fprintf(stderr, "%s: unexpected type-%d owner %s\n", what, type, r->rr[i].name); dump_resp(r); assert(0); }
    }
    for (size_t k = 0; k < nreq; k++) {
        bool found = false;
        for (int i = 0; i < r->nrr; i++)
            if (r->rr[i].sect == sect && r->rr[i].type == type && owner_matches(r->rr[i].name, req[k], hashed)) found = true;
        if (!found) { fprintf(stderr, "%s: missing type-%d owner %s\n", what, type, req[k]); dump_resp(r); assert(0); }
    }
}
#define EXPECT_N3_PLUS(r, what, req_list, extra_list) do { \
    static const char *const rq_[] = req_list; static const char *const ex_[] = extra_list; \
    expect_owner_set_plus(r, 2, 50, rq_, sizeof(rq_) / sizeof(rq_[0]), ex_, sizeof(ex_) / sizeof(ex_[0]), true, what); } while (0)
#define EXPECT_N3(r, what, ...) do { static const char *const w_[] = { __VA_ARGS__ }; expect_owner_set(r, 2, 50, w_, sizeof(w_) / sizeof(w_[0]), true, what); } while (0)
#define EXPECT_NS(r, what, ...) do { static const char *const w_[] = { __VA_ARGS__ }; expect_owner_set(r, 2, 47, w_, sizeof(w_) / sizeof(w_[0]), false, what); } while (0)

static void test_nsec3_rfc5155_appendix_b(void) {
    printf("[TEST] DNSSEC: RFC 5155 Appendix A/B NSEC3 closest-encloser proofs...\n");
    gr_setup("example.", ZONE_NSEC3);
    gr_resp_t r;

    /* B.1 name error: closest encloser x.w.example., next closer c.x.w.example., wildcard *.x.w.example. */
    gr_query("a.c.x.w.example.", 15, true, &r);
    CHECK(&r, r.rcode == 3 && r.aa && gr_count(&r, 1, -1) == 0);
    CHECK(&r, gr_count(&r, 2, 6) == 1);
    EXPECT_N3(&r, "B.1 NXDOMAIN", H_XW, H_EXAMPLE, H_A);      /* match CE, cover next closer (0p9m), cover wildcard (35mt) */

    /* B.2 no data: ns1.example. exists without MX */
    gr_query("ns1.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 6) == 1);
    EXPECT_N3(&r, "B.2 NODATA", H_NS1);

    /* B.2.1 no data at an empty non-terminal: y.w.example. */
    gr_query("y.w.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 6) == 1);
    EXPECT_N3(&r, "B.2.1 empty non-terminal", H_YW);

    /* B.3 referral to an unsigned (opt-out) zone: NS + closest provable encloser proof */
    gr_query("mc.c.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && !r.aa && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 2) == 2);
    EXPECT_N3(&r, "B.3 opt-out referral", H_EXAMPLE, H_A);   /* match example., cover c.example. */

    /* B.4 wildcard expansion: the answer is synthesized, the next closer name z.w.example. is proven absent */
    gr_query("a.z.w.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && gr_count(&r, 1, 15) == 1);
    const gr_rr_t *mx = gr_first(&r, 1, 15);
    assert(strcasecmp(mx->name, "a.z.w.example.") == 0);
    CHECK(&r, gr_count(&r, 1, 46) >= 1);                        /* RRSIG of the wildcard RRset accompanies the answer */
    /* RFC 5155 7.2.6 requires the NSEC3 covering the next closer name z.w.example.; also sending the one that
     * matches the closest encloser w.example. is harmless surplus */
    EXPECT_N3_PLUS(&r, "B.4 wildcard answer", { H_NS2 }, { H_W });

    /* B.5 wildcard no data */
    gr_query("a.z.w.example.", 28, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 6) == 1);
    /* RFC 5155 7.2.5: closest encloser proof (match w.example., cover z.w.example.) + NSEC3 matching *.w.example. */
    EXPECT_N3(&r, "B.5 wildcard NODATA", H_W, H_NS2, H_WILDW);

    /* B.6 DS at the apex of the (top) zone: no data, proven by the apex NSEC3 */
    gr_query("example.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 6) == 1);
    EXPECT_N3(&r, "B.6 apex DS", H_EXAMPLE);

    /* plain name error with wraparound: nonexist.example. hashes after the last chain entry */
    gr_query("nonexist.example.", 1, true, &r);
    CHECK(&r, r.rcode == 3);
    EXPECT_N3(&r, "NXDOMAIN wraparound", H_EXAMPLE, H_XX, H_AI);

    /* positive answers carry RRSIGs only when DO is set */
    gr_query("ai.example.", 28, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 28) == 1 && gr_count(&r, 1, 46) == 1 && gr_count(&r, 2, 50) == 0);
    gr_query("ai.example.", 28, false, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 28) == 1 && gr_count(&r, 1, 46) == 0);
    /* without DO a negative answer has no proof records at all */
    gr_query("a.c.x.w.example.", 15, false, &r);
    CHECK(&r, r.rcode == 3 && gr_count(&r, 2, 50) == 0 && gr_count(&r, 2, 46) == 0 && gr_count(&r, 2, 6) == 1);
    /* signed delegation: DS + its RRSIG are returned with the referral */
    gr_query("mc.a.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && !r.aa && gr_count(&r, 2, 2) == 2 && gr_count(&r, 2, 43) == 1 && gr_count(&r, 2, 46) >= 1);
    /* the DS RRset itself is answered authoritatively by the parent */
    gr_query("a.example.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && gr_count(&r, 1, 43) == 1 && gr_count(&r, 1, 46) == 1);
    /* NSEC3PARAM / DNSKEY at the apex */
    gr_query("example.", 51, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 51) == 1);
    gr_query("example.", 48, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 48) == 1 && gr_count(&r, 1, 46) == 1);
    zone_arena_destroy(&g_gr.arena);
    printf("  -> NSEC3 proofs match RFC 5155 Appendix B.\n");
}

static void test_nsec_rfc4035_appendix_b(void) {
    printf("[TEST] DNSSEC: RFC 4035 Appendix A/B NSEC proofs...\n");
    gr_setup("example.", ZONE_NSEC);
    gr_resp_t r;

    /* B.2 name error: NSEC covering ml.example. and NSEC covering the wildcard *.example. */
    gr_query("ml.example.", 15, true, &r);
    CHECK(&r, r.rcode == 3 && r.aa && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 6) == 1);
    EXPECT_NS(&r, "B.2 NXDOMAIN", "b.example.", "example.");

    /* B.3 no data */
    gr_query("ns1.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 6) == 1);
    EXPECT_NS(&r, "B.3 NODATA", "ns1.example.");

    /* B.4 referral to a signed zone: NS + DS + RRSIG(DS) */
    gr_query("mc.a.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && !r.aa && gr_count(&r, 2, 2) == 2 && gr_count(&r, 2, 43) == 1 && gr_count(&r, 2, 46) >= 1);
    CHECK(&r, gr_count(&r, 2, 47) == 0);

    /* B.5 referral to an unsigned zone: NSEC of the delegation proves there is no DS */
    gr_query("mc.b.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && !r.aa && gr_count(&r, 2, 2) == 2 && gr_count(&r, 2, 43) == 0);
    EXPECT_NS(&r, "B.5 unsigned referral", "b.example.");

    /* B.6 wildcard expansion: NSEC proves z.w.example. does not exist */
    gr_query("a.z.w.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && gr_count(&r, 1, 15) == 1);
    assert(strcasecmp(gr_first(&r, 1, 15)->name, "a.z.w.example.") == 0);
    EXPECT_NS(&r, "B.6 wildcard answer", "x.y.w.example.");

    /* B.7 wildcard no data: the wildcard's own NSEC plus the covering NSEC */
    gr_query("a.z.w.example.", 28, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0 && gr_count(&r, 2, 6) == 1);
    EXPECT_NS(&r, "B.7 wildcard NODATA", "*.w.example.", "x.y.w.example.");

    /* empty non-terminal w.example. : covered by the NSEC that precedes *.w.example. */
    gr_query("w.example.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0);
    EXPECT_NS(&r, "ENT NODATA", "ns2.example.");

    /* name error after the last name: the last NSEC wraps to the apex */
    gr_query("zzz.example.", 1, true, &r);
    CHECK(&r, r.rcode == 3);
    EXPECT_NS(&r, "NXDOMAIN wraparound", "xx.example.", "example.");

    /* DS query at an unsigned delegation is answered NODATA by the parent with the delegation NSEC */
    gr_query("b.example.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0);
    EXPECT_NS(&r, "unsigned delegation DS", "b.example.");

    /* NSEC itself is a queryable type */
    gr_query("xx.example.", 47, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 47) == 1 && gr_count(&r, 1, 46) == 1);

    /* RFC 8482 minimal ANY on a signed name */
    g_gr.cfg.minimal_any = true;
    gr_query("xx.example.", 255, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) >= 1);
    g_gr.cfg.minimal_any = false;
    gr_query("xx.example.", 255, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 1) == 1 && gr_count(&r, 1, 28) == 1 && gr_count(&r, 1, 13) == 1);
    zone_arena_destroy(&g_gr.arena);
    printf("  -> NSEC proofs match RFC 4035 Appendix B.\n");
}

int main(void) {
    printf("=== Starting DNSSEC Negative-Proof Tests ===\n");
    test_nsec3_rfc5155_appendix_b();
    test_nsec_rfc4035_appendix_b();
    printf("=== All DNSSEC Negative-Proof Tests PASSED ===\n");
    return 0;
}

/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}
