#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
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
int dispatch_to_program_zone(const char *view_name, const char *domain, const uint8_t *req, size_t req_len,
                             uint8_t *res, size_t max_res_len, size_t res_cap,
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
dns_record_t *find_matching_nsec3(zone_arena_t *zone, const dns_record_t *param, const char *hash_b32, const char *apex);
dns_record_t *find_covering_nsec3(zone_arena_t *zone, const dns_record_t *param, const char *target_hash);
bool find_next_closer_name(const char *qname, const char *encloser, char *out, size_t out_sz);
bool attach_nsec3_record(zone_arena_t *zone, dns_record_t *rec,
                         uint8_t *res, size_t max_res_len, uint16_t *offset,
                         compress_ctx_t *comp_ctx, uint16_t *nscount,
                         dns_record_t **attached, int *attached_count);
bool name_exists_in_zone(zone_arena_t *zone, const char *name, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag);
const char *find_closest_encloser(zone_arena_t *zone, const char *qname, const char *zone_apex, const char client_loc[2], const char *client_ecs_tag, const char *client_loc_tag);
program_plugin_t *find_program_plugin(const char *view_name, const char *domain);
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

/* RFC 5155 §5: the hash input is the canonical wire form of the owner name (RFC 4034 §6.2), so presentation
 * escapes must be turned back into octets first (R-29 addendum). Expected values: BIND 9 `nsec3hash AABBCCDD 1 2
 * <name>` on the build host. */
static void test_nsec3_hash_escaped_names(void) {
    printf("[TEST] DNSSEC: NSEC3 hash of names with presentation escapes...\n");
    static const uint8_t salt[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    static const struct { const char *name, *hash; } v[] = {
        { "a\\.b.example.",       "KP1CUN00K75M528RJK5JGHIATMGMSPKO" },   /* one label "a.b" */
        { "a.b.example.",         "MDEAMRQN8A0FLP3ECAHP6HNG4MDGA9BP" },   /* two labels: a different hash */
        { "sp\\032ace.example.",  "NOH2GVBVCS98IT5JGU1FCMEODEHMVJ3A" },
        { "abc.example.",         "IPUMAFN055RCK0CCQIH8C1MV44DK27JS" },
        { "\\065bc.example.",     "IPUMAFN055RCK0CCQIH8C1MV44DK27JS" },   /* \065 = 'A', lower-cased */
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        char out[64];
        assert(compute_nsec3_hash(v[i].name, 1, 2, salt, sizeof(salt), out, sizeof(out)));
        if (strcasecmp(out, v[i].hash) != 0) {
            fprintf(stderr, "nsec3 hash of %s: got %s, expected %s\n", v[i].name, out, v[i].hash);
            assert(0);
        }
    }
    uint8_t wire[256];
    assert(name_to_canonical_wire("A\\.B.example.", wire, sizeof(wire)) == 13);
    assert(wire[0] == 3 && memcmp(wire + 1, "a.b", 3) == 0 && wire[4] == 7);
    printf("  -> NSEC3 hashes match nsec3hash.\n");
}

/* ---- R-34: sorted NSEC3 index per chain ---------------------------------------------------------------- */

typedef struct {
    zone_arena_t arena;
    char *text;  /* parse_zone_fast() keeps pointers into it */
} n3_zone_t;

static uint64_t g_n3_rng = 0x9E3779B97F4A7C15ULL;
static uint32_t n3_rand(void) {
    g_n3_rng = g_n3_rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(g_n3_rng >> 33);
}

/* A random 160-bit hash in base32hex (RFC 4648 §7): 32 digits. Upper or lower case. */
static void n3_random_hash(char out[33], bool lower) {
    static const char up[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV", lo[] = "0123456789abcdefghijklmnopqrstuv";
    for (int i = 0; i < 32; i++) out[i] = (lower ? lo : up)[n3_rand() % 32];
    out[32] = '\0';
}

static int n3_cmp_str_ci(const void *a, const void *b) {
    return strcasecmp((const char *)a, (const char *)b);
}

/* Appends a complete chain of n NSEC3 RRs with salt `salt` (RFC 5155 §3.1.7: each next hash is the following
 * owner in hash order, the last wraps to the first). Owners are written in a scrambled order, every third in
 * lower case. hashes[] receives the sorted owner hashes (n * 33 bytes). skip >= 0 leaves that record out. */
static size_t n3_append_chain(char *buf, size_t off, size_t cap, const char *salt, size_t n, char (*hashes)[33],
                              long skip) {
    for (size_t i = 0; i < n; i++) n3_random_hash(hashes[i], false);
    qsort(hashes, n, sizeof(hashes[0]), n3_cmp_str_ci);
    for (size_t k = 0; k < n; k++) {
        size_t i = (k * 7919) % n;  /* 7919 is prime and does not divide the sizes used here */
        if ((long)i == skip) continue;
        char owner[33];
        memcpy(owner, hashes[i], sizeof(owner));
        if (i % 3 == 0)
            for (char *p = owner; *p; p++) *p = (char)tolower((unsigned char)*p);
        int w = snprintf(buf + off, cap - off, "%s IN NSEC3 1 0 0 %s %s A RRSIG\n", owner, salt, hashes[(i + 1) % n]);
        assert(w > 0 && (size_t)w < cap - off);
        off += (size_t)w;
    }
    return off;
}

static void n3_zone_load(n3_zone_t *z, char *text) {
    memset(z, 0, sizeof(*z));
    zone_arena_init(&z->arena);
    z->text = text;
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "n3.test.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(text, strlen(text), &z->arena, &ctx) >= 0);
    assert(build_zone_index(&z->arena, true) == 0);
}

static void n3_zone_free(n3_zone_t *z) {
    zone_arena_destroy(&z->arena);
    free(z->text);
}

static dns_record_t *n3_param(n3_zone_t *z) {
    for (size_t i = 0; i < z->arena.count; i++)
        if (z->arena.records[i].type_code == 51) return &z->arena.records[i];
    return NULL;
}

/* The lookup before R-34: every NSEC3 RR of the zone, in record order, limited to the chain of `param` (the
 * filtering the index adds, RFC 5155 §7.2). */
static dns_record_t *n3_linear_cover(zone_arena_t *zone, const dns_record_t *param, const char *target) {
    for (size_t i = 0; i < zone->count; i++) {
        dns_record_t *rec = &zone->records[i];
        if (rec->type_code != 50 || rec->rdata_count < 5 || strcasecmp(rec->rdata[3], param->rdata[3]) != 0)
            continue;
        char owner[64];
        const char *dot = strchr(rec->name, '.');
        memcpy(owner, rec->name, (size_t)(dot - rec->name));
        owner[dot - rec->name] = '\0';
        if (nsec3_covers_hash(owner, rec->rdata[4], target)) return rec;
    }
    return NULL;
}

static const char *n3_salt_of(const dns_record_t *rec) { return rec ? rec->rdata[3] : "(none)"; }

#define N3_HDR "$ORIGIN n3.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\n"

static void test_nsec3_index_matches_linear_scan(void) {
    printf("[TEST] DNSSEC: NSEC3 index lookups equal the linear scan (R-34)...\n");
    const size_t n = 2000, cap = 256 + n * 100;
    char (*h)[33] = malloc(n * sizeof(*h));
    char *text = malloc(cap);
    assert(h && text);
    size_t off = (size_t)snprintf(text, cap, N3_HDR "@ IN NSEC3PARAM 1 0 0 -\n");
    off = n3_append_chain(text, off, cap, "-", n, h, -1);
    n3_zone_t z;
    n3_zone_load(&z, text);
    dns_record_t *param = n3_param(&z);
    assert(param && z.arena.nsec3_chain_count == 1 && z.arena.nsec3_chains[0].count == n);

    /* every owner: matched, never covered (RFC 5155 §3.1.7: an owner hash is not strictly between owner/next) */
    for (size_t i = 0; i < n; i++) {
        dns_record_t *m = find_matching_nsec3(&z.arena, param, h[i], "n3.test.");
        assert(m && strncasecmp(m->name, h[i], 32) == 0);
        char lower[33];
        for (int k = 0; k < 33; k++) lower[k] = (char)tolower((unsigned char)h[i][k]);
        assert(find_matching_nsec3(&z.arena, param, lower, "n3.test.") == m);
        assert(find_matching_nsec3(&z.arena, param, h[i], "other.test.") == NULL);
        assert(find_covering_nsec3(&z.arena, param, h[i]) == NULL);
        assert(n3_linear_cover(&z.arena, param, h[i]) == NULL);
    }
    /* random targets and both ends of the hash space (wrap-around at the last RR) */
    const char *ends[] = { "00000000000000000000000000000000", "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV",
                           "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" };
    for (size_t i = 0; i < 5000 + 3; i++) {
        char t[33];
        if (i < 3) memcpy(t, ends[i], sizeof(t)); else n3_random_hash(t, i % 2 == 0);
        dns_record_t *got = find_covering_nsec3(&z.arena, param, t), *want = n3_linear_cover(&z.arena, param, t);
        bool owner = find_matching_nsec3(&z.arena, param, t, "n3.test.") != NULL;
        if (got != want || (!owner && !got)) {
            fprintf(stderr, "cover %s: index %s, linear %s\n", t, got ? got->name : "NULL", want ? want->name : "NULL");
            assert(0);
        }
    }
    /* rebuilding the index (as after IXFR/UPDATE) replaces it without leaking */
    assert(build_zone_index(&z.arena, true) == 0);
    assert(z.arena.nsec3_chain_count == 1 && z.arena.nsec3_chains[0].count == n);
    n3_zone_free(&z);
    free(h);
    printf("  -> %zu owners and 5003 targets agree with the linear scan.\n", n);
}

static void test_nsec3_index_two_chains(void) {
    printf("[TEST] DNSSEC: NSEC3 lookups stay in the chain of the NSEC3PARAM (RFC 5155 §7.2)...\n");
    const size_t n = 300, cap = 512 + 2 * n * 100;
    char (*ha)[33] = malloc(n * sizeof(*ha)), (*hb)[33] = malloc(n * sizeof(*hb));
    char *text = malloc(cap);
    assert(ha && hb && text);
    /* chain B first in the file: the order that gave mixed proofs before (R-31 second defect) */
    size_t off = (size_t)snprintf(text, cap, N3_HDR "@ IN NSEC3PARAM 1 0 0 aa11\n@ IN NSEC3PARAM 1 0 0 BB22\n");
    off = n3_append_chain(text, off, cap, "bb22", n, hb, -1);
    off = n3_append_chain(text, off, cap, "AA11", n, ha, -1);
    n3_zone_t z;
    n3_zone_load(&z, text);
    assert(z.arena.nsec3_chain_count == 2);
    dns_record_t *pa = NULL, *pb = NULL;
    for (size_t i = 0; i < z.arena.count; i++) {
        dns_record_t *r = &z.arena.records[i];
        if (r->type_code == 51) { if (strcasecmp(r->rdata[3], "aa11") == 0) pa = r; else pb = r; }
    }
    assert(pa && pb);
    for (size_t i = 0; i < 2000; i++) {
        char t[33];
        n3_random_hash(t, false);
        dns_record_t *ca = find_covering_nsec3(&z.arena, pa, t), *cb = find_covering_nsec3(&z.arena, pb, t);
        if (!ca || strcasecmp(n3_salt_of(ca), "aa11") != 0 || !cb || strcasecmp(n3_salt_of(cb), "bb22") != 0) {
            fprintf(stderr, "cover %s: chain A -> %s, chain B -> %s\n", t, n3_salt_of(ca), n3_salt_of(cb));
            assert(0);
        }
        assert(ca == n3_linear_cover(&z.arena, pa, t) && cb == n3_linear_cover(&z.arena, pb, t));
    }
    for (size_t i = 0; i < n; i++) {
        /* an owner of chain A is matched through chain A only */
        dns_record_t *m = find_matching_nsec3(&z.arena, pa, ha[i], "n3.test.");
        assert(m && strcasecmp(n3_salt_of(m), "aa11") == 0);
        dns_record_t *mb = find_matching_nsec3(&z.arena, pb, ha[i], "n3.test.");
        assert(mb == NULL || strcasecmp(n3_salt_of(mb), "bb22") == 0);
    }
    /* parameters without a chain, and unusable NSEC3PARAM RDATA */
    dns_record_t p;
    memset(&p, 0, sizeof(p));
    p.rdata[0] = "1"; p.rdata[1] = "0"; p.rdata[2] = "0"; p.rdata[3] = "cc33"; p.rdata_count = 4;
    assert(find_covering_nsec3(&z.arena, &p, ha[0]) == NULL && find_matching_nsec3(&z.arena, &p, ha[0], "n3.test.") == NULL);
    p.rdata[3] = "aa11"; p.rdata[2] = "1";
    assert(find_covering_nsec3(&z.arena, &p, ha[0]) == NULL);
    p.rdata[2] = "x";
    assert(find_covering_nsec3(&z.arena, &p, ha[0]) == NULL);
    p.rdata[2] = "65536";
    assert(find_covering_nsec3(&z.arena, &p, ha[0]) == NULL);
    p.rdata[2] = "0"; p.rdata_count = 3;
    assert(find_covering_nsec3(&z.arena, &p, ha[0]) == NULL);
    n3_zone_free(&z);
    free(ha);
    free(hb);
    printf("  -> both chains answer only with their own RRs.\n");
}

static void test_nsec3_index_broken_chain(void) {
    printf("[TEST] DNSSEC: NSEC3 lookups on an incomplete chain...\n");
    const size_t n = 50, cap = 256 + n * 100;
    char (*h)[33] = malloc(n * sizeof(*h));
    char *text = malloc(cap);
    assert(h && text);
    size_t off = (size_t)snprintf(text, cap, N3_HDR "@ IN NSEC3PARAM 1 0 0 -\n");
    /* no salt written as "-" in the RRs and matched by an NSEC3PARAM salt "-" */
    off = n3_append_chain(text, off, cap, "-", n, h, 10);
    /* a record the index ignores: the owner label is not base32hex (RFC 4648 §7) */
    snprintf(text + off, cap - off, "not-a-hash IN NSEC3 1 0 0 - %s A\n", h[0]);
    n3_zone_t z;
    n3_zone_load(&z, text);
    dns_record_t *param = n3_param(&z);
    assert(z.arena.nsec3_chain_count == 1 && z.arena.nsec3_chains[0].count == n - 1);
    /* h[10] is missing: a target between h[9] and h[10] has no covering RR (h[9]'s next is h[10]) */
    char t[33];
    memcpy(t, h[10], sizeof(t));
    assert(find_matching_nsec3(&z.arena, param, t, "n3.test.") == NULL);
    assert(find_covering_nsec3(&z.arena, param, t) == NULL);
    /* other targets: NULL (inside the gap) or a chain RR that really covers the target, never the ignored RR */
    size_t gaps = 0;
    for (size_t i = 0; i < 1000; i++) {
        n3_random_hash(t, false);
        dns_record_t *c = find_covering_nsec3(&z.arena, param, t);
        if (!c) { gaps++; continue; }
        char owner[33];
        memcpy(owner, c->name, 32);
        owner[32] = '\0';
        assert(c->name[32] == '.' && nsec3_covers_hash(owner, c->rdata[4], t));
    }
    assert(gaps < 1000);
    n3_zone_free(&z);
    free(h);
    printf("  -> no crash, no RR from outside the chain.\n");
}

static double n3_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Performance regression for R-34: 10 000 covering lookups on a 100 000-RR chain. The linear scan needed about
 * 10^9 comparisons for this (tens of seconds); binary search needs about 1.7 * 10^5. The bound leaves room for
 * ASan/UBSan builds and slow CI machines. */
static void test_nsec3_index_performance(void) {
    printf("[TEST] DNSSEC: NSEC3 covering lookup is logarithmic (R-34 performance regression)...\n");
    const size_t n = 100000, lookups = 10000, cap = 256 + n * 100;
    char (*h)[33] = malloc(n * sizeof(*h));
    char (*t)[33] = malloc(lookups * sizeof(*t));
    char *text = malloc(cap);
    assert(h && t && text);
    size_t off = (size_t)snprintf(text, cap, N3_HDR "@ IN NSEC3PARAM 1 0 0 -\n");
    (void)n3_append_chain(text, off, cap, "-", n, h, -1);
    n3_zone_t z;
    n3_zone_load(&z, text);
    dns_record_t *param = n3_param(&z);
    for (size_t i = 0; i < lookups; i++) n3_random_hash(t[i], false);
    size_t found = 0;
    double t0 = n3_now();
    for (size_t i = 0; i < lookups; i++) found += find_covering_nsec3(&z.arena, param, t[i]) != NULL;
    double elapsed = n3_now() - t0;
    printf("  -> %zu lookups on %zu NSEC3 RRs: %.3f s (%zu covered)\n", lookups, n, elapsed, found);
    assert(found == lookups);  /* random 160-bit targets never equal an owner */
    assert(elapsed < 2.0);
    n3_zone_free(&z);
    free(h);
    free(t);
}

/* ------------------------------------------------------------------------------------------------------------
 * R-33: DNSSEC records received in wire form (AXFR/IXFR/UPDATE) get the same text fields as the zone file parser
 * gives them, and keep their RDATA as received.
 * ---------------------------------------------------------------------------------------------------------- */

/* Serializes `rec` (owner uncompressed) and decodes it again like a transfer does. Returns the wire length. */
static size_t dw_roundtrip(const dns_record_t *rec, zone_arena_t *arena, dns_record_t *out, uint8_t *wire, size_t cap) {
    uint16_t off = 0;
    assert(serialize_dns_record(wire, cap, &off, rec, NULL, NULL, 0xFFFFFFFF) == 0);
    /* exactly sized copy: ASan reports any read past the RR */
    uint8_t *exact = malloc(off);
    assert(exact);
    memcpy(exact, wire, off);
    size_t pos = 0;
    uint16_t type = 0;
    memset(out, 0, sizeof(*out));
    assert(parse_resource_record(exact, off, &pos, arena, out, &type) == 0);
    assert(pos == off && type == rec->type_code);
    free(exact);
    return off;
}

/* RDATA of a serialized RR with an uncompressed owner name */
static const uint8_t *dw_rdata(const uint8_t *wire, size_t *rdlen) {
    size_t p = 0;
    while (wire[p] != 0) p += 1 + wire[p];
    p += 1 + 8;
    *rdlen = ((size_t)wire[p] << 8) | wire[p + 1];
    return wire + p + 2;
}

static void test_dnssec_wire_decode_roundtrip(void) {
    printf("[TEST] DNSSEC: RRSIG/NSEC/NSEC3/NSEC3PARAM/DNSKEY/DS decoded from wire like the zone parser (R-33)...\n");
    char *text = strdup(
        "$ORIGIN dw.test.\n$TTL 300\n"
        "@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n"
        "@ IN NS ns1\n"
        "@ IN DNSKEY 257 3 13 lvjQ0fEgbjekwhT1Fd4oJttlA/2Nb9qkeCfD2RPp236JZFoXPDX/Q3/um8vFAuDqFtMfSaoK/fqBeMBxJmSKXw==\n"
        "@ IN DNSKEY 256 3 8 AwEAAQ==\n"
        "@ IN RRSIG SOA 13 2 300 20300101000000 20200101000000 12345 dw.test. "
        "tPti5Ij+iPWWb+zOQSfmVt/OAJdo9WOsl6h0DM5NhjIAb/h/cn+2+qrFgHcJjmdThHHca8qp8pRfhPqASxe73A==\n"
        "@ IN RRSIG TYPE65280 13 2 4294967295 21060207062815 19700101000000 1 dw.test. AAAA\n"
        "@ IN RRSIG NSEC3PARAM 8 2 60 20290228235959 20240229120000 65535 Dw.Test. AAECAwQFBgc=\n"
        "@ IN NSEC3PARAM 1 0 10 AABBCCDD\n"
        "@ IN NSEC3PARAM 1 0 0 -\n"
        "sec IN DS 12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n"
        "www IN NSEC a\\.b.dw.test. A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY CAA TYPE1234 TYPE65534\n"
        "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM IN NSEC3 1 1 10 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG\n"
        "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR IN NSEC3 1 0 0 - 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM\n");
    assert(text);
    n3_zone_t z;
    memset(&z, 0, sizeof(z));
    zone_arena_init(&z.arena);
    z.text = text;
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "dw.test.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(text, strlen(text), &z.arena, &ctx) >= 0);

    zone_arena_t w;
    zone_arena_init(&w);
    uint8_t wire[2048], wire2[2048];
    size_t checked = 0;
    for (size_t i = 0; i < z.arena.count; i++) {
        dns_record_t *src = &z.arena.records[i];
        uint16_t t = src->type_code;
        if (t != 43 && t != 46 && t != 47 && t != 48 && t != 50 && t != 51) continue;
        dns_record_t got;
        size_t len = dw_roundtrip(src, &w, &got, wire, sizeof(wire));
        /* same fields as the zone file parser (names and hex/base32 compared case-insensitively) */
        if (got.rdata_count != src->rdata_count) {
            fprintf(stderr, "%s type %u: %d fields, zone parser %d\n", src->name, t, got.rdata_count, src->rdata_count);
            assert(0);
        }
        for (int k = 0; k < got.rdata_count; k++) {
            if (strcasecmp(got.rdata[k], src->rdata[k]) != 0) {
                fprintf(stderr, "%s type %u field %d: '%s', zone parser '%s'\n", src->name, t, k, got.rdata[k], src->rdata[k]);
                assert(0);
            }
        }
        /* RDATA kept as received and written back unchanged */
        size_t rdlen;
        const uint8_t *rd = dw_rdata(wire, &rdlen);
        assert(got.generic_data && got.generic_len == rdlen && memcmp(got.generic_data, rd, rdlen) == 0);
        uint16_t off2 = 0;
        assert(serialize_dns_record(wire2, sizeof(wire2), &off2, &got, NULL, NULL, 0xFFFFFFFF) == 0);
        assert(off2 == len && memcmp(wire, wire2, len) == 0);
        /* the RRSIG cache the answer code reads */
        if (t == 46) {
            assert(got.is_cached && src->is_cached);
            assert(got.cache.rrsig.type_covered == src->cache.rrsig.type_covered);
            assert(got.cache.rrsig.sig_exp == src->cache.rrsig.sig_exp && got.cache.rrsig.sig_inc == src->cache.rrsig.sig_inc);
            assert(got.cache.rrsig.orig_ttl == src->cache.rrsig.orig_ttl && got.cache.rrsig.key_tag == src->cache.rrsig.key_tag);
            assert(got.cache.rrsig.signature == NULL); /* not decoded again: the blob is written */
        }
        checked++;
    }
    assert(checked == 11);
    zone_arena_destroy(&w);
    n3_zone_free(&z);
    printf("  -> %zu records: same fields, RDATA unchanged.\n", checked);
}

/* A zone copied record by record through the wire decoder, as a secondary stores it. */
static void dw_copy_zone(const zone_arena_t *src, zone_arena_t *dst) {
    zone_arena_init(dst);
    dst->records = calloc(src->count, sizeof(dns_record_t));
    assert(dst->records);
    dst->records_cap = src->count;
    uint8_t wire[4096];
    for (size_t i = 0; i < src->count; i++)
        (void)dw_roundtrip(&src->records[i], dst, &dst->records[dst->count++], wire, sizeof(wire));
    assert(build_zone_index(dst, true) == 0);
}

static void test_dnssec_wire_decode_usable(void) {
    printf("[TEST] DNSSEC: transferred NSEC/NSEC3 records are indexed and found like file-loaded ones (R-33)...\n");
    const size_t n = 300, cap = 512 + n * 100;
    char (*h)[33] = malloc(n * sizeof(*h));
    char *text = malloc(cap);
    assert(h && text);
    size_t off = (size_t)snprintf(text, cap, N3_HDR "@ IN NSEC3PARAM 1 0 0 aa11\n");
    (void)n3_append_chain(text, off, cap, "AA11", n, h, -1);
    n3_zone_t z;
    n3_zone_load(&z, text);
    zone_arena_t w;
    dw_copy_zone(&z.arena, &w);
    dns_record_t *pz = n3_param(&z), *pw = NULL;
    for (size_t i = 0; i < w.count; i++)
        if (w.records[i].type_code == 51) pw = &w.records[i];
    assert(pz && pw && w.nsec3_chain_count == 1 && w.nsec3_chains[0].count == n);
    for (size_t i = 0; i < 2000; i++) {
        char t[33];
        n3_random_hash(t, i % 2 == 0);
        dns_record_t *a = find_covering_nsec3(&z.arena, pz, t), *b = find_covering_nsec3(&w, pw, t);
        assert(a && b && strcasecmp(a->name, b->name) == 0);
    }
    for (size_t i = 0; i < n; i++) {
        dns_record_t *m = find_matching_nsec3(&w, pw, h[i], "n3.test.");
        assert(m && strncasecmp(m->name, h[i], 32) == 0);
    }
    zone_arena_destroy(&w);
    n3_zone_free(&z);
    free(h);

    /* NSEC chain (RFC 4034 §4.1.1) */
    char *nt = strdup("$ORIGIN nw.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\n"
                      "@ IN NSEC b.nw.test. NS SOA RRSIG NSEC\nb IN NSEC d.nw.test. A RRSIG NSEC\n"
                      "d IN NSEC m.nw.test. A RRSIG NSEC\nm IN NSEC nw.test. A RRSIG NSEC\n"
                      "b IN A 192.0.2.1\nd IN A 192.0.2.2\nm IN A 192.0.2.3\n");
    n3_zone_t nz;
    memset(&nz, 0, sizeof(nz));
    zone_arena_init(&nz.arena);
    nz.text = nt;
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "nw.test.", .is_standalone_mode = true, .err_out = &err };
    assert(parse_zone_fast(nt, strlen(nt), &nz.arena, &ctx) >= 0);
    assert(build_zone_index(&nz.arena, true) == 0);
    dw_copy_zone(&nz.arena, &w);
    const char *names[] = { "a.nw.test.", "c.nw.test.", "c.b.nw.test.", "e.nw.test.", "z.nw.test.", "0.nw.test." };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        dns_record_t *a = find_covering_nsec(&nz.arena, names[i]), *b = find_covering_nsec(&w, names[i]);
        assert(a && b && strcasecmp(a->name, b->name) == 0);
    }
    zone_arena_destroy(&w);
    n3_zone_free(&nz);
    printf("  -> NSEC3 chain index and NSEC covering lookups equal the file-loaded zone.\n");
}

/* One RR "x.dw.test. IN <type> 300" with the given RDATA, in an exactly sized buffer. */
static uint8_t *dw_make_rr(uint16_t type, const uint8_t *rd, size_t rdlen, size_t *len) {
    static const uint8_t owner[] = { 1, 'x', 2, 'd', 'w', 4, 't', 'e', 's', 't', 0 };
    *len = sizeof(owner) + 10 + rdlen;
    uint8_t *p = malloc(*len);
    assert(p);
    memcpy(p, owner, sizeof(owner));
    uint8_t *h = p + sizeof(owner);
    h[0] = (uint8_t)(type >> 8); h[1] = (uint8_t)type; h[2] = 0; h[3] = 1;
    h[4] = 0; h[5] = 0; h[6] = 1; h[7] = 44; h[8] = (uint8_t)(rdlen >> 8); h[9] = (uint8_t)rdlen;
    if (rdlen) memcpy(h + 10, rd, rdlen);
    return p;
}

/* Decodes the RR; returns the number of text fields. The RR is always accepted and its RDATA kept. */
static int dw_decode(uint16_t type, const uint8_t *rd, size_t rdlen, zone_arena_t *arena, dns_record_t *rec) {
    size_t len, pos = 0;
    uint16_t t;
    uint8_t *p = dw_make_rr(type, rd, rdlen, &len);
    memset(rec, 0, sizeof(*rec));
    assert(parse_resource_record(p, len, &pos, arena, rec, &t) == 0 && pos == len);
    assert(rec->generic_len == rdlen && (rdlen == 0 || memcmp(rec->generic_data, rd, rdlen) == 0));
    free(p);
    return rec->rdata_count;
}

static void test_dnssec_wire_decode_malformed(void) {
    printf("[TEST] DNSSEC: malformed DNSSEC RDATA is kept opaque, never read out of bounds (R-33)...\n");
    zone_arena_t a;
    zone_arena_init(&a);
    dns_record_t r;
    /* RRSIG fixed part (18 octets) + signer "dw.test." + signature */
    uint8_t sig[64] = { 0, 1, 13, 2, 0, 0, 1, 44, 0x70, 0, 0, 0, 0x60, 0, 0, 0, 0x30, 0x39,
                        2, 'd', 'w', 4, 't', 'e', 's', 't', 0, 0xAA, 0xBB, 0xCC };
    assert(dw_decode(46, sig, 30, &a, &r) == 9);
    assert(strcmp(r.rdata[0], "A") == 0 && strcmp(r.rdata[6], "12345") == 0 && strcmp(r.rdata[7], "dw.test.") == 0);
    assert(strcmp(r.rdata[4], "20290718054952") == 0 && strcmp(r.rdata[5], "20210114082536") == 0 && strcmp(r.rdata[8], "qrvM") == 0);
    assert(dw_decode(46, sig, 17, &a, &r) == 0);          /* fixed part truncated */
    assert(dw_decode(46, sig, 22, &a, &r) == 0);          /* signer runs past RDLENGTH */
    assert(dw_decode(46, sig, 27, &a, &r) == 9);          /* empty signature: well formed */
    uint8_t csig[20];
    memcpy(csig, sig, 18);
    csig[18] = 0xC0; csig[19] = 0x0C;                      /* compressed signer (RFC 4034 §3.1.7) */
    assert(dw_decode(46, csig, 20, &a, &r) == 0);
    csig[18] = 0x40; csig[19] = 0;                         /* reserved label type */
    assert(dw_decode(46, csig, 20, &a, &r) == 0);

    /* NSEC: next name "b.dw.test." + bitmap */
    uint8_t nsec[128] = { 1, 'b', 2, 'd', 'w', 4, 't', 'e', 's', 't', 0 };
    size_t nb = 11;
    /* window 0: A(1) OPT(41, pseudo: ignored) ; window 1: 257 (CAA) */
    const uint8_t bm[] = { 0, 6, 0x40, 0, 0, 0, 0, 0x40, 1, 1, 0x40 };
    memcpy(nsec + nb, bm, sizeof(bm));
    assert(dw_decode(47, nsec, nb + sizeof(bm), &a, &r) == 3);
    assert(strcmp(r.rdata[0], "b.dw.test.") == 0 && strcmp(r.rdata[1], "A") == 0 && strcmp(r.rdata[2], "CAA") == 0);
    const uint8_t bad_order[] = { 1, 1, 0x40, 0, 1, 0x40 }, bad_len0[] = { 0, 0 }, bad_len33[] = { 0, 33 },
                  bad_short[] = { 0, 4, 0x40 }, bad_hdr[] = { 0 };
    const struct { const uint8_t *p; size_t n; } bads[] = {
        { bad_order, sizeof(bad_order) }, { bad_len0, sizeof(bad_len0) }, { bad_len33, sizeof(bad_len33) },
        { bad_short, sizeof(bad_short) }, { bad_hdr, sizeof(bad_hdr) } };
    for (size_t i = 0; i < sizeof(bads) / sizeof(bads[0]); i++) {
        memcpy(nsec + nb, bads[i].p, bads[i].n);
        assert(dw_decode(47, nsec, nb + bads[i].n, &a, &r) == 0);
    }
    nsec[0] = 0xC0; nsec[1] = 0;                           /* compressed next name (RFC 4034 §4.1.1) */
    assert(dw_decode(47, nsec, 2, &a, &r) == 0);
    nsec[0] = 1; nsec[1] = 'b';
    assert(dw_decode(47, nsec, 5, &a, &r) == 0);           /* next name truncated */
    /* a bitmap with more types than rdata[] holds: fixed field + MAX_RDATA - 1 types, RDATA kept */
    uint8_t big[11 + 2 + 32];
    memcpy(big, nsec, 11);
    big[11] = 0; big[12] = 32;
    memset(big + 13, 0xFF, 32);
    big[13] = 0x7F;                                        /* type 0 not set */
    big[13 + 5] = 0xBF;                                    /* OPT (41) not set */
    assert(dw_decode(47, big, sizeof(big), &a, &r) == MAX_RDATA);

    /* NSEC3: alg 1, flags 1, 10 iterations, salt AABB, 20-octet hash, bitmap A */
    uint8_t n3[64] = { 1, 1, 0, 10, 2, 0xAA, 0xBB, 20 };
    for (int i = 0; i < 20; i++) n3[8 + i] = (uint8_t)(i * 13);
    n3[28] = 0; n3[29] = 1; n3[30] = 0x40;
    assert(dw_decode(50, n3, 31, &a, &r) == 6);
    assert(strcmp(r.rdata[2], "10") == 0 && strcmp(r.rdata[3], "AABB") == 0 && strlen(r.rdata[4]) == 32 &&
           strcmp(r.rdata[5], "A") == 0);
    assert(dw_decode(50, n3, 28, &a, &r) == 5);            /* empty bitmap (RFC 6840 §6.4) */
    assert(dw_decode(50, n3, 4, &a, &r) == 0);             /* fixed part truncated */
    n3[4] = 30;
    assert(dw_decode(50, n3, 31, &a, &r) == 0);            /* salt length past RDLENGTH */
    n3[4] = 2; n3[7] = 0;
    assert(dw_decode(50, n3, 31, &a, &r) == 0);            /* hash length 0 */
    n3[7] = 40;
    assert(dw_decode(50, n3, 31, &a, &r) == 0);            /* hash past RDLENGTH */
    n3[7] = 20;
    assert(dw_decode(50, n3, 7, &a, &r) == 0);             /* no hash length octet */

    /* NSEC3PARAM: exactly 5 + salt length octets (RFC 5155 §4.2) */
    const uint8_t p3[] = { 1, 0, 0, 0, 0, 0 };
    assert(dw_decode(51, p3, 5, &a, &r) == 4 && strcmp(r.rdata[3], "-") == 0);
    assert(dw_decode(51, p3, 6, &a, &r) == 0);
    assert(dw_decode(51, p3, 4, &a, &r) == 0);

    /* DNSKEY / DS: 4 fixed octets */
    const uint8_t k[] = { 1, 1, 3, 13, 0xFF };
    assert(dw_decode(48, k, 5, &a, &r) == 4 && strcmp(r.rdata[0], "257") == 0 && strcmp(r.rdata[3], "/w==") == 0);
    assert(dw_decode(48, k, 3, &a, &r) == 0);
    assert(dw_decode(43, k, 5, &a, &r) == 4 && strcmp(r.rdata[3], "FF") == 0);
    assert(dw_decode(43, k, 0, &a, &r) == 0);
    zone_arena_destroy(&a);
    printf("  -> malformed RDATA stays opaque; well-formed edge cases decode.\n");
}

/* ------------------------------------------------------------------------------------------------
 * Phase 9 (AUDIT_FINDINGS R-03, R-04, O-16, O-17, R-31, R-32). Signatures are placeholders: what is checked is
 * which RRs the server puts in which section and in which order.
 * ---------------------------------------------------------------------------------------------- */
#define P9_SIG "20300101000000 20200101000000 12345"

static uint16_t p9_rrsig_covered(const gr_resp_t *r, const gr_rr_t *rr) {
    return (uint16_t)((r->msg[rr->rdoff] << 8) | r->msg[rr->rdoff + 1]);
}

/* O-16 / R-04: in section `sect` every RRset is contiguous, its RRSIGs follow it directly, and no RR appears
 * twice (RFC 2181 §5). */
static void p9_expect_grouped(const gr_resp_t *r, int sect, const char *what) {
    const gr_rr_t *cur = NULL, *prev = NULL;
    for (int i = 0; i < r->nrr; i++) {
        const gr_rr_t *rr = &r->rr[i];
        if (rr->sect != sect) continue;
        for (int j = 0; j < i; j++) {
            const gr_rr_t *o = &r->rr[j];
            if (o->sect == sect && o->type == rr->type && strcasecmp(o->name, rr->name) == 0 &&
                o->rdlen == rr->rdlen && memcmp(r->msg + o->rdoff, r->msg + rr->rdoff, rr->rdlen) == 0) {
                fprintf(stderr, "%s: duplicate type-%u RR %s\n", what, rr->type, rr->name); dump_resp(r); assert(0);
            }
        }
        if (rr->type == 46) {
            if (!cur || p9_rrsig_covered(r, rr) != cur->type || strcasecmp(rr->name, cur->name) != 0) {
                fprintf(stderr, "%s: RRSIG %s (covers %u) does not follow its RRset\n", what, rr->name,
                        p9_rrsig_covered(r, rr));
                dump_resp(r); assert(0);
            }
        } else if (!(cur && prev && prev->type != 46 && cur->type == rr->type && strcasecmp(cur->name, rr->name) == 0)) {
            for (int j = 0; j < i; j++) {
                if (r->rr[j].sect == sect && r->rr[j].type == rr->type && strcasecmp(r->rr[j].name, rr->name) == 0) {
                    fprintf(stderr, "%s: RRset %s type %u is split\n", what, rr->name, rr->type); dump_resp(r); assert(0);
                }
            }
            cur = rr;
        }
        prev = rr;
    }
}

static int p9_count_owner(const gr_resp_t *r, int sect, int type, const char *owner) {
    int n = 0;
    for (int i = 0; i < r->nrr; i++)
        if (r->rr[i].sect == sect && (type < 0 || r->rr[i].type == type) && strcasecmp(r->rr[i].name, owner) == 0) n++;
    return n;
}

static void p9_query_bufsize(const char *qname, uint16_t qtype, uint16_t udp_size, gr_resp_t *out) {
    uint8_t req[512];
    size_t req_len = 0;
    build_dns_query(req, &req_len, 0x4592, qname, qtype, true);
    req[req_len - 8] = (uint8_t)(udp_size >> 8);   // OPT CLASS = UDP payload size (RFC 6891 §6.1.2)
    req[req_len - 7] = (uint8_t)(udp_size & 0xFF);
    gr_query_raw(req, req_len, qname, qtype, "192.0.2.100", false, out);
}

static const char *ZONE_SIG =
    "$ORIGIN sig.test.\n"
    "$TTL 300\n"
    "@ SOA ns1 h 1 3600 600 86400 60\n"
    "@ RRSIG SOA 8 2 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "@ NS ns1\n"
    "@ NS ns2.sub\n"
    "@ RRSIG NS 8 2 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "@ DNSKEY 256 3 8 AwEAAQ==\n"
    "@ RRSIG DNSKEY 8 2 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "@ DNSKEY 257 3 8 AwEAAw==\n"
    "@ RRSIG DNSKEY 8 2 300 20300101000000 20200101000000 54321 sig.test. BBBBBBBB\n"
    "@ NSEC mail.sig.test. NS SOA RRSIG NSEC DNSKEY\n"
    "@ RRSIG NSEC 8 2 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "mail A 192.0.2.2\n"
    "mail RRSIG A 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "mail NSEC ns1.sig.test. A RRSIG NSEC\n"
    "mail RRSIG NSEC 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "ns1 A 192.0.2.1\n"
    "ns1 RRSIG A 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "ns1 NSEC sub.sig.test. A AAAA RRSIG NSEC\n"
    "ns1 AAAA 2001:db8::1\n"
    "ns1 RRSIG NSEC 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "ns1 RRSIG AAAA 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "sub NS ns2.sub\n"
    "sub NSEC *.wild.sig.test. NS RRSIG NSEC\n"
    "sub RRSIG NSEC 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "ns2.sub A 192.0.2.53\n"
    /* not authoritative (below the cut at sub): must never be attached, even if present */
    "ns2.sub RRSIG A 8 4 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "*.wild A 192.0.2.80\n"
    "*.wild RRSIG A 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "*.wild TXT \"w\"\n"
    "*.wild RRSIG TXT 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n"
    "*.wild NSEC sig.test. A TXT RRSIG NSEC\n"
    "*.wild RRSIG NSEC 8 3 300 " P9_SIG " sig.test. AAAAAAAA\n";

static void test_dnssec_rrsig_sections(void) {
    printf("[TEST] DNSSEC: RRSIGs in Authority/Additional, RRsets before their RRSIGs, no duplicates (R-03, R-04, O-16, O-17)...\n");
    gr_setup("sig.test.", ZONE_SIG);
    gr_resp_t r;

    /* R-03: apex NS in Authority with RRSIG(NS); in-zone NS target in Additional with RRSIG(A)/RRSIG(AAAA);
     * glue below the cut (ns2.sub) without RRSIG (RFC 4035 §3.1.1, §2.2) */
    gr_query("mail.sig.test.", 1, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && !(g_gr.res[2] & 0x02));
    CHECK(&r, gr_count(&r, 1, 1) == 1 && gr_count(&r, 1, 46) == 1);
    CHECK(&r, gr_count(&r, 2, 2) == 2 && gr_count(&r, 2, 46) == 1);
    CHECK(&r, p9_count_owner(&r, 3, 1, "ns1.sig.test.") == 1 && p9_count_owner(&r, 3, 28, "ns1.sig.test.") == 1);
    CHECK(&r, p9_count_owner(&r, 3, 46, "ns1.sig.test.") == 2);
    CHECK(&r, p9_count_owner(&r, 3, 1, "ns2.sub.sig.test.") == 1 && p9_count_owner(&r, 3, 46, "ns2.sub.sig.test.") == 0);
    p9_expect_grouped(&r, 1, "mail A answer");
    p9_expect_grouped(&r, 2, "mail A authority");
    p9_expect_grouped(&r, 3, "mail A additional");

    /* DO=0: no RRSIG anywhere */
    gr_query("mail.sig.test.", 1, false, &r);
    CHECK(&r, gr_count(&r, 1, 46) == 0 && gr_count(&r, 2, 46) == 0 && gr_count(&r, 3, 46) == 0);
    CHECK(&r, p9_count_owner(&r, 3, 1, "ns1.sig.test.") == 1);

    /* R-04: ANY + DO=1: every RRSIG exactly once, after its RRset */
    gr_query("ns1.sig.test.", 255, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 1) == 1 && gr_count(&r, 1, 28) == 1 && gr_count(&r, 1, 47) == 1);
    CHECK(&r, gr_count(&r, 1, 46) == 3);
    p9_expect_grouped(&r, 1, "ANY answer");

    /* O-16: two DNSKEYs, then both RRSIG(DNSKEY) (key rollover state) */
    gr_query("sig.test.", 48, true, &r);
    CHECK(&r, gr_count(&r, 1, 48) == 2 && gr_count(&r, 1, 46) == 2);
    CHECK(&r, r.rr[0].type == 48 && r.rr[1].type == 48 && r.rr[2].type == 46 && r.rr[3].type == 46);
    p9_expect_grouped(&r, 1, "DNSKEY answer");

    /* O-17: wildcard NODATA; the next-closer cover and the wildcard-owner NSEC are the same RR: once, signed */
    gr_query("a.wild.sig.test.", 15, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, -1) == 0);
    EXPECT_NS(&r, "wildcard NODATA", "*.wild.sig.test.");
    CHECK(&r, gr_count(&r, 2, 46) == 2);   // RRSIG(SOA) + RRSIG(NSEC)
    p9_expect_grouped(&r, 2, "wildcard NODATA authority");

    /* wildcard ANY + DO=1: each RRset (A, TXT, ...) with the QNAME as owner, followed by its own RRSIG, once */
    gr_query("b.wild.sig.test.", 255, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 1) == 1 && gr_count(&r, 1, 16) == 1);
    CHECK(&r, gr_count(&r, 1, 46) == gr_count(&r, 1, -1) - gr_count(&r, 1, 46));
    CHECK(&r, p9_count_owner(&r, 1, -1, "b.wild.sig.test.") == gr_count(&r, 1, -1));
    p9_expect_grouped(&r, 1, "wildcard ANY answer");
    EXPECT_NS(&r, "wildcard ANY proof", "*.wild.sig.test.");

    /* QTYPE RRSIG: all RRSIGs at the name, each once, nothing else in the Answer */
    gr_query("ns1.sig.test.", 46, true, &r);
    CHECK(&r, gr_count(&r, 1, -1) == 3 && gr_count(&r, 1, 46) == 3);

    /* R-04 sibling: QTYPE A + MQTYPE RRSIG (RFC 10029, option 20): RRSIG(A) once (was written twice) */
    {
        uint8_t req[512];
        size_t req_len = 0;
        build_dns_query(req, &req_len, 0x4592, "ns1.sig.test.", 1, true);
        req[req_len - 1] = 6;   // OPT RDLEN
        const uint8_t mq[6] = { 0x00, 0x14, 0x00, 0x02, 0x00, 46 };
        memcpy(req + req_len, mq, sizeof(mq));
        req_len += sizeof(mq);
        g_gr.cfg.rfc10029_mqtype_enable = true;
        g_gr.cfg.max_mqtypes = 4;
        gr_query_raw(req, req_len, "ns1.sig.test.", 1, "192.0.2.100", false, &r);
        g_gr.cfg.rfc10029_mqtype_enable = false;
        CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 1) == 1 && gr_count(&r, 1, 46) == 3 && gr_count(&r, 1, -1) == 4);
        p9_expect_grouped(&r, 2, "MQTYPE authority");
    }

    /* referral to sub: NS unsigned; the NSEC proving the missing DS; glue without RRSIG */
    gr_query("host.sub.sig.test.", 1, true, &r);
    CHECK(&r, !r.aa && gr_count(&r, 2, 2) == 1 && gr_count(&r, 2, 47) == 1 && gr_count(&r, 2, 46) == 1);
    CHECK(&r, p9_count_owner(&r, 3, 1, "ns2.sub.sig.test.") == 1 && gr_count(&r, 3, 46) == 0);
    zone_arena_destroy(&g_gr.arena);
    printf("  -> sections signed, RRsets contiguous, no duplicate RRSIG/NSEC.\n");
}

/* Zone for the size limits: `long_at` selects the RRSIG with a 420-octet signature. */
static void p9_sigb_zone(char *buf, size_t cap, int long_at) {
    char lsig[561];
    memset(lsig, 'A', 560);
    lsig[560] = '\0';
    snprintf(buf, cap,
             "$ORIGIN sigb.test.\n$TTL 300\n"
             "@ SOA ns1 h 1 3600 600 86400 60\n"
             "@ RRSIG SOA 8 2 300 " P9_SIG " sigb.test. AAAAAAAA\n"
             "@ NS ns1\n"
             "@ RRSIG NS 8 2 300 " P9_SIG " sigb.test. %s\n"
             "@ NSEC mail.sigb.test. NS SOA RRSIG NSEC\n"
             "@ RRSIG NSEC 8 2 300 " P9_SIG " sigb.test. AAAAAAAA\n"
             "mail A 192.0.2.2\n"
             "mail RRSIG A 8 3 300 " P9_SIG " sigb.test. AAAAAAAA\n"
             "mail NSEC ns1.sigb.test. A RRSIG NSEC\n"
             "mail RRSIG NSEC 8 3 300 " P9_SIG " sigb.test. AAAAAAAA\n"
             "ns1 A 192.0.2.1\n"
             "ns1 RRSIG A 8 3 300 " P9_SIG " sigb.test. %s\n"
             "ns1 NSEC sigb.test. A RRSIG NSEC\n"
             "ns1 RRSIG NSEC 8 3 300 " P9_SIG " sigb.test. %s\n",
             long_at == 1 ? lsig : "AAAAAAAA", long_at == 0 ? lsig : "AAAAAAAA", long_at == 2 ? lsig : "AAAAAAAA");
}

static void test_dnssec_rrsig_size_limits(void) {
    printf("[TEST] DNSSEC: RRSIG that does not fit: Additional dropped without TC, Authority/proof -> TC (R-03)...\n");
    static char zone[4096];
    gr_resp_t r;

    /* Additional RRSIG too large for 512 octets: RRSIG dropped, the A kept, no TC (RFC 4035 §3.1.1) */
    p9_sigb_zone(zone, sizeof(zone), 0);
    gr_setup("sigb.test.", zone);
    p9_query_bufsize("mail.sigb.test.", 1, 512, &r);
    CHECK(&r, !(g_gr.res[2] & 0x02) && r.rcode == 0);
    CHECK(&r, gr_count(&r, 2, 46) == 1 && p9_count_owner(&r, 3, 1, "ns1.sigb.test.") == 1 && gr_count(&r, 3, 46) == 0);
    p9_query_bufsize("mail.sigb.test.", 1, 4096, &r);   // with room the RRSIG is there
    CHECK(&r, gr_count(&r, 3, 46) == 1);
    zone_arena_destroy(&g_gr.arena);

    /* Authority RRSIG(NS) too large: TC=1 and no unsigned-looking partial RRSIG set */
    p9_sigb_zone(zone, sizeof(zone), 1);
    gr_setup("sigb.test.", zone);
    p9_query_bufsize("mail.sigb.test.", 1, 512, &r);
    CHECK(&r, (g_gr.res[2] & 0x02) && gr_count(&r, 2, 46) == 0);
    zone_arena_destroy(&g_gr.arena);

    /* NXDOMAIN proof does not fit (decision 2): proof removed and TC=1 */
    p9_sigb_zone(zone, sizeof(zone), 2);
    gr_setup("sigb.test.", zone);
    p9_query_bufsize("nx.sigb.test.", 1, 512, &r);
    CHECK(&r, r.rcode == 3 && (g_gr.res[2] & 0x02) && gr_count(&r, 2, 47) == 0);
    p9_query_bufsize("nx.sigb.test.", 1, 4096, &r);
    CHECK(&r, r.rcode == 3 && !(g_gr.res[2] & 0x02) && gr_count(&r, 2, 47) == 2);
    zone_arena_destroy(&g_gr.arena);
    printf("  -> size limits handled per RFC 4035 3.1.1.\n");
}

/* R-31: hashes of the names below with salt 0xCD x 255, 0 iterations, and with salt AA11, from BIND's nsec3hash
 * (an implementation independent of the code under test). */
#define S255_APEX "FHHUD9MMO2DP7JQBCVO2D6EO8PAF50R8"   /* s255.test */
#define S255_NS1  "9E66AP5OEAJKNL9SF6C0FFQAQMIH9IU9"   /* ns1.s255.test */
#define S255_WWW  "KH9DH759AS7CLAE5P98T19H8AV5NMQ8C"   /* www.s255.test */
/* nx.s255.test = E36KCAH2..., *.s255.test = UPV5HC80... */
#define AA11_APEX "7TM0UC4ORAKQGRN5MFQR43L9JNFVEJJB"   /* s255.test, salt AA11 */
#define AA11_NS1  "PJN6RTSF7UFE0DU85ARMFPRPDAMR4BI5"   /* ns1.s255.test, salt AA11 */

static void p9_s255_zone(char *buf, size_t cap, const char *params) {
    char s[511];
    for (int i = 0; i < 255; i++) memcpy(s + 2 * i, "CD", 2);
    s[510] = '\0';
    char p[2048];
    snprintf(p, sizeof(p), params, s);   /* params may use %s for the 255-octet salt */
    snprintf(buf, cap,
             "$ORIGIN s255.test.\n$TTL 300\n"
             "@ SOA ns1 h 1 3600 600 86400 60\n"
             "@ NS ns1\n"
             "%s"
             "ns1 A 192.0.2.1\n"
             "www A 192.0.2.2\n"
             S255_APEX " NSEC3 1 0 0 %s " S255_WWW " NS SOA RRSIG NSEC3PARAM\n"
             S255_WWW " NSEC3 1 0 0 %s " S255_NS1 " A RRSIG\n"
             S255_NS1 " NSEC3 1 0 0 %s " S255_APEX " A RRSIG\n"
             /* a second chain with salt AA11 that is incomplete (its next owner does not exist) */
             AA11_APEX " NSEC3 1 0 0 AA11 " AA11_NS1 " NS SOA RRSIG NSEC3PARAM\n",
             p, s, s, s);
}

static void p9_expect_s255_nxdomain(const char *what) {
    gr_resp_t r;
    gr_query("nx.s255.test.", 1, true, &r);
    static const char *const want[] = { S255_APEX ".s255.test.", S255_NS1 ".s255.test.", S255_WWW ".s255.test." };
    CHECK(&r, r.rcode == 3);
    expect_owner_set(&r, 2, 50, want, 3, false, what);
    gr_query("www.s255.test.", 15, true, &r);   // NODATA: the matching NSEC3 only
    static const char *const want_nd[] = { S255_WWW ".s255.test." };
    CHECK(&r, r.rcode == 0);
    expect_owner_set(&r, 2, 50, want_nd, 1, false, what);
}

static void test_nsec3_params_selection(void) {
    printf("[TEST] DNSSEC: NSEC3PARAM choice, 255-octet salt, Flags != 0 ignored (R-31)...\n");
    static char zone[8192];
    const nsec3_params_t *a = &g_gr.arena.nsec3_active;

    /* 255-octet salt (RFC 5155 §3.1.5): hashes with the whole salt (was truncated to 64 octets) */
    p9_s255_zone(zone, sizeof(zone), "@ NSEC3PARAM 1 0 0 %s\n");
    gr_setup("s255.test.", zone);
    assert(a->param && a->salt_len == 255 && a->salt[254] == 0xCD && a->chain && a->chain->count == 3);
    p9_expect_s255_nxdomain("255-octet salt");
    zone_arena_destroy(&g_gr.arena);

    /* RFC 5155 §4.1.2: an NSEC3PARAM with Flags 1 listed first MUST be ignored */
    p9_s255_zone(zone, sizeof(zone), "@ NSEC3PARAM 1 1 0 AA11\n@ NSEC3PARAM 1 0 0 %s\n");
    gr_setup("s255.test.", zone);
    assert(a->param && a->salt_len == 255);
    p9_expect_s255_nxdomain("flags 1 first");
    zone_arena_destroy(&g_gr.arena);

    /* §7.3: two usable NSEC3PARAMs; the first (AA11) has an incomplete chain, the complete one is chosen */
    p9_s255_zone(zone, sizeof(zone), "@ NSEC3PARAM 1 0 0 AA11\n@ NSEC3PARAM 1 0 0 %s\n");
    gr_setup("s255.test.", zone);
    assert(a->param && a->salt_len == 255 && a->chain && a->chain->count == 3);
    p9_expect_s255_nxdomain("incomplete first chain");
    zone_arena_destroy(&g_gr.arena);

    /* the incomplete chain is still used when it is the only one (with the parameters of its NSEC3PARAM) */
    p9_s255_zone(zone, sizeof(zone), "@ NSEC3PARAM 1 0 0 AA11\n");
    gr_setup("s255.test.", zone);
    assert(a->param && a->salt_len == 2 && a->salt[0] == 0xAA && a->salt[1] == 0x11 && a->chain->count == 1);
    zone_arena_destroy(&g_gr.arena);

    /* no usable NSEC3PARAM (only Flags 1; a 256-octet salt; an odd-length salt; hash algorithm 2): no NSEC3 proof */
    const char *const unusable[] = { "@ NSEC3PARAM 1 1 0 %s\n", "@ NSEC3PARAM 1 0 0 %sCD\n", "@ NSEC3PARAM 1 0 0 ABC\n",
                                     "@ NSEC3PARAM 2 0 0 %s\n" };
    for (size_t i = 0; i < sizeof(unusable) / sizeof(unusable[0]); i++) {
        p9_s255_zone(zone, sizeof(zone), unusable[i]);
        gr_setup("s255.test.", zone);
        assert(a->param == NULL);
        gr_resp_t r;
        gr_query("nx.s255.test.", 1, true, &r);
        CHECK(&r, r.rcode == 3 && gr_count(&r, 2, 50) == 0 && gr_count(&r, 2, 6) == 1);
        zone_arena_destroy(&g_gr.arena);
    }

    /* hex_to_bytes(): strict, never truncates */
    uint8_t out[255];
    assert(hex_to_bytes("", out, sizeof(out)) == 0 && hex_to_bytes("-", out, sizeof(out)) == 0);
    assert(hex_to_bytes("aB0f", out, 2) == 2 && out[0] == 0xAB && out[1] == 0x0F);
    assert(hex_to_bytes("aB0f", out, 1) == (size_t)-1);
    assert(hex_to_bytes("aB0", out, sizeof(out)) == (size_t)-1);
    assert(hex_to_bytes("zz", out, sizeof(out)) == (size_t)-1);
    assert(hex_to_bytes("a b", out, sizeof(out)) == (size_t)-1);
    printf("  -> NSEC3 parameters chosen per RFC 5155 4.1.2 / 7.3; 255-octet salt hashed in full.\n");
}

/* R-32: several zones in one view (parent pn.test., children sec. and ins.pn.test., other.test.) */
static struct {
    zone_arena_t arena[5];
    zone_db_entry_t entry[5];
    zone_db_entry_t *entries[5];
    char *acl[1];
    view_snapshot_t view;
    zone_db_snapshot_t snap;
    server_config_t cfg;
    uint8_t res[4096];
} g_mz;

static void mz_reset(void) {
    memset(&g_mz, 0, sizeof(g_mz));
    g_mz.acl[0] = (char *)"any";
    g_mz.view.name = "default";
    g_mz.view.entries = g_mz.entries;
    g_mz.view.match_clients = g_mz.acl;
    g_mz.view.match_clients_count = 1;
    g_mz.snap.views = &g_mz.view;
    g_mz.snap.view_count = 1;
}

static void mz_add(const char *origin, const char *text) {
    size_t i = g_mz.view.zone_count++;
    zone_arena_init(&g_mz.arena[i]);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = origin, .is_standalone_mode = true, .err_out = &err };
    char *buf = arena_strdup(&g_mz.arena[i], text);
    assert(buf && parse_zone_fast(buf, strlen(buf), &g_mz.arena[i], &ctx) >= 0);
    assert(build_zone_index(&g_mz.arena[i], true) == 0);
    strncpy(g_mz.entry[i].domain, origin, sizeof(g_mz.entry[i].domain) - 1);
    g_mz.entry[i].kind = ZONE_KIND_PRIMARY;
    atomic_store_explicit(&g_mz.entry[i].rcu.active, &g_mz.arena[i], memory_order_release);
    g_mz.entries[i] = &g_mz.entry[i];
}

static void mz_free(void) {
    for (size_t i = 0; i < g_mz.view.zone_count; i++) zone_arena_destroy(&g_mz.arena[i]);
}

static void mz_query(const char *qname, uint16_t qtype, bool dnssec_ok, gr_resp_t *out) {
    uint8_t req[512];
    size_t req_len = 0;
    build_dns_query(req, &req_len, 0x4592, qname, qtype, dnssec_ok);
    compress_ctx_t comp;
    memset(&comp, 0, sizeof(comp));
    compress_ctx_init_packet(&comp);
    rate_limit_config_t *rrl_out = NULL;
    zone_db_entry_t *matched = NULL;
    int n = process_dns_query_impl(req, req_len, g_mz.res, sizeof(g_mz.res), qname, qtype, "192.0.2.100", &comp,
                                   false, &rrl_out, &g_mz.snap, &g_mz.cfg, &matched);
    assert(n >= DNS_HEADER_SIZE && gr_parse(g_mz.res, (size_t)n, out));
}

static const char *ZONE_PN =
    "$ORIGIN pn.test.\n$TTL 300\n"
    "@ SOA ns1 h 1 3600 600 86400 60\n"
    "@ RRSIG SOA 8 2 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "@ NS ns1\n"
    "@ RRSIG NS 8 2 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "@ NSEC ins.pn.test. NS SOA RRSIG NSEC\n"
    "@ RRSIG NSEC 8 2 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "ins NS ns1.ins\n"
    "ins NSEC ns1.pn.test. NS RRSIG NSEC\n"
    "ins RRSIG NSEC 8 3 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "ns1.ins A 192.0.2.54\n"
    "ns1 A 192.0.2.1\n"
    "ns1 RRSIG A 8 3 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "ns1 NSEC sec.pn.test. A RRSIG NSEC\n"
    "ns1 RRSIG NSEC 8 3 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "sec NS ns1.sec\n"
    "sec DS 12345 13 2 2BB1834370273412E81E3272C18B868FD63804EB61A086C38D04FF2DEDFE2516\n"
    "sec RRSIG DS 8 3 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "sec NSEC pn.test. NS DS RRSIG NSEC\n"
    "sec RRSIG NSEC 8 3 300 " P9_SIG " pn.test. AAAAAAAA\n"
    "ns1.sec A 192.0.2.53\n";
static const char *ZONE_SEC =
    "$ORIGIN sec.pn.test.\n$TTL 300\n@ SOA ns1 h 7 3600 600 86400 60\n@ NS ns1\nns1 A 192.0.2.53\n"
    "x CNAME sec.pn.test.\n";
static const char *ZONE_INS =
    "$ORIGIN ins.pn.test.\n$TTL 300\n@ SOA ns1 h 7 3600 600 86400 60\n@ NS ns1\nns1 A 192.0.2.54\n";
static const char *ZONE_OTHER =
    "$ORIGIN other.test.\n$TTL 300\n@ SOA ns1 h 1 3600 600 86400 60\n@ NS ns1\nns1 A 192.0.2.9\n"
    "alias CNAME sec.pn.test.\n";

static void test_ds_from_parent_zone(void) {
    printf("[TEST] DNSSEC: DS at a child apex answered from the hosted parent (R-32)...\n");
    gr_resp_t r;
    mz_reset();
    mz_add("sec.pn.test.", ZONE_SEC);   // children first: the order of the view must not matter
    mz_add("ins.pn.test.", ZONE_INS);
    mz_add("pn.test.", ZONE_PN);
    mz_add("other.test.", ZONE_OTHER);

    /* signed parent has the DS: DS + RRSIG(DS) from the parent (RFC 4035 §3.1.4.1) */
    mz_query("sec.pn.test.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && gr_count(&r, 1, 43) == 1 && gr_count(&r, 1, 46) == 1);
    CHECK(&r, p9_count_owner(&r, 2, 2, "pn.test.") == 1);   // the parent's apex NS, not the child's
    mz_query("sec.pn.test.", 43, false, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 43) == 1 && gr_count(&r, 1, 46) == 0);

    /* no DS in the parent: NODATA with the parent's SOA and the parent's NSEC for ins.pn.test. */
    mz_query("ins.pn.test.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && gr_count(&r, 1, -1) == 0);
    CHECK(&r, p9_count_owner(&r, 2, 6, "pn.test.") == 1 && p9_count_owner(&r, 2, 47, "ins.pn.test.") == 1);

    /* other types at the child apex still come from the child */
    mz_query("sec.pn.test.", 6, false, &r);
    CHECK(&r, gr_count(&r, 1, 6) == 1 && p9_count_owner(&r, 1, 6, "sec.pn.test.") == 1);

    /* CNAME from another zone and from inside the child to the child apex: the DS still comes from the parent */
    mz_query("alias.other.test.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 5) == 1 && p9_count_owner(&r, 1, 43, "sec.pn.test.") == 1);
    mz_query("x.sec.pn.test.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && gr_count(&r, 1, 5) == 1 && p9_count_owner(&r, 1, 43, "sec.pn.test.") == 1);

    /* zone selection (also used by the RRL counters and the program/forward routing) */
    assert(find_zone_for_query(&g_mz.view, "sec.pn.test.", 43) == &g_mz.entry[2]);
    assert(find_zone_for_query(&g_mz.view, "SEC.PN.TEST", 43) == &g_mz.entry[2]);
    assert(find_zone_for_query(&g_mz.view, "sec.pn.test.", 1) == &g_mz.entry[0]);
    assert(find_zone_for_query(&g_mz.view, "www.sec.pn.test.", 43) == &g_mz.entry[0]);
    assert(find_zone_for_query(&g_mz.view, "sec.pn.test.", 0) == &g_mz.entry[0]);    // not a QUERY
    assert(find_zone_for_query(&g_mz.view, "pn.test.", 43) == &g_mz.entry[2]);       // no parent served
    g_mz.entry[2].kind = ZONE_KIND_FORWARD;                                            // a forward parent is not used
    assert(find_zone_for_query(&g_mz.view, "sec.pn.test.", 43) == &g_mz.entry[0]);
    g_mz.entry[2].kind = ZONE_KIND_PROGRAM;                                            // a program parent is
    assert(find_zone_for_query(&g_mz.view, "sec.pn.test.", 43) == &g_mz.entry[2]);
    mz_free();

    /* parent not served: the child answers authoritatively with NODATA from its apex (§3.1.4.1) */
    mz_reset();
    mz_add("sec.pn.test.", ZONE_SEC);
    mz_query("sec.pn.test.", 43, true, &r);
    CHECK(&r, r.rcode == 0 && r.aa && gr_count(&r, 1, -1) == 0 && p9_count_owner(&r, 2, 6, "sec.pn.test.") == 1);
    mz_free();

    /* a single-label child uses the root zone as its parent */
    zone_db_entry_t root, tld;
    memset(&root, 0, sizeof(root));
    memset(&tld, 0, sizeof(tld));
    strcpy(root.domain, ".");
    strcpy(tld.domain, "test.");
    zone_db_entry_t *ents[2] = { &tld, &root };
    view_snapshot_t v;
    memset(&v, 0, sizeof(v));
    v.entries = ents;
    v.zone_count = 2;
    assert(find_zone_for_query(&v, "test.", 43) == &root);
    assert(find_zone_for_query(&v, "test.", 2) == &tld);
    assert(find_zone_for_query(&v, ".", 43) == &root);
    printf("  -> DS comes from the parent when it is served, otherwise from the child apex.\n");
}

int main(void) {
    printf("=== Starting DNSSEC Negative-Proof Tests ===\n");
    test_dnssec_wire_decode_roundtrip();
    test_dnssec_wire_decode_usable();
    test_dnssec_wire_decode_malformed();
    test_nsec3_index_matches_linear_scan();
    test_nsec3_index_two_chains();
    test_nsec3_index_broken_chain();
    test_nsec3_index_performance();
    test_nsec3_hash_escaped_names();
    test_nsec3_rfc5155_appendix_b();
    test_nsec_rfc4035_appendix_b();
    test_nsec3_params_selection();
    test_dnssec_rrsig_sections();
    test_dnssec_rrsig_size_limits();
    test_ds_from_parent_zone();
    printf("=== All DNSSEC Negative-Proof Tests PASSED ===\n");
    return 0;
}

/* broker_connect_opts(): the TCP socket options are applied by the real broker only; the mock ignores them. */
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len,
                        const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}

/* send_tcp_dns_message(): goes through the send_tcp_robust() mock above (length prefix, then message) */
ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len) {
    uint8_t prefix[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    if (send_tcp_robust(fd, prefix, 2) < 0) return -1;
    if (send_tcp_robust(fd, msg, len) < 0) return -1;
    return (ssize_t)len;
}
