/*
 * fuzz_zone_image_validate.c - the input is the bytes of a zone image (as the store keeps them on disk); the contract
 * of zone_image_validate() is that an image it accepts can be read by every reader without any further check:
 *
 *   1. zone_image_validate() on an exact-size block must never read outside it, whatever the bytes are;
 *   2. when it returns 0, every accessor reads the image (zimg_walk(): names, RRs, extras, NSEC / NSEC3 indexes, zone level
 *      tables, thaw) and the lookups agree with the hash table and the canonical order (abort() when they do not: the
 *      validator let something through that it should have refused);
 *   3. and the query engine answers questions about the zone from it: the names of the image, names below and beside them,
 *      wildcard expansions, NSEC3-style hash labels, with and without DO, over UDP and TCP, with and without an ECS option,
 *      for clients inside and outside the tags (the zone is published as the only zone of a view, as a store attach does).
 *
 * Seeds: tests/fuzz/generate_zone_image_corpus.c writes images of the zone files under tests/zones and of a few hand-made zones (NSEC3
 * chain, tinydns locations, tags, interleaved owners).  The custom mutator keeps the size (the sections are laid out
 * exactly, so an insertion or a deletion is refused at once) and changes bytes and 32-bit words, mostly in place.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../../dns_wire.h"
#include "../../dns_zone_parser.h"
#include "../../dns_zone_image.h"
#include "../../dns_config_parser.h"
#include "../../dns_query_engine.h"
#include "../../dns_snapshot_rcu.h"
#include "../../dns_epoch_rcu.h"
#include "../../dns_rrl.h"
#include "../../dns_catalog_zone.h"
#include "../../dns_dnstap.h"
#include "../../dns_edns_ecs.h"
#include "../../dns_dynamic_update.h"
#include "../../dns_axfr_ixfr.h"
#include "../../dns_server_internal.h"
#include "../zone_image_walk.h"

/* ---- the mocks the engine needs (the same as fuzz_query_engine.c) ---- */
_Atomic int g_control_kq = -1;
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
int broker_connect_opts(int family, int type, struct sockaddr *addr, size_t addr_len, const tcp_sockopts_t *tcp_opts) {
    (void)tcp_opts;
    return broker_connect(family, type, addr, addr_len);
}
ssize_t send_tcp_dns_message(int fd, const uint8_t *msg, size_t len) {
    uint8_t prefix[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xFF)};
    if (send_tcp_robust(fd, prefix, 2) < 0) return -1;
    if (send_tcp_robust(fd, msg, len) < 0) return -1;
    return (ssize_t)len;
}

/* ---- the zone: one entry of one view; its version points at the image under test ---- */
static zone_version_t g_ver;
static zone_db_entry_t g_entry;
static zone_db_entry_t *g_entry_ptrs[1];
static char g_domain[DNS_NAME_TEXT_SIZE];
static char *g_any_acl[1] = { (char *)"any" };
static view_snapshot_t g_views[1];
static zone_db_snapshot_t g_snap;
static server_config_t g_cfg;
static bool g_ready;

static void init_engine(void) {
    if (g_ready) return;
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.rfc10029_mqtype_enable = true;
    g_cfg.max_mqtypes = 4;
    g_cfg.minimal_any = true;
    g_cfg.minimal_any_ttl = 60;
    /* the ECS option of a query is used (client 127.0.0.1 is a trusted resolver), so the zone's ECS tags are read */
    g_cfg.ecs_enable = true;
    g_cfg.ecs_trusted_resolvers = g_any_acl;
    g_cfg.ecs_trusted_resolvers_count = 1;
    atomic_store_explicit(&g_config_db.active, &g_cfg, memory_order_release);
    response_cache_init(256 * 1024);
    memset(&g_views[0], 0, sizeof(g_views[0]));
    g_views[0].name = "default";
    g_views[0].match_clients = g_any_acl;
    g_views[0].match_clients_count = 1;
    memset(&g_snap, 0, sizeof(g_snap));
    g_snap.views = g_views;
    g_snap.view_count = 1;
    g_ready = true;
}

/* publish the image as the zone `domain` (a store attach: the entry, its version, the directory of the view) */
static bool publish(const zone_image_t *img, const char *domain) {
    snprintf(g_domain, sizeof(g_domain), "%s", domain);
    memset(&g_entry, 0, sizeof(g_entry));
    g_entry.domain = g_domain;
    snprintf(g_entry.view_name, sizeof(g_entry.view_name), "default");
    memset(&g_ver, 0, sizeof(g_ver));
    g_ver.image = (zone_image_t *)(uintptr_t)img;
    g_ver.rcache_ok = false;
    g_ver.heap = false;
    atomic_store_explicit(&g_entry.rcu.active, &g_ver, memory_order_release);
    g_entry_ptrs[0] = &g_entry;
    return view_set_entries(&g_views[0], g_entry_ptrs, 1);
}

/* ---- queries ---- */
static uint64_t g_rng;
static uint32_t rnd(void) {
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 16);
}

static size_t build_query(uint8_t *q, size_t cap, const char *name, uint16_t qtype, bool edns, bool dobit, bool ecs, uint8_t ecs_prefix) {
    if (cap < 64) return 0;
    memset(q, 0, 12);
    q[0] = 0x12; q[1] = 0x34; q[2] = 0x01;
    q[5] = 1;
    long w = write_uncompressed_name_ext(q, 12, cap - 40, name, false);
    if (w <= 0) return 0;
    size_t p = 12 + (size_t)w;
    q[p++] = (uint8_t)(qtype >> 8); q[p++] = (uint8_t)qtype; q[p++] = 0; q[p++] = 1;
    if (edns) {
        q[11] = 1;
        q[p++] = 0; q[p++] = 0; q[p++] = 41;         /* root, OPT */
        q[p++] = 0x10; q[p++] = 0;                    /* UDP size 4096 */
        q[p++] = 0; q[p++] = 0; q[p++] = dobit ? 0x80 : 0; q[p++] = 0;
        if (ecs) {
            q[p++] = 0; q[p++] = 11;                  /* RDLENGTH: option 4 + 4 + 3 */
            q[p++] = 0; q[p++] = 8; q[p++] = 0; q[p++] = 7;
            q[p++] = 0; q[p++] = 1; q[p++] = ecs_prefix; q[p++] = 0;
            q[p++] = 198; q[p++] = 51; q[p++] = 100;
        } else {
            q[p++] = 0; q[p++] = 0;
        }
    }
    return p;
}

static void ask(const char *name, uint16_t qtype, unsigned mode) {
    static const char *clients[] = { "127.0.0.1", "192.0.2.77", "10.1.2.3", "198.51.100.9", "2001:db8::5" };
    uint8_t q[1500], resp[4096];
    size_t ql = build_query(q, sizeof(q), name, qtype, (mode & 1) != 0, (mode & 2) != 0, (mode & 4) != 0, (uint8_t)(mode & 8 ? 24 : 32));
    if (ql == 0) return;
    char qn[DNS_NAME_TEXT_SIZE];
    uint16_t qt = 0, qc = 1;
    size_t qend = 0;
    if (!parse_query_question_fast(q, ql, qn, sizeof(qn), &qt, &qc, &qend)) return;
    compress_ctx_t cc;
    compress_ctx_init(&cc);
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    query_set_local_addr(&local);
    int rl = process_dns_query(q, ql, resp, sizeof(resp), qn, qt, clients[(mode >> 4) % 5], &cc, (mode & 0x100) != 0, NULL, &g_snap);
    if (rl > 12 && !(resp[2] & 0x80)) abort();   /* a response has QR set */
}

static void run_queries(const zone_image_t *img) {
    static const uint16_t types[] = { 1, 28, 2, 6, 5, 15, 16, 255, 43, 48, 47, 46, 50, 51, 39, 33, 65401, 257 };
    char name[DNS_NAME_TEXT_SIZE + 64];
    const char *apex = g_domain;
    unsigned budget = 96;
    /* the names of the image, with the types they hold and a few others */
    uint32_t n = img->n_names;
    for (unsigned i = 0; i < 12 && n && budget > 8; i++) {
        uint32_t id = rnd() % n;
        const char *t = zone_image_name_text(img, id);
        uint32_t first = zone_image_name_first_rr(img, id), cnt = zone_image_name_rr_count(img, id);
        for (uint32_t k = first; k < first + cnt && k < first + 4; k++) { ask(t, zone_image_rr_type(img, k), rnd() & 0x1FF); budget--; }
        for (int j = 0; j < 3; j++) { ask(t, types[rnd() % (sizeof(types) / sizeof(types[0]))], rnd() & 0x1FF); budget--; }
        /* below it, a wildcard's expansion, beside it */
        snprintf(name, sizeof(name), "zz-%u.%s", rnd() % 1000, t);
        ask(name, 1, rnd() & 0x1FF); ask(name, 16, rnd() & 0x1FF); budget -= 2;
        if (t[0] == '*' && t[1] == '.') {
            snprintf(name, sizeof(name), "w%u%s", rnd() % 100, t + 1);
            ask(name, types[rnd() % (sizeof(types) / sizeof(types[0]))], rnd() & 0x1FF); budget--;
        }
        snprintf(name, sizeof(name), "a.b.%s", t);
        ask(name, 28, rnd() & 0x1FF); budget--;
    }
    /* the apex, a name that does not exist, a hash-label owner (NSEC3 matching / covering), the root */
    for (size_t j = 0; j < sizeof(types) / sizeof(types[0]); j++) ask(apex, types[j], (unsigned)(j * 37u + 3u) & 0x1FF);
    snprintf(name, sizeof(name), "no-such-name.%s", apex);
    for (unsigned j = 0; j < 4; j++) ask(name, types[j], 3 | (j << 4));
    snprintf(name, sizeof(name), "%08x%08x%08x%08x.%s", rnd(), rnd(), rnd(), rnd(), apex);
    ask(name, 1, 3); ask(name, 50, 3);
    snprintf(name, sizeof(name), "0000000000000000000000000000000%c.%s", "0123456789ABCDEFGHIJKLMNOPQRSTUV"[rnd() % 32], apex);
    ask(name, 1, 3);
    ask(".", 6, 3);
    ask("\\000.\\255.", 1, 3);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8 || size > (4u << 20)) return 0;
    uint8_t *buf = malloc(size);          /* exactly `size` octets, malloc() alignment (>= 8) */
    if (!buf) return 0;
    memcpy(buf, data, size);
    char why[200];
    if (zone_image_validate(buf, size, why, sizeof(why)) == 0) {
        const zone_image_t *img = (const zone_image_t *)(const void *)buf;
        unsigned bad = 0;
        (void)zimg_walk(img, &bad);
        if (bad) abort();                 /* validated, yet a lookup disagrees with the tables */
        init_engine();
        g_rng = 0x9E3779B97F4A7C15ull ^ size;
        for (size_t i = 0; i < size && i < 64; i++) g_rng = g_rng * 1099511628211ull + data[i];
        if (g_rng == 0) g_rng = 1;
        /* the zone name: the apex, else the first owner */
        const char *domain = "example.com.";
        if (img->apex_name != ZONE_IMAGE_NONE) domain = zone_image_name_text(img, img->apex_name);
        else if (img->n_names) domain = zone_image_name_text(img, 0);
        if (publish(img, domain)) run_queries(img);
        view_clear_dir(&g_views[0]);
    }
    free(buf);
    return 0;
}

/* The mutator keeps the length: the sections are laid out exactly, so any insertion or deletion is refused at the first
 * check and never reaches the rest.  Operations: flip bits, set an aligned 32-bit word to an interesting value, copy one
 * word over another, swap two words, move a block; now and then the stock mutator.  The size field is repaired most of the
 * time so a changed count or offset is judged by the checks behind it. */
extern size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);

static uint32_t xorshift(uint64_t *r) {
    *r ^= *r << 13;
    *r ^= *r >> 7;
    *r ^= *r << 17;
    return (uint32_t)(*r >> 11);
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
    uint64_t r = ((uint64_t)seed << 32 | seed) ^ 0xD1B54A32D192ED03ull;
    #define NEXT() xorshift(&r)
    if (size < sizeof(zone_image_t)) return LLVMFuzzerMutate(data, size, max_size);
    unsigned rounds = 1 + NEXT() % 3;
    for (unsigned i = 0; i < rounds; i++) {
        uint32_t words = (uint32_t)(size / 4);
        switch (NEXT() % 7) {
        case 0: data[NEXT() % size] ^= (uint8_t)(1u << (NEXT() % 8)); break;
        case 1: data[NEXT() % size] = (uint8_t)NEXT(); break;
        case 2: {
            static const uint32_t v[] = { 0, 1, 2, 3, 7, 8, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFF8u, 65535, 65536 };
            uint32_t x = NEXT() % 4 == 0 ? (uint32_t)size + (NEXT() % 3) * 8 - 8 : v[NEXT() % (sizeof(v) / sizeof(v[0]))];
            memcpy(data + (size_t)(NEXT() % words) * 4, &x, 4);
            break;
        }
        case 3: {
            uint32_t x;
            memcpy(&x, data + (size_t)(NEXT() % words) * 4, 4);
            memcpy(data + (size_t)(NEXT() % words) * 4, &x, 4);
            break;
        }
        case 4: {
            uint32_t a = NEXT() % words, b = NEXT() % words, x, y;
            memcpy(&x, data + (size_t)a * 4, 4); memcpy(&y, data + (size_t)b * 4, 4);
            memcpy(data + (size_t)a * 4, &y, 4); memcpy(data + (size_t)b * 4, &x, 4);
            break;
        }
        case 5: {
            size_t len = 1 + NEXT() % 64, from = NEXT() % size, to = NEXT() % size;
            if (len > size - from) len = size - from;
            if (len > size - to) len = size - to;
            memmove(data + to, data + from, len);
            break;
        }
        default: {
            size_t n = LLVMFuzzerMutate(data, size, max_size);
            n &= ~(size_t)7;
            if (n >= sizeof(zone_image_t)) size = n;
            break;
        }
        }
    }
    if (size % 8 == 0 && NEXT() % 8 != 0) {
        uint32_t ts = (uint32_t)size;
        memcpy(data + offsetof(zone_image_t, total_size), &ts, 4);
    }
    #undef NEXT
    return size;
}
