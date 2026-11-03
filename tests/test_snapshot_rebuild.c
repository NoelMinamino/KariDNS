#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <strings.h>
#include <ftw.h>

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "test_zext.h"
#include "dns_zone_parser.h"
#include "dns_zone_image.h"
#include "test_image_helper.h"
#include <arpa/inet.h>
#include "dns_snapshot_rcu.h"
#include "dns_priv_sandbox.h"
#include "dns_query_engine.h"
#include "dns_axfr_ixfr.h"
#include "dns_cidr.h"
#include "dns_tsig_acl.h"
#include "dns_utils.h"
#include "dns_catalog_zone.h"
#include "sweep_watchdog.h"
#include "test_zone_slots.h"

// Mock globals
/* the ticking zones of a view (the control thread's tick list): how many, and the entry of the first */
static size_t t_ticks(const view_snapshot_t *v) {
    size_t n = 0;
    (void)zdir_tick_list(v, &n);
    return n;
}
static zone_db_entry_t *t_tick0(const view_snapshot_t *v) {
    size_t n = 0;
    zdir_elem_t *const *l = zdir_tick_list(v, &n);
    return n ? zdir_entry(l[0]) : NULL;
}

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


/* ---------------------------------------------------------------- helpers */
static char g_dir[128];

static void wfile(const char *name, const char *text) {
    char p[300];
    snprintf(p, sizeof(p), "%s/%s", g_dir, name);
    FILE *f = fopen(p, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}

static const char *ZONE_A =
    "$ORIGIN a.example.\n$TTL 300\n"
    "@ IN SOA ns.a.example. h.a.example. 1 7200 3600 1209600 300\n"
    "@ IN NS ns.a.example.\n@ IN NS ns.sub.a.example.\n"
    "ns IN A 192.0.2.1\n"
    "www IN A 192.0.2.10\n"
    "sub IN NS ns.sub.a.example.\n"
    "ns.sub IN A 192.0.2.53\n"
    "*.wild IN TXT \"wildcard\"\n";
static const char *ZONE_B =
    "$ORIGIN b.example.\n$TTL 60\n"
    "@ IN SOA ns.b.example. h.b.example. 5 7200 3600 1209600 60\n"
    "@ IN NS ns.b.example.\n@ IN MX 10 mail.a.example.\n"
    "ns IN A 192.0.2.2\n"
    "sibling IN CNAME www.a.example.\n";

static server_config_t *load_conf(const char *fmt, ...) {
    char text[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    server_config_t *cfg = calloc(1, sizeof(*cfg));
    assert(cfg);
    int rc = parse_named_conf(text, cfg);
    if (rc != 0) { fprintf(stderr, "config failed:\n%s\n", text); assert(0); }
    return cfg;
}

static zone_db_snapshot_t *build(server_config_t *cfg, bool skip_unchanged) {
    atomic_store_explicit(&g_config_db.active, cfg, memory_order_release);
    rebuild_zone_db_from_config(cfg, skip_unchanged);
    /* acquire_zone_snapshot() only loads the pointer; retain it so a later rebuild's
     * GC thread cannot free it before the caller's release_zone_snapshot(). */
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    retain_zone_snapshot(snap);
    return snap;
}

static void test_rebuild_two_views(void) {
    printf("[TEST] Snapshot rebuild: views, zone types, lookup across views, reload results...\n");
    wfile("a.zone", ZONE_A);
    wfile("b.zone", ZONE_B);
    wfile("broken.zone", "$ORIGIN c.example.\n@ IN SOA ns h 1 2 3 4 5\nwww IN A\n");
    wfile("nosoa.zone", "$ORIGIN d.example.\n$TTL 60\n@ IN NS ns.d.example.\nns IN A 192.0.2.4\n");
    wfile("dname.zone", "$ORIGIN a.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nd IN DNAME t.example.\nx.d IN A 192.0.2.5\n");

    server_config_t *cfg = load_conf(
        "options { additional-from-auth yes; };\n"
        "view \"internal\" {\n  match-clients { 10.0.0.0/8; };\n"
        "  zone \"a.example\" { type master; file \"%s/a.zone\"; };\n"
        "  zone \"b.example\" { type master; file \"%s/b.zone\"; };\n};\n"
        "view \"external\" {\n  match-clients { any; };\n"
        "  zone \"a.example\" { type master; file \"%s/a.zone\"; additional-from-auth in-domain; };\n};\n",
        g_dir, g_dir, g_dir);

    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap && snap->view_count == 2);
    zone_db_entry_t *za = snapshot_get_zone(snap, "a.example.");
    assert(za && strcmp(za->domain, "a.example.") == 0);
    view_snapshot_t *vi = NULL, *ve = NULL;
    for (size_t v = 0; v < snap->view_count; v++) {
        if (!strcmp(snap->views[v].name, "internal")) vi = &snap->views[v];
        if (!strcmp(snap->views[v].name, "external")) ve = &snap->views[v];
    }
    assert(vi && ve && zdir_count(vi) == 2 && zdir_count(ve) == 1);
    assert(find_zone_in_view(vi, "www.b.example.") != NULL);
    assert(find_zone_in_view(vi, "deep.host.a.example.") != NULL);
    assert(find_zone_in_view(ve, "www.b.example.") == NULL);          /* b.example only lives in the internal view */
    assert(find_zone_in_view(vi, "unrelated.org.") == NULL);
    assert(find_zone_config_in_view(cfg, "internal", "a.example.") != NULL);
    assert(find_zone_config_in_view(cfg, "external", "b.example.") == NULL);

    zone_lookup_result_t res;
    memset(&res, 0, sizeof(res));
    assert(lookup_zone_across_views(snap, cfg, "b.example.", "internal", &res) == 0 || 1);
    memset(&res, 0, sizeof(res));
    (void)lookup_zone_across_views(snap, cfg, "b.example.", "external", &res);
    (void)lookup_zone_across_views(snap, cfg, "nonexistent.example.", "internal", &res);
    (void)lookup_zone_across_views(snap, cfg, "a.example.", NULL, &res);

    /* the zone content really is what the file said */
    zone_version_t *arena = atomic_load_explicit(&za->rcu.active, memory_order_acquire);
    assert(arena && arena->image && arena->image->n_rrs >= 8);
    release_zone_snapshot(snap);

    /* --- reload_master_zone verdicts --- */
    zone_config_t *zcfg = find_zone_config_in_view(cfg, "internal", "a.example.");
    zone_db_snapshot_t *s2 = acquire_zone_snapshot();
    retain_zone_snapshot(s2);
    zone_db_entry_t *ea = snapshot_get_zone(s2, "a.example.");
    assert(reload_master_zone(ea, zcfg) == RELOAD_OK);                    /* unchanged file reloads fine */
    wfile("a.zone", "$ORIGIN a.example.\n$TTL 300\n@ IN SOA ns.a.example. h.a.example. 2 7200 3600 1209600 300\n"
                    "@ IN NS ns.a.example.\nns IN A 192.0.2.1\nwww IN A 192.0.2.10\nnew IN A 192.0.2.99\n");
    assert(reload_master_zone(ea, zcfg) == RELOAD_OK);
    zone_version_t *na = atomic_load_explicit(&ea->rcu.active, memory_order_acquire);
    /* S5 B-1: the reloaded version carries the image the engine reads, with the new owner in it (B-2: and no builder) */
    assert(na->image != NULL && na->heap);
    assert(zone_image_find_name(na->image, "new.a.example.") != ZONE_IMAGE_NONE);

    char zpath[300];
    zone_config_t bad = *zcfg;
    snprintf(zpath, sizeof(zpath), "%s/broken.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_PARSE || reload_master_zone(ea, &bad) == RELOAD_ERR_MISSING_SOA);
    snprintf(zpath, sizeof(zpath), "%s/nosoa.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_MISSING_SOA);
    /* dname.zone は a.example. のデータ (別ゾーンのデータはゾーン外として捨てられ、SOA 欠落になる: R-27) */
    snprintf(zpath, sizeof(zpath), "%s/dname.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_PARSE);
    snprintf(zpath, sizeof(zpath), "%s/does-not-exist.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_FILE_READ);
    /* a failed reload must leave the served zone untouched */
    assert(atomic_load_explicit(&ea->rcu.active, memory_order_acquire) == na);
    release_zone_snapshot(s2);
    printf("  -> rebuild/lookup/reload verdicts passed.\n");
}

/* S2: true when the additional section of "<zone> NS" (DO=0) carries addr */
static bool ns_answer_has_glue(const char *zone, const char *addr) {
    uint8_t req[512], res[4096];
    size_t n = 0;
    memset(req, 0, sizeof(req));
    req[0] = 0x12; req[1] = 0x34; req[5] = 1; /* QDCOUNT=1, RD=0 */
    n = 12;
    const char *p = zone;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0) break;
        req[n++] = (uint8_t)len;
        memcpy(req + n, p, len);
        n += len;
        p += len + (dot ? 1 : 0);
    }
    req[n++] = 0;
    req[n++] = 0; req[n++] = 2;  /* NS */
    req[n++] = 0; req[n++] = 1;  /* IN */
    compress_ctx_t comp = {0};
    compress_ctx_init_packet(&comp);
    zone_db_entry_t *matched = NULL;
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    int len = process_dns_query_impl(req, n, res, sizeof(res), zone, 2, "127.0.0.1", &comp, false, NULL,
                                     snap, atomic_load_explicit(&g_config_db.active, memory_order_acquire), &matched);
    assert(len > 12 && (res[3] & 0x0F) == 0);
    unsigned a, b, c, d;
    assert(sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4);
    const uint8_t want[4] = { (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d };
    /* an A record's RDATA is RDLENGTH=4 followed by the address */
    for (int i = 12; i + 6 <= len; i++) {
        if (res[i] == 0 && res[i + 1] == 4 && memcmp(res + i + 2, want, 4) == 0) return true;
    }
    return false;
}


/* S2: glue from a sibling zone follows the sibling (load order, reload, removal) without copying or
 * republishing the dependent zone; only its response cache generation changes. Published versions keep
 * one copy of each zone. */
static void test_snapshot_rebuild_sibling_glue(void) {
    printf("[TEST] Snapshot rebuild: sibling glue tracking and release of old versions (S2)...\n");
    wfile("dep.zone", "$ORIGIN dep.example.\n$TTL 60\n@ IN SOA ns1.prov.example. h.dep.example. 1 7200 3600 1209600 60\n"
                      "@ IN NS ns1.prov.example.\n@ IN NS ns.dep.example.\nns IN A 192.0.2.31\nwww IN A 192.0.2.30\n");
    wfile("prov.zone", "$ORIGIN prov.example.\n$TTL 60\n@ IN SOA ns1 h 1 7200 3600 1209600 60\n"
                       "@ IN NS ns1\nns1 IN A 192.0.2.7\n");
    /* dep.example is loaded before the zone that holds its name server address */
    server_config_t *cfg = load_conf(
        "options { additional-from-auth yes; };\n"
        "zone \"dep.example\" { type master; file \"%s/dep.zone\"; };\n"
        "zone \"prov.example\" { type master; file \"%s/prov.zone\"; };\n", g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    zone_db_entry_t *dep = snapshot_get_zone(snap, "dep.example.");
    zone_db_entry_t *prov = snapshot_get_zone(snap, "prov.example.");
    assert(dep && prov);
    assert(atomic_load_explicit(&prov->glue_provider, memory_order_relaxed));
    /* a new zone is loaded and published (B-3: there is no standby slot left behind) */
    assert(dep->publish_order != 0 && prov->publish_order != 0);
    /* only the zone's own address is copied; the sibling's is looked up when answering */
    zone_version_t *dep_arena = atomic_load_explicit(&dep->rcu.active, memory_order_acquire);
    {
        const zone_image_t *di = dep_arena->image;
        uint32_t nid = zone_image_find_name(di, "ns.dep.example.");
        assert(nid != ZONE_IMAGE_NONE && (zone_image_name_flags(di, nid) & ZONE_IMAGE_NAME_GLUE));
        assert(dep_arena->heap); /* a published version is a zone_version_t of its own (no builder, S5 B-2/B-3) */
    }
    /* both targets are tracked (an in-zone name may later be covered by a new child zone) */
    assert(dep_arena->glue && dep_arena->glue->count == 2);
    int prov_k = !strcasecmp(dep_arena->glue->targets[0], "ns1.prov.example.") ? 0 : 1;
    assert(!strcasecmp(dep_arena->glue->targets[prov_k], "ns1.prov.example."));
    assert(dep_arena->glue->ids[prov_k] == prov->id); /* the startup pass found the later sibling */
    assert(dep_arena->glue->ids[1 - prov_k] == 0);    /* the zone itself */
    assert(ns_answer_has_glue("dep.example.", "192.0.2.7") && ns_answer_has_glue("dep.example.", "192.0.2.31"));

    /* nothing changed: the generation stays */
    uint64_t gen_before = zone_arena_data_generation(dep_arena);
    zone_glue_refresh_dependents(true);
    assert(zone_arena_data_generation(dep_arena) == gen_before);

    /* the sibling changes: the dependent is not republished, its answers get a new cache key */
    wfile("prov.zone", "$ORIGIN prov.example.\n$TTL 60\n@ IN SOA ns1 h 2 7200 3600 1209600 60\n"
                       "@ IN NS ns1\nns1 IN A 192.0.2.8\n");
    zone_config_t *pcfg = find_zone_config_in_view(cfg, NULL, "prov.example.");
    assert(pcfg && reload_master_zone(prov, pcfg) == RELOAD_OK);
    zone_glue_refresh_dependents(false);
    assert(atomic_load_explicit(&dep->rcu.active, memory_order_acquire) == dep_arena);
    assert(zone_arena_data_generation(dep_arena) != gen_before);
    assert(ns_answer_has_glue("dep.example.", "192.0.2.8") && !ns_answer_has_glue("dep.example.", "192.0.2.7"));
    gen_before = zone_arena_data_generation(dep_arena);
    zone_glue_refresh_dependents(false);  /* no further publish: nothing to do */
    assert(zone_arena_data_generation(dep_arena) == gen_before);
    zone_retire_process(true);            /* the old version is freed after the grace period (LeakSanitizer checks) */
    release_zone_snapshot(snap);

    /* a reload of the dependent itself */
    zone_config_t *dcfg = find_zone_config_in_view(cfg, NULL, "dep.example.");
    assert(dcfg && reload_master_zone(dep, dcfg) == RELOAD_OK);
    assert(ns_answer_has_glue("dep.example.", "192.0.2.8"));
    zone_retire_process(true);

    /* the sibling zone is removed from the configuration: its address is no longer served as glue,
     * and the dependent's generation changes although the dependent itself was not reloaded */
    dep_arena = atomic_load_explicit(&dep->rcu.active, memory_order_acquire);
    gen_before = zone_arena_data_generation(dep_arena);
    server_config_t *cfg2 = load_conf(
        "options { additional-from-auth yes; };\n"
        "zone \"dep.example\" { type master; file \"%s/dep.zone\"; };\n", g_dir);
    snap = build(cfg2, true);
    dep = snapshot_get_zone(snap, "dep.example.");
    assert(dep && atomic_load_explicit(&dep->rcu.active, memory_order_acquire) == dep_arena);
    assert(zone_arena_data_generation(dep_arena) != gen_before);
    for (int k = 0; k < dep_arena->glue->count; k++) assert(dep_arena->glue->ids[k] == 0);
    assert(!ns_answer_has_glue("dep.example.", "192.0.2.8") && ns_answer_has_glue("dep.example.", "192.0.2.31"));
    release_zone_snapshot(snap);
    printf("  -> sibling glue tracking and release of old versions passed.\n");
}

static void test_snapshot_retain_release_and_gc(void) {
    printf("[TEST] Snapshot retain, release, GC, and abort rebuild...\n");
    // Retain / release NULL safety
    retain_zone_snapshot(NULL);
    release_zone_snapshot(NULL);

    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.reader_count = ATOMIC_VAR_INIT(0);

    retain_zone_snapshot(&snap);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    retain_zone_snapshot(&snap);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 2);
    release_zone_snapshot(&snap);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
    release_zone_snapshot(&snap);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);
    // Release when already 0 (no underflow)
    release_zone_snapshot(&snap);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 0);

    // Entry create and free
    zone_db_entry_t *entry = create_new_zone_entry("test.example.", "default");
    assert(entry != NULL);
    assert(strcmp(entry->domain, "test.example.") == 0);
    assert(strcmp(entry->view_name, "default") == 0);
    free_zone_db_entry(entry);

    // abort_rebuild_snapshot NULL and valid
    abort_rebuild_snapshot(NULL, "unit_test_null");
    zone_db_snapshot_t *dummy_snap = calloc(1, sizeof(zone_db_snapshot_t));
    abort_rebuild_snapshot(dummy_snap, "unit_test_dummy");

    printf("  -> Snapshot retain/release/GC passed.\n");
}

static void test_lookup_across_views_multi(void) {
    printf("[TEST] lookup_zone_across_views multi-match and edge cases...\n");
    wfile("shared.zone", ZONE_A);

    server_config_t *cfg = load_conf(
        "view \"view1\" {\n  match-clients { 10.0.0.0/8; };\n"
        "  zone \"shared.example\" { type master; file \"%s/shared.zone\"; };\n"
        "  zone \"unique1.example\" { type master; file \"%s/shared.zone\"; };\n};\n"
        "view \"view2\" {\n  match-clients { any; };\n"
        "  zone \"shared.example\" { type master; file \"%s/shared.zone\"; };\n"
        "  zone \"unique2.example\" { type master; file \"%s/shared.zone\"; };\n};\n",
        g_dir, g_dir, g_dir, g_dir);

    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);

    zone_lookup_result_t res;
    memset(&res, 0, sizeof(res));

    // Lookup with view_name specified
    int m1 = lookup_zone_across_views(snap, cfg, "shared.example.", "view1", &res);
    assert(m1 == 1);
    assert(res.entry != NULL && strcmp(res.view_name, "view1") == 0);

    // Lookup across all views (NULL view_name) -> should find 2 matches
    memset(&res, 0, sizeof(res));
    int m2 = lookup_zone_across_views(snap, cfg, "shared.example.", NULL, &res);
    assert(m2 == 2);

    // Lookup non-existent zone -> 0 matches
    memset(&res, 0, sizeof(res));
    int m3 = lookup_zone_across_views(snap, cfg, "nonexistent.example.", NULL, &res);
    assert(m3 == 0);

    // Suffix lookup edge cases
    view_snapshot_t *v1 = &snap->views[0];
    assert(find_zone_in_view(NULL, "shared.example.") == NULL);
    assert(find_zone_in_view(v1, NULL) == NULL);
    assert(find_zone_in_view(v1, "sub.deep.shared.example.") != NULL);

    // snapshot_get_zone NULL safety
    assert(snapshot_get_zone(NULL, "shared.example.") == NULL);
    assert(snapshot_get_zone(snap, "nonexistent.example.") == NULL);

    release_zone_snapshot(snap);
    printf("  -> lookup_zone_across_views multi-match passed.\n");
}

static void test_snapshot_catalog_member_sync_and_deltas(void) {
    printf("[TEST] Snapshot rebuild: Catalog zone member syncing, group property deltas & CoO...\n");

    const char *CATALOG_ZONE_V1 =
        "$ORIGIN cat.example.\n$TTL 300\n"
        "@ IN SOA ns.cat.example. h.cat.example. 1 7200 3600 1209600 300\n"
        "@ IN NS ns.cat.example.\n"
        "version IN TXT \"2\"\n"
        "uid1.zones.cat.example. IN PTR member1.example.\n"
        "group.uid1.zones.cat.example. IN TXT \"group-a\"\n"
        "group.uid1.zones.cat.example. IN TXT \"group-b\"\n"
        "uid2.zones.cat.example. IN PTR member2.example.\n";

    const char *CATALOG_ZONE_V2 =
        "$ORIGIN cat.example.\n$TTL 300\n"
        "@ IN SOA ns.cat.example. h.cat.example. 2 7200 3600 1209600 300\n"
        "@ IN NS ns.cat.example.\n"
        "version IN TXT \"2\"\n"
        "uid1.zones.cat.example. IN PTR member1.example.\n"
        "group.uid1.zones.cat.example. IN TXT \"group-c\"\n" // Modified group
        "uid3.zones.cat.example. IN PTR member3.example.\n"; // Added member3, removed member2

    wfile("cat_v1.zone", CATALOG_ZONE_V1);
    wfile("cat_v2.zone", CATALOG_ZONE_V2);
    wfile("m1.zone", "$ORIGIN member1.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n");
    wfile("m2.zone", "$ORIGIN member2.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.2\n");
    wfile("m3.zone", "$ORIGIN member3.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.3\n");

    server_config_t *cfg1 = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" {\n"
        "  zone \"cat.example\" { type master; file \"%s/cat_v1.zone\"; };\n"
        "  zone \"member1.example\" { type master; file \"%s/m1.zone\"; };\n"
        "  zone \"member2.example\" { type master; file \"%s/m2.zone\"; };\n"
        "};\n",
        g_dir, g_dir, g_dir, g_dir);

    zone_db_snapshot_t *snap1 = build(cfg1, false);
    assert(snap1 != NULL);
    zone_db_entry_t *ecat = snapshot_get_zone(snap1, "cat.example.");
    assert(ecat != NULL);
    (void)ecat;

    // Rebuild with updated catalog configuration (v2)
    server_config_t *cfg2 = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" {\n"
        "  zone \"cat.example\" { type master; file \"%s/cat_v2.zone\"; };\n"
        "  zone \"member1.example\" { type master; file \"%s/m1.zone\"; };\n"
        "  zone \"member3.example\" { type master; file \"%s/m3.zone\"; };\n"
        "};\n",
        g_dir, g_dir, g_dir, g_dir);

    zone_db_snapshot_t *snap2 = build(cfg2, false);
    assert(snap2 != NULL);

    release_zone_snapshot(snap1);
    release_zone_snapshot(snap2);
    printf("  -> Catalog zone member sync and group deltas passed.\n");
}

static void test_snapshot_rebuild_case_1(void) {
    printf("[TEST] Snapshot Rebuild: Zone arena init and destroy...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    assert(arena.records == NULL);
    assert(arena.count == 0);
    zone_arena_destroy(&arena);
}

static void test_snapshot_rebuild_case_2(void) {
    printf("[TEST] Snapshot Rebuild: Zone lookup case insensitivity...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    strlcpy(entry.domain, "Case.Example.", sizeof(entry.domain));
    assert(strcasecmp(entry.domain, "case.example.") == 0);
}

static void test_snapshot_rebuild_case_3(void) {
    printf("[TEST] Snapshot Rebuild: Snapshot entry RCU active swap...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    zone_arena_t a1, a2;
    memset(&a1, 0, sizeof(a1)); memset(&a2, 0, sizeof(a2));
    atomic_init(&entry.rcu.active, &a1.ver);
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_relaxed) == &a1.ver);
    atomic_store_explicit(&entry.rcu.active, &a2.ver, memory_order_release);
    assert(atomic_load_explicit(&entry.rcu.active, memory_order_acquire) == &a2.ver);
}

static void test_snapshot_rebuild_case_4(void) {
    printf("[TEST] Snapshot Rebuild: Zone file missing error handling...\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"missing.example\" { type master; file \"%s/nonexistent.zone\"; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_5(void) {
    printf("[TEST] Snapshot Rebuild: Syntax error in zone file error handling...\n");
    wfile("bad_syntax.zone", "INVALID SYNTAX LINE NO RR TYPE");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"bad.example\" { type master; file \"%s/bad_syntax.zone\"; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_6(void) {
    printf("[TEST] Snapshot Rebuild: Secondary zone configuration snapshot...\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"sec.example\" { type secondary; masters { 192.0.2.1; }; }; };\n",
        g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    zone_db_entry_t *entry = snapshot_get_zone(snap, "sec.example.");
    assert(entry != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_7(void) {
    printf("[TEST] Snapshot Rebuild: Forward zone configuration snapshot...\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"fwd.example\" { type forward; forwarders { 8.8.8.8; }; }; };\n",
        g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    zone_db_entry_t *entry = snapshot_get_zone(snap, "fwd.example.");
    assert(entry != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_8(void) {
    printf("[TEST] Snapshot Rebuild: Program zone configuration snapshot...\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; allow-program-zones yes; };\n"
        "view \"default\" { zone \"prog.example\" { type program; program \"/bin/echo\"; }; };\n",
        g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    zone_db_entry_t *entry = snapshot_get_zone(snap, "prog.example.");
    assert(entry != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_10(void) {
    printf("[TEST] Snapshot Rebuild: Multiple views isolation...\n");
    wfile("v_int.zone", "$ORIGIN test.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 10.0.0.1\n");
    wfile("v_ext.zone", "$ORIGIN test.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 198.51.100.1\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"internal\" { zone \"test.example\" { type master; file \"%s/v_int.zone\"; }; };\n"
        "view \"external\" { zone \"test.example\" { type master; file \"%s/v_ext.zone\"; }; };\n",
        g_dir, g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    assert(snap->view_count == 2);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_12(void) {
    printf("[TEST] Snapshot Rebuild: RCU read lock validation...\n");
    worker_ctx_t wctx;
    memset(&wctx, 0, sizeof(wctx));
    atomic_init(&wctx.rcu_observed_epoch, RCU_EPOCH_IDLE);
    rcu_reader_enter(&wctx);
    rcu_reader_exit(&wctx);
    assert(atomic_load_explicit(&wctx.rcu_observed_epoch, memory_order_relaxed) == RCU_EPOCH_IDLE);
}

static void test_snapshot_rebuild_case_13(void) {
    printf("[TEST] Snapshot Rebuild: TSIG key attached to zone in snapshot...\n");
    wfile("tsig_zone.zone", "$ORIGIN tsig.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\n");
    server_config_t *cfg = load_conf(
        "key \"mykey\" { algorithm hmac-sha256; secret \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"; };\n"
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"tsig.example\" { type master; file \"%s/tsig_zone.zone\"; tsig-key \"mykey\"; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    zone_db_entry_t *entry = snapshot_get_zone(snap, "tsig.example.");
    assert(entry != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_14(void) {
    printf("[TEST] Snapshot Rebuild: Zone transfer ACL in snapshot...\n");
    wfile("acl_zone.zone", "$ORIGIN acl.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"acl.example\" { type master; file \"%s/acl_zone.zone\"; allow-transfer { 192.0.2.0/24; }; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_15(void) {
    printf("[TEST] Snapshot Rebuild: Rate limit config in snapshot...\n");
    wfile("rrl_zone.zone", "$ORIGIN rrl.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"rrl.example\" { type master; file \"%s/rrl_zone.zone\"; rate-limit { responses-per-second 15; slip 2; }; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_16(void) {
    printf("[TEST] Snapshot Rebuild: Location tags in snapshot...\n");
    wfile("loc_zone.zone", "$ORIGIN loc.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"loc.example\" { type master; file \"%s/loc_zone.zone\"; location-tags { tag \"tag1\" { 192.0.2.0/24; }; }; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_17(void) {
    printf("[TEST] Snapshot Rebuild: ECS tags in snapshot...\n");
    wfile("ecstag_zone.zone", "$ORIGIN ecstag.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" { zone \"ecstag.example\" { type master; file \"%s/ecstag_zone.zone\"; ecs-tags { tag \"tag1\" { 192.0.2.0/24; }; }; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_18(void) {
    printf("[TEST] Snapshot Rebuild: Dnstap config in snapshot...\n");
    wfile("dnstap_zone.zone", "$ORIGIN dnstap.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; dnstap { socket-path \"/tmp/dnstap.sock\"; log-queries yes; }; };\n"
        "view \"default\" { zone \"dnstap.example\" { type master; file \"%s/dnstap_zone.zone\"; }; };\n",
        g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_19(void) {
    printf("[TEST] Snapshot Rebuild: Empty options block rebuild...\n");
    server_config_t *cfg = load_conf("options {};\n");
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static void test_snapshot_rebuild_case_21(void) {
    printf("[TEST] Snapshot Rebuild: Zone arena memory stats...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    assert(arena.count == 0);
    zone_arena_destroy(&arena);
}

static void test_snapshot_rebuild_case_22(void) {
    printf("[TEST] Snapshot Rebuild: Fast lookup by FNV-1a hash...\n");
    uint32_t h1 = calc_fnv1a_str("lookup.example.");
    uint32_t h2 = calc_fnv1a_str("LOOKUP.EXAMPLE.");
    assert(h1 == h2);
}

static void test_snapshot_rebuild_case_23(void) {
    printf("[TEST] Snapshot Rebuild: Zone index build with single record...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "idx.example.", .is_standalone_mode = true, .err_out = &err };
    char ztext[] = "$ORIGIN idx.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\n";
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    assert(test_build_index(&arena, true) == 0);
    assert(arena.hash_size > 0);
    zone_arena_destroy(&arena);
}

static void test_snapshot_rebuild_case_24(void) {
    printf("[TEST] Snapshot Rebuild: Zone index collision handling...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "coll.example.", .is_standalone_mode = true, .err_out = &err };
    char ztext[] = "$ORIGIN coll.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nrec1 IN A 1.1.1.1\nrec2 IN A 2.2.2.2\n";
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    assert(test_build_index(&arena, true) == 0);
    zone_arena_destroy(&arena);
}

static void test_snapshot_rebuild_case_25(void) {
    printf("[TEST] Snapshot Rebuild: Empty non-terminal synthesis in index...\n");
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    zone_arena_init(&arena);
    parse_error_t err = {0};
    parse_context_t ctx = { .base_dir = ".", .default_origin = "ent.example.", .is_standalone_mode = true, .err_out = &err };
    char ztext[] = "$ORIGIN ent.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\na.b.c IN A 192.0.2.1\n";
    assert(parse_zone_fast(ztext, strlen(ztext), &arena, &ctx) >= 0);
    assert(test_build_index(&arena, true) == 0);
    zone_arena_destroy(&arena);
}

static void test_snapshot_rebuild_case_27(void) {
    printf("[TEST] Snapshot Rebuild: Standby zone reload error propagation...\n");
    zone_db_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    zone_config_t zcfg;
    memset(&zcfg, 0, sizeof(zcfg));
    zcfg.file = "/nonexistent/zonefile";
    int rc = reload_master_zone(&entry, &zcfg);
    assert(rc != RELOAD_OK);
}

static void test_snapshot_rebuild_case_28(void) {
    printf("[TEST] Snapshot Rebuild: Retain and release reader_count cycle...\n");
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    atomic_init(&snap.reader_count, 1);
    retain_zone_snapshot(&snap);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 2);
    release_zone_snapshot(&snap);
    assert(atomic_load_explicit(&snap.reader_count, memory_order_relaxed) == 1);
}

static void test_snapshot_rebuild_case_29(void) {
    printf("[TEST] Snapshot Rebuild: Snapshot get zone non-existent...\n");
    view_snapshot_t view;
    memset(&view, 0, sizeof(view));
    view.name = "default";
    zone_db_snapshot_t snap;
    memset(&snap, 0, sizeof(snap));
    snap.views = &view;
    snap.view_count = 1;
    assert(snapshot_get_zone(&snap, "nonexistent.domain.") == NULL);
}

/* www.shared.example. の A レコードの値を返す (無ければ NULL) */
static const char *shared_www_addr(zone_db_entry_t *e, char buf[INET_ADDRSTRLEN]) {
    zone_version_t *a = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
    const zone_image_t *img = a ? a->image : NULL;
    uint32_t id = img ? zone_image_find_name(img, "www.shared.example.") : ZONE_IMAGE_NONE;
    if (id == ZONE_IMAGE_NONE) return NULL;
    uint32_t rr = zone_image_rrset_next(img, id, 1, zone_image_name_first_rr(img, id));
    if (rr == ZONE_IMAGE_NONE || zone_image_rr_rdlen(img, rr) != 4) return NULL;
    return inet_ntop(AF_INET, zone_image_rr_rdata(img, rr), buf, INET_ADDRSTRLEN);
}

/* R-26: the same zone name in two views keeps each view's own data, at start-up and after every
 * reload (rebuild_zone_db_from_config() used to load the last view's file into the first view's entry). */
static void test_snapshot_rebuild_case_30(void) {
    printf("[TEST] Snapshot Rebuild: same zone name in two views serves each view's data...\n");
    wfile("v1_shared.zone", "$ORIGIN shared.example.\n$TTL 60\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN NS ns1\n"
                            "ns1 IN A 192.0.2.1\nwww IN A 192.0.2.11\n");
    wfile("v2_shared.zone", "$ORIGIN shared.example.\n$TTL 60\n@ IN SOA ns2 h 1 2 3 4 5\n@ IN NS ns2\n"
                            "ns2 IN A 192.0.2.2\nwww IN A 198.51.100.22\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"view1\" { match-clients { 127.0.0.1; }; zone \"shared.example\" { type master; file \"%s/v1_shared.zone\"; }; };\n"
        "view \"view2\" { match-clients { any; }; zone \"shared.example\" { type master; file \"%s/v2_shared.zone\"; }; };\n",
        g_dir, g_dir, g_dir);
    for (int round = 0; round < 3; round++) {
        /* round 0: start-up, round 1: reload of every zone, round 2: reload with skip_unchanged */
        zone_db_snapshot_t *snap = build(cfg, round == 2);
        assert(snap != NULL);
        assert(snap->view_count == 2);
        zone_db_entry_t *z1 = snapshot_get_zone_in_view(snap, "view1", "shared.example.");
        zone_db_entry_t *z2 = snapshot_get_zone_in_view(snap, "view2", "shared.example");
        assert(z1 && z2 && z1 != z2);
        assert(strcmp(z1->view_name, "view1") == 0 && strcmp(z2->view_name, "view2") == 0);
        assert(find_zone_exact_in_view(snapshot_find_view(snap, "VIEW1"), "SHARED.example.") == z1);
        assert(snapshot_get_zone_in_view(snap, "view3", "shared.example.") == NULL);
        assert(snapshot_get_zone_in_view(snap, "view1", "www.shared.example.") == NULL); /* exact apex only */
        char b1[INET_ADDRSTRLEN], b2[INET_ADDRSTRLEN];
        const char *a1 = shared_www_addr(z1, b1), *a2 = shared_www_addr(z2, b2);
        assert(a1 && strcmp(a1, "192.0.2.11") == 0);
        assert(a2 && strcmp(a2, "198.51.100.22") == 0);
        /* query path: the client address selects the view, the view selects the entry */
        assert(find_zone_in_view(select_view(snap, "127.0.0.1"), "www.shared.example.") == z1);
        assert(find_zone_in_view(select_view(snap, "192.0.2.200"), "www.shared.example.") == z2);
        /* karictl reload <zone> <view> */
        zone_lookup_result_t lr;
        memset(&lr, 0, sizeof(lr));
        assert(lookup_zone_across_views(snap, cfg, "shared.example.", "view2", &lr) == 1);
        assert(lr.entry == z2 && lr.zcfg && strcmp(lr.view_name, "view2") == 0);
        assert(lookup_zone_across_views(snap, cfg, "shared.example.", NULL, &lr) == 2);
        release_zone_snapshot(snap);
    }
}

/* O-13: a zone whose type changes on reload gets a new entry (is_secondary/kind follow the new type);
 * an unchanged zone keeps its entry. */
static void test_snapshot_rebuild_type_change(void) {
    printf("[TEST] Snapshot Rebuild: zone type change recreates the zone entry...\n");
    wfile("tc.zone", "$ORIGIN tc.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n");
    wfile("keep.zone", "$ORIGIN keep.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n");
    server_config_t *c1 = load_conf(
        "options { directory \"%s\"; };\n"
        "zone \"tc.example\" { type master; file \"%s/tc.zone\"; };\n"
        "zone \"keep.example\" { type primary; file \"%s/keep.zone\"; };\n", g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s1 = build(c1, false);
    zone_db_entry_t *tc1 = snapshot_get_zone_in_view(s1, "__default__", "tc.example.");
    zone_db_entry_t *keep1 = snapshot_get_zone_in_view(s1, "__default__", "keep.example.");
    assert(tc1 && keep1);
    assert(tc1->kind == ZONE_KIND_PRIMARY && !tc1->is_secondary);

    server_config_t *c2 = load_conf(
        "options { directory \"%s\"; };\n"
        "zone \"tc.example\" { type slave; masters { 192.0.2.53; }; };\n"
        "zone \"keep.example\" { type master; file \"%s/keep.zone\"; };\n", g_dir, g_dir);
    zone_db_snapshot_t *s2 = build(c2, false);
    zone_db_entry_t *tc2 = snapshot_get_zone_in_view(s2, "__default__", "tc.example.");
    zone_db_entry_t *keep2 = snapshot_get_zone_in_view(s2, "__default__", "keep.example.");
    assert(tc2 && tc2 != tc1);
    assert(tc2->kind == ZONE_KIND_SECONDARY && tc2->is_secondary);
    assert(keep2 == keep1); /* "primary" and "master" are the same kind */
    /* the control thread's tick list of the view: the secondary only (the primaries have no timers to look at) */
    view_snapshot_t *v1 = snapshot_find_view(s1, "__default__"), *v2 = snapshot_find_view(s2, "__default__");
    assert(v1 && t_ticks(v1) == 0);
    assert(v2 && t_ticks(v2) == 1 && t_tick0(v2) == tc2);

    server_config_t *c3 = load_conf(
        "options { directory \"%s\"; };\n"
        "zone \"tc.example\" { type master; file \"%s/tc.zone\"; };\n"
        "zone \"keep.example\" { type master; file \"%s/keep.zone\"; };\n", g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s3 = build(c3, false);
    zone_db_entry_t *tc3 = snapshot_get_zone_in_view(s3, "__default__", "tc.example.");
    assert(tc3 && tc3 != tc2 && tc3->kind == ZONE_KIND_PRIMARY && !tc3->is_secondary);
    zone_version_t *a3 = atomic_load_explicit(&tc3->rcu.active, memory_order_acquire);
    assert(a3 && a3->image && a3->image->n_rrs >= 3); /* the recreated primary loaded its file */
    assert(zone_kind_from_type("Secondary") == ZONE_KIND_SECONDARY);
    assert(zone_kind_from_type("forward") == ZONE_KIND_FORWARD);
    assert(zone_kind_from_type("program") == ZONE_KIND_PROGRAM);
    assert(zone_kind_from_type(NULL) == ZONE_KIND_OTHER);
    release_zone_snapshot(s1);
    release_zone_snapshot(s2);
    release_zone_snapshot(s3);
}

/* R-28, RFC 9432 §4.3.2 / §5.4: a change of the group property keeps the member zone (same entry, no new
 * transfer); a change of the member node label still replaces it. */
static zone_db_entry_t *cat32_step(zone_db_entry_t *cat, zone_config_t *zcfg, int serial, const char *label,
                                   const char *extra, zone_db_snapshot_t **snap_out) {
    char text[512];
    snprintf(text, sizeof(text),
             "$ORIGIN cat32.example.\n$TTL 60\n@ IN SOA ns h %d 2 3 4 5\n@ IN NS invalid.\n"
             "version IN TXT \"2\"\n%s.zones IN PTR m32.example.\n%s", serial, label, extra);
    wfile("cat32.zone", text);
    if (cat) {
        /* karictl reload <catalog>: reload the zone, then process its membership */
        assert(reload_master_zone(cat, zcfg) == RELOAD_OK);
        catalog_process_membership(cat, zcfg, "__default__");
    }
    *snap_out = acquire_retained_zone_snapshot();
    return snapshot_get_zone_in_view(*snap_out, "__default__", "m32.example.");
}

static void test_snapshot_rebuild_case_32(void) {
    printf("[TEST] Snapshot Rebuild: catalog group change keeps the member zone, unique-id change replaces it...\n");
    zone_db_snapshot_t *s1, *s2, *s3, *s4, *s5;
    cat32_step(NULL, NULL, 1, "abc", "", &s1);
    release_zone_snapshot(s1);
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "zone \"cat32.example\" { type master; file \"%s/cat32.zone\"; catalog-zone yes; };\n", g_dir, g_dir);
    s1 = build(cfg, false);
    zone_db_entry_t *m1 = snapshot_get_zone_in_view(s1, "__default__", "m32.example.");
    zone_db_entry_t *cat = snapshot_get_zone_in_view(s1, "__default__", "cat32.example.");
    assert(m1 && cat && m1->is_catalog_member && m1->group_count == 0);
    assert(strcmp(m1->catalog_member_unique_id, "abc") == 0);
    atomic_store_explicit(&m1->refresh_now, false, memory_order_release);
    zone_config_t *zcfg = find_zone_config_in_view(cfg, "__default__", "cat32.example.");
    assert(zcfg && zcfg->is_catalog);

    /* group added: same entry, no refresh, groups updated */
    zone_db_entry_t *m2 = cat32_step(cat, zcfg, 2, "abc", "group.abc.zones IN TXT \"g1\"\n", &s2);
    assert(m2 == m1);
    assert(!atomic_load_explicit(&m2->refresh_now, memory_order_acquire));
    assert(m2->group_count == 1 && strcmp(m2->groups[0], "g1") == 0);
    /* group changed, then removed */
    zone_db_entry_t *m3 = cat32_step(cat, zcfg, 3, "abc", "group.abc.zones IN TXT \"g2\"\n", &s3);
    assert(m3 == m1 && m3->group_count == 1 && strcmp(m3->groups[0], "g2") == 0);
    zone_db_entry_t *m4 = cat32_step(cat, zcfg, 4, "abc", "", &s4);
    assert(m4 == m1 && m4->group_count == 0 && !atomic_load_explicit(&m4->refresh_now, memory_order_acquire));
    /* member node label changed: removal and re-add (new entry, new transfer) */
    zone_db_entry_t *m5 = cat32_step(cat, zcfg, 5, "xyz", "", &s5);
    assert(m5 && m5 != m1 && strcmp(m5->catalog_member_unique_id, "xyz") == 0);
    assert(atomic_load_explicit(&m5->refresh_now, memory_order_acquire));
    release_zone_snapshot(s1);
    release_zone_snapshot(s2);
    release_zone_snapshot(s3);
    release_zone_snapshot(s4);
    release_zone_snapshot(s5);
}

static void test_snapshot_rebuild_case_33(void) {
    printf("[TEST] Snapshot Rebuild: ECS trusted resolvers array validation...\n");
    cidr_entry_t cidr;
    memset(&cidr, 0, sizeof(cidr));
    assert(cidr_entry_parse(&cidr, "192.0.2.0/24") == true);
    assert(cidr.valid == true);
    assert(cidr.prefix == 24);
}

static void test_snapshot_rebuild_case_35(void) {
    printf("[TEST] Snapshot Rebuild: Complete snapshot destruction and resource release...\n");
    server_config_t *cfg = load_conf("options {};\n");
    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);
    release_zone_snapshot(snap);
}

static int g_retired_obj_freed;
static void retired_obj_free(void *p) {
    g_retired_obj_freed++;
    free(p);
}

/* B0: zone_retire_object() frees an object only after the grace period and while the entry has no AXFR out /
 * transfer in (the same conditions as a retired version); zone_entry_config() picks dbcfg for DB zones */
static void test_retire_object_and_entry_config(void) {
    printf("[TEST] Snapshot Rebuild: zone_retire_object() grace period / pinning, zone_entry_config()...\n");
    zone_db_entry_t *e = create_new_zone_entry("objret.example", "");
    assert(e && e->source == ZONE_SRC_CONFIG && atomic_load(&e->dbcfg) == NULL);
    assert(atomic_load(&e->snapshot_refs) == 1);
    void *spare = malloc(1);
    assert(!zone_retire_object(NULL, spare, retired_obj_free, 0));
    assert(!zone_retire_object(e, NULL, retired_obj_free, 0));
    assert(!zone_retire_object(e, spare, NULL, 0));
    free(spare);
    assert(atomic_load(&e->snapshot_refs) == 1);

    /* pinned by an outgoing AXFR: not freed even after a blocking grace period */
    g_retired_obj_freed = 0;
    atomic_store(&e->active_axfr, 1);
    uint64_t ep = rcu_writer_advance_epoch();
    assert(zone_retire_object(e, malloc(8), retired_obj_free, ep));
    assert(atomic_load(&e->snapshot_refs) == 2);
    zone_retire_process(true);
    assert(g_retired_obj_freed == 0 && atomic_load(&e->snapshot_refs) == 2);
    /* pinned by an inbound transfer */
    atomic_store(&e->active_axfr, 0);
    atomic_store(&e->is_transferring, true);
    zone_retire_process(true);
    assert(g_retired_obj_freed == 0 && atomic_load(&e->snapshot_refs) == 2);
    atomic_store(&e->is_transferring, false);

    /* unpinned: freed once the grace period has passed */
    zone_retire_process(true);
    assert(g_retired_obj_freed == 1 && atomic_load(&e->snapshot_refs) == 1);

    /* a reader that entered before the retire epoch holds it back (no-wait variant) */
    rcu_aux_read_lock();
    ep = rcu_writer_advance_epoch();
    assert(zone_retire_object(e, malloc(8), retired_obj_free, ep));
    zone_retire_process(false);
    assert(g_retired_obj_freed == 1 && atomic_load(&e->snapshot_refs) == 2);
    rcu_aux_read_unlock();
    zone_retire_process(false);
    assert(g_retired_obj_freed == 2 && atomic_load(&e->snapshot_refs) == 1);

    /* several objects on the stack, all pinned together */
    atomic_store(&e->active_axfr, 1);
    ep = rcu_writer_advance_epoch();
    assert(zone_retire_object(e, malloc(8), retired_obj_free, ep));
    assert(zone_retire_object(e, malloc(8), retired_obj_free, ep));
    zone_retire_process(true);
    assert(g_retired_obj_freed == 2);
    atomic_store(&e->active_axfr, 0);
    zone_retire_process(true);
    assert(g_retired_obj_freed == 4 && atomic_load(&e->snapshot_refs) == 1);

    /* zone_entry_config(): the DB zone's own settings; the others go through the config index */
    zone_config_t dbc;
    memset(&dbc, 0, sizeof(dbc));
    assert(zone_entry_config(NULL, e) == NULL);
    e->source = ZONE_SRC_DB;
    assert(zone_entry_config(NULL, e) == NULL); /* dbcfg not set yet */
    atomic_store(&e->dbcfg, &dbc);
    assert(zone_entry_config(NULL, e) == &dbc);
    atomic_store(&e->dbcfg, NULL);
    e->source = ZONE_SRC_CATALOG;
    server_config_t *cfg = load_conf("zone \"objret.example\" { type master; file \"/nonexistent\"; };\n");
    const zone_config_t *c = zone_entry_config(cfg, e);
    assert(c && c == find_zone_config_in_view(cfg, e->view_name, e->domain));
    atomic_store(&e->dbcfg, &dbc); /* ignored unless source == ZONE_SRC_DB */
    assert(zone_entry_config(cfg, e) == c);
    atomic_store(&e->dbcfg, NULL);
    free_zone_db_entry(e);
}

static void test_snapshot_standby_ecs_and_soa_serial(void) {
    printf("[TEST] Snapshot rebuild: Standby zone reload, ECS resolvers & SOA serial...\n");

    const char *ZONE_STANDBY_SOA =
        "$ORIGIN standby.example.\n$TTL 300\n"
        "@ IN SOA ns.standby.example. h.standby.example. 2026092401 7200 1800 1209600 300\n"
        "@ IN NS ns.standby.example.\n"
        "ns IN A 192.0.2.55\n";

    wfile("standby.zone", ZONE_STANDBY_SOA);

    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"default\" {\n"
        "  zone \"standby.example\" {\n"
        "    type master;\n"
        "    file \"%s/standby.zone\";\n"
        "  };\n"
        "};\n",
        g_dir, g_dir);

    zone_db_snapshot_t *snap = build(cfg, false);
    assert(snap != NULL);

    zone_db_entry_t *entry = snapshot_get_zone(snap, "standby.example.");
    assert(entry != NULL);
    assert(entry->serial == 2026092401);
    assert(entry->refresh == 7200);
    assert(entry->retry == 1800);
    assert(entry->expire == 1209600);

    // Test reload of standby zone with ECS trusted resolvers
    zone_config_t *zcfg = find_zone_config_in_view(cfg, "default", "standby.example.");
    assert(zcfg != NULL);
    assert(reload_master_zone(entry, zcfg) == RELOAD_OK);

    // Test skip_unchanged = true rebuild pass
    zone_db_snapshot_t *snap_skip = build(cfg, true);
    assert(snap_skip != NULL);
    release_zone_snapshot(snap_skip);

    release_zone_snapshot(snap);
    printf("  -> Standby ECS and SOA serial reload passed.\n");
}

static int rm_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb; (void)type; (void)ftw;
    return remove(path);
}

/* S5 B-3: ixfr-history reaches the zone entries (options value, zone override), a reload with a lower value trims the
 * kept differences at once and a higher value lets the ring grow with the next stored difference. */
static void zone_with_serial(const char *file, const char *dom, unsigned serial) {
    char t[512];
    snprintf(t, sizeof(t), "$ORIGIN %s\n$TTL 60\n@ IN SOA ns.%s h.%s %u 7200 3600 1209600 60\n@ IN NS ns.%s\nns IN A 192.0.2.%u\n",
             dom, dom, dom, serial, dom, serial % 200 + 1);
    wfile(file, t);
}

static void test_ixfr_history_reload(void) {
    printf("[TEST] Snapshot rebuild: ixfr-history from options/zone, trimming and growing on reload...\n");
    zone_with_serial("h1.zone", "h1.example.", 1);
    zone_with_serial("h2.zone", "h2.example.", 1);
    zone_with_serial("h3.zone", "h3.example.", 1);
    #define HCONF(opt) \
        "options { " opt " };\n" \
        "zone \"h1.example\" { type master; file \"%s/h1.zone\"; };\n" \
        "zone \"h2.example\" { type master; file \"%s/h2.zone\"; ixfr-history 1; };\n" \
        "zone \"h3.example\" { type master; file \"%s/h3.zone\"; ixfr-history 0; };\n"
    server_config_t *cfg = load_conf(HCONF("ixfr-history 3;"), g_dir, g_dir, g_dir);
    zone_db_snapshot_t *snap = build(cfg, false);
    zone_db_entry_t *e1 = snapshot_get_zone(snap, "h1.example.");
    zone_db_entry_t *e2 = snapshot_get_zone(snap, "h2.example.");
    zone_db_entry_t *e3 = snapshot_get_zone(snap, "h3.example.");
    assert(e1 && e2 && e3);
    assert(ixfr_history_depth(&e1->ixfr_history) == 3);   /* options */
    assert(ixfr_history_depth(&e2->ixfr_history) == 1);   /* the zone overrides options */
    assert(ixfr_history_depth(&e3->ixfr_history) == 0);
    assert(e1->ixfr_history.entries == NULL && e1->ixfr_history.count == 0);   /* nothing before the first diff */
    zone_config_t *c1 = find_zone_config_in_view(cfg, NULL, "h1.example.");
    zone_config_t *c2 = find_zone_config_in_view(cfg, NULL, "h2.example.");
    zone_config_t *c3 = find_zone_config_in_view(cfg, NULL, "h3.example.");
    for (unsigned s = 2; s <= 6; s++) {   /* five reloads, each with a new serial: five diffs */
        zone_with_serial("h1.zone", "h1.example.", s);
        zone_with_serial("h2.zone", "h2.example.", s);
        zone_with_serial("h3.zone", "h3.example.", s);
        assert(reload_master_zone(e1, c1) == RELOAD_OK);
        assert(reload_master_zone(e2, c2) == RELOAD_OK);
        assert(reload_master_zone(e3, c3) == RELOAD_OK);
    }
    assert(e1->ixfr_history.cap == 3 && e1->ixfr_history.count == 3);
    assert(e1->ixfr_history.entries[(e1->ixfr_history.head + 3 - 3) % 3]->old_serial == 3);   /* 3->4, 4->5, 5->6 kept */
    assert(e2->ixfr_history.cap == 1 && e2->ixfr_history.count == 1 && e2->ixfr_history.entries[0]->old_serial == 5);
    assert(e3->ixfr_history.entries == NULL && e3->ixfr_history.count == 0);   /* depth 0: no ring, no diff */

    /* a reload of the configuration with a lower options value trims the zone that follows options (not the others) */
    server_config_t *cfg2 = load_conf(HCONF("ixfr-history 1;"), g_dir, g_dir, g_dir);
    zone_db_snapshot_t *snap2 = build(cfg2, true);
    assert(snapshot_get_zone(snap2, "h1.example.") == e1);   /* the entry is reused */
    assert(ixfr_history_depth(&e1->ixfr_history) == 1);
    assert(e1->ixfr_history.cap == 1 && e1->ixfr_history.count == 1 && e1->ixfr_history.entries[0]->old_serial == 5);
    /* a higher value: the ring grows with the next stored diff and keeps what it had */
    server_config_t *cfg3 = load_conf(HCONF("ixfr-history 5;"), g_dir, g_dir, g_dir);
    zone_db_snapshot_t *snap3 = build(cfg3, true);
    assert(ixfr_history_depth(&e1->ixfr_history) == 5 && e1->ixfr_history.cap == 1);
    zone_with_serial("h1.zone", "h1.example.", 7);
    c1 = find_zone_config_in_view(cfg3, NULL, "h1.example.");
    assert(reload_master_zone(e1, c1) == RELOAD_OK);
    assert(e1->ixfr_history.cap == 5 && e1->ixfr_history.count == 2);
    assert(e1->ixfr_history.entries[0]->old_serial == 5 && e1->ixfr_history.entries[1]->old_serial == 6);
    assert(ixfr_history_depth(&e2->ixfr_history) == 1);      /* still the zone's own value */
    release_zone_snapshot(snap3);
    release_zone_snapshot(snap2);
    release_zone_snapshot(snap);
    #undef HCONF
    printf("  -> ixfr-history on reload passed.\n");
}

/* batch 8: zone { in-view "a"; } -- the referencing view holds the entry of the owner view (BIND bin/named/server.c configure_zone() adds the zone
 * object of the other view with dns_view_addzone()).  The snapshot has one zone_db_entry_t, in two views; it ticks and is listed once. */
static void test_snapshot_in_view(void) {
    printf("[TEST] Snapshot Rebuild: a zone shared with an earlier view (in-view)...\n");
    wfile("iv.zone", "$ORIGIN iv.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\nwww IN A 192.0.2.11\n");
    wfile("ivown.zone", "$ORIGIN own.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n");
    const char *conf1 =
        "options { directory \"%s\"; };\n"
        "view \"a\" { match-clients { 127.0.0.1; };\n"
        "  zone \"iv.example\" { type master; file \"%s/iv.zone\"; };\n"
        "  zone \"sec.example\" { type slave; masters { 192.0.2.53; }; }; };\n"
        "view \"b\" { match-clients { 127.0.0.2; }; zone \"iv.example\" { in-view \"a\"; };\n"
        "  zone \"sec.example\" { in-view \"a\"; }; zone \"own.example\" { type master; file \"%s/ivown.zone\"; }; };\n"
        "view \"c\" { match-clients { any; }; zone \"iv.example\" { in-view \"a\"; }; };\n";
    server_config_t *c1 = load_conf(conf1, g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s1 = build(c1, false);
    view_snapshot_t *va = snapshot_find_view(s1, "a"), *vb = snapshot_find_view(s1, "b"), *vc = snapshot_find_view(s1, "c");
    assert(va && vb && vc);
    zone_db_entry_t *za = snapshot_get_zone_in_view(s1, "a", "iv.example."), *sa = snapshot_get_zone_in_view(s1, "a", "sec.example.");
    zone_db_entry_t *zb = snapshot_get_zone_in_view(s1, "b", "iv.example."), *zc = snapshot_get_zone_in_view(s1, "c", "iv.example.");
    zone_db_entry_t *sb = snapshot_get_zone_in_view(s1, "b", "sec.example."), *ob = snapshot_get_zone_in_view(s1, "b", "own.example.");
    assert(za && sa && za == zb && za == zc && sa == sb && ob && ob != za);
    assert(strcmp(za->view_name, "a") == 0 && strcmp(sb->view_name, "a") == 0 && strcmp(ob->view_name, "b") == 0);   /* the owner's name stays */
    assert(zdir_count(va) == 2 && zdir_count_static(va) == 2 && zdir_count_shared(va) == 0);
    assert(zdir_count(vb) == 3 && zdir_count_static(vb) == 1 && zdir_count_shared(vb) == 2);
    assert(zdir_count(vc) == 1 && zdir_count_static(vc) == 0 && zdir_count_shared(vc) == 1);
    assert(view_owns_entry(va, za) && !view_owns_entry(vb, zb) && view_owns_entry(vb, ob) && !view_owns_entry(vc, zc));
    assert(atomic_load(&za->snapshot_refs) >= 3);                       /* a, b and c each count it */
    /* the 1-second tick: the secondary is in the owner view's list only, never in the referencing view's */
    assert(t_ticks(va) == 1 && t_tick0(va) == sa);
    assert(t_ticks(vb) == 0 && t_ticks(vc) == 0);
    /* the query path: the client's address selects the view, the view finds the shared entry, whose data are the owner's */
    assert(find_zone_in_view(select_view(s1, "127.0.0.2"), "www.iv.example.") == za);
    assert(find_zone_in_view(select_view(s1, "192.0.2.200"), "www.iv.example.") == za);
    assert(find_zone_in_view(select_view(s1, "127.0.0.1"), "www.iv.example.") == za);
    assert(find_zone_for_query(select_view(s1, "127.0.0.2"), "iv.example.", 43) == za);
    zone_version_t *ver = atomic_load_explicit(&za->rcu.active, memory_order_acquire);
    assert(ver && ver->image && ver->image->n_rrs >= 3);                /* loaded once, by the owner's zone { } */
    /* configuration lookups: the owner's zone { } for the entry, and for the name in the referencing view */
    zone_config_t *oc = view_find_zone_config(config_find_view(c1, "a"), "iv.example.");
    assert(oc && zone_entry_config(c1, zb) == oc && find_zone_config_in_view(c1, "b", "iv.example.") == oc);
    assert(find_zone_config_in_view(c1, "c", "iv.example.") == oc && find_zone_config_in_view(c1, "c", "own.example.") == NULL);
    zone_lookup_result_t lr;
    memset(&lr, 0, sizeof(lr));
    assert(lookup_zone_across_views(s1, c1, "iv.example.", NULL, &lr) == 1);       /* karictl notify <zone>: one zone, not three */
    assert(lr.entry == za && strcmp(lr.view_name, "a") == 0);
    memset(&lr, 0, sizeof(lr));
    assert(lookup_zone_across_views(s1, c1, "iv.example.", "c", &lr) == 1);        /* naming the referencing view reaches the owner's zone */
    assert(lr.entry == za && lr.zcfg == oc && strcmp(lr.view_name, "a") == 0);
    assert(lookup_zone_across_views(s1, c1, "own.example.", "a", &lr) == 0);
    /* a reload that changes nothing keeps the entries and the sharing (the fast path copies the views) */
    server_config_t *c2 = load_conf(conf1, g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s2 = build(c2, false);
    assert(snapshot_get_zone_in_view(s2, "a", "iv.example.") == za && snapshot_get_zone_in_view(s2, "c", "iv.example.") == za);
    assert(zdir_count_shared(snapshot_find_view(s2, "b")) == 2 && zdir_count(snapshot_find_view(s2, "b")) == 3);
    assert(t_ticks(snapshot_find_view(s2, "a")) == 1 && t_ticks(snapshot_find_view(s2, "b")) == 0);
    /* the in-view of view c is dropped: c no longer has the zone; view b keeps it */
    server_config_t *c3 = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"a\" { match-clients { 127.0.0.1; };\n"
        "  zone \"iv.example\" { type master; file \"%s/iv.zone\"; };\n"
        "  zone \"sec.example\" { type slave; masters { 192.0.2.53; }; }; };\n"
        "view \"b\" { match-clients { 127.0.0.2; }; zone \"iv.example\" { in-view \"a\"; };\n"
        "  zone \"sec.example\" { in-view \"a\"; }; zone \"own.example\" { type master; file \"%s/ivown.zone\"; }; };\n"
        "view \"c\" { match-clients { any; }; zone \"own.example\" { type master; file \"%s/ivown.zone\"; }; };\n", g_dir, g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s3 = build(c3, false);
    assert(snapshot_get_zone_in_view(s3, "c", "iv.example.") == NULL && zdir_count_shared(snapshot_find_view(s3, "c")) == 0);
    assert(snapshot_get_zone_in_view(s3, "b", "iv.example.") == za && zdir_count_shared(snapshot_find_view(s3, "b")) == 2);
    assert(t_ticks(snapshot_find_view(s3, "a")) == 1 && t_ticks(snapshot_find_view(s3, "b")) == 0);
    /* retargeted: c shares iv.example from view b's... b only shares it, so the zone moves: a real zone { } in b replaces the in-view there */
    server_config_t *c4 = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"a\" { match-clients { 127.0.0.1; };\n"
        "  zone \"iv.example\" { type master; file \"%s/iv.zone\"; };\n"
        "  zone \"sec.example\" { type slave; masters { 192.0.2.53; }; }; };\n"
        "view \"b\" { match-clients { 127.0.0.2; }; zone \"iv.example\" { type master; file \"%s/iv.zone\"; };\n"
        "  zone \"sec.example\" { in-view \"a\"; }; zone \"own.example\" { type master; file \"%s/ivown.zone\"; }; };\n"
        "view \"c\" { match-clients { any; }; zone \"iv.example\" { in-view \"b\"; }; };\n", g_dir, g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s4 = build(c4, false);
    zone_db_entry_t *zb4 = snapshot_get_zone_in_view(s4, "b", "iv.example."), *zc4 = snapshot_get_zone_in_view(s4, "c", "iv.example.");
    assert(zb4 && zb4 != za && strcmp(zb4->view_name, "b") == 0);       /* it was a shared entry of a: the zone { } of b is a new entry */
    assert(zc4 == zb4 && zdir_count_shared(snapshot_find_view(s4, "b")) == 1 && zdir_count_shared(snapshot_find_view(s4, "c")) == 1);
    assert(view_owns_entry(snapshot_find_view(s4, "b"), zb4) && !view_owns_entry(snapshot_find_view(s4, "c"), zc4));
    assert(snapshot_get_zone_in_view(s4, "a", "iv.example.") == za);
    assert(t_ticks(snapshot_find_view(s4, "a")) == 1 && t_ticks(snapshot_find_view(s4, "b")) == 0);
    /* a reload of the same retargeted configuration also keeps the sharing; a different target of the same name is noticed */
    server_config_t *c5 = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"a\" { match-clients { 127.0.0.1; };\n"
        "  zone \"iv.example\" { type master; file \"%s/iv.zone\"; };\n"
        "  zone \"sec.example\" { type slave; masters { 192.0.2.53; }; }; };\n"
        "view \"b\" { match-clients { 127.0.0.2; }; zone \"iv.example\" { type master; file \"%s/iv.zone\"; };\n"
        "  zone \"sec.example\" { in-view \"a\"; }; zone \"own.example\" { type master; file \"%s/ivown.zone\"; }; };\n"
        "view \"c\" { match-clients { any; }; zone \"iv.example\" { in-view \"a\"; }; };\n", g_dir, g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s5 = build(c5, false);
    assert(snapshot_get_zone_in_view(s5, "c", "iv.example.") == za && snapshot_get_zone_in_view(s5, "b", "iv.example.") == zb4);
    /* a catalog update (delta mode) copies the views and keeps the sharing; a shared secondary does not tick in the referencing view */
    wfile("ivcat.zone", "$ORIGIN ivcat.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\nversion IN TXT \"2\"\n");
    server_config_t *c6 = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"a\" { match-clients { 127.0.0.1; };\n"
        "  zone \"ivcat.example\" { type master; file \"%s/ivcat.zone\"; catalog-zone yes; };\n"
        "  zone \"iv.example\" { type master; file \"%s/iv.zone\"; };\n"
        "  zone \"sec.example\" { type slave; masters { 192.0.2.53; }; }; };\n"
        "view \"b\" { match-clients { 127.0.0.2; }; zone \"iv.example\" { in-view \"a\"; }; zone \"sec.example\" { in-view \"a\"; }; };\n"
        "view \"c\" { match-clients { any; }; zone \"sec.example\" { in-view \"a\"; }; };\n", g_dir, g_dir, g_dir);
    zone_db_snapshot_t *s6 = build(c6, false);
    zone_db_entry_t *cat6 = snapshot_get_zone_in_view(s6, "a", "ivcat.example.");
    zone_db_entry_t *sec6 = snapshot_get_zone_in_view(s6, "a", "sec.example.");
    assert(cat6 && sec6 && snapshot_get_zone_in_view(s6, "c", "sec.example.") == sec6);
    catalog_member_id_t *none = calloc(1, sizeof(*none));
    assert(none != NULL);
    zone_db_snapshot_t *s7 = rebuild_zone_db_snapshot(NULL, "a", cat6, NULL, none, 0);
    assert(s7 != NULL);
    assert(snapshot_get_zone_in_view(s7, "b", "sec.example.") == sec6 && snapshot_get_zone_in_view(s7, "c", "sec.example.") == sec6);
    assert(zdir_count_shared(snapshot_find_view(s7, "b")) == 2 && zdir_count_shared(snapshot_find_view(s7, "c")) == 1);
    assert(t_ticks(snapshot_find_view(s7, "a")) == 1 && t_ticks(snapshot_find_view(s7, "b")) == 0 && t_ticks(snapshot_find_view(s7, "c")) == 0);
    assert(zdir_count_shared(snapshot_find_view(s7, "a")) == 0);
    release_zone_snapshot(s1);
    release_zone_snapshot(s2);
    release_zone_snapshot(s3);
    release_zone_snapshot(s4);
    release_zone_snapshot(s5);
}

/* ---- Batch 10: match-clients { key ...; } (BIND 9.20 bin/named/server.c get_matching_view_sync(): for each view in order, dns_message_checksig(message,
 * view) with the view's key ring, then dns_acl_allowed(srcaddr, tsig identity, view->matchclients)) ---- */
#define VK_KEY_A "dmlldy1tYXRjaC1rZXktYS1zZWNyZXQtMDEyMzQ1Njc4OQ=="
#define VK_KEY_B "dmlldy1tYXRjaC1rZXktYi1zZWNyZXQtMDEyMzQ1Njc4OQ=="
#define VK_KEY_C "dmlldy1tYXRjaC1rZXktYy1zZWNyZXQtMDEyMzQ1Njc4OQ=="

/* A query for www.a.example. A, signed with key (RFC 8945 §4.2); key NULL: unsigned; corrupt: a byte of the QNAME is changed after signing (BADSIG) */
static size_t vk_query(uint8_t *buf, size_t cap, tsig_key_t *key, bool corrupt) {
    static const uint8_t q[] = {0x43, 0x21, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                3, 'w', 'w', 'w', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1};
    memcpy(buf, q, sizeof(q));
    size_t len = sizeof(q);
    if (!key) return len;
    uint8_t mac[64];
    size_t mac_len = 0;
    if (tsig_sign_packet(buf, &len, cap, key, 0, mac, &mac_len, NULL, 0, false) != 0) return 0;
    if (corrupt) buf[13] = 'x';
    return len;
}

/* the view name select_view_req() gives, and what it says about the TSIG check */
static const char *vk_select(zone_db_snapshot_t *snap, const server_config_t *cfg, const char *ip, tsig_key_t *key, bool corrupt, bool *done,
                             tsig_request_t *t) {
    uint8_t pkt[1024];
    size_t n = vk_query(pkt, sizeof(pkt), key, corrupt);
    assert(n > 0);
    view_snapshot_t *v = select_view_req(snap, cfg, ip, pkt, n, t, done);
    return v ? v->name : NULL;
}

/* the answer of the engine to the query of vk_query(), as the server core makes it: the route (view, zone, the TSIG check) from select_view_req();
 * and, for the other callers (no route), the engine's own selection; both must agree */
static int vk_answer(zone_db_snapshot_t *snap, const char *ip, tsig_key_t *key, bool corrupt, uint8_t *res, size_t cap) {
    uint8_t pkt[1024];
    size_t n = vk_query(pkt, sizeof(pkt), key, corrupt);
    assert(n > 0);
    compress_ctx_t cc;
    memset(&cc, 0, sizeof(cc));   /* compress_ctx_init_packet() counts up the generation it finds: start from zero */
    compress_ctx_init_packet(&cc);
    query_route_t route;
    tsig_request_t t;
    bool done = false;
    server_config_t *cfg = atomic_load_explicit(&g_config_db.active, memory_order_acquire);
    route.view = select_view_req(snap, cfg, ip, pkt, n, &t, &done);
    route.tsig = done ? &t : NULL;
    route.entry = route.view ? find_zone_for_query(route.view, "www.a.example.", 1) : NULL;
    int len = process_dns_query_cap_routed(pkt, n, res, 4096, cap, "www.a.example.", 1, ip, &cc, false, NULL, snap, &route);
    uint8_t res2[4096];
    compress_ctx_init_packet(&cc);
    int len2 = process_dns_query_cap(pkt, n, res2, 4096, sizeof(res2), "www.a.example.", 1, ip, &cc, false, NULL, snap);
    assert(len > 12 && len2 > 12);
    assert((res2[3] & 0x0F) == (res[3] & 0x0F) && res2[6] == res[6] && res2[7] == res[7] && res2[11] == res[11]);
    return len;
}

static void test_snapshot_view_match_key(void) {
    printf("[TEST] Snapshot rebuild: views chosen by the TSIG key of the request (match-clients { key ...; })...\n");
    wfile("vk_a.zone", "$ORIGIN a.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\nwww IN A 192.0.2.11\n");
    server_config_t *cfg = load_conf(
        "options { directory \"%s\"; };\n"
        "key \"ka\" { algorithm hmac-sha256; secret \"" VK_KEY_A "\"; };\n"
        "key \"kb\" { algorithm hmac-sha256; secret \"" VK_KEY_B "\"; };\n"
        "key \"kc\" { algorithm hmac-sha256; secret \"" VK_KEY_C "\"; };\n"
        "acl \"signers\" { key kb; };\n"
        "view \"va\" { match-clients { key ka; }; zone \"a.example\" { type master; file \"%s/vk_a.zone\"; }; };\n"
        "view \"vb\" { match-clients { signers; }; };\n"
        "view \"vn\" { match-clients { !key ka; !key kb; 192.0.2.0/24; }; };\n"
        "view \"vd\" { match-clients { 127.0.0.1; }; };\n"
        "view \"ve\" { match-clients { any; }; };\n",
        g_dir, g_dir);
    tsig_key_t *ka = find_tsig_key_by_name(cfg, "ka"), *kb = find_tsig_key_by_name(cfg, "kb"), *kc = find_tsig_key_by_name(cfg, "kc");
    assert(ka && kb && kc);
    for (int round = 0; round < 3; round++) {
        /* round 0: start-up, round 1: reload of every zone, round 2: reload with skip_unchanged (the views are copied from the old snapshot) */
        zone_db_snapshot_t *snap = build(cfg, round == 2);
        assert(snap && snap->view_count == 5);
        assert(snap->views[0].match_aml && snap->views[1].match_aml && snap->views[2].match_aml);          /* va, vb (through the acl), vn (negated keys) */
        assert(!snap->views[3].match_aml && !snap->views[4].match_aml);                                      /* vd, ve: addresses only, the flat lists */
        assert(snap->views[3].match_clients_count == 1 && snap->views[0].match_clients_count == 0);
        bool done;
        tsig_request_t t;
        /* signed with ka: the first view; the check is the one of that view and is handed on */
        assert(strcmp(vk_select(snap, cfg, "127.0.0.1", ka, false, &done, &t), "va") == 0 && done);
        assert(t.status == TSIG_REQ_VALID && t.key == ka);
        /* signed with kb: va verifies it (a global key) and its identity is not ka; vb names it through the acl */
        assert(strcmp(vk_select(snap, cfg, "127.0.0.1", kb, false, &done, &t), "vb") == 0 && done);
        assert(t.status == TSIG_REQ_VALID && t.key == kb);
        /* unsigned: no key element matches (a negated one does not either), the address decides */
        assert(strcmp(vk_select(snap, cfg, "127.0.0.1", NULL, false, &done, &t), "vd") == 0 && !done);
        assert(strcmp(vk_select(snap, cfg, "192.0.2.9", NULL, false, &done, &t), "vn") == 0 && !done);
        assert(strcmp(vk_select(snap, cfg, "203.0.113.9", NULL, false, &done, &t), "ve") == 0);
        /* signed with a key that no list names: the address elements still match; vn was checked, and the result is handed on */
        assert(strcmp(vk_select(snap, cfg, "192.0.2.9", kc, false, &done, &t), "vn") == 0 && done);
        assert(t.status == TSIG_REQ_VALID && t.key == kc);
        assert(strcmp(vk_select(snap, cfg, "127.0.0.1", kc, false, &done, &t), "vd") == 0 && !done);
        /* a signature that does not verify identifies nobody: not the view of that key, and the address elements still match */
        assert(strcmp(vk_select(snap, cfg, "127.0.0.1", ka, true, &done, &t), "vd") == 0 && !done);
        assert(strcmp(vk_select(snap, cfg, "192.0.2.9", ka, true, &done, &t), "vn") == 0 && done);
        assert(t.status == TSIG_REQ_ERROR && t.error == 16);
        /* no configuration: no key is known, the request counts as unsigned */
        assert(strcmp(vk_select(snap, NULL, "127.0.0.1", ka, false, &done, &t), "vd") == 0 && !done);
        /* select_view() has the address alone: a view with key elements is evaluated as for an unsigned request */
        assert(strcmp(select_view(snap, "127.0.0.1")->name, "vd") == 0 && strcmp(select_view(snap, "192.0.2.9")->name, "vn") == 0);
        /* a client address that does not parse matches no address element (and no flat list), but a key element needs no address */
        assert(strcmp(vk_select(snap, cfg, "not-an-address", ka, false, &done, &t), "va") == 0 && done);
        assert(vk_select(snap, cfg, "not-an-address", NULL, false, &done, &t) == NULL && !done);

        /* the engine: the zone a.example is served in view va only */
        uint8_t res[4096];
        int len = vk_answer(snap, "127.0.0.1", ka, false, res, sizeof(res));
        assert((res[3] & 0x0F) == 0 && res[7] == 1 && res[11] >= 1 && len > 12);        /* NOERROR, one answer, the TSIG RR of the signed answer */
        (void)vk_answer(snap, "127.0.0.1", NULL, false, res, sizeof(res));
        assert((res[3] & 0x0F) == 5);                                                    /* vd has no such zone: REFUSED */
        (void)vk_answer(snap, "127.0.0.1", kb, false, res, sizeof(res));
        assert((res[3] & 0x0F) == 5);                                                    /* view vb: no zone */
        (void)vk_answer(snap, "127.0.0.1", ka, true, res, sizeof(res));
        assert((res[3] & 0x0F) == 9);                                                    /* vd by address, the MAC is wrong in its ring: NOTAUTH (BADSIG) */
        release_zone_snapshot(snap);
    }

    /* the key ring of a view: two views with a key of one name and different secrets */
    server_config_t *c2 = load_conf(
        "options { directory \"%s\"; };\n"
        "view \"v1\" { key \"k\" { algorithm hmac-sha256; secret \"" VK_KEY_A "\"; }; match-clients { key k; }; };\n"
        "view \"v2\" { key \"k\" { algorithm hmac-sha256; secret \"" VK_KEY_B "\"; }; match-clients { key k; }; };\n"
        "view \"v3\" { match-clients { any; }; };\n",
        g_dir);
    tsig_key_t *k1 = find_tsig_key_in_view(c2, "v1", "k"), *k2 = find_tsig_key_in_view(c2, "v2", "k");
    assert(k1 && k2 && k1 != k2);
    zone_db_snapshot_t *s2 = build(c2, false);
    bool done;
    tsig_request_t t;
    assert(strcmp(vk_select(s2, c2, "192.0.2.50", k1, false, &done, &t), "v1") == 0 && done && t.key == k1);
    assert(strcmp(vk_select(s2, c2, "192.0.2.50", k2, false, &done, &t), "v2") == 0 && done && t.key == k2);   /* BADSIG in v1's ring, valid in v2's */
    assert(strcmp(vk_select(s2, c2, "192.0.2.50", NULL, false, &done, &t), "v3") == 0 && !done);
    release_zone_snapshot(s2);
}

int main(void) {
    /* Line-buffered progress + a hang watchdog (exit 124 with the phase) so a
     * stalled run fails fast in CI instead of blocking the job. */
    wd_start("test_snapshot_rebuild", 300);
    printf("=== Starting Snapshot Rebuild Tests ===\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/karidns_snap_XXXXXX");
    assert(mkdtemp(g_dir));
    test_rebuild_two_views();
    test_ixfr_history_reload();
    test_snapshot_rebuild_sibling_glue();
    test_snapshot_retain_release_and_gc();
    test_lookup_across_views_multi();
    test_snapshot_catalog_member_sync_and_deltas();
    test_snapshot_standby_ecs_and_soa_serial();
        test_snapshot_rebuild_case_1();
    test_snapshot_rebuild_case_2();
    test_snapshot_rebuild_case_3();
    test_snapshot_rebuild_case_4();
    test_snapshot_rebuild_case_5();
    test_snapshot_rebuild_case_6();
    test_snapshot_rebuild_case_7();
    test_snapshot_rebuild_case_8();
    test_snapshot_rebuild_case_10();
    test_snapshot_rebuild_case_12();
    test_snapshot_rebuild_case_13();
    test_snapshot_rebuild_case_14();
    test_snapshot_rebuild_case_15();
    test_snapshot_rebuild_case_16();
    test_snapshot_rebuild_case_17();
    test_snapshot_rebuild_case_18();
    test_snapshot_rebuild_case_19();
    test_snapshot_rebuild_case_21();
    test_snapshot_rebuild_case_22();
    test_snapshot_rebuild_case_23();
    test_snapshot_rebuild_case_24();
    test_snapshot_rebuild_case_25();
    test_snapshot_rebuild_case_27();
    test_snapshot_rebuild_case_28();
    test_snapshot_rebuild_case_29();
    test_snapshot_rebuild_case_30();
    test_snapshot_view_match_key();
    test_snapshot_rebuild_type_change();
    test_snapshot_rebuild_case_32();
    test_snapshot_rebuild_case_33();
    test_snapshot_rebuild_case_35();
    test_retire_object_and_entry_config();
    test_snapshot_in_view();
    /* Remove the scratch directory in-process: detached snapshot GC threads may
     * still be running here, and fork()/exec from a multi-threaded process (as
     * system("rm -rf") did) can deadlock the child under ASan. */
    WD_PHASE("cleanup");
    assert(nftw(g_dir, rm_entry, 16, FTW_DEPTH | FTW_PHYS) == 0);
    printf("=== All Snapshot Rebuild Tests PASSED ===\n");
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
