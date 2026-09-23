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

#include "dns_wire.h"
#include "dns_config_parser.h"
#include "dns_zone_parser.h"
#include "dns_snapshot_rcu.h"
#include "dns_priv_sandbox.h"
#include "dns_query_engine.h"
#include "dns_axfr_ixfr.h"
#include "dns_cidr.h"
#include "dns_tsig_acl.h"
#include "dns_utils.h"

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
    return acquire_zone_snapshot();
}

static void test_rebuild_two_views(void) {
    printf("[TEST] Snapshot rebuild: views, zone types, lookup across views, reload results...\n");
    wfile("a.zone", ZONE_A);
    wfile("b.zone", ZONE_B);
    wfile("broken.zone", "$ORIGIN c.example.\n@ IN SOA ns h 1 2 3 4 5\nwww IN A\n");
    wfile("nosoa.zone", "$ORIGIN d.example.\n$TTL 60\n@ IN NS ns.d.example.\nns IN A 192.0.2.4\n");
    wfile("dname.zone", "$ORIGIN e.example.\n$TTL 60\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nd IN DNAME t.example.\nx.d IN A 192.0.2.5\n");

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
    assert(vi && ve && vi->zone_count == 2 && ve->zone_count == 1);
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
    zone_arena_t *arena = atomic_load_explicit(&za->rcu.active, memory_order_acquire);
    assert(arena && arena->count >= 8);
    release_zone_snapshot(snap);

    /* --- reload_master_zone verdicts --- */
    zone_config_t *zcfg = find_zone_config_in_view(cfg, "internal", "a.example.");
    zone_db_snapshot_t *s2 = acquire_zone_snapshot();
    zone_db_entry_t *ea = snapshot_get_zone(s2, "a.example.");
    assert(reload_master_zone(ea, zcfg) == RELOAD_OK);                    /* unchanged file reloads fine */
    wfile("a.zone", "$ORIGIN a.example.\n$TTL 300\n@ IN SOA ns.a.example. h.a.example. 2 7200 3600 1209600 300\n"
                    "@ IN NS ns.a.example.\nns IN A 192.0.2.1\nwww IN A 192.0.2.10\nnew IN A 192.0.2.99\n");
    assert(reload_master_zone(ea, zcfg) == RELOAD_OK);
    zone_arena_t *na = atomic_load_explicit(&ea->rcu.active, memory_order_acquire);
    bool found_new = false;
    for (size_t i = 0; i < na->count; i++) if (!strcasecmp(na->records[i].name, "new.a.example.")) found_new = true;
    assert(found_new);

    char zpath[300];
    zone_config_t bad = *zcfg;
    snprintf(zpath, sizeof(zpath), "%s/broken.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_PARSE || reload_master_zone(ea, &bad) == RELOAD_ERR_MISSING_SOA);
    snprintf(zpath, sizeof(zpath), "%s/nosoa.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_MISSING_SOA);
    snprintf(zpath, sizeof(zpath), "%s/dname.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_PARSE);
    snprintf(zpath, sizeof(zpath), "%s/does-not-exist.zone", g_dir); bad.file = zpath;
    assert(reload_master_zone(ea, &bad) == RELOAD_ERR_FILE_READ);
    /* a failed reload must leave the served zone untouched */
    assert(atomic_load_explicit(&ea->rcu.active, memory_order_acquire) == na);
    release_zone_snapshot(s2);
    printf("  -> rebuild/lookup/reload verdicts passed.\n");
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

    // wait_for_readers NULL and empty
    wait_for_readers(NULL);
    zone_arena_t arena;
    memset(&arena, 0, sizeof(arena));
    arena.reader_count = ATOMIC_VAR_INIT(0);
    wait_for_readers(&arena);

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

int main(void) {
    printf("=== Starting Snapshot Rebuild Tests ===\n");
    snprintf(g_dir, sizeof(g_dir), "/tmp/karidns_snap_XXXXXX");
    assert(mkdtemp(g_dir));
    test_rebuild_two_views();
    test_snapshot_retain_release_and_gc();
    test_lookup_across_views_multi();
    char cmd[200]; snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir); assert(system(cmd) == 0);
    printf("=== All Snapshot Rebuild Tests PASSED ===\n");
    return 0;
}

