#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>
#include "fi/kari_fi.h"
#include "../dns_config_parser.h"
#include "../dns_zone_parser.h"
#include "../dns_snapshot_rcu.h"
#include "../dns_epoch_rcu.h"
#include "../dns_priv_sandbox.h"

#include <limits.h>
#include "../dns_server_internal.h"
#include "../dns_query_engine.h"
#include "../dns_axfr_ixfr.h"
#include "../dns_catalog_zone.h"
#include <unistd.h>

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

static void test_fi_snapshot_rebuild(void) {
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    zc.domain = (char *)"example.com.";
    zc.type = (char *)"master";
    zc.file = (char *)"example.com.zone";
    zc.next = NULL;

    view_config_t view_cfg;
    memset(&view_cfg, 0, sizeof(view_cfg));
    view_cfg.name = (char *)"default";
    view_cfg.zones = &zc;
    view_cfg.next = NULL;

    server_config_t config;
    memset(&config, 0, sizeof(config));
    config.views = &view_cfg;

    FI_SWEEP({
        zone_db_snapshot_t *new_snap = rebuild_zone_db_snapshot(&config, NULL, NULL, NULL, NULL, 0);
        if (new_snap) {
            release_zone_snapshot(new_snap);
        }
    });

    zone_db_snapshot_t *active = atomic_load_explicit(&g_zone_db_active, memory_order_acquire);
    if (active) {
        atomic_store_explicit(&g_zone_db_active, NULL, memory_order_release);
        free_zone_db_snapshot(active);
    }
}

/* ---------------------------------------------------------------------------
 * Catalog membership under allocation failure.
 *
 * For every transition between two catalog zone versions (members added and
 * removed, groups changed, change-of-ownership between catalogs, catalogs
 * emptied) the catalog is first brought to the "before" state with fault
 * injection paused, then catalog_process_membership() is re-run with its Nth
 * allocation failing, for every N. This drives the fallback paths (member
 * hash tables that could not be allocated, skipped members, aborted
 * rebuilds) that a healthy run never takes; each run must leave a usable
 * snapshot behind.
 * ------------------------------------------------------------------------- */
static char g_cdir[256];
static unsigned g_serial = 1;

static void cwrite(const char *name, const char *text) {
    char p[512]; snprintf(p, sizeof(p), "%s/%s", g_cdir, name);
    FILE *f = fopen(p, "w"); assert(f); fputs(text, f); fclose(f);
}

#define CATHDR(z) "$ORIGIN " z "\n$TTL 300\n@ IN SOA ns." z " h." z " %u 7200 3600 1209600 300\n@ IN NS ns." z "\nns IN A 192.0.2.1\n"
static const char *FI_CAT1[] = {
    CATHDR("cat1.example.") "version IN TXT \"2\"\n"
    "u1.zones IN PTR m1.example.\ngroup.u1.zones IN TXT \"b\"\ngroup.u1.zones IN TXT \"a\"\n"
    "u2.zones IN PTR m2.example.\nu5.zones IN PTR m5.example.\nu6.zones IN PTR m6.example.\n",
    CATHDR("cat1.example.") "version IN TXT \"2\"\n"
    "u1.zones IN PTR m1.example.\ngroup.u1.zones IN TXT \"c\"\n"
    "u3.zones IN PTR m3.example.\ngroup.u3.zones IN TXT \"x\"\nu6.zones IN PTR m6.example.\n",
    CATHDR("cat1.example.") "version IN TXT \"2\"\n"
    "u1.zones IN PTR m1.example.\ncoo.u1.zones IN PTR cat2.example.\nu3.zones IN PTR m3.example.\n",
    CATHDR("cat1.example.") "version IN TXT \"2\"\n",
};
static const char *FI_CAT2[] = {
    CATHDR("cat2.example.") "version IN TXT \"2\"\nuA.zones IN PTR n1.example.\n",
    CATHDR("cat2.example.") "version IN TXT \"2\"\nuA.zones IN PTR n1.example.\nuB.zones IN PTR m2.example.\n",
    CATHDR("cat2.example.") "version IN TXT \"2\"\nuA.zones IN PTR n1.example.\nu9.zones IN PTR m1.example.\n",
    CATHDR("cat2.example.") "version IN TXT \"2\"\nu9.zones IN PTR m1.example.\ngroup.u9.zones IN TXT \"moved\"\n",
};
#define NCAT (sizeof(FI_CAT1) / sizeof(FI_CAT1[0]))

static void cat_write_version(size_t k) {
    char b[2048];
    snprintf(b, sizeof(b), FI_CAT1[k], g_serial++); cwrite("cat1.zone", b);
    snprintf(b, sizeof(b), FI_CAT2[k], g_serial++); cwrite("cat2.zone", b);
}

/* reload both catalogs in every view; with 'process' also apply membership */
static void cat_run(server_config_t *cfg, bool reload, bool process) {
    zone_db_snapshot_t *snap = acquire_zone_snapshot();
    if (!snap) return;
    retain_zone_snapshot(snap);
    const char *cats[] = { "cat1.example.", "cat2.example." };
    size_t vc = snap->view_count < 2 ? snap->view_count : 2;
    char vnames[2][64]; zone_db_entry_t *ents[2][2];
    for (size_t v = 0; v < vc; v++) {
        snprintf(vnames[v], sizeof(vnames[v]), "%s", snap->views[v].name ? snap->views[v].name : "");
        for (int c = 0; c < 2; c++) ents[v][c] = find_zone_in_view(&snap->views[v], cats[c]);
    }
    release_zone_snapshot(snap);
    for (size_t v = 0; v < vc; v++) {
        for (int c = 0; c < 2; c++) {
            zone_config_t *zc = find_zone_config_in_view(cfg, vnames[v], cats[c]);
            if (!ents[v][c] || !zc) continue;
            if (reload) (void)reload_master_zone(ents[v][c], zc);
            if (process) catalog_process_membership(ents[v][c], zc, vnames[v]);
        }
    }
}

static void test_fi_catalog_membership(void) {
    snprintf(g_cdir, sizeof(g_cdir), "/tmp/karidns_fi_cat_XXXXXX");
    assert(mkdtemp(g_cdir));
    static char conf[4096];
    snprintf(conf, sizeof(conf),
        "options { directory \"%s\"; };\n"
        "view \"internal\" { match-clients { 10.0.0.0/8; };\n"
        "  zone \"cat1.example\" { type master; file \"%s/cat1.zone\"; catalog-zone yes; masters { 127.0.0.1; }; };\n"
        "  zone \"cat2.example\" { type master; file \"%s/cat2.zone\"; catalog-zone yes; };\n"
        "};\n"
        "view \"external\" { match-clients { any; };\n"
        "  zone \"cat1.example\" { type master; file \"%s/cat1.zone\"; catalog-zone yes; };\n"
        "};\n", g_cdir, g_cdir, g_cdir, g_cdir);
    fi_reset();
    server_config_t *cfg = calloc(1, sizeof(*cfg));
    assert(cfg);
    int prc = parse_named_conf(conf, cfg);
    if (prc != 0) { fprintf(stderr, "config rejected (%d):\n%s", prc, conf); abort(); }
    atomic_store_explicit(&g_config_db.active, cfg, memory_order_release);

    unsigned runs = 0;
    for (size_t from = 0; from < NCAT; from++) {
        for (size_t to = 0; to < NCAT; to++) {
            if (to == from) continue;
            FI_SWEEP({
                fi_pause();
                cat_write_version(from);
                rebuild_zone_db_from_config(cfg, false);
                cat_run(cfg, true, true);
                cat_write_version(to);
                cat_run(cfg, true, false);
                fi_resume();
                cat_run(cfg, false, true);
                fi_pause();
                /* whatever failed, the published snapshot must stay usable */
                zone_db_snapshot_t *snap = acquire_zone_snapshot();
                assert(snap);
                retain_zone_snapshot(snap);
                for (size_t v = 0; v < snap->view_count; v++) {
                    (void)find_zone_in_view(&snap->views[v], "m1.example.");
                    (void)find_zone_in_view(&snap->views[v], "n1.example.");
                }
                release_zone_snapshot(snap);
                fi_resume();
                runs++;
            });
        }
    }
    printf("  -> catalog membership transitions under OOM: %u runs\n", runs);
}

int main(void) {
    printf("[*] Running test_fi_snapshot...\n");
    test_fi_snapshot_rebuild();
    test_fi_catalog_membership();
    printf("[+] test_fi_snapshot passed successfully.\n");
    return 0;
}
