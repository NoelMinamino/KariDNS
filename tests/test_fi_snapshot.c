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
#include "test_zext.h"
#include "test_tmpdir.h"
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

/* A digest of everything a failed change must leave as it was: the zones of the index (name, entry, owner and unique id of a catalog member,
 * groups, the members a catalog zone lists), the CoO intentions, the number of queued changes and (with_registry) the hidden state of the
 * registry's zones d1..d6.  The elements are added up, so the order of the slots does not matter (a table that grew has another order).
 * (Call it with the fault injection paused.) */
extern pending_coo_t *g_pending_coo;
extern int g_pending_coo_count;

static uint64_t fi_fnv(const char *s) {
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 1099511628211ull;
    return h;
}

static uint64_t fi_digest(bool with_registry) {
    uint64_t sum = 0, ordered = 7;
    char t[2048];
    zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
    for (size_t v = 0; snap && v < snap->view_count; v++) {
        zdir_iter_t it;
        zdir_iter_init(&it, &snap->views[v]);
        for (zdir_elem_t *e; (e = zdir_iter_next(&it));) {
            zone_db_entry_t *en = zdir_entry(e);
            size_t o = (size_t)snprintf(t, sizeof(t), "%s|%s|%p|%s|%s|%d", snap->views[v].name, e->name, (void *)en,
                                        en ? zone_entry_catalog_owner(en) : "", en ? zone_entry_catalog_uid(en) : "", en ? en->group_count : 0);
            for (int g = 0; en && g < en->group_count && o < sizeof(t); g++) o += (size_t)snprintf(t + o, sizeof(t) - o, "|g:%s", en->groups[g]);
            for (int m = 0; en && m < en->catalog_member_count && o < sizeof(t); m++)
                o += (size_t)snprintf(t + o, sizeof(t) - o, "|m:%s/%s", en->catalog_members[m].domain, en->catalog_members[m].unique_id);
            sum += fi_fnv(t);
        }
    }
    release_zone_snapshot(snap);
    for (int p = 0; p < g_pending_coo_count; p++) {
        snprintf(t, sizeof(t), "%s|%s|%s", g_pending_coo[p].domain, g_pending_coo[p].old_catalog, g_pending_coo[p].new_catalog);
        ordered = ordered * 31 + fi_fnv(t);
    }
    sum += ordered * 17 + (uint64_t)dbreg_pending_count();
    for (int i = 0; with_registry && i < 6; i++) {
        char nm[32];
        dbreg_info_t inf;
        snprintf(nm, sizeof(nm), "d%d.test.", i + 1);
        int n = dbreg_find_info("default", nm, &inf, 1);
        snprintf(t, sizeof(t), "%s|%d|%d|%d|%d|%d", nm, n, n ? inf.shadowed : 0, n ? inf.shadow_by : 0, n ? inf.has_entry : 0, n ? (int)inf.source_id : 0);
        sum += fi_fnv(t);
    }
    return sum;
}

/* with this set, every membership change of cat_run() that did not publish a snapshot (it failed, or had nothing to change) must have left
 * the zones, their owners and groups, the member lists and the CoO intentions as they were */
static bool g_cat_check;
static unsigned g_cat_unchanged;      /* how many such changes were compared */

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
            if (process) {
                zone_db_snapshot_t *before_snap = NULL;
                uint64_t before = 0;
                if (g_cat_check) {
                    fi_pause();
                    before_snap = acquire_retained_zone_snapshot();      /* (kept: its address cannot be reused by the next snapshot) */
                    before = fi_digest(false);
                    fi_resume();
                }
                catalog_process_membership(ents[v][c], zc, vnames[v]);
                if (g_cat_check) {
                    fi_pause();
                    if (acquire_zone_snapshot() == before_snap) {
                        assert(fi_digest(false) == before);
                        g_cat_unchanged++;
                    }
                    release_zone_snapshot(before_snap);
                    fi_resume();
                }
            }
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
                g_cat_check = true;
                cat_run(cfg, false, true);
                g_cat_check = false;
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
    printf("  -> catalog membership transitions under OOM: %u runs, %u changes without a new snapshot compared with the state before\n", runs, g_cat_unchanged);
    assert(g_cat_unchanged > 0);
}

/* ---------------------------------------------------------------------------
 * The zone directory under allocation failure (D1a): the DB zone registry commits zones (elements, queues, the replaced entry's
 * node), the delta changes the directory in place (plans, a bigger table, a new tick list, the clone of the snapshot), zones are
 * deleted, and the full rebuild hides a DB zone behind a zone { } block.  Whatever fails, the directory must stay usable:
 * a lookup finds the zones that were applied, the walk and the counter agree, and nothing is freed twice.
 * ------------------------------------------------------------------------- */
static void fi_dir_check(void) {
    zone_db_snapshot_t *snap = acquire_retained_zone_snapshot();
    if (!snap) return;
    for (size_t v = 0; v < snap->view_count; v++) {
        size_t n = 0;
        zdir_iter_t it;
        zdir_iter_init(&it, &snap->views[v]);
        for (zdir_elem_t *e; (e = zdir_iter_next(&it));) {
            n++;
            zone_db_entry_t *en = zdir_entry(e);
            assert(en && zdir_find_exact(&snap->views[v], e->name) == e);
            assert(find_zone_in_view(&snap->views[v], e->name) == en);
        }
        assert(n == zdir_count(&snap->views[v]));
    }
    release_zone_snapshot(snap);
}

/* the delta of the DB zones; when it fails (out of memory) the planning has changed nothing: the zones of the index, the hidden state of the
 * registry's zones, the CoO intentions and the queued changes are as they were (the changes are kept for the next try) */
static unsigned g_delta_failed;       /* how many failed deltas were compared */

static int fi_delta_checked(void) {
    fi_pause();
    uint64_t before = fi_digest(true);
    fi_resume();
    int rc = snapshot_apply_db_delta();
    if (rc < 0) {
        fi_pause();
        assert(fi_digest(true) == before);
        g_delta_failed++;
        fi_resume();
    }
    return rc;
}

static void test_fi_directory_delta(void) {
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    zc.domain = (char *)"static.test.";
    zc.type = (char *)"master";
    view_config_t vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.name = (char *)"default";
    vcfg.zones = &zc;
    server_config_t config;
    memset(&config, 0, sizeof(config));
    config.views = &vcfg;
    atomic_store_explicit(&g_config_db.active, &config, memory_order_release);
    zone_config_t zc2 = zc;
    zc2.domain = (char *)"d1.test.";                    /* a zone { } with the name of a DB zone: it hides it in the second configuration */
    server_config_t config2 = config;
    view_config_t vcfg2 = vcfg;
    vcfg2.zones = &zc2;
    config2.views = &vcfg2;

    unsigned runs = 0;
    uint8_t dg[32] = { 1 };
    FI_SWEEP({
        fi_pause();
        dbreg_reset();
        zone_db_snapshot_t *s0 = rebuild_zone_db_snapshot(&config, NULL, NULL, NULL, NULL, 0);
        assert(s0);
        zone_db_entry_t *ents[6] = { 0 };
        const char *names[6] = { "d1.test.", "d2.test.", "d3.test.", "d4.test.", "d5.test.", "d6.test." };
        for (int i = 0; i < 6; i++) {
            ents[i] = create_new_zone_entry(names[i], "default");
            assert(ents[i]);
            ents[i]->source = ZONE_SRC_DB;
            if (i == 5) {                                    /* a secondary: it ticks, so the tick list is rebuilt */
                ents[i]->is_secondary = true;
                ents[i]->kind = ZONE_KIND_SECONDARY;
            }
        }
        fi_resume();
        for (int i = 0; i < 6; i++) {
            if (dbreg_commit("default", names[i], ents[i], true, 100 + i, 1, dg, NULL) != 0) {
                fi_pause();
                free_zone_db_entry(ents[i]);                 /* (the caller keeps a new entry the registry could not take) */
                ents[i] = NULL;
                fi_resume();
            }
        }
        (void)fi_delta_checked();
        (void)fi_delta_checked();                            /* a failed delta is tried again */
        fi_pause();
        fi_dir_check();
        fi_resume();
        /* a new entry for a zone that is in the index (the old one is given back), then deletions */
        zone_db_entry_t *again = NULL;
        fi_pause();
        again = create_new_zone_entry("d2.test.", "default");
        assert(again);
        again->source = ZONE_SRC_DB;
        fi_resume();
        if (dbreg_commit("default", "d2.test.", again, true, 101, 2, dg, NULL) != 0) {
            fi_pause();
            free_zone_db_entry(again);
            fi_resume();
        }
        (void)dbreg_delete("default", "d3.test.", 102);
        (void)dbreg_delete("default", "d4.test.", 103);
        (void)fi_delta_checked();
        (void)fi_delta_checked();
        fi_pause();
        fi_dir_check();
        /* (the zones of the index, not the registry's hidden flags: the full rebuild of a configuration, unlike the delta, sets those while it
         * collects the DB zones and sets them again at the retry; that is how it was before the directory) */
        uint64_t before_rebuild = fi_digest(false);
        fi_resume();
        /* the full rebuild with a zone { } that hides d1.test.: when it fails it has hidden nothing */
        zone_db_snapshot_t *s1 = rebuild_zone_db_snapshot(&config2, NULL, NULL, NULL, NULL, 0);
        fi_pause();
        if (!s1) assert(fi_digest(false) == before_rebuild);
        fi_dir_check();
        gc_snapshot_wait_idle();
        zone_retire_process(true);
        fi_resume();
        runs++;
    });
    fi_reset();
    dbreg_reset();
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> zone directory (commit, delta, delete, hide) under OOM: %u runs, %u failed deltas compared with the state before\n", runs, g_delta_failed);
    assert(g_delta_failed > 0);
}

/* ---------------------------------------------------------------------------
 * A queued DB zone whose name an element of the index has when the delta is planned: the zone { } of karidns.conf wins (D-PRIO) and
 * the registry's zone is hidden by it.  (The race this stands for: the commit looked at the configuration before a reload, the rebuild
 * of the reload ran, then the commit queued the zone.)  Here the index has the zone { d1.test. } while the configuration the commit
 * looks at does not.  Under out-of-memory the plan that hides it changes nothing until it is carried out.
 * ------------------------------------------------------------------------- */
static zone_db_entry_t *gc_mk(const char *name);

static void test_fi_delta_hide(void) {
    zone_config_t zc1, zc2;
    memset(&zc1, 0, sizeof(zc1));
    zc1.domain = (char *)"static.test.";
    zc1.type = (char *)"master";
    zc2 = zc1;
    zc2.domain = (char *)"d1.test.";
    view_config_t vc1, vc2;
    memset(&vc1, 0, sizeof(vc1));
    vc1.name = (char *)"default";
    vc2 = vc1;
    vc1.zones = &zc1;
    vc2.zones = &zc2;
    server_config_t cfg1, cfg2;
    memset(&cfg1, 0, sizeof(cfg1));
    cfg1.views = &vc1;
    cfg2 = cfg1;
    cfg2.views = &vc2;

    unsigned runs = 0, hidden = 0;
    uint8_t dg[32] = { 1 };
    FI_SWEEP({
        fi_pause();
        dbreg_reset();
        atomic_store_explicit(&g_config_db.active, &cfg2, memory_order_release);
        zone_db_snapshot_t *s = rebuild_zone_db_snapshot(&cfg2, NULL, NULL, NULL, NULL, 0);
        assert(s);                                           /* (the index has d1.test. as the zone { } of the configuration) */
        atomic_store_explicit(&g_config_db.active, &cfg1, memory_order_release);   /* the commit does not see it */
        zone_db_entry_t *e = gc_mk("d1.test.");
        fi_resume();
        bool committed = dbreg_commit("default", "d1.test.", e, true, 300, 1, dg, NULL) == 0;
        if (!committed) {
            fi_pause();
            free_zone_db_entry(e);
            fi_resume();
        }
        (void)fi_delta_checked();
        (void)fi_delta_checked();
        fi_pause();
        fi_dir_check();
        dbreg_info_t inf;
        if (committed && dbreg_pending_count() == 0) {
            assert(dbreg_find_info("default", "d1.test.", &inf, 1) == 1);
            assert(inf.shadowed && inf.shadow_by == DBREG_SH_CONFIG);
            zone_db_snapshot_t *cur = acquire_retained_zone_snapshot();
            assert(cur && find_zone_in_view(&cur->views[0], "d1.test.") != e);   /* the zone { } is served, not the DB zone */
            release_zone_snapshot(cur);
            hidden++;
        }
        gc_snapshot_wait_idle();
        zone_retire_process(true);
        fi_resume();
        runs++;
    });
    fi_reset();
    dbreg_reset();
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> DB zone hidden by a zone { } found at the delta, under OOM: %u runs, hidden in %u\n", runs, hidden);
    assert(hidden > 0);
}

/* ---------------------------------------------------------------------------
 * The cleanup thread of a retired snapshot cannot be started (pthread_create fails once).  The snapshot stays queued with its garbage
 * (the garbage of every later snapshot waits behind it, the release is in order), and the next try frees all of it: the next publish
 * (case 1) or the control thread's tick (case 2, gc_start_pending()) starts the threads.
 * ------------------------------------------------------------------------- */
static zone_db_entry_t *gc_mk(const char *name) {
    zone_db_entry_t *e = create_new_zone_entry(name, "default");
    assert(e);
    e->source = ZONE_SRC_DB;
    return e;
}

static void gc_commit(const char *name, int64_t id, int64_t ver) {
    uint8_t dg[32] = { 1 };
    zone_db_entry_t *e = gc_mk(name);
    assert(dbreg_commit("default", name, e, true, id, ver, dg, NULL) == 0);
}

static void test_fi_gc_thread_start(void) {
    zone_config_t zc;
    memset(&zc, 0, sizeof(zc));
    zc.domain = (char *)"static.test.";
    zc.type = (char *)"master";
    view_config_t vcfg;
    memset(&vcfg, 0, sizeof(vcfg));
    vcfg.name = (char *)"default";
    vcfg.zones = &zc;
    server_config_t config;
    memset(&config, 0, sizeof(config));
    config.views = &vcfg;
    atomic_store_explicit(&g_config_db.active, &config, memory_order_release);

    for (int how = 0; how < 2; how++) {
        fi_reset();
        dbreg_reset();
        assert(rebuild_zone_db_snapshot(&config, NULL, NULL, NULL, NULL, 0));
        gc_snapshot_wait_idle();
        assert(zdir_gc_queued() == 0 && !gc_has_unstarted());
        gc_commit("g1.test.", 200, 1);
        gc_commit("g2.test.", 201, 1);
        assert(snapshot_apply_db_delta() > 0);                 /* the first snapshot retires, its thread starts */
        gc_snapshot_wait_idle();
        assert(zdir_gc_queued() == 0);

        /* a replacement (the old entry is garbage) and a deletion, with the cleanup thread of the retired snapshot failing */
        gc_commit("g2.test.", 201, 2);
        assert(dbreg_delete("default", "g1.test.", 200) == 1);
        fi_reset();
        fi_arm_nth(FI_PTHREAD_CREATE, 1);
        assert(snapshot_apply_db_delta() > 0);
        assert(fi_fired_kind(FI_PTHREAD_CREATE));
        assert(gc_has_unstarted() && zdir_gc_queued() == 1);   /* kept, with its garbage */
        gc_snapshot_wait_idle();
        assert(zdir_gc_queued() == 1);                         /* (nothing frees it) */
        fi_reset();

        if (how == 0) {
            /* the next publish: its snapshot queues behind the first, and both threads are started */
            gc_commit("g3.test.", 202, 1);
            assert(snapshot_apply_db_delta() > 0);
        } else {
            gc_start_pending();                                /* the control thread's tick */
        }
        gc_snapshot_wait_idle();
        assert(!gc_has_unstarted());
        assert(zdir_gc_queued() == 0);                         /* every queued snapshot was drained and freed with its garbage */
        fi_dir_check();
        zone_retire_process(true);
    }
    fi_reset();
    dbreg_reset();
    atomic_store_explicit(&g_config_db.active, NULL, memory_order_release);
    printf("  -> cleanup thread that cannot be started: kept, then freed by the next publish and by the tick\n");
}

int main(void) {
    printf("[*] Running test_fi_snapshot...\n");
    test_fi_snapshot_rebuild();
    test_fi_directory_delta();
    test_fi_delta_hide();
    test_fi_gc_thread_start();
    test_fi_catalog_membership();
    tmpdir_remove(g_cdir);
    printf("[+] test_fi_snapshot passed successfully.\n");
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
