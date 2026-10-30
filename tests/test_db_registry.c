/*
 * test_db_registry.c - the DB zone registry, the view delta and the zone install of the database loader link
 * (beta design 4.1-4.5, milestone B4b): dns_snapshot_rcu.c (dbreg_*, snapshot_apply_db_delta, the shadowing rules of
 * the full-configuration rebuild, dbcfg) and dns_db_install.c (db_zone_build_*).
 *
 *  1. install: a zone built from AXFR-format messages is published into an entry (serial, SOA timers, image, NOTIFY
 *     only when a loaded zone changes its serial); every rejection rule leaves the entry as it was.
 *  2. registry and delta: commit / apply / delete, idempotence, source id check, rejected-only records, walk.
 *  2b. the view delta changes the zone directory's index in place (and moves it to a bigger table when it would get too full).
 *  3. D-PRIO: a configured zone hides a DB zone, the DB zone comes back when the configured zone is removed.
 *  4. dbcfg: zone_entry_config() returns it for DB zones, a replaced block is retired and freed.
 *  5. concurrent readers while zones are added and removed: a reader never sees a DB zone without its image.
 *  6. (B6a) D17-1: a catalog member with the name of a DB zone hides it (catalog delta), the DB zone returns when the
 *     member leaves, a DB zone committed behind an existing member is hidden; dbreg_find_info(), dbreg_counts2(),
 *     dbreg_snapshot_entry().
 *  7. the reload fast path: an unchanged zone set takes the old view over (the same zone directory, the pending queue
 *     survives, match-clients and options { ixfr-history } still apply); a zone { } added, removed or retyped, or a view
 *     added, rebuilds from the registry; the queue of a view that left is dropped.
 *  8. a DB zone that leaves marks the glue dirty: the zones whose glue came from it are looked at again by the tick.
 *  9. (D1a) the zone directory: elements (state, flags, SOA values, counters, walk, longest suffix), a delta in place (no copy of the
 *     index unless it grows, tombstones reused), what a reader holds stays valid until the older snapshots are drained (ordered
 *     release of the garbage), hidden elements and zones shared with another view, a replaced entry and the tick list, the bytes per
 *     zone, and the zone memory accounting (design 8.1: resident, retired, IXFR differences, entries that go).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <ftw.h>

#include "../dns_config_parser.h"
#include "../dns_db_install.h"
#include "../dns_db_stream.h"
#include "../dns_utils.h"
#include "db/xfr_mocks.h"

/* the cleanup threads log the zone entries they free: the directory tests look at when that happens ("[GC] Freeing deleted zone 'x'") */
static pthread_mutex_t g_gc_log_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_gc_log[4096][64];
static int g_gc_logn;

void syslog(int priority, const char *format, ...) {
    (void)priority;
    /* (the code logs through kdns_syslog(), which formats the message and passes it here as "%s") */
    if (strcmp(format, "%s") == 0) {
        va_list ap;
        va_start(ap, format);
        const char *msg = va_arg(ap, const char *);
        va_end(ap);
        const char *key = "[GC] Freeing deleted zone '";
        if (strncmp(msg, key, strlen(key)) == 0) {
            pthread_mutex_lock(&g_gc_log_lock);
            if (g_gc_logn < 4096) {
                snprintf(g_gc_log[g_gc_logn], sizeof(g_gc_log[0]), "%s", msg + strlen(key));
                char *q = strrchr(g_gc_log[g_gc_logn], '\'');
                if (q) *q = '\0';
                g_gc_logn++;
            }
            pthread_mutex_unlock(&g_gc_log_lock);
        }
    }
}

static int gc_freed(const char *domain) {
    int n = 0;
    pthread_mutex_lock(&g_gc_log_lock);
    for (int i = 0; i < g_gc_logn; i++)
        if (strcmp(g_gc_log[i], domain) == 0) n++;
    pthread_mutex_unlock(&g_gc_log_lock);
    return n;
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ---------------------------------------------------------------- wire helpers */
typedef struct {
    uint8_t b[8192];
    size_t n;
    uint16_t an;
} msg_t;

static size_t put_name(uint8_t *p, const char *name) {
    size_t n = 0;
    const char *s = name;
    while (*s && !(s[0] == '.' && s[1] == '\0')) {
        const char *dot = strchr(s, '.');
        size_t l = dot ? (size_t)(dot - s) : strlen(s);
        p[n++] = (uint8_t)l;
        memcpy(p + n, s, l);
        n += l;
        if (!dot) break;
        s = dot + 1;
    }
    p[n++] = 0;
    return n;
}

static void msg_init(msg_t *m) {
    memset(m, 0, sizeof(*m));
    m->b[2] = 0x84;                       /* QR, AA */
    m->n = 12;
}

static void msg_rr(msg_t *m, const char *owner, uint16_t type, uint16_t cls, const uint8_t *rd, size_t rdlen) {
    m->n += put_name(m->b + m->n, owner);
    m->b[m->n++] = (uint8_t)(type >> 8); m->b[m->n++] = (uint8_t)type;
    m->b[m->n++] = (uint8_t)(cls >> 8); m->b[m->n++] = (uint8_t)cls;
    m->b[m->n++] = 0; m->b[m->n++] = 0; m->b[m->n++] = 0x0e; m->b[m->n++] = 0x10;       /* TTL 3600 */
    m->b[m->n++] = (uint8_t)(rdlen >> 8); m->b[m->n++] = (uint8_t)rdlen;
    memcpy(m->b + m->n, rd, rdlen);
    m->n += rdlen;
    m->an++;
    m->b[6] = (uint8_t)(m->an >> 8); m->b[7] = (uint8_t)m->an;
}

static size_t soa_rd(uint8_t *p, const char *zone, uint32_t serial) {
    char mn[300], rn[300];
    snprintf(mn, sizeof(mn), "ns.%s", zone);
    snprintf(rn, sizeof(rn), "host.%s", zone);
    size_t n = put_name(p, mn);
    n += put_name(p + n, rn);
    uint32_t v[5] = { serial, 7200, 3600, 1209600, 300 };
    for (int i = 0; i < 5; i++) {
        p[n++] = (uint8_t)(v[i] >> 24); p[n++] = (uint8_t)(v[i] >> 16); p[n++] = (uint8_t)(v[i] >> 8); p[n++] = (uint8_t)v[i];
    }
    return n;
}

static void msg_soa(msg_t *m, const char *zone, uint32_t serial) {
    uint8_t rd[600];
    msg_rr(m, zone, 6, 1, rd, soa_rd(rd, zone, serial));
}

static void msg_a(msg_t *m, const char *owner, uint8_t last) {
    uint8_t rd[4] = { 192, 0, 2, last };
    msg_rr(m, owner, 1, 1, rd, 4);
}

static void msg_ns(msg_t *m, const char *owner, const char *target) {
    uint8_t rd[300];
    msg_rr(m, owner, 2, 1, rd, put_name(rd, target));
}

/* SOA, NS, nrr A records, SOA: one message */
static void zone_msg(msg_t *m, const char *zone, uint32_t serial, int nrr) {
    msg_init(m);
    msg_soa(m, zone, serial);
    char ns[300];
    snprintf(ns, sizeof(ns), "ns.%s", zone);
    msg_ns(m, zone, ns);
    for (int i = 0; i < nrr; i++) {
        char o[320];
        snprintf(o, sizeof(o), "h%d.%s", i, zone);
        msg_a(m, o, (uint8_t)(i + 1));
    }
    msg_soa(m, zone, serial);
}

/* ---------------------------------------------------------------- fixtures */
static char g_dir[128];

static int rm_entry(const char *path, const struct stat *sb, int type, struct FTW *ftw) {
    (void)sb; (void)type; (void)ftw;
    return remove(path);
}

static server_config_t *load_conf(const char *fmt, ...) {
    char text[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    server_config_t *cfg = calloc(1, sizeof(*cfg));
    CHECK(cfg != NULL);
    int rc = parse_named_conf(text, cfg);
    if (rc != 0) { fprintf(stderr, "config failed:\n%s\n", text); exit(1); }
    return cfg;
}

static void rebuild(server_config_t *cfg) {
    atomic_store_explicit(&g_config_db.active, cfg, memory_order_release);
    rebuild_zone_db_from_config(cfg, false);
}

static zone_db_entry_t *new_entry(const char *view, const char *zone) {
    zone_db_entry_t *e = create_new_zone_entry(zone, view);
    CHECK(e != NULL);
    zone_config_t *dc = db_zone_config_new(zone, NULL);
    CHECK(dc != NULL);
    e->source = ZONE_SRC_DB;
    e->kind = ZONE_KIND_PRIMARY;
    atomic_store_explicit(&e->dbcfg, dc, memory_order_release);
    return e;
}

static int install_msgs_f(zone_db_entry_t *e, const char *zone, uint64_t declared, uint32_t flags, const msg_t *ms, int nm, char *why, size_t whylen) {
    db_zone_build_t *b = db_zone_build_new(zone, declared, flags);
    CHECK(b != NULL);
    int rc = 0;
    for (int i = 0; i < nm && rc == 0; i++) rc = db_zone_build_feed(b, ms[i].b, ms[i].n, why, whylen);
    if (rc == 0) rc = db_zone_build_install(b, e, NULL, why, whylen);
    db_zone_build_free(b);
    return rc;
}

static int install_msgs(zone_db_entry_t *e, const char *zone, uint64_t declared, const msg_t *ms, int nm,
                        char *why, size_t whylen, bool *notified) {
    db_zone_build_t *b = db_zone_build_new(zone, declared, 0);
    CHECK(b != NULL);
    int rc = 0;
    for (int i = 0; i < nm && rc == 0; i++) rc = db_zone_build_feed(b, ms[i].b, ms[i].n, why, whylen);
    if (rc == 0) rc = db_zone_build_install(b, e, notified, why, whylen);
    db_zone_build_free(b);
    return rc;
}

/* a complete zone through the same steps as the ingest thread: build, install, register */
static zone_db_entry_t *add_zone(const char *view, const char *zone, uint32_t serial, int nrr, int64_t id) {
    msg_t m;
    zone_msg(&m, zone, serial, nrr);
    zone_db_entry_t *e = dbreg_lookup_entry(view, zone);
    bool created = false;
    if (!e) { e = new_entry(view, zone); created = true; }
    char why[128];
    int rc = install_msgs(e, zone, (uint64_t)nrr + 3, &m, 1, why, sizeof(why), NULL);
    if (rc != 0) { printf("  install of %s failed: %s\n", zone, why); CHECK(rc == 0); return NULL; }
    uint8_t dg[32] = { 1 };
    bool sh = false;
    CHECK(dbreg_commit(view, zone, e, created, id, serial, dg, &sh) == 0);
    return e;
}

static bool in_snapshot(const char *view, zone_db_entry_t *e) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, view);
    bool r = v && find_zone_exact_in_view(v, e->domain) == e;
    release_zone_snapshot(s);
    return r;
}

static bool name_in_snapshot(const char *view, const char *name) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, view);
    bool r = v && find_zone_exact_in_view(v, name) != NULL;
    release_zone_snapshot(s);
    return r;
}

/* ---------------------------------------------------------------- 1. install */
static void test_install(void) {
    printf("[TEST] DB install: a zone from AXFR-format messages, every rejection rule...\n");
    zone_db_entry_t *e = new_entry("default", "a.test.");
    msg_t m;
    char why[128] = "";
    bool notified = true;

    zone_msg(&m, "a.test.", 10, 3);
    CHECK(install_msgs(e, "a.test.", 3 + 3, &m, 1, why, sizeof(why), &notified) == 0);
    CHECK(!notified);                                           /* the first load sends no NOTIFY (R-21) */
    CHECK(e->serial == 10 && e->refresh == 7200 && e->retry == 3600 && e->expire == 1209600);
    zone_version_t *v = atomic_load(&e->rcu.active);
    CHECK(v->image && v->image->n_rrs == 5);                    /* SOA, NS, 3 A (the closing SOA is not a record) */
    CHECK(!atomic_load(&e->notify_now));

    /* a new serial of a loaded zone: published, NOTIFY requested */
    zone_msg(&m, "a.test.", 11, 4);
    CHECK(install_msgs(e, "a.test.", 4 + 3, &m, 1, why, sizeof(why), &notified) == 0);
    CHECK(notified && atomic_load(&e->notify_now));
    CHECK(e->serial == 11);
    v = atomic_load(&e->rcu.active);
    CHECK(v->image && v->image->n_rrs == 6);
    atomic_store(&e->notify_now, false);
    /* the same serial again: published again, no NOTIFY; a lower serial is accepted (an operator restoring old data) */
    zone_msg(&m, "a.test.", 11, 4);
    CHECK(install_msgs(e, "a.test.", 7, &m, 1, why, sizeof(why), &notified) == 0 && !notified);
    zone_msg(&m, "a.test.", 5, 2);
    CHECK(install_msgs(e, "a.test.", 5, &m, 1, why, sizeof(why), &notified) == 0);
    CHECK(e->serial == 5);

    uint32_t keep_serial = e->serial;
    size_t keep_rrs = atomic_load(&e->rcu.active)->image->n_rrs;

    /* the zone in several messages */
    {
        msg_t a, b, c;
        msg_init(&a); msg_soa(&a, "a.test.", 20); msg_ns(&a, "a.test.", "ns.a.test.");
        msg_init(&b); msg_a(&b, "x.a.test.", 1); msg_a(&b, "y.a.test.", 2);
        msg_init(&c); msg_soa(&c, "a.test.", 20);
        msg_t ms[3] = { a, b, c };
        CHECK(install_msgs(e, "a.test.", 5, ms, 3, why, sizeof(why), &notified) == 0);
        CHECK(e->serial == 20 && atomic_load(&e->rcu.active)->image->n_rrs == 4);
        keep_serial = 20;
        keep_rrs = 4;
    }

    /* rejections: the entry keeps its last good version */
    zone_msg(&m, "a.test.", 30, 2);
    CHECK(install_msgs(e, "a.test.", 6, &m, 1, why, sizeof(why), NULL) != 0 && strstr(why, "count mismatch"));
    CHECK(install_msgs(e, "a.test.", 4, &m, 1, why, sizeof(why), NULL) != 0 && strstr(why, "count mismatch"));
    {   /* an owner outside the zone: AXFR-in would skip it, the DB path refuses the zone */
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_a(&m, "host.other.test.", 1); msg_soa(&m, "a.test.", 31);
        db_zone_build_t *b = db_zone_build_new("a.test.", 3, 0);
        CHECK(db_zone_build_feed(b, m.b, m.n, why, sizeof(why)) != 0 && strstr(why, "outside the zone"));
        db_zone_build_free(b);
    }
    {   /* the apex SOA of another zone */
        msg_init(&m); msg_soa(&m, "b.test.", 31); msg_soa(&m, "b.test.", 31);
        db_zone_build_t *b = db_zone_build_new("a.test.", 2, 0);
        CHECK(db_zone_build_feed(b, m.b, m.n, why, sizeof(why)) != 0);
        db_zone_build_free(b);
    }
    {   /* a subdomain's SOA first: it is inside the zone but not the apex */
        msg_init(&m); msg_soa(&m, "sub.a.test.", 31); msg_a(&m, "a.test.", 1); msg_soa(&m, "sub.a.test.", 31);
        CHECK(install_msgs(e, "a.test.", 3, &m, 1, why, sizeof(why), NULL) != 0 && strstr(why, "SOA of its apex"));
    }
    {   /* ZONE_BEGIN declared another serial than the SOA of the data (B8t-2): refused at ZONE_END, the entry stays */
        zone_msg(&m, "a.test.", 41, 1);
        db_zone_build_t *b = db_zone_build_new("a.test.", 4, 0);
        db_zone_build_set_serial(b, 40);
        CHECK(db_zone_build_feed(b, m.b, m.n, why, sizeof(why)) == 0);
        CHECK(db_zone_build_install(b, e, NULL, why, sizeof(why)) != 0 && strstr(why, "not the one ZONE_BEGIN declared"));
        db_zone_build_free(b);
        CHECK(e->serial == keep_serial);
        b = db_zone_build_new("a.test.", 4, 0);
        db_zone_build_set_serial(b, 41);                       /* the declared serial is the one in the data: published */
        CHECK(db_zone_build_feed(b, m.b, m.n, why, sizeof(why)) == 0);
        CHECK(db_zone_build_install(b, e, NULL, why, sizeof(why)) == 0);
        db_zone_build_free(b);
        CHECK(e->serial == 41);
        keep_serial = 41;
        keep_rrs = atomic_load(&e->rcu.active)->image->n_rrs;
    }
    {   /* no closing SOA */
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_a(&m, "x.a.test.", 1);
        CHECK(install_msgs(e, "a.test.", 3, &m, 1, why, sizeof(why), NULL) != 0 && strstr(why, "final SOA"));
    }
    {   /* a record after the closing SOA, in the same message and in a later one */
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_soa(&m, "a.test.", 31); msg_a(&m, "x.a.test.", 1);
        db_zone_build_t *b = db_zone_build_new("a.test.", 3, 0);
        CHECK(db_zone_build_feed(b, m.b, m.n, why, sizeof(why)) != 0 && strstr(why, "after the final SOA"));
        db_zone_build_free(b);
        msg_t a, c;
        msg_init(&a); msg_soa(&a, "a.test.", 31); msg_soa(&a, "a.test.", 31);
        msg_init(&c); msg_a(&c, "x.a.test.", 1);
        b = db_zone_build_new("a.test.", 3, 0);
        CHECK(db_zone_build_feed(b, a.b, a.n, why, sizeof(why)) == 0);
        CHECK(db_zone_build_feed(b, c.b, c.n, why, sizeof(why)) != 0 && strstr(why, "after the final SOA"));
        db_zone_build_free(b);
    }
    {   /* two SOAs (a different serial in the middle) */
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_soa(&m, "a.test.", 32); msg_soa(&m, "a.test.", 31);
        int rc2 = install_msgs(e, "a.test.", 3, &m, 1, why, sizeof(why), NULL);
        CHECK(rc2 != 0 && strstr(why, "more than one SOA"));
    }
    {   /* a class other than IN */
        uint8_t rd[4] = { 1, 2, 3, 4 };
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_rr(&m, "x.a.test.", 1, 3, rd, 4); msg_soa(&m, "a.test.", 31);
        CHECK(install_msgs(e, "a.test.", 3, &m, 1, why, sizeof(why), NULL) != 0 && (strstr(why, "class") || strstr(why, "malformed")));
    }
    {   /* garbage inside a valid frame: a truncated RR */
        zone_msg(&m, "a.test.", 31, 2);
        m.n -= 7;
        db_zone_build_t *b = db_zone_build_new("a.test.", 6, 0);
        CHECK(db_zone_build_feed(b, m.b, m.n, why, sizeof(why)) != 0 && strstr(why, "malformed"));
        db_zone_build_free(b);
    }
    {   /* B8: Extended AXFR records of the database stream */
        uint8_t lan[3] = { 'l', 'a', 'n' };
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_rr(&m, "a.test.", 65401, 65302, lan, 3); msg_a(&m, "x.a.test.", 1);
        msg_rr(&m, "a.test.", 65401, 65302, (const uint8_t *)"", 0); msg_soa(&m, "a.test.", 31);
        CHECK(install_msgs_f(e, "a.test.", 5, 0, &m, 1, why, sizeof(why)) != 0 && strstr(why, "did not announce"));
        CHECK(install_msgs_f(e, "a.test.", 3, KDB_ZF_EXTENDED, &m, 1, why, sizeof(why)) != 0 && strstr(why, "count mismatch"));
        uint8_t tr[2] = { 1, 0 };
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_rr(&m, "a.test.", 65407, 65302, tr, 2); msg_soa(&m, "a.test.", 31);
        CHECK(install_msgs_f(e, "a.test.", 3, KDB_ZF_EXTENDED, &m, 1, why, sizeof(why)) != 0);                 /* ECS_TRUSTED: settings only */
        uint8_t bad[1] = { 'x' };
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_rr(&m, "a.test.", 65403, 65302, bad, 1); msg_soa(&m, "a.test.", 31);
        CHECK(install_msgs_f(e, "a.test.", 3, KDB_ZF_EXTENDED, &m, 1, why, sizeof(why)) != 0);                 /* malformed LOC_TAGDEF */
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_rr(&m, "a.test.", 65405, 65302, bad, 1); msg_soa(&m, "a.test.", 31);
        CHECK(install_msgs_f(e, "a.test.", 3, KDB_ZF_EXTENDED, &m, 1, why, sizeof(why)) != 0);                 /* malformed TINYDNS_LOCDEF */
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_rr(&m, "x.a.test.", 65406, 65302, bad, 1); msg_soa(&m, "a.test.", 31);
        CHECK(install_msgs_f(e, "a.test.", 3, KDB_ZF_EXTENDED, &m, 1, why, sizeof(why)) != 0);                 /* TINYDNS_WRAP shorter than its fixed part */
        uint8_t longtag[70];
        memset(longtag, 'a', sizeof(longtag));
        msg_init(&m); msg_soa(&m, "a.test.", 31); msg_rr(&m, "a.test.", 65401, 65302, longtag, sizeof(longtag)); msg_soa(&m, "a.test.", 31);
        CHECK(install_msgs_f(e, "a.test.", 3, KDB_ZF_EXTENDED, &m, 1, why, sizeof(why)) != 0);                 /* tag state longer than 63 */
    }
    CHECK(e->serial == keep_serial && atomic_load(&e->rcu.active)->image->n_rrs == keep_rrs);
    {   /* B8: an announced zone is installed: the tag reaches the image, the tinydns flag too */
        uint8_t lan[3] = { 'l', 'a', 'n' };
        msg_t m;
        char why[128];
        msg_init(&m); msg_soa(&m, "a.test.", 40); msg_rr(&m, "a.test.", 65401, 65302, lan, 3); msg_a(&m, "x.a.test.", 1);
        msg_rr(&m, "a.test.", 65401, 65302, (const uint8_t *)"", 0); msg_soa(&m, "a.test.", 40);
        CHECK(install_msgs_f(e, "a.test.", 5, KDB_ZF_EXTENDED | KDB_ZF_TINYDNS, &m, 1, why, sizeof(why)) == 0);
        const zone_image_t *img = atomic_load(&e->rcu.active)->image;
        CHECK(img && img->n_rrs == 2 && (img->flags & ZONE_IMAGE_F_TINYDNS));
        bool tagged = false;
        for (uint32_t k = 0; img && k < img->n_rrs; k++) {
            const zone_image_ext_t *x = zone_image_rr_ext(img, k);
            if (x && x->loc_tag_off && strcmp(zone_image_str(img, x->loc_tag_off), "lan") == 0) tagged = true;
        }
        CHECK(tagged);
        msg_init(&m); msg_soa(&m, "a.test.", 41); msg_a(&m, "x.a.test.", 1); msg_soa(&m, "a.test.", 41);   /* the flag alone: no extension records */
        CHECK(install_msgs_f(e, "a.test.", 3, KDB_ZF_TINYDNS, &m, 1, why, sizeof(why)) == 0);
        img = atomic_load(&e->rcu.active)->image;
        CHECK(img && (img->flags & ZONE_IMAGE_F_TINYDNS));
        CHECK(install_msgs_f(e, "a.test.", 3, 0, &m, 1, why, sizeof(why)) == 0);
        img = atomic_load(&e->rcu.active)->image;
        CHECK(img && !(img->flags & ZONE_IMAGE_F_TINYDNS));
    }
    zone_retire_process(true);          /* the retired versions hold a reference of the entry */
    free_zone_db_entry(e);
}

/* ---------------------------------------------------------------- 2. registry and delta */
typedef struct { int n, limit; } walk_ctx_t;
static bool cb_count(void *ud, const char *view, const dbreg_zone_t *z) {
    (void)view; (void)z;
    walk_ctx_t *p = ud;
    if (p->n >= p->limit) return false;
    p->n++;
    return true;
}

static void test_registry_delta(void) {
    printf("[TEST] DB registry: commit, view delta, delete, rejected-only records...\n");
    char path[300];
    snprintf(path, sizeof(path), "%s/file.zone", g_dir);
    FILE *f = fopen(path, "w");
    fputs("$ORIGIN file.test.\n$TTL 300\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n", f);
    fclose(f);
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; };\n"
                                     "  zone \"file.test\" { type master; file \"%s\"; }; };\n"
                                     "view \"other\" { match-clients { 10.0.0.0/8; };\n"
                                     "  zone \"file.test\" { type master; file \"%s\"; }; };\n", path, path);
    rebuild(cfg);
    CHECK(name_in_snapshot("default", "file.test.") && name_in_snapshot("other", "file.test."));

    zone_db_entry_t *a = add_zone("default", "a.test.", 1, 2, 11);
    zone_db_entry_t *b = add_zone("default", "b.test.", 1, 2, 12);
    zone_db_entry_t *c = add_zone("other", "c.test.", 1, 2, 13);
    CHECK(dbreg_pending_count() == 3);
    CHECK(!in_snapshot("default", a));                         /* installed but not visible until the delta */
    CHECK(snapshot_apply_db_delta() == 3);
    CHECK(in_snapshot("default", a) && in_snapshot("default", b) && in_snapshot("other", c));
    CHECK(!in_snapshot("default", c));                         /* views are separate */
    CHECK(name_in_snapshot("default", "file.test."));
    CHECK(dbreg_pending_count() == 0 && snapshot_apply_db_delta() == 0);

    /* the same name in the other view is another entry */
    zone_db_entry_t *a2 = add_zone("other", "a.test.", 7, 1, 21);
    CHECK(a2 && a2 != a);
    CHECK(snapshot_apply_db_delta() == 1);
    CHECK(in_snapshot("other", a2) && in_snapshot("default", a));

    /* a new version of a registered zone: same entry, no delta */
    zone_db_entry_t *a_again = add_zone("default", "a.test.", 2, 3, 11);
    CHECK(a_again == a && dbreg_pending_count() == 0);
    CHECK(a->serial == 2);

    /* delete: wrong id does nothing, right id queues the removal */
    CHECK(dbreg_delete("default", "a.test.", 999) == 0);
    CHECK(dbreg_delete("default", "nothere.test.", 1) == 0);
    CHECK(dbreg_delete("default", "A.TEST.", 11) == 1);        /* names compare case-insensitively */
    CHECK(dbreg_lookup_entry("default", "a.test.") == NULL);
    CHECK(dbreg_pending_count() == 1);
    CHECK(in_snapshot("default", a));                          /* still served until the delta */
    CHECK(snapshot_apply_db_delta() == 1);
    CHECK(!name_in_snapshot("default", "a.test.") && in_snapshot("default", b));
    CHECK(in_snapshot("other", a2));

    /* a rejection keeps the last good version; a record without a version is only an error */
    CHECK(dbreg_reject("default", "b.test.", 12, "bad row 7"));
    CHECK(dbreg_lookup_entry("default", "b.test.") == b);
    CHECK(dbreg_reject("default", "never.test.", 99, "no SOA"));
    CHECK(dbreg_lookup_entry("default", "never.test.") == NULL);
    size_t total, rej, shd;
    dbreg_counts(&total, &rej, &shd);
    CHECK(total == 3 && rej == 2 && shd == 0);                 /* b, c, a2 hold a version; b and never are rejected */
    CHECK(dbreg_delete("default", "never.test.", 99) == 1);    /* an error-only record can be deleted too */
    CHECK(dbreg_pending_count() == 0);

    /* walk: in two chunks the whole registry is seen once */
    {
        walk_ctx_t w = { 0, 2 };
        dbreg_cursor_t cur;
        memset(&cur, 0, sizeof(cur));
        int seen = 0;
        bool done = false;
        for (int round = 0; round < 10 && !done; round++) {
            w.n = 0;
            done = dbreg_walk(&cur, cb_count, &w);
            seen += w.n;
        }
        CHECK(done && seen == 3);
    }

    /* a new entry for a name that is registered replaces it: the old one leaves */
    zone_db_entry_t *b_new = new_entry("default", "b.test.");
    {
        msg_t m;
        zone_msg(&m, "b.test.", 50, 1);
        char why[128];
        CHECK(install_msgs(b_new, "b.test.", 4, &m, 1, why, sizeof(why), NULL) == 0);
        uint8_t dg[32] = { 0 };
        bool sh;
        CHECK(dbreg_commit("default", "b.test.", b_new, true, 12, 50, dg, &sh) == 0 && !sh);
        CHECK(dbreg_pending_count() == 2);
        CHECK(snapshot_apply_db_delta() == 2);
        CHECK(in_snapshot("default", b_new) && !in_snapshot("default", b));
    }

    dbreg_reset();
    CHECK(dbreg_pending_count() == 0);
}

/* ---------------------------------------------------------------- 2b. the delta patches the hash tables */
/* snapshot_apply_db_delta() copies and patches the hash tables of the old snapshot (append for an addition, move-the-last-entry
 * for a removal) and rebuilds them only when the load factor would pass one half.  After every step every live zone must be found
 * by its exact name and by a name below it, every removed one by neither, whichever of the two ways was taken. */
#define INC_N 520
static void inc_verify(const char *view, zone_db_entry_t **ent, const bool *alive, int n) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, view);
    CHECK(v != NULL);
    int live = 0;
    for (int i = 0; v && i < n; i++) {
        char name[64], sub[96];
        snprintf(name, sizeof(name), "t%d.test.", i);
        snprintf(sub, sizeof(sub), "www.t%d.test.", i);
        zone_db_entry_t *x = find_zone_exact_in_view(v, name), *y = find_zone_in_view(v, sub);
        if (alive[i]) {
            live++;
            if (x != ent[i] || y != ent[i]) printf("  zone %s: exact %p suffix %p expected %p\n", name, (void *)x, (void *)y, (void *)ent[i]);
            CHECK(x == ent[i] && y == ent[i]);
        } else {
            CHECK(x == NULL && y == NULL);
        }
    }
    CHECK(v && find_zone_exact_in_view(v, "file.test.") != NULL);        /* the configured zone is untouched */
    size_t counted = 0;
    zdir_iter_t cit;
    zdir_iter_init(&cit, v);
    while (v && zdir_iter_next(&cit)) counted++;
    CHECK(counted == (size_t)live + 1);                                  /* no entry twice, none lost, no stale pointer */
    CHECK(zdir_count(v) == counted);                                     /* the counter agrees with the slots */
    release_zone_snapshot(s);
}

static void inc_add(const char *view, zone_db_entry_t **ent, bool *alive, int i) {
    char name[64];
    snprintf(name, sizeof(name), "t%d.test.", i);
    ent[i] = add_zone(view, name, 1, 1, 5000 + i);
    alive[i] = ent[i] != NULL;
}

static void inc_del(const char *view, bool *alive, int i) {
    char name[64];
    snprintf(name, sizeof(name), "t%d.test.", i);
    CHECK(dbreg_delete(view, name, 5000 + i) == 1);
    alive[i] = false;
}

static void test_incremental_delta(void) {
    printf("[TEST] view delta: patched hash tables (add, remove, swap of the last entry, growth)...\n");
    char path[300];
    snprintf(path, sizeof(path), "%s/inc.zone", g_dir);
    FILE *f = fopen(path, "w");
    fputs("$ORIGIN file.test.\n$TTL 300\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n", f);
    fclose(f);
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; };\n"
                                     "  zone \"file.test\" { type master; file \"%s\"; }; };\n", path);
    rebuild(cfg);
    static zone_db_entry_t *ent[INC_N];
    static bool alive[INC_N];
    memset(ent, 0, sizeof(ent));
    memset(alive, 0, sizeof(alive));
    int next = 0;

    for (int k = 0; k < 100; k++) inc_add("default", ent, alive, next++);       /* 1 + 100 zones: fits 256 slots at half load */
    CHECK(snapshot_apply_db_delta() == 100);
    inc_verify("default", ent, alive, next);

    /* the first, a middle and the last entry out, two in: the last slot is moved into the hole of a removed one */
    inc_del("default", alive, 0);
    inc_del("default", alive, 57);
    inc_del("default", alive, 99);
    inc_add("default", ent, alive, next++);
    inc_add("default", ent, alive, next++);
    CHECK(snapshot_apply_db_delta() == 5);
    inc_verify("default", ent, alive, next);

    /* one removal per delta, from the front (every one moves the last entry), until a few are left */
    for (int i = 1; i < 90; i++) {
        if (!alive[i]) continue;
        inc_del("default", alive, i);
        CHECK(snapshot_apply_db_delta() == 1);
        if (i % 7 == 0) inc_verify("default", ent, alive, next);
    }
    inc_verify("default", ent, alive, next);

    /* more than half of 256 slots: the tables are rebuilt (bigger), then patched again */
    for (int k = 0; k < 260; k++) inc_add("default", ent, alive, next++);
    CHECK(snapshot_apply_db_delta() == 260);
    inc_verify("default", ent, alive, next);
    inc_add("default", ent, alive, next++);
    CHECK(snapshot_apply_db_delta() == 1);
    inc_del("default", alive, 150);
    inc_del("default", alive, next - 1);
    CHECK(snapshot_apply_db_delta() == 2);
    inc_verify("default", ent, alive, next);
    CHECK(next < INC_N);

    dbreg_reset();
    CHECK(dbreg_pending_count() == 0);
}

/* ---------------------------------------------------------------- 3. D-PRIO */
static void test_shadowing(void) {
    printf("[TEST] DB registry: a configured zone hides a DB zone, and the DB zone comes back...\n");
    char path[300];
    snprintf(path, sizeof(path), "%s/file.zone", g_dir);
    char path2[300];
    snprintf(path2, sizeof(path2), "%s/dup.zone", g_dir);
    FILE *f = fopen(path2, "w");
    fputs("$ORIGIN dup.test.\n$TTL 300\n@ IN SOA ns h 9 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.9\n", f);
    fclose(f);
    server_config_t *cfg1 = load_conf("view \"default\" { match-clients { any; };\n"
                                      "  zone \"file.test\" { type master; file \"%s\"; }; };\n", path);
    rebuild(cfg1);
    zone_db_entry_t *d = add_zone("default", "dup.test.", 3, 2, 31);
    zone_db_entry_t *keep = add_zone("default", "keep.test.", 3, 2, 32);
    CHECK(snapshot_apply_db_delta() == 2);
    CHECK(in_snapshot("default", d) && in_snapshot("default", keep));

    /* full reload with a file zone of the same name: that one answers */
    server_config_t *cfg2 = load_conf("view \"default\" { match-clients { any; };\n"
                                      "  zone \"file.test\" { type master; file \"%s\"; };\n"
                                      "  zone \"dup.test\" { type master; file \"%s\"; }; };\n", path, path2);
    rebuild(cfg2);
    CHECK(name_in_snapshot("default", "dup.test.") && !in_snapshot("default", d));   /* the file zone's entry */
    CHECK(in_snapshot("default", keep));
    zone_db_entry_t *served = NULL;
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        served = find_zone_exact_in_view(snapshot_find_view(s, "default"), "dup.test.");
        CHECK(served && served->source == ZONE_SRC_CONFIG);
        release_zone_snapshot(s);
    }
    CHECK(dbreg_lookup_entry("default", "dup.test.") == d);          /* still in the registry */
    size_t total, rej, shd;
    dbreg_counts(&total, &rej, &shd);
    CHECK(total == 2 && shd == 1);

    /* a DB zone arriving while the configured zone exists: loaded, hidden, never queued */
    {
        msg_t m;
        zone_msg(&m, "dup.test.", 4, 1);
        char why[128];
        CHECK(install_msgs(d, "dup.test.", 4, &m, 1, why, sizeof(why), NULL) == 0);
        uint8_t dg[32] = { 0 };
        bool sh = false;
        CHECK(dbreg_commit("default", "dup.test.", d, false, 31, 4, dg, &sh) == 0 && sh);
        zone_db_entry_t *late = new_entry("default", "file.test.");
        CHECK(install_msgs(late, "file.test.", 4, &m, 1, why, sizeof(why), NULL) != 0);   /* wrong zone name in the data */
        zone_msg(&m, "file.test.", 4, 1);
        CHECK(install_msgs(late, "file.test.", 4, &m, 1, why, sizeof(why), NULL) == 0);
        CHECK(dbreg_commit("default", "file.test.", late, true, 33, 4, dg, &sh) == 0 && sh);
        CHECK(dbreg_pending_count() == 0);
    }

    /* the configured zone goes away: the DB version is served again at the next rebuild */
    rebuild(cfg1);
    CHECK(in_snapshot("default", d));
    CHECK(in_snapshot("default", keep));
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        zone_db_entry_t *f1 = find_zone_exact_in_view(snapshot_find_view(s, "default"), "file.test.");
        CHECK(f1 && f1->source == ZONE_SRC_CONFIG);                  /* file.test is still the configured zone's */
        release_zone_snapshot(s);
    }
    dbreg_reset();
}

/* ---------------------------------------------------------------- 6. D17-1 */
static void test_catalog_member_wins(void) {
    printf("[TEST] DB registry: a catalog member hides a DB zone of the same name and gives it back...\n");
    char path[300];
    snprintf(path, sizeof(path), "%s/cat.zone", g_dir);
    FILE *f = fopen(path, "w");
    fputs("$ORIGIN cat.test.\n$TTL 300\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.9\nversion IN TXT \"2\"\n"
          "uid1.zones IN PTR m1.test.\n", f);
    fclose(f);
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; };\n"
                                     "  zone \"cat.test\" { type master; file \"%s\"; catalog-zone yes; }; };\n", path);
    rebuild(cfg);                                                   /* the catalog zone lists m1.test as a member */
    zone_db_entry_t *cat = NULL, *member = NULL;
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        view_snapshot_t *v = snapshot_find_view(s, "default");
        cat = find_zone_exact_in_view(v, "cat.test.");
        member = find_zone_exact_in_view(v, "m1.test.");
        release_zone_snapshot(s);
    }
    CHECK(cat != NULL);
    CHECK(member && member->is_catalog_member && member->source == ZONE_SRC_CATALOG);

    /* a DB zone that arrives behind the member: committed, hidden, never queued; another one is served */
    dbreg_info_t info[2];
    zone_db_entry_t *d = new_entry("default", "m1.test.");
    {
        msg_t m;
        char why[128];
        zone_msg(&m, "m1.test.", 3, 2);
        CHECK(install_msgs(d, "m1.test.", 5, &m, 1, why, sizeof(why), NULL) == 0);
        uint8_t dg[32] = { 1 };
        bool sh = false;
        CHECK(dbreg_commit("default", "m1.test.", d, true, 41, 3, dg, &sh) == 0 && sh);
        CHECK(dbreg_pending_count() == 0);
    }
    zone_db_entry_t *other = add_zone("default", "other.test.", 3, 2, 42);
    CHECK(snapshot_apply_db_delta() == 1);
    CHECK(!in_snapshot("default", d) && in_snapshot("default", other) && in_snapshot("default", member));
    CHECK(dbreg_find_info(NULL, "M1.test", info, 2) == 1);          /* any case, no trailing dot, every view */
    CHECK(strcmp(info[0].view, "default") == 0 && info[0].source_id == 41 && info[0].serial == 3 && info[0].has_entry);
    CHECK(info[0].shadowed && info[0].shadow_by == DBREG_SH_CATALOG && info[0].last_result == DBREG_APPLIED);
    CHECK(dbreg_find_info("nosuchview", "m1.test.", info, 2) == 0 && dbreg_find_info(NULL, "nothere.test.", info, 2) == 0);
    size_t total, rej, shc, shk;
    dbreg_counts2(&total, &rej, &shc, &shk);
    CHECK(total == 2 && rej == 0 && shc == 0 && shk == 1);
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        CHECK(dbreg_snapshot_entry(s, "default", "m1.test.") == NULL);      /* hidden: not served */
        CHECK(dbreg_snapshot_entry(s, "default", "other.test.") == other);
        release_zone_snapshot(s);
    }

    /* the member leaves (a catalog update, delta mode): the DB zone is served in the same snapshot */
    catalog_member_id_t *none = calloc(1, sizeof(*none));
    CHECK(none != NULL);
    CHECK(rebuild_zone_db_snapshot(NULL, "default", cat, NULL, none, 0) != NULL);
    CHECK(in_snapshot("default", d) && in_snapshot("default", other));
    CHECK(dbreg_find_info(NULL, "m1.test.", info, 2) == 1 && !info[0].shadowed && info[0].shadow_by == DBREG_SH_NONE);
    dbreg_counts2(&total, &rej, &shc, &shk);
    CHECK(total == 2 && shc == 0 && shk == 0);
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        CHECK(dbreg_snapshot_entry(s, "default", "m1.test.") == d);
        release_zone_snapshot(s);
    }

    /* the member comes back (a catalog update that adds it): the served DB zone leaves the view */
    catalog_member_id_t *one = calloc(1, sizeof(*one));
    CHECK(one != NULL);
    snprintf(one[0].unique_id, sizeof(one[0].unique_id), "uid1");
    snprintf(one[0].domain, sizeof(one[0].domain), "m1.test.");
    CHECK(rebuild_zone_db_snapshot(NULL, "default", cat, NULL, one, 1) != NULL);
    CHECK(!in_snapshot("default", d) && in_snapshot("default", other));
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        zone_db_entry_t *m = find_zone_exact_in_view(snapshot_find_view(s, "default"), "m1.test.");
        CHECK(m && m != d && m->source == ZONE_SRC_CATALOG && m->is_catalog_member);
        release_zone_snapshot(s);
    }
    CHECK(dbreg_find_info(NULL, "m1.test.", info, 1) == 1 && info[0].shadowed && info[0].shadow_by == DBREG_SH_CATALOG);
    CHECK(dbreg_lookup_entry("default", "m1.test.") == d);          /* still registered */

    /* a new version of the hidden zone stays hidden */
    {
        msg_t m;
        char why[128];
        zone_msg(&m, "m1.test.", 4, 1);
        CHECK(install_msgs(d, "m1.test.", 4, &m, 1, why, sizeof(why), NULL) == 0);
        uint8_t dg[32] = { 2 };
        bool sh = false;
        CHECK(dbreg_commit("default", "m1.test.", d, false, 41, 4, dg, &sh) == 0 && sh);
        CHECK(dbreg_find_info("default", "m1.test.", info, 1) == 1 && info[0].shadowed && info[0].serial == 4);
        CHECK(!in_snapshot("default", d));
    }

    /* the full rebuild (the catalog file still lists the member) lets the member win too */
    rebuild(cfg);
    CHECK(!in_snapshot("default", d));
    CHECK(name_in_snapshot("default", "m1.test."));
    CHECK(in_snapshot("default", other));
    zone_retire_process(true);
    dbreg_reset();
}

/* ---------------------------------------------------------------- 4. dbcfg */
static void test_dbcfg(void) {
    printf("[TEST] DB settings: zone_entry_config() and the retirement of a replaced block...\n");
    zone_db_entry_t *e = new_entry("default", "cfg.test.");
    server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    const zone_config_t *c1 = zone_entry_config(&cfg, e);
    CHECK(c1 && strcmp(c1->type, "master") == 0 && strcmp(c1->domain, "cfg.test.") == 0 && c1->ext == NULL);
    CHECK(zone_entry_config(NULL, e) == c1);                         /* no configuration needed for a DB zone */
    zone_config_t *c2 = db_zone_config_new("cfg.test.", NULL);
    CHECK(c2 != NULL);
    db_entry_set_config(e, c2);
    CHECK(zone_entry_config(&cfg, e) == c2);
    zone_retire_process(true);                                        /* the old block is freed after the grace period */
    CHECK(zone_entry_config(&cfg, e) == c2);
    atomic_store(&e->is_transferring, false);
    free_zone_db_entry(e);                                            /* frees the current block */
    /* build_zone_response_cache() reads the entry's settings, not the configuration's */
    zone_db_entry_t *e2 = new_entry("default", "cfg2.test.");
    msg_t m;
    char why[128];
    zone_msg(&m, "cfg2.test.", 1, 2);
    CHECK(install_msgs(e2, "cfg2.test.", 5, &m, 1, why, sizeof(why), NULL) == 0);
    CHECK(atomic_load(&e2->rcu.active)->rcache_ok);
    free_zone_db_entry(e2);
}

/* ---------------------------------------------------------------- 5. readers while zones come and go */
static _Atomic bool g_stop;
static _Atomic long g_reads, g_empty;

static void *reader_thread(void *arg) {
    int id = (int)(intptr_t)arg;
    while (!atomic_load(&g_stop)) {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        view_snapshot_t *v = snapshot_find_view(s, "default");
        for (int i = 0; v && i < 40; i++) {
            char q[64];
            snprintf(q, sizeof(q), "www.z%d.test.", (i + id) % 40);
            zone_db_entry_t *e = find_zone_in_view(v, q);
            if (e && e->source == ZONE_SRC_DB) {
                rcu_aux_read_lock();
                zone_version_t *ver = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
                atomic_fetch_add(&g_reads, 1);
                if (!ver->image || ver->image->n_rrs == 0) atomic_fetch_add(&g_empty, 1);   /* must never happen */
                rcu_aux_read_unlock();
            }
        }
        release_zone_snapshot(s);
    }
    return NULL;
}

static void test_concurrent(void) {
    printf("[TEST] DB view delta under concurrent readers...\n");
    char path[300];
    snprintf(path, sizeof(path), "%s/file.zone", g_dir);
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; };\n"
                                     "  zone \"file.test\" { type master; file \"%s\"; }; };\n", path);
    rebuild(cfg);
    pthread_t th[3];
    for (intptr_t i = 0; i < 3; i++) pthread_create(&th[i], NULL, reader_thread, (void *)i);
    for (int round = 0; round < 150; round++) {
        char z[64];
        int k = round % 40;
        snprintf(z, sizeof(z), "z%d.test.", k);
        zone_db_entry_t *old = dbreg_lookup_entry("default", z);
        if (old && round % 3 == 0) {
            CHECK(dbreg_delete("default", z, 1000 + k) == 1);
        } else {
            zone_db_entry_t *e = add_zone("default", z, (uint32_t)round + 1, 1, 1000 + k);
            CHECK(e != NULL);
        }
        if (round % 5 == 4) CHECK(snapshot_apply_db_delta() >= 0);
        if (round % 20 == 19) zone_retire_process(true);
    }
    CHECK(snapshot_apply_db_delta() >= 0);
    atomic_store(&g_stop, true);
    for (int i = 0; i < 3; i++) pthread_join(th[i], NULL);
    CHECK(atomic_load(&g_empty) == 0);
    printf("  readers saw %ld DB zone lookups\n", atomic_load(&g_reads));
    /* every registered zone is in the snapshot exactly once */
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, "default");
    size_t total, rej, shd;
    dbreg_counts(&total, &rej, &shd);
    size_t db_in_view = 0;
    zdir_iter_t dit;
    zdir_iter_init(&dit, v);
    for (zdir_elem_t *el; (el = zdir_iter_next(&dit));) {
        zone_db_entry_t *de = zdir_entry(el);
        if (de && de->source == ZONE_SRC_DB) {
            db_in_view++;
            CHECK(dbreg_lookup_entry("default", de->domain) == de);
        }
    }
    CHECK(db_in_view == total);
    release_zone_snapshot(s);
    zone_retire_process(true);
    dbreg_reset();
}

/* ---------------------------------------------------------------- 4b. interned settings (B7a) */
static zone_ext_shared_t *mk_shared(const char *profile, const char *text) {
    char err[200];
    zone_ext_shared_t *s = db_settings_parse(text, strlen(text), err, sizeof(err));
    CHECK(s != NULL);
    if (!s) return NULL;
    size_t pl = strlen(profile), tl = strlen(text);
    char *key = malloc(pl + 1 + tl + 1);
    memcpy(key, profile, pl);
    key[pl] = '\0';
    memcpy(key + pl + 1, text, tl + 1);
    s->key = key;
    s->key_len = pl + 1 + tl;
    s->hash = db_settings_hash(key, s->key_len);
    snprintf(s->profile, sizeof(s->profile), "%s", profile);
    return db_settings_intern(s);                 /* a new reference for the caller */
}

static void test_settings_interning(void) {
    printf("[TEST] DB settings: interning, reference counts, replacement and take-back of an entry's block...\n");
    db_settings_reset();
    const char *t1 = "allow-transfer { 192.0.2.1; };";
    zone_ext_shared_t *a = mk_shared("p", t1), *b = mk_shared("p", t1), *c = mk_shared("q", t1);
    CHECK(a && b && c && a == b && c != a);                          /* same profile name, profile text and zone text: one object */
    CHECK(atomic_load(&a->refs) == 3 && atomic_load(&c->refs) == 2);  /* the table + the two callers / the table + one */
    CHECK(db_settings_count() == 2);
    char key[64];
    memcpy(key, "p", 2);
    memcpy(key + 2, t1, strlen(t1) + 1);
    zone_ext_shared_t *f = db_settings_find(key, 2 + strlen(t1));
    CHECK(f == a && atomic_load(&a->refs) == 4);
    zone_ext_shared_unref(f);
    CHECK(db_settings_find("nope", 4) == NULL);
    CHECK(strcmp(a->profile, "p") == 0 && a->ext.db_acl_ceiling && a->ext.allow_transfer_count == 1);

    /* an entry holds a reference through its zone_config_t; the old block of a replaced entry is freed after the grace period
     * and gives its reference back */
    zone_db_entry_t *e = new_entry("default", "set.test.");
    zone_config_t *dc = db_zone_config_new("set.test.", a);
    CHECK(dc && dc->ext_shared && dc->ext == &a->ext && atomic_load(&a->refs) == 4);
    const zone_config_t *plain = zone_entry_config(NULL, e);
    uint64_t ep;
    const zone_config_t *prev = db_entry_swap_config(e, dc, &ep);      /* publish ... */
    CHECK(prev == plain && zone_entry_config(NULL, e) == dc);
    uint64_t ep2;
    CHECK(db_entry_swap_config(e, prev, &ep2) == dc);                   /* ... and take it back (the data was refused) */
    db_entry_retire_config(e, dc, ep2);                                 /* the refused block goes to the retire stack */
    zone_retire_process(true);
    CHECK(zone_entry_config(NULL, e) == plain && atomic_load(&a->refs) == 3);   /* its reference is back */
    zone_config_t *dc2 = db_zone_config_new("set.test.", b);
    db_entry_set_config(e, dc2);                                        /* replacement retires the plain block */
    zone_retire_process(true);
    CHECK(zone_entry_config(NULL, e) == dc2 && atomic_load(&a->refs) == 4);
    atomic_store(&e->is_transferring, false);
    free_zone_db_entry(e);                                              /* frees dc2 and drops its reference */
    CHECK(atomic_load(&a->refs) == 3);
    zone_ext_shared_unref(a);
    zone_ext_shared_unref(b);
    zone_ext_shared_unref(c);

    /* nobody uses a, c: a later intern, once the table has grown, drops them (and keeps the objects in use) */
    zone_ext_shared_t *keep = mk_shared("keep", t1);
    for (int i = 0; i < 400; i++) {
        char txt[80];
        snprintf(txt, sizeof(txt), "ixfr-history %d;", i % 33);
        zone_ext_shared_t *s = mk_shared("many", txt);
        zone_ext_shared_unref(s);
    }
    for (int i = 0; i < 400; i++) {                                     /* distinct keys: different profile names */
        char pn[16], txt[40] = "ixfr-history 1;";
        snprintf(pn, sizeof(pn), "n%d", i);
        zone_ext_shared_t *s = mk_shared(pn, txt);
        zone_ext_shared_unref(s);
    }
    CHECK(db_settings_count() < 300);                                   /* swept; 433 distinct keys were interned */
    CHECK(atomic_load(&keep->refs) == 2 && keep->ext.allow_transfer_count == 1);
    zone_ext_shared_unref(keep);
    db_settings_reset();                                                /* the table's references go too */
    CHECK(db_settings_count() == 0);
}

/* ---------------------------------------------------------------- 6. B7b: secondary and catalog consumer entries */
/* is the entry of this name in the view exactly e?  (compares pointers only: e may be freed after its grace period) */
static bool name_in_snapshot_is(const char *view, const char *name, const zone_db_entry_t *e) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, view);
    bool r = v && find_zone_exact_in_view(v, name) == e;
    release_zone_snapshot(s);
    return r;
}

/* the tick list of the view (the entries the control thread looks at every second): its length, and whether e is in it;
 * -1 when the view is missing */
static int tick_list(const char *view, const zone_db_entry_t *e, bool *in_list) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, view);
    size_t tn = 0;
    zdir_elem_t *const *tl = zdir_tick_list(v, &tn);
    int n = v ? (int)tn : -1;
    *in_list = false;
    for (size_t i = 0; v && i < tn; i++)
        if (zdir_entry(tl[i]) == e) *in_list = true;
    release_zone_snapshot(s);
    return n;
}

static zone_db_entry_t *new_secondary_entry(const char *view, const char *zone, zone_ext_shared_t *sh, int kind) {
    zone_db_entry_t *e = create_new_zone_entry(zone, view);
    CHECK(e != NULL);
    zone_config_t *dc = db_zone_config_new_kind(zone, sh, kind);
    CHECK(dc != NULL);
    e->source = ZONE_SRC_DB;
    e->kind = ZONE_KIND_SECONDARY;
    e->is_secondary = true;
    atomic_store_explicit(&e->dbcfg, dc, memory_order_release);
    return e;
}

static void test_secondary_entries(void) {
    printf("[TEST] DB secondary zones: settings with masters, type of the block, replacement, a deleted consumer takes its members...\n");
    db_settings_reset();
    dbreg_reset();
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    char err[200];
    const char *txt = "masters { 192.0.2.1 port 5300; 2001:db8::1; }; tsig-key \"k1\";";
    zone_ext_shared_t *sh = db_settings_parse(txt, strlen(txt), err, sizeof(err));
    CHECK(sh != NULL && sh->ext.masters_count == 2 && sh->ext.masters[0].port == 5300 && sh->ext.masters[1].port == 0);   /* no port: 0 here, options { port } when it is used (config_target_port()) */
    CHECK(sh && strcmp(sh->ext.masters[0].ip, "192.0.2.1") == 0 && sh->ext.tsig_key && strcmp(sh->ext.tsig_key, "k1") == 0);
    CHECK(sh && sh->ext.masters_parsed != NULL);

    /* a SLAVE entry: type slave, the masters and the key where the control thread reads them (zone_entry_config) */
    zone_db_entry_t *s1 = new_secondary_entry("default", "slave.test.", sh, 1);
    const zone_config_t *c1 = zone_entry_config(NULL, s1);
    CHECK(c1 && c1->type && strcmp(c1->type, "slave") == 0 && !c1->is_catalog && zext(c1)->masters_count == 2);
    uint8_t dg[32] = { 7 };
    bool shd = false;
    CHECK(dbreg_commit("default", "slave.test.", s1, true, 11, 0, dg, &shd) == 0 && !shd);
    CHECK(snapshot_apply_db_delta() == 1 && in_snapshot("default", s1));
    dbreg_info_t info[2];
    CHECK(dbreg_find_info("default", "slave.test.", info, 2) == 1 && info[0].serial == 0 && info[0].has_entry);
    CHECK(s1->kind == ZONE_KIND_SECONDARY && s1->is_secondary);
    /* the control thread's tick list has the secondary (added by the incremental delta) and nothing else */
    bool in_tick = false;
    CHECK(tick_list("default", s1, &in_tick) == 1 && in_tick);
    /* a full reconfiguration keeps the very same entry (a secondary's transferred data is not thrown away) */
    rebuild(cfg);
    CHECK(in_snapshot("default", s1) && dbreg_lookup_entry("default", "slave.test.") == s1);
    CHECK(tick_list("default", s1, &in_tick) == 1 && in_tick);                    /* rebuilt from the entries */
    /* primaries never enter the tick list, whatever their number */
    zone_db_entry_t *pr = add_zone("default", "primary.test.", 1, 1, 99);
    CHECK(snapshot_apply_db_delta() == 1 && in_snapshot("default", pr));
    CHECK(tick_list("default", pr, &in_tick) == 1 && !in_tick);

    /* same name, other kind of zone: a new primary entry replaces the secondary one in the next delta */
    zone_db_entry_t *p1 = new_entry("default", "slave.test.");
    {
        msg_t m;
        char why[128];
        zone_msg(&m, "slave.test.", 5, 1);
        CHECK(install_msgs(p1, "slave.test.", 4, &m, 1, why, sizeof(why), NULL) == 0);
        CHECK(dbreg_commit("default", "slave.test.", p1, true, 11, 5, dg, &shd) == 0);
    }
    CHECK(snapshot_apply_db_delta() == 2 && in_snapshot("default", p1) && !name_in_snapshot_is("default", "slave.test.", s1));
    CHECK(dbreg_lookup_entry("default", "slave.test.") == p1);
    CHECK(tick_list("default", p1, &in_tick) == 0 && !in_tick);                   /* the removed secondary left the list */

    /* a catalog consumer: type slave with catalog-zone, its members come and go with it */
    zone_db_entry_t *cat = new_secondary_entry("default", "cat.test.", sh, 2);
    const zone_config_t *cc = zone_entry_config(NULL, cat);
    CHECK(cc && cc->is_catalog && cc->type && strcmp(cc->type, "slave") == 0);
    CHECK(dbreg_commit("default", "cat.test.", cat, true, 12, 0, dg, &shd) == 0);
    /* a primary DB zone that the member of the catalog will hide */
    zone_db_entry_t *hid = add_zone("default", "m1.test.", 3, 1, 13);
    CHECK(snapshot_apply_db_delta() >= 2 && in_snapshot("default", cat) && in_snapshot("default", hid));
    catalog_member_id_t *desired = calloc(2, sizeof(*desired));
    CHECK(desired != NULL);
    snprintf(desired[0].unique_id, sizeof(desired[0].unique_id), "uid1");
    snprintf(desired[0].domain, sizeof(desired[0].domain), "m1.test.");
    snprintf(desired[1].unique_id, sizeof(desired[1].unique_id), "uid2");
    snprintf(desired[1].domain, sizeof(desired[1].domain), "m2.test.");
    CHECK(rebuild_zone_db_snapshot(NULL, "default", cat, cc, desired, 2) != NULL);       /* the catalog was transferred */
    zone_db_entry_t *mem1 = NULL, *mem2 = NULL;
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        view_snapshot_t *v = snapshot_find_view(s, "default");
        mem1 = find_zone_exact_in_view(v, "m1.test.");
        mem2 = find_zone_exact_in_view(v, "m2.test.");
        release_zone_snapshot(s);
    }
    CHECK(mem2 && mem2->is_catalog_member && mem2->is_secondary && mem2->catalog_master != NULL);
    CHECK(tick_list("default", mem2, &in_tick) == 3 && in_tick);                  /* the consumer and its two members */
    CHECK(mem2 && strcmp(mem2->catalog_master->ip, "192.0.2.1") == 0 && mem2->catalog_master->port == 5300 &&
          strcmp(mem2->catalog_master->zone_key, "k1") == 0 && mem2->catalog_master->key[0] == '\0');   /* the masters and the tsig-key of the consumer (a database zone's primaries have no key of their own) */
    CHECK(mem1 && mem1 != hid && mem1->is_catalog_member);                                  /* D17-1: the member wins */
    CHECK(!in_snapshot("default", hid) && dbreg_find_info("default", "m1.test.", info, 1) == 1 && info[0].shadowed);

    /* the consumer's row is deleted: it leaves with its members, and the DB zone they hid is served again */
    CHECK(dbreg_delete("default", "cat.test.", 12) == 1);
    CHECK(snapshot_apply_db_delta() >= 1);
    CHECK(!name_in_snapshot("default", "cat.test.") && !name_in_snapshot("default", "m2.test."));
    CHECK(in_snapshot("default", hid));
    CHECK(dbreg_find_info("default", "m1.test.", info, 1) == 1 && !info[0].shadowed);
    CHECK(in_snapshot("default", p1));
    CHECK(tick_list("default", p1, &in_tick) == 0);                               /* the consumer and its members left the list */

    zone_ext_shared_unref(sh);
    zone_retire_process(true);
    dbreg_reset();
    db_settings_reset();
}

/* ---------------------------------------------------------------- 7. the reload fast path */
/* A reload whose zone { } blocks did not change takes the old view over (D1a: the new snapshot lists the same zone directory),
 * keeps the registry's pending queue, and applies what changed in the view's own settings (match-clients,
 * options { ixfr-history }).  A zone { } added, removed or of another type, or a view added, rebuilds from the registry
 * (observable: the pending queue is dropped, since the registry already has what it queued, and the view has a new directory). */
typedef struct {
    zdir_t *dir;
    zdir_elem_t **els;
    zone_db_entry_t **tick;
    size_t n, tn, sc;
} view_copy_t;

static void copy_view(const char *view, view_copy_t *c) {
    memset(c, 0, sizeof(*c));
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, view);
    CHECK(v != NULL);
    if (v) {
        c->dir = v->dir;
        c->n = zdir_count(v);
        c->sc = zdir_count_static(v);
        c->els = malloc((c->n + 1) * sizeof(*c->els));
        size_t k = 0;
        zdir_iter_t it;
        zdir_iter_init(&it, v);
        for (zdir_elem_t *el; (el = zdir_iter_next(&it)) && k < c->n;) c->els[k++] = el;
        CHECK(k == c->n);
        size_t tn = 0;
        zdir_elem_t *const *tl = zdir_tick_list(v, &tn);
        c->tn = tn;
        c->tick = malloc((tn + 1) * sizeof(*c->tick));
        for (size_t i = 0; i < tn; i++) c->tick[i] = zdir_entry(tl[i]);
    }
    release_zone_snapshot(s);
}

static bool same_view(const view_copy_t *a, const view_copy_t *b) {
    return a->dir == b->dir && a->n == b->n && a->tn == b->tn && a->sc == b->sc &&
           memcmp(a->els, b->els, a->n * sizeof(*a->els)) == 0 && memcmp(a->tick, b->tick, a->tn * sizeof(*a->tick)) == 0;
}

static void free_copy(view_copy_t *c) {
    free(c->els); free(c->tick);
}

static zone_db_snapshot_t *current_snapshot(void) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    release_zone_snapshot(s);
    return s;
}

static void test_reuse_fast_path(void) {
    printf("[TEST] reload fast path: an unchanged zone set takes the view over, a changed one rebuilds it...\n");
    char path[300], path2[300];
    snprintf(path, sizeof(path), "%s/fp.zone", g_dir);
    snprintf(path2, sizeof(path2), "%s/ra.zone", g_dir);
    FILE *f = fopen(path, "w");
    fputs("$ORIGIN fp.test.\n$TTL 300\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n", f);
    fclose(f);
    f = fopen(path2, "w");
    fputs("$ORIGIN ra.test.\n$TTL 300\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.2\n", f);
    fclose(f);
    const char *one = "view \"default\" { match-clients { any; };\n  zone \"fp.test\" { type master; file \"%s\"; }; };\n";
    server_config_t *cfg = load_conf(one, path);
    rebuild(cfg);
    zone_db_entry_t *a = add_zone("default", "ra.test.", 1, 2, 71);
    zone_db_entry_t *b = add_zone("default", "rb.test.", 1, 2, 72);
    zone_db_entry_t *c = add_zone("default", "rc.test.", 1, 2, 73);
    CHECK(a && b && c && snapshot_apply_db_delta() == 3);
    view_copy_t before, after;
    copy_view("default", &before);
    CHECK(before.n == 4 && before.sc == 1);

    /* the same configuration again: a new snapshot with the same arrays and tables; a queued addition survives it */
    zone_db_entry_t *d = add_zone("default", "rd.test.", 1, 2, 74);
    CHECK(d && dbreg_pending_count() == 1);
    zone_db_snapshot_t *s0 = current_snapshot();
    rebuild(cfg);
    CHECK(current_snapshot() != s0);
    copy_view("default", &after);
    CHECK(same_view(&before, &after));
    CHECK(dbreg_pending_count() == 1 && !in_snapshot("default", d));
    CHECK(snapshot_apply_db_delta() == 1 && in_snapshot("default", d));
    free_copy(&before);
    free_copy(&after);

    /* match-clients changed: applied, the view is still taken over */
    server_config_t *cfg_acl = load_conf("view \"default\" { match-clients { 192.0.2.0/24; };\n"
                                         "  zone \"fp.test\" { type master; file \"%s\"; }; };\n", path);
    copy_view("default", &before);
    CHECK(before.n == 5);
    rebuild(cfg_acl);
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        view_snapshot_t *v = snapshot_find_view(s, "default");
        CHECK(v && v->match_clients_count == 1 && v->match_clients[0] && strcmp(v->match_clients[0], "192.0.2.0/24") == 0);
        release_zone_snapshot(s);
    }
    copy_view("default", &after);
    CHECK(same_view(&before, &after));
    free_copy(&after);

    /* options { ixfr-history } changed: the depth of every entry follows, the view is still taken over */
    server_config_t *cfg_ix = load_conf("options { ixfr-history 7; };\nview \"default\" { match-clients { any; };\n"
                                        "  zone \"fp.test\" { type master; file \"%s\"; }; };\n", path);
    CHECK(ixfr_history_depth(&a->ixfr_history) != 7);
    rebuild(cfg_ix);
    CHECK(ixfr_history_depth(&a->ixfr_history) == 7 && ixfr_history_depth(&b->ixfr_history) == 7 &&
          ixfr_history_depth(&c->ixfr_history) == 7 && ixfr_history_depth(&d->ixfr_history) == 7);
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        zone_db_entry_t *fp = find_zone_exact_in_view(snapshot_find_view(s, "default"), "fp.test.");
        CHECK(fp && ixfr_history_depth(&fp->ixfr_history) == 7);
        release_zone_snapshot(s);
    }
    copy_view("default", &after);
    CHECK(same_view(&before, &after));
    free_copy(&before);
    free_copy(&after);

    /* a zone { } added: the full rebuild (the queued zone is dropped from the queue and comes from the registry) */
    zone_db_entry_t *e5 = add_zone("default", "re.test.", 1, 2, 75);
    CHECK(e5 && dbreg_pending_count() == 1);
    server_config_t *cfg_add = load_conf("view \"default\" { match-clients { any; };\n"
                                         "  zone \"fp.test\" { type master; file \"%s\"; };\n"
                                         "  zone \"ra.test\" { type master; file \"%s\"; }; };\n", path, path2);
    rebuild(cfg_add);
    CHECK(dbreg_pending_count() == 0 && in_snapshot("default", e5) && !in_snapshot("default", a));
    /* a zone { } removed: the full rebuild, the DB zone of that name is served again */
    zone_db_entry_t *e6 = add_zone("default", "rf.test.", 1, 2, 76);
    CHECK(e6 && dbreg_pending_count() == 1);
    rebuild(cfg);
    CHECK(dbreg_pending_count() == 0 && in_snapshot("default", e6) && in_snapshot("default", a));
    /* a view added: the full rebuild */
    zone_db_entry_t *e7 = add_zone("default", "rg.test.", 1, 2, 77);
    CHECK(e7 && dbreg_pending_count() == 1);
    server_config_t *cfg_v2 = load_conf("view \"default\" { match-clients { any; };\n"
                                        "  zone \"fp.test\" { type master; file \"%s\"; }; };\n"
                                        "view \"other\" { match-clients { 10.0.0.0/8; }; };\n", path);
    rebuild(cfg_v2);
    CHECK(dbreg_pending_count() == 0 && in_snapshot("default", e7));
    /* a view removed: the queue of its registry view is dropped, the kept view is taken over */
    zone_db_entry_t *o = add_zone("other", "o.test.", 1, 2, 78);
    zone_db_entry_t *e8 = add_zone("default", "rh.test.", 1, 2, 79);
    CHECK(o && e8 && dbreg_pending_count() == 2);
    copy_view("default", &before);
    rebuild(cfg);
    CHECK(dbreg_pending_count() == 1 && !in_snapshot("default", e8));
    copy_view("default", &after);
    CHECK(same_view(&before, &after));
    free_copy(&before);
    free_copy(&after);
    CHECK(snapshot_apply_db_delta() == 1 && in_snapshot("default", e8));
    /* the zone's type changed: the full rebuild (a new entry of the other kind) */
    zone_db_entry_t *e9 = add_zone("default", "ri.test.", 1, 2, 80);
    CHECK(e9 && dbreg_pending_count() == 1);
    server_config_t *cfg_sec = load_conf("view \"default\" { match-clients { any; };\n"
                                         "  zone \"fp.test\" { type slave; masters { 192.0.2.9; }; file \"%s\"; }; };\n", path);
    rebuild(cfg_sec);
    CHECK(dbreg_pending_count() == 0 && in_snapshot("default", e9));
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        zone_db_entry_t *fp = find_zone_exact_in_view(snapshot_find_view(s, "default"), "fp.test.");
        CHECK(fp && fp->is_secondary);
        release_zone_snapshot(s);
    }
    dbreg_reset();
}

/* ---------------------------------------------------------------- 8. a DB zone that leaves and the glue of its dependents */
static void test_glue_dirty_on_delete(void) {
    printf("[TEST] a DB zone that leaves: the zones that used its addresses as glue are looked at again by the tick...\n");
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    msg_t m;
    char why[128];
    uint8_t dg[32] = { 0 };
    bool sh = false;
    zone_db_entry_t *y = new_entry("default", "y.test.");
    msg_init(&m); msg_soa(&m, "y.test.", 1); msg_ns(&m, "y.test.", "ns.y.test."); msg_a(&m, "ns.y.test.", 9); msg_soa(&m, "y.test.", 1);
    CHECK(install_msgs(y, "y.test.", 4, &m, 1, why, sizeof(why), NULL) == 0);
    CHECK(dbreg_commit("default", "y.test.", y, true, 81, 1, dg, &sh) == 0);
    CHECK(snapshot_apply_db_delta() == 1);
    uint64_t yid = y->id;
    /* x.test names ns.y.test as its NS: its glue comes from y.test, which is in the view when x.test is built */
    zone_db_entry_t *x = new_entry("default", "x.test.");
    msg_init(&m); msg_soa(&m, "x.test.", 1); msg_ns(&m, "x.test.", "ns.y.test."); msg_soa(&m, "x.test.", 1);
    CHECK(install_msgs(x, "x.test.", 3, &m, 1, why, sizeof(why), NULL) == 0);
    CHECK(dbreg_commit("default", "x.test.", x, true, 82, 1, dg, &sh) == 0);
    CHECK(snapshot_apply_db_delta() == 1);
    zone_version_t *xv = atomic_load(&x->rcu.active);
    CHECK(xv && xv->glue && xv->glue->count == 1 && xv->glue->ids[0] == yid);
    zone_glue_refresh_dependents(false);         /* the two publications marked the glue dirty: consume that */
    xv = atomic_load(&x->rcu.active);
    CHECK(xv && xv->glue && xv->glue->ids[0] == yid);
    /* y.test leaves the database: nothing is published, the delta itself must mark the glue dirty */
    CHECK(dbreg_delete("default", "y.test.", 81) == 1);
    CHECK(snapshot_apply_db_delta() == 1);
    CHECK(!name_in_snapshot("default", "y.test.") && in_snapshot("default", x));
    zone_glue_refresh_dependents(false);
    xv = atomic_load(&x->rcu.active);
    CHECK(xv && xv->glue && xv->glue->ids[0] == 0);
    dbreg_reset();
}

/* ---------------------------------------------------------------- 9. D1a: the zone directory */
static zdir_t *current_dir(const char *view) {
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, view);
    zdir_t *d = v ? v->dir : NULL;
    release_zone_snapshot(s);
    return d;
}

static size_t iter_count(const view_snapshot_t *v, const char *name_filter) {
    size_t n = 0;
    zdir_iter_t it;
    zdir_iter_init(&it, v);
    for (zdir_elem_t *e; (e = zdir_iter_next(&it));)
        if (!name_filter || domain_names_match_ci(e->name, name_filter)) n++;
    return n;
}

static void write_zone_file(const char *file, const char *origin, const char *ns_addr) {
    char path[300];
    snprintf(path, sizeof(path), "%s/%s", g_dir, file);
    FILE *f = fopen(path, "w");
    fprintf(f, "$ORIGIN %s\n$TTL 300\n@ IN SOA ns h 1 2 3 4 5\n@ IN NS ns\nns IN A %s\n", origin, ns_addr);
    fclose(f);
}

/* The elements of the directory: what a lookup finds, what an element records of its zone, the counters, the walk, the longest match. */
static void test_dir_elements(void) {
    printf("[TEST] zone directory: elements (exact, suffix, state, flags, SOA values), counters, walk, tick list...\n");
    write_zone_file("de.zone", "de.test.", "192.0.2.1");
    char conf[1024];
    snprintf(conf, sizeof(conf), "%s/de.zone", g_dir);
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; };\n  zone \"de.test\" { type master; file \"%s\"; }; };\n", conf);
    rebuild(cfg);
    zone_db_entry_t *a = add_zone("default", "a.test.", 7, 2, 301);
    zone_db_entry_t *sub = add_zone("default", "sub.a.test.", 8, 1, 302);
    CHECK(a && sub && snapshot_apply_db_delta() == 2);

    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, "default");
    CHECK(v && v->dir);
    zdir_elem_t *ea = zdir_find_exact(v, "a.test."), *es = zdir_find_exact(v, "SUB.a.test"), *ef = zdir_find_exact(v, "de.test.");
    CHECK(ea && es && ef && ea != es);
    CHECK(zdir_entry(ea) == a && zdir_entry(es) == sub);
    CHECK(ea->state == ZDIR_ST_RESIDENT && ea->source_id == 301 && ea->serial == 7 && ea->klen == 6);
    CHECK(ea->refresh == 7200 && ea->retry == 3600 && ea->expire == 1209600);       /* the SOA values of the version served */
    CHECK(!(ea->kind & (ZDIR_K_OWNED | ZDIR_K_STATIC | ZDIR_K_SHARED)) && !ea->shadowed);
    CHECK(ea->qseen == 0 && ea->freq == 0 && !(ea->flags & (ZDIR_F_PIN | ZDIR_F_NOCACHE | ZDIR_F_NOTIFY_DEFER | ZDIR_F_NOTIFY_DUE)));
    CHECK((ef->kind & (ZDIR_K_OWNED | ZDIR_K_STATIC)) == (ZDIR_K_OWNED | ZDIR_K_STATIC) && zdir_entry(ef)->source == ZONE_SRC_CONFIG);
    CHECK(ef->source_id == 0);                                                       /* the position in the listing */
    CHECK(zdir_find_exact(v, "nope.test.") == NULL && zdir_find_exact(v, NULL) == NULL && zdir_find_exact(NULL, "a.test.") == NULL);
    /* the longest suffix wins; the root zone is last; the label boundary is an unescaped dot */
    CHECK(zdir_find_suffix(v, "x.y.sub.a.test.") == es && zdir_find_suffix(v, "x.a.test.") == ea && zdir_find_suffix(v, "a.test") == ea);
    CHECK(zdir_find_suffix(v, "a\\.test.") == NULL && zdir_find_suffix(v, "other.org.") == NULL && zdir_find_suffix(v, NULL) == NULL);
    CHECK(find_zone_in_view(v, "www.de.test.") == zdir_entry(ef) && find_zone_exact_in_view(v, "a.test.") == a);
    /* the counters, the walk (each element once), the listing order (zone { } blocks first) */
    CHECK(zdir_count(v) == 3 && zdir_count_static(v) == 1 && zdir_count_shared(v) == 0 && zdir_count_owned(v) == 3);
    CHECK(iter_count(v, NULL) == 3 && iter_count(v, "a.test.") == 1);
    zdir_elem_t *els[3] = { ea, es, ef };
    qsort(els, 3, sizeof(els[0]), zdir_listing_cmp);
    CHECK(els[0] == ef && ((els[1] == ea && els[2] == es) || (els[1] == es && els[2] == ea)));
    zdir_iter_t it;
    zdir_iter_init(&it, v);
    size_t slots = zdir_iter_slots(&it), seen = 0;
    CHECK(slots >= 64 && zdir_iter_at(&it, slots) == NULL);
    for (size_t i = 0; i < slots; i++)
        if (zdir_iter_at(&it, i)) seen++;
    CHECK(seen == 3);
    /* nobody ticks: primaries only */
    size_t tn = 99;
    CHECK(zdir_tick_list(v, &tn) == NULL || tn == 0);
    CHECK(zdir_tick_list(NULL, &tn) == NULL && tn == 0);
    /* a view without a directory */
    view_snapshot_t empty;
    memset(&empty, 0, sizeof(empty));
    zdir_iter_init(&it, &empty);
    CHECK(zdir_iter_next(&it) == NULL && zdir_iter_slots(&it) == 0 && zdir_count(&empty) == 0 && zdir_find_suffix(&empty, "a.test.") == NULL);
    release_zone_snapshot(s);

    /* the elements of view_set_entries() borrow their entries (unit tests, fuzzers) */
    zone_db_entry_t *t1 = create_new_zone_entry("one.test.", "x"), *t2 = create_new_zone_entry("two.test.", "x");
    t2->is_secondary = true;
    zone_db_entry_t *ents[3] = { t1, NULL, t2 };
    view_snapshot_t bv;
    memset(&bv, 0, sizeof(bv));
    CHECK(view_set_entries(&bv, ents, 3) && zdir_count(&bv) == 2);
    CHECK(find_zone_in_view(&bv, "a.two.test.") == t2 && find_zone_exact_in_view(&bv, "one.test") == t1);
    size_t btn = 0;
    zdir_elem_t *const *btl = zdir_tick_list(&bv, &btn);
    CHECK(btn == 1 && zdir_entry(btl[0]) == t2);                                     /* the secondary ticks */
    {   /* the tick list is in the order of the listing, not of the hashes: refreshes start in that order (transfers-per-ns) */
        zone_db_entry_t *sec[12];
        for (int i = 0; i < 12; i++) {
            char nm[32];
            snprintf(nm, sizeof(nm), "sec%d.test.", (i * 7) % 12);
            sec[i] = create_new_zone_entry(nm, "x");
            sec[i]->is_secondary = true;
        }
        CHECK(view_set_entries(&bv, sec, 12));
        size_t sn = 0;
        zdir_elem_t *const *sl = zdir_tick_list(&bv, &sn);
        CHECK(sn == 12);
        for (size_t i = 0; i < sn && i < 12; i++) CHECK(zdir_entry(sl[i]) == sec[i]);
        for (int i = 0; i < 12; i++) free_zone_db_entry(sec[i]);
    }
    CHECK(view_set_entries(&bv, ents, 1) && zdir_count(&bv) == 1);                   /* replaces the directory */
    view_clear_dir(&bv);
    CHECK(bv.dir == NULL && zdir_count(&bv) == 0);
    free_zone_db_entry(t1);
    free_zone_db_entry(t2);
    dbreg_reset();
}

/* D1a milestone 2: the digest block, the fetch state of an element that has no data, the summary, the lookup that tells a worker to park. */
static void test_dir_fetch_state(void) {
    printf("[TEST] zone directory: digest block, fetch state, summary, the lookup for a query (find_zone_for_query_ex)...\n");
    write_zone_file("fs.zone", "fs.test.", "192.0.2.1");
    char conf[1024];
    snprintf(conf, sizeof(conf), "%s/fs.zone", g_dir);
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; };\n  zone \"fs.test\" { type master; file \"%s\"; }; };\n", conf);
    rebuild(cfg);
    zone_db_entry_t *a = add_zone("default", "a.test.", 7, 2, 301);
    CHECK(a && snapshot_apply_db_delta() == 1);
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, "default");
    zdir_elem_t *ea = zdir_find_exact(v, "a.test."), *ef = zdir_find_exact(v, "fs.test.");
    CHECK(ea && ef);
    /* the digest is a block of its own that only a zone with data from the database has */
    CHECK(ea->digest != NULL && ef->digest == NULL);
    CHECK(sizeof(zdir_elem_t) <= 96);                              /* (104 before the digest left the element; the settings pointer and the cache manager's counters came back for it) */

    /* the fetch state: a zone in memory is not fetched, one that is not in the registry is not a zone, one that has no data is begun once */
    CHECK(dbreg_fetch_begin("default", "nope.test.") == DBREG_FETCH_NONE && dbreg_fetch_begin("nosuchview", "a.test.") == DBREG_FETCH_NONE);
    CHECK(dbreg_fetch_begin("default", "a.test.") == DBREG_FETCH_RESIDENT && atomic_load(&ea->state) == ZDIR_ST_RESIDENT);
    atomic_store(&ea->entry, NULL);                                /* the state of an evicted zone */
    atomic_store(&ea->state, ZDIR_ST_ABSENT);
    CHECK(dbreg_fetch_begin("default", "a.test.") == DBREG_FETCH_STARTED && atomic_load(&ea->state) == ZDIR_ST_LOADING);
    CHECK(dbreg_fetch_begin("default", "a.test.") == DBREG_FETCH_BUSY);
    dbreg_fetch_end("default", "a.test.");                         /* the fetch failed: the zone can be asked for again */
    CHECK(atomic_load(&ea->state) == ZDIR_ST_ABSENT && dbreg_fetch_begin("default", "a.test.") == DBREG_FETCH_STARTED);
    dbreg_fetch_end("default", "a.test.");
    dbreg_fetch_end("default", "nope.test.");                      /* (nothing to end) */

    /* a summary goes into an element without data, for the same source id only; a zone in memory keeps its own values */
    CHECK(dbreg_apply_summary("default", "a.test.", 301, 99, true, 11, 22, 33));
    CHECK(ea->serial == 99 && ea->refresh == 11 && ea->retry == 22 && ea->expire == 33);
    CHECK(dbreg_apply_summary("default", "a.test.", 301, 100, false, 0, 0, 0) && ea->serial == 100 && ea->refresh == 11);
    CHECK(!dbreg_apply_summary("default", "a.test.", 999, 5, true, 1, 2, 3) && ea->serial == 100);
    CHECK(!dbreg_apply_summary("default", "nope.test.", 301, 5, true, 1, 2, 3) && !dbreg_apply_summary("nosuchview", "a.test.", 301, 5, true, 1, 2, 3));
    dbreg_info_t inf;
    CHECK(dbreg_find_info("default", "a.test.", &inf, 1) == 1 && !inf.has_entry && inf.serial == 100 && inf.refresh == 11);
    CHECK(!dbreg_apply_summary("default", "fs.test.", 0, 5, true, 1, 2, 3));        /* a zone { } is not a registry zone */

    /* a cold commit (the summary of a batch, or a body that is not kept) while a fetch of the zone is on its way takes the serial and the settings,
     * and leaves the state alone: the state is the fetch's, and a second fetch must not be asked for */
    {
        uint8_t dgc[32] = { 2 };
        CHECK(dbreg_fetch_begin("default", "a.test.") == DBREG_FETCH_STARTED);
        CHECK(dbreg_commit_cold("default", "a.test.", 301, 150, dgc, NULL) == 0);
        CHECK(ea->serial == 150 && ea->digest && ea->digest[0] == 2 && atomic_load(&ea->state) == ZDIR_ST_LOADING);
        CHECK(dbreg_fetch_begin("default", "a.test.") == DBREG_FETCH_BUSY);
        /* (the fetch brings a version of its own: the summary of the version the directory has is applied as it is, another one is told to come whole) */
        CHECK(dbreg_summary_check("default", "a.test.", 301, 150) == DBREG_SUM_NONE);
        CHECK(dbreg_summary_check("default", "a.test.", 301, 151) == DBREG_SUM_DIFFERS && dbreg_summary_check("default", "a.test.", 999, 150) == DBREG_SUM_DIFFERS);
        dbreg_fetch_end("default", "a.test.");
        CHECK(atomic_load(&ea->state) == ZDIR_ST_ABSENT && dbreg_summary_check("default", "a.test.", 301, 150) == DBREG_SUM_NONE);
        CHECK(dbreg_commit_cold("default", "a.test.", 301, 151, dgc, NULL) == 0 && ea->serial == 151 && atomic_load(&ea->state) == ZDIR_ST_ABSENT);
        /* what a batch summary means for a zone that has its data: the same version, another one, or no data to compare */
        CHECK(add_zone("default", "b.test.", 5, 1, 303) != NULL);
        CHECK(dbreg_summary_check("default", "b.test.", 303, 5) == DBREG_SUM_SAME);
        CHECK(dbreg_summary_check("default", "b.test.", 303, 6) == DBREG_SUM_DIFFERS && dbreg_summary_check("default", "b.test.", 999, 5) == DBREG_SUM_DIFFERS);
        CHECK(dbreg_summary_check("default", "nope.test.", 303, 5) == DBREG_SUM_NONE && dbreg_summary_check("nosuchview", "b.test.", 303, 5) == DBREG_SUM_NONE);
        /* the list of zones to read before a query asks: a zone is in it once; taking it out says whether it is still worth a read */
        CHECK(!dbreg_warm_mark("default", "nope.test.") && !dbreg_warm_mark("nosuchview", "a.test."));
        CHECK(dbreg_warm_mark("default", "a.test.") && (ea->flags & ZDIR_F_WARM) && !dbreg_warm_mark("default", "a.test."));
        bool whole = true;
        CHECK(dbreg_warm_take("default", "a.test.", &whole) && !whole && !(ea->flags & ZDIR_F_WARM));       /* (not pinned, no apex: its summary is asked for) */
        ea->flags |= ZDIR_F_PIN;
        CHECK(dbreg_warm_mark("default", "a.test.") && dbreg_warm_take("default", "a.test.", &whole) && whole);  /* pinned, no data: read whole */
        CHECK(!dbreg_warm_take("default", "b.test.", NULL) && !dbreg_warm_take("default", "nope.test.", NULL));     /* (b.test has its data; nope is not a zone) */
        CHECK(dbreg_warm_mark("default", "a.test."));
        ea->flags |= ZDIR_F_DELETED;
        CHECK(!dbreg_warm_take("default", "a.test.", NULL) && !dbreg_warm_mark("default", "a.test."));
        ea->flags &= (uint16_t)~(ZDIR_F_DELETED | ZDIR_F_PIN);
        /* the apex a summary brings (D1a step 6): into an element without data and with the same source id, the old block goes with the garbage; a zone
         * that has its data takes none, and the data clears it */
        zdir_apex_t *ap1 = calloc(1, sizeof(*ap1)), *ap2 = calloc(1, sizeof(*ap2)), *ap3 = calloc(1, sizeof(*ap3));
        CHECK(ap1 && ap2 && ap3);
        CHECK(!dbreg_set_apex("default", "a.test.", 999, 151, ap1) && atomic_load(&ea->apex) == NULL);       /* (another source id) */
        CHECK(!dbreg_set_apex("default", "nope.test.", 301, 151, ap1) && !dbreg_set_apex("nosuchview", "a.test.", 301, 151, ap1));
        CHECK(dbreg_set_apex("default", "a.test.", 301, 151, ap1) && atomic_load(&ea->apex) == ap1 && ap1->serial == 151);
        CHECK(dbreg_set_apex("default", "a.test.", 301, 152, ap2) && atomic_load(&ea->apex) == ap2 && ap2->serial == 152);        /* (ap1 is in the garbage now) */
        CHECK(!dbreg_set_apex("default", "a.test.", 301, 153, NULL) && atomic_load(&ea->apex) == NULL);         /* none: the old one goes */
        CHECK(!dbreg_set_apex("default", "b.test.", 303, 5, ap3));                                              /* b.test has its data */
        CHECK(dbreg_set_apex("default", "a.test.", 301, 154, ap3) && atomic_load(&ea->apex) == ap3);        /* (freed with the element: dbreg_reset() below) */
        CHECK(dbreg_warm_mark("default", "a.test.") && !dbreg_warm_take("default", "a.test.", NULL));      /* (it has an apex and is not pinned: nothing to ask for) */
        /* a body that was left out of memory for a zone that has its data (a fetch brought it meanwhile) is not recorded: the caller has the loader send it again */
        CHECK(dbreg_commit_cold("default", "b.test.", 303, 9, dgc, NULL) == DBREG_COLD_RESIDENT && dbreg_find_info("default", "b.test.", &inf, 1) == 1 && inf.serial == 5);
        /* the garbage a loader that sends nothing but summaries makes is bounded: past GARB_ENTS_MAX entries a publication is due, and it drains them */
        CHECK(snapshot_apply_db_delta() >= 0 && dbreg_pending_count() == 0);
        for (int i = 0; i < 1100 && dbreg_pending_count() == 0; i++) {
            zdir_apex_t *ax = calloc(1, sizeof(*ax));
            CHECK(ax && dbreg_set_apex("default", "a.test.", 301, 155 + (uint32_t)i, ax));
        }
        CHECK(dbreg_pending_count() == 1 && dbreg_garbage_due());                   /* nothing queued, only the garbage asks for a publication, and it is due now */
        zone_db_snapshot_t *gs0 = acquire_retained_zone_snapshot();
        CHECK(snapshot_apply_db_delta() == 0 && dbreg_pending_count() == 0 && !dbreg_garbage_due());
        zone_db_snapshot_t *gs1 = acquire_retained_zone_snapshot();
        CHECK(gs1 != gs0);
        release_zone_snapshot(gs0);
        release_zone_snapshot(gs1);
    }

    /* the lookup for a query: NULL and the element for a zone that has no data (the worker parks), the entry when it has */
    zdir_elem_t *pel = (zdir_elem_t *)0x1;
    CHECK(find_zone_for_query_ex(v, "www.a.test.", 1, &pel) == NULL && pel == ea);
    CHECK(find_zone_for_query(v, "www.a.test.", 1) == NULL);
    CHECK(find_zone_for_query_ex(v, "www.fs.test.", 1, &pel) == zdir_entry(ef) && pel == ef);
    CHECK(find_zone_for_query_ex(v, "other.org.", 1, &pel) == NULL && pel == NULL);
    CHECK(find_zone_for_query_ex(v, "www.a.test.", 1, NULL) == NULL);
    /* DS (RFC 4035 3.1.4.1): the query for the DS of a child apex is answered from the parent; when the parent has no data the parent is the zone to wait for */
    zone_db_entry_t *child = add_zone("default", "c.a.test.", 3, 1, 302);
    CHECK(child && snapshot_apply_db_delta() >= 1);
    release_zone_snapshot(s);
    s = acquire_retained_zone_snapshot();
    v = snapshot_find_view(s, "default");
    CHECK(find_zone_for_query_ex(v, "c.a.test.", 43, &pel) == NULL && pel == ea);
    CHECK(find_zone_for_query_ex(v, "c.a.test.", 1, &pel) == child && pel == zdir_find_exact(v, "c.a.test."));
    atomic_store(&ea->entry, a);                                   /* the data is back */
    CHECK(find_zone_for_query_ex(v, "c.a.test.", 43, &pel) == a && pel == ea);
    CHECK(find_zone_for_query_ex(v, "www.a.test.", 1, &pel) == a && pel == ea);
    release_zone_snapshot(s);
    dbreg_reset();
}

/* D1a review 6C: a walk over the registry in steps (dbreg_walk()) does not skip a zone that is there all along, when a zone leaves its chain or the tables are
 * rehashed between two steps (the position is an ordinal in a chain; the cursor remembers the generations of the registry and goes back). */
typedef struct { size_t n, taken, stop_after; char name[512][24]; uint32_t hash[512]; } walk_t;
static bool walk_cb(void *ud, const char *view, const dbreg_zone_t *z) {
    walk_t *w = ud;
    (void)view;
    if (w->taken >= w->stop_after) return false;               /* refuse this zone: the next step starts at it */
    w->taken++;
    if (w->n < 512) {
        snprintf(w->name[w->n], sizeof(w->name[0]), "%s", z->name);
        w->hash[w->n++] = z->hash;
    }
    return true;
}
static bool walk_seen(const walk_t *w, const char *name) {
    for (size_t i = 0; i < w->n; i++)
        if (strcmp(w->name[i], name) == 0) return true;
    return false;
}
/* D1a review 6D: the first settings a cold zone gets leave nothing to give back, so they make no garbage entry (a start of a million zones would otherwise force a
 * publication a thousand times); replacing settings does */
static void test_cold_no_garbage(void) {
    printf("[TEST] registry: a cold commit with settings for a new zone makes no garbage entry...\n");
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    zone_ext_shared_t *s1 = mk_shared("p", "allow-transfer { 192.0.2.1; };"), *s2 = mk_shared("q", "allow-transfer { 192.0.2.2; };");
    CHECK(s1 && s2);
    uint8_t dg[32] = { 1 };
    const uint64_t f0 = dbreg_garbage_forced();
    char nm[24];
    for (int i = 0; i < 1200; i++) {
        snprintf(nm, sizeof(nm), "cg%04d.test.", i);
        CHECK(dbreg_commit_cold("default", nm, 9000 + i, 1, dg, s1) == 0);
    }
    CHECK(dbreg_garbage_forced() == f0 && !dbreg_garbage_due());
    for (int i = 0; i < 1200; i++) {                           /* other settings: the old ones are given back through the garbage, and that is counted */
        snprintf(nm, sizeof(nm), "cg%04d.test.", i);
        CHECK(dbreg_commit_cold("default", nm, 9000 + i, 1, dg, s2) == 0);
    }
    CHECK(dbreg_garbage_forced() == f0 + 1 && dbreg_garbage_due());
    CHECK(snapshot_apply_db_delta() >= 0 && !dbreg_garbage_due());
    zone_ext_shared_unref(s1);
    zone_ext_shared_unref(s2);
    dbreg_reset();
}

static void test_walk_robust(void) {
    printf("[TEST] registry walk in steps: a zone that leaves a chain or a rehash between two steps skips no zone...\n");
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    char nm[24];
    for (int i = 0; i < 100; i++) {
        snprintf(nm, sizeof(nm), "w%03d.test.", i);
        CHECK(add_zone("default", nm, 1, 1, 7000 + i) != NULL);
    }
    walk_t *all = calloc(1, sizeof(*all));
    dbreg_cursor_t cur;
    memset(&cur, 0, sizeof(cur));
    all->stop_after = 100000;
    CHECK(dbreg_walk(&cur, walk_cb, all) && all->n == 100);
    /* two zones in a row of one chain (100 zones in 128 chains: there are some), in the order of the chain */
    size_t b0 = (size_t)-1;
    for (size_t i = 0; i + 1 < all->n && b0 == (size_t)-1; i++)
        if ((all->hash[i] & 127) == (all->hash[i + 1] & 127)) b0 = i;
    CHECK(b0 != (size_t)-1);
    if (b0 != (size_t)-1) {
        char c0[24], c1[24];
        snprintf(c0, sizeof(c0), "%s", all->name[b0]);
        snprintf(c1, sizeof(c1), "%s", all->name[b0 + 1]);
        const size_t bucket = all->hash[b0] & 127;
        /* a zone leaves the chain after the step that visited it: the next step starts at the zone that follows, not at the one after it */
        walk_t *w = calloc(1, sizeof(*w));
        memset(&cur, 0, sizeof(cur));
        cur.bucket = bucket;                                    /* (a walk that is at the start of this chain) */
        w->stop_after = 1;
        CHECK(!dbreg_walk(&cur, walk_cb, w) && w->n == 1 && strcmp(w->name[0], c0) == 0);
        CHECK(dbreg_delete("default", c0, 7000 + atoi(c0 + 1)) == 1);
        w->taken = 0;
        CHECK(!dbreg_walk(&cur, walk_cb, w) && w->n == 2 && strcmp(w->name[1], c1) == 0);      /* (not the zone of the next chain: the position was an ordinal) */
        /* the tables are rehashed after a step: everything is seen by the end */
        memset(&cur, 0, sizeof(cur));
        memset(w, 0, sizeof(*w));
        cur.bucket = bucket;
        w->stop_after = 1;
        CHECK(!dbreg_walk(&cur, walk_cb, w) && w->n == 1);
        for (int i = 100; i < 230; i++) {                        /* 99 + 130 zones: the tables double (128 -> 256) */
            snprintf(nm, sizeof(nm), "w%03d.test.", i);
            CHECK(add_zone("default", nm, 1, 1, 7000 + i) != NULL);
        }
        w->stop_after = 100000;
        w->taken = 0;
        CHECK(dbreg_walk(&cur, walk_cb, w));
        bool every = true;
        for (int i = 0; i < 230; i++) {
            snprintf(nm, sizeof(nm), "w%03d.test.", i);
            if (i < 100 && strcmp(nm, c0) == 0) continue;        /* (the one that was deleted) */
            if (!walk_seen(w, nm)) every = false;
        }
        CHECK(every);
        free(w);
    }
    free(all);
    dbreg_reset();
}

/* A delta changes the directory in place: the new snapshot lists the same directory, and the index is copied only when it has to grow. */
static void test_dir_delta_in_place(void) {

    printf("[TEST] zone directory: a delta changes the directory in place (no copy of the index unless it grows), tombstones are reused...\n");
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    zdir_t *d0 = current_dir("default");
    CHECK(d0 != NULL);
    zone_db_entry_t *ent[400];
    int64_t base_pending = (int64_t)dbreg_pending_count();
    CHECK(base_pending == 0);
    for (int i = 0; i < 8; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "p%d.test.", i);
        ent[i] = add_zone("default", nm, 1, 1, 900 + i);
        CHECK(ent[i] != NULL);
    }
    CHECK(dbreg_pending_count() == 8 && snapshot_apply_db_delta() == 8);
    zone_db_snapshot_t *s1 = acquire_retained_zone_snapshot();
    CHECK(snapshot_find_view(s1, "default")->dir == d0);                             /* the same directory */
    zdir_tab_t *t1 = atomic_load(&d0->tab);
    CHECK(t1 != NULL && zdir_count(snapshot_find_view(s1, "default")) == 8);
    /* one more zone: the snapshot is new, the directory and its table are the ones before */
    ent[8] = add_zone("default", "p8.test.", 1, 1, 908);
    CHECK(ent[8] && snapshot_apply_db_delta() == 1);
    zone_db_snapshot_t *s2 = acquire_retained_zone_snapshot();
    CHECK(s2 != s1 && snapshot_find_view(s2, "default")->dir == d0 && atomic_load(&d0->tab) == t1);
    /* the reader that holds the older snapshot sees the zone too: it is one directory */
    CHECK(find_zone_exact_in_view(snapshot_find_view(s1, "default"), "p8.test.") == ent[8]);
    release_zone_snapshot(s2);
    release_zone_snapshot(s1);
    /* many zones: the index outgrows its table; the elements move to a bigger one (the old table is garbage) */
    for (int i = 9; i < 400; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "p%d.test.", i);
        ent[i] = add_zone("default", nm, 1, 1, 900 + i);
        CHECK(ent[i] != NULL);
    }
    CHECK(snapshot_apply_db_delta() == 391);
    zdir_tab_t *t2 = atomic_load(&d0->tab);
    CHECK(t2 != t1 && t2->cap >= 800 && atomic_load(&d0->live) == 400);
    for (int i = 0; i < 400; i += 37) {
        char nm[64];
        snprintf(nm, sizeof(nm), "www.p%d.test.", i);
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        CHECK(find_zone_in_view(snapshot_find_view(s, "default"), nm) == ent[i]);
        release_zone_snapshot(s);
    }
    /* removals leave tombstones; zones that come back use them, and the table is not rebuilt for it */
    size_t used_full = d0->used;
    for (int i = 0; i < 200; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "p%d.test.", i);
        CHECK(dbreg_delete("default", nm, 900 + i) == 1);
    }
    CHECK(snapshot_apply_db_delta() == 200 && atomic_load(&d0->live) == 200 && d0->used == used_full && atomic_load(&d0->tab) == t2);
    for (int i = 0; i < 100; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "p%d.test.", i);
        ent[i] = add_zone("default", nm, 2, 1, 900 + i);
        CHECK(ent[i] != NULL);
    }
    CHECK(snapshot_apply_db_delta() == 100 && atomic_load(&d0->live) == 300);
    CHECK(d0->used <= used_full + 100 && atomic_load(&d0->tab) == t2);
    /* names that are not (any more) zones are not found, the others are, and the walk sees each once */
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, "default");
    CHECK(find_zone_exact_in_view(v, "p150.test.") == NULL && find_zone_exact_in_view(v, "p50.test.") == ent[50]);
    CHECK(find_zone_exact_in_view(v, "p250.test.") == ent[250] && iter_count(v, NULL) == 300 && zdir_count(v) == 300);
    release_zone_snapshot(s);
    /* a queue that is applied in one delta: an element deleted while it waits to be added never enters the index */
    zone_db_entry_t *q = add_zone("default", "queued.test.", 1, 1, 7001);
    CHECK(q && dbreg_pending_count() == 1);
    CHECK(dbreg_delete("default", "queued.test.", 7001) == 1 && snapshot_apply_db_delta() >= 0);
    CHECK(!name_in_snapshot("default", "queued.test.") && dbreg_pending_count() == 0);
    gc_snapshot_wait_idle();
    dbreg_reset();
    zone_retire_process(true);
}

/* What a reader got from a lookup stays valid until the snapshot it holds is released, and what was taken out of the directory is freed
 * only when that snapshot, and every older one, is drained (the garbage of a snapshot waits for the older ones). */
static void test_dir_garbage_order(void) {
    printf("[TEST] zone directory: removed zones are freed after the older snapshots are gone...\n");
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    zone_db_entry_t *y = add_zone("default", "gcy.test.", 1, 2, 8001);
    CHECK(y && snapshot_apply_db_delta() == 1);
    zone_db_snapshot_t *held = acquire_retained_zone_snapshot();             /* an old snapshot a transfer or a command holds */
    zone_db_entry_t *seen = find_zone_exact_in_view(snapshot_find_view(held, "default"), "gcy.test.");
    CHECK(seen == y);
    zone_db_entry_t *z = add_zone("default", "gcz.test.", 1, 2, 8002);
    CHECK(z && snapshot_apply_db_delta() == 1);                              /* `held` is retired: its cleanup thread waits for the reader */
    CHECK(dbreg_delete("default", "gcy.test.", 8001) == 1);
    CHECK(snapshot_apply_db_delta() == 1);                                   /* the snapshot before this one has the garbage; it is drained at once ... */
    usleep(200000);
    CHECK(gc_freed("gcy.test.") == 0);                                       /* ... but an older one (held) is not: nothing is freed */
    CHECK(find_zone_exact_in_view(snapshot_find_view(held, "default"), "gcy.test.") == NULL);   /* the index no longer lists it */
    CHECK(strcmp(seen->domain, "gcy.test.") == 0 && atomic_load(&seen->serial) == 1);          /* the entry the reader has is intact */
    release_zone_snapshot(held);
    gc_snapshot_wait_idle();
    CHECK(gc_freed("gcy.test.") == 1);                                       /* now it is freed, once */
    CHECK(gc_freed("gcz.test.") == 0);
    /* a zone that is replaced by a new entry: the old entry waits for the readers of the older snapshots as well */
    zone_db_snapshot_t *held2 = acquire_retained_zone_snapshot();
    zone_db_entry_t *z2 = new_entry("default", "gcz.test.");
    msg_t m;
    zone_msg(&m, "gcz.test.", 2, 1);
    char why[128];
    CHECK(install_msgs(z2, "gcz.test.", 4, &m, 1, why, sizeof(why), NULL) == 0);
    uint8_t dg[32] = { 2 };
    CHECK(dbreg_commit("default", "gcz.test.", z2, true, 8002, 2, dg, NULL) == 0);
    CHECK(find_zone_exact_in_view(snapshot_find_view(held2, "default"), "gcz.test.") == z2);   /* served at once: the element points to the new entry */
    CHECK(dbreg_pending_count() == 2 && snapshot_apply_db_delta() == 2);                         /* (a removal and an addition, as ever; the delta gives the old entry back) */
    usleep(200000);
    CHECK(gc_freed("gcz.test.") == 0 && strcmp(z->domain, "gcz.test.") == 0);
    release_zone_snapshot(held2);
    gc_snapshot_wait_idle();
    CHECK(gc_freed("gcz.test.") == 1);
    dbreg_reset();
    zone_retire_process(true);
}

/* A hidden DB zone is an element that is not in the index: the zone of karidns.conf is; and a zone shared with another view (in-view) has an element of
 * its own that holds the owner's entry. */
static void test_dir_hidden_and_shared(void) {
    printf("[TEST] zone directory: hidden elements, zones shared with another view...\n");
    write_zone_file("dh.zone", "dh.test.", "192.0.2.3");
    char zf[300];
    snprintf(zf, sizeof(zf), "%s/dh.zone", g_dir);
    zone_db_entry_t *dbz = NULL;
    server_config_t *cfg0 = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg0);
    dbz = add_zone("default", "dh.test.", 5, 1, 9001);
    CHECK(dbz && snapshot_apply_db_delta() == 1);
    server_config_t *cfg1 = load_conf("view \"default\" { match-clients { any; }; zone \"dh.test\" { type master; file \"%s\"; }; };\n", zf);
    rebuild(cfg1);
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        view_snapshot_t *v = snapshot_find_view(s, "default");
        zdir_elem_t *e = zdir_find_exact(v, "dh.test.");
        CHECK(e && (e->kind & ZDIR_K_STATIC) && zdir_entry(e) != dbz && zdir_entry(e)->source == ZONE_SRC_CONFIG);   /* the winner is the zone of karidns.conf */
        CHECK(iter_count(v, "dh.test.") == 1 && zdir_count(v) == 1);                                                 /* one element for the name */
        dbreg_info_t info[1];
        CHECK(dbreg_find_info("default", "dh.test.", info, 1) == 1 && info[0].shadowed && info[0].shadow_by == DBREG_SH_CONFIG);
        CHECK(dbreg_snapshot_entry(s, "default", "dh.test.") == NULL);
        release_zone_snapshot(s);
    }
    rebuild(cfg0);                                                                       /* the zone { } goes: the hidden element comes back */
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        view_snapshot_t *v = snapshot_find_view(s, "default");
        zdir_elem_t *e = zdir_find_exact(v, "dh.test.");
        CHECK(e && !(e->kind & ZDIR_K_OWNED) && zdir_entry(e) == dbz && !e->shadowed && zdir_count_static(v) == 0);
        CHECK(dbreg_snapshot_entry(s, "default", "dh.test.") == dbz);
        release_zone_snapshot(s);
    }
    /* a zone shared with an earlier view */
    write_zone_file("sh.zone", "sh.test.", "192.0.2.4");
    char sf[300];
    snprintf(sf, sizeof(sf), "%s/sh.zone", g_dir);
    server_config_t *cfg2 = load_conf("view \"a\" { match-clients { 127.0.0.1; }; zone \"sh.test\" { type master; file \"%s\"; }; };\n"
                                      "view \"b\" { match-clients { any; }; zone \"sh.test\" { in-view \"a\"; }; };\n", sf);
    rebuild(cfg2);
    {
        zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
        view_snapshot_t *va = snapshot_find_view(s, "a"), *vb = snapshot_find_view(s, "b");
        zdir_elem_t *ea = zdir_find_exact(va, "sh.test."), *eb = zdir_find_exact(vb, "sh.test.");
        CHECK(ea && eb && ea != eb && zdir_entry(ea) == zdir_entry(eb));                     /* one entry, an element in each view */
        CHECK((ea->kind & ZDIR_K_STATIC) && !(ea->kind & ZDIR_K_SHARED) && (eb->kind & ZDIR_K_SHARED) && !(eb->kind & ZDIR_K_STATIC));
        CHECK(zdir_count(va) == 1 && zdir_count_static(va) == 1 && zdir_count_shared(va) == 0 && zdir_count_owned(va) == 1);
        CHECK(zdir_count(vb) == 1 && zdir_count_static(vb) == 0 && zdir_count_shared(vb) == 1 && zdir_count_owned(vb) == 0);
        CHECK(view_owns_elem(ea) && !view_owns_elem(eb) && view_owns_entry(va, zdir_entry(ea)) && !view_owns_entry(vb, zdir_entry(eb)));
        /* a DB zone in the owner view does not change the shared one */
        release_zone_snapshot(s);
    }
    dbreg_reset();
    zone_retire_process(true);
}

/* The replaced entry of an element in the index (a DB zone that becomes another kind of zone): the tick list follows it. */
static void test_dir_replaced_entry_ticks(void) {
    printf("[TEST] zone directory: an element whose entry is replaced (the tick list is rebuilt)...\n");
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    zone_db_entry_t *p = add_zone("default", "rk.test.", 1, 1, 9101);
    CHECK(p && snapshot_apply_db_delta() == 1);
    bool in_tick = true;
    CHECK(tick_list("default", p, &in_tick) == 0 && !in_tick);
    /* the zone becomes a secondary: a new entry replaces the primary's under the same element */
    zone_ext_shared_t *sh = NULL;
    zone_db_entry_t *sec = new_secondary_entry("default", "rk.test.", sh, 1);
    uint8_t dg[32] = { 3 };
    CHECK(dbreg_commit("default", "rk.test.", sec, true, 9101, 0, dg, NULL) == 0);
    CHECK(snapshot_apply_db_delta() == 2);
    CHECK(tick_list("default", sec, &in_tick) == 1 && in_tick);
    CHECK(name_in_snapshot_is("default", "rk.test.", sec));
    CHECK(dbreg_delete("default", "rk.test.", 9101) == 1 && snapshot_apply_db_delta() == 1);
    CHECK(tick_list("default", sec, &in_tick) == 0 && !in_tick);
    gc_snapshot_wait_idle();
    dbreg_reset();
    zone_retire_process(true);
}

/* Design 3.1: what the directory costs per zone (the entries and images are not in it).  The target is 130-160 bytes; the elements carry the
 * 32-byte digest today (it will go to the resident zones only), the index is a table of 8-byte slots at a load of at most one half. */
static void test_dir_bytes_per_zone(void) {
    printf("[TEST] zone directory: bytes per zone (registry element + hash table + index table)...\n");
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; };\n");
    rebuild(cfg);
    enum { N = 20000 };
    uint8_t dg[32] = { 7 };
    for (int i = 0; i < N; i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "z%d.test.", 100000 + i);
        zone_db_entry_t *e = new_entry("default", nm);
        CHECK(e && dbreg_commit("default", nm, e, true, 20000 + i, 1, dg, NULL) == 0);
    }
    CHECK(snapshot_apply_db_delta() == N);
    size_t nel, rb, ib;
    dbreg_dir_bytes(&nel, &rb, &ib);
    CHECK(nel == N && rb > 0 && ib > 0);
    double per = (double)(rb + ib) / (double)nel;
    printf("  -> %zu zones: sizeof(element) = %zu, %.1f bytes per zone requested (registry %.1f + index %.1f)\n", nel, sizeof(zdir_elem_t), per,
           (double)rb / (double)nel, (double)ib / (double)nel);
    CHECK(per >= 100.0 && per <= 190.0);
    gc_snapshot_wait_idle();
    dbreg_reset();
    zone_retire_process(true);
}

/* Design 8.1: the bytes a published version holds are recorded when it is frozen and counted while it is resident; a replaced one is
 * "retired" until the retire stack frees it; an IXFR difference counts while the history has it; an entry that goes takes its bytes. */
static void test_zone_bytes(void) {
    printf("[TEST] zone memory accounting: resident, retired, IXFR differences, entries that go...\n");
    zone_bytes_t db0, ot0, db, ot;
    gc_snapshot_wait_idle();                                   /* what the earlier tests left is gone */
    zone_retire_process(true);
    zone_bytes_get(ZBYTES_DB, &db0);
    zone_bytes_get(ZBYTES_OTHER, &ot0);
    write_zone_file("zb.zone", "zb.test.", "192.0.2.7");
    char zf[300];
    snprintf(zf, sizeof(zf), "%s/zb.zone", g_dir);
    server_config_t *cfg = load_conf("view \"default\" { match-clients { any; }; zone \"zb.test\" { type master; file \"%s\"; }; };\n", zf);
    rebuild(cfg);
    zone_bytes_get(ZBYTES_OTHER, &ot);
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    zone_db_entry_t *fz = find_zone_exact_in_view(snapshot_find_view(s, "default"), "zb.test.");
    release_zone_snapshot(s);
    zone_version_t *fv = fz ? atomic_load(&fz->rcu.active) : NULL;
    CHECK(fv && fv->heap && fv->counted && fv->bytes >= sizeof(zone_version_t) + fv->image->total_size);
    CHECK(fv && ot.resident >= ot0.resident + fv->bytes);                               /* a zone { } block counts as "other" */
    zone_bytes_get(ZBYTES_DB, &db);
    CHECK(db.resident == db0.resident && db.retired == db0.retired);

    /* a DB zone: its first version */
    zone_db_entry_t *z = add_zone("default", "zb2.test.", 1, 3, 9201);
    CHECK(z != NULL && snapshot_apply_db_delta() == 1);
    zone_version_t *v1 = atomic_load(&z->rcu.active);
    size_t b1 = v1->bytes;
    CHECK(v1->counted && b1 > sizeof(zone_version_t) + v1->image->total_size - 1);
    zone_bytes_get(ZBYTES_DB, &db);
    CHECK(db.resident == db0.resident + b1 && db.retired == db0.retired);               /* (no IXFR difference for the first load) */
    /* a new version: the old one is retired until it is freed */
    zone_db_entry_t *z_again = add_zone("default", "zb2.test.", 2, 6, 9201);
    CHECK(z_again == z);
    zone_version_t *v2 = atomic_load(&z->rcu.active);
    CHECK(v2 != v1 && v2->bytes > b1);
    ixfr_txn_t *txn = z->ixfr_history.count > 0 ? z->ixfr_history.entries[(z->ixfr_history.head + z->ixfr_history.cap - 1) % z->ixfr_history.cap] : NULL;
    CHECK(txn && txn->acct == 1 + ZBYTES_DB && txn->bytes >= sizeof(*txn) && txn->old_serial == 1 && txn->new_serial == 2);
    zone_bytes_get(ZBYTES_DB, &db);
    CHECK(txn && db.resident == db0.resident + v2->bytes + txn->bytes);
    CHECK(db.retired == db0.retired + b1 || db.retired == db0.retired);                 /* (b1 is still counted unless the stack was run) */
    zone_retire_process(true);
    zone_bytes_get(ZBYTES_DB, &db);
    CHECK(db.retired == db0.retired && db.resident == db0.resident + v2->bytes + txn->bytes);
    /* the zone leaves: its versions and its history go with the entry */
    CHECK(dbreg_delete("default", "zb2.test.", 9201) == 1 && snapshot_apply_db_delta() == 1);
    gc_snapshot_wait_idle();
    zone_retire_process(true);
    zone_bytes_get(ZBYTES_DB, &db);
    CHECK(db.resident == db0.resident && db.retired == db0.retired);
    dbreg_reset();
    rebuild(load_conf("view \"default\" { match-clients { any; }; };\n"));
    gc_snapshot_wait_idle();
    zone_retire_process(true);
    zone_bytes_get(ZBYTES_OTHER, &ot);
    CHECK(ot.resident <= ot0.resident + 1 && ot.retired == ot0.retired);                 /* the file zone left with its snapshot */
}

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/karidns_dbreg.XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }
    test_install();
    test_registry_delta();
    test_incremental_delta();
    test_shadowing();
    test_catalog_member_wins();
    test_dbcfg();
    test_settings_interning();
    test_secondary_entries();
    test_reuse_fast_path();
    test_glue_dirty_on_delete();
    test_dir_elements();
    test_dir_fetch_state();
    test_cold_no_garbage();
    test_walk_robust();
    test_dir_delta_in_place();
    test_dir_garbage_order();
    test_dir_hidden_and_shared();
    test_dir_replaced_entry_ticks();
    test_dir_bytes_per_zone();
    test_zone_bytes();
    test_concurrent();
    /* Remove the scratch directory in-process: the detached snapshot GC threads of test_concurrent may still be starting
     * or exiting here, and fork() from a multi-threaded process (as system("rm -rf") did) deadlocks under ASan on FreeBSD:
     * the ASan fork handler holds the allocator lock while waiting for the rtld lock, which a starting thread holds while
     * waiting for the allocator lock. */
    if (nftw(g_dir, rm_entry, 16, FTW_DEPTH | FTW_PHYS) != 0) { /* leave the directory */ }
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) return 1;
    printf("=== test_db_registry: all checks passed ===\n");
    return 0;
}
