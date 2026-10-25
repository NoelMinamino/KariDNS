/*
 * test_db_registry.c - the DB zone registry, the view delta and the zone install of the database loader link
 * (beta design 4.1-4.5, milestone B4b): dns_snapshot_rcu.c (dbreg_*, snapshot_apply_db_delta, the shadowing rules of
 * the full-configuration rebuild, dbcfg) and dns_db_install.c (db_zone_build_*).
 *
 *  1. install: a zone built from AXFR-format messages is published into an entry (serial, SOA timers, image, NOTIFY
 *     only when a loaded zone changes its serial); every rejection rule leaves the entry as it was.
 *  2. registry and delta: commit / apply / delete, idempotence, source id check, rejected-only records, walk.
 *  3. D-PRIO: a configured zone hides a DB zone, the DB zone comes back when the configured zone is removed.
 *  4. dbcfg: zone_entry_config() returns it for DB zones, a replaced block is retired and freed.
 *  5. concurrent readers while zones are added and removed: a reader never sees a DB zone without its image.
 *  6. (B6a) D17-1: a catalog member with the name of a DB zone hides it (catalog delta), the DB zone returns when the
 *     member leaves, a DB zone committed behind an existing member is hidden; dbreg_find_info(), dbreg_counts2(),
 *     dbreg_snapshot_entry().
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

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
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
    for (size_t i = 0; i < v->zone_count; i++) {
        if (v->entries[i] && v->entries[i]->source == ZONE_SRC_DB) {
            db_in_view++;
            CHECK(dbreg_lookup_entry("default", v->entries[i]->domain) == v->entries[i]);
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
    CHECK(sh != NULL && sh->ext.masters_count == 2 && sh->ext.masters[0].port == 5300 && sh->ext.masters[1].port == 53);
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
    /* a full reconfiguration keeps the very same entry (a secondary's transferred data is not thrown away) */
    rebuild(cfg);
    CHECK(in_snapshot("default", s1) && dbreg_lookup_entry("default", "slave.test.") == s1);

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
    CHECK(mem2 && strcmp(mem2->catalog_master->ip, "192.0.2.1") == 0 && mem2->catalog_master->port == 5300 &&
          strcmp(mem2->catalog_master->tsig_key, "k1") == 0);                              /* the masters and the key of the consumer */
    CHECK(mem1 && mem1 != hid && mem1->is_catalog_member);                                  /* D17-1: the member wins */
    CHECK(!in_snapshot("default", hid) && dbreg_find_info("default", "m1.test.", info, 1) == 1 && info[0].shadowed);

    /* the consumer's row is deleted: it leaves with its members, and the DB zone they hid is served again */
    CHECK(dbreg_delete("default", "cat.test.", 12) == 1);
    CHECK(snapshot_apply_db_delta() >= 1);
    CHECK(!name_in_snapshot("default", "cat.test.") && !name_in_snapshot("default", "m2.test."));
    CHECK(in_snapshot("default", hid));
    CHECK(dbreg_find_info("default", "m1.test.", info, 1) == 1 && !info[0].shadowed);
    CHECK(in_snapshot("default", p1));

    zone_ext_shared_unref(sh);
    zone_retire_process(true);
    dbreg_reset();
    db_settings_reset();
}

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/karidns_dbreg.XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }
    test_install();
    test_registry_delta();
    test_shadowing();
    test_catalog_member_wins();
    test_dbcfg();
    test_settings_interning();
    test_secondary_entries();
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
