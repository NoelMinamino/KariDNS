/*
 * test_zone_dir.c - the zone directory (D1a) under concurrent readers.
 *
 * Readers do what the query path, the control thread's tick and the ALIAS scan do (zdir_find_exact(), zdir_find_suffix(), a walk of the
 * index, a walk of the tick list, every one inside a read section, without a lock), while one writer commits, replaces and deletes zones
 * and publishes deltas that cross growths of the index table and reuse tombstones.  What a reader checks:
 *   - a name that is found maps to an element and an entry of its own (the name of the element and of the entry is the name looked up);
 *   - a walk of the index never sees the same element twice and never sees an element without an entry;
 *   - every element of the tick list has an entry that ticks (a secondary).
 * The pointers a reader gets stay valid while it is in its read section (the garbage of the directory is released after the grace period
 * and after the older snapshots are drained), so any use after free shows up under AddressSanitizer, and any unsynchronized access to what
 * a writer changes under ThreadSanitizer (make test_zone_dir-asan, make test_zone_dir-tsan).  At the end the directory lists exactly the
 * zones the writer left registered.
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
#include <unistd.h>
#include <syslog.h>

#include "../dns_config_parser.h"
#include "../dns_utils.h"
#include "db/xfr_mocks.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

#define NZ 700              /* names z0.test. .. z699.test. */
#define READERS 3
#define ROUNDS 60
#define WALK_MAX 4096

static _Atomic bool g_stop;
static _Atomic long g_reads, g_bad;
static pthread_barrier_t g_start;

static void zname(int i, char *buf, size_t n) { snprintf(buf, n, "z%d.test.", i); }

static int cmp_vp(const void *a, const void *b) {
    const void *x = *(const void *const *)a, *y = *(const void *const *)b;
    return x < y ? -1 : x > y;
}

static void *reader(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg * 2654435761u + 1;
    static __thread void *seen[WALK_MAX];
    pthread_barrier_wait(&g_start);
    for (unsigned loop = 0; !atomic_load(&g_stop); loop++) {
        rcu_aux_read_lock();
        zone_db_snapshot_t *snap = acquire_zone_snapshot();
        view_snapshot_t *view = snapshot_find_view(snap, "default");
        for (int k = 0; view && k < 24; k++) {
            seed = seed * 1103515245u + 12345u;
            int i = (int)((seed >> 8) % NZ);
            char nm[64], q[96];
            zname(i, nm, sizeof(nm));
            snprintf(q, sizeof(q), "www.sub.%s", nm);
            zdir_elem_t *el = zdir_find_exact(view, nm);
            if (el) {
                zone_db_entry_t *en = zdir_entry(el);
                if (!en || !domain_names_match_ci(en->domain, nm) || !domain_names_match_ci(el->name, nm)) atomic_fetch_add(&g_bad, 1);
            }
            zdir_elem_t *sl = zdir_find_suffix(view, q);
            if (sl) {
                zone_db_entry_t *en = zdir_entry(sl);
                /* the zone that holds www.sub.zN.test. is zN.test. itself (there is no other zone above it) */
                if (!en || !domain_names_match_ci(en->domain, nm)) atomic_fetch_add(&g_bad, 1);
            }
            atomic_fetch_add(&g_reads, 1);
        }
        if (view && loop % 4 == 0) {
            size_t n = 0;
            zdir_iter_t it;
            zdir_iter_init(&it, view);
            for (zdir_elem_t *e; (e = zdir_iter_next(&it)) && n < WALK_MAX;) {
                if (!zdir_entry(e)) atomic_fetch_add(&g_bad, 1);
                seen[n++] = e;
            }
            qsort(seen, n, sizeof(seen[0]), cmp_vp);
            for (size_t j = 1; j < n; j++)
                if (seen[j] == seen[j - 1]) atomic_fetch_add(&g_bad, 1);     /* the same element twice in one walk */
            if (n == 0) atomic_fetch_add(&g_bad, 1);                         /* (the zone { } block is always there) */
            size_t tn = 0;
            zdir_elem_t *const *tl = zdir_tick_list(view, &tn);
            for (size_t j = 0; j < tn; j++) {
                zone_db_entry_t *en = zdir_entry(tl[j]);
                if (!en || !en->is_secondary) atomic_fetch_add(&g_bad, 1);
            }
        }
        rcu_aux_read_unlock();
    }
    return NULL;
}

static zone_db_entry_t *mk_entry(int j) {
    char nm[64];
    zname(j, nm, sizeof(nm));
    zone_db_entry_t *e = create_new_zone_entry(nm, "default");
    if (!e) return NULL;
    e->source = ZONE_SRC_DB;
    e->kind = (j % 5 == 0) ? ZONE_KIND_SECONDARY : ZONE_KIND_PRIMARY;
    e->is_secondary = (j % 5 == 0);
    return e;
}

int main(void) {
    server_config_t *cfg = calloc(1, sizeof(*cfg));
    CHECK(cfg && parse_named_conf("view \"default\" { match-clients { any; }; zone \"static.test\" { type master; }; };\n", cfg) == 0);
    atomic_store_explicit(&g_config_db.active, cfg, memory_order_release);
    rebuild_zone_db_from_config(cfg, false);

    pthread_barrier_init(&g_start, NULL, READERS + 1);
    pthread_t th[READERS];
    for (long i = 0; i < READERS; i++) pthread_create(&th[i], NULL, reader, (void *)(i + 1));
    pthread_barrier_wait(&g_start);

    static bool live[NZ];
    uint8_t dg[32] = { 1 };
    unsigned seed = 12345;
    long ops = 0, deltas = 0;
    for (int round = 0; round < ROUNDS; round++) {
        /* a burst of additions that grows the index, a stretch of replacements and deletions that leaves tombstones, and the same zones back */
        int phase = round % 3;
        int lo = phase == 0 ? 0 : 100, hi = phase == 0 ? NZ : 400;
        for (int j = lo; j < hi; j++) {
            seed = seed * 1103515245u + 12345u;
            char nm[64];
            zname(j, nm, sizeof(nm));
            bool want_live = (phase == 1) ? ((seed >> 9) % 3 != 0) : (phase == 0 ? true : ((seed >> 9) % 2 == 0));
            if (want_live) {
                zone_db_entry_t *e = mk_entry(j);          /* new, or a replacement of the entry that is registered */
                if (!e) continue;
                bool created = true;
                if (dbreg_commit("default", nm, e, created, 1000 + j, 1, dg, NULL) != 0) {
                    free_zone_db_entry(e);
                    continue;
                }
                live[j] = true;
            } else if (live[j]) {
                CHECK(dbreg_delete("default", nm, 1000 + j) == 1);
                live[j] = false;
            }
            ops++;
            if (ops % 37 == 0) {
                (void)snapshot_apply_db_delta();
                deltas++;
            }
        }
        (void)snapshot_apply_db_delta();
        deltas++;
        if (round % 10 == 9) {
            gc_snapshot_wait_idle();                       /* the older snapshots are drained: their garbage is freed while readers run */
            zone_retire_process(false);
        }
    }
    atomic_store(&g_stop, true);
    for (int i = 0; i < READERS; i++) pthread_join(th[i], NULL);
    printf("  %ld operations, %ld deltas, %ld lookups by %d readers, %ld inconsistencies\n", ops, deltas, atomic_load(&g_reads), READERS,
           atomic_load(&g_bad));
    CHECK(atomic_load(&g_bad) == 0);
    CHECK(atomic_load(&g_reads) > 0);

    /* at the end the directory lists exactly the zones that are registered */
    (void)snapshot_apply_db_delta();
    zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
    view_snapshot_t *v = snapshot_find_view(s, "default");
    CHECK(v != NULL);
    size_t want = 1;                                         /* static.test. */
    for (int j = 0; j < NZ; j++) {
        char nm[64];
        zname(j, nm, sizeof(nm));
        zone_db_entry_t *reg = dbreg_lookup_entry("default", nm);
        zone_db_entry_t *got = find_zone_exact_in_view(v, nm);
        CHECK(live[j] ? (reg != NULL && got == reg) : (reg == NULL && got == NULL));
        if (live[j]) want++;
    }
    CHECK(v && zdir_count(v) == want);
    release_zone_snapshot(s);
    gc_snapshot_wait_idle();
    CHECK(zdir_gc_queued() == 0);                            /* every retired snapshot was drained and freed with its garbage */
    dbreg_reset();
    zone_retire_process(true);
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) return 1;
    printf("=== test_zone_dir: all checks passed ===\n");
    return 0;
}
