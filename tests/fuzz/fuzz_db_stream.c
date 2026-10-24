/*
 * fuzz_db_stream.c - KDB1 framer + decoder + Backend state machine on hostile bytes (dns_db_stream.c).
 *
 * Input: byte 0 is a selector, the rest is the stream.
 *   bit 7      feed the stream whole (else in chunks of 1 + selector % 61 bytes)
 *   bit 6      start the state machine in READY (skips the HELLO the fuzzer would have to find)
 *   bit 5      tiny zone limits (6 records, 200 bytes) so the limit paths are reachable
 *   bit 4      (install run only) start inside a batch, so a stream of ZONE_BEGIN .. ZONE_END is a valid input
 * The stream is run twice against the loader -> Backend side (whole buffer and the chosen chunking) and must
 * give the same result; once against the Backend -> loader side with the decoder and the entry iterators; and once
 * more through the install path of the Backend (beta design 8.5, milestone B4b): every ZONE_BEGIN / ZONE_DATA /
 * ZONE_END of the stream goes through dns_db_install.c into a scratch zone entry and the DB zone registry, as the
 * ingest thread does it (the thread itself, the sockets and the snapshot are not part of the harness).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../../dns_db_stream.h"
#include "../../dns_db_install.h"
#include "../../dns_axfr_ixfr.h"
#include "../../dns_snapshot_rcu.h"
#include "../../dns_utils.h"
#include "../../tests/db/xfr_mocks.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static uint8_t g_buf[KDB_MAX_BODY];

typedef struct {
    kdb_rc_t rc;
    int nframes;
    uint64_t sum;       /* digest of the decoded fields, to compare the two runs */
    kdb_state_t state;
} run_t;

static void mix(uint64_t *h, uint64_t v) { *h = (*h ^ v) * 1099511628211ull; }

static void run_loader(const uint8_t *p, size_t n, size_t chunk, uint8_t sel, run_t *r) {
    kdb_framer_t f;
    kdb_sm_t sm;
    kdb_msg_t m;
    kdb_limits_t lim = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, 3 };
    if (sel & 0x20) { lim.max_zone_records = 6; lim.max_zone_bytes = 200; }
    kdb_framer_init(&f, KDB_FROM_LOADER, g_buf, sizeof(g_buf));
    kdb_sm_init(&sm, &lim);
    if (sel & 0x40) sm.state = KDB_S_READY;
    memset(r, 0, sizeof(*r));
    r->sum = 1469598103934665603ull;
    size_t off = 0;
    do {
        size_t c = chunk ? (n - off < chunk ? n - off : chunk) : n - off;
        kdb_rc_t rc = kdb_framer_feed(&f, p + off, c);
        off += c;
        while (rc == KDB_OK) {
            kdb_frame_t fr;
            rc = kdb_framer_next(&f, &fr);
            if (rc == KDB_MORE) { rc = KDB_OK; break; }
            if (rc != KDB_OK) break;
            rc = kdb_sm_accept(&sm, &fr, &m);
            if (rc != KDB_OK) break;
            r->nframes++;
            mix(&r->sum, fr.type);
            mix(&r->sum, fr.len);
            if (fr.type == KDB_T_ZONE_BEGIN) mix(&r->sum, m.u.zone_begin.rr_count + strlen(m.u.zone_begin.name));
            if (fr.type == KDB_T_ZONE_DATA) mix(&r->sum, m.u.zone_data.ancount);
            if (fr.type == KDB_T_PROFILE) mix(&r->sum, m.u.profile.settings.len);
        }
        if (rc != KDB_OK) { r->rc = rc; break; }
    } while (off < n);
    r->state = sm.state;
    if (r->rc != KDB_OK && sm.state != KDB_S_ERROR && f.fail == KDB_OK) abort();   /* an error must be sticky somewhere */
}

static void run_backend(const uint8_t *p, size_t n) {
    kdb_framer_t f;
    kdb_framer_init(&f, KDB_FROM_BACKEND, g_buf, sizeof(g_buf));
    if (kdb_framer_feed(&f, p, n) != KDB_OK) return;
    for (;;) {
        kdb_frame_t fr;
        if (kdb_framer_next(&f, &fr) != KDB_OK) return;
        kdb_msg_t m;
        char why[KDB_REASON_LEN];
        if (kdb_decode(&fr, 3, &m, why, sizeof(why)) != KDB_OK) return;
        if (fr.type == KDB_T_CONFIG) {
            kdb_iter_t it;
            kdb_config_view_t v;
            uint32_t k = 0;
            kdb_config_views(&m, &it);
            while (kdb_config_views_next(&it, &v)) k++;
            if (k != m.u.config.n_views) abort();      /* the iterator sees exactly the validated entries */
        } else if (fr.type == KDB_T_INVENTORY) {
            kdb_iter_t it;
            kdb_inventory_entry_t en;
            uint32_t k = 0;
            kdb_inventory_entries(&m, &it);
            while (kdb_inventory_entries_next(&it, &en)) {
                if (strlen(en.name) == 0 || en.view >= 3) abort();
                k++;
            }
            if (k != m.u.inventory.n_entries) abort();
        }
    }
}

/* The install path: what handle_msg() of dns_db_ingest.c does with a zone, without the thread.  A zone that installs
 * is registered; the registry and the entries are dropped at the end of the input. */
/* B7a: the settings of a zone, resolved as resolve_zone_settings() of the ingest thread does: the text of the last PROFILE of
 * the stream followed by the zone's own text, restricted parse, interned.  NULL = none (or refused: the zone then has no
 * settings, which is all the harness needs from it). */
static char g_prof[4096];
static size_t g_prof_len;

static zone_ext_shared_t *fuzz_settings(const kdb_zone_begin_t *zb) {
    size_t zl = zb->settings.p ? zb->settings.len : 0;
    size_t pl = (zb->profile.p && zb->profile.len) ? g_prof_len : 0;
    if (zl + pl == 0 || zl + pl + 2 > sizeof(g_prof) * 2) return NULL;
    char *merged = malloc(pl + 1 + zl + 1);
    if (!merged) return NULL;
    memcpy(merged, g_prof, pl);
    merged[pl] = '\n';
    if (zl) memcpy(merged + pl + 1, zb->settings.p, zl);
    char err[200];
    zone_ext_shared_t *sh = db_settings_parse(merged, pl + 1 + zl, err, sizeof(err));
    if (sh) {
        sh->key = merged;                          /* (owned by the object from here on) */
        sh->key_len = pl + 1 + zl;
        sh->hash = db_settings_hash(merged, sh->key_len);
        sh = db_settings_intern(sh);
    } else {
        free(merged);
    }
    return sh;
}

static zone_db_entry_t *scratch_entry(const char *view, const char *zone, zone_ext_shared_t *sh, uint8_t kind) {
    zone_db_entry_t *e = create_new_zone_entry(zone, view);
    if (!e) return NULL;
    zone_config_t *dc = db_zone_config_new_kind(zone, sh, kind == KDB_ZK_PRIMARY ? 0 : kind == KDB_ZK_SECONDARY ? 1 : 2);
    if (!dc) {
        free_zone_db_entry(e);
        return NULL;
    }
    e->source = ZONE_SRC_DB;
    e->kind = kind == KDB_ZK_PRIMARY ? ZONE_KIND_PRIMARY : ZONE_KIND_SECONDARY;
    e->is_secondary = kind != KDB_ZK_PRIMARY;      /* B7b */
    atomic_store_explicit(&e->dbcfg, dc, memory_order_release);
    return e;
}

static void run_install(const uint8_t *p, size_t n, uint8_t sel) {
    kdb_framer_t f;
    kdb_sm_t sm;
    kdb_msg_t m;
    kdb_limits_t lim = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, 3 };
    if (sel & 0x20) { lim.max_zone_records = 6; lim.max_zone_bytes = 200; }
    kdb_framer_init(&f, KDB_FROM_LOADER, g_buf, sizeof(g_buf));
    kdb_sm_init(&sm, &lim);
    sm.state = (sel & 0x10) ? KDB_S_IN_BATCH : KDB_S_READY;   /* bit 4: start inside a batch (zones right away) */
    if (kdb_framer_feed(&f, p, n) != KDB_OK) return;
    db_zone_build_t *b = NULL;
    char zone[DNS_NAME_TEXT_SIZE] = "";
    char view[8] = "default";
    int64_t source_id = 0;
    bool failed = false;
    char why[KDB_REASON_LEN];
    zone_ext_shared_t *zsh = NULL;
    uint8_t skind = KDB_ZK_PRIMARY;
    g_prof_len = 0;
    for (;;) {
        kdb_frame_t fr;
        if (kdb_framer_next(&f, &fr) != KDB_OK) break;
        if (kdb_sm_accept(&sm, &fr, &m) != KDB_OK) break;
        switch (fr.type) {
        case KDB_T_ZONE_BEGIN:
            db_zone_build_free(b);
            snprintf(zone, sizeof(zone), "%s", m.u.zone_begin.name);
            snprintf(view, sizeof(view), "v%u", (unsigned)(m.u.zone_begin.view % 3));
            source_id = m.u.zone_begin.source_id;
            failed = false;
            zone_ext_shared_unref(zsh);
            zsh = fuzz_settings(&m.u.zone_begin);
            skind = m.u.zone_begin.zone_kind;
            b = (skind == KDB_ZK_PRIMARY) ? db_zone_build_new(zone, m.u.zone_begin.rr_count, m.u.zone_begin.flags) : NULL;
            /* B7b: a secondary zone needs masters in its settings and has no data (job_execute_secondary()) */
            if (skind == KDB_ZK_PRIMARY ? !b : !(zsh && zsh->ext.masters_count > 0)) failed = true;
            break;
        case KDB_T_PROFILE:
            g_prof_len = m.u.profile.settings.len < sizeof(g_prof) ? m.u.profile.settings.len : sizeof(g_prof);
            memcpy(g_prof, m.u.profile.settings.p, g_prof_len);
            break;
        case KDB_T_ZONE_DATA:
            if (b && !failed && db_zone_build_feed(b, m.u.zone_data.body, m.u.zone_data.len, why, sizeof(why)) != 0)
                failed = true;
            break;
        case KDB_T_ZONE_ABORT:
            db_zone_build_free(b);
            b = NULL;
            break;
        case KDB_T_ZONE_END:
            if (skind != KDB_ZK_PRIMARY && !failed) {
                zone_db_entry_t *e = dbreg_lookup_entry(view, zone);
                const zone_config_t *oc = e ? atomic_load(&e->dbcfg) : NULL;
                bool created = false;
                if (e && (!e->is_secondary || !oc || oc->is_catalog != (skind == KDB_ZK_CATALOG))) e = NULL;
                if (!e) {
                    e = scratch_entry(view, zone, zsh, skind);
                    created = e != NULL;
                } else if (!(zsh ? (oc->ext_shared && oc->ext == &zsh->ext) : oc->ext == NULL)) {
                    zone_config_t *nc = db_zone_config_new_kind(zone, zsh, skind == KDB_ZK_CATALOG ? 2 : 1);
                    if (nc) db_entry_set_config(e, nc);
                }
                uint8_t dg[32] = { 0 };
                bool sh;
                if (!e || dbreg_commit(view, zone, e, created, source_id, 0, dg, &sh) != 0) {
                    if (created) free_zone_db_entry(e);
                    (void)dbreg_reject(view, zone, source_id, "rejected");
                }
            } else if (skind != KDB_ZK_PRIMARY) {
                (void)dbreg_reject(view, zone, source_id, "rejected");
            } else if (b && !failed) {
                zone_db_entry_t *e = dbreg_lookup_entry(view, zone);
                bool created = false;
                if (e && e->is_secondary) e = NULL;       /* B7b: a SLAVE that became a primary is replaced */
                if (!e) {
                    e = scratch_entry(view, zone, zsh, KDB_ZK_PRIMARY);
                    created = e != NULL;
                }
                if (e && db_zone_build_install(b, e, NULL, why, sizeof(why)) == 0) {
                    uint8_t dg[32] = { 0 };
                    bool sh;
                    if (dbreg_commit(view, zone, e, created, source_id, (uint32_t)atomic_load(&e->serial), dg, &sh) != 0 && created)
                        free_zone_db_entry(e);
                } else {
                    if (created) free_zone_db_entry(e);
                    (void)dbreg_reject(view, zone, source_id, "rejected");
                }
            } else if (failed) {
                (void)dbreg_reject(view, zone, source_id, "rejected");
            }
            db_zone_build_free(b);
            b = NULL;
            break;
        case KDB_T_ZONE_DELETE:
            (void)dbreg_delete(view, m.u.zone_delete.name, m.u.zone_delete.source_id);
            break;
        case KDB_T_ZONE_FAILED:
            (void)dbreg_reject(view, m.u.zone_failed.name, m.u.zone_failed.source_id, "loader error");
            break;
        default:
            break;
        }
    }
    db_zone_build_free(b);
    zone_ext_shared_unref(zsh);
    zone_retire_process(true);
    dbreg_reset();
    zone_retire_process(true);
    db_settings_reset();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t sel = data[0];
    const uint8_t *p = data + 1;
    size_t n = size - 1;
    size_t chunk = (sel & 0x80) ? 0 : (size_t)(1 + sel % 61);
    run_t a, b;
    run_loader(p, n, 0, sel, &a);
    run_loader(p, n, chunk, sel, &b);
    if (a.rc != b.rc || a.nframes != b.nframes || a.sum != b.sum || a.state != b.state) abort();
    run_backend(p, n);
    run_install(p, n, sel);
    return 0;
}
