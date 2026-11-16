/*
 * fuzz_db_stream.c - KDB1 framer + decoder + Backend state machine on hostile bytes (dns_db_stream.c).
 *
 * Input: byte 0 is a selector, the rest is the stream.
 *   bit 7      feed the stream whole (else in chunks of 1 + selector % 61 bytes)
 *   bit 6      start the state machine in READY (skips the HELLO the fuzzer would have to find)
 *   bit 5      tiny zone limits (6 records, 200 bytes) so the limit paths are reachable
 *   bit 4      (install run only) start inside a batch, so a stream of ZONE_BEGIN .. ZONE_END is a valid input
 *   bit 3      D1a: the state machine of the fetch stream (kdb_sm_init_fetch(): request ids, summaries, no batches)
 *   bit 2      D1a step 7: the rest is not a stream but a hot list state file (kdb_hotl_parse(), the merge, the serializer, the parts encoder)
 * 0.7 M3: the data of a zone is a zone image (ZONE_BEGIN with the image flag, ZONE_IMAGE messages); the harness checks what the state machine promises about them.
 * The stream is run twice against the loader -> Backend side (whole buffer and the chosen chunking) and must
 * give the same result; once against the Backend -> loader side with the decoder and the entry iterators; and once
 * more through the install path of the Backend (beta design 8.5, milestone B4b): every ZONE_BEGIN / ZONE_IMAGE /
 * ZONE_END of the stream goes through the reassembly, zone_image_validate_ex() and dns_db_install.c into a scratch zone entry and the DB zone registry, as the
 * ingest thread does it (the thread itself, the sockets and the snapshot are not part of the harness; the image frames on their own: fuzz_db_image_frames.c).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../../dns_db_stream.h"
#include "../../dns_zone_image.h"
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
    if (sel & 0x08) kdb_sm_init_fetch(&sm, &lim);         /* D1a: the fetch stream (starts in READY) */
    else kdb_sm_init(&sm, &lim);
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
            if (fr.type == KDB_T_ZONE_BEGIN) {
                mix(&r->sum, m.u.zone_begin.rr_count + strlen(m.u.zone_begin.name) + m.u.zone_begin.request_id);
                /* D1a: what the machine promised about the fetch stream */
                if ((sm.fetch != (m.u.zone_begin.request_id != 0))) abort();
                if ((m.u.zone_begin.flags & KDB_ZF_SUMMARY) && m.u.zone_begin.rr_count != 0) abort();      /* (a summary has no data; since milestone 4 a batch may carry one too; the decoder refuses a summary of a zone that is not a primary) */
            }
            if (fr.type == KDB_T_ZONE_FAILED) {
                mix(&r->sum, m.u.zone_failed.request_id);
                if (sm.fetch != (m.u.zone_failed.request_id != 0)) abort();
            }
            if (fr.type == KDB_T_ZONE_BEGIN) {              /* 0.7 M3: a zone image is announced as the machine promises: a primary with data, the size of an image within max-zone-bytes */
                const kdb_zone_begin_t *zb = &m.u.zone_begin;
                if (((zb->flags & KDB_ZF_IMAGE) != 0) != sm.zone_image || (!sm.zone_image && zb->image_size != 0)) abort();
                if (sm.zone_image) {
                    if (zb->image_size != sm.zone_image_size || (zb->image_size & 7) || zb->image_size < sizeof(zone_image_t) + 8 || zb->image_size > 0xFFFFF000u ||
                        zb->image_size > sm.lim.max_zone_bytes || zb->rr_count == 0 || zb->zone_kind != KDB_ZK_PRIMARY || (zb->flags & KDB_ZF_SUMMARY)) abort();
                    mix(&r->sum, zb->image_size);
                }
            }
            if (fr.type == KDB_T_ZONE_IMAGE) {              /* the octets come to the size that was announced and never past it; the first message holds the header that says the same as ZONE_BEGIN */
                if (!sm.zone_image || m.u.zone_image.len == 0 || m.u.zone_image.len > KDB_MAX_BODY || sm.zone_image_have > sm.zone_image_size) abort();
                if (sm.zone_image_have == m.u.zone_image.len) {                /* (the first message of the image) */
                    zone_image_t h;
                    if (m.u.zone_image.len < sizeof(h)) abort();
                    memcpy(&h, m.u.zone_image.body, sizeof(h));
                    if (h.magic != ZONE_IMAGE_MAGIC || h.version != ZONE_IMAGE_VERSION || h.total_size != sm.zone_image_size || h.n_rrs != sm.zone_rr_declared) abort();
                }
                mix(&r->sum, m.u.zone_image.len + sm.zone_image_have);
            }
            if (fr.type == KDB_T_ZONE_END && sm.zone_image && sm.zone_image_have != sm.zone_image_size) abort();
            if (fr.type == KDB_T_HELLO) mix(&r->sum, m.u.hello.features + m.u.hello.image_version);
            if (fr.type == KDB_T_LOOKUP_RESULT) {            /* 0.7: only the fetch stream carries it; a zone found has its entry, as a manifest entry */
                const kdb_lookup_result_t *l = &m.u.lookup_result;
                if (!sm.fetch || l->request_id == 0) abort();
                if (l->found && (strlen(l->name) == 0 || l->kind > KDB_ZK_CATALOG || l->name[strlen(l->name) - 1] != '.')) abort();
                mix(&r->sum, l->request_id + (l->found ? (uint64_t)l->source_id + l->stamp_gen + l->stamp_time + strlen(l->name) : 0));
            }
            if (fr.type == KDB_T_PROFILE) mix(&r->sum, m.u.profile.settings.len);
            if (fr.type == KDB_T_WARM_LIST) {               /* D1a step 7: the entries the decoder validated, a view name and a canonical zone name each */
                kdb_iter_t it;
                char hv[256], hz[DNS_NAME_TEXT_SIZE];
                uint32_t k = 0;
                kdb_hot_entries(&m, &it);
                while (kdb_hot_entries_next(&it, hv, hz)) {
                    if (hv[0] == '\0' || hz[0] == '\0' || hz[strlen(hz) - 1] != '.') abort();
                    mix(&r->sum, strlen(hv) + strlen(hz));
                    k++;
                }
                if (k != m.u.hot_list.n_entries || m.u.hot_list.n_entries > KDB_HOT_PART_MAX) abort();
                if (m.u.hot_list.file_state >= KDB_HF_N) abort();
                mix(&r->sum, m.u.hot_list.list_id + m.u.hot_list.part + (m.u.hot_list.last ? 1u : 0u));
            }
            if (fr.type == KDB_T_HOT_ACK) {
                if (m.u.hot_ack.status >= KDB_HA_N) abort();
                mix(&r->sum, m.u.hot_ack.list_id + m.u.hot_ack.zones + m.u.hot_ack.error.len);
            }
            if (fr.type == KDB_T_MANIFEST) {                /* 0.7 WP7a: the iterator sees exactly the validated entries; the ones of one stream are the ones the decoder promised */
                kdb_iter_t it;
                kdb_manifest_entry_t en;
                uint32_t k = 0;
                kdb_manifest_entries(&m, &it);
                while (kdb_manifest_entries_next(&it, &en)) {
                    if (strlen(en.name) == 0 || en.kind > KDB_ZK_CATALOG) abort();
                    mix(&r->sum, (uint64_t)en.source_id + en.stamp_gen + en.stamp_time + (en.stamped ? 1u : 0u) + (en.has_serial ? en.serial : 0u) + (en.has_digest ? en.digest[0] : 0u));
                    k++;
                }
                if (k != m.u.manifest.n_entries || k > KDB_MANIFEST_PAGE_MAX || m.u.manifest.view >= 3) abort();
                mix(&r->sum, m.u.manifest.page + m.u.manifest.batch_id);
            }
            if (fr.type == KDB_T_MANIFEST_BEGIN || fr.type == KDB_T_MANIFEST_END) {
                const uint8_t il = fr.type == KDB_T_MANIFEST_BEGIN ? m.u.manifest_begin.ident_len : m.u.manifest_end.ident_len;
                if (il > KDB_IDENT_MAX) abort();
                mix(&r->sum, il + (fr.type == KDB_T_MANIFEST_BEGIN ? m.u.manifest_begin.cursor + m.u.manifest_begin.flags : m.u.manifest_end.cursor + m.u.manifest_end.n_entries));
            }
            if (fr.type == KDB_T_CHANGES) {
                kdb_iter_t it;
                kdb_changes_entry_t en;
                uint32_t k = 0;
                kdb_changes_entries(&m, &it);
                while (kdb_changes_entries_next(&it, &en)) {
                    if (en.op != KDB_CH_UPSERT && en.op != KDB_CH_DELETE) abort();
                    if (en.op == KDB_CH_UPSERT && (!en.has_name || strlen(en.name) == 0)) abort();
                    if (en.has_name && en.name[strlen(en.name) - 1] != '.') abort();
                    mix(&r->sum, (uint64_t)en.source_id + en.op + en.stamp_gen + (en.force ? 7u : 0u) + (en.has_serial ? en.serial : 0u));
                    k++;
                }
                if (k != m.u.changes.n_entries || m.u.changes.ident_len > KDB_IDENT_MAX || m.u.changes.view >= 3) abort();
                mix(&r->sum, m.u.changes.cursor + (m.u.changes.last ? 1u : 0u));
            }
            if (fr.type == KDB_T_AUTO_STATUS) {            /* B9: the iterator sees exactly the validated entries */
                kdb_iter_t it;
                kdb_auto_status_entry_t en;
                uint32_t k = 0;
                kdb_auto_status_entries(&m, &it);
                while (kdb_auto_status_entries_next(&it, &en)) {
                    if (en.view >= 3) abort();
                    mix(&r->sum, en.applied_seq + en.pending + en.error.len);
                    /* B11: the optional tags 6..11 hold what the decoder promised: flags 0..3, an id of 1..64 printable bytes, ok 0/1 */
                    if (en.flags > (KDB_AS_AUTO | KDB_AS_REQ)) abort();
                    if (en.server_id.p && (en.server_id.len < 1 || en.server_id.len > 64)) abort();
                    if (en.server_id.p) for (uint32_t q = 0; q < en.server_id.len; q++) if ((uint8_t)en.server_id.p[q] < 0x20 || (uint8_t)en.server_id.p[q] > 0x7E) abort();
                    if (en.req_error.len > 255) abort();
                    mix(&r->sum, en.req_generation + en.req_time + en.server_id.len + en.req_error.len + (en.req_ok ? 1u : 0u) + en.flags);
                    k++;
                }
                if (k != m.u.auto_status.n_entries) abort();
            }
        }
        if (rc != KDB_OK) { r->rc = rc; break; }
    } while (off < n);
    r->state = sm.state;
    if (r->rc != KDB_OK && sm.state != KDB_S_ERROR && f.fail == KDB_OK) abort();   /* an error must be sticky somewhere */
}

/* 0.7 M2: the same stream with the pages of a pass handed over as the Backend does (kdb_sm_legal_frame() on the stream thread, kdb_man_page() / kdb_man_end() on the reconcile thread, the zones of the pages added to
 * the machine before BATCH_END): the verdict and the number of frames must be the machine's own */
static void run_split(const uint8_t *p, size_t n, uint8_t sel, run_t *r) {
    kdb_framer_t f;
    kdb_sm_t sm;
    kdb_msg_t m;
    kdb_man_t man;
    kdb_limits_t lim = { KDB_DEFAULT_MAX_ZONE_RECORDS, KDB_DEFAULT_MAX_ZONE_BYTES, 3 };
    if (sel & 0x20) { lim.max_zone_records = 6; lim.max_zone_bytes = 200; }
    kdb_framer_init(&f, KDB_FROM_LOADER, g_buf, sizeof(g_buf));
    if (sel & 0x08) kdb_sm_init_fetch(&sm, &lim);
    else kdb_sm_init(&sm, &lim);
    kdb_sm_defer_manifest(&sm);
    if (sel & 0x40) sm.state = KDB_S_READY;
    memset(&man, 0, sizeof(man));
    memset(r, 0, sizeof(*r));
    uint64_t zones = 0;
    char why[KDB_REASON_LEN];
    kdb_rc_t rc = kdb_framer_feed(&f, p, n);
    while (rc == KDB_OK) {
        kdb_frame_t fr;
        rc = kdb_framer_next(&f, &fr);
        if (rc == KDB_MORE) { rc = KDB_OK; break; }
        if (rc != KDB_OK) break;
        if (fr.type == KDB_T_MANIFEST) {
            rc = kdb_sm_legal_frame(&sm, fr.type);
            if (rc != KDB_OK) break;
            rc = kdb_man_page(&man, &fr, &m, why, sizeof(why));
            if (rc != KDB_OK) break;
            zones += m.u.manifest.n_entries;
            r->nframes++;
            continue;
        }
        if (fr.type == KDB_T_BATCH_END || fr.type == KDB_T_BATCH_BEGIN) { sm.n_zones += zones; zones = 0; }
        rc = kdb_sm_accept(&sm, &fr, &m);
        if (rc != KDB_OK) break;
        if (fr.type == KDB_T_MANIFEST_BEGIN) kdb_man_begin(&man, m.u.manifest_begin.batch_id, m.u.manifest_begin.view, sm.lim.view_count);
        if (fr.type == KDB_T_MANIFEST_END) {
            rc = kdb_man_end(&man, &m.u.manifest_end, why, sizeof(why));
            if (rc != KDB_OK) break;
        }
        r->nframes++;
    }
    r->rc = rc;
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
            while (kdb_config_views_next(&it, &v)) {
                if (v.ident_len > KDB_IDENT_MAX || (!v.has_cursor && v.cursor != 0)) abort();       /* 0.7 WP7a: a cursor is valid or none */
                k++;
            }
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
        } else if (fr.type == KDB_T_HOT_LIST) {          /* D1a step 7 */
            kdb_iter_t it;
            char hv[256], hz[DNS_NAME_TEXT_SIZE];
            uint32_t k = 0;
            kdb_hot_entries(&m, &it);
            while (kdb_hot_entries_next(&it, hv, hz)) {
                if (hv[0] == '\0' || hz[0] == '\0') abort();
                k++;
            }
            if (k != m.u.hot_list.n_entries || m.u.hot_list.limit > KDB_HOT_MAX) abort();
        } else if (fr.type == KDB_T_FETCH_REQ) {         /* D1a */
            const kdb_fetch_req_t *q = &m.u.fetch_req;
            if (q->request_id == 0 || q->view >= 3 || strlen(q->name) == 0 || q->priority >= KDB_FETCH_PRIO_N || q->mode > KDB_FETCH_LOOKUP_FULL) abort();
            if ((q->mode == KDB_FETCH_LOOKUP || q->mode == KDB_FETCH_LOOKUP_FULL) && (q->has_range || q->source_id != 0)) abort();      /* 0.7: a lookup has neither */
            if (q->has_range && (strlen(q->range_lo) == 0 || strlen(q->range_hi) == 0)) abort();
            if (q->source_id < 0) abort();                  /* 0.7 WP7a */
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
    if (sel & 0x08) {
        kdb_sm_init_fetch(&sm, &lim);                          /* D1a: the fetch stream: zones from READY */
    } else {
        kdb_sm_init(&sm, &lim);
        sm.state = (sel & 0x10) ? KDB_S_IN_BATCH : KDB_S_READY;   /* bit 4: start inside a batch (zones right away) */
    }
    if (kdb_framer_feed(&f, p, n) != KDB_OK) return;
    uint8_t *img = NULL;                       /* the reassembled image (grown with the octets that come, never to the announced size) */
    size_t img_have = 0, img_cap = 0;
    bool is_image = false;
    kdb_zone_begin_t zb = { 0 };
    char zone[DNS_NAME_TEXT_SIZE] = "";
    char view[8] = "default";
    int64_t source_id = 0;
    bool failed = false, summary = false;
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
            free(img);
            img = NULL;
            img_have = img_cap = 0;
            zb = m.u.zone_begin;
            is_image = (m.u.zone_begin.flags & KDB_ZF_IMAGE) != 0;
            snprintf(zone, sizeof(zone), "%s", m.u.zone_begin.name);
            snprintf(view, sizeof(view), "v%u", (unsigned)(m.u.zone_begin.view % 3));
            source_id = m.u.zone_begin.source_id;
            failed = false;
            zone_ext_shared_unref(zsh);
            zsh = fuzz_settings(&m.u.zone_begin);
            skind = m.u.zone_begin.zone_kind;
            summary = (m.u.zone_begin.flags & KDB_ZF_SUMMARY) != 0;           /* D1a: a summary has no data and installs nothing here */
            /* B7b: a secondary zone needs masters in its settings and has no data (job_execute_secondary()) */
            if (summary) failed = false;
            else if (skind == KDB_ZK_PRIMARY ? !is_image : !(zsh && zsh->ext.masters_count > 0)) failed = true;
            break;
        case KDB_T_PROFILE:
            g_prof_len = m.u.profile.settings.len < sizeof(g_prof) ? m.u.profile.settings.len : sizeof(g_prof);
            memcpy(g_prof, m.u.profile.settings.p, g_prof_len);
            break;
        case KDB_T_ZONE_IMAGE:
            if (is_image && !failed) {
                if (img_have + m.u.zone_image.len > img_cap) {
                    size_t nc = img_cap ? img_cap * 2 : 65536;
                    while (nc < img_have + m.u.zone_image.len) nc *= 2;
                    uint8_t *nb = realloc(img, nc);
                    if (!nb) { failed = true; break; }
                    img = nb;
                    img_cap = nc;
                }
                memcpy(img + img_have, m.u.zone_image.body, m.u.zone_image.len);
                img_have += m.u.zone_image.len;
            }
            break;
        case KDB_T_ZONE_ABORT:
            free(img);
            img = NULL;
            img_have = img_cap = 0;
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
            } else if (is_image && img && !failed) {
                /* what the ingest thread does: the image against what ZONE_BEGIN said (and the limits of the stream), then the entry */
                const zone_image_policy_t pol = { zone, zb.serial, zb.rr_count, zb.image_size, sm.lim.max_zone_bytes, sm.lim.max_zone_records, (zb.flags & KDB_ZF_EXTENDED) != 0,
                                                  (zb.flags & KDB_ZF_TINYDNS) != 0 };
                bool valid = img_have == zb.image_size && zone_image_validate_ex(img, img_have, &pol, why, sizeof(why)) == 0;
                zone_db_entry_t *e = valid ? dbreg_lookup_entry(view, zone) : NULL;
                bool created = false;
                if (e && e->is_secondary) e = NULL;       /* B7b: a SLAVE that became a primary is replaced */
                if (valid && !e) {
                    e = scratch_entry(view, zone, zsh, KDB_ZK_PRIMARY);
                    created = e != NULL;
                }
                if (valid && e && db_zone_install_image(e, (zone_image_t *)img, NULL, why, sizeof(why)) == 0) {
                    img = NULL;                                              /* (the entry's version owns it) */
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
            summary = false;
            free(img);
            img = NULL;
            img_have = img_cap = 0;
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
    free(img);
    zone_ext_shared_unref(zsh);
    zone_retire_process(true);
    dbreg_reset();
    zone_retire_process(true);
    db_settings_reset();
}

static int hot_emit_count(void *ud) { (*(int *)ud)++; return 0; }

/* D1a step 7: the state file.  Whatever the bytes, the parser either refuses them or yields a list that serializes to a file it accepts again, equal to the first,
 * that merges with itself into itself, and that the parts encoder turns into messages the decoder takes. */
static void run_state_file(const uint8_t *p, size_t n) {
    kdb_hotl_t a, b, m;
    char why[200];
    kdb_hotl_init(&a);
    kdb_hotl_init(&b);
    kdb_hotl_init(&m);
    if (kdb_hotl_parse((const char *)p, n, &a, why, sizeof(why))) {
        size_t len = 0;
        char *txt = kdb_hotl_serialize(&a, &len);
        if (!txt) abort();
        if (!kdb_hotl_parse(txt, len, &b, why, sizeof(why)) || !kdb_hotl_equal(&a, &b)) abort();
        free(txt);
        if (!kdb_hotl_merge(&a, &b, 0, &m)) abort();
        if (m.n > a.n) abort();
        kdb_enc_t e;
        kdb_enc_init(&e);
        int parts = 0;
        if (kdb_hot_encode(&a, &e, KDB_T_HOT_LIST, 1, 5, -1, 0, hot_emit_count, &parts) != 0 || parts < 1) abort();
        kdb_enc_free(&e);
    } else if (a.n != 0) {
        abort();                                           /* a refused file leaves nothing behind */
    }
    kdb_hotl_free(&a);
    kdb_hotl_free(&b);
    kdb_hotl_free(&m);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t sel = data[0];
    const uint8_t *p = data + 1;
    size_t n = size - 1;
    if (sel & 0x04) {                       // D1a step 7: the state file
        run_state_file(p, n);
        return 0;
    }
    size_t chunk = (sel & 0x80) ? 0 : (size_t)(1 + sel % 61);
    run_t a, b;
    run_loader(p, n, 0, sel, &a);
    run_loader(p, n, chunk, sel, &b);
    if (a.rc != b.rc || a.nframes != b.nframes || a.sum != b.sum || a.state != b.state) abort();
    run_t c;
    run_split(p, n, sel, &c);
    if (c.rc != a.rc || c.nframes != a.nframes) abort();                                  /* (0.7 M2: the stream thread and the reconcile thread give the verdict of the one machine) */
    run_backend(p, n);
    run_install(p, n, sel);
    return 0;
}
