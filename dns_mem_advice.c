/*
 * dns_mem_advice.c - the memory a database needs and what to say about memory-limit (see dns_mem_advice.h).
 *
 * How the constants were found (W9, docs/karidns.md "Memory by number of zones" and "With memory-limit"; one host, one data set):
 *   counted bytes of a zone in memory  = the `resident` bytes of the cache line divided by the zones in memory: 2,286 B (100k small zones, all in
 *     memory), 2,308 B (1M, 432,041 in memory), 11,264 B and 11,253 B (100k medium zones, 90,388 and 21,432 in memory).  Small zones have 11 records,
 *     medium ones 98: (11,260 - 2,300) / 87 = 103 B a record, 2,300 - 11 x 103 = 1,170 B a zone.
 *   Backend, every zone in memory (no limit) = 2,461 MB at 1M small zones, 1,232 MB at 100k medium ones, 36 MB at 100 zones: (2,544 B a small zone,
 *     12,552 B a medium one) = 1,280 B a zone + 115 B a record, on 35 MB.
 *   Backend with a limit = 70 MB + 0.45 KB x zones + resident (the formula of the manual, within -4% .. +9% of eight points).
 *   Loader = 54 MB / 213 MB (100k / 1M zones, no limit), 635 MB at 1M with a limit (it holds the summaries): 30 MB + 0.18 KB or 0.6 KB a zone.
 * The estimate is within the same 10% as the manual's formula; it errs towards too much (the Backend's entry is counted once in the directory and once
 * in the zone's bytes), which is the safe side for a size to buy memory by.
 */
#include "dns_mem_advice.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

static uint64_t round_up(uint64_t v, uint64_t m) {
    uint64_t r = v / m * m;
    if (r < v) r += m;
    return r < m ? m : r;
}

void ma_estimate(const ma_in_t *in, ma_est_t *e) {
    memset(e, 0, sizeof(*e));
    e->zones = in->zones;
    e->limit = in->limit;
    if (in->have_records) {
        e->basis = MA_BASIS_RECORDS;
        e->records = in->records;
        e->counted_all = in->zones * MA_ZONE_BASE + in->records * MA_RECORD;
    } else if (in->zones > 0 && in->resident_zones > 0 && in->resident_bytes > 0 && (in->resident_zones >= MA_SAMPLE_ZONES || in->resident_zones >= in->zones)) {
        /* the zones that are in memory say how big a zone is: the zones asked for are the busy ones, so this can err on either side; the average is
         * not trusted from fewer than MA_SAMPLE_ZONES zones, unless they are all of them */
        e->basis = MA_BASIS_RESIDENT;
        uint64_t avg = in->resident_bytes / in->resident_zones;
        e->counted_all = avg * in->zones;
        e->records = avg > MA_ZONE_BASE ? (avg - MA_ZONE_BASE) * in->zones / MA_RECORD : 0;
    } else {
        e->basis = MA_BASIS_ASSUMED;
        e->records = in->zones * MA_ASSUMED_RECORDS;
        e->counted_all = in->zones * MA_ZONE_BASE + e->records * MA_RECORD;
    }
    e->avg_zone = in->zones ? e->counted_all / in->zones : 0;
    e->directory = in->zones * MA_DIR_PER_ZONE;
    e->backend_all = MA_FIXED_ALL + in->zones * MA_RSS_ZONE_BASE + e->records * MA_RSS_RECORD;
    e->loader_all = MA_LOADER_FIXED + in->zones * MA_LOADER_ZONE_ALL;
    e->recommended = round_up(e->counted_all / 100 * MA_HEADROOM_PCT, MA_ROUND);
    e->working_min = round_up(e->counted_all / MA_HIGH_MARK_PCT * MA_WORKING_PCT, MA_ROUND);
    uint64_t need_zones = (in->fetch_conc > MA_MIN_FETCH_ZONES ? in->fetch_conc : MA_MIN_FETCH_ZONES) * MA_FETCH_FACTOR;
    e->fit_zones = (uint32_t)need_zones;
    e->fit_min = need_zones * e->avg_zone / MA_HIGH_MARK_PCT * 100;
    e->fit_pct = 100;
    if (in->limit == 0 || in->zones == 0) return;
    uint64_t fit = in->limit / 100 * MA_HIGH_MARK_PCT;
    e->fit_pct = e->counted_all == 0 || fit >= e->counted_all ? 100 : (uint32_t)(fit * 100 / e->counted_all);
    e->backend_limit = MA_FIXED_LIMIT + e->directory + (fit < e->counted_all ? fit : e->counted_all);
    e->loader_limit = MA_LOADER_FIXED + in->zones * MA_LOADER_ZONE_LIM;
    if (e->fit_pct >= 100) e->level = MA_LEVEL_INFO;
    else if (fit < need_zones * e->avg_zone) e->level = MA_LEVEL_ERROR;
    else if (e->fit_pct < MA_WORKING_PCT) e->level = MA_LEVEL_WARNING;
    else e->level = MA_LEVEL_NOTICE;
}

const char *ma_level_name(int level) {
    return level == MA_LEVEL_NOTICE ? "notice" : level == MA_LEVEL_WARNING ? "warning" : level == MA_LEVEL_ERROR ? "error" : "ok";
}

size_t ma_fmt_limit(char *buf, size_t n, uint64_t bytes) {
    int w;
    if (bytes >= (1ull << 30) && bytes % (1ull << 30) == 0) w = snprintf(buf, n, "%" PRIu64 "G", bytes >> 30);
    else if (bytes % (1ull << 20) == 0) w = snprintf(buf, n, "%" PRIu64 "M", bytes >> 20);
    else w = snprintf(buf, n, "%" PRIu64 "K", (uint64_t)((bytes + 1023) >> 10));
    return w < 0 ? 0 : (size_t)w < n ? (size_t)w : n ? n - 1 : 0;
}

size_t ma_fmt_size(char *buf, size_t n, uint64_t bytes) {
    int w;
    if (bytes >= (1ull << 30)) {
        uint64_t t = (uint64_t)(bytes * 10 / (1ull << 30));
        w = snprintf(buf, n, "%" PRIu64 ".%" PRIu64 " GB", t / 10, t % 10);
    } else if (bytes >= (1ull << 20)) {
        w = snprintf(buf, n, "%" PRIu64 " MB", (uint64_t)((bytes + (1ull << 19)) >> 20));
    } else if (bytes >= 1024) {
        w = snprintf(buf, n, "%" PRIu64 " KB", (bytes + 512) >> 10);
    } else {
        w = snprintf(buf, n, "%" PRIu64 " B", bytes);
    }
    return w < 0 ? 0 : (size_t)w < n ? (size_t)w : n ? n - 1 : 0;
}

static const char *basis_text(const ma_est_t *e, char *b, size_t n) {
    if (e->basis == MA_BASIS_RECORDS) snprintf(b, n, "%" PRIu64 " records counted in the database", e->records);
    else if (e->basis == MA_BASIS_RESIDENT) snprintf(b, n, "%" PRIu64 " B a zone on average, from the zones in memory", e->avg_zone);
    else snprintf(b, n, "assumed %d records a zone: the zones in memory are too few to tell", MA_ASSUMED_RECORDS);
    return b;
}

size_t ma_text_estimate(char *buf, size_t n, const ma_est_t *e) {
    char basis[120], data[32], be[32], ld[32], dir[32], lim[32], rec[32], bl[32], ll[32];
    ma_fmt_size(data, sizeof(data), e->counted_all);
    ma_fmt_size(be, sizeof(be), e->backend_all);
    ma_fmt_size(ld, sizeof(ld), e->loader_all);
    ma_fmt_size(dir, sizeof(dir), e->directory);
    ma_fmt_limit(rec, sizeof(rec), e->recommended);
    int w;
    if (!e->limit) {
        w = snprintf(buf, n, "memory sizing: %" PRIu64 " zone(s) (%s); with every zone in memory (no memory-limit) the Backend needs about %s (the zone data %s, the directory %s, "
                             "fixed part 35 MB) and the loader about %s; a memory-limit of %s would keep every zone in memory",
                     e->zones, basis_text(e, basis, sizeof(basis)), be, data, dir, ld, rec);
    } else {
        ma_fmt_limit(lim, sizeof(lim), e->limit);
        ma_fmt_size(bl, sizeof(bl), e->backend_limit);
        ma_fmt_size(ll, sizeof(ll), e->loader_limit);
        w = snprintf(buf, n, "memory sizing: %" PRIu64 " zone(s) (%s); every zone in memory needs a memory-limit of %s (zone data %s) and the Backend about %s, the loader about %s; "
                             "memory-limit %s keeps %u%% of the zones in memory, the Backend then needs about %s (fixed part 70 MB, directory %s, zone data up to the limit) and the loader about %s",
                     e->zones, basis_text(e, basis, sizeof(basis)), rec, data, be, ld, lim, e->fit_pct, bl, dir, ll);
    }
    return w < 0 ? 0 : (size_t)w < n ? (size_t)w : n ? n - 1 : 0;
}

size_t ma_text_advice(char *buf, size_t n, const ma_est_t *e) {
    char lim[32], rec[32], wm[32], fm[32], data[32], av[32];
    if (e->level == MA_LEVEL_INFO || !e->limit) {
        if (n) buf[0] = '\0';
        return 0;
    }
    ma_fmt_limit(lim, sizeof(lim), e->limit);
    ma_fmt_limit(rec, sizeof(rec), e->recommended);
    ma_fmt_limit(wm, sizeof(wm), e->working_min);
    ma_fmt_size(fm, sizeof(fm), e->fit_min);
    ma_fmt_size(av, sizeof(av), e->avg_zone);
    ma_fmt_size(data, sizeof(data), e->counted_all);
    int w;
    if (e->level == MA_LEVEL_ERROR)
        w = snprintf(buf, n, "memory-limit %s is too small: it cannot hold the zones of the reads that run at once (%u zones of about %s: %s), so nearly every query "
                             "for a database zone waits for a read of the database or is answered SERVFAIL (EDE 14); set memory-limit to at least %s, recommended %s (every zone in memory, %s of zone data)",
                     lim, e->fit_zones, av, fm, wm, rec, data);
    else if (e->level == MA_LEVEL_WARNING)
        w = snprintf(buf, n, "memory-limit %s keeps only %u%% of the %" PRIu64 " zones in memory (%s of zone data): unless the traffic is concentrated on a small part of them, most queries will "
                             "wait for a read of the database, and queries per second and latency suffer; set memory-limit to at least %s (half of the zones), recommended %s (every zone)",
                     lim, e->fit_pct, e->zones, data, wm, rec);
    else
        w = snprintf(buf, n, "memory-limit %s is below what every zone needs (%s of zone data): %u%% of the zones fit, and queries for the others wait for a read of the database; "
                             "recommended memory-limit %s (every zone in memory), at least %s keeps half of the zones",
                     lim, data, e->fit_pct, rec, wm);
    return w < 0 ? 0 : (size_t)w < n ? (size_t)w : n ? n - 1 : 0;
}

size_t ma_text_status(char *buf, size_t n, const ma_est_t *e) {
    char data[32], be[32], ld[32], rec[32], lim[32], wm[32], bl[32], ll[32], basis[120];
    ma_fmt_size(data, sizeof(data), e->counted_all);
    ma_fmt_size(be, sizeof(be), e->backend_all);
    ma_fmt_size(ld, sizeof(ld), e->loader_all);
    ma_fmt_limit(rec, sizeof(rec), e->recommended);
    ma_fmt_limit(wm, sizeof(wm), e->working_min);
    int w = snprintf(buf, n, "zones=%" PRIu64 " (%s) all_resident: zone_data=%s backend=%s loader=%s | ", e->zones, basis_text(e, basis, sizeof(basis)), data, be, ld);
    size_t l = w < 0 ? 0 : (size_t)w < n ? (size_t)w : n ? n - 1 : 0;
    if (e->limit) {
        ma_fmt_limit(lim, sizeof(lim), e->limit);
        ma_fmt_size(bl, sizeof(bl), e->backend_limit);
        ma_fmt_size(ll, sizeof(ll), e->loader_limit);
        w = snprintf(buf + l, n - l, "memory-limit=%s fit=%u%% backend=%s loader=%s | recommended=%s (half of the zones: at least %s) | status=%s", lim, e->fit_pct, bl, ll, rec, wm,
                     ma_level_name(e->level));
    } else {
        w = snprintf(buf + l, n - l, "no memory-limit | recommended=%s | status=%s", rec, ma_level_name(e->level));
    }
    return w < 0 ? l : l + ((size_t)w < n - l ? (size_t)w : n - l - 1);
}

/* ---------------------------------------------------------------- at run time */

bool ma_rt_report_due(ma_rt_t *st, const ma_est_t *e, bool event) {
    bool due = event || !st->reported || e->limit != st->rep_limit || e->level != st->rep_level || e->basis != st->rep_basis;
    if (!due) {
        uint64_t d = e->zones > st->rep_zones ? e->zones - st->rep_zones : st->rep_zones - e->zones;
        due = d * 100 >= (st->rep_zones ? st->rep_zones : 1) * MA_RELOG_PCT;
    }
    if (due) {
        st->reported = true;
        st->rep_zones = e->zones;
        st->rep_limit = e->limit;
        st->rep_level = e->level;
        st->rep_basis = e->basis;
    }
    return due;
}

static uint64_t delta(uint64_t now, uint64_t before) { return now >= before ? now - before : 0; }

int ma_rt_tick(ma_rt_t *st, const ma_rt_in_t *in, const ma_est_t *e, char *buf, size_t n) {
    if (!st->have_prev || in->now_ms < st->prev.now_ms) {
        st->prev = *in;
        st->have_prev = true;
        return 0;
    }
    int64_t dt = in->now_ms - st->prev.now_ms;
    if (dt < MA_WINDOW_MS) return 0;
    const ma_rt_in_t p = st->prev;
    st->prev = *in;
    if (!e->limit) return 0;                                   /* without a limit every zone is in memory: no query waits for a zone */
    uint64_t h[5], inst = 0;
    for (int i = 0; i < 5; i++) {
        h[i] = delta(in->hist[i], p.hist[i]);
        inst += h[i];
    }
    uint64_t misses = delta(in->misses, p.misses), refused = delta(in->refused, p.refused);
    uint64_t pfull = delta(in->park_full, p.park_full), ptime = delta(in->park_timeout, p.park_timeout);
    uint64_t over = refused + pfull + ptime;
    uint64_t inst_s = inst * 1000 / (uint64_t)dt;
    /* the fetch capacity: the least of what fetch-concurrency allows (concurrency / mean time of a fetch: the histogram's middle values, in 0.1 ms),
     * what the ingest thread can do (the rate it managed over the share of time it was busy) and fetch-rate */
    uint64_t cap = 0;
    uint32_t util = 0;
    if (inst >= MA_FIT_MIN_INSTALLS) {
        uint64_t tenths = (h[0] * 5 + h[1] * 50 + h[2] * 500 + h[3] * 5000 + h[4] * 20000) / inst;
        if (tenths == 0) tenths = 1;
        cap = in->concurrency ? (uint64_t)in->concurrency * 10000 / tenths : 0;
        if (in->busy_pct >= 10 && (cap == 0 || inst_s * 100 / in->busy_pct < cap)) cap = inst_s * 100 / in->busy_pct;
        if (in->fetch_rate && (cap == 0 || in->fetch_rate < cap)) cap = in->fetch_rate;
        if (cap) util = (uint32_t)(inst_s * 100 / cap > 999 ? 999 : inst_s * 100 / cap);
    }
    bool load = cap && util >= MA_UTIL_PCT;
    if (!load && over < MA_OVERLOAD_MIN) return 0;
    if (st->last_warn_ms && in->now_ms - st->last_warn_ms < MA_WARN_EVERY_MS) return 0;
    st->last_warn_ms = in->now_ms;
    char lim[32], rec[32], wm[32];
    ma_fmt_limit(lim, sizeof(lim), e->limit);
    ma_fmt_limit(rec, sizeof(rec), e->recommended);
    ma_fmt_limit(wm, sizeof(wm), e->working_min);
    int w = snprintf(buf, n, "memory-limit %s is too small for the traffic: in the last %" PRId64 " s %" PRIu64 " queries (%" PRIu64 "/s) had to wait for a zone that was not in memory and %" PRIu64
                             " zones (%" PRIu64 "/s) were read from the database", lim, dt / 1000, misses, misses * 1000 / (uint64_t)dt, inst, inst_s);
    size_t l = w < 0 ? 0 : (size_t)w < n ? (size_t)w : n ? n - 1 : 0;
    if (cap) {
        w = snprintf(buf + l, n - l, ", %u%% of the fetch capacity of about %" PRIu64 "/s (fetch-concurrency %u, ingest thread busy %u%%%s)", util, cap, in->concurrency, in->busy_pct,
                     in->fetch_rate ? ", fetch-rate set" : "");
        l += w < 0 ? 0 : (size_t)w < n - l ? (size_t)w : n - l - 1;
    }
    if (over) {
        w = snprintf(buf + l, n - l, "; %" PRIu64 " queries were answered SERVFAIL + EDE 14 for overload (park table full %" PRIu64 ", park-timeout %" PRIu64 ", refused %" PRIu64 ")", over, pfull, ptime, refused);
        l += w < 0 ? 0 : (size_t)w < n - l ? (size_t)w : n - l - 1;
    }
    snprintf(buf + l, n - l, "; the zones that are asked for do not fit: set memory-limit to at least %s (half of the zones), recommended %s (every zone in memory, %u%% fit now)", wm, rec, e->fit_pct);
    return LOG_WARNING;
}
