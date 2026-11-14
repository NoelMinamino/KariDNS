/*
 * test_mem_advice.c - dns_mem_advice.c (0.7 P-F): the memory a database needs, the thresholds of the sizing lines, and the run-time warning.
 *
 * Pure functions: the estimate from zone and record counts (the three bases), the share of zones that fit, the levels (INFO / NOTICE / WARNING / ERROR) and
 * their edges, the recommended memory-limit, the formatting of sizes and limits, the texts, the decision to say the lines again, and the run-time check
 * (fetch capacity from the histogram, the ingest thread's busy share and fetch-rate; SERVFAIL for overload; once a minute).  The figures are checked
 * against the W9 measurements the constants come from (docs/karidns.md "Memory by number of zones"): the estimate must be within the manual's 10% of them.
 */
#include "../dns_mem_advice.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

static int g_run, g_fail;
#define CHECK(cond, ...) do { g_run++; if (!(cond)) { g_fail++; fprintf(stderr, "[FAIL] line %d: ", __LINE__); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

static ma_in_t mk(uint64_t zones, uint64_t records, uint64_t limit) {
    ma_in_t in;
    memset(&in, 0, sizeof(in));
    in.zones = zones;
    in.have_records = true;
    in.records = records;
    in.limit = limit;
    in.fetch_conc = 16;
    return in;
}

static int within(uint64_t got, uint64_t want, unsigned pct) {
    uint64_t d = got > want ? got - want : want - got;
    return d * 100 <= want * pct;
}

static void test_w9_points(void) {
    ma_est_t e;
    ma_in_t in = mk(1000000, 11000000, 0);                       /* 1M small zones, every zone resident: 2,461 MB measured */
    ma_estimate(&in, &e);
    CHECK(e.basis == MA_BASIS_RECORDS && e.level == MA_LEVEL_INFO && e.fit_pct == 100, "1M small: basis %d level %d fit %u", e.basis, e.level, e.fit_pct);
    CHECK(within(e.backend_all, 2461ull << 20, 10), "1M small backend %llu MB", (unsigned long long)(e.backend_all >> 20));
    in = mk(100000, 9800000, 0);                                 /* 100k medium zones: 1,232 MB */
    ma_estimate(&in, &e);
    CHECK(within(e.backend_all, 1232ull << 20, 10), "100k medium backend %llu MB", (unsigned long long)(e.backend_all >> 20));
    in = mk(100000, 1100000, 0);                                 /* 100k small: 280 MB */
    ma_estimate(&in, &e);
    CHECK(within(e.backend_all, 280ull << 20, 10), "100k small backend %llu MB", (unsigned long long)(e.backend_all >> 20));
    in = mk(10000, 980000, 0);                                   /* 10k medium: 158 MB */
    ma_estimate(&in, &e);
    CHECK(within(e.backend_all, 158ull << 20, 12), "10k medium backend %llu MB", (unsigned long long)(e.backend_all >> 20));
    in = mk(100, 1100, 0);                                       /* 100 small: 36 MB */
    ma_estimate(&in, &e);
    CHECK(within(e.backend_all, 36ull << 20, 10), "100 small backend %llu MB", (unsigned long long)(e.backend_all >> 20));
    /* what the limit counts: 2.3 KB for a small zone, 11 KB for a medium one */
    in = mk(100000, 1100000, 0);
    ma_estimate(&in, &e);
    CHECK(within(e.avg_zone, 2300, 5), "small zone counts %llu B", (unsigned long long)e.avg_zone);
    in = mk(100000, 9800000, 0);
    ma_estimate(&in, &e);
    CHECK(within(e.avg_zone, 11260, 5), "medium zone counts %llu B", (unsigned long long)e.avg_zone);
    /* the loader: 213 MB at 1M zones without a limit, 635 MB with one */
    in = mk(1000000, 11000000, 1ull << 30);
    ma_estimate(&in, &e);
    CHECK(within(e.loader_all, 213ull << 20, 10), "loader without a limit %llu MB", (unsigned long long)(e.loader_all >> 20));
    CHECK(within(e.loader_limit, 635ull << 20, 10), "loader with a limit %llu MB", (unsigned long long)(e.loader_limit >> 20));
    /* the Backend under a limit of 1G: 1,409 MB measured at 1M small zones (the manual's formula: 70 MB + 0.45 KB x zones + resident) */
    CHECK(within(e.backend_limit, 1409ull << 20, 10), "1M small under 1G: Backend %llu MB", (unsigned long long)(e.backend_limit >> 20));
    CHECK(e.fit_pct >= 40 && e.fit_pct <= 45, "1M small under 1G: %u%% fit (432,041 of 1,000,000 in the measurement)", e.fit_pct);
}

static void test_bases(void) {
    ma_est_t e;
    ma_in_t in;
    memset(&in, 0, sizeof(in));
    in.zones = 1000;
    ma_estimate(&in, &e);                                        /* nothing known about the zones: assume 11 records */
    CHECK(e.basis == MA_BASIS_ASSUMED && e.records == 11000, "assumed: basis %d records %llu", e.basis, (unsigned long long)e.records);
    in.resident_zones = 50;                                      /* too few zones in memory to trust their size */
    in.resident_bytes = 50 * 20000;
    ma_estimate(&in, &e);
    CHECK(e.basis == MA_BASIS_ASSUMED, "50 zones in memory: still assumed (%d)", e.basis);
    in.resident_zones = 100;
    in.resident_bytes = 100 * 11270;                             /* medium zones */
    ma_estimate(&in, &e);
    CHECK(e.basis == MA_BASIS_RESIDENT && e.avg_zone == 11270 && e.counted_all == 11270000, "resident average: basis %d avg %llu all %llu", e.basis, (unsigned long long)e.avg_zone,
          (unsigned long long)e.counted_all);
    CHECK(within(e.records, 98000, 3), "records derived from the average: %llu", (unsigned long long)e.records);
    in.zones = 30;                                               /* every zone is in memory: the sample is the whole */
    in.resident_zones = 30;
    in.resident_bytes = 30 * 2300;
    ma_estimate(&in, &e);
    CHECK(e.basis == MA_BASIS_RESIDENT && e.counted_all == 30 * 2300, "all in memory: basis %d all %llu", e.basis, (unsigned long long)e.counted_all);
    in.resident_bytes = 30 * 600;                                /* an average below the base of a zone: no negative records */
    ma_estimate(&in, &e);
    CHECK(e.records == 0 && e.counted_all == 30 * 600, "tiny average: records %llu", (unsigned long long)e.records);
    in.have_records = true;                                      /* the real count wins */
    in.records = 5000;
    ma_estimate(&in, &e);
    CHECK(e.basis == MA_BASIS_RECORDS && e.records == 5000 && e.counted_all == 30 * MA_ZONE_BASE + 5000 * MA_RECORD, "counted: basis %d all %llu", e.basis, (unsigned long long)e.counted_all);
    in.zones = 0;
    in.have_records = false;
    in.resident_zones = 0;
    ma_estimate(&in, &e);
    CHECK(e.avg_zone == 0 && e.level == MA_LEVEL_INFO && e.fit_pct == 100, "no zones: avg %llu level %d", (unsigned long long)e.avg_zone, e.level);
    in = mk(0, 0, 64ull << 20);                                  /* a limit and no zone: nothing to say */
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_INFO && e.backend_limit == 0, "limit, no zones: level %d", e.level);
}

static void test_levels(void) {
    ma_est_t e;
    /* 1M small zones: counted_all about 2.2 GB, recommended 2.2 GB x 1.2 rounded up to 64 MB */
    ma_in_t in = mk(1000000, 11000000, 0);
    ma_estimate(&in, &e);
    uint64_t all = e.counted_all, rec = e.recommended;
    CHECK(rec >= all * 12 / 10 && rec < all * 12 / 10 + (64ull << 20) && rec % (64ull << 20) == 0, "recommended %llu for %llu", (unsigned long long)rec, (unsigned long long)all);
    CHECK(e.working_min >= all / 2 && e.working_min < all * 6 / 10 + (64ull << 20), "half of the zones: %llu for %llu", (unsigned long long)e.working_min, (unsigned long long)all);
    /* no limit: INFO */
    CHECK(e.level == MA_LEVEL_INFO && e.limit == 0 && e.backend_limit == 0, "no limit: level %d", e.level);
    /* the recommended limit holds everything: INFO */
    in = mk(1000000, 11000000, rec);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_INFO && e.fit_pct == 100, "recommended limit: level %d fit %u", e.level, e.fit_pct);
    /* the edge: the high mark of the limit is exactly what all zones count (95%) */
    in = mk(1000000, 11000000, all / 95 * 100 + 100);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_INFO, "limit at the high mark: level %d fit %u", e.level, e.fit_pct);
    in = mk(1000000, 11000000, all / 95 * 100 - 1000);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_NOTICE && e.fit_pct >= 99 && e.fit_pct < 100, "just below the high mark: level %d fit %u", e.level, e.fit_pct);
    /* 60% of the zones: NOTICE; 49%: WARNING (the edge is 50%) */
    in = mk(1000000, 11000000, all * 60 / 100 * 100 / 95);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_NOTICE && e.fit_pct >= 59 && e.fit_pct <= 60, "60%%: level %d fit %u", e.level, e.fit_pct);
    in = mk(1000000, 11000000, all * 50 / 100 * 100 / 95 + 1000);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_NOTICE && e.fit_pct == 50, "50%%: level %d fit %u", e.level, e.fit_pct);
    in = mk(1000000, 11000000, all * 49 / 100 * 100 / 95);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_WARNING && e.fit_pct <= 49, "49%%: level %d fit %u", e.level, e.fit_pct);
    /* the example of the user: 1M small zones, 512M: a warning, 23% fit */
    in = mk(1000000, 11000000, 512ull << 20);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_WARNING && e.fit_pct >= 20 && e.fit_pct <= 25, "512M: level %d fit %u", e.level, e.fit_pct);
    /* the limit cannot hold the zones of the reads in flight (4 x fetch-concurrency, at least 4 x 16 zones): ERROR.  Zones of 100,000 records are 10 MB each:
     * the smallest memory-limit (1M) cannot hold one */
    in = mk(1000, 1000ull * 100000, 0);
    ma_estimate(&in, &e);
    uint64_t zone64 = 64 * e.avg_zone;
    CHECK(e.fit_zones == 64 && e.avg_zone > 10000000, "big zones: fit_zones %u avg %llu", e.fit_zones, (unsigned long long)e.avg_zone);
    in.limit = 1ull << 20;
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_ERROR, "1M for 10 MB zones: level %d", e.level);
    in.limit = zone64 / 95 * 100 - 100000;
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_ERROR && e.fit_pct <= 7, "just below 64 zones: level %d fit %u", e.level, e.fit_pct);
    in.limit = zone64 / 95 * 100 + 100000;
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_WARNING && e.fit_pct >= 6, "just above 64 zones: level %d fit %u", e.level, e.fit_pct);
    in.fetch_conc = 256;                                         /* fetch-concurrency 256: 1024 zones */
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_ERROR && e.fit_zones == 1024 && e.fit_min > zone64 * 10, "fetch-concurrency 256: level %d fit_zones %u fit_min %llu", e.level, e.fit_zones, (unsigned long long)e.fit_min);
    in.fetch_conc = 0;                                           /* not known: the least */
    ma_estimate(&in, &e);
    CHECK(e.fit_zones == 64, "fetch-concurrency 0: %u zones", e.fit_zones);
    /* few zones: a small limit that holds them all is fine */
    in = mk(10, 110, 1ull << 20);
    ma_estimate(&in, &e);
    CHECK(e.level == MA_LEVEL_INFO, "10 zones in 1M: level %d", e.level);
    CHECK(strcmp(ma_level_name(MA_LEVEL_INFO), "ok") == 0 && strcmp(ma_level_name(MA_LEVEL_NOTICE), "notice") == 0 && strcmp(ma_level_name(MA_LEVEL_WARNING), "warning") == 0 &&
          strcmp(ma_level_name(MA_LEVEL_ERROR), "error") == 0, "level names");
}

static void test_format(void) {
    char b[64];
    ma_fmt_limit(b, sizeof(b), 2688ull << 20);
    CHECK(strcmp(b, "2688M") == 0, "limit 2688M: %s", b);
    ma_fmt_limit(b, sizeof(b), 4ull << 30);
    CHECK(strcmp(b, "4G") == 0, "limit 4G: %s", b);
    ma_fmt_limit(b, sizeof(b), (1ull << 20) + 1);
    CHECK(strcmp(b, "1025K") == 0, "limit rounds up to a K: %s", b);
    ma_fmt_limit(b, sizeof(b), 1800ull << 10);
    CHECK(strcmp(b, "1800K") == 0, "limit 1800K: %s", b);
    ma_fmt_limit(b, sizeof(b), 512ull << 20);
    CHECK(strcmp(b, "512M") == 0, "limit 512M: %s", b);
    ma_fmt_size(b, sizeof(b), 5ull << 29);
    CHECK(strcmp(b, "2.5 GB") == 0, "size 2.5 GB: %s", b);
    ma_fmt_size(b, sizeof(b), 36ull << 20);
    CHECK(strcmp(b, "36 MB") == 0, "size 36 MB: %s", b);
    ma_fmt_size(b, sizeof(b), 40 * 1024);
    CHECK(strcmp(b, "40 KB") == 0, "size 40 KB: %s", b);
    ma_fmt_size(b, sizeof(b), 700);
    CHECK(strcmp(b, "700 B") == 0, "size 700 B: %s", b);
    char tiny[6];                                                /* a buffer that is too small: cut, terminated, the length is what was written */
    size_t l = ma_fmt_size(tiny, sizeof(tiny), 5ull << 29);
    CHECK(l == 5 && strcmp(tiny, "2.5 G") == 0, "truncated size: %zu '%s'", l, tiny);
    l = ma_fmt_limit(tiny, sizeof(tiny), 123456ull << 20);
    CHECK(l <= 5 && strlen(tiny) == l, "truncated limit: %zu '%s'", l, tiny);
}

static void test_texts(void) {
    char t[1100];
    ma_est_t e;
    ma_in_t in = mk(1000000, 11000000, 0);
    ma_estimate(&in, &e);
    size_t l = ma_text_estimate(t, sizeof(t), &e);
    CHECK(l > 0 && strstr(t, "1000000 zone(s)") && strstr(t, "11000000 records counted") && strstr(t, "no memory-limit") && strstr(t, "would keep every zone"), "estimate, no limit: %s", t);
    CHECK(ma_text_advice(t, sizeof(t), &e) == 0 && t[0] == '\0', "no advice without a limit");
    l = ma_text_status(t, sizeof(t), &e);
    CHECK(l > 0 && strstr(t, "zones=1000000") && strstr(t, "no memory-limit") && strstr(t, "recommended=") && strstr(t, "status=ok"), "status, no limit: %s", t);
    in = mk(1000000, 11000000, 512ull << 20);
    ma_estimate(&in, &e);
    l = ma_text_estimate(t, sizeof(t), &e);
    CHECK(l > 0 && strstr(t, "memory-limit 512M keeps") && strstr(t, "% of the zones"), "estimate, limit: %s", t);
    l = ma_text_advice(t, sizeof(t), &e);
    CHECK(l > 0 && strstr(t, "keeps only") && strstr(t, "recommended") && strstr(t, "queries per second"), "advice, warning: %s", t);
    l = ma_text_status(t, sizeof(t), &e);
    CHECK(strstr(t, "memory-limit=512M") && strstr(t, "fit=") && strstr(t, "status=warning"), "status, limit: %s", t);
    in = mk(1000000, 11000000, e.counted_all * 70 / 100 * 100 / 95);
    ma_estimate(&in, &e);
    l = ma_text_advice(t, sizeof(t), &e);
    CHECK(l > 0 && strstr(t, "is below what every zone needs"), "advice, notice: %s", t);
    in = mk(1000, 1000ull * 100000, 1ull << 20);                 /* zones of 10 MB: the smallest limit holds none */
    ma_estimate(&in, &e);
    l = ma_text_advice(t, sizeof(t), &e);
    CHECK(l > 0 && strstr(t, "is too small") && strstr(t, "SERVFAIL (EDE 14)"), "advice, error: %s", t);
    in = mk(1000000, 0, 0);
    in.have_records = false;
    ma_estimate(&in, &e);
    ma_text_estimate(t, sizeof(t), &e);
    CHECK(strstr(t, "assumed 11 records a zone"), "assumed basis in the text: %s", t);
    in.resident_zones = 1000;
    in.resident_bytes = 1000 * 2300;
    ma_estimate(&in, &e);
    ma_text_estimate(t, sizeof(t), &e);
    CHECK(strstr(t, "B a zone on average, from the zones in memory"), "resident basis in the text: %s", t);
    char small[40];                                              /* truncation never overruns and always terminates */
    l = ma_text_estimate(small, sizeof(small), &e);
    CHECK(l == sizeof(small) - 1 && strlen(small) == l, "estimate cut: %zu", l);
    l = ma_text_status(small, sizeof(small), &e);
    CHECK(strlen(small) == l && l <= sizeof(small) - 1, "status cut: %zu", l);
    in = mk(1000, 1000ull * 100000, 1ull << 20);
    ma_estimate(&in, &e);
    l = ma_text_advice(small, sizeof(small), &e);
    CHECK(strlen(small) == l && l <= sizeof(small) - 1, "advice cut: %zu", l);
    l = ma_text_status(small, sizeof(small), &e);
    CHECK(strlen(small) == l && l <= sizeof(small) - 1, "status (limit) cut: %zu", l);
}

static void test_report_due(void) {
    ma_rt_t st;
    memset(&st, 0, sizeof(st));
    ma_est_t e;
    ma_in_t in = mk(1000, 11000, 0);
    ma_estimate(&in, &e);
    CHECK(ma_rt_report_due(&st, &e, false), "the first time");
    CHECK(!ma_rt_report_due(&st, &e, false), "nothing moved");
    CHECK(ma_rt_report_due(&st, &e, true), "an event says it again");
    in = mk(1050, 11550, 0);                                     /* +5%: not enough */
    ma_estimate(&in, &e);
    CHECK(!ma_rt_report_due(&st, &e, false), "5%% more zones");
    in = mk(1100, 12100, 0);                                     /* +10%: enough */
    ma_estimate(&in, &e);
    CHECK(ma_rt_report_due(&st, &e, false), "10%% more zones");
    in = mk(1100, 12100, 8ull << 20);                            /* a limit: changed */
    ma_estimate(&in, &e);
    CHECK(ma_rt_report_due(&st, &e, false), "the limit changed");
    in.limit = 16ull << 20;
    ma_estimate(&in, &e);
    CHECK(ma_rt_report_due(&st, &e, false), "the limit changed again");
    in = mk(1100, 12100, 64ull << 10);                           /* the level moved (to ERROR) with the same zones */
    ma_estimate(&in, &e);
    ma_rt_report_due(&st, &e, false);
    ma_in_t in2 = mk(1100, 12100, 64ull << 10);
    in2.have_records = false;                                    /* the basis moved */
    ma_est_t e2;
    ma_estimate(&in2, &e2);
    CHECK(ma_rt_report_due(&st, &e2, false), "the basis changed");
    ma_rt_t st2;
    memset(&st2, 0, sizeof(st2));
    ma_in_t in3 = mk(1000, 11000, 1ull << 30);
    ma_estimate(&in3, &e);
    ma_rt_report_due(&st2, &e, false);
    ma_in_t in4 = mk(1000, 11000, 1ull << 30);
    in4.limit = 1ull << 30;
    in4.zones = 1000;
    in4.records = 11000000000ull;                                /* the same limit and zones, but the zones got huge: the level moved */
    ma_estimate(&in4, &e);
    CHECK(ma_rt_report_due(&st2, &e, false), "the level changed: %d", e.level);
    ma_est_t z;
    in = mk(0, 0, 0);
    ma_rt_t st3;
    memset(&st3, 0, sizeof(st3));
    ma_estimate(&in, &z);
    CHECK(ma_rt_report_due(&st3, &z, false), "zero zones the first time");
    CHECK(!ma_rt_report_due(&st3, &z, false), "zero zones again (no division by zero)");
}

static ma_rt_in_t rt0(int64_t now) {
    ma_rt_in_t in;
    memset(&in, 0, sizeof(in));
    in.now_ms = now;
    in.concurrency = 16;
    return in;
}

static void test_runtime(void) {
    char t[1100];
    ma_est_t e;
    ma_in_t ein = mk(1000000, 11000000, 256ull << 20);
    ma_estimate(&ein, &e);
    ma_rt_t st;
    memset(&st, 0, sizeof(st));
    ma_rt_in_t a = rt0(1000);
    CHECK(ma_rt_tick(&st, &a, &e, t, sizeof(t)) == 0, "the first call only takes the start of the window");
    a = rt0(5000);
    a.park_timeout = 1000;
    CHECK(ma_rt_tick(&st, &a, &e, t, sizeof(t)) == 0, "the window is not over");
    /* a quiet window: 30 fetches/s of 1 ms, nothing refused: no warning */
    a = rt0(11000);
    a.hist[0] = 300;
    a.misses = 400;
    a.issued = 300;
    a.busy_pct = 5;
    CHECK(ma_rt_tick(&st, &a, &e, t, sizeof(t)) == 0, "a quiet window");
    /* the fetches use the capacity: 1,800 in 10 s of 10..100 ms with 16 in flight: 16 / 0.05 s = 320/s, 180/s is 56%; at 3,000 it is 94% */
    ma_rt_in_t b = rt0(21000);
    b.hist[0] = a.hist[0];
    b.hist[2] = 3000;
    b.misses = a.misses + 5000;
    b.busy_pct = 20;
    int p = ma_rt_tick(&st, &b, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING, "capacity used: priority %d", p);
    CHECK(strstr(t, "memory-limit 256M is too small for the traffic") && strstr(t, "5000 queries") && strstr(t, "3000 zones") && strstr(t, "fetch capacity of about") && strstr(t, "recommended"),
          "capacity warning text: %s", t);
    CHECK(strstr(t, "%% of the fetch capacity") == NULL && strstr(t, "% of the fetch capacity"), "the share is said: %s", t);
    CHECK(strstr(t, "SERVFAIL") == NULL, "no SERVFAIL when nothing was refused: %s", t);
    /* at most once a minute while it lasts */
    ma_rt_in_t c = b;
    for (int64_t now = 31000; now <= 71000; now += 10000) {       /* 10, 20 ... 50 s after the warning: the same load, not said again */
        c.now_ms = now;
        c.hist[2] += 3000;
        CHECK(ma_rt_tick(&st, &c, &e, t, sizeof(t)) == 0, "%lld s after the warning: not said again", (long long)(now - 21000) / 1000);
    }
    c.now_ms = 82000;
    c.hist[2] += 3000;
    p = ma_rt_tick(&st, &c, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING, "61 s later: said again (%d)", p);
    /* overload: queries answered SERVFAIL + EDE 14, even when the capacity is not used up */
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.park_timeout = 7;
    b.park_full = 2;
    b.refused = 1;                                               /* 10 in all */
    p = ma_rt_tick(&st, &b, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING && strstr(t, "10 queries were answered SERVFAIL + EDE 14") && strstr(t, "park table full 2") && strstr(t, "park-timeout 7") && strstr(t, "refused 1") &&
          strstr(t, "fetch capacity") == NULL, "overload text: %d %s", p, t);
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.park_timeout = MA_OVERLOAD_MIN - 1;
    CHECK(ma_rt_tick(&st, &b, &e, t, sizeof(t)) == 0, "one below the overload threshold");
    /* the capacity from fetch-rate and from the ingest thread's busy share, and the text of both */
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    a.concurrency = 256;
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.concurrency = 256;
    b.hist[0] = 1500;                                            /* 150/s of 0.5 ms: concurrency would allow 256 / 0.0005 = 512,000/s */
    b.fetch_rate = 200;                                          /* but fetch-rate is 200/s: 75% */
    p = ma_rt_tick(&st, &b, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING && strstr(t, "75% of the fetch capacity of about 200/s") && strstr(t, "fetch-rate set"), "fetch-rate is the capacity: %d %s", p, t);
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    a.concurrency = 256;
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.concurrency = 256;
    b.hist[0] = 4000;                                            /* 400/s, the ingest thread was busy 80% of the time: it can do 500/s, so this is 80% */
    b.busy_pct = 80;
    p = ma_rt_tick(&st, &b, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING && strstr(t, "80% of the fetch capacity of about 500/s") && strstr(t, "ingest thread busy 80%"), "the ingest thread is the capacity: %d %s", p, t);
    /* too few fetches to judge the capacity, no overload: nothing */
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.hist[4] = MA_FIT_MIN_INSTALLS - 1;
    b.busy_pct = 100;
    CHECK(ma_rt_tick(&st, &b, &e, t, sizeof(t)) == 0, "too few fetches to judge");
    /* concurrency 0 (not known) and no busy share: no capacity, but the overload is still said; the text has no capacity */
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    a.concurrency = 0;
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.concurrency = 0;
    b.hist[3] = 100;
    b.park_timeout = 50;
    p = ma_rt_tick(&st, &b, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING && strstr(t, "fetch capacity") == NULL && strstr(t, "50 queries"), "no capacity known: %d %s", p, t);
    /* a very slow fetch (the last bucket): the capacity is concurrency / 2 s */
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.hist[4] = 100;                                             /* 10/s of 2 s with 16 in flight: capacity 8/s, used 125% */
    p = ma_rt_tick(&st, &b, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING && strstr(t, "125% of the fetch capacity of about 8/s"), "slow fetches: %d %s", p, t);
    /* an extreme rate does not overflow the share */
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.hist[4] = 1000000;
    p = ma_rt_tick(&st, &b, &e, t, sizeof(t));
    CHECK(p == LOG_WARNING && strstr(t, "999% of the fetch capacity"), "share capped: %d %s", p, t);
    /* without a limit every zone is in memory: nothing is said at run time */
    ma_est_t nl;
    ma_in_t nin = mk(1000000, 11000000, 0);
    ma_estimate(&nin, &nl);
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    ma_rt_tick(&st, &a, &nl, t, sizeof(t));
    b = rt0(10000);
    b.park_timeout = 1000;
    CHECK(ma_rt_tick(&st, &b, &nl, t, sizeof(t)) == 0, "no limit: nothing at run time");
    /* the clock going back starts a new window */
    memset(&st, 0, sizeof(st));
    a = rt0(50000);
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(1000);
    b.park_timeout = 1000;
    CHECK(ma_rt_tick(&st, &b, &e, t, sizeof(t)) == 0, "the clock went back: a new window");
    /* the counters going back (a restart of a counter) are not negative rates */
    b = rt0(12000);
    b.park_timeout = 0;
    CHECK(ma_rt_tick(&st, &b, &e, t, sizeof(t)) == 0, "no negative deltas");
    /* a buffer that is too small: cut and terminated */
    memset(&st, 0, sizeof(st));
    a = rt0(0);
    ma_rt_tick(&st, &a, &e, t, sizeof(t));
    b = rt0(10000);
    b.park_timeout = 100;
    b.hist[2] = 1000;
    char small[60];
    p = ma_rt_tick(&st, &b, &e, small, sizeof(small));
    CHECK(p == LOG_WARNING && strlen(small) < sizeof(small), "cut text: %s", small);
}

int main(void) {
    test_w9_points();
    test_bases();
    test_levels();
    test_format();
    test_texts();
    test_report_due();
    test_runtime();
    printf("test_mem_advice: %d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
