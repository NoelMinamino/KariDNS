#ifndef DNS_MEM_ADVICE_H
#define DNS_MEM_ADVICE_H

/*
 * dns_mem_advice.h - how much memory a database needs, and what to say about memory-limit (0.7 P-F, planning "how database zones are served", 5).
 *
 * Pure functions, no I/O and no logging: the server (dns_db_ingest.c) says the lines in syslog, `karictl dbstatus` shows the figures, and
 * `karicheck db` (through the `M` line of the loader's check protocol) says the same about a database before the server runs.  Everything
 * here is computed from the number of zones and records; the constants come from the measurements of W9 (docs/karidns.md, "Memory by
 * number of zones" and "With memory-limit": FreeBSD 15.1 amd64, jemalloc, SQLite3, zones of 11 and of 98 records, 100,000 and 1,000,000 zones).
 *
 * Two sizes are told apart, because the manual says memory-limit is not a limit on the process:
 *   counted  what memory-limit counts: the zones in memory (version, image, glue, IXFR differences and the zone's entry, 0.7).  The unit of
 *            the share of zones that fit, and of the recommended memory-limit.
 *   backend  the resident size of the Backend (`ps -o rss`): the fixed part, the directory of every zone, and the counted bytes.
 * The loader is a separate process on top.
 *
 * The thresholds (all in dns_mem_advice.c; the manual repeats them):
 *   INFO     always: the estimate.  Without memory-limit it is all there is.
 *   NOTICE   memory-limit is below what all zones need (counted / 0.95: the cache manager takes zones out above 95% of the limit): some queries
 *            wait for a read of the database.
 *   WARNING  memory-limit keeps less than half of the zones: unless the traffic is much more skewed than the zones, most queries wait, and the
 *            fetch capacity (a few thousand zones a second) is what the server's speed depends on.
 *   ERROR    memory-limit cannot hold the zones of fetch-concurrency reads at once: nearly every query for a database zone waits or is refused.
 *
 * The default (0.7.x, docs/karidns.md "Memory limit"): a database block with the zone store and without memory-limit gets one derived from the RAM, half of
 * what is above MA_DEFAULT_RESERVE, at least MA_DEFAULT_MIN (ma_default_limit()); without the store (`store none`) it keeps none, as before; `memory-limit unlimited;` keeps every zone in memory as before.  The server reads
 * hw.physmem before the sandbox, karicheck on the host it runs on (ma_host_ram(), the one function of this file that asks the system).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ---- the constants, in bytes (W9) ---- */
#define MA_FIXED_ALL        (35ull << 20)   /* the Backend without memory-limit, before any zone: 36 MB at 100 zones (W9 table 1) */
#define MA_FIXED_LIMIT      (70ull << 20)   /* with memory-limit: the park tables, the fetch rings and the threads' buffers (the formula of the manual) */
#define MA_DIR_PER_ZONE     460ull          /* the directory entry of a zone that is not in memory: 0.45 KB (the formula of the manual: 70 MB + 0.45 KB x zones + resident) */
#define MA_ZONE_BASE        1170ull         /* counted bytes of a zone in memory, without its records: 2.2 KB at 11 records, 11 KB at 98 records (W9 table 2, 100k and 1M zones) */
#define MA_RECORD           103ull          /* ... and per record */
#define MA_RSS_ZONE_BASE    1280ull         /* resident bytes of the Backend per zone when every zone is in memory (no limit), without records: 2.44 KB at 11 records */
#define MA_RSS_RECORD       115ull          /* ... and per record: 12 KB at 98 records (W9 table 1: 2,461 MB at 1M small zones, 1,232 MB at 100k medium) */
#define MA_LOADER_FIXED     (30ull << 20)   /* karidns-dbloader: 54 MB at 100k zones, 213 MB at 1M without a limit; 635 MB at 1M with one (summaries of every zone) */
#define MA_LOADER_ZONE_ALL  180ull          /* per zone, no memory-limit (it streams) */
#define MA_LOADER_ZONE_LIM  600ull          /* per zone, with memory-limit (it holds the summaries) */
#define MA_ASSUMED_RECORDS  11              /* the zone the sizes are for when nothing says otherwise: SOA, 2 NS, A, MX, 6 A hosts */
/* With the zone store (0.7; measured at 10,000,000 zones, 1,100,000 attached): the loader streams and keeps no table of the zones, 22 MB resident at most; the directory is the store's
 * tables (zt, zc, ix, sx: 1.96 GB at 10M zones, file pages, not heap); in MAP mode the image of an attached zone is a file page too (1,152 of the 2,308 counted bytes of a small zone). */
#define MA_LOADER_STORE     (20ull << 20)
#define MA_STORE_TABLE_PER_ZONE 200ull      /* zt + zc + ix + sx per zone (file pages of the store, 196 B measured) */
#define MA_STORE_IMAGE_PCT  50              /* the share of a zone's counted bytes that is its image, when the store has not said (1,152 of 2,308 B) */
#define MA_HIGH_MARK_PCT    95              /* the cache manager takes zones out above this share of memory-limit */
#define MA_HEADROOM_PCT     120             /* the recommended memory-limit: counted x 1.2 (1 / 0.95 for the high mark, x 1.1 for the zones a batch changes: manual, "The limit is a target") */
#define MA_WORKING_PCT      50              /* WARNING below this share of the zones in memory */
#define MA_ROUND            (64ull << 20)   /* a recommended memory-limit is rounded up to a multiple of this */
#define MA_SAMPLE_ZONES     100             /* the average size of the zones in memory is trusted from this many zones (or when every zone is in memory) */
#define MA_MIN_FETCH_ZONES  16              /* ERROR: the limit must hold the zones of the reads in flight: fetch-concurrency (at least this many) ... */
#define MA_FETCH_FACTOR     4               /* ... times this (a read takes room before the manager makes it, and a zone that came in is kept for 100 ms) */
/* the default memory-limit (0.7.x small-VPS defaults): (RAM - reserve) / 2, at least MA_DEFAULT_MIN, rounded down to a MiB.  512 MB of RAM: 128M; 1 GB: 384M; 16 GB: about 7.9G
 * (the 1B run on a 16 GB host: memory-limit 8G kept the Backend at 10.3 GB beside a 4 GB ARC, 11G was the highest that did not swap; without a limit the Backend grew to 14.7 GB in 70 s).
 * RAM not known: as for 1 GB. */
#define MA_DEFAULT_RESERVE  (256ull << 20)  /* the kernel, the other processes, the routers, the loader and the zones of karidns.conf on a small host */
#define MA_DEFAULT_MIN      (64ull << 20)
#define MA_DEFAULT_RAM_UNKNOWN (1ull << 30)

enum { MA_BASIS_ASSUMED = 0, MA_BASIS_RESIDENT, MA_BASIS_RECORDS, MA_BASIS_STORE };
enum { MA_STORE_NONE = 0, MA_STORE_MAP, MA_STORE_COPY };       /* ma_in_t.store_mode */
enum { MA_LEVEL_INFO = 0, MA_LEVEL_NOTICE, MA_LEVEL_WARNING, MA_LEVEL_ERROR };

typedef struct {
    uint64_t zones;             /* zones of the database (the directory) */
    bool have_records;          /* records is the real number (the database was counted: karicheck db) */
    uint64_t records;
    uint64_t resident_zones;    /* the zones whose data is in memory, and the counted bytes of them (the server) */
    uint64_t resident_bytes;
    uint64_t limit;             /* memory-limit, 0 = none */
    uint32_t fetch_conc;        /* fetch-concurrency in force (0 = MA_MIN_FETCH_ZONES) */
    int store_mode;             /* MA_STORE_*: the zone store (0.7) keeps the zones that are not in memory; MAP maps the images of the zones in memory, COPY reads them into the heap */
    uint64_t stored_zones;      /* the zones with an image in the store and the bytes of those images (the store counts them: the size of a zone without reading a record) */
    uint64_t stored_image_bytes;
    bool limit_default;         /* the limit is the default from the RAM (memory-limit not written) */
    uint64_t ram;               /* the RAM it was derived from (bytes; 0 = not known) */
} ma_in_t;

typedef struct {
    int basis;                  /* where the size of a zone comes from: MA_BASIS_* */
    uint64_t zones, records;    /* records: the number used (the basis says how it was found) */
    uint64_t counted_all;       /* what memory-limit would count with every zone in memory */
    uint64_t avg_zone;          /* counted_all / zones */
    uint64_t backend_all;       /* the Backend with every zone in memory (no limit); with the store: its heap (the mapped file pages are `mapped`) */
    uint64_t loader_all;        /* the loader without memory-limit */
    uint64_t directory;         /* the directory alone (heap; with the store it is the store's tables: `tables`, file pages) */
    bool copy_mode;             /* with the store: COPY mode (the images of the zones in memory are heap; MAP maps them) */
    uint64_t tables;            /* the store's tables: file pages that the kernel keeps (page cache), not heap */
    uint64_t mapped;            /* every file page the Backend maps for the zones: the tables, and in MAP mode the images of the zones in memory */
    uint64_t recommended;       /* memory-limit that keeps every zone in memory, rounded up to MA_ROUND */
    uint64_t working_min;       /* memory-limit that keeps MA_WORKING_PCT of the zones */
    uint64_t fit_min;           /* memory-limit below which the ERROR is said */
    uint32_t fit_zones;         /* the zones the limit must hold at the least */
    uint64_t limit;             /* memory-limit in force, 0 = none */
    uint32_t fit_pct;           /* share of the zones that fit under the limit (100 without a limit) */
    uint64_t backend_limit;     /* the Backend under the limit (0 without a limit) */
    uint64_t loader_limit;      /* the loader under the limit (0 without a limit) */
    int level;                  /* MA_LEVEL_* (always INFO without a limit) */
    bool limit_default;         /* from ma_in_t: the limit is the default from the RAM */
    uint64_t ram;
} ma_est_t;

void ma_estimate(const ma_in_t *in, ma_est_t *out);

/* The default memory-limit for `ram` bytes of RAM (0 = not known: MA_DEFAULT_RAM_UNKNOWN), and the limit in force for a database block: `configured` when it is set
 * (not 0), 0 (no limit) for `memory-limit unlimited` and for a database without the zone store (`store none`: a limit there makes the loader
 * send every zone the Backend does not have as a summary, so a start would read no zone until a query asks for it), else the default (*is_default true).  ma_host_ram(): hw.physmem, 0 when it cannot be read (or not on FreeBSD). */
uint64_t ma_default_limit(uint64_t ram);
uint64_t ma_effective_limit(uint64_t configured, bool unlimited, bool store, uint64_t ram, bool *is_default);
uint64_t ma_host_ram(void);
/* the start line of the server and the information line of karicheck: "memory-limit is not set: 384M is used (half of the 1.0 GB of RAM above 256 MB) ..." */
size_t ma_text_default(char *buf, size_t n, uint64_t limit, uint64_t ram);

/* "512M", "3G", "2688M": a value memory-limit accepts (K, M, G suffix), the exact value when it is a multiple of 1 MiB */
size_t ma_fmt_limit(char *buf, size_t n, uint64_t bytes);
/* "36 MB", "2.5 GB" for the text of a message */
size_t ma_fmt_size(char *buf, size_t n, uint64_t bytes);
/* the INFO sentence (always) and the advice sentence (level above INFO; 0 bytes written when there is nothing to advise) */
size_t ma_text_estimate(char *buf, size_t n, const ma_est_t *e);
size_t ma_text_advice(char *buf, size_t n, const ma_est_t *e);
/* the `memory:` line of `karictl dbstatus` (without the label) */
size_t ma_text_status(char *buf, size_t n, const ma_est_t *e);
const char *ma_level_name(int level);       /* "ok", "notice", "warning", "error" */

/* ---- ZFS (0.7 store design 3.6) ---- */
/* On ZFS the images are read with pread() and the ARC is the cache of the store: the Backend's heap, the ARC (vfs.zfs.arc.max), the loader and about a gigabyte for the rest
 * of the system have to fit in RAM together.  The Backend cannot read kstat / sysctl values in capability mode: karictl (and karicheck) read vfs.zfs.arc.max and hw.physmem
 * on the host and call this. */
#define MA_ARC_OTHER        (1ull << 30)    /* the system, the page cache of the rest, the jails' share: 1 GB */
#define MA_ARC_NOTICE_PCT   85              /* NOTICE above this share of RAM */
typedef struct {
    uint64_t backend, arc_max, loader, other;   /* the parts of the sum, bytes */
    uint64_t total, ram;
    uint64_t arc_fit;           /* the largest vfs.zfs.arc.max that fits (0 when the rest alone does not fit) */
    uint32_t pct;               /* total / ram, percent (0 when ram is not known) */
    int level;                  /* MA_LEVEL_INFO, NOTICE (above MA_ARC_NOTICE_PCT), WARNING (above RAM) */
} ma_arc_t;
void ma_arc_sum(uint64_t backend_heap, uint64_t arc_max, uint64_t loader, uint64_t ram, ma_arc_t *out);
size_t ma_text_arc(char *buf, size_t n, const ma_arc_t *a);

/* ---- at run time ---- */
#define MA_WINDOW_MS        10000           /* the span the rates are computed over */
#define MA_WARN_EVERY_MS    60000           /* a warning is repeated at most this often while the condition lasts */
#define MA_UTIL_PCT         70              /* WARNING when the fetches use this share of the fetch capacity ... */
#define MA_OVERLOAD_MIN     10              /* ... or this many queries in a window got SERVFAIL + EDE 14 because of overload */
#define MA_RELOG_PCT        10              /* the inventory is said again when the zone count moved by this much */
#define MA_FIT_MIN_INSTALLS 20              /* the capacity is not judged from fewer fetches in a window */

typedef struct {
    int64_t now_ms;
    uint64_t hist[5];           /* fetches installed, by time to install: <=1 ms, <=10 ms, <=100 ms, <=1 s, more (cumulative since the start) */
    uint64_t issued, misses;    /* cumulative: zones fetched, queries that had to wait for a zone */
    uint64_t refused;           /* cumulative: fetches not made (fetch-rate, fetch-concurrency, the limit): the query got "not ready" */
    uint64_t park_full, park_timeout;   /* cumulative: queries not parked (table full), parked queries that ran out of park-timeout */
    uint32_t concurrency;       /* fetch-concurrency in force */
    uint32_t fetch_rate;        /* fetch-rate in force, 0 = no rate limit */
    uint32_t busy_pct;          /* the ingest thread's busy share of its last window */
} ma_rt_in_t;

typedef struct {
    bool have_prev;
    ma_rt_in_t prev;            /* the start of the window */
    int64_t last_warn_ms;       /* 0 = never */
    bool reported;              /* the inventory line was said once */
    uint64_t rep_zones, rep_limit;
    int rep_level, rep_basis;
} ma_rt_t;

/* Should the sizing lines be said now?  First time, after a change of memory-limit or of the level, when the basis became the measured one,
 * or when the zone count moved by MA_RELOG_PCT; `event` (a start, a reload) says them whatever else.  Remembers what it said when it returns true. */
bool ma_rt_report_due(ma_rt_t *st, const ma_est_t *e, bool event);
/* Called often (every 50 ms is fine; it does the work once a window).  Returns 0 (nothing to say) or a syslog priority and the text in buf:
 * LOG_WARNING when the fetches use MA_UTIL_PCT of what the server can fetch, or MA_OVERLOAD_MIN queries of the window were answered
 * SERVFAIL + EDE 14 because of overload.  At most once a MA_WARN_EVERY_MS. */
int ma_rt_tick(ma_rt_t *st, const ma_rt_in_t *in, const ma_est_t *e, char *buf, size_t n);

#endif
