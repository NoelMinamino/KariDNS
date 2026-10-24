#ifndef DNS_DB_DRIVER_H
#define DNS_DB_DRIVER_H

/*
 * dns_db_driver.h - the database driver interface of karidns-dbloader (beta design 2.1, 2.2, 3.1; milestone B3).
 *
 * A driver reads the PowerDNS 5.1 tables and hands the rows to callbacks, nothing else.  Everything after the rows are
 * read (content parser, metadata mapping, NSEC3 rebuild, stream encoding) is shared and driver independent
 * (dns_pdns_reader.h), so two drivers give identical output by construction.  Ordinary process code (malloc allowed,
 * CLAUDE.md Rules 1-2 do not apply); every byte of every row is untrusted database content.
 *
 * Row structs (db_zone_row_t, db_record_row_t, db_meta_row_t, db_change_row_t) are defined in dns_pdns_reader.h.
 *
 * Contract
 *   - Every string of a row is a NUL-terminated C string that is valid until the callback returns (zero copy from
 *     sqlite3_column_text() / PQgetvalue()); a callback that keeps a string copies it.  A SQL NULL is a NULL pointer.
 *   - A driver rejects a value with an embedded NUL (sqlite3_column_bytes() != strlen()) as an error that names the
 *     table and the row id; the callback is not called for that row.  (The reader works on C strings.)
 *   - Names are never compared with SQL collations by the callers: only the C side decides what belongs to a zone.
 *   - Callbacks return 0 to go on, non-zero to stop the scan.  Callbacks must not call the same connection
 *     (a scan in progress owns it; a PostgreSQL single-row-mode result cannot be interleaved).
 *   - Return values of every function that can fail: 0 = done; DB_STOPPED = the callback stopped the scan; -1 = error
 *     (db_errmsg() says why, one line, no row data beyond table and id); DB_ERR_RETRY = a transient condition (SQLite
 *     SQLITE_BUSY after the busy timeout, PostgreSQL connection loss): the loader backs off and retries the batch;
 *     DB_ERR_UNAVAILABLE = the source does not offer the feature (changes_since without karidns_changes).
 *   - A connection is used by one thread at a time.  The connection is read only (the loader never writes).
 *
 * Call order: open, check_schema, begin_snapshot, (list_zones | scan_* | zones_with_keys | changes_since)*,
 * end_snapshot, close.  Everything read between begin_snapshot() and end_snapshot() is one consistent state (a WAL read
 * transaction on SQLite3, REPEATABLE READ on PostgreSQL), so a zone is never half written.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dns_pdns_reader.h"

#define DB_STOPPED 1
#define DB_ERR_RETRY (-2)
#define DB_ERR_UNAVAILABLE (-3)
#define DB_ERRLEN 400

/* Where the data is.  Paths are UTF-8, used byte for byte: '%XX' is not decoded and a SQLite3 path is never read as a
 * URI (a path that starts with "file:" is refused). */
typedef struct {
    const char *driver;             /* "sqlite3", "postgresql" */
    const char *database_file;      /* sqlite3: the database file */
    const char *conninfo_file;      /* postgresql: file holding the libpq conninfo (B10) */
    const char *schema;             /* postgresql: schema name (B10) */
    unsigned busy_timeout_ms;       /* 0 = 5000 */
} db_source_t;

/* What check_schema() found.  Missing PowerDNS tables or columns are an error, not a flag. */
typedef struct {
    bool has_changes;               /* karidns_changes exists (created by the B6 DDL) */
    bool has_domain_views;          /* karidns_domain_views exists (B6b, design 3.7, 7.1) */
    bool has_profiles;              /* karidns_profiles exists (B7a, design 3.7) */
    bool has_ext;                   /* karidns_record_tags, karidns_record_tinydns and karidns_zone_tagdefs exist (B8, design 3.7) */
} db_schema_info_t;

/* PostgreSQL only: written to karidns_server_status (B11).  SQLite3 ignores it. */
typedef struct {
    uint64_t generation;
    bool ok;
    const char *failed_zones;
} db_status_t;

typedef struct db_conn db_conn_t;   /* opaque, one per source (view file / schema) */

typedef int (*db_zone_cb)(void *ud, const db_zone_row_t *row);
typedef int (*db_record_cb)(void *ud, int64_t domain_id, const db_record_row_t *row);
typedef int (*db_meta_cb)(void *ud, const db_meta_row_t *row);
typedef int (*db_key_cb)(void *ud, int64_t domain_id);
typedef int (*db_change_cb)(void *ud, const db_change_row_t *row);
typedef int (*db_domain_view_cb)(void *ud, int64_t domain_id, const char *view_name);
typedef struct { const char *name, *settings; } db_profile_row_t;       /* one row of karidns_profiles */
typedef int (*db_profile_cb)(void *ud, const db_profile_row_t *row);
/* B8: the three extension tables, one callback each.  domain_id is the zone of the row (records.domain_id for the record tables). */
typedef struct {
    int (*record_tags)(void *ud, int64_t domain_id, const db_tag_row_t *row);
    int (*record_tinydns)(void *ud, int64_t domain_id, const db_tinydns_row_t *row);
    int (*tagdef)(void *ud, int64_t domain_id, const db_tagdef_row_t *row);
    void *ud;
} db_ext_sink_t;

typedef struct db_driver {
    const char *name;               /* "sqlite3", "postgresql" */
    int (*open)(db_conn_t **c, const db_source_t *src, char *err, size_t errlen);
    void (*close)(db_conn_t *c);
    const char *(*errmsg)(db_conn_t *c);                         /* the last error of c */
    /* required PowerDNS columns by name (extra columns are ignored); then the karidns_* tables */
    int (*check_schema)(db_conn_t *c, db_schema_info_t *out);
    int (*begin_snapshot)(db_conn_t *c);
    int (*end_snapshot)(db_conn_t *c);
    /* one row per domain, ORDER BY id; soa_content is the content of the enabled apex SOA (NULL if none) */
    int (*list_zones)(db_conn_t *c, db_zone_cb cb, void *ud);
    /* all records of the source, ORDER BY domain_id, id (bulk load); or of one zone, ORDER BY id */
    int (*scan_records)(db_conn_t *c, const int64_t *domain_id /* NULL = all */, db_record_cb cb, void *ud);
    /* domainmetadata, ORDER BY domain_id, id; domain_id NULL = all */
    int (*scan_metadata)(db_conn_t *c, const int64_t *domain_id, db_meta_cb cb, void *ud);
    /* DISTINCT cryptokeys.domain_id (existence only: the loader never reads key material) */
    int (*zones_with_keys)(db_conn_t *c, db_key_cb cb, void *ud);
    /* rows of karidns_changes after `after`, ORDER BY seq.  *last_seq = highest seq seen (or after); *gap = rows
     * after `after` were pruned (the first row is not after + 1).  DB_ERR_UNAVAILABLE when the table does not exist. */
    int (*changes_since)(db_conn_t *c, uint64_t after, db_change_cb cb, void *ud, uint64_t *last_seq, bool *gap);
    int (*wait_fd)(db_conn_t *c);                                /* fd to poll for change notifications; -1 = poll by timer */
    int (*drain_notifications)(db_conn_t *c, bool *changed);
    int (*report_status)(db_conn_t *c, const db_status_t *st);   /* PostgreSQL only; SQLite3: no-op */
    /* B6a: the highest seq in karidns_changes inside the open snapshot (0 = the table is empty); DB_ERR_UNAVAILABLE when
     * the table does not exist.  Used for the first reading of the change log (no need to list a million rows). */
    int (*changes_max)(db_conn_t *c, uint64_t *seq);
    /* B6b: records of domain_id lo..hi (both included), ORDER BY domain_id, id: the bulk scan of one range, so that
     * loader workers with their own connections read disjoint sets of zones. */
    int (*scan_records_range)(db_conn_t *c, int64_t lo, int64_t hi, db_record_cb cb, void *ud);
    /* B6b: rows of karidns_domain_views (domain_id, view_name), ORDER BY domain_id; of one domain when domain_id is not NULL.
     * DB_ERR_UNAVAILABLE when the table does not exist.  The view names are compared by the caller, in C. */
    int (*scan_domain_views)(db_conn_t *c, const int64_t *domain_id, db_domain_view_cb cb, void *ud);
    /* B7a: rows of karidns_profiles (name, settings), ORDER BY name.  DB_ERR_UNAVAILABLE when the table does not exist (the
     * database has no profiles).  A NULL name or settings, or one with an embedded NUL, is an error naming the table. */
    int (*scan_profiles)(db_conn_t *c, db_profile_cb cb, void *ud);
    /* B8: rows of karidns_record_tags, karidns_record_tinydns (ordered by domain_id, record_id) and karidns_zone_tagdefs (ordered by
     * domain_id, then in the order the rows were inserted: the order of the definitions of a zone file) for domain_id, or for every
     * domain when it is NULL; the three tables one after the other.  A callback returning non-zero stops the scan (DB_STOPPED).
     * DB_ERR_UNAVAILABLE when the tables do not exist (a plain PowerDNS database: no tags). */
    int (*scan_ext)(db_conn_t *c, const int64_t *domain_id, const db_ext_sink_t *sink);
    /* B9 (auto reload, SQLite3): the change detector on a persistent connection, called outside a snapshot.  *version is
     * an opaque value that differs from the one the previous call on this connection returned when another connection
     * committed in between (PRAGMA data_version; the first call only sets the baseline).  *replaced is set when the database
     * file is no longer the one that was opened (replaced by another file, deleted, renamed away); the connection still reads
     * the old file then, so the caller reopens.  NULL for a driver that notifies (wait_fd). */
    int (*poll_version)(db_conn_t *c, uint64_t *version, bool *replaced);
} db_driver_t;

/* compiled in when the driver is listed in DB_DRIVERS (Makefile) */
#ifdef KARIDNS_DB_SQLITE3
extern const db_driver_t db_driver_sqlite3;
#endif
#ifdef KARIDNS_DB_POSTGRESQL
extern const db_driver_t db_driver_postgresql;
#endif

#endif
