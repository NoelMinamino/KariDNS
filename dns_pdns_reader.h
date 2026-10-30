#ifndef DNS_PDNS_READER_H
#define DNS_PDNS_READER_H

/*
 * dns_pdns_reader.h - PowerDNS 5.1 reader core (beta design 3.1-3.5, milestone B2).
 *
 * Turns the rows of one PowerDNS zone (domains.name, records, domainmetadata) into a parsed zone_arena_t, the list of
 * empty non-terminals, the zone flags, the settings text and, on request, the KDB1 messages of dns_db_stream.h.
 * No DB driver, no I/O: the caller (a driver callback in karidns-dbloader / karicheck, or a test) hands over rows
 * that are already in memory.  Ordinary process code (malloc allowed, CLAUDE.md Rules 1-2 do not apply); every
 * byte of every row is untrusted DB content.
 *
 * How a zone is converted (design 3.4): each enabled row becomes one zone-file line under "$ORIGIN ."
 *     <owner>. <ttl> IN <TYPE> [<prio>] <content>
 * and the text is parsed by parse_zone_fast().  PowerDNS stores absolute names without the trailing dot, which is a
 * name relative to the root, so $ORIGIN . makes every relative name in `content` absolute exactly as PowerDNS
 * means it.  One row = one line = one record, so parser errors map back to records.id.
 *
 * Row rules (design 3.3), in the order they are applied:
 *   1. disabled                          skipped (before every other check)
 *   2. type NULL                         empty non-terminal: no RR; (name, ordername) kept in z->ents (B5)
 *   3. type token                        letters, digits, '-', first character a letter, <= 32.  ALIAS and LUA (B9a, design 3.6b) are
 *                                        accepted: the zone parser makes them TYPE65401 / TYPE65402 as PowerDNS transfers them; an ALIAS
 *                                        beside an A / AAAA RRset or in a zone with DNSSEC records, and domainmetadata
 *                                        ENABLE-LUA-RECORDS=1, fail the zone
 *   4. owner                             not empty; the zone name or below it at a label boundary (compared in C,
 *                                        never with SQL collations); safe as a zone-file token
 *   5. ttl                               NULL -> opts.default_ttl (one aggregated warning per zone); outside
 *                                        0..2^31-1 -> error
 *   6. prio                              MX with 1 content field / SRV with 3: the prio is prepended (NULL = 0,
 *                                        must be 0..65535); MX with 2 / SRV with 4 fields and prio != 0: error
 *                                        (ambiguous); any other type with prio != 0: warning, ignored
 *   7. content                           must not be empty; line-safety rules below
 *   8. after parsing                     a PRESIGNED zone gets the NSEC3PARAM / NSEC3 / NSEC RRs PowerDNS does not store
 *                                        (dns_presigned.h, design 3.6); every record is written as ZONE_DATA writes it and read back with the decoder the
 *                                        Backend uses (parse_resource_record); one it refuses (the zone parser itself refuses
 *                                        such generic RDATA since D15-2; this is defence in depth) fails the zone with its records.id, as
 *                                        does a record that cannot fit a ZONE_DATA message on its own
 *
 * Line-safety rules (pdns_text_check(); RFC 1035 5.1 master file format, and the tokenizer of dns_zone_parser.c
 * which is what decides): a stored value must not be able to end its own line, hide the rest of the line, start a
 * directive, open a group that spans lines, or swallow the newline that follows it.  Rejected:
 *   - NUL, LF, CR and every other control character except TAB (0x01-0x08, 0x0B-0x1F, 0x7F)
 *   - ';' outside quotes and outside a backslash escape (starts a comment: RFC 1035 5.1)
 *   - a content that starts with '$' (directive: $ORIGIN, $TTL, $INCLUDE, $GENERATE, ...)
 *   - an unbalanced '"' (a quoted string must be closed on its line), unbalanced or nested '(' ')' outside quotes
 *     (a '(' opens a group in which newlines are blanks: the next row would become part of this one)
 *   - a trailing lone backslash (the tokenizer would take the line terminator as the escaped character)
 *   - a bare "@" token (zone-file shorthand for the origin; here the origin is the root, which is not what the
 *     PowerDNS content means)
 * Backslash escapes are followed exactly as the tokenizer does ('\' takes the next character literally).  Owners
 * additionally must not contain whitespace, '"', '(' or ')' at all, and are written back in the canonical form of
 * dns_name_normalize().  Rows are written by this code only: nothing of a row's text reaches another line.
 *
 * Errors: every failure names the zone and the records.id (first failing row; one failing row fails the whole
 * zone, design D7).  Warnings are collected in z->warnings and are never fatal.
 *
 * String lifetime: the strings of a row are copied at once (into the text buffer or the entry list); the caller
 * may free its row as soon as pdns_zone_add_record() returns.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dns_wire.h"
#include "dns_zone_parser.h"
#include "dns_db_stream.h"
#include "dns_presigned.h"

/* ------------------------------------------------------------------ row structs (design 2.1) */
typedef struct {                                /* one row of `domains` with its apex SOA */
    int64_t id;
    const char *name;                           /* as stored (lowercase, no trailing dot) */
    const char *type;                           /* NATIVE MASTER SLAVE PRODUCER CONSUMER */
    const char *master;                         /* NULL if NULL */
    const char *catalog;                        /* NULL if NULL */
    const char *soa_content;                    /* NULL when the zone has no enabled apex SOA */
} db_zone_row_t;

typedef struct {                                /* one row of `records` */
    int64_t id, ttl, prio;
    bool ttl_null, prio_null, disabled;
    const char *name, *type, *content, *ordername;   /* type NULL = ENT row; ordername NULL if NULL */
} db_record_row_t;

typedef struct { int64_t domain_id; const char *kind, *content; } db_meta_row_t;
/* B8: rows of the extension tables (design 3.7).  karidns_record_tags: record_id -> location_tag, ecs_tag (NULL or "" = no tag).
 * karidns_record_tinydns: record_id -> ttd (unix time of the TAI64 time stamp; NULL = none), loc (1-2 characters, NULL = none),
 * countdown (a ttd that is the expiry of a countdown TTL).  karidns_zone_tagdefs: kind 'location' | 'ecs' | 'tinydns', tag,
 * cidr; the rows of a zone are given in table order (the order of the definitions in a zone file: the first tag that matches wins). */
typedef struct { int64_t record_id; const char *location_tag, *ecs_tag; } db_tag_row_t;
typedef struct { int64_t record_id; bool ttd_null; int64_t ttd; const char *loc; bool countdown; } db_tinydns_row_t;
typedef struct { const char *kind, *tag, *cidr; } db_tagdef_row_t;
typedef struct { uint64_t seq; int64_t domain_id; } db_change_row_t;
/* Strings in rows stay valid until the callback returns (zero copy from sqlite3_column_text / PQgetvalue).  They
 * are C strings: a driver must reject (or never pass) a value that has an embedded NUL (sqlite3_column_bytes() !=
 * strlen()); pdns_text_check() rejects NUL for callers that have a length. */

/* ------------------------------------------------------------------ limits */
#define PDNS_DEFAULT_TTL 3600u
#define PDNS_MAX_TTL 2147483647u                /* RFC 2181 8 / RFC 8767 4: 2^31 - 1 */
#define PDNS_MAX_CONTENT (1u << 20)             /* bytes of one records.content */
#define PDNS_MAX_TYPE_LEN 32
#define PDNS_MAX_META_ROWS 65536
#define PDNS_MAX_META_CONTENT 4096
#define PDNS_MAX_SETTINGS 65535                 /* a KDB1 TLV length is a u16 */
#define PDNS_MAX_WARNINGS 64                    /* kept; further ones are counted in warnings_dropped */
#define PDNS_ERR_LEN 600

typedef struct {
    uint32_t default_ttl;       /* for a NULL records.ttl; 0 = PDNS_DEFAULT_TTL (an explicit TTL 0 cannot be a default) */
    uint64_t max_records;       /* max-zone-records: RRs of the zone with both SOAs counted (= ZONE_BEGIN rr_count), and,\n                                   separately, enabled rows incl. ENT rows; 0 = KDB_DEFAULT_MAX_ZONE_RECORDS */
    uint64_t max_text_bytes;    /* generated zone text; 0 = 4 GiB */
    uint64_t max_zone_bytes;    /* sum of the ZONE_DATA bodies; 0 = KDB_DEFAULT_MAX_ZONE_BYTES */
} pdns_opts_t;

typedef struct { int64_t row_id; char *name; char *ordername; } pdns_ent_t;   /* name canonical absolute; ordername NULL if NULL */

/* zone flags */
#define PDNS_F_PRESIGNED 0x1u   /* domainmetadata PRESIGNED = 1 */
#define PDNS_F_TINYDNS 0x2u     /* domainmetadata X-KARIDNS-FORMAT = tinydns (tinydns zones are encoded in B8) */

typedef struct {
    char kind[65];
    char *content;
} pdns_meta_t;

typedef struct pdns_zone_s {
    /* ---- input state (private) */
    char name[DNS_NAME_TEXT_SIZE];  /* canonical absolute zone name */
    pdns_opts_t opts;
    char *text;                     /* the generated zone text, "$ORIGIN .\n" first */
    size_t text_len, text_cap;
    size_t *line_off;               /* [i] = offset of the line of enabled record row i */
    int64_t *line_id;               /* [i] = records.id of that row (0 for a record added by presigned_rebuild()) */
    size_t *ord_off;                /* [i] = 1 + offset of the row's ordername in ord_pool, 0 = NULL (kept for the presigned checks) */
    char *ord_pool;
    size_t ord_len, ord_cap;
    char *text2;                    /* NSEC3 / NSEC lines synthesized by presigned_rebuild(); the arena points into them */
    size_t n_rows, rows_cap;        /* rows that became a line */
    uint64_t n_seen;                /* enabled rows incl. ENT rows (against max_records) */
    pdns_meta_t *meta;
    size_t n_meta, meta_cap;
    size_t n_soa;
    int64_t soa_row_id;
    size_t soa_row_index;           /* index among the rows that became lines */
    uint64_t n_null_ttl, n_prio_ignored;
    int64_t first_null_ttl_id, first_prio_ignored_id;
    bool finished;

    /* ---- B8: the Extended AXFR attributes (design 3.6a, 3.7), checked when added, attached to the records by pdns_zone_finish() */
    struct pdns_tagrow { int64_t id; char *loc, *ecs; } *tags;
    size_t n_tags, tags_cap;
    struct pdns_tdrow { int64_t id; int64_t ttd; char loc[2]; bool countdown; } *tdns;
    size_t n_tdns, tdns_cap;
    ecs_tag_def_t *loc_defs, *ecs_defs;       /* $LOCATION-TAG / $ECS-SUBNET-TAG; at finish they move into arena.bind_*_tags */
    int n_loc_defs, n_ecs_defs;
    tinydns_location_entry_t *locs;           /* the %% lines; at finish they move into arena.locations */
    int n_locs;
    size_t n_def_rows;

    /* ---- result (valid after pdns_zone_finish() returned 0) */
    zone_arena_t arena;             /* parsed, build_zone_index(false) done; arena.records[i] is row i of the text */
    bool arena_ready;
    size_t soa_index;               /* index of the apex SOA in arena.records */
    uint32_t serial;                /* SOA serial */
    uint32_t flags;                 /* PDNS_F_* */
    pdns_ent_t *ents;               /* empty non-terminals, in records.id order */
    size_t n_ents, ents_cap;
    char *settings;                 /* settings text (design 3.5), "" when the metadata give none */
    char profile[256];              /* X-KARIDNS-PROFILE, "" if none */
    uint8_t zkind;                  /* B7b: KDB_ZK_PRIMARY (0, rows), KDB_ZK_SECONDARY (SLAVE) or KDB_ZK_CATALOG (CONSUMER): no rows */
    char *master;                   /* B7b: domains.master of such a zone (private copy) */
    bool summary;                   /* D1a milestone 4: only the directory entry of a primary zone (serial, SOA timers, settings, flags): no rows */
    uint32_t sum_serial, sum_refresh, sum_retry, sum_expire;
    bool sum_timers;
    char *sum_apex;                 /* D1a step 6: the apex of the summary, one block: mname NUL rname NUL the NS names separated by LF NUL (pdns_zone_set_apex()) */
    const char *sum_mname, *sum_rname, *sum_ns;
    uint32_t sum_minimum, sum_soa_ttl, sum_ns_ttl;
    char *nsec3param;               /* NSEC3PARAM metadata (first row), NULL if none */
    presigned_mode_t presigned_mode;   /* PS_NSEC3 / PS_NSEC: the chain was rebuilt; PS_NONE: served as stored */
    size_t n_synth;                 /* records presigned_rebuild() added at the end of arena.records */
    bool has_ext;                   /* B8: the zone carries Extended AXFR records (tags, tag definitions, tinydns attributes or locations) */

    /* ---- diagnostics */
    char **warnings;
    size_t n_warnings;
    size_t warnings_dropped;
    bool failed;
    int64_t error_row_id;           /* valid if error_has_row */
    bool error_has_row;
    char error[PDNS_ERR_LEN];       /* "zone 'x.test.' records.id 12: reason" */
} pdns_zone_t;

/* A new zone.  zone_name is domains.name (with or without the trailing dot).  NULL on out of memory; a zone name
 * that cannot be used (empty, root, bad escape, label or name too long) gives a zone that is already failed
 * (z->failed, z->error), so callers have one error path. */
pdns_zone_t *pdns_zone_new(const char *zone_name, const pdns_opts_t *opts);
void pdns_zone_free(pdns_zone_t *z);
/* The canonical absolute name pdns_zone_new() gives a zone called dbname (domains.name); false if that would be a failed zone
 * (empty, root, bad escape, label or name too long).  out: DNS_NAME_TEXT_SIZE bytes. */
bool pdns_canonical_zone_name(const char *dbname, char out[DNS_NAME_TEXT_SIZE]);

/* B7b: make the zone a SLAVE (kind KDB_ZK_SECONDARY) or a CONSUMER (KDB_ZK_CATALOG) before pdns_zone_finish(); master is
 * domains.master (NULL if the column is NULL).  Rows of `records` are then not needed (pdns_zone_add_record() is not called
 * by the loader); pdns_zone_finish() only converts the metadata and puts `masters { ... };` (every address of domains.master,
 * PowerDNS syntax ip, ip:port, [ip]:port, comma separated) in front of the settings text, and fails a zone without a usable
 * master.  Returns -1 on out of memory. */
int pdns_zone_set_secondary(pdns_zone_t *z, uint8_t kind, const char *master);

/* D1a milestone 4 (design 3.3, 6.3): make a primary zone a summary before pdns_zone_finish(): the part of it the Backend keeps in its zone
 * directory when the data is not in memory.  No rows are needed (pdns_zone_add_record() is not called); pdns_zone_finish() converts the
 * metadata into the settings text and the flags, and pdns_zone_encode_kdb() writes ZONE_BEGIN (KDB_ZF_SUMMARY, rr_count 0, a zero digest,
 * the serial and the SOA timers given here) and ZONE_END, no ZONE_DATA, and never calls the digest gate.  serial and timers are those of the
 * zone's SOA as the loader read them from the zone list. */
void pdns_zone_set_summary(pdns_zone_t *z, uint32_t serial, bool has_timers, uint32_t refresh, uint32_t retry, uint32_t expire);

/* One row of `records` (the driver passes them in records.id order).  0 = accepted or skipped; -1 = the zone has
 * failed (z->error says why; later calls return -1 at once, so a driver callback can stop its scan). */
int pdns_zone_add_record(pdns_zone_t *z, const db_record_row_t *row);
/* One row of `domainmetadata` (domain_id is ignored).  Rows of one kind are used in the order given. */
int pdns_zone_add_meta(pdns_zone_t *z, const db_meta_row_t *row);
/* B8: one row of karidns_record_tags / karidns_record_tinydns / karidns_zone_tagdefs (before pdns_zone_finish(); any order relative to the
 * records).  A tag name is 1-63 printable characters without blanks ("none" and "default" are the zone file's way to clear a tag,
 * so they are no names); a tag definition CIDR must parse; a tinydns location definition is an IPv4 prefix; a countdown needs a ttd.
 * 0 = accepted (a row without any attribute is skipped); -1 = the zone has failed (z->error). */
int pdns_zone_add_tags(pdns_zone_t *z, const db_tag_row_t *row);
int pdns_zone_add_tinydns(pdns_zone_t *z, const db_tinydns_row_t *row);
int pdns_zone_add_tagdef(pdns_zone_t *z, const db_tagdef_row_t *row);
/* Parse, check and index.  0 = ok (result fields valid); -1 = failed.  Call once. */
int pdns_zone_finish(pdns_zone_t *z);

/* ------------------------------------------------------------------ helpers */
/* Third field of an SOA content: strict decimal digits only, <= 2^32 - 1.  Fields are separated by blanks; the
 * content may have leading / trailing blanks.  false if there are fewer than 3 fields or the serial is not valid. */
bool pdns_soa_serial(const char *content, uint32_t *serial);
/* The refresh, retry and expire (fields 4..6) of an SOA content, with the same rules.  false if a field is missing or not a number. */
bool pdns_soa_timers(const char *content, uint32_t *refresh, uint32_t *retry, uint32_t *expire);
/* D1a step 6: the two names (canonical absolute) and the minimum (field 7) of an SOA content.  false if one is missing or not valid. */
bool pdns_soa_apex(const char *content, char mname[DNS_NAME_TEXT_SIZE], char rname[DNS_NAME_TEXT_SIZE], uint32_t *minimum);
/* D1a step 6: the target of an NS record as the Backend gets it: a canonical absolute name.  false if it is not a name. */
bool pdns_apex_name(const char *raw, char out[DNS_NAME_TEXT_SIZE]);
/* D1a step 6: give a summary (pdns_zone_set_summary()) the apex of the zone: the SOA's names and minimum, the TTLs (RFC 2181 8: at most 2^31 - 1, larger values are
 * rounded down), and the NS targets, canonical absolute names separated by LF (1..KDB_APEX_NS_MAX of them).  The names are copied.  -1: out of memory. */
int pdns_zone_set_apex(pdns_zone_t *z, const char *mname, const char *rname, uint32_t minimum, uint32_t soa_ttl, uint32_t ns_ttl, const char *ns_lf);

/* The line-safety rules above on s[0..len).  is_owner: the stricter owner rules.  Returns NULL if safe, else a
 * static reason text.  s may contain NUL (it is rejected). */
const char *pdns_text_check(const char *s, size_t len, bool is_owner);

/* ------------------------------------------------------------------ KDB1 encoding (design 1.4) */
typedef struct {
    uint16_t view;              /* ZONE_BEGIN view index */
    int64_t source_id;          /* domains.id */
    uint8_t zone_kind;          /* KDB_ZK_* */
    const char *profile;        /* NULL: z->profile when set */
    /* B6a: called once, after the digest is known and before anything is emitted.  Returns non-zero to skip the zone (the
     * loader already knows this exact version): pdns_zone_encode_kdb() then returns 1 and has emitted nothing. */
    int (*gate)(void *ud, uint32_t serial, const uint8_t digest[KDB_DIGEST_LEN]);
    void *gate_ud;
    /* B7a: the text of the profile the zone names (karidns_profiles.settings), "" or NULL = none.  It goes into the digest
     * (with the settings text and the profile name), so that editing the profile makes every zone that uses it new to a
     * loader that has the old version; the loader sends it itself as a PROFILE message. */
    const char *profile_text;
    /* D1a, fetch stream: the FETCH_REQ the zone answers (ZONE_BEGIN tag 11); 0 = none (the batch stream) */
    uint64_t request_id;
} pdns_kdb_params_t;

/* Called once per complete KDB1 message (12-byte header + body); the memory is valid during the call only.
 * Return 0, or -1 to stop (pdns_zone_encode_kdb() then returns -1). */
typedef int (*pdns_emit_fn)(void *ud, const uint8_t *msg, size_t len);

/* ZONE_BEGIN, ZONE_DATA..., ZONE_END of a converted zone, in this order and nothing else.
 *   ZONE_DATA   uncompressed RRs (serialize_dns_record without a compression context, RFC 3597 4), SOA first and
 *               last (RFC 5936 2.2), the other rows in records.id order (design 3.4: deterministic), each message
 *               <= 65,535 bytes with the header QR=1, AA=1, ID 0, QDCOUNT/NSCOUNT/ARCOUNT 0 (B1 rules).
 *   rr_count    number of RRs including both SOAs
 *   digest      SHA-256 over the ZONE_DATA bodies in stream order (the 12-byte DNS header and the RRs of each
 *               message, no framing, no ZONE_DATA headers), then, when the zone has a settings text or names a profile,
 *               a marker and the length-prefixed settings text, profile name and profile text (B7a: a metadata-only
 *               edit changes the digest); two loaders on the same rows send the same digest
 *   flags       bit0 presigned.  Extended AXFR attributes (tags, tinydns) are B8.
 *   B7b         a zone made secondary by pdns_zone_set_secondary() is encoded as ZONE_BEGIN (zone_kind secondary / catalog, serial 0,
 *               flags 0, rr_count 0, the settings text with the masters) and ZONE_END (0): no ZONE_DATA.  Its digest covers the
 *               settings text, the profile name and the profile text only, so a loader that restarts finds the zone up to date.
 * Returns 1 (nothing emitted) when p->gate asked to skip the zone.
 *
 * Fails (-1, *err filled) for a tinydns zone, for an RR that does not fit a message, and above max_zone_bytes. */
int pdns_zone_encode_kdb(const pdns_zone_t *z, const pdns_kdb_params_t *p, pdns_emit_fn emit, void *ud,
                         char *err, size_t errlen);

#endif
