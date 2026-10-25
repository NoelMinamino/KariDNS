#ifndef DNS_ZONE_LINT_H
#define DNS_ZONE_LINT_H

/*
 * dns_zone_lint.h - the checks of `karicheck zone` that look at a parsed zone (zone_arena_t).
 *
 * They used to be part of tools/karicheck.c.  `karidns-dbloader --check` (B12, beta design 7.2) runs the very same code on the zone
 * the PowerDNS reader built from the rows of a database, so a zone file and a database zone are judged by one implementation.
 * Ordinary process code (malloc allowed, CLAUDE.md Rules 1-2 do not apply).
 *
 * Every finding goes through kc_error() / kc_warning() / kc_info() / kc_ok() / kc_detail() with a kc_tally_t.  Without a sink they
 * print "[ERROR] ..." / "[WARNING] ..." on stderr and "[INFO] ..." / "[OK] ..." on stdout, as karicheck always did, and count in the
 * tally.  With a sink the text (the printf result without its final line feed) goes to the sink instead, and nothing is printed.
 */

#include <stdbool.h>
#include <stddef.h>
#include "dns_zone_parser.h"
#include "dns_wire.h"

/* level: 'E' error, 'W' warning, 'I' info, 'O' ok, 'D' detail (a continuation line of the previous finding) */
typedef void (*kc_sink_fn)(void *ud, char level, const char *text);

typedef struct {
    int errors;
    int warnings;
    kc_sink_fn sink;            /* NULL: print */
    void *sink_ud;
} kc_tally_t;

/* t == NULL: print without counting (error / warning) */
void kc_error(kc_tally_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void kc_warning(kc_tally_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void kc_info(kc_tally_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void kc_ok(kc_tally_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void kc_detail(kc_tally_t *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* RFC 2181 5.2 (what: "zone file" or "database", for the message): RRs of one RRset with different TTLs, on the raw data of the source (call before the TTLs are harmonized:
 * before build_zone_index(arena, true); a zone the reader built (build_zone_index(false)) has its TTLs as written) */
void zone_lint_ttl(const zone_arena_t *arena, const char *what, kc_tally_t *t);

typedef struct {
    const char *domain;         /* the zone name, absolute with the final dot */
    const char *src;            /* where the zone comes from, for messages: a file path, or "domains.id 12" */
    const char *raw_text;       /* the text of a tinydns data file, for the checks of its raw lines; NULL: skip them */
    bool is_catalog;
    /* the tag definitions of the server configuration (options { ecs-tags / location-tags }) or of the zone's zone {} block: used when
     * the zone defines none of its own.  NULL / 0: none (a database zone is judged by its own definitions only unless the caller
     * says more). */
    const ecs_tag_def_t *ecs_tags;
    int ecs_tag_count;
    const ecs_tag_def_t *loc_tags;
    int loc_tag_count;
} zone_lint_in_t;

/* Everything `karicheck zone` checks on a parsed and indexed zone after the parser and the zone-level validations (name lengths, DNAME,
 * ALIAS / LUA rules) passed: the printed "[OK] ... parsed" line and the final [RESULT] are the caller's. */
void zone_lint_records(zone_arena_t *arena, const zone_lint_in_t *in, kc_tally_t *t);

/* Records that survive for the "LUA / ALIAS" notes of the zone (design 3.6b), printed through kc_info() / kc_warning() */
void zone_lint_pdns_types(const zone_arena_t *arena, const char *domain, kc_tally_t *t);

#endif /* DNS_ZONE_LINT_H */
