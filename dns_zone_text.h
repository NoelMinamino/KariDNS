#ifndef DNS_ZONE_TEXT_H
#define DNS_ZONE_TEXT_H

/*
 * dns_zone_text.h - a parsed zone (zone_arena_t) -> zone file text: the writer of the 0.6.0 ZoneExporter.  The arena is the one the zone
 * parser makes of a zone file, or dns_pdns_reader.c of the rows of a database zone (a presigned zone with the records dns_presigned.c
 * rebuilds, so the file alone serves it).  Ordinary process code (malloc allowed); the server does not link it.
 *
 * BIND format (RFC 1035 section 5.1):
 *   $ORIGIN <zone>.
 *   $TTL <the TTL most records have>
 *   $LOCATION-TAG / $ECS-SUBNET-TAG definitions, in definition order
 *   one record per line in canonical order (RFC 4034 section 6.1: owner name, then type; within an RRset section 6.3: RDATA in canonical
 *   wire form; the wire form is the one dns_record_canonical_rdata() makes)
 * Owner names are relative to the zone ("@" for the apex), names in RDATA are relative when inside the zone and the parser expands them
 * (zrows_field_flags(), ZF_EXPAND) and absolute with the dot otherwise.  A TTL is written when it is not the $TTL, the class when it is not
 * IN.  A record that carries a $LOCATION / $ECS-SUBNET tag follows a directive that sets it; the directive "none" clears it again.  Blobs
 * (base64, hex) are one token, not wrapped.  Character-strings are quoted; every other token is written bare when nothing in it has a
 * meaning to the zone-file lexer, else quoted with \" \\ \DDD escapes.  A record in the RFC 3597 form (PowerDNS ALIAS and LUA, TYPE65401 /
 * TYPE65402, are such records) is written as "\# <length> <hex>".
 *
 * tinydns format: a zone that is a tinydns data file (zone_arena_t.is_tinydns_format, X-KARIDNS-FORMAT tinydns) is written as a data
 * file: the % lines of its locations, then one line per record (Z, &, +, 3, @, ', ^, C, and ':' generic lines for every other type) with
 * the TTL, the TAI64 time stamp of the ttd (a countdown TTL is TTL 0 with a time stamp) and the location code.  The BIND format cannot
 * express those: a record with a tinydns attribute makes the BIND writer fail and name the record.  $LOCATION / $ECS-SUBNET tags cannot
 * be written in the tinydns format either.
 *
 * Owners and RDATA are untrusted (they come from the database): every name, string and tag is escaped for the lexer of its format, so no
 * value can end its line, start a directive or a comment, or open a group.  Unless opts->no_verify, the text is parsed again before a
 * byte is handed to the sink and must give the same records, tags, tag definitions and locations (dns_zone_text_same_zone()); a record
 * that does not make the writer fail with a message that names it ("record 12 (www.example.test. A): ...").
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include "dns_zone_parser.h"

typedef enum {
    DZT_AUTO = 0,       /* tinydns for an arena that is a tinydns data file, else BIND */
    DZT_BIND,
    DZT_TINYDNS
} dzt_format_t;

typedef struct {
    dzt_format_t format;
    bool no_verify;     /* do not parse the text again; it is then handed to the sink in pieces while it is made */
} dzt_opts_t;

/* Gets the text in pieces; 0 = ok, anything else stops the write. */
typedef int (*dzt_sink_t)(void *ud, const char *data, size_t len);

/* Write the zone `apex` held by `arena` to sink.  opts may be NULL (dzt_opts_t zero: DZT_AUTO, verified).  false: err says why (nothing is
 * handed to the sink when a verified write fails; a sink error stops it at once). */
bool dns_zone_text_write(const zone_arena_t *arena, const char *apex, const dzt_opts_t *opts, dzt_sink_t sink, void *ud, char *err,
                         size_t errlen);
/* The same to a stdio stream (a write error is an error). */
bool dns_zone_text_write_file(const zone_arena_t *arena, const char *apex, const dzt_opts_t *opts, FILE *fp, char *err, size_t errlen);

/* Do two arenas hold the same zone?  The records are compared as sets in canonical order: owner (byte for byte), class, type, TTL, RDATA
 * (the text, or the canonical wire form when the text differs), the $LOCATION / $ECS-SUBNET tags and the tinydns attributes; then the
 * tag definitions and the tinydns locations in order.  false: why names the first difference. */
bool dns_zone_text_same_zone(const zone_arena_t *a, const zone_arena_t *b, char *why, size_t whylen);

/* One RRset (the records recs[0..n), one owner and type) as canonical lines for the delta of a change set (karidns-zone apply, karidns_zone_version_rrsets):
 * "<ttl> <TYPE> <rdata>" per record in the canonical RDATA order (RFC 4034 section 6.3), joined by LF, every name absolute (nothing is relative to a zone),
 * strings quoted as the zone-file writer does.  malloc'd; NULL with err (a record that cannot be written, out of memory). */
char *dns_zone_text_rrset_lines(const dns_record_t *const *recs, size_t n, char *err, size_t errlen);

#endif
