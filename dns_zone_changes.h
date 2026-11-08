#ifndef DNS_ZONE_CHANGES_H
#define DNS_ZONE_CHANGES_H

/*
 * dns_zone_changes.h - the change file of `karidns-zone apply` (0.6.0 items D and E; docs/karidns-zone.md "apply", "The change file").
 *
 * The WebAdmin API writes a change set of one zone as a file and hands it to karidns-zone; an operator may write one by hand.  It is external input: the
 * parser here is the only reader of it, it is fuzzed (tests/fuzz/fuzz_zone_changes.c), and it applies the line-safety rules of the loader's reader
 * (dns_pdns_reader.h, pdns_text_check(): RFC 1035 section 5.1) to every field, so that no field can end its line, start a directive, open a group or
 * hide the rest of the line when the operations are turned into zone-file text for the zone parser.
 *
 * Format: one operation per line, fields separated by blanks (space or TAB), lines ended by LF (a CR before the LF is dropped); empty lines and lines
 * whose first non-blank character is '#' are ignored.
 *     rr <owner> <ttl> <type> <rdata>      the record is part of the new RRset (owner, type): every RRset that has an rr line is REPLACED by its rr lines
 *     delete <owner> <type>                the RRset (owner, type) is deleted
 * owner: an absolute name with the final dot (letters, digits, '_', '*', '-', '/' and '.', labels of 1 to 63 octets, 253 octets at most), the zone or a name
 * below it at a label boundary (case does not matter; it is stored in lower case).  ttl: decimal, 0 to 2147483647 (RFC 2181 section 8).  type: a record
 * type name or TYPEnnn (letters, digits and '-', at most 32), any case; the types the signer owns (RRSIG NSEC NSEC3 NSEC3PARAM DNSKEY CDS CDNSKEY) and the
 * meta types (ANY AXFR IXFR OPT TSIG TKEY MAILA MAILB) are refused, also in their TYPEnnn spelling.  rdata: the rest of the line in the presentation format
 * of the zone parser (relative names in it are relative to the zone), not empty, at most 65535 octets.  An (owner, type) that has rr lines and a delete line
 * is an error; two delete lines of one RRset are one.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZC_MAX_LINE 70000u              /* the longest line (the rdata is limited to 65535 octets) */
#define ZC_MAX_OPS 4000000u             /* operations in one file */

typedef enum { ZC_RR = 0, ZC_DELETE } zc_kind_t;

typedef struct {
    zc_kind_t kind;
    char *owner;                        /* absolute, lower case, final dot: "www.example.test." */
    char type[33];                      /* upper case */
    uint32_t ttl;                       /* rr only */
    char *rdata;                        /* rr only: one line */
    size_t line;                        /* the line of the file (1 based) */
} zc_op_t;

typedef struct {
    zc_op_t *ops;
    size_t n, cap;
    size_t n_rr, n_delete;
} zc_changes_t;

/* Parse text[0..len) for the zone `zone` (the name as the zone parser writes it: lower case with the final dot).  false: err says why ("line 3: ..."); *out is
 * then empty.  Free with zc_free(). */
bool zc_parse(const char *text, size_t len, const char *zone, zc_changes_t *out, char *err, size_t errlen);
void zc_free(zc_changes_t *c);

/* The rr operations as the zone-file text the zone parser reads: "$ORIGIN <zone>" and then one line "<owner> <ttl> IN <TYPE> <rdata>" per rr operation, in
 * the order of the file.  malloc'd (NUL terminated, *len bytes); NULL on out of memory.  The parser has checked every field, so each operation is exactly one line. */
char *zc_zone_text(const zc_changes_t *c, const char *zone, size_t *len);

/* Is this a type a change file may not name (the signer's DNSSEC types and the meta types)?  type is upper case. */
bool zc_type_refused(const char *type);

#endif
