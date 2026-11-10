#ifndef DNS_ZONE_RENDER_H
#define DNS_ZONE_RENDER_H

/*
 * dns_zone_render.h - stored PowerDNS records as the presentation text a change set takes (karidns-zone render; 0.6.0 item F, the WebAdmin GUI).
 *
 * GET .../rrsets of the WebAdmin API shows records.content as stored: names without the final dot, MX and SRV with the priority in a column of their
 * own.  A change set (the change file of dns_zone_changes.h) takes zone-file text, so what a client read could not be sent back unchanged (an MX
 * `mail.example.test` would become `mail.example.test.example.test.`).  This turns one stored record into the canonical text the diff of `karidns-zone
 * apply` and the exporter write: every name absolute, strings quoted and escaped by the zone-file writer (dns_zone_text_rrset_lines()), the priority of
 * MX and SRV in front.  The conversion is the loader's own (dns_pdns_reader.c reads the row, dns_zone_text.c writes the record), so there is no second
 * RDATA parser.  Sending the text back as the record's content gives the same record again (the harness fuzz_zone_changes checks it).
 *
 * Every record is judged alone: a record the reader refuses (a bad content, a type it cannot write) gets a message and no text, the others are not
 * affected.  The records come from the database, which any writer fills, so every byte is hostile; the reader's line-safety rules apply
 * (dns_pdns_reader.h, pdns_text_check()).
 *
 * Input (the standard input of `karidns-zone render`): one record per line, fields separated by one TAB, lines ended by LF:
 *     <owner> TAB <type> TAB <prio> TAB <content>
 * owner: records.name as stored (the zone or a name below it); type: records.type; prio: records.prio as decimal digits (a '-' sign allowed), or '-' for
 * NULL; content: records.content, the rest of the line (it may hold TABs).  A line that does not have this shape, or an input of more than
 * ZR_MAX_RECORDS lines, refuses the whole input: the API writes it, so that is a bug of the caller, not a bad record.
 *
 * Ordinary process code (malloc allowed); the server does not link it.
 */

#include <stddef.h>

#define ZR_MAX_RECORDS 200000u
#define ZR_ERR_LEN 240

typedef struct {
    char *rdata;                /* malloc'd, one line, safe for the change file; NULL: the record could not be rendered (err says why) */
    char err[ZR_ERR_LEN];
} zr_result_t;

/* Render the records of text[0..len) for the zone `zone` (domains.name, with or without the final dot).  0: *out holds *n results, one for each
 * line, in the order of the lines (free with zr_free(); n may be 0).  -1: the input was refused or memory ran out (err says why, nothing is allocated). */
int zr_render(const char *zone, const char *text, size_t len, zr_result_t **out, size_t *n, char *err, size_t errlen);
void zr_free(zr_result_t *r, size_t n);

#endif
