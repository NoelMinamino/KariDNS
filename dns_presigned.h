#ifndef DNS_PRESIGNED_H
#define DNS_PRESIGNED_H

/*
 * dns_presigned.h - presigned DNSSEC zones from the PowerDNS schema (beta design 3.6, milestone B5).
 *
 * PowerDNS 5.1.4 does not store the NSEC3 / NSEC RRs of a presigned zone (verified on the build host by letting it
 * AXFR zones signed by BIND's dnssec-signzone, see design 3.6):
 *   NSEC3  PRESIGNED=1 and NSEC3PARAM ("alg flags iterations salt") in domainmetadata; no NSEC3 / NSEC3PARAM rows;
 *          RRSIG(NSEC3) rows at the hashed owners (ordername NULL); every other non-occluded row and every empty
 *          non-terminal (ENT) row carries the hash of its owner (RFC 5155 s5) in `ordername`; the apex keeps its
 *          RRSIG(NSEC3PARAM).
 *   NSEC   PRESIGNED=1 only; no NSEC rows; RRSIG(NSEC) rows at the owners; `ordername` = the owner relative to the
 *          apex, labels in reverse order separated by blanks ("x.y.z.ent" -> "ent z y x"), the apex ''; glue below a
 *          delegation and ENTs have ordername NULL.
 * This module puts the missing RRs back, so the zone image holds them exactly as if the signed zone file had been
 * loaded.  Pure code on the parsed rows (zone_arena_t): no I/O, no DB; shared by the reader (dns_pdns_reader.c), the
 * test importer and, later, karicheck.  There is no cryptographic check (DNSSEC validation is out of scope); the
 * checks are consistency checks between the stored rows and the chain that is derived from them.
 *
 * Mode (presigned_rebuild(), design D8):
 *   NSEC3PARAM metadata given      -> NSEC3 rebuild.  Stored NSEC / NSEC3 / NSEC3PARAM rows or RRSIG(NSEC) rows
 *                                     together with the metadata are a mixture and fail the zone.
 *   no metadata, NSEC3 rows stored -> PS_NONE: the zone is served as stored.
 *   no metadata, RRSIG(NSEC3) rows but no NSEC3 rows                    -> failure (nothing to build the chain from).
 *   no metadata, RRSIG(NSEC) rows and no NSEC rows                      -> NSEC rebuild (with NSEC3 data: mixture).
 *   otherwise                                                          -> PS_NONE.
 *
 * Rebuild, NSEC3 (RFC 5155 s7.1, s3.2.1, s4.1.2):
 *   - chain owners = owners of the stored RRSIG(NSEC3) rows (each <hash>.<apex>), which follows the signer's choices
 *     (Opt-Out exclusions) instead of re-deriving them;
 *   - every name of the zone that is not occluded by a delegation (RFC 1034 s4.2.1) and every empty non-terminal
 *     (RFC 5155 s7.1 step 4) is hashed; the hash must be a chain owner, except that with the Opt-Out flag an unsigned
 *     delegation (NS without DS) and an ENT that is derived only from unsigned delegations need none (s7.1);
 *   - NSEC3 flags = the metadata flags (Opt-Out bit); the NSEC3PARAM RR is written with flags 0 (s4.1.2);
 *   - next hashed owner = the next chain owner in hash order, the last one wraps to the first (s7.1 step 7);
 *   - type bit map = the types at the original owner name plus RRSIG when the name has RRSIGs, never NSEC3; the apex
 *     also gets NSEC3PARAM; at a delegation only NS, DS and RRSIG (RFC 4034 s4.1.2); empty for an ENT;
 *   - TTL of an NSEC3 = the Original TTL of its RRSIG(NSEC3) (RFC 4034 s3.1.4: the signature covers that TTL; this is
 *     what the signer used, RFC 9077 s3); NSEC3PARAM: Original TTL of RRSIG(NSEC3PARAM) at the apex, else SOA MINIMUM.
 * Rebuild, NSEC (RFC 4034 s4, s6.1): chain owners are the owners of the RRSIG(NSEC) rows and must be exactly the names
 *   that are not occluded by a delegation (s4.1.2: no NSEC for a name that only holds glue); ENTs are not in an NSEC
 *   chain; next domain name = the next owner in canonical order, the last wraps to the apex; type bit map = the types at
 *   the name plus RRSIG and NSEC (NS, DS, RRSIG, NSEC at a delegation); TTL = Original TTL of the RRSIG(NSEC).
 * A stored `ordername` that is not NULL must equal the value derived from its owner (NSEC3: the hash; NSEC: the
 * reversed relative name; names with a backslash are not compared); a mismatch fails the zone.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dns_wire.h"
#include "dns_zone_parser.h"

typedef enum { PS_NONE = 0, PS_NSEC3, PS_NSEC } presigned_mode_t;

typedef struct { const char *name; const char *ordername; } presigned_ent_t;   /* canonical absolute name */

typedef struct {
    presigned_mode_t mode;
    char *text;                 /* zone-file lines ("<owner> <ttl> IN <TYPE> <rdata>"), to be parsed with $ORIGIN .; NULL for PS_NONE */
    size_t text_len;
    size_t n_records;           /* lines in text */
    size_t *anchor;             /* per line: index (in the arena) of the stored RRSIG row that covers the RRset the line
                                 * stands for; the line belongs right before that row (a signer writes an RRset and then its
                                 * RRSIG, so ANY answers and transfers list the RRsets in the signer's order); SIZE_MAX: at the end */
} presigned_out_t;

typedef struct {
    uint8_t alg;                /* 1 = SHA-1 (RFC 5155 s11) */
    uint8_t flags;              /* 0 or 1 (Opt-Out) */
    uint16_t iterations;
    uint8_t salt[255];
    uint8_t salt_len;
} presigned_n3param_t;

#define PRESIGNED_MAX_ITERATIONS 2500u   /* RFC 5155 s10.3: the largest value for a 4096 bit key; a bigger one is a DoS on the loader */

/* "alg flags iterations salt" (salt "-" = empty).  false: *why says why (static text). */
bool presigned_parse_n3param(const char *s, presigned_n3param_t *p, const char **why);
/* RFC 5155 s5: the hash of `name` (absolute, any case) as 32 lower-case base32hex characters + NUL in out[33]. */
bool presigned_nsec3_hash(const char *name, const presigned_n3param_t *p, char out[33]);

/* The missing RRs of the presigned zone whose parsed rows are arena[0..count).  apex: canonical absolute zone name.
 * nsec3param: the NSEC3PARAM metadata or NULL.  ordernames: NULL or an array parallel to the records of the arena
 * (NULL entries = ordername NULL).  ents: the ENT rows of the DB (their ordername is checked; may be NULL, n_ents 0).
 * 0 = ok (out->mode PS_NONE: nothing to add); -1 = the zone fails, err says why (first offending name / hash). */
int presigned_rebuild(const zone_arena_t *arena, const char *apex, const char *nsec3param,
                      const char *const *ordernames, const presigned_ent_t *ents, size_t n_ents,
                      presigned_out_t *out, char *err, size_t errlen);
void presigned_out_free(presigned_out_t *out);

#endif
