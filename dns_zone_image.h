#ifndef DNS_ZONE_IMAGE_H
#define DNS_ZONE_IMAGE_H

/*
 * S5 Phase B: the compact, immutable zone image.
 *
 * A zone_image_t is one malloc block holding everything the serving side reads of one version of a zone:
 * owner names, RRs (RDATA in uncompressed wire form), a name hash, canonical (RFC 4034 §6.1) order, the NSEC and
 * NSEC3 (RFC 5155 §7.2.8 hash order) indexes, glue targets and the rarely used per-RR extras. Everything is
 * addressed by offset, so the block can be copied or mapped as is.
 *
 * Built from a zone_arena_t (the "builder", filled by a parser, an UPDATE or an AXFR) after build_zone_index() by
 * zone_image_freeze(); turned back into a builder by zone_image_thaw() (UPDATE). The image is never modified after
 * freeze, so any number of threads may read it (CLAUDE.md §3: lock-free reads).
 *
 * Contract with serialize_dns_record(): for a record that was loaded by the server (dns_record_preparse_cache()
 * has run) image_serialize_rr() writes the same bytes, returns the same status and leaves the same compression
 * state, for any message size, owner override and compress_ctx_t. RDATA is stored uncompressed; the types whose
 * names serialize_dns_record() compresses (RFC 1035 §4.1.4) are listed in dns_rdata_name_layout() (dns_wire.c).
 *
 * Nothing on the query path allocates (CLAUDE.md Rule 1): the accessors decode into caller buffers.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "dns_wire.h"
#include "dns_zone_parser.h"

#define ZONE_IMAGE_NONE 0xFFFFFFFFu
#define ZONE_IMAGE_MAGIC 0x4B5A4931u /* "KZI1" */
#define ZONE_IMAGE_VERSION 1u

/* zone_image_t.flags */
#define ZONE_IMAGE_F_TINYDNS 0x1u /* the zone was loaded from tinydns data (is_tinydns_format) */
#define ZONE_IMAGE_F_EXT     0x2u /* at least one RR has an ext[] entry */
#define ZONE_IMAGE_F_WILDCARD 0x4u /* some owner is a wildcard (first label "*"): lets the engine skip the wildcard search of a zone without one */
#define ZONE_IMAGE_F_DNAME    0x8u /* some owner has a DNAME RRset: lets the engine skip the DNAME search of a zone without one */
#define ZONE_IMAGE_F_PERM     0x10u /* the file (builder) order of the RRs differs from the image order: perm[] lists the RR indexes in that order (AXFR out and thaw use it) */
#define ZONE_IMAGE_F_VIEW     0x40u /* B8t-1: some RR is seen only by some clients or at some times (tinydns location / time stamp / countdown, $LOCATION / $ECS-SUBNET tag); an ext[] entry that only keeps an owner spelling (alt text) does not count */
#define ZONE_IMAGE_F_SOA_ATTR 0x20u /* B8t-1: some apex SOA RR is restricted (tinydns location / time stamp, $LOCATION / $ECS-SUBNET tag): a client may see no SOA of the zone, and the SOA it sees is the first visible one */
#define ZONE_IMAGE_F_CUT 0x100u /* E3: some owner other than the apex has an NS RR (a zone cut, ZONE_IMAGE_NAME_CUT): lets find_delegation() skip the walk up the name of a zone without one */
#define ZONE_IMAGE_F_ALIAS 0x80u /* B9a: some owner has an ALIAS RRset (TYPE 65401 of CLASS IN): lets the alias module and the engine skip a zone without one */

/* zone_image_name_t.rr_count_flags: low 24 bits RR count, high 8 bits flags */
#define ZONE_IMAGE_NAME_COUNT_MASK 0x00FFFFFFu
#define ZONE_IMAGE_NAME_WILDCARD   (1u << 24) /* first label is "*" */
#define ZONE_IMAGE_NAME_CUT        (1u << 25) /* NS RRset below the apex (zone cut) */
#define ZONE_IMAGE_NAME_DNAME      (1u << 26) /* DNAME RRset */
#define ZONE_IMAGE_NAME_APEX       (1u << 27)
#define ZONE_IMAGE_NAME_NSEC       (1u << 28) /* has an NSEC RR */
#define ZONE_IMAGE_NAME_GLUE       (1u << 29) /* prelinked glue target: among the first MAX_PRELINK_TARGETS (256) distinct NS/MX/SRV targets in record order and has A/AAAA RRs here (what zone_glue_track_build() links); the engine answers it with the RRs in RR order (see append_glue_records) */
#define ZONE_IMAGE_NAME_ALIAS      (1u << 30) /* B9a: has an ALIAS RR (TYPE 65401, CLASS IN) */

/* zone_image_rr_t.flags */
#define ZONE_IMAGE_RR_RAW        0x1u /* RDATA written as is (generic_data / KARIDNS_EXT class): never compressed */
#define ZONE_IMAGE_RR_NO_NAMEWIRE 0x2u /* record had no preparsed owner wire (rdata_count == 0): see image_serialize_rr */

/* 24 bytes */
typedef struct {
    uint32_t hash;           /* dns_name_hash_ci(text) */
    uint32_t wire_off;       /* owner as uncompressed wire, case as written (strings area); 0 = not encodable */
    uint32_t text_off;       /* owner as canonical text (dns_wire.h), case as written, NUL terminated */
    uint32_t first_rr;       /* RRs of the owner are rrs[first_rr .. first_rr + count), in builder (file) order */
    uint32_t rr_count_flags; /* ZONE_IMAGE_NAME_* | count */
    uint32_t canon_rank;     /* position in canon[], ZONE_IMAGE_NONE when another owner with the same canonical form
                                (compare_canonical_name() == 0) represents it there */
} zone_image_name_t;

/* 24 bytes */
typedef struct {
    uint32_t name_id;
    uint32_t ttl;        /* final TTL as serialize_dns_record() resolves it (ttl_value, else the TTL text; <= 0x7FFFFFFF) */
    uint32_t rdata_off;  /* uncompressed RDATA (strings area) */
    uint32_t ext_idx;    /* 0 = none, otherwise index + 1 into ext[] */
    uint16_t type;
    uint16_t class_val;  /* resolved CLASS (1 when the record had none) */
    uint16_t rdata_len;
    uint16_t flags;      /* ZONE_IMAGE_RR_* */
} zone_image_rr_t;

/* 32 bytes. Only for RRs that need it: tinydns time stamps / location, $LOCATION and $ECS-SUBNET tags, and an owner
 * spelled differently from the first RR of the same name (the wire form keeps the case as written, so the answer
 * must too). */
typedef struct {
    int64_t ttd;            /* tinydns_ttd (time_t) */
    uint32_t ecs_tag_off;   /* strings offset, 0 = none */
    uint32_t loc_tag_off;
    uint32_t alt_text_off;  /* this RR's own owner spelling when it differs from the name entry, 0 = same */
    uint32_t alt_wire_off;
    char loc[2];            /* tinydns_loc, {0,0} = no restriction */
    uint8_t flags;          /* ZONE_IMAGE_EXT_* */
    uint8_t pad;
} zone_image_ext_t;
#define ZONE_IMAGE_EXT_COUNTDOWN 0x1u /* tinydns_ttl_countdown */

/* 16 bytes: the NSEC3 RRs with one (algorithm, iterations, salt), sorted in hash order (RFC 5155 §7.2.8). */
typedef struct {
    uint32_t first;       /* index into the NSEC3 entry array */
    uint32_t count;
    uint32_t salt_off;    /* raw salt octets, strings area (0 when salt_len == 0) */
    uint16_t iterations;
    uint8_t algorithm;
    uint8_t salt_len;
} zone_image_n3chain_t;

typedef struct zone_image_s {
    uint32_t magic, version, total_size, flags;
    uint32_t n_names, n_rrs, n_ext, n_canon, n_nsec, n_n3chains, n_n3entries, n_glue, hash_size;
    uint32_t off_names, off_rrs, off_ext, off_hash, off_canon, off_nsec, off_n3chains, off_n3entries, off_glue,
             off_zattr, off_strings;
    uint32_t off_perm;      /* RR indexes in builder (file) order, 0 = same as the image order (ZONE_IMAGE_F_PERM) */
    uint32_t zattr_len;
    uint32_t apex_name;     /* name id of the apex, ZONE_IMAGE_NONE when the zone has no data at the apex */
    uint32_t n3_param_rr;   /* the NSEC3PARAM RR the denial proofs use (nsec3_params_t.param), ZONE_IMAGE_NONE */
    uint32_t n3_chain;      /* its chain, ZONE_IMAGE_NONE when it has none */
    uint32_t n3_salt_off;
    uint16_t n3_iterations;
    uint8_t n3_algorithm;
    uint8_t n3_salt_len;
    uint32_t reserved_;
} zone_image_t;

/* ---- build and release (load path, not the query path: these allocate) ---- */

/* Freeze a builder into an image. `builder` must have been indexed by build_zone_index() (and have had
 * zone_arena_drop_unencodable() run: an RR that serialize_dns_record() cannot write makes the freeze fail, so
 * the image never holds a record it cannot serve). `apex` is the zone name. NULL on failure (the cause is logged
 * with syslog); the builder is not modified. */
zone_image_t *zone_image_freeze(const zone_arena_t *builder, const char *apex);
void zone_image_free(zone_image_t *img);
/* Rebuild a builder from an image: records in file order (zone_image_seq_rr(); the order the zone was frozen in),
 * text RDATA made from the wire form the way AXFR / UPDATE records are (parse_resource_record()), tinydns / tag
 * extras and the zone level tables restored, indexes built (build_zone_index(builder, false)). `builder` must be
 * a zone_arena_init()ed, empty arena. 0 = success. */
int zone_image_thaw(const zone_image_t *img, zone_arena_t *builder);

/* ---- raw views ---- */
static inline const uint8_t *zone_image_base(const zone_image_t *img) { return (const uint8_t *)img; }
static inline const char *zone_image_str(const zone_image_t *img, uint32_t off) {
    return off ? (const char *)zone_image_base(img) + img->off_strings + off : NULL;
}
static inline const uint8_t *zone_image_bytes(const zone_image_t *img, uint32_t off) {
    return off ? zone_image_base(img) + img->off_strings + off : NULL;
}
static inline const zone_image_name_t *zone_image_names(const zone_image_t *img) {
    return (const zone_image_name_t *)(const void *)(zone_image_base(img) + img->off_names);
}
static inline const zone_image_rr_t *zone_image_rrs(const zone_image_t *img) {
    return (const zone_image_rr_t *)(const void *)(zone_image_base(img) + img->off_rrs);
}
static inline const zone_image_ext_t *zone_image_exts(const zone_image_t *img) {
    return (const zone_image_ext_t *)(const void *)(zone_image_base(img) + img->off_ext);
}
static inline const uint32_t *zone_image_u32s(const zone_image_t *img, uint32_t off) {
    return (const uint32_t *)(const void *)(zone_image_base(img) + off);
}
static inline const zone_image_n3chain_t *zone_image_n3chains(const zone_image_t *img) {
    return (const zone_image_n3chain_t *)(const void *)(zone_image_base(img) + img->off_n3chains);
}

/* ---- names ---- */
/* Name id of `name` (canonical text, any case, with or without the root '.'; the same matching as
 * domain_names_match_ci()), ZONE_IMAGE_NONE when the zone has no RR at that owner. */
uint32_t zone_image_find_name(const zone_image_t *img, const char *name);
static inline const char *zone_image_name_text(const zone_image_t *img, uint32_t name_id) {
    return zone_image_str(img, zone_image_names(img)[name_id].text_off);
}
static inline uint32_t zone_image_name_first_rr(const zone_image_t *img, uint32_t name_id) {
    return zone_image_names(img)[name_id].first_rr;
}
static inline uint32_t zone_image_name_rr_count(const zone_image_t *img, uint32_t name_id) {
    return zone_image_names(img)[name_id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK;
}
static inline uint32_t zone_image_name_flags(const zone_image_t *img, uint32_t name_id) {
    return zone_image_names(img)[name_id].rr_count_flags & ~ZONE_IMAGE_NAME_COUNT_MASK;
}

/* ---- RRs ---- */
static inline uint32_t zone_image_rr_name(const zone_image_t *img, uint32_t rr) { return zone_image_rrs(img)[rr].name_id; }
static inline uint16_t zone_image_rr_type(const zone_image_t *img, uint32_t rr) { return zone_image_rrs(img)[rr].type; }
static inline uint16_t zone_image_rr_class(const zone_image_t *img, uint32_t rr) { return zone_image_rrs(img)[rr].class_val; }
static inline uint32_t zone_image_rr_ttl(const zone_image_t *img, uint32_t rr) { return zone_image_rrs(img)[rr].ttl; }
static inline const uint8_t *zone_image_rr_rdata(const zone_image_t *img, uint32_t rr) {
    return zone_image_bytes(img, zone_image_rrs(img)[rr].rdata_off);
}
static inline uint16_t zone_image_rr_rdlen(const zone_image_t *img, uint32_t rr) { return zone_image_rrs(img)[rr].rdata_len; }
/* NULL when the RR has no extras */
static inline const zone_image_ext_t *zone_image_rr_ext(const zone_image_t *img, uint32_t rr) {
    uint32_t e = zone_image_rrs(img)[rr].ext_idx;
    return e ? &zone_image_exts(img)[e - 1] : NULL;
}
/* The next RR of the RRset (name_id, type) at or after `from`; ZONE_IMAGE_NONE at the end. Start with
 * from = zone_image_name_first_rr(); continue with the returned index + 1. */
uint32_t zone_image_rrset_next(const zone_image_t *img, uint32_t name_id, uint16_t type, uint32_t from);

/* Write one RR like serialize_dns_record(res, max_res_len, offset_ptr, rec, comp_ctx, owner_name, ttl-ish):
 * `owner_name` NULL = the owner of the RR (case as written), else that name (a wildcard expansion's QNAME);
 * `ttl` is the final TTL to write (zone_image_rr_ttl(), or what the caller computed from the tinydns extras or
 * min()ed with an override). 0 = written, -1 = does not fit or cannot be written (*offset_ptr is then unchanged, like serialize_dns_record()).
 * The compression state is updated exactly as serialize_dns_record() does. With comp_ctx NULL the output equals
 * serialize_dns_record(.., NULL, ..) for a preparsed record. */
int image_serialize_rr(const zone_image_t *img, uint32_t rr, uint8_t *res, size_t max_res_len, uint16_t *offset_ptr,
                       compress_ctx_t *comp_ctx, const char *owner_name, uint32_t ttl);

/* ---- decoding accessors (no allocation; names are written to the caller's buffer, DNS_NAME_TEXT_SIZE is
 *      always enough; 0 = ok, -1 = the RR is not of that type or its RDATA is malformed) ---- */
/* The first domain name of the RDATA, for the types in dns_rdata_name_layout(): the target of NS MD MF CNAME MB
 * MG MR PTR NSAP-PTR DNAME, the EXCHANGE of MX, the target of SRV, the MNAME of SOA, the next name of NSEC / NXT,
 * the signer of SIG / RRSIG, ... Same text form as expand_wire_name_to_buffer(). */
int zone_image_rr_target(const zone_image_t *img, uint32_t rr, char *buf, size_t cap);
/* Both names of an SOA (RFC 1035 §3.3.13) and the five numbers; any pointer may be NULL. */
typedef struct { uint32_t serial, refresh, retry, expire, minimum; } zone_image_soa_t;
int zone_image_soa(const zone_image_t *img, uint32_t rr, char *mname, size_t mcap, char *rname, size_t rcap,
                   zone_image_soa_t *nums);
/* MX preference (RFC 1035 §3.3.9) */
int zone_image_mx_pref(const zone_image_t *img, uint32_t rr, uint16_t *pref);
/* SRV priority / weight / port (RFC 2782) */
int zone_image_srv(const zone_image_t *img, uint32_t rr, uint16_t *priority, uint16_t *weight, uint16_t *port);
/* SOA MINIMUM (RFC 2308 §4: the negative caching TTL), the last 32 bits of the RDATA (RFC 1035 §3.3.13); decodes no names */
static inline int zone_image_soa_minimum(const zone_image_t *img, uint32_t rr, uint32_t *minimum) {
    if (zone_image_rr_type(img, rr) != 6 || zone_image_rr_rdlen(img, rr) < 22) return -1;
    const uint8_t *e = zone_image_rr_rdata(img, rr) + zone_image_rr_rdlen(img, rr) - 4;
    *minimum = ((uint32_t)e[0] << 24) | ((uint32_t)e[1] << 16) | ((uint32_t)e[2] << 8) | e[3];
    return 0;
}
/* RRSIG / SIG (RFC 4034 §3.1) type covered */
int zone_image_rrsig_covered(const zone_image_t *img, uint32_t rr, uint16_t *type_covered);
/* NSEC (RFC 4034 §4.1.2) / NSEC3 (RFC 5155 §3.2.1) type bitmap: is `type` listed? false for a malformed bitmap */
bool zone_image_rr_bitmap_has(const zone_image_t *img, uint32_t rr, uint16_t type);
typedef struct {
    uint8_t algorithm, flags;
    uint16_t iterations;
    const uint8_t *salt;      /* into the image */
    uint8_t salt_len;
    const uint8_t *next;      /* NSEC3 only: Next Hashed Owner Name (raw hash) */
    uint8_t next_len;
} zone_image_nsec3_t;
/* NSEC3 (RFC 5155 §3.2) or NSEC3PARAM (§4.2: next/next_len = NULL/0) fields */
int zone_image_nsec3(const zone_image_t *img, uint32_t rr, zone_image_nsec3_t *out);

/* ---- canonical order (RFC 4034 §6.1) ---- */
static inline uint32_t zone_image_canon_count(const zone_image_t *img) { return img->n_canon; }
static inline uint32_t zone_image_canon_name(const zone_image_t *img, uint32_t pos) {
    return zone_image_u32s(img, img->off_canon)[pos];
}
/* The last position of canon[] whose owner sorts at or before `name` (compare_canonical_name()), ZONE_IMAGE_NONE
 * when `name` sorts before every owner. *exact (optional) tells whether it is equal. */
uint32_t zone_image_canon_floor(const zone_image_t *img, const char *name, bool *exact);

/* ---- NSEC index: the NSEC RRs sorted by owner in canonical order ---- */
static inline uint32_t zone_image_nsec_count(const zone_image_t *img) { return img->n_nsec; }
static inline uint32_t zone_image_nsec_rr(const zone_image_t *img, uint32_t i) { return zone_image_u32s(img, img->off_nsec)[i]; }
/* Index of the last NSEC whose owner sorts at or before `name`, ZONE_IMAGE_NONE when `name` sorts first (the
 * caller wraps around to the last NSEC, RFC 4034 §4.1.1). */
uint32_t zone_image_nsec_floor(const zone_image_t *img, const char *name);

/* ---- NSEC3 index (RFC 5155 §7.2.8) ---- */
static inline uint32_t zone_image_n3chain_count(const zone_image_t *img) { return img->n_n3chains; }
static inline const zone_image_n3chain_t *zone_image_n3chain(const zone_image_t *img, uint32_t c) {
    return &zone_image_n3chains(img)[c];
}
/* RR of entry `i` (0 <= i < count) of chain `c`: in hash order */
static inline uint32_t zone_image_n3chain_rr(const zone_image_t *img, uint32_t c, uint32_t i) {
    return zone_image_u32s(img, img->off_n3entries)[zone_image_n3chains(img)[c].first + i];
}
/* The hash label (first label of the owner, base32hex) of entry i of chain c; *len = its length */
const char *zone_image_n3chain_hash(const zone_image_t *img, uint32_t c, uint32_t i, size_t *len);
/* Chain with these parameters (salt as raw octets), ZONE_IMAGE_NONE when there is none */
uint32_t zone_image_n3chain_find(const zone_image_t *img, uint8_t algorithm, uint16_t iterations,
                                 const uint8_t *salt, size_t salt_len);
/* First entry of chain c whose hash is >= `hash` (base32hex, compared case-insensitively); count when there is none */
uint32_t zone_image_n3chain_lower_bound(const zone_image_t *img, uint32_t c, const char *hash, size_t hash_len);

/* ---- glue targets: names that NS / MX / SRV RRs point to and that have A or AAAA RRs in the zone, in order of
 *      first appearance. The addresses are the A / AAAA RRs of the name (type 1 / 28 in its RR range). ---- */
static inline uint32_t zone_image_glue_count(const zone_image_t *img) { return img->n_glue; }
static inline uint32_t zone_image_glue_name(const zone_image_t *img, uint32_t i) { return zone_image_u32s(img, img->off_glue)[i]; }

/* ---- file order of the RRs ----
 * The RRs of one owner are contiguous in the image (rrs[]); the file (builder) order may interleave owners.
 * Phase A wrote an AXFR in builder order, and thaw gives an UPDATE the builder it had before, so both walk the RRs in
 * this order: seq 0 .. n_rrs - 1 (zone_image_seq_rr()). It is the identity unless ZONE_IMAGE_F_PERM is set. */
static inline uint32_t zone_image_seq_rr(const zone_image_t *img, uint32_t seq) {
    return img->off_perm ? zone_image_u32s(img, img->off_perm)[seq] : seq;
}
/* The reference SOA RR of the zone (B8t-1): the apex SOA that has no location, time stamp or tag if there is one, else
 * the first apex SOA in file order; ZONE_IMAGE_NONE when there is none. Zone-wide values (serial, timers, the
 * transfer frame) come from it. A zone with one SOA (nearly all) returns that SOA. */
uint32_t zone_image_apex_soa(const zone_image_t *img);

/* What one client sees of a zone: its tinydns location (char[2]), tag names and the time (tinydns time stamps).
 * A tag is NULL when the client matches none (an RR with a tag is then not visible). */
typedef struct {
    char loc[2];
    const char *loc_tag;
    const char *ecs_tag;
    time_t now;
} zone_image_view_t;

/* Is RR `rr` visible to a client that has this view? On true *effective_ttl is the TTL to serve it with (a tinydns
 * countdown RR: the time left, 2..3600, as tinydns does). The one implementation behind the query engine and AXFR. */
bool zone_image_rr_valid(const zone_image_t *img, uint32_t rr, time_t now, const char client_loc[2],
                         const char *client_ecs_tag, const char *client_loc_tag, uint32_t *effective_ttl);
static inline bool zone_image_rr_visible(const zone_image_t *img, uint32_t rr, const zone_image_view_t *v,
                                         uint32_t *effective_ttl) {
    return zone_image_rr_valid(img, rr, v->now, v->loc, v->ecs_tag, v->loc_tag, effective_ttl);
}
/* The SOA RR a client with this view sees: the first visible apex SOA RR in file order (tdlookup.c: the first SOA
 * the client can see); ZONE_IMAGE_NONE when it sees none. *effective_ttl may be NULL. */
uint32_t zone_image_visible_soa(const zone_image_t *img, const zone_image_view_t *v, uint32_t *effective_ttl);

/* ---- zone level tables: tinydns locations, $LOCATION-TAG / $ECS-SUBNET-TAG definitions, ECS trusted resolvers
 *      (stored in the image's zattr area; nothing is allocated when they are read) ---- */
const tinydns_location_entry_t *zone_image_locations(const zone_image_t *img, int *count);
#define ZONE_IMAGE_TAGS_LOCATION 0
#define ZONE_IMAGE_TAGS_ECS      1
/* cursor over the tag definitions of one table, and over the CIDRs of one tag */
typedef struct { const uint8_t *p, *end; uint32_t left; } zone_image_tags_t;
typedef struct { const char *tag; uint32_t cidr_count; const uint8_t *p, *end; uint32_t left; } zone_image_tag_t;
/* it->left is the number of definitions */
void zone_image_tags_open(const zone_image_t *img, int kind, zone_image_tags_t *it);
/* next definition (false at the end); the CIDRs of `tag` are read with zone_image_tag_next_cidr() */
bool zone_image_tags_next(zone_image_tags_t *it, zone_image_tag_t *tag);
/* next CIDR of the tag: its text (NULL when the definition has none) and the parsed form */
bool zone_image_tag_next_cidr(zone_image_tag_t *tag, const char **cidr, cidr_entry_t *parsed);
/* ECS trusted resolvers of the zone (Extended AXFR): parsed ACL (count entries, 8-aligned in the image), NULL/0 when none */
const acl_entry_t *zone_image_ecs_trusted(const zone_image_t *img, int *count);
/* True when the image has any zone level table */
bool zone_image_has_zattr(const zone_image_t *img);
/* Copy the zone level tables into the builder `a` (heap copies, freed by zone_arena_destroy()); used by Extended AXFR out. 0 = ok */
int zone_image_zattr_load(const zone_image_t *img, zone_arena_t *a);

/* One RR as a builder record, the way thaw makes it, in `arena` (strings and RDATA are allocated there). The record is
 * not linked into the arena's record array. 0 = ok, -1 = cannot be decoded. Load path only (allocates). */
int zone_image_rr_to_record(const zone_image_t *img, uint32_t rr, zone_arena_t *arena, dns_record_t *rec);

#endif
