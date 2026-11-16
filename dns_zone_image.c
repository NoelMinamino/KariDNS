/*
 * dns_zone_image.c - S5 Phase B: the compact immutable zone image (see dns_zone_image.h).
 *
 * Byte parity with serialize_dns_record() (CLAUDE.md Rule 3/4):
 *  - freeze asks serialize_dns_record() itself for the RDATA (no compress_ctx_t, so every name is expanded and
 *    nothing depends on what was written before) and stores those bytes.  Every RDATA name keeps the case as
 *    written, with or without a context (D17-4, RFC 4343 s2-s4); the lower-case form exists only in
 *    dns_record_canonical_rdata().
 *  - image_serialize_rr() copies the stored bytes and sends the domain names at the places listed in
 *    dns_rdata_name_layout() through compress_name(), the function serialize_dns_record() uses, in the same order,
 *    so the bytes, the status and the compress_ctx_t table are those of serialize_dns_record().
 *  - the owner is written from the stored wire form (case as written) exactly as serialize_dns_record() writes
 *    rec->name_wire, or through write_dns_name_str() for an override name.
 */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include "dns_log.h"
#include <assert.h>

#include "dns_zone_image.h"
#include "dns_utils.h"
#include "dns_cidr.h"
#include "dns_tsig_acl.h"

_Static_assert(sizeof(zone_image_name_t) == 24, "zone_image_name_t");
_Static_assert(sizeof(zone_image_rr_t) == 24, "zone_image_rr_t");
_Static_assert(sizeof(zone_image_ext_t) == 32, "zone_image_ext_t");
_Static_assert(sizeof(zone_image_n3chain_t) == 16, "zone_image_n3chain_t");
_Static_assert(sizeof(zone_image_t) % 8 == 0, "zone_image_t alignment");

#define IMG_MAX_RDLEN 65524u /* 65535 - 11: a root owner and the fixed fields precede the RDATA when captured */
#define IMG_MAX_PRELINK_TARGETS 256 /* MAX_PRELINK_TARGETS in dns_snapshot_rcu.c */
static bool image_soa_restricted(const zone_image_t *img);
#define IMG_FAIL() do { syslog(LOG_ERR, "[Image] freeze failed at dns_zone_image.c:%d", __LINE__); goto out; } while (0)

/* ------------------------------------------------------------------------------------------------------------
 * growable byte buffer
 * ------------------------------------------------------------------------------------------------------------ */
typedef struct {
    uint8_t *p;
    size_t len, cap;
    bool oom;
} sbuf_t;

static bool sb_reserve(sbuf_t *sb, size_t extra) {
    if (sb->oom) return false;
    if (sb->len + extra < sb->len) { sb->oom = true; return false; }
    if (sb->len + extra <= sb->cap) return true;
    size_t ncap = sb->cap ? sb->cap : 1024;
    while (ncap < sb->len + extra) ncap *= 2;
    uint8_t *np = realloc(sb->p, ncap);
    if (!np) { sb->oom = true; return false; }
    sb->p = np;
    sb->cap = ncap;
    return true;
}

/* append; returns the offset of the first byte */
static uint32_t sb_add(sbuf_t *sb, const void *data, size_t n) {
    if (!sb_reserve(sb, n)) return 0;
    uint32_t off = (uint32_t)sb->len;
    if (n) memcpy(sb->p + sb->len, data, n);
    sb->len += n;
    return off;
}

static void sb_u32(sbuf_t *sb, uint32_t v) { sb_add(sb, &v, sizeof(v)); }

/* a NUL terminated copy of s (without s's NUL) at the returned offset; 0 for NULL */
static uint32_t sb_str(sbuf_t *sb, const char *s) {
    if (!s) return 0;
    return sb_add(sb, s, strlen(s) + 1);
}

/* ------------------------------------------------------------------------------------------------------------
 * wire name helpers
 * ------------------------------------------------------------------------------------------------------------ */

/* Length (with the root label) of the uncompressed name at p, -1 if it does not end within avail octets or has a
 * compression pointer / reserved label type. */
static int wire_name_len(const uint8_t *p, size_t avail) {
    size_t i = 0;
    while (i < avail) {
        uint8_t l = p[i];
        if (l == 0) return (int)(i + 1);
        if (l > 63 || i + 1 + l > avail) return -1;
        i += 1 + (size_t)l;
    }
    return -1;
}

/* ------------------------------------------------------------------------------------------------------------
 * freeze
 * ------------------------------------------------------------------------------------------------------------ */
typedef struct {
    const char *text;
    uint32_t hash;
    uint32_t count;
    uint32_t first_rec;
    uint32_t cursor;
} tmp_name_t;

typedef struct {
    uint32_t *tab;      /* name id + 1, 0 = empty */
    size_t mask;
    tmp_name_t *names;
    uint32_t n_names;
} tmp_index_t;

static uint32_t tmp_find(const tmp_index_t *ix, const char *name, uint32_t hash) {
    size_t s = hash & ix->mask;
    for (;;) {
        uint32_t v = ix->tab[s];
        if (v == 0) return ZONE_IMAGE_NONE;
        const tmp_name_t *tn = &ix->names[v - 1];
        if (tn->hash == hash && domain_names_match_ci(tn->text, name)) return v - 1;
        s = (s + 1) & ix->mask;
    }
}

/* the owner wire the record serializes with: its preparsed name_wire, else what the text encodes to; 0 = none */
static int rec_owner_wire(const dns_record_t *rec, const uint8_t **wire, uint8_t *tmp /* 256 */) {
    if (rec->name_wire && rec->name_wire_len > 0) {
        *wire = rec->name_wire;
        return rec->name_wire_len;
    }
    long w = write_uncompressed_name_ext(tmp, 0, 256, rec->name, false);
    if (w <= 0) return 0;
    *wire = tmp;
    return (int)w;
}

static uint16_t rec_class(const dns_record_t *rec) {
    uint16_t class_val = rec->class_val;
    if (class_val == 0) {
        class_val = 1;
        if (rec->class_str) {
            if (strcasecmp(rec->class_str, "CH") == 0) class_val = 3;
            else if (strcasecmp(rec->class_str, "NONE") == 0) class_val = 254;
            else if (strcasecmp(rec->class_str, "ANY") == 0) class_val = 255;
        }
    }
    return class_val;
}

/* the TTL serialize_dns_record() writes for rec with no override */
static uint32_t rec_ttl(const dns_record_t *rec) {
    uint32_t ttl = rec->ttl_value;
    if (ttl == 0 && rec->ttl && *rec->ttl) ttl = parse_ttl_value(rec->ttl);
    if (ttl > 0x7FFFFFFF) ttl = 0x7FFFFFFF;
    return ttl;
}

static size_t round8(size_t v) { return (v + 7) & ~(size_t)7; }

/* zone level tables (tinydns locations, $LOCATION-TAG / $ECS-SUBNET-TAG definitions, ECS trusted resolvers) */
/* a string: length (0xFFFFFFFF = NULL), the octets and a NUL (so the reader can hand out a C string) */
static void put_str(sbuf_t *sb, const char *s) {
    if (!s) { sb_u32(sb, 0xFFFFFFFFu); return; }
    size_t n = strlen(s);
    sb_u32(sb, (uint32_t)n);
    sb_add(sb, s, n + 1);
}

/* M3 step 1: the image of one zone is the same bytes whenever and wherever it is made (the loader builds it, the digest and the byte
 * comparisons of the tests rest on that).  cidr_entry_t and acl_entry_t have padding (2 bytes after is_any, 3 after the last member), which a
 * struct copy leaves as it finds it: the entries are written field by field into a zeroed struct.  A member that is added to either type must
 * be added here (the sizes are asserted, so the compiler says so). */
_Static_assert(sizeof(cidr_entry_t) == 44, "cidr_entry_t is copied field by field into the zone image (zero padding): see cidr_canon()");
_Static_assert(sizeof(tinydns_location_entry_t) == 7, "tinydns_location_entry_t has no padding: it is copied into the zone image as it is");

static void cidr_canon(cidr_entry_t *dst, const cidr_entry_t *src) {
    memset(dst, 0, sizeof(*dst));
    dst->valid = src->valid;
    dst->is_any = src->is_any;
    dst->family = src->family;
    dst->prefix = src->prefix;
    memcpy(dst->addr, src->addr, sizeof(dst->addr));
    memcpy(dst->mask, src->mask, sizeof(dst->mask));
}

static void put_tags(sbuf_t *sb, const ecs_tag_def_t *tags, int count) {
    sb_u32(sb, (uint32_t)(count > 0 && tags ? count : 0));
    if (count <= 0 || !tags) return;
    for (int i = 0; i < count; i++) {
        put_str(sb, tags[i].tag);
        int nc = (tags[i].cidrs && tags[i].cidr_count > 0) ? tags[i].cidr_count : 0;
        sb_u32(sb, (uint32_t)nc);
        for (int j = 0; j < nc; j++) {
            put_str(sb, tags[i].cidrs[j].cidr);
            cidr_entry_t parsed;
            cidr_canon(&parsed, &tags[i].cidrs[j].parsed);
            sb_add(sb, &parsed, sizeof(parsed));
        }
    }
}

/* Layout: u32 nloc, nloc x tinydns_location_entry_t, location tags, ECS tags (put_tags), u32 ntr, ntr strings,
 * u32 nparsed, padding to 8, nparsed x acl_entry_t (the parsed form of the trusted resolvers, what
 * is_ecs_trusted_resolver() matches). The area is empty (zattr_len 0) when the zone has none of them, so a zone
 * without tables pays nothing at freeze or at query time. */
static bool zattr_any(const zone_arena_t *a) {
    return (a->locations && a->location_count > 0) || (a->bind_location_tags && a->bind_location_tag_count > 0) ||
           (a->bind_ecs_tags && a->bind_ecs_tag_count > 0) ||
           (a->bind_ecs_trusted_resolvers && a->bind_ecs_trusted_resolver_count > 0);
}

static void build_zattr(sbuf_t *sb, const zone_arena_t *a) {
    if (!zattr_any(a)) return;
    int nloc = (a->locations && a->location_count > 0) ? a->location_count : 0;
    sb_u32(sb, (uint32_t)nloc);
    for (int i = 0; i < nloc; i++) {
        tinydns_location_entry_t e = a->locations[i];
        sb_add(sb, &e, sizeof(e));
    }
    put_tags(sb, a->bind_location_tags, a->bind_location_tag_count);
    put_tags(sb, a->bind_ecs_tags, a->bind_ecs_tag_count);
    int ntr = (a->bind_ecs_trusted_resolvers && a->bind_ecs_trusted_resolver_count > 0) ? a->bind_ecs_trusted_resolver_count : 0;
    sb_u32(sb, (uint32_t)ntr);
    for (int i = 0; i < ntr; i++) put_str(sb, a->bind_ecs_trusted_resolvers[i]);
    /* the builder's parsed list when it has one (the same count), else parse the strings */
    acl_entry_t *own = NULL;
    const acl_entry_t *parsed = NULL;
    if (ntr > 0) {
        parsed = a->bind_ecs_trusted_resolvers_parsed;
        if (!parsed) parsed = own = acl_list_parse(a->bind_ecs_trusted_resolvers, ntr);
        if (!parsed) sb->oom = true; /* freeze fails: a zone must not lose its own trusted resolvers (it would fall back to the server's) */
    }
    /* review [4]: the parsed entries are copied into the image byte for byte, so the type must stay plain data (no pointer): a change of its
     * size has to be looked at here */
    _Static_assert(sizeof(acl_entry_t) == 48, "acl_entry_t is copied by value into the zone image: keep it free of pointers");
    sb_u32(sb, parsed ? (uint32_t)ntr : 0);
    if (parsed) {
        static const uint8_t zeros[8] = { 0 };
        size_t pad = (8 - (sb->len & 7)) & 7;
        if (pad) sb_add(sb, zeros, pad);
        for (int i = 0; i < ntr; i++) {      /* (zeroed padding: see cidr_canon()) */
            acl_entry_t e;
            memset(&e, 0, sizeof(e));
            cidr_canon(&e.cidr, &parsed[i].cidr);
            e.is_deny = parsed[i].is_deny;
            sb_add(sb, &e, sizeof(e));
        }
    }
    free(own);
}

static bool rec_in_arena(const zone_arena_t *a, const dns_record_t *r, size_t *idx) {
    if (!r || r < a->records || r >= a->records + a->count) return false;
    *idx = (size_t)(r - a->records);
    return true;
}

zone_image_t *zone_image_freeze(const zone_arena_t *a, const char *apex) {
    if (!a || !a->hash_table) {
        syslog(LOG_ERR, "[Image] freeze: the builder has no index (build_zone_index() not run)");
        return NULL;
    }
    const size_t n = a->count;
    if (n >= 0x7FFFFFFFu) return NULL;
    {   /* B9a: ALIAS / LUA rules (RDATA, ALIAS beside A/AAAA or DNSSEC records): a zone that breaks them is not published */
        char why[400];
        parse_error_t pe;
        if (validate_zone_pdns_types(a, &pe, why, sizeof(why)) != 0) {
            syslog(LOG_ERR, "[Image] freeze: %s", why);
            return NULL;
        }
    }

    zone_image_t *img = NULL;
    tmp_index_t ix = { 0 };
    uint32_t *rec_rr = NULL;     /* record index -> image RR index (ZONE_IMAGE_NONE: tombstone) */
    uint32_t *rr_rec = NULL;     /* image RR index -> record index */
    zone_image_name_t *names = NULL;
    zone_image_rr_t *rrs = NULL;
    zone_image_ext_t *exts = NULL;
    size_t n_ext = 0, cap_ext = 0;
    bool has_view = false;   /* ZONE_IMAGE_F_VIEW */
    uint32_t *canon = NULL, *nsec = NULL, *n3entries = NULL, *glue = NULL, *hashtab = NULL, *perm = NULL;
    zone_image_n3chain_t *n3chains = NULL;
    uint8_t *cap = NULL;
    uint8_t *seen = NULL;
    sbuf_t sb = { 0 }, za = { 0 };
    uint32_t n_names = 0, n_rrs = 0;
    uint32_t n_glue = 0, n_n3ch = 0, n_n3e = 0;
    bool ok = false;
    bool has_wild = false;
    bool has_dname = false;
    bool has_alias = false;
    bool has_cut = false;

    /* strings area: offset 0 is "none", so the first 8 octets are padding */
    { uint8_t pad[8] = { 0 }; sb_add(&sb, pad, sizeof(pad)); }

    size_t tab_size = 8;
    while (tab_size < n * 2 + 2) tab_size <<= 1;
    ix.tab = calloc(tab_size, sizeof(uint32_t));
    ix.mask = tab_size - 1;
    ix.names = malloc((n ? n : 1) * sizeof(tmp_name_t));
    uint32_t *rec_name = malloc((n ? n : 1) * sizeof(uint32_t));
    rec_rr = malloc((n ? n : 1) * sizeof(uint32_t));
    cap = malloc(65535);
    if (!ix.tab || !ix.names || !rec_name || !rec_rr || !cap) IMG_FAIL();

    /* 1. owners: one name id per owner (case-insensitive, with or without the root dot), first appearance order */
    for (size_t i = 0; i < n; i++) {
        const dns_record_t *r = &a->records[i];
        rec_name[i] = ZONE_IMAGE_NONE;
        rec_rr[i] = ZONE_IMAGE_NONE;
        if (!r->name) continue;
        uint32_t h = dns_name_hash_ci(r->name);
        uint32_t id = tmp_find(&ix, r->name, h);
        if (id == ZONE_IMAGE_NONE) {
            id = ix.n_names++;
            ix.names[id] = (tmp_name_t){ r->name, h, 0, (uint32_t)i, 0 };
            size_t s = h & ix.mask;
            while (ix.tab[s]) s = (s + 1) & ix.mask;
            ix.tab[s] = id + 1;
        }
        ix.names[id].count++;
        rec_name[i] = id;
        n_rrs++;
    }
    n_names = ix.n_names;
    if (n_names >= 0x7FFFFFFFu) IMG_FAIL();

    /* 2. place the RRs: names in first-appearance order, file order within a name */
    {
        uint32_t run = 0;
        for (uint32_t id = 0; id < n_names; id++) {
            if (ix.names[id].count > ZONE_IMAGE_NAME_COUNT_MASK) {
                syslog(LOG_ERR, "[Image] freeze: more than %u RRs at one owner", ZONE_IMAGE_NAME_COUNT_MASK);
                IMG_FAIL();
            }
            ix.names[id].cursor = run;
            run += ix.names[id].count;
        }
    }
    names = calloc(n_names ? n_names : 1, sizeof(*names));
    rrs = calloc(n_rrs ? n_rrs : 1, sizeof(*rrs));
    rr_rec = malloc((n_rrs ? n_rrs : 1) * sizeof(uint32_t));
    if (!names || !rrs || !rr_rec) IMG_FAIL();
    {
        uint32_t run = 0;
        for (uint32_t id = 0; id < n_names; id++) {
            names[id].first_rr = run;
            names[id].rr_count_flags = ix.names[id].count;
            names[id].canon_rank = ZONE_IMAGE_NONE;
            names[id].hash = ix.names[id].hash;
            run += ix.names[id].count;
        }
    }
    for (size_t i = 0; i < n; i++) {
        if (rec_name[i] == ZONE_IMAGE_NONE) continue;
        uint32_t idx = ix.names[rec_name[i]].cursor++;
        rec_rr[i] = idx;
        rr_rec[idx] = (uint32_t)i;
    }
    /* file (builder) order of the RRs: perm[seq] = RR index. Kept only when it differs from the image order (an
     * owner whose RRs are not contiguous in the file); AXFR out and thaw walk it so they keep Phase A's order */
    {
        bool identity = true;
        uint32_t seq = 0;
        for (size_t i = 0; i < n; i++) {
            if (rec_rr[i] == ZONE_IMAGE_NONE) continue;
            if (rec_rr[i] != seq) identity = false;
            seq++;
        }
        if (!identity) {
            perm = malloc((n_rrs ? n_rrs : 1) * sizeof(uint32_t));
            if (!perm) IMG_FAIL();
            seq = 0;
            for (size_t i = 0; i < n; i++)
                if (rec_rr[i] != ZONE_IMAGE_NONE) perm[seq++] = rec_rr[i];
        }
    }

    /* 3. owner strings (first record of each name) */
    for (uint32_t id = 0; id < n_names; id++) {
        const dns_record_t *r = &a->records[ix.names[id].first_rec];
        names[id].text_off = sb_str(&sb, r->name);
        const uint8_t *w;
        uint8_t wtmp[256];
        int wl = rec_owner_wire(r, &w, wtmp);
        names[id].wire_off = wl > 0 ? sb_add(&sb, w, (size_t)wl) : 0;
    }

    /* the apex, for the name flags */
    uint32_t apex_id = apex ? tmp_find(&ix, apex, dns_name_hash_ci(apex)) : ZONE_IMAGE_NONE;

    /* 4. RRs */
    for (uint32_t k = 0; k < n_rrs; k++) {
        const dns_record_t *r = &a->records[rr_rec[k]];
        zone_image_rr_t *rr = &rrs[k];
        uint32_t id = rec_name[rr_rec[k]];
        rr->name_id = id;
        rr->type = r->type_code;
        rr->class_val = rec_class(r);
        rr->ttl = rec_ttl(r);
        bool raw = r->generic_data != NULL || r->class_val == DNS_CLASS_KARIDNS_EXT;
        if (raw) rr->flags |= ZONE_IMAGE_RR_RAW;
        if (!(r->name_wire && r->name_wire_len > 0)) rr->flags |= ZONE_IMAGE_RR_NO_NAMEWIRE;

        /* RDATA: what serialize_dns_record() writes with no compression context */
        uint16_t len = 0;
        /* review [efficiency 2]: only what the serializer can write (owner "." + 10 + RDATA of generic_len octets) has to be zero, not all 64 KiB */
        if (r->class_val == DNS_CLASS_KARIDNS_EXT && !r->generic_data) memset(cap, 0, 11u + r->generic_len + 16u < 65535u ? 11u + r->generic_len + 16u : 65535u);
        if (serialize_dns_record(cap, 65535, &len, r, NULL, ".", 0xFFFFFFFFu) != 0 || len < 11 || cap[0] != 0) {
            syslog(LOG_ERR, "[Image] freeze: '%s' type %u cannot be written in wire format", r->name, r->type_code);
            IMG_FAIL();
        }
        size_t rdlen = ((size_t)cap[9] << 8) | cap[10];
        if (11 + rdlen != len || rdlen > IMG_MAX_RDLEN) IMG_FAIL();
        uint8_t *rd = cap + 11;
        rr->rdata_len = (uint16_t)rdlen;
        rr->rdata_off = rdlen ? sb_add(&sb, rd, rdlen) : 0;

        /* extras */
        const uint8_t *rw;
        uint8_t wtmp[256];
        int rwl = rec_owner_wire(r, &rw, wtmp);
        bool alt = strcmp(r->name, ix.names[id].text) != 0;
        if (!alt) {
            /* same spelling: the wire form must agree too (it does when name_wire was derived from name) */
            const uint8_t *ew = names[id].wire_off ? sb.p + names[id].wire_off : NULL;
            if ((ew != NULL) != (rwl > 0)) alt = true;
            else if (ew && wire_name_len(ew, 256) != rwl) alt = true;
            else if (ew && memcmp(ew, rw, (size_t)rwl) != 0) alt = true;
        }
        bool restricted = r->tinydns_ttd != 0 || r->tinydns_ttl_countdown || r->tinydns_loc[0] || r->tinydns_loc[1] ||
                          r->ecs_subnet_tag || r->bind_location_tag;
        if (restricted) has_view = true;
        bool need_ext = alt || restricted;
        if (need_ext) {
            if (n_ext == cap_ext) {
                size_t ncap = cap_ext ? cap_ext * 2 : 8;
                zone_image_ext_t *ne = realloc(exts, ncap * sizeof(*exts));
                if (!ne) IMG_FAIL();
                exts = ne;
                cap_ext = ncap;
            }
            zone_image_ext_t *e = &exts[n_ext];
            memset(e, 0, sizeof(*e));
            e->ttd = (int64_t)r->tinydns_ttd;
            if (r->tinydns_ttl_countdown) e->flags |= ZONE_IMAGE_EXT_COUNTDOWN;
            e->loc[0] = r->tinydns_loc[0];
            e->loc[1] = r->tinydns_loc[1];
            e->ecs_tag_off = sb_str(&sb, r->ecs_subnet_tag);
            e->loc_tag_off = sb_str(&sb, r->bind_location_tag);
            if (alt) {
                e->alt_text_off = sb_str(&sb, r->name);
                e->alt_wire_off = rwl > 0 ? sb_add(&sb, rw, (size_t)rwl) : 0;
            }
            n_ext++;
            rr->ext_idx = (uint32_t)n_ext;
        }
    }
    if (sb.oom || sb.len > 0xFFFFF000u) IMG_FAIL();

    /* 5. name flags */
    for (uint32_t k = 0; k < n_rrs; k++) {
        uint32_t id = rrs[k].name_id;
        if (rrs[k].type == 2 && id != apex_id) {
            names[id].rr_count_flags |= ZONE_IMAGE_NAME_CUT;
            has_cut = true;
        }
        else if (rrs[k].type == 39) {
            names[id].rr_count_flags |= ZONE_IMAGE_NAME_DNAME;
            has_dname = true;
        }
        else if (rrs[k].type == 47) names[id].rr_count_flags |= ZONE_IMAGE_NAME_NSEC;
        else if (rrs[k].type == DNS_TYPE_PDNS_ALIAS && rrs[k].class_val == 1) {   /* not the Extended AXFR record of CLASS 65302 */
            names[id].rr_count_flags |= ZONE_IMAGE_NAME_ALIAS;
            has_alias = true;
        }
    }
    for (uint32_t id = 0; id < n_names; id++) {
        const char *t = ix.names[id].text;
        if (t[0] == '*' && t[1] == '.') {
            names[id].rr_count_flags |= ZONE_IMAGE_NAME_WILDCARD;
            has_wild = true;
        }
        if (id == apex_id) {
            names[id].rr_count_flags |= ZONE_IMAGE_NAME_APEX;
            names[id].rr_count_flags &= ~ZONE_IMAGE_NAME_CUT;
        }
    }

    /* 6. canonical order, from the builder's sorted_unique_names */
    if (a->sorted_unique_count > 0) {
        canon = malloc(a->sorted_unique_count * sizeof(uint32_t));
        if (!canon) IMG_FAIL();
        for (size_t i = 0; i < a->sorted_unique_count; i++) {
            const char *t = a->sorted_unique_names[i];
            uint32_t id = t ? tmp_find(&ix, t, dns_name_hash_ci(t)) : ZONE_IMAGE_NONE;
            if (id == ZONE_IMAGE_NONE) {
                syslog(LOG_ERR, "[Image] freeze: canonical name '%s' has no RR", t ? t : "?");
                IMG_FAIL();
            }
            canon[i] = id;
            names[id].canon_rank = (uint32_t)i;
        }
    } else if (n_names > 0) {
        syslog(LOG_ERR, "[Image] freeze: the builder's canonical index is empty");
        IMG_FAIL();
    }
    /* review dns_zone_image.c [8]: every name of the image has exactly one place in the canonical order (a missing name fails above, a
     * name listed twice would overwrite its rank) */
    if (a->sorted_unique_count != n_names) {
        syslog(LOG_ERR, "[Image] freeze: %zu canonical names for %u owner names", a->sorted_unique_count, n_names);
        IMG_FAIL();
    }

    /* 7. NSEC index */
    if (a->nsec_count > 0) {
        nsec = malloc(a->nsec_count * sizeof(uint32_t));
        if (!nsec) IMG_FAIL();
        for (size_t i = 0; i < a->nsec_count; i++) {
            size_t ri;
            if (!rec_in_arena(a, a->nsec_records[i], &ri) || rec_rr[ri] == ZONE_IMAGE_NONE) IMG_FAIL();
            nsec[i] = rec_rr[ri];
        }
    }

    /* 8. NSEC3 chains and parameters */
    uint32_t n3_param_rr = ZONE_IMAGE_NONE, n3_chain = ZONE_IMAGE_NONE, n3_salt_off = 0;
    if (a->nsec3_chain_count > 0) {
        size_t total = 0;
        for (size_t c = 0; c < a->nsec3_chain_count; c++) total += a->nsec3_chains[c].count;
        n3chains = calloc(a->nsec3_chain_count, sizeof(*n3chains));
        n3entries = malloc((total ? total : 1) * sizeof(uint32_t));
        if (!n3chains || !n3entries) IMG_FAIL();
        for (size_t c = 0; c < a->nsec3_chain_count; c++) {
            const nsec3_chain_t *ch = &a->nsec3_chains[c];
            /* the salt as the first RR of the chain carries it on the wire (the chain was grouped by its text) */
            size_t ri0;
            if (ch->count == 0 || !rec_in_arena(a, ch->entries[0].rec, &ri0) || rec_rr[ri0] == ZONE_IMAGE_NONE) IMG_FAIL();
            const zone_image_rr_t *r0 = &rrs[rec_rr[ri0]];
            const uint8_t *rd0 = sb.p + r0->rdata_off;
            if (r0->rdata_len < 5 || (size_t)rd0[4] + 5 > r0->rdata_len) IMG_FAIL();
            const uint8_t *salt = rd0 + 5;
            size_t sl = rd0[4];
            n3chains[c].first = n_n3e;
            n3chains[c].count = (uint32_t)ch->count;
            n3chains[c].algorithm = ch->algorithm;
            n3chains[c].iterations = ch->iterations;
            n3chains[c].salt_len = (uint8_t)sl;
            { uint8_t keep[255]; memcpy(keep, salt, sl); n3chains[c].salt_off = sl ? sb_add(&sb, keep, sl) : 0; }
            for (size_t e = 0; e < ch->count; e++) {
                size_t ri;
                if (!rec_in_arena(a, ch->entries[e].rec, &ri) || rec_rr[ri] == ZONE_IMAGE_NONE) IMG_FAIL();
                n3entries[n_n3e++] = rec_rr[ri];
            }
        }
        n_n3ch = (uint32_t)a->nsec3_chain_count;
    }
    if (a->nsec3_active.param) {
        size_t ri;
        if (!rec_in_arena(a, a->nsec3_active.param, &ri) || rec_rr[ri] == ZONE_IMAGE_NONE) IMG_FAIL();
        n3_param_rr = rec_rr[ri];
        if (a->nsec3_active.chain) {
            ptrdiff_t ci = a->nsec3_active.chain - a->nsec3_chains;
            if (ci < 0 || (size_t)ci >= a->nsec3_chain_count) IMG_FAIL();
            n3_chain = (uint32_t)ci;
        }
        if (a->nsec3_active.salt_len) n3_salt_off = sb_add(&sb, a->nsec3_active.salt, a->nsec3_active.salt_len);
    }

    /* 9. glue targets: names NS / MX / SRV RRs point to that have A / AAAA RRs here (first appearance order) */
    seen = calloc(n_names ? n_names : 1, 1);
    glue = malloc((n_names ? n_names : 1) * sizeof(uint32_t));
    if (!seen || !glue) IMG_FAIL();
    /* ZONE_IMAGE_NAME_GLUE mirrors zone_glue_track_build(): its target list holds the first
     * IMG_MAX_PRELINK_TARGETS distinct targets in record order, whether or not they have addresses here */
    const char *prelink_targets[IMG_MAX_PRELINK_TARGETS];
    int n_prelink = 0;
    for (size_t i = 0; i < n; i++) {
        const dns_record_t *r = &a->records[i];
        const char *tgt = NULL;
        if (!r->name) continue;
        if (r->type_code == 2 && r->rdata_count >= 1) tgt = r->rdata[0];
        else if (r->type_code == 15 && r->rdata_count >= 2) tgt = r->rdata[1];
        else if (r->type_code == 33 && r->rdata_count >= 4) tgt = r->rdata[3];
        if (!tgt || *tgt == '\0') continue;
        bool in_prelink = false, dup = false;
        /* review [efficiency 1]: once the list is full nothing more is added, so the duplicate scan is not needed */
        if (n_prelink < IMG_MAX_PRELINK_TARGETS) {
            for (int k = 0; k < n_prelink; k++)
                if (domain_names_match_ci(prelink_targets[k], tgt)) { dup = true; break; }
            if (!dup) {
                prelink_targets[n_prelink++] = tgt;
                in_prelink = true;
            }
        }
        uint32_t id = tmp_find(&ix, tgt, dns_name_hash_ci(tgt));
        if (id == ZONE_IMAGE_NONE) continue;
        bool has_addr = false;
        for (uint32_t k = names[id].first_rr, e = k + (names[id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK); k < e; k++)
            if (rrs[k].type == 1 || rrs[k].type == 28) { has_addr = true; break; }
        if (has_addr && in_prelink) names[id].rr_count_flags |= ZONE_IMAGE_NAME_GLUE;
        if (seen[id]) continue;
        seen[id] = 1;
        if (has_addr) glue[n_glue++] = id;
    }

    /* 10. name hash table, load factor <= 0.75 */
    size_t hash_size = 4;
    while (hash_size * 3 < (size_t)n_names * 4) hash_size <<= 1;
    hashtab = calloc(hash_size, sizeof(uint32_t));
    if (!hashtab) IMG_FAIL();
    for (uint32_t id = 0; id < n_names; id++) {
        size_t s = names[id].hash & (hash_size - 1);
        while (hashtab[s]) s = (s + 1) & (hash_size - 1);
        hashtab[s] = id + 1;
    }

    /* 11. zone level tables */
    build_zattr(&za, a);
    if (sb.oom || za.oom) IMG_FAIL();

    /* 12. assemble */
    {
        size_t n_canon = a->sorted_unique_count;
        size_t off = sizeof(zone_image_t);
        size_t o_names = off;  off = round8(off + (size_t)n_names * sizeof(zone_image_name_t));
        size_t o_rrs = off;    off = round8(off + (size_t)n_rrs * sizeof(zone_image_rr_t));
        size_t o_ext = off;    off = round8(off + n_ext * sizeof(zone_image_ext_t));
        size_t o_n3c = off;    off = round8(off + (size_t)n_n3ch * sizeof(zone_image_n3chain_t));
        size_t o_hash = off;   off = round8(off + hash_size * sizeof(uint32_t));
        size_t o_canon = off;  off = round8(off + n_canon * sizeof(uint32_t));
        size_t o_nsec = off;   off = round8(off + a->nsec_count * sizeof(uint32_t));
        size_t o_n3e = off;    off = round8(off + (size_t)n_n3e * sizeof(uint32_t));
        size_t o_glue = off;   off = round8(off + (size_t)n_glue * sizeof(uint32_t));
        size_t o_perm = off;   off = round8(off + (perm ? (size_t)n_rrs * sizeof(uint32_t) : 0));
        size_t o_zattr = off;  off = round8(off + za.len);
        size_t o_str = off;    off = round8(off + sb.len);
        if (off > 0xFFFFF000u) {
            syslog(LOG_ERR, "[Image] freeze: the image would exceed 4 GiB");
            IMG_FAIL();
        }
        img = calloc(1, off);
        if (!img) IMG_FAIL();
        uint8_t *b = (uint8_t *)img;
        img->magic = ZONE_IMAGE_MAGIC;
        img->version = ZONE_IMAGE_VERSION;
        img->total_size = (uint32_t)off;
        img->flags = (a->is_tinydns_format ? ZONE_IMAGE_F_TINYDNS : 0) | (n_ext ? ZONE_IMAGE_F_EXT : 0) | (has_view ? ZONE_IMAGE_F_VIEW : 0) | (has_wild ? ZONE_IMAGE_F_WILDCARD : 0) | (has_dname ? ZONE_IMAGE_F_DNAME : 0) | (has_alias ? ZONE_IMAGE_F_ALIAS : 0) | (has_cut ? ZONE_IMAGE_F_CUT : 0) | (perm ? ZONE_IMAGE_F_PERM : 0);
        img->off_perm = perm ? (uint32_t)o_perm : 0;
        img->n_names = n_names; img->n_rrs = n_rrs; img->n_ext = (uint32_t)n_ext;
        img->n_canon = (uint32_t)n_canon; img->n_nsec = (uint32_t)a->nsec_count;
        img->n_n3chains = n_n3ch; img->n_n3entries = n_n3e; img->n_glue = n_glue; img->hash_size = (uint32_t)hash_size;
        img->off_names = (uint32_t)o_names; img->off_rrs = (uint32_t)o_rrs; img->off_ext = (uint32_t)o_ext;
        img->off_hash = (uint32_t)o_hash; img->off_canon = (uint32_t)o_canon; img->off_nsec = (uint32_t)o_nsec;
        img->off_n3chains = (uint32_t)o_n3c; img->off_n3entries = (uint32_t)o_n3e; img->off_glue = (uint32_t)o_glue;
        img->off_zattr = (uint32_t)o_zattr; img->off_strings = (uint32_t)o_str;
        img->zattr_len = (uint32_t)za.len;
        img->apex_name = apex_id;
        img->n3_param_rr = n3_param_rr; img->n3_chain = n3_chain; img->n3_salt_off = n3_salt_off;
        img->n3_iterations = a->nsec3_active.param ? a->nsec3_active.iterations : 0;
        img->n3_algorithm = a->nsec3_active.param ? a->nsec3_active.algorithm : 0;
        img->n3_salt_len = a->nsec3_active.param ? a->nsec3_active.salt_len : 0;
        if (n_names) memcpy(b + o_names, names, (size_t)n_names * sizeof(*names));
        if (n_rrs) memcpy(b + o_rrs, rrs, (size_t)n_rrs * sizeof(*rrs));
        if (n_ext) memcpy(b + o_ext, exts, n_ext * sizeof(*exts));
        if (n_n3ch) memcpy(b + o_n3c, n3chains, (size_t)n_n3ch * sizeof(*n3chains));
        memcpy(b + o_hash, hashtab, hash_size * sizeof(uint32_t));
        if (n_canon) memcpy(b + o_canon, canon, n_canon * sizeof(uint32_t));
        if (a->nsec_count) memcpy(b + o_nsec, nsec, a->nsec_count * sizeof(uint32_t));
        if (n_n3e) memcpy(b + o_n3e, n3entries, (size_t)n_n3e * sizeof(uint32_t));
        if (n_glue) memcpy(b + o_glue, glue, (size_t)n_glue * sizeof(uint32_t));
        if (perm) memcpy(b + o_perm, perm, (size_t)n_rrs * sizeof(uint32_t));
        if (za.len) memcpy(b + o_zattr, za.p, za.len);
        memcpy(b + o_str, sb.p, sb.len);
        if (image_soa_restricted(img)) img->flags |= ZONE_IMAGE_F_SOA_ATTR;
    }
    ok = true;

out:
    if (!ok) {
        free(img);
        img = NULL;
    }
    free(ix.tab); free(ix.names); free(rec_name); free(rec_rr); free(rr_rec); free(names); free(rrs); free(exts);
    free(canon); free(nsec); free(n3chains); free(n3entries); free(glue); free(hashtab); free(cap); free(seen);
    free(perm);
    free(sb.p); free(za.p);
    return img;
}

void zone_image_free(zone_image_t *img) { free(img); }

/* ------------------------------------------------------------------------------------------------------------
 * lookups
 * ------------------------------------------------------------------------------------------------------------ */
uint32_t zone_image_find_name(const zone_image_t *img, const char *name) {
    if (!img || !name || img->n_names == 0) return ZONE_IMAGE_NONE;
    uint32_t h = dns_name_hash_ci(name);
    const uint32_t *tab = zone_image_u32s(img, img->off_hash);
    const zone_image_name_t *names = zone_image_names(img);
    size_t mask = (size_t)img->hash_size - 1;
    for (size_t s = h & mask;; s = (s + 1) & mask) {
        uint32_t v = tab[s];
        if (v == 0) return ZONE_IMAGE_NONE;
        if (names[v - 1].hash == h && domain_names_match_ci(zone_image_str(img, names[v - 1].text_off), name)) return v - 1;
    }
}

uint32_t zone_image_rrset_next(const zone_image_t *img, uint32_t name_id, uint16_t type, uint32_t from) {
    const zone_image_name_t *nm = &zone_image_names(img)[name_id];
    uint32_t end = nm->first_rr + (nm->rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
    const zone_image_rr_t *rrs = zone_image_rrs(img);
    if (from < nm->first_rr) from = nm->first_rr;
    for (uint32_t k = from; k < end; k++)
        if (rrs[k].type == type) return k;
    return ZONE_IMAGE_NONE;
}

uint32_t zone_image_canon_floor(const zone_image_t *img, const char *name, bool *exact) {
    if (exact) *exact = false;
    if (!img || !name || img->n_canon == 0) return ZONE_IMAGE_NONE;
    uint32_t lo = 0, hi = img->n_canon, best = ZONE_IMAGE_NONE;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        int c = compare_canonical_name(zone_image_name_text(img, zone_image_canon_name(img, mid)), name);
        if (c <= 0) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (exact && best != ZONE_IMAGE_NONE)
        *exact = compare_canonical_name(zone_image_name_text(img, zone_image_canon_name(img, best)), name) == 0;
    return best;
}

uint32_t zone_image_nsec_floor(const zone_image_t *img, const char *name) {
    if (!img || !name || img->n_nsec == 0) return ZONE_IMAGE_NONE;
    uint32_t lo = 0, hi = img->n_nsec, best = ZONE_IMAGE_NONE;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t rr = zone_image_nsec_rr(img, mid);
        if (compare_canonical_name(zone_image_name_text(img, zone_image_rr_name(img, rr)), name) <= 0) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return best;
}

const char *zone_image_n3chain_hash(const zone_image_t *img, uint32_t c, uint32_t i, size_t *len) {
    uint32_t rr = zone_image_n3chain_rr(img, c, i);
    const char *t = zone_image_name_text(img, zone_image_rr_name(img, rr));
    const char *dot = strchr(t, '.');
    if (len) *len = dot ? (size_t)(dot - t) : strlen(t);
    return t;
}

uint32_t zone_image_n3chain_find(const zone_image_t *img, uint8_t algorithm, uint16_t iterations,
                                 const uint8_t *salt, size_t salt_len) {
    for (uint32_t c = 0; c < img->n_n3chains; c++) {
        const zone_image_n3chain_t *ch = &zone_image_n3chains(img)[c];
        if (ch->algorithm == algorithm && ch->iterations == iterations && ch->salt_len == salt_len &&
            (salt_len == 0 || memcmp(zone_image_bytes(img, ch->salt_off), salt, salt_len) == 0))
            return c;
    }
    return ZONE_IMAGE_NONE;
}

uint32_t zone_image_n3chain_lower_bound(const zone_image_t *img, uint32_t c, const char *hash, size_t hash_len) {
    uint32_t lo = 0, hi = zone_image_n3chains(img)[c].count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        size_t el;
        const char *eh = zone_image_n3chain_hash(img, c, mid, &el);
        int cmp = strncasecmp(eh, hash, el < hash_len ? el : hash_len);
        if (cmp == 0) cmp = el < hash_len ? -1 : (el > hash_len ? 1 : 0);
        if (cmp < 0) lo = mid + 1; else hi = mid;
    }
    return lo;
}

/* ------------------------------------------------------------------------------------------------------------
 * writing an RR
 * ------------------------------------------------------------------------------------------------------------ */
int image_serialize_rr(const zone_image_t *img, uint32_t rr_idx, uint8_t *res, size_t max_res_len, uint16_t *offset_ptr,
                       compress_ctx_t *comp_ctx, const char *owner_name, uint32_t ttl) {
    const zone_image_rr_t *rr = &zone_image_rrs(img)[rr_idx];
    const zone_image_name_t *nm = &zone_image_names(img)[rr->name_id];
    const zone_image_ext_t *ext = zone_image_rr_ext(img, rr_idx);
    uint16_t offset = *offset_ptr;
    uint16_t rec_type = rr->type;

    if (is_meta_rrtype(rec_type)) return -1;
    if ((size_t)offset + DNS_HEADER_SIZE > max_res_len) return -1;

    /* owner */
    {
        bool alt = ext && ext->alt_text_off;
        uint32_t woff = alt ? ext->alt_wire_off : nm->wire_off;
        if (!owner_name && woff && (comp_ctx || !(rr->flags & ZONE_IMAGE_RR_NO_NAMEWIRE))) {
            const uint8_t *w = zone_image_bytes(img, woff);
            if (!comp_ctx) {
                int wl = wire_name_len(w, 256);
                if (wl < 0 || (size_t)(offset + wl) > max_res_len) return -1;
                memcpy(&res[offset], w, (size_t)wl);
                offset = (uint16_t)(offset + wl);
            } else if (compress_name(res, &offset, w, comp_ctx, max_res_len) != 0) {
                return -1;
            }
        } else {
            const char *text = owner_name ? owner_name
                             : (alt ? zone_image_str(img, ext->alt_text_off) : zone_image_str(img, nm->text_off));
            if (write_dns_name_str(res, &offset, text, comp_ctx, max_res_len) != 0) return -1;
        }
    }

    if ((size_t)offset + 10 > max_res_len) return -1;
    res[offset++] = rec_type >> 8; res[offset++] = rec_type & 0xFF;
    res[offset++] = rr->class_val >> 8; res[offset++] = rr->class_val & 0xFF;
    if (ttl > 0x7FFFFFFF) ttl = 0x7FFFFFFF;
    res[offset++] = ttl >> 24; res[offset++] = (ttl >> 16) & 0xFF; res[offset++] = (ttl >> 8) & 0xFF; res[offset++] = ttl & 0xFF;
    uint16_t rdlength_idx = offset;
    offset += 2;

    const uint8_t *rd = zone_image_bytes(img, rr->rdata_off);
    size_t len = rr->rdata_len;
    const dns_rdata_name_layout_t *lay = (rr->flags & ZONE_IMAGE_RR_RAW) ? NULL : dns_rdata_name_layout(rec_type);
    if (!lay || !lay->compress) {
        if (len > 0) {
            if ((size_t)offset + len > max_res_len) return -1;
            memcpy(&res[offset], rd, len);
            offset = (uint16_t)(offset + len);
        }
    } else {
        /* RFC 1035 §4.1.4: the names of these types go through the compression table, in order */
        size_t pos = 0;
        if (lay->skip) {
            if (len < lay->skip || (size_t)offset + lay->skip > max_res_len) return -1;
            memcpy(&res[offset], rd, lay->skip);
            offset = (uint16_t)(offset + lay->skip);
            pos = lay->skip;
        }
        for (unsigned k = 0; k < lay->nnames; k++) {
            int wl = pos < len ? wire_name_len(rd + pos, len - pos) : -1;
            if (wl < 0) return -1;
            if (comp_ctx) {
                if (compress_name(res, &offset, rd + pos, comp_ctx, max_res_len) != 0) return -1;
            } else {
                if ((size_t)offset + (size_t)wl > max_res_len) return -1;
                memcpy(&res[offset], rd + pos, (size_t)wl);
                offset = (uint16_t)(offset + wl);
            }
            pos += (size_t)wl;
        }
        if (pos < len) {
            if ((size_t)offset + (len - pos) > max_res_len) return -1;
            memcpy(&res[offset], rd + pos, len - pos);
            offset = (uint16_t)(offset + (len - pos));
        }
    }

    uint16_t rdlength = (uint16_t)(offset - rdlength_idx - 2);
    res[rdlength_idx] = rdlength >> 8; res[rdlength_idx + 1] = rdlength & 0xFF;
    *offset_ptr = offset;
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------
 * decoding accessors
 * ------------------------------------------------------------------------------------------------------------ */
int zone_image_rr_target(const zone_image_t *img, uint32_t rr, char *buf, size_t cap) {
    const dns_rdata_name_layout_t *lay = dns_rdata_name_layout(zone_image_rr_type(img, rr));
    size_t len = zone_image_rr_rdlen(img, rr);
    if (!lay || lay->skip >= len) return -1;
    size_t next;
    return expand_wire_name_to_buffer(zone_image_rr_rdata(img, rr), len, lay->skip, &next, buf, cap) < 0 ? -1 : 0;
}

int zone_image_soa(const zone_image_t *img, uint32_t rr, char *mname, size_t mcap, char *rname, size_t rcap,
                   zone_image_soa_t *nums) {
    if (zone_image_rr_type(img, rr) != 6) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    size_t len = zone_image_rr_rdlen(img, rr), p = 0, next;
    char tmp[DNS_NAME_TEXT_SIZE];
    if (len == 0) return -1;
    if (expand_wire_name_to_buffer(rd, len, p, &next, mname ? mname : tmp, mname ? mcap : sizeof(tmp)) < 0) return -1;
    p = next;
    if (p >= len) return -1;
    if (expand_wire_name_to_buffer(rd, len, p, &next, rname ? rname : tmp, rname ? rcap : sizeof(tmp)) < 0) return -1;
    p = next;
    if (p + 20 != len) return -1;
    if (nums) {
        uint32_t v[5];
        for (int j = 0; j < 5; j++)
            v[j] = ((uint32_t)rd[p + 4 * j] << 24) | ((uint32_t)rd[p + 4 * j + 1] << 16) |
                   ((uint32_t)rd[p + 4 * j + 2] << 8) | rd[p + 4 * j + 3];
        nums->serial = v[0]; nums->refresh = v[1]; nums->retry = v[2]; nums->expire = v[3]; nums->minimum = v[4];
    }
    return 0;
}

int zone_image_mx_pref(const zone_image_t *img, uint32_t rr, uint16_t *pref) {
    if (zone_image_rr_type(img, rr) != 15 || zone_image_rr_rdlen(img, rr) < 3) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    *pref = (uint16_t)((rd[0] << 8) | rd[1]);
    return 0;
}

int zone_image_srv(const zone_image_t *img, uint32_t rr, uint16_t *priority, uint16_t *weight, uint16_t *port) {
    if (zone_image_rr_type(img, rr) != 33 || zone_image_rr_rdlen(img, rr) < 7) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    if (priority) *priority = (uint16_t)((rd[0] << 8) | rd[1]);
    if (weight) *weight = (uint16_t)((rd[2] << 8) | rd[3]);
    if (port) *port = (uint16_t)((rd[4] << 8) | rd[5]);
    return 0;
}

int zone_image_rrsig_covered(const zone_image_t *img, uint32_t rr, uint16_t *type_covered) {
    uint16_t t = zone_image_rr_type(img, rr);
    if ((t != 46 && t != 24) || zone_image_rr_rdlen(img, rr) < 18) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    *type_covered = (uint16_t)((rd[0] << 8) | rd[1]);
    return 0;
}

/* RFC 4034 §4.1.2: windows of (block number, length 1-32, bitmap) in ascending block order */
static bool bitmap_has(const uint8_t *bm, size_t len, uint16_t type) {
    size_t p = 0;
    while (p + 2 <= len) {
        unsigned win = bm[p], blen = bm[p + 1];
        if (blen == 0 || blen > 32 || p + 2 + blen > len) return false;
        if (win == (unsigned)(type >> 8)) {
            unsigned bit = type & 0xFF;
            return bit / 8 < blen && (bm[p + 2 + bit / 8] & (0x80 >> (bit % 8))) != 0;
        }
        if (win > (unsigned)(type >> 8)) return false;
        p += 2 + blen;
    }
    return false;
}

bool zone_image_rr_bitmap_has(const zone_image_t *img, uint32_t rr, uint16_t type) {
    uint16_t t = zone_image_rr_type(img, rr);
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    size_t len = zone_image_rr_rdlen(img, rr);
    if (t == 47) {
        int wl = len ? wire_name_len(rd, len) : -1;
        if (wl < 0) return false;
        return bitmap_has(rd + wl, len - (size_t)wl, type);
    }
    if (t == 50) {
        zone_image_nsec3_t v;
        if (zone_image_nsec3(img, rr, &v) != 0) return false;
        size_t consumed = (size_t)(v.next + v.next_len - rd);
        return bitmap_has(rd + consumed, len - consumed, type);
    }
    return false;
}

int zone_image_nsec3(const zone_image_t *img, uint32_t rr, zone_image_nsec3_t *out) {
    uint16_t t = zone_image_rr_type(img, rr);
    if (t != 50 && t != 51) return -1;
    const uint8_t *rd = zone_image_rr_rdata(img, rr);
    size_t len = zone_image_rr_rdlen(img, rr);
    if (len < 5) return -1;
    size_t sl = rd[4], p = 5 + sl;
    if (p > len) return -1;
    memset(out, 0, sizeof(*out));
    out->algorithm = rd[0];
    out->flags = rd[1];
    out->iterations = (uint16_t)((rd[2] << 8) | rd[3]);
    out->salt = rd + 5;
    out->salt_len = (uint8_t)sl;
    if (t == 51) return p == len ? 0 : -1;
    if (p >= len || rd[p] == 0 || p + 1 + rd[p] > len) return -1;
    out->next_len = rd[p];
    out->next = rd + p + 1;
    return 0;
}

/* ------------------------------------------------------------------------------------------------------------
 * thaw
 * ------------------------------------------------------------------------------------------------------------ */
typedef struct {
    const uint8_t *p;
    size_t len, pos;
    bool bad;
} cursor_t;

static uint32_t get_u32(cursor_t *c) {
    uint32_t v = 0;
    if (c->bad || c->len - c->pos < 4) { c->bad = true; return 0; }
    memcpy(&v, c->p + c->pos, 4);
    c->pos += 4;
    return v;
}

static char *get_str(cursor_t *c) {
    uint32_t n = get_u32(c);
    if (c->bad || n == 0xFFFFFFFFu) return NULL;
    if (n >= c->len || c->len - c->pos < (size_t)n + 1) { c->bad = true; return NULL; }
    char *s = malloc((size_t)n + 1);
    if (!s) { c->bad = true; return NULL; }
    memcpy(s, c->p + c->pos, n);
    s[n] = '\0';
    c->pos += (size_t)n + 1;
    return s;
}

static ecs_tag_def_t *get_tags(cursor_t *c, int *count_out) {
    uint32_t n = get_u32(c);
    *count_out = 0;
    if (c->bad || n == 0) return NULL;
    if (n > c->len) { c->bad = true; return NULL; }
    ecs_tag_def_t *tags = calloc(n, sizeof(*tags));
    if (!tags) { c->bad = true; return NULL; }
    *count_out = (int)n;
    for (uint32_t i = 0; i < n && !c->bad; i++) {
        tags[i].tag = get_str(c);
        uint32_t nc = get_u32(c);
        if (c->bad) break;
        if (nc > c->len) { c->bad = true; break; }
        if (nc) {
            tags[i].cidrs = calloc(nc, sizeof(ecs_cidr_entry_t));
            if (!tags[i].cidrs) { c->bad = true; break; }
            tags[i].cidr_count = (int)nc;
            for (uint32_t j = 0; j < nc && !c->bad; j++) {
                tags[i].cidrs[j].cidr = get_str(c);
                if (c->len - c->pos < sizeof(cidr_entry_t)) { c->bad = true; break; }
                memcpy(&tags[i].cidrs[j].parsed, c->p + c->pos, sizeof(cidr_entry_t));
                c->pos += sizeof(cidr_entry_t);
            }
        }
    }
    return tags;
}

static int thaw_zattr(const zone_image_t *img, zone_arena_t *a) {
    if (img->zattr_len == 0) return 0;
    cursor_t c = { (const uint8_t *)img + img->off_zattr, img->zattr_len, 0, false };
    uint32_t nloc = get_u32(&c);
    if (!c.bad && nloc) {
        if ((size_t)nloc > (c.len - c.pos) / sizeof(tinydns_location_entry_t)) return -1; /* review [2]: what is left, not the whole length */
        a->locations = calloc(nloc, sizeof(tinydns_location_entry_t));
        if (!a->locations) return -1;
        for (uint32_t i = 0; i < nloc; i++) {
            memcpy(&a->locations[i], c.p + c.pos, sizeof(tinydns_location_entry_t));
            c.pos += sizeof(tinydns_location_entry_t);
        }
        a->location_count = (int)nloc;
    }
    a->bind_location_tags = get_tags(&c, &a->bind_location_tag_count);
    a->bind_ecs_tags = get_tags(&c, &a->bind_ecs_tag_count);
    uint32_t ntr = get_u32(&c);
    if (!c.bad && ntr) {
        if (ntr > c.len) return -1;
        a->bind_ecs_trusted_resolvers = calloc(ntr, sizeof(char *));
        if (!a->bind_ecs_trusted_resolvers) return -1;
        a->bind_ecs_trusted_resolver_count = (int)ntr;
        for (uint32_t i = 0; i < ntr && !c.bad; i++) a->bind_ecs_trusted_resolvers[i] = get_str(&c);
        if (!c.bad) {
            a->bind_ecs_trusted_resolvers_parsed = acl_list_parse(a->bind_ecs_trusted_resolvers, (int)ntr);
            /* NULL is out of memory: the zone must not thaw without its own list (it would fall back to the server's;
             * freeze fails the same way) */
            if (!a->bind_ecs_trusted_resolvers_parsed) return -1;
        }
    }
    return c.bad ? -1 : 0;
}

/* ---- zone level tables, read in place (no allocation) ---- */
static const char *zc_str(cursor_t *c) {
    uint32_t n = get_u32(c);
    if (c->bad || n == 0xFFFFFFFFu) return NULL;
    if (n >= c->len || c->len - c->pos < (size_t)n + 1) { c->bad = true; return NULL; }
    const char *s = (const char *)c->p + c->pos;
    c->pos += (size_t)n + 1;
    return s;
}

static void zc_skip_tags(cursor_t *c) {
    uint32_t n = get_u32(c);
    if (c->bad) return;
    if (n > c->len) { c->bad = true; return; }
    for (uint32_t i = 0; i < n && !c->bad; i++) {
        (void)zc_str(c);
        uint32_t nc = get_u32(c);
        if (c->bad) return;
        if (nc > c->len) { c->bad = true; return; }
        for (uint32_t j = 0; j < nc && !c->bad; j++) {
            (void)zc_str(c);
            if (c->len - c->pos < sizeof(cidr_entry_t)) { c->bad = true; return; }
            c->pos += sizeof(cidr_entry_t);
        }
    }
}

static cursor_t zattr_cursor(const zone_image_t *img) {
    cursor_t c = { zone_image_base(img) + img->off_zattr, img->zattr_len, 0, false };
    if (img->zattr_len == 0) c.bad = true;
    return c;
}

bool zone_image_has_zattr(const zone_image_t *img) { return img && img->zattr_len > 0; }

const tinydns_location_entry_t *zone_image_locations(const zone_image_t *img, int *count) {
    *count = 0;
    if (!img) return NULL;
    cursor_t c = zattr_cursor(img);
    uint32_t n = get_u32(&c);
    if (c.bad || n == 0 || (size_t)n > (c.len - c.pos) / sizeof(tinydns_location_entry_t)) return NULL;
    *count = (int)n;
    return (const tinydns_location_entry_t *)(const void *)(c.p + c.pos);
}

void zone_image_tags_open(const zone_image_t *img, int kind, zone_image_tags_t *it) {
    memset(it, 0, sizeof(*it));
    if (!img) return;
    cursor_t c = zattr_cursor(img);
    uint32_t nloc = get_u32(&c);
    if (c.bad || (size_t)nloc > (c.len - c.pos) / sizeof(tinydns_location_entry_t)) return;
    c.pos += (size_t)nloc * sizeof(tinydns_location_entry_t);
    if (kind == ZONE_IMAGE_TAGS_ECS) zc_skip_tags(&c);
    uint32_t n = get_u32(&c);
    if (c.bad) return;
    it->p = c.p + c.pos;
    it->end = c.p + c.len;
    it->left = n;
}

bool zone_image_tags_next(zone_image_tags_t *it, zone_image_tag_t *tag) {
    if (it->left == 0) return false;
    cursor_t c = { it->p, (size_t)(it->end - it->p), 0, false };
    memset(tag, 0, sizeof(*tag));
    tag->tag = zc_str(&c);
    uint32_t nc = get_u32(&c);
    if (c.bad || nc > c.len) { it->left = 0; return false; }
    tag->cidr_count = nc;
    tag->left = nc;
    tag->p = c.p + c.pos;
    tag->end = it->end;
    for (uint32_t j = 0; j < nc && !c.bad; j++) {
        (void)zc_str(&c);
        if (c.len - c.pos < sizeof(cidr_entry_t)) c.bad = true;
        else c.pos += sizeof(cidr_entry_t);
    }
    if (c.bad) { it->left = 0; return false; }
    it->p += c.pos;
    it->left--;
    return true;
}

bool zone_image_tag_next_cidr(zone_image_tag_t *tag, const char **cidr, cidr_entry_t *parsed) {
    if (tag->left == 0) return false;
    cursor_t c = { tag->p, (size_t)(tag->end - tag->p), 0, false };
    *cidr = zc_str(&c);
    if (c.bad || c.len - c.pos < sizeof(cidr_entry_t)) { tag->left = 0; return false; }
    memcpy(parsed, c.p + c.pos, sizeof(cidr_entry_t));
    c.pos += sizeof(cidr_entry_t);
    tag->p += c.pos;
    tag->left--;
    return true;
}

const acl_entry_t *zone_image_ecs_trusted(const zone_image_t *img, int *count) {
    *count = 0;
    if (!img) return NULL;
    cursor_t c = zattr_cursor(img);
    uint32_t nloc = get_u32(&c);
    if (c.bad || (size_t)nloc > (c.len - c.pos) / sizeof(tinydns_location_entry_t)) return NULL;
    c.pos += (size_t)nloc * sizeof(tinydns_location_entry_t);
    zc_skip_tags(&c);
    zc_skip_tags(&c);
    uint32_t ntr = get_u32(&c);
    if (c.bad || ntr > c.len) return NULL;
    for (uint32_t i = 0; i < ntr && !c.bad; i++) (void)zc_str(&c);
    uint32_t np = get_u32(&c);
    if (c.bad || np == 0) return NULL;
    size_t at = (c.pos + 7) & ~(size_t)7;
    if (at > c.len || (size_t)np > (c.len - at) / sizeof(acl_entry_t)) return NULL;
    *count = (int)np;
    return (const acl_entry_t *)(const void *)(c.p + at);
}

int zone_image_zattr_load(const zone_image_t *img, zone_arena_t *a) { return thaw_zattr(img, a); }

/* Does the RR have anything that hides it from some client (tinydns location or time stamp, a tag)? An ext[] entry that
 * only keeps the owner spelling does not. */
static bool ext_restricts(const zone_image_ext_t *e) {
    return e && (e->loc[0] != 0 || e->loc[1] != 0 || e->ecs_tag_off != 0 || e->loc_tag_off != 0 || e->ttd != 0);
}

/* The RRs of one owner are in builder (file) order (zone_image_name_t.first_rr), so "first" below is the first in file order */
uint32_t zone_image_apex_soa(const zone_image_t *img) {
    if (!img || img->apex_name == ZONE_IMAGE_NONE) return ZONE_IMAGE_NONE;
    uint32_t first = ZONE_IMAGE_NONE;
    uint32_t end = zone_image_name_first_rr(img, img->apex_name) + zone_image_name_rr_count(img, img->apex_name);
    for (uint32_t k = zone_image_name_first_rr(img, img->apex_name); k < end; k++) {
        if (zone_image_rr_type(img, k) != 6) continue;
        if (first == ZONE_IMAGE_NONE) first = k;
        if (!ext_restricts(zone_image_rr_ext(img, k))) return k;
    }
    return first;
}

/* The one implementation of the tinydns / tag visibility of an RR (tinydns behaviour, djbdns 1.05: a record with a location is
 * skipped unless it equals the client's; ttl 0 = countdown until the stamp, TTL clamped to 2..3600; ttl != 0 = active only
 * after the stamp). An RR without ext[] returns at once. */
bool zone_image_rr_valid(const zone_image_t *img, uint32_t rr, time_t now, const char client_loc[2],
                         const char *client_ecs_tag, const char *client_loc_tag, uint32_t *effective_ttl) {
    const zone_image_ext_t *e = zone_image_rr_ext(img, rr);
    uint32_t ttl = zone_image_rr_ttl(img, rr);
    if (!e) {
        *effective_ttl = ttl;
        return true;
    }
    if (e->loc[0] != 0 || e->loc[1] != 0) {
        if (e->loc[0] != client_loc[0] || e->loc[1] != client_loc[1]) return false;
    }
    if (e->ecs_tag_off != 0) {
        if (client_ecs_tag == NULL || strcasecmp(zone_image_str(img, e->ecs_tag_off), client_ecs_tag) != 0) return false;
    }
    if (e->loc_tag_off != 0) {
        if (client_loc_tag == NULL || strcasecmp(zone_image_str(img, e->loc_tag_off), client_loc_tag) != 0) return false;
    }
    time_t ttd = (time_t)e->ttd;
    if (ttd == 0) {
        *effective_ttl = ttl;
        return true;
    }
    if (!(e->flags & ZONE_IMAGE_EXT_COUNTDOWN)) {
        /* the time stamp is the moment the RR becomes active */
        if (ttd >= now) return false;
        *effective_ttl = ttl;
        return true;
    }
    /* countdown TTL: the time stamp is the expiry */
    if (ttd < now) return false;
    double remaining = difftime(ttd, now);
    if (remaining < 2.0) remaining = 2.0;
    if (remaining > 3600.0) remaining = 3600.0;
    *effective_ttl = (uint32_t)remaining;
    return true;
}

uint32_t zone_image_visible_soa(const zone_image_t *img, const zone_image_view_t *v, uint32_t *effective_ttl) {
    if (!img || img->apex_name == ZONE_IMAGE_NONE) return ZONE_IMAGE_NONE;
    uint32_t end = zone_image_name_first_rr(img, img->apex_name) + zone_image_name_rr_count(img, img->apex_name);
    for (uint32_t k = zone_image_name_first_rr(img, img->apex_name); k < end; k++) {
        uint32_t ttl;
        if (zone_image_rr_type(img, k) != 6 || !zone_image_rr_visible(img, k, v, &ttl)) continue;
        if (effective_ttl) *effective_ttl = ttl;
        return k;
    }
    return ZONE_IMAGE_NONE;
}

/* freeze: ZONE_IMAGE_F_SOA_ATTR when some apex SOA RR is restricted */
static bool image_soa_restricted(const zone_image_t *img) {
    if (img->apex_name == ZONE_IMAGE_NONE) return false;
    uint32_t end = zone_image_name_first_rr(img, img->apex_name) + zone_image_name_rr_count(img, img->apex_name);
    for (uint32_t k = zone_image_name_first_rr(img, img->apex_name); k < end; k++)
        if (zone_image_rr_type(img, k) == 6 && ext_restricts(zone_image_rr_ext(img, k))) return true;
    return false;
}

/* One RR as a builder record (the way AXFR / UPDATE records look: text RDATA for the types parse_resource_record()
 * knows, generic_data for the rest). pkt (>= 255 + 10 + 65535 octets) and chk (65535) are scratch. */
static int thaw_one(const zone_image_t *img, uint32_t k, zone_arena_t *a, uint8_t *pkt, uint8_t *chk, dns_record_t *out) {
    const zone_image_rr_t *rr = &zone_image_rrs(img)[k];
    const zone_image_name_t *nm = &zone_image_names(img)[rr->name_id];
    const zone_image_ext_t *ext = zone_image_rr_ext(img, k);
    const char *text = zone_image_str(img, ext && ext->alt_text_off ? ext->alt_text_off : nm->text_off);
    uint32_t woff = ext && ext->alt_text_off ? ext->alt_wire_off : nm->wire_off;
    /* a synthetic RR in message form: owner, TYPE, CLASS, TTL, RDLENGTH, RDATA */
    size_t p = 0;
    if (woff) {
        const uint8_t *w = zone_image_bytes(img, woff);
        int wl = wire_name_len(w, 256);
        if (wl < 0) return -1;
        memcpy(pkt, w, (size_t)wl);
        p = (size_t)wl;
    } else {
        pkt[p++] = 0;
    }
    pkt[p++] = rr->type >> 8; pkt[p++] = rr->type & 0xFF;
    pkt[p++] = rr->class_val >> 8; pkt[p++] = rr->class_val & 0xFF;
    pkt[p++] = rr->ttl >> 24; pkt[p++] = (rr->ttl >> 16) & 0xFF; pkt[p++] = (rr->ttl >> 8) & 0xFF; pkt[p++] = rr->ttl & 0xFF;
    pkt[p++] = rr->rdata_len >> 8; pkt[p++] = rr->rdata_len & 0xFF;
    if (rr->rdata_len) memcpy(pkt + p, zone_image_rr_rdata(img, k), rr->rdata_len);
    p += rr->rdata_len;

    dns_record_t rec;
    memset(&rec, 0, sizeof(rec));
    size_t off = 0;
    uint16_t t = 0;
    bool raw = (rr->flags & ZONE_IMAGE_RR_RAW) != 0;
    const dns_rdata_name_layout_t *rlay = dns_rdata_name_layout(rr->type);
    /* A raw RR keeps its RDATA as it is (never compressed, RDATA of any shape): even for a type whose text form
     * exists, decoding it would make the record compressible (tinydns ":fqdn:4:...:" generic data). */
    bool decoded = !(raw && rlay && rlay->compress) && parse_resource_record(pkt, p, &off, a, &rec, &t) == 0;
    if (!decoded) {
        if (!raw) {
            syslog(LOG_ERR, "[Image] thaw: RR %u (type %u) cannot be decoded", k, rr->type);
            return -1;
        }
        memset(&rec, 0, sizeof(rec));
        rec.name = arena_strdup(a, text);
        char ttlbuf[16];
        snprintf(ttlbuf, sizeof(ttlbuf), "%u", rr->ttl);
        rec.ttl = arena_strdup(a, ttlbuf);
        rec.ttl_value = rr->ttl;
        rec.class_val = rr->class_val;
        rec.class_str = rr->class_val == DNS_CLASS_KARIDNS_EXT ? "KARIDNS" : (char *)dns_class_literal(rr->class_val);
        rec.type = (char *)get_type_str(rr->type, a);
        rec.type_code = rr->type;
        rec.next_record = -1;
        uint8_t *keep = rr->rdata_len ? arena_alloc(a, rr->rdata_len) : (uint8_t *)"";
        if (!rec.name || !rec.ttl || !rec.type || !keep) return -1;
        if (rr->rdata_len) memcpy(keep, zone_image_rr_rdata(img, k), rr->rdata_len);
        rec.generic_data = keep;
        rec.generic_len = rr->rdata_len;
    }
    if (!rec.name || strcmp(rec.name, text) != 0) {
        rec.name = arena_strdup(a, text);
        if (!rec.name) return -1;
        dns_record_preparse_cache(a, &rec);
    }
    /* a record that is raw in the image stays raw even when its RDATA is empty */
    if ((rr->flags & ZONE_IMAGE_RR_RAW) && !rec.generic_data) {
        rec.generic_data = (uint8_t *)"";
        rec.generic_len = 0;
    }
    if (ext) {
        rec.tinydns_ttd = (time_t)ext->ttd;
        rec.tinydns_ttl_countdown = (ext->flags & ZONE_IMAGE_EXT_COUNTDOWN) != 0;
        rec.tinydns_loc[0] = ext->loc[0];
        rec.tinydns_loc[1] = ext->loc[1];
        if (ext->ecs_tag_off) {
            rec.ecs_subnet_tag = arena_strdup(a, zone_image_str(img, ext->ecs_tag_off));
            if (!rec.ecs_subnet_tag) return -1;
        }
        if (ext->loc_tag_off) {
            rec.bind_location_tag = arena_strdup(a, zone_image_str(img, ext->loc_tag_off));
            if (!rec.bind_location_tag) return -1;
        }
    }
    /* the text form must write the same RDATA: types whose text form cannot hold some RDATA (a NUL octet in a
     * character-string, more strings than MAX_RDATA) fall back to the wire form kept as it is */
    uint16_t clen = 0;
    bool same = serialize_dns_record(chk, 65535, &clen, &rec, NULL, ".", 0xFFFFFFFFu) == 0 && clen == 11 + rr->rdata_len &&
                (rr->rdata_len == 0 || memcmp(chk + 11, zone_image_rr_rdata(img, k), rr->rdata_len) == 0);
    if (!same) {
        const dns_rdata_name_layout_t *lay = dns_rdata_name_layout(rr->type);
        if (lay && lay->compress) {
            syslog(LOG_ERR, "[Image] thaw: RR %u (type %u) does not round-trip", k, rr->type);
            return -1;
        }
        uint8_t *keep = rr->rdata_len ? arena_alloc(a, rr->rdata_len) : (uint8_t *)"";
        if (rr->rdata_len && !keep) return -1;
        if (rr->rdata_len) memcpy(keep, zone_image_rr_rdata(img, k), rr->rdata_len);
        rec.generic_data = keep;
        rec.generic_len = rr->rdata_len;
    }
    *out = rec;
    return 0;
}

int zone_image_rr_to_record(const zone_image_t *img, uint32_t rr, zone_arena_t *arena, dns_record_t *rec) {
    if (!img || !arena || !rec || rr >= img->n_rrs) return -1;
    uint8_t *pkt = malloc(255 + 10 + 65535);
    uint8_t *chk = malloc(65535);
    int rc = -1;
    if (pkt && chk) {
        rc = thaw_one(img, rr, arena, pkt, chk, rec);
        if (rc == 0) rec->next_record = -1;
    }
    free(pkt);
    free(chk);
    return rc;
}

int zone_image_thaw(const zone_image_t *img, zone_arena_t *a) {
    if (!img || !a || img->magic != ZONE_IMAGE_MAGIC || img->version != ZONE_IMAGE_VERSION || a->count != 0) return -1; /* review [9] */
    const uint32_t n = img->n_rrs;
    size_t hint = (size_t)img->total_size * 2 + 4096;
    a->first_pool_cap = hint > (16u << 20) ? (16u << 20) : hint;
    /* an arena that was used and emptied (count 0) may still own a record array: replace it */
    free(a->records);
    a->records = calloc(n ? n : 1, sizeof(dns_record_t));
    if (!a->records) { a->records_cap = 0; return -1; } /* review dns_zone_image.c [1]: the capacity only with the array */
    a->records_cap = n ? n : 1;
    uint8_t *pkt = malloc(255 + 10 + 65535);
    uint8_t *chk = malloc(65535);
    if (!pkt || !chk) { free(pkt); free(chk); return -1; }
    int rc = -1;
    /* file (builder) order: the order the zone had when it was frozen */
    for (uint32_t seq = 0; seq < n; seq++) {
        if (thaw_one(img, zone_image_seq_rr(img, seq), a, pkt, chk, &a->records[a->count]) != 0) goto out;
        a->count++;
    }
    a->is_tinydns_format = (img->flags & ZONE_IMAGE_F_TINYDNS) != 0;
    if (thaw_zattr(img, a) != 0) goto out;
    if (build_zone_index(a, false) != 0) goto out;
    rc = 0;
out:
    free(pkt);
    free(chk);
    return rc;
}

/* ------------------------------------------------------------------------------------------------------------
 * validation: is this block an image the readers can use without checking anything?
 *
 * Every reader above (the query engine, AXFR / IXFR, the ECS code, the catalog and alias modules) dereferences image
 * offsets and indexes unchecked: the block is written by zone_image_freeze() and never changes.  An image that is read
 * back from disk (the store, S1) is no longer "written by this process", so it is checked once, before it is
 * attached.  The check accepts exactly what zone_image_freeze() writes (same layout, same flag rules), so a valid
 * image is not rejected and a corrupt one cannot make a reader leave [buf, buf + len).
 *
 * The cost is O(size) (one pass over every section; a name or a tag is read once per reference, at most
 * DNS_NAME_TEXT_SIZE / V_MAX_TAG octets).  The only allocation is one bit array of max(n_names, n_rrs) bits, used for
 * the hash table, the glue list and the file order; it is made after the cheap header and layout checks.
 * ------------------------------------------------------------------------------------------------------------ */
#define V_IMG_FLAGS (ZONE_IMAGE_F_TINYDNS | ZONE_IMAGE_F_EXT | ZONE_IMAGE_F_WILDCARD | ZONE_IMAGE_F_DNAME | ZONE_IMAGE_F_PERM | \
                     ZONE_IMAGE_F_SOA_ATTR | ZONE_IMAGE_F_VIEW | ZONE_IMAGE_F_ALIAS | ZONE_IMAGE_F_CUT)
#define V_NAME_FLAGS (ZONE_IMAGE_NAME_WILDCARD | ZONE_IMAGE_NAME_CUT | ZONE_IMAGE_NAME_DNAME | ZONE_IMAGE_NAME_APEX | \
                      ZONE_IMAGE_NAME_NSEC | ZONE_IMAGE_NAME_GLUE | ZONE_IMAGE_NAME_ALIAS)
#define V_MAX_TAG 1024u    /* octets of a tag name in ext[] (the zone file token limit is far below it) */

typedef struct {
    const uint8_t *s;      /* the strings area */
    size_t slen;
} vstr_t;

static inline bool bm_get(const uint8_t *b, size_t i) { return (b[i >> 3] >> (i & 7)) & 1; }
static inline void bm_set(uint8_t *b, size_t i) { b[i >> 3] |= (uint8_t)(1u << (i & 7)); }
static inline void bm_clear(uint8_t *b, size_t nbits) { memset(b, 0, (nbits + 7) / 8); }

/* The NUL terminated string at strings offset `off` (0 = none and the 8 octets of padding are not strings), at most
 * `maxlen` octets before the NUL; NULL if there is none. */
static const char *v_cstr(const vstr_t *vs, uint32_t off, size_t maxlen, size_t *n) {
    if (off < 8 || off >= vs->slen) return NULL;
    size_t avail = vs->slen - off;
    const uint8_t *z = memchr(vs->s + off, 0, avail < maxlen + 1 ? avail : maxlen + 1);
    if (!z) return NULL;
    if (n) *n = (size_t)(z - (vs->s + off));
    return (const char *)(vs->s + off);
}

/* An owner spelling: canonical text (it must encode to a wire name) and, if present (0 = none), the wire form beside
 * it (an uncompressed name inside the area that equals the encoding of the text up to the case of letters). */
static const char *v_owner(const vstr_t *vs, uint32_t text_off, uint32_t wire_off) {
    const char *t = v_cstr(vs, text_off, DNS_NAME_TEXT_SIZE - 1, NULL);
    if (!t) return NULL;
    uint8_t w[256];
    long wl = write_uncompressed_name_ext(w, 0, sizeof(w), t, false);
    if (wl <= 0) return NULL;
    if (wire_off) {
        if (wire_off < 8 || wire_off >= vs->slen) return NULL;
        size_t avail = vs->slen - wire_off;
        int l = wire_name_len(vs->s + wire_off, avail < 255 ? avail : 255);
        if (l != (int)wl) return NULL;
        for (int i = 0; i < l; i++) {
            uint8_t a = vs->s[wire_off + (uint32_t)i], b = w[i];
            if (a >= 'A' && a <= 'Z') a |= 0x20;
            if (b >= 'A' && b <= 'Z') b |= 0x20;
            if (a != b) return NULL;
        }
    }
    return t;
}

/* an NSEC3 owner: base32hex digits (RFC 4648 §7; RFC 5155 §3.3: one label, at most 63 octets), '.', and the zone name (what
 * build_nsec3_index() indexes); find_matching_nsec3() reads the name after the label as owner + hlen + 1 */
static bool v_n3_owner(const char *t, size_t *hlen) {
    const char *dot = strchr(t, '.');
    if (!dot || dot == t || dot[1] == '\0' || dot - t > 63) return false;
    for (const char *p = t; p < dot; p++) {
        char c = (char)((*p >= 'a' && *p <= 'z') ? *p - 32 : *p);
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'V'))) return false;
    }
    *hlen = (size_t)(dot - t);
    return true;
}

/* cidr_entry_t as copied into the image (padding is not defined, the flags are read as bool: 0 or 1 only). A parsed
 * entry that is used (valid, not "any") must match its family: the ECS code takes `prefix` bits from the address. */
static bool v_cidr(const uint8_t *raw) {
    if (raw[offsetof(cidr_entry_t, valid)] > 1 || raw[offsetof(cidr_entry_t, is_any)] > 1) return false;
    cidr_entry_t e;
    memcpy(&e, raw, sizeof(e));
    if (e.valid && !e.is_any) {
        if (e.family == AF_INET) return e.prefix <= 32;
        if (e.family == AF_INET6) return e.prefix <= 128;
        return false;
    }
    return true;
}

/* a string of the zone level tables: u32 length (0xFFFFFFFF = NULL), the octets, a NUL (see build_zattr()) */
static bool vz_str(cursor_t *c, bool nullable) {
    uint32_t n = get_u32(c);
    if (c->bad) return false;
    if (n == 0xFFFFFFFFu) return nullable;
    if (c->len - c->pos < (size_t)n + 1 || memchr(c->p + c->pos, 0, (size_t)n + 1) != c->p + c->pos + n) return false;
    c->pos += (size_t)n + 1;
    return true;
}

static bool vz_tags(cursor_t *c) {
    uint32_t n = get_u32(c);
    if (c->bad || n > (c->len - c->pos) / 8) return false;   /* a definition is at least a length and a count */
    for (uint32_t i = 0; i < n; i++) {
        if (!vz_str(c, false)) return false;                  /* the tag name is returned to the engine */
        uint32_t nc = get_u32(c);
        if (c->bad) return false;
        for (uint32_t j = 0; j < nc; j++) {
            if (!vz_str(c, true) || c->len - c->pos < sizeof(cidr_entry_t) || !v_cidr(c->p + c->pos)) return false;
            c->pos += sizeof(cidr_entry_t);
        }
    }
    return true;
}

/* the zattr area, exactly as build_zattr() lays it out: nloc, locations, location tags, ECS tags, ntr, ntr strings,
 * nparsed (= ntr), zero padding to 8, nparsed x acl_entry_t; nothing after it */
static bool v_zattr(const uint8_t *p, size_t len) {
    cursor_t c = { p, len, 0, false };
    uint32_t nloc = get_u32(&c);
    if (c.bad || (size_t)nloc > (c.len - c.pos) / sizeof(tinydns_location_entry_t)) return false;
    for (uint32_t i = 0; i < nloc; i++) {
        if (c.p[c.pos + offsetof(tinydns_location_entry_t, prefix_bits)] > 32) return false;
        c.pos += sizeof(tinydns_location_entry_t);
    }
    if (!vz_tags(&c) || !vz_tags(&c)) return false;
    uint32_t ntr = get_u32(&c);
    if (c.bad || ntr > c.len - c.pos) return false;
    for (uint32_t i = 0; i < ntr; i++)
        if (!vz_str(&c, true)) return false;
    uint32_t np = get_u32(&c);
    if (c.bad || np != ntr) return false;
    if (np == 0) return c.pos == c.len;
    size_t at = (c.pos + 7) & ~(size_t)7;
    if (at > c.len || (size_t)np != (c.len - at) / sizeof(acl_entry_t) || (c.len - at) % sizeof(acl_entry_t) != 0) return false;
    for (size_t i = c.pos; i < at; i++)
        if (p[i] != 0) return false;
    for (uint32_t i = 0; i < np; i++) {
        const uint8_t *e = p + at + (size_t)i * sizeof(acl_entry_t);
        if (!v_cidr(e) || e[offsetof(acl_entry_t, is_deny)] > 1) return false;
    }
    return true;
}

int zone_image_validate(const void *buf, size_t len, char *why, size_t whylen) {
    int rc = 0;
    uint8_t *bits = NULL;
#define BAD(...) do { if (why && whylen) snprintf(why, whylen, __VA_ARGS__); rc = -1; goto out; } while (0)
    if (why && whylen) why[0] = '\0';
    if (!buf) BAD("no image");
    if (len < sizeof(zone_image_t)) BAD("%zu octets are shorter than the header", len);
    if (((uintptr_t)buf & 7) != 0) BAD("the image is not 8-byte aligned");
    if (len > 0xFFFFF000u || (len & 7) != 0) BAD("size %zu is not a multiple of 8 below 4 GiB", len);
    const zone_image_t *img = (const zone_image_t *)buf;
    if (img->magic != ZONE_IMAGE_MAGIC) BAD("bad magic %08x", img->magic);
    if (img->version != ZONE_IMAGE_VERSION) BAD("unknown version %u", img->version);
    if (img->total_size != len) BAD("total_size %u is not the size %zu", img->total_size, len);
    if (img->flags & ~(uint32_t)V_IMG_FLAGS) BAD("unknown flags %x", img->flags);
    if (img->reserved_ != 0) BAD("reserved field is not 0");

    const uint32_t n_names = img->n_names, n_rrs = img->n_rrs, n_ext = img->n_ext;
    if (n_names >= 0x7FFFFFFFu || n_rrs >= 0x7FFFFFFFu) BAD("count of names or RRs out of range");
    if (img->n_canon != n_names) BAD("n_canon %u != n_names %u", img->n_canon, n_names);
    if (n_ext > n_rrs || img->n_nsec > n_rrs || img->n_n3entries > n_rrs || img->n_n3chains > img->n_n3entries ||
        img->n_glue > n_names)
        BAD("a count exceeds what it counts");
    if (((img->flags & ZONE_IMAGE_F_EXT) != 0) != (n_ext != 0)) BAD("F_EXT does not match n_ext %u", n_ext);
    if (((img->flags & ZONE_IMAGE_F_PERM) != 0) != (img->off_perm != 0)) BAD("F_PERM does not match off_perm");
    if (img->off_perm && n_rrs < 2) BAD("a file order of %u RRs", n_rrs);   /* freeze keeps one only when it differs from the identity */
    {
        /* hash_size: a power of two with an empty slot, or find_name() would not end */
        uint32_t hs = img->hash_size;
        if (hs < 4 || (hs & (hs - 1)) != 0 || hs <= n_names) BAD("hash_size %u", hs);
    }

    /* the layout of zone_image_freeze(): each section follows the one before, padded to 8, in this order; with the total size
     * equal to the length this puts every section inside the block and none over another */
    uint64_t o = sizeof(zone_image_t);
#define SECTION(field, count, esize) do { \
        if ((uint64_t)img->field != o) BAD("%s is %u, expected %llu", #field, img->field, (unsigned long long)o); \
        o = (o + (uint64_t)(count) * (esize) + 7) & ~(uint64_t)7; \
    } while (0)
    SECTION(off_names, n_names, sizeof(zone_image_name_t));
    SECTION(off_rrs, n_rrs, sizeof(zone_image_rr_t));
    SECTION(off_ext, n_ext, sizeof(zone_image_ext_t));
    SECTION(off_n3chains, img->n_n3chains, sizeof(zone_image_n3chain_t));
    SECTION(off_hash, img->hash_size, sizeof(uint32_t));
    SECTION(off_canon, img->n_canon, sizeof(uint32_t));
    SECTION(off_nsec, img->n_nsec, sizeof(uint32_t));
    SECTION(off_n3entries, img->n_n3entries, sizeof(uint32_t));
    SECTION(off_glue, img->n_glue, sizeof(uint32_t));
    if (img->off_perm) SECTION(off_perm, n_rrs, sizeof(uint32_t));
    SECTION(off_zattr, img->zattr_len, 1);
#undef SECTION
    if ((uint64_t)img->off_strings != o || o + 8 > len) BAD("off_strings is %u, expected %llu", img->off_strings, (unsigned long long)o);
    const uint8_t *base = (const uint8_t *)buf;
    const vstr_t vs = { base + img->off_strings, len - img->off_strings };

    if (n_names || n_rrs) {
        size_t nbits = n_names > n_rrs ? n_names : n_rrs;
        bits = calloc((nbits + 7) / 8 + 1, 1);
        if (!bits) { if (why && whylen) snprintf(why, whylen, "out of memory"); rc = -2; goto out; }
    }

    const zone_image_name_t *names = zone_image_names(img);
    const zone_image_rr_t *rrs = zone_image_rrs(img);
    const zone_image_ext_t *exts = zone_image_exts(img);
    const uint32_t apex = img->apex_name;
    if (apex != ZONE_IMAGE_NONE && apex >= n_names) BAD("apex_name %u", apex);

    /* names, their RRs and the extras of those RRs, one owner at a time: the owners partition rrs[] in order */
    uint64_t run = 0;
    uint32_t next_ext = 1, n_glue_flag = 0;
    bool any_wild = false, any_dname = false, any_alias = false, any_cut = false, any_view = false, soa_attr = false;
    for (uint32_t id = 0; id < n_names; id++) {
        const zone_image_name_t *nm = &names[id];
        const char *text = v_owner(&vs, nm->text_off, nm->wire_off);
        if (!text) BAD("name %u: owner text / wire form", id);
        if (nm->hash != dns_name_hash_ci(text)) BAD("name %u: hash", id);
        if (nm->rr_count_flags & ~(ZONE_IMAGE_NAME_COUNT_MASK | V_NAME_FLAGS)) BAD("name %u: unknown flags", id);
        uint32_t count = nm->rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK;
        if (count == 0 || nm->first_rr != run || run + count > n_rrs) BAD("name %u: RRs [%u, +%u) of %u", id, nm->first_rr, count, n_rrs);
        if (nm->canon_rank >= img->n_canon) BAD("name %u: canon_rank %u", id, nm->canon_rank);
        bool has_ns = false, has_dname = false, has_nsec = false, has_alias = false, has_addr = false;
        for (uint32_t k = nm->first_rr; k < nm->first_rr + count; k++) {
            const zone_image_rr_t *r = &rrs[k];
            if (r->name_id != id) BAD("RR %u: name_id %u, in the range of name %u", k, r->name_id, id);
            if (r->ttl > 0x7FFFFFFFu) BAD("RR %u: ttl", k);
            if (r->flags & ~(uint16_t)(ZONE_IMAGE_RR_RAW | ZONE_IMAGE_RR_NO_NAMEWIRE)) BAD("RR %u: flags", k);
            if (r->rdata_len > IMG_MAX_RDLEN) BAD("RR %u: rdata_len %u", k, r->rdata_len);
            if (r->rdata_len == 0 ? r->rdata_off != 0
                                  : (r->rdata_off < 8 || (uint64_t)r->rdata_off + r->rdata_len > vs.slen))
                BAD("RR %u: RDATA [%u, +%u) outside the strings area", k, r->rdata_off, r->rdata_len);
            if (r->type == 2) has_ns = true;
            else if (r->type == 39) has_dname = true;
            else if (r->type == 47) has_nsec = true;
            else if (r->type == DNS_TYPE_PDNS_ALIAS && r->class_val == 1) has_alias = true;
            if (r->type == 1 || r->type == 28) has_addr = true;
            if (!(r->flags & ZONE_IMAGE_RR_RAW) && r->rdata_len) {
                /* image_serialize_rr() writes these types name by name: the names must be whole names of at most 255 octets */
                const dns_rdata_name_layout_t *lay = dns_rdata_name_layout(r->type);
                if (lay && lay->compress) {
                    const uint8_t *rd = vs.s + r->rdata_off;
                    size_t pos = lay->skip;
                    for (unsigned q = 0; q < lay->nnames; q++) {
                        int wl = pos < r->rdata_len ? wire_name_len(rd + pos, r->rdata_len - pos < 255 ? r->rdata_len - pos : 255) : -1;
                        if (wl < 0) BAD("RR %u (type %u): RDATA has no whole name %u", k, r->type, q);
                        pos += (size_t)wl;
                    }
                }
            }
            if (r->ext_idx) {
                if (r->ext_idx != next_ext || r->ext_idx > n_ext) BAD("RR %u: ext_idx %u (expected %u of %u)", k, r->ext_idx, next_ext, n_ext);
                next_ext++;
                const zone_image_ext_t *e = &exts[r->ext_idx - 1];
                if ((e->flags & ~(uint8_t)ZONE_IMAGE_EXT_COUNTDOWN) || e->pad != 0) BAD("ext %u: flags", r->ext_idx - 1);
                if ((e->ecs_tag_off && !v_cstr(&vs, e->ecs_tag_off, V_MAX_TAG, NULL)) ||
                    (e->loc_tag_off && !v_cstr(&vs, e->loc_tag_off, V_MAX_TAG, NULL)))
                    BAD("ext %u: tag", r->ext_idx - 1);
                if (e->alt_text_off) {
                    const char *alt = v_owner(&vs, e->alt_text_off, e->alt_wire_off);
                    if (!alt || !domain_names_match_ci(alt, text)) BAD("ext %u: owner spelling", r->ext_idx - 1);
                } else if (e->alt_wire_off) {
                    BAD("ext %u: wire spelling without text", r->ext_idx - 1);
                }
                bool restricts = e->loc[0] != 0 || e->loc[1] != 0 || e->ecs_tag_off != 0 || e->loc_tag_off != 0 || e->ttd != 0;
                if (restricts || (e->flags & ZONE_IMAGE_EXT_COUNTDOWN)) any_view = true;
                if (restricts && id == apex && r->type == 6) soa_attr = true;
            }
        }
        uint32_t want = 0;
        if (has_ns && id != apex) want |= ZONE_IMAGE_NAME_CUT;
        if (has_dname) want |= ZONE_IMAGE_NAME_DNAME;
        if (has_nsec) want |= ZONE_IMAGE_NAME_NSEC;
        if (has_alias) want |= ZONE_IMAGE_NAME_ALIAS;
        if (text[0] == '*' && text[1] == '.') want |= ZONE_IMAGE_NAME_WILDCARD;
        if (id == apex) want |= ZONE_IMAGE_NAME_APEX;
        if ((nm->rr_count_flags & V_NAME_FLAGS & ~ZONE_IMAGE_NAME_GLUE) != want) BAD("name %u: flags %x, the RRs give %x", id, nm->rr_count_flags & V_NAME_FLAGS, want);
        if (nm->rr_count_flags & ZONE_IMAGE_NAME_GLUE) {
            if (!has_addr || ++n_glue_flag > IMG_MAX_PRELINK_TARGETS) BAD("name %u: glue flag", id);
        }
        any_wild |= (want & ZONE_IMAGE_NAME_WILDCARD) != 0;
        any_dname |= has_dname;
        any_alias |= has_alias;
        any_cut |= (want & ZONE_IMAGE_NAME_CUT) != 0;
        run += count;
    }
    if (run != n_rrs) BAD("the names hold %llu of %u RRs", (unsigned long long)run, n_rrs);
    if (next_ext != n_ext + 1) BAD("%u of %u ext entries are used", next_ext - 1, n_ext);
    {
        uint32_t want = (img->flags & (ZONE_IMAGE_F_TINYDNS | ZONE_IMAGE_F_PERM)) | (n_ext ? ZONE_IMAGE_F_EXT : 0) |
                        (any_view ? ZONE_IMAGE_F_VIEW : 0) | (any_wild ? ZONE_IMAGE_F_WILDCARD : 0) |
                        (any_dname ? ZONE_IMAGE_F_DNAME : 0) | (any_alias ? ZONE_IMAGE_F_ALIAS : 0) |
                        (any_cut ? ZONE_IMAGE_F_CUT : 0) | (soa_attr ? ZONE_IMAGE_F_SOA_ATTR : 0);
        if (img->flags != want) BAD("flags %x, the contents give %x", img->flags, want);
    }

    /* the name hash table (zone_image_find_name()): linear probing, every slot is empty or a name id + 1, every name
     * once, and every name is reachable from its home slot without crossing an empty slot */
    if (n_names) {
        const uint32_t *tab = zone_image_u32s(img, img->off_hash);
        const size_t hs = img->hash_size, mask = hs - 1;
        size_t empty = hs, occupied = 0;
        for (size_t i = 0; i < hs; i++) {
            if (tab[i] > n_names) BAD("hash slot %zu: %u", i, tab[i]);
            if (tab[i] == 0) { if (empty == hs) empty = i; }
            else occupied++;
        }
        if (occupied != n_names || empty == hs) BAD("hash table holds %zu of %u names", occupied, n_names);
        bm_clear(bits, n_names);
        size_t cluster = 0;
        for (size_t j = 1; j <= hs; j++) {
            size_t i = (empty + j) & mask;
            if (tab[i] == 0) { cluster = 0; continue; }
            uint32_t id = tab[i] - 1;
            if (bm_get(bits, id)) BAD("hash table: name %u twice", id);
            bm_set(bits, id);
            cluster++;
            if (((i - (names[id].hash & mask)) & mask) >= cluster) BAD("hash table: name %u is not reachable from its slot", id);
        }
    } else {
        const uint32_t *tab = zone_image_u32s(img, img->off_hash);
        for (size_t i = 0; i < img->hash_size; i++)
            if (tab[i] != 0) BAD("hash slot %zu of a zone without names", i);
    }

    /* canonical order: a permutation of the names, strictly ascending (zone_image_canon_floor() is a binary search) */
    {
        const uint32_t *canon = zone_image_u32s(img, img->off_canon);
        const char *prev = NULL;
        for (uint32_t i = 0; i < img->n_canon; i++) {
            if (canon[i] >= n_names || names[canon[i]].canon_rank != i) BAD("canon[%u] = %u", i, canon[i]);
            const char *t = (const char *)vs.s + names[canon[i]].text_off;
            if (prev && compare_canonical_name(prev, t) >= 0) BAD("canon[%u] is not after canon[%u]", i, i - 1);
            prev = t;
        }
    }

    /* NSEC index: NSEC RRs, owners in canonical order (zone_image_nsec_floor()) */
    {
        const uint32_t *nsec = zone_image_u32s(img, img->off_nsec);
        const char *prev = NULL;
        for (uint32_t i = 0; i < img->n_nsec; i++) {
            if (nsec[i] >= n_rrs || rrs[nsec[i]].type != 47) BAD("nsec[%u] = %u", i, nsec[i]);
            const char *t = (const char *)vs.s + names[rrs[nsec[i]].name_id].text_off;
            if (prev && compare_canonical_name(prev, t) > 0) BAD("nsec[%u] is out of order", i);
            prev = t;
        }
    }

    /* NSEC3 chains: consecutive runs of NSEC3 RRs with the chain's parameters, hash labels in ascending order
     * (zone_image_n3chain_lower_bound()), owners that find_matching_nsec3() can split */
    {
        const zone_image_n3chain_t *chs = zone_image_n3chains(img);
        const uint32_t *ent = zone_image_u32s(img, img->off_n3entries);
        uint64_t first = 0;
        for (uint32_t c = 0; c < img->n_n3chains; c++) {
            const zone_image_n3chain_t *ch = &chs[c];
            if (ch->first != first || ch->count == 0 || ch->count > img->n_n3entries - first) BAD("NSEC3 chain %u: entries [%u, +%u)", c, ch->first, ch->count);
            if (ch->salt_len == 0 ? ch->salt_off != 0 : (ch->salt_off < 8 || (uint64_t)ch->salt_off + ch->salt_len > vs.slen))
                BAD("NSEC3 chain %u: salt", c);
            const char *plabel = NULL;
            size_t plen = 0;
            for (uint32_t i = 0; i < ch->count; i++) {
                uint32_t rr = ent[first + i];
                zone_image_nsec3_t v;
                if (rr >= n_rrs || rrs[rr].type != 50 || zone_image_nsec3(img, rr, &v) != 0) BAD("NSEC3 chain %u entry %u: RR %u", c, i, rr);
                if (v.algorithm != ch->algorithm || v.iterations != ch->iterations || v.salt_len != ch->salt_len ||
                    (v.salt_len && memcmp(v.salt, vs.s + ch->salt_off, v.salt_len) != 0))
                    BAD("NSEC3 chain %u entry %u: parameters differ from the chain's", c, i);
                const char *label = (const char *)vs.s + names[rrs[rr].name_id].text_off;
                size_t hl;
                if (!v_n3_owner(label, &hl)) BAD("NSEC3 chain %u entry %u: owner", c, i);
                if (plabel) {
                    int cmp = strncasecmp(plabel, label, plen < hl ? plen : hl);
                    if (cmp == 0) cmp = plen < hl ? -1 : (plen > hl ? 1 : 0);
                    if (cmp > 0) BAD("NSEC3 chain %u entry %u: out of hash order", c, i);
                }
                plabel = label;
                plen = hl;
            }
            first += ch->count;
        }
        if (first != img->n_n3entries) BAD("the NSEC3 chains hold %llu of %u entries", (unsigned long long)first, img->n_n3entries);
    }

    /* the NSEC3 parameters of the zone (zone_nsec3() in the engine hands salt / chain to the lookups) */
    if (img->n3_param_rr == ZONE_IMAGE_NONE) {
        if (img->n3_chain != ZONE_IMAGE_NONE || img->n3_salt_off || img->n3_iterations || img->n3_algorithm || img->n3_salt_len)
            BAD("NSEC3 parameters without an NSEC3PARAM RR");
    } else {
        zone_image_nsec3_t v;
        if (img->n3_param_rr >= n_rrs || rrs[img->n3_param_rr].type != 51 || zone_image_nsec3(img, img->n3_param_rr, &v) != 0)
            BAD("n3_param_rr %u", img->n3_param_rr);
        if (img->n3_salt_len == 0 ? img->n3_salt_off != 0 : (img->n3_salt_off < 8 || (uint64_t)img->n3_salt_off + img->n3_salt_len > vs.slen))
            BAD("n3_salt_off");
        if (v.algorithm != img->n3_algorithm || v.iterations != img->n3_iterations || v.salt_len != img->n3_salt_len ||
            (v.salt_len && memcmp(v.salt, vs.s + img->n3_salt_off, v.salt_len) != 0))
            BAD("the NSEC3 parameters are not those of n3_param_rr");
        if (img->n3_chain != ZONE_IMAGE_NONE) {
            if (img->n3_chain >= img->n_n3chains) BAD("n3_chain %u", img->n3_chain);
            const zone_image_n3chain_t *ch = &zone_image_n3chains(img)[img->n3_chain];
            if (ch->algorithm != img->n3_algorithm || ch->iterations != img->n3_iterations || ch->salt_len != img->n3_salt_len ||
                (ch->salt_len && memcmp(vs.s + ch->salt_off, vs.s + img->n3_salt_off, ch->salt_len) != 0))
                BAD("n3_chain %u has other parameters than the zone's", img->n3_chain);
        }
    }

    /* glue targets: distinct names that have an A / AAAA RR; every name flagged GLUE is among them */
    if (n_names) {
        const uint32_t *gl = zone_image_u32s(img, img->off_glue);
        bm_clear(bits, n_names);
        for (uint32_t i = 0; i < img->n_glue; i++) {
            if (gl[i] >= n_names || bm_get(bits, gl[i])) BAD("glue[%u] = %u", i, gl[i]);
            bm_set(bits, gl[i]);
            bool has_addr = false;
            for (uint32_t k = names[gl[i]].first_rr, e = k + (names[gl[i]].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK); k < e; k++)
                if (rrs[k].type == 1 || rrs[k].type == 28) { has_addr = true; break; }
            if (!has_addr) BAD("glue[%u]: name %u has no address", i, gl[i]);
        }
        for (uint32_t id = 0; id < n_names; id++)
            if ((names[id].rr_count_flags & ZONE_IMAGE_NAME_GLUE) && !bm_get(bits, id)) BAD("name %u is flagged glue but not in the list", id);
    } else if (img->n_glue) {
        BAD("glue targets of a zone without names");
    }

    /* file order: a permutation of the RRs (AXFR out and thaw walk it) */
    if (img->off_perm && n_rrs) {
        const uint32_t *perm = zone_image_u32s(img, img->off_perm);
        bm_clear(bits, n_rrs);
        for (uint32_t i = 0; i < n_rrs; i++) {
            if (perm[i] >= n_rrs || bm_get(bits, perm[i])) BAD("perm[%u] = %u", i, perm[i]);
            bm_set(bits, perm[i]);
        }
    }

    /* zone level tables */
    if (img->zattr_len && !v_zattr(base + img->off_zattr, img->zattr_len)) BAD("zone level tables (locations, tags, trusted resolvers)");
out:
#undef BAD
    free(bits);
    return rc;
}

/* ------------------------------------------------------------------------------------------------------------
 * an image from the database loader (0.7 M3): the rules of the zone and of the stream on top of zone_image_validate()
 * ------------------------------------------------------------------------------------------------------------ */
static bool ext_tag_eq(const vstr_t *vs, uint32_t a, uint32_t b) {
    if (!a || !b) return a == b;
    return strcasecmp((const char *)vs->s + a, (const char *)vs->s + b) == 0;
}

/* dns_record_same_visibility() on the extras of two RRs of one image (the tags were checked to be strings of the area) */
static bool img_same_visibility(const vstr_t *vs, const zone_image_ext_t *a, const zone_image_ext_t *b) {
    zone_image_ext_t z;
    memset(&z, 0, sizeof(z));
    if (!a) a = &z;
    if (!b) b = &z;
    return a->loc[0] == b->loc[0] && a->loc[1] == b->loc[1] && a->ttd == b->ttd &&
           (a->flags & ZONE_IMAGE_EXT_COUNTDOWN) == (b->flags & ZONE_IMAGE_EXT_COUNTDOWN) && ext_tag_eq(vs, a->loc_tag_off, b->loc_tag_off) &&
           ext_tag_eq(vs, a->ecs_tag_off, b->ecs_tag_off);
}

int zone_image_validate_ex(const void *buf, size_t len, const zone_image_policy_t *pol, char *why, size_t whylen) {
    if (!pol) return zone_image_validate(buf, len, why, whylen);
    int rc = 0;
#define PBAD(...) do { if (why && whylen) snprintf(why, whylen, __VA_ARGS__); return -1; } while (0)
    /* what costs nothing is looked at before the O(len) pass */
    if (pol->announced_size && (uint64_t)len != pol->announced_size) PBAD("the image is %zu octets, ZONE_BEGIN announced %llu", len, (unsigned long long)pol->announced_size);
    if (pol->max_bytes && (uint64_t)len > pol->max_bytes) PBAD("the image is %zu octets, above max-zone-bytes %llu", len, (unsigned long long)pol->max_bytes);
    rc = zone_image_validate(buf, len, why, whylen);
    if (rc != 0) return rc;

    const zone_image_t *img = (const zone_image_t *)buf;
    const uint8_t *base = (const uint8_t *)buf;
    const vstr_t vs = { base + img->off_strings, len - img->off_strings };
    const zone_image_name_t *names = zone_image_names(img);
    const zone_image_rr_t *rrs = zone_image_rrs(img);
    const zone_image_ext_t *exts = zone_image_exts(img);
    const uint32_t n_names = img->n_names, n_rrs = img->n_rrs, apex = img->apex_name;

    if ((uint64_t)n_rrs != pol->rr_count) PBAD("the image has %u RRs, ZONE_BEGIN declared %llu", n_rrs, (unsigned long long)pol->rr_count);
    if (pol->max_records && (uint64_t)n_rrs > pol->max_records) PBAD("the image has %u RRs, above max-zone-records %llu", n_rrs, (unsigned long long)pol->max_records);
    if (((img->flags & ZONE_IMAGE_F_TINYDNS) != 0) != pol->tinydns) PBAD("the tinydns flag of the image differs from ZONE_BEGIN's");
    if (apex == ZONE_IMAGE_NONE || !pol->apex || !domain_names_match_ci(zone_image_name_text(img, apex), pol->apex))
        PBAD("the image has no data at the apex of the zone");

    /* owners: the apex or below it (an alternative spelling of an owner is the same name: validate checked) */
    for (uint32_t id = 0; id < n_names; id++)
        if (!domain_name_is_at_or_below(zone_image_name_text(img, id), pol->apex)) PBAD("name %u is outside the zone", id);

    /* RRs: class IN, no meta type, SOA only at the apex; what the zone is made of (DNSSEC RRs) and what restricts an RR */
    bool signed_zone = false;
    uint32_t nsoa = 0;
    for (uint32_t k = 0; k < n_rrs; k++) {
        const zone_image_rr_t *r = &rrs[k];
        if (r->class_val != 1) PBAD("RR %u: class %u, a zone holds class IN only", k, (unsigned)r->class_val);
        if (r->type == 0 || is_meta_rrtype(r->type)) PBAD("RR %u: type %u cannot be zone data", k, (unsigned)r->type);
        if (r->type == 46 || r->type == 48 || r->type == 47 || r->type == 50) signed_zone = true;
        if (r->type == 6) {
            if (r->name_id != apex) PBAD("RR %u: an SOA outside the apex", k);
            nsoa++;
        }
        if (r->ext_idx && !pol->extended && (ext_restricts(&exts[r->ext_idx - 1]) || (exts[r->ext_idx - 1].flags & ZONE_IMAGE_EXT_COUNTDOWN)))
            PBAD("RR %u: tinydns or tag attributes in a zone that did not announce the extended encoding", k);
    }
    if (nsoa == 0) PBAD("the apex has no SOA");
    if (nsoa > KARIDNS_SOA_SET_MAX) PBAD("more than %u SOA records", (unsigned)KARIDNS_SOA_SET_MAX);
    if (nsoa > 1 && !pol->extended) PBAD("several SOA records in a zone that did not announce the extended encoding");

    /* the SOA RRs (RFC 2181 §6.1: one serial; a signature of the SOA RRset holds for every client or for none) */
    {
        const zone_image_name_t *an = &names[apex];
        const uint32_t first = an->first_rr, last = an->first_rr + (an->rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK);
        bool restricted = false;
        for (uint32_t k = first; k < last; k++) {
            if (rrs[k].type != 6) continue;
            zone_image_soa_t s;
            if (zone_image_soa(img, k, NULL, 0, NULL, 0, &s) != 0) PBAD("RR %u: the apex SOA is malformed", k);
            if (s.serial != pol->serial) PBAD("RR %u: the SOA serial %u is not the one ZONE_BEGIN declared (%u)", k, s.serial, pol->serial);
            if (rrs[k].ext_idx && ext_restricts(&exts[rrs[k].ext_idx - 1])) restricted = true;
        }
        if ((restricted || nsoa > 1) && signed_zone) PBAD("a zone with DNSSEC records and several or restricted SOA records");
        if (nsoa > 1)
            for (uint32_t i = first; i < last; i++) {
                if (rrs[i].type != 6) continue;
                for (uint32_t j = i + 1; j < last; j++)
                    if (rrs[j].type == 6 && img_same_visibility(&vs, rrs[i].ext_idx ? &exts[rrs[i].ext_idx - 1] : NULL, rrs[j].ext_idx ? &exts[rrs[j].ext_idx - 1] : NULL))
                        PBAD("two SOA records for the same clients");
            }
    }

    /* the zone level tables */
    if (img->zattr_len) {
        if (!pol->extended) PBAD("zone level tables in a zone that did not announce the extended encoding");
        int ntr = 0;
        (void)zone_image_ecs_trusted(img, &ntr);
        if (ntr != 0) PBAD("ECS trusted resolvers in the image (they come from the settings of the zone)");
        int nloc = 0;
        (void)zone_image_locations(img, &nloc);
        if (nloc > 4096) PBAD("more than 4096 tinydns locations");
        uint64_t cidrs = 0;
        for (int kind = ZONE_IMAGE_TAGS_LOCATION; kind <= ZONE_IMAGE_TAGS_ECS; kind++) {
            zone_image_tags_t it;
            zone_image_tag_t t;
            zone_image_tags_open(img, kind, &it);
            if (it.left > (uint32_t)XFR_TAGDEF_MAX) PBAD("more than %d tag definitions", XFR_TAGDEF_MAX);
            while (zone_image_tags_next(&it, &t)) cidrs += t.cidr_count;
        }
        if (cidrs > XFR_TAGDEF_CIDR_MAX) PBAD("more than %u CIDRs in the tag definitions", (unsigned)XFR_TAGDEF_CIDR_MAX);
    }
#undef PBAD
    return 0;
}

static int u16_cmp(const void *a, const void *b) {
    uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
    return x < y ? -1 : x > y;
}

int zone_image_check_limits(const zone_image_t *img, const zone_limits_t *lim, char *err, size_t errlen) {
    if (!img || !lim) return 0;
    if (lim->max_records && (uint64_t)img->n_rrs > lim->max_records) {
        snprintf(err, errlen, "the zone has %u records, more than max-records %llu", img->n_rrs, (unsigned long long)lim->max_records);
        return -1;
    }
    const zone_image_rr_t *rrs = zone_image_rrs(img);
    if (lim->max_zone_ttl) {
        for (uint32_t k = 0; k < img->n_rrs; k++) {
            if (rrs[k].ttl > lim->max_zone_ttl) {
                const char *nm = zone_image_name_text(img, rrs[k].name_id);
                snprintf(err, errlen, "'%.200s' type %u has TTL %u, which exceeds the configured max-zone-ttl %u", nm ? nm : "?", (unsigned)rrs[k].type,
                         rrs[k].ttl, lim->max_zone_ttl);
                return -1;
            }
        }
    }
    if (!lim->max_per_type && !lim->max_types_per_name) return 0;
    /* an owner with no more RRs than either limit cannot break it (a type count is at most the RR count): only the others are sorted */
    uint32_t floor_n = UINT32_MAX;
    if (lim->max_per_type && lim->max_per_type < floor_n) floor_n = lim->max_per_type;
    if (lim->max_types_per_name && lim->max_types_per_name < floor_n) floor_n = lim->max_types_per_name;
    uint16_t *types = NULL;
    size_t types_cap = 0;
    int rc = 0;
    const zone_image_name_t *names = zone_image_names(img);
    for (uint32_t id = 0; id < img->n_names && rc == 0; id++) {
        const uint32_t n = names[id].rr_count_flags & ZONE_IMAGE_NAME_COUNT_MASK;
        if (n <= floor_n) continue;
        if (n > types_cap) {
            uint16_t *nt = realloc(types, (size_t)n * sizeof(*types));
            if (!nt) { rc = -2; break; }
            types = nt;
            types_cap = n;
        }
        for (uint32_t i = 0; i < n; i++) types[i] = rrs[names[id].first_rr + i].type;
        qsort(types, n, sizeof(*types), u16_cmp);
        size_t ntypes = 0;
        for (size_t k = 0; k < n;) {
            size_t e = k;
            while (e < n && types[e] == types[k]) e++;
            ntypes++;
            if (lim->max_per_type && e - k > lim->max_per_type) {
                snprintf(err, errlen, "'%.200s' has %zu records of type %u, more than max-records-per-type %u", zone_image_name_text(img, id), e - k,
                         (unsigned)types[k], lim->max_per_type);
                rc = -1;
            }
            k = e;
        }
        if (rc == 0 && lim->max_types_per_name && ntypes > lim->max_types_per_name) {
            snprintf(err, errlen, "'%.200s' has %zu record types, more than max-types-per-name %u", zone_image_name_text(img, id), ntypes,
                     lim->max_types_per_name);
            rc = -1;
        }
    }
    free(types);
    if (rc == -2) snprintf(err, errlen, "out of memory checking the limits of the zone");
    return rc;
}
