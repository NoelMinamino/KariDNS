/*
 * dns_db_stream.c - KDB1 stream codec and Backend-side state machine (see dns_db_stream.h).
 *
 * No I/O, except the hot list's state file at the end (kdb_hotl_file_read / write: the loader's, never called by the Backend).  The decoder and the
 * state machine never allocate; only the encoder and the hot list (malloc) do.
 * All counts and sums that depend on the stream are 64-bit and compared against limits by subtraction.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "dns_db_stream.h"
#include "dns_utils.h"

static inline uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint64_t be64(const uint8_t *p) { return ((uint64_t)be32(p) << 32) | be32(p + 4); }
static inline void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)(v >> 16)); put16(p + 2, (uint16_t)v); }
static inline void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)(v >> 32)); put32(p + 4, (uint32_t)v); }

#define FAIL(why, wl, rc, ...) do { snprintf((why), (wl), __VA_ARGS__); return (rc); } while (0)

/* ------------------------------------------------------------------ tag tables */
enum { KT_U8, KT_U16, KT_U32, KT_U64, KT_I64, KT_STR, KT_TEXT, KT_BYTES, KT_NAME, KT_NEST, KT_PATH };
#define KS_REQ 1u      /* required */
#define KS_MAXV 2u     /* integer: value <= max */
#define KS_NE 4u       /* str / text: at least one byte */
#define KS_EXACT 8u    /* bytes: length == max */
#define KS_MUL8 16u    /* bytes: length a multiple of 8 */
#define KS_VIEW 32u    /* u16: view index, < view count */

#define KDB_MAX_TAGS 24

typedef struct kdb_tdef kdb_tdef_t;
typedef struct { uint8_t type; uint8_t flags; uint32_t max; const kdb_tdef_t *sub; } kdb_tspec_t;
/* spec[i] describes tag i+1: tags are dense from 1 */
struct kdb_tdef { const char *name; uint8_t n; const kdb_tspec_t *spec; };

#define S(t, f, m) { (t), (f), (m), NULL }
#define TDEF(var, nm, arr) static const kdb_tdef_t var = { nm, (uint8_t)(sizeof(arr) / sizeof((arr)[0])), arr }

static const kdb_tspec_t sp_hello[] = { S(KT_U16, KS_REQ, 0), S(KT_STR, KS_REQ, 64), S(KT_STR, KS_REQ, 32), S(KT_U32, KS_REQ, 0) };
static const kdb_tspec_t sp_batch_begin[] = { S(KT_U64, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 4), S(KT_U64, KS_REQ, 0), S(KT_U64, 0, 0) };
static const kdb_tspec_t sp_zone_begin[] = {
    S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 2),
    S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ | KS_MAXV, KDB_ZF_PRESIGNED | KDB_ZF_EXTENDED | KDB_ZF_TINYDNS | KDB_ZF_SUMMARY), S(KT_U64, KS_REQ, 0),
    S(KT_BYTES, KS_REQ | KS_EXACT, KDB_DIGEST_LEN), S(KT_TEXT, 0, 65535), S(KT_STR, KS_NE, 255), S(KT_U64, 0, 0),
    S(KT_U32, 0, 0), S(KT_U32, 0, 0), S(KT_U32, 0, 0),
    S(KT_NAME, 0, 0), S(KT_NAME, 0, 0), S(KT_U32, KS_MAXV, 2147483647u), S(KT_U32, KS_MAXV, 2147483647u), S(KT_U32, KS_MAXV, 2147483647u),
    S(KT_BYTES, 0, KDB_APEX_NS_BYTES), S(KT_BYTES, 0, KDB_APEX_GLUE_BYTES), S(KT_BYTES, 0, KDB_NOTIFY_ADDR_BYTES) };
static const kdb_tspec_t sp_zone_end[] = { S(KT_U64, KS_REQ, 0) };
static const kdb_tspec_t sp_zone_abort[] = { S(KT_STR, KS_REQ, 255) };
static const kdb_tspec_t sp_zone_failed[] = { S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0), S(KT_STR, KS_REQ, 255), S(KT_U64, 0, 0) };
static const kdb_tspec_t sp_zone_delete[] = { S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0) };
static const kdb_tspec_t sp_profile[] = { S(KT_STR, KS_REQ | KS_NE, 255), S(KT_TEXT, KS_REQ, 65535) };
static const kdb_tspec_t sp_batch_end[] = { S(KT_U64, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0) };
/* B11 adds the optional tags 6..11 (flags, server id, last reload request applied, ok, report error, time of the last report) */
static const kdb_tspec_t sp_auto_entry[] = {
    S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_U64, KS_REQ, 0), S(KT_U64, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_STR, 0, 255),
    S(KT_U8, KS_MAXV, KDB_AS_AUTO | KDB_AS_REQ), S(KT_STR, KS_NE, 64), S(KT_U64, 0, 0), S(KT_U8, KS_MAXV, 1), S(KT_STR, 0, 255),
    S(KT_U64, 0, 0) };
TDEF(td_auto_entry, "AUTO_STATUS.ENTRY", sp_auto_entry);
static const kdb_tspec_t sp_auto_status[] = { { KT_NEST, 0, KDB_MAX_CONFIG_VIEWS, &td_auto_entry } };
TDEF(td_auto_status, "AUTO_STATUS", sp_auto_status);
TDEF(td_hello, "HELLO", sp_hello);
TDEF(td_batch_begin, "BATCH_BEGIN", sp_batch_begin);
TDEF(td_zone_begin, "ZONE_BEGIN", sp_zone_begin);
TDEF(td_zone_end, "ZONE_END", sp_zone_end);
TDEF(td_zone_abort, "ZONE_ABORT", sp_zone_abort);
TDEF(td_zone_failed, "ZONE_FAILED", sp_zone_failed);
TDEF(td_zone_delete, "ZONE_DELETE", sp_zone_delete);
TDEF(td_profile, "PROFILE", sp_profile);
TDEF(td_batch_end, "BATCH_END", sp_batch_end);

static const kdb_tspec_t sp_cfg_view[] = {
    S(KT_U16, KS_REQ, 0), S(KT_STR, KS_REQ | KS_NE, 255), S(KT_PATH, KS_NE, 1023), S(KT_PATH, KS_NE, 1023),
    S(KT_U8, KS_REQ | KS_MAXV, 1), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U64, KS_REQ, 0), S(KT_U64, KS_REQ, 0),
    S(KT_U8, KS_MAXV, 1) };
TDEF(td_cfg_view, "CONFIG.VIEW", sp_cfg_view);
static const kdb_tspec_t sp_config[] = {
    S(KT_U64, KS_REQ, 0), S(KT_STR, KS_REQ | KS_NE, 32), S(KT_STR, 0, 64),
    { KT_NEST, 0, KDB_MAX_CONFIG_VIEWS, &td_cfg_view },
    S(KT_U32, KS_MAXV, 2147483647u), S(KT_U8, KS_MAXV, 100), S(KT_U32, KS_MAXV, 16), S(KT_U8, KS_MAXV, 1) };
TDEF(td_config, "CONFIG", sp_config);
static const kdb_tspec_t sp_reload_req[] = {
    S(KT_U64, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 1), S(KT_U16, KS_VIEW, 0), S(KT_NAME, 0, 0), S(KT_U8, KS_REQ | KS_MAXV, 1) };
TDEF(td_reload_req, "RELOAD_REQ", sp_reload_req);
static const kdb_tspec_t sp_inv_entry[] = {
    S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_I64, KS_REQ, 0), S(KT_U32, KS_REQ, 0),
    S(KT_BYTES, KS_EXACT, KDB_DIGEST_LEN), S(KT_U8, KS_MAXV, 1) };
TDEF(td_inv_entry, "INVENTORY.ENTRY", sp_inv_entry);
static const kdb_tspec_t sp_inventory[] = { { KT_NEST, 0, 65535, &td_inv_entry } };
TDEF(td_inventory, "INVENTORY", sp_inventory);
static const kdb_tspec_t sp_inventory_end[] = { S(KT_U64, KS_REQ, 0), S(KT_U64, KS_REQ, 0) };
TDEF(td_inventory_end, "INVENTORY_END", sp_inventory_end);
static const kdb_tspec_t sp_zone_result[] = {
    S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, KDB_ST_NOT_RESIDENT), S(KT_STR, 0, 255) };
TDEF(td_zone_result, "ZONE_RESULT", sp_zone_result);
static const kdb_tspec_t sp_batch_result[] = {
    S(KT_U64, KS_REQ, 0), S(KT_BYTES, KS_MUL8, 2048), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U32, KS_REQ, 0),
    S(KT_U32, KS_REQ, 0) };
TDEF(td_batch_result, "BATCH_RESULT", sp_batch_result);
static const kdb_tspec_t sp_fetch_req[] = {
    S(KT_U64, KS_REQ, 0), S(KT_U16, KS_REQ | KS_VIEW, 0), S(KT_NAME, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, KDB_FETCH_PRIO_N - 1),
    S(KT_U8, KS_REQ | KS_MAXV, KDB_FETCH_SUMMARY), S(KT_NAME, 0, 0), S(KT_NAME, 0, 0) };
TDEF(td_fetch_req, "FETCH_REQ", sp_fetch_req);
/* D1a step 7: HOT_LIST (Backend -> loader) and WARM_LIST (loader -> Backend) have one layout; tag 5 is for the first, 6 and 7 for the second */
static const kdb_tspec_t sp_hot_entry[] = { S(KT_STR, KS_REQ | KS_NE, 255), S(KT_NAME, KS_REQ, 0) };
TDEF(td_hot_entry, "HOT_LIST.ENTRY", sp_hot_entry);
static const kdb_tspec_t sp_hot_list[] = {
    S(KT_U64, KS_REQ, 0), S(KT_U32, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, 1), { KT_NEST, 0, KDB_HOT_PART_MAX, &td_hot_entry },
    S(KT_U32, KS_MAXV, KDB_HOT_MAX), S(KT_U8, KS_MAXV, KDB_HF_N - 1), S(KT_U32, KS_MAXV, KDB_HOT_MAX) };
TDEF(td_hot_list, "HOT_LIST", sp_hot_list);
TDEF(td_warm_list, "WARM_LIST", sp_hot_list);
static const kdb_tspec_t sp_hot_ack[] = { S(KT_U64, KS_REQ, 0), S(KT_U8, KS_REQ | KS_MAXV, KDB_HA_N - 1), S(KT_U32, KS_REQ, 0), S(KT_STR, 0, 255) };
TDEF(td_hot_ack, "HOT_ACK", sp_hot_ack);

_Static_assert(sizeof(sp_zone_begin) / sizeof(sp_zone_begin[0]) <= KDB_MAX_TAGS, "kdb_val_t arrays are KDB_MAX_TAGS long");
_Static_assert(sizeof(sp_cfg_view) / sizeof(sp_cfg_view[0]) <= KDB_MAX_TAGS, "kdb_val_t arrays are KDB_MAX_TAGS long");

/* INVENTORY_REQ has no tags: any tag is unknown */
static const kdb_tdef_t td_empty = { "INVENTORY_REQ", 0, NULL };

typedef struct {
    uint16_t type; const char *name; kdb_dir_t dir; bool raw; uint32_t maxlen; const kdb_tdef_t *td;
} kdb_mdef_t;

static const kdb_mdef_t mdefs[] = {
    { KDB_T_HELLO, "HELLO", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_hello },
    { KDB_T_INVENTORY_REQ, "INVENTORY_REQ", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_empty },
    { KDB_T_BATCH_BEGIN, "BATCH_BEGIN", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_batch_begin },
    { KDB_T_ZONE_BEGIN, "ZONE_BEGIN", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_begin },
    { KDB_T_ZONE_DATA, "ZONE_DATA", KDB_FROM_LOADER, true, KDB_MAX_ZONE_DATA, NULL },
    { KDB_T_ZONE_END, "ZONE_END", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_end },
    { KDB_T_ZONE_ABORT, "ZONE_ABORT", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_abort },
    { KDB_T_ZONE_FAILED, "ZONE_FAILED", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_failed },
    { KDB_T_ZONE_DELETE, "ZONE_DELETE", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_zone_delete },
    { KDB_T_PROFILE, "PROFILE", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_profile },
    { KDB_T_BATCH_END, "BATCH_END", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_batch_end },
    { KDB_T_AUTO_STATUS, "AUTO_STATUS", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_auto_status },
    { KDB_T_WARM_LIST, "WARM_LIST", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_warm_list },
    { KDB_T_HOT_ACK, "HOT_ACK", KDB_FROM_LOADER, false, KDB_MAX_BODY, &td_hot_ack },
    { KDB_T_CONFIG, "CONFIG", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_config },
    { KDB_T_RELOAD_REQ, "RELOAD_REQ", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_reload_req },
    { KDB_T_INVENTORY, "INVENTORY", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_inventory },
    { KDB_T_INVENTORY_END, "INVENTORY_END", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_inventory_end },
    { KDB_T_ZONE_RESULT, "ZONE_RESULT", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_zone_result },
    { KDB_T_BATCH_RESULT, "BATCH_RESULT", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_batch_result },
    { KDB_T_FETCH_REQ, "FETCH_REQ", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_fetch_req },
    { KDB_T_HOT_LIST, "HOT_LIST", KDB_FROM_BACKEND, false, KDB_MAX_BODY, &td_hot_list },
};
#define NMDEFS (sizeof(mdefs) / sizeof(mdefs[0]))

static const kdb_mdef_t *mdef_find(uint16_t type) {
    for (size_t i = 0; i < NMDEFS; i++)
        if (mdefs[i].type == type) return &mdefs[i];
    return NULL;
}

const char *kdb_type_name(uint16_t type) {
    const kdb_mdef_t *m = mdef_find(type);
    return m ? m->name : "?";
}

const char *kdb_rc_name(kdb_rc_t rc) {
    switch (rc) {
    case KDB_OK: return "ok";
    case KDB_MORE: return "more";
    case KDB_E_MAGIC: return "bad magic";
    case KDB_E_TYPE: return "unknown type";
    case KDB_E_FLAGS: return "bad flags";
    case KDB_E_LENGTH: return "bad length";
    case KDB_E_TLV_TRUNC: return "truncated TLV";
    case KDB_E_TLV_DUP: return "duplicate tag";
    case KDB_E_TLV_UNKNOWN: return "unknown tag";
    case KDB_E_TLV_MISSING: return "missing tag";
    case KDB_E_TLV_LEN: return "bad value length";
    case KDB_E_TLV_STR: return "bad string";
    case KDB_E_TLV_NAME: return "bad name";
    case KDB_E_RANGE: return "value out of range";
    case KDB_E_STATE: return "message not allowed in this state";
    case KDB_E_VERSION: return "protocol version mismatch";
    case KDB_E_DNSHDR: return "bad ZONE_DATA DNS header";
    case KDB_E_OPT: return "OPT outside the first ZONE_DATA";
    case KDB_E_COUNT: return "RR count mismatch";
    case KDB_E_SEQ: return "batch mismatch";
    case KDB_E_LIMIT_BYTES: return "zone byte limit exceeded";
    case KDB_E_LIMIT_RECORDS: return "zone record limit exceeded";
    case KDB_E_LIMIT_PROFILES: return "profile limit exceeded";
    }
    return "?";
}

/* ------------------------------------------------------------------ TLV parser */
typedef struct { bool present; uint64_t u; const uint8_t *p; uint32_t len; } kdb_val_t;

/* A canonical absolute presentation-format name: dns_name_normalize() returns it unchanged. */
/* The glue list of a summary's apex: records ns index u8 | type u8 | ttl u32 | address, the indexes (< ns_count) not decreasing, at most KDB_APEX_GLUE_PER_NS
 * records for one index, each address as long as its type says (RFC 1035 3.4.1: an A record is 4 octets, RFC 3596 2.2: AAAA is 16), the TTL at most 2^31 - 1
 * (RFC 2181 8).  The bytes come from a loader that is not trusted. */
bool kdb_apex_glue_valid(const uint8_t *p, size_t len, unsigned ns_count) {
    unsigned last = 0, per = 0;
    for (size_t i = 0; i < len;) {
        if (len - i < 6) return false;
        unsigned idx = p[i], type = p[i + 1];
        uint32_t ttl = ((uint32_t)p[i + 2] << 24) | ((uint32_t)p[i + 3] << 16) | ((uint32_t)p[i + 4] << 8) | p[i + 5];
        size_t al = type == 1 ? 4 : type == 28 ? 16 : 0;
        if (al == 0 || len - i - 6 < al || idx >= ns_count || idx < last || ttl > 2147483647u) return false;
        per = idx == last && i != 0 ? per + 1 : 1;
        if (per > KDB_APEX_GLUE_PER_NS) return false;
        last = idx;
        i += 6 + al;
    }
    return true;
}

/* The NOTIFY address list of a summary (tag 22): records ns index u8 | type u8 | address, the indexes (< ns_count) not decreasing, at most
 * KDB_NOTIFY_ADDR_PER_NS records for one index, each address as long as its type says (RFC 1035 3.4.1, RFC 3596 2.2).  The bytes come from a loader that
 * is not trusted. */
bool kdb_notify_addrs_valid(const uint8_t *p, size_t len, unsigned ns_count) {
    unsigned last = 0, per = 0;
    for (size_t i = 0; i < len;) {
        if (len - i < 2) return false;
        unsigned idx = p[i], type = p[i + 1];
        size_t al = type == 1 ? 4 : type == 28 ? 16 : 0;
        if (al == 0 || len - i - 2 < al || idx >= ns_count || idx < last) return false;
        per = idx == last && i != 0 ? per + 1 : 1;
        if (per > KDB_NOTIFY_ADDR_PER_NS) return false;
        last = idx;
        i += 2 + al;
    }
    return true;
}

static bool name_ok(const uint8_t *p, size_t n) {
    if (n == 0 || n > DNS_NAME_TEXT_SIZE - 1) return false;
    for (size_t i = 0; i < n; i++)   /* canonical text is graphic ASCII only (space, controls, >= 0x7F are \DDD) */
        if (p[i] < 0x21 || p[i] > 0x7E) return false;
    char in[DNS_NAME_TEXT_SIZE], out[DNS_NAME_TEXT_SIZE];
    memcpy(in, p, n);
    in[n] = '\0';
    size_t r = dns_name_normalize(in, out, sizeof(out));
    if (r != n || memcmp(in, out, n) != 0) return false;
    return dns_name_len_no_root(in, n) != n;   /* ends with an unescaped '.' (or is the root) */
}

/* File paths and schema names (KT_PATH): any valid UTF-8 (RFC 3629 §3/§4: shortest form only, no surrogates
 * U+D800..U+DFFF, nothing above U+10FFFF) without control characters (C0, DEL, C1 U+0080..U+009F). The bytes are
 * used as they are: no decoding of '%XX', '\' or anything else, so "a%65.sqlite3" names that file literally (the
 * loader opens SQLite files without SQLITE_OPEN_URI). */
static bool path_ok(const uint8_t *p, size_t n) { return dns_path_is_valid_utf8(p, n); }

static bool str_ok(const uint8_t *p, size_t n, bool text) {
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        if (c >= 0x20 && c <= 0x7E) continue;
        if (text && (c == '\t' || c == '\n')) continue;
        return false;
    }
    return true;
}

/* Parse the TLV list b[0..n) against d.  vals[0..d->n) receive the values.  *nrep (may be NULL) the number of
 * entries of the repeatable nested tag; nested entries are validated and not kept. */
static kdb_rc_t tlv_parse(const kdb_tdef_t *d, const uint8_t *b, size_t n, uint32_t vc, kdb_val_t *vals,
                          uint32_t *nrep, char *why, size_t wl) {
    memset(vals, 0, sizeof(*vals) * d->n);
    if (nrep) *nrep = 0;
    size_t off = 0;
    while (off < n) {
        if (n - off < 4) FAIL(why, wl, KDB_E_TLV_TRUNC, "%s: truncated TLV header", d->name);
        uint16_t tag = be16(b + off), len = be16(b + off + 2);
        off += 4;
        if (len > n - off) FAIL(why, wl, KDB_E_TLV_TRUNC, "%s: tag %u length %u exceeds the body", d->name, tag, len);
        if (tag == 0 || tag > d->n) FAIL(why, wl, KDB_E_TLV_UNKNOWN, "%s: unknown tag %u", d->name, tag);
        const kdb_tspec_t *s = &d->spec[tag - 1];
        const uint8_t *v = b + off;
        off += len;
        if (s->type == KT_NEST) {
            if (!nrep || *nrep >= s->max) FAIL(why, wl, KDB_E_RANGE, "%s: too many entries (tag %u)", d->name, tag);
            kdb_val_t sv[KDB_MAX_TAGS];
            kdb_rc_t rc = tlv_parse(s->sub, v, len, vc, sv, NULL, why, wl);
            if (rc != KDB_OK) return rc;
            (*nrep)++;
            continue;
        }
        kdb_val_t *x = &vals[tag - 1];
        if (x->present) FAIL(why, wl, KDB_E_TLV_DUP, "%s: duplicate tag %u", d->name, tag);
        x->p = v;
        x->len = len;
        switch (s->type) {
        case KT_U8: case KT_U16: case KT_U32: case KT_U64: case KT_I64: {
            static const uint8_t want[] = { 1, 2, 4, 8, 8 };
            if (len != want[s->type]) FAIL(why, wl, KDB_E_TLV_LEN, "%s: tag %u length %u, want %u", d->name, tag, len, want[s->type]);
            x->u = (len == 1) ? v[0] : (len == 2) ? be16(v) : (len == 4) ? be32(v) : be64(v);
            if ((s->flags & KS_MAXV) && x->u > s->max) FAIL(why, wl, KDB_E_RANGE, "%s: tag %u value out of range", d->name, tag);
            if ((s->flags & KS_VIEW) && vc != KDB_VIEWS_ANY && x->u >= vc)
                FAIL(why, wl, KDB_E_RANGE, "%s: view index %u >= %u views", d->name, (unsigned)x->u, vc);
            break;
        }
        case KT_STR: case KT_TEXT:
            if (len > s->max || ((s->flags & KS_NE) && len == 0)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u string length %u", d->name, tag, len);
            if (!str_ok(v, len, s->type == KT_TEXT)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u has a non-printable byte", d->name, tag);
            break;
        case KT_BYTES:
            if (((s->flags & KS_EXACT) ? len != s->max : len > s->max) || ((s->flags & KS_MUL8) && (len % 8) != 0))
                FAIL(why, wl, KDB_E_TLV_LEN, "%s: tag %u bytes length %u", d->name, tag, len);
            break;
        case KT_PATH:
            if (len > s->max || ((s->flags & KS_NE) && len == 0)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u path length %u", d->name, tag, len);
            if (!path_ok(v, len)) FAIL(why, wl, KDB_E_TLV_STR, "%s: tag %u is not valid UTF-8 or has a control character", d->name, tag);
            break;
        case KT_NAME:
            if (!name_ok(v, len)) FAIL(why, wl, KDB_E_TLV_NAME, "%s: tag %u is not a canonical absolute name", d->name, tag);
            break;
        default:
            FAIL(why, wl, KDB_E_TLV_UNKNOWN, "%s: internal table error", d->name);
        }
        x->present = true;
    }
    for (unsigned i = 0; i < d->n; i++)
        if ((d->spec[i].flags & KS_REQ) && !vals[i].present)
            FAIL(why, wl, KDB_E_TLV_MISSING, "%s: missing required tag %u", d->name, i + 1);
    return KDB_OK;
}

#define V(i) (vals[(i) - 1])
static kdb_str_t gstr(const kdb_val_t *v) {
    kdb_str_t s = { NULL, 0 };
    if (v->present) { s.p = (const char *)v->p; s.len = v->len; }
    return s;
}
static void gname(char *out, const kdb_val_t *v) {   /* validated: <= DNS_NAME_TEXT_SIZE - 1 bytes */
    memcpy(out, v->p, v->len);
    out[v->len] = '\0';
}

/* ------------------------------------------------------------------ decoder */
kdb_rc_t kdb_decode(const kdb_frame_t *fr, uint32_t vc, kdb_msg_t *m, char *why, size_t wl) {
    const kdb_mdef_t *md = mdef_find(fr->type);
    if (!md) FAIL(why, wl, KDB_E_TYPE, "unknown message type %u", fr->type);
    if (fr->len > md->maxlen) FAIL(why, wl, KDB_E_LENGTH, "%s: body length %u above the limit", md->name, fr->len);
    memset(m, 0, sizeof(*m));
    m->type = fr->type;
    m->view_count = vc;

    if (md->raw) {   /* ZONE_DATA: DNS header checks without parsing RRs (RFC 1035 4.1.1, RFC 5936 2.2) */
        const uint8_t *b = fr->body;
        if (fr->len < DNS_HEADER_SIZE) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: %u bytes, shorter than a DNS header", fr->len);
        uint16_t fl = be16(b + 2), qd = be16(b + 4), an = be16(b + 6), ns = be16(b + 8), ar = be16(b + 10);
        if (!(fl & 0x8000)) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: QR is not set");
        if ((fl >> 11) & 0xF) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: opcode is not QUERY");
        if (!(fl & 0x0400)) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: AA is not set (RFC 5936 2.2.1)");
        if (fl & 0x0200) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: TC is set (RFC 5936 2.2.1)");
        if (fl & 0x000F) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: RCODE is not 0");
        if (qd != 0) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: QDCOUNT is not 0");
        if (ns != 0) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: NSCOUNT is not 0 (RFC 5936 2.2.4)");
        if (ar > 1) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: ARCOUNT above 1");
        if (an == 0) FAIL(why, wl, KDB_E_DNSHDR, "ZONE_DATA: no answer RR");
        m->u.zone_data.body = b;
        m->u.zone_data.len = fr->len;
        m->u.zone_data.ancount = an;
        m->u.zone_data.arcount = ar;
        return KDB_OK;
    }

    kdb_val_t vals[KDB_MAX_TAGS];
    uint32_t nrep = 0;
    kdb_rc_t rc = tlv_parse(md->td, fr->body, fr->len, vc, vals, &nrep, why, wl);
    if (rc != KDB_OK) return rc;

    switch (fr->type) {
    case KDB_T_HELLO:
        m->u.hello.proto = (uint16_t)V(1).u;
        m->u.hello.loader_version = gstr(&V(2));
        m->u.hello.driver = gstr(&V(3));
        m->u.hello.pid = (uint32_t)V(4).u;
        break;
    case KDB_T_INVENTORY_REQ:
        break;
    case KDB_T_BATCH_BEGIN:
        m->u.batch_begin.batch_id = V(1).u;
        m->u.batch_begin.kind = (uint8_t)V(2).u;
        m->u.batch_begin.change_seq = V(3).u;
        m->u.batch_begin.request_id = V(4).present ? V(4).u : 0;
        break;
    case KDB_T_ZONE_BEGIN: {
        kdb_zone_begin_t *z = &m->u.zone_begin;
        z->view = (uint16_t)V(1).u;
        gname(z->name, &V(2));
        z->source_id = (int64_t)V(3).u;
        z->zone_kind = (uint8_t)V(4).u;
        z->serial = (uint32_t)V(5).u;
        z->flags = (uint32_t)V(6).u;
        z->rr_count = V(7).u;
        memcpy(z->digest, V(8).p, KDB_DIGEST_LEN);
        z->settings = gstr(&V(9));
        z->profile = gstr(&V(10));
        if (V(11).present) {
            if (V(11).u == 0) FAIL(why, wl, KDB_E_RANGE, "ZONE_BEGIN: request id 0");
            z->request_id = V(11).u;
        }
        if ((z->flags & KDB_ZF_SUMMARY) && z->zone_kind != KDB_ZK_PRIMARY)
            FAIL(why, wl, KDB_E_RANGE, "ZONE_BEGIN: the summary flag on a zone that is not a primary");
        if (V(12).present != V(13).present || V(12).present != V(14).present)
            FAIL(why, wl, KDB_E_TLV_MISSING, "ZONE_BEGIN: the SOA timers (tags 12, 13, 14) come all together or not at all");
        if (V(12).present) {
            z->has_soa_timers = true;
            z->soa_refresh = (uint32_t)V(12).u;
            z->soa_retry = (uint32_t)V(13).u;
            z->soa_expire = (uint32_t)V(14).u;
        }
        z->has_apex = false;
        z->naddrs = NULL;
        z->naddrs_len = 0;
        {
            unsigned np = 0;
            for (unsigned t = 15; t <= 20; t++) np += V(t).present ? 1u : 0u;
            if (np != 0 && np != 6) FAIL(why, wl, KDB_E_TLV_MISSING, "ZONE_BEGIN: the apex (tags 15 to 20) comes all together or not at all");
            if (V(21).present && np != 6) FAIL(why, wl, KDB_E_TLV_MISSING, "ZONE_BEGIN: the glue (tag 21) is part of the apex (tags 15 to 20)");
            if (V(22).present && np != 6) FAIL(why, wl, KDB_E_TLV_MISSING, "ZONE_BEGIN: the NOTIFY addresses (tag 22) are part of the apex (tags 15 to 20)");
            if (np == 6) {
                if (!(z->flags & KDB_ZF_SUMMARY) || !V(12).present)
                    FAIL(why, wl, KDB_E_RANGE, "ZONE_BEGIN: the apex of a zone is for a summary with the SOA timers only");
                /* the NS names: 1..KDB_APEX_NS_MAX canonical absolute names, one LF between two (RFC 1035 3.1: a name is at most 255 octets on the wire) */
                const uint8_t *p = V(20).p;
                uint32_t len = V(20).len, start = 0, cnt = 0;
                for (uint32_t i = 0; i <= len; i++) {
                    if (i < len && p[i] != '\n') continue;
                    if (cnt == KDB_APEX_NS_MAX || !name_ok(p + start, i - start))
                        FAIL(why, wl, KDB_E_TLV_NAME, "ZONE_BEGIN: tag 20 is not a list of 1 to %u canonical absolute names", (unsigned)KDB_APEX_NS_MAX);
                    cnt++;
                    start = i + 1;
                }
                z->glue = NULL;
                z->glue_len = 0;
                if (V(21).present && V(21).len > 0) {
                    if (!kdb_apex_glue_valid(V(21).p, V(21).len, cnt))
                        FAIL(why, wl, KDB_E_RANGE, "ZONE_BEGIN: tag 21 is not a list of address records of the names of tag 20");
                    z->glue = V(21).p;
                    z->glue_len = (uint16_t)V(21).len;
                }
                if (V(22).present && V(22).len > 0) {
                    if (!kdb_notify_addrs_valid(V(22).p, V(22).len, cnt))
                        FAIL(why, wl, KDB_E_RANGE, "ZONE_BEGIN: tag 22 is not a list of address records of the names of tag 20");
                    z->naddrs = V(22).p;
                    z->naddrs_len = (uint16_t)V(22).len;
                }
                z->has_apex = true;
                gname(z->soa_mname, &V(15));
                gname(z->soa_rname, &V(16));
                z->soa_minimum = (uint32_t)V(17).u;
                z->soa_ttl = (uint32_t)V(18).u;
                z->ns_ttl = (uint32_t)V(19).u;
                z->ns_names = (const char *)p;
                z->ns_names_len = (uint16_t)len;
                z->ns_count = (uint8_t)cnt;
            }
        }
        break;

    }
    case KDB_T_ZONE_END:
        m->u.zone_end.rr_count = V(1).u;
        break;
    case KDB_T_ZONE_ABORT:
        m->u.zone_abort.reason = gstr(&V(1));
        break;
    case KDB_T_ZONE_FAILED:
        m->u.zone_failed.view = (uint16_t)V(1).u;
        gname(m->u.zone_failed.name, &V(2));
        m->u.zone_failed.source_id = (int64_t)V(3).u;
        m->u.zone_failed.reason = gstr(&V(4));
        if (V(5).present) {
            if (V(5).u == 0) FAIL(why, wl, KDB_E_RANGE, "ZONE_FAILED: request id 0");
            m->u.zone_failed.request_id = V(5).u;
        }
        break;
    case KDB_T_ZONE_DELETE:
        m->u.zone_delete.view = (uint16_t)V(1).u;
        gname(m->u.zone_delete.name, &V(2));
        m->u.zone_delete.source_id = (int64_t)V(3).u;
        break;
    case KDB_T_PROFILE:
        m->u.profile.name = gstr(&V(1));
        m->u.profile.settings = gstr(&V(2));
        break;
    case KDB_T_BATCH_END:
        m->u.batch_end.batch_id = V(1).u;
        m->u.batch_end.n_zones = (uint32_t)V(2).u;
        m->u.batch_end.n_failed = (uint32_t)V(3).u;
        m->u.batch_end.n_deleted = (uint32_t)V(4).u;
        break;
    case KDB_T_AUTO_STATUS:
        m->u.auto_status.n_entries = nrep;
        m->u.auto_status.body = fr->body;
        m->u.auto_status.body_len = fr->len;
        break;
    case KDB_T_HOT_LIST:
    case KDB_T_WARM_LIST: {
        kdb_hot_list_t *h = &m->u.hot_list;
        h->list_id = V(1).u;
        h->part = (uint32_t)V(2).u;
        h->last = V(3).u != 0;
        h->n_entries = nrep;
        h->limit = V(5).present ? (uint32_t)V(5).u : 0;
        h->file_state = V(6).present ? (int)V(6).u : -1;
        h->file_zones = V(7).present ? (uint32_t)V(7).u : 0;
        h->body = fr->body;
        h->body_len = fr->len;
        break;
    }
    case KDB_T_HOT_ACK:
        m->u.hot_ack.list_id = V(1).u;
        m->u.hot_ack.status = (uint8_t)V(2).u;
        m->u.hot_ack.zones = (uint32_t)V(3).u;
        m->u.hot_ack.error = gstr(&V(4));
        break;
    case KDB_T_CONFIG:
        m->u.config.generation = V(1).u;
        m->u.config.driver = gstr(&V(2));
        m->u.config.server_id = gstr(&V(3));
        m->u.config.default_ttl = V(5).present ? (uint32_t)V(5).u : 0;
        m->u.config.bulk_threshold = V(6).present ? (int)V(6).u : -1;
        m->u.config.loader_threads = V(7).present ? (uint32_t)V(7).u : 0;
        m->u.config.dir_only = V(8).present && V(8).u != 0;
        m->u.config.n_views = nrep;
        m->u.config.body = fr->body;
        m->u.config.body_len = fr->len;
        break;
    case KDB_T_RELOAD_REQ: {
        kdb_reload_req_t *r = &m->u.reload_req;
        r->request_id = V(1).u;
        r->scope = (uint8_t)V(2).u;
        r->force = (uint8_t)V(5).u;
        bool hv = V(3).present, hz = V(4).present;
        if (r->scope == 1 && !(hv && hz)) FAIL(why, wl, KDB_E_TLV_MISSING, "RELOAD_REQ: scope 1 needs view and zone");
        if (r->scope == 0 && (hv || hz)) FAIL(why, wl, KDB_E_RANGE, "RELOAD_REQ: scope 0 takes no view or zone");
        if (hv) r->view = (uint16_t)V(3).u;
        if (hz) { gname(r->zone, &V(4)); r->has_zone = true; }
        break;
    }
    case KDB_T_INVENTORY: {
        m->u.inventory.n_entries = nrep;
        m->u.inventory.body = fr->body;
        m->u.inventory.body_len = fr->len;
        /* the one rule the tag table cannot say: a resident zone has its digest (the iterator ends at an entry that does not) */
        kdb_iter_t it;
        kdb_inventory_entry_t en;
        uint32_t k = 0;
        kdb_inventory_entries(m, &it);
        while (kdb_inventory_entries_next(&it, &en)) k++;
        if (k != nrep) FAIL(why, wl, KDB_E_TLV_MISSING, "INVENTORY.ENTRY: a resident zone needs its digest (tag 5)");
        break;
    }
    case KDB_T_FETCH_REQ: {
        kdb_fetch_req_t *r = &m->u.fetch_req;
        r->request_id = V(1).u;
        if (r->request_id == 0) FAIL(why, wl, KDB_E_RANGE, "FETCH_REQ: request id 0");
        r->view = (uint16_t)V(2).u;
        gname(r->name, &V(3));
        r->priority = (uint8_t)V(4).u;
        r->mode = (uint8_t)V(5).u;
        if (V(6).present != V(7).present) FAIL(why, wl, KDB_E_TLV_MISSING, "FETCH_REQ: a range needs both range_lo and range_hi");
        if (V(6).present) {
            r->has_range = true;
            gname(r->range_lo, &V(6));
            gname(r->range_hi, &V(7));
        }
        break;
    }
    case KDB_T_INVENTORY_END:
        m->u.inventory_end.last_change_seq = V(1).u;
        m->u.inventory_end.n_zones = V(2).u;
        break;
    case KDB_T_ZONE_RESULT:
        m->u.zone_result.view = (uint16_t)V(1).u;
        gname(m->u.zone_result.name, &V(2));
        m->u.zone_result.status = (uint8_t)V(3).u;
        m->u.zone_result.reason = gstr(&V(4));
        break;
    case KDB_T_BATCH_RESULT:
        m->u.batch_result.batch_id = V(1).u;
        if (V(2).present) {
            m->u.batch_result.request_ids = V(2).p;
            m->u.batch_result.n_request_ids = V(2).len / 8;
        }
        m->u.batch_result.n_applied = (uint32_t)V(3).u;
        m->u.batch_result.n_unchanged = (uint32_t)V(4).u;
        m->u.batch_result.n_rejected = (uint32_t)V(5).u;
        m->u.batch_result.n_deleted = (uint32_t)V(6).u;
        break;
    default:
        FAIL(why, wl, KDB_E_TYPE, "unknown message type %u", fr->type);
    }
    return KDB_OK;
}

/* ------------------------------------------------------------------ iterators */
static bool nest_next(kdb_iter_t *it, uint16_t tag, const kdb_tdef_t *sub, kdb_val_t *vals) {
    while (it->left >= 4) {
        uint16_t t = be16(it->p), l = be16(it->p + 2);
        if ((size_t)l > it->left - 4) break;
        const uint8_t *v = it->p + 4;
        it->p += 4 + (size_t)l;
        it->left -= 4 + (size_t)l;
        if (t != tag) continue;
        char why[KDB_REASON_LEN];
        if (tlv_parse(sub, v, l, it->view_count, vals, NULL, why, sizeof(why)) != KDB_OK) break;
        return true;
    }
    it->left = 0;
    return false;
}

void kdb_auto_status_entries(const kdb_msg_t *m, kdb_iter_t *it) {
    bool ok = m->type == KDB_T_AUTO_STATUS;
    it->p = ok ? m->u.auto_status.body : NULL;
    it->left = ok ? m->u.auto_status.body_len : 0;
    it->view_count = m->view_count;
}

bool kdb_auto_status_entries_next(kdb_iter_t *it, kdb_auto_status_entry_t *o) {
    kdb_val_t vals[KDB_MAX_TAGS];
    if (!nest_next(it, 1, &td_auto_entry, vals)) return false;
    o->view = (uint16_t)V(1).u;
    o->last_poll = V(2).u;
    o->applied_seq = V(3).u;
    o->pending = (uint32_t)V(4).u;
    o->error = gstr(&V(5));
    o->flags = V(6).present ? (uint8_t)V(6).u : KDB_AS_AUTO;      /* a loader of B9/B10 sends no flags: the entry is about auto reload */
    o->server_id = gstr(&V(7));
    o->req_generation = V(8).present ? V(8).u : 0;
    o->req_ok = V(9).present && V(9).u != 0;
    o->req_error = gstr(&V(10));
    o->req_time = V(11).present ? V(11).u : 0;
    return true;
}

void kdb_config_views(const kdb_msg_t *m, kdb_iter_t *it) {
    bool ok = m->type == KDB_T_CONFIG;
    it->p = ok ? m->u.config.body : NULL;
    it->left = ok ? m->u.config.body_len : 0;
    it->view_count = KDB_VIEWS_ANY;
}

bool kdb_config_views_next(kdb_iter_t *it, kdb_config_view_t *o) {
    kdb_val_t vals[KDB_MAX_TAGS];
    if (!nest_next(it, 4, &td_cfg_view, vals)) return false;
    o->index = (uint16_t)V(1).u;
    o->name = gstr(&V(2));
    o->source = gstr(&V(3));
    o->conninfo_file = gstr(&V(4));
    o->auto_reload = (uint8_t)V(5).u;
    o->poll_interval = (uint32_t)V(6).u;
    o->coalesce_ms = (uint32_t)V(7).u;
    o->max_zone_records = V(8).u;
    o->max_zone_bytes = V(9).u;
    o->shared_source = V(10).present ? (uint8_t)V(10).u : 0;
    return true;
}

void kdb_inventory_entries(const kdb_msg_t *m, kdb_iter_t *it) {
    bool ok = m->type == KDB_T_INVENTORY;
    it->p = ok ? m->u.inventory.body : NULL;
    it->left = ok ? m->u.inventory.body_len : 0;
    it->view_count = m->view_count;
}

bool kdb_inventory_entries_next(kdb_iter_t *it, kdb_inventory_entry_t *o) {
    kdb_val_t vals[KDB_MAX_TAGS];
    if (!nest_next(it, 1, &td_inv_entry, vals)) return false;
    o->view = (uint16_t)V(1).u;
    gname(o->name, &V(2));
    o->source_id = (int64_t)V(3).u;
    o->serial = (uint32_t)V(4).u;
    o->resident = !V(6).present || V(6).u != 0;
    if (o->resident && !V(5).present) {          /* tlv_parse() cannot say "required unless tag 6 is 0" */
        it->left = 0;
        return false;
    }
    if (V(5).present) memcpy(o->digest, V(5).p, KDB_DIGEST_LEN);
    else memset(o->digest, 0, KDB_DIGEST_LEN);
    return true;
}

/* ------------------------------------------------------------------ framer */
enum { PH_HDR = 0, PH_BODY, PH_DONE };

void kdb_framer_init(kdb_framer_t *f, kdb_dir_t dir, uint8_t *buf, size_t cap) {
    memset(f, 0, sizeof(*f));
    f->dir = dir;
    f->buf = buf;
    f->cap = cap;
}

kdb_rc_t kdb_framer_feed(kdb_framer_t *f, const uint8_t *p, size_t n) {
    if (f->fail != KDB_OK) return f->fail;
    if (f->in_len != 0) return KDB_E_STATE;
    f->in = p;
    f->in_len = n;
    return KDB_OK;
}

#define FRFAIL(f, code, ...) do { (f)->fail = (code); snprintf((f)->reason, sizeof((f)->reason), __VA_ARGS__); \
    (f)->in_len = 0; return (code); } while (0)

kdb_rc_t kdb_framer_next(kdb_framer_t *f, kdb_frame_t *out) {
    if (f->fail != KDB_OK) return f->fail;
    if (f->phase == PH_DONE) {
        f->phase = PH_HDR;
        f->hdr_have = 0;
        f->body_have = 0;
    }
    if (f->phase == PH_HDR) {
        size_t take = KDB_HEADER_LEN - f->hdr_have;
        if (take > f->in_len) take = f->in_len;
        if (take) {                                   /* (no pointer arithmetic on an input that was never offered: next() may be called first) */
            memcpy(f->hdr + f->hdr_have, f->in, take);
            f->in += take;
            f->in_len -= take;
        }
        f->hdr_have += take;
        if (f->hdr_have < KDB_HEADER_LEN) return KDB_MORE;
        if (memcmp(f->hdr, KDB_MAGIC, 4) != 0) FRFAIL(f, KDB_E_MAGIC, "bad magic");
        uint16_t type = be16(f->hdr + 4), flags = be16(f->hdr + 6);
        uint32_t len = be32(f->hdr + 8);
        const kdb_mdef_t *md = mdef_find(type);
        if (!md || md->dir != f->dir) FRFAIL(f, KDB_E_TYPE, "unknown message type %u", type);
        if (flags != 0) FRFAIL(f, KDB_E_FLAGS, "flags %u, must be 0", flags);
        if (len > md->maxlen) FRFAIL(f, KDB_E_LENGTH, "%s body length %u above the limit of the type", md->name, len);
        if (len > f->cap) FRFAIL(f, KDB_E_LENGTH, "%s body length %u above the receive buffer", md->name, len);
        f->type = type;
        f->body_len = len;
        f->body_have = 0;
        f->phase = PH_BODY;
    }
    /* PH_BODY */
    size_t take = f->body_len - f->body_have;
    if (take > f->in_len) take = f->in_len;
    if (take) {
        memcpy(f->buf + f->body_have, f->in, take);
        f->in += take;
        f->in_len -= take;
    }
    f->body_have += (uint32_t)take;
    if (f->body_have < f->body_len) return KDB_MORE;
    f->phase = PH_DONE;
    out->type = f->type;
    out->body = f->buf;
    out->len = f->body_len;
    return KDB_OK;
}

/* ------------------------------------------------------------------ encoder */
void kdb_enc_init(kdb_enc_t *e) { memset(e, 0, sizeof(*e)); }
void kdb_enc_free(kdb_enc_t *e) { free(e->buf); memset(e, 0, sizeof(*e)); }
void kdb_enc_reset(kdb_enc_t *e) { e->len = 0; e->open = e->nested = e->err = false; }

static int enc_room(kdb_enc_t *e, size_t n) {
    if (e->err) return -1;
    if (n > SIZE_MAX - e->len) { e->err = true; return -1; }
    size_t need = e->len + n;
    if (need <= e->cap) return 0;
    size_t nc = e->cap ? e->cap : 256;
    while (nc < need) {
        if (nc > SIZE_MAX / 2) { e->err = true; return -1; }
        nc *= 2;
    }
    uint8_t *nb = realloc(e->buf, nc);
    if (!nb) { e->err = true; return -1; }
    e->buf = nb;
    e->cap = nc;
    return 0;
}

int kdb_enc_begin(kdb_enc_t *e, uint16_t type) {
    if (e->err || e->open || !mdef_find(type)) { e->err = true; return -1; }
    if (enc_room(e, KDB_HEADER_LEN) != 0) return -1;
    e->msg_start = e->len;
    memcpy(e->buf + e->len, KDB_MAGIC, 4);
    put16(e->buf + e->len + 4, type);
    put16(e->buf + e->len + 6, 0);
    put32(e->buf + e->len + 8, 0);
    e->len += KDB_HEADER_LEN;
    e->cur_type = type;
    e->open = true;
    return 0;
}

static int enc_tlv(kdb_enc_t *e, uint16_t tag, const void *p, size_t n) {
    if (e->err || !e->open || n > 65535) { e->err = true; return -1; }
    if (enc_room(e, 4 + n) != 0) return -1;
    put16(e->buf + e->len, tag);
    put16(e->buf + e->len + 2, (uint16_t)n);
    if (n) memcpy(e->buf + e->len + 4, p, n);
    e->len += 4 + n;
    return 0;
}

int kdb_enc_u8(kdb_enc_t *e, uint16_t tag, uint8_t v) { return enc_tlv(e, tag, &v, 1); }
int kdb_enc_u16(kdb_enc_t *e, uint16_t tag, uint16_t v) { uint8_t b[2]; put16(b, v); return enc_tlv(e, tag, b, 2); }
int kdb_enc_u32(kdb_enc_t *e, uint16_t tag, uint32_t v) { uint8_t b[4]; put32(b, v); return enc_tlv(e, tag, b, 4); }
int kdb_enc_u64(kdb_enc_t *e, uint16_t tag, uint64_t v) { uint8_t b[8]; put64(b, v); return enc_tlv(e, tag, b, 8); }
int kdb_enc_i64(kdb_enc_t *e, uint16_t tag, int64_t v) { return kdb_enc_u64(e, tag, (uint64_t)v); }
int kdb_enc_bytes(kdb_enc_t *e, uint16_t tag, const void *p, size_t n) { return enc_tlv(e, tag, p, n); }
int kdb_enc_str(kdb_enc_t *e, uint16_t tag, const char *s) { return enc_tlv(e, tag, s, strlen(s)); }
int kdb_enc_name(kdb_enc_t *e, uint16_t tag, const char *name) { return enc_tlv(e, tag, name, strlen(name)); }

int kdb_enc_nest_begin(kdb_enc_t *e, uint16_t tag) {
    if (e->err || !e->open || e->nested) { e->err = true; return -1; }
    if (enc_tlv(e, tag, NULL, 0) != 0) return -1;
    e->nest_start = e->len - 4;
    e->nested = true;
    return 0;
}

int kdb_enc_nest_end(kdb_enc_t *e) {
    if (e->err || !e->nested) { e->err = true; return -1; }
    size_t n = e->len - e->nest_start - 4;
    if (n > 65535) { e->err = true; return -1; }
    put16(e->buf + e->nest_start + 2, (uint16_t)n);
    e->nested = false;
    return 0;
}

int kdb_enc_end(kdb_enc_t *e) {
    if (e->err || !e->open || e->nested) { e->err = true; return -1; }
    const kdb_mdef_t *md = mdef_find(e->cur_type);
    size_t body = e->len - e->msg_start - KDB_HEADER_LEN;
    if (!md || body > md->maxlen) { e->err = true; return -1; }
    put32(e->buf + e->msg_start + 8, (uint32_t)body);
    e->open = false;
    return 0;
}

int kdb_enc_raw_msg(kdb_enc_t *e, uint16_t type, const void *body, size_t n) {
    if (e->err || e->open || n > UINT32_MAX || n > SIZE_MAX - KDB_HEADER_LEN) { e->err = true; return -1; }
    if (enc_room(e, KDB_HEADER_LEN + n) != 0) return -1;
    memcpy(e->buf + e->len, KDB_MAGIC, 4);
    put16(e->buf + e->len + 4, type);
    put16(e->buf + e->len + 6, 0);
    put32(e->buf + e->len + 8, (uint32_t)n);
    if (n) memcpy(e->buf + e->len + KDB_HEADER_LEN, body, n);
    e->len += KDB_HEADER_LEN + n;
    return 0;
}

/* ------------------------------------------------------------------ state machine */
void kdb_sm_init(kdb_sm_t *sm, const kdb_limits_t *lim) {
    memset(sm, 0, sizeof(*sm));
    if (lim) {
        sm->lim = *lim;
    } else {
        sm->lim.max_zone_records = KDB_DEFAULT_MAX_ZONE_RECORDS;
        sm->lim.max_zone_bytes = KDB_DEFAULT_MAX_ZONE_BYTES;
        sm->lim.view_count = KDB_VIEWS_ANY;
    }
    sm->state = KDB_S_AWAIT_HELLO;
}

void kdb_sm_init_fetch(kdb_sm_t *sm, const kdb_limits_t *lim) {
    kdb_sm_init(sm, lim);
    sm->fetch = true;
    sm->state = KDB_S_READY;         /* no HELLO: the first stream has said who the loader is */
}

static bool sm_legal(const kdb_sm_t *sm, uint16_t t) {
    if (sm->fetch) {
        switch (sm->state) {
        case KDB_S_READY: return t == KDB_T_ZONE_BEGIN || t == KDB_T_ZONE_FAILED || t == KDB_T_PROFILE;
        case KDB_S_IN_ZONE: return t == KDB_T_ZONE_DATA || t == KDB_T_ZONE_END || t == KDB_T_ZONE_ABORT;
        default: return false;
        }
    }
    switch (sm->state) {
    case KDB_S_AWAIT_HELLO: return t == KDB_T_HELLO;
    case KDB_S_READY:
        return (t == KDB_T_INVENTORY_REQ && !sm->inventory_req_seen && !sm->batch_seen) || t == KDB_T_BATCH_BEGIN ||
               t == KDB_T_AUTO_STATUS || t == KDB_T_WARM_LIST || t == KDB_T_HOT_ACK;
    case KDB_S_IN_BATCH:
        return t == KDB_T_ZONE_BEGIN || t == KDB_T_ZONE_FAILED || t == KDB_T_ZONE_DELETE || t == KDB_T_PROFILE ||
               t == KDB_T_BATCH_END;
    case KDB_S_IN_ZONE: return t == KDB_T_ZONE_DATA || t == KDB_T_ZONE_END || t == KDB_T_ZONE_ABORT;
    case KDB_S_ERROR: break;
    }
    return false;
}

#define SMFAIL(sm, rc, ...) do { (sm)->state = KDB_S_ERROR; (sm)->fail = (rc); \
    snprintf((sm)->reason, sizeof((sm)->reason), __VA_ARGS__); return (rc); } while (0)

kdb_rc_t kdb_sm_accept(kdb_sm_t *sm, const kdb_frame_t *fr, kdb_msg_t *m) {
    if (sm->state == KDB_S_ERROR) return sm->fail;
    if (!sm_legal(sm, fr->type)) SMFAIL(sm, KDB_E_STATE, "%s not allowed in state %d", kdb_type_name(fr->type), (int)sm->state);
    kdb_rc_t rc = kdb_decode(fr, sm->lim.view_count, m, sm->reason, sizeof(sm->reason));
    if (rc != KDB_OK) { sm->state = KDB_S_ERROR; sm->fail = rc; return rc; }

    switch (fr->type) {
    case KDB_T_HELLO:
        if (m->u.hello.proto != KDB_VERSION) SMFAIL(sm, KDB_E_VERSION, "HELLO: protocol version %u, want %u", m->u.hello.proto, KDB_VERSION);
        sm->state = KDB_S_READY;
        break;
    case KDB_T_INVENTORY_REQ:
        sm->inventory_req_seen = true;
        break;
    case KDB_T_AUTO_STATUS:
    case KDB_T_WARM_LIST:
    case KDB_T_HOT_ACK:
        break;                                   /* B9, D1a step 7: informational, no state change */
    case KDB_T_BATCH_BEGIN:
        sm->batch_seen = true;
        sm->batch_id = m->u.batch_begin.batch_id;
        sm->n_zones = sm->n_failed = sm->n_deleted = 0;
        sm->n_profiles = 0;
        sm->state = KDB_S_IN_BATCH;
        break;
    case KDB_T_PROFILE:
        if (sm->n_profiles >= KDB_MAX_PROFILES) SMFAIL(sm, KDB_E_LIMIT_PROFILES, "PROFILE: more than %u profiles in a batch", KDB_MAX_PROFILES);
        sm->n_profiles++;
        break;
    case KDB_T_ZONE_FAILED:
        if (sm->fetch != (m->u.zone_failed.request_id != 0))
            SMFAIL(sm, KDB_E_STATE, sm->fetch ? "ZONE_FAILED: the fetch stream needs the request id" : "ZONE_FAILED: a request id belongs to the fetch stream");
        sm->n_failed++;
        if (sm->fetch) sm->n_profiles = 0;       /* (the profiles were for this zone) */
        break;
    case KDB_T_ZONE_DELETE:
        sm->n_deleted++;
        break;
    case KDB_T_ZONE_BEGIN: {
        uint64_t n = m->u.zone_begin.rr_count;
        uint8_t zk = m->u.zone_begin.zone_kind;
        bool summary = (m->u.zone_begin.flags & KDB_ZF_SUMMARY) != 0;
        if (sm->fetch != (m->u.zone_begin.request_id != 0))
            SMFAIL(sm, KDB_E_STATE, sm->fetch ? "ZONE_BEGIN: the fetch stream needs the request id" : "ZONE_BEGIN: a request id belongs to the fetch stream");
        sm->zone_req_id = m->u.zone_begin.request_id;
        if (zk == KDB_ZK_PRIMARY && summary) {
            if (n != 0) SMFAIL(sm, KDB_E_COUNT, "ZONE_BEGIN: a summary has rr_count 0, not %llu", (unsigned long long)n);
        } else if (zk == KDB_ZK_PRIMARY) {
            if (n < 2) SMFAIL(sm, KDB_E_COUNT, "ZONE_BEGIN: rr_count %llu, an AXFR has at least two SOAs (RFC 5936 2.2)", (unsigned long long)n);
        } else if (n != 0) {
            /* B7b: a secondary / catalog consumer zone carries no data (the Backend transfers it from the masters in the settings) */
            SMFAIL(sm, KDB_E_COUNT, "ZONE_BEGIN: a secondary zone has rr_count 0, not %llu", (unsigned long long)n);
        }
        if (n > sm->lim.max_zone_records) SMFAIL(sm, KDB_E_LIMIT_RECORDS, "ZONE_BEGIN: rr_count above max-zone-records");
        sm->zone_rr_declared = n;
        sm->zone_rr_sum = 0;
        sm->zone_bytes = 0;
        sm->zone_data_msgs = 0;
        sm->state = KDB_S_IN_ZONE;
        break;
    }
    case KDB_T_ZONE_DATA: {
        uint32_t len = m->u.zone_data.len;
        /* zone_bytes <= max_zone_bytes and zone_rr_sum <= zone_rr_declared hold here: subtract, never add */
        if ((uint64_t)len > sm->lim.max_zone_bytes - sm->zone_bytes) SMFAIL(sm, KDB_E_LIMIT_BYTES, "ZONE_DATA: zone above max-zone-bytes");
        if (m->u.zone_data.arcount != 0 && sm->zone_data_msgs != 0)
            SMFAIL(sm, KDB_E_OPT, "ZONE_DATA: ARCOUNT in a message after the first of the zone");
        if ((uint64_t)m->u.zone_data.ancount > sm->zone_rr_declared - sm->zone_rr_sum)
            SMFAIL(sm, KDB_E_COUNT, "ZONE_DATA: more RRs than ZONE_BEGIN declared");
        sm->zone_bytes += len;
        sm->zone_rr_sum += m->u.zone_data.ancount;
        if (sm->zone_data_msgs < UINT32_MAX) sm->zone_data_msgs++;
        break;
    }
    case KDB_T_ZONE_END:
        if (m->u.zone_end.rr_count != sm->zone_rr_declared) SMFAIL(sm, KDB_E_COUNT, "ZONE_END: count differs from ZONE_BEGIN");
        if (sm->zone_rr_sum != sm->zone_rr_declared) SMFAIL(sm, KDB_E_COUNT, "ZONE_END: ANCOUNT sum differs from the declared count");
        sm->n_zones++;
        if (sm->fetch) sm->n_profiles = 0;
        sm->state = sm->fetch ? KDB_S_READY : KDB_S_IN_BATCH;
        break;
    case KDB_T_ZONE_ABORT:
        if (sm->fetch) sm->n_profiles = 0;
        sm->state = sm->fetch ? KDB_S_READY : KDB_S_IN_BATCH;
        break;
    case KDB_T_BATCH_END: {
        const kdb_batch_end_t *b = &m->u.batch_end;
        if (b->batch_id != sm->batch_id) SMFAIL(sm, KDB_E_SEQ, "BATCH_END: batch id differs from BATCH_BEGIN");
        if (b->n_zones != sm->n_zones || b->n_failed != sm->n_failed || b->n_deleted != sm->n_deleted)
            SMFAIL(sm, KDB_E_COUNT, "BATCH_END: counts differ from the messages seen");
        sm->state = KDB_S_READY;
        break;
    }
    default:
        SMFAIL(sm, KDB_E_STATE, "%s not allowed from the loader", kdb_type_name(fr->type));
    }
    return KDB_OK;
}

/* ------------------------------------------------------------------ hot list (D1a step 7, design 8.4) */
void kdb_hotl_init(kdb_hotl_t *l) { memset(l, 0, sizeof(*l)); }
void kdb_hotl_free(kdb_hotl_t *l) { free(l->buf); memset(l, 0, sizeof(*l)); }
void kdb_hotl_clear(kdb_hotl_t *l) { l->len = 0; l->n = 0; }

static bool hot_view_ok(const char *v, size_t n) {
    return n >= 1 && n <= 255 && str_ok((const uint8_t *)v, n, false);
}

bool kdb_hotl_add(kdb_hotl_t *l, const char *view, const char *zone) {
    size_t vn = strlen(view), zn = strlen(zone);
    if (l->n >= KDB_HOT_MAX || !hot_view_ok(view, vn) || !name_ok((const uint8_t *)zone, zn)) return false;
    size_t need = vn + 1 + zn + 1;
    if (need > SIZE_MAX - l->len) return false;
    if (l->len + need > l->cap) {
        size_t nc = l->cap ? l->cap : 1024;
        while (nc < l->len + need) {
            if (nc > SIZE_MAX / 2) return false;
            nc *= 2;
        }
        char *nb = realloc(l->buf, nc);
        if (!nb) return false;
        l->buf = nb;
        l->cap = nc;
    }
    memcpy(l->buf + l->len, view, vn + 1);
    memcpy(l->buf + l->len + vn + 1, zone, zn + 1);
    l->len += need;
    l->n++;
    return true;
}

bool kdb_hotl_next(const kdb_hotl_t *l, size_t *pos, const char **view, const char **zone) {
    if (*pos >= l->len) return false;
    const char *v = l->buf + *pos;
    size_t vn = strlen(v);
    const char *z = v + vn + 1;
    *view = v;
    *zone = z;
    *pos += vn + 1 + strlen(z) + 1;
    return true;
}

bool kdb_hotl_equal(const kdb_hotl_t *a, const kdb_hotl_t *b) {
    return a->n == b->n && a->len == b->len && (a->len == 0 || memcmp(a->buf, b->buf, a->len) == 0);
}

static uint32_t hot_fnv(uint32_t h, const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) h = (h ^ b[i]) * 16777619u;
    return h;
}

bool kdb_hotl_merge(const kdb_hotl_t *fresh, const kdb_hotl_t *old, uint32_t limit, kdb_hotl_t *out) {
    kdb_hotl_clear(out);
    if (limit == 0 || limit > KDB_HOT_MAX) limit = KDB_HOT_MAX;
    size_t cap = 16;
    while (cap < ((size_t)fresh->n + old->n) * 2) cap *= 2;
    const char **tab = calloc(cap, sizeof(*tab));            /* the start of a pair ("view\0zone\0") in fresh or old */
    if (!tab) return false;
    const kdb_hotl_t *src[2] = { fresh, old };
    bool ok = true;
    for (int s = 0; s < 2 && ok; s++) {
        size_t pos = 0;
        const char *v, *z;
        while (out->n < limit && kdb_hotl_next(src[s], &pos, &v, &z)) {
            uint32_t h = hot_fnv(hot_fnv(2166136261u, v, strlen(v) + 1), z, strlen(z));
            size_t i = h & (cap - 1);
            bool dup = false;
            while (tab[i]) {
                const char *tv = tab[i], *tz = tv + strlen(tv) + 1;
                if (strcmp(tv, v) == 0 && strcmp(tz, z) == 0) {
                    dup = true;
                    break;
                }
                i = (i + 1) & (cap - 1);
            }
            if (dup) continue;
            tab[i] = v;
            if (!kdb_hotl_add(out, v, z)) {
                ok = false;
                break;
            }
        }
    }
    free(tab);
    return ok;
}

int kdb_hot_encode(const kdb_hotl_t *l, kdb_enc_t *e, uint16_t type, uint64_t list_id, uint32_t limit, int file_state, uint32_t file_zones,
                   int (*emit)(void *ud), void *ud) {
    size_t pos = 0;
    uint32_t part = 0;
    const char *v = NULL, *z = NULL;
    bool more = kdb_hotl_next(l, &pos, &v, &z);
    for (;;) {
        if (kdb_enc_begin(e, type) != 0 || kdb_enc_u64(e, 1, list_id) != 0 || kdb_enc_u32(e, 2, part) != 0) return -1;
        uint32_t n = 0;
        while (more && n < KDB_HOT_PART_MAX) {
            size_t need = 4 + (4 + strlen(v)) + (4 + strlen(z));
            size_t body = e->len - e->msg_start - KDB_HEADER_LEN;
            if (n > 0 && body + need + 64 > KDB_MAX_BODY) break;        /* (64: the tags that follow the entries) */
            if (kdb_enc_nest_begin(e, 4) != 0 || kdb_enc_str(e, 1, v) != 0 || kdb_enc_name(e, 2, z) != 0 || kdb_enc_nest_end(e) != 0) return -1;
            n++;
            more = kdb_hotl_next(l, &pos, &v, &z);
        }
        if (kdb_enc_u8(e, 3, more ? 0 : 1) != 0) return -1;
        if (limit && kdb_enc_u32(e, 5, limit) != 0) return -1;
        if (file_state >= 0 && (kdb_enc_u8(e, 6, (uint8_t)file_state) != 0 || kdb_enc_u32(e, 7, file_zones) != 0)) return -1;
        if (kdb_enc_end(e) != 0) return -1;
        if (emit(ud) != 0) return -1;
        kdb_enc_reset(e);
        if (!more) return 0;
        part++;
    }
}

void kdb_hot_entries(const kdb_msg_t *m, kdb_iter_t *it) {
    bool ok = m->type == KDB_T_HOT_LIST || m->type == KDB_T_WARM_LIST;
    it->p = ok ? m->u.hot_list.body : NULL;
    it->left = ok ? m->u.hot_list.body_len : 0;
    it->view_count = KDB_VIEWS_ANY;
}

bool kdb_hot_entries_next(kdb_iter_t *it, char view[256], char zone[DNS_NAME_TEXT_SIZE]) {
    kdb_val_t vals[KDB_MAX_TAGS];
    if (!nest_next(it, 4, &td_hot_entry, vals)) return false;
    memcpy(view, V(1).p, V(1).len);
    view[V(1).len] = '\0';
    gname(zone, &V(2));
    return true;
}

/* ---- the state file */
#define HOT_HDR "KARIDNS-HOT-LIST 1\n"

char *kdb_hotl_serialize(const kdb_hotl_t *l, size_t *len) {
    size_t cap = sizeof(HOT_HDR) + l->len + l->n + 64;      /* each pair gains a TAB and a newline in place of two NULs; the END line */
    char *out = malloc(cap);
    if (!out) return NULL;
    size_t o = sizeof(HOT_HDR) - 1;
    memcpy(out, HOT_HDR, o);
    uint32_t sum = 2166136261u;
    size_t pos = 0;
    const char *v, *z;
    while (kdb_hotl_next(l, &pos, &v, &z)) {
        size_t start = o;
        size_t vn = strlen(v), zn = strlen(z);
        memcpy(out + o, v, vn);
        o += vn;
        out[o++] = '\t';
        memcpy(out + o, z, zn);
        o += zn;
        out[o++] = '\n';
        sum = hot_fnv(sum, out + start, o - start);
    }
    int n = snprintf(out + o, cap - o, "END %u %08x\n", (unsigned)l->n, (unsigned)sum);
    *len = o + (size_t)n;
    return out;
}

bool kdb_hotl_parse(const char *buf, size_t len, kdb_hotl_t *out, char *why, size_t wl) {
#define PFAIL(...) do { snprintf(why, wl, __VA_ARGS__); kdb_hotl_clear(out); return false; } while (0)
    kdb_hotl_clear(out);
    if (len == 0) PFAIL("the file is empty");
    if (len < sizeof(HOT_HDR) - 1 || memcmp(buf, HOT_HDR, sizeof(HOT_HDR) - 1) != 0) PFAIL("no \"KARIDNS-HOT-LIST 1\" header");
    size_t off = sizeof(HOT_HDR) - 1;
    uint32_t sum = 2166136261u;
    for (unsigned line = 2;; line++) {
        if (off >= len) PFAIL("truncated: no END line");
        const char *p = buf + off;
        const char *nl = memchr(p, '\n', len - off);
        if (!nl) PFAIL("truncated: line %u has no end", line);
        size_t ll = (size_t)(nl - p);
        const char *tab = memchr(p, '\t', ll);
        if (!tab) {                                            /* the END line, or garbage */
            char tmp[48];
            if (ll < 5 || ll >= sizeof(tmp) || memcmp(p, "END ", 4) != 0) PFAIL("line %u is neither an entry nor the END line", line);
            memcpy(tmp, p, ll);
            tmp[ll] = '\0';
            char *e1, *e2;
            unsigned long cnt = strtoul(tmp + 4, &e1, 10);
            if (e1 == tmp + 4 || *e1 != ' ') PFAIL("the END line is not \"END <count> <checksum>\"");
            unsigned long want = strtoul(e1 + 1, &e2, 16);
            if (e2 != e1 + 9 || *e2 != '\0' || want > 0xFFFFFFFFul) PFAIL("the END line is not \"END <count> <checksum>\"");
            if (cnt != out->n) PFAIL("the END line counts %lu entries, the file has %u", cnt, (unsigned)out->n);
            if ((uint32_t)want != sum) PFAIL("the checksum does not match");
            if (off + ll + 1 != len) PFAIL("bytes after the END line");
            return true;
        }
        size_t vn = (size_t)(tab - p), zn = ll - vn - 1;
        char v[256], z[DNS_NAME_TEXT_SIZE];
        if (vn == 0 || vn >= sizeof(v) || zn == 0 || zn >= sizeof(z)) PFAIL("line %u: view or zone name length", line);
        memcpy(v, p, vn);
        v[vn] = '\0';
        memcpy(z, tab + 1, zn);
        z[zn] = '\0';
        if (!kdb_hotl_add(out, v, z)) PFAIL("line %u is not a valid entry, or the list is too long", line);
        sum = hot_fnv(sum, p, ll + 1);
        off += ll + 1;
    }
#undef PFAIL
}

int kdb_hotl_file_read(const char *path, kdb_hotl_t *out, char *why, size_t wl) {
    kdb_hotl_clear(out);
    /* never through a link, and never blocking on a fifo or a device that somebody put in its place (it is then not a regular file: UNREADABLE) */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT) {
            snprintf(why, wl, "no such file");
            return KDB_HF_MISSING;
        }
        snprintf(why, wl, "%s", strerror(errno));
        return KDB_HF_UNREADABLE;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        snprintf(why, wl, "%s", strerror(errno));
        close(fd);
        return KDB_HF_UNREADABLE;
    }
    if (!S_ISREG(st.st_mode)) {
        snprintf(why, wl, "not a regular file");
        close(fd);
        return KDB_HF_UNREADABLE;
    }
    if (st.st_size < 0 || (uint64_t)st.st_size > KDB_HOT_FILE_MAX) {
        snprintf(why, wl, "the file is larger than %u bytes", (unsigned)KDB_HOT_FILE_MAX);
        close(fd);
        return KDB_HF_CORRUPT;
    }
    size_t cap = (size_t)st.st_size + 1, n = 0;
    char *b = malloc(cap);
    if (!b) {
        snprintf(why, wl, "out of memory");
        close(fd);
        return KDB_HF_UNREADABLE;
    }
    int rc = KDB_HF_LOADED;
    for (;;) {
        ssize_t r = read(fd, b + n, cap - n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) {
            snprintf(why, wl, "%s", strerror(errno));
            rc = KDB_HF_UNREADABLE;
            break;
        }
        if (r == 0) break;
        n += (size_t)r;
        if (n == cap) {                                        /* it grew while we read it */
            snprintf(why, wl, "the file changed while it was read");
            rc = KDB_HF_CORRUPT;
            break;
        }
    }
    close(fd);
    if (rc == KDB_HF_LOADED && !kdb_hotl_parse(b, n, out, why, wl)) rc = KDB_HF_CORRUPT;
    free(b);
    return rc;
}

int kdb_hotl_file_write(const char *path, const kdb_hotl_t *l, char *err, size_t el) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
        snprintf(err, el, "the path is too long");
        return -1;
    }
    size_t len = 0;
    char *data = kdb_hotl_serialize(l, &len);
    if (!data) {
        snprintf(err, el, "out of memory");
        return -1;
    }
    /* A temporary file that an earlier run left is ours to remove if it is a regular file of this user; anything else (a link, a file of another user, a directory)
     * is somebody's doing in the loader's directory, and the write fails rather than follow it.  The new file is created with O_EXCL. */
    struct stat ls;
    if (lstat(tmp, &ls) == 0) {
        if (!S_ISREG(ls.st_mode) || ls.st_uid != geteuid()) {
            snprintf(err, el, "cannot create %s: it exists and is not a regular file of this user", tmp);
            free(data);
            return -1;
        }
        if (unlink(tmp) != 0) {
            snprintf(err, el, "cannot create %s: the old file cannot be removed: %s", tmp, strerror(errno));
            free(data);
            return -1;
        }
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        snprintf(err, el, "cannot create %s: %s", tmp, strerror(errno));
        free(data);
        return -1;
    }
    size_t done = 0;
    int bad = 0;
    while (done < len) {
        ssize_t w = write(fd, data + done, len - done);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) {
            bad = errno ? errno : EIO;
            break;
        }
        done += (size_t)w;
    }
    free(data);
    if (!bad && fsync(fd) != 0) bad = errno;
    if (close(fd) != 0 && !bad) bad = errno;
    if (!bad && rename(tmp, path) != 0) bad = errno;
    if (bad) {
        snprintf(err, el, "cannot write %s: %s", path, strerror(bad));
        (void)unlink(tmp);
        return -1;
    }
    /* the rename is in the directory: make it durable too (best effort: the file itself is complete either way) */
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *sl = strrchr(dir, '/');
    if (sl) *(sl == dir ? sl + 1 : sl) = '\0';
    else snprintf(dir, sizeof(dir), ".");
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }
    return 0;
}
