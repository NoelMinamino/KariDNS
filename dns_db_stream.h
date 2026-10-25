#ifndef DNS_DB_STREAM_H
#define DNS_DB_STREAM_H

/*
 * dns_db_stream.h - KDB1: the byte stream between karidns-dbloader and the Backend (design: beta design 1.4).
 *
 * Pure functions, no I/O.  Shared by the loader (encoder, decoder of Backend messages) and the Backend
 * (decoder of loader messages + state machine).  The Backend treats every byte as hostile.
 *
 *   encoder  kdb_enc_*       growable buffer (malloc), TLV appenders.                     (encoder side only)
 *   framer   kdb_framer_*    incremental: kdb_framer_feed(bytes) then kdb_framer_next() until KDB_MORE.
 *                            Validates the 12-byte header before the body is buffered.  No allocation: the
 *                            caller supplies the body buffer (KDB_MAX_BODY bytes for the full range).
 *   decoder  kdb_decode      one frame -> typed kdb_msg_t (required tags present, each tag once, unknown tag =
 *                            error, exact integer lengths, ASCII strings, canonical absolute DNS names, view
 *                            index < view count).  No allocation.
 *   machine  kdb_sm_accept   Backend side: AWAIT_HELLO -> READY <-> IN_BATCH <-> IN_ZONE, ZONE_DATA header and
 *                            count / byte / record limit checks.  It does not parse RRs (parse_xfr_packet(), B4b).
 *
 * Wire format: 12-byte header {"KDB1", u16 type, u16 flags (=0), u32 body length}, big-endian.  Body of every
 * message except ZONE_DATA: TLV list {u16 tag, u16 len, value}.  ZONE_DATA body: one DNS message.
 * A TLV length is a u16, so no single value (settings text, nested entry) exceeds 65,535 bytes.
 *
 * Lifetime: kdb_str_t, kdb_frame_t.body and the iterators point into the framer's buffer.  They are valid until
 * the next kdb_framer_next() call; copy what must be kept.  Names are copied into NUL-terminated arrays.
 *
 * Any KDB_E_* result on the Backend is a protocol error: the caller logs reason once and closes the stream.
 * Reasons never contain bytes taken from the stream (no log injection).
 *
 * ---------------------------------------------------------------------------------------------------------
 * Tag tables.  Tags are numbered 1..n per message type (and per nested entry).  R = required, O = optional.
 *   u8/u16/u32/u64/i64: exact length 1/2/4/8, big-endian (i64 two's complement)
 *   str   : printable ASCII 0x20-0x7E, no NUL, length <= max (ne = at least 1 byte)
 *   path  : file path or schema name: valid UTF-8 (RFC 3629, shortest form, no surrogates, <= U+10FFFF) without
 *           control characters (C0, DEL, C1); bytes kept as they are ('%XX' is not decoded); length <= max
 *   text  : like str plus TAB (0x09) and LF (0x0A)
 *   bytes : opaque, length rule given
 *   name  : canonical absolute presentation text as dns_wire.h produces (dns_name_normalize() returns it
 *           unchanged, ends with an unescaped '.'), <= 1024 bytes
 *   view  : u16 index, must be < the number of configured views (when the decoder is told it)
 *   Duplicate, unknown or truncated tags, a wrong length, a missing R tag: protocol error.
 *
 * loader -> Backend
 *   HELLO (1)         1 proto_version u16 R (=1) | 2 loader_version str<=64 R | 3 driver str<=32 R | 4 pid u32 R
 *   INVENTORY_REQ (2) no tags (empty body)
 *   BATCH_BEGIN (3)   1 batch_id u64 R | 2 kind u8 R (0 startup,1 full,2 diff,3 zone,4 auto) | 3 change_seq u64 R |
 *                     4 request_id u64 O (B6a: the batch answers that RELOAD_REQ; absent or 0 = not an answer)
 *   ZONE_BEGIN (4)    1 view view R | 2 zone name R | 3 source_id i64 R | 4 zone_kind u8 R (0 primary,1 secondary,
 *                     2 catalog) | 5 serial u32 R | 6 flags u32 R (bit0 presigned, bit1 extended, bit2 tinydns; others 0) |
 *                     7 rr_count u64 R (primary: both SOAs and, with bit1, the Extended AXFR marker and definition RRs counted, >= 2; secondary and catalog: 0, no ZONE_DATA, B7b) | 8 digest bytes R (exactly 32) |
 *                     9 settings text<=65535 O | 10 profile str ne <=255 O
 *   ZONE_DATA (5)     raw DNS message (<= 65,535 bytes), no TLV
 *   ZONE_END (6)      1 rr_count u64 R
 *   ZONE_ABORT (7)    1 reason str<=255 R
 *   ZONE_FAILED (8)   1 view view R | 2 zone name R | 3 source_id i64 R | 4 reason str<=255 R
 *   ZONE_DELETE (9)   1 view view R | 2 zone name R | 3 source_id i64 R
 *   PROFILE (10)      1 name str ne <=255 R | 2 settings text<=65535 R
 *   BATCH_END (11)    1 batch_id u64 R | 2 n_zones u32 R | 3 n_failed u32 R | 4 n_deleted u32 R
 *   AUTO_STATUS (12)  B9; only between batches (state READY), no state change.  1 ENTRY nested, repeatable (<= 1024), one per view
 *                     that has auto reload on: 1 view view R | 2 last_poll u64 R (unix seconds, 0 = never) |
 *                     3 applied_seq u64 R (change log position of the last complete load) | 4 pending u32 R (changes seen, not yet
 *                     applied) | 5 error str<=255 O (the last poll / load error of the view, absent = none) |
 *                     B11 (multi-server reload requests, PostgreSQL), all optional: 6 flags u8 (bit0 the auto reload fields 2..5 are
 *                     real, bit1 the request fields 7..11 are real; absent = 1) | 7 server_id str ne <=64 (the id the loader reports
 *                     under) | 8 req_generation u64 (the last reload request applied; 0 = none) | 9 req_ok u8 (0/1: every zone of
 *                     that reload loaded) | 10 req_error str<=255 (why the last read of the requests or write of the status
 *                     row failed, absent = none) | 11 req_time u64 (unix seconds of the last status row written, 0 = never).
 *                     An entry is sent for a view that has auto reload on or whose source has the multi-server tables.
 * Backend -> loader (type | 0x8000)
 *   CONFIG (0x8001)   1 generation u64 R | 2 driver str ne <=32 R | 3 server_id str<=64 O |
 *                     4 VIEW nested, repeatable (<= 1024):
 *                         1 index u16 R | 2 name str ne <=255 R | 3 source path ne<=1023 O (absent = driver default; B4a: the Backend repeats the global source for views that use it) |
 *                         4 conninfo_file path ne<=1023 O | 5 auto_reload u8 R (0/1) | 6 poll_interval u32 R (s) |
 *                         7 coalesce_ms u32 R | 8 max_zone_records u64 R | 9 max_zone_bytes u64 R |
 *                         10 shared_source u8 O (0/1; B6b: the source is the global one, so karidns_domain_views maps zones to this view)
 *                     5 default_ttl u32 O (<= 2147483647; B4a) | 6 bulk_threshold u8 O (<= 100) | 7 loader_threads u32 O (<= 16)
 *   RELOAD_REQ (0x8002) 1 request_id u64 R | 2 scope u8 R (0 all, 1 one zone) | 3 view view O | 4 zone name O |
 *                     5 force u8 R (0/1); scope 1 needs tags 3 and 4, scope 0 forbids them
 *   INVENTORY (0x8003) 1 ENTRY nested, repeatable: 1 view view R | 2 zone name R | 3 source_id i64 R |
 *                         4 serial u32 R | 5 digest bytes R (exactly 32)
 *   INVENTORY_END (0x8004) 1 last_change_seq u64 R | 2 n_zones u64 R
 *   ZONE_RESULT (0x8005) 1 view view R | 2 zone name R | 3 status u8 R (0 applied,1 unchanged,2 rejected,
 *                     3 shadowed,4 deleted) | 4 reason str<=255 O
 *   BATCH_RESULT (0x8006) 1 batch_id u64 R | 2 request_ids bytes O (n * u64, <= 2048 bytes) | 3 n_applied u32 R |
 *                     4 n_unchanged u32 R | 5 n_rejected u32 R | 6 n_deleted u32 R
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "dns_wire.h" /* DNS_NAME_TEXT_SIZE */

#define KDB_MAGIC "KDB1"
#define KDB_VERSION 1
#define KDB_HEADER_LEN 12
#define KDB_MAX_BODY (1u << 20)      /* every message but ZONE_DATA */
#define KDB_MAX_ZONE_DATA 65535u     /* ZONE_DATA body */
#define KDB_REASON_LEN 128
#define KDB_DIGEST_LEN 32
#define KDB_VIEWS_ANY 0xFFFFFFFFu    /* view_count: do not check view indexes */
#define KDB_MAX_CONFIG_VIEWS 1024
#define KDB_MAX_PROFILES 65535u      /* PROFILE messages per batch */
#define KDB_DEFAULT_MAX_ZONE_RECORDS 10000000ull
#define KDB_DEFAULT_MAX_ZONE_BYTES (1ull << 30)

enum {
    /* loader -> Backend */
    KDB_T_HELLO = 1, KDB_T_INVENTORY_REQ = 2, KDB_T_BATCH_BEGIN = 3, KDB_T_ZONE_BEGIN = 4, KDB_T_ZONE_DATA = 5,
    KDB_T_ZONE_END = 6, KDB_T_ZONE_ABORT = 7, KDB_T_ZONE_FAILED = 8, KDB_T_ZONE_DELETE = 9, KDB_T_PROFILE = 10,
    KDB_T_BATCH_END = 11, KDB_T_AUTO_STATUS = 12,
    /* Backend -> loader: high bit set */
    KDB_T_CONFIG = 0x8001, KDB_T_RELOAD_REQ = 0x8002, KDB_T_INVENTORY = 0x8003, KDB_T_INVENTORY_END = 0x8004,
    KDB_T_ZONE_RESULT = 0x8005, KDB_T_BATCH_RESULT = 0x8006
};

enum { KDB_BATCH_STARTUP = 0, KDB_BATCH_FULL, KDB_BATCH_DIFF, KDB_BATCH_ZONE, KDB_BATCH_AUTO };
enum { KDB_ZK_PRIMARY = 0, KDB_ZK_SECONDARY, KDB_ZK_CATALOG };
#define KDB_ZF_PRESIGNED 0x1u
#define KDB_ZF_EXTENDED 0x2u    /* ZONE_DATA carries Extended AXFR records (dns_wire.h, xext_*): location / ECS tags, tinydns time stamps and locations */
#define KDB_ZF_TINYDNS 0x4u     /* B8: the zone is a tinydns zone (ZONE_IMAGE_F_TINYDNS: time-dependent TTLs, never cached), also without any time stamp or location */
enum { KDB_ST_APPLIED = 0, KDB_ST_UNCHANGED, KDB_ST_REJECTED, KDB_ST_SHADOWED, KDB_ST_DELETED };

typedef enum {
    KDB_OK = 0,
    KDB_MORE,            /* framer: need more input */
    /* errors (protocol errors for the Backend) */
    KDB_E_MAGIC, KDB_E_TYPE, KDB_E_FLAGS, KDB_E_LENGTH,
    KDB_E_TLV_TRUNC, KDB_E_TLV_DUP, KDB_E_TLV_UNKNOWN, KDB_E_TLV_MISSING, KDB_E_TLV_LEN, KDB_E_TLV_STR,
    KDB_E_TLV_NAME, KDB_E_RANGE,
    KDB_E_STATE, KDB_E_VERSION, KDB_E_DNSHDR, KDB_E_OPT, KDB_E_COUNT, KDB_E_SEQ,
    KDB_E_LIMIT_BYTES, KDB_E_LIMIT_RECORDS, KDB_E_LIMIT_PROFILES
} kdb_rc_t;

static inline bool kdb_rc_is_error(kdb_rc_t rc) { return rc >= KDB_E_MAGIC; }
const char *kdb_rc_name(kdb_rc_t rc);
const char *kdb_type_name(uint16_t type);   /* "?" for an unknown type */

/* ---------------------------------------------------------------- encoder */
typedef struct {
    uint8_t *buf;
    size_t len, cap;
    size_t msg_start, nest_start;
    uint16_t cur_type;
    bool open, nested, err;     /* err is sticky: out of memory, value too long, message too long */
} kdb_enc_t;

void kdb_enc_init(kdb_enc_t *e);
void kdb_enc_free(kdb_enc_t *e);
void kdb_enc_reset(kdb_enc_t *e);                 /* drop the contents, keep the memory */
int kdb_enc_begin(kdb_enc_t *e, uint16_t type);   /* 0, or -1 (sticky error) */
int kdb_enc_u8(kdb_enc_t *e, uint16_t tag, uint8_t v);
int kdb_enc_u16(kdb_enc_t *e, uint16_t tag, uint16_t v);
int kdb_enc_u32(kdb_enc_t *e, uint16_t tag, uint32_t v);
int kdb_enc_u64(kdb_enc_t *e, uint16_t tag, uint64_t v);
int kdb_enc_i64(kdb_enc_t *e, uint16_t tag, int64_t v);
int kdb_enc_bytes(kdb_enc_t *e, uint16_t tag, const void *p, size_t n);   /* n <= 65535 */
int kdb_enc_str(kdb_enc_t *e, uint16_t tag, const char *s);               /* NUL not sent; also used for text */
int kdb_enc_name(kdb_enc_t *e, uint16_t tag, const char *name);           /* the caller passes the canonical form */
int kdb_enc_nest_begin(kdb_enc_t *e, uint16_t tag);                       /* one level */
int kdb_enc_nest_end(kdb_enc_t *e);
int kdb_enc_end(kdb_enc_t *e);                    /* patches the length; fails if above the type's limit */
int kdb_enc_raw_msg(kdb_enc_t *e, uint16_t type, const void *body, size_t n);   /* ZONE_DATA, or crafted bodies */

/* ---------------------------------------------------------------- framer */
typedef enum { KDB_FROM_LOADER = 0, KDB_FROM_BACKEND = 1 } kdb_dir_t;   /* which side wrote the stream */

typedef struct { uint16_t type; const uint8_t *body; uint32_t len; } kdb_frame_t;

typedef struct {
    kdb_dir_t dir;
    uint8_t *buf;                /* body buffer, caller owned, >= KDB_MAX_BODY for the whole range */
    size_t cap;
    const uint8_t *in;
    size_t in_len;
    uint8_t hdr[KDB_HEADER_LEN];
    size_t hdr_have;
    uint32_t body_len, body_have;
    uint16_t type;
    int phase;
    kdb_rc_t fail;               /* sticky */
    char reason[KDB_REASON_LEN];
} kdb_framer_t;

void kdb_framer_init(kdb_framer_t *f, kdb_dir_t dir, uint8_t *buf, size_t cap);
/* Offer input.  The bytes are not copied here: call kdb_framer_next() until KDB_MORE (or an error) before the
 * next feed and before the memory behind p goes away.  Returns KDB_E_STATE if the previous input is not consumed. */
kdb_rc_t kdb_framer_feed(kdb_framer_t *f, const uint8_t *p, size_t n);
/* KDB_OK: *out is one complete, header-validated frame (valid until the next call); KDB_MORE: input used up;
 * KDB_E_*: protocol error (sticky), f->reason says why. */
kdb_rc_t kdb_framer_next(kdb_framer_t *f, kdb_frame_t *out);

/* ---------------------------------------------------------------- decoded messages */
typedef struct { const char *p; uint32_t len; } kdb_str_t;     /* p == NULL: absent */

typedef struct { uint16_t proto; kdb_str_t loader_version, driver; uint32_t pid; } kdb_hello_t;
typedef struct { uint64_t batch_id; uint8_t kind; uint64_t change_seq; uint64_t request_id; /* 0 = none */ } kdb_batch_begin_t;
typedef struct {
    uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; uint8_t zone_kind; uint32_t serial;
    uint32_t flags; uint64_t rr_count; uint8_t digest[KDB_DIGEST_LEN]; kdb_str_t settings, profile;
} kdb_zone_begin_t;
typedef struct {
    const uint8_t *body; uint32_t len;   /* the DNS message */
    uint32_t ancount, arcount;
} kdb_zone_data_t;
typedef struct { uint64_t rr_count; } kdb_zone_end_t;
typedef struct { kdb_str_t reason; } kdb_zone_abort_t;
typedef struct { uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; kdb_str_t reason; } kdb_zone_failed_t;
typedef struct { uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; } kdb_zone_delete_t;
typedef struct { kdb_str_t name, settings; } kdb_profile_t;
typedef struct { uint64_t batch_id; uint32_t n_zones, n_failed, n_deleted; } kdb_batch_end_t;
typedef struct { uint32_t n_entries; const uint8_t *body; uint32_t body_len; } kdb_auto_status_t;     /* entries: kdb_auto_status_entries() */

typedef struct {
    uint64_t generation; kdb_str_t driver, server_id;
    uint32_t default_ttl;       /* 0 = tag absent */
    int bulk_threshold;         /* percent; -1 = tag absent */
    uint32_t loader_threads;    /* 0 = tag absent */
    uint32_t n_views;
    const uint8_t *body; uint32_t body_len;       /* for kdb_config_views() */
} kdb_config_t;
typedef struct {
    uint64_t request_id; uint8_t scope, force; bool has_zone; uint16_t view; char zone[DNS_NAME_TEXT_SIZE];
} kdb_reload_req_t;
typedef struct { uint32_t n_entries; const uint8_t *body; uint32_t body_len; } kdb_inventory_t;
typedef struct { uint64_t last_change_seq, n_zones; } kdb_inventory_end_t;
typedef struct { uint16_t view; char name[DNS_NAME_TEXT_SIZE]; uint8_t status; kdb_str_t reason; } kdb_zone_result_t;
typedef struct {
    uint64_t batch_id; const uint8_t *request_ids; uint32_t n_request_ids;   /* big-endian u64 each */
    uint32_t n_applied, n_unchanged, n_rejected, n_deleted;
} kdb_batch_result_t;

typedef struct {
    uint16_t type;
    uint32_t view_count;       /* as given to kdb_decode() */
    union {
        kdb_hello_t hello; kdb_batch_begin_t batch_begin; kdb_zone_begin_t zone_begin; kdb_zone_data_t zone_data;
        kdb_zone_end_t zone_end; kdb_zone_abort_t zone_abort; kdb_zone_failed_t zone_failed;
        kdb_zone_delete_t zone_delete; kdb_profile_t profile; kdb_batch_end_t batch_end; kdb_auto_status_t auto_status;
        kdb_config_t config; kdb_reload_req_t reload_req; kdb_inventory_t inventory;
        kdb_inventory_end_t inventory_end; kdb_zone_result_t zone_result; kdb_batch_result_t batch_result;
    } u;
} kdb_msg_t;

/* Decode one frame of either direction (the type says which).  view_count: number of configured views, or
 * KDB_VIEWS_ANY.  why (>= KDB_REASON_LEN bytes) receives the reason on error. */
kdb_rc_t kdb_decode(const kdb_frame_t *fr, uint32_t view_count, kdb_msg_t *msg, char *why, size_t whylen);

/* Repeated nested entries of CONFIG and INVENTORY.  The entries were validated by kdb_decode(); the iterator
 * checks again and simply ends on anything unexpected. */
typedef struct { const uint8_t *p; size_t left; uint32_t view_count; } kdb_iter_t;
typedef struct {
    uint16_t index; kdb_str_t name, source, conninfo_file; uint8_t auto_reload; uint32_t poll_interval, coalesce_ms;
    uint64_t max_zone_records, max_zone_bytes;
    uint8_t shared_source;      /* tag 10; 0 = absent */
} kdb_config_view_t;
typedef struct {
    uint16_t view; char name[DNS_NAME_TEXT_SIZE]; int64_t source_id; uint32_t serial; uint8_t digest[KDB_DIGEST_LEN];
} kdb_inventory_entry_t;
#define KDB_AS_AUTO 1u      /* AUTO_STATUS entry flags: the auto reload fields are real */
#define KDB_AS_REQ 2u       /* the reload request fields are real (B11) */
typedef struct {
    uint16_t view; uint64_t last_poll, applied_seq; uint32_t pending; kdb_str_t error;
    uint8_t flags; kdb_str_t server_id; uint64_t req_generation; bool req_ok; kdb_str_t req_error; uint64_t req_time;   /* B11 */
} kdb_auto_status_entry_t;
void kdb_auto_status_entries(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_auto_status_entries_next(kdb_iter_t *it, kdb_auto_status_entry_t *out);
void kdb_config_views(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_config_views_next(kdb_iter_t *it, kdb_config_view_t *out);
void kdb_inventory_entries(const kdb_msg_t *m, kdb_iter_t *it);
bool kdb_inventory_entries_next(kdb_iter_t *it, kdb_inventory_entry_t *out);

/* ---------------------------------------------------------------- Backend state machine */
typedef struct {
    uint64_t max_zone_records;   /* default KDB_DEFAULT_MAX_ZONE_RECORDS */
    uint64_t max_zone_bytes;     /* sum of the ZONE_DATA bodies of one zone; default KDB_DEFAULT_MAX_ZONE_BYTES */
    uint32_t view_count;         /* configured views, or KDB_VIEWS_ANY */
} kdb_limits_t;

typedef enum { KDB_S_AWAIT_HELLO = 0, KDB_S_READY, KDB_S_IN_BATCH, KDB_S_IN_ZONE, KDB_S_ERROR } kdb_state_t;

typedef struct {
    kdb_limits_t lim;
    kdb_state_t state;
    bool inventory_req_seen, batch_seen;
    uint64_t batch_id;
    uint64_t n_zones, n_failed, n_deleted;     /* of the current batch (zones = completed by ZONE_END) */
    uint32_t n_profiles;                       /* of the current batch */
    /* current zone, valid in IN_ZONE */
    uint64_t zone_rr_declared;                 /* ZONE_BEGIN rr_count */
    uint64_t zone_rr_sum;                      /* sum of ANCOUNT so far; at ZONE_END equal to the declared count */
    uint64_t zone_bytes;                       /* sum of ZONE_DATA bodies so far */
    uint32_t zone_data_msgs;
    kdb_rc_t fail;
    char reason[KDB_REASON_LEN];
} kdb_sm_t;

void kdb_sm_init(kdb_sm_t *sm, const kdb_limits_t *lim);   /* lim == NULL: defaults, KDB_VIEWS_ANY */
/* Validate one frame from the loader against the current state, decode it, apply the semantic checks.  KDB_OK:
 * *msg is valid and the state advanced.  KDB_E_*: protocol error; the state is KDB_S_ERROR (sticky) and
 * sm->reason says why.  An error leaves any partial zone to be discarded by the caller. */
kdb_rc_t kdb_sm_accept(kdb_sm_t *sm, const kdb_frame_t *fr, kdb_msg_t *msg);

#endif
