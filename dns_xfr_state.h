#ifndef DNS_XFR_STATE_H
#define DNS_XFR_STATE_H

/*
 * dns_xfr_state - the pure part of the secondaries' copies in the zone store (0.7, planing_0.7.x_secondary_store.md 2.2, 2.3, 3.1, 4.3, 4.5): the key of a copy,
 * the 32-byte "secondary state" kept in the record's digest, the identity and the primaries digest, and the decisions that need no server (D7, the up-to-date
 * rule, the clock sanity of a restore, the skip rule of a failure write).  No I/O, no allocation, no lock: dns_xfr_store.c (the server), the unit test and the
 * fuzz harness (tests/fuzz/fuzz_xfr_state.c) link it alone.
 *
 * The state (little endian; the cell CRC of the store protects the bytes, not the meaning, so every field is range-checked by xfr_state_decode()):
 *   off size
 *    0   1   version (XFR_STATE_VERSION)
 *    1   1   kind (XFR_K_*)
 *    2   1   flags (XFR_SF_*)
 *    3   1   reserved, 0
 *    4   4   primaries digest: CRC-32C of the primaries (address, port, key name per element, in order) and the zone's tsig-key name; a change means "refresh at once"
 *    8   8   identity: FNV-1a 64 of the kind, the zone, the full lowercased view name, a member's unique-id (RFC 9432 §4.1), a database zone's domains.id; a change
 *            means "another zone": the copy is not used
 *   16   4   last successful refresh, unix seconds (u32: until 2106)
 *   20   4   the expire deadline as a delta from the last successful refresh, seconds.  XFR_SF_EXPIRE_OPT clear: 0 = last refresh + SOA EXPIRE (RFC 1034 §4.3.5);
 *            set: the deadline the EXPIRE option gave (RFC 7314 §4), and 0 = expired at once (an EXPIRE option of 0)
 *   24   4   last attempt, unix seconds (0 = none)
 *   28   4   rx settings id (0 = none; R1 is P4)
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define XFR_STATE_VERSION 2
#define XFR_STATE_LEN     32
#define XFR_KEY_ZONE_MAX  245      /* a canonical zone name longer than this has no key (255 - the tag, the kind and the dot): not persisted */
#define XFR_KEY_MAX       255
#define XFR_CLOCK_SLACK   300      /* a persisted time this far in the future (seconds) is taken as now at a restore (in memory only) */

enum { XFR_K_CONFIG = 1, XFR_K_CATALOG = 2, XFR_K_MEMBER = 3, XFR_K_DB_SLAVE = 4, XFR_K_DB_CONSUMER = 5 };
#define XFR_SF_FAILED     0x01u    /* the last attempt failed */
#define XFR_SF_EXPIRE_OPT 0x02u    /* the deadline came from an EXPIRE option (RFC 7314) */
#define XFR_SF_FROM_FILE  0x04u    /* the image came from `file` (stored on an up-to-date refresh, never transferred) */
#define XFR_SF_RX_LOST    0x08u    /* settings were received (Extended AXFR v3) but not persisted (R2): the first refresh after a restore asks for the whole zone */
#define XFR_SF_ALL        0x0Fu

typedef struct {
  uint8_t kind, flags;
  uint32_t primaries;
  uint64_t identity;
  uint32_t last_ok, expire_delta, last_attempt, rx_settings;
} xfr_state_t;

void xfr_state_encode(const xfr_state_t *s, uint8_t out[XFR_STATE_LEN]);
/* 0, or -1: not a state of this version (another version, a kind out of range, a reserved byte or flag set, no successful refresh) */
int  xfr_state_decode(const uint8_t *in, size_t len, xfr_state_t *s);

/* CRC-32C (Castagnoli, reflected 0x82F63B78; the algorithm of the store's set_crc()), initial value 0 */
uint32_t xfr_crc32c(uint32_t crc, const void *p, size_t n);
/* the tag of a view: CRC-32C of its name in lower case (view names compare case-insensitively) */
uint32_t xfr_view_tag(const char *view);
/* the key of the copy: "<tag><k>.<zone>" (tag 8 lowercase hex digits, k 'c' for a configuration secondary, a catalog zone or a member, 'd' for a database secondary,
 * zone the canonical name in lower case without the trailing dot; the root zone: "<tag><k>").  The length, or -1: the name is longer than XFR_KEY_ZONE_MAX (or not a name) */
int  xfr_key_make(const char *view, int kind, const char *zone, char *out, size_t cap);
/* the parts of a key: 0, or -1 (not a key).  zone gets the zone with its trailing dot ("." for the root) */
int  xfr_key_parse(const char *key, size_t len, uint32_t *tag, char *kc, char *zone, size_t cap);
/* the identity (see the top) */
uint64_t xfr_identity(int kind, const char *zone, const char *view, const char *unique_id, int64_t domain_id);
/* one element of the primaries digest; crc starts at 0 */
uint32_t xfr_primaries_add(uint32_t crc, const char *addr, int port, const char *key);

/* the times of a state as a restore sets them (2.3, in memory only): last_ok and expire_at as the entry keeps them (expire_at 0 = last_ok + SOA EXPIRE); a time more than
 * XFR_CLOCK_SLACK seconds ahead of now is now, a deadline after now + soa_expire is now + soa_expire (RFC 7314 §4, the bound of xfr_expire_deadline()); clamped says that one was */
typedef struct { time_t last_ok, expire_at; bool clamped; } xfr_times_t;
void xfr_state_times(const xfr_state_t *s, uint32_t soa_expire, time_t now, xfr_times_t *out);
/* the other way: the state's last_ok, expire_delta and XFR_SF_EXPIRE_OPT from the entry's last successful refresh and expire_at */
void xfr_state_set_times(xfr_state_t *s, time_t last_ok, time_t expire_at);
/* D7 (revised): the zone's `file` wins against the stored copy only when it is newer than the copy's save time and its serial is greater (RFC 1982) */
bool xfr_file_wins(time_t file_mtime, uint32_t file_serial, uint64_t saved_time, uint32_t stored_serial);
bool xfr_serial_gt(uint32_t a, uint32_t b);      /* RFC 1982 §3.2: a > b */
/* M2: what an up-to-date refresh writes: the state alone when the record holds the copy of this serial (STORED, STORE_F_XFR, the same serial), else the whole image */
enum { XFR_UP_STATE = 0, XFR_UP_PUT = 1 };
int  xfr_uptodate_action(bool have_rec, uint8_t rec_state, uint16_t rec_flags, uint32_t rec_serial, uint32_t serial);
/* a failure write is left out when it would change nothing but the attempt time (the settings id and the kind compared too) and the attempt on disk is younger than retry */
bool xfr_failure_skip(const xfr_state_t *old, const xfr_state_t *upd, time_t now, uint32_t retry);
/* next_check after a restore (4.5, D3): 0 (at the first tick), or after a recent failed attempt last_attempt + retry, never later than the deadline (0: none) */
time_t xfr_restore_next_check(const xfr_state_t *s, uint32_t retry, time_t deadline, time_t now);

#endif /* DNS_XFR_STATE_H */
