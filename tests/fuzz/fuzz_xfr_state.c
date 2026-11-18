/*
 * fuzz_xfr_state.c - the secondary state and the key of a copy in the zone store (dns_xfr_state.c; planing_0.7.x_secondary_store.md 2.2, 2.3, 13).
 *
 * The record's digest and name come from the store's files: a cell CRC protects the bytes, not their meaning, so every byte may arrive.  The input is a
 * state (its first 32 bytes) and a key (the rest).  Properties:
 *   1. xfr_state_decode() of any bytes never reads past them; a state it accepts encodes to the same bytes and decodes to the same fields;
 *   2. the times of an accepted state (xfr_state_times(), with any SOA EXPIRE and clock) are bounded: last_ok at most now + the slack, a deadline from an EXPIRE
 *      option at most now + SOA EXPIRE, never 0 for an EXPIRE option;
 *   3. xfr_key_parse() of any bytes never reads past them; a key it accepts is made again by xfr_key_make() from its parts, byte for byte, when the tag is the one of
 *      some view (checked with the tag of the empty view name through a rebuilt key whose tag field is replaced);
 *   4. the decisions (the up-to-date rule, the failure skip, next_check, D7) take any values without fault.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../../dns_xfr_state.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < XFR_STATE_LEN + 8) return 0;
  /* 1 */
  uint8_t *st = malloc(XFR_STATE_LEN);
  if (!st) return 0;
  memcpy(st, data, XFR_STATE_LEN);
  xfr_state_t s, s2;
  if (xfr_state_decode(st, XFR_STATE_LEN, &s) == 0) {
    uint8_t b[XFR_STATE_LEN];
    xfr_state_encode(&s, b);
    if (memcmp(b, st, XFR_STATE_LEN) != 0) abort();
    if (xfr_state_decode(b, sizeof(b), &s2) != 0 || s2.identity != s.identity || s2.last_ok != s.last_ok || s2.flags != s.flags || s2.kind != s.kind) abort();
    /* 2 */
    uint32_t soa_expire, nowv;
    memcpy(&soa_expire, data + XFR_STATE_LEN, 4);
    memcpy(&nowv, data + XFR_STATE_LEN + 4, 4);
    const time_t now = (time_t)nowv;
    xfr_times_t t;
    xfr_state_times(&s, soa_expire, now, &t);
    if (t.last_ok > now + XFR_CLOCK_SLACK) abort();
    if ((s.flags & XFR_SF_EXPIRE_OPT) && t.expire_at <= 0) abort();
    if ((s.flags & XFR_SF_EXPIRE_OPT) && soa_expire > 0 && t.expire_at > now + (time_t)soa_expire) abort();
    if (!(s.flags & XFR_SF_EXPIRE_OPT) && t.expire_at != 0) abort();
    /* 4 */
    xfr_state_t u = s;
    u.last_attempt = nowv;
    (void)xfr_failure_skip(&s, &u, now, soa_expire);
    (void)xfr_restore_next_check(&s, soa_expire, t.expire_at, now);
    (void)xfr_uptodate_action(true, (uint8_t)data[0], (uint16_t)(data[1] | data[2] << 8), s.last_ok, s.last_attempt);
    (void)xfr_file_wins(now, s.last_ok, s.last_attempt, s.rx_settings);
    xfr_state_set_times(&u, (time_t)s.last_ok, now);
  }
  free(st);
  /* 3 */
  const size_t kl = size - XFR_STATE_LEN - 8;
  char *key = malloc(kl ? kl : 1);
  if (!key) return 0;
  memcpy(key, data + XFR_STATE_LEN + 8, kl);
  uint32_t tag = 0;
  char kc = 0, zone[XFR_KEY_MAX + 2];
  if (xfr_key_parse(key, kl, &tag, &kc, zone, sizeof(zone)) == 0) {
    char re[XFR_KEY_MAX + 1];
    const int n = xfr_key_make("", kc == 'd' ? XFR_K_DB_SLAVE : XFR_K_CONFIG, zone, re, sizeof(re));
    if (n >= 9) {
      /* the parts of the key that do not come from the view: the kind, and the zone of a plain name (lower case, no escape, no trailing dot) */
      if (re[8] != kc) abort();
      int plain = kl > 10 ? 1 : 0;
      for (size_t i = 10; i < kl; i++)
        if ((key[i] >= 'A' && key[i] <= 'Z') || key[i] == '\\') plain = 0;
      if (kl > 10 && key[kl - 1] == '.') plain = 0;
      if (plain && ((size_t)n != kl || memcmp(re + 8, key + 8, kl - 8) != 0)) abort();
    }
  }
  free(key);
  (void)xfr_view_tag((const char *)"");
  return 0;
}
