/*
 * dns_xfr_state.c - the key, the state and the decisions of the secondaries' copies in the zone store (see dns_xfr_state.h).
 */
#include "dns_xfr_state.h"

#include <string.h>

static void put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

void xfr_state_encode(const xfr_state_t *s, uint8_t out[XFR_STATE_LEN]) {
  memset(out, 0, XFR_STATE_LEN);
  out[0] = XFR_STATE_VERSION;
  out[1] = s->kind;
  out[2] = (uint8_t)(s->flags & XFR_SF_ALL);
  put32(out + 4, s->primaries);
  put32(out + 8, (uint32_t)s->identity);
  put32(out + 12, (uint32_t)(s->identity >> 32));
  put32(out + 16, s->last_ok);
  put32(out + 20, s->expire_delta);
  put32(out + 24, s->last_attempt);
  put32(out + 28, s->rx_settings);
}

int xfr_state_decode(const uint8_t *in, size_t len, xfr_state_t *s) {
  memset(s, 0, sizeof(*s));
  if (!in || len < XFR_STATE_LEN) return -1;
  if (in[0] != XFR_STATE_VERSION || in[1] < XFR_K_CONFIG || in[1] > XFR_K_DB_CONSUMER || (in[2] & ~XFR_SF_ALL) != 0 || in[3] != 0) return -1;
  s->kind = in[1];
  s->flags = in[2];
  s->primaries = get32(in + 4);
  s->identity = (uint64_t)get32(in + 8) | (uint64_t)get32(in + 12) << 32;
  s->last_ok = get32(in + 16);
  s->expire_delta = get32(in + 20);
  s->last_attempt = get32(in + 24);
  s->rx_settings = get32(in + 28);
  if (s->last_ok == 0) return -1;                 /* (a copy is written by a refresh that worked, or by an up-to-date answer: never without one) */
  return 0;
}

uint32_t xfr_crc32c(uint32_t crc, const void *p, size_t n) {
  const uint8_t *b = p;
  crc = ~crc;
  for (size_t i = 0; i < n; i++) {
    crc ^= b[i];
    for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
  }
  return ~crc;
}

static char lc(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

uint32_t xfr_view_tag(const char *view) {
  uint32_t crc = 0;
  for (const char *p = view ? view : ""; *p; p++) {
    const char c = lc(*p);
    crc = xfr_crc32c(crc, &c, 1);
  }
  return crc;
}

/* the canonical zone name without its trailing dot ("" for the root) */
static size_t zone_len(const char *zone) {
  size_t n = zone ? strlen(zone) : 0;
  if (n > 0 && zone[n - 1] == '.' && (n < 2 || zone[n - 2] != '\\')) n--;
  return n;
}

int xfr_key_make(const char *view, int kind, const char *zone, char *out, size_t cap) {
  if (!zone || !out) return -1;
  const size_t zl = zone_len(zone);
  if (zl > XFR_KEY_ZONE_MAX || (zl == 0 && strlen(zone) > 1)) return -1;
  const char kc = (kind == XFR_K_DB_SLAVE || kind == XFR_K_DB_CONSUMER) ? 'd' : 'c';
  static const char hx[] = "0123456789abcdef";
  const uint32_t tag = xfr_view_tag(view);
  const size_t need = 9 + (zl ? 1 + zl : 0);
  if (cap < need + 1) return -1;
  for (int i = 0; i < 8; i++) out[i] = hx[(tag >> (28 - 4 * i)) & 0xF];
  out[8] = kc;
  size_t o = 9;
  if (zl) {
    out[o++] = '.';
    for (size_t i = 0; i < zl; i++) out[o++] = lc(zone[i]);
  }
  out[o] = '\0';
  return (int)o;
}

int xfr_key_parse(const char *key, size_t len, uint32_t *tag, char *kc, char *zone, size_t cap) {
  if (!key || len < 9 || len > XFR_KEY_MAX || cap < 2) return -1;
  uint32_t t = 0;
  for (int i = 0; i < 8; i++) {
    const char c = key[i];
    int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
    if (v < 0) return -1;
    t = t << 4 | (uint32_t)v;
  }
  if (key[8] != 'c' && key[8] != 'd') return -1;
  if (len == 9) {
    if (tag) *tag = t;
    if (kc) *kc = key[8];
    zone[0] = '.';
    zone[1] = '\0';
    return 0;
  }
  if (key[9] != '.' || len == 10 || len - 10 + 2 > cap) return -1;
  for (size_t i = 10; i < len; i++)
    if (key[i] == '\0') return -1;
  memcpy(zone, key + 10, len - 10);
  zone[len - 10] = '.';
  zone[len - 9] = '\0';
  if (tag) *tag = t;
  if (kc) *kc = key[8];
  return 0;
}

static uint64_t fnv(uint64_t h, const void *p, size_t n) {
  const uint8_t *b = p;
  for (size_t i = 0; i < n; i++) {
    h ^= b[i];
    h *= 0x100000001b3ull;
  }
  return h;
}
static uint64_t fnv_lc(uint64_t h, const char *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    const char c = lc(s[i]);
    h = fnv(h, &c, 1);
  }
  const uint8_t z = 0;
  return fnv(h, &z, 1);                           /* (a separator: the fields cannot slide into each other) */
}

uint64_t xfr_identity(int kind, const char *zone, const char *view, const char *unique_id, int64_t domain_id) {
  uint64_t h = 0xcbf29ce484222325ull;
  const uint8_t k = (uint8_t)kind;
  h = fnv(h, &k, 1);
  h = fnv_lc(h, zone ? zone : "", zone_len(zone));
  h = fnv_lc(h, view ? view : "", view ? strlen(view) : 0);
  if (kind == XFR_K_MEMBER) {
    const char *u = unique_id ? unique_id : "";
    h = fnv(h, u, strlen(u));                       /* (the unique-N label is compared as it is written, RFC 9432 §4.1) */
    const uint8_t z = 0;
    h = fnv(h, &z, 1);
  }
  if (kind == XFR_K_DB_SLAVE || kind == XFR_K_DB_CONSUMER) {
    uint8_t d[8];
    for (int i = 0; i < 8; i++) d[i] = (uint8_t)((uint64_t)domain_id >> (8 * i));
    h = fnv(h, d, 8);
  }
  return h;
}

uint32_t xfr_primaries_add(uint32_t crc, const char *addr, int port, const char *key) {
  const char *a = addr ? addr : "";
  crc = xfr_crc32c(crc, a, strlen(a) + 1);
  uint8_t p[4];
  put32(p, (uint32_t)port);
  crc = xfr_crc32c(crc, p, 4);
  for (const char *k = key ? key : ""; *k; k++) {
    const char c = lc(*k);
    crc = xfr_crc32c(crc, &c, 1);
  }
  const uint8_t z = 0;
  return xfr_crc32c(crc, &z, 1);
}

void xfr_state_times(const xfr_state_t *s, uint32_t soa_expire, time_t now, xfr_times_t *out) {
  out->clamped = false;
  time_t last = (time_t)s->last_ok;
  if (last > now + XFR_CLOCK_SLACK) {             /* the clock went back since the copy was written (or the copy is from the future): the zone was fresh now at the latest */
    last = now;
    out->clamped = true;
  }
  out->last_ok = last;
  out->expire_at = 0;
  if (s->flags & XFR_SF_EXPIRE_OPT) {
    time_t at = last + (time_t)s->expire_delta;
    if (at <= 0) at = 1;                          /* (0 means "last_ok + SOA EXPIRE" to the entry) */
    if (soa_expire > 0 && at > now + (time_t)soa_expire) {
      at = now + (time_t)soa_expire;
      out->clamped = true;
    }
    out->expire_at = at;
  }
}

void xfr_state_set_times(xfr_state_t *s, time_t last_ok, time_t expire_at) {
  s->last_ok = last_ok <= 0 ? 0 : last_ok > (time_t)UINT32_MAX ? UINT32_MAX : (uint32_t)last_ok;
  if (expire_at == 0) {
    s->flags = (uint8_t)(s->flags & ~XFR_SF_EXPIRE_OPT);
    s->expire_delta = 0;
    return;
  }
  s->flags |= XFR_SF_EXPIRE_OPT;
  const time_t d = expire_at - (time_t)s->last_ok;
  s->expire_delta = d <= 0 ? 0 : d > (time_t)UINT32_MAX ? UINT32_MAX : (uint32_t)d;
}

bool xfr_serial_gt(uint32_t a, uint32_t b) { return a != b && (uint32_t)(a - b) < 0x80000000u; }

bool xfr_file_wins(time_t file_mtime, uint32_t file_serial, uint64_t saved_time, uint32_t stored_serial) {
  return file_mtime > 0 && (uint64_t)file_mtime > saved_time && xfr_serial_gt(file_serial, stored_serial);
}

int xfr_uptodate_action(bool have_rec, uint8_t rec_state, uint16_t rec_flags, uint32_t rec_serial, uint32_t serial) {
  /* (the store's constants: STORE_STATE_STORED 2, STORE_F_XFR 0x0100; dns_store.h is not included here so the harness links this file alone) */
  return have_rec && rec_state == 2 && (rec_flags & 0x0100u) && rec_serial == serial ? XFR_UP_STATE : XFR_UP_PUT;
}

bool xfr_failure_skip(const xfr_state_t *old, const xfr_state_t *upd, time_t now, uint32_t retry) {
  if (old->kind != upd->kind || old->flags != upd->flags || old->primaries != upd->primaries || old->identity != upd->identity || old->last_ok != upd->last_ok ||
      old->expire_delta != upd->expire_delta || old->rx_settings != upd->rx_settings)
    return false;
  return old->last_attempt != 0 && now >= (time_t)old->last_attempt && now - (time_t)old->last_attempt < (time_t)retry;
}

int xfr_rx_key_split(const void *key, size_t klen, const char **text, size_t *tlen) {
  static const char mark[] = XFR_RX_MARK;
  const size_t ml = sizeof(mark) - 1;
  const uint8_t *k = key;
  if (text) *text = NULL;
  if (tlen) *tlen = 0;
  /* (a settings key of a database zone with no profile name has no profile text either, "" NUL "" NUL zone text: a key whose first byte is NUL and whose next ones are the
   * mark and a NUL can only be one of these) */
  if (!k || klen < 2 + ml || k[0] != 0 || memcmp(k + 1, mark, ml) != 0 || k[1 + ml] != 0) return 0;
  const size_t n = klen - 2 - ml;
  if (n == 0 || n > XFR_RX_TEXT_MAX) return -1;
  if (text) *text = (const char *)k + 2 + ml;
  if (tlen) *tlen = n;
  return 1;
}

time_t xfr_restore_next_check(const xfr_state_t *s, uint32_t retry, time_t deadline, time_t now) {
  if (!(s->flags & XFR_SF_FAILED) || s->last_attempt == 0) return 0;
  time_t at = (time_t)s->last_attempt + (time_t)retry;
  if (at <= now) return 0;
  if (deadline > 0 && at > deadline) at = deadline;
  return at <= now ? 0 : at;
}
