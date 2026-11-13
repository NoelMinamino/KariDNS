/*
 * dns_log_state.c - the KLS1 record of the debug level and the logging runtime (see dns_log_state.h).  No state, no I/O, no allocation.
 */
#include "dns_log_state.h"

#include <string.h>

#define KLS_FACILITIES 24              /* LOG_KERN (0) .. LOG_LOCAL7 (23 << 3): <syslog.h> LOG_NFACILITIES on FreeBSD */

static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

/* A channel as a receiver accepts it (the encoder checks the same, so that it never sends what the other side refuses) */
static const char *channel_check(const kls_channel_t *c) {
  if (c->dest > 3) return "unknown destination";
  if (c->time_fmt > 3) return "unknown print-time";
  if (c->flags & ~(KLS_CF_CATEGORY | KLS_CF_SEVERITY | KLS_CF_DEBUG_ONLY)) return "unknown channel flags";
  if (c->level < LOG_LVL_CRITICAL || c->level > 99) return "severity out of range";
  if (c->facility % 8 != 0 || c->facility / 8 >= KLS_FACILITIES) return "not a syslog facility";
  if (c->dest == 0) {
    if (c->path_len == 0 || c->path_len > KLS_PATH_MAX || !c->path) return "a file channel without a path, or one too long";
    for (uint16_t i = 0; i < c->path_len; i++) {
      unsigned char b = (unsigned char)c->path[i];
      if (b < 0x20 || b == 0x7f) return "a control character in a path";
    }
  } else if (c->path_len != 0) {
    return "a path for a channel that is not a file";
  }
  return NULL;
}

size_t kls_encode(const kls_state_t *s, uint8_t *buf, size_t cap) {
  if (!s || !buf || s->debug_level < 0 || s->debug_level > 99) return 0;
  if (!s->has_spec && s->nch != 0) return 0;
  if (s->nch > KLS_CHANNELS_MAX) return 0;
  size_t o = 0;
  if (cap < KLS_HEADER_LEN) return 0;
  buf[0] = (uint8_t)(KLS_MAGIC >> 24);
  buf[1] = (uint8_t)(KLS_MAGIC >> 16);
  buf[2] = (uint8_t)(KLS_MAGIC >> 8);
  buf[3] = (uint8_t)KLS_MAGIC;
  buf[4] = KLS_VERSION;
  buf[5] = s->has_spec ? KLS_F_SPEC : 0;
  buf[6] = (uint8_t)s->debug_level;
  buf[7] = 0;
  put16(buf + 8, s->nch);
  o = KLS_HEADER_LEN;
  if (!s->has_spec) return o;
  for (uint16_t i = 0; i < s->nch; i++) {
    const kls_channel_t *c = &s->ch[i];
    if (channel_check(c)) return 0;
    if (cap - o < 8u + c->path_len) return 0;
    buf[o] = c->dest;
    buf[o + 1] = c->time_fmt;
    buf[o + 2] = c->flags;
    buf[o + 3] = (uint8_t)c->level;
    put16(buf + o + 4, c->facility);
    put16(buf + o + 6, c->path_len);
    if (c->path_len) memcpy(buf + o + 8, c->path, c->path_len);
    o += 8u + c->path_len;
  }
  for (int cat = 0; cat < LOGC_COUNT; cat++) {
    uint8_t n = s->nroute[cat];
    if (n > KLS_ROUTE_MAX || cap - o < 1u + 2u * n) return 0;
    buf[o++] = n;
    for (uint8_t k = 0; k < n; k++) {
      if (s->route[cat][k] >= s->nch) return 0;
      put16(buf + o, s->route[cat][k]);
      o += 2;
    }
  }
  return o;
}

const char *kls_parse(const uint8_t *buf, size_t len, kls_state_t *out) {
  if (!buf || !out) return "no record";
  if (len < KLS_HEADER_LEN || len > KLS_MAX) return "not the length of a record";
  if (((uint32_t)buf[0] << 24 | (uint32_t)buf[1] << 16 | (uint32_t)buf[2] << 8 | buf[3]) != KLS_MAGIC) return "bad magic";
  if (buf[4] != KLS_VERSION) return "unknown version";
  if (buf[5] & ~KLS_F_SPEC) return "unknown flags";
  if (buf[6] > 99) return "debug level out of range";
  if (buf[7] != 0) return "a reserved byte is not 0";
  out->debug_level = buf[6];
  out->has_spec = (buf[5] & KLS_F_SPEC) != 0;
  out->nch = get16(buf + 8);
  memset(out->nroute, 0, sizeof(out->nroute));
  size_t o = KLS_HEADER_LEN;
  if (!out->has_spec) {
    if (out->nch != 0) return "channels without the flag";
    return o == len ? NULL : "bytes after the record";
  }
  if (out->nch > KLS_CHANNELS_MAX) return "too many channels";
  for (uint16_t i = 0; i < out->nch; i++) {
    if (len - o < 8) return "a channel is cut";
    kls_channel_t *c = &out->ch[i];
    c->dest = buf[o];
    c->time_fmt = buf[o + 1];
    c->flags = buf[o + 2];
    c->level = (int8_t)buf[o + 3];
    c->facility = get16(buf + o + 4);
    c->path_len = get16(buf + o + 6);
    o += 8;
    if (len - o < c->path_len) return "a path is cut";
    c->path = c->path_len ? (const char *)buf + o : NULL;
    o += c->path_len;
    const char *why = channel_check(c);
    if (why) return why;
  }
  for (int cat = 0; cat < LOGC_COUNT; cat++) {
    if (len - o < 1) return "the table is cut";
    uint8_t n = buf[o++];
    if (n > KLS_ROUTE_MAX) return "too many channels for a category";
    if (len - o < 2u * n) return "the table is cut";
    for (uint8_t k = 0; k < n; k++) {
      uint16_t idx = get16(buf + o);
      o += 2;
      if (idx >= out->nch) return "a category names a channel that is not in the record";
      out->route[cat][k] = idx;
    }
    out->nroute[cat] = n;
  }
  return o == len ? NULL : "bytes after the record";
}
