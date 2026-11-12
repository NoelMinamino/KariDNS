/*
 * dns_plugin_msg.c - the checks of the manager <-> Backend plugin messages (see dns_plugin_msg.h).  No state and no I/O.
 */
#include "dns_plugin_msg.h"

#include <string.h>
#include <sys/socket.h>

_Static_assert(sizeof(plug_msg_t) == 32 + PLUG_FP_MAX + PLUG_ZONE_MAX + PLUG_VIEW_MAX, "plug_msg_t has no padding");

const char *plug_err_text(plug_err_t e) {
  switch (e) {
  case PLUG_OK: return "ok";
  case PLUG_E_SIZE: return "not one record";
  case PLUG_E_TRUNC: return "cut (data or descriptors)";
  case PLUG_E_MAGIC: return "bad magic";
  case PLUG_E_TYPE: return "unexpected type";
  case PLUG_E_SLOT: return "slot out of range or not in use";
  case PLUG_E_GEN: return "not the slot's generation";
  case PLUG_E_SEQ: return "not the expected start number";
  case PLUG_E_FDS: return "wrong number of descriptors";
  case PLUG_E_TEXT: return "malformed zone, view or fingerprint";
  case PLUG_E_FIELD: return "a field that must be 0 is not";
  }
  return "?";
}

void plug_msg_init(plug_msg_t *m, uint32_t type, uint32_t slot, uint32_t gen, uint32_t seq) {
  memset(m, 0, sizeof(*m));
  m->magic = PLUG_MAGIC;
  m->type = type;
  m->slot = slot;
  m->gen = gen;
  m->seq = seq;
}

/* A text field: NUL-terminated inside the field, between min and max bytes before the NUL, printable ASCII (the receiver logs it) */
static bool text_ok(const char *f, size_t cap, size_t min) {
  size_t n = 0;
  while (n < cap && f[n]) {
    if ((unsigned char)f[n] < 0x20 || (unsigned char)f[n] > 0x7e) return false;
    n++;
  }
  return n < cap && n >= min;
}

static bool all_zero(const char *f, size_t cap) {
  for (size_t i = 0; i < cap; i++)
    if (f[i]) return false;
  return true;
}

/* The checks every record gets: one whole record, nothing cut, the magic.  The copy into *m is aligned (buf may not be). */
static plug_err_t frame_check(const void *buf, size_t len, int msg_flags, plug_msg_t *m) {
  if (!buf || len != sizeof(plug_msg_t)) return PLUG_E_SIZE;
  if (msg_flags & (MSG_TRUNC | MSG_CTRUNC)) return PLUG_E_TRUNC;
  memcpy(m, buf, sizeof(*m));
  if (m->magic != PLUG_MAGIC) return PLUG_E_MAGIC;
  return PLUG_OK;
}

plug_err_t plug_check_from_manager(const void *buf, size_t len, int msg_flags, int nfds, const plug_expect_t *expect, size_t nexpect,
                                   plug_msg_t *out) {
  plug_msg_t m;
  plug_err_t e = frame_check(buf, len, msg_flags, &m);
  if (e != PLUG_OK) return e;
  if (m.type != PLUG_MSG_UP && m.type != PLUG_MSG_DOWN) return PLUG_E_TYPE;
  if (m.slot >= PLUG_SLOTS || m.slot >= nexpect || !expect || expect[m.slot].gen == 0) return PLUG_E_SLOT;
  if (m.gen != expect[m.slot].gen) return PLUG_E_GEN;
  /* nothing in the text fields: the Backend has the zone's names itself */
  if (!all_zero(m.zone, sizeof(m.zone)) || !all_zero(m.view, sizeof(m.view)) || !all_zero(m.fingerprint, sizeof(m.fingerprint)))
    return PLUG_E_TEXT;
  if (m.type == PLUG_MSG_UP) {
    if (nfds != PLUG_UP_NFDS) return PLUG_E_FDS;
    if (m.seq <= expect[m.slot].seq) return PLUG_E_SEQ;
    if (m.pid <= 0 || m.flags != 0 || m.status != 0) return PLUG_E_FIELD;
  } else {
    if (nfds != 0) return PLUG_E_FDS;
    if (m.seq != expect[m.slot].seq) return PLUG_E_SEQ;
    if ((m.flags & ~PLUG_DOWN_REFUSED) != 0 || m.pid != 0) return PLUG_E_FIELD;
    if ((m.flags & PLUG_DOWN_REFUSED) && m.seq != 0) return PLUG_E_SEQ;
  }
  *out = m;
  return PLUG_OK;
}

plug_err_t plug_check_from_backend(const void *buf, size_t len, int msg_flags, int nfds, plug_msg_t *out) {
  plug_msg_t m;
  plug_err_t e = frame_check(buf, len, msg_flags, &m);
  if (e != PLUG_OK) return e;
  if (m.type != PLUG_MSG_START && m.type != PLUG_MSG_STOP && m.type != PLUG_MSG_KILL) return PLUG_E_TYPE;
  if (nfds != 0) return PLUG_E_FDS;
  if (m.slot >= PLUG_SLOTS) return PLUG_E_SLOT;
  if (m.gen == 0) return PLUG_E_GEN;
  if (m.flags != 0 || m.pid != 0 || m.status != 0) return PLUG_E_FIELD;
  if (m.type == PLUG_MSG_START) {
    if (m.seq != 0) return PLUG_E_SEQ;
    if (!text_ok(m.zone, sizeof(m.zone), 1) || !text_ok(m.view, sizeof(m.view), 0)) return PLUG_E_TEXT;
    for (int i = 0; i < 16; i++) {
      char c = m.fingerprint[i];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return PLUG_E_TEXT;
    }
    if (!all_zero(m.fingerprint + 16, sizeof(m.fingerprint) - 16)) return PLUG_E_TEXT;
  } else {
    if (!all_zero(m.zone, sizeof(m.zone)) || !all_zero(m.view, sizeof(m.view)) || !all_zero(m.fingerprint, sizeof(m.fingerprint)))
      return PLUG_E_TEXT;
    if (m.type == PLUG_MSG_KILL ? m.seq == 0 : m.seq != 0) return PLUG_E_SEQ;
  }
  *out = m;
  return PLUG_OK;
}
