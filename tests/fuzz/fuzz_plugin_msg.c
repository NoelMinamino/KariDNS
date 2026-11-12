/*
 * fuzz_plugin_msg.c - the records of the plugin channel between the manager and the Backend (dns_plugin_msg.c, 0.6.2).
 *
 * Both sides treat the other as hostile: the Backend parses what the manager sends (UP with descriptors, DOWN) against what it expects for
 * each slot, and the manager (root) parses what the Backend sends (START, STOP, KILL).  The first bytes of the input choose the recvmsg
 * flags, the number of descriptors, a few slots with expectations, and the record length; the rest is the record.  Every record a check
 * accepts must satisfy the rules the receivers rely on (slot in range and in use, the slot's generation, the start number rules, the
 * descriptor count of its type, NUL-terminated printable texts of the right length, a 16 hex digit fingerprint).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../../dns_plugin_msg.h"

static void must(int c) {
    if (!c) abort();
}

static size_t text_len(const char *f, size_t cap) {
    size_t n = 0;
    while (n < cap && f[n]) {
        must((unsigned char)f[n] >= 0x20 && (unsigned char)f[n] <= 0x7e);
        n++;
    }
    must(n < cap);
    return n;
}

static int all_zero(const char *f, size_t cap) {
    for (size_t i = 0; i < cap; i++)
        if (f[i]) return 0;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    int flags = (data[0] & 1 ? MSG_TRUNC : 0) | (data[0] & 2 ? MSG_CTRUNC : 0);
    int nfds = data[1] % 6;
    static plug_expect_t ex[PLUG_SLOTS];
    memset(ex, 0, sizeof(ex));
    /* three slots in use, chosen by the input (a record that names another slot must be refused) */
    for (int i = 0; i < 3; i++) {
        uint32_t slot = (uint32_t)data[2 + i] * 2u % PLUG_SLOTS;
        ex[slot].gen = (uint32_t)(data[5] & 7) + (uint32_t)i;   /* gen 0 marks a slot not in use */
        ex[slot].seq = (uint32_t)(data[6] & 3);
    }
    data += 8;
    size -= 8;
    /* records shorter or longer than one are tried as they are; when the input is longer, a full record from its start */
    size_t len = size > sizeof(plug_msg_t) ? sizeof(plug_msg_t) + (size & 1) : size;
    unsigned char buf[sizeof(plug_msg_t) + 1];
    memcpy(buf, data, len);

    plug_msg_t m;
    plug_err_t e = plug_check_from_manager(buf, len, flags, nfds, ex, PLUG_SLOTS, &m);
    if (e == PLUG_OK) {
        must(len == sizeof(plug_msg_t) && flags == 0 && m.magic == PLUG_MAGIC);
        must(m.slot < PLUG_SLOTS && ex[m.slot].gen != 0 && m.gen == ex[m.slot].gen);
        must(all_zero(m.zone, sizeof(m.zone)) && all_zero(m.view, sizeof(m.view)) && all_zero(m.fingerprint, sizeof(m.fingerprint)));
        if (m.type == PLUG_MSG_UP) {
            must(nfds == PLUG_UP_NFDS && m.seq > ex[m.slot].seq && m.pid > 0 && m.flags == 0 && m.status == 0);
        } else {
            must(m.type == PLUG_MSG_DOWN && nfds == 0 && m.seq == ex[m.slot].seq && m.pid == 0);
            must((m.flags & ~PLUG_DOWN_REFUSED) == 0 && (!(m.flags & PLUG_DOWN_REFUSED) || m.seq == 0));
        }
    }
    /* the slot table bounds the check: with fewer expectations a slot above them is refused */
    if (len == sizeof(plug_msg_t)) {
        plug_msg_t raw;
        memcpy(&raw, buf, sizeof(raw));
        if (raw.slot >= 16 && plug_check_from_manager(buf, len, flags, nfds, ex, 16, &m) == PLUG_OK) abort();
    }

    e = plug_check_from_backend(buf, len, flags, nfds, &m);
    if (e == PLUG_OK) {
        must(len == sizeof(plug_msg_t) && flags == 0 && nfds == 0 && m.magic == PLUG_MAGIC);
        must(m.slot < PLUG_SLOTS && m.gen != 0 && m.flags == 0 && m.pid == 0 && m.status == 0);
        if (m.type == PLUG_MSG_START) {
            must(m.seq == 0);
            size_t zl = text_len(m.zone, sizeof(m.zone));
            must(zl >= 1 && zl < PLUG_ZONE_MAX);
            (void)text_len(m.view, sizeof(m.view));
            for (int i = 0; i < 16; i++) {
                char c = m.fingerprint[i];
                must((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
            }
            must(all_zero(m.fingerprint + 16, sizeof(m.fingerprint) - 16));
        } else {
            must(m.type == PLUG_MSG_STOP || m.type == PLUG_MSG_KILL);
            must(m.type == PLUG_MSG_KILL ? m.seq != 0 : m.seq == 0);
            must(all_zero(m.zone, sizeof(m.zone)) && all_zero(m.view, sizeof(m.view)) && all_zero(m.fingerprint, sizeof(m.fingerprint)));
        }
    }
    (void)plug_err_text(e);
    return 0;
}
