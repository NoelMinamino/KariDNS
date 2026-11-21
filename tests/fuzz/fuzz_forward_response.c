/*
 * fuzz_forward_response.c - the message side of DNS Cookies for the forwarders of `type forward` zones (dns_cookie_client.c, 0.7): a
 * forwarder's response, and the client's query, are untrusted network input.
 *
 *   byte 0   selector: bits 0-1 the server cookie length of this server's option (0 8 16 32), bit 2 the client cookie checked is the
 *            one in the option (else another one), bit 3 the reply carries a client cookie of its own
 *   rest     the message
 *
 * ckc_msg_scan() / ckc_msg_check() must never read outside the message and must give a consistent result; ckc_msg_rewrite() must never
 * write outside the buffer it is given, and what it makes must be a message whose OPT RR holds exactly the cookie put in (SET, KEEP),
 * or no OPT RR (DROP) - the forwarder's cookie must never survive into the reply to the client.  The OPT RDATA also goes through
 * ckc_option_parse() alone.
 */
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../db/xfr_mocks.h"
#include "../../dns_cookie_client.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static void trap_if(int cond) {
    if (cond) __builtin_trap();
}

static uint8_t g_out[65535 + 11 + CKC_OPTION_MAX + 64];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 65535 + 1) return 0;
    static const uint8_t cc[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, other[8] = { 8, 7, 6, 5, 4, 3, 2, 1 }, ccl[8] = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8 };
    static const size_t sclens[4] = { 0, 8, 16, 32 };
    uint8_t sc[32];
    memset(sc, 0x5A, sizeof(sc));
    const size_t sclen = sclens[data[0] & 3];
    const uint8_t *want = (data[0] & 4) ? cc : other;
    const uint8_t *pkt = data + 1;
    const size_t len = size - 1;

    ckc_msg_t m;
    bool walks = ckc_msg_scan(pkt, len, &m);
    if (walks) {
        trap_if(m.rr_end > len || m.rr_end < 12);
        if (m.opt_count) trap_if(m.opt_off >= m.rd_off || m.rd_off + m.rdlen != m.opt_end || m.opt_end > m.rr_end);
    }
    ckc_seen_t s;
    int r = ckc_msg_check(pkt, len, want, &s);
    trap_if(r != 0 && r != -1);
    trap_if(s.kind > CKC_SERVER);
    trap_if(s.kind == CKC_SERVER ? (s.sc_len < 8 || s.sc_len > 32) : s.sc_len != 0);
    trap_if(r == -1 && (s.kind != CKC_NONE || s.badcookie));
    trap_if(s.badcookie && !s.opt);
    trap_if(!walks && (s.kind != CKC_NONE || s.opt));
    if (walks && m.opt_count == 1) {
        ckc_seen_t s2;
        memset(&s2, 0, sizeof(s2));
        bool ok = ckc_option_parse(pkt + m.rd_off, m.rdlen, want, &s2);
        trap_if(ok != (r == 0));
        trap_if(ok && (s2.kind != s.kind || s2.sc_len != s.sc_len || memcmp(s2.sc, s.sc, s.sc_len) != 0));
    }

    /* the query: this server's cookie put in (an OPT RR added when there is none) */
    uint8_t opt[CKC_OPTION_MAX];
    size_t olen = ckc_option_put(opt, sizeof(opt), cc, sc, sclen);
    trap_if(olen != 12 + sclen);
    for (size_t capk = 0; capk < 2; capk++) {
        size_t cap = capk ? sizeof(g_out) : (len + 20 < sizeof(g_out) ? len + 20 : sizeof(g_out));
        bool added = true;
        size_t n = ckc_msg_rewrite(pkt, len, g_out, cap, opt, olen, CKC_RW_SET, &added);
        trap_if(n > cap);
        if (n == 0) {
            trap_if(added);
            continue;
        }
        trap_if(!walks);
        ckc_msg_t o;
        trap_if(!ckc_msg_scan(g_out, n, &o) || o.opt_count != 1 || o.has_sig);
        ckc_seen_t so;
        trap_if(ckc_msg_check(g_out, n, cc, &so) != 0 || so.kind != (sclen ? CKC_SERVER : CKC_CLIENT) || so.sc_len != sclen);
        trap_if(ckc_msg_check(g_out, n, other, &so) != -1);          /* exactly one COOKIE: ours */
        trap_if(added != (m.opt_count == 0));
        if (added) {
            trap_if(n != len + 11 + olen);
            trap_if(((g_out[10] << 8) | g_out[11]) != ((pkt[10] << 8) | pkt[11]) + 1);
        }
        trap_if(memcmp(g_out + 2, pkt + 2, 8) != 0);                 /* flags and the first three counts stay */
    }

    /* the reply to the client: the forwarder's cookie out, the client's in (KEEP), or the OPT RR gone (DROP) */
    uint8_t copt[CKC_OPTION_MAX];
    size_t colen = (data[0] & 8) ? ckc_option_put(copt, sizeof(copt), ccl, sc, 16) : 0;
    size_t n = ckc_msg_rewrite(pkt, len, g_out, sizeof(g_out), copt, colen, CKC_RW_KEEP, NULL);
    if (n) {
        ckc_msg_t o;
        trap_if(!ckc_msg_scan(g_out, n, &o) || o.opt_count != m.opt_count);
        ckc_seen_t so;
        if (m.opt_count == 0) {
            trap_if(n != len || memcmp(g_out, pkt, len) != 0);
        } else {
            trap_if(ckc_msg_check(g_out, n, cc, &so) == 0 && so.kind != CKC_NONE);           /* no cookie for cc survives */
            trap_if(ckc_msg_check(g_out, n, other, &so) == 0 && so.kind != CKC_NONE);
            if (colen) trap_if(ckc_msg_check(g_out, n, ccl, &so) != 0 || so.kind != CKC_SERVER);
        }
    }
    n = ckc_msg_rewrite(pkt, len, g_out, sizeof(g_out), NULL, 0, CKC_RW_DROP, NULL);
    if (n) {
        ckc_msg_t o;
        trap_if(!ckc_msg_scan(g_out, n, &o) || o.opt_count != 0 || n > len);
    }
    return 0;
}
