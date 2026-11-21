/*
 * fuzz_alias_response.c - the response of an ALIAS resolver (dns_alias.c, milestone B9a).  The bytes are untrusted network input.
 *
 *   byte 0   selector: bit0 QTYPE AAAA (else A), bits 1-2 the target name (t.target.test. / a.b.c.d.example. / the root / a 63-octet label),
 *            bit 3 the query carried the client cookie 01 02 .. 08 (RFC 7873), bits 4-5 the server cookie length of the query built (0 8 16 32)
 *   byte 1-2 the query ID the answer must carry
 *   rest     the message
 *
 * alias_parse_response() must never read outside the message and must return a consistent result: an accepted answer
 * (rc 0) has at most ALIAS_MAX_RR addresses of the right length and a TTL within ALIAS_MAX_TTL; every other result is
 * rc 1 (an RCODE), -1 or -2 with no addresses.  The same bytes also go through alias_wire_lower() as an ALIAS RDATA and,
 * the other way round, the query alias_build_query() makes for the name must be a well formed message.
 */
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../db/xfr_mocks.h"
#include "../../dns_alias.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

static void trap_if(int cond) {
    if (cond) __builtin_trap();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    static const uint8_t n0[] = { 1, 't', 6, 't', 'a', 'r', 'g', 'e', 't', 4, 't', 'e', 's', 't', 0 };
    static const uint8_t n1[] = { 1, 'a', 1, 'b', 1, 'c', 1, 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 };
    static const uint8_t n2[] = { 0 };
    static uint8_t n3[66];
    if (n3[0] == 0) {
        n3[0] = 63;
        memset(n3 + 1, 'x', 63);
        n3[64] = 0;
    }
    const uint8_t *names[4] = { n0, n1, n2, n3 };
    const size_t lens[4] = { sizeof(n0), sizeof(n1), sizeof(n2), 65 };
    int which = (data[0] >> 1) & 3;
    uint16_t qtype = (data[0] & 1) ? 28 : 1;
    uint16_t id = (uint16_t)((data[1] << 8) | data[2]);
    /* bit 3: the query carried the client cookie 01..08 (0.7, RFC 7873); bits 4-5: the server cookie length of the query built below */
    static const uint8_t cc[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    const uint8_t *ccp = (data[0] & 8) ? cc : NULL;
    static const size_t sclens[4] = { 0, 8, 16, 32 };
    size_t sclen = sclens[(data[0] >> 4) & 3];

    alias_parsed_t out;
    alias_parse_response(data + 3, size - 3, id, names[which], lens[which], qtype, ccp, &out);
    trap_if(out.rc != 0 && out.rc != 1 && out.rc != -1 && out.rc != -2);
    if (out.rc == 0) {
        trap_if(out.n > ALIAS_MAX_RR);
        trap_if(out.rdlen != (qtype == 1 ? 4 : 16));
        trap_if(out.ttl > ALIAS_MAX_TTL);
        trap_if(out.truncated);
    } else {
        trap_if(out.n != 0);
    }
    trap_if(out.badcookie && out.rc != 1);
    trap_if(!ccp && (out.cookie != ALIAS_CK_NONE || out.sc_len != 0));
    trap_if(out.cookie > ALIAS_CK_SERVER);
    trap_if(out.cookie == ALIAS_CK_SERVER ? (out.sc_len < 8 || out.sc_len > 32) : out.sc_len != 0);
    trap_if(out.rc == -2 && (out.cookie != ALIAS_CK_NONE || out.badcookie));      /* a discarded response teaches nothing */

    uint8_t w[260];
    size_t wl = 0;
    if (alias_wire_lower(data + 3, size - 3, w, &wl)) {
        trap_if(wl != size - 3 || wl == 0 || wl > 255);
        for (size_t i = 0; i < wl; i++) trap_if(w[i] >= 'A' && w[i] <= 'Z');       /* length octets are below 64: only letters could be folded wrongly */
    }

    uint8_t q[600];
    uint8_t sc[32];
    memset(sc, 0xA5, sizeof(sc));
    size_t ql = alias_build_query(q, sizeof(q), id, names[which], lens[which], qtype, ccp, sc, ccp ? sclen : 0);
    trap_if(ql != 12 + lens[which] + 4 + 11 + (ccp ? 4 + 8 + sclen : 0));
    alias_parsed_t self;
    alias_parse_response(q, ql, id, names[which], lens[which], qtype, ccp, &self);  /* a query is not a response: QR is 0 */
    trap_if(self.rc != -2);
    /* the query turned into its own response (QR=1, the OPT RR echoed) is an answer without data whose cookie is ours */
    q[2] |= 0x80;
    alias_parse_response(q, ql, id, names[which], lens[which], qtype, ccp, &self);
    trap_if(self.rc != 0 || self.n != 0);
    trap_if(ccp && self.cookie != (sclen ? ALIAS_CK_SERVER : ALIAS_CK_CLIENT));
    trap_if(ccp && self.sc_len != sclen);
    return 0;
}
