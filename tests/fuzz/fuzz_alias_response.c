/*
 * fuzz_alias_response.c - the response of an ALIAS resolver (dns_alias.c, milestone B9a).  The bytes are untrusted network input.
 *
 *   byte 0   selector: bit0 QTYPE AAAA (else A), bits 1-2 the target name (t.target.test. / a.b.c.d.example. / the root / a 63-octet label)
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

    alias_parsed_t out;
    alias_parse_response(data + 3, size - 3, id, names[which], lens[which], qtype, &out);
    trap_if(out.rc != 0 && out.rc != 1 && out.rc != -1 && out.rc != -2);
    if (out.rc == 0) {
        trap_if(out.n > ALIAS_MAX_RR);
        trap_if(out.rdlen != (qtype == 1 ? 4 : 16));
        trap_if(out.ttl > ALIAS_MAX_TTL);
        trap_if(out.truncated);
    } else {
        trap_if(out.n != 0);
    }

    uint8_t w[260];
    size_t wl = 0;
    if (alias_wire_lower(data + 3, size - 3, w, &wl)) {
        trap_if(wl != size - 3 || wl == 0 || wl > 255);
        for (size_t i = 0; i < wl; i++) trap_if(w[i] >= 'A' && w[i] <= 'Z');       /* length octets are below 64: only letters could be folded wrongly */
    }

    uint8_t q[600];
    size_t ql = alias_build_query(q, sizeof(q), id, names[which], lens[which], qtype);
    trap_if(ql != 12 + lens[which] + 4 + 11);
    alias_parsed_t self;
    alias_parse_response(q, ql, id, names[which], lens[which], qtype, &self);      /* a query is not a response: QR is 0 */
    trap_if(self.rc != -2);
    return 0;
}
