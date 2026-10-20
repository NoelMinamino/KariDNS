/*
 * fuzz_nsec3_rebuild.c - rows of a presigned PowerDNS zone -> NSEC3 / NSEC rebuild (dns_presigned.c, via the reader).
 *
 * The input drives a small model of a presigned zone instead of raw bytes, so that many inputs are consistent
 * enough to get past the first check and exercise the chain building:
 *   byte 0  selector: bit0 NSEC (else NSEC3), bit1 Opt-Out, bit2 an extra RRSIG(NSEC3) owner made from the input,
 *           bit3 ENT rows get a (right or wrong) ordername, bit4 salt present, bit5 drop the apex chain owner
 *   byte 1  iterations 0..3 (+ 0x80: iterations 2501 so the limit check runs)
 *   byte 2  number of names (1..24)
 *   then per name 3 bytes: labels (depth 1..4, each label from a table), types (A / NS / DS / TXT), flags
 *           (bit0 RRSIG(NSEC3 or NSEC) owner for it, bit1 wrong ordername, bit2 ordername NULL, bit3 add an RRSIG(A))
 * ordername and chain owners are computed with presigned_nsec3_hash() when the input says "right", so consistent
 * zones are common.  The rebuild must either fail the zone with an error that names it, or produce a chain that
 * is consistent: NSEC3 owners strictly increasing in hash order, every next hashed owner = the next owner (the last
 * one wraps), every owner the hash of a name of the zone or of an empty non-terminal; NSEC owners in canonical
 * order, next name = next owner, the first owner is the apex.  An accepted zone must also survive the KDB1 round
 * trip.  "internal error" is a bug: trap.
 */
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "../db/xfr_mocks.h"
#include "../db/pdns_roundtrip.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define ZONE "fuzz.test"
#define SIG_TAIL "13 3 300 20360101000000 20260101000000 12345 fuzz.test. AwEAAcvPyrbeMXE2CxVFJhnpJAWoJJJMiqpbRVvIgN0o"
#define SIG "A " SIG_TAIL

static const char *const k_labels[8] = { "a", "b", "c", "www", "ns", "x", "*", "y" };

static void trap_if(int cond) {
    if (cond) __builtin_trap();
}

/* insertion sort of arena indexes: NSEC3 by lower-case owner label (hash order), NSEC by canonical owner order */
static void sort_idx(const zone_arena_t *a, size_t *ix, size_t n, bool by_hash) {
    for (size_t i = 1; i < n; i++) {
        size_t v = ix[i], j = i;
        while (j > 0) {
            const char *x = a->records[ix[j - 1]].name, *y = a->records[v].name;
            int c = by_hash ? strncasecmp(x, y, 32) : compare_canonical_name(x, y);
            if (c <= 0) break;
            ix[j] = ix[j - 1];
            j--;
        }
        ix[j] = v;
    }
}

static bool is_name_of_zone(const zone_arena_t *a, const char *h, const presigned_n3param_t *np) {
    char hh[33];
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        if (r->type_code == 50 || r->type_code == 51) continue;           /* synthesized: no names of the zone */
        for (const char *p = r->name; p; ) {
            if (presigned_nsec3_hash(p, np, hh) && strcmp(hh, h) == 0) return true;
            if (domain_names_match_ci(p, ZONE ".")) break;
            const char *dot = strchr(p, '.');
            p = dot && dot[1] ? dot + 1 : NULL;
        }
    }
    return false;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3 || size > 4096) return 0;
    uint8_t sel = data[0];
    bool nsec_mode = sel & 1, optout = sel & 2;
    unsigned iter = data[1] & 3;
    if (data[1] & 0x80) iter = 2501;
    size_t nnames = (size_t)(data[2] % 24) + 1;
    const char *salt_txt = (sel & 16) ? "aabb" : "-";
    char meta[64];
    snprintf(meta, sizeof(meta), "1 %d %u %s", optout ? 1 : 0, iter, salt_txt);
    presigned_n3param_t np;
    const char *why;
    if (!presigned_parse_n3param(meta, &np, &why)) {
        np.alg = 1; np.flags = 0; np.iterations = 0; np.salt_len = 0;      /* wrong parameters: the zone must still fail cleanly */
    }

    pdns_zone_t *z = pdns_zone_new(ZONE, NULL);
    if (!z) return 0;
    int64_t id = 1;
    db_record_row_t r;
    char hashed[64], on[40], content[200];
    char names[24][300];

    memset(&r, 0, sizeof(r));
    r.id = id++; r.ttl = 300; r.name = ZONE; r.type = "SOA";
    r.content = "ns.fuzz.test hostmaster.fuzz.test 2024010101 7200 3600 1209600 300";
    pdns_zone_add_record(z, &r);
    {   /* apex: NS, RRSIG(A) stands in for the zone's signatures, chain owner */
        memset(&r, 0, sizeof(r));
        r.id = id++; r.ttl = 300; r.name = ZONE; r.type = "NS"; r.content = "ns.fuzz.test";
        char h[33];
        if (!nsec_mode && presigned_nsec3_hash(ZONE ".", &np, h)) r.ordername = h;
        if (nsec_mode) r.ordername = "";
        pdns_zone_add_record(z, &r);
        memset(&r, 0, sizeof(r));
        r.id = id++; r.ttl = 300; r.name = "ns.fuzz.test"; r.type = "A"; r.content = "192.0.2.1";
        if (!nsec_mode && presigned_nsec3_hash("ns.fuzz.test.", &np, h)) r.ordername = h;
        if (nsec_mode) r.ordername = "ns";
        pdns_zone_add_record(z, &r);
        memset(&r, 0, sizeof(r));
        r.id = id++; r.ttl = 300; r.type = "RRSIG"; r.content = SIG;
        r.name = ZONE;
        pdns_zone_add_record(z, &r);
        if (!(sel & 32)) {
            memset(&r, 0, sizeof(r));
            r.id = id++; r.ttl = 300; r.type = "RRSIG";
            if (nsec_mode) {
                r.name = ZONE;
                snprintf(content, sizeof(content), "NSEC %s", SIG_TAIL);
            } else if (presigned_nsec3_hash(ZONE ".", &np, h)) {
                snprintf(hashed, sizeof(hashed), "%s." ZONE, h);
                r.name = hashed;
                snprintf(content, sizeof(content), "NSEC3 %s", SIG_TAIL);
            }
            r.content = content;
            if (r.name) pdns_zone_add_record(z, &r);
        }
        if (!nsec_mode) {      /* ns.fuzz.test is a name of the zone: its chain owner */
            if (presigned_nsec3_hash("ns.fuzz.test.", &np, h)) {
                snprintf(hashed, sizeof(hashed), "%s." ZONE, h);
                memset(&r, 0, sizeof(r));
                r.id = id++; r.ttl = 300; r.type = "RRSIG"; r.name = hashed;
                snprintf(content, sizeof(content), "NSEC3 %s", SIG_TAIL);
                r.content = content;
                pdns_zone_add_record(z, &r);
            }
        } else {
            memset(&r, 0, sizeof(r));
            r.id = id++; r.ttl = 300; r.type = "RRSIG"; r.name = "ns.fuzz.test";
            snprintf(content, sizeof(content), "NSEC %s", SIG_TAIL);
            r.content = content;
            pdns_zone_add_record(z, &r);
        }
    }

    size_t pos = 3;
    for (size_t n = 0; n < nnames && pos + 3 <= size; n++, pos += 3) {
        uint8_t lb = data[pos], tb = data[pos + 1], fb = data[pos + 2];
        unsigned depth = 1 + (lb >> 6);
        char *nm = names[n];
        nm[0] = '\0';
        for (unsigned d = 0; d < depth; d++) {
            const char *l = k_labels[(lb >> (d * 2)) & 7];
            size_t cur = strlen(nm);
            snprintf(nm + cur, sizeof(names[n]) - cur, "%s%s", cur ? "." : "", l);
        }
        strncat(nm, "." ZONE, sizeof(names[n]) - strlen(nm) - 1);
        char abs[320], h[33];
        snprintf(abs, sizeof(abs), "%s.", nm);
        const char *ordername = NULL;
        char rev[300] = "";
        if (nsec_mode) {
            /* labels below the apex, reversed, blank separated */
            size_t nl = strlen(nm) - strlen(ZONE) - 1, end = nl, w = 0;
            while (end > 0 && w + 2 < sizeof(rev)) {
                size_t st = end;
                while (st > 0 && nm[st - 1] != '.') st--;
                if (w) rev[w++] = ' ';
                memcpy(rev + w, nm + st, end - st);
                w += end - st;
                end = st > 0 ? st - 1 : 0;
            }
            rev[w] = '\0';
            ordername = rev;
        } else if (presigned_nsec3_hash(abs, &np, h)) {
            ordername = h;
        }
        if (fb & 2) ordername = "wrong";
        if (fb & 4) ordername = NULL;
        static const char *const tys[4] = { "A", "NS", "DS", "TXT" };
        static const char *const cts[4] = { "192.0.2.7", "ns.fuzz.test", "12345 13 2 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "\"x\"" };
        for (unsigned t = 0; t < 4; t++) {
            if (!((tb >> t) & 1)) continue;
            memset(&r, 0, sizeof(r));
            r.id = id++; r.ttl = 300; r.name = nm; r.type = tys[t]; r.content = cts[t];
            r.ordername = ordername;
            pdns_zone_add_record(z, &r);
        }
        if (fb & 8) {
            memset(&r, 0, sizeof(r));
            r.id = id++; r.ttl = 300; r.name = nm; r.type = "RRSIG"; r.content = SIG;
            pdns_zone_add_record(z, &r);
        }
        if (fb & 1) {
            memset(&r, 0, sizeof(r));
            r.id = id++; r.ttl = 300; r.type = "RRSIG";
            if (nsec_mode) {
                r.name = nm;
                snprintf(content, sizeof(content), "NSEC %s", SIG_TAIL);
            } else if (presigned_nsec3_hash(abs, &np, h)) {
                snprintf(hashed, sizeof(hashed), "%s." ZONE, h);
                r.name = hashed;
                snprintf(content, sizeof(content), "NSEC3 %s", SIG_TAIL);
            }
            r.content = content;
            if (r.name) pdns_zone_add_record(z, &r);
            if (!nsec_mode) {                    /* the empty non-terminals above the name need chain owners too */
                for (const char *p = strchr(nm, '.'); p && strcmp(p + 1, ZONE) != 0; p = strchr(p + 1, '.')) {
                    char anc[320], ah[33];
                    snprintf(anc, sizeof(anc), "%s.", p + 1);
                    if (!presigned_nsec3_hash(anc, &np, ah)) break;
                    snprintf(hashed, sizeof(hashed), "%s." ZONE, ah);
                    memset(&r, 0, sizeof(r));
                    r.id = id++; r.ttl = 300; r.type = "RRSIG"; r.name = hashed;
                    snprintf(content, sizeof(content), "NSEC3 %s", SIG_TAIL);
                    r.content = content;
                    pdns_zone_add_record(z, &r);
                }
            }
        }
        if ((sel & 8) && n % 3 == 0) {          /* an ENT row for the parent */
            const char *dot = strchr(nm, '.');
            if (dot && strcmp(dot + 1, ZONE) != 0) {
                memset(&r, 0, sizeof(r));
                r.id = id++; r.name = dot + 1; r.type = NULL; r.ttl_null = r.prio_null = true;
                snprintf(abs, sizeof(abs), "%s.", dot + 1);
                if (!nsec_mode && presigned_nsec3_hash(abs, &np, h) && !(fb & 2)) {
                    snprintf(on, sizeof(on), "%s", h);
                    r.ordername = on;
                } else if (fb & 2) {
                    r.ordername = "wrong";
                }
                pdns_zone_add_record(z, &r);
            }
        }
    }
    if ((sel & 4) && !nsec_mode) {              /* an owner built from the input bytes */
        char lab[33];
        for (size_t i = 0; i < 32; i++) lab[i] = "0123456789abcdefghijklmnopqrstuv"[data[(3 + i) % size] & 31];
        lab[32] = '\0';
        snprintf(hashed, sizeof(hashed), "%s." ZONE, lab);
        memset(&r, 0, sizeof(r));
        r.id = id++; r.ttl = 300; r.type = "RRSIG"; r.name = hashed;
        snprintf(content, sizeof(content), "NSEC3 %s", SIG_TAIL);
        r.content = content;
        pdns_zone_add_record(z, &r);
    }

    db_meta_row_t m1 = { 1, "PRESIGNED", "1" }, m2 = { 1, "NSEC3PARAM", meta };
    pdns_zone_add_meta(z, &m1);
    if (!nsec_mode) pdns_zone_add_meta(z, &m2);
    int rc = pdns_zone_finish(z);
    if (getenv("FUZZ_NSEC3_VERBOSE")) fprintf(stderr, "rc=%d mode=%d %s\n", rc, (int)z->presigned_mode, rc ? z->error : "");
    if (rc != 0) {
        trap_if(!z->failed || strncmp(z->error, "zone 'fuzz.test.'", 17) != 0);
        trap_if(strstr(z->error, "internal error") != NULL);
    } else if (z->presigned_mode != PS_NONE) {
        const zone_arena_t *a = &z->arena;
        /* The synthesized RRs are not at the end: each one sits right before the stored RRSIG row that covers it.  They are
         * found by type (this mode stores no NSEC3 / NSEC3PARAM / NSEC rows) and put in chain order here. */
        size_t nsy = z->n_synth;
        trap_if(nsy == 0 || nsy > a->count);
        size_t *ix = malloc(a->count * sizeof(size_t)), nx_ = 0, n_param = 0;
        trap_if(!ix);
        uint16_t want = z->presigned_mode == PS_NSEC3 ? 50 : 47;
        for (size_t i = 0; i < a->count; i++) {
            if (a->records[i].type_code == want) ix[nx_++] = i;
            else if (z->presigned_mode == PS_NSEC3 && a->records[i].type_code == 51) n_param++;
        }
        trap_if(nx_ + n_param != nsy);
        if (z->presigned_mode == PS_NSEC3) {
            trap_if(n_param != 1 || nx_ == 0);
            sort_idx(a, ix, nx_, true);
            char prev[40] = "";
            for (size_t i = 0; i < nx_; i++) {
                const dns_record_t *rec = &a->records[ix[i]];
                trap_if(rec->ttl_value != 300 || rec->rdata_count < 5);
                char own[40];
                const char *dot = strchr(rec->name, '.');
                trap_if(!dot || dot - rec->name != 32);
                for (int k = 0; k < 32; k++) own[k] = (char)tolower((unsigned char)rec->name[k]);
                own[32] = '\0';
                trap_if(strcmp(own, prev) <= 0);                       /* strictly increasing hash order */
                snprintf(prev, sizeof(prev), "%s", own);
                const dns_record_t *nx = &a->records[ix[(i + 1) % nx_]];
                trap_if(strncasecmp(rec->rdata[4], nx->name, 32) != 0);   /* next hashed owner, last one wraps */
                trap_if(!is_name_of_zone(a, own, &np));
            }
        } else {
            trap_if(nx_ == 0);
            sort_idx(a, ix, nx_, false);
            trap_if(!domain_names_match_ci(a->records[ix[0]].name, ZONE));
            for (size_t i = 0; i < nx_; i++) {
                const dns_record_t *rec = &a->records[ix[i]];
                trap_if(rec->ttl_value != 300 || rec->rdata_count < 1);
                const dns_record_t *nx = &a->records[ix[(i + 1) % nx_]];
                trap_if(!domain_names_match_ci(rec->rdata[0], nx->name));
                if (i + 1 < nx_) trap_if(compare_canonical_name(rec->name, nx->name) >= 0);
            }
        }
        free(ix);
        char why2[400];
        if (!pdns_roundtrip(z, NULL, why2, sizeof(why2))) {
            fprintf(stderr, "fuzz_nsec3_rebuild: round trip failed: %s\n", why2);
            __builtin_trap();
        }
    }
    pdns_zone_free(z);
    return 0;
}
