/*
 * test_presigned.c - presigned DNSSEC zones from the PowerDNS schema (dns_presigned.c, beta design 3.6, milestone B5).
 *
 * Three zones are signed at test time with BIND's dnssec-signzone (NSEC, NSEC3 with salt and iterations, NSEC3 with
 * Opt-Out); the test SKIPs without dnssec-keygen / dnssec-signzone.  For each:
 *   signed zone file -> zone2sql (presigned layout: PRESIGNED / NSEC3PARAM metadata, no NSEC3 / NSEC3PARAM / NSEC
 *   rows, ordername, ENT rows) -> reader (dns_pdns_reader.c, rebuild in dns_presigned.c) -> the RRs must be the
 *   signer's byte for byte (owner, type, class, TTL and canonical RDATA, compared as sorted sets because the rebuilt
 *   RRs come last) -> KDB1 round trip.
 * Then every consistency failure of design 3.6 item 6 (RFC 5155 s7.1, RFC 4034 s4.1.2), made by editing the rows:
 * a missing chain owner, a chain owner without a name, a wrong ordername / salt, bad NSEC3PARAM metadata, mixtures of
 * stored and rebuilt data (D8), Opt-Out rules, differing Original TTLs, data at a hashed owner, the same for NSEC.
 *
 * Usage: test_presigned          (needs dnssec-keygen, dnssec-signzone; temporary files in $TMPDIR or /tmp)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>

#include "../dns_pdns_reader.h"
#include "../dns_presigned.h"
#include "../dns_utils.h"
#include "db/zone2sql.h"
#include "db/xfr_mocks.h"
#include "db/pdns_roundtrip.h"

void syslog(int priority, const char *format, ...) {
    (void)priority;
    (void)format;
}

#define H16 "0011223344556677"
#define H128 H16 H16 H16 H16 H16 H16 H16 H16

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_MSG(cond, ...) do { g_checks++; if (!(cond)) { g_failed++; \
    printf("  [FAIL] %s:%d: %s: ", __FILE__, __LINE__, #cond); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define CHECK_HAS(actual, needle) do { g_checks++; const char *a_ = (actual); const char *n_ = (needle); \
    if (!a_ || !strstr(a_, n_)) { g_failed++; printf("  [FAIL] %s:%d: \"%s\" lacks \"%s\"\n", \
        __FILE__, __LINE__, a_ ? a_ : "(null)", n_); } } while (0)

/* ------------------------------------------------------------------ fixtures */
static char g_dir[512];

static bool tool(const char *name) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "command -v %s >/dev/null 2>&1", name);
    return system(cmd) == 0;
}

static void write_zone(const char *z, FILE *fp) {
    fprintf(fp,
        "$ORIGIN %s.\n$TTL 300\n"
        "@ IN SOA ns1 hostmaster 2026101301 3600 600 86400 300\n"
        "@ IN NS ns1\n@ IN NS ns2\n@ IN MX 10 mail\n@ IN TXT \"v=spf1 -all\"\n"
        "ns1 IN A 192.0.2.53\nns1 IN AAAA 2001:db8::53\nns2 IN A 192.0.2.54\n"
        "mail IN A 192.0.2.25\nwww IN A 192.0.2.80\nwww IN AAAA 2001:db8::80\n"
        "w2 IN CNAME www\ndn IN DNAME target\ntarget IN A 192.0.2.99\nwww.target IN A 192.0.2.97\n"
        "*.wild IN A 192.0.2.100\na.wild IN A 192.0.2.101\nx.y.z.ent IN A 192.0.2.110\n"
        "sec IN NS ns1.sec\nsec IN DS 12345 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\n"
        "ns1.sec IN A 192.0.2.131\n"
        "ins IN NS ns1.ins\nns1.ins IN A 192.0.2.141\nhost.ins IN A 192.0.2.142\n"
        "srv IN SRV 10 20 5060 sip\nsip IN A 192.0.2.160\n"
        "big IN TXT \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n"
        "big IN TXT \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n",
        z);
}

/* sign zone z with the signer options in opts; the signed file is g_dir/z.signed */
static bool sign_zone(const char *z, const char *opts) {
    char path[700], cmd[1600];
    snprintf(path, sizeof(path), "%s/%s.zone", g_dir, z);
    FILE *fp = fopen(path, "w");
    if (!fp) return false;
    write_zone(z, fp);
    fclose(fp);
    snprintf(cmd, sizeof(cmd),
             "cd %s && dnssec-keygen -q -a ECDSAP256SHA256 -f KSK %s >/dev/null 2>&1 && "
             "dnssec-keygen -q -a ECDSAP256SHA256 %s >/dev/null 2>&1 && "
             "dnssec-signzone -q -S -K . %s -o %s -f %s.signed %s.zone >/dev/null 2>&1",
             g_dir, z, z, opts, z, z, z);
    return system(cmd) == 0;
}

/* ------------------------------------------------------------------ rows */
typedef struct {
    z2s_rows_t z;                   /* rows from zone2sql (presigned layout) */
    db_meta_row_t meta[2];
    size_t nmeta;
    zone_arena_t file;              /* the signed zone file */
    char apex[DNS_NAME_TEXT_SIZE];
} fx_t;

static bool fx_load(fx_t *f, const char *z, bool plain) {
    char path[700], err[400];
    snprintf(path, sizeof(path), "%s/%s.signed", g_dir, z);
    memset(f, 0, sizeof(*f));
    if (!z2s_load_zone_file(path, NULL, &f->file, f->apex, sizeof(f->apex), err, sizeof(err))) {
        printf("  [FAIL] load %s: %s\n", path, err);
        g_failed++;
        return false;
    }
    z2s_plain_signed = plain;
    bool ok = z2s_rows_from_arena(&f->file, f->apex, &f->z, err, sizeof(err));
    z2s_plain_signed = false;
    if (!ok) {
        printf("  [FAIL] rows of %s: %s\n", z, err);
        g_failed++;
        return false;
    }
    if (f->z.presigned) f->meta[f->nmeta++] = (db_meta_row_t){ 1, "PRESIGNED", "1" };
    if (f->z.nsec3param) f->meta[f->nmeta++] = (db_meta_row_t){ 1, "NSEC3PARAM", f->z.nsec3param };
    return true;
}

static void fx_free(fx_t *f) {
    z2s_rows_free(&f->z);
    zone_arena_destroy(&f->file);
}

/* a modifiable copy of the rows (extra room for added rows) */
typedef struct { db_record_row_t *r; size_t n, cap; } rs_t;

static rs_t rs_copy(const fx_t *f) {
    rs_t s;
    s.cap = f->z.n + 8;
    s.r = calloc(s.cap, sizeof(db_record_row_t));
    memcpy(s.r, f->z.rows, f->z.n * sizeof(db_record_row_t));
    s.n = f->z.n;
    return s;
}

static db_record_row_t *rs_add(rs_t *s, const db_record_row_t *r) {
    if (s->n < s->cap) {
        s->r[s->n] = *r;
        s->r[s->n].id = (int64_t)s->n + 1;
        return &s->r[s->n++];
    }
    return NULL;
}

/* first row with this type (and, if given, an owner that starts with the prefix / equals the name, a content prefix) */
static db_record_row_t *rs_find(rs_t *s, const char *type, const char *name, const char *content_prefix) {
    for (size_t i = 0; i < s->n; i++) {
        db_record_row_t *r = &s->r[i];
        if (!r->type || strcmp(r->type, type) != 0 || r->disabled) continue;
        if (name && strcmp(r->name, name) != 0) continue;
        if (content_prefix && (!r->content || strncmp(r->content, content_prefix, strlen(content_prefix)) != 0)) continue;
        return r;
    }
    return NULL;
}

static pdns_zone_t *rs_build(const fx_t *f, rs_t *s, const db_meta_row_t *meta, size_t nmeta) {
    pdns_zone_t *z = pdns_zone_new(f->z.zone, NULL);
    pdns_zone_convert(z, s->r, s->n, meta, nmeta);
    return z;
}

static pdns_zone_t *rs_build_default(const fx_t *f, rs_t *s) { return rs_build(f, s, f->meta, f->nmeta); }

/* The zone the reader built, as zone file text, checked by BIND's dnssec-verify: every signature, every NSEC / NSEC3 link and
 * the Opt-Out rules hold for the rebuilt chain.  (AXFR of a database zone is refused until B7, so the zone is taken from the
 * reader, which is what the Backend gets.)  SKIP without dnssec-verify. */
static void verify_with_bind(const char *what, const char *apex, const pdns_zone_t *z) {
    if (!tool("dnssec-verify")) {
        printf("  [SKIP] %s: dnssec-verify is not installed\n", what);
        return;
    }
    char path[700], cmd[1500];
    snprintf(path, sizeof(path), "%s/verify.zone", g_dir);
    FILE *fp = fopen(path, "w");
    CHECK(fp != NULL);
    if (!fp) return;
    fputs("$ORIGIN .\n", fp);                      /* the rdata names are as the reader sees them: relative to the root */
    for (size_t i = 0; i < z->arena.count; i++) {
        const dns_record_t *r = &z->arena.records[i];
        fprintf(fp, "%s %u IN %s", r->name, (unsigned)r->ttl_value, r->type);
        for (int k = 0; k < r->rdata_count; k++) {
            if (r->type_code == 16) {               /* TXT: the strings are stored without quotes */
                fputs(" \"", fp);
                for (const char *p = r->rdata[k]; *p; p++) {
                    if (*p == '"' || *p == '\\') fputc('\\', fp);
                    fputc(*p, fp);
                }
                fputc('"', fp);
            } else {
                fprintf(fp, " %s", r->rdata[k]);
            }
        }
        fputc('\n', fp);
    }
    fclose(fp);
    snprintf(cmd, sizeof(cmd), "dnssec-verify -q -o %s %s > %s/verify.out 2>&1", apex, path, g_dir);
    int rc = system(cmd);
    CHECK_MSG(rc == 0, "%s: dnssec-verify failed (see %s/verify.out)", what, g_dir);
    if (rc != 0) {
        snprintf(cmd, sizeof(cmd), "head -5 %s/verify.out", g_dir);
        if (system(cmd) != 0) printf("  (no output)\n");
    }
}

/* the zone has to fail with `needle` in the error */
static void expect_fail(const char *what, pdns_zone_t *z, const char *needle) {
    CHECK_MSG(z->failed, "%s: expected a failure", what);
    if (z->failed) {
        if (strstr(z->error, needle) == NULL) {
            g_failed++;
            printf("  [FAIL] %s: error \"%s\" lacks \"%s\"\n", what, z->error, needle);
        }
        g_checks++;
    }
    pdns_zone_free(z);
}

/* the rebuilt zone has exactly the RRs of the signed file; returns the number of rebuilt RRs */
static size_t expect_same_as_file(const char *what, const fx_t *f, pdns_zone_t *z, presigned_mode_t mode) {
    size_t n = 0;
    CHECK_MSG(!z->failed, "%s: %s", what, z->failed ? z->error : "");
    if (z->failed) return 0;
    CHECK_MSG(z->presigned_mode == mode, "%s: mode %d", what, (int)z->presigned_mode);
    size_t nw = 0, ng = 0;
    char **want = rt_sorted_lines(&f->file, &nw), **got = rt_sorted_lines(&z->arena, &ng);
    CHECK_MSG(want && got && nw == ng, "%s: %zu RRs in the file, %zu from the rows", what, nw, ng);
    size_t bad = 0;
    for (size_t i = 0; want && got && i < nw && i < ng; i++)
        if (strcmp(want[i], got[i]) != 0 && bad++ < 3) printf("    file   %.160s\n    reader %.160s\n", want[i], got[i]);
    CHECK_MSG(bad == 0, "%s: %zu RRs differ from the signer's", what, bad);
    if (want) rt_free_lines(want, nw);
    if (got) rt_free_lines(got, ng);
    rt_info_t info;
    char why[300];
    bool ok = pdns_roundtrip(z, &info, why, sizeof(why));
    CHECK_MSG(ok, "%s: KDB1 round trip: %s", what, why);
    n = z->n_synth;
    return n;
}

/* open item 1 (decided 2026-10-21): the hashed first label of every NSEC3 owner and of every RRSIG(NSEC3) owner is spelled in
 * upper case (RFC 4648 s7 alphabet, as BIND's signer writes it); returns how many owners were looked at */
static size_t check_upper_hash_owners(const char *what, const zone_arena_t *a) {
    size_t n = 0, lower = 0, other_changed = 0;
    for (size_t i = 0; i < a->count; i++) {
        const dns_record_t *r = &a->records[i];
        bool hashed = r->type_code == 50 || (r->type_code == 46 && r->rdata_count > 0 && r->rdata[0] && strcasecmp(r->rdata[0], "NSEC3") == 0);
        if (!hashed) {
            for (const char *p = r->name; p && *p; p++)           /* the other owners keep the lower case the rows have */
                if (*p >= 'A' && *p <= 'Z') other_changed++;
            continue;
        }
        n++;
        for (size_t k = 0; k < 32 && r->name[k]; k++)
            if (r->name[k] >= 'a' && r->name[k] <= 'z') lower++;
        if (r->name_wire && r->name_wire_len > 32)
            for (size_t k = 1; k <= 32; k++)
                if (r->name_wire[k] >= 'a' && r->name_wire[k] <= 'z') lower++;
    }
    CHECK_MSG(n > 0, "%s: no NSEC3 owners", what);
    CHECK_MSG(lower == 0, "%s: %zu lower-case letters in the hashed owner labels", what, lower);
    CHECK_MSG(other_changed == 0, "%s: %zu upper-case letters in other owner names", what, other_changed);
    return n;
}

static int count_type(const rs_t *s, const char *type) {
    int c = 0;
    for (size_t i = 0; i < s->n; i++)
        if (s->r[i].type && !s->r[i].disabled && strcmp(s->r[i].type, type) == 0) c++;
    return c;
}

/* the hashed owner of the n-th RRSIG(NSEC3) row */
static db_record_row_t *rrsig_nsec3(rs_t *s, int nth) {
    for (size_t i = 0; i < s->n; i++) {
        db_record_row_t *r = &s->r[i];
        if (r->type && !r->disabled && strcmp(r->type, "RRSIG") == 0 && strncmp(r->content, "NSEC3 ", 6) == 0 && nth-- == 0) return r;
    }
    return NULL;
}

/* ------------------------------------------------------------------ NSEC3 */
static void test_nsec3(const char *z, const char *label, bool optout) {
    printf("%s\n", label);
    fx_t f;
    if (!fx_load(&f, z, false)) return;
    CHECK(f.z.presigned && f.z.nsec3param);
    rs_t s = rs_copy(&f);
    CHECK(count_type(&s, "NSEC3") == 0 && count_type(&s, "NSEC3PARAM") == 0);
    CHECK(count_type(&s, "RRSIG") > 10);
    int nrs = 0;
    for (int i = 0; rrsig_nsec3(&s, i); i++) nrs++;
    int nent = 0;
    for (size_t i = 0; i < s.n; i++)
        if (!s.r[i].type) nent++;
    CHECK_MSG(nent >= 3, "ENT rows: %d", nent);
    char meta_flags[16];
    snprintf(meta_flags, sizeof(meta_flags), " %d ", optout ? 1 : 0);
    CHECK_HAS(f.z.nsec3param, meta_flags);

    /* 1. the signer's NSEC3 chain, byte for byte */
    pdns_zone_t *pz = rs_build_default(&f, &s);
    size_t synth = expect_same_as_file("rebuild", &f, pz, PS_NSEC3);
    CHECK_MSG((int)synth == nrs + 1, "%zu rebuilt RRs, %d chain owners + NSEC3PARAM", synth, nrs);
    (void)check_upper_hash_owners(label, &pz->arena);
    {   /* open item 3: the loader warns about NSEC3PARAM metadata with iterations > 0 (RFC 9276 s3.1); the cap stays 2500 */
        unsigned alg = 0, fl = 0, iters = 0;
        CHECK(sscanf(f.z.nsec3param, "%u %u %u", &alg, &fl, &iters) == 3);
        bool warned = false;
        for (size_t i = 0; i < pz->n_warnings; i++)
            if (strstr(pz->warnings[i], "RFC 9276")) warned = true;
        CHECK_MSG(warned == (iters > 0), "%s: iterations %u, RFC 9276 warning %s", label, iters, warned ? "given" : "absent");
    }
    verify_with_bind(label, f.apex, pz);
    pdns_zone_free(pz);

    /* the rows of a second import are the same rows: deterministic order of the synthesized RRs */
    pdns_zone_t *a = rs_build_default(&f, &s), *b = rs_build_default(&f, &s);
    rt_buf_t ba = {0}, bb = {0};
    char err[300];
    pdns_kdb_params_t kp = { 0, 1, KDB_ZK_PRIMARY, NULL, NULL, NULL, NULL };
    CHECK(pdns_zone_encode_kdb(a, &kp, rt_emit, &ba, err, sizeof(err)) == 0);
    CHECK(pdns_zone_encode_kdb(b, &kp, rt_emit, &bb, err, sizeof(err)) == 0);
    CHECK(ba.len == bb.len && ba.len > 0 && memcmp(ba.buf, bb.buf, ba.len) == 0);
    free(ba.buf);
    free(bb.buf);
    pdns_zone_free(a);
    pdns_zone_free(b);

    /* 2. a name without its RRSIG(NSEC3) (a www owner) */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *w = rs_find(&m, "A", "www.ps", NULL);
        char nm[300];
        snprintf(nm, sizeof(nm), "www.%s", f.z.zone);
        w = rs_find(&m, "A", nm, NULL);
        CHECK(w && w->ordername);
        if (w && w->ordername) {
            char hashed[400];
            snprintf(hashed, sizeof(hashed), "%s.%s", w->ordername, f.z.zone);
            db_record_row_t *sg = rs_find(&m, "RRSIG", hashed, "NSEC3 ");
            CHECK(sg != NULL);
            if (sg) sg->disabled = true;
            pdns_zone_t *x = rs_build_default(&f, &m);
            expect_fail("missing RRSIG(NSEC3) of www", x, "no RRSIG(NSEC3) owner for 'www.");
            if (sg) sg->disabled = false;
        }
        free(m.r);
    }
    /* 3. an empty non-terminal without a chain owner */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *ent = NULL;
        for (size_t i = 0; i < m.n; i++)
            if (!m.r[i].type && m.r[i].ordername) { ent = &m.r[i]; break; }
        CHECK(ent != NULL);
        if (ent) {
            char hashed[400];
            snprintf(hashed, sizeof(hashed), "%s.%s", ent->ordername, f.z.zone);
            db_record_row_t *sg = rs_find(&m, "RRSIG", hashed, "NSEC3 ");
            CHECK(sg != NULL);
            if (sg) sg->disabled = true;
            expect_fail("missing RRSIG(NSEC3) of an ENT", rs_build_default(&f, &m), "(empty non-terminal)");
        }
        free(m.r);
    }
    /* 4. a chain owner that is no name */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *sg = rrsig_nsec3(&m, 0);
        CHECK(sg != NULL);
        if (sg) {
            db_record_row_t extra = *sg;
            char bogus[400];
            snprintf(bogus, sizeof(bogus), "00000000000000000000000000000000.%s", f.z.zone);
            extra.name = bogus;
            rs_add(&m, &extra);
            expect_fail("bogus chain owner", rs_build_default(&f, &m), "matches no name");
        }
        free(m.r);
    }
    /* 5. wrong ordername */
    {
        rs_t m = rs_copy(&f);
        char nm[300];
        snprintf(nm, sizeof(nm), "www.%s", f.z.zone);
        db_record_row_t *w = rs_find(&m, "A", nm, NULL);
        CHECK(w != NULL);
        if (w) {
            w->ordername = "00000000000000000000000000000000";
            expect_fail("wrong ordername", rs_build_default(&f, &m), "is not its NSEC3 hash");
        }
        free(m.r);
    }
    /* 5b. wrong ordername of an ENT row */
    {
        rs_t m = rs_copy(&f);
        for (size_t i = 0; i < m.n; i++)
            if (!m.r[i].type && m.r[i].ordername) { m.r[i].ordername = "0123456789abcdefghijklmnopqrstuv"; break; }
        pdns_zone_t *x = rs_build_default(&f, &m);
        expect_fail("wrong ENT ordername", x, "empty non-terminal");
        free(m.r);
    }
    /* 6. another salt in the metadata: every hash is different */
    {
        rs_t m = rs_copy(&f);
        db_meta_row_t meta2[2] = { f.meta[0], { 1, "NSEC3PARAM", optout ? "1 1 0 ab" : "1 0 3 aabbccde" } };
        expect_fail("other salt", rs_build(&f, &m, meta2, 2), "is not its NSEC3 hash");
        free(m.r);
    }
    /* 7. bad metadata */
    {
        static const struct { const char *meta, *needle; } bad[] = {
            { "1 0 3", "four fields" },
            { "1 0 3 aa bb", "more than four" },
            { "2 0 3 aa", "not 1" },
            { "1 2 3 aa", "flags must be 0 or 1" },
            { "1 0 2501 aa", "exceed 2500" },
            { "1 0 x aa", "decimal" },
            { "1 0 3 abc", "even number of hex digits" },
            { "1 0 3 zz", "not hexadecimal" },
            { "1 0 3 " H128 H128 H128 H128 H16, "at most 255 octets" },
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            rs_t m = rs_copy(&f);
            db_meta_row_t meta2[2] = { f.meta[0], { 1, "NSEC3PARAM", bad[i].meta } };
            expect_fail(bad[i].meta, rs_build(&f, &m, meta2, 2), bad[i].needle);
            free(m.r);
        }
    }
    /* 8. stored NSEC3 / NSEC3PARAM / RRSIG(NSEC) rows together with the metadata (D8: mixtures are rejected) */
    {
        static const char *const types[] = { "NSEC3", "NSEC3PARAM", "NSEC" };
        for (size_t i = 0; i < 3; i++) {
            rs_t m = rs_copy(&f);
            db_record_row_t r;
            memset(&r, 0, sizeof(r));
            r.name = f.z.zone;
            r.type = types[i];
            r.content = i == 0 ? "1 0 3 AABBCCDD 4THKQJ61SGI4A5CDJ8O95M838DB7I8K5 A" : i == 1 ? "1 0 3 AABBCCDD" : "www.x.test A";
            r.ttl = 300;
            if (i == 2) r.name = f.z.zone;
            rs_add(&m, &r);
            char what[80];
            snprintf(what, sizeof(what), "mixture with stored %s", types[i]);
            expect_fail(what, rs_build_default(&f, &m), "either rebuilt from the metadata or stored as is");
            free(m.r);
        }
    }
    /* 9. no RRSIG(NSEC3) rows at all */
    {
        rs_t m = rs_copy(&f);
        while (rrsig_nsec3(&m, 0)) rrsig_nsec3(&m, 0)->disabled = true;
        expect_fail("no RRSIG(NSEC3)", rs_build_default(&f, &m), "no RRSIG(NSEC3) rows");
        free(m.r);
    }
    /* 10. RRSIG(NSEC3) owner not directly below the apex / not a hash */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *sg = rrsig_nsec3(&m, 0);
        if (sg) {
            char deeper[500];
            snprintf(deeper, sizeof(deeper), "x.%s", sg->name);
            sg->name = deeper;
            expect_fail("owner too deep", rs_build_default(&f, &m), "not a hashed owner name directly below");
        }
        free(m.r);
        m = rs_copy(&f);
        sg = rrsig_nsec3(&m, 0);
        if (sg) {
            sg->name = f.z.zone;
            pdns_zone_t *x = rs_build_default(&f, &m);
            CHECK(x->failed);            /* an RRSIG(NSEC3) at the apex is no hashed owner */
            pdns_zone_free(x);
        }
        free(m.r);
    }
    /* 11. Original TTLs of the RRSIG(NSEC3) rows of one owner differ */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *sg = rrsig_nsec3(&m, 0);
        if (sg) {
            db_record_row_t extra = *sg;
            char content[900];
            snprintf(content, sizeof(content), "%s", sg->content);
            /* "NSEC3 13 3 300 ..." -> Original TTL 301 */
            char *p = strstr(content, " 300 ");
            CHECK(p != NULL);
            if (p) {
                p[3] = '1';
                p[2] = '0';
                p[1] = '3';
                memcpy(p, " 301 ", 5);
                extra.content = content;
                rs_add(&m, &extra);
                expect_fail("differing Original TTLs", rs_build_default(&f, &m), "different Original TTLs");
            }
        }
        free(m.r);
    }
    /* 12. data at a hashed owner */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *sg = rrsig_nsec3(&m, 0);
        if (sg) {
            db_record_row_t r;
            memset(&r, 0, sizeof(r));
            r.name = sg->name;
            r.type = "A";
            r.content = "192.0.2.1";
            r.ttl = 300;
            rs_add(&m, &r);
            expect_fail("data at a hashed owner", rs_build_default(&f, &m), "holds RRSIG(NSEC3) and other data");
        }
        free(m.r);
    }
    /* 13. without PRESIGNED metadata nothing is rebuilt: the rows are served as they are */
    {
        rs_t m = rs_copy(&f);
        pdns_zone_t *x = rs_build(&f, &m, NULL, 0);
        CHECK(!x->failed);
        if (!x->failed) {
            CHECK(x->presigned_mode == PS_NONE && x->n_synth == 0);
        }
        pdns_zone_free(x);
        free(m.r);
    }
    /* 14. Opt-Out */
    if (optout) {
        rs_t m = rs_copy(&f);
        db_meta_row_t meta2[2] = { f.meta[0], { 1, "NSEC3PARAM", "1 0 0 -" } };      /* Opt-Out bit cleared */
        expect_fail("insecure delegation without Opt-Out", rs_build(&f, &m, meta2, 2), "no RRSIG(NSEC3) owner for 'ins.");
        free(m.r);
        m = rs_copy(&f);
        char nm[300];
        snprintf(nm, sizeof(nm), "sec.%s", f.z.zone);
        db_record_row_t *ds = rs_find(&m, "DS", nm, NULL);
        CHECK(ds && ds->ordername);
        if (ds && ds->ordername) {
            char hashed[400];
            snprintf(hashed, sizeof(hashed), "%s.%s", ds->ordername, f.z.zone);
            db_record_row_t *sg = rs_find(&m, "RRSIG", hashed, "NSEC3 ");
            CHECK(sg != NULL);
            if (sg) sg->disabled = true;
            expect_fail("secure delegation without NSEC3 under Opt-Out", rs_build_default(&f, &m), "no RRSIG(NSEC3) owner for 'sec.");
        }
        free(m.r);
        /* ordername of the insecure delegation and of the glue below it: NULL, as PowerDNS stores them */
        m = rs_copy(&f);
        snprintf(nm, sizeof(nm), "ins.%s", f.z.zone);
        db_record_row_t *ns = rs_find(&m, "NS", nm, NULL);
        CHECK(ns && !ns->ordername);
        free(m.r);
    } else {
        rs_t m = rs_copy(&f);
        char nm[300];
        snprintf(nm, sizeof(nm), "ins.%s", f.z.zone);
        db_record_row_t *ns = rs_find(&m, "NS", nm, NULL);
        CHECK(ns && ns->ordername);                          /* without Opt-Out the delegation is in the chain */
        free(m.r);
    }
    free(s.r);

    /* 15. stored NSEC3 rows without NSEC3PARAM metadata are served as stored (D8) */
    {
        fx_t g;
        if (fx_load(&g, z, true)) {
            rs_t m = rs_copy(&g);
            CHECK(count_type(&m, "NSEC3") > 5 && count_type(&m, "NSEC3PARAM") == 1);
            db_meta_row_t pm[1] = { { 1, "PRESIGNED", "1" } };
            pdns_zone_t *x = rs_build(&g, &m, pm, 1);
            expect_same_as_file("NSEC3 rows as stored", &g, x, PS_NONE);
            CHECK(x->n_synth == 0);
            pdns_zone_free(x);
            /* NSEC3 rows removed, RRSIG(NSEC3) rows left, no metadata */
            for (size_t i = 0; i < m.n; i++)
                if (m.r[i].type && strcmp(m.r[i].type, "NSEC3") == 0) m.r[i].disabled = true;
            expect_fail("RRSIG(NSEC3) without NSEC3", rs_build(&g, &m, pm, 1), "no NSEC3 rows and no NSEC3PARAM metadata");
            free(m.r);
            fx_free(&g);
        }
    }
    fx_free(&f);
}

/* ------------------------------------------------------------------ NSEC */
static void test_nsec(const char *z) {
    printf("NSEC (presigned, RRSIG(NSEC) rows only)\n");
    fx_t f;
    if (!fx_load(&f, z, false)) return;
    CHECK(f.z.presigned && !f.z.nsec3param);
    rs_t s = rs_copy(&f);
    CHECK(count_type(&s, "NSEC") == 0);
    int nrs = 0;
    for (size_t i = 0; i < s.n; i++)
        if (s.r[i].type && strcmp(s.r[i].type, "RRSIG") == 0 && strncmp(s.r[i].content, "NSEC ", 5) == 0) nrs++;
    CHECK(nrs > 10);

    pdns_zone_t *pz = rs_build_default(&f, &s);
    size_t synth = expect_same_as_file("NSEC rebuild", &f, pz, PS_NSEC);
    CHECK_MSG((int)synth == nrs, "%zu rebuilt NSEC RRs, %d RRSIG(NSEC) rows", synth, nrs);
    verify_with_bind("NSEC rebuild", f.apex, pz);
    pdns_zone_free(pz);

    char nm[300];
    snprintf(nm, sizeof(nm), "www.%s", f.z.zone);
    /* a name without RRSIG(NSEC) */
    {
        rs_t m = rs_copy(&f);
        for (size_t i = 0; i < m.n; i++)
            if (m.r[i].type && strcmp(m.r[i].type, "RRSIG") == 0 && strcmp(m.r[i].name, nm) == 0 &&
                strncmp(m.r[i].content, "NSEC ", 5) == 0)
                m.r[i].disabled = true;
        expect_fail("missing RRSIG(NSEC)", rs_build_default(&f, &m), "no RRSIG(NSEC) for 'www.");
        free(m.r);
    }
    /* the apex without RRSIG(NSEC) */
    {
        rs_t m = rs_copy(&f);
        for (size_t i = 0; i < m.n; i++)
            if (m.r[i].type && strcmp(m.r[i].type, "RRSIG") == 0 && strcmp(m.r[i].name, f.z.zone) == 0 &&
                strncmp(m.r[i].content, "NSEC ", 5) == 0)
                m.r[i].disabled = true;
        expect_fail("apex without RRSIG(NSEC)", rs_build_default(&f, &m), "RRSIG(NSEC)");
        free(m.r);
    }
    /* RRSIG(NSEC) at glue below a delegation (RFC 4034 s4.1.2) */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *src = NULL;
        for (size_t i = 0; i < m.n; i++)
            if (m.r[i].type && strcmp(m.r[i].type, "RRSIG") == 0 && strncmp(m.r[i].content, "NSEC ", 5) == 0) { src = &m.r[i]; break; }
        char glue[300];
        snprintf(glue, sizeof(glue), "host.ins.%s", f.z.zone);
        if (src) {
            db_record_row_t extra = *src;
            extra.name = glue;
            rs_add(&m, &extra);
            expect_fail("RRSIG(NSEC) at glue", rs_build_default(&f, &m), "below a delegation");
        }
        free(m.r);
    }
    /* ordername */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *w = rs_find(&m, "A", nm, NULL);
        CHECK(w && w->ordername && strcmp(w->ordername, "www") == 0);
        if (w) {
            w->ordername = "wwx";
            expect_fail("wrong NSEC ordername", rs_build_default(&f, &m), "ordername 'wwx'");
        }
        free(m.r);
        m = rs_copy(&f);
        snprintf(nm, sizeof(nm), "x.y.z.ent.%s", f.z.zone);
        w = rs_find(&m, "A", nm, NULL);
        CHECK(w && w->ordername && strcmp(w->ordername, "ent z y x") == 0);       /* labels reversed, PowerDNS 5.1.4 */
        free(m.r);
    }
    /* differing Original TTLs */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t *sg = NULL;
        for (size_t i = 0; i < m.n; i++)
            if (m.r[i].type && strcmp(m.r[i].type, "RRSIG") == 0 && strncmp(m.r[i].content, "NSEC ", 5) == 0) { sg = &m.r[i]; break; }
        if (sg) {
            db_record_row_t extra = *sg;
            char content[900];
            snprintf(content, sizeof(content), "%s", sg->content);
            char *p = strstr(content, " 300 ");
            if (p) {
                memcpy(p, " 301 ", 5);
                extra.content = content;
                rs_add(&m, &extra);
                expect_fail("NSEC differing Original TTLs", rs_build_default(&f, &m), "different Original TTLs");
            }
        }
        free(m.r);
    }
    /* NSEC3PARAM metadata with RRSIG(NSEC) rows: a mixture */
    {
        rs_t m = rs_copy(&f);
        db_meta_row_t meta2[2] = { f.meta[0], { 1, "NSEC3PARAM", "1 0 0 -" } };
        expect_fail("NSEC3PARAM with RRSIG(NSEC)", rs_build(&f, &m, meta2, 2), "stored RRSIG(NSEC) rows");
        free(m.r);
    }
    /* RRSIG(NSEC) rows without NSEC3 data but with an NSEC3PARAM row: mixture */
    {
        rs_t m = rs_copy(&f);
        db_record_row_t r;
        memset(&r, 0, sizeof(r));
        r.name = f.z.zone;
        r.type = "NSEC3PARAM";
        r.content = "1 0 0 -";
        r.ttl = 0;
        rs_add(&m, &r);
        expect_fail("RRSIG(NSEC) with NSEC3PARAM row", rs_build_default(&f, &m), "together with NSEC3 data");
        free(m.r);
    }
    free(s.r);
    /* NSEC rows stored: served as stored */
    {
        fx_t g;
        if (fx_load(&g, z, true)) {
            rs_t m = rs_copy(&g);
            CHECK(count_type(&m, "NSEC") > 5);
            db_meta_row_t pm[1] = { { 1, "PRESIGNED", "1" } };
            pdns_zone_t *x = rs_build(&g, &m, pm, 1);
            expect_same_as_file("NSEC rows as stored", &g, x, PS_NONE);
            pdns_zone_free(x);
            free(m.r);
            fx_free(&g);
        }
    }
    fx_free(&f);
}

/* ------------------------------------------------------------------ module level */
static void test_module(void) {
    printf("dns_presigned helpers\n");
    presigned_n3param_t p;
    const char *why = "";
    CHECK(presigned_parse_n3param("1 0 3 AABBCCDD", &p, &why));
    CHECK(p.alg == 1 && p.flags == 0 && p.iterations == 3 && p.salt_len == 4 && p.salt[0] == 0xAA && p.salt[3] == 0xDD);
    CHECK(presigned_parse_n3param("  1\t1  0 -  ", &p, &why));
    CHECK(p.flags == 1 && p.salt_len == 0);
    CHECK(!presigned_parse_n3param("", &p, &why));
    CHECK(!presigned_parse_n3param(NULL, &p, &why));
    /* RFC 5155 Appendix A: H(example) with salt aabbccdd, 12 iterations = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom */
    CHECK(presigned_parse_n3param("1 0 12 aabbccdd", &p, &why));
    char h[33];
    CHECK(presigned_nsec3_hash("example", &p, h));
    CHECK(strcmp(h, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom") == 0);
    CHECK(presigned_nsec3_hash("EXAMPLE.", &p, h));                 /* case and the trailing dot do not matter */
    CHECK(strcmp(h, "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom") == 0);
    CHECK(presigned_nsec3_hash("a.example", &p, h));
    CHECK(strcmp(h, "35mthgpgcu1qg68fab165klnsnk3dpvl") == 0);
    CHECK(presigned_nsec3_hash("ns1.example", &p, h));
    CHECK(strcmp(h, "2t7b4g4vsa5smi47k61mv5bv1a22bojr") == 0);
    CHECK(presigned_nsec3_hash("w.example", &p, h));
    CHECK(strcmp(h, "k8udemvp1j2f7eg6jebps17vp3n8i58h") == 0);
    CHECK(presigned_nsec3_hash("*.w.example", &p, h));
    CHECK(strcmp(h, "r53bq7cc2uvmubfu5ocmm6pers9tk9en") == 0);
    CHECK(presigned_nsec3_hash("x.w.example", &p, h));
    CHECK(strcmp(h, "b4um86eghhds6nea196smvmlo4ors995") == 0);
}

int main(void) {
    printf("=== presigned zones (dns_presigned.c) ===\n");
    test_module();
    if (!tool("dnssec-signzone") || !tool("dnssec-keygen")) {
        printf("[SKIP] dnssec-signzone / dnssec-keygen are not installed: the rebuild tests need signed zones\n");
        printf("\n%d checks, %d failed\n", g_checks, g_failed);
        return g_failed ? 1 : 0;
    }
    const char *tmp = getenv("TMPDIR");
    snprintf(g_dir, sizeof(g_dir), "%s/test_presigned.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(g_dir)) {
        printf("[FAIL] mkdtemp\n");
        return 1;
    }
    bool ok = sign_zone("ps-nsec.test", "") && sign_zone("ps-n3.test", "-3 AABBCCDD -H 3") &&
              sign_zone("ps-oo.test", "-3 - -H 0 -A");
    if (!ok) {
        printf("[SKIP] dnssec-signzone could not sign the test zones\n");
    } else {
        test_nsec3("ps-n3.test", "NSEC3 (salt, 3 iterations)", false);
        test_nsec3("ps-oo.test", "NSEC3 Opt-Out", true);
        test_nsec("ps-nsec.test");
    }
    char cmd[600];
    if (getenv("KARI_KEEP")) {
        printf("kept %s\n", g_dir);
    } else {
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
        if (system(cmd) != 0) printf("  (could not remove %s)\n", g_dir);
    }
    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
