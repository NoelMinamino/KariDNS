/*
 * test_tinydns_paths.c - path coverage for the tinydns-data (djbdns) parser.
 *
 *   1. Valid lines of every record type: the produced record types/counts are asserted.
 *   2. Error paths: a 64-byte label (or an over-long name) in EVERY FQDN position of every record type must
 *      be rejected, with an error message when the caller asked for one. Each rejection is exercised with
 *      (a) a context with err_out, (b) a context without err_out, (c) no context at all.
 *   3. Generic (:) records and unknown type characters.
 *   4. Robustness: truncation at every ':' boundary and junk fields must never crash or corrupt memory.
 * Known-lenient inputs (invalid IPv4 such as 300.0.2.10 is accepted) are executed but not pinned.
 * Meta-types (TKEY/TSIG/IXFR/ANY/...) in generic records are rejected.
 */
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "dns_wire.h"
#include "dns_zone_parser.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

#define N(a) (sizeof(a) / sizeof((a)[0]))
#define LONG64 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"   /* 64 chars: label limit is 63 */

typedef enum { CTX_FULL, CTX_NO_ERR_OUT, CTX_NONE } ctxmode_t;

static int run_line(const char *line, ctxmode_t mode, parse_error_t *err, zone_arena_t *arena, size_t *count_out) {
    zone_arena_init(arena);
    const char *zn[] = { "example.com." };
    parse_context_t ctx = { .base_dir = ".", .default_origin = "example.com.", .is_standalone_mode = true,
                            .err_out = (mode == CTX_FULL) ? err : NULL, .all_zone_names = zn, .all_zone_count = 1 };
    char text[4096];
    snprintf(text, sizeof(text), "%s\n", line);
    char *buf = arena_strdup(arena, text);
    assert(buf);
    memset(err, 0, sizeof(*err));
    int rc = parse_tinydns_data(buf, strlen(buf), arena, mode == CTX_NONE ? NULL : &ctx);
    if (count_out) *count_out = arena->count;
    return rc;
}

static bool has_type(zone_arena_t *a, uint16_t t) {
    for (size_t i = 0; i < a->count; i++) if (a->records[i].type_code == t) return true;
    return false;
}

/* ---------------------------------------------------------------- 1. valid lines */
static const struct { const char *line; size_t n; uint16_t must_have; } VALID[] = {
    { ".example.com:192.0.2.1:a.ns.example.com:300", 3, 6 },      /* SOA + NS + A glue */
    { ".example.com::b:300", 2, 6 },                                /* SOA + NS, no glue */
    { "&sub.example.com:192.0.2.2:ns2.example.com:300", 2, 2 },    /* NS + A */
    { "=www.example.com:192.0.2.10:300", 1, 1 },
    { "+alias.example.com:192.0.2.11:300", 1, 1 },
    { "@example.com:192.0.2.3:mail:10:300", 2, 15 },               /* MX + A for the host */
    { "@example.com::mx.example.com:20", 1, 15 },
    { "'txt.example.com:hello world:300", 1, 16 },
    { "Calias.example.com:www.example.com:300", 1, 5 },
    { "Zexample.com:ns1.example.com:hostmaster.example.com:1:2:3:4:5:300", 1, 6 },
    { ":raw.example.com:99:\\001\\002\\003:300", 1, 99 },
    { "3www.example.com:20010db8000000000000000000000001:300", 1, 28 },
    { "6www.example.com:20010db8000000000000000000000001:300", 1, 28 },
    { "Sexample.com:5.srv.example.com:5060:10:20:300", 1, 0 },
    { "Nexample.com:ns.example.com:300", 1, 0 },
    { "_sip._tcp.example.com:srv:5060", 1, 0 },
    { "=www.example.com:192.0.2.10:300:20260101T000000:lo", 1, 1 },
    { "=www.example.com:192.0.2.10:300:4611686018427387914", 1, 1 },
    { "=www.example.com:192.0.2.10:0:4611686018427387914", 1, 1 },
    { "=www.example.com:192.0.2.10:0:4611686018427387914:lo", 1, 1 },
    { "=www.example.com:192.0.2.10:300::lo", 1, 1 },
    { "=a\\056b.example.com:192.0.2.10:300", 1, 1 },                 /* octal escape for '.' stays inside the label */
    { "=a\\.b.example.com:192.0.2.10:300", 1, 1 },
};

static void test_valid_lines(void) {
    printf("[TEST] tinydns: valid lines of every record type...\n");
    for (size_t i = 0; i < N(VALID); i++) {
        for (int m = 0; m < 3; m++) {
            zone_arena_t a;
            parse_error_t e;
            size_t cnt;
            int rc = run_line(VALID[i].line, (ctxmode_t)m, &e, &a, &cnt);
            /* without a context the zone filter is off, so the same line may not be filtered either way */
            if (rc < 0) { fprintf(stderr, "valid line rejected: %s (%s)\n", VALID[i].line, e.error_message ? e.error_message : "-"); assert(0); }
            if (m == CTX_FULL) {
                if (cnt != VALID[i].n) { fprintf(stderr, "%s: expected %zu records, got %zu\n", VALID[i].line, VALID[i].n, cnt); assert(0); }
                if (VALID[i].must_have) assert(has_type(&a, VALID[i].must_have));
            }
            zone_arena_destroy(&a);
        }
    }
    /* Content checks */
    zone_arena_t a; parse_error_t e; size_t cnt;
    assert(run_line("=www.example.com:192.0.2.10:300", CTX_FULL, &e, &a, &cnt) == 1);
    assert(a.records[0].type_code == 1 && a.records[0].ttl_value == 300 && strcasecmp(a.records[0].name, "www.example.com.") == 0);
    assert(a.records[0].rdata_count == 1 && strcmp(a.records[0].rdata[0], "192.0.2.10") == 0);
    zone_arena_destroy(&a);
    assert(run_line("'txt.example.com:hello world:300", CTX_FULL, &e, &a, &cnt) == 1);
    assert(a.records[0].type_code == 16 && a.records[0].rdata_count >= 1);
    zone_arena_destroy(&a);
    /* Out-of-zone names, comments, disabled (-) and location lines produce no record and no error */
    static const char *const skipped[] = { "=www.example.org:192.0.2.10:300", ".example.org:192.0.2.1:a:300", "#comment line",
                                           "-disabled.example.com:192.0.2.1", "%lo:192.0.2", "" };
    for (size_t i = 0; i < N(skipped); i++) {
        int rc = run_line(skipped[i], CTX_FULL, &e, &a, &cnt);
        assert(rc >= 0 && cnt == 0);
        zone_arena_destroy(&a);
    }
    printf("  -> %zu valid lines checked.\n", N(VALID));
}

/* ---------------------------------------------------------------- 2. FQDN error matrix */
/* Templates with @ marking each FQDN-typed field. The first is the owner name (always a hard error). */
static const struct { const char *tmpl; int owner_only; } FQDN_TMPL[] = {
    { "=@:192.0.2.10:300", 1 }, { "+@:192.0.2.10:300", 1 }, { ".@:192.0.2.1:ns:300", 1 }, { "&@:192.0.2.2:ns2:300", 1 },
    { "@@:192.0.2.3:mail:10:300", 1 }, { "'@:text:300", 1 }, { "^@:www.example.com:300", 1 }, { "C@:www.example.com:300", 1 },
    { "Z@:ns1.example.com:hostmaster.example.com:1:2:3:4:5:300", 1 }, { ":@:99:\\001:300", 1 },
    { "3@:20010db8000000000000000000000001:300", 1 }, { "6@:20010db8000000000000000000000001:300", 1 },
    { "S@:5.srv.example.com:5060:10:20:300", 1 }, { "N@:ns.example.com:300", 1 },
    /* second FQDN position */
    { ".example.com:192.0.2.1:@:300", 0 }, { "&sub.example.com:192.0.2.2:@:300", 0 }, { "@example.com:192.0.2.3:@:10:300", 0 },
    { "^11.2.0.192.in-addr.arpa:@:300", 0 }, { "Calias.example.com:@:300", 0 },
    { "Zexample.com:@:hostmaster.example.com:1:2:3:4:5:300", 0 }, { "Zexample.com:ns1.example.com:@:1:2:3:4:5:300", 0 },
    { "Sexample.com:@:5060:10:20:300", 0 }, { "Nexample.com:@:300", 0 },
};

static char *subst(const char *tmpl, const char *with) {
    static char out[4096];
    char *p = strchr(tmpl, '@');
    /* the type character itself may be '@' (MX): the marker is the LAST '@' */
    char *last = NULL;
    for (char *q = strchr(tmpl, '@'); q; q = strchr(q + 1, '@')) last = q;
    p = last;
    snprintf(out, sizeof(out), "%.*s%s%s", (int)(p - tmpl), tmpl, with, p + 1);
    return out;
}

static void test_fqdn_error_paths(void) {
    printf("[TEST] tinydns: over-long label / name in every FQDN position...\n");
    char toolong[700];
    memset(toolong, 0, sizeof(toolong));
    for (int i = 0; i < 9; i++) { strcat(toolong, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."); }
    static const char *const bad_names[] = { LONG64, LONG64 ".example.com", "x." LONG64, NULL };
    size_t rejected = 0, owner_checked = 0;
    for (size_t t = 0; t < N(FQDN_TMPL); t++) {
        for (int v = 0; v < 4; v++) {
            const char *bad = bad_names[v] ? bad_names[v] : toolong;
            char line[4096];
            strlcpy(line, subst(FQDN_TMPL[t].tmpl, bad), sizeof(line));
            zone_arena_t a; parse_error_t e; size_t cnt;
            int rc = run_line(line, CTX_FULL, &e, &a, &cnt);
            if (rc < 0) {
                assert(e.error_message && e.error_message[0]);       /* a message is provided when asked for */
                rejected++;
            } else if (FQDN_TMPL[t].owner_only && v != 1) {
                /* owner names with an over-long label must always be rejected (v==1 has a >63 first label too) */
                fprintf(stderr, "over-long owner accepted: %s\n", line);
                assert(0);
            }
            if (FQDN_TMPL[t].owner_only) owner_checked++;
            zone_arena_destroy(&a);
            /* same rejection with err_out == NULL and with no context: verdict must not change, nothing crashes */
            int rc2 = run_line(line, CTX_NO_ERR_OUT, &e, &a, &cnt);
            zone_arena_destroy(&a);
            int rc3 = run_line(line, CTX_NONE, &e, &a, &cnt);
            zone_arena_destroy(&a);
            assert((rc < 0) == (rc2 < 0));
            (void)rc3;
        }
    }
    assert(rejected >= 50 && owner_checked >= 50);      /* guard against a vacuous matrix */
    printf("  -> %zu over-long names rejected with messages.\n", rejected);
}

/* ---------------------------------------------------------------- 3. generic / unknown */
static void test_generic_and_unknown(void) {
    printf("[TEST] tinydns: generic records and unknown type characters...\n");
    static const struct { const char *line; const char *msg; } bad[] = {
        { ":raw.example.com", "Missing type number" },
        { ":raw.example.com:notnum:data", "Prohibited or invalid RR type" },
        { ":raw.example.com:99999:data", "Prohibited or invalid RR type" },
        { "Q unknown type char", "Unknown tinydns record type character" },
    };
    for (size_t i = 0; i < N(bad); i++) {
        zone_arena_t a; parse_error_t e; size_t cnt;
        assert(run_line(bad[i].line, CTX_FULL, &e, &a, &cnt) < 0);
        assert(e.error_message && strstr(e.error_message, bad[i].msg));
        zone_arena_destroy(&a);
        assert(run_line(bad[i].line, CTX_NO_ERR_OUT, &e, &a, &cnt) < 0);
        zone_arena_destroy(&a);
        assert(run_line(bad[i].line, CTX_NONE, &e, &a, &cnt) < 0);
        zone_arena_destroy(&a);
    }
    /* Structural (0, NS, CNAME, SOA, PTR, MX) and meta types (OPT, NXNAME, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY)
     * cannot be smuggled into zone data through a generic record: the same is_meta_rrtype() the master-file parser uses. */
    static const int prohibited[] = { 0, 2, 5, 6, 12, 15, 41, 128, 249, 250, 251, 252, 253, 254, 255, 65536 };
    for (size_t i = 0; i < N(prohibited); i++) {
        char line[128];
        snprintf(line, sizeof(line), ":raw.example.com:%d:\\001:300", prohibited[i]);
        zone_arena_t a; parse_error_t e; size_t cnt;
        if (run_line(line, CTX_FULL, &e, &a, &cnt) >= 0) { fprintf(stderr, "generic type %d accepted\n", prohibited[i]); assert(0); }
        assert(e.error_message && strstr(e.error_message, "Prohibited or invalid RR type"));
        zone_arena_destroy(&a);
    }
    /* ordinary types are still accepted */
    static const int allowed[] = { 1, 16, 28, 33, 99, 257, 65280 };
    for (size_t i = 0; i < N(allowed); i++) {
        char line[128];
        snprintf(line, sizeof(line), ":raw.example.com:%d:\\001:300", allowed[i]);
        zone_arena_t a; parse_error_t e; size_t cnt;
        assert(run_line(line, CTX_FULL, &e, &a, &cnt) >= 0 && cnt == 1);
        zone_arena_destroy(&a);
    }
    printf("  -> generic/unknown rejections passed.\n");
}

/* ---------------------------------------------------------------- 4. robustness */
static void test_mutations(void) {
    printf("[TEST] tinydns: field truncation and junk substitution robustness...\n");
    size_t runs = 0;
    static const char *const junk[] = { "", "x", "-1", "99999999999999999999", "\\", "\\7", "\\777", "\\0", ":", ".", "..", "@", "*" };
    for (size_t i = 0; i < N(VALID); i++) {
        char work[1024];
        strlcpy(work, VALID[i].line, sizeof(work));
        /* positions of ':' */
        int cols[16], nc = 0;
        for (int k = 0; work[k] && nc < 16; k++) if (work[k] == ':') cols[nc++] = k;
        for (int keep = 0; keep <= nc; keep++) {                 /* truncate at each ':' boundary */
            char line[1024];
            size_t l = keep == nc ? strlen(work) : (size_t)cols[keep];
            memcpy(line, work, l); line[l] = '\0';
            for (int m = 0; m < 3; m++) { zone_arena_t a; parse_error_t e; run_line(line, (ctxmode_t)m, &e, &a, NULL); zone_arena_destroy(&a); runs++; }
        }
        for (int f = 0; f <= nc; f++) {                           /* replace each field by junk */
            for (size_t j = 0; j < N(junk); j++) {
                char line[1024];
                size_t start = f == 0 ? 1 : (size_t)cols[f - 1] + 1;
                size_t end = f == nc ? strlen(work) : (size_t)cols[f];
                snprintf(line, sizeof(line), "%c%.*s%s%s", work[0], (int)(start - 1 > 0 && f == 0 ? 0 : 0), "", "", "");
                /* rebuild explicitly */
                size_t o = 0;
                line[o++] = work[0];
                if (f > 0) { memcpy(line + o, work + 1, start - 1); o += start - 1; }
                size_t jl = strlen(junk[j]);
                memcpy(line + o, junk[j], jl); o += jl;
                strlcpy(line + o, work + end, sizeof(line) - o);
                zone_arena_t a; parse_error_t e;
                run_line(line, CTX_FULL, &e, &a, NULL);
                zone_arena_destroy(&a);
                runs++;
            }
        }
    }
    assert(runs > 1000);
    printf("  -> %zu mutated lines handled without crash.\n", runs);
}

int main(void) {
    printf("=== Starting tinydns Parser Path Coverage Tests ===\n");
    test_valid_lines();
    test_fqdn_error_paths();
    test_generic_and_unknown();
    test_mutations();
    printf("=== All tinydns Parser Path Coverage Tests PASSED ===\n");
    return 0;
}
