/*
 * test_xfr_opts.c - the transfer / NOTIFY options of BIND 9.20 (batch 4): notify-source, notify-source-v6, transfer-source,
 * transfer-source-v6, the `source` / `source-v6` of primaries and also-notify lists, min/max-refresh-time, min/max-retry-time,
 * max-transfer-{time,idle}-{in,out}, notify-delay, notify-to-soa, try-tcp-refresh, request-ixfr, provide-ixfr, request-expire,
 * multi-master, and the options-only transfers-in / transfers-out / transfers-per-ns / serial-query-rate / notify-rate /
 * startup-notify-rate.
 *
 * Expectations are worked out from the BIND 9.20 ARM (the grammar, defaults and ranges of "Zone Transfers" and "Boolean Options"),
 * bin/named/config.c (defaults), lib/isccfg/check.c (ranges: the four refresh / retry times must not be zero, max-transfer-* at most 28
 * days = 40320 minutes), lib/dns/zone.c (RANGE() and the clamp in zone_xfrdone(); the source of a request: the primaries list's source
 * unless it is `*`, then transfer-source) and lib/isccfg/namedconf.c (transfer-source takes an address or `*`, no port) by hand for each
 * case.  Addresses are documentation addresses (RFC 5737, RFC 3849).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../dns_config_parser.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode;
    (void)writable;
    return open(path, flags);
}

static int g_checks = 0;
static int g_failed = 0;

#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { g_failed++; printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

/* parse with stderr (the [ERROR] / [WARNING] lines) collected in err; returns whether the parse succeeded */
static bool parse_cap(const char *text, server_config_t *cfg, char *err, size_t errsz) {
    char path[] = "/tmp/karidns-xfropts-test.XXXXXX";
    int fd = mkstemp(path);
    int saved = dup(2);
    err[0] = '\0';
    memset(cfg, 0, sizeof(*cfg));
    if (fd < 0 || saved < 0) return parse_named_conf(text, cfg) == 0;
    fflush(stderr);
    dup2(fd, 2);
    bool ok = parse_named_conf(text, cfg) == 0;
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    lseek(fd, 0, SEEK_SET);
    ssize_t r = read(fd, err, errsz - 1);
    err[r > 0 ? r : 0] = '\0';
    close(fd);
    unlink(path);
    return ok;
}

static bool fails_with(const char *text, const char *frag) {
    server_config_t c;
    char err[2048];
    bool ok = parse_cap(text, &c, err, sizeof(err));
    if (ok) {
        free_server_config_fields(&c);
        printf("  [info] parse unexpectedly succeeded: %s\n", text);
        return false;
    }
    if (!strstr(err, frag)) {
        printf("  [info] message lacks '%s': %s\n", frag, err);
        return false;
    }
    return true;
}

static const zone_config_t *find_zone(const server_config_t *c, const char *name) { return config_find_zone_any_view(c, name); }

static bool src_is(const xfr_eff_t *e, int slot, const char *ip) {
    if (!ip) return !e->src[slot].set;
    uint8_t want[16] = {0};
    int fam = (slot == XSRC_NOTIFY6 || slot == XSRC_XFER6) ? AF_INET6 : AF_INET;
    if (inet_pton(fam, ip, want) != 1) return false;
    return e->src[slot].set && memcmp(e->src[slot].addr, want, fam == AF_INET ? 4 : 16) == 0;
}

static void test_defaults(void) {
    printf("[TEST] defaults (bin/named/config.c)...\n");
    xfr_eff_t e;
    xfr_opts_effective(NULL, NULL, NULL, &e);
    CHECK(e.min_refresh == 300 && e.max_refresh == 2419200 && e.min_retry == 500 && e.max_retry == 1209600);
    CHECK(e.xfer_time_in == 120 * 60 && e.xfer_idle_in == 60 * 60 && e.xfer_time_out == 120 * 60 && e.xfer_idle_out == 60 * 60);
    CHECK(e.notify_delay == 5);
    CHECK(!e.notify_to_soa && e.try_tcp_refresh && e.request_ixfr && e.provide_ixfr && e.request_expire && !e.multi_master);
    for (int s = 0; s < XSRC_N; s++) CHECK(!e.src[s].set);
    CHECK(xfr_cfg_limit(NULL, XL_TRANSFERS_IN) == 10 && xfr_cfg_limit(NULL, XL_TRANSFERS_OUT) == 10 && xfr_cfg_limit(NULL, XL_TRANSFERS_PER_NS) == 2);
    CHECK(xfr_cfg_limit(NULL, XL_SERIAL_QUERY_RATE) == 20 && xfr_cfg_limit(NULL, XL_NOTIFY_RATE) == 20 && xfr_cfg_limit(NULL, XL_STARTUP_NOTIFY_RATE) == 20);
    server_config_t c;
    char err[1024];
    CHECK(parse_cap("options { }; zone \"a.test\" { type slave; primaries { 192.0.2.1; }; };", &c, err, sizeof(err)));
    xfr_opts_effective(&c, find_zone(&c, "a.test."), "default", &e);
    CHECK(e.min_refresh == 300 && e.notify_delay == 5 && e.request_ixfr && !e.multi_master);
    free_server_config_fields(&c);
}

static void test_inheritance(void) {
    printf("[TEST] zone > view > options, option by option...\n");
    server_config_t c;
    char err[2048];
    const char *conf =
        "options { min-refresh-time 100; max-refresh-time 5000; min-retry-time 200; max-retry-time 3000; max-transfer-time-in 10;\n"
        "  max-transfer-idle-in 5; max-transfer-time-out 20; max-transfer-idle-out 6; notify-delay 7; notify-to-soa yes;\n"
        "  try-tcp-refresh no; request-ixfr no; provide-ixfr no; request-expire no; multi-master yes;\n"
        "  transfer-source 192.0.2.1; transfer-source-v6 2001:db8::1; notify-source 192.0.2.2; notify-source-v6 2001:db8::2; };\n"
        "view \"v1\" { match-clients { 127.0.0.1; }; min-refresh-time 111; request-ixfr yes; transfer-source 192.0.2.11;\n"
        "  zone \"z1.test\" { type slave; primaries { 192.0.2.99; }; max-refresh-time 9999; multi-master no; notify-source 192.0.2.22; };\n"
        "  zone \"z2.test\" { type slave; primaries { 192.0.2.99; }; transfer-source *; notify-source-v6 *; };\n"
        "  zone \"z3.test\" { type master; }; };\n"
        "view \"v2\" { match-clients { any; }; zone \"z4.test\" { type slave; primaries { 192.0.2.99; }; }; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    xfr_eff_t e;
    /* z1: its own max-refresh-time, multi-master and notify-source; the view's min-refresh-time, request-ixfr, transfer-source; options' rest */
    xfr_opts_effective(&c, find_zone(&c, "z1.test."), "v1", &e);
    CHECK(e.max_refresh == 9999 && e.min_refresh == 111 && e.min_retry == 200 && e.max_retry == 3000);
    CHECK(!e.multi_master && e.request_ixfr && !e.provide_ixfr && !e.request_expire && !e.try_tcp_refresh && e.notify_to_soa);
    CHECK(e.xfer_time_in == 600 && e.xfer_idle_in == 300 && e.xfer_time_out == 1200 && e.xfer_idle_out == 360 && e.notify_delay == 7);
    CHECK(src_is(&e, XSRC_NOTIFY4, "192.0.2.22") && src_is(&e, XSRC_NOTIFY6, "2001:db8::2"));
    CHECK(src_is(&e, XSRC_XFER4, "192.0.2.11") && src_is(&e, XSRC_XFER6, "2001:db8::1"));
    /* z2: `*` in the zone says "the system chooses" for that statement alone */
    xfr_opts_effective(&c, find_zone(&c, "z2.test."), "v1", &e);
    CHECK(src_is(&e, XSRC_XFER4, NULL) && src_is(&e, XSRC_NOTIFY6, NULL));
    CHECK(src_is(&e, XSRC_NOTIFY4, "192.0.2.2") && src_is(&e, XSRC_XFER6, "2001:db8::1"));
    CHECK(e.min_refresh == 111 && e.multi_master);
    /* z4 in view v2 (no statement of its own, none in the view): options' */
    xfr_opts_effective(&c, find_zone(&c, "z4.test."), "v2", &e);
    CHECK(e.min_refresh == 100 && e.request_ixfr == false && e.multi_master && src_is(&e, XSRC_XFER4, "192.0.2.1"));
    /* a view name that does not exist, or none: options' */
    xfr_opts_effective(&c, NULL, "nope", &e);
    CHECK(e.min_refresh == 100 && src_is(&e, XSRC_NOTIFY4, "192.0.2.2"));
    xfr_opts_effective(&c, NULL, NULL, &e);
    CHECK(e.min_refresh == 100);
    free_server_config_fields(&c);
}

static void test_sources_legacy_zone_notify_source(void) {
    printf("[TEST] the KariDNS zone statement notify-source (either family) keeps working, notify-source-v6 wins for IPv6...\n");
    server_config_t c;
    char err[2048];
    xfr_eff_t e;
    const char *conf =
        "zone \"a.test\" { type master; notify-source 192.0.2.5; };\n"
        "zone \"b.test\" { type master; notify-source 2001:db8::5; };\n"
        "zone \"c.test\" { type master; notify-source 2001:db8::5; notify-source-v6 2001:db8::6; };\n"
        "zone \"d.test\" { type master; notify-source-v6 2001:db8::6; notify-source 2001:db8::5; };\n"
        "zone \"e.test\" { type master; notify-source 192.0.2.5; notify-source 2001:db8::5; };\n"
        "zone \"f.test\" { type master; notify-source *; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    CHECK(strstr(err, "WARNING") == NULL);                       /* no warning for the old statement */
    xfr_opts_effective(&c, find_zone(&c, "a.test."), NULL, &e);
    CHECK(src_is(&e, XSRC_NOTIFY4, "192.0.2.5") && src_is(&e, XSRC_NOTIFY6, NULL));
    CHECK(zext(find_zone(&c, "a.test."))->notify_source && strcmp(zext(find_zone(&c, "a.test."))->notify_source, "192.0.2.5") == 0);
    xfr_opts_effective(&c, find_zone(&c, "b.test."), NULL, &e);
    CHECK(src_is(&e, XSRC_NOTIFY4, NULL) && src_is(&e, XSRC_NOTIFY6, "2001:db8::5"));
    xfr_opts_effective(&c, find_zone(&c, "c.test."), NULL, &e);
    CHECK(src_is(&e, XSRC_NOTIFY6, "2001:db8::6"));
    xfr_opts_effective(&c, find_zone(&c, "d.test."), NULL, &e);
    CHECK(src_is(&e, XSRC_NOTIFY6, "2001:db8::6") && src_is(&e, XSRC_NOTIFY4, NULL));
    /* a later statement replaces the earlier one, as it always did: the IPv4 address is gone */
    xfr_opts_effective(&c, find_zone(&c, "e.test."), NULL, &e);
    CHECK(src_is(&e, XSRC_NOTIFY4, NULL) && src_is(&e, XSRC_NOTIFY6, "2001:db8::5"));
    xfr_opts_effective(&c, find_zone(&c, "f.test."), NULL, &e);
    CHECK(src_is(&e, XSRC_NOTIFY4, NULL) && src_is(&e, XSRC_NOTIFY6, NULL));
    free_server_config_fields(&c);
}

static void test_list_sources(void) {
    printf("[TEST] source / source-v6 of primaries and also-notify lists...\n");
    server_config_t c;
    char err[2048];
    const char *conf =
        "options { transfer-source 192.0.2.1; transfer-source-v6 2001:db8::1; notify-source 192.0.2.2; };\n"
        "primaries inner source 192.0.2.30 { 192.0.2.40; 2001:db8::40; };\n"
        "primaries outer port 5353 source 192.0.2.31 source-v6 2001:db8::31 { inner; 192.0.2.41; 2001:db8::41 key k; };\n"
        "primaries starred source * { 192.0.2.50; };\n"
        "key \"k\" { algorithm hmac-sha256; secret \"c2VjcmV0LW9uZS1mb3ItdGVzdA==\"; };\n"
        "zone \"a.test\" { type slave; primaries { outer; starred; 192.0.2.60; }; also-notify source 192.0.2.70 source-v6 2001:db8::70 { 192.0.2.80; 2001:db8::80; }; };\n"
        "zone \"b.test\" { type slave; primaries source 192.0.2.32 { 192.0.2.61 port 5354; }; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    const zone_ext_t *x = zext(find_zone(&c, "a.test."));
    CHECK(x->masters_count == 6);
    /* inner's addresses keep inner's source (BIND getipandkeylist(): the list the address is written in); outer's own addresses outer's;
     * the `*` list and the bare address have none, so transfer-source applies */
    xfr_eff_t e;
    xfr_opts_effective(&c, find_zone(&c, "a.test."), NULL, &e);
    uint8_t out[16], want[16];
    CHECK(x->masters[0].ip && strcmp(x->masters[0].ip, "192.0.2.40") == 0);
    CHECK(xfr_source_for(&e, &x->masters[0], AF_INET, true, out));
    inet_pton(AF_INET, "192.0.2.30", want);
    CHECK(memcmp(out, want, 4) == 0);
    CHECK(strcmp(x->masters[1].ip, "2001:db8::40") == 0);                                   /* inner has no source-v6: transfer-source-v6 */
    CHECK(xfr_source_for(&e, &x->masters[1], AF_INET6, true, out));
    inet_pton(AF_INET6, "2001:db8::1", want);
    CHECK(memcmp(out, want, 16) == 0);
    CHECK(strcmp(x->masters[2].ip, "192.0.2.41") == 0 && xfr_source_for(&e, &x->masters[2], AF_INET, true, out));
    inet_pton(AF_INET, "192.0.2.31", want);
    CHECK(memcmp(out, want, 4) == 0);
    CHECK(strcmp(x->masters[3].ip, "2001:db8::41") == 0 && x->masters[3].key && strcmp(x->masters[3].key, "k") == 0);
    CHECK(xfr_source_for(&e, &x->masters[3], AF_INET6, true, out));
    inet_pton(AF_INET6, "2001:db8::31", want);
    CHECK(memcmp(out, want, 16) == 0);
    CHECK(strcmp(x->masters[4].ip, "192.0.2.50") == 0 && xfr_source_for(&e, &x->masters[4], AF_INET, true, out));   /* `source *`: transfer-source */
    inet_pton(AF_INET, "192.0.2.1", want);
    CHECK(memcmp(out, want, 4) == 0);
    CHECK(strcmp(x->masters[5].ip, "192.0.2.60") == 0 && xfr_source_for(&e, &x->masters[5], AF_INET, true, out) && memcmp(out, want, 4) == 0);
    /* NOTIFY: the list's source, else notify-source; the IPv6 target has no notify-source-v6 at all */
    CHECK(x->also_notify_count == 2);
    CHECK(xfr_source_for(&e, &x->also_notify[0], AF_INET, false, out));
    inet_pton(AF_INET, "192.0.2.70", want);
    CHECK(memcmp(out, want, 4) == 0);
    CHECK(xfr_source_for(&e, &x->also_notify[1], AF_INET6, false, out));
    inet_pton(AF_INET6, "2001:db8::70", want);
    CHECK(memcmp(out, want, 16) == 0);
    CHECK(xfr_source_for(&e, NULL, AF_INET, false, out));
    inet_pton(AF_INET, "192.0.2.2", want);
    CHECK(memcmp(out, want, 4) == 0);
    CHECK(!xfr_source_for(&e, NULL, AF_INET6, false, out));
    /* b.test: a primaries statement inside the zone */
    const zone_ext_t *xb = zext(find_zone(&c, "b.test."));
    CHECK(xb->masters_count == 1 && xb->masters[0].port == 5354);
    xfr_opts_effective(&c, find_zone(&c, "b.test."), NULL, &e);
    CHECK(xfr_source_for(&e, &xb->masters[0], AF_INET, true, out));
    inet_pton(AF_INET, "192.0.2.32", want);
    CHECK(memcmp(out, want, 4) == 0);
    free_server_config_fields(&c);
}

static void test_errors(void) {
    printf("[TEST] errors with the place in the file...\n");
    CHECK(fails_with("options { transfer-source 192.0.2.1 port 5353; };", "takes no port"));
    CHECK(fails_with("options { notify-source 2001:db8::1; };", "use the -v6 form"));
    CHECK(fails_with("options { notify-source-v6 192.0.2.1; };", "use the form without -v6"));
    CHECK(fails_with("options { transfer-source example.test; };", "is not an IPv4 address or '*'"));
    CHECK(fails_with("options { transfer-source ; };", "expected an IPv4 address or '*'"));
    CHECK(fails_with("options { transfer-source 192.0.2.1 };", "expected ';'"));
    CHECK(fails_with("view \"v\" { transfer-source-v6 192.0.2.1; };", "view 'v' transfer-source-v6"));
    CHECK(fails_with("zone \"a.test\" { type slave; transfer-source 2001:db8::1; };", "zone 'a.test.' transfer-source"));
    CHECK(fails_with("primaries p source 192.0.2.1 source 192.0.2.2 { 192.0.2.3; };", "given twice"));
    CHECK(fails_with("primaries p source 2001:db8::1 { 192.0.2.3; };", "not an IPv4 address or '*'"));
    CHECK(fails_with("primaries p source-v6 192.0.2.1 { 192.0.2.3; };", "not an IPv6 address or '*'"));
    CHECK(fails_with("zone \"a.test\" { type slave; also-notify source { 192.0.2.3; }; };", "expected an IPv4 address or '*'"));
    CHECK(fails_with("options { min-refresh-time 0; };", "must not be zero"));
    CHECK(fails_with("options { max-refresh-time 0; };", "must not be zero"));
    CHECK(fails_with("options { min-retry-time 0; };", "must not be zero"));
    CHECK(fails_with("options { max-retry-time 0; };", "must not be zero"));
    CHECK(fails_with("options { min-refresh-time 4294967296; };", "invalid min-refresh-time value"));
    CHECK(fails_with("options { min-refresh-time -1; };", "invalid min-refresh-time value"));
    CHECK(fails_with("options { min-refresh-time 5m; };", "invalid min-refresh-time value"));
    CHECK(fails_with("options { max-transfer-time-in 40321; };", "0..40320 minutes"));
    CHECK(fails_with("view \"v\" { max-transfer-idle-out 40321; };", "0..40320 minutes"));
    CHECK(fails_with("zone \"a.test\" { max-transfer-time-out abc; };", "invalid max-transfer-time-out value"));
    CHECK(fails_with("options { notify-delay -5; };", "invalid notify-delay value"));
    CHECK(fails_with("options { multi-master maybe; };", "expected yes or no"));
    CHECK(fails_with("options { request-ixfr; };", "expected a value after"));
    CHECK(fails_with("options { transfers-in -1; };", "invalid value"));
    CHECK(fails_with("options { transfers-out 4294967296; };", "invalid value"));
    CHECK(fails_with("options { notify-rate fast; };", "invalid value"));
    CHECK(fails_with("options { serial-query-rate 20 };", "expected ';'"));
    server_config_t c;
    char err[2048];
    /* in range: the extremes */
    CHECK(parse_cap("options { min-refresh-time 1; max-refresh-time 4294967295; max-transfer-time-in 0; max-transfer-idle-out 40320; notify-delay 0; "
                    "transfers-in 0; transfers-out 4294967295; };", &c, err, sizeof(err)));
    free_server_config_fields(&c);
    /* try-tcp-refresh no is accepted with a warning: the secondary side checks over TCP only */
    CHECK(parse_cap("options { try-tcp-refresh no; };", &c, err, sizeof(err)));
    CHECK(strstr(err, "try-tcp-refresh") != NULL && strstr(err, "WARNING") != NULL);
    free_server_config_fields(&c);
    CHECK(parse_cap("options { try-tcp-refresh yes; };", &c, err, sizeof(err)));
    CHECK(strstr(err, "WARNING") == NULL);
    free_server_config_fields(&c);
    /* the error message carries the place */
    CHECK(fails_with("options {\n  transfer-source 192.0.2.1 port 1;\n};", "line 2"));
}

static void test_options_only_limits(void) {
    printf("[TEST] transfers-in / transfers-out / transfers-per-ns / the rates...\n");
    server_config_t c;
    char err[2048];
    CHECK(parse_cap("options { transfers-in 3; transfers-out 4; transfers-per-ns 5; serial-query-rate 6; notify-rate 7; startup-notify-rate 8; };",
                    &c, err, sizeof(err)));
    CHECK(xfr_cfg_limit(&c, XL_TRANSFERS_IN) == 3 && xfr_cfg_limit(&c, XL_TRANSFERS_OUT) == 4 && xfr_cfg_limit(&c, XL_TRANSFERS_PER_NS) == 5);
    CHECK(xfr_cfg_limit(&c, XL_SERIAL_QUERY_RATE) == 6 && xfr_cfg_limit(&c, XL_NOTIFY_RATE) == 7 && xfr_cfg_limit(&c, XL_STARTUP_NOTIFY_RATE) == 8);
    free_server_config_fields(&c);
    /* a limit may be 0 (transfers-out 0 refuses every transfer); a rate of 0 is silently raised to 1 (ARM) */
    CHECK(parse_cap("options { transfers-in 0; transfers-out 0; transfers-per-ns 0; serial-query-rate 0; notify-rate 0; startup-notify-rate 0; };",
                    &c, err, sizeof(err)));
    CHECK(xfr_cfg_limit(&c, XL_TRANSFERS_IN) == 0 && xfr_cfg_limit(&c, XL_TRANSFERS_OUT) == 0 && xfr_cfg_limit(&c, XL_TRANSFERS_PER_NS) == 0);
    CHECK(xfr_cfg_limit(&c, XL_SERIAL_QUERY_RATE) == 1 && xfr_cfg_limit(&c, XL_NOTIFY_RATE) == 1 && xfr_cfg_limit(&c, XL_STARTUP_NOTIFY_RATE) == 1);
    free_server_config_fields(&c);
    CHECK(xfr_rate_clamp(0) == 1 && xfr_rate_clamp(1) == 1 && xfr_rate_clamp(4294967295u) == 4294967295u);
}

static void test_timer_clamp(void) {
    printf("[TEST] RANGE() and the timers a zone uses after a transfer (zone.c zone_xfrdone())...\n");
    CHECK(xfr_range(5, 10, 20) == 10);      /* below the minimum */
    CHECK(xfr_range(10, 10, 20) == 10);
    CHECK(xfr_range(15, 10, 20) == 15);
    CHECK(xfr_range(20, 10, 20) == 20);     /* a < hi is false: hi */
    CHECK(xfr_range(25, 10, 20) == 20);
    CHECK(xfr_range(5, 20, 10) == 20 && xfr_range(15, 20, 10) == 20 && xfr_range(25, 20, 10) == 10);   /* min > max: BIND's RANGE() as written */
    xfr_eff_t e;
    xfr_opts_effective(NULL, NULL, NULL, &e);       /* 300 / 2419200 / 500 / 1209600 */
    uint32_t r, t, x;
    xfr_clamp_timers(&e, 3600, 600, 1209600, &r, &t, &x);          /* the usual SOA: nothing changes */
    CHECK(r == 3600 && t == 600 && x == 1209600);
    xfr_clamp_timers(&e, 2, 3, 4, &r, &t, &x);                      /* a SOA of 2 / 3 / 4 seconds: refresh 300, retry 500, expire refresh + retry */
    CHECK(r == 300 && t == 500 && x == 800);
    xfr_clamp_timers(&e, 99999999, 99999999, 99999999, &r, &t, &x);
    CHECK(r == 2419200 && t == 1209600 && x == 14515200);           /* expire at most 24 weeks */
    xfr_clamp_timers(&e, 3600, 600, 3600, &r, &t, &x);              /* expire below refresh + retry is raised to it */
    CHECK(x == 4200);
    xfr_clamp_timers(&e, 3600, 600, 600, NULL, NULL, &x);
    CHECK(x == 4200);
    xfr_clamp_timers(&e, 3600, 600, 1000, &r, NULL, NULL);
    CHECK(r == 3600);
    xfr_clamp_timers(&e, 0, 0, 0, &r, &t, &x);                      /* a SOA of zeros */
    CHECK(r == 300 && t == 500 && x == 800);
    server_config_t c;
    char err[1024];
    CHECK(parse_cap("options { min-refresh-time 1; min-retry-time 1; max-refresh-time 4294967295; max-retry-time 4294967295; };", &c, err, sizeof(err)));
    xfr_opts_effective(&c, NULL, NULL, &e);
    xfr_clamp_timers(&e, 2, 3, 1, &r, &t, &x);                      /* short values pass (the tests use them) */
    CHECK(r == 2 && t == 3 && x == 5);
    xfr_clamp_timers(&e, 4294967295u, 4294967295u, 4294967295u, &r, &t, &x);   /* r + t does not wrap */
    CHECK(r == 4294967295u && t == 4294967295u && x == 14515200);
    free_server_config_fields(&c);
}

static void test_minutes(void) {
    printf("[TEST] minutes of max-transfer-*, and the test hook...\n");
    unsetenv("KARIDNS_XFER_MINUTE_SECS");
    CHECK(xfr_minutes_to_secs(0) == 0 && xfr_minutes_to_secs(1) == 60 && xfr_minutes_to_secs(40320) == 2419200);
    setenv("KARIDNS_XFER_MINUTE_SECS", "2", 1);
    CHECK(xfr_minutes_to_secs(5) == 10);
    setenv("KARIDNS_XFER_MINUTE_SECS", "0", 1);
    CHECK(xfr_minutes_to_secs(1) == 60);        /* out of 1..60: ignored */
    setenv("KARIDNS_XFER_MINUTE_SECS", "x", 1);
    CHECK(xfr_minutes_to_secs(1) == 60);
    unsetenv("KARIDNS_XFER_MINUTE_SECS");
    server_config_t c;
    char err[1024];
    xfr_eff_t e;
    CHECK(parse_cap("options { max-transfer-time-in 3; max-transfer-idle-in 1; };", &c, err, sizeof(err)));
    setenv("KARIDNS_XFER_MINUTE_SECS", "1", 1);
    xfr_opts_effective(&c, NULL, NULL, &e);
    CHECK(e.xfer_time_in == 3 && e.xfer_idle_in == 1 && e.xfer_time_out == 120);
    unsetenv("KARIDNS_XFER_MINUTE_SECS");
    free_server_config_fields(&c);
}

static void test_source_registry(void) {
    printf("[TEST] the distinct source addresses of a configuration and the start-up set...\n");
    server_config_t c;
    char err[2048];
    const char *conf =
        "options { notify-source 192.0.2.1;\n"
        "  transfer-source 192.0.2.1; };\n"
        "primaries p source 192.0.2.3 { 192.0.2.9; };\n"
        "view \"v\" { notify-source-v6 2001:db8::1;\n"
        "  zone \"a.test\" { type slave; primaries { p; }; transfer-source-v6 2001:db8::2; also-notify source 192.0.2.4 { 192.0.2.8; }; };\n"
        "  zone \"b.test\" { type slave; primaries source 192.0.2.3 { 192.0.2.7; }; notify-source *; transfer-source 192.0.2.5; }; };\n";
    CHECK(parse_cap(conf, &c, err, sizeof(err)));
    CHECK(c.xfr_source_count == 6);
    int found = 0;
    for (int i = 0; i < c.xfr_source_count; i++) {
        const xfr_source_t *s = &c.xfr_sources[i];
        if (strcmp(s->text, "192.0.2.1") == 0) { found++; CHECK(s->notify && s->xfer && strstr(s->loc, "line 1") && strcmp(s->what, "notify-source") == 0); }
        if (strcmp(s->text, "192.0.2.3") == 0) { found++; CHECK(!s->notify && s->xfer && strstr(s->loc, "line 3") && strstr(s->what, "primaries source")); }   /* written twice: one entry */
        if (strcmp(s->text, "2001:db8::1") == 0) { found++; CHECK(s->notify && !s->xfer && s->family == AF_INET6 && strstr(s->loc, "line 4")); }
        if (strcmp(s->text, "2001:db8::2") == 0) { found++; CHECK(!s->notify && s->xfer); }
        if (strcmp(s->text, "192.0.2.4") == 0) { found++; CHECK(s->notify && !s->xfer && strstr(s->what, "also-notify source")); }
        if (strcmp(s->text, "192.0.2.5") == 0) { found++; CHECK(!s->notify && s->xfer); }
    }
    CHECK(found == 6);
    /* before the server has recorded its start-up set nothing is allowed; after, exactly what was there, for the use it had */
    uint8_t a1[4], a2[16], a3[4];
    inet_pton(AF_INET, "192.0.2.1", a1);
    inet_pton(AF_INET6, "2001:db8::1", a2);
    inet_pton(AF_INET, "192.0.2.5", a3);
    CHECK(!config_xfr_source_allowed(AF_INET, a1, true));
    config_set_startup_xfr_sources(&c);
    uint8_t p1[16] = {0}, p2[16] = {0}, p3[16] = {0};
    memcpy(p1, a1, 4);
    memcpy(p2, a2, 16);
    memcpy(p3, a3, 4);
    CHECK(config_xfr_source_allowed(AF_INET, p1, true) && config_xfr_source_allowed(AF_INET, p1, false));
    CHECK(config_xfr_source_allowed(AF_INET6, p2, false) && !config_xfr_source_allowed(AF_INET6, p2, true));
    CHECK(config_xfr_source_allowed(AF_INET, p3, true) && !config_xfr_source_allowed(AF_INET, p3, false));
    uint8_t other[16] = {192, 0, 2, 99};
    CHECK(!config_xfr_source_allowed(AF_INET, other, true));
    free_server_config_fields(&c);
    config_set_startup_xfr_sources(NULL);
    CHECK(!config_xfr_source_allowed(AF_INET, p1, true));
    /* too many distinct addresses */
    char big[16 * 1024];
    size_t off = (size_t)snprintf(big, sizeof(big), "options { };\n");
    for (int i = 0; i < KARIDNS_XFR_SOURCES_MAX + 1; i++)
        off += (size_t)snprintf(big + off, sizeof(big) - off, "zone \"z%d.test\" { type slave; transfer-source 198.51.%d.%d; };\n", i, i / 200, 1 + i % 200);
    CHECK(fails_with(big, "more than 128 distinct source addresses"));
}

static void test_clone_keeps_options(void) {
    printf("[TEST] the zone copy with received settings keeps the zone's own options...\n");
    server_config_t c;
    char err[1024];
    CHECK(parse_cap("zone \"a.test\" { type slave; primaries { 192.0.2.1; }; min-refresh-time 77; transfer-source 192.0.2.9; };", &c, err, sizeof(err)));
    const zone_config_t *base = find_zone(&c, "a.test.");
    char note[256];
    zone_config_t *copy = zone_config_with_received("a.test.", base, NULL, &c, note, sizeof(note));
    CHECK(copy != NULL);
    if (copy) {
        xfr_eff_t e;
        xfr_opts_effective(&c, copy, NULL, &e);
        CHECK(e.min_refresh == 77 && src_is(&e, XSRC_XFER4, "192.0.2.9"));
        free_zone_config(copy);
    }
    free_server_config_fields(&c);
}

int main(void) {
    test_defaults();
    test_inheritance();
    test_sources_legacy_zone_notify_source();
    test_list_sources();
    test_errors();
    test_options_only_limits();
    test_timer_clamp();
    test_minutes();
    test_source_registry();
    test_clone_keeps_options();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed) {
        printf("test_xfr_opts: FAILED\n");
        return 1;
    }
    printf("test_xfr_opts: all passed\n");
    return 0;
}
