/*
 * test_xfr_store.c - the secondaries' copies in the zone store (0.7; planing_0.7.x_secondary_store.md section 13, unit part).
 *
 *  1. dns_xfr_state.c alone: the state (every field, version and garbage refused), the key (the root, 245 / 246 octets, the case of the view name, a forced tag
 *     collision whose identities differ, the view order), identity against the primaries digest (a primaries change keeps, a unique-id change does not, an owner
 *     change with the same unique-id keeps), the clock moved back and forward (clamped in memory, the state untouched), D7, the up-to-date rule (M2), the skip of a
 *     failure write, next_check after a restore, the EXPIRE option of 0
 *  2. "lifetimes" of a server in child processes on one store (the store and the restore thread are process wide; each child is a start, the next one a restart):
 *     the writes at the end of a refresh (transferred, up to date: state only or the whole image, failed and its skip, a scrub's KNOWN record stored again), the restore
 *     decisions (restored, no record, KNOWN, a bad checksum, a serial mismatch, another identity, D7 both ways, expired while stopped, a recent failure), the orphan
 *     re-check of a member whose unique-id changed during its transfer (M6), the GC with the per-view exemption of a catalog's members, a name too long, 32 views full,
 *     a store that cannot be opened (no pending bit, a reconfiguration's secondary is not held), the 30 s safety net (progress against a stall, R2'), and under TSan
 *     the restore against a concurrent transfer and the hooks of rebuilds from several threads.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../dns_config_parser.h"
#include "../dns_db_store.h"
#include "../dns_epoch_rcu.h"
#include "../dns_server_internal.h"
#include "../dns_snapshot_rcu.h"
#include "../dns_store.h"
#include "../dns_utils.h"
#include "../dns_xfr_state.h"
#include "../dns_xfr_store.h"
#include "../dns_zone_image.h"
#include "../dns_zone_parser.h"
#include "db/zimg_msgs.h"

#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if defined(__SANITIZE_THREAD__) || __has_feature(thread_sanitizer)
/* the snapshot rebuilds start the server's GC thread, which a child that ends with _exit() does not join: not a report of this test */
const char *__tsan_default_options(void);
const char *__tsan_default_options(void) { return "report_thread_leaks=0"; }
#endif

static int g_checks = 0, g_failed = 0;
#define CHECK(cond) do { g_checks++; if (!(cond)) { g_failed++; printf("  [FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); fflush(stdout); } } while (0)
#define CHECK_EQ(a, b) do { long long a_ = (long long)(a), b_ = (long long)(b); g_checks++; if (a_ != b_) { g_failed++; \
    printf("  [FAIL] %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, a_, b_); fflush(stdout); } } while (0)

/* ======================================================================================================================= 1. the pure part */

static void test_state(void) {
  printf("[the state: encode / decode, refused garbage]\n");
  xfr_state_t s = { .kind = XFR_K_MEMBER, .flags = XFR_SF_FAILED | XFR_SF_EXPIRE_OPT | XFR_SF_FROM_FILE | XFR_SF_RX_LOST, .primaries = 0xA1B2C3D4u,
                    .identity = 0x0102030405060708ull, .last_ok = 4000000000u, .expire_delta = 14515200u, .last_attempt = 4000000100u, .rx_settings = 77 };
  uint8_t b[XFR_STATE_LEN];
  xfr_state_encode(&s, b);
  CHECK_EQ(b[0], XFR_STATE_VERSION);
  CHECK_EQ(b[3], 0);
  CHECK(b[8] == 0x08 && b[15] == 0x01);                                   /* (little endian) */
  xfr_state_t d;
  CHECK_EQ(xfr_state_decode(b, sizeof(b), &d), 0);
  CHECK(d.kind == s.kind && d.flags == s.flags && d.primaries == s.primaries && d.identity == s.identity && d.last_ok == s.last_ok && d.expire_delta == s.expire_delta &&
        d.last_attempt == s.last_attempt && d.rx_settings == s.rx_settings);
  uint8_t g[XFR_STATE_LEN];
  memcpy(g, b, sizeof(g)); g[0] = 1;                                     /* version 1 */
  CHECK_EQ(xfr_state_decode(g, sizeof(g), &d), -1);
  memcpy(g, b, sizeof(g)); g[1] = 0;
  CHECK_EQ(xfr_state_decode(g, sizeof(g), &d), -1);
  memcpy(g, b, sizeof(g)); g[1] = 6;
  CHECK_EQ(xfr_state_decode(g, sizeof(g), &d), -1);
  memcpy(g, b, sizeof(g)); g[2] = 0x10;
  CHECK_EQ(xfr_state_decode(g, sizeof(g), &d), -1);
  memcpy(g, b, sizeof(g)); g[3] = 1;
  CHECK_EQ(xfr_state_decode(g, sizeof(g), &d), -1);
  memcpy(g, b, sizeof(g)); memset(g + 16, 0, 4);                         /* no successful refresh */
  CHECK_EQ(xfr_state_decode(g, sizeof(g), &d), -1);
  CHECK_EQ(xfr_state_decode(b, 31, &d), -1);
  CHECK_EQ(xfr_state_decode(NULL, 32, &d), -1);
  memset(g, 0, sizeof(g));                                                /* (a digest of zeros: a record of the database, not a copy) */
  CHECK_EQ(xfr_state_decode(g, sizeof(g), &d), -1);
}

static uint64_t vmix(uint64_t x) {
  x += 0x9e3779b97f4a7c15ull;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
  return x ^ (x >> 31);
}
static int u64_cmp(const void *a, const void *b) {
  const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return x < y ? -1 : x > y;
}
/* two view names of one CRC-32C (found by a search, the birthday bound of 32 bits) */
static bool find_collision(char *va, char *vb, size_t cap) {
  enum { NV = 1 << 19 };
  uint64_t *tags = malloc(NV * sizeof(uint64_t));                         /* (tag << 32 | index, sorted: equal neighbours are a collision) */
  int ca = -1, cb = -1;
  for (int i = 0; tags && i < NV; i++) {
    char v[32];
    snprintf(v, sizeof(v), "v%016llx", (unsigned long long)vmix((uint64_t)i));
    tags[i] = (uint64_t)xfr_view_tag(v) << 32 | (uint32_t)i;
  }
  if (tags) qsort(tags, NV, sizeof(uint64_t), u64_cmp);
  for (int i = 1; tags && i < NV && ca < 0; i++)
    if (tags[i] >> 32 == tags[i - 1] >> 32) { ca = (int)(uint32_t)tags[i - 1]; cb = (int)(uint32_t)tags[i]; }
  free(tags);
  if (ca < 0) return false;
  snprintf(va, cap, "v%016llx", (unsigned long long)vmix((uint64_t)ca));
  snprintf(vb, cap, "v%016llx", (unsigned long long)vmix((uint64_t)cb));
  return true;
}

static void test_key(void) {
  printf("[the key: the root, 245 / 246 octets, the case of the view, a forced tag collision, the view order]\n");
  char k[XFR_KEY_MAX + 1], z[STORE_NAME_MAX + 2];
  int n = xfr_key_make("internal", XFR_K_CONFIG, ".", k, sizeof(k));
  CHECK_EQ(n, 9);
  uint32_t tag = 0;
  char kc = 0;
  CHECK_EQ(xfr_key_parse(k, (size_t)n, &tag, &kc, z, sizeof(z)), 0);
  CHECK(tag == xfr_view_tag("internal") && kc == 'c' && strcmp(z, ".") == 0);
  n = xfr_key_make("Internal", XFR_K_DB_SLAVE, "WWW.Example.TEST.", k, sizeof(k));
  CHECK(n > 0 && k[8] == 'd' && strcmp(k + 9, ".www.example.test") == 0);
  CHECK_EQ(xfr_view_tag("Internal"), xfr_view_tag("INTERNAL"));
  CHECK_EQ(xfr_key_parse(k, (size_t)n, &tag, &kc, z, sizeof(z)), 0);
  CHECK(strcmp(z, "www.example.test.") == 0 && kc == 'd');
  /* 245 octets fit, 246 do not (W12) */
  char nm[300];
  memset(nm, 'a', 245);
  nm[245] = '.';
  nm[246] = '\0';
  for (int i = 63; i < 245; i += 64) nm[i] = '.';
  CHECK(xfr_key_make("v", XFR_K_CONFIG, nm, k, sizeof(k)) == 255);
  memset(nm, 'b', 246);
  nm[246] = '.';
  nm[247] = '\0';
  for (int i = 63; i < 246; i += 64) nm[i] = '.';
  CHECK_EQ(xfr_key_make("v", XFR_K_CONFIG, nm, k, sizeof(k)), -1);
  CHECK_EQ(xfr_key_make("v", XFR_K_CONFIG, "a.test.", k, 5), -1);
  /* garbage keys */
  CHECK_EQ(xfr_key_parse("0123456", 7, &tag, &kc, z, sizeof(z)), -1);
  CHECK_EQ(xfr_key_parse("0123456xc.a", 11, &tag, &kc, z, sizeof(z)), -1);
  CHECK_EQ(xfr_key_parse("01234567q.a", 11, &tag, &kc, z, sizeof(z)), -1);
  CHECK_EQ(xfr_key_parse("01234567c-a", 11, &tag, &kc, z, sizeof(z)), -1);
  CHECK_EQ(xfr_key_parse("01234567c.", 10, &tag, &kc, z, sizeof(z)), -1);
  CHECK_EQ(xfr_key_parse("01234567c.abc", 13, &tag, &kc, z, 3), -1);
  /* a forced tag collision: two view names of one CRC-32C give one key and two identities */
  char va[32], vb[32];
  if (find_collision(va, vb, sizeof(va))) {
    char ka[XFR_KEY_MAX + 1], kb[XFR_KEY_MAX + 1];
    CHECK(xfr_key_make(va, XFR_K_CONFIG, "z.test.", ka, sizeof(ka)) > 0 && xfr_key_make(vb, XFR_K_CONFIG, "z.test.", kb, sizeof(kb)) > 0 && strcmp(ka, kb) == 0);
    CHECK(xfr_identity(XFR_K_CONFIG, "z.test.", va, NULL, 0) != xfr_identity(XFR_K_CONFIG, "z.test.", vb, NULL, 0));
    printf("  tag collision: '%s' and '%s' (tag %08x): one key, two identities\n", va, vb, xfr_view_tag(va));
  } else {
    printf("  (no tag collision found in the search; the case is left out)\n");
  }
  /* the view order does not change a key: it is a function of the view's name alone */
  char k1[XFR_KEY_MAX + 1], k2[XFR_KEY_MAX + 1];
  xfr_key_make("alpha", XFR_K_CONFIG, "z.test.", k1, sizeof(k1));
  xfr_key_make("beta", XFR_K_CONFIG, "z.test.", k2, sizeof(k2));
  xfr_key_make("alpha", XFR_K_CONFIG, "z.test.", k, sizeof(k));
  CHECK(strcmp(k1, k) == 0 && strcmp(k1, k2) != 0);
}

static void test_identity(void) {
  printf("[identity against the primaries digest (M5, RFC 9432)]\n");
  const uint64_t a = xfr_identity(XFR_K_MEMBER, "m.test.", "v", "u1", 0);
  CHECK_EQ(a, xfr_identity(XFR_K_MEMBER, "M.TEST", "V", "u1", 0));              /* (name and view fold; the trailing dot does not matter) */
  CHECK(a != xfr_identity(XFR_K_MEMBER, "m.test.", "v", "u2", 0));               /* a new unique-id (§5.4): another zone */
  CHECK(a != xfr_identity(XFR_K_CONFIG, "m.test.", "v", "u1", 0));               /* another kind */
  CHECK(a != xfr_identity(XFR_K_MEMBER, "m.test.", "w", "u1", 0));
  CHECK_EQ(xfr_identity(XFR_K_CONFIG, "m.test.", "v", "x", 0), xfr_identity(XFR_K_CONFIG, "m.test.", "v", "y", 0));   /* (the unique-id is a member's only) */
  CHECK(xfr_identity(XFR_K_DB_SLAVE, "m.test.", "v", NULL, 7) != xfr_identity(XFR_K_DB_SLAVE, "m.test.", "v", NULL, 8));
  /* the owner is not in the identity: a change of ownership with the same unique-id keeps the copy (§5.5); the primaries are not either: a change refreshes, never deletes */
  const uint32_t p1 = xfr_primaries_add(xfr_primaries_add(0, "192.0.2.1", 53, "k1"), "", 0, NULL);
  const uint32_t p2 = xfr_primaries_add(xfr_primaries_add(0, "192.0.2.2", 53, "k1"), "", 0, NULL);
  const uint32_t p3 = xfr_primaries_add(xfr_primaries_add(0, "192.0.2.1", 5353, "k1"), "", 0, NULL);
  const uint32_t p4 = xfr_primaries_add(xfr_primaries_add(0, "192.0.2.1", 53, "K1"), "", 0, NULL);
  const uint32_t p5 = xfr_primaries_add(xfr_primaries_add(0, "192.0.2.1", 53, "k1"), "", 0, "tk");
  CHECK(p1 != p2 && p1 != p3 && p1 == p4 && p1 != p5);
}

static void test_times(void) {
  printf("[the clock moved back and forward: clamped in memory only; the EXPIRE option of 0]\n");
  const time_t now = 1800000000;
  xfr_state_t s;
  memset(&s, 0, sizeof(s));
  s.kind = XFR_K_CONFIG;
  xfr_state_set_times(&s, now - 100, 0);
  CHECK(s.last_ok == (uint32_t)(now - 100) && s.expire_delta == 0 && !(s.flags & XFR_SF_EXPIRE_OPT));
  xfr_times_t t;
  xfr_state_times(&s, 86400, now, &t);
  CHECK(t.last_ok == now - 100 && t.expire_at == 0 && !t.clamped);
  /* the clock went back by a day since the copy was written: the copy's time is in the future */
  s.last_ok = (uint32_t)(now + 86400);
  const xfr_state_t before = s;
  xfr_state_times(&s, 86400, now, &t);
  CHECK(t.last_ok == now && t.clamped);
  CHECK(memcmp(&before, &s, sizeof(s)) == 0);                              /* (nothing is written back: the input is untouched) */
  s.last_ok = (uint32_t)(now + XFR_CLOCK_SLACK);                          /* within the slack: taken as it is */
  xfr_state_times(&s, 86400, now, &t);
  CHECK(t.last_ok == now + XFR_CLOCK_SLACK && !t.clamped);
  /* forward: a copy from long ago is old; expired by the arithmetic, not clamped */
  xfr_state_set_times(&s, now - 10 * 86400, now - 9 * 86400);
  CHECK((s.flags & XFR_SF_EXPIRE_OPT) && s.expire_delta == 86400);
  xfr_state_times(&s, 86400, now, &t);
  CHECK(t.expire_at == now - 9 * 86400 && !t.clamped);
  /* an EXPIRE-option deadline beyond now + SOA EXPIRE (RFC 7314 §4): held to it */
  xfr_state_set_times(&s, now, now + 10 * 86400);
  xfr_state_times(&s, 86400, now, &t);
  CHECK(t.expire_at == now + 86400 && t.clamped);
  /* an EXPIRE option of 0: expired at once (bit1 set, delta 0) */
  xfr_state_set_times(&s, now - 5, now - 5);
  CHECK((s.flags & XFR_SF_EXPIRE_OPT) && s.expire_delta == 0);
  xfr_state_times(&s, 86400, now, &t);
  CHECK(t.expire_at == now - 5);
  xfr_state_set_times(&s, now, now - 50);                                 /* (a deadline before the refresh: 0 delta, expired at once) */
  CHECK(s.expire_delta == 0);
  xfr_state_set_times(&s, -1, 0);
  CHECK_EQ(s.last_ok, 0);
}

static void test_rules(void) {
  printf("[D7, the up-to-date rule (M2), the failure skip, next_check after a restore]\n");
  /* D7: the file wins only when newer than the copy's save time and of a greater serial (RFC 1982) */
  CHECK(xfr_file_wins(2000, 11, 1000, 10));
  CHECK(!xfr_file_wins(2000, 10, 1000, 10));
  CHECK(!xfr_file_wins(900, 11, 1000, 10));                               /* an old file with a higher serial: the store (a retransfer to a lower serial) */
  CHECK(!xfr_file_wins(2000, 9, 1000, 10));
  CHECK(xfr_file_wins(2000, 1, 1000, 0xFFFFFFF0u));                       /* (wrap-around) */
  CHECK(!xfr_file_wins(0, 11, 0, 10));
  CHECK(xfr_serial_gt(1, 0xFFFFFFFFu) && !xfr_serial_gt(5, 5) && !xfr_serial_gt(0x80000005u, 5));
  /* M2 */
  CHECK_EQ(xfr_uptodate_action(true, STORE_STATE_STORED, STORE_F_XFR, 7, 7), XFR_UP_STATE);
  CHECK_EQ(xfr_uptodate_action(false, 0, 0, 0, 7), XFR_UP_PUT);
  CHECK_EQ(xfr_uptodate_action(true, STORE_STATE_KNOWN, STORE_F_XFR, 7, 7), XFR_UP_PUT);
  CHECK_EQ(xfr_uptodate_action(true, STORE_STATE_STORED, STORE_F_XFR, 6, 7), XFR_UP_PUT);
  CHECK_EQ(xfr_uptodate_action(true, STORE_STATE_STORED, 0, 7, 7), XFR_UP_PUT);
  /* the failure skip: only the attempt time changes, and the one on disk is younger than retry */
  xfr_state_t o = { .kind = 1, .flags = XFR_SF_FAILED, .identity = 5, .last_ok = 100, .last_attempt = 1000 }, u = o;
  u.last_attempt = 1010;
  CHECK(xfr_failure_skip(&o, &u, 1010, 60));
  CHECK(!xfr_failure_skip(&o, &u, 1070, 60));
  u.flags = XFR_SF_FAILED | XFR_SF_RX_LOST;
  CHECK(!xfr_failure_skip(&o, &u, 1010, 60));
  u = o;
  u.kind = 3;
  CHECK(!xfr_failure_skip(&o, &u, 1010, 60));
  u = o;
  u.rx_settings = 1;
  CHECK(!xfr_failure_skip(&o, &u, 1010, 60));
  o.last_attempt = 0;
  CHECK(!xfr_failure_skip(&o, &o, 1010, 60));
  /* next_check (D3): at once, unless a recent failure */
  xfr_state_t s = { .kind = 1, .last_ok = 100 };
  CHECK_EQ(xfr_restore_next_check(&s, 60, 0, 1000), 0);
  s.flags = XFR_SF_FAILED;
  s.last_attempt = 990;
  CHECK_EQ(xfr_restore_next_check(&s, 60, 0, 1000), 1050);
  CHECK_EQ(xfr_restore_next_check(&s, 60, 1020, 1000), 1020);              /* (never later than the deadline) */
  CHECK_EQ(xfr_restore_next_check(&s, 5, 0, 1000), 0);                    /* (the retry is over) */
  CHECK_EQ(xfr_restore_next_check(&s, 60, 999, 1000), 0);
}

/* ======================================================================================================================= 2. lifetimes */

static char g_dir[256], g_store[300], g_sdir[300];
static server_config_t g_cfg;

static void wfile(const char *name, const char *text, time_t mtime) {
  char p[512];
  snprintf(p, sizeof(p), "%s/%s", g_dir, name);
  FILE *f = fopen(p, "w");
  if (!f) { perror(p); exit(2); }
  fputs(text, f);
  fclose(f);
  if (mtime) {
    struct timeval tv[2] = { { mtime, 0 }, { mtime, 0 } };
    utimes(p, tv);
  }
}
static void zfile(const char *zone, uint32_t serial, time_t mtime) {
  char t[512], n[300];
  snprintf(t, sizeof(t), "$ORIGIN %s\n$TTL 300\n@ SOA ns1 host %u 3600 600 86400 300\n@ NS ns1\nwww A 192.0.2.%u\n", zone, (unsigned)serial, 80u + (serial & 3u));
  snprintf(n, sizeof(n), "%szone", zone);
  wfile(n, t, mtime);
}

static const char *g_extra_zones = "";
static void conf_text(char *out, size_t cap, const char *store_stmt) {
  snprintf(out, cap,
           "options { %s };\n"
           "view \"v1\" { match-clients { any; };\n"
           "  zone \"a.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"b.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"c.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"d.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"e.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"f.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; file \"%s/f.test.zone\"; };\n"
           "  zone \"g.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; file \"%s/g.test.zone\"; };\n"
           "  zone \"h.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"i.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"j.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"k.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"l.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n"
           "  zone \"p.test\" { type slave; masters { 192.0.2.2; }; primary-settings no; };\n"
           "  zone \"cat.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; catalog-zone yes; };\n"
           "%s"
           "};\n", store_stmt, g_dir, g_dir, g_extra_zones);
}

static zone_db_entry_t *ent(const char *zone) {
  zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
  zone_db_entry_t *e = s ? snapshot_get_zone_in_view(s, "v1", zone) : NULL;
  if (s) release_zone_snapshot(s);
  return e;
}

static int life_start(const char *store_stmt, bool want) {
  char conf[8192];
  conf_text(conf, sizeof(conf), store_stmt);
  memset(&g_cfg, 0, sizeof(g_cfg));
  if (parse_named_conf(conf, &g_cfg) != 0) { printf("  [FAIL] the configuration does not parse\n"); return -1; }
  atomic_store_explicit(&g_config_db.active, &g_cfg, memory_order_release);
  xfr_store_want(want && db_store_wanted(&g_cfg));
  rebuild_zone_db_from_config(&g_cfg, false);
  char msg[1024];
  int lvl = 0;
  if (!db_store_frontend_open_cfg(&g_cfg, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg), &lvl)) { printf("  frontend: %s\n", msg); return -1; }
  if (msg[0]) printf("  frontend: %s\n", msg);
  if (!db_store_start(&g_cfg)) return -1;
  return 0;
}

/* a "transfer": the version of serial `serial` installed in the entry as handle_axfr_event() does (timers from the SOA), with the given last refresh and expire_at */
static void install(zone_db_entry_t *e, uint32_t serial, uint8_t origin, time_t last_ok, time_t expire_at) {
  zone_image_t *img = zi_zone(e->domain, serial, NULL, NULL, 0);
  if (!img) { CHECK(img != NULL); return; }
  zone_version_t *v = zone_version_new_ext(img, dns_alloc_size(img, img->total_size), NULL, NULL);
  pthread_mutex_lock(&e->writer_lock);
  zone_version_t *cur = atomic_load_explicit(&e->rcu.active, memory_order_acquire);
  if (cur && (!cur->image || cur->image->n_rrs == 0)) cur = NULL;
  atomic_store(&e->serial, serial);
  atomic_store(&e->refresh, 3600);
  atomic_store(&e->retry, 600);
  atomic_store(&e->expire, 86400);
  atomic_store(&e->last_successful_transfer, last_ok);
  atomic_store(&e->expire_at, expire_at);
  e->xfr_origin = origin;
  zone_install_version(e, v, cur, false);
  pthread_mutex_unlock(&e->writer_lock);
}

static void refresh_end(zone_db_entry_t *e, int outcome, time_t at) {
  const xfr_store_ops_t *o = atomic_load(&g_xfr_ops);
  CHECK(o != NULL);
  if (o) o->after_refresh(e, outcome, at);
}

static bool rec(const char *zone, int kind, store_zone_t *z) {
  store_t *st = db_store_handle();
  char k[XFR_KEY_MAX + 1];
  const int n = xfr_key_make("v1", kind, zone, k, sizeof(k));
  if (!st || n < 0 || xfr_store_vid() < 0) return false;
  store_read_lock();
  const uint32_t zid = store_find(st, (uint16_t)xfr_store_vid(), k, (size_t)n);
  const bool ok = zid != STORE_NONE && store_zone_get(st, zid, z) == 0;
  store_read_unlock();
  return ok;
}
static bool rec_state(const char *zone, int kind, xfr_state_t *s, store_zone_t *z) {
  store_zone_t zz;
  if (!z) z = &zz;
  return rec(zone, kind, z) && xfr_state_decode(z->digest, sizeof(z->digest), s) == 0;
}

/* put a record of the zone as this module would, but with what the test wants (another identity, another serial) */
static void put_raw(const char *zone, uint32_t meta_serial, uint32_t img_serial, uint64_t identity, time_t stamp) {
  store_t *st = db_store_handle();
  char k[XFR_KEY_MAX + 1];
  const int n = xfr_key_make("v1", XFR_K_CONFIG, zone, k, sizeof(k));
  zone_image_t *img = zi_zone(zone, img_serial, NULL, NULL, 0);
  xfr_state_t s = { .kind = XFR_K_CONFIG, .identity = identity, .last_ok = (uint32_t)time(NULL) };
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.flags = STORE_F_XFR;
  m.serial = meta_serial;
  m.stamp_time = (uint64_t)stamp;
  xfr_state_encode(&s, m.digest);
  CHECK_EQ(store_put_ex(st, (uint16_t)xfr_store_vid(), k, (size_t)n, &m, img, img->total_size, STORE_PUT_NO_DEGRADE, NULL), 0);
  free(img);
}

/* a byte of the stored image changes in its segment file (the store maps the file: the next read sees it) */
static void damage(const char *zone) {
  store_zone_t z;
  if (!rec(zone, XFR_K_CONFIG, &z)) { CHECK(0); return; }
  char p[512];
  snprintf(p, sizeof(p), "%s/seg.%llu", g_sdir, (unsigned long long)(z.loc >> 36));
  int fd = open(p, O_RDWR);
  CHECK(fd >= 0);
  if (fd < 0) return;
  const off_t off = (off_t)((z.loc & ((1ull << 36) - 1)) * 64) + 64 + (((off_t)z.klen + 15) & ~(off_t)15) + 40;
  uint8_t b = 0;
  CHECK(pread(fd, &b, 1, off) == 1);
  b ^= 0x5A;
  CHECK(pwrite(fd, &b, 1, off) == 1);
  close(fd);
}

static xfr_store_counters_t ctr(void) {
  xfr_store_counters_t c;
  xfr_store_counters(&c);
  return c;
}

static void wait_pass(void) {
  for (int i = 0; i < 500 && atomic_load(&g_xfr_pending) > 0; i++) usleep(10000);
  usleep(50000);                                                          /* (the GC of the pass runs after the restores) */
}

/* the catalog delta of the transfer of cat.test: its members (domain, unique-id) */
static void catalog_members(const char *const *names, const char *const *uids, int n) {
  zone_db_entry_t *cat = ent("cat.test.");
  CHECK(cat != NULL);
  catalog_member_id_t *m = calloc((size_t)(n ? n : 1), sizeof(*m));
  for (int i = 0; i < n; i++) {
    snprintf(m[i].domain, sizeof(m[i].domain), "%s", names[i]);
    snprintf(m[i].unique_id, sizeof(m[i].unique_id), "%s", uids[i]);
  }
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  const zone_config_t *cc = zone_entry_config(cfg, cat);
  rcu_aux_read_unlock();
  CHECK(rebuild_zone_db_snapshot(NULL, "v1", cat, cc, m, n) != NULL);
  release_config_snapshot(cfg);
}

/* life 1: a fresh store; the writes */
static int life1(void) {
  printf("[life 1: the writes at the end of a refresh]\n");
  rcu_aux_thread_pin();
  const time_t now = time(NULL);
  zfile("f.test.", 100, now - 86400);                                     /* (D7: an old file with a higher serial than the copy) */
  zfile("g.test.", 140, now - 86400);
  if (life_start(g_store, true) != 0) return 1;
  xfr_store_wait_start(5000);
  wait_pass();
  CHECK(xfr_store_active() && xfr_store_vid() >= 0);
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
  zone_db_entry_t *a = ent("a.test.");
  CHECK(a != NULL);
  if (!a) return 1;
  /* transferred */
  install(a, 10, XFR_ORIGIN_XFR, now - 10, 0);
  refresh_end(a, XFR_OUT_TRANSFERRED, now - 11);
  xfr_state_t s;
  store_zone_t z;
  CHECK(rec_state("a.test.", XFR_K_CONFIG, &s, &z));
  CHECK(z.state == STORE_STATE_STORED && (z.flags & STORE_F_XFR) && z.serial == 10 && z.source_id == 0 && z.settings == 0 && z.stamp_time >= (uint64_t)now - 1);
  CHECK(s.kind == XFR_K_CONFIG && s.last_ok == (uint32_t)(now - 10) && s.expire_delta == 0 && !(s.flags & (XFR_SF_EXPIRE_OPT | XFR_SF_FAILED)) && s.last_attempt == (uint32_t)(now - 11));
  CHECK_EQ(s.identity, xfr_identity(XFR_K_CONFIG, "a.test.", "v1", NULL, 0));
  CHECK_EQ(s.primaries, xfr_primaries_add(xfr_primaries_add(0, "192.0.2.1", 53, NULL), "", 0, NULL));
  xfr_store_counters_t c0 = ctr();
  CHECK_EQ(c0.puts, 1);
  /* up to date, the record holds this serial: the state alone */
  atomic_store(&a->last_successful_transfer, now - 2);
  refresh_end(a, XFR_OUT_UPTODATE, now - 3);
  xfr_store_counters_t c1 = ctr();
  CHECK(c1.puts == c0.puts && c1.state_writes == c0.state_writes + 1);
  CHECK(rec_state("a.test.", XFR_K_CONFIG, &s, NULL) && s.last_ok == (uint32_t)(now - 2));
  /* failed: the attempt time and the bit; last-ok as it was; a second failure at once is left out */
  refresh_end(a, XFR_OUT_FAILED, now);
  CHECK(rec_state("a.test.", XFR_K_CONFIG, &s, NULL) && (s.flags & XFR_SF_FAILED) && s.last_ok == (uint32_t)(now - 2) && s.last_attempt == (uint32_t)now);
  refresh_end(a, XFR_OUT_FAILED, now + 1);
  xfr_store_counters_t c2 = ctr();
  CHECK_EQ(c2.state_skipped, c1.state_skipped + 1);
  /* up to date and the record of this key is of another zone (an identity that is not this zone's, the same serial): the state alone is not written over it, the whole image is put (2.3) */
  zone_db_entry_t *k = ent("k.test.");
  install(k, 12, XFR_ORIGIN_XFR, now, 0);
  put_raw("k.test.", 12, 12, 999, now);
  xfr_store_counters_t ck0 = ctr();
  refresh_end(k, XFR_OUT_UPTODATE, now);
  xfr_store_counters_t ck1 = ctr();
  CHECK_EQ(ck1.puts_uptodate, ck0.puts_uptodate + 1);
  CHECK_EQ(ck1.state_writes, ck0.state_writes);
  CHECK(rec_state("k.test.", XFR_K_CONFIG, &s, &z) && s.identity == xfr_identity(XFR_K_CONFIG, "k.test.", "v1", NULL, 0) && z.state == STORE_STATE_STORED);
  /* a record whose state cannot be read is put whole as well */
  {
    store_t *sto = db_store_handle();
    char kk[XFR_KEY_MAX + 1];
    const int kn = xfr_key_make("v1", XFR_K_CONFIG, "k.test.", kk, sizeof(kk));
    uint8_t zero[STORE_DIGEST_LEN];
    memset(zero, 0, sizeof(zero));
    CHECK_EQ(store_set_digest(sto, (uint16_t)xfr_store_vid(), kk, (size_t)kn, 12, 0, zero, STORE_F_XFR, 0), 0);
    refresh_end(k, XFR_OUT_UPTODATE, now);
    CHECK_EQ(ctr().puts_uptodate, ck1.puts_uptodate + 1);
    CHECK(rec_state("k.test.", XFR_K_CONFIG, &s, NULL) && s.identity == xfr_identity(XFR_K_CONFIG, "k.test.", "v1", NULL, 0));
  }
  /* R2: a copy restored without the settings its primary sent (xfr_axfr_once) keeps XFR_SF_RX_LOST in the state while the whole transfer it asks for has not come: an up-to-date
   * answer (a primary that was asked in another way) and a failure write the state with the bit (and the restore of life 2 sets xfr_axfr_once again) */
  zone_db_entry_t *l = ent("l.test.");
  install(l, 20, XFR_ORIGIN_XFR, now, 0);
  refresh_end(l, XFR_OUT_TRANSFERRED, now);
  CHECK(rec_state("l.test.", XFR_K_CONFIG, &s, NULL) && !(s.flags & XFR_SF_RX_LOST));
  zone_x_t *lx = zone_x_need(l);
  CHECK(lx != NULL);
  if (lx) atomic_store(&lx->xfr_axfr_once, true);
  xfr_store_counters_t cl0 = ctr();
  refresh_end(l, XFR_OUT_UPTODATE, now + 1);
  CHECK_EQ(ctr().state_writes, cl0.state_writes + 1);                     /* (the state alone: the record holds this serial) */
  CHECK(rec_state("l.test.", XFR_K_CONFIG, &s, NULL) && (s.flags & XFR_SF_RX_LOST));
  if (lx) atomic_store(&lx->xfr_axfr_once, false);
  refresh_end(l, XFR_OUT_UPTODATE, now + 2);
  CHECK(rec_state("l.test.", XFR_K_CONFIG, &s, NULL) && !(s.flags & XFR_SF_RX_LOST));   /* (the bit goes when the transfer has come) */
  if (lx) atomic_store(&lx->xfr_axfr_once, true);
  refresh_end(l, XFR_OUT_TRANSFERRED, now + 3);                           /* (the whole image: the bit is in the state too) */
  CHECK(rec_state("l.test.", XFR_K_CONFIG, &s, NULL) && (s.flags & XFR_SF_RX_LOST));
  /* a scrub made the record KNOWN (a damaged image): the next up-to-date refresh stores the whole image (M2), and the scrub's text names the secondary's copy */
  xfr_store_counters_t c2u = ctr();
  damage("a.test.");
  store_scrub_report_t sr;
  CHECK_EQ(store_scrub_run(db_store_handle(), &sr), 0);
  CHECK(sr.bad_images >= 1);
  CHECK(rec("a.test.", XFR_K_CONFIG, &z) && z.state == STORE_STATE_KNOWN && (z.flags & STORE_F_XFR));
  refresh_end(a, XFR_OUT_UPTODATE, now);
  xfr_store_counters_t c3 = ctr();
  CHECK_EQ(c3.puts_uptodate, c2u.puts_uptodate + 1);
  CHECK(rec_state("a.test.", XFR_K_CONFIG, &s, &z) && z.state == STORE_STATE_STORED && z.serial == 10 && !(s.flags & XFR_SF_FAILED));
  /* the EXPIRE option of 0 (b.test): bit1 and a delta of 0 */
  zone_db_entry_t *b = ent("b.test.");
  install(b, 3, XFR_ORIGIN_XFR, now, now);
  refresh_end(b, XFR_OUT_TRANSFERRED, now);
  CHECK(rec_state("b.test.", XFR_K_CONFIG, &s, NULL) && (s.flags & XFR_SF_EXPIRE_OPT) && s.expire_delta == 0);
  /* the restore cases of life 2 */
  put_raw("c.test.", 5, 5, 12345, now);                                  /* another identity */
  install(ent("d.test."), 7, XFR_ORIGIN_XFR, now, 0);
  refresh_end(ent("d.test."), XFR_OUT_TRANSFERRED, now);
                                                                          /* (d.test: its image is damaged at the end of this life, after the store check) */
  put_raw("e.test.", 99, 7, xfr_identity(XFR_K_CONFIG, "e.test.", "v1", NULL, 0), now);   /* the record's serial is not the image's */
  zone_db_entry_t *f = ent("f.test.");
  CHECK(f && f->xfr_origin == XFR_ORIGIN_FILE && atomic_load(&f->serial) == 100);
  install(f, 50, XFR_ORIGIN_XFR, now, 0);                                 /* a retransfer to a lower serial */
  refresh_end(f, XFR_OUT_TRANSFERRED, now);
  zone_db_entry_t *g = ent("g.test.");
  install(g, 150, XFR_ORIGIN_XFR, now, 0);
  refresh_end(g, XFR_OUT_TRANSFERRED, now);
  zfile("g.test.", 200, now + 100);                                       /* a newer file with a greater serial (read at the next start) */
  zone_db_entry_t *h = ent("h.test.");
  install(h, 4, XFR_ORIGIN_XFR, now - 100000, 0);                         /* expires while stopped (EXPIRE 86400) */
  refresh_end(h, XFR_OUT_TRANSFERRED, now - 100000);
  zone_db_entry_t *i = ent("i.test.");
  install(i, 4, XFR_ORIGIN_XFR, now - 50, 0);
  refresh_end(i, XFR_OUT_TRANSFERRED, now - 50);
  refresh_end(i, XFR_OUT_FAILED, now);                                    /* a recent failure */
  zone_db_entry_t *p = ent("p.test.");
  install(p, 2, XFR_ORIGIN_XFR, now, 0);
  refresh_end(p, XFR_OUT_TRANSFERRED, now);                               /* (its primaries change in life 2) */
  /* M6: a member whose unique-id changes during its transfer: the copy its old entry writes is deleted again (no stale copy) */
  const char *mn[1] = { "m.test." }, *u1[1] = { "u1" }, *u2[1] = { "u2" };
  catalog_members(mn, u1, 1);
  wait_pass();
  zone_db_snapshot_t *hold = acquire_retained_zone_snapshot();
  zone_db_entry_t *m1 = hold ? snapshot_get_zone_in_view(hold, "v1", "m.test.") : NULL;
  CHECK(m1 && m1->is_catalog_member && !atomic_load(&m1->restore_pending));
  if (m1) install(m1, 9, XFR_ORIGIN_XFR, now, 0);
  catalog_members(mn, u2, 1);                                             /* (the transfer of the catalog meanwhile) */
  wait_pass();
  xfr_store_counters_t c4 = ctr();
  if (m1) refresh_end(m1, XFR_OUT_TRANSFERRED, now);
  xfr_store_counters_t c5 = ctr();
  CHECK_EQ(c5.orphans_deleted, c4.orphans_deleted + 1);
  CHECK(!rec("m.test.", XFR_K_MEMBER, &z));
  if (hold) release_zone_snapshot(hold);
  /* the copy of the new member (u2), and a member x.test whose catalog has not refreshed since the start: the GC keeps its copy (M6, per view) until it has */
  zone_db_entry_t *m2 = ent("m.test.");
  CHECK(m2 && m2 != m1);
  if (m2) { install(m2, 9, XFR_ORIGIN_XFR, now, 0); refresh_end(m2, XFR_OUT_TRANSFERRED, now); }
  CHECK(rec_state("m.test.", XFR_K_MEMBER, &s, NULL) && s.identity == xfr_identity(XFR_K_MEMBER, "m.test.", "v1", "u2", 0));
  const char *xn[2] = { "m.test.", "x.test." }, *xu[2] = { "u2", "ux" };
  catalog_members(xn, xu, 2);
  wait_pass();
  zone_db_entry_t *x = ent("x.test.");
  CHECK(x != NULL);
  if (x) { install(x, 1, XFR_ORIGIN_XFR, now, 0); refresh_end(x, XFR_OUT_TRANSFERRED, now); }
  CHECK(rec("x.test.", XFR_K_MEMBER, &z));
  catalog_members(mn, u2, 1);                                             /* x.test leaves the catalog */
  wait_pass();
  CHECK(rec("x.test.", XFR_K_MEMBER, &z));                               /* (cat.test has not refreshed: kept) */
  zone_db_entry_t *cat = ent("cat.test.");
  zone_x_t *cx = cat ? zone_x_need(cat) : NULL;
  if (cx) atomic_store(&cx->xfr_refreshed, true);
  catalog_members(mn, u2, 1);
  wait_pass();
  CHECK(!rec("x.test.", XFR_K_MEMBER, &z));                              /* (now it goes) */
  CHECK(rec("m.test.", XFR_K_MEMBER, &z));
  CHECK(ctr().gc_deleted >= 1);
  /* zonestatus */
  char zs[1024];
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  size_t zl = xfr_store_zonestatus(a, cfg, zs, sizeof(zs));
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  CHECK(zl > 0 && strstr(zs, "Store: copy serial 10, ") && strstr(zs, "Last-refresh: ") && strstr(zs, "Expires: "));
  printf("  zonestatus: %s", zs);
  store_check_report_t cr;
  CHECK_EQ(store_check(db_store_handle(), &cr), 0);
  CHECK_EQ(cr.errors, 0);
  damage("d.test.");                                                      /* a bad checksum for the restore of life 2 */
  db_store_stop();
  return g_failed;
}

/* life 2: the restart; every restore decision */
static _Atomic int g_hook_hold, g_hook_seen;
static void hold_hook(zone_db_entry_t *e) {
  (void)e;
  atomic_fetch_add(&g_hook_seen, 1);
  while (atomic_load(&g_hook_hold)) usleep(1000);
}
static int life2(void) {
  printf("[life 2: the restart: the restore decisions]\n");
  rcu_aux_thread_pin();
  const time_t now = time(NULL);
  g_extra_zones = "";
  atomic_store(&g_hook_hold, 1);
  atomic_store(&xfr_store_test_restore_hook, hold_hook);
  /* p.test: its primaries change while stopped */
  if (life_start(g_store, true) != 0) return 1;
  /* the restore thread is held at its first entry: every secondary is pending, the tick would not refresh one (M4) */
  for (int i = 0; i < 500 && !atomic_load(&g_hook_seen); i++) usleep(2000);
  CHECK(atomic_load(&g_hook_seen) == 1);
  zone_db_entry_t *a = ent("a.test.");
  CHECK(a && atomic_load(&a->restore_pending));
  CHECK(atomic_load(&g_xfr_pending) >= 10);
  char zs[1024];
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  xfr_store_zonestatus(a, cfg, zs, sizeof(zs));
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  CHECK(strstr(zs, "Store: restore pending") != NULL);
  CHECK(!xfr_restore_stuck());                                             /* (the core start stamped the progress) */
  atomic_store(&g_hook_hold, 0);
  xfr_store_wait_start(5000);
  wait_pass();
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
  xfr_store_counters_t c = ctr();
  printf("  restored %llu (expired %llu), bad %llu, identity %llu, file %llu\n", (unsigned long long)c.restored, (unsigned long long)c.restored_expired,
         (unsigned long long)c.restore_bad, (unsigned long long)c.restore_identity, (unsigned long long)c.file_won);
  /* a: restored (serial, timers from the SOA, last-ok from the state, the origin) */
  CHECK(a && atomic_load(&a->serial) == 10 && a->xfr_origin == XFR_ORIGIN_STORE && atomic_load(&a->refresh) == 3600 && atomic_load(&a->expire) == 86400);
  zone_version_t *av = a ? atomic_load(&a->rcu.active) : NULL;
  CHECK(av && av->image && av->image->n_rrs > 0);
  CHECK(a && atomic_load(&a->next_check) == 0);
  /* b: the EXPIRE option of 0: expired at once */
  zone_db_entry_t *b = ent("b.test.");
  CHECK(b && atomic_load(&b->serial) == 3 && zone_expire_deadline(b) > 0 && zone_expire_deadline(b) <= now);
  CHECK(b && zone_expire_option_value(b, now) == 0);                       /* (RFC 7314: the downstream EXPIRE is the time left: 0) */
  /* c: another identity: deleted, empty */
  zone_db_entry_t *ce = ent("c.test.");
  store_zone_t z;
  CHECK(ce && atomic_load(&ce->serial) == 0 && !rec("c.test.", XFR_K_CONFIG, &z));
  /* d: a bad checksum: KNOWN, empty; e: a serial mismatch: KNOWN, empty */
  CHECK(rec("d.test.", XFR_K_CONFIG, &z) && z.state == STORE_STATE_KNOWN && atomic_load(&ent("d.test.")->serial) == 0);
  CHECK(rec("e.test.", XFR_K_CONFIG, &z) && z.state == STORE_STATE_KNOWN && atomic_load(&ent("e.test.")->serial) == 0);
  /* f: the old file of a higher serial loses (D7); g: the newer file of a greater serial wins */
  CHECK(atomic_load(&ent("f.test.")->serial) == 50 && ent("f.test.")->xfr_origin == XFR_ORIGIN_STORE);
  CHECK(atomic_load(&ent("g.test.")->serial) == 200 && ent("g.test.")->xfr_origin == XFR_ORIGIN_FILE);
  CHECK(rec("g.test.", XFR_K_CONFIG, &z) && z.serial == 150);             /* (the record stays; the next refresh replaces it) */
  /* h: expired while stopped; i: a recent failure: next_check at last attempt + retry */
  zone_db_entry_t *h = ent("h.test.");
  CHECK(h && atomic_load(&h->serial) == 4 && zone_expire_deadline(h) < now);
  /* (D9, 2.5: the restore thread says nothing about it and does not touch the tick's state: the tick is told with exp_stopped and says `expired while stopped` through its rate limit) */
  zone_x_t *hx = h ? zone_x(h) : NULL;
  CHECK(hx && hx->exp_stopped && hx->exp_state == 0);
  const uint64_t ev0 = ctr().expire_events;
  if (h) {
    rcu_aux_read_lock();
    server_config_t *hc = acquire_config_snapshot();
    xfr_expiry_begin(now);
    xfr_expiry_entry(h, hc, now);
    xfr_expiry_end(now);
    release_config_snapshot(hc);
    rcu_aux_read_unlock();
  }
  CHECK(hx && !hx->exp_stopped && hx->exp_state == 1);
  CHECK_EQ(ctr().expire_events, ev0 + 1);
  CHECK(ctr().expired_zones >= 1);
  zone_x_t *lx2 = ent("l.test.") ? zone_x(ent("l.test.")) : NULL;
  CHECK(lx2 && atomic_load(&lx2->xfr_axfr_once));                         /* (R2: the bit of life 1's state) */
  zone_x_t *ax2 = a ? zone_x(a) : NULL;
  CHECK(!ax2 || !atomic_load(&ax2->xfr_axfr_once));
  zone_db_entry_t *i = ent("i.test.");
  CHECK(i && atomic_load(&i->serial) == 4 && atomic_load(&i->next_check) > now && atomic_load(&i->next_check) <= now + 600);
  zone_db_entry_t *j = ent("j.test.");
  CHECK(j && atomic_load(&j->serial) == 0);                                /* (no record) */
  CHECK(c.restored >= 6 && c.restored_expired >= 1 && c.restore_bad == 2 && c.restore_identity == 1 && c.file_won == 1);
  /* p: the copy is served and the zone refreshed at once (another primaries digest) -- the configuration of life 2 is the same, so the digest is too: no refresh_now */
  zone_db_entry_t *p = ent("p.test.");
  CHECK(p && atomic_load(&p->serial) == 2 && !atomic_load(&p->refresh_now));
  db_store_stop();
  return g_failed;
}

/* life 2b: the primaries of p.test changed while stopped: the copy is kept, refreshed at once (M5) */
static int life2b(void) {
  printf("[life 2b: the primaries changed while stopped]\n");
  rcu_aux_thread_pin();
  g_extra_zones = "";
  char conf[8192];
  conf_text(conf, sizeof(conf), g_store);
  char *pp = strstr(conf, "\"p.test\" { type slave; masters { 192.0.2.2; }");
  CHECK(pp != NULL);
  if (pp) memcpy(strstr(pp, "192.0.2.2"), "192.0.2.3", 9);
  memset(&g_cfg, 0, sizeof(g_cfg));
  CHECK(parse_named_conf(conf, &g_cfg) == 0);
  atomic_store_explicit(&g_config_db.active, &g_cfg, memory_order_release);
  xfr_store_want(true);
  rebuild_zone_db_from_config(&g_cfg, false);
  char msg[1024];
  int lvl;
  CHECK(db_store_frontend_open_cfg(&g_cfg, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg), &lvl));
  CHECK(db_store_start(&g_cfg));
  xfr_store_wait_start(5000);
  wait_pass();
  zone_db_entry_t *p = ent("p.test.");
  CHECK(p && atomic_load(&p->serial) == 2 && atomic_load(&p->refresh_now));
  /* a name too long for a key (W12): memory only, counted */
  CHECK(ctr().unstorable == 0);
  db_store_stop();
  return g_failed;
}

/* life 2c: a version is installed by a transfer while the entry is still pending (the restore thread, held at its first entry, is overtaken: the tick's safety net gave up on the bit
 * between the check of restore_one() and the install of restore_do(), so the late restore meets a transferred version): it installs nothing over it (4.1) */
static void transfer_hook(zone_db_entry_t *e) {
  if (strcmp(e->domain, "a.test.") == 0) install(e, 11, XFR_ORIGIN_XFR, time(NULL), 0);
}
static int life2c(void) {
  printf("[life 2c: the restore meets a transferred version]\n");
  rcu_aux_thread_pin();
  atomic_store(&xfr_store_test_restore_hook, transfer_hook);
  if (life_start(g_store, true) != 0) return 1;
  xfr_store_wait_start(5000);
  wait_pass();
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
  zone_db_entry_t *a = ent("a.test.");
  CHECK(a != NULL);
  if (!a) return 1;
  CHECK_EQ(atomic_load(&a->serial), 11);                                  /* (not the stored 10) */
  CHECK_EQ(a->xfr_origin, XFR_ORIGIN_XFR);
  zone_version_t *av = atomic_load(&a->rcu.active);
  zone_image_soa_t nums;
  const uint32_t soa = av && av->image ? zone_image_apex_soa(av->image) : ZONE_IMAGE_NONE;
  CHECK(soa != ZONE_IMAGE_NONE && zone_image_soa(av->image, soa, NULL, 0, NULL, 0, &nums) == 0 && nums.serial == 11);
  xfr_store_counters_t c = ctr();
  CHECK(c.restored >= 6);                                                 /* (the others were restored) */
  store_zone_t z;
  CHECK(rec("a.test.", XFR_K_CONFIG, &z) && z.serial == 10);              /* (the record is the copy of before: the next refresh outcome replaces it) */
  atomic_store(&xfr_store_test_restore_hook, NULL);
  db_store_stop();
  return g_failed;
}

/* life 3: 32 views full: no reserved view, the secondaries are not held (R2) */
static int life3(void) {
  printf("[life 3: 32 views full]\n");
  rcu_aux_thread_pin();
  char d3[400];
  snprintf(d3, sizeof(d3), "%s/full", g_dir);
  mkdir(d3, 0700);
  int fd = open(d3, O_RDONLY | O_DIRECTORY);
  store_opts_t o;
  store_opts_default(&o);
  o.create = true;
  o.no_readahead = true;
  store_t *s = NULL;
  CHECK_EQ(store_open(fd, &o, &s), 0);
  for (int v = 0; s && v < STORE_MAX_VIEWS; v++) {
    char vn[16];
    snprintf(vn, sizeof(vn), "db%d", v);
    CHECK(store_view_add(s, vn) == v);
  }
  if (s) store_close(s);
  close(fd);
  char st[500];
  snprintf(st, sizeof(st), "zone-store \"%s\";", d3);
  if (life_start(st, true) != 0) return 1;
  CHECK(!xfr_store_active() && xfr_store_vid() == -1);
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
  zone_db_entry_t *a = ent("a.test.");
  CHECK(a && !atomic_load(&a->restore_pending));
  CHECK(atomic_load(&g_xfr_ops) == NULL);
  CHECK(ctr().unstorable >= 1);
  db_store_stop();
  return g_failed;
}

/* life 4: the store cannot be opened (zone-store names a file): a memory-only start; a secondary that a reconfiguration adds is not held (R2) */
static int life4(void) {
  printf("[life 4: a store that cannot be opened; a reconfiguration adds a secondary]\n");
  rcu_aux_thread_pin();
  wfile("notadir", "x", 0);
  char st[500];
  snprintf(st, sizeof(st), "zone-store \"%s/notadir\";", g_dir);
  if (life_start(st, true) != 0) return 1;
  CHECK(!xfr_store_active() && db_store_dir_fd() < 0);
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
  g_extra_zones = "  zone \"new.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n";
  static server_config_t c2;
  char conf[8192];
  conf_text(conf, sizeof(conf), st);
  CHECK(parse_named_conf(conf, &c2) == 0);
  atomic_store_explicit(&g_config_db.active, &c2, memory_order_release);
  rebuild_zone_db_from_config(&c2, false);
  zone_db_entry_t *n = ent("new.test.");
  CHECK(n && !atomic_load(&n->restore_pending));
  g_extra_zones = "";
  return g_failed;
}

/* life 5: the 30 s safety net (R2'): judged by the restore thread's progress, not by a bit's age */
static _Atomic int g_slow_n;
static void slow_hook(zone_db_entry_t *e) {
  (void)e;
  atomic_fetch_add(&g_slow_n, 1);
  usleep(30000);
}
static int life5(void) {
  printf("[life 5: the restore makes progress, or it stalls]\n");
  rcu_aux_thread_pin();
  atomic_store(&xfr_store_test_restore_hook, slow_hook);
  if (life_start(g_store, true) != 0) return 1;
  /* a slow restore that keeps going: the progress moves, nothing is given up */
  int64_t p0 = atomic_load(&g_xfr_restore_progress_ms), moved = 0;
  for (int i = 0; i < 200 && atomic_load(&g_xfr_pending) > 0; i++) {
    usleep(10000);
    if (atomic_load(&g_xfr_restore_progress_ms) != p0) moved++;
    CHECK(!xfr_restore_stuck());
  }
  CHECK(moved > 0);
  wait_pass();
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
  /* a stall: the thread is held, pending entries wait, no progress for 30 s (the clock of the progress is set back here): the tick clears them all, one ERROR, the counter */
  atomic_store(&g_hook_hold, 1);
  atomic_store(&g_hook_seen, 0);
  atomic_store(&xfr_store_test_restore_hook, hold_hook);
  g_extra_zones = "  zone \"s1.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n  zone \"s2.test\" { type slave; masters { 192.0.2.1; }; };\n";
  static server_config_t c2;
  char conf[8192];
  conf_text(conf, sizeof(conf), g_store);
  CHECK(parse_named_conf(conf, &c2) == 0);
  atomic_store_explicit(&g_config_db.active, &c2, memory_order_release);
  rebuild_zone_db_from_config(&c2, false);
  for (int i = 0; i < 500 && !atomic_load(&g_hook_seen); i++) usleep(2000);
  CHECK(atomic_load(&g_xfr_pending) == 2);
  CHECK(!xfr_restore_stuck());
  atomic_store(&g_xfr_restore_progress_ms, atomic_load(&g_xfr_restore_progress_ms) - 31000);
  CHECK(xfr_restore_stuck());
  uint64_t n = 0;
  zone_db_entry_t *s1 = ent("s1.test."), *s2 = ent("s2.test.");
  if (s1 && zone_restore_pending_clear(s1)) n++;                          /* (what the tick does with every entry it meets) */
  if (s2 && zone_restore_pending_clear(s2)) n++;
  xfr_restore_note_timeouts(n);
  CHECK_EQ(n, 2);
  CHECK_EQ(ctr().restore_timeouts, 2);
  CHECK(!xfr_restore_stuck());
  atomic_store(&g_hook_hold, 0);
  wait_pass();
  CHECK(s1 && atomic_load(&s1->serial) == 0);                              /* (the restore that comes after meets entries without the bit: nothing) */
  g_extra_zones = "";
  db_store_stop();
  return g_failed;
}

/* life 7 (2.2): two configured views whose names have one store tag: the later view's secondaries are not persisted (a WARNING at the check, xfr_store_config_check()); the first view's are */
static zone_db_entry_t *entv(const char *view, const char *zone) {
  zone_db_snapshot_t *s = acquire_retained_zone_snapshot();
  zone_db_entry_t *e = s ? snapshot_get_zone_in_view(s, view, zone) : NULL;
  if (s) release_zone_snapshot(s);
  return e;
}
/* life 8 (0.7, the unlogged first fill of a store): a configuration whose secondaries keep their copies in the store begins none (a pass stays logged); and a fill that runs anyway (begun here by
 * hand, as for a store without secondaries) is ended by the first copy written, which waits for the end to be on disk and is then logged */
static int life8(void) {
  printf("[life 8: no unlogged fill with secondaries; a copy written during one is put off and stored once its end is on disk]\n");
  rcu_aux_thread_pin();
  const time_t now = time(NULL);
  if (life_start(g_store, true) != 0) return 1;
  xfr_store_wait_start(5000);
  wait_pass();
  store_t *st = db_store_handle();
  CHECK(st != NULL && xfr_store_active());
  if (!st) return 1;
  char why[200];
  CHECK(db_recon_begin("v1", 1000, false, why, sizeof(why)));             /* (an empty store and a pass that reserves: with no secondary it would be unlogged) */
  CHECK_EQ(store_bulk(st), 0);
  store_stats_t ss;
  store_stats(st, &ss);
  CHECK_EQ(ss.bulk_fills, 0);
  db_recon_abort();
  CHECK_EQ(store_bulk_begin(st), 0);
  CHECK_EQ(store_bulk(st), 1);
  zone_db_entry_t *a = ent("a.test.");
  CHECK(a != NULL);
  if (!a) return 1;
  install(a, 10, XFR_ORIGIN_XFR, now - 10, 0);
  const int64_t t0 = (int64_t)time(NULL);
  refresh_end(a, XFR_OUT_TRANSFERRED, now - 11);                          /* (the write is put off and the end of the fill asked for; the refresh does not wait for it) */
  store_zone_t z;
  CHECK(!rec("a.test.", XFR_K_CONFIG, &z));
  CHECK_EQ(ctr().puts, 0);
  CHECK_EQ(store_bulk(st), 0);
  /* the end is made by the store's checkpoint thread, then the restore thread's pass writes the copy: no new transfer */
  bool stored = false;
  for (int w = 0; w < 1500 && !stored; w++) {
    stored = rec("a.test.", XFR_K_CONFIG, &z) && z.state == STORE_STATE_STORED && z.serial == 10;
    if (!stored) usleep(10000);
  }
  CHECK(stored);
  printf("  the copy was stored %lld s after the transfer, once the end of the fill was on disk\n", (long long)((int64_t)time(NULL) - t0));
  store_stats(st, &ss);
  CHECK(!store_bulk_pending(st));
  CHECK_EQ(ss.bulk_end_pending, 0);
  CHECK_EQ(ss.bulk_unlogged_records, 0);                                  /* (the copy was not written unlogged) */
  CHECK_EQ(ctr().puts, 1);
  return 0;
}

static int life7(void) {
  printf("[life 7: two views whose names have one store tag]\n");
  rcu_aux_thread_pin();
  char va[32], vb[32];
  if (!find_collision(va, vb, sizeof(va))) {
    printf("  (no tag collision found in the search; the case is left out)\n");
    return 0;
  }
  CHECK_EQ(xfr_view_tag(va), xfr_view_tag(vb));
  char conf[4096];
  snprintf(conf, sizeof(conf),
           "options { %s };\n"
           "view \"%s\" { match-clients { 127.0.0.1; }; zone \"z.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; }; };\n"
           "view \"%s\" { match-clients { any; }; zone \"z.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; }; };\n",
           g_store, va, vb);
  memset(&g_cfg, 0, sizeof(g_cfg));
  if (parse_named_conf(conf, &g_cfg) != 0) { printf("  [FAIL] the configuration of two views does not parse\n"); return 1; }
  atomic_store_explicit(&g_config_db.active, &g_cfg, memory_order_release);
  xfr_store_want(true);
  rebuild_zone_db_from_config(&g_cfg, false);
  char msg[1024];
  int lvl = 0;
  CHECK(db_store_frontend_open_cfg(&g_cfg, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg), &lvl));
  CHECK(db_store_start(&g_cfg));
  xfr_store_wait_start(5000);
  wait_pass();
  CHECK(xfr_store_active());
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);                               /* (the entry of the left-out view is not held either: its pending bit is cleared by the pass) */
  CHECK_EQ(xfr_store_config_check(&g_cfg), 1);                            /* (the later view is left out; asked again: the same, and no second WARNING) */
  zone_db_entry_t *e1 = entv(va, "z.test."), *e2 = entv(vb, "z.test.");
  CHECK(e1 && e2 && e1 != e2);
  if (!e1 || !e2) return 1;
  const time_t now = time(NULL);
  install(e1, 5, XFR_ORIGIN_XFR, now, 0);
  install(e2, 6, XFR_ORIGIN_XFR, now, 0);
  xfr_store_counters_t c0 = ctr();
  refresh_end(e1, XFR_OUT_TRANSFERRED, now);
  refresh_end(e2, XFR_OUT_TRANSFERRED, now);
  xfr_store_counters_t c1 = ctr();
  CHECK_EQ(c1.puts, c0.puts + 1);                                         /* (only the first view's copy) */
  char key[XFR_KEY_MAX + 1];
  const int kn = xfr_key_make(va, XFR_K_CONFIG, "z.test.", key, sizeof(key));
  store_zone_t z;
  store_read_lock();
  const uint32_t zid = store_find(db_store_handle(), (uint16_t)xfr_store_vid(), key, (size_t)kn);
  const bool have = zid != STORE_NONE && store_zone_get(db_store_handle(), zid, &z) == 0;
  store_read_unlock();
  CHECK(have && z.serial == 5);
  xfr_state_t s;
  CHECK(have && xfr_state_decode(z.digest, sizeof(z.digest), &s) == 0 && s.identity == xfr_identity(XFR_K_CONFIG, "z.test.", va, NULL, 0));
  /* the up-to-date and the failed outcomes of the left-out view write nothing either */
  refresh_end(e2, XFR_OUT_UPTODATE, now + 1);
  refresh_end(e2, XFR_OUT_FAILED, now + 2);
  xfr_store_counters_t c2 = ctr();
  CHECK(c2.puts == c1.puts && c2.state_writes == c1.state_writes && c2.puts_uptodate == c1.puts_uptodate);
  char zs[1024];
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  size_t zl1 = xfr_store_zonestatus(e1, cfg, zs, sizeof(zs));
  CHECK(zl1 > 0 && strstr(zs, "Store: copy serial 5, "));
  size_t zl2 = xfr_store_zonestatus(e2, cfg, zs, sizeof(zs));
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  CHECK(zl2 > 0 && strstr(zs, "Store: not kept (the view's name has the store tag of another view"));
  /* the configuration without the second view: the set is empty again */
  CHECK_EQ(xfr_store_config_check(NULL), 0);
  refresh_end(e2, XFR_OUT_TRANSFERRED, now + 3);
  CHECK_EQ(ctr().puts, c2.puts + 1);
  db_store_stop();
  return g_failed;
}

/* life 6 (TSan): the restore against a concurrent "tick" and transfer on one entry, and the rebuild hooks from several threads */
static _Atomic bool g_race_done;
static _Atomic int g_race_skips, g_race_early;
static void *race_tick(void *arg) {
  zone_db_entry_t *e = arg;
  rcu_aux_thread_pin();
  for (int i = 0; i < 100000 && !atomic_load(&g_race_done); i++) {
    if (atomic_load_explicit(&e->restore_pending, memory_order_acquire)) {   /* (the tick skips the entry: no transfer starts) */
      atomic_fetch_add(&g_race_skips, 1);
      usleep(200);
      continue;
    }
    bool exp = false;
    if (!atomic_compare_exchange_strong(&e->is_transferring, &exp, true)) continue;
    if (atomic_load(&e->serial) != 20) atomic_fetch_add(&g_race_early, 1);  /* (a transfer before the restore installed the copy) */
    install(e, 21, XFR_ORIGIN_XFR, time(NULL), 0);
    refresh_end(e, XFR_OUT_TRANSFERRED, time(NULL));
    atomic_store(&e->is_transferring, false);
    atomic_store(&g_race_done, true);
  }
  return NULL;
}
/* the restore waits (bounded) until the tick thread has seen restore_pending, so that the check below does not depend on thread start timing */
static void race_hook(zone_db_entry_t *e) {
  slow_hook(e);
  for (int i = 0; i < 5000 && atomic_load(&g_race_skips) == 0; i++) usleep(1000);
}
static void *race_hooks(void *arg) {
  (void)arg;
  const xfr_store_ops_t *o = atomic_load(&g_xfr_ops);
  for (int i = 0; o && i < 300; i++) o->rebuilt();
  return NULL;
}
static int life6a(void) {
  rcu_aux_thread_pin();
  if (life_start(g_store, true) != 0) return 1;
  xfr_store_wait_start(5000);
  wait_pass();
  zone_db_entry_t *a = ent("a.test.");
  install(a, 20, XFR_ORIGIN_XFR, time(NULL), 0);
  refresh_end(a, XFR_OUT_TRANSFERRED, time(NULL));
  db_store_stop();
  return g_failed;
}
static int life6(void) {
  printf("[life 6: the restore against a transfer and the tick on one entry; the hooks from several threads]\n");
  rcu_aux_thread_pin();
  atomic_store(&xfr_store_test_restore_hook, race_hook);
  if (life_start(g_store, true) != 0) return 1;
  zone_db_entry_t *a = ent("a.test.");
  pthread_t t, h[3];
  pthread_create(&t, NULL, race_tick, a);
  for (int i = 0; i < 3; i++) pthread_create(&h[i], NULL, race_hooks, NULL);
  for (int i = 0; i < 3; i++) pthread_join(h[i], NULL);
  pthread_join(t, NULL);
  wait_pass();
  CHECK(atomic_load(&g_race_done));
  CHECK_EQ(atomic_load(&g_race_early), 0);
  CHECK(atomic_load(&g_race_skips) > 0);
  CHECK_EQ(atomic_load(&a->serial), 21);                                   /* (no restore over N+1) */
  store_zone_t z;
  CHECK(rec("a.test.", XFR_K_CONFIG, &z) && z.serial == 21);
  db_store_stop();
  return g_failed;
}

static int run_child(int (*fn)(void)) {
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    g_checks = g_failed = 0;
    int f = fn();
    printf("  %d checks, %d failed\n", g_checks, f);
    fflush(stdout);
    _exit(f ? 1 : 0);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  g_checks++;
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
    g_failed++;
    printf("  [FAIL] the child failed (status %d)\n", st);
  }
  return 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  signal(SIGPIPE, SIG_IGN);
  test_state();
  test_key();
  test_identity();
  test_times();
  test_rules();
  snprintf(g_dir, sizeof(g_dir), "/tmp/test_xfr_store.XXXXXX");
  if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 2; }
  snprintf(g_store, sizeof(g_store), "zone-store \"%s/store\";", g_dir);
  snprintf(g_sdir, sizeof(g_sdir), "%s/store", g_dir);
  run_child(life1);
  snprintf(g_store, sizeof(g_store), "zone-store \"%s/store\";", g_dir);
  snprintf(g_sdir, sizeof(g_sdir), "%s/store", g_dir);
  run_child(life2);
  run_child(life2b);
  run_child(life2c);
  run_child(life3);
  run_child(life4);
  run_child(life5);
  run_child(life6a);
  run_child(life6);
  snprintf(g_store, sizeof(g_store), "zone-store \"%s/store7\";", g_dir);
  run_child(life7);
  snprintf(g_store, sizeof(g_store), "zone-store \"%s/store8\";", g_dir);
  snprintf(g_sdir, sizeof(g_sdir), "%s/store8", g_dir);
  run_child(life8);
  char cmd[600];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
  if (system(cmd) != 0) printf("  (could not remove %s)\n", g_dir);
  printf("\ntest_xfr_store: %d checks, %d failed\n", g_checks, g_failed);
  return g_failed ? 1 : 0;
}
