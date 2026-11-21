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
 *     a store that cannot be opened (no pending bit, a reconfiguration's secondary is not held), the 30 s safety net (progress against a stall, R2'), a secondary whose name has no key (life 9: served, not stored, xfr.unstorable), and under TSan
 *     the restore against a concurrent transfer and the hooks of rebuilds from several threads.
 *  3. P3, the database secondaries (a fake loader on socket pairs): their copies (key `d`, the domains.id in the identity, the settings id, R1), the orphan re-check through the
 *     registry, the delete hook and a kind change; the restart without the loader (the restore jobs of 4.4 and every way out of them), the loader's jobs afterwards (one entry
 *     per zone, the copy restored into an entry they make, a damaged copy put whole again), and R3 (the jobs held: a pass keeps every `d` copy).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../dns_config_parser.h"
#include "../dns_db_ingest.h"
#include "../dns_db_store.h"
#include "../dns_db_stream.h"
#include "../dns_epoch_rcu.h"
#include "../dns_park.h"
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

/* P4 (R1, D5): the key of a received settings text in settings.dat, against the keys of the database zones; the form a build that does not know the kind reads (14, downgrade) */
static void test_rxkey(void) {
  printf("[R1: the key of a received settings text (settings.dat)]\n");
  static const char t[] = "allow-transfer { 192.0.2.7; };";
  char k[256];
  const size_t kl = xfr_rx_key_make(t, sizeof(t) - 1, k, sizeof(k));
  CHECK(kl == xfr_rx_key_len(sizeof(t) - 1) && k[0] == '\0');
  const char *tx = NULL;
  size_t tl = 0;
  CHECK_EQ(xfr_rx_key_split(k, kl, &tx, &tl), 1);
  CHECK(tl == sizeof(t) - 1 && tx == k + kl - tl && memcmp(tx, t, tl) == 0);
  /* a database zone's keys: "<profile> NUL <profile text> NUL <zone text>"; with no profile the profile text is empty too */
  static const char d1[] = "\0\0allow-transfer { 192.0.2.7; };", d2[] = "p\0allow-update { none; };\0x";
  CHECK_EQ(xfr_rx_key_split(d1, sizeof(d1) - 1, &tx, &tl), 0);
  CHECK(tx == NULL && tl == 0);
  CHECK_EQ(xfr_rx_key_split(d2, sizeof(d2) - 1, NULL, NULL), 0);
  CHECK_EQ(xfr_rx_key_split(k, 3, NULL, NULL), 0);                         /* (cut inside the mark) */
  CHECK_EQ(xfr_rx_key_split(k, kl - (sizeof(t) - 1), NULL, NULL), -1);                  /* (the mark and no text) */
  char k2[256];
  memcpy(k2, k, kl);
  k2[5] ^= 1;
  CHECK_EQ(xfr_rx_key_split(k2, kl, NULL, NULL), 0);                       /* (another mark) */
  k2[5] ^= 1;
  k2[kl - (sizeof(t) - 1) - 1] = 'x';
  CHECK_EQ(xfr_rx_key_split(k2, kl, NULL, NULL), 0);                       /* (no NUL after the mark) */
  CHECK_EQ(xfr_rx_key_split(NULL, 0, NULL, NULL), 0);
  char *huge = malloc(XFR_RX_TEXT_MAX + 200);
  if (huge) {
    memset(huge, ' ', XFR_RX_TEXT_MAX + 200);
    CHECK_EQ(xfr_rx_key_make(huge, XFR_RX_TEXT_MAX + 1, huge, XFR_RX_TEXT_MAX + 200), 0);   /* (longer than a SETTINGS record) */
    memcpy(huge, k, kl - (sizeof(t) - 1));
    CHECK_EQ(xfr_rx_key_split(huge, kl - (sizeof(t) - 1) + XFR_RX_TEXT_MAX + 1, NULL, NULL), -1);
    CHECK_EQ(xfr_rx_key_split(huge, kl - (sizeof(t) - 1) + XFR_RX_TEXT_MAX, NULL, NULL), 1);
    free(huge);
  }
  CHECK_EQ(xfr_rx_key_make(t, 0, k, sizeof(k)), 0);
  CHECK_EQ(xfr_rx_key_make(t, sizeof(t) - 1, k, 10), 0);
  /* an earlier 0.7 reads the record as a profile's text and the zone's: "<mark>\n<text>", a comment and the text; it parses, and no zone has that key (14) */
  char merged[256];
  const int ml = snprintf(merged, sizeof(merged), "%s\n%s", XFR_RX_MARK, t);
  char err[200];
  zone_ext_shared_t *sh = db_settings_parse(merged, (size_t)ml, err, sizeof(err));
  CHECK(sh != NULL && sh->ext.allow_transfer_count == 1);
  zone_ext_shared_unref(sh);
  /* the parsed object of a transfer carries the key settings.dat keeps */
  sh = zone_rx_settings_parse("r.test.", t, sizeof(t) - 1);
  CHECK(sh && sh->key && sh->key_len == kl && memcmp(sh->key, k, kl) == 0 && !sh->ext.db_acl_ceiling);
  zone_ext_shared_unref(sh);
  CHECK(zone_rx_settings_parse("r.test.", "file \"/etc/passwd\";", 19) == NULL);
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
  xfr_store_wait_start(5000);                                             /* (the GC of the pass runs after the restores, before the pass is done: wait for every asked pass, not for a fixed time) */
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
  /* #203 review (2.5): e.test's is_transferring is held (a refresh that runs after the safety net gave up on it): the restore does not make its record KNOWN, it leaves the record to that refresh */
  zone_db_entry_t *ee = ent("e.test.");
  CHECK(ee != NULL);
  if (ee) atomic_store(&ee->is_transferring, true);
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
  /* d: a bad checksum: KNOWN, empty; e: a serial mismatch, empty, and its record left STORED (its is_transferring was held: no KNOWN marking without it, 2.5) */
  CHECK(rec("d.test.", XFR_K_CONFIG, &z) && z.state == STORE_STATE_KNOWN && atomic_load(&ent("d.test.")->serial) == 0);
  CHECK(rec("e.test.", XFR_K_CONFIG, &z) && z.state == STORE_STATE_STORED && atomic_load(&ent("e.test.")->serial) == 0);
  CHECK(ee && atomic_load(&ee->is_transferring));                          /* (the restore did not take it, nor give it back) */
  if (ee) atomic_store(&ee->is_transferring, false);
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
  {
    uint64_t ne = 0, ns = 0, nf = 0;                                       /* (karictl status: the same gauges; h.test answers SERVFAIL without serve-stale... or stale with it) */
    xfr_store_expired(&ne, &ns, &nf);
    CHECK(ne >= 1 && ne == ns + nf);
  }
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
  /* (#203 review, test 19) a catalog member gained by a transfer of its catalog with the store off: not held either */
  const char *mn[1] = { "gm.test." }, *mu[1] = { "ugm" };
  catalog_members(mn, mu, 1);
  zone_db_entry_t *gm = ent("gm.test.");
  CHECK(gm && gm->is_catalog_member && !atomic_load(&gm->restore_pending));
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
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
  /* (#203 review) a rebuild that comes while the thread is stalled inside its pass asks for another pass and does not hide the stall: no progress is stamped for it */
  rebuild_zone_db_from_config(&c2, false);
  CHECK(xfr_restore_stuck());
  /* (#203 review) the item in work may take its image's read and check beyond the 30 s (a big image is one step) */
  xfr_store_test_item_allow(60000);
  CHECK(!xfr_restore_stuck());
  xfr_store_test_item_allow(0);
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

/* life 9 (2.2, W12): a secondary whose canonical name is longer than 245 octets has no key: it is transferred and served as before, its copy is not stored (xfr.unstorable, one NOTICE),
 * zonestatus says why */
static char g_long_zone[300];
static int life9(void) {
  printf("[life 9: a name too long for a key]\n");
  rcu_aux_thread_pin();
  char lab[62];
  memset(lab, 'a', 61);
  lab[61] = '\0';
  snprintf(g_long_zone, sizeof(g_long_zone), "%s.%s.%s.%s.", lab, lab, lab, lab);                          /* (247 octets without the trailing dot) */
  static char extra[512];
  snprintf(extra, sizeof(extra), "  zone \"%.*s\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n", (int)strlen(g_long_zone) - 1, g_long_zone);
  g_extra_zones = extra;
  if (life_start(g_store, true) != 0) return 1;
  wait_pass();
  zone_db_entry_t *e = ent(g_long_zone);
  CHECK(e != NULL);
  if (!e) return 1;
  const time_t now = time(NULL);
  const xfr_store_counters_t c0 = ctr();
  install(e, 5, XFR_ORIGIN_XFR, now, 0);
  refresh_end(e, XFR_OUT_TRANSFERRED, now);
  const xfr_store_counters_t c1 = ctr();
  CHECK(c1.unstorable > c0.unstorable);
  CHECK_EQ(c1.puts, c0.puts);
  CHECK_EQ(atomic_load(&e->serial), 5);                                    /* (the zone itself is served as before) */
  char zs[1024];
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  const size_t zl = xfr_store_zonestatus(e, cfg, zs, sizeof(zs));
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  CHECK(zl > 0 && strstr(zs, "Store: not kept (the name is too long)") != NULL);
  g_extra_zones = "";
  db_store_stop();
  return g_failed;
}

/* ---- P4 (R1, D5): the settings the primaries sent are kept in settings.dat with the copies ----
 * life R1: r.test and r2.test get one text (written once), r3.test another one past the cap (not kept: XFR_SF_RX_LOST, xfr.rx_capped); an up-to-date refresh keeps the id; zonestatus; an image
 * over 2 GiB is not stored (a fake length).  Between the lives the test makes r2's state name an id settings.dat does not have, and appends hostile records of the kind (no text, a text the
 * restricted parser refuses).  Life R1b, the restart: r.test's settings are in force again from settings.dat (no whole transfer asked), r2 and r3 ask for the whole zone (R2), the hostile
 * records take ids and are never used, and a refresh writes no new text. */
static const char g_rx_extra[] =
    "  zone \"r.test\" { type slave; masters { 192.0.2.1; }; };\n"
    "  zone \"r2.test\" { type slave; masters { 192.0.2.1; }; };\n"
    "  zone \"r3.test\" { type slave; masters { 192.0.2.1; }; };\n"
    "  zone \"big.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; };\n";
static const char g_rx_t1[] = "allow-transfer { 192.0.2.7; };", g_rx_t2[] = "allow-transfer { 192.0.2.8; };";
static void rx_apply(zone_db_entry_t *e, const char *text) {
  zone_ext_shared_t *sh = zone_rx_settings_parse(e->domain, text, strlen(text));
  CHECK(sh != NULL);
  pthread_mutex_lock(&e->writer_lock);
  zone_ext_shared_t *old = zone_rx_settings_apply_locked(e, sh);
  pthread_mutex_unlock(&e->writer_lock);
  zone_ext_shared_unref(old);
}
static int lifer1(void) {
  printf("[life R1: the settings of the primaries kept in settings.dat]\n");
  rcu_aux_thread_pin();
  g_extra_zones = g_rx_extra;
  if (life_start(g_store, true) != 0) return 1;
  wait_pass();
  const time_t now = time(NULL);
  zone_db_entry_t *r = ent("r.test."), *r2 = ent("r2.test."), *r3 = ent("r3.test."), *big = ent("big.test.");
  CHECK(r && r2 && r3 && big);
  if (!r || !r2 || !r3 || !big) return 1;
  install(r, 5, XFR_ORIGIN_XFR, now, 0);
  rx_apply(r, g_rx_t1);
  CHECK(zone_rx_settings_status(r, NULL, 0));
  refresh_end(r, XFR_OUT_TRANSFERRED, now);
  xfr_state_t s;
  CHECK(rec_state("r.test.", XFR_K_CONFIG, &s, NULL) && s.rx_settings != 0 && !(s.flags & XFR_SF_RX_LOST));
  const uint32_t id1 = s.rx_settings;
  xfr_store_counters_t c = ctr();
  CHECK_EQ(c.rx_texts, 1);
  /* the same text for another zone: the same id, nothing appended */
  install(r2, 6, XFR_ORIGIN_XFR, now, 0);
  rx_apply(r2, g_rx_t1);
  refresh_end(r2, XFR_OUT_TRANSFERRED, now);
  CHECK(rec_state("r2.test.", XFR_K_CONFIG, &s, NULL) && s.rx_settings == id1);
  CHECK_EQ(ctr().rx_texts, 1);
  /* an up-to-date refresh writes the state with the id (the parsed object remembers it) */
  refresh_end(r, XFR_OUT_UPTODATE, now + 1);
  CHECK(rec_state("r.test.", XFR_K_CONFIG, &s, NULL) && s.rx_settings == id1 && s.last_attempt == (uint32_t)(now + 1));
  /* the cap reached (1 text here): r3's text is not kept, R2 */
  db_store_test_rx_cap_ids = 1;
  install(r3, 7, XFR_ORIGIN_XFR, now, 0);
  rx_apply(r3, g_rx_t2);
  refresh_end(r3, XFR_OUT_TRANSFERRED, now);
  db_store_test_rx_cap_ids = -1;
  CHECK(rec_state("r3.test.", XFR_K_CONFIG, &s, NULL) && s.rx_settings == 0 && (s.flags & XFR_SF_RX_LOST));
  c = ctr();
  CHECK(c.rx_texts == 1 && c.rx_capped == 1 && c.rx_bytes > 0);
  /* zonestatus says it */
  char zs[1024];
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  (void)xfr_store_zonestatus(r, cfg, zs, sizeof(zs));
  CHECK(strstr(zs, "Store: copy serial 5, ") && strstr(zs, ", the settings of the primary kept\n"));
  (void)xfr_store_zonestatus(r3, cfg, zs, sizeof(zs));
  CHECK(strstr(zs, ", the settings of the primary not kept (a restart asks for the whole zone)\n") != NULL);
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  /* an image over 2 GiB is not stored (W1; the length is faked for the check, then put back) */
  install(big, 3, XFR_ORIGIN_XFR, now, 0);
  zone_version_t *bv = atomic_load(&big->rcu.active);
  CHECK(bv && bv->image);
  if (bv && bv->image) {
    const xfr_store_counters_t b0 = ctr();
    const uint64_t real = bv->image->total_size;
    bv->image->total_size = 0x80000000u;
    refresh_end(big, XFR_OUT_TRANSFERRED, now);
    bv->image->total_size = real;
    const xfr_store_counters_t b1 = ctr();
    CHECK(b1.unstorable == b0.unstorable + 1 && b1.puts == b0.puts);
    store_zone_t bz;
    CHECK(!rec("big.test.", XFR_K_CONFIG, &bz));
    refresh_end(big, XFR_OUT_UPTODATE, now);                                /* (at its real size: stored whole) */
    CHECK(rec("big.test.", XFR_K_CONFIG, &bz) && bz.serial == 3);
  }
  /* for life R1b: r2's state names an id that settings.dat does not have */
  store_zone_t z2;
  CHECK(rec_state("r2.test.", XFR_K_CONFIG, &s, &z2));
  s.rx_settings = 999999;
  uint8_t dg[STORE_DIGEST_LEN];
  xfr_state_encode(&s, dg);
  char k[XFR_KEY_MAX + 1];
  const int kn = xfr_key_make("v1", XFR_K_CONFIG, "r2.test.", k, sizeof(k));
  CHECK_EQ(store_set_digest(db_store_handle(), (uint16_t)xfr_store_vid(), k, (size_t)kn, z2.serial, 0, dg, STORE_F_XFR, 0), 0);
  store_check_report_t cr;
  CHECK_EQ(store_check(db_store_handle(), &cr), 0);
  db_store_stop();
  /* hostile records of the kind at the end of settings.dat: no text; a text the restricted parser refuses */
  char sp[512];
  snprintf(sp, sizeof(sp), "%s/settings.dat", g_sdir);
  int fd = open(sp, O_WRONLY | O_APPEND);
  CHECK(fd >= 0);
  if (fd >= 0) {
    static const char bad[] = "file \"/etc/passwd\";";
    char kb[256];
    const size_t kl = xfr_rx_key_make(bad, sizeof(bad) - 1, kb, sizeof(kb));
    const size_t ke = kl - (sizeof(bad) - 1);                              /* (the mark alone) */
    const struct { const char *k; size_t n; } recs[2] = { { kb, ke }, { kb, kl } };
    for (int i = 0; i < 2; i++) {
      uint32_t h[3] = { 0x4B534554u, (uint32_t)recs[i].n, xfr_crc32c(0, recs[i].k, recs[i].n) };
      CHECK(write(fd, h, 12) == 12 && write(fd, recs[i].k, recs[i].n) == (ssize_t)recs[i].n);
    }
    close(fd);
  }
  g_extra_zones = "";
  return g_failed;
}
static int lifer1b(void) {
  printf("[life R1b: the restart: the settings of the primaries from settings.dat]\n");
  rcu_aux_thread_pin();
  g_extra_zones = g_rx_extra;
  if (life_start(g_store, true) != 0) return 1;
  xfr_store_wait_start(5000);
  wait_pass();
  CHECK_EQ(atomic_load(&g_xfr_pending), 0);
  zone_db_entry_t *r = ent("r.test."), *r2 = ent("r2.test."), *r3 = ent("r3.test.");
  CHECK(r && r2 && r3);
  if (!r || !r2 || !r3) return 1;
  xfr_store_counters_t c = ctr();
  printf("  rx: %llu texts, %llu restored, %llu lost\n", (unsigned long long)c.rx_texts, (unsigned long long)c.rx_restored, (unsigned long long)c.rx_lost);
  /* r: restored with its settings in force, no whole transfer asked */
  CHECK(atomic_load(&r->serial) == 5 && zone_rx_settings_status(r, NULL, 0));
  zone_x_t *rx = zone_x(r);
  CHECK(rx && !atomic_load(&rx->xfr_axfr_once) && rx->rx_sh && rx->rx_sh->ext.allow_transfer_count == 1 && !rx->rx_sh->ext.db_acl_ceiling);
  /* r2 (an id settings.dat does not have) and r3 (not kept): served, and the whole zone is asked for */
  zone_x_t *x2 = zone_x(r2), *x3 = zone_x(r3);
  CHECK(atomic_load(&r2->serial) == 6 && x2 && atomic_load(&x2->xfr_axfr_once) && !zone_rx_settings_status(r2, NULL, 0));
  CHECK(atomic_load(&r3->serial) == 7 && x3 && atomic_load(&x3->xfr_axfr_once));
  CHECK(c.rx_restored == 1 && c.rx_lost == 2);
  CHECK_EQ(c.rx_texts, 3);                                                 /* (the one text and the two hostile records: their ids are taken, unused) */
  CHECK(db_store_rx_settings_get(c.rx_texts + 1) == NULL);                 /* (beyond them) */
  CHECK(db_store_settings_by_id(2) == NULL && db_store_settings_by_id(3) == NULL);   /* (never a database zone's settings) */
  CHECK(db_store_rx_settings_get(2) == NULL && db_store_rx_settings_get(3) == NULL);
  /* a refresh of r writes the id it has, appends nothing */
  const time_t now = time(NULL);
  refresh_end(r, XFR_OUT_UPTODATE, now);
  xfr_state_t s;
  CHECK(rec_state("r.test.", XFR_K_CONFIG, &s, NULL) && s.rx_settings != 0 && !(s.flags & XFR_SF_RX_LOST));
  CHECK_EQ(ctr().rx_texts, 3);
  /* r2 refreshed up to date before its whole transfer: the state keeps saying that its settings are lost */
  refresh_end(r2, XFR_OUT_UPTODATE, now);
  CHECK(rec_state("r2.test.", XFR_K_CONFIG, &s, NULL) && s.rx_settings == 0 && (s.flags & XFR_SF_RX_LOST));
  /* r2's whole transfer brings the text again: the id of the text settings.dat has */
  install(r2, 8, XFR_ORIGIN_XFR, now, 0);
  rx_apply(r2, g_rx_t1);
  if (x2) atomic_store(&x2->xfr_axfr_once, false);                         /* (what handle_axfr_event() does after the install) */
  refresh_end(r2, XFR_OUT_TRANSFERRED, now);
  xfr_state_t sr;
  CHECK(rec_state("r2.test.", XFR_K_CONFIG, &s, NULL) && rec_state("r.test.", XFR_K_CONFIG, &sr, NULL) && s.rx_settings == sr.rx_settings && !(s.flags & XFR_SF_RX_LOST));
  CHECK_EQ(ctr().rx_texts, 3);
  g_extra_zones = "";
  db_store_stop();
  return g_failed;
}

/* ======================================================================================================================= 3. P3: the database secondaries */
/* A server with a database block and the store: a fake loader on socket pairs (the protocol of tests/test_db_store.c) sends SLAVE and CONSUMER zones; the "transfers" are installs as in
 * the lives above.  Lives D1 (the copies are written: key `d`, the domains.id in the identity, the settings id, source id 0, R1 two views with one domains.id; the orphan re-check through the
 * registry; the delete hook; a kind change at run time), D2 (the restart without the loader: the restore jobs; every outcome of 4.4; then the loader's jobs find the entries, restore into
 * an entry they make, put a damaged copy whole again, and a kind change while stopped deletes the old copy), D3 (R3: the jobs held, a pass meanwhile keeps every `d` copy). */

typedef struct {
  int fd;
  kdb_framer_t fr;
  uint8_t body[KDB_MAX_BODY];
  uint8_t buf[65536];
} dch_t;
static dch_t g_dmain;
static int g_dfd = -1;                                     /* the loader's end of the main stream */
static kdb_enc_t g_denc;
static server_config_t g_dcfg;
static char g_dsdir[300];

static bool dch_next(dch_t *c, kdb_msg_t *m, int ms) {
  for (;;) {
    kdb_frame_t fr;
    kdb_rc_t rc = kdb_framer_next(&c->fr, &fr);
    if (rc == KDB_OK) {
      char why[KDB_REASON_LEN];
      return kdb_decode(&fr, KDB_VIEWS_ANY, m, why, sizeof(why)) == KDB_OK;
    }
    if (rc != KDB_MORE) return false;
    struct pollfd p = { c->fd, POLLIN, 0 };
    if (poll(&p, 1, ms) <= 0) return false;
    ssize_t n = read(c->fd, c->buf, sizeof(c->buf));
    if (n <= 0 || kdb_framer_feed(&c->fr, c->buf, (size_t)n) != KDB_OK) return false;
  }
}
static void dsend(void) {
  CHECK(!g_denc.err);
  size_t off = 0;
  while (off < g_denc.len) {
    ssize_t n = write(g_dfd, g_denc.buf + off, g_denc.len - off);
    if (n > 0) off += (size_t)n;
    else if (!(n < 0 && errno == EINTR)) break;
  }
  kdb_enc_reset(&g_denc);
}

/* the views: v1 and v2 take database zones (R1: the same domains.id in both), v9 too in life D1 only (its copy is deleted at the next start: a view that takes no database zones) */
static int db_life_start(bool with_v9) {
  char conf[2048];
  snprintf(conf, sizeof(conf),
           "options { database { driver sqlite3; database-file \"/nonexistent/z.db\"; loader-user \"nobody\"; loader-path \"/bin/true\"; store \"%s\"; }; };\n"
           "view \"v1\" { match-clients { any; }; zone \"cs.test\" { type slave; masters { 192.0.2.1; }; primary-settings no; }; };\n"
           "view \"v2\" { match-clients { none; }; };\n%s",
           g_dsdir, with_v9 ? "view \"v9\" { match-clients { none; }; };\n" : "");
  memset(&g_dcfg, 0, sizeof(g_dcfg));
  if (parse_named_conf(conf, &g_dcfg) != 0) { printf("  [FAIL] the configuration does not parse\n"); return -1; }
  atomic_store_explicit(&g_config_db.active, &g_dcfg, memory_order_release);
  xfr_store_want(db_store_wanted(&g_dcfg));
  rebuild_zone_db_from_config(&g_dcfg, false);
  char msg[1024];
  int lvl = 0;
  if (!db_store_frontend_open_cfg(&g_dcfg, false, (uid_t)-1, (gid_t)-1, msg, sizeof(msg), &lvl)) { printf("  frontend: %s\n", msg); return -1; }
  if (!db_store_start(&g_dcfg)) return -1;
  int a[2], f[2], cs[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, a) != 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, f) != 0 || socketpair(AF_UNIX, SOCK_SEQPACKET, 0, cs) != 0) return -1;
  int ends[3] = { a[1], f[1], cs[1] };
  for (int i = 0; i < 3; i++) fcntl(ends[i], F_SETFL, fcntl(ends[i], F_GETFL, 0) | O_NONBLOCK);
  park_register_worker(0, -1);
  if (!db_ingest_start(a[1], cs[1], f[1])) return -1;
  g_dfd = a[0];
  g_dmain.fd = a[0];
  kdb_framer_init(&g_dmain.fr, KDB_FROM_BACKEND, g_dmain.body, sizeof(g_dmain.body));
  kdb_enc_init(&g_denc);
  return 0;
}
static void db_hello(void) {
  kdb_msg_t m;
  kdb_enc_begin(&g_denc, KDB_T_HELLO);
  kdb_enc_u16(&g_denc, 1, 1); kdb_enc_str(&g_denc, 2, "test-loader"); kdb_enc_str(&g_denc, 3, "sqlite3"); kdb_enc_u32(&g_denc, 4, 4242); kdb_enc_u32(&g_denc, 5, KDB_FEAT_IMAGE);
  kdb_enc_u32(&g_denc, 6, ZONE_IMAGE_VERSION);
  kdb_enc_end(&g_denc);
  dsend();
  CHECK(dch_next(&g_dmain, &m, 5000) && m.type == KDB_T_CONFIG);
  CHECK(dch_next(&g_dmain, &m, 5000) && m.type == KDB_T_DEBUG);
}
typedef struct { uint16_t view; const char *zone; int64_t sid; uint8_t kind; } dz_t;
/* one batch of secondary zones (ZONE_BEGIN of a secondary kind without data, the masters in the settings text), then BATCH_END and the answers up to BATCH_RESULT */
static void db_batch(uint64_t id, const dz_t *z, int n) {
  kdb_msg_t m;
  kdb_enc_begin(&g_denc, KDB_T_BATCH_BEGIN);
  kdb_enc_u64(&g_denc, 1, id); kdb_enc_u8(&g_denc, 2, (uint8_t)KDB_BATCH_DIFF); kdb_enc_u64(&g_denc, 3, 0);
  kdb_enc_end(&g_denc);
  dsend();
  for (int i = 0; i < n; i++) {
    uint8_t dig[KDB_DIGEST_LEN];
    memset(dig, 0xCD, sizeof(dig));
    kdb_enc_begin(&g_denc, KDB_T_ZONE_BEGIN);
    kdb_enc_u16(&g_denc, 1, z[i].view); kdb_enc_name(&g_denc, 2, z[i].zone); kdb_enc_i64(&g_denc, 3, z[i].sid); kdb_enc_u8(&g_denc, 4, z[i].kind);
    kdb_enc_u32(&g_denc, 5, 0); kdb_enc_u32(&g_denc, 6, 0); kdb_enc_u64(&g_denc, 7, 0); kdb_enc_bytes(&g_denc, 8, dig, sizeof(dig));
    kdb_enc_str(&g_denc, 9, "masters { 192.0.2.1; };");
    kdb_enc_end(&g_denc);
    kdb_enc_begin(&g_denc, KDB_T_ZONE_END);
    kdb_enc_u64(&g_denc, 1, 0);
    kdb_enc_end(&g_denc);
    dsend();
  }
  kdb_enc_begin(&g_denc, KDB_T_BATCH_END);
  kdb_enc_u64(&g_denc, 1, id); kdb_enc_u32(&g_denc, 2, (uint32_t)n); kdb_enc_u32(&g_denc, 3, 0); kdb_enc_u32(&g_denc, 4, 0);
  kdb_enc_end(&g_denc);
  dsend();
  bool got = false;
  while (dch_next(&g_dmain, &m, 5000)) {
    if (m.type == KDB_T_BATCH_RESULT) { got = true; break; }
  }
  CHECK(got);
}
static void db_delete(uint64_t id, uint16_t view, const char *zone, int64_t sid) {
  kdb_msg_t m;
  kdb_enc_begin(&g_denc, KDB_T_BATCH_BEGIN);
  kdb_enc_u64(&g_denc, 1, id); kdb_enc_u8(&g_denc, 2, (uint8_t)KDB_BATCH_DIFF); kdb_enc_u64(&g_denc, 3, 0);
  kdb_enc_end(&g_denc);
  kdb_enc_begin(&g_denc, KDB_T_ZONE_DELETE);
  kdb_enc_u16(&g_denc, 1, view); kdb_enc_name(&g_denc, 2, zone); kdb_enc_i64(&g_denc, 3, sid);
  kdb_enc_end(&g_denc);
  dsend();
  CHECK(dch_next(&g_dmain, &m, 5000) && m.type == KDB_T_ZONE_RESULT && m.u.zone_result.status == KDB_ST_DELETED);
  kdb_enc_begin(&g_denc, KDB_T_BATCH_END);
  kdb_enc_u64(&g_denc, 1, id); kdb_enc_u32(&g_denc, 2, 0); kdb_enc_u32(&g_denc, 3, 0); kdb_enc_u32(&g_denc, 4, 1);
  kdb_enc_end(&g_denc);
  dsend();
  bool got = false;
  while (dch_next(&g_dmain, &m, 5000)) {
    if (m.type == KDB_T_BATCH_RESULT) { got = true; break; }
  }
  CHECK(got);
}
static zone_db_entry_t *dent(const char *view, const char *zone, int ms) {
  for (int i = 0; i <= ms / 10; i++) {
    zone_db_entry_t *e = dbreg_lookup_entry(view, zone);
    if (e || ms == 0) return e;
    usleep(10000);
  }
  return NULL;
}
static bool drec(const char *view, int kind, const char *zone, store_zone_t *z, xfr_state_t *s) {
  store_t *st = db_store_handle();
  char k[XFR_KEY_MAX + 1];
  const int n = xfr_key_make(view, kind, zone, k, sizeof(k));
  if (!st || n < 0 || xfr_store_vid() < 0) return false;
  store_read_lock();
  const uint32_t zid = store_find(st, (uint16_t)xfr_store_vid(), k, (size_t)n);
  const bool ok = zid != STORE_NONE && store_zone_get(st, zid, z) == 0;
  store_read_unlock();
  return ok && (!s || xfr_state_decode(z->digest, sizeof(z->digest), s) == 0);
}
/* the copy is gone within ms (the GC of a pass, asked for by a hook) */
static bool drec_gone(const char *view, const char *zone, int ms) {
  store_zone_t z;
  for (int i = 0; i <= ms / 10; i++) {
    if (!drec(view, XFR_K_DB_SLAVE, zone, &z, NULL)) return true;
    usleep(10000);
  }
  return false;
}
/* the reconcile's record of a secondary of the database view (recon_meta(): KNOWN, STORE_F_NONSTORE, the domains.id) */
static void nonstore(const char *view, const char *zone, int64_t sid) {
  store_t *st = db_store_handle();
  const int vid = store_view_id(st, view);
  CHECK(vid >= 0);
  store_meta_t m;
  memset(&m, 0, sizeof(m));
  m.source_id = sid;
  m.source = (uint16_t)vid;
  m.flags = STORE_F_NONSTORE;
  char n[300];
  snprintf(n, sizeof(n), "%s", zone);
  size_t l = strlen(n);
  if (l && n[l - 1] == '.') n[--l] = '\0';
  CHECK_EQ(store_set_known(st, (uint16_t)vid, n, l, &m, NULL), 0);
}
static void damage_d(const char *view, const char *zone) {
  store_zone_t z;
  if (!drec(view, XFR_K_DB_SLAVE, zone, &z, NULL)) { CHECK(0); return; }
  char p[512];
  snprintf(p, sizeof(p), "%s/seg.%llu", g_dsdir, (unsigned long long)(z.loc >> 36));
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
static uint32_t served_serial(zone_db_entry_t *e) {
  uint32_t s = 0;
  rcu_aux_read_lock();
  zone_version_t *v = atomic_load(&e->rcu.active);
  zone_image_soa_t nums;
  const uint32_t soa = v && v->image ? zone_image_apex_soa(v->image) : ZONE_IMAGE_NONE;
  if (soa != ZONE_IMAGE_NONE && zone_image_soa(v->image, soa, NULL, 0, NULL, 0, &nums) == 0) s = nums.serial;
  rcu_aux_read_unlock();
  return s;
}

static const dz_t g_dz1[] = {
  { 0, "s1.test.", 501, KDB_ZK_SECONDARY },  { 1, "s1.test.", 501, KDB_ZK_SECONDARY },   /* (R1: one domains.id in two views) */
  { 0, "del.test.", 502, KDB_ZK_SECONDARY }, { 0, "sid.test.", 503, KDB_ZK_SECONDARY }, { 0, "noset.test.", 504, KDB_ZK_SECONDARY },
  { 0, "kind.test.", 505, KDB_ZK_SECONDARY }, { 2, "v9z.test.", 506, KDB_ZK_SECONDARY }, { 0, "bad.test.", 507, KDB_ZK_SECONDARY },
  { 0, "c5.test.", 508, KDB_ZK_CATALOG },     { 0, "gone.test.", 509, KDB_ZK_SECONDARY }, { 0, "flip.test.", 510, KDB_ZK_SECONDARY },
  { 0, "orph.test.", 511, KDB_ZK_SECONDARY },
};
#define NDZ1 ((int)(sizeof(g_dz1) / sizeof(g_dz1[0])))
static const char *dvn(uint16_t v) { return v == 0 ? "v1" : v == 1 ? "v2" : "v9"; }

/* life D1: the copies of the database secondaries are written */
static int lifed1(void) {
  printf("[life D1: the copies of the database secondaries]\n");
  rcu_aux_thread_pin();
  const time_t now = time(NULL);
  if (db_life_start(true) != 0) return 1;
  xfr_store_wait_start(5000);
  CHECK(xfr_store_active());
  db_hello();
  db_batch(1, g_dz1, NDZ1);
  zone_db_entry_t *e[NDZ1];
  for (int i = 0; i < NDZ1; i++) {
    e[i] = dent(dvn(g_dz1[i].view), g_dz1[i].zone, 2000);
    CHECK(e[i] != NULL);
    if (!e[i]) return 1;
    CHECK_EQ(atomic_load(&zone_x(e[i])->xfr_db_sid), g_dz1[i].sid);
  }
  /* orph.test leaves the registry between its install and the end of its refresh: the copy written is deleted again (M6, through the registry) */
  install(e[11], 30, XFR_ORIGIN_XFR, now - 10, 0);
  CHECK_EQ(dbreg_delete("v1", "orph.test.", 511), 1);
  xfr_store_counters_t c0 = ctr();
  refresh_end(e[11], XFR_OUT_TRANSFERRED, now - 11);
  CHECK_EQ(ctr().orphans_deleted, c0.orphans_deleted + 1);
  store_zone_t z;
  xfr_state_t s;
  CHECK(!drec("v1", XFR_K_DB_SLAVE, "orph.test.", &z, NULL));
  for (int i = 0; i < NDZ1 - 1; i++) {
    install(e[i], (uint32_t)(10 + i), XFR_ORIGIN_XFR, now - 10, 0);
    refresh_end(e[i], XFR_OUT_TRANSFERRED, now - 11);
    const char *v = dvn(g_dz1[i].view);
    const int kind = g_dz1[i].kind == KDB_ZK_CATALOG ? XFR_K_DB_CONSUMER : XFR_K_DB_SLAVE;
    CHECK(drec(v, kind, g_dz1[i].zone, &z, &s));
    CHECK(z.state == STORE_STATE_STORED && (z.flags & STORE_F_XFR) && !(z.flags & STORE_F_NONSTORE) && z.serial == (uint32_t)(10 + i) && z.source_id == 0 && z.settings != 0);
    CHECK_EQ(s.kind, kind);
    CHECK_EQ(s.identity, xfr_identity(kind, g_dz1[i].zone, v, NULL, g_dz1[i].sid));
    CHECK(z.name[8] == 'd');
    CHECK(db_store_settings_by_id(z.settings) != NULL);
  }
  /* R1: one domains.id in two views: two copies, two keys */
  store_zone_t z1, z2;
  CHECK(drec("v1", XFR_K_DB_SLAVE, "s1.test.", &z1, NULL) && drec("v2", XFR_K_DB_SLAVE, "s1.test.", &z2, NULL) && z1.zid != z2.zid);
  /* the memory advice does not count the copies as zones of the database (review of #203) */
  {
    ma_in_t in;
    memset(&in, 0, sizeof(in));
    db_store_ma_inputs(&in);
    CHECK_EQ(in.stored_zones, 0);
    CHECK_EQ(in.stored_image_bytes, 0);
  }
  /* a failure write with the same settings id and nothing new is left out; a changed settings id is written (3.1 skip rule) */
  {
    store_t *st = db_store_handle();
    char k[XFR_KEY_MAX + 1];
    const int kn = xfr_key_make("v1", XFR_K_DB_SLAVE, "kind.test.", k, sizeof(k));
    CHECK(drec("v1", XFR_K_DB_SLAVE, "kind.test.", &z, NULL));
    const uint32_t sid0 = z.settings;
    refresh_end(e[5], XFR_OUT_FAILED, now);
    xfr_store_counters_t f0 = ctr();
    refresh_end(e[5], XFR_OUT_FAILED, now + 1);
    CHECK_EQ(ctr().state_skipped, f0.state_skipped + 1);
    CHECK_EQ(store_set_digest(st, (uint16_t)xfr_store_vid(), k, (size_t)kn, z.serial, 0, z.digest, STORE_F_XFR, 0), 0);   /* (as if the settings had changed) */
    xfr_store_counters_t f1 = ctr();
    refresh_end(e[5], XFR_OUT_FAILED, now + 2);
    CHECK_EQ(ctr().state_writes, f1.state_writes + 1);
    CHECK(drec("v1", XFR_K_DB_SLAVE, "kind.test.", &z, NULL) && z.settings == sid0);
  }
  /* the reconcile's records the restart looks at (del.test: none; sid.test: another domains.id; v9z.test: its view is gone at the restart) */
  nonstore("v1", "s1.test.", 501);
  nonstore("v2", "s1.test.", 501);
  nonstore("v1", "sid.test.", 999);
  nonstore("v1", "noset.test.", 504);
  nonstore("v1", "kind.test.", 505);
  nonstore("v1", "bad.test.", 507);
  nonstore("v1", "c5.test.", 508);
  /* noset.test: its copy names settings that settings.dat does not have */
  {
    store_t *st = db_store_handle();
    char k[XFR_KEY_MAX + 1];
    const int kn = xfr_key_make("v1", XFR_K_DB_SLAVE, "noset.test.", k, sizeof(k));
    CHECK(drec("v1", XFR_K_DB_SLAVE, "noset.test.", &z, NULL));
    CHECK_EQ(store_set_digest(st, (uint16_t)xfr_store_vid(), k, (size_t)kn, z.serial, 0x7FFFFF, z.digest, STORE_F_XFR, 0), 0);
  }
  /* the delete hook: a row deleted (ZONE_DELETE) takes its copy with it at the next pass */
  CHECK(drec("v1", XFR_K_DB_SLAVE, "gone.test.", &z, NULL));
  db_delete(2, 0, "gone.test.", 509);
  CHECK(drec_gone("v1", "gone.test.", 5000));
  /* a kind change at run time: the CONSUMER entry replaces the SLAVE one, the SLAVE's copy (another identity) goes */
  const dz_t flip = { 0, "flip.test.", 510, KDB_ZK_CATALOG };
  db_batch(3, &flip, 1);
  zone_db_entry_t *fe = dent("v1", "flip.test.", 0);
  CHECK(fe && fe != e[10]);
  CHECK(drec_gone("v1", "flip.test.", 5000));
  /* zonestatus has the `Store:` line for a database secondary too */
  char zs[1024];
  rcu_aux_read_lock();
  server_config_t *cfg = acquire_config_snapshot();
  const size_t zl = xfr_store_zonestatus(e[0], cfg, zs, sizeof(zs));
  release_config_snapshot(cfg);
  rcu_aux_read_unlock();
  CHECK(zl > 0 && strstr(zs, "Store: copy serial 10, ") != NULL);
  /* P4 (11): dbstatus <zone> of a database secondary has the same lines, indented */
  char ds[8192];
  (void)db_ingest_status("s1.test.", "v1", ds, sizeof(ds));
  CHECK(strstr(ds, "\n  Store: copy serial 10, ") != NULL && strstr(ds, "\n  Last-refresh: ") != NULL);
  if (!strstr(ds, "\n  Store: copy serial 10, ")) printf("%s", ds);
  damage_d("v1", "bad.test.");                                           /* (a bad checksum for the restart) */
  db_store_stop();
  return g_failed;
}

/* life D2: the restart, the loader away: the restore jobs (4.4), then the loader's jobs */
static int lifed2(void) {
  printf("[life D2: the restart without the loader; then the loader]\n");
  rcu_aux_thread_pin();
  if (db_life_start(false) != 0) return 1;
  xfr_store_wait_start(5000);
  zone_db_entry_t *s1 = dent("v1", "s1.test.", 5000), *s2 = dent("v2", "s1.test.", 5000);
  CHECK(s1 && s2 && s1 != s2);
  if (!s1 || !s2) return 1;
  CHECK_EQ(served_serial(s1), 10);
  CHECK_EQ(served_serial(s2), 11);
  CHECK_EQ(atomic_load(&s1->serial), 10);
  CHECK_EQ(atomic_load(&zone_x(s1)->xfr_db_sid), 501);
  CHECK(!atomic_load(&s1->restore_pending) && s1->source == ZONE_SRC_DB && s1->is_secondary);
  CHECK(atomic_load(&s1->last_successful_transfer) > 0);
  zone_db_entry_t *ke = dent("v1", "kind.test.", 2000), *ce = dent("v1", "c5.test.", 2000);
  CHECK(ke && served_serial(ke) == 15);
  const zone_config_t *cc = ce ? atomic_load(&ce->dbcfg) : NULL;
  CHECK(ce && cc && cc->is_catalog && served_serial(ce) == 18);
  /* the jobs that do not make an entry: del.test (no record of the reconcile: the row went while stopped), sid.test (another domains.id: a new row of that name), noset.test (the settings
   * are not in settings.dat: it waits for the loader), bad.test (a bad checksum: made KNOWN), v9z.test (its view takes no database zones any more: deleted by the scan) */
  CHECK(drec_gone("v1", "del.test.", 5000));
  CHECK(drec_gone("v1", "sid.test.", 5000));
  CHECK(drec_gone("v9", "v9z.test.", 1000));
  CHECK(!dent("v1", "del.test.", 0) && !dent("v1", "sid.test.", 0) && !dent("v1", "noset.test.", 0) && !dent("v1", "bad.test.", 0));
  store_zone_t z;
  CHECK(drec("v1", XFR_K_DB_SLAVE, "noset.test.", &z, NULL) && z.state == STORE_STATE_STORED);
  CHECK(drec("v1", XFR_K_DB_SLAVE, "bad.test.", &z, NULL) && z.state == STORE_STATE_KNOWN);
  CHECK(ctr().restore_bad >= 1);
  /* the loader: its jobs find the restored entries (one entry per zone, M4 c), restore into the entry they make (noset.test, its settings come with the job), make an empty one for the
   * KNOWN copy (bad.test), whose next up-to-date refresh puts the image whole (M2), and a kind change while stopped replaces the entry (kind.test: the SLAVE copy goes) */
  db_hello();
  const dz_t b2[] = { { 0, "s1.test.", 501, KDB_ZK_SECONDARY }, { 1, "s1.test.", 501, KDB_ZK_SECONDARY }, { 0, "noset.test.", 504, KDB_ZK_SECONDARY },
                      { 0, "bad.test.", 507, KDB_ZK_SECONDARY }, { 0, "kind.test.", 505, KDB_ZK_CATALOG } };
  db_batch(4, b2, 5);
  CHECK(dent("v1", "s1.test.", 0) == s1 && dent("v2", "s1.test.", 0) == s2);
  zone_db_entry_t *ne = dent("v1", "noset.test.", 0), *be = dent("v1", "bad.test.", 0);
  CHECK(ne && served_serial(ne) == 14);
  CHECK(be && served_serial(be) == 0);
  if (be) {
    install(be, 17, XFR_ORIGIN_XFR, time(NULL), 0);
    xfr_store_counters_t u0 = ctr();
    refresh_end(be, XFR_OUT_UPTODATE, time(NULL));
    CHECK_EQ(ctr().puts_uptodate, u0.puts_uptodate + 1);
    CHECK(drec("v1", XFR_K_DB_SLAVE, "bad.test.", &z, NULL) && z.state == STORE_STATE_STORED && z.serial == 17);
  }
  CHECK(dent("v1", "kind.test.", 0) != ke);
  CHECK(drec_gone("v1", "kind.test.", 5000));
  /* the copies that have their zone are kept by the GC */
  const xfr_store_ops_t *o = atomic_load(&g_xfr_ops);
  if (o) o->rebuilt();
  xfr_store_wait_start(5000);
  CHECK(drec("v1", XFR_K_DB_SLAVE, "s1.test.", &z, NULL) && drec("v2", XFR_K_DB_SLAVE, "s1.test.", &z, NULL) && drec("v1", XFR_K_DB_SLAVE, "noset.test.", &z, NULL));
  CHECK(drec("v1", XFR_K_DB_CONSUMER, "c5.test.", &z, NULL));
  store_check_report_t cr;
  CHECK_EQ(store_check(db_store_handle(), &cr), 0);
  CHECK_EQ(cr.errors, 0);
  db_store_stop();
  return g_failed;
}

/* life D3 (R3): the restore jobs held on the ingest thread; a pass meanwhile (a reconfiguration) keeps every `d` copy; released, they are restored */
static _Atomic int g_dj_hold, g_dj_seen;
static void dj_hook(const char *zone) {
  (void)zone;
  atomic_fetch_add(&g_dj_seen, 1);
  for (int i = 0; i < 1000 && atomic_load(&g_dj_hold); i++) usleep(10000);         /* (bounded: 10 s) */
}
static int lifed3(void) {
  printf("[life D3: the restore jobs held; the GC keeps the copies (R3)]\n");
  rcu_aux_thread_pin();
  atomic_store(&g_dj_hold, 1);
  atomic_store(&db_ingest_test_xfr_job_hook, dj_hook);
  if (db_life_start(false) != 0) return 1;
  xfr_store_wait_start(5000);
  for (int i = 0; i < 500 && atomic_load(&g_dj_seen) == 0; i++) usleep(10000);
  CHECK(atomic_load(&g_dj_seen) > 0);
  const xfr_store_ops_t *o = atomic_load(&g_xfr_ops);
  CHECK(o != NULL);
  if (o) o->rebuilt();                                                   /* (a reconfiguration's pass while the jobs wait) */
  xfr_store_wait_start(5000);
  store_zone_t z;
  CHECK(drec("v1", XFR_K_DB_SLAVE, "s1.test.", &z, NULL) && drec("v2", XFR_K_DB_SLAVE, "s1.test.", &z, NULL) && drec("v1", XFR_K_DB_SLAVE, "noset.test.", &z, NULL));
  CHECK(!dent("v1", "s1.test.", 0));
  atomic_store(&g_dj_hold, 0);
  CHECK(dent("v1", "s1.test.", 5000) != NULL && dent("v2", "s1.test.", 5000) != NULL);
  /* noset.test has no entry (the loader is away and its settings are not known): once every job ran, the GC keeps its copy, which the reconcile's record of the zone names (it waits
   * for the loader); after a pass with the jobs done too */
  if (o) o->rebuilt();
  xfr_store_wait_start(5000);
  CHECK(drec("v1", XFR_K_DB_SLAVE, "noset.test.", &z, NULL) && !dent("v1", "noset.test.", 0));
  CHECK(drec("v1", XFR_K_DB_SLAVE, "s1.test.", &z, NULL));
  atomic_store(&db_ingest_test_xfr_job_hook, NULL);
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
  test_rxkey();
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
  snprintf(g_store, sizeof(g_store), "zone-store \"%s/store9\";", g_dir);
  run_child(life9);
  snprintf(g_store, sizeof(g_store), "zone-store \"%s/storer\";", g_dir);
  snprintf(g_sdir, sizeof(g_sdir), "%s/storer", g_dir);
  run_child(lifer1);
  run_child(lifer1b);
  snprintf(g_dsdir, sizeof(g_dsdir), "%s/dbstore", g_dir);
  run_child(lifed1);
  run_child(lifed2);
  run_child(lifed3);
  char cmd[600];
  snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
  if (system(cmd) != 0) printf("  (could not remove %s)\n", g_dir);
  printf("\ntest_xfr_store: %d checks, %d failed\n", g_checks, g_failed);
  return g_failed ? 1 : 0;
}
