/*
 * test_plugin_msg.c - the checks of the plugin messages between the manager and the Backend (dns_plugin_msg.c, 0.6.2).
 *
 * The Backend's parser (plug_check_from_manager) must refuse a record of the wrong size, a cut one, a bad magic or type, a slot out of
 * range or not in use, another generation, a start number that does not move on (UP) or is not the current one (DOWN), the wrong number
 * of descriptors, text in the fields the manager leaves empty, and fields that must be 0.  The manager's parser (plug_check_from_backend)
 * the same for START / STOP / KILL, and a zone, view or fingerprint that is not a text of the right form.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../dns_plugin_msg.h"
#include "../dns_log_state.h"

static int g_fail, g_checks;
#define CHECK(c)                                                                \
    do {                                                                        \
        g_checks++;                                                             \
        if (!(c)) {                                                             \
            g_fail++;                                                           \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);        \
        }                                                                       \
    } while (0)

static plug_expect_t ex[PLUG_SLOTS];

static plug_err_t from_mgr(const plug_msg_t *m, int flags, int nfds) {
    plug_msg_t out;
    return plug_check_from_manager(m, sizeof(*m), flags, nfds, ex, PLUG_SLOTS, &out);
}

static plug_err_t from_bk(const plug_msg_t *m, int nfds) {
    plug_msg_t out;
    return plug_check_from_backend(m, sizeof(*m), 0, nfds, &out);
}

static void start_msg(plug_msg_t *m, uint32_t slot, uint32_t gen) {
    plug_msg_init(m, PLUG_MSG_START, slot, gen, 0);
    strcpy(m->zone, "prog.example.");
    strcpy(m->view, "_default");
    strcpy(m->fingerprint, "0123456789abcdef");
}

static void test_from_manager(void) {
    printf("[TEST] the Backend's check of the manager's records...\n");
    memset(ex, 0, sizeof(ex));
    ex[3].gen = 7;
    ex[3].seq = 1;
    plug_msg_t m, out;
    plug_msg_init(&m, PLUG_MSG_UP, 3, 7, 2);
    m.pid = 1234;
    CHECK(from_mgr(&m, 0, PLUG_UP_NFDS) == PLUG_OK);
    CHECK(plug_check_from_manager(&m, sizeof(m), 0, PLUG_UP_NFDS, ex, PLUG_SLOTS, &out) == PLUG_OK && out.slot == 3 && out.seq == 2);
    /* size, cut, magic, type */
    CHECK(plug_check_from_manager(&m, sizeof(m) - 1, 0, PLUG_UP_NFDS, ex, PLUG_SLOTS, &out) == PLUG_E_SIZE);
    CHECK(plug_check_from_manager(&m, sizeof(m) + 1, 0, PLUG_UP_NFDS, ex, PLUG_SLOTS, &out) == PLUG_E_SIZE);
    CHECK(plug_check_from_manager(NULL, sizeof(m), 0, PLUG_UP_NFDS, ex, PLUG_SLOTS, &out) == PLUG_E_SIZE);
    CHECK(from_mgr(&m, MSG_TRUNC, PLUG_UP_NFDS) == PLUG_E_TRUNC);
    CHECK(from_mgr(&m, MSG_CTRUNC, PLUG_UP_NFDS) == PLUG_E_TRUNC);
    plug_msg_t b = m;
    b.magic ^= 1;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_MAGIC);
    b = m;
    b.type = PLUG_MSG_START;   /* a type only the Backend sends */
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_TYPE);
    b.type = 99;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_TYPE);
    /* slot: out of range, not in use, beyond the expectations given */
    b = m;
    b.slot = PLUG_SLOTS;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_SLOT);
    b.slot = 0xFFFFFFFFu;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_SLOT);
    b.slot = 4;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_SLOT);
    CHECK(plug_check_from_manager(&m, sizeof(m), 0, PLUG_UP_NFDS, ex, 3, &out) == PLUG_E_SLOT);
    CHECK(plug_check_from_manager(&m, sizeof(m), 0, PLUG_UP_NFDS, NULL, PLUG_SLOTS, &out) == PLUG_E_SLOT);
    /* generation */
    b = m;
    b.gen = 6;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_GEN);
    b.gen = 0;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_GEN);
    /* UP: the start number moves on; the descriptors; pid; flags */
    b = m;
    b.seq = 1;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_SEQ);
    b.seq = 0;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_SEQ);
    CHECK(from_mgr(&m, 0, 0) == PLUG_E_FDS);
    CHECK(from_mgr(&m, 0, PLUG_UP_NFDS - 1) == PLUG_E_FDS);
    CHECK(from_mgr(&m, 0, PLUG_UP_NFDS + 1) == PLUG_E_FDS);
    b = m;
    b.pid = 0;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_FIELD);
    b.pid = -5;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_FIELD);
    b = m;
    b.flags = PLUG_DOWN_REFUSED;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_FIELD);
    b = m;
    b.status = 9;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_FIELD);
    /* the text fields stay empty */
    b = m;
    b.zone[0] = 'x';
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_TEXT);
    b = m;
    b.view[PLUG_VIEW_MAX - 1] = 'x';
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_TEXT);
    b = m;
    b.fingerprint[3] = 'x';
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_E_TEXT);
    /* DOWN: the current start, no descriptor, REFUSED only before any start */
    plug_msg_t d;
    plug_msg_init(&d, PLUG_MSG_DOWN, 3, 7, 1);
    d.status = 0x0100;   /* exit 1 */
    CHECK(from_mgr(&d, 0, 0) == PLUG_OK);
    CHECK(from_mgr(&d, 0, 1) == PLUG_E_FDS);
    d.seq = 2;
    CHECK(from_mgr(&d, 0, 0) == PLUG_E_SEQ);
    d.seq = 1;
    d.flags = PLUG_DOWN_REFUSED;
    CHECK(from_mgr(&d, 0, 0) == PLUG_E_SEQ);
    d.flags = 2;
    CHECK(from_mgr(&d, 0, 0) == PLUG_E_FIELD);
    d.flags = 0;
    d.pid = 1;
    CHECK(from_mgr(&d, 0, 0) == PLUG_E_FIELD);
    ex[5].gen = 9;   /* a START that has had no answer yet */
    plug_msg_init(&d, PLUG_MSG_DOWN, 5, 9, 0);
    d.flags = PLUG_DOWN_REFUSED;
    CHECK(from_mgr(&d, 0, 0) == PLUG_OK);
    plug_msg_init(&b, PLUG_MSG_UP, 5, 9, 1);
    b.pid = 2;
    CHECK(from_mgr(&b, 0, PLUG_UP_NFDS) == PLUG_OK);
    /* an unaligned buffer */
    unsigned char raw[sizeof(plug_msg_t) + 1];
    memcpy(raw + 1, &m, sizeof(m));
    CHECK(plug_check_from_manager(raw + 1, sizeof(m), 0, PLUG_UP_NFDS, ex, PLUG_SLOTS, &out) == PLUG_OK && out.pid == 1234);
}

static void test_from_backend(void) {
    printf("[TEST] the manager's check of the Backend's records...\n");
    plug_msg_t m, b, out;
    start_msg(&m, 0, 1);
    CHECK(from_bk(&m, 0) == PLUG_OK);
    CHECK(plug_check_from_backend(&m, sizeof(m), 0, 0, &out) == PLUG_OK && strcmp(out.zone, "prog.example.") == 0);
    CHECK(plug_check_from_backend(&m, sizeof(m) - 4, 0, 0, &out) == PLUG_E_SIZE);
    CHECK(plug_check_from_backend(&m, sizeof(m), MSG_TRUNC, 0, &out) == PLUG_E_TRUNC);
    CHECK(from_bk(&m, 1) == PLUG_E_FDS);   /* the Backend never sends a descriptor */
    b = m;
    b.magic = 0;
    CHECK(from_bk(&b, 0) == PLUG_E_MAGIC);
    b = m;
    b.type = PLUG_MSG_UP;
    CHECK(from_bk(&b, 0) == PLUG_E_TYPE);
    b = m;
    b.slot = PLUG_SLOTS;
    CHECK(from_bk(&b, 0) == PLUG_E_SLOT);
    b.slot = PLUG_SLOTS - 1;
    CHECK(from_bk(&b, 0) == PLUG_OK);
    b = m;
    b.gen = 0;
    CHECK(from_bk(&b, 0) == PLUG_E_GEN);
    b = m;
    b.seq = 1;
    CHECK(from_bk(&b, 0) == PLUG_E_SEQ);
    b = m;
    b.pid = 1;
    CHECK(from_bk(&b, 0) == PLUG_E_FIELD);
    b = m;
    b.status = 1;
    CHECK(from_bk(&b, 0) == PLUG_E_FIELD);
    b = m;
    b.flags = 1;
    CHECK(from_bk(&b, 0) == PLUG_E_FIELD);
    /* the zone: 1..255 bytes, NUL-terminated in the field, printable */
    b = m;
    b.zone[0] = '\0';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    b = m;
    memset(b.zone, 'a', sizeof(b.zone));
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    b.zone[sizeof(b.zone) - 1] = '\0';
    CHECK(from_bk(&b, 0) == PLUG_OK);
    b = m;
    b.zone[2] = '\n';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    b = m;
    b.zone[2] = (char)0x80;
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    /* the view: may be empty, NUL-terminated, printable */
    b = m;
    b.view[0] = '\0';
    CHECK(from_bk(&b, 0) == PLUG_OK);
    memset(b.view, 'v', sizeof(b.view));
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    b = m;
    b.view[1] = '\x1b';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    /* the fingerprint: 16 lowercase hex digits, the rest NUL */
    b = m;
    b.fingerprint[5] = 'A';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    b = m;
    b.fingerprint[15] = '\0';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    b = m;
    b.fingerprint[16] = '0';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    b = m;
    b.fingerprint[PLUG_FP_MAX - 1] = 'z';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    /* STOP and KILL: no text; KILL names a start, STOP none */
    plug_msg_init(&b, PLUG_MSG_STOP, 4, 2, 0);
    CHECK(from_bk(&b, 0) == PLUG_OK);
    b.seq = 1;
    CHECK(from_bk(&b, 0) == PLUG_E_SEQ);
    plug_msg_init(&b, PLUG_MSG_STOP, 4, 2, 0);
    b.zone[0] = 'z';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
    plug_msg_init(&b, PLUG_MSG_KILL, 4, 2, 3);
    CHECK(from_bk(&b, 0) == PLUG_OK);
    b.seq = 0;
    CHECK(from_bk(&b, 0) == PLUG_E_SEQ);
    plug_msg_init(&b, PLUG_MSG_KILL, 4, 2, 3);
    b.fingerprint[0] = '1';
    CHECK(from_bk(&b, 0) == PLUG_E_TEXT);
}

static void test_texts(void) {
    printf("[TEST] every reason has a text...\n");
    for (int e = PLUG_OK; e <= PLUG_E_FIELD; e++) CHECK(strcmp(plug_err_text((plug_err_t)e), "?") != 0);
    CHECK(strcmp(plug_err_text((plug_err_t)999), "?") == 0);
    plug_msg_t m;
    memset(&m, 0xAA, sizeof(m));
    plug_msg_init(&m, PLUG_MSG_STOP, 1, 2, 3);
    CHECK(m.magic == PLUG_MAGIC && m.type == PLUG_MSG_STOP && m.slot == 1 && m.gen == 2 && m.seq == 3 && m.pid == 0 && m.zone[100] == 0);
}

/* ---- 0.7 M2: the KLS1 record (dns_log_state.c) that the Backend sends the manager on the same pair (and the routers and the broker) ---- */

static kls_state_t ks, kout;
static uint8_t krec[KLS_MAX + 16];

static void kls_sample(void) {
    memset(&ks, 0, sizeof(ks));
    ks.debug_level = 3;
    ks.has_spec = true;
    ks.nch = 3;
    ks.ch[0] = (kls_channel_t){ 0, 1, KLS_CF_CATEGORY | KLS_CF_SEVERITY, 0, 3 << 3, 15, "/var/log/a.test" };
    ks.ch[1] = (kls_channel_t){ 1, 0, 0, -2, 16 << 3, 0, NULL };
    ks.ch[2] = (kls_channel_t){ 0, 3, KLS_CF_DEBUG_ONLY, 5, 0, 11, "karidns.run" };
    ks.nroute[1] = 2;
    ks.route[1][0] = 0;
    ks.route[1][1] = 2;
    ks.nroute[4] = 1;
    ks.route[4][0] = 1;
}

/* the record with one byte changed at off parses or not, as expected */
static void kls_poke(size_t len, size_t off, uint8_t v, int ok) {
    uint8_t save = krec[off];
    krec[off] = v;
    CHECK((kls_parse(krec, len, &kout) == NULL) == ok);
    krec[off] = save;
}

static void test_log_state(void) {
    printf("[TEST] the KLS1 record of the debug level and the logging runtime...\n");
    kls_sample();
    size_t n = kls_encode(&ks, krec, sizeof(krec));
    CHECK(n == KLS_HEADER_LEN + 3 * 8 + 15 + 11 + LOGC_COUNT + 2 * 3);
    CHECK(kls_parse(krec, n, &kout) == NULL);
    CHECK(kout.debug_level == 3 && kout.has_spec && kout.nch == 3);
    CHECK(kout.ch[0].dest == 0 && kout.ch[0].time_fmt == 1 && kout.ch[0].flags == (KLS_CF_CATEGORY | KLS_CF_SEVERITY) && kout.ch[0].level == 0);
    CHECK(kout.ch[0].facility == 3 << 3 && kout.ch[0].path_len == 15 && memcmp(kout.ch[0].path, "/var/log/a.test", 15) == 0);
    CHECK(kout.ch[1].dest == 1 && kout.ch[1].level == -2 && kout.ch[1].facility == 16 << 3 && kout.ch[1].path == NULL);
    CHECK(kout.ch[2].flags == KLS_CF_DEBUG_ONLY && kout.ch[2].level == 5 && kout.ch[2].time_fmt == 3);
    CHECK(kout.nroute[1] == 2 && kout.route[1][1] == 2 && kout.nroute[4] == 1 && kout.route[4][0] == 1 && kout.nroute[0] == 0);
    /* every cut is refused, and so is a byte more */
    for (size_t k = 0; k < n; k++) CHECK(kls_parse(krec, k, &kout) != NULL);
    CHECK(kls_parse(krec, n + 1, &kout) != NULL);
    CHECK(kls_parse(NULL, n, &kout) != NULL && kls_parse(krec, n, NULL) != NULL);
    CHECK(kls_parse(krec, KLS_MAX + 1, &kout) != NULL);
    /* the header */
    kls_poke(n, 0, 'k', 0);                         /* magic */
    kls_poke(n, 4, 2, 0);                           /* version */
    kls_poke(n, 5, 3, 0);                           /* unknown flag */
    kls_poke(n, 6, 99, 1);
    kls_poke(n, 6, 100, 0);                         /* level */
    kls_poke(n, 7, 1, 0);                           /* reserved */
    kls_poke(n, 9, 2, 0);                           /* nch: the record no longer adds up */
    /* the first channel: destination, print-time, flags, severity, facility, the path */
    size_t c0 = KLS_HEADER_LEN;
    kls_poke(n, c0, 4, 0);
    kls_poke(n, c0, 2, 0);                          /* stderr with a path */
    kls_poke(n, c0 + 1, 4, 0);
    kls_poke(n, c0 + 2, 8, 0);
    kls_poke(n, c0 + 3, (uint8_t)-5, 1);
    kls_poke(n, c0 + 3, (uint8_t)-6, 0);
    kls_poke(n, c0 + 3, 100, 0);
    kls_poke(n, c0 + 5, 3 << 3 | 1, 0);             /* not a multiple of 8 */
    kls_poke(n, c0 + 4, 1, 0);                      /* 3 << 3 | 256: beyond LOG_LOCAL7 */
    kls_poke(n, c0 + 8, '\n', 0);                   /* a control character in the path */
    kls_poke(n, c0 + 8, 0x7f, 0);
    kls_poke(n, c0 + 8, 0x00, 0);
    kls_poke(n, c0 + 8, 0xc3, 1);                   /* (a byte of UTF-8 is fine) */
    kls_poke(n, c0 + 7, 0, 0);                      /* a file without a path */
    /* the table: a count above KLS_ROUTE_MAX, an index beyond the channels */
    size_t t0 = KLS_HEADER_LEN + 3 * 8 + 15 + 11;
    kls_poke(n, t0, KLS_ROUTE_MAX + 1, 0);
    kls_poke(n, t0 + 1 + 1 + 1, 3, 0);              /* category 1, first index (low byte) = 3 */
    /* the level alone */
    kls_state_t lv;
    memset(&lv, 0, sizeof(lv));
    lv.debug_level = 7;
    n = kls_encode(&lv, krec, sizeof(krec));
    CHECK(n == KLS_HEADER_LEN && kls_parse(krec, n, &kout) == NULL && kout.debug_level == 7 && !kout.has_spec);
    kls_poke(n, 9, 1, 0);                           /* channels without the flag */
    /* what the encoder refuses: the same rules, and too little room */
    kls_sample();
    CHECK(kls_encode(&ks, krec, 20) == 0 && kls_encode(&ks, krec, KLS_HEADER_LEN - 1) == 0 && kls_encode(NULL, krec, sizeof(krec)) == 0);
    size_t full = kls_encode(&ks, krec, sizeof(krec));
    CHECK(full > 0 && kls_encode(&ks, krec, full - 1) == 0);
    ks.debug_level = 100;
    CHECK(kls_encode(&ks, krec, sizeof(krec)) == 0);
    kls_sample();
    ks.ch[1].path_len = 3;                          /* a path for a syslog channel */
    CHECK(kls_encode(&ks, krec, sizeof(krec)) == 0);
    kls_sample();
    ks.route[4][0] = 3;
    CHECK(kls_encode(&ks, krec, sizeof(krec)) == 0);
    kls_sample();
    ks.nroute[4] = KLS_ROUTE_MAX + 1;
    CHECK(kls_encode(&ks, krec, sizeof(krec)) == 0);
    kls_sample();
    ks.nch = KLS_CHANNELS_MAX + 1;
    CHECK(kls_encode(&ks, krec, sizeof(krec)) == 0);
    lv.nch = 1;
    CHECK(kls_encode(&lv, krec, sizeof(krec)) == 0);  /* channels without the flag */
    /* the largest table: 256 channels of long paths do not fit KLS_MAX */
    {
        static char longp[KLS_PATH_MAX];
        memset(longp, 'p', sizeof(longp));
        memset(&ks, 0, sizeof(ks));
        ks.has_spec = true;
        ks.nch = KLS_CHANNELS_MAX;
        for (int i = 0; i < KLS_CHANNELS_MAX; i++) ks.ch[i] = (kls_channel_t){ 0, 0, 0, 0, 0, KLS_PATH_MAX, longp };
        CHECK(kls_encode(&ks, krec, sizeof(krec)) == 0);
        ks.ch[0].path_len = KLS_PATH_MAX + 1;
        ks.nch = 1;
        CHECK(kls_encode(&ks, krec, sizeof(krec)) == 0);
    }
}

int main(void) {
    test_from_manager();
    test_from_backend();
    test_texts();
    test_log_state();
    printf("[*] %d checks, %d failed\n", g_checks, g_fail);
    if (g_fail) return 1;
    printf("=== All plugin message tests PASSED ===\n");
    return 0;
}
