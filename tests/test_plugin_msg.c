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

int main(void) {
    test_from_manager();
    test_from_backend();
    test_texts();
    printf("[*] %d checks, %d failed\n", g_checks, g_fail);
    if (g_fail) return 1;
    printf("=== All plugin message tests PASSED ===\n");
    return 0;
}
