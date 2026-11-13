/*
 * fuzz_db_logline.c - what karidns-dbloader writes to its stderr, as the supervisor reads it (batch 14, db_logrd_*, dns_db_supervisor.c).
 *
 * The loader runs with the rights of loader-user and reads names out of a database; the supervisor (root, until it drops) reads its stderr
 * pipe, so every byte is hostile.  The input is cut into pieces (the first bytes say how long they are and how fast they come), fed to the
 * line reader, and the end of the stream is flushed.  Every line the sink gets must be printable ASCII, no longer than DB_LOG_TEXT_MAX, with a
 * priority 0..7; the sink is not called for more than 2 * DB_LOG_RATE_LINES lines in a window (two budgets: warning and worse, the others)
 * plus the reports; the reader's buffer never grows.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "../../dns_db_supervisor.h"

/* what dns_priv_sandbox.c and dns_utils.c take from the server: not used here (as in tests/test_db_supervisor.c) */
char g_startup_cwd[PATH_MAX];
int g_cwd_fd = -1;
_Atomic int g_dnstap_sock = -1;
void gc_snapshot_wait_idle(void) {}
long write_uncompressed_name_ext(uint8_t *buf, size_t offset, size_t max_len, const char *name, bool downcase) {
    (void)buf; (void)offset; (void)max_len; (void)name; (void)downcase;
    return -1;
}

static unsigned long g_calls;

static void sink(int prio, int level, const char *text, void *ud) {
    (void)ud;
    if (prio < 0 || prio > 7) abort();
    if (level < 0 || level > 99 || (level > 0 && prio != 7)) abort();
    size_t n = strlen(text);
    if (n > DB_LOG_TEXT_MAX) abort();
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)text[i] < 0x20 || (unsigned char)text[i] >= 0x7f) abort();
    g_calls++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    size_t piece = (size_t)data[0] % 61 + 1;          /* 1 .. 61 bytes at a time */
    int64_t step = (int64_t)data[1] * 8;              /* 0 .. 2040 ms between pieces */
    data += 2;
    size -= 2;
    db_logrd_t rd;
    db_logrd_init(&rd);
    int64_t now = 100000;
    g_calls = 0;
    unsigned long pieces = 0;
    for (size_t off = 0; off < size; off += piece) {
        size_t n = size - off < piece ? size - off : piece;
        db_logrd_feed(&rd, (const char *)data + off, n, now, sink, NULL);
        if (rd.len > DB_LOG_TEXT_MAX) abort();
        now += step;
        pieces++;
    }
    db_logrd_flush(&rd, now, sink, NULL);
    if (rd.len != 0 && rd.len > DB_LOG_TEXT_MAX) abort();
    /* the rate limit: at most DB_LOG_RATE_LINES lines of warning and worse, as many others, plus one report per window; a window is at least
     * 1000 ms, a piece can end the window */
    unsigned long windows = (unsigned long)((step * (int64_t)pieces) / 1000) + 1;
    if (g_calls > windows * (2 * DB_LOG_RATE_LINES + 1) + 1) abort();
    return 0;
}
