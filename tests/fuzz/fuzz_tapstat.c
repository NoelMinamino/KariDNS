/* libFuzzer harness of karidns-tapstat's input path: the Frame Streams reader (a socket session and a file, fed in
 * pieces of a size taken from the input), the dnstap protobuf decoder and the DNS question reader behind it, and the
 * three output formats of the aggregator (small tables, so that the full-table path runs). */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../../tools/tapstat_core.h"
#include "../../tools/dnstap_decode.h"

static void frame_cb(void *ctx, const uint8_t *frame, size_t len) { tapstat_frame((tapstat_t *)ctx, frame, len); }

static tapstat_t *g_stat;
static FILE *g_null;

static void init(void) {
    tapstat_opts_t o = { .topk = 8, .show = 4, .count_type = 2, .v4_prefix = 24, .v6_prefix = 56, .hash_key = { 0x1111, 0x2222 } };
    g_stat = tapstat_new(&o);
    if (!g_stat) __builtin_trap();
    tapstat_add_zone(g_stat, "example.test");
    tapstat_add_zone(g_stat, "sub.example.test");
    tapstat_add_zone(g_stat, ".");
    g_null = fopen("/dev/null", "w");
}

static void run_stream(const uint8_t *data, size_t size, bool bidir, size_t chunk) {
    fstrm_reader_t r;
    fstrm_reader_init(&r, bidir);
    for (size_t off = 0; off < size; off += chunk) {
        size_t n = size - off < chunk ? size - off : chunk;
        int rc = fstrm_feed(&r, data + off, n, frame_cb, g_stat);
        r.reply_len = 0;
        if (rc != 0) break;
    }
    fstrm_reader_free(&r);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_stat) init();
    if (size == 0 || size > (1U << 20)) return 0;

    /* the input as a Frame Streams byte stream, whole and in pieces of 1 to 256 bytes (the first byte picks the size) */
    size_t chunk = (size_t)data[0] + 1;
    run_stream(data, size, true, size);
    run_stream(data, size, false, size);
    run_stream(data + 1, size - 1, true, chunk);
    run_stream(data + 1, size - 1, false, chunk);

    /* the input as one dnstap frame */
    tapstat_frame(g_stat, data, size);
    dnstap_msg_t m;
    (void)dnstap_decode_message(data, size, &m);
    dnstap_frame_info_t fi;
    (void)parse_dnstap_data_frame_full(data, size, &fi);

    if (g_null) {
        tapstat_render(g_stat, TAPSTAT_TEXT, g_null, 0, 60, 60.0);
        tapstat_render(g_stat, TAPSTAT_JSON, g_null, 0, 60, 60.0);
        tapstat_render(g_stat, TAPSTAT_PROM, g_null, 0, 60, 60.0);
    }
    if (tapstat_frames(g_stat) > 4096) tapstat_reset(g_stat);
    return 0;
}
