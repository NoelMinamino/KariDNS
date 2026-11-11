#ifndef TAPSTAT_CORE_H
#define TAPSTAT_CORE_H

/*
 * karidns-tapstat core: the Frame Streams reader and the bounded-memory aggregator.
 *
 * Kept apart from the command line and the sockets (tools/karidns_tapstat.c) so that the unit test and the
 * libFuzzer harness run the same code.  POSIX only (inet_ntop); not part of the Windows build of dag.
 *
 * Everything that arrives is untrusted: the Frame Streams lengths are capped before any buffer is sized from
 * them, the dnstap protobuf is walked by tools/dnstap_decode.c, and the DNS message inside is read only as far
 * as its header and question, with every length checked.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

/* ---- Frame Streams reader (the receiver side of the fstrm protocol) ---- */

#define FSTRM_MAX_DATA_FRAME   (256U * 1024U)  /* karidns sends at most about 66 KiB */
#define FSTRM_MAX_CONTROL      512U            /* control frame payload (libfstrm's limit) */
#define FSTRM_MAX_CTYPE        256U            /* one content-type field value */
#define FSTRM_CTYPE_DNSTAP     "protobuf:dnstap.Dnstap"

typedef enum {
    FSTRM_ST_INIT = 0,   /* bidirectional: waiting for READY; file: waiting for START */
    FSTRM_ST_WAIT_START, /* bidirectional: ACCEPT sent, waiting for START */
    FSTRM_ST_DATA,
    FSTRM_ST_DONE,       /* STOP received */
    FSTRM_ST_ERROR
} fstrm_state_t;

typedef struct {
    fstrm_state_t state;
    bool bidir;           /* a socket (READY / ACCEPT / START ... STOP / FINISH), not a file (START ... STOP) */
    int phase;            /* 0 = header, 1 = payload */
    uint8_t hdr[8];
    size_t hdr_have;
    bool control;
    uint32_t plen;
    uint32_t have;
    uint8_t *buf;         /* assembles a frame split over several reads */
    size_t buf_cap;
    uint8_t reply[128];   /* ACCEPT / FINISH the caller has to send, then clear with reply_len = 0 */
    size_t reply_len;
} fstrm_reader_t;

void fstrm_reader_init(fstrm_reader_t *r, bool bidir);
void fstrm_reader_free(fstrm_reader_t *r);

typedef void (*fstrm_data_cb)(void *ctx, const uint8_t *frame, size_t len);

/* Consumes in[0..len) and calls cb for each data frame.  Returns 0 to go on, 1 after STOP (r->reply may hold FINISH),
 * -1 on a protocol error (the stream must be dropped).  r->reply is filled for READY (ACCEPT) and STOP (FINISH). */
int fstrm_feed(fstrm_reader_t *r, const uint8_t *in, size_t len, fstrm_data_cb cb, void *ctx);

/* ---- aggregator ---- */

#define TAPSTAT_DIMS 5
enum { TAPSTAT_D_ZONE = 0, TAPSTAT_D_QNAME, TAPSTAT_D_QTYPE, TAPSTAT_D_RCODE, TAPSTAT_D_CLIENT };

typedef enum { TAPSTAT_TEXT = 0, TAPSTAT_JSON, TAPSTAT_PROM } tapstat_format_t;

typedef struct {
    uint32_t topk;        /* table size per dimension (keys kept); 1 .. TAPSTAT_MAX_TOPK */
    uint32_t show;        /* entries printed per dimension; 0 = all kept */
    int count_type;       /* dnstap message type counted for zone, qname, qtype and client: 1 = AUTH_QUERY, 2 = AUTH_RESPONSE */
    int v4_prefix;        /* 0 .. 32 */
    int v6_prefix;        /* 0 .. 128 */
    uint64_t hash_key[2]; /* SipHash key of the tables (random in the program, so that names cannot be chosen to collide) */
} tapstat_opts_t;

#define TAPSTAT_MAX_TOPK 1000000U

typedef struct tapstat tapstat_t;

tapstat_t *tapstat_new(const tapstat_opts_t *o);
void tapstat_free(tapstat_t *s);
/* Adds a zone name (text, "example.test" or "example.test."; no escapes).  False for a name that is not valid. */
bool tapstat_add_zone(tapstat_t *s, const char *name);
size_t tapstat_zone_count(const tapstat_t *s);
/* Counts one dnstap frame (the payload of a Frame Streams data frame). */
void tapstat_frame(tapstat_t *s, const uint8_t *frame, size_t len);
/* Starts a new interval: all counters and tables to zero (the zone list stays). */
void tapstat_reset(tapstat_t *s);
/* Writes the summary of the interval.  start / end are wall-clock seconds for the labels, secs the length measured. */
void tapstat_render(const tapstat_t *s, tapstat_format_t fmt, FILE *fp, time_t start, time_t end, double secs);

/* counters of the current interval */
uint64_t tapstat_frames(const tapstat_t *s);
uint64_t tapstat_bad_frames(const tapstat_t *s);

/* helpers shared with the program and the tests */
bool tapstat_name_to_wire(const char *name, uint8_t *out, size_t *out_len);
const char *tapstat_qtype_name(uint16_t t, char *buf, size_t cap);
const char *tapstat_rcode_name(unsigned rc, char *buf, size_t cap);

#endif /* TAPSTAT_CORE_H */
