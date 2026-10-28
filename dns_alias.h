#ifndef DNS_ALIAS_H
#define DNS_ALIAS_H

/*
 * dns_alias.h - PowerDNS ALIAS expansion (beta design 3.6b, milestone B9a).
 *
 * An ALIAS record (TYPE 65401 of CLASS IN, RDATA = the target name, uncompressed) stands for the A and AAAA RRsets of its target.
 * With `alias-resolver { <addr> [port <n>]; ... };` (zone, options, or options { database { } } for database zones) the server answers
 * A / AAAA (and ANY) at the ALIAS name with the addresses its resolver gives for the target, as PowerDNS does with expand-alias=yes.
 * Without it (the default) ALIAS is stored and transferred and nothing else (PowerDNS's default: A / AAAA at the name are NODATA).
 *
 * How (CLAUDE.md Rules 1 and 2; nothing blocks and nothing allocates on the query path):
 *   - One auxiliary thread of the Backend (alias_start()) keeps a table of jobs, one per (resolver set, target name, A or AAAA).  The
 *     targets are found by scanning the published zone versions (an image with ZONE_IMAGE_F_ALIAS); a job is added when a zone is
 *     published or the configuration changes and dropped when no zone refers to the target any more.
 *   - A job is resolved through broker_connect() / broker_connect_opts() exactly like the forwarders of a `type forward` zone: a UDP query
 *     (RD=1, EDNS0), TCP when the answer is truncated.  The answer must come on the connected socket with the right ID and question
 *     and RCODE NOERROR; the CNAME chain from the target is followed inside the answer (at most ALIAS_MAX_CNAME hops).  No DNSSEC
 *     validation is done: the resolver is trusted.
 *   - The results are published as one immutable block (the "table", a single malloc) through an atomic pointer.  The query path only
 *     reads it (alias_lookup()).  The previous block is freed after a grace period (rcu_writer_wait_until_safe(), by this thread).
 *   - A result is refreshed after two thirds of its TTL (at least ALIAS_MIN_REFRESH seconds apart).  The TTL served is min(the ALIAS
 *     record's TTL, the time left of the upstream TTL).  When a refresh fails the last result keeps being served for up to
 *     ALIAS_STALE_MAX seconds after its TTL ran out, with TTL ALIAS_STALE_TTL (RFC 8767 sections 4, 5); a target that never resolved,
 *     or whose result is older than that, answers SERVFAIL (PowerDNS answers SERVFAIL when it cannot resolve).  A failing job is retried
 *     with a back-off from ALIAS_RETRY_MIN to ALIAS_RETRY_MAX seconds; a resolver set that does not answer at all is left alone for
 *     ALIAS_DEAD_SECS seconds.
 *   - Bounds: ALIAS_MAX_TARGETS_PER_ZONE targets per zone, ALIAS_MAX_JOBS jobs in all (a target counts twice: A and AAAA),
 *     ALIAS_MAX_RR addresses per type, ALIAS_QUERIES_PER_TICK upstream queries per ALIAS_TICK_MS (about 100 per second).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "dns_config_parser.h"

#define ALIAS_MAX_RESOLVERS        KARIDNS_ALIAS_RESOLVERS_MAX
#define ALIAS_MAX_TARGETS_PER_ZONE 1024
#define ALIAS_MAX_JOBS             16384
#define ALIAS_MAX_RR               32
#define ALIAS_MAX_CNAME            8
#define ALIAS_QUERIES_PER_TICK     20
#define ALIAS_TICK_MS              200
#define ALIAS_MIN_REFRESH          5          /* seconds */
#define ALIAS_MAX_TTL              86400      /* an upstream TTL is cut to this */
#define ALIAS_NEG_TTL              30         /* TTL of a NODATA result (no SOA is looked at) */
#define ALIAS_STALE_MAX            86400      /* seconds a result is still served after its TTL ran out and refreshes fail */
#define ALIAS_STALE_TTL            30
#define ALIAS_RETRY_MIN            5
#define ALIAS_RETRY_MAX            320
#define ALIAS_DEAD_SECS            10
#define ALIAS_RESOLVE_BUDGET_MS    3000       /* all resolvers of one resolution together */

typedef struct {
    uint64_t key;                                       /* hash of the resolver list; 0 = none */
    int n;
    struct sockaddr_storage sa[ALIAS_MAX_RESOLVERS];
    socklen_t sl[ALIAS_MAX_RESOLVERS];
} alias_rset_t;

/* ---- configuration: which resolvers apply to a zone ----
 * zone alias-resolver, else options alias-resolver, else (zones of the database) options { database { alias-resolver } }.  The key is a
 * hash of the ip / port texts, 0 when there are none.  alias_resolvers_fill() also converts the addresses; entries that are not IP
 * literals are skipped (the parsers refuse them). */
uint64_t alias_resolvers_key(const server_config_t *cfg, const zone_config_t *zcfg, bool db_zone);
int alias_resolvers_fill(const server_config_t *cfg, const zone_config_t *zcfg, bool db_zone, alias_rset_t *out);

/* ---- the query path ---- */
typedef struct {
    const uint8_t *rdata;     /* n addresses of rdlen octets (4 or 16), in the table */
    uint8_t n;
    uint8_t rdlen;
    uint32_t ttl;             /* seconds left of the upstream TTL (ALIAS_STALE_TTL when stale) */
    bool stale;
} alias_answer_t;

/* The result for (resolver set key, target name, qtype 1 or 28).  `name` is the target in wire format, lower case (alias_wire_lower()).
 * true when there is a result that may be served (fresh, or stale within ALIAS_STALE_MAX); *out is valid until the end of the
 * caller's read-side critical section.  Lock-free, no allocation. */
bool alias_lookup(uint64_t key, const uint8_t *name, size_t nlen, uint16_t qtype, alias_answer_t *out);

/* The target of an ALIAS RR (its RDATA) as the lower case uncompressed wire name; false when the RDATA is not one name */
bool alias_wire_lower(const uint8_t *rdata, size_t rdlen, uint8_t *out, size_t *outlen);

/* ---- the thread ---- */
bool alias_start(void);              /* before the sandbox; false = the thread could not start */
void alias_notify(void);             /* a zone with ALIAS RRs was published or removed: rescan soon */

/* ---- exposed for the unit tests ---- */
typedef struct {
    int rc;                           /* 0 = usable answer, 1 = RCODE other than NOERROR, -1 = malformed / loop / too long a chain, -2 = not the answer to this query (ID, QR, question) */
    uint8_t n;
    uint8_t rdlen;
    uint32_t ttl;
    uint8_t rd[ALIAS_MAX_RR * 16];
    bool truncated;                   /* TC=1 */
} alias_parsed_t;
void alias_parse_response(const uint8_t *pkt, size_t len, uint16_t id, const uint8_t *name, size_t nlen, uint16_t qtype,
                          alias_parsed_t *out);
size_t alias_build_query(uint8_t *buf, size_t cap, uint16_t id, const uint8_t *name, size_t nlen, uint16_t qtype);
extern int64_t (*g_alias_now_hook)(void);   /* tests: the clock, seconds (NULL = CLOCK_MONOTONIC) */
/* One pass of the scheduler without a thread or any network I/O: `resolve` is called instead of the resolvers.  Tests only. */
typedef int (*alias_resolve_fn)(const alias_rset_t *rs, const uint8_t *name, size_t nlen, uint16_t qtype, alias_parsed_t *out);
extern alias_resolve_fn g_alias_resolve_hook;
void alias_test_want(const alias_rset_t *rs, const uint8_t *name, size_t nlen);   /* adds the A and AAAA jobs for a target */
void alias_test_pass(void);
void alias_test_reset(void);
size_t alias_test_job_count(void);

#endif
