#ifndef DNS_COOKIE_CLIENT_H
#define DNS_COOKIE_CLIENT_H

/*
 * dns_cookie_client.h - the client side of DNS Cookies (RFC 7873) for the queries this server sends upstream (0.7): the ALIAS resolver
 * thread (dns_alias.c) and the forwarders of `type forward` zones (dns_query_engine.c).  The server side (the cookies this server hands
 * to its own clients, RFC 9018) is in dns_edns_ecs.c.
 *
 *   - The COOKIE option (RFC 7873 section 4): ckc_option_put() writes it, ckc_option_parse() finds it in the options of an OPT RR and
 *     checks it against the client cookie sent (section 5.3).
 *   - The state per server address (ckc_table_t): an 8-octet client cookie (arc4random, RFC 7873 section 4.1, RFC 9018 section 3),
 *     renewed after CKC_LIFETIME minus a random 0..40 % (section 7.1), the newest server cookie the address sent (section 5.1), and
 *     whether the address is "cookie capable" (it sent a valid server cookie: from then on its UDP responses must carry one, section 5.3
 *     "expecting the response to contain a COOKIE option").  An address that gives no accepted answer in CKC_FORGET_FAILS exchanges in a
 *     row over at least CKC_FORGET_SECS loses the mark, so that a server replaced by one without cookies at the same address is heard
 *     again.  The mark is logged when it is set and when it goes.
 *   - Whole messages (the forwarders relay the client's message, so its OPT RR is rewritten rather than built): ckc_msg_scan() finds the
 *     OPT RR, ckc_msg_check() checks the COOKIE of a response, ckc_msg_rewrite() replaces the COOKIE options of a message (or adds or
 *     removes its OPT RR).
 *
 * A table is used by one thread at a time and holds no pointer to the heap (CLAUDE.md Rule 1): the ALIAS thread has one, every thread
 * that answers queries has its own for the forwarders (dns_query_engine.c).  The only state shared between threads is the optional
 * array of process-wide marks (C11 atomics, ckc_table_t.marks): a slot per address hash holds the address while some thread knows it
 * is cookie capable.  A thread whose own entry is not (yet) marked takes the process-wide mark as its own (ckc_expected()), so the
 * downgrade protection holds in every thread as soon as one thread has seen a server cookie, and the "sends DNS cookies" line and the
 * line when the mark goes are logged once per address, not once per thread.  On a hash collision (another address holds the slot) an
 * address falls back to what each thread knows itself and is logged by each thread.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define CKC_OPT_COOKIE       10       /* RFC 7873 section 8 */
#define CKC_RCODE_BADCOOKIE  23       /* RFC 7873 section 8 (extended RCODE: 1 << 4 | 7) */
#define CKC_LIFETIME         86400    /* a client cookie is renewed after this, minus 0..40 % jitter (RFC 7873 section 7.1: default one day) */
#define CKC_FORGET_FAILS     5        /* exchanges in a row without an accepted answer ... */
#define CKC_FORGET_SECS      300      /* ... and this long since the last one: the address is no longer expected to send cookies */
#define CKC_OPTION_MAX       (4 + 8 + 32)

enum {
    CKC_NONE = 0,                     /* no COOKIE option (or none was looked for) */
    CKC_CLIENT = 1,                   /* our client cookie, no server cookie (option length 8) */
    CKC_SERVER = 2                    /* our client cookie and a server cookie of sc_len (8..32) octets */
};

typedef struct {
    uint8_t kind;                     /* CKC_* */
    uint8_t sc_len;                   /* 0, or 8..32 with CKC_SERVER */
    uint8_t sc[32];
    bool opt;                         /* ckc_msg_check(): the message has an OPT RR */
    bool badcookie;                   /* ckc_msg_check(): the RCODE is BADCOOKIE */
} ckc_seen_t;

typedef struct {
    bool used;
    bool capable;                     /* it sent a valid server cookie: its responses must carry one (RFC 7873 section 5.3) */
    uint8_t fam;                      /* AF_INET / AF_INET6 */
    uint8_t sc_len;
    uint16_t port;                    /* network order */
    uint8_t addr[16];
    uint8_t cc[8];                    /* the client cookie */
    uint8_t sc[32];                   /* the newest server cookie, sc_len octets (0 = none) */
    uint32_t fails;                   /* exchanges in a row without an accepted answer */
    int64_t cc_renew;                 /* the time (seconds) at which cc is replaced */
    int64_t last_ok;                  /* the time of the last accepted answer */
    int64_t last_use;
} ckc_entry_t;

typedef struct {
    ckc_entry_t *slots;
    unsigned n;
    const char *who;                  /* the log text before the address: "[Alias] resolver" */
    const char *unit;                 /* what an exchange is called in the log: "resolutions" */
    _Atomic uint64_t *marks;          /* NULL: one thread (every set and clear is logged); else the process-wide marks of the capable addresses */
    unsigned nmarks;
} ckc_table_t;

/* ---- the option ---- */
/* writes {10, 8 + sclen, cc, sc} (RFC 7873 section 4); the length written, 0 when it does not fit or sclen is not 0 or 8..32 */
size_t ckc_option_put(uint8_t *p, size_t cap, const uint8_t cc[8], const uint8_t *sc, size_t sclen);
/* The options of an OPT RR (RFC 6891 section 6.1.2: {code, length, data} to the end of the RDATA) against the client cookie sent.
 * false = discard the response (RFC 7873 section 5.3: an illegal COOKIE length - valid are 8 and 16 to 40, section 5.2.2 -, an incorrect
 * client cookie; here also two COOKIE options or an option list that runs past the RDATA, where the cookie cannot be checked).
 * out->kind / sc_len / sc are set when a COOKIE option is there (the caller clears them first). */
bool ckc_option_parse(const uint8_t *rd, size_t rdlen, const uint8_t cc[8], ckc_seen_t *out);

/* ---- the state of the server addresses ---- */
ckc_entry_t *ckc_find(const ckc_table_t *t, const struct sockaddr_storage *sa);
/* the state of an address, made when it has none (a free slot, else the least recently used one); the client cookie is renewed when
 * it is due.  Call it between two exchanges (RFC 7873 section 7.1: no query is outstanding with the old cookie) */
ckc_entry_t *ckc_get(ckc_table_t *t, const struct sockaddr_storage *sa, int64_t now);
/* a response that passed the checks: keep the newest server cookie (RFC 7873 section 5.3: also from an error response).  true when this
 * call logged that the address sends cookies */
bool ckc_learn(ckc_table_t *t, ckc_entry_t *c, uint8_t kind, const uint8_t *sc, uint8_t sc_len);
/* the end of one exchange with this address: accepted = some response passed the checks.  true when this call logged that the mark
 * went */
bool ckc_account(ckc_table_t *t, ckc_entry_t *c, bool accepted, int64_t now);
/* RFC 7873 section 5.3 beyond the option check: once the address sent a server cookie, a UDP response without one (no COOKIE option,
 * or the client cookie alone) is discarded, as one the client expected a COOKIE option in */
bool ckc_expected(const ckc_table_t *t, const ckc_entry_t *c);   /* the address is known (here or by another thread) to send cookies */
static inline bool ckc_acceptable(const ckc_table_t *t, const ckc_entry_t *c, uint8_t kind) { return kind == CKC_SERVER || !ckc_expected(t, c); }

/* ---- whole messages ---- */
typedef struct {
    unsigned opt_count;               /* OPT RRs in the message (RFC 6891 section 6.1.1: at most one) */
    size_t opt_off, opt_end;          /* the OPT RR: from its owner to the end of its RDATA */
    size_t rd_off, rdlen;             /* its RDATA */
    uint32_t ttl;                     /* its TTL: the extended RCODE in the top 8 bits (RFC 6891 section 6.1.3) */
    bool has_sig;                     /* a TSIG or SIG(0) RR in the additional section (RFC 6891 section 6.1.1: it must stay last) */
    size_t rr_end;                    /* the end of the last RR */
} ckc_msg_t;
/* walks every RR of the message.  false when it is malformed (an RR that runs past the end, an OPT RR outside the additional section
 * or with an owner other than the root) */
bool ckc_msg_scan(const uint8_t *pkt, size_t len, ckc_msg_t *m);
/* The COOKIE option of a response to a query that carried the client cookie cc.  -1 = discard the response (ckc_option_parse() false,
 * or more than one OPT RR: the cookie cannot be checked); 0 = the checks passed: out->kind says what was there (CKC_NONE also when the
 * message cannot be walked: a truncated one), out->opt whether there is an OPT RR, out->badcookie whether the RCODE is BADCOOKIE */
int ckc_msg_check(const uint8_t *pkt, size_t len, const uint8_t cc[8], ckc_seen_t *out);
enum {
    CKC_RW_SET = 0,                   /* replace the COOKIE options of the OPT RR by opt; a message without an OPT RR gets one (*added) */
    CKC_RW_KEEP = 1,                  /* the same, but a message without an OPT RR stays as it is */
    CKC_RW_DROP = 2                   /* remove the OPT RR */
};
/* in[0..len) copied to out with its OPT RR changed as mode says; opt[0..optlen) are the options put in place of the COOKIE options
 * (optlen 0: they are only removed).  An added OPT RR advertises 512 octets (RFC 6891 section 6.2.5: what a requestor without EDNS
 * gets anyway), version 0, no flags, and goes after the last RR.  0 when the message cannot be walked, has a TSIG / SIG(0) RR (it signs
 * the message as it is), its option list runs past the RDATA, or the result does not fit in cap.  in and out must not overlap. */
size_t ckc_msg_rewrite(const uint8_t *in, size_t len, uint8_t *out, size_t cap, const uint8_t *opt, size_t optlen, int mode, bool *added);

#endif
