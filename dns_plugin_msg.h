#ifndef DNS_PLUGIN_MSG_H
#define DNS_PLUGIN_MSG_H

/*
 * dns_plugin_msg.h - the messages between the manager and the Backend about the plugins of type program zones (0.6.2, design part B).
 *
 * The manager (outside capability mode) forks and execs the plugins; the Backend talks to them.  The two speak over an AF_UNIX pair made
 * before the Backend is forked (dns_plugin_sup.c), one fixed-size record (plug_msg_t) per datagram.  SOCK_DGRAM, not SOCK_SEQPACKET as the
 * design had it: on FreeBSD 15 a recvmsg() on a SOCK_SEQPACKET socket returns bytes of the next record too (the boundaries are not kept,
 * no MSG_TRUNC), so a short or long record could not be told from the next one.  A datagram is one record, and a longer one sets MSG_TRUNC.
 *
 *   Backend -> manager   START slot gen zone view fingerprint   start a plugin for the program zone (view, zone) whose settings have that
 *                                                                fingerprint (compute_program_zone_fingerprint()); the path, the arguments
 *                                                                and the user come from the manager's own copy of the configuration
 *                        STOP  slot gen                          stop that plugin for good (its zone was removed or replaced)
 *                        KILL  slot gen seq                      kill start number seq (program-max-failures reached); it is restarted
 *   manager -> Backend   UP    slot gen seq pid  + 3 fds         start number seq runs: the write end of its stdin, the read end of its
 *                                                                stdout and its process descriptor (SCM_RIGHTS; 2 fds without pdfork())
 *                        DOWN  slot gen seq status [REFUSED]     start number seq has ended (wait status), or (REFUSED, seq 0) the manager
 *                                                                will not start it (no such zone, settings that differ, program-user root)
 *
 * slot: 0 .. PLUG_SLOTS-1, chosen by the Backend.  gen: the Backend's number of the START (never 0, never reused), so that a late message
 * about an earlier use of the slot is not taken for the current one.  seq: the manager's count of the starts of (slot, gen): 1, 2, ...
 *
 * Each side treats what the other sends as untrusted: the Backend runs the plugins' replies and is the side an attacker reaches first, and
 * the manager is root.  The checks below are pure functions (no state, no I/O) so that the unit test and the fuzz harness see exactly what
 * the receivers run.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PLUG_MAX_ZONES 256              /* program zones in one configuration; more is a configuration error */
#define PLUG_SLOTS (2 * PLUG_MAX_ZONES) /* a zone whose settings changed has two for a while: the running plugin and its replacement */
#define PLUG_MAGIC 0x4b505331u          /* "KPS1" */
#define PLUG_ZONE_MAX 256               /* zone name text with its NUL (program_plugin_t.domain) */
#define PLUG_VIEW_MAX 64                /* KARIDNS_VIEW_NAME_MAX */
#define PLUG_FP_MAX 24                  /* the 16 hex digits of the fingerprint and a NUL, padded */
#ifdef __FreeBSD__
#define PLUG_UP_NFDS 3                  /* stdin, stdout, process descriptor */
#else
#define PLUG_UP_NFDS 2
#endif

enum { PLUG_MSG_START = 1, PLUG_MSG_STOP = 2, PLUG_MSG_KILL = 3, PLUG_MSG_UP = 4, PLUG_MSG_DOWN = 5 };
#define PLUG_DOWN_REFUSED 1u            /* plug_msg_t.flags of a DOWN: not started at all (seq 0) */

typedef struct {
  uint32_t magic;
  uint32_t type;
  uint32_t slot;
  uint32_t gen;
  uint32_t seq;
  int32_t status;                       /* DOWN: the wait status */
  int32_t pid;                          /* UP: the plugin's pid (for the log) */
  uint32_t flags;
  char fingerprint[PLUG_FP_MAX];
  char zone[PLUG_ZONE_MAX];
  char view[PLUG_VIEW_MAX];
} plug_msg_t;

typedef enum {
  PLUG_OK = 0,
  PLUG_E_SIZE,      /* not exactly one record */
  PLUG_E_TRUNC,     /* MSG_TRUNC / MSG_CTRUNC: the data or the descriptors were cut */
  PLUG_E_MAGIC,
  PLUG_E_TYPE,      /* not a type this side may receive */
  PLUG_E_SLOT,      /* slot out of range, or not in use */
  PLUG_E_GEN,       /* gen 0, or not the slot's current one */
  PLUG_E_SEQ,       /* seq not the one expected */
  PLUG_E_FDS,       /* wrong number of descriptors for the type */
  PLUG_E_TEXT,      /* zone / view / fingerprint not a NUL-terminated text of the right form */
  PLUG_E_FIELD      /* a field that must be 0 for the type is not (flags, pid, status) */
} plug_err_t;

/* What the Backend expects for a slot: gen 0 = the slot is not in use; seq = the start number of the descriptors it holds (0 = none yet) */
typedef struct {
  uint32_t gen;
  uint32_t seq;
} plug_expect_t;

const char *plug_err_text(plug_err_t e);
/* A record of the given type with every other field 0 */
void plug_msg_init(plug_msg_t *m, uint32_t type, uint32_t slot, uint32_t gen, uint32_t seq);
/* The Backend's check of a record from the manager (len bytes, recvmsg flags, nfds descriptors received with it).  UP: slot in use, the
 * slot's gen, seq above the one held, PLUG_UP_NFDS descriptors, pid > 0.  DOWN: slot in use, the slot's gen, the seq held, no descriptor;
 * REFUSED only with seq 0.  The record is copied to *out (aligned) only when PLUG_OK. */
plug_err_t plug_check_from_manager(const void *buf, size_t len, int msg_flags, int nfds, const plug_expect_t *expect, size_t nexpect,
                                   plug_msg_t *out);
/* The manager's check of a record from the Backend.  START: zone (1..255 bytes), view (0..63) NUL-terminated, the fingerprint 16
 * lowercase hex digits; STOP / KILL: no text; KILL: seq > 0.  No descriptor, gen > 0, slot < PLUG_SLOTS, flags / pid / status 0. */
plug_err_t plug_check_from_backend(const void *buf, size_t len, int msg_flags, int nfds, plug_msg_t *out);

#endif /* DNS_PLUGIN_MSG_H */
