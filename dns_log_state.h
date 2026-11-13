#ifndef DNS_LOG_STATE_H
#define DNS_LOG_STATE_H

/*
 * dns_log_state.h - the debug level and the logging runtime, as the Backend hands them to the other processes of the server (0.7 M2).
 *
 * The Backend owns `karictl trace` / `notrace` and `karictl reload`.  The manager, the Frontend routers and the connect broker were forked
 * with the start-up logging and level; after a change the Backend sends them one record ("KLS1") over a descriptor each already has:
 *
 *   manager          the plugin control pair (dns_plugin_sup.c g_plug_ctrl_fd), one datagram
 *   Frontend router  the IPC pair of worker 0 (udp_ipc_t with sock_fd_idx UDP_IPC_LOGSTATE, the record as its payload)
 *   connect broker   its request stream (broker_req_t with family BROKER_REQ_LOGSTATE and the length in `type`, then the record)
 *
 * karidns-dbloader gets the level only (KDB1 DEBUG, and --debug at its start): its lines are logged by the manager (dns_db_supervisor.c).
 *
 * Every receiver treats the record as hostile: a Backend that has been taken over must not gain anything through it (the manager is root).
 * Hence the record has only what a line needs (destination, severity, the print-* flags, the syslog facility, a file path, and which channels
 * each category writes to), and a receiver holds it to what the start-up configuration allowed (dns_log.c klog_aux_init(), kept before the
 * forks): it appends only to a file that exists, in a directory of the start-up's file channels (which the Backend holds writable itself), that
 * is a plain file (no symbolic link) with one link owned by the run user, never one of root's; karidns.run (options { directory }) only through
 * the descriptor the start opened (klog_aux_append()); a syslog facility only one the start-up channels used (else daemon); and its warnings
 * and errors always reach the start-up channels of their category as well (klog_record()), so a record cannot silence them.  Nothing is
 * created, rolled or handed over by a receiver.
 *
 * Wire format (one host, but byte by byte so that it does not depend on the layout of a structure), big-endian:
 *   u32 magic "KLS1" | u8 version (1) | u8 flags (bit 0: the channels and the table follow) | u8 debug level (0..99) | u8 0 | u16 nch
 *   nch times:  u8 dest (0 file, 1 syslog, 2 stderr, 3 null) | u8 print-time (0..3) | u8 flags (bit 0 print-category, bit 1 print-severity,
 *               bit 2 the built-in default_debug) | i8 severity (-5 critical .. -1 info, 0 dynamic, 1..99 debug N) |
 *               u16 syslog facility (LOG_KERN .. LOG_LOCAL7: a multiple of 8 below 24 * 8) | u16 path length | path
 *               (a file: 1..1023 bytes, no control character, no NUL; any other destination: none)
 *   LOGC_COUNT times (only with flag bit 0): u8 n (0..KLS_ROUTE_MAX) | n times u16 channel index (< nch)
 * Without flag bit 0, nch is 0 and the record ends after the header: the level alone.  The whole record is at most KLS_MAX bytes.
 *
 * Pure functions: no I/O, no allocation (the unit test and the fuzz harness see what the receivers run).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dns_logcat.h"

#define KLS_MAGIC 0x4b4c5331u          /* "KLS1" */
#define KLS_VERSION 1
#define KLS_MAX 32768                  /* fits a datagram of each pair and a udp_ipc_t payload */
#define KLS_HEADER_LEN 10
#define KLS_CHANNELS_MAX 256           /* LOGC_COUNT categories of KLS_ROUTE_MAX channels each: no table has more distinct ones */
#define KLS_ROUTE_MAX 8                /* LOG_ROUTE_MAX (dns_config_parser.h; dns_log.c asserts they are equal) */
#define KLS_PATH_MAX 1023
#define KLS_F_SPEC 0x01u
#define KLS_CF_CATEGORY 0x01u
#define KLS_CF_SEVERITY 0x02u
#define KLS_CF_DEBUG_ONLY 0x04u

typedef struct {
  uint8_t dest;                         /* log_dest_t */
  uint8_t time_fmt;                     /* log_time_t */
  uint8_t flags;                        /* KLS_CF_* */
  int8_t level;
  uint16_t facility;
  uint16_t path_len;
  const char *path;                     /* parse: points into the record (not NUL-terminated); encode: path_len bytes are read */
} kls_channel_t;

typedef struct {
  int debug_level;
  bool has_spec;
  uint16_t nch;
  kls_channel_t ch[KLS_CHANNELS_MAX];
  uint8_t nroute[LOGC_COUNT];
  uint16_t route[LOGC_COUNT][KLS_ROUTE_MAX];
} kls_state_t;

/* The record of s in buf.  Returns its length, or 0 when it does not fit in cap (or s is not one kls_parse() would accept). */
size_t kls_encode(const kls_state_t *s, uint8_t *buf, size_t cap);
/* The checks of a receiver.  NULL: *out is the record (its paths point into buf); else the reason (a constant text, no byte of the input). */
const char *kls_parse(const uint8_t *buf, size_t len, kls_state_t *out);

#endif /* DNS_LOG_STATE_H */
