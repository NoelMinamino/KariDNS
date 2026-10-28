#ifndef DNS_LOGCAT_H
#define DNS_LOGCAT_H

/* Log categories and severities, shared by the configuration parser (the `logging { category ...; }` statement, karicheck conf) and the
 * logging runtime of the server (dns_log.h).  The names are the categories of BIND 9.20.4 (lib/isc/log.c isc_categories, lib/dns/log.c
 * dns_categories, lib/ns/log.c ns_categories, lib/isccfg/log.c cfg_categories, bin/named/log.c categories), minus the internal
 * "_placeholder"; check_logging() in lib/isccfg/check.c rejects any other name ("undefined category"). */

typedef enum {
  LOGC_DEFAULT = 0,      /* must stay 0: the category that unconfigured categories fall back to */
  LOGC_GENERAL,
  LOGC_SSLKEYLOG,
  LOGC_NOTIFY,
  LOGC_DATABASE,
  LOGC_SECURITY,
  LOGC_DNSSEC,
  LOGC_RESOLVER,
  LOGC_XFER_IN,
  LOGC_XFER_OUT,
  LOGC_DISPATCH,
  LOGC_LAME_SERVERS,
  LOGC_EDNS_DISABLED,
  LOGC_RPZ,
  LOGC_RATE_LIMIT,
  LOGC_CNAME,
  LOGC_SPILL,
  LOGC_DNSTAP,
  LOGC_ZONELOAD,
  LOGC_NSID,
  LOGC_RPZ_PASSTHRU,
  LOGC_CLIENT,
  LOGC_NETWORK,
  LOGC_UPDATE,
  LOGC_QUERIES,
  LOGC_UPDATE_SECURITY,
  LOGC_QUERY_ERRORS,
  LOGC_TRUST_ANCHOR_TELEMETRY,
  LOGC_SERVE_STALE,
  LOGC_RESPONSES,
  LOGC_CONFIG,
  LOGC_UNMATCHED,
  LOGC_COUNT
} log_cat_t;

/* "choose the category from the "[Prefix]" of the message" (see dns_log.c) */
#define LOGC_AUTO (-1)

/* Severities as in BIND (lib/isc/include/isc/log.h): critical .. info are negative, 0 is "dynamic" (the debug level in force; KariDNS has
 * no debug level, so it is 0), debug N is N. */
#define LOG_LVL_CRITICAL (-5)
#define LOG_LVL_ERROR (-4)
#define LOG_LVL_WARNING (-3)
#define LOG_LVL_NOTICE (-2)
#define LOG_LVL_INFO (-1)
#define LOG_LVL_DYNAMIC 0

extern const char *const log_category_names[LOGC_COUNT];

/* The category of that name (case-sensitive, like isc_log_categorybyname()), or -1. */
int log_category_from_name(const char *name);

#endif
