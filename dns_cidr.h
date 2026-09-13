#ifndef KARIDNS_DNS_CIDR_H
#define KARIDNS_DNS_CIDR_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

/*
 * cidr_entry_t: Pre-parsed binary CIDR entry.
 * Note: `family` holds the host OS address family constant (AF_INET or AF_INET6, or 0 if 'any' / invalid).
 * It is NOT the RFC 7871 EDNS Client Subnet family field (which uses 1 for IPv4 and 2 for IPv6).
 */
typedef struct {
    bool valid;
    bool is_any;
    int family;         /* Host OS address family: AF_INET or AF_INET6 */
    uint8_t prefix;     /* 0..128 */
    uint8_t addr[16];   /* Network byte order */
    uint8_t mask[16];   /* Precomputed prefix bitmask */
} cidr_entry_t;

/*
 * acl_entry_t: Pre-parsed binary ACL entry with optional negation ('!').
 */
typedef struct {
    cidr_entry_t cidr;
    bool is_deny;
} acl_entry_t;

/* Parse a CIDR string (e.g., "192.0.2.0/24", "2001:db8::/32", "any", "1.2.3.4") into cidr_entry_t */
bool cidr_entry_parse(cidr_entry_t *entry, const char *cidr_str);

/* Match raw network bytes against parsed CIDR (family: AF_INET or AF_INET6) */
bool cidr_entry_match(const cidr_entry_t *net, int family, const uint8_t *addr_bytes);

/* Match sockaddr_storage against parsed CIDR */
bool cidr_entry_match_sockaddr(const cidr_entry_t *net, const struct sockaddr_storage *sa);

/* Match client IP string (e.g. "192.0.2.1", "2001:db8::1") against parsed CIDR */
bool cidr_entry_match_str(const cidr_entry_t *net, const char *addr_str);

#endif /* KARIDNS_DNS_CIDR_H */
