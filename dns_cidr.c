#include "dns_cidr.h"
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

static void compute_mask(uint8_t *mask, int prefix, int total_bytes) {
    memset(mask, 0, 16);
    for (int i = 0; i < total_bytes; i++) {
        int bits = prefix - (i * 8);
        if (bits >= 8) {
            mask[i] = 0xFF;
        } else if (bits > 0) {
            mask[i] = (uint8_t)((0xFF << (8 - bits)) & 0xFF);
        } else {
            mask[i] = 0x00;
        }
    }
}

bool cidr_entry_parse(cidr_entry_t *entry, const char *cidr_str) {
    if (!entry) return false;
    memset(entry, 0, sizeof(*entry));
    if (!cidr_str || !*cidr_str) return false;

    if (strcmp(cidr_str, "any") == 0 || strcmp(cidr_str, "any;") == 0) {
        entry->valid = true;
        entry->is_any = true;
        return true;
    }

    char cidr_copy[256];
    strncpy(cidr_copy, cidr_str, sizeof(cidr_copy) - 1);
    cidr_copy[sizeof(cidr_copy) - 1] = '\0';
    char *slash = strchr(cidr_copy, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        char *endptr = NULL;
        long val = strtol(slash + 1, &endptr, 10);
        if (endptr == slash + 1 || *endptr != '\0' || val < 0 || val > 128) {
            syslog(LOG_WARNING, "[Config] Invalid CIDR prefix in ACL entry: '%s' (rejecting, no match)", cidr_str);
            return false;
        }
        prefix = (int)val;
    }

    struct in_addr addr4;
    struct in6_addr addr6;
    if (inet_pton(AF_INET, cidr_copy, &addr4) == 1) {
        if (prefix == -1) prefix = 32;
        if (prefix < 0 || prefix > 32) return false;

        entry->valid = true;
        entry->is_any = false;
        entry->family = AF_INET;
        entry->prefix = (uint8_t)prefix;
        memcpy(entry->addr, &addr4.s_addr, 4);
        compute_mask(entry->mask, prefix, 4);
        return true;
    } else if (inet_pton(AF_INET6, cidr_copy, &addr6) == 1) {
        if (prefix == -1) prefix = 128;
        if (prefix < 0 || prefix > 128) return false;

        entry->valid = true;
        entry->is_any = false;
        entry->family = AF_INET6;
        entry->prefix = (uint8_t)prefix;
        memcpy(entry->addr, &addr6.s6_addr, 16);
        compute_mask(entry->mask, prefix, 16);
        return true;
    }

    return false;
}

bool cidr_entry_match(const cidr_entry_t *net, int family, const uint8_t *addr_bytes) {
    if (!net || !net->valid) return false;
    if (net->is_any) return true;
    if (!addr_bytes || net->family != family) return false;

    if (family == AF_INET) {
        uint32_t a, b, m;
        memcpy(&a, addr_bytes, 4);
        memcpy(&b, net->addr, 4);
        memcpy(&m, net->mask, 4);
        return (a & m) == (b & m);
    } else if (family == AF_INET6) {
        for (int i = 0; i < 16; i++) {
            uint8_t m = net->mask[i];
            if (m == 0) break;
            if ((addr_bytes[i] & m) != (net->addr[i] & m)) return false;
        }
        return true;
    }
    return false;
}

bool cidr_entry_match_sockaddr(const cidr_entry_t *net, const struct sockaddr_storage *sa) {
    if (!net || !net->valid || !sa) return false;
    if (net->is_any) return true;

    if (sa->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
        return cidr_entry_match(net, AF_INET, (const uint8_t *)&sin->sin_addr.s_addr);
    } else if (sa->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        return cidr_entry_match(net, AF_INET6, (const uint8_t *)&sin6->sin6_addr.s6_addr);
    }
    return false;
}

bool cidr_entry_match_str(const cidr_entry_t *net, const char *addr_str) {
    if (!net || !net->valid || !addr_str || !*addr_str) return false;
    if (net->is_any) return true;

    struct in_addr addr4;
    struct in6_addr addr6;
    if (inet_pton(AF_INET, addr_str, &addr4) == 1) {
        return cidr_entry_match(net, AF_INET, (const uint8_t *)&addr4.s_addr);
    } else if (inet_pton(AF_INET6, addr_str, &addr6) == 1) {
        return cidr_entry_match(net, AF_INET6, (const uint8_t *)&addr6.s6_addr);
    }
    return false;
}
