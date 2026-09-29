#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "0.4.2"
#endif

#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdatomic.h>
extern _Atomic bool g_capsicum_enabled;

bool split_path_for_openat(const char *path, char *dir_out,
                          size_t dir_out_sz, char *base_out,
                          size_t base_out_sz);

uint16_t get_type_code(const char *type_str);
char *get_base_dir(const char *path);
const char *format_type_name(uint16_t type, char *buf, size_t buf_size);
const char *dns_type_to_string(uint16_t type_code);

/* Returns true for QTYPE-only / pseudo-RR "meta-types" (OPT, TKEY, TSIG,
 * IXFR, AXFR, MAILB, MAILA, ANY, and NXNAME per RFC 9824) that MUST NOT be
 * defined as stored zone data nor appear in AXFR/IXFR transfers. NXNAME in
 * particular must only be synthesized dynamically per-query for compact
 * denial-of-existence negative answers. Compliant secondaries such as BIND
 * and NSD will reject a transfer containing one of these as a standalone
 * RRset with FORMERR. */
bool is_meta_rrtype(uint16_t type_code);


int hex_char_to_val(char c);

/* Returns the number of decoded bytes written to `out`, or (size_t)-1 if
 * `out_cap` would be exceeded. Callers MUST check for both 0 (empty/invalid
 * input) AND (size_t)-1 (overflow) — do not assume 0 is the only error value. */
size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap);
int compare_canonical_name(const char *name1, const char *name2);
bool serial_is_newer(uint32_t s1, uint32_t s2);
const char *strchr_unescaped(const char *s, char c);

static inline bool dns_char_is_escaped(const char *s, size_t pos) {
    size_t bs = 0;
    while (pos > bs && s[pos - bs - 1] == '\\') bs++;
    return (bs % 2) == 1;
}

/* 名前 (正規形, dns_wire.h) の長さから、末尾のエスケープされない '.' を除いたもの。
 * "." と "" は 0。 */
static inline size_t dns_name_len_no_root(const char *name, size_t len) {
    if (len > 0 && name[len - 1] == '.' && !dns_char_is_escaped(name, len - 1)) len--;
    return len;
}

/* 2 つの名前 (正規形) が DNS 名として同じか。末尾ドットの有無は問わない。
 * 正規形では英字が必ずそのまま書かれるので、大文字小文字を無視した文字列比較が
 * RFC 4343 §2 の比較と一致する。 */
static inline bool domain_names_match_ci(const char *a, const char *b) {
    if (!a || !b) return false;
    if (strcasecmp(a, b) == 0) return true;
    size_t la = dns_name_len_no_root(a, strlen(a));
    size_t lb = dns_name_len_no_root(b, strlen(b));
    return la == lb && strncasecmp(a, b, la) == 0;
}

/* name (表示形式) が apex と同じか、その下にあるか。末尾ドットの有無は問わない。
 * ラベル境界は、エスケープされていない '.' だけとする ("a\.example.test" は
 * "example.test" の下ではない)。apex が "." または "" ならルートなので常に true。
 * RFC 1034 §4.2: ゾーンは apex とその下の (カットより上の) データからなる。 */
static inline bool domain_name_is_at_or_below(const char *name, const char *apex) {
    if (!name || !apex) return false;
    size_t nl = dns_name_len_no_root(name, strlen(name));
    size_t al = dns_name_len_no_root(apex, strlen(apex));
    if (al == 0) return true;
    if (nl < al || strncasecmp(name + (nl - al), apex, al) != 0) return false;
    if (nl == al) return true;
    size_t dot = nl - al - 1;
    return name[dot] == '.' && !dns_char_is_escaped(name, dot);
}

#endif
