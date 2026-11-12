#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef KARIDNS_VERSION
#define KARIDNS_VERSION "dev"     /* the Makefile passes the number of the file VERSION (docs/RELEASING.md) */
#endif

/* The directory of the configuration files that the programs look in when they are not told where (karictl, karicheck, karidns-zone), and the CA bundle of dag (SYSCONFDIR/ssl/cert.pem).
 * ./configure --sysconfdir=DIR passes -DKARIDNS_SYSCONFDIR="DIR" (docs/building.md); a build without it uses the FreeBSD ports layout. */
#ifndef KARIDNS_SYSCONFDIR
#define KARIDNS_SYSCONFDIR "/usr/local/etc"
#endif
#define KARIDNS_CONFDIR KARIDNS_SYSCONFDIR "/karidns"

/* The other directories ./configure sets (--prefix, --libexecdir; -DKARIDNS_PREFIX, -DKARIDNS_LIBEXECDIR when they are not these): the database
 * loader that karidns starts when `loader-path` is not set (dns_config_parser.h), and the FreeBSD ca_root_nss bundle that dag looks for. */
#ifndef KARIDNS_PREFIX
#define KARIDNS_PREFIX "/usr/local"
#endif
#ifndef KARIDNS_LIBEXECDIR
#define KARIDNS_LIBEXECDIR "/usr/local/libexec"
#endif

#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdatomic.h>
extern _Atomic bool g_capsicum_enabled;

bool split_path_for_openat(const char *path, char *dir_out,
                          size_t dir_out_sz, char *base_out,
                          size_t base_out_sz);

#ifndef _WIN32
/* P1, P5: an executable the server (or karicheck standing in for it) is going to run with the rights of another user, opened for
 * execution and checked as the open file: a regular file owned by root or by `self` (the user running karidns, or karicheck
 * standing in for it), not writable by group or others, executable by that user.  `what` ("database loader") and `who` ("the
 * user running karidns", "this user") word the messages.  Returns the descriptor (O_EXEC | O_CLOEXEC on FreeBSD) to pass to
 * exec_file_exec_fd(), or -1 with err filled. */
int exec_file_open_checked(const char *path, uid_t self, const char *what, const char *who, char *err, size_t errlen);
/* P5: execute the checked open file (fexecve() on FreeBSD, so the file that was checked is the file that runs).  A script (#!) can
 * only be run from a descriptor when fdescfs is mounted on /dev/fd; without it the script is started by its path after the same
 * checks (the window a binary no longer has).  Elsewhere (a portable karicheck build) it is execve() by path.  Returns only on
 * failure (-1, errno set). */
int exec_file_exec_fd(int fd, const char *path, char *const argv[], char *const envp[]);
/* P4: true (err filled) when `user` or `group` names root: a user of uid 0, or the gid that would be used (the group named, else
 * the user's primary group) being 0.  NULL names are skipped; a name that does not exist is not an error here (the callers say so).
 * Used for user / group, loader-user / loader-group and program-user, by karidns (start, reload) and karicheck. */
bool identity_names_root(const char *user, const char *group, char *err, size_t errlen);
/* The descriptors (SCM_RIGHTS) of a received message: the first `cap` of them go to out[] (out may be NULL with cap 0), every other one
 * is closed, so that a peer cannot leave descriptors behind in the receiver (a CMSG_SPACE() buffer is rounded up and holds more than it
 * was sized for).  Never reads past msg_controllen: a kernel that shortens a cut message may leave cmsg_len as it was.  Returns the count
 * of all of them (more than cap: the extra ones were closed).  Used by the Backend (the connect broker, the loader and plugin control
 * sockets) and by the plugin supervisor. */
struct msghdr;
int recv_take_rights(struct msghdr *mh, int *out, int cap);
#endif

uint16_t get_type_code(const char *type_str);
/* The directory part of path ("." without a slash, "/" for a file in the root); malloc()ed, the caller free()s it.  NULL for a NULL path
 * or on out of memory. */
char *get_base_dir(const char *path);
const char *format_type_name(uint16_t type, char *buf, size_t buf_size);
/* The mnemonic of a type; "TYPEnnn" (RFC 3597 5) for the rest, written into a _Thread_local buffer that the next call of the same
 * thread overwrites: use the result before calling again (two calls in one printf() argument list show the same text twice). */
const char *dns_type_to_string(uint16_t type_code);
/* The mnemonic of a CLASS as BIND prints it in its logs (IN, CH, HS, NONE, ANY); CLASSnnn (RFC 3597 5) for the rest, written into buf (>= 12 bytes) */
const char *dns_class_text(uint16_t qclass, char *buf, size_t buf_size);
/* The same mnemonics as string literals (no buffer) for the classes a zone can hold: IN, CH, HS, NONE, ANY; "CH" for anything else
 * (what dns_record_t.class_str used to say for every non-IN class; class_val is the value that counts). */
const char *dns_class_literal(uint16_t qclass);
/* The mnemonic of an RCODE 0..10 (RFC 1035 4.1.1, RFC 2136 2.2, RFC 6895); "RCODE" for the rest */
const char *dns_rcode_name(unsigned rcode);

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

/* File paths and schema names of the database configuration and of the KDB1 stream (beta design 7.1, 1.4): valid
 * UTF-8 (RFC 3629 3/4: shortest form only, no surrogates U+D800..U+DFFF, nothing above U+10FFFF) without control
 * characters (C0, DEL, C1 U+0080..U+009F).  The bytes are used as they are ('%XX' is not decoded). */
bool dns_path_is_valid_utf8(const unsigned char *p, size_t n);

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
    /* one pass (review dns_utils.h [7]): equal up to the end of the shorter name, then either both end, or the longer one is left with
     * exactly one unescaped '.' and the shorter one does not itself end in an unescaped '.' (only one trailing dot is ignored) */
    size_t i = 0;
    for (; a[i] && b[i]; i++) {
        unsigned char ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca != cb) {
            if (ca >= 'A' && ca <= 'Z') ca |= 0x20;
            if (cb >= 'A' && cb <= 'Z') cb |= 0x20;
            if (ca != cb) return false;
        }
    }
    if (!a[i] && !b[i]) return true;
    const char *longer = a[i] ? a : b, *shorter = a[i] ? b : a;
    if (longer[i] != '.' || longer[i + 1] != '\0' || dns_char_is_escaped(longer, i)) return false;
    return i == 0 || shorter[i - 1] != '.' || dns_char_is_escaped(shorter, i - 1);
}

/* domain_names_match_ci() で一致する名前が必ず同じ値になるハッシュ (FNV-1a)。
 * 末尾のエスケープされない '.' を 1 つ除き、ASCII 英字の大文字小文字を区別しない。
 * 一致の判定は domain_names_match_ci() で行い、これは候補を絞るだけ。 */
static inline uint32_t dns_name_hash_ci(const char *name) {
    /* one pass (review dns_utils.h [8]): an unescaped '.' is held back and hashed only when a character follows, so a trailing one
     * is left out like dns_name_len_no_root() does; the escape state is the parity of the backslash run before a character */
    uint32_t h = 2166136261u;
    bool esc = false, pending_dot = false;
    for (const char *p = name; *p; p++) {
        uint8_t c = (uint8_t)*p;
        if (!esc && c == '.') {
            if (pending_dot) { h ^= (uint8_t)'.'; h *= 16777619u; }
            pending_dot = true;
            continue;
        }
        if (pending_dot) { h ^= (uint8_t)'.'; h *= 16777619u; pending_dot = false; }
        esc = !esc && c == '\\';
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        h ^= c;
        h *= 16777619u;
    }
    return h;
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
