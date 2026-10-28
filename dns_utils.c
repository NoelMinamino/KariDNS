#include "dns_utils.h"
#include "dns_wire.h"
#include <ctype.h>

_Atomic bool g_capsicum_enabled = false;

bool split_path_for_openat(const char *path, char *dir_out,
                          size_t dir_out_sz, char *base_out,
                          size_t base_out_sz) {
  if (!path || !*path)
    return false;
  size_t plen = strlen(path);
  if (plen >= PATH_MAX)
    return false;
  const char *slash = strrchr(path, '/');
#ifdef _WIN32
  if (!slash) slash = strrchr(path, '\\');
#endif
  if (!slash) {
    if (strlen(path) >= base_out_sz)
      return false;
    if (snprintf(dir_out, dir_out_sz, ".") >= (int)dir_out_sz)
      return false;
    memcpy(base_out, path, plen + 1);
  } else {
    size_t dir_len = (size_t)(slash - path);
    if (dir_len == 0)
      dir_len = 1;
    if (dir_len >= dir_out_sz)
      return false;
    memcpy(dir_out, path, dir_len);
    dir_out[dir_len] = '\0';
    const char *base = slash + 1;
    size_t base_len = strlen(base);
    if (base_len == 0 || base_len >= base_out_sz)
      return false;
    memcpy(base_out, base, base_len + 1);
  }
  if (strcmp(base_out, "..") == 0 || strcmp(base_out, ".") == 0)
    return false;
  if (strstr(base_out, "/") != NULL)
    return false;
#ifdef _WIN32
  if (strstr(base_out, "\\") != NULL)
    return false;
#endif
  return true;
}

bool is_meta_rrtype(uint16_t type_code) {
    switch (type_code) {
        case 41:  /* OPT */
        case 128: /* NXNAME (RFC 9824) */
        case 249: /* TKEY */
        case 250: /* TSIG */
        case 251: /* IXFR */
        case 252: /* AXFR */
        case 253: /* MAILB */
        case 254: /* MAILA */
        case 255: /* ANY */
            return true;
        default:
            return false;
    }
}

/* type_str は大文字の綴り。get_type_code() から呼ぶ */
static uint16_t type_code_upper(const char *type_str) {
  switch (type_str[0]) {
  case 'A':
    if (strcmp(type_str, "A") == 0)
      return 1;
    if (strcmp(type_str, "AAAA") == 0)
      return 28;
    if (strcmp(type_str, "AFSDB") == 0)
      return 18;
    if (strcmp(type_str, "ATMA") == 0)
      return 34;
    if (strcmp(type_str, "A6") == 0)
      return 38;
    if (strcmp(type_str, "APL") == 0)
      return 42;
    if (strcmp(type_str, "ANY") == 0)
      return 255;
    if (strcmp(type_str, "AVC") == 0)
      return 258;
    if (strcmp(type_str, "AMTRELAY") == 0)
      return 260;
    if (strcmp(type_str, "AXFR") == 0)
      return 252;
    break;
  case 'B':
    if (strcmp(type_str, "BRID") == 0)
      return 68;
    break;
  case 'C':
    if (strcmp(type_str, "CNAME") == 0)
      return 5;
    if (strcmp(type_str, "CERT") == 0)
      return 37;
    if (strcmp(type_str, "CDS") == 0)
      return 59;
    if (strcmp(type_str, "CDNSKEY") == 0)
      return 60;
    if (strcmp(type_str, "CSYNC") == 0)
      return 62;
    if (strcmp(type_str, "CAA") == 0)
      return 257;
    break;
  case 'D':
    if (strcmp(type_str, "DS") == 0)
      return 43;
    if (strcmp(type_str, "DNAME") == 0)
      return 39;
    if (strcmp(type_str, "DNSKEY") == 0)
      return 48;
    if (strcmp(type_str, "DHCID") == 0)
      return 49;
    if (strcmp(type_str, "DOA") == 0)
      return 259;
    if (strcmp(type_str, "DLV") == 0)
      return 32769;
    if (strcmp(type_str, "DSYNC") == 0)
      return 66;
    break;
  case 'E':
    if (strcmp(type_str, "EID") == 0)
      return 31;
    if (strcmp(type_str, "EUI48") == 0)
      return 108;
    if (strcmp(type_str, "EUI64") == 0)
      return 109;
    break;
  case 'G':
    if (strcmp(type_str, "GPOS") == 0)
      return 27;
    break;
  case 'H':
    if (strcmp(type_str, "HINFO") == 0)
      return 13;
    if (strcmp(type_str, "HTTPS") == 0)
      return 65;
    if (strcmp(type_str, "HIP") == 0)
      return 55;
    if (strcmp(type_str, "HHIT") == 0)
      return 67;
    break;
  case 'I':
    if (strcmp(type_str, "ISDN") == 0)
      return 20;
    if (strcmp(type_str, "IPSECKEY") == 0)
      return 45;
    if (strcmp(type_str, "IXFR") == 0)
      return 251;
    break;
  case 'K':
    if (strcmp(type_str, "KEY") == 0)
      return 25;
    if (strcmp(type_str, "KX") == 0)
      return 36;
    break;
  case 'L':
    if (strcmp(type_str, "LOC") == 0)
      return 29;
    if (strcmp(type_str, "L32") == 0)
      return 105;
    if (strcmp(type_str, "L64") == 0)
      return 106;
    if (strcmp(type_str, "LP") == 0)
      return 107;
    break;
  case 'M':
    if (strcmp(type_str, "MX") == 0)
      return 15;
    if (strcmp(type_str, "MD") == 0)
      return 3;
    if (strcmp(type_str, "MF") == 0)
      return 4;
    if (strcmp(type_str, "MB") == 0)
      return 7;
    if (strcmp(type_str, "MG") == 0)
      return 8;
    if (strcmp(type_str, "MR") == 0)
      return 9;
    if (strcmp(type_str, "MINFO") == 0)
      return 14;
    if (strcmp(type_str, "MAILB") == 0)
      return 253;
    if (strcmp(type_str, "MAILA") == 0)
      return 254;
    break;
  case 'N':
    if (strcmp(type_str, "NS") == 0)
      return 2;
    if (strcmp(type_str, "NULL") == 0)
      return 10;
    if (strcmp(type_str, "NSAP") == 0)
      return 22;
    if (strcmp(type_str, "NSAP-PTR") == 0)
      return 23;
    if (strcmp(type_str, "NXT") == 0)
      return 30;
    if (strcmp(type_str, "NIMLOC") == 0)
      return 32;
    if (strcmp(type_str, "NXNAME") == 0)
      return 128;
    if (strcmp(type_str, "NAPTR") == 0)
      return 35;
    if (strcmp(type_str, "NSEC") == 0)
      return 47;
    if (strcmp(type_str, "NSEC3") == 0)
      return 50;
    if (strcmp(type_str, "NSEC3PARAM") == 0)
      return 51;
    if (strcmp(type_str, "NINFO") == 0)
      return 56;
    if (strcmp(type_str, "NID") == 0)
      return 104;
    break;
  case 'O':
    if (strcmp(type_str, "OPT") == 0)
      return 41;
    if (strcmp(type_str, "OPENPGPKEY") == 0)
      return 61;
    break;
  case 'P':
    if (strcmp(type_str, "PTR") == 0)
      return 12;
    if (strcmp(type_str, "PX") == 0)
      return 26;
    break;
  case 'R':
    if (strcmp(type_str, "RP") == 0)
      return 17;
    if (strcmp(type_str, "RT") == 0)
      return 21;
    if (strcmp(type_str, "RKEY") == 0)
      return 57;
    if (strcmp(type_str, "RRSIG") == 0)
      return 46;
    break;
  case 'S':
    if (strcmp(type_str, "SOA") == 0)
      return 6;
    if (strcmp(type_str, "SRV") == 0)
      return 33;
    if (strcmp(type_str, "SIG") == 0)
      return 24;
    if (strcmp(type_str, "SINK") == 0)
      return 40;
    if (strcmp(type_str, "SSHFP") == 0)
      return 44;
    if (strcmp(type_str, "SMIMEA") == 0)
      return 53;
    if (strcmp(type_str, "SVCB") == 0)
      return 64;
    if (strcmp(type_str, "SPF") == 0)
      return 99;
    break;
  case 'T':
    if (strcmp(type_str, "TXT") == 0)
      return 16;
    if (strcmp(type_str, "TLSA") == 0)
      return 52;
    if (strcmp(type_str, "TALINK") == 0)
      return 58;
    if (strcmp(type_str, "TKEY") == 0)
      return 249;
    if (strcmp(type_str, "TSIG") == 0)
      return 250;
    if (strcmp(type_str, "TA") == 0)
      return 32768;
    if (strncmp(type_str, "TYPE", 4) == 0) {
      char *endptr;
      long tval = strtol(type_str + 4, &endptr, 10);
      if (*endptr == '\0' && tval > 0 && tval <= 65535) {
        return (uint16_t)tval;
      }
      return 0;
    }
    break;
  case 'U':
    if (strcmp(type_str, "URI") == 0)
      return 256;
    break;
  case 'W':
    if (strcmp(type_str, "WKS") == 0)
      return 11;
    break;
  case 'X':
    if (strcmp(type_str, "X25") == 0)
      return 19;
    break;
  case 'Z':
    if (strcmp(type_str, "ZONEMD") == 0)
      return 63;
    break;
  }
  return 0;
}

/* RR 型のニーモニックは大文字小文字を区別しない (RFC 1035 §2.3.3, §5.1。BIND/NSD も同じ)。
 * 最長のニーモニックより長い文字列は既知の型ではない (TYPE65535 も収まる長さ)。 */
uint16_t get_type_code(const char *type_str) {
  if (!type_str)
    return 0;
  char upper[24];
  size_t i = 0;
  for (; type_str[i] != '\0'; i++) {
    if (i + 1 >= sizeof(upper))
      return 0;
    upper[i] = (char)toupper((unsigned char)type_str[i]);
  }
  upper[i] = '\0';
  return type_code_upper(upper);
}

char *get_base_dir(const char *path) {
    const char *slash = strrchr(path, '/');
    if (!slash) return strdup(".");
    size_t len = slash - path;
    if (len == 0) len = 1; // "/"
    char *base = malloc(len + 1);
    if (!base) return NULL;
    memcpy(base, path, len);
    base[len] = '\0';
    return base;
}

typedef struct { uint16_t type; const char *name; } type_name_entry_t;
static const type_name_entry_t TYPE_NAMES[] = {
    {1, "A"},
    {2, "NS"},
    {3, "MD"},
    {4, "MF"},
    {5, "CNAME"},
    {6, "SOA"},
    {7, "MB"},
    {8, "MG"},
    {9, "MR"},
    {10, "NULL"},
    {11, "WKS"},
    {12, "PTR"},
    {13, "HINFO"},
    {14, "MINFO"},
    {15, "MX"},
    {16, "TXT"},
    {17, "RP"},
    {18, "AFSDB"},
    {19, "X25"},
    {20, "ISDN"},
    {21, "RT"},
    {22, "NSAP"},
    {23, "NSAP-PTR"},
    {24, "SIG"},
    {25, "KEY"},
    {26, "PX"},
    {27, "GPOS"},
    {28, "AAAA"},
    {29, "LOC"},
    {30, "NXT"},
    {31, "EID"},
    {32, "NIMLOC"},
    {33, "SRV"},
    {34, "ATMA"},
    {35, "NAPTR"},
    {36, "KX"},
    {37, "CERT"},
    {38, "A6"},
    {39, "DNAME"},
    {40, "SINK"},
    {41, "OPT"},
    {42, "APL"},
    {43, "DS"},
    {44, "SSHFP"},
    {45, "IPSECKEY"},
    {46, "RRSIG"},
    {47, "NSEC"},
    {48, "DNSKEY"},
    {49, "DHCID"},
    {50, "NSEC3"},
    {51, "NSEC3PARAM"},
    {52, "TLSA"},
    {53, "SMIMEA"},
    {55, "HIP"},
    {56, "NINFO"},
    {57, "RKEY"},
    {58, "TALINK"},
    {59, "CDS"},
    {60, "CDNSKEY"},
    {61, "OPENPGPKEY"},
    {62, "CSYNC"},
    {63, "ZONEMD"},
    {64, "SVCB"},
    {65, "HTTPS"},
    {66, "DSYNC"},
    {67, "HHIT"},
    {68, "BRID"},
    {99, "SPF"},
    {104, "NID"},
    {105, "L32"},
    {106, "L64"},
    {107, "LP"},
    {108, "EUI48"},
    {109, "EUI64"},
    {128, "NXNAME"},
    {249, "TKEY"},
    {250, "TSIG"},
    {251, "IXFR"},
    {252, "AXFR"},
    {253, "MAILB"},
    {254, "MAILA"},
    {255, "ANY"},
    {256, "URI"},
    {257, "CAA"},
    {258, "AVC"},
    {259, "DOA"},
    {260, "AMTRELAY"},
    {32768, "TA"},
    {32769, "DLV"},
};

static const char *lookup_type_name(uint16_t type) {
    int left = 0;
    int right = sizeof(TYPE_NAMES) / sizeof(TYPE_NAMES[0]) - 1;
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (TYPE_NAMES[mid].type == type) {
            return TYPE_NAMES[mid].name;
        }
        if (TYPE_NAMES[mid].type < type) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return NULL;
}

const char *format_type_name(uint16_t type, char *buf, size_t buf_size) {
    const char *n = lookup_type_name(type);
    if (n) return n;
    snprintf(buf, buf_size, "TYPE%u", type);
    return buf;
}

const char *dns_type_to_string(uint16_t type_code) {
    const char *n = lookup_type_name(type_code);
    if (n) return n;
    static _Thread_local char buf[32];
    snprintf(buf, sizeof(buf), "TYPE%u", type_code);
    return buf;
}

int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

__attribute__((constructor))
static void verify_type_names_sorted(void) {
    size_t n = sizeof(TYPE_NAMES) / sizeof(TYPE_NAMES[0]);
    for (size_t i = 1; i < n; i++) {
        if (TYPE_NAMES[i - 1].type >= TYPE_NAMES[i].type) {
            /* LCOV_EXCL_START */
            fprintf(stderr,
                "FATAL: TYPE_NAMES is not strictly sorted at index %zu (%u >= %u)\n",
                i, TYPE_NAMES[i - 1].type, TYPE_NAMES[i].type);
            abort();
            /* LCOV_EXCL_STOP */
        }
    }
}

size_t hex_decode(const char *hex, uint8_t *out, size_t out_cap) {
    size_t out_len = 0;
    int high = -1;
    for (const char *h = hex; *h; h++) {
        int v = hex_char_to_val(*h);
        if (v < 0) continue; // 空白/コロン等の区切り文字は無視
        if (high < 0) { high = v; continue; }
        if (out_len >= out_cap) return (size_t)-1; // 出力先超過
        out[out_len++] = (uint8_t)((high << 4) | v);
        high = -1;
    }
    return out_len;
}

/* 名前を小文字化したワイヤ形式にし、各ラベルの先頭位置を labels[] に入れる。ラベル数 (ルートを除く)、失敗なら -1。 */
static int canonical_wire_labels(const char *name, uint8_t wire[256], const uint8_t *labels[128]) {
    long w = write_uncompressed_name_ext(wire, 0, 256, name, true);
    if (w <= 0) return -1;
    int n = 0;
    for (long p = 0; p < w && wire[p] != 0; p += 1 + wire[p]) {
        if (n >= 128) return -1;
        labels[n++] = &wire[p];
    }
    return n;
}

/* RFC 4034 §6.1: 右端のラベルから順に、各ラベルを符号なしの左詰めオクテット列として比較する
 * (オクテットが無い方が小さい、英大文字は小文字として扱う)。表示形式のエスケープ (\., \DDD) は
 * ワイヤ形式に直してから比べる。 */
int compare_canonical_name(const char *name1, const char *name2) {
    if (!name1 && !name2) return 0;
    if (!name1) return -1;
    if (!name2) return 1;

    /* 速い経路: エスケープを含まない名前は、テキストのラベルがそのままオクテット列。
     * (クエリ経路の二分探索で毎回呼ばれるので、ワイヤ形式への変換を避ける) */
    if (!strchr(name1, '\\') && !strchr(name2, '\\')) {
        int p1 = (int)strlen(name1), p2 = (int)strlen(name2);
        if (p1 > 0 && name1[p1 - 1] == '.') p1--;
        if (p2 > 0 && name2[p2 - 1] == '.') p2--;
        while (p1 > 0 || p2 > 0) {
            int d1 = p1 - 1, d2 = p2 - 1;
            while (d1 >= 0 && name1[d1] != '.') d1--;
            while (d2 >= 0 && name2[d2] != '.') d2--;
            if (p1 <= 0) return -1;  /* name1 のラベルが尽きた: 祖先が先 */
            if (p2 <= 0) return 1;
            int len1 = p1 - d1 - 1, len2 = p2 - d2 - 1;
            int min_len = len1 < len2 ? len1 : len2;
            for (int i = 0; i < min_len; i++) {
                unsigned char c1 = (unsigned char)name1[d1 + 1 + i];
                unsigned char c2 = (unsigned char)name2[d2 + 1 + i];
                if (c1 >= 'A' && c1 <= 'Z') c1 |= 0x20;
                if (c2 >= 'A' && c2 <= 'Z') c2 |= 0x20;
                if (c1 != c2) return (int)c1 - (int)c2;
            }
            if (len1 != len2) return len1 - len2;
            p1 = d1;
            p2 = d2;
        }
        return 0;
    }

    uint8_t w1[256], w2[256];
    const uint8_t *l1[128], *l2[128];
    int n1 = canonical_wire_labels(name1, w1, l1);
    int n2 = canonical_wire_labels(name2, w2, l2);
    if (n1 >= 0 && n2 >= 0) {
        for (int i1 = n1 - 1, i2 = n2 - 1; i1 >= 0 || i2 >= 0; i1--, i2--) {
            if (i1 < 0) return -1;
            if (i2 < 0) return 1;
            size_t len1 = l1[i1][0], len2 = l2[i2][0];
            int cmp = memcmp(l1[i1] + 1, l2[i2] + 1, len1 < len2 ? len1 : len2);
            if (cmp != 0) return cmp;
            if (len1 != len2) return len1 < len2 ? -1 : 1;
        }
        return 0;
    }
    /* 名前として不正なもの (ゾーンのロード時に弾かれる) は正当な名前の後ろに置き、
     * 不正なもの同士は文字列で比べる (qsort 用に全順序を保つ)。 */
    if (n1 < 0 && n2 < 0) return strcmp(name1, name2);
    return n1 < 0 ? 1 : -1;
}

bool serial_is_newer(uint32_t s1, uint32_t s2) {
    return ((int32_t)(s1 - s2)) > 0;
}

bool dns_path_is_valid_utf8(const unsigned char *p, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned char c = p[i];
    if (c < 0x80) {
      if (c < 0x20 || c == 0x7F) return false;
      i++;
      continue;
    }
    uint32_t cp;
    size_t k;
    if (c >= 0xC2 && c <= 0xDF) { cp = c & 0x1Fu; k = 1; }
    else if (c >= 0xE0 && c <= 0xEF) { cp = c & 0x0Fu; k = 2; }
    else if (c >= 0xF0 && c <= 0xF4) { cp = c & 0x07u; k = 3; }
    else return false; /* continuation byte, 0xC0/0xC1 (overlong) or 0xF5.. */
    if (k > n - i - 1) return false; /* truncated sequence */
    for (size_t j = 1; j <= k; j++) {
      if ((p[i + j] & 0xC0) != 0x80) return false;
      cp = (cp << 6) | (p[i + j] & 0x3Fu);
    }
    static const uint32_t min_cp[] = {0, 0x80, 0x800, 0x10000};
    if (cp < min_cp[k] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) || (cp >= 0x80 && cp <= 0x9F))
      return false;
    i += k + 1;
  }
  return true;
}

const char *strchr_unescaped(const char *s, char c) {
    if (!s) return NULL;
    for (const char *p = s; *p != '\0'; p++) {
        if (*p == '\\') {
            if (*(p + 1) == '\0') {
                break; // Trailing backslash at end of string
            }
            p++; // Skip escaped character
            continue;
        }
        if (*p == c) {
            return p;
        }
    }
    return NULL;
}

/* ThreadSanitizer builds only: built-in suppressions (used without any TSAN_OPTIONS).  The system libcrypto is not built
 * with TSan, so the synchronization inside it (OpenSSL's run-once initialization and its atomics) is invisible, and an
 * interceptor it calls (bcmp, memcpy, ...) may be reported as a race; one such report came from two loader workers that
 * started SHA-256 at the same time.  called_from_lib silences only interceptors called from libcrypto: races in KariDNS's
 * own code are still reported. */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define KARIDNS_TSAN_BUILD 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define KARIDNS_TSAN_BUILD 1
#endif
#ifdef KARIDNS_TSAN_BUILD
const char *__tsan_default_suppressions(void);
const char *__tsan_default_suppressions(void) {
    return "called_from_lib:libcrypto.so\n";
}
#endif




#ifndef _WIN32
/* ---- the files and names the server hands rights to (P1, P4, P5): used by karidns, karicheck and the tests ---- */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>

#if defined(__FreeBSD__)
#define KARIDNS_OPEN_EXEC O_EXEC   /* opened for execution only; fexecve() runs this very file */
#else
#define KARIDNS_OPEN_EXEC O_RDONLY /* karicheck on a portable build: no O_EXEC / fexecve(); the checks are made on the open file all the same */
#endif

int exec_file_open_checked(const char *path, uid_t self, const char *what, const char *who, char *err, size_t errlen) {
  int fd = open(path, KARIDNS_OPEN_EXEC | O_CLOEXEC);
  if (fd < 0) {
    int e = errno;
    struct stat ps;
    if (e == EACCES && stat(path, &ps) == 0 && S_ISREG(ps.st_mode))
      snprintf(err, errlen, "%s '%s' is not executable by %s", what, path, who);
    else if ((e == EACCES || e == EISDIR) && stat(path, &ps) == 0 && !S_ISREG(ps.st_mode))
      snprintf(err, errlen, "%s '%s' is not a regular file", what, path);
    else
      snprintf(err, errlen, "%s '%s': %s", what, path, strerror(e));
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    snprintf(err, errlen, "%s '%s': fstat: %s", what, path, strerror(errno));
    close(fd);
    return -1;
  }
  if (!S_ISREG(st.st_mode)) {
    snprintf(err, errlen, "%s '%s' is not a regular file", what, path);
    close(fd);
    return -1;
  }
  /* both findings are reported when both apply (karicheck shows them to the operator in one go) */
  size_t n = 0;
  err[0] = '\0';
  if (st.st_uid != 0 && st.st_uid != self)
    n += (size_t)snprintf(err, errlen, "%s '%s' is owned by uid %u; it must belong to root%s", what, path, (unsigned)st.st_uid,
                          self == 0 ? "" : " or to the user running karidns");
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) && n < errlen)
    n += (size_t)snprintf(err + n, errlen - n, "%s%s '%s' is writable by group or others (mode %04o)", n ? "; " : "", what, path,
                          (unsigned)(st.st_mode & 07777));
  if (n) {
    close(fd);
    return -1;
  }
  return fd;
}

int exec_file_exec_fd(int fd, const char *path, char *const argv[], char *const envp[]) {
#if defined(__FreeBSD__)
  /* An O_EXEC descriptor cannot be read, so whether the file is a script (#!) is looked at through a second, read-only
   * open of the path: only this classification depends on the name (a misread binary is still executed through `fd`; a
   * misread script fails in its interpreter) */
  int rfd = open(path, O_RDONLY | O_CLOEXEC);
  unsigned char head[2] = { 0, 0 };
  bool script = rfd >= 0 && read(rfd, head, 2) == 2 && head[0] == '#' && head[1] == '!';
  if (rfd >= 0) close(rfd);
  if (script) {
    /* execve(2): the kernel hands a script's interpreter "/dev/fd/N", which exists only when fdescfs(4) is mounted, and the
     * interpreter must find the descriptor open: it is left open across the exec for this case only */
    char devfd[32];
    snprintf(devfd, sizeof(devfd), "/dev/fd/%d", fd);
    if (access(devfd, F_OK) != 0 || fcntl(fd, F_SETFD, 0) != 0) {
      execve(path, argv, envp);
      return -1;
    }
  }
  fexecve(fd, argv, envp);
#else
  (void)fd;
  execve(path, argv, envp);
#endif
  return -1;
}

bool identity_names_root(const char *user, const char *group, char *err, size_t errlen) {
  char buf[16384];
  gid_t gid = (gid_t)-1;
  bool have_gid = false, gid_from_group = false;
  if (user) {
    struct passwd pw, *res = NULL;
    if (getpwnam_r(user, &pw, buf, sizeof(buf), &res) == 0 && res) {
      if (pw.pw_uid == 0) {
        snprintf(err, errlen, "user '%s' is uid 0: root is not accepted as the user to run as", user);
        return true;
      }
      gid = pw.pw_gid;
      have_gid = true;
    }
  }
  if (group) {
    struct group gr, *res = NULL;
    if (getgrnam_r(group, &gr, buf, sizeof(buf), &res) == 0 && res) {
      gid = gr.gr_gid;   /* the group named overrides the user's primary group */
      have_gid = gid_from_group = true;
    }
  }
  if (have_gid && gid == 0) {
    if (gid_from_group)
      snprintf(err, errlen, "group '%s' is gid 0: the root group is not accepted as the group to run as", group);
    else
      snprintf(err, errlen, "user '%s' has the root group (gid 0) as its primary group: set a group, the root group is not "
                            "accepted as the group to run as", user);
    return true;
  }
  return false;
}
#endif

#ifndef _WIN32
/* ---- the entry points of the operational log (dns_log.h) ---- */
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include "dns_logcat.h"
#include "dns_log.h"
#undef syslog   /* the calls below are the real syslog() (or the unit test's stub), not kdns_syslog() */

/* Written once, before the threads exist (the server installs it at start-up); null = no routing. */
static _Atomic(klog_hook_t) g_klog_hook;

void klog_set_hook(klog_hook_t hook) {
  atomic_store_explicit(&g_klog_hook, hook, memory_order_release);
}

const char *const log_category_names[LOGC_COUNT] = {
  [LOGC_DEFAULT] = "default", [LOGC_GENERAL] = "general", [LOGC_SSLKEYLOG] = "sslkeylog", [LOGC_NOTIFY] = "notify",
  [LOGC_DATABASE] = "database", [LOGC_SECURITY] = "security", [LOGC_DNSSEC] = "dnssec", [LOGC_RESOLVER] = "resolver",
  [LOGC_XFER_IN] = "xfer-in", [LOGC_XFER_OUT] = "xfer-out", [LOGC_DISPATCH] = "dispatch", [LOGC_LAME_SERVERS] = "lame-servers",
  [LOGC_EDNS_DISABLED] = "edns-disabled", [LOGC_RPZ] = "rpz", [LOGC_RATE_LIMIT] = "rate-limit", [LOGC_CNAME] = "cname",
  [LOGC_SPILL] = "spill", [LOGC_DNSTAP] = "dnstap", [LOGC_ZONELOAD] = "zoneload", [LOGC_NSID] = "nsid",
  [LOGC_RPZ_PASSTHRU] = "rpz-passthru", [LOGC_CLIENT] = "client", [LOGC_NETWORK] = "network", [LOGC_UPDATE] = "update",
  [LOGC_QUERIES] = "queries", [LOGC_UPDATE_SECURITY] = "update-security", [LOGC_QUERY_ERRORS] = "query-errors",
  [LOGC_TRUST_ANCHOR_TELEMETRY] = "trust-anchor-telemetry", [LOGC_SERVE_STALE] = "serve-stale", [LOGC_RESPONSES] = "responses",
  [LOGC_CONFIG] = "config", [LOGC_UNMATCHED] = "unmatched",
};

int log_category_from_name(const char *name) {
  if (!name) return -1;
  for (int i = 0; i < LOGC_COUNT; i++)
    if (strcmp(name, log_category_names[i]) == 0) return i;
  return -1;
}

/* syslog() understands %m (the text of errno); vsnprintf() does not everywhere.  Expand it first (a '%' inside the text is doubled).
 * A format too long to expand is left as it is. */
size_t klog_vformat(char *buf, size_t n, const char *fmt, va_list ap, int saved_errno) {
  if (!buf || n == 0) return 0;
  char fbuf[KLOG_MSG_MAX];
  const char *f = fmt;
  if (strstr(fmt, "%m") && strlen(fmt) < sizeof(fbuf) / 2) {
    size_t o = 0;
    for (const char *p = fmt; *p && o + 2 < sizeof(fbuf); p++) {
      if (p[0] == '%' && p[1] == '%') {
        fbuf[o++] = '%';
        fbuf[o++] = '%';
        p++;
      } else if (p[0] == '%' && p[1] == 'm') {
        for (const char *e = strerror(saved_errno); *e && o + 3 < sizeof(fbuf); e++) {
          if (*e == '%') fbuf[o++] = '%';
          fbuf[o++] = *e;
        }
        p++;
      } else {
        fbuf[o++] = *p;
      }
    }
    fbuf[o] = '\0';
    f = fbuf;
  }
  int r = vsnprintf(buf, n, f, ap);
  if (r < 0) {
    buf[0] = '\0';
    return 0;
  }
  return (size_t)r < n ? (size_t)r : n - 1;
}

static void klog_dispatch(int cat, int prio, const char *fmt, va_list ap, int saved_errno) {
  klog_hook_t hook = atomic_load_explicit(&g_klog_hook, memory_order_acquire);
  if (hook) {
    hook(cat, prio, fmt, ap, saved_errno);
    return;
  }
  char msg[KLOG_MSG_MAX];
  klog_vformat(msg, sizeof(msg), fmt, ap, saved_errno);
  syslog(prio, "%s", msg);
}

void kdns_syslog(int prio, const char *fmt, ...) {
  int saved = errno;
  va_list ap;
  va_start(ap, fmt);
  klog_dispatch(LOGC_AUTO, prio, fmt, ap, saved);
  va_end(ap);
}

void kdns_logc(int cat, int prio, const char *fmt, ...) {
  int saved = errno;
  va_list ap;
  va_start(ap, fmt);
  klog_dispatch(cat, prio, fmt, ap, saved);
  va_end(ap);
}
#endif
