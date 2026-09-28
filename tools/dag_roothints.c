#include "dag_internal.h"
#include "dag_roothints.h"

/* IANA named.root (https://www.internic.net/domain/named.root) 相当。
 * b.root-servers.net は 2023-11 のアドレス変更後の値。 */
static const struct { const char *name; const char *v4; const char *v6; } k_builtin_roots[] = {
    { "a.root-servers.net.", "198.41.0.4",     "2001:503:ba3e::2:30" },
    { "b.root-servers.net.", "170.247.170.2",  "2801:1b8:10::b" },
    { "c.root-servers.net.", "192.33.4.12",    "2001:500:2::c" },
    { "d.root-servers.net.", "199.7.91.13",    "2001:500:2d::d" },
    { "e.root-servers.net.", "192.203.230.10", "2001:500:a8::e" },
    { "f.root-servers.net.", "192.5.5.241",    "2001:500:2f::f" },
    { "g.root-servers.net.", "192.112.36.4",   "2001:500:12::d0d" },
    { "h.root-servers.net.", "198.97.190.53",  "2001:500:1::53" },
    { "i.root-servers.net.", "192.36.148.17",  "2001:7fe::53" },
    { "j.root-servers.net.", "192.58.128.30",  "2001:503:c27::2:30" },
    { "k.root-servers.net.", "193.0.14.129",   "2001:7fd::1" },
    { "l.root-servers.net.", "199.7.83.42",    "2001:500:9f::42" },
    { "m.root-servers.net.", "202.12.27.33",   "2001:dc3::35" },
};

static void roothints_add(roothints_t *rh, const char *name, const char *addr) {
    if (rh->count >= ROOTHINT_MAX) return;
    snprintf(rh->h[rh->count].name, sizeof(rh->h[rh->count].name), "%s", name);
    snprintf(rh->h[rh->count].addr, sizeof(rh->h[rh->count].addr), "%s", addr);
    rh->count++;
}

void roothints_load_builtin(roothints_t *rh) {
    rh->count = 0;
    for (size_t i = 0; i < sizeof(k_builtin_roots) / sizeof(k_builtin_roots[0]); i++) {
        roothints_add(rh, k_builtin_roots[i].name, k_builtin_roots[i].v4);
        roothints_add(rh, k_builtin_roots[i].name, k_builtin_roots[i].v6);
    }
}

static bool is_ip_literal(const char *s, int *family_out) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, s, &a4) == 1) { if (family_out) *family_out = AF_INET; return true; }
    if (inet_pton(AF_INET6, s, &a6) == 1) { if (family_out) *family_out = AF_INET6; return true; }
    return false;
}

static bool is_ttl_token(const char *s) {
    if (!*s) return false;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) return false;
    }
    return true;
}

/* 末尾ドットを付けて小文字化した名前を dst に書く */
static void norm_name(char *dst, size_t cap, const char *src) {
    size_t n = 0;
    for (; *src && n + 2 < cap; src++) dst[n++] = (char)tolower((unsigned char)*src);
    if (n == 0 || dst[n - 1] != '.') dst[n++] = '.';
    dst[n] = '\0';
}

#define RH_MAX_PENDING 128

int roothints_parse_text(const char *text, roothints_t *rh, char *err, size_t err_len) {
    char ns_names[ROOTHINT_MAX][256];
    int ns_count = 0;
    /* 解析途中のアドレス。NS 名との突き合わせは全行読んでから行う */
    struct { char name[256]; char addr[64]; } *pend = calloc(RH_MAX_PENDING, sizeof(*pend));
    if (!pend) {
        snprintf(err, err_len, "out of memory");
        return -1;
    }
    int pend_count = 0;
    int lineno = 0;
    rh->count = 0;

    const char *p = text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[1024];
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        p = eol ? eol + 1 : p + strlen(p);
        lineno++;

        char *semi = strchr(line, ';');
        if (semi) *semi = '\0';
        char *tok[8];
        int nt = 0;
        for (char *save = NULL, *t = strtok_r(line, " \t\r", &save); t && nt < 8; t = strtok_r(NULL, " \t\r", &save)) {
            tok[nt++] = t;
        }
        if (nt == 0) continue;

        /* "name address" の2カラム形式 */
        if (nt == 2 && is_ip_literal(tok[1], NULL)) {
            if (pend_count < RH_MAX_PENDING) {
                norm_name(pend[pend_count].name, sizeof(pend[pend_count].name), tok[0]);
                snprintf(pend[pend_count].addr, sizeof(pend[pend_count].addr), "%s", tok[1]);
                pend_count++;
            }
            continue;
        }

        /* owner [ttl] [class] type rdata */
        int i = 1;
        if (i < nt && is_ttl_token(tok[i])) i++;
        if (i < nt && (strcasecmp(tok[i], "IN") == 0)) i++;
        if (i < nt && is_ttl_token(tok[i])) i++;
        if (i + 1 >= nt) {
            snprintf(err, err_len, "line %d: malformed record", lineno);
            free(pend);
            return -1;
        }
        const char *type = tok[i];
        const char *rdata = tok[i + 1];
        char owner[256];
        norm_name(owner, sizeof(owner), tok[0]);
        if (strcasecmp(type, "NS") == 0) {
            if (strcmp(owner, ".") == 0 && ns_count < ROOTHINT_MAX) {
                norm_name(ns_names[ns_count], sizeof(ns_names[ns_count]), rdata);
                ns_count++;
            }
        } else if (strcasecmp(type, "A") == 0 || strcasecmp(type, "AAAA") == 0) {
            int fam = 0;
            if (!is_ip_literal(rdata, &fam) || (fam == AF_INET) != (strcasecmp(type, "A") == 0)) {
                snprintf(err, err_len, "line %d: invalid %s address '%s'", lineno, type, rdata);
                free(pend);
                return -1;
            }
            if (pend_count < RH_MAX_PENDING) {
                snprintf(pend[pend_count].name, sizeof(pend[pend_count].name), "%s", owner);
                snprintf(pend[pend_count].addr, sizeof(pend[pend_count].addr), "%s", rdata);
                pend_count++;
            }
        }
        /* それ以外の型は無視する */
    }

    for (int k = 0; k < pend_count; k++) {
        bool take = (ns_count == 0);
        for (int j = 0; j < ns_count && !take; j++) {
            if (strcmp(ns_names[j], pend[k].name) == 0) take = true;
        }
        if (take) roothints_add(rh, pend[k].name, pend[k].addr);
    }
    free(pend);

    if (rh->count == 0) {
        snprintf(err, err_len, "no root server addresses found");
        return -1;
    }
    return rh->count;
}

int roothints_load_file(const char *path, roothints_t *rh, char *err, size_t err_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        snprintf(err, err_len, "%s: %s", path, strerror(errno));
        return -1;
    }
    size_t cap = 65536, len = 0;
    char *buf = malloc(cap + 1);
    if (!buf) {
        fclose(fp);
        snprintf(err, err_len, "out of memory");
        return -1;
    }
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, fp)) > 0) {
        len += n;
        if (len == cap) {
            /* named.root は数 KB。1MB を超えるものは拒否する */
            if (cap >= 1024 * 1024) {
                free(buf);
                fclose(fp);
                snprintf(err, err_len, "%s: file too large", path);
                return -1;
            }
            char *nb = realloc(buf, cap * 2 + 1);
            if (!nb) {
                free(buf);
                fclose(fp);
                snprintf(err, err_len, "out of memory");
                return -1;
            }
            buf = nb;
            cap *= 2;
        }
    }
    fclose(fp);
    buf[len] = '\0';
    int rc = roothints_parse_text(buf, rh, err, err_len);
    free(buf);
    return rc;
}
