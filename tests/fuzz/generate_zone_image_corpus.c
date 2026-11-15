/*
 * generate_zone_image_corpus.c - seeds for fuzz_zone_image_validate: the images zone_image_freeze() makes of the zone
 * files under a directory (default tests/zones) and of a few zones written out below (NSEC / NSEC3 chains and glue,
 * tinydns locations and time stamps, $LOCATION / $ECS-SUBNET tags with trusted resolvers, interleaved owners, ALIAS,
 * mixed-case and escaped owners).  One file per image, `<out_dir>/img_<name>.bin`; the bytes are what the store keeps.
 *
 *   make tests/fuzz/generate_zone_image_corpus   (see the Makefile)
 *   tests/fuzz/generate_zone_image_corpus tests/fuzz/corpus_fuzz_zone_image_validate [tests/zones]
 *
 * Images above 256 KiB are skipped: the fuzzer is faster on small ones and the large zones add no new structure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../../dns_wire.h"
#include "../../dns_zone_parser.h"
#include "../../dns_zone_image.h"

int open_via_dir_cache(const char *path, int flags, mode_t mode, bool writable) {
    (void)mode; (void)writable;
    return open(path, flags);
}

static char *load_file_cb(parse_context_t *ctx, const char *path, dev_t *out_dev, ino_t *out_ino) {
    (void)ctx;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    if (out_dev) *out_dev = st.st_dev;
    if (out_ino) *out_ino = st.st_ino;
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n < 0) { free(buf); return NULL; }
    buf[n] = '\0';
    return buf;
}

static void silent_report(const dns_record_t *rec, void *ud) { (void)rec; (void)ud; }

static const char *g_out;
static int g_written;

/* parse like reload_master_zone(), freeze and write the image; 0 = written */
static int make_image(const char *name, const char *text, const char *origin, const char *base_dir, bool tinydns) {
    zone_arena_t a;
    zone_arena_init(&a);
    char *visited_paths[16] = { 0 };
    dev_t visited_devs[16] = { 0 };
    ino_t visited_inos[16] = { 0 };
    char *root_ttl = NULL, *root_ecs = NULL, *root_loc = NULL;
    parse_error_t err;
    memset(&err, 0, sizeof(err));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.base_dir = base_dir ? base_dir : ".";
    ctx.default_origin = origin;
    ctx.is_standalone_mode = true;
    ctx.err_out = &err;
    ctx.visited_paths = visited_paths;
    ctx.visited_devs = visited_devs;
    ctx.visited_inos = visited_inos;
    ctx.visited_cap = 16;
    ctx.load_file_cb = load_file_cb;
    ctx.shared_ttl_io = &root_ttl;
    ctx.shared_ecs_tag_io = &root_ecs;
    ctx.shared_loc_tag_io = &root_loc;
    char *buf = arena_strdup(&a, text);
    int rc = -1;
    if (!buf) goto out;
    if ((tinydns ? parse_tinydns_data(buf, strlen(buf), &a, &ctx) : parse_zone_fast(buf, strlen(buf), &a, &ctx)) < 0) goto out;
    zone_arena_drop_out_of_zone(&a, origin, silent_report, NULL);
    zone_arena_drop_unencodable(&a, silent_report, NULL);
    zone_arena_shrink_records(&a);
    if (a.count == 0 || build_zone_index(&a, true) != 0) goto out;
    const char *apex = origin;
    for (size_t i = 0; i < a.count; i++)
        if (a.records[i].type_code == 6 && a.records[i].name) { apex = a.records[i].name; break; }
    zone_image_t *img = zone_image_freeze(&a, apex);
    if (!img) goto out;
    char why[200];
    if (zone_image_validate(img, img->total_size, why, sizeof(why)) != 0) {
        fprintf(stderr, "%s: the image of this zone does not validate: %s\n", name, why);
        zone_image_free(img);
        goto out;
    }
    if (img->total_size > (256u << 10)) {
        fprintf(stderr, "%s: %u octets, skipped\n", name, img->total_size);
        zone_image_free(img);
        goto out;
    }
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/img_%s.bin", g_out, name);
    FILE *f = fopen(path, "wb");
    if (f) {
        if (fwrite(img, 1, img->total_size, f) == img->total_size) { g_written++; rc = 0; }
        fclose(f);
    }
    zone_image_free(img);
out:
    zone_arena_destroy(&a);
    return rc;
}

static const struct { const char *name, *origin; bool tinydns; const char *text; } BUILTIN[] = {
    { "rich", "rich.example.", false,
      "$ORIGIN rich.example.\n$TTL 3600\n"
      "@ IN SOA ns1 hostmaster 2026111401 7200 3600 1209600 300\n"
      "@ IN NS ns1\n@ IN NS NS2.Rich.Example.\n@ IN NS ns.other.test.\n"
      "@ IN A 192.0.2.1\n@ IN AAAA 2001:db8::1\n@ IN MX 10 mail\n@ IN MX 20 mail2.other.test.\n@ IN TXT \"v=spf1 -all\"\n"
      "@ IN CAA 0 issue \"ca.example.test\"\n"
      "ns1 IN A 192.0.2.53\nNS2 IN AAAA 2001:db8::53\nmail IN A 192.0.2.10\n"
      "www IN CNAME target\ntarget IN A 192.0.2.20\nloop1 IN CNAME loop2\nloop2 IN CNAME loop1\n"
      "dn IN DNAME elsewhere.example.test.\n"
      "*.wild IN A 192.0.2.100\n*.wild IN TXT \"wildcard\"\nent.sub IN A 192.0.2.101\n"
      "sub IN NS ns.sub\nns.sub IN A 192.0.2.60\nsub IN DS 1 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
      "MixedCase IN A 192.0.2.50\nmixedcase IN A 192.0.2.51\nMIXEDCASE IN TXT \"t\"\nesc\\.dot IN A 192.0.2.54\nsp\\032ace IN TXT \"sp\"\n"
      "_sip._tcp IN SRV 10 60 5060 www\n_443._tcp IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
      "svc IN HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1\nunk IN TYPE65280 \\# 4 DEADBEEF\nunk0 IN TYPE65281 \\# 0\n"
      "@ IN NSEC mail A AAAA MX NS SOA TXT CAA RRSIG NSEC\n"
      "mail IN NSEC www A RRSIG NSEC\nwww IN NSEC @ CNAME RRSIG NSEC\n"
      "@ IN RRSIG SOA 13 2 3600 20300101000000 20200101000000 12345 rich.example. c2lnbmF0dXJl\n"
      "@ IN DNSKEY 257 3 13 AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jDaC/BNVI7NzXAWz2sMz1+\n" },
    { "nsec3", "n3.example.", false,
      "$ORIGIN n3.example.\n$TTL 3600\n"
      "@ IN SOA ns1 hostmaster 2026111401 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n@ IN A 192.0.2.1\n"
      "*.w IN A 192.0.2.7\nd IN NS ns.d\nns.d IN A 192.0.2.9\n"
      "@ IN NSEC3PARAM 1 0 12 aabbccdd\n"
      "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM IN NSEC3 1 1 12 aabbccdd 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG\n"
      "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR IN NSEC3 1 1 12 aabbccdd 6C1B6OTLU1LDBBG5I5HEGT2PGCLEUDRB NS SOA MX RRSIG DNSKEY NSEC3PARAM\n"
      "6C1B6OTLU1LDBBG5I5HEGT2PGCLEUDRB IN NSEC3 1 1 12 aabbccdd 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM NS DS RRSIG\n"
      "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM IN RRSIG NSEC3 8 3 3600 20300101000000 20200101000000 12345 n3.example. c2lnbmF0dXJl\n"
      "@ IN RRSIG NSEC3PARAM 8 2 3600 20300101000000 20200101000000 12345 n3.example. c2lnbmF0dXJl\n"
      "@ IN DNSKEY 257 3 8 AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jDaC/BNVI7NzXAWz2sMz1+\n" },
    { "two_chains", "n3b.example.", false,
      "$ORIGIN n3b.example.\n$TTL 300\n"
      "@ IN SOA ns1 h 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n"
      "@ IN NSEC3PARAM 1 0 0 -\n"
      "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM IN NSEC3 1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG\n"
      "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR IN NSEC3 1 0 0 - 0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM NS SOA RRSIG NSEC3PARAM\n"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA IN NSEC3 1 1 3 ab BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB A\n"
      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB IN NSEC3 1 1 3 ab AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A\n" },
    { "tinydns", "tiny.test.", true,
      "%in:127.0.0.1\n%ex:10.0.0.0/8\n%lo:192.168\n"
      ".tiny.test:127.0.0.1:ns1.tiny.test:2560\n"
      "+act-future.tiny.test:192.168.1.10:300:40000000b2d05e00\n"
      "+act-past.tiny.test:192.168.1.20:300:400000003b9aca00\n"
      "+cnt-valid.tiny.test:192.168.1.30:0:4000000099999999\n"
      "+normal.tiny.test:192.168.1.50:600\n"
      "+www.tiny.test:192.168.1.10:300::in\n+www.tiny.test:10.0.0.10:300::ex\n+www.tiny.test:192.0.2.4:300\n"
      "+Mixed.Tiny.Test:192.0.2.9:300::lo\n"
      "@tiny.test:192.168.1.30:mx1.tiny.test:10:1800\n'txt.tiny.test:Hello\\040World:300\n^ptr.tiny.test:target.tiny.test:600\n"
      "Calias.tiny.test:www.tiny.test:1200\n"
      "Zcustom.tiny.test:ns1.custom.tiny.test:admin.custom.tiny.test:2026090201:7200:3600:1209600:300:600\n"
      ":ssh.tiny.test:44:\\002\\001\\001\\012\\023\\045:3600\n&sub.tiny.test:192.0.2.61:ns.sub.tiny.test:259200\n" },
    { "tags", "tag.test.", false,
      "$ORIGIN tag.test.\n$TTL 300\n"
      "@ IN SOA ns1 host 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
      "$LOCATION-TAG office 192.0.2.0/24 198.51.100.0/24\n"
      "$ECS-SUBNET-TAG far 203.0.113.0/24 2001:db8::/32\n$ECS-SUBNET-TAG near 198.51.100.0/24 192.0.2.128/25\n"
      "$LOCATION office\nwww IN A 192.0.2.10\n"
      "$LOCATION \"\"\n$ECS-SUBNET far\nwww IN A 192.0.2.20\n$ECS-SUBNET near\nwww IN A 192.0.2.25\nwww IN AAAA 2001:db8::25\n"
      "$ECS-SUBNET \"\"\nwww IN A 192.0.2.30\n" },
    { "interleaved", "perm.test.", false,
      "$ORIGIN perm.test.\n$TTL 300\n"
      "@ IN SOA ns1 host 1 7200 3600 1209600 300\n"
      "www IN A 192.0.2.1\n@ IN NS ns1\nwww IN AAAA 2001:db8::1\nns1 IN A 192.0.2.53\n@ IN MX 10 www\nwww IN TXT \"x\"\n" },
    { "alias", "al.test.", false,
      "$ORIGIN al.test.\n$TTL 60\n@ SOA ns h 1 2 3 4 5\n@ NS ns\nns A 192.0.2.1\n"
      "a ALIAS t.target.test.\na TXT \"x\"\nl LUA A \"c\"\nb A 192.0.2.2\n" },
    { "soa_set", "ss.test.", true,
      "%in:127.0.0.1\n%ex:10.0.0.0/8\n"
      "Zss.test:ns1.in.ss.test.:h.ss.test.:5:7200:3600:1209600:300:300::in\n"
      "Zss.test:ns1.ex.ss.test.:h.ss.test.:6:7200:3600:1209600:300:300::ex\n"
      "Zss.test:ns1.ss.test.:h.ss.test.:7:7200:3600:1209600:300:300\n"
      "&ss.test::ns1.ss.test.:300\n+ns1.ss.test:192.0.2.1:300\n" },
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s OUT_DIR [ZONE_DIR]\n", argv[0]);
        return 2;
    }
    g_out = argv[1];
    const char *dir = argc > 2 ? argv[2] : "tests/zones";
    for (size_t i = 0; i < sizeof(BUILTIN) / sizeof(BUILTIN[0]); i++)
        if (make_image(BUILTIN[i].name, BUILTIN[i].text, BUILTIN[i].origin, NULL, BUILTIN[i].tinydns) != 0)
            fprintf(stderr, "%s: not written\n", BUILTIN[i].name);
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "no %s\n", dir); return 1; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t l = strlen(de->d_name);
        if (l < 6 || strcmp(de->d_name + l - 5, ".zone") != 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        char *text = load_file_cb(NULL, path, NULL, NULL);
        if (!text) continue;
        /* the zone name: the first $ORIGIN of the file, else a default (as tests/test_zone_image.c) */
        char origin_buf[256];
        const char *origin = strncmp(de->d_name, "example.com", 11) == 0 ? "example.com." : "example.";
        for (const char *p = text; (p = strstr(p, "$ORIGIN")) != NULL; p += 7) {
            if (p != text && p[-1] != '\n') continue;
            p += 7;
            while (*p == ' ' || *p == '\t') p++;
            size_t n = 0;
            while (p[n] && p[n] != ' ' && p[n] != '\t' && p[n] != '\r' && p[n] != '\n' && p[n] != ';' && n < sizeof(origin_buf) - 2) n++;
            if (n == 0) break;
            memcpy(origin_buf, p, n);
            if (origin_buf[n - 1] != '.') origin_buf[n++] = '.';
            origin_buf[n] = '\0';
            origin = origin_buf;
            break;
        }
        char name[PATH_MAX];
        snprintf(name, sizeof(name), "%.*s", (int)(l - 5), de->d_name);
        make_image(name, text, origin, dir, false);   /* (a zone that does not load is skipped: not every file is meant to) */
        free(text);
    }
    closedir(d);
    printf("%d images written to %s\n", g_written, g_out);
    return g_written > 0 ? 0 : 1;
}
