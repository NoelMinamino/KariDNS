/*
 * test_coverage_sweep_tools.c - coverage sweeps for karicheck and karictl.
 *
 *   karicheck: every lint rule is fed a zone (BIND and tinydns-data) or config that
 *              triggers it, via karicheck's real main() run in a forked child.
 *   karictl:   a fake control socket implements the CHALLENGE/AUTH handshake and
 *              answers every command (status/reload/.../observatory) and error path.
 * karicheck.c / karictl.c are compiled in with main() renamed.
 */
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "sweep_watchdog.h"

#define main karicheck_main
#include "../tools/karicheck.c"
#undef main

int karictl_main(int argc, char **argv);

#define N(a) (sizeof(a) / sizeof((a)[0]))
static char g_tmp[256];
static int g_runs;

static int run_child(int (*fn)(int, char **), int argc, char **argv) {
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        if (!getenv("SWTOOLS_VERBOSE")) { int dn = open("/dev/null", O_WRONLY); dup2(dn, 1); dup2(dn, 2); }
        wd_child();
        alarm(20);
        exit(fn(argc, argv) & 0xFF);
    }
    int st = 0; waitpid(pid, &st, 0);
    g_runs++;
    if (WIFSIGNALED(st) && WTERMSIG(st) != SIGALRM) {
        fprintf(stderr, "  !! crashed (signal %d):", WTERMSIG(st));
        for (int i = 0; i < argc; i++) fprintf(stderr, " %s", argv[i]);
        fprintf(stderr, "\n");
        assert(!"tool crashed");
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int run_tool(int (*fn)(int, char **), const char *name, ...) {
    char *argv[16]; int argc = 0; argv[argc++] = (char *)name;
    va_list ap; va_start(ap, name);
    for (const char *a; (a = va_arg(ap, const char *)) != NULL && argc < 15;) argv[argc++] = (char *)a;
    va_end(ap); argv[argc] = NULL;
    return run_child(fn, argc, argv);
}

static const char *wfile(const char *name, const char *text) {
    static char paths[64][300]; static int n;
    char *p = paths[n++ % 64];
    snprintf(p, 300, "%s/%s", g_tmp, name);
    FILE *f = fopen(p, "w"); assert(f); fputs(text, f); fclose(f);
    return p;
}

/* ---------------------------------------------------------------- karicheck */
#define HDR(z) "$ORIGIN " z "\n$TTL 300\n@ IN SOA ns1." z " h." z " 2026092501 7200 3600 1209600 300\n@ IN NS ns1." z "\nns1 IN A 192.0.2.1\n"

static const char *BIND_ZONES[] = {
    HDR("a.test.") "www IN A 192.0.2.2\n",
    HDR("a.test.") "$LOCATION-TAG office 10.0.0.0/8\n$LOCATION office\nx IN A 192.0.2.3\n$LOCATION nosuchtag\ny IN A 192.0.2.4\n",
    HDR("a.test.") "$ECS-SUBNET-TAG eu 198.51.100.0/24\n$ECS-SUBNET eu\ne IN A 192.0.2.5\n$ECS-SUBNET missing\nf IN A 192.0.2.6\n",
    HDR("a.test.") "svc IN SVCB 1 target.a.test alpn=h2\nhttps IN HTTPS 1 other.test alpn=h3\nsvc2 IN SVCB 0 alias.test.\n",
    HDR("a.test.") "hip IN HIP 2 200100107B1A74DF365639CC39F1D578\ngpos IN GPOS 1 2\nx25 IN X25 \\# 0\nisdn IN ISDN \"1\" \"2\" \"3\"\n",
    HDR("a.test.") "sub IN NS ns.sub.a.test.\nsub IN NS ns.other.test.\nsub2 IN NS ns.sub2.a.test.\nns.sub2 IN A 192.0.2.9\n"
                   "ns.other.test. IN A 192.0.2.10\nsub3 IN NS ns.sub3.a.test.\nns.sub3 IN AAAA not:an:ip\n",
    "$ORIGIN a.test.\n$TTL 300\n@ IN SOA mn.a.test. h.a.test. 1 2 3 4 5\n@ IN NS ns1.a.test.\nns1 IN A 192.0.2.1\nmn IN CNAME ns1.a.test.\n",
    HDR("a.test.") "m IN TYPE251 \\# 0\nm2 IN TYPE252 \\# 0\nm3 IN OPT \\# 0\nm4 IN TYPE255 \\# 0\n",
    HDR("a.test.") "@ IN NSEC3PARAM 1 1 10 AABB\nabc IN NSEC3 1 1 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A\n@ IN NSEC3PARAM 2 0 200 -\n",
    HDR("a.test.") "@ IN DNSKEY 257 3 99 AwEAAQ==\n@ IN DS 1 13 0 00\n@ IN DS 1 13 9 AABB\n@ IN CDS 0 0 0 00\n@ IN CDS 1 13 0 AA\n@ IN RRSIG A 200 2 300 20300101000000 20200101000000 1 a.test. AAAA\n",
    HDR("a.test.") "@ IN ZONEMD 1 1 1 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899\n"
                   "@ IN ZONEMD 2026092501 1 1 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899\n"
                   "@ IN ZONEMD 2026092501 1 2 AABB\n@ IN ZONEMD 2026092501 2 1 AABB\n",
    HDR("a.test.") "a IN A 192.0.2.1\na IN CNAME b.a.test.\nc IN CNAME c.a.test.\n*.w IN CNAME x.test.\nd IN DNAME e.test.\nf.d IN A 192.0.2.1\n",
    HDR("a.test.") "t IN TXT \"" "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345" "\"\nmx IN MX 10 cname.a.test.\ncname IN CNAME www.a.test.\nsrv IN SRV 1 1 1 cname.a.test.\n",
    HDR("a.test.") "$INCLUDE inc_missing.zone\n",
    HDR("a.test.") "bad IN A 999.1.1.1\n",
    HDR("a.test.") "long.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa IN A 192.0.2.1\n",
    "$ORIGIN a.test.\n$TTL 300\nwww IN A 192.0.2.1\n",
    "$ORIGIN a.test.\n$TTL 300\n@ IN SOA ns1.a.test. h.a.test. 1 2 3 4 5\n@ IN SOA ns1.a.test. h.a.test. 2 2 3 4 5\n",
    "",
    "$ORIGIN other.test.\n@ 300 IN SOA a. b. 1 2 3 4 5\n",
    HDR("a.test.") "out.of.zone.test. IN A 192.0.2.1\n",
    HDR("a.test.") "ttl 4294967295 IN A 192.0.2.1\nttl2 0 IN A 192.0.2.2\nttl2 60 IN A 192.0.2.3\n",
    /* one lint issue per zone, so that a parse error elsewhere cannot hide it */
    HDR("a.test.") "hip IN HIP 2 200100107B1A74DF365639CC39F1D578\n",
    HDR("a.test.") "hip IN HIP 2 200100107B1A74DF365639CC39F1D578 AwEAAb\n",
    HDR("a.test.") "hip IN HIP 2 200100107B1A74DF365639CC39F1D578 AwEAAQ== rvs.a.test.\n",
    HDR("a.test.") "w IN WKS 192.0.2.1 zzz smtp\n",
    HDR("a.test.") "c IN CSYNC 1 0 A NOSUCHTYPE\n",
    HDR("a.test.") "@ IN ZONEMD 1 1\n",
    HDR("a.test.") "sub IN ZONEMD 2026092501 1 1 AABB\n",
    HDR("a.test.") "@ IN DNSKEY 257 3 5 AwEAAQ==\n@ IN CDNSKEY 0 3 0 AA==\n@ IN DNSKEY 256 3 1 AwEAAQ==\n@ IN RRSIG A 3 2 300 20300101000000 20200101000000 1 a.test. AAAA\n",
    HDR("a.test.") "@ IN DS 1 8 1 AABBCCDDEEFF00112233445566778899AABBCCDD\n@ IN CDS 1 5 3 AABB\n",
    HDR("a.test.") "sub IN NS ns.other.test.\nns.other.test. IN A 192.0.2.10\n",
    HDR("a.test.") "sub IN NS ns.sub.a.test.\n",
    HDR("a.test.") "sub IN NS ns.sub.a.test.\nns.sub IN AAAA 2001:db8::1\n",
    HDR("a.test.") "s IN SRV 1 2 3 .\ns2 IN SRV 1 2 3 nx.a.test.\n",
};

static const char *CATALOG_ZONES[] = {
    HDR("cat.test.") "version IN TXT \"2\"\nu1.zones IN PTR m1.test.\ngroup.u1.zones IN TXT \"g\"\ngroup.u2.zones IN TXT \"orphan\"\ncoo.u1.zones IN PTR other.cat.\n",
    HDR("cat.test.") "version IN TXT \"1\"\nu1.zones IN PTR m1.test.\nu2.zones IN PTR m1.test.\nu3.zones IN TXT \"x\"\n",
    HDR("cat.test.") "u1.zones IN PTR m1.test.\n",
    HDR("cat.test.") "version IN TXT \"2\"\ngroup.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zones IN TXT \"g\"\n",
};

static const char *TINY_ZONES[] = {
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n.a.test.:192.0.2.1:ns1:300\n+www.a.test.:192.0.2.2:300\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\nSs.a.test.:192.0.2.3:t:5060:99999:70000:300\nSs2.a.test.::t.a.test.:x:y:z\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\nNn.a.test.:99999:1:u:E2U+sip:!x!y!:.:300\nNn2.a.test.:x:y:::\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n_s.a.test.:300:1:0123:300\n_s2.a.test.:0:9:zz\n_s3.a.test.:5:0:0123456789abcdef\n_s4.a.test.:1:2:\n_s5.a.test.:x:y:12\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n3v6.a.test.:20010db8000000000000000000000001:300\n6v6b.a.test.:zz:300\n3short.a.test.:2001:300\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n%in:192.0.2\n%xx:1.2.3.4.5\n%ab\n+loc.a.test.:192.0.2.9:300::in\n+loc2.a.test.:192.0.2.9:300::zz\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n+x.other.test.:192.0.2.1\n",
    "+nosoa.a.test.:192.0.2.1\n",
    "garbage line\n?\n",
    /* one raw-line lint issue per file */
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\nSs.a.test.:192.0.2.3:t:5060:99999:70000:300\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\nSs.a.test.:192.0.2.3:t:5060:x:y:300\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\n_s.a.test.:9:9:0123\n_s.a.test.:x:y:0123\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\n_s.a.test.:1:1:zz\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\nNn.a.test.:70000:x:u:E2U+sip:!x!y!:.:300\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\n3v6.a.test.:2001:300\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\n6v6.a.test.:20010db800000000000000000000zz01:300\n",
    "Za.test.:ns1.a.test.:h.a.test.:1:2:3:4:5:300\n&a.test.::ns1.a.test.:300\n%ab:192.0.2\n%ab:198.51.100\n%cd:10.1.2.3.4\n+l.a.test.:192.0.2.9:300::ab\n",
};

static const char *CONFS[] = {
    "options { directory \"%s\"; user \"nobody\"; allow-program-zones yes; bind-address { 127.0.0.1; }; port 5300; };\n"
    "zone \"a.test\" { type master; file \"%s/z0.zone\"; };\n"
    "zone \"t.test\" { type master; file \"%s/t0.data\"; file-format \"tinydns\"; };\n"
    "zone \"p.test\" { type program; program \"/bin/cat\"; program-user \"root\"; };\n"
    "zone \"p2.test\" { type program; program \"/bin/cat\"; };\n"
    "zone \"f.test\" { type forward; forwarders { 127.0.0.1 port 5300; 127.0.0.1; 192.0.2.1; }; };\n"
    "zone \"f2.test\" { type forward; };\n"
    "zone \"s.test\" { type slave; file \"%s/s.zone\"; masters { 192.0.2.1; }; };\n"
    "zone \"c.test\" { type master; file \"%s/c0.zone\"; catalog-zone yes; };\n",
    "options { directory \"%s\"; };\nzone \"p.test\" { type program; program \"/bin/cat\"; program-args { "
    "\"1\";\"2\";\"3\";\"4\";\"5\";\"6\";\"7\";\"8\";\"9\";\"10\";\"11\";\"12\";\"13\";\"14\";\"15\";\"16\";\"17\";\"18\";\"19\";\"20\";"
    "\"21\";\"22\";\"23\";\"24\";\"25\";\"26\";\"27\";\"28\";\"29\";\"30\";\"31\";\"32\";\"33\";\"34\";\"35\";\"36\";\"37\";\"38\";\"39\";\"40\";"
    "\"41\";\"42\";\"43\";\"44\";\"45\";\"46\";\"47\";\"48\";\"49\";\"50\";\"51\";\"52\";\"53\";\"54\";\"55\";\"56\";\"57\";\"58\";\"59\";\"60\";"
    "\"61\";\"62\";\"63\";\"64\"; }; };\n",
    "options { directory \"%s\"; };\nzone \"p.test\" { type program; };\n",
    "options { directory \"%s\"; allow-program-zones no; };\nzone \"p.test\" { type program; program \"/bin/cat\"; };\n",
    "options { directory \"%s\"; };\nzone \"a.test\" { type master; };\nzone \"b.test\" { type master; file \"/nonexistent/b.zone\"; };\n",
    "this is not a config {\n",
};

static void test_karicheck(void) {
    printf("[TEST] tools sweep: karicheck lint rules...\n");
    char nm[64], cfg[8192];
    for (size_t i = 0; i < N(BIND_ZONES); i++) {
        snprintf(nm, sizeof(nm), "z%zu.zone", i);
        const char *p = wfile(nm, BIND_ZONES[i]);
        run_tool(karicheck_main, "karicheck", "zone", "a.test", p, NULL);
        run_tool(karicheck_main, "karicheck", "zone", "a.test.", p, NULL);
    }
    for (size_t i = 0; i < N(TINY_ZONES); i++) {
        snprintf(nm, sizeof(nm), "t%zu.data", i);
        wfile(nm, TINY_ZONES[i]);
    }
    for (size_t i = 0; i < N(CATALOG_ZONES); i++) {
        snprintf(nm, sizeof(nm), "c%zu.zone", i);
        wfile(nm, CATALOG_ZONES[i]);
    }
    wfile("s.zone", HDR("s.test."));
    /* configs that point at the tinydns and catalog files in turn */
    for (size_t t = 0; t < N(TINY_ZONES) || t < N(CATALOG_ZONES) || t < N(BIND_ZONES); t++) {
        snprintf(cfg, sizeof(cfg),
            "options { directory \"%s\"; };\n"
            "zone \"a.test\" { type master; file \"%s/z%zu.zone\"; };\n"
            "zone \"t.test\" { type master; file \"%s/t%zu.data\"; file-format \"tinydns\"; };\n"
            "zone \"cat.test\" { type master; file \"%s/c%zu.zone\"; catalog-zone yes; };\n",
            g_tmp, g_tmp, t % N(BIND_ZONES), g_tmp, t % N(TINY_ZONES), g_tmp, t % N(CATALOG_ZONES));
        const char *cp = wfile("sweep.conf", cfg);
        run_tool(karicheck_main, "karicheck", "zones", cp, NULL);
        run_tool(karicheck_main, "karicheck", "zone", "t.test", cp, NULL);
        run_tool(karicheck_main, "karicheck", "zone", "cat.test", cp, NULL);
    }
    for (size_t c = 0; c < N(CONFS); c++) {
        snprintf(cfg, sizeof(cfg), CONFS[c], g_tmp, g_tmp, g_tmp, g_tmp, g_tmp, g_tmp);
        snprintf(nm, sizeof(nm), "c%zu.conf", c);
        const char *cp = wfile(nm, cfg);
        run_tool(karicheck_main, "karicheck", "conf", cp, NULL);
        run_tool(karicheck_main, "karicheck", "zones", cp, NULL);
        run_tool(karicheck_main, "karicheck", "zone", "p.test", cp, NULL);
        run_tool(karicheck_main, "karicheck", "zone", "missing.test", cp, NULL);
    }
    run_tool(karicheck_main, "karicheck", NULL);
    run_tool(karicheck_main, "karicheck", "-v", NULL);
    run_tool(karicheck_main, "karicheck", "bogus", NULL);
    run_tool(karicheck_main, "karicheck", "zone", NULL);
    run_tool(karicheck_main, "karicheck", "zone", "a.test", "/nonexistent.zone", NULL);
    run_tool(karicheck_main, "karicheck", "conf", "/nonexistent.conf", NULL);
    run_tool(karicheck_main, "karicheck", "zone", "a.test", g_tmp, NULL);          /* a directory */
    printf("  -> karicheck runs done (%d).\n", g_runs);
}

/* ---------------------------------------------------------------- karictl */
static char g_sock[200];
static volatile int g_ctl_mode;
static const char *CTL_SECRET_B64 = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0";
static const char *CTL_SECRET_RAW = "secretsecretsecretsecret";     /* CTL_SECRET_B64 decoded */
static volatile int g_ctl_auth_ok;                                  /* mode 9: result of the HMAC check */

static void *ctl_server(void *arg) {
    int ls = *(int *)arg;
    for (;;) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) break;
        int mode = g_ctl_mode;
        if (mode < 0) { close(c); break; }
        const char *chal = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        char b[1024];
        if (mode == 1) { close(c); continue; }                                            /* hang up */
        if (mode == 2) { send(c, "HELLO\n", 6, 0); close(c); continue; }                  /* bad challenge */
        if (mode == 3) { send(c, "CHALLENGE abc\n", 14, 0); close(c); continue; }         /* bad length */
        int n = snprintf(b, sizeof(b), "CHALLENGE %s\n", chal); send(c, b, (size_t)n, 0);
        ssize_t r = recv(c, b, sizeof(b) - 1, 0);
        if (r <= 0 || mode == 4) { close(c); continue; }                                  /* no auth reply */
        if (mode == 9) {                                  /* verify an HMAC-SHA512 challenge response */
            b[r] = 0;
            unsigned char md[EVP_MAX_MD_SIZE]; unsigned int md_len = 0;
            HMAC(EVP_sha512(), CTL_SECRET_RAW, strlen(CTL_SECRET_RAW), (const unsigned char *)chal, 64, md, &md_len);
            char want[2 * EVP_MAX_MD_SIZE + 8] = "AUTH ";
            for (unsigned int k = 0; k < md_len; k++) snprintf(want + 5 + 2 * k, 3, "%02x", md[k]);
            strcat(want, "\n");
            g_ctl_auth_ok = (strcmp(b, want) == 0);
            if (!g_ctl_auth_ok) { send(c, "DENIED\n", 7, 0); close(c); continue; }
        }
        if (mode == 5) { send(c, "DENIED\n", 7, 0); close(c); continue; }
        send(c, "OK\n", 3, 0);
        r = recv(c, b, sizeof(b) - 1, 0);
        if (r <= 0) { close(c); continue; }
        b[r] = 0;
        if (!strncmp(b, "status", 6)) {
            karidns_status_t st; memset(&st, 0, sizeof(st));
            st.boot_time = time(NULL) - 100000; st.last_configured_time = time(NULL) - 50; st.num_zones = 3;
            st.worker_threads = 4; st.frontend_alive = mode != 6; st.query_logging = true; st.rrl_dropped = 5;
            snprintf(st.config_file, sizeof(st.config_file), "/etc/karidns.conf");
            char out[3 + sizeof(st)]; memcpy(out, "OK ", 3); memcpy(out + 3, &st, sizeof(st));
            send(c, out, mode == 7 ? 5 : sizeof(out), 0);
        } else if (mode == 8) {
            send(c, "ERR unknown zone\n", 17, 0);
        } else {
            const char *resp = "OK\nzone a.test. serial 5\nqueries 10\n";
            for (int i = 0; i < 3; i++) send(c, resp, strlen(resp), 0);
        }
        close(c);
    }
    return NULL;
}

static void test_karictl(void) {
    printf("[TEST] tools sweep: karictl against a fake control socket...\n");
    snprintf(g_sock, sizeof(g_sock), "/tmp/kctl_%d.sock", (int)getpid());
    unlink(g_sock);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un un; memset(&un, 0, sizeof(un)); un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof(un.sun_path), "%.100s", g_sock);
    if (bind(ls, (struct sockaddr *)&un, sizeof(un)) != 0 || listen(ls, 16) != 0) { perror("bind/listen (control socket)"); abort(); }
    pthread_t t; pthread_create(&t, NULL, ctl_server, &ls);
    char conf[600];
    snprintf(conf, sizeof(conf), "control-channel {\n  socket \"%s\";\n  algorithm \"hmac-sha256\";\n  secret \"%s\";\n};\n", g_sock, CTL_SECRET_B64);
    const char *cp = wfile("karictl.conf", conf);
    const char *cp_nosock = wfile("karictl2.conf", "key \"karictl\" { algorithm hmac-sha256; secret \"c2VjcmV0\"; };\n");
    const char *cp_nosecret = wfile("karictl3.conf", "control-channel { socket \"/tmp/x\"; };\n");
    const char *cp_long = wfile("karictl4.conf", "control-channel { secret \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; };\n");
    const char *cp_bad = wfile("karictl5.conf", "control-channel { secret \"@@@@\"; };\n");
    const char *cmds[][3] = { { "status", NULL, NULL }, { "reload", NULL, NULL }, { "reload", "a.test", NULL }, { "reconfig", NULL, NULL },
                              { "stop", NULL, NULL }, { "notify", "a.test", NULL }, { "retransfer", "a.test", NULL },
                              { "zonestatus", "a.test", NULL }, { "observatory", NULL, NULL }, { "observatory", "a.test", "extra" },
                              { "querylog", "on", NULL }, { "bogus", NULL, NULL } };
    for (int mode = 0; mode <= 8; mode++) {
        g_ctl_mode = mode;
        for (size_t c = 0; c < N(cmds); c++) {
            if (mode != 0 && c > 1) break;
            run_tool(karictl_main, "karictl", "-c", cp, cmds[c][0], cmds[c][1], cmds[c][2], NULL);
        }
    }
    g_ctl_mode = 0;
    run_tool(karictl_main, "karictl", "-f", cp_nosock, "-s", g_sock, "status", NULL);
    run_tool(karictl_main, "karictl", "-c", cp_nosecret, "status", NULL);
    run_tool(karictl_main, "karictl", "-c", cp_long, "status", NULL);
    run_tool(karictl_main, "karictl", "-c", cp_bad, "status", NULL);
    run_tool(karictl_main, "karictl", "-c", "/nonexistent.conf", "status", NULL);
    run_tool(karictl_main, "karictl", "-c", cp, "-s", "/tmp/definitely-not-a-socket", "status", NULL);
    run_tool(karictl_main, "karictl", "-c", cp, "-s",
             "/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sock", "status", NULL);
    /* control-channel algorithm: karictl uses the algorithm of karictl.conf (quoted or bare) */
    {
        char c512[600], c256[600], cbad[600], cbare[600];
        snprintf(c512, sizeof(c512), "socket \"%s\";\nkey \"k\" { algorithm \"hmac-sha512\"; secret \"%s\"; };\n", g_sock, CTL_SECRET_B64);
        snprintf(cbare, sizeof(cbare), "socket \"%s\";\nkey \"k\" { algorithm hmac-sha512; secret \"%s\"; };\n", g_sock, CTL_SECRET_B64);
        snprintf(c256, sizeof(c256), "socket \"%s\";\nkey \"k\" { algorithm hmac-sha256; secret \"%s\"; };\n", g_sock, CTL_SECRET_B64);
        snprintf(cbad, sizeof(cbad), "socket \"%s\";\nkey \"k\" { algorithm hmac-sha999; secret \"%s\"; };\n", g_sock, CTL_SECRET_B64);
        const char *p512 = wfile("karictl_512.conf", c512);
        const char *pbare = wfile("karictl_bare.conf", cbare);
        const char *p256 = wfile("karictl_256.conf", c256);
        const char *pbad = wfile("karictl_bad_alg.conf", cbad);
        g_ctl_mode = 9;
        g_ctl_auth_ok = 0;
        assert(run_tool(karictl_main, "karictl", "-c", p512, "reconfig", NULL) == 0);
        assert(g_ctl_auth_ok == 1);
        g_ctl_auth_ok = 0;
        assert(run_tool(karictl_main, "karictl", "-c", pbare, "reconfig", NULL) == 0);
        assert(g_ctl_auth_ok == 1);
        assert(run_tool(karictl_main, "karictl", "-c", p256, "reconfig", NULL) == 2);   /* wrong algorithm: denied */
        assert(g_ctl_auth_ok == 0);
        assert(run_tool(karictl_main, "karictl", "-c", pbad, "reconfig", NULL) == 2);   /* unsupported: no connect */
        g_ctl_mode = 0;
    }
    run_tool(karictl_main, "karictl", "tsig-keygen", NULL);
    run_tool(karictl_main, "karictl", "tsig-keygen", "mykey", NULL);
    run_tool(karictl_main, "karictl", "-v", NULL);
    run_tool(karictl_main, "karictl", "--version", NULL);
    run_tool(karictl_main, "karictl", "-x", NULL);
    run_tool(karictl_main, "karictl", NULL);
    g_ctl_mode = -1;
    int k = socket(AF_UNIX, SOCK_STREAM, 0); connect(k, (struct sockaddr *)&un, sizeof(un)); close(k);
    pthread_join(t, NULL);
    close(ls); unlink(g_sock);
    printf("  -> karictl runs done.\n");
}

/* ---------------------------------------------------------------- the zone checks of dns_zone_lint.c, message by message
 * (the runs above only execute them: here a zone is fed to the checks and the findings are compared) */
typedef struct { char text[16384]; } lint_out_t;

static void lint_sink(void *ud, char level, const char *text) {
    lint_out_t *o = ud;
    size_t l = strlen(o->text);
    snprintf(o->text + l, sizeof(o->text) - l, "%c %s\n", level, text);
}

/* Parse `body` (after a plain header) as a BIND zone of a.test. and run the checks; fix lets a test change the arena first.  Returns the
 * findings, one per line ("E ..." / "W ..."). */
static void lint_zone(lint_out_t *o, const char *body, const char *raw, void (*fix)(zone_arena_t *)) {
    memset(o, 0, sizeof(*o));
    char text[4096];
    snprintf(text, sizeof(text), "$ORIGIN a.test.\n$TTL 300\n@ IN SOA ns1.a.test. h.a.test. 1 7200 3600 1209600 300\n@ IN NS ns1.a.test.\nns1 IN A 192.0.2.1\n%s", body);
    zone_arena_t a;
    zone_arena_init(&a);
    parse_error_t err;
    memset(&err, 0, sizeof(err));
    parse_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.default_origin = "a.test.";
    ctx.err_out = &err;
    ctx.is_standalone_mode = true;
    char *buf = arena_strdup(&a, text);
    assert(buf && parse_zone_fast(buf, strlen(buf), &a, &ctx) >= 0);
    build_zone_index(&a, true);
    if (fix) fix(&a);
    kc_tally_t t = { 0, 0, lint_sink, o };
    zone_lint_ttl(&a, "zone file", &t);
    zone_lint_in_t in;
    memset(&in, 0, sizeof(in));
    in.domain = "a.test.";
    in.src = "lint.zone";
    in.raw_text = raw;
    zone_lint_records(&a, &in, &t);
    zone_arena_destroy(&a);
}

static void lint_expect(const char *label, const lint_out_t *o, const char *needle) {
    if (!strstr(o->text, needle)) {
        fprintf(stderr, "lint: %s: no \"%s\" in\n%s", label, needle, o->text);
        assert(0);
    }
}

static void fix_tinydns(zone_arena_t *a) {
    tinydns_location_entry_t *locs = calloc(3, sizeof(*locs));      /* the arena frees it */
    memcpy(locs[0].code, "ab", 2); locs[0].prefix_bits = 33;
    memcpy(locs[1].code, "cd", 2); locs[1].prefix_bits = 8;
    memcpy(locs[2].code, "cd", 2); locs[2].prefix_bits = 16;
    a->is_tinydns_format = true;
    a->locations = locs;
    a->location_count = 3;
}

static void fix_soa_restricted(zone_arena_t *a) {
    tinydns_location_entry_t *locs = calloc(1, sizeof(*locs));
    memcpy(locs[0].code, "ab", 2);
    locs[0].prefix_bits = 8;
    a->is_tinydns_format = true;
    a->locations = locs;
    a->location_count = 1;
    for (size_t i = 0; i < a->count; i++)
        if (a->records[i].type_code == 6) {
            a->records[i].tinydns_ttd = 1;                 /* a countdown time stamp in the past */
            a->records[i].tinydns_ttl_countdown = true;
        }
}

static void fix_soa_loc(zone_arena_t *a) {
    fix_soa_restricted(a);
    for (size_t i = 0; i < a->count; i++)
        if (a->records[i].type_code == 6) {
            a->records[i].tinydns_ttd = 0;
            a->records[i].tinydns_loc[0] = 'z';             /* a location the zone does not define */
            a->records[i].tinydns_loc[1] = 'z';
        }
}

/* record shapes the parser never produces (lint is also fed the zones a database reader builds): the arena is changed after the parse */
static int g_mut;
static void fix_mutate(zone_arena_t *a) {
    for (size_t i = 0; i < a->count; i++) {
        dns_record_t *r = &a->records[i];
        if (!r->name || strncmp(r->name, "x.", 2) != 0) continue;
        switch (g_mut) {
        case 1: if (r->type_code == 1) r->rdata_count = 0; break;
        case 2: if (r->type_code == 1) r->rdata[0] = (char *)"999.1.1.1"; break;
        case 3: if (r->type_code == 28) r->rdata_count = 0; break;
        case 4: if (r->type_code == 28) r->rdata[0] = (char *)"2001:zz::1"; break;
        case 5: if (r->type_code == 64) r->rdata[1] = (char *)"target"; break;
        case 6: if (r->type_code == 27) r->rdata_count = 2; break;
        case 7: if (r->type_code == 19) r->rdata_count = 0; break;
        case 8: if (r->type_code == 20) r->rdata_count = 0; break;
        case 9: if (r->type_code == 1) r->type_code = 251; break;
        }
    }
}

static void test_lint_messages(void) {
    printf("[TEST] tools: zone checks, message by message...\n");
    lint_out_t o;
    /* ML-DSA-44 (draft-westerbaan-dnssec-mldsa): the sizes of the key and the signature */
    lint_zone(&o, "@ IN DNSKEY 257 3 18 AwEAAQ==\n", NULL, NULL);
    lint_expect("mldsa key", &o, "algorithm 18 (MLDSA44) public key must be 1312 octets, found 4");
    lint_zone(&o, "@ IN RRSIG A 18 2 300 20300101000000 20200101000000 1 a.test. AwEAAQ==\n", NULL, NULL);
    lint_expect("mldsa signature", &o, "algorithm 18 (MLDSA44) signature must be 2420 octets, found 4");
    lint_zone(&o, "@ IN DNSKEY 257 3 18 !!!!\n", NULL, NULL);
    lint_expect("mldsa base64", &o, "public key is not valid base64");
    /* NSEC3 chains the server does not use or that are unwise (RFC 5155, RFC 9276) */
    lint_zone(&o, "@ IN NSEC3 2 0 1 AABB 2t7b4g4vsa5smi47k61mv5bv1a22bojr A\n", NULL, NULL);
    lint_expect("nsec3 algorithm", &o, "only hash algorithm 1 (SHA-1) is defined (RFC 5155 section 3.1.1)");
    lint_expect("nsec3 iterations", &o, "the iteration count MUST be 0 (RFC 9276 section 3.1)");
    lint_expect("nsec3 salt", &o, "operators SHOULD NOT use a salt");
    lint_expect("nsec3 param", &o, "matches no NSEC3PARAM with Flags 0 at the apex");
    lint_zone(&o, "@ IN NSEC3 1 128 1 AABB 2t7b4g4vsa5smi47k61mv5bv1a22bojr A\n", NULL, NULL);
    lint_expect("nsec3 flags", &o, "have reserved Flags bits set; only bit 0 (opt-out) is defined (RFC 5155 section 3.1.2)");
    lint_zone(&o, "@ IN NSEC3 1 0 600 AABB 2t7b4g4vsa5smi47k61mv5bv1a22bojr A\n", NULL, NULL);
    lint_expect("nsec3 excessive", &o, "E NSEC3 chain (iterations 600, salt AABB; 1 RRs) in zone 'a.test.': iterations value is excessively high");

    /* tinydns: locations and the raw lines of the data file */
    lint_zone(&o, "", "", fix_tinydns);
    lint_expect("location /33", &o, "E Location prefix length /33 exceeds /32 for location 'ab' in zone 'a.test.'");
    lint_expect("duplicate location", &o, "W Duplicate location code 'cd' in zone 'a.test.' (lint.zone)");
    lint_zone(&o,
              "",
              "-comment\r\n"
              "6x.a.test.:zz:300\r\n"
              "3v6.a.test.:2001:300\n"
              "Ss.a.test.:192.0.2.3:t:99999:70000:80000:300\n"
              "Ssz.a.test.:192.0.2.3:t:80:10:10:300\n"
              "Nn.a.test.:70000:80000:u:E2U+sip:!x!y!:.:300\n"
              "_k.a.test.:300:9:0123\n"
              "_k2.a.test.:1:1:zz\n"
              "_k3.a.test.:1:1:\n",
              fix_tinydns);
    lint_expect("type 6", &o, "(line 2): type '6' requires a 32-character hexadecimal IPv6 address, got 'zz'");
    lint_expect("type 3", &o, "(line 3): type '3' requires a 32-character hexadecimal IPv6 address, got '2001'");
    lint_expect("srv port", &o, "(line 4): SRV port '99999' out of range (0-65535)");
    lint_expect("srv weight", &o, "(line 4): SRV weight '70000' out of range (0-65535)");
    lint_expect("srv priority", &o, "(line 4): SRV priority '80000' out of range (0-65535)");
    lint_expect("naptr order", &o, "(line 6): NAPTR order '70000' out of range (0-65535)");
    lint_expect("naptr preference", &o, "(line 6): NAPTR preference '80000' out of range (0-65535)");
    lint_expect("sshfp algorithm", &o, "(line 7): SSHFP algorithm '300' out of range (0-255)");
    lint_expect("sshfp fp_type", &o, "(line 7): SSHFP fp_type '9' is outside standard RFC assignments (1-2)");
    lint_expect("sshfp hex", &o, "(line 8): SSHFP invalid fingerprint hex string 'zz'");
    lint_expect("sshfp empty", &o, "(line 9): SSHFP invalid fingerprint hex string ''");
    lint_zone(&o, "", "_k.a.test.:0:300:0123\n", fix_tinydns);
    lint_expect("sshfp fp_type range", &o, "SSHFP fp_type '300' out of range (0-255)");
    lint_expect("sshfp algorithm 0", &o, "SSHFP algorithm '0' is outside standard RFC assignments (1-4)");

    /* the apex SOA that no client sees */
    lint_zone(&o, "", "", fix_soa_restricted);
    lint_expect("soa expired", &o, "has expired (countdown time stamp in the past): no client sees it");
    lint_zone(&o, "", "", fix_soa_loc);
    lint_expect("soa location", &o, "is restricted to location 'zz', which the zone does not define: no client sees it");
    /* shapes of records that the zone parser would not accept: A / AAAA parameters and addresses, SVCB target, GPOS / X25 / ISDN fields, meta-types */
    static const struct { int mut; const char *body; const char *needle; } shapes[] = {
        { 1, "x IN A 192.0.2.7\n", "E A record must have exactly 1 parameter for name 'x.a.test.'" },
        { 2, "x IN A 192.0.2.7\n", "E Invalid IPv4 address '999.1.1.1' for name 'x.a.test.'" },
        { 3, "x IN AAAA 2001:db8::1\n", "E AAAA record must have exactly 1 parameter for name 'x.a.test.'" },
        { 4, "x IN AAAA 2001:db8::1\n", "E Invalid IPv6 address '2001:zz::1' for name 'x.a.test.'" },
        { 5, "x IN SVCB 1 target.a.test. alpn=h2\n", "W SVCB record TargetName 'target' does not end with a dot" },
        { 6, "x IN GPOS 1 2 3\n", "W GPOS record requires exactly 3 fields" },
        { 7, "x IN X25 12345\n", "W X25 record requires at least 1 field for name 'x.a.test.'" },
        { 8, "x IN ISDN \"150862028003217\"\n", "W ISDN record requires 1 or 2 fields for name 'x.a.test.'" },
        { 9, "x IN A 192.0.2.7\n", "E type 251 is a meta-type and must not appear as a standalone RRset in zone 'a.test.'" },
    };
    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        g_mut = shapes[i].mut;
        lint_zone(&o, shapes[i].body, NULL, fix_mutate);
        lint_expect("record shape", &o, shapes[i].needle);
    }
    lint_zone(&o, "", "6x.a.test.:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz:300\n", fix_tinydns);
    lint_expect("type 6, 32 characters that are not hexadecimal", &o, "type '6' requires a 32-character hexadecimal IPv6 address, got 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'");
    printf("  -> zone check messages compared.\n");
}

int main(void) {
    wd_start("test_coverage_sweep_tools", 300);
    printf("=== Tools Coverage Sweep Tests ===\n");
    signal(SIGPIPE, SIG_IGN);
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/ktools_XXXXXX");
    if (!mkdtemp(g_tmp)) { perror("mkdtemp"); return 1; }
    WD_PHASE("test_karicheck"); test_karicheck();
    WD_PHASE("test_lint_messages"); test_lint_messages();
    WD_PHASE("test_karictl"); test_karictl();
    printf("=== All Tools Coverage Sweep Tests PASSED (%d runs) ===\n", g_runs);
    return 0;
}
