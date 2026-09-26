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

int main(void) {
    wd_start("test_coverage_sweep_tools", 300);
    printf("=== Tools Coverage Sweep Tests ===\n");
    signal(SIGPIPE, SIG_IGN);
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/ktools_XXXXXX");
    if (!mkdtemp(g_tmp)) { perror("mkdtemp"); return 1; }
    WD_PHASE("test_karicheck"); test_karicheck();
    WD_PHASE("test_karictl"); test_karictl();
    printf("=== All Tools Coverage Sweep Tests PASSED (%d runs) ===\n", g_runs);
    return 0;
}
