#!/bin/sh
# run_karicheck_codes_test.sh - the message codes of karicheck (dns_diag_codes.h): the table, the docs list, and that every code is printed.
#
#   1. The table follows its rules and the list in docs/karicheck.md is the one generated from it (tests/check_diag_codes.pl).
#   2. Every code that is not retired is printed by some test: karicheck appends the code of every message to the file named by
#      KARICHECK_CODE_LOG, and this test collects them from (the log exists only in the test builds karicheck-codelog and
#      test_coverage_sweep_tools-codelog, made with -DKARIDNS_DIAG_CODELOG; the shipped karicheck has no such code)
#        - the karicheck tests that exist (run_karicheck_*.sh, which print the findings they look for in text mode),
#        - the fixtures below, one per code that those tests do not reach (each is also checked in the JSON document), and
#        - test_coverage_sweep_tools-codelog when it is built (the zone checks fed with hand-made zones: the records no zone file can hold).
#      A code that is in none of them and not in the lists of exceptions fails the test.
#
# The exceptions are the codes no run can print: out of memory, a failing system call, a setting of the machine karicheck runs on, the
# check that only a reconfig of a running karidns makes, and the defensive checks the configuration parser makes unreachable.  Codes
# that only a run by root prints are required when this test runs as root.
#
# SKIP (exit 0, with the reason) without karicheck or perl.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

KC=${KC:-$ROOT/karicheck-codelog}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
JC="perl $ROOT/tests/lib/json_check.pl"
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karicheck_codes.XXXXXX") || exit 1
chmod 755 "$T"
trap 'if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"; fi' EXIT INT TERM
PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -${BADLINES:-12} | sed 's/^/         /'; }
IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1
LOG=$T/codes.log
: > "$LOG"
export KARICHECK_CODE_LOG=$LOG

# ---------------------------------------------------------------- 1. the table and the docs
echo "== the table and the documentation"
if perl tests/check_diag_codes.pl --check-table; then ok "dns_diag_codes.h follows its rules"; else bad "dns_diag_codes.h breaks a rule"; fi
if perl tests/check_diag_codes.pl --check-docs; then ok "docs/karicheck.md lists the codes of the table"; else bad "docs/karicheck.md is not the list generated from the table"; fi

if [ ! -x "$KC" ]; then
    echo "SKIP: $KC is not built (make karicheck-codelog): the codes the tests print are not collected"
    [ "$FAILS" -eq 0 ] && exit 0 || exit 1
fi

# ---------------------------------------------------------------- 2. the fixtures
echo "== fixtures for the codes the other tests do not print"
OUT=$T/o.json
# fx CODE DESC ARGS...: karicheck --json ARGS must have a message with CODE
JSONOK=1; perl -MJSON::PP -e 1 2>/dev/null || JSONOK=0
fx() {
    code=$1; shift
    if [ $JSONOK = 0 ]; then "$KC" "$@" > /dev/null 2>&1 < /dev/null; return; fi
    "$KC" --json "$@" > "$OUT" 2> /dev/null < /dev/null
    if $JC "$OUT" has "$code"; then ok "$code"; else bad "$code: not in the document of: karicheck --json $*" "$($JC "$OUT" get 'messages.*.code' | tr '\n' ' ')"; fi
}
cfix() {            # cfix CODE 'configuration text' [command]
    printf '%s\n' "$2" > "$T/f.conf"
    fx "$1" "${3:-conf}" "$T/f.conf"
}
zfix() {            # zfix CODE ORIGIN 'options' 'zone lines'
    printf '$ORIGIN %s.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.1\n%s\n' "$2" "$4" > "$T/$2.zone"
    printf 'options { %s };\nzone "%s" { type master; file "%s/%s.zone"; };\n' "$3" "$2" "$T" "$2" > "$T/$2.conf"
    fx "$1" zone "$2" "$T/$2.conf"
}
SEC=c2VjcmV0c2VjcmV0
LONGSEC=$(printf 'QUJD%.0s' $(seq 1 700))

# configuration parser
cfix conf.acl.duplicate 'acl "a" { 192.0.2.1; }; acl "a" { 192.0.2.2; };'
cfix conf.acl.entry 'options { ecs-trusted-resolvers { localnets-x; }; };'
cfix conf.acl.list 'options { allow-transfer { nosuchacl; }; };'
cfix conf.alias-resolver 'options { alias-resolver { 999.1.1.1; }; };'
cfix conf.cookie.secret 'options { cookie-secret "xyz"; };'
cfix conf.cookie.secret-count 'options { cookie-secret "00112233445566778899aabbccddee00"; cookie-secret "00112233445566778899aabbccddee01"; cookie-secret "00112233445566778899aabbccddee02"; cookie-secret "00112233445566778899aabbccddee03"; cookie-secret "00112233445566778899aabbccddee04"; };'
cfix conf.cookie.algorithm 'options { cookie-algorithm aes; };'
cfix conf.query-log.max-qps 'options { query-log-max-qps abc; };'
cfix conf.query-log.buffer-size 'options { query-log-buffer-size 1000; };'
cfix conf.minimal-any-ttl 'options { minimal-any-ttl abc; };'
cfix conf.alerts.option 'options { alerts { qps-over 5; }; };'
cfix conf.alerts.range 'options { alerts { interval 5; }; };'
cfix conf.alerts.empty 'options { alerts { }; };'
cfix conf.wire-cache.max-records 'options { wire-cache-max-records abc; };'
cfix conf.acl.transfer-order "key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; }; zone \"a.test\" { type master; file \"/x\"; allow-transfer { 192.0.2.1; key \"k\"; }; };"
cfix conf.acl.update-order "key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; }; zone \"a.test\" { type master; file \"/x\"; allow-update { !192.0.2.9; key \"k\"; }; };"
cfix conf.transfers-out-zero 'options { transfers-out 0; transfers-per-ns 0; };'
cfix conf.transfers-per-ns-zero 'options { transfers-out 0; transfers-per-ns 0; };'
cfix conf.tsig.algorithm "key \"k\" { algorithm hmac-foo; secret \"$SEC\"; };"
cfix conf.tsig.secret-length "key \"k\" { algorithm hmac-sha256; secret \"$LONGSEC\"; };"
cfix conf.key.duplicate "key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; }; key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; };"
cfix conf.key.view-clash "key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; }; view \"v\" { key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; }; };"
cfix conf.view.duplicate 'view "v" { match-clients { any; }; }; view "v" { match-clients { any; }; };'
cfix conf.view.key-duplicate "view \"v\" { key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; }; key \"k\" { algorithm hmac-sha256; secret \"$SEC\"; }; };"
cfix conf.view.name-length "view \"$(printf 'a%.0s' $(seq 1 250))\" { match-clients { any; }; };"
cfix conf.server.key-unknown 'server 192.0.2.1 { keys "nosuchkey"; };'
cfix conf.zone.file-format 'zone "a.test" { type master; file "/x"; file-format foo; };'
cfix conf.zone.name 'zone "a..b" { type master; file "/x"; };'
cfix conf.zone.type-resolver 'zone "a.test" { type hint; file "/x"; };'
cfix conf.zone.type-unknown 'zone "a.test" { type bogus; file "/x"; };'
cfix conf.zone.update-on-secondary 'zone "a.test" { type slave; masters { 192.0.2.1; }; allow-update { 192.0.2.5; }; };'
cfix conf.zone.refresh-range 'zone "a.test" { type slave; masters { 192.0.2.1; }; min-refresh-time 500; max-refresh-time 100; min-retry-time 500; max-retry-time 100; };'
cfix conf.zone.retry-range 'zone "a.test" { type slave; masters { 192.0.2.1; }; min-refresh-time 500; max-refresh-time 100; min-retry-time 500; max-retry-time 100; };'
cfix conf.zone.secondary-options-on-primary 'zone "a.test" { type master; file "/x"; min-refresh-time 100; };'
cfix conf.zone.multi-master 'zone "a.test" { type slave; masters { 192.0.2.1; }; multi-master yes; };'
cfix conf.zone.tsig-key-undefined 'zone "a.test" { type master; file "/x"; tsig-key "nokey"; };'
cfix conf.zone.forward-loop 'zone "f.test" { type forward; forwarders { 0.0.0.0; }; };'
cfix conf.warning 'view "v1" { match-clients { any; }; server 192.0.2.1 { bogus no; }; zone "a.test" { type master; file "/x"; }; }; server 192.0.2.2 { };'
cfix conf.view.servers-override 'view "v1" { match-clients { any; }; server 192.0.2.1 { bogus no; }; zone "a.test" { type master; file "/x"; }; }; server 192.0.2.2 { };'
cfix conf.notify 'options { also-notify { 999.1.1.1; }; };'
cfix conf.directory.access 'options { directory "/nonexistent-dir-xyz"; };'
cfix conf.directory.not-dir 'options { directory "/dev/null"; };'
mkdir "$T/cwd"
( cd "$T/cwd" && mkdir sub && printf 'options { directory "sub"; };\n' > f.conf && "$KC" --json conf f.conf > "$OUT" 2>/dev/null </dev/null; $JC "$OUT" has conf.directory.relative ) && ok conf.directory.relative || bad "conf.directory.relative"
cfix conf.identity.root 'options { user "toor"; };'
cfix conf.control-key.tsig "key \"tk\" { algorithm hmac-sha256; secret \"$SEC\"; };
control-channel { socket \"$T/x.sock\"; secret \"ZGlmZmVyZW50c2VjcmV0MTIz\"; keys { \"tk\"; }; };
zone \"a.test\" { type master; file \"/x\"; allow-transfer { key \"tk\"; }; };"
# more than KARIDNS_XFR_SOURCES_MAX (128) distinct source addresses
i=1; : > "$T/xfr.conf"
while [ $i -le 130 ]; do
    printf 'zone "z%d.test" { type slave; masters { 192.0.2.1; }; transfer-source 10.0.%d.%d; };\n' $i $((i / 250)) $((i % 250 + 1)) >> "$T/xfr.conf"
    i=$((i + 1))
done
fx conf.xfr-source.limit conf "$T/xfr.conf"

# the database block of the configuration
ME=$(id -un)
DBD=$T/dbd; mkdir "$DBD"; chmod 755 "$DBD"
printf '#!/bin/sh\nexit 1\n' > "$DBD/noanswer"; chmod 755 "$DBD/noanswer"
[ $IS_ROOT = 1 ] && chown 0:0 "$DBD/noanswer"
LU=$ME; [ $IS_ROOT = 1 ] && LU=${KARIDNS_TEST_LOADER_USER:-${SUDO_USER:-nobody}}
dbconf() {          # dbconf EXTRA [LOADER-PATH [LOADER-USER]]
    printf 'options {\n  user "%s";\n  database { driver sqlite3; database-file "%s/x.db"; loader-user "%s"; loader-path "%s"; %s };\n};\n' "$LU" "$DBD" "${3:-$LU}" "${2:-$DBD/noanswer}" "$1" > "$T/f.conf"
}
dbconf 'acl-ceiling { 192.0.2.0/24; }; acl-ceiling-match all;'; fx conf.database.acl-ceiling-match conf "$T/f.conf"
dbconf 'loader-state-file "'"$DBD"'/state"; warm-before-serve 5;'; fx conf.database.state-file conf "$T/f.conf"; fx conf.database.warm conf "$T/f.conf"
dbconf ''; fx conf.database.loader-answer conf "$T/f.conf"
dbconf '' "$DBD/noanswer" root; fx conf.database.identity-root conf "$T/f.conf"

# zone checks
printf '$ORIGIN nottl.test.\nns1 IN A 192.0.2.1\n@ 300 IN SOA ns1 h 1 7200 3600 1209600 300\n@ 300 IN NS ns1\n' > "$T/nottl.zone"
fx zone.ttl.missing zone nottl.test "$T/nottl.zone"
zfix zone.limits lim.test 'max-records 2;' ''
zfix zone.pdns-types pd.test '' 'www ALIAS target.test.
www A 192.0.2.5'
ZM='AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899'
zfix zone.zonemd.mismatch zm.test '' "@ ZONEMD 1 1 1 $ZM"
zfix zone.zonemd.duplicate zmd.test '' "@ ZONEMD 1 1 1 $ZM
@ ZONEMD 1 1 1 $ZM"
zfix zone.zonemd.hash-invalid zmh.test '' '@ ZONEMD 1 1 300 AABB'
zfix zone.zonemd.scheme-invalid zms.test '' '@ ZONEMD 1 300 1 AABB'
zfix zone.wildcard.non-terminal ck.test 'check-dup-records warn; check-wildcard yes; check-mx warn; check-names primary warn;' 'dup A 192.0.2.9
dup A 192.0.2.9
a.*.w A 192.0.2.8
@ MX 10 192.0.2.9.
@ MX 20 bad_name.ck.test.'
fx zone.dup-records zone ck.test "$T/ck.test.conf"
fx zone.mx.address zone ck.test "$T/ck.test.conf"
fx zone.names.target zone ck.test "$T/ck.test.conf"
# a tinydns file with a record that no zone of the view owns
printf '=host.other.test:192.0.2.9:300\n' > "$T/tiny.data"
printf 'zone "tiny.test" { type master; file "%s/tiny.data"; file-format tinydns; };\n' "$T" > "$T/tiny.conf"
fx zone.tinydns.out-of-zone zones "$T/tiny.conf"
# zone text from standard input: a zone with $INCLUDE, and one too big
printf '$ORIGIN inc.test.\n$TTL 300\n@ IN SOA ns1 h 1 7200 3600 1209600 300\n$INCLUDE other.zone\n' | "$KC" zone inc.test - > /dev/null 2>&1
yes ';cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' | head -c 67108865 | "$KC" zone x.test - > /dev/null 2>&1
fx zone.not-found zone nothing.test "$T/tiny.conf"
fx io.open zone x.test "$T/nothing.zone"
mkdir "$T/adir"; fx io.not-regular conf "$T/adir"
fx usage.command.missing
fx usage.command.unknown frobnicate
fx usage.args zone
fx usage.args db a b c

# the check protocol: lines of a loader that has things to say about the settings
cat > "$DBD/fake" <<'EOFAKE'
#!/bin/sh
case "$1" in --drivers) echo sqlite3; exit 0;; esac
printf 'Z\tok.test.\t1\tprimary\t*\n'
printf 'S\tok.test.\t1\tbogus-statement;\t\t\n'
printf 'S\tok.test.\t1\tallow-transfer { 192.0.2.1; };\tp1\tallow-transfer { 192.0.2.2; };\n'
printf 'S\tok.test.\t1\tbroken \\9 escape\t\t\n'
printf 'R\t1\t0\t0\n'
EOFAKE
chmod 755 "$DBD/fake"; [ $IS_ROOT = 1 ] && chown 0:0 "$DBD/fake"
dbconf 'acl-ceiling { 192.0.2.0/24; };' "$DBD/fake"
fx db.settings.zone db "$T/f.conf"
fx db.protocol.settings db "$T/f.conf"
printf 'options {\n  user "%s";\n  database { driver sqlite3; database-file "%s/x.db"; loader-user "%s"; loader-path "%s/fake"; };\n};\nview "a" { database none; match-clients { any; }; };\n' "$LU" "$DBD" "$LU" "$DBD" > "$T/none.conf"
fx db.nothing db "$T/none.conf"

# only a run by root prints these (the loader is never run as root; the user is looked up first)
if [ $IS_ROOT = 1 ]; then
    cp "$DBD/fake" "$DBD/fake2"; chown 0:0 "$DBD/fake2"
    dbconf '' "$DBD/fake2"
    sed 's/ loader-user "[^"]*";//' "$T/f.conf" > "$T/nouser.conf"
    fx db.identity.no-loader-user db "$T/nouser.conf"
    fx conf.database.drivers-not-run conf "$T/nouser.conf"
    dbconf '' "$DBD/fake2" toor; fx db.identity.root db "$T/f.conf"
    dbconf '' "$DBD/fake2" nosuchuser; fx db.identity.user db "$T/f.conf"
    dbconf '' "$DBD/fake2" "$LU"; sed 's/loader-user "\([^"]*\)";/loader-user "\1"; loader-group "nosuchgroup";/' "$T/f.conf" > "$T/grp.conf"; fx db.identity.group db "$T/grp.conf"
    printf 'host=/tmp dbname=pdns\n' > "$T/ci"; chmod 600 "$T/ci"; chown 12345 "$T/ci"
    printf 'options {\n  user "%s";\n  database { driver postgresql; conninfo-file "%s/ci"; loader-user "%s"; loader-path "%s/fake2"; };\n};\n' "$LU" "$T" "$LU" "$DBD" > "$T/pg.conf"
    fx conf.database.conninfo-owner conf "$T/pg.conf"
fi

# ---------------------------------------------------------------- 3. the tests that exist
echo "== the karicheck tests"
# the tests run karicheck as $ROOT/karicheck or ./karicheck: give them a root whose karicheck is the test build
SH=$T/root; mkdir "$SH"
for e in $(ls -A "$ROOT"); do [ "$e" = karicheck ] || ln -s "$ROOT/$e" "$SH/$e"; done
ln -s "$KC" "$SH/karicheck"
for t in tests/run_karicheck_*.sh tests/run_karicheck_json_test.sh; do
    case "$t" in */run_karicheck_codes_test.sh) continue;; esac
    sh "$SH/$t" > "$T/sub.log" 2>&1 < /dev/null; rc=$?
    if [ $rc -ne 0 ]; then echo "  (note) $t exited with $rc; its own run reports why"; fi
done
if [ -x "$ROOT/test_coverage_sweep_tools-codelog" ]; then
    echo "== the zone checks with hand-made zones (test_coverage_sweep_tools-codelog)"
    "$ROOT/test_coverage_sweep_tools-codelog" > "$T/sweep.log" 2>&1 < /dev/null || echo "  (note) test_coverage_sweep_tools-codelog exited with $?"
    SWEEP=1
else
    echo "  (the sweep test is not built: the codes only it prints are not required; make test_coverage_sweep_tools-codelog)"
    SWEEP=0
fi

# ---------------------------------------------------------------- 4. every code
echo "== every code is printed by some test"
sort -u "$LOG" > "$T/seen.txt"
perl tests/check_diag_codes.pl --list | sort -u > "$T/all.txt"
# no run prints these: out of memory, failing system calls, the machine's host name, a reconfig of a running karidns, and checks that the
# configuration parser makes unreachable
cat > "$T/exc.txt" <<'EOF'
conf.database.no-driver
conf.database.server-id-host
conf.directory.changed
conf.zone.transfer-key-undefined
db.settings.combined
zone.catalog.name-too-long
zone.zonemd.canonical
internal.oom
io.fork
io.pipe
io.read
io.stat
io.stdin.read
zone.zonemd.compute-failed
EOF
# printed only when the zone checks get records no zone file can hold (tests/test_coverage_sweep_tools.c, built as test_coverage_sweep_tools-codelog)
cat > "$T/sweep.txt" <<'EOF'
conf.zone.program-args
conf.zone.program-user-root
zone.a.address
zone.a.fields
zone.aaaa.address
zone.aaaa.fields
zone.catalog.orphan-group
zone.dnssec.algorithm-unknown
zone.dnssec.key-base64
zone.dnssec.mldsa-length
zone.ds.digest-null
zone.ds.digest-unknown
zone.ecs.tag-undefined
zone.gpos.fields
zone.hip.fields
zone.isdn.fields
zone.location.prefix
zone.location.tag-undefined
zone.meta-type
zone.nsec3.flags-reserved
zone.nsec3.hash-algorithm
zone.nsec3.iterations-high
zone.soa.expired
zone.soa.mname-cname
zone.svcb.target-dot
zone.x25.fields
zone.zonemd.digest-length
zone.zonemd.fields
zone.zonemd.unsupported
EOF
# printed only by a run by root
cat > "$T/root.txt" <<'EOF'
conf.database.conninfo-owner
conf.database.drivers-not-run
db.identity.group
db.identity.no-loader-user
db.identity.root
db.identity.user
EOF
# printed only by a run by another user than root (root can read every file)
printf 'conf.database.file-unreadable\n' > "$T/nonroot.txt"
cp "$T/exc.txt" "$T/skip.txt"
[ $IS_ROOT = 0 ] || cat "$T/nonroot.txt" >> "$T/skip.txt"
[ $IS_ROOT = 1 ] || cat "$T/root.txt" >> "$T/skip.txt"
[ $SWEEP = 1 ] || cat "$T/sweep.txt" >> "$T/skip.txt"
# printed by the ZoneImporter / ZoneExporter (dns_zone_import.c, dns_zone_export.c) and by tools/karidns_zone.c, never by karicheck: tests/test_zone_import.c
# checks that it printed each db.import.* and db.export.* of the library (all but db.import.rows, the rows of a parsed zone that cannot be written as
# PowerDNS rows, and the three the tool prints), tests/run_karidns_zone_test.sh the codes of the tool; db.apply.* are printed by karidns-zone apply (tests/test_zone_import.c, tests/run_karidns_zone_apply_test.sh)
cat > "$T/zonetool.txt" <<'EOF'
db.apply.changes
db.apply.zone
db.export.not-found
db.export.open
db.export.read
db.export.warning
db.export.write
db.export.zone
db.export.zone-type
db.import.busy
db.import.checks
db.import.done
db.import.dry-run
db.import.file-zone
db.import.keys
db.import.no-reload
db.import.open
db.import.option
db.import.rows
db.import.schema
db.import.serial
db.import.strict
db.import.write
db.import.zone-name
db.import.verify
db.import.not-primary
db.import.summary
db.import.change
db.import.changed
db.render.input
db.import.signer
db.import.signer-zone
db.export.done
db.zone.driver
db.zone.no-source
db.zone.output
db.zone.output-exists
usage.option
EOF
cat "$T/zonetool.txt" >> "$T/skip.txt"
sort -u "$T/skip.txt" -o "$T/skip.txt"
comm -23 "$T/all.txt" "$T/seen.txt" > "$T/missing.txt"
comm -23 "$T/missing.txt" "$T/skip.txt" > "$T/need.txt"
n_all=$(wc -l < "$T/all.txt" | tr -d ' ')
n_seen=$(comm -12 "$T/all.txt" "$T/seen.txt" | wc -l | tr -d ' ')
BADLINES=100
if [ -s "$T/need.txt" ]; then bad "codes that no test printed ($(wc -l < "$T/need.txt" | tr -d ' ') of $n_all)" "$(cat "$T/need.txt")"; else ok "$n_seen of $n_all codes were printed; the others are exceptions: $(wc -l < "$T/missing.txt" | tr -d ' ') ($(tr '\n' ' ' < "$T/missing.txt"))"; fi
# an exception that is printed after all is a stale entry
comm -12 "$T/skip.txt" "$T/seen.txt" > "$T/stale.txt"
if [ -s "$T/stale.txt" ]; then bad "exceptions that are printed after all (remove them from the lists)" "$(cat "$T/stale.txt")"; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_karicheck_codes_test: $PASS check(s) passed ==="; exit 0; fi
echo "=== run_karicheck_codes_test: $FAILS check(s) FAILED, $PASS passed ==="
exit 1
