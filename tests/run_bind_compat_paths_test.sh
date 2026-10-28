#!/bin/sh
# run_bind_compat_paths_test.sh - batch 1 of the BIND 9.20 configuration compatibility (paths and syntax):
#   - options { directory }: the base of the zone `file`, `include`, relative and absolute `$INCLUDE`, `pid-file` and log files; karidns
#     is started from another working directory and serves in capability mode; a reload brings in a file in a directory that did not
#     exist at start-up (opened through the directory fd), an absolute $INCLUDE outside the zone directory and `directory` is refused
#     with the reason, a changed `directory` needs a restart
#   - zone "x" IN { }, view "v" IN { }; another class is an error with file:line
#   - a FreeBSD style BIND named.conf (root hint zone, localhost, empty zones, listen-on, forwarders, ...) is accepted by karicheck conf
#     with warnings only and served by karidns
#   - zone types hint / stub / static-stub / mirror / redirect are skipped with a warning; in-view is an error
#   - karicheck: the same $INCLUDE verdicts and messages as the server (standalone and from a configuration), invalid TTLs and ports are
#     errors, a zone without any TTL is a warning
# Runs as a normal user on 127.0.0.1 (as root the server drops to nobody); needs no root.
set -u

DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
ROOT="$DIR/.."
KARIDNS="${KARIDNS:-$ROOT/karidns}"
KARICTL="${KARICTL:-$ROOT/karictl}"
KARICHECK="${KARICHECK:-$ROOT/karicheck}"
DAG="${DAG:-$ROOT/dag}"
[ -x "$KARIDNS" ] && [ -x "$KARICTL" ] && [ -x "$KARICHECK" ] && [ -x "$DAG" ] || make -C "$ROOT" karidns karictl karicheck dag >/dev/null || exit 1
case "$KARIDNS" in /*) ;; *) KARIDNS="$(pwd)/$KARIDNS" ;; esac   # the server is started from another directory

W="$(mktemp -d "${TMPDIR:-/tmp}/karidns-bcp.XXXXXX")"
chmod 755 "$W" # readable after the privilege drop when run as root
USER_OPT=""
[ "$(id -u)" -eq 0 ] && USER_OPT='user "nobody"; group "nobody";'
P1=$(kari_port 1 15721)   # server 1: directory
P2=$(kari_port 2 15722)   # server 2: stock BIND named.conf
SECRET="cDEwLWJjcC10ZXN0LWNvbnRyb2wta2V5LXNlY3JldA=="
KD="a2QtYmNwLXRlc3Qta2V5LXNlY3JldC1mb3ItYmNw"
PIDS=""
FAILS=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }
cleanup() {
    set +e
    kari_kill_tree $PIDS
    kari_kill_conf "$W/etc/s1.conf" "$W/etc/s2.conf"
    if [ "$FAILS" -ne 0 ]; then
        for l in s1 s2; do echo "--- $l.log (tail)"; tail -25 "$W/$l.log" 2>/dev/null; done
    fi
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

for p in $P1 $P2; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

mkdir -p "$W/etc" "$W/named/zones" "$W/named/inc" "$W/named/abs" "$W/cwd" "$W/other"
chmod -R 755 "$W"

# ---------------------------------------------------------------- server 1: options { directory }
cat > "$W/named/zones/main.test.zone" <<EOF
\$TTL 300
\$ORIGIN main.test.
@ IN SOA ns1 hostmaster 1 3600 600 86400 60
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.80
\$INCLUDE inc/a.inc
\$INCLUDE $W/named/abs/b.inc
\$INCLUDE sub/../inc/c.inc
EOF
echo 'a IN A 192.0.2.10' > "$W/named/inc/a.inc"
echo 'b IN A 192.0.2.11' > "$W/named/abs/b.inc"
echo 'c IN A 192.0.2.12' > "$W/named/inc/c.inc"
echo 'secret IN A 192.0.2.99' > "$W/other/o.inc"
# included relative to `directory`, not to the directory of the configuration file
echo "key \"kd\" { algorithm hmac-sha256; secret \"$KD\"; };" > "$W/named/keys.conf"
echo "key \"karictl\" { algorithm hmac-sha256; secret \"$SECRET\"; };" > "$W/ctl.conf"
chmod 600 "$W/ctl.conf"
cat > "$W/etc/s1.conf" <<EOF
options { port $P1; bind-address { 127.0.0.1; }; directory "$W/named"; pid-file "k.pid"; $USER_OPT };
include "keys.conf";
control-channel { socket "$W/ctl1.sock"; algorithm hmac-sha256; secret "$SECRET"; };
logging { channel qlog { file "q.log"; }; category queries { qlog; }; };
zone "main.test" IN { type primary; file "zones/main.test.zone"; allow-transfer { key kd; }; };
zone "." IN { type hint; file "root.cache"; };
zone "stub.test" { type stub; masters { 192.0.2.7; }; file "stub.db"; };
EOF

OUT=$("$KARICHECK" conf "$W/etc/s1.conf" 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karicheck conf accepts directory, a relative include, a class and skipped zone types" || fail "karicheck conf s1 (rc=$RC): $OUT"
echo "$OUT" | grep -q "zone '.': type 'hint'.*is not loaded" && pass "karicheck conf warns that the hint zone is not loaded" || fail "no hint warning: $OUT"
echo "$OUT" | grep -q "zone 'stub.test.': type 'stub'.*is not loaded" && pass "karicheck conf warns that the stub zone is not loaded" || fail "no stub warning: $OUT"
OUT=$("$KARICHECK" zones "$W/etc/s1.conf" 2>&1); RC=$?
[ $RC -eq 0 ] && echo "$OUT" | grep -q "Zone 'main.test.' is valid" && pass "karicheck zones resolves the file and the \$INCLUDE lines through directory" || fail "karicheck zones s1 (rc=$RC): $OUT"

( cd "$W/cwd" && exec "$KARIDNS" -f -c "$W/etc/s1.conf" ) > "$W/s1.log" 2>&1 &
PIDS="$PIDS $!"
if ! kari_wait_answer "$DAG" "$P1" main.test 20; then fail "server 1 did not start"; tail -20 "$W/s1.log"; exit 1; fi

ans() { # ans PORT NAME [TYPE] : the short answer
    "$DAG" "@127.0.0.1" -p "$1" "$2" "${3:-A}" +short +nohexdump +time=2 +tries=1 2>&1
}
status() { # status PORT NAME TYPE : the rcode
    "$DAG" "@127.0.0.1" -p "$1" "$2" "${3:-A}" +nohexdump +time=2 +tries=1 2>&1 | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1
}
check_a() { # check_a LABEL NAME EXPECTED
    _got=$(ans "$P1" "$2")
    [ "$_got" = "$3" ] && pass "$1" || fail "$1: expected $3, got: $_got"
}

check_a "zone file relative to directory (the server was started in another directory)" www.main.test 192.0.2.80
check_a "relative \$INCLUDE is read from directory" a.main.test 192.0.2.10
check_a "absolute \$INCLUDE inside directory" b.main.test 192.0.2.11
check_a "\$INCLUDE with .. that stays inside the tree" c.main.test 192.0.2.12
[ -f "$W/named/k.pid" ] && pass "relative pid-file is written below directory" || fail "no $W/named/k.pid"
[ -f "$W/named/q.log" ] && pass "relative log file is opened below directory" || fail "no $W/named/q.log"
[ ! -e "$W/cwd/k.pid" ] && [ ! -e "$W/cwd/q.log" ] && pass "nothing is created in the working directory" || fail "files in the working directory: $(ls "$W/cwd")"

ctl() { "$KARICTL" -s "$W/ctl1.sock" -f "$W/ctl.conf" "$@" 2>&1; }

# reload 1: a file in a directory that did not exist at start-up (reached through the directory fd in capability mode)
mkdir -p "$W/named/inc/newdir/deeper"
chmod -R 755 "$W/named"
echo 'd IN A 192.0.2.13' > "$W/named/inc/newdir/deeper/d.inc"
echo "\$INCLUDE inc/newdir/deeper/d.inc" >> "$W/named/zones/main.test.zone"
echo 'e IN A 192.0.2.14' > "$W/named/inc/newdir/deeper/e.inc"
echo "\$INCLUDE $W/named/inc/newdir/deeper/e.inc" >> "$W/named/zones/main.test.zone"
OUT=$(ctl reload); RC=$?
[ $RC -eq 0 ] && pass "reload: $OUT" || fail "reload with a new include directory (rc=$RC): $OUT"
check_a "reload: a relative include in a directory that did not exist at start-up is served" d.main.test 192.0.2.13
check_a "reload: an absolute include in such a directory is served" e.main.test 192.0.2.14
check_a "reload: the other names still answer" www.main.test 192.0.2.80

# reload 2: an absolute $INCLUDE outside the zone directory and directory is refused, with the reason
echo "\$INCLUDE $W/other/o.inc" >> "$W/named/zones/main.test.zone"
OUT=$(ctl reload); RC=$?
[ $RC -ne 0 ] && pass "reload with an \$INCLUDE outside the directories is reported as an error" || fail "reload accepted an \$INCLUDE outside the directories: $OUT"
grep -q "outside the directories opened at startup (zone file dir, directory)" "$W/s1.log" && pass "the server log states why the \$INCLUDE is refused" || fail "no reason in the log: $(tail -5 "$W/s1.log")"
echo "$OUT" | grep -q "main.test" && pass "the reload reply names the zone that failed" || fail "reply: $OUT"
[ "$(status "$P1" secret.main.test A)" != "NOERROR" ] && pass "the refused file is not served" || fail "secret.main.test answers"
# fixed again
sed -i.bak '$d' "$W/named/zones/main.test.zone" && rm -f "$W/named/zones/main.test.zone.bak"
OUT=$(ctl reload); RC=$?
[ $RC -eq 0 ] && pass "reload after the fix: $OUT" || fail "reload after the fix (rc=$RC): $OUT"
check_a "the zone answers again after the fix" d.main.test 192.0.2.13

# reload 3: another directory in the configuration needs a restart; the running server keeps the old one
mkdir -p "$W/named2/zones"
chmod -R 755 "$W/named2"
cp "$W/named/zones/main.test.zone" "$W/named2/zones/main.test.zone"
cp "$W/named/keys.conf" "$W/named2/keys.conf"
sed -i.bak "s|directory \"$W/named\"|directory \"$W/named2\"|" "$W/etc/s1.conf" && rm -f "$W/etc/s1.conf.bak"
OUT=$(ctl reconfig); RC=$?
echo "$OUT" | grep -q "restart needed for: .*directory" && pass "a changed directory is reported as needing a restart: $OUT" || fail "reconfig reply (rc=$RC): $OUT"
grep -q "differs from the directory the server was started with" "$W/s1.log" && pass "the server log says that the old directory stays in use" || fail "no log line for the changed directory"
check_a "the old directory is still used after the reload" www.main.test 192.0.2.80

# ---------------------------------------------------------------- a FreeBSD style BIND named.conf
mkdir -p "$W/namedb/working" "$W/namedb/primary"
chmod -R 755 "$W/namedb"
cat > "$W/namedb/primary/localhost-forward.db" <<EOF
\$TTL 3600
@ IN SOA localhost. root.localhost. 42 86400 7200 3600000 120
@ IN NS localhost.
localhost. IN A 127.0.0.1
localhost. IN AAAA ::1
EOF
cat > "$W/namedb/primary/localhost-reverse.db" <<EOF
\$TTL 3600
@ IN SOA localhost. root.localhost. 42 86400 7200 3600000 120
@ IN NS localhost.
1 IN PTR localhost.
EOF
cat > "$W/namedb/primary/empty.db" <<EOF
\$TTL 3h
@ IN SOA @ nobody.invalid. 1 1d 12h 1w 3h
  NS @
EOF
cat > "$W/namedb/primary/example.test.db" <<EOF
\$TTL 1h
@ IN SOA ns1 hostmaster 2026102801 1d 2h 4w 1h
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.80
EOF
cat > "$W/namedb/root.cache" <<'EOF'
.                        3600000      NS    A.ROOT-SERVERS.EXAMPLE.
A.ROOT-SERVERS.EXAMPLE.  3600000      A     192.0.2.53
A.ROOT-SERVERS.EXAMPLE.  3600000      AAAA  2001:db8::53
EOF
# What dns/bind920 and the FreeBSD base BIND ship in named.conf, with example names and addresses and test paths; port / bind-address /
# user are the KariDNS statements that a BIND configuration does not have.
cat > "$W/etc/s2.conf" <<EOF
// FreeBSD style named.conf
options {
	// All file and path names are relative to the chroot directory, if any, and should be fully qualified.
	directory	"$W/namedb/working";
	pid-file	"$W/namedb/working/named.pid";
	dump-file	"$W/namedb/working/named_dump.db";
	statistics-file	"$W/namedb/working/named.stats";

	listen-on	{ 127.0.0.1; };
	listen-on-v6	{ ::1; };

	// If named is being used only as a local resolver, this is a safe default.
	recursion no;
	// forwarders { 192.0.2.53; };
	// forward only;
	dnssec-validation auto;
	empty-zones-enable yes;
	disable-empty-zone "10.IN-ADDR.ARPA";
	version "none";
	allow-transfer { none; };
	notify no;
	// KariDNS
	port $P2; bind-address { 127.0.0.1; }; $USER_OPT
};

// Provide a reverse mapping for the loopback address 127.0.0.1.
zone "." { type hint; file "$W/namedb/root.cache"; };
zone "localhost" { type primary; file "../primary/localhost-forward.db"; };
zone "0.0.127.in-addr.arpa" { type primary; file "../primary/localhost-reverse.db"; };
zone "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa" { type primary; file "../primary/localhost-reverse.db"; };
zone "0.in-addr.arpa" { type primary; file "../primary/empty.db"; };
zone "255.in-addr.arpa" { type primary; file "../primary/empty.db"; };
zone "example.test" IN { type primary; file "../primary/example.test.db"; };
zone "mirror.test" { type mirror; masters { 192.0.2.9; }; };
zone "static.test" { type static-stub; server-addresses { 192.0.2.10; }; };
zone "nx.test" { type redirect; file "../primary/empty.db"; };

logging {
	channel default_log { file "$W/namedb/working/named.log" versions 3 size 5m; print-time yes; severity info; };
	category default { default_log; };
};

controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; }; };
EOF
OUT=$("$KARICHECK" conf "$W/etc/s2.conf" 2>&1); RC=$?
if [ $RC -eq 0 ] && ! echo "$OUT" | grep -q "\[ERROR\]"; then pass "karicheck conf accepts a FreeBSD style BIND named.conf"; else fail "karicheck conf s2 (rc=$RC): $OUT"; fi
for t in hint mirror static-stub redirect; do
    echo "$OUT" | grep -q "type '$t' is a BIND zone type.*is not loaded" && pass "karicheck conf warns about type $t" || fail "no warning for type $t: $OUT"
done
echo "$OUT" | grep -q "'listen-on' is a BIND option that KariDNS does not implement" && pass "listen-on is a warning" || fail "no listen-on warning"
echo "$OUT" | grep -q "\[WARNING\]" && pass "the stock configuration passes with warnings only" || fail "no warnings at all?"
"$KARIDNS" -f -c "$W/etc/s2.conf" > "$W/s2.log" 2>&1 &
PIDS="$PIDS $!"
if ! kari_wait_answer "$DAG" "$P2" localhost 20; then fail "server 2 (the stock configuration) did not start"; tail -20 "$W/s2.log"; exit 1; fi
[ "$(ans "$P2" localhost A)" = "127.0.0.1" ] && pass "server 2: localhost answers (file relative to directory, with ..)" || fail "localhost: $(ans "$P2" localhost A)"
[ "$(ans "$P2" 1.0.0.127.in-addr.arpa PTR)" = "localhost." ] && pass "server 2: 0.0.127.in-addr.arpa answers" || fail "ptr: $(ans "$P2" 1.0.0.127.in-addr.arpa PTR)"
[ "$(ans "$P2" www.example.test A)" = "192.0.2.80" ] && pass "server 2: a zone declared with IN answers" || fail "www.example.test: $(ans "$P2" www.example.test A)"
[ "$(status "$P2" . NS)" = "REFUSED" ] && pass "server 2: the hint zone is not served (REFUSED)" || fail "root NS status: $(status "$P2" . NS)"
[ "$(status "$P2" www.mirror.test A)" = "REFUSED" ] && pass "server 2: a mirror zone is not served" || fail "mirror status: $(status "$P2" www.mirror.test A)"
[ -f "$W/namedb/working/named.pid" ] && pass "server 2: pid-file written" || fail "no pid file"

# ---------------------------------------------------------------- karicheck: $INCLUDE ranges (standalone and from a configuration)
mkdir -p "$W/z/sub"
echo 'in1 IN A 192.0.2.21' > "$W/z/sub/in1.inc"
echo 'out1 IN A 192.0.2.22' > "$W/other/out1.inc"
zonefile() { # zonefile FILE INCLUDE-LINE
    printf '$TTL 300\n$ORIGIN inc.test.\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\n%s\n' "$2" > "$1"
}
zonefile "$W/z/in_abs.zone" "\$INCLUDE $W/z/sub/in1.inc"
zonefile "$W/z/in_dots.zone" "\$INCLUDE sub/../sub/in1.inc"
zonefile "$W/z/out_abs.zone" "\$INCLUDE $W/other/out1.inc"
zonefile "$W/z/out_dots.zone" "\$INCLUDE ../other/out1.inc"
zonefile "$W/z/out_etc.zone" "\$INCLUDE /etc/hosts"
OUT=$("$KARICHECK" zone inc.test "$W/z/in_abs.zone" 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karicheck zone: an absolute \$INCLUDE inside the zone directory is accepted" || fail "in_abs (rc=$RC): $OUT"
OUT=$("$KARICHECK" zone inc.test "$W/z/in_dots.zone" 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karicheck zone: .. that stays inside is accepted" || fail "in_dots (rc=$RC): $OUT"
for f in out_abs out_dots out_etc; do
    OUT=$("$KARICHECK" zone inc.test "$W/z/$f.zone" 2>&1); RC=$?
    if [ $RC -ne 0 ] && echo "$OUT" | grep -q "outside the directories opened at startup (zone file dir)"; then pass "karicheck zone: $f is refused with the reason"; else fail "$f (rc=$RC): $OUT"; fi
done
# the same files from a configuration with directory: both trees are ranges
cat > "$W/etc/s3.conf" <<EOF
options { directory "$W/z"; };
zone "inc.test" { type primary; file "in_abs.zone"; };
EOF
OUT=$("$KARICHECK" zone inc.test "$W/etc/s3.conf" 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karicheck zone <domain> <conf>: the same verdict through the configuration" || fail "s3 in_abs (rc=$RC): $OUT"
mkdir -p "$W/z/zf"     # the zone file is not in directory itself: sub/in1.inc exists only below directory
zonefile "$W/z/zf/dir_rel.zone" "\$INCLUDE sub/in1.inc"
sed -i.bak 's|in_abs.zone|zf/dir_rel.zone|' "$W/etc/s3.conf" && rm -f "$W/etc/s3.conf.bak"
OUT=$("$KARICHECK" zone inc.test "$W/etc/s3.conf" 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karicheck zone: a relative \$INCLUDE is read from directory" || fail "s3 dir_rel (rc=$RC): $OUT"
sed -i.bak 's|zf/dir_rel.zone|out_abs.zone|' "$W/etc/s3.conf" && rm -f "$W/etc/s3.conf.bak"
OUT=$("$KARICHECK" zone inc.test "$W/etc/s3.conf" 2>&1); RC=$?
if [ $RC -ne 0 ] && echo "$OUT" | grep -q "outside the directories opened at startup (zone file dir, directory)"; then pass "karicheck zone: through the configuration the message names both ranges"; else fail "s3 out_abs (rc=$RC): $OUT"; fi

# ---------------------------------------------------------------- karicheck: classes, ports, TTLs, directory
expect_conf_error() { # expect_conf_error LABEL TEXT PATTERN
    printf '%s\n' "$2" > "$W/bad.conf"
    OUT=$("$KARICHECK" conf "$W/bad.conf" 2>&1); RC=$?
    if [ $RC -ne 0 ] && echo "$OUT" | grep -Eq "$3"; then pass "$1"; else fail "$1 (rc=$RC): $OUT"; fi
}
expect_conf_error "zone class CH is an error with file:line" 'zone "x.test" CH { type primary; file "x"; };' 'bad.conf:1: zone .x.test..: class .CH. is not supported \(only IN\)'
expect_conf_error "view class HS is an error with file:line" '
view "v" HS { match-clients { any; }; };' 'bad.conf:2: view .v.: class .HS. is not supported'
expect_conf_error "port 0" 'options { port 0; };' 'bad.conf:1: options: port: invalid port .0. \(expected 1-65535\)'
expect_conf_error "port 65536" 'options { port 65536; };' 'invalid port .65536.'
expect_conf_error "port abc" 'options { port abc; };' 'invalid port .abc.'
expect_conf_error "in-view" 'zone "x.test" { in-view "a"; };' "in-view.*not supported"
expect_conf_error "directory that does not exist" "options { directory \"$W/nonexistent\"; };" "directory '$W/nonexistent' cannot be accessed"
expect_conf_error "directory that is a file" "options { directory \"$W/ctl.conf\"; };" "is not a directory"

printf '$TTL 1x\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\n' > "$W/z/badttl.zone"
OUT=$("$KARICHECK" zone ttl.test "$W/z/badttl.zone" 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "Invalid \$TTL value" && pass "karicheck zone: \$TTL 1x is an error" || fail "badttl (rc=$RC): $OUT"
printf '@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\nwww 2147483648 IN A 192.0.2.1\n' > "$W/z/bigttl.zone"
OUT=$("$KARICHECK" zone ttl.test "$W/z/bigttl.zone" 2>&1); RC=$?
[ $RC -ne 0 ] && echo "$OUT" | grep -q "Invalid TTL" && pass "karicheck zone: a TTL above 2147483647 is an error" || fail "bigttl (rc=$RC): $OUT"
printf '$TTL 1h30m\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ 2147483647 IN NS ns1\nns1 0 IN A 192.0.2.1\n' > "$W/z/okttl.zone"
OUT=$("$KARICHECK" zone ttl.test "$W/z/okttl.zone" 2>&1); RC=$?
[ $RC -eq 0 ] && pass "karicheck zone: units and 2147483647 are accepted" || fail "okttl (rc=$RC): $OUT"
printf 'ns1 IN A 192.0.2.1\n@ IN SOA ns1 hostmaster 1 3600 600 86400 60\n@ IN NS ns1\n' > "$W/z/nottl.zone"
OUT=$("$KARICHECK" zone ttl.test "$W/z/nottl.zone" 2>&1); RC=$?
if [ $RC -eq 0 ] && echo "$OUT" | grep -q "1 record(s) have no TTL" && echo "$OUT" | grep -q "BIND rejects such a zone"; then pass "karicheck zone: a record without any TTL is a warning"; else fail "nottl (rc=$RC): $OUT"; fi

if [ "$FAILS" -eq 0 ]; then echo "ALL TESTS PASSED"; exit 0; fi
echo "$FAILS FAILURE(S)"
exit 1
