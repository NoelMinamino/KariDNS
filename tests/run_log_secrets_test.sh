#!/bin/sh
# ==============================================================================
# tests/run_log_secrets_test.sh - no secret in any log at any debug level, and the debug 1 decision lines of each category (0.7 M3)
# ==============================================================================
# Two servers on loopback, a primary P started at `karidns -d 99` and a secondary S started at level 0, with distinctive canary strings in
# every setting that holds a secret:
#   - the TSIG key of the transfers and NOTIFYs (xfer-key) and the key of the UPDATEs (upd-key), in an `include` file;
#   - the secret of the control channel;
#   - cookie-secret;
#   - an argument of a program zone's plugin (program-args);
#   - with KARIDNS_TEST_PG: a server G whose PostgreSQL conninfo file has a canary password and names a database that does not exist, so that
#     the loader's connection fails and its error (PQerrorMessage) is logged; otherwise only SQLite3 (no credential).
# Exercised: start, reload, reconfig, AXFR / IXFR in (S from P) and out (P to S and to dag) with TSIG (good key, bad key, bad time), NOTIFY
# (P to S, and one from an address that is no primary), a signed UPDATE (allowed) and unsigned ones (refused), control commands with the good
# key and a bad key, a database zone (SQLite3, memory-limit: the query fetches it), a program zone query, DNS cookies, shutdown.
# Then every output is searched for each canary in raw, base64 and hex (lower and upper case) form, and for the MACs of signed answers and
# the full server cookie the clients were given: the stderr of the servers (a foreground server also prints its syslog lines there), every
# file channel, karidns.run, and the lines the host's syslog wrote meanwhile (/var/log/messages, debug.log, all.log when they exist).
#   L  the decision lines at debug 1 of general, config, zoneload, xfer-in, xfer-out, notify, update, security, database and network
#      appear when the level is 1 (S after `trace 1`, P from the start), and none of them while the level is 0 (S before, both after notrace)
# Needs root (the servers drop to nobody, the loader runs as nobody).  SKIP otherwise, and without the binaries, SQLite3 or perl.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="${BIN_DIR:-$ROOT}"
KARIDNS="${KARIDNS:-$BIN/karidns}"
cd "$ROOT" || exit 1

if [ "$(id -u)" != "0" ]; then echo "SKIP: needs root (the servers drop to nobody, the loader runs as nobody)"; exit 0; fi
for b in "$KARIDNS" "$BIN/karictl" "$BIN/dag" "$BIN/karidns-dbloader"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
"$BIN/karidns-dbloader" --drivers | grep -qx sqlite3 || { echo "SKIP: karidns-dbloader has no SQLite3 driver"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_secrets.XXXXXX") || exit 1
chmod 755 "$T"
PSRV="" SSRV="" GSRV=""
FAILS=0; PASSES=0
pass() { PASSES=$((PASSES + 1)); echo "PASS: $1"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL: $1"; }
cleanup() {
    set +e
    kari_kill_tree $PSRV $SSRV $GSRV
    kari_kill_conf "$T/p.conf" "$T/s.conf" "$T/g.conf"
    if [ "$FAILS" -ne 0 ]; then
        for f in "$T/p.log" "$T/s.log" "$T/g.log" "$T/logs/p.log" "$T/logs/s.log"; do echo "--- $f (tail)"; tail -30 "$f" 2>/dev/null; done
    fi
    if [ -n "${KARI_KEEP_TMP:-}" ]; then echo "kept: $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

PP=$(kari_port 0) SP=$(kari_port 1) GP=$(kari_port 2)
for p in $PP $SP $GP; do
    if sockstat -4 -l -p "$p" 2>/dev/null | grep -q ":$p "; then echo "SKIP: port $p is in use"; exit 0; fi
done

# ---------------------------------------------------------------- the canaries (raw text; the configuration holds their base64 or hex form)
b64() { printf '%s' "$1" | openssl base64 -A; }
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
C_XFR="KcanaryXfrTsigSecret01"
C_UPD="KcanaryUpdTsigSecret02"
C_CTL="KcanaryControlSecret03"
C_COOKIE="KcanaryCookieS04"        # 16 octets: cookie-secret is 128 bits of hex
C_PLUG="KcanaryPluginArgument05"
C_PG="KcanaryPgPassword06"
XFR_B64=$(b64 "$C_XFR"); UPD_B64=$(b64 "$C_UPD"); CTL_B64=$(b64 "$C_CTL"); COOKIE_HEX=$(hex "$C_COOKIE")
[ ${#COOKIE_HEX} -eq 32 ] || { fail "setup: the cookie canary is not 16 octets"; exit 1; }

LOGD="$T/logs"; mkdir "$LOGD"; chmod 777 "$LOGD"
mkdir "$T/pdir" "$T/sdir" "$T/gdir" "$T/ev"; chmod 777 "$T/pdir" "$T/sdir" "$T/gdir" "$T/ev"

# the keys, in a file the configurations include (read by the run user at a reload: world-readable here, a test)
cat > "$T/keys.conf" <<EOF
key "xfer-key" { algorithm hmac-sha256; secret "$XFR_B64"; };
key "upd-key" { algorithm hmac-sha256; secret "$UPD_B64"; };
EOF
chmod 644 "$T/keys.conf"
printf 'key "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$CTL_B64" > "$T/ctl.key"
printf 'key "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$(b64 'not-the-control-secret-0')" > "$T/bad.key"
chmod 600 "$T/ctl.key" "$T/bad.key"

zonefile() { printf '$TTL 300\n$ORIGIN %s.\n@ IN SOA ns1 hostmaster %s 3600 600 86400 60\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN A 192.0.2.10\n' "$2" "$3" > "$1"; chmod 644 "$1"; }
zonefile "$T/pri.zone" pri.test 1
zonefile "$T/sfile.zone" sfile.test 1

# a database zone (SQLite3), out of memory until a query fetches it (memory-limit)
mkdir "$T/db"
sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('db.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'db.test', 'SOA', 'ns1.db.test host.db.test 1 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'db.test', 'NS', 'ns1.db.test', 3600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.db.test', 'A', '192.0.2.53', 600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'www.db.test', 'A', '192.0.2.77', 300, 0, 0 FROM domains;
SQL
chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
install -o root -g wheel -m 755 "$BIN/karidns-dbloader" "$T/karidns-dbloader"
# the plugin: the one of the supervisor test, behind a wrapper that takes (and ignores) a third argument, the canary
PERL=$(command -v perl)
printf '#!/bin/sh\nexec %s %s "$1" "$2"\n' "$PERL" "$ROOT/tests/plugins/supervised_plugin.pl" > "$T/plugin.sh"
chown root:wheel "$T/plugin.sh"; chmod 755 "$T/plugin.sh"
chmod +x "$ROOT/tests/plugins/supervised_plugin.pl" 2>/dev/null || true

logging() { # logging NAME : one severity dynamic channel for everything, karidns.run (default_debug) and syslog besides
    cat <<EOF
logging {
    channel all { file "$LOGD/$1.log"; severity dynamic; print-category yes; print-severity yes; };
    category default { all; default_debug; default_syslog; };
};
EOF
}
cat > "$T/p.conf" <<EOF
include "$T/keys.conf";
options {
    directory "$T/pdir"; user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PP;
    cookie-secret "$COOKIE_HEX";
    allow-program-zones yes;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; memory-limit 64m; acl-ceiling { 127.0.0.1; }; };
};
control-channel { socket "$T/p.sock"; algorithm hmac-sha256; secret "$CTL_B64"; };
$(logging p)
zone "pri.test" { type primary; file "$T/pri.zone"; allow-transfer { key xfer-key; }; allow-update { key upd-key; };
    also-notify { 127.0.0.1 port $SP key xfer-key; }; };
zone "prog.test" { type program; program "$T/plugin.sh"; program-args { "192.0.2.50"; "$T/ev/plug"; "$C_PLUG"; }; program-user "nobody"; };
EOF
cat > "$T/s.conf" <<EOF
include "$T/keys.conf";
options { directory "$T/sdir"; user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $SP; cookie-secret "$COOKIE_HEX"; };
control-channel { socket "$T/s.sock"; algorithm hmac-sha256; secret "$CTL_B64"; };
$(logging s)
zone "pri.test" { type secondary; primaries { 127.0.0.1 port $PP key xfer-key; }; };
zone "sfile.test" { type primary; file "$T/sfile.zone"; };
EOF
chmod 644 "$T/p.conf" "$T/s.conf"

ctl() { _s=$1; shift; "$BIN/karictl" -s "$T/$_s.sock" -f "$T/ctl.key" "$@" 2>&1; }
d() { _p=$1; shift; "$BIN/dag" @127.0.0.1 -p "$_p" +time=2 +tries=1 +nohexdump "$@" 2>&1; }
wl() { kari_wait_log "$1" "$2" "${3:-15}" "${4:-1}"; }          # wl FILE PATTERN [SECONDS] [COUNT]
cnt() { grep -c -- "$2" "$1" 2>/dev/null || true; }
up() { _i=0; until ctl "$1" status 2>/dev/null | grep -q '^version:'; do _i=$((_i + 1)); [ $_i -gt 80 ] && return 1; sleep 0.25; done; }
serial_of() { d "$1" pri.test SOA +short | awk '{ print $3 }'; }
macs() { awk '/TSIG[ \t]+hmac-sha256/ { for (i = 1; i <= NF; i++) if ($i == "32") { print $(i + 1); break } }' "$@"; }   # the MACs of the TSIG RRs dag printed

: > "$T/macs"
syslog_mark() { for f in /var/log/messages /var/log/debug.log /var/log/all.log; do [ -f "$f" ] && wc -c < "$f" | tr -d ' ' > "$T/mark.$(basename "$f")"; done; }
syslog_mark

# ================================================================ start: P at level 99, S at level 0
"$KARIDNS" -d 99 -c "$T/p.conf" -f > "$T/p.log" 2>&1 &
PSRV=$!
"$KARIDNS" -c "$T/s.conf" -f > "$T/s.log" 2>&1 &
SSRV=$!
up p && pass "start: P (karidns -d 99) is up" || fail "start: P did not come up"
up s && pass "start: S (level 0) is up" || fail "start: S did not come up"
ctl p status | grep -q '^debug level: 99$' && pass "start: P runs at debug level 99" || fail "start: P's level: $(ctl p status | grep debug)"
wl "$LOGD/p.log" 'database: info: \[DB\] loader connected' 30 || fail "start: P's loader did not connect"
_i=0; while [ $_i -lt 60 ] && [ "$(serial_of $SP)" != 1 ]; do sleep 0.25; _i=$((_i + 1)); done
[ "$(serial_of $SP)" = 1 ] && pass "AXFR in: S has pri.test from P (TSIG xfer-key)" || fail "AXFR in: S has no pri.test"
[ "$(cnt "$LOGD/s.log" ': debug [0-9]*: ')" = 0 ] && pass "L: S at level 0 wrote no debug line (start, AXFR in)" || fail "L: S wrote debug lines at level 0"
[ ! -s "$T/sdir/karidns.run" ] && pass "L: S's karidns.run stays empty at level 0" || fail "L: S's karidns.run has lines at level 0"

# ================================================================ S at level 1: the decision lines of xfer-in, notify and the others
echo "== traffic with S at level 1"
ctl s trace 1 | grep -q '^OK debug level is now 1$' && pass "S: trace 1" || fail "S: trace 1"
d $PP pri.test A --update-add 'u1.pri.test 300 A 192.0.2.101' -y "hmac-sha256:upd-key:$UPD_B64" > "$T/upd1.out"
grep -q "status: NOERROR" "$T/upd1.out" && pass "UPDATE: signed with upd-key: applied" || fail "UPDATE: signed: $(grep status "$T/upd1.out")"
macs "$T/upd1.out" >> "$T/macs"
d $PP pri.test A --update-add 'u2.pri.test 300 A 192.0.2.102' | grep -q "status: REFUSED" && pass "UPDATE: unsigned: refused" || fail "UPDATE: unsigned was not refused"
d $PP pri.test A --update-add 'u3.pri.test 300 A 192.0.2.103' -y "hmac-sha256:xfer-key:$XFR_B64" | grep -q "status: REFUSED" && pass "UPDATE: signed with a key allow-update does not name: refused" || fail "UPDATE: wrong key was not refused"
# the UPDATE made serial 2; P sends a NOTIFY at its next tick, S refreshes with an IXFR
_i=0; while [ $_i -lt 80 ] && [ "$(serial_of $SP)" != 2 ]; do sleep 0.25; _i=$((_i + 1)); done
[ "$(serial_of $SP)" = 2 ] && pass "NOTIFY + IXFR in: S followed P to serial 2" || fail "NOTIFY + IXFR in: S has serial $(serial_of $SP)"
ctl p notify pri.test | grep -q '^OK' && pass "control: notify pri.test (good key)" || fail "control: notify"
ctl s retransfer pri.test | grep -q '^OK' && pass "control: retransfer on S" || fail "control: retransfer"
d $SP pri.test SOA +opcode=NOTIFY > /dev/null    # unsigned, from the address of the primary: refused (the zone needs xfer-key)
"$BIN/karictl" -s "$T/s.sock" -f "$T/bad.key" status > "$T/badctl.out" 2>&1
grep -q '^version:' "$T/badctl.out" && fail "control: a bad key was let in" || pass "control: a bad key is refused"
wl "$LOGD/s.log" 'xfer-in: debug 1: \[AXFR\] zone pri.test[.]*: asking primary 127.0.0.1#' 20 && pass "L xfer-in: 'asking primary' at debug 1" || fail "L xfer-in: no 'asking primary' line"
wl "$LOGD/s.log" 'xfer-in: debug 1: \[AXFR\] zone pri.test[.]*: refresh done: ' && pass "L xfer-in: 'refresh done' at debug 1" || fail "L xfer-in: no 'refresh done' line"
grep 'asking primary' "$LOGD/s.log" | grep -q 'TSIG key xfer-key' && pass "L xfer-in: the key is named (its name only)" || fail "L xfer-in: no key name"
wl "$LOGD/s.log" "notify: debug 1: client 127.0.0.1#[0-9]*: received NOTIFY for zone 'pri.test[.]*' (view '[^']*'), signed with key xfer-key[.]*: accepted" &&
    pass "L notify: a received NOTIFY at debug 1, accepted from a primary" || fail "L notify: no 'received NOTIFY' line"
wl "$LOGD/s.log" "security: debug 1: \[Control\] connection [0-9]*: authentication failed" && pass "L security: the failed control authentication at debug 1" || fail "L security: no authentication line"
ctl s reload > /dev/null
wl "$LOGD/s.log" "general: debug 1: \[Core\] zone snapshot" && pass "L general: the zone snapshot of the reload at debug 1" || fail "L general: no zone snapshot line"
wl "$LOGD/s.log" "zoneload: debug 1: \[Zone\] zone 'sfile.test[.]*' (view '[^']*'): reading '[^']*sfile.zone' again: a full reload reads every zone file" &&
    pass "L zoneload: why the file is read again, at debug 1" || fail "L zoneload: no 'reading again' line"
wl "$LOGD/s.log" "zoneload: debug 1: \[Zone\] zone 'sfile.test[.]*' (view '[^']*') loaded from " && pass "L zoneload: the load (records, serial, time) at debug 1" || fail "L zoneload: no 'loaded from' line"
wl "$LOGD/s.log" "config: debug 1: \[Config\] include '$T/keys.conf' read (" && pass "L config: the include of the reload at debug 1 (its name, never its text)" || fail "L config: no include line"
grep -q ': debug [3-9]: \|: debug [1-9][0-9]: ' "$LOGD/s.log" && fail "L: S at level 1 wrote lines above debug 1" || pass "L: S at level 1 wrote no line above debug 1"
# P (level 99 since the start): xfer-out, notify, update, database, network
wl "$LOGD/p.log" "xfer-out: debug 1: client 127.0.0.1: transfer of 'pri.test[.]*' (view '[^']*'): allowed by a positive element of allow-transfer, request signed with key xfer-key" &&
    pass "L xfer-out: the allow-transfer decision at debug 1" || fail "L xfer-out: no ACL decision line"
wl "$LOGD/p.log" "xfer-out: debug 1: client 127.0.0.1#[0-9]*: transfer of 'pri.test/IN': IXFR asked (client serial 1, ours 2): answering with IXFR" &&
    pass "L xfer-out: the IXFR answer decision at debug 1" || fail "L xfer-out: no IXFR decision line"
wl "$LOGD/p.log" "notify: debug 1: \[Notify\] zone 'pri.test[.]*' (view '[^']*'): 1 destination(s)" && pass "L notify: the destinations of a NOTIFY at debug 1" || fail "L notify: no destinations line"
wl "$LOGD/p.log" "update: debug 1: client 127.0.0.1#[0-9]*: UPDATE of zone 'pri.test[.]*' (view '[^']*'), signed with key upd-key[.]*: allowed by allow-update" &&
    pass "L update: the allow-update decision at debug 1" || fail "L update: no decision line"
wl "$LOGD/p.log" "update: debug 1: client 127.0.0.1#[0-9]*: UPDATE of zone 'pri.test[.]*' (view '[^']*'), unsigned: refused by allow-update" &&
    pass "L update: the refusal at debug 1" || fail "L update: no refusal line"
wl "$LOGD/p.log" "update: debug 2: client 127.0.0.1#[0-9]*: \[Update\] zone 'pri.test[.]*': 0 prerequisite(s), 1 update RR(s): prerequisites satisfied, the zone changes" &&
    pass "update: the prerequisite result at debug 2" || fail "update: no prerequisite line"
wl "$LOGD/p.log" "database: debug 1: \[DB\] zone 'db.test[.]*' (view '[^']*'), serial 1: " && pass "L database: the zone of the batch at debug 1" || fail "L database: no zone line"
wl "$LOGD/p.log" "network: debug 1: \[Network\] UDP listener 127.0.0.1#$PP" && pass "L network: the listener of a router at debug 1 (P was started at -d 99)" || fail "L network: no listener line"
grep -q '\[Network\] UDP listener' "$LOGD/s.log" && fail "L network: S (started at level 0) wrote a listener line" || pass "L network: no listener line from S, which was started at level 0"

# ================================================================ more of the canary exercise at P (level 99)
echo "== transfers out, TSIG errors, cookies, the database and program zones at P"
d $PP pri.test AXFR -y "hmac-sha256:xfer-key:$XFR_B64" > "$T/axfr.out"
grep -q "SOA" "$T/axfr.out" && pass "AXFR out: signed with xfer-key" || fail "AXFR out: $(tail -2 "$T/axfr.out")"
macs "$T/axfr.out" >> "$T/macs"
d $PP pri.test IXFR=1 -y "hmac-sha256:xfer-key:$XFR_B64" +tcp > "$T/ixfr.out"
grep -q "SOA" "$T/ixfr.out" && pass "IXFR out: signed with xfer-key" || fail "IXFR out"
macs "$T/ixfr.out" >> "$T/macs"
d $PP pri.test AXFR -y "hmac-sha256:xfer-key:$(b64 'a-wrong-secret-for-xfer')" > "$T/axfr_bad.out"
grep -qi "fail\|NOTAUTH\|BADSIG" "$T/axfr_bad.out" && pass "AXFR out: a bad key is refused" || fail "AXFR out: bad key"
d $PP pri.test AXFR -y "hmac-sha256:xfer-key:$XFR_B64" +fuzztime=1646972129 > "$T/axfr_time.out"
grep -qi "BADTIME\|NOTAUTH" "$T/axfr_time.out" && pass "AXFR out: a bad time is refused (BADTIME)" || fail "AXFR out: bad time"
macs "$T/axfr_time.out" >> "$T/macs"
d $PP www.pri.test A -y "hmac-sha256:xfer-key:$XFR_B64" > "$T/q_signed.out"
macs "$T/q_signed.out" >> "$T/macs"
wl "$LOGD/p.log" "security: debug 3: client 127.0.0.1: \[TSIG\] key 'xfer-key' algorithm hmac-sha256 view '[^']*': BADTIME (time signed 1646972129, fudge 300, our clock +" &&
    pass "security: the BADTIME detail at debug 3 (time values, no secret)" || fail "security: no BADTIME detail line"
wl "$LOGD/p.log" "security: debug 3: client 127.0.0.1: \[TSIG\] key 'xfer-key' algorithm hmac-sha256 view '[^']*': BADSIG" && pass "security: the BADSIG detail at debug 3" || fail "security: no BADSIG detail"
d $PP www.pri.test A +cookie > "$T/cookie1.out"
SC=$(sed -n 's/^; COOKIE: \([0-9a-f]*\).*/\1/p' "$T/cookie1.out" | head -1)
if [ ${#SC} -ge 32 ]; then
    pass "cookies: P gave a server cookie"
    echo "$SC" > "$T/servercookie"
    d $PP www.pri.test A +cookie="$SC" > "$T/cookie2.out"
    wl "$LOGD/p.log" "security: debug 3: client 127.0.0.1: \[Cookie\] server cookie valid: made [0-9-]* s ago with cookie-secret #1" && pass "security: the cookie decision at debug 3" || fail "security: no cookie line"
else
    fail "cookies: no server cookie in '$(grep COOKIE "$T/cookie1.out")'"
fi
_i=0; until d $PP www.db.test A +short | grep -q '192\.0\.2\.77'; do _i=$((_i + 1)); [ $_i -gt 40 ] && break; sleep 0.25; done
d $PP www.db.test A +short | grep -q '192\.0\.2\.77' && pass "database: www.db.test is answered (the zone was fetched)" || fail "database: no answer from db.test"
wl "$LOGD/p.log" "database: debug 2: \[DB\] fetch [0-9]*: zone 'db.test[.]*' (view '[^']*'), whole zone, for a query" && pass "database: the fetch at debug 2" || fail "database: no fetch line"
_i=0; until d $PP www.prog.test A +short | grep -q '192\.0\.2\.50'; do _i=$((_i + 1)); [ $_i -gt 40 ] && break; sleep 0.25; done
d $PP www.prog.test A +short | grep -q '192\.0\.2\.50' && pass "program zone: answered by the plugin" || fail "program zone: no answer"
ctl p reload | grep -q '^OK' && pass "control: reload of P" || fail "control: reload of P"
ctl p reconfig | grep -q '^OK' && pass "control: reconfig of P" || fail "control: reconfig of P"
wl "$LOGD/p.log" "general: debug 3: \[Control\] key \"[^\"]*\": command 'reconfig'" && pass "general: the control command at debug 3 (the key's name only)" || fail "general: no control command line"
wl "$LOGD/p.log" "client: debug 3: client 127.0.0.1#[0-9]*: query www.pri.test/A (signed): view '[^']*', zone 'pri.test" && pass "client: the route of a signed query at debug 3" || fail "client: no route line"
"$BIN/karictl" -s "$T/p.sock" -f "$T/bad.key" reload > /dev/null 2>&1

# ================================================================ G: PostgreSQL with a canary password and a database that does not exist
if [ -n "${KARIDNS_TEST_PG:-}" ] && "$BIN/karidns-dbloader" --drivers | grep -qx postgresql; then
    echo "== G: PostgreSQL conninfo with a canary password (KARIDNS_TEST_PG)"
    printf '%s dbname=karidns_canary_nodb password=%s\n' "$KARIDNS_TEST_PG" "$C_PG" > "$T/conninfo"
    chown nobody "$T/conninfo"; chmod 600 "$T/conninfo"
    cat > "$T/g.conf" <<EOF
options {
    directory "$T/gdir"; user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $GP;
    database { driver postgresql; conninfo-file "$T/conninfo"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; };
};
control-channel { socket "$T/g.sock"; algorithm hmac-sha256; secret "$CTL_B64"; };
$(logging g)
zone "sfile.test" { type primary; file "$T/sfile.zone"; };
EOF
    chmod 644 "$T/g.conf"
    "$KARIDNS" -d 99 -c "$T/g.conf" -f > "$T/g.log" 2>&1 &
    GSRV=$!
    up g && pass "G: the server is up" || fail "G: did not come up"
    wl "$LOGD/g.log" 'karidns_canary_nodb' 30 && pass "G: the loader's connection error is logged (it names the database)" || fail "G: no connection error line"
    grep 'karidns_canary_nodb' "$LOGD/g.log" | head -2 | sed 's/^/        /'
    kari_kill_tree $GSRV; GSRV=""
else
    echo "NOTE: KARIDNS_TEST_PG is not set (or no PostgreSQL driver): the conninfo password and the libpq error path are not exercised"
fi

# ================================================================ notrace: no decision line at level 0
echo "== notrace"
ctl p notrace | grep -q '^OK debug level is now 0$' && pass "notrace on P" || fail "notrace on P"
ctl s notrace | grep -q '^OK debug level is now 0$' && pass "notrace on S" || fail "notrace on S"
wl "$LOGD/s.log" 'general: notice: \[Control\] debug level is now 0' || true
wl "$LOGD/p.log" 'general: notice: \[Control\] debug level is now 0' || true
DP0=$(cnt "$LOGD/p.log" ': debug [0-9]*: '); DS0=$(cnt "$LOGD/s.log" ': debug [0-9]*: ')
d $PP pri.test A --update-add 'u4.pri.test 300 A 192.0.2.104' -y "hmac-sha256:upd-key:$UPD_B64" | grep -q "status: NOERROR" || fail "level 0: UPDATE"
d $PP pri.test A --update-add 'u5.pri.test 300 A 192.0.2.105' -y "hmac-sha256:upd-key:$UPD_B64" | grep -q "status: NOERROR" || fail "level 0: UPDATE 2"
PSER=$(serial_of $PP)
_i=0; while [ $_i -lt 80 ] && [ "$(serial_of $SP)" != "$PSER" ]; do sleep 0.25; _i=$((_i + 1)); done
[ "$(serial_of $SP)" = "$PSER" ] && pass "level 0: NOTIFY + transfer in to serial $PSER" || fail "level 0: S has serial $(serial_of $SP)"
d $PP pri.test AXFR -y "hmac-sha256:xfer-key:$XFR_B64" > /dev/null
"$BIN/karictl" -s "$T/s.sock" -f "$T/bad.key" status > /dev/null 2>&1
ctl s reload > /dev/null
ctl p reload > /dev/null
wl "$LOGD/p.log" 'Configuration and zones reloaded successfully' 15 3 || true
sleep 1
[ "$(cnt "$LOGD/p.log" ': debug [0-9]*: ')" = "$DP0" ] && [ "$(cnt "$LOGD/s.log" ': debug [0-9]*: ')" = "$DS0" ] &&
    pass "L: at level 0 neither server wrote a debug line (UPDATE, NOTIFY, IXFR in and out, AXFR out, a bad control key, reloads)" ||
    { fail "L: debug lines at level 0"; grep ': debug [0-9]*: ' "$LOGD/p.log" | tail -n +$((DP0 + 1)) | head -5; grep ': debug [0-9]*: ' "$LOGD/s.log" | tail -n +$((DS0 + 1)) | head -5; }

# ================================================================ shutdown, then the search
ctl p trace 99 > /dev/null
kill -TERM $PSRV $SSRV 2>/dev/null
_i=0; while [ $_i -lt 100 ] && { kill -0 $PSRV 2>/dev/null || kill -0 $SSRV 2>/dev/null; }; do sleep 0.1; _i=$((_i + 1)); done
kari_kill_tree $PSRV $SSRV; PSRV="" SSRV=""
for f in /var/log/messages /var/log/debug.log /var/log/all.log; do
    [ -f "$f" ] || continue
    m=$(cat "$T/mark.$(basename "$f")" 2>/dev/null || echo 0)
    tail -c +$((m + 1)) "$f" > "$T/syslog.$(basename "$f")" 2>/dev/null
done
OUTS=$(ls "$T"/p.log "$T"/s.log "$T"/g.log "$LOGD"/*.log "$T"/pdir/karidns.run "$T"/sdir/karidns.run "$T"/gdir/karidns.run "$T"/syslog.* 2>/dev/null)
echo "== searching: $(echo $OUTS | wc -w) outputs, $(cat $OUTS 2>/dev/null | wc -l | tr -d ' ') lines"
[ -s "$T/pdir/karidns.run" ] && pass "outputs: P's karidns.run has the debug lines" || fail "outputs: P's karidns.run is empty"
upper() { echo "$1" | tr 'a-f' 'A-F'; }
hits=0
check() { # check WHAT NEEDLE
    [ -n "$2" ] || return 0
    if grep -F -l -- "$2" $OUTS > "$T/hit" 2>/dev/null; then
        hits=$((hits + 1)); fail "secret: $1 found in: $(tr '\n' ' ' < "$T/hit")"; grep -F -h -- "$2" $OUTS | head -2 | cut -c1-200 | sed 's/^/        /'
    fi
}
for c in "$C_XFR" "$C_UPD" "$C_CTL" "$C_COOKIE" "$C_PLUG" "$C_PG"; do
    check "canary '$c' (raw)" "$c"
    check "canary '$c' (base64)" "$(b64 "$c")"
    h=$(hex "$c"); check "canary '$c' (hex)" "$h"; check "canary '$c' (HEX)" "$(upper "$h")"
done
NM=0
for m in $(sort -u "$T/macs"); do
    NM=$((NM + 1))
    check "a MAC of a signed answer (base64)" "$m"
    mh=$(printf '%s' "$m" | openssl base64 -d -A 2>/dev/null | od -An -tx1 | tr -d ' \n'); check "a MAC (hex)" "$mh"; check "a MAC (HEX)" "$(upper "$mh")"
done
[ "$NM" -ge 3 ] && pass "secrets: $NM MACs of signed answers were searched for" || fail "secrets: only $NM MACs were taken from the dag output"
[ -s "$T/servercookie" ] && { check "the full client+server cookie" "$(cat "$T/servercookie")"; check "the server cookie" "$(cut -c17- "$T/servercookie")"; }
[ "$hits" = 0 ] && pass "secrets: no canary (raw, base64, hex), MAC or server cookie in any output" || true
if grep -lE "AddressSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$T"/p.log "$T"/s.log "$T"/g.log >/dev/null 2>&1; then
    fail "a sanitizer report in a server's stderr"; grep -hE -A8 "Sanitizer|runtime error:" "$T"/p.log "$T"/s.log "$T"/g.log | head -30
fi

echo "== $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
