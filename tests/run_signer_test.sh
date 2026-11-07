#!/bin/sh
# run_signer_test.sh - karidns-signer (signer/, 0.6.0 item C) on SQLite3 with BIND's real dnssec-keygen / dnssec-signzone / dnssec-verify.
#
# The daemon runs against a SQLite3 database; the zone data goes through karidns-zone (export, import --signer), the keys through dnssec-keygen.
# With root a karidns server serves the database (auto-reload, signer-wait yes) and the signer asks it to reload with a restricted control key
# (control-channel { keys { "signer" read-only yes allow-commands { reload-zone; }; }; }).  The scenarios are in tests/lib/signer_lib.sh (shared with
# tests/run_signer_pg_test.sh); the numbering is theirs:
#   A  first signing by key request for the algorithms 13, 8 (NSEC), 10, 14, 15 and 16: signed, the keys stored only afterwards, the metadata,
#      dnssec-verify and karicheck accept what the database exports;
#   B  the signer's own writes (import --signer, the key INSERT) are not changes (no loop); a record merged in without a serial bump is signed and
#      the signatures that are still good are kept;
#   C  a change while a zone is being signed: karidns-zone exits with status 3, the signer signs again at once;
#   D  (root) a change is served only when it is signed (signer-wait), karictl dbstatus names the zone that waits;
#   E  re-signing before expiry (a zone with validity 60 s);
#   F  NSEC3 opt-out, KSK + ZSK, requests of kind add, requests that cannot be done are answered failed;
#   G  a key made by PowerDNS (Private-key-format: v1.2) next to the signer's own, a key that is published only;
#   H  a broken key: failed, the old data is kept, nothing in the work directory, no key material in the log; an operator fixes it and resets next_due;
#   I  SIGHUP, SIGTERM while a zone is signed (finished first, exit 0), kill -9 (key files stay, the next start wipes them);
#   J  karidns-signer --check.
# Runs as any user; the parts that need a server (D, and the reloads) need root and are SKIPped otherwise.  SKIP (exit 0) when node 22.13 or newer,
# BIND's dnssec tools, the sqlite3 command line tool or a binary is missing.  About 4 minutes.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }
for t in dnssec-keygen dnssec-signzone dnssec-verify sqlite3; do command -v "$t" >/dev/null 2>&1 || { echo "SKIP: $t is not installed"; exit 0; }; done
for b in ./karidns-zone ./karicheck ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
./karidns-zone --version | grep -q sqlite3 || { echo "SKIP: karidns-zone has no SQLite3 driver"; exit 0; }
SERVER=0
if [ "$(id -u)" = "0" ]; then
    SERVER=1
    for b in ./karidns ./dag ./karidns-dbloader; do [ -x "$b" ] || { echo "  (no server part: $b is not built)"; SERVER=0; }; done
    [ $SERVER = 1 ] && { ./karidns-dbloader --drivers | grep -qx sqlite3 || { echo "  (no server part: karidns-dbloader has no SQLite3 driver)"; SERVER=0; }; }
    [ $SERVER = 1 ] && { id nobody >/dev/null 2>&1 || { echo "  (no server part: no user nobody)"; SERVER=0; }; }
else
    echo "  (not root: no server, so no check that the zones are served; the reloads fail with a warning)"
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_signer.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""
cleanup() {
    [ -n "$SG_PID" ] && sg_kill_tree "$SG_PID"
    [ -n "$SRV" ] && { kill -TERM "$SRV" 2>/dev/null; i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done; kari_kill_tree "$SRV"; }
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"; fi
}
SG_PID=""
trap cleanup EXIT
trap "exit 130" INT TERM
. "$ROOT/tests/lib/signer_lib.sh"

PASS=0; FAILS=0
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
SSECRET="c2lnbmVyLXNlY3JldC0wMTIzNDU2Nzg5YWJjZGVmMDEyMw=="

# --- the database ---------------------------------------------------------------------------------------------------------------------------
mkdir "$T/db" "$T/work"; chmod 700 "$T/work"
[ $SERVER = 1 ] && { chown nobody "$T/db"; chmod 777 "$T/db"; }
DB="$T/db/p.sqlite3"
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql || { echo "  [FAIL] cannot create the schema"; exit 1; }
[ $SERVER = 1 ] && chmod 666 "$DB"
dbq() { sqlite3 "$DB" "$1"; _rc=$?; [ $SERVER = 1 ] && chmod 666 "$DB"* 2>/dev/null; return $_rc; }
asu() { "$@"; }
ZONE_BIN="$ROOT/karidns-zone"
ZI="$ZONE_BIN"
ZDB="--no-config --sqlite3 $DB"
SG_DBKIND=sqlite3
SG_SIGNED_AT="signed_at"
SG_DUE0="0"
SG_TRUE=1; SG_FALSE=0; SG_NOW0=0
SG_CONF="$T/signer.conf"; SG_LOG="$T/signer.log"; : > "$SG_LOG"
printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T/ctl.sock" "$SSECRET" > "$T/signer-karictl.conf"; chmod 600 "$T/signer-karictl.conf"
SG_DBCONF="database = sqlite3
sqlite-file = $DB
karictl-config = $T/signer-karictl.conf"
sg_make_bt
SG_ZONES="[zone fast.test]
validity = 60
refresh = 20
jitter = 5
[zone opt.test]
nsec3-opt-out = yes"
sg_write_conf

# --- the server (root) ----------------------------------------------------------------------------------------------------------------------
SG_SERVER=$SERVER
qa_dnssec() { ./dag @127.0.0.1 -p "$PORT" "$1" "$2" +dnssec +nohexdump +time=3 +tries=1 2>&1; }
sg_dbstatus() { ./karictl -c "$T/main-karictl.conf" dbstatus 2>&1; }
if [ $SERVER = 1 ]; then
    install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
    printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T/ctl.sock" "$SECRET" > "$T/main-karictl.conf"; chmod 600 "$T/main-karictl.conf"
    cat > "$T/s.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$DB"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; auto-reload yes; poll-interval 1; coalesce 300; };
};
key "signer" { algorithm hmac-sha256; secret "$SSECRET"; };
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; keys { "signer" read-only yes allow-commands { reload-zone; }; }; };
EOF
    chmod 644 "$T/s.conf"
    sg_zone seed.test 1; sg_import seed.test "$T/z/seed.test.zone"
    ./karidns -c "$T/s.conf" -f > "$T/server.log" 2>&1 &
    SRV=$!
    if kari_wait_log "$T/server.log" "\[DB\] initial load complete" 30; then pass "the server started and loaded the database"; else fail "the server did not start"; tail -20 "$T/server.log"; fi
fi

# --- the scenarios ---------------------------------------------------------------------------------------------------------------------------
sg_phase_algorithms
sg_phase_own_writes
sg_phase_changed
sg_phase_served
sg_phase_resign
sg_phase_variants
sg_phase_powerdns_key
sg_phase_broken_key
sg_phase_signals
sg_phase_check

echo "== the signer's reloads"
if [ $SERVER = 1 ]; then
    sg_eq "the restricted key reloaded the zones (no 'karictl reload' failure in the log)" "$(grep -c 'karictl reload .* failed' "$SG_LOG")" 0
    OUT=$(./karictl -c "$T/signer-karictl.conf" stop 2>&1); RC=$?
    if [ $RC -ne 0 ] && printf '%s' "$OUT" | grep -q 'command not allowed for key "signer"'; then pass "the signer's control key may reload a zone and nothing else (stop is refused)"; else fail "the signer's key: rc $RC '$OUT'"; fi
else
    echo "  SKIP: no server"
fi
sg_stop
if [ $SERVER = 1 ] && grep -q "killed by signal\|AddressSanitizer\|ThreadSanitizer" "$T/server.log"; then fail "the server or the loader crashed"; fi
if grep -q "unexpected error\|Unhandled\|TypeError" "$SG_LOG"; then fail "the signer logged an unexpected error" "$(grep 'unexpected error\|Unhandled\|TypeError' "$SG_LOG" | head -5)"; else pass "no unexpected error in the signer's log"; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_signer_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_signer_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
