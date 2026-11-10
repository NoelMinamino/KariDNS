#!/bin/sh
# run_webadmin_write_test.sh - karidns-webadmin (webadmin/, 0.6.0 items D and E, milestone M3: the write side) on SQLite3, with a running karidns.
#
# A real karidns (as root, dropping to nobody) with its loader serves example.test, other.test and signed.test (kept by the signer: the metadata X-KARIDNS-SIGNER)
# from a SQLite3 file; the API runs as root on a real port with the real karidns-zone (through a wrapper that can change the zone behind the API's back between the
# check run and the commit run) and a RESTRICTED control key (allow-commands { reload-zone; }) for karictl.  webadmin/test/it_write.mjs then, through HTTP and `dag`:
# a change set is in the DNS answer after the reload (not before, without one), a write outside the grant is refused, max_rr, a conflict between the check run and
# the commit run (the API repeats; a zone that changes every time: 409), preconditions, a signer zone that the API does not reload (the operator's karictl does),
# the import, a zone made and deleted (its grants go), metadata, key requests, the audit log, and the cost of a change set of a small and of a zone of 20,000
# records (planning assumption 13.7: the lines "[COST]").
# Environment: ZONE (default ./karidns-zone), KARICHECK, KARIDNS, LOADER, NODE, BIG (records of the big zone, default 20000), ZONES (more, empty zones for the cost of the search in the zone list, default 0).  Needs root; SKIP (exit 0, with the
# reason) otherwise and without node 22.13, the sqlite3 tool, the user nobody or a binary.  About 2 minutes.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
KARIDNS=${KARIDNS:-$ROOT/karidns}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
BIG=${BIG:-20000}
ZONES=${ZONES:-0}
for v in ZONE KARICHECK KARIDNS LOADER; do eval "p=\$$v"; case $p in /*) ;; *) eval "$v=$ROOT/\${p#./}" ;; esac; done
[ "$(id -u)" = "0" ] || { echo "SKIP: needs root (the server drops to nobody; the loader must be root-owned)"; exit 0; }
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
for b in "$ZONE" "$KARICHECK" "$KARIDNS" "$LOADER" ./dag ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_w.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""; WEB=""
cleanup() {
    [ -n "$WEB" ] && kill -TERM "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "$WEB" ] && kill -KILL "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

mkdir "$T/db" "$T/ctl"; chmod 777 "$T/db" "$T/ctl"
DB=$T/db/zones.sqlite3
AUTH=$T/auth.sqlite3
sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the zone file"; exit 1; }
sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { echo "  [FAIL] cannot make the auth file"; exit 1; }
chmod 600 "$AUTH"; chmod 666 "$DB"
cat > "$T/example.test.zone" <<'EOF'
$ORIGIN example.test.
$TTL 300
@ IN SOA ns1 hostmaster 10 7200 3600 1209600 300
@ IN NS ns1
@ IN MX 10 mail
ns1 IN A 192.0.2.1
mail IN A 192.0.2.40
www IN A 192.0.2.10
www IN A 192.0.2.11
sub IN A 192.0.2.20
a.sub IN TXT "hello"
evilsub IN A 192.0.2.30
EOF
for z in other signed; do
    cat > "$T/$z.test.zone" <<EOF
\$ORIGIN $z.test.
\$TTL 300
@ IN SOA ns1 hostmaster 5 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 198.51.100.1
www IN A 192.0.2.20
EOF
done
for z in example other signed; do
    "$ZONE" import --no-config --sqlite3 "$DB" "$z.test" "$T/$z.test.zone" > "$T/import.out" 2>&1 && ok "$z.test is imported" || bad "import of $z" "$(cat "$T/import.out")"
done
sqlite3 "$DB" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = 'signed.test'"
# the zone of the round trip (the text form of the records, item F): every kind of RDATA whose text is not its stored form
"$ZONE" import --no-config --sqlite3 "$DB" rt.test "$ROOT/webadmin/test/rt.test.zone" > "$T/import.out" 2>&1 && ok "rt.test (the round trip zone) is imported" || bad "import of rt.test" "$(cat "$T/import.out")"
chmod 666 "$DB"*

# ---------------------------------------------------------------- karidns, its loader, the control keys
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
WPORT=$(kari_port 1 $((PORT + 1)))
b64() { printf '%s' "$1" | openssl base64 -A; }
MAIN_SECRET=$(b64 "wr-test-main-secret-0123456789abc")
WEB_SECRET=$(b64 "wr-test-web-secret-0123456789abcd")
install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
cat > "$T/karidns.conf" <<EOF
options {
    user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver sqlite3; database-file "$DB"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; };
};
key "web" { algorithm hmac-sha256; secret "$WEB_SECRET"; };
control-channel {
    socket "$T/ctl.sock";
    secret "$MAIN_SECRET";
    keys { "web" read-only yes allow-commands { reload-zone; }; };
};
EOF
chmod 644 "$T/karidns.conf"
printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T/ctl.sock" "$MAIN_SECRET" > "$T/main-karictl.conf"
printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T/ctl.sock" "$WEB_SECRET" > "$T/web-karictl.conf"
chmod 600 "$T/main-karictl.conf" "$T/web-karictl.conf"
"$KARIDNS" -c "$T/karidns.conf" -f > "$T/karidns.log" 2>&1 &
SRV=$!
if kari_wait_log "$T/karidns.log" "\[DB\] initial load complete" 30; then ok "karidns is up, the startup batch is complete"; else bad "karidns did not load the zones" "$(tail -20 "$T/karidns.log")"; exit 1; fi

# ---------------------------------------------------------------- the API
cp "$ZONE" "$T/karidns-zone-real"
cat > "$T/kz" <<EOF
#!/bin/sh
# karidns-zone for the API; the test makes it change example.test behind the API's back between the check run and the commit run
REAL="$T/karidns-zone-real"
if [ -f "$T/ctl/conflict.once" ] || [ -f "$T/ctl/conflict.always" ]; then
    case " \$* " in
    *" --dry-run "*example.test*)
        input=\$(cat)
        out=\$(printf '%s\n' "\$input" | "\$REAL" "\$@"); rc=\$?
        rm -f "$T/ctl/conflict.once"
        printf 'rr noise.example.test. 60 TXT "n%s"\n' "\$(date +%s)\$\$" | "\$REAL" apply --no-config --sqlite3 "$DB" --changes - example.test > /dev/null 2>&1
        echo conflict >> "$T/ctl/wrapper.log"
        printf '%s\n' "\$out"
        exit \$rc ;;
    esac
fi
exec "\$REAL" "\$@"
EOF
chmod 755 "$T/kz"
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
listen = 127.0.0.1:$WPORT
public-origin = http://127.0.0.1:$WPORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
totp-key-file = $T/totp.key
karidns-zone = $T/kz
karicheck = $KARICHECK
karictl = $ROOT/karictl
karictl-config = $T/web-karictl.conf
scrypt-ln = 14
require-totp = none
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr
EOF
APP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $CONF"
$APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine (karictl and its key file included)" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
$APP --create-admin admin > "$T/admin.out" 2> "$T/admin.err" || bad "--create-admin" "$(cat "$T/admin.err")"
ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
$APP >> "$T/server.log" 2>&1 &
WEB=$!
i=0
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
if grep -q "karidns-webadmin [^ ]* started" "$T/server.log"; then ok "the API started (pid $WEB)"; else bad "the API did not start" "$(cat "$T/server.log")"; exit 1; fi

# a big zone, imported by the operator after the server started (it is never loaded: the cost measurement only needs the database)
if [ "$BIG" -gt 0 ]; then
    awk -v n="$BIG" 'BEGIN { print "$ORIGIN big.test."; print "$TTL 300"; print "@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300"; print "@ IN NS ns1"; print "ns1 IN A 192.0.2.1";
        for (i = 0; i < n / 2; i++) printf "h%d IN A 10.%d.%d.%d\ns%d.sub1 IN TXT \"x%d\"\n", i, int(i / 65536) % 256, int(i / 256) % 256, i % 256, i, i }' > "$T/big.zone"
    s=$(date +%s)
    "$ZONE" import --no-config --sqlite3 "$DB" big.test "$T/big.zone" > "$T/import.out" 2>&1 && ok "big.test is imported (about $BIG records, $(( $(date +%s) - s )) s)" || bad "import of big.test" "$(tail -3 "$T/import.out")"
    chmod 666 "$DB"*
fi
# many zones, for the cost of the search in the zone list (zones with no records: the server was told nothing about them); ZONES=10000 for the measurement
if [ "$ZONES" -gt 0 ]; then
    awk -v n="$ZONES" 'BEGIN { print "BEGIN;"; for (i = 0; i < n; i++) printf "INSERT INTO domains (name, type) VALUES (\x27z%04d.bulk.test\x27, \x27NATIVE\x27);\n", i; print "COMMIT;" }' | sqlite3 "$DB" && ok "$ZONES empty zones are in the database" || bad "the empty zones"
    chmod 666 "$DB"*
fi

echo "-- the scenarios (webadmin/test/it_write.mjs)"
IT_BASE="http://127.0.0.1:$WPORT/api/v1" IT_ORIGIN="http://127.0.0.1:$WPORT" IT_ADMIN_PASSWORD="$ADMIN_PW" IT_DNS_PORT=$PORT IT_DAG="$ROOT/dag" IT_DIR="$T/ctl" \
    IT_KARICTL="$ROOT/karictl" IT_KARICTL_CONF="$T/main-karictl.conf" IT_KARICTL_SOCK="$T/ctl.sock" IT_DB=sqlite IT_BIG="$BIG" IT_ZONES="$ZONES" "$NODE" webadmin/test/it_write.mjs > "$T/it.out" 2>&1
IT_RC=$?
cat "$T/it.out"
[ $IT_RC = 0 ] && ok "the integration scenarios (webadmin/test/it_write.mjs)" || bad "the integration scenarios failed"

echo "-- afterwards"
kill -TERM "$WEB" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$WEB" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$WEB" 2>/dev/null; then bad "the API did not stop after SIGTERM"; kill -KILL "$WEB" 2>/dev/null; else wait "$WEB" 2>/dev/null; [ $? = 0 ] && ok "the API stops on SIGTERM with status 0" || bad "the API stopped with a status"; fi
WEB=""
grep -q "(a bug)" "$T/server.log" && bad "row level security refused what the API had allowed" "$(grep '(a bug)' "$T/server.log" | head -3)" || ok "the API never logged a disagreement with the database"
grep -Eq '^[^ ]+ error ' "$T/server.log" && bad "the API logged an error" "$(grep ' error ' "$T/server.log" | head -3)" || ok "the API logged no error"
if grep -Eq 'Sunrise-Harbor|Maple-Anchor|Granite-Pine|karidns_session=|\$scrypt\$|kdt_|zone_text|192\.0\.2\.77' "$T/server.log"; then bad "the log holds a password, cookie, hash, token or request data"; else ok "the log holds no password, cookie, hash, token or record data"; fi
[ "$(sqlite3 "$DB" 'SELECT count(*) FROM karidns_audit_actor')" = 0 ] && [ "$(sqlite3 "$AUTH" 'SELECT count(*) FROM karidns_auth_actor')" = 0 ] && ok "no actor row is left in either file" || bad "an actor row is left"
[ "$(sqlite3 "$DB" "SELECT count(*) FROM karidns_audit_log WHERE principal_name = 'dom' AND change_set IS NOT NULL")" -gt 0 ] && ok "the changes of the domain master are in the audit log under its name and a change set" || bad "no audit row names the domain master"
grep -q "ERROR\|assertion\|Assertion" "$T/karidns.log" && bad "karidns logged an error" "$(grep 'ERROR\|ssertion' "$T/karidns.log" | head -3)" || ok "karidns logged no error"

echo
echo "=== run_webadmin_write_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]
