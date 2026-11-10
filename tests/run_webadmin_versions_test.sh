#!/bin/sh
# run_webadmin_versions_test.sh - karidns-webadmin (webadmin/, 0.6.0 items D and E, milestone M4: zone versions and templates) on SQLite3, with a running karidns.
#
# A real karidns (as root, dropping to nobody) with its loader serves example.test and signed.test (kept by the signer: the metadata X-KARIDNS-SIGNER) from a SQLite3
# file; the API runs as root on a real port with the real karidns-zone and karicheck and a RESTRICTED control key (allow-commands { reload-zone; }) for karictl.
# webadmin/test/it_versions.mjs then, through HTTP, SQL and `dag`: the operator's import is version 1; changes through the API are versions (who, when, the delta, the
# diff of two versions and against the zone); a rollback is a new change set (a subdomain master restores its own names, a domain master cannot restore the apex, a
# conflict with something done outside the versions is 409 and `force` restores anyway, a rollback of a rollback); the marker for changes outside the versions (what
# SQL did, not what the signer does); a zone the signer keeps signed (rollback is unsigned data, no reload from the API); templates (karicheck refuses a broken one),
# a zone made from a template (the day as serial, the version names the template) and a template applied to a zone and rolled back.
# Environment: ZONE (default ./karidns-zone), KARICHECK, KARIDNS, LOADER, NODE.  Needs root; SKIP (exit 0, with the reason) otherwise and without node 22.13, the
# sqlite3 tool, the user nobody or a binary.  About 1 minute (SQLite3's audit log and versions have the resolution of a second: the scenario waits).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
ZONE=${ZONE:-$ROOT/karidns-zone}
KARICHECK=${KARICHECK:-$ROOT/karicheck}
KARIDNS=${KARIDNS:-$ROOT/karidns}
LOADER=${LOADER:-$ROOT/karidns-dbloader}
for v in ZONE KARICHECK KARIDNS LOADER; do eval "p=\$$v"; case $p in /*) ;; *) eval "$v=$ROOT/\${p#./}" ;; esac; done
[ "$(id -u)" = "0" ] || { echo "SKIP: needs root (the server drops to nobody; the loader must be root-owned)"; exit 0; }
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
for b in "$ZONE" "$KARICHECK" "$KARIDNS" "$LOADER" ./dag ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_webadmin_v.XXXXXX") || exit 1
chmod 755 "$T"
SRV=""; WEB=""
cleanup() {
    [ -n "${SG:-}" ] && kill -TERM "$SG" 2>/dev/null
    [ -n "$WEB" ] && kill -TERM "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "${SG:-}" ] && kill -KILL "$SG" 2>/dev/null
    [ -n "$WEB" ] && kill -KILL "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

mkdir "$T/db"; chmod 777 "$T/db"
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
cat > "$T/signed.test.zone" <<'EOF'
$ORIGIN signed.test.
$TTL 300
@ IN SOA ns1 hostmaster 5 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 198.51.100.1
www IN A 192.0.2.20
EOF
cat > "$T/real.test.zone" <<'EOF'
$ORIGIN real.test.
$TTL 300
@ IN SOA ns1 hostmaster 5 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 198.51.100.1
www IN A 192.0.2.2
EOF
for z in example signed real; do
    "$ZONE" import --no-config --sqlite3 "$DB" "$z.test" "$T/$z.test.zone" > "$T/import.out" 2>&1 && ok "$z.test is imported (version 1)" || bad "import of $z" "$(cat "$T/import.out")"
done
sqlite3 "$DB" "INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'X-KARIDNS-SIGNER', '1' FROM domains WHERE name = 'signed.test'"
chmod 666 "$DB"*

# ---------------------------------------------------------------- karidns, its loader, the control keys
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
WPORT=$(kari_port 1 $((PORT + 1)))
b64() { printf '%s' "$1" | openssl base64 -A; }
MAIN_SECRET=$(b64 "vr-test-main-secret-0123456789abc")
WEB_SECRET=$(b64 "vr-test-web-secret-0123456789abcd")
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
printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T/ctl.sock" "$WEB_SECRET" > "$T/web-karictl.conf"
chmod 600 "$T/web-karictl.conf"
"$KARIDNS" -c "$T/karidns.conf" -f > "$T/karidns.log" 2>&1 &
SRV=$!
if kari_wait_log "$T/karidns.log" "\[DB\] initial load complete" 30; then ok "karidns is up, the startup batch is complete"; else bad "karidns did not load the zones" "$(tail -20 "$T/karidns.log")"; exit 1; fi

# ---------------------------------------------------------------- the API
CONF=$T/karidns-webadmin.conf
cat > "$CONF" <<EOF
listen = 127.0.0.1:$WPORT
public-origin = http://127.0.0.1:$WPORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
totp-key-file = $T/totp.key
karidns-zone = $ZONE
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
$APP --check > "$T/check.out" 2> "$T/check.err" && ok "--check is fine" || bad "--check" "$(cat "$T/check.err" "$T/check.out")"
$APP --create-admin admin > "$T/admin.out" 2> "$T/admin.err" || bad "--create-admin" "$(cat "$T/admin.err")"
ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$T/admin.out")
$APP >> "$T/server.log" 2>&1 &
WEB=$!
i=0
while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$T/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
if grep -q "karidns-webadmin [^ ]* started" "$T/server.log"; then ok "the API started (pid $WEB)"; else bad "the API did not start" "$(cat "$T/server.log")"; exit 1; fi

# the real karidns-signer (BIND's dnssec tools): it signs real.test when the API files the key request, and asks karidns to reload with the restricted key
SG_ENV=""
SG=""
if command -v dnssec-keygen >/dev/null 2>&1 && command -v dnssec-signzone >/dev/null 2>&1 && command -v dnssec-verify >/dev/null 2>&1 && [ -f signer/bin/karidns-signer.js ]; then
    mkdir -p "$T/bt" "$T/work" "$T/tmp"; chmod 700 "$T/work"
    for t in dnssec-keygen dnssec-signzone dnssec-verify; do ln -sf "$(command -v $t)" "$T/bt/$t"; done
    cat > "$T/signer.conf" <<EOF
database = sqlite3
sqlite-file = $DB
karictl-config = $T/web-karictl.conf
work-dir = $T/work
karidns-zone = $ZONE
karicheck = $KARICHECK
karictl = $ROOT/karictl
bind-tools = $T/bt
validity = 1h
refresh = 20m
jitter = 2m
debounce = 2
timeout = 120
log = stderr
EOF
    $NODE "$ROOT/signer/bin/karidns-signer.js" -c "$T/signer.conf" >> "$T/signer.log" 2>&1 &
    SG=$!
    i=0
    while [ $i -lt 100 ] && ! grep -q "karidns-signer [^ ]* started" "$T/signer.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    if grep -q "karidns-signer [^ ]* started" "$T/signer.log"; then ok "karidns-signer started (pid $SG)"; SG_ENV=1; else bad "karidns-signer did not start" "$(cat "$T/signer.log")"; fi
else
    echo "  (no real signer: BIND's dnssec-keygen, dnssec-signzone and dnssec-verify and signer/ are needed; the signer's writes are only simulated with SQL)"
fi

# SQL behind the API's back: what the signer, a script or an operator with sqlite3 does
printf '#!/bin/sh\nexec sqlite3 "%s"\n' "$DB" > "$T/sql.sh"
chmod 755 "$T/sql.sh"

echo "-- the scenarios (webadmin/test/it_versions.mjs)"
IT_BASE="http://127.0.0.1:$WPORT/api/v1" IT_ORIGIN="http://127.0.0.1:$WPORT" IT_ADMIN_PASSWORD="$ADMIN_PW" IT_DNS_PORT=$PORT IT_DAG="$ROOT/dag" IT_SQL="$T/sql.sh" IT_DB=sqlite IT_SIGNER="$SG_ENV" IT_VERIFY="$T/bt/dnssec-verify" IT_TMP="$T/tmp" \
    "$NODE" webadmin/test/it_versions.mjs > "$T/it.out" 2>&1
IT_RC=$?
cat "$T/it.out"
[ $IT_RC = 0 ] && ok "the integration scenarios (webadmin/test/it_versions.mjs)" || bad "the integration scenarios failed"

echo "-- afterwards"
if [ -n "$SG" ]; then
    kill -TERM "$SG" 2>/dev/null
    i=0; while [ $i -lt 100 ] && kill -0 "$SG" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    if kill -0 "$SG" 2>/dev/null; then bad "the signer did not stop after SIGTERM"; kill -KILL "$SG" 2>/dev/null; else wait "$SG" 2>/dev/null; [ $? = 0 ] && ok "the signer stops on SIGTERM with status 0" || bad "the signer stopped with a status"; fi
    SG=""
    if grep -q "unexpected error\|Unhandled\|TypeError" "$T/signer.log"; then bad "the signer logged an unexpected error" "$(grep 'unexpected error\|Unhandled\|TypeError' "$T/signer.log" | head -3)"; else ok "the signer logged no unexpected error"; fi
fi
kill -TERM "$WEB" 2>/dev/null
i=0; while [ $i -lt 100 ] && kill -0 "$WEB" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$WEB" 2>/dev/null; then bad "the API did not stop after SIGTERM"; kill -KILL "$WEB" 2>/dev/null; else wait "$WEB" 2>/dev/null; [ $? = 0 ] && ok "the API stops on SIGTERM with status 0" || bad "the API stopped with a status"; fi
WEB=""
grep -q "(a bug)" "$T/server.log" && bad "row level security refused what the API had allowed" "$(grep '(a bug)' "$T/server.log" | head -3)" || ok "the API never logged a disagreement with the database"
grep -Eq '^[^ ]+ error ' "$T/server.log" && bad "the API logged an error" "$(grep ' error ' "$T/server.log" | head -3)" || ok "the API logged no error"
if grep -Eq 'Sunrise-Harbor|Maple-Anchor|karidns_session=|\$scrypt\$|kdt_|zone_text|192\.0\.2\.250' "$T/server.log"; then bad "the log holds a password, cookie, hash, token or request data"; else ok "the log holds no password, cookie, hash, token or record data"; fi
[ "$(sqlite3 "$DB" 'SELECT count(*) FROM karidns_audit_actor')" = 0 ] && [ "$(sqlite3 "$AUTH" 'SELECT count(*) FROM karidns_auth_actor')" = 0 ] && ok "no actor row is left in either file" || bad "an actor row is left"
[ "$(sqlite3 "$DB" "SELECT count(*) FROM karidns_zone_versions v JOIN domains d ON d.id = v.domain_id WHERE d.name = 'example.test' AND v.kind = 'rollback' AND v.rollback_of IS NOT NULL")" -ge 3 ] && ok "the rollbacks are versions of kind rollback with the version they restore" || bad "the rollback versions are not in the database"
grep -q "ERROR\|assertion\|Assertion" "$T/karidns.log" && bad "karidns logged an error" "$(grep 'ERROR\|ssertion' "$T/karidns.log" | head -3)" || ok "karidns logged no error"

echo
echo "=== run_webadmin_versions_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]
