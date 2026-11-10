#!/bin/sh
# run_release_roundtrip_test.sh - the pieces of release 0.6.0 together, end to end (SQLite3, and PostgreSQL when a server is reachable).
#
#   1. a BIND zone file is imported into a fresh database with `karidns-zone import`;
#   2. `karidns` serves it from the database (database { }, karidns-dbloader);
#   3. a change set through the karidns-webadmin API (a dry run first, then REPLACE of three RRsets with reload: true): `dag` sees the new data and the
#      raised SOA serial (the same serial as the answer of the API);
#   4. the zone is rolled back through the API (versions/N/rollback of the import): `dag` sees the old data again, the serial is raised once more, and the
#      export of the zone equals the zone file that was imported (SOA aside);
#   5. the AXFR of `karidns` (dag) is the same set of records as `karidns-zone export` of the database, both brought into one canonical form (absolute
#      lower-case names, TTL, class, type, RDATA; sorted), after the change and after the rollback;
#   6. (SQLite3) `karidns-signer` signs another zone of the database by a key request (BIND's dnssec-keygen / dnssec-signzone): the database holds the
#      RRSIGs and the metadata PRESIGNED, and the server answers with RRSIG records when asked with +dnssec.
# SQLite3: the API runs with the restricted control key (allow-commands { reload-zone; }) and reloads through karictl.  PostgreSQL: the API role with row
# level security, the check role, the reload requests of the commit runs (as tests/run_webadmin_write_pg_test.sh); no signer part there (tests/run_signer_pg_test.sh).
# Root runs everything.  Without root there is no server: the same steps are checked through the database (the export of the zone, the answers of the API);
# the steps that need DNS answers and the PostgreSQL part are SKIPped.  SKIP (exit 0, with the reason) without node 22.13, the sqlite3 tool or a binary;
# without BIND's dnssec tools only the signer part is SKIPped.  Environment: ZONE (default ./karidns-zone), KARICHECK, KARIDNS, LOADER, NODE.  About 1 minute.
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
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 13) ? 0 : 1)' || { echo "SKIP: node 22.13 or newer is needed (node:sqlite)"; exit 0; }
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: the sqlite3 command line tool is not installed"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "SKIP: curl is not installed"; exit 0; }
for b in "$ZONE" "$KARICHECK" "$KARIDNS" "$LOADER" ./dag ./karictl; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
"$ZONE" --version | grep -q sqlite3 || { echo "SKIP: $ZONE has no SQLite3 driver"; exit 0; }
"$LOADER" --drivers | grep -qx sqlite3 || { echo "SKIP: $LOADER has no SQLite3 driver"; exit 0; }
ISROOT=0; [ "$(id -u)" = "0" ] && ISROOT=1
if [ $ISROOT = 1 ]; then
    id nobody >/dev/null 2>&1 || { echo "SKIP: no user nobody"; exit 0; }
else
    echo "SKIP: not root: no server, so no DNS answers and no PostgreSQL part (the steps are checked through the database and the API)"
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_roundtrip.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""; WEB=""; SG=""; ROLES=""
stop_all() {
    [ -n "$SG" ] && kill -TERM "$SG" 2>/dev/null
    [ -n "$WEB" ] && kill -TERM "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kill -TERM "$SRV" 2>/dev/null
    sleep 1
    [ -n "$SG" ] && kill -KILL "$SG" 2>/dev/null
    [ -n "$WEB" ] && kill -KILL "$WEB" 2>/dev/null
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    SG=""; WEB=""; SRV=""
}
cleanup() {
    stop_all
    pg_cleanup
    for r in $ROLES; do psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $r" > /dev/null 2>&1; done
    chmod -R u+rwx "$T" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }

# ---------------------------------------------------------------- the zone and the canonical form
cat > "$T/example.test.zone" <<'EOF'
$ORIGIN example.test.
$TTL 300
@ IN SOA ns1 hostmaster 10 7200 3600 1209600 300
@ IN NS ns1
@ IN MX 10 mail
ns1 IN A 192.0.2.1
ns1 IN AAAA 2001:db8::1
mail IN A 192.0.2.40
www IN A 192.0.2.10
www IN A 192.0.2.11
alias IN CNAME www
txt IN TXT "original text"
EOF
cat > "$T/signed.test.zone" <<'EOF'
$ORIGIN signed.test.
$TTL 300
@ IN SOA ns1 hostmaster 5 7200 3600 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.1
www IN A 192.0.2.20
www IN AAAA 2001:db8::20
EOF
# a zone file or an AXFR printed by dag -> "owner ttl IN TYPE rdata", absolute, lower case (one record a line; names inside the RDATA of NS, CNAME, MX and SOA made absolute)
cat > "$T/norm.awk" <<'EOF'
function absn(n) { if (n == "@") return ORIGIN; if (substr(n, length(n)) == ".") return n; return n "." ORIGIN }
function rest(from,   s, k) { s = ""; for (k = from; k <= NF; k++) s = s (k > from ? " " : "") $k; return s }
BEGIN { ORIGIN = origin; TTL = 0 }
/^[ \t]*(;|$)/ { next }
$1 == "$ORIGIN" { ORIGIN = absn($2); next }
$1 == "$TTL" { TTL = $2; next }
{
    i = 1; owner = absn($i); i++
    ttl = TTL; if ($i ~ /^[0-9]+$/) { ttl = $i; i++ }
    if (toupper($i) == "IN") i++
    type = toupper($i); i++
    if (type == "NS" || type == "CNAME") rd = absn($i)
    else if (type == "MX") rd = $i " " absn($(i + 1))
    else if (type == "SOA") rd = absn($i) " " absn($(i + 1)) " " rest(i + 2)
    else rd = rest(i)
    print tolower(owner " " ttl " IN " type " " rd)
}
EOF
norm() { awk -v origin="$1" -f "$T/norm.awk" | sort -u; }
nosoa() { grep -v ' in soa '; }

# ---------------------------------------------------------------- helpers shared by the phases (P: the directory of the phase)
jv() { "$NODE" -e 'const j = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); const v = (new Function("j", "return " + process.argv[2]))(j); console.log(v !== null && typeof v === "object" ? JSON.stringify(v) : v)' "$P/resp.json" "$1"; }
api() {   # METHOD PATH [BODY]: the answer in $P/resp.json, the status in API_CODE
    if [ $# -ge 3 ]; then
        API_CODE=$(curl -s -o "$P/resp.json" -w '%{http_code}' -b "$P/jar" -X "$1" -H "X-KariDNS-CSRF: $CSRF" -H "Origin: http://127.0.0.1:$WPORT" -H 'Content-Type: application/json' -d "$3" "http://127.0.0.1:$WPORT/api/v1$2")
    else
        API_CODE=$(curl -s -o "$P/resp.json" -w '%{http_code}' -b "$P/jar" "http://127.0.0.1:$WPORT/api/v1$2")
    fi
}
dns_now() {   # NAME TYPE: the short answer on one line, sorted
    ./dag @127.0.0.1 -p "$PORT" "$1" "$2" +short +nohexdump +time=2 +tries=1 2>&1 | sort | tr '\n' ' ' | sed 's/ $//'
}
wait_dns() {   # DESCRIPTION NAME TYPE EXPECTED [SECONDS]
    _i=0; _n=$(( ${5:-20} * 5 ))
    while [ $_i -lt $_n ]; do
        _o=$(dns_now "$2" "$3")
        if [ "$_o" = "$4" ]; then ok "$1"; return 0; fi
        sleep 0.2; _i=$((_i + 1))
    done
    bad "$1 (got '$_o', wanted '$4')"; return 1
}
serial_dns() { dns_now example.test SOA | awk '{ print $3 }'; }
serial_db() { zexport example.test | norm example.test. | awk '$4 == "soa" { print $7 }'; }
wait_serial() { _i=0; while [ $_i -lt 100 ]; do [ "$(serial_dns)" = "$2" ] && { ok "$1"; return 0; }; sleep 0.2; _i=$((_i + 1)); done; bad "$1 (got '$(serial_dns)')"; return 1; }
axfr_vs_export() {   # DESCRIPTION: dag's AXFR and the export of the database, canonically
    ./dag @127.0.0.1 -p "$PORT" example.test AXFR +nohexdump +noall +answer 2> /dev/null | norm . > "$P/axfr.n"
    zexport example.test | norm example.test. > "$P/export.n"
    _n=$(wc -l < "$P/export.n" | tr -d ' ')
    if [ "$_n" -lt 5 ]; then bad "$1: the export is too short ($_n lines)" "$(cat "$P/export.n")"
    elif cmp -s "$P/axfr.n" "$P/export.n"; then ok "$1: AXFR and the export are the same $_n records"
    else bad "$1: AXFR ($(wc -l < "$P/axfr.n" | tr -d ' ') records) differs from the export ($_n)" "$(diff "$P/axfr.n" "$P/export.n")"; fi
}

# the steps 2 to 5 on a running karidns (SERVER=1) and API; $1 names the database
scenario() {
    echo "-- $1: the API"
    ADMIN_URL="http://127.0.0.1:$WPORT/api/v1"
    code=$(curl -s -o "$P/resp.json" -w '%{http_code}' -c "$P/jar" -H 'Content-Type: application/json' -d "{\"user\":\"admin\",\"password\":\"$ADMIN_PW\"}" "$ADMIN_URL/auth/login")
    CSRF=$(jv 'j.csrf')
    if [ "$code" = 200 ] && [ -n "$CSRF" ]; then ok "the administrator logs in"; else bad "login (HTTP $code)" "$(cat "$P/resp.json")"; return 1; fi
    api GET /datasets
    DS=$(jv 'j.datasets[0].id || j.datasets[0].name')
    [ -n "$DS" ] && [ "$DS" != undefined ] && ok "dataset '$DS'" || { bad "no dataset" "$(cat "$P/resp.json")"; return 1; }
    ZP="/datasets/$DS/zones/example.test."

    if [ $SERVER = 1 ]; then
        wait_dns "$1: the zone is served from the database (www A)" www.example.test A "192.0.2.10 192.0.2.11" 10
        wait_dns "$1: AAAA of ns1 (2001:db8::/32)" ns1.example.test AAAA "2001:db8::1" 5
        wait_dns "$1: TXT" txt.example.test TXT '"original text"' 5
        SER0=$(serial_dns)
    else
        SER0=$(serial_db)
    fi
    [ -n "$SER0" ] && ok "the serial before the change is $SER0" || { bad "no serial"; return 1; }

    echo "-- $1: a change set"
    CS='"rrsets":[{"name":"www.example.test.","type":"A","changetype":"REPLACE","ttl":300,"records":[{"content":"192.0.2.50"}]},{"name":"new.example.test.","type":"AAAA","changetype":"REPLACE","ttl":300,"records":[{"content":"2001:db8::50"}]},{"name":"txt.example.test.","type":"TXT","changetype":"REPLACE","ttl":300,"records":[{"content":"\"changed by the API\""}]}]'
    api PATCH "$ZP/rrsets" "{\"dry_run\":true,\"comment\":\"dry run\",$CS}"
    if [ "$API_CODE" = 200 ] && [ "$(jv 'j.dry_run')" = true ] && [ "$(jv 'j.diff.length')" = 3 ]; then ok "the dry run shows 3 RRsets and commits nothing"; else bad "dry run (HTTP $API_CODE)" "$(head -c 600 "$P/resp.json")"; fi
    [ $SERVER = 1 ] && same "$1: the dry run changed no answer" "$(dns_now www.example.test A)" "192.0.2.10 192.0.2.11"
    RELOAD=false; [ $SERVER = 1 ] && RELOAD=true
    api PATCH "$ZP/rrsets" "{\"reload\":$RELOAD,\"comment\":\"release roundtrip\",$CS}"
    if [ "$API_CODE" = 200 ] && [ "$(jv 'j.committed')" = true ] && [ "$(jv 'j.diff.length')" = 3 ]; then ok "the change set is committed (3 RRsets)"; else bad "change set (HTTP $API_CODE)" "$(head -c 600 "$P/resp.json")"; return 1; fi
    SER1=$(jv 'j.serial.after')
    same "the API raised the serial by one (RFC 1982)" "$(jv 'j.serial.before')|$SER1" "$SER0|$((SER0 + 1))"
    if [ $SERVER = 1 ]; then
        case $(jv 'j.reload') in requested) ok "the reload was requested" ;; *) bad "reload: $(jv 'j.reload')" ;; esac
        wait_dns "$1: www A is the new address" www.example.test A "192.0.2.50" 20
        wait_dns "$1: the new name is there (2001:db8::50)" new.example.test AAAA "2001:db8::50" 10
        wait_dns "$1: TXT is the new text" txt.example.test TXT '"changed by the API"' 10
        wait_serial "$1: the SOA serial in the answer is the one the API reported ($SER1)" "$SER1"
        axfr_vs_export "$1 after the change"
    else
        same "the serial in the export" "$(serial_db)" "$SER1"
        zexport example.test | norm example.test. | grep -q '^www.example.test. 300 in a 192.0.2.50$' && ok "the export has the new address" || bad "the export lacks the new address"
    fi

    echo "-- $1: the rollback"
    api GET "$ZP/versions"
    V1=$(jv 'j.versions.filter(v => v.kind === "import").map(v => v.version).pop()')
    NV=$(jv 'j.versions.length')
    if [ -n "$V1" ] && [ "$V1" != undefined ] && [ "$NV" -ge 2 ]; then ok "the history has $NV versions, the import is version $V1"; else bad "versions" "$(head -c 600 "$P/resp.json")"; return 1; fi
    same "the newest version is the change set (kind edit, comment kept)" "$(jv 'j.versions[0].kind + "|" + j.versions[0].comment')" "edit|release roundtrip"
    api POST "$ZP/versions/$V1/rollback" '{"dry_run":true}'
    if [ "$API_CODE" = 200 ] && [ "$(jv 'j.dry_run')" = true ] && [ "$(jv 'j.diff.length')" = 3 ]; then ok "the dry run of the rollback restores 3 RRsets"; else bad "rollback dry run (HTTP $API_CODE)" "$(head -c 600 "$P/resp.json")"; fi
    api POST "$ZP/versions/$V1/rollback" "{\"comment\":\"back to the import\",\"reload\":$RELOAD}"
    if [ "$API_CODE" = 200 ] && [ "$(jv 'j.committed')" = true ] && [ "$(jv 'j.rollback_of')" = "$V1" ]; then ok "the rollback to version $V1 is committed"; else bad "rollback (HTTP $API_CODE)" "$(head -c 600 "$P/resp.json")"; return 1; fi
    SER2=$(jv 'j.serial.after')
    same "the rollback raised the serial again" "$SER2" "$((SER1 + 1))"
    if [ $SERVER = 1 ]; then
        wait_dns "$1: www A is the old pair again" www.example.test A "192.0.2.10 192.0.2.11" 20
        wait_dns "$1: the name added by the change set is gone" new.example.test AAAA "" 10
        wait_dns "$1: TXT is the original text" txt.example.test TXT '"original text"' 10
        wait_serial "$1: the SOA serial in the answer is the one of the rollback ($SER2)" "$SER2"
        axfr_vs_export "$1 after the rollback"
    else
        same "the serial in the export" "$(serial_db)" "$SER2"
    fi
    norm example.test. < "$T/example.test.zone" | nosoa > "$P/orig.n"
    zexport example.test | norm example.test. | nosoa > "$P/back.n"
    if cmp -s "$P/orig.n" "$P/back.n"; then ok "$1: after the rollback the export equals the imported zone file ($(wc -l < "$P/orig.n" | tr -d ' ') records, SOA aside)"; else bad "$1: the export differs from the imported zone file" "$(diff "$P/orig.n" "$P/back.n")"; fi
    api GET "$ZP/versions"
    same "the history now ends with the rollback (kinds, newest first)" "$(jv 'j.versions.map(v => v.kind).slice(0, 3).join(",")')" "rollback,edit,import"
}

# ---------------------------------------------------------------- SQLite3
phase_sqlite() {
    echo "== SQLite3"
    P=$T/sq; mkdir "$P" "$P/db" "$P/work"; chmod 755 "$P"; chmod 777 "$P/db"; chmod 700 "$P/work"
    DB=$P/db/zones.sqlite3; AUTH=$P/auth.sqlite3
    ZR="$ZONE"
    zimport() { "$ZR" import --no-config --sqlite3 "$DB" "$1" "$2"; }
    zexport() { "$ZR" export --no-config --sqlite3 "$DB" "$1"; }
    sqlite3 "$DB" < tests/db/pdns_schema.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_ext.sqlite3.sql > /dev/null && sqlite3 "$DB" < db/karidns_audit.sqlite3.sql > /dev/null || { bad "cannot make the zone file"; return 1; }
    sqlite3 "$AUTH" < db/karidns_auth.sqlite3.sql > /dev/null || { bad "cannot make the auth file"; return 1; }
    chmod 600 "$AUTH"; chmod 666 "$DB"
    for z in example signed; do
        zimport "$z.test" "$T/$z.test.zone" > "$P/import.out" 2>&1 && ok "$z.test is imported (karidns-zone import)" || bad "import of $z.test" "$(cat "$P/import.out")"
    done
    chmod 666 "$DB"*
    zexport example.test | norm example.test. | nosoa > "$P/exp0.n"
    norm example.test. < "$T/example.test.zone" | nosoa > "$P/orig0.n"
    cmp -s "$P/exp0.n" "$P/orig0.n" && ok "the export of the fresh database equals the zone file" || bad "the export differs from the zone file" "$(diff "$P/orig0.n" "$P/exp0.n")"

    PORT=$(kari_port 0 $((20000 + $$ % 20000)))
    WPORT=$(kari_port 1 $((PORT + 1)))
    b64() { printf '%s' "$1" | openssl base64 -A; }
    WEB_SECRET=$(b64 "rt-test-web-secret-0123456789abcd")
    SIG_SECRET=$(b64 "rt-test-sig-secret-0123456789abcd")
    printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$P/ctl.sock" "$WEB_SECRET" > "$P/web-karictl.conf"
    printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$P/ctl.sock" "$SIG_SECRET" > "$P/sig-karictl.conf"
    chmod 600 "$P/web-karictl.conf" "$P/sig-karictl.conf"
    SERVER=$ISROOT
    if [ $SERVER = 1 ]; then
        install -o root -g wheel -m 755 "$LOADER" "$P/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$P/karidns-dbloader"; chown 0:0 "$P/karidns-dbloader"; chmod 755 "$P/karidns-dbloader"; }
        MAIN_SECRET=$(b64 "rt-test-main-secret-0123456789abc")
        cat > "$P/karidns.conf" <<EOF
options {
    user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    allow-transfer { 127.0.0.1; };
    database { driver sqlite3; database-file "$DB"; loader-user "nobody"; loader-path "$P/karidns-dbloader"; db-reload-timeout 10; };
};
key "web" { algorithm hmac-sha256; secret "$WEB_SECRET"; };
key "signer" { algorithm hmac-sha256; secret "$SIG_SECRET"; };
control-channel {
    socket "$P/ctl.sock";
    secret "$MAIN_SECRET";
    keys { "web" read-only yes allow-commands { reload-zone; }; "signer" read-only yes allow-commands { reload-zone; }; };
};
EOF
        chmod 644 "$P/karidns.conf"
        "$KARIDNS" -c "$P/karidns.conf" -f > "$P/karidns.log" 2>&1 &
        SRV=$!
        if kari_wait_log "$P/karidns.log" "\[DB\] initial load complete" 30; then ok "karidns is up, the startup batch is complete"; else bad "karidns did not load the zones" "$(tail -20 "$P/karidns.log")"; return 1; fi
    fi

    CONF=$P/karidns-webadmin.conf
    {
        cat <<EOF
listen = 127.0.0.1:$WPORT
public-origin = http://127.0.0.1:$WPORT
database = sqlite3
sqlite-file = $DB
auth-file = $AUTH
totp-key-file = $P/totp.key
karidns-zone = $ZONE
karicheck = $KARICHECK
karictl = $ROOT/karictl
scrypt-ln = 14
require-totp = none
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr
EOF
        [ $SERVER = 1 ] && echo "karictl-config = $P/web-karictl.conf"
    } > "$CONF"
    APP="$NODE $ROOT/webadmin/bin/karidns-webadmin.js -c $CONF"
    $APP --check > "$P/check.out" 2> "$P/check.err" && ok "karidns-webadmin --check is fine" || bad "--check" "$(cat "$P/check.err" "$P/check.out")"
    $APP --create-admin admin > "$P/admin.out" 2> "$P/admin.err" || bad "--create-admin" "$(cat "$P/admin.err")"
    ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$P/admin.out")
    $APP >> "$P/server.log" 2>&1 &
    WEB=$!
    i=0
    while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$P/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    grep -q "karidns-webadmin [^ ]* started" "$P/server.log" && ok "the API started (pid $WEB)" || { bad "the API did not start" "$(cat "$P/server.log")"; return 1; }

    scenario SQLite3 || return 1
    phase_signer
    logs_clean
    stop_all
}

# the signer on the SQLite3 database: another zone of the same database, a key request, BIND's tools
phase_signer() {
    echo "-- SQLite3: karidns-signer"
    for t in dnssec-keygen dnssec-signzone dnssec-verify; do command -v $t >/dev/null 2>&1 || { echo "SKIP: $t is not installed (the signer part)"; return 0; }; done
    cat > "$P/signer.conf" <<EOF
database = sqlite3
sqlite-file = $DB
karictl-config = $P/sig-karictl.conf
work-dir = $P/work
workers = 1
karidns-zone = $ZONE
karicheck = $KARICHECK
karictl = $ROOT/karictl
bind-tools = $(dirname "$(command -v dnssec-signzone)")
validity = 1h
refresh = 20m
jitter = 2m
debounce = 2
timeout = 120
log = stderr
EOF
    chmod 644 "$P/signer.conf"
    if [ $SERVER = 1 ]; then same "signed.test is served unsigned before the request" "$(./dag @127.0.0.1 -p "$PORT" www.signed.test A +dnssec +noall +answer +nohexdump | grep -c RRSIG)" 0; fi
    $NODE "$ROOT/signer/bin/karidns-signer.js" --check -c "$P/signer.conf" > "$P/sg.check" 2>&1 && ok "karidns-signer --check is fine" || bad "signer --check" "$(cat "$P/sg.check")"
    sqlite3 "$DB" "INSERT INTO karidns_key_requests (domain_id, kind, algorithm) SELECT id, 'enable', 13 FROM domains WHERE name = 'signed.test'" && chmod 666 "$DB"*
    $NODE "$ROOT/signer/bin/karidns-signer.js" -c "$P/signer.conf" >> "$P/signer.log" 2>&1 &
    SG=$!
    i=0; st=""
    while [ $i -lt 240 ]; do
        st=$(sqlite3 "$DB" "SELECT state FROM karidns_key_requests ORDER BY id DESC LIMIT 1")
        case $st in done|failed) break ;; esac
        sleep 0.5; i=$((i + 1))
    done
    if [ "$st" = done ]; then ok "the key request is done"; else bad "the key request is '$st'" "$(sqlite3 "$DB" 'SELECT message FROM karidns_key_requests'; tail -5 "$P/signer.log")"; fi
    same "the metadata PRESIGNED is set" "$(sqlite3 "$DB" "SELECT content FROM domainmetadata m JOIN domains d ON d.id = m.domain_id WHERE d.name = 'signed.test' AND m.kind = 'PRESIGNED'")" 1
    NR=$(zexport signed.test | grep -c RRSIG)
    [ "$NR" -ge 4 ] && ok "the export of the database holds $NR RRSIG records" || bad "RRSIGs in the export: $NR"
    zexport signed.test > "$P/signed.export"
    "$KARICHECK" zone signed.test "$P/signed.export" > "$P/kc.out" 2>&1 && ok "karicheck accepts the signed zone" || bad "karicheck zone of the signed export" "$(tail -5 "$P/kc.out")"
    if [ $SERVER = 1 ]; then
        i=0; n=0
        while [ $i -lt 100 ]; do
            n=$(./dag @127.0.0.1 -p "$PORT" www.signed.test A +dnssec +noall +answer +nohexdump 2>&1 | grep -c RRSIG)
            [ "$n" -gt 0 ] && break
            sleep 0.5; i=$((i + 1))
        done
        [ "$n" -gt 0 ] && ok "the server answers www.signed.test A with +dnssec and an RRSIG" || bad "no RRSIG in the answer" "$(./dag @127.0.0.1 -p "$PORT" www.signed.test A +dnssec +nohexdump 2>&1 | head -12)"
        ./dag @127.0.0.1 -p "$PORT" signed.test DNSKEY +dnssec +noall +answer +nohexdump 2>&1 | grep -q DNSKEY && ok "the DNSKEY RRset is served" || bad "no DNSKEY in the answer"
    fi
    kill -TERM "$SG" 2>/dev/null
    i=0; while [ $i -lt 100 ] && kill -0 "$SG" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    if kill -0 "$SG" 2>/dev/null; then bad "the signer did not stop after SIGTERM"; kill -KILL "$SG" 2>/dev/null; else wait "$SG" 2>/dev/null; [ $? = 0 ] && ok "the signer stops on SIGTERM with status 0" || bad "the signer stopped with a status"; fi
    SG=""
    grep -q "unexpected error\|Unhandled\|TypeError" "$P/signer.log" && bad "the signer logged an unexpected error" "$(grep 'unexpected error\|Unhandled\|TypeError' "$P/signer.log" | head -3)" || ok "no unexpected error in the signer's log"
}

logs_clean() {
    [ -n "$WEB" ] && { kill -TERM "$WEB" 2>/dev/null; i=0; while [ $i -lt 100 ] && kill -0 "$WEB" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done; kill -0 "$WEB" 2>/dev/null && { bad "the API did not stop after SIGTERM"; kill -KILL "$WEB" 2>/dev/null; } || ok "the API stops on SIGTERM"; WEB=""; }
    grep -q "(a bug)" "$P/server.log" && bad "row level security refused what the API had allowed" "$(grep '(a bug)' "$P/server.log" | head -3)" || ok "the API never logged a disagreement with the database"
    grep -Eq '^[^ ]+ error ' "$P/server.log" && bad "the API logged an error" "$(grep ' error ' "$P/server.log" | head -3)" || ok "the API logged no error"
    [ -f "$P/karidns.log" ] && { grep -q "ERROR\|assertion\|Assertion" "$P/karidns.log" && bad "karidns logged an error" "$(grep 'ERROR\|ssertion' "$P/karidns.log" | head -3)" || ok "karidns logged no error"; }
}

# ---------------------------------------------------------------- PostgreSQL
phase_pg() {
    echo "== PostgreSQL"
    if [ $ISROOT != 1 ]; then echo "SKIP: PostgreSQL part needs root (the loader and the API run as an unprivileged PostgreSQL user)"; return 0; fi
    [ -d webadmin/node_modules/pg ] || { echo "SKIP: webadmin/node_modules/pg is missing (run npm ci --ignore-scripts in webadmin/)"; return 0; }
    "$ZONE" --version | grep -q postgresql || { echo "SKIP: $ZONE has no PostgreSQL driver"; return 0; }
    "$LOADER" --drivers | grep -qx postgresql || { echo "SKIP: $LOADER has no PostgreSQL driver"; return 0; }
    pg_setup roundtrip || return 0
    [ -n "$PG_AS" ] || { echo "SKIP: no unprivileged PostgreSQL user (the loader and the API cannot run as root); set KARIDNS_TEST_PG_USER"; return 0; }
    P=$T/pg; mkdir "$P"; chmod 755 "$P"
    RA=krt_api_$$; RK=krt_chk_$$; ROLES="$RA $RK"
    PW="pw$$x$(date +%s)"
    if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE $RA LOGIN PASSWORD '$PW'" -c "CREATE ROLE $RK LOGIN PASSWORD '$PW'" > /dev/null 2>&1; then
        echo "SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"; return 0
    fi
    PORT_PG=$(pq "SHOW port"); OWNER=$(pq "SELECT current_user"); PGSOCK=$(pq "SHOW unix_socket_directories" | cut -d, -f1)
    rc_of() { echo "host=127.0.0.1 port=$PORT_PG user=$1 password=$PW dbname=$PGDB"; }
    if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$(rc_of $RA)" -c "SELECT 1" > /dev/null 2>&1; then
        echo "SKIP: the server does not accept a password login over 127.0.0.1:$PORT_PG (pg_hba.conf)"; return 0
    fi
    pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { bad "cannot create the schema"; return 1; }
    rolescript() { psql -X -q -At -v ON_ERROR_STOP=1 -v role="$2" -v schema=public -f "$1" "$PGC" > "$P/role.out" 2>&1 && ok "$3" || bad "$3" "$(head -5 "$P/role.out")"; }
    rolescript db/karidns_api_role.pgsql.sql $RA "the API role script (row level security on)"
    rolescript db/karidns_check_role.pgsql.sql $RK "the check role script"

    mkdir -p "$P/app/webadmin" "$P/app/node" "$P/web"
    cp "$ZONE" "$P/karidns-zone"; cp "$KARICHECK" "$P/karicheck"; cp ./karictl "$P/karictl"; chmod 755 "$P/karidns-zone" "$P/karicheck" "$P/karictl"
    cp -R webadmin/bin webadmin/lib webadmin/ui webadmin/package.json webadmin/node_modules "$P/app/webadmin/" && cp -R node/lib "$P/app/node/" && chmod -R a+rX "$P/app"
    chown "$PG_AS" "$P/web"
    mkci() { printf '%s\n' "$2" > "$1"; chown "$PG_AS" "$1"; chmod 600 "$1"; }
    mkci "$P/ci_owner" "host=$PGSOCK port=$PORT_PG user=$OWNER dbname=$PGDB"
    mkci "$P/ci_api" "$(rc_of $RA)"
    mkci "$P/ci_check" "$(rc_of $RK)"
    pg_conninfo_file "$P/ci_loader"
    chmod 644 "$T"/*.zone
    ZR="$P/karidns-zone"
    zimport() { as_pg "$ZR" import --no-config --conninfo-file "$P/ci_owner" "$1" "$2"; }
    zexport() { as_pg "$ZR" export --no-config --conninfo-file "$P/ci_owner" "$1"; }
    zimport example.test "$T/example.test.zone" > "$P/import.out" 2>&1 && ok "example.test is imported (karidns-zone import)" || bad "import of example.test" "$(cat "$P/import.out")"
    zexport example.test | norm example.test. | nosoa > "$P/exp0.n"
    norm example.test. < "$T/example.test.zone" | nosoa > "$P/orig0.n"
    cmp -s "$P/exp0.n" "$P/orig0.n" && ok "the export of the fresh database equals the zone file" || bad "the export differs from the zone file" "$(diff "$P/orig0.n" "$P/exp0.n")"

    PORT=$(kari_port 2 $((20000 + $$ % 20000 + 2)))
    WPORT=$(kari_port 3 $((PORT + 1)))
    SERVER=1
    install -o root -g wheel -m 755 "$LOADER" "$P/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$P/karidns-dbloader"; chown 0:0 "$P/karidns-dbloader"; chmod 755 "$P/karidns-dbloader"; }
    cat > "$P/karidns.conf" <<EOF
options {
    user "nobody"; group "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    allow-transfer { 127.0.0.1; };
    database { driver postgresql; conninfo-file "$P/ci_loader"; loader-user "$PG_AS"; loader-path "$P/karidns-dbloader"; db-reload-timeout 10; };
};
EOF
    chmod 644 "$P/karidns.conf"
    "$KARIDNS" -c "$P/karidns.conf" -f > "$P/karidns.log" 2>&1 &
    SRV=$!
    if kari_wait_log "$P/karidns.log" "\[DB\] initial load complete" 30; then ok "karidns is up, the startup batch is complete"; else bad "karidns did not load the zones" "$(tail -20 "$P/karidns.log")"; return 1; fi

    CONF=$P/karidns-webadmin.conf
    cat > "$CONF" <<EOF
listen = 127.0.0.1:$WPORT
public-origin = http://127.0.0.1:$WPORT
database = pg
api-conninfo-file = $P/ci_api
check-conninfo-file = $P/ci_check
totp-key-file = $P/web/totp.key
karidns-zone = $P/karidns-zone
karicheck = $P/karicheck
scrypt-ln = 14
require-totp = none
rate-login = 600
rate-api = 5000
rate-write = 5000
log = stderr
EOF
    chmod 644 "$CONF"
    APP="$NODE $P/app/webadmin/bin/karidns-webadmin.js -c $CONF"
    as_pg $APP --check > "$P/check.out" 2> "$P/check.err" && ok "karidns-webadmin --check is fine" || bad "--check" "$(cat "$P/check.err" "$P/check.out")"
    as_pg $APP --create-admin admin --bootstrap-conninfo-file "$P/ci_owner" > "$P/admin.out" 2> "$P/admin.err" || bad "--create-admin" "$(cat "$P/admin.err")"
    ADMIN_PW=$(sed -n 's/^password (shown once): //p' "$P/admin.out")
    rm -f "$P/web/server.pid"
    as_pg sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$P/web/server.pid" $APP >> "$P/server.log" 2>&1 &
    i=0
    while [ $i -lt 100 ] && ! grep -q "karidns-webadmin [^ ]* started" "$P/server.log" 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
    WEB=$(cat "$P/web/server.pid" 2>/dev/null)
    grep -q "karidns-webadmin [^ ]* started" "$P/server.log" && ok "the API started (pid $WEB)" || { bad "the API did not start" "$(cat "$P/server.log")"; return 1; }

    scenario PostgreSQL || return 1
    same "PostgreSQL: the reload requests of the two commit runs are in the database" "$(pq "SELECT count(*) >= 2 FROM karidns_reload_requests WHERE zone = 'example.test'")" t
    logs_clean
    stop_all
}

phase_sqlite
phase_pg

echo
echo "=== run_release_roundtrip_test: $FAILS failed, $PASS passed ==="
[ "$FAILS" = 0 ]
