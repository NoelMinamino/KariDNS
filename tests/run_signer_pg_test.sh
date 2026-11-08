#!/bin/sh
# run_signer_pg_test.sh - karidns-signer (signer/, 0.6.0 item C) on PostgreSQL, as the signer role (db/karidns_signer_role.pgsql.sql, row level security on),
# with BIND's real dnssec-keygen / dnssec-signzone / dnssec-verify and the npm package `pg`.
#
# The scenarios A to J are those of tests/run_signer_test.sh (tests/lib/signer_lib.sh): first signing by key request for six algorithms, own writes
# are not changes, a change during signing (exit status 3), a change is served only when signed (root), re-signing before expiry, NSEC3 opt-out and KSK + ZSK
# and requests of kind add, a key made by PowerDNS, a broken key, SIGHUP / SIGTERM / kill -9, --check.  What PostgreSQL adds, checked here:
#   P1  the signer's role cannot write an A record (INSERT, UPDATE, DELETE refused or without effect), cannot change or delete a key, cannot touch the
#       requests it did not answer, and the data of the zones it signs is the data that was there;
#   P2  one zone is signed by one instance: a pg_try_advisory_lock held by somebody else keeps the signer off the zone (it is signed when the lock is gone);
#   P3  the reload goes through karidns_reload_requests (written by import --reload in the transaction of the signature);
#   P4  the change log is read through LISTEN karidns_changes: a change is signed within seconds, not after the 30 s poll;
#   P5  the signer's connection string is checked like the loader's (a conninfo file with a wrong mode is refused).
# With root a karidns server on the same database serves the zones (the loader is PostgreSQL's, reload requests make it read a signer zone).
# SKIP (exit 0) when PostgreSQL is not reachable (tests/db/pg_lib.sh), the role may not create roles, the password login over 127.0.0.1 is not accepted,
# node 22 or newer, BIND's dnssec tools, a binary or signer/node_modules (run `npm ci` in signer/) is missing.  About 6 minutes.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/tests/lib_proc.sh"
cd "$ROOT" || exit 1

NODE=${NODE:-node}
command -v "$NODE" >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }
"$NODE" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || { echo "SKIP: node 22 or newer is needed"; exit 0; }
[ -d signer/node_modules/pg ] || { echo "SKIP: signer/node_modules/pg is missing (run npm ci in signer/)"; exit 0; }
for t in dnssec-keygen dnssec-signzone dnssec-verify; do command -v "$t" >/dev/null 2>&1 || { echo "SKIP: $t is not installed"; exit 0; }; done
for b in ./karidns-zone ./karicheck; do [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }; done
./karidns-zone --version | grep -q postgresql || { echo "SKIP: karidns-zone has no PostgreSQL driver"; exit 0; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_signerpg.XXXXXX") || exit 1
chmod 755 "$T"
. "$ROOT/tests/db/pg_lib.sh"
SRV=""; SG_PID=""; ROLE=""
cleanup() {
    [ -n "$SG_PID" ] && sg_kill_tree "$SG_PID"
    [ -n "$SRV" ] && { kill -TERM "$SRV" 2>/dev/null; i=0; while [ $i -lt 100 ] && kill -0 "$SRV" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done; kari_kill_tree "$SRV"; }
    pg_cleanup
    [ -n "$ROLE" ] && psql -X -q -d "$PGMAINT" -c "DROP ROLE IF EXISTS $ROLE" > /dev/null 2>&1
    chmod -R u+rwx "$T" 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT
trap "exit 130" INT TERM
pg_setup signer || exit 0
. "$ROOT/tests/lib/signer_lib.sh"

PASS=0; FAILS=0
ROLE="karidns_test_sg_$$"
PW="pw$$x$(date +%s)"
if ! psql -X -q -d "$PGMAINT" -c "CREATE ROLE $ROLE LOGIN PASSWORD '$PW'" > /dev/null 2>&1; then
    ROLE=""
    echo "SKIP: the PostgreSQL role may not create roles (set KARIDNS_TEST_PG_USER to a user that may)"
    exit 0
fi
PGPORT_=$(pq "SHOW port")
OWNER=$(pq "SELECT current_user")
RCS="host=127.0.0.1 port=$PGPORT_ user=$ROLE password=$PW dbname=$PGDB"
if ! PGCONNECT_TIMEOUT=5 psql -X -q -At "$RCS" -c "SELECT 1" > /dev/null 2>&1; then
    echo "SKIP: the server does not accept a password login of the new role over 127.0.0.1:$PGPORT_ (pg_hba.conf)"
    exit 0
fi

# --- the database: the PowerDNS schema, the extension, the signer role (RLS on for everybody but the owner) -------------------------------------
pf tests/db/pdns_schema.pgsql.sql > /dev/null && pf db/karidns_ext.pgsql.sql > /dev/null || { echo "  [FAIL] cannot create the schema"; exit 1; }
if psql -X -q -At -v ON_ERROR_STOP=1 -v role=$ROLE -v schema=public -f db/karidns_signer_role.pgsql.sql "$PGC" > "$T/role.out" 2>&1; then pass "db/karidns_signer_role.pgsql.sql applies (RLS on)"; else fail "the signer role script" "$(head -5 "$T/role.out")"; exit 1; fi

# the programs the signer runs, and the signer itself, where the user it runs as can read them (as root that is the PostgreSQL user)
cp ./karidns-zone ./karicheck "$T/" && chmod 755 "$T/karidns-zone" "$T/karicheck"
mkdir -p "$T/app/signer" "$T/app/node" && cp -R signer/bin signer/lib signer/package.json signer/node_modules "$T/app/signer/" && cp -R node/lib node/package.json "$T/app/node/" && chmod -R a+rX "$T/app"     # (signer/lib imports ../../node/lib)
SG_APP="$T/app/signer"; SG_ZONE_BIN="$T/karidns-zone"; SG_KARICHECK="$T/karicheck"; SG_KARICTL="$T/karicheck"
mkdir "$T/work"; chmod 700 "$T/work"; chmod 777 "$T/out"             # (out: written by the signer, too: the exports, the signals of the slow dnssec-signzone)
[ -n "$PG_AS" ] && chown "$PG_AS" "$T/work"
printf '%s\n' "$RCS" > "$T/ci_sg"; [ -n "$PG_AS" ] && chown "$PG_AS" "$T/ci_sg"; chmod 600 "$T/ci_sg"
# the connection strings name the server (the loader and karidns-zone get no PG* variables from the environment of a daemon)
PGSOCK=$(pq "SHOW unix_socket_directories" | cut -d, -f1)
CONN="host=$PGSOCK port=$PGPORT_ user=$OWNER dbname=$PGDB"
mkci() { echo "$CONN" > "$1"; [ -n "$PG_AS" ] && chown "$PG_AS" "$1"; chmod 600 "$1"; }
mkci "$T/ci_owner"

dbq() { pq "$1"; }
asu() { as_pg "$@"; }
ZI="as_pg $T/karidns-zone"
ZDB="--no-config --conninfo-file $T/ci_owner"
SG_DBKIND=pg
SG_SIGNED_AT="extract(epoch from signed_at)::bigint"
SG_DUE0="to_timestamp(0)"
SG_TRUE=true; SG_FALSE=false; SG_NOW0="now()"
SG_CONF="$T/signer.conf"; SG_LOG="$T/signer.log"; : > "$SG_LOG"
SG_DBCONF="database = pg
conninfo-file = $T/ci_sg
schema = public"
sg_make_bt
SG_ZONES="[zone fast.test]
validity = 60
refresh = 20
jitter = 5
[zone opt.test]
nsec3-opt-out = yes"
sg_write_conf

# --- the server (root) ----------------------------------------------------------------------------------------------------------------------
SERVER=0
if [ "$(id -u)" = "0" ] && [ -n "$PG_AS" ] && [ -x ./karidns ] && [ -x ./dag ] && [ -x ./karictl ] && [ -x ./karidns-dbloader ] && ./karidns-dbloader --drivers | grep -qx postgresql && id nobody >/dev/null 2>&1; then SERVER=1; fi
[ $SERVER = 0 ] && echo "  (no server part: it needs root, an unprivileged PostgreSQL user, karidns, dag, karictl and a karidns-dbloader with the PostgreSQL driver)"
SG_SERVER=$SERVER
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
qa_dnssec() { ./dag @127.0.0.1 -p "$PORT" "$1" "$2" +dnssec +nohexdump +time=3 +tries=1 2>&1; }
sg_dbstatus() { ./karictl -c "$T/main-karictl.conf" dbstatus 2>&1; }
if [ $SERVER = 1 ]; then
    install -o root -g wheel -m 755 ./karidns-dbloader "$T/karidns-dbloader" 2>/dev/null || { cp ./karidns-dbloader "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
    mkci "$T/ci_loader"
    printf 'socket "%s";\nkey "karictl" { algorithm hmac-sha256; secret "%s"; };\n' "$T/ctl.sock" "$SECRET" > "$T/main-karictl.conf"; chmod 600 "$T/main-karictl.conf"
    cat > "$T/s.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT;
    database { driver postgresql; conninfo-file "$T/ci_loader"; loader-user "$PG_AS"; loader-path "$T/karidns-dbloader"; db-reload-timeout 10; auto-reload yes; poll-interval 1; coalesce 300; };
};
control-channel { socket "$T/ctl.sock"; secret "$SECRET"; };
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

# --- P1: the signer's role -------------------------------------------------------------------------------------------------------------------
echo "== P1: what the signer's role may not do (row level security on)"
sgpsql() { psql -X -q -At "$RCS" -c "$1" 2>&1; }
exid=$(sg_domain_id ex.test)
wwwA=$(dbq "SELECT content FROM records WHERE name = 'www.ex.test' AND type = 'A'")
nrec=$(dbq "SELECT count(*) FROM records WHERE domain_id = $exid AND type NOT IN ('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY')")
nkeys=$(dbq "SELECT count(*) FROM cryptokeys")
OUT=$(sgpsql "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($exid, 'evil.ex.test', 'A', '192.0.2.66', 60)")
sg_has "an A record cannot be inserted" "$OUT" 'row-level security\|permission denied\|violates'
OUT=$(sgpsql "UPDATE records SET content = '192.0.2.67' WHERE name = 'www.ex.test' AND type = 'A'")
sg_eq "the content of an A record cannot be changed (an error or no row)" "$(dbq "SELECT content FROM records WHERE name = 'www.ex.test' AND type = 'A'")" "$wwwA"
sg_eq "...the answer was an error or UPDATE 0" "$([ -z "$OUT" ] || printf '%s' "$OUT" | grep -q 'ERROR\|error\|violates\|only' && echo yes)" yes
OUT=$(sgpsql "DELETE FROM records WHERE name = 'www.ex.test' AND type = 'A'")
sg_eq "an A record cannot be deleted" "$(dbq "SELECT count(*) FROM records WHERE name = 'www.ex.test' AND type = 'A'")" 1
OUT=$(sgpsql "INSERT INTO records (domain_id, name, type, content, ttl) VALUES ($exid, 'ex.test', 'SOA', 'ns1.ex.test hostmaster.ex.test 1 1 1 1 1', 60)")
sg_has "a second SOA cannot be inserted" "$OUT" 'row-level security\|permission denied\|violates\|SOA'
sg_eq "the zone's other data is the data that was there" "$(dbq "SELECT count(*) FROM records WHERE domain_id = $exid AND type NOT IN ('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY')")" "$nrec"
OUT=$(sgpsql "UPDATE cryptokeys SET active = false")
sg_has "a key cannot be changed" "$OUT" 'permission denied'
OUT=$(sgpsql "DELETE FROM cryptokeys")
sg_has "a key cannot be deleted" "$OUT" 'permission denied'
sg_eq "...all keys are there" "$(dbq "SELECT count(*) FROM cryptokeys")" "$nkeys"
OUT=$(sgpsql "UPDATE karidns_key_requests SET kind = 'add', algorithm = 8")
sg_has "a key request cannot be rewritten (only the answer: state, message, done_at)" "$OUT" 'permission denied'
OUT=$(sgpsql "INSERT INTO karidns_key_requests (domain_id, kind) VALUES ($exid, 'add')")
sg_has "...and the signer files none" "$OUT" 'permission denied'
OUT=$(sgpsql "UPDATE domains SET type = 'SLAVE'")
sg_has "a zone cannot be changed" "$OUT" 'permission denied'
sg_eq "the signer reads the keys (it needs them)" "$(sgpsql "SELECT count(*) > 0 FROM cryptokeys WHERE content LIKE 'Private-key-format%'")" t

# --- P3: the reload request ------------------------------------------------------------------------------------------------------------------
echo "== P3: reload requests"
sg_has "import --signer --reload wrote a reload request for ex.test" "$(dbq "SELECT count(*) FROM karidns_reload_requests WHERE zone = 'ex.test'")" '^[1-9]'
sg_eq "...and for every zone the signer signed (the request per signature)" "$([ "$(dbq "SELECT count(DISTINCT zone) FROM karidns_reload_requests")" -ge 8 ] && echo yes)" yes

# --- P4: LISTEN karidns_changes --------------------------------------------------------------------------------------------------------------
echo "== P4: a change is signed within seconds (NOTIFY), not after the 30 s poll"
s0=$(sg_state ex.test signed_serial)
printf '$ORIGIN ex.test.\n$TTL 300\nlisten IN A 192.0.2.111\n' > "$T/z/listen.part"; chmod 644 "$T/z/listen.part"
t0=$(date +%s)
sg_import ex.test "$T/z/listen.part" --mode merge
sg_quiet_wait 28 '[ "$(sg_state ex.test signed_serial)" != "'"$s0"'" ]'
t1=$(date +%s)
sg_eq "ex.test: signed after the change" "$([ "$(sg_state ex.test signed_serial)" != "$s0" ] && echo yes)" yes
sg_eq "...within 15 s of the change ($((t1 - t0)) s)" "$([ $((t1 - t0)) -le 15 ] && echo yes)" yes

# --- P2: one zone, one instance (advisory lock) -----------------------------------------------------------------------------------------------
echo "== P2: a zone that another instance holds is left alone"
exid=$(sg_domain_id ex.test)
( printf "SELECT pg_advisory_lock(hashtextextended('karidns-signer:public:%s', 0));\nSELECT pg_sleep(40);\n" "$exid" | psql -X -q -At "$PGC" > /dev/null 2>&1 ) &
LOCKER=$!
sleep 2
sg_eq "the lock is held by another session" "$(dbq "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted")" 1
s0=$(sg_state ex.test signed_serial)
printf '$ORIGIN ex.test.\n$TTL 300\nlocked IN A 192.0.2.112\n' > "$T/z/locked.part"; chmod 644 "$T/z/locked.part"
sg_import ex.test "$T/z/locked.part" --mode merge
sleep 9
sg_eq "ex.test: not signed while the other instance holds the lock" "$(sg_state ex.test signed_serial)" "$s0"
# end the session that holds the lock; the signer takes the zone when its 30 s wait is over
dbq "SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND granted" > /dev/null
wait "$LOCKER" 2>/dev/null
sg_wait 70 "ex.test: signed once the lock is gone" '[ "$(sg_state ex.test signed_serial)" != "'"$s0"'" ]'
sg_verify ex.test

# --- P5: the conninfo file is checked ---------------------------------------------------------------------------------------------------------
echo "== P5: the connection string file"
chmod 644 "$T/ci_sg"
asu "$NODE" "$SG_APP/bin/karidns-signer.js" --check -c "$SG_CONF" > "$T/check4.out" 2>&1; rc=$?
sg_eq "a conninfo file with mode 0644 is a problem for --check (exit status 1)" "$rc" 1
sg_has "...it says so" "$(cat "$T/check4.out")" 'mode 0644'
chmod 600 "$T/ci_sg"

echo "== the end"
sg_stop
if [ $SERVER = 1 ] && grep -q "killed by signal\|AddressSanitizer\|ThreadSanitizer" "$T/server.log"; then fail "the server or the loader crashed"; fi
if grep -q "unexpected error\|Unhandled\|TypeError" "$SG_LOG"; then fail "the signer logged an unexpected error" "$(grep 'unexpected error\|Unhandled\|TypeError' "$SG_LOG" | head -5)"; else pass "no unexpected error in the signer's log"; fi

echo
if [ "$FAILS" -eq 0 ]; then echo "=== run_signer_pg_test: all $PASS checks passed ==="; exit 0; fi
echo "=== run_signer_pg_test: $FAILS check(s) FAILED ($PASS passed) ==="
exit 1
