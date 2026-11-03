#!/bin/sh
# ==============================================================================
# run_xfr_request_shape_test.sh - the shape of an AXFR / IXFR request (RFC 5936 §2.1, RFC 1995 §3)
#
# A transfer request that is not shaped like one is answered with FORMERR and no transfer (RFC 5936 §2.2.1 note e).  The check (xfr_request_shape(),
# dns_wire.c) comes after the TSIG and the ACL (BIND checks the transfer ACL before the IXFR SOA, too) and before the transfer is started or a zone is
# read.  A transfer request has: OPCODE QUERY and RCODE 0; QDCOUNT 1 (one complete question);
# ANCOUNT 0; NSCOUNT 0 (AXFR) or 1 (IXFR: the client's SOA); an Additional section of at most one OPT and one TSIG / SIG(0) (the last RR); and no
# octets after the last counted record.
#
#   - TCP, a zone in memory: the good requests are transferred (plain, with OPT, signed); every malformed one is a FORMERR with no record for a client that may
#     transfer the zone (one that may not, or a zone that does not exist, is REFUSED as before); a malformed request with a good TSIG gets a signed FORMERR, one with a bad TSIG NOTAUTH
#   - a transfer of a class other than IN (CH, ANY, NONE, HS; RFC 5936 §2.1.2: QCLASS is the class of the zone) has no zone: REFUSED, AA=0, before the ACL
#     and the shape check, over TCP and for a UDP IXFR, for a zone in memory and one of the database that is not (nothing is fetched)
#   - UDP IXFR (RFC 1995 §4.2) answers the same malformed requests with FORMERR
#   - the log of category xfer-out names the reason ("bad zone transfer request: malformed request, <why> (FORMERR)")
#   - a zone of the database that is not in memory (D1a): the same FORMERR, and nothing is fetched for it (needs root; SKIP without it)
# Uses tests/tsig_query.pl (core Perl only).
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
BIN_DIR="${BIN_DIR:-$ROOT}"
KARIDNS=${KARIDNS:-$BIN_DIR/karidns}
DAG=${DAG:-$BIN_DIR/dag}
for b in "$KARIDNS" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
perl -MDigest::SHA -MMIME::Base64 -e 1 2>/dev/null || { echo "SKIP: perl lacks Digest::SHA or MIME::Base64"; exit 0; }
TQ="perl $ROOT/tests/tsig_query.pl"

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_xshape.XXXXXX") || exit 1
chmod 755 "$T"
mkdir "$T/logs"; chmod 777 "$T/logs"
SRV=""
stop_srv() {
    [ -n "$SRV" ] && kari_kill_tree "$SRV"
    SRV=""
}
trap 'stop_srv; rm -rf "$T"' EXIT INT TERM
PASS=0; FAILS=0
pass() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
fail() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; }
PORT=$(kari_port 0 $((20000 + $$ % 20000)))
SECRET=$(openssl rand -base64 32)
BADSECRET=$(openssl rand -base64 32)
USER_OPT=""
if [ "$(id -u)" = "0" ]; then USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"; fi

# t NAME ERE ARGS... : one request with tests/tsig_query.pl (TCP unless --udp is among the args) and the first line of the answer must match ERE
# (rcode=N tc= aa= qd= an= ns= ar= opt= tsig=)
t() {
    _n=$1; _w=$2; shift 2
    case " $* " in *" --udp "*) _a=$(echo "$*" | sed 's/--udp//'); _o=$($TQ --port "$PORT" $_a) ;; *) _o=$($TQ --port "$PORT" --tcp "$@") ;; esac
    if echo "$_o" | grep -Eq "$_w"; then pass "$_n ($_o)"; else fail "$_n: got '$_o', expected /$_w/"; fi
}
# the answers: a malformed request is a FORMERR that echoes the first question only (none when QDCOUNT is 0), has no records and AA=0
FE1='^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=[01] '
FE0='^rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=[01] '
XFER='^rcode=0 tc=0 aa=1 qd=1 an=[1-9]'

cat > "$T/ax.zone" <<'EOF'
$TTL 300
$ORIGIN ax.test.
@ IN SOA ns1.ax.test. hostmaster.ax.test. ( 5 3600 600 86400 60 )
@ IN NS ns1.ax.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
EOF
sed 's/ax\.test/kz.test/g' "$T/ax.zone" > "$T/kz.zone"
chmod 644 "$T"/*.zone
cat > "$T/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT };
key "k1" { algorithm hmac-sha256; secret "$SECRET"; };
zone "ax.test" { type master; file "$T/ax.zone"; allow-transfer { 127.0.0.1; }; };
zone "kz.test" { type master; file "$T/kz.zone"; allow-transfer { key "k1"; }; };
logging {
    channel xo { file "$T/logs/xfer.log"; severity debug 1; print-category yes; print-severity yes; };
    category xfer-out { xo; };
    category security { xo; };
};
EOF
"$KARIDNS" -f "$T/k.conf" > "$T/server.log" 2>&1 &
SRV=$!
kari_wait_answer "$DAG" "$PORT" ax.test. || { echo "FAIL: the server did not start"; cat "$T/server.log"; exit 1; }

echo "== TCP, a zone in memory: good requests are transferred"
t "AXFR"                                        "$XFER" --name ax.test --type AXFR
t "AXFR with OPT"                               "$XFER" --name ax.test --type AXFR --edns-version 0
t "IXFR from an old serial"                     "$XFER" --name ax.test --type IXFR --ixfr-serial 1
t "IXFR with OPT"                               "$XFER" --name ax.test --type IXFR --ixfr-serial 1 --edns-version 0
t "IXFR from the current serial (one SOA)"      '^rcode=0 tc=0 aa=1 qd=1 an=1 ns=0' --name ax.test --type IXFR --ixfr-serial 5
t "signed AXFR (allow-transfer { key })"        '^rcode=0 .* an=[1-9].* tsig=ok' --name kz.test --type AXFR --key "k1:$SECRET"
t "signed AXFR with OPT"                        '^rcode=0 .* an=[1-9].* tsig=ok' --name kz.test --type AXFR --edns-version 0 --key "k1:$SECRET"
n=$($DAG @127.0.0.1 -p "$PORT" ax.test AXFR +nohexdump +noall +answer 2>/dev/null | grep -c 'SOA')
[ "$n" = 2 ] && pass "dag AXFR: the opening and the closing SOA" || fail "dag AXFR: $n SOA records"

echo "== TCP: malformed requests are a FORMERR without a transfer"
t "QDCOUNT 0 with a question after the header"  "$FE0" --name ax.test --type AXFR --hdr-qd 0
t "QDCOUNT 2"                                   "$FE1" --name ax.test --type AXFR --second-question
t "QDCOUNT 3 (counts, one question)"            "$FE1" --name ax.test --type AXFR --hdr-qd 3
t "OPCODE NOTIFY with the question of an AXFR"  "$FE1" --name ax.test --type AXFR --opcode 4
t "OPCODE UPDATE with the question of an AXFR"  "$FE1" --name ax.test --type AXFR --opcode 5
t "OPCODE IQUERY with the question of an AXFR"  "$FE1" --name ax.test --type AXFR --opcode 1
t "OPCODE NOTIFY with the question of an IXFR"  "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --opcode 4
t "request RCODE 1"                             "$FE1" --name ax.test --type AXFR --req-rcode 1
t "request RCODE 5 (IXFR)"                      "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --req-rcode 5
t "AXFR with ANCOUNT 1"                         "$FE1" --name ax.test --type AXFR --hdr-an 1
t "IXFR with ANCOUNT 1"                         "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --hdr-an 1
t "AXFR with an Authority record"               "$FE1" --name ax.test --type AXFR --ixfr-serial 1
t "IXFR with NSCOUNT 5 (one record)"            "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --hdr-ns 5
t "IXFR with NSCOUNT 2 (one record)"            "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --hdr-ns 2
t "IXFR without the client's SOA"               "$FE1" --name ax.test --type IXFR
t "IXFR whose Authority record is an NS"        "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --auth-type 2
t "1 octet after the request (AXFR)"            "$FE1" --name ax.test --type AXFR --trailing 1
t "16 octets after the request (AXFR)"          "$FE1" --name ax.test --type AXFR --trailing 16
t "16 octets after the request (AXFR with OPT)" "$FE1" --name ax.test --type AXFR --edns-version 0 --trailing 16
t "16 octets after the request (IXFR)"          "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --trailing 16
t "6000 octets after the request"               "$FE1" --name ax.test --type AXFR --trailing 6000
t "two OPT records"                             "$FE1" --name ax.test --type AXFR --edns-version 0 --second-opt
t "two OPT records (IXFR)"                      "$FE1" --name ax.test --type IXFR --ixfr-serial 1 --edns-version 0 --second-opt

echo "== TCP: the check comes after the TSIG and the ACL (only a client that may transfer sees the FORMERR)"
t "good request, the client may not transfer: REFUSED"      '^rcode=5 ' --name kz.test --type AXFR
t "malformed request, the client may not transfer: REFUSED" '^rcode=5 ' --name kz.test --type AXFR --opcode 4
t "good request, no such zone: REFUSED"                     '^rcode=5 ' --name nx.test --type AXFR
t "malformed request, no such zone: REFUSED" '^rcode=5 ' --name nx.test --type AXFR --req-rcode 3
t "malformed request, the TSIG is good: FORMERR, signed"    '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 .* tsig=ok' --name kz.test --type AXFR --opcode 4 --key "k1:$SECRET"
t "malformed IXFR, the TSIG is good: FORMERR, signed"       '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 .* tsig=ok' --name kz.test --type IXFR --ixfr-serial 1 --auth-type 2 --key "k1:$SECRET"
t "malformed request with OPT, the TSIG is good"            '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=2 .* tsig=ok' --name kz.test --type AXFR --edns-version 0 --req-rcode 1 --key "k1:$SECRET"
t "malformed request, the TSIG key is wrong: NOTAUTH"       '^rcode=9 ' --name kz.test --type AXFR --opcode 4 --key "k1:$BADSECRET"
t "octets after a good TSIG: FORMERR"                       '^rcode=1 ' --name kz.test --type AXFR --trailing 16 --key "k1:$SECRET"

echo "== QCLASS other than IN (RFC 5936 §2.1.2: the class of the zone): no such zone, REFUSED without a transfer"
NA='^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 '
t "AXFR of class CH"                            "$NA" --name ax.test --type AXFR --class 3
t "AXFR of class ANY"                           "$NA" --name ax.test --type AXFR --class 255
t "AXFR of class NONE"                          "$NA" --name ax.test --type AXFR --class 254
t "AXFR of class HS"                            "$NA" --name ax.test --type AXFR --class 4
t "AXFR of class CH with OPT"                   "$NA" --name ax.test --type AXFR --class 3 --edns-version 0
t "IXFR of class CH"                            "$NA" --name ax.test --type IXFR --ixfr-serial 1 --class 3
t "IXFR of class ANY from the current serial"   "$NA" --name ax.test --type IXFR --ixfr-serial 5 --class 255
t "malformed AXFR of class CH: REFUSED, not FORMERR" "$NA" --name ax.test --type AXFR --class 3 --opcode 4
t "signed AXFR of class CH: REFUSED, signed"    '^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 .* tsig=ok' --name kz.test --type AXFR --class 3 --key "k1:$SECRET"
t "UDP IXFR of class CH"                        "$NA" --udp --name ax.test --type IXFR --ixfr-serial 5 --class 3
t "UDP IXFR of class ANY, old serial (no TC)"   "$NA" --udp --name ax.test --type IXFR --ixfr-serial 1 --class 255
t "UDP IXFR of class HS"                        "$NA" --udp --name ax.test --type IXFR --ixfr-serial 5 --class 4
t "the same AXFR of class IN is transferred"    "$XFER" --name ax.test --type AXFR

echo "== UDP IXFR (RFC 1995 §4.2)"
t "IXFR from the current serial"                '^rcode=0 tc=0 aa=1 qd=1 an=1 ns=0' --udp --name ax.test --type IXFR --ixfr-serial 5
t "IXFR from an old serial: TC"                 '^rcode=0 tc=1 ' --udp --name ax.test --type IXFR --ixfr-serial 1
t "UDP: request RCODE 1"                        "$FE1" --udp --name ax.test --type IXFR --ixfr-serial 5 --req-rcode 1
t "UDP: ANCOUNT 1"                              "$FE1" --udp --name ax.test --type IXFR --ixfr-serial 5 --hdr-an 1
t "UDP: NSCOUNT 5 (one record)"                 "$FE1" --udp --name ax.test --type IXFR --ixfr-serial 5 --hdr-ns 5
t "UDP: NSCOUNT 2 (one record)"                 "$FE1" --udp --name ax.test --type IXFR --ixfr-serial 5 --hdr-ns 2
t "UDP: the Authority record is an NS"          "$FE1" --udp --name ax.test --type IXFR --ixfr-serial 5 --auth-type 2
t "UDP: no client SOA"                          "$FE1" --udp --name ax.test --type IXFR
t "UDP: 16 octets after the request"            "$FE1" --udp --name ax.test --type IXFR --ixfr-serial 5 --trailing 16
t "UDP: two OPT records (the query path's own FORMERR)" '^rcode=1 tc=0 aa=0 qd=[01] an=0 ns=0 ' --udp --name ax.test --type IXFR --ixfr-serial 5 --edns-version 0 --second-opt
t "UDP: malformed, the client may not transfer: REFUSED" '^rcode=5 ' --udp --name kz.test --type IXFR --ixfr-serial 5 --req-rcode 1
t "UDP: good, the client may not transfer"      '^rcode=5 ' --udp --name kz.test --type IXFR --ixfr-serial 5

echo "== the log of category xfer-out"
lg() { i=0; while [ $i -lt 50 ]; do grep -q -- "$1" "$T/logs/xfer.log" 2>/dev/null && return 0; sleep 0.2; i=$((i + 1)); done; return 1; }
for why in "OPCODE is not QUERY" "RCODE is not NOERROR" "QDCOUNT is not 1" "ANCOUNT is not 0" "unexpected NSCOUNT" "the IXFR Authority record is not a SOA" \
           "trailing octets after the last record" "request too long" "malformed or unexpected Additional record"; do
    lg "transfer of 'ax.test/IN': bad zone transfer request: malformed request, $why (FORMERR)" && pass "logged: $why" || fail "not logged: $why"
done
lg "transfer of 'ax.test/IN': bad zone transfer request: non-authoritative zone (REFUSED)" && pass "a transfer of another class is logged as a non-authoritative zone" || fail "a transfer of class CH was not logged as non-authoritative"
! grep -q "transfer of 'nx.test/IN': bad zone transfer request: malformed" "$T/logs/xfer.log" && pass "a malformed request for a zone that does not exist is logged as a refusal, not as malformed" || fail "nx.test was logged as malformed"
if grep -qE "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$T/server.log"; then fail "sanitizer report in server.log"; tail -20 "$T/server.log"; else pass "no sanitizer report"; fi
stop_srv

# ------------------------------------------------------------------------------------------------------------------------------
# a zone of the database whose data is not in memory (D1a step 7): the same answers, and nothing is fetched for a malformed request
# ------------------------------------------------------------------------------------------------------------------------------
echo "== a database zone that is not in memory"
LOADER=${LOADER:-$BIN_DIR/karidns-dbloader}
KCTLB=${KCTLB:-$BIN_DIR/karictl}
if [ "$(id -u)" != "0" ]; then echo "SKIP: the database part needs root (the loader runs as another user)"
elif [ ! -x "$LOADER" ] || [ ! -x "$KCTLB" ]; then echo "SKIP: $LOADER or $KCTLB is not built"
elif ! command -v sqlite3 >/dev/null 2>&1; then echo "SKIP: the sqlite3 command line tool is not installed"
elif ! "$LOADER" --drivers | grep -qx sqlite3; then echo "SKIP: $LOADER has no SQLite3 driver"
elif ! id nobody >/dev/null 2>&1; then echo "SKIP: no user nobody"
else
    mkdir "$T/db"
    sqlite3 "$T/db/z.db" < tests/db/pdns_schema.sqlite3.sql > /dev/null
    sqlite3 "$T/db/z.db" <<SQL
INSERT INTO domains (name, type) VALUES ('a.test', 'NATIVE');
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT id, name, 'SOA', 'ns1.' || name || ' host.' || name || ' 5 3600 600 86400 300', 900, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, name, 'NS', 'ns1.' || name, 3600, 0, 0 FROM domains;
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled) SELECT id, 'ns1.' || name, 'A', '192.0.2.53', 600, 0, 0 FROM domains;
WITH RECURSIVE k(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM k WHERE j < 59)
INSERT INTO records (domain_id, name, type, content, ttl, prio, disabled)
  SELECT d.id, 'h' || k.j || '.' || d.name, 'A', printf('10.0.0.%d', k.j + 1), 300, 0, 0 FROM domains d, k;
INSERT INTO domainmetadata (domain_id, kind, content) SELECT id, 'ALLOW-AXFR-FROM', '127.0.0.1' FROM domains;
SQL
    chown -R nobody "$T/db"; chmod 600 "$T/db/z.db"*
    install -o root -g wheel -m 755 "$LOADER" "$T/karidns-dbloader" 2>/dev/null || { cp "$LOADER" "$T/karidns-dbloader"; chown 0:0 "$T/karidns-dbloader"; chmod 755 "$T/karidns-dbloader"; }
    DSECRET="dGVzdC1zZWNyZXQtMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3"
    cat > "$T/karictl.conf" <<EOF
socket "$T/ctl.sock";
key "karictl" { algorithm hmac-sha256; secret "$DSECRET"; };
EOF
    chmod 600 "$T/karictl.conf"
    KCTL="$KCTLB -c $T/karictl.conf"
    cat > "$T/kd.conf" <<EOF
options {
    user "nobody"; pid-file "none"; listen-on { 127.0.0.1; }; port $PORT; notify no;
    database { driver sqlite3; database-file "$T/db/z.db"; loader-user "nobody"; loader-path "$T/karidns-dbloader"; fetch-rate 5000; park-timeout 4000;
               acl-ceiling { 127.0.0.1; }; max-zone-records 200; transfer-fetch-timeout 3000; memory-limit 64m; };
};
control-channel { socket "$T/ctl.sock"; secret "$DSECRET"; };
logging {
    channel xo { file "$T/logs/xfer-db.log"; severity debug 1; print-category yes; print-severity yes; };
    category xfer-out { xo; };
    category security { xo; };
};
EOF
    "$KARIDNS" -c "$T/kd.conf" -f > "$T/srv-db.log" 2>&1 &
    SRV=$!
    i=0
    while [ $i -lt 1800 ] && ! grep -q "\[DB\] initial load complete" "$T/srv-db.log" 2>/dev/null; do sleep 0.1; i=$((i + 1)); done
    grep -q "\[DB\] initial load complete" "$T/srv-db.log" && pass "the startup batch is complete" || { fail "no 'initial load complete'"; tail -20 "$T/srv-db.log"; }
    sleep 1
    issued() { $KCTL dbstatus 2>/dev/null | grep '^fetch:' | sed -n 's/.* issued=\([0-9]*\).*/\1/p' | tail -1; }
    oom() { $KCTL dbstatus "$1" 2>/dev/null | grep -q "out of memory"; }
    oom a.test && pass "a.test starts out of memory" || fail "a.test is in memory at the start"
    I0=$(issued)
    t "DB: AXFR with OPCODE NOTIFY"                  "$FE1" --name a.test --type AXFR --opcode 4
    t "DB: AXFR with 16 octets after the request"    "$FE1" --name a.test --type AXFR --trailing 16
    t "DB: AXFR with ANCOUNT 1"                      "$FE1" --name a.test --type AXFR --hdr-an 1
    t "DB: AXFR with QDCOUNT 0"                      "$FE0" --name a.test --type AXFR --hdr-qd 0
    t "DB: IXFR from the current serial, 16 octets after the request" "$FE1" --name a.test --type IXFR --ixfr-serial 5 --trailing 16
    t "DB: IXFR from the current serial, NSCOUNT 5"  "$FE1" --name a.test --type IXFR --ixfr-serial 5 --hdr-ns 5
    t "DB: IXFR from the current serial, NS record"  "$FE1" --name a.test --type IXFR --ixfr-serial 5 --auth-type 2
    t "DB: IXFR from an old serial, request RCODE 1" "$FE1" --name a.test --type IXFR --ixfr-serial 1 --req-rcode 1
    t "DB: IXFR without the client's SOA"            "$FE1" --name a.test --type IXFR
    t "DB: UDP IXFR from the current serial, RCODE 1" "$FE1" --udp --name a.test --type IXFR --ixfr-serial 5 --req-rcode 1
    t "DB: UDP IXFR from the current serial, trailing" "$FE1" --udp --name a.test --type IXFR --ixfr-serial 5 --trailing 16
    t "DB: AXFR of class CH: REFUSED"                "$NA" --name a.test --type AXFR --class 3
    t "DB: IXFR of class ANY from an old serial: REFUSED" "$NA" --name a.test --type IXFR --ixfr-serial 1 --class 255
    t "DB: UDP IXFR of class CH from the current serial: REFUSED" "$NA" --udp --name a.test --type IXFR --ixfr-serial 5 --class 3
    [ "$(issued)" = "$I0" ] && oom a.test && pass "nothing was fetched for them (issued=$I0), the zone is still out of memory" || fail "a malformed request made the server read the zone (issued $I0 -> $(issued))"
    t "DB: IXFR from the current serial: the one SOA, from the summary" '^rcode=0 tc=0 aa=1 qd=1 an=1 ns=0' --name a.test --type IXFR --ixfr-serial 5
    [ "$(issued)" = "$I0" ] && oom a.test && pass "the summary answered it, nothing was fetched" || fail "the good IXFR read the zone"
    n=$($DAG @127.0.0.1 -p "$PORT" a.test AXFR +nohexdump +noall +answer 2>/dev/null | grep -c 'SOA')
    [ "$n" = 2 ] && pass "DB: AXFR (the zone is read for it): the opening and the closing SOA" || fail "DB: AXFR: $n SOA records"
    lg2() { i=0; while [ $i -lt 50 ]; do grep -q -- "$1" "$T/logs/xfer-db.log" 2>/dev/null && return 0; sleep 0.2; i=$((i + 1)); done; return 1; }
    lg2 "transfer of 'a.test/IN': bad zone transfer request: malformed request, OPCODE is not QUERY (FORMERR)" && pass "logged" || fail "not logged"
    if grep -qE "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$T/srv-db.log"; then fail "sanitizer report in srv-db.log"; tail -20 "$T/srv-db.log"; else pass "no sanitizer report"; fi
    stop_srv
fi

echo "== $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
