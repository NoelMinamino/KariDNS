#!/bin/sh
# ==============================================================================
# run_formerr_bind_compat_test.sh - error answers to malformed and unsupported requests, as BIND 9.20 gives them
#
# Compared with named 9.20.29 on the same requests (the answers below are BIND's, except where noted):
#   - a question section that does not parse (dns_question_section_ok(), dns_wire.c: a second name or class, a type twice, a question cut short, a NOTIFY
#     or UPDATE of class NONE or ANY) is a FORMERR without OPT and EDE (BIND's dns_message_parse() stops before the OPT), for every opcode (no NOTIMP), EDNS
#     version (no BADVERS) and transport, and for a transfer request also from a client allow-transfer refuses (the TCP dispatch); a FORMERR for a request
#     whose section is good keeps its OPT
#   - NOTIMP (an opcode other than QUERY, NOTIFY and UPDATE) echoes no question (dns_message_reply()), with the OPT (KariDNS adds EDE 21)
#   - BADVERS echoes the questions a FORMERR would (none for such an opcode), over UDP and in the TCP transfer dispatch
#   - an UPDATE whose zone class is ANY or NONE is a FORMERR without a zone section (RFC 2136 §2.3; it was NOTAUTH), a NOTIFY of class ANY / NONE too
#   - an UPDATE or NOTIFY of another class (CH, HS) is a NOTIMP with the question (named: no view of that class; an UPDATE was NOTAUTH, a NOTIFY REFUSED or
#     accepted), and a NOTIFY whose question is not an SOA (RFC 1996 4.5) a FORMERR with the question and the OPT (KariDNS adds EDE 0; it was REFUSED or accepted)
#   - an AXFR over UDP (RFC 5936 §4.2) is a FORMERR only after the checks of a transfer (BIND ns_xfr_start()): a forward zone, a name that is not a zone
#     and a name inside a zone are no zone (KariDNS: REFUSED + EDE 20; BIND: NOTAUTH), a client allow-transfer refuses gets REFUSED + EDE 18; a UDP IXFR of
#     a name inside a zone is no zone either (it was answered with the zone's SOA); an AXFR over UDP of a built-in CHAOS zone is a FORMERR
#   - a FORMERR repeated to one address, port and ID is answered every time (UDP and TCP), as named 9.20 does (its ns_client_error() formerrcache is
#     reset with each request by ns__client_setup()); KariDNS has no loop guard
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

T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_formerr.XXXXXX") || exit 1
chmod 755 "$T"
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
CLOSED=$(kari_port 1 $((PORT + 1)))     # nothing listens there: the forwarder of fw.test
USER_OPT=""
if [ "$(id -u)" = "0" ]; then USER_OPT="user \"nobody\"; group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"; fi

# t NAME ERE ARGS... : one request (UDP; --tcp among ARGS for TCP), the first line of the answer must match ERE
t() {
    _n=$1; _w=$2; shift 2
    _o=$($TQ --port "$PORT" --show-ede "$@" | head -1)
    if echo "$_o" | grep -Eq "$_w"; then pass "$_n ($_o)"; else fail "$_n: got '$_o', expected /$_w/"; fi
}
# a FORMERR without a question and without OPT (the answer to a question section that does not parse)
FE0='^rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=0 opt=none tsig=none ede=-'

cat > "$T/ax.zone" <<'EOF'
$TTL 300
$ORIGIN ax.test.
@ IN SOA ns1.ax.test. hostmaster.ax.test. ( 5 3600 600 86400 60 )
@ IN NS ns1.ax.test.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
EOF
sed 's/ax\.test/nt.test/g' "$T/ax.zone" > "$T/nt.zone"
chmod 644 "$T"/*.zone
cat > "$T/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; tcp-connection-reuse yes; $USER_OPT };
zone "ax.test" { type master; file "$T/ax.zone"; allow-transfer { 127.0.0.1; }; allow-update { 127.0.0.1; }; };
zone "nt.test" { type master; file "$T/nt.zone"; allow-transfer { none; }; };
zone "fw.test" { type forward; forwarders { 127.0.0.1 port $CLOSED; }; forward-timeout 500; };
EOF
"$KARIDNS" -f "$T/k.conf" >> "$T/server.log" 2>&1 &
SRV=$!
kari_wait_answer "$DAG" "$PORT" ax.test. || { echo "FAIL: the server did not start"; cat "$T/server.log"; exit 1; }

echo "== a question section that does not parse: FORMERR, no question, no OPT, no EDE"
for tr in "" --tcp; do
    w=${tr:-udp}; w=${w#--}
    t "$w: QUERY, a second name"                     "$FE0" $tr --name ax.test --type A --q2-name www.ax.test --edns-version 0
    t "$w: QUERY, a second class"                    "$FE0" $tr --name ax.test --type A --q2-class 3 --edns-version 0
    t "$w: QUERY, the same question twice"           "$FE0" $tr --name ax.test --type A --second-question --edns-version 0
    t "$w: NOTIFY, a second name"                    "$FE0" $tr --name ax.test --type SOA --opcode 4 --q2-name www.ax.test --edns-version 0
    t "$w: an unassigned opcode (3): FORMERR, not NOTIMP" "$FE0" $tr --name ax.test --type A --opcode 3 --q2-name www.ax.test --edns-version 0
    t "$w: EDNS version 1: FORMERR, not BADVERS"     "$FE0" $tr --name ax.test --type A --q2-name www.ax.test --edns-version 1
    t "$w: UPDATE, a second zone name: the first is echoed" '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=0 opt=none' $tr --name ax.test --type SOA --opcode 5 --q2-name www.ax.test --edns-version 0
done
t "tcp: AXFR, a second name (the transfer dispatch)" "$FE0" --tcp --name ax.test --type AXFR --q2-name www.ax.test --edns-version 0
t "tcp: AXFR, a second name, a client allow-transfer refuses: FORMERR first" "$FE0" --tcp --name nt.test --type AXFR --q2-name www.nt.test --edns-version 0
t "tcp: AXFR, a second name, EDNS version 1: FORMERR, not BADVERS" "$FE0" --tcp --name ax.test --type AXFR --q2-name www.ax.test --edns-version 1
t "udp: IXFR, a second name"                         "$FE0" --name ax.test --type IXFR --ixfr-serial 1 --q2-name www.ax.test --edns-version 0
t "a good section (two types of one name): the FORMERR keeps its OPT" '^rcode=1 tc=0 aa=0 qd=2 an=0 ns=0 ar=1 opt=0' --name ax.test --type A --q2-type AAAA --edns-version 0

echo "== NOTIMP: no question, the OPT stays"
for op in 1 2 3 6 15; do
    t "opcode $op"                                   '^rcode=4 tc=0 aa=0 qd=0 an=0 ns=0 ar=1 opt=0' --name ax.test --type A --opcode $op --edns-version 0
done
t "opcode 3 without OPT"                             '^rcode=4 tc=0 aa=0 qd=0 an=0 ns=0 ar=0 opt=none' --name ax.test --type A --opcode 3
t "tcp: opcode 6"                                    '^rcode=4 tc=0 aa=0 qd=0 an=0 ns=0 ar=1 opt=0' --tcp --name ax.test --type A --opcode 6 --edns-version 0
t "opcode 3, two types of one name (a good section)" '^rcode=4 tc=0 aa=0 qd=0 an=0 ns=0 ar=1 opt=0' --name ax.test --type A --opcode 3 --q2-type AAAA --edns-version 0

echo "== BADVERS: the questions a FORMERR would echo"
t "QUERY"                                            '^rcode=16 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0' --name ax.test --type A --edns-version 1
t "QUERY, two types of one name"                     '^rcode=16 tc=0 aa=0 qd=2 an=0 ns=0 ar=1 opt=0' --name ax.test --type A --q2-type AAAA --edns-version 1
t "NOTIFY"                                           '^rcode=16 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0' --name ax.test --type SOA --opcode 4 --edns-version 1
t "UPDATE"                                           '^rcode=16 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0' --name ax.test --type SOA --opcode 5 --edns-version 1
t "IQUERY: no question"                              '^rcode=16 tc=0 aa=0 qd=0 an=0 ns=0 ar=1 opt=0' --name ax.test --type A --opcode 1 --edns-version 1
t "opcode 3: no question"                            '^rcode=16 tc=0 aa=0 qd=0 an=0 ns=0 ar=1 opt=0' --name ax.test --type A --opcode 3 --edns-version 1
t "tcp: AXFR (the transfer dispatch)"                '^rcode=16 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0' --tcp --name ax.test --type AXFR --edns-version 1
t "tcp: IQUERY with the question of an AXFR: no question" '^rcode=16 tc=0 aa=0 qd=0 an=0 ns=0 ar=1 opt=0' --tcp --name ax.test --type AXFR --opcode 1 --edns-version 1

echo "== UPDATE and NOTIFY of class ANY / NONE: FORMERR without the zone section (was NOTAUTH / REFUSED)"
for tr in "" --tcp; do
    w=${tr:-udp}; w=${w#--}
    for c in 255 254; do
        t "$w: UPDATE of class $c"                   "$FE0" $tr --name ax.test --type SOA --opcode 5 --class $c --edns-version 0
        t "$w: NOTIFY of class $c"                   "$FE0" $tr --name ax.test --type SOA --opcode 4 --class $c --edns-version 0
    done
done
t "UPDATE of class ANY for a zone that is not here"  "$FE0" --name nx.test --type SOA --opcode 5 --class 255
echo "== UPDATE and NOTIFY of another class: NOTIMP (named: no view of that class); a NOTIFY that is not of the SOA: FORMERR (RFC 1996 4.5)"
for tr in "" --tcp; do
    w=${tr:-udp}; w=${w#--}
    t "$w: UPDATE of class CH"                       '^rcode=4 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=-' $tr --name ax.test --type SOA --opcode 5 --class 3 --edns-version 0
    t "$w: NOTIFY of class CH"                       '^rcode=4 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=-' $tr --name ax.test --type SOA --opcode 4 --class 3 --edns-version 0
    t "$w: NOTIFY of class HS"                       '^rcode=4 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=-' $tr --name ax.test --type SOA --opcode 4 --class 4 --edns-version 0
    t "$w: NOTIFY of an A record"                    '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=0' $tr --name ax.test --type A --opcode 4 --edns-version 0
done
t "UPDATE of class CH for a zone that is not here"   '^rcode=4 tc=0 aa=0 qd=1 ' --name nx.test --type SOA --opcode 5 --class 3
t "NOTIFY of an NS record for a zone that is not here" '^rcode=1 tc=0 aa=0 qd=1 ' --name nx.test --type NS --opcode 4

echo "== AXFR over UDP: the zone and allow-transfer first, then FORMERR"
t "a zone the client may transfer: FORMERR"          '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=-' --name ax.test --type AXFR --edns-version 0
t "a zone allow-transfer refuses: REFUSED, EDE 18"   '^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=18' --name nt.test --type AXFR --edns-version 0
t "a forward zone: REFUSED, EDE 20"                  '^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 opt=0 tsig=none ede=20' --name fw.test --type AXFR --edns-version 0
t "a name that is not a zone: REFUSED, EDE 20"       '^rcode=5 tc=0 aa=0 qd=1 .* ede=20' --name nx.test --type AXFR --edns-version 0
t "a name inside a zone: REFUSED, EDE 20"            '^rcode=5 tc=0 aa=0 qd=1 .* ede=20' --name www.ax.test --type AXFR --edns-version 0
t "class ANY: no zone, REFUSED, EDE 20"              '^rcode=5 tc=0 aa=0 qd=1 .* ede=20' --name ax.test --type AXFR --class 255 --edns-version 0
t "a built-in CHAOS zone: FORMERR"                   '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ' --name version.bind --type AXFR --class 3
t "UDP IXFR of a name inside a zone: REFUSED, EDE 20 (not the zone's SOA)" '^rcode=5 tc=0 aa=0 qd=1 an=0 .* ede=20' --name www.ax.test --type IXFR --ixfr-serial 1 --edns-version 0

echo "== a repeated FORMERR is answered every time (no loop guard: named 9.20 resets its formerrcache with each request)"
# QDCOUNT 2 with one question (ID 0x4b4c): a FORMERR every time, from one socket / over one connection
H=4b4c010000020000000000000261780474657374000001000100
o=$($TQ --port "$PORT" --hex $H --count 3 | tr '\n' ' ')
case "$o" in
    "rcode=1 "*" rcode=1 "*" rcode=1 "*) pass "udp: three FORMERRs to one address, port and ID ($o)" ;;
    *) fail "udp, repeated FORMERR: $o" ;;
esac
o=$($TQ --port "$PORT" --tcp --hex $H --count 2 | tr '\n' ' ')
case "$o" in
    "rcode=1 "*" rcode=1 "*) pass "tcp: two FORMERRs with one ID on one connection ($o)" ;;
    *) fail "tcp, repeated FORMERR: $o" ;;
esac

stop_srv
grep -E 'AddressSanitizer|runtime error' "$T/server.log" > /dev/null && fail "sanitizer report in the server log" || pass "no sanitizer report"
echo "== $PASS passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
