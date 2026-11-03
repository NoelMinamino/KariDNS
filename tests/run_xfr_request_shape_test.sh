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
#   - EDE (RFC 8914): 20 Not Authoritative for a zone or a class that is not here, 18 Prohibited for a client the ACL refuses, the same over TCP and UDP
#   - a query with two OPT records (RFC 6891 §6.1.1): FORMERR without OPT, the question echoed, UDP and TCP
#   - program and forward zones (answered by the query engine): the class and shape checks come before the plugin / the forwarders; a forward zone
#     is not authoritative: its transfer is REFUSED, AA=0, EDE 20, before the shape check (as a zone that is not here)
#   - the question section of a FORMERR is the one BIND 9.20 gives (dns_error_qd_echo(), dns_wire.c): every question when the section is good (several
#     types of one name and class), none when it is not (a second name or class, a repeated question, a truncated one) or the opcode is not QUERY,
#     NOTIFY or UPDATE; an UPDATE keeps the zone names before the bad one
#   - send-extended-errors no: no EDE on any refusal or error of a transfer (the TCP dispatch, the transfer thread, the query engine)
#   - transfers-out: a request over the limit is REFUSED with EDE 0 "Too many zone transfers in progress" (not 18 Prohibited)
#   - the log lines name the class of the request ('ax.test/CH')
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
# the answers: a malformed request is a FORMERR with no records and AA=0; it echoes the question when the question section is good (BIND), none when
# QDCOUNT is 0, the section is bad or the opcode has no question section (IQUERY)
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
PROG_USER_OPT=""
[ "$(id -u)" = "0" ] && PROG_USER_OPT='program-user "nobody";'
cp tests/plugins/dnstestscript.pl "$T/plugin.pl" && chmod 755 "$T/plugin.pl"
CLOSED=$(kari_port 1 $((PORT + 1)))     # nothing listens there: the forwarder of fw.test
# write_conf EXTRA: the configuration, with EXTRA among the options.  sz.test is a secondary whose primary does not answer: a zone without data
write_conf() {
cat > "$T/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; allow-program-zones yes; $USER_OPT $1 };
key "k1" { algorithm hmac-sha256; secret "$SECRET"; };
zone "ax.test" { type master; file "$T/ax.zone"; allow-transfer { 127.0.0.1; }; };
zone "kz.test" { type master; file "$T/kz.zone"; allow-transfer { key "k1"; }; };
zone "fw.test" { type forward; forwarders { 127.0.0.1 port $CLOSED; }; forward-timeout 500; };
zone "pg.test" { type program; program "$T/plugin.pl"; $PROG_USER_OPT program-timeout 2000; };
zone "sz.test" { type slave; primaries { 127.0.0.1 port $CLOSED; }; allow-transfer { 127.0.0.1; }; };
logging {
    channel xo { file "$T/logs/xfer.log"; severity debug 1; print-category yes; print-severity yes; };
    category xfer-out { xo; };
    category security { xo; };
};
EOF
}
start_srv() {
    "$KARIDNS" -f "$T/k.conf" >> "$T/server.log" 2>&1 &
    SRV=$!
    kari_wait_answer "$DAG" "$PORT" ax.test. || { echo "FAIL: the server did not start"; cat "$T/server.log"; exit 1; }
}
write_conf ""
start_srv

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
t "QDCOUNT 2, the same question twice"          "$FE0" --name ax.test --type AXFR --second-question
t "QDCOUNT 2, AXFR and IXFR of the zone (both echoed)" '^rcode=1 tc=0 aa=0 qd=2 an=0 ns=0 ' --name ax.test --type AXFR --q2-type IXFR
t "QDCOUNT 2, another name"                     "$FE0" --name ax.test --type AXFR --q2-name www.ax.test
t "QDCOUNT 3 (counts, one question)"            "$FE0" --name ax.test --type AXFR --hdr-qd 3
t "OPCODE NOTIFY with the question of an AXFR"  "$FE1" --name ax.test --type AXFR --opcode 4
t "OPCODE UPDATE with the question of an AXFR"  "$FE1" --name ax.test --type AXFR --opcode 5
t "OPCODE IQUERY with the question of an AXFR"  "$FE0" --name ax.test --type AXFR --opcode 1
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

sleep 1   # (the xfer-out lines are limited to 50 a second, dns_utils.c logev_rate_limit(): the log checks below want every one)
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

sleep 1
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
t "UDP: two OPT records (the query path's own FORMERR, the question echoed)" "$FE1" --udp --name ax.test --type IXFR --ixfr-serial 5 --edns-version 0 --second-opt
t "UDP: malformed, the client may not transfer: REFUSED" '^rcode=5 ' --udp --name kz.test --type IXFR --ixfr-serial 5 --req-rcode 1
t "UDP: good, the client may not transfer"      '^rcode=5 ' --udp --name kz.test --type IXFR --ixfr-serial 5

echo "== EDE (RFC 8914): 20 Not Authoritative for a zone or a class that is not here, 18 Prohibited for a client the ACL refuses; TCP and UDP agree"
EDE20='^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 .* ede=20$'
EDE18='^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 .* ede=18$'
t "TCP AXFR, no such zone: EDE 20"              "$EDE20" --name nx.test --type AXFR --edns-version 0 --show-ede
t "TCP IXFR, no such zone: EDE 20"              "$EDE20" --name nx.test --type IXFR --ixfr-serial 1 --edns-version 0 --show-ede
t "TCP AXFR of class CH: EDE 20"                "$EDE20" --name ax.test --type AXFR --class 3 --edns-version 0 --show-ede
t "TCP IXFR of class ANY: EDE 20"               "$EDE20" --name ax.test --type IXFR --ixfr-serial 1 --class 255 --edns-version 0 --show-ede
t "TCP AXFR, the client may not transfer: EDE 18" "$EDE18" --name kz.test --type AXFR --edns-version 0 --show-ede
t "UDP IXFR of class CH: EDE 20"                "$EDE20" --udp --name ax.test --type IXFR --ixfr-serial 5 --class 3 --edns-version 0 --show-ede
t "UDP IXFR, no such zone: EDE 20"              "$EDE20" --udp --name nx.test --type IXFR --ixfr-serial 5 --edns-version 0 --show-ede
t "UDP IXFR, the client may not transfer: EDE 18" "$EDE18" --udp --name kz.test --type IXFR --ixfr-serial 5 --edns-version 0 --show-ede

echo "== a query with two OPT records (RFC 6891 §6.1.1): FORMERR without OPT, the question echoed (§7: header and question)"
t "UDP A query, two OPT records"                "$FE1" --udp --name www.ax.test --type A --edns-version 0 --second-opt
t "TCP A query, two OPT records"                "$FE1" --name www.ax.test --type A --edns-version 0 --second-opt
t "UDP SOA query, two OPT records, no such zone" "$FE1" --udp --name nx.test --type SOA --edns-version 0 --second-opt

sleep 1
echo "== program and forward zones (answered by the query engine, not the transfer dispatch): the same checks of the request first"
t "forward zone: AXFR is REFUSED with EDE 20, not relayed" "$EDE20" --name fw.test --type AXFR --edns-version 0 --show-ede
t "forward zone: IXFR is REFUSED, AA=0"         "$NA" --name fw.test --type IXFR --ixfr-serial 1
t "forward zone: UDP IXFR is REFUSED, EDE 20"   "$EDE20" --udp --name fw.test --type IXFR --ixfr-serial 1 --edns-version 0 --show-ede
t "forward zone: a malformed AXFR is REFUSED (not ours: before the shape check)" "$NA" --name fw.test --type AXFR --hdr-an 1
t "forward zone: AXFR of class CH: REFUSED"     "$NA" --name fw.test --type AXFR --class 3
t "forward zone: UDP IXFR of class ANY: REFUSED, EDE 20" "$EDE20" --udp --name fw.test --type IXFR --ixfr-serial 1 --class 255 --edns-version 0 --show-ede
t "program zone: a malformed AXFR is a FORMERR (not given to the plugin)" "$FE1" --name pg.test --type AXFR --hdr-an 1
t "program zone: AXFR with octets after it"     "$FE1" --name pg.test --type AXFR --trailing 16
t "program zone: a malformed UDP IXFR is a FORMERR" "$FE1" --udp --name pg.test --type IXFR --ixfr-serial 1 --hdr-ns 2
t "program zone: IXFR without the client's SOA" "$FE1" --name pg.test --type IXFR
t "program zone: AXFR of class CH: REFUSED"     "$NA" --name pg.test --type AXFR --class 3
t "program zone: UDP IXFR of class CH: REFUSED, EDE 20" "$EDE20" --udp --name pg.test --type IXFR --ixfr-serial 1 --class 3 --edns-version 0 --show-ede
t "program zone: a good AXFR still goes to the plugin (not FORMERR / REFUSED)" '^rcode=[0234] ' --name pg.test --type AXFR

echo "== the question section of a FORMERR is BIND's (lib/dns/message.c getquestions(), dns_message_reply())"
FE2='^rcode=1 tc=0 aa=0 qd=2 an=0 ns=0 '
t "QUERY, two questions of one name, A and AAAA: both echoed"  "$FE2" --udp --name www.ax.test --type A --q2-type AAAA --edns-version 0
t "QUERY, the same over TCP"                                   "$FE2" --name www.ax.test --type A --q2-type AAAA --edns-version 0
t "QUERY, two names: none"                                     "$FE0" --udp --name www.ax.test --type A --q2-name ns1.ax.test --edns-version 0
t "QUERY, the same question twice: none"                       "$FE0" --udp --name www.ax.test --type A --second-question --edns-version 0
t "QUERY, one name, classes IN and CH: none"                   "$FE0" --udp --name www.ax.test --type A --q2-class 3 --edns-version 0
t "QUERY, QDCOUNT 2 and one question: none"                    "$FE0" --udp --name www.ax.test --type A --hdr-qd 2
t "QUERY, A and AAAA and two OPT records: both, no OPT"        '^rcode=1 tc=0 aa=0 qd=2 an=0 ns=0 ar=0 ' --udp --name www.ax.test --type A --q2-type AAAA --edns-version 0 --second-opt
t "QUERY, two names and two OPT records: none"                 '^rcode=1 tc=0 aa=0 qd=0 an=0 ns=0 ar=0 ' --udp --name www.ax.test --type A --q2-name ns1.ax.test --edns-version 0 --second-opt
t "QUERY, a COOKIE of 5 octets: the question, OPT"            '^rcode=1 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 ' --udp --name www.ax.test --type A --edns-version 0 --opt-data 000a00056162636465
t "NOTIFY, two names: none"                                    "$FE0" --udp --name ax.test --type SOA --opcode 4 --q2-name www.ax.test
t "UPDATE, two zone names: the first one (read before the bad one)" "$FE1" --udp --name ax.test --type SOA --opcode 5 --q2-name www.ax.test
t "UPDATE, SOA and A of the zone: both"                        "$FE2" --udp --name ax.test --type SOA --opcode 5 --q2-type A
t "UPDATE, a zone of type A: FORMERR with the zone"            "$FE1" --udp --name ax.test --type A --opcode 5

echo "== a zone without data (sz.test): the transfer thread's SERVFAIL, EDE 14"
t "TCP AXFR of a secondary without data: SERVFAIL, EDE 14"     '^rcode=2 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 .* ede=14$' --name sz.test --type AXFR --edns-version 0 --show-ede

echo "== the log of category xfer-out"
lg() { i=0; while [ $i -lt 50 ]; do grep -q -- "$1" "$T/logs/xfer.log" 2>/dev/null && return 0; sleep 0.2; i=$((i + 1)); done; return 1; }
for why in "OPCODE is not QUERY" "RCODE is not NOERROR" "QDCOUNT is not 1" "ANCOUNT is not 0" "unexpected NSCOUNT" "the IXFR Authority record is not a SOA" \
           "trailing octets after the last record" "request too long" "malformed or unexpected Additional record"; do
    lg "transfer of 'ax.test/IN': bad zone transfer request: malformed request, $why (FORMERR)" && pass "logged: $why" || fail "not logged: $why"
done
for c in CH ANY NONE HS; do
    lg "transfer of 'ax.test/$c': bad zone transfer request: non-authoritative zone (REFUSED)" && pass "a transfer of class $c is logged as a non-authoritative zone of class $c" || fail "the transfer of class $c was not logged as 'ax.test/$c'"
done
! grep -q "transfer of 'ax.test/IN': bad zone transfer request: non-authoritative" "$T/logs/xfer.log" && pass "no transfer of ax.test of another class is logged as IN" || fail "a transfer of another class was logged as 'ax.test/IN'"
lg "transfer of 'nx.test/IN': bad zone transfer request: non-authoritative zone (REFUSED)" && pass "a zone that does not exist (class IN) is logged as IN" || fail "nx.test/IN not logged"
lg "zone transfer 'kz.test/AXFR/IN' denied" && pass "the ACL refusal names the class (security)" || fail "no 'zone transfer 'kz.test/AXFR/IN' denied'"
lg "transfer of 'fw.test/ANY': bad zone transfer request: non-authoritative zone (REFUSED)" && pass "forward zone: an IXFR of class ANY is logged with its class" || fail "fw.test/ANY not logged"
lg "transfer of 'fw.test/IN': bad zone transfer request: non-authoritative zone (REFUSED)" && pass "forward zone: a transfer is logged as a non-authoritative zone" || fail "fw.test/IN not logged as non-authoritative"
lg "transfer of 'pg.test/IN': bad zone transfer request: malformed request, ANCOUNT is not 0 (FORMERR)" && pass "program zone: the malformed AXFR is logged" || fail "pg.test malformed AXFR not logged"
! grep -q "transfer of 'nx.test/IN': bad zone transfer request: malformed" "$T/logs/xfer.log" && pass "a malformed request for a zone that does not exist is logged as a refusal, not as malformed" || fail "nx.test was logged as malformed"
if grep -qE "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error:" "$T/server.log"; then fail "sanitizer report in server.log"; tail -20 "$T/server.log"; else pass "no sanitizer report"; fi
stop_srv

echo "== transfers-out 0: every transfer is over the limit, REFUSED with EDE 0 and its text (a server-side reason, not 18 Prohibited)"
write_conf "transfers-out 0;"
start_srv
t "AXFR over transfers-out: REFUSED, EDE 0 'Too many zone transfers in progress'" \
  '^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=1 .* ede=0 ede-text="Too many zone transfers in progress"$' --name ax.test --type AXFR --edns-version 0 --show-ede-text
t "IXFR over transfers-out, signed: REFUSED, EDE 0, signed" '^rcode=5 tc=0 aa=0 qd=1 an=0 ns=0 ar=2 .* tsig=ok ede=0$' --name kz.test --type IXFR --ixfr-serial 1 --edns-version 0 --key "k1:$SECRET" --show-ede
lg "transfer of 'ax.test/IN': AXFR request denied: quota reached (transfers-out 0)" && pass "the quota is logged" || fail "the quota was not logged"
stop_srv

echo "== send-extended-errors no: no EDE on a transfer's refusal or error (the TCP dispatch, the transfer thread, the query engine)"
write_conf "send-extended-errors no;"
start_srv
NOEDE='ar=1 opt=0 tsig=none ede=-$'
t "TCP AXFR, no such zone: REFUSED, no EDE"             "^rcode=5 .*$NOEDE" --name nx.test --type AXFR --edns-version 0 --show-ede
t "TCP AXFR, the client may not transfer: no EDE"       "^rcode=5 .*$NOEDE" --name kz.test --type AXFR --edns-version 0 --show-ede
t "TCP AXFR of class CH: no EDE"                        "^rcode=5 .*$NOEDE" --name ax.test --type AXFR --class 3 --edns-version 0 --show-ede
t "forward zone AXFR: REFUSED, no EDE"                  "^rcode=5 .*$NOEDE" --name fw.test --type AXFR --edns-version 0 --show-ede
t "UDP IXFR, no such zone: no EDE"                      "^rcode=5 .*$NOEDE" --udp --name nx.test --type IXFR --ixfr-serial 5 --edns-version 0 --show-ede
t "secondary without data (transfer thread): SERVFAIL, no EDE" "^rcode=2 .*$NOEDE" --name sz.test --type AXFR --edns-version 0 --show-ede
t "a zone transfer still works"                         "$XFER" --name ax.test --type AXFR
stop_srv
write_conf "send-extended-errors no; transfers-out 0;"
start_srv
t "transfers-out 0 and send-extended-errors no: REFUSED, no EDE" "^rcode=5 .*$NOEDE" --name ax.test --type AXFR --edns-version 0 --show-ede
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
    t "DB: AXFR of class CH: EDE 20, as for a zone in memory" "$EDE20" --name a.test --type AXFR --class 3 --edns-version 0 --show-ede
    t "DB: UDP IXFR of class CH: EDE 20"             "$EDE20" --udp --name a.test --type IXFR --ixfr-serial 5 --class 3 --edns-version 0 --show-ede
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
