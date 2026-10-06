#!/bin/sh
# ==============================================================================
# run_dag_dig_output_compat_test.sh
#
# Phase 15 (T-01, T-03, T-07, T-08, T-09, T-13, D-14, D-15, X-14, X-36): dag prints
# answers from KariDNS the way dig 9.20 does. Every expected string below was taken
# from dig 9.20.29 against the same zones. When dig 9.20 is installed, the case list
# at the end is also compared with dig directly (whitespace normalised).
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS="${KARIDNS:-$BASE_DIR/karidns}"
DAG="${DAG:-$BASE_DIR/dag}"
[ -x "$KARIDNS" ] || make -C "$BASE_DIR" karidns >/dev/null 2>&1
[ -x "$DAG" ] || make -C "$BASE_DIR" dag >/dev/null 2>&1

TMP_DIR="$(mktemp -d /tmp/dag_output_compat.XXXXXX)"
PORT=$((38000 + $$ % 5000))
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM
chmod 755 "$TMP_DIR"

cat > "$TMP_DIR/esc.zone" <<'EOF'
$TTL 300
@ SOA ns1 h 1 2 3 90061 5
@ NS ns1
ns1 A 192.0.2.1
c\(p A 192.0.2.4
q\"x A 192.0.2.5
dl\$r A 192.0.2.8
EOF
cat > "$TMP_DIR/ax.zone" <<'EOF'
$TTL 300
@ SOA ns1 h 5 3600 600 86400 60
@ NS ns1
ns1 A 192.0.2.1
www A 192.0.2.10
EOF
cp "$SCRIPT_DIR/zones/example.com.zone" "$SCRIPT_DIR/zones/example.com.dnskey" "$SCRIPT_DIR/zones/example.com.hosts" "$TMP_DIR/"
SECRET="cGhhc2UxNS14MzYtdGVzdC1rZXktMDEyMzQ1Njc4OQ=="
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
chmod 644 "$TMP_DIR"/*.zone
cat > "$TMP_DIR/k.conf" <<EOF
options { port $PORT; bind-address { 127.0.0.1; }; pid-file "none"; $USER_OPT
          tcp-connection-reuse yes; nsid "kari-ns1"; };
key "k1" { algorithm hmac-sha256; secret "$SECRET"; };
zone "esc.test" { type master; file "$TMP_DIR/esc.zone"; };
zone "ax.test" { type master; file "$TMP_DIR/ax.zone"; allow-transfer { key "k1"; }; };
zone "example.com" { type master; file "$TMP_DIR/example.com.zone"; };
EOF
"$KARIDNS" -f "$TMP_DIR/k.conf" > "$TMP_DIR/karidns.log" 2>&1 &
SERVER_PID=$!
sleep 1
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: karidns did not start"; cat "$TMP_DIR/karidns.log"; exit 1
fi

S="@127.0.0.1 -p $PORT"
K="-y hmac-sha256:k1:$SECRET"
OUT="$TMP_DIR/out.txt"
FAILED=0
PASSED=0
run() { CUR="$*"; eval "\"$DAG\" $S $* +nohexdump" 2>&1 | sed -E 's/[[:space:]]+/ /g; s/ $//' > "$OUT"; }
has() {
    if grep -qF -- "$1" "$OUT"; then return 0; fi
    echo "FAIL [$CUR]: expected '$1'"; sed 's/^/    | /' "$OUT" | head -60; FAILED=$((FAILED + 1)); return 1
}
hasnt() {
    if ! grep -qF -- "$1" "$OUT"; then return 0; fi
    echo "FAIL [$CUR]: unexpected '$1'"; sed 's/^/    | /' "$OUT" | head -60; FAILED=$((FAILED + 1)); return 1
}
lines() { # exact number of output lines
    if [ "$(wc -l < "$OUT" | tr -d ' ')" -eq "$1" ]; then return 0; fi
    echo "FAIL [$CUR]: expected $1 line(s)"; sed 's/^/    | /' "$OUT"; FAILED=$((FAILED + 1)); return 1
}
ok() { PASSED=$((PASSED + 1)); echo "PASS [$CUR]"; }

echo "=== EDNS options (T-01, T-03, D-15, RFC 7314, RFC 7828, RFC 7830) ==="
run esc.test SOA +expire +norec;           has "; EXPIRE: 90061 (1 day 1 hour 1 minute 1 second)" && ok
run example.com SOA +expire +norec;        has "; EXPIRE: 1209600 (2 weeks)" && ok
run esc.test SOA +expire +qr +norec;       has "; EXPIRE:" && hasnt "; EXPIRE (" && ok
run esc.test SOA +expire +yaml +norec;     has "EXPIRE: 90061 # 1 day 1 hour 1 minute 1 second" && ok
run esc.test SOA +keepalive +qr;           has "; TCP-KEEPALIVE:" && has "(UDP)" && ok
run esc.test SOA +keepalive +tcp;          has "; TCP-KEEPALIVE: " && has " secs" && ok
run esc.test SOA +padding=128 +qr;         has "; PADDING:" && hasnt "octets" && has ";; QUERY SIZE: 128" && ok
run esc.test SOA +nsid;                    has '; NSID: 6b 61 72 69 2d 6e 73 31 ("kari-ns1")' && ok
run esc.test SOA +ednsopt=65001:41420043 +qr; has '; OPT=65001: 41 42 00 43 ("AB.C")' && ok
run esc.test SOA +nsid +subnet=192.0.2.0/24 +qr +noall +comments
awk '/^; (NSID|CLIENT-SUBNET|COOKIE)/{print $2}' "$OUT" | head -3 | tr '\n' ' ' > "$TMP_DIR/order"
if [ "$(cat "$TMP_DIR/order")" = "NSID: CLIENT-SUBNET: COOKIE: " ]; then ok; else echo "FAIL [$CUR]: option order $(cat "$TMP_DIR/order")"; FAILED=$((FAILED + 1)); fi

echo "=== BADVERS and signed retries (X-36) ==="
run esc.test SOA +edns=1 +noednsnegotiation; has "status: BADVERS," && hasnt "EXT RCODE" && hasnt "BADSIG" && has "(echoed)" && ok
run ax.test SOA +edns=1 $K;                has ";; BADVERS, retrying with EDNS version 0." && has "status: NOERROR" && hasnt "Couldn't verify" && ok
run ax.test SOA $K;                        has ";; TSIG PSEUDOSECTION:" && has "NOERROR 0" && ok
run ax.test SOA -y hmac-sha256:k1:AAAA;    has ";; Couldn't verify signature: tsig indicates error" && has " BADSIG 0" && ok
run ax.test AXFR $K +edns=1;               has "www.ax.test. 300 IN A 192.0.2.10" && hasnt "BADVERS" && hasnt "Couldn't verify" && ok
run ax.test AXFR;                          has "; Transfer failed." && hasnt "XFR size" && ok
run ax.test AXFR $K +yaml;                 has "flags: qr aa" && hasnt "QUESTION_SECTION" && has "TSIG_PSEUDOSECTION:" && ok

echo "=== display flags, hex dumps and YAML (T-07, T-09, T-13) ==="
CUR="ns1.esc.test A +noall +answer"
"$DAG" $S ns1.esc.test A +noall +answer > "$OUT" 2>&1
lines 1 && has "ns1.esc.test." && ok
CUR="+noall +answer +hexdump"
"$DAG" $S ns1.esc.test A +noall +answer +hexdump > "$OUT" 2>&1
has "Query (" && ok
run ns1.esc.test A +yaml +noall;           hasnt "OPT_PSEUDOSECTION" && hasnt "QUESTION_SECTION" && hasnt "ANSWER_SECTION" && has "status: NOERROR" && ok
run ns1.esc.test A +yaml +nocomments;      hasnt "OPT_PSEUDOSECTION" && has "QUESTION_SECTION" && ok
run ns1.esc.test A +yaml +qr;              has "type: RECURSIVE_QUERY" && has "query_message_data:" && hasnt "Sending query in YAML" && ok
run ns1.esc.test A +yaml +qr +norec;       has "type: AUTH_QUERY" && ok
ms_ok=0
for i in 1 2 3 4 5; do
    "$DAG" $S ns1.esc.test A +yaml > "$OUT" 2>&1
    grep -qE "query_time: !!timestamp [0-9-]+T[0-9:]+\.[0-9]{3}Z" "$OUT" || { ms_ok=-99; break; }
    grep -qE "query_time: !!timestamp .*\.000Z" "$OUT" || ms_ok=1
done
CUR="+yaml millisecond timestamps"
if [ "$ms_ok" -eq 1 ]; then ok; else echo "FAIL [$CUR]"; sed 's/^/    | /' "$OUT" | head -8; FAILED=$((FAILED + 1)); fi

echo "=== names (X-14) ==="
run 'c\(p.esc.test' A;                       has ";c\(p.esc.test. IN A" && has "c\(p.esc.test. 300 IN A 192.0.2.4" && ok
run 'q\"x.esc.test' A +noall +answer;        has 'q\"x.esc.test. 300 IN A 192.0.2.5' && ok
run 'dl\$r.esc.test' A +yaml;                has "- 'dl\\\$r.esc.test. IN A'" && ok

echo "=== search list (D-14) ==="
run nx A +search +domain=esc.test;         has "status: REFUSED" && hasnt "status: NXDOMAIN" && hasnt "MULTI-SERVER" && ok
run nx A +showsearch +domain=esc.test;     has "status: NXDOMAIN" && has "status: REFUSED" && hasnt "MULTI-SERVER" && ok
run ns1 A +search +domain=esc.test;        has "ns1.esc.test. 300 IN A 192.0.2.1" && ok

echo "=== multiline (T-08) ==="
run example.com DNSKEY +multiline +noall +answer; has ") ; KSK; alg = ECDSAP256SHA256 ; key id = 23534" && has ") ; ZSK; alg = ECDSAP256SHA256 ; key id = 33640" && ok
run example.com DNSKEY +multiline +norrcomments +noall +answer; hasnt "key id" && ok
run host-key.example.com KEY +multiline +noall +answer; has "); alg = ECDSAP256SHA256 ; key id = 23533" && ok
run eid-node.example.com EID +multiline +noall +answer; has "EID ( 01020304 )" && ok
run generic-rr.example.com TYPE65280 +multiline +noall +answer; has '\# 4 ( C0000201 )' && ok
run sig-node.example.com SIG +multiline +noall +answer; has "SIG A 13 4 86400 20300101000000 (" && ok
run sink-node.example.com SINK +multiline +noall +answer; has "SINK 1 2 3 (" && ok
run example.com SOA +multiline +norrcomments +noall +answer; has "86400)" && hasnt "; serial" && ok

if command -v dig >/dev/null 2>&1 && dig -v 2>&1 | grep -q "DiG 9\.20\."; then
    echo "=== comparison with $(dig -v 2>&1) ==="
    norm() {
        sed -E -e '/^; <<>> /d' -e '/^;; global options/d' -e '/^;; WHEN:/d' -e '/^;; Query time:/d' \
            -e 's/id: [0-9]+/id: X/' -e 's/(COOKIE: )[0-9a-f]+/\1C/' -e 's/(CLIENT|SERVER): [0-9a-f]+/\1: C/' \
            -e 's/(query_time|response_time): !!timestamp .*/\1: T/' \
            -e 's/(TSIG[[:space:]]+hmac-[a-z0-9]+\. )[0-9]+ ([0-9]+) ([0-9]+)( [A-Za-z0-9+\/=]+)? [0-9]+ /\1T \2 \3 MAC ID /' \
            -e 's/[[:space:]]+/ /g' -e 's/ $//'
    }
    while IFS= read -r c; do
        eval "dig $S $c" 2>/dev/null | norm > "$TMP_DIR/dig.txt"
        eval "\"$DAG\" $S $c +nohexdump" 2>/dev/null | norm > "$TMP_DIR/dag.txt"
        CUR="$c (vs dig)"
        if cmp -s "$TMP_DIR/dig.txt" "$TMP_DIR/dag.txt"; then
            PASSED=$((PASSED + 1))
        else
            echo "FAIL [$CUR]"; diff "$TMP_DIR/dig.txt" "$TMP_DIR/dag.txt" | head -20 | sed 's/^/    /'; FAILED=$((FAILED + 1))
        fi
    done <<EOF
esc.test SOA
esc.test SOA +norec +expire
esc.test SOA +keepalive +qr
esc.test SOA +keepalive +tcp
esc.test SOA +padding=512 +qr
esc.test SOA +nsid +subnet=192.0.2.0/24 +ednsopt=65001:01 +qr
esc.test SOA +edns=1
esc.test SOA +edns=1 +noednsnegotiation
esc.test SOA +edns=1 +showbadvers
esc.test SOA +yaml
esc.test SOA +yaml +qr
esc.test SOA +yaml +noall +answer
esc.test SOA +noall +answer +comments
'c\(p.esc.test' A
'c\(p.esc.test' A +yaml
nx A +search +domain=esc.test
nx A +showsearch +domain=esc.test
nx A +search +domain=esc.test +qr
ax.test SOA $K
ax.test SOA $K +qr
ax.test SOA $K +yaml
ax.test AXFR $K
ax.test AXFR $K +qr
ax.test AXFR
ax.test SOA -y hmac-sha256:k1:AAAA
example.com DNSKEY +multiline
example.com SOA +multiline +norrcomments
EOF
else
    echo "SKIP: dig 9.20 not installed; direct comparison not run"
fi

echo "========================================================="
echo "passed=$PASSED failed=$FAILED"
[ "$FAILED" -eq 0 ] || exit 1
echo "PASS: dag output matches dig 9.20"
