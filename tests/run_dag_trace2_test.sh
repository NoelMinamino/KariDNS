#!/bin/sh
# dag +trace2 (フルリゾルバ相当の反復解決) の統合テスト
#
# KariDNS を 127.0.0.1〜127.0.0.4 の 4 プロセスと、異常応答用の mock (127.0.0.5) を同じポートで起動し、
# ルートからの委任ツリーを組んで dag @127.0.0.1 -p PORT +trace2 で解決させる。
# referral の glue にはポートを書けないため、すべての hop で -p のポートを使う。
#
#   127.0.0.1  "."                               ルート
#   127.0.0.2  "test." "alt."                    TLD
#   127.0.0.3  "example.test." "other.alt." "lame.test." "sibling.test."
#   127.0.0.4  "glueless.test."                  (NS ns2.other.alt. / glue なし)
#   127.0.0.5  mock_trace2_server.pl            "tc.test." (UDP は TC=1) / "noedns.test." (EDNS に FORMERR)
#                                               "mockp.test." (bailiwick 外の偽 glue を返す)
#                                               それ以外は REFUSED (lame 役)
#
# 127.0.0.2 以降の loopback alias がない場合、root なら追加し、そうでなければ SKIP する。

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$DIR/.."
BIN="$ROOT/karidns"
DAG_BIN="${DAG_BIN:-$ROOT/dag}"   # DAG_BIN=./dag-asan で ASan 版を検査できる
PORT="${TRACE2_TEST_PORT:-15353}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/dag_trace2.XXXXXX")"
IPS="127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5"
ADDED_ALIASES=""
PIDS=""
PASS=0
FAIL=0

[ -x "$BIN" ] && [ -x "$ROOT/dag" ] || {
    echo "[*] Building targets..."
    make -C "$ROOT" karidns dag || exit 1
}
[ -x "$DAG_BIN" ] || { echo "[FAIL] $DAG_BIN not found"; exit 1; }

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null; done
    sleep 0.2
    for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
    for ip in $ADDED_ALIASES; do
        ifconfig lo0 inet "$ip" -alias 2>/dev/null || ifconfig lo inet "$ip" -alias 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ip_available() {
    ifconfig lo0 2>/dev/null | grep -q "inet $1 " && return 0
    ifconfig lo 2>/dev/null | grep -q "inet $1 " && return 0
    # Linux は 127.0.0.0/8 全体が lo に載っている
    [ "$(uname -s)" = "Linux" ] && return 0
    return 1
}

for ip in $IPS; do
    ip_available "$ip" && continue
    if [ "$(id -u)" -eq 0 ] && { ifconfig lo0 inet "$ip/32" alias 2>/dev/null || ifconfig lo inet "$ip/32" alias 2>/dev/null; }; then
        ADDED_ALIASES="$ADDED_ALIASES $ip"
    else
        echo "[SKIP] loopback alias $ip is not configured (run as root, or: ifconfig lo0 inet $ip/32 alias)"
        exit 0
    fi
done

# ---------------------------------------------------------------- zones
SOA_TAIL="1 3600 900 604800 300"

cat > "$WORK/root.zone" <<EOF
\$ORIGIN .
\$TTL 3600
.                   IN SOA a.root-servers. hostmaster.root-servers. $SOA_TAIL
.                   IN NS  a.root-servers.
a.root-servers.     IN A   127.0.0.1
test.               IN NS  ns.tld.
alt.                IN NS  ns.tld.
ns.tld.             IN A   127.0.0.2
EOF

cat > "$WORK/test.zone" <<EOF
\$ORIGIN test.
\$TTL 3600
@            IN SOA ns.tld. hostmaster.test. $SOA_TAIL
@            IN NS  ns.tld.
example      IN NS  ns.example
ns.example   IN A   127.0.0.3
example      IN DS  12345 8 2 49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC0001
glueless     IN NS  ns2.other.alt.
lame         IN NS  ns1.lame
lame         IN NS  ns2.lame
ns1.lame     IN A   127.0.0.5
ns2.lame     IN A   127.0.0.3
alllame      IN NS  ns.alllame
ns.alllame   IN A   127.0.0.5
loop1        IN NS  ns.loop2.alt.
sibling      IN NS  ns.example.test.
tc           IN NS  ns.tc
ns.tc        IN A   127.0.0.5
noedns       IN NS  ns.noedns
ns.noedns    IN A   127.0.0.5
deadonly     IN NS  ns.deadonly
ns.deadonly  IN A   127.0.0.5
noglue       IN NS  ns.noglue.test.
mockp        IN NS  ns.mockp
ns.mockp     IN A   127.0.0.5
EOF

cat > "$WORK/alt.zone" <<EOF
\$ORIGIN alt.
\$TTL 3600
@            IN SOA ns.tld. hostmaster.alt. $SOA_TAIL
@            IN NS  ns.tld.
other        IN NS  ns.other
ns.other     IN A   127.0.0.3
loop2        IN NS  ns.loop1.test.
EOF

cat > "$WORK/example.test.zone" <<EOF
\$ORIGIN example.test.
\$TTL 3600
@            IN SOA ns hostmaster $SOA_TAIL
@            IN NS  ns
ns           IN A   127.0.0.3
www          IN A   192.0.2.1
alias        IN CNAME www.glueless.test.
loopa        IN CNAME loopb
loopb        IN CNAME loopa
deep.a.b     IN A   192.0.2.7
dn           IN DNAME other.alt.
xloop        IN CNAME yloop.other.alt.
EOF

cat > "$WORK/other.alt.zone" <<EOF
\$ORIGIN other.alt.
\$TTL 3600
@            IN SOA ns hostmaster $SOA_TAIL
@            IN NS  ns
ns           IN A   127.0.0.3
ns2          IN A   127.0.0.4
x            IN A   192.0.2.9
yloop        IN CNAME xloop.example.test.
EOF

cat > "$WORK/lame.test.zone" <<EOF
\$ORIGIN lame.test.
\$TTL 3600
@            IN SOA ns2 hostmaster $SOA_TAIL
@            IN NS  ns1
@            IN NS  ns2
ns1          IN A   127.0.0.5
ns2          IN A   127.0.0.3
www          IN A   192.0.2.3
EOF

cat > "$WORK/sibling.test.zone" <<EOF
\$ORIGIN sibling.test.
\$TTL 3600
@            IN SOA ns.example.test. hostmaster $SOA_TAIL
@            IN NS  ns.example.test.
www          IN A   192.0.2.4
EOF

cat > "$WORK/glueless.test.zone" <<EOF
\$ORIGIN glueless.test.
\$TTL 3600
@            IN SOA ns2.other.alt. hostmaster $SOA_TAIL
@            IN NS  ns2.other.alt.
www          IN A   192.0.2.2
EOF

# ---------------------------------------------------------------- servers
# write_conf <ip> <zone>...
write_conf() {
    ip="$1"; shift
    conf="$WORK/karidns-$ip.conf"
    {
        echo "options {"
        echo "    port $PORT;"
        echo "    bind-address { $ip; };"
        if [ "$(id -u)" -eq 0 ]; then
            # root 起動時は特権分離のため user 指定が必須
            echo "    user \"nobody\";"
            echo "    group \"$(id -gn nobody 2>/dev/null || echo nobody)\";"
        fi
        echo "};"
        for z in "$@"; do
            f="$WORK/$z.zone"
            [ "$z" = "." ] && f="$WORK/root.zone"
            echo "zone \"$z\" { type master; file \"$f\"; };"
        done
    } > "$conf"
}

write_conf 127.0.0.1 .
write_conf 127.0.0.2 test alt
write_conf 127.0.0.3 example.test other.alt lame.test sibling.test
write_conf 127.0.0.4 glueless.test

for ip in 127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4; do
    "$BIN" -f -c "$WORK/karidns-$ip.conf" -P "$WORK/karidns-$ip.pid" > "$WORK/karidns-$ip.log" 2>&1 &
    PIDS="$PIDS $!"
done
perl "$DIR/mock_trace2_server.pl" --host 127.0.0.5 --port "$PORT" > "$WORK/karidns-127.0.0.5.log" 2>&1 &
PIDS="$PIDS $!"

# 起動待ち: 各サーバの SOA が引けるまで
for ip in $IPS; do
    ok=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if "$DAG_BIN" @"$ip" -p "$PORT" . SOA +norec +short +time=1 >/dev/null 2>&1; then ok=1; break; fi
        if "$DAG_BIN" @"$ip" -p "$PORT" unrelated.alt SOA +norec +short +time=1 2>/dev/null | grep -q .; then ok=1; break; fi
        sleep 0.3
    done
    if [ "$ok" != 1 ]; then
        echo "[FAIL] karidns on $ip:$PORT did not start"
        cat "$WORK/karidns-$ip.log"
        exit 1
    fi
done

# ---------------------------------------------------------------- tests
DAG="$DAG_BIN @127.0.0.1 -p $PORT +nohexdump +noldnsz +time=2"

# run <name> <args...>: 出力を $OUT に保存する
run() {
    NAME="$1"; shift
    OUT="$WORK/out.txt"
    $DAG "$@" > "$OUT" 2>&1
    RC=$?
}

expect() {
    if grep -q -- "$1" "$OUT"; then
        return 0
    fi
    echo "[FAIL] $NAME: expected /$1/"
    sed 's/^/    | /' "$OUT"
    FAIL=$((FAIL + 1))
    return 1
}

expect_not() {
    if grep -q -- "$1" "$OUT"; then
        echo "[FAIL] $NAME: unexpected /$1/"
        sed 's/^/    | /' "$OUT"
        FAIL=$((FAIL + 1))
        return 1
    fi
    return 0
}

ok() {
    echo "[PASS] $NAME"
    PASS=$((PASS + 1))
}

run "delegation with in-domain glue" www.example.test A +trace2
expect "^www.example.test.*192.0.2.1" && expect "trace2: NOERROR for www.example.test" \
    && expect "(ns.example.test)" && expect "0 in 0 sub-resolutions" && ok

run "glueless NS resolved iteratively" www.glueless.test A +trace2
expect "^;; \[sub\] ns2.other.alt -> 127.0.0.4" && expect "^www.glueless.test.*192.0.2.2" \
    && expect "trace2: NOERROR for www.glueless.test" && expect "in 1 sub-resolution" && ok

run "brief hides sub-resolution summary" www.glueless.test A +trace2=brief
expect "trace2: NOERROR for www.glueless.test" && expect_not "\[sub\]" && ok

run "verbose shows sub-resolution hops" www.glueless.test A +trace2=verbose
expect "^;; \[sub 1\] ns2.other.alt/A @127.0.0.2(ns.tld) for alt" \
    && expect "^;; \[sub 1\] ns2.other.alt/A @127.0.0.3(ns.other.alt) for other.alt" && ok

run "CNAME to another zone is followed" alias.example.test A +trace2
expect "following alias alias.example.test -> www.glueless.test" \
    && expect "^www.glueless.test.*192.0.2.2" && expect "trace2: NOERROR for www.glueless.test" && ok

run "DNAME is synthesized and followed" x.dn.example.test A +trace2
expect "following alias x.dn.example.test -> x.other.alt" && expect "^x.other.alt.*192.0.2.9" && ok

run "CNAME loop is detected" loopa.example.test A +trace2
expect "resolution failed: CNAME/DNAME loop at loopa.example.test" && expect "trace2: SERVFAIL for loopa.example.test" && ok

run "NXDOMAIN" nx.example.test A +trace2
expect "trace2: NXDOMAIN for nx.example.test" && ok

run "NODATA" www.example.test TXT +trace2
expect "trace2: NOERROR (no data) for www.example.test" && ok

run "DS is answered by the parent zone" example.test DS +trace2
expect "^example.test.*DS.*12345 8 2" && expect "(ns.tld)" && expect "trace2: NOERROR for example.test" && ok

run "lame server is skipped" www.lame.test A +trace2
expect "^www.lame.test.*192.0.2.3" && expect "trace2: NOERROR for www.lame.test" && ok

run "all servers lame" www.alllame.test A +trace2
expect "lame server 127.0.0.5(ns.alllame.test) for alllame.test" && expect "resolution failed" \
    && expect "trace2: SERVFAIL" && ok

run "NS dependency loop terminates" www.loop1.test A +trace2
expect "couldn't get address for 'ns.loop2.alt': dependency loop on ns.loop2.alt (nameservers of loop2.alt)"     && expect "resolution failed: dependency loop on ns.loop2.alt (nameservers of loop1.test)" \
    && expect "resolution failed" && expect "trace2: SERVFAIL for www.loop1.test" && ok

run "TC=1 over UDP falls back to TCP" www.tc.test A +trace2
expect "^www.tc.test.*192.0.2.10" && expect "trace2: NOERROR for www.tc.test" && ok

run "FORMERR to EDNS is retried without EDNS" www.noedns.test A +trace2 +edns
expect "FORMERR from 127.0.0.5, retrying without EDNS" && expect "^www.noedns.test.*192.0.2.11" \
    && expect "trace2: NOERROR for www.noedns.test" && ok

run "query budget" www.glueless.test A +trace2 +trace2-maxqueries=3
expect "query budget exhausted (3 queries)" && ok

run "qname minimisation (A probes)" deep.a.b.example.test A +trace2 +qmin
expect "^deep.a.b.example.test.*192.0.2.7" && expect "trace2: NOERROR for deep.a.b.example.test" && ok

run "qname minimisation (NS probes)" deep.a.b.example.test A +trace2 +qmin=ns
expect "^deep.a.b.example.test.*192.0.2.7" && ok

run "qname minimisation hides full name from the root" www.example.test A +trace2=verbose +qmin +nohexdump-response +hexdump-query
# ルートへの問い合わせ (2 番目の Query) に "www" ラベル (03 77 77 77) が含まれないこと
awk '/^Query/{q++} q==2' "$OUT" | sed '/^$/q' > "$WORK/q2.txt"
if grep -q "03 77 77 77" "$WORK/q2.txt"; then
    echo "[FAIL] $NAME: full qname was sent to the root"; sed 's/^/    | /' "$OUT"; FAIL=$((FAIL + 1))
else
    ok
fi

run "+glue=indomain ignores sibling glue" www.sibling.test A +trace2 +glue=indomain
expect "^www.sibling.test.*192.0.2.4" && ok

run "yaml output" www.example.test A +trace2 +yaml
expect "type: AUTH_RESPONSE" && expect_not "trace2:" && ok

run "short output" www.glueless.test A +trace2 +short
expect "^192.0.2.2$" && expect_not "Received" && ok

printf '. 3600000 NS a.root-servers.\na.root-servers. 3600000 A 127.0.0.1\n' > "$WORK/named.root"
NAME="+roothints file without @server"
OUT="$WORK/out.txt"
"$DAG_BIN" -p "$PORT" +nohexdump +noldnsz +time=2 www.example.test A +trace2 +roothints="$WORK/named.root" > "$OUT" 2>&1
expect "(a.root-servers)" && expect "trace2: NOERROR for www.example.test" && ok

run "timeout moves to the next server and fails when none answers" www.deadonly.test A +trace2 +time=1
expect "connection to 127.0.0.5#$PORT(ns.deadonly.test) for deadonly.test failed; trying next server" \
    && expect "resolution failed: all nameservers for deadonly.test failed" && expect ", 1 timeout," && ok

run "out-of-bailiwick glue is ignored even with +glue=all" www.child.mockp.test A +trace2 +glue=all
expect "ignoring out-of-bailiwick glue for 'ns.evil.alt' (not under mockp.test)" \
    && expect "couldn't get address for 'ns.evil.alt': NXDOMAIN" && expect "resolution failed" \
    && expect_not "127.0.0.66" && ok

run "in-domain NS without glue" www.noglue.test A +trace2
expect "no glue for in-domain nameserver 'ns.noglue.test' of 'noglue.test'" && expect "resolution failed" && ok

run "CNAME loop across zones is detected" xloop.example.test A +trace2
expect "following alias xloop.example.test -> yloop.other.alt" \
    && expect "resolution failed: CNAME loop at xloop.example.test" && ok

run "qname minimisation falls back on NXDOMAIN" a.b.nx.example.test A +trace2 +qmin
expect "qname minimisation: NXDOMAIN for nx.example.test/A, retrying with full name" \
    && expect "trace2: NXDOMAIN for a.b.nx.example.test" && ok

run "short output with TTL" www.example.test A +trace2 +short +ttlid
expect "^3600 192.0.2.1$" && ok

NAME="-6 with an IPv4-only root"
"$DAG_BIN" -6 @127.0.0.1 -p "$PORT" +nohexdump +noldnsz www.example.test A +trace2 > "$OUT" 2>&1
RC=$?
expect "no usable root server address" && expect "priming failed" && [ "$RC" -eq 9 ] && ok

NAME="-6 priming failure in YAML"
"$DAG_BIN" -6 @127.0.0.1 -p "$PORT" +nohexdump +noldnsz www.example.test A +trace2 +yaml > "$OUT" 2>&1
expect "type: DIG_ERROR" && ok

NAME="unreachable IPv6 root hint"
printf 'a.root-servers. ::1\n' > "$WORK/named6.root"
"$DAG_BIN" -6 -p "$PORT" +nohexdump +noldnsz +time=1 www.example.test A +trace2 +roothints="$WORK/named6.root" > "$OUT" 2>&1
expect "connection to ::1#$PORT(a.root-servers) for . failed" && expect "priming failed" && ok

NAME="@server given as a host name is resolved iteratively"
"$DAG_BIN" @a.root-servers -p "$PORT" +nohexdump +noldnsz +time=2 www.example.test A +trace2 +roothints="$WORK/named.root" > "$OUT" 2>&1
expect "(a.root-servers)" && expect "trace2: NOERROR for www.example.test" && ok

NAME="unreadable +roothints file"
"$DAG_BIN" www.example.test A +trace2 +roothints="$WORK/does-not-exist" > "$OUT" 2>&1
RC=$?
expect "dag: +roothints: " && [ "$RC" -eq 1 ] && ok

NAME="priming answer without glue uses the priming server itself"
"$DAG_BIN" @127.0.0.5 -p "$PORT" +nohexdump +noldnsz +time=2 www.example.test A +trace2 > "$OUT" 2>&1
expect "a.root-servers." && expect "lame server 127.0.0.5(127.0.0.5) for .: REFUSED" && expect "resolution failed" && ok

NAME="priming to a non-root server fails"
"$DAG_BIN" @127.0.0.3 -p "$PORT" +nohexdump +noldnsz +time=2 www.example.test A +trace2 > "$OUT" 2>&1
RC=$?
expect "priming query to 127.0.0.3 failed" && expect "priming failed" && [ "$RC" -eq 9 ] && ok

NAME="+ldnsz trace URL has one entry per main-path hop"
# glueless: プライミング / ルート / test. / glueless.test. の 4 hop。NS 名の再帰解決の 3 hop は含めない
"$DAG_BIN" @127.0.0.1 -p "$PORT" +nohexdump +time=2 www.glueless.test A +trace2 +ldnsz > "$OUT" 2>&1
if expect "https://ldns.jp/trace/#c="; then
    hops=$(grep "https://ldns.jp/trace/#c=" "$OUT" | sed 's/.*#c=//' | tr ',' '\n' | grep -c '|UDP|')
    if [ "$hops" -eq 4 ]; then ok; else echo "[FAIL] $NAME: expected 4 hops, got $hops"; FAIL=$((FAIL + 1)); fi
fi

NAME="batch file (-f) inherits +trace2"
printf 'www.example.test A\nwww.glueless.test A\n' > "$WORK/batch.txt"
"$DAG_BIN" @127.0.0.1 -p "$PORT" +nohexdump +noldnsz +time=2 +trace2 -f "$WORK/batch.txt" > "$OUT" 2>&1
expect "trace2: NOERROR for www.example.test" && expect "trace2: NOERROR for www.glueless.test" \
    && expect "\[sub\] ns2.other.alt" && ok

NAME="+trace2 and +trace are exclusive"
"$DAG_BIN" -p "$PORT" www.example.test +trace2 +trace > "$OUT" 2>&1
expect "cannot be combined" && ok

NAME="invalid +trace2 mode"
"$DAG_BIN" www.example.test +trace2=bogus > "$OUT" 2>&1
expect "invalid +trace2 mode" && ok

echo
echo "dag +trace2: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
