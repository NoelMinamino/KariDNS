#!/bin/sh
# dnsqps client cookies (RFC 7873 4.1) as a server sees them: a small UDP server (perl, core modules only) records the client cookie of every query it gets
# and answers it (QR set), dnsqps runs against it on loopback over the socket paths.  +cookie=random must give a new 8-octet cookie in (nearly) every query,
# +cookie the same cookie in all of them, +cookie=HEX16 exactly that one, and a query file may mix them line by line.  The raw paths patch the same bytes
# into pre-built frames (unit tests and tests/run_dnsqps_netmap_test.sh).  SKIP without perl.  No real domain names: example.test.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib_proc.sh"
cd "$DIR/.." || exit 1
DQ="${DNSQPS:-./dnsqps}"
[ -x "$DQ" ] || { echo "SKIP: no $DQ"; exit 0; }
command -v perl >/dev/null 2>&1 || { echo "SKIP: no perl"; exit 0; }
PORT=$(kari_port 0 15731)
T=$(mktemp -d "${TMPDIR:-/tmp}/dnsqps_cookie.XXXXXX")
SRV=""
cleanup() {
    set +e
    [ -n "$SRV" ] && kill "$SRV" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM
FAILED=0
fail() { echo "FAIL: $*"; FAILED=1; }
jnum() { sed -n "s/.*\"$1\":\([0-9.]*\).*/\1/p" | head -1; }

cat > "$T/srv.pl" <<'PERL'
use strict; use warnings; use IO::Socket::INET;
my ($port, $out) = @ARGV;
my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Proto => 'udp') or die "bind: $!";
open(my $o, '>>', $out) or die; select((select($o), $| = 1)[0]);
print STDERR "ready\n";
my $buf;
while ($s->recv($buf, 4096)) {
    my $n = length $buf; next if $n < 12;
    my $p = 12;
    while ($p < $n && ord(substr($buf, $p, 1)) != 0) { $p += ord(substr($buf, $p, 1)) + 1 }
    $p += 1 + 4;                                  # the root label, QTYPE and QCLASS
    my $ck = '-';
    if ($p + 11 <= $n && ord(substr($buf, $p, 1)) == 0 && unpack('n', substr($buf, $p + 1, 2)) == 41) {
        my $rd = unpack('n', substr($buf, $p + 9, 2)); my $q = $p + 11; my $end = $q + $rd; $end = $n if $end > $n;
        while ($q + 4 <= $end) {
            my ($code, $len) = unpack('nn', substr($buf, $q, 4));
            if ($code == 10 && $len == 8 && $q + 4 + 8 <= $end) { $ck = unpack('H16', substr($buf, $q + 4, 8)); last }
            $q += 4 + $len;
        }
    }
    print $o "$ck\n";
    substr($buf, 2, 1) = chr(ord(substr($buf, 2, 1)) | 0x80);
    $s->send($buf);
}
PERL
perl "$T/srv.pl" "$PORT" "$T/seen.txt" 2> "$T/srv.err" &
SRV=$!
i=0
until grep -q ready "$T/srv.err" 2>/dev/null; do
    i=$((i + 1)); kill -0 "$SRV" 2>/dev/null || { cat "$T/srv.err"; echo "SKIP: the perl server cannot start"; exit 0; }
    [ "$i" -le 100 ] || { fail "the perl server did not start"; exit 1; }
    sleep 0.1
done
printf 'www.example.test A\nmail.example.test MX\nodd.example.test AAAA\n' > "$T/q.txt"

# run LABEL ARGS...: one run; the cookies the server saw are in $T/seen.txt (it is read until as many lines as answers were counted, bounded)
run() {
    label=$1; shift
    : > "$T/seen.txt"
    "$DQ" -r -s 127.0.0.1 -p "$PORT" -d "$T/q.txt" -N 2000 -T 1 -q 32 -t 1 --json "$@" > "$T/o.json" 2> "$T/o.err" || { cat "$T/o.err"; fail "$label: exit $?"; return 1; }
    sent=$(jnum sent < "$T/o.json")
    k=0
    while [ "$(wc -l < "$T/seen.txt" | tr -d ' ')" -lt "${sent:-0}" ] && [ "$k" -lt 50 ]; do k=$((k + 1)); sleep 0.1; done   # the server writes after it answered: bounded wait
    seen=$(wc -l < "$T/seen.txt" | tr -d ' ')
    distinct=$(sort -u "$T/seen.txt" | wc -l | tr -d ' ')
    if [ "$seen" -lt $((sent * 95 / 100)) ]; then fail "$label: the server saw $seen of $sent queries"; return 1; fi
    return 0
}

for io in sendto mmsg; do
    [ "$io" = mmsg ] && { case "$(uname -s)" in Linux|FreeBSD) ;; *) continue ;; esac; }
    run "random, $io" --io "$io" +cookie=random && {
        # 2^64 values: a repeat among 2000 would be a bug of the generator
        [ "$distinct" -ge $((seen - 2)) ] || fail "+cookie=random ($io): $distinct different cookies in $seen queries"
        grep -qv '^[0-9a-f]\{16\}$' "$T/seen.txt" && fail "+cookie=random ($io): a query without a client cookie"
        echo "ok: +cookie=random ($io): $distinct different cookies in $seen queries"
    }
    run "fixed, $io" --io "$io" +cookie && {
        [ "$distinct" -eq 1 ] || fail "+cookie ($io): $distinct different cookies, expected 1"
        echo "ok: +cookie ($io): one cookie in $seen queries"
    }
    run "hex, $io" --io "$io" +cookie=0123456789abcdef && {
        [ "$distinct" -eq 1 ] && [ "$(head -1 "$T/seen.txt")" = "0123456789abcdef" ] || fail "+cookie=HEX16 ($io): $(sort -u "$T/seen.txt" | head -3 | tr '\n' ' ')"
        echo "ok: +cookie=0123456789abcdef ($io)"
    }
    run "none, $io" --io "$io" +edns && {
        [ "$distinct" -eq 1 ] && [ "$(head -1 "$T/seen.txt")" = "-" ] || fail "+edns without a cookie ($io) sent one"
        echo "ok: no cookie unless asked ($io)"
    }
done

# one line random, one fixed, one without: about a third of the queries have a new cookie each, a third the same one, a third none
printf 'www.example.test A +cookie=random\nmail.example.test MX +cookie\nodd.example.test AAAA\n' > "$T/q.txt"
run "mixed lines" && {
    nonec=$(grep -c '^-$' "$T/seen.txt"); rnd=$(grep -v '^-$' "$T/seen.txt" | sort | uniq -c | awk '$1 == 1' | wc -l | tr -d ' ')
    [ "$nonec" -ge $((seen * 25 / 100)) ] && [ "$nonec" -le $((seen * 42 / 100)) ] || fail "mixed lines: $nonec queries without a cookie of $seen"
    [ "$rnd" -ge $((seen * 25 / 100)) ] || fail "mixed lines: only $rnd single-use cookies in $seen queries"
    echo "ok: per-line mix: $nonec without, $rnd random"
}

# a repeatable run: the same --seed, the same cookie sequence is not promised, but a different value per run is: two runs differ
run "run 1" +cookie=random --seed 5 -N 100 && cp "$T/seen.txt" "$T/a.txt"
run "run 2" +cookie=random --seed 6 -N 100 && cp "$T/seen.txt" "$T/b.txt"
[ -s "$T/a.txt" ] && ! cmp -s "$T/a.txt" "$T/b.txt" || fail "two runs with different seeds saw the same cookies"

[ "$FAILED" -eq 0 ] || { echo "FAIL: dnsqps cookie test"; exit 1; }
echo "PASS: dnsqps cookie test"
exit 0
