#!/bin/sh
# ==============================================================================
# run_karictl_store_test.sh - karictl store (0.7 WP5): text, -j JSON, -k key=value, zone <name>
#
#   A  a running server WITHOUT a store (state=none): the three forms answer, every form carries the same keys, the JSON is one valid
#      object with the attach counters (all zero) and the memory figures, the key=value lines have no repeated key, the text has its
#      sections and no histogram buckets, zone <name> and a bad argument are answered ERROR (exit 3), and a restricted read-only key
#      may ask (store is a read command)
#   B  polling: ten requests in a row return the same keys; the counters do not reset when read
#
# WP4 extends this with a server that has a store (zones, attaches, cold queries).  SKIP (exit 0, with the reason) without karidns, karictl.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS=${KARIDNS:-$ROOT_DIR/karidns}
KARICTL=${KARICTL:-$ROOT_DIR/karictl}
for b in "$KARIDNS" "$KARICTL"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karictl_store.XXXXXX") || exit 1
chmod 755 "$T"
SERVER_PID=""
cleanup() {
    set +e
    [ -n "$SERVER_PID" ] && kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$T/karidns.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

PORT=$(kari_port 0 $((26000 + $$ % 4000)))
CTRL_SOCK="$T/control.sock"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"
MAIN_SECRET="c3RvcmUtdGVzdC1zZWNyZXQta2V5LTAwMQ=="
WEB_SECRET="c3RvcmUtdGVzdC13ZWIta2V5LXNlY3JldC0wMDI="

cat > "$T/one.zone" <<'EOF'
$TTL 300
@ IN SOA ns1 hostmaster 2026111401 3600 600 86400 300
@ IN NS ns1
ns1 IN A 127.0.0.1
www IN A 192.0.2.1
EOF
cat > "$T/karidns.conf" <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
};
key "web" { algorithm hmac-sha256; secret "$WEB_SECRET"; };
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "$MAIN_SECRET"; keys { "web" read-only yes; }; };
zone "a.example.test" { type primary; file "$T/one.zone"; };
EOF
cat > "$T/karictl.conf" <<EOF
socket "$CTRL_SOCK";
key "karictl" { algorithm hmac-sha256; secret "$MAIN_SECRET"; };
EOF
cat > "$T/web.conf" <<EOF
socket "$CTRL_SOCK";
key "web" { algorithm hmac-sha256; secret "$WEB_SECRET"; };
EOF
chmod 644 "$T/one.zone" "$T/karidns.conf"
chmod 600 "$T/karictl.conf" "$T/web.conf"
ctl() { "$KARICTL" -s "$CTRL_SOCK" -f "$T/karictl.conf" "$@"; }

echo "== starting karidns on port $PORT"
"$KARIDNS" -f "$T/karidns.conf" > "$T/karidns.out" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 100 ]; do
    [ -S "$CTRL_SOCK" ] && ctl status > /dev/null 2>&1 && break
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.3
    i=$((i + 1))
done
if ! ctl status > /dev/null 2>&1; then
    echo "FAIL: karidns does not answer on the control channel"; tail -20 "$T/karidns.out"; exit 1
fi

# ---------------------------------------------------------------- A. no store
echo "== A. karictl store without a store (state=none)"
ctl store > "$T/s.txt" 2> "$T/s.err"; st=$?
[ "$st" = 0 ] && ok "karictl store: exit 0" || bad "karictl store: exit $st" "$(cat "$T/s.err")"
grep -q '^  state = none$' "$T/s.txt" && ok "text: state = none" || bad "text: no 'state = none'" "$(head -20 "$T/s.txt")"
grep -q '^attach:$' "$T/s.txt" && grep -q '^cold:$' "$T/s.txt" && grep -q '^memory:$' "$T/s.txt" && ok "text: the sections attach, cold and memory" || bad "text sections" "$(cat "$T/s.txt")"
grep -q 'hist' "$T/s.txt" && bad "the text has histogram buckets" || ok "text: no histogram buckets"
grep -q '^  count = 0$' "$T/s.txt" && ok "text: counters are zero without a store" || bad "text: counters" "$(cat "$T/s.txt")"
grep -q '^  available = 1$' "$T/s.txt" && ok "text: the memory figures are there" || bad "text: memory.available" "$(sed -n '/^memory:/,$p' "$T/s.txt")"

ctl store -k > "$T/s.kv" 2> "$T/s.err"; st=$?
[ "$st" = 0 ] && ok "karictl store -k: exit 0" || bad "-k: exit $st" "$(cat "$T/s.err")"
grep -q -v -E '^[a-z0-9_.]+=[^ ]+$|^[a-z0-9_.]+="[^"]*"$' "$T/s.kv" && bad "a line of -k is not key=value" "$(grep -v -E '^[a-z0-9_.]+=' "$T/s.kv" | head -3)" || ok "-k: every line is key=value"
dups=$(sed 's/=.*//' "$T/s.kv" | sort | uniq -d)
[ -z "$dups" ] && ok "-k: no key twice" || bad "-k: keys twice" "$dups"
for k in schema store.state store.time.mono_ms store.time.unix store.attach.count store.attach.p50_us store.attach.p99_us store.attach.hist.le_1us \
         store.attach.hist.more store.attach.fail.checksum store.detach.count store.cold.attach store.cold.fetch store.cold.p50_us \
         store.memory.available store.memory.zones store.memory.level; do
    grep -q "^$k=" "$T/s.kv" || bad "-k: key $k missing" "$(head -5 "$T/s.kv")"
done
grep -q '^store.state=none$' "$T/s.kv" && grep -q '^schema=1$' "$T/s.kv" && ok "-k: schema=1, store.state=none" || bad "-k: schema / state" "$(head -5 "$T/s.kv")"
grep -q '^store.zones\.' "$T/s.kv" && bad "-k: store keys without a store" || ok "-k: no store.zones.* without a store"

ctl store -j > "$T/s.json" 2> "$T/s.err"; st=$?
[ "$st" = 0 ] && ok "karictl store -j: exit 0" || bad "-j: exit $st" "$(cat "$T/s.err")"
[ $(wc -l < "$T/s.json") -eq 1 ] && ok "-j: one line" || bad "-j: not one line"
if perl -MJSON::PP -e 1 2>/dev/null; then
    cat > "$T/chk.pl" <<'EOF'
use strict; use warnings; use JSON::PP;
local $/; open my $f, '<', $ARGV[0] or die; my $d = JSON::PP->new->decode(<$f>); $/ = "\n";
open my $k, '<', $ARGV[1] or die; my %kv = map { chomp; /^([^=]+)=/ ? (scalar("$1") => 1) : () } <$k>;
die "schema\n" unless $d->{schema} == 1;
die "state\n" unless $d->{'store.state'} eq 'none';
for my $key (keys %kv) { die "kv key $key not in json\n" unless exists $d->{$key}; }
for my $key (keys %$d) { die "json key $key not in kv\n" unless $kv{$key}; }
for my $key (qw(store.attach.count store.attach.p99_us store.cold.fetch store.time.mono_ms store.memory.available)) {
    die "$key not a number\n" unless defined $d->{$key} && $d->{$key} =~ /^\d+$/ && !ref $d->{$key} && JSON::PP::is_bool($d->{$key}) == 0;
}
die "level\n" unless $d->{'store.memory.level'} =~ /^(ok|notice|warning|error)$/;
print "ok\n";
EOF
    r=$(perl "$T/chk.pl" "$T/s.json" "$T/s.kv" 2>&1)
    [ "$r" = ok ] && ok "-j: one valid object with the keys of -k and numbers as numbers" || bad "-j check" "$r"
else
    echo "  (perl JSON::PP is missing: the JSON check is reduced)"
    grep -q '^{"schema":1,' "$T/s.json" && grep -q '"store.state":"none"' "$T/s.json" && ok "-j: starts with the schema and says none" || bad "-j" "$(head -c 300 "$T/s.json")"
fi

# errors
ctl store zone a.example.test > "$T/e1.out" 2> "$T/e1.err"; st=$?
[ "$st" = 3 ] && grep -q 'ERROR store not configured' "$T/e1.out" && ok "zone without a store: ERROR, exit 3" || bad "zone without a store: exit $st" "$(cat "$T/e1.out" "$T/e1.err")"
ctl store -x > "$T/e2.out" 2> "$T/e2.err"; st=$?
[ "$st" = 3 ] && grep -q 'ERROR usage' "$T/e2.out" && ok "a bad argument: usage ERROR, exit 3" || bad "bad argument: exit $st" "$(cat "$T/e2.out" "$T/e2.err")"
ctl store zone > "$T/e3.out" 2> "$T/e3.err"; st=$?
[ "$st" = 3 ] && grep -q 'ERROR' "$T/e3.out" && ok "zone without a name: ERROR, exit 3" || bad "zone without a name: exit $st" "$(cat "$T/e3.out" "$T/e3.err")"
"$KARICTL" --help 2>&1 | grep -q 'store \[-j | -k\]' && ok "--help lists the command" || bad "--help has no store line"

# a restricted read-only key asks (store is a read command)
"$KARICTL" -s "$CTRL_SOCK" -f "$T/web.conf" store -k > "$T/w.kv" 2> "$T/w.err"; st=$?
if [ "$st" = 0 ] && grep -q '^store.state=none$' "$T/w.kv"; then ok "a read-only key may ask for the store"; else bad "read-only key: exit $st" "$(cat "$T/w.kv" "$T/w.err" | head -5)"; fi
"$KARICTL" -s "$CTRL_SOCK" -f "$T/web.conf" reconfig > "$T/w2.out" 2>&1; st=$?
[ "$st" != 0 ] && ok "(control: the same key may not reconfig)" || bad "the read-only key reconfigured"

# ---------------------------------------------------------------- B. polling
echo "== B. polling"
n=0; same=1
ctl store -k | sed 's/=.*//' > "$T/keys0.txt"
while [ $n -lt 10 ]; do
    ctl store -k | sed 's/=.*//' > "$T/keysN.txt"
    cmp -s "$T/keys0.txt" "$T/keysN.txt" || same=0
    n=$((n + 1))
done
[ "$same" = 1 ] && ok "ten polls in a row: the same keys every time" || bad "the key list changed between polls"
size=$(ctl store -j | wc -c)
[ "$size" -gt 500 ] && [ "$size" -lt 32768 ] && ok "-j: $size bytes, below the 32 KiB bound" || bad "-j size $size"
ctl store -k | grep -q '^store.memory.available=1$' && ok "the memory figures are in the poll" || bad "store.memory.available"

echo
echo "karictl store: $PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
