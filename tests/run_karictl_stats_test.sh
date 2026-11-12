#!/bin/sh
# ==============================================================================
# run_karictl_stats_test.sh - karictl stats (Prometheus text and JSON, paging, filters) and options / zone alerts { } (0.6.1)
#
#   A  karicheck conf: the alerts { } statements (valid forms silent; unknown statement, bad ranges, interval and reload-failures-above in a
#      zone block, an empty block) with the codes conf.alerts.option / conf.alerts.range / conf.alerts.empty
#   B  karictl stats against a running server with 2104 zones (4 named ones and 2100 generated: two pages of 2000 and 104):
#      the server part (queries by transport, responses by RCODE, the unzoned REFUSED, version, zone count), the text format (every sample
#      line valid, HELP / TYPE once, every zone once and in order across the pages), JSON (valid document, same numbers), one zone, --zones,
#      --limit and the --after continuation, the errors (unknown zone, bad options: exit 2)
#   C  alerts: options { alerts { interval 10; qps-above 0; ... } } with a zone that inherits and overrides: "alert: ..." exactly once while
#      the value stays above its limit (load kept up for two intervals), "alert cleared: ..." once when it is quiet, for the server (queries),
#      a zone that takes the options limit, a zone that replaces it (no alert), a failed secondary refresh and a failed reload
#
# SKIP (exit 0, with the reason) without karidns, karictl and dag.  Part C takes about 45 s.
# ==============================================================================
. "$(dirname "$0")/lib_proc.sh"
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KARIDNS=${KARIDNS:-$ROOT_DIR/karidns}
KARICTL=${KARICTL:-$ROOT_DIR/karictl}
DAG=${DAG:-$ROOT_DIR/dag}
KC=${KC:-$ROOT_DIR/karicheck}
for b in "$KARIDNS" "$KARICTL" "$DAG"; do
    [ -x "$b" ] || { echo "SKIP: $b is not built"; exit 0; }
done

PASS=0; FAILS=0
ok() { PASS=$((PASS + 1)); echo "  [ OK ] $1"; }
bad() { FAILS=$((FAILS + 1)); echo "  [FAIL] $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | head -12 | sed 's/^/         /'; }

T=$(mktemp -d "${TMPDIR:-/tmp}/karictl_stats.XXXXXX") || exit 1
chmod 755 "$T"
SERVER_PID=""
LOAD_PID=""
cleanup() {
    set +e
    [ -n "$LOAD_PID" ] && kill "$LOAD_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kari_kill_tree "$SERVER_PID"
    kari_kill_conf "$T/karidns.conf"
    if [ -n "${KEEP:-}" ]; then echo "(kept $T)"; else rm -rf "$T"; fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- A. karicheck
echo "== A. karicheck conf: alerts { }"
if [ -x "$KC" ]; then
    kc() {   # kc DESC WANT-STATUS 'configuration' WANT-TEXT-OR-EMPTY
        printf '%s\n' "$3" > "$T/kc.conf"
        out=$("$KC" conf "$T/kc.conf" 2>&1); st=$?
        if [ "$st" != "$2" ]; then bad "$1: exit $st, wanted $2" "$out"; return; fi
        if [ -n "$4" ] && ! printf '%s' "$out" | grep -q "$4"; then bad "$1: no \"$4\" in the output" "$out"; return; fi
        ok "$1"
    }
    kc "valid options block" 0 'options { alerts { interval 10; qps-above 200000; servfail-ratio-above 0.5; rrl-drops-above 1000; transfer-failures-above 0; reload-failures-above 0; }; };' ''
    kc "valid zone block" 0 'zone "a.test" { type master; file "/x"; alerts { qps-above 5; servfail-ratio-above 1; rrl-drops-above 0; transfer-failures-above 2; }; };' ''
    kc "unknown statement" 1 'options { alerts { qps-over 5; }; };' "unknown statement 'qps-over'"
    kc "interval below 10" 1 'options { alerts { interval 5; }; };' 'interval 5 is outside 10..3600'
    kc "interval above 3600" 1 'options { alerts { interval 3601; }; };' 'interval 3601 is outside 10..3600'
    kc "ratio above 100" 1 'options { alerts { servfail-ratio-above 101; }; };' 'outside 0..100'
    kc "negative limit" 1 'options { alerts { qps-above -1; }; };' 'outside 0 and above'
    kc "not a number" 1 'options { alerts { qps-above many; }; };' 'is not a number'
    kc "interval in a zone" 1 'zone "a.test" { type master; file "/x"; alerts { interval 20; }; };' 'options { alerts { } } only'
    kc "reload-failures-above in a zone" 1 'zone "a.test" { type master; file "/x"; alerts { reload-failures-above 1; }; };' 'options { alerts { } } only'
    kc "an empty block is a warning" 0 'options { alerts { }; };' 'sets no limit'
    if perl -MJSON::PP -e 1 2>/dev/null; then
        printf '%s\n' 'options { alerts { interval 5; }; alerts { }; };' > "$T/kc.conf"
        "$KC" --json conf "$T/kc.conf" > "$T/kc.json" 2>/dev/null
        if grep -q '"conf.alerts.range"' "$T/kc.json"; then ok "--json: conf.alerts.range"; else bad "--json: conf.alerts.range missing" "$(head -c 400 "$T/kc.json")"; fi
        printf '%s\n' 'options { alerts { }; };' > "$T/kc.conf"
        "$KC" --json conf "$T/kc.conf" > "$T/kc.json" 2>/dev/null
        if grep -q '"conf.alerts.empty"' "$T/kc.json"; then ok "--json: conf.alerts.empty"; else bad "--json: conf.alerts.empty missing" "$(head -c 400 "$T/kc.json")"; fi
    fi
else
    echo "  (karicheck is not built: part A skipped)"
fi

# ---------------------------------------------------------------- the server
PORT=$(kari_port 0 $((26000 + $$ % 4000)))
DEADPORT=$(kari_port 5 $((PORT + 5)))
CTRL_SOCK="$T/control.sock"
LOG="$T/karidns-alerts.log"
USER_OPT=""
[ "$(id -u)" = "0" ] && USER_OPT="user \"nobody\"; group \"nobody\";"

cat > "$T/one.zone" <<'EOF'
$TTL 300
@ IN SOA ns1 hostmaster 2026111101 3600 600 86400 300
@ IN NS ns1
ns1 IN A 127.0.0.1
www IN A 192.0.2.1
EOF
{
    cat <<EOF
options {
    port $PORT;
    bind-address { 127.0.0.1; };
    $USER_OPT
    alerts { interval 10; qps-above 0; transfer-failures-above 0; reload-failures-above 0; };
};
control-channel { socket "$CTRL_SOCK"; algorithm hmac-sha256; secret "c3RhdHMtdGVzdC1zZWNyZXQta2V5LTAwMQ=="; };
logging {
    channel alog { file "$LOG" versions unlimited size 20m; severity info; print-severity yes; };
    category general { alog; };
};
zone "a.example.test" { type primary; file "$T/one.zone"; alerts { servfail-ratio-above 90; }; };
zone "b.example.test" { type primary; file "$T/one.zone"; alerts { qps-above 1000000; }; };
zone "example.test" { type primary; file "$T/one.zone"; };
zone "s.example.test" { type slave; masters { 127.0.0.1 port $DEADPORT; }; file "$T/s.example.test.zone"; };
EOF
    i=1
    while [ $i -le 2100 ]; do
        printf 'zone "z%04d.bulk.test" { type primary; file "%s/one.zone"; };\n' $i "$T"
        i=$((i + 1))
    done
} > "$T/karidns.conf"
cat > "$T/karictl.conf" <<EOF
socket "$CTRL_SOCK";
key "karictl" { algorithm hmac-sha256; secret "c3RhdHMtdGVzdC1zZWNyZXQta2V5LTAwMQ=="; };
EOF
chmod 644 "$T/one.zone" "$T/karidns.conf"
chmod 600 "$T/karictl.conf"
ctl() { "$KARICTL" -s "$CTRL_SOCK" -f "$T/karictl.conf" "$@"; }

echo "== starting karidns on port $PORT (2104 zones)"
"$KARIDNS" -f "$T/karidns.conf" > "$T/karidns.out" 2>&1 &
SERVER_PID=$!
i=0
while [ $i -lt 100 ]; do
    "$DAG" @127.0.0.1 -p "$PORT" www.a.example.test A +short +nohexdump 2>/dev/null | grep -q 192.0.2.1 && break
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 0.3
    i=$((i + 1))
done
if ! "$DAG" @127.0.0.1 -p "$PORT" www.a.example.test A +short +nohexdump 2>/dev/null | grep -q 192.0.2.1; then
    echo "FAIL: karidns does not answer"; tail -20 "$T/karidns.out"; exit 1
fi
sleep 3   # the first check of the alerts only takes the starting values

# the load of part C: a query to zone a every 0.2 s for 12 s (the first interval and part of the second), started now
( n=0; while [ $n -lt 60 ]; do "$DAG" @127.0.0.1 -p "$PORT" www.a.example.test A +short +nohexdump >/dev/null 2>&1; sleep 0.2; n=$((n + 1)); done ) &
LOAD_PID=$!

# traffic for part B: zone a and b (UDP, TCP, NXDOMAIN), a name no zone has (REFUSED), a failed refresh and a failed reload (for the alerts)
dq() { "$DAG" @127.0.0.1 -p "$PORT" "$@" +nohexdump >/dev/null 2>&1; }
for _ in 1 2 3 4 5; do dq www.b.example.test A; done
dq www.b.example.test A +tcp
dq nothere.b.example.test A
dq www.nozone.invalid A
dq www.nozone.invalid A
ctl retransfer s.example.test > /dev/null 2>&1
cp "$T/karidns.conf" "$T/karidns.conf.good"
echo 'zone "broken.test" { type bogus; };' >> "$T/karidns.conf"
ctl reload > "$T/reload.out" 2>&1; rst=$?
cp "$T/karidns.conf.good" "$T/karidns.conf"   # (the server keeps the configuration it has; nothing reloads it again)
if [ "$rst" = 3 ]; then ok "the broken configuration is refused by karictl reload (exit 3)"; else bad "karictl reload of a broken configuration exited $rst" "$(cat "$T/reload.out")"; fi
sleep 1

# ---------------------------------------------------------------- B. karictl stats
echo "== B. karictl stats"
ctl stats > "$T/all.prom"; st=$?
if [ "$st" = 0 ]; then ok "karictl stats exits 0 (Prometheus text is the default)"; else bad "karictl stats exit $st" "$(head -5 "$T/all.prom")"; fi
# 0.6.2: one log line per listing (its first page), not one per page: this listing has two pages
n=$(grep -c ': obspage ' "$LOG" 2>/dev/null)
[ "${n:-0}" = 1 ] && ok "the two pages of the listing log one line" || bad "obspage lines in the log: ${n:-0}, want 1" "$(grep ': obspage ' "$LOG" | head -3)"
has() { grep -q -- "$1" "$2"; }
getv() { sed -n "s/^$1 //p" "$2" | head -1; }   # value of a sample whose name{labels} is exactly $1 (regex-free text)
has '^karidns_build_info{version="' "$T/all.prom" && ok "karidns_build_info has the version" || bad "karidns_build_info missing"
[ "$(getv 'karidns_zones' "$T/all.prom")" = 2104 ] && ok "karidns_zones 2104" || bad "karidns_zones: $(getv 'karidns_zones' "$T/all.prom")"
q_udp=$(getv 'karidns_queries_total{proto="udp"}' "$T/all.prom"); q_tcp=$(getv 'karidns_queries_total{proto="tcp"}' "$T/all.prom")
[ "${q_udp:-0}" -ge 5 ] 2>/dev/null && [ "${q_tcp:-0}" -ge 1 ] 2>/dev/null && ok "queries by transport (udp $q_udp, tcp $q_tcp)" || bad "queries by transport: udp=$q_udp tcp=$q_tcp"
unz=$(getv 'karidns_unzoned_responses_total{rcode="REFUSED"}' "$T/all.prom")
[ "${unz:-0}" -ge 2 ] 2>/dev/null && ok "REFUSED for a name no zone has is in karidns_unzoned_responses_total ($unz)" || bad "unzoned REFUSED: $unz"
tot_ref=$(getv 'karidns_responses_total{rcode="REFUSED"}' "$T/all.prom")
[ "${tot_ref:-0}" -ge "${unz:-1}" ] 2>/dev/null && ok "karidns_responses_total includes the unzoned responses" || bad "responses_total REFUSED $tot_ref < unzoned $unz"
[ "$(getv 'karidns_responses_total{rcode="NXDOMAIN"}' "$T/all.prom")" -ge 1 ] 2>/dev/null && ok "NXDOMAIN counted" || bad "NXDOMAIN not counted"
[ "$(getv 'karidns_reload_failures_total' "$T/all.prom")" -ge 1 ] 2>/dev/null && ok "the failed reload is counted" || bad "karidns_reload_failures_total"
[ "$(getv 'karidns_transfer_failures_total' "$T/all.prom")" -ge 1 ] 2>/dev/null && ok "the failed refresh is counted" || bad "karidns_transfer_failures_total"
nz=$(grep -c '^karidns_zone_serial{' "$T/all.prom")
[ "$nz" = 2104 ] && ok "every zone once across two pages ($nz karidns_zone_serial series)" || bad "zone series: $nz (wanted 2104)"
grep '^karidns_zone_serial{' "$T/all.prom" | sed 's/^karidns_zone_serial{zone="\([^"]*\)",view="\([^"]*\)".*/\2 \1/' > "$T/order.txt"
# (the order is the order of the server zone tables, not alphabetical: no ordering check; the continuation test below checks the sequence)
[ -z "$(sort "$T/order.txt" | uniq -d)" ] && ok "no zone twice" || bad "a zone twice"
# the exposition format: the samples of a metric family are one contiguous group (also across the two pages)
split=$(grep -v '^#' "$T/all.prom" | sed 's/[{ ].*//' | awk 'p != $0 { if (seen[$0]++) print $0; p = $0 }' | head -3)
[ -z "$split" ] && ok "every metric family is one contiguous group of samples" || bad "a metric family is split" "$split"
help_twice=$(grep '^# HELP ' "$T/all.prom" | sort | uniq -d)
[ -z "$help_twice" ] && ok "every # HELP line once" || bad "# HELP twice" "$help_twice"
dup=$(grep '^# TYPE ' "$T/all.prom" | sort | uniq -d)
[ -z "$dup" ] && ok "every # TYPE line once" || bad "# TYPE twice" "$dup"
badline=$(grep -v '^#' "$T/all.prom" | grep -v -E '^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-z_]+="([^"\\]|\\.)*"(,|\}))+)? -?[0-9]+(\.[0-9]+)?$' | head -3)
[ -z "$badline" ] && ok "every sample line is name{labels} number" || bad "an invalid sample line" "$badline"
va=$(grep '^karidns_zone_queries_total{zone="a.example.test' "$T/all.prom" | head -1)
[ -n "$va" ] && ok "the series of a zone: $va" || bad "no karidns_zone_queries_total for a.example.test"
has '^karidns_view_queries_total{view=' "$T/all.prom" && has '^karidns_view_zones{view=' "$T/all.prom" && ok "the full listing has the per-view sums" || bad "per-view sums missing"
view_sum=$(sed -n 's/^karidns_view_zones{view="[^"]*"} //p' "$T/all.prom" | awk '{s+=$1} END {print s}')
[ "$view_sum" = 2104 ] && ok "the views' zone counts add up to 2104" || bad "view zone sum: $view_sum"

# JSON
if perl -MJSON::PP -e 1 2>/dev/null; then
    ctl stats -f json > "$T/all.json"; st=$?
    cat > "$T/chk.pl" <<'EOF'
use strict; use warnings; use JSON::PP;
local $/; open my $f, '<', $ARGV[0] or die; my $d = decode_json(<$f>);
my $n = scalar @{ $d->{zones} };
die "zones $n\n" unless $n == 2104;
die "server.zones\n" unless $d->{server}{zones} == 2104;
die "version\n" unless length $d->{server}{version};
die "unzoned\n" unless $d->{server}{unzoned_responses}{REFUSED} >= 2;
my ($a) = grep { $_->{zone} =~ /^a\.example\.test/ } @{ $d->{zones} };
die "no zone a\n" unless $a && $a->{role} eq 'primary' && $a->{serial} == 2026111101;
die "views\n" unless ref $d->{views} eq 'ARRAY' && @{ $d->{views} };
my $s = 0; $s += $_->{zones} for @{ $d->{views} }; die "view sum $s\n" unless $s == 2104;
die "more\n" if $d->{more};
print "ok\n";
EOF
    r=$(perl "$T/chk.pl" "$T/all.json" 2>&1)
    if [ "$st" = 0 ] && [ "$r" = ok ]; then ok "-f json: one valid document with the server, 2104 zones and the views"; else bad "-f json (exit $st): $r" "$(head -c 300 "$T/all.json")"; fi
    ctl stats --format=json a.example.test > "$T/one.json"
    r=$(perl -MJSON::PP -e 'local $/; open my $f, "<", $ARGV[0]; my $d = decode_json(<$f>); print scalar(@{$d->{zones}}), " ", (exists $d->{views} ? "views" : "noviews"), "\n"' "$T/one.json" 2>&1)
    [ "$r" = "1 noviews" ] && ok "--format=json with a zone: that zone only, no view sums" || bad "json of one zone: $r"
else
    echo "  (perl JSON::PP is missing: the JSON checks are skipped)"
fi

# one zone, filters, paging
ctl stats a.example.test > "$T/z1.prom"; st=$?
[ "$st" = 0 ] && [ "$(grep -c '^karidns_zone_serial{' "$T/z1.prom")" = 1 ] && ok "stats <zone>: one zone" || bad "stats a.example.test (exit $st): $(grep -c '^karidns_zone_serial{' "$T/z1.prom") zones"
if grep -q '^karidns_view_' "$T/z1.prom"; then bad "stats <zone> has per-view sums (they would cover one zone only)"; else ok "stats <zone> has no per-view sums"; fi
ctl stats nosuch.test > "$T/none.out" 2> "$T/none.err"; st=$?
[ "$st" = 3 ] && ok "stats <unknown zone>: exit 3" || bad "unknown zone exit $st" "$(cat "$T/none.err")"
ctl stats --zones 'z00*.bulk.test' > "$T/glob.prom"
n=$(grep -c '^karidns_zone_serial{' "$T/glob.prom")
[ "$n" = 99 ] && ok "--zones 'z00*.bulk.test': 99 zones" || bad "--zones z00*: $n zones"
ctl stats --zones 'A.EXAMPLE.*' > "$T/glob2.prom"
n=$(grep -c '^karidns_zone_serial{' "$T/glob2.prom")
[ "$n" = 1 ] && ok "--zones is case-insensitive and ignores the root label" || bad "--zones A.EXAMPLE.*: $n zones"
ctl stats --zones 'nothing*' > "$T/glob3.prom"; st=$?
[ "$st" = 0 ] && [ "$(grep -c '^karidns_zone_serial{' "$T/glob3.prom")" = 0 ] && ok "--zones with no match: exit 0, no zones" || bad "--zones nothing*: exit $st"
ctl stats --limit 5 > "$T/l1.prom"
n=$(grep -c '^karidns_zone_serial{' "$T/l1.prom")
hint=$(grep '^# more zones: ' "$T/l1.prom")
[ "$n" = 5 ] && [ -n "$hint" ] && ok "--limit 5: 5 zones and the continuation hint" || bad "--limit 5: $n zones, hint '$hint'"
if grep -q '^karidns_view_' "$T/l1.prom"; then bad "a limited listing has per-view sums"; else ok "a limited listing has no per-view sums"; fi
after=$(printf '%s\n' "$hint" | sed -n 's/^# more zones: karictl stats --after \([^ ]*\).*/\1/p')

ctl stats --limit 5 --after "$after" > "$T/l2.prom"
grep '^karidns_zone_serial{' "$T/l1.prom" "$T/l2.prom" | sed 's/.*zone="\([^"]*\)".*/\1/' > "$T/l12.txt"
grep '^karidns_zone_serial{' "$T/all.prom" | head -10 | sed 's/.*zone="\([^"]*\)".*/\1/' > "$T/first10.txt"
if cmp -s "$T/l12.txt" "$T/first10.txt"; then ok "--after continues where --limit stopped (two runs = the first 10 zones)"; else bad "--after continuation differs" "$(diff "$T/l12.txt" "$T/first10.txt")"; fi
if perl -MJSON::PP -e 1 2>/dev/null; then
    ctl stats -f json --limit 3 > "$T/lj.json"
    r=$(perl -MJSON::PP -e 'local $/; open my $f, "<", $ARGV[0]; my $d = decode_json(<$f>); print scalar(@{$d->{zones}}), " ", ($d->{more} ? "more" : "done"), " ", $d->{after}, "\n"' "$T/lj.json" 2>&1)
    case "$r" in "3 more "*) ok "-f json --limit 3: three zones, more:true and the cursor ($r)";; *) bad "json --limit 3: $r";; esac
fi
# a cursor that does not fit the server's zone tables is refused (exit 3), never skipped over
ctl stats --after 0.0.1 > "$T/st.out" 2> "$T/st.err"; st=$?
if [ "$st" = 3 ] && grep -q 'cursor is stale' "$T/st.err"; then ok "a stale cursor: exit 3 and the message"; else bad "stale cursor: exit $st" "$(cat "$T/st.err")"; fi
ctl stats -f json --after nonsense > "$T/st.out" 2> "$T/st.err"; st=$?
[ "$st" = 3 ] && ok "a bad cursor with -f json: exit 3" || bad "bad cursor with json: exit $st"
# the errors
for args in "-f xml" "--limit 0" "--limit abc" "--after-view v" "--bogus" "a.test b.test c.test" "a.example.test --limit 3" "--zones" "--zones a b c d"; do
    ctl stats $args > /dev/null 2> "$T/e.err"; st=$?
    [ "$st" = 2 ] && ok "stats $args: usage error (exit 2)" || bad "stats $args: exit $st" "$(cat "$T/e.err")"
done
ctl stats --help >/dev/null 2>&1
"$KARICTL" --help | grep -q 'stats \[-f prometheus|json\]' && ok "--help lists stats" || bad "--help does not list stats"
# the three examples of --help, as written there (the control socket and key through the options before the command)
mkdir "$T/node_exporter"
ctl stats > "$T/node_exporter/karidns.prom.$$" && mv "$T/node_exporter/karidns.prom.$$" "$T/node_exporter/karidns.prom"
if [ -s "$T/node_exporter/karidns.prom" ] && [ ! -e "$T/node_exporter/karidns.prom.$$" ] && grep -q '^karidns_zones ' "$T/node_exporter/karidns.prom"; then ok "--help example 1: karictl stats > file && mv"; else bad "--help example 1"; fi
ctl stats -f json example.test > "$T/ex2.json" 2>"$T/ex2.err"; st=$?
if [ "$st" = 0 ] && grep -q '"zone":"example.test."' "$T/ex2.json"; then ok "--help example 2: karictl stats -f json example.test"; else bad "--help example 2 (exit $st)" "$(cat "$T/ex2.err"; head -c 300 "$T/ex2.json")"; fi
ctl stats --zones '*.example.test' --limit 100 > "$T/ex3.prom" 2>"$T/ex3.err"; st=$?
n=$(grep -c '^karidns_zone_serial{' "$T/ex3.prom")
if [ "$st" = 0 ] && [ "$n" = 3 ] && ! grep -q '^# more zones' "$T/ex3.prom"; then ok "--help example 3: karictl stats --zones '*.example.test' --limit 100 (3 zones, nothing more)"; else bad "--help example 3 (exit $st, $n zones)" "$(cat "$T/ex3.err")"; fi
# the old commands still work
ctl observatory a.example.test | grep -q 'Zone: a.example.test' && ok "observatory still works" || bad "observatory"
ctl status | grep -q 'number of zones: 2104' && ok "status still works" || bad "status"

# ---------------------------------------------------------------- C. alerts
echo "== C. alerts (about 45 s)"
act=$(getv 'karidns_alerts_active' "$T/all.prom")
echo "  (alerts raised when the first listing was taken: ${act:-?})"
count() { grep -c -- "$1" "$LOG" 2>/dev/null; }
wait_for() {   # wait_for TEXT SECONDS
    j=0
    while [ $j -lt $(($2 * 2)) ]; do
        [ "$(count "$1")" -ge 1 ] 2>/dev/null && return 0
        sleep 0.5
        j=$((j + 1))
    done
    return 1
}
for a in "alert: qps-above on server" "alert: qps-above on zone a.example.test" "alert: transfer-failures-above on server" "alert: reload-failures-above on server"; do
    if wait_for "$a" 30; then ok "raised: $a"; else bad "not raised within 30 s: $a" "$(tail -8 "$LOG" 2>/dev/null)"; fi
done
ctl stats > "$T/during.prom"
a1=$(getv 'karidns_alerts_active' "$T/during.prom")
[ "${a1:-0}" -ge 4 ] 2>/dev/null && ok "karidns_alerts_active counts the raised alerts ($a1)" || bad "karidns_alerts_active: $a1"
# the load ran for 12 s: the next check (about 10 s later) sees the value still above the limit and must write nothing
sleep 12
for a in "alert: qps-above on server" "alert: qps-above on zone a.example.test"; do
    n=$(count "$a")
    [ "$n" = 1 ] && ok "no repeat while above the limit: $a (1 line)" || bad "$a written $n times"
done
if grep -q 'alert: .* on zone b.example.test' "$LOG"; then bad "zone b replaces the options limit with 1000000: no alert expected" "$(grep 'on zone b.example.test' "$LOG")"; else ok "the zone that replaces the limit is not alerted"; fi
if grep -q -E 'alert: .* on zone (s[.]example[.]test|z0)' "$LOG"; then bad "a zone without an alerts block was alerted individually"; else ok "zones without an alerts block are only in the server's totals"; fi
for a in "alert cleared: qps-above on server" "alert cleared: qps-above on zone a.example.test" "alert cleared: transfer-failures-above on server" "alert cleared: reload-failures-above on server"; do
    if wait_for "$a" 30; then ok "cleared: $a"; else bad "not cleared within 30 s: $a" "$(tail -8 "$LOG" 2>/dev/null)"; fi
done
for a in "alert: qps-above on server" "alert cleared: qps-above on server" "alert: transfer-failures-above on server" "alert cleared: reload-failures-above on server"; do
    n=$(count "$a")
    [ "$n" = 1 ] && ok "exactly one line: $a" || bad "$a written $n times"
done
ctl stats > "$T/after.prom"
[ "$(getv 'karidns_alerts_active' "$T/after.prom")" = 0 ] && ok "karidns_alerts_active is 0 again" || bad "alerts still active: $(getv 'karidns_alerts_active' "$T/after.prom")"

echo
echo "$PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
