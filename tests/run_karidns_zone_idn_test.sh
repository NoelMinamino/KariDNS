#!/bin/sh
# run_karidns_zone_idn_test.sh - karidns-zone idn --json (0.7, the WebAdmin): names converted exactly as dig 9.20 converts them (+idnin, +idnout), against
# webadmin/test/idn_dig_vectors.json (what dig 9.20.30 / libidn2 2.3.8 sent and showed on the build host; webadmin/test/idn_dig_vectors_gen.mjs makes it).
# Also the usage errors, a line that is no request, and the example of --help.  A karidns-zone built without libidn2 must say db.idn.unavailable (the rest
# is then skipped: the coverage build has no libidn2).  SKIP without perl.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ZONE=${ZONE:-$ROOT/karidns-zone}
VEC=$ROOT/webadmin/test/idn_dig_vectors.json
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl is not installed"; exit 0; }
[ -x "$ZONE" ] || make -C "$ROOT" karidns-zone >/dev/null || { echo "FAIL: cannot build karidns-zone"; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_zone_idn.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  [ OK ] $1"; }
bad() { fail=$((fail + 1)); echo "  [FAIL] $1"; }
expect_rc() {                     # expect_rc WANT WHAT CMD...
    want=$1 what=$2
    shift 2
    "$@" < /dev/null > "$T/out" 2>&1
    rc=$?
    [ "$rc" -eq "$want" ] && ok "$what (exit $rc)" || bad "$what: exit $rc, expected $want: $(head -c 300 "$T/out")"
}

echo "=== the command line ==="
expect_rc 2 "idn without --json" "$ZONE" idn
expect_rc 2 "idn with an argument" "$ZONE" idn --json example.test
expect_rc 2 "idn with a database option" "$ZONE" idn --json --sqlite3 "$T/x.sqlite3"

printf 'u\txn--r8jz45g.test\n' | "$ZONE" idn --json > "$T/probe.json" 2>&1
if grep -q 'db.idn.unavailable' "$T/probe.json"; then
    ok "built without libidn2: db.idn.unavailable"
    echo "=== run_karidns_zone_idn_test: $pass passed, $fail failed (without libidn2: the conversions are not checked) ==="
    [ "$fail" -eq 0 ]
    exit
fi

echo "=== the example of --help, a line that is no request ==="
"$ZONE" --help 2>&1 | grep -q "printf 'u.txn--r8jz45g.test.n' | karidns-zone idn --json" && ok "--help names the example" || bad "--help has no idn example"
grep -q '"unicode": "例え.test"' "$T/probe.json" && ok "the example: xn--r8jz45g.test is 例え.test" || bad "the example: $(head -c 300 "$T/probe.json")"
printf 'x\texample.test\n' | "$ZONE" idn --json > "$T/bad.json" 2>&1
rc=$?
[ $rc -eq 1 ] && grep -q 'db.idn.input' "$T/bad.json" && ok "a line that is no request: exit 1, db.idn.input" || bad "a line that is no request: exit $rc $(head -c 300 "$T/bad.json")"

echo "=== the vectors of dig 9.20 ==="
perl -MJSON::PP -e '
    use strict; use warnings;
    local $/; open my $f, "<:raw", $ARGV[0] or die; my $v = JSON::PP->new->utf8->decode(<$f>);
    open my $o, ">:raw", $ARGV[1] or die;
    for my $x (@{$v->{vectors}}) { my $n = $x->{name}; utf8::encode($n); print $o "a\t$n\n"; }
    for my $x (@{$v->{display}}) { my $n = $x->{name}; utf8::encode($n); print $o "u\t$n\n"; }
' "$VEC" "$T/in.txt" || { bad "cannot read $VEC"; exit 1; }
"$ZONE" idn --json < "$T/in.txt" > "$T/out.json" 2> "$T/err"
rc=$?
[ $rc -eq 0 ] && ok "every vector in one run (exit 0)" || bad "the run: exit $rc $(head -c 300 "$T/err")"
perl -MJSON::PP -e '
    use strict; use warnings;
    local $/;
    open my $f, "<:raw", $ARGV[0] or die; my $v = JSON::PP->new->utf8->decode(<$f>);
    open my $g, "<:raw", $ARGV[1] or die; my $d = JSON::PP->new->utf8->decode(<$g>);
    my @got = @{$d->{idn} // []};
    my ($p, $q) = (0, 0);
    my @want = ((map { [ "a", $_ ] } @{$v->{vectors}}), (map { [ "u", $_ ] } @{$v->{display}}));
    @got == @want or do { print "  [FAIL] ", scalar(@got), " answers for ", scalar(@want), " lines\n"; exit 1 };
    for my $i (0 .. $#want) {
        my ($k, $x) = @{$want[$i]}; my $r = $got[$i]; my $name = $x->{name}; my $dig = $x->{dig};
        my $ascii_only = $name !~ /[^\x00-\x7f]/;
        my $good;
        if ($k eq "a") {
            $good = defined $dig ? (defined $r->{ascii} && lc $r->{ascii} eq lc $dig)
                                 : ($ascii_only ? (defined $r->{ascii} && $r->{ascii} eq $name) : !defined $r->{ascii});
        } else {
            my $shown = $r->{unicode} // $name;
            $good = $shown eq $dig;
        }
        my $line = "$k $name: dig " . ($dig // "(the octets)") . ", karidns-zone " . ($k eq "a" ? ($r->{ascii} // "null (" . ($r->{error} // "") . ")") : ($r->{unicode} // "null"));
        utf8::encode($line);
        if ($good) { $p++ } else { $q++; print "  [FAIL] $line\n" }
    }
    print "  [ OK ] $p vectors as dig\n" if $p; exit($q ? 1 : 0);
' "$VEC" "$T/out.json" && ok "karidns-zone idn is dig 9.20, byte for byte" || bad "karidns-zone idn differs from dig"

echo "=== run_karidns_zone_idn_test: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
