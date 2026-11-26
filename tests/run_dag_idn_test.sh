#!/bin/sh
# run_dag_idn_test.sh - dag +idnin / +idnout against what dig 9.20 (libidn2) does, from tests/dag_idn_vectors.tsv (made by tests/dag_idn_vectors_gen.sh with
# dig 9.20.30 / libidn2 2.3.8).  For each row dag prints its query with +qr (to 127.0.0.1#1, where nobody listens: nothing leaves the host) and the name of the
# question must be the one dig printed, byte for byte: the UTS #46 non-transitional mapping, the transitional mapping of the whole name when a label has a code
# point IDNA2008 disallows, an ASCII name as typed, the UTF-8 octets (\DDD) when the name has no IDNA2008 form, and the U-labels of +idnout.
# When dig is installed the rows are also asked of it (KARIDNS_TEST_NO_DIG=1 skips that).  SKIP when dag was built without libidn2.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DAG=${DAG:-$ROOT/dag}
VEC=$ROOT/tests/dag_idn_vectors.tsv
[ -x "$DAG" ] || make -C "$ROOT" dag >/dev/null || { echo "FAIL: cannot build dag"; exit 1; }
for l in C.UTF-8 en_US.UTF-8; do
    if LC_ALL=$l locale charmap 2>/dev/null | grep -qi 'utf-\?8'; then LC_ALL=$l; break; fi
done
export LC_ALL
q() { awk '/QUESTION SECTION/ { getline; sub(/^;/, ""); print $1; exit }'; }
if "$DAG" +idnin +qr +nohexdump +tries=1 +timeout=1 -p 1 @127.0.0.1 -q "$(printf 'r\303\251.test')" A 2>&1 | grep -q 'without libidn2'; then
    # KARIDNS_TEST_REQUIRE=1 (CI): a dag without libidn2 is a failure, not a SKIP
    [ "${KARIDNS_TEST_REQUIRE:-0}" = 1 ] && { echo "FAIL: dag was built without libidn2 (KARIDNS_TEST_REQUIRE=1)"; exit 1; }
    echo "SKIP: dag was built without libidn2"
    exit 0
fi
WITH_DIG=0
if [ "${KARIDNS_TEST_NO_DIG:-0}" != 1 ] && command -v dig >/dev/null 2>&1 && dig -v 2>&1 | grep -q 'DiG 9\.\(1[89]\|2[0-9]\)'; then WITH_DIG=1; fi
pass=0
fail=0
TAB=$(printf '\t')
while IFS="$TAB" read -r dir name want; do
    case $dir in in) opts='+idnin +noidnout' ;; out) opts='+noidnin +idnout' ;; *) continue ;; esac
    # shellcheck disable=SC2086
    got=$("$DAG" $opts +qr +nohexdump +tries=1 +timeout=1 -p 1 @127.0.0.1 -q "$name" A 2>/dev/null | q)
    if [ "$got" = "$want" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  [FAIL] $dir $name: dag $got, dig $want"; fi
    if [ $WITH_DIG = 1 ]; then
        # shellcheck disable=SC2086
        live=$(dig $opts +qr +tries=1 +timeout=1 -p 1 @127.0.0.1 -q "$name" A 2>/dev/null | q)
        if [ "$live" = "$want" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "  [FAIL] $dir $name: the dig here prints $live, the table $want (make the table again?)"; fi
    fi
done < "$VEC"
echo "=== run_dag_idn_test: $pass passed, $fail failed (dig asked as well: $WITH_DIG) ==="
[ $fail -eq 0 ] && [ $pass -gt 0 ]
