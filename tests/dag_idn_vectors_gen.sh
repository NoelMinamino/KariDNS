#!/bin/sh
# dag_idn_vectors_gen.sh - makes tests/dag_idn_vectors.tsv again: for each row, the question dig prints with +qr (the query it sends) for the name of the row,
# with +idnin (rows "in") or +idnout (rows "out").  Run where dig (BIND 9.20 with libidn2) and a UTF-8 locale exist:
#   sh tests/dag_idn_vectors_gen.sh > tests/dag_idn_vectors.tsv.new && mv tests/dag_idn_vectors.tsv.new tests/dag_idn_vectors.tsv
# The names are the second column of the current file; the third is replaced.  dig asks a port nobody listens on (127.0.0.1#1): nothing is sent anywhere else.
set -eu
cd "$(dirname "$0")/.."
LC_ALL=${LC_ALL:-en_US.UTF-8}
export LC_ALL
printf '# made by tests/dag_idn_vectors_gen.sh with %s, %s: dir<TAB>name<TAB>the question dig prints (+qr)\n' "$(dig -v 2>&1 | head -1)" "$(date +%Y-%m-%d)"
grep -v '^#' tests/dag_idn_vectors.tsv | while IFS="$(printf '\t')" read -r dir name _; do
    if [ "$dir" = in ]; then opts='+idnin +noidnout'; else opts='+noidnin +idnout'; fi
    # shellcheck disable=SC2086
    q=$(dig $opts +qr +tries=1 +timeout=1 -p 1 @127.0.0.1 -q "$name" A 2>/dev/null | awk '/QUESTION SECTION/ { getline; sub(/^;/, ""); print $1; exit }')
    printf '%s\t%s\t%s\n' "$dir" "$name" "$q"
done
