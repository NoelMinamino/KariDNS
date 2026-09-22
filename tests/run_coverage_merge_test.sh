#!/bin/sh
# run_coverage_merge_test.sh - tests/coverage_merge.sh must survive corrupt raw profiles.
#
# Regression guard for `make coverage` failing at the very end with
#     warning: coverage_raw/karidns_NNN_..._0.profraw: invalid instrumentation profile data (file header is corrupt)
#     error: no profile can be merged
# A raw profile is truncated when a process is SIGKILLed (test teardown) while it writes its profile at exit; the
# default failure mode of `llvm-profdata merge` then throws away every valid profile. The real llvm-profdata is not
# needed: a stub with the same "any input invalid => abort" behaviour stands in for it.
set -u
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="${ROOT_DIR}/tests/coverage_merge.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/karidns_covmerge.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM

fail() { echo "FAIL: $1"; exit 1; }

# --- stub llvm-profdata (failure mode "any"): valid raw profile = 8-byte raw magic + >= 128 bytes -------------------
cat > "$WORK/llvm-profdata" <<'STUB'
#!/bin/sh
[ "$1" = merge ] || exit 2
shift
files=""; out=""
while [ $# -gt 0 ]; do
    case $1 in
        -sparse) ;;
        -o) out=$2; shift ;;
        -f) files="$files $(cat "$2")"; shift ;;
        *) files="$files $1" ;;
    esac
    shift
done
err=0
for f in $files; do
    magic=$(head -c 8 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    size=$(wc -c < "$f" | tr -d ' ')
    if [ "$magic" != "ff6c70726f667281" ] || [ "$size" -lt 128 ]; then
        echo "warning: $f: invalid instrumentation profile data (file header is corrupt)" >&2
        err=$((err + 1))
    fi
done
if [ "$err" -gt 0 ]; then echo "error: no profile can be merged" >&2; exit 1; fi
cat $files > "$out"
STUB
chmod +x "$WORK/llvm-profdata"
STUBBIN="$WORK/llvm-profdata"

mkvalid() { printf '\377lprofr\201' > "$1"; head -c 200 /dev/zero >> "$1"; }   # 208 bytes

echo "Test 1: the stub reproduces the reported failure for a plain merge ..."
mkdir "$WORK/t1"; mkvalid "$WORK/t1/a.profraw"; mkvalid "$WORK/t1/b.profraw"
printf 'truncated' > "$WORK/t1/karidns_29459_1_0.profraw"
if "$STUBBIN" merge -sparse "$WORK"/t1/*.profraw -o "$WORK/t1.out" >/dev/null 2>&1; then
    fail "plain merge should abort on a corrupt input (stub is wrong)"
fi
echo "  OK"

echo "Test 2: coverage_merge.sh skips the corrupt/empty files and merges the rest ..."
mkdir "$WORK/t2"
mkvalid "$WORK/t2/a.profraw"; mkvalid "$WORK/t2/b.profraw"; mkvalid "$WORK/t2/c.profraw"
printf 'truncated' > "$WORK/t2/karidns_29459_1_0.profraw"      # too short for a header
: > "$WORK/t2/karidns_29460_1_0.profraw"                        # created, killed before the first write
head -c 300 /dev/urandom > "$WORK/t2/garbage.profraw"           # wrong magic
OUT=$(sh "$SCRIPT" "$STUBBIN" "$WORK/t2" "$WORK/t2.profdata" 2>&1) || { echo "$OUT"; fail "merge failed although valid profiles exist"; }
echo "$OUT" | grep -q 'total=6 valid=3 skipped=3' || { echo "$OUT"; fail "unexpected file accounting"; }
echo "$OUT" | grep -q 'karidns_29459_1_0.profraw' || { echo "$OUT"; fail "skipped file was not named in the output"; }
[ "$(wc -c < "$WORK/t2.profdata" | tr -d ' ')" -eq 624 ] || fail "merged output must contain exactly the 3 valid profiles (3 x 208 bytes)"
[ ! -e "$WORK/t2/.valid_profraw.list" ] && [ ! -e "$WORK/t2/.probe.profdata" ] || fail "temporary files were left in the raw directory"
echo "  OK"

echo "Test 3: all files valid -> nothing skipped ..."
mkdir "$WORK/t3"; mkvalid "$WORK/t3/a.profraw"; mkvalid "$WORK/t3/b.profraw"
OUT=$(sh "$SCRIPT" "$STUBBIN" "$WORK/t3" "$WORK/t3.profdata" 2>&1) || { echo "$OUT"; fail "merge failed"; }
echo "$OUT" | grep -q 'total=2 valid=2 skipped=0' || { echo "$OUT"; fail "unexpected file accounting"; }
echo "  OK"

echo "Test 4: no valid profile at all must still be an error ..."
mkdir "$WORK/t4"; printf 'x' > "$WORK/t4/a.profraw"; : > "$WORK/t4/b.profraw"
if sh "$SCRIPT" "$STUBBIN" "$WORK/t4" "$WORK/t4.profdata" >/dev/null 2>&1; then fail "expected a non-zero exit"; fi
mkdir "$WORK/t5"
if sh "$SCRIPT" "$STUBBIN" "$WORK/t5" "$WORK/t5.profdata" >/dev/null 2>&1; then fail "empty directory must be an error"; fi
sh "$SCRIPT" "$STUBBIN" >/dev/null 2>&1; [ $? -eq 2 ] || fail "wrong usage must exit with status 2"
echo "  OK"

echo "PASS: coverage_merge.sh tolerates corrupt raw profiles"
