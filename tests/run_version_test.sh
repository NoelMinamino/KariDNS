#!/bin/sh
# run_version_test.sh - the release number has one source (docs/RELEASING.md): the file VERSION.  Checks that
#   1. VERSION is x.y.z;
#   2. the copies `make set-version` writes agree with it: package.json and package-lock.json (the top level and packages[""]) of signer/ and
#      webadmin/, GUI_VERSION of webadmin/ui/js/version.js;
#   3. no other source holds a number of its own: the fallback of KARIDNS_VERSION in the C sources is "dev", the Node programs read package.json,
#      the packaging scripts take the file when no number is given;
#   4. tools/set_version.sh rewrites every copy (on a scratch copy of the files) and refuses a number that is not x.y.z;
#   5. the programs that are built in the tree report the number (they are optional: a check of an unbuilt program is a SKIP line).
# Needs sh, grep, sed, perl.  Run from anywhere; the release workflow runs it before it builds.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
FAIL=0
ok()  { echo "  [OK] $1"; }
bad() { echo "  [FAIL] $1"; FAIL=1; }

V=$(tr -d ' \r\n' < VERSION 2>/dev/null)
printf '%s\n' "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' && ok "VERSION is $V" || { bad "VERSION is missing or not x.y.z: '$V'"; exit 1; }

# the "version" values of a JSON file, in order (package.json: the first is the package's; package-lock.json: the top level, then packages[""])
versions() { perl -0ne 'print "$1\n" while /"version":\s*"([^"]*)"/g' "$1"; }
for p in signer webadmin; do
    [ "$(versions "$p/package.json" | head -1)" = "$V" ] && ok "$p/package.json is $V" || bad "$p/package.json says $(versions "$p/package.json" | head -1), VERSION says $V (make set-version V=$V)"
    [ "$(versions "$p/package-lock.json" | head -2 | sort -u)" = "$V" ] && ok "$p/package-lock.json is $V" || bad "$p/package-lock.json says $(versions "$p/package-lock.json" | head -2 | tr '\n' ' '), VERSION says $V"
done
G=$(sed -n "s/^export const GUI_VERSION = '\([^']*\)';.*/\1/p" webadmin/ui/js/version.js | tr -d '\r')
[ "$G" = "$V" ] && ok "webadmin/ui/js/version.js is $V" || bad "webadmin/ui/js/version.js says '$G', VERSION says $V"

# no number of its own anywhere else
L=$(grep -n -E '#define KARIDNS_VERSION "' ./*.c ./*.h tools/*.c tools/*.h | grep -v '"dev"')
[ -z "$L" ] && ok "the C fallbacks of KARIDNS_VERSION are \"dev\"" || bad "a C source defines a number: $L"
L=$(grep -n -E "VERSION = '[0-9]" signer/lib/*.js webadmin/lib/*.js node/lib/*.js)
[ -z "$L" ] && ok "signer and webadmin read their package.json" || bad "a Node module holds a number: $L"
L=$(grep -n -E '^VERSION="\$\{1:-[0-9]' packaging/*/*.sh)
[ -z "$L" ] && ok "the packaging scripts default to the file VERSION" || bad "a packaging script has a number of its own: $L"
grep -Eq '^VERSION_FILE != .*< VERSION' Makefile && ok "the Makefile reads VERSION" || bad "the Makefile does not read the file VERSION"

# set_version.sh on a scratch copy
T=$(mktemp -d "${TMPDIR:-/tmp}/karidns_version.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/tools" "$T/signer" "$T/webadmin/ui/js"
cp tools/set_version.sh "$T/tools/"
cp VERSION "$T/"
for p in signer webadmin; do cp "$p/package.json" "$p/package-lock.json" "$T/$p/"; done
cp webadmin/ui/js/version.js "$T/webadmin/ui/js/"
DEPS_BEFORE=$(versions "$T/webadmin/package-lock.json" | tail -n +3)
if sh "$T/tools/set_version.sh" 98.76.54 > "$T/out" 2>&1; then
    [ "$(tr -d '\r\n' < "$T/VERSION")" = 98.76.54 ] && ok "set_version.sh writes VERSION" || bad "set_version.sh did not write VERSION"
    for p in signer webadmin; do
        [ "$(versions "$T/$p/package.json" | head -1)" = 98.76.54 ] && [ "$(versions "$T/$p/package-lock.json" | head -2 | sort -u)" = 98.76.54 ] \
            && ok "set_version.sh writes $p/package.json and package-lock.json" || bad "set_version.sh did not write $p/package*.json"
    done
    [ "$(versions "$T/webadmin/package-lock.json" | tail -n +3)" = "$DEPS_BEFORE" ] && ok "set_version.sh leaves the dependencies' versions" || bad "set_version.sh changed a dependency's version"
    grep -q "^export const GUI_VERSION = '98.76.54';" "$T/webadmin/ui/js/version.js" && ok "set_version.sh writes version.js" || bad "set_version.sh did not write version.js: $(grep GUI_VERSION "$T/webadmin/ui/js/version.js")"
else
    bad "set_version.sh 98.76.54 failed: $(cat "$T/out")"
fi
for arg in '' 1.2 1.2.3.4 v1.2.3 1.2.3-rc1 '1.2.3 '; do
    sh "$T/tools/set_version.sh" "$arg" > "$T/out" 2>&1
    [ $? -eq 2 ] && [ "$(tr -d '\r\n' < "$T/VERSION")" = 98.76.54 ] && ok "set_version.sh refuses '$arg'" || bad "set_version.sh took '$arg'"
done

# the built programs report the number (a SKIP line for each one that is not built)
for b in "karidns -v:KariDNS $V" "dag -v:KariDNS dag v$V" "karicheck --version:karicheck $V" "karictl --version:karictl $V" \
         "karidns-dbloader --version:karidns-dbloader $V" "karidns-zone --version:karidns-zone $V "; do
    cmd=${b%%:*}; want=${b#*:}; prog=${cmd%% *}
    if [ ! -x "./$prog" ]; then echo "  [SKIP] ./$prog is not built"; continue; fi
    got=$(./$cmd 2>&1 | head -1)
    case "$got" in "$want"*) ok "./$cmd: $got" ;; *) bad "./$cmd says '$got', expected '$want'" ;; esac
done

if [ $FAIL -ne 0 ]; then echo "=== run_version_test: FAILED ==="; exit 1; fi
echo "=== run_version_test: the release number is $V everywhere ==="
exit 0
