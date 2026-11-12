#!/bin/sh
# set_version.sh - change the release number of KariDNS everywhere it is kept (docs/RELEASING.md).
#
# The file VERSION at the top of the source tree is the one source.  The C programs get it through the Makefile
# (-DKARIDNS_VERSION); karidns-signer and karidns-webadmin read the version of their package.json when they start.
# This script writes VERSION and the files that cannot read it: package.json and package-lock.json of signer/ and
# webadmin/ (npm and the packages take the version from there) and webadmin/ui/js/version.js (a static file of the
# browser, compared with the service's version by the page).  tests/run_version_test.sh fails when they disagree.
#
# Usage: tools/set_version.sh x.y.z      (or: make set-version V=x.y.z)

set -eu

V=${1:-}
if ! printf '%s\n' "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "usage: tools/set_version.sh x.y.z (three numbers, for example 0.6.1)" >&2
    exit 2
fi
cd "$(dirname "$0")/.."
for f in VERSION signer/package.json signer/package-lock.json webadmin/package.json webadmin/package-lock.json webadmin/ui/js/version.js; do
    [ -f "$f" ] || { echo "set_version.sh: $f is missing (run it in a KariDNS source tree)" >&2; exit 1; }
done

printf '%s\n' "$V" > VERSION
export V
# a config.mk written by ./configure holds the number it read (VERSION_FILE): keep it in step, or the next make builds the old one
[ ! -f config.mk ] || perl -pi -e 's/^VERSION_FILE = .*/VERSION_FILE = $ENV{V}/' config.mk
for p in signer webadmin; do
    # package.json: the first "version" (the package's own).  package-lock.json (lockfileVersion 3): the first two, the top
    # level and packages[""]; the later ones are the dependencies' and stay.
    perl -0pi -e 's/("version":\s*")[^"]*(")/$1$ENV{V}$2/' "$p/package.json"
    perl -0pi -e '$n = 0; s/("version":\s*")[^"]*(")/$n++ < 2 ? "$1$ENV{V}$2" : $&/ge' "$p/package-lock.json"
done
perl -pi -e "s/^(export const GUI_VERSION = ')[^']*(';)/\${1}\$ENV{V}\${2}/" webadmin/ui/js/version.js

echo "version $V: VERSION, signer/ and webadmin/ package.json and package-lock.json, webadmin/ui/js/version.js"
