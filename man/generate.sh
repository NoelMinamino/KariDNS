#!/bin/sh
# generate.sh - the manual pages of man/ from the Markdown manuals docs/*.md (make man; docs/RELEASING.md "Manual pages").
#
#   sh man/generate.sh [OUTDIR]
#
# Writes every page into OUTDIR (default man/, the committed pages) with man/md2man.pl.  The date of a page (.TH) is the day its text last
# changed: a page whose text is the one of the committed page in man/ keeps that page's date, a changed or new page gets today's, so that
# `make man` without a change of a manual changes nothing and tests/run_md2man_test.sh (OUTDIR = a scratch directory) can compare byte for
# byte.  The options of each page are here and nowhere else.  Needs perl.
set -eu
cd "$(dirname "$0")/.."
OUT=${1:-man}
mkdir -p "$OUT"
TODAY=$(date +%Y-%m-%d)
TMP=$(mktemp "${TMPDIR:-/tmp}/karidns_man.XXXXXX")
trap 'rm -f "$TMP"' EXIT

# page FILE SECTION NAME OPTION...: man/NAME.SECTION from docs/FILE
page() {
    md=$1 sec=$2 name=$3
    shift 3
    perl man/md2man.pl -s "$sec" -n "$name" -d @DATE@ "$@" "docs/$md" > "$TMP"
    old=man/$name.$sec
    date=$TODAY
    if [ -f "$old" ] && [ "$(sed 1d "$TMP")" = "$(sed 1d "$old")" ] && [ "$(sed -n 1p "$TMP" | sed 's/"@DATE@"//')" = "$(sed -n 1p "$old" | sed 's/"[0-9-]*"//')" ]; then
        date=$(sed -n '1s/^\.TH [^ ]* [^ ]* "\([0-9-]*\)".*/\1/p' "$old")
    fi
    sed "1s/\"@DATE@\"/\"$date\"/" "$TMP" > "$OUT/$name.$sec"
}

CONF='^(CONFIGURATION OVERVIEW|CONFIGURATION REFERENCE|TRANSPORT TUNING)'
page karidns.md 8 karidns --omit "$CONF" --omit-note 'CONFIGURATION=The configuration file is described in karidns.conf(5).' --see-also 'karidns.conf(5)'
page karidns.md 5 karidns.conf --only "$CONF" --name-desc 'the configuration file of karidns(8)' --synopsis /usr/local/etc/karidns/karidns.conf \
    --see-also 'karidns(8), karicheck(8), karictl(8)'
page karictl.md 8 karictl
page karicheck.md 8 karicheck
page dag.md 1 dag
page karidns-tapstat.md 1 karidns-tapstat
page karidns-dbloader.md 8 karidns-dbloader
page karidns-zone.md 8 karidns-zone
page karidns-signer.md 8 karidns-signer
page karidns-webadmin.md 8 karidns-webadmin --synopsis 'karidns-webadmin [-c config] [--check]' \
    --synopsis 'karidns-webadmin [-c config] --create-admin NAME [--bootstrap-conninfo-file FILE]' --synopsis 'karidns-webadmin --version | -h | --help'
