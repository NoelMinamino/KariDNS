#!/bin/sh
# freebsd_no_rebuild_check.sh - fail when a CI test job built something (.github/workflows/freebsd.yml).
#
# usage: sh tests/freebsd_no_rebuild_check.sh STAMP    (in the tree that tests/coverage_pack.sh unpack filled, STAMP touched right after it)
#
# The job build makes every object and program the test jobs use and packs them; a test job unpacks them (every file older than STAMP) and only
# runs tests.  An object file (.o, .a) or a program newer than STAMP was made by a test: a target the job build does not list (add it there, or the test
# builds it each time on every runner).  The logs, node_modules, .git and the profiles of a coverage run are not looked at.
set -u
stamp="${1:-}"
[ -n "$stamp" ] && [ -f "$stamp" ] || { echo "usage: $0 STAMP (an existing file)" >&2; exit 2; }
made=$(find . \( -path ./.git -o -name node_modules -o -path ./tests/.test_logs -o -path ./coverage_raw \) -prune -o \
    -type f \( -name '*.o' -o -name '*.a' -o -perm -100 \) -newer "$stamp" -print | sed 's|^\./||' | sort)
if [ -n "$made" ]; then
    echo "::error title=A test built something::the files below are newer than the unpacked build: add their make targets to the job build of .github/workflows/freebsd.yml"
    echo "$made"
    exit 1
fi
echo "no object file or program was made after the unpack"
