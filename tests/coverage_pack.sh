#!/bin/sh
# coverage_pack.sh - carry the instrumented build of `make coverage-build` from one CI job (VM) to the next.
#
# usage: sh tests/coverage_pack.sh pack ARCHIVE [STAMP]     (in the tree that was built)
#        sh tests/coverage_pack.sh unpack ARCHIVE            (in a fresh checkout of the same commit, at the same path)
#        sh tests/coverage_pack.sh clean ARCHIVE             (remove the files that ARCHIVE holds)
#
# pack: everything the build made, i.e. every file of the tree that is not tracked by git (binaries, objects, config.mk, tests/db/zone2sql ...),
# or, with STAMP (a file that was touched before the build), every file newer than STAMP (no git needed on the host).  Left out: .git, node_modules,
# coverage_raw (the profiles of a run), tests/.test_logs, the archive and the stamp.  The archive is zstd (tar --zstd), else xz, else gzip; unpack
# finds out which by itself.  Objects come first in the archive.
# unpack: tar -m: every file gets the time of the extraction, so the binaries are newer than the sources of the fresh checkout (nothing is
# rebuilt, and a test that runs `make karictl` finds it up to date: an uninstrumented rebuild would lose the coverage of the binary), and,
# as the objects are extracted before the programs, a program is never older than its objects.
# clean: the files of the archive are removed again, so that the copyback of the VM action (the whole workspace goes back to the runner)
# carries the archive and the results, not the build.
# The instrumented loader has the absolute path of coverage_raw compiled in: the tree must be at the same path as where it was built.
set -u

mode="${1:-}"
archive="${2:-}"
stamp="${3:-}"
if { [ "$mode" != pack ] && [ "$mode" != unpack ] && [ "$mode" != clean ]; } || [ -z "$archive" ]; then
    echo "usage: $0 pack ARCHIVE [STAMP] | unpack ARCHIVE | clean ARCHIVE" >&2
    exit 2
fi

if [ "$mode" = clean ]; then
    [ -f "$archive" ] || { echo "Error: $archive not found" >&2; exit 1; }
    tar -t -f "$archive" | while IFS= read -r f; do
        case "$f" in /*|*..*) continue ;; esac
        rm -f "$f"
    done
    echo "removed the files of $archive"
    exit 0
fi

if [ "$mode" = unpack ]; then
    [ -f "$archive" ] || { echo "Error: $archive not found" >&2; exit 1; }
    tar -x -m -p -f "$archive" || { echo "Error: could not unpack $archive" >&2; exit 1; }
    echo "unpacked $archive"
    exit 0
fi

list="${archive}.list.$$"
trap 'rm -f "$list" "$list.all" "$list.sorted"' EXIT
if [ -n "$stamp" ]; then
    [ -f "$stamp" ] || { echo "Error: stamp $stamp not found" >&2; exit 1; }
    find . -path ./.git -prune -o -type d -name node_modules -prune -o \( -type f -o -type l \) -newer "$stamp" -print | sed 's|^\./||' > "$list.all"
else
    { git ls-files -o -i --exclude-standard; git ls-files -o --exclude-standard; } > "$list.all" 2>/dev/null ||
        { echo "Error: git ls-files failed (no git, or not a work tree); give a stamp file" >&2; exit 1; }
fi
a=${archive#./}
s=${stamp#./}
grep -v -E '^\.git/|(^|/)node_modules/|^coverage_raw/|^tests/\.test_logs/|^\.ci-cache/' "$list.all" | grep -v -F -e "$a" -e "${s:-/nonexistent}" |
    sort -u > "$list.sorted"
# objects first, then the rest (extraction order = the order of the times)
{ grep -E '\.(o|a)$' "$list.sorted"; grep -v -E '\.(o|a)$' "$list.sorted"; } > "$list"
n=$(wc -l < "$list" | tr -d ' ')
[ "$n" -gt 0 ] || { echo "Error: nothing to pack (was anything built?)" >&2; exit 1; }

rm -f "$archive"
if tar --zstd -c -f "$archive" -T "$list" 2>/dev/null; then kind=zstd
elif tar -c -J -f "$archive" -T "$list" 2>/dev/null; then kind=xz
elif tar -c -z -f "$archive" -T "$list"; then kind=gzip
else echo "Error: tar failed" >&2; exit 1
fi
echo "packed $n files into $archive ($kind, $(wc -c < "$archive" | tr -d ' ') bytes)"
