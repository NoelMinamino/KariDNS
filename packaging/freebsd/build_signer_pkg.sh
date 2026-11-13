#!/bin/sh
set -e

# build_signer_pkg.sh - Build the FreeBSD .pkg of karidns-signer (docs/karidns-signer.md)
# Usage: ./packaging/freebsd/build_signer_pkg.sh [version] [output_dir]
#
# karidns-signer is Node.js (no compiler): the program with its one npm dependency (pg, `npm ci --omit=dev --ignore-scripts`), a wrapper in sbin,
# the rc script, a sample configuration, the manual page and the manual, staged with `make install-signer install-man-signer install-docs-signer
# DESTDIR=<stage>` (the Makefile is the one list of what goes where; packaging/freebsd/pkg_files.sh makes the package list of the stage).  The
# package depends on node24 and bind-tools (the packages that provide them on the build host) and creates the user and group karidns-signer.  It
# needs karidns-zone, which the database packages (build_pkg.sh --db sqlite3|postgresql|both) install and provide; it `requires` karidns-zone for
# pkg's solver, and as `pkg add` of a file does not look at that, its pre-install script refuses to install without /usr/local/bin/karidns-zone.
# The build host needs node24, npm-node24 and bind-tools.

VERSION_ARG="${1:-}"; . packaging/version.sh   # the file VERSION when no number is given
OUT_DIR="${2:-./dist}"
case "$VERSION" in -*) echo "build_signer_pkg.sh: usage: build_signer_pkg.sh [version] [output_dir]" >&2; exit 2 ;; esac
. packaging/freebsd/pkg_files.sh

ARCH=$(pkg config ABI 2>/dev/null || echo "FreeBSD:$(uname -r | cut -d. -f1):$(uname -m)")
ABI_SUFFIX=$(echo "$ARCH" | tr ':' '-')

DEPS=""
for p in node24 bind-tools; do
    if ! pkg query '%n' "$p" >/dev/null 2>&1; then
        echo "ERROR: ${p} is not installed on the build host (pkg install node24 npm-node24 bind-tools)" >&2
        exit 1
    fi
    DEPS="${DEPS}${DEPS:+,
}    $p: { origin: \"$(pkg query '%o' "$p")\", version: \"$(pkg query '%v' "$p")\" }"
    echo "==> depends on ${p}-$(pkg query '%v' "$p")"
done

(cd signer && npm ci --omit=dev --ignore-scripts) || { echo "ERROR: npm ci in signer/ failed (pkg install npm-node24)" >&2; exit 1; }
STAGE_DIR="$(mktemp -d -t karidns-signer-stage)"
MANIFEST_DIR="$(mktemp -d -t karidns-signer-manifest)"
trap 'rm -rf "${STAGE_DIR}" "${MANIFEST_DIR}"' EXIT
mkdir -p "${OUT_DIR}"
echo "==> Staging with make install (DESTDIR=${STAGE_DIR})..."
pkg_stage "${STAGE_DIR}" install-signer install-man-signer install-docs-signer

echo "==> Generating +MANIFEST..."
printf '%s\n' "$DEPS" > "${MANIFEST_DIR}/deps.txt"
pkg_files "${STAGE_DIR}" > "${MANIFEST_DIR}/files.txt"
sed -e "s/__VERSION__/${VERSION}/g" -e "s/__ARCH__/${ARCH}/g" packaging/freebsd/MANIFEST.signer.in | tr -d '\r' | awk -v dd="${MANIFEST_DIR}/deps.txt" -v ff="${MANIFEST_DIR}/files.txt" '
    function put(f,   l) { while ((getline l < f) > 0) print l; close(f) }
    $0 == "__DEPS__" { put(dd); next }
    $0 == "__FILES__" { put(ff); next }
    { print }' > "${MANIFEST_DIR}/+MANIFEST"
rm -f "${MANIFEST_DIR}/deps.txt" "${MANIFEST_DIR}/files.txt"
echo "==> Creating FreeBSD pkg..."
pkg create -m "${MANIFEST_DIR}" -r "${STAGE_DIR}" -o "${OUT_DIR}"
if [ -f "${OUT_DIR}/karidns-signer-${VERSION}.pkg" ]; then
    mv "${OUT_DIR}/karidns-signer-${VERSION}.pkg" "${OUT_DIR}/karidns-signer-${VERSION}-${ABI_SUFFIX}.pkg"
fi
echo "==> Successfully created FreeBSD package in ${OUT_DIR}:"
ls -lh "${OUT_DIR}/karidns-signer-${VERSION}"*.pkg*
